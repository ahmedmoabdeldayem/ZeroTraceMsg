// ZeroTraceMsg Server — core logic

#include "server.hpp"
#include "../common/identity.hpp"
#include "../common/protocol.hpp"
#include "../common/store.hpp"
#include "../common/tls_utils.hpp"
#include <algorithm>
#include <arpa/inet.h>
#include <atomic>
#include <botan/auto_rng.h>
#include <botan/data_src.h>
#include <botan/ec_group.h>
#include <botan/ecdsa.h>
#include <botan/ed25519.h>
#include <botan/hex.h>
#include <botan/pkcs8.h>
#include <botan/tls_session_manager_noop.h>
#include <botan/x509self.h>
#include <chrono>
#include <ctime>
#include <fstream>
#include <functional>
#include <iostream>
#include <map>
#include <mutex>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <sstream>
#include <string>
#include <sys/socket.h>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>
#include <vector>

// ── logging ──────────────────────────────────────────────────────────────────

static int g_log_level = 1; // 0=debug 1=info 2=warn 3=error
static bool g_log_json = false;
static std::ofstream g_log_file;
static std::mutex g_log_mutex;

static void log_init(const Config& cfg)
{
    std::string lv = cfg.log_level;
    if (lv == "debug")
        g_log_level = 0;
    else if (lv == "info")
        g_log_level = 1;
    else if (lv == "warn")
        g_log_level = 2;
    else
        g_log_level = 3; // error

    g_log_json = (cfg.log_format == "json");

    if (!cfg.log_file.empty()) {
        g_log_file.open(cfg.log_file, std::ios::app);
    }
}

static void log_msg(int level, const std::string& msg)
{
    if (level < g_log_level)
        return;
    std::lock_guard<std::mutex> lk(g_log_mutex);
    std::ostream& out = g_log_file.is_open() ? g_log_file : std::cout;
    if (g_log_json) {
        static const char* labels[] = {"debug", "info", "warn", "error"};
        out << "{\"level\":\"" << labels[level] << "\",\"msg\":\"" << msg << "\"}\n";
    } else {
        out << msg << "\n";
    }
}

#define LOG_DEBUG(m) log_msg(0, m)
#define LOG_INFO(m) log_msg(1, m)
#define LOG_WARN(m) log_msg(2, m)
#define LOG_ERROR(m) log_msg(3, m)

// ── server state ─────────────────────────────────────────────────────────────

static bool ct_equal(const uint8_t* a, const uint8_t* b, size_t len)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < len; ++i)
        diff |= a[i] ^ b[i];
    return diff == 0;
}

// The store is created once on first call with the configured db_path.
// Subsequent calls return the same instance. reset_server_state() replaces it
// with a fresh in-memory store so tests start clean.
static std::unique_ptr<Store> g_store;
static std::mutex store_mutex;

static Store& get_store() { return *g_store; }

// ── server-wide globals ───────────────────────────────────────────────────────

static std::atomic<bool> g_shutdown{false};
static std::atomic<bool> g_reload_config{false};
static std::atomic<bool> g_log_reopen{false};
static std::atomic<int> g_active_connections{0};
static int64_t g_start_time = 0;
static std::string g_config_path;

static void handle_signal(int sig)
{
    if (sig == SIGTERM || sig == SIGINT)
        g_shutdown.store(true);
    else if (sig == SIGHUP)
        g_reload_config.store(true);
    else if (sig == SIGUSR1)
        g_log_reopen.store(true);
}

// ── helpers ───────────────────────────────────────────────────────────────────

static std::string new_message_id()
{
    // Random 16-byte ID — avoids leaking total server message volume
    static Botan::AutoSeeded_RNG id_rng;
    return Botan::hex_encode(id_rng.random_vec(16));
}

static int64_t now_unix()
{
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

static std::string format_cert_date(std::time_t t)
{
    struct tm tm_info;
    gmtime_r(&t, &tm_info);
    char buf[16];
    strftime(buf, sizeof(buf), "%Y%m%d%H%M%SZ", &tm_info);
    return std::string(buf);
}

// ── protocol handler ──────────────────────────────────────────────────────────

using SendFn = std::function<void(const std::string&)>;
using RecvFn = std::function<std::string()>;

static void handle_client(int client_fd, SendFn sl, RecvFn rl, const Config& cfg)
{
    Botan::AutoSeeded_RNG rng;
    LOG_INFO("[CONNECT]  client connected (fd=" + std::to_string(client_fd) + ")");

    while (true) {
        std::string line = rl();
        if (line.empty())
            break;

        std::istringstream ss(line);
        std::string cmd;
        ss >> cmd;

        if (cmd == "HELLO") {
            // Protocol version handshake — optional (old clients send REGISTER directly)
            std::string ver;
            ss >> ver;
            std::string expected = "ZTM/" + std::to_string(PROTOCOL_VERSION);
            if (ver == expected) {
                sl("OK " + expected);
            } else {
                sl("ERR version_mismatch supported=" + std::to_string(PROTOCOL_VERSION));
                break;
            }

        } else if (cmd == "STATUS") {
            // Health check — no auth required; safe for load balancers / k8s probes
            std::lock_guard<std::mutex> lock(store_mutex);
            Store& s = get_store();
            int64_t uptime = now_unix() - g_start_time;
            sl("OK users=" + std::to_string(s.user_count()) +
               " sessions=" + std::to_string(s.session_count()) + " messages=" +
               std::to_string(s.total_messages()) + " uptime=" + std::to_string(uptime));
            LOG_DEBUG("[STATUS]   queried");

        } else if (cmd == "REGISTER") {
            std::string user_id, pubkey_hex;
            ss >> user_id >> pubkey_hex;
            try {
                auto pubkey = Botan::hex_decode(pubkey_hex);

                if (pubkey.size() != cfg.kem_pubkey_len()) {
                    sl("ERR pubkey size mismatch for configured KEM");
                    continue;
                }

                std::string expected_id = derive_user_id(pubkey);
                if (expected_id != user_id) {
                    sl("ERR user_id does not match pubkey");
                    continue;
                }

                std::lock_guard<std::mutex> lock(store_mutex);
                Store& s = get_store();

                if (cfg.max_users > 0 && !s.user_exists(user_id) &&
                    s.user_count() >= cfg.max_users) {
                    sl("ERR server has reached maximum user capacity");
                    continue;
                }

                auto existing = s.get_pubkey(user_id);
                if (existing.has_value() && *existing != pubkey) {
                    sl("ERR user_id already registered with a different key");
                    continue;
                }

                auto token_bytes = rng.random_vec(32);
                std::string token = Botan::hex_encode(token_bytes);
                s.put_user(user_id, pubkey);
                s.put_session(user_id, token, now_unix());

                sl("OK " + token + " kem=" + cfg.kem + " cipher=" + cfg.cipher +
                   " hash=" + cfg.hash + " pad=" + std::to_string(cfg.padded_plaintext_kb));
                LOG_INFO("[REGISTER] user=" + user_id +
                         " total_users=" + std::to_string(s.user_count()));
            } catch (...) {
                sl("ERR invalid pubkey");
            }

        } else if (cmd == "GETKEY") {
            std::string user_id;
            ss >> user_id;
            std::lock_guard<std::mutex> lock(store_mutex);
            auto key = get_store().get_pubkey(user_id);
            if (!key.has_value()) {
                sl("ERR unknown user");
            } else {
                sl("OK " + Botan::hex_encode(*key));
            }

        } else if (cmd == "SEND") {
            std::string sender_id, token, recipient_id, blob_hex;
            ss >> sender_id >> token >> recipient_id >> blob_hex;
            std::lock_guard<std::mutex> lock(store_mutex);
            Store& s = get_store();

            // Token auth + session TTL
            auto sess = s.get_session(sender_id);
            bool token_ok =
                sess.has_value() && sess->token.size() == token.size() &&
                ct_equal(reinterpret_cast<const uint8_t*>(sess->token.data()),
                         reinterpret_cast<const uint8_t*>(token.data()), sess->token.size());

            if (token_ok && cfg.session_ttl_hours > 0) {
                int64_t age_h = (now_unix() - sess->created_at) / 3600;
                if (age_h >= cfg.session_ttl_hours) {
                    s.remove_session(sender_id);
                    token_ok = false;
                }
            }

            if (!token_ok) {
                sl("ERR invalid token");
                continue;
            }

            // Rate limiting
            {
                int64_t now = now_unix();
                auto bucket = s.get_rate_bucket(sender_id);
                int count = 0;
                int64_t window_start = now;
                if (bucket.has_value()) {
                    count = bucket->count;
                    window_start = bucket->window_start;
                    if (now - window_start >= cfg.rate_limit_window_s) {
                        count = 0;
                        window_start = now;
                    }
                }
                if (count >= cfg.rate_limit_msgs) {
                    sl("ERR rate limit exceeded");
                    continue;
                }
                s.put_rate_bucket(sender_id, count + 1, window_start, now);
            }

            if (!s.user_exists(recipient_id)) {
                sl("ERR unknown recipient");
                continue;
            }

            if (s.inbox_size(recipient_id) >= cfg.max_inbox_messages) {
                sl("ERR recipient inbox is full");
                continue;
            }

            try {
                auto blob = Botan::hex_decode(blob_hex);
                if (blob.size() > cfg.max_blob_len()) {
                    sl("ERR blob too large");
                    continue;
                }
                std::string msg_id = new_message_id();
                s.enqueue(msg_id, recipient_id, sender_id, blob, now_unix());
                sl("OK");
                LOG_INFO("[SEND]     to=" + recipient_id + " msg_id=" + msg_id + " blob=" +
                         std::to_string(blob.size()) + " bytes (server cannot read content)");
            } catch (...) {
                sl("ERR invalid blob");
            }

        } else if (cmd == "POLL") {
            std::string user_id, token;
            ss >> user_id >> token;
            std::lock_guard<std::mutex> lock(store_mutex);
            Store& s = get_store();

            auto sess = s.get_session(user_id);
            bool token_ok =
                sess.has_value() && sess->token.size() == token.size() &&
                ct_equal(reinterpret_cast<const uint8_t*>(sess->token.data()),
                         reinterpret_cast<const uint8_t*>(token.data()), sess->token.size());

            if (token_ok && cfg.session_ttl_hours > 0) {
                int64_t age_h = (now_unix() - sess->created_at) / 3600;
                if (age_h >= cfg.session_ttl_hours) {
                    s.remove_session(user_id);
                    token_ok = false;
                }
            }

            if (!token_ok) {
                sl("ERR invalid token");
                LOG_INFO("[POLL]     user=" + user_id + " -> REJECTED invalid token");
                continue;
            }

            auto msgs = s.drain_inbox(user_id);
            if (!msgs.empty()) {
                for (auto& msg : msgs) {
                    sl("MSG " + msg.id + " " + Botan::hex_encode(msg.blob));
                    s.increment_ack(msg.sender_id);
                }
                LOG_INFO("[POLL]     user=" + user_id + " -> delivered " +
                         std::to_string(msgs.size()) + " message(s), wiped from store");
            }

            int ack = s.drain_ack(user_id);
            if (ack > 0)
                sl("ACK " + std::to_string(ack));
            sl("NOMSG");

        } else if (cmd == "DEREGISTER") {
            // GDPR right to erasure — removes all server-side data for this user
            std::string user_id, token;
            ss >> user_id >> token;
            std::lock_guard<std::mutex> lock(store_mutex);
            Store& s = get_store();

            auto sess = s.get_session(user_id);
            bool token_ok =
                sess.has_value() && sess->token.size() == token.size() &&
                ct_equal(reinterpret_cast<const uint8_t*>(sess->token.data()),
                         reinterpret_cast<const uint8_t*>(token.data()), sess->token.size());
            if (!token_ok) {
                sl("ERR invalid token");
                continue;
            }

            s.remove_user(user_id);
            s.remove_session(user_id);
            s.remove_rate_bucket(user_id);
            // drain_inbox implicitly deletes messages; delivery_acks reset on drain
            s.drain_inbox(user_id);
            s.drain_ack(user_id);
            sl("OK");
            LOG_INFO("[DEREGISTER] user=" + user_id + " — all data removed");

        } else {
            sl("ERR unknown command");
        }
    }

    LOG_INFO("[DISCONNECT] client disconnected (fd=" + std::to_string(client_fd) + ")");
    close(client_fd);
}

// ── background cleanup ────────────────────────────────────────────────────────

static void cleanup_thread(const Config& cfg)
{
    while (true) {
        std::this_thread::sleep_for(std::chrono::minutes(cfg.cleanup_interval_min));
        int64_t now = now_unix();
        int64_t msg_cutoff = now - int64_t(cfg.msg_ttl_hours) * 3600;
        int64_t sess_cutoff =
            (cfg.session_ttl_hours > 0) ? now - int64_t(cfg.session_ttl_hours) * 3600 : 0;
        int64_t bucket_cutoff = now - int64_t(cfg.rate_limit_window_s) * 2;

        std::lock_guard<std::mutex> lock(store_mutex);
        Store& s = get_store();
        s.prune_messages(msg_cutoff);
        if (sess_cutoff > 0)
            s.prune_sessions(sess_cutoff);
        s.prune_rate_buckets(bucket_cutoff);
    }
}

// ── socket helper ─────────────────────────────────────────────────────────────

static int make_listening_socket(int port, const std::string& bind_addr)
{
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        return -1;
    }
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = bind_addr == "0.0.0.0" ? INADDR_ANY : inet_addr(bind_addr.c_str());
    addr.sin_port = htons(static_cast<uint16_t>(port));
    if (bind(server_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        perror("bind");
        return -1;
    }
    listen(server_fd, SOMAXCONN);
    return server_fd;
}

// ── plain TCP server (tests) ──────────────────────────────────────────────────

void start_server(int port)
{
    Config cfg; // default config — always use in-memory DB for the plain TCP test server
    cfg.db_path = "";
    {
        std::lock_guard<std::mutex> lock(store_mutex);
        if (!g_store)
            g_store = std::make_unique<Store>(cfg.db_path);
    }

    int server_fd = make_listening_socket(port, "0.0.0.0");
    if (server_fd < 0)
        return;
    LOG_INFO("[*] Server listening on port " + std::to_string(port) + " (plain TCP)");
    std::thread([cfg]() { cleanup_thread(cfg); }).detach();
    while (true) {
        int cfd = accept(server_fd, nullptr, nullptr);
        if (cfd < 0)
            continue;
        std::thread([cfd, cfg]() {
            handle_client(
                cfd,
                [cfd](const std::string& s) {
                    std::string msg = s + "\n";
                    ::send(cfd, msg.data(), msg.size(), 0);
                },
                [cfd]() {
                    std::string line;
                    char c;
                    while (::recv(cfd, &c, 1, 0) > 0) {
                        if (c == '\n')
                            break;
                        if (line.size() >= MAX_LINE_LEN)
                            return std::string{};
                        line += c;
                    }
                    return line;
                },
                cfg);
        }).detach();
    }
}

// ── TLS server ────────────────────────────────────────────────────────────────

class ServerCredentials : public Botan::Credentials_Manager
{
    Botan::X509_Certificate cert_;
    std::shared_ptr<Botan::Private_Key> key_;

  public:
    ServerCredentials(const std::string& cert_path, const std::string& key_path) : cert_(cert_path)
    {
        Botan::DataSource_Stream key_src(key_path);
        key_.reset(Botan::PKCS8::load_key(key_src).release());
    }
    std::vector<Botan::X509_Certificate>
    find_cert_chain(const std::vector<std::string>&, const std::vector<Botan::AlgorithmIdentifier>&,
                    const std::vector<Botan::X509_DN>&, const std::string& type,
                    const std::string&) override
    {
        return type == "tls-server" ? std::vector{cert_} : std::vector<Botan::X509_Certificate>{};
    }
    std::shared_ptr<Botan::Private_Key> private_key_for(const Botan::X509_Certificate&,
                                                        const std::string& type,
                                                        const std::string&) override
    {
        return type == "tls-server" ? key_ : nullptr;
    }
};

class ServerTlsPolicy : public Botan::TLS::Policy
{
    bool allow_tls12_;

  public:
    explicit ServerTlsPolicy(bool allow_tls12) : allow_tls12_(allow_tls12) {}
    bool allow_tls12() const override { return allow_tls12_; }
    std::vector<std::string> allowed_signature_methods() const override
    {
        return {"ECDSA", "RSA", "Ed25519"};
    }
    std::vector<std::string> allowed_signature_hashes() const override
    {
        return {"SHA-512", "SHA-384", "SHA-256", "Pure"};
    }
};

static void ensure_server_cert(const Config& cfg)
{
    std::ifstream k(cfg.key_path), c(cfg.cert_path);
    if (k.good() && c.good())
        return;

    Botan::AutoSeeded_RNG rng;
    std::unique_ptr<Botan::Private_Key> key;

    if (cfg.cert_algorithm == "ECDSA-P384") {
        key =
            std::make_unique<Botan::ECDSA_PrivateKey>(rng, Botan::EC_Group::from_name("secp384r1"));
    } else if (cfg.cert_algorithm == "Ed25519") {
        key = std::make_unique<Botan::Ed25519_PrivateKey>(rng);
    } else {
        key =
            std::make_unique<Botan::ECDSA_PrivateKey>(rng, Botan::EC_Group::from_name("secp256r1"));
    }

    Botan::X509_Cert_Options opts;
    opts.common_name = "ZeroTraceMsg";

    auto now_t = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    auto exp_t = now_t + static_cast<std::time_t>(cfg.cert_validity_days) * 86400LL;
    opts.not_before(format_cert_date(now_t));
    opts.not_after(format_cert_date(exp_t));

    std::string cert_hash = (cfg.cert_algorithm == "Ed25519") ? "SHA-512" : "SHA-256";
    auto cert = Botan::X509::create_self_signed_cert(opts, *key, cert_hash, rng);

    std::ofstream kf(cfg.key_path);
    kf << Botan::PKCS8::PEM_encode(*key);
    std::ofstream cf(cfg.cert_path);
    cf << cert.PEM_encode();

    LOG_INFO("[TLS] Generated self-signed certificate: " + cfg.cert_path);
}

void start_server_tls(const Config& cfg_init, const std::string& config_path)
{
    Config cfg = cfg_init;
    log_init(cfg);
    g_start_time = now_unix();
    g_config_path = config_path;

    {
        std::lock_guard<std::mutex> lock(store_mutex);
        if (!g_store)
            g_store = std::make_unique<Store>(cfg.db_path);
    }

    signal(SIGTERM, handle_signal);
    signal(SIGINT, handle_signal);
    signal(SIGHUP, handle_signal);
    signal(SIGUSR1, handle_signal);

    mkdir("certs", 0700);
    ensure_server_cert(cfg);

    auto creds = std::make_shared<ServerCredentials>(cfg.cert_path, cfg.key_path);
    bool tls12 = (cfg.tls_min_version == "1.2");
    auto policy = std::make_shared<ServerTlsPolicy>(tls12);

    int server_fd = make_listening_socket(cfg.server_port, cfg.server_bind);
    if (server_fd < 0)
        return;
    LOG_INFO("[*] Server listening on " + cfg.server_bind + ":" + std::to_string(cfg.server_port) +
             " (TLS " + cfg.tls_min_version + "+)");
    std::thread([cfg]() { cleanup_thread(cfg); }).detach();

    struct pollfd pfd = {server_fd, POLLIN, 0};
    while (!g_shutdown.load()) {
        // SIGHUP: hot-reload mutable config fields without restarting
        if (g_reload_config.exchange(false) && !g_config_path.empty()) {
            try {
                Config nc = Config::load(g_config_path);
                cfg.log_level = nc.log_level;
                cfg.log_format = nc.log_format;
                cfg.rate_limit_msgs = nc.rate_limit_msgs;
                cfg.rate_limit_window_s = nc.rate_limit_window_s;
                cfg.session_ttl_hours = nc.session_ttl_hours;
                cfg.msg_ttl_hours = nc.msg_ttl_hours;
                cfg.max_connections = nc.max_connections;
                {
                    std::lock_guard<std::mutex> lk(g_log_mutex);
                    g_log_json = (cfg.log_format == "json");
                    if (cfg.log_level == "debug")
                        g_log_level = 0;
                    else if (cfg.log_level == "info")
                        g_log_level = 1;
                    else if (cfg.log_level == "warn")
                        g_log_level = 2;
                    else
                        g_log_level = 3;
                }
                LOG_INFO("[SIGHUP] Config reloaded from " + g_config_path);
            } catch (const std::exception& e) {
                LOG_WARN("[SIGHUP] Config reload failed: " + std::string(e.what()));
            }
        }

        // SIGUSR1: reopen log file (for logrotate integration)
        if (g_log_reopen.exchange(false)) {
            std::lock_guard<std::mutex> lk(g_log_mutex);
            if (g_log_file.is_open()) {
                g_log_file.close();
                g_log_file.open(cfg.log_file, std::ios::app);
            }
            LOG_INFO("[SIGUSR1] Log file reopened");
        }

        int r = poll(&pfd, 1, 1000); // 1 s timeout to check shutdown / reload flags
        if (r < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        if (r == 0)
            continue;

        if (cfg.max_connections > 0 && g_active_connections.load() >= cfg.max_connections) {
            int cfd = accept(server_fd, nullptr, nullptr);
            if (cfd >= 0) {
                LOG_WARN("[CONNECT] rejected (max_connections=" +
                         std::to_string(cfg.max_connections) + " reached)");
                close(cfd);
            }
            continue;
        }

        int cfd = accept(server_fd, nullptr, nullptr);
        if (cfd < 0)
            continue;

        g_active_connections.fetch_add(1);
        std::thread([cfd, creds, policy, cfg]() {
            struct Guard {
                ~Guard() { g_active_connections.fetch_sub(1); }
            } guard;
            auto rng_ptr = std::make_shared<Botan::AutoSeeded_RNG>();
            auto cb = std::make_shared<SocketTlsCallbacks>(cfd);
            auto sess_mgr = std::make_shared<Botan::TLS::Session_Manager_Noop>();
            auto tls = std::make_shared<Botan::TLS::Server>(
                cb, sess_mgr, creds, policy,
                std::shared_ptr<Botan::RandomNumberGenerator>(rng_ptr));
            handle_client(
                cfd, [tls](const std::string& s) { tls_send_line(*tls, s); },
                [cfd, tls, cb]() { return tls_read_line(cfd, *tls, *cb); }, cfg);
        }).detach();
    }

    LOG_INFO("[*] Server shut down gracefully.");
    close(server_fd);
}

void reset_server_state()
{
    std::lock_guard<std::mutex> lock(store_mutex);
    if (g_store) {
        g_store->clear_all();
    } else {
        g_store = std::make_unique<Store>("");
    }
}
