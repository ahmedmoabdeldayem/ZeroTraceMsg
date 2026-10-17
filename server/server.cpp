// ZeroTraceMsg Server — core logic
// Extracted from main.cpp so tests can link against it.

#include "server.hpp"
#include "../common/identity.hpp"
#include "../common/protocol.hpp"
#include "../common/tls_utils.hpp"
#include <algorithm>
#include <atomic>
#include <botan/auto_rng.h>
#include <botan/data_src.h>
#include <botan/ec_group.h>
#include <botan/ecdsa.h>
#include <botan/hex.h>
#include <botan/pkcs8.h>
#include <botan/tls_session_manager_noop.h>
#include <botan/x509self.h>
#include <chrono>
#include <fstream>
#include <functional>
#include <iostream>
#include <map>
#include <mutex>
#include <netinet/in.h>
#include <sstream>
#include <string>
#include <sys/socket.h>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>
#include <vector>

static bool ct_equal(const uint8_t* a, const uint8_t* b, size_t len)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < len; ++i)
        diff |= a[i] ^ b[i];
    return diff == 0;
}

struct PendingMessage {
    std::string id;
    std::string sender_id;
    std::vector<uint8_t> blob;
    int64_t timestamp;
};

struct RateBucket {
    int count{0};
    int64_t window_start{0};
};

static std::map<std::string, std::vector<uint8_t>> pubkeys;
static std::map<std::string, std::vector<PendingMessage>> messages;
static std::map<std::string, std::string> tokens;
static std::map<std::string, RateBucket> rate_buckets;
static std::map<std::string, int>
    delivery_acks; // sender_id → count of messages delivered to recipients
static std::mutex store_mutex;

static std::string new_message_id()
{
    static std::atomic<uint64_t> counter{1};
    std::ostringstream ss;
    ss << std::hex << counter.fetch_add(1);
    return ss.str();
}

static int64_t now_unix()
{
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

// -------------------------------------------------------
// Protocol handler — I/O is injected via lambdas so the
// same logic runs over both plain TCP (tests) and TLS.
// -------------------------------------------------------
using SendFn = std::function<void(const std::string&)>;
using RecvFn = std::function<std::string()>;

static void handle_client(int client_fd, SendFn sl, RecvFn rl)
{
    Botan::AutoSeeded_RNG rng;
    std::cout << "[CONNECT]  client connected (fd=" << client_fd << ")\n";

    while (true) {
        std::string line = rl();
        if (line.empty())
            break;

        std::istringstream ss(line);
        std::string cmd;
        ss >> cmd;

        if (cmd == "REGISTER") {
            std::string user_id, pubkey_hex;
            ss >> user_id >> pubkey_hex;
            try {
                auto pubkey = Botan::hex_decode(pubkey_hex);
                std::string expected_id = derive_user_id(pubkey);
                if (expected_id != user_id) {
                    sl("ERR user_id does not match pubkey");
                    continue;
                }
                std::lock_guard<std::mutex> lock(store_mutex);
                auto existing = pubkeys.find(user_id);
                if (existing != pubkeys.end() && existing->second != pubkey) {
                    sl("ERR user_id already registered with a different key");
                    continue;
                }
                auto token_bytes = rng.random_vec(32);
                std::string token = Botan::hex_encode(token_bytes);
                pubkeys[user_id] = pubkey;
                tokens[user_id] = token;
                sl("OK " + token);
                std::cout << "[REGISTER] user=" << user_id << " total_users=" << pubkeys.size()
                          << "\n";
            } catch (...) {
                sl("ERR invalid pubkey");
            }

        } else if (cmd == "GETKEY") {
            std::string user_id;
            ss >> user_id;
            std::lock_guard<std::mutex> lock(store_mutex);
            auto it = pubkeys.find(user_id);
            if (it == pubkeys.end()) {
                sl("ERR unknown user");
            } else {
                sl("OK " + Botan::hex_encode(it->second));
            }

        } else if (cmd == "SEND") {
            std::string sender_id, token, recipient_id, blob_hex;
            ss >> sender_id >> token >> recipient_id >> blob_hex;
            std::lock_guard<std::mutex> lock(store_mutex);
            auto tok_it = tokens.find(sender_id);
            bool sender_valid =
                tok_it != tokens.end() && tok_it->second.size() == token.size() &&
                ct_equal(reinterpret_cast<const uint8_t*>(tok_it->second.data()),
                         reinterpret_cast<const uint8_t*>(token.data()), tok_it->second.size());
            if (!sender_valid) {
                sl("ERR invalid token");
                continue;
            }
            {
                auto& bucket = rate_buckets[sender_id];
                int64_t now = now_unix();
                if (now - bucket.window_start >= RATE_LIMIT_WINDOW_S) {
                    bucket.count = 0;
                    bucket.window_start = now;
                }
                if (bucket.count >= RATE_LIMIT_MSGS) {
                    sl("ERR rate limit exceeded");
                    continue;
                }
                bucket.count++;
            }
            if (pubkeys.find(recipient_id) == pubkeys.end()) {
                sl("ERR unknown recipient");
                continue;
            }
            try {
                auto blob = Botan::hex_decode(blob_hex);
                if (blob.size() > MAX_BLOB_LEN) {
                    sl("ERR blob too large");
                    continue;
                }
                std::string msg_id = new_message_id();
                messages[recipient_id].push_back({msg_id, sender_id, blob, now_unix()});
                sl("OK");
                std::cout << "[SEND]     to=" << recipient_id << " msg_id=" << msg_id
                          << " blob=" << blob.size() << " bytes"
                          << " (server cannot read content)\n";
            } catch (...) {
                sl("ERR invalid blob");
            }

        } else if (cmd == "POLL") {
            std::string user_id, token;
            ss >> user_id >> token;
            std::lock_guard<std::mutex> lock(store_mutex);
            auto tok_it = tokens.find(user_id);
            bool token_valid =
                tok_it != tokens.end() && tok_it->second.size() == token.size() &&
                ct_equal(reinterpret_cast<const uint8_t*>(tok_it->second.data()),
                         reinterpret_cast<const uint8_t*>(token.data()), tok_it->second.size());
            if (!token_valid) {
                sl("ERR invalid token");
                std::cout << "[POLL]     user=" << user_id << " -> REJECTED invalid token\n";
                continue;
            }
            auto msg_it = messages.find(user_id);
            if (msg_it != messages.end() && !msg_it->second.empty()) {
                size_t count = msg_it->second.size();
                for (auto& msg : msg_it->second) {
                    sl("MSG " + msg.id + " " + Botan::hex_encode(msg.blob));
                    delivery_acks[msg.sender_id]++;
                }
                msg_it->second.clear();
                std::cout << "[POLL]     user=" << user_id << " -> delivered " << count
                          << " message(s), wiped from store\n";
            }
            auto ack_it = delivery_acks.find(user_id);
            if (ack_it != delivery_acks.end() && ack_it->second > 0) {
                sl("ACK " + std::to_string(ack_it->second));
                ack_it->second = 0;
            }
            sl("NOMSG");

        } else {
            sl("ERR unknown command");
        }
    }

    std::cout << "[DISCONNECT] client disconnected (fd=" << client_fd << ")\n";
    close(client_fd);
}

static void cleanup_thread()
{
    while (true) {
        std::this_thread::sleep_for(std::chrono::minutes(10));
        int64_t cutoff = now_unix() - MSG_TTL_SERVER_S;
        std::lock_guard<std::mutex> lock(store_mutex);
        for (auto& [uid, msgs] : messages) {
            msgs.erase(
                std::remove_if(msgs.begin(), msgs.end(),
                               [cutoff](const PendingMessage& m) { return m.timestamp < cutoff; }),
                msgs.end());
        }
    }
}

static int make_listening_socket(int port)
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
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(static_cast<uint16_t>(port));
    if (bind(server_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        perror("bind");
        return -1;
    }
    listen(server_fd, 16);
    return server_fd;
}

// -------------------------------------------------------
// Plain TCP server — used by the test suite
// -------------------------------------------------------
void start_server(int port)
{
    int server_fd = make_listening_socket(port);
    if (server_fd < 0)
        return;
    std::cout << "[*] Server listening on port " << port << " (plain TCP)\n";
    std::thread(cleanup_thread).detach();

    while (true) {
        int cfd = accept(server_fd, nullptr, nullptr);
        if (cfd < 0)
            continue;
        std::thread([cfd]() {
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
                });
        }).detach();
    }
}

// -------------------------------------------------------
// TLS infrastructure — production server
// -------------------------------------------------------

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
        if (type == "tls-server")
            return {cert_};
        return {};
    }

    std::shared_ptr<Botan::Private_Key> private_key_for(const Botan::X509_Certificate&,
                                                        const std::string& type,
                                                        const std::string&) override
    {
        if (type == "tls-server")
            return key_;
        return nullptr;
    }
};

static void ensure_server_cert(const std::string& key_path, const std::string& cert_path)
{
    std::ifstream k(key_path), c(cert_path);
    if (k.good() && c.good())
        return;

    Botan::AutoSeeded_RNG rng;
    Botan::ECDSA_PrivateKey key(rng, Botan::EC_Group::from_name("secp256r1"));

    Botan::X509_Cert_Options opts;
    opts.common_name = "ZeroTraceMsg";
    opts.not_before("20240101000000Z");
    opts.not_after("20340101000000Z");
    auto cert = Botan::X509::create_self_signed_cert(opts, key, "SHA-256", rng);

    std::ofstream kf(key_path);
    kf << Botan::PKCS8::PEM_encode(key);

    std::ofstream cf(cert_path);
    cf << cert.PEM_encode();

    std::cout << "[TLS] Generated self-signed certificate: " << cert_path << "\n";
}

// -------------------------------------------------------
// TLS server — production entrypoint
// -------------------------------------------------------
void start_server_tls(int port)
{
    mkdir("certs", 0700);
    const std::string key_path = "certs/server.key.pem";
    const std::string cert_path = "certs/server.cert.pem";
    ensure_server_cert(key_path, cert_path);

    auto creds = std::make_shared<ServerCredentials>(cert_path, key_path);
    auto policy = std::make_shared<Botan::TLS::Policy>();

    int server_fd = make_listening_socket(port);
    if (server_fd < 0)
        return;
    std::cout << "[*] Server listening on port " << port << " (TLS)\n";
    std::thread(cleanup_thread).detach();

    while (true) {
        int cfd = accept(server_fd, nullptr, nullptr);
        if (cfd < 0)
            continue;

        std::thread([cfd, creds, policy]() {
            auto rng = std::make_shared<Botan::AutoSeeded_RNG>();
            auto cb = std::make_shared<SocketTlsCallbacks>(cfd);
            auto session_mgr = std::make_shared<Botan::TLS::Session_Manager_Noop>();

            auto tls = std::make_shared<Botan::TLS::Server>(
                cb, session_mgr, creds, policy, std::shared_ptr<Botan::RandomNumberGenerator>(rng));

            handle_client(
                cfd, [tls](const std::string& s) { tls_send_line(*tls, s); },
                [cfd, tls, cb]() { return tls_read_line(cfd, *tls, *cb); });
        }).detach();
    }
}

void reset_server_state()
{
    std::lock_guard<std::mutex> lock(store_mutex);
    pubkeys.clear();
    messages.clear();
    tokens.clear();
    rate_buckets.clear();
    delivery_acks.clear();
}
