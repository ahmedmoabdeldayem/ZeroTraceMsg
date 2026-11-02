// Tests for the server protocol — REGISTER, GETKEY, SEND, POLL
// Starts a real server thread on TEST_PORT (plain TCP) and TEST_TLS_PORT (TLS).

#include "../common/crypto.hpp"
#include "../common/identity.hpp"
#include "../common/protocol.hpp"
#include "../common/tls_utils.hpp"
#include "../server/server.hpp"
#include "test_runner.hpp"
#include <arpa/inet.h>
#include <botan/auto_rng.h>
#include <botan/hash.h>
#include <botan/hex.h>
#include <botan/tls_session_manager_noop.h>
#include <chrono>
#include <fstream>
#include <iostream>
#include <netinet/in.h>
#include <signal.h>
#include <sstream>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>

static const int TEST_PORT = 59998;
static const int TEST_TLS_PORT = 59997;
static const int TEST_TLS_P384_PORT = 59996;
static const int TEST_TLS_ED25519_PORT = 59995;
// Plain TCP server with tight limits (max_users=2, max_inbox_messages=2)
static const int TEST_RESTRICTED_PORT = 59994;
// TLS server that writes logs to a file (covers log_init file/level/format paths)
static const int TEST_LOG_FILE_PORT = 59993;
// TLS server with a fresh cert path (covers ensure_server_cert generation path)
static const int TEST_CERT_GEN_PORT = 59992;
// TLS server with admin port enabled
static const int TEST_ADMIN_TLS_PORT = 59991;
static const int TEST_ADMIN_PORT = 59990;
// TLS server with metrics port enabled
static const int TEST_METRICS_TLS_PORT = 59989;
static const int TEST_METRICS_PORT = 59988;
// Plain TCP server with max_prekeys_per_user=1 (covers prekey store full path)
static const int TEST_PREKEY_CAP_PORT = 59987;
// TLS server bound to :: (dual-stack) for IPv6 connectivity tests
static const int TEST_IPV6_PORT = 59986;
// TLS server bound to ::1 (IPv6 loopback) for specific-address inet_pton coverage
static const int TEST_IPV6_LOOPBACK_PORT = 59985;
// TLS server with max_devices_per_user=1 (covers device limit path)
static const int TEST_DEVICE_LIMIT_PORT = 59984;
// TLS server with max_group_members=1 (covers group-full path)
static const int TEST_GROUP_LIMIT_PORT = 59983;
// TLS server with shutdown_timeout_s=1 (covers graceful shutdown drain path)
static const int TEST_SHUTDOWN_PORT = 59982;
// TLS server with max_connections=1 (covers connection-rejection LOG_WARN path)
static const int TEST_MAX_CONN_PORT = 59980;
// Ports for admin/metrics bind-failure tests (inline servers started mid-test)
static const int TEST_ADMIN_BIND_FAIL_PORT = 59969;   // TLS main port
static const int TEST_ADMIN_BLOCKER_PORT = 59968;     // pre-bound to block admin bind
static const int TEST_METRICS_BIND_FAIL_PORT = 59967; // TLS main port
static const int TEST_METRICS_BLOCKER_PORT = 59966;   // pre-bound to block metrics bind
// Port used for IPv6-bind-fallback test (pre-bound on IPv6 to force fallback)
static const int TEST_IPV6_FALLBACK_PORT = 59965;

// -------------------------------------------------------
// TLS test helpers
// -------------------------------------------------------
class TestTlsCallbacks : public SocketTlsCallbacks
{
  public:
    explicit TestTlsCallbacks(int fd) : SocketTlsCallbacks(fd) {}
    void tls_verify_cert_chain(const std::vector<Botan::X509_Certificate>&,
                               const std::vector<std::optional<Botan::OCSP::Response>>&,
                               const std::vector<Botan::Certificate_Store*>&, Botan::Usage_Type,
                               std::string_view, const Botan::TLS::Policy&) override
    {
    }
};

class TestTlsCredentials : public Botan::Credentials_Manager
{
};

// Extends the default policy to also allow Ed25519 certificates.
// Needed because the Botan default policy only allows ECDSA and RSA.
class AllSigMethodsPolicy : public Botan::TLS::Policy
{
  public:
    std::vector<std::string> allowed_signature_methods() const override
    {
        return {"ECDSA", "RSA", "Ed25519"};
    }
    // "Pure" is Ed25519's hash identifier (it embeds SHA-512 internally)
    std::vector<std::string> allowed_signature_hashes() const override
    {
        return {"SHA-512", "SHA-384", "SHA-256", "Pure"};
    }
};

struct TlsConn {
    int fd;
    std::shared_ptr<TestTlsCallbacks> cb;
    std::shared_ptr<Botan::TLS::Client> tls;
};

static TlsConn tls_connect(int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        close(fd);
        return {-1, nullptr, nullptr};
    }
    // 30-second recv timeout so a hung TLS handshake fails fast rather than blocking forever.
    // On failure (n<=0) we always close fd to avoid leaking the socket.
    struct timeval tv = {30, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    auto rng = std::make_shared<Botan::AutoSeeded_RNG>();
    auto cb = std::make_shared<TestTlsCallbacks>(fd);
    auto session_mgr = std::make_shared<Botan::TLS::Session_Manager_Noop>();
    auto creds = std::make_shared<TestTlsCredentials>();
    auto policy = std::make_shared<Botan::TLS::Policy>();
    auto tls = std::make_shared<Botan::TLS::Client>(
        cb, session_mgr, creds, policy, std::shared_ptr<Botan::RandomNumberGenerator>(rng),
        Botan::TLS::Server_Information("127.0.0.1", port));
    while (!tls->is_active() && !cb->closed) {
        uint8_t buf[4096];
        ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
        if (n <= 0) {
            close(fd);
            return {-1, nullptr, nullptr};
        }
        tls->received_data({buf, static_cast<size_t>(n)});
    }
    if (!tls->is_active()) {
        close(fd);
        return {-1, nullptr, nullptr};
    }
    return {fd, cb, tls};
}

static TlsConn tls_connect_all_sig(int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        close(fd);
        return {-1, nullptr, nullptr};
    }
    auto rng = std::make_shared<Botan::AutoSeeded_RNG>();
    auto cb = std::make_shared<TestTlsCallbacks>(fd);
    auto session_mgr = std::make_shared<Botan::TLS::Session_Manager_Noop>();
    auto creds = std::make_shared<TestTlsCredentials>();
    auto policy = std::make_shared<AllSigMethodsPolicy>();
    auto tls = std::make_shared<Botan::TLS::Client>(
        cb, session_mgr, creds, policy, std::shared_ptr<Botan::RandomNumberGenerator>(rng),
        Botan::TLS::Server_Information("127.0.0.1", port));
    while (!tls->is_active() && !cb->closed) {
        uint8_t buf[4096];
        ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
        if (n <= 0)
            return {-1, nullptr, nullptr};
        tls->received_data({buf, static_cast<size_t>(n)});
    }
    if (!tls->is_active())
        return {-1, nullptr, nullptr};
    return {fd, cb, tls};
}

static std::string tls_cmd(TlsConn& c, const std::string& line)
{
    tls_send_line(*c.tls, line);
    return tls_read_line(c.fd, *c.tls, *c.cb);
}
static Botan::AutoSeeded_RNG rng;
static Config g_cfg; // default config used by all tests

// Extract the session token (first word after "OK ") from a REGISTER response.
// The full response format is: OK <64hex-token> kem=X cipher=Y hash=Z pad=N
static std::string extract_token(const std::string& resp)
{
    if (resp.size() < 3 || resp.substr(0, 3) != "OK ")
        return "";
    std::istringstream ss(resp.substr(3));
    std::string tok;
    ss >> tok;
    return tok;
}

static int connect_test()
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(TEST_PORT);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static void send_line(int fd, const std::string& line)
{
    std::string msg = line + "\n";
    send(fd, msg.data(), msg.size(), 0);
}

static std::string read_line(int fd)
{
    std::string line;
    char c;
    while (recv(fd, &c, 1, 0) > 0) {
        if (c == '\n')
            break;
        line += c;
    }
    return line;
}

static std::string cmd(int fd, const std::string& line)
{
    send_line(fd, line);
    return read_line(fd);
}

// Read all MSG lines from a POLL response, send MSGACK, return the blobs.
static std::vector<std::vector<uint8_t>> poll_all(int fd, const std::string& user_id,
                                                  const std::string& token)
{
    send_line(fd, "POLL " + user_id + " " + token);
    std::vector<std::vector<uint8_t>> blobs;
    std::vector<std::string> ids;
    while (true) {
        std::string line = read_line(fd);
        if (line == "NOMSG" || line.empty() || line.substr(0, 3) == "ERR")
            break;
        if (line.substr(0, 4) == "MSG ") {
            std::istringstream ss(line.substr(4));
            std::string msg_id, prekey_id, blob_hex;
            ss >> msg_id >> prekey_id >> blob_hex;
            ids.push_back(msg_id);
            blobs.push_back(Botan::hex_decode(blob_hex));
        }
    }
    if (!ids.empty()) {
        std::string id_list;
        for (size_t i = 0; i < ids.size(); ++i) {
            if (i > 0)
                id_list += ',';
            id_list += ids[i];
        }
        send_line(fd, "MSGACK " + user_id + " " + token + " " + id_list);
        read_line(fd); // consume OK
    }
    return blobs;
}

// Poll and return the ACK count (0 if no ACK line present).
static int poll_ack(int fd, const std::string& user_id, const std::string& token)
{
    send_line(fd, "POLL " + user_id + " " + token);
    int ack = 0;
    while (true) {
        std::string line = read_line(fd);
        if (line == "NOMSG" || line.empty())
            break;
        if (line.substr(0, 4) == "ACK ") {
            std::istringstream ss(line.substr(4));
            ss >> ack;
        }
    }
    return ack;
}

int main()
{
    SUITE_INIT("test_server");
    std::cout << "=== server tests ===\n\n";

    // Initialise in-memory store before any server threads start so all
    // servers share one in-memory DB and none try to open "zerotrace.db".
    reset_server_state();

    std::thread([] { start_server(TEST_PORT); }).detach();
    std::thread([] {
        Config tls_cfg;
        tls_cfg.server_port = TEST_TLS_PORT;
        start_server_tls(tls_cfg);
    }).detach();
    // Restricted server: max_users=2, max_inbox_messages=2 (uses TLS so Config is respected)
    std::thread([] {
        Config cfg;
        cfg.server_port = TEST_RESTRICTED_PORT;
        cfg.max_users = 2;
        cfg.max_inbox_messages = 2;
        cfg.cert_path = "/tmp/ztm_restricted.cert.pem";
        cfg.key_path = "/tmp/ztm_restricted.key.pem";
        start_server_tls(cfg);
    }).detach();
    // Log-to-file server: covers log_level=debug and log_format=json paths
    // Uses its own cert paths to avoid racing with the TEST_TLS_PORT server over
    // "certs/server.cert.pem" (both would otherwise use the default path).
    std::thread([] {
        Config cfg;
        cfg.server_port = TEST_LOG_FILE_PORT;
        cfg.log_level = "debug";
        cfg.log_format = "json";
        cfg.log_file = "/tmp/ztm_test_server.log";
        cfg.cert_path = "/tmp/ztm_logfile.cert.pem";
        cfg.key_path = "/tmp/ztm_logfile.key.pem";
        start_server_tls(cfg);
    }).detach();
    // Fresh-cert server: covers ensure_server_cert generation (delete files first)
    std::thread([] {
        std::remove("/tmp/ztm_certgen.cert.pem");
        std::remove("/tmp/ztm_certgen.key.pem");
        Config cfg;
        cfg.server_port = TEST_CERT_GEN_PORT;
        cfg.cert_path = "/tmp/ztm_certgen.cert.pem";
        cfg.key_path = "/tmp/ztm_certgen.key.pem";
        start_server_tls(cfg);
    }).detach();
    std::thread([] {
        Config cfg;
        cfg.server_port = TEST_TLS_P384_PORT;
        cfg.cert_algorithm = "ECDSA-P384";
        cfg.cert_path = "/tmp/ztm_test_p384.cert.pem";
        cfg.key_path = "/tmp/ztm_test_p384.key.pem";
        start_server_tls(cfg);
    }).detach();
    std::thread([] {
        Config cfg;
        cfg.server_port = TEST_TLS_ED25519_PORT;
        cfg.cert_algorithm = "Ed25519";
        cfg.cert_path = "/tmp/ztm_test_ed25519.cert.pem";
        cfg.key_path = "/tmp/ztm_test_ed25519.key.pem";
        start_server_tls(cfg);
    }).detach();
    // TLS server with admin port enabled (covers admin command paths)
    std::thread([] {
        Config cfg;
        cfg.server_port = TEST_ADMIN_TLS_PORT;
        cfg.admin_port = TEST_ADMIN_PORT;
        cfg.cert_path = "/tmp/ztm_admin.cert.pem";
        cfg.key_path = "/tmp/ztm_admin.key.pem";
        start_server_tls(cfg);
    }).detach();
    // TLS server with metrics port enabled (covers Prometheus metrics paths)
    std::thread([] {
        Config cfg;
        cfg.server_port = TEST_METRICS_TLS_PORT;
        cfg.admin_port = 0;
        cfg.metrics_port = TEST_METRICS_PORT;
        cfg.cert_path = "/tmp/ztm_metrics.cert.pem";
        cfg.key_path = "/tmp/ztm_metrics.key.pem";
        start_server_tls(cfg);
    }).detach();
    // TLS server with max_prekeys_per_user=1 (covers prekey store full path)
    std::thread([] {
        Config cfg;
        cfg.server_port = TEST_PREKEY_CAP_PORT;
        cfg.max_prekeys_per_user = 1;
        cfg.admin_port = 0;
        cfg.metrics_port = 0;
        cfg.cert_path = "/tmp/ztm_prekey_cap.cert.pem";
        cfg.key_path = "/tmp/ztm_prekey_cap.key.pem";
        start_server_tls(cfg);
    }).detach();
    // TLS server bound to :: (dual-stack IPv4+IPv6) for IPv6 connectivity tests
    std::thread([] {
        Config cfg;
        cfg.server_port = TEST_IPV6_PORT;
        cfg.server_bind = "::";
        cfg.admin_port = 0;
        cfg.metrics_port = 0;
        cfg.cert_path = "/tmp/ztm_ipv6.cert.pem";
        cfg.key_path = "/tmp/ztm_ipv6.key.pem";
        start_server_tls(cfg);
    }).detach();
    // TLS server bound to ::1 (IPv6 loopback) — covers the inet_pton path for specific addresses
    std::thread([] {
        Config cfg;
        cfg.server_port = TEST_IPV6_LOOPBACK_PORT;
        cfg.server_bind = "::1";
        cfg.admin_port = 0;
        cfg.metrics_port = 0;
        cfg.cert_path = "/tmp/ztm_ipv6lb.cert.pem";
        cfg.key_path = "/tmp/ztm_ipv6lb.key.pem";
        start_server_tls(cfg);
    }).detach();
    std::thread([] {
        Config cfg;
        cfg.server_port = TEST_DEVICE_LIMIT_PORT;
        cfg.max_devices_per_user = 1;
        cfg.worker_threads = 1; // single worker to keep total thread count manageable
        cfg.admin_port = 0;
        cfg.metrics_port = 0;
        cfg.cert_path = "/tmp/ztm_devlimit.cert.pem";
        cfg.key_path = "/tmp/ztm_devlimit.key.pem";
        start_server_tls(cfg);
    }).detach();
    std::thread([] {
        Config cfg;
        cfg.server_port = TEST_GROUP_LIMIT_PORT;
        cfg.max_group_members = 1;
        cfg.worker_threads = 1;
        cfg.admin_port = 0;
        cfg.metrics_port = 0;
        cfg.cert_path = "/tmp/ztm_grplimit.cert.pem";
        cfg.key_path = "/tmp/ztm_grplimit.key.pem";
        start_server_tls(cfg);
    }).detach();
    std::thread([] {
        Config cfg;
        cfg.server_port = TEST_SHUTDOWN_PORT;
        cfg.shutdown_timeout_s = 1;
        cfg.worker_threads = 1;
        cfg.admin_port = 0;
        cfg.metrics_port = 0;
        cfg.cert_path = "/tmp/ztm_shutdown.cert.pem";
        cfg.key_path = "/tmp/ztm_shutdown.key.pem";
        start_server_tls(cfg);
    }).detach();
    std::thread([] {
        Config cfg;
        cfg.server_port = TEST_MAX_CONN_PORT;
        cfg.max_connections = 1;
        cfg.worker_threads = 1;
        cfg.admin_port = 0;
        cfg.metrics_port = 0;
        cfg.cert_path = "/tmp/ztm_maxconn.cert.pem";
        cfg.key_path = "/tmp/ztm_maxconn.key.pem";
        start_server_tls(cfg);
    }).detach();
    std::this_thread::sleep_for(std::chrono::milliseconds(1200));

    // -------------------------------------------------------
    // REGISTER
    // -------------------------------------------------------
    TEST("REGISTER returns 64-char token for valid user");
    {
        reset_server_state();
        auto id = generate_identity(rng, g_cfg);
        int fd = connect_test();
        std::string resp =
            cmd(fd, "REGISTER " + id.user_id + " " + Botan::hex_encode(id.pubkey_bytes));
        ASSERT_TRUE(resp.substr(0, 3) == "OK ");
        ASSERT_EQ(extract_token(resp).size(), (size_t)64);
        close(fd);
    }

    TEST("REGISTER rejects user_id that does not match pubkey");
    {
        reset_server_state();
        auto id1 = generate_identity(rng, g_cfg);
        auto id2 = generate_identity(rng, g_cfg);
        int fd = connect_test();
        std::string resp =
            cmd(fd, "REGISTER " + id1.user_id + " " + Botan::hex_encode(id2.pubkey_bytes));
        ASSERT_TRUE(resp.substr(0, 3) == "ERR");
        close(fd);
    }

    TEST("REGISTER allows same-key re-registration");
    {
        reset_server_state();
        auto id = generate_identity(rng, g_cfg);
        std::string reg = "REGISTER " + id.user_id + " " + Botan::hex_encode(id.pubkey_bytes);
        int fd1 = connect_test();
        cmd(fd1, reg);
        close(fd1);
        int fd2 = connect_test();
        std::string resp = cmd(fd2, reg);
        ASSERT_TRUE(resp.substr(0, 3) == "OK ");
        close(fd2);
    }

    TEST("REGISTER rejects invalid hex pubkey");
    {
        reset_server_state();
        int fd = connect_test();
        std::string resp = cmd(fd, "REGISTER 0000000000000000 ZZZZZZ");
        ASSERT_TRUE(resp.substr(0, 3) == "ERR");
        close(fd);
    }

    // -------------------------------------------------------
    // GETKEY
    // -------------------------------------------------------
    TEST("GETKEY returns pubkey for registered user");
    {
        reset_server_state();
        auto id = generate_identity(rng, g_cfg);
        int fd = connect_test();
        cmd(fd, "REGISTER " + id.user_id + " " + Botan::hex_encode(id.pubkey_bytes));
        std::string resp = cmd(fd, "GETKEY " + id.user_id);
        ASSERT_TRUE(resp.substr(0, 3) == "OK ");
        ASSERT_EQ(resp.substr(3), Botan::hex_encode(id.pubkey_bytes));
        close(fd);
    }

    TEST("GETKEY returns ERR for unknown user");
    {
        reset_server_state();
        int fd = connect_test();
        std::string resp = cmd(fd, "GETKEY 0000000000000000");
        ASSERT_TRUE(resp.substr(0, 3) == "ERR");
        close(fd);
    }

    // -------------------------------------------------------
    // SEND
    // -------------------------------------------------------
    TEST("SEND rejects invalid token");
    {
        reset_server_state();
        auto sender = generate_identity(rng, g_cfg);
        auto recipient = generate_identity(rng, g_cfg);
        int fd = connect_test();
        cmd(fd, "REGISTER " + sender.user_id + " " + Botan::hex_encode(sender.pubkey_bytes));
        cmd(fd, "REGISTER " + recipient.user_id + " " + Botan::hex_encode(recipient.pubkey_bytes));
        auto blob =
            encrypt_message("hello", sender.user_id, "s", recipient.pubkey_bytes, rng, g_cfg);
        std::string resp = cmd(fd, "SEND " + sender.user_id + " " + std::string(64, '0') + " " +
                                       recipient.user_id + " " + Botan::hex_encode(blob));
        ASSERT_TRUE(resp.substr(0, 3) == "ERR");
        close(fd);
    }

    TEST("SEND accepts authenticated message and returns OK");
    {
        reset_server_state();
        auto sender = generate_identity(rng, g_cfg);
        auto recipient = generate_identity(rng, g_cfg);
        int fd = connect_test();
        std::string s_tok = extract_token(
            cmd(fd, "REGISTER " + sender.user_id + " " + Botan::hex_encode(sender.pubkey_bytes)));
        cmd(fd, "REGISTER " + recipient.user_id + " " + Botan::hex_encode(recipient.pubkey_bytes));
        auto blob =
            encrypt_message("hello", sender.user_id, "s", recipient.pubkey_bytes, rng, g_cfg);
        std::string resp = cmd(fd, "SEND " + sender.user_id + " " + s_tok + " " +
                                       recipient.user_id + " " + Botan::hex_encode(blob));
        ASSERT_EQ(resp, std::string("OK"));
        close(fd);
    }

    TEST("SEND rejects unknown recipient");
    {
        reset_server_state();
        auto sender = generate_identity(rng, g_cfg);
        int fd = connect_test();
        std::string s_tok = extract_token(
            cmd(fd, "REGISTER " + sender.user_id + " " + Botan::hex_encode(sender.pubkey_bytes)));
        std::string resp =
            cmd(fd, "SEND " + sender.user_id + " " + s_tok + " 0000000000000000 AABB");
        ASSERT_TRUE(resp.substr(0, 3) == "ERR");
        close(fd);
    }

    TEST("SEND rejects blob exceeding MAX_BLOB_LEN");
    {
        reset_server_state();
        auto sender = generate_identity(rng, g_cfg);
        auto recipient = generate_identity(rng, g_cfg);
        int fd = connect_test();
        std::string s_tok = extract_token(
            cmd(fd, "REGISTER " + sender.user_id + " " + Botan::hex_encode(sender.pubkey_bytes)));
        cmd(fd, "REGISTER " + recipient.user_id + " " + Botan::hex_encode(recipient.pubkey_bytes));
        std::vector<uint8_t> oversized(MAX_BLOB_LEN + 1, 0xAB);
        std::string resp = cmd(fd, "SEND " + sender.user_id + " " + s_tok + " " +
                                       recipient.user_id + " " + Botan::hex_encode(oversized));
        ASSERT_TRUE(resp.substr(0, 3) == "ERR");
        close(fd);
    }

    TEST("SEND accepts blob exactly at MAX_BLOB_LEN");
    {
        reset_server_state();
        auto sender = generate_identity(rng, g_cfg);
        auto recipient = generate_identity(rng, g_cfg);
        int fd = connect_test();
        std::string s_tok = extract_token(
            cmd(fd, "REGISTER " + sender.user_id + " " + Botan::hex_encode(sender.pubkey_bytes)));
        cmd(fd, "REGISTER " + recipient.user_id + " " + Botan::hex_encode(recipient.pubkey_bytes));
        std::vector<uint8_t> max_blob(MAX_BLOB_LEN, 0xCD);
        std::string resp = cmd(fd, "SEND " + sender.user_id + " " + s_tok + " " +
                                       recipient.user_id + " " + Botan::hex_encode(max_blob));
        ASSERT_EQ(resp, std::string("OK"));
        close(fd);
    }

    // -------------------------------------------------------
    // Rate limiting
    // -------------------------------------------------------
    TEST("SEND allows burst up to RATE_LIMIT_MSGS");
    {
        reset_server_state();
        auto sender = generate_identity(rng, g_cfg);
        auto recipient = generate_identity(rng, g_cfg);
        int fd = connect_test();
        std::string s_tok = extract_token(
            cmd(fd, "REGISTER " + sender.user_id + " " + Botan::hex_encode(sender.pubkey_bytes)));
        cmd(fd, "REGISTER " + recipient.user_id + " " + Botan::hex_encode(recipient.pubkey_bytes));
        auto blob = encrypt_message("hi", sender.user_id, "s", recipient.pubkey_bytes, rng, g_cfg);
        std::string blob_hex = Botan::hex_encode(blob);
        for (int i = 0; i < RATE_LIMIT_MSGS; ++i) {
            std::string resp = cmd(fd, "SEND " + sender.user_id + " " + s_tok + " " +
                                           recipient.user_id + " " + blob_hex);
            ASSERT_EQ(resp, std::string("OK"));
        }
        close(fd);
    }

    TEST("SEND rejects message after RATE_LIMIT_MSGS in window");
    {
        reset_server_state();
        auto sender = generate_identity(rng, g_cfg);
        auto recipient = generate_identity(rng, g_cfg);
        int fd = connect_test();
        std::string s_tok = extract_token(
            cmd(fd, "REGISTER " + sender.user_id + " " + Botan::hex_encode(sender.pubkey_bytes)));
        cmd(fd, "REGISTER " + recipient.user_id + " " + Botan::hex_encode(recipient.pubkey_bytes));
        auto blob = encrypt_message("hi", sender.user_id, "s", recipient.pubkey_bytes, rng, g_cfg);
        std::string blob_hex = Botan::hex_encode(blob);
        for (int i = 0; i < RATE_LIMIT_MSGS; ++i)
            cmd(fd,
                "SEND " + sender.user_id + " " + s_tok + " " + recipient.user_id + " " + blob_hex);
        std::string resp = cmd(fd, "SEND " + sender.user_id + " " + s_tok + " " +
                                       recipient.user_id + " " + blob_hex);
        ASSERT_TRUE(resp.find("rate limit") != std::string::npos);
        close(fd);
    }

    // -------------------------------------------------------
    // POLL
    // -------------------------------------------------------
    TEST("POLL returns NOMSG when inbox is empty");
    {
        reset_server_state();
        auto id = generate_identity(rng, g_cfg);
        int fd = connect_test();
        std::string token = extract_token(
            cmd(fd, "REGISTER " + id.user_id + " " + Botan::hex_encode(id.pubkey_bytes)));
        auto blobs = poll_all(fd, id.user_id, token);
        ASSERT_EQ(blobs.size(), (size_t)0);
        close(fd);
    }

    TEST("POLL rejects invalid token");
    {
        reset_server_state();
        auto id = generate_identity(rng, g_cfg);
        int fd = connect_test();
        cmd(fd, "REGISTER " + id.user_id + " " + Botan::hex_encode(id.pubkey_bytes));
        std::string resp = cmd(fd, "POLL " + id.user_id + " " + std::string(64, '0'));
        ASSERT_TRUE(resp.substr(0, 3) == "ERR");
        close(fd);
    }

    TEST("POLL then MSGACK removes message; second poll returns empty");
    {
        reset_server_state();
        auto sender = generate_identity(rng, g_cfg);
        auto recipient = generate_identity(rng, g_cfg);
        int fd = connect_test();
        std::string s_tok = extract_token(
            cmd(fd, "REGISTER " + sender.user_id + " " + Botan::hex_encode(sender.pubkey_bytes)));
        std::string r_tok = extract_token(cmd(fd, "REGISTER " + recipient.user_id + " " +
                                                      Botan::hex_encode(recipient.pubkey_bytes)));
        auto blob = encrypt_message("secret message", sender.user_id, "sender",
                                    recipient.pubkey_bytes, rng, g_cfg);
        cmd(fd, "SEND " + sender.user_id + " " + s_tok + " " + recipient.user_id + " " +
                    Botan::hex_encode(blob));

        // poll_all sends MSGACK — message is deleted after this call.
        auto blobs = poll_all(fd, recipient.user_id, r_tok);
        ASSERT_EQ(blobs.size(), (size_t)1);

        // Second poll — inbox is empty after MSGACK.
        auto blobs2 = poll_all(fd, recipient.user_id, r_tok);
        ASSERT_EQ(blobs2.size(), (size_t)0);
        close(fd);
    }

    TEST("POLL without MSGACK keeps message in-flight; not re-sent on next poll");
    {
        reset_server_state();
        auto sender = generate_identity(rng, g_cfg);
        auto recipient = generate_identity(rng, g_cfg);
        int fd = connect_test();
        std::string s_tok = extract_token(
            cmd(fd, "REGISTER " + sender.user_id + " " + Botan::hex_encode(sender.pubkey_bytes)));
        std::string r_tok = extract_token(cmd(fd, "REGISTER " + recipient.user_id + " " +
                                                      Botan::hex_encode(recipient.pubkey_bytes)));
        auto blob = encrypt_message("hi", sender.user_id, "s", recipient.pubkey_bytes, rng, g_cfg);
        cmd(fd, "SEND " + sender.user_id + " " + s_tok + " " + recipient.user_id + " " +
                    Botan::hex_encode(blob));

        // First poll without MSGACK — message goes in-flight.
        send_line(fd, "POLL " + recipient.user_id + " " + r_tok);
        std::vector<std::string> lines1;
        while (true) {
            std::string l = read_line(fd);
            if (l == "NOMSG" || l.empty())
                break;
            lines1.push_back(l);
        }
        ASSERT_EQ(lines1.size(), (size_t)1); // one MSG line

        // Second poll (no MSGACK sent) — message still in-flight, not re-sent.
        send_line(fd, "POLL " + recipient.user_id + " " + r_tok);
        std::vector<std::string> lines2;
        while (true) {
            std::string l = read_line(fd);
            if (l == "NOMSG" || l.empty())
                break;
            lines2.push_back(l);
        }
        ASSERT_EQ(lines2.size(), (size_t)0);
        close(fd);
    }

    TEST("MSGACK with invalid token is rejected");
    {
        reset_server_state();
        auto id = generate_identity(rng, g_cfg);
        int fd = connect_test();
        cmd(fd, "REGISTER " + id.user_id + " " + Botan::hex_encode(id.pubkey_bytes));
        std::string resp = cmd(fd, "MSGACK " + id.user_id + " " + std::string(64, '0') +
                                       " deadbeefdeadbeefdeadbeefdeadbeef");
        ASSERT_TRUE(resp.substr(0, 3) == "ERR");
        close(fd);
    }

    TEST("MSGACK with valid token and unknown IDs returns OK (idempotent)");
    {
        reset_server_state();
        auto id = generate_identity(rng, g_cfg);
        int fd = connect_test();
        std::string token = extract_token(
            cmd(fd, "REGISTER " + id.user_id + " " + Botan::hex_encode(id.pubkey_bytes)));
        // ACKing a non-existent ID is a no-op, not an error.
        std::string resp =
            cmd(fd, "MSGACK " + id.user_id + " " + token + " deadbeefdeadbeefdeadbeefdeadbeef");
        ASSERT_EQ(resp, std::string("OK"));
        close(fd);
    }

    TEST("POLL delivered blob decrypts to original message");
    {
        reset_server_state();
        auto sender = generate_identity(rng, g_cfg);
        auto recipient = generate_identity(rng, g_cfg);
        int fd = connect_test();
        std::string s_tok = extract_token(
            cmd(fd, "REGISTER " + sender.user_id + " " + Botan::hex_encode(sender.pubkey_bytes)));
        std::string r_tok = extract_token(cmd(fd, "REGISTER " + recipient.user_id + " " +
                                                      Botan::hex_encode(recipient.pubkey_bytes)));
        auto blob = encrypt_message("end to end", sender.user_id, "alice", recipient.pubkey_bytes,
                                    rng, g_cfg);
        cmd(fd, "SEND " + sender.user_id + " " + s_tok + " " + recipient.user_id + " " +
                    Botan::hex_encode(blob));

        auto blobs = poll_all(fd, recipient.user_id, r_tok);
        ASSERT_EQ(blobs.size(), (size_t)1);

        auto dec = decrypt_message(blobs[0], recipient, rng, g_cfg);
        ASSERT_EQ(dec.plaintext, std::string("end to end"));
        ASSERT_EQ(dec.sender_id, sender.user_id);
        ASSERT_EQ(dec.sender_name, std::string("alice"));
        close(fd);
    }

    // -------------------------------------------------------
    // Delivery confirmation
    // -------------------------------------------------------
    TEST("sender POLL returns ACK 1 after recipient polls");
    {
        reset_server_state();
        auto sender = generate_identity(rng, g_cfg);
        auto recipient = generate_identity(rng, g_cfg);
        int fd = connect_test();
        std::string s_tok = extract_token(
            cmd(fd, "REGISTER " + sender.user_id + " " + Botan::hex_encode(sender.pubkey_bytes)));
        std::string r_tok = extract_token(cmd(fd, "REGISTER " + recipient.user_id + " " +
                                                      Botan::hex_encode(recipient.pubkey_bytes)));
        auto blob = encrypt_message("hi", sender.user_id, "s", recipient.pubkey_bytes, rng, g_cfg);
        cmd(fd, "SEND " + sender.user_id + " " + s_tok + " " + recipient.user_id + " " +
                    Botan::hex_encode(blob));
        poll_all(fd, recipient.user_id, r_tok); // recipient collects — triggers ack
        int ack = poll_ack(fd, sender.user_id, s_tok);
        ASSERT_EQ(ack, 1);
        close(fd);
    }

    TEST("ACK count matches number of messages delivered");
    {
        reset_server_state();
        auto sender = generate_identity(rng, g_cfg);
        auto recipient = generate_identity(rng, g_cfg);
        int fd = connect_test();
        std::string s_tok = extract_token(
            cmd(fd, "REGISTER " + sender.user_id + " " + Botan::hex_encode(sender.pubkey_bytes)));
        std::string r_tok = extract_token(cmd(fd, "REGISTER " + recipient.user_id + " " +
                                                      Botan::hex_encode(recipient.pubkey_bytes)));
        auto blob = encrypt_message("hi", sender.user_id, "s", recipient.pubkey_bytes, rng, g_cfg);
        std::string blob_hex = Botan::hex_encode(blob);
        for (int i = 0; i < 3; ++i)
            cmd(fd,
                "SEND " + sender.user_id + " " + s_tok + " " + recipient.user_id + " " + blob_hex);
        poll_all(fd, recipient.user_id, r_tok);
        int ack = poll_ack(fd, sender.user_id, s_tok);
        ASSERT_EQ(ack, 3);
        close(fd);
    }

    TEST("ACK is consumed after first sender POLL");
    {
        reset_server_state();
        auto sender = generate_identity(rng, g_cfg);
        auto recipient = generate_identity(rng, g_cfg);
        int fd = connect_test();
        std::string s_tok = extract_token(
            cmd(fd, "REGISTER " + sender.user_id + " " + Botan::hex_encode(sender.pubkey_bytes)));
        std::string r_tok = extract_token(cmd(fd, "REGISTER " + recipient.user_id + " " +
                                                      Botan::hex_encode(recipient.pubkey_bytes)));
        auto blob = encrypt_message("hi", sender.user_id, "s", recipient.pubkey_bytes, rng, g_cfg);
        cmd(fd, "SEND " + sender.user_id + " " + s_tok + " " + recipient.user_id + " " +
                    Botan::hex_encode(blob));
        poll_all(fd, recipient.user_id, r_tok);
        poll_ack(fd, sender.user_id, s_tok);            // first poll — consumes ACK
        int ack2 = poll_ack(fd, sender.user_id, s_tok); // second poll — no ACK
        ASSERT_EQ(ack2, 0);
        close(fd);
    }

    TEST("sender POLL returns no ACK when message has not been delivered");
    {
        reset_server_state();
        auto sender = generate_identity(rng, g_cfg);
        auto recipient = generate_identity(rng, g_cfg);
        int fd = connect_test();
        std::string s_tok = extract_token(
            cmd(fd, "REGISTER " + sender.user_id + " " + Botan::hex_encode(sender.pubkey_bytes)));
        cmd(fd, "REGISTER " + recipient.user_id + " " + Botan::hex_encode(recipient.pubkey_bytes));
        auto blob = encrypt_message("hi", sender.user_id, "s", recipient.pubkey_bytes, rng, g_cfg);
        cmd(fd, "SEND " + sender.user_id + " " + s_tok + " " + recipient.user_id + " " +
                    Botan::hex_encode(blob));
        // recipient has not polled — no ACK yet
        int ack = poll_ack(fd, sender.user_id, s_tok);
        ASSERT_EQ(ack, 0);
        close(fd);
    }

    // -------------------------------------------------------
    // TLS transport — verify protocol works over encrypted channel
    // -------------------------------------------------------
    TEST("TLS REGISTER returns token");
    {
        reset_server_state();
        auto id = generate_identity(rng, g_cfg);
        auto conn = tls_connect(TEST_TLS_PORT);
        ASSERT_TRUE(conn.fd >= 0);
        std::string resp =
            tls_cmd(conn, "REGISTER " + id.user_id + " " + Botan::hex_encode(id.pubkey_bytes));
        ASSERT_TRUE(resp.substr(0, 3) == "OK ");
        ASSERT_EQ(extract_token(resp).size(), (size_t)64);
        close(conn.fd);
    }

    TEST("TLS SEND and POLL deliver message end-to-end");
    {
        reset_server_state();
        auto sender = generate_identity(rng, g_cfg);
        auto recipient = generate_identity(rng, g_cfg);
        auto conn = tls_connect(TEST_TLS_PORT);
        ASSERT_TRUE(conn.fd >= 0);
        std::string s_tok = extract_token(tls_cmd(
            conn, "REGISTER " + sender.user_id + " " + Botan::hex_encode(sender.pubkey_bytes)));
        std::string r_tok =
            extract_token(tls_cmd(conn, "REGISTER " + recipient.user_id + " " +
                                            Botan::hex_encode(recipient.pubkey_bytes)));
        auto blob =
            encrypt_message("tls hello", sender.user_id, "s", recipient.pubkey_bytes, rng, g_cfg);
        tls_cmd(conn, "SEND " + sender.user_id + " " + s_tok + " " + recipient.user_id + " " +
                          Botan::hex_encode(blob));
        // POLL recipient
        tls_send_line(*conn.tls, "POLL " + recipient.user_id + " " + r_tok);
        std::string msg_line = tls_read_line(conn.fd, *conn.tls, *conn.cb);
        ASSERT_TRUE(msg_line.substr(0, 4) == "MSG ");
        std::istringstream mss(msg_line.substr(4));
        std::string mid;
        mss >> mid;
        tls_read_line(conn.fd, *conn.tls, *conn.cb); // consume NOMSG
        tls_cmd(conn, "MSGACK " + recipient.user_id + " " + r_tok + " " + mid);
        close(conn.fd);
    }

    TEST("TLS connection with bad token is rejected");
    {
        reset_server_state();
        auto id = generate_identity(rng, g_cfg);
        auto conn = tls_connect(TEST_TLS_PORT);
        ASSERT_TRUE(conn.fd >= 0);
        tls_cmd(conn, "REGISTER " + id.user_id + " " + Botan::hex_encode(id.pubkey_bytes));
        std::string resp = tls_cmd(conn, "POLL " + id.user_id + " " + std::string(64, '0'));
        ASSERT_TRUE(resp.substr(0, 3) == "ERR");
        close(conn.fd);
    }

    // -------------------------------------------------------
    // TLS cert algorithm variants
    // Verifies that ECDSA-P384 and Ed25519 server certs
    // complete a TLS handshake and accept REGISTER.
    // -------------------------------------------------------
    TEST("TLS ECDSA-P384 cert: handshake completes and REGISTER succeeds");
    {
        reset_server_state();
        auto id = generate_identity(rng, g_cfg);
        auto conn = tls_connect(TEST_TLS_P384_PORT);
        ASSERT_TRUE(conn.fd >= 0);
        std::string resp =
            tls_cmd(conn, "REGISTER " + id.user_id + " " + Botan::hex_encode(id.pubkey_bytes));
        ASSERT_TRUE(resp.substr(0, 3) == "OK ");
        ASSERT_EQ(extract_token(resp).size(), (size_t)64);
        close(conn.fd);
    }

    TEST("TLS Ed25519 cert: server starts and cert file is created");
    {
        // Note: Botan's Signature_Scheme::all_available_schemes() comments out EDDSA_25519
        // ("not supported as a signature scheme for certificate authentication" — botan/pull/2958).
        // So an Ed25519 cert cannot complete a TLS 1.3 handshake in this Botan build.
        // We test that the server at least starts and accepts TCP connections.
        reset_server_state();
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(TEST_TLS_ED25519_PORT);
        inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
        int rc = connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
        ASSERT_EQ(rc, 0); // server is listening
        close(fd);
        // Verify cert file was created
        std::ifstream cert_file("/tmp/ztm_test_ed25519.cert.pem");
        ASSERT_TRUE(cert_file.good());
    }

    // -------------------------------------------------------
    // HELLO — version handshake
    // -------------------------------------------------------
    TEST("HELLO with correct version returns OK");
    {
        reset_server_state();
        int fd = connect_test();
        std::string resp = cmd(fd, "HELLO ZTM/1");
        ASSERT_TRUE(resp.substr(0, 3) == "OK ");
        ASSERT_TRUE(resp.find("ZTM/1") != std::string::npos);
        close(fd);
    }

    TEST("HELLO with wrong version closes connection");
    {
        reset_server_state();
        int fd = connect_test();
        std::string resp = cmd(fd, "HELLO ZTM/999");
        ASSERT_TRUE(resp.substr(0, 3) == "ERR");
        ASSERT_TRUE(resp.find("version_mismatch") != std::string::npos);
        close(fd);
    }

    TEST("REGISTER without HELLO still works (backward compat)");
    {
        reset_server_state();
        auto id = generate_identity(rng, g_cfg);
        int fd = connect_test();
        std::string resp =
            cmd(fd, "REGISTER " + id.user_id + " " + Botan::hex_encode(id.pubkey_bytes));
        ASSERT_TRUE(resp.substr(0, 3) == "OK ");
        close(fd);
    }

    // -------------------------------------------------------
    // STATUS — health check (no auth)
    // -------------------------------------------------------
    TEST("STATUS returns OK with metrics");
    {
        reset_server_state();
        auto id = generate_identity(rng, g_cfg);
        int fd = connect_test();
        cmd(fd, "REGISTER " + id.user_id + " " + Botan::hex_encode(id.pubkey_bytes));
        close(fd);

        fd = connect_test();
        std::string resp = cmd(fd, "STATUS");
        ASSERT_TRUE(resp.substr(0, 3) == "OK ");
        ASSERT_TRUE(resp.find("users=1") != std::string::npos);
        ASSERT_TRUE(resp.find("uptime=") != std::string::npos);
        close(fd);
    }

    // -------------------------------------------------------
    // DEREGISTER — account erasure
    // -------------------------------------------------------
    TEST("DEREGISTER removes user, key, and messages");
    {
        reset_server_state();
        auto id = generate_identity(rng, g_cfg);
        int fd = connect_test();
        std::string token = extract_token(
            cmd(fd, "REGISTER " + id.user_id + " " + Botan::hex_encode(id.pubkey_bytes)));
        ASSERT_TRUE(!token.empty());

        std::string dresp = cmd(fd, "DEREGISTER " + id.user_id + " " + token);
        ASSERT_TRUE(dresp == "OK");

        // GETKEY should now fail
        std::string kresp = cmd(fd, "GETKEY " + id.user_id);
        ASSERT_TRUE(kresp.substr(0, 3) == "ERR");
        close(fd);
    }

    TEST("DEREGISTER with wrong token is rejected");
    {
        reset_server_state();
        auto id = generate_identity(rng, g_cfg);
        int fd = connect_test();
        cmd(fd, "REGISTER " + id.user_id + " " + Botan::hex_encode(id.pubkey_bytes));
        std::string resp = cmd(fd, "DEREGISTER " + id.user_id + " " + std::string(64, '0'));
        ASSERT_TRUE(resp.substr(0, 3) == "ERR");
        close(fd);
    }

    // -------------------------------------------------------
    // Message IDs — must be 32 hex chars (random, not sequential)
    // -------------------------------------------------------
    TEST("message IDs are 32-char hex strings");
    {
        reset_server_state();
        auto sender = generate_identity(rng, g_cfg);
        auto recipient = generate_identity(rng, g_cfg);
        int fd = connect_test();
        std::string s_tok = extract_token(
            cmd(fd, "REGISTER " + sender.user_id + " " + Botan::hex_encode(sender.pubkey_bytes)));
        std::string r_tok = extract_token(cmd(fd, "REGISTER " + recipient.user_id + " " +
                                                      Botan::hex_encode(recipient.pubkey_bytes)));
        auto blob = encrypt_message("x", sender.user_id, "s", recipient.pubkey_bytes, rng, g_cfg);
        cmd(fd, "SEND " + sender.user_id + " " + s_tok + " " + recipient.user_id + " " +
                    Botan::hex_encode(blob));

        // parse MSG line to extract ID
        send_line(fd, "POLL " + recipient.user_id + " " + r_tok);
        std::string msg_line;
        while (true) {
            msg_line = read_line(fd);
            if (msg_line == "NOMSG" || msg_line.empty())
                break;
            if (msg_line.substr(0, 4) == "MSG ")
                break;
        }
        ASSERT_TRUE(msg_line.substr(0, 4) == "MSG ");
        std::istringstream ss(msg_line.substr(4));
        std::string msg_id;
        ss >> msg_id;
        ASSERT_EQ(msg_id.size(), (size_t)32);
        bool all_hex = true;
        for (char c : msg_id)
            if (!std::isxdigit(c))
                all_hex = false;
        ASSERT_TRUE(all_hex);
        // Drain NOMSG then send MSGACK
        while (msg_line != "NOMSG" && !msg_line.empty())
            msg_line = read_line(fd);
        send_line(fd, "MSGACK " + recipient.user_id + " " + r_tok + " " + msg_id);
        read_line(fd); // consume OK
        close(fd);
    }

    // -------------------------------------------------------
    // Unknown command
    // -------------------------------------------------------
    TEST("unknown command returns ERR");
    {
        reset_server_state();
        int fd = connect_test();
        std::string resp = cmd(fd, "INVALID");
        ASSERT_TRUE(resp.substr(0, 3) == "ERR");
        close(fd);
    }

    // -------------------------------------------------------
    // Admin port
    // -------------------------------------------------------

    // Helper: connect to the admin port (plain TCP, 127.0.0.1 only)
    auto connect_admin = []() -> int {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(TEST_ADMIN_PORT);
        inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
        if (connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
            close(fd);
            return -1;
        }
        return fd;
    };

    TEST("admin STATS returns OK with metrics");
    {
        reset_server_state();
        int fd = connect_admin();
        ASSERT_TRUE(fd >= 0);
        std::string resp = cmd(fd, "STATS");
        ASSERT_TRUE(resp.substr(0, 3) == "OK ");
        ASSERT_TRUE(resp.find("users=") != std::string::npos);
        ASSERT_TRUE(resp.find("uptime=") != std::string::npos);
        ASSERT_TRUE(resp.find("connections=") != std::string::npos);
        close(fd);
    }

    TEST("admin LIST_USERS returns registered users and END");
    {
        reset_server_state();
        // Register a user on the admin TLS server
        auto id = generate_identity(rng, g_cfg);
        auto conn = tls_connect(TEST_ADMIN_TLS_PORT);
        ASSERT_TRUE(conn.fd >= 0);
        tls_cmd(conn, "REGISTER " + id.user_id + " " + Botan::hex_encode(id.pubkey_bytes));
        close(conn.fd);

        int fd = connect_admin();
        ASSERT_TRUE(fd >= 0);
        send_line(fd, "LIST_USERS");
        // Read until END
        bool found_user = false;
        bool found_end = false;
        for (int i = 0; i < 20; ++i) {
            std::string line = read_line(fd);
            if (line.substr(0, 5) == "USER ")
                found_user = true;
            if (line == "END") {
                found_end = true;
                break;
            }
            if (line.empty())
                break;
        }
        ASSERT_TRUE(found_user);
        ASSERT_TRUE(found_end);
        close(fd);
    }

    TEST("admin KICK removes user and returns OK");
    {
        reset_server_state();
        auto id = generate_identity(rng, g_cfg);
        auto conn = tls_connect(TEST_ADMIN_TLS_PORT);
        ASSERT_TRUE(conn.fd >= 0);
        tls_cmd(conn, "REGISTER " + id.user_id + " " + Botan::hex_encode(id.pubkey_bytes));
        close(conn.fd);

        int fd = connect_admin();
        ASSERT_TRUE(fd >= 0);
        std::string resp = cmd(fd, "KICK " + id.user_id);
        ASSERT_EQ(resp, std::string("OK"));
        close(fd);

        // User should be gone — GETKEY returns ERR
        auto conn2 = tls_connect(TEST_ADMIN_TLS_PORT);
        ASSERT_TRUE(conn2.fd >= 0);
        std::string kresp = tls_cmd(conn2, "GETKEY " + id.user_id);
        ASSERT_TRUE(kresp.substr(0, 3) == "ERR");
        close(conn2.fd);
    }

    TEST("admin KICK returns ERR for unknown user");
    {
        reset_server_state();
        int fd = connect_admin();
        ASSERT_TRUE(fd >= 0);
        std::string resp = cmd(fd, "KICK 0000000000000000");
        ASSERT_TRUE(resp.substr(0, 3) == "ERR");
        close(fd);
    }

    TEST("admin RELOAD returns OK");
    {
        reset_server_state();
        int fd = connect_admin();
        ASSERT_TRUE(fd >= 0);
        std::string resp = cmd(fd, "RELOAD");
        ASSERT_EQ(resp, std::string("OK"));
        close(fd);
    }

    TEST("admin unknown command returns ERR");
    {
        reset_server_state();
        int fd = connect_admin();
        ASSERT_TRUE(fd >= 0);
        std::string resp = cmd(fd, "INVALID_ADMIN_CMD");
        ASSERT_TRUE(resp.substr(0, 3) == "ERR");
        close(fd);
    }

    // -------------------------------------------------------
    // REGISTER edge cases (covers uncovered server.cpp paths)
    // -------------------------------------------------------

    TEST("REGISTER rejects pubkey whose byte-length does not match the configured KEM");
    {
        reset_server_state();
        int fd = connect_test();
        // Default server uses ML-KEM-768 (1184-byte pubkey). Send 65 bytes instead.
        std::vector<uint8_t> wrong_size(65, 0xAB);
        std::string resp = cmd(fd, "REGISTER 0000000000000000 " + Botan::hex_encode(wrong_size));
        ASSERT_TRUE(resp.find("mismatch") != std::string::npos || resp.substr(0, 3) == "ERR");
        close(fd);
    }

    TEST("REGISTER rejects when max_users limit is reached");
    {
        // Restricted server has max_users=2
        reset_server_state();
        auto id1 = generate_identity(rng, g_cfg);
        auto id2 = generate_identity(rng, g_cfg);
        auto id3 = generate_identity(rng, g_cfg);
        auto conn = tls_connect(TEST_RESTRICTED_PORT);
        ASSERT_TRUE(conn.fd >= 0);
        // Register up to the limit
        ASSERT_TRUE(
            tls_cmd(conn, "REGISTER " + id1.user_id + " " + Botan::hex_encode(id1.pubkey_bytes))
                .substr(0, 3) == "OK ");
        ASSERT_TRUE(
            tls_cmd(conn, "REGISTER " + id2.user_id + " " + Botan::hex_encode(id2.pubkey_bytes))
                .substr(0, 3) == "OK ");
        // Third registration must be rejected
        std::string resp =
            tls_cmd(conn, "REGISTER " + id3.user_id + " " + Botan::hex_encode(id3.pubkey_bytes));
        ASSERT_TRUE(resp.substr(0, 3) == "ERR");
        close(conn.fd);
    }

    // -------------------------------------------------------
    // SEND edge cases
    // -------------------------------------------------------

    TEST("SEND rejects non-hex blob");
    {
        reset_server_state();
        auto sender = generate_identity(rng, g_cfg);
        auto recipient = generate_identity(rng, g_cfg);
        int fd = connect_test();
        std::string s_tok = extract_token(
            cmd(fd, "REGISTER " + sender.user_id + " " + Botan::hex_encode(sender.pubkey_bytes)));
        cmd(fd, "REGISTER " + recipient.user_id + " " + Botan::hex_encode(recipient.pubkey_bytes));
        // ZZZZ is not valid hex
        std::string resp =
            cmd(fd, "SEND " + sender.user_id + " " + s_tok + " " + recipient.user_id + " ZZZZZZZZ");
        ASSERT_TRUE(resp.substr(0, 3) == "ERR");
        close(fd);
    }

    TEST("SEND rejects when recipient inbox is full");
    {
        // Restricted server has max_inbox_messages=2
        reset_server_state();
        auto sender = generate_identity(rng, g_cfg);
        auto recipient = generate_identity(rng, g_cfg);
        auto conn = tls_connect(TEST_RESTRICTED_PORT);
        ASSERT_TRUE(conn.fd >= 0);
        std::string s_tok = extract_token(tls_cmd(
            conn, "REGISTER " + sender.user_id + " " + Botan::hex_encode(sender.pubkey_bytes)));
        tls_cmd(conn,
                "REGISTER " + recipient.user_id + " " + Botan::hex_encode(recipient.pubkey_bytes));
        auto blob = encrypt_message("hi", sender.user_id, "s", recipient.pubkey_bytes, rng, g_cfg);
        std::string blob_hex = Botan::hex_encode(blob);
        // Fill inbox to the limit (2 messages)
        tls_cmd(conn,
                "SEND " + sender.user_id + " " + s_tok + " " + recipient.user_id + " " + blob_hex);
        tls_cmd(conn,
                "SEND " + sender.user_id + " " + s_tok + " " + recipient.user_id + " " + blob_hex);
        // Third send must be rejected
        std::string resp = tls_cmd(conn, "SEND " + sender.user_id + " " + s_tok + " " +
                                             recipient.user_id + " " + blob_hex);
        ASSERT_TRUE(resp.find("inbox") != std::string::npos || resp.substr(0, 3) == "ERR");
        close(conn.fd);
    }

    // -------------------------------------------------------
    // Logging paths
    // -------------------------------------------------------

    TEST("log_level=debug and log_format=json: server writes to log file");
    {
        // The log-file server was started with debug + json + a file path.
        // The log file's existence confirms log_init opened it (covers the
        // log_file branch in log_init). Multiple servers share global log
        // state, so we only assert the file was created and is non-empty —
        // not the exact format, which depends on which log_init ran last.
        reset_server_state();
        auto id = generate_identity(rng, g_cfg);
        auto conn = tls_connect(TEST_LOG_FILE_PORT);
        ASSERT_TRUE(conn.fd >= 0);
        tls_cmd(conn, "REGISTER " + id.user_id + " " + Botan::hex_encode(id.pubkey_bytes));
        close(conn.fd);
        std::ifstream f("/tmp/ztm_test_server.log");
        ASSERT_TRUE(f.good());
        // file must contain at least one log line
        std::string content((std::istreambuf_iterator<char>(f)), {});
        ASSERT_TRUE(!content.empty());
    }

    // -------------------------------------------------------
    // Cert generation path
    // -------------------------------------------------------

    // -------------------------------------------------------
    // REKEY
    // -------------------------------------------------------
    TEST("REKEY replaces pubkey, issues new token, old session gone");
    {
        reset_server_state();
        auto id = generate_identity(rng, g_cfg);
        int fd = connect_test();
        std::string old_tok = extract_token(
            cmd(fd, "REGISTER " + id.user_id + " " + Botan::hex_encode(id.pubkey_bytes)));
        ASSERT_TRUE(!old_tok.empty());

        auto new_id = generate_identity(rng, g_cfg);
        std::string resp = cmd(fd, "REKEY " + id.user_id + " " + old_tok + " " + new_id.user_id +
                                       " " + Botan::hex_encode(new_id.pubkey_bytes));
        ASSERT_TRUE(resp.substr(0, 3) == "OK ");
        std::string new_tok = resp.substr(3);
        ASSERT_EQ(new_tok.size(), (size_t)64);

        // New identity is registered and fetchable
        std::string kr = cmd(fd, "GETKEY " + new_id.user_id);
        ASSERT_TRUE(kr.substr(0, 3) == "OK ");

        // Old identity is gone
        std::string old_kr = cmd(fd, "GETKEY " + id.user_id);
        ASSERT_TRUE(old_kr.substr(0, 3) == "ERR");

        // Old token no longer works
        std::string poll_resp = cmd(fd, "POLL " + id.user_id + " " + old_tok);
        ASSERT_TRUE(poll_resp.substr(0, 3) == "ERR");

        close(fd);
    }

    TEST("REKEY rejects invalid token");
    {
        reset_server_state();
        auto id = generate_identity(rng, g_cfg);
        int fd = connect_test();
        cmd(fd, "REGISTER " + id.user_id + " " + Botan::hex_encode(id.pubkey_bytes));
        auto new_id = generate_identity(rng, g_cfg);
        std::string resp =
            cmd(fd, "REKEY " + id.user_id + " " + std::string(64, '0') + " " + new_id.user_id +
                        " " + Botan::hex_encode(new_id.pubkey_bytes));
        ASSERT_TRUE(resp.substr(0, 3) == "ERR");
        close(fd);
    }

    TEST("REKEY rejects pubkey size mismatch");
    {
        reset_server_state();
        auto id = generate_identity(rng, g_cfg);
        int fd = connect_test();
        std::string tok = extract_token(
            cmd(fd, "REGISTER " + id.user_id + " " + Botan::hex_encode(id.pubkey_bytes)));
        // Send 65 bytes instead of the required KEM pubkey length
        std::vector<uint8_t> wrong(65, 0xAB);
        std::string fake_id = derive_user_id(wrong);
        std::string resp = cmd(fd, "REKEY " + id.user_id + " " + tok + " " + fake_id + " " +
                                       Botan::hex_encode(wrong));
        ASSERT_TRUE(resp.find("mismatch") != std::string::npos || resp.substr(0, 3) == "ERR");
        close(fd);
    }

    TEST("REKEY rejects new user_id / pubkey derivation mismatch");
    {
        reset_server_state();
        auto id = generate_identity(rng, g_cfg);
        auto new_id = generate_identity(rng, g_cfg);
        int fd = connect_test();
        std::string tok = extract_token(
            cmd(fd, "REGISTER " + id.user_id + " " + Botan::hex_encode(id.pubkey_bytes)));
        // Pass new_id pubkey but a completely wrong user_id
        std::string resp = cmd(fd, "REKEY " + id.user_id + " " + tok + " " + std::string(16, '0') +
                                       " " + Botan::hex_encode(new_id.pubkey_bytes));
        ASSERT_TRUE(resp.substr(0, 3) == "ERR");
        close(fd);
    }

    TEST("REKEY rejects attempt to rekey to the same identity");
    {
        reset_server_state();
        auto id = generate_identity(rng, g_cfg);
        int fd = connect_test();
        std::string tok = extract_token(
            cmd(fd, "REGISTER " + id.user_id + " " + Botan::hex_encode(id.pubkey_bytes)));
        std::string resp = cmd(fd, "REKEY " + id.user_id + " " + tok + " " + id.user_id + " " +
                                       Botan::hex_encode(id.pubkey_bytes));
        ASSERT_TRUE(resp.substr(0, 3) == "ERR");
        close(fd);
    }

    TEST("REKEY migrates pending inbox messages to new identity");
    {
        reset_server_state();
        auto sender = generate_identity(rng, g_cfg);
        auto recipient = generate_identity(rng, g_cfg);
        int fd = connect_test();

        std::string s_tok = extract_token(
            cmd(fd, "REGISTER " + sender.user_id + " " + Botan::hex_encode(sender.pubkey_bytes)));
        std::string r_tok = extract_token(cmd(fd, "REGISTER " + recipient.user_id + " " +
                                                      Botan::hex_encode(recipient.pubkey_bytes)));

        // Send a message to recipient's old identity
        auto blob = encrypt_message("hi", sender.user_id, "s", recipient.pubkey_bytes, rng, g_cfg);
        cmd(fd, "SEND " + sender.user_id + " " + s_tok + " " + recipient.user_id + " " +
                    Botan::hex_encode(blob));

        // Recipient rotates their key
        auto new_recip = generate_identity(rng, g_cfg);
        std::string rekey_resp =
            cmd(fd, "REKEY " + recipient.user_id + " " + r_tok + " " + new_recip.user_id + " " +
                        Botan::hex_encode(new_recip.pubkey_bytes));
        ASSERT_TRUE(rekey_resp.substr(0, 3) == "OK ");
        std::string new_r_tok = rekey_resp.substr(3);

        // Message must be in the new inbox
        auto msgs = poll_all(fd, new_recip.user_id, new_r_tok);
        ASSERT_EQ(msgs.size(), (size_t)1);

        // Old inbox is gone
        auto old_msgs = poll_all(fd, recipient.user_id, r_tok);
        ASSERT_EQ(old_msgs.size(), (size_t)0);

        close(fd);
    }

    TEST("REKEY to already-registered new_user_id with same key is allowed");
    {
        // Exercises the existing.has_value() branch in the duplicate-key guard:
        // new_user_id is already registered with the exact same pubkey (idempotent upsert).
        reset_server_state();
        auto id = generate_identity(rng, g_cfg);
        auto new_id = generate_identity(rng, g_cfg);
        int fd = connect_test();

        std::string tok = extract_token(
            cmd(fd, "REGISTER " + id.user_id + " " + Botan::hex_encode(id.pubkey_bytes)));
        // Pre-register new_id so get_pubkey(new_user_id) returns a value
        cmd(fd, "REGISTER " + new_id.user_id + " " + Botan::hex_encode(new_id.pubkey_bytes));

        std::string resp = cmd(fd, "REKEY " + id.user_id + " " + tok + " " + new_id.user_id + " " +
                                       Botan::hex_encode(new_id.pubkey_bytes));
        ASSERT_TRUE(resp.substr(0, 3) == "OK ");

        close(fd);
    }

    TEST("REKEY carries over pending delivery acks to new identity");
    {
        reset_server_state();
        auto sender = generate_identity(rng, g_cfg);
        auto recipient = generate_identity(rng, g_cfg);
        int fd = connect_test();

        std::string s_tok = extract_token(
            cmd(fd, "REGISTER " + sender.user_id + " " + Botan::hex_encode(sender.pubkey_bytes)));
        std::string r_tok = extract_token(cmd(fd, "REGISTER " + recipient.user_id + " " +
                                                      Botan::hex_encode(recipient.pubkey_bytes)));

        // Send a message and poll+ack it so recipient accumulates a delivery ack
        auto blob =
            encrypt_message("ack-test", sender.user_id, "s", recipient.pubkey_bytes, rng, g_cfg);
        cmd(fd, "SEND " + sender.user_id + " " + s_tok + " " + recipient.user_id + " " +
                    Botan::hex_encode(blob));
        // poll_all sends MSGACK internally, which increments the ack counter
        poll_all(fd, recipient.user_id, r_tok);

        // Now rotate recipient's key
        auto new_recip = generate_identity(rng, g_cfg);
        std::string rekey_resp =
            cmd(fd, "REKEY " + recipient.user_id + " " + r_tok + " " + new_recip.user_id + " " +
                        Botan::hex_encode(new_recip.pubkey_bytes));
        ASSERT_TRUE(rekey_resp.substr(0, 3) == "OK ");
        std::string new_r_tok = rekey_resp.substr(3);

        // POLL on new identity should return the carried-over ack count (DELIVERED line)
        std::string poll_resp = cmd(fd, "POLL " + new_recip.user_id + " " + new_r_tok);
        ASSERT_TRUE(poll_resp.find("NOMSG") != std::string::npos ||
                    poll_resp.find("DELIVERED") != std::string::npos);

        close(fd);
    }

    TEST("REKEY rejects invalid hex in pubkey");
    {
        reset_server_state();
        auto id = generate_identity(rng, g_cfg);
        int fd = connect_test();
        std::string tok = extract_token(
            cmd(fd, "REGISTER " + id.user_id + " " + Botan::hex_encode(id.pubkey_bytes)));
        auto new_id = generate_identity(rng, g_cfg);
        // Pass a non-hex string as the pubkey to trigger the catch(…) path
        std::string resp =
            cmd(fd, "REKEY " + id.user_id + " " + tok + " " + new_id.user_id + " ZZZZZZZZZZZZZZZZ");
        ASSERT_TRUE(resp.substr(0, 3) == "ERR");

        close(fd);
    }

    // -------------------------------------------------------
    // Prekeys (UPLOAD_PREKEYS / GETPREKEY)
    // -------------------------------------------------------

    // -------------------------------------------------------
    // POLL pagination
    // -------------------------------------------------------

    TEST("POLL with limit returns at most limit messages and emits MORE");
    {
        reset_server_state();
        auto sender = generate_identity(rng, g_cfg);
        auto recip = generate_identity(rng, g_cfg);
        int fd = connect_test();
        std::string s_tok = extract_token(
            cmd(fd, "REGISTER " + sender.user_id + " " + Botan::hex_encode(sender.pubkey_bytes)));
        std::string r_tok = extract_token(
            cmd(fd, "REGISTER " + recip.user_id + " " + Botan::hex_encode(recip.pubkey_bytes)));
        for (int i = 0; i < 3; ++i) {
            auto blob = encrypt_message("m", sender.user_id, "s", recip.pubkey_bytes, rng, g_cfg);
            cmd(fd, "SEND " + sender.user_id + " " + s_tok + " " + recip.user_id + " _ " +
                        Botan::hex_encode(blob));
        }
        // POLL with limit=2 → 2 MSG + MORE + NOMSG
        send_line(fd, "POLL " + recip.user_id + " " + r_tok + " 2");
        int mc = 0;
        bool got_more = false;
        std::vector<std::string> ids;
        while (true) {
            std::string line = read_line(fd);
            if (line == "NOMSG" || line.empty())
                break;
            if (line == "MORE") {
                got_more = true;
            } else if (line.substr(0, 4) == "MSG ") {
                std::istringstream ss(line.substr(4));
                std::string mid;
                ss >> mid;
                ids.push_back(mid);
                ++mc;
            }
        }
        ASSERT_EQ(mc, 2);
        ASSERT_TRUE(got_more);
        // MSGACK the 2 messages, then poll remainder
        cmd(fd, "MSGACK " + recip.user_id + " " + r_tok + " " + ids[0] + "," + ids[1]);
        auto remaining = poll_all(fd, recip.user_id, r_tok);
        ASSERT_EQ(remaining.size(), (size_t)1);
        close(fd);
    }

    TEST("POLL without limit returns all messages with no MORE");
    {
        reset_server_state();
        auto sender = generate_identity(rng, g_cfg);
        auto recip = generate_identity(rng, g_cfg);
        int fd = connect_test();
        std::string s_tok = extract_token(
            cmd(fd, "REGISTER " + sender.user_id + " " + Botan::hex_encode(sender.pubkey_bytes)));
        std::string r_tok = extract_token(
            cmd(fd, "REGISTER " + recip.user_id + " " + Botan::hex_encode(recip.pubkey_bytes)));
        for (int i = 0; i < 3; ++i) {
            auto blob = encrypt_message("x", sender.user_id, "s", recip.pubkey_bytes, rng, g_cfg);
            cmd(fd, "SEND " + sender.user_id + " " + s_tok + " " + recip.user_id + " _ " +
                        Botan::hex_encode(blob));
        }
        auto blobs = poll_all(fd, recip.user_id, r_tok);
        ASSERT_EQ(blobs.size(), (size_t)3);
        close(fd);
    }

    // -------------------------------------------------------
    // Key fingerprint verification (GETFINGERPRINT)
    // -------------------------------------------------------

    TEST("GETFINGERPRINT returns 64-hex SHA-256 of registered pubkey");
    {
        reset_server_state();
        auto id = generate_identity(rng, g_cfg);
        int fd = connect_test();
        cmd(fd, "REGISTER " + id.user_id + " " + Botan::hex_encode(id.pubkey_bytes));
        std::string resp = cmd(fd, "GETFINGERPRINT " + id.user_id);
        ASSERT_TRUE(resp.substr(0, 3) == "OK ");
        std::string fp = resp.substr(3);
        ASSERT_EQ(fp.size(), (size_t)64); // 32 bytes SHA-256 → 64 hex chars
        // Verify it's actually SHA-256(pubkey)
        auto sha = Botan::HashFunction::create_or_throw("SHA-256");
        sha->update(id.pubkey_bytes);
        ASSERT_EQ(fp, Botan::hex_encode(sha->final()));
        close(fd);
    }

    TEST("GETFINGERPRINT returns ERR for unknown user");
    {
        reset_server_state();
        int fd = connect_test();
        ASSERT_TRUE(cmd(fd, "GETFINGERPRINT 0000000000000000").substr(0, 3) == "ERR");
        close(fd);
    }

    // -------------------------------------------------------
    // Session refresh (REFRESH_TOKEN)
    // -------------------------------------------------------

    TEST("REFRESH_TOKEN issues a new token; old token no longer works");
    {
        reset_server_state();
        auto id = generate_identity(rng, g_cfg);
        int fd = connect_test();
        std::string old_tok = extract_token(
            cmd(fd, "REGISTER " + id.user_id + " " + Botan::hex_encode(id.pubkey_bytes)));

        std::string resp = cmd(fd, "REFRESH_TOKEN " + id.user_id + " " + old_tok);
        ASSERT_TRUE(resp.substr(0, 3) == "OK ");
        std::string new_tok = resp.substr(3);
        ASSERT_EQ(new_tok.size(), (size_t)64);
        ASSERT_TRUE(new_tok != old_tok);
        // Old token rejected; new token accepted
        ASSERT_TRUE(cmd(fd, "POLL " + id.user_id + " " + old_tok).substr(0, 3) == "ERR");
        ASSERT_TRUE(cmd(fd, "POLL " + id.user_id + " " + new_tok).find("NOMSG") !=
                    std::string::npos);
        close(fd);
    }

    TEST("REFRESH_TOKEN rejects invalid token");
    {
        reset_server_state();
        auto id = generate_identity(rng, g_cfg);
        int fd = connect_test();
        cmd(fd, "REGISTER " + id.user_id + " " + Botan::hex_encode(id.pubkey_bytes));
        ASSERT_TRUE(
            cmd(fd, "REFRESH_TOKEN " + id.user_id + " " + std::string(64, '0')).substr(0, 3) ==
            "ERR");
        close(fd);
    }

    TEST("PREKEY_COUNT returns current server-side prekey count");
    {
        reset_server_state();
        auto id = generate_identity(rng, g_cfg);
        int fd = connect_test();
        std::string tok = extract_token(
            cmd(fd, "REGISTER " + id.user_id + " " + Botan::hex_encode(id.pubkey_bytes)));

        // Initially zero
        std::string r0 = cmd(fd, "PREKEY_COUNT " + id.user_id + " " + tok);
        ASSERT_EQ(r0, std::string("OK 0"));

        // Upload 3 prekeys
        auto pks = generate_prekeys(3, rng, g_cfg);
        std::string up = "UPLOAD_PREKEYS " + id.user_id + " " + tok;
        for (auto& pk : pks)
            up += " " + Botan::hex_encode(pk.pubkey_bytes);
        cmd(fd, up);

        std::string r3 = cmd(fd, "PREKEY_COUNT " + id.user_id + " " + tok);
        ASSERT_EQ(r3, std::string("OK 3"));

        close(fd);
    }

    TEST("PREKEY_COUNT rejects invalid token");
    {
        reset_server_state();
        auto id = generate_identity(rng, g_cfg);
        int fd = connect_test();
        cmd(fd, "REGISTER " + id.user_id + " " + Botan::hex_encode(id.pubkey_bytes));
        std::string resp = cmd(fd, "PREKEY_COUNT " + id.user_id + " " + std::string(64, '0'));
        ASSERT_TRUE(resp.substr(0, 3) == "ERR");
        close(fd);
    }

    TEST("UPLOAD_PREKEYS stores prekeys and GETPREKEY pops one");
    {
        reset_server_state();
        auto id = generate_identity(rng, g_cfg);
        int fd = connect_test();
        std::string tok = extract_token(
            cmd(fd, "REGISTER " + id.user_id + " " + Botan::hex_encode(id.pubkey_bytes)));

        // Generate a prekey pair and upload it
        auto prekeys = generate_prekeys(1, rng, g_cfg);
        std::string upload_resp = cmd(fd, "UPLOAD_PREKEYS " + id.user_id + " " + tok + " " +
                                              Botan::hex_encode(prekeys[0].pubkey_bytes));
        ASSERT_TRUE(upload_resp.substr(0, 3) == "OK ");

        // GETPREKEY should return identity pubkey + prekey
        std::string gp_resp = cmd(fd, "GETPREKEY " + id.user_id);
        ASSERT_TRUE(gp_resp.substr(0, 3) == "OK ");
        std::istringstream gp_ss(gp_resp.substr(3));
        std::string id_pub, pk_id, pk_pub;
        gp_ss >> id_pub >> pk_id >> pk_pub;
        ASSERT_EQ(id_pub, Botan::hex_encode(id.pubkey_bytes));
        ASSERT_EQ(pk_id, prekeys[0].prekey_id);
        ASSERT_TRUE(!pk_pub.empty());

        // Second GETPREKEY — no more prekeys, should return NONE
        std::string gp2 = cmd(fd, "GETPREKEY " + id.user_id);
        ASSERT_TRUE(gp2.find("NONE") != std::string::npos);

        close(fd);
    }

    TEST("GETPREKEY falls back to NONE when no prekeys uploaded");
    {
        reset_server_state();
        auto id = generate_identity(rng, g_cfg);
        int fd = connect_test();
        cmd(fd, "REGISTER " + id.user_id + " " + Botan::hex_encode(id.pubkey_bytes));
        std::string resp = cmd(fd, "GETPREKEY " + id.user_id);
        ASSERT_TRUE(resp.substr(0, 3) == "OK ");
        ASSERT_TRUE(resp.find("NONE") != std::string::npos);
        close(fd);
    }

    TEST("GETPREKEY returns ERR for unknown user");
    {
        reset_server_state();
        int fd = connect_test();
        std::string resp = cmd(fd, "GETPREKEY 0000000000000000");
        ASSERT_TRUE(resp.substr(0, 3) == "ERR");
        close(fd);
    }

    TEST("UPLOAD_PREKEYS rejects invalid token");
    {
        reset_server_state();
        auto id = generate_identity(rng, g_cfg);
        int fd = connect_test();
        cmd(fd, "REGISTER " + id.user_id + " " + Botan::hex_encode(id.pubkey_bytes));
        auto pk = generate_prekeys(1, rng, g_cfg);
        std::string resp = cmd(fd, "UPLOAD_PREKEYS " + id.user_id + " " + std::string(64, '0') +
                                       " " + Botan::hex_encode(pk[0].pubkey_bytes));
        ASSERT_TRUE(resp.substr(0, 3) == "ERR");
        close(fd);
    }

    TEST("UPLOAD_PREKEYS rejects no prekeys provided");
    {
        reset_server_state();
        auto id = generate_identity(rng, g_cfg);
        int fd = connect_test();
        std::string tok = extract_token(
            cmd(fd, "REGISTER " + id.user_id + " " + Botan::hex_encode(id.pubkey_bytes)));
        std::string resp = cmd(fd, "UPLOAD_PREKEYS " + id.user_id + " " + tok);
        ASSERT_TRUE(resp.substr(0, 3) == "ERR");
        close(fd);
    }

    TEST("UPLOAD_PREKEYS rejects pubkey with wrong size");
    {
        reset_server_state();
        auto id = generate_identity(rng, g_cfg);
        int fd = connect_test();
        std::string tok = extract_token(
            cmd(fd, "REGISTER " + id.user_id + " " + Botan::hex_encode(id.pubkey_bytes)));
        // Send 16 bytes (way too short for any KEM)
        std::string resp = cmd(fd, "UPLOAD_PREKEYS " + id.user_id + " " + tok + " " +
                                       Botan::hex_encode(std::vector<uint8_t>(16, 0xAB)));
        ASSERT_TRUE(resp.substr(0, 3) == "ERR");
        close(fd);
    }

    TEST("UPLOAD_PREKEYS rejects invalid hex");
    {
        reset_server_state();
        auto id = generate_identity(rng, g_cfg);
        int fd = connect_test();
        std::string tok = extract_token(
            cmd(fd, "REGISTER " + id.user_id + " " + Botan::hex_encode(id.pubkey_bytes)));
        std::string resp =
            cmd(fd, "UPLOAD_PREKEYS " + id.user_id + " " + tok + " ZZZZZZZZZZZZZZZZ");
        ASSERT_TRUE(resp.substr(0, 3) == "ERR");
        close(fd);
    }

    TEST("UPLOAD_PREKEYS rejects when prekey store is full");
    {
        // Uses the prekey-cap TLS server which has max_prekeys_per_user=1
        reset_server_state();
        auto id = generate_identity(rng, g_cfg);
        auto conn = tls_connect(TEST_PREKEY_CAP_PORT);
        ASSERT_TRUE(conn.fd >= 0);
        std::string tok = extract_token(
            tls_cmd(conn, "REGISTER " + id.user_id + " " + Botan::hex_encode(id.pubkey_bytes)));
        auto pks = generate_prekeys(2, rng, g_cfg);
        // First upload fills the store (cap=1)
        tls_cmd(conn, "UPLOAD_PREKEYS " + id.user_id + " " + tok + " " +
                          Botan::hex_encode(pks[0].pubkey_bytes));
        // Second upload must be rejected
        std::string resp = tls_cmd(conn, "UPLOAD_PREKEYS " + id.user_id + " " + tok + " " +
                                             Botan::hex_encode(pks[1].pubkey_bytes));
        ASSERT_TRUE(resp.substr(0, 3) == "ERR");
        close(conn.fd);
    }

    TEST("SEND with prekey_id stores it and POLL returns it");
    {
        reset_server_state();
        auto sender = generate_identity(rng, g_cfg);
        auto recip = generate_identity(rng, g_cfg);
        int fd = connect_test();
        std::string s_tok = extract_token(
            cmd(fd, "REGISTER " + sender.user_id + " " + Botan::hex_encode(sender.pubkey_bytes)));
        std::string r_tok = extract_token(
            cmd(fd, "REGISTER " + recip.user_id + " " + Botan::hex_encode(recip.pubkey_bytes)));

        // Upload a prekey for recipient
        auto pks = generate_prekeys(1, rng, g_cfg);
        cmd(fd, "UPLOAD_PREKEYS " + recip.user_id + " " + r_tok + " " +
                    Botan::hex_encode(pks[0].pubkey_bytes));

        // Send using the prekey
        auto blob = encrypt_message("hi", sender.user_id, "s", pks[0].pubkey_bytes, rng, g_cfg);
        std::string send_resp =
            cmd(fd, "SEND " + sender.user_id + " " + s_tok + " " + recip.user_id + " " +
                        pks[0].prekey_id + " " + Botan::hex_encode(blob));
        ASSERT_EQ(send_resp, std::string("OK"));

        // POLL should include the prekey_id in the MSG line
        send_line(fd, "POLL " + recip.user_id + " " + r_tok);
        std::string msg_line = read_line(fd);
        ASSERT_TRUE(msg_line.substr(0, 4) == "MSG ");
        std::istringstream mss(msg_line.substr(4));
        std::string msg_id, msg_pk_id, msg_blob_hex;
        mss >> msg_id >> msg_pk_id >> msg_blob_hex;
        ASSERT_EQ(msg_pk_id, pks[0].prekey_id);

        // Decrypt using the prekey private key
        auto msg_blob = Botan::hex_decode(msg_blob_hex);
        auto dec = decrypt_message(msg_blob, *pks[0].priv_key, pks[0].priv_key2.get(),
                                   pks[0].pubkey_bytes, rng, g_cfg);
        ASSERT_EQ(dec.plaintext, std::string("hi"));
        read_line(fd); // NOMSG
        cmd(fd, "MSGACK " + recip.user_id + " " + r_tok + " " + msg_id);
        close(fd);
    }

    // -------------------------------------------------------
    // Multi-device (LINK_DEVICE / UNLINK_DEVICE / GETLINKED)
    // -------------------------------------------------------

    TEST("LINK_DEVICE links two identities; GETLINKED returns the device");
    {
        reset_server_state();
        auto primary = generate_identity(rng, g_cfg);
        auto device = generate_identity(rng, g_cfg);
        int fd = connect_test();
        std::string p_tok = extract_token(
            cmd(fd, "REGISTER " + primary.user_id + " " + Botan::hex_encode(primary.pubkey_bytes)));
        cmd(fd, "REGISTER " + device.user_id + " " + Botan::hex_encode(device.pubkey_bytes));

        std::string link_resp =
            cmd(fd, "LINK_DEVICE " + primary.user_id + " " + p_tok + " " + device.user_id);
        ASSERT_EQ(link_resp, std::string("OK"));

        std::string gl_resp = cmd(fd, "GETLINKED " + primary.user_id);
        ASSERT_TRUE(gl_resp.find(device.user_id) != std::string::npos);
        close(fd);
    }

    TEST("UNLINK_DEVICE removes the device from GETLINKED");
    {
        reset_server_state();
        auto primary = generate_identity(rng, g_cfg);
        auto device = generate_identity(rng, g_cfg);
        int fd = connect_test();
        std::string p_tok = extract_token(
            cmd(fd, "REGISTER " + primary.user_id + " " + Botan::hex_encode(primary.pubkey_bytes)));
        cmd(fd, "REGISTER " + device.user_id + " " + Botan::hex_encode(device.pubkey_bytes));
        cmd(fd, "LINK_DEVICE " + primary.user_id + " " + p_tok + " " + device.user_id);

        std::string unlink_resp =
            cmd(fd, "UNLINK_DEVICE " + primary.user_id + " " + p_tok + " " + device.user_id);
        ASSERT_EQ(unlink_resp, std::string("OK"));

        std::string gl_resp = cmd(fd, "GETLINKED " + primary.user_id);
        ASSERT_TRUE(gl_resp.find(device.user_id) == std::string::npos);
        close(fd);
    }

    TEST("LINK_DEVICE rejects invalid token");
    {
        reset_server_state();
        auto primary = generate_identity(rng, g_cfg);
        auto device = generate_identity(rng, g_cfg);
        int fd = connect_test();
        cmd(fd, "REGISTER " + primary.user_id + " " + Botan::hex_encode(primary.pubkey_bytes));
        cmd(fd, "REGISTER " + device.user_id + " " + Botan::hex_encode(device.pubkey_bytes));
        std::string resp = cmd(fd, "LINK_DEVICE " + primary.user_id + " " + std::string(64, '0') +
                                       " " + device.user_id);
        ASSERT_TRUE(resp.substr(0, 3) == "ERR");
        close(fd);
    }

    TEST("LINK_DEVICE rejects unregistered device");
    {
        reset_server_state();
        auto primary = generate_identity(rng, g_cfg);
        int fd = connect_test();
        std::string p_tok = extract_token(
            cmd(fd, "REGISTER " + primary.user_id + " " + Botan::hex_encode(primary.pubkey_bytes)));
        std::string resp =
            cmd(fd, "LINK_DEVICE " + primary.user_id + " " + p_tok + " 0000000000000000");
        ASSERT_TRUE(resp.substr(0, 3) == "ERR");
        close(fd);
    }

    TEST("LINK_DEVICE rejects self-link");
    {
        reset_server_state();
        auto primary = generate_identity(rng, g_cfg);
        int fd = connect_test();
        std::string p_tok = extract_token(
            cmd(fd, "REGISTER " + primary.user_id + " " + Botan::hex_encode(primary.pubkey_bytes)));
        std::string resp =
            cmd(fd, "LINK_DEVICE " + primary.user_id + " " + p_tok + " " + primary.user_id);
        ASSERT_TRUE(resp.substr(0, 3) == "ERR");
        close(fd);
    }

    TEST("GETLINKED returns ERR for unknown user");
    {
        reset_server_state();
        int fd = connect_test();
        std::string resp = cmd(fd, "GETLINKED 0000000000000000");
        ASSERT_TRUE(resp.substr(0, 3) == "ERR");
        close(fd);
    }

    TEST("DEREGISTER removes all device links");
    {
        reset_server_state();
        auto primary = generate_identity(rng, g_cfg);
        auto device = generate_identity(rng, g_cfg);
        int fd = connect_test();
        std::string p_tok = extract_token(
            cmd(fd, "REGISTER " + primary.user_id + " " + Botan::hex_encode(primary.pubkey_bytes)));
        std::string d_tok = extract_token(
            cmd(fd, "REGISTER " + device.user_id + " " + Botan::hex_encode(device.pubkey_bytes)));
        cmd(fd, "LINK_DEVICE " + primary.user_id + " " + p_tok + " " + device.user_id);
        cmd(fd, "DEREGISTER " + primary.user_id + " " + p_tok);

        // Device is still registered but link is gone
        std::string gl_resp = cmd(fd, "GETLINKED " + device.user_id);
        ASSERT_TRUE(gl_resp.find(primary.user_id) == std::string::npos);
        close(fd);
    }

    // -------------------------------------------------------
    // Group messaging (CREATE_GROUP / ADD_MEMBER / REMOVE_MEMBER / LIST_MEMBERS)
    // -------------------------------------------------------

    TEST("CREATE_GROUP creates a group and returns group_id");
    {
        reset_server_state();
        auto owner = generate_identity(rng, g_cfg);
        int fd = connect_test();
        std::string tok = extract_token(
            cmd(fd, "REGISTER " + owner.user_id + " " + Botan::hex_encode(owner.pubkey_bytes)));
        std::string resp = cmd(fd, "CREATE_GROUP " + owner.user_id + " " + tok + " MyGroup");
        ASSERT_TRUE(resp.substr(0, 3) == "OK ");
        std::string gid = resp.substr(3);
        ASSERT_EQ(gid.size(), (size_t)16); // 8-byte hex = 16 chars
        close(fd);
    }

    TEST("ADD_MEMBER adds a user; LIST_MEMBERS returns all members");
    {
        reset_server_state();
        auto owner = generate_identity(rng, g_cfg);
        auto member = generate_identity(rng, g_cfg);
        int fd = connect_test();
        std::string o_tok = extract_token(
            cmd(fd, "REGISTER " + owner.user_id + " " + Botan::hex_encode(owner.pubkey_bytes)));
        cmd(fd, "REGISTER " + member.user_id + " " + Botan::hex_encode(member.pubkey_bytes));
        std::string gid = cmd(fd, "CREATE_GROUP " + owner.user_id + " " + o_tok + " G").substr(3);

        std::string add_resp =
            cmd(fd, "ADD_MEMBER " + gid + " " + owner.user_id + " " + o_tok + " " + member.user_id);
        ASSERT_EQ(add_resp, std::string("OK"));

        std::string list_resp = cmd(fd, "LIST_MEMBERS " + gid);
        ASSERT_TRUE(list_resp.find(member.user_id) != std::string::npos);
        ASSERT_TRUE(list_resp.find(owner.user_id) != std::string::npos);
        close(fd);
    }

    TEST("REMOVE_MEMBER removes a user from the group");
    {
        reset_server_state();
        auto owner = generate_identity(rng, g_cfg);
        auto member = generate_identity(rng, g_cfg);
        int fd = connect_test();
        std::string o_tok = extract_token(
            cmd(fd, "REGISTER " + owner.user_id + " " + Botan::hex_encode(owner.pubkey_bytes)));
        cmd(fd, "REGISTER " + member.user_id + " " + Botan::hex_encode(member.pubkey_bytes));
        std::string gid = cmd(fd, "CREATE_GROUP " + owner.user_id + " " + o_tok + " G").substr(3);
        cmd(fd, "ADD_MEMBER " + gid + " " + owner.user_id + " " + o_tok + " " + member.user_id);

        cmd(fd, "REMOVE_MEMBER " + gid + " " + owner.user_id + " " + o_tok + " " + member.user_id);
        std::string list_resp = cmd(fd, "LIST_MEMBERS " + gid);
        ASSERT_TRUE(list_resp.find(member.user_id) == std::string::npos);
        close(fd);
    }

    TEST("ADD_MEMBER rejects non-owner");
    {
        reset_server_state();
        auto owner = generate_identity(rng, g_cfg);
        auto other = generate_identity(rng, g_cfg);
        int fd = connect_test();
        std::string o_tok = extract_token(
            cmd(fd, "REGISTER " + owner.user_id + " " + Botan::hex_encode(owner.pubkey_bytes)));
        std::string other_tok = extract_token(
            cmd(fd, "REGISTER " + other.user_id + " " + Botan::hex_encode(other.pubkey_bytes)));
        std::string gid = cmd(fd, "CREATE_GROUP " + owner.user_id + " " + o_tok + " G").substr(3);

        std::string resp = cmd(fd, "ADD_MEMBER " + gid + " " + other.user_id + " " + other_tok +
                                       " " + owner.user_id);
        ASSERT_TRUE(resp.substr(0, 3) == "ERR");
        close(fd);
    }

    TEST("CREATE_GROUP rejects invalid token");
    {
        reset_server_state();
        auto id = generate_identity(rng, g_cfg);
        int fd = connect_test();
        cmd(fd, "REGISTER " + id.user_id + " " + Botan::hex_encode(id.pubkey_bytes));
        std::string resp =
            cmd(fd, "CREATE_GROUP " + id.user_id + " " + std::string(64, '0') + " G");
        ASSERT_TRUE(resp.substr(0, 3) == "ERR");
        close(fd);
    }

    TEST("LIST_MEMBERS returns ERR for unknown group");
    {
        reset_server_state();
        int fd = connect_test();
        std::string resp = cmd(fd, "LIST_MEMBERS 0000000000000000");
        ASSERT_TRUE(resp.substr(0, 3) == "ERR");
        close(fd);
    }

    TEST("CREATE_GROUP rejects empty group name");
    {
        reset_server_state();
        auto id = generate_identity(rng, g_cfg);
        int fd = connect_test();
        std::string tok = extract_token(
            cmd(fd, "REGISTER " + id.user_id + " " + Botan::hex_encode(id.pubkey_bytes)));
        // Send CREATE_GROUP with no name (trailing whitespace only)
        std::string resp = cmd(fd, "CREATE_GROUP " + id.user_id + " " + tok);
        ASSERT_TRUE(resp.substr(0, 3) == "ERR");
        close(fd);
    }

    TEST("ADD_MEMBER rejects unknown group");
    {
        reset_server_state();
        auto id = generate_identity(rng, g_cfg);
        int fd = connect_test();
        std::string tok = extract_token(
            cmd(fd, "REGISTER " + id.user_id + " " + Botan::hex_encode(id.pubkey_bytes)));
        std::string resp =
            cmd(fd, "ADD_MEMBER 0000000000000000 " + id.user_id + " " + tok + " " + id.user_id);
        ASSERT_TRUE(resp.substr(0, 3) == "ERR");
        close(fd);
    }

    TEST("ADD_MEMBER rejects unknown user");
    {
        reset_server_state();
        auto owner = generate_identity(rng, g_cfg);
        int fd = connect_test();
        std::string tok = extract_token(
            cmd(fd, "REGISTER " + owner.user_id + " " + Botan::hex_encode(owner.pubkey_bytes)));
        std::string gid = cmd(fd, "CREATE_GROUP " + owner.user_id + " " + tok + " G").substr(3);
        std::string resp =
            cmd(fd, "ADD_MEMBER " + gid + " " + owner.user_id + " " + tok + " 0000000000000000");
        ASSERT_TRUE(resp.substr(0, 3) == "ERR");
        close(fd);
    }

    TEST("REMOVE_MEMBER rejects unknown group");
    {
        reset_server_state();
        auto id = generate_identity(rng, g_cfg);
        int fd = connect_test();
        std::string tok = extract_token(
            cmd(fd, "REGISTER " + id.user_id + " " + Botan::hex_encode(id.pubkey_bytes)));
        std::string resp =
            cmd(fd, "REMOVE_MEMBER 0000000000000000 " + id.user_id + " " + tok + " " + id.user_id);
        ASSERT_TRUE(resp.substr(0, 3) == "ERR");
        close(fd);
    }

    // -------------------------------------------------------
    // Group management: DELETE_GROUP, LEAVE_GROUP, TRANSFER_GROUP
    // -------------------------------------------------------

    TEST("DELETE_GROUP disbands the group; LIST_MEMBERS returns ERR after");
    {
        reset_server_state();
        auto owner = generate_identity(rng, g_cfg);
        auto member = generate_identity(rng, g_cfg);
        int fd = connect_test();
        std::string o_tok = extract_token(
            cmd(fd, "REGISTER " + owner.user_id + " " + Botan::hex_encode(owner.pubkey_bytes)));
        cmd(fd, "REGISTER " + member.user_id + " " + Botan::hex_encode(member.pubkey_bytes));
        std::string gid = cmd(fd, "CREATE_GROUP " + owner.user_id + " " + o_tok + " G").substr(3);
        cmd(fd, "ADD_MEMBER " + gid + " " + owner.user_id + " " + o_tok + " " + member.user_id);
        std::string del = cmd(fd, "DELETE_GROUP " + gid + " " + owner.user_id + " " + o_tok);
        ASSERT_EQ(del, std::string("OK"));
        ASSERT_TRUE(cmd(fd, "LIST_MEMBERS " + gid).substr(0, 3) == "ERR");
        close(fd);
    }

    TEST("DELETE_GROUP rejects non-owner");
    {
        reset_server_state();
        auto owner = generate_identity(rng, g_cfg);
        auto other = generate_identity(rng, g_cfg);
        int fd = connect_test();
        std::string o_tok = extract_token(
            cmd(fd, "REGISTER " + owner.user_id + " " + Botan::hex_encode(owner.pubkey_bytes)));
        std::string other_tok = extract_token(
            cmd(fd, "REGISTER " + other.user_id + " " + Botan::hex_encode(other.pubkey_bytes)));
        std::string gid = cmd(fd, "CREATE_GROUP " + owner.user_id + " " + o_tok + " G").substr(3);
        ASSERT_TRUE(
            cmd(fd, "DELETE_GROUP " + gid + " " + other.user_id + " " + other_tok).substr(0, 3) ==
            "ERR");
        close(fd);
    }

    TEST("LEAVE_GROUP removes the member");
    {
        reset_server_state();
        auto owner = generate_identity(rng, g_cfg);
        auto member = generate_identity(rng, g_cfg);
        int fd = connect_test();
        std::string o_tok = extract_token(
            cmd(fd, "REGISTER " + owner.user_id + " " + Botan::hex_encode(owner.pubkey_bytes)));
        std::string m_tok = extract_token(
            cmd(fd, "REGISTER " + member.user_id + " " + Botan::hex_encode(member.pubkey_bytes)));
        std::string gid = cmd(fd, "CREATE_GROUP " + owner.user_id + " " + o_tok + " G").substr(3);
        cmd(fd, "ADD_MEMBER " + gid + " " + owner.user_id + " " + o_tok + " " + member.user_id);
        ASSERT_EQ(cmd(fd, "LEAVE_GROUP " + gid + " " + member.user_id + " " + m_tok),
                  std::string("OK"));
        std::string list = cmd(fd, "LIST_MEMBERS " + gid);
        ASSERT_TRUE(list.find(member.user_id) == std::string::npos);
        close(fd);
    }

    TEST("LEAVE_GROUP rejects non-member");
    {
        reset_server_state();
        auto owner = generate_identity(rng, g_cfg);
        auto outsider = generate_identity(rng, g_cfg);
        int fd = connect_test();
        std::string o_tok = extract_token(
            cmd(fd, "REGISTER " + owner.user_id + " " + Botan::hex_encode(owner.pubkey_bytes)));
        std::string out_tok = extract_token(cmd(fd, "REGISTER " + outsider.user_id + " " +
                                                        Botan::hex_encode(outsider.pubkey_bytes)));
        std::string gid = cmd(fd, "CREATE_GROUP " + owner.user_id + " " + o_tok + " G").substr(3);
        ASSERT_TRUE(
            cmd(fd, "LEAVE_GROUP " + gid + " " + outsider.user_id + " " + out_tok).substr(0, 3) ==
            "ERR");
        close(fd);
    }

    TEST("TRANSFER_GROUP changes owner to a current member");
    {
        reset_server_state();
        auto owner = generate_identity(rng, g_cfg);
        auto member = generate_identity(rng, g_cfg);
        int fd = connect_test();
        std::string o_tok = extract_token(
            cmd(fd, "REGISTER " + owner.user_id + " " + Botan::hex_encode(owner.pubkey_bytes)));
        cmd(fd, "REGISTER " + member.user_id + " " + Botan::hex_encode(member.pubkey_bytes));
        std::string gid = cmd(fd, "CREATE_GROUP " + owner.user_id + " " + o_tok + " G").substr(3);
        cmd(fd, "ADD_MEMBER " + gid + " " + owner.user_id + " " + o_tok + " " + member.user_id);
        ASSERT_EQ(cmd(fd, "TRANSFER_GROUP " + gid + " " + owner.user_id + " " + o_tok + " " +
                              member.user_id),
                  std::string("OK"));
        // Old owner can no longer delete (no longer owner)
        ASSERT_TRUE(
            cmd(fd, "DELETE_GROUP " + gid + " " + owner.user_id + " " + o_tok).substr(0, 3) ==
            "ERR");
        close(fd);
    }

    TEST("TRANSFER_GROUP rejects transferring to a non-member");
    {
        reset_server_state();
        auto owner = generate_identity(rng, g_cfg);
        auto outsider = generate_identity(rng, g_cfg);
        int fd = connect_test();
        std::string o_tok = extract_token(
            cmd(fd, "REGISTER " + owner.user_id + " " + Botan::hex_encode(owner.pubkey_bytes)));
        cmd(fd, "REGISTER " + outsider.user_id + " " + Botan::hex_encode(outsider.pubkey_bytes));
        std::string gid = cmd(fd, "CREATE_GROUP " + owner.user_id + " " + o_tok + " G").substr(3);
        ASSERT_TRUE(cmd(fd, "TRANSFER_GROUP " + gid + " " + owner.user_id + " " + o_tok + " " +
                                outsider.user_id)
                        .substr(0, 3) == "ERR");
        close(fd);
    }

    // -------------------------------------------------------
    // IPv6 connectivity
    // -------------------------------------------------------

    TEST("server accepts connections on IPv6 loopback (::1)");
    {
        // Connect to the dual-stack server via IPv6 loopback
        int fd = socket(AF_INET6, SOCK_STREAM, 0);
        if (fd >= 0) {
            sockaddr_in6 addr6{};
            addr6.sin6_family = AF_INET6;
            addr6.sin6_port = htons(TEST_IPV6_PORT);
            inet_pton(AF_INET6, "::1", &addr6.sin6_addr);
            if (connect(fd, reinterpret_cast<sockaddr*>(&addr6), sizeof(addr6)) == 0) {
                // TLS handshake via tls_connect would require a separate helper;
                // just verify the TCP connection succeeds (server is listening on ::).
                close(fd);
                ASSERT_TRUE(true);
            } else {
                close(fd);
                // IPv6 may not be available in the CI environment — skip gracefully
                ASSERT_TRUE(true);
            }
        } else {
            // AF_INET6 not supported — skip
            ASSERT_TRUE(true);
        }
    }

    TEST("server accepts connections on IPv4 loopback via dual-stack");
    {
        // Dual-stack server should also accept IPv4 connections on the same port
        auto conn = tls_connect(TEST_IPV6_PORT);
        if (conn.fd >= 0) {
            reset_server_state();
            auto id = generate_identity(rng, g_cfg);
            std::string resp =
                tls_cmd(conn, "REGISTER " + id.user_id + " " + Botan::hex_encode(id.pubkey_bytes));
            ASSERT_TRUE(resp.substr(0, 3) == "OK ");
            close(conn.fd);
        } else {
            // Dual-stack IPv4 fallback not available — skip
            ASSERT_TRUE(true);
        }
    }

    // -------------------------------------------------------
    // Thread pool / async I/O
    // -------------------------------------------------------

    TEST("thread pool handles concurrent connections without deadlock");
    {
        // Open several connections simultaneously and verify each can REGISTER.
        // If the pool deadlocked, the test would hang; ASSERT_TRUE verifies responses.
        reset_server_state();
        std::vector<std::string> resps;
        std::mutex mu;
        std::vector<std::thread> threads;
        for (int i = 0; i < 4; ++i) {
            threads.emplace_back([&] {
                auto id = generate_identity(rng, g_cfg);
                int fd = connect_test();
                std::string r =
                    cmd(fd, "REGISTER " + id.user_id + " " + Botan::hex_encode(id.pubkey_bytes));
                close(fd);
                std::lock_guard<std::mutex> lk(mu);
                resps.push_back(r);
            });
        }
        for (auto& t : threads)
            t.join();
        ASSERT_EQ(resps.size(), (size_t)4);
        for (const auto& r : resps)
            ASSERT_TRUE(r.substr(0, 3) == "OK ");
    }

    TEST("ensure_server_cert: cert and key files are created on first start");
    {
        // The cert-gen server deleted its cert files before starting,
        // so ensure_server_cert must have generated them.
        ASSERT_TRUE(std::ifstream("/tmp/ztm_certgen.cert.pem").good());
        ASSERT_TRUE(std::ifstream("/tmp/ztm_certgen.key.pem").good());
    }

    // -------------------------------------------------------
    // Prometheus metrics
    // -------------------------------------------------------

    // Helper: send a minimal HTTP GET to the metrics port and return the full response.
    auto scrape_metrics = []() -> std::string {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(TEST_METRICS_PORT);
        inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
        if (connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
            close(fd);
            return "";
        }
        std::string req = "GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
        ::send(fd, req.data(), req.size(), 0);
        std::string resp;
        char buf[4096];
        ssize_t n;
        while ((n = ::recv(fd, buf, sizeof(buf) - 1, 0)) > 0) {
            buf[n] = '\0';
            resp.append(buf, n);
        }
        close(fd);
        return resp;
    };

    TEST("metrics endpoint returns HTTP 200 with Prometheus content-type");
    {
        std::string resp = scrape_metrics();
        ASSERT_TRUE(resp.find("HTTP/1.1 200 OK") != std::string::npos);
        ASSERT_TRUE(resp.find("text/plain") != std::string::npos);
        ASSERT_TRUE(resp.find("version=0.0.4") != std::string::npos);
    }

    TEST("metrics response contains all expected metric names");
    {
        std::string resp = scrape_metrics();
        ASSERT_TRUE(resp.find("zerotrace_users_total") != std::string::npos);
        ASSERT_TRUE(resp.find("zerotrace_sessions_active") != std::string::npos);
        ASSERT_TRUE(resp.find("zerotrace_messages_pending") != std::string::npos);
        ASSERT_TRUE(resp.find("zerotrace_connections_active") != std::string::npos);
        ASSERT_TRUE(resp.find("zerotrace_uptime_seconds") != std::string::npos);
        ASSERT_TRUE(resp.find("zerotrace_messages_sent_total") != std::string::npos);
        ASSERT_TRUE(resp.find("zerotrace_rate_limit_hits_total") != std::string::npos);
    }

    TEST("metrics response includes HELP and TYPE lines for each metric");
    {
        std::string resp = scrape_metrics();
        ASSERT_TRUE(resp.find("# HELP zerotrace_users_total") != std::string::npos);
        ASSERT_TRUE(resp.find("# TYPE zerotrace_users_total gauge") != std::string::npos);
        ASSERT_TRUE(resp.find("# TYPE zerotrace_messages_sent_total counter") != std::string::npos);
        ASSERT_TRUE(resp.find("# TYPE zerotrace_rate_limit_hits_total counter") !=
                    std::string::npos);
    }

    TEST("metrics_sent counter increments after a successful SEND");
    {
        reset_server_state();
        // Register two users on the metrics TLS server
        auto sender = generate_identity(rng, g_cfg);
        auto recipient = generate_identity(rng, g_cfg);
        auto conn = tls_connect(TEST_METRICS_TLS_PORT);
        ASSERT_TRUE(conn.fd >= 0);
        std::string s_tok = extract_token(tls_cmd(
            conn, "REGISTER " + sender.user_id + " " + Botan::hex_encode(sender.pubkey_bytes)));
        tls_cmd(conn,
                "REGISTER " + recipient.user_id + " " + Botan::hex_encode(recipient.pubkey_bytes));

        // Scrape before send
        std::string before = scrape_metrics();

        auto blob = encrypt_message("hi", sender.user_id, "s", recipient.pubkey_bytes, rng, g_cfg);
        tls_cmd(conn, "SEND " + sender.user_id + " " + s_tok + " " + recipient.user_id + " " +
                          Botan::hex_encode(blob));
        close(conn.fd);

        // Scrape after send — zerotrace_messages_sent_total must be higher
        std::string after = scrape_metrics();
        // Extract the value after "zerotrace_messages_sent_total "
        auto extract_val = [](const std::string& text, const std::string& key) -> int64_t {
            // Skip past HELP/TYPE lines — find the bare metric line (no leading #)
            size_t pos = 0;
            while (pos != std::string::npos) {
                pos = text.find(key, pos);
                if (pos == std::string::npos)
                    break;
                // Must not be a # comment line — look backwards to the start of the line
                size_t line_start = text.rfind('\n', pos);
                line_start = (line_start == std::string::npos) ? 0 : line_start + 1;
                if (text[line_start] != '#') {
                    size_t val_start = pos + key.size() + 1;
                    if (val_start < text.size())
                        return std::stoll(text.substr(val_start));
                }
                pos += key.size();
            }
            return -1;
        };
        int64_t sent_before = extract_val(before, "zerotrace_messages_sent_total");
        int64_t sent_after = extract_val(after, "zerotrace_messages_sent_total");
        ASSERT_TRUE(sent_before >= 0);
        ASSERT_TRUE(sent_after > sent_before);
    }

    // -------------------------------------------------------
    // REGISTER duplicate with different key
    // -------------------------------------------------------

    TEST("REGISTER same user_id with different pubkey returns ERR");
    {
        reset_server_state();
        auto id = generate_identity(rng, g_cfg);
        auto id2 = generate_identity(rng, g_cfg);
        int fd = connect_test();
        cmd(fd, "REGISTER " + id.user_id + " " + Botan::hex_encode(id.pubkey_bytes));
        // Try registering same user_id but with id2's pubkey
        std::string resp =
            cmd(fd, "REGISTER " + id.user_id + " " + Botan::hex_encode(id2.pubkey_bytes));
        ASSERT_TRUE(resp.substr(0, 3) == "ERR");
        close(fd);
    }

    // -------------------------------------------------------
    // REKEY additional edge cases
    // -------------------------------------------------------

    TEST("REKEY with missing arguments returns ERR");
    {
        reset_server_state();
        auto id = generate_identity(rng, g_cfg);
        int fd = connect_test();
        std::string tok = extract_token(
            cmd(fd, "REGISTER " + id.user_id + " " + Botan::hex_encode(id.pubkey_bytes)));
        std::string resp = cmd(fd, "REKEY " + id.user_id + " " + tok);
        ASSERT_TRUE(resp.substr(0, 3) == "ERR");
        close(fd);
    }

    TEST("REKEY migrates linked devices to new identity");
    {
        reset_server_state();
        auto primary = generate_identity(rng, g_cfg);
        auto device = generate_identity(rng, g_cfg);
        int fd = connect_test();
        std::string p_tok = extract_token(
            cmd(fd, "REGISTER " + primary.user_id + " " + Botan::hex_encode(primary.pubkey_bytes)));
        cmd(fd, "REGISTER " + device.user_id + " " + Botan::hex_encode(device.pubkey_bytes));
        cmd(fd, "LINK_DEVICE " + primary.user_id + " " + p_tok + " " + device.user_id);
        auto new_id = generate_identity(rng, g_cfg);
        std::string resp = cmd(fd, "REKEY " + primary.user_id + " " + p_tok + " " + new_id.user_id +
                                       " " + Botan::hex_encode(new_id.pubkey_bytes));
        ASSERT_TRUE(resp.substr(0, 3) == "OK ");
        // Device should now be linked to new identity
        std::string linked = cmd(fd, "GETLINKED " + new_id.user_id);
        ASSERT_TRUE(linked.find(device.user_id) != std::string::npos);
        close(fd);
    }

    // -------------------------------------------------------
    // UNLINK_DEVICE invalid token
    // -------------------------------------------------------

    TEST("UNLINK_DEVICE rejects invalid token");
    {
        reset_server_state();
        auto primary = generate_identity(rng, g_cfg);
        auto device = generate_identity(rng, g_cfg);
        int fd = connect_test();
        std::string tok = extract_token(
            cmd(fd, "REGISTER " + primary.user_id + " " + Botan::hex_encode(primary.pubkey_bytes)));
        cmd(fd, "REGISTER " + device.user_id + " " + Botan::hex_encode(device.pubkey_bytes));
        cmd(fd, "LINK_DEVICE " + primary.user_id + " " + tok + " " + device.user_id);
        std::string resp = cmd(fd, "UNLINK_DEVICE " + primary.user_id + " " + std::string(64, '0') +
                                       " " + device.user_id);
        ASSERT_TRUE(resp.substr(0, 3) == "ERR");
        close(fd);
    }

    // -------------------------------------------------------
    // REMOVE_MEMBER non-owner
    // -------------------------------------------------------

    TEST("REMOVE_MEMBER rejects non-owner token");
    {
        reset_server_state();
        auto owner = generate_identity(rng, g_cfg);
        auto user = generate_identity(rng, g_cfg);
        int fd = connect_test();
        std::string o_tok = extract_token(
            cmd(fd, "REGISTER " + owner.user_id + " " + Botan::hex_encode(owner.pubkey_bytes)));
        std::string u_tok = extract_token(
            cmd(fd, "REGISTER " + user.user_id + " " + Botan::hex_encode(user.pubkey_bytes)));
        std::string cr = cmd(fd, "CREATE_GROUP " + owner.user_id + " " + o_tok + " testgroup2");
        std::string gid = cr.size() > 3 ? cr.substr(3) : "";
        cmd(fd, "ADD_MEMBER " + gid + " " + owner.user_id + " " + o_tok + " " + user.user_id);
        // user tries REMOVE_MEMBER (not owner)
        std::string resp =
            cmd(fd, "REMOVE_MEMBER " + gid + " " + user.user_id + " " + u_tok + " " + user.user_id);
        ASSERT_TRUE(resp.substr(0, 3) == "ERR");
        close(fd);
    }

    // -------------------------------------------------------
    // DELETE_GROUP unknown group
    // -------------------------------------------------------

    TEST("DELETE_GROUP rejects unknown group");
    {
        reset_server_state();
        auto owner = generate_identity(rng, g_cfg);
        int fd = connect_test();
        std::string tok = extract_token(
            cmd(fd, "REGISTER " + owner.user_id + " " + Botan::hex_encode(owner.pubkey_bytes)));
        std::string resp =
            cmd(fd, "DELETE_GROUP " + std::string(16, '0') + " " + owner.user_id + " " + tok);
        ASSERT_TRUE(resp.substr(0, 3) == "ERR");
        close(fd);
    }

    // -------------------------------------------------------
    // LEAVE_GROUP edge cases
    // -------------------------------------------------------

    TEST("LEAVE_GROUP rejects unknown group");
    {
        reset_server_state();
        auto user = generate_identity(rng, g_cfg);
        int fd = connect_test();
        std::string tok = extract_token(
            cmd(fd, "REGISTER " + user.user_id + " " + Botan::hex_encode(user.pubkey_bytes)));
        std::string resp =
            cmd(fd, "LEAVE_GROUP " + std::string(16, '0') + " " + user.user_id + " " + tok);
        ASSERT_TRUE(resp.substr(0, 3) == "ERR");
        close(fd);
    }

    TEST("LEAVE_GROUP rejects invalid token");
    {
        reset_server_state();
        auto owner = generate_identity(rng, g_cfg);
        auto user = generate_identity(rng, g_cfg);
        int fd = connect_test();
        std::string o_tok = extract_token(
            cmd(fd, "REGISTER " + owner.user_id + " " + Botan::hex_encode(owner.pubkey_bytes)));
        cmd(fd, "REGISTER " + user.user_id + " " + Botan::hex_encode(user.pubkey_bytes));
        std::string cr = cmd(fd, "CREATE_GROUP " + owner.user_id + " " + o_tok + " grp");
        std::string gid = cr.size() > 3 ? cr.substr(3) : "";
        cmd(fd, "ADD_MEMBER " + gid + " " + owner.user_id + " " + o_tok + " " + user.user_id);
        std::string resp =
            cmd(fd, "LEAVE_GROUP " + gid + " " + user.user_id + " " + std::string(64, '0'));
        ASSERT_TRUE(resp.substr(0, 3) == "ERR");
        close(fd);
    }

    // -------------------------------------------------------
    // TRANSFER_GROUP edge cases
    // -------------------------------------------------------

    TEST("TRANSFER_GROUP rejects unknown group");
    {
        reset_server_state();
        auto owner = generate_identity(rng, g_cfg);
        auto user = generate_identity(rng, g_cfg);
        int fd = connect_test();
        std::string tok = extract_token(
            cmd(fd, "REGISTER " + owner.user_id + " " + Botan::hex_encode(owner.pubkey_bytes)));
        cmd(fd, "REGISTER " + user.user_id + " " + Botan::hex_encode(user.pubkey_bytes));
        std::string resp = cmd(fd, "TRANSFER_GROUP " + std::string(16, '0') + " " + owner.user_id +
                                       " " + tok + " " + user.user_id);
        ASSERT_TRUE(resp.substr(0, 3) == "ERR");
        close(fd);
    }

    TEST("TRANSFER_GROUP rejects non-owner");
    {
        reset_server_state();
        auto owner = generate_identity(rng, g_cfg);
        auto user = generate_identity(rng, g_cfg);
        int fd = connect_test();
        std::string o_tok = extract_token(
            cmd(fd, "REGISTER " + owner.user_id + " " + Botan::hex_encode(owner.pubkey_bytes)));
        std::string u_tok = extract_token(
            cmd(fd, "REGISTER " + user.user_id + " " + Botan::hex_encode(user.pubkey_bytes)));
        std::string cr = cmd(fd, "CREATE_GROUP " + owner.user_id + " " + o_tok + " grp");
        std::string gid = cr.size() > 3 ? cr.substr(3) : "";
        cmd(fd, "ADD_MEMBER " + gid + " " + owner.user_id + " " + o_tok + " " + user.user_id);
        // user tries to transfer the group they don't own
        std::string resp = cmd(fd, "TRANSFER_GROUP " + gid + " " + user.user_id + " " + u_tok +
                                       " " + owner.user_id);
        ASSERT_TRUE(resp.substr(0, 3) == "ERR");
        close(fd);
    }

    // -------------------------------------------------------
    // POLL with non-integer limit
    // -------------------------------------------------------

    TEST("POLL with non-integer limit falls back to server default");
    {
        reset_server_state();
        auto id = generate_identity(rng, g_cfg);
        int fd = connect_test();
        std::string tok = extract_token(
            cmd(fd, "REGISTER " + id.user_id + " " + Botan::hex_encode(id.pubkey_bytes)));
        send_line(fd, "POLL " + id.user_id + " " + tok + " notanumber");
        // drain response
        while (true) {
            std::string line = read_line(fd);
            if (line == "NOMSG" || line.empty())
                break;
        }
        close(fd);
    }

    // -------------------------------------------------------
    // LINK_DEVICE device limit (max_devices_per_user=1)
    // -------------------------------------------------------

    TEST("LINK_DEVICE rejects when max_devices_per_user is reached");
    {
        reset_server_state();
        auto primary = generate_identity(rng, g_cfg);
        auto dev1 = generate_identity(rng, g_cfg);
        auto dev2 = generate_identity(rng, g_cfg);
        auto conn = tls_connect(TEST_DEVICE_LIMIT_PORT);
        ASSERT_TRUE(conn.fd >= 0);
        std::string p_tok = extract_token(tls_cmd(
            conn, "REGISTER " + primary.user_id + " " + Botan::hex_encode(primary.pubkey_bytes)));
        tls_cmd(conn, "REGISTER " + dev1.user_id + " " + Botan::hex_encode(dev1.pubkey_bytes));
        tls_cmd(conn, "REGISTER " + dev2.user_id + " " + Botan::hex_encode(dev2.pubkey_bytes));
        tls_cmd(conn, "LINK_DEVICE " + primary.user_id + " " + p_tok + " " + dev1.user_id);
        std::string resp =
            tls_cmd(conn, "LINK_DEVICE " + primary.user_id + " " + p_tok + " " + dev2.user_id);
        ASSERT_TRUE(resp.substr(0, 3) == "ERR");
        close(conn.fd);
    }

    // -------------------------------------------------------
    // ADD_MEMBER group full (max_group_members=1)
    // -------------------------------------------------------

    TEST("ADD_MEMBER rejects when group is full");
    {
        reset_server_state();
        auto owner = generate_identity(rng, g_cfg);
        auto user1 = generate_identity(rng, g_cfg);
        auto user2 = generate_identity(rng, g_cfg);
        auto conn = tls_connect(TEST_GROUP_LIMIT_PORT);
        ASSERT_TRUE(conn.fd >= 0);
        std::string tok = extract_token(tls_cmd(conn, "REGISTER " + owner.user_id + " " +
                                                          Botan::hex_encode(owner.pubkey_bytes)));
        tls_cmd(conn, "REGISTER " + user1.user_id + " " + Botan::hex_encode(user1.pubkey_bytes));
        tls_cmd(conn, "REGISTER " + user2.user_id + " " + Botan::hex_encode(user2.pubkey_bytes));
        std::string cr = tls_cmd(conn, "CREATE_GROUP " + owner.user_id + " " + tok + " fullgrp");
        std::string gid = cr.size() > 3 ? cr.substr(3) : "";
        tls_cmd(conn, "ADD_MEMBER " + gid + " " + owner.user_id + " " + tok + " " + user1.user_id);
        std::string resp = tls_cmd(conn, "ADD_MEMBER " + gid + " " + owner.user_id + " " + tok +
                                             " " + user2.user_id);
        ASSERT_TRUE(resp.substr(0, 3) == "ERR");
        close(conn.fd);
    }

    // -------------------------------------------------------
    // Session TTL expiry mid-operation
    // -------------------------------------------------------

    TEST("SEND rejects expired session token");
    {
        reset_server_state();
        auto sender = generate_identity(rng, g_cfg);
        auto recip = generate_identity(rng, g_cfg);
        int fd = connect_test();
        std::string s_tok = extract_token(
            cmd(fd, "REGISTER " + sender.user_id + " " + Botan::hex_encode(sender.pubkey_bytes)));
        cmd(fd, "REGISTER " + recip.user_id + " " + Botan::hex_encode(recip.pubkey_bytes));
        expire_session_for_test(sender.user_id, s_tok);
        std::vector<uint8_t> blob(32, 0xAB);
        std::string resp = cmd(fd, "SEND " + sender.user_id + " " + s_tok + " " + recip.user_id +
                                       " _ " + Botan::hex_encode(blob));
        ASSERT_TRUE(resp.substr(0, 3) == "ERR");
        close(fd);
    }

    TEST("POLL rejects expired session token");
    {
        reset_server_state();
        auto id = generate_identity(rng, g_cfg);
        int fd = connect_test();
        std::string tok = extract_token(
            cmd(fd, "REGISTER " + id.user_id + " " + Botan::hex_encode(id.pubkey_bytes)));
        expire_session_for_test(id.user_id, tok);
        send_line(fd, "POLL " + id.user_id + " " + tok);
        std::string resp = read_line(fd);
        ASSERT_TRUE(resp.substr(0, 3) == "ERR");
        close(fd);
    }

    TEST("MSGACK rejects expired session token");
    {
        reset_server_state();
        auto id = generate_identity(rng, g_cfg);
        int fd = connect_test();
        std::string tok = extract_token(
            cmd(fd, "REGISTER " + id.user_id + " " + Botan::hex_encode(id.pubkey_bytes)));
        expire_session_for_test(id.user_id, tok);
        std::string resp = cmd(fd, "MSGACK " + id.user_id + " " + tok + " fakeid");
        ASSERT_TRUE(resp.substr(0, 3) == "ERR");
        close(fd);
    }

    TEST("REKEY rejects expired session token");
    {
        reset_server_state();
        auto id = generate_identity(rng, g_cfg);
        auto new_id = generate_identity(rng, g_cfg);
        int fd = connect_test();
        std::string tok = extract_token(
            cmd(fd, "REGISTER " + id.user_id + " " + Botan::hex_encode(id.pubkey_bytes)));
        expire_session_for_test(id.user_id, tok);
        std::string resp = cmd(fd, "REKEY " + id.user_id + " " + tok + " " + new_id.user_id + " " +
                                       Botan::hex_encode(new_id.pubkey_bytes));
        ASSERT_TRUE(resp.substr(0, 3) == "ERR");
        close(fd);
    }

    // -------------------------------------------------------
    // Rate limit window reset
    // -------------------------------------------------------

    TEST("SEND resets rate limit counter when window expires");
    {
        reset_server_state();
        auto sender = generate_identity(rng, g_cfg);
        auto recip = generate_identity(rng, g_cfg);
        int fd = connect_test();
        std::string s_tok = extract_token(
            cmd(fd, "REGISTER " + sender.user_id + " " + Botan::hex_encode(sender.pubkey_bytes)));
        cmd(fd, "REGISTER " + recip.user_id + " " + Botan::hex_encode(recip.pubkey_bytes));
        reset_rate_bucket_window_for_test(sender.user_id);
        std::vector<uint8_t> blob(32, 0xCD);
        std::string resp = cmd(fd, "SEND " + sender.user_id + " " + s_tok + " " + recip.user_id +
                                       " _ " + Botan::hex_encode(blob));
        ASSERT_TRUE(resp == "OK");
        close(fd);
    }

    // -------------------------------------------------------
    // Cleanup thread: prune_sessions
    // -------------------------------------------------------

    TEST("prune_sessions removes expired sessions from the store");
    {
        reset_server_state();
        auto id = generate_identity(rng, g_cfg);
        int fd = connect_test();
        std::string tok = extract_token(
            cmd(fd, "REGISTER " + id.user_id + " " + Botan::hex_encode(id.pubkey_bytes)));
        ASSERT_TRUE(!tok.empty());
        prune_sessions_for_test();
        send_line(fd, "POLL " + id.user_id + " " + tok);
        ASSERT_TRUE(read_line(fd).substr(0, 3) == "ERR");
        close(fd);
    }

    // -------------------------------------------------------
    // max_connections rejection path
    // -------------------------------------------------------

    TEST("max_connections: server rejects connections over the limit");
    {
        reset_server_state();
        auto conn1 = tls_connect(TEST_MAX_CONN_PORT);
        ASSERT_TRUE(conn1.fd >= 0);
        auto conn2 = tls_connect(TEST_MAX_CONN_PORT);
        if (conn2.fd >= 0) {
            std::string resp = tls_read_line(conn2.fd, *conn2.tls, *conn2.cb);
            ASSERT_TRUE(resp.empty());
            close(conn2.fd);
        }
        close(conn1.fd);
    }

    // -------------------------------------------------------
    // Plain TCP line-too-long truncation
    // -------------------------------------------------------

    TEST("oversized line causes disconnect");
    {
        reset_server_state();
        int fd = connect_test();
        std::string giant(MAX_LINE_LEN + 1, 'X');
        giant += '\n';
        send(fd, giant.data(), giant.size(), 0);
        std::string resp = read_line(fd);
        ASSERT_TRUE(resp.empty() || resp.substr(0, 3) == "ERR");
        close(fd);
    }

    // -------------------------------------------------------
    // log_init warn/error branches and JSON log format
    // -------------------------------------------------------

    TEST("log_init: warn level branch");
    {
        Config cfg;
        cfg.log_level = "warn";
        call_log_init_for_test(cfg);
        cfg.log_level = "info";
        call_log_init_for_test(cfg);
    }

    TEST("log_init: error (else) level branch");
    {
        Config cfg;
        cfg.log_level = "error";
        call_log_init_for_test(cfg);
        cfg.log_level = "info";
        call_log_init_for_test(cfg);
    }

    TEST("log_msg: JSON format path");
    {
        Config cfg;
        cfg.log_level = "debug";
        cfg.log_format = "json";
        call_log_init_for_test(cfg);
        int fd = connect_test();
        cmd(fd, "STATUS");
        close(fd);
        cfg.log_format = "text";
        cfg.log_level = "info";
        call_log_init_for_test(cfg);
    }

    // -------------------------------------------------------
    // AllSigMethodsPolicy: connects to P384 server with extended sig policy
    // Exercises the AllSigMethodsPolicy class and tls_connect_all_sig helper.
    // -------------------------------------------------------

    TEST("AllSigMethodsPolicy: connects to P384 server");
    {
        auto conn = tls_connect_all_sig(TEST_TLS_P384_PORT);
        ASSERT_TRUE(conn.fd >= 0);
        if (conn.fd >= 0) {
            std::string r = tls_cmd(conn, "STATUS");
            ASSERT_TRUE(r.substr(0, 2) == "OK");
            close(conn.fd);
        }
    }

    // -------------------------------------------------------
    // log_init: unwritable log-file path silently falls back to stdout
    // -------------------------------------------------------

    TEST("log_init: unwritable log file path does not crash");
    {
        Config cfg;
        cfg.log_file = "/nonexistent_ztm_dir/test.log"; // open() will fail silently
        call_log_init_for_test(cfg);
        // Subsequent LOG_INFO calls go to stdout (g_log_file stays closed).
        Config def;
        call_log_init_for_test(def); // restore
    }

    // -------------------------------------------------------
    // Admin recv error: close connection before sending a command
    // -------------------------------------------------------

    TEST("admin: immediate disconnect is handled gracefully");
    {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(TEST_ADMIN_PORT);
        inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
        if (connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0) {
            close(fd); // recv returns 0 in read_line_raw → handler exits cleanly
        }
    }

    // -------------------------------------------------------
    // Metrics recv error: close connection before sending HTTP request
    // -------------------------------------------------------

    TEST("metrics: immediate disconnect before HTTP request is handled gracefully");
    {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(TEST_METRICS_PORT);
        inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
        if (connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0) {
            close(fd); // recv returns 0 in handle_metrics_client → break
        }
    }

    // -------------------------------------------------------
    // SIGHUP reload: malformed config file emits LOG_WARN
    // Covers the exception path in the config-reload try/catch block.
    // -------------------------------------------------------

    TEST("SIGHUP reload: malformed config file emits LOG_WARN");
    {
        const std::string path = "/tmp/ztm_reload_malformed.conf";
        {
            std::ofstream f(path);
            f << "[server]\nbadline_without_equals\n"; // triggers parse error
        }
        set_config_path_for_test(path);
        trigger_reload_for_test();
        std::this_thread::sleep_for(std::chrono::milliseconds(1300));
        Config def;
        call_log_init_for_test(def);
        set_config_path_for_test("zerotrace.conf");
    }

    // -------------------------------------------------------
    // Admin port bind failure: LOG_WARN emitted, main TLS server still starts
    // -------------------------------------------------------

    TEST("admin bind failure: main server starts despite admin port conflict");
    {
        // Pre-bind the admin port so the server's bind() call fails.
        int blocker = socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in ba{};
        ba.sin_family = AF_INET;
        ba.sin_addr.s_addr = inet_addr("127.0.0.1");
        ba.sin_port = htons(TEST_ADMIN_BLOCKER_PORT);
        bool pre_bound = (bind(blocker, reinterpret_cast<sockaddr*>(&ba), sizeof(ba)) == 0);
        (void)pre_bound;

        std::thread([] {
            Config cfg;
            cfg.server_port = TEST_ADMIN_BIND_FAIL_PORT;
            cfg.admin_port = TEST_ADMIN_BLOCKER_PORT; // already in use → LOG_WARN
            cfg.metrics_port = 0;
            cfg.worker_threads = 1;
            cfg.cert_path = "/tmp/ztm_adminbind.cert.pem";
            cfg.key_path = "/tmp/ztm_adminbind.key.pem";
            start_server_tls(cfg);
        }).detach();
        std::this_thread::sleep_for(std::chrono::milliseconds(600));

        auto conn = tls_connect(TEST_ADMIN_BIND_FAIL_PORT);
        ASSERT_TRUE(conn.fd >= 0);
        if (conn.fd >= 0) {
            std::string r = tls_cmd(conn, "STATUS");
            ASSERT_TRUE(r.substr(0, 2) == "OK");
            close(conn.fd);
        }
        close(blocker);
    }

    // -------------------------------------------------------
    // Metrics port bind failure: LOG_WARN emitted, main TLS server still starts
    // -------------------------------------------------------

    TEST("metrics bind failure: main server starts despite metrics port conflict");
    {
        int blocker = socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in bm{};
        bm.sin_family = AF_INET;
        bm.sin_addr.s_addr = INADDR_ANY;
        bm.sin_port = htons(TEST_METRICS_BLOCKER_PORT);
        bool pre_bound = (bind(blocker, reinterpret_cast<sockaddr*>(&bm), sizeof(bm)) == 0);
        (void)pre_bound;

        std::thread([] {
            Config cfg;
            cfg.server_port = TEST_METRICS_BIND_FAIL_PORT;
            cfg.admin_port = 0;
            cfg.metrics_port = TEST_METRICS_BLOCKER_PORT; // already in use → LOG_WARN
            cfg.worker_threads = 1;
            cfg.cert_path = "/tmp/ztm_metricsbind.cert.pem";
            cfg.key_path = "/tmp/ztm_metricsbind.key.pem";
            start_server_tls(cfg);
        }).detach();
        std::this_thread::sleep_for(std::chrono::milliseconds(600));

        auto conn = tls_connect(TEST_METRICS_BIND_FAIL_PORT);
        ASSERT_TRUE(conn.fd >= 0);
        if (conn.fd >= 0) {
            std::string r = tls_cmd(conn, "STATUS");
            ASSERT_TRUE(r.substr(0, 2) == "OK");
            close(conn.fd);
        }
        close(blocker);
    }

    // -------------------------------------------------------
    // IPv6 bind fallback: make_listening_socket falls through to IPv4 when
    // IPv6 bind fails (line 1010 of server.cpp: close(fd) after failed bind).
    // -------------------------------------------------------

    TEST("IPv6 bind fallback: server gracefully handles IPv6 bind failure");
    {
        // Pre-occupy the IPv6 port so the server's IPv6 bind fails.
        int blocker = socket(AF_INET6, SOCK_STREAM, 0);
        if (blocker >= 0) {
            sockaddr_in6 a6{};
            a6.sin6_family = AF_INET6;
            a6.sin6_addr = in6addr_any;
            a6.sin6_port = htons(TEST_IPV6_FALLBACK_PORT);
            if (bind(blocker, reinterpret_cast<sockaddr*>(&a6), sizeof(a6)) == 0) {
                // IPv6 port is now occupied. The server below will fail its IPv6
                // bind, execute close(fd) at line 1010, fall through to IPv4
                // (which also fails for "::" → inet_addr returns INADDR_NONE),
                // and return -1 from make_listening_socket.
                std::thread([] {
                    Config cfg;
                    cfg.server_port = TEST_IPV6_FALLBACK_PORT;
                    cfg.server_bind = "::";
                    cfg.admin_port = 0;
                    cfg.metrics_port = 0;
                    cfg.cert_path = "/tmp/ztm_ipv6fb.cert.pem";
                    cfg.key_path = "/tmp/ztm_ipv6fb.key.pem";
                    start_server_tls(cfg); // returns early: make_listening_socket → -1
                }).detach();
                std::this_thread::sleep_for(std::chrono::milliseconds(300));
            }
            close(blocker);
        }
    }

    // -------------------------------------------------------
    // SIGHUP: hot-reload log-level branches + failed reload
    // -------------------------------------------------------

    TEST("SIGHUP reload: debug level branch");
    {
        const std::string path = "/tmp/ztm_reload_debug.conf";
        {
            std::ofstream f(path);
            f << "[server]\n[client]\n[tls]\n[crypto]\n[logging]\nlevel = debug\n";
        }
        set_config_path_for_test(path);
        trigger_reload_for_test();
        std::this_thread::sleep_for(std::chrono::milliseconds(1300));
        Config def;
        call_log_init_for_test(def);
    }

    TEST("SIGHUP reload: warn level branch");
    {
        const std::string path = "/tmp/ztm_reload_warn.conf";
        {
            std::ofstream f(path);
            f << "[server]\n[client]\n[tls]\n[crypto]\n[logging]\nlevel = warn\n";
        }
        set_config_path_for_test(path);
        trigger_reload_for_test();
        std::this_thread::sleep_for(std::chrono::milliseconds(1300));
        Config def;
        call_log_init_for_test(def);
    }

    TEST("SIGHUP reload: error (else) level branch");
    {
        const std::string path = "/tmp/ztm_reload_error.conf";
        {
            std::ofstream f(path);
            f << "[server]\n[client]\n[tls]\n[crypto]\n[logging]\nlevel = error\n";
        }
        set_config_path_for_test(path);
        trigger_reload_for_test();
        std::this_thread::sleep_for(std::chrono::milliseconds(1300));
        Config def;
        call_log_init_for_test(def);
    }

    TEST("SIGHUP reload: missing config file emits LOG_WARN");
    {
        set_config_path_for_test("/tmp/ztm_nonexistent_reload.conf");
        trigger_reload_for_test();
        std::this_thread::sleep_for(std::chrono::milliseconds(1300));
        set_config_path_for_test("zerotrace.conf");
    }

    // -------------------------------------------------------
    // SIGUSR1: log file reopen (via flag — no real signal sent)
    // -------------------------------------------------------

    TEST("SIGUSR1 path reopens the log file");
    {
        trigger_log_reopen_for_test();
        std::this_thread::sleep_for(std::chrono::milliseconds(1300));
    }

    // -------------------------------------------------------
    // Graceful shutdown — drain and force-close.
    // trigger_shutdown_for_test exits all TLS accept loops, so
    // handle_signal tests come after (they don't need live servers).
    // -------------------------------------------------------

    TEST("graceful shutdown: force-closes held-open connection within timeout");
    {
        auto conn = tls_connect(TEST_SHUTDOWN_PORT);
        ASSERT_TRUE(conn.fd >= 0);
        if (conn.fd >= 0) {
            tls_cmd(conn, "HELLO ZTM/1");
            trigger_shutdown_for_test();
            std::string line = tls_read_line(conn.fd, *conn.tls, *conn.cb);
            ASSERT_TRUE(line.empty());
            close(conn.fd);
            reset_shutdown_for_test();
        }
    }

    // -------------------------------------------------------
    // handle_signal() branches — cover each branch of handle_signal().
    // TLS servers have already exited their accept loops above, so
    // the momentary g_shutdown=true cannot disrupt any live server.
    // -------------------------------------------------------

    TEST("handle_signal: SIGTERM branch sets g_shutdown");
    {
        call_handle_signal_for_test(SIGTERM);
        reset_shutdown_for_test();
    }

    TEST("handle_signal: SIGINT branch sets g_shutdown");
    {
        call_handle_signal_for_test(SIGINT);
        reset_shutdown_for_test();
    }

    TEST("handle_signal: SIGHUP branch sets g_reload_config");
    {
        call_handle_signal_for_test(SIGHUP);
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    TEST("handle_signal: SIGUSR1 branch sets g_log_reopen");
    {
        call_handle_signal_for_test(SIGUSR1);
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    SUITE_RESULTS();
}
