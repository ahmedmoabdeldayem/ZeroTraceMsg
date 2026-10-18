#include "config.hpp"
#include <algorithm>
#include <cctype>
#include <fstream>
#include <set>
#include <sstream>
#include <stdexcept>

// ── helpers ─────────────────────────────────────────────────────────────────

static std::string trim(const std::string& s)
{
    size_t l = s.find_first_not_of(" \t\r\n");
    size_t r = s.find_last_not_of(" \t\r\n");
    return (l == std::string::npos) ? "" : s.substr(l, r - l + 1);
}

static std::string strip_comment(const std::string& s)
{
    size_t p = s.find(';');
    if (p == std::string::npos)
        p = s.find('#');
    return trim(p == std::string::npos ? s : s.substr(0, p));
}

static bool parse_bool(const std::string& v, const std::string& key)
{
    std::string lv = v;
    std::transform(lv.begin(), lv.end(), lv.begin(), ::tolower);
    if (lv == "true" || lv == "1" || lv == "yes")
        return true;
    if (lv == "false" || lv == "0" || lv == "no")
        return false;
    throw std::invalid_argument("Invalid boolean for '" + key + "': " + v);
}

static int parse_int(const std::string& v, const std::string& key)
{
    try {
        size_t pos;
        int n = std::stoi(v, &pos);
        if (pos != v.size())
            throw std::exception{};
        return n;
    } catch (...) {
        throw std::invalid_argument("Invalid integer for '" + key + "': " + v);
    }
}

// ── Config::validate ─────────────────────────────────────────────────────────

void Config::validate() const
{
    // server
    if (server_port < 1 || server_port > 65535)
        throw std::invalid_argument("server.port must be 1–65535");
    if (max_users < 0)
        throw std::invalid_argument("server.max_users must be >= 0");
    if (max_inbox_messages < 1)
        throw std::invalid_argument("server.max_inbox_messages must be >= 1");
    if (session_ttl_hours < 0)
        throw std::invalid_argument("server.session_ttl_hours must be >= 0");
    if (msg_ttl_hours < 1)
        throw std::invalid_argument("server.msg_ttl_hours must be >= 1");
    if (cleanup_interval_min < 1)
        throw std::invalid_argument("server.cleanup_interval_min must be >= 1");
    if (rate_limit_msgs < 1)
        throw std::invalid_argument("server.rate_limit_msgs must be >= 1");
    if (rate_limit_window_s < 1)
        throw std::invalid_argument("server.rate_limit_window_s must be >= 1");

    // client
    if (client_port < 1 || client_port > 65535)
        throw std::invalid_argument("client.port must be 1–65535");
    if (poll_interval_s < 1)
        throw std::invalid_argument("client.poll_interval_s must be >= 1");
    if (msg_ttl_s < 1)
        throw std::invalid_argument("client.msg_ttl_s must be >= 1");
    if (connection_timeout_s < 1)
        throw std::invalid_argument("client.connection_timeout_s must be >= 1");

    // tls
    static const std::set<std::string> tls_versions = {"1.2", "1.3"};
    if (!tls_versions.count(tls_min_version))
        throw std::invalid_argument("tls.min_version must be '1.2' or '1.3'");

    static const std::set<std::string> cert_algos = {"ECDSA-P256", "ECDSA-P384", "Ed25519"};
    if (!cert_algos.count(cert_algorithm))
        throw std::invalid_argument(
            "tls.cert_algorithm must be ECDSA-P256, ECDSA-P384, or Ed25519");
    if (cert_validity_days < 1)
        throw std::invalid_argument("tls.cert_validity_days must be >= 1");

    // crypto — kem
    static const std::set<std::string> valid_kem = {
        "ECDH-P256",
        "ECDH-P384",
        "X25519",
        "ML-KEM-512",
        "ML-KEM-768",
        "ML-KEM-1024",
        "HYBRID-P256-ML-KEM-768",
        "HYBRID-P384-ML-KEM-1024",
        "HYBRID-X25519-ML-KEM-768",
        "RSA-2048",
        "RSA-3072",
        "RSA-4096",
    };
    if (!valid_kem.count(kem))
        throw std::invalid_argument("crypto.kem: unknown value '" + kem + "'");

    static const std::set<std::string> valid_cipher = {"AES-256-GCM", "AES-128-GCM",
                                                       "ChaCha20Poly1305"};
    if (!valid_cipher.count(cipher))
        throw std::invalid_argument("crypto.cipher: unknown value '" + cipher + "'");

    static const std::set<std::string> valid_hash = {"SHA-256", "SHA-384", "SHA-512", "SHA3-256"};
    if (!valid_hash.count(hash))
        throw std::invalid_argument("crypto.hash: unknown value '" + hash + "'");

    if (padded_plaintext_kb < 1)
        throw std::invalid_argument("crypto.padded_plaintext_kb must be >= 1");

    static const std::set<std::string> valid_kdf = {"PBKDF2", "Argon2id"};
    if (!valid_kdf.count(passphrase_kdf))
        throw std::invalid_argument("crypto.passphrase_kdf must be PBKDF2 or Argon2id");
    if (passphrase_kdf_cost < 1)
        throw std::invalid_argument("crypto.passphrase_kdf_cost must be >= 1");
    if (passphrase_kdf == "Argon2id") {
        if (passphrase_kdf_memory_kb < 8)
            throw std::invalid_argument("crypto.passphrase_kdf_memory_kb must be >= 8");
        if (passphrase_kdf_parallelism < 1)
            throw std::invalid_argument("crypto.passphrase_kdf_parallelism must be >= 1");
    }

    // logging
    static const std::set<std::string> valid_levels = {"debug", "info", "warn", "error"};
    if (!valid_levels.count(log_level))
        throw std::invalid_argument("logging.level must be debug, info, warn, or error");

    static const std::set<std::string> valid_formats = {"text", "json"};
    if (!valid_formats.count(log_format))
        throw std::invalid_argument("logging.format must be 'text' or 'json'");
}

// ── Config::load ──────────────────────────────────────────────────────────────

Config Config::load(const std::string& path)
{
    std::ifstream f(path);
    if (!f)
        throw std::runtime_error("Cannot open config file: " + path);

    Config cfg;
    std::string section;
    std::string line;
    int lineno = 0;

    while (std::getline(f, line)) {
        ++lineno;
        std::string s = strip_comment(line);
        if (s.empty())
            continue;

        // section header
        if (s.front() == '[') {
            if (s.back() != ']')
                throw std::runtime_error(path + ":" + std::to_string(lineno) +
                                         ": malformed section header");
            section = trim(s.substr(1, s.size() - 2));
            continue;
        }

        // key = value
        size_t eq = s.find('=');
        if (eq == std::string::npos)
            throw std::runtime_error(path + ":" + std::to_string(lineno) +
                                     ": expected 'key = value'");

        std::string key = trim(s.substr(0, eq));
        std::string val = trim(s.substr(eq + 1));

        // dispatch
        auto bad = [&](const std::string& msg) {
            throw std::runtime_error(path + ":" + std::to_string(lineno) + ": " + msg);
        };

        try {
            if (section == "server") {
                if (key == "port")
                    cfg.server_port = parse_int(val, key);
                else if (key == "bind_address")
                    cfg.server_bind = val;
                else if (key == "max_users")
                    cfg.max_users = parse_int(val, key);
                else if (key == "max_inbox_messages")
                    cfg.max_inbox_messages = parse_int(val, key);
                else if (key == "session_ttl_hours")
                    cfg.session_ttl_hours = parse_int(val, key);
                else if (key == "msg_ttl_hours")
                    cfg.msg_ttl_hours = parse_int(val, key);
                else if (key == "cleanup_interval_min")
                    cfg.cleanup_interval_min = parse_int(val, key);
                else if (key == "rate_limit_msgs")
                    cfg.rate_limit_msgs = parse_int(val, key);
                else if (key == "rate_limit_window_s")
                    cfg.rate_limit_window_s = parse_int(val, key);
                else if (key == "cert_path")
                    cfg.cert_path = val;
                else if (key == "key_path")
                    cfg.key_path = val;
                else
                    bad("unknown key in [server]: " + key);

            } else if (section == "client") {
                if (key == "server")
                    cfg.client_server = val;
                else if (key == "port")
                    cfg.client_port = parse_int(val, key);
                else if (key == "poll_interval_s")
                    cfg.poll_interval_s = parse_int(val, key);
                else if (key == "msg_ttl_s")
                    cfg.msg_ttl_s = parse_int(val, key);
                else if (key == "identity_dir")
                    cfg.identity_dir = val;
                else if (key == "connection_timeout_s")
                    cfg.connection_timeout_s = parse_int(val, key);
                else if (key == "reconnect_on_disconnect")
                    cfg.reconnect_on_disconnect = parse_bool(val, key);
                else
                    bad("unknown key in [client]: " + key);

            } else if (section == "tls") {
                if (key == "min_version")
                    cfg.tls_min_version = val;
                else if (key == "cert_algorithm")
                    cfg.cert_algorithm = val;
                else if (key == "cert_validity_days")
                    cfg.cert_validity_days = parse_int(val, key);
                else
                    bad("unknown key in [tls]: " + key);

            } else if (section == "crypto") {
                if (key == "kem")
                    cfg.kem = val;
                else if (key == "cipher")
                    cfg.cipher = val;
                else if (key == "hash")
                    cfg.hash = val;
                else if (key == "padded_plaintext_kb")
                    cfg.padded_plaintext_kb = parse_int(val, key);
                else if (key == "passphrase_kdf")
                    cfg.passphrase_kdf = val;
                else if (key == "passphrase_kdf_cost")
                    cfg.passphrase_kdf_cost = parse_int(val, key);
                else if (key == "passphrase_kdf_memory_kb")
                    cfg.passphrase_kdf_memory_kb = parse_int(val, key);
                else if (key == "passphrase_kdf_parallelism")
                    cfg.passphrase_kdf_parallelism = parse_int(val, key);
                else
                    bad("unknown key in [crypto]: " + key);

            } else if (section == "logging") {
                if (key == "level")
                    cfg.log_level = val;
                else if (key == "file")
                    cfg.log_file = val;
                else if (key == "format")
                    cfg.log_format = val;
                else
                    bad("unknown key in [logging]: " + key);

            } else {
                bad("unknown section [" + section + "]");
            }
        } catch (const std::invalid_argument& e) {
            bad(e.what());
        }
    }

    cfg.validate();
    return cfg;
}
