// Tests for common/config — defaults, validation, INI parsing, helpers, and
// a full encrypt/decrypt round-trip for every documented KEM × cipher × hash combo.

#include "../common/config.hpp"
#include "../common/crypto.hpp"
#include "../common/identity.hpp"
#include "test_runner.hpp"
#include <botan/auto_rng.h>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

// ── helpers ──────────────────────────────────────────────────────────────────

// Write content to a temp file and return its path.
static std::string write_conf(const std::string& content)
{
    const std::string path = "/tmp/ztm_test_config.conf";
    std::ofstream f(path);
    f << content;
    return path;
}

// ─────────────────────────────────────────────────────────────────────────────
int main()
{
    SUITE_INIT("test_config");
    std::cout << "=== config tests ===\n\n";
    Botan::AutoSeeded_RNG rng;

    // =========================================================================
    // Default values
    // =========================================================================
    TEST("default config is valid");
    ASSERT_NO_THROW(Config{}.validate());

    TEST("default server settings");
    {
        Config c;
        ASSERT_EQ(c.server_port, 9999);
        ASSERT_EQ(c.server_bind, std::string("0.0.0.0"));
        ASSERT_EQ(c.max_users, 0);
        ASSERT_EQ(c.max_inbox_messages, 100);
        ASSERT_EQ(c.session_ttl_hours, 24);
        ASSERT_EQ(c.msg_ttl_hours, 48);
        ASSERT_EQ(c.cleanup_interval_min, 10);
        ASSERT_EQ(c.rate_limit_msgs, 20);
        ASSERT_EQ(c.rate_limit_window_s, 60);
    }

    TEST("default client settings");
    {
        Config c;
        ASSERT_EQ(c.client_server, std::string("127.0.0.1"));
        ASSERT_EQ(c.client_port, 9999);
        ASSERT_EQ(c.poll_interval_s, 3);
        ASSERT_EQ(c.msg_ttl_s, 120);
        ASSERT_EQ(c.connection_timeout_s, 10);
        ASSERT_EQ(c.reconnect_on_disconnect, true);
    }

    TEST("default TLS settings");
    {
        Config c;
        ASSERT_EQ(c.tls_min_version, std::string("1.3"));
        ASSERT_EQ(c.cert_algorithm, std::string("ECDSA-P256"));
        ASSERT_EQ(c.cert_validity_days, 365);
    }

    TEST("default crypto settings");
    {
        Config c;
        ASSERT_EQ(c.kem, std::string("ML-KEM-768"));
        ASSERT_EQ(c.cipher, std::string("AES-256-GCM"));
        ASSERT_EQ(c.hash, std::string("SHA-256"));
        ASSERT_EQ(c.padded_plaintext_kb, 4);
        ASSERT_EQ(c.passphrase_kdf, std::string("Argon2id"));
        ASSERT_EQ(c.passphrase_kdf_cost, 3);
        ASSERT_EQ(c.passphrase_kdf_memory_kb, 65536);
        ASSERT_EQ(c.passphrase_kdf_parallelism, 1);
    }

    TEST("default logging settings");
    {
        Config c;
        ASSERT_EQ(c.log_level, std::string("info"));
        ASSERT_EQ(c.log_file, std::string(""));
        ASSERT_EQ(c.log_format, std::string("text"));
    }

    // =========================================================================
    // Config::validate() — every invalid value
    // =========================================================================

    TEST("validation rejects port = 0");
    {
        Config c;
        c.server_port = 0;
        ASSERT_THROWS(c.validate());
    }

    TEST("validation rejects port = 65536");
    {
        Config c;
        c.server_port = 65536;
        ASSERT_THROWS(c.validate());
    }

    TEST("validation rejects max_users = -1");
    {
        Config c;
        c.max_users = -1;
        ASSERT_THROWS(c.validate());
    }

    TEST("validation rejects max_inbox_messages = 0");
    {
        Config c;
        c.max_inbox_messages = 0;
        ASSERT_THROWS(c.validate());
    }

    TEST("validation rejects session_ttl_hours = -1");
    {
        Config c;
        c.session_ttl_hours = -1;
        ASSERT_THROWS(c.validate());
    }

    TEST("validation rejects msg_ttl_hours = 0");
    {
        Config c;
        c.msg_ttl_hours = 0;
        ASSERT_THROWS(c.validate());
    }

    TEST("validation rejects cleanup_interval_min = 0");
    {
        Config c;
        c.cleanup_interval_min = 0;
        ASSERT_THROWS(c.validate());
    }

    TEST("validation rejects rate_limit_msgs = 0");
    {
        Config c;
        c.rate_limit_msgs = 0;
        ASSERT_THROWS(c.validate());
    }

    TEST("validation rejects rate_limit_window_s = 0");
    {
        Config c;
        c.rate_limit_window_s = 0;
        ASSERT_THROWS(c.validate());
    }

    TEST("validation rejects client port = 0");
    {
        Config c;
        c.client_port = 0;
        ASSERT_THROWS(c.validate());
    }

    TEST("validation rejects client port = 65536");
    {
        Config c;
        c.client_port = 65536;
        ASSERT_THROWS(c.validate());
    }

    TEST("validation rejects poll_interval_s = 0");
    {
        Config c;
        c.poll_interval_s = 0;
        ASSERT_THROWS(c.validate());
    }

    TEST("validation rejects msg_ttl_s = 0");
    {
        Config c;
        c.msg_ttl_s = 0;
        ASSERT_THROWS(c.validate());
    }

    TEST("validation rejects connection_timeout_s = 0");
    {
        Config c;
        c.connection_timeout_s = 0;
        ASSERT_THROWS(c.validate());
    }

    TEST("validation rejects tls_min_version = 1.1");
    {
        Config c;
        c.tls_min_version = "1.1";
        ASSERT_THROWS(c.validate());
    }

    TEST("validation rejects unknown cert_algorithm");
    {
        Config c;
        c.cert_algorithm = "RSA";
        ASSERT_THROWS(c.validate());
    }

    TEST("validation rejects cert_validity_days = 0");
    {
        Config c;
        c.cert_validity_days = 0;
        ASSERT_THROWS(c.validate());
    }

    TEST("validation rejects unknown kem");
    {
        Config c;
        c.kem = "DES-56";
        ASSERT_THROWS(c.validate());
    }

    TEST("validation rejects unknown cipher");
    {
        Config c;
        c.cipher = "3DES";
        ASSERT_THROWS(c.validate());
    }

    TEST("validation rejects unknown hash");
    {
        Config c;
        c.hash = "MD5";
        ASSERT_THROWS(c.validate());
    }

    TEST("validation rejects padded_plaintext_kb = 0");
    {
        Config c;
        c.padded_plaintext_kb = 0;
        ASSERT_THROWS(c.validate());
    }

    TEST("validation rejects unknown passphrase_kdf");
    {
        Config c;
        c.passphrase_kdf = "bcrypt";
        ASSERT_THROWS(c.validate());
    }

    TEST("validation rejects passphrase_kdf_cost = 0");
    {
        Config c;
        c.passphrase_kdf_cost = 0;
        ASSERT_THROWS(c.validate());
    }

    TEST("validation rejects Argon2id memory_kb < 8");
    {
        Config c;
        c.passphrase_kdf_memory_kb = 4;
        ASSERT_THROWS(c.validate());
    }

    TEST("validation rejects Argon2id parallelism = 0");
    {
        Config c;
        c.passphrase_kdf_parallelism = 0;
        ASSERT_THROWS(c.validate());
    }

    TEST("validation rejects unknown log_level");
    {
        Config c;
        c.log_level = "verbose";
        ASSERT_THROWS(c.validate());
    }

    TEST("validation rejects unknown log_format");
    {
        Config c;
        c.log_format = "xml";
        ASSERT_THROWS(c.validate());
    }

    TEST("validation accepts session_ttl_hours = 0 (never expire)");
    {
        Config c;
        c.session_ttl_hours = 0;
        ASSERT_NO_THROW(c.validate());
    }

    TEST("validation accepts max_users = 0 (unlimited)");
    {
        Config c;
        c.max_users = 0;
        ASSERT_NO_THROW(c.validate());
    }

    TEST("validation accepts tls_min_version = 1.2");
    {
        Config c;
        c.tls_min_version = "1.2";
        ASSERT_NO_THROW(c.validate());
    }

    TEST("PBKDF2 ignores Argon2 memory/parallelism constraints");
    {
        Config c;
        c.passphrase_kdf = "PBKDF2";
        c.passphrase_kdf_cost = 200000;
        c.passphrase_kdf_memory_kb = 0;   // irrelevant for PBKDF2
        c.passphrase_kdf_parallelism = 0; // irrelevant for PBKDF2
        ASSERT_NO_THROW(c.validate());
    }

    // =========================================================================
    // Config::load() — INI parsing
    // =========================================================================

    TEST("load: missing file throws");
    ASSERT_THROWS(Config::load("/tmp/ztm_nonexistent_config.conf"));

    TEST("load: valid file overrides defaults");
    {
        auto path = write_conf("[server]\n"
                               "port = 8888\n"
                               "max_users = 50\n"
                               "rate_limit_msgs = 10\n"
                               "[client]\n"
                               "poll_interval_s = 5\n"
                               "connection_timeout_s = 15\n"
                               "[tls]\n"
                               "min_version = 1.2\n"
                               "cert_validity_days = 180\n"
                               "[crypto]\n"
                               "kem = ECDH-P256\n"
                               "cipher = ChaCha20Poly1305\n"
                               "hash = SHA-512\n"
                               "padded_plaintext_kb = 8\n"
                               "passphrase_kdf = PBKDF2\n"
                               "passphrase_kdf_cost = 300000\n"
                               "[logging]\n"
                               "level = warn\n"
                               "format = json\n");
        auto c = Config::load(path);
        ASSERT_EQ(c.server_port, 8888);
        ASSERT_EQ(c.max_users, 50);
        ASSERT_EQ(c.rate_limit_msgs, 10);
        ASSERT_EQ(c.poll_interval_s, 5);
        ASSERT_EQ(c.connection_timeout_s, 15);
        ASSERT_EQ(c.tls_min_version, std::string("1.2"));
        ASSERT_EQ(c.cert_validity_days, 180);
        ASSERT_EQ(c.kem, std::string("ECDH-P256"));
        ASSERT_EQ(c.cipher, std::string("ChaCha20Poly1305"));
        ASSERT_EQ(c.hash, std::string("SHA-512"));
        ASSERT_EQ(c.padded_plaintext_kb, 8);
        ASSERT_EQ(c.passphrase_kdf, std::string("PBKDF2"));
        ASSERT_EQ(c.passphrase_kdf_cost, 300000);
        ASSERT_EQ(c.log_level, std::string("warn"));
        ASSERT_EQ(c.log_format, std::string("json"));
    }

    TEST("load: semicolon and hash comments are stripped");
    {
        auto path = write_conf("[server]\n"
                               "port = 7777  ; inline comment\n"
                               "# full-line hash comment\n"
                               "; full-line semicolon comment\n"
                               "max_users = 5\n");
        auto c = Config::load(path);
        ASSERT_EQ(c.server_port, 7777);
        ASSERT_EQ(c.max_users, 5);
    }

    TEST("load: empty lines are skipped");
    {
        auto path = write_conf("\n\n[server]\n\nport = 1234\n\n");
        auto c = Config::load(path);
        ASSERT_EQ(c.server_port, 1234);
    }

    TEST("load: unset fields keep their defaults");
    {
        auto path = write_conf("[server]\nport = 9999\n");
        auto c = Config::load(path);
        ASSERT_EQ(c.max_users, 0);
        ASSERT_EQ(c.max_inbox_messages, 100);
        ASSERT_EQ(c.kem, std::string("ML-KEM-768"));
    }

    TEST("load: malformed section header throws");
    ASSERT_THROWS(Config::load(write_conf("[server\nport = 9999\n")));

    TEST("load: line without '=' throws");
    ASSERT_THROWS(Config::load(write_conf("[server]\nbadline\n")));

    TEST("load: unknown section throws");
    ASSERT_THROWS(Config::load(write_conf("[mystery]\nfoo = bar\n")));

    TEST("load: unknown key in [server] throws");
    ASSERT_THROWS(Config::load(write_conf("[server]\nunknown_key = 1\n")));

    TEST("load: unknown key in [client] throws");
    ASSERT_THROWS(Config::load(write_conf("[client]\nunknown_key = 1\n")));

    TEST("load: unknown key in [tls] throws");
    ASSERT_THROWS(Config::load(write_conf("[tls]\nunknown_key = 1\n")));

    TEST("load: unknown key in [crypto] throws");
    ASSERT_THROWS(Config::load(write_conf("[crypto]\nunknown_key = 1\n")));

    TEST("load: unknown key in [logging] throws");
    ASSERT_THROWS(Config::load(write_conf("[logging]\nunknown_key = 1\n")));

    TEST("load: invalid integer throws");
    ASSERT_THROWS(Config::load(write_conf("[server]\nport = abc\n")));

    TEST("load: invalid value caught at validate()");
    ASSERT_THROWS(Config::load(write_conf("[server]\nport = 99999\n")));

    TEST("load: bool true/false/yes/no/1/0 all parse");
    {
        for (auto& v : {"true", "1", "yes"}) {
            auto path = write_conf(std::string("[client]\nreconnect_on_disconnect = ") + v + "\n");
            auto c = Config::load(path);
            ASSERT_TRUE(c.reconnect_on_disconnect == true);
        }
        for (auto& v : {"false", "0", "no"}) {
            auto path = write_conf(std::string("[client]\nreconnect_on_disconnect = ") + v + "\n");
            auto c = Config::load(path);
            ASSERT_TRUE(c.reconnect_on_disconnect == false);
        }
    }

    TEST("load: invalid bool throws");
    ASSERT_THROWS(Config::load(write_conf("[client]\nreconnect_on_disconnect = maybe\n")));

    // =========================================================================
    // Derived helpers — botan_cipher / botan_key_len / botan_hash / botan_passphrase_kdf
    // =========================================================================

    TEST("botan_cipher: AES-256-GCM -> AES-256/GCM");
    {
        Config c;
        c.cipher = "AES-256-GCM";
        ASSERT_EQ(c.botan_cipher(), std::string("AES-256/GCM"));
    }

    TEST("botan_cipher: AES-128-GCM -> AES-128/GCM");
    {
        Config c;
        c.cipher = "AES-128-GCM";
        ASSERT_EQ(c.botan_cipher(), std::string("AES-128/GCM"));
    }

    TEST("botan_cipher: ChaCha20Poly1305 passes through");
    {
        Config c;
        c.cipher = "ChaCha20Poly1305";
        ASSERT_EQ(c.botan_cipher(), std::string("ChaCha20Poly1305"));
    }

    TEST("botan_key_len: AES-256-GCM -> 32");
    {
        Config c;
        c.cipher = "AES-256-GCM";
        ASSERT_EQ(c.botan_key_len(), (size_t)32);
    }

    TEST("botan_key_len: AES-128-GCM -> 16");
    {
        Config c;
        c.cipher = "AES-128-GCM";
        ASSERT_EQ(c.botan_key_len(), (size_t)16);
    }

    TEST("botan_key_len: ChaCha20Poly1305 -> 32");
    {
        Config c;
        c.cipher = "ChaCha20Poly1305";
        ASSERT_EQ(c.botan_key_len(), (size_t)32);
    }

    TEST("botan_hash: SHA-256 passes through");
    {
        Config c;
        c.hash = "SHA-256";
        ASSERT_EQ(c.botan_hash(), std::string("SHA-256"));
    }

    TEST("botan_hash: SHA-384 passes through");
    {
        Config c;
        c.hash = "SHA-384";
        ASSERT_EQ(c.botan_hash(), std::string("SHA-384"));
    }

    TEST("botan_hash: SHA-512 passes through");
    {
        Config c;
        c.hash = "SHA-512";
        ASSERT_EQ(c.botan_hash(), std::string("SHA-512"));
    }

    TEST("botan_hash: SHA3-256 -> SHA-3(256)");
    {
        Config c;
        c.hash = "SHA3-256";
        ASSERT_EQ(c.botan_hash(), std::string("SHA-3(256)"));
    }

    TEST("botan_passphrase_kdf: Argon2id passes through");
    {
        Config c;
        c.passphrase_kdf = "Argon2id";
        ASSERT_EQ(c.botan_passphrase_kdf(), std::string("Argon2id"));
    }

    TEST("botan_passphrase_kdf: PBKDF2 -> PBKDF2(SHA-256)");
    {
        Config c;
        c.passphrase_kdf = "PBKDF2";
        ASSERT_EQ(c.botan_passphrase_kdf(), std::string("PBKDF2(SHA-256)"));
    }

    // =========================================================================
    // Derived helpers — kem sizes and blob geometry
    // =========================================================================

    TEST("kem_pubkey_len: ECDH-P256 = 65");
    {
        Config c;
        c.kem = "ECDH-P256";
        ASSERT_EQ(c.kem_pubkey_len(), (size_t)65);
    }

    TEST("kem_pubkey_len: ECDH-P384 = 97");
    {
        Config c;
        c.kem = "ECDH-P384";
        ASSERT_EQ(c.kem_pubkey_len(), (size_t)97);
    }

    TEST("kem_pubkey_len: ML-KEM-512 = 800");
    {
        Config c;
        c.kem = "ML-KEM-512";
        ASSERT_EQ(c.kem_pubkey_len(), (size_t)800);
    }

    TEST("kem_pubkey_len: ML-KEM-768 = 1184");
    {
        Config c;
        c.kem = "ML-KEM-768";
        ASSERT_EQ(c.kem_pubkey_len(), (size_t)1184);
    }

    TEST("kem_pubkey_len: ML-KEM-1024 = 1568");
    {
        Config c;
        c.kem = "ML-KEM-1024";
        ASSERT_EQ(c.kem_pubkey_len(), (size_t)1568);
    }

    TEST("kem_pubkey_len: HYBRID-P256-ML-KEM-768 = 65+1184");
    {
        Config c;
        c.kem = "HYBRID-P256-ML-KEM-768";
        ASSERT_EQ(c.kem_pubkey_len(), (size_t)(65 + 1184));
    }

    TEST("kem_pubkey_len: HYBRID-P384-ML-KEM-1024 = 97+1568");
    {
        Config c;
        c.kem = "HYBRID-P384-ML-KEM-1024";
        ASSERT_EQ(c.kem_pubkey_len(), (size_t)(97 + 1568));
    }

    TEST("kem_ciphertext_len: ECDH-P256 = 65");
    {
        Config c;
        c.kem = "ECDH-P256";
        ASSERT_EQ(c.kem_ciphertext_len(), (size_t)65);
    }

    TEST("kem_ciphertext_len: ECDH-P384 = 97");
    {
        Config c;
        c.kem = "ECDH-P384";
        ASSERT_EQ(c.kem_ciphertext_len(), (size_t)97);
    }

    TEST("kem_ciphertext_len: ML-KEM-512 = 768");
    {
        Config c;
        c.kem = "ML-KEM-512";
        ASSERT_EQ(c.kem_ciphertext_len(), (size_t)768);
    }

    TEST("kem_ciphertext_len: ML-KEM-768 = 1088");
    {
        Config c;
        c.kem = "ML-KEM-768";
        ASSERT_EQ(c.kem_ciphertext_len(), (size_t)1088);
    }

    TEST("kem_ciphertext_len: ML-KEM-1024 = 1568");
    {
        Config c;
        c.kem = "ML-KEM-1024";
        ASSERT_EQ(c.kem_ciphertext_len(), (size_t)1568);
    }

    TEST("kem_ciphertext_len: HYBRID-P256-ML-KEM-768 = 65+1088");
    {
        Config c;
        c.kem = "HYBRID-P256-ML-KEM-768";
        ASSERT_EQ(c.kem_ciphertext_len(), (size_t)(65 + 1088));
    }

    TEST("kem_ciphertext_len: HYBRID-P384-ML-KEM-1024 = 97+1568");
    {
        Config c;
        c.kem = "HYBRID-P384-ML-KEM-1024";
        ASSERT_EQ(c.kem_ciphertext_len(), (size_t)(97 + 1568));
    }

    TEST("kem_pubkey_len: X25519 = 32");
    {
        Config c;
        c.kem = "X25519";
        ASSERT_EQ(c.kem_pubkey_len(), (size_t)32);
    }

    TEST("kem_ciphertext_len: X25519 = 32");
    {
        Config c;
        c.kem = "X25519";
        ASSERT_EQ(c.kem_ciphertext_len(), (size_t)32);
    }

    TEST("kem_pubkey_len: HYBRID-X25519-ML-KEM-768 = 32+1184");
    {
        Config c;
        c.kem = "HYBRID-X25519-ML-KEM-768";
        ASSERT_EQ(c.kem_pubkey_len(), (size_t)(32 + 1184));
    }

    TEST("kem_ciphertext_len: HYBRID-X25519-ML-KEM-768 = 32+1088");
    {
        Config c;
        c.kem = "HYBRID-X25519-ML-KEM-768";
        ASSERT_EQ(c.kem_ciphertext_len(), (size_t)(32 + 1088));
    }

    TEST("kem_pubkey_len: RSA-2048 = 256");
    {
        Config c;
        c.kem = "RSA-2048";
        ASSERT_EQ(c.kem_pubkey_len(), (size_t)256);
    }

    TEST("kem_ciphertext_len: RSA-2048 = 256");
    {
        Config c;
        c.kem = "RSA-2048";
        ASSERT_EQ(c.kem_ciphertext_len(), (size_t)256);
    }

    TEST("kem_pubkey_len: RSA-3072 = 384");
    {
        Config c;
        c.kem = "RSA-3072";
        ASSERT_EQ(c.kem_pubkey_len(), (size_t)384);
    }

    TEST("kem_pubkey_len: RSA-4096 = 512");
    {
        Config c;
        c.kem = "RSA-4096";
        ASSERT_EQ(c.kem_pubkey_len(), (size_t)512);
    }

    TEST("padded_plaintext_bytes = padded_plaintext_kb * 1024");
    {
        Config c;
        c.padded_plaintext_kb = 4;
        ASSERT_EQ(c.padded_plaintext_bytes(), (size_t)4096);
        c.padded_plaintext_kb = 8;
        ASSERT_EQ(c.padded_plaintext_bytes(), (size_t)8192);
        c.padded_plaintext_kb = 1;
        ASSERT_EQ(c.padded_plaintext_bytes(), (size_t)1024);
    }

    TEST("max_blob_len = kem_ciphertext_len + padded_plaintext_bytes + 16 (GCM tag)");
    {
        Config c;
        c.kem = "ML-KEM-768";
        c.padded_plaintext_kb = 4;
        ASSERT_EQ(c.max_blob_len(), (size_t)(1088 + 4096 + 16)); // 5200

        c.kem = "ECDH-P256";
        c.padded_plaintext_kb = 4;
        ASSERT_EQ(c.max_blob_len(), (size_t)(65 + 4096 + 16)); // 4177

        c.kem = "ML-KEM-1024";
        c.padded_plaintext_kb = 8;
        ASSERT_EQ(c.max_blob_len(), (size_t)(1568 + 8192 + 16)); // 9776
    }

    // =========================================================================
    // Encrypt/decrypt round-trip — all KEM × cipher × hash combinations
    // =========================================================================

    std::vector<std::string> kems = {
        "ML-KEM-512",
        "ML-KEM-768",
        "ML-KEM-1024",
        "ECDH-P256",
        "ECDH-P384",
        "X25519",
        "HYBRID-P256-ML-KEM-768",
        "HYBRID-P384-ML-KEM-1024",
        "HYBRID-X25519-ML-KEM-768",
        "RSA-2048",
        "RSA-3072",
        "RSA-4096",
    };
    std::vector<std::string> ciphers = {"AES-256-GCM", "AES-128-GCM", "ChaCha20Poly1305"};
    std::vector<std::string> hashes = {"SHA-256", "SHA-384", "SHA-512", "SHA3-256"};

    for (const auto& kem : kems) {
        for (const auto& cipher : ciphers) {
            for (const auto& hash : hashes) {
                TEST("encrypt/decrypt: " + kem + " + " + cipher + " + " + hash);
                {
                    Config cfg;
                    cfg.kem = kem;
                    cfg.cipher = cipher;
                    cfg.hash = hash;

                    auto alice = generate_identity(rng, cfg);
                    auto bob = generate_identity(rng, cfg);

                    // blob size matches config geometry
                    auto blob = encrypt_message("hello", alice.user_id, "alice", bob.pubkey_bytes,
                                                rng, cfg);
                    ASSERT_EQ(blob.size(), cfg.max_blob_len());

                    // round-trip preserves plaintext and sealed sender
                    auto dec = decrypt_message(blob, bob, rng, cfg);
                    ASSERT_EQ(dec.plaintext, std::string("hello"));
                    ASSERT_EQ(dec.sender_id, alice.user_id);
                    ASSERT_EQ(dec.sender_name, std::string("alice"));

                    // wrong recipient cannot decrypt
                    auto eve = generate_identity(rng, cfg);
                    ASSERT_THROWS(decrypt_message(blob, eve, rng, cfg));
                }
            }
        }
    }

    std::remove("/tmp/ztm_test_config.conf");
    SUITE_RESULTS();
}
