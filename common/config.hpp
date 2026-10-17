#pragma once
#include <cstddef>
#include <stdexcept>
#include <string>

// ──────────────────────────────────────────────────────────────────────────
// Operator configuration — loaded from zerotrace.conf (INI format).
// Settings marked [protocol] must match across the whole deployment.
// Settings marked [local] only affect the machine they are set on.
// ──────────────────────────────────────────────────────────────────────────
struct Config {

    // ── [server] ────────────────────────────────────────────────────────
    int         server_port             = 9999;
    std::string server_bind             = "0.0.0.0";
    int         max_users               = 0;     // 0 = unlimited
    int         max_inbox_messages      = 100;
    int         session_ttl_hours       = 24;    // 0 = never expire
    int         msg_ttl_hours           = 48;
    int         cleanup_interval_min    = 10;
    int         rate_limit_msgs         = 20;
    int         rate_limit_window_s     = 60;
    std::string cert_path               = "certs/server.cert.pem";
    std::string key_path                = "certs/server.key.pem";

    // ── [client] ────────────────────────────────────────────────────────
    std::string client_server           = "127.0.0.1";
    int         client_port             = 9999;
    int         poll_interval_s         = 3;
    int         msg_ttl_s               = 120;
    std::string identity_dir            = "users/";
    int         connection_timeout_s    = 10;
    bool        reconnect_on_disconnect = true;

    // ── [tls] ───────────────────────────────────────────────────────────
    // [local] min_version:   1.2 | 1.3
    std::string tls_min_version         = "1.3";
    // [local] cert_algorithm: ECDSA-P256 | ECDSA-P384 | Ed25519
    std::string cert_algorithm          = "ECDSA-P256";
    int         cert_validity_days      = 365;

    // ── [crypto] ────────────────────────────────────────────────────────
    // [protocol] kem:
    //   Classical  : ECDH-P256 | ECDH-P384
    //   Post-quantum: ML-KEM-512 | ML-KEM-768 | ML-KEM-1024
    //   Hybrid     : HYBRID-P256-ML-KEM-768 | HYBRID-P384-ML-KEM-1024
    std::string kem                     = "ML-KEM-768";

    // [protocol] cipher: AES-256-GCM | AES-128-GCM | ChaCha20Poly1305
    std::string cipher                  = "AES-256-GCM";

    // [protocol] hash: SHA-256 | SHA-384 | SHA-512 | SHA3-256
    std::string hash                    = "SHA-256";

    // [protocol] padded_plaintext_kb: any multiple of 1 (KB)
    int         padded_plaintext_kb     = 4;

    // [local] passphrase_kdf: PBKDF2 | Argon2id
    std::string passphrase_kdf          = "Argon2id";
    // cost: iterations for PBKDF2 (e.g. 200000), time cost for Argon2id (e.g. 3)
    int         passphrase_kdf_cost     = 3;
    // memory_kb: Argon2id only (ignored for PBKDF2)
    int         passphrase_kdf_memory_kb = 65536;
    // parallelism: Argon2id only (ignored for PBKDF2)
    int         passphrase_kdf_parallelism = 1;

    // ── [logging] ───────────────────────────────────────────────────────
    // [local] level: debug | info | warn | error
    std::string log_level               = "info";
    // [local] file: empty = stdout
    std::string log_file                = "";
    // [local] format: text | json
    std::string log_format              = "text";

    // ── derived helpers ─────────────────────────────────────────────────
    size_t padded_plaintext_bytes() const
    {
        return static_cast<size_t>(padded_plaintext_kb) * 1024;
    }

    // Length (bytes) of the KEM prefix that starts every encrypted blob.
    size_t kem_ciphertext_len() const
    {
        if (kem == "ECDH-P256")                  return 65;
        if (kem == "ECDH-P384")                  return 97;
        if (kem == "ML-KEM-512")                 return 768;
        if (kem == "ML-KEM-768")                 return 1088;
        if (kem == "ML-KEM-1024")                return 1568;
        if (kem == "HYBRID-P256-ML-KEM-768")     return 65 + 1088;
        if (kem == "HYBRID-P384-ML-KEM-1024")    return 97 + 1568;
        throw std::invalid_argument("Unknown KEM: " + kem);
    }

    // Length (bytes) of the public key stored in the identity / sent to server.
    size_t kem_pubkey_len() const
    {
        if (kem == "ECDH-P256")                  return 65;
        if (kem == "ECDH-P384")                  return 97;
        if (kem == "ML-KEM-512")                 return 800;
        if (kem == "ML-KEM-768")                 return 1184;
        if (kem == "ML-KEM-1024")                return 1568;
        if (kem == "HYBRID-P256-ML-KEM-768")     return 65 + 1184;
        if (kem == "HYBRID-P384-ML-KEM-1024")    return 97 + 1568;
        throw std::invalid_argument("Unknown KEM: " + kem);
    }

    size_t max_blob_len() const
    {
        return kem_ciphertext_len() + padded_plaintext_bytes() + 16; // 16 = GCM tag
    }

    // Botan AEAD name for the configured cipher.
    std::string botan_cipher() const
    {
        if (cipher == "AES-256-GCM")       return "AES-256/GCM";
        if (cipher == "AES-128-GCM")       return "AES-128/GCM";
        if (cipher == "ChaCha20Poly1305")  return "ChaCha20Poly1305";
        throw std::invalid_argument("Unknown cipher: " + cipher);
    }

    // Botan hash name for the configured hash.
    std::string botan_hash() const
    {
        if (hash == "SHA3-256") return "SHA-3(256)";
        return hash; // SHA-256, SHA-384, SHA-512 pass through unchanged
    }

    // Botan PasswordHashFamily name for the configured passphrase KDF.
    std::string botan_passphrase_kdf() const
    {
        if (passphrase_kdf == "PBKDF2")   return "PBKDF2(SHA-256)";
        if (passphrase_kdf == "Argon2id") return "Argon2id";
        throw std::invalid_argument("Unknown passphrase_kdf: " + passphrase_kdf);
    }

    // Validate all fields; throws std::invalid_argument with a descriptive message.
    void validate() const;

    // Parse from an INI file; returns a Config with defaults overridden by the file.
    // Throws std::runtime_error if the file cannot be opened or contains invalid values.
    static Config load(const std::string& path);

    // Return the default config (same as default-constructed).
    static Config defaults() { return {}; }
};
