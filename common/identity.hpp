#pragma once
#include "config.hpp"
#include "secure_memory.hpp"
#include <botan/auto_rng.h>
#include <botan/pk_keys.h>
#include <map>
#include <memory>
#include <string>
#include <vector>

struct Identity {
    std::string user_id;               // 16 hex chars, derived from pubkey
    std::vector<uint8_t> pubkey_bytes; // raw public key bytes (size depends on KEM)

    // Primary private key. For classical/PQ: holds the single key.
    // For hybrid: holds the ECDH key (classical component).
    std::unique_ptr<Botan::Private_Key> priv_key;

    // Secondary private key — non-null for hybrid modes only (holds the ML-KEM key).
    std::unique_ptr<Botan::Private_Key> priv_key2;
};

// One-time prekey pair — generated in bulk and uploaded to the server.
// Private halves are stored locally; server only ever sees the public half.
struct PrekeyPair {
    std::string prekey_id;             // hex(SHA-256(pubkey)[0:8]) — 16 hex chars
    std::vector<uint8_t> pubkey_bytes; // public key (sent to server)
    std::unique_ptr<Botan::Private_Key> priv_key;
    std::unique_ptr<Botan::Private_Key> priv_key2; // null for non-hybrid
};

// Derive user ID from a public key — deterministic (SHA-256, first 8 bytes → 16 hex chars).
std::string derive_user_id(const std::vector<uint8_t>& pubkey_bytes);

// Generate a brand new identity using the KEM specified in cfg.
Identity generate_identity(Botan::AutoSeeded_RNG& rng, const Config& cfg);

// Save identity to file, encrypted with passphrase using cfg passphrase KDF settings.
// Format: salt(16) + nonce(12) + AES-256-GCM( raw_privkey_bytes [+ raw_privkey2_bytes] )
void save_identity(const Identity& id, const SecureString& passphrase, const std::string& path,
                   Botan::AutoSeeded_RNG& rng, const Config& cfg);

// Load identity from file. Throws on wrong passphrase or corrupt file.
Identity load_identity(const SecureString& passphrase, const std::string& path, const Config& cfg);

// Derive a 32-byte AES key for encrypting the contacts file, deterministically from the
// private key seed via HKDF. No passphrase needed — tied to the identity itself.
Botan::secure_vector<uint8_t> derive_contacts_key(const Identity& id, const Config& cfg);

// Generate n one-time prekey pairs using the KEM from cfg.
std::vector<PrekeyPair> generate_prekeys(int n, Botan::AutoSeeded_RNG& rng, const Config& cfg);

// Persist prekey private keys to a file (plaintext hex, one line per prekey).
// Format per line: prekey_id SP hex(priv_key_bytes) [SP hex(priv_key2_bytes)]
void save_prekeys(const std::vector<PrekeyPair>& prekeys, const std::string& path);

// Load prekey private keys from the prekey file.
// Returns a map from prekey_id to PrekeyPair (private keys only; pubkey_bytes reconstructed).
std::map<std::string, PrekeyPair> load_prekeys(const std::string& path, const Config& cfg);
