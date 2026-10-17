#pragma once
#include "secure_memory.hpp"
#include <botan/auto_rng.h>
#include <botan/ml_kem.h>
#include <memory>
#include <string>
#include <vector>

struct Identity {
    std::string user_id;               // 16 hex chars, derived from pubkey
    std::vector<uint8_t> pubkey_bytes; // 1184-byte ML-KEM-768 public key

    // owning pointer — private key lives here, wiped on destruction
    std::unique_ptr<Botan::ML_KEM_PrivateKey> priv_key;
};

// Generate a brand new identity (first launch)
Identity generate_identity(Botan::AutoSeeded_RNG& rng);

// Derive user ID from a public key — deterministic
std::string derive_user_id(const std::vector<uint8_t>& pubkey_bytes);

// Save identity to file, encrypted with passphrase.
// passphrase is held in mlocked memory — not swappable, zeroed on destruction.
// Format: salt(16) + nonce(12) + encrypted_privkey(64-byte ML-KEM seed + 16 byte GCM tag)
void save_identity(const Identity& id, const SecureString& passphrase, const std::string& path,
                   Botan::AutoSeeded_RNG& rng);

// Load identity from file — throws on wrong passphrase or corrupt file.
// passphrase is held in mlocked memory — not swappable, zeroed on destruction.
Identity load_identity(const SecureString& passphrase, const std::string& path);
