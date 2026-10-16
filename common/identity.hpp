#pragma once
#include <string>
#include <vector>
#include <memory>
#include <botan/ecdh.h>
#include <botan/ec_group.h>
#include <botan/auto_rng.h>

struct Identity {
    std::string              user_id;       // 16 hex chars, derived from pubkey
    std::vector<uint8_t>     pubkey_bytes;  // 65-byte uncompressed P-256 pubkey

    // owning pointer — private key lives here, wiped on destruction
    std::unique_ptr<Botan::ECDH_PrivateKey> priv_key;
};

// Generate a brand new identity (first launch)
Identity generate_identity(Botan::AutoSeeded_RNG& rng);

// Derive user ID from a public key — deterministic
std::string derive_user_id(const std::vector<uint8_t>& pubkey_bytes);

// Save identity to file, encrypted with passphrase
// Format: salt(16) + nonce(12) + encrypted_privkey(raw_bytes + 16 byte GCM tag)
void save_identity(const Identity& id, const std::string& passphrase,
                   const std::string& path, Botan::AutoSeeded_RNG& rng);

// Load identity from file — throws on wrong passphrase or corrupt file
Identity load_identity(const std::string& passphrase, const std::string& path);
