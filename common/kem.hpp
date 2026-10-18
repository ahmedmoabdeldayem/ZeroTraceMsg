#pragma once
#include "config.hpp"
#include <botan/auto_rng.h>
#include <botan/pk_keys.h>
#include <botan/secmem.h>
#include <memory>
#include <string>
#include <vector>

// ──────────────────────────────────────────────────────────────────────────
// KEM abstraction — unified interface over ECDH, ML-KEM, and Hybrid.
//
// Encapsulation (sender side):
//   - takes the recipient's public key bytes
//   - produces a (ciphertext, shared_secret) pair
//   - ciphertext is prepended to the blob
//
// Decapsulation (recipient side):
//   - takes the ciphertext from the blob and the private key
//   - recovers the shared_secret
// ──────────────────────────────────────────────────────────────────────────

struct KemEncapResult {
    std::vector<uint8_t> ciphertext;             // prepended to blob
    Botan::secure_vector<uint8_t> shared_secret; // fed into HKDF
};

// Generate a private key for the configured KEM.
// For hybrid, the primary key (index 0 = ECDH) is returned; caller must also
// generate the secondary key via make_kem_key2().
std::unique_ptr<Botan::Private_Key> make_kem_key(Botan::AutoSeeded_RNG& rng, const Config& cfg);

// Returns the secondary ML-KEM private key for hybrid modes; nullptr for non-hybrid.
std::unique_ptr<Botan::Private_Key> make_kem_key2(Botan::AutoSeeded_RNG& rng, const Config& cfg);

// Get raw public key bytes from a private key.
std::vector<uint8_t> kem_pubkey_bytes(const Botan::Private_Key& key);

// Reconstruct a private key from raw bytes (seed/scalar).
std::unique_ptr<Botan::Private_Key> kem_key_from_bytes(std::span<const uint8_t> bytes,
                                                       const Config& cfg, bool secondary = false);

// Encapsulate: produce ciphertext + shared secret from a public key.
// For hybrid, pubkey = ecdh_pub_bytes || kem_pub_bytes (concatenated).
KemEncapResult kem_encapsulate(const std::vector<uint8_t>& recipient_pubkey,
                               Botan::AutoSeeded_RNG& rng, const Config& cfg);

// Decapsulate: recover shared secret from ciphertext + private key(s).
// priv2 is the secondary ML-KEM key for hybrid modes; nullptr for non-hybrid.
Botan::secure_vector<uint8_t> kem_decapsulate(const std::vector<uint8_t>& ciphertext,
                                              const Botan::Private_Key& priv,
                                              const Botan::Private_Key* priv2,
                                              Botan::AutoSeeded_RNG& rng, const Config& cfg);
