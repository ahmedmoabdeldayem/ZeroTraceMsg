#pragma once
#include "config.hpp"
#include "identity.hpp"
#include <botan/auto_rng.h>
#include <string>
#include <vector>

struct DecryptedMessage {
    std::vector<uint8_t> msg_nonce; // 16-byte replay-detection nonce
    std::string sender_id;          // 16-char user ID, sealed inside ciphertext
    std::string sender_name;        // chosen username, sealed inside ciphertext
    std::string plaintext;
};

// Encrypt plaintext to recipient's public key using the KEM + cipher + hash from cfg.
// Blob: kem_ciphertext (cfg.kem_ciphertext_len()) + AES/ChaCha ciphertext+tag
// Plaintext layout: msg_nonce(16) + sender_id(16) + name_len(1) + name + msg_len(2) + message +
// padding
std::vector<uint8_t> encrypt_message(const std::string& plaintext, const std::string& sender_id,
                                     const std::string& sender_name,
                                     const std::vector<uint8_t>& recipient_pubkey,
                                     Botan::AutoSeeded_RNG& rng, const Config& cfg);

// Decrypt a blob using raw key components (used for both identity and prekey decryption).
DecryptedMessage decrypt_message(const std::vector<uint8_t>& blob,
                                 const Botan::Private_Key& priv_key,
                                 const Botan::Private_Key* priv_key2,
                                 const std::vector<uint8_t>& pubkey_bytes,
                                 Botan::AutoSeeded_RNG& rng, const Config& cfg);

// Convenience overload: decrypt using the recipient's full identity.
inline DecryptedMessage decrypt_message(const std::vector<uint8_t>& blob, const Identity& id,
                                        Botan::AutoSeeded_RNG& rng, const Config& cfg)
{
    return decrypt_message(blob, *id.priv_key, id.priv_key2.get(), id.pubkey_bytes, rng, cfg);
}
