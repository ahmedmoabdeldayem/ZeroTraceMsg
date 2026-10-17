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
// Plaintext layout: msg_nonce(16) + sender_id(16) + name_len(1) + name + msg_len(2) + message + padding
std::vector<uint8_t> encrypt_message(const std::string& plaintext, const std::string& sender_id,
                                     const std::string& sender_name,
                                     const std::vector<uint8_t>& recipient_pubkey,
                                     Botan::AutoSeeded_RNG& rng, const Config& cfg);

// Decrypt a blob using the recipient's identity and the deployment config.
DecryptedMessage decrypt_message(const std::vector<uint8_t>& blob, const Identity& id,
                                 Botan::AutoSeeded_RNG& rng, const Config& cfg);
