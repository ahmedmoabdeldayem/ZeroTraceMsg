#pragma once
#include <string>
#include <vector>
#include <botan/auto_rng.h>
#include <botan/ecdh.h>

struct DecryptedMessage {
    std::string sender_id;    // 16-char user ID, extracted from ciphertext
    std::string sender_name;  // chosen username, sealed inside ciphertext
    std::string plaintext;
};

// Encrypt plaintext to recipient's public key.
// Sender ID and username are sealed inside — server never sees them.
//
// Blob format: ephemeral_pub(65) + ciphertext+tag
// Nonce is derived via HKDF (not stored — unique per message via ephemeral key)
// Plaintext layout: sender_id(16) + name_len(1) + sender_name + message
std::vector<uint8_t> encrypt_message(const std::string& plaintext,
                                     const std::string& sender_id,
                                     const std::string& sender_name,
                                     const std::vector<uint8_t>& recipient_pubkey,
                                     Botan::AutoSeeded_RNG& rng);

// Decrypt a blob using recipient's private key.
DecryptedMessage decrypt_message(const std::vector<uint8_t>& blob,
                                 const Botan::ECDH_PrivateKey& priv_key,
                                 Botan::AutoSeeded_RNG& rng);
