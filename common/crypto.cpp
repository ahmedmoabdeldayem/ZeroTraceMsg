#include "crypto.hpp"
#include "protocol.hpp"
#include <botan/aead.h>
#include <botan/hex.h>
#include <botan/kdf.h>
#include <botan/pubkey.h>
#include <stdexcept>

std::vector<uint8_t> encrypt_message(const std::string& plaintext, const std::string& sender_id,
                                     const std::string& sender_name,
                                     const std::vector<uint8_t>& recipient_pubkey,
                                     Botan::AutoSeeded_RNG& rng)
{
    // Step 1 — load recipient's ML-KEM-768 public key and encapsulate a shared secret
    Botan::ML_KEM_PublicKey pub_key(recipient_pubkey, Botan::KyberMode::ML_KEM_768);
    Botan::PK_KEM_Encryptor kem_enc(pub_key, "Raw");
    auto kem = kem_enc.encrypt(rng, 32); // 32-byte shared secret, 1088-byte encapsulated key
    const auto& kem_ct = kem.encapsulated_shared_key(); // 1088 bytes
    const auto& shared_raw = kem.shared_key();          // 32 bytes

    // Step 2 — HKDF: use kem_ct as salt to bind key derivation to this encapsulation
    auto hkdf_extract = Botan::KDF::create_or_throw("HKDF-Extract(SHA-256)");
    auto hkdf_expand = Botan::KDF::create_or_throw("HKDF-Expand(SHA-256)");

    Botan::secure_vector<uint8_t> prk =
        hkdf_extract->derive_key(32, shared_raw, kem_ct, std::vector<uint8_t>{});

    auto aes_key_bytes = hkdf_expand->derive_key(
        32, prk, std::vector<uint8_t>{}, std::vector<uint8_t>{'a', 'e', 's', '-', 'k', 'e', 'y'});
    auto nonce_bytes = hkdf_expand->derive_key(12, prk, std::vector<uint8_t>{},
                                               std::vector<uint8_t>{'a', 'e', 's', '-', 'i', 'v'});

    // Step 3 — assemble and pad plaintext payload:
    //   msg_nonce(16) + sender_id(16) + name_len(1) + sender_name
    //   + msg_len(2, big-endian) + message + zero padding → fixed PADDED_PLAINTEXT_LEN
    auto nonce_raw = rng.random_vec(MSG_NONCE_LEN);
    uint8_t name_len = static_cast<uint8_t>(sender_name.size() < 255 ? sender_name.size() : 255);

    constexpr size_t fixed_overhead =
        MSG_NONCE_LEN + USER_ID_LEN + 1 + 2; // nonce+id+name_len+msg_len
    if (fixed_overhead + name_len + plaintext.size() > PADDED_PLAINTEXT_LEN)
        throw std::runtime_error("Message too long to encrypt");

    auto msg_len = static_cast<uint16_t>(plaintext.size());
    Botan::secure_vector<uint8_t> payload;
    payload.reserve(PADDED_PLAINTEXT_LEN);
    payload.insert(payload.end(), nonce_raw.begin(), nonce_raw.end());
    payload.insert(payload.end(), sender_id.begin(), sender_id.end());
    payload.push_back(name_len);
    payload.insert(payload.end(), sender_name.begin(), sender_name.begin() + name_len);
    payload.push_back(static_cast<uint8_t>(msg_len >> 8));
    payload.push_back(static_cast<uint8_t>(msg_len & 0xFF));
    payload.insert(payload.end(), plaintext.begin(), plaintext.end());
    payload.resize(PADDED_PLAINTEXT_LEN, 0); // zero-pad to fixed size

    // Step 4 — AES-256-GCM encrypt
    auto aead = Botan::AEAD_Mode::create_or_throw("AES-256/GCM", Botan::Cipher_Dir::Encryption);
    aead->set_key(Botan::SymmetricKey(aes_key_bytes));
    aead->start(nonce_bytes);
    aead->finish(payload);

    // Step 5 — blob: kem_ciphertext(1088) + ciphertext+tag (always MAX_BLOB_LEN bytes)
    std::vector<uint8_t> blob;
    blob.insert(blob.end(), kem_ct.begin(), kem_ct.end());
    blob.insert(blob.end(), payload.begin(), payload.end());

    return blob;
}

DecryptedMessage decrypt_message(const std::vector<uint8_t>& blob,
                                 const Botan::ML_KEM_PrivateKey& priv_key,
                                 Botan::AutoSeeded_RNG& rng)
{
    if (blob.size() != KEM_CIPHERTEXT_LEN + PADDED_PLAINTEXT_LEN + GCM_TAG_LEN)
        throw std::runtime_error("Blob size mismatch");

    // Step 1 — split blob into KEM ciphertext and AES ciphertext
    std::vector<uint8_t> kem_ct(blob.begin(), blob.begin() + KEM_CIPHERTEXT_LEN);
    Botan::secure_vector<uint8_t> ciphertext(blob.begin() + KEM_CIPHERTEXT_LEN, blob.end());

    // Step 2 — ML-KEM decapsulation: recover shared secret
    Botan::PK_KEM_Decryptor kem_dec(priv_key, rng, "Raw");
    auto shared_raw = kem_dec.decrypt(std::span<const uint8_t>(kem_ct), 32);

    // Step 3 — HKDF: same derivation as encrypt side
    auto hkdf_extract = Botan::KDF::create_or_throw("HKDF-Extract(SHA-256)");
    auto hkdf_expand = Botan::KDF::create_or_throw("HKDF-Expand(SHA-256)");

    Botan::secure_vector<uint8_t> prk =
        hkdf_extract->derive_key(32, shared_raw, kem_ct, std::vector<uint8_t>{});

    auto aes_key_bytes = hkdf_expand->derive_key(
        32, prk, std::vector<uint8_t>{}, std::vector<uint8_t>{'a', 'e', 's', '-', 'k', 'e', 'y'});
    auto nonce_bytes = hkdf_expand->derive_key(12, prk, std::vector<uint8_t>{},
                                               std::vector<uint8_t>{'a', 'e', 's', '-', 'i', 'v'});

    // Step 4 — AES-256-GCM decrypt (throws if tampered)
    auto aead = Botan::AEAD_Mode::create_or_throw("AES-256/GCM", Botan::Cipher_Dir::Decryption);
    aead->set_key(Botan::SymmetricKey(aes_key_bytes));
    aead->start(nonce_bytes);
    aead->finish(ciphertext);

    // Step 5 — parse payload:
    //   msg_nonce(16) + sender_id(16) + name_len(1) + sender_name + msg_len(2) + message + padding
    constexpr size_t min_payload = MSG_NONCE_LEN + USER_ID_LEN + 1 + 2;
    if (ciphertext.size() < min_payload)
        throw std::runtime_error("Decrypted payload too short");

    DecryptedMessage result;
    size_t pos = 0;

    result.msg_nonce = std::vector<uint8_t>(ciphertext.begin(), ciphertext.begin() + MSG_NONCE_LEN);
    pos += MSG_NONCE_LEN;

    result.sender_id =
        std::string(ciphertext.begin() + pos, ciphertext.begin() + pos + USER_ID_LEN);
    pos += USER_ID_LEN;

    uint8_t name_len = ciphertext[pos++];
    if (ciphertext.size() < pos + name_len + 2)
        throw std::runtime_error("Decrypted payload malformed");

    result.sender_name = std::string(ciphertext.begin() + pos, ciphertext.begin() + pos + name_len);
    pos += name_len;

    uint16_t msg_len = (static_cast<uint16_t>(ciphertext[pos]) << 8) | ciphertext[pos + 1];
    pos += 2;
    if (ciphertext.size() < pos + msg_len)
        throw std::runtime_error("Decrypted payload malformed");

    result.plaintext = std::string(ciphertext.begin() + pos, ciphertext.begin() + pos + msg_len);

    return result;
}
