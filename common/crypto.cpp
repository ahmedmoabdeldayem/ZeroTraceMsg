#include "crypto.hpp"
#include "protocol.hpp"
#include <botan/aead.h>
#include <botan/ec_group.h>
#include <botan/hex.h>
#include <botan/kdf.h>
#include <botan/pubkey.h>
#include <stdexcept>

std::vector<uint8_t> encrypt_message(const std::string& plaintext, const std::string& sender_id,
                                     const std::string& sender_name,
                                     const std::vector<uint8_t>& recipient_pubkey,
                                     Botan::AutoSeeded_RNG& rng)
{
    auto group = Botan::EC_Group::from_name("secp256r1");

    // Step 1 — fresh ephemeral key pair (discarded after this function returns)
    Botan::ECDH_PrivateKey ephemeral(rng, group);
    auto ephemeral_pub_bytes = ephemeral.raw_public_key_bits();

    // Step 2 — ECDH shared secret
    Botan::PK_Key_Agreement ecdh(ephemeral, rng, "Raw");
    Botan::SymmetricKey shared = ecdh.derive_key(32, recipient_pubkey);

    // Step 3 — HKDF: ephemeral pubkey used as salt to bind derivation to this message
    auto hkdf_extract = Botan::KDF::create_or_throw("HKDF-Extract(SHA-256)");
    auto hkdf_expand = Botan::KDF::create_or_throw("HKDF-Expand(SHA-256)");

    Botan::secure_vector<uint8_t> prk =
        hkdf_extract->derive_key(32, shared.bits_of(), ephemeral_pub_bytes, std::vector<uint8_t>{});

    auto aes_key_bytes = hkdf_expand->derive_key(
        32, prk, std::vector<uint8_t>{}, std::vector<uint8_t>{'a', 'e', 's', '-', 'k', 'e', 'y'});
    auto nonce_bytes = hkdf_expand->derive_key(12, prk, std::vector<uint8_t>{},
                                               std::vector<uint8_t>{'a', 'e', 's', '-', 'i', 'v'});

    // Step 4 — assemble plaintext payload:
    //   msg_nonce(16) + sender_id(16) + name_len(1) + sender_name + message
    auto nonce_raw = rng.random_vec(MSG_NONCE_LEN);
    uint8_t name_len = static_cast<uint8_t>(sender_name.size() < 255 ? sender_name.size() : 255);
    Botan::secure_vector<uint8_t> payload;
    payload.insert(payload.end(), nonce_raw.begin(), nonce_raw.end());
    payload.insert(payload.end(), sender_id.begin(), sender_id.end());
    payload.push_back(name_len);
    payload.insert(payload.end(), sender_name.begin(), sender_name.begin() + name_len);
    payload.insert(payload.end(), plaintext.begin(), plaintext.end());

    // Step 5 — AES-256-GCM encrypt
    auto aead = Botan::AEAD_Mode::create_or_throw("AES-256/GCM", Botan::Cipher_Dir::Encryption);
    aead->set_key(Botan::SymmetricKey(aes_key_bytes));
    aead->start(nonce_bytes);
    aead->finish(payload);

    // Step 6 — blob: ephemeral_pub(65) + ciphertext+tag
    // Nonce is NOT stored — recipient re-derives it from HKDF using the ephemeral pubkey
    std::vector<uint8_t> blob;
    blob.insert(blob.end(), ephemeral_pub_bytes.begin(), ephemeral_pub_bytes.end());
    blob.insert(blob.end(), payload.begin(), payload.end());

    return blob;
}

DecryptedMessage decrypt_message(const std::vector<uint8_t>& blob,
                                 const Botan::ECDH_PrivateKey& priv_key, Botan::AutoSeeded_RNG& rng)
{
    // blob: ephemeral_pub(65) + ciphertext+tag — minimum: 65 + MSG_NONCE_LEN + USER_ID_LEN + 1 + 16
    if (blob.size() < 65 + MSG_NONCE_LEN + USER_ID_LEN + 1 + 16)
        throw std::runtime_error("Blob too short");

    // Step 1 — parse blob
    std::vector<uint8_t> ephemeral_pub(blob.begin(), blob.begin() + 65);
    Botan::secure_vector<uint8_t> ciphertext(blob.begin() + 65, blob.end());

    // Step 2 — ECDH shared secret
    Botan::PK_Key_Agreement ecdh(priv_key, rng, "Raw");
    Botan::SymmetricKey shared = ecdh.derive_key(32, ephemeral_pub);

    // Step 3 — HKDF: same derivation as encrypt side — ephemeral pubkey as salt
    auto hkdf_extract = Botan::KDF::create_or_throw("HKDF-Extract(SHA-256)");
    auto hkdf_expand = Botan::KDF::create_or_throw("HKDF-Expand(SHA-256)");

    Botan::secure_vector<uint8_t> prk =
        hkdf_extract->derive_key(32, shared.bits_of(), ephemeral_pub, std::vector<uint8_t>{});

    auto aes_key_bytes = hkdf_expand->derive_key(
        32, prk, std::vector<uint8_t>{}, std::vector<uint8_t>{'a', 'e', 's', '-', 'k', 'e', 'y'});
    auto nonce_bytes = hkdf_expand->derive_key(12, prk, std::vector<uint8_t>{},
                                               std::vector<uint8_t>{'a', 'e', 's', '-', 'i', 'v'});

    // Step 4 — AES-256-GCM decrypt (throws if tampered)
    auto aead = Botan::AEAD_Mode::create_or_throw("AES-256/GCM", Botan::Cipher_Dir::Decryption);
    aead->set_key(Botan::SymmetricKey(aes_key_bytes));
    aead->start(nonce_bytes);
    aead->finish(ciphertext);

    // Step 5 — parse payload: msg_nonce(16) + sender_id(16) + name_len(1) + sender_name + message
    if (ciphertext.size() < MSG_NONCE_LEN + USER_ID_LEN + 1)
        throw std::runtime_error("Decrypted payload too short");

    DecryptedMessage result;
    size_t pos = 0;

    result.msg_nonce = std::vector<uint8_t>(ciphertext.begin(), ciphertext.begin() + MSG_NONCE_LEN);
    pos += MSG_NONCE_LEN;

    result.sender_id =
        std::string(ciphertext.begin() + pos, ciphertext.begin() + pos + USER_ID_LEN);
    pos += USER_ID_LEN;

    uint8_t name_len = ciphertext[pos++];
    if (ciphertext.size() < pos + name_len)
        throw std::runtime_error("Decrypted payload malformed");

    result.sender_name = std::string(ciphertext.begin() + pos, ciphertext.begin() + pos + name_len);
    pos += name_len;
    result.plaintext = std::string(ciphertext.begin() + pos, ciphertext.end());

    return result;
}
