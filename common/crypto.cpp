#include "crypto.hpp"
#include "kem.hpp"
#include "protocol.hpp"
#include <botan/aead.h>
#include <botan/hex.h>
#include <botan/kdf.h>
#include <stdexcept>

std::vector<uint8_t> encrypt_message(const std::string& plaintext, const std::string& sender_id,
                                     const std::string& sender_name,
                                     const std::vector<uint8_t>& recipient_pubkey,
                                     Botan::AutoSeeded_RNG& rng, const Config& cfg)
{
    // Step 1 — KEM encapsulation: produces (ciphertext, shared_secret)
    auto kem = kem_encapsulate(recipient_pubkey, rng, cfg);

    // Step 2 — HKDF: use KEM ciphertext as salt to bind derivation to this encapsulation
    std::string hkdf_extract = "HKDF-Extract(" + cfg.botan_hash() + ")";
    std::string hkdf_expand = "HKDF-Expand(" + cfg.botan_hash() + ")";

    auto hkdf_ext = Botan::KDF::create_or_throw(hkdf_extract);
    auto hkdf_exp = Botan::KDF::create_or_throw(hkdf_expand);

    // Bind derivation to the intended recipient's public key by including it
    // in the HKDF-Extract salt alongside the KEM ciphertext.  This ensures
    // decryption with a different identity always produces a distinct key,
    // regardless of what the underlying KEM returns.
    std::vector<uint8_t> hkdf_salt(kem.ciphertext.begin(), kem.ciphertext.end());
    hkdf_salt.insert(hkdf_salt.end(), recipient_pubkey.begin(), recipient_pubkey.end());
    Botan::secure_vector<uint8_t> prk =
        hkdf_ext->derive_key(32, kem.shared_secret, hkdf_salt, std::vector<uint8_t>{});

    auto aes_key_bytes =
        hkdf_exp->derive_key(cfg.botan_key_len(), prk, std::vector<uint8_t>{},
                             std::vector<uint8_t>{'a', 'e', 's', '-', 'k', 'e', 'y'});
    auto nonce_bytes = hkdf_exp->derive_key(12, prk, std::vector<uint8_t>{},
                                            std::vector<uint8_t>{'a', 'e', 's', '-', 'i', 'v'});

    // Step 3 — assemble and pad plaintext:
    //   msg_nonce(16) + sender_id(16) + name_len(1) + sender_name
    //   + msg_len(2, big-endian) + message + zero-padding → PADDED_PLAINTEXT_LEN
    auto nonce_raw = rng.random_vec(MSG_NONCE_LEN);
    uint8_t name_len = static_cast<uint8_t>(sender_name.size() < 255 ? sender_name.size() : 255);

    size_t padded = cfg.padded_plaintext_bytes();
    constexpr size_t fixed_overhead = MSG_NONCE_LEN + USER_ID_LEN + 1 + 2;
    if (fixed_overhead + name_len + plaintext.size() > padded)
        throw std::runtime_error("Message too long to encrypt");

    auto msg_len = static_cast<uint16_t>(plaintext.size());
    Botan::secure_vector<uint8_t> payload;
    payload.reserve(padded);
    payload.insert(payload.end(), nonce_raw.begin(), nonce_raw.end());
    payload.insert(payload.end(), sender_id.begin(), sender_id.end());
    payload.push_back(name_len);
    payload.insert(payload.end(), sender_name.begin(), sender_name.begin() + name_len);
    payload.push_back(static_cast<uint8_t>(msg_len >> 8));
    payload.push_back(static_cast<uint8_t>(msg_len & 0xFF));
    payload.insert(payload.end(), plaintext.begin(), plaintext.end());
    payload.resize(padded, 0);

    // Step 4 — AEAD encrypt (cipher from config)
    auto aead =
        Botan::AEAD_Mode::create_or_throw(cfg.botan_cipher(), Botan::Cipher_Dir::Encryption);
    aead->set_key(aes_key_bytes);
    aead->start(nonce_bytes);
    aead->finish(payload);

    // Step 5 — blob: kem_ciphertext + aead_ciphertext+tag
    std::vector<uint8_t> blob;
    blob.insert(blob.end(), kem.ciphertext.begin(), kem.ciphertext.end());
    blob.insert(blob.end(), payload.begin(), payload.end());
    return blob;
}

DecryptedMessage decrypt_message(const std::vector<uint8_t>& blob, const Identity& id,
                                 Botan::AutoSeeded_RNG& rng, const Config& cfg)
{
    size_t expected = cfg.max_blob_len();
    if (blob.size() != expected)
        throw std::runtime_error("Blob size mismatch: expected " + std::to_string(expected) +
                                 " got " + std::to_string(blob.size()));

    size_t kem_len = cfg.kem_ciphertext_len();
    std::vector<uint8_t> kem_ct(blob.begin(), blob.begin() + kem_len);
    Botan::secure_vector<uint8_t> ciphertext(blob.begin() + kem_len, blob.end());

    // Step 1 — KEM decapsulation
    auto shared_secret = kem_decapsulate(kem_ct, *id.priv_key, id.priv_key2.get(), rng, cfg);

    // Step 2 — HKDF (same derivation as encrypt)
    std::string hkdf_extract = "HKDF-Extract(" + cfg.botan_hash() + ")";
    std::string hkdf_expand = "HKDF-Expand(" + cfg.botan_hash() + ")";

    auto hkdf_ext = Botan::KDF::create_or_throw(hkdf_extract);
    auto hkdf_exp = Botan::KDF::create_or_throw(hkdf_expand);

    std::vector<uint8_t> hkdf_salt(kem_ct.begin(), kem_ct.end());
    hkdf_salt.insert(hkdf_salt.end(), id.pubkey_bytes.begin(), id.pubkey_bytes.end());
    Botan::secure_vector<uint8_t> prk =
        hkdf_ext->derive_key(32, shared_secret, hkdf_salt, std::vector<uint8_t>{});

    auto aes_key_bytes =
        hkdf_exp->derive_key(cfg.botan_key_len(), prk, std::vector<uint8_t>{},
                             std::vector<uint8_t>{'a', 'e', 's', '-', 'k', 'e', 'y'});
    auto nonce_bytes = hkdf_exp->derive_key(12, prk, std::vector<uint8_t>{},
                                            std::vector<uint8_t>{'a', 'e', 's', '-', 'i', 'v'});

    // Step 3 — AEAD decrypt
    auto aead =
        Botan::AEAD_Mode::create_or_throw(cfg.botan_cipher(), Botan::Cipher_Dir::Decryption);
    aead->set_key(aes_key_bytes);
    aead->start(nonce_bytes);
    aead->finish(ciphertext);

    // Step 4 — parse payload
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
