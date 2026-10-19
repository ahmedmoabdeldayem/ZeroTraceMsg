#include "identity.hpp"
#include "kem.hpp"
#include "secure_memory.hpp"
#include <botan/aead.h>
#include <botan/hash.h>
#include <botan/hex.h>
#include <botan/kdf.h>
#include <botan/pkcs8.h>
#include <botan/pwdhash.h>
#include <fstream>
#include <span>
#include <stdexcept>

std::string derive_user_id(const std::vector<uint8_t>& pubkey_bytes)
{
    auto sha256 = Botan::HashFunction::create_or_throw("SHA-256");
    sha256->update(pubkey_bytes);
    auto digest = sha256->final();
    return Botan::hex_encode(digest.data(), 8); // first 8 bytes → 16 hex chars
}

Identity generate_identity(Botan::AutoSeeded_RNG& rng, const Config& cfg)
{
    Identity id;
    id.priv_key = make_kem_key(rng, cfg);
    id.priv_key2 = make_kem_key2(rng, cfg); // null for non-hybrid

    // pubkey_bytes = primary_pub [ || secondary_pub ] for hybrid
    id.pubkey_bytes = kem_pubkey_bytes(*id.priv_key);
    if (id.priv_key2) {
        auto pub2 = kem_pubkey_bytes(*id.priv_key2);
        id.pubkey_bytes.insert(id.pubkey_bytes.end(), pub2.begin(), pub2.end());
    }

    id.user_id = derive_user_id(id.pubkey_bytes);
    return id;
}

// ── passphrase KDF ───────────────────────────────────────────────────────────

static Botan::secure_vector<uint8_t> kdf_from_passphrase(const SecureString& passphrase,
                                                         std::span<const uint8_t> salt,
                                                         const Config& cfg)
{
    auto fam = Botan::PasswordHashFamily::create_or_throw(cfg.botan_passphrase_kdf());
    std::unique_ptr<Botan::PasswordHash> pwhash;

    if (cfg.passphrase_kdf == "Argon2id") {
        // Botan's from_params order for Argon2: (M=memory_KB, t=time_cost, p=parallelism)
        pwhash = fam->from_params(static_cast<size_t>(cfg.passphrase_kdf_memory_kb),
                                  static_cast<size_t>(cfg.passphrase_kdf_cost),
                                  static_cast<size_t>(cfg.passphrase_kdf_parallelism));
    } else {
        // PBKDF2 — cost is iterations directly
        pwhash = fam->from_iterations(static_cast<size_t>(cfg.passphrase_kdf_cost));
    }

    Botan::secure_vector<uint8_t> key(32);
    pwhash->derive_key(key.data(), key.size(), passphrase.data(), passphrase.size(), salt.data(),
                       salt.size());
    return key;
}

// ── save / load ───────────────────────────────────────────────────────────────

void save_identity(const Identity& id, const SecureString& passphrase, const std::string& path,
                   Botan::AutoSeeded_RNG& rng, const Config& cfg)
{
    auto salt = rng.random_vec(16);
    auto nonce = rng.random_vec(12);
    auto aes_key =
        kdf_from_passphrase(passphrase, std::span<const uint8_t>(salt.data(), salt.size()), cfg);

    // Collect private key material.
    // RSA does not implement raw_private_key_bits(); store full PKCS#8 PrivateKeyInfo instead.
    auto raw = (cfg.kem.substr(0, 3) == "RSA") ? Botan::PKCS8::BER_encode(*id.priv_key)
                                               : id.priv_key->raw_private_key_bits();
    if (id.priv_key2) {
        auto raw2 = id.priv_key2->raw_private_key_bits();
        raw.insert(raw.end(), raw2.begin(), raw2.end());
    }

    auto enc = Botan::AEAD_Mode::create_or_throw("AES-256/GCM", Botan::Cipher_Dir::Encryption);
    enc->set_key(aes_key);
    enc->start(nonce);
    Botan::secure_vector<uint8_t> buf(raw.begin(), raw.end());
    enc->finish(buf);

    std::ofstream out(path, std::ios::binary);
    if (!out)
        throw std::runtime_error("Cannot write identity file: " + path);
    out.write(reinterpret_cast<const char*>(salt.data()), salt.size());
    out.write(reinterpret_cast<const char*>(nonce.data()), nonce.size());
    out.write(reinterpret_cast<const char*>(buf.data()), buf.size());
}

Identity load_identity(const SecureString& passphrase, const std::string& path, const Config& cfg)
{
    std::ifstream in(path, std::ios::binary);
    if (!in)
        throw std::runtime_error("Identity file not found: " + path);

    Botan::secure_vector<uint8_t> salt(16), nonce(12);
    in.read(reinterpret_cast<char*>(salt.data()), 16);
    in.read(reinterpret_cast<char*>(nonce.data()), 12);

    std::vector<char> raw_ct(std::istreambuf_iterator<char>(in), {});
    Botan::secure_vector<uint8_t> ciphertext(raw_ct.begin(), raw_ct.end());

    auto aes_key =
        kdf_from_passphrase(passphrase, std::span<const uint8_t>(salt.data(), salt.size()), cfg);

    auto dec = Botan::AEAD_Mode::create_or_throw("AES-256/GCM", Botan::Cipher_Dir::Decryption);
    dec->set_key(aes_key);
    dec->start(nonce);
    dec->finish(ciphertext); // throws on wrong passphrase

    // Determine how many bytes belong to the primary key
    bool hybrid = (cfg.kem == "HYBRID-P256-ML-KEM-768" || cfg.kem == "HYBRID-P384-ML-KEM-1024" ||
                   cfg.kem == "HYBRID-X25519-ML-KEM-768");
    size_t primary_bytes;
    if (cfg.kem == "HYBRID-P256-ML-KEM-768")
        primary_bytes = 32; // ECDH-P256 scalar
    else if (cfg.kem == "HYBRID-P384-ML-KEM-1024")
        primary_bytes = 48; // ECDH-P384 scalar
    else if (cfg.kem == "HYBRID-X25519-ML-KEM-768")
        primary_bytes = 32; // X25519 scalar
    else
        primary_bytes = ciphertext.size(); // all bytes for non-hybrid

    std::span<const uint8_t> bytes1(ciphertext.data(), primary_bytes);
    Identity id;
    id.priv_key = kem_key_from_bytes(bytes1, cfg, /*secondary=*/false);

    if (hybrid) {
        std::span<const uint8_t> bytes2(ciphertext.data() + primary_bytes,
                                        ciphertext.size() - primary_bytes);
        id.priv_key2 = kem_key_from_bytes(bytes2, cfg, /*secondary=*/true);
    }

    id.pubkey_bytes = kem_pubkey_bytes(*id.priv_key);
    if (id.priv_key2) {
        auto pub2 = kem_pubkey_bytes(*id.priv_key2);
        id.pubkey_bytes.insert(id.pubkey_bytes.end(), pub2.begin(), pub2.end());
    }
    id.user_id = derive_user_id(id.pubkey_bytes);
    return id;
}

// ── contacts key derivation ───────────────────────────────────────────────────

Botan::secure_vector<uint8_t> derive_contacts_key(const Identity& id, const Config& cfg)
{
    auto hkdf_ext = Botan::KDF::create_or_throw("HKDF-Extract(" + cfg.botan_hash() + ")");
    auto hkdf_exp = Botan::KDF::create_or_throw("HKDF-Expand(" + cfg.botan_hash() + ")");

    auto raw = id.priv_key->raw_private_key_bits();

    // Extract: IKM = private key seed, no salt (deterministic per identity)
    Botan::secure_vector<uint8_t> prk =
        hkdf_ext->derive_key(32, raw, std::vector<uint8_t>{}, std::vector<uint8_t>{});

    // Expand: domain-separate with a fixed info string
    static const std::vector<uint8_t> info{'Z', 'T', 'M', '-', 'c', 'o', 'n', 't',
                                           'a', 'c', 't', 's', '-', 'v', '1'};
    return hkdf_exp->derive_key(32, prk, std::vector<uint8_t>{}, info);
}
