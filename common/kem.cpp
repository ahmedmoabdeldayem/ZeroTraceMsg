#include "kem.hpp"
#include <botan/ec_group.h>
#include <botan/ecdh.h>
#include <botan/hex.h>
#include <botan/ml_kem.h>
#include <botan/pubkey.h>
#include <stdexcept>

// ── helpers ──────────────────────────────────────────────────────────────────

static Botan::EC_Group ec_group(const Config& cfg, bool secondary = false)
{
    std::string curve;
    if (!secondary) {
        curve = (cfg.kem == "ECDH-P384" || cfg.kem == "HYBRID-P384-ML-KEM-1024") ? "secp384r1"
                                                                                 : "secp256r1";
    }
    return Botan::EC_Group::from_name(curve);
}

static Botan::KyberMode kem_mode(const Config& cfg)
{
    if (cfg.kem == "ML-KEM-512")
        return Botan::KyberMode::ML_KEM_512;
    if (cfg.kem == "ML-KEM-768")
        return Botan::KyberMode::ML_KEM_768;
    if (cfg.kem == "ML-KEM-1024")
        return Botan::KyberMode::ML_KEM_1024;
    if (cfg.kem == "HYBRID-P256-ML-KEM-768")
        return Botan::KyberMode::ML_KEM_768;
    if (cfg.kem == "HYBRID-P384-ML-KEM-1024")
        return Botan::KyberMode::ML_KEM_1024;
    throw std::invalid_argument("kem_mode: no ML-KEM mode for " + cfg.kem);
}

static bool is_ecdh(const Config& cfg, bool secondary = false)
{
    if (secondary)
        return false;
    return cfg.kem == "ECDH-P256" || cfg.kem == "ECDH-P384" ||
           cfg.kem == "HYBRID-P256-ML-KEM-768" || cfg.kem == "HYBRID-P384-ML-KEM-1024";
}

static bool is_mlkem(const Config& cfg, bool secondary = false)
{
    if (secondary)
        return cfg.kem == "HYBRID-P256-ML-KEM-768" || cfg.kem == "HYBRID-P384-ML-KEM-1024";
    return cfg.kem == "ML-KEM-512" || cfg.kem == "ML-KEM-768" || cfg.kem == "ML-KEM-1024" ||
           cfg.kem == "HYBRID-P256-ML-KEM-768" || cfg.kem == "HYBRID-P384-ML-KEM-1024";
}

// ── public API ────────────────────────────────────────────────────────────────

std::unique_ptr<Botan::Private_Key> make_kem_key(Botan::AutoSeeded_RNG& rng, const Config& cfg)
{
    if (is_ecdh(cfg))
        return std::make_unique<Botan::ECDH_PrivateKey>(rng, ec_group(cfg));
    if (is_mlkem(cfg) && !is_ecdh(cfg))
        return std::make_unique<Botan::ML_KEM_PrivateKey>(rng, kem_mode(cfg));
    throw std::invalid_argument("make_kem_key: unknown kem " + cfg.kem);
}

std::unique_ptr<Botan::Private_Key> make_kem_key2(Botan::AutoSeeded_RNG& rng, const Config& cfg)
{
    if (!is_mlkem(cfg, /*secondary=*/true))
        return nullptr;
    return std::make_unique<Botan::ML_KEM_PrivateKey>(rng, kem_mode(cfg));
}

std::vector<uint8_t> kem_pubkey_bytes(const Botan::Private_Key& key)
{
    return key.raw_public_key_bits();
}

std::unique_ptr<Botan::Private_Key> kem_key_from_bytes(std::span<const uint8_t> bytes,
                                                       const Config& cfg, bool secondary)
{
    if (secondary)
        return std::make_unique<Botan::ML_KEM_PrivateKey>(bytes, kem_mode(cfg));

    if (is_ecdh(cfg)) {
        auto grp = ec_group(cfg);
        auto scalar = Botan::EC_Scalar::deserialize(grp, bytes);
        if (!scalar)
            throw std::runtime_error("Invalid ECDH private key bytes");
        return std::make_unique<Botan::ECDH_PrivateKey>(grp, *scalar);
    }
    // pure ML-KEM
    return std::make_unique<Botan::ML_KEM_PrivateKey>(bytes, kem_mode(cfg));
}

// ── encapsulate ───────────────────────────────────────────────────────────────

KemEncapResult kem_encapsulate(const std::vector<uint8_t>& recipient_pubkey,
                               Botan::AutoSeeded_RNG& rng, const Config& cfg)
{
    KemEncapResult result;

    if (cfg.kem == "ECDH-P256" || cfg.kem == "ECDH-P384") {
        // Classical ECDH: generate ephemeral key, derive shared secret
        auto grp = ec_group(cfg);
        Botan::ECDH_PrivateKey ephemeral(rng, grp);
        Botan::PK_Key_Agreement ecdh(ephemeral, rng, "Raw");
        auto ss = ecdh.derive_key(32, recipient_pubkey);
        result.ciphertext = ephemeral.raw_public_key_bits();
        result.shared_secret.assign(ss.bits_of().begin(), ss.bits_of().end());

    } else if (cfg.kem == "ML-KEM-512" || cfg.kem == "ML-KEM-768" || cfg.kem == "ML-KEM-1024") {
        // Pure ML-KEM
        Botan::ML_KEM_PublicKey pub(recipient_pubkey, kem_mode(cfg));
        Botan::PK_KEM_Encryptor enc(pub, "Raw");
        auto kem = enc.encrypt(rng, 32);
        result.ciphertext = kem.encapsulated_shared_key();
        result.shared_secret = kem.shared_key();

    } else if (cfg.kem == "HYBRID-P256-ML-KEM-768" || cfg.kem == "HYBRID-P384-ML-KEM-1024") {
        // Hybrid: ECDH pubkey || ML-KEM pubkey concatenated in recipient_pubkey
        size_t ecdh_pub_len = (cfg.kem == "HYBRID-P256-ML-KEM-768") ? 65 : 97;

        std::vector<uint8_t> ecdh_pub(recipient_pubkey.begin(),
                                      recipient_pubkey.begin() + ecdh_pub_len);
        std::vector<uint8_t> kem_pub(recipient_pubkey.begin() + ecdh_pub_len,
                                     recipient_pubkey.end());

        // ECDH leg
        auto grp = ec_group(cfg);
        Botan::ECDH_PrivateKey ephemeral(rng, grp);
        Botan::PK_Key_Agreement ecdh(ephemeral, rng, "Raw");
        auto ecdh_ss = ecdh.derive_key(32, ecdh_pub);
        auto ecdh_ct = ephemeral.raw_public_key_bits();

        // ML-KEM leg
        Botan::ML_KEM_PublicKey pub(kem_pub, kem_mode(cfg));
        Botan::PK_KEM_Encryptor enc(pub, "Raw");
        auto kem_r = enc.encrypt(rng, 32);
        auto& kem_ct = kem_r.encapsulated_shared_key();
        auto& kem_ss = kem_r.shared_key();

        // Combine ciphertexts: ecdh_ephemeral_pub || kem_ct
        result.ciphertext.insert(result.ciphertext.end(), ecdh_ct.begin(), ecdh_ct.end());
        result.ciphertext.insert(result.ciphertext.end(), kem_ct.begin(), kem_ct.end());

        // Combine shared secrets: concatenate (HKDF will bind them together)
        result.shared_secret.insert(result.shared_secret.end(), ecdh_ss.bits_of().begin(),
                                    ecdh_ss.bits_of().end());
        result.shared_secret.insert(result.shared_secret.end(), kem_ss.begin(), kem_ss.end());

    } else {
        throw std::invalid_argument("kem_encapsulate: unknown kem " + cfg.kem);
    }

    return result;
}

// ── decapsulate ───────────────────────────────────────────────────────────────

Botan::secure_vector<uint8_t> kem_decapsulate(const std::vector<uint8_t>& ciphertext,
                                              const Botan::Private_Key& priv,
                                              const Botan::Private_Key* priv2,
                                              Botan::AutoSeeded_RNG& rng, const Config& cfg)
{
    Botan::secure_vector<uint8_t> shared;

    if (cfg.kem == "ECDH-P256" || cfg.kem == "ECDH-P384") {
        auto& ecdh_priv = dynamic_cast<const Botan::ECDH_PrivateKey&>(priv);
        Botan::PK_Key_Agreement ecdh(ecdh_priv, rng, "Raw");
        auto ss = ecdh.derive_key(32, ciphertext);
        shared.assign(ss.bits_of().begin(), ss.bits_of().end());

    } else if (cfg.kem == "ML-KEM-512" || cfg.kem == "ML-KEM-768" || cfg.kem == "ML-KEM-1024") {
        auto& kem_priv = dynamic_cast<const Botan::ML_KEM_PrivateKey&>(priv);
        Botan::PK_KEM_Decryptor dec(kem_priv, rng, "Raw");
        shared = dec.decrypt(std::span<const uint8_t>(ciphertext), 32);

    } else if (cfg.kem == "HYBRID-P256-ML-KEM-768" || cfg.kem == "HYBRID-P384-ML-KEM-1024") {
        if (!priv2)
            throw std::runtime_error("Hybrid decapsulation requires secondary key");

        size_t ecdh_ct_len = (cfg.kem == "HYBRID-P256-ML-KEM-768") ? 65 : 97;

        std::vector<uint8_t> ecdh_ct(ciphertext.begin(), ciphertext.begin() + ecdh_ct_len);
        std::vector<uint8_t> kem_ct(ciphertext.begin() + ecdh_ct_len, ciphertext.end());

        // ECDH leg
        auto& ecdh_priv = dynamic_cast<const Botan::ECDH_PrivateKey&>(priv);
        Botan::PK_Key_Agreement ecdh(ecdh_priv, rng, "Raw");
        auto ecdh_ss = ecdh.derive_key(32, ecdh_ct);

        // ML-KEM leg
        auto& kem_priv = dynamic_cast<const Botan::ML_KEM_PrivateKey&>(*priv2);
        Botan::PK_KEM_Decryptor dec(kem_priv, rng, "Raw");
        auto kem_ss = dec.decrypt(std::span<const uint8_t>(kem_ct), 32);

        // Concatenate shared secrets
        shared.insert(shared.end(), ecdh_ss.bits_of().begin(), ecdh_ss.bits_of().end());
        shared.insert(shared.end(), kem_ss.begin(), kem_ss.end());

    } else {
        throw std::invalid_argument("kem_decapsulate: unknown kem " + cfg.kem);
    }

    return shared;
}
