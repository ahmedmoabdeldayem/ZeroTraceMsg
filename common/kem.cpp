#include "kem.hpp"
#include <botan/bigint.h>
#include <botan/data_src.h>
#include <botan/ec_group.h>
#include <botan/ecdh.h>
#include <botan/hex.h>
#include <botan/ml_kem.h>
#include <botan/pkcs8.h>
#include <botan/pubkey.h>
#include <botan/rsa.h>
#include <botan/x25519.h>
#include <stdexcept>

// ── classification helpers ────────────────────────────────────────────────────

static bool is_ecdh_p(const Config& cfg)
{
    return cfg.kem == "ECDH-P256" || cfg.kem == "ECDH-P384" ||
           cfg.kem == "HYBRID-P256-ML-KEM-768" || cfg.kem == "HYBRID-P384-ML-KEM-1024";
}

static bool is_x25519(const Config& cfg)
{
    return cfg.kem == "X25519" || cfg.kem == "HYBRID-X25519-ML-KEM-768";
}

static bool is_rsa(const Config& cfg)
{
    return cfg.kem == "RSA-2048" || cfg.kem == "RSA-3072" || cfg.kem == "RSA-4096";
}

static size_t rsa_key_bytes(const Config& cfg)
{
    if (cfg.kem == "RSA-2048")
        return 256;
    if (cfg.kem == "RSA-3072")
        return 384;
    return 512; // RSA-4096
}

static bool is_mlkem(const Config& cfg, bool secondary = false)
{
    if (secondary)
        return cfg.kem == "HYBRID-P256-ML-KEM-768" || cfg.kem == "HYBRID-P384-ML-KEM-1024" ||
               cfg.kem == "HYBRID-X25519-ML-KEM-768";
    return cfg.kem == "ML-KEM-512" || cfg.kem == "ML-KEM-768" || cfg.kem == "ML-KEM-1024" ||
           cfg.kem == "HYBRID-P256-ML-KEM-768" || cfg.kem == "HYBRID-P384-ML-KEM-1024" ||
           cfg.kem == "HYBRID-X25519-ML-KEM-768";
}

static Botan::EC_Group ec_group(const Config& cfg)
{
    std::string curve = (cfg.kem == "ECDH-P384" || cfg.kem == "HYBRID-P384-ML-KEM-1024")
                            ? "secp384r1"
                            : "secp256r1";
    return Botan::EC_Group::from_name(curve);
}

static Botan::KyberMode kem_mode(const Config& cfg)
{
    if (cfg.kem == "ML-KEM-512")
        return Botan::KyberMode::ML_KEM_512;
    if (cfg.kem == "ML-KEM-768" || cfg.kem == "HYBRID-P256-ML-KEM-768" ||
        cfg.kem == "HYBRID-X25519-ML-KEM-768")
        return Botan::KyberMode::ML_KEM_768;
    if (cfg.kem == "ML-KEM-1024" || cfg.kem == "HYBRID-P384-ML-KEM-1024")
        return Botan::KyberMode::ML_KEM_1024;
    throw std::invalid_argument("kem_mode: no ML-KEM mode for " + cfg.kem);
}

// ── public API ────────────────────────────────────────────────────────────────

std::unique_ptr<Botan::Private_Key> make_kem_key(Botan::AutoSeeded_RNG& rng, const Config& cfg)
{
    if (is_ecdh_p(cfg))
        return std::make_unique<Botan::ECDH_PrivateKey>(rng, ec_group(cfg));
    if (is_x25519(cfg))
        return std::make_unique<Botan::X25519_PrivateKey>(rng);
    if (is_rsa(cfg))
        return std::make_unique<Botan::RSA_PrivateKey>(rng, rsa_key_bytes(cfg) * 8);
    // pure ML-KEM
    if (is_mlkem(cfg))
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
    // RSA: return just the modulus in fixed-size encoding (not the full DER)
    if (const auto* rsa = dynamic_cast<const Botan::RSA_PublicKey*>(&key)) {
        const auto& n = rsa->get_n();
        size_t key_bytes = (n.bits() + 7) / 8;
        auto mod = n.serialize<std::vector<uint8_t>>(key_bytes);
        return mod;
    }
    return key.raw_public_key_bits();
}

std::unique_ptr<Botan::Private_Key> kem_key_from_bytes(std::span<const uint8_t> bytes,
                                                       const Config& cfg, bool secondary)
{
    if (secondary)
        return std::make_unique<Botan::ML_KEM_PrivateKey>(bytes, kem_mode(cfg));

    if (is_ecdh_p(cfg)) {
        auto grp = ec_group(cfg);
        auto scalar = Botan::EC_Scalar::deserialize(grp, bytes);
        if (!scalar)
            throw std::runtime_error("Invalid ECDH private key bytes");
        return std::make_unique<Botan::ECDH_PrivateKey>(grp, *scalar);
    }
    if (is_x25519(cfg))
        return std::make_unique<Botan::X25519_PrivateKey>(bytes);
    if (is_rsa(cfg)) {
        // RSA uses full PKCS#8 encoding (raw_private_key_bits is not implemented for RSA)
        Botan::DataSource_Memory ds(bytes.data(), bytes.size());
        return Botan::PKCS8::load_key(ds);
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
        auto grp = ec_group(cfg);
        Botan::ECDH_PrivateKey ephemeral(rng, grp);
        Botan::PK_Key_Agreement ecdh(ephemeral, rng, "Raw");
        auto ss = ecdh.derive_key(32, recipient_pubkey);
        result.ciphertext = ephemeral.raw_public_key_bits();
        result.shared_secret.assign(ss.bits_of().begin(), ss.bits_of().end());

    } else if (cfg.kem == "X25519") {
        Botan::X25519_PrivateKey ephemeral(rng);
        Botan::PK_Key_Agreement ecdh(ephemeral, rng, "Raw");
        auto ss = ecdh.derive_key(32, recipient_pubkey);
        result.ciphertext = ephemeral.raw_public_key_bits();
        result.shared_secret.assign(ss.bits_of().begin(), ss.bits_of().end());

    } else if (cfg.kem == "ML-KEM-512" || cfg.kem == "ML-KEM-768" || cfg.kem == "ML-KEM-1024") {
        Botan::ML_KEM_PublicKey pub(recipient_pubkey, kem_mode(cfg));
        Botan::PK_KEM_Encryptor enc(pub, "Raw");
        auto kem = enc.encrypt(rng, 32);
        result.ciphertext = kem.encapsulated_shared_key();
        result.shared_secret = kem.shared_key();

    } else if (cfg.kem == "HYBRID-P256-ML-KEM-768" || cfg.kem == "HYBRID-P384-ML-KEM-1024") {
        size_t ecdh_pub_len = (cfg.kem == "HYBRID-P256-ML-KEM-768") ? 65 : 97;
        std::vector<uint8_t> ecdh_pub(recipient_pubkey.begin(),
                                      recipient_pubkey.begin() + ecdh_pub_len);
        std::vector<uint8_t> kem_pub(recipient_pubkey.begin() + ecdh_pub_len,
                                     recipient_pubkey.end());

        auto grp = ec_group(cfg);
        Botan::ECDH_PrivateKey ephemeral(rng, grp);
        Botan::PK_Key_Agreement ecdh(ephemeral, rng, "Raw");
        auto ecdh_ss = ecdh.derive_key(32, ecdh_pub);
        auto ecdh_ct = ephemeral.raw_public_key_bits();

        Botan::ML_KEM_PublicKey pub(kem_pub, kem_mode(cfg));
        Botan::PK_KEM_Encryptor enc(pub, "Raw");
        auto kem_r = enc.encrypt(rng, 32);
        auto& kem_ct = kem_r.encapsulated_shared_key();
        auto& kem_ss = kem_r.shared_key();

        result.ciphertext.insert(result.ciphertext.end(), ecdh_ct.begin(), ecdh_ct.end());
        result.ciphertext.insert(result.ciphertext.end(), kem_ct.begin(), kem_ct.end());
        result.shared_secret.insert(result.shared_secret.end(), ecdh_ss.bits_of().begin(),
                                    ecdh_ss.bits_of().end());
        result.shared_secret.insert(result.shared_secret.end(), kem_ss.begin(), kem_ss.end());

    } else if (cfg.kem == "HYBRID-X25519-ML-KEM-768") {
        std::vector<uint8_t> x25519_pub(recipient_pubkey.begin(), recipient_pubkey.begin() + 32);
        std::vector<uint8_t> kem_pub(recipient_pubkey.begin() + 32, recipient_pubkey.end());

        Botan::X25519_PrivateKey ephemeral(rng);
        Botan::PK_Key_Agreement ecdh(ephemeral, rng, "Raw");
        auto x25519_ss = ecdh.derive_key(32, x25519_pub);
        auto x25519_ct = ephemeral.raw_public_key_bits();

        Botan::ML_KEM_PublicKey pub(kem_pub, Botan::KyberMode::ML_KEM_768);
        Botan::PK_KEM_Encryptor enc(pub, "Raw");
        auto kem_r = enc.encrypt(rng, 32);
        auto& kem_ct = kem_r.encapsulated_shared_key();
        auto& kem_ss = kem_r.shared_key();

        result.ciphertext.insert(result.ciphertext.end(), x25519_ct.begin(), x25519_ct.end());
        result.ciphertext.insert(result.ciphertext.end(), kem_ct.begin(), kem_ct.end());
        result.shared_secret.insert(result.shared_secret.end(), x25519_ss.bits_of().begin(),
                                    x25519_ss.bits_of().end());
        result.shared_secret.insert(result.shared_secret.end(), kem_ss.begin(), kem_ss.end());

    } else if (is_rsa(cfg)) {
        // RSA-KEM: encrypt a random shared secret with the recipient's RSA public key (OAEP)
        Botan::BigInt n(recipient_pubkey.data(), recipient_pubkey.size());
        Botan::RSA_PublicKey rsa_pub(n, Botan::BigInt(65537));
        auto ss = rng.random_vec(32);
        Botan::PK_Encryptor_EME enc(rsa_pub, rng, "OAEP(SHA-256)");
        result.ciphertext = enc.encrypt(ss, rng);
        result.shared_secret.assign(ss.begin(), ss.end());

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

    } else if (cfg.kem == "X25519") {
        auto& x_priv = dynamic_cast<const Botan::X25519_PrivateKey&>(priv);
        Botan::PK_Key_Agreement ecdh(x_priv, rng, "Raw");
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

        auto& ecdh_priv = dynamic_cast<const Botan::ECDH_PrivateKey&>(priv);
        Botan::PK_Key_Agreement ecdh(ecdh_priv, rng, "Raw");
        auto ecdh_ss = ecdh.derive_key(32, ecdh_ct);

        auto& kem_priv = dynamic_cast<const Botan::ML_KEM_PrivateKey&>(*priv2);
        Botan::PK_KEM_Decryptor dec(kem_priv, rng, "Raw");
        auto kem_ss = dec.decrypt(std::span<const uint8_t>(kem_ct), 32);

        shared.insert(shared.end(), ecdh_ss.bits_of().begin(), ecdh_ss.bits_of().end());
        shared.insert(shared.end(), kem_ss.begin(), kem_ss.end());

    } else if (cfg.kem == "HYBRID-X25519-ML-KEM-768") {
        if (!priv2)
            throw std::runtime_error("Hybrid decapsulation requires secondary key");
        std::vector<uint8_t> x25519_ct(ciphertext.begin(), ciphertext.begin() + 32);
        std::vector<uint8_t> kem_ct(ciphertext.begin() + 32, ciphertext.end());

        auto& x_priv = dynamic_cast<const Botan::X25519_PrivateKey&>(priv);
        Botan::PK_Key_Agreement ecdh(x_priv, rng, "Raw");
        auto x25519_ss = ecdh.derive_key(32, x25519_ct);

        auto& kem_priv = dynamic_cast<const Botan::ML_KEM_PrivateKey&>(*priv2);
        Botan::PK_KEM_Decryptor dec(kem_priv, rng, "Raw");
        auto kem_ss = dec.decrypt(std::span<const uint8_t>(kem_ct), 32);

        shared.insert(shared.end(), x25519_ss.bits_of().begin(), x25519_ss.bits_of().end());
        shared.insert(shared.end(), kem_ss.begin(), kem_ss.end());

    } else if (is_rsa(cfg)) {
        auto& rsa_priv = dynamic_cast<const Botan::RSA_PrivateKey&>(priv);
        Botan::PK_Decryptor_EME dec(rsa_priv, rng, "OAEP(SHA-256)");
        auto ss = dec.decrypt(std::span<const uint8_t>(ciphertext));
        shared.assign(ss.begin(), ss.end());

    } else {
        throw std::invalid_argument("kem_decapsulate: unknown kem " + cfg.kem);
    }

    return shared;
}
