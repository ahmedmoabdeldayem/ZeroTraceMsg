#include "identity.hpp"
#include <botan/hash.h>
#include <botan/hex.h>
#include <botan/aead.h>
#include <botan/pwdhash.h>
#include <fstream>
#include <stdexcept>
#include <span>

static Botan::EC_Group p256() {
    return Botan::EC_Group::from_name("secp256r1");
}

std::string derive_user_id(const std::vector<uint8_t>& pubkey_bytes) {
    auto sha256 = Botan::HashFunction::create_or_throw("SHA-256");
    sha256->update(pubkey_bytes);
    auto digest = sha256->final();
    return Botan::hex_encode(digest.data(), 8);  // 8 bytes = 16 hex chars
}

Identity generate_identity(Botan::AutoSeeded_RNG& rng) {
    Identity id;
    id.priv_key = std::make_unique<Botan::ECDH_PrivateKey>(rng, p256());
    id.pubkey_bytes = id.priv_key->raw_public_key_bits();
    id.user_id = derive_user_id(id.pubkey_bytes);
    return id;
}

// derive AES-256 key from passphrase + salt using PBKDF2
static Botan::secure_vector<uint8_t> kdf_from_passphrase(
    const std::string& passphrase, std::span<const uint8_t> salt)
{
    auto pbkdf  = Botan::PasswordHashFamily::create_or_throw("PBKDF2(SHA-256)");
    auto pwhash = pbkdf->from_iterations(200000);
    Botan::secure_vector<uint8_t> key(32);
    pwhash->derive_key(key.data(), key.size(),
                       passphrase.data(), passphrase.size(),
                       salt.data(), salt.size());
    return key;
}

void save_identity(const Identity& id, const std::string& passphrase,
                   const std::string& path, Botan::AutoSeeded_RNG& rng)
{
    // rng.random_vec returns secure_vector — wiped on destruction
    auto salt  = rng.random_vec(16);
    auto nonce = rng.random_vec(12);
    auto aes_key = kdf_from_passphrase(passphrase, std::span<const uint8_t>(salt.data(), salt.size()));

    auto raw_priv = id.priv_key->raw_private_key_bits();

    auto enc = Botan::AEAD_Mode::create_or_throw("AES-256/GCM", Botan::Cipher_Dir::Encryption);
    enc->set_key(aes_key);
    enc->start(nonce);
    Botan::secure_vector<uint8_t> buf(raw_priv.begin(), raw_priv.end());
    enc->finish(buf);

    std::ofstream out(path, std::ios::binary);
    if(!out) throw std::runtime_error("Cannot write identity file: " + path);
    out.write(reinterpret_cast<const char*>(salt.data()),  salt.size());
    out.write(reinterpret_cast<const char*>(nonce.data()), nonce.size());
    out.write(reinterpret_cast<const char*>(buf.data()),   buf.size());
}

Identity load_identity(const std::string& passphrase, const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if(!in) throw std::runtime_error("Identity file not found: " + path);

    // use secure_vector so salt and nonce are wiped from memory on destruction
    Botan::secure_vector<uint8_t> salt(16), nonce(12);
    in.read(reinterpret_cast<char*>(salt.data()),  16);
    in.read(reinterpret_cast<char*>(nonce.data()), 12);

    // read ciphertext into secure memory
    std::vector<char> raw(std::istreambuf_iterator<char>(in), {});
    Botan::secure_vector<uint8_t> ciphertext(raw.begin(), raw.end());

    auto aes_key = kdf_from_passphrase(passphrase, std::span<const uint8_t>(salt.data(), salt.size()));

    auto dec = Botan::AEAD_Mode::create_or_throw("AES-256/GCM", Botan::Cipher_Dir::Decryption);
    dec->set_key(aes_key);
    dec->start(nonce);
    dec->finish(ciphertext);  // throws Botan::Invalid_Authentication_Tag on wrong passphrase

    Identity id;
    auto scalar_opt = Botan::EC_Scalar::deserialize(p256(), std::span<const uint8_t>(ciphertext.data(), ciphertext.size()));
    if(!scalar_opt) throw std::runtime_error("Invalid private key in identity file");
    id.priv_key = std::make_unique<Botan::ECDH_PrivateKey>(p256(), *scalar_opt);
    id.pubkey_bytes = id.priv_key->raw_public_key_bits();
    id.user_id = derive_user_id(id.pubkey_bytes);
    return id;
}
