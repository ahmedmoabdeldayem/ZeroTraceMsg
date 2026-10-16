// Tests for common/identity — key generation, derivation, save/load

#include "../common/identity.hpp"
#include "../common/protocol.hpp"
#include "test_runner.hpp"
#include <botan/auto_rng.h>
#include <botan/hex.h>
#include <cstdio>
#include <fstream>
#include <iostream>

int main()
{
    SUITE_INIT("test_identity");
    std::cout << "=== identity tests ===\n\n";
    Botan::AutoSeeded_RNG rng;

    // -------------------------------------------------------
    // derive_user_id
    // -------------------------------------------------------
    TEST("derive_user_id produces 16 hex chars");
    {
        auto id = generate_identity(rng);
        ASSERT_EQ(id.user_id.size(), USER_ID_LEN);
        for (char c : id.user_id)
            ASSERT_TRUE((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F'));
        std::cout << "  user_id: " << id.user_id << "\n";
    }

    TEST("derive_user_id is deterministic");
    {
        auto id = generate_identity(rng);
        std::string id2 = derive_user_id(id.pubkey_bytes);
        ASSERT_EQ(id.user_id, id2);
    }

    TEST("different identities produce different user IDs");
    {
        auto id1 = generate_identity(rng);
        auto id2 = generate_identity(rng);
        ASSERT_NE(id1.user_id, id2.user_id);
        ASSERT_NE(id1.pubkey_bytes, id2.pubkey_bytes);
    }

    TEST("user_id matches SHA-256(pubkey)[0:8]");
    {
        auto id = generate_identity(rng);
        std::string computed = derive_user_id(id.pubkey_bytes);
        ASSERT_EQ(id.user_id, computed);
    }

    TEST("pubkey is 65 bytes (uncompressed P-256)");
    {
        auto id = generate_identity(rng);
        ASSERT_EQ(id.pubkey_bytes.size(), PUBKEY_LEN);
        ASSERT_EQ(id.pubkey_bytes[0], 0x04); // uncompressed point prefix
    }

    // -------------------------------------------------------
    // save / load identity
    // -------------------------------------------------------
    const std::string tmp_file = "/tmp/ztm_test_identity.enc";

    TEST("save and load round-trip preserves identity");
    {
        auto id = generate_identity(rng);
        save_identity(id, "test-passphrase", tmp_file, rng);

        auto loaded = load_identity("test-passphrase", tmp_file);
        ASSERT_EQ(id.user_id, loaded.user_id);
        ASSERT_EQ(id.pubkey_bytes, loaded.pubkey_bytes);
        std::cout << "  user_id preserved: " << loaded.user_id << "\n";
    }

    TEST("wrong passphrase throws on load");
    {
        auto id = generate_identity(rng);
        save_identity(id, "correct-pass", tmp_file, rng);
        ASSERT_THROWS(load_identity("wrong-pass", tmp_file));
    }

    TEST("different saves produce different ciphertext (random salt)");
    {
        auto id = generate_identity(rng);
        save_identity(id, "same-pass", tmp_file, rng);
        std::ifstream f1(tmp_file, std::ios::binary);
        std::string c1((std::istreambuf_iterator<char>(f1)), {});

        save_identity(id, "same-pass", tmp_file, rng);
        std::ifstream f2(tmp_file, std::ios::binary);
        std::string c2((std::istreambuf_iterator<char>(f2)), {});

        ASSERT_NE(c1, c2); // different random salts
    }

    TEST("load from nonexistent file throws");
    {
        ASSERT_THROWS(load_identity("pass", "/tmp/ztm_nonexistent_xyz.enc"));
    }

    std::remove(tmp_file.c_str());
    SUITE_RESULTS();
}
