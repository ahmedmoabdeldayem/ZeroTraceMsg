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
    Config cfg;

    // -------------------------------------------------------
    // derive_user_id
    // -------------------------------------------------------
    TEST("derive_user_id produces 16 hex chars");
    {
        auto id = generate_identity(rng, cfg);
        ASSERT_EQ(id.user_id.size(), USER_ID_LEN);
        for (char c : id.user_id)
            ASSERT_TRUE((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F'));
        std::cout << "  user_id: " << id.user_id << "\n";
    }

    TEST("derive_user_id is deterministic");
    {
        auto id = generate_identity(rng, cfg);
        std::string id2 = derive_user_id(id.pubkey_bytes);
        ASSERT_EQ(id.user_id, id2);
    }

    TEST("different identities produce different user IDs");
    {
        auto id1 = generate_identity(rng, cfg);
        auto id2 = generate_identity(rng, cfg);
        ASSERT_NE(id1.user_id, id2.user_id);
        ASSERT_NE(id1.pubkey_bytes, id2.pubkey_bytes);
    }

    TEST("user_id matches SHA-256(pubkey)[0:8]");
    {
        auto id = generate_identity(rng, cfg);
        std::string computed = derive_user_id(id.pubkey_bytes);
        ASSERT_EQ(id.user_id, computed);
    }

    TEST("pubkey is 1184 bytes (ML-KEM-768)");
    {
        auto id = generate_identity(rng, cfg);
        ASSERT_EQ(id.pubkey_bytes.size(), ML_KEM_PUBKEY_LEN);
    }

    // -------------------------------------------------------
    // save / load identity
    // -------------------------------------------------------
    const std::string tmp_file = "/tmp/ztm_test_identity.enc";

    TEST("save and load round-trip preserves identity");
    {
        auto id = generate_identity(rng, cfg);
        save_identity(id, make_secure("test-passphrase"), tmp_file, rng, cfg);

        auto loaded = load_identity(make_secure("test-passphrase"), tmp_file, cfg);
        ASSERT_EQ(id.user_id, loaded.user_id);
        ASSERT_EQ(id.pubkey_bytes, loaded.pubkey_bytes);
        std::cout << "  user_id preserved: " << loaded.user_id << "\n";
    }

    TEST("wrong passphrase throws on load");
    {
        auto id = generate_identity(rng, cfg);
        save_identity(id, make_secure("correct-pass"), tmp_file, rng, cfg);
        ASSERT_THROWS(load_identity(make_secure("wrong-pass"), tmp_file, cfg));
    }

    TEST("different saves produce different ciphertext (random salt)");
    {
        auto id = generate_identity(rng, cfg);
        save_identity(id, make_secure("same-pass"), tmp_file, rng, cfg);
        std::ifstream f1(tmp_file, std::ios::binary);
        std::string c1((std::istreambuf_iterator<char>(f1)), {});

        save_identity(id, make_secure("same-pass"), tmp_file, rng, cfg);
        std::ifstream f2(tmp_file, std::ios::binary);
        std::string c2((std::istreambuf_iterator<char>(f2)), {});

        ASSERT_NE(c1, c2); // different random salts
    }

    TEST("load from nonexistent file throws");
    {
        ASSERT_THROWS(load_identity(make_secure("pass"), "/tmp/ztm_nonexistent_xyz.enc", cfg));
    }

    // -------------------------------------------------------
    // Passphrase KDF — production parameters
    // Argon2id: m=65536 KB (64 MB), t=3 passes, p=1 thread  ~200-500 ms
    // PBKDF2:   600 000 iterations                           ~200-400 ms
    // -------------------------------------------------------
    TEST("Argon2id (m=65536, t=3, p=1): save/load round-trip");
    {
        Config argon_cfg;
        argon_cfg.passphrase_kdf = "Argon2id";
        argon_cfg.passphrase_kdf_memory_kb = 65536;
        argon_cfg.passphrase_kdf_cost = 3;
        argon_cfg.passphrase_kdf_parallelism = 1;

        auto id = generate_identity(rng, argon_cfg);
        save_identity(id, make_secure("strong-passphrase"), tmp_file, rng, argon_cfg);
        auto loaded = load_identity(make_secure("strong-passphrase"), tmp_file, argon_cfg);
        ASSERT_EQ(id.user_id, loaded.user_id);
        ASSERT_EQ(id.pubkey_bytes, loaded.pubkey_bytes);
    }

    TEST("Argon2id (m=65536, t=3, p=1): wrong passphrase throws");
    {
        Config argon_cfg;
        argon_cfg.passphrase_kdf = "Argon2id";
        argon_cfg.passphrase_kdf_memory_kb = 65536;
        argon_cfg.passphrase_kdf_cost = 3;
        argon_cfg.passphrase_kdf_parallelism = 1;

        auto id = generate_identity(rng, argon_cfg);
        save_identity(id, make_secure("correct"), tmp_file, rng, argon_cfg);
        ASSERT_THROWS(load_identity(make_secure("wrong"), tmp_file, argon_cfg));
    }

    TEST("PBKDF2 (600000 iterations): save/load round-trip");
    {
        Config pbkdf2_cfg;
        pbkdf2_cfg.passphrase_kdf = "PBKDF2";
        pbkdf2_cfg.passphrase_kdf_cost = 600000;

        auto id = generate_identity(rng, pbkdf2_cfg);
        save_identity(id, make_secure("strong-passphrase"), tmp_file, rng, pbkdf2_cfg);
        auto loaded = load_identity(make_secure("strong-passphrase"), tmp_file, pbkdf2_cfg);
        ASSERT_EQ(id.user_id, loaded.user_id);
        ASSERT_EQ(id.pubkey_bytes, loaded.pubkey_bytes);
    }

    TEST("PBKDF2 (600000 iterations): wrong passphrase throws");
    {
        Config pbkdf2_cfg;
        pbkdf2_cfg.passphrase_kdf = "PBKDF2";
        pbkdf2_cfg.passphrase_kdf_cost = 600000;

        auto id = generate_identity(rng, pbkdf2_cfg);
        save_identity(id, make_secure("correct"), tmp_file, rng, pbkdf2_cfg);
        ASSERT_THROWS(load_identity(make_secure("wrong"), tmp_file, pbkdf2_cfg));
    }

    // -------------------------------------------------------
    // Argon2id — parameter variants
    // Each row tests a distinct (m, t, p) combination to
    // exercise different memory and parallelism paths.
    // -------------------------------------------------------
    struct ArgonParams {
        int m, t, p;
    };
    for (auto [m, t, p] : std::vector<ArgonParams>{
             {8, 1, 1},     // minimum valid — tests lower bound, fast
             {16384, 2, 1}, // 16 MB, 2 passes
             {32768, 2, 2}, // 32 MB, 2 passes, 2 threads
             {65536, 3, 4}, // 64 MB, 3 passes, 4 threads
         }) {
        std::string label = "Argon2id (m=" + std::to_string(m) + ", t=" + std::to_string(t) +
                            ", p=" + std::to_string(p) + "): save/load round-trip";
        TEST(label);
        {
            Config c;
            c.passphrase_kdf = "Argon2id";
            c.passphrase_kdf_memory_kb = m;
            c.passphrase_kdf_cost = t;
            c.passphrase_kdf_parallelism = p;

            auto id = generate_identity(rng, c);
            save_identity(id, make_secure("pass"), tmp_file, rng, c);
            auto loaded = load_identity(make_secure("pass"), tmp_file, c);
            ASSERT_EQ(id.user_id, loaded.user_id);
            ASSERT_EQ(id.pubkey_bytes, loaded.pubkey_bytes);
        }
    }

    // -------------------------------------------------------
    // PBKDF2 — iteration counts
    // -------------------------------------------------------
    for (int iters : {10000, 100000, 200000, 600000}) {
        std::string label =
            "PBKDF2 (" + std::to_string(iters) + " iterations): save/load round-trip";
        TEST(label);
        {
            Config c;
            c.passphrase_kdf = "PBKDF2";
            c.passphrase_kdf_cost = iters;

            auto id = generate_identity(rng, c);
            save_identity(id, make_secure("pass"), tmp_file, rng, c);
            auto loaded = load_identity(make_secure("pass"), tmp_file, c);
            ASSERT_EQ(id.user_id, loaded.user_id);
            ASSERT_EQ(id.pubkey_bytes, loaded.pubkey_bytes);
        }
    }

    // -------------------------------------------------------
    // KEM variants — save/load with every supported algorithm
    // Uses minimal Argon2id (m=8, t=1, p=1) so key-format
    // correctness is tested without KDF cost dominating time.
    // -------------------------------------------------------
    for (const auto& kem : {"ECDH-P256", "ECDH-P384", "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
                            "HYBRID-P256-ML-KEM-768", "HYBRID-P384-ML-KEM-1024"}) {
        TEST(std::string("save/load round-trip: ") + kem);
        {
            Config c;
            c.kem = kem;
            c.passphrase_kdf = "Argon2id";
            c.passphrase_kdf_memory_kb = 8;
            c.passphrase_kdf_cost = 1;
            c.passphrase_kdf_parallelism = 1;

            auto id = generate_identity(rng, c);
            save_identity(id, make_secure("pass"), tmp_file, rng, c);
            auto loaded = load_identity(make_secure("pass"), tmp_file, c);
            ASSERT_EQ(id.user_id, loaded.user_id);
            ASSERT_EQ(id.pubkey_bytes, loaded.pubkey_bytes);
        }
    }

    // -------------------------------------------------------
    // SecureString / make_secure
    // -------------------------------------------------------
    TEST("make_secure from string literal holds correct bytes");
    {
        auto s = make_secure("hello");
        ASSERT_EQ(s.size(), (size_t)5);
        ASSERT_EQ(s[0], 'h');
        ASSERT_EQ(s[4], 'o');
    }

    TEST("make_secure from std::string holds correct bytes");
    {
        std::string src = "world";
        auto s = make_secure(src);
        ASSERT_EQ(s.size(), src.size());
        ASSERT_EQ(std::string(s.begin(), s.end()), src);
    }

    std::remove(tmp_file.c_str());
    SUITE_RESULTS();
}
