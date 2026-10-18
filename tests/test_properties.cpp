// Property-based tests — security invariants that must hold for all valid inputs.
//
// Unlike unit tests that check specific fixed values, property tests generate
// many random inputs and assert that invariants never break.  Each failure
// points to a security regression, not just a wrong number.

#include "../common/config.hpp"
#include "../common/crypto.hpp"
#include "../common/identity.hpp"
#include "../common/replay.hpp"
#include "test_runner.hpp"
#include <botan/auto_rng.h>
#include <iostream>
#include <set>
#include <thread>
#include <vector>

static Botan::AutoSeeded_RNG rng;
static Config cfg;

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

// Random printable string of length n.
static std::string rand_string(size_t n)
{
    auto bytes = rng.random_vec(n);
    std::string s;
    s.reserve(n);
    for (auto b : bytes)
        s += static_cast<char>('A' + (b % 26));
    return s;
}

// ─────────────────────────────────────────────────────────────────────────────
int main()
{
    SUITE_INIT("test_properties");
    std::cout << "=== property tests ===\n\n";

    auto alice = generate_identity(rng, cfg);
    auto bob = generate_identity(rng, cfg);

    // =========================================================================
    // Encryption properties
    // =========================================================================

    TEST("P1: encrypt→decrypt is correct for every valid message length (0 to max)");
    {
        // overhead = nonce(16) + user_id(16) + name_len(1) + msg_len(2) + name bytes
        const std::string sender_name = "a";
        constexpr size_t fixed_overhead = 16 + 16 + 1 + 2;
        size_t max_msg = cfg.padded_plaintext_bytes() - fixed_overhead - sender_name.size();

        // Sample 50 lengths spread across the full range (0, 1, mid, max-1, max)
        std::vector<size_t> lengths = {0, 1, 2, max_msg / 4, max_msg / 2, max_msg - 1, max_msg};
        for (size_t i = 3; i < 45; ++i)
            lengths.push_back(i * max_msg / 50);

        for (size_t len : lengths) {
            std::string msg = rand_string(len);
            auto blob =
                encrypt_message(msg, alice.user_id, sender_name, bob.pubkey_bytes, rng, cfg);
            auto dec = decrypt_message(blob, bob, rng, cfg);
            ASSERT_EQ(dec.plaintext, msg);
            ASSERT_EQ(dec.sender_id, alice.user_id);
        }
    }

    TEST("P2: encrypt always produces a different ciphertext (ephemeral keys)");
    {
        // Encrypt the same message 20 times — every blob must be distinct.
        std::string msg = "same message every time";
        std::set<std::vector<uint8_t>> seen;
        for (int i = 0; i < 20; ++i) {
            auto blob = encrypt_message(msg, alice.user_id, "a", bob.pubkey_bytes, rng, cfg);
            ASSERT_TRUE(seen.insert(blob).second); // insertion fails if duplicate
        }
    }

    TEST("P3: blob size is always exactly max_blob_len regardless of message length");
    {
        for (size_t len : {(size_t)0, (size_t)1, (size_t)100, (size_t)1000}) {
            auto blob =
                encrypt_message(rand_string(len), alice.user_id, "a", bob.pubkey_bytes, rng, cfg);
            ASSERT_EQ(blob.size(), cfg.max_blob_len());
        }
    }

    TEST("P4: flipping any single byte in the blob causes authentication failure");
    {
        auto blob = encrypt_message("secret", alice.user_id, "a", bob.pubkey_bytes, rng, cfg);
        // Sample 50 positions spread across the blob
        size_t step = std::max((size_t)1, blob.size() / 50);
        for (size_t pos = 0; pos < blob.size(); pos += step) {
            auto tampered = blob;
            tampered[pos] ^= 0xFF;
            bool threw = false;
            try {
                decrypt_message(tampered, bob, rng, cfg);
            } catch (...) {
                threw = true;
            }
            ASSERT_TRUE(threw);
        }
    }

    TEST("P5: wrong recipient always fails decryption");
    {
        for (int i = 0; i < 10; ++i) {
            auto impostor = generate_identity(rng, cfg);
            auto blob = encrypt_message("secret", alice.user_id, "a", bob.pubkey_bytes, rng, cfg);
            ASSERT_THROWS(decrypt_message(blob, impostor, rng, cfg));
        }
    }

    TEST("P6: sender_id is sealed — never appears as raw bytes in the blob");
    {
        for (int i = 0; i < 10; ++i) {
            auto blob = encrypt_message("hello", alice.user_id, "a", bob.pubkey_bytes, rng, cfg);
            // user_id is a 16-char hex string; search for it as raw bytes
            std::string blob_str(blob.begin(), blob.end());
            ASSERT_EQ(blob_str.find(alice.user_id), std::string::npos);
        }
    }

    // =========================================================================
    // Identity properties
    // =========================================================================

    TEST("P7: every generate_identity call produces a unique user_id");
    {
        std::set<std::string> ids;
        for (int i = 0; i < 20; ++i) {
            auto id = generate_identity(rng, cfg);
            ASSERT_TRUE(ids.insert(id.user_id).second);
        }
    }

    TEST("P8: save→load round-trip preserves identity for 5 random passphrases");
    {
        const std::string path = "/tmp/ztm_prop_id.enc";
        for (int i = 0; i < 5; ++i) {
            // Use fast KDF params so the test doesn't take forever
            Config fast_cfg;
            fast_cfg.passphrase_kdf = "Argon2id";
            fast_cfg.passphrase_kdf_memory_kb = 8;
            fast_cfg.passphrase_kdf_cost = 1;
            fast_cfg.passphrase_kdf_parallelism = 1;

            auto pass = make_secure(rand_string(16));
            auto id = generate_identity(rng, fast_cfg);
            save_identity(id, pass, path, rng, fast_cfg);
            auto loaded = load_identity(pass, path, fast_cfg);
            ASSERT_EQ(id.user_id, loaded.user_id);
            ASSERT_EQ(id.pubkey_bytes, loaded.pubkey_bytes);
        }
        std::remove("/tmp/ztm_prop_id.enc");
    }

    TEST("P9: wrong passphrase always throws, correct passphrase always succeeds");
    {
        const std::string path = "/tmp/ztm_prop_pass.enc";
        Config fast_cfg;
        fast_cfg.passphrase_kdf = "Argon2id";
        fast_cfg.passphrase_kdf_memory_kb = 8;
        fast_cfg.passphrase_kdf_cost = 1;
        fast_cfg.passphrase_kdf_parallelism = 1;

        auto id = generate_identity(rng, fast_cfg);
        for (int i = 0; i < 5; ++i) {
            auto correct = make_secure(rand_string(12));
            auto wrong = make_secure(rand_string(12));
            save_identity(id, correct, path, rng, fast_cfg);
            ASSERT_NO_THROW(load_identity(correct, path, fast_cfg));
            ASSERT_THROWS(load_identity(wrong, path, fast_cfg));
        }
        std::remove("/tmp/ztm_prop_pass.enc");
    }

    // =========================================================================
    // Replay guard properties
    // =========================================================================

    TEST("P10: 1000 distinct nonces are all accepted by ReplayGuard");
    {
        ReplayGuard guard;
        for (int i = 0; i < 1000; ++i) {
            // Encode i into the nonce so every one is unique
            std::vector<uint8_t> nonce(16, 0);
            nonce[0] = static_cast<uint8_t>(i >> 8);
            nonce[1] = static_cast<uint8_t>(i & 0xFF);
            nonce[2] = 0xAB; // distinguish from all-zero nonces
            ASSERT_TRUE(guard.check_and_insert(nonce));
        }
    }

    TEST("P11: every seen nonce is rejected on replay");
    {
        ReplayGuard guard;
        std::vector<std::vector<uint8_t>> seen;
        for (int i = 0; i < 50; ++i) {
            std::vector<uint8_t> nonce(16, 0);
            nonce[0] = static_cast<uint8_t>(i);
            nonce[2] = 0xCD;
            guard.check_and_insert(nonce);
            seen.push_back(nonce);
        }
        for (const auto& n : seen)
            ASSERT_TRUE(!guard.check_and_insert(n));
    }

    TEST("P12: replayed real message nonces are always rejected");
    {
        ReplayGuard guard;
        auto blob = encrypt_message("hi", alice.user_id, "a", bob.pubkey_bytes, rng, cfg);
        auto dec = decrypt_message(blob, bob, rng, cfg);
        ASSERT_TRUE(guard.check_and_insert(dec.msg_nonce));
        // Same blob decrypted again → same nonce → must be rejected
        auto dec2 = decrypt_message(blob, bob, rng, cfg);
        ASSERT_TRUE(!guard.check_and_insert(dec2.msg_nonce));
    }

    // =========================================================================
    // Config validation properties
    // =========================================================================

    TEST("P13: Config{} default is always valid");
    {
        for (int i = 0; i < 10; ++i)
            ASSERT_NO_THROW(Config{}.validate());
    }

    TEST("P14: every out-of-range port value fails validation");
    {
        for (int port : {0, -1, 65536, 65537, 99999, -100}) {
            Config c;
            c.server_port = port;
            ASSERT_THROWS(c.validate());
        }
    }

    TEST("P15: every unknown KEM value fails validation");
    {
        for (const auto& k : {"", "DES", "RSA-1024", "ECDH-P521", "ML-KEM-256"}) {
            Config c;
            c.kem = k;
            ASSERT_THROWS(c.validate());
        }
    }

    // =========================================================================
    // Concurrency / stress property
    // =========================================================================

    TEST("P16: ReplayGuard is safe under concurrent inserts (no lost accepts, no double-accepts)");
    {
        // 4 threads each inserting 250 unique nonces = exactly 1000 accepted
        ReplayGuard guard;
        std::atomic<int> accepted{0};

        auto worker = [&](int start) {
            for (int i = start; i < start + 250; ++i) {
                std::vector<uint8_t> nonce(16, 0);
                nonce[0] = static_cast<uint8_t>(i >> 8);
                nonce[1] = static_cast<uint8_t>(i & 0xFF);
                nonce[2] = 0xEF;
                if (guard.check_and_insert(nonce))
                    accepted++;
            }
        };

        std::thread t1(worker, 0);
        std::thread t2(worker, 250);
        std::thread t3(worker, 500);
        std::thread t4(worker, 750);
        t1.join();
        t2.join();
        t3.join();
        t4.join();

        ASSERT_EQ(accepted.load(), 1000);
    }

    SUITE_RESULTS();
}
