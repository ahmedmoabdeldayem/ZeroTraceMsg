// Tests for common/replay.hpp — ReplayGuard nonce deduplication

#include "../common/crypto.hpp"
#include "../common/identity.hpp"
#include "../common/protocol.hpp"
#include "../common/replay.hpp"
#include "test_runner.hpp"
#include <atomic>
#include <botan/auto_rng.h>
#include <iostream>
#include <thread>

int main()
{
    SUITE_INIT("test_replay");
    std::cout << "=== replay tests ===\n\n";
    Botan::AutoSeeded_RNG rng;
    Config cfg;

    // -------------------------------------------------------
    // ReplayGuard unit tests
    // -------------------------------------------------------
    TEST("new nonce is accepted");
    {
        ReplayGuard guard;
        std::vector<uint8_t> nonce(16, 0xAB);
        ASSERT_TRUE(guard.check_and_insert(nonce));
    }

    TEST("same nonce rejected on second check");
    {
        ReplayGuard guard;
        std::vector<uint8_t> nonce(16, 0x42);
        ASSERT_TRUE(guard.check_and_insert(nonce));
        ASSERT_TRUE(!guard.check_and_insert(nonce));
    }

    TEST("different nonces are all accepted");
    {
        ReplayGuard guard;
        for (int i = 0; i < 100; i++) {
            std::vector<uint8_t> nonce(16, static_cast<uint8_t>(i));
            ASSERT_TRUE(guard.check_and_insert(nonce));
        }
    }

    TEST("nonces that differ in one byte are treated as distinct");
    {
        ReplayGuard guard;
        std::vector<uint8_t> a(16, 0x00);
        std::vector<uint8_t> b(16, 0x00);
        b[7] = 0x01;
        ASSERT_TRUE(guard.check_and_insert(a));
        ASSERT_TRUE(guard.check_and_insert(b));
    }

    TEST("zero nonce is accepted");
    {
        ReplayGuard guard;
        std::vector<uint8_t> nonce(16, 0x00);
        ASSERT_TRUE(guard.check_and_insert(nonce));
    }

    TEST("independent guards don't share state");
    {
        ReplayGuard g1, g2;
        std::vector<uint8_t> nonce(16, 0xCC);
        ASSERT_TRUE(g1.check_and_insert(nonce));
        ASSERT_TRUE(!g1.check_and_insert(nonce));
        ASSERT_TRUE(g2.check_and_insert(nonce)); // g2 has never seen it
    }

    // -------------------------------------------------------
    // End-to-end: encrypt → decrypt → replay check
    // -------------------------------------------------------
    TEST("first decryption of a blob is accepted by ReplayGuard");
    {
        ReplayGuard guard;
        auto alice = generate_identity(rng, cfg);
        auto bob = generate_identity(rng, cfg);

        auto blob =
            encrypt_message("hello", alice.user_id, "alice", bob.pubkey_bytes, rng, cfg);
        auto dec = decrypt_message(blob, bob, rng, cfg);
        ASSERT_TRUE(guard.check_and_insert(dec.msg_nonce));
    }

    TEST("replaying the same blob is rejected by ReplayGuard");
    {
        ReplayGuard guard;
        auto alice = generate_identity(rng, cfg);
        auto bob = generate_identity(rng, cfg);

        auto blob =
            encrypt_message("hello", alice.user_id, "alice", bob.pubkey_bytes, rng, cfg);

        // first delivery — accepted
        auto dec1 = decrypt_message(blob, bob, rng, cfg);
        ASSERT_TRUE(guard.check_and_insert(dec1.msg_nonce));

        // replay — same blob, same nonce → rejected
        auto dec2 = decrypt_message(blob, bob, rng, cfg);
        ASSERT_TRUE(!guard.check_and_insert(dec2.msg_nonce));
    }

    TEST("two distinct messages both accepted");
    {
        ReplayGuard guard;
        auto alice = generate_identity(rng, cfg);
        auto bob = generate_identity(rng, cfg);

        auto blob1 =
            encrypt_message("msg1", alice.user_id, "alice", bob.pubkey_bytes, rng, cfg);
        auto blob2 =
            encrypt_message("msg2", alice.user_id, "alice", bob.pubkey_bytes, rng, cfg);

        auto dec1 = decrypt_message(blob1, bob, rng, cfg);
        auto dec2 = decrypt_message(blob2, bob, rng, cfg);

        ASSERT_TRUE(guard.check_and_insert(dec1.msg_nonce));
        ASSERT_TRUE(guard.check_and_insert(dec2.msg_nonce));
    }

    // -------------------------------------------------------
    // Thread safety
    // -------------------------------------------------------
    TEST("concurrent inserts of distinct nonces all succeed");
    {
        ReplayGuard guard;
        std::atomic<int> accepted{0};

        auto worker = [&](int start) {
            for (int i = start; i < start + 50; i++) {
                std::vector<uint8_t> nonce(16, 0);
                // encode i into the nonce so each is unique
                nonce[0] = static_cast<uint8_t>(i >> 8);
                nonce[1] = static_cast<uint8_t>(i & 0xFF);
                if (guard.check_and_insert(nonce))
                    accepted++;
            }
        };

        std::thread t1(worker, 0);
        std::thread t2(worker, 50);
        t1.join();
        t2.join();
        ASSERT_EQ(accepted.load(), 100);
    }

    TEST("concurrent inserts of the same nonce — exactly one accepted");
    {
        ReplayGuard guard;
        std::vector<uint8_t> nonce(16, 0x77);
        std::atomic<int> accepted{0};

        auto worker = [&]() {
            for (int i = 0; i < 50; i++)
                if (guard.check_and_insert(nonce))
                    accepted++;
        };

        std::thread t1(worker);
        std::thread t2(worker);
        t1.join();
        t2.join();
        ASSERT_EQ(accepted.load(), 1);
    }

    SUITE_RESULTS();
}
