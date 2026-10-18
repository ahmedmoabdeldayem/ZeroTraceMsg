// Tests for protocol constants and integration of identity + crypto

#include "../common/crypto.hpp"
#include "../common/identity.hpp"
#include "../common/protocol.hpp"
#include "test_runner.hpp"
#include <botan/auto_rng.h>
#include <iostream>

int main()
{
    SUITE_INIT("test_protocol");
    std::cout << "=== protocol tests ===\n\n";
    Botan::AutoSeeded_RNG rng;
    Config cfg;

    // -------------------------------------------------------
    // Protocol constants
    // -------------------------------------------------------
    TEST("USER_ID_LEN is 16");
    ASSERT_EQ(USER_ID_LEN, (size_t)16);

    TEST("ML_KEM_PUBKEY_LEN is 1184");
    ASSERT_EQ(ML_KEM_PUBKEY_LEN, (size_t)1184);

    TEST("KEM_CIPHERTEXT_LEN is 1088");
    ASSERT_EQ(KEM_CIPHERTEXT_LEN, (size_t)1088);

    TEST("MSG_TTL_CLIENT_S is 120 seconds");
    ASSERT_EQ(MSG_TTL_CLIENT_S, 120);

    TEST("MSG_TTL_SERVER_S is 48 hours");
    ASSERT_EQ(MSG_TTL_SERVER_S, 172800);

    TEST("MAX_LINE_LEN is 1MB");
    ASSERT_EQ(MAX_LINE_LEN, (size_t)(1024 * 1024));

    // -------------------------------------------------------
    // user_id validation (what server checks on REGISTER)
    // -------------------------------------------------------
    TEST("derived user_id matches hash of pubkey");
    {
        auto id = generate_identity(rng, cfg);
        std::string recomputed = derive_user_id(id.pubkey_bytes);
        ASSERT_EQ(id.user_id, recomputed);
    }

    TEST("modified pubkey produces different user_id");
    {
        auto id = generate_identity(rng, cfg);
        auto modified = id.pubkey_bytes;
        modified[10] ^= 0xFF;
        std::string wrong_id = derive_user_id(modified);
        ASSERT_NE(id.user_id, wrong_id);
    }

    // -------------------------------------------------------
    // Full encrypt → decrypt pipeline (simulates a message exchange)
    // -------------------------------------------------------
    TEST("full pipeline: alice sends to bob, bob decrypts correctly");
    {
        auto alice = generate_identity(rng, cfg);
        auto bob = generate_identity(rng, cfg);

        std::string message = "hello bob, this is alice";
        auto blob = encrypt_message(message, alice.user_id, "alice", bob.pubkey_bytes, rng, cfg);

        auto dec = decrypt_message(blob, bob, rng, cfg);
        ASSERT_EQ(dec.plaintext, message);
        ASSERT_EQ(dec.sender_id, alice.user_id);
        ASSERT_EQ(dec.sender_name, std::string("alice"));
    }

    TEST("bob cannot decrypt message meant for carol");
    {
        auto alice = generate_identity(rng, cfg);
        auto bob = generate_identity(rng, cfg);
        auto carol = generate_identity(rng, cfg);

        auto blob = encrypt_message("secret", alice.user_id, "alice", carol.pubkey_bytes, rng, cfg);
        ASSERT_THROWS(decrypt_message(blob, bob, rng, cfg));
    }

    TEST("forward secrecy: two messages have independent ciphertexts");
    {
        auto alice = generate_identity(rng, cfg);
        auto bob = generate_identity(rng, cfg);

        auto blob1 = encrypt_message("msg1", alice.user_id, "alice", bob.pubkey_bytes, rng, cfg);
        auto blob2 = encrypt_message("msg2", alice.user_id, "alice", bob.pubkey_bytes, rng, cfg);

        // different ephemeral keys → completely different blobs
        ASSERT_NE(blob1, blob2);

        // both still decrypt correctly
        auto dec1 = decrypt_message(blob1, bob, rng, cfg);
        auto dec2 = decrypt_message(blob2, bob, rng, cfg);
        ASSERT_EQ(dec1.plaintext, std::string("msg1"));
        ASSERT_EQ(dec2.plaintext, std::string("msg2"));
    }

    TEST("unicode message round-trip");
    {
        auto alice = generate_identity(rng, cfg);
        auto bob = generate_identity(rng, cfg);
        std::string unicode = "مرحبا بالعالم 🔒";
        auto blob = encrypt_message(unicode, alice.user_id, "alice", bob.pubkey_bytes, rng, cfg);
        auto dec = decrypt_message(blob, bob, rng, cfg);
        ASSERT_EQ(dec.plaintext, unicode);
    }

    SUITE_RESULTS();
}
