// Tests for common/crypto — encrypt/decrypt, tamper detection, payload parsing

#include "../common/crypto.hpp"
#include "../common/identity.hpp"
#include "../common/protocol.hpp"
#include "test_runner.hpp"
#include <botan/auto_rng.h>
#include <iostream>

int main()
{
    SUITE_INIT("test_crypto");
    std::cout << "=== crypto tests ===\n\n";
    Botan::AutoSeeded_RNG rng;

    auto recipient = generate_identity(rng);
    auto sender = generate_identity(rng);

    // -------------------------------------------------------
    // Basic round-trip
    // -------------------------------------------------------
    TEST("encrypt/decrypt round-trip");
    {
        auto blob =
            encrypt_message("hello world", sender.user_id, "alice", recipient.pubkey_bytes, rng);
        auto dec = decrypt_message(blob, *recipient.priv_key, rng);
        ASSERT_EQ(dec.plaintext, std::string("hello world"));
        ASSERT_EQ(dec.sender_id, sender.user_id);
        ASSERT_EQ(dec.sender_name, std::string("alice"));
    }

    TEST("message with embedded newlines round-trips correctly");
    {
        std::string multiline = "line one\nline two\nline three";
        auto blob =
            encrypt_message(multiline, sender.user_id, "alice", recipient.pubkey_bytes, rng);
        auto dec = decrypt_message(blob, *recipient.priv_key, rng);
        ASSERT_EQ(dec.plaintext, multiline);
    }

    TEST("empty message round-trip");
    {
        auto blob = encrypt_message("", sender.user_id, "alice", recipient.pubkey_bytes, rng);
        auto dec = decrypt_message(blob, *recipient.priv_key, rng);
        ASSERT_EQ(dec.plaintext, std::string(""));
    }

    TEST("empty sender_name round-trip");
    {
        auto blob = encrypt_message("hello", sender.user_id, "", recipient.pubkey_bytes, rng);
        auto dec = decrypt_message(blob, *recipient.priv_key, rng);
        ASSERT_EQ(dec.sender_name, std::string(""));
        ASSERT_EQ(dec.plaintext, std::string("hello"));
    }

    TEST("long message round-trip");
    {
        std::string long_msg(4000, 'x');
        auto blob = encrypt_message(long_msg, sender.user_id, "alice", recipient.pubkey_bytes, rng);
        auto dec = decrypt_message(blob, *recipient.priv_key, rng);
        ASSERT_EQ(dec.plaintext, long_msg);
    }

    TEST("sender_name truncated at 255 chars");
    {
        std::string long_name(300, 'a');
        auto blob = encrypt_message("msg", sender.user_id, long_name, recipient.pubkey_bytes, rng);
        auto dec = decrypt_message(blob, *recipient.priv_key, rng);
        ASSERT_EQ(dec.sender_name.size(), (size_t)255);
    }

    // -------------------------------------------------------
    // Blob structure
    // -------------------------------------------------------
    TEST("blob is MAX_BLOB_LEN bytes and starts with KEM ciphertext");
    {
        auto blob = encrypt_message("test", sender.user_id, "alice", recipient.pubkey_bytes, rng);
        ASSERT_EQ(blob.size(),
                  MAX_BLOB_LEN); // KEM_CIPHERTEXT_LEN + PADDED_PLAINTEXT_LEN + GCM_TAG_LEN
    }

    TEST("same plaintext produces different ciphertext each time (ephemeral key)");
    {
        auto blob1 = encrypt_message("hello", sender.user_id, "alice", recipient.pubkey_bytes, rng);
        auto blob2 = encrypt_message("hello", sender.user_id, "alice", recipient.pubkey_bytes, rng);
        ASSERT_NE(blob1, blob2);
    }

    TEST("blob too short throws on decrypt");
    {
        std::vector<uint8_t> short_blob(10, 0x00);
        ASSERT_THROWS(decrypt_message(short_blob, *recipient.priv_key, rng));
    }

    // -------------------------------------------------------
    // Tamper detection
    // -------------------------------------------------------
    TEST("flipping a byte in ciphertext throws on decrypt");
    {
        auto blob = encrypt_message("secret", sender.user_id, "alice", recipient.pubkey_bytes, rng);
        blob[70] ^= 0xFF; // flip byte in ciphertext (past 65-byte pubkey)
        ASSERT_THROWS(decrypt_message(blob, *recipient.priv_key, rng));
    }

    TEST("flipping GCM tag throws on decrypt");
    {
        auto blob = encrypt_message("secret", sender.user_id, "alice", recipient.pubkey_bytes, rng);
        blob[blob.size() - 1] ^= 0xFF; // flip last byte (GCM tag)
        ASSERT_THROWS(decrypt_message(blob, *recipient.priv_key, rng));
    }

    TEST("wrong recipient key throws on decrypt");
    {
        auto blob = encrypt_message("secret", sender.user_id, "alice", recipient.pubkey_bytes, rng);
        auto wrong_recipient = generate_identity(rng);
        ASSERT_THROWS(decrypt_message(blob, *wrong_recipient.priv_key, rng));
    }

    // -------------------------------------------------------
    // Replay nonce
    // -------------------------------------------------------
    TEST("decrypted message contains a 16-byte msg_nonce");
    {
        auto blob = encrypt_message("hello", sender.user_id, "alice", recipient.pubkey_bytes, rng);
        auto dec = decrypt_message(blob, *recipient.priv_key, rng);
        ASSERT_EQ(dec.msg_nonce.size(), (size_t)MSG_NONCE_LEN);
    }

    TEST("two messages have different nonces");
    {
        auto blob1 = encrypt_message("hello", sender.user_id, "alice", recipient.pubkey_bytes, rng);
        auto blob2 = encrypt_message("hello", sender.user_id, "alice", recipient.pubkey_bytes, rng);
        auto dec1 = decrypt_message(blob1, *recipient.priv_key, rng);
        auto dec2 = decrypt_message(blob2, *recipient.priv_key, rng);
        ASSERT_NE(dec1.msg_nonce, dec2.msg_nonce);
    }

    // -------------------------------------------------------
    // Sealed sender
    // -------------------------------------------------------
    TEST("sender_id in decrypted message matches actual sender");
    {
        auto blob = encrypt_message("hello", sender.user_id, "alice", recipient.pubkey_bytes, rng);
        auto dec = decrypt_message(blob, *recipient.priv_key, rng);
        ASSERT_EQ(dec.sender_id, sender.user_id);
    }

    TEST("sender_id is not visible in blob plaintext scan");
    {
        auto blob = encrypt_message("hello", sender.user_id, "alice", recipient.pubkey_bytes, rng);
        // sender_id should not appear as raw bytes in the blob
        std::string blob_str(blob.begin(), blob.end());
        ASSERT_EQ(blob_str.find(sender.user_id), std::string::npos);
    }

    TEST("encrypt_message with garbage pubkey throws");
    {
        std::vector<uint8_t> bad_key(65, 0xFF);
        ASSERT_THROWS(encrypt_message("hello", sender.user_id, "alice", bad_key, rng));
    }

    // -------------------------------------------------------
    // Padding
    // -------------------------------------------------------
    TEST("blob is always MAX_BLOB_LEN bytes regardless of message length");
    {
        auto b1 = encrypt_message("hi", sender.user_id, "alice", recipient.pubkey_bytes, rng);
        auto b2 = encrypt_message(std::string(3000, 'x'), sender.user_id, "alice",
                                  recipient.pubkey_bytes, rng);
        ASSERT_EQ(b1.size(), MAX_BLOB_LEN);
        ASSERT_EQ(b2.size(), MAX_BLOB_LEN);
    }

    TEST("message at max content length encrypts and decrypts correctly");
    {
        // Fixed overhead in payload: nonce(16) + sender_id(16) + name_len(1) + msg_len(2) = 35
        // Max content = PADDED_PLAINTEXT_LEN - 35 (with empty name)
        constexpr size_t max_text = PADDED_PLAINTEXT_LEN - MSG_NONCE_LEN - USER_ID_LEN - 1 - 2;
        std::string big(max_text, 'Z');
        auto blob = encrypt_message(big, sender.user_id, "", recipient.pubkey_bytes, rng);
        auto dec = decrypt_message(blob, *recipient.priv_key, rng);
        ASSERT_EQ(dec.plaintext, big);
    }

    TEST("message one byte over max throws");
    {
        constexpr size_t max_text = PADDED_PLAINTEXT_LEN - MSG_NONCE_LEN - USER_ID_LEN - 1 - 2;
        std::string too_big(max_text + 1, 'Z');
        ASSERT_THROWS(encrypt_message(too_big, sender.user_id, "", recipient.pubkey_bytes, rng));
    }

    TEST("decrypt_message with wrong blob size throws");
    {
        std::vector<uint8_t> wrong_size(MAX_BLOB_LEN - 1, 0x00);
        ASSERT_THROWS(decrypt_message(wrong_size, *recipient.priv_key, rng));
    }

    SUITE_RESULTS();
}
