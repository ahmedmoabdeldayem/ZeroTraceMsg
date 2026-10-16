// Tests for the server protocol — REGISTER, GETKEY, SEND, POLL
// Starts a real server thread on TEST_PORT and connects via TCP.

#include "../common/crypto.hpp"
#include "../common/identity.hpp"
#include "../common/protocol.hpp"
#include "../server/server.hpp"
#include "test_runner.hpp"
#include <arpa/inet.h>
#include <botan/auto_rng.h>
#include <botan/hex.h>
#include <chrono>
#include <iostream>
#include <netinet/in.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>

static const int TEST_PORT = 59998;
static Botan::AutoSeeded_RNG rng;

static int connect_test()
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(TEST_PORT);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static void send_line(int fd, const std::string& line)
{
    std::string msg = line + "\n";
    send(fd, msg.data(), msg.size(), 0);
}

static std::string read_line(int fd)
{
    std::string line;
    char c;
    while (recv(fd, &c, 1, 0) > 0) {
        if (c == '\n')
            break;
        line += c;
    }
    return line;
}

static std::string cmd(int fd, const std::string& line)
{
    send_line(fd, line);
    return read_line(fd);
}

// Read all MSG lines from a POLL response, return the blobs; stops at NOMSG.
static std::vector<std::vector<uint8_t>> poll_all(int fd, const std::string& user_id,
                                                  const std::string& token)
{
    send_line(fd, "POLL " + user_id + " " + token);
    std::vector<std::vector<uint8_t>> blobs;
    while (true) {
        std::string line = read_line(fd);
        if (line == "NOMSG" || line.empty())
            break;
        if (line.substr(0, 4) == "MSG ") {
            std::istringstream ss(line.substr(4));
            std::string msg_id, blob_hex;
            ss >> msg_id >> blob_hex;
            blobs.push_back(Botan::hex_decode(blob_hex));
        }
    }
    return blobs;
}

int main()
{
    SUITE_INIT("test_server");
    std::cout << "=== server tests ===\n\n";

    std::thread([] { start_server(TEST_PORT); }).detach();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // -------------------------------------------------------
    // REGISTER
    // -------------------------------------------------------
    TEST("REGISTER returns 64-char token for valid user");
    {
        reset_server_state();
        auto id = generate_identity(rng);
        int fd = connect_test();
        std::string resp =
            cmd(fd, "REGISTER " + id.user_id + " " + Botan::hex_encode(id.pubkey_bytes));
        ASSERT_TRUE(resp.substr(0, 3) == "OK ");
        ASSERT_EQ(resp.substr(3).size(), (size_t)64);
        close(fd);
    }

    TEST("REGISTER rejects user_id that does not match pubkey");
    {
        reset_server_state();
        auto id1 = generate_identity(rng);
        auto id2 = generate_identity(rng);
        int fd = connect_test();
        std::string resp =
            cmd(fd, "REGISTER " + id1.user_id + " " + Botan::hex_encode(id2.pubkey_bytes));
        ASSERT_TRUE(resp.substr(0, 3) == "ERR");
        close(fd);
    }

    TEST("REGISTER allows same-key re-registration");
    {
        reset_server_state();
        auto id = generate_identity(rng);
        std::string reg = "REGISTER " + id.user_id + " " + Botan::hex_encode(id.pubkey_bytes);
        int fd1 = connect_test();
        cmd(fd1, reg);
        close(fd1);
        int fd2 = connect_test();
        std::string resp = cmd(fd2, reg);
        ASSERT_TRUE(resp.substr(0, 3) == "OK ");
        close(fd2);
    }

    TEST("REGISTER rejects invalid hex pubkey");
    {
        reset_server_state();
        int fd = connect_test();
        std::string resp = cmd(fd, "REGISTER 0000000000000000 ZZZZZZ");
        ASSERT_TRUE(resp.substr(0, 3) == "ERR");
        close(fd);
    }

    // -------------------------------------------------------
    // GETKEY
    // -------------------------------------------------------
    TEST("GETKEY returns pubkey for registered user");
    {
        reset_server_state();
        auto id = generate_identity(rng);
        int fd = connect_test();
        cmd(fd, "REGISTER " + id.user_id + " " + Botan::hex_encode(id.pubkey_bytes));
        std::string resp = cmd(fd, "GETKEY " + id.user_id);
        ASSERT_TRUE(resp.substr(0, 3) == "OK ");
        ASSERT_EQ(resp.substr(3), Botan::hex_encode(id.pubkey_bytes));
        close(fd);
    }

    TEST("GETKEY returns ERR for unknown user");
    {
        reset_server_state();
        int fd = connect_test();
        std::string resp = cmd(fd, "GETKEY 0000000000000000");
        ASSERT_TRUE(resp.substr(0, 3) == "ERR");
        close(fd);
    }

    // -------------------------------------------------------
    // SEND
    // -------------------------------------------------------
    TEST("SEND rejects invalid token");
    {
        reset_server_state();
        auto sender = generate_identity(rng);
        auto recipient = generate_identity(rng);
        int fd = connect_test();
        cmd(fd, "REGISTER " + sender.user_id + " " + Botan::hex_encode(sender.pubkey_bytes));
        cmd(fd, "REGISTER " + recipient.user_id + " " + Botan::hex_encode(recipient.pubkey_bytes));
        auto blob = encrypt_message("hello", sender.user_id, "s", recipient.pubkey_bytes, rng);
        std::string resp = cmd(fd, "SEND " + sender.user_id + " " + std::string(64, '0') + " " +
                                       recipient.user_id + " " + Botan::hex_encode(blob));
        ASSERT_TRUE(resp.substr(0, 3) == "ERR");
        close(fd);
    }

    TEST("SEND accepts authenticated message and returns OK");
    {
        reset_server_state();
        auto sender = generate_identity(rng);
        auto recipient = generate_identity(rng);
        int fd = connect_test();
        std::string s_tok =
            cmd(fd, "REGISTER " + sender.user_id + " " + Botan::hex_encode(sender.pubkey_bytes))
                .substr(3);
        cmd(fd, "REGISTER " + recipient.user_id + " " + Botan::hex_encode(recipient.pubkey_bytes));
        auto blob = encrypt_message("hello", sender.user_id, "s", recipient.pubkey_bytes, rng);
        std::string resp = cmd(fd, "SEND " + sender.user_id + " " + s_tok + " " +
                                       recipient.user_id + " " + Botan::hex_encode(blob));
        ASSERT_EQ(resp, std::string("OK"));
        close(fd);
    }

    TEST("SEND rejects unknown recipient");
    {
        reset_server_state();
        auto sender = generate_identity(rng);
        int fd = connect_test();
        std::string s_tok =
            cmd(fd, "REGISTER " + sender.user_id + " " + Botan::hex_encode(sender.pubkey_bytes))
                .substr(3);
        std::string resp =
            cmd(fd, "SEND " + sender.user_id + " " + s_tok + " 0000000000000000 AABB");
        ASSERT_TRUE(resp.substr(0, 3) == "ERR");
        close(fd);
    }

    TEST("SEND rejects blob exceeding MAX_BLOB_LEN");
    {
        reset_server_state();
        auto sender = generate_identity(rng);
        auto recipient = generate_identity(rng);
        int fd = connect_test();
        std::string s_tok =
            cmd(fd, "REGISTER " + sender.user_id + " " + Botan::hex_encode(sender.pubkey_bytes))
                .substr(3);
        cmd(fd, "REGISTER " + recipient.user_id + " " + Botan::hex_encode(recipient.pubkey_bytes));
        std::vector<uint8_t> oversized(MAX_BLOB_LEN + 1, 0xAB);
        std::string resp = cmd(fd, "SEND " + sender.user_id + " " + s_tok + " " +
                                       recipient.user_id + " " + Botan::hex_encode(oversized));
        ASSERT_TRUE(resp.substr(0, 3) == "ERR");
        close(fd);
    }

    TEST("SEND accepts blob exactly at MAX_BLOB_LEN");
    {
        reset_server_state();
        auto sender = generate_identity(rng);
        auto recipient = generate_identity(rng);
        int fd = connect_test();
        std::string s_tok =
            cmd(fd, "REGISTER " + sender.user_id + " " + Botan::hex_encode(sender.pubkey_bytes))
                .substr(3);
        cmd(fd, "REGISTER " + recipient.user_id + " " + Botan::hex_encode(recipient.pubkey_bytes));
        std::vector<uint8_t> max_blob(MAX_BLOB_LEN, 0xCD);
        std::string resp = cmd(fd, "SEND " + sender.user_id + " " + s_tok + " " +
                                       recipient.user_id + " " + Botan::hex_encode(max_blob));
        ASSERT_EQ(resp, std::string("OK"));
        close(fd);
    }

    // -------------------------------------------------------
    // POLL
    // -------------------------------------------------------
    TEST("POLL returns NOMSG when inbox is empty");
    {
        reset_server_state();
        auto id = generate_identity(rng);
        int fd = connect_test();
        std::string token =
            cmd(fd, "REGISTER " + id.user_id + " " + Botan::hex_encode(id.pubkey_bytes)).substr(3);
        auto blobs = poll_all(fd, id.user_id, token);
        ASSERT_EQ(blobs.size(), (size_t)0);
        close(fd);
    }

    TEST("POLL rejects invalid token");
    {
        reset_server_state();
        auto id = generate_identity(rng);
        int fd = connect_test();
        cmd(fd, "REGISTER " + id.user_id + " " + Botan::hex_encode(id.pubkey_bytes));
        std::string resp = cmd(fd, "POLL " + id.user_id + " " + std::string(64, '0'));
        ASSERT_TRUE(resp.substr(0, 3) == "ERR");
        close(fd);
    }

    TEST("POLL delivers message and wipes inbox on receipt");
    {
        reset_server_state();
        auto sender = generate_identity(rng);
        auto recipient = generate_identity(rng);
        int fd = connect_test();
        std::string s_tok =
            cmd(fd, "REGISTER " + sender.user_id + " " + Botan::hex_encode(sender.pubkey_bytes))
                .substr(3);
        std::string r_tok = cmd(fd, "REGISTER " + recipient.user_id + " " +
                                        Botan::hex_encode(recipient.pubkey_bytes))
                                .substr(3);
        auto blob = encrypt_message("secret message", sender.user_id, "sender",
                                    recipient.pubkey_bytes, rng);
        cmd(fd, "SEND " + sender.user_id + " " + s_tok + " " + recipient.user_id + " " +
                    Botan::hex_encode(blob));

        // First poll — should deliver the message
        auto blobs = poll_all(fd, recipient.user_id, r_tok);
        ASSERT_EQ(blobs.size(), (size_t)1);

        // Second poll — inbox must be empty after delivery
        auto blobs2 = poll_all(fd, recipient.user_id, r_tok);
        ASSERT_EQ(blobs2.size(), (size_t)0);
        close(fd);
    }

    TEST("POLL delivered blob decrypts to original message");
    {
        reset_server_state();
        auto sender = generate_identity(rng);
        auto recipient = generate_identity(rng);
        int fd = connect_test();
        std::string s_tok =
            cmd(fd, "REGISTER " + sender.user_id + " " + Botan::hex_encode(sender.pubkey_bytes))
                .substr(3);
        std::string r_tok = cmd(fd, "REGISTER " + recipient.user_id + " " +
                                        Botan::hex_encode(recipient.pubkey_bytes))
                                .substr(3);
        auto blob =
            encrypt_message("end to end", sender.user_id, "alice", recipient.pubkey_bytes, rng);
        cmd(fd, "SEND " + sender.user_id + " " + s_tok + " " + recipient.user_id + " " +
                    Botan::hex_encode(blob));

        auto blobs = poll_all(fd, recipient.user_id, r_tok);
        ASSERT_EQ(blobs.size(), (size_t)1);

        auto dec = decrypt_message(blobs[0], *recipient.priv_key, rng);
        ASSERT_EQ(dec.plaintext, std::string("end to end"));
        ASSERT_EQ(dec.sender_id, sender.user_id);
        ASSERT_EQ(dec.sender_name, std::string("alice"));
        close(fd);
    }

    // -------------------------------------------------------
    // Unknown command
    // -------------------------------------------------------
    TEST("unknown command returns ERR");
    {
        reset_server_state();
        int fd = connect_test();
        std::string resp = cmd(fd, "INVALID");
        ASSERT_TRUE(resp.substr(0, 3) == "ERR");
        close(fd);
    }

    SUITE_RESULTS();
}
