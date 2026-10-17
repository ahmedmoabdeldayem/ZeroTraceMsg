// ZeroTraceMsg Server — core logic
// Extracted from main.cpp so tests can link against it.

#include "server.hpp"
#include "../common/identity.hpp"
#include "../common/protocol.hpp"
#include <algorithm>
#include <atomic>
#include <botan/auto_rng.h>
#include <botan/hex.h>
#include <chrono>
#include <iostream>
#include <map>
#include <mutex>
#include <netinet/in.h>
#include <sstream>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>

static bool ct_equal(const uint8_t* a, const uint8_t* b, size_t len)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < len; ++i)
        diff |= a[i] ^ b[i];
    return diff == 0;
}

struct PendingMessage {
    std::string id;
    std::string sender_id;
    std::vector<uint8_t> blob;
    int64_t timestamp;
};

struct RateBucket {
    int count{0};
    int64_t window_start{0};
};

static std::map<std::string, std::vector<uint8_t>> pubkeys;
static std::map<std::string, std::vector<PendingMessage>> messages;
static std::map<std::string, std::string> tokens;
static std::map<std::string, RateBucket> rate_buckets;
static std::map<std::string, int>
    delivery_acks; // sender_id → count of messages delivered to recipients
static std::mutex store_mutex;

static std::string new_message_id()
{
    static std::atomic<uint64_t> counter{1};
    std::ostringstream ss;
    ss << std::hex << counter.fetch_add(1);
    return ss.str();
}

static int64_t now_unix()
{
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
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
        if (line.size() >= MAX_LINE_LEN)
            return "";
        line += c;
    }
    return line;
}

static void handle_client(int client_fd)
{
    Botan::AutoSeeded_RNG rng;
    std::cout << "[CONNECT]  client connected (fd=" << client_fd << ")\n";

    while (true) {
        std::string line = read_line(client_fd);
        if (line.empty())
            break;

        std::istringstream ss(line);
        std::string cmd;
        ss >> cmd;

        if (cmd == "REGISTER") {
            std::string user_id, pubkey_hex;
            ss >> user_id >> pubkey_hex;
            try {
                auto pubkey = Botan::hex_decode(pubkey_hex);
                std::string expected_id = derive_user_id(pubkey);
                if (expected_id != user_id) {
                    send_line(client_fd, "ERR user_id does not match pubkey");
                    continue;
                }
                std::lock_guard<std::mutex> lock(store_mutex);
                auto existing = pubkeys.find(user_id);
                if (existing != pubkeys.end() && existing->second != pubkey) {
                    send_line(client_fd, "ERR user_id already registered with a different key");
                    continue;
                }
                auto token_bytes = rng.random_vec(32);
                std::string token = Botan::hex_encode(token_bytes);
                pubkeys[user_id] = pubkey;
                tokens[user_id] = token;
                send_line(client_fd, "OK " + token);
                std::cout << "[REGISTER] user=" << user_id << " total_users=" << pubkeys.size()
                          << "\n";
            } catch (...) {
                send_line(client_fd, "ERR invalid pubkey");
            }

        } else if (cmd == "GETKEY") {
            std::string user_id;
            ss >> user_id;
            std::lock_guard<std::mutex> lock(store_mutex);
            auto it = pubkeys.find(user_id);
            if (it == pubkeys.end()) {
                send_line(client_fd, "ERR unknown user");
            } else {
                send_line(client_fd, "OK " + Botan::hex_encode(it->second));
            }

        } else if (cmd == "SEND") {
            std::string sender_id, token, recipient_id, blob_hex;
            ss >> sender_id >> token >> recipient_id >> blob_hex;
            std::lock_guard<std::mutex> lock(store_mutex);
            auto tok_it = tokens.find(sender_id);
            bool sender_valid =
                tok_it != tokens.end() && tok_it->second.size() == token.size() &&
                ct_equal(reinterpret_cast<const uint8_t*>(tok_it->second.data()),
                         reinterpret_cast<const uint8_t*>(token.data()), tok_it->second.size());
            if (!sender_valid) {
                send_line(client_fd, "ERR invalid token");
                continue;
            }
            {
                auto& bucket = rate_buckets[sender_id];
                int64_t now = now_unix();
                if (now - bucket.window_start >= RATE_LIMIT_WINDOW_S) {
                    bucket.count = 0;
                    bucket.window_start = now;
                }
                if (bucket.count >= RATE_LIMIT_MSGS) {
                    send_line(client_fd, "ERR rate limit exceeded");
                    continue;
                }
                bucket.count++;
            }
            if (pubkeys.find(recipient_id) == pubkeys.end()) {
                send_line(client_fd, "ERR unknown recipient");
                continue;
            }
            try {
                auto blob = Botan::hex_decode(blob_hex);
                if (blob.size() > MAX_BLOB_LEN) {
                    send_line(client_fd, "ERR blob too large");
                    continue;
                }
                std::string msg_id = new_message_id();
                messages[recipient_id].push_back({msg_id, sender_id, blob, now_unix()});
                send_line(client_fd, "OK");
                std::cout << "[SEND]     to=" << recipient_id << " msg_id=" << msg_id
                          << " blob=" << blob.size() << " bytes"
                          << " (server cannot read content)\n";
            } catch (...) {
                send_line(client_fd, "ERR invalid blob");
            }

        } else if (cmd == "POLL") {
            std::string user_id, token;
            ss >> user_id >> token;
            std::lock_guard<std::mutex> lock(store_mutex);
            auto tok_it = tokens.find(user_id);
            bool token_valid =
                tok_it != tokens.end() && tok_it->second.size() == token.size() &&
                ct_equal(reinterpret_cast<const uint8_t*>(tok_it->second.data()),
                         reinterpret_cast<const uint8_t*>(token.data()), tok_it->second.size());
            if (!token_valid) {
                send_line(client_fd, "ERR invalid token");
                std::cout << "[POLL]     user=" << user_id << " -> REJECTED invalid token\n";
                continue;
            }
            auto msg_it = messages.find(user_id);
            if (msg_it != messages.end() && !msg_it->second.empty()) {
                size_t count = msg_it->second.size();
                for (auto& msg : msg_it->second) {
                    send_line(client_fd, "MSG " + msg.id + " " + Botan::hex_encode(msg.blob));
                    delivery_acks[msg.sender_id]++;
                }
                msg_it->second.clear();
                std::cout << "[POLL]     user=" << user_id << " -> delivered " << count
                          << " message(s), wiped from store\n";
            }
            auto ack_it = delivery_acks.find(user_id);
            if (ack_it != delivery_acks.end() && ack_it->second > 0) {
                send_line(client_fd, "ACK " + std::to_string(ack_it->second));
                ack_it->second = 0;
            }
            send_line(client_fd, "NOMSG");

        } else {
            send_line(client_fd, "ERR unknown command");
        }
    }

    std::cout << "[DISCONNECT] client disconnected (fd=" << client_fd << ")\n";
    close(client_fd);
}

static void cleanup_thread()
{
    while (true) {
        std::this_thread::sleep_for(std::chrono::minutes(10));
        int64_t cutoff = now_unix() - MSG_TTL_SERVER_S;
        std::lock_guard<std::mutex> lock(store_mutex);
        for (auto& [uid, msgs] : messages) {
            msgs.erase(
                std::remove_if(msgs.begin(), msgs.end(),
                               [cutoff](const PendingMessage& m) { return m.timestamp < cutoff; }),
                msgs.end());
        }
    }
}

void start_server(int port)
{
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        return;
    }
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(static_cast<uint16_t>(port));

    if (bind(server_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        perror("bind");
        return;
    }
    listen(server_fd, 16);
    std::cout << "[*] Server listening on port " << port << "\n";
    std::thread(cleanup_thread).detach();

    while (true) {
        int client_fd = accept(server_fd, nullptr, nullptr);
        if (client_fd < 0)
            continue;
        std::thread(handle_client, client_fd).detach();
    }
}

void reset_server_state()
{
    std::lock_guard<std::mutex> lock(store_mutex);
    pubkeys.clear();
    messages.clear();
    tokens.clear();
    rate_buckets.clear();
    delivery_acks.clear();
}
