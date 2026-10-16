// ZeroTraceMsg Server
// Stores encrypted blobs only — cannot read any message content.
// Knows: recipient ID, sender ID (for auth only), timestamp.
// Does not know: plaintext, sender's real identity, display names.

#include "../common/protocol.hpp"
#include "../common/identity.hpp"
#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <thread>
#include <atomic>
#include <chrono>
#include <sstream>
#include <algorithm>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <botan/hex.h>
#include <botan/auto_rng.h>
#include <botan/mem_ops.h>

struct PendingMessage {
    std::string              id;
    std::vector<uint8_t>     blob;
    int64_t                  timestamp;
};

// Server state — all access serialized via store_mutex
static std::map<std::string, std::vector<uint8_t>>        pubkeys;   // user_id → pubkey
static std::map<std::string, std::vector<PendingMessage>>  messages;  // user_id → msgs
static std::map<std::string, std::string>                  tokens;    // user_id → session token
static std::mutex store_mutex;

static std::string new_message_id() {
    static std::atomic<uint64_t> counter{1};
    std::ostringstream ss;
    ss << std::hex << counter.fetch_add(1);
    return ss.str();
}

static int64_t now_unix() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

static void send_line(int fd, const std::string& line) {
    std::string msg = line + "\n";
    send(fd, msg.data(), msg.size(), 0);
}

// Read a line — enforces MAX_LINE_LEN to prevent memory exhaustion DoS
static std::string read_line(int fd) {
    std::string line;
    char c;
    while(recv(fd, &c, 1, 0) > 0) {
        if(c == '\n') break;
        if(line.size() >= MAX_LINE_LEN) return "";  // too long — signal disconnect
        line += c;
    }
    return line;
}

static void handle_client(int client_fd) {
    Botan::AutoSeeded_RNG rng;
    std::cout << "[CONNECT]  client connected (fd=" << client_fd << ")\n";

    while(true) {
        std::string line = read_line(client_fd);
        if(line.empty()) break;

        std::istringstream ss(line);
        std::string cmd;
        ss >> cmd;

        // -------------------------------------------------------
        // REGISTER <user_id> <pubkey_hex>
        // Validates user_id == SHA-256(pubkey)[0:8]
        // Rejects if user_id already registered with a different key
        // -------------------------------------------------------
        if(cmd == "REGISTER") {
            std::string user_id, pubkey_hex;
            ss >> user_id >> pubkey_hex;

            try {
                auto pubkey = Botan::hex_decode(pubkey_hex);
                std::string expected_id = derive_user_id(pubkey);

                if(expected_id != user_id) {
                    send_line(client_fd, "ERR user_id does not match pubkey");
                    continue;
                }

                std::lock_guard<std::mutex> lock(store_mutex);

                // reject if already registered with a DIFFERENT key
                auto existing = pubkeys.find(user_id);
                if(existing != pubkeys.end() && existing->second != pubkey) {
                    send_line(client_fd, "ERR user_id already registered with a different key");
                    continue;
                }

                // allow same-key re-registration (reconnect after server restart)
                auto token_bytes = rng.random_vec(32);
                std::string token = Botan::hex_encode(token_bytes);
                pubkeys[user_id] = pubkey;
                tokens[user_id]  = token;
                send_line(client_fd, "OK " + token);
                std::cout << "[REGISTER] user=" << user_id
                          << " total_users=" << pubkeys.size() << "\n";
            } catch(...) {
                send_line(client_fd, "ERR invalid pubkey");
                std::cout << "[REGISTER] FAILED invalid pubkey\n";
            }

        // -------------------------------------------------------
        // GETKEY <user_id>
        // Returns the public key for a given user ID
        // -------------------------------------------------------
        } else if(cmd == "GETKEY") {
            std::string user_id;
            ss >> user_id;

            std::lock_guard<std::mutex> lock(store_mutex);
            auto it = pubkeys.find(user_id);
            if(it == pubkeys.end()) {
                send_line(client_fd, "ERR unknown user");
                std::cout << "[GETKEY]   user=" << user_id << " -> NOT FOUND\n";
            } else {
                send_line(client_fd, "OK " + Botan::hex_encode(it->second));
                std::cout << "[GETKEY]   user=" << user_id << " -> sent pubkey\n";
            }

        // -------------------------------------------------------
        // SEND <sender_id> <token> <recipient_id> <blob_hex>
        // Authenticated — sender must present their session token
        // Server cannot read the blob content
        // -------------------------------------------------------
        } else if(cmd == "SEND") {
            std::string sender_id, token, recipient_id, blob_hex;
            ss >> sender_id >> token >> recipient_id >> blob_hex;

            std::lock_guard<std::mutex> lock(store_mutex);

            // verify sender token — prevents anonymous inbox flooding
            auto tok_it = tokens.find(sender_id);
            bool sender_valid = tok_it != tokens.end() &&
                                tok_it->second.size() == token.size() &&
                                Botan::constant_time_compare(
                                    reinterpret_cast<const uint8_t*>(tok_it->second.data()),
                                    reinterpret_cast<const uint8_t*>(token.data()),
                                    tok_it->second.size());
            if(!sender_valid) {
                send_line(client_fd, "ERR invalid token");
                continue;
            }

            if(pubkeys.find(recipient_id) == pubkeys.end()) {
                send_line(client_fd, "ERR unknown recipient");
                continue;
            }

            try {
                auto blob = Botan::hex_decode(blob_hex);
                PendingMessage msg;
                msg.id        = new_message_id();
                msg.blob      = blob;
                msg.timestamp = now_unix();
                messages[recipient_id].push_back(std::move(msg));
                send_line(client_fd, "OK");
                std::cout << "[SEND]     to=" << recipient_id
                          << " msg_id=" << msg.id
                          << " blob=" << blob.size() << " bytes"
                          << " (server cannot read content)\n";
            } catch(...) {
                send_line(client_fd, "ERR invalid blob");
            }

        // -------------------------------------------------------
        // POLL <user_id> <token>
        // Authenticated via session token
        // Returns pending messages, removes them from store
        // -------------------------------------------------------
        } else if(cmd == "POLL") {
            std::string user_id, token;
            ss >> user_id >> token;

            std::lock_guard<std::mutex> lock(store_mutex);
            auto tok_it = tokens.find(user_id);

            // constant-time comparison prevents timing side-channel on token
            bool token_valid = tok_it != tokens.end() &&
                               tok_it->second.size() == token.size() &&
                               Botan::constant_time_compare(
                                   reinterpret_cast<const uint8_t*>(tok_it->second.data()),
                                   reinterpret_cast<const uint8_t*>(token.data()),
                                   tok_it->second.size());
            if(!token_valid) {
                send_line(client_fd, "ERR invalid token");
                std::cout << "[POLL]     user=" << user_id << " -> REJECTED invalid token\n";
                continue;
            }

            auto msg_it = messages.find(user_id);
            if(msg_it == messages.end() || msg_it->second.empty()) {
                send_line(client_fd, "NOMSG");
                continue;
            }

            size_t count = msg_it->second.size();
            for(auto& msg : msg_it->second)
                send_line(client_fd, "MSG " + msg.id + " " + Botan::hex_encode(msg.blob));
            msg_it->second.clear();
            send_line(client_fd, "NOMSG");
            std::cout << "[POLL]     user=" << user_id
                      << " -> delivered " << count << " message(s), wiped from store\n";

        } else {
            send_line(client_fd, "ERR unknown command");
        }
    }

    std::cout << "[DISCONNECT] client disconnected (fd=" << client_fd << ")\n";
    close(client_fd);
}

static void cleanup_thread() {
    while(true) {
        std::this_thread::sleep_for(std::chrono::minutes(10));
        int64_t cutoff = now_unix() - MSG_TTL_SERVER_S;

        std::lock_guard<std::mutex> lock(store_mutex);
        for(auto& [uid, msgs] : messages) {
            msgs.erase(std::remove_if(msgs.begin(), msgs.end(),
                [cutoff](const PendingMessage& m) { return m.timestamp < cutoff; }),
                msgs.end());
        }
    }
}

int main() {
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if(server_fd < 0) { perror("socket"); return 1; }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(SERVER_PORT);

    if(bind(server_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        perror("bind"); return 1;
    }
    listen(server_fd, 16);

    std::cout << "[*] Server listening on port " << SERVER_PORT << "\n";
    std::thread(cleanup_thread).detach();

    while(true) {
        int client_fd = accept(server_fd, nullptr, nullptr);
        if(client_fd < 0) continue;
        std::thread(handle_client, client_fd).detach();
    }
}
