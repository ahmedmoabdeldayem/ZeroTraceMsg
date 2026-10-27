// Secure Messaging Client
// Usage: ./client <username> [server_ip] [--config path]

#include "../common/config.hpp"
#include "../common/crypto.hpp"
#include "../common/identity.hpp"
#include "../common/protocol.hpp"
#include "../common/replay.hpp"
#include "../common/secure_memory.hpp"
#include "../common/tls_utils.hpp"
#include <arpa/inet.h>
#include <atomic>
#include <botan/aead.h>
#include <botan/auto_rng.h>
#include <botan/hex.h>
#include <botan/secmem.h>
#include <botan/x509cert.h>
#include <chrono>
#include <fstream>
#include <iostream>
#include <map>
#include <mutex>
#include <netdb.h>
#include <netinet/in.h>
#include <sstream>
#include <string>
#include <sys/socket.h>
#include <sys/stat.h>
#include <termios.h>
#include <thread>
#include <unistd.h>
#include <vector>

// -------------------------------------------------------
// TLS client with TOFU cert pinning.
// On first connect: saves the server cert fingerprint to pin_file.
// On subsequent connects: rejects any cert that doesn't match the saved fingerprint.
// To re-pin (e.g. after a legitimate cert rotation): delete the pin file.
// -------------------------------------------------------
class ClientCallbacks : public SocketTlsCallbacks
{
    std::string pin_file_;

  public:
    explicit ClientCallbacks(int fd, std::string pin_file)
        : SocketTlsCallbacks(fd), pin_file_(std::move(pin_file))
    {
    }

    void tls_verify_cert_chain(const std::vector<Botan::X509_Certificate>& chain,
                               const std::vector<std::optional<Botan::OCSP::Response>>&,
                               const std::vector<Botan::Certificate_Store*>&, Botan::Usage_Type,
                               std::string_view, const Botan::TLS::Policy&) override
    {
        if (chain.empty())
            throw std::runtime_error("Server sent no certificate");

        std::string fp = chain[0].fingerprint("SHA-256");

        std::ifstream pf(pin_file_);
        if (pf.good()) {
            std::string saved;
            std::getline(pf, saved);
            if (fp != saved)
                throw std::runtime_error("Server certificate mismatch!\n"
                                         "  Pinned:  " +
                                         saved +
                                         "\n"
                                         "  Current: " +
                                         fp +
                                         "\n"
                                         "  Delete " +
                                         pin_file_ + " to trust the new certificate.");
        } else {
            std::ofstream of(pin_file_);
            if (!of)
                throw std::runtime_error("Cannot write pin file: " + pin_file_);
            of << fp << "\n";
            std::cout << "[TOFU] Pinned server certificate: " << fp.substr(0, 23) << "...\n";
        }
    }
};

class ClientCredentials : public Botan::Credentials_Manager
{
    // No client certificate; all methods use base-class defaults (empty chains, no keys).
};

static std::shared_ptr<ClientCallbacks> g_tls_cb;
static std::shared_ptr<Botan::TLS::Client> g_tls_conn;
static Config g_cfg; // loaded from zerotrace.conf at startup

// -------------------------------------------------------
// Received message — lives in memory until timer expires
// -------------------------------------------------------
struct LiveMessage {
    std::string id;
    std::string sender_id;
    std::string sender_name; // chosen username from inside the message
    std::string text;
    int64_t received_at; // unix seconds
};

static std::vector<LiveMessage> live_messages;
static std::mutex messages_mutex;
static Botan::AutoSeeded_RNG rng;
static Identity identity;
static std::atomic<int> sock_fd{-1};
static std::string username_local;                      // chosen username, sealed in messages
static std::string session_token;                       // issued by server on REGISTER
static std::map<std::string, PrekeyPair> prekey_store;  // prekey_id → private key pair
static std::string prekeys_file;                        // path to persisted prekey private keys
static std::atomic<int64_t> sent_at{0};                 // timestamp of last send
static std::atomic<int64_t> delivered_at{0};            // timestamp of last delivery confirmation
static std::mutex socket_mutex;                         // serializes all socket send/recv
static std::map<std::string, std::string> contacts;     // id → nickname
static std::map<std::string, std::string> contacts_rev; // nickname → id
static std::string contacts_file;
static Botan::secure_vector<uint8_t>
    g_contacts_key;            // derived from identity, used to encrypt contacts
static std::string g_pin_file; // TOFU cert pin file path
static ReplayGuard replay_guard;

static void save_prekeys_to_file()
{
    if (prekeys_file.empty())
        return;
    std::vector<PrekeyPair*> ptrs;
    for (auto& [id, pk] : prekey_store)
        ptrs.push_back(&pk);
    // Rebuild vector for save_prekeys (it takes const vector<PrekeyPair>&)
    // Re-use save_prekeys by building a temporary non-owning view isn't possible;
    // write directly instead.
    std::ofstream out(prekeys_file, std::ios::trunc);
    if (!out)
        return;
    for (auto& [pk_id, pk] : prekey_store) {
        auto raw = pk.priv_key->raw_private_key_bits();
        out << pk_id << " " << Botan::hex_encode(raw);
        if (pk.priv_key2) {
            auto raw2 = pk.priv_key2->raw_private_key_bits();
            out << " " << Botan::hex_encode(raw2);
        }
        out << "\n";
    }
}

// -------------------------------------------------------
// Contacts — persisted to users/<username>.contacts
// Format: nonce(12) || AES-256-GCM( "id nickname\n"... )
// Key is derived from the identity private key via HKDF (no extra passphrase needed).
//
// The path parameter must be caller-sanitised (username validated in main()).
// Passing it explicitly keeps the sanitised value's data-flow path visible
// to static analysers and avoids taint through the global.
// -------------------------------------------------------
static void load_contacts(const std::string& path)
{
    if (g_contacts_key.empty())
        return;
    std::ifstream f(path, std::ios::binary);
    if (!f)
        return;

    std::vector<uint8_t> nonce(12);
    f.read(reinterpret_cast<char*>(nonce.data()), 12);
    if (f.gcount() < 12)
        return; // empty or truncated — start fresh

    std::string raw(std::istreambuf_iterator<char>(f), {});
    if (raw.empty())
        return;
    try {
        Botan::secure_vector<uint8_t> ct(raw.begin(), raw.end());
        auto dec = Botan::AEAD_Mode::create_or_throw("AES-256/GCM", Botan::Cipher_Dir::Decryption);
        dec->set_key(g_contacts_key);
        dec->start(nonce);
        dec->finish(ct);

        std::istringstream ss(std::string(ct.begin(), ct.end()));
        std::string id, nick;
        while (ss >> id >> nick) {
            contacts[id] = nick;
            contacts_rev[nick] = id;
        }
    } catch (...) {
        // Corrupt or tampered — start with empty contacts
    }
}

static void save_contacts(const std::string& path)
{
    if (g_contacts_key.empty())
        return;

    std::string plaintext;
    for (const auto& [id, nick] : contacts)
        plaintext += id + " " + nick + "\n";

    auto nonce = rng.random_vec(12);
    auto enc = Botan::AEAD_Mode::create_or_throw("AES-256/GCM", Botan::Cipher_Dir::Encryption);
    enc->set_key(g_contacts_key);
    enc->start(nonce);
    Botan::secure_vector<uint8_t> buf(plaintext.begin(), plaintext.end());
    enc->finish(buf);

    std::ofstream f(path, std::ios::binary);
    f.write(reinterpret_cast<const char*>(nonce.data()), nonce.size());
    f.write(reinterpret_cast<const char*>(buf.data()), buf.size());
}

static void add_contact(const std::string& id, const std::string& nick)
{
    // remove old reverse mapping if nickname was used before
    if (contacts.count(id))
        contacts_rev.erase(contacts[id]);
    contacts[id] = nick;
    contacts_rev[nick] = id;
    save_contacts(contacts_file);
}

// resolve nickname or raw ID → user ID
static std::string resolve_id(const std::string& input)
{
    if (input.size() == USER_ID_LEN)
        return input; // raw ID
    auto it = contacts_rev.find(input);
    if (it != contacts_rev.end())
        return it->second; // nickname
    return "";             // not found
}

// display name: nickname if known, otherwise raw ID
static std::string display_name(const std::string& id)
{
    auto it = contacts.find(id);
    return it != contacts.end() ? it->second : id;
}

// -------------------------------------------------------
// Socket helpers — route all I/O through the TLS channel
// -------------------------------------------------------
static void send_line(int /*fd*/, const std::string& line) { tls_send_line(*g_tls_conn, line); }

static std::string read_line(int fd) { return tls_read_line(fd, *g_tls_conn, *g_tls_cb); }

// TLS policy that honours tls_min_version from config
class ClientTlsPolicy : public Botan::TLS::Policy
{
    bool allow_tls12_;

  public:
    explicit ClientTlsPolicy(bool allow_tls12) : allow_tls12_(allow_tls12) {}
    bool allow_tls12() const override { return allow_tls12_; }
};

static int connect_to_server(const std::string& ip)
{
    // Use getaddrinfo so both IPv4 and IPv6 addresses (and hostnames) work.
    struct addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%d", g_cfg.client_port);
    struct addrinfo* res = nullptr;
    if (getaddrinfo(ip.c_str(), port_str, &hints, &res) != 0 || res == nullptr)
        return -1;

    struct timeval tv;
    tv.tv_sec = g_cfg.connection_timeout_s;
    tv.tv_usec = 0;

    int fd = -1;
    for (struct addrinfo* p = res; p != nullptr; p = p->ai_next) {
        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0)
            continue;
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        if (connect(fd, p->ai_addr, p->ai_addrlen) == 0)
            break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0)
        return -1;

    // Establish TLS over the connected socket
    auto rng = std::make_shared<Botan::AutoSeeded_RNG>();
    g_tls_cb = std::make_shared<ClientCallbacks>(fd, g_pin_file);
    auto session_mgr = std::make_shared<Botan::TLS::Session_Manager_Noop>();
    auto creds = std::make_shared<ClientCredentials>();
    auto policy = std::make_shared<ClientTlsPolicy>(g_cfg.tls_min_version == "1.2");

    g_tls_conn = std::make_shared<Botan::TLS::Client>(
        g_tls_cb, session_mgr, creds, policy, std::shared_ptr<Botan::RandomNumberGenerator>(rng),
        Botan::TLS::Server_Information(ip, static_cast<uint16_t>(g_cfg.client_port)));

    // Drive the handshake by feeding raw bytes until TLS is active
    while (!g_tls_conn->is_active() && !g_tls_cb->closed) {
        uint8_t buf[4096];
        ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
        if (n <= 0) {
            close(fd);
            return -1;
        }
        g_tls_conn->received_data({buf, static_cast<size_t>(n)});
    }

    if (!g_tls_conn->is_active()) {
        close(fd);
        return -1;
    }

    return fd;
}

static int64_t now_unix()
{
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

// -------------------------------------------------------
// Protocol version handshake
// -------------------------------------------------------
static bool do_hello(int fd)
{
    std::lock_guard<std::mutex> lock(socket_mutex);
    send_line(fd, "HELLO ZTM/" + std::to_string(PROTOCOL_VERSION));
    std::string resp = read_line(fd);
    if (resp.substr(0, 3) == "ERR") {
        std::cerr << "[error] Server rejected version handshake: " << resp << "\n";
        return false;
    }
    return true;
}

// -------------------------------------------------------
// Register identity with server
// -------------------------------------------------------
// Parse "key=value" pairs out of the REGISTER OK response and validate
// that the server's crypto config matches ours.
static void check_server_crypto(const std::string& resp_tail)
{
    std::istringstream ss(resp_tail);
    std::string tok;
    while (ss >> tok) {
        auto eq = tok.find('=');
        if (eq == std::string::npos)
            continue;
        std::string key = tok.substr(0, eq);
        std::string val = tok.substr(eq + 1);
        if (key == "kem" && val != g_cfg.kem)
            std::cerr << "\n[warning] server kem=" << val << " but client kem=" << g_cfg.kem
                      << " — messages will fail to decrypt\n";
        if (key == "cipher" && val != g_cfg.cipher)
            std::cerr << "\n[warning] server cipher=" << val
                      << " but client cipher=" << g_cfg.cipher << "\n";
        if (key == "hash" && val != g_cfg.hash)
            std::cerr << "\n[warning] server hash=" << val << " but client hash=" << g_cfg.hash
                      << "\n";
    }
}

static bool do_register(int fd)
{
    std::lock_guard<std::mutex> lock(socket_mutex);
    std::string pubkey_hex = Botan::hex_encode(identity.pubkey_bytes);
    send_line(fd, "REGISTER " + identity.user_id + " " + pubkey_hex);
    std::string resp = read_line(fd);
    if (resp.substr(0, 3) == "OK ") {
        std::istringstream ss(resp.substr(3));
        ss >> session_token; // first word is the token
        // remaining words are key=value crypto params
        std::string rest;
        std::getline(ss >> std::ws, rest);
        if (!rest.empty())
            check_server_crypto(rest);
        return true;
    }
    return false;
}

// -------------------------------------------------------
// -------------------------------------------------------
// Send an encrypted message to recipient
// -------------------------------------------------------
// Send one encrypted message to a single target_id (may be primary or a linked device).
static void send_to_one(int fd, const std::string& target_id, const std::string& text)
{
    std::vector<uint8_t> encrypt_pub;
    std::string prekey_id = "_";
    {
        std::lock_guard<std::mutex> lock(socket_mutex);
        send_line(fd, "GETPREKEY " + target_id);
        std::string resp = read_line(fd);
        if (resp.size() < 3 || resp.substr(0, 3) != "OK ")
            return;
        std::istringstream ss(resp.substr(3));
        std::string id_pub_hex, pk_id_or_none, pk_pub_hex;
        ss >> id_pub_hex >> pk_id_or_none >> pk_pub_hex;
        encrypt_pub = (pk_id_or_none == "NONE") ? Botan::hex_decode(id_pub_hex)
                                                : Botan::hex_decode(pk_pub_hex);
        if (pk_id_or_none != "NONE")
            prekey_id = pk_id_or_none;
    }
    auto blob = encrypt_message(text, identity.user_id, username_local, encrypt_pub, rng, g_cfg);
    {
        std::lock_guard<std::mutex> lock(socket_mutex);
        send_line(fd, "SEND " + identity.user_id + " " + session_token + " " + target_id + " " +
                          prekey_id + " " + Botan::hex_encode(blob));
        read_line(fd);
    }
}

static void do_send(int fd, const std::string& recipient_id, const std::string& text)
{
    try {
        // Send to the primary recipient.
        send_to_one(fd, recipient_id, text);

        // Fan out to all linked devices so every device receives the message.
        std::vector<std::string> devices;
        {
            std::lock_guard<std::mutex> lock(socket_mutex);
            send_line(fd, "GETLINKED " + recipient_id);
            std::string resp = read_line(fd);
            if (resp.size() >= 3 && resp.substr(0, 3) == "OK ") {
                std::istringstream ss(resp.substr(3));
                std::string dev;
                while (ss >> dev)
                    devices.push_back(dev);
            }
        }
        for (const auto& dev : devices)
            send_to_one(fd, dev, text);
    } catch (...) {
    }
    sent_at.store(now_unix());
}

// -------------------------------------------------------
// Clear terminal and reprint all active messages.
// Called when a message arrives or expires — ensures
// expired content is visually removed from the screen.
// -------------------------------------------------------
static int prev_lines = 0;
static bool first_draw = true;

// caller must hold messages_mutex
static void redraw_screen_locked()
{
    if (first_draw) {
        // full clear on first draw — wipes all startup output cleanly
        std::cout << "\033[2J\033[H";
        first_draw = false;
    } else {
        std::cout << "\033[s"  // save cursor (where user is typing)
                  << "\033[H"; // go to top-left

        // clear exactly as many lines as last draw — never touches the input line
        for (int i = 0; i < prev_lines; i++)
            std::cout << "\033[2K\n";
        std::cout << "\033[H"; // back to top
    }

    int lines = 0;
    std::cout << "\033[2K" << "your id: " << identity.user_id << "\n";
    lines++;
    std::cout << "\033[2K" << "─────────────────────────\n\n";
    lines += 2;

    {
        int64_t now = now_unix();
        if (now - delivered_at.load() < 5) {
            std::cout << "\033[2K[delivered]\n\n";
            lines += 2;
        } else if (now - sent_at.load() < 2) {
            std::cout << "\033[2K[sent]\n\n";
            lines += 2;
        }
    }

    for (const auto& msg : live_messages) {
        std::string name = msg.sender_name.empty() ? display_name(msg.sender_id) : msg.sender_name;
        std::cout << "\033[2K" << "from: " << name << "  (auto-deletes in ~2 min)\n";
        lines++;
        // split on embedded newlines — each line needs its own \033[2K clear
        std::istringstream ts(msg.text);
        std::string tl;
        while (std::getline(ts, tl)) {
            std::cout << "\033[2K" << tl << "\n";
            lines++;
        }
        std::cout << "\033[2K─────────────────────────\n\n";
        lines += 2;
    }

    prev_lines = lines;

    if (!first_draw)
        std::cout << "\033[u"; // restore cursor to input line (not needed on first draw)
    std::cout << std::flush;
}

static void redraw_screen()
{
    std::lock_guard<std::mutex> lock(messages_mutex);
    redraw_screen_locked();
}

// -------------------------------------------------------
// Poll for new messages — runs on background thread
// -------------------------------------------------------
static void poll_thread(std::string server_ip)
{
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(g_cfg.poll_interval_s));

        int fd = sock_fd.load();
        if (fd < 0)
            continue;

        std::vector<std::string> received_lines;
        {
            std::lock_guard<std::mutex> lock(socket_mutex);
            // Re-poll in a loop when server signals MORE (paginated inbox).
            bool more = true;
            while (more) {
                more = false;
                send_line(fd, "POLL " + identity.user_id + " " + session_token);
                std::vector<std::string> msg_ids;
                while (true) {
                    std::string line = read_line(fd);
                    if (line == "NOMSG" || line.empty())
                        break;
                    if (line == "MORE") {
                        more = true;
                        continue;
                    }
                    if (line.substr(0, 4) == "ACK ") {
                        delivered_at.store(now_unix());
                    } else if (line.substr(0, 4) == "MSG ") {
                        std::istringstream ss(line.substr(4));
                        std::string msg_id, pk_id;
                        ss >> msg_id >> pk_id;
                        msg_ids.push_back(msg_id);
                        received_lines.push_back(line);
                        (void)pk_id;
                    }
                }
                // Phase 2: confirm receipt so the server deletes the messages.
                if (!msg_ids.empty()) {
                    std::string id_list;
                    for (size_t i = 0; i < msg_ids.size(); ++i) {
                        if (i > 0)
                            id_list += ',';
                        id_list += msg_ids[i];
                    }
                    send_line(fd,
                              "MSGACK " + identity.user_id + " " + session_token + " " + id_list);
                    read_line(fd); // consume OK
                }
            } // end while (more)

            // Prekey replenishment: if server-side count is below threshold, upload
            // a fresh batch so senders always have one-time prekeys available.
            if (g_cfg.prekey_refill_threshold > 0) {
                send_line(fd, "PREKEY_COUNT " + identity.user_id + " " + session_token);
                std::string cnt_resp = read_line(fd);
                if (cnt_resp.size() > 3 && cnt_resp.substr(0, 3) == "OK ") {
                    int server_count = std::stoi(cnt_resp.substr(3));
                    if (server_count < g_cfg.prekey_refill_threshold) {
                        auto new_pks = generate_prekeys(g_cfg.prekey_batch_size, rng, g_cfg);
                        std::string upload =
                            "UPLOAD_PREKEYS " + identity.user_id + " " + session_token;
                        for (auto& pk : new_pks)
                            upload += " " + Botan::hex_encode(pk.pubkey_bytes);
                        send_line(fd, upload);
                        read_line(fd); // consume OK / ERR
                        for (auto& pk : new_pks)
                            prekey_store[pk.prekey_id] = std::move(pk);
                        save_prekeys_to_file();
                    }
                }
            }
        }

        for (const auto& line : received_lines) {

            if (line.substr(0, 4) == "MSG ") {
                std::istringstream ss(line.substr(4));
                std::string msg_id, msg_prekey_id, blob_hex;
                ss >> msg_id >> msg_prekey_id >> blob_hex;

                try {
                    auto blob = Botan::hex_decode(blob_hex);
                    DecryptedMessage decrypted;
                    if (msg_prekey_id != "_") {
                        auto it = prekey_store.find(msg_prekey_id);
                        if (it != prekey_store.end()) {
                            auto& pk = it->second;
                            decrypted = decrypt_message(blob, *pk.priv_key, pk.priv_key2.get(),
                                                        pk.pubkey_bytes, rng, g_cfg);
                            prekey_store.erase(it);
                            save_prekeys_to_file();
                        } else {
                            continue; // prekey not found — skip undecryptable message
                        }
                    } else {
                        decrypted = decrypt_message(blob, identity, rng, g_cfg);
                    }

                    if (!replay_guard.check_and_insert(decrypted.msg_nonce))
                        continue; // duplicate nonce — silently drop replay

                    LiveMessage lm;
                    lm.id = msg_id;
                    lm.sender_id = decrypted.sender_id;
                    lm.sender_name = decrypted.sender_name;
                    lm.text = decrypted.plaintext;
                    lm.received_at = now_unix();

                    {
                        std::lock_guard<std::mutex> lock(messages_mutex);
                        live_messages.push_back(lm);
                    }

                    redraw_screen();
                } catch (const std::exception& e) {
                    std::cout << "\n[failed to decrypt message: " << e.what() << "]\n> "
                              << std::flush;
                }
            }
        }
    }
}

// -------------------------------------------------------
// Display thread — redraws every second so the countdown
// is live, and wipes messages when their timer expires.
// -------------------------------------------------------
static void display_thread()
{
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(10));

        int64_t cutoff = now_unix() - g_cfg.msg_ttl_s;
        std::lock_guard<std::mutex> lock(messages_mutex);

        // wipe any expired messages
        bool any_expired = false;
        auto it = live_messages.begin();
        while (it != live_messages.end()) {
            if (it->received_at < cutoff) {
                std::fill(it->text.begin(), it->text.end(), '\0');
                std::fill(it->sender_id.begin(), it->sender_id.end(), '\0');
                std::fill(it->sender_name.begin(), it->sender_name.end(), '\0');
                it = live_messages.erase(it);
                any_expired = true;
            } else {
                ++it;
            }
        }

        // only redraw when something actually changed — stops concurrent stdout
        // writes that interfere with std::getline in the main thread
        if (any_expired) {
            redraw_screen_locked();
        }
    }
}

// -------------------------------------------------------
// Read passphrase without echo
// -------------------------------------------------------
static SecureString read_passphrase(const std::string& prompt)
{
    std::cout << prompt << std::flush;
    std::string tmp;
    struct termios oldt, newt;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    std::getline(std::cin, tmp);
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    std::cout << "\n";
    SecureString pass = make_secure(tmp);
    std::fill(tmp.begin(), tmp.end(), '\0'); // zero the temporary before it leaves scope
    return pass;
}

int main(int argc, char* argv[])
{
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <username> <server_ip> [--config path]\n";
        std::cerr << "Example: " << argv[0] << " alice 127.0.0.1\n";
        return 1;
    }

    std::string username = argv[1];
    std::string server_ip = argv[2];

    // Optional flags
    std::string config_path = "zerotrace.conf";
    bool do_rekey = false;
    std::string link_primary; // --link-device <primary_id>
    for (int i = 3; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--config" && i + 1 < argc)
            config_path = argv[++i];
        else if (a == "--rekey")
            do_rekey = true;
        else if (a == "--link-device" && i + 1 < argc)
            link_primary = argv[++i];
    }
    try {
        g_cfg = Config::load(config_path);
    } catch (...) {
        // fall back to defaults if file missing or invalid
    }

    // strip .enc extension if user passed a filename instead of a name
    if (username.size() > 4 && username.substr(username.size() - 4) == ".enc")
        username = username.substr(0, username.size() - 4);

    // Reject usernames that could escape the users/ directory via path traversal
    for (char c : username) {
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '-' && c != '_') {
            std::cerr << "Username may only contain letters, digits, hyphens, and underscores.\n";
            return 1;
        }
    }
    if (username.empty()) {
        std::cerr << "Username must not be empty.\n";
        return 1;
    }

    // Rebuild username from the allowlist so the path it produces is demonstrably
    // free of separators — allowlist reconstruction is the pattern CodeQL recognises
    // as a path-injection sanitizer.
    std::string safe_username;
    safe_username.reserve(username.size());
    for (char c : username)
        if (std::isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_')
            safe_username += c;
    if (safe_username.empty() || safe_username != username) {
        std::cerr << "Username contains invalid characters.\n";
        return 1;
    }
    username = safe_username;
    username_local = username;

    // store identity in users/<username>.enc
    // store contacts in users/<username>.contacts (AES-256-GCM encrypted)
    std::string identity_file = "users/" + username + ".enc";
    contacts_file = "users/" + username + ".contacts";
    prekeys_file = "users/" + username + ".prekeys";
    g_pin_file = "users/.server_pin";

    // create users/ with restricted permissions — contains encrypted private keys
    mkdir("users", 0700); // silently succeeds if already exists

    // -------------------------------------------------------
    // Load or create identity
    // -------------------------------------------------------
    std::ifstream check(identity_file);
    if (check.good()) {
        check.close();
        auto pass = read_passphrase("Passphrase: ");
        try {
            identity = load_identity(pass, identity_file, g_cfg);
        } catch (...) {
            std::cerr << "Wrong passphrase or corrupt identity file.\n";
            return 1;
        }
    } else {
        check.close();
        std::cout << "No identity found for '" << username << "'. Creating new identity.\n";
        auto pass = read_passphrase("Set passphrase: ");
        identity = generate_identity(rng, g_cfg);
        save_identity(identity, pass, identity_file, rng, g_cfg);
        chmod(identity_file.c_str(), 0600); // owner-read only
        std::cout << "Identity saved to " << identity_file << "\n";
    }

    // Derive contacts encryption key from the private key (deterministic, no extra passphrase)
    g_contacts_key = derive_contacts_key(identity, g_cfg);

    // Load any previously-generated prekey private keys from disk.
    prekey_store = load_prekeys(prekeys_file, g_cfg);

    // -------------------------------------------------------
    // Connect and register
    // -------------------------------------------------------
    int fd = connect_to_server(server_ip);
    if (fd < 0) {
        std::cerr << "Cannot connect to server.\n";
        return 1;
    }
    sock_fd.store(fd);

    if (!do_hello(fd)) {
        std::cerr << "Version handshake failed.\n";
        return 1;
    }

    if (!do_register(fd)) {
        std::cerr << "Registration failed.\n";
        return 1;
    }

    // Generate and upload a fresh batch of one-time prekeys for forward secrecy.
    {
        auto new_prekeys = generate_prekeys(g_cfg.prekey_batch_size, rng, g_cfg);
        std::string upload_cmd = "UPLOAD_PREKEYS " + identity.user_id + " " + session_token;
        for (auto& pk : new_prekeys)
            upload_cmd += " " + Botan::hex_encode(pk.pubkey_bytes);
        send_line(fd, upload_cmd);
        read_line(fd); // consume OK / ERR
        for (auto& pk : new_prekeys)
            prekey_store[pk.prekey_id] = std::move(pk);
        save_prekeys_to_file();
    }

    // -------------------------------------------------------
    // Link-device mode (--link-device <primary_id>)
    // -------------------------------------------------------
    // --link-device <device_id>: this client IS the primary; link a new device to us.
    if (!link_primary.empty()) {
        std::string resp;
        {
            std::lock_guard<std::mutex> lock(socket_mutex);
            send_line(fd,
                      "LINK_DEVICE " + identity.user_id + " " + session_token + " " + link_primary);
            resp = read_line(fd);
        }
        if (resp.substr(0, 3) == "OK") {
            std::cout << "Device " << link_primary << " linked to this identity.\n";
        } else {
            std::cerr << "Failed to link device: " << resp << "\n";
        }
    }

    // -------------------------------------------------------
    // Key rotation mode (--rekey)
    // -------------------------------------------------------
    if (do_rekey) {
        Identity new_id = generate_identity(rng, g_cfg);
        std::string resp;
        {
            std::lock_guard<std::mutex> lock(socket_mutex);
            send_line(fd, "REKEY " + identity.user_id + " " + session_token + " " + new_id.user_id +
                              " " + Botan::hex_encode(new_id.pubkey_bytes));
            resp = read_line(fd);
        }

        if (resp.size() < 3 || resp.substr(0, 3) != "OK ") {
            std::cerr << "[rekey failed] " << resp << "\n";
            close(fd);
            return 1;
        }

        std::cout << "Key rotation successful.\n";
        std::cout << "Old ID: " << identity.user_id << "\n";
        std::cout << "New ID: " << new_id.user_id << "\n";
        std::cout << "Share your new ID with your contacts.\n";

        auto new_pass = read_passphrase("Set new passphrase: ");
        save_identity(new_id, new_pass, identity_file, rng, g_cfg);
        chmod(identity_file.c_str(), 0600);
        std::cout << "New identity saved to " << identity_file << "\n";

        close(fd);
        return 0;
    }

    load_contacts(contacts_file);

    // start background threads
    std::thread(poll_thread, server_ip).detach();
    std::thread(display_thread).detach();

    // initial screen draw
    redraw_screen();
    std::cout << "> " << std::flush;

    // -------------------------------------------------------
    // Main input loop
    // -------------------------------------------------------
    std::string line;
    while (std::getline(std::cin, line)) {
        if (line.empty()) {
            std::cout << "> " << std::flush;
            continue;
        }

        std::istringstream ss(line);
        std::string first;
        ss >> first;

        if (first == "quit") {
            break;
        } else if (first == "deregister") {
            std::lock_guard<std::mutex> lock(socket_mutex);
            send_line(fd, "DEREGISTER " + identity.user_id + " " + session_token);
            std::string resp = read_line(fd);
            if (resp == "OK") {
                std::cout << "\n[Account removed from server. Goodbye.]\n";
                break;
            } else {
                std::cout << "\n[Deregister failed: " << resp << "]\n";
            }
        } else if (first == "add") {
            // add <id> <nickname>
            std::string id, nick;
            ss >> id >> nick;
            if (id.size() == USER_ID_LEN && !nick.empty()) {
                add_contact(id, nick);
            }
        } else if (first == "/group") {
            // /group create <name>
            // /group add <group_id> <user_id>
            // /group remove <group_id> <user_id>
            // /group members <group_id>
            // /group send <group_id> <message>
            std::string sub;
            ss >> sub;
            if (sub == "create") {
                std::string gname;
                std::getline(ss >> std::ws, gname);
                if (gname.empty()) {
                    std::cout << "\n[usage: /group create <name>]\n";
                } else {
                    std::lock_guard<std::mutex> lock(socket_mutex);
                    send_line(fd, "CREATE_GROUP " + identity.user_id + " " + session_token + " " +
                                      gname);
                    std::string resp = read_line(fd);
                    if (resp.substr(0, 3) == "OK ")
                        std::cout << "\n[Group created: " << resp.substr(3) << "]\n";
                    else
                        std::cout << "\n[" << resp << "]\n";
                }
            } else if (sub == "add") {
                std::string gid, uid;
                ss >> gid >> uid;
                std::lock_guard<std::mutex> lock(socket_mutex);
                send_line(fd, "ADD_MEMBER " + gid + " " + identity.user_id + " " + session_token +
                                  " " + uid);
                std::cout << "\n[" << read_line(fd) << "]\n";
            } else if (sub == "remove") {
                std::string gid, uid;
                ss >> gid >> uid;
                std::lock_guard<std::mutex> lock(socket_mutex);
                send_line(fd, "REMOVE_MEMBER " + gid + " " + identity.user_id + " " +
                                  session_token + " " + uid);
                std::cout << "\n[" << read_line(fd) << "]\n";
            } else if (sub == "members") {
                std::string gid;
                ss >> gid;
                std::lock_guard<std::mutex> lock(socket_mutex);
                send_line(fd, "LIST_MEMBERS " + gid);
                std::cout << "\n[" << read_line(fd) << "]\n";
            } else if (sub == "send") {
                std::string gid, text;
                ss >> gid;
                std::getline(ss >> std::ws, text);
                if (gid.empty() || text.empty()) {
                    std::cout << "\n[usage: /group send <group_id> <message>]\n";
                } else {
                    // Fetch members and send to each
                    std::vector<std::string> members;
                    {
                        std::lock_guard<std::mutex> lock(socket_mutex);
                        send_line(fd, "LIST_MEMBERS " + gid);
                        std::string resp = read_line(fd);
                        if (resp.size() >= 3 && resp.substr(0, 3) == "OK ") {
                            std::istringstream mss(resp.substr(3));
                            std::string m;
                            while (mss >> m)
                                members.push_back(m);
                        }
                    }
                    for (const auto& m : members)
                        if (m != identity.user_id)
                            send_to_one(fd, m, text);
                    sent_at.store(now_unix());
                }
            } else if (sub == "delete") {
                std::string gid;
                ss >> gid;
                if (gid.empty()) {
                    std::cout << "\n[usage: /group delete <group_id>]\n";
                } else {
                    std::lock_guard<std::mutex> lock(socket_mutex);
                    send_line(fd,
                              "DELETE_GROUP " + gid + " " + identity.user_id + " " + session_token);
                    std::cout << "\n[" << read_line(fd) << "]\n";
                }
            } else if (sub == "leave") {
                std::string gid;
                ss >> gid;
                if (gid.empty()) {
                    std::cout << "\n[usage: /group leave <group_id>]\n";
                } else {
                    std::lock_guard<std::mutex> lock(socket_mutex);
                    send_line(fd,
                              "LEAVE_GROUP " + gid + " " + identity.user_id + " " + session_token);
                    std::cout << "\n[" << read_line(fd) << "]\n";
                }
            } else if (sub == "transfer") {
                std::string gid, new_owner;
                ss >> gid >> new_owner;
                if (gid.empty() || new_owner.empty()) {
                    std::cout << "\n[usage: /group transfer <group_id> <new_owner_id>]\n";
                } else {
                    std::lock_guard<std::mutex> lock(socket_mutex);
                    send_line(fd, "TRANSFER_GROUP " + gid + " " + identity.user_id + " " +
                                      session_token + " " + new_owner);
                    std::cout << "\n[" << read_line(fd) << "]\n";
                }
            }
        } else {
            // <id or nickname> [message]
            // If no message follows, enter multi-line mode: type lines, then "." to send.
            std::string resolved = resolve_id(first);
            if (!resolved.empty()) {
                std::string text;
                std::getline(ss >> std::ws, text);

                if (text.empty()) {
                    // multi-line mode
                    std::string collected;
                    std::string ml;
                    std::cout << "... " << std::flush;
                    while (std::getline(std::cin, ml)) {
                        if (ml == ".")
                            break;
                        if (!collected.empty())
                            collected += '\n';
                        collected += ml;
                        std::cout << "... " << std::flush;
                    }
                    text = collected;
                }

                if (!text.empty()) {
                    // guard against exceeding PADDED_PLAINTEXT_LEN
                    constexpr size_t fixed_overhead = MSG_NONCE_LEN + USER_ID_LEN + 1 + 2;
                    size_t name_bytes = std::min(username_local.size(), size_t(255));
                    if (text.size() + fixed_overhead + name_bytes >
                        g_cfg.padded_plaintext_bytes()) {
                        std::cout << "\n[message too long — max "
                                  << (g_cfg.padded_plaintext_bytes() - fixed_overhead - name_bytes)
                                  << " bytes]\n";
                    } else {
                        do_send(fd, resolved, text);
                    }
                }
            }
        }

        redraw_screen();
        std::cout << "> " << std::flush;
    }

    close(fd);
    return 0;
}
