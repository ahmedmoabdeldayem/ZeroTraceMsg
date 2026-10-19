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

// -------------------------------------------------------
// Contacts — persisted to users/<username>.contacts
// Format: nonce(12) || AES-256-GCM( "id nickname\n"... )
// Key is derived from the identity private key via HKDF (no extra passphrase needed).
// -------------------------------------------------------
static void load_contacts()
{
    if (g_contacts_key.empty())
        return;
    std::ifstream f(contacts_file, std::ios::binary);
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

static void save_contacts()
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

    std::ofstream f(contacts_file, std::ios::binary);
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
    save_contacts();
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
    int fd = socket(AF_INET, SOCK_STREAM, 0);

    // Connection timeout via SO_RCVTIMEO / SO_SNDTIMEO
    struct timeval tv;
    tv.tv_sec = g_cfg.connection_timeout_s;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(g_cfg.client_port));
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);
    if (connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }

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
// Fetch recipient's public key from server
// -------------------------------------------------------
// caller must hold socket_mutex
static std::vector<uint8_t> get_pubkey_locked(int fd, const std::string& user_id)
{
    send_line(fd, "GETKEY " + user_id);
    std::string resp = read_line(fd);
    if (resp.substr(0, 3) != "OK ")
        throw std::runtime_error("User not found: " + user_id);
    return Botan::hex_decode(resp.substr(3));
}

// -------------------------------------------------------
// Send an encrypted message to recipient
// -------------------------------------------------------
static void do_send(int fd, const std::string& recipient_id, const std::string& text)
{
    try {
        std::vector<uint8_t> recipient_pub;
        std::vector<uint8_t> blob;
        {
            std::lock_guard<std::mutex> lock(socket_mutex);
            recipient_pub = get_pubkey_locked(fd, recipient_id);
        }
        // encrypt outside the lock — can be slow, no need to hold socket
        blob = encrypt_message(text, identity.user_id, username_local, recipient_pub, rng, g_cfg);
        {
            std::lock_guard<std::mutex> lock(socket_mutex);
            // include sender_id + token so server can authenticate the send
            send_line(fd, "SEND " + identity.user_id + " " + session_token + " " + recipient_id +
                              " " + Botan::hex_encode(blob));
            read_line(fd); // consume server response
        }
    } catch (...) {
        // intentionally silent — revealing failure details leaks whether recipient exists
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
            send_line(fd, "POLL " + identity.user_id + " " + session_token);
            while (true) {
                std::string line = read_line(fd);
                if (line == "NOMSG" || line.empty())
                    break;
                if (line.substr(0, 4) == "ACK ") {
                    delivered_at.store(now_unix());
                } else {
                    received_lines.push_back(line);
                }
            }
        }

        for (const auto& line : received_lines) {

            if (line.substr(0, 4) == "MSG ") {
                std::istringstream ss(line.substr(4));
                std::string msg_id, blob_hex;
                ss >> msg_id >> blob_hex;

                try {
                    auto blob = Botan::hex_decode(blob_hex);
                    auto decrypted = decrypt_message(blob, identity, rng, g_cfg);

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

    // Optional --config flag
    std::string config_path = "zerotrace.conf";
    for (int i = 3; i < argc - 1; ++i) {
        if (std::string(argv[i]) == "--config")
            config_path = argv[i + 1];
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

    username_local = username;

    // store identity in users/<username>.enc
    // store contacts in users/<username>.contacts (AES-256-GCM encrypted)
    std::string identity_file = "users/" + username + ".enc";
    contacts_file = "users/" + username + ".contacts";
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

    load_contacts();

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
