// ZeroTraceMsg Admin CLI
// Connects to the server's admin port (127.0.0.1:admin_port) and sends one command.
//
// Usage:
//   msg_admin [--port PORT] stats
//   msg_admin [--port PORT] list-users
//   msg_admin [--port PORT] kick <user_id>
//   msg_admin [--port PORT] reload
//
// Default port: 9998 (matches server default; override with --port or zerotrace.conf)

#include "../common/config.hpp"
#include <arpa/inet.h>
#include <iostream>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

static int connect_admin(int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(port));
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static void send_cmd(int fd, const std::string& line)
{
    std::string msg = line + "\n";
    ::send(fd, msg.data(), msg.size(), 0);
}

static std::string read_line(int fd)
{
    std::string line;
    char c;
    while (::recv(fd, &c, 1, 0) > 0) {
        if (c == '\n')
            break;
        line += c;
    }
    return line;
}

// Read and print lines until we see one starting with "OK", "ERR", or "END".
static int drain_response(int fd)
{
    while (true) {
        std::string line = read_line(fd);
        if (line.empty())
            return 1;
        std::cout << line << "\n";
        if (line.substr(0, 2) == "OK" || line.substr(0, 3) == "ERR" || line == "END")
            return (line.substr(0, 3) == "ERR") ? 1 : 0;
    }
}

static void usage(const char* prog)
{
    std::cerr << "Usage: " << prog << " [--port PORT] [--config PATH] <command> [args]\n"
              << "\nCommands:\n"
              << "  stats              — show server statistics\n"
              << "  list-users         — list all registered user IDs\n"
              << "  kick <user_id>     — remove a user and all their data\n"
              << "  reload             — hot-reload server config (like SIGHUP)\n";
}

int main(int argc, char* argv[])
{
    int port = 0;
    std::string config_path = "zerotrace.conf";
    std::vector<std::string> args;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--port" && i + 1 < argc) {
            try {
                port = std::stoi(argv[++i]);
            } catch (...) {
                std::cerr << "Invalid port: " << argv[i] << "\n";
                return 1;
            }
        } else if (a == "--config" && i + 1 < argc) {
            config_path = argv[++i];
        } else {
            args.push_back(a);
        }
    }

    if (args.empty()) {
        usage(argv[0]);
        return 1;
    }

    // If no --port given, load from config (fall back to default 9998).
    if (port == 0) {
        try {
            Config cfg = Config::load(config_path);
            port = cfg.admin_port;
        } catch (...) {
            port = 9998;
        }
    }

    if (port <= 0) {
        std::cerr << "Admin port is 0 (disabled in config).\n";
        return 1;
    }

    int fd = connect_admin(port);
    if (fd < 0) {
        std::cerr << "Cannot connect to admin port " << port
                  << " — is the server running with admin_port=" << port << "?\n";
        return 1;
    }

    std::string cmd_word = args[0];
    int rc = 0;

    if (cmd_word == "stats") {
        send_cmd(fd, "STATS");
        rc = drain_response(fd);
    } else if (cmd_word == "list-users") {
        send_cmd(fd, "LIST_USERS");
        rc = drain_response(fd);
    } else if (cmd_word == "kick") {
        if (args.size() < 2) {
            std::cerr << "kick requires a user_id argument.\n";
            close(fd);
            return 1;
        }
        send_cmd(fd, "KICK " + args[1]);
        rc = drain_response(fd);
    } else if (cmd_word == "reload") {
        send_cmd(fd, "RELOAD");
        rc = drain_response(fd);
    } else {
        std::cerr << "Unknown command: " << cmd_word << "\n";
        usage(argv[0]);
        close(fd);
        return 1;
    }

    close(fd);
    return rc;
}
