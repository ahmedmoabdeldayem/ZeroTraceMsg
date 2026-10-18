#include "../common/config.hpp"
#include "../common/protocol.hpp"
#include "server.hpp"
#include <iostream>

int main(int argc, char* argv[])
{
    std::string config_path = "zerotrace.conf";
    if (argc >= 2)
        config_path = argv[1];

    Config cfg;
    try {
        cfg = Config::load(config_path);
    } catch (const std::exception& e) {
        std::cerr << "Config error: " << e.what() << "\n";
        std::cerr << "Using default configuration.\n";
    }

    start_server_tls(cfg);
}
