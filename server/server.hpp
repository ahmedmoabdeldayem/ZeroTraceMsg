#pragma once
#include "../common/config.hpp"

// Start plain TCP server — for tests only.
void start_server(int port);

// Start TLS server using the operator config.
// config_path is stored for SIGHUP hot-reload; defaults to "zerotrace.conf".
void start_server_tls(const Config& cfg, const std::string& config_path = "zerotrace.conf");

// Clear all server state — for tests only.
void reset_server_state();

// Trigger and then reset the shutdown flag — for tests only.
void trigger_shutdown_for_test();
void reset_shutdown_for_test();
