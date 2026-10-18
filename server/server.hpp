#pragma once
#include "../common/config.hpp"

// Start plain TCP server — for tests only.
void start_server(int port);

// Start TLS server using the operator config.
void start_server_tls(const Config& cfg);

// Clear all server state — for tests only.
void reset_server_state();
