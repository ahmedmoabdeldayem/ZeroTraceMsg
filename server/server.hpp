#pragma once

// Start the server on the given port (plain TCP). For tests only.
void start_server(int port);

// Start the server with TLS. Generates a self-signed cert on first run.
void start_server_tls(int port);

// Clear all server state. For testing only.
void reset_server_state();
