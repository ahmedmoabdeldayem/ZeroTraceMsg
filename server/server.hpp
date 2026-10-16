#pragma once

// Start the server on the given port. Blocks forever — run in a detached thread.
void start_server(int port);

// Clear all server state. For testing only.
void reset_server_state();
