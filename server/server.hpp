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

// Test helpers that expose internal server state for coverage of otherwise-unreachable paths.
void expire_session_for_test(const std::string& user_id, const std::string& token);
void reset_rate_bucket_window_for_test(const std::string& user_id);
void prune_sessions_for_test();
void call_log_init_for_test(const Config& cfg);
void set_config_path_for_test(const std::string& path);
// Call handle_signal() directly — covers its branches without sending real OS signals.
void call_handle_signal_for_test(int sig);
// Set reload/log-reopen flags directly — accept loop processes them within 1 s.
void trigger_reload_for_test();
void trigger_log_reopen_for_test();
