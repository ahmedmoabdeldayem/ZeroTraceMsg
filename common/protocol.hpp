#pragma once
#include <cstdint>
#include <string>

// Network
static constexpr int SERVER_PORT = 9999;

// Timing
static constexpr int POLL_INTERVAL_S = 3;       // client polls every 3 seconds
static constexpr int MSG_TTL_CLIENT_S = 120;    // client deletes after 2 minutes
static constexpr int MSG_TTL_SERVER_S = 172800; // server deletes after 48 hours

// Sizes
static constexpr size_t USER_ID_LEN = 16;   // 16 hex chars (8 bytes of SHA-256)
static constexpr size_t PUBKEY_LEN = 65;    // uncompressed P-256 public key
static constexpr size_t MSG_NONCE_LEN = 16; // random nonce sealed in payload for replay detection
static constexpr size_t MAX_LINE_LEN = 1024 * 1024; // 1 MB max line length
static constexpr size_t MAX_BLOB_LEN =
    8 * 1024; // 8 KB max encrypted blob (tightened when padding lands)
