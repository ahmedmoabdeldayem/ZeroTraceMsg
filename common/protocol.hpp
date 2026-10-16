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
// Message padding — all plaintexts are padded to this fixed size before encryption
// so the server cannot infer message length from blob size.
static constexpr size_t PADDED_PLAINTEXT_LEN = 4 * 1024; // 4 KB fixed plaintext
static constexpr size_t GCM_TAG_LEN = 16;                // AES-256-GCM authentication tag
static constexpr size_t MAX_BLOB_LEN = PUBKEY_LEN + PADDED_PLAINTEXT_LEN + GCM_TAG_LEN; // 4177 B

// Rate limiting
static constexpr int RATE_LIMIT_MSGS = 20;     // max messages per user per window
static constexpr int RATE_LIMIT_WINDOW_S = 60; // window duration in seconds
