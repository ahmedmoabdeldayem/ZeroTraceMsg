# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- `X25519` KEM option (Curve25519 ECDH — used in TLS 1.3 and Signal)
- `HYBRID-X25519-ML-KEM-768` KEM option (X25519 + ML-KEM-768 combined)
- `RSA-2048`, `RSA-3072`, `RSA-4096` KEM options (RSA-OAEP; legacy support)
- TLS certificate tests for ECDSA-P384 and Ed25519 cert algorithms
- Test coverage improvements: `config.cpp` now at 100% line coverage

### Fixed
- `AES-128-GCM` cipher now correctly derives a 16-byte key (was incorrectly deriving 32 bytes)
- Argon2id `from_params` parameter order corrected to `(M, t, p)` per Botan 3 API

---

## [3.0.0] - 2026-10-18

### Added
- **Operator configuration system** — all settings now live in `zerotrace.conf` (INI format)
  - `[server]`: port, bind address, max users, inbox cap, session TTL, rate limits, cert paths
  - `[client]`: server address, poll interval, message TTL, connection timeout, identity directory
  - `[tls]`: minimum TLS version, cert algorithm (ECDSA-P256/384, Ed25519), cert validity
  - `[crypto]`: KEM algorithm, cipher, hash, padding size, passphrase KDF and parameters
  - `[logging]`: level (debug/info/warn/error), output file, format (text/json)
- All crypto and identity functions now accept `Config`; hardcoded constants replaced
- `common/config.hpp` + `config.cpp` — INI parser with full validation and descriptive errors
- `common/kem.hpp` + `kem.cpp` — unified KEM abstraction over all supported algorithms
- `zerotrace.conf` committed to the repo root as a documented default configuration
- 1,186 tests across 6 test suites (up from 243)
- `test_config.cpp` — 879 tests covering all config options, all KEM × cipher × hash combos (144 total), and every validation error path
- Server now advertises crypto parameters in the `REGISTER OK` response for client compatibility checking
- JSON structured logging support for log aggregators (ELK, Splunk, etc.)

### Fixed
- Cleanup thread now respects `session_ttl_hours` from config (was never purging sessions)

---

## [2.0.0] - 2024-XX-XX

### Added
- **Post-quantum encryption** — replaced ECDH with ML-KEM-768 (NIST PQC standard, 192-bit security)
- TLS transport — all connections now wrapped in TLS 1.3 with a self-signed ECDSA cert
- Delivery confirmation — `ACK <n>` line in POLL response; client shows `[delivered]`
- Multi-line message input — type recipient alone, enter lines, send with `.`
- Fixed-size blobs — all messages padded to 4 KB before encryption (hides message length)
- Per-user rate limiting — 20 messages per 60-second window
- `MAX_BLOB_LEN` enforcement on SEND to prevent oversized blob DoS

### Changed
- Key encapsulation upgraded from ECDH-P256 (classical) to ML-KEM-768 (post-quantum)
- Identity files now store the 64-byte ML-KEM seed instead of a 32-byte EC scalar

---

## [1.0.0] - 2024-XX-XX

### Added
- End-to-end encrypted messaging over TCP
- Hybrid encryption: ECDH-P256 + HKDF + AES-256-GCM per message
- Sealed sender: sender identity encrypted inside the message blob
- Replay protection: 16-byte nonce per message, client tracks seen nonces
- Session tokens: 32-byte random tokens issued on REGISTER
- Argon2id passphrase KDF for identity file encryption
- Auto-delete: messages wiped after 2 minutes client-side, 48 hours server-side
- Memory locking: private keys locked with `mlock()` to prevent swap exposure
- Contacts: `users/<name>.contacts` for ID-to-nickname mappings
- ANSI terminal display with live countdown for ephemeral messages
