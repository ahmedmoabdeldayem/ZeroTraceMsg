# ZeroTraceMsg

[![CI](https://github.com/ahmedmoabdeldayem/ZeroTraceMsg/actions/workflows/ci.yml/badge.svg)](https://github.com/ahmedmoabdeldayem/ZeroTraceMsg/actions/workflows/ci.yml)
[![CodeQL](https://github.com/ahmedmoabdeldayem/ZeroTraceMsg/actions/workflows/codeql.yml/badge.svg)](https://github.com/ahmedmoabdeldayem/ZeroTraceMsg/actions/workflows/codeql.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A secure CLI messaging application built on [Botan](https://github.com/randombit/botan).

Messages are end-to-end encrypted and auto-delete after delivery. The server cannot read message content or the sender's identity.

---

## Security Properties

- **End-to-end encrypted** — per-message hybrid encryption using a configurable KEM + HKDF + AEAD cipher (default: ML-KEM-768 + AES-256-GCM, quantum-resistant)
- **Sealed sender** — sender identity is encrypted inside the message; the server only knows the recipient
- **Ephemeral key encapsulation** — a fresh ciphertext is generated for every message; no shared secret is ever reused
- **Replay protection** — each message carries a sealed random nonce; the client silently drops any blob it has already seen
- **Auto-delete** — messages are wiped from the client after 2 minutes and from the server after 48 hours if unread
- **Anonymous identity** — user ID derived from a public key hash; no name, email, or phone number required
- **Session tokens** — 256-bit random tokens issued on REGISTER; comparison is constant-time
- **Memory locking** — private key material locked with `mlock()` to prevent swapping to disk
- **Fixed-size blobs** — all messages padded to a fixed plaintext size before encryption; server cannot infer message length
- **TLS transport** — all connections wrapped in TLS (configurable: 1.2 or 1.3); session tokens, recipient IDs, and timing are hidden from network observers
- **Configurable KEM** — operators choose from 12 supported algorithms (see table below)

---

## Supported Algorithms

### Key Encapsulation (KEM)

| Algorithm | Type | Security | Notes |
|---|---|---|---|
| `ML-KEM-768` | Post-quantum | 192-bit | **Default** — NIST PQC standard |
| `ML-KEM-512` | Post-quantum | 128-bit | Smaller keys |
| `ML-KEM-1024` | Post-quantum | 256-bit | Larger keys |
| `HYBRID-P256-ML-KEM-768` | Hybrid | Classical + PQ | Belt-and-suspenders |
| `HYBRID-P384-ML-KEM-1024` | Hybrid | Classical + PQ | Stronger hybrid |
| `HYBRID-X25519-ML-KEM-768` | Hybrid | Classical + PQ | X25519 + post-quantum |
| `X25519` | Classical | 128-bit | Used in TLS 1.3 and Signal |
| `ECDH-P256` | Classical | 128-bit | NIST P-256 |
| `ECDH-P384` | Classical | 192-bit | NIST P-384 |
| `RSA-2048` | Classical | 112-bit | Legacy |
| `RSA-3072` | Classical | 128-bit | Legacy |
| `RSA-4096` | Classical | 140-bit | Legacy |

### Symmetric Cipher

`AES-256-GCM` (default) · `AES-128-GCM` · `ChaCha20Poly1305`

### Hash (HKDF)

`SHA-256` (default) · `SHA-384` · `SHA-512` · `SHA3-256`

---

## Requirements

- macOS (Apple Silicon or Intel)
- Xcode Command Line Tools: `xcode-select --install`
- Python 3 (for Botan's build script)

---

## Setup

**1. Clone with submodules:**
```bash
git clone --recurse-submodules https://github.com/ahmedmoabdeldayem/ZeroTraceMsg
cd ZeroTraceMsg
```

**2. Build Botan (~5 minutes, run once):**
```bash
make setup
```

**3. Build the server and client:**
```bash
make all
```

**4. Run tests:**
```bash
make test          # 1186 tests across 6 suites
make system-test   # binary-level tests (starts actual executables)
make sanitize      # rerun under ASan + UBSan
make coverage      # LLVM coverage report → coverage_report/index.html
```

---

## Configuration

All operator settings live in `zerotrace.conf` in the directory you run the binary from. The file is committed with defaults and full documentation.

```bash
./build/msg_server                          # loads ./zerotrace.conf
./build/msg_server /etc/zerotrace.conf      # explicit path
./build/msg_client alice 127.0.0.1          # loads ./zerotrace.conf
./build/msg_client alice host --config /path/to/zerotrace.conf
```

Key settings:

```ini
[server]
port              = 9999
max_users         = 0         ; 0 = unlimited
session_ttl_hours = 24

[crypto]
kem    = ML-KEM-768           ; see supported algorithms above
cipher = AES-256-GCM
hash   = SHA-256

[logging]
level  = info                 ; debug | info | warn | error
format = text                 ; text | json
```

See `zerotrace.conf` for the complete reference with all options and valid values.

---

## Running

**Terminal 1 — start the server:**
```bash
./build/msg_server
```

**Terminal 2 — first user:**
```bash
./build/msg_client alice 127.0.0.1
```

**Terminal 3 — second user:**
```bash
./build/msg_client bob 127.0.0.1
```

Your user ID is shown at the top of the screen. Share it with the other person out of band.

---

## Usage

**Send a single-line message:**
```
> <recipient_id> hello
```

**Send a multi-line message** (type `.` alone to send):
```
> alice
... first line
... second line
... .
```

**Add a contact nickname:**
```
> add <recipient_id> alice
```

**Send using a nickname:**
```
> alice hello
```

**Quit:**
```
> quit
```

---

## Project Structure

```
ZeroTraceMsg/
├── common/
│   ├── config.hpp/cpp         Operator configuration — INI parser, validation, derived helpers
│   ├── kem.hpp/cpp            KEM abstraction — ECDH, X25519, ML-KEM, RSA, Hybrid modes
│   ├── crypto.hpp/cpp         Hybrid encryption pipeline (KEM + HKDF + AEAD)
│   ├── identity.hpp/cpp       Key generation, save/load (Argon2id/PBKDF2 protected)
│   ├── protocol.hpp           Shared constants (wire format, limits)
│   ├── replay.hpp             Replay-nonce tracking
│   └── secure_memory.hpp      SecureString — zeroed on destruction
├── server/
│   ├── server.hpp/cpp         Protocol handler, token auth, rate limiting, message routing
│   └── main.cpp               Entry point — loads config, starts TLS server
├── client/main.cpp            CLI, TLS client, polling loop, contacts, ANSI display
├── tests/
│   ├── test_config.cpp        879 tests — config, all KEM x cipher x hash combos (144 total)
│   ├── test_identity.cpp       78 tests — key gen, save/load, all KEMs, KDF variants
│   ├── test_crypto.cpp         25 tests — encrypt/decrypt, tamper detection
│   ├── test_protocol.cpp       16 tests — full send/receive pipeline
│   ├── test_replay.cpp        116 tests — nonce deduplication, thread safety
│   ├── test_server.cpp         72 tests — server protocol over plain TCP and TLS
│   └── test_system.sh              — binary-level system tests (actual executables)
├── zerotrace.conf             Documented default configuration
├── CHANGELOG.md               Version history
├── CONTRIBUTING.md            Development workflow
└── SECURITY.md                Vulnerability reporting policy
```

---

## Known Limitations

- **IP visibility** — the server sees client IP addresses and recipient user IDs
- **TLS certificate not pinned** — the client accepts any self-signed certificate; pin `certs/server.cert.pem` for production
- **Unverified usernames** — display names are self-declared inside the encrypted payload
- **Contacts file is plaintext** — `users/<name>.contacts` leaks your social graph on a shared machine
- **Delivery confirmation is approximate** — `[delivered]` appears when the recipient polls, not when they read

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).
Security issues: see [SECURITY.md](SECURITY.md) — **do not open public issues for vulnerabilities**.
