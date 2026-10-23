# ZeroTraceMsg Wire Protocol

**Version 1** — authoritative spec derived from `server/server.cpp`, `common/crypto.cpp`,
and `common/protocol.hpp`.

---

## 1. Transport

| Property | Value |
|---|---|
| Protocol | TCP |
| TLS | TLS 1.3 required; 1.2 permitted by config |
| Default port | 9999 (configurable via `zerotrace.conf`) |
| Server certificate | Self-signed; auto-generated on first run |
| Client certificate | None required |
| Cert pinning | TOFU — SHA-256 fingerprint saved to `users/.server_pin` on first connect |

The server generates a self-signed certificate at startup if none exists.  
On first TLS connect the client records the fingerprint; subsequent connects reject any cert
that does not match. To rotate, delete the pin file.

---

## 2. Framing

All messages in both directions are **newline-delimited ASCII lines**:

- Terminated by `\n` (LF only; no CR)
- Maximum length: **1 048 576 bytes** (1 MiB), including the `\n`
- Binary payloads are always **lowercase hex-encoded** on the wire

There is no binary frame header, no length prefix, and no TLV envelope.
Every command and every response is a single self-contained line.

---

## 3. Session Lifecycle

```
Client                            Server
  │                                  │
  ├── HELLO ZTM/1 ────────────────►  │  optional version handshake
  │◄──── OK ZTM/1 ─────────────────  │
  │                                  │
  ├── REGISTER <user_id> <pubkey> ►  │
  │◄──── OK <token> kem=… ─────────  │  token issued for this session
  │                                  │
  ├── GETKEY <user_id> ───────────►  │  look up any registered user
  │◄──── OK <pubkey_hex> ──────────  │
  │                                  │
  ├── SEND <id> <token> <rcpt> <blob>│  deliver encrypted message
  │◄──── OK ───────────────────────  │
  │                                  │
  ├── POLL <user_id> <token> ──────► │  check inbox (repeat on interval)
  │◄──── MSG <msg_id> <blob_hex> ──  │  zero or more messages (now in-flight)
  │◄──── ACK <N> ──────────────────  │  optional delivery confirmation
  │◄──── NOMSG ────────────────────  │  always the final POLL line
  │                                  │
  ├── MSGACK <id> <token> <ids> ───► │  confirm receipt; server deletes messages
  │                                  │
  ├── REKEY <old_id> <tok> <new_id> <key> ► │  optional key rotation
  │◄──── OK <new_token> ──────────  │
  │                                  │
  ├── DEREGISTER <user_id> <token> ► │  optional right-to-erasure
  │◄──── OK ───────────────────────  │
  │                                  │
  │  [close]                         │
```

---

## 4. Command Reference

### HELLO — version handshake

Optional. Old clients that skip HELLO go directly to REGISTER and are still accepted.
Sending an unsupported version causes the server to send `ERR` and close the connection.

**Request**

```
HELLO ZTM/<version>
```

| Field | Type | Description |
|---|---|---|
| version | uint | Protocol version integer; currently `1` |

**Responses**

| Response | Meaning |
|---|---|
| `OK ZTM/1` | Version accepted |
| `ERR version_mismatch supported=<N>` | Unsupported version; server closes connection after this |

---

### STATUS — health check

Unauthenticated. Safe for load balancers, Kubernetes probes, and monitoring agents.

**Request**

```
STATUS
```

**Response**

```
OK users=<N> sessions=<N> messages=<N> uptime=<N>
```

| Field | Description |
|---|---|
| users | Total registered users |
| sessions | Active sessions |
| messages | Total messages currently queued in all inboxes |
| uptime | Server uptime in seconds since last start |

---

### REGISTER — claim an identity

Associates a public key with a user ID. If the same user ID and the same public key are
registered again, the call is idempotent and issues a fresh session token. Registering the
same user ID with a **different** public key is rejected.

**Request**

```
REGISTER <user_id> <pubkey_hex>
```

| Field | Type | Description |
|---|---|---|
| user_id | 16 hex chars | First 8 bytes of SHA-256(pubkey_bytes), hex-encoded |
| pubkey_hex | hex | Public key bytes, hex-encoded; length is KEM-specific (see §7) |

**Success response**

```
OK <token> kem=<kem> cipher=<cipher> hash=<hash> pad=<N>
```

| Field | Description |
|---|---|
| token | 64 hex chars (32 random bytes); authenticate subsequent SEND, POLL, DEREGISTER |
| kem | KEM identifier, e.g. `ML-KEM-768` |
| cipher | AEAD cipher, e.g. `AES-256-GCM` |
| hash | Hash for HKDF, e.g. `SHA-256` |
| pad | Padded plaintext size in KB, e.g. `4` |

The client **must** compare `kem`, `cipher`, `hash`, and `pad` against its local config.
Any mismatch means encrypted blobs will fail to decrypt.

**Error responses**

| Error string | Meaning |
|---|---|
| `ERR pubkey size mismatch for configured KEM` | pubkey_hex length wrong for server's KEM |
| `ERR user_id does not match pubkey` | Supplied user_id ≠ SHA-256(pubkey)[0:8] |
| `ERR server has reached maximum user capacity` | `max_users` limit reached |
| `ERR user_id already registered with a different key` | Key change not allowed |
| `ERR invalid pubkey` | Hex decode of pubkey_hex failed |

---

### GETKEY — fetch a user's public key

**Request**

```
GETKEY <user_id>
```

**Responses**

| Response | Meaning |
|---|---|
| `OK <pubkey_hex>` | Public key bytes, hex-encoded |
| `ERR unknown user` | No such user_id |

---

### SEND — deliver an encrypted message

**Request**

```
SEND <sender_id> <token> <recipient_id> <blob_hex>
```

| Field | Description |
|---|---|
| sender_id | Sender's user_id (16 hex chars) |
| token | Session token from REGISTER (64 hex chars) |
| recipient_id | Recipient's user_id (16 hex chars) |
| blob_hex | Hex-encoded encrypted blob (see §6); length is 2 × max_blob_len |

The server stores and forwards the blob without decrypting it.

**Responses**

| Response | Meaning |
|---|---|
| `OK` | Message queued in recipient's inbox |
| `ERR invalid token` | Token missing, wrong, or session expired |
| `ERR rate limit exceeded` | Sender exceeded `rate_limit_msgs` in `rate_limit_window_s` |
| `ERR unknown recipient` | No such recipient_id |
| `ERR recipient inbox is full` | Recipient's inbox has `max_inbox_messages` queued |
| `ERR blob too large` | Blob exceeds `max_blob_len` for the configured KEM |
| `ERR invalid blob` | Hex decode of blob_hex failed |

---

### POLL — retrieve queued messages

**Request**

```
POLL <user_id> <token>
```

**Response sequence** (on success)

```
MSG <msg_id> <blob_hex>     ← zero or more, one per queued message
ACK <N>                     ← optional, sent once if N > 0
NOMSG                       ← always the final line
```

**Response** (on auth failure)

```
ERR invalid token
```

| Line | Description |
|---|---|
| `MSG <msg_id> <blob_hex>` | One queued message. `msg_id` is 32 hex chars (16 random bytes assigned by the server at send time). The blob is identical to what was submitted by the sender. |
| `ACK <N>` | Delivery acknowledgement: N of this user's previously sent messages have been picked up by their recipients in a prior POLL. Only sent if N > 0. |
| `NOMSG` | End of inbox; no more lines follow for this POLL. |

**Atomicity note:** Messages are dequeued from the server atomically when `MSG` lines are
sent. If the client crashes after receiving MSG lines but before processing them, those
messages are permanently lost. A two-phase ACK mechanism (future roadmap) will address this.

---

### MSGACK — confirm message receipt (phase 2 of delivery)

Must be sent after each POLL that returned at least one `MSG` line. The server deletes
the confirmed messages and credits delivery acknowledgements to their senders.

Until MSGACK is received the messages are held in an **in-flight** state. If the client
crashes before sending MSGACK, the server re-queues in-flight messages as pending after
a stale timeout (2 × `cleanup_interval_min`; default 20 minutes), so the client receives
them again on the next POLL after reconnecting.

**Request**

```
MSGACK <user_id> <token> <id1,id2,...>
```

| Field | Description |
|---|---|
| user_id | User's user_id (16 hex chars) |
| token | Session token from REGISTER (64 hex chars) |
| id1,id2,… | Comma-separated message IDs from the preceding POLL |

**Responses**

| Response | Meaning |
|---|---|
| `OK` | Messages deleted; delivery acks credited to senders |
| `ERR invalid token` | Token missing, wrong, or expired |

ACKing an ID that does not exist or belongs to a different recipient is silently ignored
(idempotent — safe to retry).

---

### DEREGISTER — delete all server-side user data

Implements the GDPR right to erasure. Removes the public key, session token, all queued
inbox messages, and the rate-limit state for this user.

**Request**

```
DEREGISTER <user_id> <token>
```

**Responses**

| Response | Meaning |
|---|---|
| `OK` | All server-side data for this user has been deleted |
| `ERR invalid token` | Token missing, wrong, or expired |

---

### REKEY — rotate to a new keypair

Replaces the caller's long-term keypair with a new one in a single atomic operation.
Pending inbox messages are migrated to the new identity so they are not lost.
The old identity (public key, session, rate-limit state) is deleted.

Use this command to rotate keys after a suspected compromise, on a scheduled basis,
or whenever a fresh post-quantum keypair is desired.

**Request**

```
REKEY <old_user_id> <old_token> <new_user_id> <new_pubkey_hex>
```

| Field | Description |
|---|---|
| old_user_id | Current user_id (16 hex chars) |
| old_token | Current session token (64 hex chars) |
| new_user_id | New user_id derived from new pubkey: `hex(SHA-256(new_pubkey)[0:8])` |
| new_pubkey_hex | New public key bytes, hex-encoded |

**Success response**

```
OK <new_token>
```

`new_token` is a fresh 64 hex-char session token for the new identity.
The caller must update their local identity file and inform contacts of the new user_id.

**Error responses**

| Error string | Meaning |
|---|---|
| `ERR invalid token` | old_token missing, wrong, or session expired |
| `ERR pubkey size mismatch for configured KEM` | new pubkey length wrong for server's KEM |
| `ERR new user_id does not match new pubkey` | new_user_id ≠ hex(SHA-256(new_pubkey)[0:8]) |
| `ERR cannot rekey to the same identity` | new_user_id equals old_user_id |
| `ERR new user_id already registered with a different key` | Key conflict for new_user_id |
| `ERR invalid pubkey` | Hex decode of new_pubkey_hex failed |
| `ERR missing arguments` | One or more fields empty |

**Atomicity guarantee:** The server performs all mutations under a single lock:
register new identity → migrate inbox → carry over delivery acks → delete old identity.
Either the full rotation succeeds or the original state is unchanged.

---

### Unknown command

Any unrecognized command verb receives:

```
ERR unknown command
```

The connection remains open; subsequent commands are still accepted.

---

## 5. Field Types

| Field | Format | Length | Example |
|---|---|---|---|
| user_id | hex | 16 chars (8 bytes) | `a1b2c3d4e5f60718` |
| token | hex | 64 chars (32 bytes) | (random) |
| msg_id | hex | 32 chars (16 bytes) | (random) |
| pubkey_hex | hex | KEM-dependent (see §7) | — |
| blob_hex | hex | 2 × max_blob_len | — |

**user_id derivation:**

```
user_id = hex( SHA-256(pubkey_bytes)[0:8] )
```

---

## 6. Encrypted Blob

Every blob has this exact binary layout:

```
+--------------------------------+-----------------------------------+
|       KEM ciphertext           |   AEAD ciphertext  |  AEAD tag   |
|  kem_ct_len bytes              |  padded_plaintext_bytes           | 16 B |
+--------------------------------+-----------------------------------+
```

Sizes with the **default config** (ML-KEM-768, AES-256-GCM, pad=4 KB):

| Part | Bytes |
|---|---|
| KEM ciphertext | 1088 |
| AEAD ciphertext | 4096 |
| AEAD tag | 16 |
| **Total blob** | **5200** |
| **Total blob_hex** | **10 400 chars** |

KEM ciphertext lengths for all supported algorithms are listed in §7.

---

### 6.1 Plaintext layout (inside the AEAD)

Before encryption, the plaintext is assembled and **zero-padded to exactly
`padded_plaintext_kb × 1024` bytes**. Padding hides message length from the server.

```
Offset          Length          Field
──────────────  ──────────────  ──────────────────────────────────────────
0               16              msg_nonce    — 16 random bytes; replay nonce
16              16              sender_id    — sender's user_id (ASCII hex)
32              1               name_len     — length of sender_name (0–255)
33              name_len        sender_name  — sender's chosen username
33 + name_len   2               msg_len      — message length, big-endian uint16
35 + name_len   msg_len         message      — UTF-8 message text
35 + name_len   padding to end  zero bytes   — padding to padded_plaintext_kb × 1024
  + msg_len
```

`msg_nonce` is distinct from the AEAD nonce: it is a random value sealed inside the
ciphertext, used only by the client's replay-detection guard (`ReplayGuard`). The AEAD
nonce is derived deterministically from the KEM shared secret via HKDF (see §6.2).

**Maximum message length** with default config (4 KB pad):

```
max_message_bytes = 4096 − 35 − name_len
```

For a username of 8 characters this is 4053 bytes; for the maximum 255-character username
it is 3806 bytes.

---

### 6.2 Key derivation

The AEAD key and nonce are derived fresh for every message from the KEM shared secret:

```
Step 1 — KEM encapsulation (sender)
  (kem_ct, shared_secret) = KEM.encapsulate(recipient_pubkey)

Step 2 — HKDF-Extract
  salt = kem_ct ‖ recipient_pubkey
  PRK  = HKDF-Extract(hash, IKM=shared_secret, salt=salt)

  Including recipient_pubkey in the salt binds the derived key to the
  intended recipient, preventing cross-recipient decryption attacks.

Step 3 — HKDF-Expand: AEAD key
  aead_key = HKDF-Expand(hash, PRK, info="aes-key", len=key_len)

Step 4 — HKDF-Expand: AEAD nonce
  aead_nonce = HKDF-Expand(hash, PRK, info="aes-iv", len=12)

Step 5 — AEAD encryption
  ciphertext ‖ tag = AEAD.Encrypt(key=aead_key, nonce=aead_nonce, pt=padded_plaintext)

Step 6 — blob assembly
  blob = kem_ct ‖ ciphertext ‖ tag
```

**Decryption** reverses steps 5→1: split blob at `kem_ct_len`, decapsulate to recover
`shared_secret`, re-derive `aead_key` and `aead_nonce` via steps 2–4, then AEAD-decrypt.

| Derived value | Length | Info label |
|---|---|---|
| `aead_key` | 32 B (AES-256-GCM, ChaCha20Poly1305) or 16 B (AES-128-GCM) | `aes-key` |
| `aead_nonce` | 12 B | `aes-iv` |

---

## 7. KEM Algorithm Reference

All sizes in bytes. Wire sizes (hex) are double.

| KEM | Pubkey bytes | KEM CT bytes | Total blob (pad=4 KB) |
|---|---|---|---|
| ECDH-P256 | 65 | 65 | 4177 |
| ECDH-P384 | 97 | 97 | 4209 |
| ML-KEM-512 | 800 | 768 | 4880 |
| **ML-KEM-768** (default) | **1184** | **1088** | **5200** |
| ML-KEM-1024 | 1568 | 1568 | 5680 |
| HYBRID-P256-ML-KEM-768 | 1249 | 1153 | 5265 |
| HYBRID-P384-ML-KEM-1024 | 1665 | 1665 | 5777 |

For hybrid KEMs the public key is `primary_pubkey ‖ ml_kem_pubkey` and the KEM ciphertext
is `primary_ct ‖ ml_kem_ct`. Both parts are encapsulated independently; their shared secrets
are concatenated before HKDF-Extract.

---

## 8. Error Code Index

All errors follow the form `ERR <description>`. The description is a fixed ASCII string.

| Description | Command(s) | Meaning |
|---|---|---|
| `version_mismatch supported=<N>` | HELLO | Unsupported protocol version; server closes |
| `pubkey size mismatch for configured KEM` | REGISTER | Wrong pubkey byte length for server's KEM |
| `user_id does not match pubkey` | REGISTER | user_id ≠ hex(SHA-256(pubkey)[0:8]) |
| `server has reached maximum user capacity` | REGISTER | `max_users` cap hit |
| `user_id already registered with a different key` | REGISTER | Key-change attempt rejected |
| `invalid pubkey` | REGISTER | Hex decode of pubkey_hex failed |
| `unknown user` | GETKEY | No registered user with that user_id |
| `invalid token` | SEND, POLL, MSGACK, DEREGISTER | Token absent, wrong, or session expired |
| `rate limit exceeded` | SEND | Sender exceeded `rate_limit_msgs` per `rate_limit_window_s` |
| `unknown recipient` | SEND | No registered user with that recipient_id |
| `recipient inbox is full` | SEND | Recipient's inbox at `max_inbox_messages` |
| `blob too large` | SEND | Blob exceeds `kem_ct_len + padded_plaintext + 16` |
| `invalid blob` | SEND | Hex decode of blob_hex failed |
| `invalid token` | REKEY | old_token missing, wrong, or session expired |
| `new user_id does not match new pubkey` | REKEY | new_user_id derivation mismatch |
| `cannot rekey to the same identity` | REKEY | new_user_id equals old_user_id |
| `new user_id already registered with a different key` | REKEY | Key conflict for new_user_id |
| `missing arguments` | REKEY | One or more required fields empty |
| `unknown command` | any | Unrecognised command verb |

---

## 9. Protocol Constants

Defined in `common/protocol.hpp`. Default-config values shown.

| Constant | Value | Description |
|---|---|---|
| `PROTOCOL_VERSION` | 1 | Version integer used in HELLO |
| `SERVER_PORT` | 9999 | Default TCP port |
| `USER_ID_LEN` | 16 | hex chars (8 bytes) |
| `MSG_NONCE_LEN` | 16 | bytes; random replay-detection nonce inside plaintext |
| `ML_KEM_PUBKEY_LEN` | 1184 | bytes; ML-KEM-768 public key |
| `KEM_CIPHERTEXT_LEN` | 1088 | bytes; ML-KEM-768 KEM ciphertext prefix in blob |
| `PADDED_PLAINTEXT_LEN` | 4096 | bytes; fixed plaintext length before encryption |
| `GCM_TAG_LEN` | 16 | bytes; AES-256-GCM authentication tag |
| `MAX_BLOB_LEN` | 5200 | bytes; total blob size (ML-KEM-768 defaults) |
| `MAX_LINE_LEN` | 1 048 576 | bytes; maximum wire line length |
| `RATE_LIMIT_MSGS` | 20 | max messages per user per window |
| `RATE_LIMIT_WINDOW_S` | 60 | rate-limit window duration in seconds |
| `POLL_INTERVAL_S` | 3 | client poll interval in seconds |
| `MSG_TTL_CLIENT_S` | 120 | client wipes decrypted messages after 2 minutes |
| `MSG_TTL_SERVER_S` | 172 800 | server TTL for undelivered messages (48 hours) |

---

## 10. Security Properties

**Sealed sender.** The sender's user_id and username are encrypted inside the blob.
The server forwards opaque blobs; server logs never reveal who sent a message to whom.

**Forward secrecy per message.** Every message uses a fresh KEM encapsulation. Compromise
of the recipient's long-term private key exposes past messages only if the attacker also
retained the ciphertext blobs.

**Post-quantum security.** The default KEM (ML-KEM-768) is a NIST-standardised
lattice-based scheme providing ~192-bit post-quantum security. Hybrid modes
(HYBRID-P256-ML-KEM-768, HYBRID-P384-ML-KEM-1024) additionally provide classical
ECDH security, so breaking either algorithm alone is insufficient.

**Message padding.** All plaintexts are zero-padded to a fixed length before encryption.
The server cannot infer message length from blob size.

**Replay detection.** The 16-byte `msg_nonce` inside each plaintext is checked against a
sliding recent-nonces window on the client. Replayed blobs (same nonce) are silently
discarded.

**Constant-time token comparison.** Session tokens are compared byte-by-byte with XOR
accumulation to prevent timing-based token oracle attacks.

**No persistent sessions on the wire.** There is no persistent connection ID or cookie
visible outside the TLS layer. Each TCP connection is independent.

---

## 11. Admin Protocol

The server exposes a separate **admin port** (default 9998) that binds to `127.0.0.1` only.
It uses the same line-based framing as the main protocol but requires no TLS and no auth —
access control is delegated to the OS (only local processes can connect).

Use `msg_admin` to interact with it:

```
msg_admin [--port PORT] stats
msg_admin [--port PORT] list-users
msg_admin [--port PORT] kick <user_id>
msg_admin [--port PORT] reload
```

Set `admin_port = 0` in `zerotrace.conf` to disable the admin interface entirely.

### Admin commands

| Command | Request | Response |
|---|---|---|
| `STATS` | `STATS` | `OK users=N sessions=N messages=N connections=N uptime=N` |
| `LIST_USERS` | `LIST_USERS` | `USER <id>` lines, then `END` |
| `KICK <user_id>` | `KICK <user_id>` | `OK` or `ERR unknown user` |
| `RELOAD` | `RELOAD` | `OK` (triggers SIGHUP-equivalent hot-reload) |

`KICK` performs a full user removal: public key, session, inbox, and rate-limit state are
all deleted. It is equivalent to an admin-initiated DEREGISTER.

---

## 12. Configurable Protocol Parameters

The following parameters are marked `[protocol]` in `zerotrace.conf` and **must be
identical** across all clients and the server in a deployment. Mismatches cause decryption
failures.

| Parameter | Config key | Default |
|---|---|---|
| KEM algorithm | `kem` | `ML-KEM-768` |
| AEAD cipher | `cipher` | `AES-256-GCM` |
| HKDF hash | `hash` | `SHA-256` |
| Padded plaintext size | `padded_plaintext_kb` | `4` |
| Server port | `port` | `9999` |
| Message TTL | `msg_ttl_hours` | `48` |

The server echoes its configured values in the REGISTER response (`kem=`, `cipher=`,
`hash=`, `pad=`). Clients should warn the user if any value differs from the client config.
