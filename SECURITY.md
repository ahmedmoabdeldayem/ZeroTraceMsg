# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| latest on `main` | ✅ |
| older tags | ❌ |

Only the latest commit on `main` receives security fixes. There are no long-term support branches.

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Report vulnerabilities by emailing:

**ahmed.mo.abdeldayem@gmail.com**

Include in your report:
- A description of the vulnerability and its potential impact
- Steps to reproduce or a proof-of-concept
- The affected component (`common/crypto`, `server/`, `client/`, etc.)
- Any suggested mitigations if you have them

You will receive an acknowledgement within **48 hours**. We aim to release a fix within **7 days** for critical issues and **30 days** for lower-severity ones.

We will credit you in the release notes unless you request otherwise.

## Scope

In scope:
- Cryptographic weaknesses in the encryption pipeline (`common/crypto.cpp`, `common/kem.cpp`)
- Authentication bypasses in the server protocol (`server/server.cpp`)
- Private key exposure in identity save/load (`common/identity.cpp`)
- TLS misconfigurations
- Memory safety issues (buffer overflows, use-after-free, etc.)

Out of scope:
- The known limitations listed in the README (TLS cert not pinned, plaintext contacts file, IP visibility)
- Vulnerabilities in the Botan library itself — report those to the [Botan project](https://github.com/randombit/botan/security/advisories/new)
- Denial-of-service attacks that require physical access to the server machine

## Security Design Notes

- Messages are encrypted end-to-end with a post-quantum hybrid KEM (configurable: ML-KEM, ECDH, X25519, RSA, or hybrid modes)
- The server stores only encrypted blobs and never has access to plaintext or sender identity
- Session tokens are 32 random bytes (256-bit entropy); comparison is constant-time
- Passphrases are stretched with Argon2id (64 MB, 3 passes, 1 thread by default) before any key material is derived
