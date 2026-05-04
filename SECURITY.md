# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 1.0.x | Yes |

## Reporting a Vulnerability

**Do not report security vulnerabilities through public GitHub issues.**

To report a vulnerability:

1. Email the maintainer directly. The email address is in the git commit history or the GitHub profile.
2. Describe the vulnerability, the affected component (TCB or orchestration layer), and steps to reproduce.
3. Allow up to 72 hours for an initial response.
4. Allow up to 14 days for a fix before public disclosure.

## What Counts as a Vulnerability

**Critical — TCB (phantom_core/src/):**
- Any condition where key material leaks to Python memory
- Any bypass of the HMAC header verification
- Any nonce reuse in AES-256-GCM-SIV or ChaCha20-Poly1305
- Memory not zeroed after key use
- Incorrect Shamir reconstruction producing wrong output silently

**High — Orchestration layer:**
- Vault container accepting tampered data without error
- Session handle remaining valid after lock_session() is called
- Source directory files not cleared after vault lock

**Not a vulnerability (by design):**
- Filesystem journal recording file history before vaulting
- A compromised OS kernel defeating mlock protection
- Hibernation writing memory to disk (warned at startup, documented)
- The vault header revealing that two regions exist

## Cryptographic Agility

PhantomVault v1.0 does not support algorithm negotiation at runtime. The cipher is chosen at vault creation time and authenticated in the header HMAC. Any attempt to change the cipher in the header without the key will fail HMAC verification.
