# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 1.0.x | ✅ Yes |

---

## Reporting a Vulnerability

> [!CAUTION]
> **Do not open a public GitHub issue for security vulnerabilities.**

To report a vulnerability privately:

1. Email the maintainer directly. The address is in the git commit history or GitHub profile.
2. Include: affected component (TCB or orchestration layer), description, and steps to reproduce.
3. Allow **72 hours** for an initial response.
4. Allow **14 days** for a fix before public disclosure.

---

## What Counts as a Vulnerability

### Critical — TCB (`phantom_core/src/`)

| Condition | Severity |
|---|---|
| Key material leaks to Python memory | Critical |
| HMAC header verification bypass | Critical |
| Nonce reuse in AES-256-GCM-SIV or ChaCha20 | Critical |
| Keys not zeroed after use | Critical |
| Incorrect Shamir reconstruction with no error | Critical |

### High — Orchestration layer (`phantomvault/`)

| Condition | Severity |
|---|---|
| Tampered container accepted without error | High |
| Session handle valid after `lock_session()` | High |
| Source directory not cleared after lock | High |

### Not a Vulnerability (by design)

These are documented limitations, not bugs:

- Filesystem journal recording file history before vaulting
- A compromised OS kernel defeating mlock protection
- Hibernation writing memory to disk (warned at startup)
- The vault header showing that two encrypted regions exist
- Hardware keyloggers capturing the password before software sees it

---

## Cryptographic Design

PhantomVault v1.0 does not support cipher negotiation at runtime. The cipher is chosen at vault creation and authenticated in the header HMAC. Changing the cipher byte in the header without the key fails HMAC verification immediately.

---

## Known Accepted Advisories

| Advisory | Component | Status | Rationale |
|---|---|---|---|
| RUSTSEC-2024-0398 | sharks (Shamir) | Accepted — v1.5 fix | Requires 500-1500 repeated distributions of same secret. PhantomVault distributes once per vault. |
| RUSTSEC-2025-0020 | pyo3 (FFI) | Accepted | Vulnerable function `PyString::from_object` never called in PhantomVault code paths. |
