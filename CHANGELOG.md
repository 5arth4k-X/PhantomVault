# Changelog

All notable changes to PhantomVault are documented here.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html)

---

## [Unreleased] — v1.5

### Planned
- macOS and Windows support
- TOTP second factor (pyotp)
- FIDO2 / YubiKey second factor (python-fido2)
- Two-process watchdog daemon (watcher + watchdog via Unix socket)
- HMAC-chained audit log with remote anchoring
- Shamir recovery export with BIP-39 word encoding
- Remote attestation — nonce-based challenge-response

---

## [1.0.0] — 2026-05-03

### Rust Trusted Computing Base (`phantom_core`)

- `memory.rs` — `SecretBytes` type: mlock, ZeroizeOnDrop, constant-time comparison, catch_unwind
- `crypto.rs` — AES-256-GCM-SIV (nonce-misuse-resistant), ChaCha20-Poly1305, Argon2id (enforced minimums), HKDF-SHA256
- `header.rs` — 256-byte authenticated vault header, HMAC-SHA256, downgrade-resistant KDF enforcement
- `input.rs` — Rust TTY password reading via rpassword (Python never holds the password)
- `hmac.rs` — HMAC-SHA256 audit chain with chained entries (deletion detectable)
- `shamir.rs` — Shamir secret sharing via sharks crate with mandatory self-test on every export
- `lib.rs` — PyO3 exports using opaque session handles — no key material crosses the FFI boundary

### Python Orchestration Layer

- `cli.py` — Typer/Rich CLI: create, unlock, lock, remove, status, panic, about, version
- `vault.py` — Vault lifecycle management with alias system
- `stealth.py` — Secure file deletion (random rename chains), mtime randomisation ±72 hours
- `vault_region.py` — Two independent encrypted compartments accessible with separate passwords
- `container/portable.py` — Container file backend: CSPRNG-padded binary container
- `obfuscation.py` — Poisson-distributed dummy I/O (statistically indistinguishable from human access)
- `hibernation.py` — Startup hibernation detection and warning
- `modes.py` — Security mode detection (SECURE / KERNEL / PORTABLE)
- `utils/aliases.py` — Vault name to container path mapping
- `utils/warnings.py` — Rich-formatted security warnings

### Security Properties Implemented

- Keys zero on lock via `ZeroizeOnDrop` and explicit `zero_now()`
- Keys zero on panic via `catch_unwind` with `ZeroOnDrop` guard
- Keys mlock'd — not swappable when `RLIMIT_MEMLOCK = unlimited`
- Header tamper detection including padding bytes (`verify_hmac_raw`)
- KDF parameter minimums enforced in code — downgrade attacks rejected at parse time
- Constant-time HMAC comparison via `subtle` crate

### Testing

- 144 unit tests across all 6 TCB modules
- 9 integration tests covering full vault lifecycle
- 4 fuzz targets: fuzz_crypto, fuzz_header, fuzz_shamir, fuzz_hmac

### Documentation

- `docs/VAULT_FORMAT_v1.md` — Complete binary format specification
- `docs/THREAT_MODEL.md` — T1 through T4 attacker tiers with honest capabilities
- `docs/SECURITY.md` — Cryptographic design, known limitations, legal disclaimer
- `docs/AUDIT_PLAN.md` — TCB definition, testing strategy, external review roadmap
- `docs/VERSIONING.md` — Release process and vault format versioning

### Known Limitations in v1.0

- Linux only — macOS and Windows in v1.5
- Filesystem journal may retain pre-vault filenames — use fresh volumes for maximum stealth
- Hibernation writes RAM to disk — warned at startup, disable for maximum security
- No TOTP or FIDO2 second factor — v1.5
- No remote attestation — v1.5
- No TPM hardware binding — v2.0
- Shamir recovery export is a stub — full implementation in v1.5
