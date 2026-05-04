# Changelog

All notable changes to PhantomVault are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] — 2026-05-03

### Added
- Rust Trusted Computing Base (phantom_core) — 6 files, ~2000 lines
- AES-256-GCM-SIV primary encryption (nonce-misuse-resistant)
- ChaCha20-Poly1305 alternative encryption for platforms without AES-NI
- Argon2id key derivation with enforced minimums (t≥3, m≥64MB, p≥4)
- HKDF-SHA256 session key derivation (no timestamp, CSPRNG nonce only)
- HMAC-SHA256 authenticated 256-byte vault header
- Two independent encrypted storage compartments per vault
- Shamir secret sharing with mandatory self-test on export
- Rust TTY password reading via rpassword (Python never holds password)
- SecretBytes type — mlock'd, ZeroizeOnDrop, constant-time comparison
- catch_unwind wrapping all TCB entry points
- Portable container backend (Linux, no root required)
- Ghost directory stealth — source directory left empty when locked
- Poisson-distributed dummy I/O for access pattern obfuscation
- mtime randomisation ±72 hours on all vault operations
- Hibernation detection and warning at startup
- Typer/Rich CLI with create, unlock, lock, remove, status, panic, about
- HMAC-chained audit log infrastructure
- Session handle system — opaque integer handles, keys never cross FFI
- Vault alias system — names map to container paths
- 144 unit tests + 9 integration tests
- 4 fuzz targets (crypto, header, shamir, hmac)
- Complete documentation: VAULT_FORMAT_v1.md, THREAT_MODEL.md, SECURITY.md, AUDIT_PLAN.md

### Security properties
- Keys zero on lock (ZeroizeOnDrop + explicit zero_now)
- Keys zero on panic (catch_unwind + ZeroOnDrop guard)
- Keys mlock'd — not swappable when RLIMIT_MEMLOCK is unlimited
- Header tamper detection including padding bytes (verify_hmac_raw)
- KDF parameter minimums enforced — downgrade attacks rejected
- Constant-time HMAC comparison via subtle crate

### Known limitations in v1.0
- Linux only (macOS and Windows in v1.5)
- Filesystem journal may retain pre-vault filenames
- Hibernation writes RAM to disk (warned, documented)
- No TOTP or FIDO2 second factor (v1.5)
- No remote attestation (v1.5)
- No TPM hardware binding (v2.0)

## [Unreleased] — v1.5 planned

- macOS and Windows support
- TOTP second factor
- Two-process watchdog daemon
- HMAC audit log with remote anchoring
- Shamir recovery export with BIP-39 word encoding
- Remote attestation with nonce-based challenge-response
