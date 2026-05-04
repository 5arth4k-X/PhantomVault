# PhantomVault Audit Plan v1.0

## Trusted Computing Base

The audit target is the phantom_core Rust crate exclusively.
Approximately 2,000 lines of Rust across 6 files:
  - memory.rs: SecretBytes, mlock, ZeroizeOnDrop
  - crypto.rs: AES-256-GCM-SIV, ChaCha20, Argon2id, HKDF
  - header.rs: Vault format, HMAC authentication
  - input.rs: TTY password reading
  - hmac.rs: HMAC-SHA256 chain operations
  - shamir.rs: Shamir Secret Sharing

A bug in any TCB file is a critical security vulnerability.
A bug outside the TCB is a UX defect.

## Automated Testing (CI — every commit)

- cargo fmt: formatting enforcement
- cargo clippy -- -D warnings: zero warnings allowed in TCB
- cargo test -- --test-threads=1: full unit test suite
- cargo miri test: undefined behaviour detection in unsafe blocks
- cargo deny check: CVE advisory database check on all dependencies

## Fuzzing Targets (24h before each release)

- fuzz_crypto: AES-GCM-SIV and ChaCha20 with malformed inputs
- fuzz_header: Header parsing with corrupted bytes at every offset
- fuzz_shamir: Share reconstruction edge cases and corrupted shares
- fuzz_hmac: HMAC verification with tampered chain entries

## External Review Roadmap

### Phase 1: Academic Review (after v1.5)
Submit phantom_core to a university cryptography research group.
Inexpensive, credible, catches conceptual errors fuzzing misses.
Target: one institution with an active cryptography research group.

### Phase 2: Commercial Audit (before v2.0 ships)
Commission audit of phantom_core from Trail of Bits, NCC Group, or Cure53.
Audit target: TCB only (~2,000 lines Rust) — manageable scope.
Audit report published publicly in this repository.
Required before any government or organisational deployment.

## Dependency Policy

Only these crate groups are permitted in phantom_core:
- RustCrypto project crates (aes-gcm-siv, chacha20poly1305, argon2, hkdf, sha2, hmac, zeroize, subtle)
- sharks (audited Shamir implementation)
- rpassword (TTY input)
- getrandom (OS CSPRNG)
- pyo3 (Python FFI)
- libc / winapi (platform memory locking)

Any new dependency requires explicit manual review and cargo-deny allowlist update.
