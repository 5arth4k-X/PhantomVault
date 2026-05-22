# PhantomVault — Audit Plan v1.0

## Trusted Computing Base Definition

The audit target is `phantom_core/src/` exclusively — approximately 2,000 lines
of Rust across 6 files.

| File | Responsibility | Lines (approx) |
|---|---|---|
| `memory.rs` | SecretBytes, mlock, zeroing | ~300 |
| `crypto.rs` | AES-256-GCM-SIV, ChaCha20, Argon2id, HKDF | ~500 |
| `header.rs` | Vault format, HMAC authentication | ~400 |
| `input.rs` | TTY password reading | ~200 |
| `hmac.rs` | HMAC-SHA256 chain | ~200 |
| `shamir.rs` | Shamir secret sharing | ~350 |

**A bug in any TCB file is a critical security vulnerability.**
**A bug in `phantomvault/` (Python) is a UX defect.**

This distinction is what makes the audit feasible — the Python layer is large
but the security-critical surface is small and precisely bounded.

---

## Automated Testing (Every Commit via CI)

| Check | Tool | Requirement |
|---|---|---|
| Formatting | `cargo fmt` | Zero diff |
| Linting | `cargo clippy -- -D warnings` | Zero warnings |
| Unit tests | `cargo test -- --test-threads=1` | All 144 pass |
| Integration tests | `cargo test --test integration_test` | All 9 pass |
| Dependency licences | `cargo deny check licenses` | No unlisted licences |
| Dependency bans | `cargo deny check bans` | No banned crates |
| Advisory database | `cargo deny check advisories` | No unreviewed CVEs |

---

## Test Coverage

### Unit Tests — 144 tests

| Module | Tests | What is verified |
|---|---|---|
| `memory` | 21 | SecretBytes construction, zeroing, constant-time comparison, mlock status |
| `crypto` | 36 | AES encrypt/decrypt round-trips, Argon2id determinism, HKDF subkey separation |
| `header` | 27 | Binary format, HMAC coverage of all bytes including padding, downgrade rejection |
| `hmac` | 16 | Chain integrity, tamper detection, deletion detection |
| `input` | 14 | Constant-time comparison, validation, zeroing |
| `shamir` | 30 | All k-of-n combinations, self-test verification, error cases |

### Integration Tests — 9 tests

| Test | What is verified |
|---|---|
| `full_vault_create_unlock_cycle` | End-to-end: password → master key → session key → encrypt → decrypt |
| `wrong_password_cannot_decrypt` | Wrong password produces wrong key — ciphertext cannot be decrypted |
| `header_create_serialize_verify` | Header HMAC covers all bytes, serialise/deserialise round-trip |
| `tampered_header_detected` | Any header modification invalidates HMAC |
| `audit_chain_tamper_detection` | Deleted audit entries are detectable |
| `shamir_full_recovery_cycle` | Split → reconstruct → verify equals original |
| `shamir_insufficient_shares` | Fewer than threshold shares cannot reconstruct |
| `secret_bytes_zeroing` | `zero_now()` produces all-zero bytes |
| `session_key_different_from_master` | Session key differs from master key that produced it |

---

## Fuzzing Targets

Four fuzz targets in `phantom_core/fuzz/src/`:

| Target | What it does |
|---|---|
| `fuzz_crypto` | AES-256-GCM-SIV and ChaCha20 with random keys, nonces, ciphertext — must not panic |
| `fuzz_header` | Header parsing with corrupted bytes at every offset — must return errors, not panic |
| `fuzz_shamir` | Share reconstruction with random share data — must return errors, not panic |
| `fuzz_hmac` | HMAC verification with tampered entries — must return errors, not panic |

### Running the fuzzer

```bash
# Requires nightly toolchain
cargo +nightly fuzz run fuzz_crypto
cargo +nightly fuzz run fuzz_header
cargo +nightly fuzz run fuzz_shamir
cargo +nightly fuzz run fuzz_hmac
```

Run each target for at least 1 hour before any release. Run for 24 hours before a major version release.

---

## External Review Roadmap

### Phase 1 — Academic Review (after v1.5)

Submit `phantom_core` to a university cryptography research group for informal review.
Academics review for conceptual errors that automated testing misses — algorithm
selection rationale, constant-time guarantees, and GF(256) arithmetic correctness.

Target: one institution with an active applied cryptography group.
Cost: low. Timeline: 2-6 months.

### Phase 2 — Commercial Audit (before v2.0)

Commission a formal security audit of `phantom_core` from an independent firm
(Trail of Bits, NCC Group, Cure53, or equivalent).

Scope: TCB only (~2,000 lines Rust). The small, bounded scope makes this audit
achievable without an enterprise budget.

The audit report will be published in full in this repository regardless of findings.
No government or organisational deployment should occur before this report is available.

---

## Dependency Policy

Only these crate groups are permitted in `phantom_core`:

| Crate group | Examples | Reason permitted |
|---|---|---|
| RustCrypto project | aes-gcm-siv, argon2, hkdf, hmac, zeroize, subtle | Audited, widely used |
| sharks / Shamir | sharks | Dedicated Shamir implementation |
| rpassword | rpassword | TTY input only |
| getrandom | getrandom | OS CSPRNG wrapper |
| pyo3 | pyo3 | Python FFI bridge |
| Platform | libc, winapi | Memory locking syscalls |

Any new dependency requires:
1. Manual review of the crate source
2. Explicit addition to the `deny.toml` allowlist
3. A comment in `phantom_core/Cargo.toml` explaining why it is needed
