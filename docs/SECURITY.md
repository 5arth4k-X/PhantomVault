# PhantomVault — Security Documentation v1.0

## Architecture Boundary

The most important security property in PhantomVault is the boundary between Python and Rust.
Python sends plaintext and receives ciphertext.
Python sends ciphertext and receives plaintext.
Python holds an opaque integer handle (e.g. `42`) — useless without Rust.
The actual session key never leaves Rust memory.

---

## Cryptographic Primitives

### Primary Cipher — AES-256-GCM-SIV

| Property | Value |
|---|---|
| Implementation | `aes-gcm-siv` crate (RustCrypto project) |
| Key size | 256 bits |
| Nonce | 96 bits, synthetic IV construction |
| Nonce misuse resistance | YES — nonce reuse reveals only identical plaintexts, not the key |
| Header byte | `0x01` |

AES-256-GCM-SIV is chosen over standard AES-256-GCM specifically for nonce misuse resistance.
Standard GCM is catastrophically broken on nonce reuse — a single reused nonce allows key recovery.
GCM-SIV limits nonce reuse damage to revealing whether two plaintexts are identical.

### Alternative Cipher — ChaCha20-Poly1305

| Property | Value |
|---|---|
| Implementation | `chacha20poly1305` crate (RustCrypto project) |
| Key size | 256 bits |
| Nonce | 96 bits, constructed as `nonce_base XOR write_counter` |
| Header byte | `0x02` |

The write counter is stored in the vault header and incremented before every encryption.
This ensures nonce uniqueness across all writes to the same vault.
Use ChaCha20 on ARM hardware or any platform without AES hardware acceleration.

### Key Derivation — Argon2id

| Property | Value |
|---|---|
| Implementation | `argon2` crate (RustCrypto project) |
| Variant | Argon2id (hybrid: side-channel resistant + GPU resistant) |
| Minimum t (time cost) | 3 — enforced in code, cannot be reduced |
| Minimum m (memory cost) | 65536 KiB = 64 MB — enforced in code |
| Minimum p (parallelism) | 4 — enforced in code |
| Output | 32 bytes |

The minimums are enforced at the code level. If a vault header is tampered with to show
weaker parameters, HMAC verification fails first. If somehow a tampered vault reaches
key derivation, the parameter check here rejects it. Two independent layers.

### Session Key Derivation — HKDF-SHA256

| Property | Value |
|---|---|
| Implementation | `hkdf` crate (RustCrypto project) |
| IKM | Master key (32 bytes, from Argon2id) |
| Salt | Vault ID (16-byte random UUID, unique per vault) |
| Info | 32-byte CSPRNG session nonce (fresh on every unlock) |
| No timestamp | Timestamps are low-entropy and manipulable — excluded by design |

The master key is zeroed immediately after session key derivation.
From this point, only the session key exists — the master key is gone.
A memory dump taken during an open vault session finds only the session key,
not the master key used to derive it.

### Header Authentication — HMAC-SHA256

| Property | Value |
|---|---|
| Implementation | `hmac` crate (RustCrypto project) |
| Coverage | All 224 bytes of header before the HMAC field |
| Key | Derived from master key via HKDF with `info = b"header-auth-key-v1"` |
| Verification | Uses raw on-disk bytes (not re-serialised) to catch padding tampering |
| Comparison | Constant-time via `subtle` crate — no timing oracle |

### Secret Sharing — Shamir over GF(256)

| Property | Value |
|---|---|
| Implementation | `sharks` crate |
| Self-test | Mandatory on every share export — shares verified before distribution |
| Default split | 3-of-5 |

---

## Memory Safety

### SecretBytes

All key material is held in `SecretBytes` — a Rust type with these guarantees:

- `mlock()` called on creation — OS cannot swap this memory to disk
- `ZeroizeOnDrop` — memory zeroed the moment the value goes out of scope
- No `Clone`, no `Copy` — keys cannot be accidentally duplicated
- No `Debug`, no `Display` — keys cannot appear in logs or panic messages
- `!Send + !Sync` — keys cannot cross thread boundaries silently

### Zeroing paths

Keys are zeroed on all exit paths:

| Event | Zero mechanism |
|---|---|
| Normal vault lock | `zero_now()` then `drop()` |
| Scope exit | `ZeroizeOnDrop` |
| Rust panic | `catch_unwind` + `ZeroOnDrop` guard |
| SIGKILL | Not zeroed — OS reclaims memory (documented limitation) |

### mlock limits

On default Linux systems, `RLIMIT_MEMLOCK` is 64KB. The setup script sets it to `unlimited`.
If mlock fails, PhantomVault displays a prominent warning and continues.
Keys may be swappable if RLIMIT_MEMLOCK is not configured — check with `ulimit -l`.

---

## Known Limitations

### Filesystem Journal

ext4, NTFS, APFS, and other journalling filesystems record file creation, renaming,
and deletion events. Tools like `extundelete` and Autopsy can recover filenames and
metadata of files that existed in the source directory before vaulting.

PhantomVault uses random rename chains before deletion to reduce journal traceability
but cannot fully eliminate journal entries.

**Mitigation:** Create vaults on freshly formatted volumes.

### Hibernation

When a system hibernates, the entire contents of RAM — including mlock'd pages — are
written to `hiberfil.sys` (Windows) or `sleepimage` (macOS). Key material may be
recoverable from hibernation files.

PhantomVault detects hibernation and displays a warning at startup.

**Mitigation:** Disable hibernation entirely.

### Side-Channel Attacks

All HMAC verifications and key comparisons use constant-time operations via the `subtle`
crate. Argon2id memory access patterns during key derivation are data-independent (the
Argon2i property of the hybrid). Cache timing attacks on shared hardware (cloud VMs,
multi-tenant servers) are not fully mitigated.

**Mitigation:** Do not use PhantomVault on shared infrastructure.

### Power Analysis

Not mitigated in software. Requires hardware countermeasures such as shielded
enclosures or specialised CPUs.

---

## Known Dependency Advisories

### RUSTSEC-2024-0398 — sharks: Polynomial Coefficient Bias

**Component:** `sharks` crate (Shamir secret sharing)
**Severity:** Moderate
**Status:** Accepted for v1.0 — replacement scheduled for v1.5

The `sharks` crate generates polynomial coefficients in the range `[1, 255]` instead
of the correct `[0, 255]`. An attacker who obtains shares from 500-1500 independent
distributions of the same secret could statistically narrow the keyspace.

**PhantomVault exposure:** PhantomVault distributes each vault's master key shares
exactly once per user request. The attack requires hundreds of repeated distributions
of the same secret — a condition that does not occur in normal usage.

### RUSTSEC-2025-0020 — pyo3: Buffer Overflow in PyString::from_object

**Component:** `pyo3` crate (Python FFI bridge)
**Severity:** Low
**Status:** Accepted — function not called in PhantomVault

The vulnerable function `PyString::from_object` can read beyond its input buffer.
PhantomVault does not call this function. All PyO3 boundary types are `Vec<u8>`,
`u64`, `bool`, and string literals — none involve `PyString::from_object`.

---

## Legal Disclaimer

PhantomVault is provided "as is" without warranty of any kind, either express or
implied, including without limitation any warranties of merchantability, fitness for
a particular purpose, or non-infringement.

In no event shall the authors or contributors be liable for any damages arising from
use of this software.

Users are solely responsible for determining the suitability of this software for their
use case and for compliance with all applicable laws in their jurisdiction.
