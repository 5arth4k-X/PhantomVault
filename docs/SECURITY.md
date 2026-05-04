# PhantomVault Security Documentation v1.0

## Cryptographic Primitives

### Primary Cipher: AES-256-GCM-SIV
- Implementation: aes-gcm-siv crate (RustCrypto project)
- Key size: 256 bits
- Nonce: 96 bits, synthetic IV construction
- Nonce misuse resistance: YES — nonce reuse reveals only identical plaintexts,
  not the key. This is the critical advantage over standard AES-256-GCM.

### Alternative Cipher: ChaCha20-Poly1305
- Implementation: chacha20poly1305 crate (RustCrypto project)
- Key size: 256 bits
- Nonce: 96 bits, constructed as nonce_base XOR write_counter
- Use when: platforms without AES hardware acceleration (ARM without AES-NI)

### Key Derivation: Argon2id
- Implementation: argon2 crate (RustCrypto project)
- Minimum parameters enforced in code: t=3, m=65536 KiB (64 MB), p=4
- These minimums cannot be reduced — vault refuses to open if params below minimum
- Parameters stored in vault header and covered by HMAC (downgrade-resistant)

### Session Key Derivation: HKDF-SHA256
- IKM: master key (from Argon2id)
- Salt: vault_id (16-byte random UUID, unique per vault)
- Info: 32-byte CSPRNG session nonce (fresh on every unlock)
- NO timestamp in derivation — timestamps are low-entropy and manipulable

### Header Authentication: HMAC-SHA256
- Covers all 224 bytes of header before the HMAC field
- Key derived from master key via HKDF with info = b"header-auth-key-v1"
- Verified using raw bytes (not re-serialised) to catch padding tampering
- Constant-time comparison via subtle crate

### Secret Sharing: Shamir over GF(256)
- Implementation: sharks crate (audited, not custom)
- Mandatory self-test on every share export
- Default: 3-of-5 split

## Memory Safety

- All key material held in SecretBytes (Rust type)
- mlock() pins key memory, preventing swap (fails gracefully with warning)
- ZeroizeOnDrop: keys zeroed when scope exits (normal and panic paths)
- catch_unwind: keys zeroed before any panic propagates
- No key material ever crosses the PyO3 FFI boundary to Python

## Known Limitations and Residual Risks

### Filesystem Journal
Filesystem journal analysis (extundelete, Autopsy) may recover filenames
and metadata of files that existed in the source directory before vaulting.
The random rename chain mitigation reduces but does not eliminate this.
Recommendation: create vaults on freshly formatted volumes for maximum stealth.

### Hibernation
Hibernation files (hiberfil.sys on Windows, sleepimage on macOS) capture
physical RAM including mlock'd pages. PhantomVault detects and warns about
this at startup. Disable hibernation for maximum security.

### Side-Channel Attacks
Constant-time comparisons are implemented for all security-critical operations
via the subtle crate. Cache timing attacks during Argon2id on shared hardware
(multi-tenant VMs, cloud servers) are not fully mitigated.
Do not use PhantomVault on shared infrastructure.

### Power Analysis
Not mitigated in software. Requires hardware countermeasures.

## Legal Disclaimer

PhantomVault is provided "as is" without warranty of any kind, either
express or implied, including without limitation warranties of
merchantability, fitness for a particular purpose, and non-infringement.

In no event shall the authors or contributors be liable for any damages
arising from use of this software.

Users are solely responsible for determining the suitability of this
software for their use case and for compliance with all applicable laws
in their jurisdiction.

## Known Dependency Vulnerabilities

### CVE: Sharks — Polynomial Coefficient Bias (Moderate)

**Component:** sharks crate (Shamir secret sharing)
**Status:** Accepted for v1.0. Will be addressed in v1.5.
**Impact in PhantomVault:** Minimal. The bias requires an attacker to observe
multiple independent share generation sessions from the same secret. PhantomVault
generates shares once per vault per user request. The recovery export feature
is a stub in v1.0 and the full implementation in v1.5 will use a crate without
this bias.

### CVE: PyO3 — Buffer Overflow in PyString::from_object (Low)

**Component:** pyo3 crate (Python FFI bridge)
**Status:** Accepted for v1.0. Fix is to update pyo3 when a patched version ships.
**Impact in PhantomVault:** Not exploitable. PhantomVault does not call
PyString::from_object on untrusted input. All string data passed across the
PyO3 boundary is either a fixed prompt string or a result from Rust operations.
