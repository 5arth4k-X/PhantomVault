# PhantomVault

**Encrypted file vault with a Rust cryptographic core.**

PhantomVault encrypts a directory of files into a single authenticated container. The source directory is left empty when locked. Decrypted files are restored when unlocked. All cryptographic operations happen inside a Rust module — Python handles only the interface and file management.

---

## Security Properties

| Property | Implementation |
|---|---|
| Encryption | AES-256-GCM-SIV (nonce-misuse-resistant) |
| Alternative cipher | ChaCha20-Poly1305 (ARM / no AES-NI) |
| Key derivation | Argon2id — minimum t=3, m=64 MB, p=4 |
| Header authentication | HMAC-SHA256 — tamper-evident, downgrade-resistant |
| Memory safety | Rust `SecretBytes` — mlock'd, zeroed on drop |
| Secret sharing | Shamir (sharks crate) with mandatory self-test |

Python never holds raw key bytes. Keys are derived, used, and zeroed entirely inside the Rust TCB (`phantom_core`).

---

## Requirements

- Linux (v1.0) — macOS and Windows in v1.5
- Python 3.11 or later
- Rust stable (for building from source)

---

## Installation

### From source

```bash
git clone https://github.com/your-username/phantomvault
cd phantomvault
bash scripts/setup.sh
source .venv/bin/activate
phantomvault --help
```

### Verify the build

```bash
cargo test --manifest-path phantom_core/Cargo.toml -- --test-threads=1
```

All tests must pass before use.

---

## Usage

```bash
# Create a vault from a directory
phantomvault create my-vault ~/Documents/private

# Unlock — restores files to the source directory
phantomvault unlock my-vault

# Lock — zeroes session key and clears source directory
phantomvault lock my-vault

# Show all vaults and their status
phantomvault status

# Emergency lock all open vaults immediately
phantomvault panic

# Learn what PhantomVault is
phantomvault about
```

---

## Architecture
phantomvault/          Python orchestration (CLI, file management, stealth)
cli.py             Typer/Rich command-line interface
vault.py           Vault lifecycle: create, unlock, lock, remove
stealth.py         Secure file deletion, mtime randomisation
vault_region.py    Two independent encrypted compartments
container/         Container file read/write
phantom_core/          Rust Trusted Computing Base (TCB)
src/memory.rs      SecretBytes — mlock, ZeroizeOnDrop
src/crypto.rs      AES-256-GCM-SIV, ChaCha20, Argon2id, HKDF
src/header.rs      256-byte vault header — HMAC authenticated
src/input.rs       TTY password reading — Python never sees password
src/hmac.rs        HMAC-SHA256 audit chain
src/shamir.rs      Shamir secret sharing with mandatory self-test
src/lib.rs         PyO3 exports — opaque session handles only
The Python layer calls Rust via PyO3. The boundary is strict: Python sends data to encrypt and receives ciphertext. Python sends ciphertext and receives plaintext. Session keys never cross the boundary — Python holds only an opaque integer handle.

---

## Vault File Format

Every vault is a single binary file with a 256-byte authenticated header followed by CSPRNG random padding with two encrypted regions embedded within it. The complete format specification is in [docs/VAULT_FORMAT_v1.md](docs/VAULT_FORMAT_v1.md).

---

## Threat Model

PhantomVault is designed against five attacker tiers ranging from casual filesystem browsing to forensic root access. It honestly documents what it does not protect against. See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

---

## Known Limitations

- Filesystem journal analysis can recover filenames of files that existed in the source directory before vaulting. Creating vaults on freshly formatted volumes eliminates this.
- If hibernation is enabled, keys may be written to disk during a hibernate event. PhantomVault warns about this at startup.
- A fully compromised OS defeats all software-only protections.

The complete list is in [docs/SECURITY.md](docs/SECURITY.md).

---

## Repository Structure
phantom_core/        Rust TCB — the only security-critical audit target
phantomvault/        Python orchestration — UX, not crypto
docs/                Security documentation and specifications
scripts/             Setup and environment verification
---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Before submitting any changes to `phantom_core/src/`, read [docs/AUDIT_PLAN.md](docs/AUDIT_PLAN.md). The TCB is held to a higher standard than the rest of the codebase.

---

## Licence

Apache-2.0. See [LICENSE](LICENSE).

---

## Disclaimer

PhantomVault is provided on an as-is basis without warranty of any kind. Users are solely responsible for determining its suitability and for compliance with all applicable laws in their jurisdiction.
