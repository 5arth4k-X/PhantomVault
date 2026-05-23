````markdown

██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗██╗   ██╗ █████╗ ██╗   ██╗██╗  ████████╗
██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║██║   ██║██╔══██╗██║   ██║██║  ╚══██╔══╝
██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║██║   ██║███████║██║   ██║██║     ██║   
██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║╚██╗ ██╔╝██╔══██║██║   ██║██║     ██║   
██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║ ╚████╔╝ ██║  ██║╚██████╔╝███████╗██║   
╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝  ╚═══╝  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝   

````
<div align="center">

### Encrypted File Vault with a Rust Cryptographic Core

[![Rust](https://img.shields.io/badge/Rust-Stable-orange?style=for-the-badge&logo=rust&logoColor=white)](https://rust-lang.org)
[![Python](https://img.shields.io/badge/Python-3.11+-blue?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Platform](https://img.shields.io/badge/Platform-Linux-557C94?style=for-the-badge&logo=linux&logoColor=white)](https://kernel.org)
[![License](https://img.shields.io/badge/License-Apache%202.0-green?style=for-the-badge)](LICENSE)
[![Version](https://img.shields.io/badge/Version-1.0.0-red?style=for-the-badge)](CHANGELOG.md)
[![CI](https://img.shields.io/github/actions/workflow/status/5arth4k-X/PhantomVault/ci.yml?style=for-the-badge&label=CI)](https://github.com/5arth4k-X/PhantomVault/actions)

*All cryptographic operations happen inside a Rust module. Python never touches a key.*

</div>

---

## What is PhantomVault?

PhantomVault takes a directory of files, encrypts everything into a single authenticated container, and leaves the source directory empty. When you unlock the vault, files are decrypted back to their original location. When you lock it, they are removed and every key byte is zeroed from memory immediately.

The entire cryptographic core lives in a Rust module called `phantom_core`. Python handles the interface and file management but never holds raw key material. Keys are derived, used, and zeroed entirely inside Rust — Python receives only an opaque integer handle.

---

## Security Properties

| Property | Implementation |
|---|---|
| Primary encryption | AES-256-GCM-SIV — nonce-misuse-resistant |
| Alternative encryption | ChaCha20-Poly1305 — ARM / no AES-NI hardware |
| Key derivation | Argon2id — enforced minimums t=3, m=64 MB, p=4 |
| Header authentication | HMAC-SHA256 — tamper-evident, downgrade-resistant |
| Memory safety | Rust `SecretBytes` — mlock'd, zeroed on drop |
| Secret sharing | Shamir (sharks crate) with mandatory self-test |
| Two compartments | Two independent encrypted regions per vault |

> Python never holds raw key bytes. Keys are derived, used, and zeroed entirely inside the Rust TCB (`phantom_core`).

---

## Requirements

> [!IMPORTANT]
> PhantomVault v1.0 supports **Linux only**. macOS and Windows support is planned for v1.5.

- Linux (Kali, Ubuntu, Debian, Arch)
- Python 3.11 or later
- Rust stable (installed automatically by setup script)
- No root access required

---

## Installation

```bash
git clone https://github.com/5arth4k-X/PhantomVault
cd PhantomVault
bash scripts/setup.sh
source .venv/bin/activate
phantomvault --help
```

**The setup script handles everything:**

| Step | What it does |
|---|---|
| 1 | Installs system packages (build tools, libssl, clang) |
| 2 | Installs Rust via rustup (stable + nightly for fuzzing) |
| 3 | Installs cargo tools (maturin, cargo-fuzz, cargo-deny) |
| 4 | Creates Python virtual environment |
| 5 | Compiles the Rust TCB and installs the Python package |
| 6 | Creates test directories |

> [!TIP]
> After install, run `bash scripts/check_env.sh` to verify everything is configured correctly.

---

## Verify the Build

```bash
cargo test --manifest-path phantom_core/Cargo.toml -- --test-threads=1
```

All 144 unit tests and 9 integration tests must pass before use.

---

## Usage

```bash
phantomvault <command> [options]
```

### Commands

| Command | Description |
|---|---|
| `create <name> <path>` | Create a new vault from a directory |
| `unlock <name>` | Unlock a vault — restores files to source directory |
| `lock <name>` | Lock a vault — zeroes session key, clears source directory |
| `status` | Show all registered vaults and their current status |
| `remove <name>` | Permanently destroy a vault and its container |
| `panic` | Emergency — lock all open vaults immediately |
| `about` | Learn what PhantomVault is and how it works |
| `version` | Show version information |

### Options

| Flag | Description |
|---|---|
| `--cipher aes` | Use AES-256-GCM-SIV (default) |
| `--cipher chacha` | Use ChaCha20-Poly1305 |
| `--size <MB>` | Container size in megabytes (default: 32) |
| `--yes` | Skip confirmation prompts |

---

## Examples

```bash
# Create a vault from a directory — password read from terminal
phantomvault create work-vault ~/Documents/work

# Unlock — files restored to ~/Documents/work
phantomvault unlock work-vault

# Lock — keys zeroed, directory cleared
phantomvault lock work-vault

# See all vaults and whether they are open or locked
phantomvault status

# Emergency lock everything immediately
phantomvault panic

# Permanently destroy a vault (asks for confirmation)
phantomvault remove work-vault

# Create a larger vault with ChaCha20 instead of AES
phantomvault create big-vault ~/Videos --size 500 --cipher chacha
```

---

## Architecture

```
PhantomVault
├── phantomvault/              Python orchestration layer
│   ├── cli.py                 Typer/Rich command-line interface
│   ├── vault.py               Vault lifecycle: create, unlock, lock, remove
│   ├── stealth.py             Secure file deletion, mtime randomisation
│   ├── vault_region.py        Two independent encrypted compartments
│   ├── obfuscation.py         Poisson-distributed dummy I/O
│   ├── hibernation.py         Startup hibernation detection
│   ├── modes.py               Security mode detection (SECURE/KERNEL/PORTABLE)
│   └── container/
│       └── portable.py        Container file read/write backend
│
└── phantom_core/              Rust Trusted Computing Base (TCB)
└── src/
├── memory.rs          SecretBytes — mlock, ZeroizeOnDrop
├── crypto.rs          AES-256-GCM-SIV, ChaCha20, Argon2id, HKDF
├── header.rs          256-byte vault header — HMAC authenticated
├── input.rs           TTY password reading — Python never sees password
├── hmac.rs            HMAC-SHA256 audit chain
├── shamir.rs          Shamir secret sharing with mandatory self-test
└── lib.rs             PyO3 exports — opaque session handles only
```
**The boundary is strict.** Python sends plaintext and receives ciphertext. Python sends ciphertext and receives plaintext. Session keys never cross the boundary — Python holds only an opaque integer handle.

---

## Vault File Format

Every vault is a single binary file:
[0    - 255 ]  256-byte authenticated header (HMAC-SHA256)
[256 - EOF  ]  CSPRNG random padding + two encrypted vault regions
The complete binary format specification is in [docs/VAULT_FORMAT_v1.md](docs/VAULT_FORMAT_v1.md).

---

## How Keys Work

```
User types password
│  (stays in terminal TTY — Rust reads it directly)
▼
Argon2id(password, salt, t=3, m=64MB, p=4)
│  (~2-5 seconds — intentionally slow to resist brute force)
▼
master_key (32 bytes, mlock'd in Rust memory)
│  password zeroed immediately after this step
▼
HKDF-SHA256(master_key, vault_id, session_nonce)
│  master_key zeroed immediately after this step
▼
session_key (32 bytes, mlock'd in Rust memory)
│  Python receives only: handle = 42 (an integer)
▼
AES-256-GCM-SIV encrypt/decrypt using session_key
│
▼
vault locked → session_key zeroed → handle invalidated
---
```

## Threat Model Summary

| Attacker | Capabilities | Protected? |
|---|---|---|
| T1 — Casual | File manager access | ✅ Full — directory appears empty |
| T2 — Skilled local | CLI tools, entropy analysis, password attacks | ✅ Argon2id + CSPRNG padding |
| T3 — Root / forensic | Disk image, RAM dump, swap analysis | ✅ mlock + ZeroizeOnDrop |
| T3.5 — Root + OS compromise | Hook TTY, intercept syscalls | ⚠️ Partial — boot integrity warning |
| T4 — Nation state | Hardware implants, power analysis | ⚠️ Partial — two compartments + Shamir |

Full details in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

---

## Known Limitations

> [!WARNING]
> Read these before using PhantomVault for sensitive data.

- **Filesystem journal** — Tools like extundelete can recover filenames of files that existed before vaulting. Use freshly formatted volumes for maximum stealth.
- **Hibernation** — If the system hibernates while a vault is open, keys may be written to disk. PhantomVault warns at startup. Disable hibernation for maximum security.
- **Compromised OS** — A fully compromised kernel defeats all software-only protections.
- **Hardware keyloggers** — Capturing the password before it reaches the software is out of scope for any software tool.

Full list in [docs/SECURITY.md](docs/SECURITY.md).

---

## Repository Structure

```
phantom_core/     Rust TCB — the ONLY security-critical audit target
phantomvault/     Python orchestration — UX and file management, not crypto
docs/             Security documentation and format specifications
scripts/          Setup and environment verification
.github/          CI workflows
---
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

Changes to `phantom_core/src/` are security changes and require justification. Changes to `phantomvault/` are UX changes. Read [docs/AUDIT_PLAN.md](docs/AUDIT_PLAN.md) before touching the TCB.

---

## Roadmap

| Version | Focus |
|---|---|
| **v1.0** (current) | Linux — Rust TCB, portable container, full CLI |
| **v1.5** | macOS + Windows, TOTP, watchdog daemon, Shamir recovery, audit log |
| **v2.0** | TPM 2.0, YubiKey/FIDO2, LUKS/BitLocker/FileVault integration |

---

## Licence

Apache-2.0 — see [LICENSE](LICENSE).

---

<div align="center">

> PhantomVault is provided on an as-is basis without warranty of any kind.  
> Users are solely responsible for compliance with all applicable laws in their jurisdiction.

[![GitHub](https://img.shields.io/badge/GitHub-5arth4k--X-red?style=for-the-badge&logo=github)](https://github.com/5arth4k-X)

</div>
