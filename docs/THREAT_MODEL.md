# PhantomVault — Threat Model v1.0

## Purpose

Security properties are only meaningful when measured against a defined adversary.
This document defines exactly who PhantomVault is built to protect against, what it
does at each tier, and what it explicitly does not protect against.

Honest threat modelling means stating limits clearly. A security tool that
overclaims is more dangerous than one that underclaims.

---

## Attacker Tiers

### T1 — Casual Access

**Who:** A person with physical or remote access to an unlocked machine, no technical skills.

**What they can do:**
- Browse the filesystem with a file manager
- Open any visible file
- Copy files to USB or upload them

**What PhantomVault does:**
- Ghost directory — the vault source folder appears completely empty when locked
- No visible vault files in the source location
- Container file stored in `~/.phantomvault/containers/` with a randomised mtime

**Result:** Complete protection. This attacker finds nothing.

---

### T2 — Skilled Local Attacker

**Who:** A technical person with a user-level account on the machine.

**What they can do:**
- Run CLI tools and scripts
- Copy the vault container file
- Run entropy analysis tools (binwalk, ent)
- Attempt offline password brute-force against a copied container
- Read shell history and process list
- Install user-space keyloggers

**What PhantomVault does:**
- Argon2id (t=3, m=64MB, p=4) — one password attempt takes 2-5 seconds and 64MB RAM, making GPU attacks impractical
- CSPRNG padding fills the entire container — entropy analysis finds no structure
- Rust TTY input via rpassword — password never appears in shell history or process arguments
- Vault alias system — the container path does not appear in the process list

**Honest limits:**
- A user-space keylogger installed before PhantomVault runs can capture the password
- This is outside the scope of any software-only protection

---

### T3 — Privileged Analyst (Root, No OS Compromise)

**Who:** A forensic analyst or system administrator with root access.

**What they can do:**
- Image the entire disk
- Dump RAM to a file
- Read swap file contents
- Kill user processes
- Copy the vault container file and run it on different hardware
- Read system logs and filesystem metadata

**What PhantomVault does:**
- `mlock()` pins key memory pages — OS cannot write them to swap
- `ZeroizeOnDrop` zeroes all keys when vault is locked
- `catch_unwind` zeroes all keys even on unexpected errors
- Secure file deletion uses random rename chains before deletion
- mtime randomisation obscures when the vault was last accessed

**Honest limits:**
- DMA attacks via Thunderbolt or PCIe can read physical RAM directly, bypassing mlock
- If hibernation is enabled, RAM including mlock'd pages is written to `hiberfil.sys` or `sleepimage` — PhantomVault warns about this at startup

---

### T3.5 — Root + OS Compromise

**Who:** An attacker with root access who can also modify kernel code or hook system calls.

**What they can do:**
- Hook the TTY driver to intercept password input
- Intercept Rust function calls via dynamic linker manipulation
- Fake TPM responses
- Read live process memory

**What PhantomVault does:**
- rpassword reads directly from `/dev/tty`, raising the cost of interception
- Boot integrity check (v2.0 with TPM) detects if the boot environment changed

**Honest limits:**
- A fully compromised OS defeats software-only protections
- PhantomVault is not an OS — it cannot protect itself from the OS
- Recommendation: use PhantomVault inside Qubes OS or Tails for this threat tier

---

### T4 — Nation-State / Sophisticated Adversary

**Who:** A well-resourced adversary with hardware capabilities, legal authority, or supply chain access.

**What they can do:**
- Install hardware implants before the device is received
- Perform power analysis or electromagnetic analysis during vault operations
- Apply legal compulsion for password disclosure
- Compromise the software supply chain

**What PhantomVault does:**
- Two independent vault compartments with separate passwords for different categories of files
- Shamir secret sharing distributes recovery material across independent physical locations (v1.5)
- Hardware binding via TPM raises the cost of vault file copying attacks (v2.0)

**Honest limits:**
- Power analysis and cold boot attacks with specialised hardware are beyond software-only mitigation
- Supply chain compromise of the Rust compiler or core crates is beyond project scope
- Legal compulsion for password disclosure is a legal matter, not a technical one

---

## What PhantomVault Does NOT Do

PhantomVault is **not** designed to:

- Help users violate any applicable law in any jurisdiction
- Defeat lawful legal process
- Protect against hardware keyloggers installed before use
- Protect against an observer watching the screen during password entry
- Protect against a fully compromised OS or bootloader
- Mitigate power analysis or electromagnetic side-channel attacks
- Resist quantum computing attacks against AES-256 (currently theoretical)

Users are solely responsible for compliance with all applicable laws in their jurisdiction.

---

## Summary Table

| Threat | Protected | Method |
|---|---|---|
| Casual file browser | ✅ Full | Ghost directory |
| Entropy analysis | ✅ Full | CSPRNG container padding |
| Offline brute force | ✅ Full | Argon2id — 2-5 seconds per attempt |
| Shell history leak | ✅ Full | Rust TTY — password never in Python |
| Swap analysis | ✅ Full | mlock on all key memory |
| RAM dump (locked vault) | ✅ Full | ZeroizeOnDrop + zero_now() |
| Tampered header | ✅ Full | HMAC-SHA256 — any byte change detected |
| DMA attack | ❌ None | Hardware issue — software cannot prevent |
| Hibernation | ⚠️ Warned | Disable hibernation for full protection |
| Compromised OS | ❌ None | Use Qubes OS or Tails |
| Power analysis | ❌ None | Hardware countermeasure required |
