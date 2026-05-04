# PhantomVault Threat Model v1.0

## Purpose

Security properties are only meaningful relative to a defined adversary.
This document defines the attacker tiers PhantomVault is designed against,
what it protects at each tier, and what it explicitly does not protect.

## Attacker Tiers

### T1 — Casual Access
**Profile:** No technical skills. Physical access to unlocked machine.
**Capabilities:** Browse file manager, open visible files, copy to USB.
**PhantomVault protection:** Ghost directory. Vault folder appears empty.
**Honest limit:** None. Complete protection at this tier.

### T2 — Skilled Local Attacker
**Profile:** Technical user with user-level account access.
**Capabilities:** Run CLI tools, copy files, entropy analysis, password attack attempts.
**PhantomVault protection:** Argon2id (t=3, m=64MB) makes GPU brute-force impractical.
CSPRNG padding defeats standard entropy analysis. Rust TTY input prevents
password leakage to shell history or process list.
**Honest limit:** Hardware keylogger installed before use captures password.
Out of scope for any software tool.

### T3 — Privileged Analyst (no OS compromise)
**Profile:** Root/admin access. No kernel modification.
**Capabilities:** Disk image, RAM dump, kill processes, copy container.
**PhantomVault protection:** mlock prevents key swapping. Rust ZeroizeOnDrop
zeroes keys on lock. catch_unwind zeroes keys on error paths.
**Honest limit:** DMA attacks (Thunderbolt/PCIe) bypass mlock.
Hibernation writes RAM to disk including mlock'd pages (warned at startup).

### T3.5 — Root + OS Compromise (NEW TIER)
**Profile:** Root access AND ability to modify kernel or hook system calls.
**Capabilities:** Hook TTY driver, intercept Rust function calls, fake TPM.
**PhantomVault protection:** Boot integrity warning (v2.0 with TPM).
Rust reads from TTY directly (rpassword) raising interception cost.
**Honest limit:** A fully compromised OS defeats software-only protections.
Recommendation: use PhantomVault within Qubes OS or Tails for T3.5 environments.

### T4 — Nation-State
**Profile:** Hardware implants, power analysis, legal compulsion, supply chain.
**PhantomVault protection:** Dual vault compartments allow separate file sets
under different passwords. Shamir shares distributed across jurisdictions (v1.5).
Hardware binding raises physical attack cost (v2.0).
**Honest limit:** Power analysis, cold boot with specialised equipment,
and supply chain compromise are beyond software-only mitigation.

## Explicit Non-Goals

PhantomVault does NOT and is NOT designed to:
- Help users violate any applicable law
- Defeat lawful legal process in any jurisdiction
- Protect against hardware keyloggers installed before use
- Protect against an observer watching the screen during password entry
- Protect against a fully compromised OS or bootloader (T3.5+)
- Mitigate power analysis attacks
- Resist quantum computing attacks against AES-256 (currently theoretical)

Users are solely responsible for compliance with all applicable laws
in their jurisdiction.
