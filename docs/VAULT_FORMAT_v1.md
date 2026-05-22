# PhantomVault — Vault Format Specification v1.0

## Overview

This document is the complete specification for the PhantomVault vault container
format version 1.0. Any implementation claiming compatibility must conform exactly.

The vault container is a single binary file:
- [0    - 255 ]  Header — 256 bytes, authenticated with HMAC-SHA256
- [256 - EOF  ]  CSPRNG random padding with two encrypted vault regions at recorded offsets
---

## Header Field Table

All multi-byte integers are **little-endian**. Total header size: exactly **256 bytes**.

| Offset | Length | Field | Type | Description |
|---|---|---|---|---|
| 0 | 8 | `magic` | `[u8; 8]` | ASCII `PHVLT100` — identifies file format |
| 8 | 16 | `vault_id` | `[u8; 16]` | Random UUID generated at vault creation |
| 24 | 8 | `created_at` | `u64 LE` | Unix timestamp — informational only, never used in crypto |
| 32 | 1 | `cipher` | `u8` | `0x01` = AES-256-GCM-SIV, `0x02` = ChaCha20-Poly1305 |
| 33 | 15 | `reserved` | `[u8; 15]` | Zero bytes, reserved for future use |
| 48 | 1 | `kdf` | `u8` | `0x01` = Argon2id (only valid value in v1.0) |
| 49 | 4 | `argon2_t` | `u32 LE` | Time cost — minimum 3, enforced in code |
| 53 | 4 | `argon2_m` | `u32 LE` | Memory cost in KiB — minimum 65536 (64 MB), enforced in code |
| 57 | 4 | `argon2_p` | `u32 LE` | Parallelism — minimum 4, enforced in code |
| 61 | 16 | `argon2_salt` | `[u8; 16]` | Random bytes generated at creation, fixed for vault lifetime |
| 77 | 7 | `kdf_padding` | `[u8; 7]` | Zero bytes, alignment padding |
| 84 | 24 | `chacha20_nonce_base` | `[u8; 24]` | Random base for ChaCha20 nonce XOR construction |
| 108 | 8 | `write_counter` | `u64 LE` | Monotonic counter, incremented before each encryption |
| 116 | 8 | `region_a_offset` | `u64 LE` | Byte offset of primary vault region from file start |
| 124 | 8 | `region_a_len` | `u64 LE` | Byte length of primary vault region |
| 132 | 8 | `region_b_offset` | `u64 LE` | Byte offset of secondary vault region from file start |
| 140 | 8 | `region_b_len` | `u64 LE` | Byte length of secondary vault region |
| 148 | 32 | `padding_seed` | `[u8; 32]` | Seed for CSPRNG container padding generation |
| 180 | 44 | `header_padding` | `[u8; 44]` | Zero bytes, fills header to offset 224 |
| 224 | 32 | `header_hmac` | `[u8; 32]` | HMAC-SHA256 over bytes 0..223 inclusive |

**Total: 256 bytes**

---

## HMAC Computation

The `header_hmac` field authenticates every byte from offset 0 through offset 223.

### Key derivation
HMAC key = HKDF-SHA256(
IKM  = Argon2id(password, argon2_salt, argon2_t, argon2_m, argon2_p),
salt = vault_id,
info = b"header-auth-key-v1",
len  = 32
)


---


### Verification rule

- Verification uses the **raw on-disk bytes** — not re-serialised bytes
- This ensures padding bytes at offsets 180-223 are genuinely authenticated
- Re-serialising from the parsed struct would silently re-zero any tampered padding bytes

---

## Nonce Construction

### AES-256-GCM-SIV

A fresh 12-byte random nonce is generated from the OS CSPRNG for each encryption.
The nonce is **prepended to the ciphertext** so it can be recovered during decryption.
- nonce[0..8]  = chacha20_nonce_base[0..8] XOR write_counter.to_le_bytes()
- nonce[8..12] = chacha20_nonce_base[8..12]

The `write_counter` is incremented in the header before each encryption and
the updated header is written to disk atomically. The nonce is **not stored**
in the ciphertext — it is reconstructed from the vault header during decryption.

---

## Container Layout
[  0 -  255]  Header (256 bytes)
[256 -  EOF]  Data region
├── CSPRNG random bytes filling the entire region
├── Primary vault ciphertext at region_a_offset
└── Secondary vault ciphertext at region_b_offset

The CSPRNG padding fills the entire data region. The two vault ciphertexts are
written at their recorded offsets, overwriting the padding at those locations.
Both ciphertexts and the remaining padding are uniform high-entropy data —
standard entropy analysis tools cannot identify region boundaries.

---

## Version Compatibility

Implementations **must** reject vault files where:

- `magic` bytes do not equal `b"PHVLT100"`
- `header_hmac` does not verify correctly
- `kdf` byte is not `0x01` (Argon2id)
- `cipher` byte is not `0x01` or `0x02`
- `argon2_t < 3`, `argon2_m < 65536`, or `argon2_p < 4`

These checks prevent downgrade attacks where an attacker modifies the header
to force weaker key derivation parameters. HMAC verification would catch most
tampering, but the parameter minimums are checked before HMAC verification to
provide a clear error message.

---

## Known Limitations

The `region_b_offset` and `region_b_len` fields are visible in the header to
any party who reads this specification. The dual-region structure does not
provide cryptographic proof that only one region exists.

The `created_at` timestamp is stored for informational display purposes only.
It is never used in any cryptographic computation.
