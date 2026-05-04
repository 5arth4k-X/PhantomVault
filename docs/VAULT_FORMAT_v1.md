# PhantomVault Vault Format Specification v1.0

## Overview

This document is the complete specification for the PhantomVault vault
container format version 1.0. Any implementation claiming compatibility
with PhantomVault must conform to this specification exactly.

The vault container is a single binary file. The first 256 bytes are an
authenticated header. The remaining bytes are CSPRNG random padding with
two encrypted vault regions written at offsets recorded in the header.

## File Structure
[0    - 255 ]  Header (256 bytes, authenticated with HMAC-SHA256)
[256 - EOF  ]  CSPRNG padding + encrypted vault regions
## Header Field Table

All multi-byte integers are little-endian.
Total header size: exactly 256 bytes.

| Offset | Length | Field              | Type     | Description                              |
|--------|--------|--------------------|----------|------------------------------------------|
| 0      | 8      | magic              | [u8; 8]  | ASCII "PHVLT100" — identifies format     |
| 8      | 16     | vault_id           | [u8; 16] | Random UUID, generated at creation       |
| 24     | 8      | created_at         | u64 LE   | Unix timestamp — informational only      |
| 32     | 1      | cipher             | u8       | 0x01=AES-256-GCM-SIV, 0x02=ChaCha20    |
| 33     | 15     | reserved           | [u8; 15] | Zero bytes, reserved for future use      |
| 48     | 1      | kdf                | u8       | 0x01=Argon2id (only valid value)         |
| 49     | 4      | argon2_t           | u32 LE   | Time cost, minimum 3                     |
| 53     | 4      | argon2_m           | u32 LE   | Memory cost KiB, minimum 65536           |
| 57     | 4      | argon2_p           | u32 LE   | Parallelism, minimum 4                   |
| 61     | 16     | argon2_salt        | [u8; 16] | Random salt, fixed at vault creation     |
| 77     | 7      | kdf_padding        | [u8; 7]  | Zero bytes, alignment padding            |
| 84     | 24     | chacha20_nonce_base| [u8; 24] | Random base for ChaCha20 nonce XOR       |
| 108    | 8      | write_counter      | u64 LE   | Monotonic counter, incremented per write |
| 116    | 8      | region_a_offset    | u64 LE   | Byte offset of primary vault region      |
| 124    | 8      | region_a_len       | u64 LE   | Byte length of primary vault region      |
| 132    | 8      | region_b_offset    | u64 LE   | Byte offset of secondary vault region    |
| 140    | 8      | region_b_len       | u64 LE   | Byte length of secondary vault region    |
| 148    | 32     | padding_seed       | [u8; 32] | Seed for CSPRNG container padding        |
| 180    | 44     | header_padding     | [u8; 44] | Zero bytes, fills to offset 224          |
| 224    | 32     | header_hmac        | [u8; 32] | HMAC-SHA256 over bytes 0..223 inclusive  |

## HMAC Computation

The header_hmac field covers every byte from offset 0 through offset 223
inclusive. The HMAC key is derived as:

  HKDF-SHA256(
      ikm  = Argon2id(password, argon2_salt, argon2_t, argon2_m, argon2_p),
      salt = vault_id,
      info = b"header-auth-key-v1",
      len  = 32
  )

The HMAC is verified before any decryption attempt. Any modification to
any header byte — including cipher choice or KDF parameters — invalidates
the HMAC and the vault refuses to open.

## Region Layout

After the 256-byte header, the entire remaining file is filled with
CSPRNG random bytes. The two vault regions are written at the offsets
recorded in the header. Remaining bytes stay as random padding.

Both encrypted regions and the padding appear as uniform high-entropy
data. Standard entropy analysis tools cannot identify region boundaries.

## Nonce Construction

AES-256-GCM-SIV: nonce generated fresh per encryption (stored with ciphertext).
ChaCha20-Poly1305: nonce = chacha20_nonce_base[0..12] XOR write_counter
  where write_counter is the u64 value as little-endian bytes, zero-padded
  to 12 bytes. Counter is incremented before each write.

## Version Compatibility

Implementations must reject vault files where:
- magic bytes do not equal b"PHVLT100"
- header_hmac does not verify correctly
- kdf byte is not 0x01
- cipher byte is not 0x01 or 0x02
- argon2_t < 3, argon2_m < 65536, or argon2_p < 4

## Known Limitations

The region_b_offset and region_b_len fields are visible in the header to
any party reading this specification. The structure does not provide
cryptographic proof that only one region exists.

The created_at timestamp is stored for informational purposes only. It is
never used in any cryptographic computation.
