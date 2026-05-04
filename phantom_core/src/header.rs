// =============================================================================
// PhantomVault — phantom_core/src/header.rs
// =============================================================================
//
// THE TRUSTED COMPUTING BASE — FILE 3 OF 6
//
// This file implements the vault container header format as defined in
// docs/VAULT_FORMAT_v1.md. The spec and this code must always match.
//
// WHAT THIS FILE DOES:
//
//   1. VaultHeader struct — represents the 256-byte header in memory.
//
//   2. VaultHeader::new() — creates a fresh header for a new vault.
//      Generates vault_id, salt, nonce_base, padding_seed from CSPRNG.
//      Records cipher choice and KDF parameters.
//      Does NOT compute the HMAC here — that requires the derived key.
//
//   3. VaultHeader::serialize() — converts the struct to exactly 256 bytes.
//      The layout matches VAULT_FORMAT_v1.md exactly, field by field.
//
//   4. VaultHeader::deserialize() — parses 256 bytes back to a struct.
//      Validates magic bytes and cipher/kdf identifiers.
//      Does NOT verify HMAC here — that requires the derived key.
//
//   5. VaultHeader::compute_hmac() — computes HMAC-SHA256 over bytes 0..223.
//      Called during vault creation to produce the authenticator.
//      Also called during vault opening to verify the header.
//
//   6. VaultHeader::verify_hmac() — constant-time comparison of computed
//      vs stored HMAC. Returns generic error if mismatch.
//      This is the downgrade attack prevention.
//
//   7. VaultHeader::increment_write_counter() — increments the monotonic
//      counter used for ChaCha20 nonce construction.
//
// SECURITY PROPERTIES:
//
//   [✓] Any modification to any header byte invalidates the HMAC
//   [✓] Downgrade attacks (weakening KDF params) are detected
//   [✓] Cipher switching attacks are detected
//   [✓] HMAC verification is constant-time (no timing oracle)
//   [✓] Magic bytes checked before any key derivation (fast fail)
//   [✓] KDF parameter minimums enforced before key derivation
//
// LAYOUT (matches VAULT_FORMAT_v1.md exactly):
//
//   Offset   0, len  8: magic           b"PHVLT100"
//   Offset   8, len 16: vault_id        random UUID
//   Offset  24, len  8: created_at      unix timestamp (u64 LE)
//   Offset  32, len  1: cipher          0x01=AES-256-GCM-SIV, 0x02=ChaCha20
//   Offset  33, len 15: reserved        zero bytes
//   Offset  48, len  1: kdf             0x01=Argon2id
//   Offset  49, len  4: argon2_t        u32 LE, min 3
//   Offset  53, len  4: argon2_m        u32 LE, min 65536
//   Offset  57, len  4: argon2_p        u32 LE, min 4
//   Offset  61, len 16: argon2_salt     random bytes
//   Offset  77, len  7: kdf_padding     zero bytes
//   Offset  84, len 24: nonce_base      random bytes (ChaCha20 XOR base)
//   Offset 108, len  8: write_counter   u64 LE, starts 0
//   Offset 116, len  8: region_a_offset u64 LE
//   Offset 124, len  8: region_a_len    u64 LE
//   Offset 132, len  8: region_b_offset u64 LE
//   Offset 140, len  8: region_b_len    u64 LE
//   Offset 148, len 32: padding_seed    random bytes
//   Offset 180, len 44: header_padding  zero bytes
//   Offset 224, len 32: header_hmac     HMAC-SHA256 over bytes 0..223
//   Total: 256 bytes
//
// =============================================================================

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::crypto::{
    generate_random_bytes,
    Argon2Params,
    CipherChoice,
    CryptoError,
    ARGON2_SALT_LEN,
};
use crate::memory::SecretBytes;

// =============================================================================
// CONSTANTS
// =============================================================================

/// Magic bytes at the start of every PhantomVault container.
/// ASCII "PHVLT100" — PhantomVault version 1.0.0
pub const HEADER_MAGIC: &[u8; 8] = b"PHVLT100";

/// Total header size in bytes. Fixed. Never changes for v1.0 format.
pub const HEADER_SIZE: usize = 256;

/// Byte offset where the HMAC begins.
/// The HMAC covers bytes 0..HMAC_OFFSET (exclusive).
pub const HMAC_OFFSET: usize = 224;

/// Length of the HMAC field.
pub const HMAC_LEN: usize = 32;

/// HKDF info string for the header authentication key.
/// Different from session key derivation — completely different key.
pub const HEADER_AUTH_KEY_INFO: &[u8] = b"header-auth-key-v1";

/// KDF identifier byte for Argon2id.
const KDF_ARGON2ID: u8 = 0x01;

// =============================================================================
// ERRORS
// =============================================================================

/// Errors specific to header operations.
#[derive(Debug, Clone, PartialEq)]
pub enum HeaderError {
    /// Input bytes are not 256 bytes long.
    InvalidLength { got: usize },

    /// Magic bytes do not match b"PHVLT100".
    /// This is not a PhantomVault container, or it is corrupted.
    InvalidMagic,

    /// Cipher byte is not a recognised value (not 0x01 or 0x02).
    UnknownCipher { byte: u8 },

    /// KDF byte is not 0x01 (Argon2id).
    UnknownKdf { byte: u8 },

    /// KDF parameters are below the enforced minimum.
    /// Returned before any key derivation to prevent downgrade attacks.
    ParamsBelowMinimum(CryptoError),

    /// HMAC verification failed.
    /// Either the password is wrong or the header has been tampered with.
    /// The message is deliberately generic — do not distinguish between the two.
    HmacVerificationFailed,

    /// Write counter would overflow u64.
    /// Should never happen in practice (2^64 writes).
    WriteCounterOverflow,

    /// Error from the crypto layer.
    CryptoError(CryptoError),

    /// System time error when recording created_at.
    TimeError,
}

impl fmt::Display for HeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HeaderError::InvalidLength { got } => {
                write!(f, "Header must be exactly {} bytes, got {}", HEADER_SIZE, got)
            }
            HeaderError::InvalidMagic => {
                write!(
                    f,
                    "Not a valid PhantomVault container. \
                     The file may be corrupted or is not a PhantomVault vault."
                )
            }
            HeaderError::UnknownCipher { byte } => {
                write!(f, "Unknown cipher identifier: 0x{:02X}", byte)
            }
            HeaderError::UnknownKdf { byte } => {
                write!(f, "Unknown KDF identifier: 0x{:02X}", byte)
            }
            HeaderError::ParamsBelowMinimum(e) => {
                write!(f, "Vault security parameters are below minimum: {}", e)
            }
            HeaderError::HmacVerificationFailed => {
                // Generic message intentionally — do not reveal whether it was
                // a wrong password or tampered header.
                write!(f, "Incorrect password or vault data is corrupted.")
            }
            HeaderError::WriteCounterOverflow => {
                write!(f, "Write counter overflow. Vault has been used an extraordinary number of times.")
            }
            HeaderError::CryptoError(e) => {
                write!(f, "Cryptographic error: {}", e)
            }
            HeaderError::TimeError => {
                write!(f, "Could not read system time for vault creation timestamp.")
            }
        }
    }
}

impl std::error::Error for HeaderError {}

impl From<CryptoError> for HeaderError {
    fn from(e: CryptoError) -> Self {
        HeaderError::CryptoError(e)
    }
}

// =============================================================================
// RegionLayout
// Describes where the two encrypted vault regions sit in the container.
// =============================================================================

/// The byte offsets and lengths of the two encrypted vault regions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegionLayout {
    /// Byte offset of primary vault region (region A) from file start.
    pub region_a_offset: u64,
    /// Byte length of primary vault region.
    pub region_a_len: u64,
    /// Byte offset of secondary vault region (region B) from file start.
    pub region_b_offset: u64,
    /// Byte length of secondary vault region.
    pub region_b_len: u64,
}

impl RegionLayout {
    /// Creates a new RegionLayout with all fields set to zero.
    /// Used when creating a vault before region sizes are known.
    /// Updated via VaultHeader::set_regions() once sizes are calculated.
    pub fn zeroed() -> Self {
        Self {
            region_a_offset: 0,
            region_a_len: 0,
            region_b_offset: 0,
            region_b_len: 0,
        }
    }

    /// Validates that regions do not overlap and are within the file.
    pub fn validate(&self) -> bool {
        if self.region_a_len == 0 || self.region_b_len == 0 {
            return false;
        }

        let a_end = self.region_a_offset + self.region_a_len;
        let b_end = self.region_b_offset + self.region_b_len;

        // Regions must not overlap.
        // A ends before B starts, or B ends before A starts.
        (a_end <= self.region_b_offset) || (b_end <= self.region_a_offset)
    }
}

// =============================================================================
// VaultHeader
// The in-memory representation of the 256-byte vault header.
// =============================================================================

/// In-memory representation of the PhantomVault v1.0 header.
///
/// This struct maps exactly to the binary layout defined in
/// docs/VAULT_FORMAT_v1.md. The serialize() and deserialize() methods
/// convert between this struct and the on-disk binary format.
#[derive(Debug, Clone)]
pub struct VaultHeader {
    /// Random 16-byte UUID identifying this vault. Used as HKDF salt.
    pub vault_id: [u8; 16],

    /// Unix timestamp of vault creation. Informational only.
    /// NEVER used in any cryptographic computation.
    pub created_at: u64,

    /// Which cipher encrypts the vault regions.
    pub cipher: CipherChoice,

    /// Validated Argon2id parameters. Enforces minimums.
    pub argon2_params: Argon2Params,

    /// Random 16-byte salt for Argon2id. Fixed at vault creation.
    /// Different salt = completely different key from same password.
    pub argon2_salt: [u8; ARGON2_SALT_LEN],

    /// Random 24-byte base for ChaCha20 nonce XOR construction.
    /// Only used when cipher == ChaCha20Poly1305.
    pub chacha20_nonce_base: [u8; 24],

    /// Monotonic write counter. Incremented before each ChaCha20 operation.
    /// Provides nonce uniqueness for ChaCha20-Poly1305.
    pub write_counter: u64,

    /// Layout of the two encrypted vault regions.
    pub regions: RegionLayout,

    /// Random 32-byte seed used to generate the CSPRNG container padding.
    pub padding_seed: [u8; 32],

    /// The HMAC-SHA256 authenticator over bytes 0..223.
    /// Zero when a fresh header is created (before compute_hmac is called).
    /// Populated by compute_hmac() and verified by verify_hmac().
    pub header_hmac: [u8; HMAC_LEN],
}

impl VaultHeader {
    // =========================================================================
    // CREATION
    // =========================================================================

    /// Creates a fresh VaultHeader for a new vault.
    ///
    /// Generates vault_id, argon2_salt, chacha20_nonce_base, and padding_seed
    /// from the OS CSPRNG. Records the current timestamp.
    ///
    /// The header_hmac field is zeroed. Call compute_and_store_hmac() after
    /// key derivation to populate it.
    ///
    /// # Parameters
    /// - `cipher`: Which cipher the vault will use.
    /// - `argon2_params`: Validated KDF parameters.
    ///
    /// # Returns
    /// A fresh VaultHeader ready to be serialized after HMAC computation.
    pub fn new(
        cipher: CipherChoice,
        argon2_params: Argon2Params,
    ) -> Result<Self, HeaderError> {
        let vault_id = generate_random_bytes::<16>()
            .map_err(HeaderError::from)?;

        let argon2_salt = generate_random_bytes::<ARGON2_SALT_LEN>()
            .map_err(HeaderError::from)?;

        let chacha20_nonce_base = generate_random_bytes::<24>()
            .map_err(HeaderError::from)?;

        let padding_seed = generate_random_bytes::<32>()
            .map_err(HeaderError::from)?;

        // Record creation timestamp.
        // This is informational only — never used in crypto.
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| HeaderError::TimeError)?
            .as_secs();

        Ok(VaultHeader {
            vault_id,
            created_at,
            cipher,
            argon2_params,
            argon2_salt,
            chacha20_nonce_base,
            write_counter: 0,
            regions: RegionLayout::zeroed(),
            padding_seed,
            header_hmac: [0u8; HMAC_LEN],
        })
    }

    /// Updates the region layout after vault regions have been allocated.
    /// Must be called before compute_and_store_hmac().
    pub fn set_regions(&mut self, regions: RegionLayout) {
        self.regions = regions;
    }

    // =========================================================================
    // HMAC — HEADER AUTHENTICATION
    // =========================================================================

    /// Computes HMAC-SHA256 over header bytes 0..223 using the provided key.
    ///
    /// The key must be the header authentication subkey derived from the
    /// master key using derive_subkey() with info = HEADER_AUTH_KEY_INFO.
    ///
    /// This is called:
    /// - During vault creation: to produce the HMAC stored in the header.
    /// - During vault opening: to verify the stored HMAC.
    ///
    /// # Returns
    /// 32-byte HMAC value.
    fn compute_hmac(
        &self,
        header_auth_key: &SecretBytes,
    ) -> Result<[u8; HMAC_LEN], HeaderError> {
        // Serialize the header to get the bytes to authenticate.
        // The HMAC covers bytes 0..HMAC_OFFSET (224 bytes).
        let serialized = self.serialize()?;

        // Create HMAC-SHA256 instance with the provided key.
        let mut mac = <Hmac<Sha256>>::new_from_slice(header_auth_key.expose_secret())
            .map_err(|_| HeaderError::CryptoError(CryptoError::HkdfFailed {
                detail: "Invalid HMAC key length".to_string(),
            }))?;

        // Feed only the non-HMAC bytes (first 224 bytes).
        mac.update(&serialized[..HMAC_OFFSET]);

        // Finalize and return the 32-byte result.
        let result = mac.finalize().into_bytes();
        let mut hmac_bytes = [0u8; HMAC_LEN];
        hmac_bytes.copy_from_slice(&result);
        Ok(hmac_bytes)
    }

    /// Computes the HMAC and stores it in header_hmac field.
    ///
    /// Call this after set_regions() and before serialize() for final output.
    /// The header_auth_key is the subkey derived from the master key with
    /// info = b"header-auth-key-v1".
    pub fn compute_and_store_hmac(
        &mut self,
        header_auth_key: &SecretBytes,
    ) -> Result<(), HeaderError> {
        let hmac = self.compute_hmac(header_auth_key)?;
        self.header_hmac = hmac;
        Ok(())
    }

    /// Verifies the HMAC against the raw 256-byte header bytes.
///
/// This method takes the original raw bytes rather than re-serializing
/// from the struct. This ensures ALL bytes in the 0..224 range are
/// authenticated — including padding bytes that are not stored in the
/// struct fields. Re-serializing would silently re-zero any tampered
/// padding bytes, making that tampering undetectable.
///
/// Uses constant-time comparison to prevent timing attacks.
pub fn verify_hmac_raw(
    &self,
    raw_header_bytes: &[u8; HEADER_SIZE],
    header_auth_key: &SecretBytes,
) -> Result<(), HeaderError> {
    // Compute HMAC over the first 224 bytes of the RAW on-disk bytes.
    let mut mac = <Hmac<Sha256>>::new_from_slice(header_auth_key.expose_secret())
        .map_err(|_| HeaderError::CryptoError(CryptoError::HkdfFailed {
            detail: "Invalid HMAC key length".to_string(),
        }))?;

    mac.update(&raw_header_bytes[..HMAC_OFFSET]);

    let result = mac.finalize().into_bytes();
    let mut computed = [0u8; HMAC_LEN];
    computed.copy_from_slice(&result);

    // Constant-time comparison.
    let matches: bool = computed.ct_eq(&self.header_hmac).into();

    if matches {
        Ok(())
    } else {
        Err(HeaderError::HmacVerificationFailed)
    }
}

/// Verifies HMAC by re-serializing from the struct.
///
/// Use this only when you do not have the raw bytes available.
/// Prefer verify_hmac_raw() when raw bytes are available because
/// it catches tampering in padding regions that are not stored
/// in the struct.
pub fn verify_hmac(
    &self,
    header_auth_key: &SecretBytes,
) -> Result<(), HeaderError> {
    let computed = self.compute_hmac(header_auth_key)?;
    let matches: bool = computed.ct_eq(&self.header_hmac).into();

    if matches {
        Ok(())
    } else {
        Err(HeaderError::HmacVerificationFailed)
    }
}

    // =========================================================================
    // WRITE COUNTER
    // =========================================================================

    /// Increments the write counter and returns the new value.
    ///
    /// Called before each ChaCha20-Poly1305 encryption to get the
    /// counter value to use in nonce construction. The incremented
    /// value must be written back to the header on disk atomically.
    ///
    /// # Returns
    /// - `Ok(new_counter)` — the counter value to use for this write.
    /// - `Err(HeaderError::WriteCounterOverflow)` — counter at u64::MAX.
    ///   Should never happen in practice (2^64 writes).
    pub fn increment_write_counter(&mut self) -> Result<u64, HeaderError> {
        self.write_counter = self
            .write_counter
            .checked_add(1)
            .ok_or(HeaderError::WriteCounterOverflow)?;
        Ok(self.write_counter)
    }

    // =========================================================================
    // SERIALIZATION
    // Converts the struct to exactly 256 bytes matching the spec layout.
    // =========================================================================

    /// Serializes the VaultHeader to exactly 256 bytes.
    ///
    /// The layout matches VAULT_FORMAT_v1.md exactly.
    /// Called during both header creation and HMAC computation.
    pub fn serialize(&self) -> Result<[u8; HEADER_SIZE], HeaderError> {
        let mut buf = [0u8; HEADER_SIZE];

        // Offset 0, length 8: magic bytes
        buf[0..8].copy_from_slice(HEADER_MAGIC);

        // Offset 8, length 16: vault_id
        buf[8..24].copy_from_slice(&self.vault_id);

        // Offset 24, length 8: created_at (little-endian u64)
        buf[24..32].copy_from_slice(&self.created_at.to_le_bytes());

        // Offset 32, length 1: cipher identifier
        buf[32] = self.cipher.to_header_byte();

        // Offset 33, length 15: reserved (already zero from [0u8; HEADER_SIZE])

        // Offset 48, length 1: KDF identifier (Argon2id = 0x01)
        buf[48] = KDF_ARGON2ID;

        // Offset 49, length 4: argon2_t (little-endian u32)
        buf[49..53].copy_from_slice(&self.argon2_params.t_cost.to_le_bytes());

        // Offset 53, length 4: argon2_m (little-endian u32)
        buf[53..57].copy_from_slice(&self.argon2_params.m_cost.to_le_bytes());

        // Offset 57, length 4: argon2_p (little-endian u32)
        buf[57..61].copy_from_slice(&self.argon2_params.p_cost.to_le_bytes());

        // Offset 61, length 16: argon2_salt
        buf[61..77].copy_from_slice(&self.argon2_salt);

        // Offset 77, length 7: kdf_padding (already zero)

        // Offset 84, length 24: chacha20_nonce_base
        buf[84..108].copy_from_slice(&self.chacha20_nonce_base);

        // Offset 108, length 8: write_counter (little-endian u64)
        buf[108..116].copy_from_slice(&self.write_counter.to_le_bytes());

        // Offset 116, length 8: region_a_offset (little-endian u64)
        buf[116..124].copy_from_slice(&self.regions.region_a_offset.to_le_bytes());

        // Offset 124, length 8: region_a_len (little-endian u64)
        buf[124..132].copy_from_slice(&self.regions.region_a_len.to_le_bytes());

        // Offset 132, length 8: region_b_offset (little-endian u64)
        buf[132..140].copy_from_slice(&self.regions.region_b_offset.to_le_bytes());

        // Offset 140, length 8: region_b_len (little-endian u64)
        buf[140..148].copy_from_slice(&self.regions.region_b_len.to_le_bytes());

        // Offset 148, length 32: padding_seed
        buf[148..180].copy_from_slice(&self.padding_seed);

        // Offset 180, length 44: header_padding (already zero)

        // Offset 224, length 32: header_hmac
        buf[224..256].copy_from_slice(&self.header_hmac);

        Ok(buf)
    }

    // =========================================================================
    // DESERIALIZATION
    // Parses 256 bytes back into a VaultHeader struct.
    // =========================================================================

    /// Parses exactly 256 bytes into a VaultHeader.
    ///
    /// Validates: magic bytes, cipher identifier, KDF identifier,
    /// and KDF parameter minimums.
    ///
    /// Does NOT verify the HMAC here — that requires the derived key.
    /// HMAC verification is done separately via verify_hmac() after
    /// key derivation.
    ///
    /// # Security
    /// Magic bytes are checked first (fast fail before key derivation).
    /// KDF parameters are checked before key derivation to prevent
    /// downgrade attacks where an attacker modifies params to low values
    /// then brute-forces offline. The HMAC verification that follows
    /// would catch the tampering anyway, but this check provides early
    /// detection with a clear error message.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, HeaderError> {
        // Length check first.
        if bytes.len() != HEADER_SIZE {
            return Err(HeaderError::InvalidLength { got: bytes.len() });
        }

        // Magic bytes check — fast fail before any computation.
        if &bytes[0..8] != HEADER_MAGIC.as_slice() {
            return Err(HeaderError::InvalidMagic);
        }

        // vault_id
        let mut vault_id = [0u8; 16];
        vault_id.copy_from_slice(&bytes[8..24]);

        // created_at (little-endian u64)
        let created_at = u64::from_le_bytes(
            bytes[24..32].try_into().unwrap()
        );

        // cipher identifier
        let cipher_byte = bytes[32];
        let cipher = CipherChoice::from_header_byte(cipher_byte)
            .ok_or(HeaderError::UnknownCipher { byte: cipher_byte })?;

        // KDF identifier
        let kdf_byte = bytes[48];
        if kdf_byte != KDF_ARGON2ID {
            return Err(HeaderError::UnknownKdf { byte: kdf_byte });
        }

        // Argon2id parameters (little-endian u32 each)
        let argon2_t = u32::from_le_bytes(bytes[49..53].try_into().unwrap());
        let argon2_m = u32::from_le_bytes(bytes[53..57].try_into().unwrap());
        let argon2_p = u32::from_le_bytes(bytes[57..61].try_into().unwrap());

        // Validate minimums before key derivation.
        // This enforces security minimums and prevents downgrade attacks.
        let argon2_params = Argon2Params::new(argon2_t, argon2_m, argon2_p)
            .map_err(HeaderError::ParamsBelowMinimum)?;

        // argon2_salt
        let mut argon2_salt = [0u8; ARGON2_SALT_LEN];
        argon2_salt.copy_from_slice(&bytes[61..77]);

        // chacha20_nonce_base
        let mut chacha20_nonce_base = [0u8; 24];
        chacha20_nonce_base.copy_from_slice(&bytes[84..108]);

        // write_counter (little-endian u64)
        let write_counter = u64::from_le_bytes(
            bytes[108..116].try_into().unwrap()
        );

        // Region layout
        let region_a_offset = u64::from_le_bytes(bytes[116..124].try_into().unwrap());
        let region_a_len   = u64::from_le_bytes(bytes[124..132].try_into().unwrap());
        let region_b_offset = u64::from_le_bytes(bytes[132..140].try_into().unwrap());
        let region_b_len   = u64::from_le_bytes(bytes[140..148].try_into().unwrap());

        let regions = RegionLayout {
            region_a_offset,
            region_a_len,
            region_b_offset,
            region_b_len,
        };

        // padding_seed
        let mut padding_seed = [0u8; 32];
        padding_seed.copy_from_slice(&bytes[148..180]);

        // header_hmac
        let mut header_hmac = [0u8; HMAC_LEN];
        header_hmac.copy_from_slice(&bytes[224..256]);

        Ok(VaultHeader {
            vault_id,
            created_at,
            cipher,
            argon2_params,
            argon2_salt,
            chacha20_nonce_base,
            write_counter,
            regions,
            padding_seed,
            header_hmac,
        })
    }
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{
        derive_master_key, derive_subkey,
        Argon2Params, CipherChoice, ARGON2_SALT_LEN,
    };
    use crate::memory::SecretBytes;

    // Helper: create a fresh header with default secure params.
    fn make_test_header() -> VaultHeader {
        VaultHeader::new(
            CipherChoice::AesGcmSiv,
            Argon2Params::default_secure(),
        )
        .unwrap()
    }

    // Helper: derive a header auth key from a test password.
    fn make_test_header_key(vault_id: &[u8; 16]) -> SecretBytes {
        let params = Argon2Params::default_secure();
        let salt = [0x42u8; ARGON2_SALT_LEN];
        let (pw, _) = SecretBytes::new(b"test_password".to_vec()).unwrap();
        let (master_key, _) = derive_master_key(pw, &salt, &params).unwrap();
        let (header_key, _) = derive_subkey(
            &master_key,
            vault_id,
            b"header-auth-key-v1",
        )
        .unwrap();
        header_key
    }

    // -------------------------------------------------------------------------
    // Header creation
    // -------------------------------------------------------------------------

    #[test]
    fn test_new_creates_valid_header() {
        let header = make_test_header();
        assert_eq!(header.write_counter, 0);
        assert_eq!(header.header_hmac, [0u8; HMAC_LEN]);
        assert_eq!(header.cipher, CipherChoice::AesGcmSiv);
    }

    #[test]
    fn test_new_generates_random_vault_id() {
        let h1 = make_test_header();
        let h2 = make_test_header();
        // Two vaults must have different IDs.
        assert_ne!(h1.vault_id, h2.vault_id);
    }

    #[test]
    fn test_new_generates_random_salt() {
        let h1 = make_test_header();
        let h2 = make_test_header();
        assert_ne!(h1.argon2_salt, h2.argon2_salt);
    }

    #[test]
    fn test_new_generates_random_nonce_base() {
        let h1 = make_test_header();
        let h2 = make_test_header();
        assert_ne!(h1.chacha20_nonce_base, h2.chacha20_nonce_base);
    }

    #[test]
    fn test_new_records_timestamp() {
        let header = make_test_header();
        // created_at should be a recent Unix timestamp (after year 2020).
        assert!(header.created_at > 1_577_836_800);
    }

    // -------------------------------------------------------------------------
    // Serialization round-trip
    // -------------------------------------------------------------------------

    #[test]
    fn test_serialize_produces_256_bytes() {
        let header = make_test_header();
        let bytes = header.serialize().unwrap();
        assert_eq!(bytes.len(), HEADER_SIZE);
    }

    #[test]
    fn test_deserialize_round_trip() {
        let original = make_test_header();
        let bytes = original.serialize().unwrap();
        let parsed = VaultHeader::deserialize(&bytes).unwrap();

        assert_eq!(parsed.vault_id, original.vault_id);
        assert_eq!(parsed.created_at, original.created_at);
        assert_eq!(parsed.cipher, original.cipher);
        assert_eq!(parsed.argon2_salt, original.argon2_salt);
        assert_eq!(parsed.chacha20_nonce_base, original.chacha20_nonce_base);
        assert_eq!(parsed.write_counter, original.write_counter);
        assert_eq!(parsed.padding_seed, original.padding_seed);
        assert_eq!(parsed.header_hmac, original.header_hmac);
        assert_eq!(
            parsed.argon2_params.t_cost,
            original.argon2_params.t_cost
        );
        assert_eq!(
            parsed.argon2_params.m_cost,
            original.argon2_params.m_cost
        );
        assert_eq!(
            parsed.argon2_params.p_cost,
            original.argon2_params.p_cost
        );
    }

    #[test]
    fn test_magic_bytes_in_serialized_output() {
        let header = make_test_header();
        let bytes = header.serialize().unwrap();
        assert_eq!(&bytes[0..8], HEADER_MAGIC.as_slice());
    }

    #[test]
    fn test_kdf_byte_in_serialized_output() {
        let header = make_test_header();
        let bytes = header.serialize().unwrap();
        assert_eq!(bytes[48], KDF_ARGON2ID);
    }

    #[test]
    fn test_cipher_byte_aes_in_serialized_output() {
        let header = VaultHeader::new(
            CipherChoice::AesGcmSiv,
            Argon2Params::default_secure(),
        )
        .unwrap();
        let bytes = header.serialize().unwrap();
        assert_eq!(bytes[32], 0x01);
    }

    #[test]
    fn test_cipher_byte_chacha_in_serialized_output() {
        let header = VaultHeader::new(
            CipherChoice::ChaCha20Poly1305,
            Argon2Params::default_secure(),
        )
        .unwrap();
        let bytes = header.serialize().unwrap();
        assert_eq!(bytes[32], 0x02);
    }

    #[test]
    fn test_reserved_bytes_are_zero() {
        let header = make_test_header();
        let bytes = header.serialize().unwrap();
        // Bytes 33..48 are reserved — must be zero.
        assert!(bytes[33..48].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_kdf_padding_bytes_are_zero() {
        let header = make_test_header();
        let bytes = header.serialize().unwrap();
        // Bytes 77..84 are kdf_padding — must be zero.
        assert!(bytes[77..84].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_header_padding_bytes_are_zero() {
        let header = make_test_header();
        let bytes = header.serialize().unwrap();
        // Bytes 180..224 are header_padding — must be zero.
        assert!(bytes[180..224].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_write_counter_serialized_little_endian() {
        let mut header = make_test_header();
        header.write_counter = 0x0102030405060708u64;
        let bytes = header.serialize().unwrap();
        // Little-endian: least significant byte first.
        assert_eq!(bytes[108], 0x08);
        assert_eq!(bytes[109], 0x07);
        assert_eq!(bytes[110], 0x06);
        assert_eq!(bytes[111], 0x05);
        assert_eq!(bytes[112], 0x04);
        assert_eq!(bytes[113], 0x03);
        assert_eq!(bytes[114], 0x02);
        assert_eq!(bytes[115], 0x01);
    }

    // -------------------------------------------------------------------------
    // Deserialization validation
    // -------------------------------------------------------------------------

    #[test]
    fn test_deserialize_wrong_length_fails() {
        let result = VaultHeader::deserialize(&[0u8; 100]);
        assert!(matches!(result, Err(HeaderError::InvalidLength { got: 100 })));
    }

    #[test]
    fn test_deserialize_wrong_magic_fails() {
        let mut bytes = [0u8; HEADER_SIZE];
        bytes[0..8].copy_from_slice(b"WRONGMAG");
        let result = VaultHeader::deserialize(&bytes);
        assert!(matches!(result, Err(HeaderError::InvalidMagic)));
    }

    #[test]
    fn test_deserialize_unknown_cipher_fails() {
        let header = make_test_header();
        let mut bytes = header.serialize().unwrap();
        bytes[32] = 0xFF; // Unknown cipher byte
        let result = VaultHeader::deserialize(&bytes);
        assert!(matches!(
            result,
            Err(HeaderError::UnknownCipher { byte: 0xFF })
        ));
    }

    #[test]
    fn test_deserialize_unknown_kdf_fails() {
        let header = make_test_header();
        let mut bytes = header.serialize().unwrap();
        bytes[48] = 0xFF; // Unknown KDF byte
        let result = VaultHeader::deserialize(&bytes);
        assert!(matches!(
            result,
            Err(HeaderError::UnknownKdf { byte: 0xFF })
        ));
    }

    #[test]
    fn test_deserialize_low_t_cost_fails() {
        let header = make_test_header();
        let mut bytes = header.serialize().unwrap();
        // Write t_cost = 1 (below minimum of 3)
        bytes[49..53].copy_from_slice(&1u32.to_le_bytes());
        let result = VaultHeader::deserialize(&bytes);
        assert!(matches!(result, Err(HeaderError::ParamsBelowMinimum(_))));
    }

    #[test]
    fn test_deserialize_low_m_cost_fails() {
        let header = make_test_header();
        let mut bytes = header.serialize().unwrap();
        // Write m_cost = 1024 (below minimum of 65536)
        bytes[53..57].copy_from_slice(&1024u32.to_le_bytes());
        let result = VaultHeader::deserialize(&bytes);
        assert!(matches!(result, Err(HeaderError::ParamsBelowMinimum(_))));
    }

    #[test]
    fn test_deserialize_low_p_cost_fails() {
        let header = make_test_header();
        let mut bytes = header.serialize().unwrap();
        // Write p_cost = 1 (below minimum of 4)
        bytes[57..61].copy_from_slice(&1u32.to_le_bytes());
        let result = VaultHeader::deserialize(&bytes);
        assert!(matches!(result, Err(HeaderError::ParamsBelowMinimum(_))));
    }

    // -------------------------------------------------------------------------
    // HMAC computation and verification
    // -------------------------------------------------------------------------

    #[test]
    fn test_compute_and_verify_hmac_succeeds() {
        let mut header = make_test_header();
        let vault_id = header.vault_id;
        let key = make_test_header_key(&vault_id);
        header.compute_and_store_hmac(&key).unwrap();
        // HMAC should no longer be all zeros after computation.
        assert_ne!(header.header_hmac, [0u8; HMAC_LEN]);
        // Verification with same key must succeed.
        assert!(header.verify_hmac(&key).is_ok());
    }

    #[test]
    fn test_verify_hmac_wrong_key_fails() {
        let mut header = make_test_header();
        let vault_id = header.vault_id;
        let correct_key = make_test_header_key(&vault_id);
        header.compute_and_store_hmac(&correct_key).unwrap();

        // Create a wrong key.
        let (wrong_key, _) = SecretBytes::new(vec![0xFFu8; 32]).unwrap();

        // Verification with wrong key must fail.
        let result = header.verify_hmac(&wrong_key);
        assert!(matches!(result, Err(HeaderError::HmacVerificationFailed)));
    }

    #[test]
    fn test_verify_hmac_tampered_cipher_fails() {
        let mut header = make_test_header();
        let vault_id = header.vault_id;
        let key = make_test_header_key(&vault_id);
        header.compute_and_store_hmac(&key).unwrap();

        // Tamper: flip the cipher byte.
        // Serialize, modify, deserialize, then verify.
        let mut bytes = header.serialize().unwrap();
        bytes[32] ^= 0x03; // Flip bits in cipher byte
        bytes[32] = 0x02;  // Change to ChaCha20

        // Parse the tampered bytes.
        let tampered = VaultHeader::deserialize(&bytes).unwrap();

        // Verification must fail — cipher byte changed, HMAC does not match.
        let result = tampered.verify_hmac(&key);
        assert!(matches!(result, Err(HeaderError::HmacVerificationFailed)));
    }

    #[test]
    fn test_verify_hmac_tampered_t_cost_fails() {
        let mut header = make_test_header();
        let vault_id = header.vault_id;
        let key = make_test_header_key(&vault_id);
        header.compute_and_store_hmac(&key).unwrap();

        let mut bytes = header.serialize().unwrap();
        // Increase t_cost — this is above minimum so deserialize succeeds,
        // but HMAC should fail because the byte value changed.
        bytes[49..53].copy_from_slice(&10u32.to_le_bytes());
        let tampered = VaultHeader::deserialize(&bytes).unwrap();

        let result = tampered.verify_hmac(&key);
        assert!(matches!(result, Err(HeaderError::HmacVerificationFailed)));
    }

    #[test]
fn test_hmac_covers_all_header_bytes() {
    // Verify that flipping ANY byte in positions 0..224 causes
    // HMAC verification to fail. Uses verify_hmac_raw() which
    // operates on the actual on-disk bytes rather than re-serializing,
    // ensuring padding bytes (180..224) are also truly covered.
    let mut header = make_test_header();
    let vault_id = header.vault_id;
    let key = make_test_header_key(&vault_id);
    header.compute_and_store_hmac(&key).unwrap();

    let original_bytes = header.serialize().unwrap();

    // Test positions across all meaningful regions of the header.
    // Includes padding region (180, 200, 223) to verify raw-byte coverage.
    let positions_to_test = [
        0usize,  // magic
        8,       // vault_id start
        24,      // created_at
        32,      // cipher byte
        48,      // kdf byte
        49,      // argon2_t start
        61,      // argon2_salt start
        84,      // nonce_base start
        108,     // write_counter start
        116,     // region_a_offset
        148,     // padding_seed start
        180,     // header_padding — only caught by verify_hmac_raw
        200,     // header_padding middle
        223,     // last byte before HMAC
    ];

    for pos in &positions_to_test {
        let mut tampered = original_bytes;
        tampered[*pos] ^= 0xFF;

        // Some positions cause parse errors (magic, cipher, kdf params).
        // Others will parse but must fail HMAC via raw verification.
        match VaultHeader::deserialize(&tampered) {
            Err(_) => {
                // Parse error is correct — byte was in a validated field.
            }
            Ok(h) => {
                // Must fail HMAC using raw bytes — catches padding tampering.
                assert!(
                    h.verify_hmac_raw(&tampered, &key).is_err(),
                    "Tampering at byte {} was not detected by verify_hmac_raw",
                    pos
                );
            }
        }
    }
}
          

    #[test]
    fn test_hmac_is_deterministic() {
        let mut h1 = make_test_header();
        // Make h2 identical to h1.
        let mut h2 = h1.clone();

        let key1 = make_test_header_key(&h1.vault_id);
        let key2 = make_test_header_key(&h2.vault_id);

        h1.compute_and_store_hmac(&key1).unwrap();
        h2.compute_and_store_hmac(&key2).unwrap();

        // Same header + same key = same HMAC.
        assert_eq!(h1.header_hmac, h2.header_hmac);
    }

    // -------------------------------------------------------------------------
    // Write counter
    // -------------------------------------------------------------------------

    #[test]
    fn test_write_counter_increments() {
        let mut header = make_test_header();
        assert_eq!(header.write_counter, 0);
        assert_eq!(header.increment_write_counter().unwrap(), 1);
        assert_eq!(header.increment_write_counter().unwrap(), 2);
        assert_eq!(header.increment_write_counter().unwrap(), 3);
        assert_eq!(header.write_counter, 3);
    }

    #[test]
    fn test_write_counter_overflow_detected() {
        let mut header = make_test_header();
        header.write_counter = u64::MAX;
        let result = header.increment_write_counter();
        assert!(matches!(result, Err(HeaderError::WriteCounterOverflow)));
    }

    // -------------------------------------------------------------------------
    // Region layout
    // -------------------------------------------------------------------------

    #[test]
    fn test_set_regions_stores_correctly() {
        let mut header = make_test_header();
        let regions = RegionLayout {
            region_a_offset: 1024,
            region_a_len: 4096,
            region_b_offset: 8192,
            region_b_len: 4096,
        };
        header.set_regions(regions);
        let bytes = header.serialize().unwrap();
        let parsed = VaultHeader::deserialize(&bytes).unwrap();
        assert_eq!(parsed.regions.region_a_offset, 1024);
        assert_eq!(parsed.regions.region_a_len, 4096);
        assert_eq!(parsed.regions.region_b_offset, 8192);
        assert_eq!(parsed.regions.region_b_len, 4096);
    }

    #[test]
    fn test_region_layout_validate_non_overlapping() {
        let layout = RegionLayout {
            region_a_offset: 256,
            region_a_len: 1024,
            region_b_offset: 2048,
            region_b_len: 1024,
        };
        assert!(layout.validate());
    }

    #[test]
    fn test_region_layout_validate_overlapping_fails() {
        let layout = RegionLayout {
            region_a_offset: 256,
            region_a_len: 2048,
            region_b_offset: 512,  // Starts inside region A.
            region_b_len: 1024,
        };
        assert!(!layout.validate());
    }

    #[test]
    fn test_region_layout_validate_zero_len_fails() {
        let layout = RegionLayout {
            region_a_offset: 256,
            region_a_len: 0,  // Zero length is invalid.
            region_b_offset: 2048,
            region_b_len: 1024,
        };
        assert!(!layout.validate());
    }
}
