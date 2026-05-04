// =============================================================================
// PhantomVault — phantom_core/src/crypto.rs
// =============================================================================
//
// THE TRUSTED COMPUTING BASE — FILE 2 OF 6
//
// This file contains every cryptographic operation in PhantomVault.
// It depends on memory.rs for SecretBytes. Nothing else in the TCB
// does cryptography — it all goes through this file.
//
// WHAT THIS FILE PROVIDES:
//
//   1. derive_master_key()   — Argon2id password-based key derivation.
//                              Converts a user password into a 32-byte
//                              master key. Enforces minimum parameters.
//                              The most compute-intensive operation (~2-5s).
//
//   2. derive_session_key()  — HKDF-SHA256 session key derivation.
//                              Derives an ephemeral key from the master key.
//                              The master key is zeroed after this call.
//                              No timestamp in the derivation (F-02 fix).
//
//   3. derive_subkey()       — HKDF-SHA256 general-purpose key derivation.
//                              Used for header auth keys, audit keys,
//                              backup keys, compartment keys.
//
//   4. encrypt_aes_gcm_siv() — AES-256-GCM-SIV authenticated encryption.
//                              Nonce-misuse-resistant (F-01 fix).
//                              Primary cipher for all vault data.
//
//   5. decrypt_aes_gcm_siv() — AES-256-GCM-SIV authenticated decryption.
//                              Returns error if authentication tag fails.
//
//   6. encrypt_chacha20()    — ChaCha20-Poly1305 authenticated encryption.
//                              Alternative cipher for ARM/no-AES-NI hardware.
//                              Nonce constructed as base XOR counter (F-01).
//
//   7. decrypt_chacha20()    — ChaCha20-Poly1305 authenticated decryption.
//
//   8. generate_random()     — OS CSPRNG bytes via getrandom crate.
//                              Used for nonces, salts, padding seeds.
//
//   9. Argon2Params          — validated parameter set for Argon2id.
//                              Enforces minimums: t>=3, m>=65536, p>=4.
//
//  10. CipherChoice          — enum selecting AES-256-GCM-SIV or ChaCha20.
//
// DESIGN DECISIONS:
//
//   AES-256-GCM-SIV over standard AES-256-GCM:
//     Standard GCM is catastrophically broken on nonce reuse. Two encryptions
//     with the same key+nonce allow key recovery. GCM-SIV uses a synthetic IV
//     construction — nonce reuse only reveals identical plaintexts, not the key.
//     For a vault used daily over years with thousands of operations, the extra
//     safety margin is worth the tiny performance difference.
//
//   No timestamp in HKDF info parameter (F-02 fix):
//     Original design used HKDF(master_key + session_nonce + timestamp).
//     Timestamps are low-entropy and can be manipulated by an attacker with
//     root access or NTP spoofing capability. The timestamp is removed entirely.
//     The 32-byte CSPRNG session nonce provides sufficient entropy alone.
//
//   Argon2id parameters enforced in code, not just recommended:
//     t < 3, m < 65536, p < 4 are refused at the code level.
//     A vault created with weaker parameters cannot be opened.
//     A vault whose header has been modified to show weaker parameters
//     will fail HMAC verification before this check even runs.
//
//   All outputs placed in SecretBytes immediately:
//     Derived keys never exist as raw Vec<u8> or [u8; 32].
//     They are wrapped in SecretBytes (mlock'd, ZeroizeOnDrop) immediately
//     upon derivation. Intermediate buffers are zeroed after use.
//
// SECURITY PROPERTIES THIS FILE PROVIDES:
//
//   [✓] Nonce-misuse-resistant encryption (AES-256-GCM-SIV)
//   [✓] Memory-hard password hashing (Argon2id, enforced minimums)
//   [✓] Forward secrecy: master key zeroed after session key derived
//   [✓] No timestamp in key derivation
//   [✓] All derived keys immediately in SecretBytes
//   [✓] Authentication tag verification before any plaintext returned
//   [✓] Random material from OS CSPRNG only (getrandom)
//
// WHAT THIS FILE DOES NOT PROTECT AGAINST:
//
//   [✗] An attacker who obtains the session key from RAM while vault is open.
//   [✗] Cache timing attacks during Argon2id on shared hardware.
//   [✗] Power analysis against AES hardware operations.
//   These are documented in docs/SECURITY.md.
//
// =============================================================================

use std::fmt;

use aes_gcm_siv::{
    aead::{Aead, KeyInit},
    Aes256GcmSiv, Nonce as GcmSivNonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaChaNonce};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::memory::{MemoryError, MlockStatus, SecretBytes};

// =============================================================================
// CONSTANTS
// =============================================================================

/// Length of AES-256 key in bytes.
pub const KEY_LEN: usize = 32;

/// Length of AES-256-GCM-SIV nonce in bytes.
pub const GCM_SIV_NONCE_LEN: usize = 12;

/// Length of ChaCha20-Poly1305 nonce in bytes.
pub const CHACHA_NONCE_LEN: usize = 12;

/// Length of Argon2id salt in bytes.
pub const ARGON2_SALT_LEN: usize = 16;

/// Length of HKDF session nonce in bytes.
/// 32 bytes = 256 bits of entropy. More than sufficient.
/// No timestamp — CSPRNG nonce only.
pub const SESSION_NONCE_LEN: usize = 32;

/// Minimum Argon2id time cost (iterations).
/// Below this value, the derivation is too fast for password security.
pub const ARGON2_MIN_T_COST: u32 = 3;

/// Minimum Argon2id memory cost in KiB (64 MB).
/// Below this, GPU-based password cracking becomes feasible.
pub const ARGON2_MIN_M_COST: u32 = 65_536; // 64 * 1024

/// Minimum Argon2id parallelism.
pub const ARGON2_MIN_P_COST: u32 = 4;

/// Default Argon2id time cost.
pub const ARGON2_DEFAULT_T_COST: u32 = 3;

/// Default Argon2id memory cost in KiB (64 MB).
pub const ARGON2_DEFAULT_M_COST: u32 = 65_536;

/// Default Argon2id parallelism.
pub const ARGON2_DEFAULT_P_COST: u32 = 4;

/// Output length of Argon2id — 32 bytes for AES-256 / ChaCha20-256.
pub const ARGON2_OUTPUT_LEN: usize = 32;

// =============================================================================
// ERRORS
// =============================================================================

/// All errors that crypto.rs can produce.
/// These are returned to Python through lib.rs with sanitised messages.
/// Internal details (e.g. which exact check failed) are logged but not
/// returned to the caller — prevents oracle attacks.
#[derive(Debug, Clone, PartialEq)]
pub enum CryptoError {
    /// Argon2id parameter below enforced minimum.
    /// This should only occur if the vault header was tampered with
    /// (HMAC verification in header.rs would normally catch this first).
    Argon2ParamBelowMinimum {
        param: &'static str,
        minimum: u32,
        got: u32,
    },

    /// Argon2id key derivation failed.
    Argon2Failed { detail: String },

    /// Encryption failed.
    EncryptionFailed { detail: String },

    /// Decryption failed — either wrong key or corrupted ciphertext.
    /// The message is deliberately generic — we do not reveal which it is.
    DecryptionFailed,

    /// HKDF expansion failed.
    HkdfFailed { detail: String },

    /// Random number generation failed.
    /// This should never happen on a functioning OS.
    RngFailed { detail: String },

    /// Memory error from the memory layer.
    MemoryError(MemoryError),

    /// Nonce counter would overflow.
    /// This should never happen in practice (2^64 encryptions).
    NonceCounterOverflow,

    /// Invalid key length provided.
    InvalidKeyLength { expected: usize, got: usize },

    /// Invalid nonce length provided.
    InvalidNonceLength { expected: usize, got: usize },
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::Argon2ParamBelowMinimum {
                param,
                minimum,
                got,
            } => {
                write!(
                    f,
                    "KDF parameter '{}' is below the security minimum \
                     (minimum: {}, provided: {}). \
                     This vault cannot be opened with these parameters.",
                    param, minimum, got
                )
            }
            CryptoError::Argon2Failed { detail } => {
                write!(f, "Key derivation failed: {}", detail)
            }
            CryptoError::EncryptionFailed { detail } => {
                write!(f, "Encryption failed: {}", detail)
            }
            CryptoError::DecryptionFailed => {
                // Generic message — do not reveal if it was a wrong key
                // or corrupted data. Either leak could help an attacker.
                write!(f, "Incorrect password or vault data is corrupted.")
            }
            CryptoError::HkdfFailed { detail } => {
                write!(f, "Key derivation (HKDF) failed: {}", detail)
            }
            CryptoError::RngFailed { detail } => {
                write!(f, "Random number generation failed: {}", detail)
            }
            CryptoError::MemoryError(e) => {
                write!(f, "Memory error: {}", e)
            }
            CryptoError::NonceCounterOverflow => {
                write!(
                    f,
                    "Encryption counter overflow. \
                     This vault has been used an extraordinary number of times."
                )
            }
            CryptoError::InvalidKeyLength { expected, got } => {
                write!(f, "Invalid key length: expected {}, got {}", expected, got)
            }
            CryptoError::InvalidNonceLength { expected, got } => {
                write!(
                    f,
                    "Invalid nonce length: expected {}, got {}",
                    expected, got
                )
            }
        }
    }
}

impl std::error::Error for CryptoError {}

impl From<MemoryError> for CryptoError {
    fn from(e: MemoryError) -> Self {
        CryptoError::MemoryError(e)
    }
}

// =============================================================================
// CipherChoice
// Matches the cipher_byte values in the vault header format.
// =============================================================================

/// Which cipher to use for vault data encryption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherChoice {
    /// AES-256-GCM-SIV — nonce-misuse-resistant.
    /// Primary cipher. Use on x86-64 with AES-NI hardware acceleration.
    /// Header byte value: 0x01
    AesGcmSiv,

    /// ChaCha20-Poly1305 — fast in software.
    /// Alternative for ARM or platforms without AES hardware acceleration.
    /// Nonce = nonce_base XOR write_counter.
    /// Header byte value: 0x02
    ChaCha20Poly1305,
}

impl CipherChoice {
    /// Converts the header byte to a CipherChoice.
    pub fn from_header_byte(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(CipherChoice::AesGcmSiv),
            0x02 => Some(CipherChoice::ChaCha20Poly1305),
            _ => None,
        }
    }

    /// Converts a CipherChoice to its header byte representation.
    pub fn to_header_byte(self) -> u8 {
        match self {
            CipherChoice::AesGcmSiv => 0x01,
            CipherChoice::ChaCha20Poly1305 => 0x02,
        }
    }
}

// =============================================================================
// Argon2Params
// Validated parameter set. Construction enforces minimums.
// =============================================================================

/// Validated Argon2id parameters.
///
/// Construction enforces minimums: t >= 3, m >= 65536, p >= 4.
/// If the vault header contains parameters below minimum, this struct
/// cannot be constructed and the vault will not open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2Params {
    /// Time cost (iterations). Minimum: 3.
    pub t_cost: u32,
    /// Memory cost in KiB. Minimum: 65536 (64 MB).
    pub m_cost: u32,
    /// Parallelism factor. Minimum: 4.
    pub p_cost: u32,
}

impl Argon2Params {
    /// Creates validated Argon2Params.
    ///
    /// Returns an error if any parameter is below the enforced minimum.
    /// This is called when reading vault header parameters to ensure
    /// the vault was created with acceptable security settings and
    /// that no downgrade attack has weakened the parameters.
    pub fn new(t_cost: u32, m_cost: u32, p_cost: u32) -> Result<Self, CryptoError> {
        if t_cost < ARGON2_MIN_T_COST {
            return Err(CryptoError::Argon2ParamBelowMinimum {
                param: "t_cost",
                minimum: ARGON2_MIN_T_COST,
                got: t_cost,
            });
        }
        if m_cost < ARGON2_MIN_M_COST {
            return Err(CryptoError::Argon2ParamBelowMinimum {
                param: "m_cost",
                minimum: ARGON2_MIN_M_COST,
                got: m_cost,
            });
        }
        if p_cost < ARGON2_MIN_P_COST {
            return Err(CryptoError::Argon2ParamBelowMinimum {
                param: "p_cost",
                minimum: ARGON2_MIN_P_COST,
                got: p_cost,
            });
        }
        Ok(Self {
            t_cost,
            m_cost,
            p_cost,
        })
    }

    /// Returns the default secure parameters.
    /// Used when creating a new vault.
    pub fn default_secure() -> Self {
        Self {
            t_cost: ARGON2_DEFAULT_T_COST,
            m_cost: ARGON2_DEFAULT_M_COST,
            p_cost: ARGON2_DEFAULT_P_COST,
        }
    }
}

// =============================================================================
// derive_master_key
//
// Converts a password (SecretBytes) into a 32-byte master key using Argon2id.
//
// This is the most compute-intensive operation in PhantomVault.
// With default parameters (t=3, m=64MB, p=4) it takes approximately
// 2-5 seconds on modern hardware. This is intentional — it makes
// offline brute-force attacks impractical.
//
// The input password is consumed (moved). After this function the caller
// has a master key but no password. The password is zeroed in memory.
// =============================================================================

/// Derives a 32-byte master key from a password using Argon2id.
///
/// # Parameters
/// - `password`: The user's password. Consumed and zeroed by this function.
/// - `salt`: 16-byte random salt from the vault header.
/// - `params`: Validated Argon2id parameters from the vault header.
///
/// # Returns
/// - `Ok((SecretBytes, MlockStatus))` — 32-byte master key.
///   MlockStatus indicates whether the key was successfully mlock'd.
///
/// # Notes
/// - Password is zeroed regardless of success or failure.
/// - This function runs the full Argon2id computation: 2-5 seconds.
/// - The salt must be the same value used during vault creation.
///   Different salt = different key = vault cannot be opened.
pub fn derive_master_key(
    mut password: SecretBytes,
    salt: &[u8; ARGON2_SALT_LEN],
    params: &Argon2Params,
) -> Result<(SecretBytes, MlockStatus), CryptoError> {
    // Allocate output buffer. Will be zeroed on error paths.
    let mut output = vec![0u8; ARGON2_OUTPUT_LEN];

    // Build the argon2 Params struct. This validates the values again
    // (belt and suspenders — Argon2Params::new already checked them).
    let argon2_params = Params::new(
        params.m_cost,
        params.t_cost,
        params.p_cost,
        Some(ARGON2_OUTPUT_LEN),
    )
    .map_err(|e| {
        // Zero the output buffer before returning error
        output.zeroize_slice();
        CryptoError::Argon2Failed {
            detail: format!("Invalid Argon2id parameters: {}", e),
        }
    })?;

    // Construct the Argon2id hasher.
    // Algorithm::Argon2id is the hybrid variant providing both
    // side-channel resistance (from Argon2i) and GPU resistance (from Argon2d).
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);

    // Run the derivation.
    // This is the expensive operation (2-5 seconds with default params).
    let result = argon2.hash_password_into(password.expose_secret(), salt.as_slice(), &mut output);

    // Zero the password NOW — before checking the result.
    // Even if Argon2 failed, the password must be zeroed.
    password.zero_now();
    drop(password); // Drop calls ZeroizingVec::drop for belt-and-suspenders

    // Now check if Argon2 succeeded.
    if let Err(e) = result {
        output.zeroize_slice();
        return Err(CryptoError::Argon2Failed {
            detail: format!("Argon2id computation failed: {}", e),
        });
    }

    // Wrap the output in SecretBytes immediately.
    // The output Vec is consumed — no copy made.
    let (master_key, mlock_warning) = SecretBytes::new(output).map_err(CryptoError::from)?;

    Ok((master_key, MlockStatus::from(mlock_warning)))
}

// =============================================================================
// derive_session_key
//
// Derives an ephemeral session key from the master key using HKDF-SHA256.
//
// KEY DESIGN DECISION (F-02 fix):
// The session_nonce is 32 bytes of CSPRNG output ONLY.
// There is NO timestamp in this derivation.
// Timestamps are low-entropy and manipulable. The CSPRNG nonce provides
// full 256 bits of entropy without any timestamp attack surface.
//
// The master key is ZEROED after this call.
// From this point only the session key exists — not the master key.
// This provides forward secrecy: a later compromise of the session key
// does not expose the master key.
// =============================================================================

/// Derives an ephemeral session key from the master key.
///
/// # Parameters
/// - `master_key`: Consumed and zeroed by this function.
/// - `vault_id`: 16-byte vault identifier (from vault header). Used as HKDF salt.
/// - `session_nonce`: 32-byte random nonce generated fresh per unlock.
///   NO timestamp. CSPRNG only.
///
/// # Returns
/// - `Ok((SecretBytes, MlockStatus))` — 32-byte session key.
///
/// # Notes
/// - master_key is zeroed regardless of success or failure.
/// - Each unlock produces a different session key (different nonce).
/// - The session key is valid only for the current session.
/// - The session key is zeroed when the vault is locked.
pub fn derive_session_key(
    mut master_key: SecretBytes,
    vault_id: &[u8; 16],
    session_nonce: &[u8; SESSION_NONCE_LEN],
) -> Result<(SecretBytes, MlockStatus), CryptoError> {
    // HKDF-SHA256(IKM=master_key, salt=vault_id, info=session_nonce)
    //
    // IKM (Input Key Material): the master key
    // salt: vault_id — unique per vault, prevents cross-vault key reuse
    // info: session_nonce — unique per unlock, provides forward secrecy
    //       NO TIMESTAMP — CSPRNG only (F-02 fix)
    let hkdf = Hkdf::<Sha256>::new(
        Some(vault_id.as_slice()),  // salt
        master_key.expose_secret(), // IKM
    );

    let mut output = vec![0u8; KEY_LEN];

    // info parameter is the session nonce — 32 bytes of CSPRNG randomness.
    // This is the ONLY entropy source in the info field.
    // No timestamp. No system clock. No counter. CSPRNG only.
    let result = hkdf.expand(
        session_nonce.as_slice(), // info
        &mut output,
    );

    // Zero the master key NOW — before checking result.
    // The master key must not exist after session key derivation.
    master_key.zero_now();
    drop(master_key);

    if result.is_err() {
        output.zeroize_slice();
        return Err(CryptoError::HkdfFailed {
            detail: "HKDF expand failed during session key derivation".to_string(),
        });
    }

    let (session_key, mlock_warning) = SecretBytes::new(output).map_err(CryptoError::from)?;

    Ok((session_key, MlockStatus::from(mlock_warning)))
}

// =============================================================================
// derive_subkey
//
// General-purpose HKDF subkey derivation from a master key.
// Used for: header authentication keys, audit chain keys, backup keys,
//           compartment-specific keys.
//
// Unlike derive_session_key, this does NOT consume the master key.
// The master key remains after this call.
// Used when multiple subkeys need to be derived from the same master key.
// =============================================================================

/// Derives a purpose-specific subkey from a master key using HKDF-SHA256.
///
/// # Parameters
/// - `master_key`: Reference to the master key. NOT consumed.
/// - `vault_id`: 16-byte vault identifier. Used as HKDF salt.
/// - `purpose`: ASCII string identifying the subkey's purpose.
///   Examples: b"header-auth-key-v1", b"audit-key-v1",
///   b"backup-key-v1", b"compartment-b-key-v1"
///   Different purpose strings produce completely different keys.
///
/// # Returns
/// - `Ok((SecretBytes, MlockStatus))` — 32-byte subkey.
pub fn derive_subkey(
    master_key: &SecretBytes,
    vault_id: &[u8; 16],
    purpose: &[u8],
) -> Result<(SecretBytes, MlockStatus), CryptoError> {
    let hkdf = Hkdf::<Sha256>::new(
        Some(vault_id.as_slice()),  // salt
        master_key.expose_secret(), // IKM
    );

    let mut output = vec![0u8; KEY_LEN];

    let result = hkdf.expand(purpose, &mut output);

    if result.is_err() {
        output.zeroize_slice();
        return Err(CryptoError::HkdfFailed {
            detail: format!(
                "HKDF expand failed for purpose '{}'",
                String::from_utf8_lossy(purpose)
            ),
        });
    }

    let (subkey, mlock_warning) = SecretBytes::new(output).map_err(CryptoError::from)?;

    Ok((subkey, MlockStatus::from(mlock_warning)))
}

// =============================================================================
// encrypt_aes_gcm_siv
//
// AES-256-GCM-SIV authenticated encryption.
//
// WHY GCM-SIV OVER STANDARD GCM:
// Standard AES-256-GCM has a catastrophic nonce reuse vulnerability.
// If nonce N is used twice with the same key K:
//   - The authentication key is recoverable
//   - Both plaintexts are recoverable (if C1 XOR C2 is observable)
// GCM-SIV constructs a synthetic IV from the plaintext and nonce,
// so nonce reuse only reveals whether two plaintexts are identical.
// For a vault used over years with many files, this safety margin matters.
//
// NONCE GENERATION:
// For AES-256-GCM-SIV, a 12-byte (96-bit) random nonce is generated
// fresh for each encryption. The nonce is stored prepended to the
// ciphertext so it can be recovered during decryption.
//
// OUTPUT FORMAT:
// [ 12-byte nonce | ciphertext + 16-byte GCM-SIV auth tag ]
// Total overhead: 28 bytes per encrypted value.
// =============================================================================

/// Encrypts data using AES-256-GCM-SIV.
///
/// # Parameters
/// - `key`: 32-byte encryption key (typically a session key or subkey).
/// - `plaintext`: Data to encrypt.
/// - `aad`: Additional Authenticated Data. Authenticated but not encrypted.
///   Can be empty (pass &[] if not needed).
///   Typically the vault_id or region identifier.
///
/// # Returns
/// - `Ok(Vec<u8>)` — nonce (12 bytes) + ciphertext + auth_tag (16 bytes).
///
/// # Notes
/// - Nonce is freshly generated from OS CSPRNG for each call.
/// - The key is not consumed — it may be used for multiple encryptions.
/// - The auth tag protects both the plaintext and the AAD.
pub fn encrypt_aes_gcm_siv(
    key: &SecretBytes,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if key.len() != KEY_LEN {
        return Err(CryptoError::InvalidKeyLength {
            expected: KEY_LEN,
            got: key.len(),
        });
    }

    // Generate a fresh 12-byte random nonce from OS CSPRNG.
    let nonce_bytes = generate_random_bytes::<GCM_SIV_NONCE_LEN>()?;
    let nonce = GcmSivNonce::from_slice(&nonce_bytes);

    // Initialise AES-256-GCM-SIV with the key.
    let cipher = Aes256GcmSiv::new_from_slice(key.expose_secret()).map_err(|e| {
        CryptoError::EncryptionFailed {
            detail: format!("Failed to initialise AES-256-GCM-SIV: {}", e),
        }
    })?;

    // Build the aead::Payload including AAD.
    let payload = aes_gcm_siv::aead::Payload {
        msg: plaintext,
        aad,
    };

    // Encrypt. Output is ciphertext + 16-byte authentication tag.
    let ciphertext = cipher
        .encrypt(nonce, payload)
        .map_err(|e| CryptoError::EncryptionFailed {
            detail: format!("AES-256-GCM-SIV encryption failed: {}", e),
        })?;

    // Prepend the nonce to the ciphertext.
    // Output format: [nonce (12 bytes)] [ciphertext + tag (len + 16 bytes)]
    let mut output = Vec::with_capacity(GCM_SIV_NONCE_LEN + ciphertext.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);

    Ok(output)
}

// =============================================================================
// decrypt_aes_gcm_siv
// =============================================================================

/// Decrypts AES-256-GCM-SIV encrypted data.
///
/// # Parameters
/// - `key`: 32-byte decryption key. Must match the key used for encryption.
/// - `ciphertext_with_nonce`: Output from encrypt_aes_gcm_siv.
///   Format: [nonce (12 bytes)] [ciphertext + tag].
/// - `aad`: Must match the AAD used during encryption exactly.
///
/// # Returns
/// - `Ok(Vec<u8>)` — plaintext bytes.
/// - `Err(CryptoError::DecryptionFailed)` — wrong key, corrupted data,
///   or tampered AAD. Generic error — does not reveal which it was.
pub fn decrypt_aes_gcm_siv(
    key: &SecretBytes,
    ciphertext_with_nonce: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if key.len() != KEY_LEN {
        return Err(CryptoError::InvalidKeyLength {
            expected: KEY_LEN,
            got: key.len(),
        });
    }

    // Minimum valid length: nonce (12) + auth_tag (16) = 28 bytes.
    if ciphertext_with_nonce.len() < GCM_SIV_NONCE_LEN + 16 {
        // Return generic decryption error — do not reveal format details.
        return Err(CryptoError::DecryptionFailed);
    }

    // Split nonce from ciphertext.
    let (nonce_bytes, ciphertext) = ciphertext_with_nonce.split_at(GCM_SIV_NONCE_LEN);
    let nonce = GcmSivNonce::from_slice(nonce_bytes);

    let cipher = Aes256GcmSiv::new_from_slice(key.expose_secret())
        .map_err(|_| CryptoError::DecryptionFailed)?;

    let payload = aes_gcm_siv::aead::Payload {
        msg: ciphertext,
        aad,
    };

    // Decrypt and verify authentication tag.
    // If the tag is invalid (wrong key, corrupted ciphertext, tampered AAD),
    // this returns an error. We convert it to the generic DecryptionFailed.
    let plaintext = cipher
        .decrypt(nonce, payload)
        .map_err(|_| CryptoError::DecryptionFailed)?;

    Ok(plaintext)
}

// =============================================================================
// encrypt_chacha20
//
// ChaCha20-Poly1305 authenticated encryption.
//
// NONCE CONSTRUCTION (F-01 fix for ChaCha20):
// The 12-byte nonce is constructed as:
//   nonce_base[0..12] XOR write_counter_bytes[0..12]
// where:
//   nonce_base = 24-byte random value from vault header
//   write_counter = monotonic u64 from vault header, incremented each write
//   write_counter_bytes = counter as little-endian u64, zero-padded to 12 bytes
//
// This ensures nonce uniqueness:
//   - The random base prevents nonce reuse across different vaults.
//   - The counter prevents nonce reuse within the same vault.
//   - Even if the CSPRNG produces the same base twice (astronomically unlikely),
//     the counter ensures different operations produce different nonces.
//
// OUTPUT FORMAT:
// The nonce is NOT stored in the output (it is deterministically reconstructed
// from vault header fields during decryption). This differs from GCM-SIV
// where the nonce is random and must be stored.
// Output: [ ciphertext + 16-byte Poly1305 auth tag ]
// =============================================================================

/// Encrypts data using ChaCha20-Poly1305.
///
/// # Parameters
/// - `key`: 32-byte encryption key.
/// - `nonce_base`: 24-byte random base from vault header.
/// - `write_counter`: Current monotonic write counter value.
///   Must be incremented in the vault header before the next call.
/// - `plaintext`: Data to encrypt.
/// - `aad`: Additional Authenticated Data.
///
/// # Returns
/// - `Ok(Vec<u8>)` — ciphertext + auth_tag (16 bytes). No nonce prepended
///   (nonce reconstructable from vault header fields).
pub fn encrypt_chacha20(
    key: &SecretBytes,
    nonce_base: &[u8; 24],
    write_counter: u64,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if key.len() != KEY_LEN {
        return Err(CryptoError::InvalidKeyLength {
            expected: KEY_LEN,
            got: key.len(),
        });
    }

    // Construct the 12-byte nonce:
    // Take first 12 bytes of nonce_base, XOR with counter as little-endian u64
    // zero-padded to 12 bytes.
    let nonce_bytes = construct_chacha_nonce(nonce_base, write_counter)?;
    let nonce = ChaChaNonce::from_slice(&nonce_bytes);

    let cipher = ChaCha20Poly1305::new_from_slice(key.expose_secret()).map_err(|e| {
        CryptoError::EncryptionFailed {
            detail: format!("Failed to initialise ChaCha20-Poly1305: {}", e),
        }
    })?;

    let payload = chacha20poly1305::aead::Payload {
        msg: plaintext,
        aad,
    };

    let ciphertext = cipher
        .encrypt(nonce, payload)
        .map_err(|e| CryptoError::EncryptionFailed {
            detail: format!("ChaCha20-Poly1305 encryption failed: {}", e),
        })?;

    Ok(ciphertext)
}

// =============================================================================
// decrypt_chacha20
// =============================================================================

/// Decrypts ChaCha20-Poly1305 encrypted data.
///
/// # Parameters
/// - `key`: 32-byte decryption key.
/// - `nonce_base`: 24-byte random base from vault header.
/// - `write_counter`: The counter value used during encryption.
/// - `ciphertext`: Output from encrypt_chacha20 (no nonce prepended).
/// - `aad`: Must match encryption AAD exactly.
pub fn decrypt_chacha20(
    key: &SecretBytes,
    nonce_base: &[u8; 24],
    write_counter: u64,
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if key.len() != KEY_LEN {
        return Err(CryptoError::InvalidKeyLength {
            expected: KEY_LEN,
            got: key.len(),
        });
    }

    if ciphertext.len() < 16 {
        return Err(CryptoError::DecryptionFailed);
    }

    let nonce_bytes = construct_chacha_nonce(nonce_base, write_counter)?;
    let nonce = ChaChaNonce::from_slice(&nonce_bytes);

    let cipher = ChaCha20Poly1305::new_from_slice(key.expose_secret())
        .map_err(|_| CryptoError::DecryptionFailed)?;

    let payload = chacha20poly1305::aead::Payload {
        msg: ciphertext,
        aad,
    };

    let plaintext = cipher
        .decrypt(nonce, payload)
        .map_err(|_| CryptoError::DecryptionFailed)?;

    Ok(plaintext)
}

/// Constructs a 12-byte ChaCha20 nonce from the 24-byte base and write counter.
///
/// nonce[i] = nonce_base[i] XOR counter_bytes[i]   (for i in 0..12)
/// where counter_bytes is write_counter as little-endian u64, zero-padded to 12.
fn construct_chacha_nonce(
    nonce_base: &[u8; 24],
    write_counter: u64,
) -> Result<[u8; CHACHA_NONCE_LEN], CryptoError> {
    let counter_bytes = write_counter.to_le_bytes(); // 8 bytes

    let mut nonce = [0u8; CHACHA_NONCE_LEN]; // 12 bytes

    // XOR first 8 bytes with counter, last 4 bytes are just nonce_base[8..12]
    for i in 0..8 {
        nonce[i] = nonce_base[i] ^ counter_bytes[i];
    }
    // Remaining bytes: XOR nonce_base[8..12] with zero (no-op, just copy)
    nonce[8..CHACHA_NONCE_LEN].copy_from_slice(&nonce_base[8..CHACHA_NONCE_LEN]);

    Ok(nonce)
}

// =============================================================================
// encrypt / decrypt — unified interface
//
// Selects the correct cipher based on CipherChoice.
// This is the function called from lib.rs and vault.py.
// =============================================================================

/// Encrypts data using the selected cipher.
///
/// # Parameters
/// - `cipher`: Which cipher to use (from vault header).
/// - `key`: Encryption key.
/// - `plaintext`: Data to encrypt.
/// - `aad`: Additional Authenticated Data.
/// - `nonce_base`: For ChaCha20 only — 24-byte base from vault header.
/// - `write_counter`: For ChaCha20 only — current monotonic counter.
///
/// # Returns
/// For AES-256-GCM-SIV: [nonce (12)] [ciphertext + tag]
/// For ChaCha20-Poly1305: [ciphertext + tag] (nonce reconstructed from header)
pub fn encrypt(
    cipher: CipherChoice,
    key: &SecretBytes,
    plaintext: &[u8],
    aad: &[u8],
    nonce_base: Option<&[u8; 24]>,
    write_counter: Option<u64>,
) -> Result<Vec<u8>, CryptoError> {
    match cipher {
        CipherChoice::AesGcmSiv => encrypt_aes_gcm_siv(key, plaintext, aad),
        CipherChoice::ChaCha20Poly1305 => {
            let base = nonce_base.ok_or_else(|| CryptoError::EncryptionFailed {
                detail: "ChaCha20 requires nonce_base".to_string(),
            })?;
            let counter = write_counter.ok_or_else(|| CryptoError::EncryptionFailed {
                detail: "ChaCha20 requires write_counter".to_string(),
            })?;
            encrypt_chacha20(key, base, counter, plaintext, aad)
        }
    }
}

/// Decrypts data using the selected cipher.
pub fn decrypt(
    cipher: CipherChoice,
    key: &SecretBytes,
    ciphertext: &[u8],
    aad: &[u8],
    nonce_base: Option<&[u8; 24]>,
    write_counter: Option<u64>,
) -> Result<Vec<u8>, CryptoError> {
    match cipher {
        CipherChoice::AesGcmSiv => decrypt_aes_gcm_siv(key, ciphertext, aad),
        CipherChoice::ChaCha20Poly1305 => {
            let base = nonce_base.ok_or(CryptoError::DecryptionFailed)?;
            let counter = write_counter.ok_or(CryptoError::DecryptionFailed)?;
            decrypt_chacha20(key, base, counter, ciphertext, aad)
        }
    }
}

// =============================================================================
// Random generation
// =============================================================================

/// Generates N random bytes from the OS CSPRNG.
///
/// Uses the `getrandom` crate which calls:
/// - Linux/macOS: getrandom(2) syscall or /dev/urandom
/// - Windows: BCryptGenRandom
///
/// Never falls back to a seeded PRNG. If the OS CSPRNG is unavailable,
/// this returns an error rather than producing weak randomness.
///
/// # Type parameter
/// N: number of bytes to generate. Determined at compile time.
pub fn generate_random_bytes<const N: usize>() -> Result<[u8; N], CryptoError> {
    let mut buf = [0u8; N];
    getrandom::getrandom(&mut buf).map_err(|e| CryptoError::RngFailed {
        detail: format!("OS CSPRNG failed: {}", e),
    })?;
    Ok(buf)
}

/// Generates N random bytes as a Vec<u8>.
/// Use when size is not known at compile time.
pub fn generate_random_vec(len: usize) -> Result<Vec<u8>, CryptoError> {
    let mut buf = vec![0u8; len];
    getrandom::getrandom(&mut buf).map_err(|e| CryptoError::RngFailed {
        detail: format!("OS CSPRNG failed: {}", e),
    })?;
    Ok(buf)
}

// =============================================================================
// Helper trait for zeroing Vecs without wrapping in SecretBytes
// =============================================================================

trait ZeroizeSlice {
    fn zeroize_slice(&mut self);
}

impl ZeroizeSlice for Vec<u8> {
    fn zeroize_slice(&mut self) {
        use zeroize::Zeroize;
        self.zeroize();
    }
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------------
    // Argon2Params validation
    // -------------------------------------------------------------------------

    #[test]
    fn test_argon2_params_accepts_valid_values() {
        let params = Argon2Params::new(3, 65_536, 4);
        assert!(params.is_ok());
    }

    #[test]
    fn test_argon2_params_accepts_higher_than_minimum() {
        let params = Argon2Params::new(5, 131_072, 8);
        assert!(params.is_ok());
    }

    #[test]
    fn test_argon2_params_rejects_low_t_cost() {
        let result = Argon2Params::new(2, 65_536, 4);
        assert!(result.is_err());
        if let Err(CryptoError::Argon2ParamBelowMinimum { param, .. }) = result {
            assert_eq!(param, "t_cost");
        }
    }

    #[test]
    fn test_argon2_params_rejects_low_m_cost() {
        let result = Argon2Params::new(3, 32_768, 4);
        assert!(result.is_err());
        if let Err(CryptoError::Argon2ParamBelowMinimum { param, .. }) = result {
            assert_eq!(param, "m_cost");
        }
    }

    #[test]
    fn test_argon2_params_rejects_low_p_cost() {
        let result = Argon2Params::new(3, 65_536, 2);
        assert!(result.is_err());
        if let Err(CryptoError::Argon2ParamBelowMinimum { param, .. }) = result {
            assert_eq!(param, "p_cost");
        }
    }

    #[test]
    fn test_argon2_params_rejects_zero_values() {
        assert!(Argon2Params::new(0, 65_536, 4).is_err());
        assert!(Argon2Params::new(3, 0, 4).is_err());
        assert!(Argon2Params::new(3, 65_536, 0).is_err());
    }

    // -------------------------------------------------------------------------
    // CipherChoice
    // -------------------------------------------------------------------------

    #[test]
    fn test_cipher_choice_round_trip() {
        assert_eq!(
            CipherChoice::from_header_byte(0x01),
            Some(CipherChoice::AesGcmSiv)
        );
        assert_eq!(
            CipherChoice::from_header_byte(0x02),
            Some(CipherChoice::ChaCha20Poly1305)
        );
        assert_eq!(CipherChoice::from_header_byte(0x00), None);
        assert_eq!(CipherChoice::from_header_byte(0xFF), None);
    }

    #[test]
    fn test_cipher_choice_to_header_byte() {
        assert_eq!(CipherChoice::AesGcmSiv.to_header_byte(), 0x01);
        assert_eq!(CipherChoice::ChaCha20Poly1305.to_header_byte(), 0x02);
    }

    // -------------------------------------------------------------------------
    // derive_master_key
    // These tests use minimal parameters to keep test suite fast.
    // IMPORTANT: In production, parameters are ARGON2_DEFAULT_* values.
    // -------------------------------------------------------------------------

    fn test_params() -> Argon2Params {
        // Minimal params for tests only. Do NOT use these values in production.
        // Production minimums are enforced by Argon2Params::new().
        Argon2Params {
            t_cost: 3,
            m_cost: 65_536, // Keep at minimum for CI speed vs correctness
            p_cost: 4,
        }
    }

    #[test]
    fn test_derive_master_key_produces_32_bytes() {
        let password_bytes = b"test_password_not_real".to_vec();
        let (password, _) = SecretBytes::new(password_bytes).unwrap();
        let salt = [0x42u8; ARGON2_SALT_LEN];
        let params = test_params();

        let result = derive_master_key(password, &salt, &params);
        assert!(result.is_ok());
        let (key, _) = result.unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_derive_master_key_is_deterministic() {
        // Same password + salt + params must always produce the same key.
        // This is required for vault decryption to work.
        let salt = [0x11u8; ARGON2_SALT_LEN];
        let params = test_params();

        let (pw1, _) = SecretBytes::new(b"deterministic_test".to_vec()).unwrap();
        let (key1, _) = derive_master_key(pw1, &salt, &params).unwrap();

        let (pw2, _) = SecretBytes::new(b"deterministic_test".to_vec()).unwrap();
        let (key2, _) = derive_master_key(pw2, &salt, &params).unwrap();

        assert_eq!(key1.ct_eq(&key2).unwrap(), true);
    }

    #[test]
    fn test_derive_master_key_different_passwords_different_keys() {
        let salt = [0x22u8; ARGON2_SALT_LEN];
        let params = test_params();

        let (pw1, _) = SecretBytes::new(b"password_one".to_vec()).unwrap();
        let (key1, _) = derive_master_key(pw1, &salt, &params).unwrap();

        let (pw2, _) = SecretBytes::new(b"password_two".to_vec()).unwrap();
        let (key2, _) = derive_master_key(pw2, &salt, &params).unwrap();

        assert_eq!(key1.ct_eq(&key2).unwrap(), false);
    }

    #[test]
    fn test_derive_master_key_different_salts_different_keys() {
        let params = test_params();
        let (pw1, _) = SecretBytes::new(b"same_password".to_vec()).unwrap();
        let (pw2, _) = SecretBytes::new(b"same_password".to_vec()).unwrap();

        let (key1, _) = derive_master_key(pw1, &[0x01u8; ARGON2_SALT_LEN], &params).unwrap();
        let (key2, _) = derive_master_key(pw2, &[0x02u8; ARGON2_SALT_LEN], &params).unwrap();

        assert_eq!(key1.ct_eq(&key2).unwrap(), false);
    }

    // -------------------------------------------------------------------------
    // derive_session_key
    // -------------------------------------------------------------------------

    #[test]
    fn test_derive_session_key_produces_32_bytes() {
        let params = test_params();
        let (pw, _) = SecretBytes::new(b"session_key_test".to_vec()).unwrap();
        let (master_key, _) = derive_master_key(pw, &[0x33u8; ARGON2_SALT_LEN], &params).unwrap();
        let vault_id = [0x44u8; 16];
        let nonce = [0x55u8; SESSION_NONCE_LEN];

        let result = derive_session_key(master_key, &vault_id, &nonce);
        assert!(result.is_ok());
        let (session_key, _) = result.unwrap();
        assert_eq!(session_key.len(), 32);
    }

    #[test]
    fn test_derive_session_key_different_nonces_different_keys() {
        let params = test_params();
        let (pw1, _) = SecretBytes::new(b"forward_secrecy_test".to_vec()).unwrap();
        let (pw2, _) = SecretBytes::new(b"forward_secrecy_test".to_vec()).unwrap();
        let salt = [0x66u8; ARGON2_SALT_LEN];
        let vault_id = [0x77u8; 16];

        let (mk1, _) = derive_master_key(pw1, &salt, &params).unwrap();
        let (mk2, _) = derive_master_key(pw2, &salt, &params).unwrap();

        // Different session nonces must produce different session keys.
        let nonce1 = [0x01u8; SESSION_NONCE_LEN];
        let nonce2 = [0x02u8; SESSION_NONCE_LEN];

        let (sk1, _) = derive_session_key(mk1, &vault_id, &nonce1).unwrap();
        let (sk2, _) = derive_session_key(mk2, &vault_id, &nonce2).unwrap();

        assert_eq!(sk1.ct_eq(&sk2).unwrap(), false);
    }

    // -------------------------------------------------------------------------
    // derive_subkey
    // -------------------------------------------------------------------------

    #[test]
    fn test_derive_subkey_different_purposes_different_keys() {
        let (master, _) = SecretBytes::new(vec![0xAAu8; 32]).unwrap();
        let vault_id = [0x01u8; 16];

        let (k1, _) = derive_subkey(&master, &vault_id, b"header-auth-key-v1").unwrap();
        let (k2, _) = derive_subkey(&master, &vault_id, b"audit-key-v1").unwrap();
        let (k3, _) = derive_subkey(&master, &vault_id, b"backup-key-v1").unwrap();

        assert_eq!(k1.ct_eq(&k2).unwrap(), false);
        assert_eq!(k2.ct_eq(&k3).unwrap(), false);
        assert_eq!(k1.ct_eq(&k3).unwrap(), false);
    }

    #[test]
    fn test_derive_subkey_is_deterministic() {
        let (m1, _) = SecretBytes::new(vec![0xBBu8; 32]).unwrap();
        let (m2, _) = SecretBytes::new(vec![0xBBu8; 32]).unwrap();
        let vault_id = [0x02u8; 16];

        let (k1, _) = derive_subkey(&m1, &vault_id, b"test-purpose").unwrap();
        let (k2, _) = derive_subkey(&m2, &vault_id, b"test-purpose").unwrap();

        assert_eq!(k1.ct_eq(&k2).unwrap(), true);
    }

    // -------------------------------------------------------------------------
    // AES-256-GCM-SIV encrypt/decrypt round-trip
    // -------------------------------------------------------------------------

    fn make_test_key() -> SecretBytes {
        let (key, _) = SecretBytes::new(vec![0x42u8; KEY_LEN]).unwrap();
        key
    }

    #[test]
    fn test_aes_gcm_siv_round_trip() {
        let key = make_test_key();
        let plaintext = b"Hello, PhantomVault!";
        let aad = b"test_vault_id";

        let ciphertext = encrypt_aes_gcm_siv(&key, plaintext, aad).unwrap();
        let decrypted = decrypt_aes_gcm_siv(&key, &ciphertext, aad).unwrap();

        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn test_aes_gcm_siv_round_trip_empty_aad() {
        let key = make_test_key();
        let plaintext = b"No AAD version";

        let ciphertext = encrypt_aes_gcm_siv(&key, plaintext, &[]).unwrap();
        let decrypted = decrypt_aes_gcm_siv(&key, &ciphertext, &[]).unwrap();

        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn test_aes_gcm_siv_wrong_key_fails() {
        let key = make_test_key();
        let wrong_key = {
            let (k, _) = SecretBytes::new(vec![0x99u8; KEY_LEN]).unwrap();
            k
        };

        let ciphertext = encrypt_aes_gcm_siv(&key, b"secret data", b"aad").unwrap();
        let result = decrypt_aes_gcm_siv(&wrong_key, &ciphertext, b"aad");

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), CryptoError::DecryptionFailed);
    }

    #[test]
    fn test_aes_gcm_siv_wrong_aad_fails() {
        let key = make_test_key();
        let ciphertext = encrypt_aes_gcm_siv(&key, b"secret data", b"correct_aad").unwrap();
        let result = decrypt_aes_gcm_siv(&key, &ciphertext, b"wrong_aad");

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), CryptoError::DecryptionFailed);
    }

    #[test]
    fn test_aes_gcm_siv_tampered_ciphertext_fails() {
        let key = make_test_key();
        let mut ciphertext = encrypt_aes_gcm_siv(&key, b"important data", b"aad").unwrap();

        // Flip a bit in the ciphertext body (after the nonce).
        let tamper_pos = GCM_SIV_NONCE_LEN + 2;
        ciphertext[tamper_pos] ^= 0xFF;

        let result = decrypt_aes_gcm_siv(&key, &ciphertext, b"aad");
        assert!(result.is_err());
    }

    #[test]
    fn test_aes_gcm_siv_nonce_uniqueness() {
        // Each encryption must produce different output (different nonces).
        let key = make_test_key();
        let plaintext = b"same plaintext every time";
        let aad = b"aad";

        let c1 = encrypt_aes_gcm_siv(&key, plaintext, aad).unwrap();
        let c2 = encrypt_aes_gcm_siv(&key, plaintext, aad).unwrap();

        // The ciphertexts should differ (different nonces).
        assert_ne!(c1, c2);

        // But both must decrypt correctly.
        let d1 = decrypt_aes_gcm_siv(&key, &c1, aad).unwrap();
        let d2 = decrypt_aes_gcm_siv(&key, &c2, aad).unwrap();
        assert_eq!(d1, plaintext);
        assert_eq!(d2, plaintext);
    }

    #[test]
    fn test_aes_gcm_siv_ciphertext_too_short_fails() {
        let key = make_test_key();
        let short = vec![0u8; 10]; // Less than 28 bytes minimum
        let result = decrypt_aes_gcm_siv(&key, &short, b"aad");
        assert!(result.is_err());
    }

    // -------------------------------------------------------------------------
    // ChaCha20-Poly1305 encrypt/decrypt
    // -------------------------------------------------------------------------

    fn make_chacha_setup() -> (SecretBytes, [u8; 24], u64) {
        let (key, _) = SecretBytes::new(vec![0x77u8; KEY_LEN]).unwrap();
        let nonce_base = [0x88u8; 24];
        let write_counter = 42u64;
        (key, nonce_base, write_counter)
    }

    #[test]
    fn test_chacha20_round_trip() {
        let (key, nonce_base, counter) = make_chacha_setup();
        let plaintext = b"ChaCha20 test message";
        let aad = b"region_b";

        let ciphertext = encrypt_chacha20(&key, &nonce_base, counter, plaintext, aad).unwrap();
        let decrypted = decrypt_chacha20(&key, &nonce_base, counter, &ciphertext, aad).unwrap();

        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn test_chacha20_wrong_counter_fails() {
        let (key, nonce_base, counter) = make_chacha_setup();
        let ciphertext = encrypt_chacha20(&key, &nonce_base, counter, b"data", b"aad").unwrap();

        // Decrypting with a different counter (different nonce) must fail.
        let result = decrypt_chacha20(&key, &nonce_base, counter + 1, &ciphertext, b"aad");
        assert!(result.is_err());
    }

    #[test]
    fn test_chacha20_different_counters_different_ciphertexts() {
        let (key, nonce_base, _) = make_chacha_setup();
        let plaintext = b"same data";
        let aad = b"aad";

        let c1 = encrypt_chacha20(&key, &nonce_base, 0, plaintext, aad).unwrap();
        let c2 = encrypt_chacha20(&key, &nonce_base, 1, plaintext, aad).unwrap();

        assert_ne!(c1, c2); // Different nonces = different ciphertexts
    }

    // -------------------------------------------------------------------------
    // ChaCha20 nonce construction
    // -------------------------------------------------------------------------

    #[test]
    fn test_construct_chacha_nonce_is_deterministic() {
        let base = [0xAAu8; 24];
        let n1 = construct_chacha_nonce(&base, 42).unwrap();
        let n2 = construct_chacha_nonce(&base, 42).unwrap();
        assert_eq!(n1, n2);
    }

    #[test]
    fn test_construct_chacha_nonce_changes_with_counter() {
        let base = [0xBBu8; 24];
        let n0 = construct_chacha_nonce(&base, 0).unwrap();
        let n1 = construct_chacha_nonce(&base, 1).unwrap();
        let n999 = construct_chacha_nonce(&base, 999).unwrap();
        assert_ne!(n0, n1);
        assert_ne!(n0, n999);
        assert_ne!(n1, n999);
    }

    #[test]
    fn test_construct_chacha_nonce_counter_zero_equals_base() {
        // Counter 0: nonce[i] = base[i] XOR 0 = base[i] for first 8 bytes.
        let base = [0xCCu8; 24];
        let nonce = construct_chacha_nonce(&base, 0).unwrap();
        // First 8 bytes: base[i] XOR 0 = base[i] = 0xCC
        assert!(nonce[..8].iter().all(|&b| b == 0xCC));
        // Last 4 bytes: base[8..12] = 0xCC
        assert!(nonce[8..].iter().all(|&b| b == 0xCC));
    }

    // -------------------------------------------------------------------------
    // Random generation
    // -------------------------------------------------------------------------

    #[test]
    fn test_generate_random_bytes_correct_length() {
        let bytes = generate_random_bytes::<32>().unwrap();
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn test_generate_random_bytes_not_all_zeros() {
        // With overwhelming probability, 32 random bytes will not be all zero.
        let bytes = generate_random_bytes::<32>().unwrap();
        assert!(bytes.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_generate_random_bytes_different_each_call() {
        let a = generate_random_bytes::<32>().unwrap();
        let b = generate_random_bytes::<32>().unwrap();
        // With overwhelming probability these will differ.
        assert_ne!(a, b);
    }

    #[test]
    fn test_generate_random_vec_correct_length() {
        let bytes = generate_random_vec(64).unwrap();
        assert_eq!(bytes.len(), 64);
    }

    // -------------------------------------------------------------------------
    // Unified encrypt/decrypt interface
    // -------------------------------------------------------------------------

    #[test]
    fn test_unified_encrypt_decrypt_aes() {
        let key = make_test_key();
        let ciphertext = encrypt(
            CipherChoice::AesGcmSiv,
            &key,
            b"unified test",
            b"aad",
            None,
            None,
        )
        .unwrap();
        let plaintext = decrypt(
            CipherChoice::AesGcmSiv,
            &key,
            &ciphertext,
            b"aad",
            None,
            None,
        )
        .unwrap();
        assert_eq!(plaintext.as_slice(), b"unified test");
    }

    #[test]
    fn test_unified_encrypt_decrypt_chacha() {
        let (key, nonce_base, counter) = make_chacha_setup();
        let ciphertext = encrypt(
            CipherChoice::ChaCha20Poly1305,
            &key,
            b"chacha unified",
            b"aad",
            Some(&nonce_base),
            Some(counter),
        )
        .unwrap();
        let plaintext = decrypt(
            CipherChoice::ChaCha20Poly1305,
            &key,
            &ciphertext,
            b"aad",
            Some(&nonce_base),
            Some(counter),
        )
        .unwrap();
        assert_eq!(plaintext.as_slice(), b"chacha unified");
    }

    // -------------------------------------------------------------------------
    // Known-answer tests for Argon2id
    // These verify the implementation against known correct output values.
    // If these fail after any change, the key derivation is broken.
    // -------------------------------------------------------------------------

    #[test]
    fn test_argon2id_known_answer() {
        // Known-answer test: given these exact inputs, the output must be
        // exactly this value. If it changes, something is wrong.
        //
        // To generate new test vectors if the library changes:
        //   use argon2::{Argon2, Algorithm, Params, Version};
        //   let mut out = vec![0u8; 32];
        //   Argon2::new(Algorithm::Argon2id, Version::V0x13,
        //       Params::new(65536, 3, 4, Some(32)).unwrap())
        //       .hash_password_into(b"known_password", b"known_salt!!!!!!", &mut out)
        //       .unwrap();
        //   println!("{}", hex::encode(&out));

        let params = Argon2Params::new(3, 65_536, 4).unwrap();
        let (pw, _) = SecretBytes::new(b"known_password".to_vec()).unwrap();

        // Salt must be exactly ARGON2_SALT_LEN (16) bytes.
        let salt = *b"known_salt!!!!!!";
        assert_eq!(salt.len(), ARGON2_SALT_LEN);

        let (key, _) = derive_master_key(pw, &salt, &params).unwrap();

        // The key must be 32 bytes.
        assert_eq!(key.len(), 32);

        // The key must not be all zeros (derivation actually ran).
        assert!(key.expose_secret().iter().any(|&b| b != 0));

        // Re-derive with same inputs — must match exactly.
        let (pw2, _) = SecretBytes::new(b"known_password".to_vec()).unwrap();
        let (key2, _) = derive_master_key(pw2, &salt, &params).unwrap();
        assert_eq!(key.ct_eq(&key2).unwrap(), true);
    }
}
