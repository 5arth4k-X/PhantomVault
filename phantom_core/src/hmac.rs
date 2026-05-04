// =============================================================================
// PhantomVault — phantom_core/src/hmac.rs
// =============================================================================
//
// THE TRUSTED COMPUTING BASE — FILE 5 OF 6
//
// This file provides the HMAC-SHA256 operations used for the audit log chain.
// The vault header HMAC is handled directly in header.rs using the hmac crate.
// This module exposes clean functions for the audit chain and any other
// HMAC operations needed by the Python orchestration layer.
//
// WHAT THIS FILE PROVIDES:
//   compute_hmac()    — computes HMAC-SHA256 of data with a key
//   verify_hmac_ct()  — verifies HMAC in constant time
//   chain_hmac()      — chains a new entry: HMAC(key, data || prev_hmac)
//
// SECURITY PROPERTIES:
//   [✓] All verification is constant-time (subtle crate)
//   [✓] Key material held in SecretBytes
//   [✓] Chain links entries so deletion is detectable
//
// =============================================================================

use std::fmt;

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::memory::SecretBytes;

// =============================================================================
// ERRORS
// =============================================================================

#[derive(Debug, Clone, PartialEq)]
pub enum HmacError {
    /// Invalid key length for HMAC-SHA256.
    InvalidKeyLength { got: usize },
    /// HMAC verification failed — data was tampered with.
    VerificationFailed,
    /// Input data is empty.
    EmptyData,
}

impl fmt::Display for HmacError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HmacError::InvalidKeyLength { got } => {
                write!(f, "HMAC key must be 32 bytes, got {}", got)
            }
            HmacError::VerificationFailed => {
                write!(
                    f,
                    "HMAC verification failed — data may have been tampered with."
                )
            }
            HmacError::EmptyData => {
                write!(f, "Cannot compute HMAC of empty data.")
            }
        }
    }
}

impl std::error::Error for HmacError {}

// =============================================================================
// HMAC SIZE
// =============================================================================

/// Output length of HMAC-SHA256 in bytes.
pub const HMAC_OUTPUT_LEN: usize = 32;

// =============================================================================
// compute_hmac
// =============================================================================

/// Computes HMAC-SHA256 of `data` using `key`.
///
/// # Parameters
/// - `key`: The HMAC key. Should be 32 bytes (256-bit security).
///   Shorter keys are accepted by HMAC-SHA256 but provide
///   less security — use 32 bytes for audit chain keys.
/// - `data`: The data to authenticate. Must not be empty.
///
/// # Returns
/// 32-byte HMAC value.
pub fn compute_hmac(key: &SecretBytes, data: &[u8]) -> Result<[u8; HMAC_OUTPUT_LEN], HmacError> {
    if data.is_empty() {
        return Err(HmacError::EmptyData);
    }

    let mut mac = <Hmac<Sha256>>::new_from_slice(key.expose_secret())
        .map_err(|_| HmacError::InvalidKeyLength { got: key.len() })?;

    mac.update(data);

    let result = mac.finalize().into_bytes();
    let mut output = [0u8; HMAC_OUTPUT_LEN];
    output.copy_from_slice(&result);
    Ok(output)
}

// =============================================================================
// verify_hmac_ct
// =============================================================================

/// Verifies an HMAC-SHA256 value in constant time.
///
/// Computes the expected HMAC and compares it against the provided
/// value using constant-time comparison. Returns an error if they
/// do not match.
///
/// The error message is generic — does not reveal what was expected.
pub fn verify_hmac_ct(
    key: &SecretBytes,
    data: &[u8],
    expected_hmac: &[u8; HMAC_OUTPUT_LEN],
) -> Result<(), HmacError> {
    let computed = compute_hmac(key, data)?;
    let matches: bool = computed.ct_eq(expected_hmac).into();

    if matches {
        Ok(())
    } else {
        Err(HmacError::VerificationFailed)
    }
}

// =============================================================================
// chain_hmac
// =============================================================================

/// Computes the chained HMAC for an audit log entry.
///
/// Each audit log entry's HMAC includes the previous entry's HMAC,
/// forming a chain. Deleting or modifying any entry breaks the chain.
///
/// chain_hmac(key, entry_data, prev_hmac) = HMAC(key, entry_data || prev_hmac)
///
/// For the genesis entry (first entry), pass [0u8; 32] as prev_hmac.
///
/// # Parameters
/// - `key`: Audit chain key (derived from master key).
/// - `entry_data`: The serialised log entry bytes.
/// - `prev_hmac`: HMAC of the previous entry. All zeros for genesis.
///
/// # Returns
/// 32-byte chained HMAC for this entry.
pub fn chain_hmac(
    key: &SecretBytes,
    entry_data: &[u8],
    prev_hmac: &[u8; HMAC_OUTPUT_LEN],
) -> Result<[u8; HMAC_OUTPUT_LEN], HmacError> {
    if entry_data.is_empty() {
        return Err(HmacError::EmptyData);
    }

    let mut mac = <Hmac<Sha256>>::new_from_slice(key.expose_secret())
        .map_err(|_| HmacError::InvalidKeyLength { got: key.len() })?;

    // Feed entry data first, then previous HMAC.
    // Order matters — must be consistent during verification.
    mac.update(entry_data);
    mac.update(prev_hmac.as_slice());

    let result = mac.finalize().into_bytes();
    let mut output = [0u8; HMAC_OUTPUT_LEN];
    output.copy_from_slice(&result);
    Ok(output)
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::SecretBytes;

    fn make_key(byte: u8) -> SecretBytes {
        let (key, _) = SecretBytes::new(vec![byte; 32]).unwrap();
        key
    }

    // -------------------------------------------------------------------------
    // compute_hmac
    // -------------------------------------------------------------------------

    #[test]
    fn test_compute_hmac_produces_32_bytes() {
        let key = make_key(0x42);
        let result = compute_hmac(&key, b"test data").unwrap();
        assert_eq!(result.len(), HMAC_OUTPUT_LEN);
    }

    #[test]
    fn test_compute_hmac_is_deterministic() {
        let k1 = make_key(0x01);
        let k2 = make_key(0x01);
        let r1 = compute_hmac(&k1, b"same data").unwrap();
        let r2 = compute_hmac(&k2, b"same data").unwrap();
        assert_eq!(r1, r2);
    }

    #[test]
    fn test_compute_hmac_different_keys_different_output() {
        let k1 = make_key(0x01);
        let k2 = make_key(0x02);
        let r1 = compute_hmac(&k1, b"same data").unwrap();
        let r2 = compute_hmac(&k2, b"same data").unwrap();
        assert_ne!(r1, r2);
    }

    #[test]
    fn test_compute_hmac_different_data_different_output() {
        let key = make_key(0x42);
        let r1 = compute_hmac(&key, b"data one").unwrap();
        let r2 = compute_hmac(&key, b"data two").unwrap();
        assert_ne!(r1, r2);
    }

    #[test]
    fn test_compute_hmac_empty_data_fails() {
        let key = make_key(0x42);
        let result = compute_hmac(&key, b"");
        assert!(matches!(result, Err(HmacError::EmptyData)));
    }

    #[test]
    fn test_compute_hmac_single_byte_change_changes_output() {
        let key = make_key(0x42);
        let r1 = compute_hmac(&key, b"hello world").unwrap();
        let r2 = compute_hmac(&key, b"Hello world").unwrap();
        assert_ne!(r1, r2);
    }

    // -------------------------------------------------------------------------
    // verify_hmac_ct
    // -------------------------------------------------------------------------

    #[test]
    fn test_verify_hmac_ct_correct_succeeds() {
        let key = make_key(0x55);
        let data = b"verify this data";
        let hmac = compute_hmac(&key, data).unwrap();
        assert!(verify_hmac_ct(&key, data, &hmac).is_ok());
    }

    #[test]
    fn test_verify_hmac_ct_wrong_key_fails() {
        let key = make_key(0x55);
        let wrong_key = make_key(0x56);
        let data = b"verify this data";
        let hmac = compute_hmac(&key, data).unwrap();
        let result = verify_hmac_ct(&wrong_key, data, &hmac);
        assert!(matches!(result, Err(HmacError::VerificationFailed)));
    }

    #[test]
    fn test_verify_hmac_ct_tampered_data_fails() {
        let key = make_key(0x55);
        let data = b"original data";
        let hmac = compute_hmac(&key, data).unwrap();
        let result = verify_hmac_ct(&key, b"tampered data", &hmac);
        assert!(matches!(result, Err(HmacError::VerificationFailed)));
    }

    #[test]
    fn test_verify_hmac_ct_tampered_hmac_fails() {
        let key = make_key(0x55);
        let data = b"some data";
        let mut hmac = compute_hmac(&key, data).unwrap();
        hmac[0] ^= 0xFF; // Flip bits in first byte
        let result = verify_hmac_ct(&key, data, &hmac);
        assert!(matches!(result, Err(HmacError::VerificationFailed)));
    }

    // -------------------------------------------------------------------------
    // chain_hmac
    // -------------------------------------------------------------------------

    #[test]
    fn test_chain_hmac_genesis_entry() {
        let key = make_key(0xAA);
        let genesis_prev = [0u8; HMAC_OUTPUT_LEN];
        let result = chain_hmac(&key, b"first log entry", &genesis_prev);
        assert!(result.is_ok());
        let hmac = result.unwrap();
        assert_ne!(hmac, [0u8; HMAC_OUTPUT_LEN]);
    }

    #[test]
    fn test_chain_hmac_links_entries() {
        let key = make_key(0xBB);
        let genesis_prev = [0u8; HMAC_OUTPUT_LEN];

        let entry1_hmac = chain_hmac(&key, b"entry one", &genesis_prev).unwrap();
        let entry2_hmac = chain_hmac(&key, b"entry two", &entry1_hmac).unwrap();
        let entry3_hmac = chain_hmac(&key, b"entry three", &entry2_hmac).unwrap();

        // All three must be different.
        assert_ne!(entry1_hmac, entry2_hmac);
        assert_ne!(entry2_hmac, entry3_hmac);
        assert_ne!(entry1_hmac, entry3_hmac);
    }

    #[test]
    fn test_chain_hmac_deletion_detectable() {
        // If entry 2 is deleted, entry 3 cannot be verified because
        // its chain link (prev_hmac = entry2_hmac) is missing.
        // This test demonstrates the chain property.
        let key = make_key(0xCC);
        let genesis = [0u8; HMAC_OUTPUT_LEN];

        let e1 = chain_hmac(&key, b"entry one", &genesis).unwrap();
        let e2 = chain_hmac(&key, b"entry two", &e1).unwrap();
        let e3 = chain_hmac(&key, b"entry three", &e2).unwrap();

        // Verify e3 using e2 as prev — should succeed.
        let e3_recomputed = chain_hmac(&key, b"entry three", &e2).unwrap();
        assert_eq!(e3, e3_recomputed);

        // If attacker deletes e2 and tries to recompute e3 with e1 as prev:
        let e3_fake = chain_hmac(&key, b"entry three", &e1).unwrap();
        // The result is different — tampering is detectable.
        assert_ne!(e3, e3_fake);
    }

    #[test]
    fn test_chain_hmac_empty_data_fails() {
        let key = make_key(0xDD);
        let prev = [0u8; HMAC_OUTPUT_LEN];
        let result = chain_hmac(&key, b"", &prev);
        assert!(matches!(result, Err(HmacError::EmptyData)));
    }

    #[test]
    fn test_chain_hmac_is_deterministic() {
        let k1 = make_key(0xEE);
        let k2 = make_key(0xEE);
        let prev = [0x11u8; HMAC_OUTPUT_LEN];

        let r1 = chain_hmac(&k1, b"same entry", &prev).unwrap();
        let r2 = chain_hmac(&k2, b"same entry", &prev).unwrap();
        assert_eq!(r1, r2);
    }

    #[test]
    fn test_error_display_not_empty() {
        let errors = vec![
            HmacError::InvalidKeyLength { got: 16 },
            HmacError::VerificationFailed,
            HmacError::EmptyData,
        ];
        for e in errors {
            assert!(!format!("{}", e).is_empty());
        }
    }
}
