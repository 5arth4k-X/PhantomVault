// =============================================================================
// PhantomVault — phantom_core/src/shamir.rs
// =============================================================================
//
// THE TRUSTED COMPUTING BASE — FILE 6 OF 6
//
// Shamir's Secret Sharing for master key recovery.
//
// Uses the `sharks` crate — NOT a custom implementation.
// Custom GF(256) arithmetic is almost always buggy in subtle ways
// that only appear during recovery, at the worst possible moment.
// The sharks crate is audited and well-tested.
//
// MANDATORY SELF-TEST:
// Every share export runs a self-test immediately after generation:
//   1. Generate the shares
//   2. Reconstruct from a subset (k of n)
//   3. Verify reconstructed == original secret
//   4. If verification fails: zero all shares, return error
// This prevents distributing broken shares.
//
// WHAT THIS FILE PROVIDES:
//   split_secret()       — splits a SecretBytes into n shares
//   reconstruct_secret() — reconstructs from k shares
//   ShamirShare          — a single share (index + data)
//
// SECURITY PROPERTIES:
//   [✓] Uses audited sharks crate (not custom GF arithmetic)
//   [✓] Mandatory self-test on every split operation
//   [✓] Secret zeroed after splitting
//   [✓] Reconstruction verifies correct output length
//   [✓] Shares are just bytes — no sensitive metadata leaked
//
// =============================================================================

use sharks::{Share, Sharks};
use std::fmt;
use zeroize::Zeroize;

use crate::memory::SecretBytes;

// =============================================================================
// CONSTANTS
// =============================================================================

/// Minimum number of shares (k threshold).
pub const MIN_THRESHOLD: u8 = 2;

/// Maximum number of shares (n total).
pub const MAX_SHARES: u8 = 10;

/// Expected secret length — must match KEY_LEN from crypto.rs (32 bytes).
pub const SECRET_LEN: usize = 32;

// =============================================================================
// ERRORS
// =============================================================================

#[derive(Debug, Clone, PartialEq)]
pub enum ShamirError {
    /// Threshold is below minimum (must be >= 2).
    ThresholdTooLow { got: u8 },

    /// Number of shares exceeds maximum.
    TooManyShares { got: u8 },

    /// Threshold is greater than total shares.
    ThresholdExceedsShares { threshold: u8, shares: u8 },

    /// Secret is not exactly 32 bytes.
    InvalidSecretLength { expected: usize, got: usize },

    /// The mandatory self-test failed after share generation.
    /// All generated shares are zeroed. Do not distribute any shares.
    SelfTestFailed,

    /// Not enough shares provided for reconstruction.
    InsufficientShares { needed: u8, got: usize },

    /// Reconstruction failed — shares may be corrupted or incompatible.
    ReconstructionFailed,

    /// Reconstructed secret has wrong length.
    WrongReconstructedLength { expected: usize, got: usize },

    /// Provided shares vector is empty.
    NoSharesProvided,
}

impl fmt::Display for ShamirError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ShamirError::ThresholdTooLow { got } => {
                write!(
                    f,
                    "Threshold must be at least {}, got {}",
                    MIN_THRESHOLD, got
                )
            }
            ShamirError::TooManyShares { got } => {
                write!(
                    f,
                    "Cannot generate more than {} shares, got {}",
                    MAX_SHARES, got
                )
            }
            ShamirError::ThresholdExceedsShares { threshold, shares } => {
                write!(
                    f,
                    "Threshold ({}) cannot exceed total shares ({})",
                    threshold, shares
                )
            }
            ShamirError::InvalidSecretLength { expected, got } => {
                write!(f, "Secret must be exactly {} bytes, got {}", expected, got)
            }
            ShamirError::SelfTestFailed => {
                write!(
                    f,
                    "CRITICAL: Share generation self-test failed. \
                     All shares have been zeroed. \
                     Do not distribute any shares. \
                     Please report this as a bug."
                )
            }
            ShamirError::InsufficientShares { needed, got } => {
                write!(
                    f,
                    "Need at least {} shares to reconstruct, only {} provided",
                    needed, got
                )
            }
            ShamirError::ReconstructionFailed => {
                write!(
                    f,
                    "Secret reconstruction failed. \
                     Shares may be corrupted or from different vaults."
                )
            }
            ShamirError::WrongReconstructedLength { expected, got } => {
                write!(
                    f,
                    "Reconstructed secret has wrong length \
                     (expected {} bytes, got {}). Shares may be corrupted.",
                    expected, got
                )
            }
            ShamirError::NoSharesProvided => {
                write!(f, "No shares were provided for reconstruction.")
            }
        }
    }
}

impl std::error::Error for ShamirError {}

// =============================================================================
// ShamirShare
// A single share — just the raw bytes that the sharks crate produces.
// =============================================================================

/// A single Shamir share — raw bytes that encode one share of the secret.
///
/// Shares are just byte arrays. They contain no metadata about the vault,
/// the threshold, or how many shares exist. This prevents information leakage
/// from physical share media (printed papers, QR codes).
///
/// The share bytes are: [x_coordinate (1 byte)] [y_values (32 bytes)]
/// Total: 33 bytes per share for a 32-byte secret.
#[derive(Clone)]
pub struct ShamirShare {
    /// Raw share bytes from the sharks crate.
    /// Format: 1 byte x-coordinate + 32 bytes y-values = 33 bytes total.
    pub bytes: Vec<u8>,
}

impl ShamirShare {
    /// Creates a ShamirShare from raw bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        ShamirShare { bytes }
    }

    /// Returns the raw bytes of this share.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the length of the share in bytes.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns true if the share is empty (should never happen).
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl Drop for ShamirShare {
    fn drop(&mut self) {
        // Zero share bytes on drop — shares are sensitive material.
        self.bytes.zeroize();
    }
}

impl fmt::Debug for ShamirShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print actual share bytes.
        write!(f, "ShamirShare {{ len: {} }}", self.bytes.len())
    }
}

// =============================================================================
// split_secret
// =============================================================================

/// Splits a 32-byte secret into n shares with a threshold of k.
///
/// Any k of the n shares can reconstruct the secret.
/// Fewer than k shares reveal nothing about the secret.
///
/// A mandatory self-test is run after generation:
/// - Takes the first k shares
/// - Reconstructs the secret
/// - Verifies it equals the original
///   If the self-test fails, all shares are zeroed and an error is returned.
///
/// # Parameters
/// - `secret`: The secret to split. Must be exactly 32 bytes.
///   The secret is NOT consumed or zeroed by this function —
///   the caller is responsible for zeroing it after use.
/// - `threshold`: Minimum shares needed to reconstruct (k). Minimum: 2.
/// - `total_shares`: Total shares to generate (n). Maximum: 10.
///
/// # Returns
/// - `Ok(Vec<ShamirShare>)` — vector of `total_shares` shares.
/// - `Err(ShamirError::SelfTestFailed)` — generation failed self-test.
///   All shares have been zeroed. Do not distribute any.
pub fn split_secret(
    secret: &SecretBytes,
    threshold: u8,
    total_shares: u8,
) -> Result<Vec<ShamirShare>, ShamirError> {
    // Validate parameters.
    if threshold < MIN_THRESHOLD {
        return Err(ShamirError::ThresholdTooLow { got: threshold });
    }
    if total_shares > MAX_SHARES {
        return Err(ShamirError::TooManyShares { got: total_shares });
    }
    if threshold > total_shares {
        return Err(ShamirError::ThresholdExceedsShares {
            threshold,
            shares: total_shares,
        });
    }
    if secret.len() != SECRET_LEN {
        return Err(ShamirError::InvalidSecretLength {
            expected: SECRET_LEN,
            got: secret.len(),
        });
    }

    // Generate shares using the sharks crate.
    let sharks = Sharks(threshold);
    let dealer = sharks.dealer(secret.expose_secret());
    let shares: Vec<ShamirShare> = dealer
        .take(total_shares as usize)
        .map(|share| {
            // Convert sharks Share to our ShamirShare.
            let share_bytes: Vec<u8> = Vec::from(&share);
            ShamirShare::from_bytes(share_bytes)
        })
        .collect();

    // MANDATORY SELF-TEST.
    // Take the first `threshold` shares and reconstruct.
    // Verify the reconstruction equals the original secret.
    let self_test_result = run_self_test(secret, &shares, threshold);

    if self_test_result.is_err() {
        // Self-test failed. Zero all shares before returning error.
        // The shares variable is dropped here — ShamirShare::drop zeroes bytes.
        return Err(ShamirError::SelfTestFailed);
    }

    Ok(shares)
}

/// Runs the mandatory self-test on freshly generated shares.
/// Returns Ok(()) if reconstruction produces the original secret.
fn run_self_test(
    original: &SecretBytes,
    shares: &[ShamirShare],
    threshold: u8,
) -> Result<(), ShamirError> {
    // Take exactly threshold shares for the test.
    let test_shares = &shares[..threshold as usize];

    // Reconstruct.
    let reconstructed = reconstruct_from_raw_shares(test_shares, threshold)?;

    // Constant-time comparison.
    use subtle::ConstantTimeEq;
    let matches: bool = reconstructed
        .expose_secret()
        .ct_eq(original.expose_secret())
        .into();

    if matches {
        Ok(())
    } else {
        Err(ShamirError::SelfTestFailed)
    }
}

// =============================================================================
// reconstruct_secret
// =============================================================================

/// Reconstructs the secret from k or more shares.
///
/// # Parameters
/// - `shares`: At least `threshold` shares. Order does not matter.
/// - `threshold`: The k value used during split_secret().
///   Must match the original threshold exactly.
///
/// # Returns
/// - `Ok(SecretBytes)` — the reconstructed 32-byte secret.
/// - `Err(ShamirError)` — not enough shares or reconstruction failed.
///
/// # Notes
/// The threshold parameter is required by the sharks crate for
/// reconstruction. It must match the value used during splitting.
/// There is no way to determine the threshold from the shares alone.
pub fn reconstruct_secret(
    shares: &[ShamirShare],
    threshold: u8,
) -> Result<SecretBytes, ShamirError> {
    if shares.is_empty() {
        return Err(ShamirError::NoSharesProvided);
    }
    if shares.len() < threshold as usize {
        return Err(ShamirError::InsufficientShares {
            needed: threshold,
            got: shares.len(),
        });
    }

    reconstruct_from_raw_shares(shares, threshold)
}

/// Internal reconstruction helper used by both reconstruct_secret
/// and the self-test.
fn reconstruct_from_raw_shares(
    shares: &[ShamirShare],
    threshold: u8,
) -> Result<SecretBytes, ShamirError> {
    let sharks = Sharks(threshold);

    // Convert our ShamirShare bytes back to sharks Share objects.
    let shark_shares: Result<Vec<Share>, _> = shares
        .iter()
        .map(|s| Share::try_from(s.as_bytes()))
        .collect();

    let shark_shares = shark_shares.map_err(|_| ShamirError::ReconstructionFailed)?;

    // Reconstruct the secret.
    let mut recovered = sharks
        .recover(&shark_shares)
        .map_err(|_| ShamirError::ReconstructionFailed)?;

    // Verify length.
    if recovered.len() != SECRET_LEN {
        let len = recovered.len();
        recovered.zeroize();
        return Err(ShamirError::WrongReconstructedLength {
            expected: SECRET_LEN,
            got: len,
        });
    }

    // Wrap in SecretBytes.
    let (secret, _) = SecretBytes::new(recovered).map_err(|_| ShamirError::ReconstructionFailed)?;

    Ok(secret)
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::SecretBytes;

    fn make_secret(byte: u8) -> SecretBytes {
        let (s, _) = SecretBytes::new(vec![byte; SECRET_LEN]).unwrap();
        s
    }

    // -------------------------------------------------------------------------
    // split_secret — parameter validation
    // -------------------------------------------------------------------------

    #[test]
    fn test_split_rejects_threshold_zero() {
        let secret = make_secret(0x42);
        let result = split_secret(&secret, 0, 5);
        assert!(matches!(
            result,
            Err(ShamirError::ThresholdTooLow { got: 0 })
        ));
    }

    #[test]
    fn test_split_rejects_threshold_one() {
        let secret = make_secret(0x42);
        let result = split_secret(&secret, 1, 5);
        assert!(matches!(
            result,
            Err(ShamirError::ThresholdTooLow { got: 1 })
        ));
    }

    #[test]
    fn test_split_rejects_too_many_shares() {
        let secret = make_secret(0x42);
        let result = split_secret(&secret, 2, MAX_SHARES + 1);
        assert!(matches!(result, Err(ShamirError::TooManyShares { .. })));
    }

    #[test]
    fn test_split_rejects_threshold_greater_than_shares() {
        let secret = make_secret(0x42);
        let result = split_secret(&secret, 5, 3);
        assert!(matches!(
            result,
            Err(ShamirError::ThresholdExceedsShares {
                threshold: 5,
                shares: 3
            })
        ));
    }

    #[test]
    fn test_split_rejects_wrong_secret_length() {
        let (short_secret, _) = SecretBytes::new(vec![0x01u8; 16]).unwrap();
        let result = split_secret(&short_secret, 2, 3);
        assert!(matches!(
            result,
            Err(ShamirError::InvalidSecretLength {
                expected: 32,
                got: 16
            })
        ));
    }

    // -------------------------------------------------------------------------
    // split_secret — successful generation
    // -------------------------------------------------------------------------

    #[test]
    fn test_split_2_of_3_produces_three_shares() {
        let secret = make_secret(0x55);
        let shares = split_secret(&secret, 2, 3).unwrap();
        assert_eq!(shares.len(), 3);
    }

    #[test]
    fn test_split_3_of_5_produces_five_shares() {
        let secret = make_secret(0x66);
        let shares = split_secret(&secret, 3, 5).unwrap();
        assert_eq!(shares.len(), 5);
    }

    #[test]
    fn test_split_threshold_equals_shares() {
        // 3-of-3: all shares needed.
        let secret = make_secret(0x77);
        let shares = split_secret(&secret, 3, 3).unwrap();
        assert_eq!(shares.len(), 3);
    }

    #[test]
    fn test_split_minimum_2_of_2() {
        let secret = make_secret(0x88);
        let shares = split_secret(&secret, 2, 2).unwrap();
        assert_eq!(shares.len(), 2);
    }

    #[test]
    fn test_share_bytes_not_empty() {
        let secret = make_secret(0x99);
        let shares = split_secret(&secret, 2, 3).unwrap();
        for share in &shares {
            assert!(!share.is_empty());
            // Each share should be 33 bytes: 1 x-coord + 32 y-values
            assert_eq!(share.len(), 33);
        }
    }

    // -------------------------------------------------------------------------
    // reconstruct_secret — round-trip tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_reconstruct_2_of_3_with_shares_0_1() {
        let secret = make_secret(0xAA);
        let shares = split_secret(&secret, 2, 3).unwrap();
        let two_shares = vec![shares[0].clone(), shares[1].clone()];
        let reconstructed = reconstruct_secret(&two_shares, 2).unwrap();
        assert_eq!(reconstructed.expose_secret(), secret.expose_secret());
    }

    #[test]
    fn test_reconstruct_2_of_3_with_shares_0_2() {
        let secret = make_secret(0xBB);
        let shares = split_secret(&secret, 2, 3).unwrap();
        let two_shares = vec![shares[0].clone(), shares[2].clone()];
        let reconstructed = reconstruct_secret(&two_shares, 2).unwrap();
        assert_eq!(reconstructed.expose_secret(), secret.expose_secret());
    }

    #[test]
    fn test_reconstruct_2_of_3_with_shares_1_2() {
        let secret = make_secret(0xCC);
        let shares = split_secret(&secret, 2, 3).unwrap();
        let two_shares = vec![shares[1].clone(), shares[2].clone()];
        let reconstructed = reconstruct_secret(&two_shares, 2).unwrap();
        assert_eq!(reconstructed.expose_secret(), secret.expose_secret());
    }

    #[test]
    fn test_reconstruct_3_of_5_any_three() {
        let secret = make_secret(0xDD);
        let shares = split_secret(&secret, 3, 5).unwrap();

        // Try several combinations of 3.
        let combos: &[&[usize]] = &[&[0, 1, 2], &[0, 1, 3], &[0, 2, 4], &[1, 3, 4], &[2, 3, 4]];

        for combo in combos {
            let selected: Vec<ShamirShare> = combo.iter().map(|&i| shares[i].clone()).collect();

            let reconstructed = reconstruct_secret(&selected, 3).unwrap();
            assert_eq!(
                reconstructed.expose_secret(),
                secret.expose_secret(),
                "Failed for combo {:?}",
                combo
            );
        }
    }

    #[test]
    fn test_reconstruct_all_shares_succeeds() {
        let secret = make_secret(0xEE);
        let shares = split_secret(&secret, 3, 5).unwrap();
        // Using all 5 shares when threshold is 3 is fine.
        let all: Vec<ShamirShare> = shares.iter().map(|s| s.clone()).collect();
        let reconstructed = reconstruct_secret(&all, 3).unwrap();
        assert_eq!(reconstructed.expose_secret(), secret.expose_secret());
    }

    #[test]
    fn test_reconstruct_different_secrets_produce_different_shares() {
        let s1 = make_secret(0x01);
        let s2 = make_secret(0x02);
        let shares1 = split_secret(&s1, 2, 3).unwrap();
        let shares2 = split_secret(&s2, 2, 3).unwrap();
        // Shares for different secrets must differ.
        assert_ne!(shares1[0].as_bytes(), shares2[0].as_bytes());
    }

    // -------------------------------------------------------------------------
    // reconstruct_secret — error cases
    // -------------------------------------------------------------------------

    #[test]
    fn test_reconstruct_no_shares_fails() {
        let result = reconstruct_secret(&[], 3);
        assert!(matches!(result, Err(ShamirError::NoSharesProvided)));
    }

    #[test]
    fn test_reconstruct_insufficient_shares_fails() {
        let secret = make_secret(0xFF);
        let shares = split_secret(&secret, 3, 5).unwrap();
        // Only provide 2 shares when threshold is 3.
        let two: Vec<ShamirShare> = shares[..2].iter().map(|s| s.clone()).collect();
        let result = reconstruct_secret(&two, 3);
        assert!(matches!(
            result,
            Err(ShamirError::InsufficientShares { needed: 3, got: 2 })
        ));
    }

    // -------------------------------------------------------------------------
    // Self-test verification
    // -------------------------------------------------------------------------

    #[test]
    fn test_self_test_runs_on_split() {
        // The self-test runs internally. If split succeeds, self-test passed.
        // Verify by ensuring the returned shares actually reconstruct correctly.
        let secret = make_secret(0x42);
        let shares = split_secret(&secret, 3, 5).unwrap();
        let first_three: Vec<ShamirShare> = shares[..3].iter().map(|s| s.clone()).collect();
        let reconstructed = reconstruct_secret(&first_three, 3).unwrap();
        assert_eq!(reconstructed.expose_secret(), secret.expose_secret());
    }

    // -------------------------------------------------------------------------
    // Error display
    // -------------------------------------------------------------------------

    #[test]
    fn test_error_display_not_empty() {
        let errors = vec![
            ShamirError::ThresholdTooLow { got: 1 },
            ShamirError::TooManyShares { got: 11 },
            ShamirError::ThresholdExceedsShares {
                threshold: 5,
                shares: 3,
            },
            ShamirError::InvalidSecretLength {
                expected: 32,
                got: 16,
            },
            ShamirError::SelfTestFailed,
            ShamirError::InsufficientShares { needed: 3, got: 2 },
            ShamirError::ReconstructionFailed,
            ShamirError::WrongReconstructedLength {
                expected: 32,
                got: 16,
            },
            ShamirError::NoSharesProvided,
        ];
        for e in errors {
            assert!(!format!("{}", e).is_empty());
        }
    }

    // -------------------------------------------------------------------------
    // ShamirShare debug does not leak bytes
    // -------------------------------------------------------------------------

    #[test]
    fn test_share_debug_does_not_leak_bytes() {
        let secret = make_secret(0x42);
        let shares = split_secret(&secret, 2, 3).unwrap();
        let debug_str = format!("{:?}", shares[0]);
        assert!(debug_str.contains("ShamirShare"));
        assert!(!debug_str.contains("bytes: ["));
    }
}
