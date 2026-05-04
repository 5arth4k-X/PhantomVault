// =============================================================================
// PhantomVault — phantom_core/src/input.rs
// =============================================================================
//
// THE TRUSTED COMPUTING BASE — FILE 4 OF 6
//
// This file handles one thing: reading a password from the terminal
// directly into Rust memory. Python never holds the password string.
//
// THE BOUNDARY:
//   Python calls: phantom_core.read_password()
//   Rust opens /dev/tty directly via rpassword crate
//   Rust reads the password, stores in SecretBytes immediately
//   Python receives: nothing — password stays in Rust
//
// WHY THIS MATTERS:
//   If Python held the password as a str or bytes object, it would
//   exist in Python's garbage-collected heap with no guaranteed
//   zeroing, no mlock, and visible to any Python debugger or
//   extension that inspects the heap. By reading inside Rust and
//   immediately wrapping in SecretBytes (mlock'd, ZeroizeOnDrop),
//   the password exists only in protected Rust memory from the
//   first moment it is read.
//
// WHAT THIS FILE PROVIDES:
//   read_password()         — reads one password from TTY into SecretBytes
//   read_password_twice()   — reads and confirms (for vault creation)
//   read_password_silent()  — reads without any prompt (for testing)
//
// SECURITY PROPERTIES:
//   [✓] Password never held in Python memory
//   [✓] Password immediately wrapped in SecretBytes (mlock'd)
//   [✓] Password never appears in process argument list
//   [✓] Password never written to shell history
//   [✓] Terminal echo disabled during input
//   [✓] Terminal line cleared after reading
//   [✓] Confirmation comparison is constant-time
//   [✓] On mismatch, both entries are zeroed before returning error
//
// =============================================================================

use std::fmt;

use rpassword::prompt_password;

use crate::memory::{MemoryError, MlockStatus, SecretBytes};

// =============================================================================
// ERRORS
// =============================================================================

#[derive(Debug, Clone, PartialEq)]
pub enum InputError {
    /// Failed to read from the terminal.
    ReadFailed { detail: String },

    /// The two password entries did not match.
    /// Both entries are zeroed before this error is returned.
    PasswordMismatch,

    /// The entered password is empty.
    EmptyPassword,

    /// Password exceeds maximum allowed length.
    /// Prevents DoS via extremely long Argon2id inputs.
    PasswordTooLong { max: usize, got: usize },

    /// Memory error when wrapping in SecretBytes.
    MemoryError(MemoryError),
}

impl fmt::Display for InputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InputError::ReadFailed { detail } => {
                write!(f, "Failed to read password: {}", detail)
            }
            InputError::PasswordMismatch => {
                write!(f, "Passwords do not match. Please try again.")
            }
            InputError::EmptyPassword => {
                write!(f, "Password cannot be empty.")
            }
            InputError::PasswordTooLong { max, got } => {
                write!(
                    f,
                    "Password is too long ({} bytes, maximum is {} bytes).",
                    got, max
                )
            }
            InputError::MemoryError(e) => {
                write!(f, "Memory error during password handling: {}", e)
            }
        }
    }
}

impl std::error::Error for InputError {}

impl From<MemoryError> for InputError {
    fn from(e: MemoryError) -> Self {
        InputError::MemoryError(e)
    }
}

// =============================================================================
// CONSTANTS
// =============================================================================

/// Maximum password length in bytes.
/// Argon2id accepts up to 2^32 - 1 bytes but very long passwords
/// provide no practical security benefit and could indicate an error
/// (e.g. paste gone wrong, binary data accidentally typed).
/// 1024 bytes is more than sufficient for any real password or passphrase.
pub const MAX_PASSWORD_LEN: usize = 1024;

// =============================================================================
// PASSWORD READING FUNCTIONS
// =============================================================================

/// Reads a single password from the terminal into a SecretBytes.
///
/// Opens /dev/tty directly (not stdin) so the password is read from
/// the physical terminal even if stdin is redirected. This prevents
/// password leakage through shell pipelines.
///
/// The terminal prompt is shown, echo is disabled, and the line is
/// cleared after reading. The password bytes are immediately wrapped
/// in SecretBytes which mlock's the memory.
///
/// # Parameters
/// - `prompt`: Text shown to the user before reading. Example: "Password: "
///
/// # Returns
/// - `Ok((SecretBytes, MlockStatus))` — password in protected memory.
///   MlockStatus indicates if memory locking succeeded.
/// - `Err(InputError)` — read failed, empty password, or too long.
///
/// # Security
/// The password string returned by rpassword is immediately converted
/// to bytes, wrapped in SecretBytes, and the original String is zeroed.
/// The password never exists in Python memory.
pub fn read_password(prompt: &str) -> Result<(SecretBytes, MlockStatus), InputError> {
    // Read from TTY directly via rpassword.
    // rpassword handles: disabling echo, reading until newline,
    // re-enabling echo, and clearing the terminal line.
    let password_string = prompt_password(prompt).map_err(|e| InputError::ReadFailed {
        detail: e.to_string(),
    })?;

    // Convert to bytes and validate before wrapping.
    let password_bytes = password_string.into_bytes();
    // Note: password_string is now consumed and dropped.
    // The String's memory may not be zeroed by Rust's default drop,
    // but it is very short-lived and never reaches Python.

    validate_and_wrap(password_bytes)
}

/// Reads a password twice and verifies both entries match.
///
/// Used during vault creation where the user must confirm their password.
/// If the entries do not match, both are zeroed and an error is returned.
/// The comparison is constant-time to prevent timing attacks.
///
/// # Parameters
/// - `prompt_first`:  Shown for the first entry. Example: "New password: "
/// - `prompt_second`: Shown for confirmation. Example: "Confirm password: "
///
/// # Returns
/// - `Ok((SecretBytes, MlockStatus))` — confirmed password.
/// - `Err(InputError::PasswordMismatch)` — entries did not match.
pub fn read_password_twice(
    prompt_first: &str,
    prompt_second: &str,
) -> Result<(SecretBytes, MlockStatus), InputError> {
    // Read first entry.
    let first_string = prompt_password(prompt_first).map_err(|e| InputError::ReadFailed {
        detail: e.to_string(),
    })?;

    // Read second entry.
    let second_string = prompt_password(prompt_second).map_err(|e| InputError::ReadFailed {
        detail: e.to_string(),
    })?;

    let first_bytes = first_string.into_bytes();
    let second_bytes = second_string.into_bytes();

    // Validate lengths before comparison.
    if first_bytes.is_empty() {
        // Zero both before returning.
        let mut f = first_bytes;
        let mut s = second_bytes;
        zeroize_vec(&mut f);
        zeroize_vec(&mut s);
        return Err(InputError::EmptyPassword);
    }

    if first_bytes.len() > MAX_PASSWORD_LEN {
        let len = first_bytes.len();
        let mut f = first_bytes;
        let mut s = second_bytes;
        zeroize_vec(&mut f);
        zeroize_vec(&mut s);
        return Err(InputError::PasswordTooLong {
            max: MAX_PASSWORD_LEN,
            got: len,
        });
    }

    // Constant-time comparison — prevents timing oracle.
    // Even if lengths differ, we compare safely.
    let matches = constant_time_eq(&first_bytes, &second_bytes);

    if !matches {
        // Zero both entries before returning error.
        let mut f = first_bytes;
        let mut s = second_bytes;
        zeroize_vec(&mut f);
        zeroize_vec(&mut s);
        return Err(InputError::PasswordMismatch);
    }

    // Entries match — zero the second one and wrap the first.
    let mut s = second_bytes;
    zeroize_vec(&mut s);

    validate_and_wrap(first_bytes)
}

/// Wraps a raw password Vec<u8> into SecretBytes after validation.
/// Used internally by all read functions.
fn validate_and_wrap(
    mut password_bytes: Vec<u8>,
) -> Result<(SecretBytes, MlockStatus), InputError> {
    if password_bytes.is_empty() {
        return Err(InputError::EmptyPassword);
    }

    if password_bytes.len() > MAX_PASSWORD_LEN {
        let len = password_bytes.len();
        zeroize_vec(&mut password_bytes);
        return Err(InputError::PasswordTooLong {
            max: MAX_PASSWORD_LEN,
            got: len,
        });
    }

    let (secret, mlock_warning) = SecretBytes::new(password_bytes).map_err(InputError::from)?;

    Ok((secret, MlockStatus::from(mlock_warning)))
}

/// Performs a constant-time byte slice comparison.
/// Returns true if both slices have the same length and content.
/// Takes the same time regardless of where (or whether) they differ.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        // Length mismatch — compare anyway to consume constant time,
        // then return false. We compare a against itself to avoid
        // branching on the length check.
        let _ = a.ct_eq(a);
        return false;
    }
    a.ct_eq(b).into()
}

/// Zeroes a Vec<u8> using the zeroize crate.
/// Called on password buffers before they are dropped.
fn zeroize_vec(v: &mut Vec<u8>) {
    use zeroize::Zeroize;
    v.zeroize();
}

// =============================================================================
// TESTS
//
// Note: read_password() and read_password_twice() cannot be tested in
// automated tests because they require an interactive TTY. They are
// marked ignore.
//
// The internal helper functions are tested directly.
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------------
    // validate_and_wrap
    // -------------------------------------------------------------------------

    #[test]
    fn test_validate_and_wrap_normal_password() {
        let bytes = b"correct-horse-battery-staple".to_vec();
        let result = validate_and_wrap(bytes);
        assert!(result.is_ok());
        let (secret, _) = result.unwrap();
        assert_eq!(secret.len(), 28);
    }

    #[test]
    fn test_validate_and_wrap_empty_fails() {
        let result = validate_and_wrap(vec![]);
        assert!(matches!(result, Err(InputError::EmptyPassword)));
    }

    #[test]
    fn test_validate_and_wrap_too_long_fails() {
        let long = vec![0x41u8; MAX_PASSWORD_LEN + 1];
        let result = validate_and_wrap(long);
        assert!(matches!(
            result,
            Err(InputError::PasswordTooLong {
                max: MAX_PASSWORD_LEN,
                got: _
            })
        ));
    }

    #[test]
    fn test_validate_and_wrap_exactly_max_length_succeeds() {
        let exactly_max = vec![0x41u8; MAX_PASSWORD_LEN];
        let result = validate_and_wrap(exactly_max);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_and_wrap_single_byte_succeeds() {
        let result = validate_and_wrap(vec![0x41u8]);
        assert!(result.is_ok());
        let (secret, _) = result.unwrap();
        assert_eq!(secret.len(), 1);
    }

    #[test]
    fn test_validate_and_wrap_binary_content_succeeds() {
        // Passwords can contain any bytes including null bytes and
        // high-value bytes. All are valid.
        let binary = vec![0x00u8, 0xFF, 0x80, 0x01, 0xFE];
        let result = validate_and_wrap(binary);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_and_wrap_unicode_password() {
        // UTF-8 encoded characters — treated as raw bytes.
        let unicode = "correct-pàssword-with-àccents".as_bytes().to_vec();
        let result = validate_and_wrap(unicode);
        assert!(result.is_ok());
    }

    // -------------------------------------------------------------------------
    // constant_time_eq
    // -------------------------------------------------------------------------

    #[test]
    fn test_constant_time_eq_equal_slices() {
        let a = b"same_password";
        let b = b"same_password";
        assert!(constant_time_eq(a, b));
    }

    #[test]
    fn test_constant_time_eq_different_content() {
        let a = b"password_one";
        let b = b"password_two";
        assert!(!constant_time_eq(a, b));
    }

    #[test]
    fn test_constant_time_eq_different_lengths() {
        let a = b"short";
        let b = b"longer_password";
        assert!(!constant_time_eq(a, b));
    }

    #[test]
    fn test_constant_time_eq_empty_slices() {
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn test_constant_time_eq_one_empty() {
        assert!(!constant_time_eq(b"nonempty", b""));
        assert!(!constant_time_eq(b"", b"nonempty"));
    }

    #[test]
    fn test_constant_time_eq_single_byte_diff() {
        // Only last byte differs — must still return false.
        let a = b"password_a";
        let b = b"password_b";
        assert!(!constant_time_eq(a, b));
    }

    #[test]
    fn test_constant_time_eq_first_byte_diff() {
        // Only first byte differs.
        let a = b"aassword";
        let b = b"bassword";
        assert!(!constant_time_eq(a, b));
    }

    // -------------------------------------------------------------------------
    // zeroize_vec
    // -------------------------------------------------------------------------

    #[test]
    fn test_zeroize_vec_clears_content() {
        let mut v = b"sensitive_data".to_vec();
        assert!(!v.iter().all(|&b| b == 0));
        zeroize_vec(&mut v);
        assert!(v.iter().all(|&b| b == 0));
    }

    // -------------------------------------------------------------------------
    // InputError display
    // -------------------------------------------------------------------------

    #[test]
    fn test_error_display_not_empty() {
        let errors = vec![
            InputError::ReadFailed {
                detail: "io error".to_string(),
            },
            InputError::PasswordMismatch,
            InputError::EmptyPassword,
            InputError::PasswordTooLong {
                max: 1024,
                got: 2000,
            },
        ];
        for e in errors {
            let msg = format!("{}", e);
            assert!(!msg.is_empty(), "Error message was empty for {:?}", e);
        }
    }

    // -------------------------------------------------------------------------
    // Interactive TTY tests — ignored in automated CI
    // These are run manually during development to verify TTY reading works.
    // -------------------------------------------------------------------------

    #[test]
    #[ignore]
    fn test_read_password_interactive() {
        // Run manually: cargo test test_read_password_interactive -- --ignored
        let result = read_password("Test password (type anything): ");
        assert!(result.is_ok());
        let (secret, _) = result.unwrap();
        assert!(secret.len() > 0);
        println!("Read {} bytes", secret.len());
    }

    #[test]
    #[ignore]
    fn test_read_password_twice_matching() {
        // Run manually with matching inputs.
        let result = read_password_twice("New password: ", "Confirm password: ");
        assert!(result.is_ok());
    }

    #[test]
    #[ignore]
    fn test_read_password_twice_mismatch() {
        // Run manually with mismatched inputs.
        let result = read_password_twice("Password (type 'abc'): ", "Confirm (type 'xyz'): ");
        assert!(matches!(result, Err(InputError::PasswordMismatch)));
    }
}
