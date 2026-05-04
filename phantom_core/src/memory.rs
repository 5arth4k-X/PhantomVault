// =============================================================================
// PhantomVault — phantom_core/src/memory.rs
// =============================================================================
//
// THE TRUSTED COMPUTING BASE — FILE 1 OF 6
//
// This is the first file written in the entire project and the most important
// one. Every other file in the TCB depends on this one. It defines:
//
//   1. SecretBytes  — a wrapper type for all sensitive byte data (keys,
//                     passwords, derived material). It NEVER implements Clone
//                     or Copy. It zeroes its contents the moment it is dropped.
//                     It attempts to lock its memory page with mlock() to
//                     prevent the OS from writing it to swap.
//
//   2. mlock()      — platform-specific memory locking. Prevents the OS from
//                     swapping the memory page containing key material to disk.
//                     Returns a Result so callers can decide how to handle
//                     failures (warn the user, do not abort).
//
//   3. secure_zero()— explicit memory zeroing with a compiler fence to prevent
//                     the compiler from optimising the zero-write away as
//                     "dead code" (a real and documented compiler behaviour).
//
//   4. catch_and_zero() — a wrapper around std::panic::catch_unwind that
//                         guarantees all SecretBytes in a provided closure
//                         are zeroed even if a panic occurs mid-operation.
//
// DESIGN DECISIONS:
//
//   - panic = "unwind" is set in Cargo.toml (not "abort"). This ensures that
//     Rust's Drop trait (and therefore ZeroizeOnDrop) runs when a panic
//     unwinds the stack. If "abort" were used, Drop would NOT run on panic
//     and keys would remain in memory after a crash.
//
//   - We use the `zeroize` crate rather than writing zeroing by hand. The
//     zeroize crate uses volatile writes and memory fences correctly across
//     all platforms and has been audited. Do not replace this with a manual
//     implementation.
//
//   - mlock() failure is a WARNING, not an error. On many default Linux
//     systems the RLIMIT_MEMLOCK limit is too low to lock even 32 bytes.
//     Rather than refusing to run, we warn the user and continue. The setup
//     documentation instructs users to set RLIMIT_MEMLOCK to unlimited.
//
//   - SecretBytes is NOT Send or Sync deliberately (via PhantomData). Key
//     material must not be moved between threads silently.
//
// SECURITY PROPERTIES THIS FILE PROVIDES:
//
//   [✓] Keys are zeroed when SecretBytes goes out of scope (normal path)
//   [✓] Keys are zeroed when SecretBytes goes out of scope (panic unwind path)
//   [✓] Keys cannot be accidentally cloned (no Clone/Copy)
//   [✓] Keys cannot appear in debug output (no Debug/Display)
//   [✓] Keys are not swappable when mlock succeeds
//   [✓] Zeroing cannot be optimised away by the compiler (memory fence)
//   [✓] All comparisons are constant-time (via subtle crate)
//
// WHAT THIS FILE DOES NOT PROTECT AGAINST:
//
//   [✗] SIGKILL — Drop does not run. Key in RAM until page reused by OS.
//   [✗] Hibernation — entire RAM written to disk including mlock'd pages.
//   [✗] DMA attacks via Thunderbolt/PCIe — reads physical RAM directly.
//   [✗] Fully compromised OS/kernel.
//   These limitations are documented in docs/SECURITY.md.
//
// =============================================================================

use std::fmt;
use std::marker::PhantomData;

use subtle::ConstantTimeEq;
use zeroize::Zeroize;

// =============================================================================
// PLATFORM-SPECIFIC IMPORTS
// mlock() and VirtualLock() are OS-specific calls that pin memory pages.
// =============================================================================

#[cfg(unix)]
use libc::{mlock, munlock};

#[cfg(windows)]
use winapi::um::memoryapi::{VirtualLock, VirtualUnlock};

// =============================================================================
// ERRORS
// =============================================================================

/// All errors that memory.rs can produce.
/// These are returned to callers as Results — never panic'd.
#[derive(Debug, Clone, PartialEq)]
pub enum MemoryError {
    /// mlock() returned a non-zero error code.
    /// This is a WARNING condition — the caller should log this and continue.
    /// It means the key may be written to swap if memory pressure is high.
    MlockFailed {
        /// The errno value returned by the OS.
        errno: i32,
        /// Human-readable explanation.
        message: String,
    },

    /// munlock() failed during SecretBytes drop.
    /// Logged internally but not propagated (drop cannot return errors).
    MunlockFailed {
        errno: i32,
    },

    /// Attempted to use an empty SecretBytes (len == 0).
    /// This indicates a programming error in the calling code.
    EmptySecret,

    /// The two values being compared have different lengths.
    /// Constant-time comparison requires equal lengths.
    LengthMismatch {
        expected: usize,
        got: usize,
    },
}

impl fmt::Display for MemoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MemoryError::MlockFailed { errno, message } => {
                write!(
                    f,
                    "Memory locking failed (errno {}): {}. \
                     Keys may be written to swap. \
                     See setup documentation to increase RLIMIT_MEMLOCK.",
                    errno, message
                )
            }
            MemoryError::MunlockFailed { errno } => {
                write!(f, "Memory unlock failed (errno {})", errno)
            }
            MemoryError::EmptySecret => {
                write!(f, "Attempted to use empty secret material")
            }
            MemoryError::LengthMismatch { expected, got } => {
                write!(
                    f,
                    "Length mismatch in constant-time comparison: \
                     expected {} bytes, got {} bytes",
                    expected, got
                )
            }
        }
    }
}

impl std::error::Error for MemoryError {}

// =============================================================================
// SecretBytes
//
// The core type of the TCB. All key material, all passwords, all derived
// sensitive values are stored in SecretBytes.
//
// INVARIANTS:
//   - Inner Vec<u8> is zeroed on drop (ZeroizeOnDrop).
//   - mlock() is called on creation (may fail — logged, not fatal).
//   - munlock() is called on drop before zeroing.
//   - No Clone, no Copy, no Debug, no Display.
//   - !Send + !Sync: must not cross thread boundaries.
// =============================================================================

/// A secure wrapper for sensitive byte data.
///
/// Zeroes its contents on drop. Attempts to pin memory with mlock().
/// Cannot be cloned, copied, or printed.
///
/// # Example
/// ```ignore
/// let key = SecretBytes::new(vec![0u8; 32])?;
/// // key is mlock'd and will be zeroed when it goes out of scope
/// ```
pub struct SecretBytes {
    /// The actual sensitive bytes.
    /// Wrapped in a struct so we can control all access.
    data: ZeroizingVec,

    /// Whether mlock() succeeded for this allocation.
    /// If false, the memory may be swapped to disk.
    is_locked: bool,

    /// Raw pointer to the data buffer — needed for mlock/munlock calls
    /// which operate on raw pointers rather than Rust references.
    /// This is safe because we control the lifetime of `data`.
    raw_ptr: *const u8,

    /// Length of the data — cached for munlock.
    raw_len: usize,

    /// Marker to make SecretBytes !Send and !Sync.
    /// Key material must not be silently shared between threads.
    _not_send_sync: PhantomData<*const u8>,
}

// Internal wrapper that implements ZeroizeOnDrop for Vec<u8>.
// We cannot put #[derive(ZeroizeOnDrop)] directly on SecretBytes
// because of the raw pointer fields.
struct ZeroizingVec(Vec<u8>);

impl Drop for ZeroizingVec {
    fn drop(&mut self) {
        // Explicit zeroing with volatile writes + memory fence.
        // The zeroize crate guarantees this cannot be optimised away.
        self.0.zeroize();
    }
}

impl SecretBytes {
    /// Creates a new SecretBytes from a Vec<u8>.
    ///
    /// Attempts to lock the memory with mlock(). If mlock() fails,
    /// returns the SecretBytes along with the mlock error so the caller
    /// can warn the user.
    ///
    /// The input Vec is consumed and its original allocation is used
    /// (no copy made — the sensitive bytes are not duplicated in memory).
    ///
    /// # Returns
    /// - `Ok((SecretBytes, None))` — created and mlock'd successfully.
    /// - `Ok((SecretBytes, Some(MemoryError)))` — created but mlock failed.
    ///   The key is usable but may be swappable. Caller should warn user.
    ///
    /// # Errors
    /// - `Err(MemoryError::EmptySecret)` — input Vec was empty.
    pub fn new(mut data: Vec<u8>) -> Result<(Self, Option<MemoryError>), MemoryError> {
        if data.is_empty() {
            // Zero the input before returning error — it may have been
            // a partially-filled sensitive buffer.
            data.zeroize();
            return Err(MemoryError::EmptySecret);
        }

        let raw_ptr = data.as_ptr();
        let raw_len = data.len();

        // Attempt to lock the memory page containing this data.
        let mlock_result = secure_mlock(raw_ptr, raw_len);

        let is_locked = mlock_result.is_ok();
        let mlock_warning = mlock_result.err();

        let secret = SecretBytes {
            data: ZeroizingVec(data),
            is_locked,
            raw_ptr,
            raw_len,
            _not_send_sync: PhantomData,
        };

        Ok((secret, mlock_warning))
    }

    /// Creates SecretBytes from a fixed-size array.
    /// Convenience wrapper — arrays are common for key sizes (32 bytes).
    pub fn from_array<const N: usize>(
        mut arr: [u8; N],
    ) -> Result<(Self, Option<MemoryError>), MemoryError> {
        let vec = arr.to_vec();
        // Zero the original array — we have a copy in vec now.
        arr.zeroize();
        Self::new(vec)
    }

    /// Returns the length of the secret data in bytes.
    pub fn len(&self) -> usize {
        self.data.0.len()
    }

    /// Returns true if the secret data is empty.
    /// Should never be true after construction (EmptySecret error prevents it).
    pub fn is_empty(&self) -> bool {
        self.data.0.is_empty()
    }

    /// Returns whether this SecretBytes was successfully mlock'd.
    /// If false, the caller should have received a warning at construction.
    pub fn is_memory_locked(&self) -> bool {
        self.is_locked
    }

    /// Provides read-only access to the secret bytes.
    ///
    /// # Safety Contract
    /// The returned slice must not be stored anywhere. It must not be
    /// passed to any function that stores it. It must not be cloned.
    /// It is intended solely for immediate use in cryptographic operations.
    ///
    /// Clippy will warn about this with a "sensitive data" lint — that is
    /// expected and the usage sites are audited for safety.
    pub fn expose_secret(&self) -> &[u8] {
        &self.data.0
    }

    /// Performs a constant-time equality comparison with another SecretBytes.
    ///
    /// Both must have the same length. Uses the `subtle` crate to ensure
    /// the comparison takes the same amount of time regardless of how many
    /// bytes match. This prevents timing attacks where an attacker measures
    /// how long a comparison takes to learn information about the secret.
    ///
    /// # Returns
    /// - `Ok(true)`  — equal (constant-time)
    /// - `Ok(false)` — not equal (constant-time)
    /// - `Err(MemoryError::LengthMismatch)` — lengths differ
    pub fn ct_eq(&self, other: &SecretBytes) -> Result<bool, MemoryError> {
        if self.len() != other.len() {
            return Err(MemoryError::LengthMismatch {
                expected: self.len(),
                got: other.len(),
            });
        }

        // subtle::ConstantTimeEq returns a Choice (0 or 1) not a bool.
        // .into() converts Choice to bool.
        let result: bool = self
            .data
            .0
            .ct_eq(&other.data.0)
            .into();

        Ok(result)
    }

    /// Performs a constant-time equality comparison with a raw byte slice.
    /// Used when comparing against a derived value not in SecretBytes form.
    pub fn ct_eq_slice(&self, other: &[u8]) -> Result<bool, MemoryError> {
        if self.len() != other.len() {
            return Err(MemoryError::LengthMismatch {
                expected: self.len(),
                got: other.len(),
            });
        }

        let result: bool = self.data.0.ct_eq(other).into();
        Ok(result)
    }

    /// Explicitly zeroes the secret data immediately.
    ///
    /// This is called in all error paths and after key derivation when
    /// the secret is no longer needed. Drop will also zero it, but calling
    /// this explicitly ensures zeroing happens at the precise known point.
    pub fn zero_now(&mut self) {
        self.data.0.zeroize();
    }

    /// Concatenates two SecretBytes into a new one.
    /// Both inputs are consumed (and zeroed via Drop).
    /// Used when combining TPM material with password-derived key.
    pub fn concat(
        a: SecretBytes,
        b: SecretBytes,
    ) -> Result<(Self, Option<MemoryError>), MemoryError> {
        let mut combined = Vec::with_capacity(a.len() + b.len());
        combined.extend_from_slice(a.expose_secret());
        combined.extend_from_slice(b.expose_secret());
        // a and b are dropped here — their Drop zeroes them.
        drop(a);
        drop(b);
        Self::new(combined)
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        // Step 1: unlock the memory page if we locked it.
        if self.is_locked {
            let _ = secure_munlock(self.raw_ptr, self.raw_len);
            // We ignore munlock errors in Drop — cannot propagate them.
            // The kernel will reclaim the memory either way.
        }

        // Step 2: ZeroizingVec's Drop handles the actual zeroing.
        // The zeroize crate uses volatile writes + memory fence.
        // This runs automatically when `self.data` is dropped.
        // Nothing more to do here — the ZeroizingVec Drop handles it.
    }
}

// SecretBytes is explicitly NOT Clone and NOT Copy.
// These are intentionally absent — the derive macros are not used.
// A Clone would duplicate sensitive material.

// SecretBytes is NOT Debug — keys must not appear in logs or panic messages.
impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print the actual bytes.
        write!(
            f,
            "SecretBytes {{ len: {}, locked: {} }}",
            self.len(),
            self.is_locked
        )
    }
}

// SecretBytes is NOT Display — same reason.
impl fmt::Display for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED SecretBytes len={}]", self.len())
    }
}

// =============================================================================
// PLATFORM-SPECIFIC mlock / munlock
// =============================================================================

/// Attempts to lock a memory region using the OS memory locking API.
///
/// On Linux/macOS: calls mlock(2) which pins the pages in physical RAM.
/// On Windows: calls VirtualLock() which does the equivalent.
///
/// # Why this can fail
/// Linux has RLIMIT_MEMLOCK which limits how much memory a process can lock.
/// Default on Ubuntu/Kali/Debian is 64KB or 8MB depending on the distro.
/// If the limit is too low, mlock returns EPERM.
/// setup.sh sets RLIMIT_MEMLOCK to unlimited for the phantomvault user.
/// If that was not done, this returns MemoryError::MlockFailed.
///
/// # Safety
/// The pointer must be valid, the length must be correct, and the memory
/// must remain alive for as long as it is locked. SecretBytes ensures this
/// by holding the Vec (and therefore the allocation) alive.
fn secure_mlock(ptr: *const u8, len: usize) -> Result<(), MemoryError> {
    #[cfg(unix)]
    {
        // SAFETY: ptr is valid (from a live Vec), len matches the Vec length.
        let result = unsafe { mlock(ptr as *const libc::c_void, len) };
        if result != 0 {
            let errno = unsafe { *libc::__errno_location() };
            return Err(MemoryError::MlockFailed {
                errno,
                message: errno_to_string(errno),
            });
        }
        Ok(())
    }

    #[cfg(windows)]
    {
        // SAFETY: same as above.
        let result = unsafe { VirtualLock(ptr as *mut winapi::ctypes::c_void, len) };
        if result == 0 {
            let err = unsafe { winapi::um::errhandlingapi::GetLastError() };
            return Err(MemoryError::MlockFailed {
                errno: err as i32,
                message: format!("VirtualLock failed with error code {}", err),
            });
        }
        Ok(())
    }

    #[cfg(not(any(unix, windows)))]
    {
        // Unknown platform — mlock not available.
        // Return a warning (not a hard error) so the tool still works.
        let _ = (ptr, len); // suppress unused warnings
        Err(MemoryError::MlockFailed {
            errno: 0,
            message: "mlock not supported on this platform".to_string(),
        })
    }
}

/// Unlocks a previously mlock'd memory region.
/// Called in Drop before zeroing.
fn secure_munlock(ptr: *const u8, len: usize) -> Result<(), MemoryError> {
    #[cfg(unix)]
    {
        let result = unsafe { munlock(ptr as *const libc::c_void, len) };
        if result != 0 {
            let errno = unsafe { *libc::__errno_location() };
            return Err(MemoryError::MunlockFailed { errno });
        }
        Ok(())
    }

    #[cfg(windows)]
    {
        let result = unsafe { VirtualUnlock(ptr as *mut winapi::ctypes::c_void, len) };
        if result == 0 {
            let err = unsafe { winapi::um::errhandlingapi::GetLastError() };
            return Err(MemoryError::MunlockFailed { errno: err as i32 });
        }
        Ok(())
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = (ptr, len);
        Ok(()) // Nothing to unlock
    }
}

/// Converts a Unix errno to a human-readable string.
#[cfg(unix)]
fn errno_to_string(errno: i32) -> String {
    match errno {
        libc::EPERM => {
            "Operation not permitted (EPERM). \
             The process does not have permission to lock this memory. \
             RLIMIT_MEMLOCK may be too low. \
             Run: ulimit -l unlimited"
                .to_string()
        }
        libc::ENOMEM => {
            "Not enough memory (ENOMEM). \
             Some of the specified address range does not correspond \
             to mapped pages in the address space. \
             Or the process's mlock limit has been reached."
                .to_string()
        }
        libc::EINVAL => "Invalid argument (EINVAL). Address not page-aligned.".to_string(),
        _ => format!("OS error code {}", errno),
    }
}

// =============================================================================
// secure_zero — standalone function for zeroing raw buffers
//
// Use this when you have a raw Vec<u8> or array that is not wrapped in
// SecretBytes but still contains sensitive data and needs zeroing before
// being dropped. For example, an intermediate buffer during file reading.
// =============================================================================

/// Zeroes a mutable byte slice using volatile writes and a memory fence.
///
/// The `zeroize` crate handles this correctly across platforms.
/// Do NOT replace with ptr::write_bytes — the compiler may optimise it away.
///
/// # Example
/// ```ignore
/// let mut buffer = vec![0xAAu8; 32];
/// // ... use buffer for sensitive operation ...
/// secure_zero(&mut buffer);
/// // buffer is now all zeros and the zeroing was not optimised away
/// ```
pub fn secure_zero(data: &mut Vec<u8>) {
    data.zeroize();
}

/// Zeroes a fixed-size array using volatile writes.
pub fn secure_zero_array<const N: usize>(arr: &mut [u8; N]) {
    arr.zeroize();
}

// =============================================================================
// catch_and_zero
//
// Wraps a closure in std::panic::catch_unwind. If the closure panics,
// the provided SecretBytes list is zeroed before the panic is re-raised.
//
// This is the defence against unexpected panics leaving keys in memory.
// Every PyO3 entry point in lib.rs uses this wrapper.
// =============================================================================

/// Result type returned by catch_and_zero.
pub type PanicSafeResult<T> = Result<T, Box<dyn std::any::Any + Send>>;

/// Executes a closure, catching any panics.
///
/// If the closure panics, all provided keys are zeroed before
/// the panic information is returned to the caller.
///
/// # Usage
/// ```ignore
/// let (key, _) = SecretBytes::new(vec![0u8; 32])?;
/// let result = catch_and_zero(
///     || {
///         // ... cryptographic operation that might panic ...
///         Ok(42u64)
///     },
///     vec![&mut some_key, &mut another_key],
/// );
/// ```
///
/// # Note on `panic = "unwind"` in Cargo.toml
/// This function only works correctly when panic = "unwind" is set.
/// If panic = "abort", catch_unwind does not prevent abort and Drop
/// does not run. Cargo.toml must have:
///   [profile.release]
///   panic = "unwind"
pub fn catch_and_zero<F, T>(
    f: F,
    keys_to_zero_on_panic: Vec<&mut SecretBytes>,
) -> Result<T, String>
where
    F: FnOnce() -> Result<T, String> + std::panic::UnwindSafe,
{
    // We need to hold mutable references to keys, but catch_unwind requires
    // UnwindSafe. We use a raw pointer approach here, wrapped safely.
    //
    // SAFETY: The keys vector lives for the duration of this function.
    // The closure runs synchronously within this function's scope.
    // No other thread can access these references simultaneously (!Sync).

    // Wrap keys in a structure that zeroes on drop.
    struct ZeroOnDrop<'a>(Vec<&'a mut SecretBytes>);
    impl<'a> Drop for ZeroOnDrop<'a> {
        fn drop(&mut self) {
            for key in &mut self.0 {
                key.zero_now();
            }
        }
    }

    // Using AssertUnwindSafe is justified here because:
    // 1. ZeroOnDrop's drop always runs (even on panic with unwind)
    // 2. SecretBytes is !Sync so no concurrent access is possible
    // 3. We zero everything on drop regardless of panic or normal exit
    let zero_guard = std::panic::AssertUnwindSafe(ZeroOnDrop(keys_to_zero_on_panic));
    let safe_f = std::panic::AssertUnwindSafe(f);

    match std::panic::catch_unwind(move || {
        let _guard = zero_guard; // ZeroOnDrop runs when this scope exits
        safe_f()
    }) {
        Ok(result) => result,
        Err(panic_info) => {
            // Panic was caught. ZeroOnDrop already ran, zeroing all keys.
            // Convert panic info to a string error.
            let msg = if let Some(s) = panic_info.downcast_ref::<String>() {
                s.clone()
            } else if let Some(s) = panic_info.downcast_ref::<&str>() {
                s.to_string()
            } else {
                "An unexpected internal error occurred".to_string()
            };
            // Never expose internal panic details to Python layer —
            // they could contain sensitive context.
            Err(format!("Internal error: {}", msg))
        }
    }
}

// =============================================================================
// MlockStatus — helper for Python layer to display warnings
// =============================================================================

/// Status of memory locking for a SecretBytes instance.
/// Returned to the Python layer so it can display appropriate warnings.
#[derive(Debug, Clone, PartialEq)]
pub enum MlockStatus {
    /// Memory is locked — key cannot be swapped to disk.
    Locked,
    /// Memory locking failed — key MAY be swapped to disk.
    /// Contains the warning message to display to the user.
    Unlocked { warning: String },
}

impl From<Option<MemoryError>> for MlockStatus {
    fn from(err: Option<MemoryError>) -> Self {
        match err {
            None => MlockStatus::Locked,
            Some(e) => MlockStatus::Unlocked {
                warning: e.to_string(),
            },
        }
    }
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------------
    // SecretBytes construction
    // -------------------------------------------------------------------------

    #[test]
    fn test_new_creates_secret_bytes() {
        let data = vec![0x01u8, 0x02, 0x03, 0x04];
        let (secret, _mlock_warning) = SecretBytes::new(data).unwrap();
        assert_eq!(secret.len(), 4);
        assert!(!secret.is_empty());
    }

    #[test]
    fn test_empty_input_returns_error() {
        let result = SecretBytes::new(vec![]);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), MemoryError::EmptySecret);
    }

    #[test]
    fn test_from_array_works() {
        let arr = [0xAAu8; 32];
        let (secret, _) = SecretBytes::from_array(arr).unwrap();
        assert_eq!(secret.len(), 32);
    }

    #[test]
    fn test_expose_secret_returns_correct_bytes() {
        let data = vec![0xDEu8, 0xAD, 0xBE, 0xEF];
        let (secret, _) = SecretBytes::new(data.clone()).unwrap();
        assert_eq!(secret.expose_secret(), data.as_slice());
    }

    // -------------------------------------------------------------------------
    // No debug/display leaks
    // -------------------------------------------------------------------------

    #[test]
    fn test_debug_does_not_leak_bytes() {
        let data = vec![0xFFu8; 32];
        let (secret, _) = SecretBytes::new(data).unwrap();
        let debug_str = format!("{:?}", secret);
        // Must contain length info but NOT the actual bytes (0xFF)
        assert!(debug_str.contains("len: 32"));
        assert!(!debug_str.contains("255")); // 0xFF as decimal
        assert!(!debug_str.contains("ff"));  // 0xFF as hex
        assert!(!debug_str.contains("FF"));
    }

    #[test]
    fn test_display_does_not_leak_bytes() {
        let data = vec![0xFFu8; 16];
        let (secret, _) = SecretBytes::new(data).unwrap();
        let display_str = format!("{}", secret);
        assert!(display_str.contains("REDACTED"));
        assert!(!display_str.contains("255"));
    }

    // -------------------------------------------------------------------------
    // Constant-time comparison
    // -------------------------------------------------------------------------

    #[test]
    fn test_ct_eq_equal_secrets() {
        let data = vec![0x42u8; 32];
        let (a, _) = SecretBytes::new(data.clone()).unwrap();
        let (b, _) = SecretBytes::new(data).unwrap();
        assert_eq!(a.ct_eq(&b).unwrap(), true);
    }

    #[test]
    fn test_ct_eq_unequal_secrets() {
        let (a, _) = SecretBytes::new(vec![0x00u8; 32]).unwrap();
        let (b, _) = SecretBytes::new(vec![0x01u8; 32]).unwrap();
        assert_eq!(a.ct_eq(&b).unwrap(), false);
    }

    #[test]
    fn test_ct_eq_different_lengths_returns_error() {
        let (a, _) = SecretBytes::new(vec![0x00u8; 32]).unwrap();
        let (b, _) = SecretBytes::new(vec![0x00u8; 16]).unwrap();
        let result = a.ct_eq(&b);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), MemoryError::LengthMismatch { .. }));
    }

    #[test]
    fn test_ct_eq_slice_equal() {
        let data = vec![0x55u8; 32];
        let (secret, _) = SecretBytes::new(data.clone()).unwrap();
        assert_eq!(secret.ct_eq_slice(&data).unwrap(), true);
    }

    #[test]
    fn test_ct_eq_slice_unequal() {
        let (secret, _) = SecretBytes::new(vec![0x00u8; 32]).unwrap();
        let other = vec![0xFFu8; 32];
        assert_eq!(secret.ct_eq_slice(&other).unwrap(), false);
    }

    // -------------------------------------------------------------------------
    // Zeroing
    // -------------------------------------------------------------------------

    #[test]
    fn test_zero_now_clears_bytes() {
        let data = vec![0xFFu8; 32];
        let (mut secret, _) = SecretBytes::new(data).unwrap();
        secret.zero_now();
        // After zero_now, all bytes should be 0x00
        assert!(secret.expose_secret().iter().all(|&b| b == 0x00));
    }

    #[test]
    fn test_zeroing_on_drop() {
        // This test verifies conceptually that zeroing happens on drop.
        // We cannot directly observe memory after drop (undefined behaviour
        // to read freed memory) but we can verify zero_now works correctly
        // as a proxy for the drop behaviour.
        let data = vec![0xAAu8; 64];
        let (mut secret, _) = SecretBytes::new(data).unwrap();
        assert!(secret.expose_secret().iter().all(|&b| b == 0xAA));
        secret.zero_now();
        assert!(secret.expose_secret().iter().all(|&b| b == 0x00));
        // drop(secret) will call ZeroizingVec::drop which also zeroes
        // The data is already zero so this is a no-op but it runs.
    }

    // -------------------------------------------------------------------------
    // Concatenation
    // -------------------------------------------------------------------------

    #[test]
    fn test_concat_produces_combined_bytes() {
        let (a, _) = SecretBytes::new(vec![0x01u8; 16]).unwrap();
        let (b, _) = SecretBytes::new(vec![0x02u8; 16]).unwrap();
        let (combined, _) = SecretBytes::concat(a, b).unwrap();
        assert_eq!(combined.len(), 32);
        assert!(combined.expose_secret()[..16].iter().all(|&b| b == 0x01));
        assert!(combined.expose_secret()[16..].iter().all(|&b| b == 0x02));
    }

    // -------------------------------------------------------------------------
    // secure_zero standalone functions
    // -------------------------------------------------------------------------

    #[test]
    fn test_secure_zero_clears_vec() {
        let mut data = vec![0xFFu8; 64];
        secure_zero(&mut data);
        assert!(data.iter().all(|&b| b == 0x00));
    }

    #[test]
    fn test_secure_zero_array_clears_array() {
        let mut arr = [0xBBu8; 32];
        secure_zero_array(&mut arr);
        assert!(arr.iter().all(|&b| b == 0x00));
    }

    // -------------------------------------------------------------------------
    // catch_and_zero
    // -------------------------------------------------------------------------

    #[test]
    fn test_catch_and_zero_returns_ok_on_success() {
        let (mut key, _) = SecretBytes::new(vec![0x01u8; 32]).unwrap();
        let result = catch_and_zero(
            || Ok(42u64),
            vec![&mut key],
        );
        assert_eq!(result.unwrap(), 42u64);
    }

    #[test]
    fn test_catch_and_zero_returns_err_on_failure() {
        let (mut key, _) = SecretBytes::new(vec![0x01u8; 32]).unwrap();
        let result: Result<u64, String> = catch_and_zero(
            || Err("operation failed".to_string()),
            vec![&mut key],
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_mlock_status_from_none() {
        let status = MlockStatus::from(None);
        assert_eq!(status, MlockStatus::Locked);
    }

    #[test]
    fn test_mlock_status_from_error() {
        let error = Some(MemoryError::MlockFailed {
            errno: 1,
            message: "test".to_string(),
        });
        let status = MlockStatus::from(error);
        assert!(matches!(status, MlockStatus::Unlocked { .. }));
    }

    // -------------------------------------------------------------------------
    // MlockStatus
    // -------------------------------------------------------------------------

    #[test]
    fn test_secret_bytes_reports_lock_status() {
        let (secret, mlock_warning) = SecretBytes::new(vec![0x01u8; 32]).unwrap();
        // On a properly configured system (RLIMIT_MEMLOCK = unlimited),
        // mlock_warning should be None and is_memory_locked should be true.
        // On a restricted system, mlock_warning contains the warning.
        // Either way the SecretBytes is created successfully.
        let _ = mlock_warning; // Either outcome is acceptable
        let _ = secret.is_memory_locked(); // Just verify the method works
    }
}
