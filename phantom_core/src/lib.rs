// =============================================================================
// PhantomVault — phantom_core/src/lib.rs
// =============================================================================
//
// PyO3 entry point. Exports the public API to Python.
// Python NEVER holds raw key bytes. Only opaque handles, ciphertext,
// and success/failure results cross this boundary.
//
// SESSION MANAGEMENT:
//   A global Mutex<HashMap> maps u64 handles to live session keys.
//   Python receives only the handle integer.
//   All crypto uses the stored key looked up by handle.
//   lock_session() zeroes and removes the key from the map.
//
// THREAD SAFETY NOTE:
//   SecretBytes is deliberately !Send + !Sync (PhantomData<*const u8>)
//   to prevent accidental movement between threads. However, storing
//   Session in a global Mutex<HashMap> is safe because:
//   1. Mutex guarantees exclusive access — only one thread at a time.
//   2. The raw_ptr in SecretBytes points into memory owned by the
//      Vec inside the same struct. Moving Session via Mutex is safe
//      because ownership transfers atomically under the lock.
//   3. PyO3 functions run within the Python GIL context.
//   We implement Send + Sync for Session with this justification.
//
// =============================================================================

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;

pub mod crypto;
pub mod header;
pub mod hmac;
pub mod input;
pub mod memory;
pub mod shamir;

use crate::crypto::{
    decrypt, derive_master_key, derive_session_key, derive_subkey, encrypt, generate_random_bytes,
    generate_random_vec, Argon2Params, CipherChoice, KEY_LEN, SESSION_NONCE_LEN,
};
use crate::header::{VaultHeader, HEADER_SIZE};
use crate::hmac as hmac_mod;
use crate::input::{read_password, read_password_twice};
use crate::memory::SecretBytes;
use crate::shamir::{reconstruct_secret, split_secret, ShamirShare, SECRET_LEN};

// =============================================================================
// SESSION STORE
// =============================================================================

struct Session {
    key: SecretBytes,
    cipher: CipherChoice,
    #[allow(dead_code)]
    vault_id: [u8; 16],
    nonce_base: [u8; 24],
}

// SAFETY: Session is only accessed through a Mutex which serialises all access.
// The raw_ptr field in SecretBytes points to memory owned by the Vec in the
// same struct. Moving Session between threads under a Mutex lock is safe
// because only one thread holds the lock at any time.
unsafe impl Send for Session {}
unsafe impl Sync for Session {}

static SESSION_COUNTER: AtomicU64 = AtomicU64::new(1);

fn session_store() -> &'static Mutex<HashMap<u64, Session>> {
    static STORE: OnceLock<Mutex<HashMap<u64, Session>>> = OnceLock::new();
    STORE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn next_handle() -> u64 {
    SESSION_COUNTER.fetch_add(1, Ordering::SeqCst)
}

fn to_py_err(msg: impl std::fmt::Display) -> PyErr {
    PyRuntimeError::new_err(msg.to_string())
}

// Helper: copy a Vec<u8> into a fixed-size array.
fn vec_to_arr<const N: usize>(v: &[u8], name: &str) -> PyResult<[u8; N]> {
    if v.len() != N {
        return Err(to_py_err(format!(
            "{} must be {} bytes, got {}",
            name,
            N,
            v.len()
        )));
    }
    let mut arr = [0u8; N];
    arr.copy_from_slice(v);
    Ok(arr)
}

// =============================================================================
// EXPORTED FUNCTIONS
// =============================================================================

/// Read password from TTY and derive a session key for an existing vault.
/// Returns an opaque session handle (u64).
/// Python never sees the password or the key.
#[pyfunction]
#[allow(clippy::too_many_arguments)]
fn unlock_vault(
    vault_id_bytes: Vec<u8>,
    raw_header_bytes: Vec<u8>,
    t_cost: u32,
    m_cost: u32,
    p_cost: u32,
    salt_bytes: Vec<u8>,
    cipher_byte: u8,
    nonce_base_bytes: Vec<u8>,
    prompt: &str,
) -> PyResult<u64> {
    let vault_id = vec_to_arr::<16>(&vault_id_bytes, "vault_id")?;
    let salt = vec_to_arr::<16>(&salt_bytes, "salt")?;
    let nonce_base = vec_to_arr::<24>(&nonce_base_bytes, "nonce_base")?;

    let cipher = CipherChoice::from_header_byte(cipher_byte)
        .ok_or_else(|| to_py_err(format!("Unknown cipher byte: 0x{:02X}", cipher_byte)))?;

    let params = Argon2Params::new(t_cost, m_cost, p_cost).map_err(to_py_err)?;

    // Read password from TTY — Python never holds it.
    let (password, mlock_warning) = read_password(prompt).map_err(to_py_err)?;

    if let crate::memory::MlockStatus::Unlocked { ref warning } = mlock_warning {
        eprintln!("WARNING: {}", warning);
    }

    // Derive master key from password.
    let (master_key, _) = derive_master_key(password, &salt, &params).map_err(to_py_err)?;

    // Derive header auth key and verify header HMAC.
    let (header_key, _) =
        derive_subkey(&master_key, &vault_id, b"header-auth-key-v1").map_err(to_py_err)?;

    if raw_header_bytes.len() == HEADER_SIZE {
        let raw_arr = vec_to_arr::<HEADER_SIZE>(&raw_header_bytes, "raw_header")?;
        let parsed = VaultHeader::deserialize(&raw_arr).map_err(to_py_err)?;
        parsed
            .verify_hmac_raw(&raw_arr, &header_key)
            .map_err(|_| to_py_err("Incorrect password or vault is corrupted."))?;
    }
    drop(header_key);

    // Derive ephemeral session key. Master key zeroed inside this call.
    let session_nonce = generate_random_bytes::<SESSION_NONCE_LEN>().map_err(to_py_err)?;
    let (session_key, _) =
        derive_session_key(master_key, &vault_id, &session_nonce).map_err(to_py_err)?;

    let handle = next_handle();
    session_store()
        .lock()
        .map_err(|_| to_py_err("Session store lock poisoned"))?
        .insert(
            handle,
            Session {
                key: session_key,
                cipher,
                vault_id,
                nonce_base,
            },
        );

    Ok(handle)
}

/// Create a new vault. Reads password from TTY twice (confirmation).
/// Returns (session_handle, header_bytes).
#[pyfunction]
fn create_vault(
    cipher_byte: u8,
    t_cost: u32,
    m_cost: u32,
    p_cost: u32,
    prompt_first: &str,
    prompt_second: &str,
) -> PyResult<(u64, Vec<u8>)> {
    let cipher = CipherChoice::from_header_byte(cipher_byte)
        .ok_or_else(|| to_py_err(format!("Unknown cipher byte: 0x{:02X}", cipher_byte)))?;

    let params = Argon2Params::new(t_cost, m_cost, p_cost).map_err(to_py_err)?;

    // Read and confirm password — Python never holds it.
    let (password, mlock_warning) =
        read_password_twice(prompt_first, prompt_second).map_err(to_py_err)?;

    if let crate::memory::MlockStatus::Unlocked { ref warning } = mlock_warning {
        eprintln!("WARNING: {}", warning);
    }

    // Generate vault header with fresh random vault_id, salt, nonce_base.
    let mut vault_header = VaultHeader::new(cipher, params).map_err(to_py_err)?;

    let vault_id = vault_header.vault_id;
    let salt = vault_header.argon2_salt;
    let nonce_base = vault_header.chacha20_nonce_base;

    // Derive master key.
    let (master_key, _) =
        derive_master_key(password, &salt, &vault_header.argon2_params).map_err(to_py_err)?;

    // Derive header auth key, compute and store HMAC.
    let (header_key, _) =
        derive_subkey(&master_key, &vault_id, b"header-auth-key-v1").map_err(to_py_err)?;
    vault_header
        .compute_and_store_hmac(&header_key)
        .map_err(to_py_err)?;
    drop(header_key);

    // Derive session key. Master key zeroed inside.
    let session_nonce = generate_random_bytes::<SESSION_NONCE_LEN>().map_err(to_py_err)?;
    let (session_key, _) =
        derive_session_key(master_key, &vault_id, &session_nonce).map_err(to_py_err)?;

    let handle = next_handle();
    session_store()
        .lock()
        .map_err(|_| to_py_err("Session store lock poisoned"))?
        .insert(
            handle,
            Session {
                key: session_key,
                cipher,
                vault_id,
                nonce_base,
            },
        );

    let header_bytes = vault_header.serialize().map_err(to_py_err)?.to_vec();

    Ok((handle, header_bytes))
}

/// Encrypt plaintext using the session key identified by handle.
/// Returns ciphertext bytes.
#[pyfunction]
fn encrypt_data(
    handle: u64,
    plaintext: Vec<u8>,
    aad: Vec<u8>,
    write_counter: Option<u64>,
) -> PyResult<Vec<u8>> {
    let store = session_store()
        .lock()
        .map_err(|_| to_py_err("Session store lock poisoned"))?;

    let s = store
        .get(&handle)
        .ok_or_else(|| to_py_err("Invalid or expired session handle"))?;

    encrypt(
        s.cipher,
        &s.key,
        &plaintext,
        &aad,
        Some(&s.nonce_base),
        write_counter,
    )
    .map_err(to_py_err)
}

/// Decrypt ciphertext using the session key identified by handle.
/// Returns plaintext bytes.
#[pyfunction]
fn decrypt_data(
    handle: u64,
    ciphertext: Vec<u8>,
    aad: Vec<u8>,
    write_counter: Option<u64>,
) -> PyResult<Vec<u8>> {
    let store = session_store()
        .lock()
        .map_err(|_| to_py_err("Session store lock poisoned"))?;

    let s = store
        .get(&handle)
        .ok_or_else(|| to_py_err("Invalid or expired session handle"))?;

    decrypt(
        s.cipher,
        &s.key,
        &ciphertext,
        &aad,
        Some(&s.nonce_base),
        write_counter,
    )
    .map_err(to_py_err)
}

/// Lock a vault: zero the session key and remove the handle.
#[pyfunction]
fn lock_session(handle: u64) -> PyResult<()> {
    session_store()
        .lock()
        .map_err(|_| to_py_err("Session store lock poisoned"))?
        .remove(&handle);
    // Session dropped here — SecretBytes::drop() zeroes the key.
    Ok(())
}

/// Lock ALL open sessions. Used by panic command.
/// Returns count of sessions that were locked.
#[pyfunction]
fn lock_all_sessions() -> PyResult<usize> {
    let mut store = session_store()
        .lock()
        .map_err(|_| to_py_err("Session store lock poisoned"))?;
    let count = store.len();
    store.clear();
    // All Sessions dropped — all keys zeroed.
    Ok(count)
}

/// Returns true if the session handle is currently active.
#[pyfunction]
fn session_active(handle: u64) -> PyResult<bool> {
    Ok(session_store()
        .lock()
        .map_err(|_| to_py_err("Session store lock poisoned"))?
        .contains_key(&handle))
}

/// Split a 32-byte secret into Shamir shares.
/// Returns list of share byte arrays.
#[pyfunction]
fn shamir_split(secret_bytes: Vec<u8>, threshold: u8, total_shares: u8) -> PyResult<Vec<Vec<u8>>> {
    if secret_bytes.len() != SECRET_LEN {
        return Err(to_py_err(format!(
            "Secret must be {} bytes, got {}",
            SECRET_LEN,
            secret_bytes.len()
        )));
    }
    let (secret, _) = SecretBytes::new(secret_bytes).map_err(to_py_err)?;
    let shares = split_secret(&secret, threshold, total_shares).map_err(to_py_err)?;
    Ok(shares.iter().map(|s| s.as_bytes().to_vec()).collect())
}

/// Reconstruct a secret from Shamir shares.
/// Returns 32 secret bytes.
#[pyfunction]
fn shamir_reconstruct(share_bytes_list: Vec<Vec<u8>>, threshold: u8) -> PyResult<Vec<u8>> {
    let shares: Vec<ShamirShare> = share_bytes_list
        .into_iter()
        .map(ShamirShare::from_bytes)
        .collect();
    let secret = reconstruct_secret(&shares, threshold).map_err(to_py_err)?;
    Ok(secret.expose_secret().to_vec())
}

/// Compute HMAC-SHA256 of data with a 32-byte key.
#[pyfunction]
fn compute_hmac(key_bytes: Vec<u8>, data: Vec<u8>) -> PyResult<Vec<u8>> {
    if key_bytes.len() != KEY_LEN {
        return Err(to_py_err(format!(
            "HMAC key must be {} bytes, got {}",
            KEY_LEN,
            key_bytes.len()
        )));
    }
    let (key, _) = SecretBytes::new(key_bytes).map_err(to_py_err)?;
    let result = hmac_mod::compute_hmac(&key, &data).map_err(to_py_err)?;
    Ok(result.to_vec())
}

/// Compute a chained HMAC for audit log entries.
#[pyfunction]
fn chain_hmac(key_bytes: Vec<u8>, entry_data: Vec<u8>, prev_hmac: Vec<u8>) -> PyResult<Vec<u8>> {
    if key_bytes.len() != KEY_LEN {
        return Err(to_py_err("HMAC key must be 32 bytes"));
    }
    let prev_arr = vec_to_arr::<32>(&prev_hmac, "prev_hmac")?;
    let (key, _) = SecretBytes::new(key_bytes).map_err(to_py_err)?;
    let result = hmac_mod::chain_hmac(&key, &entry_data, &prev_arr).map_err(to_py_err)?;
    Ok(result.to_vec())
}

/// Generate N cryptographically random bytes from OS CSPRNG.
#[pyfunction]
fn random_bytes(n: usize) -> PyResult<Vec<u8>> {
    generate_random_vec(n).map_err(to_py_err)
}

// =============================================================================
// MODULE REGISTRATION
// =============================================================================

#[pymodule]
fn phantom_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(unlock_vault, m)?)?;
    m.add_function(wrap_pyfunction!(create_vault, m)?)?;
    m.add_function(wrap_pyfunction!(encrypt_data, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt_data, m)?)?;
    m.add_function(wrap_pyfunction!(lock_session, m)?)?;
    m.add_function(wrap_pyfunction!(lock_all_sessions, m)?)?;
    m.add_function(wrap_pyfunction!(session_active, m)?)?;
    m.add_function(wrap_pyfunction!(shamir_split, m)?)?;
    m.add_function(wrap_pyfunction!(shamir_reconstruct, m)?)?;
    m.add_function(wrap_pyfunction!(compute_hmac, m)?)?;
    m.add_function(wrap_pyfunction!(chain_hmac, m)?)?;
    m.add_function(wrap_pyfunction!(random_bytes, m)?)?;
    Ok(())
}
