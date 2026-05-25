use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::sync::atomic::{AtomicU64, Ordering};

use pyo3::prelude::*;
use pyo3::exceptions::PyRuntimeError;

pub mod memory;
pub mod crypto;
pub mod header;
pub mod input;
pub mod hmac;
pub mod shamir;

use crate::memory::SecretBytes;
use crate::crypto::{
    Argon2Params, CipherChoice,
    derive_master_key, derive_subkey,
    encrypt, decrypt, generate_random_vec,
    KEY_LEN, ARGON2_SALT_LEN,
};
use crate::header::{VaultHeader, HEADER_SIZE};
use crate::input::{read_password, read_password_twice};
use crate::hmac as hmac_mod;
use crate::shamir::{split_secret, reconstruct_secret, ShamirShare, SECRET_LEN};

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

fn vec_to_arr<const N: usize>(v: &[u8], name: &str) -> PyResult<[u8; N]> {
    if v.len() != N {
        return Err(to_py_err(format!(
            "{} must be {} bytes, got {}", name, N, v.len()
        )));
    }
    let mut arr = [0u8; N];
    arr.copy_from_slice(v);
    Ok(arr)
}

// =============================================================================
// VAULT DATA KEY DERIVATION
//
// This is the key used to encrypt/decrypt files stored in the vault container.
// It must be DETERMINISTIC — re-derivable from the same password every time.
//
// Unlike the ephemeral session key (which uses a random nonce), this key uses
// a fixed purpose string so the same key is produced on every unlock.
//
// Key = HKDF-SHA256(master_key, vault_id, "vault-data-key-v1")
// =============================================================================

const VAULT_DATA_KEY_PURPOSE: &[u8] = b"vault-data-key-v1";

fn derive_vault_data_key(
    master_key: SecretBytes,
    vault_id: &[u8; 16],
) -> PyResult<(SecretBytes, [u8; 24])> {
    // Derive deterministic vault data key from master key.
    // master_key is consumed and zeroed inside derive_subkey.
    let (data_key, _) = derive_subkey(&master_key, vault_id, VAULT_DATA_KEY_PURPOSE)
        .map_err(to_py_err)?;
    drop(master_key); // explicitly zero master key

    // Also derive a stable nonce base for ChaCha20 from master key.
    // This is derived before master_key is consumed above, but we need
    // to use a separate subkey for the nonce base.
    // Since master_key is already consumed, we derive nonce_base from data_key.
    // For AES-256-GCM-SIV, nonce_base is unused (fresh nonce per encrypt).
    // For ChaCha20, nonce_base is XOR'd with write_counter.
    // We use a fixed nonce_base derived from the data_key for consistency.
    let mut nonce_base = [0u8; 24];
    // Use bytes 8..32 of data_key as nonce_base (24 bytes).
    // This is deterministic — same password always produces same nonce_base.
    nonce_base.copy_from_slice(&data_key.expose_secret()[8..32]);

    Ok((data_key, nonce_base))
}

// =============================================================================
// EXPORTED FUNCTIONS
// =============================================================================

/// Read password from TTY and derive the vault data key.
/// Returns opaque session handle. Python never sees the key.
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
    _nonce_base_bytes: Vec<u8>,
    prompt: &str,
) -> PyResult<u64> {
    let vault_id = vec_to_arr::<16>(&vault_id_bytes, "vault_id")?;
    let salt     = vec_to_arr::<ARGON2_SALT_LEN>(&salt_bytes, "salt")?;

    let cipher = CipherChoice::from_header_byte(cipher_byte)
        .ok_or_else(|| to_py_err(format!("Unknown cipher byte: 0x{:02X}", cipher_byte)))?;

    let params = Argon2Params::new(t_cost, m_cost, p_cost)
        .map_err(to_py_err)?;

    // Read password from TTY — Python never holds it.
    let (password, mlock_warning) = read_password(prompt).map_err(to_py_err)?;
    if let crate::memory::MlockStatus::Unlocked { ref warning } = mlock_warning {
        eprintln!("WARNING: {}", warning);
    }

    // Derive master key from password.
    let (master_key, _) = derive_master_key(password, &salt, &params)
        .map_err(to_py_err)?;

    // Verify header HMAC using master key.
    let (header_key, _) = derive_subkey(&master_key, &vault_id, b"header-auth-key-v1")
        .map_err(to_py_err)?;

    if raw_header_bytes.len() == HEADER_SIZE {
        let raw_arr = vec_to_arr::<HEADER_SIZE>(&raw_header_bytes, "raw_header")?;
        let parsed = crate::header::VaultHeader::deserialize(&raw_arr)
            .map_err(to_py_err)?;
        parsed.verify_hmac_raw(&raw_arr, &header_key)
            .map_err(|_| to_py_err("Incorrect password or vault is corrupted."))?;
    }
    drop(header_key);

    // Derive the DETERMINISTIC vault data key.
    // This is the same key used during create — re-derivable from same password.
    let (data_key, nonce_base) = derive_vault_data_key(master_key, &vault_id)?;

    let handle = next_handle();
    session_store()
        .lock()
        .map_err(|_| to_py_err("Session store lock poisoned"))?
        .insert(handle, Session {
            key: data_key,
            cipher,
            vault_id,
            nonce_base,
        });

    Ok(handle)
}

/// Create a new vault. Reads password from TTY twice (confirmation).
/// Returns (session_handle, header_bytes).
/// The session key is the DETERMINISTIC vault data key.
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

    let params = Argon2Params::new(t_cost, m_cost, p_cost)
        .map_err(to_py_err)?;

    // Read and confirm password — Python never holds it.
    let (password, mlock_warning) = read_password_twice(prompt_first, prompt_second)
        .map_err(to_py_err)?;
    if let crate::memory::MlockStatus::Unlocked { ref warning } = mlock_warning {
        eprintln!("WARNING: {}", warning);
    }

    // Create vault header — generates vault_id, salt, nonce_base.
    let mut vault_header = VaultHeader::new(cipher, params)
        .map_err(to_py_err)?;
    let vault_id = vault_header.vault_id;
    let salt     = vault_header.argon2_salt;

    // Derive master key from password.
    let (master_key, _) = derive_master_key(password, &salt, &vault_header.argon2_params)
        .map_err(to_py_err)?;

    // Compute and store header HMAC.
    let (header_key, _) = derive_subkey(&master_key, &vault_id, b"header-auth-key-v1")
        .map_err(to_py_err)?;
    vault_header.compute_and_store_hmac(&header_key).map_err(to_py_err)?;
    drop(header_key);

    // Derive the DETERMINISTIC vault data key.
    // Same derivation as unlock_vault — must match exactly.
    let (data_key, nonce_base) = derive_vault_data_key(master_key, &vault_id)?;

    let handle = next_handle();
    session_store()
        .lock()
        .map_err(|_| to_py_err("Session store lock poisoned"))?
        .insert(handle, Session {
            key: data_key,
            cipher,
            vault_id,
            nonce_base,
        });

    let header_bytes = vault_header.serialize()
        .map_err(to_py_err)?
        .to_vec();

    Ok((handle, header_bytes))
}

/// Encrypt plaintext using the session key identified by handle.
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
    let s = store.get(&handle)
        .ok_or_else(|| to_py_err("Invalid or expired session handle"))?;
    encrypt(s.cipher, &s.key, &plaintext, &aad, Some(&s.nonce_base), write_counter)
        .map_err(to_py_err)
}

/// Decrypt ciphertext using the session key identified by handle.
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
    let s = store.get(&handle)
        .ok_or_else(|| to_py_err("Invalid or expired session handle"))?;
    decrypt(s.cipher, &s.key, &ciphertext, &aad, Some(&s.nonce_base), write_counter)
        .map_err(to_py_err)
}

/// Lock a vault: zero the session key and remove the handle.
#[pyfunction]
fn lock_session(handle: u64) -> PyResult<()> {
    session_store()
        .lock()
        .map_err(|_| to_py_err("Session store lock poisoned"))?
        .remove(&handle);
    Ok(())
}

/// Lock ALL open sessions.
#[pyfunction]
fn lock_all_sessions() -> PyResult<usize> {
    let mut store = session_store()
        .lock()
        .map_err(|_| to_py_err("Session store lock poisoned"))?;
    let count = store.len();
    store.clear();
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
#[pyfunction]
fn shamir_split(secret_bytes: Vec<u8>, threshold: u8, total_shares: u8) -> PyResult<Vec<Vec<u8>>> {
    if secret_bytes.len() != SECRET_LEN {
        return Err(to_py_err(format!("Secret must be {} bytes, got {}", SECRET_LEN, secret_bytes.len())));
    }
    let (secret, _) = SecretBytes::new(secret_bytes).map_err(to_py_err)?;
    let shares = split_secret(&secret, threshold, total_shares).map_err(to_py_err)?;
    Ok(shares.iter().map(|s| s.as_bytes().to_vec()).collect())
}

/// Reconstruct a secret from Shamir shares.
#[pyfunction]
fn shamir_reconstruct(share_bytes_list: Vec<Vec<u8>>, threshold: u8) -> PyResult<Vec<u8>> {
    let shares: Vec<ShamirShare> = share_bytes_list.into_iter().map(ShamirShare::from_bytes).collect();
    let secret = reconstruct_secret(&shares, threshold).map_err(to_py_err)?;
    Ok(secret.expose_secret().to_vec())
}

/// Compute HMAC-SHA256 of data with a 32-byte key.
#[pyfunction]
fn compute_hmac(key_bytes: Vec<u8>, data: Vec<u8>) -> PyResult<Vec<u8>> {
    if key_bytes.len() != KEY_LEN {
        return Err(to_py_err(format!("HMAC key must be {} bytes, got {}", KEY_LEN, key_bytes.len())));
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
