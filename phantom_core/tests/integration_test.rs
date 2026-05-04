// =============================================================================
// PhantomVault — Integration Tests
// Tests that verify the full flow: password -> key -> encrypt -> decrypt
// These test the entire TCB working together, not individual units.
// =============================================================================

use phantom_core::crypto::{
    decrypt_aes_gcm_siv, derive_master_key, derive_session_key, derive_subkey, encrypt_aes_gcm_siv,
    generate_random_bytes, Argon2Params, CipherChoice, ARGON2_SALT_LEN, SESSION_NONCE_LEN,
};
use phantom_core::header::{VaultHeader, HEADER_SIZE};
use phantom_core::hmac::{chain_hmac, HMAC_OUTPUT_LEN};
use phantom_core::memory::SecretBytes;
use phantom_core::shamir::{reconstruct_secret, split_secret};

// ─────────────────────────────────────────────────────────────────────────────
// Test params — minimal Argon2id for speed in tests
// These are the absolute minimums. Production uses defaults (3/65536/4).
// ─────────────────────────────────────────────────────────────────────────────
fn test_params() -> Argon2Params {
    Argon2Params::new(3, 65_536, 4).unwrap()
}

// ─────────────────────────────────────────────────────────────────────────────
// Full vault creation flow: password -> master key -> session key -> encrypt
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn integration_full_vault_create_unlock_cycle() {
    let params = test_params();
    let salt = generate_random_bytes::<ARGON2_SALT_LEN>().unwrap();
    let vault_id = generate_random_bytes::<16>().unwrap();
    let session_nonce = generate_random_bytes::<SESSION_NONCE_LEN>().unwrap();

    // Simulate vault creation
    let (pw, _) = SecretBytes::new(b"correct-horse-battery".to_vec()).unwrap();
    let (master_key, _) = derive_master_key(pw, &salt, &params).unwrap();

    // Derive header auth key
    let (_header_key, _) = derive_subkey(&master_key, &vault_id, b"header-auth-key-v1").unwrap();

    // Derive session key (master_key consumed here)
    let (session_key, _) = derive_session_key(master_key, &vault_id, &session_nonce).unwrap();

    // Encrypt some data
    let plaintext = b"This is sensitive vault content for integration testing.";
    let aad = b"vault-region-a-v1";
    let ciphertext = encrypt_aes_gcm_siv(&session_key, plaintext, aad).unwrap();

    assert_ne!(ciphertext.as_slice(), plaintext.as_slice());

    // Simulate unlock: re-derive from same password
    let (pw2, _) = SecretBytes::new(b"correct-horse-battery".to_vec()).unwrap();
    let (master_key2, _) = derive_master_key(pw2, &salt, &params).unwrap();
    let (session_key2, _) = derive_session_key(master_key2, &vault_id, &session_nonce).unwrap();

    // Decrypt
    let decrypted = decrypt_aes_gcm_siv(&session_key2, &ciphertext, aad).unwrap();
    assert_eq!(decrypted.as_slice(), plaintext.as_slice());
}

#[test]
fn integration_wrong_password_cannot_decrypt() {
    let params = test_params();
    let salt = generate_random_bytes::<ARGON2_SALT_LEN>().unwrap();
    let vault_id = generate_random_bytes::<16>().unwrap();
    let session_nonce = generate_random_bytes::<SESSION_NONCE_LEN>().unwrap();

    // Encrypt with correct password
    let (pw, _) = SecretBytes::new(b"correct_password".to_vec()).unwrap();
    let (master_key, _) = derive_master_key(pw, &salt, &params).unwrap();
    let (session_key, _) = derive_session_key(master_key, &vault_id, &session_nonce).unwrap();
    let ciphertext = encrypt_aes_gcm_siv(&session_key, b"secret data", b"aad").unwrap();

    // Try to decrypt with wrong password
    let (pw_wrong, _) = SecretBytes::new(b"wrong_password".to_vec()).unwrap();
    let (master_wrong, _) = derive_master_key(pw_wrong, &salt, &params).unwrap();
    let (session_wrong, _) = derive_session_key(master_wrong, &vault_id, &session_nonce).unwrap();
    let result = decrypt_aes_gcm_siv(&session_wrong, &ciphertext, b"aad");

    assert!(
        result.is_err(),
        "Wrong password must not decrypt successfully"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Header creation, HMAC, and verification cycle
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn integration_header_create_serialize_verify() {
    let params = test_params();

    let mut header = VaultHeader::new(CipherChoice::AesGcmSiv, params).unwrap();
    let vault_id = header.vault_id;
    let salt = header.argon2_salt;

    // Derive master key and header auth key
    let (pw, _) = SecretBytes::new(b"header_test_password".to_vec()).unwrap();
    let (master_key, _) = derive_master_key(pw, &salt, &params).unwrap();
    let (header_key, _) = derive_subkey(&master_key, &vault_id, b"header-auth-key-v1").unwrap();

    // Compute and store HMAC
    header.compute_and_store_hmac(&header_key).unwrap();

    // Serialize
    let bytes = header.serialize().unwrap();
    assert_eq!(bytes.len(), HEADER_SIZE);

    // Deserialize
    let parsed = VaultHeader::deserialize(&bytes).unwrap();

    // Verify using raw bytes (correct approach)
    let (pw2, _) = SecretBytes::new(b"header_test_password".to_vec()).unwrap();
    let (master2, _) = derive_master_key(pw2, &salt, &params).unwrap();
    let (key2, _) = derive_subkey(&master2, &vault_id, b"header-auth-key-v1").unwrap();

    assert!(parsed.verify_hmac_raw(&bytes, &key2).is_ok());
}

#[test]
fn integration_tampered_header_detected() {
    let params = test_params();
    let mut header = VaultHeader::new(CipherChoice::AesGcmSiv, params).unwrap();
    let vault_id = header.vault_id;
    let salt = header.argon2_salt;

    let (pw, _) = SecretBytes::new(b"tamper_test".to_vec()).unwrap();
    let (master, _) = derive_master_key(pw, &salt, &params).unwrap();
    let (key, _) = derive_subkey(&master, &vault_id, b"header-auth-key-v1").unwrap();
    header.compute_and_store_hmac(&key).unwrap();

    let mut bytes = header.serialize().unwrap();
    // Tamper with cipher byte
    bytes[32] ^= 0x03;
    // Try to parse and verify
    match VaultHeader::deserialize(&bytes) {
        Err(_) => {} // Parse error — acceptable
        Ok(h) => {
            let (pw2, _) = SecretBytes::new(b"tamper_test".to_vec()).unwrap();
            let (m2, _) = derive_master_key(pw2, &salt, &params).unwrap();
            let (k2, _) = derive_subkey(&m2, &vault_id, b"header-auth-key-v1").unwrap();
            assert!(h.verify_hmac_raw(&bytes, &k2).is_err());
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HMAC audit chain integrity
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn integration_audit_chain_tamper_detection() {
    let (key, _) = SecretBytes::new(vec![0xAAu8; 32]).unwrap();
    let genesis = [0u8; HMAC_OUTPUT_LEN];

    let e1 = chain_hmac(&key, b"entry:VAULT_CREATED", &genesis).unwrap();
    let e2 = chain_hmac(&key, b"entry:UNLOCK_SUCCESS", &e1).unwrap();
    let e3 = chain_hmac(&key, b"entry:LOCK_SUCCESS", &e2).unwrap();

    // Verify chain forward
    assert_ne!(e1, e2);
    assert_ne!(e2, e3);

    // Verify e3 recomputes correctly
    let e3_check = chain_hmac(&key, b"entry:LOCK_SUCCESS", &e2).unwrap();
    assert_eq!(e3, e3_check);

    // Delete e2 — e3 cannot be verified with e1 as prev
    let e3_fake = chain_hmac(&key, b"entry:LOCK_SUCCESS", &e1).unwrap();
    assert_ne!(e3, e3_fake, "Deletion of e2 must be detectable");
}

// ─────────────────────────────────────────────────────────────────────────────
// Shamir recovery full cycle
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn integration_shamir_full_recovery_cycle() {
    // Create a master key
    let params = test_params();
    let salt = generate_random_bytes::<ARGON2_SALT_LEN>().unwrap();
    let (pw, _) = SecretBytes::new(b"recovery_test_password".to_vec()).unwrap();
    let (master_key, _) = derive_master_key(pw, &salt, &params).unwrap();

    // Encrypt some data with this key
    let vault_id = generate_random_bytes::<16>().unwrap();
    let nonce = generate_random_bytes::<SESSION_NONCE_LEN>().unwrap();
    let (session_key, _) = derive_session_key(master_key, &vault_id, &nonce).unwrap();
    let _ciphertext = encrypt_aes_gcm_siv(&session_key, b"protected data", b"aad").unwrap();

    // Create a fresh master key to use as the "recovery secret"
    let (pw2, _) = SecretBytes::new(b"recovery_test_password".to_vec()).unwrap();
    let (master_for_recovery, _) = derive_master_key(pw2, &salt, &params).unwrap();

    // Split into 5 shares, need 3
    let shares = split_secret(&master_for_recovery, 3, 5).unwrap();
    assert_eq!(shares.len(), 5);

    // Reconstruct from shares 1, 3, 5 (indices 0, 2, 4)
    let selected = vec![shares[0].clone(), shares[2].clone(), shares[4].clone()];
    let reconstructed = reconstruct_secret(&selected, 3).unwrap();

    // Reconstructed key must equal original
    assert_eq!(
        reconstructed.expose_secret(),
        master_for_recovery.expose_secret(),
        "Reconstructed key must equal original"
    );
}

#[test]
fn integration_shamir_insufficient_shares_cannot_recover() {
    let params = test_params();
    let salt = [0x55u8; ARGON2_SALT_LEN];
    let (pw, _) = SecretBytes::new(b"insufficient_shares_test".to_vec()).unwrap();
    let (master, _) = derive_master_key(pw, &salt, &params).unwrap();

    let shares = split_secret(&master, 3, 5).unwrap();

    // Only 2 shares — threshold is 3 — must fail
    let two_shares = vec![shares[0].clone(), shares[1].clone()];
    let result = reconstruct_secret(&two_shares, 3);
    assert!(
        result.is_err(),
        "2 shares must not reconstruct when threshold is 3"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Memory zeroing verification
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn integration_secret_bytes_zeroing() {
    let data = vec![0xFFu8; 32];
    let (mut secret, _) = SecretBytes::new(data).unwrap();

    // Verify content before zeroing
    assert!(secret.expose_secret().iter().all(|&b| b == 0xFF));

    // Explicit zero
    secret.zero_now();

    // Verify content after zeroing
    assert!(
        secret.expose_secret().iter().all(|&b| b == 0x00),
        "Secret must be all zeros after zero_now()"
    );
}

#[test]
fn integration_session_key_different_from_master_key() {
    let params = test_params();
    let salt = [0x42u8; ARGON2_SALT_LEN];
    let vault_id = [0x11u8; 16];
    let nonce = [0x22u8; SESSION_NONCE_LEN];

    let (pw1, _) = SecretBytes::new(b"master_vs_session".to_vec()).unwrap();
    let (_pw2, _) = SecretBytes::new(b"master_vs_session".to_vec()).unwrap();

    let (master, _) = derive_master_key(pw1, &salt, &params).unwrap();
    // Capture master key bytes before it is consumed
    let master_bytes: Vec<u8> = master.expose_secret().to_vec();

    let (session, _) = derive_session_key(master, &vault_id, &nonce).unwrap();

    // Session key must differ from master key
    assert_ne!(
        session.expose_secret(),
        master_bytes.as_slice(),
        "Session key must differ from master key"
    );
}
