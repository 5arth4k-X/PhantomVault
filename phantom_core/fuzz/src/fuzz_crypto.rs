#![no_main]
use libfuzzer_sys::fuzz_target;
use phantom_core::memory::SecretBytes;
use phantom_core::crypto::{
    encrypt_aes_gcm_siv, decrypt_aes_gcm_siv,
    Argon2Params, derive_master_key, KEY_LEN,
};

fuzz_target!(|data: &[u8]| {
    if data.len() < KEY_LEN + 16 + 1 {
        return;
    }

    let key_bytes = data[..KEY_LEN].to_vec();
    let aad = &data[KEY_LEN..KEY_LEN + 16];
    let plaintext = &data[KEY_LEN + 16..];

    let Ok((key, _)) = SecretBytes::new(key_bytes) else { return };

    // Fuzz encrypt + decrypt round-trip
    if let Ok(ciphertext) = encrypt_aes_gcm_siv(&key, plaintext, aad) {
        let _ = decrypt_aes_gcm_siv(&key, &ciphertext, aad);
        // Tamper with ciphertext — decrypt should fail, not panic
        if !ciphertext.is_empty() {
            let mut tampered = ciphertext.clone();
            tampered[0] ^= 0xFF;
            let _ = decrypt_aes_gcm_siv(&key, &tampered, aad);
        }
    }

    // Fuzz decrypt with random bytes as ciphertext — must not panic
    let _ = decrypt_aes_gcm_siv(&key, data, aad);
});
