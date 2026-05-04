#![no_main]
use libfuzzer_sys::fuzz_target;
use phantom_core::memory::SecretBytes;
use phantom_core::hmac::{compute_hmac, verify_hmac_ct, chain_hmac, HMAC_OUTPUT_LEN};

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 + 1 {
        return;
    }

    let key_bytes = data[..32].to_vec();
    let content = &data[32..];

    let Ok((key, _)) = SecretBytes::new(key_bytes) else { return };

    // Fuzz compute_hmac
    if let Ok(hmac) = compute_hmac(&key, content) {
        // verify with correct data must succeed
        let _ = verify_hmac_ct(&key, content, &hmac);

        // verify with tampered data must fail, not panic
        if !content.is_empty() {
            let mut tampered = content.to_vec();
            tampered[0] ^= 0xFF;
            let _ = verify_hmac_ct(&key, &tampered, &hmac);
        }

        // Fuzz chain_hmac with arbitrary prev_hmac
        let prev = [0u8; HMAC_OUTPUT_LEN];
        let _ = chain_hmac(&key, content, &prev);
    }

    // Fuzz with empty data — must return EmptyData error, not panic
    let _ = compute_hmac(&key, b"");
});
