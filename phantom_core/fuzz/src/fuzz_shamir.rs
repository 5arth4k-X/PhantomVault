#![no_main]
use libfuzzer_sys::fuzz_target;
use phantom_core::shamir::{ShamirShare, reconstruct_secret, SECRET_LEN};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // Use first byte to determine threshold
    let threshold = (data[0] % 9) + 2; // 2..10
    let rest = &data[1..];

    if rest.len() < 33 {
        return;
    }

    // Split rest into 33-byte share chunks
    let shares: Vec<ShamirShare> = rest
        .chunks(33)
        .take(10)
        .map(|chunk| {
            let mut padded = vec![0u8; 33];
            padded[..chunk.len().min(33)].copy_from_slice(&chunk[..chunk.len().min(33)]);
            ShamirShare::from_bytes(padded)
        })
        .collect();

    if shares.is_empty() {
        return;
    }

    // Must not panic regardless of share content
    let _ = reconstruct_secret(&shares, threshold);
});
