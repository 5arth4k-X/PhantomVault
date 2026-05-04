#![no_main]
use libfuzzer_sys::fuzz_target;
use phantom_core::header::{VaultHeader, HEADER_SIZE};

fuzz_target!(|data: &[u8]| {
    // Feed arbitrary bytes as vault header — must not panic,
    // must return a proper error for invalid input.
    let _ = VaultHeader::deserialize(data);

    // If data is exactly HEADER_SIZE, try parsing it
    if data.len() == HEADER_SIZE {
        match VaultHeader::deserialize(data) {
            Ok(header) => {
                // If parsing succeeded, serialization must also succeed
                let _ = header.serialize();
            }
            Err(_) => {
                // Parse errors are expected and correct
            }
        }
    }
});
