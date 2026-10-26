#![no_main]

use libfuzzer_sys::fuzz_target;
use onepass_core::manifest::Manifest;

fuzz_target!(|data: &[u8]| {
    let _ = postcard::from_bytes::<Manifest>(data);
});
