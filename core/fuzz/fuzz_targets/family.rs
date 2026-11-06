#![no_main]

//! Family bodies as a hostile zone serves them: decoding must not panic,
//! and whatever decodes re-encodes to the same bytes.

use libfuzzer_sys::fuzz_target;
use onepass_core::family::SignedFamily;

fuzz_target!(|data: &[u8]| {
    if let Ok(f) = SignedFamily::decode(data) {
        assert_eq!(f.encode(), data);
        let _ = f.body.hash();
    }
});
