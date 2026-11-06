#![no_main]

//! `SharedSignedManifest` records as a hostile zone serves them: decoding
//! must not panic, and whatever decodes re-encodes to the same bytes.

use libfuzzer_sys::fuzz_target;
use onepass_core::share::SharedSignedManifest;

fuzz_target!(|data: &[u8]| {
    if let Ok(sm) = SharedSignedManifest::decode(data) {
        assert_eq!(sm.encode(), data);
    }
});
