#![no_main]

//! The rekey request decoder, fed what any member or a hostile server may
//! write in a vault zone: no panic, and whatever decodes re-encodes to the
//! same bytes.

use libfuzzer_sys::fuzz_target;
use onepass_core::share::RekeyRequest;

fuzz_target!(|data: &[u8]| {
    if let Ok(r) = RekeyRequest::decode(data) {
        assert_eq!(r.encode(), data);
        let _ = r.id();
    }
});
