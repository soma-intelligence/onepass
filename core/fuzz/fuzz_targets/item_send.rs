#![no_main]

//! Item sends as a hostile contact zone serves them: decoding must not
//! panic, and whatever decodes re-encodes to the same bytes.

use libfuzzer_sys::fuzz_target;
use onepass_core::send::ItemSend;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = ItemSend::decode(data) {
        assert_eq!(s.encode(), data);
    }
});
