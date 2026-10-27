#![no_main]

use libfuzzer_sys::fuzz_target;
use onepass_core::reference::parse_ref;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = parse_ref(s);
    }
});
