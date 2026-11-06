#![no_main]

//! `MemberKey` envelopes as a hostile zone serves them: decoding must not
//! panic, and whatever decodes re-encodes to the same bytes.

use libfuzzer_sys::fuzz_target;
use onepass_core::share::MemberKey;

fuzz_target!(|data: &[u8]| {
    if let Ok(mk) = MemberKey::decode(data) {
        assert_eq!(mk.encode(), data);
        let _ = mk.id();
    }
});
