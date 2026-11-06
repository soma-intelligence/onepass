#![no_main]

//! Signed membership bodies as a hostile zone serves them: decoding must not
//! panic, whatever decodes passes the shape rules and re-encodes to the same
//! bytes, and merging it with itself is the identity.

use libfuzzer_sys::fuzz_target;
use onepass_core::share::{SignedMembership, merge_concurrent};

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = SignedMembership::decode(data) {
        assert_eq!(s.encode(), data);
        let b = &s.body;
        let _ = b.hash();
        let merged = merge_concurrent(b, b, b).expect("self merge");
        assert_eq!(merged, b.members);
    }
});
