#![no_main]

//! Signed org rosters as a hostile org mailbox serves them: decoding must
//! not panic, whatever decodes passes the shape rules and re-encodes to the
//! same bytes, and merging its members with themselves is the identity.

use libfuzzer_sys::fuzz_target;
use onepass_core::org::{SignedRoster, merge_members};

fuzz_target!(|data: &[u8]| {
    if let Ok(r) = SignedRoster::decode(data) {
        assert_eq!(r.encode(), data);
        let b = &r.body;
        b.check().expect("decoded roster passes check");
        let _ = b.hash();
        let m = &b.members;
        let merged = merge_members(m, m, m).expect("self merge");
        assert_eq!(&merged, m);
    }
});
