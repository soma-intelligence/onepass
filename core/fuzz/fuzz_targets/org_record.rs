#![no_main]

//! Org lineage records as a hostile org mailbox serves them: decoding must
//! not panic, whatever decodes re-encodes to the same bytes, and its hash
//! and generation are computable.

use libfuzzer_sys::fuzz_target;
use onepass_core::org::SignedOrgRecord;

fuzz_target!(|data: &[u8]| {
    if let Ok(rec) = SignedOrgRecord::decode(data) {
        assert_eq!(rec.encode(), data);
        let _ = rec.hash();
        let _ = rec.generation();
        let _ = rec.org_id();
    }
});
