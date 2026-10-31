#![no_main]

//! Lineage records as a hostile store or peer serves them: decoding must
//! not panic, and whatever decodes re-encodes to the same bytes.

use libfuzzer_sys::fuzz_target;
use onepass_core::lineage::{LineageRecord, SignedIntro, SignedLegacyIntro};

fuzz_target!(|data: &[u8]| {
    if let Ok(record) = LineageRecord::decode(data) {
        assert_eq!(record.encode(), data);
        let _ = record.hash();
        let _ = record.record_id();
    }
    if let Ok(intro) = SignedIntro::decode(data) {
        assert_eq!(intro.encode(), data);
    }
    if let Ok(intro) = SignedLegacyIntro::decode(data) {
        assert_eq!(intro.encode(), data);
    }
});
