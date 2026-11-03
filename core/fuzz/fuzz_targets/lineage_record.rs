#![no_main]

//! Lineage records as a hostile store or peer serves them: decoding must
//! not panic, and whatever decodes re-encodes to the same bytes. Wipe
//! orders share the lineage rows: a buffer never decodes as both.

use libfuzzer_sys::fuzz_target;
use onepass_core::lineage::wipe::SignedWipe;
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
    if let Ok(order) = SignedWipe::decode(data) {
        assert_eq!(order.encode(), data);
        assert!(LineageRecord::decode(data).is_err());
        let _ = order.record_id();
    }
});
