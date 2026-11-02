#![no_main]

//! The zone access, zone home and contact zone offer decoders, fed what a
//! hostile store or peer may serve: no panic, and whatever decodes
//! re-encodes to the same bytes.

use libfuzzer_sys::fuzz_target;
use onepass_core::share::{SignedContactZoneOffer, SignedZoneAccess, ZoneHome};

fuzz_target!(|data: &[u8]| {
    if let Ok(a) = SignedZoneAccess::decode(data) {
        assert_eq!(a.encode(), data);
        let _ = a.access.target.record_id();
    }
    if let Ok(h) = ZoneHome::decode(data) {
        assert_eq!(h.encode(), data);
        let _ = h.host();
    }
    if let Ok(o) = SignedContactZoneOffer::decode(data) {
        assert_eq!(o.encode(), data);
    }
});
