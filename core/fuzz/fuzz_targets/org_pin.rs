#![no_main]

//! Stored org pins as a corrupted or hostile local store holds them:
//! decoding must not panic, and whatever decodes re-encodes to the same
//! bytes.

use libfuzzer_sys::fuzz_target;
use onepass_core::org::OrgPin;

fuzz_target!(|data: &[u8]| {
    if let Ok(pin) = OrgPin::decode(data) {
        assert_eq!(pin.encode(), data);
        let _ = pin.fingerprint();
        let _ = pin.head();
        let _ = pin.roster_seq();
    }
});
