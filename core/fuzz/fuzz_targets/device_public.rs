#![no_main]

//! A device public key as a hostile store or peer serves it: decoding must
//! not panic, and whatever decodes re-encodes to the same bytes.

use libfuzzer_sys::fuzz_target;
use onepass_core::device_keys::DevicePublic;

fuzz_target!(|data: &[u8]| {
    if let Ok(public) = DevicePublic::decode(data) {
        assert_eq!(public.encode(), data);
        let _ = public.fingerprint();
    }
});
