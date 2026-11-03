#![no_main]

//! Recovery messages and halves as a hostile server serves them: decoding
//! must not panic, and whatever decodes re-encodes to the same bytes.

use libfuzzer_sys::fuzz_target;
use onepass_core::recovery::RecoveryHalf;
use onepass_core::recovery::messages::RecoveryMessage;

fuzz_target!(|data: &[u8]| {
    if let Ok(m) = RecoveryMessage::decode(data) {
        assert_eq!(m.encode(), data);
    }
    if let Ok(h) = RecoveryHalf::decode(data) {
        assert_eq!(&h.encode()[..], data);
    }
});
