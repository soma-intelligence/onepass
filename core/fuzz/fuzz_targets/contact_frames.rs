#![no_main]

//! Contact verification frames as a hostile peer sends them: the Hello in
//! the clear and the plaintext of a channel frame. Decoding must not panic,
//! and whatever decodes re-encodes to the same bytes.

use libfuzzer_sys::fuzz_target;
use onepass_core::contact::{ContactHello, ContactMessage};

fuzz_target!(|data: &[u8]| {
    if let Ok(hello) = ContactHello::from_bytes(data) {
        assert_eq!(hello.to_bytes().unwrap(), data);
    }
    if let Ok(msg) = ContactMessage::decode(data) {
        assert_eq!(&*msg.encode().unwrap(), data);
    }
});
