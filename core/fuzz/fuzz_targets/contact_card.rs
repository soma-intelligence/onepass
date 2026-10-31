#![no_main]

//! Contact cards as a peer, a link or a hostile store serves them: decoding
//! must not panic, and whatever decodes re-encodes to the same bytes.

use libfuzzer_sys::fuzz_target;
use onepass_core::contact::SignedContactCard;

fuzz_target!(|data: &[u8]| {
    if let Ok(card) = SignedContactCard::decode(data) {
        assert_eq!(card.encode(), data);
        let _ = card.keys();
    }
});
