#![no_main]

//! A contact book record as a hostile store serves it (sharing spec 5.4):
//! verified with a fixed account key, as `Repository::contacts` reads it.
//! The input is tried twice: as the whole record (random bytes never pass
//! the signature), and as the signed body of a record signed here, which
//! reaches the strict decoding of the entries. Nothing may panic; a body
//! that verifies re-encodes to the input and merges with itself to itself.

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use onepass_core::contact::{CONTACT_BOOK_DOMAIN, ContactEntry};
use onepass_core::crypto::{HybridSigningKey, HybridVerifyingKey};
use onepass_core::lists::{ListBody, merge, verify};

fn keys() -> &'static (HybridSigningKey, HybridVerifyingKey) {
    static K: OnceLock<(HybridSigningKey, HybridVerifyingKey)> = OnceLock::new();
    K.get_or_init(|| {
        let sk = HybridSigningKey::generate().unwrap();
        let vk = sk.verifying_key().unwrap();
        (sk, vk)
    })
}

fn check(body: ListBody<ContactEntry>, input: &[u8]) {
    assert_eq!(body.encode(), input);
    assert_eq!(merge(&body.entries, &body.entries), body.entries);
}

fuzz_target!(|data: &[u8]| {
    let (sk, vk) = keys();
    let _ = verify::<ContactEntry>(vk, CONTACT_BOOK_DOMAIN, data, None);
    let Ok(sig) = sk.sign(CONTACT_BOOK_DOMAIN, data) else {
        return;
    };
    let record = postcard::to_allocvec(&(serde_bytes::Bytes::new(data), &sig)).unwrap();
    if let Ok(body) = verify::<ContactEntry>(vk, CONTACT_BOOK_DOMAIN, &record, None) {
        check(body, data);
    }
});
