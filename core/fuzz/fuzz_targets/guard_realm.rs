#![no_main]

//! Guarded Kit messages as a hostile network sends them: a realm answering
//! arbitrary request bytes (it must always sign a refusal, never panic),
//! a client opening arbitrary response bytes against a request, and the
//! guard descriptor a hostile store serves.

use std::sync::{Mutex, OnceLock};

use libfuzzer_sys::fuzz_target;
use onepass_core::guarded_kit::GuardDescriptor;
use onepass_core::guarded_kit::realm::{DEFAULT_LIMIT, MemoryRealmStore, Realm};
use onepass_core::guarded_kit::wire::{decode_request, open_response};

fn realm() -> &'static Mutex<Realm<MemoryRealmStore>> {
    static R: OnceLock<Mutex<Realm<MemoryRealmStore>>> = OnceLock::new();
    R.get_or_init(|| {
        Mutex::new(Realm::new(
            [7; 32],
            DEFAULT_LIMIT,
            MemoryRealmStore::default(),
        ))
    })
}

fuzz_target!(|data: &[u8]| {
    let _ = decode_request(data);
    let _ = GuardDescriptor::decode(data);
    let mut r = realm().lock().unwrap();
    let key = r.response_key().unwrap();
    // A realm signs an answer to anything it is sent.
    let resp = r.handle(data, 1_800_000_000).unwrap();
    assert!(open_response(&resp, data, &key).is_ok());
    // A response the client did not ask for, or forged, never opens.
    let _ = open_response(data, b"OPGRQ01", &key);
    if r.store().len() > 10_000 {
        r.store_mut().clear();
    }
});
