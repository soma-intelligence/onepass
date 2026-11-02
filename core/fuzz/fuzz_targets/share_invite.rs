#![no_main]

//! The contact zone invite decoder, fed what a hostile server or contact
//! may drop in a contact zone: no panic, and whatever decodes re-encodes
//! to the same bytes.

use libfuzzer_sys::fuzz_target;
use onepass_core::share::InviteRecord;

fuzz_target!(|data: &[u8]| {
    if let Ok(r) = InviteRecord::decode(data) {
        assert_eq!(r.encode(), data);
        let _ = r.id();
        if let InviteRecord::Vault(i) = &r {
            let _ = i.home.host();
        }
    }
});
