#![no_main]

//! A mailbox enroll request as the frozen iCloud zone serves it
//! (cross-platform spec D.5): strict decoding of the whole record, and of
//! a body signed here with a fixed device key (random bytes never pass the
//! signature). Nothing may panic; a record that decodes re-encodes to the
//! input, and a signed body verifies under its domain only.

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use onepass_core::Id;
use onepass_core::device_keys::{DEVICE_POP_DOMAIN, DeviceKeys, DevicePublic};
use onepass_core::enroll_request::{ENROLL_REQUEST_DOMAIN, SignedEnrollRequest};

fn keys() -> &'static (DeviceKeys, DevicePublic) {
    static K: OnceLock<(DeviceKeys, DevicePublic)> = OnceLock::new();
    K.get_or_init(|| {
        let keys = DeviceKeys::generate_software().unwrap();
        let public = keys.public(Id([1; 16])).unwrap();
        (keys, public)
    })
}

fuzz_target!(|data: &[u8]| {
    let (keys, public) = keys();
    if let Ok(signed) = SignedEnrollRequest::decode(data) {
        assert_eq!(signed.encode(), data);
    }
    let Ok(sig) = keys.sign(ENROLL_REQUEST_DOMAIN, data) else {
        return;
    };
    let record = postcard::to_allocvec(&(serde_bytes::Bytes::new(data), &sig)).unwrap();
    let Ok(signed) = SignedEnrollRequest::decode(&record) else {
        return;
    };
    assert_eq!(signed.body.encode(), data);
    let body = signed.body.encode();
    assert!(
        public
            .sign_pub
            .verify(ENROLL_REQUEST_DOMAIN, &body, &signed.sig)
            .is_ok()
    );
    assert!(
        public
            .sign_pub
            .verify(DEVICE_POP_DOMAIN, &body, &signed.sig)
            .is_err()
    );
});
