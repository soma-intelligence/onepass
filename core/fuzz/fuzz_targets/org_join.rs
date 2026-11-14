#![no_main]

//! Org join requests as a hostile joiner or org mailbox serves them:
//! decoding must not panic, and whatever decodes re-encodes to the same
//! bytes.

use libfuzzer_sys::fuzz_target;
use onepass_core::org::SignedJoinRequest;

fuzz_target!(|data: &[u8]| {
    if let Ok(req) = SignedJoinRequest::decode(data) {
        assert_eq!(req.encode(), data);
        req.body.check().expect("decoded join request passes check");
    }
});
