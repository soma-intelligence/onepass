#![no_main]

//! A kind 32 body and record id as a hostile org mailbox serves them: parsing
//! must not panic, and a frame it keeps is one whose prefix derives the
//! record id.

use libfuzzer_sys::fuzz_target;
use onepass_mailbox::org::{join_record_id, parse_join_frame};

fuzz_target!(|data: &[u8]| {
    let Some((org_id, rest)) = data.split_first_chunk::<16>() else {
        return;
    };
    let Some((record_id, body)) = rest.split_first_chunk::<16>() else {
        return;
    };
    if let Some((acc, request)) = parse_join_frame(org_id, record_id, body) {
        assert_eq!(join_record_id(org_id, &acc), *record_id);
        assert_eq!(request, &body[16..]);
    }
    if let Some((prefix, _)) = body.split_first_chunk::<16>() {
        let derived = join_record_id(org_id, prefix);
        assert!(parse_join_frame(org_id, &derived, body).is_some());
    }
});
