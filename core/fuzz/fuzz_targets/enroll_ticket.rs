#![no_main]

//! Hostile enroll bodies: no panic, whatever decodes re-encodes to exactly
//! the input, and the ticket helpers run on it without panicking.

use libfuzzer_sys::fuzz_target;
use onepass_mailbox_proto::*;

fuzz_target!(|data: &[u8]| {
    if let Ok(e) = decode::<Enroll>(data) {
        assert_eq!(encode(&e), data);
        let signed = ticket_signed_bytes(&e.ticket.ticket);
        assert!(signed.starts_with(ENROLL_DOMAIN));
        let _ = ticket_hash(&e.ticket);
        let now = e.ticket.ticket.expires_at.wrapping_sub(i64::from(data[0]));
        let _ = check_ticket_times(&e.ticket.ticket, now);
        let _ = check_ticket_times(&e.ticket.ticket, i64::MIN);
        let _ = check_ticket_times(&e.ticket.ticket, i64::MAX);
    }
});
