#![no_main]

//! Contact verification frames as a hostile peer sends them: the Hello in
//! the clear and the plaintext of a channel frame; and the remote
//! invitation as a hostile rendezvous or link sender serves it: the link,
//! the reply plaintext and the answer. Decoding must not panic, and
//! whatever decodes re-encodes to the same bytes.

use libfuzzer_sys::fuzz_target;
use onepass_core::contact::{
    ContactHello, ContactInvite, ContactMessage, InviteAnswer, InviteReply,
};

fuzz_target!(|data: &[u8]| {
    if let Ok(hello) = ContactHello::from_bytes(data) {
        assert_eq!(hello.to_bytes().unwrap(), data);
    }
    if let Ok(msg) = ContactMessage::decode(data) {
        assert_eq!(&*msg.encode().unwrap(), data);
    }
    if let Ok(reply) = InviteReply::decode(data) {
        assert_eq!(&*reply.encode().unwrap(), data);
    }
    if let Ok(answer) = InviteAnswer::decode(data) {
        assert_eq!(answer.encode().unwrap(), data);
    }
    if let Ok(s) = std::str::from_utf8(data)
        && let Ok(invite) = ContactInvite::parse_link(s)
    {
        assert_eq!(invite.link(), s);
    }
});
