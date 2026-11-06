//! Invite drops (sharing spec 13.9, remote invitation of 5.3.2): four
//! write-once slots of 64 KiB under a random 16 byte id that only the two
//! sides of an invitation know, open 72 hours from the first write. No
//! signature: the id is the only key, like the rendezvous.
//!
//! The bytes are opaque here: the sharing layer seals them end to end. A
//! hostile server can withhold, delay or drop a slot, never forge one the
//! sealed layer accepts.

use crate::MailboxError;
use crate::client::expect;
use crate::http::{self, Endpoint, Http, Method};

/// Slots of a drop, numbered 0 to 3.
pub const DROP_SLOTS: u8 = 4;
/// Largest slot, bytes.
pub const DROP_MAX: usize = 64 * 1024;
/// A drop stays open this long after its first write.
pub const DROP_LIFE_SECS: u64 = 72 * 3600;

/// The local checks of a write, before anything is sent.
pub(crate) fn check_put(slot: u8, bytes: &[u8]) -> Result<(), MailboxError> {
    check_slot(slot)?;
    if bytes.len() > DROP_MAX {
        return Err(MailboxError::TooLarge);
    }
    Ok(())
}

pub(crate) fn check_slot(slot: u8) -> Result<(), MailboxError> {
    if slot >= DROP_SLOTS {
        return Err(MailboxError::Malformed("drop slot"));
    }
    Ok(())
}

fn url(endpoint: &Endpoint, id: [u8; 16]) -> Result<String, MailboxError> {
    Ok(format!(
        "{}/v1/drops/{}",
        http::base_url(endpoint)?,
        onepass_mailbox_proto::hex(&id)
    ))
}

/// `PUT /v1/drops/{d}/{slot}`. `Conflict` when the slot was already
/// written (by anyone: the first write wins), `Server(NotFound)` once the
/// drop expired or was deleted.
pub fn drop_put(
    endpoint: &Endpoint,
    id: [u8; 16],
    slot: u8,
    bytes: &[u8],
) -> Result<(), MailboxError> {
    check_put(slot, bytes)?;
    let http = Http::new(endpoint)?;
    let headers = [("content-type", "application/octet-stream".to_string())];
    let r = http.send(
        Method::Put,
        &format!("{}/{slot}", url(endpoint, id)?),
        &headers,
        bytes,
        64 * 1024,
    )?;
    if r.status == 409 {
        return Err(MailboxError::Conflict);
    }
    let r = expect(r, &[204])?;
    if !r.body.is_empty() {
        return Err(MailboxError::Malformed("body on 204"));
    }
    Ok(())
}

/// `GET /v1/drops/{d}/{slot}`: the slot's bytes, `None` when there is
/// nothing to read (never written, expired or deleted).
pub fn drop_get(
    endpoint: &Endpoint,
    id: [u8; 16],
    slot: u8,
) -> Result<Option<Vec<u8>>, MailboxError> {
    check_slot(slot)?;
    let http = Http::new(endpoint)?;
    // One byte of slack: ureq refuses a body that reaches its limit.
    let r = http.send(
        Method::Get,
        &format!("{}/{slot}", url(endpoint, id)?),
        &[],
        &[],
        DROP_MAX as u64 + 1,
    )?;
    let r = expect(r, &[200, 204])?;
    if r.status == 204 {
        if !r.body.is_empty() {
            return Err(MailboxError::Malformed("body on 204"));
        }
        return Ok(None);
    }
    let octets = r
        .content_type
        .as_deref()
        .is_some_and(|t| t.trim().eq_ignore_ascii_case("application/octet-stream"));
    if !octets {
        return Err(MailboxError::Malformed("content type"));
    }
    if r.body.len() > DROP_MAX {
        return Err(MailboxError::Malformed("drop size"));
    }
    Ok(Some(r.body))
}

/// `DELETE /v1/drops/{d}`: closes the drop for good, whatever it held.
pub fn drop_delete(endpoint: &Endpoint, id: [u8; 16]) -> Result<(), MailboxError> {
    let http = Http::new(endpoint)?;
    let r = http.send(Method::Delete, &url(endpoint, id)?, &[], &[], 64 * 1024)?;
    let r = expect(r, &[204])?;
    if !r.body.is_empty() {
        return Err(MailboxError::Malformed("body on 204"));
    }
    Ok(())
}

// ---- invitation blobs over several slots ----------------------------------------

/// Which half of a remote invitation a blob is: the invitee's reply or
/// the inviter's answer. Each has a drop of its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvitePart {
    Reply,
    Answer,
}

/// Bytes of the header of slot 0: the slot count, then the blob length
/// (big-endian u32).
const INVITE_HEADER: usize = 5;
/// Largest invitation blob a drop carries: its four slots, less the header.
pub const INVITE_DROP_MAX: usize = DROP_SLOTS as usize * DROP_MAX - INVITE_HEADER;

/// The drop of one half of the invitation at rendezvous `rdv`:
/// `SHA-256("onepass/invite-drop/v1" || rdv || part)[..16]`. A sealed
/// reply holds a contact card (two identity signatures and the device
/// keys): above one 64 KiB slot, so each half spreads over the slots of a
/// drop of its own.
pub fn invite_drop_id(rdv: [u8; 16], part: InvitePart) -> [u8; 16] {
    let mut ctx = aws_lc_rs::digest::Context::new(&aws_lc_rs::digest::SHA256);
    ctx.update(b"onepass/invite-drop/v1");
    ctx.update(&rdv);
    ctx.update(&[match part {
        InvitePart::Reply => 0,
        InvitePart::Answer => 1,
    }]);
    let mut out = [0u8; 16];
    out.copy_from_slice(&ctx.finish().as_ref()[..16]);
    out
}

/// The slots of `bytes`: slot 0 opens with the header.
fn split_invite(bytes: &[u8]) -> Result<Vec<Vec<u8>>, MailboxError> {
    if bytes.len() > INVITE_DROP_MAX {
        return Err(MailboxError::TooLarge);
    }
    let first = bytes.len().min(DROP_MAX - INVITE_HEADER);
    let rest: Vec<&[u8]> = bytes[first..].chunks(DROP_MAX).collect();
    let count = u8::try_from(1 + rest.len()).map_err(|_| MailboxError::TooLarge)?;
    let len = u32::try_from(bytes.len()).map_err(|_| MailboxError::TooLarge)?;
    let mut slot0 = Vec::with_capacity(INVITE_HEADER + first);
    slot0.push(count);
    slot0.extend_from_slice(&len.to_be_bytes());
    slot0.extend_from_slice(&bytes[..first]);
    let mut out = vec![slot0];
    out.extend(rest.into_iter().map(<[u8]>::to_vec));
    Ok(out)
}

/// The header of slot 0: the slot count and the blob length, checked.
fn invite_header(slot0: &[u8]) -> Result<(u8, usize), MailboxError> {
    let bad = MailboxError::Malformed("invite drop");
    if slot0.len() < INVITE_HEADER {
        return Err(bad);
    }
    let count = slot0[0];
    let len = u32::from_be_bytes([slot0[1], slot0[2], slot0[3], slot0[4]]) as usize;
    if count == 0 || count > DROP_SLOTS || len > INVITE_DROP_MAX {
        return Err(bad);
    }
    Ok((count, len))
}

/// Write one half of an invitation. The other slots first, slot 0 last:
/// a reader that finds slot 0 finds the whole blob. A retry after a
/// partial write passes over the slots that hold these same bytes; a slot
/// that holds others is `Conflict`.
pub fn invite_put(
    endpoint: &Endpoint,
    rdv: [u8; 16],
    part: InvitePart,
    bytes: &[u8],
) -> Result<(), MailboxError> {
    let id = invite_drop_id(rdv, part);
    let slots = split_invite(bytes)?;
    let order = (1..slots.len()).chain(std::iter::once(0));
    for i in order {
        let slot = u8::try_from(i).map_err(|_| MailboxError::TooLarge)?;
        match drop_put(endpoint, id, slot, &slots[i]) {
            Ok(()) => {}
            Err(MailboxError::Conflict) => {
                if drop_get(endpoint, id, slot)?.as_deref() != Some(&slots[i][..]) {
                    return Err(MailboxError::Conflict);
                }
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Read one half of an invitation: `None` until slot 0 is there. A slot 0
/// whose other slots are missing, or whose length does not match, is
/// `Malformed("invite drop")` (the sealed layer would refuse it anyway).
pub fn invite_get(
    endpoint: &Endpoint,
    rdv: [u8; 16],
    part: InvitePart,
) -> Result<Option<Vec<u8>>, MailboxError> {
    let id = invite_drop_id(rdv, part);
    let Some(slot0) = drop_get(endpoint, id, 0)? else {
        return Ok(None);
    };
    let (count, len) = invite_header(&slot0)?;
    let mut out = slot0[INVITE_HEADER..].to_vec();
    for slot in 1..count {
        let part = drop_get(endpoint, id, slot)?.ok_or(MailboxError::Malformed("invite drop"))?;
        out.extend_from_slice(&part);
    }
    if out.len() != len {
        return Err(MailboxError::Malformed("invite drop"));
    }
    Ok(Some(out))
}

/// Close the drop of one half of an invitation.
pub fn invite_delete(
    endpoint: &Endpoint,
    rdv: [u8; 16],
    part: InvitePart,
) -> Result<(), MailboxError> {
    drop_delete(endpoint, invite_drop_id(rdv, part))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invite_blobs_split_and_join() {
        for len in [
            0,
            1,
            DROP_MAX - INVITE_HEADER,
            DROP_MAX,
            131_138,
            INVITE_DROP_MAX,
        ] {
            let bytes: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let slots = split_invite(&bytes).unwrap();
            assert!(slots.iter().all(|s| s.len() <= DROP_MAX), "{len}");
            let (count, got_len) = invite_header(&slots[0]).unwrap();
            assert_eq!((usize::from(count), got_len), (slots.len(), len));
            let joined: Vec<u8> = std::iter::once(&slots[0][INVITE_HEADER..])
                .chain(slots[1..].iter().map(Vec::as_slice))
                .flatten()
                .copied()
                .collect();
            assert_eq!(joined, bytes);
        }
        assert_eq!(
            split_invite(&vec![0; INVITE_DROP_MAX + 1]),
            Err(MailboxError::TooLarge)
        );
        assert!(invite_header(&[0, 0, 0, 0, 0]).is_err());
        assert!(invite_header(&[5, 0, 0, 0, 0]).is_err());
        assert!(invite_header(&[1, 0]).is_err());
        assert_ne!(
            invite_drop_id([1; 16], InvitePart::Reply),
            invite_drop_id([1; 16], InvitePart::Answer)
        );
    }

    fn nowhere() -> Endpoint {
        // Never reached: every case below is refused before the network.
        Endpoint {
            base_url: "https://mailbox.invalid/functions/v1/mailbox".into(),
            extra_ca_pem: None,
        }
    }

    #[test]
    fn slot_out_of_range_refused_locally() {
        assert_eq!(
            drop_put(&nowhere(), [1; 16], 4, b"x"),
            Err(MailboxError::Malformed("drop slot"))
        );
        assert_eq!(
            drop_get(&nowhere(), [1; 16], 200),
            Err(MailboxError::Malformed("drop slot"))
        );
    }

    #[test]
    fn oversized_slot_refused_locally() {
        assert_eq!(
            drop_put(&nowhere(), [1; 16], 0, &vec![0; DROP_MAX + 1]),
            Err(MailboxError::TooLarge)
        );
        assert!(check_put(3, &vec![0; DROP_MAX]).is_ok());
    }
}
