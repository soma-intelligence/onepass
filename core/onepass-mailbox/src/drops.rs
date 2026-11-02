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

#[cfg(test)]
mod tests {
    use super::*;

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
