//! Enroll ticket (spec 4.12): an enrolled credential lets a new device's
//! credential into the same mailbox, once, within ten minutes.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256 as Sha256Hasher};

use crate::messages::{CredentialId, LABEL_MAX, MailboxId, Message, ProtoError, Sha256, URL_MAX};
use crate::sig::{CredentialPublicKey, CredentialSignature, SKEW_SECS};

pub const ENROLL_DOMAIN: &[u8] = b"onepass/mailbox-enroll/v1";
pub const TICKET_TTL_MAX_SECS: i64 = 600;
pub const TICKET_VERSION: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollTicket {
    pub version: u8,
    pub mailbox_url: String,
    #[serde(with = "crate::bytes::fixed")]
    pub mailbox_id: MailboxId,
    #[serde(with = "crate::bytes::fixed")]
    pub new_credential_pub: CredentialPublicKey,
    pub expires_at: i64,
    #[serde(with = "crate::bytes::fixed")]
    pub nonce: [u8; 16],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedEnrollTicket {
    pub ticket: EnrollTicket,
    #[serde(with = "crate::bytes::fixed")]
    pub approver_credential: CredentialId,
    #[serde(with = "crate::bytes::fixed")]
    pub sig: CredentialSignature,
}

/// Body of `POST /v1/mailboxes/{m}/credentials`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Enroll {
    pub ticket: SignedEnrollTicket,
    #[serde(with = "crate::bytes::vec")]
    pub label: Vec<u8>,
}

impl EnrollTicket {
    /// Version and URL cap. The times are checked by `check_ticket_times`,
    /// which needs the clock.
    pub fn check(&self) -> Result<(), ProtoError> {
        if self.version != TICKET_VERSION {
            return Err(ProtoError::Format("ticket version"));
        }
        if self.mailbox_url.len() > URL_MAX {
            return Err(ProtoError::TooLarge("url"));
        }
        Ok(())
    }
}

/// The encoding a pairing grant carries (`FullGrantV2::enroll`): the
/// newcomer decodes it strictly before it calls the server.
impl Message for SignedEnrollTicket {
    fn check(&self) -> Result<(), ProtoError> {
        self.ticket.check()
    }
}

impl Message for Enroll {
    fn check(&self) -> Result<(), ProtoError> {
        self.ticket.ticket.check()?;
        if self.label.len() > LABEL_MAX {
            return Err(ProtoError::TooLarge("label"));
        }
        Ok(())
    }
}

/// What the approver signs: `ENROLL_DOMAIN || postcard(ticket)`.
pub fn ticket_signed_bytes(t: &EnrollTicket) -> Vec<u8> {
    let mut out = ENROLL_DOMAIN.to_vec();
    out.extend(postcard::to_allocvec(t).expect("postcard to a Vec cannot fail"));
    out
}

/// SHA-256 of the whole signed ticket, signature included: the key of the
/// server's `used_tickets`.
pub fn ticket_hash(t: &SignedEnrollTicket) -> Sha256 {
    Sha256Hasher::digest(postcard::to_allocvec(t).expect("postcard to a Vec cannot fail")).into()
}

/// `now <= expires_at <= now + TICKET_TTL_MAX_SECS + SKEW_SECS` (spec 4.12:
/// 600 s of life on the approver's clock, which may run 300 s ahead; the
/// server refuses more than 900 s). When the ticket was made is the
/// approver's call; only the deadline is checked.
pub fn check_ticket_times(t: &EnrollTicket, now: i64) -> Result<(), ProtoError> {
    if t.expires_at < now {
        return Err(ProtoError::Ticket("expired"));
    }
    if i128::from(t.expires_at)
        > i128::from(now) + i128::from(TICKET_TTL_MAX_SECS) + i128::from(SKEW_SECS)
    {
        return Err(ProtoError::Ticket("lifetime"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{decode, encode};

    const NOW: i64 = 1_793_404_800;

    fn ticket() -> EnrollTicket {
        EnrollTicket {
            version: 1,
            mailbox_url: "https://example.invalid/functions/v1/mailbox".into(),
            mailbox_id: [1; 16],
            new_credential_pub: [2; 32],
            expires_at: NOW + 600,
            nonce: [3; 16],
        }
    }

    fn enroll(t: EnrollTicket) -> Enroll {
        Enroll {
            ticket: SignedEnrollTicket {
                ticket: t,
                approver_credential: [4; 16],
                sig: [5; 64],
            },
            label: b"laptop".to_vec(),
        }
    }

    #[test]
    fn ticket_round_trip_and_caps() {
        let e = enroll(ticket());
        assert_eq!(decode::<Enroll>(&encode(&e)).unwrap(), e);

        let url = |n| {
            enroll(EnrollTicket {
                mailbox_url: "u".repeat(n),
                ..ticket()
            })
        };
        assert!(decode::<Enroll>(&encode(&url(URL_MAX))).is_ok());
        assert_eq!(
            decode::<Enroll>(&encode(&url(URL_MAX + 1))),
            Err(ProtoError::TooLarge("url"))
        );
        let v2 = enroll(EnrollTicket {
            version: 2,
            ..ticket()
        });
        assert_eq!(
            decode::<Enroll>(&encode(&v2)),
            Err(ProtoError::Format("ticket version"))
        );
        let mut long_label = enroll(ticket());
        long_label.label = vec![b'a'; LABEL_MAX + 1];
        assert_eq!(
            decode::<Enroll>(&encode(&long_label)),
            Err(ProtoError::TooLarge("label"))
        );

        let t = ticket();
        assert_eq!(check_ticket_times(&t, NOW), Ok(()));
        assert_eq!(check_ticket_times(&t, NOW + 600), Ok(()));
        assert_eq!(
            check_ticket_times(&t, NOW + 601),
            Err(ProtoError::Ticket("expired"))
        );
        // 600 s of life plus 300 s of approver skew, never more.
        assert_eq!(check_ticket_times(&t, NOW - 300), Ok(()));
        assert_eq!(
            check_ticket_times(&t, NOW - 301),
            Err(ProtoError::Ticket("lifetime"))
        );
        let far = EnrollTicket {
            expires_at: i64::MAX,
            ..ticket()
        };
        assert!(check_ticket_times(&far, i64::MAX - 1).is_ok());
        assert_eq!(
            check_ticket_times(&far, i64::MIN),
            Err(ProtoError::Ticket("lifetime"))
        );
    }

    #[test]
    fn signed_bytes_are_domain_then_postcard() {
        let t = ticket();
        let b = ticket_signed_bytes(&t);
        assert!(b.starts_with(ENROLL_DOMAIN));
        assert_eq!(
            &b[ENROLL_DOMAIN.len()..],
            postcard::to_allocvec(&t).unwrap()
        );
        // version, url length, then the url itself.
        assert_eq!(b[ENROLL_DOMAIN.len()], 1);
        assert_eq!(b[ENROLL_DOMAIN.len() + 1] as usize, t.mailbox_url.len());
    }

    #[test]
    fn ticket_hash_covers_signature() {
        let a = enroll(ticket()).ticket;
        let mut b = a.clone();
        b.sig[63] ^= 1;
        assert_ne!(ticket_hash(&a), ticket_hash(&b));
        let mut c = a.clone();
        c.ticket.nonce[0] ^= 1;
        assert_ne!(ticket_hash(&a), ticket_hash(&c));
        assert_eq!(ticket_hash(&a), ticket_hash(&a.clone()));
    }
}
