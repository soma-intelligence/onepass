//! A signed copy of one item sent to a contact (sharing spec 14.1 choice
//! B, 14.2, S29, decision 9, plan 3 arbitrage B-6).
//!
//! Record `RecordKind::ItemSend`, id = `send_id`, in the contact zone of
//! the pair. The item key is wrapped for the recipient's pinned KEM key
//! under `onepass/share/item-send/v1`, the item sealed under that key
//! (`BlobKind::ItemSend`, AAD = `send_id`), and the whole signed by the
//! sender's hybrid key under `onepass/item-send/v1`.

use serde::{Deserialize, Serialize};

use crate::crypto::{HybridSignature, HybridSigningKey, HybridVerifyingKey};
use crate::lineage::decode_strict_with;
use crate::share::MemberRef;
use crate::{Error, Id, Result};

/// KEM label of the item key's envelope.
pub const ITEM_SEND_LABEL: &[u8] = b"onepass/share/item-send/v1";
/// Signature domain of a send.
pub const ITEM_SEND_DOMAIN: &[u8] = b"onepass/item-send/v1";
/// Longest a send waits for its recipient.
pub const MAX_SEND_TTL_SECS: i64 = 30 * 86_400;
/// Largest sealed item a send carries.
pub const MAX_SEND_BLOB: usize = 256 * 1024;
/// Largest envelope a send carries.
pub const MAX_SEND_ENVELOPE: usize = 4096;

const BAD: Error = Error::InvalidFormat("item send");

/// One item copy on its way to a contact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemSend {
    pub send_id: Id,
    pub from: MemberRef,
    pub to: Id,
    /// The recipient's identity the envelope was made for (its context).
    pub to_identity: Id,
    pub envelope: Vec<u8>,
    pub blob: Vec<u8>,
    pub expires_at: i64,
    pub sig: HybridSignature,
}

fn message(s: &ItemSend) -> Vec<u8> {
    postcard::to_allocvec(&(
        s.send_id,
        &s.from,
        s.to,
        s.to_identity,
        &s.envelope,
        &s.blob,
        s.expires_at,
    ))
    .expect("item send encodes")
}

/// The KEM context of a send's envelope: `postcard((send_id,
/// from.account_id, to, recipient identity_id))`.
pub fn send_context(send_id: Id, from: Id, to: Id, to_identity: Id) -> Vec<u8> {
    postcard::to_allocvec(&(send_id, from, to, to_identity)).expect("send context encodes")
}

impl ItemSend {
    /// Sign `unsigned` (its `sig` is replaced).
    pub fn sign(mut unsigned: ItemSend, key: &HybridSigningKey) -> Result<ItemSend> {
        unsigned.check()?;
        unsigned.sig = key.sign(ITEM_SEND_DOMAIN, &message(&unsigned))?;
        Ok(unsigned)
    }

    fn check(&self) -> Result<()> {
        if self.envelope.is_empty()
            || self.envelope.len() > MAX_SEND_ENVELOPE
            || self.blob.is_empty()
            || self.blob.len() > MAX_SEND_BLOB
        {
            return Err(BAD);
        }
        Ok(())
    }

    pub fn verify(&self, sender_key: &HybridVerifyingKey) -> Result<()> {
        sender_key.verify(ITEM_SEND_DOMAIN, &message(self), &self.sig)
    }

    pub fn encode(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("item send encodes")
    }

    /// Strict decoding and sizes; the signature is checked by the reader
    /// against its contact book.
    pub fn decode(b: &[u8]) -> Result<ItemSend> {
        let s: ItemSend = decode_strict_with(b, BAD)?;
        s.check()?;
        Ok(s)
    }
}
