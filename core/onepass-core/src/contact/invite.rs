//! Remote contact invitation through a sealed rendezvous (sharing spec
//! 5.3.2 and 13.4, S27, plan ruling A-5, founder decision 1).
//!
//! 1. Alice draws `invite_id` (16 bytes) and `invite_secret` (32 bytes)
//!    and sends the link `onepass://contact#<base32(invite_id ||
//!    invite_secret)>` (RFC 4648 alphabet, upper case, no padding) over a
//!    channel of her choice. The fragment never reaches a server. The
//!    invitation is valid `CONTACT_INVITE_TTL_SECS` and used once: her
//!    device keeps `(created_at, invite_secret)` in its local metadata
//!    (`contact_invite.<hex id>`, the secret wrapped to the account's KEM
//!    key) and removes it when a reply is accepted or found expired.
//! 2. Bob opens the link and writes, at the public rendezvous record
//!    `rdv_id = SHA-256("onepass/invite-rdv/v1" || invite_id)[..16]`, his
//!    `InviteReply` (his card and a fresh ephemeral KEM public key),
//!    sealed under `K_inv = HKDF(invite_secret, "onepass/contact-invite/v1"
//!    || invite_id)` (blob kind `ContactInvite`, AAD `rdv_id`, schema 1).
//! 3. Alice opens it, checks Bob's card (`pin_contact`: not her account,
//!    signatures, lineage) and answers: a fresh key wrapped to Bob's
//!    ephemeral key by `wrap_key_labeled` under `onepass/contact/v1`,
//!    context `SHA-256(rdv_id || reply_bytes)`, which seals her card
//!    (AAD `rdv_id`, schema 2). The context is the envelope's AEAD
//!    associated data: the answer opens only for those exact reply bytes
//!    at that rendezvous.
//! 4. Both pin the other at `Link`, transcript hash `SHA-256(rdv_id ||
//!    reply_bytes)` on both sides. Comparing the safety number by voice
//!    then lifts the contact to `Verified` (`confirm_safety_number`).
//!
//! The rendezvous server only ever sees sealed bytes; whoever read the link
//! in transit can stand in for Bob, hence `Link` gives Read only (founder
//! decision 1).

use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::book::{ContactEntry, ContactLevel, ContactState};
use super::{
    CONTACT_INVITE_INFO, CONTACT_LABEL, INVITE_RDV_PREFIX, MAX_CONTACT_MESSAGE_BYTES,
    SignedContactCard, sha256,
};
use crate::crypto::aead::{OpenStage, open_detailed};
use crate::crypto::kem::{unwrap_key_labeled, wrap_key_labeled};
use crate::crypto::key::hkdf32;
use crate::crypto::{
    Aad, BlobKind, HybridKemPublic, HybridKemSecret, SymmetricKey, random_array, seal,
};
use crate::lineage::decode_strict_with;
use crate::lists::AccountList;
use crate::repo::Repository;
use crate::store::RecordStore;
use crate::{Error, Id, IntegrityError, Result, ValidationError};

/// An invitation is valid 72 hours (spec 5.3.2).
pub const CONTACT_INVITE_TTL_SECS: i64 = 72 * 3600;
/// Everything of a link before the fragment.
pub const CONTACT_LINK_PREFIX: &str = "onepass://contact#";
/// Prefix of the local metadata key of a pending invitation.
pub const CONTACT_INVITE_META_PREFIX: &str = "contact_invite.";
/// Largest sealed reply or answer blob opened: a card at the session cap,
/// padded, with the blob header and tag.
pub const MAX_INVITE_BLOB_BYTES: usize = MAX_CONTACT_MESSAGE_BYTES + 2 * 65536;
/// Largest encoded `InviteAnswer`: the blob and a KEM envelope.
pub const MAX_INVITE_ANSWER_BYTES: usize = MAX_INVITE_BLOB_BYTES + 4096;

/// AAD schema of the sealed reply (under `K_inv`).
const REPLY_SCHEMA: u16 = 1;
/// AAD schema of the sealed answer card (under the fresh key).
const ANSWER_SCHEMA: u16 = 2;
/// Bytes behind the fragment: `invite_id || invite_secret`.
const LINK_BYTES: usize = 48;
/// `ceil(48 * 8 / 5)` base32 characters.
const LINK_CHARS: usize = 77;
const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

fn refused(reason: &'static str) -> Error {
    ValidationError {
        field: "invite".into(),
        reason,
    }
    .into()
}

/// An invitation: its id, its secret and, on the issuing device only, its
/// creation date (0 for a link parsed on the invitee's side).
pub struct ContactInvite {
    pub invite_id: [u8; 16],
    invite_secret: Zeroizing<[u8; 32]>,
    pub created_at: i64,
}

impl fmt::Debug for ContactInvite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ContactInvite")
            .field("invite_id", &self.invite_id)
            .field("created_at", &self.created_at)
            .finish_non_exhaustive()
    }
}

impl ContactInvite {
    /// A fresh invitation created at `now`.
    pub fn new(now: i64) -> Result<ContactInvite> {
        Ok(ContactInvite {
            invite_id: random_array()?,
            invite_secret: Zeroizing::new(random_array()?),
            created_at: now,
        })
    }

    /// `onepass://contact#<base32(invite_id || invite_secret)>`: 77 upper
    /// case characters after the `#`, no padding.
    pub fn link(&self) -> String {
        let mut raw = Zeroizing::new([0u8; LINK_BYTES]);
        raw[..16].copy_from_slice(&self.invite_id);
        raw[16..].copy_from_slice(&*self.invite_secret);
        let mut out = String::with_capacity(CONTACT_LINK_PREFIX.len() + LINK_CHARS);
        out.push_str(CONTACT_LINK_PREFIX);
        out.push_str(&base32_encode(&*raw));
        out
    }

    /// Strict: the exact prefix, then exactly 77 characters of the upper
    /// case alphabet whose unused trailing bit is zero (the one canonical
    /// spelling). Anything else is `InvalidFormat`. `created_at` is 0: only
    /// the issuer knows the date.
    pub fn parse_link(s: &str) -> Result<ContactInvite> {
        const BAD: Error = Error::InvalidFormat("contact link");
        let body = s.strip_prefix(CONTACT_LINK_PREFIX).ok_or(BAD)?;
        let raw = base32_decode(body).ok_or(BAD)?;
        let mut invite_id = [0u8; 16];
        invite_id.copy_from_slice(&raw[..16]);
        let mut secret = Zeroizing::new([0u8; 32]);
        secret.copy_from_slice(&raw[16..]);
        Ok(ContactInvite {
            invite_id,
            invite_secret: secret,
            created_at: 0,
        })
    }

    /// The public rendezvous id: `SHA-256("onepass/invite-rdv/v1" ||
    /// invite_id)[..16]` (spec 13.4).
    pub fn rdv_id(&self) -> Id {
        rdv_id_of(&self.invite_id)
    }

    /// `K_inv = HKDF(invite_secret, "onepass/contact-invite/v1" ||
    /// invite_id)`, empty salt.
    fn k_inv(&self) -> Result<SymmetricKey> {
        hkdf32(
            &[],
            &*self.invite_secret,
            &[CONTACT_INVITE_INFO, &self.invite_id],
        )
    }
}

fn rdv_id_of(invite_id: &[u8; 16]) -> Id {
    let h = sha256(&[INVITE_RDV_PREFIX, invite_id]);
    let mut id = [0u8; 16];
    id.copy_from_slice(&h[..16]);
    Id(id)
}

/// RFC 4648 base32, no padding.
fn base32_encode(b: &[u8]) -> String {
    let mut out = String::with_capacity((b.len() * 8).div_ceil(5));
    let mut acc: u32 = 0;
    let mut bits = 0;
    for byte in b {
        acc = (acc << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((acc >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((acc << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// The 48 bytes of a link fragment, or `None`: another length, a character
/// outside the upper case alphabet, or a non-zero trailing bit.
fn base32_decode(s: &str) -> Option<Zeroizing<[u8; LINK_BYTES]>> {
    if s.len() != LINK_CHARS {
        return None;
    }
    let mut out = Zeroizing::new([0u8; LINK_BYTES]);
    let mut acc: u32 = 0;
    let mut bits = 0;
    let mut n = 0;
    for c in s.bytes() {
        let v = ALPHABET.iter().position(|a| *a == c)? as u32;
        acc = ((acc << 5) | v) & 0xFFFF;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            *out.get_mut(n)? = (acc >> bits) as u8;
            n += 1;
        }
    }
    // 77 * 5 = 385 bits: one left over, which must be zero.
    if n != LINK_BYTES || acc & ((1 << bits) - 1) != 0 {
        return None;
    }
    Some(out)
}

/// What Bob writes at the rendezvous, sealed under `K_inv`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InviteReply {
    /// The key Alice's answer is wrapped to.
    pub ephemeral_public: HybridKemPublic,
    pub card: SignedContactCard,
}

impl InviteReply {
    /// postcard, in a buffer wiped on drop.
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        postcard::to_allocvec(self)
            .map(Zeroizing::new)
            .map_err(|_| Error::InvalidFormat("invite reply"))
    }

    /// Strict: at most `MAX_CONTACT_MESSAGE_BYTES`, the whole buffer, a
    /// canonical re-encoding, a key that parses as a hybrid public key and
    /// a card that passes `SignedContactCard::decode`. Anything else is
    /// `InvalidFormat`. No signature is verified.
    pub fn decode(b: &[u8]) -> Result<InviteReply> {
        const BAD: Error = Error::InvalidFormat("invite reply");
        if b.len() > MAX_CONTACT_MESSAGE_BYTES {
            return Err(BAD);
        }
        let reply: InviteReply = decode_strict_with(b, BAD)?;
        HybridKemPublic::from_bytes(&reply.ephemeral_public.to_bytes()).map_err(|_| BAD)?;
        SignedContactCard::decode(&reply.card.encode())?;
        Ok(reply)
    }
}

/// What Alice writes back at the rendezvous: her card sealed under a fresh
/// key, and that key wrapped to Bob's ephemeral key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InviteAnswer {
    pub envelope: Vec<u8>,
    pub sealed: Vec<u8>,
}

impl InviteAnswer {
    pub fn encode(&self) -> Result<Vec<u8>> {
        postcard::to_allocvec(self).map_err(|_| Error::InvalidFormat("invite answer"))
    }

    /// Strict: at most `MAX_INVITE_ANSWER_BYTES`, the whole buffer and a
    /// canonical re-encoding, else `InvalidFormat`.
    pub fn decode(b: &[u8]) -> Result<InviteAnswer> {
        const BAD: Error = Error::InvalidFormat("invite answer");
        if b.len() > MAX_INVITE_ANSWER_BYTES {
            return Err(BAD);
        }
        decode_strict_with(b, BAD)
    }
}

/// `open`, a wrong key or a damaged blob both reading `Integrity(Aead)`:
/// at the rendezvous neither is worth telling apart.
fn open_invite_blob(key: &SymmetricKey, aad: &Aad, blob: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if blob.len() > MAX_INVITE_BLOB_BYTES {
        return Err(Error::InvalidFormat("invite blob"));
    }
    open_detailed(key, BlobKind::ContactInvite, aad, blob).map_err(|(stage, e)| match stage {
        OpenStage::Commitment | OpenStage::Aead => Error::Integrity(IntegrityError::Aead),
        _ => e,
    })
}

fn aad(rdv: Id, schema: u16) -> Aad {
    Aad {
        blob_id: rdv,
        vault_id: None,
        schema,
    }
}

/// `SHA-256(rdv_id || reply_bytes)`: the context of the answer envelope
/// and the transcript hash both sides pin.
pub fn invite_transcript(rdv: Id, reply_bytes: &[u8]) -> [u8; 32] {
    sha256(&[&rdv.0, reply_bytes])
}

/// Bob's side: his reply for the rendezvous of `invite`, and the ephemeral
/// secret to open Alice's answer with (`open_answer`).
pub fn seal_reply(
    invite: &ContactInvite,
    card: &SignedContactCard,
) -> Result<(Vec<u8>, HybridKemSecret)> {
    let secret = HybridKemSecret::generate()?;
    let reply = InviteReply {
        ephemeral_public: secret.public()?,
        card: card.clone(),
    };
    let plain = reply.encode()?;
    if plain.len() > MAX_CONTACT_MESSAGE_BYTES {
        return Err(Error::InvalidFormat("invite reply"));
    }
    let bytes = seal(
        &invite.k_inv()?,
        BlobKind::ContactInvite,
        &aad(invite.rdv_id(), REPLY_SCHEMA),
        &plain,
    )?;
    Ok((bytes, secret))
}

/// Alice's side: the reply at the rendezvous of `invite`. A blob sealed
/// under another key, or damaged, is `Integrity(Aead)`; a plaintext that
/// is not a strict `InviteReply`, `InvalidFormat`. The card is not checked
/// here (`Repository::accept_invite_reply` does).
pub fn open_reply(invite: &ContactInvite, bytes: &[u8]) -> Result<InviteReply> {
    let plain = open_invite_blob(&invite.k_inv()?, &aad(invite.rdv_id(), REPLY_SCHEMA), bytes)?;
    InviteReply::decode(&plain)
}

/// Alice's side: her card for Bob, bound to the exact `reply_bytes` at
/// `rdv` (plan ruling A-5).
pub fn seal_answer(
    reply_bytes: &[u8],
    reply: &InviteReply,
    my_card: &SignedContactCard,
    rdv: Id,
) -> Result<Vec<u8>> {
    let key = SymmetricKey::generate()?;
    let envelope = wrap_key_labeled(
        &reply.ephemeral_public,
        &key,
        CONTACT_LABEL,
        &invite_transcript(rdv, reply_bytes),
    )?;
    let card = my_card.encode();
    if card.len() > MAX_CONTACT_MESSAGE_BYTES {
        return Err(Error::InvalidFormat("invite answer"));
    }
    let sealed = seal(
        &key,
        BlobKind::ContactInvite,
        &aad(rdv, ANSWER_SCHEMA),
        &card,
    )?;
    InviteAnswer { envelope, sealed }.encode()
}

/// Bob's side: Alice's card from `answer`, which opens only with the
/// ephemeral secret of `reply_bytes`, for those bytes at `rdv`. The card
/// is not checked here (`Repository::finish_invite` does).
pub fn open_answer(
    secret: &HybridKemSecret,
    reply_bytes: &[u8],
    rdv: Id,
    answer: &[u8],
) -> Result<SignedContactCard> {
    let a = InviteAnswer::decode(answer)?;
    let key = unwrap_key_labeled(
        secret,
        &a.envelope,
        CONTACT_LABEL,
        &invite_transcript(rdv, reply_bytes),
    )?;
    let plain = open_invite_blob(&key, &aad(rdv, ANSWER_SCHEMA), &a.sealed)?;
    SignedContactCard::decode(&plain)
}

/// The local record of a pending invitation: its date and its secret,
/// wrapped to the account's KEM key (label `onepass/contact-invite/v1`,
/// context `invite_id`; the length-framed KEM info never meets the HKDF
/// info of `K_inv`, whose input key is the secret itself).
#[derive(Serialize, Deserialize)]
struct InviteMeta {
    created_at: i64,
    envelope: Vec<u8>,
}

fn meta_key(invite_id: &[u8; 16]) -> String {
    let mut k = String::from(CONTACT_INVITE_META_PREFIX);
    for b in invite_id {
        k.push_str(&format!("{b:02x}"));
    }
    k
}

fn expired(created_at: i64, now: i64) -> bool {
    now > created_at.saturating_add(CONTACT_INVITE_TTL_SECS)
}

impl<S: RecordStore> Repository<S> {
    /// A fresh invitation, kept in this device's local metadata until a
    /// reply is accepted or it expires. Expired invitations of this device
    /// are removed first. The store must keep local metadata (the sync
    /// store does).
    pub fn create_contact_invite(&mut self, now: i64) -> Result<ContactInvite> {
        for key in self.store.local_meta_keys(CONTACT_INVITE_META_PREFIX)? {
            let stale = match self.store.local_meta(&key)? {
                Some(v) => postcard::from_bytes::<InviteMeta>(&v)
                    .map_or(true, |m| expired(m.created_at, now)),
                None => false,
            };
            if stale {
                self.store.set_local_meta(&key, None)?;
            }
        }
        let invite = ContactInvite::new(now)?;
        let wrapped = SymmetricKey::from_bytes(*invite.invite_secret);
        let envelope = wrap_key_labeled(
            &self.account.params.kem_pub,
            &wrapped,
            CONTACT_INVITE_INFO,
            &invite.invite_id,
        )?;
        let meta = postcard::to_allocvec(&InviteMeta {
            created_at: now,
            envelope,
        })
        .map_err(|_| Error::InvalidFormat("invite meta"))?;
        self.store
            .set_local_meta(&meta_key(&invite.invite_id), Some(&meta))?;
        Ok(invite)
    }

    /// Accept Bob's reply to this device's invitation `invite_id`: open it,
    /// pin his card at `Link` (transcript `SHA-256(rdv_id || reply_bytes)`)
    /// and return the entry with the answer to write at the rendezvous,
    /// carrying this account's card named `my_name`
    /// (`own_contact_card`).
    ///
    /// Refused with nothing written: an invitation this device does not
    /// hold, already used, or expired (`now > created_at +
    /// CONTACT_INVITE_TTL_SECS`, its record then removed): `Validation`; a
    /// reply that does not open or decode (`open_reply`), the invitation
    /// staying usable; any refusal of `pin_contact` (a card of this
    /// account, bad signatures or lineage, a removed contact, another
    /// genesis or head). The book write and the removal of the invitation
    /// are one store transaction: of two replies racing on one invitation,
    /// one wins, the other is `Conflict` or `Validation`.
    pub fn accept_invite_reply(
        &mut self,
        invite_id: [u8; 16],
        reply_bytes: &[u8],
        my_name: &str,
        now: i64,
    ) -> Result<(ContactEntry, Vec<u8>)> {
        let key = meta_key(&invite_id);
        let raw = self
            .store
            .local_meta(&key)?
            .ok_or_else(|| refused("unknown or used"))?;
        let Ok(meta) = postcard::from_bytes::<InviteMeta>(&raw) else {
            self.store.set_local_meta(&key, None)?;
            return Err(refused("unreadable"));
        };
        if expired(meta.created_at, now) {
            self.store.set_local_meta(&key, None)?;
            return Err(refused("expired"));
        }
        let invite = self.held_invite(invite_id, &meta)?;
        let reply = open_reply(&invite, reply_bytes)?;
        let rdv = invite.rdv_id();
        let transcript = invite_transcript(rdv, reply_bytes);
        let (entry, write) = self.plan_pin(&reply.card, ContactLevel::Link, transcript, now)?;
        let my_card = self.own_contact_card(my_name, now)?;
        let answer = seal_answer(reply_bytes, &reply, &my_card, rdv)?;
        match write {
            Some((current, entries)) => {
                let (rec, expected, body) = self.list_write(current.as_ref(), entries)?;
                self.store
                    .put_all_if_version_taking_meta(vec![(rec, expected)], &key, &raw)?;
                ContactEntry::set_seen(&mut self.chain, body.seen());
            }
            None => self
                .store
                .put_all_if_version_taking_meta(Vec::new(), &key, &raw)?,
        }
        Ok((entry, answer))
    }

    /// Bob's side, once Alice answered: open the answer to the reply this
    /// device wrote (`open_answer`) and pin her card at `Link`, transcript
    /// `SHA-256(rdv || reply_bytes)`. `pin_contact`'s refusals apply.
    pub fn finish_invite(
        &mut self,
        secret: &HybridKemSecret,
        reply_bytes: &[u8],
        rdv: Id,
        answer: &[u8],
        now: i64,
    ) -> Result<ContactEntry> {
        let card = open_answer(secret, reply_bytes, rdv, answer)?;
        self.pin_contact(
            &card,
            ContactLevel::Link,
            invite_transcript(rdv, reply_bytes),
            now,
        )
    }

    /// The user confirmed the safety number shown for this contact is the
    /// same on both phones (by voice): a contact `Active` at `Link` becomes
    /// `Verified`, verified now on this device; its head, keys and
    /// transcript stay. Any other contact is `Validation`: one already
    /// `Verified`, one whose keys changed (the number shown no longer
    /// matches the identity in use), a removed one (a re-add takes a
    /// face-to-face verification, spec 5.4). An unknown one is `NotFound`.
    pub fn confirm_safety_number(&mut self, account_id: Id, now: i64) -> Result<ContactEntry> {
        let entry = self.contact(account_id)?.ok_or(Error::NotFound)?;
        if entry.state != ContactState::Active || entry.level != ContactLevel::Link {
            return Err(refused("contact not active at link"));
        }
        let device = self.this_device()?;
        self.edit_contact(account_id, |e| {
            if e.state != ContactState::Active || e.level != ContactLevel::Link {
                return Err(refused("contact not active at link"));
            }
            e.level = ContactLevel::Verified;
            e.verified_at = now;
            e.verified_on = device;
            Ok(())
        })?;
        self.contact(account_id)?.ok_or(Error::NotFound)
    }

    /// The invitation of `meta`: its secret unwrapped with the account's
    /// current KEM key, or a retired one (the account rotated since).
    fn held_invite(&self, invite_id: [u8; 16], meta: &InviteMeta) -> Result<ContactInvite> {
        let keyset = self.account.keyset();
        let secret = std::iter::once(&keyset.kem)
            .chain(keyset.retired_kem.iter())
            .find_map(|k| {
                unwrap_key_labeled(k, &meta.envelope, CONTACT_INVITE_INFO, &invite_id).ok()
            })
            .ok_or_else(|| refused("unreadable"))?;
        Ok(ContactInvite {
            invite_id,
            invite_secret: Zeroizing::new(*secret.expose()),
            created_at: meta.created_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{HEADER_LEN, padded_len};

    /// Bytes of a padded blob for a plaintext of `len` bytes.
    fn blob_len(len: usize) -> usize {
        HEADER_LEN + padded_len(len + 4) + 16
    }

    #[test]
    fn base32_round_trip() {
        for _ in 0..64 {
            let raw: [u8; LINK_BYTES] = random_array().unwrap();
            let s = base32_encode(&raw);
            assert_eq!(s.len(), LINK_CHARS);
            assert_eq!(*base32_decode(&s).unwrap(), raw);
        }
    }

    #[test]
    fn base32_refuses_non_canonical() {
        let raw = [0u8; LINK_BYTES];
        let s = base32_encode(&raw);
        // The last character carries one unused bit: "B" sets it.
        let mut bad = s.clone();
        bad.pop();
        bad.push('B');
        assert!(base32_decode(&bad).is_none());
        assert!(base32_decode(&s.to_lowercase()).is_none());
        assert!(base32_decode(&s[1..]).is_none());
        assert!(base32_decode(&format!("{s}A")).is_none());
    }

    #[test]
    fn caps_hold_a_full_card() {
        assert!(blob_len(MAX_CONTACT_MESSAGE_BYTES) <= MAX_INVITE_BLOB_BYTES);
    }
}
