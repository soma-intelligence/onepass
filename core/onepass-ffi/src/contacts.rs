//! Contacts for the apps (sharing plan 4, Task 2): the book, the
//! face-to-face verification (QR, SAS, cards, the pair's mailbox offer) and
//! the remote invitation (link, reply, answer, safety number).
//!
//! The pair's mailbox is made by `ZoneSyncHandle::contact_zone_create`
//! (network) on the creator's side: the smaller account id face to face,
//! the inviter remotely. Its offer travels in the session
//! (`send_zone_offer`) or in the invitation answer.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use onepass_core::contact::{
    ContactEntry, ContactInitiator, ContactInvite, ContactLevel, ContactOutcome, ContactResponder,
    ContactState, SignedContactCard, VerifiedPeer, format_safety_number, is_contact_zone_creator,
    seal_reply,
};
use onepass_core::crypto::HybridKemSecret;
use onepass_core::id::Id;
use zeroize::Zeroizing;

use crate::convert::{id_hex, parse_id};
use crate::error::{OnePassError, invalid};
use crate::rotation::{FfiPqDeviceHalf, device_keys};
use crate::session::{Repo, Session, account_id_of};

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

fn this_device(repo: &Repo) -> Result<Id, OnePassError> {
    repo.this_device_id().ok_or(OnePassError::Validation {
        field: "device".into(),
        reason: "unregistered".into(),
    })
}

// ---- the book ---------------------------------------------------------------

#[derive(uniffi::Enum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum FfiContactLevel {
    /// A remote invitation, no comparison: Read only (founder decision 1).
    Link,
    /// In person, or by a compared safety number.
    Verified,
}

impl From<ContactLevel> for FfiContactLevel {
    fn from(l: ContactLevel) -> FfiContactLevel {
        match l {
            ContactLevel::Link => FfiContactLevel::Link,
            ContactLevel::Verified => FfiContactLevel::Verified,
        }
    }
}

#[derive(uniffi::Enum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum FfiContactState {
    Active,
    /// A rotation of the contact's account was seen at `seen_at`: the old
    /// identity is no longer used, the new one waits for a confirmation.
    KeysChanged {
        seen_at: i64,
    },
    /// Removed at `at`: never active again (a re-add verifies in person).
    Removed {
        at: i64,
    },
}

impl From<ContactState> for FfiContactState {
    fn from(s: ContactState) -> FfiContactState {
        match s {
            ContactState::Active => FfiContactState::Active,
            ContactState::KeysChanged { seen_at, .. } => FfiContactState::KeysChanged { seen_at },
            ContactState::Removed { at } => FfiContactState::Removed { at },
        }
    }
}

/// One contact. `safety_number`: twelve groups of five digits, the same on
/// both phones (empty when it cannot be computed, a removed contact for
/// one).
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct FfiContact {
    pub account_id: String,
    pub name_local: String,
    pub level: FfiContactLevel,
    pub state: FfiContactState,
    pub verified_at: i64,
    pub safety_number: String,
}

fn contact_to_ffi(repo: &mut Repo, e: &ContactEntry) -> FfiContact {
    let safety_number = match e.state {
        ContactState::Removed { .. } => String::new(),
        _ => repo
            .contact_safety_number(e.account_id)
            .map(|n| format_safety_number(&n))
            .unwrap_or_default(),
    };
    FfiContact {
        account_id: id_hex(e.account_id),
        name_local: e.name_local.clone(),
        level: e.level.into(),
        state: e.state.into(),
        verified_at: e.verified_at,
        safety_number,
    }
}

/// The groups of a displayed safety number, as `format_safety_number`
/// prints them (spaces between groups; other separators are ignored).
fn parse_safety_number(s: &str) -> Result<[u32; 12], OnePassError> {
    let digits: Vec<u32> = s
        .chars()
        .filter(char::is_ascii_digit)
        .filter_map(|c| c.to_digit(10))
        .collect();
    if digits.len() != 60 {
        return Err(invalid("safety number"));
    }
    let mut out = [0u32; 12];
    for (i, g) in out.iter_mut().enumerate() {
        *g = digits[5 * i..5 * i + 5].iter().fold(0, |a, d| a * 10 + d);
    }
    Ok(out)
}

#[uniffi::export]
impl Session {
    /// The contact book, removed contacts included.
    pub fn contacts(&self) -> Result<Vec<FfiContact>, OnePassError> {
        self.with(|repo| {
            let entries = repo.contacts()?;
            Ok(entries.iter().map(|e| contact_to_ffi(repo, e)).collect())
        })
    }

    /// The local name of a contact (never shared).
    pub fn rename_contact(&self, account_id: String, name: String) -> Result<(), OnePassError> {
        let id = parse_id(&account_id)?;
        self.with(|repo| Ok(repo.rename_contact(id, &name)?))
    }

    /// Remove a contact: its shares are revoked by the next zone round.
    pub fn remove_contact(&self, account_id: String, now: i64) -> Result<(), OnePassError> {
        let id = parse_id(&account_id)?;
        self.with(|repo| Ok(repo.remove_contact(id, now)?))
    }

    /// The user compared `shown` (the contact's `safety_number`, as
    /// displayed) by voice: a `Link` contact becomes `Verified`. Refused
    /// (`Validation`) when the number changed since it was displayed, or
    /// for a contact not active at `Link`.
    pub fn confirm_safety_number(
        &self,
        account_id: String,
        shown: String,
        now: i64,
    ) -> Result<FfiContact, OnePassError> {
        let id = parse_id(&account_id)?;
        let shown = parse_safety_number(&shown)?;
        self.with(|repo| {
            let e = repo.confirm_safety_number(id, &shown, now)?;
            Ok(contact_to_ffi(repo, &e))
        })
    }

    /// Whether this account makes the pair's mailbox with `peer` face to
    /// face (the smaller account id does, decision 16): then it calls
    /// `ZoneSyncHandle::contact_zone_create` and sends the offer; the other
    /// side waits for `PeerZoneOffer`.
    pub fn creates_contact_zone(&self, peer: Arc<FfiVerifiedPeer>) -> Result<bool, OnePassError> {
        self.with(|repo| {
            let me = account_id_of(repo)?;
            Ok(is_contact_zone_creator(
                me,
                peer.peer.card().card.account_id,
                None,
            ))
        })
    }

    /// Pin the peer of a completed face-to-face session at `Verified`. The
    /// creator passes no offer (its mailbox is made already); the other
    /// side passes the creator's `zone_offer`. Without the pair's mailbox
    /// nothing is pinned (`Validation("contact", "no zone")`).
    pub fn finish_contact_session(
        &self,
        peer: Arc<FfiVerifiedPeer>,
        zone_offer: Option<Vec<u8>>,
        now: i64,
    ) -> Result<FfiContact, OnePassError> {
        self.with(|repo| {
            let e = repo.finish_contact_session(peer.peer.clone(), zone_offer.as_deref(), now)?;
            Ok(contact_to_ffi(repo, &e))
        })
    }
}

// ---- face to face -------------------------------------------------------------

/// A peer card checked by a completed session, after the local user
/// confirmed the SAS: what `finish_contact_session` pins.
#[derive(uniffi::Object)]
pub struct FfiVerifiedPeer {
    peer: VerifiedPeer,
}

#[uniffi::export]
impl FfiVerifiedPeer {
    /// The peer's account id (32 hex characters).
    pub fn account_id(&self) -> String {
        id_hex(self.peer.card().card.account_id)
    }

    /// The name the peer gave (a suggestion for the local name).
    pub fn name(&self) -> String {
        self.peer.card().card.name.clone()
    }

    /// The signed card, for `ZoneSyncHandle::contact_zone_create`.
    pub fn card(&self) -> Vec<u8> {
        self.peer.card().encode()
    }
}

#[derive(uniffi::Enum)]
pub enum FfiContactOutcome {
    Waiting,
    PeerCard { peer: Arc<FfiVerifiedPeer> },
    Done,
    PeerZoneOffer { offer: Vec<u8> },
}

impl From<ContactOutcome> for FfiContactOutcome {
    fn from(o: ContactOutcome) -> FfiContactOutcome {
        match o {
            ContactOutcome::Waiting => FfiContactOutcome::Waiting,
            ContactOutcome::PeerCard(peer) => FfiContactOutcome::PeerCard {
                peer: Arc::new(FfiVerifiedPeer { peer }),
            },
            ContactOutcome::Done => FfiContactOutcome::Done,
            ContactOutcome::PeerZoneOffer(offer) => FfiContactOutcome::PeerZoneOffer { offer },
        }
    }
}

/// This account's card under `my_name`, its device keys and device id: the
/// three things a session's `confirm_and_send_card` needs.
fn card_and_keys(
    session: &Session,
    my_name: &str,
    now: i64,
) -> Result<(SignedContactCard, Id), OnePassError> {
    session.with(|repo| Ok((repo.own_contact_card(my_name, now)?, this_device(repo)?)))
}

/// The side that shows the QR (`contact_responder_start`).
#[derive(uniffi::Object)]
pub struct FfiContactResponder {
    inner: Mutex<ContactResponder>,
}

/// A new responder, its QR text and the Hello to hand to the initiator.
#[derive(uniffi::Record)]
pub struct FfiContactStart {
    pub responder: Arc<FfiContactResponder>,
    pub qr: String,
    pub hello: Vec<u8>,
}

/// Start a face-to-face verification on the side that shows the QR.
#[uniffi::export]
pub fn contact_responder_start(now: i64) -> Result<FfiContactStart, OnePassError> {
    let (responder, qr, hello) = ContactResponder::new(now)?;
    Ok(FfiContactStart {
        responder: Arc::new(FfiContactResponder {
            inner: Mutex::new(responder),
        }),
        qr: qr.to_text(),
        hello,
    })
}

#[uniffi::export]
impl FfiContactResponder {
    /// The initiator's KeyExchange: the SAS to show.
    pub fn on_key_exchange(&self, kx: Vec<u8>, now: i64) -> Result<String, OnePassError> {
        Ok(lock(&self.inner).on_key_exchange(&kx, now)?)
    }

    /// The user confirmed the SAS: this account's card under `my_name`,
    /// with the proof of possession of this device's keys (`classical` and
    /// the app's `pq` half). A failing half sends and pins nothing.
    pub fn confirm_and_send_card(
        &self,
        session: Arc<Session>,
        my_name: String,
        classical: Vec<u8>,
        pq: Arc<dyn FfiPqDeviceHalf>,
        now: i64,
    ) -> Result<Vec<u8>, OnePassError> {
        let (card, me) = card_and_keys(&session, &my_name, now)?;
        let keys = device_keys(&classical, pq)?;
        Ok(lock(&self.inner).confirm_and_send_card(&card, &keys, me, now)?)
    }

    pub fn on_frame(&self, frame: Vec<u8>, now: i64) -> Result<FfiContactOutcome, OnePassError> {
        Ok(lock(&self.inner).on_frame(&frame, now)?.into())
    }

    /// The peer's checked card once the user confirmed, or `None`.
    pub fn verified_peer(&self) -> Option<Arc<FfiVerifiedPeer>> {
        lock(&self.inner)
            .verified_peer()
            .map(|peer| Arc::new(FfiVerifiedPeer { peer }))
    }

    pub fn send_zone_offer(&self, offer: Vec<u8>, now: i64) -> Result<Vec<u8>, OnePassError> {
        Ok(lock(&self.inner).send_zone_offer(&offer, now)?)
    }

    pub fn confirm_pinned(&self, now: i64) -> Result<Vec<u8>, OnePassError> {
        Ok(lock(&self.inner).confirm_pinned(now)?)
    }

    pub fn end(&self, now: i64) -> Result<Vec<u8>, OnePassError> {
        Ok(lock(&self.inner).end(now)?)
    }

    pub fn expires_at(&self) -> i64 {
        lock(&self.inner).expires_at()
    }
}

/// The side that scans the QR (`contact_initiator_begin`).
#[derive(uniffi::Object)]
pub struct FfiContactInitiator {
    inner: Mutex<ContactInitiator>,
}

/// A new initiator, the KeyExchange to send and the SAS to show.
#[derive(uniffi::Record)]
pub struct FfiContactBegin {
    pub initiator: Arc<FfiContactInitiator>,
    pub key_exchange: Vec<u8>,
    pub sas: String,
}

/// Start a face-to-face verification from a scanned QR and its Hello.
#[uniffi::export]
pub fn contact_initiator_begin(
    qr: String,
    hello: Vec<u8>,
    now: i64,
) -> Result<FfiContactBegin, OnePassError> {
    let (initiator, key_exchange, sas) = ContactInitiator::begin(&qr, &hello, now)?;
    Ok(FfiContactBegin {
        initiator: Arc::new(FfiContactInitiator {
            inner: Mutex::new(initiator),
        }),
        key_exchange,
        sas,
    })
}

#[uniffi::export]
impl FfiContactInitiator {
    /// See `FfiContactResponder::confirm_and_send_card`.
    pub fn confirm_and_send_card(
        &self,
        session: Arc<Session>,
        my_name: String,
        classical: Vec<u8>,
        pq: Arc<dyn FfiPqDeviceHalf>,
        now: i64,
    ) -> Result<Vec<u8>, OnePassError> {
        let (card, me) = card_and_keys(&session, &my_name, now)?;
        let keys = device_keys(&classical, pq)?;
        Ok(lock(&self.inner).confirm_and_send_card(&card, &keys, me, now)?)
    }

    pub fn on_frame(&self, frame: Vec<u8>, now: i64) -> Result<FfiContactOutcome, OnePassError> {
        Ok(lock(&self.inner).on_frame(&frame, now)?.into())
    }

    pub fn verified_peer(&self) -> Option<Arc<FfiVerifiedPeer>> {
        lock(&self.inner)
            .verified_peer()
            .map(|peer| Arc::new(FfiVerifiedPeer { peer }))
    }

    pub fn send_zone_offer(&self, offer: Vec<u8>, now: i64) -> Result<Vec<u8>, OnePassError> {
        Ok(lock(&self.inner).send_zone_offer(&offer, now)?)
    }

    pub fn confirm_pinned(&self, now: i64) -> Result<Vec<u8>, OnePassError> {
        Ok(lock(&self.inner).confirm_pinned(now)?)
    }

    pub fn end(&self, now: i64) -> Result<Vec<u8>, OnePassError> {
        Ok(lock(&self.inner).end(now)?)
    }
}

// ---- remote invitation -----------------------------------------------------------

/// An invitation of this device. `link`: what the user sends; `invite_id`:
/// what `invite_reply_card` and `accept_invite_reply` take; `rdv_id`: the
/// invite drop (16 bytes) where the reply (slot 0) and the answer (slot 1)
/// land.
#[derive(uniffi::Record, Debug, Clone)]
pub struct FfiContactInvite {
    pub link: String,
    pub invite_id: String,
    pub rdv_id: Vec<u8>,
    pub expires_at: i64,
}

/// The invitee's side between its reply and the inviter's answer: the
/// ephemeral secret to open the answer with. `to_bytes` holds that secret:
/// the app keeps it only in the Keychain, for an answer that lands after a
/// restart.
#[derive(uniffi::Object)]
pub struct FfiPendingInvite {
    secret: HybridKemSecret,
    reply: Vec<u8>,
    rdv: Id,
}

const PENDING_FORMAT: u8 = 1;

#[uniffi::export]
impl FfiPendingInvite {
    pub fn rdv_id(&self) -> Vec<u8> {
        self.rdv.0.to_vec()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let secret = self.secret.to_bytes();
        let mut out = Vec::with_capacity(1 + 16 + 4 + secret.len() + self.reply.len());
        out.push(PENDING_FORMAT);
        out.extend_from_slice(&self.rdv.0);
        out.extend_from_slice(&u32::try_from(secret.len()).unwrap_or(0).to_be_bytes());
        out.extend_from_slice(&secret);
        out.extend_from_slice(&self.reply);
        out
    }
}

/// A pending invitation kept with `FfiPendingInvite::to_bytes`.
#[uniffi::export]
pub fn pending_invite_from_bytes(bytes: Vec<u8>) -> Result<Arc<FfiPendingInvite>, OnePassError> {
    let bytes = Zeroizing::new(bytes);
    let bad = || invalid("pending invite");
    let (&format, rest) = bytes.split_first().ok_or_else(bad)?;
    if format != PENDING_FORMAT || rest.len() < 20 {
        return Err(bad());
    }
    let rdv: [u8; 16] = rest[..16].try_into().map_err(|_| bad())?;
    let len = u32::from_be_bytes(rest[16..20].try_into().map_err(|_| bad())?) as usize;
    let rest = &rest[20..];
    if rest.len() < len {
        return Err(bad());
    }
    let secret = HybridKemSecret::from_bytes(&rest[..len]).map_err(|_| bad())?;
    Ok(Arc::new(FfiPendingInvite {
        secret,
        reply: rest[len..].to_vec(),
        rdv: Id(rdv),
    }))
}

/// The invitee's reply: write `bytes` at drop `rdv_id` slot 0, keep
/// `pending` until the answer (slot 1) lands.
#[derive(uniffi::Record)]
pub struct FfiInviteReply {
    pub rdv_id: Vec<u8>,
    pub bytes: Vec<u8>,
    pub pending: Arc<FfiPendingInvite>,
}

/// The inviter's side once the reply is accepted: the contact (at `Link`)
/// and the answer to write at slot 1 until it lands.
#[derive(uniffi::Record)]
pub struct FfiInviteAnswer {
    pub contact: FfiContact,
    pub answer: Vec<u8>,
}

#[uniffi::export]
impl Session {
    /// A fresh invitation, kept on this device until used or expired.
    /// `host`: the universal link host, none for the `onepass:` scheme.
    pub fn create_contact_invite(
        &self,
        host: Option<String>,
        now: i64,
    ) -> Result<FfiContactInvite, OnePassError> {
        self.with(|repo| {
            let invite = repo.create_contact_invite(now)?;
            Ok(FfiContactInvite {
                link: invite.link_for(host.as_deref()),
                invite_id: id_hex(Id(invite.invite_id)),
                rdv_id: invite.rdv_id().0.to_vec(),
                expires_at: invite
                    .created_at
                    .saturating_add(onepass_core::contact::CONTACT_INVITE_TTL_SECS),
            })
        })
    }

    /// The invitee's reply to `link`, carrying this account's card under
    /// `my_name`.
    pub fn contact_invite_reply(
        &self,
        link: String,
        my_name: String,
        now: i64,
    ) -> Result<FfiInviteReply, OnePassError> {
        let (invite, _host) = ContactInvite::parse_link(link.trim())?;
        let card = self.with(|repo| Ok(repo.own_contact_card(&my_name, now)?))?;
        let (bytes, secret) = seal_reply(&invite, &card)?;
        let rdv = invite.rdv_id();
        Ok(FfiInviteReply {
            rdv_id: rdv.0.to_vec(),
            pending: Arc::new(FfiPendingInvite {
                secret,
                reply: bytes.clone(),
                rdv,
            }),
            bytes,
        })
    }

    /// The card in a reply to this device's invitation, without using the
    /// invitation: what `ZoneSyncHandle::contact_zone_create` takes before
    /// `accept_invite_reply` (the inviter makes the pair's mailbox).
    pub fn invite_reply_card(
        &self,
        invite_id: String,
        reply: Vec<u8>,
        now: i64,
    ) -> Result<Vec<u8>, OnePassError> {
        let id = parse_id(&invite_id)?;
        self.with(|repo| Ok(repo.invite_reply_card(id.0, &reply, now)?.encode()))
    }

    /// Accept the reply: the invitee is pinned at `Link`, the answer
    /// carries this account's card under `my_name` and the pair's mailbox
    /// `zone_offer`. The invitation is used: keep writing the answer until
    /// it lands.
    pub fn accept_invite_reply(
        &self,
        invite_id: String,
        reply: Vec<u8>,
        my_name: String,
        zone_offer: Vec<u8>,
        now: i64,
    ) -> Result<FfiInviteAnswer, OnePassError> {
        let id = parse_id(&invite_id)?;
        self.with(|repo| {
            let (e, answer) = repo.accept_invite_reply(id.0, &reply, &my_name, &zone_offer, now)?;
            Ok(FfiInviteAnswer {
                contact: contact_to_ffi(repo, &e),
                answer,
            })
        })
    }

    /// The invitee's side once the answer landed: the inviter is pinned at
    /// `Link`, with the pair's mailbox from its offer.
    pub fn finish_invite(
        &self,
        pending: Arc<FfiPendingInvite>,
        answer: Vec<u8>,
        now: i64,
    ) -> Result<FfiContact, OnePassError> {
        self.with(|repo| {
            let e =
                repo.finish_invite(&pending.secret, &pending.reply, pending.rdv, &answer, now)?;
            Ok(contact_to_ffi(repo, &e))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safety_number_parses_as_printed() {
        let n = [1, 23, 456, 7890, 12345, 0, 99999, 5, 50, 500, 5000, 50000];
        assert_eq!(parse_safety_number(&format_safety_number(&n)).unwrap(), n);
        assert!(parse_safety_number("12345").is_err());
    }
}
