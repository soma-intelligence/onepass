//! Face-to-face contact verification (sharing spec 5.3.1, S2, plan ruling
//! A-2): the pairing channel of milestone 2b, its cryptography unchanged,
//! under its own Hello, label and messages.
//!
//! 1. The responder (who shows the QR) draws an ephemeral hybrid KEM pair
//!    and a 16-byte `session_id`, and shows a `PairingQr` exactly as a
//!    pairing newcomer does (`"OPPAIR1:"`, `key_hash`, 120 s). It sends the
//!    Hello `"OPC1" || postcard(ContactHello {session_id,
//!    ephemeral_public})`, at most 4096 bytes. A pairing Hello is `"OPH1"`:
//!    neither side ever takes the other's.
//! 2. The initiator (who scans) refuses the QR and Hello as a pairing
//!    approver does (canonical QR, not expired, not issued more than
//!    `CLOCK_SKEW_SECS` ahead, same session, `SHA-256(ephemeral_public) ==
//!    key_hash`, else `WrongContext`), draws the session key K and wraps it:
//!    `wrap_key_labeled(ephemeral_public, K, "onepass/contact/v1",
//!    transcript)`, `transcript = SHA-256(QR text || Hello bytes)`. The
//!    KeyExchange is `"OPK1" || envelope`, as in pairing.
//! 3. Both show the pairing SAS of K and the transcript.
//! 4. From here, pairing channel frames (`Channel`: the initiator sends
//!    under "a2n", the responder under "n2a"), whose plaintext is
//!    `postcard(ContactMessage)`. Once its user confirmed the SAS, each side
//!    sends `Card {card, device, pop}`, `pop = sign_pop(device keys,
//!    transcript, device)` (domain `onepass/device-pop/v1`). Each side
//!    checks the peer's card (signatures, lineage), the proof over its own
//!    transcript, and that `device` is in the roster of the card's head and
//!    revoked by none of its records. A card of one's own account is
//!    refused. A card is handed to the caller only once the local user
//!    confirmed; the caller pins it (`Repository::finish_contact_session`),
//!    then may send `Confirmed` (pinned), and `End` closes both sides.
//!
//! Any failed check closes the session; nothing is pinned without a card
//! handed over. No Secret Key and no snapshot ever pass here.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::book::{ContactEntry, ContactLevel, check_card_lineage};
use super::lineage::roster_at;
use super::{CONTACT_LABEL, SignedContactCard};
use crate::crypto::kem::{unwrap_key_labeled, wrap_key_labeled};
use crate::crypto::sign::MLDSA_SIG_LEN;
use crate::crypto::{
    HybridKemPublic, HybridKemSecret, HybridSignature, SymmetricKey, random_array,
};
use crate::device_keys::{DeviceKeys, DevicePublic, sign_pop, verify_pop};
use crate::lineage::{LineageRecord, decode_strict_with};
use crate::pairing::qr::QR_VERSION;
use crate::pairing::{
    CLOCK_SKEW_SECS, Channel, KeyExchange, PairingQr, QR_LIFETIME_SECS, sas, sha256, transcript,
};
use crate::repo::Repository;
use crate::store::RecordStore;
use crate::{Error, Id, IntegrityError, Result, ValidationError};

const HELLO_MAGIC: &[u8; 4] = b"OPC1";
/// A contact Hello is about 1.6 KB: anything larger is refused unread.
pub const MAX_CONTACT_HELLO_BYTES: usize = 4096;

fn refused(reason: &'static str) -> Error {
    ValidationError {
        field: "contact".into(),
        reason,
    }
    .into()
}

/// Responder -> initiator, in the clear: the ephemeral key the QR commits
/// to. No device, no mode: a contact session asks for nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContactHello {
    pub session_id: [u8; 16],
    pub ephemeral_public: HybridKemPublic,
}

impl ContactHello {
    /// `"OPC1" || postcard(self)`.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let body =
            postcard::to_allocvec(self).map_err(|_| Error::InvalidFormat("contact hello"))?;
        let mut out = HELLO_MAGIC.to_vec();
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Strict: at most `MAX_CONTACT_HELLO_BYTES`, the magic, the whole
    /// buffer, a canonical re-encoding and a key that parses as a hybrid
    /// public key. Anything else is `InvalidFormat`.
    pub fn from_bytes(b: &[u8]) -> Result<ContactHello> {
        const BAD: Error = Error::InvalidFormat("contact hello");
        if b.len() > MAX_CONTACT_HELLO_BYTES {
            return Err(BAD);
        }
        let body = b.strip_prefix(HELLO_MAGIC).ok_or(BAD)?;
        let hello: ContactHello = decode_strict_with(body, BAD)?;
        HybridKemPublic::from_bytes(&hello.ephemeral_public.to_bytes()).map_err(|_| BAD)?;
        Ok(hello)
    }
}

/// A message inside the contact channel. postcard encodes the variants by
/// index: new ones are only ever appended.
///
/// `Card` is held unboxed, as the plan's interface names it: one message
/// per frame, never kept in bulk.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContactMessage {
    /// The sender's user confirmed the SAS: its card, the device that
    /// speaks for the account, and that device's proof of possession over
    /// the transcript.
    Card {
        card: SignedContactCard,
        device: DevicePublic,
        pop: HybridSignature,
    },
    /// The sender pinned the peer's card.
    Confirmed,
    /// The session is over.
    End,
}

impl ContactMessage {
    /// postcard, in a buffer wiped on drop.
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        postcard::to_allocvec(self)
            .map(Zeroizing::new)
            .map_err(|_| Error::InvalidFormat("contact message"))
    }

    /// Strict: the whole buffer, a canonical re-encoding, and in a `Card`
    /// a card that passes `SignedContactCard::decode`, a device that passes
    /// `DevicePublic::decode` and a proof of the hybrid signature layout.
    /// Anything else is `InvalidFormat`. No signature is verified.
    pub fn decode(b: &[u8]) -> Result<ContactMessage> {
        const BAD: Error = Error::InvalidFormat("contact message");
        let msg: ContactMessage = decode_strict_with(b, BAD)?;
        if let ContactMessage::Card { card, device, pop } = &msg {
            SignedContactCard::decode(&card.encode())?;
            DevicePublic::decode(&device.encode())?;
            if pop.mldsa.len() != MLDSA_SIG_LEN {
                return Err(BAD);
            }
        }
        Ok(msg)
    }
}

/// What a frame from the peer brought. `PeerCard` is unboxed, as the
/// plan's interface names it: one value per frame.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContactOutcome {
    /// Nothing for the caller yet (a card that waits for the local user's
    /// confirmation, see `peer_card`).
    Waiting,
    /// The peer's checked card, to pin with
    /// `Repository::finish_contact_session`.
    PeerCard(SignedContactCard),
    /// The peer pinned this side's card (`Confirmed`), or ended the
    /// session (`End`).
    Done,
}

/// Both ends once the key is known.
struct Session {
    channel: Channel,
    transcript: [u8; 32],
    /// The local user confirmed the SAS and this side's card went out.
    confirmed: bool,
    own_account: Option<Id>,
    /// The peer's card, checked.
    peer: Option<SignedContactCard>,
    /// `peer` was handed to the caller (local confirmation, not its own
    /// account).
    released: bool,
    pinned_sent: bool,
    peer_pinned: bool,
    failed: bool,
}

impl Session {
    fn new(channel: Channel, transcript: [u8; 32]) -> Session {
        Session {
            channel,
            transcript,
            confirmed: false,
            own_account: None,
            peer: None,
            released: false,
            pinned_sent: false,
            peer_pinned: false,
            failed: false,
        }
    }

    fn fail(&mut self) {
        self.failed = true;
        self.peer = None;
        self.released = false;
        self.channel.close();
    }

    fn live(&self) -> Result<()> {
        if self.failed {
            return Err(refused("session closed"));
        }
        Ok(())
    }

    fn confirm_and_send_card(
        &mut self,
        card: &SignedContactCard,
        keys: &DeviceKeys,
        me: Id,
        now: i64,
    ) -> Result<Vec<u8>> {
        self.live()?;
        if self.confirmed {
            return Err(refused("already confirmed"));
        }
        let device = keys.public(me)?;
        let pop = sign_pop(keys, &self.transcript, &device)?;
        // What the peer will check, checked before it leaves.
        check_card(card, &device, &pop, &self.transcript)?;
        let account = card.card.account_id;
        if self
            .peer
            .as_ref()
            .is_some_and(|p| p.card.account_id == account)
        {
            self.fail();
            return Err(refused("own account"));
        }
        let msg = ContactMessage::Card {
            card: card.clone(),
            device,
            pop,
        };
        let frame = self.channel.seal_bytes_at(&msg.encode()?, false, now)?;
        self.confirmed = true;
        self.own_account = Some(account);
        self.released = self.peer.is_some();
        Ok(frame)
    }

    fn on_frame(&mut self, frame: &[u8], now: i64) -> Result<ContactOutcome> {
        self.live()?;
        let r = self.take(frame, now);
        if r.is_err() {
            self.fail();
        }
        r
    }

    fn take(&mut self, frame: &[u8], now: i64) -> Result<ContactOutcome> {
        let plain = self.channel.open_bytes_at(frame, now)?;
        match ContactMessage::decode(&plain)? {
            ContactMessage::Card { card, device, pop } if self.peer.is_none() => {
                check_card(&card, &device, &pop, &self.transcript)?;
                if self.own_account == Some(card.card.account_id) {
                    return Err(refused("own account"));
                }
                let out = if self.confirmed {
                    self.released = true;
                    ContactOutcome::PeerCard(card.clone())
                } else {
                    ContactOutcome::Waiting
                };
                self.peer = Some(card);
                Ok(out)
            }
            ContactMessage::Confirmed
                if self.confirmed && self.peer.is_some() && !self.peer_pinned =>
            {
                self.peer_pinned = true;
                Ok(ContactOutcome::Done)
            }
            ContactMessage::End => {
                self.channel.close();
                Ok(ContactOutcome::Done)
            }
            _ => Err(refused("unexpected message")),
        }
    }

    fn peer_card(&self) -> Option<&SignedContactCard> {
        if self.released && !self.failed {
            self.peer.as_ref()
        } else {
            None
        }
    }

    fn confirm_pinned(&mut self, now: i64) -> Result<Vec<u8>> {
        self.live()?;
        if !self.released || self.pinned_sent {
            return Err(refused("nothing pinned"));
        }
        let frame = self
            .channel
            .seal_bytes_at(&ContactMessage::Confirmed.encode()?, false, now)?;
        self.pinned_sent = true;
        Ok(frame)
    }

    fn end(&mut self, now: i64) -> Result<Vec<u8>> {
        self.live()?;
        self.channel
            .seal_bytes_at(&ContactMessage::End.encode()?, true, now)
    }

    #[cfg(all(feature = "dev-fast-kdf", debug_assertions))]
    fn test_seal(&mut self, msg: &ContactMessage, now: i64) -> Result<Vec<u8>> {
        self.channel
            .seal_bytes_at(&msg.encode()?, *msg == ContactMessage::End, now)
    }
}

/// A card a device speaks for: its signatures and params (`keys`), its
/// lineage from its own genesis (`Integrity(Signature)`), the proof of
/// possession of `device` over `transcript` (`Integrity(Signature)`), and
/// `device`, with the same keys, in the roster of the card's head and
/// revoked by none of its records (`Integrity(WrongContext)`): a card
/// replayed by a device the account does not list is refused.
fn check_card(
    card: &SignedContactCard,
    device: &DevicePublic,
    pop: &HybridSignature,
    transcript: &[u8; 32],
) -> Result<()> {
    card.keys()?;
    check_card_lineage(card)?;
    verify_pop(transcript, device, pop)?;
    let c = &card.card;
    let revoked: BTreeSet<Id> = c
        .lineage
        .iter()
        .filter_map(|r| match r {
            LineageRecord::Rotation(s) => Some(s.body.revoked.iter().copied()),
            LineageRecord::Genesis(_) => None,
        })
        .flatten()
        .collect();
    let roster = roster_at(&c.lineage, &c.intros, &c.legacy(), &c.head.hash)?;
    let listed = roster.iter().any(|e| {
        e.device_id == device.device_id
            && e.sign_pub == device.sign_pub
            && e.kem_pub == device.kem_pub
            && !revoked.contains(&e.device_id)
    });
    if !listed {
        return Err(IntegrityError::WrongContext.into());
    }
    Ok(())
}

/// The side that shows the QR.
pub struct ContactResponder {
    /// Dropped (and wiped) as soon as the key exchange is handled.
    secret: Option<HybridKemSecret>,
    session_id: [u8; 16],
    expires_at: i64,
    transcript: [u8; 32],
    session: Option<Session>,
}

impl ContactResponder {
    /// A fresh session: an ephemeral key pair and session id, the QR to
    /// show (valid `QR_LIFETIME_SECS` from `now`) and the Hello to send.
    pub fn new(now: i64) -> Result<(ContactResponder, PairingQr, Vec<u8>)> {
        let secret = HybridKemSecret::generate()?;
        let public = secret.public()?;
        let session_id = random_array()?;
        let qr = PairingQr {
            version: QR_VERSION,
            session_id,
            key_hash: sha256(&public.to_bytes()),
            expires_at: now.checked_add(QR_LIFETIME_SECS).ok_or(refused("time"))?,
        };
        let hello = ContactHello {
            session_id,
            ephemeral_public: public,
        }
        .to_bytes()?;
        let responder = ContactResponder {
            secret: Some(secret),
            session_id,
            expires_at: qr.expires_at,
            transcript: transcript(&qr.to_text(), &hello),
            session: None,
        };
        Ok((responder, qr, hello))
    }

    /// Take the session key from the initiator's KeyExchange and return the
    /// SAS to show. Refused after the QR expired, or a second time. Any
    /// failure ends the session: the user shows a new QR.
    pub fn on_key_exchange(&mut self, kx: &[u8], now: i64) -> Result<String> {
        let secret = self
            .secret
            .take()
            .ok_or(refused("unexpected key exchange"))?;
        if now > self.expires_at {
            return Err(refused("qr expired"));
        }
        let kx = KeyExchange::from_bytes(kx)?;
        let k = unwrap_key_labeled(&secret, &kx.envelope, CONTACT_LABEL, &self.transcript)?;
        drop(secret);
        let code = sas(&k, &self.transcript)?;
        self.session = Some(Session::new(
            Channel::newcomer(&k, self.session_id)?,
            self.transcript,
        ));
        Ok(code)
    }

    fn session(&mut self) -> Result<&mut Session> {
        self.session.as_mut().ok_or(refused("no channel"))
    }

    /// The local user confirmed the SAS: the frame carrying `card` (this
    /// account's own card) and the proof of possession of `keys`, the keys
    /// of device `me`, over the transcript. Refused before the SAS exists,
    /// a second time, for a card this device does not speak for (the
    /// checks the peer runs), or when the peer's waiting card is of the
    /// same account (`Validation`, the session closes). Once sent, a peer
    /// card that came earlier is in `peer_card`.
    pub fn confirm_and_send_card(
        &mut self,
        card: &SignedContactCard,
        keys: &DeviceKeys,
        me: Id,
        now: i64,
    ) -> Result<Vec<u8>> {
        self.session()?.confirm_and_send_card(card, keys, me, now)
    }

    /// Open a frame from the initiator. A card that fails a check, a card
    /// of this side's own account (`Validation`), a second card, a
    /// `Confirmed` before both cards, or any bad frame closes the session.
    pub fn on_frame(&mut self, frame: &[u8], now: i64) -> Result<ContactOutcome> {
        self.session()?.on_frame(frame, now)
    }

    /// The peer's checked card, once the local user confirmed.
    pub fn peer_card(&self) -> Option<&SignedContactCard> {
        self.session.as_ref().and_then(Session::peer_card)
    }

    /// The `Confirmed` frame, once the peer's card was handed over.
    pub fn confirm_pinned(&mut self, now: i64) -> Result<Vec<u8>> {
        self.session()?.confirm_pinned(now)
    }

    /// The `End` frame; the session is over.
    pub fn end(&mut self, now: i64) -> Result<Vec<u8>> {
        self.session()?.end(now)
    }

    /// `SHA-256(QR text || Hello bytes)`, what the contact entry keeps.
    pub fn transcript_hash(&self) -> [u8; 32] {
        self.transcript
    }

    pub fn expires_at(&self) -> i64 {
        self.expires_at
    }

    /// Seal any message on the raw channel, for the hostile-peer tests.
    #[cfg(all(feature = "dev-fast-kdf", debug_assertions))]
    #[doc(hidden)]
    pub fn test_seal(&mut self, msg: &ContactMessage, now: i64) -> Result<Vec<u8>> {
        self.session()?.test_seal(msg, now)
    }
}

/// The side that scans the QR.
pub struct ContactInitiator {
    session: Session,
}

impl ContactInitiator {
    /// Check a scanned QR and the Hello it commits to, and answer with the
    /// KeyExchange to send and the SAS to show.
    ///
    /// Refused: a QR that is not canonical, expired (`now > expires_at`),
    /// or issued more than `CLOCK_SKEW_SECS` after `now`; a Hello that is
    /// not a contact Hello (`InvalidFormat`: a pairing Hello is one); a
    /// Hello for another session or whose key does not hash to the QR's
    /// `key_hash` (`IntegrityError::WrongContext`).
    pub fn begin(
        qr_text: &str,
        hello: &[u8],
        now: i64,
    ) -> Result<(ContactInitiator, Vec<u8>, String)> {
        let qr = PairingQr::parse(qr_text)?;
        if now > qr.expires_at {
            return Err(refused("qr expired"));
        }
        let earliest = qr
            .expires_at
            .saturating_sub(QR_LIFETIME_SECS)
            .saturating_sub(CLOCK_SKEW_SECS);
        if now < earliest {
            return Err(refused("qr from the future"));
        }
        let h = ContactHello::from_bytes(hello)?;
        if h.session_id != qr.session_id || sha256(&h.ephemeral_public.to_bytes()) != qr.key_hash {
            return Err(IntegrityError::WrongContext.into());
        }
        let t = transcript(qr_text, hello);
        let k = SymmetricKey::generate()?;
        let envelope = wrap_key_labeled(&h.ephemeral_public, &k, CONTACT_LABEL, &t)?;
        let code = sas(&k, &t)?;
        let initiator = ContactInitiator {
            session: Session::new(Channel::approver(&k, h.session_id)?, t),
        };
        Ok((initiator, KeyExchange { envelope }.to_bytes(), code))
    }

    /// See `ContactResponder::confirm_and_send_card`.
    pub fn confirm_and_send_card(
        &mut self,
        card: &SignedContactCard,
        keys: &DeviceKeys,
        me: Id,
        now: i64,
    ) -> Result<Vec<u8>> {
        self.session.confirm_and_send_card(card, keys, me, now)
    }

    /// See `ContactResponder::on_frame`.
    pub fn on_frame(&mut self, frame: &[u8], now: i64) -> Result<ContactOutcome> {
        self.session.on_frame(frame, now)
    }

    /// The peer's checked card, once the local user confirmed.
    pub fn peer_card(&self) -> Option<&SignedContactCard> {
        self.session.peer_card()
    }

    /// The `Confirmed` frame, once the peer's card was handed over.
    pub fn confirm_pinned(&mut self, now: i64) -> Result<Vec<u8>> {
        self.session.confirm_pinned(now)
    }

    /// The `End` frame; the session is over.
    pub fn end(&mut self, now: i64) -> Result<Vec<u8>> {
        self.session.end(now)
    }

    /// `SHA-256(QR text || Hello bytes)`, what the contact entry keeps.
    pub fn transcript_hash(&self) -> [u8; 32] {
        self.session.transcript
    }

    /// Seal any message on the raw channel, for the hostile-peer tests.
    #[cfg(all(feature = "dev-fast-kdf", debug_assertions))]
    #[doc(hidden)]
    pub fn test_seal(&mut self, msg: &ContactMessage, now: i64) -> Result<Vec<u8>> {
        self.session.test_seal(msg, now)
    }
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ContactSession")
            .field("confirmed", &self.confirmed)
            .field("released", &self.released)
            .field("pinned_sent", &self.pinned_sent)
            .field("peer_pinned", &self.peer_pinned)
            .field("failed", &self.failed)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for ContactResponder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ContactResponder")
            .field("expires_at", &self.expires_at)
            .field("session", &self.session)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for ContactInitiator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ContactInitiator")
            .field("session", &self.session)
            .finish_non_exhaustive()
    }
}

impl<S: RecordStore> Repository<S> {
    /// Pin the peer's card from a face-to-face session at `Verified`, with
    /// the session's transcript hash (`pin_contact`, whose refusals apply:
    /// this account's own card is `Validation`, nothing written).
    pub fn finish_contact_session(
        &mut self,
        peer: &SignedContactCard,
        transcript_hash: [u8; 32],
        now: i64,
    ) -> Result<ContactEntry> {
        self.pin_contact(peer, ContactLevel::Verified, transcript_hash, now)
    }
}
