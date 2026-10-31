//! The unlocked device that scans the QR: checks the commitment, sends the
//! session key, and grants only after both confirmations.

use std::fmt;

use crate::crypto::kem::wrap_key_labeled;
use crate::crypto::{HybridSignature, SecretKey, SymmetricKey};
use crate::device_keys::{DevicePublic, verify_pop};
use crate::devices::DeviceMode;
use crate::{Id, IntegrityError, Result};

use super::channel::Channel;
use super::messages::{DeviceInfo, Grant, Hello, KeyExchange, Message, ProfileCard};
use super::qr::PairingQr;
use super::snapshot::check_snapshot;
use super::{
    CLOCK_SKEW_SECS, KEM_LABEL, QR_LIFETIME_SECS, now_unix, refused, sas, sha256, transcript,
};

pub struct Approver {
    pub(crate) channel: Channel,
    session_id: [u8; 16],
    requested: DeviceMode,
    peer_confirmed: bool,
    /// `Some(public)` once a grant went out.
    granted: Option<bool>,
    acked: bool,
    /// Started from an invite: the newcomer takes a `Profile`.
    invite: bool,
    profile_sent: bool,
    /// `SHA-256(QR text || Hello)`: the context of the newcomer's first
    /// proof of possession (spec 5.2).
    transcript: [u8; 32],
    /// The id the Hello asked to be listed under.
    peer_id: Id,
    /// Key rotation v2: the newcomer's device key, from its
    /// `ConfirmedWithKey` (pop over the transcript verified). `None` for a
    /// legacy newcomer (`Confirmed`).
    peer_key: Option<DevicePublic>,
    /// The account a `FullV2` granted, for the second proof of possession.
    granted_account: Option<Id>,
    /// The newcomer's proof of possession over the granted account id, from
    /// its second `ConfirmedWithKey` (its acknowledgment): what the intro
    /// carries (spec 6.4).
    account_pop: Option<HybridSignature>,
}

impl Approver {
    /// Check a scanned QR and the Hello it commits to, and answer with the
    /// KeyExchange to send. Also returns the SAS to show, and the device
    /// and mode the approval screen names.
    ///
    /// Refused: a QR that is not canonical, expired (`now > expires_at`),
    /// or issued more than `CLOCK_SKEW_SECS` after `now`; a Hello for
    /// another session or whose key does not hash to the QR's `key_hash`
    /// (`IntegrityError::WrongContext`).
    pub fn begin(
        qr_text: &str,
        hello: &[u8],
        now: i64,
    ) -> Result<(Approver, Vec<u8>, String, DeviceInfo, DeviceMode)> {
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
        let h = Hello::from_bytes(hello)?;
        if h.session_id != qr.session_id || sha256(&h.ephemeral_public.to_bytes()) != qr.key_hash {
            return Err(IntegrityError::WrongContext.into());
        }
        Approver::start(qr_text, hello, h, false)
    }

    /// The key exchange for a checked Hello: `qr_text` is the text both
    /// sides hash into the transcript (the newcomer's QR, or the invite).
    pub(super) fn start(
        qr_text: &str,
        hello: &[u8],
        h: Hello,
        invite: bool,
    ) -> Result<(Approver, Vec<u8>, String, DeviceInfo, DeviceMode)> {
        let t = transcript(qr_text, hello);
        let k = SymmetricKey::generate()?;
        let envelope = wrap_key_labeled(&h.ephemeral_public, &k, KEM_LABEL, &t)?;
        let code = sas(&k, &t)?;
        let approver = Approver {
            channel: Channel::approver(&k, h.session_id)?,
            session_id: h.session_id,
            requested: h.requested_mode,
            peer_confirmed: false,
            granted: None,
            acked: false,
            invite,
            profile_sent: false,
            transcript: t,
            peer_id: h.device.device_id,
            peer_key: None,
            granted_account: None,
            account_pop: None,
        };
        let kx = KeyExchange { envelope }.to_bytes();
        Ok((approver, kx, code, h.device, h.requested_mode))
    }

    pub fn on_frame(&mut self, frame: &[u8]) -> Result<Message> {
        self.on_frame_at(frame, now_unix())
    }

    /// Open a frame from the newcomer: `Confirmed` or `ConfirmedWithKey`
    /// first (recorded), then the acknowledgment after the grant (`Ack`, or
    /// for a `FullV2` the second `ConfirmedWithKey`), `Audit` in a public
    /// session, or `End`. Anything else ends the session.
    ///
    /// A `ConfirmedWithKey` is refused, and the session ended, unless its
    /// device id is the Hello's and its proof of possession verifies: over
    /// the transcript hash the first time (spec 5.2), over the granted
    /// account id the second time, for the same device key.
    pub fn on_frame_at(&mut self, frame: &[u8], now: i64) -> Result<Message> {
        let msg = self.channel.open_at(frame, now)?;
        let v2 = self.peer_key.is_some();
        let ok = match &msg {
            Message::Confirmed => !self.peer_confirmed && self.granted.is_none(),
            // A public device has no device key to pin.
            Message::ConfirmedWithKey { .. } if !self.peer_confirmed => {
                self.granted.is_none() && self.requested != DeviceMode::Public
            }
            Message::ConfirmedWithKey { .. } => {
                self.granted_account.is_some() && self.account_pop.is_none()
            }
            Message::Ack => self.granted.is_some() && !self.acked && !v2,
            Message::Audit(_) => self.granted == Some(true),
            Message::End => true,
            Message::Grant(_) | Message::Profile(_) => false,
        };
        let checked = if ok { self.check_key(&msg) } else { Ok(()) };
        if !ok || checked.is_err() {
            self.channel.close();
            return Err(checked
                .err()
                .unwrap_or_else(|| refused("unexpected message")));
        }
        match &msg {
            Message::Confirmed => self.peer_confirmed = true,
            Message::ConfirmedWithKey { device, .. } if !self.peer_confirmed => {
                self.peer_confirmed = true;
                self.peer_key = Some(device.clone());
            }
            Message::ConfirmedWithKey { pop, .. } => {
                self.account_pop = Some(pop.clone());
                self.acked = true;
            }
            Message::Ack => self.acked = true,
            _ => {}
        }
        Ok(msg)
    }

    /// The proof of possession of a `ConfirmedWithKey`.
    fn check_key(&self, msg: &Message) -> Result<()> {
        let Message::ConfirmedWithKey { device, pop, .. } = msg else {
            return Ok(());
        };
        if device.device_id != self.peer_id {
            return Err(refused("device id"));
        }
        match (&self.peer_key, self.granted_account) {
            (None, _) => verify_pop(&self.transcript, device, pop),
            (Some(first), Some(account)) if first == device => verify_pop(&account.0, device, pop),
            _ => Err(refused("device key")),
        }
    }

    /// The newcomer's device key, once its `ConfirmedWithKey` arrived (its
    /// proof of possession over the transcript verified). `None` for a
    /// legacy newcomer: it pairs as before and is trusted on first use
    /// (spec 15).
    pub fn newcomer_key(&self) -> Option<&DevicePublic> {
        self.peer_key.as_ref()
    }

    /// The newcomer's proof of possession over the granted account id, once
    /// its acknowledgment of a `FullV2` arrived: with `newcomer_key`, what
    /// the approver's intro carries (`Repository::introduce`).
    pub fn newcomer_account_pop(&self) -> Option<&HybridSignature> {
        self.account_pop.as_ref()
    }

    pub fn seal_grant(&mut self, grant: Grant, user_confirmed: bool) -> Result<Vec<u8>> {
        self.seal_grant_at(grant, user_confirmed, now_unix())
    }

    /// Seal the one grant of the session. Refused unless the newcomer's
    /// `Confirmed` arrived and `user_confirmed` (the local user confirmed
    /// the SAS and passed the presence check), and unless the grant
    /// matches the requested mode: a `PublicGrant` for a public request
    /// (this session, read only, not yet expired), a `FullGrant` of the
    /// requested mode otherwise, with a snapshot within the cap. A
    /// newcomer that sent its device key gets a `FullV2` (its trust
    /// snapshot well formed and of the granted account), a legacy one a
    /// `Full`: an older newcomer cannot read a `FullV2`, and a newer one
    /// refuses a `Full` (a downgrade).
    pub fn seal_grant_at(
        &mut self,
        grant: Grant,
        user_confirmed: bool,
        now: i64,
    ) -> Result<Vec<u8>> {
        if self.granted.is_some() {
            return Err(refused("already granted"));
        }
        if !self.peer_confirmed || !user_confirmed {
            return Err(refused("not confirmed"));
        }
        let expiry = match &grant {
            Grant::Public(g) if self.requested == DeviceMode::Public => {
                if g.session_id != self.session_id || !g.read_only || g.expires_at <= now {
                    return Err(refused("public grant"));
                }
                Some(g.expires_at)
            }
            Grant::Full(g)
                if self.requested != DeviceMode::Public
                    && g.mode == self.requested
                    && self.peer_key.is_none() =>
            {
                SecretKey::parse(&g.secret_key)?;
                check_snapshot(&g.snapshot)?;
                None
            }
            Grant::FullV2(g)
                if self.requested != DeviceMode::Public
                    && g.full.mode == self.requested
                    && g.full.device_id == self.peer_id
                    && self.peer_key.is_some() =>
            {
                SecretKey::parse(&g.full.secret_key)?;
                check_snapshot(&g.full.snapshot)?;
                g.check()?;
                None
            }
            _ => return Err(refused("grant does not match the requested mode")),
        };
        let account = match &grant {
            Grant::FullV2(g) => Some(g.full.account_id),
            _ => None,
        };
        let frame = self.channel.seal_at(&Message::Grant(grant), now)?;
        self.granted_account = account;
        if let Some(e) = expiry {
            self.channel.set_expiry(e);
        }
        self.granted = Some(expiry.is_some());
        Ok(frame)
    }

    pub fn seal(&mut self, msg: &Message) -> Result<Vec<u8>> {
        self.seal_at(msg, now_unix())
    }

    /// Seal the account's profile, once, in an invite session, after both
    /// confirmations and before a full grant (`user_confirmed` as for the
    /// grant). Refused in a session from the newcomer's QR: an older
    /// newcomer would not read it.
    pub fn seal_profile_at(
        &mut self,
        card: ProfileCard,
        user_confirmed: bool,
        now: i64,
    ) -> Result<Vec<u8>> {
        if !self.invite || self.profile_sent || self.granted.is_some() {
            return Err(refused("profile not allowed now"));
        }
        if !self.peer_confirmed || !user_confirmed {
            return Err(refused("not confirmed"));
        }
        if self.requested == DeviceMode::Public {
            return Err(refused("profile for a public session"));
        }
        card.check()?;
        let frame = self.channel.seal_at(&Message::Profile(card), now)?;
        self.profile_sent = true;
        Ok(frame)
    }

    /// Seal `End`: the grant goes through `seal_grant`.
    pub fn seal_at(&mut self, msg: &Message, now: i64) -> Result<Vec<u8>> {
        if *msg != Message::End {
            return Err(refused("message not allowed now"));
        }
        self.channel.seal_at(msg, now)
    }
}

impl fmt::Debug for Approver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Approver")
            .field("requested", &self.requested)
            .field("peer_confirmed", &self.peer_confirmed)
            .field("granted", &self.granted)
            .field("acked", &self.acked)
            .field("v2", &self.peer_key.is_some())
            .finish_non_exhaustive()
    }
}
