//! The unlocked device that scans the QR: checks the commitment, sends the
//! session key, and grants only after both confirmations.

use std::fmt;

use crate::crypto::kem::wrap_key_labeled;
use crate::crypto::{SecretKey, SymmetricKey};
use crate::devices::DeviceMode;
use crate::{IntegrityError, Result};

use super::channel::Channel;
use super::messages::{DeviceInfo, Grant, Hello, KeyExchange, Message};
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

        let t = transcript(qr_text, hello);
        let k = SymmetricKey::generate()?;
        let envelope = wrap_key_labeled(&h.ephemeral_public, &k, KEM_LABEL, &t)?;
        let code = sas(&k, &t)?;
        let approver = Approver {
            channel: Channel::approver(&k, qr.session_id)?,
            session_id: qr.session_id,
            requested: h.requested_mode,
            peer_confirmed: false,
            granted: None,
            acked: false,
        };
        let kx = KeyExchange { envelope }.to_bytes();
        Ok((approver, kx, code, h.device, h.requested_mode))
    }

    pub fn on_frame(&mut self, frame: &[u8]) -> Result<Message> {
        self.on_frame_at(frame, now_unix())
    }

    /// Open a frame from the newcomer: `Confirmed` first (recorded), then
    /// `Ack` after the grant, `Audit` in a public session, or `End`.
    /// Anything else ends the session.
    pub fn on_frame_at(&mut self, frame: &[u8], now: i64) -> Result<Message> {
        let msg = self.channel.open_at(frame, now)?;
        let ok = match &msg {
            Message::Confirmed => !self.peer_confirmed && self.granted.is_none(),
            Message::Ack => self.granted.is_some() && !self.acked,
            Message::Audit(_) => self.granted == Some(true),
            Message::End => true,
            Message::Grant(_) => false,
        };
        if !ok {
            self.channel.close();
            return Err(refused("unexpected message"));
        }
        match msg {
            Message::Confirmed => self.peer_confirmed = true,
            Message::Ack => self.acked = true,
            _ => {}
        }
        Ok(msg)
    }

    pub fn seal_grant(&mut self, grant: Grant, user_confirmed: bool) -> Result<Vec<u8>> {
        self.seal_grant_at(grant, user_confirmed, now_unix())
    }

    /// Seal the one grant of the session. Refused unless the newcomer's
    /// `Confirmed` arrived and `user_confirmed` (the local user confirmed
    /// the SAS and passed the presence check), and unless the grant
    /// matches the requested mode: a `PublicGrant` for a public request
    /// (this session, read only, not yet expired), a `FullGrant` of the
    /// requested mode otherwise, with a snapshot within the cap.
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
            Grant::Full(g) if self.requested != DeviceMode::Public && g.mode == self.requested => {
                SecretKey::parse(&g.secret_key)?;
                check_snapshot(&g.snapshot)?;
                None
            }
            _ => return Err(refused("grant does not match the requested mode")),
        };
        let frame = self.channel.seal_at(&Message::Grant(grant), now)?;
        if let Some(e) = expiry {
            self.channel.set_expiry(e);
        }
        self.granted = Some(expiry.is_some());
        Ok(frame)
    }

    pub fn seal(&mut self, msg: &Message) -> Result<Vec<u8>> {
        self.seal_at(msg, now_unix())
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
            .finish_non_exhaustive()
    }
}
