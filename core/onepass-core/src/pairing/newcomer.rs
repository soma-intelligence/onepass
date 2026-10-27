//! The new device: shows the QR, decapsulates the session key, and takes a
//! grant only after its own user confirmed the SAS.

use std::fmt;

use crate::Result;
use crate::crypto::kem::unwrap_key_labeled;
use crate::crypto::{HybridKemSecret, SecretKey, random_array};
use crate::devices::{DeviceMode, check_name};

use super::channel::Channel;
use super::messages::{DeviceInfo, Grant, Hello, KeyExchange, Message};
use super::qr::{PairingQr, QR_VERSION};
use super::snapshot::check_snapshot;
use super::{KEM_LABEL, QR_LIFETIME_SECS, now_unix, refused, sas, sha256, transcript};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    AwaitingKey,
    /// The SAS is shown, the user has not confirmed yet.
    KeyReady,
    Confirmed,
    Granted,
    Failed,
}

pub struct Newcomer {
    /// Dropped (and wiped) as soon as the key exchange is handled.
    secret: Option<HybridKemSecret>,
    session_id: [u8; 16],
    expires_at: i64,
    mode: DeviceMode,
    transcript: [u8; 32],
    channel: Option<Channel>,
    state: State,
    public_granted: bool,
    acked: bool,
}

impl Newcomer {
    /// A fresh session: a new ephemeral key pair and session id, the QR to
    /// show (valid `QR_LIFETIME_SECS` from `now`) and the Hello to send.
    pub fn new(
        device: DeviceInfo,
        mode: DeviceMode,
        now: i64,
    ) -> Result<(Newcomer, PairingQr, Vec<u8>)> {
        check_name(&device.name)?;
        let secret = HybridKemSecret::generate()?;
        let public = secret.public()?;
        let session_id = random_array()?;
        let qr = PairingQr {
            version: QR_VERSION,
            session_id,
            key_hash: sha256(&public.to_bytes()),
            expires_at: now.checked_add(QR_LIFETIME_SECS).ok_or(refused("time"))?,
        };
        let hello = Hello {
            session_id,
            ephemeral_public: public,
            device,
            requested_mode: mode,
        }
        .to_bytes()?;
        let newcomer = Newcomer {
            secret: Some(secret),
            session_id,
            expires_at: qr.expires_at,
            mode,
            transcript: transcript(&qr.to_text(), &hello),
            channel: None,
            state: State::AwaitingKey,
            public_granted: false,
            acked: false,
        };
        Ok((newcomer, qr, hello))
    }

    pub fn session_id(&self) -> [u8; 16] {
        self.session_id
    }

    pub fn expires_at(&self) -> i64 {
        self.expires_at
    }

    /// Take the session key from the approver's KeyExchange and return the
    /// SAS to show. Refused after the QR expired. Any failure ends the
    /// session: the user scans a new QR.
    pub fn on_key_exchange(&mut self, bytes: &[u8], now: i64) -> Result<String> {
        if self.state != State::AwaitingKey {
            return Err(refused("unexpected key exchange"));
        }
        let r = self.take_key(bytes, now);
        self.state = if r.is_ok() {
            State::KeyReady
        } else {
            State::Failed
        };
        r
    }

    fn take_key(&mut self, bytes: &[u8], now: i64) -> Result<String> {
        let secret = self.secret.take().ok_or(refused("no key"))?;
        if now > self.expires_at {
            return Err(refused("qr expired"));
        }
        let kx = KeyExchange::from_bytes(bytes)?;
        let k = unwrap_key_labeled(&secret, &kx.envelope, KEM_LABEL, &self.transcript)?;
        drop(secret);
        let code = sas(&k, &self.transcript)?;
        self.channel = Some(Channel::newcomer(&k, self.session_id)?);
        Ok(code)
    }

    /// The user confirmed the codes match: the `Confirmed` frame to send.
    pub fn confirm(&mut self) -> Result<Vec<u8>> {
        if self.state != State::KeyReady {
            return Err(refused("nothing to confirm"));
        }
        let frame = self.channel_mut()?.seal(&Message::Confirmed)?;
        self.state = State::Confirmed;
        Ok(frame)
    }

    pub fn open(&mut self, frame: &[u8]) -> Result<Message> {
        self.open_at(frame, now_unix())
    }

    /// Open a frame from the approver: a grant (once, after `confirm`,
    /// matching the requested mode) or `End`. Anything else, or a grant
    /// that fails its checks, ends the session.
    pub fn open_at(&mut self, frame: &[u8], now: i64) -> Result<Message> {
        let msg = self.channel_mut()?.open_at(frame, now)?;
        let r = match &msg {
            Message::Grant(g) if self.state == State::Confirmed => self.accept(g, now),
            Message::Grant(_) => Err(refused("grant before confirmation")),
            Message::End => Ok(()),
            _ => Err(refused("unexpected message")),
        };
        if let Err(e) = r {
            self.fail();
            return Err(e);
        }
        Ok(msg)
    }

    fn accept(&mut self, grant: &Grant, now: i64) -> Result<()> {
        match grant {
            Grant::Public(g) if self.mode == DeviceMode::Public => {
                if g.session_id != self.session_id || !g.read_only || g.expires_at <= now {
                    return Err(refused("public grant"));
                }
                self.channel_mut()?.set_expiry(g.expires_at);
                self.public_granted = true;
            }
            Grant::Full(g) if self.mode != DeviceMode::Public && g.mode == self.mode => {
                SecretKey::parse(&g.secret_key)?;
                check_snapshot(&g.snapshot)?;
            }
            _ => return Err(refused("grant does not match the requested mode")),
        }
        self.state = State::Granted;
        Ok(())
    }

    pub fn seal(&mut self, msg: &Message) -> Result<Vec<u8>> {
        self.seal_at(msg, now_unix())
    }

    /// Seal `Ack` (once, after the grant), `Audit` (public session, after
    /// the grant) or `End`. `Confirmed` goes through `confirm`.
    pub fn seal_at(&mut self, msg: &Message, now: i64) -> Result<Vec<u8>> {
        let granted = self.state == State::Granted;
        match msg {
            Message::Ack if granted && !self.acked => {}
            Message::Audit(_) if granted && self.public_granted => {}
            Message::End => {}
            _ => return Err(refused("message not allowed now")),
        }
        let frame = self.channel_mut()?.seal_at(msg, now)?;
        if *msg == Message::Ack {
            self.acked = true;
        }
        Ok(frame)
    }

    fn channel_mut(&mut self) -> Result<&mut Channel> {
        match (&mut self.channel, self.state) {
            (Some(c), s) if s != State::Failed => Ok(c),
            _ => Err(refused("no channel")),
        }
    }

    fn fail(&mut self) {
        if let Some(c) = &mut self.channel {
            c.close();
        }
        self.state = State::Failed;
    }
}

impl fmt::Debug for Newcomer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Newcomer")
            .field("state", &self.state)
            .field("mode", &self.mode)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::devices::DeviceKind;
    use crate::pairing::approver::Approver;
    use crate::pairing::messages::FullGrant;
    use crate::{Error, Id};
    use zeroize::Zeroizing;

    const NOW: i64 = 1_790_000_000;

    fn grant() -> Message {
        Message::Grant(Grant::Full(FullGrant {
            account_id: Id::new(),
            secret_key: Zeroizing::new(SecretKey::generate().unwrap().to_display()),
            mode: DeviceMode::Personal,
            device_id: Id::new(),
            snapshot: vec![],
        }))
    }

    #[test]
    fn grant_before_own_confirmation_is_refused() {
        // A hostile approver seals a grant on its raw channel before the
        // newcomer's user confirmed.
        let device = DeviceInfo {
            device_id: Id::new(),
            name: "iPhone de Camille".into(),
            kind: DeviceKind::Phone,
        };
        let (mut n, qr, hello) = Newcomer::new(device, DeviceMode::Personal, NOW).unwrap();
        let (mut a, kx, _, _, _) = Approver::begin(&qr.to_text(), &hello, NOW + 1).unwrap();
        n.on_key_exchange(&kx, NOW + 2).unwrap();
        let frame = a.channel.seal_at(&grant(), NOW + 3).unwrap();
        assert!(n.open_at(&frame, NOW + 3).is_err());
        // The session is over.
        assert!(n.confirm().is_err());
        assert!(n.seal_at(&Message::End, NOW + 4).is_err());
    }

    #[test]
    fn steps_out_of_order_are_refused() {
        let device = DeviceInfo {
            device_id: Id::new(),
            name: "iPhone de Camille".into(),
            kind: DeviceKind::Phone,
        };
        let (mut n, qr, hello) = Newcomer::new(device, DeviceMode::Personal, NOW).unwrap();
        assert!(n.confirm().is_err());
        assert!(n.seal_at(&Message::Ack, NOW).is_err());
        let (_, kx, _, _, _) = Approver::begin(&qr.to_text(), &hello, NOW + 1).unwrap();
        n.on_key_exchange(&kx, NOW + 2).unwrap();
        assert!(n.secret.is_none(), "ephemeral secret kept");
        assert!(n.on_key_exchange(&kx, NOW + 2).is_err());
        assert!(n.seal_at(&Message::Ack, NOW + 2).is_err());
        n.confirm().unwrap();
        assert!(n.confirm().is_err());
        assert!(!format!("{n:?}").contains("secret"));
    }

    #[test]
    fn a_bad_name_is_refused() {
        let device = DeviceInfo {
            device_id: Id::new(),
            name: String::new(),
            kind: DeviceKind::Phone,
        };
        assert!(matches!(
            Newcomer::new(device, DeviceMode::Personal, NOW),
            Err(Error::Validation(_))
        ));
    }
}
