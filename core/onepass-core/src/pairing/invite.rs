//! The other direction: the unlocked device shows an invite QR and the new
//! device scans it (a Mac approves without a camera). The key exchange, the
//! SAS, the channel and the grants are the ones of the QR the newcomer
//! shows; only the first two steps change.
//!
//! 1. A draws a random 16-byte `session_id` and a 32-byte `secret`, and
//!    shows `"OPJOIN1:" || BASE32(postcard(InviteQr))`, `InviteQr =
//!    {version: u8 = 1, session_id, secret, expires_at = issue + 120}` (the
//!    layout of `PairingQr`). A publishes the service named after
//!    `session_id`: the name is public, the secret only on A's screen.
//! 2. N scans it, refuses an invite past `expires_at + CLOCK_SKEW_SECS` on
//!    its own clock, draws its ephemeral pair and sends
//!    `Hello || HMAC-SHA256(hello_key, Hello)`, `hello_key =
//!    HKDF-SHA256(salt = empty, ikm = secret, info =
//!    "onepass/pairing/invite/hello/v1")`. N gives up the key exchange 120 s
//!    after it scanned.
//! 3. A refuses a frame whose tag does not verify, a Hello for another
//!    session, or any frame after `expires_at` or after one was accepted;
//!    a refused frame does not spend the invite. Then step 3 of the main
//!    protocol, with `transcript = SHA-256(invite text || Hello)`: the
//!    secret is in the transcript, so a key exchange wrapped by anyone who
//!    did not read the screen does not open, and the session key A wraps
//!    opens only for the Hello it checked.

use std::fmt;

use aws_lc_rs::hmac::{self, HMAC_SHA256};

use crate::crypto::key::hkdf32;
use crate::crypto::random_array;
use crate::devices::DeviceMode;
use crate::{IntegrityError, Result};

use super::approver::Approver;
use super::messages::{DeviceInfo, Hello};
use super::qr::{InviteQr, QR_VERSION};
use super::{CLOCK_SKEW_SECS, QR_LIFETIME_SECS, refused};

const HELLO_TAG_INFO: &[u8] = b"onepass/pairing/invite/hello/v1";
/// Length of the HMAC-SHA256 tag after the Hello.
pub const HELLO_TAG_LEN: usize = 32;

/// The approver's open invite: one key exchange at most.
pub struct Invite {
    text: String,
    session_id: [u8; 16],
    expires_at: i64,
    hello_key: hmac::Key,
    used: bool,
}

impl Invite {
    /// A fresh invite, valid `QR_LIFETIME_SECS` from `now`.
    pub fn new(now: i64) -> Result<Invite> {
        let qr = InviteQr {
            version: QR_VERSION,
            session_id: random_array()?,
            secret: random_array()?,
            expires_at: now.checked_add(QR_LIFETIME_SECS).ok_or(refused("time"))?,
        };
        Ok(Invite {
            text: qr.to_text(),
            session_id: qr.session_id,
            expires_at: qr.expires_at,
            hello_key: hello_key(&qr.secret)?,
            used: false,
        })
    }

    /// The text to show as a QR code. It carries the secret: never log it.
    pub fn qr_text(&self) -> &str {
        &self.text
    }

    pub fn session_id(&self) -> [u8; 16] {
        self.session_id
    }

    pub fn expires_at(&self) -> i64 {
        self.expires_at
    }

    /// Check a connection's first frame (`Hello || tag`) and start the
    /// session: the KeyExchange to send, the SAS, and the device and mode
    /// to name. A refused frame leaves the invite open for the next
    /// connection; an accepted one spends it.
    pub fn accept(
        &mut self,
        frame: &[u8],
        now: i64,
    ) -> Result<(Approver, Vec<u8>, String, DeviceInfo, DeviceMode)> {
        if self.used {
            return Err(refused("invite used"));
        }
        if now > self.expires_at {
            return Err(refused("invite expired"));
        }
        if frame.len() <= HELLO_TAG_LEN {
            return Err(IntegrityError::WrongContext.into());
        }
        let (hello, tag) = frame.split_at(frame.len() - HELLO_TAG_LEN);
        hmac::verify(&self.hello_key, hello, tag).map_err(|_| IntegrityError::WrongContext)?;
        let h = Hello::from_bytes(hello)?;
        if h.session_id != self.session_id {
            return Err(IntegrityError::WrongContext.into());
        }
        let started = Approver::start(&self.text, hello, h)?;
        self.used = true;
        Ok(started)
    }
}

impl fmt::Debug for Invite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Invite")
            .field("expires_at", &self.expires_at)
            .field("used", &self.used)
            .finish_non_exhaustive()
    }
}

/// The newcomer's checks on a scanned invite, then its Hello signed with
/// the invite's secret. Returns the parsed invite and the frame to send.
pub(super) fn signed_hello(
    invite_text: &str,
    hello: &[u8],
    now: i64,
) -> Result<(InviteQr, Vec<u8>)> {
    let qr = InviteQr::parse(invite_text)?;
    if now > qr.expires_at.saturating_add(CLOCK_SKEW_SECS) {
        return Err(refused("invite expired"));
    }
    let earliest = qr
        .expires_at
        .saturating_sub(QR_LIFETIME_SECS)
        .saturating_sub(CLOCK_SKEW_SECS);
    if now < earliest {
        return Err(refused("invite from the future"));
    }
    let tag = hmac::sign(&hello_key(&qr.secret)?, hello);
    let mut frame = Vec::with_capacity(hello.len() + HELLO_TAG_LEN);
    frame.extend_from_slice(hello);
    frame.extend_from_slice(tag.as_ref());
    Ok((qr, frame))
}

fn hello_key(secret: &[u8; 32]) -> Result<hmac::Key> {
    let k = hkdf32(&[], secret, &[HELLO_TAG_INFO])?;
    Ok(hmac::Key::new(HMAC_SHA256, k.expose()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::kem::wrap_key_labeled;
    use crate::crypto::{HybridKemSecret, SecretKey, SymmetricKey};
    use crate::devices::DeviceKind;
    use crate::pairing::messages::{FullGrant, Grant, KeyExchange, Message};
    use crate::pairing::newcomer::Newcomer;
    use crate::{Error, Id};
    use zeroize::Zeroizing;

    const NOW: i64 = 1_790_000_000;

    fn device() -> DeviceInfo {
        DeviceInfo {
            device_id: Id::new(),
            name: "iPhone de Camille".into(),
            kind: DeviceKind::Phone,
        }
    }

    fn full_grant() -> Grant {
        Grant::Full(FullGrant {
            account_id: Id::new(),
            secret_key: Zeroizing::new(SecretKey::generate().unwrap().to_display()),
            mode: DeviceMode::Personal,
            device_id: Id::new(),
            snapshot: vec![],
        })
    }

    #[test]
    fn a_scanned_invite_pairs_end_to_end() {
        let mut invite = Invite::new(NOW).unwrap();
        let (mut n, frame) =
            Newcomer::join(invite.qr_text(), device(), DeviceMode::Personal, NOW + 3).unwrap();
        let (mut a, kx, sas_a, peer, mode) = invite.accept(&frame, NOW + 4).unwrap();
        assert_eq!(peer.name, "iPhone de Camille");
        assert_eq!(mode, DeviceMode::Personal);
        let sas_n = n.on_key_exchange(&kx, NOW + 5).unwrap();
        assert_eq!(sas_a, sas_n);

        let confirmed = n.confirm().unwrap();
        assert_eq!(
            a.on_frame_at(&confirmed, NOW + 6).unwrap(),
            Message::Confirmed
        );
        let grant = a.seal_grant_at(full_grant(), true, NOW + 7).unwrap();
        assert!(matches!(
            n.open_at(&grant, NOW + 7).unwrap(),
            Message::Grant(Grant::Full(_))
        ));
        let ack = n.seal_at(&Message::Ack, NOW + 8).unwrap();
        assert_eq!(a.on_frame_at(&ack, NOW + 8).unwrap(), Message::Ack);
    }

    #[test]
    fn a_hello_without_the_secret_is_refused_and_the_invite_stays_open() {
        let mut invite = Invite::new(NOW).unwrap();
        // An intruder knows the session id (it names the service) but not
        // the secret: it signs with a guess.
        let secret = HybridKemSecret::generate().unwrap();
        let hello = Hello {
            session_id: invite.session_id(),
            ephemeral_public: secret.public().unwrap(),
            device: device(),
            requested_mode: DeviceMode::Personal,
        }
        .to_bytes()
        .unwrap();
        let mut forged = hello.clone();
        forged.extend_from_slice(&[0u8; HELLO_TAG_LEN]);
        assert!(matches!(
            invite.accept(&forged, NOW + 1),
            Err(Error::Integrity(IntegrityError::WrongContext))
        ));
        assert!(invite.accept(&hello, NOW + 1).is_err(), "untagged hello");
        assert!(invite.accept(&[], NOW + 1).is_err());

        // The genuine newcomer still gets through.
        let (_, frame) =
            Newcomer::join(invite.qr_text(), device(), DeviceMode::Personal, NOW + 2).unwrap();
        assert!(invite.accept(&frame, NOW + 2).is_ok());
    }

    #[test]
    fn an_invite_is_spent_once_and_expires() {
        let mut invite = Invite::new(NOW).unwrap();
        let (_, frame) =
            Newcomer::join(invite.qr_text(), device(), DeviceMode::Personal, NOW).unwrap();
        invite.accept(&frame, NOW + 1).unwrap();
        assert!(invite.accept(&frame, NOW + 2).is_err(), "replayed hello");

        let mut late = Invite::new(NOW).unwrap();
        let (_, frame) =
            Newcomer::join(late.qr_text(), device(), DeviceMode::Personal, NOW).unwrap();
        assert!(late.accept(&frame, NOW + QR_LIFETIME_SECS + 1).is_err());
    }

    #[test]
    fn a_hello_signed_for_another_invite_is_refused() {
        let mut first = Invite::new(NOW).unwrap();
        let second = Invite::new(NOW).unwrap();
        let (_, frame) =
            Newcomer::join(second.qr_text(), device(), DeviceMode::Personal, NOW).unwrap();
        assert!(first.accept(&frame, NOW + 1).is_err());
    }

    #[test]
    fn the_newcomer_refuses_a_stale_or_future_invite() {
        let invite = Invite::new(NOW).unwrap();
        let stale = NOW + QR_LIFETIME_SECS + CLOCK_SKEW_SECS + 1;
        assert!(Newcomer::join(invite.qr_text(), device(), DeviceMode::Personal, stale).is_err());
        let early = NOW - CLOCK_SKEW_SECS - 1;
        assert!(Newcomer::join(invite.qr_text(), device(), DeviceMode::Personal, early).is_err());
        // A pairing QR is not an invite.
        assert!(Newcomer::join("OPPAIR1:AAAA", device(), DeviceMode::Personal, NOW).is_err());
    }

    #[test]
    fn a_key_exchange_from_someone_who_never_saw_the_screen_does_not_open() {
        let invite = Invite::new(NOW).unwrap();
        let (mut n, frame) =
            Newcomer::join(invite.qr_text(), device(), DeviceMode::Personal, NOW).unwrap();
        // The intruder read the Hello off the network and wraps its own key
        // to it, under every transcript it can compute without the secret.
        let hello = Hello::from_bytes(&frame[..frame.len() - HELLO_TAG_LEN]).unwrap();
        let guess = super::super::transcript("OPJOIN1:", &frame[..frame.len() - HELLO_TAG_LEN]);
        let envelope = wrap_key_labeled(
            &hello.ephemeral_public,
            &SymmetricKey::generate().unwrap(),
            b"onepass/pairing/v1",
            &guess,
        )
        .unwrap();
        let kx = KeyExchange { envelope }.to_bytes();
        assert!(n.on_key_exchange(&kx, NOW + 1).is_err());
        // The session is over: no confirmation goes out.
        assert!(n.confirm().is_err());
    }

    #[test]
    fn debug_keeps_the_invite_text_out() {
        let invite = Invite::new(NOW).unwrap();
        let shown = format!("{invite:?}");
        assert!(!shown.contains(invite.qr_text()));
        assert!(!shown.contains("OPJOIN1"));
    }
}
