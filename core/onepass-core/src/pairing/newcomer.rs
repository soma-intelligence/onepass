//! The new device: shows the QR, decapsulates the session key, and takes a
//! grant only after its own user confirmed the SAS.

use std::fmt;

use crate::account::AccountParams;
use crate::crypto::kem::unwrap_key_labeled;
use crate::crypto::{HybridKemSecret, SecretKey, random_array};
use crate::device_keys::{DeviceKeys, DevicePublic, sign_pop};
use crate::devices::{DeviceMode, check_name};
use crate::store::{RecordKind, account_record_id};
use crate::synchome::{SyncBackend, SyncHomeBody, verify_sync_home};
use crate::{Error, IntegrityError};
use crate::{Id, Result};
use onepass_mailbox_proto::SignedEnrollTicket;

use super::channel::Channel;
use super::invite::signed_hello;
use super::messages::{
    DeviceInfo, FullGrantV2, Grant, Hello, JoinHello, KeyExchange, Message, ProfileCard,
};
use super::qr::{InviteQr, PairingQr, QR_VERSION};
use super::rendezvous::RendezvousCode;
use super::snapshot::{check_snapshot, check_trust_for};
use super::{
    KEM_LABEL, KEM_LABEL_RV, QR_LIFETIME_SECS, now_unix, refused, sas, sha256, transcript,
};

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
    label: &'static [u8],
    channel: Option<Channel>,
    state: State,
    public_granted: bool,
    acked: bool,
    /// Joined from an invite: the approver may send its `Profile`.
    joined: bool,
    profile: Option<ProfileCard>,
    /// Who this device says it is (the Hello's).
    device: DeviceInfo,
    /// Key rotation v2: this device's public key, once it confirmed with
    /// it (`confirm_with_key`).
    key: Option<DevicePublic>,
    /// The account a `FullV2` granted.
    granted_account: Option<Id>,
    /// The mailbox credential key this device sent (mailbox spec 4.12).
    mailbox_credential: Option<[u8; 32]>,
    /// From a `FullV2`: the account's home, verified against the account
    /// key of the granted snapshot, and the enroll ticket checked against
    /// `mailbox_credential` (encoded as the proto encodes it).
    home: Option<(SyncHomeBody, Option<Vec<u8>>)>,
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
            device: device.clone(),
            requested_mode: mode,
        }
        .to_bytes()?;
        let newcomer = Newcomer {
            secret: Some(secret),
            session_id,
            expires_at: qr.expires_at,
            mode,
            transcript: transcript(&qr.to_text(), &hello),
            label: KEM_LABEL,
            channel: None,
            state: State::AwaitingKey,
            public_granted: false,
            acked: false,
            joined: false,
            profile: None,
            device,
            key: None,
            granted_account: None,
            mailbox_credential: None,
            home: None,
        };
        Ok((newcomer, qr, hello))
    }

    /// Join from a scanned invite (`invite`): the new ephemeral key pair,
    /// the invite's session, and the Hello signed with its secret, the frame
    /// to send once connected. The key exchange is taken for
    /// `QR_LIFETIME_SECS` from `now`, on this device's clock.
    pub fn join(
        invite_text: &str,
        device: DeviceInfo,
        mode: DeviceMode,
        now: i64,
    ) -> Result<(Newcomer, Vec<u8>)> {
        check_name(&device.name)?;
        let session_id = InviteQr::parse(invite_text)?.session_id;
        let secret = HybridKemSecret::generate()?;
        let hello = Hello {
            session_id,
            ephemeral_public: secret.public()?,
            device: device.clone(),
            requested_mode: mode,
        }
        .to_bytes()?;
        let (_, frame) = signed_hello(invite_text, &hello, now)?;
        let newcomer = Newcomer {
            secret: Some(secret),
            session_id,
            expires_at: now.checked_add(QR_LIFETIME_SECS).ok_or(refused("time"))?,
            mode,
            transcript: transcript(invite_text, &hello),
            label: KEM_LABEL,
            channel: None,
            state: State::AwaitingKey,
            public_granted: false,
            acked: false,
            joined: true,
            profile: None,
            device,
            key: None,
            granted_account: None,
            mailbox_credential: None,
            home: None,
        };
        Ok((newcomer, frame))
    }

    /// Join an approver that shows `code` (reverse pairing): a fresh
    /// ephemeral key pair and session id, and the `JoinHello` to send once
    /// connected. Valid `QR_LIFETIME_SECS` from `now`.
    pub fn join_code(
        device: DeviceInfo,
        mode: DeviceMode,
        code: &RendezvousCode,
        now: i64,
    ) -> Result<(Newcomer, Vec<u8>)> {
        check_name(&device.name)?;
        let secret = HybridKemSecret::generate()?;
        let session_id = random_array()?;
        let hello = Hello {
            session_id,
            ephemeral_public: secret.public()?,
            device: device.clone(),
            requested_mode: mode,
        };
        let proof = code.proof(&JoinHello::signed_part(&hello)?)?;
        let join_hello = JoinHello { hello, proof }.to_bytes()?;
        let newcomer = Newcomer {
            secret: Some(secret),
            session_id,
            expires_at: now.checked_add(QR_LIFETIME_SECS).ok_or(refused("time"))?,
            mode,
            transcript: transcript(&code.qr_text(), &join_hello),
            label: KEM_LABEL_RV,
            channel: None,
            state: State::AwaitingKey,
            public_granted: false,
            acked: false,
            joined: false,
            profile: None,
            device,
            key: None,
            granted_account: None,
            mailbox_credential: None,
            home: None,
        };
        Ok((newcomer, join_hello))
    }

    /// The approver's profile, when it sent one (invite sessions).
    pub fn profile(&self) -> Option<&ProfileCard> {
        self.profile.as_ref()
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
        let k = unwrap_key_labeled(&secret, &kx.envelope, self.label, &self.transcript)?;
        drop(secret);
        let code = sas(&k, &self.transcript)?;
        self.channel = Some(Channel::newcomer(&k, self.session_id)?);
        Ok(code)
    }

    /// The user confirmed the codes match: the `Confirmed` frame to send.
    /// A legacy confirmation: the approver grants a `Full` and lists this
    /// device without a device key (spec 15). The only one an approver
    /// from before key rotation v2 reads: the app retries with it, on a
    /// new QR, when a `confirm_with_key` session was closed at once.
    pub fn confirm(&mut self) -> Result<Vec<u8>> {
        if self.state != State::KeyReady {
            return Err(refused("nothing to confirm"));
        }
        let frame = self.channel_mut()?.seal(&Message::Confirmed)?;
        self.state = State::Confirmed;
        Ok(frame)
    }

    /// The user confirmed the codes match, on a device with device keys
    /// (spec 5.2): the `ConfirmedWithKey` frame to send, with this device's
    /// public key under the Hello's device id and its proof of possession
    /// over the session transcript hash. The approver then grants a
    /// `FullV2`. Refused for a public session (no key to pin).
    pub fn confirm_with_key(&mut self, keys: &DeviceKeys) -> Result<Vec<u8>> {
        self.confirm_with_key_and_mailbox(keys, None)
    }

    /// `confirm_with_key`, with the public key of the mailbox credential
    /// this device wants enrolled (mailbox spec 4.12): it travels only
    /// inside the SAS-confirmed channel, and the approver answers with an
    /// enroll ticket for it when the account lives on a mailbox.
    pub fn confirm_with_key_and_mailbox(
        &mut self,
        keys: &DeviceKeys,
        mailbox_credential: Option<[u8; 32]>,
    ) -> Result<Vec<u8>> {
        if self.state != State::KeyReady {
            return Err(refused("nothing to confirm"));
        }
        if self.mode == DeviceMode::Public {
            return Err(refused("device key for a public session"));
        }
        let public = keys.public(self.device.device_id)?;
        let pop = sign_pop(keys, &self.transcript, &public)?;
        let frame = self.channel_mut()?.seal(&Message::ConfirmedWithKey {
            device: public.clone(),
            pop,
            mailbox_credential,
        })?;
        self.key = Some(public);
        self.mailbox_credential = mailbox_credential;
        self.state = State::Confirmed;
        Ok(frame)
    }

    /// The acknowledgment of a `FullV2` (spec 5.2, 6.4): the same device
    /// key, its proof of possession now over the granted account id, which
    /// the approver's intro for this device carries. In place of `Ack`.
    pub fn seal_key_ack(&mut self, keys: &DeviceKeys) -> Result<Vec<u8>> {
        self.seal_key_ack_at(keys, now_unix())
    }

    pub fn seal_key_ack_at(&mut self, keys: &DeviceKeys, now: i64) -> Result<Vec<u8>> {
        let (Some(me), Some(account)) = (self.key.clone(), self.granted_account) else {
            return Err(refused("message not allowed now"));
        };
        if self.state != State::Granted || self.acked {
            return Err(refused("message not allowed now"));
        }
        if keys.public(me.device_id)? != me {
            return Err(refused("device key"));
        }
        let pop = sign_pop(keys, &account.0, &me)?;
        let frame = self.channel_mut()?.seal_at(
            &Message::ConfirmedWithKey {
                device: me,
                pop,
                mailbox_credential: None,
            },
            now,
        )?;
        self.acked = true;
        Ok(frame)
    }

    /// This device's public key, after `confirm_with_key`.
    pub fn device_key(&self) -> Option<&DevicePublic> {
        self.key.as_ref()
    }

    /// The device this session asked to join as.
    pub fn device_info(&self) -> &DeviceInfo {
        &self.device
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
            Message::Profile(p)
                if self.joined
                    && self.state == State::Confirmed
                    && self.mode != DeviceMode::Public
                    && self.profile.is_none() =>
            {
                p.check().map(|()| self.profile = Some(p.clone()))
            }
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
            Grant::Full(g)
                if self.mode != DeviceMode::Public && g.mode == self.mode && self.key.is_none() =>
            {
                SecretKey::parse(&g.secret_key)?;
                check_snapshot(&g.snapshot)?;
            }
            Grant::FullV2(g) if self.mode != DeviceMode::Public && g.full.mode == self.mode => {
                let me = self.key.as_ref().ok_or(refused("grant does not match"))?;
                self.check_v2(g, me)?;
                self.home = self.check_mailbox(g)?;
                self.granted_account = Some(g.full.account_id);
            }
            _ => return Err(refused("grant does not match the requested mode")),
        }
        self.state = State::Granted;
        Ok(())
    }

    /// A `FullV2` for this device: the full grant's checks, listed under
    /// the Hello's id, and a trust snapshot this device can pin
    /// (`check_trust_for`).
    fn check_v2(&self, g: &FullGrantV2, me: &DevicePublic) -> Result<()> {
        SecretKey::parse(&g.full.secret_key)?;
        check_snapshot(&g.full.snapshot)?;
        g.check()?;
        if g.full.device_id != me.device_id {
            return Err(refused("device id"));
        }
        check_trust_for(&g.trust, me)
    }

    /// The home and ticket of a `FullV2` (mailbox spec 4.12, 5.2), checked
    /// before this device calls any server: the `SyncHome` signed by the
    /// account key of the granted snapshot (its params verified by the
    /// identity at the head of the granted lineage), and a ticket only for
    /// a mailbox home, for this device's credential, that mailbox and URL.
    fn check_mailbox(&self, g: &FullGrantV2) -> Result<Option<(SyncHomeBody, Option<Vec<u8>>)>> {
        let Some(sync) = &g.sync else {
            if g.enroll.is_some() {
                return Err(refused("ticket without a home"));
            }
            return Ok(None);
        };
        let identity = g
            .trust
            .lineage
            .last()
            .ok_or(Error::InvalidFormat("trust snapshot"))?
            .identity_pub();
        // Generation 0 keeps its records under the account id (spec 6.6).
        let rid = account_record_id(
            g.full.account_id,
            (g.trust.lineage.len() > 1).then_some(identity),
        );
        let params = g
            .full
            .snapshot
            .iter()
            .find(|r| r.kind == RecordKind::AccountParams.code() && r.id == rid)
            .ok_or(refused("home without account params"))?;
        let params = AccountParams::decode_verified(&params.data, identity)?;
        if params.account_id != g.full.account_id {
            return Err(IntegrityError::WrongContext.into());
        }
        let home = verify_sync_home(sync, &params.signing_pub, params.account_id, None)?;
        let Some(t) = &g.enroll else {
            return Ok(Some((home, None)));
        };
        let SyncBackend::Mailbox { url, mailbox_id } = &home.backend else {
            return Err(refused("ticket for a CloudKit account"));
        };
        let mine = self
            .mailbox_credential
            .ok_or(refused("ticket not asked for"))?;
        let ticket: SignedEnrollTicket =
            onepass_mailbox_proto::decode(t).map_err(|_| Error::InvalidFormat("enroll ticket"))?;
        if ticket.ticket.new_credential_pub != mine
            || ticket.ticket.mailbox_id != *mailbox_id
            || ticket.ticket.mailbox_url != *url
        {
            return Err(refused("enroll ticket"));
        }
        Ok(Some((home, Some(t.clone()))))
    }

    /// The account's home from a `FullV2`, verified (`None`: the approver
    /// sent none, an older approver or an account from before the mailbox).
    pub fn sync_home(&self) -> Option<&SyncHomeBody> {
        self.home.as_ref().map(|(h, _)| h)
    }

    /// The mailbox to join and the encoded enroll ticket, once a `FullV2`
    /// carried both, checked against this device's credential and the
    /// verified home (`None`: no mailbox to join; a CloudKit account or an
    /// older approver).
    pub fn mailbox_enrollment(&self) -> Option<(SyncHomeBody, Vec<u8>)> {
        match &self.home {
            Some((h, Some(t))) => Some((h.clone(), t.clone())),
            _ => None,
        }
    }

    pub fn seal(&mut self, msg: &Message) -> Result<Vec<u8>> {
        self.seal_at(msg, now_unix())
    }

    /// Seal `Ack` (once, after a legacy grant), `Audit` (public session,
    /// after the grant) or `End`. `Confirmed` goes through `confirm`, the
    /// acknowledgment of a `FullV2` through `seal_key_ack`.
    pub fn seal_at(&mut self, msg: &Message, now: i64) -> Result<Vec<u8>> {
        let granted = self.state == State::Granted;
        match msg {
            Message::Ack if granted && !self.acked && self.key.is_none() => {}
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

    /// A trust snapshot of a one-device account: its genesis by `a`.
    fn trust_snapshot(account: Id, a: &DeviceKeys, a_id: Id) -> super::super::TrustSnapshot {
        use crate::crypto::IdentityKey;
        use crate::lineage::{
            GenesisBody, LINEAGE_FORMAT, LineageRecord, RosterEntry, sign_genesis,
        };
        let approver = a.public(a_id).unwrap();
        let entry = RosterEntry {
            device_id: a_id,
            sign_pub: approver.sign_pub.clone(),
            kem_pub: approver.kem_pub.clone(),
            name: "iPhone".into(),
            kind: DeviceKind::Phone,
            mode: DeviceMode::Personal,
            introduced_by: None,
        };
        let identity = IdentityKey::generate().unwrap();
        let genesis = sign_genesis(
            GenesisBody {
                format: LINEAGE_FORMAT,
                account_id: account,
                identity_pub: identity.verifying_key(),
                creator: entry.clone(),
                created_at: NOW,
            },
            a,
            &identity,
        )
        .unwrap();
        super::super::TrustSnapshot {
            lineage: vec![LineageRecord::Genesis(genesis)],
            levels: vec![(a_id, crate::trust::TrustLevel::Verified)],
            roster: vec![entry],
            approver,
        }
    }

    fn session(n_id: Id) -> (Newcomer, Approver) {
        let device = DeviceInfo {
            device_id: n_id,
            name: "iPad de Camille".into(),
            kind: DeviceKind::Tablet,
        };
        let (mut n, qr, hello) = Newcomer::new(device, DeviceMode::Personal, NOW).unwrap();
        let (a, kx, _, _, _) = Approver::begin(&qr.to_text(), &hello, NOW + 1).unwrap();
        n.on_key_exchange(&kx, NOW + 2).unwrap();
        (n, a)
    }

    fn key_message(keys: &DeviceKeys, id: Id, context: &[u8]) -> Message {
        let device = keys.public(id).unwrap();
        Message::ConfirmedWithKey {
            pop: sign_pop(keys, context, &device).unwrap(),
            device,
            mailbox_credential: None,
        }
    }

    #[test]
    fn pop_mismatch_refused() {
        let keys = DeviceKeys::generate_software().unwrap();
        let id = Id::new();
        // A pop over another transcript.
        let (mut n, mut a) = session(id);
        let frame = n
            .channel_mut()
            .unwrap()
            .seal_at(&key_message(&keys, id, &[9; 32]), NOW + 3)
            .unwrap();
        assert_eq!(
            a.on_frame_at(&frame, NOW + 3),
            Err(Error::Integrity(crate::IntegrityError::Signature))
        );
        // The session is over: the honest confirmation no longer passes.
        let good = n
            .channel_mut()
            .unwrap()
            .seal_at(&Message::Confirmed, NOW + 4);
        assert!(a.on_frame_at(&good.unwrap(), NOW + 4).is_err());
        assert_eq!(a.newcomer_key(), None);

        // A key under another device id than the Hello's.
        let (mut n, mut a) = session(id);
        let t = n.transcript;
        let frame = n
            .channel_mut()
            .unwrap()
            .seal_at(&key_message(&keys, Id::new(), &t), NOW + 3)
            .unwrap();
        assert!(a.on_frame_at(&frame, NOW + 3).is_err());

        // The honest one passes.
        let (mut n, mut a) = session(id);
        let frame = n.confirm_with_key(&keys).unwrap();
        assert!(matches!(
            a.on_frame_at(&frame, NOW + 3).unwrap(),
            Message::ConfirmedWithKey { .. }
        ));
        assert_eq!(a.newcomer_key(), Some(&keys.public(id).unwrap()));
    }

    #[test]
    fn key_ack_pop_must_cover_the_granted_account() {
        let keys = DeviceKeys::generate_software().unwrap();
        let a_keys = DeviceKeys::generate_software().unwrap();
        let id = Id::new();
        let account = Id::new();
        let grant = || {
            Grant::FullV2(super::super::FullGrantV2 {
                full: FullGrant {
                    account_id: account,
                    secret_key: Zeroizing::new(SecretKey::generate().unwrap().to_display()),
                    mode: DeviceMode::Personal,
                    device_id: id,
                    snapshot: vec![],
                },
                trust: trust_snapshot(account, &a_keys, Id::new()),
                sync: None,
                enroll: None,
            })
        };
        for (context, ok) in [(Id::new().0, false), (account.0, true)] {
            let (mut n, mut a) = session(id);
            let f = n.confirm_with_key(&keys).unwrap();
            a.on_frame_at(&f, NOW + 3).unwrap();
            let f = a.seal_grant_at(grant(), true, NOW + 4).unwrap();
            n.open_at(&f, NOW + 5).unwrap();
            let frame = n
                .channel_mut()
                .unwrap()
                .seal_at(&key_message(&keys, id, &context), NOW + 6)
                .unwrap();
            assert_eq!(a.on_frame_at(&frame, NOW + 6).is_ok(), ok);
            assert_eq!(a.newcomer_account_pop().is_some(), ok);
        }
        // Another key than the confirmed one.
        let (mut n, mut a) = session(id);
        let f = n.confirm_with_key(&keys).unwrap();
        a.on_frame_at(&f, NOW + 3).unwrap();
        let f = a.seal_grant_at(grant(), true, NOW + 4).unwrap();
        n.open_at(&f, NOW + 5).unwrap();
        let other = DeviceKeys::generate_software().unwrap();
        let frame = n
            .channel_mut()
            .unwrap()
            .seal_at(&key_message(&other, id, &account.0), NOW + 6)
            .unwrap();
        assert!(a.on_frame_at(&frame, NOW + 6).is_err());
    }

    #[test]
    fn full_v2_checked_by_the_newcomer() {
        let keys = DeviceKeys::generate_software().unwrap();
        let a_keys = DeviceKeys::generate_software().unwrap();
        let id = Id::new();
        let account = Id::new();
        let mk = |device_id: Id, account_id: Id, snap_account: Id| {
            Message::Grant(Grant::FullV2(super::super::FullGrantV2 {
                full: FullGrant {
                    account_id,
                    secret_key: Zeroizing::new(SecretKey::generate().unwrap().to_display()),
                    mode: DeviceMode::Personal,
                    device_id,
                    snapshot: vec![],
                },
                trust: trust_snapshot(snap_account, &a_keys, Id::new()),
                sync: None,
                enroll: None,
            }))
        };
        let cases = [
            (mk(id, account, account), true),
            // Listed under another id than the Hello's.
            (mk(Id::new(), account, account), false),
            // A chain of another account.
            (mk(id, account, Id::new()), false),
        ];
        for (msg, ok) in cases {
            let (mut n, mut a) = session(id);
            let f = n.confirm_with_key(&keys).unwrap();
            a.on_frame_at(&f, NOW + 3).unwrap();
            // Sealed raw, as a hostile approver would.
            let f = a.channel.seal_at(&msg, NOW + 4).unwrap();
            assert_eq!(n.open_at(&f, NOW + 5).is_ok(), ok);
        }
        // A legacy grant to a newcomer that sent its key: a downgrade.
        let (mut n, mut a) = session(id);
        let f = n.confirm_with_key(&keys).unwrap();
        a.on_frame_at(&f, NOW + 3).unwrap();
        let f = a.channel.seal_at(&grant(), NOW + 4).unwrap();
        assert!(n.open_at(&f, NOW + 5).is_err());
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
