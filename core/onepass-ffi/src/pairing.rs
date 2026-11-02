//! QR pairing over the UniFFI surface (milestone 2b, spec 5). The core
//! holds every cryptographic state; Swift moves opaque frames over its
//! transport and sees only the QR text, the 6-digit code, the peer's name
//! and, in a public session, the lent items (decrypted, like the rest of
//! the FFI). The Secret Key a newcomer receives stays in the object until
//! its snapshot is imported and verified (`take_secret_key`).

use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use onepass_core::chain::ChainState;
use onepass_core::crypto::SecretKey;
use onepass_core::devices::{DeviceEntry, DeviceMode};
use onepass_core::model::{FieldValue, Item};
use onepass_core::pairing::{
    Approver, AuditAction, AuditEvent, DeviceInfo, FullGrant, FullGrantV2, Grant, Host, Invite,
    InviteQr, Message, Newcomer, PairingQr, ProfileCard, PublicGrant, RendezvousCode,
    SnapshotRecord, check_snapshot_size, import_full_v2, snapshot_from_store,
};
use onepass_core::store::{RecordKind, RecordStore};
use onepass_core::sync::{AccountState, SyncStore};
use onepass_core::{Id, IntegrityError};
use time::OffsetDateTime;
use zeroize::Zeroizing;

use crate::convert::{bytes_hex, id_hex, item_to_ffi, parse_id};
use crate::devices::{FfiDeviceKind, FfiDeviceMode};
use crate::error::{OnePassError, invalid};
use crate::mailbox::{FfiMailboxEnrollment, FfiSyncHome, MailboxSync};
use crate::rotation::{FfiFollowed, FfiPqDeviceHalf, device_keys, followed, require_current};
use crate::session::{Repo, Session, account_id_of, find_item, find_vault};
use crate::types::{FfiItem, FfiUnlocked};

/// Default length of a public session, in minutes.
pub const PUBLIC_SESSION_DEFAULT_MINUTES: u32 = 15;
/// Longest public session, in minutes.
pub const PUBLIC_SESSION_MAX_MINUTES: u32 = 60;

/// What a public device did with a lent item.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum FfiAuditAction {
    Opened,
    /// The label of the copied field, never its value.
    Copied {
        label: String,
    },
}

/// One item to lend to a public device.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiItemRef {
    pub vault_id: String,
    pub item_id: String,
}

/// The device asking to join, as the approver shows it.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiPeerDevice {
    pub id: String,
    pub name: String,
    pub kind: FfiDeviceKind,
}

/// A message read from the channel. A full grant carries no secret here:
/// the snapshot and the Secret Key stay in the `PairingNewcomer`.
#[derive(Debug, Clone, PartialEq, uniffi::Enum)]
pub enum FfiPairingMessage {
    Confirmed,
    FullGrant {
        account_id: String,
        mode: FfiDeviceMode,
        device_id: String,
        snapshot_records: u32,
    },
    PublicGrant {
        expires_at: i64,
        items: Vec<FfiItem>,
    },
    Ack,
    Audit {
        at: i64,
        item_id: String,
        action: FfiAuditAction,
    },
    End,
    /// Invite sessions: the approver's display name and photo (empty for
    /// none), right before its full grant.
    Profile {
        name: String,
        photo: Vec<u8>,
    },
}

impl From<AuditAction> for FfiAuditAction {
    fn from(a: AuditAction) -> Self {
        match a {
            AuditAction::Opened => Self::Opened,
            AuditAction::Copied(label) => Self::Copied { label },
        }
    }
}

impl From<FfiAuditAction> for AuditAction {
    fn from(a: FfiAuditAction) -> Self {
        match a {
            FfiAuditAction::Opened => Self::Opened,
            FfiAuditAction::Copied { label } => Self::Copied(label),
        }
    }
}

/// The message as Swift sees it. A full grant is reduced to its public
/// fields; the caller keeps the grant itself.
fn message_to_ffi(msg: &Message) -> FfiPairingMessage {
    match msg {
        // Key rotation v2 (Task 13): a newcomer with device keys confirms
        // with them; the app sees a confirmation. Granting it a `FullV2`
        // through the FFI is Task 17.
        Message::Confirmed | Message::ConfirmedWithKey { .. } => FfiPairingMessage::Confirmed,
        Message::Grant(Grant::Full(g)) => FfiPairingMessage::FullGrant {
            account_id: id_hex(g.account_id),
            mode: g.mode.into(),
            device_id: id_hex(g.device_id),
            snapshot_records: u32::try_from(g.snapshot.len()).unwrap_or(u32::MAX),
        },
        Message::Grant(Grant::FullV2(g)) => FfiPairingMessage::FullGrant {
            account_id: id_hex(g.full.account_id),
            mode: g.full.mode.into(),
            device_id: id_hex(g.full.device_id),
            snapshot_records: u32::try_from(g.full.snapshot.len()).unwrap_or(u32::MAX),
        },
        Message::Grant(Grant::Public(g)) => FfiPairingMessage::PublicGrant {
            expires_at: g.expires_at,
            items: g.items.iter().map(item_to_ffi).collect(),
        },
        Message::Ack => FfiPairingMessage::Ack,
        Message::Audit(e) => FfiPairingMessage::Audit {
            at: e.at,
            item_id: id_hex(e.item_id),
            action: e.action.clone().into(),
        },
        Message::End => FfiPairingMessage::End,
        Message::Profile(p) => FfiPairingMessage::Profile {
            name: p.name.clone(),
            photo: p.photo.clone(),
        },
    }
}

fn now_unix() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}

fn refused(reason: &str) -> OnePassError {
    OnePassError::Validation {
        field: "pairing".into(),
        reason: reason.into(),
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The Bonjour service name of a pairing QR or an invite: its session id in
/// hex. Parses the code (canonical text only) and trusts nothing else.
#[uniffi::export]
pub fn pairing_service_name(qr_text: String) -> Result<String, OnePassError> {
    if let Ok(invite) = InviteQr::parse(&qr_text) {
        return Ok(bytes_hex(&invite.session_id));
    }
    Ok(bytes_hex(&PairingQr::parse(&qr_text)?.session_id))
}

/// What a scanned code is: the QR a new device shows, an invite an unlocked
/// device shows, or neither. Canonical texts only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiPairingCodeKind {
    Pairing,
    Invite,
    Unknown,
}

#[uniffi::export]
pub fn pairing_code_kind(text: String) -> FfiPairingCodeKind {
    if PairingQr::parse(&text).is_ok() {
        FfiPairingCodeKind::Pairing
    } else if InviteQr::parse(&text).is_ok() {
        FfiPairingCodeKind::Invite
    } else {
        FfiPairingCodeKind::Unknown
    }
}

// ---- invite (the unlocked device shows the code) ----------------------------

/// The unlocked device's open invite: shows the code, publishes the
/// service, and starts the session with the first connection whose Hello
/// carries the invite's secret. Renew it by making a new object.
#[derive(uniffi::Object)]
pub struct PairingInvite {
    session_id: [u8; 16],
    expires_at: i64,
    core: Mutex<Invite>,
}

#[uniffi::export]
impl PairingInvite {
    /// A fresh invite, valid 120 s from `now` (Unix seconds).
    #[uniffi::constructor]
    pub fn new(now: i64) -> Result<Arc<Self>, OnePassError> {
        let core = Invite::new(now)?;
        Ok(Arc::new(PairingInvite {
            session_id: core.session_id(),
            expires_at: core.expires_at(),
            core: Mutex::new(core),
        }))
    }

    /// The text to show as a QR code (`OPJOIN1:...`). It holds the secret:
    /// show it, never log or store it.
    pub fn qr_text(&self) -> String {
        lock(&self.core).qr_text().to_owned()
    }

    pub fn expires_at(&self) -> i64 {
        self.expires_at
    }

    /// The Bonjour service name to publish: the session id in hex.
    pub fn service_name(&self) -> String {
        bytes_hex(&self.session_id)
    }

    /// Check a connection's first frame and start the session: send the
    /// approver's `key_exchange()` back. A refused frame leaves the invite
    /// open for another connection; an accepted one spends it.
    pub fn accept(&self, hello: Vec<u8>, now: i64) -> Result<Arc<PairingApprover>, OnePassError> {
        let (core, key_exchange, sas, peer, requested) = lock(&self.core).accept(&hello, now)?;
        Ok(Arc::new(PairingApprover {
            key_exchange,
            sas,
            peer,
            requested,
            session_id: self.session_id,
            state: Mutex::new(ApproverState {
                core,
                peer_confirmed: false,
                granted: false,
                introduced: false,
            }),
        }))
    }
}

// ---- newcomer ---------------------------------------------------------------

struct NewcomerState {
    core: Newcomer,
    /// The full grant received, until its snapshot is imported.
    grant: Option<FullGrant>,
    /// Key rotation v2: the `FullV2` received after `confirm_with_key`,
    /// until it is imported (`import_snapshot_v2`) or applied to a known
    /// device (`repair_with_grant`).
    grant_v2: Option<FullGrantV2>,
    /// The Secret Key, once the import succeeded, until Swift takes it.
    released: Option<Zeroizing<String>>,
    imported: bool,
    /// Cross-platform sync (spec 4.12): this device's mailbox credential
    /// key, sent inside the SAS channel with its device key, so the
    /// approver can issue an enroll ticket for it.
    mailbox_credential: Option<[u8; 32]>,
}

/// The account's signed home, and the enroll ticket `mailbox` issues for
/// the newcomer's credential, added to a `FullV2` (`grant_with_mailbox`).
fn with_mailbox(
    core: &Approver,
    repo: &mut Repo,
    grant: FullGrantV2,
    mailbox: Option<&MailboxSync>,
) -> Result<FullGrantV2, OnePassError> {
    let home = repo.signed_sync_home()?;
    let now = now_unix();
    let issue = |key: [u8; 32]| match mailbox {
        Some(m) => m.ticket_for(key, now),
        None => Err(onepass_core::Error::NotFound),
    };
    let issuer: Option<&dyn Fn([u8; 32]) -> onepass_core::Result<Vec<u8>>> =
        mailbox.map(|_| &issue as &dyn Fn([u8; 32]) -> onepass_core::Result<Vec<u8>>);
    Ok(core.grant_with_mailbox(grant, home.as_deref(), issuer)?)
}

/// A mailbox credential public key as the app hands it: 32 bytes, or none.
fn credential_pub(key: Option<Vec<u8>>) -> Result<Option<[u8; 32]>, OnePassError> {
    key.map(|k| k.try_into().map_err(|_| invalid("mailbox credential")))
        .transpose()
}

/// The new device's side: shows the QR, gets the account or a public
/// session.
#[derive(uniffi::Object)]
pub struct PairingNewcomer {
    device_id: Id,
    qr_text: String,
    hello: Vec<u8>,
    /// The Bonjour service: published (QR direction) or joined (code direction).
    service: String,
    expires_at: i64,
    state: Mutex<NewcomerState>,
}

#[uniffi::export]
impl PairingNewcomer {
    /// A new pairing session for this device, under a fresh device id. The
    /// QR is valid 120 s from `now` (Unix seconds); renew it by making a new
    /// object.
    ///
    /// `mailbox_credential_pub`: this device's mailbox credential key (32
    /// bytes), when it will sync through a mailbox; the approver then
    /// grants an enroll ticket for it (`mailbox_enrollment`).
    #[uniffi::constructor(default(mailbox_credential_pub = None))]
    pub fn new(
        name: String,
        kind: FfiDeviceKind,
        mode: FfiDeviceMode,
        now: i64,
        mailbox_credential_pub: Option<Vec<u8>>,
    ) -> Result<Arc<Self>, OnePassError> {
        let device_id = Id::new();
        let info = DeviceInfo {
            device_id,
            name,
            kind: kind.into(),
        };
        let (core, qr, hello) = Newcomer::new(info, mode.into(), now)?;
        Ok(Arc::new(PairingNewcomer {
            device_id,
            qr_text: qr.to_text(),
            hello,
            service: bytes_hex(&qr.session_id),
            expires_at: qr.expires_at,
            state: Mutex::new(NewcomerState {
                core,
                grant: None,
                grant_v2: None,
                released: None,
                imported: false,
                mailbox_credential: credential_pub(mailbox_credential_pub)?,
            }),
        }))
    }

    /// Join from a scanned invite (`OPJOIN1:...`), under a fresh device id:
    /// connect to `service_name()` and send `hello()` (signed with the
    /// invite's secret); the key exchange is taken for 120 s from `now`.
    /// `qr_text()` is empty: this device shows no code.
    /// `mailbox_credential_pub` as in `new`.
    #[uniffi::constructor(default(mailbox_credential_pub = None))]
    pub fn join(
        invite_text: String,
        name: String,
        kind: FfiDeviceKind,
        mode: FfiDeviceMode,
        now: i64,
        mailbox_credential_pub: Option<Vec<u8>>,
    ) -> Result<Arc<Self>, OnePassError> {
        let device_id = Id::new();
        let info = DeviceInfo {
            device_id,
            name,
            kind: kind.into(),
        };
        let (core, hello) = Newcomer::join(&invite_text, info, mode.into(), now)?;
        Ok(Arc::new(PairingNewcomer {
            device_id,
            qr_text: String::new(),
            hello,
            service: bytes_hex(&core.session_id()),
            expires_at: core.expires_at(),
            state: Mutex::new(NewcomerState {
                core,
                grant: None,
                grant_v2: None,
                released: None,
                imported: false,
                mailbox_credential: credential_pub(mailbox_credential_pub)?,
            }),
        }))
    }

    /// Re-pair this device (spec 7.4): a pairing session under the id this
    /// device already has in the account (`session`'s), so the approver
    /// grants it again instead of listing a new device. Then
    /// `confirm_with_key` and `repair_with_grant`.
    #[uniffi::constructor]
    pub fn repair(
        session: Arc<Session>,
        name: String,
        kind: FfiDeviceKind,
        mode: FfiDeviceMode,
        now: i64,
    ) -> Result<Arc<Self>, OnePassError> {
        let device_id = session
            .this_device_id()
            .ok_or_else(|| refused("no device id"))
            .and_then(|id| parse_id(&id))?;
        let info = DeviceInfo {
            device_id,
            name,
            kind: kind.into(),
        };
        let (core, qr, hello) = Newcomer::new(info, mode.into(), now)?;
        Ok(Arc::new(PairingNewcomer {
            device_id,
            qr_text: qr.to_text(),
            hello,
            service: bytes_hex(&qr.session_id),
            expires_at: qr.expires_at,
            state: Mutex::new(NewcomerState {
                core,
                grant: None,
                grant_v2: None,
                released: None,
                imported: false,
                mailbox_credential: None,
            }),
        }))
    }

    /// Join an approver that shows a code (rendezvous direction): `code` is
    /// the scanned QR text (`OPPAIR2:...`) or the typed `XXXX-XXXX`. The
    /// device is valid for 120 s from `now`. `hello()` is the first frame to
    /// send to the host; `service_name()` is the code's service, `qr_text()` the
    /// canonical code text.
    /// `mailbox_credential_pub` as in `new`.
    #[uniffi::constructor(default(mailbox_credential_pub = None))]
    pub fn join_code(
        name: String,
        kind: FfiDeviceKind,
        mode: FfiDeviceMode,
        code: String,
        now: i64,
        mailbox_credential_pub: Option<Vec<u8>>,
    ) -> Result<Arc<Self>, OnePassError> {
        let code = RendezvousCode::parse(&code)?;
        let device_id = Id::new();
        let info = DeviceInfo {
            device_id,
            name,
            kind: kind.into(),
        };
        let (core, hello) = Newcomer::join_code(info, mode.into(), &code, now)?;
        let expires_at = core.expires_at();
        Ok(Arc::new(PairingNewcomer {
            device_id,
            qr_text: code.qr_text(),
            service: code.service_name(),
            hello,
            expires_at,
            state: Mutex::new(NewcomerState {
                core,
                grant: None,
                grant_v2: None,
                released: None,
                imported: false,
                mailbox_credential: credential_pub(mailbox_credential_pub)?,
            }),
        }))
    }

    /// The text to show as a QR code (`OPPAIR1:...`).
    pub fn qr_text(&self) -> String {
        self.qr_text.clone()
    }

    /// When the QR stops being accepted (Unix seconds).
    pub fn expires_at(&self) -> i64 {
        self.expires_at
    }

    /// The first frame, sent in the clear once the approver connects.
    pub fn hello(&self) -> Vec<u8> {
        self.hello.clone()
    }

    /// The Bonjour service name: the session id in hex to publish (QR
    /// direction), or the code's service to connect to (code direction).
    pub fn service_name(&self) -> String {
        self.service.clone()
    }

    /// The id this device asks to be listed under.
    pub fn device_id(&self) -> String {
        id_hex(self.device_id)
    }

    /// Read the approver's key exchange; returns the 6-digit code to compare.
    pub fn on_key_exchange(&self, bytes: Vec<u8>, now: i64) -> Result<String, OnePassError> {
        Ok(lock(&self.state).core.on_key_exchange(&bytes, now)?)
    }

    /// The user saw the same code on both screens: the frame to send.
    pub fn confirm(&self) -> Result<Vec<u8>, OnePassError> {
        Ok(lock(&self.state).core.confirm()?)
    }

    /// Open a frame from the approver. A full grant is kept here (see
    /// `import_snapshot`); a public grant hands over the lent items.
    pub fn open(&self, frame: Vec<u8>) -> Result<FfiPairingMessage, OnePassError> {
        let mut s = lock(&self.state);
        let msg = s.core.open(&frame)?;
        let out = message_to_ffi(&msg);
        match msg {
            Message::Grant(Grant::Full(g)) => s.grant = Some(g),
            Message::Grant(Grant::FullV2(g)) => s.grant_v2 = Some(g),
            _ => {}
        }
        Ok(out)
    }

    /// Key rotation v2 (spec 5.2): the user saw the same code on both
    /// screens, on a device with device keys: the frame to send, carrying
    /// this device's public key and its proof of possession. The approver
    /// then grants a `FullV2`. An approver from before key rotation v2
    /// closes the session: the app retries on a new QR with `confirm`.
    pub fn confirm_with_key(
        &self,
        classical: Vec<u8>,
        pq: Arc<dyn FfiPqDeviceHalf>,
    ) -> Result<Vec<u8>, OnePassError> {
        let classical = Zeroizing::new(classical);
        let keys = device_keys(&classical, pq)?;
        let mut s = lock(&self.state);
        let credential = s.mailbox_credential;
        Ok(s.core.confirm_with_key_and_mailbox(&keys, credential)?)
    }

    /// Cross-platform sync (spec 4.12): the mailbox a `FullV2` grant hands
    /// over, once opened (`open`): the account's signed home, verified
    /// against the granted account key, and the enroll ticket for this
    /// device's credential, checked against it (`mailbox_enroll`). `None`
    /// when the grant names no mailbox to join (a CloudKit account, an
    /// approver without a mailbox or from before the mailbox).
    pub fn mailbox_enrollment(&self) -> Result<Option<FfiMailboxEnrollment>, OnePassError> {
        Ok(lock(&self.state)
            .core
            .mailbox_enrollment()
            .map(|(home, ticket)| FfiMailboxEnrollment {
                home: (&home).into(),
                ticket,
            }))
    }

    /// The account's signed sync home a `FullV2` grant carried, verified
    /// (`None` without one).
    pub fn grant_sync_home(&self) -> Option<FfiSyncHome> {
        lock(&self.state).core.sync_home().map(FfiSyncHome::from)
    }

    /// Key rotation v2: import the `FullV2` into the empty store at
    /// `db_path` (its trust snapshot pinned, this device in the roster),
    /// then unlock with `password` and the received Secret Key and read
    /// every vault and item, as `import_snapshot`. Refused without a
    /// `FullV2`, after a successful import, on a store that is not empty;
    /// any later failure empties the store again. Then `seal_key_ack`.
    /// `classical` and `pq` are this device's keys (the ones it confirmed
    /// with): they sign its acknowledgment of the approver's head (spec
    /// 6.8, O6).
    pub fn import_snapshot_v2(
        &self,
        db_path: String,
        password: String,
        classical: Vec<u8>,
        pq: Arc<dyn FfiPqDeviceHalf>,
    ) -> Result<FfiUnlocked, OnePassError> {
        let password = Zeroizing::new(password);
        let classical = Zeroizing::new(classical);
        let keys = device_keys(&classical, pq)?;
        let mut s = lock(&self.state);
        if s.imported {
            return Err(refused("already imported"));
        }
        let grant = s
            .grant_v2
            .as_ref()
            .ok_or_else(|| refused("no full grant"))?;
        if grant.full.device_id != self.device_id {
            return Err(refused("device id"));
        }
        let me = s
            .core
            .device_key()
            .cloned()
            .ok_or_else(|| refused("no device key"))?;
        let info = s.core.device_info().clone();
        let path = Path::new(&db_path);
        if SyncStore::open(path)?.account_state()? != AccountState::Empty {
            return Err(invalid("store not empty"));
        }
        let done = (|| {
            {
                let mut store = SyncStore::open(path)?;
                import_full_v2(&mut store, grant, &me, &keys, &info)?;
            }
            let unlocked = crate::unlock_password(&db_path, &password, &grant.full.secret_key)?;
            if unlocked.session.account_id() != id_hex(grant.full.account_id) {
                return Err(OnePassError::from(onepass_core::Error::Integrity(
                    IntegrityError::WrongContext,
                )));
            }
            unlocked.session.vaults()?;
            unlocked.session.item_summaries()?;
            Ok(unlocked)
        })();
        match done {
            Ok(unlocked) => {
                s.released = Some(grant.full.secret_key.clone());
                s.grant_v2 = None;
                s.imported = true;
                Ok(unlocked)
            }
            Err(e) => {
                if let Ok(mut store) = SyncStore::open(path) {
                    let _ = store.reset();
                }
                Err(e)
            }
        }
    }

    /// Key rotation v2 (spec 5.2, 6.4): the acknowledgment of a `FullV2`,
    /// in place of `seal_ack`, with the same device keys: its proof of
    /// possession over the account id goes into the approver's intro.
    pub fn seal_key_ack(
        &self,
        classical: Vec<u8>,
        pq: Arc<dyn FfiPqDeviceHalf>,
    ) -> Result<Vec<u8>, OnePassError> {
        let classical = Zeroizing::new(classical);
        let keys = device_keys(&classical, pq)?;
        Ok(lock(&self.state).core.seal_key_ack(&keys)?)
    }

    /// Re-pair a device that already holds this account (spec 7.4, ruling
    /// A9: an orphaned device, one whose keys did not arrive): the `FullV2`
    /// applied as a follow from `session` (open on the identity the device
    /// is on), the local data kept and its own writes replayed. The session
    /// is consumed (locked afterwards, also on failure). This object must
    /// come from `PairingNewcomer::repair`, under the device's own id.
    pub fn repair_with_grant(
        &self,
        session: Arc<Session>,
        password: String,
        classical: Vec<u8>,
        pq: Arc<dyn FfiPqDeviceHalf>,
    ) -> Result<FfiFollowed, OnePassError> {
        let password = Zeroizing::new(password);
        let classical = Zeroizing::new(classical);
        let keys = device_keys(&classical, pq)?;
        let mut s = lock(&self.state);
        let grant = s.grant_v2.take().ok_or_else(|| refused("no full grant"))?;
        let repo = session.take()?;
        let (repo, auk, sk) =
            onepass_core::repo::pairing::repair_from_grant(repo, &grant, &password, &keys)?;
        s.imported = true;
        Ok(followed(repo, auk, sk))
    }

    /// The acknowledgement of a grant.
    pub fn seal_ack(&self) -> Result<Vec<u8>, OnePassError> {
        Ok(lock(&self.state).core.seal(&Message::Ack)?)
    }

    /// Public session: report what the user did with a lent item.
    pub fn seal_audit(
        &self,
        item_id: String,
        action: FfiAuditAction,
        at: i64,
    ) -> Result<Vec<u8>, OnePassError> {
        let event = AuditEvent {
            at,
            item_id: parse_id(&item_id)?,
            action: action.into(),
        };
        Ok(lock(&self.state).core.seal(&Message::Audit(event))?)
    }

    /// End the session (the guest leaves, or the user cancels).
    pub fn seal_end(&self) -> Result<Vec<u8>, OnePassError> {
        Ok(lock(&self.state).core.seal(&Message::End)?)
    }

    /// Import the received snapshot into the empty store at `db_path`, then
    /// unlock it with `password` and the received Secret Key and read every
    /// vault and item: a tampered or foreign record fails here. Refused
    /// without a full grant, after a successful import, and on a store that
    /// is not empty (left as it was). Any later failure (wrong password
    /// included) empties the store again and keeps the Secret Key withheld;
    /// the grant stays, so the user can retry. On success the session is
    /// open and the Secret Key can be taken once (`take_secret_key`).
    pub fn import_snapshot(
        &self,
        db_path: String,
        password: String,
    ) -> Result<FfiUnlocked, OnePassError> {
        let password = Zeroizing::new(password);
        let mut s = lock(&self.state);
        if s.imported {
            return Err(refused("already imported"));
        }
        let grant = s.grant.as_ref().ok_or_else(|| refused("no full grant"))?;
        // The approver lists this device under the id it asked for.
        if grant.device_id != self.device_id {
            return Err(refused("device id"));
        }
        let path = Path::new(&db_path);
        // A store the sync already filled with this account (iCloud reached
        // this device before the pairing) takes the grant on top of it, if
        // this device never opened it: the snapshot rows merge like a fetch.
        let synced = {
            let store = SyncStore::open(path)?;
            match store.account_state()? {
                AccountState::Empty => None,
                AccountState::Present if synced_only(&store, grant.account_id)? => {
                    Some(store.chain_state()?)
                }
                AccountState::Present | AccountState::PinnedButMissing => {
                    return Err(invalid("store not empty"));
                }
            }
        };
        match import(path, &db_path, &password, grant, synced.clone()) {
            Ok(unlocked) => {
                s.released = Some(grant.secret_key.clone());
                s.grant = None;
                s.imported = true;
                Ok(unlocked)
            }
            Err(e) => {
                // Nothing of the snapshot stays on an empty device. A synced
                // store keeps its records (the sync brought them, the
                // snapshot only repeats signed ones) and gets its chain state
                // back, so a retry finds it as it was. If the clean-up itself
                // fails the import error is still the one reported.
                if let Ok(mut store) = SyncStore::open(path) {
                    match synced {
                        None => {
                            let _ = store.reset();
                        }
                        Some(chain) => {
                            let _ = store.set_chain_state(&chain);
                        }
                    }
                }
                Err(e)
            }
        }
    }

    /// Forget the received full grant (its Secret Key and snapshot) and a
    /// Secret Key not taken yet: too many wrong passwords, inactivity, or
    /// the user left the screen. A later `import_snapshot` is refused.
    pub fn discard_grant(&self) {
        let mut s = lock(&self.state);
        s.grant = None;
        s.released = None;
    }

    /// The received Secret Key, once, after a successful import; `None`
    /// before, after a failed import, and once taken.
    pub fn take_secret_key(&self) -> Option<String> {
        lock(&self.state).released.take().map(|k| k.to_string())
    }
}

/// Stage the snapshot as a remote fetch (the hostile-store checks of
/// `commit_remote` apply), record the device id, then unlock and read
/// everything.
fn import(
    path: &Path,
    db_path: &str,
    password: &str,
    grant: &FullGrant,
    synced: Option<ChainState>,
) -> Result<FfiUnlocked, OnePassError> {
    {
        let mut store = SyncStore::open(path)?;
        for r in &grant.snapshot {
            store.stage_remote(r.to_remote_change()?)?;
        }
        store.commit_remote()?;
        store.set_chain_state(&ChainState {
            device_id: Some(grant.device_id),
            ..synced.unwrap_or_default()
        })?;
    }
    let unlocked = crate::unlock_password(db_path, password, &grant.secret_key)?;
    if unlocked.session.account_id() != id_hex(grant.account_id) {
        return Err(OnePassError::from(onepass_core::Error::Integrity(
            IntegrityError::WrongContext,
        )));
    }
    // Every vault and every item opens and matches its signed manifest.
    unlocked.session.vaults()?;
    unlocked.session.item_summaries()?;
    if unlocked.session.this_device_id() != Some(id_hex(grant.device_id)) {
        return Err(refused("device id"));
    }
    Ok(unlocked)
}

/// The store holds `account` only because the sync brought it: its params
/// record is that account's, and this device never opened it (no pinned
/// account, no device id of its own).
fn synced_only(store: &SyncStore, account: Id) -> Result<bool, OnePassError> {
    let params = store.list(RecordKind::AccountParams)?;
    Ok(params.len() == 1
        && params[0].id == account
        && store.device_state()?.pinned.is_none()
        && store.chain_state()?.device_id.is_none())
}

// ---- approver ---------------------------------------------------------------

/// The store as this device sees it (ruling A10): every kind, the `base`
/// rows with the pending writes on top, pending deletions left out. Each
/// row is a signed record as written; the size cap applies.
fn local_snapshot(store: &SyncStore) -> Result<Vec<SnapshotRecord>, OnePassError> {
    let mut snapshot = Vec::new();
    for code in 1..=u8::MAX {
        let Ok(kind) = RecordKind::from_code(code) else {
            break;
        };
        let mut rows = store.list(kind)?;
        rows.sort_by_key(|r| r.id);
        snapshot.extend(rows.iter().map(SnapshotRecord::from_record));
    }
    check_snapshot_size(&snapshot)?;
    Ok(snapshot)
}

/// An item as a public device gets it (ruling A11): no password history
/// and no passkey (its private key would sign for the account).
fn lean(mut item: Item) -> Item {
    item.password_history.clear();
    for section in &mut item.sections {
        section
            .fields
            .retain(|f| !matches!(f.value, FieldValue::Passkey(_)));
    }
    item
}

/// The approver's side of the rendezvous direction: shows a code (QR and
/// typed) renewed every 30 s, and takes the one `JoinHello` that proves it.
/// Once a Hello is accepted, or after five bad ones, the host is closed.
#[derive(uniffi::Object)]
pub struct PairingHost {
    inner: Mutex<Host>,
}

/// A code on the approver's screen.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiHostCode {
    /// The text to draw as a QR code (`OPPAIR2:...`).
    pub qr_text: String,
    /// The same secret to read and type (`XXXX-XXXX`).
    pub short_text: String,
    /// The Bonjour service to publish for this code until `expires_at`.
    pub service_name: String,
    /// When this code stops being accepted (Unix seconds).
    pub expires_at: i64,
}

/// The Bonjour service name of a rendezvous code: what a newcomer connects
/// to after scanning or typing it. Accepts the QR text or the typed form.
#[uniffi::export]
pub fn pairing_rendezvous_service_name(code: String) -> Result<String, OnePassError> {
    Ok(RendezvousCode::parse(&code)?.service_name())
}

#[uniffi::export]
impl PairingHost {
    #[uniffi::constructor]
    pub fn new() -> Result<Arc<Self>, OnePassError> {
        Ok(Arc::new(PairingHost {
            inner: Mutex::new(Host::new()),
        }))
    }

    /// A new code, valid 120 s from `now`; older ones stay valid until
    /// their own expiry. Call every 30 s while the window is open.
    pub fn issue(&self, now: i64) -> Result<FfiHostCode, OnePassError> {
        let c = lock(&self.inner).issue(now)?;
        Ok(FfiHostCode {
            qr_text: c.qr_text,
            short_text: c.short_text,
            service_name: c.service_name,
            expires_at: c.expires_at,
        })
    }

    /// Check a newcomer's first frame against the live codes and start the
    /// approver session. Errors do not say whether the code or the frame
    /// was wrong. After success every code is spent.
    pub fn accept(
        &self,
        join_hello: Vec<u8>,
        now: i64,
    ) -> Result<Arc<PairingApprover>, OnePassError> {
        let (core, key_exchange, sas, peer, requested) =
            lock(&self.inner).accept(&join_hello, now)?;
        // The session id the grant is bound to: the newcomer drew it.
        let session_id = onepass_core::pairing::JoinHello::from_bytes(&join_hello)?
            .hello
            .session_id;
        Ok(PairingApprover::from_parts(
            core,
            key_exchange,
            sas,
            peer,
            requested,
            session_id,
        ))
    }

    /// Spend the codes: the window closed or the user refused the code.
    pub fn close(&self) {
        lock(&self.inner).close();
    }

    pub fn is_open(&self) -> bool {
        lock(&self.inner).is_open()
    }
}

struct ApproverState {
    core: Approver,
    peer_confirmed: bool,
    granted: bool,
    /// Key rotation v2: the newcomer's key is introduced (`introduce`).
    introduced: bool,
}

/// The unlocked device's side: scans the QR, compares the code, grants.
#[derive(uniffi::Object)]
pub struct PairingApprover {
    key_exchange: Vec<u8>,
    sas: String,
    peer: DeviceInfo,
    requested: DeviceMode,
    session_id: [u8; 16],
    state: Mutex<ApproverState>,
}

impl PairingApprover {
    fn from_parts(
        core: Approver,
        key_exchange: Vec<u8>,
        sas: String,
        peer: DeviceInfo,
        requested: DeviceMode,
        session_id: [u8; 16],
    ) -> Arc<Self> {
        Arc::new(PairingApprover {
            key_exchange,
            sas,
            peer,
            requested,
            session_id,
            state: Mutex::new(ApproverState {
                core,
                peer_confirmed: false,
                granted: false,
                introduced: false,
            }),
        })
    }
}

#[uniffi::export]
impl PairingApprover {
    /// Check the scanned QR text against the newcomer's Hello and start the
    /// session. Refused for an expired QR or a Hello the QR does not commit
    /// to, before anything is sent.
    #[uniffi::constructor]
    pub fn begin(qr_text: String, hello: Vec<u8>, now: i64) -> Result<Arc<Self>, OnePassError> {
        let session_id = PairingQr::parse(&qr_text)?.session_id;
        let (core, key_exchange, sas, peer, requested) = Approver::begin(&qr_text, &hello, now)?;
        Ok(Self::from_parts(
            core,
            key_exchange,
            sas,
            peer,
            requested,
            session_id,
        ))
    }

    /// The 6-digit code to compare with the newcomer's screen.
    pub fn sas(&self) -> String {
        self.sas.clone()
    }

    /// Who asks to join.
    pub fn peer(&self) -> FfiPeerDevice {
        FfiPeerDevice {
            id: id_hex(self.peer.device_id),
            name: self.peer.name.clone(),
            kind: self.peer.kind.into(),
        }
    }

    pub fn requested_mode(&self) -> FfiDeviceMode {
        self.requested.into()
    }

    /// The frame to send right after `begin`.
    pub fn key_exchange(&self) -> Vec<u8> {
        self.key_exchange.clone()
    }

    /// The Bonjour service name of this session (the session id in hex).
    pub fn service_name(&self) -> String {
        bytes_hex(&self.session_id)
    }

    /// Open a frame from the newcomer (its confirmation, the ack, audit
    /// events, the end).
    pub fn on_frame(&self, frame: Vec<u8>) -> Result<FfiPairingMessage, OnePassError> {
        let mut s = lock(&self.state);
        let msg = s.core.on_frame(&frame)?;
        match &msg {
            Message::Confirmed => s.peer_confirmed = true,
            // Key rotation v2: the first one is the confirmation; the
            // second, after the `FullV2`, the acknowledgment (`Ack`): the
            // app then calls `introduce`.
            Message::ConfirmedWithKey { .. } if !s.peer_confirmed => s.peer_confirmed = true,
            Message::ConfirmedWithKey { .. } => return Ok(FfiPairingMessage::Ack),
            _ => {}
        }
        Ok(message_to_ffi(&msg))
    }

    /// Invite sessions only: the account's display name and photo (at most
    /// 64 characters and 256 KiB), sent once, after the newcomer confirmed
    /// and the user here approved (calling this is that approval), before
    /// `seal_full_grant`. Refused in a session from the newcomer's QR.
    pub fn seal_profile(&self, name: String, photo: Vec<u8>) -> Result<Vec<u8>, OnePassError> {
        let mut s = lock(&self.state);
        if !s.peer_confirmed {
            return Err(refused("the new device has not confirmed the code"));
        }
        Ok(s.core
            .seal_profile_at(ProfileCard { name, photo }, true, now_unix())?)
    }

    /// Grant the account to a personal or shared device, once the newcomer
    /// confirmed the code and the user here approved (calling this is that
    /// approval). Adds the newcomer to the signed device list (added by this
    /// device), then seals the Secret Key and the store snapshot, at most
    /// 50 MiB, in one store transaction: a snapshot above the cap, or any
    /// refusal of the seal, rolls the addition back (nothing is listed). Without `include_pending` (an approver
    /// that syncs, and synced just before) the snapshot is the rows the
    /// server holds, and a store with no synced account is refused. With
    /// `include_pending` (an approver without sync, ruling A10) it is the
    /// full local view: the server rows with every pending write on top,
    /// the new device list included; each is a signed record the newcomer
    /// checks like a server fetch. Refused before the peer's confirmation,
    /// for a public request, and for a mode other than the one requested.
    ///
    /// Cross-platform sync (spec 4.12): a `FullV2` carries the account's
    /// signed `SyncHome`, if any, and, for a mailbox home, an enroll ticket
    /// `mailbox` issues for the newcomer's credential (when it sent one).
    #[uniffi::method(default(mailbox = None))]
    pub fn seal_full_grant(
        &self,
        session: Arc<Session>,
        secret_key: String,
        mode: FfiDeviceMode,
        include_pending: bool,
        mailbox: Option<Arc<MailboxSync>>,
    ) -> Result<Vec<u8>, OnePassError> {
        let secret_key = Zeroizing::new(secret_key);
        let secret_key = Zeroizing::new(SecretKey::parse(&secret_key)?.to_display());
        let mode = DeviceMode::from(mode);
        let mut s = lock(&self.state);
        if s.granted {
            return Err(refused("already granted"));
        }
        if !s.peer_confirmed {
            return Err(refused("not confirmed"));
        }
        if self.requested == DeviceMode::Public || mode != self.requested {
            return Err(refused("grant does not match the requested mode"));
        }
        let peer = self.peer.clone();
        let v2 = s.core.newcomer_key().is_some();
        let core = &mut s.core;
        let frame = session.with(|repo| {
            // Key rotation v2 (spec 5.2): a device waiting for the user,
            // locked or orphaned pins nobody.
            require_current(repo.store().trust_state()?.as_ref())?;
            let account_id = account_id_of(repo)?;
            // Without pending writes the snapshot is the `base` rows: the
            // device list written below is pending and reaches the newcomer
            // through sync.
            let base = if include_pending {
                None
            } else {
                let snapshot = snapshot_from_store(repo.store())?;
                let synced = |kind: RecordKind| {
                    snapshot
                        .iter()
                        .any(|r| r.kind == kind.code() && r.id == account_id)
                };
                if !synced(RecordKind::AccountParams) || !synced(RecordKind::Keyset) {
                    return Err(invalid("account not synced"));
                }
                Some(snapshot)
            };
            // A device already listed (and not revoked) re-pairs (spec 7.4):
            // granted again, not listed twice.
            let listed = repo
                .devices()?
                .into_iter()
                .find(|d| d.device_id == peer.device_id);
            if let Some(d) = &listed {
                if d.revoked_at.is_some() || !v2 {
                    return Err(refused("device already listed"));
                }
                let snapshot = match base {
                    Some(snapshot) => snapshot,
                    None => local_snapshot(repo.store())?,
                };
                let grant = FullGrantV2 {
                    full: FullGrant {
                        account_id,
                        secret_key: secret_key.clone(),
                        mode,
                        device_id: peer.device_id,
                        snapshot,
                    },
                    trust: repo.trust_snapshot()?,
                    sync: None,
                    enroll: None,
                };
                let grant = with_mailbox(core, repo, grant, mailbox.as_deref())?;
                return Ok(core.seal_grant(Grant::FullV2(grant), true)?);
            }
            let added_by = repo.this_device_id();
            let entry = DeviceEntry {
                device_id: peer.device_id,
                name: peer.name.clone(),
                kind: peer.kind,
                mode,
                added_at: now_unix(),
                added_by,
                revoked_at: None,
            };
            // The device is listed only if the grant seals: a snapshot above
            // the cap (or any refusal) rolls the addition back.
            let secret_key = secret_key.clone();
            repo.add_device_then(entry, |repo| {
                // Key rotation v2 (spec 15, Task 13): a newcomer paired
                // without a device key is trusted on first use.
                if !v2 {
                    repo.mark_legacy_device(peer.device_id)?;
                }
                let snapshot = match base {
                    Some(snapshot) => snapshot,
                    None => local_snapshot(repo.store())?,
                };
                let full = FullGrant {
                    account_id,
                    secret_key,
                    mode,
                    device_id: peer.device_id,
                    snapshot,
                };
                // A newcomer that sent its device key gets its trust
                // snapshot (spec 5.2); its intro follows its acknowledgment.
                let grant = if v2 {
                    let grant = FullGrantV2 {
                        full,
                        trust: repo.trust_snapshot()?,
                        sync: None,
                        enroll: None,
                    };
                    Grant::FullV2(with_mailbox(core, repo, grant, mailbox.as_deref())?)
                } else {
                    Grant::Full(full)
                };
                Ok::<_, OnePassError>(core.seal_grant(grant, true)?)
            })
        })?;
        s.granted = true;
        Ok(frame)
    }

    /// Lend these items, read only, for `minutes` (1 to 60, 15 by default)
    /// to a public device, once the newcomer confirmed the code and the user
    /// here approved. Nothing is listed or written.
    #[uniffi::method(default(minutes = 15))]
    pub fn seal_public_grant(
        &self,
        session: Arc<Session>,
        items: Vec<FfiItemRef>,
        minutes: u32,
    ) -> Result<Vec<u8>, OnePassError> {
        if !(1..=PUBLIC_SESSION_MAX_MINUTES).contains(&minutes) {
            return Err(OnePassError::Validation {
                field: "minutes".into(),
                reason: "out of range".into(),
            });
        }
        if items.is_empty() {
            return Err(OnePassError::Validation {
                field: "items".into(),
                reason: "empty".into(),
            });
        }
        let refs = items
            .iter()
            .map(|r| Ok((parse_id(&r.vault_id)?, parse_id(&r.item_id)?)))
            .collect::<Result<Vec<_>, OnePassError>>()?;
        let mut s = lock(&self.state);
        if s.granted {
            return Err(refused("already granted"));
        }
        if !s.peer_confirmed {
            return Err(refused("not confirmed"));
        }
        if self.requested != DeviceMode::Public {
            return Err(refused("grant does not match the requested mode"));
        }
        let lent = session.with(|repo| {
            // Spec 10.9: public sessions are refused outside `Current`.
            require_current(repo.store().trust_state()?.as_ref())?;
            let mut out = Vec::with_capacity(refs.len());
            for (vault_id, item_id) in &refs {
                let vault = find_vault(repo, *vault_id)?;
                out.push(lean(find_item(repo, &vault, *item_id)?));
            }
            Ok(out)
        })?;
        let grant = Grant::Public(PublicGrant {
            session_id: self.session_id,
            expires_at: now_unix().saturating_add(i64::from(minutes) * 60),
            read_only: true,
            items: lent,
        });
        let frame = s.core.seal_grant(grant, true)?;
        s.granted = true;
        Ok(frame)
    }

    /// Key rotation v2 (spec 5.2, 6.4): after the newcomer's
    /// acknowledgment of its `FullV2` (`on_frame` returns `Ack`), pin its
    /// device key: the signed intro and this device's trust state, in one
    /// transaction, with this device's keys. Once; a device already pinned
    /// with these keys (a re-pair) changes nothing.
    pub fn introduce(
        &self,
        session: Arc<Session>,
        classical: Vec<u8>,
        pq: Arc<dyn FfiPqDeviceHalf>,
    ) -> Result<(), OnePassError> {
        let classical = Zeroizing::new(classical);
        let keys = device_keys(&classical, pq)?;
        let mut s = lock(&self.state);
        if s.introduced {
            return Err(refused("already introduced"));
        }
        let key = s
            .core
            .newcomer_key()
            .cloned()
            .ok_or_else(|| refused("no device key"))?;
        let pop = s
            .core
            .newcomer_account_pop()
            .cloned()
            .ok_or_else(|| refused("not acknowledged"))?;
        let info = self.peer.clone();
        let mode = self.requested;
        session.with(|repo| Ok(repo.introduce(&key, &info, mode, &pop, &keys)?))?;
        s.introduced = true;
        Ok(())
    }

    /// Whether the device asking is already listed in the account (spec
    /// 7.4): the screen says "Ajouter de nouveau <nom>" rather than a new
    /// device, and `seal_full_grant` grants it again without listing it.
    pub fn is_known_device(&self, session: Arc<Session>) -> Result<bool, OnePassError> {
        let id = self.peer.device_id;
        session.with(|repo| {
            Ok(repo
                .devices()?
                .iter()
                .any(|d| d.device_id == id && d.revoked_at.is_none()))
        })
    }

    /// End the session (the user stops a public session, or cancels).
    pub fn seal_end(&self) -> Result<Vec<u8>, OnePassError> {
        Ok(lock(&self.state).core.seal(&Message::End)?)
    }
}
