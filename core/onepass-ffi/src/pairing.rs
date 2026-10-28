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
    Approver, AuditAction, AuditEvent, DeviceInfo, FullGrant, Grant, Message, Newcomer, PairingQr,
    PublicGrant, SnapshotRecord, check_snapshot_size, snapshot_from_store,
};
use onepass_core::store::{RecordKind, RecordStore};
use onepass_core::sync::{AccountState, SyncStore};
use onepass_core::{Id, IntegrityError};
use time::OffsetDateTime;
use zeroize::Zeroizing;

use crate::convert::{bytes_hex, id_hex, item_to_ffi, parse_id};
use crate::devices::{FfiDeviceKind, FfiDeviceMode};
use crate::error::{OnePassError, invalid};
use crate::session::{Session, account_id_of, find_item, find_vault};
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
        Message::Confirmed => FfiPairingMessage::Confirmed,
        Message::Grant(Grant::Full(g)) => FfiPairingMessage::FullGrant {
            account_id: id_hex(g.account_id),
            mode: g.mode.into(),
            device_id: id_hex(g.device_id),
            snapshot_records: u32::try_from(g.snapshot.len()).unwrap_or(u32::MAX),
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

/// The Bonjour service name of a pairing QR: its session id in hex. Parses
/// the QR (canonical text only) and trusts nothing else.
#[uniffi::export]
pub fn pairing_service_name(qr_text: String) -> Result<String, OnePassError> {
    Ok(bytes_hex(&PairingQr::parse(&qr_text)?.session_id))
}

// ---- newcomer ---------------------------------------------------------------

struct NewcomerState {
    core: Newcomer,
    /// The full grant received, until its snapshot is imported.
    grant: Option<FullGrant>,
    /// The Secret Key, once the import succeeded, until Swift takes it.
    released: Option<Zeroizing<String>>,
    imported: bool,
}

/// The new device's side: shows the QR, gets the account or a public
/// session.
#[derive(uniffi::Object)]
pub struct PairingNewcomer {
    device_id: Id,
    qr_text: String,
    hello: Vec<u8>,
    session_id: [u8; 16],
    expires_at: i64,
    state: Mutex<NewcomerState>,
}

#[uniffi::export]
impl PairingNewcomer {
    /// A new pairing session for this device, under a fresh device id. The
    /// QR is valid 120 s from `now` (Unix seconds); renew it by making a new
    /// object.
    #[uniffi::constructor]
    pub fn new(
        name: String,
        kind: FfiDeviceKind,
        mode: FfiDeviceMode,
        now: i64,
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
            session_id: qr.session_id,
            expires_at: qr.expires_at,
            state: Mutex::new(NewcomerState {
                core,
                grant: None,
                released: None,
                imported: false,
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

    /// The Bonjour service name to publish: the session id in hex.
    pub fn service_name(&self) -> String {
        bytes_hex(&self.session_id)
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
        if let Message::Grant(Grant::Full(g)) = msg {
            s.grant = Some(g);
        }
        Ok(out)
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
        match SyncStore::open(path)?.account_state()? {
            AccountState::Empty => {}
            AccountState::Present | AccountState::PinnedButMissing => {
                return Err(invalid("store not empty"));
            }
        }
        match import(path, &db_path, &password, grant) {
            Ok(unlocked) => {
                s.released = Some(grant.secret_key.clone());
                s.grant = None;
                s.imported = true;
                Ok(unlocked)
            }
            Err(e) => {
                // Nothing of the snapshot stays on the device. If the reset
                // itself fails the import error is still the one reported.
                if let Ok(mut store) = SyncStore::open(path) {
                    let _ = store.reset();
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
) -> Result<FfiUnlocked, OnePassError> {
    {
        let mut store = SyncStore::open(path)?;
        for r in &grant.snapshot {
            store.stage_remote(r.to_remote_change()?)?;
        }
        store.commit_remote()?;
        store.set_chain_state(&ChainState {
            device_id: Some(grant.device_id),
            ..ChainState::default()
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

struct ApproverState {
    core: Approver,
    peer_confirmed: bool,
    granted: bool,
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

#[uniffi::export]
impl PairingApprover {
    /// Check the scanned QR text against the newcomer's Hello and start the
    /// session. Refused for an expired QR or a Hello the QR does not commit
    /// to, before anything is sent.
    #[uniffi::constructor]
    pub fn begin(qr_text: String, hello: Vec<u8>, now: i64) -> Result<Arc<Self>, OnePassError> {
        let session_id = PairingQr::parse(&qr_text)?.session_id;
        let (core, key_exchange, sas, peer, requested) = Approver::begin(&qr_text, &hello, now)?;
        Ok(Arc::new(PairingApprover {
            key_exchange,
            sas,
            peer,
            requested,
            session_id,
            state: Mutex::new(ApproverState {
                core,
                peer_confirmed: false,
                granted: false,
            }),
        }))
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
        if msg == Message::Confirmed {
            s.peer_confirmed = true;
        }
        Ok(message_to_ffi(&msg))
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
    pub fn seal_full_grant(
        &self,
        session: Arc<Session>,
        secret_key: String,
        mode: FfiDeviceMode,
        include_pending: bool,
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
        let core = &mut s.core;
        let frame = session.with(|repo| {
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
            repo.devices()?;
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
                let snapshot = match base {
                    Some(snapshot) => snapshot,
                    None => local_snapshot(repo.store())?,
                };
                let grant = Grant::Full(FullGrant {
                    account_id,
                    secret_key,
                    mode,
                    device_id: peer.device_id,
                    snapshot,
                });
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

    /// End the session (the user stops a public session, or cancels).
    pub fn seal_end(&self) -> Result<Vec<u8>, OnePassError> {
        Ok(lock(&self.state).core.seal(&Message::End)?)
    }
}
