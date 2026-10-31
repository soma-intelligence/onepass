//! Key rotation v2 over the UniFFI surface (spec 7, 8, 9, 10.9, 18, Task
//! 17): device keys, rotate, the confirmation prompt, follow, reject, the
//! quarantine, the Emergency Kit restore, the migration of a legacy device
//! and what the device screens show.
//!
//! Rust never touches the Keychain. The app keeps its device keys in its
//! own Keychain item (`device.<account_id>`): the classical halves as the
//! bytes `generate_classical_device_keys` returns, the post-quantum half in
//! the Secure Enclave (`SecureEnclave.MLDSA87`, `SecureEnclave.MLKEM1024`)
//! or in software where there is none. Every call that signs or unwraps
//! with the device keys takes `classical` and `pq` (an `FfiPqDeviceHalf`
//! the app implements); a foreign half that fails makes the call fail with
//! nothing written.
//!
//! Secrets handed back to the app (the new Secret Key after a follow, the
//! Account Unlock Key) are returned once, as the rest of the crate does:
//! the app moves them into the Keychain and drops its copy.

use std::path::Path;
use std::sync::Arc;

use onepass_core::crypto::SecretKey;
use onepass_core::crypto::sign::HybridSignature;
use onepass_core::device_keys::{DeviceKeys, DevicePublic, PqDeviceHalf};
use onepass_core::lineage::RotationReason;
use onepass_core::lineage::resolve::PromptKind;
use onepass_core::repo::follow::{self, QuarantineChoice, QuarantineTick};
use onepass_core::repo::kit::{KitRestore, KitRestored};
use onepass_core::repo::migrate::Migration;
use onepass_core::repo::replay::ReplayReport;
use onepass_core::repo::{LineageLock, Repository, RotateRequest, RotationOutcome, RotationPrompt};
use onepass_core::store::RecordStore;
use onepass_core::sync::SyncStore;
use onepass_core::trust::{DeviceLineageState, TrustLevel, TrustState};
use onepass_core::{Error, Id};
use zeroize::Zeroizing;

use crate::convert::{bytes_hex, hex_bytes, id_hex, parse_id};
use crate::devices::{FfiDeviceKind, FfiDeviceMode};
use crate::error::{OnePassError, invalid};
use crate::pairing::FfiItemRef;
use crate::session::{Repo, Session, refine};
use crate::travel::TRAVEL_STATE_KEY;

// ---- device keys --------------------------------------------------------------

/// The post-quantum half of this device's keys, implemented by the app:
/// pure ML-DSA-87 with an empty context and FIPS 203 ML-KEM-1024, in the
/// Secure Enclave where there is one. Same wire format as the software
/// half of the core. Called on the thread of the FFI call, sometimes while
/// that call holds its `Session` (rotate, reapply, migrate, kit accept,
/// introduce): an implementation must never call back into the FFI from
/// these methods, or it deadlocks.
#[uniffi::export(with_foreign)]
pub trait FfiPqDeviceHalf: Send + Sync {
    /// ML-DSA-87 public key, 2592 bytes.
    fn mldsa_public(&self) -> Result<Vec<u8>, OnePassError>;
    /// ML-KEM-1024 encapsulation key, 1568 bytes.
    fn mlkem_public(&self) -> Result<Vec<u8>, OnePassError>;
    /// Pure ML-DSA-87 signature (empty context) over `message`, 4627 bytes.
    fn mldsa_sign(&self, message: Vec<u8>) -> Result<Vec<u8>, OnePassError>;
    /// The 32-byte shared secret of `ciphertext` (FIPS 203 decapsulation).
    fn mlkem_decapsulate(&self, ciphertext: Vec<u8>) -> Result<Vec<u8>, OnePassError>;
}

/// The app's half seen by the core. Any error of the app is a failed
/// cryptographic operation (`Error::Crypto`): the core writes nothing then.
struct ForeignHalf(Arc<dyn FfiPqDeviceHalf>);

impl PqDeviceHalf for ForeignHalf {
    fn mldsa_public(&self) -> onepass_core::Result<Vec<u8>> {
        self.0.mldsa_public().map_err(|_| Error::Crypto)
    }

    fn mlkem_public(&self) -> onepass_core::Result<Vec<u8>> {
        self.0.mlkem_public().map_err(|_| Error::Crypto)
    }

    fn mldsa_sign(&self, message: &[u8]) -> onepass_core::Result<Vec<u8>> {
        self.0
            .mldsa_sign(message.to_vec())
            .map_err(|_| Error::Crypto)
    }

    fn mlkem_decapsulate(&self, ciphertext: &[u8]) -> onepass_core::Result<Zeroizing<Vec<u8>>> {
        self.0
            .mlkem_decapsulate(ciphertext.to_vec())
            .map(Zeroizing::new)
            .map_err(|_| Error::Crypto)
    }
}

/// This device's keys from the app's classical bytes and its half.
pub(crate) fn device_keys(
    classical: &[u8],
    pq: Arc<dyn FfiPqDeviceHalf>,
) -> Result<DeviceKeys, OnePassError> {
    Ok(DeviceKeys::new(classical, Box::new(ForeignHalf(pq)))?)
}

/// Fresh classical halves (Ed25519 seed and X25519 secret, 65 bytes): the
/// app stores them with its Secure Enclave key blobs in its Keychain item
/// `device.<account_id>`, once, when it creates the device's keys.
#[uniffi::export]
pub fn generate_classical_device_keys() -> Result<Vec<u8>, OnePassError> {
    Ok(DeviceKeys::generate_classical()?.to_vec())
}

/// The public keys of this device under `device_id` (32 hex characters),
/// encoded as the core pins them: what a pairing or a verification shows.
#[uniffi::export]
pub fn device_public(
    classical: Vec<u8>,
    pq: Arc<dyn FfiPqDeviceHalf>,
    device_id: String,
) -> Result<Vec<u8>, OnePassError> {
    let classical = Zeroizing::new(classical);
    let keys = device_keys(&classical, pq)?;
    Ok(keys.public(parse_id(&device_id)?)?.encode())
}

/// The fingerprint of an encoded device public key (hex), as the
/// verification screens compare it.
#[uniffi::export]
pub fn device_fingerprint(public: Vec<u8>) -> Result<String, OnePassError> {
    Ok(bytes_hex(&DevicePublic::decode(&public)?.fingerprint()))
}

/// A new Secret Key for a rotation (K6): the app stores it as pending in
/// the Keychain before `rotate_keys`, and promotes it once the call
/// returns.
#[uniffi::export]
pub fn generate_secret_key() -> Result<String, OnePassError> {
    Ok(SecretKey::generate()?.to_display())
}

// ---- states -------------------------------------------------------------------

/// Where this device stands along the lineage (spec 8.1).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum FfiLineageState {
    /// No device keys yet: `migrate_to_v2` after the first unlock.
    Legacy,
    Current,
    /// A rotation waits for the user: read only.
    Candidate,
    /// This device pushes its own rotation (phases 1 to 3).
    Rotating {
        phase: u8,
    },
    /// Locked, erased at `erase_at` (device time, Unix seconds) unless the
    /// user answers "Ce n'était pas moi".
    Quarantined {
        since: u64,
        erase_at: u64,
    },
    /// Not in the account's keys any more: reads, never writes.
    Orphaned,
}

/// What the device screens and the extensions read before anything else
/// (spec 10.9: the AutoFill extension, the Watch and the widgets show
/// "Ouvre OnePass pour continuer" unless `usable`).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiLineageStatus {
    pub state: FfiLineageState,
    /// The generation of the head (0 at the genesis); 0 for `Legacy`.
    pub generation: u64,
    /// `Current` or `Legacy`: the extension and public sessions may run.
    pub usable: bool,
    /// Removing a device is a rotation (`rotate_keys` with `revoke`), never
    /// `revoke_device` (spec 10.1).
    pub removes_by_rotation: bool,
    /// Restored with the Emergency Kit, no device pinned it yet.
    pub awaiting_pin: bool,
}

fn state_of(t: Option<&TrustState>) -> FfiLineageState {
    match t.map(|t| &t.state) {
        None | Some(DeviceLineageState::Legacy) => FfiLineageState::Legacy,
        Some(DeviceLineageState::Current) => FfiLineageState::Current,
        Some(DeviceLineageState::Candidate { .. }) => FfiLineageState::Candidate,
        Some(DeviceLineageState::Rotating { phase }) => FfiLineageState::Rotating { phase: *phase },
        Some(DeviceLineageState::Quarantined { since, .. }) => FfiLineageState::Quarantined {
            since: *since,
            erase_at: since.saturating_add(follow::QUARANTINE_ERASE_AFTER_SECS),
        },
        Some(DeviceLineageState::Orphaned { .. }) => FfiLineageState::Orphaned,
    }
}

fn status_of(t: Option<&TrustState>, awaiting_pin: bool) -> FfiLineageStatus {
    let state = state_of(t);
    FfiLineageStatus {
        usable: matches!(state, FfiLineageState::Legacy | FfiLineageState::Current),
        state,
        generation: t.map_or(0, |t| t.head.generation),
        removes_by_rotation: t.is_some(),
        awaiting_pin,
    }
}

/// The status of the store at `db_path`, without unlocking (the
/// extensions, the launch screen).
#[uniffi::export]
pub fn lineage_status(db_path: String) -> Result<FfiLineageStatus, OnePassError> {
    let store = open(&db_path)?;
    let t = store.trust_state()?;
    let unpinned = t
        .as_ref()
        .is_some_and(|t| !t.roster.iter().any(|e| e.device_id == t.me.device_id));
    Ok(status_of(t.as_ref(), unpinned))
}

/// `RotationPending`, `Quarantined` or `Orphaned` unless the trust state
/// is `Current` (or absent: a legacy device). For the calls that need the
/// device `Current` (rotate, public sessions, pairing as approver).
pub(crate) fn require_current(t: Option<&TrustState>) -> Result<(), OnePassError> {
    match t.map(|t| &t.state) {
        None | Some(DeviceLineageState::Legacy | DeviceLineageState::Current) => Ok(()),
        Some(DeviceLineageState::Candidate { .. } | DeviceLineageState::Rotating { .. }) => {
            Err(OnePassError::RotationPending)
        }
        Some(DeviceLineageState::Quarantined { .. }) => Err(OnePassError::Quarantined),
        Some(DeviceLineageState::Orphaned { .. }) => Err(OnePassError::Orphaned),
    }
}

/// A core refusal of a call that needs `Current`, named by the state the
/// device is in.
fn state_refusal(repo: &Repo, e: OnePassError) -> OnePassError {
    let e = refine(repo, e);
    match &e {
        OnePassError::Validation { field, reason }
            if field == "device"
                && (reason == "not current" || reason == "own writes to replay") =>
        {
            match require_current(repo.store().trust_state().ok().flatten().as_ref()) {
                Err(named) => named,
                Ok(()) => OnePassError::RotationPending,
            }
        }
        _ => e,
    }
}

fn open(db_path: &str) -> Result<SyncStore, OnePassError> {
    Ok(SyncStore::open(Path::new(db_path))?)
}

fn hash_hex(h: &[u8; 32]) -> String {
    bytes_hex(h)
}

fn parse_hash(s: &str) -> Result<[u8; 32], OnePassError> {
    hex_bytes(s)
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .ok_or_else(|| invalid("rotation"))
}

/// A postcard-encoded hybrid signature, decoded strictly (the whole
/// buffer, canonical).
fn decode_signature(b: &[u8]) -> Result<HybridSignature, OnePassError> {
    let sig: HybridSignature = postcard::from_bytes(b).map_err(|_| invalid("signature"))?;
    if postcard::to_allocvec(&sig).ok().as_deref() != Some(b) {
        return Err(invalid("signature"));
    }
    Ok(sig)
}

fn code_text(code: u32) -> String {
    format!("{code:06}")
}

// ---- rotate -------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiRotationReason {
    /// "Retirer cet appareil": `revoke` lists at least one device.
    Revoke,
    /// "Faire tourner les clés".
    Rotate,
    /// "Faire tourner les clés" with a new master password.
    RotateWithPassword,
}

/// What the rotator's screens collected (spec 7.1, 9).
#[derive(uniffi::Record)]
pub struct FfiRotateRequest {
    /// Devices to remove (32 hex characters each), never this one.
    pub revoke: Vec<String>,
    /// The new master password, `None` to keep it.
    pub new_password: Option<String>,
    pub password: String,
    pub secret_key: String,
    /// From `generate_secret_key`, stored as pending in the Keychain
    /// before the call (K6).
    pub new_secret_key: String,
    pub reason: FfiRotationReason,
    /// Spec 15 step 5: the devices trusted on first use (`FfiRosterDevice`
    /// with `Tofu`) the user confirmed to keep, each listed on the screen;
    /// any other one leaves the new keys and re-pairs. Empty by default.
    pub keep_tofu: Vec<String>,
}

/// A committed rotation (spec 9: the new Emergency Kit, the code).
#[derive(uniffi::Record)]
pub struct FfiRotationOutcome {
    /// The new Account Unlock Key, to enroll biometrics again.
    pub auk: Vec<u8>,
    /// The 6-digit rotation code shown on both sides (O2).
    pub code: String,
    /// The lineage hash of the new head (hex).
    pub head: String,
}

fn outcome(o: RotationOutcome) -> FfiRotationOutcome {
    FfiRotationOutcome {
        auk: o.auk.as_bytes().to_vec(),
        code: code_text(o.code),
        head: hash_hex(&o.head),
    }
}

fn ids(list: &[String]) -> Result<Vec<Id>, OnePassError> {
    list.iter().map(|s| parse_id(s)).collect()
}

/// A device of this device's roster (spec 5.3), for the rotation screens:
/// the `Tofu` ones need an explicit yes to be kept (spec 15 step 5).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiRosterDevice {
    pub id: String,
    pub name: String,
    pub kind: FfiDeviceKind,
    pub mode: FfiDeviceMode,
    /// Trusted on first use: "Cet appareil n'a pas été vérifié depuis la
    /// mise à jour."
    pub tofu: bool,
    pub is_this_device: bool,
}

/// The own-write alert (spec 10.4, G4): writes of this device that a
/// rotation could not carry over, named.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiOwnWriteAlert {
    pub alert: bool,
    /// Vault and item of each; an item id equal to its vault id is the
    /// vault's name and look.
    pub lost: Vec<FfiItemRef>,
}

/// What a replay of this device's own writes did (spec 10.4).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiReplayReport {
    pub replayed: u32,
    pub present: u32,
    pub superseded: u32,
    pub lost: u32,
    pub waiting: u32,
}

fn count(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

fn report(r: &ReplayReport) -> FfiReplayReport {
    FfiReplayReport {
        replayed: count(r.replayed),
        present: count(r.present),
        superseded: count(r.superseded),
        lost: count(r.lost),
        waiting: count(r.waiting),
    }
}

/// A device restored with the Emergency Kit asking to be trusted (spec 7.5
/// step 5). The app shows the name with the marker "restauré par Kit",
/// never as a known device.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiKitRestored {
    pub id: String,
    pub name: String,
    pub kind: FfiDeviceKind,
    pub mode: FfiDeviceMode,
    /// The name is one of this device's roster: "porte le même nom qu'un de
    /// tes appareils".
    pub name_in_use: bool,
    /// It already changed the keys: it cannot be accepted any more (alert
    /// "Quelqu'un a restauré avec ton Emergency Kit et changé les clés").
    pub rotated: bool,
}

fn kit_to_ffi(k: KitRestored) -> FfiKitRestored {
    FfiKitRestored {
        id: id_hex(k.device_id),
        name: k.name,
        kind: k.kind.into(),
        mode: k.mode.into(),
        name_in_use: k.name_in_use,
        rotated: k.rotated,
    }
}

/// What `migrate_to_v2` did (spec 15).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum FfiMigration {
    Already,
    /// This device made the genesis (lineage hash, hex).
    Genesis {
        head: String,
    },
    /// This device joined the genesis of another device.
    Joined {
        head: String,
    },
}

/// The one-time screens of spec 15.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct FfiMigrationAlerts {
    /// "Un appareil retiré garde encore les clés de ton compte. Fais
    /// tourner les clés maintenant."
    pub rotate_now: bool,
    /// Another genesis of this account appeared.
    pub other_genesis: bool,
}

/// A session after a follow, a switch or a re-pair.
#[derive(uniffi::Record)]
pub struct FfiFollowed {
    /// Open on the new identity; `None` when a step after the adoption
    /// failed (`warning`): the adoption stands, the app stores the keys
    /// below and opens the session again with a plain unlock.
    pub session: Option<Arc<Session>>,
    /// To enroll biometrics again.
    pub auk: Vec<u8>,
    /// The new Secret Key, once: the app promotes it in the Keychain (no
    /// Secret Key is ever typed to follow, R4).
    pub secret_key: String,
    /// This device removed devices the new keys keep (spec 8.5 step 5):
    /// call `Session::reapply` in the same user step.
    pub reapply_needed: bool,
    /// Writes of this device the follow could not carry over.
    pub own_writes: FfiOwnWriteAlert,
    /// The first step after the adoption that failed (saving the device
    /// state, re-sealing the Travel Mode state, opening the session).
    /// Never a reason to drop the keys: the adoption is committed.
    pub warning: Option<OnePassError>,
}

fn alert_of(repo: &Repo) -> Result<FfiOwnWriteAlert, OnePassError> {
    let a = repo.own_write_alert()?;
    Ok(FfiOwnWriteAlert {
        alert: a.alert,
        lost: a
            .lost
            .into_iter()
            .map(|(v, i)| FfiItemRef {
                vault_id: id_hex(v),
                item_id: id_hex(i),
            })
            .collect(),
    })
}

/// After a follow, a switch or a re-pair: the device state persisted, the
/// Travel Mode state re-sealed under the new identity (spec 10.6, Task 16:
/// right after the adoption, before the session opens it), the session
/// opened.
///
/// Review Important 1 (fix round 1): the adoption is committed when this
/// runs, so nothing here fails the call. A failing step is reported in
/// `warning` and the keys always go back to the app; every step is one a
/// plain unlock with the new Secret Key runs again (`reconcile_pin`, the
/// re-seal tolerance of `open_travel_state`).
pub(crate) fn followed(
    mut repo: Repo,
    auk: onepass_core::account::Auk,
    secret_key: SecretKey,
) -> FfiFollowed {
    let mut warning: Option<OnePassError> = None;
    let mut note = |r: Result<(), OnePassError>| {
        if let Err(e) = r {
            warning.get_or_insert(e);
        }
    };
    note(repo.persist_device_state().map_err(Into::into));
    note((|| {
        if let Some(sealed) = repo.store().meta(TRAVEL_STATE_KEY)? {
            let fresh = repo.reseal_travel_state(&sealed)?;
            repo.store_mut().set_meta(TRAVEL_STATE_KEY, &fresh)?;
        }
        Ok(())
    })());
    let reapply_needed = repo.uncovered_removals().is_ok_and(|r| !r.is_empty());
    let own_writes = alert_of(&repo).unwrap_or(FfiOwnWriteAlert {
        alert: false,
        lost: Vec::new(),
    });
    let session = match Session::new(repo) {
        Ok(s) => Some(s),
        Err(e) => {
            warning.get_or_insert(e);
            None
        }
    };
    FfiFollowed {
        session,
        auk: auk.as_bytes().to_vec(),
        secret_key: secret_key.to_display(),
        reapply_needed,
        own_writes,
        warning,
    }
}

/// Review Minor 2: a locked device answers with its own kind before any
/// follow or reject (`Quarantined`, `Orphaned`).
fn refuse_locked(store: &SyncStore) -> Result<(), OnePassError> {
    match store.trust_state()?.map(|t| t.state) {
        Some(DeviceLineageState::Quarantined { .. }) => Err(OnePassError::Quarantined),
        Some(DeviceLineageState::Orphaned { .. }) => Err(OnePassError::Orphaned),
        _ => Ok(()),
    }
}

#[uniffi::export]
impl Session {
    /// The lineage status of this session's store.
    pub fn lineage_status(&self) -> Result<FfiLineageStatus, OnePassError> {
        self.with(|repo| {
            let t = repo.store().trust_state()?;
            Ok(status_of(t.as_ref(), repo.awaiting_pin()?))
        })
    }

    /// Rotate every key of the account (spec 7.1): "Retirer cet appareil"
    /// or "Faire tourner les clés". The app ran a full sync first and keeps
    /// the new Secret Key pending in the Keychain (K6); once this returns,
    /// it promotes it, shows the new Emergency Kit and the code, and syncs
    /// (the phases go up in order).
    ///
    /// Refused, nothing written: a device not `Current` (`RotationPending`,
    /// `Quarantined`, `Orphaned`), Travel Mode on, a device to remove that
    /// is this one or unknown, a `Tofu` device to keep that is not one
    /// (`Validation`), the same Secret Key (`Validation`), a wrong password
    /// (`WrongPassword`), device keys other than the pinned ones or a
    /// failing `pq` (`Validation`, `Crypto`).
    pub fn rotate_keys(
        &self,
        request: FfiRotateRequest,
        classical: Vec<u8>,
        pq: Arc<dyn FfiPqDeviceHalf>,
    ) -> Result<FfiRotationOutcome, OnePassError> {
        let classical = Zeroizing::new(classical);
        let password = Zeroizing::new(request.password);
        let new_password = request.new_password.map(Zeroizing::new);
        let secret_key = SecretKey::parse(&Zeroizing::new(request.secret_key))?;
        let new_secret_key = SecretKey::parse(&Zeroizing::new(request.new_secret_key))?;
        let revoke = ids(&request.revoke)?;
        let keep_tofu = ids(&request.keep_tofu)?;
        let reason = match request.reason {
            FfiRotationReason::Revoke => RotationReason::Revoke,
            FfiRotationReason::Rotate => RotationReason::Rotate,
            FfiRotationReason::RotateWithPassword => RotationReason::RotateWithPassword,
        };
        let keys = device_keys(&classical, pq)?;
        self.with(|repo| {
            require_current(repo.store().trust_state()?.as_ref())?;
            let out = repo
                .rotate(RotateRequest {
                    revoke: revoke.clone(),
                    new_password: new_password.as_ref().map(|p| p.as_str()),
                    password: &password,
                    secret_key: &secret_key,
                    new_secret_key: &new_secret_key,
                    device_keys: &keys,
                    reason,
                    keep_tofu: &keep_tofu,
                })
                .map_err(|e| state_refusal(repo, e.into()))?;
            Ok(outcome(out))
        })
    }

    /// After a switch (`FfiFollowed::reapply_needed`): remove again, as a
    /// child of the new head, the devices this device removed that it keeps
    /// (spec 8.5 step 5), in the same user step. `password` and
    /// `secret_key` are the ones just followed; `new_secret_key` is drawn
    /// and kept pending as for `rotate_keys`. `None`: nothing to re-apply,
    /// nothing written.
    pub fn reapply(
        &self,
        password: String,
        secret_key: String,
        new_secret_key: String,
        classical: Vec<u8>,
        pq: Arc<dyn FfiPqDeviceHalf>,
    ) -> Result<Option<FfiRotationOutcome>, OnePassError> {
        let classical = Zeroizing::new(classical);
        let password = Zeroizing::new(password);
        let secret_key = SecretKey::parse(&Zeroizing::new(secret_key))?;
        let new_secret_key = SecretKey::parse(&Zeroizing::new(new_secret_key))?;
        let keys = device_keys(&classical, pq)?;
        self.with(|repo| {
            Ok(repo
                .reapply(&password, &secret_key, &new_secret_key, &keys)
                .map_err(|e| state_refusal(repo, e.into()))?
                .map(outcome))
        })
    }

    /// This device's roster (spec 5.3), sorted by id; empty on a legacy
    /// device.
    pub fn roster(&self) -> Result<Vec<FfiRosterDevice>, OnePassError> {
        self.with(|repo| {
            let Some(t) = repo.store().trust_state()? else {
                return Ok(Vec::new());
            };
            Ok(t.roster
                .iter()
                .map(|e| FfiRosterDevice {
                    id: id_hex(e.device_id),
                    name: e.name.clone(),
                    kind: e.kind.into(),
                    mode: e.mode.into(),
                    tofu: t.levels.get(&e.device_id) == Some(&TrustLevel::Tofu),
                    is_this_device: e.device_id == t.me.device_id,
                })
                .collect())
        })
    }

    /// The rotation prompt this session waits on, looked for again first
    /// (after a sync in another connection): while there is one every
    /// write is `ReadOnly`.
    pub fn pending_rotation(&self) -> Result<Option<FfiRotationPrompt>, OnePassError> {
        let mut guard = self.guard();
        let repo = guard.as_mut().ok_or(OnePassError::Locked)?;
        if crate::session::identity_left(repo)? {
            return Err(OnePassError::IdentityLeft);
        }
        Ok(repo.refresh_pending_rotation()?.as_ref().map(prompt_to_ffi))
    }

    /// Follow `choice` from this session (spec 8.5 step 4): a switch, or any
    /// prompt while the session is open. The session is consumed: locked
    /// afterwards, also when the call fails (unlock again then).
    pub fn follow_switch(
        &self,
        choice: String,
        password: String,
        classical: Vec<u8>,
        pq: Arc<dyn FfiPqDeviceHalf>,
    ) -> Result<FfiFollowed, OnePassError> {
        let classical = Zeroizing::new(classical);
        let password = Zeroizing::new(password);
        let choice = parse_hash(&choice)?;
        let keys = device_keys(&classical, pq)?;
        let repo = self.take()?;
        let (repo, auk, sk) = follow::follow_switch(repo, choice, &password, &keys)?;
        Ok(followed(repo, auk, sk))
    }

    /// Replay this device's own writes of an identity it left (spec 10.4)
    /// again: after a sync brought the new content, or once a prompt was
    /// answered. The follow already ran it once.
    pub fn replay_own_writes(&self) -> Result<FfiReplayReport, OnePassError> {
        self.with(|repo| Ok(report(&repo.replay_own_writes()?)))
    }

    /// Re-seal the stored Travel Mode state under the identity this session
    /// is on (spec 10.6, Task 16). The follows of this crate already do it
    /// right after the adoption; this is for a state the app put back
    /// later. A no-op outside Travel Mode.
    pub fn reseal_travel_state(&self) -> Result<(), OnePassError> {
        self.with(|repo| {
            if let Some(sealed) = repo.store().meta(TRAVEL_STATE_KEY)? {
                let fresh = repo.reseal_travel_state(&sealed)?;
                repo.store_mut().set_meta(TRAVEL_STATE_KEY, &fresh)?;
            }
            Ok(())
        })
    }

    /// The own-write alert (spec 10.4).
    pub fn own_write_alert(&self) -> Result<FfiOwnWriteAlert, OnePassError> {
        self.with(|repo| alert_of(repo))
    }

    /// The user saw the own-write alert.
    pub fn clear_own_write_alert(&self) -> Result<(), OnePassError> {
        self.with(|repo| Ok(repo.clear_own_write_alert()?))
    }

    // ---- migration (spec 15) ----

    /// On the first unlock after the update, with the device keys the app
    /// just created: the genesis, or this device's legacy intro under the
    /// genesis of another device. A full sync first.
    pub fn migrate_to_v2(
        &self,
        classical: Vec<u8>,
        pq: Arc<dyn FfiPqDeviceHalf>,
    ) -> Result<FfiMigration, OnePassError> {
        let classical = Zeroizing::new(classical);
        let keys = device_keys(&classical, pq)?;
        self.with(|repo| {
            Ok(match repo.migrate_to_v2(&keys)? {
                Migration::Already => FfiMigration::Already,
                Migration::Genesis(h) => FfiMigration::Genesis { head: hash_hex(&h) },
                Migration::Joined(h) => FfiMigration::Joined { head: hash_hex(&h) },
            })
        })
    }

    pub fn migration_alerts(&self) -> Result<FfiMigrationAlerts, OnePassError> {
        self.with(|repo| {
            let a = repo.migration_alerts()?;
            Ok(FfiMigrationAlerts {
                rotate_now: a.rotate_now,
                other_genesis: a.other_genesis,
            })
        })
    }

    pub fn clear_rotate_now_prompt(&self) -> Result<(), OnePassError> {
        self.with(|repo| Ok(repo.clear_rotate_now_prompt()?))
    }

    pub fn clear_genesis_alert(&self) -> Result<(), OnePassError> {
        self.with(|repo| Ok(repo.clear_genesis_alert()?))
    }

    /// The devices that have not migrated (spec 15): a rotation now leaves
    /// them out, "devra être réappairé". Sorted ids.
    pub fn unmigrated_devices(&self) -> Result<Vec<String>, OnePassError> {
        self.with(|repo| Ok(repo.unmigrated_devices()?.into_iter().map(id_hex).collect()))
    }

    /// "Vérifier mes appareils" (spec 15 step 4): `peer` (an encoded
    /// device public key) and its proof of possession `pop` (encoded
    /// signature) over the pairing `transcript`, carried by the QR and SAS
    /// session the Swift plan builds. `peer` becomes `Verified`.
    pub fn verify_device(
        &self,
        peer: Vec<u8>,
        transcript: Vec<u8>,
        pop: Vec<u8>,
    ) -> Result<(), OnePassError> {
        let peer = DevicePublic::decode(&peer)?;
        let pop = decode_signature(&pop)?;
        self.with(|repo| Ok(repo.verify_device(&peer, &transcript, &pop)?))
    }

    // ---- Emergency Kit (spec 7.5) ----

    /// Restored with the Emergency Kit and not pinned yet.
    pub fn awaiting_pin(&self) -> Result<bool, OnePassError> {
        self.with(|repo| Ok(repo.awaiting_pin()?))
    }

    /// The devices restored with the Emergency Kit asking this device to
    /// trust them.
    pub fn kit_restored_devices(&self) -> Result<Vec<FfiKitRestored>, OnePassError> {
        self.with(|repo| {
            Ok(repo
                .kit_restored_devices()?
                .into_iter()
                .map(kit_to_ffi)
                .collect())
        })
    }

    /// The kit-restored devices that changed the keys without this device.
    pub fn kit_rotation_alerts(&self) -> Result<Vec<FfiKitRestored>, OnePassError> {
        self.with(|repo| {
            Ok(repo
                .kit_rotation_alerts()?
                .into_iter()
                .map(kit_to_ffi)
                .collect())
        })
    }

    /// "Faire confiance" to a kit-restored device.
    pub fn accept_kit_restored(
        &self,
        id: String,
        classical: Vec<u8>,
        pq: Arc<dyn FfiPqDeviceHalf>,
    ) -> Result<(), OnePassError> {
        let classical = Zeroizing::new(classical);
        let id = parse_id(&id)?;
        let keys = device_keys(&classical, pq)?;
        self.with(|repo| Ok(repo.accept_kit_restored(id, &keys)?))
    }

    /// "Refuser" a kit-restored device: excluded on this device.
    pub fn reject_kit_restored(&self, id: String) -> Result<(), OnePassError> {
        let id = parse_id(&id)?;
        self.with(|repo| Ok(repo.reject_kit_restored(id)?))
    }

    /// Spec 7.5 step 5 (confirmed by the founder on 2026-10-31): "Je n'ai plus
    /// d'autre appareil" on a kit-restored device, after the master
    /// password: it may rotate and pair from then on. The core takes no
    /// password here: the app asks for it first (`verify_password`), also
    /// on a session opened with biometrics.
    pub fn claim_only_device(&self) -> Result<(), OnePassError> {
        self.with(|repo| Ok(repo.claim_only_device()?))
    }
}

// ---- prompt -------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiPromptKind {
    /// "Les clés de ton compte ont changé".
    Single,
    /// "Deux appareils se sont retirés l'un l'autre. Lequel as-tu encore
    /// en main ?"
    Mutual,
    /// "<nom> a aussi fait tourner les clés au même moment..."
    Switch,
    /// A switch whose losing branch is this device's own rotation.
    Reapply,
}

/// One record the user can confirm or reject. Names are this device's
/// local names, never the server's.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiPromptChoice {
    /// To pass to `follow_rotation` or `reject_rotation`.
    pub choice: String,
    pub rotator_name: String,
    pub revoked_names: Vec<String>,
    /// Unix seconds, informative.
    pub issued_at: i64,
    /// "C'est moi" can follow now; otherwise only "Ce n'était pas moi".
    pub complete: bool,
}

/// The confirmation screen (spec 9).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiRotationPrompt {
    pub kind: FfiPromptKind,
    pub choices: Vec<FfiPromptChoice>,
    /// The 6-digit code of the only choice; `None` for `Mutual`.
    pub code: Option<String>,
    /// "Cet appareil n'a pas été vérifié depuis la mise à jour."
    pub tofu_signer: bool,
    pub pending_password_change: bool,
    /// "<rotateur> a retiré <nom> sur un autre jeu de clés."
    pub cross_branch_revocation: bool,
    /// The devices `Session::reapply` removes again after the follow.
    pub reapply_names: Vec<String>,
}

fn prompt_to_ffi(p: &RotationPrompt) -> FfiRotationPrompt {
    FfiRotationPrompt {
        kind: match p.kind {
            PromptKind::Single => FfiPromptKind::Single,
            PromptKind::Mutual => FfiPromptKind::Mutual,
            PromptKind::Switch => FfiPromptKind::Switch,
            PromptKind::Reapply => FfiPromptKind::Reapply,
        },
        choices: p
            .choices
            .iter()
            .map(|c| FfiPromptChoice {
                choice: hash_hex(&c.hash),
                rotator_name: c.rotator_name.clone(),
                revoked_names: c.revoked_names.clone(),
                issued_at: c.issued_at,
                complete: c.complete,
            })
            .collect(),
        code: p.code.map(code_text),
        tofu_signer: p.tofu_signer,
        pending_password_change: p.pending_password_change,
        cross_branch_revocation: p.cross_branch_revocation,
        reapply_names: p.reapply_names.clone(),
    }
}

/// The lock a valid lineage record puts on this device (spec 8.1).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum FfiLineageLock {
    Quarantine { by: String },
    Orphaned { child: String },
}

fn lock_to_ffi(l: LineageLock) -> FfiLineageLock {
    match l {
        LineageLock::Quarantine { by } => FfiLineageLock::Quarantine { by: hash_hex(&by) },
        LineageLock::Orphaned { child } => FfiLineageLock::Orphaned {
            child: hash_hex(&child),
        },
    }
}

/// The confirmation the device waits for (spec 7.2, 9), without
/// unlocking. `None` on a legacy device, with nothing to decide, or when
/// a lock applies (`lineage_lock`).
#[uniffi::export]
pub fn pending_rotation(db_path: String) -> Result<Option<FfiRotationPrompt>, OnePassError> {
    let store = open(&db_path)?;
    Ok(follow::pending_rotation(&store)?
        .as_ref()
        .map(prompt_to_ffi))
}

/// The lock a valid lineage record puts on this device, without
/// unlocking.
#[uniffi::export]
pub fn lineage_lock(db_path: String) -> Result<Option<FfiLineageLock>, OnePassError> {
    let store = open(&db_path)?;
    Ok(follow::lineage_lock(&store)?.map(lock_to_ffi))
}

/// "C'est moi" and the master password (spec 7.2): this device's Secret
/// Key delivery opened with its device keys, the new identity adopted in
/// one local transaction, own writes replayed, the Travel Mode state
/// re-sealed, the session opened on the new identity. A switch follows
/// from the open session (`Session::follow_switch`). Refused with nothing
/// written: a choice not offered or incomplete (`Validation`, `NotFound`),
/// a wrong password, device keys other than the pinned ones or a failing
/// `pq`, a locked device (`Validation`).
#[uniffi::export]
pub fn follow_rotation(
    db_path: String,
    choice: String,
    password: String,
    classical: Vec<u8>,
    pq: Arc<dyn FfiPqDeviceHalf>,
) -> Result<FfiFollowed, OnePassError> {
    let classical = Zeroizing::new(classical);
    let password = Zeroizing::new(password);
    let choice = parse_hash(&choice)?;
    let keys = device_keys(&classical, pq)?;
    let store = open(&db_path)?;
    refuse_locked(&store)?;
    let (repo, auk, sk) = follow::follow_rotation(store, choice, &password, &keys)?;
    Ok(followed(repo, auk, sk))
}

/// "Ce n'était pas moi" for `choice` (spec 8.2): rejected on this device,
/// its signer excluded when `exclude` ("OnePass ne fait plus confiance à
/// <nom> sur cet appareil"). The app then offers "Retirer et faire tourner
/// les clés" (`Session::rotate_keys` revoking that signer).
#[uniffi::export]
pub fn reject_rotation(db_path: String, choice: String, exclude: bool) -> Result<(), OnePassError> {
    let choice = parse_hash(&choice)?;
    let mut store = open(&db_path)?;
    refuse_locked(&store)?;
    Ok(follow::reject_rotation(&mut store, choice, exclude)?)
}

// ---- quarantine ---------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiQuarantineTick {
    NotQuarantined,
    /// Locked; erased at `erase_at` (device time, Unix seconds).
    Waiting {
        erase_at: u64,
    },
    /// The store was erased: the app deletes what it keeps for the account
    /// in the Keychain (Secret Key, Account Unlock Key, device keys).
    Erased,
}

fn tick_to_ffi(t: QuarantineTick) -> FfiQuarantineTick {
    match t {
        QuarantineTick::NotQuarantined => FfiQuarantineTick::NotQuarantined,
        QuarantineTick::Waiting { erase_at } => FfiQuarantineTick::Waiting { erase_at },
        QuarantineTick::Erased => FfiQuarantineTick::Erased,
    }
}

/// The quarantine clock (spec 8.4, R8, O1) with the app's clock `now`
/// (Unix seconds): at launch and on the quarantine screen. Erases only
/// 7 days after a valid lineage record revoking this device was first
/// read; a clock moved back only delays it.
#[uniffi::export]
pub fn quarantine_tick(db_path: String, now: u64) -> Result<FfiQuarantineTick, OnePassError> {
    let mut store = open(&db_path)?;
    Ok(tick_to_ffi(follow::quarantine_tick(&mut store, now)?))
}

/// The user's answer on the quarantine or orphaned screen.
#[derive(uniffi::Enum)]
pub enum FfiQuarantineChoice {
    /// "Effacer cet appareil" (quarantine only).
    Erase,
    /// "Ce n'était pas moi" with the password and the Secret Key of the
    /// identity the device is on.
    NotMe {
        password: String,
        secret_key: String,
    },
}

/// Answer the lock (spec 8.2, 8.4). `Erase`: the store is erased, `None`
/// (the app deletes its Keychain items). `NotMe`: the signer excluded, the
/// erase cancelled, the session opened.
#[uniffi::export]
pub fn quarantine_resolve(
    db_path: String,
    choice: FfiQuarantineChoice,
) -> Result<Option<Arc<Session>>, OnePassError> {
    let store = open(&db_path)?;
    let device = store.device_state()?;
    let repo = match choice {
        FfiQuarantineChoice::Erase => follow::quarantine_resolve(store, QuarantineChoice::Erase)?,
        FfiQuarantineChoice::NotMe {
            password,
            secret_key,
        } => {
            let password = Zeroizing::new(password);
            let secret_key = SecretKey::parse(&Zeroizing::new(secret_key))?;
            follow::quarantine_resolve(
                store,
                QuarantineChoice::NotMe {
                    password: &password,
                    secret_key: &secret_key,
                    device,
                },
            )?
        }
    };
    match repo {
        Some(mut repo) => {
            repo.persist_device_state()?;
            Ok(Some(Session::new(repo)?))
        }
        None => Ok(None),
    }
}

// ---- sync contract --------------------------------------------------------------

/// What a committed fetch changed for the device (the sync contract of
/// key rotation v2): the vaults held for a rebase, then the prompt and the
/// lock looked for again and the quarantine clock run, so no app path can
/// skip them.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiRemoteCommit {
    /// The vaults held for a rebase (`Session::rebase_all`).
    pub vaults: Vec<String>,
    /// The confirmation to show now, if any.
    pub prompt: Option<FfiRotationPrompt>,
    /// The lock to show now, if any.
    pub lock: Option<FfiLineageLock>,
    /// The quarantine clock after this fetch.
    pub quarantine: FfiQuarantineTick,
}

/// After every `commit_remote`: the quarantine clock at `now`, then the
/// prompt and the lock as the store shows them. A store without a trust
/// state (legacy) gets nothing.
pub(crate) fn after_commit(
    store: &mut SyncStore,
    vaults: Vec<Id>,
    now: u64,
) -> Result<FfiRemoteCommit, OnePassError> {
    let quarantine = tick_to_ffi(follow::quarantine_tick(store, now)?);
    let (prompt, lock) = if quarantine == FfiQuarantineTick::Erased {
        (None, None)
    } else {
        (
            follow::pending_rotation(store)?.as_ref().map(prompt_to_ffi),
            follow::lineage_lock(store)?.map(lock_to_ffi),
        )
    };
    Ok(FfiRemoteCommit {
        vaults: vaults.into_iter().map(id_hex).collect(),
        prompt,
        lock,
        quarantine,
    })
}

// ---- accounts and restore ----------------------------------------------------------

/// New account with device keys (spec 6.2, 15 step 6): the genesis and
/// this device's trust state in the same write. `kdf`: `None` for the
/// default (floor) parameters.
#[uniffi::export]
#[allow(clippy::too_many_arguments)]
pub fn create_account_v2(
    db_path: String,
    password: String,
    kdf: Option<crate::types::FfiKdfParams>,
    classical: Vec<u8>,
    pq: Arc<dyn FfiPqDeviceHalf>,
    name: String,
    kind: FfiDeviceKind,
    mode: FfiDeviceMode,
) -> Result<crate::types::FfiCreatedAccount, OnePassError> {
    let password = Zeroizing::new(password);
    let classical = Zeroizing::new(classical);
    let kdf = match kdf {
        Some(k) => crate::kdf_params(k)?,
        None => onepass_core::crypto::KdfParams::new_default()?,
    };
    let keys = device_keys(&classical, pq)?;
    crate::create_v2(
        &db_path,
        &password,
        kdf,
        &keys,
        &name,
        kind.into(),
        mode.into(),
    )
}

/// "Restaurer avec mon Emergency Kit" (spec 7.5, R14), after a full sync:
/// with the master password, the kit's Secret Key and the device keys the
/// app just created. An outdated kit is `OutdatedKit` (nothing restored).
/// The session opens on the kit's identity; the device asks the others to
/// trust it.
#[uniffi::export]
#[allow(clippy::too_many_arguments)]
pub fn restore_from_kit(
    db_path: String,
    password: String,
    secret_key: String,
    classical: Vec<u8>,
    pq: Arc<dyn FfiPqDeviceHalf>,
    name: String,
    kind: FfiDeviceKind,
    mode: FfiDeviceMode,
) -> Result<Arc<Session>, OnePassError> {
    let password = Zeroizing::new(password);
    let classical = Zeroizing::new(classical);
    let secret_key = SecretKey::parse(&Zeroizing::new(secret_key))?;
    let keys = device_keys(&classical, pq)?;
    let store = open(&db_path)?;
    let device = store.device_state()?;
    let mut repo = Repository::restore_from_kit(
        store,
        KitRestore {
            password: &password,
            secret_key: &secret_key,
            device_keys: &keys,
            name: &name,
            kind: kind.into(),
            mode: mode.into(),
            device,
        },
    )?;
    repo.persist_device_state()?;
    Session::new(repo)
}
