//! Remote approval and remote unlock (agent-ready spec 4 to 6) over the
//! FFI: the approval keys of this device, the signed and sealed messages
//! between a Mac and an iPhone, the split-knowledge unlock (`C` on the Mac,
//! `K_r` on the phone) and the agents-only session it opens.
//!
//! Swift keeps the private approval keys in its keychain and passes them in
//! at each call (`FfiApproverKeys`); they are wiped here after use. The
//! transport (CloudKit) only ever carries the blobs.
//!
//! Local memory, in the meta table of this device's `SyncStore` (never
//! synced, out of reach of `SyncStoreHandle`, whose keys are under `sync.`):
//! - phone: the replay guard and, per Mac, the highest device list and
//!   approver list `seq` its requests carried (a lower one is refused, spec
//!   threat A5);
//! - Mac: the replay guard of the phone's notices (`Lock`, `ForgetUnlock`),
//!   the remote unlock throttle and the request it waits on. Policy:
//!   a request whose answer never came counts as a refusal, settled by the
//!   next `begin` (or `throttle_state`, read only) once it has expired.

use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use onepass_core::account::{Account, Auk};
use onepass_core::approvers::{ApproverEntry, ApproverRole, approvers_without_unlock};
use onepass_core::crypto::{
    HybridKemPublic, HybridKemSecret, HybridSigningKey, SymmetricKey, random_array,
};
use onepass_core::remote::{
    self as core_remote, ApproverIdentity, PendingRequests, REQUEST_TTL_SECS, RemoteDecision,
    RemoteKind, ReplayGuard, RequestBody, RequestHeader,
};
use onepass_core::remote_unlock::{self, UnlockThrottle, clamp_window_minutes};
use onepass_core::repo::Repository;
use onepass_core::store::{RecordKind, RecordStore};
use onepass_core::sync::SyncStore;
use onepass_core::{Error, Id, IntegrityError};
use zeroize::Zeroizing;

use crate::convert::{id_hex, parse_id};
use crate::developer::FfiDetail;
use crate::error::{OnePassError, invalid};
use crate::session::{Repo, Session};

const REPLAY_KEY: &str = "remote.replay_guard";
const PEER_SEQS_KEY: &str = "remote.peer_seqs";
const THROTTLE_KEY: &str = "remote.unlock_throttle";
const WAITING_KEY: &str = "remote.unlock_waiting";
const NOTICE_REPLAY_KEY: &str = "remote.notice_replay_guard";

/// Serializes every read-modify-write of the remote memory in the local
/// meta (throttle, waiting mark, replay guards) within this process, so two
/// concurrent calls (two `begin` on one or two `RemoteUnlocker`s, two
/// notices) never lose an update.
static META: Mutex<()> = Mutex::new(());
/// Most Macs whose last `seq` values a phone remembers.
const MAX_PEERS: usize = 256;

fn unix_now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

fn integrity(e: IntegrityError) -> OnePassError {
    Error::Integrity(e).into()
}

fn unregistered() -> OnePassError {
    OnePassError::Validation {
        field: "device".into(),
        reason: "unregistered".into(),
    }
}

fn remote_unlock_refused(reason: &str) -> OnePassError {
    OnePassError::Validation {
        field: "remote_unlock".into(),
        reason: reason.into(),
    }
}

// ---- types

/// This device's private approval keys, as the keychain keeps them. Never
/// printed.
#[derive(Clone, uniffi::Record)]
pub struct FfiApproverKeys {
    pub signing: Vec<u8>,
    pub kem_secret: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiApproverRole {
    Mac,
    Phone,
}

impl From<FfiApproverRole> for ApproverRole {
    fn from(r: FfiApproverRole) -> Self {
        match r {
            FfiApproverRole::Mac => ApproverRole::Mac,
            FfiApproverRole::Phone => ApproverRole::Phone,
        }
    }
}

impl From<ApproverRole> for FfiApproverRole {
    fn from(r: ApproverRole) -> Self {
        match r {
            ApproverRole::Mac => FfiApproverRole::Mac,
            ApproverRole::Phone => FfiApproverRole::Phone,
        }
    }
}

/// An approver of the account that counts (listed, not revoked, not
/// retired).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiApprover {
    pub device_id: String,
    /// The name in the device list.
    pub device_name: String,
    pub role: FfiApproverRole,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiRemoteKind {
    Approve,
    Unlock,
    ApproveAndUnlock,
    Pair,
    Lock,
    ForgetUnlock,
}

impl From<FfiRemoteKind> for RemoteKind {
    fn from(k: FfiRemoteKind) -> Self {
        match k {
            FfiRemoteKind::Approve => RemoteKind::Approve,
            FfiRemoteKind::Unlock => RemoteKind::Unlock,
            FfiRemoteKind::ApproveAndUnlock => RemoteKind::ApproveAndUnlock,
            FfiRemoteKind::Pair => RemoteKind::Pair,
            FfiRemoteKind::Lock => RemoteKind::Lock,
            FfiRemoteKind::ForgetUnlock => RemoteKind::ForgetUnlock,
        }
    }
}

impl From<RemoteKind> for FfiRemoteKind {
    fn from(k: RemoteKind) -> Self {
        match k {
            RemoteKind::Approve => FfiRemoteKind::Approve,
            RemoteKind::Unlock => FfiRemoteKind::Unlock,
            RemoteKind::ApproveAndUnlock => FfiRemoteKind::ApproveAndUnlock,
            RemoteKind::Pair => FfiRemoteKind::Pair,
            RemoteKind::Lock => FfiRemoteKind::Lock,
            RemoteKind::ForgetUnlock => FfiRemoteKind::ForgetUnlock,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiRemoteDecision {
    Denied,
    Once,
    Grant5m,
}

impl From<FfiRemoteDecision> for RemoteDecision {
    fn from(d: FfiRemoteDecision) -> Self {
        match d {
            FfiRemoteDecision::Denied => RemoteDecision::Denied,
            FfiRemoteDecision::Once => RemoteDecision::Once,
            FfiRemoteDecision::Grant5m => RemoteDecision::Grant5m,
        }
    }
}

impl From<RemoteDecision> for FfiRemoteDecision {
    fn from(d: RemoteDecision) -> Self {
        match d {
            RemoteDecision::Denied => FfiRemoteDecision::Denied,
            RemoteDecision::Once => FfiRemoteDecision::Once,
            RemoteDecision::Grant5m => FfiRemoteDecision::Grant5m,
        }
    }
}

/// What the phone shows of a request (sealed to it, no secret). The keys
/// an unlock or a pairing needs are filled by the core, never by Swift.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiRequestBody {
    pub client: String,
    pub client_verified: bool,
    pub action: String,
    pub details: Vec<FfiDetail>,
    /// Vault, item and field names the request touches.
    pub targets: Vec<String>,
    pub remember_allowed: bool,
    pub strong_required: bool,
    /// The two letters shown to the agent.
    pub confirm_code: String,
    /// Agents-only window of an unlock request (set by `begin`).
    pub window_minutes: Option<u32>,
}

/// A signed request ready for the transport.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiSealedRequest {
    pub request_id: Vec<u8>,
    /// The phone's device id (the clear `to` field of the record).
    pub to: String,
    pub expires_at: i64,
    pub blob: Vec<u8>,
}

/// A request the phone accepted.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiOpenedRequest {
    pub request_id: Vec<u8>,
    /// The Mac's device id and its name in the device list.
    pub from: String,
    pub from_name: String,
    pub kind: FfiRemoteKind,
    pub created_at: i64,
    pub expires_at: i64,
    pub body: FfiRequestBody,
}

/// What a phone may tell its Mac (spec 6.3, 6.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiNoticeKind {
    /// "Verrouiller maintenant": end the agents-only window.
    Lock,
    /// The phone forgot `K_r`: erase `C`.
    ForgetUnlock,
}

impl From<FfiNoticeKind> for RemoteKind {
    fn from(k: FfiNoticeKind) -> Self {
        match k {
            FfiNoticeKind::Lock => RemoteKind::Lock,
            FfiNoticeKind::ForgetUnlock => RemoteKind::ForgetUnlock,
        }
    }
}

/// A notice the Mac accepted from an enrolled phone.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiNotice {
    pub kind: FfiNoticeKind,
    /// The phone's device id.
    pub from: String,
}

/// A phone's answer the Mac accepted.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiRemoteResponse {
    pub request_id: Vec<u8>,
    pub from: String,
    pub created_at: i64,
    pub decision: FfiRemoteDecision,
}

/// Remote unlock enrollment: `C` for the Mac's keychain, and the `Pair`
/// request carrying `K_r` to the phone (already wiped here).
#[derive(Clone, uniffi::Record)]
pub struct FfiEnrollment {
    pub c: Vec<u8>,
    /// Shown on the Mac; the phone shows the same two letters.
    pub confirm_code: String,
    pub transfer_request: FfiSealedRequest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct FfiUnlockThrottleState {
    /// A remote unlock request may go out now.
    pub may_request: bool,
}

// ---- conversions

/// The identity of `device_id` from the keychain bytes, which are wiped.
fn identity(keys: FfiApproverKeys, device_id: Id) -> Result<ApproverIdentity, OnePassError> {
    let signing = Zeroizing::new(keys.signing);
    let kem = Zeroizing::new(keys.kem_secret);
    Ok(ApproverIdentity {
        device_id,
        signing: HybridSigningKey::from_bytes(&signing)?,
        kem: HybridKemSecret::from_bytes(&kem)?,
    })
}

fn body_to_core(
    b: FfiRequestBody,
    unlock_eph_pub: Option<HybridKemPublic>,
    transfer_key: Option<Zeroizing<[u8; 32]>>,
    window_minutes: Option<u32>,
) -> RequestBody {
    RequestBody {
        client: b.client,
        client_verified: b.client_verified,
        action: b.action,
        details: b.details.into_iter().map(|d| (d.label, d.value)).collect(),
        targets: b.targets,
        remember_allowed: b.remember_allowed,
        strong_required: b.strong_required,
        confirm_code: b.confirm_code,
        unlock_eph_pub,
        transfer_key,
        window_minutes,
    }
}

fn body_to_ffi(b: &RequestBody) -> FfiRequestBody {
    FfiRequestBody {
        client: b.client.clone(),
        client_verified: b.client_verified,
        action: b.action.clone(),
        details: b
            .details
            .iter()
            .map(|(label, value)| FfiDetail {
                label: label.clone(),
                value: value.clone(),
            })
            .collect(),
        targets: b.targets.clone(),
        remember_allowed: b.remember_allowed,
        strong_required: b.strong_required,
        confirm_code: b.confirm_code.clone(),
        window_minutes: b.window_minutes,
    }
}

fn sealed(header: &RequestHeader, blob: Vec<u8>) -> FfiSealedRequest {
    FfiSealedRequest {
        request_id: header.request_id.to_vec(),
        to: id_hex(header.to),
        expires_at: header.expires_at,
        blob,
    }
}

fn header(
    from: Id,
    to: Id,
    kind: RemoteKind,
    device_list_seq: u64,
    approver_list_seq: u64,
    created_at: i64,
) -> Result<RequestHeader, OnePassError> {
    Ok(RequestHeader {
        request_id: core_remote::new_request_id()?,
        from,
        to,
        created_at,
        expires_at: created_at + REQUEST_TTL_SECS,
        registry_seq: device_list_seq,
        approver_list_seq,
        kind,
    })
}

/// The active entry of `device` with `role`, or `NotFound`.
fn entry_of(
    approvers: &[ApproverEntry],
    device: Id,
    role: ApproverRole,
) -> Result<&ApproverEntry, OnePassError> {
    approvers
        .iter()
        .find(|e| e.device_id == device && e.role == role)
        .ok_or(OnePassError::NotFound)
}

/// Two letters for a pairing, drawn without modulo bias.
fn confirm_code() -> Result<String, OnePassError> {
    let mut out = String::new();
    while out.len() < 2 {
        let [b] = random_array::<1>()?;
        if b < 234 {
            out.push(char::from(b'a' + b % 26));
        }
    }
    Ok(out)
}

// ---- local memory

type PeerSeqs = Vec<([u8; 16], u64, u64)>;
type WaitingMark = ([u8; 16], i64);

/// One encoding only: trailing bytes are refused.
fn decode_peer_seqs(bytes: &[u8]) -> Result<PeerSeqs, OnePassError> {
    match postcard::take_from_bytes::<PeerSeqs>(bytes) {
        Ok((v, [])) if v.len() <= MAX_PEERS => Ok(v),
        _ => Err(invalid("remote peer seqs")),
    }
}

fn decode_waiting(bytes: &[u8]) -> Result<WaitingMark, OnePassError> {
    match postcard::take_from_bytes::<WaitingMark>(bytes) {
        Ok((v, [])) => Ok(v),
        _ => Err(invalid("remote unlock waiting")),
    }
}

fn load_replay(store: &SyncStore) -> Result<ReplayGuard, OnePassError> {
    match store.meta(REPLAY_KEY)? {
        Some(b) => Ok(ReplayGuard::from_bytes(&b)?),
        None => Ok(ReplayGuard::new()),
    }
}

fn load_peer_seqs(store: &SyncStore) -> Result<PeerSeqs, OnePassError> {
    match store.meta(PEER_SEQS_KEY)? {
        Some(b) => decode_peer_seqs(&b),
        None => Ok(Vec::new()),
    }
}

/// Record the `seq` values a request of `from` carried; refuse lower ones
/// than the last request of that Mac.
fn check_peer_seqs(
    seqs: &mut PeerSeqs,
    from: Id,
    device_list_seq: u64,
    approver_list_seq: u64,
) -> Result<(), OnePassError> {
    if let Some(at) = seqs.iter().position(|(id, _, _)| *id == from.0) {
        let (_, d, a) = seqs.remove(at);
        if device_list_seq < d || approver_list_seq < a {
            seqs.insert(at, (from.0, d, a));
            return Err(OnePassError::Integrity {
                kind: "remote_stale_registry".into(),
            });
        }
    }
    if seqs.len() >= MAX_PEERS {
        seqs.remove(0);
    }
    seqs.push((from.0, device_list_seq, approver_list_seq));
    Ok(())
}

fn load_throttle(store: &SyncStore) -> Result<UnlockThrottle, OnePassError> {
    match store.meta(THROTTLE_KEY)? {
        Some(b) => Ok(UnlockThrottle::from_bytes(&b)?),
        None => Ok(UnlockThrottle::new()),
    }
}

fn load_waiting(store: &SyncStore) -> Result<Option<WaitingMark>, OnePassError> {
    match store.meta(WAITING_KEY)? {
        Some(b) => Ok(Some(decode_waiting(&b)?)),
        None => Ok(None),
    }
}

/// An unanswered request past its expiry counts as a refusal. True when
/// one was settled.
fn settle(throttle: &mut UnlockThrottle, waiting: Option<WaitingMark>, now: i64) -> bool {
    match waiting {
        Some((_, expires_at)) if now > expires_at => {
            throttle.refused(now);
            true
        }
        _ => false,
    }
}

fn save_throttle(
    store: &mut SyncStore,
    throttle: &UnlockThrottle,
    waiting: Option<WaitingMark>,
) -> Result<(), OnePassError> {
    store.set_meta(THROTTLE_KEY, &throttle.to_bytes()?)?;
    match waiting {
        Some(w) => {
            let bytes = postcard::to_allocvec(&w).map_err(|_| invalid("remote unlock waiting"))?;
            store.set_meta(WAITING_KEY, &bytes)?;
        }
        None => store.delete_meta(WAITING_KEY)?,
    }
    Ok(())
}

// ---- keys

/// Fresh approval keys for this device: a hybrid signing key (ML-DSA-87 +
/// Ed25519) and a hybrid KEM key (ML-KEM-1024 + X25519), as bytes for the
/// keychain (this device only, no iCloud sync).
#[uniffi::export]
pub fn generate_approver_keys() -> Result<FfiApproverKeys, OnePassError> {
    let signing = HybridSigningKey::generate()?.to_bytes();
    let kem = HybridKemSecret::generate()?.to_bytes();
    Ok(FfiApproverKeys {
        signing: signing.to_vec(),
        kem_secret: kem.to_vec(),
    })
}

/// The remote unlock throttle of the Mac whose store is at `db_path`, with
/// an expired unanswered request counted as refused (nothing is written).
#[uniffi::export]
pub fn throttle_state(db_path: String) -> Result<FfiUnlockThrottleState, OnePassError> {
    let store = SyncStore::open(Path::new(&db_path))?;
    let mut throttle = load_throttle(&store)?;
    let now = unix_now();
    settle(&mut throttle, load_waiting(&store)?, now);
    Ok(FfiUnlockThrottleState {
        may_request: throttle.may_request(now),
    })
}

// ---- session side

fn this_device(repo: &Repo) -> Result<Id, OnePassError> {
    repo.this_device_id().ok_or_else(unregistered)
}

fn list_seqs(repo: &Repo) -> (u64, u64) {
    let chain = repo.chain();
    (
        chain.device_list.map_or(0, |s| s.seq),
        chain.approver_list.map_or(0, |s| s.seq),
    )
}

fn device_name(repo: &mut Repo, id: Id) -> Result<String, OnePassError> {
    Ok(repo
        .devices()?
        .into_iter()
        .find(|d| d.device_id == id)
        .map(|d| d.name)
        .unwrap_or_default())
}

impl Session {
    fn full(&self) -> Result<(), OnePassError> {
        if self.is_agent_only() {
            Err(OnePassError::Locked)
        } else {
            Ok(())
        }
    }

    /// Seal and sign `body` to `to` (holding the recipient role of `kind`).
    /// A request from the Mac is waited on; a phone notice is not answered.
    fn seal_to(
        &self,
        repo: &mut Repo,
        me: &ApproverIdentity,
        to: Id,
        kind: RemoteKind,
        body: &RequestBody,
    ) -> Result<FfiSealedRequest, OnePassError> {
        let approvers = repo.approvers()?;
        let entry = entry_of(&approvers, to, kind.recipient_role())?;
        let (d, a) = list_seqs(repo);
        let h = header(me.device_id, to, kind, d, a, unix_now())?;
        let blob = core_remote::seal_request(&me.signing, entry, h.clone(), body)?;
        if kind.sender_role() == ApproverRole::Mac {
            lock(&self.pending).insert_header(&h);
        }
        Ok(sealed(&h, blob))
    }

    /// The phone side check shared by the answers: `request_blob` verifies
    /// in full against a fresh guard, and the stored guard already holds it
    /// (opened, so shown, before).
    fn reopen(
        repo: &mut Repo,
        me: &ApproverIdentity,
        request_blob: &[u8],
    ) -> Result<(Vec<ApproverEntry>, core_remote::RemoteRequest, RequestBody), OnePassError> {
        let approvers = repo.approvers()?;
        let (request, body) = core_remote::open_request(
            request_blob,
            me,
            &approvers,
            unix_now(),
            &mut ReplayGuard::new(),
        )?;
        if !load_replay(repo.store())?.contains(&request.request_id) {
            return Err(integrity(IntegrityError::RemoteUnknownRequest));
        }
        Ok((approvers, request, body))
    }
}

#[uniffi::export]
impl Session {
    /// This session was opened from the phone: only the agents (MCP, SSH)
    /// may use it; the app, the extension, AutoFill and the widgets treat
    /// it as locked.
    pub fn is_agent_only(&self) -> bool {
        self.agent_window().is_some()
    }

    /// End of the agents-only window (Unix seconds); `None` for a session
    /// opened on this device. The keys stay in memory until the first use
    /// of the session after that instant (which drops them): Swift must run
    /// a timer that calls `lock` at this deadline.
    pub fn agent_window_ends_at(&self) -> Option<i64> {
        self.agent_window()
    }

    /// Enroll this device's approval keys with `role` (its earlier ones
    /// are retired).
    pub fn register_approver(
        &self,
        keys: FfiApproverKeys,
        role: FfiApproverRole,
    ) -> Result<(), OnePassError> {
        self.full()?;
        let signing = Zeroizing::new(keys.signing);
        let kem = Zeroizing::new(keys.kem_secret);
        let sign_pub = HybridSigningKey::from_bytes(&signing)?.verifying_key()?;
        let kem_pub = HybridKemSecret::from_bytes(&kem)?.public()?;
        self.with(|repo| {
            Ok(repo.register_this_approver(sign_pub.clone(), kem_pub.clone(), role.into())?)
        })
    }

    /// The approvers that count, with their device names.
    pub fn approvers(&self) -> Result<Vec<FfiApprover>, OnePassError> {
        self.with(|repo| {
            let list = repo.approvers()?;
            let devices = repo.devices()?;
            Ok(list
                .iter()
                .map(|e| FfiApprover {
                    device_id: id_hex(e.device_id),
                    device_name: devices
                        .iter()
                        .find(|d| d.device_id == e.device_id)
                        .map(|d| d.name.clone())
                        .unwrap_or_default(),
                    role: e.role.into(),
                })
                .collect())
        })
    }

    /// Mac side: a signed request to the phone `to`, its body sealed to the
    /// phone. `Approve` only: the unlock kinds go through `RemoteUnlocker`,
    /// pairing through `remote_unlock_enroll`, and `Lock` and
    /// `ForgetUnlock` are phone notices (`seal_remote_notice`).
    pub fn seal_remote_request(
        &self,
        keys: FfiApproverKeys,
        to: String,
        kind: FfiRemoteKind,
        body: FfiRequestBody,
    ) -> Result<FfiSealedRequest, OnePassError> {
        let kind = RemoteKind::from(kind);
        if kind != RemoteKind::Approve {
            return Err(invalid("remote kind"));
        }
        let phone = parse_id(&to)?;
        let body = body_to_core(body, None, None, None);
        let me = self.with(|repo| this_device(repo))?;
        let me = identity(keys, me)?;
        self.with(|repo| self.seal_to(repo, &me, phone, kind, &body))
    }

    /// Mac side: the phone's answer to a request this session sent and
    /// still waits on (one answer per request).
    pub fn open_remote_response(
        &self,
        keys: FfiApproverKeys,
        blob: Vec<u8>,
    ) -> Result<FfiRemoteResponse, OnePassError> {
        let me = self.with(|repo| this_device(repo))?;
        let me = identity(keys, me)?;
        self.with(|repo| {
            let approvers = repo.approvers()?;
            let r = core_remote::open_response(
                &blob,
                &me,
                &approvers,
                &mut lock(&self.pending),
                unix_now(),
            )?;
            Ok(FfiRemoteResponse {
                request_id: r.request_id.to_vec(),
                from: id_hex(r.from),
                created_at: r.created_at,
                decision: r.decision.into(),
            })
        })
    }

    /// Phone side: check and open a request (recipient, signing Mac, expiry
    /// with the clock tolerance, replay, list `seq` values), remembered
    /// across sessions.
    pub fn open_remote_request(
        &self,
        keys: FfiApproverKeys,
        blob: Vec<u8>,
    ) -> Result<FfiOpenedRequest, OnePassError> {
        let me = self.with(|repo| this_device(repo))?;
        let me = identity(keys, me)?;
        let _meta = lock(&META);
        self.with(|repo| {
            let approvers = repo.approvers()?;
            let mut guard = load_replay(repo.store())?;
            let (request, body) =
                core_remote::open_request(&blob, &me, &approvers, unix_now(), &mut guard)?;
            let mut seqs = load_peer_seqs(repo.store())?;
            check_peer_seqs(
                &mut seqs,
                request.from,
                request.registry_seq,
                request.approver_list_seq,
            )?;
            let seqs = postcard::to_allocvec(&seqs).map_err(|_| invalid("remote peer seqs"))?;
            let store = repo.store_mut();
            store.set_meta(REPLAY_KEY, &guard.to_bytes()?)?;
            store.set_meta(PEER_SEQS_KEY, &seqs)?;
            Ok(FfiOpenedRequest {
                request_id: request.request_id.to_vec(),
                from: id_hex(request.from),
                from_name: device_name(repo, request.from)?,
                kind: request.kind.into(),
                created_at: request.created_at,
                expires_at: request.expires_at,
                body: body_to_ffi(&body),
            })
        })
    }

    /// Phone side: the signed answer to a request opened before with
    /// `open_remote_request` (and still valid). `unlock_key` (`K_r`) goes
    /// with an approval of an unlock request, and only then.
    pub fn seal_remote_response(
        &self,
        keys: FfiApproverKeys,
        request_blob: Vec<u8>,
        decision: FfiRemoteDecision,
        unlock_key: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, OnePassError> {
        let unlock_key = unlock_key.map(Zeroizing::new);
        let decision = RemoteDecision::from(decision);
        let me = self.with(|repo| this_device(repo))?;
        let me = identity(keys, me)?;
        self.with(|repo| {
            let (approvers, request, body) = Self::reopen(repo, &me, &request_blob)?;
            let mac = entry_of(&approvers, request.from, ApproverRole::Mac)?;
            let unlocks = matches!(
                request.kind,
                RemoteKind::Unlock | RemoteKind::ApproveAndUnlock
            );
            let key = match (&unlock_key, decision) {
                (_, RemoteDecision::Denied) => None,
                (Some(k), _) if unlocks => {
                    let mut bytes = Zeroizing::new([0u8; 32]);
                    if k.len() != bytes.len() {
                        return Err(invalid("unlock key"));
                    }
                    bytes.copy_from_slice(k);
                    Some(SymmetricKey::from_bytes(*bytes))
                }
                (None, _) if !unlocks => None,
                _ => return Err(invalid("unlock key")),
            };
            let eph = key.as_ref().and(body.unlock_eph_pub.as_ref());
            Ok(core_remote::seal_response(
                &me.signing,
                mac,
                &request,
                decision,
                key.as_ref(),
                eph,
                unix_now(),
            )?)
        })
    }

    /// Mac side, full session only: seal `auk` (checked against the
    /// account) under a fresh `K_r` for the pair (this Mac, `phone`), and
    /// the `Pair` request carrying `K_r` to the phone. `K_r` is wiped here;
    /// `C` goes to the Mac's keychain.
    pub fn remote_unlock_enroll(
        &self,
        keys: FfiApproverKeys,
        phone: String,
        auk: Vec<u8>,
    ) -> Result<FfiEnrollment, OnePassError> {
        self.full()?;
        let auk = Zeroizing::new(auk);
        let mut bytes = Zeroizing::new([0u8; 32]);
        if auk.len() != bytes.len() {
            return Err(invalid("auk"));
        }
        bytes.copy_from_slice(&auk);
        let auk = Auk::from_bytes(*bytes);
        let phone = parse_id(&phone)?;
        let me = self.with(|repo| this_device(repo))?;
        let me = identity(keys, me)?;
        let code = confirm_code()?;
        self.with(|repo| {
            // An AUK that does not open this account would enroll a `C`
            // that never unlocks.
            let account = repo.account().params.account_id;
            let params = repo
                .store()
                .get(RecordKind::AccountParams, account)?
                .ok_or(OnePassError::NotFound)?;
            let keyset = repo
                .store()
                .get(RecordKind::Keyset, account)?
                .ok_or(OnePassError::NotFound)?;
            Account::unlock_with_auk_at(
                &auk,
                &params.data,
                &keyset.data,
                repo.device_state().pinned.as_ref(),
                repo.chain().params_epoch,
            )?;
            let (c, k_r) = remote_unlock::enroll(&auk, me.device_id, phone)?;
            let body = RequestBody {
                client: "OnePass".into(),
                client_verified: true,
                action: "remote_unlock_pair".into(),
                details: Vec::new(),
                targets: Vec::new(),
                remember_allowed: false,
                strong_required: true,
                confirm_code: code.clone(),
                unlock_eph_pub: None,
                transfer_key: Some({
                    let mut t = Zeroizing::new([0u8; 32]);
                    t.copy_from_slice(k_r.expose());
                    t
                }),
                window_minutes: None,
            };
            let transfer_request = self.seal_to(repo, &me, phone, RemoteKind::Pair, &body)?;
            Ok(FfiEnrollment {
                c,
                confirm_code: code.clone(),
                transfer_request,
            })
        })
    }
}

#[uniffi::export]
impl Session {
    /// Phone side, after Face ID: `K_r` of a `Pair` request opened before
    /// with `open_remote_request` (verified again in full), for the
    /// keychain only. `open_remote_request` never returns it.
    pub fn accept_enrollment(
        &self,
        keys: FfiApproverKeys,
        request_blob: Vec<u8>,
    ) -> Result<Vec<u8>, OnePassError> {
        let me = self.with(|repo| this_device(repo))?;
        let me = identity(keys, me)?;
        self.with(|repo| {
            let (_, request, body) = Self::reopen(repo, &me, &request_blob)?;
            match (request.kind, body.transfer_key.as_ref()) {
                (RemoteKind::Pair, Some(k)) => Ok(k.to_vec()),
                _ => Err(invalid("remote kind")),
            }
        })
    }

    /// Phone side: a signed notice to the Mac `mac` ("Verrouiller
    /// maintenant", or `K_r` forgotten), sealed to the Mac's key.
    pub fn seal_remote_notice(
        &self,
        keys: FfiApproverKeys,
        mac: String,
        kind: FfiNoticeKind,
    ) -> Result<FfiSealedRequest, OnePassError> {
        let mac = parse_id(&mac)?;
        let kind = RemoteKind::from(kind);
        let body = RequestBody {
            client: "OnePass".into(),
            client_verified: true,
            action: match kind {
                RemoteKind::Lock => "lock".into(),
                _ => "forget_unlock".into(),
            },
            details: Vec::new(),
            targets: Vec::new(),
            remember_allowed: false,
            strong_required: false,
            confirm_code: String::new(),
            unlock_eph_pub: None,
            transfer_key: None,
            window_minutes: None,
        };
        let me = self.with(|repo| this_device(repo))?;
        let me = identity(keys, me)?;
        self.with(|repo| {
            let mine = repo.approvers()?;
            if !mine
                .iter()
                .any(|e| e.device_id == me.device_id && e.role == ApproverRole::Phone)
            {
                return Err(OnePassError::Validation {
                    field: "approver".into(),
                    reason: "not a phone".into(),
                });
            }
            self.seal_to(repo, &me, mac, kind, &body)
        })
    }
}

// ---- remote unlock, Mac side, before any session

/// The unlock request a `RemoteUnlocker` waits on.
struct Waiting {
    pending: PendingRequests,
    phone: Id,
    eph: HybridKemSecret,
    window_minutes: u32,
}

/// Opens an agents-only session on a locked Mac from the phone's answer.
/// Exists without a session: the approver list is read in clear and
/// verified with the account's public key (`approvers_without_unlock`).
/// The ephemeral key of the request lives in this object only.
#[derive(uniffi::Object)]
pub struct RemoteUnlocker {
    db_path: String,
    me: ApproverIdentity,
    waiting: Mutex<Option<Waiting>>,
    last_decision: Mutex<Option<FfiRemoteDecision>>,
}

impl RemoteUnlocker {
    fn store(&self) -> Result<SyncStore, OnePassError> {
        Ok(SyncStore::open(Path::new(&self.db_path))?)
    }
}

fn locked_approvers(
    store: &SyncStore,
) -> Result<onepass_core::approvers::LockedApprovers, OnePassError> {
    Ok(approvers_without_unlock(
        store,
        &store.device_state()?,
        &store.chain_state()?,
    )?)
}

#[uniffi::export]
impl RemoteUnlocker {
    /// `mac_keys` are this Mac's approval keys; the store must know this
    /// device's id (registered).
    #[uniffi::constructor]
    pub fn new(
        db_path: String,
        mac_keys: FfiApproverKeys,
    ) -> Result<Arc<RemoteUnlocker>, OnePassError> {
        let store = SyncStore::open(Path::new(&db_path))?;
        let device = store.chain_state()?.device_id.ok_or_else(unregistered)?;
        Ok(Arc::new(RemoteUnlocker {
            db_path,
            me: identity(mac_keys, device)?,
            waiting: Mutex::new(None),
            last_decision: Mutex::new(None),
        }))
    }

    /// The `ApproveAndUnlock` request to `phone_id` for the agent request
    /// `body`, with a fresh ephemeral key and a window clamped to 15 min
    /// through 8 h. Refused while the throttle holds
    /// (`Validation("remote_unlock", "throttled")`).
    pub fn begin(
        &self,
        phone_id: String,
        body: FfiRequestBody,
        window_minutes: u32,
    ) -> Result<FfiSealedRequest, OnePassError> {
        self.begin_at(phone_id, body, window_minutes, unix_now())
    }

    /// The phone's answer: an approval opens `c` with `K_r` and the store
    /// with the AUK, as an agents-only session for the window of `begin`.
    /// A refusal is `Validation("remote_unlock", "denied")`; an answer
    /// after the request expired counts as a refusal and is
    /// `Integrity("remote_expired")`; an AUK that no longer opens the
    /// account (password changed elsewhere) is `RemoteUnlockStale`, and the
    /// caller erases `c` and asks to enroll again. A forged or misdirected
    /// answer is refused and the wait goes on. `K_r`, the AUK and the
    /// ephemeral key are wiped.
    pub fn finish(&self, response_blob: Vec<u8>, c: Vec<u8>) -> Result<Arc<Session>, OnePassError> {
        self.finish_at(response_blob, c, unix_now())
    }

    /// Mac side, locked, agents-only or open: a notice from a phone
    /// (`Lock`: end the agents-only window; `ForgetUnlock`: erase `C`),
    /// checked like a request (signing phone in the verified list,
    /// addressed to this Mac, expiry, replay with a guard kept in the local
    /// meta). `Lock` comes from any active phone; `ForgetUnlock` only from
    /// `enrolled_phone`, the phone whose `C` this Mac holds (`None`: no
    /// enrollment, refused as `RemoteUnknownDevice`). Any other kind is
    /// refused. A refused notice is not remembered.
    pub fn open_remote_notice(
        &self,
        blob: Vec<u8>,
        enrolled_phone: Option<String>,
    ) -> Result<FfiNotice, OnePassError> {
        let enrolled = enrolled_phone.as_deref().map(parse_id).transpose()?;
        let _meta = lock(&META);
        let mut store = self.store()?;
        let approvers = locked_approvers(&store)?;
        let mut guard = match store.meta(NOTICE_REPLAY_KEY)? {
            Some(b) => ReplayGuard::from_bytes(&b)?,
            None => ReplayGuard::new(),
        };
        let (request, _) =
            core_remote::open_request(&blob, &self.me, &approvers.entries, unix_now(), &mut guard)?;
        let kind = match request.kind {
            RemoteKind::Lock => FfiNoticeKind::Lock,
            RemoteKind::ForgetUnlock if enrolled == Some(request.from) => {
                FfiNoticeKind::ForgetUnlock
            }
            RemoteKind::ForgetUnlock => {
                return Err(integrity(IntegrityError::RemoteUnknownDevice));
            }
            _ => return Err(invalid("remote kind")),
        };
        store.set_meta(NOTICE_REPLAY_KEY, &guard.to_bytes()?)?;
        Ok(FfiNotice {
            kind,
            from: id_hex(request.from),
        })
    }

    /// The phone's decision in the last answer `finish` accepted (`Once` or
    /// `Grant5m` also cover the agent request that asked).
    pub fn last_decision(&self) -> Option<FfiRemoteDecision> {
        *lock(&self.last_decision)
    }
}

impl RemoteUnlocker {
    /// `begin` with the clock given (tests).
    #[doc(hidden)]
    pub fn begin_at(
        &self,
        phone_id: String,
        body: FfiRequestBody,
        window_minutes: u32,
        now: i64,
    ) -> Result<FfiSealedRequest, OnePassError> {
        let phone = parse_id(&phone_id)?;
        // Held from the throttle read to its write: no two requests slip
        // through one interval.
        let _meta = lock(&META);
        let mut store = self.store()?;
        let mut throttle = load_throttle(&store)?;
        let waiting = load_waiting(&store)?;
        if settle(&mut throttle, waiting, now) {
            save_throttle(&mut store, &throttle, None)?;
        }
        if !throttle.may_request(now) {
            return Err(remote_unlock_refused("throttled"));
        }
        let approvers = locked_approvers(&store)?;
        let to = entry_of(&approvers.entries, phone, ApproverRole::Phone)?;
        let eph = HybridKemSecret::generate()?;
        let window = clamp_window_minutes(window_minutes);
        let body = body_to_core(body, Some(eph.public()?), None, Some(window));
        let h = header(
            self.me.device_id,
            phone,
            RemoteKind::ApproveAndUnlock,
            approvers.device_list_seq,
            approvers.approver_list_seq,
            now,
        )?;
        let blob = core_remote::seal_request(&self.me.signing, to, h.clone(), &body)?;
        throttle.requested(now);
        save_throttle(&mut store, &throttle, Some((h.request_id, h.expires_at)))?;
        let mut pending = PendingRequests::new();
        pending.insert_header(&h);
        *lock(&self.waiting) = Some(Waiting {
            pending,
            phone,
            eph,
            window_minutes: window,
        });
        *lock(&self.last_decision) = None;
        Ok(sealed(&h, blob))
    }

    /// `finish` with the clock given (tests).
    #[doc(hidden)]
    pub fn finish_at(
        &self,
        response_blob: Vec<u8>,
        c: Vec<u8>,
        now: i64,
    ) -> Result<Arc<Session>, OnePassError> {
        let c = Zeroizing::new(c);
        let meta = lock(&META);
        let mut slot = lock(&self.waiting);
        let mut waiting = slot
            .take()
            .ok_or_else(|| integrity(IntegrityError::RemoteUnknownRequest))?;
        let mut store = self.store()?;
        let approvers = locked_approvers(&store)?;
        let response = match core_remote::open_response(
            &response_blob,
            &self.me,
            &approvers.entries,
            &mut waiting.pending,
            now,
        ) {
            Ok(r) => r,
            Err(Error::Integrity(IntegrityError::RemoteExpired)) => {
                let mut throttle = load_throttle(&store)?;
                throttle.refused(now);
                save_throttle(&mut store, &throttle, None)?;
                return Err(integrity(IntegrityError::RemoteExpired));
            }
            Err(e) => {
                // A forged or misdirected answer does not end the wait.
                *slot = Some(waiting);
                return Err(e.into());
            }
        };
        drop(slot);
        *lock(&self.last_decision) = Some(response.decision.into());
        let mut throttle = load_throttle(&store)?;
        if response.decision == RemoteDecision::Denied {
            throttle.refused(now);
            save_throttle(&mut store, &throttle, None)?;
            return Err(remote_unlock_refused("denied"));
        }
        throttle.approved();
        save_throttle(&mut store, &throttle, None)?;
        drop(meta);

        let stale = |e: Error| match e {
            Error::WrongPassword | Error::Integrity(IntegrityError::Aead) => {
                OnePassError::RemoteUnlockStale
            }
            other => other.into(),
        };
        let k_r = core_remote::open_unlock(&response, &waiting.eph)?;
        let auk = remote_unlock::open(&c, &k_r, self.me.device_id, waiting.phone).map_err(stale)?;
        drop(k_r);
        let device = store.device_state()?;
        let mut repo = Repository::unlock_with_auk(store, &auk, device).map_err(stale)?;
        drop(auk);
        repo.persist_device_state()?;
        let ends_at = now.saturating_add(i64::from(waiting.window_minutes) * 60);
        Session::new_agent_only(repo, ends_at)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lower_seqs_of_a_mac_are_refused() {
        let mut seqs = PeerSeqs::new();
        let (m1, m2) = (Id([1; 16]), Id([2; 16]));
        check_peer_seqs(&mut seqs, m1, 5, 3).unwrap();
        check_peer_seqs(&mut seqs, m1, 5, 3).unwrap();
        check_peer_seqs(&mut seqs, m1, 6, 3).unwrap();
        assert!(check_peer_seqs(&mut seqs, m1, 5, 9).is_err());
        assert!(check_peer_seqs(&mut seqs, m1, 9, 2).is_err());
        // The refused ones moved nothing; another Mac has its own values.
        check_peer_seqs(&mut seqs, m1, 6, 3).unwrap();
        check_peer_seqs(&mut seqs, m2, 1, 1).unwrap();
        assert_eq!(seqs.len(), 2);
        let bytes = postcard::to_allocvec(&seqs).unwrap();
        assert_eq!(decode_peer_seqs(&bytes).unwrap(), seqs);
        let mut longer = bytes.clone();
        longer.push(0);
        assert!(decode_peer_seqs(&longer).is_err());
    }

    #[test]
    fn an_expired_unanswered_request_counts_as_refused() {
        let t = 1_800_000_000;
        let mut th = UnlockThrottle::new();
        assert!(!settle(&mut th, None, t));
        assert!(!settle(&mut th, Some(([0; 16], t + 60)), t));
        for i in 0..3 {
            assert!(settle(&mut th, Some(([0; 16], t)), t + 1 + i));
        }
        // Three refusals block for an hour.
        assert!(!th.may_request(t + 1000));
    }

    #[test]
    fn approver_keys_round_trip() {
        let keys = generate_approver_keys().unwrap();
        let id = identity(keys.clone(), Id([3; 16])).unwrap();
        assert_eq!(id.device_id, Id([3; 16]));
        assert!(
            identity(
                FfiApproverKeys {
                    signing: vec![1, 2, 3],
                    kem_secret: keys.kem_secret.clone(),
                },
                Id([3; 16])
            )
            .is_err()
        );
    }
}
