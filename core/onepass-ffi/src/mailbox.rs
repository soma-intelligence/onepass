//! The OnePass mailbox for the apps (cross-platform spec 4.14, 9): the
//! credential, the creation and the enrollment of a mailbox, the sync round
//! of `onepass-sync` over it, the wake channel, the rendezvous of a pairing
//! and the account's signed `SyncHome`.
//!
//! Everything blocks: the app calls it from a thread of its own. The Rust
//! side never keeps a credential seed: the app stores it in its secure
//! storage and hands it to each call that signs.

use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use onepass_core::Id;
use onepass_core::crypto::SecretKey;
use onepass_core::mailbox_recovery::{mailbox_locator as locator_of, mailbox_recovery_seed};
use onepass_core::store::{RecordKind, SIDE_KIND_MAILBOX_ENROLL_REQUEST};
use onepass_core::sync::{RebaseReport, SyncStore, VaultSyncHealth};
use onepass_core::synchome::{SyncBackend, SyncHomeBody};
use onepass_mailbox::{
    Credential, CredentialKey, Endpoint, MailboxClient, MailboxError, RdvRole, Rendezvous,
    WakeListener,
};
use onepass_mailbox_proto::{
    CredentialRole, ErrorCode, PushKind, SignedEnrollTicket, decode, encode,
};
use onepass_sync::{MailboxTransport, RoundHooks, RoundReport, RoundStatus, SyncDriver};
use time::OffsetDateTime;
use zeroize::Zeroizing;

use crate::convert::{bytes_hex, hex_bytes, id_hex};
use crate::error::{OnePassError, invalid};
use crate::rotation::{FfiPqDeviceHalf, device_keys};
use crate::session::{Session, identity_left};

/// What the server sees of a device's label: none. The app names devices in
/// the account's own (encrypted) device list.
const LABEL: &[u8] = b"";

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A mailbox failure as the app sees it: a clock off by more than 300 s is
/// `ClockSkew` (the app asks the user to fix the time); anything else is
/// `MailboxUnavailable`, with the client's reason (never a field value).
impl From<MailboxError> for OnePassError {
    fn from(e: MailboxError) -> Self {
        match e {
            MailboxError::Stale => OnePassError::ClockSkew,
            MailboxError::Forbidden | MailboxError::Server(ErrorCode::Forbidden) => {
                OnePassError::Forbidden
            }
            e => OnePassError::MailboxUnavailable {
                reason: e.to_string(),
            },
        }
    }
}

fn mailbox_id(hex: &str) -> Result<[u8; 16], OnePassError> {
    if hex.len() != 32 {
        return Err(invalid("mailbox id"));
    }
    hex_bytes(hex)
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| invalid("mailbox id"))
}

fn credential(seed: &[u8]) -> Result<Credential, OnePassError> {
    Credential::from_seed(seed).map_err(|_| invalid("credential seed"))
}

// ---- records ----------------------------------------------------------------

/// A new mailbox credential. The app keeps `seed` in its secure storage;
/// `public_key` goes to the approver of a pairing; `id` (hex) names the
/// credential to revoke.
#[derive(uniffi::Record)]
pub struct FfiMailboxCredential {
    pub seed: Vec<u8>,
    pub public_key: Vec<u8>,
    pub id: String,
}

/// A mailbox server: its base URL (`https://`) and, for a self-host, the PEM
/// of a CA trusted on top of the web roots.
#[derive(uniffi::Record, Clone)]
pub struct FfiMailboxEndpoint {
    pub base_url: String,
    pub extra_ca_pem: Option<String>,
}

impl From<FfiMailboxEndpoint> for Endpoint {
    fn from(e: FfiMailboxEndpoint) -> Self {
        Endpoint {
            base_url: e.base_url,
            extra_ca_pem: e.extra_ca_pem,
        }
    }
}

/// A mailbox this device belongs to.
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct FfiMailboxHome {
    pub base_url: String,
    /// 32 hex characters.
    pub mailbox_id: String,
    pub incarnation: u64,
}

/// Where an account syncs.
#[derive(uniffi::Enum, Debug, Clone, PartialEq, Eq)]
pub enum FfiSyncBackend {
    CloudKit,
    Mailbox {
        base_url: String,
        /// 32 hex characters.
        mailbox_id: String,
    },
}

impl From<&SyncBackend> for FfiSyncBackend {
    fn from(b: &SyncBackend) -> Self {
        match b {
            SyncBackend::CloudKit => FfiSyncBackend::CloudKit,
            SyncBackend::Mailbox { url, mailbox_id } => FfiSyncBackend::Mailbox {
                base_url: url.clone(),
                mailbox_id: bytes_hex(mailbox_id),
            },
        }
    }
}

impl TryFrom<FfiSyncBackend> for SyncBackend {
    type Error = OnePassError;

    fn try_from(b: FfiSyncBackend) -> Result<Self, OnePassError> {
        Ok(match b {
            FfiSyncBackend::CloudKit => SyncBackend::CloudKit,
            FfiSyncBackend::Mailbox {
                base_url,
                mailbox_id: m,
            } => SyncBackend::Mailbox {
                url: base_url,
                mailbox_id: mailbox_id(&m)?,
            },
        })
    }
}

/// The account's signed sync home, verified and pinned.
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct FfiSyncHome {
    pub seq: u64,
    pub backend: FfiSyncBackend,
    /// Unix seconds, as the signing device's clock said.
    pub issued_at: i64,
}

impl From<&SyncHomeBody> for FfiSyncHome {
    fn from(h: &SyncHomeBody) -> Self {
        FfiSyncHome {
            seq: h.seq,
            backend: (&h.backend).into(),
            issued_at: h.issued_at,
        }
    }
}

/// The mailbox a pairing grant hands over: its verified home and the enroll
/// ticket for this device's credential (`mailbox_enroll`).
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct FfiMailboxEnrollment {
    pub home: FfiSyncHome,
    pub ticket: Vec<u8>,
}

/// A credential's role on a mailbox.
#[derive(uniffi::Enum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum FfiCredentialRole {
    Read,
    Write,
    Manage,
}

impl From<FfiCredentialRole> for CredentialRole {
    fn from(r: FfiCredentialRole) -> Self {
        match r {
            FfiCredentialRole::Read => CredentialRole::Read,
            FfiCredentialRole::Write => CredentialRole::Write,
            FfiCredentialRole::Manage => CredentialRole::Manage,
        }
    }
}

/// A verified enroll request: grant `credential_pub` to `device_id`.
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct FfiEnrollRequest {
    pub device_id: String,
    pub credential_pub: Vec<u8>,
    pub issued_at: i64,
}

/// How a round ended (`onepass_sync::RoundStatus`).
#[derive(uniffi::Enum, Debug, Clone, PartialEq, Eq)]
pub enum FfiRoundStatus {
    Idle,
    Offline,
    Retrying,
    ClockSkew,
    WaitingForServer,
    Refused {
        kind: String,
    },
    Unsettled,
    Unreadable,
    /// The account's signed home names another place: nothing was sent.
    /// `base_url` is `None` for CloudKit.
    HomeMoved {
        base_url: Option<String>,
    },
}

impl From<RoundStatus> for FfiRoundStatus {
    fn from(s: RoundStatus) -> Self {
        match s {
            RoundStatus::Idle => Self::Idle,
            RoundStatus::Offline => Self::Offline,
            RoundStatus::Retrying => Self::Retrying,
            RoundStatus::ClockSkew => Self::ClockSkew,
            RoundStatus::WaitingForServer => Self::WaitingForServer,
            RoundStatus::Refused { kind } => Self::Refused { kind },
            RoundStatus::Unsettled => Self::Unsettled,
            RoundStatus::Unreadable => Self::Unreadable,
            RoundStatus::HomeMoved(b) => Self::HomeMoved {
                base_url: match b {
                    SyncBackend::CloudKit => None,
                    SyncBackend::Mailbox { url, .. } => Some(url),
                },
            },
        }
    }
}

/// The report of one round: reload when `changed`, run the next round at
/// once when `rerun`, else after `retry_after_seconds` (or on a wake).
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct FfiRoundReport {
    pub status: FfiRoundStatus,
    pub changed: bool,
    /// Vault ids (hex) a rebase changed.
    pub rebased: Vec<String>,
    pub retry_after_seconds: Option<u32>,
    pub rerun: bool,
}

impl From<RoundReport> for FfiRoundReport {
    fn from(r: RoundReport) -> Self {
        FfiRoundReport {
            status: r.status.into(),
            changed: r.changed,
            rebased: r.rebased.into_iter().map(id_hex).collect(),
            retry_after_seconds: r
                .retry_after
                .map(|d| u32::try_from(d.as_secs().max(1)).unwrap_or(u32::MAX)),
            rerun: r.rerun,
        }
    }
}

#[derive(uniffi::Enum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum FfiPushKind {
    None,
    Fcm,
    Apns,
    UnifiedPush,
}

impl From<FfiPushKind> for PushKind {
    fn from(k: FfiPushKind) -> Self {
        match k {
            FfiPushKind::None => PushKind::None,
            FfiPushKind::Fcm => PushKind::Fcm,
            FfiPushKind::Apns => PushKind::Apns,
            FfiPushKind::UnifiedPush => PushKind::UnifiedPush,
        }
    }
}

/// The public wake channel of a mailbox (spec 4.10): its Realtime URL, the
/// publishable key, and the topic (32 hex characters).
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct FfiWakeInfo {
    pub realtime_url: String,
    pub publishable_key: String,
    pub topic: String,
}

// ---- free functions -----------------------------------------------------------

/// A fresh mailbox credential (Ed25519). Nothing is kept on the Rust side.
#[uniffi::export]
pub fn mailbox_generate_credential() -> Result<FfiMailboxCredential, OnePassError> {
    Ok(credential_record(&Credential::generate()?))
}

fn credential_record(c: &Credential) -> FfiMailboxCredential {
    let public = c.public_key();
    FfiMailboxCredential {
        seed: c.seed().to_vec(),
        public_key: public.to_bytes().to_vec(),
        id: bytes_hex(&public.id()),
    }
}

/// The locator of the account of `secret_key` (16 bytes, spec D.4): what
/// its mailbox registers (`MailboxSync::set_locator`) and a restore looks
/// up (`mailbox_locate`). Secret Key as displayed.
#[uniffi::export]
pub fn mailbox_locator(secret_key: String) -> Result<Vec<u8>, OnePassError> {
    let sk = SecretKey::parse(&Zeroizing::new(secret_key))?;
    Ok(locator_of(&sk)?.to_vec())
}

/// The recovery credential of `mailbox_id` (hex) for the account of
/// `secret_key`: derived, never stored. The app grants it once
/// (`MailboxSync::grant`, role manage) and signs with it during a restore.
#[uniffi::export]
pub fn mailbox_recovery_credential(
    secret_key: String,
    mailbox_id: String,
) -> Result<FfiMailboxCredential, OnePassError> {
    let sk = SecretKey::parse(&Zeroizing::new(secret_key))?;
    let seed = mailbox_recovery_seed(&sk, &self::mailbox_id(&mailbox_id)?)?;
    Ok(credential_record(&credential(&*seed)?))
}

/// The mailboxes registered under `locator` on `endpoint` (hex ids, at
/// most 8, oldest first; empty when none). An id is only where to look:
/// the app tries each with its recovery credential.
#[uniffi::export]
pub fn mailbox_locate(
    endpoint: FfiMailboxEndpoint,
    locator: Vec<u8>,
) -> Result<Vec<String>, OnePassError> {
    let locator: [u8; 16] = locator.try_into().map_err(|_| invalid("locator"))?;
    let ids = onepass_mailbox::locate(&endpoint.into(), locator)?;
    Ok(ids.iter().map(|m| bytes_hex(m)).collect())
}

/// Whether `code` is a record kind of this core: what a CloudKit record
/// may carry to the store. The side kind of the enroll request and any
/// unknown code are not.
#[uniffi::export]
pub fn is_known_record_kind(code: u8) -> bool {
    code != SIDE_KIND_MAILBOX_ENROLL_REQUEST && RecordKind::from_code(code).is_ok()
}

/// The side kind of a mailbox enroll request in the frozen iCloud zone.
#[uniffi::export]
pub fn side_kind_mailbox_enroll_request() -> u8 {
    SIDE_KIND_MAILBOX_ENROLL_REQUEST
}

/// Create a mailbox on `endpoint`, managed by the credential of
/// `credential_seed`. `invite`: the server's invite, when it takes invites
/// only (`MailboxUnavailable` says so otherwise).
#[uniffi::export]
pub fn mailbox_create(
    endpoint: FfiMailboxEndpoint,
    credential_seed: Vec<u8>,
    invite: Option<String>,
) -> Result<FfiMailboxHome, OnePassError> {
    let seed = Zeroizing::new(credential_seed);
    let base_url = endpoint.base_url.clone();
    let mut client = MailboxClient::new(endpoint.into(), credential(&seed)?)?;
    let created = client.create(invite.as_deref().map(str::as_bytes), LABEL)?;
    Ok(FfiMailboxHome {
        base_url,
        mailbox_id: bytes_hex(&created.mailbox_id),
        incarnation: created.incarnation,
    })
}

/// Join the mailbox a pairing grant names, with its enroll ticket
/// (`PairingNewcomer::mailbox_enrollment`). The URL is the ticket's, which
/// the newcomer checked against the account's signed `SyncHome` when it
/// opened the grant.
#[uniffi::export]
pub fn mailbox_enroll(
    credential_seed: Vec<u8>,
    ticket: Vec<u8>,
    extra_ca_pem: Option<String>,
) -> Result<FfiMailboxHome, OnePassError> {
    let seed = Zeroizing::new(credential_seed);
    let ticket: SignedEnrollTicket = decode(&ticket).map_err(|_| invalid("enroll ticket"))?;
    let base_url = ticket.ticket.mailbox_url.clone();
    let endpoint = Endpoint {
        base_url: base_url.clone(),
        extra_ca_pem,
    };
    let mut client = MailboxClient::new(endpoint, credential(&seed)?)?;
    client.enroll(&ticket, LABEL)?;
    let info = client.info()?;
    Ok(FfiMailboxHome {
        base_url,
        mailbox_id: bytes_hex(&ticket.ticket.mailbox_id),
        incarnation: info.incarnation,
    })
}

// ---- the sync round ---------------------------------------------------------

/// What the unlocked session lends a round, one call at a time: the session
/// stays usable by the app between two calls (the round's network time is
/// spent without its lock). A session locked or left mid-round fails the
/// call, and the round ends `Retrying`.
struct SessionHooks<'a>(&'a Session);

impl SessionHooks<'_> {
    fn with<R>(
        &mut self,
        write: bool,
        f: impl FnOnce(&mut crate::session::Repo) -> onepass_core::Result<R>,
    ) -> onepass_core::Result<R> {
        let gone = || onepass_core::Error::Store("session locked".into());
        let mut guard = self.0.guard();
        let repo = guard.as_mut().ok_or_else(gone)?;
        if identity_left(repo).map_err(|_| gone())? {
            return Err(gone());
        }
        let out = f(repo)?;
        if write {
            repo.persist_device_state()?;
        }
        Ok(out)
    }
}

impl RoundHooks for SessionHooks<'_> {
    fn rebase(&mut self) -> onepass_core::Result<RebaseReport> {
        self.with(true, |r| r.rebase_report())
    }

    fn note_round(&mut self, now: i64) -> onepass_core::Result<Vec<(Id, VaultSyncHealth)>> {
        self.with(true, |r| {
            r.note_sync_round(now)?;
            Ok(r.sync_health()?.into_iter().collect())
        })
    }

    fn health(&mut self) -> onepass_core::Result<Vec<(Id, VaultSyncHealth)>> {
        self.with(false, |r| Ok(r.sync_health()?.into_iter().collect()))
    }

    fn keep_this_device(&mut self) -> onepass_core::Result<u64> {
        self.with(true, RoundHooks::keep_this_device)
    }

    fn sync_home(&mut self) -> onepass_core::Result<Option<SyncHomeBody>> {
        self.with(false, |r| r.sync_home())
    }
}

struct SyncInner {
    store: SyncStore,
    driver: SyncDriver<MailboxTransport<MailboxClient>>,
}

/// The sync of one account through one mailbox: its own store connection,
/// the driver and the client. One round at a time.
#[derive(uniffi::Object)]
pub struct MailboxSync {
    inner: Mutex<SyncInner>,
}

impl MailboxSync {
    fn inner(&self) -> MutexGuard<'_, SyncInner> {
        lock(&self.inner)
    }

    /// An enroll ticket for a pairing grant (`grant_with_mailbox`).
    pub(crate) fn ticket_for(
        &self,
        new_credential_pub: [u8; 32],
        now: i64,
    ) -> onepass_core::Result<Vec<u8>> {
        let inner = self.inner();
        let t = inner
            .driver
            .transport()
            .api()
            .issue_ticket(CredentialKey::from_bytes(new_credential_pub), now)
            .map_err(|e| onepass_core::Error::Store(e.to_string()))?;
        Ok(encode(&t))
    }
}

#[uniffi::export]
impl MailboxSync {
    /// The sync of the store at `db_path` through mailbox `mailbox_id` on
    /// `endpoint`, signed with the credential of `credential_seed`. The
    /// driver follows the home `endpoint.base_url` + `mailbox_id`: a signed
    /// `SyncHome` naming anything else stops every round (`HomeMoved`), so
    /// the app passes the URL exactly as the home names it.
    #[uniffi::constructor]
    pub fn open(
        db_path: String,
        endpoint: FfiMailboxEndpoint,
        mailbox_id: String,
        credential_seed: Vec<u8>,
    ) -> Result<Arc<Self>, OnePassError> {
        let seed = Zeroizing::new(credential_seed);
        let mailbox = self::mailbox_id(&mailbox_id)?;
        let home = SyncBackend::Mailbox {
            url: endpoint.base_url.clone(),
            mailbox_id: mailbox,
        };
        let mut client = MailboxClient::new(endpoint.into(), credential(&seed)?)?;
        client.open(mailbox);
        Ok(Arc::new(MailboxSync {
            inner: Mutex::new(SyncInner {
                store: SyncStore::open(Path::new(&db_path))?,
                driver: SyncDriver::new(MailboxTransport::new(client), home),
            }),
        }))
    }

    /// One round (`SyncDriver::run_round`). With an unlocked `session` the
    /// round rebases, counts the sync health and checks the home; without
    /// (or locked) it still fetches and sends, and held vaults send nothing.
    /// `now`: Unix seconds.
    pub fn run_round(&self, session: Option<Arc<Session>>, now: i64) -> FfiRoundReport {
        let mut inner = self.inner();
        let SyncInner { store, driver } = &mut *inner;
        let unlocked = session.as_deref().filter(|s| {
            s.guard()
                .as_ref()
                .is_some_and(|r| !identity_left(r).unwrap_or(true))
        });
        let mut hooks = unlocked.map(SessionHooks);
        let hooks = hooks.as_mut().map(|h| h as &mut dyn RoundHooks);
        driver.run_round(store, hooks, now).into()
    }

    /// The mailbox's wake channel, for `start_wake_listener`.
    pub fn wake_info(&self) -> Result<FfiWakeInfo, OnePassError> {
        let inner = self.inner();
        let api = inner.driver.transport().api();
        let config = api.server_config()?;
        let info = api.info()?;
        Ok(FfiWakeInfo {
            realtime_url: config.realtime_url,
            publishable_key: config.publishable_key,
            topic: bytes_hex(&info.wake_topic),
        })
    }

    /// Register this device's push token (`FfiPushKind::None` and an empty
    /// token remove it).
    pub fn set_push_token(&self, kind: FfiPushKind, token: Vec<u8>) -> Result<(), OnePassError> {
        let inner = self.inner();
        Ok(inner
            .driver
            .transport()
            .api()
            .set_push(kind.into(), &token)?)
    }

    /// An enroll ticket for the credential `new_credential_pub` (32 bytes),
    /// valid 300 s from `now`. No request is made.
    pub fn issue_enroll_ticket(
        &self,
        new_credential_pub: Vec<u8>,
        now: i64,
    ) -> Result<Vec<u8>, OnePassError> {
        let key: [u8; 32] = new_credential_pub
            .try_into()
            .map_err(|_| invalid("credential public key"))?;
        let inner = self.inner();
        let t = inner
            .driver
            .transport()
            .api()
            .issue_ticket(CredentialKey::from_bytes(key), now)?;
        Ok(encode(&t))
    }

    /// Let `public_key` (32 bytes) in with `role`, without a ticket (spec
    /// D.7; manager only, else `Forbidden`). Returns the new credential's
    /// hex id. A weak key is refused by the server.
    pub fn grant(
        &self,
        public_key: Vec<u8>,
        role: FfiCredentialRole,
        label: Vec<u8>,
    ) -> Result<String, OnePassError> {
        let key: [u8; 32] = public_key
            .try_into()
            .map_err(|_| invalid("credential public key"))?;
        let inner = self.inner();
        let id = inner
            .driver
            .transport()
            .api()
            .grant(key, role.into(), None, &label)?;
        Ok(bytes_hex(&id))
    }

    /// Register the account's locator (16 bytes) on this mailbox (manager
    /// only). A mailbox holds the last two.
    pub fn set_locator(&self, locator: Vec<u8>) -> Result<(), OnePassError> {
        let locator: [u8; 16] = locator.try_into().map_err(|_| invalid("locator"))?;
        let inner = self.inner();
        Ok(inner.driver.transport().api().set_locator(locator)?)
    }

    /// Abandon this fresh mailbox (its creator, before anyone else used
    /// it: a migration that lost its race, spec D.5).
    pub fn abandon(&self) -> Result<(), OnePassError> {
        let inner = self.inner();
        Ok(inner.driver.transport().api().abandon()?)
    }

    /// Revoke a credential of the mailbox (hex id, as
    /// `FfiMailboxCredential::id`).
    pub fn revoke_credential(&self, credential_id: String) -> Result<(), OnePassError> {
        let id: [u8; 16] = hex_bytes(&credential_id)
            .filter(|_| credential_id.len() == 32)
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| invalid("credential id"))?;
        let inner = self.inner();
        Ok(inner.driver.transport().api().revoke(id)?)
    }
}

// ---- the wake channel -------------------------------------------------------

/// Called on the listener's thread on each wake: "fetch". Return quickly.
#[uniffi::export(with_foreign)]
pub trait FfiWakeObserver: Send + Sync {
    fn wake(&self);
}

/// A running wake listener. `stop` (or dropping it) ends its thread.
#[derive(uniffi::Object)]
pub struct WakeListenerHandle {
    listener: Mutex<Option<WakeListener>>,
}

/// Listen to a mailbox's wake channel (spec 4.10) until `stop`. The
/// connection is made, and made again, in the background.
#[uniffi::export]
pub fn start_wake_listener(
    info: FfiWakeInfo,
    observer: Arc<dyn FfiWakeObserver>,
) -> Result<Arc<WakeListenerHandle>, OnePassError> {
    let topic: [u8; 16] = hex_bytes(&info.topic)
        .filter(|_| info.topic.len() == 32)
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| invalid("wake topic"))?;
    let listener = WakeListener::start(
        &info.realtime_url,
        &info.publishable_key,
        topic,
        Box::new(move || observer.wake()),
    )?;
    Ok(Arc::new(WakeListenerHandle {
        listener: Mutex::new(Some(listener)),
    }))
}

#[uniffi::export]
impl WakeListenerHandle {
    /// Stop listening: returns within about 1 s, and the observer is never
    /// called once this returns.
    pub fn stop(&self) {
        if let Some(l) = lock(&self.listener).take() {
            l.stop();
        }
    }
}

// ---- the rendezvous of a pairing ------------------------------------------

#[derive(uniffi::Enum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum FfiRdvRole {
    Newcomer,
    Approver,
}

/// One side of a pairing rendezvous through a mailbox server (T-RDV,
/// spec 5.3): opaque sealed frames, nothing else. Dropping it closes the
/// session.
#[derive(uniffi::Object)]
pub struct RendezvousTransport {
    rdv: Mutex<Rendezvous>,
}

#[uniffi::export]
impl RendezvousTransport {
    /// `session_id`: 32 hex characters, from the pairing code.
    /// `extra_ca_pem`: a self-host's CA, as `FfiMailboxEndpoint`.
    #[uniffi::constructor(default(extra_ca_pem = None))]
    pub fn new(
        base_url: String,
        session_id: String,
        role: FfiRdvRole,
        extra_ca_pem: Option<String>,
    ) -> Result<Arc<Self>, OnePassError> {
        let session = mailbox_id(&session_id).map_err(|_| invalid("session id"))?;
        let role = match role {
            FfiRdvRole::Newcomer => RdvRole::Newcomer,
            FfiRdvRole::Approver => RdvRole::Approver,
        };
        let endpoint = Endpoint {
            base_url,
            extra_ca_pem,
        };
        Ok(Arc::new(RendezvousTransport {
            rdv: Mutex::new(Rendezvous::new(endpoint, session, role)?),
        }))
    }

    pub fn send(&self, frame: Vec<u8>) -> Result<(), OnePassError> {
        Ok(lock(&self.rdv).send_frame(&frame)?)
    }

    /// The next frame, at most `max_bytes`, waiting `timeout_ms` at most
    /// (`MailboxUnavailable` when nothing came).
    pub fn receive(&self, max_bytes: u64, timeout_ms: u64) -> Result<Vec<u8>, OnePassError> {
        let max = usize::try_from(max_bytes).unwrap_or(usize::MAX);
        let deadline = Instant::now() + Duration::from_millis(timeout_ms);
        Ok(lock(&self.rdv).recv_frame(max, deadline)?)
    }

    pub fn close(&self) {
        lock(&self.rdv).close();
    }
}

// ---- the session's sync home ------------------------------------------------

#[uniffi::export]
impl Session {
    /// Where the account syncs: the signed `SyncHome`, verified and pinned
    /// (`None` before any was written).
    pub fn sync_home(&self) -> Result<Option<FfiSyncHome>, OnePassError> {
        self.with(|repo| Ok(repo.sync_home()?.as_ref().map(FfiSyncHome::from)))
    }

    /// Sign the next home: the account moves to `backend`. A mailbox URL
    /// must be `https://`, at most 256 bytes.
    pub fn set_sync_home(&self, backend: FfiSyncBackend) -> Result<FfiSyncHome, OnePassError> {
        let backend = SyncBackend::try_from(backend)?;
        let now = OffsetDateTime::now_utc().unix_timestamp();
        self.with(|repo| Ok((&repo.set_sync_home(backend.clone(), now)?).into()))
    }

    /// The next home to `backend`, signed and not adopted: a migration
    /// claims it in iCloud first, then adopts it (spec D.5).
    pub fn sign_sync_home(&self, backend: FfiSyncBackend) -> Result<Vec<u8>, OnePassError> {
        let backend = SyncBackend::try_from(backend)?;
        let now = OffsetDateTime::now_utc().unix_timestamp();
        self.with(|repo| Ok(repo.sign_sync_home(backend.clone(), now)?))
    }

    /// Verify a signed home (this device's, or the winner's of a migration
    /// race) and adopt it.
    pub fn adopt_sync_home(&self, signed: Vec<u8>) -> Result<FfiSyncHome, OnePassError> {
        self.with(|repo| Ok((&repo.adopt_sync_home(&signed)?).into()))
    }

    /// A request, signed with this device's keys (`classical` and `pq`, as
    /// for `rotate_keys`), for the credential `credential_pub` on
    /// `mailbox_id` (hex).
    pub fn sign_enroll_request(
        &self,
        classical: Vec<u8>,
        pq: Arc<dyn FfiPqDeviceHalf>,
        credential_pub: Vec<u8>,
        mailbox_id: String,
    ) -> Result<Vec<u8>, OnePassError> {
        let classical = Zeroizing::new(classical);
        let keys = device_keys(&classical, pq)?;
        let credential: [u8; 32] = credential_pub
            .try_into()
            .map_err(|_| invalid("credential public key"))?;
        let mailbox = self::mailbox_id(&mailbox_id)?;
        let now = OffsetDateTime::now_utc().unix_timestamp();
        self.with(|repo| Ok(repo.sign_enroll_request(&keys, credential, mailbox, now)?))
    }

    /// Verify a request read from the frozen iCloud zone for `mailbox_id`
    /// (hex): a device of the verified roster, this account, 7 days.
    pub fn verify_enroll_request(
        &self,
        bytes: Vec<u8>,
        mailbox_id: String,
    ) -> Result<FfiEnrollRequest, OnePassError> {
        let mailbox = self::mailbox_id(&mailbox_id)?;
        let now = OffsetDateTime::now_utc().unix_timestamp();
        self.with(|repo| {
            let body = repo.verify_enroll_request(&bytes, mailbox, now)?;
            Ok(FfiEnrollRequest {
                device_id: id_hex(body.device_id),
                credential_pub: body.credential_pub.to_vec(),
                issued_at: body.issued_at,
            })
        })
    }
}
