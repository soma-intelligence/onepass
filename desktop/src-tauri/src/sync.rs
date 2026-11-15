//! Cross-device sync through the OnePass mailbox (cross-platform spec 4.14,
//! D.2 to D.4), as the Apple apps' mailbox path does it:
//!
//! - where the account syncs (`Backend`, store meta `sync.backend`): on this
//!   PC only (an account from before sync), a setup to finish, or a mailbox;
//! - the setup of a mailbox for an account (`MailboxSetup.swift`), step by
//!   step in the store meta (`sync.mailbox.setup`), so a cut resumes where it
//!   stopped and never creates a second mailbox;
//! - the rounds (`MailboxSyncCoordinator.swift`): after each change
//!   (debounced 2 s), on unlock, on the mailbox's wake channel, on a timer
//!   and on "Synchroniser maintenant"; failures retry after 30 s, 2 min,
//!   then 10 min (or the server's delay). A locked PC still fetches.
//!
//! The device's mailbox credential seeds live in `mailbox.bin`, sealed like
//! `device.bin`. Nothing here logs a seed, a key or a record.

use std::collections::VecDeque;
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError, mpsc};
use std::time::{Duration, Instant};

use onepass_ffi::{
    FfiCredentialRole, FfiMailboxEndpoint, FfiRoundReport, FfiRoundStatus, FfiSyncBackend,
    FfiWakeObserver, MailboxSync, OnePassError, Session, WakeListenerHandle,
};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager};
use zeroize::Zeroizing;

use crate::state::{AppState, now};

/// The OnePass server hosted by Soma Labs (the Apple apps' `OnePassMailboxURL`).
pub const HOSTED_URL: &str = "https://mailbox.somalabs.me/functions/v1/mailbox";
/// The backoff of failed rounds (`SyncCoordinator.retryDelays`).
pub const RETRY_DELAYS: [u64; 3] = [30, 120, 600];
/// One round this long after the last local write.
const DEBOUNCE: Duration = Duration::from_secs(2);
/// A round at least this often while the app runs (the desktop has no push).
const PERIOD: Duration = Duration::from_secs(5 * 60);
/// The grant label of the recovery credential: the server sees it, it names a role only.
const RECOVERY_LABEL: &[u8] = b"recovery";
/// The seed slot of a credential made before its mailbox exists.
const PENDING: &str = "pending";

/// The commands that write to the store: each one is followed by a round
/// (debounced), wherever it was called from (main.rs).
pub const WRITES: &[&str] = &[
    "save_item",
    "trash_item",
    "set_favorite",
    "set_archived",
    "restore_item",
    "delete_item",
    "move_item",
    "duplicate_item",
    "save_vault",
    "delete_vault",
    "change_password",
    "set_profile_name",
    "remove_attachment",
    "set_vault_travel_safe",
    "enter_travel",
    "exit_travel",
    "merge_duplicates",
    "merge_sure_duplicates",
    "resolve_duplicates",
    "rename_device",
    "revoke_device",
];

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

// ---- servers -------------------------------------------------------------------

/// A mailbox server: its base URL and, for a self-host, a CA in PEM.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Server {
    pub base_url: String,
    pub ca_pem: Option<String>,
}

impl Server {
    pub fn endpoint(&self) -> FfiMailboxEndpoint {
        FfiMailboxEndpoint {
            base_url: self.base_url.clone(),
            extra_ca_pem: self.ca_pem.clone(),
        }
    }
}

#[cfg(debug_assertions)]
static DEBUG_HOSTED: std::sync::OnceLock<Server> = std::sync::OnceLock::new();

/// Debug builds: the test mailbox started in this process stands for the
/// OnePass server.
#[cfg(all(debug_assertions, feature = "test-mailbox"))]
pub fn set_debug_hosted(server: Server) {
    let _ = DEBUG_HOSTED.set(server);
}

/// The OnePass server of this build. A debug build may point it elsewhere:
/// the test mailbox of this process, or ONEPASS_MAILBOX_URL (with the CA in
/// the file ONEPASS_MAILBOX_CA), for the end-to-end test.
pub fn hosted() -> Server {
    #[cfg(debug_assertions)]
    {
        if let Some(s) = DEBUG_HOSTED.get() {
            return s.clone();
        }
        if let Ok(url) = std::env::var("ONEPASS_MAILBOX_URL") {
            let ca_pem = std::env::var_os("ONEPASS_MAILBOX_CA")
                .and_then(|p| std::fs::read_to_string(p).ok());
            return Server {
                base_url: url,
                ca_pem,
            };
        }
    }
    Server {
        base_url: HOSTED_URL.into(),
        ca_pem: None,
    }
}

/// The CA to trust for `base_url`: the OnePass server's own (none, or the
/// debug test CA), else `fallback`.
pub fn ca_for(base_url: &str, fallback: Option<String>) -> Option<String> {
    let h = hosted();
    if h.base_url == base_url {
        h.ca_pem
    } else {
        fallback
    }
}

/// `https`, a host, no user info, query or fragment, at most 256 bytes of
/// visible ASCII (the core's rule for a signed home; `MailboxEndpoints.validate`).
pub fn valid_url(text: &str) -> bool {
    if text.len() > 256 || text.contains('\\') || !text.bytes().all(|b| (0x21..=0x7e).contains(&b))
    {
        return false;
    }
    match url::Url::parse(text) {
        Ok(u) => {
            u.scheme() == "https"
                && u.host_str().is_some_and(|h| !h.is_empty())
                && u.username().is_empty()
                && u.password().is_none()
                && u.query().is_none()
                && u.fragment().is_none()
        }
        Err(_) => false,
    }
}

/// What the settings line names: the OnePass server, or a self-host's host.
#[derive(Serialize, Clone, Debug, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ServerName {
    pub hosted: bool,
    pub host: String,
}

pub fn server_name(base_url: &str) -> ServerName {
    ServerName {
        hosted: base_url == hosted().base_url,
        host: url::Url::parse(base_url)
            .ok()
            .and_then(|u| u.host_str().map(str::to_owned))
            .unwrap_or_else(|| base_url.to_owned()),
    }
}

// ---- where the account syncs ------------------------------------------------------

/// A mailbox this account syncs with.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Home {
    pub base_url: String,
    /// 32 hex characters.
    pub mailbox_id: String,
    pub ca_pem: Option<String>,
}

impl Home {
    pub fn endpoint(&self) -> FfiMailboxEndpoint {
        FfiMailboxEndpoint {
            base_url: self.base_url.clone(),
            extra_ca_pem: self.ca_pem.clone(),
        }
    }

    pub fn backend(&self) -> FfiSyncBackend {
        FfiSyncBackend::Mailbox {
            base_url: self.base_url.clone(),
            mailbox_id: self.mailbox_id.clone(),
        }
    }
}

/// Where this store's account syncs, as the app last decided it.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum Backend {
    /// On this PC only: an account from before sync, or none yet.
    Local,
    /// A setup to finish on this server (it resumes at each unlock).
    Pending {
        server: Server,
    },
    Mailbox {
        home: Home,
    },
}

const BACKEND_KEY: &str = "backend";
const SETUP_KEY: &str = "mailbox.setup";

fn meta_read<T: for<'a> Deserialize<'a>>(db: &str, key: &str) -> Result<Option<T>, OnePassError> {
    let store = onepass_ffi::open_sync_store(db.to_owned())?;
    match store.meta(key.into())? {
        Some(b) if !b.is_empty() => Ok(serde_json::from_slice(&b).ok()),
        _ => Ok(None),
    }
}

fn meta_write<T: Serialize>(db: &str, key: &str, value: Option<&T>) -> Result<(), OnePassError> {
    let store = onepass_ffi::open_sync_store(db.to_owned())?;
    let bytes = match value {
        Some(v) => serde_json::to_vec(v).map_err(|_| OnePassError::Store)?,
        None => Vec::new(),
    };
    store.set_meta(key.into(), bytes)
}

pub fn backend(state: &AppState) -> Backend {
    meta_read(&state.db_path(), BACKEND_KEY)
        .ok()
        .flatten()
        .unwrap_or(Backend::Local)
}

pub fn set_backend(state: &AppState, b: &Backend) -> Result<(), OnePassError> {
    meta_write(&state.db_path(), BACKEND_KEY, Some(b))
}

// ---- credential seeds (mailbox.bin) ------------------------------------------------

const SEEDS_MAGIC: &[u8; 8] = b"OPMBX\x00\x00\x01";
const SEEDS_CONTEXT: &[u8] = b"onepass/desktop/mailbox/v1";

#[derive(Serialize, Deserialize, Default)]
struct Seeds(Vec<(String, Zeroizing<Vec<u8>>)>);

fn seeds_path(state: &AppState) -> std::path::PathBuf {
    state.data_dir().join("mailbox.bin")
}

fn load_seeds(state: &AppState) -> Result<Seeds, String> {
    let bytes = match std::fs::read(seeds_path(state)) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Seeds::default()),
        Err(e) => return Err(format!("read: {e}")),
    };
    let sealed = bytes
        .strip_prefix(SEEDS_MAGIC.as_slice())
        .ok_or("mailbox file format")?;
    let plain = state.sealer.open(sealed, SEEDS_CONTEXT)?;
    postcard::from_bytes(&plain).map_err(|_| "mailbox file format".into())
}

fn save_seeds(state: &AppState, seeds: &Seeds) -> Result<(), String> {
    let plain = Zeroizing::new(postcard::to_allocvec(seeds).map_err(|_| "encode")?);
    let mut out = SEEDS_MAGIC.to_vec();
    out.extend_from_slice(&state.sealer.seal(&plain, SEEDS_CONTEXT)?);
    let path = seeds_path(state);
    let tmp = path.with_extension("bin.tmp");
    std::fs::write(&tmp, out).map_err(|e| format!("write: {e}"))?;
    std::fs::rename(tmp, path).map_err(|e| format!("write: {e}"))
}

pub fn seed(state: &AppState, mailbox_id: &str) -> Result<Option<Zeroizing<Vec<u8>>>, String> {
    Ok(load_seeds(state)?
        .0
        .into_iter()
        .find(|(id, _)| id == mailbox_id)
        .map(|(_, s)| s))
}

pub fn store_seed(state: &AppState, mailbox_id: &str, seed: &[u8]) -> Result<(), String> {
    let mut seeds = load_seeds(state)?;
    seeds.0.retain(|(id, _)| id != mailbox_id);
    seeds
        .0
        .push((mailbox_id.to_owned(), Zeroizing::new(seed.to_vec())));
    save_seeds(state, &seeds)
}

fn delete_seed(state: &AppState, mailbox_id: &str) -> Result<(), String> {
    let mut seeds = load_seeds(state)?;
    seeds.0.retain(|(id, _)| id != mailbox_id);
    save_seeds(state, &seeds)
}

// ---- the setup of a mailbox (MailboxSetup.swift) ----------------------------------

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
struct Progress {
    /// 0 started, 1 credential, 2 created, 3 recovery granted, 4 locator
    /// set, 5 home adopted.
    step: u8,
    server: Server,
    mailbox_id: Option<String>,
}

pub enum SetupOutcome {
    Ready(Home),
    /// The server could not be reached: the setup resumes later.
    Offline,
    Failed(String),
}

fn advance(db: &str, p: &mut Progress, step: u8) -> Result<(), OnePassError> {
    p.step = step;
    meta_write(db, SETUP_KEY, Some(&*p))
}

/// Run (or resume) the setup on `server` for the unlocked `session`.
pub fn run_setup(
    state: &AppState,
    session: &Arc<Session>,
    server: &Server,
    secret_key: &str,
) -> SetupOutcome {
    match setup_steps(state, session, server, secret_key) {
        Ok(home) => SetupOutcome::Ready(home),
        Err(OnePassError::MailboxUnavailable { .. }) => SetupOutcome::Offline,
        Err(e) => SetupOutcome::Failed(format!("{e:?}")),
    }
}

fn setup_steps(
    state: &AppState,
    session: &Arc<Session>,
    server: &Server,
    secret_key: &str,
) -> Result<Home, OnePassError> {
    let db = state.db_path();
    let dev = |e: String| OnePassError::InvalidInput { what: e };
    let mut p = match meta_read::<Progress>(&db, SETUP_KEY)? {
        Some(p) if p.server == *server => p,
        _ => {
            let p = Progress {
                step: 0,
                server: server.clone(),
                mailbox_id: None,
            };
            meta_write(&db, SETUP_KEY, Some(&p))?;
            p
        }
    };
    let endpoint = p.server.endpoint();
    // 1. This device's credential, kept before the server knows it.
    if p.step < 1 {
        let c = onepass_ffi::mailbox_generate_credential()?;
        store_seed(state, PENDING, &Zeroizing::new(c.seed)).map_err(dev)?;
        advance(&db, &mut p, 1)?;
    }
    // 2. The mailbox, managed by that credential.
    if p.step < 2 {
        let seed = seed(state, PENDING)
            .map_err(dev)?
            .ok_or_else(|| dev("mailbox credential".into()))?;
        let created = onepass_ffi::mailbox_create(endpoint.clone(), seed.to_vec(), None)?;
        store_seed(state, &created.mailbox_id, &seed).map_err(dev)?;
        delete_seed(state, PENDING).map_err(dev)?;
        p.mailbox_id = Some(created.mailbox_id);
        advance(&db, &mut p, 2)?;
    }
    let mailbox_id = p
        .mailbox_id
        .clone()
        .ok_or_else(|| dev("mailbox id".into()))?;
    let seed = seed(state, &mailbox_id)
        .map_err(dev)?
        .ok_or_else(|| dev("mailbox credential".into()))?;
    let home = Home {
        base_url: p.server.base_url.clone(),
        mailbox_id: mailbox_id.clone(),
        ca_pem: p.server.ca_pem.clone(),
    };
    let sync = MailboxSync::open(
        db.clone(),
        home.endpoint(),
        mailbox_id.clone(),
        seed.to_vec(),
    )?;
    // 3. The recovery credential, derived from the Secret Key, granted, then forgotten.
    if p.step < 3 {
        let recovery =
            onepass_ffi::mailbox_recovery_credential(secret_key.to_owned(), mailbox_id.clone())?;
        match sync.grant(
            recovery.public_key.clone(),
            FfiCredentialRole::Manage,
            RECOVERY_LABEL.to_vec(),
        ) {
            // Conflict: granted before a cut.
            Ok(_) | Err(OnePassError::Conflict) => {}
            Err(e) => return Err(e),
        }
        advance(&db, &mut p, 3)?;
    }
    // 4. The locator a restore looks the mailbox up by.
    if p.step < 4 {
        sync.set_locator(onepass_ffi::mailbox_locator(secret_key.to_owned())?)?;
        advance(&db, &mut p, 4)?;
    }
    // 5. The account's signed home names the mailbox.
    if p.step < 5 {
        let backend = home.backend();
        let current = session.sync_home()?;
        if current.map(|h| h.backend) != Some(backend.clone()) {
            session.adopt_sync_home(session.sign_sync_home(backend)?)?;
        }
        advance(&db, &mut p, 5)?;
    }
    // 6. The app syncs with it from now on.
    set_backend(state, &Backend::Mailbox { home: home.clone() })?;
    meta_write::<Progress>(&db, SETUP_KEY, None)?;
    Ok(home)
}

// ---- the status --------------------------------------------------------------------

/// What Settings > Sync and the sidebar show.
#[derive(Serialize, Clone, Debug, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SyncView {
    /// "local", "pending" or "mailbox".
    pub backend: &'static str,
    pub server: Option<ServerName>,
    /// "off", "waitingUnlock", "setupOffline", "setupFailed", "idle",
    /// "syncing", "offline", "retrying", "clockSkew", "waiting", "refused",
    /// "unreadable" or "homeMoved".
    pub state: &'static str,
    /// Unix seconds of the last round that ended idle.
    pub last_sync: Option<i64>,
    /// The refused kind, the moved-to host, or a setup failure.
    pub detail: Option<String>,
}

// ---- the coordinator ---------------------------------------------------------------

/// The account's mailbox client, shared by the sync thread and pairing.
type SharedClient = Arc<Mutex<Option<(Home, Arc<MailboxSync>)>>>;

enum Msg {
    /// A round now; the sender (if any) hears when it is done.
    Kick(Option<mpsc::Sender<()>>),
    /// A local write: a round after `DEBOUNCE`.
    Changed,
    /// The backend changed (setup, restore, pairing): reopen everything.
    Reset,
}

/// The handle the app keeps: sends triggers to the sync thread and reads
/// its status.
#[derive(Default)]
pub struct SyncEngine {
    tx: Mutex<Option<mpsc::Sender<Msg>>>,
    view: Arc<Mutex<SyncView>>,
    client: SharedClient,
}

impl SyncEngine {
    fn send(&self, m: Msg) {
        if let Some(tx) = lock(&self.tx).as_ref() {
            let _ = tx.send(m);
        }
    }

    pub fn kick(&self) {
        self.send(Msg::Kick(None));
    }

    pub fn changed(&self) {
        self.send(Msg::Changed);
    }

    pub fn reset(&self) {
        self.send(Msg::Reset);
    }

    /// A round now, returning once it ran (at most `timeout`).
    pub fn sync_now_blocking(&self, timeout: Duration) {
        let (tx, rx) = mpsc::channel();
        self.send(Msg::Kick(Some(tx)));
        let _ = rx.recv_timeout(timeout);
    }

    pub fn view(&self) -> SyncView {
        lock(&self.view).clone()
    }

    /// The mailbox client of the account, once the sync thread opened it.
    pub fn client(&self) -> Option<(Home, Arc<MailboxSync>)> {
        lock(&self.client).clone()
    }
}

/// Starts the sync thread of the app (once, at launch).
pub fn spawn(handle: AppHandle) {
    let (tx, rx) = mpsc::channel();
    let state = handle.state::<AppState>();
    *lock(&state.sync.tx) = Some(tx.clone());
    let view = state.sync.view.clone();
    let client = state.sync.client.clone();
    std::thread::Builder::new()
        .name("onepass-sync".into())
        .spawn(move || {
            let mut w = Worker {
                handle,
                tx,
                view,
                client,
                wake: None,
                moved: false,
                retry_at: None,
                attempt: 0,
                debounce_at: None,
                periodic_at: Instant::now() + period(),
                last_sync: None,
            };
            w.run(rx);
        })
        .expect("sync thread");
}

fn period() -> Duration {
    #[cfg(debug_assertions)]
    if let Some(s) = std::env::var("ONEPASS_SYNC_PERIOD_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
    {
        return Duration::from_secs(s.max(1));
    }
    PERIOD
}

/// A wake from the mailbox's channel: one more round.
struct WakeKick(Mutex<mpsc::Sender<Msg>>);

impl FfiWakeObserver for WakeKick {
    fn wake(&self) {
        let _ = lock(&self.0).send(Msg::Kick(None));
    }
}

struct Worker {
    handle: AppHandle,
    tx: mpsc::Sender<Msg>,
    view: Arc<Mutex<SyncView>>,
    client: SharedClient,
    wake: Option<Arc<WakeListenerHandle>>,
    moved: bool,
    retry_at: Option<Instant>,
    attempt: usize,
    debounce_at: Option<Instant>,
    periodic_at: Instant,
    last_sync: Option<i64>,
}

impl Worker {
    fn run(&mut self, rx: mpsc::Receiver<Msg>) {
        // The first round at launch (a locked PC still fetches).
        let mut queue: VecDeque<Msg> = VecDeque::from([Msg::Kick(None)]);
        loop {
            let mut due = false;
            let mut waiters = Vec::new();
            if queue.is_empty() {
                let next = [self.debounce_at, self.retry_at, Some(self.periodic_at)]
                    .into_iter()
                    .flatten()
                    .min();
                let wait = next.map_or(PERIOD, |t| t.saturating_duration_since(Instant::now()));
                match rx.recv_timeout(wait) {
                    Ok(m) => queue.push_back(m),
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                    Err(mpsc::RecvTimeoutError::Disconnected) => return,
                }
            }
            while let Ok(m) = rx.try_recv() {
                queue.push_back(m);
            }
            for m in queue.drain(..) {
                match m {
                    Msg::Kick(w) => {
                        due = true;
                        waiters.extend(w);
                    }
                    Msg::Changed => self.debounce_at = Some(Instant::now() + DEBOUNCE),
                    Msg::Reset => {
                        self.close();
                        self.moved = false;
                        self.retry_at = None;
                        self.attempt = 0;
                        due = true;
                    }
                }
            }
            let now_i = Instant::now();
            for slot in [&mut self.debounce_at, &mut self.retry_at] {
                if slot.is_some_and(|t| t <= now_i) {
                    *slot = None;
                    due = true;
                }
            }
            if self.periodic_at <= now_i {
                self.periodic_at = now_i + period();
                due = true;
            }
            if due {
                // A round that asks for another gets it at once (bounded).
                for _ in 0..8 {
                    if !self.round() {
                        break;
                    }
                }
                self.periodic_at = Instant::now() + period();
            }
            for w in waiters {
                let _ = w.send(());
            }
        }
    }

    fn state(&self) -> tauri::State<'_, AppState> {
        self.handle.state::<AppState>()
    }

    fn set(&self, v: SyncView) {
        let changed = {
            let mut cur = lock(&self.view);
            let changed = *cur != v;
            *cur = v.clone();
            changed
        };
        if changed {
            let _ = self.handle.emit("sync-status", v);
        }
    }

    fn view(
        &self,
        backend: &'static str,
        server: Option<ServerName>,
        state: &'static str,
    ) -> SyncView {
        SyncView {
            backend,
            server,
            state,
            last_sync: self.last_sync,
            detail: None,
        }
    }

    fn close(&mut self) {
        if let Some(w) = self.wake.take() {
            w.stop();
        }
        lock(&self.client).take();
    }

    fn schedule_retry(&mut self, after: Option<u32>) {
        let secs = match after {
            Some(s) => u64::from(s),
            None => {
                let d = RETRY_DELAYS[self.attempt.min(RETRY_DELAYS.len() - 1)];
                self.attempt += 1;
                d
            }
        };
        self.retry_at = Some(Instant::now() + Duration::from_secs(secs));
    }

    /// One step: the setup when it is pending, else a round. True when the
    /// round asks for another at once.
    fn round(&mut self) -> bool {
        let state = self.state();
        let has_account = matches!(
            onepass_ffi::store_state(state.db_path()),
            Ok(onepass_ffi::FfiStoreState::Account)
        );
        let backend = if has_account {
            backend(&state)
        } else {
            Backend::Local
        };
        let home = match backend {
            Backend::Local => {
                self.close();
                self.set(self.view("local", None, "off"));
                return false;
            }
            Backend::Pending { server } => match self.setup(&server) {
                Some(home) => home,
                None => return false,
            },
            Backend::Mailbox { home } => home,
        };
        let name = Some(server_name(&home.base_url));
        if self.moved {
            return false;
        }
        let Some(client) = self.open(&home) else {
            self.set(SyncView {
                detail: Some("credential".into()),
                ..self.view("mailbox", name, "setupFailed")
            });
            return false;
        };
        let mut syncing = self.view("mailbox", name.clone(), "syncing");
        // Keep showing what the last round said while this one runs, unless
        // the UI asked: "syncing" is enough of a signal.
        syncing.detail = None;
        self.set(syncing);
        let session = self.state().session();
        let report = client.run_round(session, now());
        debug_log(&format!(
            "round {:?} changed={} rebased={} rerun={}",
            report.status,
            report.changed,
            report.rebased.len(),
            report.rerun
        ));
        if report.changed || !report.rebased.is_empty() {
            let _ = self.handle.emit("sync-changed", ());
        }
        self.apply(&report, name)
    }

    /// The setup of a pending account. `Some(home)` once ready.
    fn setup(&mut self, server: &Server) -> Option<Home> {
        let state = self.state();
        let name = Some(server_name(&server.base_url));
        let Some(session) = state.session() else {
            self.set(self.view("pending", name, "waitingUnlock"));
            return None;
        };
        let secrets = match state.load_secrets() {
            Ok(Some(s)) => s,
            _ => {
                self.set(SyncView {
                    detail: Some("device".into()),
                    ..self.view("pending", name, "setupFailed")
                });
                return None;
            }
        };
        let outcome = run_setup(&state, &session, server, &secrets.secret_key);
        match outcome {
            SetupOutcome::Ready(home) => {
                self.attempt = 0;
                Some(home)
            }
            SetupOutcome::Offline => {
                self.set(self.view("pending", name, "setupOffline"));
                self.schedule_retry(None);
                None
            }
            SetupOutcome::Failed(detail) => {
                debug_log(&format!("setup failed {detail}"));
                self.set(SyncView {
                    detail: Some(detail),
                    ..self.view("pending", name, "setupFailed")
                });
                self.schedule_retry(None);
                None
            }
        }
    }

    /// The account's client, opened once per home, and its wake channel.
    fn open(&mut self, home: &Home) -> Option<Arc<MailboxSync>> {
        if let Some((h, c)) = lock(&self.client).as_ref()
            && h == home
        {
            return Some(c.clone());
        }
        self.close();
        let state = self.state();
        let seed = seed(&state, &home.mailbox_id).ok().flatten()?;
        let client = MailboxSync::open(
            state.db_path(),
            home.endpoint(),
            home.mailbox_id.clone(),
            seed.to_vec(),
        )
        .ok()?;
        *lock(&self.client) = Some((home.clone(), client.clone()));
        // No wake channel: rounds still run on writes, unlock and the timer.
        if let Ok(info) = client.wake_info() {
            let observer = Arc::new(WakeKick(Mutex::new(self.tx.clone())));
            self.wake = onepass_ffi::start_wake_listener(info, observer).ok();
        }
        Some(client)
    }

    fn apply(&mut self, report: &FfiRoundReport, name: Option<ServerName>) -> bool {
        let v = |s: &'static str, w: &Worker| w.view("mailbox", name.clone(), s);
        match &report.status {
            FfiRoundStatus::Idle => {
                self.attempt = 0;
                self.retry_at = None;
                self.last_sync = Some(now());
                self.set(v("idle", self));
            }
            FfiRoundStatus::Offline => {
                self.set(v("offline", self));
                self.schedule_retry(report.retry_after_seconds);
            }
            FfiRoundStatus::Retrying => {
                self.set(v("retrying", self));
                self.schedule_retry(report.retry_after_seconds);
            }
            FfiRoundStatus::ClockSkew => {
                self.set(v("clockSkew", self));
                self.schedule_retry(report.retry_after_seconds);
            }
            FfiRoundStatus::WaitingForServer => {
                self.set(v("waiting", self));
                self.schedule_retry(report.retry_after_seconds);
            }
            FfiRoundStatus::Refused { kind } => {
                self.set(SyncView {
                    detail: Some(kind.clone()),
                    ..v("refused", self)
                });
            }
            FfiRoundStatus::Unsettled => {
                self.set(v("syncing", self));
                self.schedule_retry(report.retry_after_seconds);
            }
            FfiRoundStatus::Unreadable => {
                self.set(v("unreadable", self));
                self.schedule_retry(report.retry_after_seconds);
            }
            FfiRoundStatus::HomeMoved { base_url } => {
                self.moved = true;
                self.retry_at = None;
                self.debounce_at = None;
                if let Some(w) = self.wake.take() {
                    w.stop();
                }
                let host = base_url
                    .as_deref()
                    .map(|u| server_name(u).host)
                    .unwrap_or_else(|| "iCloud".into());
                self.set(SyncView {
                    detail: Some(host),
                    ..v("homeMoved", self)
                });
                return false;
            }
        }
        report.rerun
    }
}

/// Whether the store at `path` has no account (a restore or a pairing may
/// fill it).
pub fn store_is_empty(path: &Path) -> bool {
    matches!(
        onepass_ffi::store_state(path.to_string_lossy().into_owned()),
        Ok(onepass_ffi::FfiStoreState::Empty)
    )
}

/// Debug builds: the end-to-end test reads how rounds and setups ended
/// (statuses only, never a record or a key) in ONEPASS_SYNC_LOG.
fn debug_log(line: &str) {
    #[cfg(debug_assertions)]
    if let Some(path) = std::env::var_os("ONEPASS_SYNC_LOG") {
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        {
            let _ = writeln!(f, "{} {line}", now());
        }
    }
    #[cfg(not(debug_assertions))]
    let _ = line;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls() {
        assert!(valid_url(
            "https://mailbox.example.com/functions/v1/mailbox"
        ));
        assert!(valid_url("https://localhost:47800/functions/v1/mailbox"));
        assert!(!valid_url("http://mailbox.example.com"));
        assert!(!valid_url("https://user@mailbox.example.com"));
        assert!(!valid_url("https://mailbox.example.com/?q=1"));
        assert!(!valid_url("https://mailbox.example.com/#x"));
        assert!(!valid_url("https://mail box.example.com"));
        assert!(!valid_url(&format!("https://{}.com", "a".repeat(260))));
        assert!(!valid_url("ftp://x"));
    }

    #[test]
    fn backend_round_trip() {
        let b = Backend::Mailbox {
            home: Home {
                base_url: HOSTED_URL.into(),
                mailbox_id: "00".repeat(16),
                ca_pem: None,
            },
        };
        let json = serde_json::to_vec(&b).unwrap();
        assert_eq!(serde_json::from_slice::<Backend>(&json).unwrap(), b);
        assert!(server_name(HOSTED_URL).hosted || cfg!(debug_assertions));
        assert_eq!(
            server_name("https://sync.example.org/x").host,
            "sync.example.org"
        );
    }
}
