//! The production bridge in the Mac app (spec
//! `docs/specs/2026-10-27-release-bridge-design.md`).
//!
//! `BridgeServer` listens on `bridge.sock` in the App Group container and
//! serves each admitted client (the Safari extension or `onepass-relay`,
//! same team, checked by code signature in `onepass-relay`) with the host
//! loop of `onepass-bridge`: the same pairing, session, envelope and
//! disclosure rules as everywhere else, over the session the user unlocked
//! in the app. Locking the app locks the bridge: it is the same `Session`.
//!
//! Swift gets callbacks through `BridgeDelegate`: show a pairing request
//! and answer it with `answer_pairing`, persist pairings in the keychain,
//! confirm a `reprompt` item with Touch ID, bring the app forward to
//! unlock, reload after a write. Pairing keys cross the FFI like the Secret
//! Key does (spec P-06); vault keys never do.

use std::collections::{HashMap, HashSet};
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use onepass_bridge::audit::{AuditEvent, AuditSink};
use onepass_bridge::host::{Approval, Approver, Conn, Journal, Limits, PairingStore, spawn_reader};
use onepass_bridge::pairing::PairingRecord;
use onepass_bridge::service::{VaultAccess, VaultInfo, VaultStatus};
use onepass_bridge::{AppErrorCode, BridgeError};
use onepass_core::Id;
use onepass_core::model::Item;
use onepass_core::model::usage::SiteUsage;
use time::OffsetDateTime;
use zeroize::Zeroizing;

use crate::convert::{id_hex, parse_id};
use crate::error::{OnePassError, invalid};
use crate::session::{Session, find_vault};

/// A stored pairing, as the keychain keeps it (spec 6.4).
#[derive(Clone, uniffi::Record)]
pub struct FfiBridgePairing {
    /// 16 bytes, lowercase hex.
    pub pairing_id: String,
    /// The 32-byte pairing key.
    pub key: Vec<u8>,
    pub ext_name: String,
    pub browser: String,
    /// `safari`, a Chrome extension id or a Firefox add-on id.
    pub extension_id: String,
    pub created_at: u64,
    pub last_used: u64,
}

impl std::fmt::Debug for FfiBridgePairing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FfiBridgePairing")
            .field("pairing_id", &self.pairing_id)
            .field("key", &"**")
            .finish_non_exhaustive()
    }
}

/// A pairing waiting for the user's answer in the app.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiBridgePairingRequest {
    pub request_id: u64,
    /// Self-declared by the extension: shown, never trusted.
    pub ext_name: String,
    pub browser: String,
    /// `safari`, or the extension id the browser gave the relay.
    pub extension_id: String,
    /// The six digits, `123 456`, derived by the app.
    pub code: String,
}

/// What the app does for the bridge. Called on bridge threads, never the
/// main thread: an implementation hops to the main actor itself.
#[uniffi::export(with_foreign)]
pub trait BridgeDelegate: Send + Sync {
    /// Show the request (code, extension, browser). Answer later with
    /// `BridgeServer::answer_pairing`.
    fn pairing_requested(&self, request: FfiBridgePairingRequest);
    /// The request is over (answered, timed out, or the browser left).
    fn pairing_ended(&self, request_id: u64);
    /// Persist a completed pairing (keychain).
    fn pairing_stored(&self, pairing: FfiBridgePairing);
    /// A session was opened with this pairing at `at` (Unix seconds).
    fn pairing_used(&self, pairing_id: String, at: u64);
    /// The extension asked to unlock: bring the app forward.
    fn unlock_requested(&self);
    /// Confirm the user for an item marked `reprompt` (Touch ID). Blocks
    /// this bridge thread until answered; `false` refuses.
    fn confirm_reprompt(&self, vault_id: String, item_id: String) -> bool;
    /// The bridge wrote to the vault: reload and push.
    fn vault_changed(&self);
    /// A journal line (fixed text, never a secret or extension input).
    fn note(&self, message: String);
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Shared by every connection of one server.
struct Shared {
    delegate: Arc<dyn BridgeDelegate>,
    session: Mutex<Option<Arc<Session>>>,
    account: Mutex<String>,
    excluded: Mutex<HashSet<Id>>,
    pairings: Mutex<Vec<FfiBridgePairing>>,
    // Read by the socket admission, which exists on macOS only.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    allowed_extensions: Vec<String>,
    answers: Mutex<HashMap<u64, Option<bool>>>,
    next_request: AtomicU64,
    audit_path: PathBuf,
}

impl Shared {
    fn session(&self) -> Option<Arc<Session>> {
        lock(&self.session).clone()
    }
}

impl Journal for Shared {
    fn line(&self, msg: &str) {
        self.delegate.note(msg.to_owned());
    }
}

/// Pairing store of one connection over the shared list.
struct Pairings<'a>(&'a Shared);

impl PairingStore for Pairings<'_> {
    fn key(&self, id: &[u8; 16]) -> Option<Zeroizing<[u8; 32]>> {
        let want = data_encoding::HEXLOWER.encode(id);
        let list = lock(&self.0.pairings);
        let p = list.iter().find(|p| p.pairing_id == want)?;
        let mut key = Zeroizing::new([0u8; 32]);
        if p.key.len() != key.len() {
            return None;
        }
        key.copy_from_slice(&p.key);
        Some(key)
    }

    fn add(&mut self, r: &PairingRecord, extension_id: &str) -> Result<(), String> {
        let p = FfiBridgePairing {
            pairing_id: data_encoding::HEXLOWER.encode(&r.pairing_id),
            key: r.key.to_vec(),
            ext_name: r.ext_name.clone(),
            browser: r.browser.clone(),
            extension_id: extension_id.to_owned(),
            created_at: r.created_at,
            last_used: r.created_at,
        };
        {
            let mut list = lock(&self.0.pairings);
            list.retain(|q| q.pairing_id != p.pairing_id);
            list.push(p.clone());
        }
        self.0.delegate.pairing_stored(p);
        Ok(())
    }

    fn touch(&mut self, id: &[u8; 16], now: u64) -> Result<(), String> {
        let hex = data_encoding::HEXLOWER.encode(id);
        if let Some(p) = lock(&self.0.pairings)
            .iter_mut()
            .find(|p| p.pairing_id == hex)
        {
            p.last_used = now;
        }
        self.0.delegate.pairing_used(hex, now);
        Ok(())
    }
}

/// Approval of one connection: a request shown in the app, answered with
/// `answer_pairing`.
struct AppApprover<'a> {
    shared: &'a Shared,
    extension_id: String,
    request: Option<u64>,
}

impl Approver for AppApprover<'_> {
    fn begin(&mut self, sas: &str, ext_name: &str, browser: &str) -> Result<(), String> {
        let id = self.shared.next_request.fetch_add(1, Ordering::SeqCst);
        lock(&self.shared.answers).insert(id, None);
        self.request = Some(id);
        self.shared
            .delegate
            .pairing_requested(FfiBridgePairingRequest {
                request_id: id,
                ext_name: ext_name.to_owned(),
                browser: browser.to_owned(),
                extension_id: self.extension_id.clone(),
                code: sas.to_owned(),
            });
        Ok(())
    }

    fn poll(&mut self) -> Approval {
        let Some(id) = self.request else {
            return Approval::Refused;
        };
        match lock(&self.shared.answers).get(&id) {
            Some(Some(true)) => Approval::Approved,
            Some(Some(false)) | None => Approval::Refused,
            Some(None) => Approval::Pending,
        }
    }

    fn end(&mut self) {
        if let Some(id) = self.request.take() {
            lock(&self.shared.answers).remove(&id);
            self.shared.delegate.pairing_ended(id);
        }
    }
}

/// Audit journal: one JSON object per line (0600), never a value.
struct FileAudit(PathBuf);

impl AuditSink for FileAudit {
    fn record(&mut self, e: AuditEvent) {
        let mut line = serde_json::json!({
            "at": e.at,
            "op": e.op,
            "item_id": e.item_id,
            "origin": e.origin,
            "ctx": e.ctx.as_str(),
        });
        if let (Some(p), Some(obj)) = (e.plan, line.as_object_mut()) {
            obj.insert("intent".into(), serde_json::json!(p.intent));
            obj.insert("action".into(), serde_json::json!(p.action));
            obj.insert("confidence".into(), serde_json::json!(p.confidence));
        }
        if let Ok(mut f) = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&self.0)
        {
            let _ = writeln!(f, "{line}");
        }
    }
}

fn bridge_error(e: OnePassError) -> BridgeError {
    BridgeError::App(match e {
        OnePassError::Locked => AppErrorCode::Locked,
        OnePassError::NotFound => AppErrorCode::NotFound,
        OnePassError::Validation { .. } | OnePassError::InvalidInput { .. } => {
            AppErrorCode::Invalid
        }
        _ => AppErrorCode::Internal,
    })
}

/// The vault as the bridge sees it: the app's session, read at each call,
/// so a lock in the app is seen at once. Vaults excluded from AutoFill in
/// the app are invisible here too.
struct AppVault<'a>(&'a Shared);

impl AppVault<'_> {
    fn session(&self) -> onepass_bridge::Result<Arc<Session>> {
        self.0
            .session()
            .ok_or(BridgeError::App(AppErrorCode::Locked))
    }

    fn info(v: &onepass_core::vault::Vault) -> VaultInfo {
        VaultInfo {
            id: v.id,
            name: v.meta.name.clone(),
            color: Some(v.meta.color.clone()),
        }
    }
}

impl VaultAccess for AppVault<'_> {
    fn status(&self) -> VaultStatus {
        let account = lock(&self.0.account).clone();
        match self.vaults() {
            Ok(v) => VaultStatus {
                locked: false,
                account,
                vaults: v.len(),
            },
            Err(_) => VaultStatus {
                locked: true,
                account,
                vaults: 0,
            },
        }
    }

    fn unlock(&mut self) -> onepass_bridge::Result<bool> {
        self.0.delegate.unlock_requested();
        Ok(!self.status().locked)
    }

    fn vaults(&self) -> onepass_bridge::Result<Vec<VaultInfo>> {
        let excluded = lock(&self.0.excluded).clone();
        let vaults = self
            .session()?
            .with(|repo| Ok(repo.vaults()?))
            .map_err(bridge_error)?;
        Ok(vaults
            .iter()
            .filter(|v| !excluded.contains(&v.id))
            .map(Self::info)
            .collect())
    }

    fn items(&mut self) -> onepass_bridge::Result<Vec<(VaultInfo, Item)>> {
        let excluded = lock(&self.0.excluded).clone();
        self.session()?
            .with(|repo| {
                let mut out = Vec::new();
                for v in repo.vaults()? {
                    if excluded.contains(&v.id) {
                        continue;
                    }
                    let info = Self::info(&v);
                    out.extend(repo.items(&v)?.into_iter().map(|i| (info.clone(), i)));
                }
                Ok(out)
            })
            .map_err(bridge_error)
    }

    fn save(&mut self, vault_id: Id, item: Item) -> onepass_bridge::Result<()> {
        if lock(&self.0.excluded).contains(&vault_id) {
            return Err(BridgeError::App(AppErrorCode::NotFound));
        }
        self.session()?
            .with(|repo| {
                let vault = find_vault(repo, vault_id)?;
                repo.save_item(&vault, item.clone())?;
                Ok(())
            })
            .map_err(bridge_error)?;
        self.0.delegate.vault_changed();
        Ok(())
    }

    fn approve_reprompt(&mut self, item_id: Id) -> bool {
        // The item's vault, for the app to name it; no lock is held while
        // the delegate waits for the user.
        let found = self.items().ok().and_then(|items| {
            items
                .into_iter()
                .find(|(_, i)| i.id == item_id)
                .map(|(v, _)| v.id)
        });
        match found {
            Some(vault_id) => self
                .0
                .delegate
                .confirm_reprompt(id_hex(vault_id), id_hex(item_id)),
            None => false,
        }
    }

    fn record_usage(
        &mut self,
        vault_id: Id,
        item_id: Id,
        u: SiteUsage,
        now: OffsetDateTime,
        force: bool,
    ) -> onepass_bridge::Result<bool> {
        if lock(&self.0.excluded).contains(&vault_id) {
            return Err(BridgeError::App(AppErrorCode::NotFound));
        }
        let written = self
            .session()?
            .with(|repo| {
                let vault = find_vault(repo, vault_id)?;
                Ok(repo.record_usage(&vault, item_id, u.clone(), now, force)?)
            })
            .map_err(bridge_error)?;
        if written {
            self.0.delegate.vault_changed();
        }
        Ok(written)
    }

    fn forget_site_usage(&mut self, site: &str) -> onepass_bridge::Result<usize> {
        // Vaults hidden from the extension keep their memory, as they are
        // never read nor written from here.
        let excluded = lock(&self.0.excluded).clone();
        let result = self
            .session()?
            .with(|repo| Ok(repo.forget_site_usage_in(site, |v| !excluded.contains(&v.id))?));
        match result {
            Ok(rewritten) => {
                if rewritten > 0 {
                    self.0.delegate.vault_changed();
                }
                Ok(rewritten)
            }
            Err(e) => {
                // Best effort: other vaults may have been rewritten before
                // the failure.
                self.0.delegate.vault_changed();
                Err(bridge_error(e))
            }
        }
    }
}

/// Serve one admitted connection until it ends. `allowed`: the caller's
/// extension id passed the app's list (Safari always does).
fn serve_stream(shared: &Shared, stream: UnixStream, extension_id: String, allowed: bool) {
    let Ok(reader) = stream.try_clone() else {
        return;
    };
    let mut pairings = Pairings(shared);
    let mut approver = AppApprover {
        shared,
        extension_id: extension_id.clone(),
        request: None,
    };
    let clock = unix_now;
    let mut conn = Conn {
        allowed,
        extension_id,
        journal: shared,
        clock: &clock,
        limits: Limits::default(),
        pairings: &mut pairings,
        approver: &mut approver,
        audit: Some(Box::new(FileAudit(shared.audit_path.clone()))),
        rx: spawn_reader(reader),
        out: &stream,
    };
    conn.serve(|| Ok(AppVault(shared)));
    let _ = stream.shutdown(std::net::Shutdown::Both);
}

/// The bridge of the Mac app.
#[derive(uniffi::Object)]
pub struct BridgeServer {
    shared: Arc<Shared>,
    #[cfg(target_os = "macos")]
    server: Mutex<Option<onepass_relay::server::Server>>,
}

#[uniffi::export]
impl BridgeServer {
    /// `pairings`: what the keychain holds. `allowed_extensions`: Chrome and
    /// Firefox extension ids the app serves (Safari is always served).
    /// `audit_path`: the disclosure journal (JSON lines, 0600).
    #[uniffi::constructor]
    pub fn new(
        delegate: Arc<dyn BridgeDelegate>,
        pairings: Vec<FfiBridgePairing>,
        allowed_extensions: Vec<String>,
        audit_path: String,
    ) -> Arc<BridgeServer> {
        Arc::new(BridgeServer {
            shared: Arc::new(Shared {
                delegate,
                session: Mutex::new(None),
                account: Mutex::new(String::new()),
                excluded: Mutex::new(HashSet::new()),
                pairings: Mutex::new(pairings),
                allowed_extensions,
                answers: Mutex::new(HashMap::new()),
                next_request: AtomicU64::new(1),
                audit_path: PathBuf::from(audit_path),
            }),
            #[cfg(target_os = "macos")]
            server: Mutex::new(None),
        })
    }

    /// Listen on `<group_container>/bridge.sock`. Refused unless this app
    /// is signed by a team (an ad hoc build can check no one's signature);
    /// a second instance of the app finds the socket in use.
    pub fn start(&self, group_container: String) -> Result<(), OnePassError> {
        #[cfg(target_os = "macos")]
        {
            use onepass_relay::rendezvous::{SOCKET_NAME, own_team, peer_identity};
            use onepass_relay::server::{
                Accepted, MAX_CONNECTIONS, OPENING_TIMEOUT, Server, ServerConfig,
            };

            let mut slot = lock(&self.server);
            if slot.is_some() {
                return Ok(());
            }
            let team = own_team().ok_or_else(|| invalid("unsigned app: no bridge"))?;
            let path = PathBuf::from(group_container).join(SOCKET_NAME);
            let shared = self.shared.clone();
            let note = self.shared.clone();
            let server = Server::start(
                ServerConfig {
                    path,
                    team,
                    max_connections: MAX_CONNECTIONS,
                    opening_timeout: OPENING_TIMEOUT,
                    identify: Arc::new(peer_identity),
                    note: Arc::new(move |m| note.delegate.note(m.to_owned())),
                },
                Arc::new(move |a: Accepted| {
                    let allowed = matches!(a.client, onepass_relay::Client::Safari)
                        || shared.allowed_extensions.contains(&a.extension_id);
                    serve_stream(&shared, a.stream, a.extension_id, allowed);
                }),
            )
            .map_err(|_| invalid("bridge socket"))?;
            *slot = Some(server);
            Ok(())
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = group_container;
            Err(invalid("the bridge runs on macOS only"))
        }
    }

    /// Stop listening; connections in progress end on their own (each
    /// reads the session again at every request).
    pub fn stop(&self) {
        #[cfg(target_os = "macos")]
        {
            let server = lock(&self.server).take();
            drop(server);
        }
    }

    pub fn is_running(&self) -> bool {
        #[cfg(target_os = "macos")]
        {
            lock(&self.server).is_some()
        }
        #[cfg(not(target_os = "macos"))]
        {
            false
        }
    }

    /// The unlocked session (on unlock), or none (on lock).
    pub fn set_session(&self, session: Option<Arc<Session>>, account_name: String) {
        *lock(&self.shared.session) = session;
        *lock(&self.shared.account) = account_name;
    }

    /// Vaults hidden from AutoFill in the app (hex ids): hidden here too.
    pub fn set_excluded_vaults(&self, vault_ids: Vec<String>) -> Result<(), OnePassError> {
        let ids = vault_ids
            .iter()
            .map(|s| parse_id(s))
            .collect::<Result<HashSet<_>, _>>()?;
        *lock(&self.shared.excluded) = ids;
        Ok(())
    }

    /// The user's answer to a pairing request. An unknown or finished
    /// request is ignored.
    pub fn answer_pairing(&self, request_id: u64, approved: bool) {
        if let Some(slot) = lock(&self.shared.answers).get_mut(&request_id)
            && slot.is_none()
        {
            *slot = Some(approved);
        }
    }

    /// Forget a pairing: its next session gets `unknown_pairing`.
    pub fn forget_pairing(&self, pairing_id: String) {
        lock(&self.shared.pairings).retain(|p| p.pairing_id != pairing_id);
    }

    /// Current pairings, without their keys' bytes (for the settings list).
    pub fn pairings(&self) -> Vec<FfiBridgePairing> {
        lock(&self.shared.pairings)
            .iter()
            .map(|p| FfiBridgePairing {
                key: Vec::new(),
                ..p.clone()
            })
            .collect()
    }
}

/// Test entry: serve one connection on `stream` as an admitted client
/// (the socket admission is tested in `onepass-relay`).
#[doc(hidden)]
pub fn serve_for_tests(
    server: &BridgeServer,
    stream: UnixStream,
    extension_id: &str,
    allowed: bool,
) {
    serve_stream(&server.shared, stream, extension_id.to_owned(), allowed);
}
