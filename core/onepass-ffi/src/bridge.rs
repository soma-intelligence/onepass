//! The production bridge in the Mac app (spec
//! `docs/superpowers/specs/2026-10-27-release-bridge-design.md`).
//!
//! `BridgeServer` listens on `bridge.sock` in the App Group container and
//! serves each admitted client (the Safari extension or `onepass-relay`,
//! same team, checked by code signature in `onepass-relay`) with the host
//! loop of `onepass-bridge`: the same pairing, session, envelope and
//! disclosure rules as everywhere else, over the session the user unlocked
//! in the app. Locking the app locks the bridge: it is the same `Session`.
//!
//! Added accounts (owner ruling of 2026-11-10, which reverses ruling P7 of
//! the multi-account spec): the app lists every account with its session
//! (`set_sessions`). Requests are decrypted and served here, on one socket,
//! so the accounts are merged here too (`AppVault`): the lists hold the
//! items of every unlocked account, a write goes to the session that owns
//! the vault, and every check of the bridge (pairing, allowed extension,
//! origin, reprompt, journal) runs as for one account. The lock state is
//! the primary account's; a locked added account gives nothing and asks
//! nothing.
//!
//! Swift gets callbacks through `BridgeDelegate`: show a pairing request
//! and answer it with `answer_pairing`, persist pairings in the keychain,
//! confirm a `reprompt` item with Touch ID, bring the app forward to
//! unlock, reload after a write. Pairing keys cross the FFI like the Secret
//! Key does (spec P-06); vault keys never do.

use std::cell::Cell;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use onepass_bridge::agent::AgentHub;
use onepass_bridge::audit::{AuditEvent, AuditSink};
use onepass_bridge::host::{Approval, Approver, Conn, Journal, Limits, PairingStore, spawn_reader};
use onepass_bridge::pairing::PairingRecord;
use onepass_bridge::service::{AccountTag, VaultAccess, VaultInfo, VaultStatus};
use onepass_bridge::{AppErrorCode, BridgeError};
use onepass_core::Id;
use onepass_core::autofill_history::{AutofillEvent, ClientContext};
use onepass_core::model::Item;
use onepass_core::model::usage::SiteUsage;
use onepass_core::profiles::{AccountDirectory, Slot};
use time::OffsetDateTime;
use zeroize::Zeroizing;

use crate::convert::{id_hex, parse_id};
use crate::error::{OnePassError, invalid};
use crate::session::{Repo, Session, find_vault};

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
    /// The browser the app vouched for by code signature when it paired
    /// without a code (`Safari`, `Google Chrome`...); empty after the code
    /// flow (spec 2026-11-02-browser-auto-pairing).
    pub verified_browser: String,
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

/// One account the bridge serves (`BridgeServer::set_sessions`).
#[derive(Clone, uniffi::Record)]
pub struct FfiBridgeAccount {
    /// `primary`, or the 32 hex characters of an added account's slot (as
    /// in `FfiAccountEntry`).
    pub slot: String,
    /// The account's unlocked session; none while it is locked.
    pub session: Option<Arc<Session>>,
    /// Shown on a candidate when several accounts answer (the account's
    /// label). The status names the primary account's.
    pub account_name: String,
    /// Vaults of this account hidden from AutoFill (hex ids): hidden here
    /// too, with those of `set_excluded_vaults`.
    pub excluded_vault_ids: Vec<String>,
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
    /// The extension asked to unlock: bring the app forward. `pairing_id`:
    /// the paired client that asks (hex, as in `FfiBridgePairing`).
    /// `origin_host`: the host of the page the user's gesture was on, when
    /// the extension said (an older one does not). Both let the app bind
    /// what this unlock allows next to that client and that site.
    fn unlock_requested(&self, pairing_id: String, origin_host: Option<String>);
    /// Confirm the user for an item marked `reprompt` (Touch ID). `slot`:
    /// the account of the item (`primary` or an added account's slot).
    /// `pairing_id`: the paired client that asks. `origin_host`: the host
    /// of the page the secret is for, none for a request without a page
    /// (the extension's own window). Blocks this bridge thread until
    /// answered; `false` refuses.
    fn confirm_reprompt(
        &self,
        slot: String,
        vault_id: String,
        item_id: String,
        pairing_id: String,
        origin_host: Option<String>,
    ) -> bool;
    /// A secret was served to a browser, after every check of the bridge:
    /// the user is at work with the vault. `slot`: the account of the item.
    /// `pairing_id`: the client served. `kind`: `fill_login`, `fill_card`,
    /// `fill_identity`, `fill_document`, `fill_loyalty`, `fill_provider`,
    /// `totp`, `reveal` or `passkey_get`. Called exactly where the journal
    /// records such a line, and never for a plan, a note, a save, a refused
    /// request or an agent fill.
    fn fill_served(&self, slot: String, pairing_id: String, kind: String);
    /// The bridge wrote to the account in `slot`: reload and push that
    /// account. `vault_id`: the vault written; none when several of its
    /// vaults may have changed (a forgotten site).
    fn vault_changed(&self, slot: String, vault_id: Option<String>);
    /// A journal line (fixed text, never a secret or extension input).
    fn note(&self, message: String);
}

/// The extension id of a Safari connection (`onepass_relay::SAFARI_EXTENSION_ID`
/// on the Mac, where the relay crate exists).
const SAFARI_EXTENSION_ID: &str = "safari";
/// The browser a Safari pairing is vouched as.
const SAFARI_BROWSER: &str = "Safari";

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// One listed account: its slot, session and what it hides.
#[derive(Clone)]
struct Account {
    slot: Slot,
    session: Option<Arc<Session>>,
    name: String,
    excluded: HashSet<Id>,
}

/// Shared by every connection of one server.
struct Shared {
    delegate: Arc<dyn BridgeDelegate>,
    /// The accounts the app listed, the primary one first when it is
    /// there. One entry (the primary account) after `set_session`.
    accounts: Mutex<Vec<Account>>,
    /// Hidden in every account (`set_excluded_vaults`).
    excluded: Mutex<HashSet<Id>>,
    /// The primary store's folder, where the account directory lives: a
    /// page's host is routed with it. None: every host is the primary's.
    routing: Mutex<Option<PathBuf>>,
    pairings: Mutex<Vec<FfiBridgePairing>>,
    // Read by the socket admission, which exists on macOS only.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    allowed_extensions: Vec<String>,
    /// Extension ids the user revoked: never paired without a code again
    /// until a code pairing or the user's "allow again".
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    blocked_auto: Mutex<Vec<String>>,
    answers: Mutex<HashMap<u64, Option<bool>>>,
    next_request: AtomicU64,
    audit_path: PathBuf,
    /// The agent fills of `fill_in_browser`: every session may poll it
    /// (`agent_wait`); the MCP host fills through the same one.
    agent: Arc<AgentHub>,
}

/// An account as one request sees it: listed, with a session.
struct Open {
    slot: Slot,
    name: String,
    session: Arc<Session>,
    /// Its own hidden vaults and the app-wide ones.
    excluded: HashSet<Id>,
}

impl Shared {
    /// The listed accounts that have a session, in order. An agents-only
    /// session does not count: the browsers see a session opened from the
    /// phone as locked (spec 6.3).
    fn open_accounts(&self) -> Vec<Open> {
        let everywhere = lock(&self.excluded).clone();
        lock(&self.accounts)
            .iter()
            .filter_map(|a| {
                let session = a.session.clone().filter(|s| !s.is_agent_only())?;
                Some(Open {
                    slot: a.slot.clone(),
                    name: a.name.clone(),
                    session,
                    excluded: a.excluded.union(&everywhere).copied().collect(),
                })
            })
            .collect()
    }

    /// The name the status shows: the primary account's.
    fn primary_name(&self) -> String {
        lock(&self.accounts)
            .iter()
            .find(|a| a.slot.is_primary())
            .map(|a| a.name.clone())
            .unwrap_or_default()
    }

    /// The account AutoFill uses for `host` (`AccountDirectory::route`):
    /// the one claiming the domain, else the primary one. A directory that
    /// is not set or does not load routes to the primary account.
    fn route(&self, host: &str) -> Slot {
        lock(&self.routing)
            .as_deref()
            .and_then(|folder| AccountDirectory::load(folder).ok())
            .map(|d| d.route(host))
            .unwrap_or_else(Slot::primary)
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

    fn add(
        &mut self,
        r: &PairingRecord,
        extension_id: &str,
        verified: Option<&str>,
    ) -> Result<(), String> {
        let p = FfiBridgePairing {
            pairing_id: data_encoding::HEXLOWER.encode(&r.pairing_id),
            key: r.key.to_vec(),
            ext_name: r.ext_name.clone(),
            browser: r.browser.clone(),
            extension_id: extension_id.to_owned(),
            verified_browser: verified.unwrap_or_default().to_owned(),
            created_at: r.created_at,
            last_used: r.created_at,
        };
        {
            let mut list = lock(&self.0.pairings);
            list.retain(|q| q.pairing_id != p.pairing_id);
            list.push(p.clone());
        }
        // A code pairing approved with Touch ID lifts the user's block (the
        // app's store does the same on `pairing_stored`).
        if verified.is_none() {
            lock(&self.0.blocked_auto).retain(|b| b != extension_id);
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
        // Several accounts served: the slot of the item's account.
        if let (Some(a), Some(obj)) = (e.account, line.as_object_mut()) {
            obj.insert("account".into(), serde_json::json!(a));
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

/// The vault as the bridge sees it: the sessions of the listed accounts,
/// read at each call, so a lock in the app is seen at once. Vaults excluded
/// from AutoFill in the app are invisible here too.
///
/// The primary account decides the lock state: without its unlocked
/// session every call is `locked`. An added account that is locked, or
/// whose store fails, is left out of the call: no error, no prompt.
struct AppVault<'a> {
    shared: &'a Shared,
    /// An added account was left out for a failure (journaled once).
    warned: Cell<bool>,
    /// The pairing of the client served (hex), once the session is open.
    pairing_id: String,
}

const LOCKED: BridgeError = BridgeError::App(AppErrorCode::Locked);
const NOT_FOUND: BridgeError = BridgeError::App(AppErrorCode::NotFound);

impl<'a> AppVault<'a> {
    fn new(shared: &'a Shared) -> Self {
        AppVault {
            shared,
            warned: Cell::new(false),
            pairing_id: String::new(),
        }
    }

    /// The accounts to read: `locked` unless the primary one is open.
    fn accounts(&self) -> onepass_bridge::Result<Vec<Open>> {
        let open = self.shared.open_accounts();
        if !open.iter().any(|a| a.slot.is_primary()) {
            return Err(LOCKED);
        }
        Ok(open)
    }

    /// Run `f` on the repository of each account, the primary one first. A
    /// failure of the primary account is the call's; an added account that
    /// is locked or fails is left out.
    fn each<R>(
        &self,
        mut f: impl FnMut(&Open, &mut Repo) -> Result<R, OnePassError>,
    ) -> onepass_bridge::Result<Vec<(Open, R)>> {
        let mut accounts = self.accounts()?;
        accounts.sort_by_key(|a| !a.slot.is_primary());
        let mut out = Vec::with_capacity(accounts.len());
        for a in accounts {
            match a.session.with(|repo| f(&a, repo)) {
                Ok(r) => out.push((a, r)),
                Err(e) if a.slot.is_primary() => return Err(bridge_error(e)),
                Err(OnePassError::Locked) => {}
                Err(_) => {
                    if !self.warned.replace(true) {
                        self.shared
                            .delegate
                            .note("an added account was left out: its store failed".to_owned());
                    }
                }
            }
        }
        Ok(out)
    }

    fn info(v: &onepass_core::vault::Vault, account: Option<&AccountTag>) -> VaultInfo {
        VaultInfo {
            id: v.id,
            name: v.meta.name.clone(),
            color: Some(v.meta.color.clone()),
            account: account.cloned(),
            personal: v.zone() == onepass_core::store::Zone::Private,
            shared: v.zone().is_shared(),
        }
    }

    /// The tag of each answering account, in order; none at all unless two
    /// accounts or more show a vault (the single account wire is unchanged).
    fn tags<R>(answers: &[(Open, Vec<R>)]) -> Vec<Option<AccountTag>> {
        let several = answers.iter().filter(|(_, v)| !v.is_empty()).count() > 1;
        answers
            .iter()
            .map(|(a, _)| {
                several.then(|| AccountTag {
                    key: a.slot.as_str().to_owned(),
                    label: a.name.clone(),
                    behind: false,
                })
            })
            .collect()
    }

    /// Every item of every account, by account then vault. Travel Mode
    /// (spec 2026-11-02): an item behind extra protection is never served
    /// to the extension while travelling.
    fn read_items(&self) -> onepass_bridge::Result<Vec<(VaultInfo, Item)>> {
        type Shelf = (onepass_core::vault::Vault, Vec<Item>);
        let answers = self.each(|a, repo| {
            let guard = repo.travelling();
            let mut shelves: Vec<Shelf> = Vec::new();
            for v in repo.vaults()? {
                if a.excluded.contains(&v.id) {
                    continue;
                }
                let items = repo
                    .items(&v)?
                    .into_iter()
                    .filter(|i| !(guard && i.travel_guarded()))
                    .collect();
                shelves.push((v, items));
            }
            Ok(shelves)
        })?;
        let tags = Self::tags(&answers);
        let mut out = Vec::new();
        for ((_, shelves), tag) in answers.into_iter().zip(tags) {
            for (v, items) in shelves {
                let info = Self::info(&v, tag.as_ref());
                out.extend(items.into_iter().map(|i| (info.clone(), i)));
            }
        }
        Ok(out)
    }

    /// The account that owns the vault `vault_id`, if it is served, and
    /// whether other accounts are served beside it.
    fn owner(&self, vault_id: Id) -> onepass_bridge::Result<(Open, bool)> {
        let mut accounts = self.accounts()?;
        if accounts.len() == 1 {
            // One account: the write itself finds the vault, as it always
            // did (one pass over the repository).
            let only = accounts.remove(0);
            if only.excluded.contains(&vault_id) {
                return Err(NOT_FOUND);
            }
            return Ok((only, false));
        }
        self.each(|a, repo| {
            Ok(!a.excluded.contains(&vault_id) && repo.vaults()?.iter().any(|v| v.id == vault_id))
        })?
        .into_iter()
        .find_map(|(a, owns)| owns.then_some((a, true)))
        .ok_or(NOT_FOUND)
    }

    /// The account and vault of a served item.
    fn home_of(&self, item_id: Id) -> Option<(Open, Id)> {
        self.each(|a, repo| {
            let guard = repo.travelling();
            for v in repo.vaults()? {
                if a.excluded.contains(&v.id) {
                    continue;
                }
                let held = repo
                    .items(&v)?
                    .iter()
                    .any(|i| i.id == item_id && !(guard && i.travel_guarded()));
                if held {
                    return Ok(Some(v.id));
                }
            }
            Ok(None)
        })
        .ok()?
        .into_iter()
        .find_map(|(a, vault)| vault.map(|v| (a, v)))
    }

    /// The account a page on `host` routes to among `keys` (the accounts
    /// that answer, by slot): as AutoFill, the one claiming the domain when
    /// it answers here, else the primary one.
    fn routed<'k>(&self, host: &str, mut keys: impl Iterator<Item = &'k str>) -> Slot {
        let claimed = self.shared.route(host);
        if keys.any(|k| k == claimed.as_str()) {
            claimed
        } else {
            Slot::primary()
        }
    }

    /// The visible items of each served account, by id.
    fn item_ids(&self) -> onepass_bridge::Result<Vec<(Open, HashSet<Id>)>> {
        self.each(|a, repo| {
            let guard = repo.travelling();
            let mut ids = HashSet::new();
            for v in repo.vaults()? {
                if a.excluded.contains(&v.id) {
                    continue;
                }
                ids.extend(
                    repo.items(&v)?
                        .iter()
                        .filter(|i| !(guard && i.travel_guarded()))
                        .map(|i| i.id),
                );
            }
            Ok(ids)
        })
    }

    fn changed(&self, account: &Open, vault_id: Option<Id>) {
        self.shared
            .delegate
            .vault_changed(account.slot.as_str().to_owned(), vault_id.map(id_hex));
    }
}

impl VaultAccess for AppVault<'_> {
    fn status(&self) -> VaultStatus {
        let account = self.shared.primary_name();
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

    fn unlock(&mut self, origin_host: Option<&str>) -> onepass_bridge::Result<bool> {
        self.shared
            .delegate
            .unlock_requested(self.pairing_id.clone(), origin_host.map(str::to_owned));
        Ok(!self.status().locked)
    }

    fn bind_client(&mut self, pairing_id: &[u8; 16]) {
        self.pairing_id = data_encoding::HEXLOWER.encode(pairing_id);
    }

    fn secret_served(&mut self, kind: &'static str, _item_id: Id, account: Option<&str>) {
        self.shared.delegate.fill_served(
            account.unwrap_or(Slot::primary().as_str()).to_owned(),
            self.pairing_id.clone(),
            kind.to_owned(),
        );
    }

    fn vaults_for(&self, host: &str) -> onepass_bridge::Result<Vec<VaultInfo>> {
        let mut all = self.vaults()?;
        if !all.iter().any(|v| v.account.is_some()) {
            return Ok(all);
        }
        let routed = self.routed(
            host,
            all.iter()
                .filter_map(|v| v.account.as_ref().map(|a| a.key.as_str())),
        );
        for v in &mut all {
            if let Some(a) = &mut v.account {
                a.behind = a.key != routed.as_str();
            }
        }
        all.sort_by_key(|v| v.account.as_ref().is_some_and(|a| a.behind));
        Ok(all)
    }

    fn vaults(&self) -> onepass_bridge::Result<Vec<VaultInfo>> {
        let answers = self.each(|a, repo| {
            let mut vaults = repo.vaults()?;
            vaults.retain(|v| !a.excluded.contains(&v.id));
            Ok(vaults)
        })?;
        let tags = Self::tags(&answers);
        Ok(answers
            .iter()
            .zip(&tags)
            .flat_map(|((_, vaults), tag)| vaults.iter().map(|v| Self::info(v, tag.as_ref())))
            .collect())
    }

    fn items(&mut self) -> onepass_bridge::Result<Vec<(VaultInfo, Item)>> {
        self.read_items()
    }

    fn items_for(&mut self, host: &str) -> onepass_bridge::Result<Vec<(VaultInfo, Item)>> {
        let mut all = self.read_items()?;
        if !all.iter().any(|(v, _)| v.account.is_some()) {
            return Ok(all);
        }
        let routed = self.routed(
            host,
            all.iter()
                .filter_map(|(v, _)| v.account.as_ref().map(|a| a.key.as_str())),
        );
        for (v, _) in &mut all {
            if let Some(a) = &mut v.account {
                a.behind = a.key != routed.as_str();
            }
        }
        all.sort_by_key(|(v, _)| v.account.as_ref().is_some_and(|a| a.behind));
        Ok(all)
    }

    fn save(&mut self, vault_id: Id, item: Item) -> onepass_bridge::Result<()> {
        let (owner, several) = self.owner(vault_id)?;
        // An item never moves from one account to another through the
        // bridge: an id another account holds is refused.
        let item_id = item.id;
        let elsewhere = several
            && self
                .each(|a, repo| {
                    if a.slot == owner.slot {
                        return Ok(false);
                    }
                    for v in repo.vaults()? {
                        if repo.items(&v)?.iter().any(|i| i.id == item_id) {
                            return Ok(true);
                        }
                    }
                    Ok(false)
                })?
                .into_iter()
                .any(|(_, held)| held);
        if elsewhere {
            return Err(NOT_FOUND);
        }
        owner
            .session
            .with(|repo| {
                let vault = find_vault(repo, vault_id)?;
                repo.save_item(&vault, item.clone())?;
                Ok(())
            })
            .map_err(bridge_error)?;
        self.changed(&owner, Some(vault_id));
        Ok(())
    }

    fn delete(&mut self, vault_id: Id, item_id: Id) -> onepass_bridge::Result<()> {
        let (owner, _) = self.owner(vault_id)?;
        owner
            .session
            .with(|repo| {
                let vault = find_vault(repo, vault_id)?;
                repo.delete_item(&vault, item_id)?;
                Ok(())
            })
            .map_err(bridge_error)?;
        self.changed(&owner, Some(vault_id));
        Ok(())
    }

    fn approve_reprompt(&mut self, item_id: Id, origin_host: Option<&str>) -> bool {
        // The item's account and vault, for the app to name it; no lock is
        // held while the delegate waits for the user.
        match self.home_of(item_id) {
            Some((account, vault_id)) => self.shared.delegate.confirm_reprompt(
                account.slot.as_str().to_owned(),
                id_hex(vault_id),
                id_hex(item_id),
                self.pairing_id.clone(),
                origin_host.map(str::to_owned),
            ),
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
        let (owner, _) = self.owner(vault_id)?;
        let written = owner
            .session
            .with(|repo| {
                let vault = find_vault(repo, vault_id)?;
                Ok(repo.record_usage(&vault, item_id, u.clone(), now, force)?)
            })
            .map_err(bridge_error)?;
        if written {
            self.changed(&owner, Some(vault_id));
        }
        Ok(written)
    }

    fn forget_site_usage(&mut self, site: &str) -> onepass_bridge::Result<usize> {
        // Vaults hidden from the extension keep their memory, as they are
        // never read nor written from here.
        let mut accounts = self.accounts()?;
        accounts.sort_by_key(|a| !a.slot.is_primary());
        let mut total = 0;
        for a in accounts {
            let result = a
                .session
                .with(|repo| Ok(repo.forget_site_usage_in(site, |v| !a.excluded.contains(&v.id))?));
            match result {
                Ok(rewritten) => {
                    if rewritten > 0 {
                        self.changed(&a, None);
                    }
                    total += rewritten;
                }
                Err(e) if a.slot.is_primary() => {
                    // Best effort: other vaults may have been rewritten
                    // before the failure.
                    self.changed(&a, None);
                    return Err(bridge_error(e));
                }
                // A locked added account wrote nothing.
                Err(OnePassError::Locked) => {}
                Err(_) => self.changed(&a, None),
            }
        }
        Ok(total)
    }

    fn record_autofill_event(&mut self, mut ev: AutofillEvent) -> onepass_bridge::Result<bool> {
        let mut accounts = self.accounts()?;
        // Each account keeps its own history: the event goes to the account
        // that holds its item (the primary one when it names none), with
        // the shown items of that account only. The home is looked up in
        // the accounts themselves, whatever they show beside it: an item of
        // an added account is never written to the primary's history.
        let account = if accounts.len() > 1 {
            let homes = self.item_ids()?;
            let home = match ev.item_id {
                Some(id) => homes.into_iter().find(|(_, ids)| ids.contains(&id)),
                None => homes.into_iter().find(|(a, _)| a.slot.is_primary()),
            };
            // An item no served account holds: nothing to remember.
            let Some((account, ids)) = home else {
                return Ok(false);
            };
            ev.shown.retain(|id| ids.contains(id));
            account
        } else {
            accounts.remove(0)
        };
        account
            .session
            .with(|repo| Ok(repo.record_autofill_event(ev.clone())?))
            .map_err(bridge_error)
    }

    fn autofill_affinity(
        &mut self,
        site: &str,
        client: &ClientContext,
        now: OffsetDateTime,
    ) -> onepass_bridge::Result<BTreeMap<Id, i64>> {
        // Item ids are unique across accounts: the learned bonuses of each
        // account's own history, side by side.
        Ok(self
            .each(|_, repo| Ok(repo.autofill_affinity(site, client, now)?))?
            .into_iter()
            .flat_map(|(_, learned)| learned)
            .collect())
    }
}

/// Serve one admitted connection until it ends. `allowed`: the caller's
/// extension id passed the app's list (Safari always does). `vouched`: the
/// browser the app vouches for, which may then pair without a code.
fn serve_stream(
    shared: &Shared,
    stream: UnixStream,
    extension_id: String,
    allowed: bool,
    vouched: Option<String>,
) {
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
        vouched,
        extension_id,
        journal: shared,
        clock: &clock,
        limits: Limits::default(),
        pairings: &mut pairings,
        approver: &mut approver,
        audit: Some(Box::new(FileAudit(shared.audit_path.clone()))),
        agent: Some(shared.agent.clone()),
        rx: spawn_reader(reader),
        out: &stream,
    };
    conn.serve(|| Ok(AppVault::new(shared)));
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
                accounts: Mutex::new(Vec::new()),
                excluded: Mutex::new(HashSet::new()),
                routing: Mutex::new(None),
                pairings: Mutex::new(pairings),
                allowed_extensions,
                blocked_auto: Mutex::new(Vec::new()),
                answers: Mutex::new(HashMap::new()),
                next_request: AtomicU64::new(1),
                audit_path: PathBuf::from(audit_path),
                agent: crate::developer::agent_hub(),
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
            use onepass_relay::rendezvous::{SOCKET_NAME, own_identity, peer_identity};
            use onepass_relay::server::{
                Accepted, MAX_CONNECTIONS, OPENING_TIMEOUT, Server, ServerConfig,
            };

            let mut slot = lock(&self.server);
            if slot.is_some() {
                return Ok(());
            }
            let (team, app) = own_identity().ok_or_else(|| invalid("unsigned app: no bridge"))?;
            let path = PathBuf::from(group_container).join(SOCKET_NAME);
            let shared = self.shared.clone();
            let note = self.shared.clone();
            let server = Server::start(
                ServerConfig {
                    path,
                    team,
                    app,
                    max_connections: MAX_CONNECTIONS,
                    opening_timeout: OPENING_TIMEOUT,
                    identify: Arc::new(peer_identity),
                    note: Arc::new(move |m| note.delegate.note(m.to_owned())),
                },
                Arc::new(move |a: Accepted| {
                    serve_admitted(
                        &shared,
                        a.stream,
                        a.client,
                        a.extension_id,
                        a.launcher.as_deref(),
                    );
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

    /// The unlocked session (on unlock), or none (on lock): the bridge
    /// serves this one account, as the primary one. The same as
    /// `set_sessions` with a single `primary` entry.
    pub fn set_session(&self, session: Option<Arc<Session>>, account_name: String) {
        *lock(&self.shared.accounts) = vec![Account {
            slot: Slot::primary(),
            session,
            name: account_name,
            excluded: HashSet::new(),
        }];
    }

    /// Every account the bridge serves, replacing the previous list: the
    /// primary account and the added ones, each with its session (none
    /// while locked). Call it again whenever an account unlocks, locks, is
    /// added or removed, or hides a vault.
    ///
    /// The lock state the browsers see is the primary account's (the entry
    /// whose slot is `primary`): without its session, everything is locked.
    /// An added account without a session gives nothing. Refused, the list
    /// unchanged, for a slot that is not one, a slot listed twice or a
    /// vault id that is not one.
    pub fn set_sessions(&self, accounts: Vec<FfiBridgeAccount>) -> Result<(), OnePassError> {
        let mut list: Vec<Account> = Vec::with_capacity(accounts.len());
        for a in accounts {
            let slot = Slot::parse(&a.slot)?;
            if list.iter().any(|b| b.slot == slot) {
                return Err(invalid("slot listed twice"));
            }
            let excluded = a
                .excluded_vault_ids
                .iter()
                .map(|s| parse_id(s))
                .collect::<Result<HashSet<_>, _>>()?;
            list.push(Account {
                slot,
                session: a.session,
                name: a.account_name,
                excluded,
            });
        }
        list.sort_by_key(|a| !a.slot.is_primary());
        *lock(&self.shared.accounts) = list;
        Ok(())
    }

    /// The primary store's folder (the one every `account_directory_*`
    /// call names): a page's host is routed as `account_directory_route`
    /// does, and the items of that account are offered first. None (the
    /// default): every host is the primary account's.
    pub fn set_routing_folder(&self, folder: Option<String>) {
        *lock(&self.shared.routing) = folder.map(PathBuf::from);
    }

    /// Vaults hidden from AutoFill in the app (hex ids): hidden here too,
    /// in whichever account they are.
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

    /// Extension ids the user revoked (from the keychain at launch, then
    /// after each "forget" or "allow again"): never paired without a code.
    pub fn set_blocked_auto(&self, extension_ids: Vec<String>) {
        *lock(&self.shared.blocked_auto) = extension_ids;
    }

    /// The current block list (a code pairing removes its id).
    pub fn blocked_auto(&self) -> Vec<String> {
        lock(&self.shared.blocked_auto).clone()
    }

    /// Forget a pairing: its next session gets `unknown_pairing`.
    pub fn forget_pairing(&self, pairing_id: String) {
        lock(&self.shared.pairings).retain(|p| p.pairing_id != pairing_id);
    }

    /// iPhone and iPad (spec 2026-11-03-ios-safari-autofill, ruling I1):
    /// serve one Safari extension connection inside this process, over a
    /// socket pair, and return the caller's end as a file descriptor (the
    /// caller owns and closes it). No app listens on iOS: the Safari Web
    /// Extension handler serves the bridge itself. Safari routes native
    /// messages only to the handler of the bundle that holds the extension,
    /// so the connection is admitted as Safari and may pair without a code
    /// (ruling I2), unless the user revoked it.
    pub fn connect_in_process(&self) -> Result<i32, OnePassError> {
        use std::os::fd::IntoRawFd;

        let (ours, theirs) = UnixStream::pair().map_err(|_| invalid("socket pair"))?;
        let shared = self.shared.clone();
        let blocked = lock(&shared.blocked_auto).contains(&SAFARI_EXTENSION_ID.to_owned());
        let vouched = (!blocked).then(|| SAFARI_BROWSER.to_owned());
        std::thread::Builder::new()
            .name("onepass-bridge-safari".into())
            // SLH-DSA signing needs a deep stack (spec P-14).
            .stack_size(16 << 20)
            .spawn(move || {
                serve_stream(&shared, ours, SAFARI_EXTENSION_ID.to_owned(), true, vouched);
            })
            .map_err(|_| invalid("bridge thread"))?;
        Ok(theirs.into_raw_fd())
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

impl BridgeServer {
    /// The hub the sessions of this server serve agent fills through: the
    /// process's one, shared with the MCP host. One hub per process is
    /// safe because the agent servers stay on the primary account
    /// (AppModel.swift, ruling P7): a ticket names an item of that account,
    /// and the bridge checks it against the item it fills.
    pub fn agent_hub(&self) -> Arc<AgentHub> {
        self.shared.agent.clone()
    }
}

/// What the app decides for a client the socket admitted (code signature
/// checked): whether it may use the bridge at all, and whether it may pair
/// without a code (spec 2026-11-02-browser-auto-pairing 3).
#[cfg(target_os = "macos")]
fn serve_admitted(
    shared: &Shared,
    stream: UnixStream,
    client: onepass_relay::Client,
    extension_id: String,
    launcher: Option<&str>,
) {
    use onepass_relay::Client;
    use onepass_relay::launcher::vouch;

    let allowed =
        matches!(client, Client::Safari) || shared.allowed_extensions.contains(&extension_id);
    let vouched = if allowed {
        let blocked = lock(&shared.blocked_auto).clone();
        vouch(
            client,
            &extension_id,
            launcher,
            &shared.allowed_extensions,
            &blocked,
        )
    } else {
        None
    };
    if matches!(client, Client::Relay) && allowed && vouched.is_none() {
        // The relay's verified parent, never extension input: enough to see
        // why a browser gets the code flow on a release install.
        shared.delegate.note(match launcher {
            Some(l) => format!("browser not vouched for automatic pairing: {l}"),
            None => "browser not vouched for automatic pairing: no signed launcher".to_owned(),
        });
    }
    serve_stream(
        shared,
        stream,
        extension_id,
        allowed,
        vouched.map(str::to_owned),
    );
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
    serve_stream(
        &server.shared,
        stream,
        extension_id.to_owned(),
        allowed,
        None,
    );
}

/// Test entry: a connection the socket admitted as the relay, with the
/// launcher it reported; the app's own decision follows.
#[cfg(target_os = "macos")]
#[doc(hidden)]
pub fn serve_relay_for_tests(
    server: &BridgeServer,
    stream: UnixStream,
    extension_id: &str,
    launcher: Option<&str>,
) {
    serve_admitted(
        &server.shared,
        stream,
        onepass_relay::Client::Relay,
        extension_id.to_owned(),
        launcher,
    );
}

/// Test entry: a connection the socket admitted as the Safari extension.
#[cfg(target_os = "macos")]
#[doc(hidden)]
pub fn serve_safari_for_tests(server: &BridgeServer, stream: UnixStream) {
    serve_admitted(
        &server.shared,
        stream,
        onepass_relay::Client::Safari,
        onepass_relay::SAFARI_EXTENSION_ID.to_owned(),
        None,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{FfiItemType, FfiKdfParams};

    struct Quiet;

    impl BridgeDelegate for Quiet {
        fn pairing_requested(&self, _request: FfiBridgePairingRequest) {}
        fn pairing_ended(&self, _request_id: u64) {}
        fn pairing_stored(&self, _pairing: FfiBridgePairing) {}
        fn pairing_used(&self, _pairing_id: String, _at: u64) {}
        fn unlock_requested(&self, _pairing_id: String, _origin_host: Option<String>) {}
        fn confirm_reprompt(
            &self,
            _slot: String,
            _vault_id: String,
            _item_id: String,
            _pairing_id: String,
            _origin_host: Option<String>,
        ) -> bool {
            false
        }
        fn fill_served(&self, _slot: String, _pairing_id: String, _kind: String) {}
        fn vault_changed(&self, _slot: String, _vault_id: Option<String>) {}
        fn note(&self, _message: String) {}
    }

    /// A fresh account holding one Login: its session, vault and item.
    fn account(dir: &tempfile::TempDir, file: &str, title: &str) -> (Arc<Session>, Id, Item) {
        let path = dir.path().join(file).to_string_lossy().into_owned();
        let kdf = FfiKdfParams {
            m_kib: 8192,
            t: 1,
            p: 1,
        };
        let session = crate::create_account_with_kdf(path, "Cafe-etoile".into(), kdf)
            .unwrap()
            .session;
        let vault = session.vaults().unwrap()[0].id.clone();
        let mut draft = session
            .new_item(vault.clone(), FfiItemType::Login, title.into())
            .unwrap();
        for f in draft.sections.iter_mut().flat_map(|s| s.fields.iter_mut()) {
            if f.id == "username" {
                f.value = crate::types::FfiFieldValue::Text {
                    value: "alex@atlas.dev".into(),
                };
            }
        }
        let saved = session.save_item(draft).unwrap();
        let (vault, id) = (parse_id(&vault).unwrap(), parse_id(&saved.id).unwrap());
        let item = session
            .with(|repo| {
                let v = find_vault(repo, vault)?;
                crate::session::find_item(repo, &v, id)
            })
            .unwrap();
        (session, vault, item)
    }

    #[test]
    fn an_item_of_one_account_is_never_saved_into_another() {
        let dir = tempfile::TempDir::new().unwrap();
        let (home, home_vault, home_item) = account(&dir, "home.db", "Home");
        let (work, work_vault, work_item) = account(&dir, "work.db", "Work");
        let server = BridgeServer::new(Arc::new(Quiet), Vec::new(), Vec::new(), String::new());
        let work_slot = "0123456789abcdef0123456789abcdef";
        let entry = |slot: &str, session: &Arc<Session>| FfiBridgeAccount {
            slot: slot.into(),
            session: Some(session.clone()),
            account_name: slot.into(),
            excluded_vault_ids: Vec::new(),
        };
        server
            .set_sessions(vec![entry(work_slot, &work), entry("primary", &home)])
            .unwrap();
        let mut vault = AppVault::new(&server.shared);
        let count = |s: &Arc<Session>| s.item_summaries().unwrap().len();

        // The added account's item, sent to a vault of the primary one (and
        // the other way round): refused, nothing written on either side.
        let mut moved = work_item.clone();
        moved.vault_id = home_vault;
        assert!(matches!(
            vault.save(home_vault, moved),
            Err(BridgeError::App(AppErrorCode::NotFound))
        ));
        let mut moved = home_item.clone();
        moved.vault_id = work_vault;
        assert!(matches!(
            vault.save(work_vault, moved),
            Err(BridgeError::App(AppErrorCode::NotFound))
        ));
        assert_eq!((count(&home), count(&work)), (1, 1));

        // In its own account the same item is saved.
        let mut renamed = work_item;
        renamed.title = "Work, renamed".into();
        vault.save(work_vault, renamed).unwrap();
        assert_eq!(work.item_summaries().unwrap()[0].title, "Work, renamed");
        // The primary account is listed first whatever the order given.
        let vaults = vault.vaults().unwrap();
        assert_eq!(vaults[0].id, home_vault);
        assert_eq!(vaults[1].id, work_vault);
    }
}
