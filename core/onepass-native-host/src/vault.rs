//! Vault access of the development host over a real `Repository`.
//!
//! `RepoVault` serves both sources: `fixture` (a `MemoryStore` built from a
//! JSON file, see `fixture.rs`) and `dev` (the data directory of the
//! development CLI: `device.bin` and `vault.sqlite`). Only the minimal
//! open logic of the CLI is copied here. For the dev source, each read and
//! each write runs under the data directory lock on a repository rebuilt
//! from the `device.bin` on disk merged with what this process saw (per
//! vault, the higher seq wins; the same seq with another hash is a fork and
//! is refused). After each read and each write `device.bin` is rewritten
//! with the merged last seen manifests (only when they changed), so a
//! rollback of `vault.sqlite` stays detectable across connections, and a
//! manifest the CLI or another host process accepted meanwhile is never
//! regressed, as with the CLI.

use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use onepass_bridge::service::{VaultAccess, VaultInfo, VaultStatus};
use onepass_bridge::{AppErrorCode, BridgeError};
use onepass_core::account::Auk;
use onepass_core::crypto::SecretKey;
use onepass_core::model::Item;
use onepass_core::model::usage::SiteUsage;
use onepass_core::repo::{DeviceState, Repository};
use onepass_core::store::{RecordStore, SqliteStore};
use onepass_core::{Error, Id, IntegrityError};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use zeroize::Zeroizing;

use crate::config::HostError;
use crate::log::Log;
use crate::pairings::write_atomic;

const DEVICE_FILE: &str = "device.bin";
const STORE_FILE: &str = "vault.sqlite";
const LOCK_FILE: &str = "lock";

/// Opens the repository on `unlock` when it is not open yet.
pub type Opener<S> = Box<dyn FnMut() -> Option<Repository<S>> + Send>;
/// Persists what a request changed, still under the data directory lock:
/// set with `set_after_save` (after each successful `save`) and with
/// `set_after_read` (after each `items`, even a failed one). The dev source
/// rewrites `device.bin`, the fixture source its cache (writes only). An
/// error makes the request reply `internal`.
pub type Persist<S> = Box<dyn FnMut(&Repository<S>) -> Result<(), HostError> + Send>;
/// Called before each `items` and each `save`, under the data directory
/// lock, with the device state of the current repository: returns the
/// repository to use instead (the dev source rebuilds it on the device
/// state of disk merged with this one). The current repository is dropped
/// first, so its store is closed before the new one opens (two connections
/// of one process to a replaced SQLite file share stale WAL state). An
/// error makes the request reply `internal` and leaves the vault locked:
/// `unlock` opens it again (each request persisted its state before).
///
/// Accepted limits: `status` and `vaults` do not refresh, so their check
/// of known vaults uses the last seen manifests of this process, which may
/// lag `device.bin` (they never write it, so nothing regresses); and a
/// `save` that fails after its refresh does not persist the merged state,
/// the next request does.
pub type Refresh<S> = Box<dyn FnMut(&DeviceState) -> Result<Repository<S>, HostError> + Send>;

/// A `VaultAccess` over a repository, with a simulated lock state.
pub struct RepoVault<S: RecordStore> {
    repo: Option<Repository<S>>,
    locked: bool,
    account: String,
    allow_reprompt: bool,
    /// Vault count shown while locked (the fixture knows it).
    known_vaults: usize,
    /// Display colors that replace the stored vault color.
    colors: HashMap<Id, String>,
    opener: Option<Opener<S>>,
    after_save: Option<Persist<S>>,
    /// Like `after_save`, after each `items` (reads move the last seen
    /// manifests too), even when the read failed.
    after_read: Option<Persist<S>>,
    refresh: Option<Refresh<S>>,
    /// Lock file of the CLI data directory, held during each store access.
    lock_path: Option<PathBuf>,
    /// Journal for the cause of a failed request (the reply only says
    /// `internal`). Error messages of the core carry no data.
    log: Option<Log>,
}

fn bridge_error(e: Error) -> BridgeError {
    BridgeError::App(match e {
        Error::Validation(_) => AppErrorCode::Invalid,
        Error::NotFound => AppErrorCode::NotFound,
        _ => AppErrorCode::Internal,
    })
}

const LOCKED: BridgeError = BridgeError::App(AppErrorCode::Locked);
const INTERNAL: BridgeError = BridgeError::App(AppErrorCode::Internal);

impl<S: RecordStore> RepoVault<S> {
    pub fn new(repo: Option<Repository<S>>, account: &str) -> Self {
        Self {
            repo,
            locked: false,
            account: account.to_owned(),
            allow_reprompt: false,
            known_vaults: 0,
            colors: HashMap::new(),
            opener: None,
            after_save: None,
            after_read: None,
            refresh: None,
            lock_path: None,
            log: None,
        }
    }

    /// Start locked: `status` reports locked until `unlock`.
    pub fn set_repo(&mut self, repo: Repository<S>) {
        self.repo = Some(repo);
    }

    pub fn set_locked(&mut self, locked: bool) {
        self.locked = locked;
    }

    /// Answer of `approve_reprompt` (the user's confirmation, simulated).
    pub fn set_allow_reprompt(&mut self, allow: bool) {
        self.allow_reprompt = allow;
    }

    pub fn set_known_vaults(&mut self, n: usize) {
        self.known_vaults = n;
    }

    pub fn set_color(&mut self, vault: Id, color: String) {
        self.colors.insert(vault, color);
    }

    pub fn set_opener(&mut self, opener: Opener<S>) {
        self.opener = Some(opener);
    }

    pub fn set_after_save(&mut self, f: Persist<S>) {
        self.after_save = Some(f);
    }

    pub fn set_after_read(&mut self, f: Persist<S>) {
        self.after_read = Some(f);
    }

    pub fn set_refresh(&mut self, f: Refresh<S>) {
        self.refresh = Some(f);
    }

    /// Replace the repository through the `refresh` hook, if any. The
    /// caller holds the data directory lock.
    fn refresh_repo(&mut self) -> Result<(), BridgeError> {
        if self.refresh.is_none() {
            return Ok(());
        }
        let Some(old) = self.repo.take() else {
            return Ok(());
        };
        let seen = old.device_state().clone();
        drop(old);
        let fresh = match self.refresh.as_mut() {
            Some(f) => f(&seen),
            None => return Ok(()),
        };
        match fresh {
            Ok(repo) => {
                self.repo = Some(repo);
                Ok(())
            }
            Err(e) => Err(self.fail("vault refresh", &e, INTERNAL)),
        }
    }

    fn read_items(&mut self) -> onepass_bridge::Result<Vec<(VaultInfo, Item)>> {
        let repo = self.repo.as_mut().ok_or(LOCKED)?;
        let read = repo.vaults().and_then(|vaults| {
            let mut infos = Vec::new();
            for v in &vaults {
                infos.push(repo.items(v)?);
            }
            Ok((vaults, infos))
        });
        let (vaults, infos) = read.map_err(|e| self.core_fail("vault read", e))?;
        let mut out = Vec::new();
        for (v, items) in vaults.iter().zip(infos) {
            let info = self.info(v);
            out.extend(items.into_iter().map(|i| (info.clone(), i)));
        }
        Ok(out)
    }

    pub fn set_log(&mut self, log: Log) {
        self.log = Some(log);
    }

    /// Journal that `what` failed with `cause`, then return `err`.
    fn fail(&self, what: &str, cause: &dyn std::fmt::Display, err: BridgeError) -> BridgeError {
        if let Some(log) = &self.log {
            log.line(&format!("{what} failed: {cause}"));
        }
        err
    }

    /// Like `bridge_error`, journaling the cause.
    fn core_fail(&self, what: &str, e: Error) -> BridgeError {
        let msg = e.to_string();
        self.fail(what, &msg, bridge_error(e))
    }

    /// Run the after-save hook (device state of the dev source).
    fn persist_after_save(&mut self) -> Result<(), BridgeError> {
        let saved = match (self.after_save.as_mut(), self.repo.as_ref()) {
            (Some(f), Some(repo)) => f(repo),
            _ => Ok(()),
        };
        saved.map_err(|e| self.fail("device state save", &e, INTERNAL))
    }

    pub fn set_lock_path(&mut self, path: PathBuf) {
        self.lock_path = Some(path);
    }

    fn is_locked(&self) -> bool {
        self.locked || self.repo.is_none()
    }

    /// Exclusive lock of the CLI data directory, released on drop.
    fn guard(&self) -> Result<Option<fs::File>, BridgeError> {
        let Some(path) = &self.lock_path else {
            return Ok(None);
        };
        let f = lock_file(path).map_err(|_| BridgeError::App(AppErrorCode::Internal))?;
        Ok(Some(f))
    }

    fn info(&self, v: &onepass_core::vault::Vault) -> VaultInfo {
        VaultInfo {
            id: v.id,
            name: v.meta.name.clone(),
            color: Some(
                self.colors
                    .get(&v.id)
                    .cloned()
                    .unwrap_or_else(|| v.meta.color.clone()),
            ),
        }
    }
}

impl<S: RecordStore> VaultAccess for RepoVault<S> {
    fn status(&self) -> VaultStatus {
        let vaults = match (&self.repo, self.is_locked()) {
            (Some(repo), false) => {
                let _g = self.guard().ok().flatten();
                repo.vaults().map(|v| v.len()).unwrap_or(0)
            }
            _ => self.known_vaults,
        };
        VaultStatus {
            locked: self.is_locked(),
            account: self.account.clone(),
            vaults,
        }
    }

    fn unlock(&mut self) -> onepass_bridge::Result<bool> {
        if self.repo.is_none()
            && let Some(open) = self.opener.as_mut()
        {
            self.repo = open();
        }
        if self.repo.is_some() {
            self.locked = false;
        }
        Ok(!self.is_locked())
    }

    fn vaults(&self) -> onepass_bridge::Result<Vec<VaultInfo>> {
        let repo = match (&self.repo, self.locked) {
            (Some(r), false) => r,
            _ => return Err(LOCKED),
        };
        let _g = self.guard()?;
        let vaults = repo.vaults().map_err(bridge_error)?;
        Ok(vaults.iter().map(|v| self.info(v)).collect())
    }

    fn items(&mut self) -> onepass_bridge::Result<Vec<(VaultInfo, Item)>> {
        if self.is_locked() {
            return Err(LOCKED);
        }
        let _g = self.guard()?;
        self.refresh_repo()?;
        let result = self.read_items();
        // Persisted whatever the result, as the CLI does: a vault read
        // before a failure still moved its last seen manifest.
        let saved = match (self.after_read.as_mut(), self.repo.as_ref()) {
            (Some(f), Some(repo)) => f(repo),
            _ => Ok(()),
        };
        let out = result?;
        saved.map_err(|e| self.fail("device state save", &e, INTERNAL))?;
        Ok(out)
    }

    fn save(&mut self, vault_id: Id, item: Item) -> onepass_bridge::Result<()> {
        if self.is_locked() {
            return Err(LOCKED);
        }
        let _g = self.guard()?;
        self.refresh_repo()?;
        let repo = self.repo.as_mut().ok_or(LOCKED)?;
        let written = repo.vaults().and_then(|vaults| {
            let Some(vault) = vaults.iter().find(|v| v.id == vault_id) else {
                return Ok(false);
            };
            let mut item = item;
            item.vault_id = vault_id;
            repo.save_item(vault, item)?;
            Ok(true)
        });
        match written {
            Ok(true) => {}
            Ok(false) => return Err(BridgeError::App(AppErrorCode::NotFound)),
            Err(e) => return Err(self.core_fail("vault write", e)),
        }
        self.persist_after_save()
    }

    fn approve_reprompt(&mut self, _item_id: Id) -> bool {
        self.allow_reprompt
    }

    fn record_usage(
        &mut self,
        vault_id: Id,
        item_id: Id,
        u: SiteUsage,
        now: OffsetDateTime,
        force: bool,
    ) -> onepass_bridge::Result<bool> {
        if self.is_locked() {
            return Err(LOCKED);
        }
        let _g = self.guard()?;
        self.refresh_repo()?;
        let repo = self.repo.as_mut().ok_or(LOCKED)?;
        let written = repo.vaults().and_then(|vaults| {
            let Some(vault) = vaults.iter().find(|v| v.id == vault_id) else {
                return Err(Error::NotFound);
            };
            repo.record_usage(vault, item_id, u, now, force)
        });
        let written = match written {
            Ok(w) => w,
            Err(Error::NotFound) => return Err(BridgeError::App(AppErrorCode::NotFound)),
            Err(e) => return Err(self.core_fail("usage write", e)),
        };
        // Persisted even without a write: the read may have moved a last
        // seen manifest.
        self.persist_after_save()?;
        Ok(written)
    }

    fn forget_site_usage(&mut self, site: &str) -> onepass_bridge::Result<usize> {
        if self.is_locked() {
            return Err(LOCKED);
        }
        let _g = self.guard()?;
        self.refresh_repo()?;
        let repo = self.repo.as_mut().ok_or(LOCKED)?;
        let rewritten = match repo.forget_site_usage(site) {
            Ok(n) => n,
            Err(e) => {
                // Best effort: other vaults may have been rewritten before
                // the failure, so the device state is still persisted.
                let _ = self.persist_after_save();
                return Err(self.core_fail("usage forget", e));
            }
        };
        self.persist_after_save()?;
        Ok(rewritten)
    }
}

/// The `dev` source: the data directory of the development CLI.
pub type DevVault = RepoVault<SqliteStore>;

/// What `device.bin` holds (postcard), as written by the CLI: the Secret
/// Key, then the device state as the byte string of `DeviceState::encode`.
#[derive(Deserialize)]
struct DeviceFile {
    secret_key: Zeroizing<String>,
    #[serde(with = "onepass_core::format::device_state_bytes")]
    state: DeviceState,
}

/// `device.bin` before the versioned state: the version 1 state inline.
/// Read only, migrated with `epoch = 0`; the next write uses the current
/// layout.
#[derive(Deserialize)]
struct LegacyDeviceFile {
    secret_key: Zeroizing<String>,
    #[serde(deserialize_with = "onepass_core::format::device_state_v1_inline::deserialize")]
    state: DeviceState,
}

/// `device.bin` as the CLI encodes it (borrowed fields, same layout).
#[derive(Serialize)]
struct DeviceRef<'a> {
    secret_key: &'a str,
    #[serde(with = "onepass_core::format::device_state_bytes")]
    state: &'a DeviceState,
}

/// Decode `device.bin`: the current layout (whole buffer), else the legacy
/// one.
fn decode_device(bytes: &[u8]) -> Result<DeviceFile, HostError> {
    if let Ok((file, [])) = postcard::take_from_bytes::<DeviceFile>(bytes) {
        return Ok(file);
    }
    match postcard::take_from_bytes::<LegacyDeviceFile>(bytes) {
        Ok((old, [])) => Ok(DeviceFile {
            secret_key: old.secret_key,
            state: old.state,
        }),
        _ => Err(HostError::new("device.bin is unreadable")),
    }
}

fn encode_device(secret_key: &str, state: &DeviceState) -> Result<Zeroizing<Vec<u8>>, HostError> {
    postcard::to_allocvec(&DeviceRef { secret_key, state })
        .map(Zeroizing::new)
        .map_err(|_| HostError::new("cannot encode device.bin"))
}

/// Merge two device states. The pinned account: the one of `base` (of
/// `other` when `base` pinned none) with its KDF floor raised to the floor
/// of `other`; pins of two different accounts (id or identity key) are
/// refused with `WrongContext`, like a fork. Per vault, the last seen
/// manifest with the higher seq. At the same seq the entry of `base`
/// stays; a different hash there means two histories of the vault (a
/// fork): refused with `ManifestRollback`, as the core refuses it, rather
/// than choosing one. The restore epoch: the larger of the two.
pub fn merge_device(base: &DeviceState, other: &DeviceState) -> Result<DeviceState, Error> {
    let mut out = base.clone();
    match (&mut out.pinned, &other.pinned) {
        (Some(mine), Some(theirs)) => {
            if mine.account_id != theirs.account_id || mine.identity_pub != theirs.identity_pub {
                return Err(IntegrityError::WrongContext.into());
            }
            mine.raise_floor(&theirs.kdf_floor);
        }
        (None, Some(theirs)) => out.pinned = Some(theirs.clone()),
        _ => {}
    }
    out.epoch = out.epoch.max(other.epoch);
    for (id, seen) in &other.last_seen {
        match out.last_seen.get(id) {
            Some(kept) if kept.seq > seen.seq => {}
            Some(kept) if kept.seq == seen.seq => {
                if kept.hash != seen.hash {
                    return Err(IntegrityError::ManifestRollback.into());
                }
            }
            _ => {
                out.last_seen.insert(*id, seen.clone());
            }
        }
    }
    Ok(out)
}

fn read_device(path: &Path) -> Result<(Zeroizing<Vec<u8>>, DeviceFile), HostError> {
    let bytes = Zeroizing::new(
        fs::read(path).map_err(|e| HostError::new(format!("device.bin: {}", e.kind())))?,
    );
    let file = decode_device(&bytes)?;
    Ok((bytes, file))
}

/// Rewrite `device.bin` with `state` merged into the state on disk
/// (`merge_device`, the pinned account of `state` first), keeping its
/// Secret Key unchanged, as the CLI does after each request: atomically,
/// 0600, file and directory synced, and only when the bytes change (a
/// legacy file is rewritten in the current layout). So a
/// manifest another process accepted meanwhile is never regressed. The
/// caller holds the data directory lock.
pub fn persist_device(dir: &Path, state: &DeviceState) -> Result<(), HostError> {
    let path = dir.join(DEVICE_FILE);
    let (bytes, file) = read_device(&path)?;
    let merged =
        merge_device(state, &file.state).map_err(|e| HostError::new(format!("device.bin: {e}")))?;
    let new = encode_device(&file.secret_key, &merged)?;
    if *new == *bytes {
        return Ok(());
    }
    write_atomic(&path, &new).map_err(|e| HostError::new(format!("device.bin: {}", e.kind())))
}

/// Open `path` (0600) and take its exclusive lock, released on drop.
pub fn lock_file(path: &Path) -> std::io::Result<fs::File> {
    let f = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path)?;
    f.lock()?;
    Ok(f)
}

/// The password of the dev source: `ONEPASS_PASSWORD`, only when
/// `ONEPASS_DEV_ALLOW_ENV_PASSWORD` is `1` in a debug build, as the CLI
/// does. A release build never reads it.
pub fn env_password() -> Option<Zeroizing<String>> {
    let switch = std::env::var("ONEPASS_DEV_ALLOW_ENV_PASSWORD").ok();
    if env_password_allowed(cfg!(debug_assertions), switch.as_deref()) != Ok(true) {
        return None;
    }
    std::env::var("ONEPASS_PASSWORD").ok().map(Zeroizing::new)
}

/// Whether the environment password switch is on: `Ok(true)` for `1` in a
/// debug build, `Err` for `1` in a release build (refused), else `Ok(false)`.
pub fn env_password_allowed(debug: bool, var: Option<&str>) -> Result<bool, &'static str> {
    match var {
        Some("1") if debug => Ok(true),
        Some("1") => Err("ONEPASS_DEV_ALLOW_ENV_PASSWORD is refused in a release build"),
        _ => Ok(false),
    }
}

/// Unlock the CLI account of `dir` with `password`, holding its lock. Also
/// returns the Account Unlock Key, for `reopen_dev`.
pub fn open_dev(dir: &Path, password: &str) -> Result<(Repository<SqliteStore>, Auk), HostError> {
    let device = dir.join(DEVICE_FILE);
    let store_path = dir.join(STORE_FILE);
    if !device.is_file() || !store_path.is_file() {
        return Err(HostError::new("no dev account in the vault directory"));
    }
    let _lock = lock_file(&dir.join(LOCK_FILE))
        .map_err(|e| HostError::new(format!("cannot lock the vault directory: {}", e.kind())))?;
    let (_, file) = read_device(&device)?;
    let key = SecretKey::parse(&file.secret_key)
        .map_err(|_| HostError::new("device.bin holds an invalid key"))?;
    let store = SqliteStore::open(&store_path)
        .map_err(|_| HostError::new("cannot open the vault store"))?;
    Repository::unlock_exporting_auk(store, password, &key, file.state)
        .map_err(|e| HostError::new(format!("cannot unlock the dev vault: {e}")))
}

/// Rebuild the repository of `dir` with `auk`, on the device state of disk
/// merged with `seen` (what this process accepted so far): what another
/// process accepted meanwhile is taken into account, and nothing this
/// process accepted is forgotten. The caller holds the data directory lock.
pub fn reopen_dev(
    dir: &Path,
    auk: &Auk,
    seen: &DeviceState,
) -> Result<Repository<SqliteStore>, HostError> {
    let (_, file) = read_device(&dir.join(DEVICE_FILE))?;
    let merged =
        merge_device(&file.state, seen).map_err(|e| HostError::new(format!("device.bin: {e}")))?;
    let store = SqliteStore::open(&dir.join(STORE_FILE))
        .map_err(|_| HostError::new("cannot open the vault store"))?;
    Repository::unlock_with_auk(store, auk, merged)
        .map_err(|e| HostError::new(format!("cannot reopen the dev vault: {e}")))
}

/// Build the `dev` source. With `unlocked`, try the environment password
/// now; otherwise (or if that fails) stay locked until `unlock`.
pub fn load_dev(dir: PathBuf, unlocked: bool, log: &crate::log::Log) -> DevVault {
    // The Account Unlock Key of the open repository, to rebuild it before
    // each request without the password (and without the KDF).
    let auk: Arc<Mutex<Option<Auk>>> = Arc::default();
    let try_open = {
        let dir = dir.clone();
        let auk = auk.clone();
        move || -> Option<Repository<SqliteStore>> {
            let password = env_password()?;
            let (repo, key) = open_dev(&dir, &password).ok()?;
            *auk.lock().ok()? = Some(key);
            Some(repo)
        }
    };
    let repo = if unlocked {
        match env_password() {
            Some(p) => match open_dev(&dir, &p) {
                Ok((r, key)) => {
                    if let Ok(mut slot) = auk.lock() {
                        *slot = Some(key);
                    }
                    Some(r)
                }
                Err(e) => {
                    log.line(&format!("dev vault stays locked: {e}"));
                    None
                }
            },
            None => {
                let switch = std::env::var("ONEPASS_DEV_ALLOW_ENV_PASSWORD").ok();
                match env_password_allowed(cfg!(debug_assertions), switch.as_deref()) {
                    Err(refused) => log.line(&format!("dev vault stays locked: {refused}")),
                    Ok(_) => log.line("dev vault stays locked: no environment password"),
                }
                None
            }
        }
    } else {
        None
    };
    let mut v = RepoVault::new(repo, "onepass-dev");
    v.set_opener(Box::new(try_open));
    let device_dir = dir.clone();
    v.set_after_save(Box::new(move |repo| {
        persist_device(&device_dir, repo.device_state())
    }));
    let device_dir = dir.clone();
    v.set_after_read(Box::new(move |repo| {
        persist_device(&device_dir, repo.device_state())
    }));
    let device_dir = dir.clone();
    v.set_refresh(Box::new(move |seen| {
        let slot = auk
            .lock()
            .map_err(|_| HostError::new("account key unavailable"))?;
        let key = slot
            .as_ref()
            .ok_or_else(|| HostError::new("account key unavailable"))?;
        reopen_dev(&device_dir, key, seen)
    }));
    v.set_lock_path(dir.join(LOCK_FILE));
    v.set_log(log.clone());
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use onepass_core::manifest::SeenManifest;

    fn state(entries: &[(Id, u64, u8)]) -> DeviceState {
        let mut s = DeviceState::default();
        for (id, seq, h) in entries {
            s.last_seen.insert(
                *id,
                SeenManifest {
                    seq: *seq,
                    hash: [*h; 32],
                },
            );
        }
        s
    }

    #[test]
    fn merge_keeps_the_higher_seq_per_vault() {
        let (a, b, c) = (Id::new(), Id::new(), Id::new());
        let disk = state(&[(a, 5, 1), (b, 2, 2)]);
        let mem = state(&[(a, 3, 9), (b, 4, 4), (c, 1, 7)]);
        let merged = merge_device(&disk, &mem).unwrap();
        assert_eq!(merged, state(&[(a, 5, 1), (b, 4, 4), (c, 1, 7)]));
        assert_eq!(merge_device(&mem, &disk).unwrap(), merged);
    }

    #[test]
    fn merge_keeps_the_larger_epoch() {
        let old = DeviceState {
            epoch: 2,
            ..DeviceState::default()
        };
        let new = DeviceState {
            epoch: 5,
            ..DeviceState::default()
        };
        assert_eq!(merge_device(&old, &new).unwrap().epoch, 5);
        assert_eq!(merge_device(&new, &old).unwrap().epoch, 5);
    }

    #[test]
    fn merge_refuses_a_fork_at_equal_seq() {
        let a = Id::new();
        assert_eq!(
            merge_device(&state(&[(a, 3, 1)]), &state(&[(a, 3, 1)])).unwrap(),
            state(&[(a, 3, 1)])
        );
        assert!(matches!(
            merge_device(&state(&[(a, 3, 1)]), &state(&[(a, 3, 2)])),
            Err(Error::Integrity(IntegrityError::ManifestRollback))
        ));
    }

    /// The device state pinned by a fresh account (dev KDF floor).
    fn pinned_state() -> DeviceState {
        use onepass_core::crypto::{DEV_KDF_FLOOR, KdfParams};
        use onepass_core::store::MemoryStore;
        let mut kdf = KdfParams::new_default().unwrap();
        (kdf.m_kib, kdf.t, kdf.p) = DEV_KDF_FLOOR;
        let (repo, _) = Repository::create_account(MemoryStore::default(), "pw", kdf).unwrap();
        let state = repo.device_state().clone();
        assert!(state.pinned.is_some());
        state
    }

    #[test]
    fn merge_raises_the_pin_floor_and_refuses_another_account() {
        let mine = pinned_state();
        let mut stronger = mine.clone();
        stronger.pinned.as_mut().unwrap().kdf_floor.t += 1;
        let merged = merge_device(&mine, &stronger).unwrap();
        assert_eq!(merged.pinned, stronger.pinned);
        assert_eq!(
            merge_device(&DeviceState::default(), &mine).unwrap().pinned,
            mine.pinned
        );

        let other = pinned_state();
        assert!(matches!(
            merge_device(&mine, &other),
            Err(Error::Integrity(IntegrityError::WrongContext))
        ));
    }

    #[test]
    fn env_password_switch_is_debug_only() {
        assert_eq!(env_password_allowed(true, Some("1")), Ok(true));
        assert_eq!(env_password_allowed(true, None), Ok(false));
        assert_eq!(env_password_allowed(false, None), Ok(false));
        assert_eq!(env_password_allowed(false, Some("0")), Ok(false));
        assert_eq!(
            env_password_allowed(false, Some("1")),
            Err("ONEPASS_DEV_ALLOW_ENV_PASSWORD is refused in a release build")
        );
    }

    /// A `device.bin` written before the versioned state: Secret Key "sk",
    /// then the version 1 state inline,
    /// `{ pinned: None, last_seen: { [1; 16]: (7, [0xab; 32]) } }`.
    const LEGACY_DEVICE_BIN_HEX: &str = concat!(
        "02736b",
        "00",
        "01",
        "01010101010101010101010101010101",
        "07",
        "abababababababababababababababababababababababababababababababab",
    );

    fn from_hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn fixed_state() -> DeviceState {
        let mut state = DeviceState::default();
        state.last_seen.insert(
            onepass_core::Id([1; 16]),
            onepass_core::manifest::SeenManifest {
                seq: 7,
                hash: [0xab; 32],
            },
        );
        state
    }

    #[test]
    fn legacy_device_bin_reads() {
        let mut bytes = from_hex(LEGACY_DEVICE_BIN_HEX);
        let file = decode_device(&bytes).unwrap();
        assert_eq!(file.secret_key.as_str(), "sk");
        assert_eq!(file.state, fixed_state());
        let new = encode_device(&file.secret_key, &file.state).unwrap();
        assert_eq!(&new[..3], b"\x02sk");
        assert_eq!(&new[4..8], b"ODS\x02");
        assert_eq!(decode_device(&new).unwrap().state, file.state);
        bytes.push(0);
        assert!(decode_device(&bytes).is_err());
    }

    #[test]
    fn device_bin_roundtrips() {
        let mut state = fixed_state();
        state.epoch = 9;
        let mut bytes = encode_device("sk", &state).unwrap();
        let file = decode_device(&bytes).unwrap();
        assert_eq!(file.secret_key.as_str(), "sk");
        assert_eq!(file.state, state);
        bytes.push(0);
        assert!(decode_device(&bytes).is_err());
    }

    /// `persist_device` migrates a legacy file: same Secret Key, new layout.
    #[test]
    fn persist_device_rewrites_legacy_layout() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join(DEVICE_FILE),
            from_hex(LEGACY_DEVICE_BIN_HEX),
        )
        .unwrap();
        let mut state = fixed_state();
        state.epoch = 1;
        persist_device(dir.path(), &state).unwrap();
        let file = decode_device(&fs::read(dir.path().join(DEVICE_FILE)).unwrap()).unwrap();
        assert_eq!(file.secret_key.as_str(), "sk");
        assert_eq!(file.state, state);
    }

    /// Spec 1 success criterion: `plan_fill` over a 500-item vault under
    /// 20 ms, end to end through the bridge service and a real repository
    /// (every item decrypted and checked against its manifest, as the host
    /// serves it). Release build only, debug crypto is far slower:
    /// `cargo test --release -p onepass-native-host plan_fill_500_items`.
    #[test]
    fn plan_fill_500_items_under_20ms() {
        use onepass_bridge::audit::MemoryAudit;
        use onepass_bridge::service::Service;
        use onepass_core::crypto::KdfParams;
        use onepass_core::model::templates::new_item;
        use onepass_core::model::{FieldValue, ItemType, ItemUrl, MatchRule};
        use onepass_core::store::MemoryStore;
        use std::time::Instant;

        if cfg!(debug_assertions) {
            eprintln!("plan_fill_500_items_under_20ms: release build only, skipped");
            return;
        }
        let (mut repo, _) =
            Repository::create_account(MemoryStore::new(), "pw", KdfParams::new_default().unwrap())
                .unwrap();
        let v = repo.vaults().unwrap().remove(0);
        for i in 0..500u32 {
            let item = match i % 25 {
                // 40 cards and 20 identities, 440 logins of which 20 on the page's site.
                0 | 1 => {
                    let mut card = new_item(ItemType::CreditCard, v.id, &format!("Card {i}"));
                    card.field_mut("cardholder").unwrap().value =
                        FieldValue::Text(format!("Holder {i}"));
                    card.field_mut("number").unwrap().value =
                        FieldValue::Concealed("4111111111111111".to_owned().into());
                    card.field_mut("expiry").unwrap().value = FieldValue::MonthYear {
                        year: 2030,
                        month: 4,
                    };
                    card
                }
                2 => {
                    let mut id = new_item(ItemType::Identity, v.id, &format!("Identity {i}"));
                    id.field_mut("first_name").unwrap().value = FieldValue::Text(format!("N{i}"));
                    id
                }
                n => {
                    let mut item = new_item(ItemType::Login, v.id, &format!("Login {i}"));
                    item.field_mut("username").unwrap().value =
                        FieldValue::Text(format!("user{i}@example.com"));
                    item.field_mut("password").unwrap().value =
                        FieldValue::Password(format!("pw-{i}-Xy9!").into());
                    let host = if n == 3 {
                        "shop.test".to_owned()
                    } else {
                        format!("site{i}.test")
                    };
                    item.urls.push(ItemUrl {
                        label: "site web".into(),
                        url: format!("https://{host}/login"),
                        rule: MatchRule::Domain,
                        primary: true,
                    });
                    item
                }
            };
            repo.save_item(&v, item).unwrap();
        }
        assert_eq!(repo.items(&v).unwrap().len(), 500);
        let mut access = RepoVault::new(Some(repo), "a");
        assert_eq!(access.items().unwrap().len(), 500);
        let mut svc = Service::new(access, Box::new(MemoryAudit::new()));
        let field = |r: &str, role: &str| {
            serde_json::json!({"field_ref":r,"role":role,"confidence":0.9,"visible":true,
                               "prefilled":"empty"})
        };
        let form = |fields: Vec<serde_json::Value>, class: &str| {
            serde_json::json!({"form_ref":"f","intent_hints":{"kind":null,"signup_words":false,
                "reset_words":false,"checkout_words":false,"ignore":false},"step_index":null,
                "fields":fields,"buttons":[{"button_ref":"b","class":class}]})
        };
        let login = form(
            vec![field("u", "username"), field("p", "current_password")],
            "submit",
        );
        let checkout = form(
            [
                "cc_name",
                "cc_number",
                "cc_exp",
                "cc_csc",
                "given_name",
                "family_name",
                "email",
                "address_line1",
                "city",
                "postal_code",
                "country",
            ]
            .iter()
            .enumerate()
            .map(|(i, r)| field(&format!("x{i}"), r))
            .collect(),
            "pay",
        );
        let o = "https://shop.test";
        let mut next = 0u64;
        for (name, f, intent) in [
            ("login", login, "login"),
            ("checkout", checkout, "checkout"),
        ] {
            let mut times: Vec<u128> = (0..41)
                .map(|_| {
                    // Each request id once (the service refuses a replay).
                    next += 1;
                    let req = serde_json::json!({"id":next,"op":"plan_fill","ctx":"menu",
                        "origin":o,"context":{"origin":o,"top_origin":o,"frame_kind":"top",
                        "forms":[f.clone()],"typed_username_hash":null}});
                    let bytes = serde_json::to_vec(&req).unwrap();
                    let t = Instant::now();
                    let out = svc.handle(&bytes, 1_790_000_000);
                    let us = t.elapsed().as_micros();
                    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
                    assert_eq!(v["ok"]["plan"]["intent"], intent, "{v}");
                    us
                })
                .collect();
            times.sort_unstable();
            let median = times[times.len() / 2];
            println!(
                "plan_fill 500 items, {name}: median {median} us, max {} us",
                times[40]
            );
            // The spec's budget (about 5 ms measured on an M-series Mac, 2026-10-29).
            assert!(median < 20_000, "{name}: median {median} us");
        }
    }
}
