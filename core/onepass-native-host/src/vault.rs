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
use onepass_core::repo::{DeviceState, Repository};
use onepass_core::store::{RecordStore, SqliteStore};
use onepass_core::{Error, Id, IntegrityError};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::config::HostError;
use crate::pairings::write_atomic;

const DEVICE_FILE: &str = "device.bin";
const STORE_FILE: &str = "vault.sqlite";
const LOCK_FILE: &str = "lock";

/// Opens the repository on `unlock` when it is not open yet.
pub type Opener<S> = Box<dyn FnMut() -> Option<Repository<S>> + Send>;
/// Called after each successful `save`, still under the data directory
/// lock (the dev source rewrites `device.bin`, the fixture source its
/// cache). An error makes the `save` reply `internal`.
pub type AfterSave<S> = Box<dyn FnMut(&Repository<S>) -> Result<(), HostError> + Send>;
/// Called before each read and each write, under the data directory lock:
/// returns the repository to use instead of the current one (the dev
/// source rebuilds it on the device state of disk merged with its own).
/// An error makes the request reply `internal` and keeps the current one.
pub type Refresh<S> = Box<dyn FnMut(&Repository<S>) -> Result<Repository<S>, HostError> + Send>;

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
    after_save: Option<AfterSave<S>>,
    /// Like `after_save`, after each `items` (reads move the last seen
    /// manifests too), even when the read failed.
    after_read: Option<AfterSave<S>>,
    refresh: Option<Refresh<S>>,
    /// Lock file of the CLI data directory, held during each store access.
    lock_path: Option<PathBuf>,
}

fn bridge_error(e: Error) -> BridgeError {
    BridgeError::App(match e {
        Error::Validation(_) => AppErrorCode::Invalid,
        Error::NotFound => AppErrorCode::NotFound,
        _ => AppErrorCode::Internal,
    })
}

const LOCKED: BridgeError = BridgeError::App(AppErrorCode::Locked);

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

    pub fn set_after_save(&mut self, f: AfterSave<S>) {
        self.after_save = Some(f);
    }

    pub fn set_after_read(&mut self, f: AfterSave<S>) {
        self.after_read = Some(f);
    }

    pub fn set_refresh(&mut self, f: Refresh<S>) {
        self.refresh = Some(f);
    }

    /// Replace the repository through the `refresh` hook, if any. The
    /// caller holds the data directory lock.
    fn refresh_repo(&mut self) -> Result<(), BridgeError> {
        if let (Some(f), Some(repo)) = (self.refresh.as_mut(), self.repo.as_ref()) {
            let fresh = f(repo).map_err(|_| BridgeError::App(AppErrorCode::Internal))?;
            self.repo = Some(fresh);
        }
        Ok(())
    }

    fn read_items(&mut self) -> onepass_bridge::Result<Vec<(VaultInfo, Item)>> {
        let repo = self.repo.as_mut().ok_or(LOCKED)?;
        let vaults = repo.vaults().map_err(bridge_error)?;
        let mut out = Vec::new();
        let mut infos = Vec::new();
        for v in &vaults {
            let items = repo.items(v).map_err(bridge_error)?;
            infos.push((v.id, items));
        }
        for (v, (_, items)) in vaults.iter().zip(infos) {
            let info = self.info(v);
            out.extend(items.into_iter().map(|i| (info.clone(), i)));
        }
        Ok(out)
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
            (Some(f), Some(repo)) => f(repo).map_err(|_| BridgeError::App(AppErrorCode::Internal)),
            _ => Ok(()),
        };
        let out = result?;
        saved?;
        Ok(out)
    }

    fn save(&mut self, vault_id: Id, item: Item) -> onepass_bridge::Result<()> {
        if self.is_locked() {
            return Err(LOCKED);
        }
        let _g = self.guard()?;
        self.refresh_repo()?;
        let repo = self.repo.as_mut().ok_or(LOCKED)?;
        let vaults = repo.vaults().map_err(bridge_error)?;
        let vault = vaults
            .iter()
            .find(|v| v.id == vault_id)
            .ok_or(BridgeError::App(AppErrorCode::NotFound))?;
        let mut item = item;
        item.vault_id = vault_id;
        repo.save_item(vault, item).map_err(bridge_error)?;
        if let Some(f) = self.after_save.as_mut() {
            f(repo).map_err(|_| BridgeError::App(AppErrorCode::Internal))?;
        }
        Ok(())
    }

    fn approve_reprompt(&mut self, _item_id: Id) -> bool {
        self.allow_reprompt
    }
}

/// The `dev` source: the data directory of the development CLI.
pub type DevVault = RepoVault<SqliteStore>;

/// What `device.bin` holds (postcard), as written by the CLI.
#[derive(Deserialize)]
struct DeviceFile {
    secret_key: Zeroizing<String>,
    state: DeviceState,
}

/// `device.bin` as the CLI encodes it (borrowed fields, same layout).
#[derive(Serialize)]
struct DeviceRef<'a> {
    secret_key: &'a str,
    state: &'a DeviceState,
}

/// Merge two device states: the pinned account of `base` (of `other` when
/// `base` pinned none), and per vault the last seen manifest with the
/// higher seq. At the same seq the entry of `base` stays; a different hash
/// there means two histories of the vault (a fork): refused with
/// `ManifestRollback`, as the core refuses it, rather than choosing one.
pub fn merge_device(base: &DeviceState, other: &DeviceState) -> Result<DeviceState, Error> {
    let mut out = base.clone();
    if out.pinned.is_none() {
        out.pinned = other.pinned.clone();
    }
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
    let file: DeviceFile =
        postcard::from_bytes(&bytes).map_err(|_| HostError::new("device.bin is unreadable"))?;
    Ok((bytes, file))
}

/// Rewrite `device.bin` with `state` merged into the state on disk
/// (`merge_device`, the pinned account of `state` first), keeping its
/// Secret Key unchanged, as the CLI does after each request: atomically,
/// 0600, file and directory synced, and only when the bytes change. So a
/// manifest another process accepted meanwhile is never regressed. The
/// caller holds the data directory lock.
pub fn persist_device(dir: &Path, state: &DeviceState) -> Result<(), HostError> {
    let path = dir.join(DEVICE_FILE);
    let (bytes, file) = read_device(&path)?;
    let merged =
        merge_device(state, &file.state).map_err(|e| HostError::new(format!("device.bin: {e}")))?;
    let new = Zeroizing::new(
        postcard::to_allocvec(&DeviceRef {
            secret_key: &file.secret_key,
            state: &merged,
        })
        .map_err(|_| HostError::new("cannot encode device.bin"))?,
    );
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
/// `ONEPASS_DEV_ALLOW_ENV_PASSWORD` is `1`, as the CLI does.
pub fn env_password() -> Option<Zeroizing<String>> {
    if std::env::var("ONEPASS_DEV_ALLOW_ENV_PASSWORD").as_deref() != Ok("1") {
        return None;
    }
    std::env::var("ONEPASS_PASSWORD").ok().map(Zeroizing::new)
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
    let bytes = Zeroizing::new(
        fs::read(&device).map_err(|e| HostError::new(format!("device.bin: {}", e.kind())))?,
    );
    let file: DeviceFile =
        postcard::from_bytes(&bytes).map_err(|_| HostError::new("device.bin is unreadable"))?;
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
                log.line("dev vault stays locked: no environment password");
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
    v.set_refresh(Box::new(move |repo| {
        let slot = auk
            .lock()
            .map_err(|_| HostError::new("account key unavailable"))?;
        let key = slot
            .as_ref()
            .ok_or_else(|| HostError::new("account key unavailable"))?;
        reopen_dev(&device_dir, key, repo.device_state())
    }));
    v.set_lock_path(dir.join(LOCK_FILE));
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
}
