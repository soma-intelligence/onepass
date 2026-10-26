//! Vault access of the development host over a real `Repository`.
//!
//! `RepoVault` serves both sources: `fixture` (a `MemoryStore` built from a
//! JSON file, see `fixture.rs`) and `dev` (the data directory of the
//! development CLI: `device.bin` and `vault.sqlite`). Only the minimal
//! open logic of the CLI is copied here; `device.bin` is read, never
//! written (the CLI keeps a staler last seen manifest, which it accepts).

use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use onepass_bridge::service::{VaultAccess, VaultInfo, VaultStatus};
use onepass_bridge::{AppErrorCode, BridgeError};
use onepass_core::crypto::SecretKey;
use onepass_core::model::Item;
use onepass_core::repo::{DeviceState, Repository};
use onepass_core::store::{RecordStore, SqliteStore};
use onepass_core::{Error, Id};
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::config::HostError;

const DEVICE_FILE: &str = "device.bin";
const STORE_FILE: &str = "vault.sqlite";
const LOCK_FILE: &str = "lock";

/// Opens the repository on `unlock` when it is not open yet.
pub type Opener<S> = Box<dyn FnMut() -> Option<Repository<S>> + Send>;
/// Called after each successful `save` (the fixture source persists its
/// store there).
pub type AfterSave<S> = Box<dyn FnMut(&Repository<S>) + Send>;

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

    fn save(&mut self, vault_id: Id, item: Item) -> onepass_bridge::Result<()> {
        if self.is_locked() {
            return Err(LOCKED);
        }
        let _g = self.guard()?;
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
            f(repo);
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

fn lock_file(path: &Path) -> std::io::Result<fs::File> {
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

/// Unlock the CLI account of `dir` with `password`, holding its lock.
pub fn open_dev(dir: &Path, password: &str) -> Result<Repository<SqliteStore>, HostError> {
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
    Repository::unlock(store, password, &key, file.state)
        .map_err(|e| HostError::new(format!("cannot unlock the dev vault: {e}")))
}

/// Build the `dev` source. With `unlocked`, try the environment password
/// now; otherwise (or if that fails) stay locked until `unlock`.
pub fn load_dev(dir: PathBuf, unlocked: bool, log: &crate::log::Log) -> DevVault {
    let try_open = {
        let dir = dir.clone();
        move || -> Option<Repository<SqliteStore>> {
            let password = env_password()?;
            open_dev(&dir, &password).ok()
        }
    };
    let repo = if unlocked {
        match env_password() {
            Some(p) => match open_dev(&dir, &p) {
                Ok(r) => Some(r),
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
    v.set_lock_path(dir.join(LOCK_FILE));
    v
}
