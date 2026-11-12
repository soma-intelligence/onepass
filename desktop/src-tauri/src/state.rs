//! The app's state: where the store lives, the sealer of `device.bin`, and
//! the unlocked session if any.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use onepass_ffi::Session;

use crate::secrets::{self, DeviceSecrets, Sealer};

/// Minutes without a command before the session locks itself.
pub const AUTO_LOCK_SECS: i64 = 10 * 60;
/// Seconds before a copied secret leaves the clipboard (spec 3.1, 7.3).
pub const CLIPBOARD_CLEAR_SECS: u64 = 90;

pub struct AppState {
    dir: PathBuf,
    pub sealer: Box<dyn Sealer>,
    session: Mutex<Option<Arc<Session>>>,
    last_activity: AtomicI64,
}

pub fn now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

impl AppState {
    pub fn new(dir: PathBuf) -> Result<AppState, String> {
        let state = AppState {
            dir,
            sealer: secrets::sealer(),
            session: Mutex::new(None),
            last_activity: AtomicI64::new(now()),
        };
        // The hedged random source gets this install's seed as early as
        // possible (onepass-ffi `set_device_rng_seed`).
        if let Ok(Some(s)) = state.load_secrets() {
            let _ = onepass_ffi::set_device_rng_seed(s.rng_seed.to_vec());
        }
        Ok(state)
    }

    pub fn db_path(&self) -> String {
        self.dir.join("vault.db").to_string_lossy().into_owned()
    }

    pub fn device_path(&self) -> PathBuf {
        self.dir.join("device.bin")
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn load_secrets(&self) -> Result<Option<DeviceSecrets>, String> {
        secrets::load(self.sealer.as_ref(), &self.device_path())
    }

    pub fn save_secrets(&self, s: &DeviceSecrets) -> Result<(), String> {
        secrets::save(self.sealer.as_ref(), &self.device_path(), s)
    }

    pub fn touch(&self) {
        self.last_activity.store(now(), Ordering::Relaxed);
    }

    pub fn session(&self) -> Option<Arc<Session>> {
        self.session
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    pub fn set_session(&self, s: Arc<Session>) {
        self.touch();
        *self.session.lock().unwrap_or_else(PoisonError::into_inner) = Some(s);
    }

    /// Drops the keys: every later call needs an unlock.
    pub fn lock(&self) {
        if let Some(s) = self
            .session
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        {
            s.lock();
        }
    }

    /// Locks when the last command is older than `AUTO_LOCK_SECS`. True when
    /// it locked an open session.
    pub fn lock_if_idle(&self) -> bool {
        let idle = now() - self.last_activity.load(Ordering::Relaxed);
        if idle >= AUTO_LOCK_SECS && self.session().is_some() {
            self.lock();
            return true;
        }
        false
    }
}
