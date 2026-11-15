//! The app's state: where the store lives, the sealer of `device.bin`, and
//! the unlocked session if any.

use std::path::PathBuf;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use onepass_ffi::Session;
use zeroize::Zeroizing;

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
    prefs: Mutex<crate::prefs::Prefs>,
    /// Why the last Windows Hello attempt fell back to the password.
    pub hello_dropped: Mutex<Option<crate::hello::Dropped>>,
    /// An export waiting for "Enregistrer quand même" (cloud folder).
    pub pending_export: Mutex<Option<(PathBuf, Zeroizing<Vec<u8>>)>>,
    /// The file read for a restore or an import, until it is done.
    pub pending_import: Mutex<Option<(String, Zeroizing<Vec<u8>>)>>,
    /// Have I Been Pwned ranges fetched this session (breach.rs).
    pub ranges: Arc<crate::breach::RangeCache>,
    /// The sync thread's handle (sync.rs).
    pub sync: crate::sync::SyncEngine,
    /// The pairing in progress on this PC, either side (pairing.rs).
    pub pairing: Mutex<Option<crate::pairing::Pairing>>,
    /// The contact invitation in progress on this PC, either side (contacts.rs).
    pub invite: Mutex<Option<crate::contacts::InviteFlow>>,
}

pub fn now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

impl AppState {
    pub fn new(dir: PathBuf) -> Result<AppState, String> {
        let prefs = Mutex::new(crate::prefs::load(&dir));
        let state = AppState {
            prefs,
            hello_dropped: Mutex::new(None),
            pending_export: Mutex::new(None),
            pending_import: Mutex::new(None),
            ranges: Arc::default(),
            sync: crate::sync::SyncEngine::default(),
            pairing: Mutex::new(None),
            invite: Mutex::new(None),
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

    pub fn data_dir(&self) -> PathBuf {
        self.dir.clone()
    }

    pub fn hello_path(&self) -> PathBuf {
        self.dir.join("hello.bin")
    }

    pub fn prefs(&self) -> crate::prefs::Prefs {
        *self.prefs.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Changes the settings and writes them.
    pub fn update_prefs(&self, f: impl FnOnce(&mut crate::prefs::Prefs)) -> Result<(), String> {
        let mut p = self.prefs.lock().unwrap_or_else(PoisonError::into_inner);
        f(&mut p);
        crate::prefs::save(&self.dir, &p)
    }

    pub fn device_path(&self) -> PathBuf {
        self.dir.join("device.bin")
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
        // Registered under this PC's name and type (a restored device
        // starts as the default "Appareil"), as the Apple apps do at unlock.
        if let Some(s) = self.session()
            && register_if_needed(&s)
        {
            self.sync.changed();
        }
        // Unlocked: a round with the session (rebase, health, home check).
        self.sync.kick();
    }

    /// Drops the keys: every later call needs an unlock.
    pub fn lock(&self) {
        purge_opened();
        self.ranges.clear();
        // An invitation waiting needs the keys: the invitee's resumes at the
        // next unlock (contacts.rs).
        if let Some(f) = self
            .invite
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        {
            f.cancel();
        }
        self.pending_export
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        self.pending_import
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
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

/// Where an attachment is written to be opened by another app. Emptied at
/// lock, at exit, at start (after a crash) and 10 minutes after each open.
pub fn opened_dir() -> PathBuf {
    std::env::temp_dir().join("OnePass-open")
}

pub fn purge_opened() {
    let _ = std::fs::remove_dir_all(opened_dir());
}

/// "fr" when the Windows display language is French, "en" otherwise. A debug
/// build honours ONEPASS_LANG (the end-to-end test runs in French).
pub fn language() -> &'static str {
    if let (true, Ok(l)) = (cfg!(debug_assertions), std::env::var("ONEPASS_LANG")) {
        return if l.starts_with("fr") { "fr" } else { "en" };
    }
    #[cfg(windows)]
    {
        // SAFETY: no argument, returns the LANGID of the user's UI language.
        let id = unsafe { windows_sys::Win32::Globalization::GetUserDefaultUILanguage() };
        // The primary language is the low 10 bits; LANG_FRENCH is 0x0c.
        if id & 0x3ff == 0x0c {
            return "fr";
        }
        "en"
    }
    #[cfg(not(windows))]
    {
        match std::env::var("LANG") {
            Ok(l) if l.starts_with("fr") => "fr",
            _ => "en",
        }
    }
}

/// Registers this device in the signed list when it has no entry yet, or
/// only the default one (`VaultSession.needsRegistration`). True when it
/// wrote.
fn register_if_needed(s: &Session) -> bool {
    use onepass_ffi::{FfiDeviceKind, FfiDeviceMode};
    let needs = match s.this_device_id() {
        None => true,
        Some(_) => s
            .devices()
            .ok()
            .and_then(|d| d.into_iter().find(|d| d.is_this_device))
            .is_some_and(|me| {
                !me.revoked && me.name == "Appareil" && me.kind == FfiDeviceKind::Other
            }),
    };
    needs
        && s.register_this_device(
            crate::commands::device_name(),
            crate::commands::device_kind(),
            FfiDeviceMode::Personal,
        )
        .is_ok()
}
