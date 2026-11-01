//! Where the CLI keeps the account Secret Key: the secret store of the
//! system (macOS login keychain, Secret Service on Linux), never
//! `device.bin` unless the user passed `--insecure-file-secret-key`.
//!
//! One entry per account, `secretkey.<account id>` under the service
//! [`SERVICE`] (the entry name of the apps, spec
//! `docs/superpowers/specs/2026-10-28-cli-secret-key-design.md`).

use std::fmt;
use std::fs;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::PathBuf;
use std::sync::Arc;

use onepass_core::Id;
use zeroize::Zeroizing;

use crate::session::CliError;

/// The service of every entry the CLI writes.
pub const SERVICE: &str = "me.somalabs.onepass.cli";

/// The test switch choosing the secret store: `dir:<directory>` (one file
/// per entry) or `none` (no store). Debug builds only.
pub const DEV_STORE_SWITCH: &str = "ONEPASS_DEV_SECRET_STORE";

/// The entry of an account's Secret Key.
pub fn entry_name(account: Id) -> String {
    format!("secretkey.{account}")
}

/// The entry of the Secret Key a rotation drew and has not committed yet
/// (K6, spec 7.1): next to `entry_name`, never replacing it before the
/// rotation commits.
pub fn pending_entry(account: Id) -> String {
    format!("{}.pending", entry_name(account))
}

/// Why the store did not answer. The message never holds a secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    /// No store is reachable on this machine (no Secret Service on the
    /// session bus, no session bus, unsupported system).
    Unavailable(String),
    /// A store is there but refused or failed (locked keychain, denied
    /// prompt, I/O error).
    Failed(String),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::Unavailable(m) | StoreError::Failed(m) => f.write_str(m),
        }
    }
}

/// A secret store holding text secrets by entry name.
pub trait SecretStore: Send + Sync {
    /// The store's name, for messages ("macOS login keychain").
    fn name(&self) -> &str;
    /// The secret of `entry`, `None` when there is no such entry.
    fn get(&self, entry: &str) -> Result<Option<Zeroizing<String>>, StoreError>;
    /// Create or replace `entry`.
    fn set(&self, entry: &str, secret: &str) -> Result<(), StoreError>;
    /// Remove `entry`; removing a missing entry succeeds.
    fn delete(&self, entry: &str) -> Result<(), StoreError>;
}

/// The store of this process: the system store, or in a debug build the
/// one [`DEV_STORE_SWITCH`] names.
pub fn system() -> Result<Arc<dyn SecretStore>, CliError> {
    select(
        cfg!(debug_assertions),
        std::env::var(DEV_STORE_SWITCH).ok().as_deref(),
    )
}

/// [`system`] with the build kind and the switch value given. A release
/// build refuses the switch instead of ignoring it.
pub fn select(debug: bool, var: Option<&str>) -> Result<Arc<dyn SecretStore>, CliError> {
    let Some(var) = var else {
        return Ok(platform());
    };
    if !debug {
        return Err(CliError::usage(format!(
            "{DEV_STORE_SWITCH} is refused in a release build"
        )));
    }
    if var == "none" {
        return Ok(Arc::new(NoStore::new(
            "no secret store (ONEPASS_DEV_SECRET_STORE=none)",
        )));
    }
    match var.strip_prefix("dir:") {
        Some(dir) if !dir.is_empty() => Ok(Arc::new(DevDirStore {
            dir: PathBuf::from(dir),
        })),
        _ => Err(CliError::usage(format!(
            "{DEV_STORE_SWITCH} must be `dir:<directory>` or `none`"
        ))),
    }
}

#[cfg(target_os = "macos")]
fn platform() -> Arc<dyn SecretStore> {
    Arc::new(macos::LoginKeychain)
}

#[cfg(target_os = "linux")]
fn platform() -> Arc<dyn SecretStore> {
    Arc::new(linux::SecretService)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn platform() -> Arc<dyn SecretStore> {
    Arc::new(NoStore::new("no secret store on this system"))
}

/// No store: every call is [`StoreError::Unavailable`].
pub struct NoStore {
    why: String,
}

impl NoStore {
    pub fn new(why: &str) -> NoStore {
        NoStore {
            why: why.to_owned(),
        }
    }
}

impl SecretStore for NoStore {
    fn name(&self) -> &str {
        "secret store"
    }

    fn get(&self, _: &str) -> Result<Option<Zeroizing<String>>, StoreError> {
        Err(StoreError::Unavailable(self.why.clone()))
    }

    fn set(&self, _: &str, _: &str) -> Result<(), StoreError> {
        Err(StoreError::Unavailable(self.why.clone()))
    }

    fn delete(&self, _: &str) -> Result<(), StoreError> {
        Err(StoreError::Unavailable(self.why.clone()))
    }
}

/// Test store of the end-to-end tests: one file per entry (mode 0600) in a
/// directory of its own, standing in for the system store. Debug builds
/// only ([`select`]).
pub struct DevDirStore {
    dir: PathBuf,
}

impl DevDirStore {
    fn path(&self, entry: &str) -> Result<PathBuf, StoreError> {
        if entry.is_empty() || entry.contains('/') || entry.starts_with('.') {
            return Err(StoreError::Failed("bad entry name".to_owned()));
        }
        Ok(self.dir.join(entry))
    }
}

fn io_failed(e: std::io::Error) -> StoreError {
    StoreError::Failed(format!("i/o error: {}", e.kind()))
}

impl SecretStore for DevDirStore {
    fn name(&self) -> &str {
        "development secret store"
    }

    fn get(&self, entry: &str) -> Result<Option<Zeroizing<String>>, StoreError> {
        match fs::read(self.path(entry)?) {
            Ok(bytes) => String::from_utf8(bytes)
                .map(|s| Some(Zeroizing::new(s)))
                .map_err(|_| StoreError::Failed("entry is not text".to_owned())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(io_failed(e)),
        }
    }

    fn set(&self, entry: &str, secret: &str) -> Result<(), StoreError> {
        let path = self.path(entry)?;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&self.dir)
            .map_err(io_failed)?;
        // Unique temporary name: test processes share the directory.
        let tmp = self.dir.join(format!(
            ".{entry}.{}.{:?}.tmp",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_file(&tmp);
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(io_failed)?;
        f.write_all(secret.as_bytes()).map_err(io_failed)?;
        f.sync_all().map_err(io_failed)?;
        fs::rename(&tmp, path).map_err(io_failed)
    }

    fn delete(&self, entry: &str) -> Result<(), StoreError> {
        match fs::remove_file(self.path(entry)?) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(io_failed(e)),
        }
    }
}

#[cfg(target_os = "macos")]
mod macos {
    //! The macOS login keychain, as generic password items. Not the
    //! data-protection keychain of the apps: it needs the
    //! `keychain-access-groups` entitlement, which a CLI binary cannot hold
    //! (-34018).

    use security_framework::passwords::{
        PasswordOptions, delete_generic_password, generic_password, set_generic_password_options,
    };
    use zeroize::Zeroizing;

    use super::{SERVICE, SecretStore, StoreError};

    const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;
    const ERR_SEC_NOT_AVAILABLE: i32 = -25291;
    const ERR_SEC_NO_SUCH_KEYCHAIN: i32 = -25294;
    const ERR_SEC_INTERACTION_NOT_ALLOWED: i32 = -25308;

    pub struct LoginKeychain;

    fn error(e: security_framework::base::Error) -> StoreError {
        match e.code() {
            ERR_SEC_NOT_AVAILABLE | ERR_SEC_NO_SUCH_KEYCHAIN => {
                StoreError::Unavailable(format!("no login keychain (OSStatus {})", e.code()))
            }
            ERR_SEC_INTERACTION_NOT_ALLOWED => StoreError::Failed(
                "the login keychain is locked; unlock it (security unlock-keychain) and retry"
                    .to_owned(),
            ),
            code => StoreError::Failed(format!("keychain error (OSStatus {code})")),
        }
    }

    impl SecretStore for LoginKeychain {
        fn name(&self) -> &str {
            "macOS login keychain"
        }

        fn get(&self, entry: &str) -> Result<Option<Zeroizing<String>>, StoreError> {
            match generic_password(PasswordOptions::new_generic_password(SERVICE, entry)) {
                Ok(bytes) => {
                    let bytes = Zeroizing::new(bytes);
                    std::str::from_utf8(&bytes)
                        .map(|s| Some(Zeroizing::new(s.to_owned())))
                        .map_err(|_| StoreError::Failed("keychain entry is not text".to_owned()))
                }
                Err(e) if e.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(None),
                Err(e) => Err(error(e)),
            }
        }

        fn set(&self, entry: &str, secret: &str) -> Result<(), StoreError> {
            let mut options = PasswordOptions::new_generic_password(SERVICE, entry);
            options.set_label("OnePass CLI Secret Key");
            set_generic_password_options(secret.as_bytes(), options).map_err(error)
        }

        fn delete(&self, entry: &str) -> Result<(), StoreError> {
            match delete_generic_password(SERVICE, entry) {
                Ok(()) => Ok(()),
                Err(e) if e.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(()),
                Err(e) => Err(error(e)),
            }
        }
    }
}

#[cfg(target_os = "linux")]
mod linux {
    //! The freedesktop Secret Service (GNOME Keyring, KWallet, KeePassXC)
    //! over the session D-Bus, default collection. Plain session: the bus
    //! is a socket of the same user, who can ask the store anyway.

    use std::collections::HashMap;

    use dbus_secret_service::{EncryptionType, Error, SecretService as Service};
    use zeroize::Zeroizing;

    use super::{SERVICE, SecretStore, StoreError};

    pub struct SecretService;

    fn error(e: Error) -> StoreError {
        match e {
            Error::Unavailable => {
                StoreError::Unavailable("no Secret Service on the session bus".to_owned())
            }
            // No session bus at all (headless, CI) surfaces as a D-Bus error
            // at connection time: see `connect`.
            Error::Locked => {
                StoreError::Failed("the Secret Service collection is locked".to_owned())
            }
            Error::Prompt => {
                StoreError::Failed("the Secret Service prompt was dismissed".to_owned())
            }
            other => StoreError::Failed(format!("Secret Service error: {other}")),
        }
    }

    fn connect() -> Result<Service, StoreError> {
        Service::connect(EncryptionType::Plain).map_err(|e| match e {
            Error::Dbus(_) | Error::Unavailable => StoreError::Unavailable(
                "no Secret Service reachable (no session D-Bus or no keyring daemon)".to_owned(),
            ),
            other => error(other),
        })
    }

    fn attributes(entry: &str) -> HashMap<&str, &str> {
        HashMap::from([("service", SERVICE), ("account", entry)])
    }

    impl SecretStore for SecretService {
        fn name(&self) -> &str {
            "Secret Service"
        }

        fn get(&self, entry: &str) -> Result<Option<Zeroizing<String>>, StoreError> {
            let ss = connect()?;
            let found = ss.search_items(attributes(entry)).map_err(error)?;
            let item = match (found.unlocked.first(), found.locked.first()) {
                (Some(item), _) => item,
                (None, Some(item)) => {
                    item.unlock().map_err(error)?;
                    item
                }
                (None, None) => return Ok(None),
            };
            let bytes = Zeroizing::new(item.get_secret().map_err(error)?);
            std::str::from_utf8(&bytes)
                .map(|s| Some(Zeroizing::new(s.to_owned())))
                .map_err(|_| StoreError::Failed("Secret Service entry is not text".to_owned()))
        }

        fn set(&self, entry: &str, secret: &str) -> Result<(), StoreError> {
            let ss = connect()?;
            let collection = ss.get_default_collection().map_err(error)?;
            collection.ensure_unlocked().map_err(error)?;
            collection
                .create_item(
                    "OnePass CLI Secret Key",
                    attributes(entry),
                    secret.as_bytes(),
                    true,
                    "text/plain",
                )
                .map_err(error)?;
            Ok(())
        }

        fn delete(&self, entry: &str) -> Result<(), StoreError> {
            let ss = connect()?;
            let found = ss.search_items(attributes(entry)).map_err(error)?;
            for item in found.unlocked.iter().chain(found.locked.iter()) {
                item.delete().map_err(error)?;
            }
            Ok(())
        }
    }
}

/// In-memory store of the unit tests, with switches for the failure paths.
#[cfg(test)]
pub mod memory {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use zeroize::Zeroizing;

    use super::{SecretStore, StoreError};

    #[derive(Default)]
    pub struct MemoryStore {
        pub entries: Mutex<HashMap<String, Zeroizing<String>>>,
        /// Every call answers this error instead.
        pub fail: Mutex<Option<StoreError>>,
    }

    impl MemoryStore {
        pub fn failing(e: StoreError) -> MemoryStore {
            let s = MemoryStore::default();
            *s.fail.lock().unwrap() = Some(e);
            s
        }

        fn check(&self) -> Result<(), StoreError> {
            match &*self.fail.lock().unwrap() {
                Some(e) => Err(e.clone()),
                None => Ok(()),
            }
        }
    }

    impl SecretStore for MemoryStore {
        fn name(&self) -> &str {
            "memory store"
        }

        fn get(&self, entry: &str) -> Result<Option<Zeroizing<String>>, StoreError> {
            self.check()?;
            Ok(self.entries.lock().unwrap().get(entry).cloned())
        }

        fn set(&self, entry: &str, secret: &str) -> Result<(), StoreError> {
            self.check()?;
            self.entries
                .lock()
                .unwrap()
                .insert(entry.to_owned(), Zeroizing::new(secret.to_owned()));
            Ok(())
        }

        fn delete(&self, entry: &str) -> Result<(), StoreError> {
            self.check()?;
            self.entries.lock().unwrap().remove(entry);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dev_switch_is_debug_only() {
        let e = select(false, Some("none")).err().unwrap();
        assert_eq!(
            e.msg,
            "ONEPASS_DEV_SECRET_STORE is refused in a release build"
        );
        assert!(select(false, None).is_ok());
        let none = select(true, Some("none")).unwrap();
        assert!(matches!(none.get("x"), Err(StoreError::Unavailable(_))));
        assert!(select(true, Some("dir:")).is_err());
        assert!(select(true, Some("bogus")).is_err());
    }

    #[test]
    fn dev_dir_store_roundtrips() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("store");
        let s = select(true, Some(&format!("dir:{}", dir.display()))).unwrap();
        assert_eq!(s.get("secretkey.a").unwrap(), None);
        s.set("secretkey.a", "one").unwrap();
        s.set("secretkey.a", "two").unwrap();
        assert_eq!(s.get("secretkey.a").unwrap().unwrap().as_str(), "two");
        s.delete("secretkey.a").unwrap();
        s.delete("secretkey.a").unwrap();
        assert_eq!(s.get("secretkey.a").unwrap(), None);
        assert!(s.set("../x", "y").is_err());
    }

    #[test]
    fn entry_is_named_by_the_account_id() {
        assert_eq!(
            entry_name(Id([0x11; 16])),
            "secretkey.11111111-1111-1111-1111-111111111111"
        );
    }

    /// The real store of this machine: writes, reads back and removes a
    /// test entry. Run by hand: `cargo test -p onepass-cli -- --ignored`.
    #[test]
    #[ignore = "touches the real keychain or Secret Service"]
    fn platform_store_roundtrips() {
        let s = platform();
        let entry = format!("secretkey.test-{}", std::process::id());
        s.set(&entry, "TEST-ONLY-NOT-A-KEY").unwrap();
        assert_eq!(
            s.get(&entry).unwrap().unwrap().as_str(),
            "TEST-ONLY-NOT-A-KEY"
        );
        s.set(&entry, "TEST-ONLY-REPLACED").unwrap();
        assert_eq!(
            s.get(&entry).unwrap().unwrap().as_str(),
            "TEST-ONLY-REPLACED"
        );
        s.delete(&entry).unwrap();
        assert_eq!(s.get(&entry).unwrap(), None);
    }
}
