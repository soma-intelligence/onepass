//! The signed device list, vault deletion, master password change
//! (milestone 2b) and key rotation (spec 2026-10-28). Swift gets the list as
//! plain records, the new Account Unlock Key after a password change or a
//! rotation, and the new Secret Key it drew itself, never a key of the
//! account.

use std::path::Path;

use onepass_core::account::AccountParams;
use onepass_core::crypto::SecretKey;
use onepass_core::devices::{DeviceEntry, DeviceKind, DeviceMode};
use onepass_core::repo::Repository;
use onepass_core::store::{RecordKind, RecordStore};
use onepass_core::sync::SyncStore;
use zeroize::Zeroizing;

use crate::convert::{id_hex, parse_id};
use crate::error::OnePassError;
use crate::session::{Session, find_vault};
use crate::types::FfiUnlocked;

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiDeviceKind {
    Phone,
    Tablet,
    Mac,
    Vision,
    Other,
}

/// What a device may hold: a personal or shared device holds the account, a
/// public one only a read-only session (never listed).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiDeviceMode {
    Personal,
    Shared,
    Public,
}

/// One entry of the signed device list. Dates are Unix seconds; ids are 32
/// hex characters.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiDevice {
    pub id: String,
    pub name: String,
    pub kind: FfiDeviceKind,
    pub mode: FfiDeviceMode,
    pub added_at: i64,
    /// The device that approved it, `None` when it registered itself.
    pub added_by: Option<String>,
    pub revoked_at: Option<i64>,
    pub is_this_device: bool,
}

impl From<DeviceKind> for FfiDeviceKind {
    fn from(k: DeviceKind) -> Self {
        match k {
            DeviceKind::Phone => Self::Phone,
            DeviceKind::Tablet => Self::Tablet,
            DeviceKind::Mac => Self::Mac,
            DeviceKind::Vision => Self::Vision,
            DeviceKind::Other => Self::Other,
        }
    }
}

impl From<FfiDeviceKind> for DeviceKind {
    fn from(k: FfiDeviceKind) -> Self {
        match k {
            FfiDeviceKind::Phone => Self::Phone,
            FfiDeviceKind::Tablet => Self::Tablet,
            FfiDeviceKind::Mac => Self::Mac,
            FfiDeviceKind::Vision => Self::Vision,
            FfiDeviceKind::Other => Self::Other,
        }
    }
}

impl From<DeviceMode> for FfiDeviceMode {
    fn from(m: DeviceMode) -> Self {
        match m {
            DeviceMode::Personal => Self::Personal,
            DeviceMode::Shared => Self::Shared,
            DeviceMode::Public => Self::Public,
        }
    }
}

impl From<FfiDeviceMode> for DeviceMode {
    fn from(m: FfiDeviceMode) -> Self {
        match m {
            FfiDeviceMode::Personal => Self::Personal,
            FfiDeviceMode::Shared => Self::Shared,
            FfiDeviceMode::Public => Self::Public,
        }
    }
}

fn device_to_ffi(e: &DeviceEntry, me: Option<onepass_core::Id>) -> FfiDevice {
    FfiDevice {
        id: id_hex(e.device_id),
        name: e.name.clone(),
        kind: e.kind.into(),
        mode: e.mode.into(),
        added_at: e.added_at,
        added_by: e.added_by.map(id_hex),
        revoked_at: e.revoked_at,
        is_this_device: Some(e.device_id) == me,
    }
}

#[uniffi::export]
impl Session {
    /// Change the master password. The current password and the Secret Key
    /// are checked first (`WrongPassword`, nothing written). Returns the new
    /// Account Unlock Key, to enroll biometrics again. Other devices then
    /// ask for the new password (`store_params_epoch` above
    /// `pinned_params_epoch`).
    pub fn change_password(
        &self,
        current: String,
        secret_key: String,
        new: String,
    ) -> Result<Vec<u8>, OnePassError> {
        let (current, secret_key, new) = (
            Zeroizing::new(current),
            Zeroizing::new(secret_key),
            Zeroizing::new(new),
        );
        let secret_key = SecretKey::parse(&secret_key)?;
        self.with(|repo| {
            let auk = repo.change_password(&current, &secret_key, &new)?;
            Ok(auk.as_bytes().to_vec())
        })
    }

    /// Rotate every key of the account (spec 2026-10-28): new Secret Key,
    /// keyset, vault keys, every item re-encrypted, in one write. `current`
    /// and `secret_key` are checked first (`WrongPassword`, nothing
    /// written). `new_secret_key` comes from `generate_secret_key`, stored
    /// as pending by the app before this call and promoted after it
    /// succeeds (the old Emergency Kit stops working: show the new one).
    /// `new_password` also changes the master password. Returns the new
    /// Account Unlock Key, to enroll biometrics again. Refused while the
    /// Travel Mode is on, and for a new key equal to the current one
    /// (`Validation`).
    ///
    /// Errors: every error is returned before anything is written; once the
    /// write committed, the call succeeds (a failure to save the device
    /// state afterwards is not reported). Discard the pending key only on
    /// `WrongPassword`, `Conflict`, `Validation`, `Locked` or
    /// `InvalidInput`; on any other error keep both keys and let the next
    /// unlock try each (ruling K12).
    pub fn rotate_keys(
        &self,
        current: String,
        secret_key: String,
        new_secret_key: String,
        new_password: Option<String>,
    ) -> Result<Vec<u8>, OnePassError> {
        let (current, secret_key, new_secret_key) = (
            Zeroizing::new(current),
            Zeroizing::new(secret_key),
            Zeroizing::new(new_secret_key),
        );
        let new_password = new_password.map(Zeroizing::new);
        let secret_key = SecretKey::parse(&secret_key)?;
        let new_secret_key = SecretKey::parse(&new_secret_key)?;
        self.with_committed(|repo| {
            let auk = repo.rotate_keys(
                &current,
                &secret_key,
                &new_secret_key,
                new_password.as_deref().map(String::as_str),
            )?;
            Ok(auk.as_bytes().to_vec())
        })
    }

    /// Revoke another device and rotate every key in the same write: the
    /// revoked device, even if it keeps its data and Secret Key, reads
    /// nothing written afterwards. Same arguments, result and error contract
    /// as `rotate_keys`; this device cannot revoke itself
    /// (`Validation("device", "this device")`), an unknown id is
    /// `NotFound`. Use this instead of `revoke_device`, which only marks
    /// the device.
    pub fn revoke_device_rotating(
        &self,
        id: String,
        password: String,
        secret_key: String,
        new_secret_key: String,
    ) -> Result<Vec<u8>, OnePassError> {
        let id = parse_id(&id)?;
        let (password, secret_key, new_secret_key) = (
            Zeroizing::new(password),
            Zeroizing::new(secret_key),
            Zeroizing::new(new_secret_key),
        );
        let secret_key = SecretKey::parse(&secret_key)?;
        let new_secret_key = SecretKey::parse(&new_secret_key)?;
        self.with_committed(|repo| {
            let auk = repo.revoke_device_rotating(id, &password, &secret_key, &new_secret_key)?;
            Ok(auk.as_bytes().to_vec())
        })
    }

    /// The signed device list, revoked devices included, sorted by id.
    pub fn devices(&self) -> Result<Vec<FfiDevice>, OnePassError> {
        self.with(|repo| {
            let entries = repo.devices()?;
            let me = repo.this_device_id();
            Ok(entries.iter().map(|e| device_to_ffi(e, me)).collect())
        })
    }

    /// This device's id in the device list, once it has one (`None` while
    /// locked).
    pub fn this_device_id(&self) -> Option<String> {
        self.guard()
            .as_ref()
            .and_then(|repo| repo.this_device_id())
            .map(id_hex)
    }

    /// Register this device (or update its name, type and mode) and return
    /// its id. Refused for a revoked device and for the public mode.
    pub fn register_this_device(
        &self,
        name: String,
        kind: FfiDeviceKind,
        mode: FfiDeviceMode,
    ) -> Result<String, OnePassError> {
        self.with(|repo| {
            Ok(id_hex(repo.register_this_device(
                &name,
                kind.into(),
                mode.into(),
            )?))
        })
    }

    /// Mark another device revoked, without rotating the keys: the device
    /// is asked to erase itself, nothing more (see `revoke_device_rotating`
    /// for the cryptographic cut). This device cannot revoke itself from
    /// the list (`Validation("device", "this device")`); revoking twice
    /// changes nothing; an unknown id is `NotFound`.
    pub fn revoke_device(&self, id: String) -> Result<(), OnePassError> {
        let id = parse_id(&id)?;
        self.with(|repo| {
            repo.devices()?;
            if repo.this_device_id() == Some(id) {
                return Err(OnePassError::Validation {
                    field: "device".into(),
                    reason: "this device".into(),
                });
            }
            Ok(repo.revoke_device(id)?)
        })
    }

    pub fn rename_device(&self, id: String, name: String) -> Result<(), OnePassError> {
        let id = parse_id(&id)?;
        self.with(|repo| Ok(repo.rename_device(id, &name)?))
    }

    /// Whether the device list marks this device revoked: the app then
    /// erases the device.
    pub fn is_this_device_revoked(&self) -> Result<bool, OnePassError> {
        self.with(|repo| Ok(repo.is_this_device_revoked()?))
    }

    /// Delete an empty vault (trashed items go with it). The last vault and
    /// a vault with live items are refused (`InvalidInput`).
    pub fn delete_vault(&self, vault_id: String) -> Result<(), OnePassError> {
        let id = parse_id(&vault_id)?;
        self.with(|repo| {
            let vault = find_vault(repo, id)?;
            Ok(repo.delete_vault(&vault)?)
        })
    }

    /// The epoch of the account params this session opened.
    pub fn params_epoch(&self) -> Result<u64, OnePassError> {
        self.guard()
            .as_ref()
            .map(|repo| repo.account().params.epoch)
            .ok_or(OnePassError::Locked)
    }
}

/// The epoch of the account params in the store at `db_path`, without
/// unlocking (nothing verified). Above `pinned_params_epoch`: the master
/// password changed on another device.
#[uniffi::export]
pub fn store_params_epoch(db_path: String) -> Result<u64, OnePassError> {
    let store = SyncStore::open(Path::new(&db_path))?;
    let params = store.list(RecordKind::AccountParams)?;
    let record = params.first().ok_or(OnePassError::NotFound)?;
    Ok(AccountParams::decode(&record.data)?.epoch)
}

/// The highest params epoch an unlock accepted on this device (0 before
/// the first unlock).
#[uniffi::export]
pub fn pinned_params_epoch(db_path: String) -> Result<u64, OnePassError> {
    let store = SyncStore::open(Path::new(&db_path))?;
    Ok(store.chain_state()?.params_epoch)
}

/// A new Secret Key, in its display form, for `rotate_keys` and
/// `revoke_device_rotating`: the app stores it as pending (Keychain) before
/// the rotation, so a crash between the write and the new Emergency Kit
/// never locks the account out.
#[uniffi::export]
pub fn generate_secret_key() -> Result<String, OnePassError> {
    Ok(SecretKey::generate()?.to_display())
}

/// Whether the account at `db_path` is the one this device pinned, now
/// signed by another identity, without unlocking: its keys were rotated on
/// another device. The app then asks for the new Secret Key (from the new
/// Emergency Kit, or by pairing again) and calls `unlock_after_rotation`.
#[uniffi::export]
pub fn store_keys_rotated(db_path: String) -> Result<bool, OnePassError> {
    let store = SyncStore::open(Path::new(&db_path))?;
    let device = store.device_state()?;
    Ok(Repository::keys_rotated(&store, &device)?)
}

/// Unlock after the keys were rotated on another device, with the new
/// Secret Key the user just typed or received by pairing, and
/// `previous_secret_key`, the one this device held until now (Keychain):
/// the device follows the new account identity, keeping its pinned state.
/// A new identity offered with `previous_secret_key` itself is refused
/// (`Validation`: a revoked device can forge a "rotation" under the old
/// key); any other key the rotation was not sealed under is
/// `WrongPassword`; old params served again are `Integrity`.
#[uniffi::export]
pub fn unlock_after_rotation(
    db_path: String,
    password: String,
    secret_key: String,
    previous_secret_key: String,
) -> Result<FfiUnlocked, OnePassError> {
    let (password, secret_key, previous) = (
        Zeroizing::new(password),
        Zeroizing::new(secret_key),
        Zeroizing::new(previous_secret_key),
    );
    let store = SyncStore::open(Path::new(&db_path))?;
    let secret_key = SecretKey::parse(&secret_key)?;
    let previous = SecretKey::parse(&previous)?;
    let device = store.device_state()?;
    let (mut repo, auk) =
        Repository::unlock_after_rotation(store, &password, &secret_key, &previous, device)?;
    repo.persist_device_state()?;
    Ok(FfiUnlocked {
        session: Session::new(repo)?,
        auk: auk.as_bytes().to_vec(),
    })
}
