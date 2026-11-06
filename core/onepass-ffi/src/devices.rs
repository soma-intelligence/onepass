//! The signed device list, vault deletion and master password change
//! (milestone 2b). Swift gets the list as plain records and the new Account
//! Unlock Key after a password change, never a key of the account.

use std::path::Path;

use onepass_core::crypto::SecretKey;
use onepass_core::devices::{DeviceEntry, DeviceKind, DeviceMode};
use onepass_core::sync::SyncStore;
use zeroize::Zeroizing;

use crate::convert::{id_hex, parse_id};
use crate::error::OnePassError;
use crate::session::{Session, find_vault};

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiDeviceKind {
    Phone,
    Tablet,
    Mac,
    Vision,
    Other,
    Android,
    Windows,
    Linux,
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
    /// When it was revoked; `None` when it is not, or when the date is
    /// unknown (key rotation v2 derives it from the lineage, Task 12 M2):
    /// `revoked` tells.
    pub revoked_at: Option<i64>,
    pub revoked: bool,
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
            DeviceKind::Android => Self::Android,
            DeviceKind::Windows => Self::Windows,
            DeviceKind::Linux => Self::Linux,
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
            FfiDeviceKind::Android => Self::Android,
            FfiDeviceKind::Windows => Self::Windows,
            FfiDeviceKind::Linux => Self::Linux,
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
        revoked_at: e.revoked_at.filter(|at| *at != 0),
        revoked: e.revoked_at.is_some(),
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

    /// Mark another device revoked. This device cannot revoke itself from
    /// the list (`Validation("device", "this device")`); revoking twice
    /// changes nothing; an unknown id is `NotFound`.
    ///
    /// Key rotation v2 (spec 10.1): on a device with device keys
    /// (`FfiLineageStatus::removes_by_rotation`) "Retirer" is a rotation,
    /// `rotate_keys` with the device in `revoke`; this call is refused
    /// there (`Validation("device", "remove by rotation")`).
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

    /// "Appairage incomplet" (spec 5.2 as ruled, Task 13): devices listed
    /// whose pairing stopped before their key was introduced. The app
    /// offers to finish (pair it again) or remove it (`cancel_pairing`,
    /// then `rotate_keys`). Sorted ids.
    pub fn pairing_incomplete(&self) -> Result<Vec<String>, OnePassError> {
        self.with(|repo| Ok(repo.pairing_incomplete()?.into_iter().map(id_hex).collect()))
    }

    /// Remove a device whose pairing is incomplete: listed revoked and
    /// excluded here, in one transaction. It got the Secret Key with its
    /// grant: the app follows with `rotate_keys` (reason `Rotate`).
    pub fn cancel_pairing(&self, id: String) -> Result<(), OnePassError> {
        let id = parse_id(&id)?;
        self.with(|repo| Ok(repo.cancel_pairing(id)?))
    }

    /// Whether this device is revoked (on a device with key rotation v2
    /// trust state, by a valid lineage record only; otherwise by the device
    /// list). The app locks the device; it never erases on this answer
    /// (only the quarantine erases, spec 8.4).
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
/// unlocking. The signature is verified (G8) under the identity this device
/// pinned, or under the record's own identity on a device that pinned
/// nothing yet: params signed by any other identity are an integrity error,
/// never an epoch. Above `pinned_params_epoch`: the master password changed
/// on another device.
#[uniffi::export]
pub fn store_params_epoch(db_path: String) -> Result<u64, OnePassError> {
    let store = SyncStore::open(Path::new(&db_path))?;
    let pinned = store.device_state()?.pinned;
    // With a trust state, the params of its identity (key rotation v2):
    // a rotation waiting for the user is not an error here, and once
    // followed the poll reads the new identity's params.
    Ok(onepass_core::repo::follow::stored_params_epoch(
        &store,
        pinned.as_ref(),
    )?)
}

/// The highest params epoch an unlock accepted on this device (0 before
/// the first unlock).
#[uniffi::export]
pub fn pinned_params_epoch(db_path: String) -> Result<u64, OnePassError> {
    let store = SyncStore::open(Path::new(&db_path))?;
    Ok(store.chain_state()?.params_epoch)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(revoked_at: Option<i64>) -> DeviceEntry {
        DeviceEntry {
            device_id: onepass_core::Id([1; 16]),
            name: "iPad de Camille".into(),
            kind: DeviceKind::Tablet,
            mode: DeviceMode::Personal,
            added_at: 1,
            added_by: None,
            revoked_at,
        }
    }

    /// Task 12 M2: a revocation the lineage holds without a date (0) shows
    /// as revoked, without a date.
    #[test]
    fn unknown_revocation_date_is_hidden() {
        let d = device_to_ffi(&entry(Some(0)), None);
        assert!(d.revoked);
        assert_eq!(d.revoked_at, None);
        let d = device_to_ffi(&entry(Some(1_700_000_000)), None);
        assert!(d.revoked);
        assert_eq!(d.revoked_at, Some(1_700_000_000));
        let d = device_to_ffi(&entry(None), None);
        assert!(!d.revoked);
        assert_eq!(d.revoked_at, None);
    }
}
