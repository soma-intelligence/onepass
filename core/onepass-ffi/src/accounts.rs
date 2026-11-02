//! The accounts of the device (multi-account spec 2026-11-02, section 5).
//! Every call names the primary store's folder; a mutation loads the
//! directory, changes it and writes it back whole (atomic rename).

use std::path::Path;

use onepass_core::profiles::{
    self, AccountColor, AccountDirectory, AccountEntry, AccountKind, Slot,
};
use onepass_core::sync::SyncStore;
use time::OffsetDateTime;

use crate::convert::{id_hex, parse_id};
use crate::error::OnePassError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiAccountColor {
    Blue,
    Green,
    Orange,
    Purple,
    Pink,
    Teal,
    Indigo,
    Graphite,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum FfiAccountKind {
    Personal,
    Business,
    /// An organisation's account (enterprise spec E1): `org_id` in hex.
    Managed {
        server_url: String,
        org_id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiAccountEntry {
    /// `primary` or 32 hex characters.
    pub slot: String,
    /// The bound account id (hex), none while being added.
    pub account_id: Option<String>,
    pub kind: FfiAccountKind,
    pub label: String,
    pub color: FfiAccountColor,
    pub work_domains: Vec<String>,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiAccountDirectory {
    pub active: String,
    pub unified_search: bool,
    pub entries: Vec<FfiAccountEntry>,
}

impl From<AccountColor> for FfiAccountColor {
    fn from(c: AccountColor) -> Self {
        match c {
            AccountColor::Blue => Self::Blue,
            AccountColor::Green => Self::Green,
            AccountColor::Orange => Self::Orange,
            AccountColor::Purple => Self::Purple,
            AccountColor::Pink => Self::Pink,
            AccountColor::Teal => Self::Teal,
            AccountColor::Indigo => Self::Indigo,
            AccountColor::Graphite => Self::Graphite,
        }
    }
}

impl From<FfiAccountColor> for AccountColor {
    fn from(c: FfiAccountColor) -> Self {
        match c {
            FfiAccountColor::Blue => Self::Blue,
            FfiAccountColor::Green => Self::Green,
            FfiAccountColor::Orange => Self::Orange,
            FfiAccountColor::Purple => Self::Purple,
            FfiAccountColor::Pink => Self::Pink,
            FfiAccountColor::Teal => Self::Teal,
            FfiAccountColor::Indigo => Self::Indigo,
            FfiAccountColor::Graphite => Self::Graphite,
        }
    }
}

fn kind_to_ffi(kind: &AccountKind) -> FfiAccountKind {
    match kind {
        AccountKind::Personal => FfiAccountKind::Personal,
        AccountKind::Business => FfiAccountKind::Business,
        AccountKind::Managed { server_url, org_id } => FfiAccountKind::Managed {
            server_url: server_url.clone(),
            org_id: id_hex(*org_id),
        },
    }
}

fn kind_from_ffi(kind: FfiAccountKind) -> Result<AccountKind, OnePassError> {
    Ok(match kind {
        FfiAccountKind::Personal => AccountKind::Personal,
        FfiAccountKind::Business => AccountKind::Business,
        FfiAccountKind::Managed { server_url, org_id } => AccountKind::Managed {
            server_url,
            org_id: parse_id(&org_id)?,
        },
    })
}

fn entry_to_ffi(e: &AccountEntry) -> FfiAccountEntry {
    FfiAccountEntry {
        slot: e.slot.as_str().to_owned(),
        account_id: e.account_id.map(id_hex),
        kind: kind_to_ffi(&e.kind),
        label: e.label.clone(),
        color: e.color.into(),
        work_domains: e.work_domains.clone(),
        created_at: e.created_at,
    }
}

fn to_ffi(d: &AccountDirectory) -> FfiAccountDirectory {
    FfiAccountDirectory {
        active: d.active.as_str().to_owned(),
        unified_search: d.unified_search,
        entries: d.entries.iter().map(entry_to_ffi).collect(),
    }
}

fn slot(text: &str) -> Result<Slot, OnePassError> {
    Ok(Slot::parse(text)?)
}

/// Load, change, save, return the new directory.
fn change(
    folder: &str,
    f: impl FnOnce(&mut AccountDirectory) -> Result<(), OnePassError>,
) -> Result<FfiAccountDirectory, OnePassError> {
    let folder = Path::new(folder);
    let mut directory = AccountDirectory::load(folder)?;
    f(&mut directory)?;
    directory.save(folder)?;
    Ok(to_ffi(&directory))
}

/// The accounts of the device: the file, or the primary account alone.
#[uniffi::export]
pub fn account_directory_load(folder: String) -> Result<FfiAccountDirectory, OnePassError> {
    Ok(to_ffi(&AccountDirectory::load(Path::new(&folder))?))
}

/// Adds an account in a new slot (not bound yet) and returns its slot.
#[uniffi::export]
pub fn account_directory_add(
    folder: String,
    kind: FfiAccountKind,
    label: String,
    color: FfiAccountColor,
) -> Result<String, OnePassError> {
    let kind = kind_from_ffi(kind)?;
    let mut added = None;
    change(&folder, |d| {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        added = Some(d.add(kind, &label, color.into(), now)?);
        Ok(())
    })?;
    added
        .map(|s| s.as_str().to_owned())
        .ok_or(OnePassError::NotFound)
}

/// Binds the account a slot's store holds (`Conflict` when that account
/// is bound elsewhere, or the slot to another account).
#[uniffi::export]
pub fn account_directory_bind(
    folder: String,
    slot: String,
    account_id: String,
) -> Result<FfiAccountDirectory, OnePassError> {
    let (s, id) = (self::slot(&slot)?, parse_id(&account_id)?);
    change(&folder, |d| Ok(d.bind(&s, id)?))
}

#[uniffi::export]
pub fn account_directory_update(
    folder: String,
    slot: String,
    label: String,
    color: FfiAccountColor,
    work_domains: Vec<String>,
) -> Result<FfiAccountDirectory, OnePassError> {
    let s = self::slot(&slot)?;
    change(&folder, |d| {
        Ok(d.update(&s, &label, color.into(), &work_domains)?)
    })
}

/// Takes an added account out of the directory (never the primary one).
/// The caller erases its files and keychain entries.
#[uniffi::export]
pub fn account_directory_remove(
    folder: String,
    slot: String,
) -> Result<FfiAccountDirectory, OnePassError> {
    let s = self::slot(&slot)?;
    change(&folder, |d| d.remove(&s).map(|_| ()).map_err(Into::into))
}

#[uniffi::export]
pub fn account_directory_set_active(
    folder: String,
    slot: String,
) -> Result<FfiAccountDirectory, OnePassError> {
    let s = self::slot(&slot)?;
    change(&folder, |d| Ok(d.set_active(&s)?))
}

#[uniffi::export]
pub fn account_directory_reorder(
    folder: String,
    slot: String,
    index: u32,
) -> Result<FfiAccountDirectory, OnePassError> {
    let s = self::slot(&slot)?;
    change(&folder, |d| Ok(d.reorder(&s, index as usize)?))
}

#[uniffi::export]
pub fn account_directory_set_unified_search(
    folder: String,
    enabled: bool,
) -> Result<FfiAccountDirectory, OnePassError> {
    change(&folder, |d| {
        d.unified_search = enabled;
        Ok(())
    })
}

/// The slot whose work domain covers `host`, or `primary`. Never fails: a
/// directory that does not load routes to the primary account.
#[uniffi::export]
pub fn account_directory_route(folder: String, host: String) -> String {
    AccountDirectory::load(Path::new(&folder))
        .map(|d| d.route(&host))
        .unwrap_or_else(|_| Slot::primary())
        .as_str()
        .to_owned()
}

/// The store file of a slot, derived from the slot only.
#[uniffi::export]
pub fn account_store_path(folder: String, slot: String) -> Result<String, OnePassError> {
    let s = self::slot(&slot)?;
    Ok(profiles::store_path(Path::new(&folder), &s)
        .to_string_lossy()
        .into_owned())
}

/// The account this device pinned in the store at `db_path` (hex), without
/// unlocking; none before its first unlock here.
#[uniffi::export]
pub fn store_account_id(db_path: String) -> Result<Option<String>, OnePassError> {
    let store = SyncStore::open(Path::new(&db_path))?;
    Ok(store.device_state()?.pinned.map(|p| id_hex(p.account_id)))
}

/// The store of `slot` may be opened: unbound, or bound to the account the
/// store pinned (`Conflict` otherwise, spec M4).
#[uniffi::export]
pub fn account_check_binding(
    folder: String,
    slot: String,
    db_path: String,
) -> Result<(), OnePassError> {
    let s = self::slot(&slot)?;
    let directory = AccountDirectory::load(Path::new(&folder))?;
    let found = if Path::new(&db_path).exists() {
        SyncStore::open(Path::new(&db_path))?
            .device_state()?
            .pinned
            .map(|p| p.account_id)
    } else {
        None
    };
    Ok(directory.check_binding(&s, found)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn folder() -> (tempfile::TempDir, String) {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().to_string_lossy().into_owned();
        (tmp, path)
    }

    #[test]
    fn round_trip_through_the_ffi() {
        let (_tmp, f) = folder();
        let d = account_directory_load(f.clone()).unwrap();
        assert_eq!(d.entries.len(), 1);
        assert_eq!(d.active, "primary");
        let s = account_directory_add(
            f.clone(),
            FfiAccountKind::Business,
            "Soma Labs".into(),
            FfiAccountColor::Orange,
        )
        .unwrap();
        let id = id_hex(onepass_core::Id::new());
        let d = account_directory_bind(f.clone(), s.clone(), id.clone()).unwrap();
        assert_eq!(d.entries[1].account_id.as_deref(), Some(id.as_str()));
        let d = account_directory_update(
            f.clone(),
            s.clone(),
            "Soma".into(),
            FfiAccountColor::Teal,
            vec!["SomaLabs.me".into()],
        )
        .unwrap();
        assert_eq!(d.entries[1].work_domains, vec!["somalabs.me"]);
        assert_eq!(d.entries[1].color, FfiAccountColor::Teal);
        assert_eq!(
            account_directory_route(f.clone(), "app.somalabs.me".into()),
            s
        );
        assert_eq!(
            account_directory_route(f.clone(), "github.com".into()),
            "primary"
        );
        let d = account_directory_set_active(f.clone(), s.clone()).unwrap();
        assert_eq!(d.active, s);
        let d = account_directory_set_unified_search(f.clone(), true).unwrap();
        assert!(d.unified_search);
        assert!(
            account_store_path(f.clone(), s.clone())
                .unwrap()
                .ends_with(&format!("accounts/{s}/vault.sqlite"))
        );
        assert!(matches!(
            account_directory_remove(f.clone(), "primary".into()),
            Err(OnePassError::InvalidInput { .. })
        ));
        let d = account_directory_remove(f.clone(), s).unwrap();
        assert_eq!(d.entries.len(), 1);
        assert_eq!(d.active, "primary");
    }

    #[test]
    fn managed_kind_round_trips_and_bad_slots_are_refused() {
        let (_tmp, f) = folder();
        let org = id_hex(onepass_core::Id::new());
        let s = account_directory_add(
            f.clone(),
            FfiAccountKind::Managed {
                server_url: "https://org.example".into(),
                org_id: org.clone(),
            },
            "Org".into(),
            FfiAccountColor::Indigo,
        )
        .unwrap();
        let d = account_directory_load(f.clone()).unwrap();
        assert_eq!(
            d.entries[1].kind,
            FfiAccountKind::Managed {
                server_url: "https://org.example".into(),
                org_id: org
            }
        );
        assert!(account_store_path(f.clone(), "../x".into()).is_err());
        assert!(account_directory_set_active(f.clone(), "../x".into()).is_err());
        assert_eq!(
            account_check_binding(f.clone(), s, "/nonexistent/vault.sqlite".into()),
            Ok(())
        );
    }
}
