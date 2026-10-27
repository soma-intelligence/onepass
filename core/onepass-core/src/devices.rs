//! The signed device list (milestone 2b, spec 4.3): every device of the
//! account, with its name, type and mode, and when it was revoked.
//!
//! It is a monotone list (`lists`): an entry is never removed, a revoked
//! device stays revoked. The lists are kept up to date lazily: the first
//! call that may write (`devices`, `vault_list`, `register_this_device`,
//! the edits, `is_this_device_revoked`, and `create_vault` on an account
//! without a vault list) creates a missing list (an account from before
//! milestone 2b), registers this device if it is not listed yet, and adopts
//! the unlisted vaults (`vaultlist`). Reading never fails because a list was
//! never written; a revoked device writes nothing.
//!
//! This device's id lives in the chain state. It is written in the same
//! transaction as the list that first lists it
//! (`RecordStore::put_all_if_version_with_chain`), so a cut never leaves an
//! entry nobody holds. A store that does not keep the chain state between
//! sessions (`RecordStore::persists_chain`: memory, plain SQLite) never
//! registers a device: there `register_this_device` is refused and the
//! device list is only read and edited.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::chain::{ChainState, Seen};
use crate::lists::{AccountList, MonotoneEntry, Stored};
use crate::repo::Repository;
use crate::store::{RecordKind, RecordStore};
use crate::vaultlist::VaultListEntry;
use crate::{Error, Id, Result, ValidationError};

/// Most characters in a device name.
pub const MAX_DEVICE_NAME_CHARS: usize = 64;

/// The name a device gets when it registers itself without one (migration,
/// lazy self-registration). `register_this_device` replaces it.
pub const DEFAULT_DEVICE_NAME: &str = "Appareil";

/// The type of a device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum DeviceKind {
    Phone,
    Tablet,
    Mac,
    Vision,
    Other,
}

/// What a device may hold (architecture spec 4.10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum DeviceMode {
    Personal,
    Shared,
    Public,
}

/// One device of the list. Dates are Unix seconds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceEntry {
    pub device_id: Id,
    pub name: String,
    pub kind: DeviceKind,
    pub mode: DeviceMode,
    pub added_at: i64,
    /// The device that added it (pairing), `None` for a device that
    /// registered itself.
    pub added_by: Option<Id>,
    pub revoked_at: Option<i64>,
}

impl DeviceEntry {
    /// The fields an edit changes, as one comparable value. A real name
    /// ranks above the default one, whatever their spelling.
    fn editable(&self) -> (bool, &str, DeviceKind, DeviceMode, Option<Id>) {
        (
            self.name != DEFAULT_DEVICE_NAME,
            &self.name,
            self.kind,
            self.mode,
            self.added_by,
        )
    }

    /// `self`'s editable fields with the forward steps of both.
    fn with_monotone_of(&self, other: &Self) -> Self {
        DeviceEntry {
            added_at: self.added_at.min(other.added_at),
            revoked_at: earliest(self.revoked_at, other.revoked_at),
            ..self.clone()
        }
    }
}

/// The earliest of two optional dates, a date winning over none.
pub(crate) fn earliest(a: Option<i64>, b: Option<i64>) -> Option<i64> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.min(y)),
        (x, y) => x.or(y),
    }
}

impl MonotoneEntry for DeviceEntry {
    fn id(&self) -> Id {
        self.device_id
    }

    /// Revocation wins, the earliest dates are kept; the editable fields
    /// come from the larger of the two (a real name before the default one,
    /// then by name, kind, mode and `added_by`), so the merge is
    /// commutative.
    fn merge(&self, other: &Self) -> Self {
        if self.editable() >= other.editable() {
            self.with_monotone_of(other)
        } else {
            other.with_monotone_of(self)
        }
    }

    fn merge_preferring(&self, other: &Self) -> Self {
        self.with_monotone_of(other)
    }
}

impl AccountList for DeviceEntry {
    const KIND: RecordKind = RecordKind::DeviceList;
    const DOMAIN: &'static [u8] = crate::lists::DEVICE_LIST_DOMAIN;

    fn seen(chain: &ChainState) -> Option<Seen> {
        chain.device_list
    }

    fn set_seen(chain: &mut ChainState, seen: Seen) {
        chain.device_list = Some(seen);
    }
}

/// How this device describes itself in the list.
pub(crate) struct Registration<'a> {
    pub(crate) name: &'a str,
    pub(crate) kind: DeviceKind,
    pub(crate) mode: DeviceMode,
}

pub(crate) fn now() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}

fn invalid(field: &str, reason: &'static str) -> Error {
    ValidationError {
        field: field.into(),
        reason,
    }
    .into()
}

/// A name of 1 to `MAX_DEVICE_NAME_CHARS` characters, not only spaces.
pub(crate) fn check_name(name: &str) -> Result<()> {
    if name.trim().is_empty() {
        return Err(invalid("device name", "empty"));
    }
    if name.chars().count() > MAX_DEVICE_NAME_CHARS {
        return Err(invalid("device name", "too long"));
    }
    Ok(())
}

fn revoked() -> Error {
    invalid("device", "revoked")
}

/// A public session adds nothing to the list (architecture spec 4.10).
fn check_mode(mode: DeviceMode) -> Result<()> {
    match mode {
        DeviceMode::Public => Err(invalid("device mode", "public")),
        DeviceMode::Personal | DeviceMode::Shared => Ok(()),
    }
}

/// A device entry registered by the device itself.
pub(crate) fn self_entry(device_id: Id, me: Option<&Registration<'_>>, at: i64) -> DeviceEntry {
    DeviceEntry {
        device_id,
        name: me.map_or(DEFAULT_DEVICE_NAME, |r| r.name).to_owned(),
        kind: me.map_or(DeviceKind::Other, |r| r.kind),
        mode: me.map_or(DeviceMode::Personal, |r| r.mode),
        added_at: at,
        added_by: None,
        revoked_at: None,
    }
}

impl<S: RecordStore> Repository<S> {
    /// Bring both lists up to date, in one write (spec 4.3, 4.4):
    ///
    /// - a missing device list is created with this device, a device list
    ///   without this device gets it (self-registration), and with `me` this
    ///   device's name, type and mode are set;
    /// - a missing vault list is created with the vaults present (trust on
    ///   first use), and a vault present with a valid key, meta and signed
    ///   manifest but missing from the list is added (adoption). When the
    ///   vaults do not verify (`vaults()` fails), the vault list is left
    ///   alone: `vaults()` reports the fault.
    ///
    /// This device gets an id in the chain state on its first call, saved
    /// with the list write; on a store that does not persist the chain
    /// state the device part is skipped (see the module doc). A device the
    /// list marks revoked writes nothing. The lists read are remembered as
    /// accepted (`ChainState`).
    pub(crate) fn maintain_lists(&mut self, me: Option<&Registration<'_>>) -> Result<()> {
        let devices = self.read_list::<DeviceEntry>()?;
        let vault_list = self.read_list::<VaultListEntry>()?;
        if let Some(d) = &devices {
            self.chain.device_list = Some(d.body.seen());
        }
        if let Some(v) = &vault_list {
            self.chain.vault_list = Some(v.body.seen());
            // A vault deleted (here or elsewhere) is no longer remembered.
            for e in v.body.entries.iter().filter(|e| e.deleted_at.is_some()) {
                self.forget_vault(e.vault_id);
            }
        }
        let registers = self.store.persists_chain();
        if registers && self.chain.device_id.is_none() {
            // Another process on the same file (the AutoFill extension)
            // may have registered this device since this session read the
            // chain state: its id, already saved, is this device's (and
            // tells whether it is revoked), never a second one.
            self.chain.device_id = self.store.chain_state()?.device_id;
        }
        let mut chain = self.chain.clone();
        let my_id = if registers {
            Some(*chain.device_id.get_or_insert_with(Id::new))
        } else {
            chain.device_id
        };
        let mine = my_id.and_then(|id| devices.as_ref().and_then(|d| d.body.entry(id)));
        if mine.is_some_and(|e| e.revoked_at.is_some()) {
            return Ok(());
        }
        let at = now();

        let wanted = match (my_id.filter(|_| registers), mine, me) {
            (None, _, _) => None,
            (Some(my_id), None, _) => Some(self_entry(my_id, me, at)),
            (Some(_), Some(e), Some(r))
                if (e.name.as_str(), e.kind, e.mode) != (r.name, r.kind, r.mode) =>
            {
                Some(DeviceEntry {
                    name: r.name.to_owned(),
                    kind: r.kind,
                    mode: r.mode,
                    ..e.clone()
                })
            }
            _ => None,
        };
        let mut writes = Vec::new();
        let mut device_body = None;
        if let Some(entry) = wanted {
            let mut entries: Vec<DeviceEntry> = devices
                .as_ref()
                .map(|d| d.body.entries.clone())
                .unwrap_or_default();
            entries.retain(|e| e.device_id != entry.device_id);
            entries.push(entry);
            let (rec, expected, body) = self.list_write(devices.as_ref(), entries)?;
            writes.push((rec, expected));
            device_body = Some(body);
        }

        let mut vault_body = None;
        if let Ok(present) = self.vaults() {
            let listed: Vec<VaultListEntry> = vault_list
                .as_ref()
                .map(|v| v.body.entries.clone())
                .unwrap_or_default();
            let unlisted: Vec<VaultListEntry> = present
                .iter()
                .filter(|v| !listed.iter().any(|e| e.vault_id == v.id))
                .map(|v| VaultListEntry {
                    vault_id: v.id,
                    created_at: at,
                    deleted_at: None,
                })
                .collect();
            if vault_list.is_none() || !unlisted.is_empty() {
                let mut entries = listed;
                entries.extend(unlisted);
                let (rec, expected, body) = self.list_write(vault_list.as_ref(), entries)?;
                writes.push((rec, expected));
                vault_body = Some(body);
            }
        }

        if writes.is_empty() {
            return Ok(());
        }
        if let Some(b) = device_body {
            chain.device_list = Some(b.seen());
        }
        if let Some(b) = vault_body {
            chain.vault_list = Some(b.seen());
        }
        // The device id (new or not) goes with the list that carries it.
        self.store.put_all_if_version_with_chain(writes, &chain)?;
        self.chain = chain;
        Ok(())
    }

    /// Every device of the account, sorted by id, revoked ones included,
    /// after bringing the lists up to date (`maintain_lists`).
    pub fn devices(&mut self) -> Result<Vec<DeviceEntry>> {
        self.maintain_lists(None)?;
        Ok(self
            .read_list::<DeviceEntry>()?
            .map(|d| d.body.entries)
            .unwrap_or_default())
    }

    /// This device's id in the device list, once it has one.
    pub fn this_device_id(&self) -> Option<Id> {
        self.chain.device_id
    }

    /// Register this device under `name`, `kind` and `mode` (or update its
    /// entry), creating its id if it has none yet, and return the id. The
    /// name has 1 to `MAX_DEVICE_NAME_CHARS` characters
    /// (`Validation("device name")`). A device the list marks revoked is
    /// refused (`Validation("device")`): a revoked id never registers again.
    /// A public session never registers (`Validation("device mode")`), and
    /// a store that does not persist the chain state cannot hold the id
    /// (`InvalidFormat("device registration needs a sync store")`).
    pub fn register_this_device(
        &mut self,
        name: &str,
        kind: DeviceKind,
        mode: DeviceMode,
    ) -> Result<Id> {
        check_name(name)?;
        check_mode(mode)?;
        if !self.store.persists_chain() {
            return Err(Error::InvalidFormat(
                "device registration needs a sync store",
            ));
        }
        self.maintain_lists(Some(&Registration { name, kind, mode }))?;
        if self.is_revoked_here()? {
            return Err(revoked());
        }
        self.chain.device_id.ok_or(Error::NotFound)
    }

    /// Add a device (pairing): its id must not be listed yet
    /// (`Validation("device")`), its name valid, its mode personal or
    /// shared, and it must not be revoked already. Refused on a revoked
    /// device.
    pub fn add_device(&mut self, entry: DeviceEntry) -> Result<()> {
        check_name(&entry.name)?;
        check_mode(entry.mode)?;
        if entry.revoked_at.is_some() {
            return Err(revoked());
        }
        self.edit_devices(|entries| {
            if entries.iter().any(|e| e.device_id == entry.device_id) {
                return Err(invalid("device", "already listed"));
            }
            entries.push(entry);
            Ok(true)
        })
    }

    /// Mark a device revoked (now). Revoking it again changes nothing. An
    /// unknown id is `NotFound`.
    pub fn revoke_device(&mut self, id: Id) -> Result<()> {
        let at = now();
        self.edit_devices(|entries| {
            let e = entries
                .iter_mut()
                .find(|e| e.device_id == id)
                .ok_or(Error::NotFound)?;
            if e.revoked_at.is_some() {
                return Ok(false);
            }
            e.revoked_at = Some(at);
            Ok(true)
        })
    }

    /// Rename a device. An unknown id is `NotFound`, a revoked one
    /// `Validation("device")`.
    pub fn rename_device(&mut self, id: Id, name: &str) -> Result<()> {
        check_name(name)?;
        self.edit_devices(|entries| {
            let e = entries
                .iter_mut()
                .find(|e| e.device_id == id)
                .ok_or(Error::NotFound)?;
            if e.revoked_at.is_some() {
                return Err(revoked());
            }
            if e.name == name {
                return Ok(false);
            }
            e.name = name.to_owned();
            Ok(true)
        })
    }

    /// Whether the device list marks this device revoked: the app then
    /// erases the device (spec 4.3). Brings the lists up to date first.
    pub fn is_this_device_revoked(&mut self) -> Result<bool> {
        self.maintain_lists(None)?;
        self.is_revoked_here()
    }

    fn is_revoked_here(&self) -> Result<bool> {
        let Some(me) = self.chain.device_id else {
            return Ok(false);
        };
        Ok(self
            .read_list::<DeviceEntry>()?
            .and_then(|d| d.body.entry(me).cloned())
            .is_some_and(|e| e.revoked_at.is_some()))
    }

    /// Bring the lists up to date, then apply `edit` to the device entries
    /// and write the next list if it says something changed. Refused on a
    /// revoked device.
    fn edit_devices(
        &mut self,
        edit: impl FnOnce(&mut Vec<DeviceEntry>) -> Result<bool>,
    ) -> Result<()> {
        self.maintain_lists(None)?;
        if self.is_revoked_here()? {
            return Err(revoked());
        }
        let current: Stored<DeviceEntry> = self.read_list()?.ok_or(Error::NotFound)?;
        let mut entries = current.body.entries.clone();
        if !edit(&mut entries)? {
            return Ok(());
        }
        self.write_list(Some(&current), entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev(n: u8, name: &str) -> DeviceEntry {
        DeviceEntry {
            device_id: Id([n; 16]),
            name: name.into(),
            kind: DeviceKind::Phone,
            mode: DeviceMode::Personal,
            added_at: 100,
            added_by: None,
            revoked_at: None,
        }
    }

    #[test]
    fn device_merge_is_commutative_revocation_wins() {
        let a = DeviceEntry {
            revoked_at: Some(500),
            added_at: 200,
            ..dev(1, "iPhone")
        };
        let b = DeviceEntry {
            revoked_at: Some(300),
            ..dev(1, "iPad")
        };
        let c = dev(1, "Mac");
        for (x, y) in [(&a, &b), (&a, &c), (&b, &c)] {
            assert_eq!(x.merge(y), y.merge(x));
            assert!(x.merge(y).revoked_at.is_some());
        }
        let ab = a.merge(&b);
        assert_eq!(ab.revoked_at, Some(300));
        assert_eq!(ab.added_at, 100);
        // Associative.
        assert_eq!(a.merge(&b).merge(&c), a.merge(&b.merge(&c)));
        // The preferring merge keeps the edit and still the revocation.
        let renamed = dev(1, "Nouveau nom");
        let m = renamed.merge_preferring(&b);
        assert_eq!(m.name, "Nouveau nom");
        assert_eq!(m.revoked_at, Some(300));
    }

    #[test]
    fn no_registration_without_a_persisted_chain() {
        use crate::crypto::{KdfParams, random_array};
        use crate::store::MemoryStore;
        use crate::{Error, IntegrityError};

        let kdf = KdfParams {
            m_kib: 8192,
            t: 1,
            p: 1,
            salt: random_array().unwrap(),
        };
        let (mut repo, _) = Repository::create_account(MemoryStore::new(), "pw", kdf).unwrap();
        // No id that could not outlive the session: no entry, no ghost.
        assert_eq!(repo.this_device_id(), None);
        assert_eq!(repo.devices().unwrap(), vec![]);
        assert_eq!(repo.this_device_id(), None);
        assert_eq!(
            repo.register_this_device("Mac", DeviceKind::Mac, DeviceMode::Personal),
            Err(Error::InvalidFormat(
                "device registration needs a sync store"
            ))
        );
        assert!(!repo.is_this_device_revoked().unwrap());
        assert_eq!(repo.vault_list().unwrap().len(), 1);

        // A list removed after this session accepted one is a rollback, not
        // a migration.
        let id = repo.account.params.account_id;
        repo.store.delete(RecordKind::VaultList, id).unwrap();
        assert_eq!(
            repo.vaults().unwrap_err(),
            Error::Integrity(IntegrityError::VaultListRollback)
        );
    }

    #[test]
    fn default_name_never_wins_a_merge() {
        let default = dev(1, DEFAULT_DEVICE_NAME);
        let real = dev(1, "Aaron");
        assert_eq!(default.merge(&real).name, "Aaron");
        assert_eq!(real.merge(&default).name, "Aaron");
    }

    #[test]
    fn device_names_are_checked() {
        assert!(check_name("iPhone de Camille").is_ok());
        assert!(check_name(&"é".repeat(64)).is_ok());
        assert!(check_name(&"é".repeat(65)).is_err());
        assert!(check_name("  ").is_err());
    }
}
