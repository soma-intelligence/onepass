//! Record storage. A store keeps opaque records and is not trusted: the
//! `Repository` verifies everything it reads back.

mod memory;
mod sqlite;

pub use memory::MemoryStore;
pub use sqlite::SqliteStore;

use crate::chain::ChainState;
use crate::{Error, Id, IntegrityError, Result};

/// What a record holds. The numeric codes are the on-disk encoding: append
/// only, never renumber.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RecordKind {
    AccountParams,
    Keyset,
    VaultKey,
    VaultMeta,
    Item,
    Manifest,
    /// The account's signed restore epoch (one record, id = account id).
    RestoreEpoch,
    /// The signed device list, id = account id, version = its seq.
    DeviceList,
    /// The signed vault list, id = account id, version = its seq.
    VaultList,
}

impl RecordKind {
    pub fn code(self) -> u8 {
        match self {
            Self::AccountParams => 1,
            Self::Keyset => 2,
            Self::VaultKey => 3,
            Self::VaultMeta => 4,
            Self::Item => 5,
            Self::Manifest => 6,
            Self::RestoreEpoch => 7,
            Self::DeviceList => 8,
            Self::VaultList => 9,
        }
    }

    pub fn from_code(code: u8) -> Result<RecordKind> {
        Ok(match code {
            1 => Self::AccountParams,
            2 => Self::Keyset,
            3 => Self::VaultKey,
            4 => Self::VaultMeta,
            5 => Self::Item,
            6 => Self::Manifest,
            7 => Self::RestoreEpoch,
            8 => Self::DeviceList,
            9 => Self::VaultList,
            _ => return Err(Error::InvalidFormat("record kind")),
        })
    }
}

/// A stored record. Only `id`, `kind` and the opaque `version` are in clear.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub id: Id,
    pub kind: RecordKind,
    pub version: u64,
    pub data: Vec<u8>,
}

/// A key-value store of records, keyed by `(kind, id)`. `put` replaces the
/// record with the same key; `delete` of a missing record is not an error.
pub trait RecordStore {
    fn put(&mut self, r: Record) -> Result<()>;
    /// Write `r` only if the stored record with its key has version
    /// `expected` (`None`: only if there is no such record), atomically.
    /// Otherwise nothing is written and the error is `Error::Conflict`.
    fn put_if_version(&mut self, r: Record, expected: Option<u64>) -> Result<()>;
    fn get(&self, kind: RecordKind, id: Id) -> Result<Option<Record>>;
    fn list(&self, kind: RecordKind) -> Result<Vec<Record>>;
    fn delete(&mut self, kind: RecordKind, id: Id) -> Result<()>;

    /// The restore epoch this device accepted or issued last, with the
    /// SHA-256 of its record data, if the store keeps it (device-local, not
    /// synced). Used to tell two different epochs with the same number
    /// apart (a fork). The default keeps nothing: the check is then skipped.
    fn restore_epoch_mark(&self) -> Result<Option<(u64, [u8; 32])>> {
        Ok(None)
    }

    /// Remember the mark of `restore_epoch_mark`. The default drops it.
    fn set_restore_epoch_mark(&mut self, _epoch: u64, _hash: [u8; 32]) -> Result<()> {
        Ok(())
    }

    /// The rows of `vault` (its manifest, its item records) that the
    /// server replaced or removed since the vault last loaded cleanly, for
    /// a store that keeps the device's own copy when the server falls
    /// behind (`crate::sync::SyncStore`). `None` (the default): the store
    /// keeps no such copy, and a vault that fails its checks is an error.
    fn kept_rows(&self, _vault: Id) -> Result<Option<Vec<Record>>> {
        Ok(None)
    }

    /// Make the device's verified copy of `vault` the visible one again,
    /// as pending writes: `manifest` (if it is not already the visible
    /// one), the item records `restore` it lists that only the kept rows
    /// still hold, and deletions of the vault's visible item records it
    /// does not list (`unlisted`). Done for a `write`, or when the server
    /// went back to an older manifest (so that the next push restores the
    /// server's copy); otherwise nothing is written. Only called when
    /// `kept_rows` is `Some`. The default refuses.
    fn keep_local_copy(
        &mut self,
        _vault: Id,
        _manifest: &Record,
        _restore: &[Record],
        _unlisted: &[Id],
        _write: bool,
    ) -> Result<()> {
        Err(Error::Store("no local copy".into()))
    }

    /// What the repository learned about a vault's server state, for the
    /// sync health (`crate::sync::VaultSyncHealth`). The default ignores it.
    fn vault_event(&mut self, _vault: Id, _event: VaultEvent) -> Result<()> {
        Ok(())
    }

    /// Write every record only if the stored record with its key has the
    /// version paired with it (`None`: no such record), all or nothing:
    /// on a conflict nothing is written (`Error::Conflict`). The default
    /// checks every version, then puts in order, which is atomic only for a
    /// store whose `put` cannot fail (in memory); a persistent store
    /// overrides it with one transaction (`SqliteStore`, `SyncStore`).
    fn put_all_if_version(&mut self, writes: Vec<(Record, Option<u64>)>) -> Result<()> {
        for (r, expected) in &writes {
            if self.get(r.kind, r.id)?.map(|c| c.version) != *expected {
                return Err(Error::Conflict);
            }
        }
        for (r, _) in writes {
            self.put(r)?;
        }
        Ok(())
    }

    /// `put_all_if_version`, then delete every `(kind, id)` of `deletes` in
    /// order, all or nothing where the store can: on a conflict nothing is
    /// written or deleted (`Error::Conflict`). The default writes then
    /// deletes, which is atomic only for a store whose `put` and `delete`
    /// cannot fail (in memory); a persistent store overrides it with one
    /// transaction (`SqliteStore`, `SyncStore`). A deletion the store
    /// refuses (a signed list record) fails the whole call there.
    fn put_all_if_version_and_delete(
        &mut self,
        writes: Vec<(Record, Option<u64>)>,
        deletes: Vec<(RecordKind, Id)>,
    ) -> Result<()> {
        self.put_all_if_version(writes)?;
        for (kind, id) in deletes {
            self.delete(kind, id)?;
        }
        Ok(())
    }

    /// The pinned chain state this store keeps for the device, read by the
    /// `Repository` unlock functions. Only `SyncStore` persists one (meta key
    /// `chain`); other stores give the default, so each session pins on
    /// first use.
    fn chain_state(&self) -> Result<ChainState> {
        Ok(ChainState::default())
    }

    /// Whether `chain_state` gives back, in a later session, the chain state
    /// saved with `put_all_if_version_with_chain` (only `SyncStore`). A
    /// device registers itself in the device list only on such a store: its
    /// id must outlive the session.
    fn persists_chain(&self) -> bool {
        false
    }

    /// `put_all_if_version`, and on a store that persists the chain state,
    /// save `chain` in the same transaction (all or nothing). Other stores
    /// only write the records.
    fn put_all_if_version_with_chain(
        &mut self,
        writes: Vec<(Record, Option<u64>)>,
        chain: &ChainState,
    ) -> Result<()> {
        let _ = chain;
        self.put_all_if_version(writes)
    }
}

/// What the repository reports to the store about one vault
/// (`RecordStore::vault_event`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultEvent {
    /// The visible copy loaded and passed every check.
    Clean,
    /// The server's state failed the checks (`cause`); the device serves
    /// its own verified copy, manifest seq `seq`, instead.
    Behind { seq: u64, cause: IntegrityError },
    /// The rebase verified and adopted the server's newer state.
    CaughtUp,
    /// Nothing safe to serve or merge: no verified local copy, or a server
    /// manifest that forks from it (`seq`: the local copy's, 0 for none).
    Alert { seq: u64, cause: IntegrityError },
    /// A newer restore epoch with this vault among its heads was accepted:
    /// the owner took a safe exit (maybe on another device), so an alert
    /// from a fork now clears like one from staying behind, once the
    /// server serves the head cleanly.
    EpochAccepted,
}

/// Shared behavior checks, run against every store.
#[cfg(test)]
pub(crate) fn exercise(store: &mut dyn RecordStore) {
    let a = Id::new();
    let b = Id::new();
    let rec = |id, kind, version, data: &[u8]| Record {
        id,
        kind,
        version,
        data: data.to_vec(),
    };
    assert_eq!(store.get(RecordKind::Item, a).unwrap(), None);
    store.put(rec(a, RecordKind::Item, 1, b"one")).unwrap();
    store.put(rec(b, RecordKind::Item, 7, b"two")).unwrap();
    // Same id, other kind: a distinct record.
    store.put(rec(a, RecordKind::Manifest, 3, b"m")).unwrap();
    assert_eq!(
        store.get(RecordKind::Item, a).unwrap(),
        Some(rec(a, RecordKind::Item, 1, b"one"))
    );
    // Replace.
    store.put(rec(a, RecordKind::Item, 2, b"uno")).unwrap();
    let mut items = store.list(RecordKind::Item).unwrap();
    items.sort_by_key(|r| r.id);
    assert_eq!(
        items,
        vec![
            rec(a, RecordKind::Item, 2, b"uno"),
            rec(b, RecordKind::Item, 7, b"two")
        ]
    );
    assert_eq!(store.list(RecordKind::Keyset).unwrap(), vec![]);
    store.delete(RecordKind::Item, a).unwrap();
    store.delete(RecordKind::Item, a).unwrap();
    assert_eq!(store.get(RecordKind::Item, a).unwrap(), None);
    assert!(store.get(RecordKind::Manifest, a).unwrap().is_some());
    assert_eq!(store.list(RecordKind::Item).unwrap().len(), 1);

    // Conditional writes.
    let c = Id::new();
    store
        .put_if_version(rec(c, RecordKind::Manifest, 1, b"m1"), None)
        .unwrap();
    assert_eq!(
        store.put_if_version(rec(c, RecordKind::Manifest, 1, b"x"), None),
        Err(Error::Conflict)
    );
    store
        .put_if_version(rec(c, RecordKind::Manifest, 2, b"m2"), Some(1))
        .unwrap();
    assert_eq!(
        store.put_if_version(rec(c, RecordKind::Manifest, 2, b"y"), Some(1)),
        Err(Error::Conflict)
    );
    assert_eq!(
        store.put_if_version(rec(Id::new(), RecordKind::Manifest, 2, b"z"), Some(1)),
        Err(Error::Conflict)
    );
    assert_eq!(
        store.get(RecordKind::Manifest, c).unwrap(),
        Some(rec(c, RecordKind::Manifest, 2, b"m2"))
    );
    // Same id, other kind: not the same record.
    store
        .put_if_version(rec(c, RecordKind::Item, 9, b"i"), None)
        .unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_codes_roundtrip() {
        for kind in [
            RecordKind::AccountParams,
            RecordKind::Keyset,
            RecordKind::VaultKey,
            RecordKind::VaultMeta,
            RecordKind::Item,
            RecordKind::Manifest,
            RecordKind::RestoreEpoch,
            RecordKind::DeviceList,
            RecordKind::VaultList,
        ] {
            assert_eq!(RecordKind::from_code(kind.code()).unwrap(), kind);
        }
        // Frozen codes: the on-disk and CloudKit encoding.
        assert_eq!(RecordKind::RestoreEpoch.code(), 7);
        assert_eq!(RecordKind::DeviceList.code(), 8);
        assert_eq!(RecordKind::VaultList.code(), 9);
        assert_eq!(
            RecordKind::from_code(10).unwrap_err(),
            Error::InvalidFormat("record kind")
        );
        assert_eq!(
            RecordKind::from_code(0).unwrap_err(),
            Error::InvalidFormat("record kind")
        );
        assert_eq!(
            RecordKind::from_code(u8::MAX).unwrap_err(),
            Error::InvalidFormat("record kind")
        );
    }
}
