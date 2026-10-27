//! Record storage. A store keeps opaque records and is not trusted: the
//! `Repository` verifies everything it reads back.

mod memory;
mod sqlite;

pub use memory::MemoryStore;
pub use sqlite::SqliteStore;

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
        ] {
            assert_eq!(RecordKind::from_code(kind.code()).unwrap(), kind);
        }
        // Frozen codes: the on-disk and CloudKit encoding.
        assert_eq!(RecordKind::RestoreEpoch.code(), 7);
        assert_eq!(
            RecordKind::from_code(8).unwrap_err(),
            Error::InvalidFormat("record kind")
        );
        assert_eq!(
            RecordKind::from_code(0).unwrap_err(),
            Error::InvalidFormat("record kind")
        );
    }
}
