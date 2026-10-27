//! Record storage. A store keeps opaque records and is not trusted: the
//! `Repository` verifies everything it reads back.

mod memory;
mod sqlite;

pub use memory::MemoryStore;
pub use sqlite::SqliteStore;

use crate::chain::ChainState;
use crate::{Error, Id, Result};

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
            Self::DeviceList => 7,
            Self::VaultList => 8,
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
            7 => Self::DeviceList,
            8 => Self::VaultList,
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
            RecordKind::DeviceList,
            RecordKind::VaultList,
        ] {
            assert_eq!(RecordKind::from_code(kind.code()).unwrap(), kind);
        }
        assert_eq!(
            RecordKind::from_code(0).unwrap_err(),
            Error::InvalidFormat("record kind")
        );
        assert_eq!(
            RecordKind::from_code(9).unwrap_err(),
            Error::InvalidFormat("record kind")
        );
    }
}
