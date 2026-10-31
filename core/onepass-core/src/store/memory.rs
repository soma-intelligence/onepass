//! In-memory store, for tests.

use std::collections::BTreeMap;

use super::{Record, RecordKind, RecordStore, check_local_meta_key, check_local_meta_prefix};
use crate::chain::ChainState;
use crate::trust::TrustState;
use crate::{Error, Id, Result};

#[derive(Debug, Clone, Default)]
pub struct MemoryStore {
    records: BTreeMap<(RecordKind, Id), Record>,
    trust: Option<TrustState>,
    meta: BTreeMap<String, Vec<u8>>,
}

impl MemoryStore {
    pub fn new() -> MemoryStore {
        MemoryStore::default()
    }
}

impl RecordStore for MemoryStore {
    fn put(&mut self, r: Record) -> Result<()> {
        self.records.insert((r.kind, r.id), r);
        Ok(())
    }

    fn put_if_version(&mut self, r: Record, expected: Option<u64>) -> Result<()> {
        let current = self.records.get(&(r.kind, r.id)).map(|c| c.version);
        if current != expected {
            return Err(Error::Conflict);
        }
        self.records.insert((r.kind, r.id), r);
        Ok(())
    }

    fn get(&self, kind: RecordKind, id: Id) -> Result<Option<Record>> {
        Ok(self.records.get(&(kind, id)).cloned())
    }

    fn list(&self, kind: RecordKind) -> Result<Vec<Record>> {
        Ok(self
            .records
            .values()
            .filter(|r| r.kind == kind)
            .cloned()
            .collect())
    }

    fn delete(&mut self, kind: RecordKind, id: Id) -> Result<()> {
        self.records.remove(&(kind, id));
        Ok(())
    }

    fn local_meta(&self, key: &str) -> Result<Option<Vec<u8>>> {
        check_local_meta_key(key)?;
        Ok(self.meta.get(key).cloned())
    }

    fn local_meta_keys(&self, prefix: &str) -> Result<Vec<String>> {
        check_local_meta_prefix(prefix)?;
        Ok(self
            .meta
            .keys()
            .filter(|k| k.starts_with(prefix))
            .cloned()
            .collect())
    }

    fn set_local_meta(&mut self, key: &str, value: Option<&[u8]>) -> Result<()> {
        check_local_meta_key(key)?;
        match value {
            Some(v) => self.meta.insert(key.to_owned(), v.to_vec()),
            None => self.meta.remove(key),
        };
        Ok(())
    }

    /// All or nothing: a version mismatch or another meta value leaves
    /// both as they were.
    fn put_all_if_version_taking_meta(
        &mut self,
        writes: Vec<(Record, Option<u64>)>,
        key: &str,
        expected: &[u8],
    ) -> Result<()> {
        check_local_meta_key(key)?;
        if self.meta.get(key).map(Vec::as_slice) != Some(expected) {
            return Err(Error::Conflict);
        }
        let mut records = self.records.clone();
        for (r, version) in writes {
            if records.get(&(r.kind, r.id)).map(|c| c.version) != version {
                return Err(Error::Conflict);
            }
            records.insert((r.kind, r.id), r);
        }
        self.records = records;
        self.meta.remove(key);
        Ok(())
    }

    fn trust_state(&self) -> Result<Option<TrustState>> {
        Ok(self.trust.clone())
    }

    /// All or nothing: a version mismatch leaves records and trust as they
    /// were. The chain state is not kept here (as in the default).
    fn put_all_if_version_with_trust(
        &mut self,
        writes: Vec<(Record, Option<u64>)>,
        deletes: Vec<(RecordKind, Id)>,
        chain: Option<ChainState>,
        trust: &TrustState,
    ) -> Result<()> {
        let _ = chain;
        let mut records = self.records.clone();
        for (r, expected) in writes {
            if records.get(&(r.kind, r.id)).map(|c| c.version) != expected {
                return Err(Error::Conflict);
            }
            records.insert((r.kind, r.id), r);
        }
        for key in deletes {
            records.remove(&key);
        }
        self.records = records;
        self.trust = Some(trust.clone());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_trust_is_all_or_nothing() {
        let mut s = MemoryStore::new();
        assert_eq!(s.trust_state().unwrap(), None);
        let a = Id::new();
        let rec = |version, n| Record {
            id: a,
            kind: RecordKind::Item,
            version,
            data: vec![n],
        };
        let mut trust = crate::trust::tests::sample();
        s.put_all_if_version_with_trust(vec![(rec(1, 1), None)], vec![], None, &trust)
            .unwrap();
        assert_eq!(s.trust_state().unwrap(), Some(trust.clone()));
        let before = trust.clone();
        trust.add_revoked(&[Id([0xEE; 16])]);
        let r = s.put_all_if_version_with_trust(
            vec![(rec(2, 2), Some(9))],
            vec![(RecordKind::Item, a)],
            None,
            &trust,
        );
        assert_eq!(r, Err(Error::Conflict));
        assert_eq!(s.trust_state().unwrap(), Some(before));
        assert_eq!(s.get(RecordKind::Item, a).unwrap().unwrap().version, 1);
    }

    #[test]
    fn memory_store_behaves() {
        super::super::exercise(&mut MemoryStore::new());
    }
}
