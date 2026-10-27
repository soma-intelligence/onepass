//! In-memory store, for tests.

use std::collections::BTreeMap;

use super::{Record, RecordKind, RecordStore};
use crate::{Error, Id, Result};

#[derive(Debug, Clone, Default)]
pub struct MemoryStore {
    records: BTreeMap<(RecordKind, Id), Record>,
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_store_behaves() {
        super::super::exercise(&mut MemoryStore::new());
    }
}
