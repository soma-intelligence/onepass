//! In-memory store, for tests.

use std::collections::BTreeMap;

use super::{
    AutofillRow, Record, RecordKind, RecordStore, Zone, check_local_meta_key,
    check_local_meta_prefix,
};
use crate::chain::ChainState;
use crate::share::ShareState;
use crate::trust::TrustState;
use crate::{Error, Id, Result};

#[derive(Debug, Clone, Default)]
pub struct MemoryStore {
    records: BTreeMap<(RecordKind, Id), Record>,
    trust: Option<TrustState>,
    meta: BTreeMap<String, Vec<u8>>,
    /// Shared zones (sharing plan 2): one table per zone.
    zoned: BTreeMap<Zone, BTreeMap<(RecordKind, Id), Record>>,
    /// Local state of each shared vault, never synced.
    shares: BTreeMap<Id, ShareState>,
    /// Autofill history rows `(seq, site tag, data)`, oldest first.
    autofill: Vec<AutofillRow>,
    autofill_seq: i64,
}

impl MemoryStore {
    pub fn new() -> MemoryStore {
        MemoryStore::default()
    }
}

impl RecordStore for MemoryStore {
    fn get_in(&self, zone: Zone, kind: RecordKind, id: Id) -> Result<Option<Record>> {
        match zone {
            Zone::Private => self.get(kind, id),
            _ => Ok(self
                .zoned
                .get(&zone)
                .and_then(|t| t.get(&(kind, id)))
                .cloned()),
        }
    }

    fn list_in(&self, zone: Zone, kind: RecordKind) -> Result<Vec<Record>> {
        match zone {
            Zone::Private => self.list(kind),
            _ => Ok(self
                .zoned
                .get(&zone)
                .map(|t| t.values().filter(|r| r.kind == kind).cloned().collect())
                .unwrap_or_default()),
        }
    }

    fn put_all_zoned(
        &mut self,
        writes: Vec<(Zone, Record, Option<u64>)>,
        deletes: Vec<(Zone, RecordKind, Id)>,
        trust: Option<&TrustState>,
        shares: &[ShareState],
    ) -> Result<()> {
        for (zone, r, expected) in &writes {
            if self.get_in(*zone, r.kind, r.id)?.map(|c| c.version) != *expected {
                return Err(Error::Conflict);
            }
            if r.kind.is_immutable()
                && self
                    .get_in(*zone, r.kind, r.id)?
                    .is_some_and(|old| old.data != r.data)
            {
                return Err(Error::Conflict);
            }
        }
        for (zone, kind, _) in &deletes {
            if zone.is_shared() && kind.server_deletion_refused() {
                return Err(Error::InvalidFormat("zone record deletion"));
            }
        }
        for (zone, r, _) in writes {
            match zone {
                Zone::Private => {
                    self.records.insert((r.kind, r.id), r);
                }
                _ => {
                    self.zoned
                        .entry(zone)
                        .or_default()
                        .insert((r.kind, r.id), r);
                }
            }
        }
        for (zone, kind, id) in deletes {
            match zone {
                Zone::Private => {
                    self.records.remove(&(kind, id));
                }
                _ => {
                    if let Some(t) = self.zoned.get_mut(&zone) {
                        t.remove(&(kind, id));
                    }
                }
            }
        }
        if let Some(t) = trust {
            self.trust = Some(t.clone());
        }
        for s in shares {
            self.shares.insert(s.vault_id, s.clone());
        }
        Ok(())
    }

    fn share_state(&self, vault: Id) -> Result<Option<ShareState>> {
        Ok(self.shares.get(&vault).cloned())
    }

    fn share_states(&self) -> Result<Vec<ShareState>> {
        Ok(self.shares.values().cloned().collect())
    }

    fn zones(&self) -> Result<Vec<Zone>> {
        Ok(self
            .zoned
            .iter()
            .filter(|(_, t)| !t.is_empty())
            .map(|(z, _)| *z)
            .collect())
    }

    fn drop_zone(&mut self, zone: Zone) -> Result<()> {
        if zone.is_shared() {
            self.zoned.remove(&zone);
        }
        if let Zone::Vault(id) = zone {
            self.shares.remove(&id);
        }
        Ok(())
    }

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

    fn keeps_autofill_history(&self) -> bool {
        true
    }

    fn autofill_append(
        &mut self,
        site_tag: &[u8; 32],
        data: &[u8],
        keep_per_site: usize,
        keep_total: usize,
    ) -> Result<()> {
        self.autofill_seq += 1;
        self.autofill
            .push((self.autofill_seq, *site_tag, data.to_vec()));
        let same = self.autofill.iter().filter(|r| r.1 == *site_tag).count();
        let mut drop_same = same.saturating_sub(keep_per_site);
        self.autofill.retain(|r| {
            if r.1 == *site_tag && drop_same > 0 {
                drop_same -= 1;
                false
            } else {
                true
            }
        });
        let extra = self.autofill.len().saturating_sub(keep_total);
        self.autofill.drain(..extra);
        Ok(())
    }

    fn autofill_rows(&self, site_tag: Option<&[u8; 32]>) -> Result<Vec<AutofillRow>> {
        Ok(self
            .autofill
            .iter()
            .filter(|r| site_tag.is_none_or(|t| r.1 == *t))
            .cloned()
            .collect())
    }

    fn autofill_delete(&mut self, seqs: &[i64]) -> Result<()> {
        self.autofill.retain(|r| !seqs.contains(&r.0));
        Ok(())
    }

    fn autofill_clear(&mut self) -> Result<usize> {
        let n = self.autofill.len();
        self.autofill.clear();
        Ok(n)
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

    /// `put_all_if_version_with_trust` if no trust state is stored.
    fn put_first_trust(
        &mut self,
        writes: Vec<(Record, Option<u64>)>,
        chain: Option<ChainState>,
        trust: &TrustState,
    ) -> Result<()> {
        if self.trust.is_some() {
            return Err(Error::Conflict);
        }
        self.put_all_if_version_with_trust(writes, Vec::new(), chain, trust)
    }

    /// `put_all_if_version_with_trust` if the trust state is `expected`.
    fn put_with_trust_cas(
        &mut self,
        writes: Vec<(Record, Option<u64>)>,
        deletes: Vec<(RecordKind, Id)>,
        chain: Option<ChainState>,
        expected: &TrustState,
        trust: &TrustState,
    ) -> Result<()> {
        if self.trust.as_ref() != Some(expected) {
            return Err(Error::Conflict);
        }
        self.put_all_if_version_with_trust(writes, deletes, chain, trust)
    }

    /// Everything goes if the trust state is `expected`.
    fn erase_device(&mut self, expected: &TrustState) -> Result<()> {
        if self.trust.as_ref() != Some(expected) {
            return Err(Error::Conflict);
        }
        *self = MemoryStore::default();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn erase_device_is_conditional_on_the_trust_state() {
        let mut s = MemoryStore::new();
        let rec = Record {
            id: Id::new(),
            kind: RecordKind::Item,
            version: 1,
            data: vec![1],
        };
        let trust = crate::trust::tests::sample();
        s.put_all_if_version_with_trust(vec![(rec.clone(), None)], vec![], None, &trust)
            .unwrap();
        let mut other = trust.clone();
        other.ignore([0xAB; 32]);
        assert_eq!(s.erase_device(&other), Err(Error::Conflict));
        assert_eq!(s.get(rec.kind, rec.id).unwrap(), Some(rec.clone()));
        s.erase_device(&trust).unwrap();
        assert_eq!(s.get(rec.kind, rec.id).unwrap(), None);
        assert_eq!(s.trust_state().unwrap(), None);
    }

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

        // Conditional on the stored trust state.
        let stored = s.trust_state().unwrap().unwrap();
        let r = s.put_with_trust_cas(vec![(rec(9, 1), None)], vec![], None, &trust, &trust);
        assert_eq!(r, Err(Error::Conflict));
        assert_eq!(s.trust_state().unwrap(), Some(stored.clone()));
        s.put_with_trust_cas(vec![], vec![], None, &stored, &trust)
            .unwrap();
        assert_eq!(s.trust_state().unwrap(), Some(trust.clone()));
    }

    #[test]
    fn memory_store_behaves() {
        super::super::exercise(&mut MemoryStore::new());
    }
}
