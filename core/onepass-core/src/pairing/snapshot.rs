//! The store snapshot a full grant carries (spec 5.1, ruling B10): every
//! record as the server holds it, already encrypted and signed. The
//! newcomer imports it as a remote fetch (`SyncStore::stage_remote` then
//! `commit_remote`), so every check of a hostile store applies.

use std::collections::BTreeSet;

use crate::store::{Record, RecordKind};
use crate::sync::{MAX_RECORD_BYTES, RemoteChange, SyncStore};
use crate::{Error, Result};

use super::messages::SnapshotRecord;

/// Largest snapshot, postcard serialized.
pub const MAX_SNAPSHOT_BYTES: usize = 50 * 1024 * 1024;

impl SnapshotRecord {
    pub fn from_record(r: &Record) -> SnapshotRecord {
        SnapshotRecord {
            kind: r.kind.code(),
            id: r.id,
            version: r.version,
            data: r.data.clone(),
        }
    }

    /// The change to stage on the newcomer. It has no server metadata yet.
    pub fn to_remote_change(&self) -> Result<RemoteChange> {
        Ok(RemoteChange {
            kind: RecordKind::from_code(self.kind)?,
            id: self.id,
            version: self.version,
            data: Some(self.data.clone()),
            server_meta: None,
        })
    }
}

/// The snapshot of `store`: its `base` rows, refused above
/// `MAX_SNAPSHOT_BYTES`.
pub fn snapshot_from_store(store: &SyncStore) -> Result<Vec<SnapshotRecord>> {
    let snapshot: Vec<SnapshotRecord> = store
        .export_records()?
        .iter()
        .map(SnapshotRecord::from_record)
        .collect();
    check_snapshot_size(&snapshot)?;
    Ok(snapshot)
}

/// Refuse a snapshot above `MAX_SNAPSHOT_BYTES` serialized.
pub fn check_snapshot_size(snapshot: &[SnapshotRecord]) -> Result<()> {
    let size = postcard::experimental::serialized_size(snapshot)
        .map_err(|_| Error::InvalidFormat("pairing snapshot"))?;
    if size > MAX_SNAPSHOT_BYTES {
        return Err(Error::InvalidFormat("pairing snapshot too large"));
    }
    Ok(())
}

/// The size cap, plus what the store would refuse anyway: an unknown kind,
/// a record above `MAX_RECORD_BYTES`, or one key twice.
pub(crate) fn check_snapshot(snapshot: &[SnapshotRecord]) -> Result<()> {
    check_snapshot_size(snapshot)?;
    let mut keys = BTreeSet::new();
    for r in snapshot {
        RecordKind::from_code(r.kind)?;
        if r.data.len() > MAX_RECORD_BYTES || !keys.insert((r.kind, r.id)) {
            return Err(Error::InvalidFormat("pairing snapshot"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Id;
    use crate::store::RecordStore;

    fn remote(kind: RecordKind, id: Id, data: &[u8]) -> RemoteChange {
        RemoteChange {
            kind,
            id,
            version: 1,
            data: Some(data.to_vec()),
            server_meta: Some(b"tag".to_vec()),
        }
    }

    #[test]
    fn export_takes_base_rows_only() {
        let mut s = SyncStore::open_in_memory().unwrap();
        let a = Id::new();
        let b = Id::new();
        s.stage_remote(remote(RecordKind::Item, b, b"item"))
            .unwrap();
        s.stage_remote(remote(RecordKind::Keyset, a, b"keyset"))
            .unwrap();
        s.commit_remote().unwrap();
        // A local write stays pending: never in the snapshot.
        s.put(Record {
            id: Id::new(),
            kind: RecordKind::Item,
            version: 1,
            data: b"local".to_vec(),
        })
        .unwrap();

        let snap = snapshot_from_store(&s).unwrap();
        assert_eq!(snap.len(), 2);
        assert_eq!(snap[0].kind, RecordKind::Keyset.code());
        assert_eq!(snap[0].data, b"keyset");
        assert_eq!(snap[1].id, b);
        let c = snap[1].to_remote_change().unwrap();
        assert_eq!(c.kind, RecordKind::Item);
        assert_eq!(c.data.as_deref(), Some(&b"item"[..]));
    }

    #[test]
    fn check_refuses_bad_records() {
        let r = SnapshotRecord {
            kind: 5,
            id: Id::new(),
            version: 1,
            data: vec![1],
        };
        check_snapshot(std::slice::from_ref(&r)).unwrap();
        assert!(check_snapshot(&[r.clone(), r.clone()]).is_err());
        let mut unknown = r.clone();
        unknown.kind = 99;
        assert!(check_snapshot(&[unknown]).is_err());
        let mut big = r;
        big.data = vec![0; MAX_RECORD_BYTES + 1];
        assert!(check_snapshot(&[big]).is_err());
    }
}
