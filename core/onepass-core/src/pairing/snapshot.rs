//! The store snapshot a full grant carries (spec 5.1, ruling B10): every
//! record as the server holds it, already encrypted and signed. The
//! newcomer imports it as a remote fetch (`SyncStore::stage_remote` then
//! `commit_remote`), so every check of a hostile store applies.

use std::collections::BTreeSet;

use crate::chain::ChainState;
use crate::device_keys::DevicePublic;
use crate::lineage::{MAX_ROSTER, RosterEntry};
use crate::store::{Record, RecordKind, RecordStore};
use crate::sync::{MAX_RECORD_BYTES, RemoteChange, SyncStore};
use crate::trust::{DeviceLineageState, LineageHead, TrustLevel, TrustState};
use crate::{Error, Result};

use super::messages::{DeviceInfo, FullGrantV2, SnapshotRecord, TrustSnapshot};
use super::refused;

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

/// A trust snapshot `me` can pin (spec 5.2): well formed
/// (`TrustSnapshot::check`), the approver is another device, `me` is not
/// revoked along the chain, and a roster that already lists `me` (a
/// re-pair, ruling A9) pins its own keys.
pub fn check_trust_for(trust: &TrustSnapshot, me: &DevicePublic) -> Result<()> {
    trust.check()?;
    if trust.approver.device_id == me.device_id || trust.revoked().contains(&me.device_id) {
        return Err(refused("trust snapshot"));
    }
    if let Some(e) = trust.roster.iter().find(|e| e.device_id == me.device_id)
        && (e.sign_pub != me.sign_pub || e.kem_pub != me.kem_pub)
    {
        return Err(refused("trust snapshot"));
    }
    Ok(())
}

/// This device's roster entry as its approver writes it (spec 6.4): the
/// Hello's name and kind, the granted mode, introduced by the approver.
pub fn newcomer_entry(me: &DevicePublic, info: &DeviceInfo, grant: &FullGrantV2) -> RosterEntry {
    RosterEntry {
        device_id: me.device_id,
        sign_pub: me.sign_pub.clone(),
        kem_pub: me.kem_pub.clone(),
        name: info.name.clone(),
        kind: info.kind,
        mode: grant.full.mode,
        introduced_by: Some(grant.trust.approver.device_id),
    }
}

/// The trust state a newcomer pins from a `FullV2` (spec 5.2, 7.4): the
/// approver's head and identity, its roster plus this device (as the
/// approver's intro lists it), every device trusted `Verified` (the SAS
/// authenticates the approver, and the approver vouches for the rest),
/// every revocation along the chain, state `Current`.
pub fn trust_from_grant(
    grant: &FullGrantV2,
    me: &DevicePublic,
    info: &DeviceInfo,
) -> Result<TrustState> {
    check_trust_for(&grant.trust, me)?;
    let head = grant.trust.head().ok_or(refused("trust snapshot"))?;
    let mut roster = grant.trust.roster.clone();
    if !roster.iter().any(|e| e.device_id == me.device_id) {
        roster.push(newcomer_entry(me, info, grant));
        roster.sort_by_key(|e| e.device_id);
    }
    if roster.len() > MAX_ROSTER {
        return Err(refused("roster full"));
    }
    let mut trust = TrustState::new(
        grant.full.account_id,
        me.clone(),
        LineageHead {
            generation: head.generation(),
            hash: head.hash(),
        },
        head.identity_pub().clone(),
        roster,
        DeviceLineageState::Current,
    );
    trust.levels = trust
        .roster
        .iter()
        .map(|e| (e.device_id, TrustLevel::Verified))
        .collect();
    trust.add_revoked(&grant.trust.revoked());
    Ok(trust)
}

/// Import a `FullV2` into an empty store (spec 5.2, 7.4): the snapshot
/// staged and committed as a remote fetch (every check of a hostile store
/// applies), this device's id recorded, then the trust state pinned
/// (`trust_from_grant`). Refused on a store that holds a trust state
/// already: a device that holds the account re-pairs as a follow
/// (`crate::repo::pairing::repair_from_grant`, ruling A9). The caller then
/// unlocks with the password and the granted Secret Key.
pub fn import_full_v2(
    store: &mut SyncStore,
    grant: &FullGrantV2,
    me: &DevicePublic,
    info: &DeviceInfo,
) -> Result<TrustState> {
    if RecordStore::trust_state(store)?.is_some() {
        return Err(refused("store holds a trust state"));
    }
    let trust = trust_from_grant(grant, me, info)?;
    for r in &grant.full.snapshot {
        store.stage_remote(r.to_remote_change()?)?;
    }
    store.commit_remote()?;
    store.set_chain_state(&ChainState {
        device_id: Some(me.device_id),
        ..store.chain_state()?
    })?;
    store.put_all_if_version_with_trust(Vec::new(), Vec::new(), None, &trust)?;
    Ok(trust)
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
