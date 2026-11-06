//! Record zones in the local stores (sharing plan 2, Task 1).

use onepass_core::store::{MemoryStore, Record, RecordKind, RecordStore, Zone};
use onepass_core::sync::{RemoteChange, SyncStore};
use onepass_core::{Error, Id};

fn rec(kind: RecordKind, id: Id, version: u64, data: &[u8]) -> Record {
    Record {
        kind,
        id,
        version,
        data: data.to_vec(),
    }
}

fn remote(kind: RecordKind, id: Id, version: u64, data: Option<&[u8]>) -> RemoteChange {
    RemoteChange {
        kind,
        id,
        version,
        data: data.map(<[u8]>::to_vec),
        server_meta: Some(b"tag".to_vec()),
    }
}

fn stores() -> Vec<Box<dyn RecordStore>> {
    vec![
        Box::new(MemoryStore::new()),
        Box::new(SyncStore::open_in_memory().unwrap()),
    ]
}

#[test]
fn zone_key_round_trip() {
    let id = Id([7; 16]);
    for z in [
        Zone::Private,
        Zone::Vault(id),
        Zone::Contact(id),
        Zone::Family(id),
    ] {
        assert_eq!(Zone::from_key(&z.key()).unwrap(), z);
    }
    assert!(Zone::Private.key().is_empty());
    assert_eq!(Zone::Vault(id).key()[0], 1);
    assert_eq!(Zone::Contact(id).key()[0], 2);
    assert_eq!(Zone::Family(id).key()[0], 3);
    for bad in [vec![0u8; 16], vec![1u8; 18], {
        let mut b = vec![9u8];
        b.extend([0u8; 16]);
        b
    }] {
        assert!(matches!(Zone::from_key(&bad), Err(Error::InvalidFormat(_))));
    }
}

#[test]
fn same_id_in_two_zones_is_two_records() {
    let v = Id::new();
    let item = Id::new();
    for mut s in stores() {
        s.put_all_zoned(
            vec![
                (
                    Zone::Private,
                    rec(RecordKind::Item, item, 1, b"private"),
                    None,
                ),
                (
                    Zone::Vault(v),
                    rec(RecordKind::Item, item, 3, b"shared"),
                    None,
                ),
            ],
            vec![],
            None,
            &[],
        )
        .unwrap();
        assert_eq!(
            s.get(RecordKind::Item, item).unwrap().unwrap().data,
            b"private"
        );
        let shared = s
            .get_in(Zone::Vault(v), RecordKind::Item, item)
            .unwrap()
            .unwrap();
        assert_eq!(
            (shared.version, shared.data.as_slice()),
            (3, &b"shared"[..])
        );
        assert_eq!(
            s.list_in(Zone::Vault(v), RecordKind::Item).unwrap().len(),
            1
        );
        assert_eq!(s.zones().unwrap(), vec![Zone::Vault(v)]);
    }
}

#[test]
fn zoned_write_is_atomic() {
    let v = Id::new();
    let a = Id::new();
    let b = Id::new();
    for mut s in stores() {
        s.put_all_zoned(
            vec![(Zone::Vault(v), rec(RecordKind::Item, b, 1, b"one"), None)],
            vec![],
            None,
            &[],
        )
        .unwrap();
        let r = s.put_all_zoned(
            vec![
                (Zone::Private, rec(RecordKind::Item, a, 1, b"a"), None),
                // Wrong expected version in the shared zone.
                (Zone::Vault(v), rec(RecordKind::Item, b, 2, b"two"), Some(5)),
            ],
            vec![],
            None,
            &[],
        );
        assert!(matches!(r, Err(Error::Conflict)));
        assert!(s.get(RecordKind::Item, a).unwrap().is_none());
        assert_eq!(
            s.get_in(Zone::Vault(v), RecordKind::Item, b)
                .unwrap()
                .unwrap()
                .data,
            b"one"
        );
    }
}

#[test]
fn existing_file_migrates() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.sqlite");
    let id = Id::new();
    {
        let mut s = SyncStore::open(&path).unwrap();
        s.put(rec(RecordKind::VaultKey, id, 1, b"before")).unwrap();
    }
    // A file from before the zone tables.
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(
            "DROP TABLE zone_base; DROP TABLE zone_pending; DROP TABLE zone_staging;
             DROP TABLE zone_fetch;",
        )
        .unwrap();
    }
    let s = SyncStore::open(&path).unwrap();
    assert_eq!(
        s.get(RecordKind::VaultKey, id).unwrap().unwrap().data,
        b"before"
    );
    assert_eq!(
        s.get_in(Zone::Private, RecordKind::VaultKey, id)
            .unwrap()
            .unwrap()
            .version,
        1
    );
    assert_eq!(s.pending_changes().unwrap().len(), 1);
    assert!(s.zones().unwrap().is_empty());
}

#[test]
fn server_deletion_refused_per_zone() {
    let v = Id::new();
    let zone = Zone::Vault(v);
    let mut s = SyncStore::open_in_memory().unwrap();
    let m = Id::new();
    let l = Id::new();
    let i = Id::new();
    for (k, id) in [
        (RecordKind::Membership, m),
        (RecordKind::MemberLineage, l),
        (RecordKind::Item, i),
    ] {
        s.stage_remote_in(zone, remote(k, id, 1, Some(b"x")))
            .unwrap();
    }
    s.commit_remote_in(zone).unwrap();
    for (k, id) in [
        (RecordKind::Membership, m),
        (RecordKind::MemberLineage, l),
        (RecordKind::Item, i),
    ] {
        s.stage_remote_in(zone, remote(k, id, 1, None)).unwrap();
    }
    s.commit_remote_in(zone).unwrap();
    assert!(s.get_in(zone, RecordKind::Membership, m).unwrap().is_some());
    assert!(
        s.get_in(zone, RecordKind::MemberLineage, l)
            .unwrap()
            .is_some()
    );
    assert!(s.get_in(zone, RecordKind::Item, i).unwrap().is_none());
    // An immutable row served again with other bytes is ignored.
    s.stage_remote_in(zone, remote(RecordKind::MemberLineage, l, 1, Some(b"y")))
        .unwrap();
    s.commit_remote_in(zone).unwrap();
    assert_eq!(
        s.get_in(zone, RecordKind::MemberLineage, l)
            .unwrap()
            .unwrap()
            .data,
        b"x"
    );
}

#[test]
fn drop_zone_wipes_only_that_zone() {
    let v = Id::new();
    let w = Id::new();
    let id = Id::new();
    for mut s in stores() {
        s.put_all_zoned(
            vec![
                (Zone::Private, rec(RecordKind::Item, id, 1, b"p"), None),
                (Zone::Vault(v), rec(RecordKind::Item, id, 1, b"v"), None),
                (Zone::Vault(w), rec(RecordKind::Item, id, 1, b"w"), None),
            ],
            vec![],
            None,
            &[],
        )
        .unwrap();
        s.drop_zone(Zone::Vault(v)).unwrap();
        assert!(
            s.get_in(Zone::Vault(v), RecordKind::Item, id)
                .unwrap()
                .is_none()
        );
        assert!(
            s.get_in(Zone::Vault(w), RecordKind::Item, id)
                .unwrap()
                .is_some()
        );
        assert!(s.get(RecordKind::Item, id).unwrap().is_some());
        assert_eq!(s.zones().unwrap(), vec![Zone::Vault(w)]);
    }
}

#[test]
fn pending_changes_are_per_zone() {
    let v = Id::new();
    let w = Id::new();
    let a = Id::new();
    let b = Id::new();
    let mut s = SyncStore::open_in_memory().unwrap();
    s.put_all_zoned(
        vec![
            (Zone::Private, rec(RecordKind::VaultKey, a, 1, b"p"), None),
            (Zone::Vault(v), rec(RecordKind::Item, a, 1, b"v"), None),
            (Zone::Vault(w), rec(RecordKind::Item, b, 2, b"w"), None),
        ],
        vec![],
        None,
        &[],
    )
    .unwrap();
    let pv = s.pending_changes_in(Zone::Vault(v)).unwrap();
    assert_eq!(pv.len(), 1);
    assert_eq!(pv[0].data.as_deref(), Some(&b"v"[..]));
    assert_eq!(s.pending_changes_in(Zone::Vault(w)).unwrap()[0].id, b);
    assert_eq!(s.pending_changes().unwrap().len(), 1);
    // Pushed: the row moves to the base, nothing left pending.
    s.mark_pushed_in(Zone::Vault(v), RecordKind::Item, a, 1, Some(b"t".to_vec()))
        .unwrap();
    assert!(s.pending_changes_in(Zone::Vault(v)).unwrap().is_empty());
    assert_eq!(
        s.server_meta_in(Zone::Vault(v), RecordKind::Item, a)
            .unwrap(),
        Some(b"t".to_vec())
    );
    // A local deletion of a pushed row is queued; of a membership, refused.
    s.put_all_zoned(
        vec![],
        vec![(Zone::Vault(v), RecordKind::Item, a)],
        None,
        &[],
    )
    .unwrap();
    let pv = s.pending_changes_in(Zone::Vault(v)).unwrap();
    assert_eq!((pv.len(), pv[0].data.is_none()), (1, true));
    assert!(
        s.get_in(Zone::Vault(v), RecordKind::Item, a)
            .unwrap()
            .is_none()
    );
    assert!(matches!(
        s.put_all_zoned(
            vec![],
            vec![(Zone::Vault(v), RecordKind::Membership, a)],
            None,
            &[]
        ),
        Err(Error::InvalidFormat(_))
    ));
}

#[test]
fn full_fetch_settles_items_of_a_served_manifest() {
    let v = Id::new();
    let zone = Zone::Vault(v);
    let (i1, i2) = (Id::new(), Id::new());
    let mut s = SyncStore::open_in_memory().unwrap();
    s.stage_remote_in(zone, remote(RecordKind::Manifest, v, 1, Some(b"m1")))
        .unwrap();
    s.stage_remote_in(zone, remote(RecordKind::Item, i1, 1, Some(b"a")))
        .unwrap();
    s.stage_remote_in(zone, remote(RecordKind::Item, i2, 1, Some(b"b")))
        .unwrap();
    assert_eq!(s.commit_remote_in(zone).unwrap(), vec![v]);
    s.begin_full_fetch_in(zone).unwrap();
    s.stage_remote_in(zone, remote(RecordKind::Manifest, v, 2, Some(b"m2")))
        .unwrap();
    s.stage_remote_in(zone, remote(RecordKind::Item, i1, 1, Some(b"a")))
        .unwrap();
    s.commit_remote_in(zone).unwrap();
    assert!(s.get_in(zone, RecordKind::Item, i1).unwrap().is_some());
    assert!(s.get_in(zone, RecordKind::Item, i2).unwrap().is_none());
}

#[test]
fn default_store_refuses_shared_zones() {
    let dir = tempfile::tempdir().unwrap();
    let s = onepass_core::store::SqliteStore::open(&dir.path().join("s.sqlite")).unwrap();
    assert!(matches!(
        s.get_in(Zone::Vault(Id::new()), RecordKind::Item, Id::new()),
        Err(Error::Store(_))
    ));
}

#[test]
fn reset_wipes_shared_zones() {
    let v = Id::new();
    let mut s = SyncStore::open_in_memory().unwrap();
    s.put_all_zoned(
        vec![(
            Zone::Vault(v),
            rec(RecordKind::Item, Id::new(), 1, b"v"),
            None,
        )],
        vec![],
        None,
        &[],
    )
    .unwrap();
    s.reset().unwrap();
    assert!(s.zones().unwrap().is_empty());
}
