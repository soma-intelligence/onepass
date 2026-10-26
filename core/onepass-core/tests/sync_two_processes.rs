//! Two processes (the app and the AutoFill extension) over one store file,
//! each with its own unlocked `Repository` and in-memory device state. The
//! persisted state is merged, so neither rewinds `last_seen`.

use std::path::Path;

use onepass_core::crypto::{KdfParams, SecretKey, random_array};
use onepass_core::model::{FieldValue, Item, ItemType, new_item};
use onepass_core::repo::Repository;
use onepass_core::store::{RecordKind, RecordStore};
use onepass_core::sync::SyncStore;
use onepass_core::{Error, Id, IntegrityError, Result};

const PASSWORD: &str = "Projet Atlas, Camille Durand";

fn kdf() -> KdfParams {
    KdfParams {
        m_kib: 8192,
        t: 1,
        p: 1,
        salt: random_array().unwrap(),
    }
}

fn login(vault: Id, user: &str) -> Item {
    let mut item = new_item(ItemType::Login, vault, "Exemple");
    item.field_mut("username").unwrap().value = FieldValue::Text(user.into());
    item
}

fn unlock(path: &Path, sk: &SecretKey) -> Repository<SyncStore> {
    let store = SyncStore::open(path).unwrap();
    let state = store.device_state().unwrap();
    Repository::unlock(store, PASSWORD, sk, state).unwrap()
}

fn integrity<T: std::fmt::Debug>(r: Result<T>) -> IntegrityError {
    match r {
        Err(Error::Integrity(e)) => e,
        other => panic!("expected an integrity error, got {other:?}"),
    }
}

/// Process A created the account; both processes are unlocked.
fn two_processes() -> (
    tempfile::TempDir,
    std::path::PathBuf,
    Repository<SyncStore>,
    Repository<SyncStore>,
    Id,
) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("onepass.sqlite");
    let store = SyncStore::open(&path).unwrap();
    let (mut a, sk) = Repository::create_account(store, PASSWORD, kdf()).unwrap();
    a.persist_device_state().unwrap();
    let v = a.vaults().unwrap().remove(0).id;
    let b = unlock(&path, &sk);
    (dir, path, a, b, v)
}

#[test]
fn two_repositories_never_rewind_last_seen() {
    let (_dir, path, mut a, mut b, v) = two_processes();
    let vault = a.vaults().unwrap().remove(0);
    let n = b.device_state().last_seen[&v].seq;

    // A saves: its manifest is n + 1. B only reads, still at n in memory.
    a.save_item(&vault, login(v, "a1")).unwrap();
    a.persist_device_state().unwrap();
    assert_eq!(b.device_state().last_seen[&v].seq, n);
    b.persist_device_state().unwrap();

    let stored = SyncStore::open(&path).unwrap().device_state().unwrap();
    assert_eq!(stored.last_seen[&v].seq, n + 1);
    assert_eq!(b.device_state().last_seen[&v].seq, n + 1);

    // B saves (n + 2), then A, whose memory is behind, saves again.
    b.save_item(&vault, login(v, "b1")).unwrap();
    b.persist_device_state().unwrap();
    a.save_item(&vault, login(v, "a2")).unwrap();
    a.persist_device_state().unwrap();
    let stored = SyncStore::open(&path).unwrap().device_state().unwrap();
    assert_eq!(stored.last_seen[&v].seq, n + 3);
    assert_eq!(a.items(&vault).unwrap().len(), 3);
}

#[test]
fn merged_state_still_detects_rollback() {
    let (_dir, path, mut a, mut b, v) = two_processes();
    let vault = a.vaults().unwrap().remove(0);

    a.save_item(&vault, login(v, "a1")).unwrap();
    let old = SyncStore::open(&path)
        .unwrap()
        .get(RecordKind::Manifest, v)
        .unwrap()
        .unwrap();
    a.persist_device_state().unwrap();
    b.persist_device_state().unwrap();
    b.save_item(&vault, login(v, "b1")).unwrap();
    b.persist_device_state().unwrap();
    a.save_item(&vault, login(v, "a2")).unwrap();
    a.persist_device_state().unwrap();

    // The store serves an older manifest again.
    let mut evil = SyncStore::open(&path).unwrap();
    evil.put(old).unwrap();

    assert_eq!(integrity(a.items(&vault)), IntegrityError::ManifestRollback);
    assert_eq!(integrity(b.items(&vault)), IntegrityError::ManifestRollback);
}
