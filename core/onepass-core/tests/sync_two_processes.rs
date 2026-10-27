//! Two processes (the app and the AutoFill extension) over one store file,
//! each with its own unlocked `Repository` and in-memory device state. The
//! persisted state is merged, so neither rewinds `last_seen`.

use std::path::Path;

use onepass_core::chain::ChainState;
use onepass_core::crypto::{KdfParams, SecretKey, random_array};
use onepass_core::devices::{DeviceKind, DeviceMode};
use onepass_core::model::{FieldValue, Item, ItemType, new_item};
use onepass_core::repo::Repository;
use onepass_core::store::{MemoryStore, RecordKind, RecordStore};
use onepass_core::sync::SyncStore;
use onepass_core::vault::VaultMeta;
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

/// Every record of `repo`'s store, copied into a fresh upstream.
fn upstream_of(repo: &Repository<SyncStore>) -> MemoryStore {
    let mut up = MemoryStore::new();
    for kind in [
        RecordKind::AccountParams,
        RecordKind::Keyset,
        RecordKind::VaultKey,
        RecordKind::VaultMeta,
        RecordKind::Item,
        RecordKind::Manifest,
    ] {
        for r in repo.store().list(kind).unwrap() {
            up.put(r).unwrap();
        }
    }
    up
}

/// Travel Mode (milestone 7) drops a parked vault from the device state on
/// purpose; the merge of milestone 3 must not bring the stored entry back,
/// while it still keeps what another process saw of the other vaults.
#[test]
fn merge_does_not_resurrect_a_vault_parked_by_travel_mode() {
    let (_dir, path, mut a, _b, v) = two_processes();
    let vault = a.vaults().unwrap().remove(0);
    a.save_item(&vault, login(v, "a1")).unwrap();
    a.persist_device_state().unwrap();
    let up = upstream_of(&a);

    let state = a.enter_travel(&up).unwrap();
    assert!(state.parked.contains_key(&v));
    assert!(!a.device_state().last_seen.contains_key(&v));
    a.persist_device_state().unwrap();
    assert!(!a.device_state().last_seen.contains_key(&v));
    let stored = SyncStore::open(&path).unwrap().device_state().unwrap();
    assert!(!stored.last_seen.contains_key(&v));

    // A later persist does not bring it back either.
    a.persist_device_state().unwrap();
    assert!(
        !SyncStore::open(&path)
            .unwrap()
            .device_state()
            .unwrap()
            .last_seen
            .contains_key(&v)
    );

    // Back from travel: the parked entry returns and persists as usual.
    a.exit_travel(&up, &state).unwrap();
    a.persist_device_state().unwrap();
    let stored = SyncStore::open(&path).unwrap().device_state().unwrap();
    assert_eq!(stored.last_seen[&v], state.parked[&v]);
}

/// The same `seq` with another hash in the stored state is a fork: the
/// merge refuses it before writing, like `adopt_device_state`, so the stored
/// and in-memory states both stay as they were.
#[test]
fn merge_refuses_a_forked_entry_and_changes_nothing() {
    let (_dir, path, mut a, _b, v) = two_processes();
    let mine = a.device_state().last_seen[&v].clone();
    let mut forged = SyncStore::open(&path).unwrap().device_state().unwrap();
    let mut other = mine.clone();
    other.hash[0] ^= 0xff;
    forged.last_seen.insert(v, other);
    SyncStore::open(&path)
        .unwrap()
        .set_device_state(&forged)
        .unwrap();
    let before = a.device_state().clone();

    assert_eq!(
        integrity(a.persist_device_state()),
        IntegrityError::ManifestRollback
    );
    assert_eq!(a.device_state(), &before);
    assert_eq!(
        SyncStore::open(&path).unwrap().device_state().unwrap(),
        forged
    );
}

/// The merged pin keeps the higher KDF floor: a process whose memory pin
/// is older never lowers the floor another process raised.
#[test]
fn merge_keeps_the_higher_kdf_floor() {
    let (_dir, path, mut a, mut b, _v) = two_processes();
    let low = a.device_state().pinned.clone().unwrap().kdf_floor;
    let mut raised = SyncStore::open(&path).unwrap().device_state().unwrap();
    let floor = &mut raised.pinned.as_mut().unwrap().kdf_floor;
    floor.m_kib = low.m_kib * 2;
    floor.t = low.t + 1;
    let raised_floor = floor.clone();
    SyncStore::open(&path)
        .unwrap()
        .set_device_state(&raised)
        .unwrap();

    a.persist_device_state().unwrap();
    let merged = &a.device_state().pinned.as_ref().unwrap().kdf_floor;
    assert_eq!(
        (merged.m_kib, merged.t, merged.p),
        (raised_floor.m_kib, raised_floor.t, low.p)
    );
    let stored = SyncStore::open(&path).unwrap().device_state().unwrap();
    assert_eq!(&stored.pinned.unwrap().kdf_floor, merged);

    // An equal floor keeps the memory salt.
    b.persist_device_state().unwrap();
    b.persist_device_state().unwrap();
    let again = &b.device_state().pinned.as_ref().unwrap().kdf_floor;
    assert_eq!((again.m_kib, again.t), (raised_floor.m_kib, raised_floor.t));
}

fn vault_meta(name: &str) -> VaultMeta {
    VaultMeta {
        name: name.into(),
        icon: "key".into(),
        color: "blue".into(),
        travel_safe: false,
        mcp_access: false,
    }
}

/// A deleted vault (signed vault list) stays forgotten: the other process,
/// which read it before the deletion, neither brings its entry back into
/// the stored `last_seen` nor reports it missing.
#[test]
fn merge_does_not_resurrect_a_deleted_vault() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("onepass.sqlite");
    let store = SyncStore::open(&path).unwrap();
    let (mut a, sk) = Repository::create_account(store, PASSWORD, kdf()).unwrap();
    let travail = a.create_vault(vault_meta("Travail")).unwrap();
    a.persist_device_state().unwrap();
    let mut b = unlock(&path, &sk);
    b.items(&travail).unwrap();
    assert!(b.device_state().last_seen.contains_key(&travail.id));

    a.delete_vault(&travail).unwrap();
    a.persist_device_state().unwrap();
    b.persist_device_state().unwrap();

    let stored = SyncStore::open(&path).unwrap().device_state().unwrap();
    assert!(!stored.last_seen.contains_key(&travail.id));
    assert!(!b.device_state().last_seen.contains_key(&travail.id));
    assert_eq!(b.vaults().unwrap().len(), 1);
    // A later persist of either process keeps it out.
    a.persist_device_state().unwrap();
    let stored = SyncStore::open(&path).unwrap().device_state().unwrap();
    assert!(!stored.last_seen.contains_key(&travail.id));
}

/// The vault list pin of the chain state never goes back: a process that
/// unlocked before the other wrote a newer list persists its older pin,
/// and the stored one stays, so a later session still refuses a store that
/// serves the older list.
#[test]
fn merge_never_rewinds_the_vault_list_pin() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("onepass.sqlite");
    let store = SyncStore::open(&path).unwrap();
    let (mut a, sk) = Repository::create_account(store, PASSWORD, kdf()).unwrap();
    a.persist_device_state().unwrap();
    let mut b = unlock(&path, &sk);
    let old = b.chain().vault_list.unwrap();

    a.create_vault(vault_meta("Travail")).unwrap();
    a.persist_device_state().unwrap();
    let new = a.chain().vault_list.unwrap();
    assert!(new.seq > old.seq);
    b.persist_device_state().unwrap();

    let stored = SyncStore::open(&path).unwrap().chain_state().unwrap();
    assert_eq!(stored.vault_list, Some(new));
    assert_eq!(b.chain().vault_list, Some(new));
    assert_eq!(b.vaults().unwrap().len(), 2);
}

/// Two processes of one device that were both unlocked before it had an id
/// (an account from before the device list): the second to register finds
/// the id the first one saved, instead of listing the device twice.
#[test]
fn two_processes_register_one_device_id() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("onepass.sqlite");
    let store = SyncStore::open(&path).unwrap();
    let (mut a, sk) = Repository::create_account(store, PASSWORD, kdf()).unwrap();
    a.persist_device_state().unwrap();
    let creator = a.this_device_id().unwrap();
    drop(a);
    // Forget the id, as on a device that never registered.
    let store = SyncStore::open(&path).unwrap();
    let chain = ChainState {
        device_id: None,
        ..store.chain_state().unwrap()
    };
    store.set_chain_state(&chain).unwrap();

    let mut a = unlock(&path, &sk);
    let mut b = unlock(&path, &sk);
    assert_eq!(a.this_device_id(), None);
    assert_eq!(b.this_device_id(), None);
    let id = a
        .register_this_device("Mac de Camille", DeviceKind::Mac, DeviceMode::Personal)
        .unwrap();
    assert_ne!(id, creator);
    let again = b
        .register_this_device("Mac de Camille", DeviceKind::Mac, DeviceMode::Personal)
        .unwrap();
    assert_eq!(again, id);
    let ids: Vec<Id> = b.devices().unwrap().iter().map(|d| d.device_id).collect();
    assert_eq!(ids.len(), 2);
    assert!(ids.contains(&creator) && ids.contains(&id));
    b.persist_device_state().unwrap();
    a.persist_device_state().unwrap();
    let stored = SyncStore::open(&path).unwrap().chain_state().unwrap();
    assert_eq!(stored.device_id, Some(id));
}
