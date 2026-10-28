//! Regressions for the 2026-10-28 audit: a hostile store replays an older
//! vault meta (its flags), or hides a fork behind a seq gap.

use onepass_core::crypto::KdfParams;
use onepass_core::model::{FieldValue, Item, ItemType, new_item};
use onepass_core::repo::{DeviceState, Repository};
use onepass_core::store::{MemoryStore, RecordKind, RecordStore};
use onepass_core::vault::{Vault, VaultMeta};
use onepass_core::{Error, Id, IntegrityError};

fn kdf() -> KdfParams {
    KdfParams {
        m_kib: 8192,
        t: 1,
        p: 1,
        salt: [7u8; 32],
    }
}

fn meta(mcp_access: bool, travel_safe: bool) -> VaultMeta {
    VaultMeta {
        name: "Work".into(),
        icon: "key".into(),
        color: "blue".into(),
        travel_safe,
        mcp_access,
    }
}

fn login(vault: Id, title: &str) -> Item {
    let mut item = new_item(ItemType::Login, vault, title);
    item.field_mut("username").unwrap().value = FieldValue::Text("alice".into());
    item
}

fn find(repo: &Repository<MemoryStore>, id: Id) -> Vault {
    repo.vaults()
        .unwrap()
        .into_iter()
        .find(|v| v.id == id)
        .unwrap()
}

const ALL: [RecordKind; 9] = [
    RecordKind::AccountParams,
    RecordKind::Keyset,
    RecordKind::VaultKey,
    RecordKind::VaultMeta,
    RecordKind::Item,
    RecordKind::Manifest,
    RecordKind::RestoreEpoch,
    RecordKind::DeviceList,
    RecordKind::VaultList,
];

/// The owner turns `mcp_access` and `travel_safe` off; the store serves the
/// old sealed meta again. The vault must not come back with the old flags.
#[test]
fn replayed_vault_meta_is_refused() {
    let (mut repo, _) = Repository::create_account(MemoryStore::new(), "pw", kdf()).unwrap();
    let v = repo.create_vault(meta(true, true)).unwrap();
    let old = repo
        .store()
        .get(RecordKind::VaultMeta, v.id)
        .unwrap()
        .unwrap();
    let v2 = repo.update_vault_meta(&v, meta(false, false)).unwrap();
    assert!(!v2.meta.mcp_access && !v2.meta.travel_safe);
    assert_eq!(find(&repo, v.id).meta, meta(false, false));

    let mut replay = old;
    replay.version = 99;
    repo.store_mut().put(replay).unwrap();
    assert_eq!(
        repo.vaults().unwrap_err(),
        Error::Integrity(IntegrityError::WrongContext)
    );
}

/// Updating the meta, then writing items, keeps the vault readable on this
/// device and on a fresh one.
#[test]
fn updated_meta_stays_readable() {
    let (mut repo, sk) = Repository::create_account(MemoryStore::new(), "pw", kdf()).unwrap();
    let v = repo.create_vault(meta(true, false)).unwrap();
    let v = repo.update_vault_meta(&v, meta(false, true)).unwrap();
    repo.save_item(&v, login(v.id, "a")).unwrap();
    let v = repo.update_vault_meta(&v, meta(true, true)).unwrap();
    repo.save_item(&v, login(v.id, "b")).unwrap();
    assert_eq!(repo.items(&find(&repo, v.id)).unwrap().len(), 2);

    let mut other =
        Repository::unlock(repo.store().clone(), "pw", &sk, DeviceState::default()).unwrap();
    let seen = find(&other, v.id);
    assert_eq!(seen.meta, meta(true, true));
    assert_eq!(other.items(&seen).unwrap().len(), 2);
}

/// Two writers both got seq 3 accepted; the store serves the other branch,
/// two writes later, to device B. B must see a rollback, not lose its write.
#[test]
fn fork_hidden_by_a_seq_gap_is_refused() {
    let (mut a, sk) = Repository::create_account(MemoryStore::new(), "pw", kdf()).unwrap();
    let va = a.create_vault(meta(false, false)).unwrap();
    a.save_item(&va, login(va.id, "base")).unwrap();

    let mut b = Repository::unlock(a.store().clone(), "pw", &sk, DeviceState::default()).unwrap();
    let vb = find(&b, va.id);
    b.items(&vb).unwrap();
    b.save_item(&vb, login(vb.id, "B-write")).unwrap();

    for title in ["A1", "A2", "A3"] {
        a.save_item(&va, login(va.id, title)).unwrap();
    }
    for kind in ALL {
        for r in b.store().list(kind).unwrap() {
            b.store_mut().delete(kind, r.id).unwrap();
        }
        for r in a.store().list(kind).unwrap() {
            b.store_mut().put(r).unwrap();
        }
    }
    assert_eq!(
        b.items(&vb).unwrap_err(),
        Error::Integrity(IntegrityError::ManifestRollback)
    );
}
