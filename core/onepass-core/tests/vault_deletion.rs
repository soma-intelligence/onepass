//! Vault deletion (milestone 2b, spec 4.5, ruling B8) through the signed
//! vault list, over the fake CloudKit-like server of `common`: an empty
//! vault is deleted locally, the deletion reaches the other devices, a
//! deletion the signed list does not back stays refused, and a pending
//! write into a vault deleted elsewhere is dropped.

mod common;

use common::*;
use onepass_core::crypto::HybridSigningKey;
use onepass_core::crypto::SecretKey;
use onepass_core::devices::{DeviceKind, DeviceMode};
use onepass_core::epoch::EpochReason;
use onepass_core::lists::{ListBody, SignedList, VAULT_LIST_DOMAIN};
use onepass_core::model::{FieldValue, Item, ItemType, new_item};
use onepass_core::repo::split_item_record;
use onepass_core::store::{Record, RecordKind, RecordStore};
use onepass_core::vault::VaultMeta;
use onepass_core::vaultlist::VaultListEntry;
use onepass_core::{Error, Id, IntegrityError, Result};

fn meta(name: &str) -> VaultMeta {
    VaultMeta {
        name: name.into(),
        icon: "key".into(),
        color: "blue".into(),
        travel_safe: false,
        mcp_access: false,
    }
}

fn integrity<T: std::fmt::Debug>(r: Result<T>) -> IntegrityError {
    match r {
        Err(Error::Integrity(e)) => e,
        other => panic!("expected an integrity error, got {other:?}"),
    }
}

fn login(vault: Id, user: &str) -> Item {
    let mut item = new_item(ItemType::Login, vault, "Exemple");
    item.field_mut("username").unwrap().value = FieldValue::Text(user.into());
    item
}

const VAULT_KINDS: [RecordKind; 3] = [
    RecordKind::VaultKey,
    RecordKind::VaultMeta,
    RecordKind::Manifest,
];

/// The entry of `vault` in the device's signed vault list.
fn list_entry(dev: &mut Device, vault: Id) -> VaultListEntry {
    dev.repo()
        .vault_list()
        .unwrap()
        .into_iter()
        .find(|e| e.vault_id == vault)
        .expect("listed vault")
}

fn list_version(dev: &mut Device) -> u64 {
    let id = dev.repo().account().params.account_id;
    dev.repo()
        .store()
        .get(RecordKind::VaultList, id)
        .unwrap()
        .unwrap()
        .version
}

/// The item records the device store holds for `vault`.
fn item_rows(store: &impl RecordStore, vault: Id) -> usize {
    store
        .list(RecordKind::Item)
        .unwrap()
        .iter()
        .filter(|r| split_item_record(&r.data).is_ok_and(|(p, _)| p == vault))
        .count()
}

/// Whether the device store still holds any row of `vault`.
fn holds_vault(store: &impl RecordStore, vault: Id) -> bool {
    VAULT_KINDS
        .iter()
        .any(|k| store.get(*k, vault).unwrap().is_some())
        || item_rows(store, vault) > 0
}

fn server_holds_vault(server: &Server, vault: Id) -> bool {
    VAULT_KINDS.iter().any(|k| server.get(*k, vault).is_some())
        || server.records.iter().any(|((k, _), e)| {
            *k == RecordKind::Item
                && e.record
                    .as_ref()
                    .is_some_and(|r| split_item_record(&r.data).is_ok_and(|(p, _)| p == vault))
        })
}

fn ignored_ids(dev: &Device) -> Vec<Id> {
    dev.store()
        .ignored_deletions()
        .unwrap()
        .into_iter()
        .map(|d| d.id)
        .collect()
}

/// A creates the account and a "Travail" vault, and syncs; B fetches,
/// unlocks, registers itself, reads both vaults (so they are in B's last
/// seen manifests) and syncs. Returns both devices, the secret key and the id of
/// "Travail".
fn two_devices(server: &mut Server) -> (Device, Device, SecretKey, Id) {
    let (mut a, sk) = Device::create();
    let travail = a.repo().create_vault(meta("Travail")).unwrap();
    sync(server, &mut a).unwrap();
    let mut b = Device::empty();
    pull(server, &mut b);
    b.unlock(&sk);
    b.repo()
        .register_this_device("iPad de Camille", DeviceKind::Tablet, DeviceMode::Personal)
        .unwrap();
    for v in b.repo().vaults().unwrap() {
        b.repo().items(&v).unwrap();
    }
    assert!(b.repo().device_state().last_seen.contains_key(&travail.id));
    b.repo().persist_device_state().unwrap();
    sync(server, &mut b).unwrap();
    pull(server, &mut a);
    (a, b, sk, travail.id)
}

#[test]
fn delete_empty_vault_removes_rows_and_lists_tombstone() {
    let mut server = Server::default();
    let (mut a, _sk) = Device::create();
    let travail = a.repo().create_vault(meta("Travail")).unwrap();
    sync(&mut server, &mut a).unwrap();
    let before = list_version(&mut a);

    a.repo().delete_vault(&travail).unwrap();

    assert!(list_entry(&mut a, travail.id).deleted_at.is_some());
    assert_eq!(list_version(&mut a), before + 1);
    assert!(!holds_vault(a.repo().store(), travail.id));
    assert!(!a.repo().device_state().last_seen.contains_key(&travail.id));
    let names: Vec<String> = a
        .repo()
        .vaults()
        .unwrap()
        .into_iter()
        .map(|v| v.meta.name)
        .collect();
    assert_eq!(names, vec!["Personnel".to_string()]);

    // The push carries the list, then the deletions of the vault rows.
    let out = outbox(&a);
    let list = out
        .iter()
        .position(|(c, _)| c.kind == RecordKind::VaultList && c.data.is_some())
        .expect("list write");
    for kind in VAULT_KINDS {
        let del = out
            .iter()
            .position(|(c, _)| c.kind == kind && c.id == travail.id && c.data.is_none())
            .expect("vault row deletion");
        assert!(del > list);
    }
    sync(&mut server, &mut a).unwrap();
    assert!(!server_holds_vault(&server, travail.id));
    // A deleted vault is gone: deleting it again is not found.
    assert_eq!(a.repo().delete_vault(&travail), Err(Error::NotFound));
}

#[test]
fn delete_refuses_live_or_archived_items() {
    let (mut a, _sk) = Device::create();
    let travail = a.repo().create_vault(meta("Travail")).unwrap();
    let item = login(travail.id, "camille.durand@exemple.fr");
    a.repo().save_item(&travail, item.clone()).unwrap();
    let before = list_version(&mut a);
    let not_empty = Err(Error::InvalidFormat("vault not empty"));

    assert_eq!(a.repo().delete_vault(&travail), not_empty);
    a.repo().archive_item(&travail, item.id).unwrap();
    assert_eq!(a.repo().delete_vault(&travail), not_empty);

    // Nothing changed.
    assert_eq!(list_version(&mut a), before);
    assert!(list_entry(&mut a, travail.id).deleted_at.is_none());
    assert_eq!(a.repo().items(&travail).unwrap().len(), 1);
    assert_eq!(a.repo().vaults().unwrap().len(), 2);
}

#[test]
fn delete_purges_trashed_items() {
    let (mut a, _sk) = Device::create();
    let travail = a.repo().create_vault(meta("Travail")).unwrap();
    let item = login(travail.id, "camille.durand@exemple.fr");
    a.repo().save_item(&travail, item.clone()).unwrap();
    a.repo().trash_item(&travail, item.id).unwrap();
    // An archived item in the trash goes too.
    let other = login(travail.id, "c.durand@exemple.fr");
    a.repo().save_item(&travail, other.clone()).unwrap();
    a.repo().archive_item(&travail, other.id).unwrap();
    a.repo().trash_item(&travail, other.id).unwrap();
    assert!(item_rows(a.repo().store(), travail.id) >= 2);

    a.repo().delete_vault(&travail).unwrap();

    assert_eq!(item_rows(a.repo().store(), travail.id), 0);
    assert!(!holds_vault(a.repo().store(), travail.id));
    assert!(list_entry(&mut a, travail.id).deleted_at.is_some());
}

#[test]
fn last_vault_refused() {
    let (mut a, _sk) = Device::create();
    let personal = a.vault();
    let last = Err(Error::InvalidFormat("last vault"));
    assert_eq!(a.repo().delete_vault(&personal), last);

    // With a second vault, one goes; then the other is the last one.
    let travail = a.repo().create_vault(meta("Travail")).unwrap();
    a.repo().delete_vault(&personal).unwrap();
    assert_eq!(a.repo().delete_vault(&travail), last);
    assert_eq!(a.repo().vaults().unwrap().len(), 1);
}

#[test]
fn deletion_propagates_to_other_device() {
    let mut server = Server::default();
    let (mut a, mut b, sk, travail) = two_devices(&mut server);
    let v = a.vault_named("Travail");
    a.repo().delete_vault(&v).unwrap();
    sync(&mut server, &mut a).unwrap();

    pull(&server, &mut b);
    // Accepted: the rows are gone, nothing logged as ignored.
    assert!(!holds_vault(&b.store(), travail));
    assert!(!ignored_ids(&b).contains(&travail));
    // The persisted last seen manifests forget it.
    assert!(
        !b.store()
            .device_state()
            .unwrap()
            .last_seen
            .contains_key(&travail)
    );
    // B drops the vault cleanly: no `VaultMissing`.
    let names: Vec<String> = b
        .repo()
        .vaults()
        .unwrap()
        .into_iter()
        .map(|v| v.meta.name)
        .collect();
    assert_eq!(names, vec!["Personnel".to_string()]);
    assert!(list_entry(&mut b, travail).deleted_at.is_some());
    assert!(!b.repo().device_state().last_seen.contains_key(&travail));
    // A later session too.
    b.lock();
    b.unlock(&sk);
    assert_eq!(b.repo().vaults().unwrap().len(), 1);
    assert!(!b.repo().device_state().last_seen.contains_key(&travail));
    sync(&mut server, &mut b).unwrap();
    assert!(!server_holds_vault(&server, travail));
}

#[test]
fn forged_deletion_of_listed_vault_still_ignored() {
    let mut server = Server::default();
    let (_a, mut b, _sk, travail) = two_devices(&mut server);
    // Tombstones the signed list does not back.
    for kind in VAULT_KINDS {
        server.forge_deletion(kind, travail);
    }
    pull(&server, &mut b);
    let ignored = ignored_ids(&b);
    assert_eq!(ignored.iter().filter(|id| **id == travail).count(), 3);
    assert!(b.repo().vaults().unwrap().iter().any(|v| v.id == travail));

    // Nor does a list marking it deleted signed by another key, in the
    // same batch as the tombstones.
    b.store().clear_ignored_deletions().unwrap();
    let account = b.repo().account().params.account_id;
    let current = b
        .repo()
        .store()
        .get(RecordKind::VaultList, account)
        .unwrap()
        .unwrap();
    let mut entries = b.repo().vault_list().unwrap();
    for e in &mut entries {
        if e.vault_id == travail {
            e.deleted_at = Some(1_800_000_000);
        }
    }
    let prev: ListBody<VaultListEntry> = ListBody {
        account_id: account,
        seq: current.version,
        prev_hash: [0; 32],
        entries: vec![],
    };
    let body = ListBody::next(Some(&prev), account, entries).unwrap();
    let stranger = HybridSigningKey::generate().unwrap();
    let sig = stranger.sign(VAULT_LIST_DOMAIN, &body.encode()).unwrap();
    let forged = SignedList { body, sig };
    server.replay(Record {
        id: account,
        kind: RecordKind::VaultList,
        version: current.version + 1,
        data: forged.encode(),
    });
    for kind in VAULT_KINDS {
        server.forge_deletion(kind, travail);
    }
    pull(&server, &mut b);
    assert_eq!(
        ignored_ids(&b).iter().filter(|id| **id == travail).count(),
        3
    );
    for kind in VAULT_KINDS {
        assert!(b.store().get(kind, travail).unwrap().is_some());
    }
    // The forged list itself is caught on reading.
    assert_eq!(integrity(b.repo().vaults()), IntegrityError::Signature);
}

#[test]
fn pending_write_into_deleted_vault_dropped() {
    let mut server = Server::default();
    let (mut a, mut b, _sk, travail) = two_devices(&mut server);
    // B writes into "Travail" offline; A deletes it (empty on A) and syncs.
    let v = b.vault_named("Travail");
    b.repo()
        .save_item(&v, login(travail, "camille.durand@exemple.fr"))
        .unwrap();
    let v = a.vault_named("Travail");
    a.repo().delete_vault(&v).unwrap();
    sync(&mut server, &mut a).unwrap();

    // B's push conflicts, B fetches the deletion and rebases: the write is
    // dropped and logged, never pushed.
    sync(&mut server, &mut b).unwrap();
    assert!(!server_holds_vault(&server, travail));
    let dropped: Vec<Id> = b
        .store()
        .dropped_vault_writes()
        .unwrap()
        .into_iter()
        .map(|d| d.vault_id)
        .collect();
    assert_eq!(dropped, vec![travail]);
    assert!(!holds_vault(&b.store(), travail));
    assert!(outbox(&b).is_empty());
    assert_eq!(b.repo().vaults().unwrap().len(), 1);
}

#[test]
fn pending_write_withheld_until_rebase() {
    let mut server = Server::default();
    let (mut a, mut b, _sk, travail) = two_devices(&mut server);
    let v = b.vault_named("Travail");
    b.repo()
        .save_item(&v, login(travail, "camille.durand@exemple.fr"))
        .unwrap();
    let v = a.vault_named("Travail");
    a.repo().delete_vault(&v).unwrap();
    sync(&mut server, &mut a).unwrap();

    // B fetches first: its write into the deleted vault is not pushed.
    pull(&server, &mut b);
    let into_travail = |c: &onepass_core::sync::Change| match &c.data {
        Some(d) if c.kind == RecordKind::Item => {
            split_item_record(d).is_ok_and(|(p, _)| p == travail)
        }
        Some(_) => c.id == travail,
        None => false,
    };
    assert!(!outbox(&b).iter().any(|(c, _)| into_travail(c)));
    sync(&mut server, &mut b).unwrap();
    assert!(!server_holds_vault(&server, travail));
    // The rebase drops it for good.
    assert_eq!(b.repo().rebase().unwrap(), Vec::<Id>::new());
    assert_eq!(b.store().dropped_vault_writes().unwrap().len(), 1);
    assert!(!holds_vault(&b.store(), travail));
    assert!(outbox(&b).is_empty());
}

#[test]
fn full_fetch_after_deletion_clean() {
    let mut server = Server::default();
    let (mut a, mut b, _sk, travail) = two_devices(&mut server);
    b.lock();
    let v = a.vault_named("Travail");
    a.repo().delete_vault(&v).unwrap();
    sync(&mut server, &mut a).unwrap();

    // B's change token expired: a fetch from scratch, which carries no
    // tombstones.
    full_fetch(&server, &mut b);
    assert!(!holds_vault(&b.store(), travail));
    assert!(!ignored_ids(&b).contains(&travail));
    assert!(
        !b.store()
            .device_state()
            .unwrap()
            .last_seen
            .contains_key(&travail)
    );

    // Without the list marking it deleted, a vault the server stops serving
    // stays, and the refusal is logged.
    let personal = a.vault_named("Personnel").id;
    for kind in VAULT_KINDS {
        server.withhold(kind, personal);
    }
    full_fetch(&server, &mut b);
    for kind in VAULT_KINDS {
        assert!(b.store().get(kind, personal).unwrap().is_some());
    }
    assert!(ignored_ids(&b).contains(&personal));
}

/// A restore epoch issued on a device that had not seen a deletion yet
/// names the deleted vault among its heads. The deletion wins everywhere:
/// the epoch still ships, its head of the deleted vault is never expected
/// nor remembered, and no device reports the vault missing or keeps a sync
/// health entry for it.
#[test]
fn restore_epoch_naming_a_deleted_vault() {
    let mut server = Server::default();
    let (mut a, mut b, sk, travail) = two_devices(&mut server);
    let v = a.vault_named("Travail");
    a.repo().delete_vault(&v).unwrap();
    sync(&mut server, &mut a).unwrap();

    // B, offline, restores: its epoch re-signs both vaults it holds.
    let epoch = b.repo().issue_restore_epoch(EpochReason::Restore).unwrap();
    assert!(epoch.heads.contains_key(&travail));
    sync(&mut server, &mut b).unwrap();
    // The re-signed manifest of the deleted vault was dropped, not pushed;
    // the epoch went out.
    assert!(!server_holds_vault(&server, travail));
    let account = b.repo().account().params.account_id;
    assert_eq!(
        server
            .get(RecordKind::RestoreEpoch, account)
            .map(|r| r.version),
        Some(epoch.epoch)
    );
    assert_eq!(b.repo().vaults().unwrap().len(), 1);
    assert!(!b.repo().device_state().last_seen.contains_key(&travail));
    assert!(!b.repo().sync_health().unwrap().contains_key(&travail));

    // A accepts the epoch: its heads stand for the vaults read, except the
    // deleted one.
    sync(&mut server, &mut a).unwrap();
    assert_eq!(a.repo().vaults().unwrap().len(), 1);
    a.items();
    assert_eq!(a.repo().restore_epoch(), Some(epoch.epoch));
    assert!(!a.repo().device_state().last_seen.contains_key(&travail));
    a.repo().persist_device_state().unwrap();
    assert!(
        !a.store()
            .device_state()
            .unwrap()
            .last_seen
            .contains_key(&travail)
    );
    assert!(!a.repo().sync_health().unwrap().contains_key(&travail));

    // A new device takes the account as the server holds it.
    let mut c = Device::empty();
    pull(&server, &mut c);
    c.unlock(&sk);
    assert_eq!(c.repo().vaults().unwrap().len(), 1);
    c.items();
}

/// "Take the server's version" drops every local write, a vault created
/// here and never pushed included, with the pending vault list that named
/// it: the server's lists are taken like a first use, so the vault is not
/// reported missing afterwards, in this session or the next.
#[test]
fn take_server_drops_an_unpushed_vault_and_its_list() {
    let mut server = Server::default();
    let (mut a, mut b, sk, _travail) = two_devices(&mut server);
    let before = list_version(&mut a);
    let local = a.repo().create_vault(meta("Brouillon")).unwrap();
    assert_eq!(list_version(&mut a), before + 1);

    a.repo().issue_restore_epoch_take_server().unwrap();
    assert!(!holds_vault(a.repo().store(), local.id));
    assert_eq!(list_version(&mut a), before);
    let names: Vec<String> = a
        .repo()
        .vaults()
        .unwrap()
        .into_iter()
        .map(|v| v.meta.name)
        .collect();
    assert!(!names.contains(&"Brouillon".to_string()));
    assert_eq!(names.len(), 2);
    a.lock();
    a.unlock(&sk);
    assert_eq!(a.repo().vaults().unwrap().len(), 2);
    sync(&mut server, &mut a).unwrap();
    sync(&mut server, &mut b).unwrap();
    assert_eq!(b.repo().vaults().unwrap().len(), 2);
    assert!(!server_holds_vault(&server, local.id));
}
