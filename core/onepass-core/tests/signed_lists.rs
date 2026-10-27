//! Signed device and vault lists (milestone 2b, spec 4) seen from devices
//! syncing through the fake CloudKit-like server of `common`: creation,
//! migration of an account from before the lists, self-registration,
//! revocation, detection of a hidden vault, adoption of an unlisted one,
//! concurrent edits that converge, and remote deletions ignored.

mod common;

use common::*;
use onepass_core::chain::ChainState;
use onepass_core::crypto::HybridSigningKey;
use onepass_core::devices::{DEFAULT_DEVICE_NAME, DeviceEntry, DeviceKind, DeviceMode};
use onepass_core::manifest::{Manifest, sign_manifest};
use onepass_core::store::{Record, RecordKind, RecordStore};
use onepass_core::vault::{Vault, VaultMeta};
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

fn account_id(dev: &mut Device) -> Id {
    dev.repo().account().params.account_id
}

/// The stored version (the seq) of a list record of the device.
fn list_version(dev: &mut Device, kind: RecordKind) -> u64 {
    let id = account_id(dev);
    dev.repo().store().get(kind, id).unwrap().unwrap().version
}

fn vault_ids(dev: &mut Device) -> Vec<Id> {
    dev.repo()
        .vault_list()
        .unwrap()
        .into_iter()
        .map(|e| e.vault_id)
        .collect()
}

/// A creates the account and syncs; B fetches it, unlocks, registers
/// itself and syncs; A fetches.
fn two_devices(server: &mut Server) -> (Device, Device) {
    let (mut a, sk) = Device::create();
    sync(server, &mut a).unwrap();
    let mut b = Device::empty();
    pull(server, &mut b);
    b.unlock(&sk);
    b.repo()
        .register_this_device("iPad de Camille", DeviceKind::Tablet, DeviceMode::Personal)
        .unwrap();
    sync(server, &mut b).unwrap();
    pull(server, &mut a);
    (a, b)
}

#[test]
fn new_account_has_both_lists() {
    let (mut a, _sk) = Device::create();
    let me = a.repo().this_device_id().unwrap();
    let devices = a.repo().devices().unwrap();
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].device_id, me);
    assert_eq!(devices[0].name, DEFAULT_DEVICE_NAME);
    assert_eq!(devices[0].revoked_at, None);
    let personal = a.vault().id;
    assert_eq!(vault_ids(&mut a), vec![personal]);
    // Reading changed nothing: both lists are still the first ones.
    assert_eq!(list_version(&mut a, RecordKind::DeviceList), 1);
    assert_eq!(list_version(&mut a, RecordKind::VaultList), 1);

    // Registering names the device, in the next list.
    a.repo()
        .register_this_device("iPhone de Camille", DeviceKind::Phone, DeviceMode::Personal)
        .unwrap();
    let devices = a.repo().devices().unwrap();
    assert_eq!(devices[0].name, "iPhone de Camille");
    assert_eq!(devices[0].kind, DeviceKind::Phone);
    assert_eq!(list_version(&mut a, RecordKind::DeviceList), 2);

    // A new vault is listed in the same write.
    let travail = a.repo().create_vault(meta("Travail")).unwrap();
    assert!(vault_ids(&mut a).contains(&travail.id));
    assert_eq!(list_version(&mut a, RecordKind::VaultList), 2);
}

#[test]
fn migration_creates_lists_once() {
    let (mut a, sk) = Device::create();
    let travail = a.repo().create_vault(meta("Travail")).unwrap().id;
    let personal = a.vault_named("Personnel").id;
    let id = account_id(&mut a);
    a.lock();
    // A milestone 2 store: no lists, and a chain state that never saw any.
    let mut store = a.store();
    store.delete(RecordKind::DeviceList, id).unwrap();
    store.delete(RecordKind::VaultList, id).unwrap();
    store
        .set_chain_state(&ChainState {
            params_epoch: 1,
            ..ChainState::default()
        })
        .unwrap();

    a.unlock(&sk);
    assert_eq!(a.repo().this_device_id(), None);
    // Reading the vaults never fails because a list is missing.
    assert_eq!(a.repo().vaults().unwrap().len(), 2);
    let devices = a.repo().devices().unwrap();
    let me = a.repo().this_device_id().unwrap();
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].device_id, me);
    let mut expected = vec![personal, travail];
    expected.sort();
    assert_eq!(vault_ids(&mut a), expected);
    assert_eq!(list_version(&mut a, RecordKind::DeviceList), 1);
    assert_eq!(list_version(&mut a, RecordKind::VaultList), 1);

    // Once: the next session finds them and writes nothing.
    a.lock();
    a.unlock(&sk);
    assert_eq!(a.repo().devices().unwrap(), devices);
    assert_eq!(vault_ids(&mut a), expected);
    assert_eq!(list_version(&mut a, RecordKind::DeviceList), 1);
    assert_eq!(list_version(&mut a, RecordKind::VaultList), 1);

    // A list removed after this device saw one is a rollback, not a
    // migration.
    a.lock();
    a.store().delete(RecordKind::VaultList, id).unwrap();
    a.unlock(&sk);
    assert_eq!(
        integrity(a.repo().vaults()),
        IntegrityError::VaultListRollback
    );
}

#[test]
fn self_registration_adds_second_device() {
    let mut server = Server::default();
    let (mut a, sk) = Device::create();
    sync(&mut server, &mut a).unwrap();
    let a_id = a.repo().this_device_id().unwrap();

    let mut b = Device::empty();
    pull(&server, &mut b);
    b.unlock(&sk);
    // The first call that may write registers B under the default name.
    let devices = b.repo().devices().unwrap();
    let b_id = b.repo().this_device_id().unwrap();
    assert_ne!(a_id, b_id);
    assert_eq!(devices.len(), 2);
    assert_eq!(
        devices.iter().find(|d| d.device_id == b_id).unwrap().name,
        DEFAULT_DEVICE_NAME
    );
    let id = b
        .repo()
        .register_this_device("iPad de Camille", DeviceKind::Tablet, DeviceMode::Shared)
        .unwrap();
    assert_eq!(id, b_id);
    sync(&mut server, &mut b).unwrap();

    pull(&server, &mut a);
    let seen = a.repo().devices().unwrap();
    let entry = seen.iter().find(|d| d.device_id == b_id).unwrap();
    assert_eq!(entry.name, "iPad de Camille");
    assert_eq!(entry.kind, DeviceKind::Tablet);
    assert_eq!(entry.mode, DeviceMode::Shared);
    assert_eq!(seen, b.repo().devices().unwrap());
    // B's id survives a new session.
    b.lock();
    b.unlock(&sk);
    assert_eq!(b.repo().this_device_id(), Some(b_id));
    assert_eq!(b.repo().devices().unwrap().len(), 2);
}

#[test]
fn revoked_id_cannot_reregister() {
    let mut server = Server::default();
    let (mut a, mut b) = two_devices(&mut server);
    let b_id = b.repo().this_device_id().unwrap();
    assert!(!b.repo().is_this_device_revoked().unwrap());

    a.repo().revoke_device(b_id).unwrap();
    sync(&mut server, &mut a).unwrap();
    pull(&server, &mut b);

    let before = list_version(&mut b, RecordKind::DeviceList);
    assert!(b.repo().is_this_device_revoked().unwrap());
    assert!(matches!(
        b.repo()
            .register_this_device("iPad", DeviceKind::Tablet, DeviceMode::Personal),
        Err(Error::Validation(_))
    ));
    assert!(matches!(
        b.repo().rename_device(b_id, "Autre"),
        Err(Error::Validation(_))
    ));
    // Nothing written: still revoked, no second entry for B.
    let devices = b.repo().devices().unwrap();
    assert_eq!(devices.len(), 2);
    assert!(
        devices
            .iter()
            .find(|d| d.device_id == b_id)
            .unwrap()
            .revoked_at
            .is_some()
    );
    assert_eq!(list_version(&mut b, RecordKind::DeviceList), before);
    assert!(
        b.store()
            .pending_changes()
            .unwrap()
            .iter()
            .all(|c| c.kind != RecordKind::DeviceList)
    );
    // Revoking again changes nothing; an unknown id is not found.
    a.repo().revoke_device(b_id).unwrap();
    assert_eq!(a.repo().revoke_device(Id::new()), Err(Error::NotFound));
}

#[test]
fn hidden_never_opened_vault_detected() {
    let mut server = Server::default();
    let (mut a, sk) = Device::create();
    let travail = a.repo().create_vault(meta("Travail")).unwrap().id;
    sync(&mut server, &mut a).unwrap();
    // The server hides "Travail" from a new device.
    for kind in [
        RecordKind::VaultKey,
        RecordKind::VaultMeta,
        RecordKind::Manifest,
    ] {
        server.withhold(kind, travail);
    }
    let mut b = Device::empty();
    pull(&server, &mut b);
    b.unlock(&sk);
    assert!(b.repo().device_state().last_seen.is_empty());
    assert_eq!(integrity(b.repo().vaults()), IntegrityError::VaultMissing);
}

/// The records of a vault made outside the repository: key, meta and a
/// first manifest signed by `signer`.
fn vault_records(dev: &mut Device, signer: Option<&HybridSigningKey>) -> (Id, Vec<Record>) {
    let account = dev.repo().account();
    let (vault, envelope, meta_blob) = Vault::create(account, meta("Ancien")).unwrap();
    let m = Manifest::next(None, vault.id, vec![]).unwrap();
    let signer = signer.unwrap_or(&account.keyset().signing);
    let sm = sign_manifest(&vault, signer, &m).unwrap();
    let rec = |kind, data| Record {
        id: vault.id,
        kind,
        version: 1,
        data,
    };
    let records = vec![
        rec(RecordKind::Manifest, postcard::to_allocvec(&sm).unwrap()),
        rec(RecordKind::VaultMeta, meta_blob),
        rec(RecordKind::VaultKey, envelope),
    ];
    (vault.id, records)
}

#[test]
fn unlisted_signed_vault_adopted() {
    let (mut a, _sk) = Device::create();
    // A client from before the vault list writes a vault without listing it.
    let (old, records) = vault_records(&mut a, None);
    for r in records {
        a.repo().store_mut().put(r).unwrap();
    }
    let before = list_version(&mut a, RecordKind::VaultList);
    // Accepted as it is: valid key, meta and signed manifest.
    assert!(a.repo().vaults().unwrap().iter().any(|v| v.id == old));
    // Adopted by the next call that brings the lists up to date.
    assert!(vault_ids(&mut a).contains(&old));
    assert_eq!(list_version(&mut a, RecordKind::VaultList), before + 1);
    // Listed now: hiding it is detected.
    for kind in [
        RecordKind::VaultKey,
        RecordKind::VaultMeta,
        RecordKind::Manifest,
    ] {
        a.repo().store_mut().delete(kind, old).unwrap();
    }
    // (This device never read it: not in its last seen manifests.)
    assert!(!a.repo().device_state().last_seen.contains_key(&old));
    assert_eq!(integrity(a.repo().vaults()), IntegrityError::VaultMissing);
}

#[test]
fn unsigned_extra_vault_refused() {
    let (mut a, _sk) = Device::create();
    let stranger = HybridSigningKey::generate().unwrap();
    let (extra, records) = vault_records(&mut a, Some(&stranger));
    for r in records {
        a.repo().store_mut().put(r).unwrap();
    }
    let before = list_version(&mut a, RecordKind::VaultList);
    assert_eq!(integrity(a.repo().vaults()), IntegrityError::Signature);
    // Never adopted: the list does not change.
    assert!(!vault_ids(&mut a).contains(&extra));
    assert_eq!(list_version(&mut a, RecordKind::VaultList), before);
    assert_eq!(integrity(a.repo().vaults()), IntegrityError::Signature);
}

#[test]
fn concurrent_list_edits_converge() {
    let mut server = Server::default();
    let (mut a, mut b) = two_devices(&mut server);
    let third = DeviceEntry {
        device_id: Id::new(),
        name: "Mac de Camille".into(),
        kind: DeviceKind::Mac,
        mode: DeviceMode::Personal,
        added_at: 1_800_000_000,
        added_by: a.repo().this_device_id(),
        revoked_at: None,
    };
    a.repo().add_device(third.clone()).unwrap();
    sync(&mut server, &mut a).unwrap();
    pull(&server, &mut b);
    assert_eq!(b.repo().devices().unwrap().len(), 3);
    let devices_before = list_version(&mut b, RecordKind::DeviceList);
    let vaults_before = list_version(&mut b, RecordKind::VaultList);

    // Both offline. A creates a vault and adds a fourth device; B revokes
    // the third device and creates a vault.
    let travail = a.repo().create_vault(meta("Travail")).unwrap().id;
    let fourth = DeviceEntry {
        device_id: Id::new(),
        name: "Vision Pro".into(),
        kind: DeviceKind::Vision,
        ..third.clone()
    };
    a.repo().add_device(fourth.clone()).unwrap();
    b.repo().revoke_device(third.device_id).unwrap();
    let famille = b.repo().create_vault(meta("Famille")).unwrap().id;

    sync(&mut server, &mut a).unwrap();
    sync(&mut server, &mut b).unwrap();
    pull(&server, &mut a);

    for dev in [&mut a, &mut b] {
        let devices = dev.repo().devices().unwrap();
        assert_eq!(devices.len(), 4);
        let t = devices
            .iter()
            .find(|d| d.device_id == third.device_id)
            .unwrap();
        assert!(t.revoked_at.is_some());
        assert!(devices.iter().any(|d| d.device_id == fourth.device_id));
        let ids = vault_ids(dev);
        assert!(ids.contains(&travail) && ids.contains(&famille));
        assert_eq!(ids.len(), 3);
        assert_eq!(dev.repo().vaults().unwrap().len(), 3);
        // Two edits on each list: the server's, then the rebased one.
        assert_eq!(
            list_version(dev, RecordKind::DeviceList),
            devices_before + 2
        );
        assert_eq!(list_version(dev, RecordKind::VaultList), vaults_before + 2);
    }
    assert_eq!(a.repo().devices().unwrap(), b.repo().devices().unwrap());
    assert_eq!(vault_ids(&mut a), vault_ids(&mut b));
    // Nothing left to send.
    assert!(outbox(&a).is_empty());
    assert!(outbox(&b).is_empty());
}

#[test]
fn remote_list_deletion_ignored() {
    let mut server = Server::default();
    let (mut a, mut b) = two_devices(&mut server);
    let id = account_id(&mut a);
    let devices = b.repo().devices().unwrap();
    let vaults = vault_ids(&mut b);
    server.forge_deletion(RecordKind::DeviceList, id);
    server.forge_deletion(RecordKind::VaultList, id);
    pull(&server, &mut b);
    let ignored: Vec<RecordKind> = b
        .store()
        .ignored_deletions()
        .unwrap()
        .into_iter()
        .map(|d| d.kind)
        .collect();
    assert!(ignored.contains(&RecordKind::DeviceList));
    assert!(ignored.contains(&RecordKind::VaultList));
    assert_eq!(b.repo().devices().unwrap(), devices);
    assert_eq!(vault_ids(&mut b), vaults);

    // A fetch from scratch where the server no longer serves them keeps
    // them too.
    server.withhold(RecordKind::DeviceList, id);
    server.withhold(RecordKind::VaultList, id);
    full_fetch(&server, &mut b);
    assert_eq!(b.repo().devices().unwrap(), devices);
    assert_eq!(vault_ids(&mut b), vaults);
}
