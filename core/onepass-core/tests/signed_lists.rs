//! Signed device and vault lists (milestone 2b, spec 4) seen from devices
//! syncing through the fake CloudKit-like server of `common`: creation,
//! migration of an account from before the lists, self-registration,
//! revocation, detection of a hidden vault, adoption of an unlisted one,
//! concurrent edits that converge, and remote deletions ignored.

mod common;

use common::*;
use onepass_core::crypto::HybridSigningKey;
use onepass_core::crypto::SecretKey;
use onepass_core::devices::{DEFAULT_DEVICE_NAME, DeviceEntry, DeviceKind, DeviceMode};
use onepass_core::manifest::{Manifest, sign_manifest};
use onepass_core::store::{MemoryStore, Record, RecordKind, RecordStore, SqliteStore};
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

    // A public session never registers.
    assert!(matches!(
        a.repo()
            .register_this_device("Ordinateur", DeviceKind::Mac, DeviceMode::Public),
        Err(Error::Validation(_))
    ));
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
    a.lock();
    // A milestone 2 device: the same records without the lists, and a
    // chain state that never saw any.
    let mut m2 = Device::empty();
    let mut store = m2.store();
    let source = a.store();
    for kind in [
        RecordKind::AccountParams,
        RecordKind::Keyset,
        RecordKind::VaultKey,
        RecordKind::VaultMeta,
        RecordKind::Item,
        RecordKind::Manifest,
    ] {
        for r in source.list(kind).unwrap() {
            store.put(r).unwrap();
        }
    }

    m2.unlock(&sk);
    assert_eq!(m2.repo().this_device_id(), None);
    // Reading the vaults never fails because a list is missing.
    assert_eq!(m2.repo().vaults().unwrap().len(), 2);
    let devices = m2.repo().devices().unwrap();
    let me = m2.repo().this_device_id().unwrap();
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].device_id, me);
    let mut expected = vec![personal, travail];
    expected.sort();
    assert_eq!(vault_ids(&mut m2), expected);
    assert_eq!(list_version(&mut m2, RecordKind::DeviceList), 1);
    assert_eq!(list_version(&mut m2, RecordKind::VaultList), 1);

    // Once: the next session finds them and writes nothing.
    m2.lock();
    m2.unlock(&sk);
    assert_eq!(m2.repo().this_device_id(), Some(me));
    assert_eq!(m2.repo().devices().unwrap(), devices);
    assert_eq!(vault_ids(&mut m2), expected);
    assert_eq!(list_version(&mut m2, RecordKind::DeviceList), 1);
    assert_eq!(list_version(&mut m2, RecordKind::VaultList), 1);
}

#[test]
fn migration_on_first_vault_creation() {
    let (mut a, sk) = Device::create();
    a.lock();
    let mut m2 = Device::empty();
    let mut store = m2.store();
    let source = a.store();
    for kind in [
        RecordKind::AccountParams,
        RecordKind::Keyset,
        RecordKind::VaultKey,
        RecordKind::VaultMeta,
        RecordKind::Manifest,
    ] {
        for r in source.list(kind).unwrap() {
            store.put(r).unwrap();
        }
    }
    m2.unlock(&sk);
    let travail = m2.repo().create_vault(meta("Travail")).unwrap().id;
    let personal = m2.vault_named("Personnel").id;
    let ids = vault_ids(&mut m2);
    assert!(ids.contains(&travail) && ids.contains(&personal));
    assert_eq!(m2.repo().devices().unwrap().len(), 1);
}

#[test]
fn device_id_survives_a_cut_before_persist() {
    let mut server = Server::default();
    let (mut a, sk) = Device::create();
    sync(&mut server, &mut a).unwrap();
    let mut b = Device::empty();
    pull(&server, &mut b);
    b.unlock(&sk);
    b.repo().devices().unwrap();
    let id = b.repo().this_device_id().unwrap();
    // Killed before `persist_device_state`.
    b.repo = None;
    b.unlock(&sk);
    assert_eq!(b.repo().this_device_id(), Some(id));
    let devices = b.repo().devices().unwrap();
    assert_eq!(devices.len(), 2);
    assert!(devices.iter().any(|d| d.device_id == id));
}

#[test]
fn list_records_cannot_be_deleted_locally() {
    let (mut a, _sk) = Device::create();
    let id = account_id(&mut a);
    for kind in [RecordKind::DeviceList, RecordKind::VaultList] {
        assert_eq!(
            a.repo().store_mut().delete(kind, id),
            Err(Error::InvalidFormat("list record deletion"))
        );
        assert!(a.repo().store().get(kind, id).unwrap().is_some());
    }
    assert!(
        a.store()
            .pending_changes()
            .unwrap()
            .iter()
            .all(|c| c.data.is_some())
    );
    let dir = tempfile::tempdir().unwrap();
    let mut sqlite = SqliteStore::open(&dir.path().join("s.sqlite")).unwrap();
    let rec = a
        .repo()
        .store()
        .get(RecordKind::VaultList, id)
        .unwrap()
        .unwrap();
    sqlite.put(rec.clone()).unwrap();
    assert_eq!(
        sqlite.delete(RecordKind::VaultList, id),
        Err(Error::InvalidFormat("list record deletion"))
    );
    assert_eq!(sqlite.get(RecordKind::VaultList, id).unwrap(), Some(rec));
}

/// A device with "Personnel" (not travel safe) and "Voyage" (travel safe),
/// and an upstream holding a copy of every record.
fn travelling() -> (Device, SecretKey, MemoryStore, Id) {
    let (mut a, sk) = Device::create();
    let mut voyage = meta("Voyage");
    voyage.travel_safe = true;
    a.repo().create_vault(voyage).unwrap();
    let personal = a.vault_named("Personnel").id;
    let mut upstream = MemoryStore::new();
    for kind in [
        RecordKind::AccountParams,
        RecordKind::Keyset,
        RecordKind::VaultKey,
        RecordKind::VaultMeta,
        RecordKind::Item,
        RecordKind::Manifest,
        RecordKind::DeviceList,
        RecordKind::VaultList,
    ] {
        for r in a.repo().store().list(kind).unwrap() {
            upstream.put(r).unwrap();
        }
    }
    (a, sk, upstream, personal)
}

#[test]
fn travel_keeps_vault_list_and_pin() {
    let (mut a, _sk, upstream, personal) = travelling();
    let list_before = vault_ids(&mut a);
    let version = list_version(&mut a, RecordKind::VaultList);
    let pin = a.repo().chain().vault_list;

    let state = a.repo().enter_travel(&upstream).unwrap();
    assert!(state.parked.contains_key(&personal));
    let names: Vec<String> = a
        .repo()
        .vaults()
        .unwrap()
        .into_iter()
        .map(|v| v.meta.name)
        .collect();
    assert_eq!(names, vec!["Voyage".to_string()]);
    assert_eq!(vault_ids(&mut a), list_before);
    assert_eq!(list_version(&mut a, RecordKind::VaultList), version);
    assert_eq!(a.repo().chain().vault_list, pin);
    // No list deletion on its way to the server.
    assert!(
        a.store()
            .pending_changes()
            .unwrap()
            .iter()
            .all(
                |c| !matches!(c.kind, RecordKind::DeviceList | RecordKind::VaultList)
                    || c.data.is_some()
            )
    );

    a.repo().exit_travel(&upstream, &state).unwrap();
    assert_eq!(a.repo().vaults().unwrap().len(), 2);
    assert_eq!(vault_ids(&mut a), list_before);
    assert_eq!(list_version(&mut a, RecordKind::VaultList), version);
    assert_eq!(a.repo().chain().vault_list, pin);
}

#[test]
fn travel_without_resume_reports_missing() {
    let (mut a, sk, upstream, _personal) = travelling();
    let state = a.repo().enter_travel(&upstream).unwrap();
    // A later session that does not resume the Travel Mode.
    a.lock();
    a.unlock(&sk);
    assert_eq!(integrity(a.repo().vaults()), IntegrityError::VaultMissing);
    // Resumed, the hidden vault is not expected; the exit brings it back.
    a.repo().resume_travel(&state);
    assert_eq!(a.repo().vaults().unwrap().len(), 1);
    a.repo().exit_travel(&upstream, &state).unwrap();
    assert_eq!(a.repo().vaults().unwrap().len(), 2);
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
