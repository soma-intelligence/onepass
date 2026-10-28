//! Key rotation (finding F1, spec 2026-10-28) seen from devices syncing
//! through the fake CloudKit-like server of `common`: a revoked device that
//! kept its Secret Key, keyset and vault keys reads nothing written after
//! the rotation and no longer holds a single readable record; nothing it
//! signs with the old keys is accepted; a remaining device follows only with
//! the new Secret Key; and the store cannot take the account back to the
//! old keyset.

mod common;

use common::*;
use onepass_core::crypto::SecretKey;
use onepass_core::devices::{DeviceKind, DeviceMode};
use onepass_core::manifest::{Manifest, sign_manifest};
use onepass_core::repo::DeviceState;

const NEW_PASSWORD: &str = "Projet Zénith, Camille Durand";

fn register(dev: &mut Device, name: &str, kind: DeviceKind) -> Id {
    dev.repo()
        .register_this_device(name, kind, DeviceMode::Personal)
        .unwrap()
}

fn account_id(dev: &mut Device) -> Id {
    dev.repo().account().params.account_id
}

/// What a revoked device walks away with: its session (old keyset in
/// memory), its vault (old vault key) and its Secret Key.
struct Stolen {
    repo: Repository<SyncStore>,
    vault: Vault,
}

/// A creates the account, registers and writes one item; B (to be revoked)
/// and C (staying) fetch, unlock, register. Everything synced.
fn three_devices(server: &mut Server) -> (Device, Device, Device, SecretKey, Id) {
    let (mut a, sk) = Device::create();
    register(&mut a, "Mac de Camille", DeviceKind::Mac);
    let v = a.vault().id;
    a.save(&login(v, "avant.rotation@exemple.fr", T0));
    sync(server, &mut a).unwrap();
    let mut b = Device::empty();
    pull(server, &mut b);
    b.unlock(&sk);
    let b_id = register(&mut b, "iPhone perdu", DeviceKind::Phone);
    sync(server, &mut b).unwrap();
    let mut c = Device::empty();
    pull(server, &mut c);
    c.unlock(&sk);
    register(&mut c, "iPad de Camille", DeviceKind::Tablet);
    sync(server, &mut c).unwrap();
    pull(server, &mut a);
    pull(server, &mut b);
    (a, b, c, sk, b_id)
}

fn steal(b: &mut Device) -> Stolen {
    let vault = b.vault();
    let mut repo = b.repo.take().expect("unlocked");
    repo.persist_device_state().unwrap();
    Stolen { repo, vault }
}

/// Every item record the server holds.
fn server_items(server: &Server) -> Vec<ItemRecord> {
    server
        .records
        .values()
        .filter_map(|e| e.record.clone())
        .filter(|r| r.kind == RecordKind::Item)
        .map(|r| ItemRecord::decode(split_item_record(&r.data).unwrap().1).unwrap())
        .collect()
}

#[test]
fn revoked_device_reads_nothing_after_rotation() {
    let mut server = Server::default();
    let (mut a, mut b, _c, sk, b_id) = three_devices(&mut server);
    let v = a.vault().id;
    let stolen = steal(&mut b);
    // Before the rotation, the stolen vault key opens what the server holds.
    let before = server_items(&server);
    assert_eq!(before.len(), 1);
    stolen.vault.open_item(&before[0]).unwrap();

    let new_sk = SecretKey::generate().unwrap();
    a.repo()
        .revoke_device_rotating(b_id, PASSWORD, &sk, &new_sk)
        .unwrap();
    a.repo().persist_device_state().unwrap();
    a.save(&login(v, "apres.rotation@exemple.fr", T0 + 60));
    sync(&mut server, &mut a).unwrap();

    // A reads both items under the new keys; B is marked revoked.
    assert_eq!(
        users(&a.items()),
        vec!["apres.rotation@exemple.fr", "avant.rotation@exemple.fr"]
    );
    let devices = a.repo().devices().unwrap();
    let revoked = devices.iter().find(|d| d.device_id == b_id).unwrap();
    assert!(revoked.revoked_at.is_some());

    // The server holds exactly the two current records, both re-sealed:
    // the stolen vault key opens neither, the old one is gone.
    let after = server_items(&server);
    assert_eq!(after.len(), 2);
    for rec in &after {
        assert!(stolen.vault.open_item(rec).is_err());
        assert!(!before.contains(rec));
    }
    // The stolen keyset no longer opens the vault key envelope.
    let env = server.get(RecordKind::VaultKey, v).unwrap();
    let meta = server.get(RecordKind::VaultMeta, v).unwrap();
    assert!(Vault::open(stolen.repo.account(), v, &env.data, &meta.data).is_err());

    // B, with its old Secret Key, cannot open the rotated account at all,
    // not even through the rotation path.
    pull(&server, &mut b);
    let store = b.store();
    let state = store.device_state().unwrap();
    assert_eq!(
        integrity(Repository::unlock(store, PASSWORD, &sk, state.clone()).map(|_| ())),
        IntegrityError::ParamsUnsigned
    );
    assert!(matches!(
        Repository::unlock_after_rotation(b.store(), PASSWORD, &sk, state),
        Err(Error::WrongPassword)
    ));
}

#[test]
fn nothing_signed_with_the_old_keys_is_accepted() {
    let mut server = Server::default();
    let (mut a, mut b, _c, sk, b_id) = three_devices(&mut server);
    let v = a.vault().id;
    let stolen = steal(&mut b);
    let old_key = server.get(RecordKind::VaultKey, v).unwrap();

    let new_sk = SecretKey::generate().unwrap();
    a.repo()
        .revoke_device_rotating(b_id, PASSWORD, &sk, &new_sk)
        .unwrap();
    a.repo().persist_device_state().unwrap();
    sync(&mut server, &mut a).unwrap();
    let current = server.get(RecordKind::Manifest, v).unwrap();

    // A manifest forged far ahead with the old signing key and old vault
    // key: refused.
    let mut m = Manifest::next(None, v, vec![]).unwrap();
    m.seq = current.version + 1;
    m.prev_hash = [0; 32];
    let forged = sign_manifest(&stolen.vault, &stolen.repo.account().keyset().signing, &m).unwrap();
    server.replay(Record {
        id: v,
        kind: RecordKind::Manifest,
        version: m.seq,
        data: postcard::to_allocvec(&forged).unwrap(),
    });
    pull(&server, &mut a);
    assert_eq!(integrity(a.repo().vaults()), IntegrityError::Signature);
    server.replay(current);

    // The old vault key envelope served again: it does not open.
    server.replay(old_key);
    pull(&server, &mut a);
    assert!(a.repo().vaults().is_err());
}

#[test]
fn remaining_device_follows_only_with_the_new_secret_key() {
    let mut server = Server::default();
    let (mut a, mut b, mut c, sk, b_id) = three_devices(&mut server);
    let _stolen = steal(&mut b);
    c.lock();

    let new_sk = SecretKey::generate().unwrap();
    a.repo()
        .revoke_device_rotating(b_id, PASSWORD, &sk, &new_sk)
        .unwrap();
    a.repo().persist_device_state().unwrap();
    sync(&mut server, &mut a).unwrap();
    pull(&server, &mut c);

    let store = c.store();
    let state = store.device_state().unwrap();
    assert!(Repository::keys_rotated(&store, &state).unwrap());
    // The normal unlock never follows a new identity, whatever the key.
    for key in [&sk, &new_sk] {
        assert_eq!(
            integrity(c.try_unlock(PASSWORD, key)),
            IntegrityError::ParamsUnsigned
        );
    }
    // The rotation path with the old key: wrong password.
    assert!(matches!(
        Repository::unlock_after_rotation(c.store(), PASSWORD, &sk, state.clone()),
        Err(Error::WrongPassword)
    ));
    let (repo, _auk) =
        Repository::unlock_after_rotation(c.store(), PASSWORD, &new_sk, state).unwrap();
    c.repo = Some(repo);
    c.repo().persist_device_state().unwrap();
    let store = c.store();
    assert!(!Repository::keys_rotated(&store, &store.device_state().unwrap()).unwrap());
    assert_eq!(c.items(), a.items());

    // C writes; A reads it. Then C locks and unlocks normally.
    let v = c.vault().id;
    c.save(&login(v, "ipad.apres@exemple.fr", T0 + 120));
    sync(&mut server, &mut c).unwrap();
    pull(&server, &mut a);
    assert_eq!(a.items(), c.items());
    c.lock();
    c.try_unlock(PASSWORD, &new_sk).unwrap();
    assert_eq!(c.items().len(), 2);
}

#[test]
fn store_cannot_roll_back_to_the_old_keyset() {
    let mut server = Server::default();
    let (mut a, _b, _c, sk, _) = three_devices(&mut server);
    let id = account_id(&mut a);
    let old_params = server.get(RecordKind::AccountParams, id).unwrap();
    let old_keyset = server.get(RecordKind::Keyset, id).unwrap();

    let new_sk = SecretKey::generate().unwrap();
    a.repo().rotate_keys(PASSWORD, &sk, &new_sk, None).unwrap();
    a.repo().persist_device_state().unwrap();
    sync(&mut server, &mut a).unwrap();
    a.lock();

    // The server serves the pre-rotation pair again.
    server.replay(old_params);
    server.replay(old_keyset);
    pull(&server, &mut a);
    for key in [&sk, &new_sk] {
        assert_eq!(
            integrity(a.try_unlock(PASSWORD, key)),
            IntegrityError::ParamsRollback
        );
        let store = a.store();
        let state = store.device_state().unwrap();
        assert_eq!(
            integrity(Repository::unlock_after_rotation(store, PASSWORD, key, state).map(|_| ())),
            IntegrityError::ParamsRollback
        );
    }
}

#[test]
fn rotation_with_a_new_password_invalidates_the_old_kit() {
    let mut server = Server::default();
    let (mut a, _b, _c, sk, _) = three_devices(&mut server);
    let before = a.items();
    let new_sk = SecretKey::generate().unwrap();
    let auk = a
        .repo()
        .rotate_keys(PASSWORD, &sk, &new_sk, Some(NEW_PASSWORD))
        .unwrap();
    a.repo().persist_device_state().unwrap();
    assert_eq!(a.repo().account().params.epoch, 2);
    sync(&mut server, &mut a).unwrap();
    a.lock();

    for (pw, key) in [(PASSWORD, &sk), (NEW_PASSWORD, &sk), (PASSWORD, &new_sk)] {
        assert!(matches!(a.try_unlock(pw, key), Err(Error::WrongPassword)));
    }
    let again = a.try_unlock(NEW_PASSWORD, &new_sk).unwrap();
    assert_eq!(again.as_bytes(), auk.as_bytes());
    assert_eq!(a.items(), before);
    a.lock();
    a.try_unlock_with_auk(&auk).unwrap();

    // A brand new device with the old kit gets nothing.
    let mut fresh = Device::empty();
    pull(&server, &mut fresh);
    for pw in [PASSWORD, NEW_PASSWORD] {
        assert!(matches!(
            fresh.try_unlock(pw, &sk),
            Err(Error::WrongPassword)
        ));
    }
    fresh.try_unlock(NEW_PASSWORD, &new_sk).unwrap();
    assert_eq!(fresh.items(), before);
}

#[test]
fn refused_rotations_write_nothing() {
    let mut server = Server::default();
    let (mut a, _b, _c, sk, _) = three_devices(&mut server);
    let me = a.repo().this_device_id().unwrap();
    let new_sk = SecretKey::generate().unwrap();
    let snapshot = |a: &Device| a.store().export_records().unwrap();
    let before = snapshot(&a);

    assert!(matches!(
        a.repo().rotate_keys("faux", &sk, &new_sk, None),
        Err(Error::WrongPassword)
    ));
    assert!(matches!(
        a.repo().rotate_keys(PASSWORD, &new_sk, &new_sk, None),
        Err(Error::WrongPassword)
    ));
    assert!(matches!(
        a.repo().revoke_device_rotating(me, PASSWORD, &sk, &new_sk),
        Err(Error::Validation(_))
    ));
    assert!(matches!(
        a.repo()
            .revoke_device_rotating(Id::new(), PASSWORD, &sk, &new_sk),
        Err(Error::NotFound)
    ));
    assert_eq!(snapshot(&a), before);
    assert_eq!(a.repo().account().params.epoch, 1);
}

#[test]
fn keys_rotated_is_false_on_a_fresh_or_current_device() {
    let (a, _) = Device::create();
    let store = a.store();
    assert!(!Repository::keys_rotated(&store, &store.device_state().unwrap()).unwrap());
    assert!(!Repository::keys_rotated(&store, &DeviceState::default()).unwrap());
}
