//! Key rotation (finding F1, spec 2026-10-28) seen from devices syncing
//! through the fake CloudKit-like server of `common`: a revoked device that
//! kept its Secret Key, keyset and vault keys reads nothing written after
//! the rotation and no longer holds a single readable record; nothing it
//! signs with the old keys is accepted; a remaining device follows only with
//! the new Secret Key; and the store cannot take the account back to the
//! old keyset.

mod common;

use common::*;
use onepass_core::account::{Account, AccountParams};
use onepass_core::crypto::SecretKey;
use onepass_core::devices::{DeviceEntry, DeviceKind, DeviceMode};
use onepass_core::epoch::{EpochReason, RestoreEpoch, SignedRestoreEpoch};
use onepass_core::lists::{DEVICE_LIST_DOMAIN, ListBody, VAULT_LIST_DOMAIN, sign};
use onepass_core::manifest::{Manifest, sign_manifest};
use onepass_core::repo::DeviceState;
use onepass_core::store::{MemoryStore, VaultEvent};
use onepass_core::vaultlist::VaultListEntry;

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

/// What a revoked device does to its own store: it forgets which Secret
/// Keys it used, so its own `rotate_keys` no longer refuses the old one.
fn forget_known_keys(dev: &Device) {
    rusqlite::Connection::open(&dev.path)
        .unwrap()
        .execute("DELETE FROM meta WHERE key = 'known_secret_keys'", [])
        .unwrap();
}

/// A forged rotation by `b`, sealed under `sk` (the old key) under a new
/// identity: two rotations, the second back to the old key after the
/// device forgot its keys. Returns the forged identity.
fn forge_rotation_under(
    b: &mut Device,
    sk: &SecretKey,
) -> onepass_core::crypto::IdentityVerifyingKey {
    let detour = SecretKey::generate().unwrap();
    b.repo().rotate_keys(PASSWORD, sk, &detour, None).unwrap();
    // It knows `sk`: refused until the device forgets its keys.
    assert!(matches!(
        b.repo().rotate_keys(PASSWORD, &detour, sk, None),
        Err(Error::Validation(_))
    ));
    forget_known_keys(b);
    b.repo().rotate_keys(PASSWORD, &detour, sk, None).unwrap();
    b.repo().account().params.identity_pub.clone()
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
    sync_all(&mut server, &mut a);

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
    // The rotation path refuses the key the device already held, and any
    // other key the rotation was not sealed under is a wrong password.
    assert!(matches!(
        Repository::unlock_after_rotation(b.store(), PASSWORD, &sk, state.clone()),
        Err(Error::Validation(_))
    ));
    let guess = SecretKey::generate().unwrap();
    assert!(matches!(
        Repository::unlock_after_rotation(b.store(), PASSWORD, &guess, state),
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
    sync_all(&mut server, &mut a);
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
    sync_all(&mut server, &mut a);
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
    // The rotation path with the key it already held: refused.
    assert!(matches!(
        Repository::unlock_after_rotation(c.store(), PASSWORD, &sk, state.clone()),
        Err(Error::Validation(_))
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
    sync_all(&mut server, &mut c);
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
    sync_all(&mut server, &mut a);
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
    sync_all(&mut server, &mut a);
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
    let other = SecretKey::generate().unwrap();
    assert!(matches!(
        a.repo().rotate_keys(PASSWORD, &new_sk, &other, None),
        Err(Error::WrongPassword)
    ));
    assert!(matches!(
        a.repo().rotate_keys(PASSWORD, &sk, &sk, None),
        Err(Error::Validation(_))
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

/// The params the server holds, decoded (not verified).
fn server_params(server: &Server, id: Id) -> AccountParams {
    AccountParams::decode(&server.get(RecordKind::AccountParams, id).unwrap().data).unwrap()
}

/// Push and pull until nothing is left to push (a rotation goes out in two
/// pushes: the account pair first, then the rest).
fn sync_all(server: &mut Server, dev: &mut Device) {
    for _ in 0..4 {
        sync(server, dev).unwrap();
        if outbox(dev).is_empty() {
            return;
        }
    }
    panic!("still pending after four rounds");
}

#[test]
fn the_rotated_pair_goes_out_first_and_alone() {
    let mut server = Server::default();
    let (mut a, _b, _c, sk, _) = three_devices(&mut server);
    let new_sk = SecretKey::generate().unwrap();
    a.repo().rotate_keys(PASSWORD, &sk, &new_sk, None).unwrap();
    a.repo().persist_device_state().unwrap();
    let kinds = |a: &Device| -> Vec<RecordKind> { outbox(a).iter().map(|(c, _)| c.kind).collect() };
    assert_eq!(
        kinds(&a),
        vec![RecordKind::AccountParams, RecordKind::Keyset]
    );
    push(&mut server, &a).unwrap();
    let rest = kinds(&a);
    assert!(!rest.is_empty());
    assert!(!rest.contains(&RecordKind::AccountParams));
    assert!(rest.contains(&RecordKind::Manifest));
    assert!(rest.contains(&RecordKind::RestoreEpoch));
    sync_all(&mut server, &mut a);
}

#[test]
fn a_concurrent_password_change_does_not_undo_the_rotation() {
    let mut server = Server::default();
    let (mut a, _b, mut c, sk, _) = three_devices(&mut server);
    let before = a.items();
    let id = account_id(&mut a);
    // C changes the password under the old keys and pushes first; A
    // rotates without having seen it (both at epoch 2).
    c.repo()
        .change_password(PASSWORD, &sk, NEW_PASSWORD)
        .unwrap();
    c.repo().persist_device_state().unwrap();
    let new_sk = SecretKey::generate().unwrap();
    a.repo().rotate_keys(PASSWORD, &sk, &new_sk, None).unwrap();
    a.repo().persist_device_state().unwrap();
    sync_all(&mut server, &mut c);
    sync_all(&mut server, &mut a);

    // The rotation won over the old identity's params whatever their epoch
    // (P1: nothing signed by the old identity outranks it), and nothing
    // was lost.
    let held = server_params(&server, id);
    assert_eq!(held.identity_pub, a.repo().account().params.identity_pub);
    assert_eq!(held.epoch, 2);
    assert_eq!(a.repo().account().params.epoch, 2);
    a.lock();
    a.try_unlock(PASSWORD, &new_sk).unwrap();
    assert_eq!(a.items(), before);
    let mut fresh = Device::empty();
    pull(&server, &mut fresh);
    fresh.try_unlock(PASSWORD, &new_sk).unwrap();
    assert_eq!(fresh.items(), before);
    assert!(matches!(
        fresh.try_unlock(NEW_PASSWORD, &sk),
        Err(Error::WrongPassword)
    ));

    // C follows the rotation (its own password change is lost).
    c.lock();
    pull(&server, &mut c);
    let store = c.store();
    let state = store.device_state().unwrap();
    assert!(Repository::keys_rotated(&store, &state).unwrap());
    let (repo, _) = Repository::unlock_after_rotation(c.store(), PASSWORD, &new_sk, state).unwrap();
    c.repo = Some(repo);
    assert_eq!(c.items(), before);
}

#[test]
fn a_hostile_server_cannot_drop_a_pending_rotation() {
    let mut server = Server::default();
    let (mut a, _b, _c, sk, _) = three_devices(&mut server);
    let before = a.items();
    let id = account_id(&mut a);
    let old_params = server.get(RecordKind::AccountParams, id).unwrap();
    let old_keyset = server.get(RecordKind::Keyset, id).unwrap();
    let new_sk = SecretKey::generate().unwrap();
    a.repo().rotate_keys(PASSWORD, &sk, &new_sk, None).unwrap();
    a.repo().persist_device_state().unwrap();
    // The server serves the pre-rotation pair again, as new, before A's
    // push lands.
    server.replay(old_params);
    server.replay(old_keyset);
    sync_all(&mut server, &mut a);
    assert_eq!(
        server_params(&server, id).identity_pub,
        a.repo().account().params.identity_pub
    );
    let mut fresh = Device::empty();
    pull(&server, &mut fresh);
    fresh.try_unlock(PASSWORD, &new_sk).unwrap();
    assert_eq!(fresh.items(), before);
}

#[test]
fn a_forged_rotation_under_the_old_secret_key_is_refused() {
    let mut server = Server::default();
    let (mut a, mut b, mut c, sk, b_id) = three_devices(&mut server);
    a.repo().revoke_device(b_id).unwrap();
    a.repo().persist_device_state().unwrap();
    sync_all(&mut server, &mut a);
    c.lock();
    // The revoked device cannot "rotate" to the key it holds.
    assert!(matches!(
        b.repo().rotate_keys(PASSWORD, &sk, &sk, None),
        Err(Error::Validation(_))
    ));
    // It forges one anyway, in two steps (to its own key, then back to
    // the old one under a new identity), and the server serves it.
    let id = account_id(&mut b);
    let forged_identity = forge_rotation_under(&mut b, &sk);
    for kind in [RecordKind::AccountParams, RecordKind::Keyset] {
        server.replay(b.store().get(kind, id).unwrap().unwrap());
    }
    pull(&server, &mut c);
    let store = c.store();
    let state = store.device_state().unwrap();
    // C sees a rotation, but the old key it already holds never opens it.
    assert!(Repository::keys_rotated(&store, &state).unwrap());
    assert!(matches!(
        Repository::unlock_after_rotation(c.store(), PASSWORD, &sk, state.clone()),
        Err(Error::Validation(_))
    ));
    assert_eq!(c.store().device_state().unwrap(), state);
    assert_ne!(state.pinned.as_ref().unwrap().identity_pub, forged_identity);
}

#[test]
fn keys_rotated_ignores_an_identity_the_device_left() {
    let mut server = Server::default();
    let (mut a, _b, mut c, sk, _) = three_devices(&mut server);
    let id = account_id(&mut a);
    let old_params = server.get(RecordKind::AccountParams, id).unwrap();
    let old_keyset = server.get(RecordKind::Keyset, id).unwrap();
    let new_sk = SecretKey::generate().unwrap();
    a.repo().rotate_keys(PASSWORD, &sk, &new_sk, None).unwrap();
    a.repo().persist_device_state().unwrap();
    sync_all(&mut server, &mut a);
    c.lock();
    pull(&server, &mut c);
    let state = c.store().device_state().unwrap();
    let (repo, _) = Repository::unlock_after_rotation(c.store(), PASSWORD, &new_sk, state).unwrap();
    c.repo = Some(repo);
    c.lock();
    // The server serves the old identity again: not a rotation to follow,
    // and following it is a rollback, whatever key.
    server.replay(old_params);
    server.replay(old_keyset);
    pull(&server, &mut c);
    let store = c.store();
    let state = store.device_state().unwrap();
    assert!(!Repository::keys_rotated(&store, &state).unwrap());
    for key in [&sk, &new_sk] {
        assert_eq!(
            integrity(
                Repository::unlock_after_rotation(c.store(), PASSWORD, key, state.clone())
                    .map(|_| ())
            ),
            IntegrityError::ParamsRollback
        );
    }
}

#[test]
fn lists_and_epoch_signed_with_the_old_keys_are_refused() {
    let mut server = Server::default();
    let (mut a, mut b, _c, sk, b_id) = three_devices(&mut server);
    let stolen = steal(&mut b);
    let new_sk = SecretKey::generate().unwrap();
    a.repo()
        .revoke_device_rotating(b_id, PASSWORD, &sk, &new_sk)
        .unwrap();
    a.repo().persist_device_state().unwrap();
    sync_all(&mut server, &mut a);
    let id = account_id(&mut a);
    let old: &Account = stolen.repo.account();
    let devices = a.repo().devices().unwrap();

    // A device list where B is not revoked, far ahead, old signing key.
    let unrevoked: Vec<DeviceEntry> = devices
        .into_iter()
        .map(|mut e| {
            e.revoked_at = None;
            e
        })
        .collect();
    let mut body = ListBody::next(None, id, unrevoked).unwrap();
    body.seq = 1_000;
    let forged = sign(old, DEVICE_LIST_DOMAIN, body).unwrap();
    let current = server.get(RecordKind::DeviceList, id).unwrap();
    server.replay(Record {
        id,
        kind: RecordKind::DeviceList,
        version: 1_000,
        data: forged.encode(),
    });
    pull(&server, &mut a);
    assert_eq!(
        integrity(a.repo().devices().map(|_| ())),
        IntegrityError::Signature
    );
    server.replay(current);
    pull(&server, &mut a);

    // A vault list marking the vault deleted, old signing key.
    let v = a.vault().id;
    let mut body = ListBody::next(
        None,
        id,
        vec![VaultListEntry {
            vault_id: v,
            created_at: T0,
            deleted_at: Some(T0),
        }],
    )
    .unwrap();
    body.seq = 1_000;
    let forged = sign(old, VAULT_LIST_DOMAIN, body).unwrap();
    let current = server.get(RecordKind::VaultList, id).unwrap();
    server.replay(Record {
        id,
        kind: RecordKind::VaultList,
        version: 1_000,
        data: forged.encode(),
    });
    pull(&server, &mut a);
    assert_eq!(
        integrity(a.repo().vaults().map(|_| ())),
        IntegrityError::Signature
    );
    server.replay(current);
    pull(&server, &mut a);

    // A restore epoch far ahead, old signing key.
    let epoch = RestoreEpoch {
        account_id: id,
        epoch: 1_000,
        issued_at: T0,
        heads: BTreeMap::new(),
        reason: EpochReason::Restore,
    };
    let forged = SignedRestoreEpoch::sign(epoch, &old.keyset().signing).unwrap();
    server.replay(Record {
        id,
        kind: RecordKind::RestoreEpoch,
        version: 1_000,
        data: forged.encode(),
    });
    pull(&server, &mut a);
    assert_eq!(
        integrity(a.repo().vaults().map(|_| ())),
        IntegrityError::Signature
    );
}

/// A store whose bookkeeping after the write fails on demand (an I/O error
/// or a busy database after the commit).
struct Flaky {
    inner: MemoryStore,
    fail: bool,
}

impl RecordStore for Flaky {
    fn put(&mut self, r: Record) -> Result<()> {
        self.inner.put(r)
    }
    fn put_if_version(&mut self, r: Record, expected: Option<u64>) -> Result<()> {
        self.inner.put_if_version(r, expected)
    }
    fn get(&self, kind: RecordKind, id: Id) -> Result<Option<Record>> {
        self.inner.get(kind, id)
    }
    fn list(&self, kind: RecordKind) -> Result<Vec<Record>> {
        self.inner.list(kind)
    }
    fn delete(&mut self, kind: RecordKind, id: Id) -> Result<()> {
        self.inner.delete(kind, id)
    }
    fn set_restore_epoch_mark(&mut self, _epoch: u64, _hash: [u8; 32]) -> Result<()> {
        if self.fail {
            return Err(Error::Store("disk I/O error".into()));
        }
        Ok(())
    }
    fn vault_event(&mut self, _vault: Id, _event: VaultEvent) -> Result<()> {
        if self.fail {
            return Err(Error::Store("database is locked".into()));
        }
        Ok(())
    }
}

#[test]
fn a_failure_after_the_write_is_not_an_error() {
    let store = Flaky {
        inner: MemoryStore::default(),
        fail: false,
    };
    let (mut repo, sk) = Repository::create_account(store, PASSWORD, kdf()).unwrap();
    let v = repo.vaults().unwrap().remove(0);
    repo.save_item(&v, login(v.id, "camille@exemple.fr", T0))
        .unwrap();
    repo.store_mut().fail = true;
    let new_sk = SecretKey::generate().unwrap();
    // The write committed: the caller must keep the new key, so this is Ok.
    repo.rotate_keys(PASSWORD, &sk, &new_sk, None).unwrap();
    let id = repo.account().params.account_id;
    let store = repo.store();
    let params = store.get(RecordKind::AccountParams, id).unwrap().unwrap();
    let keyset = store.get(RecordKind::Keyset, id).unwrap().unwrap();
    Account::unlock(PASSWORD, &new_sk, &params.data, &keyset.data, None).unwrap();
    assert!(matches!(
        Account::unlock(PASSWORD, &sk, &params.data, &keyset.data, None),
        Err(Error::WrongPassword)
    ));
}

/// One round as the app runs it (`SyncCoordinator.round`): fetch, rebase
/// (its error reported, not fatal), push.
fn app_round(server: &mut Server, dev: &mut Device) {
    pull(server, dev);
    let _ = dev.repo().rebase_report();
    let _ = push(server, dev);
}

#[test]
fn a_dropped_rotation_epoch_does_not_reopen_the_pair_drop() {
    let mut server = Server::default();
    let (mut a, _b, mut c, sk, _) = three_devices(&mut server);
    let id = account_id(&mut a);
    let v = a.vault().id;
    let before = a.items();
    let new_sk = SecretKey::generate().unwrap();
    a.repo().rotate_keys(PASSWORD, &sk, &new_sk, None).unwrap();
    a.repo().persist_device_state().unwrap();
    // C, still on the old keys, writes into the vault and pushes before
    // the rotation lands: A's vault is held.
    c.save(&login(v, "ipad.concurrent@exemple.fr", T0 + 30));
    sync_all(&mut server, &mut c);
    pull(&server, &mut a);
    let _ = a.repo().rebase_report();
    // C changes the password and pushes before A pushes anything.
    c.repo()
        .change_password(PASSWORD, &sk, NEW_PASSWORD)
        .unwrap();
    c.repo().persist_device_state().unwrap();
    sync_all(&mut server, &mut c);
    for _ in 0..4 {
        app_round(&mut server, &mut a);
    }
    assert!(outbox(&a).is_empty());

    // The rotation is what the server holds, whole.
    let held = server_params(&server, id);
    assert_eq!(held.identity_pub, a.repo().account().params.identity_pub);
    a.lock();
    a.try_unlock(PASSWORD, &new_sk).unwrap();
    assert_eq!(a.items(), before);
    let mut fresh = Device::empty();
    pull(&server, &mut fresh);
    assert!(matches!(
        fresh.try_unlock(NEW_PASSWORD, &sk),
        Err(Error::WrongPassword)
    ));
    fresh.try_unlock(PASSWORD, &new_sk).unwrap();
    assert_eq!(fresh.repo().vaults().unwrap().len(), 1);
    // C's write under the old keys lost the race to the rotation.
    assert_eq!(fresh.items(), before);
}

#[test]
fn a_server_cannot_pick_the_reissue_epoch() {
    for forged in [u64::MAX - 1, u64::MAX] {
        let mut server = Server::default();
        let (mut a, _b, _c, sk, _) = three_devices(&mut server);
        let id = account_id(&mut a);
        let old = server.get(RecordKind::AccountParams, id).unwrap();
        let new_sk = SecretKey::generate().unwrap();
        a.repo().rotate_keys(PASSWORD, &sk, &new_sk, None).unwrap();
        a.repo().persist_device_state().unwrap();
        // The server serves the old params with a forged epoch (its
        // signature no longer holds) before the rotation lands.
        let mut p = AccountParams::decode(&old.data).unwrap();
        p.epoch = forged;
        server.replay(Record {
            data: p.encode().unwrap(),
            ..old.clone()
        });
        for _ in 0..4 {
            app_round(&mut server, &mut a);
        }
        assert!(outbox(&a).is_empty());
        // The forged epoch was never taken: the rotation landed at epoch
        // 2, and the account can still change its password and rotate.
        assert_eq!(server_params(&server, id).epoch, 2);
        assert_eq!(a.repo().chain().params_epoch, 2);
        a.repo()
            .change_password(PASSWORD, &new_sk, NEW_PASSWORD)
            .unwrap();
        let again = SecretKey::generate().unwrap();
        a.repo()
            .rotate_keys(NEW_PASSWORD, &new_sk, &again, None)
            .unwrap();
        assert_eq!(a.repo().account().params.epoch, 4);
    }
}

#[test]
fn a_known_secret_key_never_opens_a_new_identity() {
    let mut server = Server::default();
    let (mut a, mut b, mut c, sk, b_id) = three_devices(&mut server);
    a.repo().revoke_device(b_id).unwrap();
    a.repo().persist_device_state().unwrap();
    sync_all(&mut server, &mut a);
    c.lock();
    // The revoked device forges a rotation sealed under the old key.
    let id = account_id(&mut b);
    forge_rotation_under(&mut b, &sk);
    for kind in [RecordKind::AccountParams, RecordKind::Keyset] {
        server.replay(b.store().get(kind, id).unwrap().unwrap());
    }
    pull(&server, &mut c);
    let state = c.store().device_state().unwrap();
    // C used the old key: refused whatever order the app tries keys in,
    // there is no other argument to swap.
    assert!(matches!(
        Repository::unlock_after_rotation(c.store(), PASSWORD, &sk, state.clone()),
        Err(Error::Validation(_))
    ));
    assert_eq!(c.store().device_state().unwrap(), state);
}

#[test]
fn a_crash_after_the_rotation_still_lets_the_device_follow_its_own_key() {
    let mut server = Server::default();
    let (mut a, _b, _c, sk, _) = three_devices(&mut server);
    let new_sk = SecretKey::generate().unwrap();
    a.repo().rotate_keys(PASSWORD, &sk, &new_sk, None).unwrap();
    // Crash: the session ends without persisting the device state, so
    // the stored pin is still the old identity.
    a.repo = None;
    let store = a.store();
    let state = store.device_state().unwrap();
    assert!(Repository::keys_rotated(&store, &state).unwrap());
    // The app tries the old key first: refused, then the new one: accepted.
    assert!(matches!(
        Repository::unlock_after_rotation(a.store(), PASSWORD, &sk, state.clone()),
        Err(Error::Validation(_))
    ));
    let (repo, _) = Repository::unlock_after_rotation(a.store(), PASSWORD, &new_sk, state).unwrap();
    a.repo = Some(repo);
    a.repo().persist_device_state().unwrap();
    sync_all(&mut server, &mut a);
}

#[test]
fn the_rotating_device_learns_it_overtook_a_password_change() {
    let mut server = Server::default();
    let (mut a, _b, mut c, sk, _) = three_devices(&mut server);
    c.repo()
        .change_password(PASSWORD, &sk, NEW_PASSWORD)
        .unwrap();
    c.repo().persist_device_state().unwrap();
    sync_all(&mut server, &mut c);
    let new_sk = SecretKey::generate().unwrap();
    a.repo().rotate_keys(PASSWORD, &sk, &new_sk, None).unwrap();
    a.repo().persist_device_state().unwrap();
    assert!(!a.store().take_password_change_overtaken().unwrap());
    sync_all(&mut server, &mut a);
    assert!(a.store().take_password_change_overtaken().unwrap());
    assert!(!a.store().take_password_change_overtaken().unwrap());
}

#[test]
fn a_biometric_only_device_fails_closed_until_it_records_its_key() {
    let mut server = Server::default();
    let (_a, mut b, mut c, sk, _) = three_devices(&mut server);
    // C as a device from before K15 that only unlocks by Face ID: it has
    // no record of the keys it used.
    let auk = {
        c.lock();
        c.try_unlock(PASSWORD, &sk).unwrap()
    };
    c.lock();
    forget_known_keys(&c);
    c.try_unlock_with_auk(&auk).unwrap();
    c.lock();
    assert!(c.store().known_secret_keys().unwrap().is_empty());
    // The revoked device forges a rotation under the old key.
    let id = account_id(&mut b);
    forge_rotation_under(&mut b, &sk);
    for kind in [RecordKind::AccountParams, RecordKind::Keyset] {
        server.replay(b.store().get(kind, id).unwrap().unwrap());
    }
    pull(&server, &mut c);
    let state = c.store().device_state().unwrap();
    // P2: no record, no proof: refused, whatever key.
    for key in [&sk, &SecretKey::generate().unwrap()] {
        assert!(matches!(
            Repository::unlock_after_rotation(c.store(), PASSWORD, key, state.clone()),
            Err(Error::Validation(_))
        ));
    }
    assert_eq!(c.store().device_state().unwrap(), state);
}

#[test]
fn an_auk_unlock_records_the_keychain_key() {
    let (mut a, sk) = Device::create();
    let auk = {
        a.lock();
        a.try_unlock(PASSWORD, &sk).unwrap()
    };
    a.lock();
    forget_known_keys(&a);
    a.try_unlock_with_auk(&auk).unwrap();
    assert!(a.store().known_secret_keys().unwrap().is_empty());
    a.repo().note_secret_key(&sk).unwrap();
    assert_eq!(a.store().known_secret_keys().unwrap().len(), 1);
    // And rotate_keys refuses any key the device knows, not only the
    // current one.
    let k1 = SecretKey::generate().unwrap();
    a.repo().rotate_keys(PASSWORD, &sk, &k1, None).unwrap();
    let k2 = SecretKey::generate().unwrap();
    a.repo().rotate_keys(PASSWORD, &k1, &k2, None).unwrap();
    assert!(matches!(
        a.repo().rotate_keys(PASSWORD, &k2, &sk, None),
        Err(Error::Validation(_))
    ));
}

#[test]
fn the_revoked_device_cannot_wedge_the_rotation_with_old_identity_epochs() {
    let mut server = Server::default();
    let (mut a, mut b, mut c, sk, b_id) = three_devices(&mut server);
    let new_sk = SecretKey::generate().unwrap();
    a.repo()
        .revoke_device_rotating(b_id, PASSWORD, &sk, &new_sk)
        .unwrap();
    a.repo().persist_device_state().unwrap();
    // Before A's pair lands, the revoked device pushes many valid password
    // changes under the old identity.
    for i in 0..20 {
        let (cur, next) = if i % 2 == 0 {
            (PASSWORD, NEW_PASSWORD)
        } else {
            (NEW_PASSWORD, PASSWORD)
        };
        b.repo().change_password(cur, &sk, next).unwrap();
    }
    b.repo().persist_device_state().unwrap();
    let id = account_id(&mut b);
    assert_eq!(b.repo().account().params.epoch, 21);
    for kind in [RecordKind::AccountParams, RecordKind::Keyset] {
        server.replay(b.store().get(kind, id).unwrap().unwrap());
    }
    // C, still on the old keys, accepts B's params meanwhile.
    pull(&server, &mut c);
    c.lock();
    c.try_unlock(PASSWORD, &sk).unwrap();
    assert_eq!(c.repo().chain().params_epoch, 21);
    c.lock();
    let v = a.vault().id;
    a.save(&login(v, "apres.revocation@exemple.fr", T0 + 99));
    for _ in 0..4 {
        app_round(&mut server, &mut a);
    }
    // P1: the rotation landed whole, at its own epoch, never wedged.
    assert!(outbox(&a).is_empty());
    let held = server_params(&server, id);
    assert_eq!(held.identity_pub, a.repo().account().params.identity_pub);
    assert_eq!(held.epoch, 2);
    // C follows although it pinned epoch 21 from the old identity, then
    // unlocks normally from then on.
    pull(&server, &mut c);
    let store = c.store();
    let state = store.device_state().unwrap();
    assert!(Repository::keys_rotated(&store, &state).unwrap());
    let (repo, _) = Repository::unlock_after_rotation(c.store(), PASSWORD, &new_sk, state).unwrap();
    c.repo = Some(repo);
    c.repo().persist_device_state().unwrap();
    assert_eq!(c.repo().chain().params_epoch, 2);
    assert_eq!(c.items(), a.items());
    c.lock();
    c.try_unlock(PASSWORD, &new_sk).unwrap();
    assert_eq!(c.items().len(), 2);
}

#[test]
fn of_two_concurrent_rotations_the_first_complete_wins() {
    let mut server = Server::default();
    let (mut a, _b, mut c, sk, _) = three_devices(&mut server);
    let v = a.vault().id;
    let before = a.items();
    let (ka, kc) = (
        SecretKey::generate().unwrap(),
        SecretKey::generate().unwrap(),
    );
    a.repo().rotate_keys(PASSWORD, &sk, &ka, None).unwrap();
    a.repo().persist_device_state().unwrap();
    c.repo().rotate_keys(PASSWORD, &sk, &kc, None).unwrap();
    c.repo().persist_device_state().unwrap();
    // C lands complete first, then writes under its new keys.
    for _ in 0..3 {
        app_round(&mut server, &mut c);
    }
    c.save(&login(v, "c.apres.sa.rotation@exemple.fr", T0 + 50));
    for _ in 0..2 {
        app_round(&mut server, &mut c);
    }
    assert!(outbox(&c).is_empty());
    // A's rotation lost: it is told so and drops its pending content.
    pull(&server, &mut a);
    assert_eq!(
        integrity(a.repo().rebase().map(|_| ())),
        IntegrityError::RotationOvertaken
    );
    assert!(outbox(&a).is_empty());
    for _ in 0..2 {
        app_round(&mut server, &mut a);
    }
    // A follows the winner with C's key, and can rotate again from there.
    a.repo = None;
    let state = a.store().device_state().unwrap();
    assert!(Repository::keys_rotated(&a.store(), &state).unwrap());
    assert!(matches!(
        Repository::unlock_after_rotation(a.store(), PASSWORD, &ka, state.clone()),
        Err(Error::Validation(_)) | Err(Error::WrongPassword)
    ));
    let (repo, _) = Repository::unlock_after_rotation(a.store(), PASSWORD, &kc, state).unwrap();
    a.repo = Some(repo);
    a.repo().persist_device_state().unwrap();
    let mut expected = users(&before);
    expected.push("c.apres.sa.rotation@exemple.fr".into());
    expected.sort();
    assert_eq!(users(&a.items()), expected);
    // Every device reads under the winner's key.
    let mut fresh = Device::empty();
    pull(&server, &mut fresh);
    assert!(matches!(
        fresh.try_unlock(PASSWORD, &ka),
        Err(Error::WrongPassword)
    ));
    fresh.try_unlock(PASSWORD, &kc).unwrap();
    assert_eq!(fresh.repo().vaults().unwrap().len(), 1);
    // The three devices, and the fresh one, which registers itself.
    assert_eq!(fresh.repo().devices().unwrap().len(), 4);
    assert_eq!(users(&fresh.items()), expected);
    let again = SecretKey::generate().unwrap();
    a.repo().rotate_keys(PASSWORD, &kc, &again, None).unwrap();
    a.repo().persist_device_state().unwrap();
    sync_all(&mut server, &mut a);
    let mut fresh = Device::empty();
    pull(&server, &mut fresh);
    fresh.try_unlock(PASSWORD, &again).unwrap();
    assert_eq!(users(&fresh.items()), expected);
}

#[test]
fn rotation_follow_needs_a_store_that_remembers_keys() {
    let (mut repo, sk) =
        Repository::create_account(MemoryStore::default(), PASSWORD, kdf()).unwrap();
    let new_sk = SecretKey::generate().unwrap();
    repo.rotate_keys(PASSWORD, &sk, &new_sk, None).unwrap();
    let state = DeviceState {
        pinned: None,
        ..repo.device_state().clone()
    };
    let mut pinned_state = repo.device_state().clone();
    // A pinned device on a store without a memory of keys: refused.
    if let Some(p) = pinned_state.pinned.as_mut() {
        p.identity_pub = Account::create_with_params("x", kdf())
            .unwrap()
            .account
            .params
            .identity_pub;
    }
    let store = repo.store().clone();
    assert!(matches!(
        Repository::unlock_after_rotation(store.clone(), PASSWORD, &new_sk, pinned_state),
        Err(Error::InvalidFormat(_))
    ));
    // Without a pin it is a first unlock.
    Repository::unlock_after_rotation(store, PASSWORD, &new_sk, state).unwrap();
}
