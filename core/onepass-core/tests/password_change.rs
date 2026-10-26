//! Master password change seen from devices syncing through the fake
//! CloudKit-like server of `common`: the other device follows without
//! losing its pending writes, a replay of the old params is refused, a torn
//! fetch is not a wrong password, the change is written atomically, and of
//! two concurrent changes exactly one wins everywhere.

mod common;

use common::*;
use onepass_core::account::Auk;
use onepass_core::crypto::SecretKey;
use onepass_core::model::{FieldValue, Item, ItemType, new_item};
use onepass_core::repo::Repository;
use onepass_core::store::{RecordKind, RecordStore};
use onepass_core::{Error, Id, IntegrityError, Result};

const NEW_PASSWORD: &str = "Projet Zénith, Camille Durand";
const OTHER_PASSWORD: &str = "Projet Orion, Camille Durand";

fn login(vault: Id, user: &str) -> Item {
    let mut item = new_item(ItemType::Login, vault, "Exemple");
    item.field_mut("username").unwrap().value = FieldValue::Text(user.into());
    item
}

fn users(items: &[Item]) -> Vec<String> {
    let mut out: Vec<String> = items.iter().map(Item::subtitle).collect();
    out.sort();
    out
}

fn integrity<T>(r: Result<T>) -> IntegrityError {
    match r {
        Err(Error::Integrity(e)) => e,
        Err(e) => panic!("expected an integrity error, got {e:?}"),
        Ok(_) => panic!("expected an integrity error, got success"),
    }
}

fn wrong_password<T>(r: Result<T>) -> bool {
    matches!(r, Err(Error::WrongPassword))
}

/// A creates the account with one item and syncs; B restores it and
/// unlocks. Returns B's Account Unlock Key too.
fn setup(server: &mut Server) -> (Device, Device, SecretKey, Auk) {
    let (mut a, sk) = Device::create();
    let v = a.vault().id;
    a.save(&login(v, "camille.durand@exemple.fr"));
    sync(server, &mut a).unwrap();
    let mut b = Device::empty();
    pull(server, &mut b);
    let auk = b.try_unlock(PASSWORD, &sk).unwrap();
    assert_eq!(b.items(), a.items());
    assert_eq!(b.repo().chain().params_epoch, 1);
    (a, b, sk, auk)
}

fn account_id(dev: &mut Device) -> Id {
    dev.repo().account().params.account_id
}

/// The account params and keyset the device's store serves.
fn account_pair(dev: &Device, id: Id) -> (Vec<u8>, Vec<u8>) {
    let store = dev.store();
    (
        store
            .get(RecordKind::AccountParams, id)
            .unwrap()
            .unwrap()
            .data,
        store.get(RecordKind::Keyset, id).unwrap().unwrap().data,
    )
}

#[test]
fn other_device_follows_without_loss() {
    let mut server = Server::default();
    let (mut a, mut b, sk, b_old_auk) = setup(&mut server);
    let v = a.vault().id;

    // B writes an item and locks before pushing it.
    b.save(&login(v, "b.en.attente@exemple.fr"));
    b.lock();
    assert!(!outbox(&b).is_empty());

    // A writes too (B will have to rebase), then changes the password.
    a.save(&login(v, "a.apres@exemple.fr"));
    let a_new_auk = a
        .repo()
        .change_password(PASSWORD, &sk, NEW_PASSWORD)
        .unwrap();
    assert_eq!(a.repo().chain().params_epoch, 2);
    a.repo().persist_device_state().unwrap();
    assert_eq!(a.store().chain_state().unwrap().params_epoch, 2);
    sync(&mut server, &mut a).unwrap();

    // B fetches the new params: its biometric key and the old password
    // both fail as a wrong password.
    pull(&server, &mut b);
    assert!(wrong_password(b.try_unlock_with_auk(&b_old_auk)));
    assert!(wrong_password(b.try_unlock(PASSWORD, &sk)));
    let b_new_auk = b.try_unlock(NEW_PASSWORD, &sk).unwrap();
    assert_eq!(b_new_auk.as_bytes(), a_new_auk.as_bytes());
    assert_eq!(b.repo().chain().params_epoch, 2);
    assert_eq!(b.store().chain_state().unwrap().params_epoch, 2);

    // Its pending write survived: rebase, push, and A reads it.
    assert_eq!(b.repo().rebase().unwrap(), vec![v]);
    sync(&mut server, &mut b).unwrap();
    pull(&server, &mut a);
    let expected = vec![
        "a.apres@exemple.fr".to_owned(),
        "b.en.attente@exemple.fr".to_owned(),
        "camille.durand@exemple.fr".to_owned(),
    ];
    assert_eq!(users(&a.items()), expected);
    assert_eq!(users(&b.items()), expected);

    // A, locked and unlocked again, uses the new password only.
    a.lock();
    assert!(wrong_password(a.try_unlock(PASSWORD, &sk)));
    a.try_unlock_with_auk(&a_new_auk).unwrap();
    assert_eq!(users(&a.items()), expected);
}

#[test]
fn old_params_replay_refused_after_change() {
    let mut server = Server::default();
    let (mut a, mut b, sk, b_old_auk) = setup(&mut server);
    let id = account_id(&mut a);
    let old_params = server.get(RecordKind::AccountParams, id).unwrap();
    let old_keyset = server.get(RecordKind::Keyset, id).unwrap();

    a.repo()
        .change_password(PASSWORD, &sk, NEW_PASSWORD)
        .unwrap();
    sync(&mut server, &mut a).unwrap();
    b.lock();
    pull(&server, &mut b);
    b.try_unlock(NEW_PASSWORD, &sk).unwrap();
    b.lock();

    // The server serves the old params and keyset again.
    server.replay(old_params);
    server.replay(old_keyset);
    pull(&server, &mut b);
    // Refused before any derivation: whichever password, or the old AUK.
    assert_eq!(
        integrity(b.try_unlock(PASSWORD, &sk)),
        IntegrityError::ParamsRollback
    );
    assert_eq!(
        integrity(b.try_unlock(NEW_PASSWORD, &sk)),
        IntegrityError::ParamsRollback
    );
    assert_eq!(
        integrity(b.try_unlock_with_auk(&b_old_auk)),
        IntegrityError::ParamsRollback
    );

    // Control: the refusal is the pinned epoch. A device that never saw the
    // new epoch accepts the replayed pair (trust on first use).
    let mut c = Device::empty();
    pull(&server, &mut c);
    c.try_unlock(PASSWORD, &sk).unwrap();
    assert_eq!(c.repo().chain().params_epoch, 1);
}

#[test]
fn torn_fetch_is_wrong_context_not_wrong_password() {
    let mut server = Server::default();
    let (mut a, mut b, sk, _) = setup(&mut server);
    let id = account_id(&mut a);
    let old_params = server.get(RecordKind::AccountParams, id).unwrap();
    a.repo()
        .change_password(PASSWORD, &sk, NEW_PASSWORD)
        .unwrap();
    sync(&mut server, &mut a).unwrap();
    b.lock();

    // B gets the new params but not the new keyset.
    let cursor = b.cursor;
    pull_only(&server, &mut b, |c| c.kind == RecordKind::AccountParams);
    for pw in [PASSWORD, NEW_PASSWORD] {
        assert_eq!(
            integrity(b.try_unlock(pw, &sk)),
            IntegrityError::WrongContext
        );
    }

    // Then the keyset: the pair matches again.
    b.cursor = cursor;
    pull_only(&server, &mut b, |c| c.kind == RecordKind::Keyset);
    b.try_unlock(NEW_PASSWORD, &sk).unwrap();
    assert_eq!(b.repo().chain().params_epoch, 2);

    // The other way round, on a new device: the new keyset beside the old
    // params.
    let c = Device::empty();
    let mut store = c.store();
    store.put(old_params).unwrap();
    store
        .put(server.get(RecordKind::Keyset, id).unwrap())
        .unwrap();
    for pw in [PASSWORD, NEW_PASSWORD] {
        let r = Repository::unlock(c.store(), pw, &sk, Default::default());
        assert_eq!(integrity(r), IntegrityError::WrongContext);
    }
}

#[test]
fn failed_second_write_leaves_the_old_pair() {
    let mut server = Server::default();
    let (mut a, _b, sk, _) = setup(&mut server);
    let id = account_id(&mut a);
    let before = account_pair(&a, id);

    // Inject a failure on the params write, the second of the two: the
    // keyset write before it has already gone through in the transaction.
    let conn = rusqlite::Connection::open(&a.path).unwrap();
    conn.execute_batch(
        "CREATE TRIGGER fail_params BEFORE INSERT ON pending WHEN NEW.kind = 1
         BEGIN SELECT RAISE(ABORT, 'injected'); END;",
    )
    .unwrap();
    let err = a
        .repo()
        .change_password(PASSWORD, &sk, NEW_PASSWORD)
        .unwrap_err();
    assert!(matches!(err, Error::Store(_)), "{err:?}");

    // Nothing changed: the old pair, nothing to push, epoch 1 everywhere.
    assert_eq!(account_pair(&a, id), before);
    assert!(
        outbox(&a)
            .iter()
            .all(|(c, _)| !matches!(c.kind, RecordKind::AccountParams | RecordKind::Keyset))
    );
    assert_eq!(a.repo().account().params.epoch, 1);
    assert_eq!(a.repo().chain().params_epoch, 1);
    conn.execute_batch("DROP TRIGGER fail_params;").unwrap();
    a.lock();
    a.try_unlock(PASSWORD, &sk).unwrap();
    assert!(wrong_password(a.try_unlock(NEW_PASSWORD, &sk)));
}

#[test]
fn concurrent_changes_second_conflicts() {
    let mut server = Server::default();
    let (mut a, mut b, sk, _) = setup(&mut server);

    // Both devices change the password from epoch 1.
    a.repo()
        .change_password(PASSWORD, &sk, NEW_PASSWORD)
        .unwrap();
    b.repo()
        .change_password(PASSWORD, &sk, OTHER_PASSWORD)
        .unwrap();
    assert_eq!(a.repo().chain().params_epoch, 2);
    assert_eq!(b.repo().chain().params_epoch, 2);

    // The first push wins; the second one conflicts and writes nothing.
    push(&mut server, &a).unwrap();
    let id = account_id(&mut a);
    let on_server = |s: &Server| {
        (
            s.get(RecordKind::AccountParams, id).unwrap().data,
            s.get(RecordKind::Keyset, id).unwrap().data,
        )
    };
    let after_a = on_server(&server);
    assert!(push(&mut server, &b).is_err());
    assert_eq!(on_server(&server), after_a);

    // A third device follows A's change.
    let mut c = Device::empty();
    pull(&server, &mut c);
    c.try_unlock(NEW_PASSWORD, &sk).unwrap();
    assert_eq!(c.repo().chain().params_epoch, 2);
}

#[test]
fn racing_password_changes_loser_dropped() {
    let mut server = Server::default();
    let (mut a, mut b, sk, _) = setup(&mut server);
    let id = account_id(&mut a);

    a.repo()
        .change_password(PASSWORD, &sk, NEW_PASSWORD)
        .unwrap();
    a.repo().persist_device_state().unwrap();
    b.repo()
        .change_password(PASSWORD, &sk, OTHER_PASSWORD)
        .unwrap();
    b.repo().persist_device_state().unwrap();

    // A syncs first. B's sync conflicts, fetches, and retries as the apps
    // do: its overtaken change is dropped, never pushed over A's.
    sync(&mut server, &mut a).unwrap();
    let winner = (
        server.get(RecordKind::AccountParams, id).unwrap().data,
        server.get(RecordKind::Keyset, id).unwrap().data,
    );
    sync(&mut server, &mut b).unwrap();
    assert_eq!(
        (
            server.get(RecordKind::AccountParams, id).unwrap().data,
            server.get(RecordKind::Keyset, id).unwrap().data,
        ),
        winner
    );
    assert_eq!(account_pair(&b, id), winner);
    assert!(
        outbox(&b)
            .iter()
            .all(|(c, _)| !matches!(c.kind, RecordKind::AccountParams | RecordKind::Keyset))
    );
    // B is told, once; A is not.
    assert!(b.store().take_password_change_superseded().unwrap());
    assert!(!b.store().take_password_change_superseded().unwrap());
    assert!(!a.store().take_password_change_superseded().unwrap());

    // Exactly one password works everywhere: A's.
    let mut c = Device::empty();
    pull(&server, &mut c);
    a.lock();
    b.lock();
    for dev in [&mut a, &mut b, &mut c] {
        assert!(wrong_password(dev.try_unlock(OTHER_PASSWORD, &sk)));
        assert!(wrong_password(dev.try_unlock(PASSWORD, &sk)));
        dev.try_unlock(NEW_PASSWORD, &sk).unwrap();
        assert_eq!(dev.repo().chain().params_epoch, 2);
        assert_eq!(dev.items().len(), 1);
    }
}
