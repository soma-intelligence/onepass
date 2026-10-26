//! Master password change seen from two devices syncing through a fake
//! CloudKit-like server (the minimal harness of `sync_two_devices.rs`):
//! the other device follows without losing its pending writes, a replay of
//! the old params is refused, a torn fetch is not a wrong password, and two
//! concurrent changes cannot both be pushed.

use std::collections::BTreeMap;
use std::path::PathBuf;

use onepass_core::account::Auk;
use onepass_core::crypto::{KdfParams, SecretKey, random_array};
use onepass_core::model::{FieldValue, Item, ItemType, new_item};
use onepass_core::repo::Repository;
use onepass_core::store::{Record, RecordKind, RecordStore};
use onepass_core::sync::{Change, RemoteChange, SyncStore};
use onepass_core::{Error, Id, IntegrityError, Result};

const PASSWORD: &str = "Projet Atlas, Camille Durand";
const NEW_PASSWORD: &str = "Projet Zénith, Camille Durand";

fn kdf() -> KdfParams {
    KdfParams {
        m_kib: 8192,
        t: 1,
        p: 1,
        salt: random_array().unwrap(),
    }
}

// ---------------------------------------------------------------- server

struct Entry {
    record: Option<Record>,
    tag: u64,
    changed: u64,
}

/// A fake CloudKit zone: a batch goes through only if every record still
/// has the tag the device last saw (none for a new record).
#[derive(Default)]
struct Server {
    records: BTreeMap<(RecordKind, Id), Entry>,
    clock: u64,
}

#[derive(Debug)]
struct Conflict;

fn tag_bytes(tag: u64) -> Vec<u8> {
    tag.to_le_bytes().to_vec()
}

fn tag_of(meta: Option<Vec<u8>>) -> Option<u64> {
    meta.map(|m| u64::from_le_bytes(m.try_into().expect("8-byte tag")))
}

impl Server {
    fn tick(&mut self) -> u64 {
        self.clock += 1;
        self.clock
    }

    fn push(&mut self, batch: &[(Change, Option<u64>)]) -> std::result::Result<Vec<u64>, Conflict> {
        for (c, expected) in batch {
            let current = self
                .records
                .get(&(c.kind, c.id))
                .filter(|e| e.record.is_some())
                .map(|e| e.tag);
            let ok = match (c.data.is_some(), expected, current) {
                (_, None, None) => true,
                (_, Some(e), Some(cur)) => *e == cur,
                (false, Some(_), None) => true,
                _ => false,
            };
            if !ok {
                return Err(Conflict);
            }
        }
        let mut tags = Vec::new();
        for (c, _) in batch {
            let tag = self.tick();
            let record = c.data.clone().map(|data| Record {
                id: c.id,
                kind: c.kind,
                version: c.version,
                data,
            });
            self.records.insert(
                (c.kind, c.id),
                Entry {
                    record,
                    tag,
                    changed: tag,
                },
            );
            tags.push(tag);
        }
        Ok(tags)
    }

    fn changes_since(&self, cursor: u64) -> (Vec<RemoteChange>, u64) {
        let changes = self
            .records
            .iter()
            .filter(|(_, e)| e.changed > cursor)
            .map(|((kind, id), e)| RemoteChange {
                kind: *kind,
                id: *id,
                version: e.record.as_ref().map_or(0, |r| r.version),
                data: e.record.as_ref().map(|r| r.data.clone()),
                server_meta: e.record.as_ref().map(|_| tag_bytes(e.tag)),
            })
            .collect();
        (changes, self.clock)
    }

    fn get(&self, kind: RecordKind, id: Id) -> Option<Record> {
        self.records.get(&(kind, id)).and_then(|e| e.record.clone())
    }

    /// The server serves `record` again as if it were new (a replay).
    fn replay(&mut self, record: Record) {
        let tag = self.tick();
        self.records.insert(
            (record.kind, record.id),
            Entry {
                record: Some(record),
                tag,
                changed: tag,
            },
        );
    }
}

// ---------------------------------------------------------------- devices

struct Device {
    _dir: tempfile::TempDir,
    path: PathBuf,
    cursor: u64,
    repo: Option<Repository<SyncStore>>,
}

impl Device {
    fn empty() -> Device {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("onepass.sqlite");
        Device {
            _dir: dir,
            path,
            cursor: 0,
            repo: None,
        }
    }

    fn create() -> (Device, SecretKey) {
        let mut dev = Device::empty();
        let store = SyncStore::open(&dev.path).unwrap();
        let (mut repo, sk) = Repository::create_account(store, PASSWORD, kdf()).unwrap();
        repo.persist_device_state().unwrap();
        dev.repo = Some(repo);
        (dev, sk)
    }

    fn store(&self) -> SyncStore {
        SyncStore::open(&self.path).unwrap()
    }

    fn repo(&mut self) -> &mut Repository<SyncStore> {
        self.repo.as_mut().expect("device unlocked")
    }

    /// Unlock as the apps do: device state and chain state from the store.
    fn unlock(&mut self, password: &str, sk: &SecretKey) -> Result<Auk> {
        let store = self.store();
        let state = store.device_state()?;
        let (repo, auk) = Repository::unlock_exporting_auk(store, password, sk, state)?;
        self.repo = Some(repo);
        self.repo().persist_device_state()?;
        Ok(auk)
    }

    fn unlock_with_auk(&mut self, auk: &Auk) -> Result<()> {
        let store = self.store();
        let state = store.device_state()?;
        self.repo = Some(Repository::unlock_with_auk(store, auk, state)?);
        self.repo().persist_device_state()
    }

    fn lock(&mut self) {
        self.repo().persist_device_state().unwrap();
        self.repo = None;
    }

    fn vault_id(&mut self) -> Id {
        self.repo().vaults().unwrap().remove(0).id
    }

    fn items(&mut self) -> Vec<Item> {
        let v = self.repo().vaults().unwrap().remove(0);
        self.repo().items(&v).unwrap()
    }

    fn save(&mut self, item: &Item) {
        let v = self.repo().vaults().unwrap().remove(0);
        self.repo().save_item(&v, item.clone()).unwrap();
    }
}

fn outbox(dev: &Device) -> Vec<(Change, Option<u64>)> {
    let store = dev.store();
    store
        .pending_changes()
        .unwrap()
        .into_iter()
        .map(|c| {
            let tag = tag_of(store.server_meta(c.kind, c.id).unwrap());
            (c, tag)
        })
        .collect()
}

fn push(server: &mut Server, dev: &Device) -> std::result::Result<(), Conflict> {
    let batch = outbox(dev);
    let tags = server.push(&batch)?;
    let mut store = dev.store();
    for ((c, _), tag) in batch.iter().zip(tags) {
        let meta = c.data.as_ref().map(|_| tag_bytes(tag));
        store.mark_pushed(c.kind, c.id, c.version, meta).unwrap();
    }
    Ok(())
}

/// Fetch the changes after the cursor that `keep` lets through, stage them
/// and commit at once.
fn pull_only(server: &Server, dev: &mut Device, keep: impl Fn(&RemoteChange) -> bool) {
    let (changes, cursor) = server.changes_since(dev.cursor);
    let mut store = dev.store();
    for c in changes.into_iter().filter(|c| keep(c)) {
        store.stage_remote(c).unwrap();
    }
    store.commit_remote().unwrap();
    dev.cursor = cursor;
}

fn pull(server: &Server, dev: &mut Device) {
    pull_only(server, dev, |_| true);
}

fn sync(server: &mut Server, dev: &mut Device) {
    push(server, dev).expect("push accepted");
    pull(server, dev);
}

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
    let v = a.vault_id();
    a.save(&login(v, "camille.durand@exemple.fr"));
    sync(server, &mut a);
    let mut b = Device::empty();
    pull(server, &mut b);
    let auk = b.unlock(PASSWORD, &sk).unwrap();
    assert_eq!(b.items(), a.items());
    assert_eq!(b.repo().chain().params_epoch, 1);
    (a, b, sk, auk)
}

fn account_id(dev: &mut Device) -> Id {
    dev.repo().account().params.account_id
}

// ---------------------------------------------------------------- tests

#[test]
fn other_device_follows_without_loss() {
    let mut server = Server::default();
    let (mut a, mut b, sk, b_old_auk) = setup(&mut server);
    let v = a.vault_id();

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
    sync(&mut server, &mut a);

    // B fetches the new params: its biometric key and the old password
    // both fail as a wrong password.
    pull(&server, &mut b);
    assert!(wrong_password(b.unlock_with_auk(&b_old_auk)));
    assert!(wrong_password(b.unlock(PASSWORD, &sk)));
    let b_new_auk = b.unlock(NEW_PASSWORD, &sk).unwrap();
    assert_eq!(b_new_auk.as_bytes(), a_new_auk.as_bytes());
    assert_eq!(b.repo().chain().params_epoch, 2);
    assert_eq!(b.store().chain_state().unwrap().params_epoch, 2);

    // Its pending write survived: rebase, push, and A reads it.
    assert_eq!(b.repo().rebase().unwrap(), vec![v]);
    sync(&mut server, &mut b);
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
    assert!(wrong_password(a.unlock(PASSWORD, &sk)));
    a.unlock_with_auk(&a_new_auk).unwrap();
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
    sync(&mut server, &mut a);
    b.lock();
    pull(&server, &mut b);
    b.unlock(NEW_PASSWORD, &sk).unwrap();
    b.lock();

    // The server serves the old params and keyset again.
    server.replay(old_params);
    server.replay(old_keyset);
    pull(&server, &mut b);
    // Refused before any derivation: whichever password, or the old AUK.
    assert_eq!(
        integrity(b.unlock(PASSWORD, &sk)),
        IntegrityError::ParamsRollback
    );
    assert_eq!(
        integrity(b.unlock(NEW_PASSWORD, &sk)),
        IntegrityError::ParamsRollback
    );
    assert_eq!(
        integrity(b.unlock_with_auk(&b_old_auk)),
        IntegrityError::ParamsRollback
    );

    // Control: the refusal is the pinned epoch. A device that never saw the
    // new epoch accepts the replayed pair (trust on first use).
    let mut c = Device::empty();
    pull(&server, &mut c);
    c.unlock(PASSWORD, &sk).unwrap();
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
    sync(&mut server, &mut a);
    b.lock();

    // B gets the new params but not the new keyset.
    let cursor = b.cursor;
    pull_only(&server, &mut b, |c| c.kind == RecordKind::AccountParams);
    for pw in [PASSWORD, NEW_PASSWORD] {
        assert_eq!(integrity(b.unlock(pw, &sk)), IntegrityError::WrongContext);
    }

    // Then the keyset: the pair matches again.
    b.cursor = cursor;
    pull_only(&server, &mut b, |c| c.kind == RecordKind::Keyset);
    b.unlock(NEW_PASSWORD, &sk).unwrap();
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
fn concurrent_changes_second_conflicts() {
    let mut server = Server::default();
    let (mut a, mut b, sk, _) = setup(&mut server);

    // Both devices change the password from epoch 1.
    a.repo()
        .change_password(PASSWORD, &sk, NEW_PASSWORD)
        .unwrap();
    b.repo()
        .change_password(PASSWORD, &sk, "Projet Orion, Camille Durand")
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
    c.unlock(NEW_PASSWORD, &sk).unwrap();
    assert_eq!(c.repo().chain().params_epoch, 2);
}
