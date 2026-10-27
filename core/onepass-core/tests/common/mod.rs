//! Shared harness of the two-device sync tests: a fake CloudKit-like
//! server (atomic conditional batches, a change log read with a cursor, and
//! a few ways for the server to misbehave) and devices over SyncStore
//! files. No network.

#![allow(dead_code, unused_imports)]

pub use std::collections::BTreeMap;
pub use std::path::PathBuf;

pub use onepass_core::account::Auk;
pub use onepass_core::crypto::{KdfParams, SecretKey, random_array};
pub use onepass_core::model::{FieldValue, Item, ItemType, new_item};
pub use onepass_core::repo::{Repository, split_item_record};
pub use onepass_core::store::{Record, RecordKind, RecordStore};
pub use onepass_core::sync::{
    AccountState, Change, RemoteChange, STALE_ALERT_MAX_ROUNDS, STALE_ALERT_ROUNDS,
    STALE_ALERT_SECONDS, STALE_CLEAR_ROUNDS, SyncStore, VaultSyncHealth,
};
pub use onepass_core::vault::{ItemRecord, Vault, VaultMeta};
pub use onepass_core::{Error, Id, IntegrityError, Result};
pub use time::OffsetDateTime;

pub const PASSWORD: &str = "Projet Atlas, Camille Durand";

pub fn kdf() -> KdfParams {
    KdfParams {
        m_kib: 8192,
        t: 1,
        p: 1,
        salt: random_array().unwrap(),
    }
}

// ---------------------------------------------------------------- server

/// One server record. A deletion keeps the entry with `record: None`, so
/// the change log can report it.
#[derive(Clone)]
pub struct Entry {
    pub record: Option<Record>,
    pub tag: u64,
    /// Position in the change log.
    pub changed: u64,
}

/// A fake CloudKit zone: `(kind, id) -> (record, tag)`. A batch goes
/// through only if every record still has the tag the device last saw
/// (none for a new record); otherwise nothing is written.
#[derive(Default, Clone)]
pub struct Server {
    pub records: BTreeMap<(RecordKind, Id), Entry>,
    pub clock: u64,
}

/// What the server answers a refused batch: the records in conflict.
#[derive(Debug)]
pub struct Conflict(pub Vec<(RecordKind, Id)>);

pub fn tag_bytes(tag: u64) -> Vec<u8> {
    tag.to_le_bytes().to_vec()
}

pub fn tag_of(meta: Option<Vec<u8>>) -> Option<u64> {
    meta.map(|m| u64::from_le_bytes(m.try_into().expect("8-byte tag")))
}

impl Server {
    pub fn live(&self, kind: RecordKind, id: Id) -> Option<&Entry> {
        self.records.get(&(kind, id)).filter(|e| e.record.is_some())
    }

    pub fn tick(&mut self) -> u64 {
        self.clock += 1;
        self.clock
    }

    /// Apply the whole batch or nothing. Returns the new tag of each change.
    pub fn push(
        &mut self,
        batch: &[(Change, Option<u64>)],
    ) -> std::result::Result<Vec<u64>, Conflict> {
        let mut conflicts = Vec::new();
        for (c, expected) in batch {
            let current = self.live(c.kind, c.id).map(|e| e.tag);
            let ok = match (c.data.is_some(), expected, current) {
                (_, None, None) => true,
                (_, Some(e), Some(cur)) => *e == cur,
                // Deleting what is already gone is fine.
                (false, Some(_), None) => true,
                _ => false,
            };
            if !ok {
                conflicts.push((c.kind, c.id));
            }
        }
        if !conflicts.is_empty() {
            return Err(Conflict(conflicts));
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

    /// Every change after `cursor`, and the new cursor.
    pub fn changes_since(&self, cursor: u64) -> (Vec<RemoteChange>, u64) {
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

    pub fn get(&self, kind: RecordKind, id: Id) -> Option<Record> {
        self.live(kind, id).and_then(|e| e.record.clone())
    }

    /// The server serves `record` again as if it were new (a replay).
    pub fn replay(&mut self, record: Record) {
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

    /// The server logs a deletion no client asked for (a forged tombstone).
    pub fn forge_deletion(&mut self, kind: RecordKind, id: Id) {
        let tag = self.tick();
        self.records.insert(
            (kind, id),
            Entry {
                record: None,
                tag,
                changed: tag,
            },
        );
    }

    /// The server drops a record without telling anyone.
    pub fn withhold(&mut self, kind: RecordKind, id: Id) {
        self.records.remove(&(kind, id));
    }

    /// The blob id of the server record holding this version of the item.
    pub fn item_blob(&self, item_id: Id, version: u64) -> Id {
        self.records
            .iter()
            .filter(|((k, _), _)| *k == RecordKind::Item)
            .find_map(|((_, id), e)| {
                let data = &e.record.as_ref()?.data;
                let (_, body) = split_item_record(data).ok()?;
                let rec = ItemRecord::decode(body).ok()?;
                (rec.item_id == item_id && rec.version == version).then_some(*id)
            })
            .expect("item record on the server")
    }
}

// ---------------------------------------------------------------- devices

/// A device: its own SQLite file, its fetch cursor, and a session while
/// unlocked. Sync runs on its own connection, locked or not.
pub struct Device {
    pub _dir: tempfile::TempDir,
    pub path: PathBuf,
    pub cursor: u64,
    pub repo: Option<Repository<SyncStore>>,
}

impl Device {
    pub fn empty() -> Device {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("onepass.sqlite");
        Device {
            _dir: dir,
            path,
            cursor: 0,
            repo: None,
        }
    }

    /// A new device that creates the account.
    pub fn create() -> (Device, SecretKey) {
        let mut dev = Device::empty();
        let store = SyncStore::open(&dev.path).unwrap();
        let (mut repo, sk) = Repository::create_account(store, PASSWORD, kdf()).unwrap();
        repo.persist_device_state().unwrap();
        dev.repo = Some(repo);
        (dev, sk)
    }

    /// A second connection on the device file, as the sync manager has.
    pub fn store(&self) -> SyncStore {
        SyncStore::open(&self.path).unwrap()
    }

    pub fn repo(&mut self) -> &mut Repository<SyncStore> {
        self.repo.as_mut().expect("device unlocked")
    }

    pub fn unlock(&mut self, sk: &SecretKey) {
        let store = self.store();
        let state = store.device_state().unwrap();
        self.repo = Some(Repository::unlock(store, PASSWORD, sk, state).unwrap());
    }

    pub fn lock(&mut self) {
        self.repo().persist_device_state().unwrap();
        self.repo = None;
    }

    pub fn vault(&mut self) -> Vault {
        self.repo().vaults().unwrap().remove(0)
    }

    pub fn vault_named(&mut self, name: &str) -> Vault {
        self.repo()
            .vaults()
            .unwrap()
            .into_iter()
            .find(|v| v.meta.name == name)
            .unwrap()
    }

    pub fn items(&mut self) -> Vec<Item> {
        let v = self.vault();
        self.repo().items(&v).unwrap()
    }

    pub fn try_items(&mut self) -> Result<Vec<Item>> {
        let v = self.vault();
        self.repo().items(&v)
    }

    pub fn save(&mut self, item: &Item) {
        let v = self.vault();
        self.repo().save_item(&v, item.clone()).unwrap();
    }

    pub fn delete(&mut self, item_id: Id) {
        let v = self.vault();
        self.repo().delete_item(&v, item_id).unwrap();
    }
}

/// The changes a push would send, with the tag each one expects.
pub fn outbox(dev: &Device) -> Vec<(Change, Option<u64>)> {
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

/// Send `batch`; if the server takes it and `mark` is set, confirm each row.
pub fn send(
    server: &mut Server,
    dev: &Device,
    batch: Vec<(Change, Option<u64>)>,
    mark: bool,
) -> std::result::Result<(), Conflict> {
    let tags = server.push(&batch)?;
    if mark {
        let mut store = dev.store();
        for ((c, _), tag) in batch.iter().zip(tags) {
            let meta = c.data.as_ref().map(|_| tag_bytes(tag));
            store.mark_pushed(c.kind, c.id, c.version, meta).unwrap();
        }
    }
    Ok(())
}

pub fn push(server: &mut Server, dev: &Device) -> std::result::Result<(), Conflict> {
    send(server, dev, outbox(dev), true)
}

/// Fetch everything after the cursor: stage it all, then commit at once.
pub fn pull(server: &Server, dev: &mut Device) {
    let (changes, cursor) = server.changes_since(dev.cursor);
    let mut store = dev.store();
    for c in changes {
        store.stage_remote(c).unwrap();
    }
    store.commit_remote().unwrap();
    dev.cursor = cursor;
}

/// A fetch from scratch (token lost or expired): every live record, then the
/// settlement of the rows the server did not return.
pub fn full_fetch(server: &Server, dev: &mut Device) {
    let (changes, cursor) = server.changes_since(0);
    let mut store = dev.store();
    store.begin_full_fetch().unwrap();
    for c in changes.into_iter().filter(|c| c.data.is_some()) {
        store.stage_remote(c).unwrap();
    }
    store.commit_remote().unwrap();
    store.finish_full_fetch().unwrap();
    dev.cursor = cursor;
}

/// Push; on a conflict pull, rebase and push again (three rounds at most).
/// Then pull what the others wrote.
pub fn sync(server: &mut Server, dev: &mut Device) -> Result<()> {
    for _ in 0..3 {
        match push(server, dev) {
            Ok(()) => {
                pull(server, dev);
                return Ok(());
            }
            Err(_) => {
                pull(server, dev);
                dev.repo().rebase()?;
            }
        }
    }
    panic!("no agreement after three rounds");
}

/// Change token key of the harness devices (any name the store does not use).
pub const TOKEN_KEY: &str = "sync.token";

/// The zone was deleted and recreated: the device settles a reset fetch of
/// what the zone holds now, so the rows it lacks go up again.
pub fn zone_reset(server: &Server, dev: &mut Device) {
    let (changes, cursor) = server.changes_since(0);
    let mut store = dev.store();
    store.begin_zone_reset(TOKEN_KEY).unwrap();
    for c in changes.into_iter().filter(|c| c.data.is_some()) {
        store.stage_remote(c).unwrap();
    }
    store.commit_remote().unwrap();
    store.finish_full_fetch().unwrap();
    dev.cursor = cursor;
}

/// One sync round as the apps run it, unlocked, at `now`: push (pull and
/// rebase on a conflict), pull, rebase what is still held, then count the
/// round (`note_sync_round`).
pub fn round(server: &mut Server, dev: &mut Device, now: i64) -> Result<()> {
    let synced = sync(server, dev);
    if synced.is_ok() && !dev.store().vaults_needing_rebase()?.is_empty() {
        dev.repo().rebase()?;
    }
    dev.repo().note_sync_round(now)?;
    synced
}

/// `STALE_CLEAR_ROUNDS` rounds for every device, from `now`, one minute
/// apart: long enough for a vault the server caught up on to be `Ok` again.
pub fn settle(server: &mut Server, devs: &mut [&mut Device], now: i64) {
    for i in 0..STALE_CLEAR_ROUNDS {
        for dev in devs.iter_mut() {
            round(server, dev, now + 60 * i64::from(i)).unwrap();
        }
    }
}

/// The sync health of one vault.
pub fn health(dev: &mut Device, vault: Id) -> VaultSyncHealth {
    dev.repo().sync_health().unwrap()[&vault]
}

pub fn is_behind(h: VaultSyncHealth) -> bool {
    matches!(h, VaultSyncHealth::ServerBehind { .. })
}

/// A pending change as the record the server would hold.
pub fn as_record(c: &Change) -> Record {
    Record {
        kind: c.kind,
        id: c.id,
        version: c.version,
        data: c.data.clone().expect("a write"),
    }
}

// ---------------------------------------------------------------- items

pub fn at(unix: i64) -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(unix).unwrap()
}

/// A login in `vault`, created and last edited at `when`.
pub fn login(vault: Id, user: &str, when: i64) -> Item {
    let mut item = new_item(ItemType::Login, vault, "Exemple");
    item.field_mut("username").unwrap().value = FieldValue::Text(user.into());
    item.created_at = at(when);
    item.updated_at = at(when);
    item
}

pub fn edited(item: &Item, user: &str, when: i64) -> Item {
    let mut out = item.clone();
    out.field_mut("username").unwrap().value = FieldValue::Text(user.into());
    out.updated_at = at(when);
    out
}

pub fn users(items: &[Item]) -> Vec<String> {
    let mut out: Vec<String> = items.iter().map(Item::subtitle).collect();
    out.sort();
    out
}

pub fn integrity<T: std::fmt::Debug>(r: Result<T>) -> IntegrityError {
    match r {
        Err(Error::Integrity(e)) => e,
        other => panic!("expected an integrity error, got {other:?}"),
    }
}

pub const T0: i64 = 1_793_000_000;

/// Device A with its vault id, before anything syncs, for building items.
pub fn personal_vault_of(dev: &mut Device) -> Id {
    dev.vault().id
}

pub fn setup(
    server: &mut Server,
    users_at: &[(&str, i64)],
) -> (Device, Device, SecretKey, Vec<Item>) {
    let (mut a, sk) = Device::create();
    let v = personal_vault_of(&mut a);
    let items: Vec<Item> = users_at.iter().map(|(u, t)| login(v, u, *t)).collect();
    for i in &items {
        a.save(i);
    }
    sync(server, &mut a).unwrap();
    let mut b = Device::empty();
    pull(server, &mut b);
    b.unlock(&sk);
    assert_eq!(b.items(), a.items());
    (a, b, sk, items)
}

pub fn meta(name: &str) -> VaultMeta {
    VaultMeta {
        name: name.into(),
        icon: "briefcase".into(),
        color: "green".into(),
        travel_safe: false,
        mcp_access: false,
    }
}
impl Device {
    /// Unlock with `password` as the apps do (device state and chain state
    /// from the store), persist, and hand back the Account Unlock Key.
    pub fn try_unlock(&mut self, password: &str, sk: &SecretKey) -> Result<Auk> {
        let store = self.store();
        let state = store.device_state()?;
        let (repo, auk) = Repository::unlock_exporting_auk(store, password, sk, state)?;
        self.repo = Some(repo);
        self.repo().persist_device_state()?;
        Ok(auk)
    }

    /// Unlock with a kept Account Unlock Key, then persist.
    pub fn try_unlock_with_auk(&mut self, auk: &Auk) -> Result<()> {
        let store = self.store();
        let state = store.device_state()?;
        self.repo = Some(Repository::unlock_with_auk(store, auk, state)?);
        self.repo().persist_device_state()
    }
}

/// Fetch the changes after the cursor that `keep` lets through, stage them
/// and commit at once (a torn fetch when `keep` drops some).
pub fn pull_only(server: &Server, dev: &mut Device, keep: impl Fn(&RemoteChange) -> bool) {
    let (changes, cursor) = server.changes_since(dev.cursor);
    let mut store = dev.store();
    for c in changes.into_iter().filter(|c| keep(c)) {
        store.stage_remote(c).unwrap();
    }
    store.commit_remote().unwrap();
    dev.cursor = cursor;
}
