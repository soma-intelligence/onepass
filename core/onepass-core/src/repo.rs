//! Repository: ties the account, its vaults, items and manifests to a
//! record store, and verifies everything it reads back from it.
//!
//! Layout in the store:
//! - account params (`AccountParams`) and keyset (`Keyset`), id = account id;
//! - vault key envelope (`VaultKey`) and sealed meta (`VaultMeta`), id = vault id;
//! - signed manifest (`Manifest`), id = vault id, version = seq,
//!   data = `postcard(SignedManifest)`;
//! - item records (`Item`), id = a fresh blob id per written version,
//!   version = item version, data = `vault_id (16 bytes) || postcard(ItemRecord)`.
//!
//! Item versions get their own blob ids so that writing a new version never
//! overwrites the one the current manifest lists. Writes go record first,
//! manifest second, cleanup last. A crash before the manifest leaves an
//! interrupted write, which loading ignores: a record that opens under the
//! vault key and carries exactly the next version of a listed item, or
//! version 1 of an item the manifest does not list. Any other record that
//! does not match the manifest is reported, as `check_records` does.
//!
//! Known limit: a crash after the manifest is written but before the old
//! record is deleted leaves a stale record, reported as
//! `ManifestUnexpectedItem` on the next load (the data is intact).

use std::collections::BTreeMap;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::account::{Account, NewAccount, PinnedAccount};
use crate::crypto::{KdfParams, SecretKey};
use crate::manifest::{
    Manifest, ManifestEntry, SeenManifest, SignedManifest, check_records, manifest_hash,
    record_hash, sign_manifest, verify_manifest,
};
use crate::model::Item;
use crate::store::{Record, RecordKind, RecordStore};
use crate::vault::{ItemRecord, Vault, VaultMeta};
use crate::{Error, Id, IntegrityError, Result};

/// What a device keeps between sessions: the account pinned at first
/// unlock, and the last manifest accepted for each vault.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct DeviceState {
    pub pinned: Option<PinnedAccount>,
    pub last_seen: BTreeMap<Id, SeenManifest>,
}

/// An unlocked account over a record store it does not trust.
pub struct Repository<S: RecordStore> {
    store: S,
    account: Account,
    device: DeviceState,
}

/// The verified content of a vault.
struct Loaded {
    manifest: Manifest,
    /// Records matching the manifest, sorted by item id, with their blob ids.
    records: Vec<(Id, ItemRecord)>,
    /// Interrupted writes: `(blob id, item id)`, ignored on load.
    pending: Vec<(Id, Id)>,
}

impl Loaded {
    fn listed(&self, item_id: Id) -> Option<&(Id, ItemRecord)> {
        self.records.iter().find(|(_, r)| r.item_id == item_id)
    }

    fn next_version(&self, item_id: Id) -> Result<u64> {
        match self.listed(item_id) {
            Some((_, r)) => r
                .version
                .checked_add(1)
                .ok_or(Error::InvalidFormat("item version")),
            None => Ok(1),
        }
    }

    fn pending_of(&self, item_id: Id) -> impl Iterator<Item = Id> + '_ {
        self.pending
            .iter()
            .filter(move |(_, i)| *i == item_id)
            .map(|(blob, _)| *blob)
    }

    /// The manifest entries without `item_id`.
    fn entries_without(&self, item_id: Id) -> Vec<ManifestEntry> {
        self.manifest
            .entries
            .iter()
            .filter(|e| e.item_id != item_id)
            .cloned()
            .collect()
    }
}

fn pin(account: &Account) -> PinnedAccount {
    PinnedAccount {
        account_id: account.params.account_id,
        identity_pub: account.params.identity_pub.clone(),
        kdf_floor: account.params.kdf.clone(),
    }
}

fn seen(m: &Manifest) -> SeenManifest {
    SeenManifest {
        seq: m.seq,
        hash: manifest_hash(m),
    }
}

fn entry(rec: &ItemRecord) -> ManifestEntry {
    ManifestEntry {
        item_id: rec.item_id,
        version: rec.version,
        record_hash: record_hash(rec),
    }
}

/// Decode the whole buffer: trailing bytes are refused.
fn decode_all<T: DeserializeOwned>(bytes: &[u8]) -> Option<T> {
    match postcard::take_from_bytes(bytes) {
        Ok((value, [])) => Some(value),
        _ => None,
    }
}

fn personal() -> VaultMeta {
    VaultMeta {
        name: "Personnel".into(),
        icon: "person".into(),
        color: "blue".into(),
        travel_safe: false,
        mcp_access: false,
    }
}

impl<S: RecordStore> Repository<S> {
    /// Create an account in an empty store: params, keyset, then the
    /// "Personnel" vault. The device pins the new account.
    pub fn create_account(
        mut store: S,
        password: &str,
        kdf: KdfParams,
    ) -> Result<(Repository<S>, SecretKey)> {
        if !store.list(RecordKind::AccountParams)?.is_empty() {
            return Err(Error::InvalidFormat("store already holds an account"));
        }
        let NewAccount {
            account,
            secret_key,
            params_record,
            keyset_record,
        } = Account::create_with_params(password, kdf)?;
        let id = account.params.account_id;
        for (kind, data) in [
            (RecordKind::AccountParams, params_record),
            (RecordKind::Keyset, keyset_record),
        ] {
            store.put(Record {
                id,
                kind,
                version: 1,
                data,
            })?;
        }
        let device = DeviceState {
            pinned: Some(pin(&account)),
            last_seen: BTreeMap::new(),
        };
        let mut repo = Repository {
            store,
            account,
            device,
        };
        repo.create_vault(personal())?;
        Ok((repo, secret_key))
    }

    /// Unlock the single account of the store (`NotFound` if there is none,
    /// `InvalidFormat("account params")` if there are several). On a device
    /// that pinned nothing yet, the account is pinned now (trust on first
    /// use); otherwise `Account::unlock` checks it against the pin.
    pub fn unlock(
        store: S,
        password: &str,
        secret_key: &SecretKey,
        mut device: DeviceState,
    ) -> Result<Repository<S>> {
        let mut found = store.list(RecordKind::AccountParams)?;
        let params = match found.len() {
            0 => return Err(Error::NotFound),
            1 => found.remove(0),
            _ => return Err(Error::InvalidFormat("account params")),
        };
        let keyset = store
            .get(RecordKind::Keyset, params.id)?
            .ok_or(Error::NotFound)?;
        let account = Account::unlock(
            password,
            secret_key,
            &params.data,
            &keyset.data,
            device.pinned.as_ref(),
        )?;
        if account.params.account_id != params.id {
            return Err(IntegrityError::WrongContext.into());
        }
        if device.pinned.is_none() {
            device.pinned = Some(pin(&account));
        }
        Ok(Repository {
            store,
            account,
            device,
        })
    }

    /// The state to persist on the device after each session.
    pub fn device_state(&self) -> &DeviceState {
        &self.device
    }

    /// Every vault of the account, sorted by id. A key envelope without its
    /// meta record is `InvalidFormat("vault meta")`.
    pub fn vaults(&self) -> Result<Vec<Vault>> {
        let mut out = Vec::new();
        for key in self.store.list(RecordKind::VaultKey)? {
            let meta = self
                .store
                .get(RecordKind::VaultMeta, key.id)?
                .ok_or(Error::InvalidFormat("vault meta"))?;
            out.push(Vault::open(&self.account, key.id, &key.data, &meta.data)?);
        }
        out.sort_by_key(|v| v.id);
        Ok(out)
    }

    /// Create a vault with an empty signed manifest (seq 1), so that a
    /// vault without a manifest is always a storage fault. The key envelope
    /// is written last: until then the vault is not listed.
    pub fn create_vault(&mut self, meta: VaultMeta) -> Result<Vault> {
        let (vault, envelope, meta_blob) = Vault::create(&self.account, meta)?;
        self.write_manifest(&vault, &Manifest::next(None, vault.id, vec![]))?;
        for (kind, data) in [
            (RecordKind::VaultMeta, meta_blob),
            (RecordKind::VaultKey, envelope),
        ] {
            self.store.put(Record {
                id: vault.id,
                kind,
                version: 1,
                data,
            })?;
        }
        Ok(vault)
    }

    /// The items of a vault, sorted by id, after verifying the manifest
    /// against the last one seen and the records against the manifest. The
    /// manifest is then remembered as the last one seen.
    pub fn items(&mut self, vault: &Vault) -> Result<Vec<Item>> {
        let loaded = self.load(vault)?;
        let items = loaded
            .records
            .iter()
            .map(|(_, r)| vault.open_item(r))
            .collect::<Result<Vec<_>>>()?;
        self.device
            .last_seen
            .insert(vault.id, seen(&loaded.manifest));
        Ok(items)
    }

    /// Store a new version of the item (or its first one), then the
    /// manifest that lists it, then delete the previous record.
    pub fn save_item(&mut self, vault: &Vault, item: Item) -> Result<()> {
        let loaded = self.load(vault)?;
        let rec = vault.seal_item(&item, loaded.next_version(item.id)?)?;
        let old = loaded.listed(item.id).map(|(blob, _)| *blob);
        self.delete_pending(&loaded, item.id)?;
        self.put_item(vault.id, &rec)?;
        let mut entries = loaded.entries_without(item.id);
        entries.push(entry(&rec));
        self.write_manifest(
            vault,
            &Manifest::next(Some(&loaded.manifest), vault.id, entries),
        )?;
        if let Some(blob) = old {
            self.store.delete(RecordKind::Item, blob)?;
        }
        Ok(())
    }

    /// Remove an item for good: manifest without it first, then its record.
    pub fn delete_item(&mut self, vault: &Vault, item_id: Id) -> Result<()> {
        let loaded = self.load(vault)?;
        let (blob, _) = *loaded.listed(item_id).ok_or(Error::NotFound)?;
        self.delete_pending(&loaded, item_id)?;
        let entries = loaded.entries_without(item_id);
        self.write_manifest(
            vault,
            &Manifest::next(Some(&loaded.manifest), vault.id, entries),
        )?;
        self.store.delete(RecordKind::Item, blob)
    }

    /// Put the item in the trash: a new version with `trashed_at` set.
    pub fn trash_item(&mut self, vault: &Vault, item_id: Id) -> Result<()> {
        self.update(vault, item_id, |item, now| item.trashed_at = Some(now))
    }

    /// Archive the item: a new version with `archived` set.
    pub fn archive_item(&mut self, vault: &Vault, item_id: Id) -> Result<()> {
        self.update(vault, item_id, |item, _| item.archived = true)
    }

    /// Move an item to another vault: the record re-sealed for `to`
    /// (version 1 there, or the next one if `to` already lists it), the
    /// manifest of `to`, the manifest of `from`, then the old record. A crash
    /// between the two manifests leaves the item in both vaults.
    pub fn move_item(&mut self, item_id: Id, from: &Vault, to: &Vault) -> Result<()> {
        if from.id == to.id {
            return Err(Error::InvalidFormat("move to the same vault"));
        }
        let src = self.load(from)?;
        let (blob, rec) = src.listed(item_id).ok_or(Error::NotFound)?.clone();
        let dst = self.load(to)?;
        let moved = from.move_item(to, &rec, dst.next_version(item_id)?)?;
        let replaced = dst.listed(item_id).map(|(b, _)| *b);
        self.delete_pending(&dst, item_id)?;
        self.put_item(to.id, &moved)?;
        let mut entries = dst.entries_without(item_id);
        entries.push(entry(&moved));
        self.write_manifest(to, &Manifest::next(Some(&dst.manifest), to.id, entries))?;
        let entries = src.entries_without(item_id);
        self.write_manifest(from, &Manifest::next(Some(&src.manifest), from.id, entries))?;
        self.delete_pending(&src, item_id)?;
        self.store.delete(RecordKind::Item, blob)?;
        if let Some(b) = replaced {
            self.store.delete(RecordKind::Item, b)?;
        }
        Ok(())
    }

    /// Open the listed item, apply `change` with the current time, bump
    /// `updated_at` and save it as a new version.
    fn update(
        &mut self,
        vault: &Vault,
        item_id: Id,
        change: impl FnOnce(&mut Item, OffsetDateTime),
    ) -> Result<()> {
        let loaded = self.load(vault)?;
        let (_, rec) = loaded.listed(item_id).ok_or(Error::NotFound)?;
        let mut item = vault.open_item(rec)?;
        let now = OffsetDateTime::now_utc();
        change(&mut item, now);
        item.updated_at = now;
        self.save_item(vault, item)
    }

    /// Load and verify the manifest and item records of a vault.
    ///
    /// Errors: no manifest record is `ManifestMissingItem` (the vault was
    /// created with one, so the store dropped it); an undecodable manifest
    /// record is `InvalidFormat("manifest")`; an item record shorter than
    /// the 16 byte vault prefix is `InvalidFormat("item record")`; a record
    /// with this vault's prefix that does not decode is
    /// `ManifestUnexpectedItem`. Then `verify_manifest` and `check_records`.
    fn load(&self, vault: &Vault) -> Result<Loaded> {
        let rec = self
            .store
            .get(RecordKind::Manifest, vault.id)?
            .ok_or(IntegrityError::ManifestMissingItem)?;
        let sm: SignedManifest = decode_all(&rec.data).ok_or(Error::InvalidFormat("manifest"))?;
        let manifest = verify_manifest(
            vault,
            &self.account.params.signing_pub,
            &sm,
            self.device.last_seen.get(&vault.id),
        )?;

        let mut records = Vec::new();
        let mut pending = Vec::new();
        for r in self.store.list(RecordKind::Item)? {
            let (prefix, body) = r
                .data
                .split_at_checked(16)
                .ok_or(Error::InvalidFormat("item record"))?;
            if prefix != vault.id.0 {
                continue;
            }
            let item: ItemRecord =
                decode_all(body).ok_or(IntegrityError::ManifestUnexpectedItem)?;
            if interrupted_write(vault, &manifest, &item) {
                pending.push((r.id, item.item_id));
            } else {
                records.push((r.id, item));
            }
        }
        records.sort_by_key(|(_, r)| r.item_id);
        let plain: Vec<ItemRecord> = records.iter().map(|(_, r)| r.clone()).collect();
        check_records(&manifest, &plain)?;
        Ok(Loaded {
            manifest,
            records,
            pending,
        })
    }

    fn delete_pending(&mut self, loaded: &Loaded, item_id: Id) -> Result<()> {
        for blob in loaded.pending_of(item_id) {
            self.store.delete(RecordKind::Item, blob)?;
        }
        Ok(())
    }

    fn put_item(&mut self, vault_id: Id, rec: &ItemRecord) -> Result<()> {
        let mut data = vault_id.0.to_vec();
        data.extend(postcard::to_allocvec(rec).map_err(|_| Error::InvalidFormat("item record"))?);
        self.store.put(Record {
            id: Id::new(),
            kind: RecordKind::Item,
            version: rec.version,
            data,
        })
    }

    /// Sign and store the manifest, and remember it as the last one seen.
    fn write_manifest(&mut self, vault: &Vault, m: &Manifest) -> Result<()> {
        let sm = sign_manifest(vault, &self.account.keyset().signing, m)?;
        let data = postcard::to_allocvec(&sm).map_err(|_| Error::InvalidFormat("manifest"))?;
        self.store.put(Record {
            id: vault.id,
            kind: RecordKind::Manifest,
            version: m.seq,
            data,
        })?;
        self.device.last_seen.insert(vault.id, seen(m));
        Ok(())
    }
}

/// A record left by a write that stopped before its manifest: exactly the
/// next version of a listed item, or version 1 of an unlisted one, and it
/// opens under this vault's key (so the store cannot fake one).
fn interrupted_write(vault: &Vault, m: &Manifest, rec: &ItemRecord) -> bool {
    let expected = match m.entries.binary_search_by_key(&rec.item_id, |e| e.item_id) {
        Ok(i) => m.entries[i].version.checked_add(1),
        Err(_) => Some(1),
    };
    expected == Some(rec.version) && vault.open_item(rec).is_ok()
}

#[cfg(test)]
mod tests {
    use std::sync::OnceLock;

    use super::*;
    use crate::account::NewAccount;
    use crate::crypto::random_array;
    use crate::model::{FieldValue, ItemType, new_item};
    use crate::store::{MemoryStore, Record, RecordKind, SqliteStore};
    use crate::vault::ItemRecord;
    use crate::{Error, IntegrityError};

    fn kdf() -> KdfParams {
        KdfParams {
            m_kib: 8192,
            t: 1,
            p: 1,
            salt: random_array().unwrap(),
        }
    }

    /// One account shared by the tests that do not test creation itself.
    fn shared() -> &'static NewAccount {
        static N: OnceLock<NewAccount> = OnceLock::new();
        N.get_or_init(|| Account::create_with_params("pw", kdf()).unwrap())
    }

    /// Write the shared account into `store`, unlock it on a new device and
    /// give it one vault.
    fn fresh<S: RecordStore>(mut store: S) -> (Repository<S>, Vault) {
        let n = shared();
        let id = n.account.params.account_id;
        for (kind, data) in [
            (RecordKind::AccountParams, &n.params_record),
            (RecordKind::Keyset, &n.keyset_record),
        ] {
            store
                .put(Record {
                    id,
                    kind,
                    version: 1,
                    data: data.clone(),
                })
                .unwrap();
        }
        let mut repo =
            Repository::unlock(store, "pw", &n.secret_key, DeviceState::default()).unwrap();
        let v = repo.create_vault(meta("A")).unwrap();
        (repo, v)
    }

    fn meta(name: &str) -> VaultMeta {
        VaultMeta {
            name: name.into(),
            icon: "key".into(),
            color: "blue".into(),
            travel_safe: false,
            mcp_access: false,
        }
    }

    fn login(v: &Vault, user: &str) -> Item {
        let mut item = new_item(ItemType::Login, v.id, "Example");
        item.field_mut("username").unwrap().value = FieldValue::Text(user.into());
        item
    }

    fn user(item: &Item) -> String {
        item.subtitle()
    }

    /// Store an item record by hand, as an interrupted write would leave it.
    fn put_raw<S: RecordStore>(repo: &mut Repository<S>, vault_id: Id, rec: &ItemRecord) -> Id {
        let mut data = vault_id.0.to_vec();
        data.extend(postcard::to_allocvec(rec).unwrap());
        let id = Id::new();
        repo.store
            .put(Record {
                id,
                kind: RecordKind::Item,
                version: rec.version,
                data,
            })
            .unwrap();
        id
    }

    fn integrity<T: std::fmt::Debug>(r: Result<T>) -> IntegrityError {
        match r {
            Err(Error::Integrity(e)) => e,
            other => panic!("expected an integrity error, got {other:?}"),
        }
    }

    #[test]
    fn create_save_reload() {
        let (mut repo, sk) =
            Repository::create_account(MemoryStore::new(), "pass word", kdf()).unwrap();
        let pinned = repo.device_state().pinned.clone().unwrap();
        assert_eq!(pinned.account_id, repo.account.params.account_id);
        let vaults = repo.vaults().unwrap();
        assert_eq!(vaults.len(), 1);
        assert_eq!(vaults[0].meta.name, "Personnel");
        assert_eq!(repo.items(&vaults[0]).unwrap(), vec![]);

        let item = login(&vaults[0], "alice");
        repo.save_item(&vaults[0], item.clone()).unwrap();
        let device = repo.device_state().clone();

        let mut again = Repository::unlock(repo.store, "pass word", &sk, device).unwrap();
        let vaults = again.vaults().unwrap();
        assert_eq!(again.items(&vaults[0]).unwrap(), vec![item]);
        assert_eq!(again.device_state().pinned, Some(pinned));
        assert!(matches!(
            Repository::unlock(again.store, "wrong", &sk, DeviceState::default()),
            Err(Error::WrongPassword)
        ));
    }

    #[test]
    fn interrupted_write_keeps_last_consistent_version() {
        let (mut repo, v) = fresh(MemoryStore::new());
        let item = login(&v, "v1");
        repo.save_item(&v, item.clone()).unwrap();

        // Next version of the item, record written, manifest never written.
        let rec = v.seal_item(&login_as(&item, "v2"), 2).unwrap();
        put_raw(&mut repo, v.id, &rec);
        // A new item, record written, manifest never written.
        let other = login(&v, "new");
        put_raw(&mut repo, v.id, &v.seal_item(&other, 1).unwrap());

        assert_eq!(repo.items(&v).unwrap(), vec![item.clone()]);

        // The next save goes through and clears the leftovers.
        repo.save_item(&v, login_as(&item, "v3")).unwrap();
        let items = repo.items(&v).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(user(&items[0]), "v3");
        assert_eq!(repo.store.list(RecordKind::Item).unwrap().len(), 2);
    }

    fn login_as(item: &Item, name: &str) -> Item {
        let mut out = item.clone();
        out.field_mut("username").unwrap().value = FieldValue::Text(name.into());
        out
    }

    #[test]
    fn records_that_are_not_interrupted_writes_stay_errors() {
        let (mut repo, v) = fresh(MemoryStore::new());
        let item = login(&v, "v1");
        repo.save_item(&v, item.clone()).unwrap();

        // Two versions ahead: not an interrupted write.
        let rec = v.seal_item(&login_as(&item, "v3"), 3).unwrap();
        let stray = put_raw(&mut repo, v.id, &rec);
        assert_eq!(
            integrity(repo.items(&v)),
            IntegrityError::ManifestUnexpectedItem
        );
        repo.store.delete(RecordKind::Item, stray).unwrap();
        assert_eq!(repo.items(&v).unwrap(), vec![item.clone()]);

        // Version + 1, but sealed for another vault: injected, not pending.
        let w = repo.create_vault(meta("B")).unwrap();
        let mut foreign = login_as(&item, "x");
        foreign.vault_id = w.id;
        let rec = w.seal_item(&foreign, 2).unwrap();
        assert_eq!(rec.item_id, item.id);
        put_raw(&mut repo, v.id, &rec);
        assert_eq!(
            integrity(repo.items(&v)),
            IntegrityError::ManifestUnexpectedItem
        );
    }

    #[test]
    fn missing_or_old_manifest_is_refused() {
        let (mut repo, v) = fresh(MemoryStore::new());
        repo.save_item(&v, login(&v, "a")).unwrap();
        let old = repo.store.get(RecordKind::Manifest, v.id).unwrap().unwrap();
        repo.save_item(&v, login(&v, "b")).unwrap();
        assert_eq!(repo.items(&v).unwrap().len(), 2);
        let seen = repo.device_state().last_seen[&v.id].clone();
        assert_eq!(seen.seq, 3);

        let current = repo.store.get(RecordKind::Manifest, v.id).unwrap().unwrap();
        repo.store.put(old).unwrap();
        assert_eq!(integrity(repo.items(&v)), IntegrityError::ManifestRollback);

        repo.store.delete(RecordKind::Manifest, v.id).unwrap();
        assert_eq!(
            integrity(repo.items(&v)),
            IntegrityError::ManifestMissingItem
        );

        let mut bad = current.clone();
        bad.data.truncate(bad.data.len() - 1);
        repo.store.put(bad).unwrap();
        assert_eq!(repo.items(&v), Err(Error::InvalidFormat("manifest")));

        repo.store.put(current).unwrap();
        assert_eq!(repo.items(&v).unwrap().len(), 2);
    }

    #[test]
    fn delete_trash_archive() {
        let (mut repo, v) = fresh(MemoryStore::new());
        let (a, b, c) = (login(&v, "a"), login(&v, "b"), login(&v, "c"));
        for i in [&a, &b, &c] {
            repo.save_item(&v, i.clone()).unwrap();
        }
        repo.delete_item(&v, a.id).unwrap();
        repo.trash_item(&v, b.id).unwrap();
        repo.archive_item(&v, c.id).unwrap();
        let items = repo.items(&v).unwrap();
        assert_eq!(items.len(), 2);
        let get = |id| items.iter().find(|i| i.id == id).unwrap();
        assert!(get(b.id).trashed_at.is_some());
        assert!(!get(b.id).archived);
        assert!(get(c.id).archived);
        assert!(get(c.id).trashed_at.is_none());
        assert_eq!(repo.store.list(RecordKind::Item).unwrap().len(), 2);
        assert_eq!(repo.delete_item(&v, a.id), Err(Error::NotFound));
    }

    #[test]
    fn unlock_requires_exactly_one_account() {
        let n = shared();
        assert!(matches!(
            Repository::unlock(
                MemoryStore::new(),
                "pw",
                &n.secret_key,
                DeviceState::default()
            ),
            Err(Error::NotFound)
        ));
        let (repo, _) = fresh(MemoryStore::new());
        let mut store = repo.store;
        let mut twin = store
            .list(RecordKind::AccountParams)
            .unwrap()
            .pop()
            .unwrap();
        twin.id = Id::new();
        store.put(twin).unwrap();
        assert!(matches!(
            Repository::unlock(store, "pw", &n.secret_key, DeviceState::default()),
            Err(Error::InvalidFormat(_))
        ));
    }

    #[test]
    fn sqlite_store_persists_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("onepass.sqlite");
        let (mut repo, v) = fresh(SqliteStore::open(&path).unwrap());
        let item = login(&v, "alice");
        repo.save_item(&v, item.clone()).unwrap();
        let device = repo.device_state().clone();
        drop(repo);

        let store = SqliteStore::open(&path).unwrap();
        let mut repo = Repository::unlock(store, "pw", &shared().secret_key, device).unwrap();
        let vaults = repo.vaults().unwrap();
        assert_eq!(vaults.len(), 1);
        assert_eq!(repo.items(&vaults[0]).unwrap(), vec![item]);
    }

    #[test]
    fn move_item_between_vaults() {
        let (mut repo, a) = fresh(MemoryStore::new());
        let b = repo.create_vault(meta("B")).unwrap();
        let item = login(&a, "alice");
        let stay = login(&a, "bob");
        repo.save_item(&a, item.clone()).unwrap();
        repo.save_item(&a, stay.clone()).unwrap();

        repo.move_item(item.id, &a, &b).unwrap();
        assert_eq!(repo.items(&a).unwrap(), vec![stay]);
        let mut expected = item.clone();
        expected.vault_id = b.id;
        assert_eq!(repo.items(&b).unwrap(), vec![expected]);
        assert_eq!(repo.store.list(RecordKind::Item).unwrap().len(), 2);
        assert_eq!(repo.move_item(item.id, &a, &b), Err(Error::NotFound));
    }
}
