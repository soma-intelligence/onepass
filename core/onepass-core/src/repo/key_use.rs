//! The key-use log of an item (`crate::model::key_use`): record a use,
//! the device-local queue (`crate::key_use_queue`), its flush, clear, and
//! the earliest use on record.
//!
//! A use is written into the item at most once an hour per entry, with
//! the item's `updated_at` unchanged (as `record_usage`), so it never
//! beats a real edit from another device. A use inside the hour, or one a
//! read-only session cannot write (`Error::ReadOnly`), goes to the queue,
//! which the next write of the item or a flush folds in. Every queue call
//! is a no-op on a store that keeps no queue.

use std::collections::BTreeMap;

use time::{Duration, OffsetDateTime};

use super::{Repository, Use};
use crate::devices::DeviceEntry;
use crate::id::Id;
use crate::key_use_queue::{MAX_QUEUE_ROWS, QueueKeys, QueuedKeyUse};
use crate::model::Item;
use crate::model::key_use::{KeyUseAction, KeyUseChannel, KeyUseInput, KeyUseTrailer};
use crate::model::usage::REWRITE_AFTER_SECS;
use crate::store::RecordStore;
use crate::vault::Vault;
use crate::{Error, Result};

/// A queued row with its store `seq`.
type Queued = (i64, QueuedKeyUse);

impl<S: RecordStore> Repository<S> {
    fn key_use_queue_keys(&self) -> Result<QueueKeys> {
        let ikm = self.account.keyset().kem.to_bytes();
        QueueKeys::derive(&ikm, self.account_id())
    }

    /// A use by this device: its id in the device list (the nil id while
    /// unregistered) and its name there (empty when unknown, or when the
    /// list cannot be read). Never fails: recording is best effort.
    pub fn this_device_key_use(
        &self,
        channel: KeyUseChannel,
        action: KeyUseAction,
        client: &str,
        field: &str,
    ) -> KeyUseInput {
        let device_id = self.this_device_id();
        let device_name = device_id
            .and_then(|id| {
                self.read_list::<DeviceEntry>()
                    .ok()
                    .flatten()?
                    .body
                    .entries
                    .into_iter()
                    .find(|e| e.device_id == id)
                    .map(|e| e.name)
            })
            .unwrap_or_default();
        KeyUseInput {
            channel,
            action,
            device_id: device_id.unwrap_or(Id([0; 16])),
            device_name,
            client: client.into(),
            field: field.into(),
        }
    }

    /// Record one use `u` of the item at `now`. The item is written (with
    /// its `updated_at` unchanged, its queued rows folded in) when its
    /// entry for `u` is due (`KeyUseTrailer::due`: none yet, or the last
    /// write an hour ago or more), or when an entry carries a time after
    /// `now` (a skewed or hostile synced entry is clamped at once, so it
    /// neither skews the TTL nor blocks the coalescing). Otherwise the use
    /// goes to the device's queue, as it does when the write is refused
    /// for now (`write_refused_for_now`: a read-only session, or a shared
    /// vault where this account only reads). Archived and trashed items are recorded; the
    /// account profile is `NotFound`. Returns `true` when the item was
    /// written. Callers record after the secret was handed out and ignore
    /// the error: a failure to record never fails the use.
    pub fn record_key_use(
        &mut self,
        vault: &Vault,
        item_id: Id,
        u: KeyUseInput,
        now: OffsetDateTime,
    ) -> Result<bool> {
        match self.write_key_use(vault, item_id, &u, now) {
            Ok(true) => Ok(true),
            Ok(false) => {
                self.queue_key_use(vault.id, item_id, &u, now)?;
                Ok(false)
            }
            Err(e) if write_refused_for_now(&e) => {
                self.queue_key_use(vault.id, item_id, &u, now)?;
                Ok(false)
            }
            Err(e) => Err(e),
        }
    }

    /// The write path of `record_key_use`: `false` when the use is not due.
    fn write_key_use(
        &mut self,
        vault: &Vault,
        item_id: Id,
        u: &KeyUseInput,
        now: OffsetDateTime,
    ) -> Result<bool> {
        let mut item = self.item_for_key_use(vault, item_id)?;
        let t = item.key_use_trailer();
        let future = t
            .entries
            .iter()
            .any(|e| e.first_at > now || e.last_at > now);
        if !t.due(u, now) && !future {
            return Ok(false);
        }
        let seqs = self.apply_key_use(vault, &mut item, u.clone(), now)?;
        self.save_item(vault, item)?;
        // The item is saved: a failure to drop the rows folded in does not
        // fail the use (core has no logger; the caller's debug log is the
        // place). Those rows stay queued and are folded again at the next
        // write or flush, so their batch may be counted twice.
        let _ = self.drop_queued_key_uses(&seqs);
        Ok(true)
    }

    /// Apply the use `u` to `item` in memory, not saved: fold in the item's
    /// queued rows, clamp the entries after `now`, note `u`, apply the TTL
    /// and the cap. Returns the `seq`s of the rows folded in, for
    /// `drop_queued_key_uses` once the item is saved (a failed save keeps
    /// them queued). For a caller that saves the item anyway
    /// (`record_usage`, `record_app_use`), so one save carries both.
    pub(crate) fn apply_key_use(
        &mut self,
        vault: &Vault,
        item: &mut Item,
        u: KeyUseInput,
        now: OffsetDateTime,
    ) -> Result<Vec<i64>> {
        let rows = self.queued_key_uses_of(vault.id, item.id)?;
        let mut t = item.key_use_trailer();
        for (_, q) in &rows {
            fold(&mut t, q, now);
        }
        t.note(&u, 1, now, now);
        item.set_key_use_trailer(t);
        Ok(rows.into_iter().map(|(seq, _)| seq).collect())
    }

    /// Remove the queued rows `seqs` (folded into a saved item).
    pub(crate) fn drop_queued_key_uses(&mut self, seqs: &[i64]) -> Result<()> {
        if seqs.is_empty() || !self.store.keeps_key_use_queue() {
            return Ok(());
        }
        self.store.key_use_queue_delete(seqs)
    }

    /// Fold the queued rows whose last use is an hour old or more into
    /// their items, item by item, each saved with its `updated_at`
    /// unchanged. Rows of an item or a vault that is gone, and rows that
    /// no longer open, are dropped; rows sealed before a key rotation are
    /// sealed again under the current keys first (`rekey_key_use_queue`).
    /// An item this account may not write for now (a shared vault where it
    /// only reads, `write_refused_for_now`) keeps its rows, without error:
    /// a later role change flushes them, and the cap bounds them. Any other
    /// item that cannot be written (a read-only session, an alert) keeps
    /// its rows and does not stop the others; the first such error is
    /// returned once all were tried.
    /// Returns how many rows were applied. Run at the start of a write
    /// session and at each app foreground.
    pub fn flush_key_use_queue(&mut self, now: OffsetDateTime) -> Result<usize> {
        if !self.store.keeps_key_use_queue() {
            return Ok(0);
        }
        self.rekey_key_use_queue()?;
        let keys = self.key_use_queue_keys()?;
        let ripe_before = now - Duration::seconds(REWRITE_AFTER_SECS);
        let mut dead = Vec::new();
        let mut ripe: BTreeMap<(Id, Id), Vec<Queued>> = BTreeMap::new();
        for (seq, tag, data) in self.store.key_use_queue_rows(None)? {
            match keys.open_row(&tag, &data) {
                Ok(q) if q.entry.last_at <= ripe_before => ripe
                    .entry((q.vault_id, q.item_id))
                    .or_default()
                    .push((seq, q)),
                Ok(_) => {}
                Err(_) => dead.push(seq),
            }
        }
        self.drop_queued_key_uses(&dead)?;
        let vaults = self.vaults()?;
        let mut applied = 0;
        let mut first_err = None;
        for ((vault_id, item_id), rows) in ripe {
            let seqs: Vec<i64> = rows.iter().map(|(seq, _)| *seq).collect();
            let result = match vaults.iter().find(|v| v.id == vault_id) {
                None => Err(Error::NotFound),
                Some(vault) => self.flush_item(vault, item_id, &rows, now),
            };
            match result {
                Ok(()) => {
                    applied += seqs.len();
                    self.drop_queued_key_uses(&seqs)?;
                }
                Err(Error::NotFound) => self.drop_queued_key_uses(&seqs)?,
                Err(Error::ReadOnly) => {
                    first_err.get_or_insert(Error::ReadOnly);
                }
                Err(e) if write_refused_for_now(&e) => {}
                Err(e) => {
                    first_err.get_or_insert(e);
                }
            }
        }
        match first_err {
            Some(e) => Err(e),
            None => Ok(applied),
        }
    }

    fn flush_item(
        &mut self,
        vault: &Vault,
        item_id: Id,
        rows: &[Queued],
        now: OffsetDateTime,
    ) -> Result<()> {
        let mut item = self.item_for_key_use(vault, item_id)?;
        let mut t = item.key_use_trailer();
        for (_, q) in rows {
            fold(&mut t, q, now);
        }
        item.set_key_use_trailer(t);
        self.save_item(vault, item)
    }

    /// Seal again under the current keys every queued row that opens only
    /// under a key the account retired (`Keyset::retired_kem`): the queue
    /// keys derive from the KEM secret, so a key rotation (this device's,
    /// or one it followed) would otherwise leave the rows of a read-only
    /// session (`Error::ReadOnly` until the rotation is answered) unread
    /// and dropped. Each row moves under its item's current tag. Rows that
    /// open under no key are left for the caller to drop.
    fn rekey_key_use_queue(&mut self) -> Result<()> {
        let retired = &self.account.keyset().retired_kem;
        if retired.is_empty() {
            return Ok(());
        }
        let account_id = self.account_id();
        let old: Vec<QueueKeys> = retired
            .iter()
            .map(|k| QueueKeys::derive(&k.to_bytes(), account_id))
            .collect::<Result<_>>()?;
        let keys = self.key_use_queue_keys()?;
        for (seq, tag, data) in self.store.key_use_queue_rows(None)? {
            if keys.open_row(&tag, &data).is_ok() {
                continue;
            }
            let Some(row) = old.iter().find_map(|k| k.open_row(&tag, &data).ok()) else {
                continue;
            };
            let new_tag = keys.item_tag(row.item_id);
            let blob = keys.seal_row(&new_tag, &row)?;
            self.store
                .key_use_queue_put(&new_tag, &[seq], &blob, MAX_QUEUE_ROWS)?;
        }
        Ok(())
    }

    /// Erase this device's whole queue (Travel Mode): how many rows went.
    pub fn clear_key_use_queue(&mut self) -> Result<usize> {
        if !self.store.keeps_key_use_queue() {
            return Ok(0);
        }
        self.store.key_use_queue_clear()
    }

    /// Empty the item's key-use log and set its `cleared_at` to `now`, so
    /// an older entry another device still holds does not come back
    /// (merge drops entries at or before it). Saved with `updated_at`
    /// unchanged; syncs like any item write. This device's queued rows of
    /// the item go too.
    pub fn clear_key_uses(
        &mut self,
        vault: &Vault,
        item_id: Id,
        now: OffsetDateTime,
    ) -> Result<()> {
        let mut item = self.item_for_key_use(vault, item_id)?;
        let mut t = item.key_use_trailer();
        t.clear(now);
        item.set_key_use_trailer(t);
        self.save_item(vault, item)?;
        let seqs: Vec<i64> = self
            .queued_key_uses_of(vault.id, item_id)?
            .into_iter()
            .map(|(seq, _)| seq)
            .collect();
        self.drop_queued_key_uses(&seqs)
    }

    /// The earliest use on record: the smallest `first_at` over the key-use
    /// logs of the live items (neither archived nor trashed) of every
    /// vault, `None` when there is none. Derived from the synced logs, so
    /// every device agrees on it once synced; Watchtower reads it as the
    /// start of the warm-up before calling a key unused.
    pub fn key_use_since(&mut self) -> Result<Option<OffsetDateTime>> {
        let mut since: Option<OffsetDateTime> = None;
        for vault in self.vaults()? {
            for item in self.items(&vault)? {
                if item.archived || item.trashed_at.is_some() {
                    continue;
                }
                for e in item.key_use_trailer().entries {
                    since = Some(since.map_or(e.first_at, |s| s.min(e.first_at)));
                }
            }
        }
        Ok(since)
    }

    /// The item for a key-use write: served for writing (a read-only
    /// session is `Error::ReadOnly`), never the account profile.
    fn item_for_key_use(&mut self, vault: &Vault, item_id: Id) -> Result<Item> {
        self.sync_epoch()?;
        let loaded = self.served(vault, Use::Write)?;
        let (_, rec) = loaded.listed(item_id).ok_or(Error::NotFound)?;
        let item = vault.open_item(rec)?;
        if item.is_profile() {
            return Err(Error::NotFound);
        }
        Ok(item)
    }

    /// The queued rows of the item in `vault_id`. Rows under its tag that
    /// no longer open are deleted on the way.
    fn queued_key_uses_of(&mut self, vault_id: Id, item_id: Id) -> Result<Vec<Queued>> {
        if !self.store.keeps_key_use_queue() {
            return Ok(Vec::new());
        }
        let keys = self.key_use_queue_keys()?;
        let tag = keys.item_tag(item_id);
        let mut out = Vec::new();
        let mut dead = Vec::new();
        for (seq, t, data) in self.store.key_use_queue_rows(Some(&tag))? {
            match keys.open_row(&t, &data) {
                Ok(q) if q.vault_id == vault_id => out.push((seq, q)),
                Ok(_) => {}
                Err(_) => dead.push(seq),
            }
        }
        self.drop_queued_key_uses(&dead)?;
        Ok(out)
    }

    /// Queue the use `u` of the item at `now`: coalesced into the item's
    /// row of the same key, or a new row; the oldest rows past
    /// `MAX_QUEUE_ROWS` are dropped. Rows of the item that no longer open
    /// go in the same write.
    fn queue_key_use(
        &mut self,
        vault_id: Id,
        item_id: Id,
        u: &KeyUseInput,
        now: OffsetDateTime,
    ) -> Result<()> {
        if !self.store.keeps_key_use_queue() {
            return Ok(());
        }
        let keys = self.key_use_queue_keys()?;
        let tag = keys.item_tag(item_id);
        let mut replace = Vec::new();
        let mut row = None;
        for (seq, t, data) in self.store.key_use_queue_rows(Some(&tag))? {
            match keys.open_row(&t, &data) {
                Ok(q) if q.vault_id == vault_id && q.same_key(u) && row.is_none() => {
                    replace.push(seq);
                    row = Some(q);
                }
                Ok(_) => {}
                Err(_) => replace.push(seq),
            }
        }
        let row = match row {
            Some(mut q) => {
                q.bump(u, now);
                q
            }
            None => QueuedKeyUse::new(vault_id, item_id, u, now),
        };
        let blob = keys.seal_row(&tag, &row)?;
        self.store
            .key_use_queue_put(&tag, &replace, &blob, MAX_QUEUE_ROWS)
    }
}

/// A key-use write refused for now that may be allowed later: a read-only
/// session (`Error::ReadOnly`, until the rotation is answered), or a
/// shared vault where this account's role only reads
/// (`Validation("role", "read only")`; a manager may raise it with
/// `set_role`). The use is queued rather than lost.
fn write_refused_for_now(e: &Error) -> bool {
    match e {
        Error::ReadOnly => true,
        Error::Validation(v) => v.field == "role" && v.reason == "read only",
        _ => false,
    }
}

/// Fold a queued row into a log: its count at its last use, then its first
/// use with no count, so the entry spans both. Each `note` clamps to `now`
/// and prunes; a row already past the TTL or the log's `cleared_at` goes.
fn fold(t: &mut KeyUseTrailer, q: &QueuedKeyUse, now: OffsetDateTime) {
    let u = q.input();
    t.note(&u, q.entry.count, q.entry.last_at, now);
    t.note(&u, 0, q.entry.first_at, now);
}

#[cfg(test)]
mod tests {
    use std::sync::OnceLock;

    use time::macros::datetime;

    use super::*;
    use crate::account::{Account, NewAccount};
    use crate::crypto::{KdfParams, random_array};
    use crate::model::{FieldValue, ItemType, new_item};
    use crate::repo::{DeviceState, LineageLock};
    use crate::store::{MemoryStore, Record, RecordKind};
    use crate::vault::VaultMeta;

    const T: OffsetDateTime = datetime!(2026-11-14 12:00 UTC);

    fn shared() -> &'static NewAccount {
        static N: OnceLock<NewAccount> = OnceLock::new();
        N.get_or_init(|| {
            let kdf = KdfParams {
                m_kib: 8192,
                t: 1,
                p: 1,
                salt: random_array().unwrap(),
            };
            Account::create_with_params("pw", kdf).unwrap()
        })
    }

    fn fresh() -> (Repository<MemoryStore>, Vault) {
        let n = shared();
        let id = n.account.params.account_id;
        let mut store = MemoryStore::default();
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
        let v = repo
            .create_vault(VaultMeta {
                name: "A".into(),
                icon: "key".into(),
                color: "blue".into(),
                travel_safe: false,
                mcp_access: false,
            })
            .unwrap();
        (repo, v)
    }

    fn with_item() -> (Repository<MemoryStore>, Vault, Item) {
        let (mut repo, v) = fresh();
        let mut item = new_item(ItemType::Login, v.id, "Example");
        item.field_mut("username").unwrap().value = FieldValue::Text("me".into());
        repo.save_item(&v, item.clone()).unwrap();
        (repo, v, item)
    }

    fn stored(repo: &mut Repository<MemoryStore>, v: &Vault, id: Id) -> Item {
        repo.items(v)
            .unwrap()
            .into_iter()
            .find(|i| i.id == id)
            .unwrap()
    }

    fn input(repo: &Repository<MemoryStore>, field: &str) -> KeyUseInput {
        repo.this_device_key_use(
            KeyUseChannel::Mcp,
            KeyUseAction::Revealed,
            "Claude Code",
            field,
        )
    }

    fn queue_len(repo: &Repository<MemoryStore>) -> usize {
        repo.store.key_use_queue_rows(None).unwrap().len()
    }

    fn mins(n: i64) -> Duration {
        Duration::minutes(n)
    }

    fn read_only(repo: &mut Repository<MemoryStore>, on: bool) {
        repo.lineage_lock = on.then_some(LineageLock::Orphaned { child: [0; 32] });
    }

    #[test]
    fn this_device_key_use_without_a_registered_device() {
        let (repo, _) = fresh();
        let u = input(&repo, "password");
        assert_eq!(u.device_id, Id([0; 16]));
        assert_eq!(u.device_name, "");
        assert_eq!(u.client, "Claude Code");
        assert_eq!(u.field, "password");
    }

    #[test]
    fn first_use_writes_item_and_keeps_updated_at() {
        let (mut repo, v, item) = with_item();
        let u = input(&repo, "password");
        assert!(repo.record_key_use(&v, item.id, u, T).unwrap());
        let got = stored(&mut repo, &v, item.id);
        assert_eq!(got.updated_at, item.updated_at);
        let t = got.key_use_trailer();
        assert_eq!(t.entries.len(), 1);
        assert_eq!(t.entries[0].count, 1);
        assert_eq!(t.entries[0].last_at, T);
        assert_eq!(queue_len(&repo), 0);
    }

    #[test]
    fn second_use_within_hour_goes_to_queue() {
        let (mut repo, v, item) = with_item();
        let u = input(&repo, "password");
        assert!(repo.record_key_use(&v, item.id, u.clone(), T).unwrap());
        let before = stored(&mut repo, &v, item.id);
        assert!(!repo.record_key_use(&v, item.id, u, T + mins(10)).unwrap());
        let after = stored(&mut repo, &v, item.id);
        assert_eq!(after, before);
        let rows = repo.store.key_use_queue_rows(None).unwrap();
        assert_eq!(rows.len(), 1);
        let keys = repo.key_use_queue_keys().unwrap();
        let row = keys.open_row(&rows[0].1, &rows[0].2).unwrap();
        assert_eq!(row.entry.count, 1);
        assert_eq!(row.item_id, item.id);
    }

    #[test]
    fn use_after_hour_merges_queue_and_writes() {
        let (mut repo, v, item) = with_item();
        let u = input(&repo, "password");
        assert!(repo.record_key_use(&v, item.id, u.clone(), T).unwrap());
        assert!(
            !repo
                .record_key_use(&v, item.id, u.clone(), T + mins(10))
                .unwrap()
        );
        assert!(repo.record_key_use(&v, item.id, u, T + mins(61)).unwrap());
        let t = stored(&mut repo, &v, item.id).key_use_trailer();
        assert_eq!(t.entries.len(), 1);
        assert_eq!(t.entries[0].count, 3);
        assert_eq!(t.entries[0].first_at, T);
        assert_eq!(t.entries[0].last_at, T + mins(61));
        assert_eq!(queue_len(&repo), 0);
    }

    #[test]
    fn read_only_session_queues() {
        let (mut repo, v, item) = with_item();
        let u = input(&repo, "password");
        read_only(&mut repo, true);
        assert!(!repo.record_key_use(&v, item.id, u, T).unwrap());
        assert_eq!(queue_len(&repo), 1);
        read_only(&mut repo, false);
        assert!(
            stored(&mut repo, &v, item.id)
                .key_use_trailer()
                .entries
                .is_empty()
        );
        assert_eq!(repo.flush_key_use_queue(T + mins(120)).unwrap(), 1);
        assert_eq!(queue_len(&repo), 0);
        let got = stored(&mut repo, &v, item.id);
        assert_eq!(got.updated_at, item.updated_at);
        let t = got.key_use_trailer();
        assert_eq!(t.entries.len(), 1);
        assert_eq!(t.entries[0].count, 1);
        assert_eq!(t.entries[0].last_at, T);
    }

    #[test]
    fn flush_skips_rows_younger_than_an_hour() {
        let (mut repo, v, item) = with_item();
        let u = input(&repo, "password");
        read_only(&mut repo, true);
        repo.record_key_use(&v, item.id, u, T).unwrap();
        read_only(&mut repo, false);
        assert_eq!(repo.flush_key_use_queue(T + mins(59)).unwrap(), 0);
        assert_eq!(queue_len(&repo), 1);
        assert!(
            stored(&mut repo, &v, item.id)
                .key_use_trailer()
                .entries
                .is_empty()
        );
        assert_eq!(repo.flush_key_use_queue(T + mins(60)).unwrap(), 1);
        assert_eq!(queue_len(&repo), 0);
    }

    #[test]
    fn flush_drops_rows_of_missing_items() {
        let (mut repo, v, item) = with_item();
        let u = input(&repo, "password");
        repo.record_key_use(&v, item.id, u.clone(), T).unwrap();
        repo.record_key_use(&v, item.id, u.clone(), T + mins(5))
            .unwrap();
        // A row of an item that never was.
        read_only(&mut repo, true);
        repo.record_key_use(&v, Id::new(), u, T).unwrap();
        read_only(&mut repo, false);
        assert_eq!(queue_len(&repo), 2);
        repo.delete_item(&v, item.id).unwrap();
        assert_eq!(repo.flush_key_use_queue(T + mins(120)).unwrap(), 0);
        assert_eq!(queue_len(&repo), 0);
    }

    #[test]
    fn queue_caps_at_1000() {
        let (mut repo, v, _) = with_item();
        let u = input(&repo, "password");
        read_only(&mut repo, true);
        let ids: Vec<Id> = (0..=MAX_QUEUE_ROWS).map(|_| Id::new()).collect();
        for id in &ids {
            repo.record_key_use(&v, *id, u.clone(), T).unwrap();
        }
        assert_eq!(queue_len(&repo), MAX_QUEUE_ROWS);
        let keys = repo.key_use_queue_keys().unwrap();
        let first = keys.item_tag(ids[0]);
        assert!(
            repo.store
                .key_use_queue_rows(Some(&first))
                .unwrap()
                .is_empty()
        );
        let last = keys.item_tag(ids[MAX_QUEUE_ROWS]);
        assert_eq!(repo.store.key_use_queue_rows(Some(&last)).unwrap().len(), 1);
    }

    #[test]
    fn travel_mode_erases_queue() {
        let (mut repo, v, item) = with_item();
        let u = input(&repo, "password");
        read_only(&mut repo, true);
        repo.record_key_use(&v, item.id, u, T).unwrap();
        read_only(&mut repo, false);
        assert_eq!(queue_len(&repo), 1);
        let upstream = repo.store.clone();
        repo.enter_travel(&upstream).unwrap();
        assert_eq!(queue_len(&repo), 0);
    }

    #[test]
    fn clear_sets_tombstone() {
        let (mut repo, v, item) = with_item();
        let u = input(&repo, "password");
        repo.record_key_use(&v, item.id, u.clone(), T).unwrap();
        repo.record_key_use(&v, item.id, u, T + mins(5)).unwrap();
        assert_eq!(queue_len(&repo), 1);
        repo.clear_key_uses(&v, item.id, T + mins(10)).unwrap();
        let got = stored(&mut repo, &v, item.id);
        assert_eq!(got.updated_at, item.updated_at);
        let t = got.key_use_trailer();
        assert!(t.entries.is_empty());
        assert_eq!(t.cleared_at, Some(T + mins(10)));
        assert_eq!(queue_len(&repo), 0);
    }

    #[test]
    fn key_use_since_is_earliest_first_at() {
        let (mut repo, v, item) = with_item();
        assert_eq!(repo.key_use_since().unwrap(), None);
        let mut other = new_item(ItemType::Login, v.id, "Other");
        other.field_mut("username").unwrap().value = FieldValue::Text("you".into());
        repo.save_item(&v, other.clone()).unwrap();
        let u = input(&repo, "password");
        repo.record_key_use(&v, item.id, u.clone(), T + mins(30))
            .unwrap();
        assert_eq!(repo.key_use_since().unwrap(), Some(T + mins(30)));
        repo.record_key_use(&v, other.id, u.clone(), T).unwrap();
        assert_eq!(repo.key_use_since().unwrap(), Some(T));
        repo.record_key_use(&v, other.id, u, T + mins(120)).unwrap();
        assert_eq!(repo.key_use_since().unwrap(), Some(T));
        // A trashed item no longer counts.
        repo.trash_item(&v, other.id).unwrap();
        assert_eq!(repo.key_use_since().unwrap(), Some(T + mins(30)));
    }

    #[test]
    fn archived_and_trashed_items_are_recorded() {
        let (mut repo, v, item) = with_item();
        repo.trash_item(&v, item.id).unwrap();
        let u = input(&repo, "password");
        assert!(repo.record_key_use(&v, item.id, u, T).unwrap());
        assert_eq!(
            stored(&mut repo, &v, item.id)
                .key_use_trailer()
                .entries
                .len(),
            1
        );
    }

    #[test]
    fn unopenable_queue_row_is_dropped() {
        let (mut repo, v, item) = with_item();
        let u = input(&repo, "password");
        let tag = repo.key_use_queue_keys().unwrap().item_tag(item.id);
        repo.store
            .key_use_queue_put(&tag, &[], b"not a sealed row", MAX_QUEUE_ROWS)
            .unwrap();
        assert!(repo.record_key_use(&v, item.id, u, T).unwrap());
        assert_eq!(queue_len(&repo), 0);
        let other = Id::new();
        let tag = repo.key_use_queue_keys().unwrap().item_tag(other);
        repo.store
            .key_use_queue_put(&tag, &[], b"garbage", MAX_QUEUE_ROWS)
            .unwrap();
        assert_eq!(repo.flush_key_use_queue(T + mins(120)).unwrap(), 0);
        assert_eq!(queue_len(&repo), 0);
    }

    #[test]
    fn future_entry_is_clamped_and_written() {
        let (mut repo, v, mut item) = with_item();
        let u = input(&repo, "password");
        let mut t = KeyUseTrailer::default();
        let future = T + Duration::days(10);
        t.note(&u, 4, future, future);
        item.set_key_use_trailer(t);
        repo.save_item(&v, item.clone()).unwrap();
        assert!(repo.record_key_use(&v, item.id, u, T).unwrap());
        let t = stored(&mut repo, &v, item.id).key_use_trailer();
        assert!(t.entries.iter().all(|e| e.first_at <= T && e.last_at <= T));
        assert_eq!(t.entries[0].count, 5);
    }
}
