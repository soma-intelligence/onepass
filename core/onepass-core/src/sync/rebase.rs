//! Rebase of local vault writes onto a server manifest that moved on.
//!
//! A vault is held (`SyncStore::vaults_needing_rebase`) when its pending
//! manifest was built on a `base` manifest (its ancestor) that the server
//! has since replaced. The local manifest cannot be pushed: it does not
//! chain to the server's. The rebase turns the local manifest back into
//! intents (items changed, items deleted) by comparing it with the
//! ancestor, drops the vault's pending rows, checks that the server
//! manifest chains to the ancestor, then replays each intent with
//! `save_item` or `delete_item` on top of the server state.
//!
//! Merge rule for an item changed on both sides: the newest `updated_at`
//! wins, a tie goes to the larger record hash (bytes), the same answer on
//! every device. An item the server left as it was in the ancestor keeps
//! the local change whatever the clocks say. A local deletion applies only
//! if the server still has the very record the ancestor listed; otherwise
//! the server's change is kept. A local edit of an item the server deleted
//! brings it back (a deletion carries no date).
//!
//! No ancestor row: the pending manifest was written before the vault had
//! any `base` manifest (a vault created here whose push was never
//! confirmed). The ancestor is then empty: every local entry is an intent,
//! nothing is deleted, and the server manifest is accepted without history
//! for that vault (its signature and vault key are still checked). If the
//! server manifest is exactly the local one, it is simply adopted.
//!
//! The signed lists (device list, vault list) are rebased the same way
//! (`SyncStore::lists_needing_rebase`): the server list must chain to the
//! ancestor the local list was built on, then the local list is rebuilt as
//! the union of both (`lists::rebase_entries`), signed at the server's seq
//! plus one and chained to it. When the server list already holds every
//! local change, it is simply accepted and nothing is written.
//!
//! One vault's rebase is one SQLite transaction (`SyncStore::begin_batch`):
//! dropping the pending rows, the replay and the device state with the new
//! last seen manifest commit together. A failure or a crash leaves the
//! previous pending writes with their last seen manifest, and the vault
//! stays held.
//!
//! Restore epoch: a local epoch not pushed yet is dropped when it lost the
//! race to another device's (`SyncStore::epoch_held`) or when any vault is
//! held (its head, a pending manifest, is about to be rebased away and
//! would never reach the server). The device then goes back to the epoch it
//! had before issuing it, and the rebase reports `Error::Conflict` (first,
//! before any vault error): the caller syncs and issues it again once the
//! vaults converged. Only then is the stored epoch checked and applied
//! (`Repository::sync_epoch`), so a winner's epoch with the same number is
//! adopted with its heads. When the stored epoch has a head for a vault
//! newer than its ancestor, the server manifest must chain to that head
//! instead: a manifest from before the epoch is refused.
//!
//! Server behind or incomplete: a `base` manifest older than the ancestor
//! does not hold the vault (the push restores the server's copy, see
//! `SyncStore`). A rebase that fails because the server's newer state is
//! not complete yet (a record missing or unexpected) is not an error: the
//! vault stays held, the device serves its own copy and the vault is
//! `ServerBehind` until a later round brings the rest. A server manifest
//! that does not chain to the ancestor is a fork the rebase cannot merge:
//! an alert (`ManifestRollback`) right away.
//!
//! Serialization premise: each vault's plan is read before its batch opens.
//! Only the session writes pending rows, with one exception: the settlement
//! of a zone reset (`SyncStore::finish_full_fetch` in reset mode) requeues
//! rows through the sync connection. A rebase and that settlement must not
//! interleave; the apps guarantee it by running the rebase inside the sync
//! round that owns the fetch (one round at a time).

use std::collections::BTreeMap;

use crate::chain::Seen;
use crate::devices::DeviceEntry;
use crate::epoch::{EpochReason, RestoreEpoch};
use crate::lists::{AccountList, Stored, open_record, rebase_entries};
use crate::manifest::{
    Manifest, ManifestEntry, SignedManifest, manifest_hash, record_hash, verify_manifest,
};
use crate::model::Item;
use crate::repo::{Repository, Use, seen, split_item_record};
use crate::store::{Record, RecordKind, RecordStore, VaultEvent};
use crate::sync::SyncStore;
use crate::vault::{ItemRecord, Vault};
use crate::vaultlist::VaultListEntry;
use crate::{Error, Id, IntegrityError, Result};

/// A local item write to replay: the item and the hash of its local record.
struct Changed {
    item: Item,
    hash: [u8; 32],
}

/// A held vault's intents, worked out before anything is written.
struct Plan {
    /// The local pending manifest, as stored and decoded.
    local: Record,
    local_manifest: Manifest,
    /// `None`: no ancestor row, an empty ancestor without history.
    ancestor: Option<Manifest>,
    changed: Vec<Changed>,
    /// Ancestor entries the local manifest no longer lists.
    deleted: Vec<ManifestEntry>,
}

impl Plan {
    fn ancestor_entries(&self) -> &[ManifestEntry] {
        self.ancestor.as_ref().map_or(&[], |a| &a.entries)
    }
}

/// What `Repository::rebase_report` did: the vaults rebased (their content
/// changed, the app refreshes them), and the error to report, if any (the
/// one `rebase` returns).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RebaseReport {
    pub rebased: Vec<Id>,
    pub error: Option<Error>,
}

impl Repository<SyncStore> {
    /// The safe exit "keep this device" (`KeepThisDevice`, after an
    /// alert): an epoch whose heads are the copies this device serves,
    /// pushed over the server's where the server is behind or forked.
    ///
    /// 1. The held vaults are rebased first (`rebase_report`): a vault
    ///    whose rebase succeeds merges the other devices' writes as usual.
    /// 2. The epoch is issued like `issue_restore_epoch`, each head being
    ///    the copy this device serves (`served` with `Use::Keep`: its
    ///    verified copy, even over a fork), re-signed at the epoch floor.
    /// 3. Only the vaults in alert (a fork, or behind past the
    ///    thresholds) or whose server state went back (older than the copy,
    ///    or gone) get their pending manifest rebuilt on the current server
    ///    row (`SyncStore::keep_targets`, `rebuild_ancestors_on_base`):
    ///    their push overwrites the server's copy. Their health restarts
    ///    (behind, not counted) until the server serves the copies back.
    ///    Every other vault keeps its ancestor. One whose server state is
    ///    newer but incomplete (another device's write, part of it not
    ///    fetched yet) stays held on its copy, nothing of it is sent, and
    ///    the rebase merges onto the server's state once complete. One
    ///    another device wrote meanwhile conflicts at the push. Either way
    ///    the epoch cannot ship while a vault is held: the rebase drops it
    ///    (`Error::Conflict`) and the caller syncs and calls this again.
    ///    Another device's committed write is never overwritten silently.
    ///
    /// `reason` must be `KeepThisDevice` (`InvalidFormat("restore epoch
    /// reason")` otherwise; `TakeServer` is
    /// `issue_restore_epoch_take_server`). Still refused: a stored epoch
    /// that fails the rules, and a vault without a verified copy.
    pub fn issue_restore_epoch_from_local(&mut self, reason: EpochReason) -> Result<RestoreEpoch> {
        if reason != EpochReason::KeepThisDevice {
            return Err(Error::InvalidFormat("restore epoch reason"));
        }
        match self.rebase_report()?.error {
            None | Some(Error::Integrity(_) | Error::Conflict) => {}
            Some(e) => return Err(e),
        }
        let troubled = self.store.keep_targets()?;
        let stored = self.sync_epoch()?.map(|e| e.epoch);
        let vaults = self.vaults()?;
        let issued = self.issue_epoch(reason, stored, vaults, true)?;
        self.store.rebuild_ancestors_on_base(&troubled)?;
        let heads: BTreeMap<Id, u64> = troubled
            .iter()
            .filter_map(|v| issued.heads.get(v).map(|h| (*v, h.seq)))
            .collect();
        self.store.restart_health(&heads)?;
        self.persist_device_state()?;
        Ok(issued)
    }

    /// The safe exit "take the server's version" (`TakeServer`, after an
    /// alert): every local write of vault rows not pushed yet is dropped,
    /// with the copies kept for the vaults the server is behind on and the
    /// sync health; the server's current state becomes this device's, each
    /// vault checked like a first use (signature, vault key, records), and
    /// an epoch is issued with those manifests re-signed at its floor as
    /// heads, so every device accepts them.
    ///
    /// Destructive: the changes this device made and did not push are
    /// lost. The caller exports them first (an encrypted archive) and asks
    /// for the master password. The stored epoch's signature is checked,
    /// not its number (the owner takes the server as it is); the new epoch
    /// is above both the stored one and this device's.
    ///
    /// All or nothing: one store transaction. A vault whose server state
    /// fails its checks (nothing safe to take) fails the call before
    /// anything is discarded: the local writes and the device state stay.
    pub fn issue_restore_epoch_take_server(&mut self) -> Result<RestoreEpoch> {
        let device = self.device.clone();
        let chain = self.chain.clone();
        self.store.begin_batch()?;
        let result = self.take_server().and_then(|issued| {
            self.store.commit_batch()?;
            Ok(issued)
        });
        if result.is_err() {
            self.device = device;
            self.chain = chain;
            self.lists_forced = false;
            // The original error wins; SQLite undoes an open transaction
            // when the connection closes anyway.
            let _ = self.store.rollback_batch();
        }
        result
    }

    fn take_server(&mut self) -> Result<RestoreEpoch> {
        self.store.discard_local_changes()?;
        self.replace_last_seen(BTreeMap::new());
        // The pending lists went with the other local writes: the server's
        // lists are taken like a first use, as the vaults are.
        self.take_server_lists()?;
        let stored = self.stored_epoch_number()?;
        let vaults = self.open_vaults()?;
        let issued = self.issue_epoch(EpochReason::TakeServer, stored, vaults, false)?;
        self.persist_device_state()?;
        Ok(issued)
    }

    /// Save the device state and the chain state in the store, merged with
    /// what the store already holds: another process on the same file (the
    /// AutoFill extension) may have seen newer manifests or lists, and this
    /// one must not rewind them. Per vault the larger `seq` wins, and the
    /// same `seq` with another hash is refused (`ManifestRollback`, nothing
    /// written). The pin is this process's, its KDF floor raised to the
    /// stored one when both pin the same account. The chain state merges by
    /// `SyncStore::merge_chain` (larger list seq, larger params epoch, a
    /// device id that never changes). The merged states replace
    /// `self.device` and `self.chain`. Read, merge and write run in one
    /// transaction (a savepoint inside a rebase batch). The accepted restore
    /// epoch is the larger of the two, except right after this process
    /// dropped a pending epoch (`epoch_rewound`): then the in-memory one
    /// stands. The vaults the signed vault list marks deleted leave
    /// `last_seen` first, for good (`dropped`).
    pub fn persist_device_state(&mut self) -> Result<()> {
        self.persist_device_state_forcing(&[])
    }

    /// `persist_device_state`, except that the vaults in `force` keep the
    /// in-memory entry whatever is stored (a rebase renumbers them).
    ///
    /// The vaults dropped on purpose since the last persist (`dropped`:
    /// Travel Mode, a restore epoch, a deleted vault) are forced too: the
    /// stored entry must not come back. After a list rebase or a take of
    /// the server's lists (`lists_forced`), the in-memory lists seen stand.
    fn persist_device_state_forcing(&mut self, force: &[Id]) -> Result<()> {
        self.forget_deleted_vaults();
        let mut forced: Vec<Id> = force.to_vec();
        forced.extend(self.dropped.iter().copied());
        let (device, chain) = self.store.merge_device_state(
            &self.device,
            &self.chain,
            &forced,
            self.epoch_rewound,
            self.lists_forced,
        )?;
        self.device = device;
        self.chain = chain;
        self.dropped.clear();
        self.epoch_rewound = false;
        self.lists_forced = false;
        Ok(())
    }

    /// Rebase every held signed list, then drop the pending writes into the
    /// vaults the signed vault list marks deleted (spec 4.5: a write into a
    /// vault deleted elsewhere is abandoned, and logged in
    /// `SyncStore::dropped_vault_writes`), then rebase every held vault (see
    /// the module doc) and return their ids. Each list and each vault is
    /// tried, in one transaction with the device state; a failing one does
    /// not stop the others. The device state is persisted again at the end.
    ///
    /// Errors, the first one met after trying every list and vault (a list
    /// that does not chain to its ancestor is `DeviceListRollback` or
    /// `VaultListRollback`): a local
    /// manifest that does not descend from its ancestor, or a server
    /// manifest that does not chain to the ancestor, is `ManifestRollback`
    /// (an alert, `crate::sync::VaultSyncHealth`); then any error of
    /// `load`, `save_item` or `delete_item`, except a server state not
    /// complete yet while the device serves its own copy (`ServerBehind`,
    /// not an error). A vault in error keeps its pending writes and stays
    /// held; the others stay rebased.
    ///
    /// After the lists and the dropped writes, before any vault: a local
    /// restore epoch that cannot ship (see the module doc) is dropped and the device goes back to the epoch it had
    /// before issuing it; then the stored epoch is checked and applied (its
    /// errors stop the rebase). The dropped epoch is `Error::Conflict`,
    /// returned after every vault was tried, before any vault error.
    ///
    /// The vaults rebased before an error are lost to the caller here: see
    /// `rebase_report`.
    pub fn rebase(&mut self) -> Result<Vec<Id>> {
        let report = self.rebase_report()?;
        match report.error {
            Some(e) => Err(e),
            None => Ok(report.rebased),
        }
    }

    /// `rebase`, reporting the vaults rebased along with the error instead
    /// of either one. `Err` only for what stops the rebase before any vault
    /// (the stored epoch's rules, the store).
    pub fn rebase_report(&mut self) -> Result<RebaseReport> {
        let mut first_error = None;
        for (kind, _) in self.store.lists_needing_rebase()? {
            let result = match kind {
                RecordKind::DeviceList => self.rebase_list::<DeviceEntry>(),
                _ => self.rebase_list::<VaultListEntry>(),
            };
            if let Err(e) = result {
                first_error.get_or_insert(e);
            }
        }
        if let Err(e) = self.drop_deleted_vault_writes() {
            first_error.get_or_insert(e);
        }
        let held = self.store.vaults_needing_rebase()?;
        let pending_epoch = self.store.pending_epoch()?;
        let lost_epoch = pending_epoch.is_some() && (self.store.epoch_held()? || !held.is_empty());
        if let (true, Some(issued)) = (lost_epoch, pending_epoch) {
            self.store.drop_pending_epoch()?;
            // `issue_restore_epoch` takes the epoch accepted plus one, so
            // the one before is what this device had accepted.
            if self.device.epoch == issued {
                self.device.epoch = issued - 1;
                self.epoch_rewound = true;
            }
            self.persist_device_state()?;
        }
        let epoch = self.sync_epoch()?;
        let mut rebased = Vec::new();
        // From here on, an error (the store's included) goes into the
        // report with the vaults already rebased: they changed either way.
        for v in held {
            match self.rebase_vault(v, epoch.as_ref()) {
                Ok(()) => {
                    rebased.push(v);
                    if let Err(e) = self.store.vault_event(v, VaultEvent::CaughtUp) {
                        first_error.get_or_insert(e);
                    }
                }
                Err(e) => match self.rebase_failed(v, e) {
                    Ok(None) => {}
                    Ok(Some(e)) | Err(e) => {
                        first_error.get_or_insert(e);
                    }
                },
            }
        }
        if let Err(e) = self.persist_device_state() {
            first_error.get_or_insert(e);
        }
        let error = if lost_epoch {
            Some(Error::Conflict)
        } else {
            first_error
        };
        Ok(RebaseReport { rebased, error })
    }

    /// Classify a failed vault rebase: the error to report, or `None` when
    /// the server's newer state is only incomplete and the device serves
    /// its own copy meanwhile (`ServerBehind`). A fork (`ManifestRollback`)
    /// is an alert.
    fn rebase_failed(&mut self, v: Id, e: Error) -> Result<Option<Error>> {
        let Error::Integrity(cause) = e else {
            return Ok(Some(e));
        };
        let seq = self.device.last_seen.get(&v).map_or(0, |s| s.seq);
        if cause == IntegrityError::ManifestRollback {
            self.store
                .vault_event(v, VaultEvent::Alert { seq, cause })?;
            return Ok(Some(e));
        }
        let vault = self.open_vault(v)?;
        match self.served(&vault, Use::Read) {
            Ok(loaded) => {
                let seq = loaded.manifest.seq;
                self.store
                    .vault_event(v, VaultEvent::Behind { seq, cause })?;
                Ok(None)
            }
            Err(e) => Ok(Some(e)),
        }
    }

    /// Drop the pending writes into every vault the verified vault list
    /// marks deleted (`SyncStore::drop_pending_vault_writes`, logged there),
    /// and forget those vaults' last manifest seen.
    fn drop_deleted_vault_writes(&mut self) -> Result<()> {
        let Some(list) = self.read_list::<VaultListEntry>()? else {
            return Ok(());
        };
        for e in list.body.entries.iter().filter(|e| e.deleted_at.is_some()) {
            self.store.drop_pending_vault_writes(e.vault_id)?;
            self.forget_vault(e.vault_id);
        }
        Ok(())
    }

    fn rebase_vault(&mut self, v: Id, epoch: Option<&RestoreEpoch>) -> Result<()> {
        let vault = self.open_vault(v)?;
        let plan = self.plan(&vault)?;
        let last_seen = self.device.last_seen.get(&v).cloned();
        let dropped = self.dropped.clone();
        let epoch_rewound = self.epoch_rewound;
        self.store.begin_batch()?;
        let result = self
            .apply(&vault, plan, epoch)
            .and_then(|()| self.persist_device_state_forcing(&[v]))
            .and_then(|()| self.store.commit_batch());
        if let Err(e) = result {
            match last_seen {
                Some(s) => self.device.last_seen.insert(v, s),
                None => self.device.last_seen.remove(&v),
            };
            // The forced merge was rolled back with the batch: the vaults
            // Travel Mode dropped must still be forced by the next persist.
            self.dropped = dropped;
            self.epoch_rewound = epoch_rewound;
            // The original error wins. If the rollback fails too, SQLite
            // undoes the open transaction when the connection closes, and
            // the next batch on it is refused ("batch already open").
            let _ = self.store.rollback_batch();
            return Err(e);
        }
        Ok(())
    }

    /// Rebuild the held local list of this kind over the server's (see the
    /// module doc), in one transaction with the device state. The server
    /// list must chain to the ancestor (`DeviceListRollback`,
    /// `VaultListRollback`). On failure the local list stays pending and
    /// held, and the chain state is as it was.
    fn rebase_list<E: AccountList>(&mut self) -> Result<()> {
        let id = self.account.params.account_id;
        let local = self.store.get(E::KIND, id)?.ok_or(Error::NotFound)?;
        let local: crate::lists::ListBody<E> = open_record(&self.account, &local, None)?;
        let ancestor = match self.store.ancestor_record(E::KIND, id)? {
            Some(rec) => Some(open_record::<E>(&self.account, &rec, None)?),
            None => None,
        };
        let server = self
            .store
            .base_record(E::KIND, id)?
            .ok_or(Error::NotFound)?;
        let after: Option<Seen> = ancestor.as_ref().map(|a| a.seen());
        let server = Stored {
            version: server.version,
            body: open_record::<E>(&self.account, &server, after.as_ref())?,
        };
        let entries = rebase_entries(
            ancestor.as_ref().map(|a| a.entries.as_slice()),
            &local.entries,
            &server.body.entries,
        );
        let previous = self.chain.clone();
        let forced = self.lists_forced;
        self.store.begin_batch()?;
        let result = self
            .store
            .drop_pending_record(E::KIND, id)
            .and_then(|()| {
                if entries == server.body.entries {
                    E::set_seen(&mut self.chain, server.body.seen());
                    Ok(())
                } else {
                    self.write_list(Some(&server), entries)
                }
            })
            .and_then(|()| {
                // The rebase renumbers this list: a pin of the abandoned
                // local list stored earlier (same seq, another hash) must
                // not refuse the merge.
                self.lists_forced = true;
                self.persist_device_state()
            })
            .and_then(|()| self.store.commit_batch());
        if let Err(e) = result {
            self.chain = previous;
            self.lists_forced = forced;
            let _ = self.store.rollback_batch();
            return Err(e);
        }
        Ok(())
    }

    /// The vault from its key and meta records, without reading its
    /// manifest (that is the rebase's job).
    fn open_vault(&self, v: Id) -> Result<Vault> {
        let key = self
            .store
            .get(RecordKind::VaultKey, v)?
            .ok_or(Error::NotFound)?;
        let meta = self
            .store
            .get(RecordKind::VaultMeta, v)?
            .ok_or(Error::InvalidFormat("vault meta"))?;
        Vault::open(&self.account, v, &key.data, &meta.data)
    }

    /// A signed manifest record, verified without history: the local
    /// manifest and its ancestor were both checked when they were written.
    fn open_manifest(&self, vault: &Vault, data: &[u8]) -> Result<Manifest> {
        let sm = SignedManifest::decode(data)?;
        verify_manifest(vault, &self.account.params.signing_pub, &sm, None)
    }

    /// Read the local manifest and its ancestor, and turn them into intents.
    /// Nothing is written.
    fn plan(&self, vault: &Vault) -> Result<Plan> {
        // Held means a pending manifest with data: that is what `get` sees.
        let local = self
            .store
            .get(RecordKind::Manifest, vault.id)?
            .ok_or(IntegrityError::ManifestMissingItem)?;
        let local_manifest = self.open_manifest(vault, &local.data)?;
        let ancestor = match self.store.ancestor_manifest(vault.id)? {
            Some(rec) => {
                let a = self.open_manifest(vault, &rec.data)?;
                // The local copy kept as is over a newer server state: no
                // intent of its own.
                if rec.data != local.data {
                    descends(&local_manifest, &a)?;
                }
                Some(a)
            }
            None => None,
        };
        let ancestor_entries: &[ManifestEntry] = ancestor.as_ref().map_or(&[], |a| &a.entries);

        // The local records of this vault, to find each changed entry's:
        // the visible ones, and the ones kept from before the server removed
        // them.
        let mut rows = self.store.list(RecordKind::Item)?;
        rows.extend(self.store.kept_rows(vault.id)?.unwrap_or_default());
        let records: Vec<ItemRecord> = rows
            .iter()
            .filter_map(|r| {
                let (prefix, body) = split_item_record(&r.data).ok()?;
                (prefix == vault.id).then(|| ItemRecord::decode(body).ok())?
            })
            .collect();
        let mut changed = Vec::new();
        for e in &local_manifest.entries {
            if ancestor_entries.contains(e) {
                continue;
            }
            let rec = records
                .iter()
                .find(|r| {
                    r.item_id == e.item_id
                        && r.version == e.version
                        && record_hash(r) == e.record_hash
                })
                .ok_or(IntegrityError::ManifestMissingItem)?;
            changed.push(Changed {
                item: vault.open_item(rec)?,
                hash: e.record_hash,
            });
        }
        let deleted = ancestor_entries
            .iter()
            .filter(|a| {
                !local_manifest
                    .entries
                    .iter()
                    .any(|e| e.item_id == a.item_id)
            })
            .cloned()
            .collect();
        Ok(Plan {
            local,
            local_manifest,
            ancestor,
            changed,
            deleted,
        })
    }

    /// Carry out the plan inside the open batch.
    fn apply(&mut self, vault: &Vault, plan: Plan, epoch: Option<&RestoreEpoch>) -> Result<()> {
        self.store.drop_pending_vault(vault.id)?;
        let head = epoch.and_then(|e| e.heads.get(&vault.id)).cloned();
        let behind_head = head
            .as_ref()
            .is_some_and(|h| h.seq > plan.local_manifest.seq);
        if !behind_head
            && plan.ancestor.is_some()
            && self.store.get(RecordKind::Manifest, vault.id)?.as_ref() == Some(&plan.local)
        {
            // The server holds the local manifest itself (this device's
            // copy pushed back, the confirmation lost): adopt it, checking
            // its records like any load.
            self.device
                .last_seen
                .insert(vault.id, seen(&plan.local_manifest));
            self.load(vault)?;
            return Ok(());
        }
        match &plan.ancestor {
            // The server manifest must chain to the ancestor, as if the
            // local writes had never happened, or to the epoch head if the
            // epoch came after the ancestor.
            Some(a) => {
                let base = match head {
                    Some(h) if h.seq > a.seq => h,
                    _ => seen(a),
                };
                self.device.last_seen.insert(vault.id, base);
            }
            None => {
                if self.store.get(RecordKind::Manifest, vault.id)?.as_ref() == Some(&plan.local) {
                    // Our own unconfirmed push came back as it was: adopt it,
                    // checking its records like any load.
                    self.device
                        .last_seen
                        .insert(vault.id, seen(&plan.local_manifest));
                    self.load(vault)?;
                    return Ok(());
                }
                // First use for this vault: no history to check against,
                // except the epoch head if there is one.
                match head {
                    Some(h) => self.device.last_seen.insert(vault.id, h),
                    None => self.device.last_seen.remove(&vault.id),
                };
            }
        }
        let loaded = self.load(vault)?;
        self.device
            .last_seen
            .insert(vault.id, seen(&loaded.manifest));

        let ancestor = plan.ancestor_entries();
        let mut saves = Vec::new();
        for c in &plan.changed {
            let keep = match loaded.listed(c.item.id) {
                None => true,
                Some((_, remote)) => {
                    let remote_hash = record_hash(remote);
                    let untouched = ancestor.iter().any(|a| {
                        a.item_id == remote.item_id
                            && a.version == remote.version
                            && a.record_hash == remote_hash
                    });
                    untouched || {
                        let theirs = vault.open_item(remote)?.updated_at;
                        c.item.updated_at > theirs
                            || (c.item.updated_at == theirs && c.hash > remote_hash)
                    }
                }
            };
            if keep {
                saves.push(c.item.clone());
            }
        }
        let deletes: Vec<Id> = plan
            .deleted
            .iter()
            .filter(|a| {
                loaded
                    .listed(a.item_id)
                    .is_some_and(|(_, r)| r.version == a.version && record_hash(r) == a.record_hash)
            })
            .map(|a| a.item_id)
            .collect();

        for item in saves {
            self.save_item(vault, item)?;
        }
        for id in deletes {
            self.delete_item(vault, id)?;
        }
        Ok(())
    }
}

/// The local manifest must have been built on the ancestor: a later seq,
/// and the very next one must point at it. Otherwise `ManifestRollback`.
fn descends(local: &Manifest, ancestor: &Manifest) -> Result<()> {
    let chained = local.seq > ancestor.seq
        && (local.seq != ancestor.seq + 1 || local.prev_hash == manifest_hash(ancestor));
    if chained {
        Ok(())
    } else {
        Err(IntegrityError::ManifestRollback.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_manifest_must_descend_from_its_ancestor() {
        let v = Id::new();
        let a = Manifest::next(None, v, vec![]).unwrap();
        let next = Manifest::next(Some(&a), v, vec![]).unwrap();
        let later = Manifest::next(Some(&next), v, vec![]).unwrap();
        assert_eq!(descends(&next, &a), Ok(()));
        // Two local writes on the ancestor: no direct link to check.
        assert_eq!(descends(&later, &a), Ok(()));

        let rollback = Err(Error::Integrity(IntegrityError::ManifestRollback));
        // Same seq, or older.
        assert_eq!(descends(&a, &a), rollback);
        assert_eq!(descends(&a, &next), rollback);
        // The next seq, built on another manifest (a fork).
        let other = Manifest::next(None, v, vec![]).unwrap();
        let mut forked = Manifest::next(Some(&other), v, vec![]).unwrap();
        forked.prev_hash[0] ^= 1;
        assert_eq!(descends(&forked, &a), rollback);
    }
}
