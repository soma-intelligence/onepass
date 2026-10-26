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
//! Serialization premise: each vault's plan is read before its batch opens.
//! Only the session writes pending rows, with one exception: the settlement
//! of a zone reset (`SyncStore::finish_full_fetch` in reset mode) requeues
//! rows through the sync connection. A rebase and that settlement must not
//! interleave; the apps guarantee it by running the rebase inside the sync
//! round that owns the fetch (one round at a time).

use crate::epoch::{EpochReason, RestoreEpoch};
use crate::manifest::{
    Manifest, ManifestEntry, SignedManifest, manifest_hash, record_hash, verify_manifest,
};
use crate::model::Item;
use crate::repo::{Repository, seen, split_item_record};
use crate::store::{Record, RecordKind, RecordStore};
use crate::sync::SyncStore;
use crate::vault::{ItemRecord, Vault};
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

impl Repository<SyncStore> {
    /// Like `issue_restore_epoch`, for an owner's explicit choice of this
    /// device's copy (`KeepThisDevice` after an alert): the heads are this
    /// device's local copies, verified against its own history (pending
    /// writes over the server state), even where the server is behind or
    /// the vault is held for a rebase that cannot succeed. Every head is
    /// re-signed at the epoch floor, then every pending manifest and the
    /// epoch are rebuilt on the current server rows
    /// (`SyncStore::rebuild_ancestors_on_base`): none is held, and the next
    /// push overwrites the server's copies with them.
    ///
    /// Still refused: a stored epoch that fails the rules, and a vault
    /// whose local copy fails the checks (nothing verified to keep).
    pub fn issue_restore_epoch_from_local(&mut self, reason: EpochReason) -> Result<RestoreEpoch> {
        let issued = self.issue_restore_epoch(reason)?;
        self.store.rebuild_ancestors_on_base()?;
        self.persist_device_state()?;
        Ok(issued)
    }

    /// Save the device state in the store (`SyncStore::set_device_state`).
    pub fn persist_device_state(&mut self) -> Result<()> {
        self.store.set_device_state(&self.device)
    }

    /// Rebase every held vault (see the module doc) and return their ids.
    /// Each vault is tried, in one transaction with the device state; a
    /// failing vault does not stop the others. The device state is
    /// persisted again at the end.
    ///
    /// Errors, the first one met after trying every vault: a local
    /// manifest that does not descend from its ancestor, or a server
    /// manifest that does not chain to the ancestor, is `ManifestRollback`;
    /// then any error of `load`, `save_item` or `delete_item`. A vault in
    /// error keeps its pending writes and stays held; the others stay
    /// rebased.
    ///
    /// Before any vault: a local restore epoch that cannot ship (see the
    /// module doc) is dropped and the device goes back to the epoch it had
    /// before issuing it; then the stored epoch is checked and applied (its
    /// errors stop the rebase). The dropped epoch is `Error::Conflict`,
    /// returned after every vault was tried, before any vault error.
    pub fn rebase(&mut self) -> Result<Vec<Id>> {
        let held = self.store.vaults_needing_rebase()?;
        let pending_epoch = self.store.pending_epoch()?;
        let lost_epoch = pending_epoch.is_some() && (self.store.epoch_held()? || !held.is_empty());
        if let (true, Some(issued)) = (lost_epoch, pending_epoch) {
            self.store.drop_pending_epoch()?;
            // `issue_restore_epoch` takes the epoch accepted plus one, so
            // the one before is what this device had accepted.
            if self.device.epoch == issued {
                self.device.epoch = issued - 1;
            }
            self.persist_device_state()?;
        }
        let epoch = self.sync_epoch()?;
        let mut rebased = Vec::new();
        let mut first_error = None;
        for v in held {
            match self.rebase_vault(v, epoch.as_ref()) {
                Ok(()) => rebased.push(v),
                Err(e) => {
                    first_error.get_or_insert(e);
                }
            }
        }
        let persisted = self.persist_device_state();
        if lost_epoch {
            return persisted.and(Err(Error::Conflict));
        }
        match first_error {
            Some(e) => Err(e),
            None => persisted.map(|()| rebased),
        }
    }

    fn rebase_vault(&mut self, v: Id, epoch: Option<&RestoreEpoch>) -> Result<()> {
        let vault = self.open_vault(v)?;
        let plan = self.plan(&vault)?;
        let last_seen = self.device.last_seen.get(&v).cloned();
        self.store.begin_batch()?;
        let result = self
            .apply(&vault, plan, epoch)
            .and_then(|()| self.persist_device_state())
            .and_then(|()| self.store.commit_batch());
        if let Err(e) = result {
            match last_seen {
                Some(s) => self.device.last_seen.insert(v, s),
                None => self.device.last_seen.remove(&v),
            };
            // The original error wins. If the rollback fails too, SQLite
            // undoes the open transaction when the connection closes, and
            // the next batch on it is refused ("batch already open").
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
                descends(&local_manifest, &a)?;
                Some(a)
            }
            None => None,
        };
        let ancestor_entries: &[ManifestEntry] = ancestor.as_ref().map_or(&[], |a| &a.entries);

        // The local records of this vault, to find each changed entry's.
        let records: Vec<ItemRecord> = self
            .store
            .list(RecordKind::Item)?
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
