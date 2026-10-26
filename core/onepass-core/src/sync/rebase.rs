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
//! the server's change is kept.
//!
//! Nothing local is lost on a failure: if anything goes wrong after the
//! pending rows are dropped (a server manifest that does not chain, an item
//! withheld, a write error), they are put back as they were, with the
//! device's last seen manifest, and the vault stays held.

use crate::manifest::{Manifest, ManifestEntry, SignedManifest, record_hash, verify_manifest};
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

/// What to do with a held vault, worked out before anything is dropped.
enum Plan {
    /// Replay the local intents on top of the server manifest, which must
    /// chain to `ancestor`.
    Replay {
        ancestor: Manifest,
        changed: Vec<Changed>,
        /// Ancestor entries the local manifest no longer lists.
        deleted: Vec<ManifestEntry>,
    },
    /// No ancestor: the pending manifest was written before the vault had
    /// any `base` manifest (a new vault). The only way the server can have
    /// one is that our own push went through unconfirmed: adopt it if it is
    /// exactly the local manifest.
    Adopt { local: Record, manifest: Manifest },
}

impl Repository<SyncStore> {
    /// Save the device state in the store (`SyncStore::set_device_state`).
    pub fn persist_device_state(&mut self) -> Result<()> {
        self.store.set_device_state(&self.device)
    }

    /// Rebase every held vault (see the module doc) and return their ids.
    /// The device state is persisted at the end, also on error: a rebased
    /// vault's new last seen manifest must survive the session.
    ///
    /// Errors: a held vault with no ancestor whose server manifest is not
    /// the local one is `InvalidFormat("rebase ancestor")`; a server
    /// manifest that does not chain to the ancestor is `ManifestRollback`;
    /// then any error of `load`, `save_item` or `delete_item`. The vault in
    /// error keeps its pending writes and stays held; the vaults before it
    /// stay rebased.
    pub fn rebase(&mut self) -> Result<Vec<Id>> {
        let result = self.rebase_held();
        let persisted = self.persist_device_state();
        let rebased = result?;
        persisted?;
        Ok(rebased)
    }

    fn rebase_held(&mut self) -> Result<Vec<Id>> {
        let held = self.store.vaults_needing_rebase()?;
        for &v in &held {
            self.rebase_vault(v)?;
        }
        Ok(held)
    }

    fn rebase_vault(&mut self, v: Id) -> Result<()> {
        let vault = self.open_vault(v)?;
        let plan = self.plan(&vault)?;
        let last_seen = self.device.last_seen.get(&v).cloned();
        let snapshot = self.store.drop_pending_vault(v)?;
        match self.apply(&vault, plan) {
            Ok(()) => Ok(()),
            Err(e) => {
                self.store.restore_pending_vault(snapshot)?;
                match last_seen {
                    Some(s) => self.device.last_seen.insert(v, s),
                    None => self.device.last_seen.remove(&v),
                };
                Err(e)
            }
        }
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
        let local_rec = self
            .store
            .get(RecordKind::Manifest, vault.id)?
            .ok_or(IntegrityError::ManifestMissingItem)?;
        let local = self.open_manifest(vault, &local_rec.data)?;
        let Some(ancestor_rec) = self.store.ancestor_manifest(vault.id)? else {
            return Ok(Plan::Adopt {
                local: local_rec,
                manifest: local,
            });
        };
        let ancestor = self.open_manifest(vault, &ancestor_rec.data)?;

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
        for e in &local.entries {
            if ancestor.entries.contains(e) {
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
        let deleted = ancestor
            .entries
            .iter()
            .filter(|a| !local.entries.iter().any(|e| e.item_id == a.item_id))
            .cloned()
            .collect();
        Ok(Plan::Replay {
            ancestor,
            changed,
            deleted,
        })
    }

    /// Carry out the plan, the vault's pending rows already dropped.
    fn apply(&mut self, vault: &Vault, plan: Plan) -> Result<()> {
        match plan {
            Plan::Adopt { local, manifest } => {
                let server = self.store.get(RecordKind::Manifest, vault.id)?;
                if server.as_ref() != Some(&local) {
                    return Err(Error::InvalidFormat("rebase ancestor"));
                }
                // Our own manifest, already seen: check its records are all
                // there, as for any load.
                self.device.last_seen.insert(vault.id, seen(&manifest));
                self.load(vault)?;
                Ok(())
            }
            Plan::Replay {
                ancestor,
                changed,
                deleted,
            } => self.replay(vault, &ancestor, changed, &deleted),
        }
    }

    fn replay(
        &mut self,
        vault: &Vault,
        ancestor: &Manifest,
        changed: Vec<Changed>,
        deleted: &[ManifestEntry],
    ) -> Result<()> {
        // The server manifest must chain to the ancestor, as if the local
        // writes had never happened.
        self.device.last_seen.insert(vault.id, seen(ancestor));
        let loaded = self.load(vault)?;
        self.device
            .last_seen
            .insert(vault.id, seen(&loaded.manifest));

        let mut saves = Vec::new();
        for c in changed {
            let keep = match loaded.listed(c.item.id) {
                None => true,
                Some((_, remote)) => {
                    let remote_hash = record_hash(remote);
                    let untouched = ancestor.entries.iter().any(|a| {
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
                saves.push(c.item);
            }
        }
        let deletes: Vec<Id> = deleted
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
