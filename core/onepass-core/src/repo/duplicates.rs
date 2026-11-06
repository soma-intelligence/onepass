//! Possible duplicates over the vaults of the account (spec
//! 2026-11-03-duplicates): find them, merge them, archive or trash the
//! extra copies, or remember that they are not duplicates.
//!
//! Every write goes through `save_item`, `archive_item` and `trash_item`,
//! so a shared vault where this account is Read only refuses it in the core
//! (`require_role`) whatever the caller asks. The calls here also check it
//! first, so nothing is half done: a merge into a read-only primary is
//! refused before any write.

use time::OffsetDateTime;

use super::Repository;
use crate::attachment::{self, MAX_PER_ITEM};
use crate::duplicates::{self, Candidate, Group, Merge};
use crate::error::{Error, Result, ValidationError};
use crate::id::Id;
use crate::model::{EventKind, Item, events::record_edit};
use crate::share::Role;
use crate::store::RecordStore;
use crate::vault::Vault;

fn vault_of(vaults: &[Vault], id: Id) -> Result<&Vault> {
    vaults.iter().find(|v| v.id == id).ok_or(Error::NotFound)
}

fn refused(field: &str, reason: &'static str) -> Error {
    ValidationError {
        field: field.into(),
        reason,
    }
    .into()
}

/// One item of the scan: where it lives and whether this account may change
/// it.
#[derive(Debug, Clone)]
pub struct ScannedItem {
    pub item: Item,
    pub vault_id: Id,
    pub vault_name: String,
    pub writable: bool,
}

/// The result of `duplicate_scan`: `groups` index `items`.
#[derive(Debug, Clone, Default)]
pub struct DuplicateScan {
    pub items: Vec<ScannedItem>,
    pub groups: Vec<Group>,
}

/// A merge as planned: what would be saved, and how many read-only copies
/// stay as they are.
#[derive(Debug, Clone)]
pub struct MergePlan {
    pub merge: Merge,
    pub read_only_left: usize,
}

/// The primary as stored, the writable others (vault id, item), the plan.
type Planned = (Item, Vec<(Id, Item)>, MergePlan);

/// An item by its vault and id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ItemKey {
    pub vault_id: Id,
    pub item_id: Id,
}

impl<S: RecordStore> Repository<S> {
    /// This account may write items of `vault`: always for a personal vault,
    /// from `Role::Write` up in a shared one.
    pub fn can_write_vault(&self, vault: &Vault) -> Result<bool> {
        if !vault.zone().is_shared() {
            return Ok(true);
        }
        let me = self.me();
        Ok(self
            .store
            .share_state(vault.id)?
            .and_then(|s| {
                s.head
                    .member(me.account_id)
                    .filter(|m| m.identity_id == me.identity_id)
                    .map(|m| m.role)
            })
            .is_some_and(|r| r >= Role::Write))
    }

    /// Every vault but `excluded` (the ones the app hides), with the items
    /// of each and its write right, then the groups of possible duplicates
    /// (`duplicates::find`). Only this account's vaults: never another
    /// account of the device.
    pub fn duplicate_scan(&mut self, excluded: &[Id]) -> Result<DuplicateScan> {
        let mut items = Vec::new();
        for vault in self.vaults()? {
            if excluded.contains(&vault.id) {
                continue;
            }
            let writable = self.can_write_vault(&vault)?;
            for item in self.items(&vault)? {
                items.push(ScannedItem {
                    item,
                    vault_id: vault.id,
                    vault_name: vault.meta.name.clone(),
                    writable,
                });
            }
        }
        let cands: Vec<Candidate<'_>> = items
            .iter()
            .map(|s| Candidate {
                item: &s.item,
                writable: s.writable,
            })
            .collect();
        let groups = duplicates::find(&cands);
        Ok(DuplicateScan { items, groups })
    }

    fn listed(&mut self, vault: &Vault, id: Id) -> Result<Item> {
        self.items(vault)?
            .into_iter()
            .find(|i| i.id == id)
            .ok_or(Error::NotFound)
    }

    /// Merge `others` into `primary` (`duplicates::merge`) and return the
    /// primary as saved.
    ///
    /// The primary must be writable (`Validation("primary", "read only")`).
    /// A read-only copy among `others` is left as it is, neither folded nor
    /// archived, and the primary remembers it as "not a duplicate" so the
    /// group does not come back for it.
    ///
    /// Order, so a crash loses nothing: the files of the others are copied
    /// into the primary's vault first (new attachments, the copies keep
    /// theirs), then the primary is saved, then each other copy is saved
    /// archived with `note`. A crash after the primary leaves the others
    /// live: the group shows again and merging again adds nothing new.
    pub fn merge_duplicates(
        &mut self,
        primary: ItemKey,
        others: &[ItemKey],
        note: &str,
    ) -> Result<Item> {
        let vaults = self.vaults()?;
        let pv = vault_of(&vaults, primary.vault_id)?;
        let now = OffsetDateTime::now_utc();
        let (before, folded, plan) = self.plan_merge(&vaults, primary, others, note, now)?;
        let Merge {
            mut merged,
            archived,
            attachments,
        } = plan.merge;
        // Files first: read from the copy, sealed anew for the primary's vault.
        let mut written: Vec<Id> = Vec::new();
        let copied = (|| -> Result<()> {
            for (from_item, r) in &attachments {
                let (fv, _) = folded
                    .iter()
                    .find(|(_, i)| i.id == *from_item)
                    .ok_or(Error::NotFound)?;
                let fv = vault_of(&vaults, *fv)?;
                let bytes = self.read_attachment(fv, *from_item, r.id)?;
                let (reference, records) =
                    attachment::seal_attachment(pv, &r.name, &r.mime, &bytes)?;
                written.extend(records.iter().map(|c| c.id));
                self.put_chunks(pv.zone(), records)?;
                merged.record(
                    now,
                    EventKind::AttachmentAdded {
                        name: reference.name.clone(),
                    },
                );
                merged.attachments.push(reference);
            }
            Ok(())
        })();
        if let Err(e) = copied {
            self.delete_chunks(pv.zone(), &written);
            return Err(e);
        }
        record_edit(Some(&before), &mut merged, now);
        if let Err(e) = self.save_item(pv, merged.clone()) {
            self.delete_chunks(pv.zone(), &written);
            return Err(e);
        }
        for mut copy in archived {
            let v = vault_of(&vaults, copy.vault_id)?;
            copy.record(now, EventKind::Archived);
            self.save_item(v, copy)?;
        }
        Ok(merged)
    }

    /// What `merge_duplicates` would save, without writing anything: the
    /// primary as merged (files of the others counted, not copied yet).
    pub fn merge_preview(
        &mut self,
        primary: ItemKey,
        others: &[ItemKey],
        note: &str,
    ) -> Result<MergePlan> {
        let vaults = self.vaults()?;
        let (_, _, plan) =
            self.plan_merge(&vaults, primary, others, note, OffsetDateTime::now_utc())?;
        Ok(plan)
    }

    /// Load the primary and the others, check the rights, fold them.
    /// Returns the primary as stored, the writable others (vault id, item)
    /// and the plan.
    fn plan_merge(
        &mut self,
        vaults: &[Vault],
        primary: ItemKey,
        others: &[ItemKey],
        note: &str,
        now: OffsetDateTime,
    ) -> Result<Planned> {
        let pv = vault_of(vaults, primary.vault_id)?;
        if !self.can_write_vault(pv)? {
            return Err(refused("primary", "read only"));
        }
        let before = self.listed(pv, primary.item_id)?;
        let mut folded: Vec<(Id, Item)> = Vec::new();
        let mut read_only: Vec<Id> = Vec::new();
        for k in others {
            if k.item_id == primary.item_id || folded.iter().any(|(_, i)| i.id == k.item_id) {
                continue;
            }
            let v = vault_of(vaults, k.vault_id)?;
            let item = self.listed(v, k.item_id)?;
            if self.can_write_vault(v)? {
                folded.push((v.id, item));
            } else {
                read_only.push(item.id);
            }
        }
        let refs: Vec<&Item> = folded.iter().map(|(_, i)| i).collect();
        let mut merge = duplicates::merge(&before, &refs, note, now);
        duplicates::mark_distinct(&mut merge.merged, read_only.iter().copied());
        if merge.merged.attachments.len() + merge.attachments.len() > MAX_PER_ITEM {
            return Err(Error::InvalidFormat("too many attachments"));
        }
        Ok((
            before,
            folded,
            MergePlan {
                merge,
                read_only_left: read_only.len(),
            },
        ))
    }

    /// Archive each of `items` (the extra copies). A read-only or missing
    /// one is refused before anything is written.
    pub fn archive_duplicates(&mut self, items: &[ItemKey]) -> Result<()> {
        let vaults = self.writable_vaults_of(items)?;
        for k in items {
            self.archive_item(vault_of(&vaults, k.vault_id)?, k.item_id)?;
        }
        Ok(())
    }

    /// Put each of `items` in the trash (the existing trash flow, restorable).
    pub fn trash_duplicates(&mut self, items: &[ItemKey]) -> Result<()> {
        let vaults = self.writable_vaults_of(items)?;
        for k in items {
            self.trash_item(vault_of(&vaults, k.vault_id)?, k.item_id)?;
        }
        Ok(())
    }

    /// The vaults, after checking that each of `items` is in a writable one
    /// that lists it.
    fn writable_vaults_of(&mut self, items: &[ItemKey]) -> Result<Vec<Vault>> {
        let vaults = self.vaults()?;
        for k in items {
            let v = vault_of(&vaults, k.vault_id)?;
            if !self.can_write_vault(v)? {
                return Err(refused("item", "read only"));
            }
            self.listed(v, k.item_id)?;
        }
        Ok(vaults)
    }

    /// "Not duplicates": every writable member remembers every other one
    /// (hidden tag, sealed and synced with the item, `updated_at`
    /// unchanged so the dismissal never wins over a real edit). Refused
    /// when no member is writable.
    pub fn dismiss_duplicates(&mut self, members: &[ItemKey]) -> Result<()> {
        let vaults = self.vaults()?;
        let ids: Vec<Id> = members.iter().map(|k| k.item_id).collect();
        let mut targets = Vec::new();
        for k in members {
            let v = vault_of(&vaults, k.vault_id)?;
            if self.can_write_vault(v)? {
                let item = self.listed(v, k.item_id)?;
                targets.push((v, item));
            }
        }
        if targets.is_empty() {
            return Err(refused("item", "read only"));
        }
        for (v, mut item) in targets {
            if duplicates::mark_distinct(&mut item, ids.iter().copied()) {
                self.save_item(v, item)?;
            }
        }
        Ok(())
    }
}
