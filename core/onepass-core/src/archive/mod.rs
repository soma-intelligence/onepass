//! Encrypted OnePass archive: export and backup (milestone 5).

#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

pub mod format;

use std::collections::HashSet;

use crate::Id;
use crate::model::Item;
use crate::store::RecordKind;
use crate::vault::VaultMeta;

pub use format::{
    ArchiveKind, ArchivedVault, CURRENT_SCHEMA, Contents, HeaderInfo, Unlock, backup, export,
    inspect, open, open_retired,
};

/// Whether a record of `kind` can be written by a restore: the vault
/// content only. The account records, the lists, the epoch and everything
/// keyed by the identity (lineage, device intros, key deliveries) belong to
/// the live account and are never restored from a file (spec 10.7). An
/// archive carries no record at all, only vaults and items: this names the
/// boundary a restore must stay inside.
pub fn restorable_kind(kind: RecordKind) -> bool {
    matches!(
        kind,
        RecordKind::VaultKey | RecordKind::VaultMeta | RecordKind::Item | RecordKind::Manifest
    )
}

/// What restoring an archive into an account does. Nothing is overwritten.
#[derive(Debug, Clone, PartialEq)]
pub struct RestorePlan {
    /// Archive vaults absent from the account, by archive id: create one
    /// with this meta each.
    pub new_vaults: Vec<(Id, VaultMeta)>,
    /// `(archive vault id, item)` for each item whose id is absent from the
    /// whole account. The caller rewrites `vault_id` to the vault it writes
    /// into.
    pub writes: Vec<(Id, Item)>,
    /// Items whose id already exists in any vault of the account (or earlier
    /// in the archive), left untouched.
    pub skipped: u32,
}

/// What `Repository::restore_archive` did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreReport {
    pub vaults_created: u32,
    pub restored: u32,
    pub skipped: u32,
    /// The archive was made before a key rotation (R18): the restore
    /// screen says so before this runs.
    pub made_before_rotation: bool,
}

/// Plan a restore of `contents` into an account whose vaults and item ids
/// are `existing`. An archive vault whose id exists is reused, otherwise it
/// is listed in `new_vaults`. An item whose id already exists in any vault
/// of the account, or appeared earlier in the archive (in any archive
/// vault), is skipped and counted: an item id is written at most once. The
/// output follows the archive order; the order of `existing` does not
/// matter.
pub fn restore_plan(contents: &Contents, existing: &[(Id, Vec<Id>)]) -> RestorePlan {
    let vaults: HashSet<Id> = existing.iter().map(|(v, _)| *v).collect();
    let mut items: HashSet<Id> = existing
        .iter()
        .flat_map(|(_, ids)| ids.iter().copied())
        .collect();
    let mut created: HashSet<Id> = HashSet::new();
    let mut plan = RestorePlan {
        new_vaults: Vec::new(),
        writes: Vec::new(),
        skipped: 0,
    };
    for vault in &contents.vaults {
        if !vaults.contains(&vault.id) && created.insert(vault.id) {
            plan.new_vaults.push((vault.id, vault.meta.clone()));
        }
        for item in &vault.items {
            if items.insert(item.id) {
                plan.writes.push((vault.id, item.clone()));
            } else {
                plan.skipped = plan.skipped.saturating_add(1);
            }
        }
    }
    plan
}
