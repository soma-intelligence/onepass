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
use crate::vault::VaultMeta;

pub use format::{
    ArchiveKind, ArchivedVault, CURRENT_SCHEMA, Contents, HeaderInfo, Unlock, backup, export,
    inspect, open,
};

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
