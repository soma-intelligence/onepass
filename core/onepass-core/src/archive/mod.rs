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

use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};

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
    /// `(archive vault id, item)` for each item absent from its target vault.
    /// The caller rewrites `vault_id` to the vault it writes into.
    pub writes: Vec<(Id, Item)>,
    /// Items already present in their target vault, left untouched.
    pub skipped: u32,
}

/// Plan a restore of `contents` into an account whose vaults and item ids
/// are `existing`. An archive vault whose id exists is reused, otherwise it
/// is listed in `new_vaults`. An item whose id is already in its target
/// vault (or appeared earlier in the same archive vault) is skipped and
/// counted. The output follows the archive order; the order of `existing`
/// does not matter.
pub fn restore_plan(contents: &Contents, existing: &[(Id, Vec<Id>)]) -> RestorePlan {
    let mut targets: HashMap<Id, HashSet<Id>> = HashMap::new();
    for (vault, items) in existing {
        targets
            .entry(*vault)
            .or_default()
            .extend(items.iter().copied());
    }
    let mut plan = RestorePlan {
        new_vaults: Vec::new(),
        writes: Vec::new(),
        skipped: 0,
    };
    for vault in &contents.vaults {
        let present = match targets.entry(vault.id) {
            Entry::Occupied(e) => e.into_mut(),
            Entry::Vacant(e) => {
                plan.new_vaults.push((vault.id, vault.meta.clone()));
                e.insert(HashSet::new())
            }
        };
        for item in &vault.items {
            if present.insert(item.id) {
                plan.writes.push((vault.id, item.clone()));
            } else {
                plan.skipped = plan.skipped.saturating_add(1);
            }
        }
    }
    plan
}
