//! The signed vault list (milestone 2b, spec 4.4): every vault of the
//! account, so that a store hiding a vault is caught even on a device that
//! never opened it (gap 8 of the security model).
//!
//! `Repository::vaults` checks it: every live vault of the list must be
//! present (`VaultMissing`); a deleted one is no longer expected. A vault
//! present with a valid key, meta and signed manifest but missing from the
//! list (created by a client from before the list) is accepted, and added
//! to the list by the next call that brings the lists up to date
//! (adoption, see `devices`). `create_vault` adds its entry in the same
//! write as the vault; `delete_vault` marks it deleted in the same write as
//! the deletion of the vault's rows, and the sync store accepts the remote
//! deletion of a vault's rows only for a vault the verified list marks
//! deleted (spec 4.5).

use serde::{Deserialize, Serialize};

use crate::chain::{ChainState, Seen};
use crate::devices::earliest;
use crate::lists::{AccountList, MonotoneEntry};
use crate::repo::Repository;
use crate::store::{RecordKind, RecordStore};
use crate::{Id, Result};

/// One vault of the list. Dates are Unix seconds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultListEntry {
    pub vault_id: Id,
    pub created_at: i64,
    pub deleted_at: Option<i64>,
}

impl MonotoneEntry for VaultListEntry {
    fn id(&self) -> Id {
        self.vault_id
    }

    /// Deletion wins, the earliest dates are kept.
    fn merge(&self, other: &Self) -> Self {
        VaultListEntry {
            vault_id: self.vault_id,
            created_at: self.created_at.min(other.created_at),
            deleted_at: earliest(self.deleted_at, other.deleted_at),
        }
    }
}

impl AccountList for VaultListEntry {
    const KIND: RecordKind = RecordKind::VaultList;
    const DOMAIN: &'static [u8] = crate::lists::VAULT_LIST_DOMAIN;

    fn seen(chain: &ChainState) -> Option<Seen> {
        chain.vault_list
    }

    fn set_seen(chain: &mut ChainState, seen: Seen) {
        chain.vault_list = Some(seen);
    }
}

impl<S: RecordStore> Repository<S> {
    /// Every vault of the signed list, sorted by id, deleted ones included,
    /// after bringing the lists up to date (`maintain_lists`).
    pub fn vault_list(&mut self) -> Result<Vec<VaultListEntry>> {
        self.maintain_lists(None)?;
        Ok(self
            .read_list::<VaultListEntry>()?
            .map(|v| v.body.entries)
            .unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_merge_deletion_wins() {
        let id = Id::new();
        let live = VaultListEntry {
            vault_id: id,
            created_at: 10,
            deleted_at: None,
        };
        let gone = VaultListEntry {
            vault_id: id,
            created_at: 20,
            deleted_at: Some(30),
        };
        assert_eq!(live.merge(&gone), gone.merge(&live));
        assert_eq!(
            live.merge(&gone),
            VaultListEntry {
                vault_id: id,
                created_at: 10,
                deleted_at: Some(30)
            }
        );
    }
}
