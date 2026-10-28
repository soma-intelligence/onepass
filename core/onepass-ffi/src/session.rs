//! The unlocked session and the lock-free sync handle.

use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use onepass_core::Id;
use onepass_core::model::{self, Item};
use onepass_core::store::{RecordKind, RecordStore};
use onepass_core::sync::{RemoteChange, SyncStore};
use onepass_core::vault::Vault;
use time::{Duration, OffsetDateTime};

use crate::convert::*;
use crate::error::{OnePassError, invalid};
use crate::types::*;

pub(crate) type Repo = onepass_core::repo::Repository<SyncStore>;

/// An unlocked account. The only writer of pending rows and device state.
/// `lock` drops the repository, which wipes every key it holds.
#[derive(uniffi::Object)]
pub struct Session {
    account_id: String,
    inner: Mutex<Option<Repo>>,
}

pub(crate) fn account_id_of(repo: &Repo) -> Result<Id, OnePassError> {
    repo.store()
        .list(RecordKind::AccountParams)?
        .first()
        .map(|r| r.id)
        .ok_or(OnePassError::NotFound)
}

impl Session {
    /// A session over an unlocked repository. A store in Travel Mode keeps
    /// its parked vaults parked (`resume_travel`), so `vaults()` does not
    /// expect them; a sealed state that does not verify fails the unlock.
    pub(crate) fn new(mut repo: Repo) -> Result<Arc<Session>, OnePassError> {
        if let Some(state) = crate::travel::open_state(&repo)? {
            repo.resume_travel(&state);
        }
        Ok(Arc::new(Session {
            account_id: id_hex(account_id_of(&repo)?),
            inner: Mutex::new(Some(repo)),
        }))
    }

    pub(crate) fn guard(&self) -> MutexGuard<'_, Option<Repo>> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Run `f` on the unlocked repository. A `Conflict` is retried once. The
    /// device state is persisted after every success.
    pub(crate) fn with<R>(
        &self,
        mut f: impl FnMut(&mut Repo) -> Result<R, OnePassError>,
    ) -> Result<R, OnePassError> {
        let mut guard = self.guard();
        let repo = guard.as_mut().ok_or(OnePassError::Locked)?;
        let out = match f(repo) {
            Err(OnePassError::Conflict) => f(repo)?,
            other => other?,
        };
        repo.persist_device_state()?;
        Ok(out)
    }
}

pub(crate) fn find_vault(repo: &Repo, id: Id) -> Result<Vault, OnePassError> {
    repo.vaults()?
        .into_iter()
        .find(|v| v.id == id)
        .ok_or(OnePassError::NotFound)
}

pub(crate) fn find_item(repo: &mut Repo, vault: &Vault, id: Id) -> Result<Item, OnePassError> {
    repo.items(vault)?
        .into_iter()
        .find(|i| i.id == id)
        .ok_or(OnePassError::NotFound)
}

fn live_count(items: &[Item]) -> u32 {
    u32::try_from(items.iter().filter(|i| i.trashed_at.is_none()).count()).unwrap_or(u32::MAX)
}

impl Session {
    /// Open the item, change it, bump `updated_at`, save a new version.
    fn update(
        &self,
        vault_id: &str,
        item_id: &str,
        change: impl Fn(&mut Item),
    ) -> Result<(), OnePassError> {
        let (vault_id, item_id) = (parse_id(vault_id)?, parse_id(item_id)?);
        self.with(|repo| {
            let vault = find_vault(repo, vault_id)?;
            let mut item = find_item(repo, &vault, item_id)?;
            let before = item.clone();
            change(&mut item);
            let now = OffsetDateTime::now_utc();
            model::events::record_edit(Some(&before), &mut item, now);
            item.updated_at = now;
            repo.save_item(&vault, item)?;
            Ok(())
        })
    }
}

#[uniffi::export]
impl Session {
    pub fn account_id(&self) -> String {
        self.account_id.clone()
    }

    pub fn vaults(&self) -> Result<Vec<FfiVault>, OnePassError> {
        self.with(|repo| {
            let mut out = Vec::new();
            for v in repo.vaults()? {
                let items = repo.items(&v)?;
                out.push(vault_to_ffi(&v, live_count(&items)));
            }
            Ok(out)
        })
    }

    pub fn create_vault(&self, meta: FfiVaultMeta) -> Result<FfiVault, OnePassError> {
        self.with(|repo| {
            let v = repo.create_vault(meta_to_core(&meta))?;
            Ok(vault_to_ffi(&v, 0))
        })
    }

    pub fn update_vault(
        &self,
        vault_id: String,
        meta: FfiVaultMeta,
    ) -> Result<FfiVault, OnePassError> {
        let id = parse_id(&vault_id)?;
        self.with(|repo| {
            let vault = find_vault(repo, id)?;
            let v = repo.update_vault_meta(&vault, meta_to_core(&meta))?;
            let items = repo.items(&v)?;
            Ok(vault_to_ffi(&v, live_count(&items)))
        })
    }

    /// Every item of every vault, trashed and archived ones included.
    pub fn item_summaries(&self) -> Result<Vec<FfiItemSummary>, OnePassError> {
        self.with(|repo| {
            let mut out = Vec::new();
            for v in repo.vaults()? {
                out.extend(repo.items(&v)?.iter().map(summary));
            }
            Ok(out)
        })
    }

    pub fn item(&self, vault_id: String, item_id: String) -> Result<FfiItem, OnePassError> {
        let (vault_id, item_id) = (parse_id(&vault_id)?, parse_id(&item_id)?);
        self.with(|repo| {
            let vault = find_vault(repo, vault_id)?;
            Ok(item_to_ffi(&find_item(repo, &vault, item_id)?))
        })
    }

    /// An empty item of this type. Not stored until `save_item`.
    pub fn new_item(
        &self,
        vault_id: String,
        item_type: FfiItemType,
        title: String,
    ) -> Result<FfiItem, OnePassError> {
        let vault_id = parse_id(&vault_id)?;
        self.with(|repo| {
            find_vault(repo, vault_id)?;
            Ok(item_to_ffi(&model::new_item(
                item_type.into(),
                vault_id,
                &title,
            )))
        })
    }

    /// Validate, then write. Keeps what the UI cannot carry (see
    /// `item_to_core`) and returns the item as stored.
    pub fn save_item(&self, item: FfiItem) -> Result<FfiItem, OnePassError> {
        let (vault_id, item_id) = (parse_id(&item.vault_id)?, parse_id(&item.id)?);
        self.with(|repo| {
            let vault = find_vault(repo, vault_id)?;
            let stored = repo.items(&vault)?.into_iter().find(|i| i.id == item_id);
            if stored.is_none() {
                // A stale editor: the item moved to another vault meanwhile.
                for other in repo.vaults()?.iter().filter(|v| v.id != vault_id) {
                    if repo.items(other)?.iter().any(|i| i.id == item_id) {
                        return Err(OnePassError::Conflict);
                    }
                }
            }
            let kept = Kept::new(stored.as_ref(), false);
            let now = OffsetDateTime::now_utc();
            let core = item_to_core(&item, &kept, now)?;
            let mut core = crate::validate_for_save(core)?;
            model::events::record_edit(stored.as_ref(), &mut core, now);
            repo.save_item(&vault, core.clone())?;
            Ok(item_to_ffi(&core))
        })
    }

    pub fn trash_item(&self, vault_id: String, item_id: String) -> Result<(), OnePassError> {
        let (vault_id, item_id) = (parse_id(&vault_id)?, parse_id(&item_id)?);
        self.with(|repo| {
            let vault = find_vault(repo, vault_id)?;
            Ok(repo.trash_item(&vault, item_id)?)
        })
    }

    pub fn restore_item(&self, vault_id: String, item_id: String) -> Result<(), OnePassError> {
        self.update(&vault_id, &item_id, |i| i.trashed_at = None)
    }

    pub fn archive_item(&self, vault_id: String, item_id: String) -> Result<(), OnePassError> {
        let (vault_id, item_id) = (parse_id(&vault_id)?, parse_id(&item_id)?);
        self.with(|repo| {
            let vault = find_vault(repo, vault_id)?;
            Ok(repo.archive_item(&vault, item_id)?)
        })
    }

    pub fn unarchive_item(&self, vault_id: String, item_id: String) -> Result<(), OnePassError> {
        self.update(&vault_id, &item_id, |i| i.archived = false)
    }

    pub fn delete_item(&self, vault_id: String, item_id: String) -> Result<(), OnePassError> {
        let (vault_id, item_id) = (parse_id(&vault_id)?, parse_id(&item_id)?);
        self.with(|repo| {
            let vault = find_vault(repo, vault_id)?;
            Ok(repo.delete_item(&vault, item_id)?)
        })
    }

    pub fn set_favorite(
        &self,
        vault_id: String,
        item_id: String,
        favorite: bool,
    ) -> Result<(), OnePassError> {
        self.update(&vault_id, &item_id, |i| i.favorite = favorite)
    }

    pub fn move_item(
        &self,
        item_id: String,
        from_vault: String,
        to_vault: String,
    ) -> Result<(), OnePassError> {
        let item_id = parse_id(&item_id)?;
        let (from, to) = (parse_id(&from_vault)?, parse_id(&to_vault)?);
        self.with(|repo| {
            let (from, to) = (find_vault(repo, from)?, find_vault(repo, to)?);
            Ok(repo.move_item(item_id, &from, &to)?)
        })
    }

    /// Delete the items trashed at least `older_than_days` days ago and
    /// return how many.
    pub fn purge_trash(&self, older_than_days: u32) -> Result<u32, OnePassError> {
        self.with(|repo| {
            // An age beyond the representable dates matches nothing.
            let Some(cutoff) =
                OffsetDateTime::now_utc().checked_sub(Duration::days(i64::from(older_than_days)))
            else {
                return Ok(0);
            };
            let mut purged = 0u32;
            for v in repo.vaults()? {
                let doomed: Vec<Id> = repo
                    .items(&v)?
                    .iter()
                    .filter(|i| i.trashed_at.is_some_and(|t| t <= cutoff))
                    .map(|i| i.id)
                    .collect();
                for id in doomed {
                    repo.delete_item(&v, id)?;
                    purged = purged.saturating_add(1);
                }
            }
            Ok(purged)
        })
    }

    pub fn password_history(
        &self,
        vault_id: String,
        item_id: String,
    ) -> Result<Vec<FfiHistoryEntry>, OnePassError> {
        let (vault_id, item_id) = (parse_id(&vault_id)?, parse_id(&item_id)?);
        self.with(|repo| {
            let vault = find_vault(repo, vault_id)?;
            let item = find_item(repo, &vault, item_id)?;
            Ok(item
                .password_history
                .iter()
                .map(|h| FfiHistoryEntry {
                    value: h.value.to_string(),
                    replaced_at: ts(h.replaced_at),
                })
                .collect())
        })
    }

    /// Rebase every vault held back by a remote change. Returns their ids.
    pub fn rebase_all(&self) -> Result<Vec<String>, OnePassError> {
        self.with(|repo| Ok(repo.rebase()?.into_iter().map(id_hex).collect()))
    }

    /// Drop the keys. Every later call is `Locked`.
    pub fn lock(&self) {
        self.guard().take();
    }
}

/// Base-layer sync operations over their own connection, usable while the
/// vault is locked. Never writes the device state. It writes pending rows in
/// one case only: `finish_full_fetch` after a zone reset requeues the rows
/// the server lost. `Session::rebase_all` reads pending rows before its
/// batch opens (see `rebase.rs`), so the app must never run a rebase and a
/// reset settlement at the same time: the coordinator serializes them (one
/// sync round at a time, rebases inside the round).
#[derive(uniffi::Object)]
pub struct SyncStoreHandle {
    store: Mutex<SyncStore>,
}

impl SyncStoreHandle {
    pub(crate) fn open(path: &Path) -> Result<Arc<SyncStoreHandle>, OnePassError> {
        Ok(Arc::new(SyncStoreHandle {
            store: Mutex::new(SyncStore::open(path)?),
        }))
    }

    fn guard(&self) -> MutexGuard<'_, SyncStore> {
        self.store.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Every key of the handle lives under this prefix, so it can never reach
/// the device state or any other key the core reserves.
fn handle_key(key: &str) -> String {
    format!("sync.{key}")
}

fn kind_of(code: u8) -> Result<RecordKind, OnePassError> {
    RecordKind::from_code(code).map_err(|_| invalid("record kind"))
}

#[uniffi::export]
impl SyncStoreHandle {
    pub fn pending_changes(&self) -> Result<Vec<FfiRecordChange>, OnePassError> {
        Ok(self
            .guard()
            .pending_changes()?
            .into_iter()
            .map(|c| FfiRecordChange {
                kind: c.kind.code(),
                id: id_hex(c.id),
                version: c.version,
                data: c.data,
            })
            .collect())
    }

    pub fn mark_pushed(
        &self,
        kind: u8,
        id: String,
        version: u64,
        server_meta: Option<Vec<u8>>,
    ) -> Result<(), OnePassError> {
        let (kind, id) = (kind_of(kind)?, parse_id(&id)?);
        Ok(self.guard().mark_pushed(kind, id, version, server_meta)?)
    }

    pub fn stage_remote(&self, record: FfiRemoteRecord) -> Result<(), OnePassError> {
        let change = RemoteChange {
            kind: kind_of(record.kind)?,
            id: parse_id(&record.id)?,
            version: record.version,
            data: record.data,
            server_meta: record.server_meta,
        };
        Ok(self.guard().stage_remote(change)?)
    }

    pub fn commit_remote(&self) -> Result<Vec<String>, OnePassError> {
        Ok(self
            .guard()
            .commit_remote()?
            .into_iter()
            .map(id_hex)
            .collect())
    }

    pub fn server_meta(&self, kind: u8, id: String) -> Result<Option<Vec<u8>>, OnePassError> {
        let (kind, id) = (kind_of(kind)?, parse_id(&id)?);
        Ok(self.guard().server_meta(kind, id)?)
    }

    pub fn meta(&self, key: String) -> Result<Option<Vec<u8>>, OnePassError> {
        Ok(self.guard().meta(&handle_key(&key))?)
    }

    pub fn set_meta(&self, key: String, value: Vec<u8>) -> Result<(), OnePassError> {
        Ok(self.guard().set_meta(&handle_key(&key), &value)?)
    }

    pub fn has_account(&self) -> Result<bool, OnePassError> {
        Ok(self.guard().has_account()?)
    }

    /// `store_state` over this handle's connection.
    pub fn store_state(&self) -> Result<FfiStoreState, OnePassError> {
        Ok(self.guard().account_state()?.into())
    }

    /// Start of a fetch from scratch (no token, or an expired one): forgets server tags and staged
    /// pages. Pair with `finish_full_fetch` after the commit of the complete fetch.
    pub fn begin_full_fetch(&self) -> Result<(), OnePassError> {
        Ok(self.guard().begin_full_fetch()?)
    }

    /// Start of a fetch after a server data loss: like `begin_full_fetch`, plus the change token stored
    /// under `token_key` is cleared and the records the server lacks will be queued again.
    pub fn begin_zone_reset(&self, token_key: String) -> Result<(), OnePassError> {
        Ok(self.guard().begin_zone_reset(&handle_key(&token_key))?)
    }

    /// The id of the account whose params record the store shows, if any.
    pub fn account_id(&self) -> Result<Option<String>, OnePassError> {
        Ok(self
            .guard()
            .list(RecordKind::AccountParams)?
            .first()
            .map(|r| id_hex(r.id)))
    }

    /// Remote deletions the store refused (account params, keyset, rows of a
    /// vault already read), oldest first, at most 100.
    pub fn ignored_deletions(&self) -> Result<Vec<FfiIgnoredDeletion>, OnePassError> {
        Ok(self
            .guard()
            .ignored_deletions()?
            .into_iter()
            .map(|e| FfiIgnoredDeletion {
                kind: e.kind.code(),
                id: id_hex(e.id),
                at: e.at,
            })
            .collect())
    }

    pub fn clear_ignored_deletions(&self) -> Result<(), OnePassError> {
        Ok(self.guard().clear_ignored_deletions()?)
    }

    /// After the commit of a complete fetch from scratch: settles the rows the server did not return
    /// (deleted, or after a reset queued again). A no-op unless a begin ran. True when rows were deleted.
    pub fn finish_full_fetch(&self) -> Result<bool, OnePassError> {
        Ok(self.guard().finish_full_fetch()?)
    }
}
