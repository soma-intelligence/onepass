//! Travel Mode over the app's store (spec 2026-10-27-m7-app, section 5).
//!
//! The vaults without `travel_safe` leave this device only: `enter_travel`
//! evicts their records (nothing is queued for the server), seals the
//! parked last manifests seen into the store's local meta and makes the
//! sync drop their records (`SyncStore::set_travel_hidden`). Leaving takes
//! two steps around a fetch from scratch: `begin_travel_exit` lets the sync
//! bring them back, then `finish_travel_exit` verifies them against the
//! parked manifests. A refused copy is evicted again and the Travel Mode
//! stays on, with its sealed state intact.

use std::collections::BTreeSet;

use onepass_core::Id;
use onepass_core::repo::travel::TravelState;
use onepass_core::store::{MemoryStore, Record, RecordKind, RecordStore};
use onepass_core::sync::SyncStore;

use crate::convert::id_hex;
use crate::error::{OnePassError, invalid};
use crate::session::{Repo, Session};

/// Local meta key of the sealed `TravelState`.
pub(crate) const TRAVEL_STATE_KEY: &str = "travel_state";

/// Where the Travel Mode stands on this device.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiTravelStatus {
    /// Vaults are off this device.
    pub active: bool,
    /// The sync may bring them back: `finish_travel_exit` is due.
    pub exiting: bool,
    /// When the Travel Mode was entered (Unix seconds).
    pub entered_at: Option<i64>,
    /// How many vaults are off this device.
    pub hidden_count: u32,
}

/// One vault in the plan shown before entering.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiTravelPlanEntry {
    pub vault_id: String,
    pub name: String,
    /// False: marked safe for travel, it stays.
    pub leaves: bool,
}

fn sealed_state(store: &SyncStore) -> Result<Option<Vec<u8>>, OnePassError> {
    Ok(store.meta(TRAVEL_STATE_KEY)?)
}

/// The parked state of the store, verified, if the Travel Mode is on.
pub(crate) fn open_state(repo: &Repo) -> Result<Option<TravelState>, OnePassError> {
    match sealed_state(repo.store())? {
        Some(bytes) => Ok(Some(repo.open_travel_state(&bytes)?)),
        None => Ok(None),
    }
}

/// Whether a record belongs to one of `vaults`. A pending item deletion
/// carries no data: it counts as belonging (refusing is the safe side).
fn in_vaults(vaults: &BTreeSet<Id>, kind: RecordKind, id: Id, data: Option<&[u8]>) -> bool {
    match kind {
        RecordKind::VaultKey | RecordKind::VaultMeta | RecordKind::Manifest => vaults.contains(&id),
        RecordKind::Item => match data {
            Some(d) => d
                .get(..16)
                .and_then(|p| <[u8; 16]>::try_from(p).ok())
                .is_some_and(|p| vaults.contains(&Id(p))),
            None => true,
        },
        _ => false,
    }
}

/// Every record of `vaults` the store shows (pending over base).
fn records_of(store: &SyncStore, vaults: &BTreeSet<Id>) -> Result<Vec<Record>, OnePassError> {
    let mut out = Vec::new();
    for kind in [
        RecordKind::Item,
        RecordKind::Manifest,
        RecordKind::VaultMeta,
        RecordKind::VaultKey,
    ] {
        out.extend(
            store
                .list(kind)?
                .into_iter()
                .filter(|r| in_vaults(vaults, r.kind, r.id, Some(&r.data))),
        );
    }
    Ok(out)
}

fn status_of(repo: &Repo) -> Result<FfiTravelStatus, OnePassError> {
    let state = open_state(repo)?;
    let hidden = repo.store().travel_hidden()?;
    Ok(FfiTravelStatus {
        active: state.is_some(),
        exiting: state.is_some() && hidden.is_empty(),
        entered_at: state.as_ref().map(|s| s.entered_at),
        hidden_count: state
            .map(|s| u32::try_from(s.parked.len()).unwrap_or(u32::MAX))
            .unwrap_or(0),
    })
}

#[uniffi::export]
impl Session {
    pub fn travel_status(&self) -> Result<FfiTravelStatus, OnePassError> {
        self.with(|repo| status_of(repo))
    }

    /// Every vault on the device and whether it would leave.
    pub fn travel_plan(&self) -> Result<Vec<FfiTravelPlanEntry>, OnePassError> {
        self.with(|repo| {
            Ok(repo
                .vaults()?
                .into_iter()
                .map(|v| FfiTravelPlanEntry {
                    vault_id: id_hex(v.id),
                    name: v.meta.name.clone(),
                    leaves: !v.meta.travel_safe,
                })
                .collect())
        })
    }

    /// Take the vaults without `travel_safe` off this device. Refused while
    /// the Travel Mode is on, or while a write of a leaving vault waits to
    /// be pushed (`InvalidInput("unsynced changes")`: sync first, the
    /// server copy is what comes back). The server copy is the store's
    /// `base`, the state the server last confirmed.
    pub fn enter_travel(&self) -> Result<FfiTravelStatus, OnePassError> {
        self.with(|repo| {
            if sealed_state(repo.store())?.is_some() {
                return Err(invalid("travel mode already on"));
            }
            let leaving: BTreeSet<Id> = repo
                .vaults()?
                .into_iter()
                .filter(|v| !v.meta.travel_safe)
                .map(|v| v.id)
                .collect();
            if leaving.is_empty() {
                return Err(invalid("no vault leaves"));
            }
            let unsynced = repo
                .store()
                .pending_changes()?
                .iter()
                .any(|c| in_vaults(&leaving, c.kind, c.id, c.data.as_deref()));
            if unsynced {
                return Err(invalid("unsynced changes"));
            }
            // A vault the server is behind on: this device keeps its own
            // verified copy (`kept`), which the server does not hold. It
            // must not leave until the sync has put that copy back.
            for id in &leaving {
                if repo
                    .store()
                    .kept_rows(*id)?
                    .is_some_and(|rows| !rows.is_empty())
                {
                    return Err(invalid("unsynced changes"));
                }
            }
            let mut upstream = MemoryStore::new();
            for r in repo.store().export_records()? {
                upstream.put(r)?;
            }
            let state = repo.enter_travel(&upstream)?;
            let sealed = repo.seal_travel_state(&state)?;
            let parked: BTreeSet<Id> = state.parked.keys().copied().collect();
            let store = repo.store_mut();
            store.set_meta(TRAVEL_STATE_KEY, &sealed)?;
            store.set_travel_hidden(&parked)?;
            // Best effort: another connection may hold the WAL.
            let _ = repo.store().compact();
            status_of(repo)
        })
    }

    /// Let the sync bring the hidden vaults back. The app then fetches from
    /// scratch and calls `finish_travel_exit`.
    pub fn begin_travel_exit(&self) -> Result<FfiTravelStatus, OnePassError> {
        self.with(|repo| {
            if open_state(repo)?.is_none() {
                return Err(invalid("travel mode off"));
            }
            repo.store_mut().set_travel_hidden(&BTreeSet::new())?;
            status_of(repo)
        })
    }

    /// Verify the vaults the fetch brought back against their parked last
    /// manifest seen. On success the Travel Mode is off. On failure (an
    /// older manifest, a dropped item, a vault the server lacks) their
    /// records leave the device again, the sync drops them again, the
    /// sealed state stays, and the core's error is returned.
    pub fn finish_travel_exit(&self) -> Result<FfiTravelStatus, OnePassError> {
        self.with(|repo| {
            let state = open_state(repo)?.ok_or_else(|| invalid("travel mode off"))?;
            let parked: BTreeSet<Id> = state.parked.keys().copied().collect();
            match repo.exit_travel(&MemoryStore::new(), &state) {
                Ok(()) => {
                    let store = repo.store_mut();
                    store.set_travel_hidden(&BTreeSet::new())?;
                    store.delete_meta(TRAVEL_STATE_KEY)?;
                    status_of(repo)
                }
                Err(e) => {
                    let records = records_of(repo.store(), &parked)?;
                    let store = repo.store_mut();
                    store.evict_all(&records)?;
                    store.set_travel_hidden(&parked)?;
                    repo.resume_travel(&state);
                    Err(e.into())
                }
            }
        })
    }
}
