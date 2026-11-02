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
//!
//! Items marked hidden in travel in vaults that stay leave the same way
//! (spec 2026-11-02): the core parks them, the sync drops their records and
//! chunks (`SyncStore::set_travel_hidden_items`), and a refused exit takes
//! what the fetch brought of them off the device again.

use std::collections::{BTreeMap, BTreeSet};

use onepass_core::Id;
use onepass_core::attachment::chunk_ids;
use onepass_core::repo::split_item_record;
use onepass_core::repo::travel::TravelState;
use onepass_core::store::{MemoryStore, Record, RecordKind, RecordStore};
use onepass_core::sync::{SyncStore, TravelHiddenItems};
use onepass_core::model::Item;
use onepass_core::vault::{ItemRecord, Vault};

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
    /// How many items of vaults that stay are off this device (spec
    /// 2026-11-02).
    #[uniffi(default = 0)]
    pub hidden_item_count: u32,
}

/// One item that Travel Mode treats on its own, in a vault that stays.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiTravelItemEntry {
    pub vault_id: String,
    pub item_id: String,
    pub title: String,
    pub vault_name: String,
}

/// The items marked for Travel Mode in vaults that stay, for the
/// confirmation sheet and Settings.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiTravelItemPlan {
    /// "Hidden in Travel Mode": they leave the device.
    pub hidden: Vec<FfiTravelItemEntry>,
    /// "Extra protection": they stay, behind password and biometrics.
    pub guarded: Vec<FfiTravelItemEntry>,
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
        k if k.is_vault_prefixed() => match data {
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
        RecordKind::Attachment,
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
    let hidden_items = repo.store().travel_hidden_items()?;
    let count = |n: usize| u32::try_from(n).unwrap_or(u32::MAX);
    let parked_items = state
        .as_ref()
        .map_or(0, |s| s.parked_items.values().map(BTreeSet::len).sum());
    let anything_parked = state
        .as_ref()
        .is_some_and(|s| !s.parked.is_empty() || parked_items > 0);
    Ok(FfiTravelStatus {
        active: state.is_some(),
        exiting: anything_parked && hidden.is_empty() && hidden_items.is_empty(),
        entered_at: state.as_ref().map(|s| s.entered_at),
        hidden_count: state.map(|s| count(s.parked.len())).unwrap_or(0),
        hidden_item_count: count(parked_items),
    })
}

/// The item records of `parked` (vault id to item ids) the store shows, and
/// the chunks of their attachments: what leaves again after a refused exit.
fn item_records_of(
    repo: &Repo,
    parked: &BTreeMap<Id, BTreeSet<Id>>,
) -> Result<Vec<Record>, OnePassError> {
    let vaults = repo.vaults()?;
    let mut out = Vec::new();
    for r in repo.store().list(RecordKind::Item)? {
        let Ok((prefix, body)) = split_item_record(&r.data) else {
            continue;
        };
        let Ok(rec) = ItemRecord::decode(body) else {
            continue;
        };
        if !parked.get(&prefix).is_some_and(|s| s.contains(&rec.item_id)) {
            continue;
        }
        if let Some(item) = vaults
            .iter()
            .find(|v| v.id == prefix)
            .and_then(|v| v.open_item(&rec).ok())
        {
            for a in &item.attachments {
                for id in chunk_ids(a).unwrap_or_default() {
                    if let Some(c) = repo.store().get(RecordKind::Attachment, id)? {
                        out.push(c);
                    }
                }
            }
        }
        out.push(r);
    }
    Ok(out)
}

/// Every item of the vaults that stay, read once: the hidden and guarded
/// ones (profile excluded).
fn marked_items(repo: &mut Repo) -> Result<Vec<(Vault, Item)>, OnePassError> {
    let mut out = Vec::new();
    for v in repo.vaults()? {
        if !v.meta.travel_safe {
            continue;
        }
        for item in repo.items(&v)? {
            if item.travel_hidden() || item.travel_guarded() {
                out.push((v.clone(), item));
            }
        }
    }
    Ok(out)
}

#[uniffi::export]
impl Session {
    /// Whether this session is in Travel Mode (entered or resumed), without
    /// opening the sealed state: cheap enough for every list refresh. Items
    /// behind extra protection are locked harder while it is true.
    pub fn travelling(&self) -> Result<bool, OnePassError> {
        self.with(|repo| Ok(repo.travelling()))
    }

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

    /// The items of vaults that stay that Travel Mode hides or guards.
    pub fn travel_item_plan(&self) -> Result<FfiTravelItemPlan, OnePassError> {
        self.with(|repo| {
            let mut plan = FfiTravelItemPlan {
                hidden: Vec::new(),
                guarded: Vec::new(),
            };
            for (v, item) in marked_items(repo)? {
                let entry = FfiTravelItemEntry {
                    vault_id: id_hex(v.id),
                    item_id: id_hex(item.id),
                    title: item.title.clone(),
                    vault_name: v.meta.name.clone(),
                };
                if item.travel_hidden() {
                    plan.hidden.push(entry);
                } else {
                    plan.guarded.push(entry);
                }
            }
            Ok(plan)
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
            // Items hidden in vaults that stay (spec 2026-11-02): their
            // vault must be pushed too, and the sync must drop their chunks.
            let marked = marked_items(repo)?;
            let hidden: Vec<_> = marked
                .iter()
                .filter(|(_, i)| i.travel_hidden() && !i.is_profile())
                .collect();
            if leaving.is_empty() && marked.is_empty() {
                return Err(invalid("nothing leaves"));
            }
            let mut checked = leaving.clone();
            checked.extend(hidden.iter().map(|(v, _)| v.id));
            let chunks: BTreeSet<Id> = hidden
                .iter()
                .flat_map(|(_, i)| i.attachments.iter())
                .flat_map(|a| chunk_ids(a).unwrap_or_default())
                .collect();
            let unsynced = repo
                .store()
                .pending_changes()?
                .iter()
                .any(|c| in_vaults(&checked, c.kind, c.id, c.data.as_deref()));
            if unsynced {
                return Err(invalid("unsynced changes"));
            }
            // A vault the server is behind on: this device keeps its own
            // verified copy (`kept`), which the server does not hold. It
            // must not leave until the sync has put that copy back.
            for id in &checked {
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
            let hidden_items = TravelHiddenItems {
                items: state.parked_items.values().flatten().copied().collect(),
                chunks,
            };
            let store = repo.store_mut();
            store.set_meta(TRAVEL_STATE_KEY, &sealed)?;
            store.set_travel_hidden(&parked)?;
            store.set_travel_hidden_items(&hidden_items)?;
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
            let store = repo.store_mut();
            store.set_travel_hidden(&BTreeSet::new())?;
            store.set_travel_hidden_items(&TravelHiddenItems::default())?;
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
                    store.set_travel_hidden_items(&TravelHiddenItems::default())?;
                    store.delete_meta(TRAVEL_STATE_KEY)?;
                    status_of(repo)
                }
                Err(e) => {
                    // Back off the device: the vaults and the items, with
                    // what the fetch brought of them.
                    repo.resume_travel(&state);
                    let items = item_records_of(repo, &state.parked_items)?;
                    let hidden_items = TravelHiddenItems {
                        items: state.parked_items.values().flatten().copied().collect(),
                        chunks: items
                            .iter()
                            .filter(|r| r.kind == RecordKind::Attachment)
                            .map(|r| r.id)
                            .collect(),
                    };
                    let mut records = records_of(repo.store(), &parked)?;
                    records.extend(items);
                    let store = repo.store_mut();
                    store.evict_all(&records)?;
                    store.set_travel_hidden(&parked)?;
                    store.set_travel_hidden_items(&hidden_items)?;
                    Err(e.into())
                }
            }
        })
    }
}
