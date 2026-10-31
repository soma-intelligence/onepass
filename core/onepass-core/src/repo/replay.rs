//! Own-write log and replay of key rotation v2 (spec 10.4, G4, R7, R11).
//!
//! Every item write of a device with a trust state first records its
//! intent in the trust state's `OwnWriteLog` (the vault, the item, the
//! manifest the write is based on, the time). Adopting a head (a follow)
//! moves those intents to the log's `replay` list with the rotation's
//! `from_heads`. The replay then brings each intent the new content does
//! not reflect into the vault under the new keys:
//!
//! - the device's own copy of the vault under the identity it left is
//!   opened with the retired keys: the vault key envelope it held
//!   (`RecordStore::retained_rows` once the rotation re-sealed it, else the
//!   visible one) under a KEM secret of the session keyset's
//!   `retired_kem`, the newest manifest it holds (pending, visible or kept)
//!   that verifies under a retired signing key (`TrustState::retired`),
//!   and the item records that manifest lists. The retired KEM secrets are
//!   part of the current keyset, sealed under the current Account Unlock
//!   Key: nothing else is kept for the replay;
//! - an intent is reflected when the rotation was made from a manifest of
//!   the vault newer than the one the write was based on and the device
//!   holds no pending manifest of that vault (spec 10.4: "based on a
//!   manifest newer than `from_heads[v]`, or still pending");
//! - an intent not reflected is applied with the merge rule of the rebase
//!   (`crate::sync::rebase`): the device's item wins over the new content's
//!   when its `updated_at` is later (a tie goes to the device), and a
//!   deletion applies when the new content's item was not changed after
//!   it. The same state on both sides writes nothing, so a replay that runs
//!   again changes nothing.
//!
//! Only this device's intents are replayed: what other devices wrote under
//! the identity left after `from_heads` is never imported (R11), they
//! replay it themselves.
//!
//! One vault is one batch (`RecordStore::batch_begin`): the vault's
//! pending writes of the identity left go (`RecordStore::settle_replayed`,
//! with its retained and kept rows), the intents are written under the new
//! keys and leave the log, all together. A vault whose new content is not
//! on the device yet (phase 2 of the rotation still on its way) waits:
//! its intents stay, and the next replay (unlock, rebase, follow) tries
//! again. Nothing of a vault is dropped before its replay commits.

use std::collections::BTreeMap;

use time::OffsetDateTime;

use super::{Repository, Use, seen, split_item_record, trust_of};
use crate::manifest::{
    Manifest, ManifestEntry, SeenManifest, SignedManifest, record_hash, signed_by, verify_manifest,
};
use crate::model::Item;
use crate::store::{Record, RecordKind, RecordStore};
use crate::trust::{DeviceLineageState, OwnWrite, TrustState};
use crate::vault::{ItemRecord, Vault};
use crate::{Error, Id, IntegrityError, Result};

/// What a replay did, intent by intent.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReplayReport {
    /// Written under the new keys.
    pub replayed: usize,
    /// Already in the new content as this device left it.
    pub present: usize,
    /// Reflected by the rotation, or overtaken by a later change in the new
    /// content: nothing written.
    pub superseded: usize,
    /// The device's own copy of the item (or of its whole vault) is gone,
    /// nothing to replay from: dropped, with the log's alert raised (the
    /// app offers "Réimporter depuis cet appareil").
    pub lost: usize,
    /// Still waiting: the vault's new content is not on the device yet, or
    /// a rotation prompt makes the session read-only.
    pub waiting: usize,
}

/// The device's own copy of a vault under the identity it left.
struct OldView {
    /// The items its newest manifest lists, by item id. Items whose record
    /// the device no longer holds are in `missing`.
    items: BTreeMap<Id, Item>,
    missing: Vec<Id>,
    /// That manifest is a pending write of this device.
    pending: bool,
}

/// Rows of `vault` among `rows` (manifests by id, items by prefix).
fn item_of(r: &Record, vault: Id) -> Option<ItemRecord> {
    let (prefix, body) = split_item_record(&r.data).ok()?;
    (prefix == vault).then(|| ItemRecord::decode(body).ok())?
}

fn exact(e: &ManifestEntry, i: &ItemRecord) -> bool {
    i.item_id == e.item_id && i.version == e.version && record_hash(i) == e.record_hash
}

impl<S: RecordStore> Repository<S> {
    /// Record the intent of an item write before it is made (spec 10.4):
    /// `item` of `vault`, based on `based_on`. A store without a trust
    /// state records nothing. The trust state is written conditionally on
    /// the one read (another writer may move it), a few times at most.
    pub(crate) fn log_own_write(&mut self, vault: Id, item: Id, based_on: &Manifest) -> Result<()> {
        let w = OwnWrite {
            vault,
            item,
            based_on: seen(based_on),
            at: OffsetDateTime::now_utc().unix_timestamp(),
        };
        for _ in 0..3 {
            let Some(trust) = trust_of(&self.store)? else {
                return Ok(());
            };
            let mut next = trust.clone();
            let needed = matches!(trust.state, DeviceLineageState::Candidate { .. });
            next.own_writes.record(w.clone(), needed);
            match self
                .store
                .put_with_trust_cas(Vec::new(), Vec::new(), None, &trust, &next)
            {
                Err(Error::Conflict) => continue,
                other => return other,
            }
        }
        Err(Error::Conflict)
    }

    /// Whether unlisted item records of `vault` that do not open under its
    /// key are left alone instead of being an integrity alert (R21: records
    /// of foreign key generations). From generation 1 on, or for a vault a
    /// rotation re-sealed that this device still reads from its own copy.
    pub(crate) fn tolerates_foreign(&self, vault: Id) -> Result<bool> {
        Ok(self.records_id != self.account.params.account_id
            || !self.store.retained_rows(vault)?.is_empty())
    }

    /// The vault as this device sealed it before a rotation re-sealed it
    /// (`retained_rows`), opened under the session's keys and authenticated
    /// by a manifest this device holds (pending, visible or kept) that
    /// verifies under the session's signing key. `None` without such rows
    /// or such a manifest.
    pub(crate) fn retained_vault(&self, vault: Id) -> Result<Option<Vault>> {
        let rows = self.store.retained_rows(vault)?;
        let row = |kind| rows.iter().find(|r| r.kind == kind);
        let (Some(key), Some(meta)) = (row(RecordKind::VaultKey), row(RecordKind::VaultMeta))
        else {
            return Ok(None);
        };
        let Ok(v) = Vault::open(&self.account, vault, &key.data, &meta.data) else {
            return Ok(None);
        };
        let signer = &self.account.params.signing_pub;
        let verifies = self.manifest_rows(vault)?.iter().any(|r| {
            SignedManifest::decode(&r.data)
                .is_ok_and(|sm| verify_manifest(&v, signer, &sm, None).is_ok())
        });
        Ok(verifies.then_some(v))
    }

    /// The session reads `vault` from its own copy: retained rows exist and
    /// the visible vault key does not open under the session's keys (a
    /// rotation this device has not followed re-sealed it).
    pub(crate) fn reads_own_copy(&self, vault: Id) -> Result<bool> {
        if self.store.retained_rows(vault)?.is_empty() {
            return Ok(false);
        }
        let key = self.store.get(RecordKind::VaultKey, vault)?;
        let meta = self.store.get(RecordKind::VaultMeta, vault)?;
        Ok(match (key, meta) {
            (Some(k), Some(m)) => Vault::open(&self.account, vault, &k.data, &m.data).is_err(),
            _ => true,
        })
    }

    /// The manifest rows of `vault` this device holds: the visible one,
    /// then the kept ones.
    fn manifest_rows(&self, vault: Id) -> Result<Vec<Record>> {
        let mut out: Vec<Record> = self
            .store
            .get(RecordKind::Manifest, vault)?
            .into_iter()
            .collect();
        for r in self.store.kept_rows(vault)?.unwrap_or_default() {
            if r.kind == RecordKind::Manifest && !out.contains(&r) {
                out.push(r);
            }
        }
        Ok(out)
    }

    /// See `OldView`. `None` when no retired key opens the vault or no
    /// manifest of the vault verifies under a retired signing key.
    fn old_view(&self, vault: Id, trust: &TrustState) -> Result<Option<OldView>> {
        let mut keys = self.store.retained_rows(vault)?;
        for kind in [RecordKind::VaultKey, RecordKind::VaultMeta] {
            keys.extend(self.store.get(kind, vault)?);
        }
        let of = |kind| keys.iter().filter(move |r| r.kind == kind);
        let mut old = None;
        'open: for key in of(RecordKind::VaultKey) {
            for meta in of(RecordKind::VaultMeta) {
                for kem in &self.account.keyset().retired_kem {
                    if let Ok(v) = Vault::open_with_kem(kem, vault, &key.data, &meta.data) {
                        old = Some(v);
                        break 'open;
                    }
                }
            }
        }
        let Some(old) = old else {
            return Ok(None);
        };
        let pending_manifest = self.store.is_pending_write(RecordKind::Manifest, vault)?;
        let visible = self.store.get(RecordKind::Manifest, vault)?;
        let mut best: Option<(Manifest, bool)> = None;
        for r in self.manifest_rows(vault)? {
            let Ok(sm) = SignedManifest::decode(&r.data) else {
                continue;
            };
            let verified = trust
                .retired
                .iter()
                .rev()
                .find_map(|ri| verify_manifest(&old, &ri.sign_pub, &sm, None).ok());
            let Some(m) = verified else {
                continue;
            };
            let pending = pending_manifest && visible.as_ref() == Some(&r);
            if best.as_ref().is_none_or(|(b, _)| m.seq > b.seq) {
                best = Some((m, pending));
            }
        }
        let Some((manifest, pending)) = best else {
            return Ok(None);
        };
        let mut held: Vec<ItemRecord> = self
            .store
            .list(RecordKind::Item)?
            .iter()
            .filter_map(|r| item_of(r, vault))
            .collect();
        for r in self.store.kept_rows(vault)?.unwrap_or_default() {
            if r.kind == RecordKind::Item
                && let Some(i) = item_of(&r, vault)
            {
                held.push(i);
            }
        }
        let mut items = BTreeMap::new();
        let mut missing = Vec::new();
        for e in &manifest.entries {
            match held
                .iter()
                .find(|i| exact(e, i))
                .and_then(|i| old.open_item(i).ok())
            {
                Some(item) => {
                    items.insert(e.item_id, item);
                }
                None => missing.push(e.item_id),
            }
        }
        Ok(Some(OldView {
            items,
            missing,
            pending,
        }))
    }

    /// The vault as the session's identity sealed it (visible key and meta
    /// open under its keys), or `None` while it is not on the device.
    fn current_vault(&self, vault: Id) -> Result<Option<Vault>> {
        let key = self.store.get(RecordKind::VaultKey, vault)?;
        let meta = self.store.get(RecordKind::VaultMeta, vault)?;
        let (Some(k), Some(m)) = (key, meta) else {
            return Ok(None);
        };
        match Vault::open(&self.account, vault, &k.data, &m.data) {
            Ok(v) => Ok(Some(v)),
            Err(Error::Integrity(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Replay this device's own writes of the identity it left under the
    /// keys it follows now (see the module doc). Nothing to do without a
    /// trust state or intents waiting; outside `Current`, or while a
    /// rotation prompt makes the session read-only, every intent waits.
    pub fn replay_own_writes(&mut self) -> Result<ReplayReport> {
        let mut report = ReplayReport::default();
        let Some(trust) = trust_of(&self.store)? else {
            return Ok(report);
        };
        let mut vaults = trust.own_writes.replay_vaults();
        self.drop_left_copies(&vaults)?;
        if !trust.retired.is_empty() {
            vaults.extend(self.left_signed_vaults()?);
        }
        if vaults.is_empty() {
            return Ok(report);
        }
        let ready = trust.state == DeviceLineageState::Current
            && match self.writable() {
                Ok(()) => true,
                Err(Error::ReadOnly) => false,
                Err(e) => return Err(e),
            };
        if !ready {
            report.waiting = trust.own_writes.replay.len();
            return Ok(report);
        }
        let heads = trust.own_writes.replay_heads.clone();
        for vault in vaults {
            let intents: Vec<OwnWrite> = trust
                .own_writes
                .replay
                .iter()
                .filter(|w| w.vault == vault)
                .cloned()
                .collect();
            let Some(current) = self.current_vault(vault)? else {
                report.waiting += intents.len();
                continue;
            };
            let Some(old) = self.old_view(vault, &trust)? else {
                // The new content is here, the device's own copy is not
                // (nothing retained it): nothing to replay from.
                report.lost += intents.len();
                self.store.settle_replayed(vault)?;
                self.forget_replayed(vault, !intents.is_empty())?;
                continue;
            };
            let last_seen = self.device.last_seen.get(&vault).cloned();
            self.store.batch_begin()?;
            let done = self
                .replay_vault(&current, &old, &intents, heads.get(&vault))
                .and_then(|r| {
                    self.forget_replayed(vault, r.lost > 0)?;
                    self.store.batch_commit()?;
                    Ok(r)
                });
            match done {
                Ok(r) => {
                    report.replayed += r.replayed;
                    report.present += r.present;
                    report.superseded += r.superseded;
                    report.lost += r.lost;
                }
                Err(e) => {
                    let _ = self.store.batch_rollback();
                    match last_seen {
                        Some(s) => self.device.last_seen.insert(vault, s),
                        None => self.device.last_seen.remove(&vault),
                    };
                    return Err(e);
                }
            }
        }
        Ok(report)
    }

    /// The vaults whose pending manifest the session's identity did not
    /// sign: written under an identity this device left, before it
    /// followed (the store never pushes them, `SyncStore::pending_changes`).
    /// Their pending rows go once their new content is here, replayed or
    /// not (a vault created or renamed there carries no item intent).
    pub(crate) fn left_signed_vaults(&self) -> Result<std::collections::BTreeSet<Id>> {
        let signer = &self.account.params.signing_pub;
        let mut out = std::collections::BTreeSet::new();
        for key in self.store.list(RecordKind::VaultKey)? {
            if !self.store.is_pending_write(RecordKind::Manifest, key.id)? {
                continue;
            }
            let ours = self
                .store
                .get(RecordKind::Manifest, key.id)?
                .is_some_and(|r| {
                    SignedManifest::decode(&r.data).is_ok_and(|sm| signed_by(&sm, signer))
                });
            if !ours {
                out.insert(key.id);
            }
        }
        Ok(out)
    }

    /// Drop the retained copies of an identity this device left (they no
    /// longer open under the session's keys) for every vault but `keep`
    /// (intents still to replay from them). Pending rows are left alone:
    /// they may be the session's own.
    fn drop_left_copies(&mut self, keep: &std::collections::BTreeSet<Id>) -> Result<()> {
        for key in self.store.list(RecordKind::VaultKey)? {
            if keep.contains(&key.id) {
                continue;
            }
            let rows = self.store.retained_rows(key.id)?;
            let row = |kind| rows.iter().find(|r| r.kind == kind);
            let opens = match (row(RecordKind::VaultKey), row(RecordKind::VaultMeta)) {
                (None, None) => continue,
                (Some(k), Some(m)) => Vault::open(&self.account, key.id, &k.data, &m.data).is_ok(),
                _ => false,
            };
            if !opens {
                self.store.drop_retained(key.id)?;
            }
        }
        Ok(())
    }

    /// One vault's replay, inside the open batch.
    fn replay_vault(
        &mut self,
        vault: &Vault,
        old: &OldView,
        intents: &[OwnWrite],
        head: Option<&SeenManifest>,
    ) -> Result<ReplayReport> {
        let mut r = ReplayReport::default();
        self.store.settle_replayed(vault.id)?;
        let loaded = self.served(vault, Use::Write)?;
        let mut saves = Vec::new();
        let mut deletes = Vec::new();
        for w in intents {
            if old.missing.contains(&w.item) {
                r.lost += 1;
                continue;
            }
            let mine = old.items.get(&w.item);
            let theirs = match loaded.listed(w.item) {
                Some((_, rec)) => Some(vault.open_item(rec)?),
                None => None,
            };
            if mine == theirs.as_ref() {
                r.present += 1;
                continue;
            }
            let reflected = !old.pending && head.is_some_and(|h| w.based_on.seq < h.seq);
            if reflected {
                r.superseded += 1;
                continue;
            }
            match (mine, theirs) {
                (Some(m), None) => saves.push(m.clone()),
                (Some(m), Some(t)) if m.updated_at >= t.updated_at => saves.push(m.clone()),
                (None, Some(t)) if t.updated_at.unix_timestamp() <= w.at => deletes.push(w.item),
                _ => {
                    r.superseded += 1;
                    continue;
                }
            }
            r.replayed += 1;
        }
        for item in saves {
            self.save_item(vault, item)?;
        }
        for id in deletes {
            self.delete_item(vault, id)?;
        }
        Ok(r)
    }

    /// The intents of `vault` leave the replay list (conditionally on the
    /// trust state read, a few times at most); `lost`: some could not be
    /// replayed, the log's alert is raised.
    fn forget_replayed(&mut self, vault: Id, lost: bool) -> Result<()> {
        for _ in 0..3 {
            let trust = trust_of(&self.store)?.ok_or(IntegrityError::WrongContext)?;
            let mut next = trust.clone();
            next.own_writes.replay.retain(|w| w.vault != vault);
            if next.own_writes.replay.is_empty() {
                next.own_writes.replay_heads.clear();
            }
            next.own_writes.alert |= lost;
            match self
                .store
                .put_with_trust_cas(Vec::new(), Vec::new(), None, &trust, &next)
            {
                Err(Error::Conflict) => continue,
                other => return other,
            }
        }
        Err(Error::Conflict)
    }
}
