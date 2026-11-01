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
//!   `retired_kem`. Each intent names what this device wrote
//!   (`OwnWrite::wrote`: the hash of its own item record, or of its sealed
//!   meta for a meta intent, `None` for a deletion), and only that very
//!   record is replayed, found among the rows the device holds (visible,
//!   pending, kept, retained). What another device wrote over it under the
//!   identity left (the revoked device can) is never taken (R11); a record
//!   the device no longer holds is `lost` and raises the log's alert. The
//!   retired KEM secrets are part of the current keyset, sealed under the
//!   current Account Unlock Key. After a switch (Task 11) the identity left
//!   is not among them: `follow_switch` wraps the vault key of the own copy
//!   again for the session's KEM key and keeps it in the retained rows,
//!   which the session's own KEM secret then opens;
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
//! A vault of the identity left that the head's rotation did not re-seal
//! (created there after `from_heads`) is re-created under the session's
//! keys, with this device's own items (Task 11).
//!
//! One vault is one batch (`RecordStore::batch_begin`): the vault's
//! pending writes of the identity left go (`RecordStore::settle_replayed`,
//! with its retained and kept rows), the intents are written under the new
//! keys and leave the log, all together. A vault whose new content is not
//! on the device yet (phase 2 of the rotation still on its way) waits:
//! its intents stay, and the next replay (unlock, rebase, follow) tries
//! again. Nothing of a vault is dropped before its replay commits.

use std::collections::BTreeSet;

use aws_lc_rs::digest::{SHA256, digest};
use time::OffsetDateTime;

use super::{Repository, Use, seen, split_item_record, trust_of};
use crate::crypto::unwrap_key;
use crate::lineage::{recreated_vault_id, recreated_vault_key};
use crate::manifest::{
    Manifest, SeenManifest, SignedManifest, record_hash, signed_by, verify_manifest,
};
use crate::model::Item;
use crate::store::{Record, RecordKind, RecordStore};
use crate::trust::{DeviceLineageState, OwnWrite};
use crate::vault::{ItemRecord, Vault, VaultMeta, kem_context};
use crate::vaultlist::VaultListEntry;
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
    /// The (vault, item) of each `lost` intent, also kept in the log
    /// (`OwnWriteLog::lost`) until the user saw them (Task 17, G4).
    pub lost_items: Vec<(Id, Id)>,
    /// Still waiting: the vault's new content is not on the device yet, or
    /// a rotation prompt makes the session read-only.
    pub waiting: usize,
}

/// The device's own copy of a vault under the identity it left: the old
/// vault (key and meta opened with a retired KEM secret), every item record
/// and meta row of the vault it still holds (visible, pending, kept,
/// retained), and whether it holds a pending manifest of that identity.
struct OldView {
    /// Every copy that opens: its vault key row, the index of the KEM
    /// secret that opens it, the vault. Since the retained rows keep one
    /// copy per identity (Task 19 carried item 3) there may be several,
    /// and each intent's record opens under the one it was sealed with.
    opened: Vec<(Record, usize, Vault)>,
    items: Vec<ItemRecord>,
    metas: Vec<Record>,
    pending: bool,
}

/// The item record of `vault` in `r`, if it is one.
fn item_of(r: &Record, vault: Id) -> Option<ItemRecord> {
    let (prefix, body) = split_item_record(&r.data).ok()?;
    (prefix == vault).then(|| ItemRecord::decode(body).ok())?
}

/// The meta of a re-created vault when this device logged none of its own.
/// A rebase that joins another device's creation tells it from an own meta
/// by this value (`Repository::rebase_report`, fix round 2 of Task 19).
pub(crate) fn recovered_meta() -> VaultMeta {
    VaultMeta {
        name: "Coffre récupéré".into(),
        icon: "tray".into(),
        color: "gray".into(),
        travel_safe: false,
        mcp_access: false,
    }
}

/// What a meta intent records of the sealed meta it wrote (`OwnWrite::wrote`).
pub(crate) fn meta_hash(sealed: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(digest(&SHA256, sealed).as_ref());
    out
}

impl ReplayReport {
    fn lose(&mut self, vault: Id, item: Id) {
        self.lost += 1;
        self.lost_items.push((vault, item));
    }

    fn add(&mut self, r: ReplayReport) {
        self.replayed += r.replayed;
        self.present += r.present;
        self.superseded += r.superseded;
        self.lost += r.lost;
        self.lost_items.extend(r.lost_items);
        self.waiting += r.waiting;
    }
}

/// The own-write alert of a device (spec 10.4, G4, Task 17): raised when
/// an intent was dropped by the log's bounds or found no copy to replay
/// from; `lost` names them, (vault, item).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OwnWriteAlert {
    pub alert: bool,
    pub lost: Vec<(Id, Id)>,
}

impl<S: RecordStore> Repository<S> {
    /// The own-write alert (`OwnWriteAlert`). Nothing without a trust
    /// state.
    pub fn own_write_alert(&self) -> Result<OwnWriteAlert> {
        Ok(
            trust_of(&self.store)?.map_or_else(OwnWriteAlert::default, |t| OwnWriteAlert {
                alert: t.own_writes.alert,
                lost: t.own_writes.lost,
            }),
        )
    }

    /// The user saw the own-write alert: lowered, the lost intents
    /// forgotten. Conditional on the trust state read (`Conflict`). A no-op
    /// without a trust state or an alert.
    pub fn clear_own_write_alert(&mut self) -> Result<()> {
        let Some(trust) = trust_of(&self.store)? else {
            return Ok(());
        };
        if !trust.own_writes.alert && trust.own_writes.lost.is_empty() {
            return Ok(());
        }
        let mut next = trust.clone();
        next.own_writes.clear_alert();
        self.store
            .put_with_trust_cas(Vec::new(), Vec::new(), None, &trust, &next)
    }

    /// Record the intent of an item write before it is made (spec 10.4):
    /// `item` of `vault`, based on `based_on`, writing the record whose
    /// hash is `wrote` (`None`: a deletion). A store without a trust
    /// state records nothing. The trust state is written conditionally on
    /// the one read (another writer may move it), a few times at most.
    pub(crate) fn log_own_write(
        &mut self,
        vault: Id,
        item: Id,
        based_on: &Manifest,
        wrote: Option<[u8; 32]>,
    ) -> Result<()> {
        self.log_own_write_seen(vault, item, seen(based_on), wrote)
    }

    /// `log_own_write` with the manifest the write is based on as seen.
    pub(crate) fn log_own_write_seen(
        &mut self,
        vault: Id,
        item: Id,
        based_on: SeenManifest,
        wrote: Option<[u8; 32]>,
    ) -> Result<()> {
        let w = OwnWrite {
            vault,
            item,
            based_on,
            at: OffsetDateTime::now_utc().unix_timestamp(),
            wrote,
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

    /// Whether this device knows a valid rotation of its head that it has
    /// not followed: it waits on a prompt (`Candidate`, or found by this
    /// session, or found now in what a fetch brought), one locks it
    /// (`Quarantined`, `Orphaned`, Task 12), or the user rejected a child
    /// of its head (`ignored`). Only then is a vault key the server
    /// replaced read from the device's own copy; otherwise a vault key that
    /// does not open stays an integrity error (review I3).
    ///
    /// Task 11: `ignored` keeps every record the user rejected (the
    /// resolver must go on ignoring them, siblings included), so only a
    /// rejected record whose parent is still the head keeps the gate open;
    /// once the device moved on (followed, switched or rotated), it closes.
    pub(crate) fn rotation_known(&self) -> Result<bool> {
        let Some(t) = trust_of(&self.store)? else {
            return Ok(false);
        };
        if self.pending.is_some()
            || self.lineage_lock.is_some()
            || matches!(
                t.state,
                DeviceLineageState::Candidate { .. }
                    | DeviceLineageState::Quarantined { .. }
                    | DeviceLineageState::Orphaned { .. }
            )
        {
            return Ok(true);
        }
        if !t.ignored.is_empty() {
            let records = super::follow::lineage_records(&self.store)?;
            let rejected_child = super::follow::rotations(&records)
                .iter()
                .any(|(h, b)| b.parent == t.head.hash && t.ignored.contains(h));
            if rejected_child {
                return Ok(true);
            }
        }
        // A fetch brought one that no write looked at yet.
        let look = super::follow::look_for(&self.store, &t)?;
        Ok(look.prompt.is_some() || look.lock.is_some())
    }

    /// Whether unlisted item records of `vault` that do not open under its
    /// key are left alone instead of being an integrity alert (R21: records
    /// of foreign key generations). From generation 1 on, or for a vault a
    /// known rotation re-sealed that this device still reads from its own
    /// copy.
    pub(crate) fn tolerates_foreign(&self, vault: Id) -> Result<bool> {
        Ok(self.records_id != self.account.params.account_id
            || (!self.store.retained_rows(vault)?.is_empty() && self.rotation_known()?))
    }

    /// The vault as this device sealed it before a rotation re-sealed it
    /// (`retained_rows`), opened under the session's keys and authenticated
    /// by a manifest this device holds (pending, visible or kept) that
    /// verifies under the session's signing key. `None` without such rows
    /// or such a manifest, or without a known rotation (`rotation_known`).
    pub(crate) fn retained_vault(&self, vault: Id) -> Result<Option<Vault>> {
        if !self.rotation_known()? {
            return Ok(None);
        }
        let rows = self.store.retained_rows(vault)?;
        let manifests = self.manifest_rows(vault)?;
        let signer = &self.account.params.signing_pub;
        // One copy per identity this device was on (Task 19 carried item
        // 3): the one that opens under the session's keys and that a
        // manifest it holds authenticates.
        let of = |kind| rows.iter().filter(move |r: &&Record| r.kind == kind);
        for key in of(RecordKind::VaultKey) {
            for meta in of(RecordKind::VaultMeta) {
                let Ok(v) = Vault::open(&self.account, vault, &key.data, &meta.data) else {
                    continue;
                };
                let verifies = manifests.iter().any(|r| {
                    SignedManifest::decode(&r.data)
                        .is_ok_and(|sm| verify_manifest(&v, signer, &sm, None).is_ok())
                });
                if verifies {
                    return Ok(Some(v));
                }
            }
        }
        Ok(None)
    }

    /// The session reads `vault` from its own copy: a rotation is known
    /// (`rotation_known`), retained rows exist and the visible vault key
    /// does not open under the session's keys (a
    /// rotation this device has not followed re-sealed it).
    pub(crate) fn reads_own_copy(&self, vault: Id) -> Result<bool> {
        if self.store.retained_rows(vault)?.is_empty() || !self.rotation_known()? {
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

    /// See `OldView`. `None` when no retired KEM secret opens the vault.
    fn old_view(&self, vault: Id) -> Result<Option<OldView>> {
        let mut rows = self.store.retained_rows(vault)?;
        for kind in [RecordKind::VaultKey, RecordKind::VaultMeta] {
            rows.extend(self.store.get(kind, vault)?);
        }
        let of = |kind| rows.iter().filter(move |r| r.kind == kind);
        // The retired KEM secrets, then the session's own: a switch wraps
        // the device's own copy again for the identity it follows
        // (`crate::repo::follow`). The retained rows come first, so the
        // visible key of the new content is tried last.
        let keyset = self.account.keyset();
        let secrets: Vec<_> = keyset
            .retired_kem
            .iter()
            .chain(std::iter::once(&keyset.kem))
            .collect();
        let mut opened: Vec<(Record, usize, Vault)> = Vec::new();
        for key in of(RecordKind::VaultKey) {
            if opened.iter().any(|(k, _, _)| k.data == key.data) {
                continue;
            }
            'key: for meta in of(RecordKind::VaultMeta) {
                for (kem, secret) in secrets.iter().enumerate() {
                    if let Ok(v) = Vault::open_with_kem(secret, vault, &key.data, &meta.data) {
                        opened.push((key.clone(), kem, v));
                        break 'key;
                    }
                }
            }
        }
        if opened.is_empty() {
            return Ok(None);
        }
        let metas = of(RecordKind::VaultMeta).cloned().collect();
        let mut items: Vec<ItemRecord> = self
            .store
            .list(RecordKind::Item)?
            .iter()
            .filter_map(|r| item_of(r, vault))
            .collect();
        for r in self.store.kept_rows(vault)?.unwrap_or_default() {
            if r.kind == RecordKind::Item
                && let Some(i) = item_of(&r, vault)
            {
                items.push(i);
            }
        }
        let pending = self.left_signed_vaults()?.contains(&vault);
        Ok(Some(OldView {
            opened,
            items,
            metas,
            pending,
        }))
    }

    /// The item this device itself wrote for `w` (the record whose hash it
    /// logged), opened under the old vault key: `Ok(None)` for a deletion,
    /// `Err(())` when the device no longer holds that record.
    fn own_item(old: &OldView, w: &OwnWrite) -> std::result::Result<Option<Item>, ()> {
        let Some(h) = w.wrote else {
            return Ok(None);
        };
        old.items
            .iter()
            .find(|i| i.item_id == w.item && record_hash(i) == h)
            .and_then(|i| old.opened.iter().find_map(|(_, _, v)| v.open_item(i).ok()))
            .map(Some)
            .ok_or(())
    }

    /// The meta this device itself wrote for the meta intent `w`, opened
    /// under the old vault key, or `None` when it no longer holds it.
    fn own_meta(&self, old: &OldView, w: &OwnWrite) -> Option<VaultMeta> {
        let h = w.wrote?;
        let row = old.metas.iter().find(|m| meta_hash(&m.data) == h)?;
        let keyset = self.account.keyset();
        old.opened.iter().find_map(|(key, kem, _)| {
            let kem = keyset
                .retired_kem
                .get(*kem)
                .or_else(|| (*kem == keyset.retired_kem.len()).then_some(&keyset.kem))?;
            Vault::open_with_kem(kem, w.vault, &key.data, &row.data)
                .ok()
                .map(|v| v.meta)
        })
    }

    /// Whether the visible vault key of `vault` opens under the session's
    /// KEM key.
    fn key_opens(&self, vault: Id) -> Result<bool> {
        Ok(self
            .store
            .get(RecordKind::VaultKey, vault)?
            .is_some_and(|k| {
                unwrap_key(&self.account.keyset().kem, &k.data, &kem_context(vault)).is_ok()
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
            // The new content is here once the visible vault key opens
            // under the session's keys (its meta may still be shadowed by a
            // pending meta of the identity left, which the replay settles).
            if !self.key_opens(vault)? {
                if self.recreates(vault, &trust)? {
                    report.add(self.recreate_vault(vault, &intents)?);
                } else {
                    report.waiting += intents.len();
                }
                continue;
            }
            let old = self.old_view(vault)?;
            let last_seen = self.device.last_seen.get(&vault).cloned();
            self.store.batch_begin()?;
            let done = match &old {
                Some(old) => self.replay_vault(vault, old, &intents, heads.get(&vault)),
                // The new content is here, the device's own copy is not
                // (nothing retained it): nothing to replay from.
                None => self.store.settle_replayed(vault).map(|()| {
                    let mut r = ReplayReport::default();
                    for w in &intents {
                        r.lose(vault, w.item);
                    }
                    r
                }),
            }
            .and_then(|r| {
                self.forget_replayed(vault, &r.lost_items)?;
                self.store.batch_commit()?;
                Ok(r)
            });
            match done {
                Ok(r) => report.add(r),
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

    /// Whether `vault`, whose visible key does not open under the session's
    /// keys, is one no rotation will bring under them: a vault of an
    /// identity this device left (its own copy opens with a retired KEM
    /// secret) that the head's rotation did not re-seal (not in its
    /// `from_heads`) and that the session's verified vault list does not
    /// list live. It was created there after the rotation's `from_heads`
    /// (review I1 of Task 10): it is re-created under the session's keys.
    fn recreates(&self, vault: Id, trust: &crate::trust::TrustState) -> Result<bool> {
        if trust.retired.is_empty() {
            return Ok(false);
        }
        let records = super::follow::lineage_records(&self.store)?;
        let bodies = super::follow::rotations(&records);
        let Some(head) = bodies.get(&trust.head.hash) else {
            return Ok(false);
        };
        if head.from_heads.contains_key(&vault) {
            return Ok(false);
        }
        let listed = self
            .read_list::<VaultListEntry>()?
            .is_some_and(|l| l.body.entries.iter().any(|e| e.vault_id == vault));
        if listed {
            return Ok(false);
        }
        Ok(self.old_view(vault)?.is_some())
    }

    /// Re-create `vault` (see `recreates`) under the session's keys: a new
    /// vault, its meta as this device last wrote it (or as its own copy
    /// holds it), and this device's own items of it, each from the very
    /// record it wrote (R11). The old vault is left as it is on the server
    /// (a foreign generation, ignored); its pending rows go. One batch.
    fn recreate_vault(&mut self, vault: Id, intents: &[OwnWrite]) -> Result<ReplayReport> {
        let mut r = ReplayReport::default();
        let Some(old) = self.old_view(vault)? else {
            return Ok(r);
        };
        // Review M4 (Task 11): this device's own meta (a creation or a
        // change it logged), never one another device wrote there (R11);
        // without one, a neutral meta.
        let mut own_meta = None;
        for w in intents.iter().filter(|w| w.item == w.vault) {
            match self.own_meta(&old, w) {
                Some(m) => own_meta = Some(m),
                None => r.lose(vault, w.item),
            }
        }
        let mut items = Vec::new();
        for w in intents.iter().filter(|w| w.item != w.vault) {
            match Self::own_item(&old, w) {
                Ok(Some(item)) => items.push(item),
                // A deletion in a vault that starts empty: nothing to do.
                Ok(None) => r.superseded += 1,
                Err(()) => r.lose(vault, w.item),
            }
        }
        // Task 19 carried item 2: one id per (identity, old vault), so a
        // device that replays after another one did joins the vault that
        // one re-created, under the same merge rule as a replay.
        //
        // Review I3 (fix round 1): the id is predictable, so a server can
        // plant rows there. Only a vault that opens under the session's
        // keys and loads through the verified path (a manifest this
        // identity signed) is joined; any other row at that id, a key or a
        // meta alone, or one that does not verify, sends the re-creation to
        // a fresh random id instead of wedging the replay.
        let id = recreated_vault_id(&self.account.params.identity_pub, vault);
        let key = recreated_vault_key(&self.account.keyset().kem.to_bytes(), vault)?;
        let joined = match self.current_vault(id)? {
            Some(existing)
                if existing.has_key(&key) && self.served(&existing, Use::Write).is_ok() =>
            {
                Some(existing)
            }
            _ => None,
        };
        let planted = joined.is_none()
            && (self.store.get(RecordKind::VaultKey, id)?.is_some()
                || self.store.get(RecordKind::VaultMeta, id)?.is_some()
                || self.store.get(RecordKind::Manifest, id)?.is_some());
        let (id, key) = if planted {
            (Id::new(), None)
        } else {
            (id, Some(key))
        };
        self.store.batch_begin()?;
        let done = (|| {
            let fresh = match (joined, own_meta) {
                (Some(existing), Some(m)) if m != existing.meta => {
                    self.update_vault_meta(&existing, m)?
                }
                (Some(existing), _) => existing,
                (None, m) => {
                    self.create_vault_with_id(id, key, m.unwrap_or_else(recovered_meta))?
                }
            };
            let loaded = self.served(&fresh, Use::Write)?;
            for mut item in items {
                item.vault_id = fresh.id;
                if let Some((_, rec)) = loaded.listed(item.id) {
                    let theirs = fresh.open_item(rec)?;
                    if theirs == item {
                        r.present += 1;
                        continue;
                    }
                    if theirs.updated_at > item.updated_at {
                        r.superseded += 1;
                        continue;
                    }
                }
                self.save_item(&fresh, item)?;
                r.replayed += 1;
            }
            self.store.settle_replayed(vault)?;
            self.forget_replayed(vault, &r.lost_items)?;
            self.store.batch_commit()?;
            self.forget_vault(vault);
            Ok(r)
        })();
        if done.is_err() {
            let _ = self.store.batch_rollback();
        }
        done
    }

    /// The vaults whose pending manifest the session's identity did not
    /// sign: written under an identity this device left, before it
    /// followed (the store never pushes them, `SyncStore::pending_changes`).
    /// Their pending rows go once their new content is here, replayed or
    /// not (a vault created or renamed there carries no item intent).
    pub(crate) fn left_signed_vaults(&self) -> Result<BTreeSet<Id>> {
        let signer = &self.account.params.signing_pub;
        let mut out = BTreeSet::new();
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
    fn drop_left_copies(&mut self, keep: &BTreeSet<Id>) -> Result<()> {
        for key in self.store.list(RecordKind::VaultKey)? {
            if keep.contains(&key.id) {
                continue;
            }
            let rows = self.store.retained_rows(key.id)?;
            if rows.is_empty() {
                continue;
            }
            let of = |kind| rows.iter().filter(move |r: &&Record| r.kind == kind);
            let opens = of(RecordKind::VaultKey).any(|k| {
                of(RecordKind::VaultMeta)
                    .any(|m| Vault::open(&self.account, key.id, &k.data, &m.data).is_ok())
            });
            if !opens {
                self.store.drop_retained(key.id)?;
            }
        }
        Ok(())
    }

    /// One vault's replay, inside the open batch. The meta first (its
    /// manifest carries it), then the items, each from the very record this
    /// device wrote (R11: what another device wrote over it under the
    /// identity left is never taken).
    fn replay_vault(
        &mut self,
        vault: Id,
        old: &OldView,
        intents: &[OwnWrite],
        head: Option<&SeenManifest>,
    ) -> Result<ReplayReport> {
        let mut r = ReplayReport::default();
        self.store.settle_replayed(vault)?;
        let reflected = |w: &OwnWrite| !old.pending && head.is_some_and(|h| w.based_on.seq < h.seq);
        let mut current = self.current_vault(vault)?.ok_or(Error::NotFound)?;
        for w in intents.iter().filter(|w| w.item == w.vault) {
            let Some(meta) = self.own_meta(old, w) else {
                if reflected(w) {
                    r.superseded += 1;
                } else {
                    r.lose(vault, w.item);
                }
                continue;
            };
            if meta == current.meta {
                r.present += 1;
            } else if reflected(w) {
                r.superseded += 1;
            } else {
                current = self.update_vault_meta(&current, meta)?;
                r.replayed += 1;
            }
        }
        let loaded = self.served(&current, Use::Write)?;
        let mut saves = Vec::new();
        let mut deletes = Vec::new();
        for w in intents.iter().filter(|w| w.item != w.vault) {
            let theirs = match loaded.listed(w.item) {
                Some((_, rec)) => Some(current.open_item(rec)?),
                None => None,
            };
            let Ok(mine) = Self::own_item(old, w) else {
                // Reflected by the rotation: its record is no longer needed
                // (a phase 3 may have collected it).
                if reflected(w) {
                    r.superseded += 1;
                } else {
                    r.lose(vault, w.item);
                }
                continue;
            };
            if mine == theirs {
                r.present += 1;
                continue;
            }
            if reflected(w) {
                r.superseded += 1;
                continue;
            }
            // The merge rule of the rebase, ties to this device (it has no
            // record hash to compare with: its record is of other keys).
            match (mine, theirs) {
                (Some(m), None) => saves.push(m),
                (Some(m), Some(t)) if m.updated_at >= t.updated_at => saves.push(m),
                (None, Some(t)) if t.updated_at.unix_timestamp() <= w.at => deletes.push(w.item),
                _ => {
                    r.superseded += 1;
                    continue;
                }
            }
            r.replayed += 1;
        }
        for item in saves {
            self.save_item(&current, item)?;
        }
        for id in deletes {
            self.delete_item(&current, id)?;
        }
        Ok(r)
    }

    /// The intents of `vault` leave the replay list (conditionally on the
    /// trust state read, a few times at most); `lost`: the ones that could
    /// not be replayed, named in the log, its alert raised (Task 17: they
    /// stay named after the intents go).
    fn forget_replayed(&mut self, vault: Id, lost: &[(Id, Id)]) -> Result<()> {
        for _ in 0..3 {
            let trust = trust_of(&self.store)?.ok_or(IntegrityError::WrongContext)?;
            let mut next = trust.clone();
            next.own_writes.replay.retain(|w| w.vault != vault);
            if next.own_writes.replay.is_empty() {
                next.own_writes.replay_heads.clear();
            }
            for (v, item) in lost {
                next.own_writes.lose(*v, *item);
            }
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
