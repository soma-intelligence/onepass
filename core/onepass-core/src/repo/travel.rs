//! Travel Mode: the vaults without `travel_safe` leave the device and come
//! back verified.
//!
//! Entering checks every vault to hide through the verified path (`load`,
//! with the last manifest seen) and checks that the upstream holds byte for
//! byte each record that verified state is made of (key, meta, manifest and
//! the item records the manifest lists), for all vaults, before deleting
//! anything: the Travel Mode never deletes the only copy. Records the
//! upstream holds beyond those (older versions or deleted items left by a
//! put-only push) are ignored. The last manifest seen of each
//! hidden vault moves from the device state into a `TravelState`, sealed to
//! the account.
//!
//! Leaving copies the records back from the upstream, which is not trusted:
//! the key, meta and manifest, and only the item records whose item id and
//! version the upstream manifest lists (it is decoded to choose, not
//! trusted; upstream orphans are never copied). It then puts the parked last
//! seen back into the device state, and loads the
//! vaults through `vaults()` then `items()`, exactly as in normal use: a
//! replayed manifest or a dropped item is refused. On failure the copied
//! records are deleted and the device state is restored, so the
//! `TravelState` stays valid.
//!
//! Neither direction touches the account (params, keyset), the signed
//! device and vault lists or the `travel_safe` vaults. The vault list still
//! lists the hidden vaults as live: the repository remembers them as parked
//! (in memory), so `vaults()` does not expect them. A later session on a
//! travelling device must call `resume_travel` with the `TravelState`;
//! otherwise `vaults()` reports them missing (`VaultMissing`), it never
//! silently accepts their absence.
//!
//! Records of a vault: `VaultKey`, `VaultMeta` and `Manifest` with id = the
//! vault id, and the `Item` and `Attachment` records whose prefix
//! (`split_item_record`) is the vault id.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use super::{Repository, seen, split_item_record};
use crate::crypto::{
    Aad, BlobKind, HybridSignature, SymmetricKey, open, seal, unwrap_key, wrap_key,
};
use crate::manifest::SeenManifest;
use crate::manifest::{ManifestEntry, SignedManifest, record_hash, verify_manifest};
use crate::store::{Record, RecordKind, RecordStore};
use crate::vault::{ItemRecord, Vault};
use crate::{Error, Id, IntegrityError, Result};

/// Length of a sealed `TravelState`, padding included: fixed, so the file
/// does not reveal how many vaults are hidden.
pub const SEALED_TRAVEL_STATE_LEN: usize = 65536;

/// Local signature domain of a sealed state (`sign_local` adds `local:`).
const SIG_DOMAIN: &[u8] = b"travel-state";
/// KEM context prefix, followed by the account id.
const KEM_CONTEXT: &[u8] = b"travel:";
/// Schema of a sealed state: 2 adds `parked_items`. Schema 1 still opens.
const SCHEMA: u16 = 2;
const SCHEMA_V1: u16 = 1;
const LEN_PREFIX: usize = 4;

const BAD: Error = Error::InvalidFormat("travel state");
const UPSTREAM_MISMATCH: Error = Error::InvalidFormat("upstream does not hold the vault");

/// The vaults parked by `enter_travel`, with the last manifest seen of
/// each, and when the Travel Mode was entered (Unix seconds).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TravelState {
    pub parked: BTreeMap<Id, SeenManifest>,
    pub entered_at: i64,
    /// Items marked `travel_hidden` parked from vaults that stay: vault id
    /// to item ids (schema 2; empty in a schema 1 state). Their manifest
    /// entries stay in the vault's manifest, pinned by `last_seen`.
    pub parked_items: BTreeMap<Id, BTreeSet<Id>>,
}

/// A schema 1 state, before parked items.
#[derive(Serialize, Deserialize)]
struct TravelStateV1 {
    parked: BTreeMap<Id, SeenManifest>,
    entered_at: i64,
}

/// A vault to bring back: its parked last manifest seen, if any, and
/// whether its records are copied from the upstream (false: already local).
struct Restore {
    id: Id,
    parked: Option<SeenManifest>,
    copy: bool,
}

/// The vault kinds keyed by the vault id, in deletion order: the key first,
/// so a vault cut halfway is no longer listed.
const VAULT_KINDS: [RecordKind; 3] = [
    RecordKind::VaultKey,
    RecordKind::VaultMeta,
    RecordKind::Manifest,
];

/// The item records of `records` whose prefix is `vault`. Records too short
/// for a prefix belong to no vault and are skipped.
fn items_of(records: &[Record], vault: Id) -> impl Iterator<Item = &Record> {
    records
        .iter()
        .filter(move |r| split_item_record(&r.data).is_ok_and(|(p, _)| p == vault))
}

fn same(a: &Record, b: &Record) -> bool {
    a.version == b.version && a.data == b.data
}

/// KEM context of the Travel state key: `"travel:" || account_id` (23
/// bytes).
pub(crate) fn kem_context(account_id: Id) -> Vec<u8> {
    let mut c = KEM_CONTEXT.to_vec();
    c.extend_from_slice(&account_id.0);
    c
}

fn state_aad(account_id: Id, schema: u16) -> Aad {
    Aad {
        blob_id: account_id,
        vault_id: None,
        schema,
    }
}

/// Whether `r` is the exact record a manifest entry lists.
fn exact(e: &ManifestEntry, r: &ItemRecord) -> bool {
    r.item_id == e.item_id && r.version == e.version && record_hash(r) == e.record_hash
}

/// The item record body of a stored record of `vault`, if it is one.
fn item_of(r: &Record, vault: Id) -> Option<ItemRecord> {
    let (prefix, body) = split_item_record(&r.data).ok()?;
    (prefix == vault).then(|| ItemRecord::decode(body).ok())?
}

/// Postcard of the whole buffer, trailing bytes refused.
fn decode_exact<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> Result<T> {
    match postcard::take_from_bytes(bytes) {
        Ok((v, [])) => Ok(v),
        _ => Err(BAD),
    }
}

impl<S: RecordStore> Repository<S> {
    /// Hide every vault without `travel_safe`: verify it, check that
    /// `upstream` holds each record of its verified state (same version and
    /// data: key, meta, manifest and the item records the manifest lists),
    /// then delete it locally and move its last manifest seen into the
    /// returned state. Upstream records beyond those (orphans of older
    /// versions or deleted items) are ignored.
    ///
    /// Everything is checked for all vaults before anything is deleted: a
    /// vault the upstream lacks or holds differently is
    /// `InvalidFormat("upstream does not hold the vault")`, and a vault
    /// that fails verification gives the core's error; in both cases the
    /// device is left unchanged. `upstream` is only read. While a rotation
    /// waits for the user it is `Error::ReadOnly` (R10), as are both exits.
    pub fn enter_travel<U: RecordStore>(&mut self, upstream: &U) -> Result<TravelState> {
        // R10: no write while a rotation waits for the user.
        self.writable()?;
        let local_items = self.store.list(RecordKind::Item)?;
        let local_chunks = self.store.list(RecordKind::Attachment)?;
        let mut plan: Vec<(Id, SeenManifest, Vec<Record>)> = Vec::new();
        // Spec 2026-11-02: items marked `travel_hidden` in personal vaults
        // that stay. Shared vaults stay out of Travel Mode, items included.
        let mut item_plan: Vec<(Id, BTreeSet<Id>, Vec<Record>)> = Vec::new();
        let mut guarded = false;
        for vault in self.personal_vaults()? {
            if vault.meta.travel_safe {
                let (hidden, records, any_guard) = self.hidden_items_of(&vault, upstream)?;
                guarded |= any_guard;
                if !hidden.is_empty() {
                    item_plan.push((vault.id, hidden, records));
                }
                continue;
            }
            let loaded = self.load(&vault)?;
            let mut chunks = Vec::new();
            for (_, r) in &loaded.records {
                let item = vault.open_item(r)?;
                // The chunks leave too: the server must hold each one.
                for a in &item.attachments {
                    for id in crate::attachment::chunk_ids(a)? {
                        if let Some(chunk) = self.store.get(RecordKind::Attachment, id)? {
                            chunks.push(chunk);
                        }
                    }
                }
            }
            let mut required = Vec::new();
            for kind in VAULT_KINDS {
                // `vaults()` and `load` just read them.
                required.push(self.store.get(kind, vault.id)?.ok_or(Error::NotFound)?);
            }
            for (blob, _) in &loaded.records {
                required.push(
                    self.store
                        .get(RecordKind::Item, *blob)?
                        .ok_or(Error::NotFound)?,
                );
            }
            required.extend(chunks);
            for r in &required {
                match upstream.get(r.kind, r.id)? {
                    Some(u) if same(&u, r) => {}
                    _ => return Err(UPSTREAM_MISMATCH),
                }
            }
            // Every local record of the vault goes, ignored leftovers too.
            let mut records: Vec<Record> = required.into_iter().take(VAULT_KINDS.len()).collect();
            records.extend(items_of(&local_items, vault.id).cloned());
            records.extend(items_of(&local_chunks, vault.id).cloned());
            plan.push((vault.id, seen(&loaded.manifest), records));
        }
        if plan.is_empty() && item_plan.is_empty() && !guarded {
            return Err(Error::InvalidFormat("nothing leaves"));
        }

        // Only this device's copy goes (`evict`, all or nothing): a store
        // with a server never pushes these as deletions.
        let all: Vec<Record> = plan
            .iter()
            .flat_map(|(_, _, r)| r.iter().cloned())
            .chain(item_plan.iter().flat_map(|(_, _, r)| r.iter().cloned()))
            .collect();
        self.store.evict_all(&all)?;
        let mut parked = BTreeMap::new();
        for (id, seen, _) in plan {
            self.device.last_seen.remove(&id);
            self.dropped.insert(id);
            self.travel_parked.insert(id);
            parked.insert(id, seen);
        }
        let mut parked_items = BTreeMap::new();
        for (id, items, _) in item_plan {
            self.travel_parked_items.insert(id, items.clone());
            parked_items.insert(id, items);
        }
        self.travelling = true;
        Ok(TravelState {
            parked,
            entered_at: OffsetDateTime::now_utc().unix_timestamp(),
            parked_items,
        })
    }

    /// The items of a vault that stays and that leave (`travel_hidden`,
    /// never the profile), checked against `upstream`: each one's current
    /// record and every chunk of its attachments held locally must be there
    /// byte for byte (`InvalidFormat("upstream does not hold the vault")`
    /// otherwise). Returns their ids, every local record that goes (the
    /// current one, ignored leftovers, chunks), and whether any item of the
    /// vault is guarded.
    fn hidden_items_of<U: RecordStore>(
        &self,
        vault: &Vault,
        upstream: &U,
    ) -> Result<(BTreeSet<Id>, Vec<Record>, bool)> {
        let loaded = self.load(vault)?;
        let mut hidden = BTreeSet::new();
        let mut records = Vec::new();
        let mut guarded = false;
        for (blob, r) in &loaded.records {
            let item = vault.open_item(r)?;
            guarded |= item.travel_guarded();
            if !item.travel_hidden() || item.is_profile() {
                continue;
            }
            let mut required = vec![
                self.store
                    .get(RecordKind::Item, *blob)?
                    .ok_or(Error::NotFound)?,
            ];
            for a in &item.attachments {
                for id in crate::attachment::chunk_ids(a)? {
                    if let Some(chunk) = self.store.get(RecordKind::Attachment, id)? {
                        required.push(chunk);
                    }
                }
            }
            for r in &required {
                match upstream.get(r.kind, r.id)? {
                    Some(u) if same(&u, r) => {}
                    _ => return Err(UPSTREAM_MISMATCH),
                }
            }
            records.extend(required);
            for leftover in loaded.ignored_of(item.id) {
                if let Some(r) = self.store.get(RecordKind::Item, leftover)? {
                    records.push(r);
                }
            }
            hidden.insert(item.id);
        }
        Ok((hidden, records, guarded))
    }

    /// The Travel Mode is on in this session: entered or resumed, and not
    /// left since (guarded items only count too).
    pub fn travelling(&self) -> bool {
        self.travelling
            || !self.travel_parked.is_empty()
            || self.travel_parked_items.values().any(|s| !s.is_empty())
    }

    /// Whether the Travel Mode parked `item` of `vault` (its records are off
    /// this device).
    pub fn is_parked_item(&self, vault: Id, item: Id) -> bool {
        self.travel_parked_items
            .get(&vault)
            .is_some_and(|s| s.contains(&item))
    }

    /// Resume the Travel Mode in a new session: the vaults of `state` are
    /// parked, so `vaults()` does not expect them although the vault list
    /// lists them. Nothing is read or written. `state` comes from
    /// `open_travel_state`, which verifies it.
    pub fn resume_travel(&mut self, state: &TravelState) {
        self.travel_parked.extend(state.parked.keys().copied());
        for (vault, items) in &state.parked_items {
            self.travel_parked_items
                .entry(*vault)
                .or_default()
                .extend(items.iter().copied());
        }
        self.travelling = true;
    }

    /// Bring the parked vaults back from `upstream` and verify them as in
    /// normal use, against their parked last manifest seen: an older
    /// manifest, a fork at the same seq or a dropped item is refused with
    /// the core's error, and a newer manifest (written by another device
    /// meanwhile) is accepted.
    ///
    /// A parked vault already present locally (an exit cut short, or records
    /// planted in the local store) is not copied again but still verified
    /// against its parked last manifest seen: the local one is kept only if
    /// its seq is at least the parked one, and the same seq with another
    /// hash is a fork (`ManifestRollback`).
    ///
    /// On failure, the records copied are deleted and the device state is
    /// restored: `state` stays valid for another attempt.
    pub fn exit_travel<U: RecordStore>(&mut self, upstream: &U, state: &TravelState) -> Result<()> {
        // R10: no write while a rotation waits for the user.
        self.writable()?;
        // R19: a vault the head rotation covered starts again from its
        // `from_heads` (R12), which the adoption put in the device state: a
        // parked pin made under the identity left (sealed to a retired KEM
        // key, signed by a retired key the revoked device also holds) never
        // replaces it. If the device moved past `from_heads` since (it
        // wrote the vault under the new identity), the pin is the device's.
        let heads = self.head_from_heads()?;
        let mut todo = Vec::new();
        for (id, seen) in &state.parked {
            let present = self.store.get(RecordKind::VaultKey, *id)?.is_some();
            let covered = heads
                .get(id)
                .is_some_and(|h| self.device.last_seen.get(id) == Some(h));
            todo.push(Restore {
                id: *id,
                parked: (!covered).then(|| seen.clone()),
                copy: !present,
            });
        }
        self.restore_items(upstream, &state.parked_items)?;
        self.restore(upstream, &todo)?;
        self.travelling = false;
        Ok(())
    }

    /// Bring back the parked items of the vaults that stayed: copy from
    /// `upstream` the exact records the local manifest (verified against
    /// the last one seen) lists for them, and their attachments' chunks,
    /// then load each vault through `items()` with nothing tolerated. An
    /// item the manifest no longer lists (deleted by another device) is
    /// forgotten. A vault no longer listed (deleted meanwhile) is skipped.
    ///
    /// On failure the copied records are evicted again and the parked set
    /// is put back, so the state stays valid.
    fn restore_items<U: RecordStore>(
        &mut self,
        upstream: &U,
        parked: &BTreeMap<Id, BTreeSet<Id>>,
    ) -> Result<()> {
        if parked.values().all(BTreeSet::is_empty) {
            return Ok(());
        }
        let before = self.travel_parked_items.clone();
        let mut copied: Vec<(RecordKind, Id)> = Vec::new();
        let result = self.copy_items(upstream, parked, &mut copied);
        if result.is_err() {
            self.travel_parked_items = before;
            let mut rollback = Ok(());
            for (kind, id) in copied.into_iter().rev() {
                if let Err(e) = self.store.evict(kind, id) {
                    rollback = rollback.and(Err(e));
                }
            }
            rollback?;
        }
        result
    }

    fn copy_items<U: RecordStore>(
        &mut self,
        upstream: &U,
        parked: &BTreeMap<Id, BTreeSet<Id>>,
        copied: &mut Vec<(RecordKind, Id)>,
    ) -> Result<()> {
        let vaults = self.vaults()?;
        let upstream_items = upstream.list(RecordKind::Item)?;
        let local_items = self.store.list(RecordKind::Item)?;
        for (vault_id, items) in parked {
            let Some(vault) = vaults.iter().find(|v| v.id == *vault_id) else {
                self.travel_parked_items.remove(vault_id);
                continue;
            };
            let manifest = self.read_manifest(vault, self.device.last_seen.get(vault_id))?;
            for e in manifest
                .entries
                .iter()
                .filter(|e| items.contains(&e.item_id))
            {
                let local = local_items
                    .iter()
                    .find(|r| item_of(r, *vault_id).is_some_and(|i| exact(e, &i)));
                let record = match local {
                    Some(r) => r.clone(),
                    None => match upstream_items
                        .iter()
                        .find(|r| item_of(r, *vault_id).is_some_and(|i| exact(e, &i)))
                    {
                        Some(r) => {
                            self.put_new(r.clone(), copied)?;
                            r.clone()
                        }
                        // The verification below reports it missing.
                        None => continue,
                    },
                };
                let Some(rec) = item_of(&record, *vault_id) else {
                    continue;
                };
                let Ok(item) = vault.open_item(&rec) else {
                    continue;
                };
                for a in &item.attachments {
                    for id in crate::attachment::chunk_ids(a)? {
                        if self.store.get(RecordKind::Attachment, id)?.is_none()
                            && let Some(chunk) = upstream.get(RecordKind::Attachment, id)?
                        {
                            self.put_new(chunk, copied)?;
                        }
                    }
                }
            }
            self.travel_parked_items.remove(vault_id);
            self.items(vault)?;
        }
        Ok(())
    }

    /// Put `r` unless the same record is already there; a different local
    /// record under its key is refused (never overwritten).
    fn put_new(&mut self, r: Record, copied: &mut Vec<(RecordKind, Id)>) -> Result<()> {
        match self.store.get(r.kind, r.id)? {
            None => {
                let key = (r.kind, r.id);
                self.store.put(r)?;
                copied.push(key);
                Ok(())
            }
            Some(local) if same(&local, &r) => Ok(()),
            Some(_) => Err(IntegrityError::WrongContext.into()),
        }
    }

    /// Bring back every vault of `upstream` absent locally, without a
    /// parked last manifest seen (the sealed state was lost): the manifest
    /// signature and the records are still verified, but an old authentic
    /// manifest would be accepted. Returns the restored vault ids, sorted.
    /// Same rollback on failure as `exit_travel`.
    pub fn exit_travel_unpinned<U: RecordStore>(&mut self, upstream: &U) -> Result<Vec<Id>> {
        // R10: no write while a rotation waits for the user.
        self.writable()?;
        let local: BTreeSet<Id> = self
            .store
            .list(RecordKind::VaultKey)?
            .into_iter()
            .map(|r| r.id)
            .collect();
        let missing: BTreeSet<Id> = upstream
            .list(RecordKind::VaultKey)?
            .into_iter()
            .map(|r| r.id)
            .filter(|id| !local.contains(id))
            .collect();
        let todo: Vec<Restore> = missing
            .iter()
            .map(|id| Restore {
                id: *id,
                parked: None,
                copy: true,
            })
            .collect();
        self.restore(upstream, &todo)?;
        // Items parked from vaults that stayed: every listed entry without
        // a local record is brought back the same way.
        let mut parked: BTreeMap<Id, BTreeSet<Id>> = BTreeMap::new();
        let local_items = self.store.list(RecordKind::Item)?;
        for vault in self.open_vaults()? {
            let Ok(m) = self.read_manifest(&vault, self.device.last_seen.get(&vault.id)) else {
                continue;
            };
            let absent: BTreeSet<Id> = m
                .entries
                .iter()
                .filter(|e| {
                    !local_items
                        .iter()
                        .any(|r| item_of(r, vault.id).is_some_and(|i| exact(e, &i)))
                })
                .map(|e| e.item_id)
                .collect();
            if !absent.is_empty() {
                self.travel_parked_items
                    .entry(vault.id)
                    .or_default()
                    .extend(absent.iter().copied());
                parked.insert(vault.id, absent);
            }
        }
        self.restore_items(upstream, &parked)?;
        self.travelling = false;
        Ok(missing.into_iter().collect())
    }

    /// Copy the records of the vaults to `copy` from `upstream`, merge the
    /// parked last manifest seen, then verify every vault of `vaults`
    /// through `vaults()` and `items()`. Undo everything on failure.
    ///
    /// Rollback is best effort over every step. If one of its steps fails,
    /// the store is not back to its previous state: that failure is
    /// returned instead of the original error, so the caller never takes
    /// a partial rollback for a clean one.
    fn restore<U: RecordStore>(&mut self, upstream: &U, vaults: &[Restore]) -> Result<()> {
        if vaults.is_empty() {
            return Ok(());
        }
        // A fork against the device's own pin is refused before anything.
        for v in vaults {
            if let (Some(p), Some(mine)) = (&v.parked, self.device.last_seen.get(&v.id))
                && mine.seq == p.seq
                && mine.hash != p.hash
            {
                return Err(IntegrityError::ManifestRollback.into());
            }
        }
        // Items first and the key last, so a vault cut halfway is not listed.
        let upstream_items = upstream.list(RecordKind::Item)?;
        let upstream_chunks = upstream.list(RecordKind::Attachment)?;
        let mut copy = Vec::new();
        for v in vaults.iter().filter(|v| v.copy) {
            copy.extend(items_of(&upstream_chunks, v.id).cloned());
            let listed = self.upstream_listed(upstream, v.id)?;
            copy.extend(
                items_of(&upstream_items, v.id)
                    .filter(|r| {
                        split_item_record(&r.data)
                            .ok()
                            .and_then(|(_, body)| ItemRecord::decode(body).ok())
                            .is_some_and(|rec| listed.contains(&(rec.item_id, rec.version)))
                    })
                    .cloned(),
            );
            for kind in VAULT_KINDS.iter().rev() {
                if let Some(r) = upstream.get(*kind, v.id)? {
                    copy.push(r);
                }
            }
        }
        // Never overwrite a local record: an upstream record under the key
        // of another local record is refused. The same record already there
        // (left by an interrupted exit) is kept and not copied.
        let mut to_put = Vec::new();
        for r in copy {
            match self.store.get(r.kind, r.id)? {
                None => to_put.push(r),
                Some(local) if same(&local, &r) => {}
                Some(_) => return Err(IntegrityError::WrongContext.into()),
            }
        }

        let before: Vec<(Id, Option<SeenManifest>)> = vaults
            .iter()
            .map(|v| (v.id, self.device.last_seen.get(&v.id).cloned()))
            .collect();
        let mut copied = Vec::new();
        let result = self.copy_and_verify(to_put, vaults, &mut copied);
        if result.is_err() {
            for (id, seen) in before {
                match seen {
                    Some(s) => self.device.last_seen.insert(id, s),
                    None => {
                        self.dropped.insert(id);
                        self.device.last_seen.remove(&id)
                    }
                };
            }
            // Reverse copy order: the key goes first, so a rollback cut
            // short never leaves a listed vault without its items.
            let mut rollback = Ok(());
            for (kind, id) in copied.into_iter().rev() {
                if let Err(e) = self.store.evict(kind, id) {
                    rollback = rollback.and(Err(e));
                }
            }
            rollback?;
        } else {
            for v in vaults {
                self.travel_parked.remove(&v.id);
            }
        }
        result
    }

    /// The `(item id, version)` pairs the upstream manifest of `vault_id`
    /// lists, used only to choose which item records to copy: trust comes
    /// from the normal verification after the copy. Empty when the upstream
    /// lacks the vault's key, meta or manifest, or when they do not open:
    /// that verification then reports the problem.
    fn upstream_listed<U: RecordStore>(
        &self,
        upstream: &U,
        vault_id: Id,
    ) -> Result<BTreeSet<(Id, u64)>> {
        let (Some(key), Some(meta), Some(manifest)) = (
            upstream.get(RecordKind::VaultKey, vault_id)?,
            upstream.get(RecordKind::VaultMeta, vault_id)?,
            upstream.get(RecordKind::Manifest, vault_id)?,
        ) else {
            return Ok(BTreeSet::new());
        };
        let listed = Vault::open(&self.account, vault_id, &key.data, &meta.data)
            .and_then(|vault| {
                let sm = SignedManifest::decode(&manifest.data)?;
                verify_manifest(&vault, &self.account.params.signing_pub, &sm, None)
            })
            .map(|m| m.entries.iter().map(|e| (e.item_id, e.version)).collect())
            .unwrap_or_default();
        Ok(listed)
    }

    fn copy_and_verify(
        &mut self,
        to_put: Vec<Record>,
        vaults: &[Restore],
        copied: &mut Vec<(RecordKind, Id)>,
    ) -> Result<()> {
        for r in to_put {
            let key = (r.kind, r.id);
            self.store.put(r)?;
            copied.push(key);
        }
        for v in vaults {
            if let Some(p) = &v.parked {
                let keep = self
                    .device
                    .last_seen
                    .get(&v.id)
                    .is_some_and(|mine| mine.seq >= p.seq);
                if !keep {
                    self.device.last_seen.insert(v.id, p.clone());
                }
            }
        }
        let listed = self.personal_vaults()?;
        for v in vaults {
            let vault = listed
                .iter()
                .find(|l| l.id == v.id)
                .ok_or(IntegrityError::VaultMissing)?;
            self.items(vault)?;
        }
        Ok(())
    }

    /// Seal `s` for this account: a fresh key wrapped to the account KEM
    /// key (context `"travel:" || account id`) encrypts the state, and the
    /// whole is signed with `sign_local`. Layout:
    /// `u32 BE len(body) || body || postcard(sig)`, zero padded to
    /// `SEALED_TRAVEL_STATE_LEN`, where `body = postcard((envelope, blob))`.
    pub fn seal_travel_state(&self, s: &TravelState) -> Result<Vec<u8>> {
        let plain = postcard::to_allocvec(s).map_err(|_| BAD)?;
        self.seal_state_bytes(&plain, SCHEMA)
    }

    /// A schema 1 sealed state, as a build from before parked items wrote
    /// it (`parked_items` is left out). For compatibility tests only.
    #[doc(hidden)]
    pub fn seal_travel_state_v1_for_tests(&self, s: &TravelState) -> Result<Vec<u8>> {
        let v1 = TravelStateV1 {
            parked: s.parked.clone(),
            entered_at: s.entered_at,
        };
        let plain = postcard::to_allocvec(&v1).map_err(|_| BAD)?;
        self.seal_state_bytes(&plain, SCHEMA_V1)
    }

    fn seal_state_bytes(&self, plain: &[u8], schema: u16) -> Result<Vec<u8>> {
        let account_id = self.account_id();
        let key = SymmetricKey::generate()?;
        let envelope = wrap_key(&self.account.params.kem_pub, &key, &kem_context(account_id))?;
        let blob = seal(
            &key,
            BlobKind::TravelState,
            &state_aad(account_id, schema),
            plain,
        )?;
        let body = postcard::to_allocvec(&(envelope, blob)).map_err(|_| BAD)?;
        let sig = self.sign_local(SIG_DOMAIN, &body)?;
        let sig = postcard::to_allocvec(&sig).map_err(|_| BAD)?;
        let len = u32::try_from(body.len()).map_err(|_| BAD)?;
        let total = LEN_PREFIX + body.len() + sig.len();
        if total > SEALED_TRAVEL_STATE_LEN {
            return Err(Error::InvalidFormat("travel state too large"));
        }
        let mut out = Vec::with_capacity(SEALED_TRAVEL_STATE_LEN);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&body);
        out.extend_from_slice(&sig);
        out.resize(SEALED_TRAVEL_STATE_LEN, 0);
        Ok(out)
    }

    /// Open a state sealed by `seal_travel_state` for this account. Any
    /// other length, a body that does not verify under the account's local
    /// signature, non-zero padding, or a state that does not open is an
    /// error.
    ///
    /// R18/R19: a state made before a rotation also opens (retired KEM
    /// secrets, retired signing keys). The revoked device holds those keys
    /// and can forge such a file, so one that verifies only under a retired
    /// key is trusted for nothing but what the rotation itself says: it is
    /// refused (`Integrity(Signature)`) if it lists a vault outside the
    /// head rotation's `from_heads` (a genuine one cannot: a parked vault
    /// is covered by the rotator), and its pins are replaced by
    /// `from_heads`. `reseal_travel_state` binds it to the new identity.
    pub fn open_travel_state(&self, bytes: &[u8]) -> Result<TravelState> {
        let (mut state, retired_only) = self.open_travel_state_raw(bytes)?;
        if retired_only {
            let heads = self.head_from_heads()?;
            for (id, seen) in &mut state.parked {
                *seen = heads
                    .get(id)
                    .cloned()
                    .ok_or(Error::Integrity(IntegrityError::Signature))?;
            }
        }
        Ok(state)
    }

    /// Re-seal a state made before a rotation under the current identity
    /// (the follower holds the genuine file when it adopts): the result is
    /// signed and sealed with the current keys, so it no longer depends on
    /// the retired ones. The pins are those `open_travel_state` returns.
    pub fn reseal_travel_state(&self, bytes: &[u8]) -> Result<Vec<u8>> {
        self.seal_travel_state(&self.open_travel_state(bytes)?)
    }

    fn open_travel_state_raw(&self, bytes: &[u8]) -> Result<(TravelState, bool)> {
        if bytes.len() != SEALED_TRAVEL_STATE_LEN {
            return Err(BAD);
        }
        let (len, rest) = bytes.split_at(LEN_PREFIX);
        let len = u32::from_be_bytes(len.try_into().map_err(|_| BAD)?);
        let len = usize::try_from(len).map_err(|_| BAD)?;
        let (body, rest) = rest.split_at_checked(len).ok_or(BAD)?;
        let (sig, padding): (HybridSignature, &[u8]) =
            postcard::take_from_bytes(rest).map_err(|_| BAD)?;
        if padding.iter().any(|b| *b != 0) {
            return Err(BAD);
        }
        let mut retired_only = self.verify_local_or_retired(SIG_DOMAIN, body, &sig)?;
        let (envelope, blob): (Vec<u8>, Vec<u8>) = decode_exact(body)?;
        let account_id = self.account_id();
        let ctx = kem_context(account_id);
        let keyset = self.account.keyset();
        let mut first_err = None;
        let mut found = None;
        for (i, k) in std::iter::once(&keyset.kem)
            .chain(&keyset.retired_kem)
            .enumerate()
        {
            match unwrap_key(k, &envelope, &ctx) {
                Ok(key) => {
                    retired_only |= i > 0;
                    found = Some(key);
                    break;
                }
                Err(e) => {
                    first_err.get_or_insert(e);
                }
            }
        }
        let key = found.ok_or_else(|| first_err.unwrap_or(BAD))?;
        // The schema is bound in the AAD: a schema 1 state (before parked
        // items) opens only under schema 1 and decodes as one.
        if let Ok(plain) = open(
            &key,
            BlobKind::TravelState,
            &state_aad(account_id, SCHEMA),
            &blob,
        ) {
            return Ok((decode_exact(&plain)?, retired_only));
        }
        let plain = open(
            &key,
            BlobKind::TravelState,
            &state_aad(account_id, SCHEMA_V1),
            &blob,
        )?;
        let v1: TravelStateV1 = decode_exact(&plain)?;
        let state = TravelState {
            parked: v1.parked,
            entered_at: v1.entered_at,
            parked_items: BTreeMap::new(),
        };
        Ok((state, retired_only))
    }
}
