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
//! vault id, and the `Item` records whose prefix (`split_item_record`) is the
//! vault id.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use super::{Repository, seen, split_item_record};
use crate::crypto::{
    Aad, BlobKind, HybridSignature, SymmetricKey, open, seal, unwrap_key, wrap_key,
};
use crate::manifest::SeenManifest;
use crate::manifest::{SignedManifest, verify_manifest};
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
const SCHEMA: u16 = 1;
const LEN_PREFIX: usize = 4;

const BAD: Error = Error::InvalidFormat("travel state");
const UPSTREAM_MISMATCH: Error = Error::InvalidFormat("upstream does not hold the vault");

/// The vaults parked by `enter_travel`, with the last manifest seen of
/// each, and when the Travel Mode was entered (Unix seconds).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TravelState {
    pub parked: BTreeMap<Id, SeenManifest>,
    pub entered_at: i64,
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

fn state_aad(account_id: Id) -> Aad {
    Aad {
        blob_id: account_id,
        vault_id: None,
        schema: SCHEMA,
    }
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
    /// device is left unchanged. `upstream` is only read.
    pub fn enter_travel<U: RecordStore>(&mut self, upstream: &U) -> Result<TravelState> {
        let local_items = self.store.list(RecordKind::Item)?;
        let mut plan: Vec<(Id, SeenManifest, Vec<Record>)> = Vec::new();
        for vault in self.vaults()? {
            if vault.meta.travel_safe {
                continue;
            }
            let loaded = self.load(&vault)?;
            for (_, r) in &loaded.records {
                vault.open_item(r)?;
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
            for r in &required {
                match upstream.get(r.kind, r.id)? {
                    Some(u) if same(&u, r) => {}
                    _ => return Err(UPSTREAM_MISMATCH),
                }
            }
            // Every local record of the vault goes, ignored leftovers too.
            let mut records: Vec<Record> = required.into_iter().take(VAULT_KINDS.len()).collect();
            records.extend(items_of(&local_items, vault.id).cloned());
            plan.push((vault.id, seen(&loaded.manifest), records));
        }

        // Only this device's copy goes (`evict`, all or nothing): a store
        // with a server never pushes these as deletions.
        let all: Vec<Record> = plan
            .iter()
            .flat_map(|(_, _, r)| r.iter().cloned())
            .collect();
        self.store.evict_all(&all)?;
        let mut parked = BTreeMap::new();
        for (id, seen, _) in plan {
            self.device.last_seen.remove(&id);
            self.dropped.insert(id);
            self.travel_parked.insert(id);
            parked.insert(id, seen);
        }
        Ok(TravelState {
            parked,
            entered_at: OffsetDateTime::now_utc().unix_timestamp(),
        })
    }

    /// Resume the Travel Mode in a new session: the vaults of `state` are
    /// parked, so `vaults()` does not expect them although the vault list
    /// lists them. Nothing is read or written. `state` comes from
    /// `open_travel_state`, which verifies it.
    pub fn resume_travel(&mut self, state: &TravelState) {
        self.travel_parked.extend(state.parked.keys().copied());
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
        let mut todo = Vec::new();
        for (id, seen) in &state.parked {
            let present = self.store.get(RecordKind::VaultKey, *id)?.is_some();
            todo.push(Restore {
                id: *id,
                parked: Some(seen.clone()),
                copy: !present,
            });
        }
        self.restore(upstream, &todo)
    }

    /// Bring back every vault of `upstream` absent locally, without a
    /// parked last manifest seen (the sealed state was lost): the manifest
    /// signature and the records are still verified, but an old authentic
    /// manifest would be accepted. Returns the restored vault ids, sorted.
    /// Same rollback on failure as `exit_travel`.
    pub fn exit_travel_unpinned<U: RecordStore>(&mut self, upstream: &U) -> Result<Vec<Id>> {
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
        let mut copy = Vec::new();
        for v in vaults.iter().filter(|v| v.copy) {
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
        let listed = self.vaults()?;
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
        let account_id = self.account_id();
        let key = SymmetricKey::generate()?;
        let envelope = wrap_key(&self.account.params.kem_pub, &key, &kem_context(account_id))?;
        let plain = postcard::to_allocvec(s).map_err(|_| BAD)?;
        let blob = seal(&key, BlobKind::TravelState, &state_aad(account_id), &plain)?;
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
    pub fn open_travel_state(&self, bytes: &[u8]) -> Result<TravelState> {
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
        self.verify_local(SIG_DOMAIN, body, &sig)?;
        let (envelope, blob): (Vec<u8>, Vec<u8>) = decode_exact(body)?;
        let account_id = self.account_id();
        let key = unwrap_key(
            &self.account.keyset().kem,
            &envelope,
            &kem_context(account_id),
        )?;
        let plain = open(&key, BlobKind::TravelState, &state_aad(account_id), &blob)?;
        decode_exact(&plain)
    }
}
