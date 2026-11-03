//! A new key generation for a shared vault (sharing spec 9.2, 9.3, 13.8;
//! plan 2 Task 9): removal of a member with every item resealed, the
//! three-phase push (`SharePush`), following a newer membership body, the
//! removed side's erasure, and the shared rebase of a write that lost the
//! manifest race.

use std::collections::BTreeSet;

use super::reseal::item_record;
use super::{Repository, Use, entry, split_item_record};
use crate::contact::ContactLevel;
use crate::manifest::{Manifest, ManifestEntry, SeenManifest, manifest_hash, meta_hash};
use crate::model::Item;
use crate::share::{
    AccessTarget, FormerMemberExposure, InviteRecord, MemberKey, MemberRef, MembershipBody,
    MembershipReason, MembershipView, Removed, Role, SharePush, ShareState, SharedSignedManifest,
    SignedMembership, ZONE_ACCESS_KIND, accept_next, key_commit, open_member_key, sign_membership,
    sign_shared_manifest, verify_shared_manifest, wrap_member_key,
};
use crate::store::{Record, RecordKind, RecordStore, Zone};
use crate::sync::SyncStore;
use crate::vault::{ItemRecord, Vault, VaultMeta};
use crate::{Error, Id, Result, ValidationError};

/// What a new key generation did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RekeyOutcome {
    pub generation: u32,
    /// The items the vault listed when the key changed (live, archived,
    /// trashed): all of them were readable by a removed member.
    pub seen_items: u32,
}

/// What `zone_access_refused` concluded (spec 13.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessRefusal {
    /// A signed body removing me was found: the local copy is erased (my
    /// unsent writes kept in a personal copy).
    Removed,
    /// No signed removal: the vault stays here read-only, nothing erased.
    Unconfirmed,
}

/// The name of the personal vault that keeps the unsent writes of a vault
/// I was removed from (plan 2, Task 9).
fn copy_name(name: &str) -> String {
    format!("Copie de {name}")
}

fn refused(field: &str, reason: &'static str) -> Error {
    ValidationError {
        field: field.into(),
        reason,
    }
    .into()
}

impl<S: RecordStore> Repository<S> {
    /// Remove member `account_id` from shared vault `vault_id` (spec 9.2):
    /// a new key generation, every item resealed, in one transaction; the
    /// signed removal copy and the revocation of its credential follow once
    /// the new body and manifest are confirmed (`SharePush` phase 3).
    /// Refused: not a manager, myself (`Validation("member", "self")`, a
    /// departure is `leave`), the owner (`Validation("member", "owner")`),
    /// not a member, a resealing still being pushed.
    pub fn remove_member(
        &mut self,
        vault_id: Id,
        account_id: Id,
        now: i64,
    ) -> Result<RekeyOutcome> {
        self.rekey_vault(vault_id, MembershipReason::Remove, Some(account_id), now)
    }

    /// A new key generation for shared vault `vault_id` (spec 9.2 steps 1
    /// to 5): the next body (reason `reason`, `remove` taken out and listed
    /// in `removed`), a fresh key, an envelope for each remaining member
    /// whose keys are confirmed (the book's `Active` entry equal to the
    /// body's, or no entry: the body's managers vouched for it), the
    /// others at `key_pending` without one, every item resealed with the
    /// meta and the next manifest, the share state advanced with the
    /// `SharePush` to send. One local transaction.
    pub(crate) fn rekey_vault(
        &mut self,
        vault_id: Id,
        reason: MembershipReason,
        remove: Option<Id>,
        now: i64,
    ) -> Result<RekeyOutcome> {
        self.writable()?;
        self.follow_head(vault_id)?;
        let state = self.store.share_state(vault_id)?.ok_or(Error::NotFound)?;
        let me = self.me();
        let mine = state
            .head
            .member(me.account_id)
            .filter(|m| m.identity_id == me.identity_id)
            .ok_or_else(|| refused("role", "not a member"))?;
        if mine.role != Role::Manage {
            return Err(refused("role", "manager only"));
        }
        if state.push.is_some() {
            return Err(refused("vault", "key change pending"));
        }
        if state.access_refused.is_some() {
            return Err(refused("vault", "access refused"));
        }
        let zone = state.zone;
        let vault = self.open_shared(vault_id)?;
        let loaded = self.shared_served(&vault, Use::Write)?;
        // `shared_served` may have remembered the manifest: read again.
        let mut state = self.store.share_state(vault_id)?.ok_or(Error::NotFound)?;

        let mut body = state.head.next(me, reason, now)?;
        let mut removed_member = None;
        if let Some(target) = remove {
            if target == me.account_id {
                return Err(refused("member", "self"));
            }
            let i = body
                .members
                .iter()
                .position(|m| m.account_id == target)
                .ok_or_else(|| refused("member", "not a member"))?;
            if body.members[i].owner {
                return Err(refused("member", "owner"));
            }
            let m = body.members.remove(i);
            body.removed.push(Removed {
                account_id: m.account_id,
                identity_id: m.identity_id,
                removed_at: now,
                by: me,
            });
            removed_member = Some(m);
        }
        let g = state
            .head
            .generation
            .checked_add(1)
            .ok_or(Error::InvalidFormat("generation"))?;
        let (next, key, meta_blob) = Vault::new_shared(vault_id, vault.meta.clone())?;
        body.generation = g;
        body.key_commit = key_commit(&key, vault_id, g);
        let mut envelopes = Vec::new();
        for m in &mut body.members {
            let who = m.member_ref();
            let confirmed = if who == me {
                true
            } else {
                match self.contact(m.account_id)? {
                    Some(c) => {
                        c.usable_for(ContactLevel::Link)
                            && c.sign_pub == m.sign_pub
                            && c.kem_pub == m.kem_pub
                    }
                    None => true,
                }
            };
            m.key_pending = !confirmed;
            if confirmed {
                envelopes.push(wrap_member_key(&m.kem_pub, &key, vault_id, g, &who)?);
            }
        }
        let signed = sign_membership(body, &self.account.keyset().signing)?;
        let head = accept_next(&state.head, &signed)?;

        let resealed = self.reseal_vault(&vault, &next, &loaded)?;
        let m = resealed
            .manifest
            .clone()
            .with_meta(&next.meta)
            .with_membership(head.seen(), g);
        let sm = sign_shared_manifest(&next, &self.account.keyset().signing, me, &m)?;

        let meta_rec = self
            .store
            .get_in(zone, RecordKind::VaultMeta, vault_id)?
            .ok_or(Error::InvalidFormat("vault meta"))?;
        let mut writes: Vec<(Zone, Record, Option<u64>)> = vec![
            (
                zone,
                Record {
                    kind: RecordKind::Membership,
                    id: vault_id,
                    version: head.seq,
                    data: signed.encode(),
                },
                Some(state.head.seq),
            ),
            (
                zone,
                Record {
                    kind: RecordKind::VaultMeta,
                    id: vault_id,
                    version: meta_rec.version.checked_add(1).ok_or(Error::Conflict)?,
                    data: meta_blob,
                },
                Some(meta_rec.version),
            ),
            (
                zone,
                Record {
                    kind: RecordKind::Manifest,
                    id: vault_id,
                    version: m.seq,
                    data: sm.encode(),
                },
                Some(loaded.manifest.seq),
            ),
        ];
        for mk in &envelopes {
            writes.push((
                zone,
                Record {
                    kind: RecordKind::MemberKey,
                    id: mk.id(),
                    version: 1,
                    data: mk.encode(),
                },
                None,
            ));
        }
        let mut resealed_map = Vec::new();
        for (r, (_, from)) in resealed.items.iter().zip(&loaded.records) {
            let (_, rest) = split_item_record(&r.data)?;
            let sealed = ItemRecord::decode(rest)?;
            resealed_map.push((sealed.item_id, from.version, r.id, entry(&sealed)));
            writes.push((zone, r.clone(), None));
        }
        for (moved, version) in resealed.attachments {
            writes.push((zone, moved, Some(version)));
        }
        // Old records never pushed go now: they were sealed under the old
        // key and must never reach the server after the key changed.
        let mut deletes = Vec::new();
        let mut collect = Vec::new();
        for blob in &resealed.collect {
            if self
                .store
                .zone_base_version(zone, RecordKind::Item, *blob)?
                .is_some()
            {
                collect.push(*blob);
            } else {
                deletes.push((zone, RecordKind::Item, *blob));
            }
        }
        let mut old_keys = Vec::new();
        for r in self.store.list_in(zone, RecordKind::MemberKey)? {
            if let Ok(mk) = MemberKey::decode(&r.data)
                && mk.generation < g
            {
                if self
                    .store
                    .zone_base_version(zone, RecordKind::MemberKey, r.id)?
                    .is_some()
                {
                    old_keys.push(r.id);
                } else {
                    deletes.push((zone, RecordKind::MemberKey, r.id));
                }
            }
        }
        let mut notice = None;
        let mut revoke = None;
        if let Some(gone) = &removed_member {
            revoke = Some(gone.credential_id);
            if let Ok(cz) = self.contact_zone(gone.account_id) {
                let rec = InviteRecord::Removed(signed.clone());
                notice = Some((cz, rec.id(), rec.encode()));
            }
            state.exposures.push(FormerMemberExposure {
                vault_id,
                account_id: gone.account_id,
                removed_at: now,
                items: m.entries.iter().map(|e| (e.item_id, e.version)).collect(),
            });
        }
        let seen_items = u32::try_from(loaded.records.len()).unwrap_or(u32::MAX);
        state.advance(head);
        state.last_manifest = Some(SeenManifest {
            seq: m.seq,
            hash: manifest_hash(&m),
        });
        state.last_meta = Some(meta_hash(&next.meta));
        state.push = Some(SharePush {
            phase: 1,
            collect,
            old_keys,
            notice,
            revoke,
            from: resealed.from.clone(),
            resealed: resealed_map,
        });
        self.store
            .put_all_zoned(writes, deletes, None, std::slice::from_ref(&state))?;
        Ok(RekeyOutcome {
            generation: g,
            seen_items,
        })
    }

    /// Follow every shared vault to the newest membership body its zone
    /// holds (gap 2 of Task 9).
    pub(crate) fn follow_heads(&mut self) -> Result<()> {
        for state in self.store.share_states()? {
            self.follow_head(state.vault_id)?;
        }
        Ok(())
    }

    /// Follow shared vault `vault_id` to the body its zone holds when it is
    /// newer than the pinned head and `accept_next` takes it (skips through
    /// `history`). A body that raises my role above `Read` while its signer
    /// is held at `Link` only in my book is not followed (decision 1, A13).
    /// A body that removes me erases the vault here (`erase_shared`). A
    /// body refused is left where it is: the pinned head stays.
    pub(crate) fn follow_head(&mut self, vault_id: Id) -> Result<()> {
        let Some(mut state) = self.store.share_state(vault_id)? else {
            return Ok(());
        };
        let Some(rec) = self
            .store
            .get_in(state.zone, RecordKind::Membership, vault_id)?
        else {
            return Ok(());
        };
        if rec.version <= state.head.seq {
            return Ok(());
        }
        let Ok(signed) = SignedMembership::decode(&rec.data) else {
            return Ok(());
        };
        let Ok(next) = accept_next(&state.head, &signed) else {
            return Ok(());
        };
        let me = self.me();
        match next.member(me.account_id) {
            Some(m) if m.identity_id == me.identity_id => {
                let before = state
                    .head
                    .member(me.account_id)
                    .map_or(Role::Read, |m| m.role);
                if m.role > before && m.role > Role::Read && !self.verified_signer(&next.signer)? {
                    return Ok(());
                }
                state.advance(next);
                self.store
                    .put_all_zoned(vec![], vec![], None, std::slice::from_ref(&state))
            }
            _ if removes(&next, &me) => self.erase_shared(&state),
            _ => Ok(()),
        }
    }

    /// The signer is me or a `Verified` contact of the book under the
    /// body's identity.
    fn verified_signer(&mut self, signer: &MemberRef) -> Result<bool> {
        if signer.account_id == self.me().account_id {
            return Ok(true);
        }
        Ok(self.contact(signer.account_id)?.is_some_and(|c| {
            c.usable_for(ContactLevel::Verified)
                && crate::lineage::identity_id(&c.identity_pub) == signer.identity_id
        }))
    }

    /// I was removed from the vault of `state` (spec 9.2, S11): my item
    /// writes not sent yet go to a new personal vault "Copie de <name>",
    /// then my zone access and every local record of the zone go.
    pub(crate) fn erase_shared(&mut self, state: &ShareState) -> Result<()> {
        let zone = state.zone;
        let mut kept = Vec::new();
        let vaults = self.generation_vaults(state)?;
        let name = vaults
            .first()
            .map_or_else(|| state.name.clone(), |v| v.meta.name.clone());
        for (kind, _, _, data) in self.store.zone_pending(zone)? {
            let Some(data) = data else { continue };
            if kind != RecordKind::Item {
                continue;
            }
            if let Some(item) = open_item_row(&vaults, &data) {
                kept.push(item);
            }
        }
        if !kept.is_empty() {
            let copy = self.create_vault(VaultMeta {
                name: copy_name(&name),
                icon: String::new(),
                color: String::new(),
                travel_safe: false,
                mcp_access: false,
            })?;
            for mut item in kept {
                item.vault_id = copy.id;
                self.save_item(&copy, item)?;
            }
        }
        let access = AccessTarget::Zone(zone).record_id()?;
        if self.store.get(ZONE_ACCESS_KIND, access)?.is_some() {
            self.store.put_all_zoned(
                vec![],
                vec![(Zone::Private, ZONE_ACCESS_KIND, access)],
                None,
                &[],
            )?;
        }
        self.store.drop_zone(zone)
    }

    /// The transport got `revoked_credential` on `zone` (spec 13.8): look
    /// for the signed body that removes me, in the zone or as a copy in a
    /// contact zone. Found and valid: the vault is erased here
    /// (`Removed`). Otherwise the vault stays read-only, nothing erased and
    /// nothing sent (`Unconfirmed`). Not a shared vault I hold: `NotFound`.
    pub fn zone_access_refused(&mut self, zone: Zone, now: i64) -> Result<AccessRefusal> {
        let Zone::Vault(vault_id) = zone else {
            return Err(Error::NotFound);
        };
        self.follow_head(vault_id)?;
        let Some(mut state) = self.store.share_state(vault_id)? else {
            return Ok(AccessRefusal::Removed);
        };
        let me = self.me();
        for cz in self.contact_zones()? {
            for rec in self.store.list_in(cz, RecordKind::ShareInvite)? {
                let Ok(InviteRecord::Removed(signed)) = InviteRecord::decode(&rec.data) else {
                    continue;
                };
                if signed.body.vault_id != vault_id {
                    continue;
                }
                if let Ok(next) = accept_next(&state.head, &signed)
                    && removes(&next, &me)
                {
                    self.erase_shared(&state)?;
                    return Ok(AccessRefusal::Removed);
                }
            }
        }
        if state.access_refused.is_none() {
            state.access_refused = Some(now);
            self.store
                .put_all_zoned(vec![], vec![], None, std::slice::from_ref(&state))?;
        }
        Ok(AccessRefusal::Unconfirmed)
    }

    /// Items a former member saw and nobody changed since (spec 9.3): the
    /// listed version is still the one of the reseal after its removal.
    pub fn seen_by_former_members(&mut self) -> Result<Vec<(Id, Id)>> {
        let mut out = BTreeSet::new();
        for state in self.store.share_states()? {
            if state.exposures.is_empty() {
                continue;
            }
            let Ok(vault) = self.open_shared(state.vault_id) else {
                continue;
            };
            let Ok(loaded) = self.shared_served(&vault, Use::Read) else {
                continue;
            };
            for x in &state.exposures {
                for (item, version) in &x.items {
                    if loaded
                        .manifest
                        .entries
                        .iter()
                        .any(|e| e.item_id == *item && e.version == *version)
                    {
                        out.insert((state.vault_id, *item));
                    }
                }
            }
        }
        Ok(out.into_iter().collect())
    }

    /// The vault keys I can open for the vault of `state`, newest first:
    /// my envelope of each generation still held, checked against the
    /// commitment of a body of that generation.
    fn generation_vaults(&self, state: &ShareState) -> Result<Vec<Vault>> {
        let me = self.me();
        let meta_blob = self
            .store
            .get_in(state.zone, RecordKind::VaultMeta, state.vault_id)?
            .map(|r| r.data);
        let mut keys = Vec::new();
        let mut done = BTreeSet::new();
        for body in std::iter::once(&state.head).chain(&state.ancestors) {
            if !done.insert(body.generation) {
                continue;
            }
            let id = crate::share::member_key_id(state.vault_id, body.generation, &me);
            let Some(r) = self.store.get_in(state.zone, RecordKind::MemberKey, id)? else {
                continue;
            };
            let Ok(mk) = MemberKey::decode(&r.data) else {
                continue;
            };
            if mk.member() != me || mk.generation != body.generation {
                continue;
            }
            if let Ok(key) = open_member_key(self.account.keyset(), &mk, &body.key_commit) {
                keys.push(key);
            }
        }
        // The meta is sealed under the newest key only: the others carry
        // the one that opens, else the name this device last saw.
        let meta = meta_blob
            .as_deref()
            .and_then(|blob| {
                keys.iter().find_map(|k| {
                    Vault::from_shared(state.vault_id, k.duplicate(), blob)
                        .ok()
                        .map(|v| v.meta)
                })
            })
            .unwrap_or_else(|| VaultMeta {
                name: state.name.clone(),
                icon: String::new(),
                color: String::new(),
                travel_safe: false,
                mcp_access: false,
            });
        Ok(keys
            .into_iter()
            .map(|k| Vault::with_key(state.vault_id, k, meta.clone(), state.zone))
            .collect())
    }
}

/// `body` lists `me` as removed and no longer as a member.
fn removes(body: &MembershipBody, me: &MemberRef) -> bool {
    body.member(me.account_id).is_none()
        && body
            .removed
            .iter()
            .any(|r| r.account_id == me.account_id && r.identity_id == me.identity_id)
}

/// The item of a stored item row, opened with the first of `vaults` that
/// opens it.
fn open_item_row(vaults: &[Vault], data: &[u8]) -> Option<Item> {
    let (prefix, rest) = split_item_record(data).ok()?;
    let rec = ItemRecord::decode(rest).ok()?;
    vaults
        .iter()
        .filter(|v| v.id == prefix)
        .find_map(|v| v.open_item(&rec).ok())
}

impl Repository<SyncStore> {
    /// Rebase the shared vaults whose pending manifest lost the race on the
    /// server (gap 3 of Task 9): each is followed to its newest body first.
    /// A member's own writes (items, deletions, meta) are read back with
    /// the key they were sealed under and written again over the server's
    /// manifest, under the current generation. A resealing being pushed is
    /// redone over the server's manifest (`rebase_rekey`). Errors stop at
    /// the vault they hit; the first is returned after the others ran.
    pub(crate) fn rebase_shared(&mut self) -> Result<()> {
        let mut first = None;
        for state in self.store.share_states()? {
            if let Err(e) = self.rebase_shared_vault(state.vault_id) {
                first.get_or_insert(e);
            }
        }
        first.map_or(Ok(()), Err)
    }

    fn manifest_lost(&self, zone: Zone, vault_id: Id) -> Result<bool> {
        let pending = self
            .store
            .zone_pending(zone)?
            .into_iter()
            .find(|(k, id, _, d)| *k == RecordKind::Manifest && *id == vault_id && d.is_some());
        let Some((_, _, version, _)) = pending else {
            return Ok(false);
        };
        let base = self
            .store
            .zone_base_version(zone, RecordKind::Manifest, vault_id)?
            .unwrap_or(0);
        Ok(base.checked_add(1) != Some(version))
    }

    fn rebase_shared_vault(&mut self, vault_id: Id) -> Result<()> {
        let Some(state) = self.store.share_state(vault_id)? else {
            return Ok(());
        };
        let zone = state.zone;
        if !self.manifest_lost(zone, vault_id)? {
            return Ok(());
        }
        if state.push.as_ref().is_some_and(|p| p.phase <= 2) {
            return self.rebase_rekey(vault_id);
        }
        // Read my writes back before the head moves on, and the manifest
        // my lost one followed: the server's continues from it.
        let before = self.generation_vaults(&state)?;
        let mut confirmed = None;
        if let Some(r) = self.store.get_in(zone, RecordKind::Manifest, vault_id)?
            && let Ok(sm) = SharedSignedManifest::decode(&r.data)
        {
            confirmed = before.iter().find_map(|v| {
                crate::share::manifest::open_own_shared_manifest(v, &sm)
                    .ok()
                    .and_then(|m| {
                        Some(SeenManifest {
                            seq: m.seq.checked_sub(1)?,
                            hash: m.prev_hash,
                        })
                    })
            });
        }
        self.follow_head(vault_id)?;
        let Some(mut state) = self.store.share_state(vault_id)? else {
            // Removed: `erase_shared` kept my writes.
            return Ok(());
        };
        if let Some(seen) = confirmed {
            state.last_manifest = Some(seen);
            self.store
                .put_all_zoned(vec![], vec![], None, std::slice::from_ref(&state))?;
        }
        let mut vaults = self.generation_vaults(&state)?;
        vaults.extend(before);
        let rows = self.store.zone_pending(zone)?;
        let mut saves = Vec::new();
        let mut deleted_blobs = Vec::new();
        let mut meta = None;
        let mut drop = Vec::new();
        for (kind, id, _, data) in &rows {
            match (kind, data) {
                (RecordKind::Item, Some(d)) => {
                    if let Some(item) = open_item_row(&vaults, d) {
                        saves.push(item);
                    }
                    drop.push((*kind, *id));
                }
                (RecordKind::Item, None) => {
                    deleted_blobs.push(*id);
                    drop.push((*kind, *id));
                }
                (RecordKind::VaultMeta, Some(d)) => {
                    meta = vaults
                        .iter()
                        .find_map(|v| Vault::from_shared(vault_id, v.key().duplicate(), d).ok())
                        .map(|v| v.meta);
                    drop.push((*kind, *id));
                }
                (RecordKind::Manifest, _) => drop.push((*kind, *id)),
                _ => {}
            }
        }
        // A deletion with no write of the same item is a delete.
        let mut deletes = Vec::new();
        for blob in deleted_blobs {
            let Some(base) = self.store.get_in(zone, RecordKind::Item, blob)? else {
                continue;
            };
            let Ok((_, rest)) = split_item_record(&base.data) else {
                continue;
            };
            let Ok(rec) = ItemRecord::decode(rest) else {
                continue;
            };
            if !saves.iter().any(|i| i.id == rec.item_id) {
                deletes.push(rec.item_id);
            }
        }
        self.store.begin_batch()?;
        let result = (|| {
            self.store.drop_zone_pending(zone, &drop)?;
            let mut vault = self.open_shared(vault_id)?;
            if let Some(meta) = meta
                && meta != vault.meta
            {
                vault = self.shared_update_meta(&vault, meta)?;
            }
            for mut item in saves {
                item.vault_id = vault_id;
                self.shared_save_item(&vault, item)?;
            }
            for item_id in deletes {
                let loaded = self.shared_served(&vault, Use::Read)?;
                if loaded.listed(item_id).is_some() {
                    self.shared_delete_item(&vault, item_id)?;
                }
            }
            Ok(())
        })()
        .and_then(|()| self.store.commit_batch());
        if let Err(e) = result {
            let _ = self.store.rollback_batch();
            return Err(e);
        }
        Ok(())
    }

    /// My resealing lost the manifest race (a member wrote between my
    /// phase 1 and phase 2): the server's manifest, verified under the
    /// generation it was written at, is taken over. Each item it lists at
    /// the version I resealed keeps my record; any other version is
    /// resealed now from the old key (or kept when already written under
    /// the new one); my records of items it no longer lists are collected.
    /// The new manifest replaces my pending one, conditional on the
    /// server's.
    fn rebase_rekey(&mut self, vault_id: Id) -> Result<()> {
        let mut state = self.store.share_state(vault_id)?.ok_or(Error::NotFound)?;
        let zone = state.zone;
        let mut push = state.push.clone().ok_or(Error::NotFound)?;
        let base = self
            .store
            .zone_base_record(zone, RecordKind::Manifest, vault_id)?
            .ok_or(Error::NotFound)?;
        let old_head = state.ancestors.first().ok_or(Error::NotFound)?.clone();
        let vaults = self.generation_vaults(&state)?;
        let new = vaults.first().ok_or(Error::NotFound)?;
        let old = vaults
            .iter()
            .find(|v| key_commit(v.key(), vault_id, old_head.generation) == old_head.key_commit)
            .ok_or(Error::NotFound)?;
        let sm = SharedSignedManifest::decode(&base.data)?;
        let view = MembershipView {
            head: &old_head,
            ancestors: &state.ancestors[1..],
        };
        let theirs =
            verify_shared_manifest(old, &view, &sm, Some(&push.from), None).or_else(|_| {
                let view = state.view();
                verify_shared_manifest(new, &view, &sm, None, None)
            })?;
        let mut entries: Vec<ManifestEntry> = Vec::new();
        let mut writes: Vec<(Zone, Record, Option<u64>)> = Vec::new();
        let mut kept_blobs = BTreeSet::new();
        let items = self.store.list_in(zone, RecordKind::Item)?;
        for e in &theirs.entries {
            if let Some((_, _, blob, mine)) = push
                .resealed
                .iter()
                .find(|(item, from, _, _)| *item == e.item_id && *from == e.version)
            {
                entries.push(mine.clone());
                kept_blobs.insert(*blob);
                continue;
            }
            // Written by someone else since: find its record.
            let Some((blob, rec)) = items.iter().find_map(|r| {
                let (prefix, rest) = split_item_record(&r.data).ok()?;
                let rec = ItemRecord::decode(rest).ok()?;
                (prefix == vault_id
                    && rec.item_id == e.item_id
                    && rec.version == e.version
                    && crate::manifest::record_hash(&rec) == e.record_hash)
                    .then_some((r.id, rec))
            }) else {
                return Err(crate::IntegrityError::ManifestMissingItem.into());
            };
            if new.open_item(&rec).is_ok() {
                entries.push(e.clone());
                continue;
            }
            let item = old.open_item(&rec)?;
            let version = rec
                .version
                .checked_add(1)
                .ok_or(Error::InvalidFormat("item version"))?;
            let sealed = new.reseal_item(&item, version)?;
            entries.push(entry(&sealed));
            writes.push((zone, item_record(vault_id, &sealed)?, None));
            if !push.collect.contains(&blob) {
                push.collect.push(blob);
            }
        }
        for (_, _, blob, _) in &push.resealed {
            if !kept_blobs.contains(blob) && !push.collect.contains(blob) {
                push.collect.push(*blob);
            }
        }
        let m = Manifest::next(Some(&theirs), vault_id, entries)?
            .with_meta(&new.meta)
            .with_membership(state.head.seen(), state.head.generation);
        let sm = sign_shared_manifest(new, &self.account.keyset().signing, self.me(), &m)?;
        let pending = self
            .store
            .get_in(zone, RecordKind::Manifest, vault_id)?
            .map(|r| r.version);
        writes.push((
            zone,
            Record {
                kind: RecordKind::Manifest,
                id: vault_id,
                version: m.seq,
                data: sm.encode(),
            },
            pending,
        ));
        push.from = SeenManifest {
            seq: theirs.seq,
            hash: manifest_hash(&theirs),
        };
        if let Some(x) = state.exposures.last_mut() {
            x.items = m.entries.iter().map(|e| (e.item_id, e.version)).collect();
        }
        state.push = Some(push);
        state.last_manifest = Some(SeenManifest {
            seq: m.seq,
            hash: manifest_hash(&m),
        });
        self.store
            .put_all_zoned(writes, vec![], None, std::slice::from_ref(&state))
    }
}
