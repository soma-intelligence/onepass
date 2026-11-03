//! Shared vaults and zones on the repository (sharing plan 2): zone
//! accesses (Task 5b), then sharing, members and roles (Tasks 6 to 15).

use super::reseal::item_record;
use super::{Loaded, Repository, Use, entry, split_item_record};
use crate::contact::{ContactEntry, ContactLevel, pair_id};
use crate::lineage::identity_id;
use crate::manifest::{
    Manifest, ManifestEntry, SeenManifest, check_records, manifest_hash, meta_hash, record_hash,
    sign_manifest,
};
use crate::model::Item;
use crate::share::{
    AccessTarget, MEMBERSHIP_FORMAT, Member, MemberRef, MemberView, MembershipBody,
    MembershipReason, Role, ShareAction, ShareState, SharedVaultInfo, SignedZoneAccess,
    ZONE_ACCESS_KIND, ZoneAccess, ZoneHome, ZoneMailboxKind, ZoneSeed, accept_first,
    identity_pub_hash, key_commit, sign_membership, sign_shared_manifest, wrap_member_key,
};
use crate::share::{
    InviteRecord, ShareInvite, ShareInviteView, accept_next, open_zone_credential, server_role,
    wrap_zone_credential,
};
use crate::share::{
    MemberKey, SharedSignedManifest, SignedMembership, member_key_id, open_member_key,
    verify_shared_manifest,
};
use crate::store::{Record, RecordKind, RecordStore, Zone};
use crate::vault::{ItemRecord, Vault, VaultMeta};
use crate::vaultlist::VaultListEntry;
use crate::{Error, Id, IntegrityError, Result, ValidationError};

/// Every zone access in `store`'s private zone, decoded but neither
/// verified nor opened: what a locked device may show (which zones, on
/// which servers). Records that do not decode are skipped.
pub fn list_zone_accesses(store: &impl RecordStore) -> Result<Vec<ZoneAccess>> {
    Ok(store
        .list(ZONE_ACCESS_KIND)?
        .iter()
        .filter_map(|r| {
            SignedZoneAccess::decode(&r.data)
                .ok()
                .filter(|s| s.access.target.record_id().ok() == Some(r.id))
        })
        .map(|s| s.access)
        .collect())
}

impl<S: RecordStore> Repository<S> {
    /// This session's account and identity.
    pub fn me(&self) -> MemberRef {
        MemberRef {
            account_id: self.account.params.account_id,
            identity_id: identity_id(&self.account.params.identity_pub),
        }
    }

    /// The stored access record of `target`, decoded, its signature checked
    /// against this account and its id matching its target.
    fn stored_access(&self, target: AccessTarget) -> Result<Option<(Record, SignedZoneAccess)>> {
        let id = target.record_id()?;
        let Some(r) = self.store.get(ZONE_ACCESS_KIND, id)? else {
            return Ok(None);
        };
        let s = SignedZoneAccess::decode(&r.data)?;
        if s.access.target != target {
            return Err(IntegrityError::WrongContext.into());
        }
        s.verify(
            self.account.params.account_id,
            &self.account.params.signing_pub,
        )?;
        Ok(Some((r, s)))
    }

    /// My access to `target` and its opened seed. Refused: a record signed
    /// by another key (`Integrity(Signature)`), an envelope that does not
    /// open for this account (`Crypto`), a seed that does not match its
    /// credential id (`Integrity(WrongContext)`).
    pub fn zone_access(&self, target: AccessTarget) -> Result<Option<(ZoneAccess, ZoneSeed)>> {
        let Some((_, s)) = self.stored_access(target)? else {
            return Ok(None);
        };
        let seed = s.open(
            self.account.params.account_id,
            &self.account.params.signing_pub,
            self.account.keyset(),
        )?;
        Ok(Some((s.access, seed)))
    }

    /// Every verified access of this account, without seeds.
    pub fn zone_accesses(&self) -> Result<Vec<ZoneAccess>> {
        let mut out = Vec::new();
        for r in self.store.list(ZONE_ACCESS_KIND)? {
            let Ok(s) = SignedZoneAccess::decode(&r.data) else {
                continue;
            };
            if s.access.target.record_id().ok() != Some(r.id) {
                continue;
            }
            if s.verify(
                self.account.params.account_id,
                &self.account.params.signing_pub,
            )
            .is_ok()
            {
                out.push(s.access);
            }
        }
        Ok(out)
    }

    /// The record of my access to `target` with `home` and `seed`, at the
    /// version after the stored one, for the caller to write in its
    /// transaction (with the stored version as the expected one).
    pub(crate) fn zone_access_record(
        &self,
        target: AccessTarget,
        home: Option<ZoneHome>,
        seed: &ZoneSeed,
    ) -> Result<(Record, Option<u64>)> {
        let id = target.record_id()?;
        let expected = self.store.get(ZONE_ACCESS_KIND, id)?.map(|r| r.version);
        let s = SignedZoneAccess::seal(
            self.account.params.account_id,
            &self.account.params.kem_pub,
            &self.account.keyset().signing,
            target,
            home,
            seed,
        )?;
        let version = expected.map_or(Ok(1), |v| {
            v.checked_add(1)
                .ok_or(Error::InvalidFormat("zone access version"))
        })?;
        Ok((
            Record {
                kind: ZONE_ACCESS_KIND,
                id,
                version,
                data: s.encode(),
            },
            expected,
        ))
    }

    /// Write my access to `target` on its own.
    pub(crate) fn write_zone_access(
        &mut self,
        target: AccessTarget,
        home: Option<ZoneHome>,
        seed: &ZoneSeed,
    ) -> Result<Record> {
        let (r, expected) = self.zone_access_record(target, home, seed)?;
        self.store.put_all_zoned(
            vec![(Zone::Private, r.clone(), expected)],
            vec![],
            None,
            &[],
        )?;
        Ok(r)
    }

    /// `write_zone_access` for the integration tests.
    #[cfg(all(feature = "dev-fast-kdf", debug_assertions))]
    #[doc(hidden)]
    pub fn test_write_zone_access(
        &mut self,
        target: AccessTarget,
        home: Option<ZoneHome>,
        seed: &ZoneSeed,
    ) -> Result<Record> {
        self.write_zone_access(target, home, seed)
    }

    /// Set the mailbox of a zone this account created, once the transport
    /// made it. A home already set is never changed here
    /// (`Validation("zone", "home already set")`): only a `Rekey` body with
    /// `moved_to` moves a zone. Setting the same home again is a no-op.
    pub fn set_zone_home(&mut self, target: AccessTarget, home: ZoneHome) -> Result<()> {
        home.check()?;
        let (access, seed) = self.zone_access(target)?.ok_or(Error::NotFound)?;
        match &access.home {
            Some(h) if *h == home => Ok(()),
            Some(_) => Err(refused("zone", "home already set")),
            None => {
                self.write_zone_access(target, Some(home), &seed)?;
                if let AccessTarget::Zone(Zone::Vault(id)) = target {
                    self.finish_transfer(id, crate::devices::now())?;
                }
                Ok(())
            }
        }
    }

    /// The account's anchor mailbox access: created on the first call
    /// without a home, its seed returned.
    pub fn anchor(&mut self) -> Result<(Option<ZoneHome>, ZoneSeed)> {
        if let Some((a, seed)) = self.zone_access(AccessTarget::Anchor)? {
            return Ok((a.home, seed));
        }
        let seed = ZoneSeed::generate()?;
        self.write_zone_access(AccessTarget::Anchor, None, &seed)?;
        Ok((None, seed))
    }
}

impl<S: RecordStore> Repository<S> {
    /// This account as the member of a body: keys from the session's
    /// params, `Verified` (an account trusts itself).
    fn self_member(&self, role: Role, owner: bool, credential_id: [u8; 16], now: i64) -> Member {
        let me = self.me();
        let p = &self.account.params;
        Member {
            account_id: me.account_id,
            identity_id: me.identity_id,
            identity_pub_hash: identity_pub_hash(&p.identity_pub),
            sign_pub: p.signing_pub.clone(),
            kem_pub: p.kem_pub.clone(),
            role,
            owner,
            level: ContactLevel::Verified,
            added_by: me,
            added_at: now,
            key_pending: false,
            credential_id,
        }
    }

    /// The screens' view of a shared vault from its pinned state.
    pub(crate) fn shared_info(
        &mut self,
        state: &ShareState,
        name: &str,
    ) -> Result<SharedVaultInfo> {
        let me = self.me();
        let mine = state
            .head
            .member(me.account_id)
            .ok_or(Error::NotFound)?
            .clone();
        let mut members = Vec::with_capacity(state.head.members.len());
        for m in &state.head.members {
            let (name_local, keys_changed) = if m.account_id == me.account_id {
                (String::new(), false)
            } else {
                match self.contact(m.account_id)? {
                    Some(c) => (
                        c.name_local.clone(),
                        c.sign_pub != m.sign_pub || c.kem_pub != m.kem_pub,
                    ),
                    None => (String::new(), false),
                }
            };
            members.push(MemberView {
                account_id: m.account_id,
                name_local,
                role: m.role,
                owner: m.owner,
                level: m.level,
                keys_changed,
                key_pending: m.key_pending,
            });
        }
        Ok(SharedVaultInfo {
            vault_id: state.vault_id,
            name: name.to_owned(),
            role: mine.role,
            owner: mine.owner,
            generation: state.head.generation,
            members,
            identity_pending: state.identity_pending.is_some(),
            mcp_hidden: state.mcp_hidden,
        })
    }

    /// Share a personal vault (spec 9.5, 6.2, 9.1 choice C): same vault id,
    /// a fresh key at generation 1 wrapped for this account, every item
    /// resealed, the first membership body (`Create`, this account owner
    /// and manager) and a shared manifest in zone `Vault(id)`; in the same
    /// transaction the vault's private records go, the vault list marks it
    /// deleted, the local share state is written with a
    /// `CreateZoneMailbox` action, and the owner's credential seed is kept
    /// in a `ZoneAccess` without a home.
    ///
    /// Refused: Travel Mode on (`Validation("travel mode")`), a device that
    /// cannot write or sign lists, a vault not among `vaults()`
    /// (`NotFound`), the last live personal vault (`InvalidFormat("last
    /// vault")`, the account profile needs one).
    pub fn share_vault(&mut self, vault: &Vault, now: i64) -> Result<SharedVaultInfo> {
        if !self.travel_parked.is_empty() {
            return Err(refused("travel mode", "active"));
        }
        self.writable()?;
        self.signs_lists()?;
        if vault.zone().is_shared() {
            return Err(refused("vault", "already shared"));
        }
        if self.read_list::<VaultListEntry>()?.is_none() {
            self.maintain_lists(None)?;
        }
        if !self.vaults()?.iter().any(|v| v.id == vault.id) {
            return Err(Error::NotFound);
        }
        let list = self.read_list::<VaultListEntry>()?.ok_or(Error::NotFound)?;
        let other = self
            .vaults()?
            .into_iter()
            .find(|v| v.id != vault.id && !v.zone().is_shared());
        let Some(other) = other else {
            return Err(Error::InvalidFormat("last vault"));
        };
        // The hidden account profile never goes to a shared vault.
        let loaded = self.load(vault)?;
        let profile = loaded
            .records
            .iter()
            .map(|(_, rec)| vault.open_item(rec))
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .find(|i| i.is_profile())
            .map(|i| i.id);
        if let Some(id) = profile {
            self.move_item(id, vault, &other)?;
        }
        let loaded = self.load(vault)?;

        let me = self.me();
        let zone = Zone::Vault(vault.id);
        let (shared, key, meta_blob) = Vault::new_shared(vault.id, vault.meta.clone())?;
        let resealed = self.reseal_vault(vault, &shared, &loaded)?;
        let seed = ZoneSeed::generate()?;
        let owner = self.self_member(Role::Manage, true, seed.credential_id(), now);
        let body = MembershipBody {
            format: MEMBERSHIP_FORMAT,
            vault_id: vault.id,
            seq: 1,
            prev_hash: [0; 32],
            generation: 1,
            key_commit: key_commit(&key, vault.id, 1),
            members: vec![owner],
            removed: Vec::new(),
            signer: me,
            reason: MembershipReason::Create,
            moved_to: None,
            history: Vec::new(),
            issued_at: now,
        };
        let signed = sign_membership(body, &self.account.keyset().signing)?;
        let head = accept_first(&signed, &self.account.params.signing_pub)?;
        let mk = wrap_member_key(&self.account.params.kem_pub, &key, vault.id, 1, &me)?;
        let m = resealed
            .manifest
            .clone()
            .with_meta(&shared.meta)
            .with_membership(head.seen(), 1);
        let sm = sign_shared_manifest(&shared, &self.account.keyset().signing, me, &m)?;

        let mut writes: Vec<(Zone, Record, Option<u64>)> = Vec::new();
        let rec = |kind, id, version, data| Record {
            kind,
            id,
            version,
            data,
        };
        writes.push((
            zone,
            rec(RecordKind::Membership, vault.id, 1, signed.encode()),
            None,
        ));
        writes.push((
            zone,
            rec(RecordKind::MemberKey, mk.id(), 1, mk.encode()),
            None,
        ));
        writes.push((
            zone,
            rec(RecordKind::VaultMeta, vault.id, 1, meta_blob),
            None,
        ));
        writes.push((
            zone,
            rec(RecordKind::Manifest, vault.id, m.seq, sm.encode()),
            None,
        ));
        for r in resealed.items {
            writes.push((zone, r, None));
        }
        let mut deletes: Vec<(Zone, RecordKind, Id)> = [
            RecordKind::VaultKey,
            RecordKind::VaultMeta,
            RecordKind::Manifest,
        ]
        .into_iter()
        .map(|k| (Zone::Private, k, vault.id))
        .collect();
        for (moved, _) in resealed.attachments {
            deletes.push((Zone::Private, RecordKind::Attachment, moved.id));
            writes.push((zone, moved, None));
        }
        for r in self.store.list(RecordKind::Item)? {
            if split_item_record(&r.data).is_ok_and(|(prefix, _)| prefix == vault.id) {
                deletes.push((Zone::Private, RecordKind::Item, r.id));
            }
        }
        for r in self.store.list(RecordKind::Attachment)? {
            if split_item_record(&r.data).is_ok_and(|(prefix, _)| prefix == vault.id)
                && !deletes
                    .iter()
                    .any(|(_, k, id)| *k == RecordKind::Attachment && *id == r.id)
            {
                deletes.push((Zone::Private, RecordKind::Attachment, r.id));
            }
        }
        let mut entries = list.body.entries.clone();
        match entries.iter_mut().find(|e| e.vault_id == vault.id) {
            Some(e) => e.deleted_at = Some(now),
            None => entries.push(VaultListEntry {
                vault_id: vault.id,
                created_at: now,
                deleted_at: Some(now),
            }),
        }
        let (list_rec, list_expected, list_body) = self.list_write(Some(&list), entries)?;
        writes.push((Zone::Private, list_rec, list_expected));
        let (access_rec, access_expected) =
            self.zone_access_record(AccessTarget::Zone(zone), None, &seed)?;
        writes.push((Zone::Private, access_rec, access_expected));
        let mut state = ShareState::new(zone, head);
        state.actions.push(ShareAction::CreateZoneMailbox {
            zone,
            kind: ZoneMailboxKind::Shared,
            owner_public_key: seed.public_key(),
        });
        self.store
            .put_all_zoned(writes, deletes, None, std::slice::from_ref(&state))?;
        self.chain.vault_list = Some(list_body.seen());
        self.forget_vault(vault.id);
        let _ = resealed.from;
        self.shared_info(&state, &shared.meta.name)
    }

    /// The mailbox steps waiting for the transport, every shared vault
    /// together, each zone's in order. A step that needs the zone's mailbox
    /// waits until `set_zone_home` gave it one.
    pub fn pending_share_actions(&self) -> Result<Vec<ShareAction>> {
        let mut out = Vec::new();
        for state in self.store.share_states()? {
            // A departure revokes my credential only once the body and the
            // rekey request are on the server (spec 9.4).
            if state.leaving && !self.store.zone_pending(state.zone)?.is_empty() {
                continue;
            }
            let has_home = self
                .zone_accesses()?
                .iter()
                .any(|a| a.target == AccessTarget::Zone(state.zone) && a.home.is_some());
            for a in &state.actions {
                let needs_home = !matches!(a, ShareAction::CreateZoneMailbox { .. });
                if needs_home && !has_home {
                    break;
                }
                out.push(a.clone());
            }
        }
        out.extend(self.pending_family_actions()?);
        Ok(out)
    }

    /// The transport ran `a`: drop it from its zone's queue. An action no
    /// longer queued is a no-op.
    pub fn share_action_done(&mut self, a: &ShareAction) -> Result<()> {
        if let Zone::Family(_) = a.zone() {
            return self.family_action_done(a);
        }
        let Zone::Vault(id) = a.zone() else {
            return Ok(());
        };
        let Some(mut state) = self.store.share_state(id)? else {
            return Ok(());
        };
        let Some(i) = state.actions.iter().position(|x| x == a) else {
            return Ok(());
        };
        state.actions.remove(i);
        self.store
            .put_all_zoned(vec![], vec![], None, std::slice::from_ref(&state))?;
        self.finish_leave(id)
    }
}

fn refused(field: &str, reason: &'static str) -> Error {
    ValidationError {
        field: field.into(),
        reason,
    }
    .into()
}

impl<S: RecordStore> Repository<S> {
    fn share_state_of(&self, vault: Id) -> Result<ShareState> {
        self.store.share_state(vault)?.ok_or(Error::NotFound)
    }

    /// Open shared vault `vault_id` (spec 6.3): my `MemberKey` of the
    /// pinned head's generation, checked against its key commitment, then
    /// the zone's sealed meta.
    pub fn open_shared(&self, vault_id: Id) -> Result<Vault> {
        let state = self.share_state_of(vault_id)?;
        self.open_shared_with(&state)
    }

    fn open_shared_with(&self, state: &ShareState) -> Result<Vault> {
        let me = self.me();
        let zone = state.zone;
        let g = state.head.generation;
        let mk_rec = self
            .store
            .get_in(
                zone,
                RecordKind::MemberKey,
                member_key_id(state.vault_id, g, &me),
            )?
            .ok_or(Error::NotFound)?;
        let mk = MemberKey::decode(&mk_rec.data)?;
        if mk.vault_id != state.vault_id || mk.generation != g || mk.member() != me {
            return Err(IntegrityError::WrongContext.into());
        }
        let key = open_member_key(self.account.keyset(), &mk, &state.head.key_commit)?;
        let meta = self
            .store
            .get_in(zone, RecordKind::VaultMeta, state.vault_id)?
            .ok_or(Error::InvalidFormat("vault meta"))?;
        Vault::from_shared(state.vault_id, key, &meta.data)
    }

    /// Every shared vault that opens, by id. One that does not open is left
    /// out here (its screen shows it through `shared_vaults`); during
    /// Travel Mode only the travel-safe ones.
    pub(crate) fn open_shared_vaults(&self) -> Result<Vec<Vault>> {
        let travel = !self.travel_parked.is_empty();
        let mut out = Vec::new();
        for state in self.store.share_states()? {
            if let Ok(v) = self.open_shared_with(&state)
                && (!travel || v.meta.travel_safe)
            {
                out.push(v);
            }
        }
        out.sort_by_key(|v| v.id);
        Ok(out)
    }

    /// The shared vaults this account is a member of, as the screens show
    /// them. Zone accesses synced from this account's other devices are
    /// adopted first (ruling A-14).
    pub fn shared_vaults(&mut self) -> Result<Vec<SharedVaultInfo>> {
        self.adopt_zone_accesses()?;
        self.follow_heads()?;
        let mut out = Vec::new();
        for mut state in self.store.share_states()? {
            // On its way out: erased once its last steps ran.
            if state.leaving {
                continue;
            }
            let name = self
                .open_shared_with(&state)
                .map(|v| v.meta.name)
                .unwrap_or_default();
            if !name.is_empty() && name != state.name {
                state.name = name.clone();
                self.store
                    .put_all_zoned(vec![], vec![], None, std::slice::from_ref(&state))?;
            }
            out.push(self.shared_info(&state, &name)?);
        }
        Ok(out)
    }

    /// For each `ZoneAccess` of a vault zone without a local share state:
    /// pin the zone's membership head when `pin_head_from` accepts it
    /// (ruling A-14): signed by this account or by an `Active` contact of
    /// the book, naming me under my current keys. Anything else waits.
    pub fn adopt_zone_accesses(&mut self) -> Result<()> {
        for access in self.zone_accesses()? {
            let AccessTarget::Zone(zone @ Zone::Vault(id)) = access.target else {
                continue;
            };
            if self.store.share_state(id)?.is_some() {
                continue;
            }
            let Some(rec) = self.store.get_in(zone, RecordKind::Membership, id)? else {
                continue;
            };
            let Ok(signed) = SignedMembership::decode(&rec.data) else {
                continue;
            };
            let Ok(head) = self.pin_head_from(&signed) else {
                continue;
            };
            let state = ShareState::new(zone, head);
            self.store
                .put_all_zoned(vec![], vec![], None, std::slice::from_ref(&state))?;
        }
        Ok(())
    }

    /// Hide a shared vault from the MCP server on this device (only ever
    /// restricts: a vault whose meta refuses MCP stays hidden).
    pub fn set_shared_vault_mcp_hidden(&mut self, vault_id: Id, hidden: bool) -> Result<()> {
        let mut state = self.share_state_of(vault_id)?;
        state.mcp_hidden = hidden;
        self.store
            .put_all_zoned(vec![], vec![], None, std::slice::from_ref(&state))
    }

    /// Whether the MCP server may see `vault`: its meta allows it, and for
    /// a shared vault, this device did not hide it.
    pub fn mcp_visible(&self, vault: &Vault) -> Result<bool> {
        if !vault.meta.mcp_access {
            return Ok(false);
        }
        match vault.zone() {
            Zone::Vault(id) => Ok(!self.share_state_of(id)?.mcp_hidden),
            _ => Ok(true),
        }
    }

    /// My role in the pinned head: refused below `min`.
    fn require_role(&self, state: &ShareState, min: Role) -> Result<()> {
        let me = self.me();
        let role = state
            .head
            .member(me.account_id)
            .filter(|m| m.identity_id == me.identity_id)
            .map(|m| m.role)
            .ok_or_else(|| refused("role", "not a member"))?;
        if role < min {
            return Err(refused(
                "role",
                if min == Role::Manage {
                    "manager only"
                } else {
                    "read only"
                },
            ));
        }
        Ok(())
    }

    /// `served` for a shared vault: the zone's manifest verified against
    /// the pinned chain (`verify_shared_manifest`) and the records it
    /// lists. Records of the vault the manifest does not list are ignored
    /// (a race lost by another member). The manifest and its meta hash are
    /// then remembered in the share state.
    pub(crate) fn shared_served(&mut self, vault: &Vault, use_: Use) -> Result<Loaded> {
        if use_ != Use::Read {
            self.writable()?;
        }
        self.follow_head(vault.id)?;
        let mut state = self.share_state_of(vault.id)?;
        let zone = state.zone;
        let rec = self
            .store
            .get_in(zone, RecordKind::Manifest, vault.id)?
            .ok_or(IntegrityError::ManifestMissingItem)?;
        let sm = SharedSignedManifest::decode(&rec.data)?;
        let manifest = verify_shared_manifest(
            vault,
            &state.view(),
            &sm,
            state.last_manifest.as_ref(),
            state.last_meta,
        )?;
        // Ruling A-12: an identity seen to rotate signs nothing new.
        if state.retired_signers.contains_key(&sm.signer)
            && state
                .last_manifest
                .as_ref()
                .is_some_and(|m| manifest.seq > m.seq)
        {
            return Err(IntegrityError::Signature.into());
        }
        let mut records = Vec::new();
        let mut ignored = Vec::new();
        for r in self.store.list_in(zone, RecordKind::Item)? {
            let (prefix, body) = split_item_record(&r.data)?;
            if prefix != vault.id {
                continue;
            }
            let item =
                ItemRecord::decode(body).map_err(|_| IntegrityError::ManifestUnexpectedItem)?;
            let listed = manifest.entries.iter().any(|e| {
                e.item_id == item.item_id
                    && e.version == item.version
                    && record_hash(&item) == e.record_hash
            });
            if listed {
                records.push((r.id, item));
            } else {
                ignored.push((r.id, item.item_id));
            }
        }
        records.sort_by_key(|(_, r)| r.item_id);
        let plain: Vec<ItemRecord> = records.iter().map(|(_, r)| r.clone()).collect();
        check_records(&manifest, &plain)?;
        let seen = SeenManifest {
            seq: manifest.seq,
            hash: manifest_hash(&manifest),
        };
        let meta = manifest.ext.as_ref().and_then(|e| e.meta_hash);
        // Ruling A-13: a member whose manifest names my IdentityUpdate (or
        // a later body) follows my new identity.
        let mut confirmed = false;
        if let Some((seq, list)) = &mut state.self_update
            && sm.signer.account_id != self.me().account_id
            && manifest
                .ext
                .as_ref()
                .and_then(|e| e.membership.as_ref())
                .is_some_and(|m| m.seq >= *seq)
            && !list.contains(&sm.signer.account_id)
        {
            list.push(sm.signer.account_id);
            confirmed = true;
        }
        if confirmed || state.last_manifest.as_ref() != Some(&seen) || state.last_meta != meta {
            state.last_manifest = Some(seen);
            state.last_meta = meta;
            self.store
                .put_all_zoned(vec![], vec![], None, std::slice::from_ref(&state))?;
        }
        Ok(Loaded {
            manifest,
            records,
            ignored,
        })
    }

    /// One shared write: `items` (new records) and `deletes` in the zone,
    /// with the next manifest over `entries`, signed by me under the pinned
    /// head, in one transaction conditional on the manifest loaded.
    fn shared_commit(
        &mut self,
        vault: &Vault,
        state: &ShareState,
        loaded: &Loaded,
        entries: Vec<ManifestEntry>,
        mut writes: Vec<(Zone, Record, Option<u64>)>,
        deletes: Vec<(Zone, RecordKind, Id)>,
    ) -> Result<()> {
        let m = Manifest::next(Some(&loaded.manifest), vault.id, entries)?
            .with_meta(&vault.meta)
            .with_membership(state.head.seen(), state.head.generation);
        let sm = sign_shared_manifest(vault, &self.account.keyset().signing, self.me(), &m)?;
        writes.push((
            state.zone,
            Record {
                kind: RecordKind::Manifest,
                id: vault.id,
                version: m.seq,
                data: sm.encode(),
            },
            Some(loaded.manifest.seq),
        ));
        let mut state = state.clone();
        state.last_manifest = Some(SeenManifest {
            seq: m.seq,
            hash: manifest_hash(&m),
        });
        state.last_meta = Some(meta_hash(&vault.meta));
        self.store
            .put_all_zoned(writes, deletes, None, std::slice::from_ref(&state))
    }

    fn writer_state(&mut self, vault: &Vault) -> Result<ShareState> {
        let state = self.share_state_of(vault.id)?;
        if state.access_refused.is_some() {
            return Err(refused("vault", "access refused"));
        }
        if state.leaving {
            return Err(refused("vault", "leaving"));
        }
        if state.moving_to.is_some() || state.head.moved_to.is_some() {
            return Err(refused("vault", "moved"));
        }
        // Spec 12.3 point 2: my new identity waits for a manager.
        if state.identity_pending.is_some() {
            return Err(refused("vault", "identity pending"));
        }
        self.require_role(&state, Role::Write)?;
        // The vault must be open under the head's generation (a rekey
        // since it was opened: reopen it).
        if key_commit(vault.key(), vault.id, state.head.generation) != state.head.key_commit {
            return Err(Error::Conflict);
        }
        Ok(state)
    }

    pub(crate) fn shared_save_item(&mut self, vault: &Vault, item: Item) -> Result<()> {
        let state = self.writer_state(vault)?;
        let loaded = self.shared_served(vault, Use::Write)?;
        let rec = vault.seal_item(&item, loaded.next_version(item.id)?)?;
        let mut entries = loaded.entries_without(item.id);
        entries.push(entry(&rec));
        let mut deletes: Vec<(Zone, RecordKind, Id)> = loaded
            .listed(item.id)
            .map(|(blob, _)| (state.zone, RecordKind::Item, *blob))
            .into_iter()
            .collect();
        deletes.extend(
            loaded
                .ignored_of(item.id)
                .map(|b| (state.zone, RecordKind::Item, b)),
        );
        let writes = vec![(state.zone, item_record(vault.id, &rec)?, None)];
        self.shared_commit(vault, &state, &loaded, entries, writes, deletes)
    }

    pub(crate) fn shared_delete_item(&mut self, vault: &Vault, item_id: Id) -> Result<()> {
        let state = self.writer_state(vault)?;
        let loaded = self.shared_served(vault, Use::Write)?;
        let (blob, rec) = loaded.listed(item_id).ok_or(Error::NotFound)?;
        let mut deletes = vec![(state.zone, RecordKind::Item, *blob)];
        deletes.extend(
            loaded
                .ignored_of(item_id)
                .map(|b| (state.zone, RecordKind::Item, b)),
        );
        // Its attachments' chunks go in the same transaction.
        if let Ok(item) = vault.open_item(rec) {
            for r in &item.attachments {
                for id in crate::attachment::chunk_ids(r).unwrap_or_default() {
                    if self
                        .store
                        .get_in(state.zone, RecordKind::Attachment, id)?
                        .is_some()
                    {
                        deletes.push((state.zone, RecordKind::Attachment, id));
                    }
                }
            }
        }
        let entries = loaded.entries_without(item_id);
        self.shared_commit(vault, &state, &loaded, entries, vec![], deletes)
    }

    /// Move an item between two vaults, one of them at least shared: both
    /// manifests and both records in one transaction.
    pub(crate) fn shared_move_item(&mut self, item_id: Id, from: &Vault, to: &Vault) -> Result<()> {
        self.writable()?;
        let src = self.served(from, Use::Write)?;
        let (blob, rec) = src.listed(item_id).ok_or(Error::NotFound)?.clone();
        let dst = self.served(to, Use::Write)?;
        let moved = from.move_item(to, &rec, dst.next_version(item_id)?)?;
        let mut writes: Vec<(Zone, Record, Option<u64>)> = Vec::new();
        let mut deletes: Vec<(Zone, RecordKind, Id)> = vec![(from.zone(), RecordKind::Item, blob)];
        writes.push((to.zone(), item_record(to.id, &moved)?, None));
        if let Some((b, _)) = dst.listed(item_id) {
            deletes.push((to.zone(), RecordKind::Item, *b));
        }
        // The attachments' chunks change zone with the item, re-wrapped
        // for `to`, in the same transaction.
        if let Ok(item) = from.open_item(&rec) {
            for r in &item.attachments {
                for id in crate::attachment::chunk_ids(r).unwrap_or_default() {
                    let Some(chunk) = self.store.get_in(from.zone(), RecordKind::Attachment, id)?
                    else {
                        continue;
                    };
                    let moved = crate::attachment::rewrap(from, to, &chunk)?;
                    let expected = self
                        .store
                        .get_in(to.zone(), RecordKind::Attachment, id)?
                        .map(|r| r.version);
                    writes.push((to.zone(), moved, expected));
                    deletes.push((from.zone(), RecordKind::Attachment, id));
                }
            }
        }
        let mut to_entries = dst.entries_without(item_id);
        to_entries.push(entry(&moved));
        let from_entries = src.entries_without(item_id);
        let mut shares = Vec::new();
        for (v, loaded, entries) in [(to, &dst, to_entries), (from, &src, from_entries)] {
            match v.zone() {
                Zone::Vault(_) => {
                    let mut state = self.writer_state(v)?;
                    let m = Manifest::next(Some(&loaded.manifest), v.id, entries)?
                        .with_meta(&v.meta)
                        .with_membership(state.head.seen(), state.head.generation);
                    let sm =
                        sign_shared_manifest(v, &self.account.keyset().signing, self.me(), &m)?;
                    writes.push((
                        state.zone,
                        Record {
                            kind: RecordKind::Manifest,
                            id: v.id,
                            version: m.seq,
                            data: sm.encode(),
                        },
                        Some(loaded.manifest.seq),
                    ));
                    state.last_manifest = Some(SeenManifest {
                        seq: m.seq,
                        hash: manifest_hash(&m),
                    });
                    state.last_meta = Some(meta_hash(&v.meta));
                    shares.push(state);
                }
                _ => {
                    let m =
                        Manifest::next(Some(&loaded.manifest), v.id, entries)?.with_meta(&v.meta);
                    let sm = sign_manifest(v, &self.account.keyset().signing, &m)?;
                    writes.push((
                        Zone::Private,
                        Record {
                            kind: RecordKind::Manifest,
                            id: v.id,
                            version: m.seq,
                            data: postcard::to_allocvec(&sm)
                                .map_err(|_| Error::InvalidFormat("manifest"))?,
                        },
                        Some(loaded.manifest.seq),
                    ));
                    self.device.last_seen.insert(v.id, super::seen(&m));
                }
            }
        }
        self.store.put_all_zoned(writes, deletes, None, &shares)
    }

    /// Rename or change the options of a shared vault: managers only
    /// (spec 10.2).
    pub(crate) fn shared_update_meta(&mut self, vault: &Vault, meta: VaultMeta) -> Result<Vault> {
        self.writable()?;
        let state = self.share_state_of(vault.id)?;
        self.require_role(&state, Role::Manage)?;
        let loaded = self.shared_served(vault, Use::Write)?;
        let current = self
            .store
            .get_in(state.zone, RecordKind::VaultMeta, vault.id)?
            .ok_or(Error::InvalidFormat("vault meta"))?;
        let updated = vault.with_meta(meta)?;
        let blob = updated.seal_meta_blob()?;
        let version = current.version.checked_add(1).ok_or(Error::Conflict)?;
        let writes = vec![(
            state.zone,
            Record {
                kind: RecordKind::VaultMeta,
                id: vault.id,
                version,
                data: blob,
            },
            Some(current.version),
        )];
        let entries = loaded.manifest.entries.clone();
        self.shared_commit(&updated, &state, &loaded, entries, writes, vec![])?;
        Ok(updated)
    }
}

impl<S: RecordStore> Repository<S> {
    /// The zone this account shares with contact `account_id` (spec 13.5):
    /// `Zone::Contact(pair_id)`, once a `ZoneAccess` of that zone with a
    /// home exists (Task 7b sets it). Otherwise `Validation("contact", "no
    /// zone")`.
    pub fn contact_zone(&mut self, account_id: Id) -> Result<Zone> {
        let zone = Zone::Contact(pair_id(self.me().account_id, account_id));
        let ready = self
            .zone_accesses()?
            .iter()
            .any(|a| a.target == AccessTarget::Zone(zone) && a.home.is_some());
        if !ready {
            return Err(refused("contact", "no zone"));
        }
        Ok(zone)
    }

    /// The next manifest of a shared vault over the same entries, pointing
    /// at `head`: written with each membership change so that a member who
    /// pinned `head` as its first body can verify the zone (plan 2 ruling,
    /// spec 8.2 rule 5 sets aside a manifest naming an unknown body).
    pub(crate) fn manifest_for_head(
        &mut self,
        vault: &Vault,
        head: &MembershipBody,
    ) -> Result<(Record, Option<u64>, SeenManifest)> {
        let loaded = self.shared_served(vault, Use::Write)?;
        let m = Manifest::next(
            Some(&loaded.manifest),
            vault.id,
            loaded.manifest.entries.clone(),
        )?
        .with_meta(&vault.meta)
        .with_membership(head.seen(), head.generation);
        let sm = sign_shared_manifest(vault, &self.account.keyset().signing, self.me(), &m)?;
        Ok((
            Record {
                kind: RecordKind::Manifest,
                id: vault.id,
                version: m.seq,
                data: sm.encode(),
            },
            Some(loaded.manifest.seq),
            SeenManifest {
                seq: m.seq,
                hash: manifest_hash(&m),
            },
        ))
    }

    /// Add contact `contact` to shared vault `vault_id` with `role` (spec
    /// 7.3, 13.4): I manage the vault; the contact is `Active` in my book,
    /// `Verified` for any role above `Read`; its keys are copied from the
    /// book, never from anywhere else; the zone has its mailbox. One
    /// transaction writes the `Add` body, the contact's `MemberKey` of the
    /// current generation, the next manifest naming the new body, the
    /// signed invite in our contact zone (with the contact's credential
    /// seed wrapped for its pinned KEM key) and the share state with a
    /// `GrantCredential` action at `server_role(role)`.
    pub fn add_member(
        &mut self,
        vault_id: Id,
        contact: Id,
        role: Role,
        now: i64,
    ) -> Result<SharedVaultInfo> {
        self.writable()?;
        self.follow_head(vault_id)?;
        let state = self.share_state_of(vault_id)?;
        self.require_role(&state, Role::Manage)?;
        let me = self.me();
        if contact == me.account_id {
            return Err(refused("contact", "self"));
        }
        let c = self
            .contact(contact)?
            .ok_or_else(|| refused("contact", "unknown"))?;
        if !c.usable_for(ContactLevel::Link) {
            return Err(refused("contact", "not active"));
        }
        if role > Role::Read && c.level != ContactLevel::Verified {
            return Err(refused("contact", "not verified"));
        }
        if state.head.member(contact).is_some() {
            return Err(refused("member", "already a member"));
        }
        let zone = state.zone;
        let home = self
            .zone_accesses()?
            .into_iter()
            .find(|a| a.target == AccessTarget::Zone(zone))
            .and_then(|a| a.home)
            .ok_or_else(|| refused("zone", "not created yet"))?;
        let czone = self.contact_zone(contact)?;
        let vault = self.open_shared_with(&state)?;

        let seed = ZoneSeed::generate()?;
        let member = Member {
            account_id: c.account_id,
            identity_id: identity_id(&c.identity_pub),
            identity_pub_hash: identity_pub_hash(&c.identity_pub),
            sign_pub: c.sign_pub.clone(),
            kem_pub: c.kem_pub.clone(),
            role,
            owner: false,
            level: c.level,
            added_by: me,
            added_at: now,
            key_pending: false,
            credential_id: seed.credential_id(),
        };
        let who = member.member_ref();
        let mut body = state.head.next(me, MembershipReason::Add, now)?;
        let at = body
            .members
            .partition_point(|m| m.account_id < member.account_id);
        body.members.insert(at, member);
        let signed = sign_membership(body, &self.account.keyset().signing)?;
        let head = accept_next(&state.head, &signed)?;
        let g = head.generation;
        let mk = wrap_member_key(&c.kem_pub, vault.key(), vault_id, g, &who)?;
        let credential = wrap_zone_credential(&c.kem_pub, &seed, zone, home.mailbox_id, &who)?;
        let invite = ShareInvite::sign(
            vault_id,
            signed.clone(),
            home,
            credential,
            me,
            &self.account.keyset().signing,
        )?;
        let invite = InviteRecord::Vault(invite);
        let (manifest_rec, manifest_expected, seen) = self.manifest_for_head(&vault, &head)?;
        // `manifest_for_head` refreshed the state's last manifest.
        let mut state = self.share_state_of(vault_id)?;

        let writes = vec![
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
                    kind: RecordKind::MemberKey,
                    id: mk.id(),
                    version: 1,
                    data: mk.encode(),
                },
                None,
            ),
            (zone, manifest_rec, manifest_expected),
            (
                czone,
                Record {
                    kind: RecordKind::ShareInvite,
                    id: invite.id(),
                    version: 1,
                    data: invite.encode(),
                },
                None,
            ),
        ];
        state.advance(head);
        state.last_manifest = Some(seen);
        state.last_meta = Some(meta_hash(&vault.meta));
        let (zrole, put_kinds) = server_role(role);
        state.actions.push(ShareAction::GrantCredential {
            zone,
            public_key: seed.public_key(),
            role: zrole,
            put_kinds,
        });
        self.store
            .put_all_zoned(writes, vec![], None, std::slice::from_ref(&state))?;
        self.shared_info(&state, &vault.meta.name)
    }

    /// The contact zones this account has an access to.
    pub(crate) fn contact_zones(&self) -> Result<Vec<Zone>> {
        Ok(self
            .zone_accesses()?
            .into_iter()
            .filter_map(|a| match a.target {
                AccessTarget::Zone(z @ Zone::Contact(_)) => Some(z),
                _ => None,
            })
            .collect())
    }

    /// An invite of a contact zone checked for this account (spec 7.3):
    /// in the zone of the pair, from an `Active` contact of the book whose
    /// book keys sign it, the signer `Manage` in the body with those keys,
    /// and me a member of the body under my current keys. Returns the
    /// invite, the pinned first body, the contact and my member entry.
    pub(crate) fn checked_invite(
        &mut self,
        zone: Zone,
        rec: &Record,
    ) -> Result<(ShareInvite, MembershipBody, ContactEntry, Member)> {
        let InviteRecord::Vault(invite) = InviteRecord::decode(&rec.data)? else {
            return Err(refused("invite", "not a vault invite"));
        };
        if rec.id != InviteRecord::Vault(invite.clone()).id() {
            return Err(IntegrityError::WrongContext.into());
        }
        let me = self.me();
        let from = invite.signer;
        if from.account_id == me.account_id {
            return Err(refused("invite", "mine"));
        }
        if zone != Zone::Contact(pair_id(me.account_id, from.account_id)) {
            return Err(IntegrityError::WrongContext.into());
        }
        let c = self
            .contact(from.account_id)?
            .ok_or_else(|| refused("invite", "unknown signer"))?;
        if !c.usable_for(ContactLevel::Link) || identity_id(&c.identity_pub) != from.identity_id {
            return Err(refused("invite", "unknown signer"));
        }
        invite.verify(&c.sign_pub)?;
        if invite.membership.body.signer != from {
            return Err(IntegrityError::WrongContext.into());
        }
        let head = accept_first(&invite.membership, &c.sign_pub)?;
        let signer = head.member(from.account_id).ok_or(Error::NotFound)?;
        if signer.level != ContactLevel::Verified || signer.kem_pub != c.kem_pub {
            return Err(refused("invite", "signer keys"));
        }
        let p = &self.account.params;
        let mine = head
            .member(me.account_id)
            .filter(|m| {
                m.identity_id == me.identity_id
                    && m.sign_pub == p.signing_pub
                    && m.kem_pub == p.kem_pub
                    && m.identity_pub_hash == identity_pub_hash(&p.identity_pub)
            })
            .ok_or_else(|| refused("invite", "not for my keys"))?
            .clone();
        if !trusts_signer_for(c.level, mine.role) {
            return Err(refused("invite", "signer not verified"));
        }
        Ok((invite, head, c, mine))
    }

    /// The vault invites waiting for this account, from `Active` contacts
    /// of the book only; one whose vault I already joined is left out.
    pub fn share_invites(&mut self) -> Result<Vec<ShareInviteView>> {
        let mut out = Vec::new();
        for zone in self.contact_zones()? {
            for rec in self.store.list_in(zone, RecordKind::ShareInvite)? {
                let Ok((invite, _, c, mine)) = self.checked_invite(zone, &rec) else {
                    continue;
                };
                if self.store.share_state(invite.vault_id)?.is_some() {
                    continue;
                }
                out.push(ShareInviteView {
                    id: rec.id,
                    vault_name_hint: None,
                    from_name_local: c.name_local.clone(),
                    role: mine.role,
                    server_host: invite.home.host().to_owned(),
                });
            }
        }
        out.sort_by_key(|v| v.id);
        Ok(out)
    }

    fn find_invite(&self, invite: Id) -> Result<(Zone, Record)> {
        for zone in self.contact_zones()? {
            if let Some(r) = self.store.get_in(zone, RecordKind::ShareInvite, invite)? {
                return Ok((zone, r));
            }
        }
        Err(Error::NotFound)
    }

    /// Accept invite `invite` (spec 7.3): checked as `share_invites` does,
    /// the body pinned as the first head, my credential seed opened and
    /// matched against my member entry, my `ZoneAccess` written with the
    /// invite's home and the share state created, in one transaction.
    pub fn accept_share_invite(&mut self, invite: Id, now: i64) -> Result<SharedVaultInfo> {
        let _ = now;
        self.writable()?;
        let (zone, rec) = self.find_invite(invite)?;
        let (inv, head, _, mine) = self.checked_invite(zone, &rec)?;
        if self.store.share_state(inv.vault_id)?.is_some() {
            return Err(refused("vault", "already joined"));
        }
        let vzone = Zone::Vault(inv.vault_id);
        let seed = open_zone_credential(
            self.account.keyset(),
            &inv.credential,
            vzone,
            inv.home.mailbox_id,
            &self.me(),
        )?;
        if seed.credential_id() != mine.credential_id {
            return Err(IntegrityError::WrongContext.into());
        }
        let (access, expected) =
            self.zone_access_record(AccessTarget::Zone(vzone), Some(inv.home.clone()), &seed)?;
        let state = ShareState::new(vzone, head);
        self.store.put_all_zoned(
            vec![(Zone::Private, access, expected)],
            vec![],
            None,
            std::slice::from_ref(&state),
        )?;
        let name = self
            .open_shared_with(&state)
            .map(|v| v.meta.name)
            .unwrap_or_default();
        self.shared_info(&state, &name)
    }

    /// Decline invite `invite`: its record leaves our contact zone.
    pub fn decline_share_invite(&mut self, invite: Id) -> Result<()> {
        self.writable()?;
        let (zone, _) = self.find_invite(invite)?;
        self.store.put_all_zoned(
            vec![],
            vec![(zone, RecordKind::ShareInvite, invite)],
            None,
            &[],
        )
    }

    /// Join a shared vault from the zone's membership head (ruling A-14):
    /// another device of mine accepted, its `ZoneAccess` synced here.
    /// `NotFound` while the access or the zone's head is missing here,
    /// `Validation` when the head is not one this account may pin.
    pub fn join_from_head(&mut self, vault_id: Id, now: i64) -> Result<SharedVaultInfo> {
        let _ = now;
        if let Some(state) = self.store.share_state(vault_id)? {
            let name = self
                .open_shared_with(&state)
                .map(|v| v.meta.name)
                .unwrap_or_default();
            return self.shared_info(&state, &name);
        }
        let zone = Zone::Vault(vault_id);
        if self.zone_access(AccessTarget::Zone(zone))?.is_none() {
            return Err(Error::NotFound);
        }
        let rec = self
            .store
            .get_in(zone, RecordKind::Membership, vault_id)?
            .ok_or(Error::NotFound)?;
        let signed = SignedMembership::decode(&rec.data)?;
        let head = self.pin_head_from(&signed)?;
        let state = ShareState::new(zone, head);
        self.store
            .put_all_zoned(vec![], vec![], None, std::slice::from_ref(&state))?;
        let name = self
            .open_shared_with(&state)
            .map(|v| v.meta.name)
            .unwrap_or_default();
        self.shared_info(&state, &name)
    }

    /// A body this account may pin without its history: signed by me, or
    /// by an `Active` contact of the book whose book keys are the signer's
    /// in the body (the rule of `accept_share_invite`), and naming me under
    /// my current keys.
    pub(crate) fn pin_head_from(&mut self, signed: &SignedMembership) -> Result<MembershipBody> {
        let me = self.me();
        let signer = signed.body.signer;
        let (key, seen) = if signer.account_id == me.account_id {
            (
                self.account.params.signing_pub.clone(),
                ContactLevel::Verified,
            )
        } else {
            let c = self
                .contact(signer.account_id)?
                .ok_or_else(|| refused("membership", "unknown signer"))?;
            if !c.usable_for(ContactLevel::Link)
                || identity_id(&c.identity_pub) != signer.identity_id
            {
                return Err(refused("membership", "unknown signer"));
            }
            (c.sign_pub.clone(), c.level)
        };
        let head = accept_first(signed, &key)?;
        let p = &self.account.params;
        let mine = head
            .member(me.account_id)
            .filter(|m| {
                m.identity_id == me.identity_id
                    && m.sign_pub == p.signing_pub
                    && m.kem_pub == p.kem_pub
            })
            .ok_or_else(|| refused("membership", "not for my keys"))?;
        if !trusts_signer_for(seen, mine.role) {
            return Err(refused("membership", "signer not verified"));
        }
        Ok(head)
    }
}

/// Decision 1 seen from the member's side: a manager I hold only at the
/// `Link` level may have come through a link read in transit (A13), so I
/// take from them a `Read` place only, never one where I would write my
/// own secrets into a vault an impersonator manages.
fn trusts_signer_for(seen: ContactLevel, my_role: Role) -> bool {
    seen == ContactLevel::Verified || my_role == Role::Read
}
