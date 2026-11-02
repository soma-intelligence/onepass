//! Shared vaults and zones on the repository (sharing plan 2): zone
//! accesses (Task 5b), then sharing, members and roles (Tasks 6 to 15).

use super::reseal::item_record;
use super::{Loaded, Repository, Use, entry, split_item_record};
use crate::contact::ContactLevel;
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
            None => self
                .write_zone_access(target, Some(home), &seed)
                .map(|_| ()),
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
        Ok(out)
    }

    /// The transport ran `a`: drop it from its zone's queue. An action no
    /// longer queued is a no-op.
    pub fn share_action_done(&mut self, a: &ShareAction) -> Result<()> {
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
            .put_all_zoned(vec![], vec![], None, std::slice::from_ref(&state))
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
        let mut out = Vec::new();
        for state in self.store.share_states()? {
            let name = self
                .open_shared_with(&state)
                .map(|v| v.meta.name)
                .unwrap_or_default();
            out.push(self.shared_info(&state, &name)?);
        }
        Ok(out)
    }

    /// For each `ZoneAccess` of a vault zone without a local share state:
    /// pin the zone's membership head when its signer is this account
    /// (another device of mine) or a `Verified` contact of the book with
    /// `Manage` in that body (ruling A-14). Anything else waits.
    pub fn adopt_zone_accesses(&mut self) -> Result<()> {
        let me = self.me();
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
            let signer = signed.body.signer;
            let key = if signer.account_id == me.account_id {
                Some(self.account.params.signing_pub.clone())
            } else {
                match self.contact(signer.account_id)? {
                    Some(c)
                        if c.level == ContactLevel::Verified
                            && signed.body.member(signer.account_id).is_some_and(|m| {
                                m.role == Role::Manage && m.sign_pub == c.sign_pub
                            }) =>
                    {
                        Some(c.sign_pub.clone())
                    }
                    _ => None,
                }
            };
            let Some(key) = key else {
                continue;
            };
            let Ok(head) = accept_first(&signed, &key) else {
                continue;
            };
            if head.member(me.account_id).is_none() {
                continue;
            }
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
        if state.last_manifest.as_ref() != Some(&seen) || state.last_meta != meta {
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
        let (blob, _) = loaded.listed(item_id).ok_or(Error::NotFound)?;
        let mut deletes = vec![(state.zone, RecordKind::Item, *blob)];
        deletes.extend(
            loaded
                .ignored_of(item_id)
                .map(|b| (state.zone, RecordKind::Item, b)),
        );
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
