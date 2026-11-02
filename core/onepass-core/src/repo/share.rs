//! Shared vaults and zones on the repository (sharing plan 2): zone
//! accesses (Task 5b), then sharing, members and roles (Tasks 6 to 15).

use super::{Repository, split_item_record};
use crate::contact::ContactLevel;
use crate::lineage::identity_id;
use crate::share::{
    AccessTarget, MEMBERSHIP_FORMAT, Member, MemberRef, MemberView, MembershipBody,
    MembershipReason, Role, ShareAction, ShareState, SharedVaultInfo, SignedZoneAccess,
    ZONE_ACCESS_KIND, ZoneAccess, ZoneHome, ZoneMailboxKind, ZoneSeed, accept_first,
    identity_pub_hash, key_commit, sign_membership, sign_shared_manifest, wrap_member_key,
};
use crate::store::{Record, RecordKind, RecordStore, Zone};
use crate::vault::Vault;
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
