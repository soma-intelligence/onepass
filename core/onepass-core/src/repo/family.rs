//! The family on the repository (sharing plan 3 Task 2, spec 11.1, 11.2,
//! S15, S16, decisions 1, 2, 13): one family per account, its chained
//! body in the zone `Family(family_id)`, its shared vaults driven by the
//! operations of plan 2.
//!
//! The pinned head and the mailbox steps of the family zone live in the
//! device-local metadata `family.state` (never synced). The family body
//! lists accounts and vault ids only: an organizer reads nothing of a
//! member's personal vaults (S16).

use serde::{Deserialize, Serialize};

use super::Repository;
use crate::contact::{ContactEntry, ContactLevel, ContactState};
use crate::family::{
    FAMILY_FORMAT, FamilyBody, FamilyInvite, FamilyMember, FamilyReason, FamilyRole, MAX_FAMILY,
    SignedFamily, accept_first_family, accept_next_family, sign_family,
};
use crate::lineage::{decode_strict_with, identity_id};
use crate::share::{
    AccessTarget, InviteRecord, Removed, Role, ShareAction, ZoneMailboxKind, ZoneRole, ZoneSeed,
    open_zone_credential, wrap_zone_credential,
};
use crate::store::{Record, RecordKind, RecordStore, Zone};
use crate::vault::{Vault, VaultMeta};
use crate::{Error, Id, IntegrityError, Result, ValidationError};

/// Device-local metadata key of the family state.
const FAMILY_STATE_KEY: &str = "family.state";

fn refused(field: &str, reason: &'static str) -> Error {
    ValidationError {
        field: field.into(),
        reason,
    }
    .into()
}

/// The pinned family head and the family zone's mailbox steps.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FamilyState {
    pub family_id: Id,
    pub head: FamilyBody,
    pub actions: Vec<ShareAction>,
}

impl FamilyState {
    fn zone(&self) -> Zone {
        Zone::Family(self.family_id)
    }
}

/// One member as the screens show it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FamilyMemberView {
    pub account_id: Id,
    pub name_local: String,
    pub role: FamilyRole,
    pub level: ContactLevel,
    pub keys_changed: bool,
}

/// The family as the screens show it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FamilyInfo {
    pub family_id: Id,
    pub members: Vec<FamilyMemberView>,
    pub vaults: Vec<Id>,
    pub i_am_organizer: bool,
    /// One organizer only: the app reminds the family (decision 13).
    pub needs_second_organizer: bool,
}

/// A family invitation waiting for this account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FamilyInviteView {
    pub id: Id,
    pub from_name_local: String,
    pub role: FamilyRole,
}

impl<S: RecordStore> Repository<S> {
    pub(crate) fn family_state(&self) -> Result<Option<FamilyState>> {
        let Some(b) = self.store.local_meta(FAMILY_STATE_KEY)? else {
            return Ok(None);
        };
        decode_strict_with(&b, Error::InvalidFormat("family state")).map(Some)
    }

    fn put_family_state(&mut self, s: Option<&FamilyState>) -> Result<()> {
        let bytes = s.map(|s| postcard::to_allocvec(s).expect("family state encodes"));
        self.store
            .set_local_meta(FAMILY_STATE_KEY, bytes.as_deref())
    }

    fn self_family_member(&self, role: FamilyRole, now: i64) -> FamilyMember {
        let me = self.me();
        let p = &self.account.params;
        FamilyMember {
            account_id: me.account_id,
            identity_id: me.identity_id,
            sign_pub: p.signing_pub.clone(),
            kem_pub: p.kem_pub.clone(),
            role,
            level: ContactLevel::Verified,
            added_at: now,
        }
    }

    /// The family zone's body, signed, written over the pinned head.
    fn family_write(
        &mut self,
        state: &FamilyState,
        signed: &SignedFamily,
    ) -> (Zone, Record, Option<u64>) {
        (
            state.zone(),
            Record {
                kind: RecordKind::Family,
                id: state.family_id,
                version: signed.body.seq,
                data: signed.encode(),
            },
            Some(state.head.seq),
        )
    }

    /// The family state with its head followed to the zone's body when
    /// `accept_next_family` takes it. A body that removes me drops the
    /// family here (the vaults go through their own chains).
    fn followed_family(&mut self) -> Result<Option<FamilyState>> {
        let Some(mut state) = self.family_state()? else {
            return Ok(None);
        };
        let Some(rec) = self
            .store
            .get_in(state.zone(), RecordKind::Family, state.family_id)?
        else {
            return Ok(Some(state));
        };
        if rec.version <= state.head.seq {
            return Ok(Some(state));
        }
        let Ok(signed) = SignedFamily::decode(&rec.data) else {
            return Ok(Some(state));
        };
        let Ok(next) = accept_next_family(&state.head, &signed) else {
            return Ok(Some(state));
        };
        let me = self.me();
        if next
            .member(me.account_id)
            .is_none_or(|m| m.identity_id != me.identity_id)
        {
            self.drop_family(&state)?;
            return Ok(None);
        }
        state.head = next;
        self.put_family_state(Some(&state))?;
        Ok(Some(state))
    }

    /// Forget the family here: its access and its local state.
    fn drop_family(&mut self, state: &FamilyState) -> Result<()> {
        let access = AccessTarget::Zone(state.zone()).record_id()?;
        if self
            .store
            .get(crate::share::ZONE_ACCESS_KIND, access)?
            .is_some()
        {
            self.store.put_all_zoned(
                vec![],
                vec![(Zone::Private, crate::share::ZONE_ACCESS_KIND, access)],
                None,
                &[],
            )?;
        }
        self.put_family_state(None)
    }

    fn organizer_state(&mut self) -> Result<FamilyState> {
        let state = self
            .followed_family()?
            .ok_or_else(|| refused("family", "none"))?;
        let me = self.me();
        if state
            .head
            .member(me.account_id)
            .is_none_or(|m| m.role != FamilyRole::Organizer || m.identity_id != me.identity_id)
        {
            return Err(refused("family", "organizer only"));
        }
        Ok(state)
    }

    fn family_info(&mut self, state: &FamilyState) -> Result<FamilyInfo> {
        let me = self.me();
        let mut members = Vec::new();
        for m in &state.head.members {
            let (name_local, keys_changed) = if m.account_id == me.account_id {
                (String::new(), false)
            } else {
                match self.contact(m.account_id)? {
                    Some(c) => (
                        c.name_local.clone(),
                        matches!(c.state, ContactState::KeysChanged { .. }),
                    ),
                    None => (String::new(), false),
                }
            };
            members.push(FamilyMemberView {
                account_id: m.account_id,
                name_local,
                role: m.role,
                level: m.level,
                keys_changed,
            });
        }
        Ok(FamilyInfo {
            family_id: state.family_id,
            members,
            vaults: state.head.vaults.clone(),
            i_am_organizer: state
                .head
                .member(me.account_id)
                .is_some_and(|m| m.role == FamilyRole::Organizer),
            needs_second_organizer: state.head.organizers().count() < 2,
        })
    }

    /// Create my family (spec 11.1): the zone `Family(family_id)` with
    /// me as its only organizer, and a vault named `vault_name` created
    /// then shared (plan 2 `share_vault`) as the family's first vault.
    /// One family per account (`Validation("family", "already one")`).
    pub fn create_family(&mut self, vault_name: &str, now: i64) -> Result<FamilyInfo> {
        self.writable()?;
        if self.family_state()?.is_some() {
            return Err(refused("family", "already one"));
        }
        let vault = self.create_vault(VaultMeta {
            name: vault_name.to_owned(),
            icon: String::new(),
            color: String::new(),
            travel_safe: false,
            mcp_access: false,
        })?;
        let shared = self.share_vault(&vault, now)?;
        let family_id = Id::new();
        let zone = Zone::Family(family_id);
        let me = self.me();
        let body = FamilyBody {
            format: FAMILY_FORMAT,
            family_id,
            seq: 1,
            prev_hash: [0; 32],
            members: vec![self.self_family_member(FamilyRole::Organizer, now)],
            removed: Vec::new(),
            vaults: vec![shared.vault_id],
            signer: me,
            reason: FamilyReason::Create,
            history: Vec::new(),
            issued_at: now,
        };
        let signed = sign_family(body, &self.account.keyset().signing)?;
        let head = accept_first_family(&signed, &self.account.params.signing_pub)?;
        let seed = ZoneSeed::generate()?;
        let (access, expected) = self.zone_access_record(AccessTarget::Zone(zone), None, &seed)?;
        self.store.put_all_zoned(
            vec![
                (
                    zone,
                    Record {
                        kind: RecordKind::Family,
                        id: family_id,
                        version: 1,
                        data: signed.encode(),
                    },
                    None,
                ),
                (Zone::Private, access, expected),
            ],
            vec![],
            None,
            &[],
        )?;
        let state = FamilyState {
            family_id,
            head,
            actions: vec![ShareAction::CreateZoneMailbox {
                zone,
                kind: ZoneMailboxKind::Shared,
                owner_public_key: seed.public_key(),
            }],
        };
        self.put_family_state(Some(&state))?;
        self.family_info(&state)
    }

    /// My family, its head followed first. `None` without one.
    pub fn family(&mut self) -> Result<Option<FamilyInfo>> {
        match self.followed_family()? {
            Some(s) => self.family_info(&s).map(Some),
            None => Ok(None),
        }
    }

    /// Invite contact `contact` (spec 11.2): I am an organizer; an
    /// organizer must be `Verified` in my book. A body `Add`, then the
    /// contact added to every vault of the family (`Write` when
    /// `Verified`, `Read` at `Link`, decision 1), and a `FamilyInvite` in
    /// our contact zone. The family zone needs its mailbox first.
    pub fn invite_to_family(
        &mut self,
        contact: Id,
        role: FamilyRole,
        now: i64,
    ) -> Result<FamilyInfo> {
        self.writable()?;
        let state = self.organizer_state()?;
        let me = self.me();
        if contact == me.account_id {
            return Err(refused("contact", "self"));
        }
        if state.head.member(contact).is_some() {
            return Err(refused("member", "already a member"));
        }
        if state.head.members.len() >= MAX_FAMILY {
            return Err(refused("family", "full"));
        }
        let c = self
            .contact(contact)?
            .ok_or_else(|| refused("contact", "unknown"))?;
        if !c.usable_for(ContactLevel::Link) {
            return Err(refused("contact", "not active"));
        }
        if role == FamilyRole::Organizer && c.level != ContactLevel::Verified {
            return Err(refused("contact", "not verified"));
        }
        let zone = state.zone();
        let home = self
            .zone_accesses()?
            .into_iter()
            .find(|a| a.target == AccessTarget::Zone(zone))
            .and_then(|a| a.home)
            .ok_or_else(|| refused("zone", "not created yet"))?;
        let member = family_member_of(&c, role, now);
        let who = member.member_ref();
        let mut body = state.head.next(me, FamilyReason::Add, now)?;
        let at = body
            .members
            .partition_point(|m| m.account_id < member.account_id);
        body.members.insert(at, member);
        let signed = sign_family(body, &self.account.keyset().signing)?;
        let head = accept_next_family(&state.head, &signed)?;
        // The vaults first: an invite never names a vault the member was
        // not added to.
        let vault_role = if c.level == ContactLevel::Verified {
            Role::Write
        } else {
            Role::Read
        };
        for v in &state.head.vaults {
            let joined = self
                .store
                .share_state(*v)?
                .is_some_and(|s| s.head.member(contact).is_some());
            if !joined {
                self.add_member(*v, contact, vault_role, now)?;
            }
        }
        let seed = ZoneSeed::generate()?;
        let credential = wrap_zone_credential(&c.kem_pub, &seed, zone, home.mailbox_id, &who)?;
        let invite = InviteRecord::Family(FamilyInvite::sign(
            signed.clone(),
            home,
            credential,
            me,
            &self.account.keyset().signing,
        )?);
        let czone = self.contact_zone(contact)?;
        let write = self.family_write(&state, &signed);
        self.store.put_all_zoned(
            vec![
                write,
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
            ],
            vec![],
            None,
            &[],
        )?;
        let mut state = state;
        state.head = head;
        state.actions.push(ShareAction::GrantCredential {
            zone,
            public_key: seed.public_key(),
            role: ZoneRole::Write,
            put_kinds: None,
        });
        self.put_family_state(Some(&state))?;
        self.family_info(&state)
    }

    /// A family invite of a contact zone checked for this account: from
    /// an `Active` contact whose book keys sign it, the signer an
    /// organizer of the body with those keys, me a member under my
    /// current keys.
    fn checked_family_invite(
        &mut self,
        zone: Zone,
        rec: &Record,
    ) -> Result<(FamilyInvite, FamilyBody, ContactEntry, FamilyMember)> {
        let InviteRecord::Family(invite) = InviteRecord::decode(&rec.data)? else {
            return Err(refused("invite", "not a family invite"));
        };
        if rec.id != InviteRecord::Family(invite.clone()).id() {
            return Err(IntegrityError::WrongContext.into());
        }
        let me = self.me();
        let from = invite.signer;
        if from.account_id == me.account_id {
            return Err(refused("invite", "mine"));
        }
        if zone != Zone::Contact(crate::contact::pair_id(me.account_id, from.account_id)) {
            return Err(IntegrityError::WrongContext.into());
        }
        let c = self
            .contact(from.account_id)?
            .ok_or_else(|| refused("invite", "unknown signer"))?;
        if !c.usable_for(ContactLevel::Link) || identity_id(&c.identity_pub) != from.identity_id {
            return Err(refused("invite", "unknown signer"));
        }
        invite.verify(&c.sign_pub)?;
        if invite.family.body.signer != from {
            return Err(IntegrityError::WrongContext.into());
        }
        let head = accept_first_family(&invite.family, &c.sign_pub)?;
        let signer = head.member(from.account_id).ok_or(Error::NotFound)?;
        if signer.kem_pub != c.kem_pub {
            return Err(refused("invite", "signer keys"));
        }
        // An organizer I hold at Link only gives nothing (decision 1).
        if c.level != ContactLevel::Verified {
            return Err(refused("invite", "signer not verified"));
        }
        let p = &self.account.params;
        let mine = head
            .member(me.account_id)
            .filter(|m| {
                m.identity_id == me.identity_id
                    && m.sign_pub == p.signing_pub
                    && m.kem_pub == p.kem_pub
            })
            .ok_or_else(|| refused("invite", "not for my keys"))?
            .clone();
        Ok((invite, head, c, mine))
    }

    /// The family invitations waiting for this account.
    pub fn family_invites(&mut self) -> Result<Vec<FamilyInviteView>> {
        let mut out = Vec::new();
        if self.family_state()?.is_some() {
            return Ok(out);
        }
        for zone in self.contact_zones()? {
            for rec in self.store.list_in(zone, RecordKind::ShareInvite)? {
                let Ok((_, _, c, mine)) = self.checked_family_invite(zone, &rec) else {
                    continue;
                };
                out.push(FamilyInviteView {
                    id: rec.id,
                    from_name_local: c.name_local.clone(),
                    role: mine.role,
                });
            }
        }
        out.sort_by_key(|v| v.id);
        Ok(out)
    }

    /// Accept family invite `invite`: checked as `family_invites` does,
    /// the body pinned, my credential opened, my `ZoneAccess` written;
    /// then the vault invites of the family's vaults waiting for me are
    /// accepted.
    pub fn accept_family_invite(&mut self, invite: Id, now: i64) -> Result<FamilyInfo> {
        self.writable()?;
        if self.family_state()?.is_some() {
            return Err(refused("family", "already one"));
        }
        let mut found = None;
        for zone in self.contact_zones()? {
            if let Some(r) = self.store.get_in(zone, RecordKind::ShareInvite, invite)? {
                found = Some((zone, r));
            }
        }
        let (zone, rec) = found.ok_or(Error::NotFound)?;
        let (inv, head, _, _) = self.checked_family_invite(zone, &rec)?;
        let fzone = Zone::Family(head.family_id);
        let seed = open_zone_credential(
            self.account.keyset(),
            &inv.credential,
            fzone,
            inv.home.mailbox_id,
            &self.me(),
        )?;
        let (access, expected) =
            self.zone_access_record(AccessTarget::Zone(fzone), Some(inv.home.clone()), &seed)?;
        self.store
            .put_all_zoned(vec![(Zone::Private, access, expected)], vec![], None, &[])?;
        let state = FamilyState {
            family_id: head.family_id,
            head,
            actions: Vec::new(),
        };
        self.put_family_state(Some(&state))?;
        for view in self.share_invites()? {
            let Ok((czone, r)) = self.find_share_invite(view.id) else {
                continue;
            };
            let Ok((vinv, _, _, _)) = self.checked_invite(czone, &r) else {
                continue;
            };
            if state.head.vaults.contains(&vinv.vault_id) {
                self.accept_share_invite(view.id, now)?;
            }
        }
        self.family_info(&state)
    }

    fn find_share_invite(&self, invite: Id) -> Result<(Zone, Record)> {
        for zone in self.contact_zones()? {
            if let Some(r) = self.store.get_in(zone, RecordKind::ShareInvite, invite)? {
                return Ok((zone, r));
            }
        }
        Err(Error::NotFound)
    }

    /// Remove `account_id` from the family: a body `Remove`, then
    /// `remove_member` in every family vault that lists it (a new key
    /// generation in each, plan 2 Task 9).
    pub fn remove_from_family(&mut self, account_id: Id, now: i64) -> Result<FamilyInfo> {
        self.writable()?;
        let state = self.organizer_state()?;
        let me = self.me();
        if account_id == me.account_id {
            return Err(refused("member", "self"));
        }
        let gone = state
            .head
            .member(account_id)
            .ok_or_else(|| refused("member", "not a member"))?
            .clone();
        let mut body = state.head.next(me, FamilyReason::Remove, now)?;
        body.members.retain(|m| m.account_id != account_id);
        body.removed.push(Removed {
            account_id: gone.account_id,
            identity_id: gone.identity_id,
            removed_at: now,
            by: me,
        });
        body.removed.sort_by_key(|r| (r.account_id, r.identity_id));
        let signed = sign_family(body, &self.account.keyset().signing)?;
        let head = accept_next_family(&state.head, &signed)?;
        let write = self.family_write(&state, &signed);
        self.store.put_all_zoned(vec![write], vec![], None, &[])?;
        let mut state = state;
        state.head = head;
        self.put_family_state(Some(&state))?;
        for v in state.head.vaults.clone() {
            let listed = self
                .store
                .share_state(v)?
                .is_some_and(|s| s.head.member(account_id).is_some());
            if listed {
                self.remove_member(v, account_id, now)?;
            }
        }
        self.family_info(&state)
    }

    /// Leave my family: a body `Leave` signed by me, then each family
    /// vault left (plan 2 `leave_shared_vault`). The last organizer
    /// cannot leave (`InvalidFormat` from the body's shape).
    pub fn leave_family(&mut self, now: i64) -> Result<()> {
        self.writable()?;
        let state = self
            .followed_family()?
            .ok_or_else(|| refused("family", "none"))?;
        let me = self.me();
        let mine = state
            .head
            .member(me.account_id)
            .ok_or(Error::NotFound)?
            .clone();
        let mut body = state.head.next(me, FamilyReason::Leave, now)?;
        body.members.retain(|m| m.account_id != me.account_id);
        body.removed.push(Removed {
            account_id: mine.account_id,
            identity_id: mine.identity_id,
            removed_at: now,
            by: me,
        });
        body.removed.sort_by_key(|r| (r.account_id, r.identity_id));
        let signed = sign_family(body, &self.account.keyset().signing)?;
        accept_next_family(&state.head, &signed)?;
        let write = self.family_write(&state, &signed);
        self.store.put_all_zoned(vec![write], vec![], None, &[])?;
        for v in state.head.vaults.clone() {
            let owner = self
                .store
                .share_state(v)?
                .and_then(|s| s.head.member(me.account_id).map(|m| m.owner));
            if owner == Some(false) {
                self.leave_shared_vault(v, now)?;
            }
        }
        // The body must reach the zone before the access goes: the state
        // stays until the transport pushed it (the app syncs, then calls
        // `family`, which drops it once the zone holds my leave).
        let mut state = state;
        state.actions.clear();
        self.put_family_state(Some(&state))
    }

    /// Change `account_id`'s family role. An organizer must be `Verified`
    /// in the body; the family keeps at least one organizer.
    pub fn set_family_role(
        &mut self,
        account_id: Id,
        role: FamilyRole,
        now: i64,
    ) -> Result<FamilyInfo> {
        self.writable()?;
        let state = self.organizer_state()?;
        let me = self.me();
        let current = state
            .head
            .member(account_id)
            .ok_or_else(|| refused("member", "not a member"))?;
        if current.role == role {
            return self.family_info(&state);
        }
        if role == FamilyRole::Organizer && current.level != ContactLevel::Verified {
            return Err(refused("member", "not verified"));
        }
        let mut body = state.head.next(me, FamilyReason::Role, now)?;
        for m in &mut body.members {
            if m.account_id == account_id {
                m.role = role;
            }
        }
        if body.organizers().next().is_none() {
            return Err(refused("family", "last organizer"));
        }
        let signed = sign_family(body, &self.account.keyset().signing)?;
        let head = accept_next_family(&state.head, &signed)?;
        let write = self.family_write(&state, &signed);
        self.store.put_all_zoned(vec![write], vec![], None, &[])?;
        let mut state = state;
        state.head = head;
        self.put_family_state(Some(&state))?;
        self.family_info(&state)
    }

    /// Add shared vault `vault` (I manage it) to the family: a body
    /// `Vaults`, then every family member I hold in my book added to it
    /// (`Write` when `Verified`, `Read` at `Link`).
    pub fn add_family_vault(&mut self, vault: &Vault, now: i64) -> Result<FamilyInfo> {
        self.writable()?;
        let state = self.organizer_state()?;
        let Zone::Vault(vault_id) = vault.zone() else {
            return Err(refused("vault", "not shared"));
        };
        if state.head.vaults.contains(&vault_id) {
            return self.family_info(&state);
        }
        let me = self.me();
        let mut body = state.head.next(me, FamilyReason::Vaults, now)?;
        let at = body.vaults.partition_point(|v| *v < vault_id);
        body.vaults.insert(at, vault_id);
        let signed = sign_family(body, &self.account.keyset().signing)?;
        let head = accept_next_family(&state.head, &signed)?;
        for m in &state.head.members {
            if m.account_id == me.account_id {
                continue;
            }
            let listed = self
                .store
                .share_state(vault_id)?
                .is_some_and(|s| s.head.member(m.account_id).is_some());
            let Some(c) = self.contact(m.account_id)? else {
                continue;
            };
            if listed || !c.usable_for(ContactLevel::Link) {
                continue;
            }
            let role = if c.level == ContactLevel::Verified {
                Role::Write
            } else {
                Role::Read
            };
            self.add_member(vault_id, m.account_id, role, now)?;
        }
        let write = self.family_write(&state, &signed);
        self.store.put_all_zoned(vec![write], vec![], None, &[])?;
        let mut state = state;
        state.head = head;
        self.put_family_state(Some(&state))?;
        self.family_info(&state)
    }

    /// The family zone's mailbox steps, in order; a step that needs the
    /// zone's mailbox waits for `set_zone_home`.
    pub(crate) fn pending_family_actions(&self) -> Result<Vec<ShareAction>> {
        let Some(state) = self.family_state()? else {
            return Ok(Vec::new());
        };
        let has_home = self
            .zone_accesses()?
            .iter()
            .any(|a| a.target == AccessTarget::Zone(state.zone()) && a.home.is_some());
        let mut out = Vec::new();
        for a in &state.actions {
            if !matches!(a, ShareAction::CreateZoneMailbox { .. }) && !has_home {
                break;
            }
            out.push(a.clone());
        }
        Ok(out)
    }

    /// The transport ran family zone step `a`.
    pub(crate) fn family_action_done(&mut self, a: &ShareAction) -> Result<()> {
        let Some(mut state) = self.family_state()? else {
            return Ok(());
        };
        if let Some(i) = state.actions.iter().position(|x| x == a) {
            state.actions.remove(i);
            self.put_family_state(Some(&state))?;
        }
        Ok(())
    }
}

fn family_member_of(c: &ContactEntry, role: FamilyRole, now: i64) -> FamilyMember {
    FamilyMember {
        account_id: c.account_id,
        identity_id: identity_id(&c.identity_pub),
        sign_pub: c.sign_pub.clone(),
        kem_pub: c.kem_pub.clone(),
        role,
        level: c.level,
        added_at: now,
    }
}
