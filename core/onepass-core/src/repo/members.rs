//! A member's new identity (sharing spec 12.3, 12.5, S22 to S24, decision
//! 6, A11; plan 2 Task 14): the old identity is retired at once when its
//! rotation is seen, the new one is adopted only on a human check, by a
//! manager who then signs an `IdentityUpdate` body.

use std::collections::BTreeMap;

use super::Repository;
use crate::account::AccountParams;
use crate::contact::{ContactLevel, ContactState, ForeignLineage, LegacyIntros, follow_foreign};
use crate::lineage::{LineageRecord, SignedIntro, identity_id, rotation_code};
use crate::manifest::meta_hash;
use crate::share::{
    AccessTarget, CredentialRenewal, InviteRecord, MemberLineageRecord, MemberRef,
    MembershipReason, Role, ShareAction, SharedVaultInfo, ZoneSeed, accept_next,
    accept_self_update, identity_pub_hash, open_zone_credential, server_role, sign_membership,
    wrap_member_key, wrap_zone_credential,
};
use crate::store::{Record, RecordKind, RecordStore, Zone};
use crate::trust::LineageHead;
use crate::{Error, Id, IntegrityError, Result, ValidationError};

fn refused(field: &str, reason: &'static str) -> Error {
    ValidationError {
        field: field.into(),
        reason,
    }
    .into()
}

/// A contact's rotation seen in the zones we share (spec 12.3 point 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityChange {
    pub account_id: Id,
    pub name_local: String,
    /// The new head to confirm (the smallest sibling with a fork).
    pub child: [u8; 32],
    /// From the contact's own roster, never from a card name.
    pub rotator_name: Option<String>,
    pub revoked_names: Vec<String>,
    pub issued_at: i64,
    /// The shared vaults the contact is a member of.
    pub vaults: Vec<Id>,
    pub forked: bool,
}

/// How a manager checked a member's new identity (decision 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdoptionProof {
    /// The 6-digit rotation code the member read out: enough for a reader.
    Code(u32),
    /// A finished face-to-face contact session pinned the new head.
    InPerson { transcript_hash: [u8; 32] },
}

/// What the zones hold about one account's lineage.
#[derive(Default)]
struct Published {
    records: Vec<LineageRecord>,
    intros: Vec<SignedIntro>,
    params: Vec<Vec<u8>>,
}

impl<S: RecordStore> Repository<S> {
    /// Every `MemberLineage` record of the shared and contact zones, by
    /// account.
    fn published_lineage(&self) -> Result<BTreeMap<Id, Published>> {
        let mut zones: Vec<Zone> = self
            .store
            .share_states()?
            .into_iter()
            .map(|s| s.zone)
            .collect();
        zones.extend(self.contact_zones()?);
        let mut out: BTreeMap<Id, Published> = BTreeMap::new();
        let mut params = Vec::new();
        for zone in zones {
            for rec in self.store.list_in(zone, RecordKind::MemberLineage)? {
                let Ok(m) = MemberLineageRecord::decode(&rec.data) else {
                    continue;
                };
                if m.id() != rec.id {
                    continue;
                }
                match m {
                    MemberLineageRecord::Lineage(l) => {
                        out.entry(l.account_id()).or_default().records.push(l)
                    }
                    MemberLineageRecord::Intro(i) => {
                        out.entry(i.body.account_id).or_default().intros.push(i)
                    }
                    MemberLineageRecord::Params(p) => params.push(p),
                }
            }
        }
        for p in params {
            if let Ok(decoded) = AccountParams::decode(&p) {
                out.entry(decoded.account_id).or_default().params.push(p);
            }
        }
        Ok(out)
    }

    /// Read the members' and contacts' lineage records in the zones we
    /// share and follow each contact (`refresh_contact`). A valid rotation
    /// past the pinned head retires the old identity at once: in each
    /// shared vault the contact belongs to, a body or manifest it signs
    /// after the seq accepted now is refused (ruling A-12). Returns the
    /// contacts whose keys changed, for the screens.
    pub fn refresh_member_identities(&mut self, now: i64) -> Result<Vec<IdentityChange>> {
        let me = self.me();
        let mut out = Vec::new();
        for (account_id, p) in self.published_lineage()? {
            if account_id == me.account_id {
                continue;
            }
            let Some(entry) = self.contact(account_id)? else {
                continue;
            };
            let Ok(result) = self.refresh_contact(account_id, &p.records, &p.intros, now) else {
                continue;
            };
            let (child, forked, last) = match &result {
                ForeignLineage::Advanced {
                    head,
                    last_rotation,
                    ..
                } => (head.hash, false, Some(last_rotation.clone())),
                ForeignLineage::Forked { siblings } => (siblings[0], true, None),
                _ => continue,
            };
            let mut vaults = Vec::new();
            for mut state in self.store.share_states()? {
                let Some(m) = state.head.member(account_id) else {
                    continue;
                };
                let old = MemberRef {
                    account_id,
                    identity_id: m.identity_id,
                };
                vaults.push(state.vault_id);
                if !state.retired_signers.contains_key(&old) {
                    state.retired_signers.insert(old, state.head.seq);
                    self.store
                        .put_all_zoned(vec![], vec![], None, std::slice::from_ref(&state))?;
                }
            }
            let names = |id: &Id| {
                p.records.iter().find_map(|r| match r {
                    LineageRecord::Rotation(s) => s
                        .body
                        .roster
                        .iter()
                        .find(|e| e.device_id == *id)
                        .map(|e| e.name.clone()),
                    LineageRecord::Genesis(g) => {
                        (g.body.creator.device_id == *id).then(|| g.body.creator.name.clone())
                    }
                })
            };
            out.push(IdentityChange {
                account_id,
                name_local: entry.name_local.clone(),
                child,
                rotator_name: last.as_ref().and_then(|l| names(&l.rotator)),
                revoked_names: last
                    .as_ref()
                    .map(|l| l.revoked.iter().filter_map(names).collect())
                    .unwrap_or_default(),
                issued_at: last.as_ref().map_or(now, |l| l.issued_at),
                vaults,
                forked,
            });
        }
        Ok(out)
    }

    /// Adopt contact `account_id`'s new identity `child` (spec 12.3 point
    /// 3, decision 6) after a human check: `Code` (the rotation code of
    /// `child`) only when the contact is a reader in every vault we
    /// share; `InPerson` when a face-to-face session already pinned
    /// `child` `Verified` in the book with that transcript. `child` must
    /// be the valid head the contact's records lead to, or with a fork one
    /// of the siblings (the user's explicit choice). Then the book pins
    /// the new head and, in each shared vault I manage where the contact
    /// is a member, an `IdentityUpdate` body replaces its identity, keys
    /// and credential, its envelope of the current generation is written,
    /// its new credential seed goes to our contact zone
    /// (`InviteRecord::Credential`), and the transport is asked to grant
    /// the new credential, then revoke the old one (spec 13.8).
    pub fn adopt_member_identity(
        &mut self,
        account_id: Id,
        child: [u8; 32],
        proof: AdoptionProof,
        now: i64,
    ) -> Result<Vec<SharedVaultInfo>> {
        self.writable()?;
        let entry = self
            .contact(account_id)?
            .ok_or_else(|| refused("contact", "unknown"))?;
        let published = self.published_lineage()?;
        let p = published.get(&account_id).ok_or(Error::NotFound)?;
        let record = p
            .records
            .iter()
            .find(|r| r.hash() == child)
            .ok_or(Error::NotFound)?
            .clone();
        let LineageRecord::Rotation(rotation) = &record else {
            return Err(refused("child", "not a rotation"));
        };
        let pinned_here = entry.pinned_head.hash == child;
        if !pinned_here {
            let legacy = LegacyIntros {
                intros: &[],
                genesis_params: None,
            };
            match follow_foreign(&entry.pin(), &p.records, &p.intros, &legacy) {
                ForeignLineage::Advanced { head, .. } if head.hash == child => {}
                ForeignLineage::Forked { siblings } if siblings.contains(&child) => {}
                ForeignLineage::Forked { .. } => return Err(refused("child", "not a sibling")),
                _ => return Err(refused("child", "not the new head")),
            }
        }
        let states: Vec<_> = self
            .store
            .share_states()?
            .into_iter()
            .filter(|s| s.head.member(account_id).is_some())
            .collect();
        let level = match proof {
            AdoptionProof::Code(code) => {
                if code != rotation_code(&child) {
                    return Err(refused("code", "wrong code"));
                }
                if states.iter().any(|s| {
                    s.head
                        .member(account_id)
                        .is_some_and(|m| m.role > Role::Read)
                }) {
                    return Err(refused("proof", "in person required"));
                }
                ContactLevel::Link
            }
            AdoptionProof::InPerson { transcript_hash } => {
                if !pinned_here
                    || entry.level != ContactLevel::Verified
                    || entry.transcript_hash != transcript_hash
                {
                    return Err(refused("proof", "no session"));
                }
                ContactLevel::Verified
            }
        };
        let identity_pub = rotation.body.identity_pub.clone();
        let params_rec = p
            .params
            .iter()
            .find(|x| crate::share::sha256(&[x.as_slice()]) == rotation.body.params_hash)
            .ok_or(Error::NotFound)?;
        let params = AccountParams::decode_verified(params_rec, &identity_pub)?;
        if params.account_id != account_id {
            return Err(IntegrityError::WrongContext.into());
        }
        let new_ref = MemberRef {
            account_id,
            identity_id: identity_id(&identity_pub),
        };
        // The book pins the new head.
        let head = LineageHead {
            generation: record.generation(),
            hash: child,
        };
        let (sign_pub, kem_pub) = (params.signing_pub.clone(), params.kem_pub.clone());
        {
            let identity_pub = identity_pub.clone();
            let (sign_pub, kem_pub) = (sign_pub.clone(), kem_pub.clone());
            self.edit_contact(account_id, move |e| {
                e.pinned_head = head;
                e.identity_pub = identity_pub;
                e.sign_pub = sign_pub;
                e.kem_pub = kem_pub;
                e.level = level;
                e.state = ContactState::Active;
                Ok(())
            })?;
        }
        let me = self.me();
        let mut out = Vec::new();
        for state in states {
            let vault_id = state.vault_id;
            let Ok(state) = self.manager_state(vault_id) else {
                // Spec 12.4: a manager I cannot replace by a body of my
                // own is adopted here only; its own IdentityUpdate is then
                // accepted on this device.
                let mut state = state;
                if let Some(old) = state.head.member(account_id).cloned()
                    && old.role == Role::Manage
                    && old.identity_id != new_ref.identity_id
                {
                    let mut adopted = old;
                    adopted.identity_id = new_ref.identity_id;
                    adopted.identity_pub_hash = identity_pub_hash(&identity_pub);
                    adopted.sign_pub = sign_pub.clone();
                    adopted.kem_pub = kem_pub.clone();
                    state
                        .adopted_managers
                        .retain(|m| m.account_id != account_id);
                    state.adopted_managers.push(adopted);
                    self.store
                        .put_all_zoned(vec![], vec![], None, std::slice::from_ref(&state))?;
                    self.follow_head(vault_id)?;
                }
                continue;
            };
            let Some(old) = state.head.member(account_id).cloned() else {
                continue;
            };
            if old.identity_id == new_ref.identity_id {
                continue;
            }
            let zone = state.zone;
            let home = self
                .zone_accesses()?
                .into_iter()
                .find(|a| a.target == AccessTarget::Zone(zone))
                .and_then(|a| a.home)
                .ok_or_else(|| refused("zone", "no home"))?;
            let seed = ZoneSeed::generate()?;
            let mut body = state.head.next(me, MembershipReason::IdentityUpdate, now)?;
            for m in &mut body.members {
                if m.account_id == account_id {
                    m.identity_id = new_ref.identity_id;
                    m.identity_pub_hash = identity_pub_hash(&identity_pub);
                    m.sign_pub = sign_pub.clone();
                    m.kem_pub = kem_pub.clone();
                    m.credential_id = seed.credential_id();
                    m.level = level;
                    m.key_pending = false;
                }
            }
            let signed = sign_membership(body, &self.account.keyset().signing)?;
            let next = accept_next(&state.head, &signed)?;
            let vault = self.open_shared(vault_id)?;
            let g = next.generation;
            let mk = wrap_member_key(&kem_pub, vault.key(), vault_id, g, &new_ref)?;
            let credential =
                wrap_zone_credential(&kem_pub, &seed, zone, home.mailbox_id, &new_ref)?;
            let renewal = InviteRecord::Credential(CredentialRenewal::sign(
                vault_id,
                home,
                credential,
                me,
                &self.account.keyset().signing,
            )?);
            let cz = self.contact_zone(account_id)?;
            let (manifest_rec, manifest_expected, seen) = self.manifest_for_head(&vault, &next)?;
            let mut state = self.store.share_state(vault_id)?.ok_or(Error::NotFound)?;
            let mut writes = vec![
                (
                    zone,
                    Record {
                        kind: RecordKind::Membership,
                        id: vault_id,
                        version: next.seq,
                        data: signed.encode(),
                    },
                    Some(state.head.seq),
                ),
                (zone, manifest_rec, manifest_expected),
                (
                    cz,
                    Record {
                        kind: RecordKind::ShareInvite,
                        id: renewal.id(),
                        version: 1,
                        data: renewal.encode(),
                    },
                    None,
                ),
            ];
            // The member wrote its own envelope with its rotation: an
            // envelope is immutable, that one stays.
            if self
                .store
                .get_in(zone, RecordKind::MemberKey, mk.id())?
                .is_none()
            {
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
            state.advance(next);
            state.last_manifest = Some(seen);
            state.last_meta = Some(meta_hash(&vault.meta));
            let (zrole, put_kinds) = server_role(old.role);
            state.actions.push(ShareAction::GrantCredential {
                zone,
                public_key: seed.public_key(),
                role: zrole,
                put_kinds,
            });
            state.actions.push(ShareAction::RevokeCredential {
                zone,
                credential_id: old.credential_id,
            });
            self.store
                .put_all_zoned(writes, vec![], None, std::slice::from_ref(&state))?;
            out.push(self.shared_info(&state, &vault.meta.name)?);
        }
        Ok(out)
    }

    /// My entry in `vault_id`'s head names a credential my zone access
    /// does not hold (an adoption renewed it): open the renewal a manager
    /// of the head left in our contact zone and write my access with the
    /// new seed. Nothing found yet: nothing changes.
    pub(crate) fn apply_credential_renewal(&mut self, vault_id: Id) -> Result<()> {
        let Some(state) = self.store.share_state(vault_id)? else {
            return Ok(());
        };
        let me = self.me();
        let Some(mine) = state
            .head
            .member(me.account_id)
            .filter(|m| m.identity_id == me.identity_id)
            .cloned()
        else {
            return Ok(());
        };
        let target = AccessTarget::Zone(state.zone);
        let Some((access, seed)) = self.zone_access(target)? else {
            return Ok(());
        };
        if seed.credential_id() == mine.credential_id {
            return Ok(());
        }
        for cz in self.contact_zones()? {
            for rec in self.store.list_in(cz, RecordKind::ShareInvite)? {
                let Ok(InviteRecord::Credential(r)) = InviteRecord::decode(&rec.data) else {
                    continue;
                };
                if r.vault_id != vault_id {
                    continue;
                }
                let Some(signer) = state
                    .head
                    .member(r.signer.account_id)
                    .filter(|m| m.identity_id == r.signer.identity_id && m.role == Role::Manage)
                else {
                    continue;
                };
                if r.verify(&signer.sign_pub).is_err() {
                    continue;
                }
                let Ok(fresh) = open_zone_credential(
                    self.account.keyset(),
                    &r.credential,
                    state.zone,
                    r.home.mailbox_id,
                    &me,
                ) else {
                    continue;
                };
                if fresh.credential_id() != mine.credential_id {
                    continue;
                }
                self.write_zone_access(target, access.home.clone().or(Some(r.home)), &fresh)?;
                return Ok(());
            }
        }
        Ok(())
    }

    /// My keys rotated and I manage vault `vault_id` (spec 12.4, Task 15):
    /// my first body under the new identity, an `IdentityUpdate` signed by
    /// it that replaces my own entry (role, owner flag and credential
    /// kept), with the next manifest. A member accepts it once it adopted
    /// my new identity (`adopt_member_identity`, in person); until then it
    /// keeps the last body my old identity signed. Refused: no new
    /// identity waiting here, not a manager.
    pub fn publish_own_identity(&mut self, vault_id: Id, now: i64) -> Result<SharedVaultInfo> {
        self.writable()?;
        let mut state = self.store.share_state(vault_id)?.ok_or(Error::NotFound)?;
        let me = self.me();
        if state.identity_pending.is_none() {
            return Err(refused("identity", "not pending"));
        }
        let old = state
            .head
            .member(me.account_id)
            .cloned()
            .ok_or_else(|| refused("role", "not a member"))?;
        if old.role != Role::Manage {
            return Err(refused("role", "manager only"));
        }
        let p = &self.account.params;
        let mut mine = old.clone();
        mine.identity_id = me.identity_id;
        mine.identity_pub_hash = identity_pub_hash(&p.identity_pub);
        mine.sign_pub = p.signing_pub.clone();
        mine.kem_pub = p.kem_pub.clone();
        let mut body = state.head.next(me, MembershipReason::IdentityUpdate, now)?;
        for m in &mut body.members {
            if m.account_id == me.account_id {
                *m = mine.clone();
            }
        }
        let signed = sign_membership(body, &self.account.keyset().signing)?;
        let next = accept_self_update(&state.head, &signed, &mine)?;
        let vault = self.open_shared(vault_id)?;
        let zone = state.zone;
        let writes = vec![(
            zone,
            Record {
                kind: RecordKind::Membership,
                id: vault_id,
                version: next.seq,
                data: signed.encode(),
            },
            Some(state.head.seq),
        )];
        let seq = next.seq;
        state.advance(next);
        state.identity_pending = None;
        state.self_update = Some((seq, Vec::new()));
        self.store
            .put_all_zoned(writes, vec![], None, std::slice::from_ref(&state))?;
        self.shared_info(&state, &vault.meta.name)
    }

    /// The members who have not yet shown they follow my `IdentityUpdate`
    /// (`publish_own_identity`, ruling A-13): none of their manifests
    /// names a body at or after it yet.
    pub fn members_not_confirmed(&mut self, vault_id: Id) -> Result<Vec<Id>> {
        let state = self.store.share_state(vault_id)?.ok_or(Error::NotFound)?;
        let Some((_, confirmed)) = &state.self_update else {
            return Ok(Vec::new());
        };
        let me = self.me();
        Ok(state
            .head
            .members
            .iter()
            .map(|m| m.account_id)
            .filter(|a| *a != me.account_id && !confirmed.contains(a))
            .collect())
    }
}
