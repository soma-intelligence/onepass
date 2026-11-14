//! Roster acceptance (spec 5.5, plan B Task 7): who may sign which roster
//! change. The signer is looked up by device fingerprint in the PINNED
//! (previous) roster, never in the roster it signs (D23), or vouched by
//! the lineage head for an owner (R7f); its roles there decide what it
//! may change (D7, D9), Owner authority only for a device of a head
//! owner; the `Owner` bits follow the org lineage (5.4); members never
//! disappear and a `Removed` entry never changes again (D10); a gap or an
//! unknown lineage head is `NotFound` (D13); the first pin may start at
//! any roster a device of a head owner signed (D12, R7f). Any change the
//! table below does not allow is `Integrity(OrgRoleDenied)`.

use super::{
    DeviceFpr, MemberRef, MemberState, ORG_ROSTER_DOMAIN, OrgHeadInfo, OrgId, OrgLineage,
    OrgMember, Role, RoleSet, RosterBody, SignedRoster, member_kem_hash,
};
use crate::device_keys::DevicePublic;
use crate::{Error, Id, IntegrityError, Result};

fn denied() -> Error {
    IntegrityError::OrgRoleDenied.into()
}

/// The roles an Owner or Admin may grant or revoke.
fn admin_grants() -> RoleSet {
    RoleSet::of(&[
        Role::Admin,
        Role::UserManager,
        Role::PolicyManager,
        Role::Auditor,
        Role::Provisioner,
    ])
}

/// The roles a UserManager may grant or revoke, if it holds them itself.
fn user_manager_grants() -> RoleSet {
    RoleSet::of(&[
        Role::UserManager,
        Role::PolicyManager,
        Role::Auditor,
        Role::Provisioner,
    ])
}

/// GRANT(S) of the permission table.
fn grantable(s: RoleSet) -> RoleSet {
    if s.contains(Role::Owner) || s.contains(Role::Admin) {
        admin_grants()
    } else if s.contains(Role::UserManager) {
        s.intersection(user_manager_grants())
    } else {
        RoleSet::EMPTY
    }
}

/// The member of a checked body (sorted by account id).
fn find(body: &RosterBody, a: Id) -> Option<&OrgMember> {
    body.members
        .binary_search_by(|m| m.account_id.cmp(&a))
        .ok()
        .map(|i| &body.members[i])
}

/// A lineage owner as the roster lists it: Active, roles `{Owner}`, the
/// reference's identity, KEM hash and devices, zero directory and
/// invitation hashes (D21).
fn owner_member(r: &MemberRef) -> OrgMember {
    OrgMember {
        account_id: r.account_id,
        account_identity_pub: Some(r.account_identity_pub.clone()),
        scim_id_hash: [0; 32],
        invite_commit: [0; 32],
        account_kem_hash: member_kem_hash(&r.account_kem_pub),
        roles: RoleSet::of(&[Role::Owner]),
        state: MemberState::Active,
        devices: r.devices.clone(),
    }
}

fn founding_at(org_id: OrgId, head: &OrgHeadInfo) -> Result<RosterBody> {
    let body = RosterBody {
        format: super::ORG_FORMAT,
        org_id,
        seq: 1,
        prev_hash: [0; 32],
        org_head: head.hash,
        members: head.owners.iter().map(owner_member).collect(),
    };
    body.check()?;
    Ok(body)
}

/// The roster at seq 1: the owners of `lineage.head()`, each Active with
/// roles `{Owner}` and the devices of its `MemberRef`.
pub fn founding_roster(lineage: &OrgLineage) -> Result<RosterBody> {
    founding_at(lineage.org_id, lineage.head())
}

/// Owner mirror: the members holding `Owner` are exactly the `owners`
/// accounts, each Active with the reference's identity, KEM hash and
/// devices (R7c: owner devices change only through the lineage).
fn check_owner_mirror(body: &RosterBody, owners: &[MemberRef]) -> Result<()> {
    for m in &body.members {
        if m.roles.contains(Role::Owner) && !owners.iter().any(|r| r.account_id == m.account_id) {
            return Err(denied());
        }
    }
    for r in owners {
        let m = find(body, r.account_id).ok_or_else(denied)?;
        if !m.roles.contains(Role::Owner)
            || m.state != MemberState::Active
            || m.account_identity_pub.as_ref() != Some(&r.account_identity_pub)
            || m.account_kem_hash != member_kem_hash(&r.account_kem_pub)
            || m.devices != r.devices
        {
            return Err(denied());
        }
    }
    Ok(())
}

/// R7d: an Owner entry whose identity, KEM hash and devices are those of
/// its lineage `MemberRef`.
fn follows_lineage(owners: &[MemberRef], e: &OrgMember) -> bool {
    e.roles.contains(Role::Owner)
        && owners.iter().any(|r| {
            r.account_id == e.account_id
                && e.account_identity_pub.as_ref() == Some(&r.account_identity_pub)
                && e.account_kem_hash == member_kem_hash(&r.account_kem_pub)
                && e.devices == r.devices
        })
}

/// The allowed state moves (an unchanged state included).
fn transition_allowed(p: &MemberState, e: &MemberState) -> bool {
    use MemberState::*;
    match (p, e) {
        (Removed { .. }, _) => p == e,
        (Invited, Invited | Active | Removed { .. }) => true,
        (Active, Active | Suspended | Removed { .. }) => true,
        (Suspended, Suspended | Active | Removed { .. }) => true,
        _ => false,
    }
}

/// The `MemberRef` devices of account `a` among the owners of
/// `lineage.head()`, if `a` is one.
fn head_owner_devices(lineage: &OrgLineage, a: Id) -> Option<&[DeviceFpr]> {
    lineage
        .head()
        .owners
        .iter()
        .find(|r| r.account_id == a)
        .map(|r| r.devices.as_slice())
}

/// The signer as the previous roster lists it.
struct Signer {
    account: Id,
    roles: RoleSet,
}

/// R7f: the signer of a roster after `prev`, with its effective roles.
/// The fingerprint is looked up in `prev` first (its holder must be
/// Active). If absent, a device listed in the head `MemberRef` of an
/// owner account that is Active with `Owner` in `prev` signs as that
/// account with that entry's roles (a lineage-vouched device, R7e).
/// Owner authority is device-level: it holds only for a device in the
/// head `MemberRef` of its account. A listed Owner whose account is still
/// a head owner but whose device the head dropped has no authority at all;
/// an account no longer a head owner loses `Owner` and keeps its other
/// roles (R7b).
fn resolve_signer(lineage: &OrgLineage, prev: &RosterBody, fpr: &DeviceFpr) -> Result<Signer> {
    if let Some(m) = prev.device_holder(fpr) {
        if m.state != MemberState::Active {
            return Err(denied());
        }
        let mut roles = m.roles;
        if roles.contains(Role::Owner) {
            match head_owner_devices(lineage, m.account_id) {
                Some(devices) if devices.contains(fpr) => {}
                Some(_) => return Err(denied()),
                None => roles = roles.without(Role::Owner),
            }
        }
        return Ok(Signer {
            account: m.account_id,
            roles,
        });
    }
    for r in &lineage.head().owners {
        if !r.devices.contains(fpr) {
            continue;
        }
        if let Some(m) = find(prev, r.account_id)
            && m.state == MemberState::Active
            && m.roles.contains(Role::Owner)
        {
            return Ok(Signer {
                account: m.account_id,
                roles: m.roles,
            });
        }
    }
    Err(denied())
}

/// A Provisioner without Owner, Admin or UserManager (D7): only suspends
/// or removes members that hold neither Owner nor Admin, never itself,
/// under the same org head, without adding anyone.
fn check_provisioner(prev: &RosterBody, next: &RosterBody, s: &Signer) -> Result<()> {
    if !s.roles.contains(Role::Provisioner)
        || next.org_head != prev.org_head
        || next.members.len() != prev.members.len()
    {
        return Err(denied());
    }
    for p in &prev.members {
        let e = find(next, p.account_id).ok_or_else(denied)?;
        if e == p {
            continue;
        }
        if p.account_id == s.account
            || p.roles.contains(Role::Owner)
            || p.roles.contains(Role::Admin)
        {
            return Err(denied());
        }
        let expected = match (&p.state, &e.state) {
            (MemberState::Active, MemberState::Suspended) => OrgMember {
                state: MemberState::Suspended,
                ..p.clone()
            },
            (
                MemberState::Invited | MemberState::Active | MemberState::Suspended,
                MemberState::Removed { by, .. },
            ) if *by == s.account => OrgMember {
                state: e.state.clone(),
                roles: RoleSet::EMPTY,
                devices: Vec::new(),
                ..p.clone()
            },
            _ => return Err(denied()),
        };
        if *e != expected {
            return Err(denied());
        }
    }
    Ok(())
}

/// One changed (`p` is `Some` and differs) or new (`p` is `None`) entry
/// under an Owner, Admin or UserManager signer.
fn check_entry(
    s: &Signer,
    owners: &[MemberRef],
    p: Option<&OrgMember>,
    e: &OrgMember,
) -> Result<()> {
    let is_owner_or_admin = s.roles.contains(Role::Owner) || s.roles.contains(Role::Admin);
    if e.account_id == s.account {
        // Its own entry: only roles change, and only shrink (Owner
        // included: a lineage promotion of the signer is mirrored by
        // another signer). R7e: an effective Owner may also sync its own
        // identity, KEM hash and devices to its lineage MemberRef (a sole
        // owner's rotation), signed by its new device (vouched by the
        // lineage head) or by an old device the head still lists (R7f).
        let p = p.ok_or_else(denied)?;
        let lineage_sync = s.roles.contains(Role::Owner) && follows_lineage(owners, e);
        let same_but_roles = OrgMember {
            roles: p.roles,
            ..e.clone()
        };
        let same_but_roles_and_keys = OrgMember {
            account_identity_pub: p.account_identity_pub.clone(),
            account_kem_hash: p.account_kem_hash,
            devices: p.devices.clone(),
            ..same_but_roles.clone()
        };
        let allowed = same_but_roles == *p || (lineage_sync && same_but_roles_and_keys == *p);
        if !allowed || !e.roles.is_subset(p.roles) {
            return Err(denied());
        }
        return Ok(());
    }
    let p_roles = p.map_or(RoleSet::EMPTY, |p| p.roles);
    let touches_owner = p_roles.contains(Role::Owner) || e.roles.contains(Role::Owner);
    let touches_admin = p_roles.contains(Role::Admin) || e.roles.contains(Role::Admin);
    if touches_owner && !is_owner_or_admin {
        return Err(denied());
    }
    if touches_admin && !is_owner_or_admin {
        return Err(denied());
    }
    let changed = e
        .roles
        .union(p_roles)
        .difference(e.roles.intersection(p_roles));
    if !changed.without(Role::Owner).is_subset(grantable(s.roles)) {
        return Err(denied());
    }
    match p {
        None if e.roles.contains(Role::Owner) => {
            // A lineage owner absent from the previous roster, added
            // directly as the lineage names it.
            let r = owners
                .iter()
                .find(|r| r.account_id == e.account_id)
                .ok_or_else(denied)?;
            let expected = OrgMember {
                roles: e.roles,
                ..owner_member(r)
            };
            if *e != expected {
                return Err(denied());
            }
        }
        None => {
            if e.state != MemberState::Invited || e.invite_commit == [0; 32] {
                return Err(denied());
            }
        }
        Some(p) => {
            // R7a: taking over an account (its devices, or its activation)
            // needs the right to grant every role it holds. Any other state
            // change (suspend, reactivate, remove) needs it too (final
            // review minor 1): a UserManager does not suspend or reactivate
            // a member it could not grant.
            let activation = p.state == MemberState::Invited && e.state == MemberState::Active;
            if (e.devices != p.devices || e.state != p.state)
                && !p_roles
                    .union(e.roles)
                    .without(Role::Owner)
                    .is_subset(grantable(s.roles))
            {
                return Err(denied());
            }
            // R7a: identity and KEM hash are set once, on Invited -> Active.
            // R7d, the single exception: an Owner entry's keys and devices
            // follow its lineage MemberRef, synced by an effective Owner.
            let keys_changed = e.account_identity_pub != p.account_identity_pub
                || e.account_kem_hash != p.account_kem_hash;
            let owner_devices_changed = e.roles.contains(Role::Owner) && e.devices != p.devices;
            if (keys_changed || owner_devices_changed)
                && !activation
                && !(s.roles.contains(Role::Owner) && follows_lineage(owners, e))
            {
                return Err(denied());
            }
            if touches_owner && !s.roles.contains(Role::Owner) {
                // An Admin only mirrors the Owner bit.
                let owner_bit = p.roles.intersection(RoleSet::of(&[Role::Owner]));
                let mirrored = OrgMember {
                    roles: e.roles.without(Role::Owner).union(owner_bit),
                    ..e.clone()
                };
                if mirrored != *p {
                    return Err(denied());
                }
            }
            if !transition_allowed(&p.state, &e.state) {
                return Err(denied());
            }
            if let MemberState::Removed { by, .. } = &e.state
                && *by != s.account
            {
                return Err(denied());
            }
            if e.account_id != p.account_id
                || e.scim_id_hash != p.scim_id_hash
                || e.invite_commit != p.invite_commit
            {
                return Err(denied());
            }
        }
    }
    Ok(())
}

/// The permission table of spec 5.5 (plan B Task 7, D7 to D10). `prev` is
/// the pinned roster, `next` the candidate, `signer` the device that
/// signed `next`. The chain fields (`seq`, `prev_hash`) and the signature
/// are `accept_next_roster`'s.
pub fn check_transition(
    lineage: &OrgLineage,
    prev: &RosterBody,
    next: &RosterBody,
    signer: &DevicePublic,
) -> Result<()> {
    prev.check()?;
    next.check()?;
    if prev.org_id != lineage.org_id || next.org_id != lineage.org_id {
        return Err(IntegrityError::WrongContext.into());
    }
    // R7b, R7f: Owner authority only for a device of an owner of the
    // newest verified generation, whatever org head the rosters still name.
    let s = resolve_signer(lineage, prev, &signer.fingerprint())?;
    let head = lineage.find(&next.org_head).ok_or(Error::NotFound)?;
    let prev_head = lineage.find(&prev.org_head).ok_or(Error::NotFound)?;
    if head.generation < prev_head.generation {
        return Err(IntegrityError::OrgLineageRollback.into());
    }
    check_owner_mirror(next, &head.owners)?;
    for p in &prev.members {
        let e = find(next, p.account_id).ok_or_else(denied)?;
        if matches!(p.state, MemberState::Removed { .. }) && e != p {
            return Err(denied());
        }
    }
    let manager = s.roles.contains(Role::Owner)
        || s.roles.contains(Role::Admin)
        || s.roles.contains(Role::UserManager);
    if !manager {
        return check_provisioner(prev, next, &s);
    }
    for e in &next.members {
        let p = find(prev, e.account_id);
        if p == Some(e) {
            continue;
        }
        check_no_squat(lineage, p, e)?;
        check_entry(&s, &head.owners, p, e)?;
    }
    Ok(())
}

/// Final review minor 2: a changed or new entry may not take a device
/// fingerprint that `lineage.head()` lists for ANOTHER owner account (an
/// admin squatting a rotating owner's new device would block its sync).
fn check_no_squat(lineage: &OrgLineage, p: Option<&OrgMember>, e: &OrgMember) -> Result<()> {
    let added = e
        .devices
        .iter()
        .filter(|f| p.is_none_or(|p| !p.devices.contains(f)));
    for f in added {
        if lineage
            .head()
            .owners
            .iter()
            .any(|r| r.account_id != e.account_id && r.devices.contains(f))
        {
            return Err(denied());
        }
    }
    Ok(())
}

fn verify_roster_sig(rec: &SignedRoster) -> Result<()> {
    rec.signer
        .sign_pub
        .verify(ORG_ROSTER_DOMAIN, &rec.body.encode(), &rec.sig)
}

/// The roster after `pinned`. Order: shape, org id (`WrongContext`), seq
/// (the pinned roster again is a no-op, another body at its seq a fork, an
/// older seq a rollback, a gap `NotFound`, a wrong `prev_hash` a fork),
/// the signer resolved from `pinned` and the lineage head (`resolve_signer`,
/// else `OrgRoleDenied`), the signature,
/// then `check_transition`.
///
/// The pinned roster again returns `Ok` after comparing bodies only: it
/// proves nothing about the received signature, so never store the
/// received record, keep your own.
pub fn accept_next_roster(
    lineage: &OrgLineage,
    pinned: &RosterBody,
    next: &SignedRoster,
) -> Result<RosterBody> {
    let body = &next.body;
    body.check()?;
    if body.org_id != pinned.org_id || body.org_id != lineage.org_id {
        return Err(IntegrityError::WrongContext.into());
    }
    if body.seq == pinned.seq {
        return if body.hash() == pinned.hash() {
            Ok(pinned.clone())
        } else {
            Err(IntegrityError::OrgRosterFork.into())
        };
    }
    if body.seq < pinned.seq {
        return Err(IntegrityError::OrgRosterRollback.into());
    }
    if body.seq - pinned.seq > 1 {
        return Err(Error::NotFound);
    }
    if body.prev_hash != pinned.hash() {
        return Err(IntegrityError::OrgRosterFork.into());
    }
    // Before the signature check (an unlisted key costs no verification);
    // `check_transition` looks it up again as a standalone entry point.
    resolve_signer(lineage, pinned, &next.signer.fingerprint())?;
    verify_roster_sig(next)?;
    check_transition(lineage, pinned, body, &next.signer)?;
    Ok(body.clone())
}

/// Consecutive rosters after `pinned`; each must move the seq forward (a
/// repeated roster is a rollback). An empty chain keeps `pinned`.
pub fn accept_roster_chain(
    lineage: &OrgLineage,
    pinned: &RosterBody,
    chain: &[SignedRoster],
) -> Result<RosterBody> {
    let mut cur = pinned.clone();
    for rec in chain {
        if rec.body.seq <= cur.seq {
            accept_next_roster(lineage, &cur, rec)?;
            return Err(IntegrityError::OrgRosterRollback.into());
        }
        cur = accept_next_roster(lineage, &cur, rec)?;
    }
    Ok(cur)
}

/// The first pin (D12): `chain[0]` is the founding roster of its lineage
/// generation, or any later roster, signed by a device listed in the
/// `MemberRef` of an owner of `lineage.head()` (R7f) whose account is
/// Active with `Owner` in it, the owner mirror of its `org_head`
/// generation holding; the rest goes through `accept_roster_chain`. An
/// empty chain is `NotFound`.
pub fn accept_first_roster(lineage: &OrgLineage, chain: &[SignedRoster]) -> Result<RosterBody> {
    let (first, rest) = chain.split_first().ok_or(Error::NotFound)?;
    let body = &first.body;
    body.check()?;
    if body.org_id != lineage.org_id {
        return Err(IntegrityError::WrongContext.into());
    }
    let head = lineage.find(&body.org_head).ok_or(Error::NotFound)?;
    let fpr = first.signer.fingerprint();
    let owner = lineage
        .head()
        .owners
        .iter()
        .find(|r| r.devices.contains(&fpr))
        .ok_or_else(denied)?;
    let m = find(body, owner.account_id).ok_or_else(denied)?;
    if m.state != MemberState::Active || !m.roles.contains(Role::Owner) {
        return Err(denied());
    }
    check_owner_mirror(body, &head.owners)?;
    if body.seq == 1 && *body != founding_at(lineage.org_id, head)? {
        return Err(denied());
    }
    verify_roster_sig(first)?;
    accept_roster_chain(lineage, body, rest)
}
