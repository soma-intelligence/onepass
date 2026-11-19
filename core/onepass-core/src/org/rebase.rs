//! Rebase after a lost write (plan B Task 8): two rosters written after the
//! same `base` (siblings), one of which (`theirs`) took the next seq first.
//! The other side's change is merged three-way into a roster that follows
//! `theirs`, then checked as if its signer had written it after `theirs`
//! (`check_transition`), so a merge never grants what the signer could
//! not have signed itself.
//!
//! The merge is per account and symmetric in the two sides: a removal wins
//! (copied from the side that removed, the earlier `(at, by)` when both
//! did, but with the keys of an activation only the other side made), a
//! state changed on one side only follows that side and a state changed
//! on both sides is the more restrictive one, roles and devices are merged
//! per bit and per fingerprint, and the keys (identity, KEM hash) with the
//! directory and invitation hashes come together from one side, never
//! mixed.

use std::collections::BTreeSet;

use super::{
    DeviceFpr, MAX_ROSTER_MEMBERS, MemberState, ORG_FORMAT, OrgId, OrgLineage, OrgMember, RoleSet,
    RosterBody, check_transition,
};
use crate::device_keys::DevicePublic;
use crate::{Error, Id, Result, ValidationError};

fn bad(what: &'static str) -> Error {
    Error::InvalidFormat(what)
}

/// The entry of account `a` in a list sorted by account id.
fn find(list: &[OrgMember], a: Id) -> Option<&OrgMember> {
    list.binary_search_by(|m| m.account_id.cmp(&a))
        .ok()
        .map(|i| &list[i])
}

fn encoded(m: &OrgMember) -> Vec<u8> {
    postcard::to_allocvec(m).expect("org member encodes")
}

/// The entry with the smaller postcard encoding (the symmetric tie-break).
fn smaller<'a>(x: &'a OrgMember, y: &'a OrgMember) -> &'a OrgMember {
    if encoded(x) <= encoded(y) { x } else { y }
}

fn removed_key(m: &OrgMember) -> Option<(i64, Id)> {
    match m.state {
        MemberState::Removed { at, by } => Some((at, by)),
        _ => None,
    }
}

fn rank(s: &MemberState) -> u8 {
    match s {
        MemberState::Invited => 0,
        MemberState::Active => 1,
        MemberState::Suspended => 2,
        MemberState::Removed { .. } => 3,
    }
}

/// One account: `x` and `y` the two sides (the base entry where a side has
/// none), `b` the base entry if any.
fn join(x: &OrgMember, y: &OrgMember, b: Option<&OrgMember>) -> OrgMember {
    if x == y {
        return x.clone();
    }
    let keys = |m: &OrgMember| (m.account_identity_pub.clone(), m.account_kem_hash);
    // A removal wins, copied from the side that removed, except the keys:
    // when only the other side's keys moved off the base (an activation
    // the removal did not see), they come from that side with its
    // directory and invitation hashes, since keys never change once set
    // (X12).
    let removal = |r: &OrgMember, o: &OrgMember| {
        let mut out = r.clone();
        if let Some(b) = b
            && keys(o) != keys(b)
            && keys(r) == keys(b)
        {
            out.account_identity_pub = o.account_identity_pub.clone();
            out.account_kem_hash = o.account_kem_hash;
            out.scim_id_hash = o.scim_id_hash;
            out.invite_commit = o.invite_commit;
        }
        out
    };
    match (removed_key(x), removed_key(y)) {
        (Some(kx), Some(ky)) if kx != ky => return if kx < ky { x } else { y }.clone(),
        (Some(_), Some(_)) => return smaller(x, y).clone(),
        (Some(_), None) => return removal(x, y),
        (None, Some(_)) => return removal(y, x),
        (None, None) => {}
    }
    let state = match b {
        Some(b) if y.state == b.state => x.state.clone(),
        Some(b) if x.state == b.state => y.state.clone(),
        _ if x.state == y.state => x.state.clone(),
        _ => {
            if rank(&x.state) >= rank(&y.state) {
                x.state.clone()
            } else {
                y.state.clone()
            }
        }
    };
    // Per bit: the side that changed it, else (no base) the intersection.
    let (xr, yr) = (x.roles.bits(), y.roles.bits());
    let roles_bits = match b {
        Some(b) => {
            let differ = xr ^ yr;
            // Where the sides disagree, one of them equals the base; take
            // the other one's bit, which is the inverse of the base's.
            (xr & !differ) | (!b.roles.bits() & differ)
        }
        None => xr & yr,
    };
    let roles = RoleSet::try_from(roles_bits).expect("role bits of two valid sets");
    // Per fingerprint: present iff both sides agree it is, or the side that
    // differs from the base has it.
    let all: BTreeSet<&DeviceFpr> = x.devices.iter().chain(&y.devices).collect();
    let devices = all
        .into_iter()
        .filter(|f| {
            let (hx, hy) = (x.devices.contains(f), y.devices.contains(f));
            if hx == hy {
                hx
            } else {
                b.is_some_and(|b| !b.devices.contains(f))
            }
        })
        .copied()
        .collect();
    // Keys and hashes together from one side: the one whose keys moved off
    // the base, else the smaller encoding.
    let from = match b {
        Some(b) if keys(x) != keys(b) && keys(y) == keys(b) => x,
        Some(b) if keys(y) != keys(b) && keys(x) == keys(b) => y,
        _ => smaller(x, y),
    };
    OrgMember {
        account_id: x.account_id,
        account_identity_pub: from.account_identity_pub.clone(),
        scim_id_hash: from.scim_id_hash,
        invite_commit: from.invite_commit,
        account_kem_hash: from.account_kem_hash,
        roles,
        state,
        devices,
    }
}

fn check_list(list: &[OrgMember]) -> Result<()> {
    if list.len() > MAX_ROSTER_MEMBERS {
        return Err(bad("org roster size"));
    }
    if !list.windows(2).all(|w| w[0].account_id < w[1].account_id) {
        return Err(bad("roster members order"));
    }
    Ok(())
}

/// The three-way merge of two member lists written after `base`, sorted by
/// account id, symmetric in `mine` and `theirs`. Each input must be sorted
/// and unique; more than `MAX_ROSTER_MEMBERS` accounts in all is
/// `InvalidFormat("org roster size")`; a result that breaks a roster shape
/// rule (a removed entry with roles, a device held twice, too many devices)
/// is the `InvalidFormat` of `RosterBody::check`. That holds even when the
/// three inputs are equal: members that fail the roster shape are an
/// `Err`, never passed through.
pub fn merge_members(
    base: &[OrgMember],
    mine: &[OrgMember],
    theirs: &[OrgMember],
) -> Result<Vec<OrgMember>> {
    check_list(base)?;
    check_list(mine)?;
    check_list(theirs)?;
    let ids: BTreeSet<Id> = base
        .iter()
        .chain(mine)
        .chain(theirs)
        .map(|m| m.account_id)
        .collect();
    if ids.len() > MAX_ROSTER_MEMBERS {
        return Err(bad("org roster size"));
    }
    let mut out = Vec::with_capacity(ids.len());
    for a in ids {
        let b = find(base, a);
        let (x, y) = match (find(mine, a).or(b), find(theirs, a).or(b)) {
            (Some(x), Some(y)) => (x, y),
            (Some(x), None) => (x, x),
            (None, Some(y)) => (y, y),
            (None, None) => unreachable!("an account of the union"),
        };
        out.push(join(x, y, b));
    }
    // The shape rules of a roster body, on the merged list alone.
    let probe = RosterBody {
        format: ORG_FORMAT,
        org_id: OrgId([0; 16]),
        seq: 1,
        prev_hash: [0; 32],
        org_head: [0; 32],
        members: out,
    };
    probe.check()?;
    Ok(probe.members)
}

fn not_siblings() -> Error {
    Error::Validation(ValidationError {
        field: "org roster".into(),
        reason: "not siblings",
    })
}

/// `mine` rebased over `theirs`, both written after `base` (same org id,
/// same seq `base.seq + 1`, both `prev_hash == base.hash()`, else
/// `Validation("not siblings")`): `theirs.next()` with the merged members
/// (every member theirs has as Removed kept as theirs wrote it, R8a) and
/// the newer (by lineage generation) of the two org heads, accepted by
/// `check_transition(lineage, theirs, out, signer)` (else its error,
/// `OrgRoleDenied` for a change `signer` may not sign). An org head the
/// lineage does not know is `NotFound`.
pub fn rebase_roster(
    lineage: &OrgLineage,
    base: &RosterBody,
    mine: &RosterBody,
    theirs: &RosterBody,
    signer: &DevicePublic,
) -> Result<RosterBody> {
    let parent = base.hash();
    if mine.org_id != base.org_id
        || theirs.org_id != base.org_id
        || mine.seq != theirs.seq
        || base.seq.checked_add(1) != Some(mine.seq)
        || mine.prev_hash != parent
        || theirs.prev_hash != parent
    {
        return Err(not_siblings());
    }
    base.check()?;
    mine.check()?;
    theirs.check()?;
    let mine_head = lineage.find(&mine.org_head).ok_or(Error::NotFound)?;
    let theirs_head = lineage.find(&theirs.org_head).ok_or(Error::NotFound)?;
    let org_head = if mine_head.generation > theirs_head.generation {
        mine.org_head
    } else {
        theirs.org_head
    };
    let mut out = theirs.next()?;
    out.members = merge_members(&base.members, &mine.members, &theirs.members)?;
    // R8a: a removal theirs already landed is terminal; when both sides
    // removed a member, keep theirs' entry even if mine's `(at, by)` is
    // smaller (the merge itself stays symmetric).
    for t in &theirs.members {
        if matches!(t.state, MemberState::Removed { .. })
            && let Ok(i) = out
                .members
                .binary_search_by(|m| m.account_id.cmp(&t.account_id))
        {
            out.members[i] = t.clone();
        }
    }
    out.org_head = org_head;
    check_transition(lineage, theirs, &out, signer)?;
    Ok(out)
}
