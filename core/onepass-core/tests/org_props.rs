//! Roster properties (Business E1, plan B Task 11): the three-way merge
//! commutes and has the expected identities, two admins writing at once
//! converge whichever lands first, and an accepted chain is monotone (seq
//! by one, no member lost, Removed entries frozen, no role granted beyond
//! what the signer may grant). Keys come from `org_common` (made once per
//! binary); the operations are drawn on non-owner members so that an Admin
//! signer may sign every step, except in `accepted_chains_are_monotone`,
//! which draws random signers and operations and keeps the accepted steps.

mod org_common;

use onepass_core::Id;
use onepass_core::org::{
    DeviceFpr, MemberState, OrgMember, Role, RoleSet, RosterBody, accept_next_roster,
    accept_roster_chain, member_kem_hash, merge_members, rebase_roster,
};
use onepass_core::{Error, IntegrityError};
use org_common::*;
use proptest::collection::vec;
use proptest::prelude::*;

/// Non-owner accounts the operations act on (absent from the seed roster).
const TARGETS: std::ops::Range<u8> = 20..28;
/// Activation devices use indices `0..5`, added devices `5..10`: an
/// activation device is never dropped, so no Active member ends up
/// without a device whichever side dropped what.
const ACTIVATION_DEVICES: std::ops::Range<u8> = 0..5;
const EXTRA_DEVICES: std::ops::Range<u8> = 5..10;
/// At most this many devices per member after one side's operations, so
/// two sides together never exceed `MAX_MEMBER_DEVICES` (8).
const DEVICES_PER_SIDE: usize = 4;
const REMOVED_AT: i64 = 1_700_001_000;

#[derive(Debug, Clone)]
enum Op {
    Invite(u8, RoleSet),
    Activate(u8, u8),
    Grant(u8, Role),
    Revoke(u8, Role),
    Suspend(u8),
    Reactivate(u8),
    Remove(u8),
    AddDevice(u8, u8),
    DropDevice(u8, u8),
}

/// A synthetic device fingerprint of account `t`, index `k`.
fn fpr(t: u8, k: u8) -> DeviceFpr {
    let mut f = [0xD7; 32];
    f[0] = t;
    f[1] = k;
    f
}

/// The roles an Admin may grant (no Owner, no RecoveryOfficer).
fn admin_role() -> impl Strategy<Value = Role> + Clone {
    prop::sample::select(vec![
        Role::Admin,
        Role::UserManager,
        Role::PolicyManager,
        Role::Auditor,
        Role::Provisioner,
    ])
}

/// One operation on account drawn from `accounts`, roles from `role`.
fn op_on(
    accounts: impl Strategy<Value = u8> + Clone + 'static,
    role: impl Strategy<Value = Role> + Clone + 'static,
) -> impl Strategy<Value = Op> {
    let roles = vec(role.clone(), 0..3).prop_map(|r| RoleSet::of(&r));
    prop_oneof![
        (accounts.clone(), roles).prop_map(|(t, r)| Op::Invite(t, r)),
        (accounts.clone(), ACTIVATION_DEVICES).prop_map(|(t, k)| Op::Activate(t, k)),
        (accounts.clone(), role.clone()).prop_map(|(t, r)| Op::Grant(t, r)),
        (accounts.clone(), role).prop_map(|(t, r)| Op::Revoke(t, r)),
        accounts.clone().prop_map(Op::Suspend),
        accounts.clone().prop_map(Op::Reactivate),
        accounts.clone().prop_map(Op::Remove),
        (accounts.clone(), EXTRA_DEVICES).prop_map(|(t, k)| Op::AddDevice(t, k)),
        (accounts, EXTRA_DEVICES).prop_map(|(t, k)| Op::DropDevice(t, k)),
    ]
}

/// Operations an Admin may sign: on the non-owner targets, Admin roles.
fn ops() -> impl Strategy<Value = Vec<Op>> {
    vec(op_on(TARGETS, admin_role()), 0..10)
}

fn find_mut(members: &mut [OrgMember], a: Id) -> Option<&mut OrgMember> {
    members.iter_mut().find(|m| m.account_id == a)
}

/// `op` applied to `members` (written after `prev`) by account `by`; an
/// operation that does not fit the member's state is skipped, and so is
/// any change but a role change to an account `prev` does not hold (a
/// new entry starts Invited), and a state move `prev`'s state does not
/// allow (no Invited to Suspended in one step).
fn apply_op(prev: &RosterBody, members: &mut Vec<OrgMember>, op: &Op, by: Id) {
    let live = |m: &OrgMember| !matches!(m.state, MemberState::Removed { .. });
    let (Op::Activate(t, _)
    | Op::Suspend(t)
    | Op::Reactivate(t)
    | Op::Remove(t)
    | Op::AddDevice(t, _)
    | Op::DropDevice(t, _)) = *op
    else {
        return apply_role_op(members, op);
    };
    let Some(p) = find(prev, acct(t)) else {
        return;
    };
    match *op {
        Op::Activate(t, k) => {
            if p.state == MemberState::Invited
                && let Some(m) = find_mut(members, acct(t))
                && m.state == MemberState::Invited
            {
                let i = usize::from(t % 3);
                m.state = MemberState::Active;
                m.account_identity_pub = Some(identity_pool(i).1.clone());
                m.account_kem_hash = member_kem_hash(&kem_pool(i).1);
                m.devices = vec![fpr(t, k)];
            }
        }
        Op::Suspend(t) => {
            if p.state == MemberState::Active
                && let Some(m) = find_mut(members, acct(t))
                && m.state == MemberState::Active
            {
                m.state = MemberState::Suspended;
            }
        }
        Op::Reactivate(t) => {
            if p.state == MemberState::Suspended
                && let Some(m) = find_mut(members, acct(t))
                && m.state == MemberState::Suspended
            {
                m.state = MemberState::Active;
            }
        }
        Op::Remove(t) => {
            if let Some(m) = find_mut(members, acct(t))
                && live(m)
            {
                m.state = MemberState::Removed { at: REMOVED_AT, by };
                m.roles = RoleSet::EMPTY;
                m.devices.clear();
                // Keys stay as `prev` has them: an invitation activated
                // and removed in one step is the invitation removed.
                m.account_identity_pub = p.account_identity_pub.clone();
                m.account_kem_hash = p.account_kem_hash;
            }
        }
        Op::AddDevice(t, k) => {
            let f = fpr(t, k);
            if let Some(m) = find_mut(members, acct(t))
                && matches!(m.state, MemberState::Active | MemberState::Suspended)
                && m.devices.len() < DEVICES_PER_SIDE
                && let Err(i) = m.devices.binary_search(&f)
            {
                m.devices.insert(i, f);
            }
        }
        Op::DropDevice(t, k) => {
            let f = fpr(t, k);
            if let Some(m) = find_mut(members, acct(t))
                && let Ok(i) = m.devices.binary_search(&f)
            {
                m.devices.remove(i);
            }
        }
        _ => unreachable!("role operations return above"),
    }
}

/// An invitation or a role change.
fn apply_role_op(members: &mut Vec<OrgMember>, op: &Op) {
    let live = |m: &OrgMember| !matches!(m.state, MemberState::Removed { .. });
    match *op {
        Op::Invite(t, roles) => {
            if let Err(i) = members.binary_search_by(|m| m.account_id.cmp(&acct(t))) {
                members.insert(i, invited_member(STD_ORG, t, roles));
            }
        }
        Op::Grant(t, r) => {
            if let Some(m) = find_mut(members, acct(t))
                && live(m)
            {
                m.roles = m.roles.with(r);
            }
        }
        Op::Revoke(t, r) => {
            if let Some(m) = find_mut(members, acct(t))
                && live(m)
            {
                m.roles = m.roles.without(r);
            }
        }
        _ => unreachable!("not a role operation"),
    }
}

/// `prev.next()` with `ops` applied by account `by`.
fn apply(prev: &RosterBody, ops: &[Op], by: u8) -> RosterBody {
    let mut next = prev.next().unwrap();
    for op in ops {
        apply_op(prev, &mut next.members, op, acct(by));
    }
    next
}

/// `next` signed by account `by`'s device, accepted after `prev`.
fn accept(prev: &RosterBody, next: &RosterBody, by: u8) -> onepass_core::Result<RosterBody> {
    let s = std_org();
    accept_next_roster(&s.lineage, prev, &signed_by(next.clone(), s.dev(by)))
}

/// A base roster: the standard org's r3 followed by two rosters of an
/// Admin's operations (the first one invites, the second one may then
/// activate), returned with the roster between.
fn roster_strategy() -> impl Strategy<Value = (RosterBody, RosterBody)> {
    (ops(), ops()).prop_map(|(first, second)| {
        let mid = apply(std_org().roster(3), &first, ACC_A);
        let base = apply(&mid, &second, ACC_A);
        (mid, base)
    })
}

/// `mid` and `base` accepted after the standard org's r3 (A signed both).
fn accepted_base(mid: &RosterBody, base: &RosterBody) -> Result<(), TestCaseError> {
    let s = std_org();
    let got = accept(s.roster(3), mid, ACC_A);
    prop_assert!(got.is_ok(), "first base step refused: {:?}", got);
    let got = accept(mid, base, ACC_A);
    prop_assert!(got.is_ok(), "second base step refused: {:?}", got);
    Ok(())
}

fn merged(b: &RosterBody, x: &RosterBody, y: &RosterBody) -> String {
    format!("{:?}", merge_members(&b.members, &x.members, &y.members))
}

/// What `GRANT(S)` allows (the permission table as `rules.rs` implements
/// it): Owner or Admin grant every role but Owner and RecoveryOfficer, a
/// UserManager the manager roles it holds itself, anyone else nothing.
fn grantable(roles: RoleSet) -> RoleSet {
    let admin = RoleSet::of(&[
        Role::Admin,
        Role::UserManager,
        Role::PolicyManager,
        Role::Auditor,
        Role::Provisioner,
    ]);
    let manager = RoleSet::of(&[
        Role::UserManager,
        Role::PolicyManager,
        Role::Auditor,
        Role::Provisioner,
    ]);
    if roles.contains(Role::Owner) || roles.contains(Role::Admin) {
        admin
    } else if roles.contains(Role::UserManager) {
        roles.intersection(manager)
    } else {
        RoleSet::EMPTY
    }
}

fn owner_bit() -> RoleSet {
    RoleSet::of(&[Role::Owner])
}

/// The signers of `accepted_chains_are_monotone`: every account of the
/// standard org, and `None` for the server's own device.
fn signer_strategy() -> impl Strategy<Value = Option<u8>> {
    prop::sample::select(vec![
        Some(ACC_O),
        Some(ACC_A),
        Some(ACC_B),
        Some(ACC_U),
        Some(ACC_P),
        Some(ACC_M),
        None,
    ])
}

/// A step by a random signer: random operations on any account, any role
/// (Owner included).
fn signed_op() -> impl Strategy<Value = (Option<u8>, Vec<Op>)> {
    let accounts = prop::sample::select(
        [ACC_O, ACC_A, ACC_B, ACC_U, ACC_P, ACC_M]
            .into_iter()
            .chain(TARGETS)
            .collect::<Vec<_>>(),
    );
    let role = prop::sample::select(vec![
        Role::Owner,
        Role::Admin,
        Role::UserManager,
        Role::PolicyManager,
        Role::Auditor,
        Role::Provisioner,
    ]);
    (signer_strategy(), vec(op_on(accounts, role), 1..4))
}

fn server_device() -> &'static TestDevice {
    static CELL: std::sync::OnceLock<TestDevice> = std::sync::OnceLock::new();
    CELL.get_or_init(|| device(0xEE))
}

fn encoded(m: &OrgMember) -> Vec<u8> {
    postcard::to_allocvec(m).unwrap()
}

fn find(b: &RosterBody, a: Id) -> Option<&OrgMember> {
    b.members.iter().find(|m| m.account_id == a)
}

fn is_removed(m: Option<&OrgMember>) -> bool {
    matches!(m.map(|m| &m.state), Some(MemberState::Removed { .. }))
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

    #[test]
    fn merge_commutes((_, base) in roster_strategy(), ops_a in ops(), ops_b in ops()) {
        let x = apply(&base, &ops_a, ACC_A);
        let y = apply(&base, &ops_b, ACC_B);
        prop_assert_eq!(merged(&base, &x, &y), merged(&base, &y, &x));
    }

    #[test]
    fn merge_identities((_, base) in roster_strategy(), ops_a in ops()) {
        let x = apply(&base, &ops_a, ACC_A);
        let b = &base.members;
        prop_assert_eq!(merge_members(b, b, b).unwrap(), b.clone());
        prop_assert_eq!(merge_members(b, &x.members, b).unwrap(), x.members.clone());
        prop_assert_eq!(merge_members(b, b, &x.members).unwrap(), x.members.clone());
        prop_assert_eq!(merge_members(b, &x.members, &x.members).unwrap(), x.members.clone());
    }

    #[test]
    fn concurrent_admins_converge((mid, base) in roster_strategy(), ops_a in ops(), ops_b in ops()) {
        let s = std_org();
        let l = &s.lineage;
        accepted_base(&mid, &base)?;
        let xa = apply(&base, &ops_a, ACC_A);
        let yb = apply(&base, &ops_b, ACC_B);
        prop_assert_eq!(accept(&base, &xa, ACC_A).unwrap(), xa.clone());
        prop_assert_eq!(accept(&base, &yb, ACC_B).unwrap(), yb.clone());
        // Order 1: A's roster lands at n + 1, B rebases to n + 2.
        let one = rebase_roster(l, &base, &yb, &xa, &s.b.public);
        prop_assert!(one.is_ok(), "B rebases over A: {:?}", one);
        let one = one.unwrap();
        prop_assert_eq!(accept(&xa, &one, ACC_B).unwrap(), one.clone());
        // Order 2: B's roster lands, A rebases.
        let two = rebase_roster(l, &base, &xa, &yb, &s.a.public);
        prop_assert!(two.is_ok(), "A rebases over B: {:?}", two);
        let two = two.unwrap();
        prop_assert_eq!(accept(&yb, &two, ACC_A).unwrap(), two.clone());
        let chain = [signed_by(xa.clone(), &s.a), signed_by(one.clone(), &s.b)];
        prop_assert_eq!(accept_roster_chain(l, &base, &chain).unwrap(), one.clone());
        prop_assert_eq!(one.members.len(), two.members.len());
        for (m1, m2) in one.members.iter().zip(&two.members) {
            prop_assert_eq!(m1.account_id, m2.account_id);
            let a = m1.account_id;
            let (in_xa, in_yb) = (find(&xa, a), find(&yb, a));
            if is_removed(in_xa) && is_removed(in_yb) {
                // X13: both removed it; each order keeps the landed removal.
                prop_assert_eq!(Some(m1), in_xa);
                prop_assert_eq!(Some(m2), in_yb);
            } else if is_removed(in_xa) != is_removed(in_yb) {
                // One side removed it. The landed removal is terminal and
                // keys never change once set (X12), so when the other side
                // activated it the two orders agree on everything but the
                // keys: the order where the removal landed first keeps the
                // invitation's (none).
                let strip = |m: &OrgMember| OrgMember {
                    account_identity_pub: None,
                    account_kem_hash: [0; 32],
                    ..m.clone()
                };
                prop_assert_eq!(strip(m1), strip(m2));
                let removed = if is_removed(in_xa) { in_xa } else { in_yb }.unwrap();
                let landed_first = if is_removed(in_xa) { m1 } else { m2 };
                prop_assert_eq!(landed_first, removed);
                if m1 != m2 {
                    prop_assert!(removed.account_identity_pub.is_none());
                    let other = if is_removed(in_xa) { in_yb } else { in_xa }.unwrap();
                    let later = if is_removed(in_xa) { m2 } else { m1 };
                    prop_assert_eq!(&later.account_identity_pub, &other.account_identity_pub);
                    prop_assert_eq!(later.account_kem_hash, other.account_kem_hash);
                }
            } else {
                prop_assert_eq!(m1, m2);
            }
        }
    }

    #[test]
    fn accepted_chains_are_monotone(
        (mid, base) in roster_strategy(),
        steps in vec(signed_op(), 1..12),
    ) {
        let s = std_org();
        let l = &s.lineage;
        accepted_base(&mid, &base)?;
        let head_owners: Vec<Id> = l.head().owners.iter().map(|r| r.account_id).collect();
        let mut cur = base;
        for (signer, ops) in steps {
            let (by, d) = match signer {
                Some(a) => (acct(a), s.dev(a)),
                None => (Id([0xEE; 16]), server_device()),
            };
            let mut next = cur.next().unwrap();
            for op in &ops {
                apply_op(&cur, &mut next.members, op, by);
            }
            if next.check().is_err() {
                continue;
            }
            let rec = signed_by(next, d);
            let accepted = match accept_next_roster(l, &cur, &rec) {
                Ok(b) => b,
                Err(Error::Integrity(IntegrityError::OrgRoleDenied)) => continue,
                Err(e) => return Err(TestCaseError::fail(format!("unexpected refusal: {e:?}"))),
            };
            prop_assert_eq!(&accepted, &rec.body);
            prop_assert_eq!(accepted.seq, cur.seq + 1);
            // The signer, as the pinned roster lists it (the lineage head
            // lists O's only device, so Owner authority is O's entry's).
            let holder = cur.device_holder(&d.public.fingerprint());
            prop_assert!(holder.is_some(), "accepted from an unlisted device");
            let holder = holder.unwrap();
            prop_assert_eq!(&holder.state, &MemberState::Active);
            let grant = grantable(holder.roles);
            let manager = [Role::Owner, Role::Admin, Role::UserManager]
                .iter()
                .any(|r| holder.roles.contains(*r));
            for p in &cur.members {
                let e = find(&accepted, p.account_id);
                prop_assert!(e.is_some(), "member dropped");
                if matches!(p.state, MemberState::Removed { .. }) {
                    prop_assert_eq!(encoded(e.unwrap()), encoded(p), "removed entry changed");
                }
            }
            for e in &accepted.members {
                let p = find(&cur, e.account_id);
                if p == Some(e) {
                    continue;
                }
                let p_roles = p.map_or(RoleSet::EMPTY, |p| p.roles);
                if e.account_id == holder.account_id {
                    prop_assert!(e.roles.is_subset(p_roles), "signer grew its own roles");
                    continue;
                }
                let added = e.roles.difference(p_roles).difference(owner_bit());
                prop_assert!(added.is_subset(grant), "granted {:?} beyond {:?}", added, grant);
                if let Some(p) = p {
                    let activation =
                        p.state == MemberState::Invited && e.state == MemberState::Active;
                    let removal = matches!(e.state, MemberState::Removed { .. });
                    // A Provisioner's removal clears devices and roles
                    // through its own rule (D7), not the manager table.
                    if (e.devices != p.devices || activation) && (manager || !removal) {
                        // X7: taking over an account needs every role it holds.
                        prop_assert!(
                            p.roles.union(e.roles).difference(owner_bit()).is_subset(grant),
                            "took over a member beyond GRANT"
                        );
                    }
                }
            }
            let owners: Vec<Id> = accepted
                .members
                .iter()
                .filter(|m| m.roles.contains(Role::Owner))
                .map(|m| m.account_id)
                .collect();
            prop_assert_eq!(&owners, &head_owners);
            cur = accepted;
        }
    }
}
