//! Attack regressions for organizations (Business E1, plan B Task 11),
//! named after spec 14 and the server's powers. The server is modelled as
//! bytes it can rewrite: it serves records, replays old ones, signs with
//! its own device keys and may hold an org identity of its own making; it
//! never holds an owner's or a member's device keys.

mod org_common;

use std::sync::OnceLock;

use onepass_core::crypto::{HybridKemSecret, IdentityKey};
use onepass_core::org::{
    MemberRef, MemberState, OrgChangeBody, OrgChangeKind, OrgGenesisBody, OrgId, OrgKeyset,
    OrgLineage, OrgMember, OrgPin, OrgSecrets, PinSource, Role, RoleSet, RosterBody,
    SealedOrgKeyset, SignedOrgRecord, SignedRoster, accept_first_roster, accept_next_roster,
    founding_roster, invite_member, member_kem_hash, open_org_keyset, pin_org, scim_id_hash,
    seal_org_keyset, sign_join_request, sign_org_change, sign_org_genesis, verify_join_request,
    verify_org_genesis,
};
use onepass_core::repo::ManagedGenesis;
use onepass_core::{Error, IntegrityError};
use org_common::*;

/// Accounts the attacks add.
const X: u8 = 20;
const Y: u8 = 21;
const Z: u8 = 22;
const NEWCOMER: u8 = 23;
/// The server's own account in the orgs it makes up.
const SERVER: u8 = 0x55;

fn integrity<T: std::fmt::Debug>(r: onepass_core::Result<T>, want: IntegrityError, what: &str) {
    match r {
        Err(Error::Integrity(e)) if e == want => {}
        other => panic!("{what}: expected Integrity({want:?}), got {other:?}"),
    }
}

fn denied<T: std::fmt::Debug>(r: onepass_core::Result<T>, what: &str) {
    integrity(r, IntegrityError::OrgRoleDenied, what);
}

/// The standard org carried on to seq 7: r4 and r5 by O unchanged, r6 O
/// removes admin B, r7 A invites X with {Auditor}. `pinned` is a device's
/// DNS pin of the org advanced to r7.
struct Attacks {
    chain: Vec<SignedRoster>,
    pinned: OrgPin,
}

fn attacks() -> &'static Attacks {
    static CELL: OnceLock<Attacks> = OnceLock::new();
    CELL.get_or_init(|| {
        let s = std_org();
        let r3 = s.roster(3);
        let r4 = r3.next().unwrap();
        let r5 = r4.next().unwrap();
        let mut r6 = r5.next().unwrap();
        let b = r6
            .members
            .iter_mut()
            .find(|m| m.account_id == acct(ACC_B))
            .unwrap();
        b.state = MemberState::Removed {
            at: 1_700_000_600,
            by: acct(ACC_O),
        };
        b.roles = RoleSet::EMPTY;
        b.devices.clear();
        let mut r7 = r6.next().unwrap();
        upsert_member(
            &mut r7,
            invited_member(STD_ORG, X, RoleSet::of(&[Role::Auditor])),
        );
        let mut chain = s.chain.clone();
        chain.push(signed_by(r4, &s.o));
        chain.push(signed_by(r5, &s.o));
        chain.push(signed_by(r6, &s.o));
        chain.push(signed_by(r7, &s.a));
        let pinned = pin_org(
            PinSource::Dns,
            Some(s.lineage.fingerprint),
            &s.genesis.encode(),
        )
        .unwrap()
        .advance(&genesis_list(), &served(&chain))
        .unwrap();
        assert_eq!(pinned.roster_seq(), Some(7));
        Attacks { chain, pinned }
    })
}

/// Roster `seq` of the attack chain.
fn r(seq: usize) -> &'static RosterBody {
    &attacks().chain[seq - 1].body
}

fn signed(seq: usize) -> &'static SignedRoster {
    &attacks().chain[seq - 1]
}

fn lineage() -> &'static OrgLineage {
    &std_org().lineage
}

/// What the server serves for the lineage: the pinned genesis.
fn genesis_list() -> Vec<(u64, Vec<u8>)> {
    vec![(0, std_org().genesis.encode())]
}

fn served(rosters: &[SignedRoster]) -> Vec<(u64, Vec<u8>)> {
    rosters.iter().map(|r| (r.body.seq, r.encode())).collect()
}

/// `prev.next()` edited by `f`.
fn edit(prev: &RosterBody, f: impl FnOnce(&mut RosterBody)) -> RosterBody {
    let mut n = prev.next().unwrap();
    f(&mut n);
    n
}

fn entry(b: &mut RosterBody, a: u8) -> &mut OrgMember {
    b.members
        .iter_mut()
        .find(|m| m.account_id == acct(a))
        .unwrap()
}

/// An Active member as the server would write it: pool keys, one
/// synthetic device fingerprint.
fn forged_active(a: u8) -> OrgMember {
    let i = usize::from(a % 3);
    OrgMember {
        account_id: acct(a),
        account_identity_pub: Some(identity_pool(i).1.clone()),
        scim_id_hash: [0; 32],
        invite_commit: [0; 32],
        account_kem_hash: member_kem_hash(&kem_pool(i).1),
        roles: RoleSet::of(&[Role::Admin]),
        state: MemberState::Active,
        devices: vec![[0xF0; 32]],
    }
}

/// The server's own device.
fn server_device() -> &'static TestDevice {
    static CELL: OnceLock<TestDevice> = OnceLock::new();
    CELL.get_or_init(|| device(0xEE))
}

#[test]
fn fixture_chain_is_accepted() {
    let a = attacks();
    let s = std_org();
    assert_eq!(
        accept_first_roster(&s.lineage, &a.chain).unwrap(),
        *r(7),
        "the attack chain is a valid history"
    );
    assert_eq!(a.pinned.roster(), Some(r(7)));
}

#[test]
fn a4_server_adds_member() {
    // The server rewrites the bytes of the latest roster (r7, signed by A)
    // to add an Active Admin, keeping A's signature.
    let mut rec = SignedRoster::decode(&signed(7).encode()).unwrap();
    upsert_member(&mut rec.body, forged_active(NEWCOMER));
    let bytes = rec.encode();
    let tampered = SignedRoster::decode(&bytes).unwrap();
    integrity(
        accept_next_roster(lineage(), r(6), &tampered),
        IntegrityError::Signature,
        "edited roster",
    );
    // Through the pin, as a device at r6 would fetch it.
    let at6 = pin_org(
        PinSource::Dns,
        Some(lineage().fingerprint),
        &std_org().genesis.encode(),
    )
    .unwrap()
    .advance(&genesis_list(), &served(&attacks().chain[..6]))
    .unwrap();
    integrity(
        at6.advance(&genesis_list(), &[(7, bytes)]),
        IntegrityError::Signature,
        "edited roster through the pin",
    );
}

#[test]
fn a4_server_signs_with_unknown_device() {
    // The server signs its own r8 with a device the pinned roster does not
    // list: whatever the change, the signer is unknown.
    let sd = server_device();
    let add = edit(r(7), |b| upsert_member(b, forged_active(NEWCOMER)));
    denied(
        accept_next_roster(lineage(), r(7), &signed_by(add, sd)),
        "server adds a member",
    );
    let unchanged = r(7).next().unwrap();
    let rec = signed_by(unchanged, sd);
    denied(
        accept_next_roster(lineage(), r(7), &rec),
        "server signs an unchanged roster",
    );
    denied(
        attacks()
            .pinned
            .advance(&genesis_list(), &served(std::slice::from_ref(&rec))),
        "through the pin",
    );
    // Nor can it start a first pin.
    let first = signed_by(founding_roster(lineage()).unwrap(), sd);
    denied(
        accept_first_roster(lineage(), &[first]),
        "server signs the founding roster",
    );
}

#[test]
fn role_escalation_user_manager_to_admin() {
    let s = std_org();
    for role in [Role::Admin, Role::PolicyManager, Role::Owner] {
        let next = edit(r(7), |b| {
            let e = entry(b, ACC_U);
            e.roles = e.roles.with(role);
        });
        denied(
            accept_next_roster(lineage(), r(7), &signed_by(next, &s.u)),
            &format!("U grants itself {role:?}"),
        );
    }
}

#[test]
fn role_escalation_via_new_member() {
    let s = std_org();
    // U invites an account it controls with {Admin}, or with a role U does
    // not hold itself.
    for roles in [
        RoleSet::of(&[Role::Admin]),
        RoleSet::of(&[Role::Auditor]),
        RoleSet::of(&[Role::UserManager, Role::Admin]),
    ] {
        let next = edit(r(7), |b| {
            upsert_member(b, invited_member(STD_ORG, NEWCOMER, roles))
        });
        denied(
            accept_next_roster(lineage(), r(7), &signed_by(next, &s.u)),
            &format!("U invites with {roles:?}"),
        );
    }
    // Nor raise an invitation it did not make: A's invitee X holds
    // {Auditor}; U may not grant it Admin.
    let next = edit(r(7), |b| {
        let e = entry(b, X);
        e.roles = e.roles.with(Role::Admin);
    });
    denied(
        accept_next_roster(lineage(), r(7), &signed_by(next, &s.u)),
        "U grants Admin to an invitee",
    );
    // What U may do: invite with a role it holds.
    let next = edit(r(7), |b| {
        upsert_member(
            b,
            invited_member(STD_ORG, NEWCOMER, RoleSet::of(&[Role::UserManager])),
        )
    });
    accept_next_roster(lineage(), r(7), &signed_by(next, &s.u)).unwrap();
}

#[test]
fn role_escalation_provisioner_invites() {
    let s = std_org();
    for roles in [RoleSet::EMPTY, RoleSet::of(&[Role::Provisioner])] {
        let next = edit(r(7), |b| {
            upsert_member(b, invited_member(STD_ORG, NEWCOMER, roles))
        });
        denied(
            accept_next_roster(lineage(), r(7), &signed_by(next, &s.p)),
            &format!("P invites with {roles:?}"),
        );
    }
    // Nor grant a role to someone already there.
    let next = edit(r(7), |b| {
        let e = entry(b, ACC_M);
        e.roles = e.roles.with(Role::Provisioner);
    });
    denied(
        accept_next_roster(lineage(), r(7), &signed_by(next, &s.p)),
        "P grants Provisioner",
    );
}

#[test]
fn removed_admin_signs_after_removal() {
    let s = std_org();
    // B removed at seq 6; B's device signs seq 7 (in place of A's r7), or
    // seq 8 after r7, or tries to put itself back.
    let seven = r(6).next().unwrap();
    denied(
        accept_next_roster(lineage(), r(6), &signed_by(seven, &s.b)),
        "removed admin signs seq 7",
    );
    let eight = r(7).next().unwrap();
    denied(
        accept_next_roster(lineage(), r(7), &signed_by(eight, &s.b)),
        "removed admin signs seq 8",
    );
    let back = edit(r(7), |b| {
        let e = entry(b, ACC_B);
        e.state = MemberState::Active;
        e.roles = RoleSet::of(&[Role::Admin]);
        e.devices = vec![s.b.public.fingerprint()];
    });
    denied(
        accept_next_roster(lineage(), r(7), &signed_by(back.clone(), &s.b)),
        "removed admin restores itself",
    );
    // A Removed entry never changes, whoever signs.
    denied(
        accept_next_roster(lineage(), r(7), &signed_by(back, &s.o)),
        "owner restores a removed admin",
    );
}

#[test]
fn replay_old_roster() {
    let a = attacks();
    integrity(
        accept_next_roster(lineage(), r(7), signed(5)),
        IntegrityError::OrgRosterRollback,
        "seq 5 after seq 7",
    );
    integrity(
        a.pinned.advance(&genesis_list(), &served(&a.chain[4..5])),
        IntegrityError::OrgRosterRollback,
        "seq 5 served to a device pinned at 7",
    );
    integrity(
        a.pinned.advance(&genesis_list(), &served(&a.chain[..5])),
        IntegrityError::OrgRosterRollback,
        "the chain up to 5 served to a device pinned at 7",
    );
}

#[test]
fn fork_two_rosters_same_seq() {
    let s = std_org();
    let a = attacks();
    // Two valid seq 8: A invites Y, U invites Z; the server shows each to
    // one device.
    let by_a = signed_by(
        edit(r(7), |b| {
            upsert_member(b, invited_member(STD_ORG, Y, RoleSet::of(&[Role::Auditor])))
        }),
        &s.a,
    );
    let by_u = signed_by(
        edit(r(7), |b| {
            upsert_member(
                b,
                invited_member(STD_ORG, Z, RoleSet::of(&[Role::UserManager])),
            )
        }),
        &s.u,
    );
    let d1 = a
        .pinned
        .advance(&genesis_list(), &served(std::slice::from_ref(&by_a)))
        .unwrap();
    let d2 = a
        .pinned
        .advance(&genesis_list(), &served(std::slice::from_ref(&by_u)))
        .unwrap();
    assert_eq!(d1.roster(), Some(&by_a.body));
    assert_eq!(d2.roster(), Some(&by_u.body));
    // Each device then sees the other's roster: a fork, never a switch.
    integrity(
        d1.advance(&genesis_list(), &served(std::slice::from_ref(&by_u))),
        IntegrityError::OrgRosterFork,
        "first device sees the other seq 8",
    );
    integrity(
        d2.advance(&genesis_list(), &served(std::slice::from_ref(&by_a))),
        IntegrityError::OrgRosterFork,
        "second device sees the other seq 8",
    );
    integrity(
        accept_next_roster(lineage(), &by_a.body, &by_u),
        IntegrityError::OrgRosterFork,
        "accept_next_roster",
    );
    // A seq 9 built on the other branch is a fork as well.
    let nine = signed_by(by_u.body.next().unwrap(), &s.u);
    integrity(
        d1.advance(&genesis_list(), &served(std::slice::from_ref(&nine))),
        IntegrityError::OrgRosterFork,
        "seq 9 on the other branch",
    );
}

/// Owners for the lineage attacks: account 11 with two devices, 12 and 13
/// with one each; a 2-owner org {11, 12} and a 3-owner org {11, 12, 13},
/// both under the test org identity, at generation 0.
struct Owners {
    x1: TestDevice,
    x2: TestDevice,
    y: TestDevice,
    z: TestDevice,
    two: OrgLineage,
    three: OrgLineage,
}

const OX: u8 = 11;
const OY: u8 = 12;
const OZ: u8 = 13;

fn owners_org(org_id: OrgId, owners: Vec<MemberRef>, signers: &[&TestDevice]) -> SignedOrgRecord {
    let secrets = org_secrets();
    let devices: Vec<_> = signers.iter().map(|d| (&d.public, &d.keys)).collect();
    sign_org_genesis(
        OrgGenesisBody {
            format: 1,
            org_id,
            name: "Owners".to_string(),
            org_identity_pub: secrets.identity.verifying_key(),
            audit_kem_pub: secrets.audit.public().unwrap(),
            owners,
            created_at: 1_700_000_000,
        },
        &secrets.identity,
        &devices,
    )
    .unwrap()
}

fn owners() -> &'static Owners {
    static CELL: OnceLock<Owners> = OnceLock::new();
    CELL.get_or_init(|| {
        let (x1, x2, y, z) = (device(0x11), device(0x12), device(0x13), device(0x14));
        let two = verify_org_genesis(&owners_org(
            OrgId([11; 16]),
            vec![member_ref(OX, &[&x1, &x2]), member_ref(OY, &[&y])],
            &[&x1, &y],
        ))
        .unwrap();
        let three = verify_org_genesis(&owners_org(
            OrgId([12; 16]),
            vec![
                member_ref(OX, &[&x1, &x2]),
                member_ref(OY, &[&y]),
                member_ref(OZ, &[&z]),
            ],
            &[&x1, &y],
        ))
        .unwrap();
        Owners {
            x1,
            x2,
            y,
            z,
            two,
            three,
        }
    })
}

/// The next change of `l` (an audit key rotation), signed by the org
/// identity and `signers`.
fn audit_rotation(l: &OrgLineage, signers: &[&TestDevice]) -> SignedOrgRecord {
    let devices: Vec<_> = signers.iter().map(|d| (&d.public, &d.keys)).collect();
    sign_org_change(
        OrgChangeBody {
            format: 1,
            org_id: l.org_id,
            generation: l.head().generation + 1,
            parent: l.head().hash,
            kind: OrgChangeKind::AuditKeyRotated {
                audit_kem_pub: kem_pool(2).1.clone(),
            },
            issued_at: 1_700_000_100,
        },
        &org_secrets().identity,
        &devices,
    )
    .unwrap()
}

#[test]
fn fork_lineage_two_owner_sets() {
    // Two valid generation 1 records of the standard org, each signed by
    // the identity and the sole owner O: owners {O, M} and owners {O, A}.
    let s = std_org();
    let l0 = lineage();
    let change = |extra: u8, d: &TestDevice| {
        let mut owners = vec![member_ref(ACC_O, &[&s.o]), member_ref(extra, &[d])];
        owners.sort_by_key(|m| m.account_id);
        sign_org_change(
            OrgChangeBody {
                format: 1,
                org_id: STD_ORG,
                generation: 1,
                parent: l0.head().hash,
                kind: OrgChangeKind::OwnersChanged { owners },
                issued_at: 1_700_000_100,
            },
            &org_secrets().identity,
            &[(&s.o.public, &s.o.keys)],
        )
        .unwrap()
    };
    let g1a = change(ACC_M, &s.m);
    let g1b = change(ACC_A, &s.a);
    let la = l0.apply(&g1a).unwrap();
    let lb = l0.apply(&g1b).unwrap();
    integrity(la.apply(&g1b), IntegrityError::OrgLineageFork, "a then b");
    integrity(lb.apply(&g1a), IntegrityError::OrgLineageFork, "b then a");
    // Through the pin: a device at g1a is served g1b.
    let pin = pin_org(PinSource::Dns, Some(l0.fingerprint), &s.genesis.encode())
        .unwrap()
        .advance(&[(0, s.genesis.encode()), (1, g1a.encode())], &[])
        .unwrap();
    integrity(
        pin.advance(&[(1, g1b.encode())], &[]),
        IntegrityError::OrgLineageFork,
        "pinned at g1a, served g1b",
    );
}

#[test]
fn forged_lineage_identity_alone() {
    let ow = owners();
    // Identity signature and no owner signature at all: refused as a
    // malformed record (at least one owner signature is a shape rule).
    let bare = audit_rotation(&ow.two, &[]);
    assert!(bare.owner_sigs.is_empty());
    assert!(matches!(
        ow.two.apply(&bare),
        Err(Error::InvalidFormat("owner signature count"))
    ));
    assert!(matches!(
        SignedOrgRecord::decode(&bare.encode()),
        Err(Error::InvalidFormat(_))
    ));
    // Identity signature plus the server's own device: no owner signed.
    integrity(
        ow.two.apply(&audit_rotation(&ow.two, &[server_device()])),
        IntegrityError::OrgQuorum,
        "identity and a device of no owner",
    );
}

#[test]
fn forged_lineage_one_owner_of_two_with_fake_second() {
    let ow = owners();
    // Identity + owner X + a signature that claims owner Y's device but
    // was made by the server's key.
    let mut rec = audit_rotation(&ow.two, &[&ow.x1, server_device()]);
    let fake = rec
        .owner_sigs
        .iter_mut()
        .find(|(p, _)| *p == server_device().public)
        .unwrap();
    fake.0 = ow.y.public.clone();
    rec.owner_sigs.sort_by_key(|(p, _)| p.fingerprint());
    let decoded = SignedOrgRecord::decode(&rec.encode()).unwrap();
    integrity(
        ow.two.apply(&decoded),
        IntegrityError::Signature,
        "fake second owner signature",
    );
    // Identity + owner X twice (two of X's devices) on a 3-owner org: one
    // account, below the quorum of 2.
    integrity(
        ow.three
            .apply(&audit_rotation(&ow.three, &[&ow.x1, &ow.x2])),
        IntegrityError::OrgQuorum,
        "two devices of one owner",
    );
}

#[test]
fn one_owner_of_two_is_refused() {
    let ow = owners();
    assert_eq!(onepass_core::org::quorum(2), 2);
    for d in [&ow.x1, &ow.x2, &ow.y] {
        integrity(
            ow.two.apply(&audit_rotation(&ow.two, &[d])),
            IntegrityError::OrgQuorum,
            "one owner of two",
        );
    }
    // The genesis too.
    integrity(
        verify_org_genesis(&owners_org(
            OrgId([11; 16]),
            vec![member_ref(OX, &[&ow.x1, &ow.x2]), member_ref(OY, &[&ow.y])],
            &[&ow.x1],
        )),
        IntegrityError::OrgQuorum,
        "genesis by one owner of two",
    );
    // Both owners pass.
    ow.two
        .apply(&audit_rotation(&ow.two, &[&ow.x2, &ow.y]))
        .unwrap();
}

#[test]
fn two_owners_of_three_pass() {
    let ow = owners();
    for signers in [[&ow.x1, &ow.y], [&ow.y, &ow.z], [&ow.x2, &ow.z]] {
        let next = ow
            .three
            .apply(&audit_rotation(&ow.three, &signers))
            .unwrap();
        assert_eq!(next.head().generation, 1);
        assert_eq!(next.audit_kem_pub, kem_pool(2).1);
        assert_eq!(next.head().owners, ow.three.head().owners);
    }
}

#[test]
fn a19_one_owner_of_three() {
    let ow = owners();
    for d in [&ow.x1, &ow.y, &ow.z] {
        integrity(
            ow.three.apply(&audit_rotation(&ow.three, &[d])),
            IntegrityError::OrgQuorum,
            "one owner of three",
        );
    }
}

/// The server's made-up org: its own identity, the server as sole owner.
fn fake_secrets() -> &'static OrgSecrets {
    static CELL: OnceLock<OrgSecrets> = OnceLock::new();
    CELL.get_or_init(|| OrgSecrets::generate().unwrap())
}

fn fake_genesis(org_id: OrgId) -> SignedOrgRecord {
    let f = fake_secrets();
    let sd = server_device();
    sign_org_genesis(
        OrgGenesisBody {
            format: 1,
            org_id,
            name: "Acme".to_string(),
            org_identity_pub: f.identity.verifying_key(),
            audit_kem_pub: f.audit.public().unwrap(),
            owners: vec![member_ref(SERVER, &[sd])],
            created_at: 1_700_000_000,
        },
        &f.identity,
        &[(&sd.public, &sd.keys)],
    )
    .unwrap()
}

#[test]
fn a6_server_swaps_org_at_join() {
    let s = std_org();
    let real_fpr = s.lineage.fingerprint;
    // Real org R, pinned by DNS on device D1; A invites a newcomer at r8.
    let d1 = pin_org(PinSource::Dns, Some(real_fpr), &s.genesis.encode()).unwrap();
    assert_eq!(d1.fingerprint(), real_fpr);
    let (r8, invitation) = invite_member(
        r(7),
        scim_id_hash(STD_ORG, "camille"),
        RoleSet::of(&[Role::Auditor]),
    )
    .unwrap();
    accept_next_roster(lineage(), r(7), &signed_by(r8.clone(), &s.a)).unwrap();
    // The server serves the genesis of a fake org F (own identity, same
    // org id) to the joiner's device D2.
    let fake = fake_genesis(STD_ORG).encode();
    integrity(
        pin_org(PinSource::Dns, Some(real_fpr), &fake),
        IntegrityError::OrgPinMismatch,
        "DNS pin of R, served F",
    );
    integrity(
        pin_org(PinSource::Mdm, Some(real_fpr), &fake),
        IntegrityError::OrgPinMismatch,
        "MDM pin of R, served F",
    );
    let d2 = pin_org(PinSource::Tofu { verified: false }, None, &fake).unwrap();
    assert_eq!(d2.source(), PinSource::Tofu { verified: false });
    assert_ne!(d2.fingerprint(), real_fpr);
    // D2's join request carries F's fingerprint; R's admin refuses it.
    let joiner = create(Some(ManagedGenesis {
        org_id: STD_ORG,
        account_id: invitation.account_id,
    }));
    let body = |pinned_fpr: [u8; 32]| onepass_core::org::JoinRequestBody {
        format: 1,
        org_id: STD_ORG,
        account_id: invitation.account_id,
        invite_nonce: invitation.nonce,
        pinned_fpr,
        account_genesis: joiner.genesis.clone(),
        devices: vec![joiner.device.clone()],
        display_name: "Camille Durand".to_string(),
        mailbox_credential: [0x42; 32],
        account_kem_pub: joiner.kem.clone(),
        issued_at: 1_700_000_900,
    };
    let req = sign_join_request(body(d2.fingerprint()), &joiner.keys).unwrap();
    integrity(
        verify_join_request(&req, &r8, &real_fpr),
        IntegrityError::OrgPinMismatch,
        "join request pinned on F",
    );
    // D2 then confirms its TOFU pin with R's fingerprint read from the admin.
    integrity(
        d2.confirm_tofu(&real_fpr),
        IntegrityError::OrgPinMismatch,
        "TOFU confirmation against R",
    );
    // Control: the same request pinned on R verifies.
    let honest = sign_join_request(body(real_fpr), &joiner.keys).unwrap();
    verify_join_request(&honest, &r8, &real_fpr).unwrap();
}

#[test]
fn a6_server_swaps_roster_of_other_org() {
    // A valid roster of another org F (its own lineage and owner), offered
    // to a device pinned on R.
    let sd = server_device();
    let f_genesis = fake_genesis(OrgId([8; 16]));
    let f_lineage = verify_org_genesis(&f_genesis).unwrap();
    let mut f_chain = vec![signed_by(founding_roster(&f_lineage).unwrap(), sd)];
    while f_chain.len() < 8 {
        let next = f_chain.last().unwrap().body.next().unwrap();
        f_chain.push(signed_by(next, sd));
    }
    assert_eq!(
        accept_first_roster(&f_lineage, &f_chain).unwrap(),
        f_chain[7].body,
        "F's chain is valid for F"
    );
    let f8 = &f_chain[7];
    assert_eq!(f8.body.seq, 8);
    integrity(
        accept_next_roster(lineage(), r(7), f8),
        IntegrityError::WrongContext,
        "F's seq 8 after R's seq 7",
    );
    integrity(
        attacks()
            .pinned
            .advance(&genesis_list(), &served(std::slice::from_ref(f8))),
        IntegrityError::WrongContext,
        "through the pin",
    );
    integrity(
        accept_first_roster(lineage(), &f_chain[..1]),
        IntegrityError::WrongContext,
        "F's founding roster as R's first pin",
    );
}

/// The test org secrets rebuilt from bytes (`OrgSecrets` is not `Clone`).
fn keyset() -> OrgKeyset {
    let s = org_secrets();
    OrgKeyset {
        org_id: STD_ORG,
        secrets: OrgSecrets {
            identity: IdentityKey::from_bytes(&s.identity.to_bytes()).unwrap(),
            audit: HybridKemSecret::from_bytes(&s.audit.to_bytes()).unwrap(),
        },
    }
}

#[test]
fn owner_keyset_for_other_owner() {
    // Owner A is account 11 (KEM pool 2), owner B account 12 (KEM pool 0).
    let (a, b) = (acct(OX), acct(OY));
    let (a_kem, b_kem) = (kem_pool(2), kem_pool(0));
    let sealed_a = seal_org_keyset(&keyset(), a, &a_kem.1).unwrap();
    // Served to B as is.
    integrity(
        open_org_keyset(&sealed_a, STD_ORG, b, &b_kem.0),
        IntegrityError::WrongContext,
        "A's keyset opened by B",
    );
    // The server rewrites the account id to B's: the envelope is still
    // sealed to A's key under A's context.
    let relabelled = SealedOrgKeyset {
        account_id: b,
        ..sealed_a.clone()
    };
    let relabelled = SealedOrgKeyset::decode(&relabelled.encode()).unwrap();
    assert!(matches!(
        open_org_keyset(&relabelled, STD_ORG, b, &b_kem.0),
        Err(Error::Integrity(_))
    ));
    // Control: A opens its own.
    let opened = open_org_keyset(&sealed_a, STD_ORG, a, &a_kem.0).unwrap();
    opened.check_against(lineage()).unwrap();
}
