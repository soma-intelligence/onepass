//! The signed org roster (Business E1, plan B Tasks 6 and 7): roles as a
//! bit set, member shape rules, the strict codec and the caps; then the
//! acceptance rules of spec 5.5 (who may sign which change).

mod org_common;

use std::sync::OnceLock;

use onepass_core::crypto::IdentityVerifyingKey;
use onepass_core::org::{
    DeviceFpr, MAX_MEMBER_DEVICES, MAX_ORG_RECORD_BYTES, MAX_ROSTER_MEMBERS, MemberRef,
    MemberState, OrgChangeBody, OrgChangeKind, OrgGenesisBody, OrgId, OrgLineage, OrgMember, Role,
    RoleSet, RosterBody, SignedRoster, accept_first_roster, accept_next_roster,
    accept_roster_chain, check_transition, founding_roster, invite_commit, member_kem_hash,
    scim_id_hash, sign_org_change, sign_org_genesis, sign_roster, verify_org_genesis,
};
use onepass_core::{Error, Id, IntegrityError};
use org_common::*;

const ORG: OrgId = OrgId([7; 16]);

fn signer() -> &'static TestDevice {
    static CELL: OnceLock<TestDevice> = OnceLock::new();
    CELL.get_or_init(|| device(0xA0))
}

/// The fingerprints of three small fixture devices, sorted.
fn fprs() -> &'static [DeviceFpr; 3] {
    static CELL: OnceLock<[DeviceFpr; 3]> = OnceLock::new();
    CELL.get_or_init(|| {
        let mut f = [1u8, 2, 3].map(|t| device(t).public.fingerprint());
        f.sort_unstable();
        f
    })
}

fn active(account: u8, devices: Vec<DeviceFpr>, roles: RoleSet) -> OrgMember {
    OrgMember {
        account_id: Id([account; 16]),
        account_identity_pub: Some(identity_pool(0).1.clone()),
        scim_id_hash: scim_id_hash(ORG, &format!("ext-{account}")),
        invite_commit: [0; 32],
        account_kem_hash: member_kem_hash(&kem_pool(0).1),
        roles,
        state: MemberState::Active,
        devices,
    }
}

fn invited(account: u8) -> OrgMember {
    OrgMember {
        account_id: Id([account; 16]),
        account_identity_pub: None,
        scim_id_hash: [0; 32],
        invite_commit: invite_commit(ORG, Id([account; 16]), &[9; 32]),
        account_kem_hash: [0; 32],
        roles: RoleSet::of(&[Role::Auditor]),
        state: MemberState::Invited,
        devices: vec![],
    }
}

fn removed(account: u8) -> OrgMember {
    OrgMember {
        account_id: Id([account; 16]),
        account_identity_pub: Some(identity_pool(0).1.clone()),
        scim_id_hash: [5; 32],
        invite_commit: [6; 32],
        account_kem_hash: [4; 32],
        roles: RoleSet::EMPTY,
        state: MemberState::Removed {
            at: 1_700_000_000,
            by: Id([1; 16]),
        },
        devices: vec![],
    }
}

/// Owner (account 1, two devices), Suspended admin (2, one device), an
/// invited member (3) and a removed one (4).
fn small_body() -> RosterBody {
    let f = fprs();
    let mut suspended = active(2, vec![f[2]], RoleSet::of(&[Role::Admin]));
    suspended.state = MemberState::Suspended;
    RosterBody {
        format: 1,
        org_id: ORG,
        seq: 1,
        prev_hash: [0; 32],
        org_head: [3; 32],
        members: vec![
            active(1, vec![f[0], f[1]], RoleSet::of(&[Role::Owner])),
            suspended,
            invited(3),
            removed(4),
        ],
    }
}

fn small_signed() -> &'static SignedRoster {
    static CELL: OnceLock<SignedRoster> = OnceLock::new();
    CELL.get_or_init(|| sign_roster(small_body(), &signer().public, &signer().keys).unwrap())
}

fn invalid<T: std::fmt::Debug>(r: onepass_core::Result<T>) -> bool {
    matches!(r, Err(Error::InvalidFormat(_)))
}

/// `body` with `f` applied must fail `check()` and, signed with the
/// fixture signature (decode checks no signature), `decode()`.
fn refused_body(what: &str, f: impl FnOnce(&mut RosterBody)) {
    let mut rec = small_signed().clone();
    f(&mut rec.body);
    assert!(invalid(rec.body.check()), "check: {what}");
    assert!(
        invalid(SignedRoster::decode(&rec.encode())),
        "decode: {what}"
    );
}

/// An identity verifying key of `len` bytes.
fn identity_with_len(len: usize) -> IdentityVerifyingKey {
    let enc = postcard::to_allocvec(&serde_bytes::ByteBuf::from(vec![1u8; len])).unwrap();
    postcard::from_bytes(&enc).unwrap()
}

/// `n` Active members with `devices` synthetic fingerprints each.
fn big_body(n: usize, devices: u8, roles: RoleSet) -> RosterBody {
    let members = (0..n)
        .map(|i| {
            let mut id = [0u8; 16];
            id[..8].copy_from_slice(&(i as u64).to_be_bytes());
            let fprs: Vec<DeviceFpr> = (0..devices)
                .map(|d| {
                    let mut f = [0xEE; 32];
                    f[0] = i as u8;
                    f[1] = (i >> 8) as u8;
                    f[2] = d;
                    f
                })
                .collect();
            OrgMember {
                account_id: Id(id),
                account_identity_pub: Some(identity_pool(0).1.clone()),
                scim_id_hash: [0x11; 32],
                invite_commit: [0x22; 32],
                account_kem_hash: [0x33; 32],
                roles,
                state: MemberState::Active,
                devices: fprs,
            }
        })
        .collect();
    RosterBody {
        format: 1,
        org_id: ORG,
        seq: 1,
        prev_hash: [0; 32],
        org_head: [3; 32],
        members,
    }
}

#[test]
fn roleset_bits_are_frozen() {
    let all = [
        (Role::Owner, 0x01),
        (Role::Admin, 0x02),
        (Role::UserManager, 0x04),
        (Role::PolicyManager, 0x08),
        (Role::Auditor, 0x10),
        (Role::RecoveryOfficer, 0x20),
        (Role::Provisioner, 0x40),
    ];
    for (r, bit) in all {
        assert_eq!(r as u8, bit);
        assert_eq!(RoleSet::of(&[r]).bits(), bit);
    }
    let s = RoleSet::of(&[Role::Admin, Role::Auditor]);
    assert_eq!(postcard::to_allocvec(&s).unwrap(), vec![0x12]);
    assert_eq!(s.bits(), 0x12);
    assert!(s.contains(Role::Admin) && s.contains(Role::Auditor));
    assert!(!s.contains(Role::Owner));
    assert_eq!(s.with(Role::Owner).bits(), 0x13);
    assert_eq!(s.without(Role::Admin).bits(), 0x10);
    let o = RoleSet::of(&[Role::Auditor, Role::Provisioner]);
    assert_eq!(s.union(o).bits(), 0x52);
    assert_eq!(s.intersection(o).bits(), 0x10);
    assert_eq!(s.difference(o).bits(), 0x02);
    assert!(RoleSet::of(&[Role::Admin]).is_subset(s));
    assert!(!o.is_subset(s));
    assert!(RoleSet::EMPTY.is_subset(s));
    assert_eq!(RoleSet::default(), RoleSet::EMPTY);
    assert_eq!(RoleSet::EMPTY.bits(), 0);
    assert_eq!(
        postcard::from_bytes::<RoleSet>(&[0x7F]).unwrap().bits(),
        0x7F
    );
    assert!(postcard::from_bytes::<RoleSet>(&[0x80]).is_err());
}

#[test]
fn roleset_high_bit_refused() {
    // Two encodings differing only in the roles byte of member 0 locate it.
    let rec = small_signed();
    let mut a = rec.clone();
    a.body.members[0].roles = RoleSet::of(&[Role::Admin]);
    let mut b = rec.clone();
    b.body.members[0].roles = RoleSet::of(&[Role::Auditor]);
    let (ea, eb) = (a.encode(), b.encode());
    assert_eq!(ea.len(), eb.len());
    let diff: Vec<usize> = (0..ea.len()).filter(|&i| ea[i] != eb[i]).collect();
    assert_eq!(diff.len(), 1);
    assert!(SignedRoster::decode(&ea).is_ok());
    let mut high = ea.clone();
    high[diff[0]] = 0x80;
    assert!(invalid(SignedRoster::decode(&high)));
    let mut high_and_admin = ea;
    high_and_admin[diff[0]] = 0x82;
    assert!(invalid(SignedRoster::decode(&high_and_admin)));
}

#[test]
fn scim_and_invite_hashes() {
    let org = OrgId([0x42; 16]);
    assert_eq!(
        scim_id_hash(org, "émile@acme"),
        sha256(&[b"onepass/scim-id/v1", &org.0, "émile@acme".as_bytes()])
    );
    assert_ne!(scim_id_hash(org, "a"), scim_id_hash(OrgId([1; 16]), "a"));
    let acct = Id([0x13; 16]);
    let nonce = [0x99; 32];
    assert_eq!(
        invite_commit(org, acct, &nonce),
        sha256(&[b"onepass/org-invite/v1", &org.0, &acct.0, &nonce])
    );
    let kem = &kem_pool(1).1;
    assert_eq!(
        member_kem_hash(kem),
        sha256(&[b"onepass/org-member-kem/v1", &kem.to_bytes()])
    );
    assert_ne!(member_kem_hash(kem), member_kem_hash(&kem_pool(2).1));
}

#[test]
fn roster_hash_is_prefixed() {
    let body = small_body();
    let enc = body.encode();
    assert_eq!(enc, postcard::to_allocvec(&body).unwrap());
    assert_eq!(body.hash(), sha256(&[b"onepass/org-roster/v1", &enc]));
    let rec = small_signed();
    let back = SignedRoster::decode(&rec.encode()).unwrap();
    assert_eq!(&back, rec);
    // The signature is over the same message.
    signer()
        .public
        .sign_pub
        .verify(b"onepass/org-roster/v1", &enc, &rec.sig)
        .unwrap();
    assert_eq!(
        body.member(Id([3; 16])).map(|m| &m.state),
        Some(&MemberState::Invited)
    );
    assert!(body.member(Id([9; 16])).is_none());
    assert_eq!(
        body.device_holder(&fprs()[2]).map(|m| m.account_id),
        Some(Id([2; 16]))
    );
    assert!(body.device_holder(&[0xFF; 32]).is_none());
}

#[test]
fn roster_shape_rules() {
    assert!(small_body().check().is_ok());
    assert!(SignedRoster::decode(&small_signed().encode()).is_ok());
    let f = *fprs();

    refused_body("format 2", |b| b.format = 2);
    refused_body("seq 0", |b| b.seq = 0);
    refused_body("seq 1 with a prev_hash", |b| b.prev_hash = [1; 32]);
    refused_body("members unsorted", |b| b.members.swap(0, 1));
    refused_body("member repeated", |b| {
        b.members[1].account_id = b.members[0].account_id
    });

    refused_body("invited with identity", |b| {
        b.members[2].account_identity_pub = Some(identity_pool(0).1.clone())
    });
    refused_body("invited with a device", |b| {
        b.members[2].devices = vec![[0xAB; 32]]
    });
    refused_body("invited with a kem hash", |b| {
        b.members[2].account_kem_hash = [1; 32]
    });
    for i in [0usize, 1] {
        refused_body("active/suspended without identity", |b| {
            b.members[i].account_identity_pub = None
        });
        refused_body("active/suspended without device", |b| {
            b.members[i].devices.clear()
        });
        refused_body("active/suspended with a zero kem hash", |b| {
            b.members[i].account_kem_hash = [0; 32]
        });
    }

    let eight: Vec<DeviceFpr> = (1u8..=8).map(|i| [i; 32]).collect();
    let mut ok = small_body();
    ok.members[0].devices = eight;
    assert!(ok.check().is_ok(), "8 devices are fine");
    refused_body("9 devices", |b| {
        b.members[0].devices = (1u8..=9).map(|i| [i; 32]).collect()
    });
    refused_body("fingerprints unsorted", |b| b.members[0].devices.reverse());
    refused_body("fingerprint repeated", |b| {
        b.members[0].devices = vec![f[0], f[0]]
    });
    refused_body("fingerprint held by two members", |b| {
        b.members[1].devices = vec![f[1]]
    });

    for r in [0usize, 1, 2] {
        refused_body("RecoveryOfficer", |b| {
            b.members[r].roles = b.members[r].roles.with(Role::RecoveryOfficer)
        });
    }
    refused_body("removed with roles", |b| {
        b.members[3].roles = RoleSet::of(&[Role::Auditor])
    });
    refused_body("removed with a device", |b| {
        b.members[3].devices = vec![[0xAB; 32]]
    });
    refused_body("identity key of wrong length", |b| {
        b.members[0].account_identity_pub = Some(identity_with_len(63))
    });
    refused_body("removed identity key of wrong length", |b| {
        b.members[3].account_identity_pub = Some(identity_with_len(65))
    });

    // The signer key is checked as `DevicePublic::decode` does.
    let mut rec = small_signed().clone();
    rec.signer.sign_pub.mldsa.pop();
    assert!(invalid(SignedRoster::decode(&rec.encode())), "signer key");
    let mut rec = small_signed().clone();
    rec.signer.kem_pub.mlkem.pop();
    assert!(
        invalid(SignedRoster::decode(&rec.encode())),
        "signer kem key"
    );
    let mut rec = small_signed().clone();
    rec.sig.mldsa.pop();
    assert!(
        invalid(SignedRoster::decode(&rec.encode())),
        "signature length"
    );

    // sign_roster runs check() first.
    let mut bad = small_body();
    bad.format = 2;
    assert!(invalid(sign_roster(bad, &signer().public, &signer().keys)));
    // and refuses keys that do not belong to the signer.
    let other = device(0xA1);
    assert!(sign_roster(small_body(), &signer().public, &other.keys).is_err());
}

#[test]
fn roster_member_cap_refused() {
    let roles = RoleSet::of(&[Role::Admin]);
    let over = big_body(MAX_ROSTER_MEMBERS + 1, 1, roles);
    assert!(invalid(over.check()));
    assert!(invalid(sign_roster(over, &signer().public, &signer().keys)));
    let at = big_body(MAX_ROSTER_MEMBERS, 1, roles);
    let rec = sign_roster(at, &signer().public, &signer().keys).unwrap();
    assert_eq!(rec.body.members.len(), 2000);
    assert!(SignedRoster::decode(&rec.encode()).is_ok());
}

#[test]
fn roster_2000_members_3_devices_fits() {
    let body = big_body(2000, 3, RoleSet::of(&[Role::UserManager]));
    let rec = sign_roster(body, &signer().public, &signer().keys).unwrap();
    let len = rec.encode().len();
    println!("2000 members x 3 devices: {len} bytes");
    assert!(len < 900 * 1024);
    assert_eq!(SignedRoster::decode(&rec.encode()).unwrap(), rec);
}

#[test]
fn roster_worst_case_fits() {
    let roles = RoleSet::of(&[
        Role::Owner,
        Role::Admin,
        Role::UserManager,
        Role::PolicyManager,
        Role::Auditor,
        Role::Provisioner,
    ]);
    let body = big_body(MAX_ROSTER_MEMBERS, MAX_MEMBER_DEVICES as u8, roles);
    let rec = sign_roster(body, &signer().public, &signer().keys).unwrap();
    let enc = rec.encode();
    println!(
        "worst case 2000 members x 8 devices: {} bytes (cap {MAX_ORG_RECORD_BYTES})",
        enc.len()
    );
    assert!(enc.len() <= MAX_ORG_RECORD_BYTES);
    assert_eq!(SignedRoster::decode(&enc).unwrap(), rec);
}

#[test]
fn removed_member_keeps_no_devices() {
    let mut body = small_body();
    assert!(body.check().is_ok());
    body.members[3].devices = vec![[0xAB; 32]];
    assert!(invalid(body.check()));
    // Identity and hashes are kept on a removed member.
    let body = small_body();
    let m = body.member(Id([4; 16])).unwrap();
    assert!(m.account_identity_pub.is_some());
    assert_ne!(m.account_kem_hash, [0; 32]);
}

#[test]
fn roster_decode_strict() {
    let enc = small_signed().encode();
    assert!(SignedRoster::decode(&enc).is_ok());

    let mut trailing = enc.clone();
    trailing.push(0);
    assert!(invalid(SignedRoster::decode(&trailing)), "trailing byte");

    assert!(
        invalid(SignedRoster::decode(&enc[..enc.len() - 1])),
        "truncated"
    );
    assert!(
        invalid(SignedRoster::decode(&vec![0u8; MAX_ORG_RECORD_BYTES + 1])),
        "oversize input"
    );

    // format (1 byte), org_id (16 bytes), then seq as a varint: 1 is 0x01,
    // the overlong 0x81 0x00 also reads as 1.
    assert_eq!(enc[0], 1);
    assert_eq!(&enc[1..17], &ORG.0);
    assert_eq!(enc[17], 1);
    let mut overlong = enc[..17].to_vec();
    overlong.extend_from_slice(&[0x81, 0x00]);
    overlong.extend_from_slice(&enc[18..]);
    assert!(
        invalid(SignedRoster::decode(&overlong)),
        "non-canonical varint"
    );
}

#[test]
fn next_chains() {
    let body = small_body();
    let n = body.next().unwrap();
    assert_eq!(n.seq, 2);
    assert_eq!(n.prev_hash, body.hash());
    assert_eq!(n.members, body.members);
    assert_eq!(n.org_head, body.org_head);
    assert_eq!(n.org_id, body.org_id);
    assert!(n.check().is_ok());
    let n2 = n.next().unwrap();
    assert_eq!(n2.seq, 3);
    assert_eq!(n2.prev_hash, n.hash());
    let mut last = body.clone();
    last.seq = u64::MAX;
    last.prev_hash = [1; 32];
    assert!(last.next().is_err());
}

// ---------------------------------------------------------------------
// Task 7: roster acceptance rules (spec 5.5, D7 to D13).
// ---------------------------------------------------------------------

/// Accounts of the fixture org: owner O, admin A, user manager U,
/// provisioner P, plain member M; X and Y are invited later.
const O: u8 = 1;
const A: u8 = 2;
const U: u8 = 3;
const P: u8 = 4;
const M: u8 = 5;
const X: u8 = 6;
const Y: u8 = 7;

fn acct(a: u8) -> Id {
    Id([a; 16])
}

/// The fixture org: its devices, the lineage at generation 0 (owners {O}),
/// 1 (audit key rotated, owners {O}) and 2 (owners {O, M}), and rosters
/// r1..r7 (`chain[i]` is seq `i + 1`): r1 founding by O, r2 O invites A, U,
/// P, M, r3 O activates them, r4 and r5 by O unchanged, r6 A invites X
/// with {UserManager}, r7 U invites Y with {UserManager}.
struct Org {
    o: TestDevice,
    a: TestDevice,
    u: TestDevice,
    p: TestDevice,
    m: TestDevice,
    lineages: [OrgLineage; 3],
    chain: Vec<SignedRoster>,
}

fn dev(o: &Org, a: u8) -> &TestDevice {
    match a {
        O => &o.o,
        A => &o.a,
        U => &o.u,
        P => &o.p,
        M => &o.m,
        _ => unreachable!(),
    }
}

fn invite(a: u8, roles: RoleSet) -> OrgMember {
    OrgMember {
        account_id: acct(a),
        account_identity_pub: None,
        scim_id_hash: [0; 32],
        invite_commit: invite_commit(ORG, acct(a), &[a; 32]),
        account_kem_hash: [0; 32],
        roles,
        state: MemberState::Invited,
        devices: vec![],
    }
}

/// `m` Active with the identity, KEM hash and devices of `member_ref(a)`.
fn activate(m: &mut OrgMember, r: &MemberRef) {
    m.state = MemberState::Active;
    m.account_identity_pub = Some(r.account_identity_pub.clone());
    m.account_kem_hash = member_kem_hash(&r.account_kem_pub);
    m.devices = r.devices.clone();
}

fn upsert(body: &mut RosterBody, m: OrgMember) {
    match body
        .members
        .binary_search_by(|x| x.account_id.cmp(&m.account_id))
    {
        Ok(i) => body.members[i] = m,
        Err(i) => body.members.insert(i, m),
    }
}

fn entry(body: &mut RosterBody, a: u8) -> &mut OrgMember {
    body.members
        .iter_mut()
        .find(|m| m.account_id == acct(a))
        .unwrap()
}

fn org() -> &'static Org {
    static CELL: OnceLock<Org> = OnceLock::new();
    CELL.get_or_init(|| {
        let (o, a, u, p, m) = (
            device(0x10),
            device(0x20),
            device(0x30),
            device(0x40),
            device(0x50),
        );
        let secrets = org_secrets();
        let owner_o = member_ref(O, &[&o]);
        let genesis = sign_org_genesis(
            OrgGenesisBody {
                format: 1,
                org_id: ORG,
                name: "Acme".to_string(),
                org_identity_pub: secrets.identity.verifying_key(),
                audit_kem_pub: secrets.audit.public().unwrap(),
                owners: vec![owner_o.clone()],
                created_at: 1_700_000_000,
            },
            &secrets.identity,
            &[(&o.public, &o.keys)],
        )
        .unwrap();
        let l0 = verify_org_genesis(&genesis).unwrap();
        let change = |l: &OrgLineage, kind: OrgChangeKind| {
            let body = OrgChangeBody {
                format: 1,
                org_id: ORG,
                generation: l.head().generation + 1,
                parent: l.head().hash,
                kind,
                issued_at: 1_700_000_100,
            };
            let rec = sign_org_change(body, &secrets.identity, &[(&o.public, &o.keys)]).unwrap();
            l.apply(&rec).unwrap()
        };
        let l1 = change(
            &l0,
            OrgChangeKind::AuditKeyRotated {
                audit_kem_pub: kem_pool(1).1.clone(),
            },
        );
        let l2 = change(
            &l1,
            OrgChangeKind::OwnersChanged {
                owners: vec![owner_o, member_ref(M, &[&m])],
            },
        );

        let sign =
            |body: RosterBody, d: &TestDevice| sign_roster(body, &d.public, &d.keys).unwrap();
        let r1 = founding_roster(&l0).unwrap();
        let mut r2 = r1.next().unwrap();
        upsert(&mut r2, invite(A, RoleSet::of(&[Role::Admin])));
        upsert(&mut r2, invite(U, RoleSet::of(&[Role::UserManager])));
        upsert(&mut r2, invite(P, RoleSet::of(&[Role::Provisioner])));
        upsert(&mut r2, invite(M, RoleSet::EMPTY));
        let mut r3 = r2.next().unwrap();
        for (acc, d) in [(A, &a), (U, &u), (P, &p), (M, &m)] {
            activate(entry(&mut r3, acc), &member_ref(acc, &[d]));
        }
        let r4 = r3.next().unwrap();
        let r5 = r4.next().unwrap();
        let mut r6 = r5.next().unwrap();
        upsert(&mut r6, invite(X, RoleSet::of(&[Role::UserManager])));
        let mut r7 = r6.next().unwrap();
        upsert(&mut r7, invite(Y, RoleSet::of(&[Role::UserManager])));
        let chain = vec![
            sign(r1, &o),
            sign(r2, &o),
            sign(r3, &o),
            sign(r4, &o),
            sign(r5, &o),
            sign(r6, &a),
            sign(r7, &u),
        ];
        Org {
            o,
            a,
            u,
            p,
            m,
            lineages: [l0, l1, l2],
            chain,
        }
    })
}

fn l0() -> &'static OrgLineage {
    &org().lineages[0]
}

/// Roster `seq` of the fixture chain.
fn r(seq: usize) -> &'static RosterBody {
    &org().chain[seq - 1].body
}

/// The pinned roster most tests start from: r3, all five members Active.
fn base() -> &'static RosterBody {
    r(3)
}

/// `prev.next()` edited by `f`.
fn edit(prev: &RosterBody, f: impl FnOnce(&mut RosterBody)) -> RosterBody {
    let mut n = prev.next().unwrap();
    f(&mut n);
    n
}

/// `next` signed by account `by`'s device, accepted after `prev` under
/// lineage `l`.
fn accept_in(
    l: &OrgLineage,
    prev: &RosterBody,
    next: RosterBody,
    by: u8,
) -> onepass_core::Result<RosterBody> {
    let d = dev(org(), by);
    let rec = sign_roster(next, &d.public, &d.keys).unwrap();
    accept_next_roster(l, prev, &rec)
}

fn accept(prev: &RosterBody, next: RosterBody, by: u8) -> onepass_core::Result<RosterBody> {
    accept_in(l0(), prev, next, by)
}

fn integrity_err<T: std::fmt::Debug>(r: onepass_core::Result<T>) -> IntegrityError {
    match r {
        Err(Error::Integrity(e)) => e,
        other => panic!("expected an integrity error, got {other:?}"),
    }
}

fn denied<T: std::fmt::Debug>(r: onepass_core::Result<T>, what: &str) {
    match r {
        Err(Error::Integrity(IntegrityError::OrgRoleDenied)) => {}
        other => panic!("{what}: expected OrgRoleDenied, got {other:?}"),
    }
}

fn not_found<T: std::fmt::Debug>(r: onepass_core::Result<T>, what: &str) {
    match r {
        Err(Error::NotFound) => {}
        other => panic!("{what}: expected NotFound, got {other:?}"),
    }
}

fn add_role(b: &mut RosterBody, a: u8, role: Role) {
    let e = entry(b, a);
    e.roles = e.roles.with(role);
}

fn set_state(b: &mut RosterBody, a: u8, s: MemberState) {
    entry(b, a).state = s;
}

fn removed_by(b: &mut RosterBody, a: u8, by: u8) {
    let e = entry(b, a);
    e.state = MemberState::Removed {
        at: 1_700_000_500,
        by: acct(by),
    };
    e.roles = RoleSet::EMPTY;
    e.devices.clear();
}

#[test]
fn founding_roster_signed_by_owner_accepted() {
    let org = org();
    let f = founding_roster(l0()).unwrap();
    assert_eq!(f.seq, 1);
    assert_eq!(f.prev_hash, [0; 32]);
    assert_eq!(f.org_id, ORG);
    assert_eq!(f.org_head, l0().head().hash);
    let owner = member_ref(O, &[&org.o]);
    assert_eq!(
        f.members,
        vec![OrgMember {
            account_id: acct(O),
            account_identity_pub: Some(owner.account_identity_pub.clone()),
            scim_id_hash: [0; 32],
            invite_commit: [0; 32],
            account_kem_hash: member_kem_hash(&owner.account_kem_pub),
            roles: RoleSet::of(&[Role::Owner]),
            state: MemberState::Active,
            devices: owner.devices.clone(),
        }]
    );
    assert_eq!(&f, r(1));
    assert_eq!(
        accept_first_roster(l0(), &org.chain[..1]).unwrap(),
        f,
        "founding roster by O"
    );
    // The whole fixture chain from seq 1, under every lineage generation.
    for l in &org.lineages {
        assert_eq!(&accept_first_roster(l, &org.chain).unwrap(), r(7));
    }
    // founding_roster follows the lineage head: owners {O, M} at gen 2.
    let f2 = founding_roster(&org.lineages[2]).unwrap();
    assert_eq!(f2.org_head, org.lineages[2].head().hash);
    assert_eq!(
        f2.members.iter().map(|m| m.account_id).collect::<Vec<_>>(),
        vec![acct(O), acct(M)]
    );
    assert!(
        accept_first_roster(
            &org.lineages[2],
            &[sign_roster(f2, &org.m.public, &org.m.keys).unwrap()]
        )
        .is_ok()
    );
}

#[test]
fn founding_roster_by_non_owner_refused() {
    let org = org();
    let f = founding_roster(l0()).unwrap();
    let by_a = sign_roster(f.clone(), &org.a.public, &org.a.keys).unwrap();
    denied(accept_first_roster(l0(), &[by_a]), "founding by A");
    // A seq-1 roster that is not the founding roster, even by O.
    let mut other = f;
    upsert(&mut other, invite(X, RoleSet::EMPTY));
    let rec = sign_roster(other, &org.o.public, &org.o.keys).unwrap();
    denied(accept_first_roster(l0(), &[rec]), "seq 1 not founding");
    not_found(accept_first_roster(l0(), &[]), "empty chain");
}

#[test]
fn admin_invites_and_grants() {
    let n = edit(base(), |b| {
        upsert(b, invite(X, RoleSet::of(&[Role::UserManager])))
    });
    assert_eq!(accept(base(), n.clone(), A).unwrap(), n);
    let n = edit(base(), |b| add_role(b, M, Role::Auditor));
    assert!(accept(base(), n, A).is_ok(), "A grants Auditor to M");
    let n = edit(base(), |b| add_role(b, M, Role::Admin));
    assert!(accept(base(), n, A).is_ok(), "A grants Admin to M");
    // A new invitation needs an invitation commitment.
    let n = edit(base(), |b| {
        let mut x = invite(X, RoleSet::EMPTY);
        x.invite_commit = [0; 32];
        upsert(b, x)
    });
    denied(accept(base(), n, A), "invite without commitment");
}

#[test]
fn user_manager_cannot_grant_admin() {
    let n = edit(base(), |b| {
        upsert(b, invite(X, RoleSet::of(&[Role::Admin])))
    });
    denied(accept(base(), n, U), "U invites an Admin");
    let n = edit(base(), |b| add_role(b, M, Role::Admin));
    denied(accept(base(), n, U), "U grants Admin to M");
}

#[test]
fn user_manager_grants_only_what_it_holds() {
    let n = edit(base(), |b| add_role(b, M, Role::Auditor));
    denied(accept(base(), n, U), "U grants Auditor");
    let n = edit(base(), |b| {
        upsert(b, invite(X, RoleSet::of(&[Role::Provisioner])))
    });
    denied(accept(base(), n, U), "U invites a Provisioner");
    let n = edit(base(), |b| add_role(b, M, Role::UserManager));
    assert!(accept(base(), n, U).is_ok(), "U grants UserManager");
    let n = edit(base(), |b| {
        upsert(b, invite(X, RoleSet::of(&[Role::UserManager])))
    });
    assert!(accept(base(), n, U).is_ok(), "U invites a UserManager");
}

#[test]
fn no_self_escalation() {
    let n = edit(base(), |b| add_role(b, U, Role::Admin));
    denied(accept(base(), n, U), "U adds Admin to itself");
    let n = edit(base(), |b| add_role(b, U, Role::Auditor));
    denied(accept(base(), n, U), "U adds Auditor to itself");
    let n = edit(base(), |b| entry(b, U).devices.push([0xFF; 32]));
    denied(accept(base(), n, U), "U adds a device to itself");
    let n = edit(base(), |b| add_role(b, A, Role::Owner));
    denied(accept(base(), n, A), "A adds Owner to itself");
    let n = edit(base(), |b| entry(b, U).roles = RoleSet::EMPTY);
    assert!(accept(base(), n, U).is_ok(), "U drops its own UserManager");
}

#[test]
fn user_manager_cannot_touch_admins() {
    let n = edit(base(), |b| set_state(b, A, MemberState::Suspended));
    denied(accept(base(), n, U), "U suspends A");
    let n = edit(base(), |b| removed_by(b, A, U));
    denied(accept(base(), n, U), "U removes A");
    let n = edit(base(), |b| entry(b, A).roles = RoleSet::EMPTY);
    denied(accept(base(), n, U), "U revokes A's Admin");
    let n = edit(base(), |b| set_state(b, O, MemberState::Suspended));
    denied(accept(base(), n, U), "U suspends O");
    // A plain member is fine.
    let n = edit(base(), |b| set_state(b, M, MemberState::Suspended));
    assert!(accept(base(), n, U).is_ok(), "U suspends M");
}

#[test]
fn admin_cannot_touch_owners() {
    let n = edit(base(), |b| set_state(b, O, MemberState::Suspended));
    denied(accept(base(), n, A), "A suspends O");
    let n = edit(base(), |b| {
        let e = entry(b, O);
        e.devices.push([0xFF; 32]);
    });
    denied(accept(base(), n, A), "A edits O's devices");
    let n = edit(base(), |b| add_role(b, O, Role::Auditor));
    denied(accept(base(), n, A), "A grants Auditor to O");
    // An owner may.
    let n = edit(base(), |b| add_role(b, A, Role::Auditor));
    assert!(accept(base(), n, O).is_ok(), "O grants Auditor to A");
    let n = edit(base(), |b| set_state(b, A, MemberState::Suspended));
    assert!(accept(base(), n, O).is_ok(), "O suspends A");
}

#[test]
fn provisioner_only_suspends_or_removes() {
    let org = org();
    let n = edit(base(), |b| set_state(b, M, MemberState::Suspended));
    let suspended = accept(base(), n, P).unwrap();
    let n = edit(&suspended, |b| removed_by(b, M, P));
    assert!(accept(&suspended, n, P).is_ok(), "P removes suspended M");
    let n = edit(base(), |b| removed_by(b, M, P));
    assert!(accept(base(), n, P).is_ok(), "P removes M");
    let n = edit(base(), |b| removed_by(b, U, P));
    assert!(accept(base(), n, P).is_ok(), "P removes U and its roles");

    let n = edit(base(), |b| upsert(b, invite(X, RoleSet::EMPTY)));
    denied(accept(base(), n, P), "P invites");
    let n = edit(base(), |b| add_role(b, M, Role::Auditor));
    denied(accept(base(), n, P), "P grants");
    let n = edit(&suspended, |b| set_state(b, M, MemberState::Active));
    denied(accept(&suspended, n, P), "P reactivates");
    // r6 has X invited: P cannot activate it.
    let x = device(0x61);
    let n = edit(r(6), |b| activate(entry(b, X), &member_ref(X, &[&x])));
    assert!(accept(r(6), n.clone(), O).is_ok(), "O activates X");
    denied(accept(r(6), n, P), "P activates X");
    let n = edit(base(), |b| entry(b, M).devices.push([0xFF; 32]));
    denied(accept(base(), n, P), "P edits devices");
    let n = edit(base(), |b| b.org_head = org.lineages[1].head().hash);
    denied(
        accept_in(&org.lineages[1], base(), n.clone(), P),
        "P changes org_head",
    );
    assert!(
        accept_in(&org.lineages[1], base(), n, O).is_ok(),
        "O changes org_head"
    );
    let n = edit(base(), |b| removed_by(b, P, P));
    denied(accept(base(), n, P), "P removes itself");
    let n = edit(base(), |b| {
        removed_by(b, M, P);
        entry(b, M).scim_id_hash = [1; 32];
    });
    denied(accept(base(), n, P), "P removes and edits");
    let n = edit(base(), |b| {
        set_state(b, U, MemberState::Suspended);
        entry(b, U).roles = RoleSet::EMPTY;
    });
    denied(accept(base(), n, P), "P suspends U and revokes its role");
    // Unchanged roster: fine.
    assert!(accept(base(), base().next().unwrap(), P).is_ok());
}

#[test]
fn provisioner_cannot_remove_admin() {
    let n = edit(base(), |b| removed_by(b, A, P));
    denied(accept(base(), n, P), "P removes A");
    let n = edit(base(), |b| set_state(b, A, MemberState::Suspended));
    denied(accept(base(), n, P), "P suspends A");
    let n = edit(base(), |b| set_state(b, O, MemberState::Suspended));
    denied(accept(base(), n, P), "P suspends O");
}

#[test]
fn policy_manager_and_auditor_cannot_sign() {
    for role in [Role::PolicyManager, Role::Auditor] {
        let n = edit(base(), |b| add_role(b, M, role));
        let pinned = accept(base(), n, O).unwrap();
        denied(
            accept(&pinned, pinned.next().unwrap(), M),
            "unchanged roster by M",
        );
        let n = edit(&pinned, |b| upsert(b, invite(X, RoleSet::EMPTY)));
        denied(accept(&pinned, n, M), "invite by M");
    }
    denied(
        accept(base(), base().next().unwrap(), M),
        "member without roles",
    );
}

#[test]
fn suspended_or_removed_signer_refused() {
    let n = edit(base(), |b| set_state(b, A, MemberState::Suspended));
    let pinned = accept(base(), n, O).unwrap();
    denied(
        accept(&pinned, pinned.next().unwrap(), A),
        "suspended admin",
    );
    let n = edit(&pinned, |b| set_state(b, A, MemberState::Active));
    denied(accept(&pinned, n, A), "suspended admin reactivates itself");
    let n = edit(base(), |b| removed_by(b, U, O));
    let pinned = accept(base(), n, O).unwrap();
    denied(
        accept(&pinned, pinned.next().unwrap(), U),
        "removed user manager",
    );
}

#[test]
fn signer_key_from_pinned_roster() {
    let org = org();
    let new = device(0x60);
    let n = edit(base(), |b| {
        let e = entry(b, A);
        e.devices.push(new.public.fingerprint());
        e.devices.sort_unstable();
    });
    let rec = sign_roster(n.clone(), &new.public, &new.keys).unwrap();
    denied(
        accept_next_roster(l0(), base(), &rec),
        "signed by the new device",
    );
    // O may add A's device; then the new device signs.
    let pinned = accept(base(), n, O).unwrap();
    let rec = sign_roster(pinned.next().unwrap(), &new.public, &new.keys).unwrap();
    assert!(accept_next_roster(l0(), &pinned, &rec).is_ok());

    // A's signing key under another device id: its fingerprint is not listed.
    let other = org.a.keys.public(Id([0x99; 16])).unwrap();
    assert_ne!(other.fingerprint(), org.a.public.fingerprint());
    let rec = sign_roster(base().next().unwrap(), &other, &org.a.keys).unwrap();
    denied(
        accept_next_roster(l0(), base(), &rec),
        "fingerprint mismatch",
    );
    // A listed signer with a signature by other keys.
    let mut rec = sign_roster(base().next().unwrap(), &org.u.public, &org.u.keys).unwrap();
    rec.signer = org.a.public.clone();
    assert!(
        accept_next_roster(l0(), base(), &rec).is_err(),
        "bad signature"
    );
}

#[test]
fn owner_role_mirrors_lineage() {
    let org = org();
    let l2 = &org.lineages[2];
    let n = edit(base(), |b| add_role(b, M, Role::Owner));
    denied(accept(base(), n, A), "A grants Owner to M");
    let n = edit(base(), |b| add_role(b, M, Role::Owner));
    denied(accept(base(), n, O), "O grants Owner to M");
    let promoted = edit(base(), |b| {
        b.org_head = l2.head().hash;
        add_role(b, M, Role::Owner);
    });
    assert_eq!(
        accept_in(l2, base(), promoted.clone(), A).unwrap(),
        promoted,
        "mirror by A"
    );
    assert!(
        accept_in(l2, base(), promoted.clone(), O).is_ok(),
        "mirror by O"
    );
    denied(
        accept_in(l2, base(), promoted, U),
        "mirror by a user manager",
    );
    let omitted = edit(base(), |b| b.org_head = l2.head().hash);
    denied(accept_in(l2, base(), omitted, A), "owner omitted");
    // A mirrored owner with another identity.
    let n = edit(base(), |b| {
        b.org_head = l2.head().hash;
        add_role(b, M, Role::Owner);
        entry(b, M).account_identity_pub = Some(identity_pool(0).1.clone());
    });
    denied(accept_in(l2, base(), n, O), "owner identity differs");
    // A lineage owner absent from prev may be added directly, Active.
    let pinned = r(1);
    let n = edit(pinned, |b| {
        b.org_head = l2.head().hash;
        let mut m = OrgMember {
            roles: RoleSet::of(&[Role::Owner]),
            ..invite(M, RoleSet::EMPTY)
        };
        m.invite_commit = [0; 32];
        activate(&mut m, &member_ref(M, &[&org.m]));
        upsert(b, m);
    });
    assert!(accept_in(l2, pinned, n, O).is_ok(), "lineage owner added");
}

#[test]
fn recovery_officer_never_in_e1() {
    let org = org();
    let mut rec = sign_roster(base().next().unwrap(), &org.o.public, &org.o.keys).unwrap();
    add_role(&mut rec.body, M, Role::RecoveryOfficer);
    assert!(matches!(
        accept_next_roster(l0(), base(), &rec),
        Err(Error::InvalidFormat(_))
    ));
    assert!(matches!(
        check_transition(l0(), base(), &rec.body, &org.o.public),
        Err(Error::InvalidFormat(_))
    ));
}

#[test]
fn members_never_disappear() {
    let n = edit(base(), |b| b.members.retain(|m| m.account_id != acct(M)));
    denied(accept(base(), n, O), "O drops M");
    let n = edit(r(6), |b| b.members.retain(|m| m.account_id != acct(X)));
    denied(accept(r(6), n, A), "A drops invited X");
}

#[test]
fn removed_is_terminal() {
    let n = edit(base(), |b| removed_by(b, M, O));
    let pinned = accept(base(), n, O).unwrap();
    let org = org();
    let n = edit(&pinned, |b| {
        activate(entry(b, M), &member_ref(M, &[&org.m]));
    });
    denied(accept(&pinned, n, O), "Removed -> Active");
    let n = edit(&pinned, |b| {
        entry(b, M).state = MemberState::Removed {
            at: 1_800_000_000,
            by: acct(O),
        }
    });
    denied(accept(&pinned, n, O), "another at");
    let n = edit(&pinned, |b| entry(b, M).scim_id_hash = [1; 32]);
    denied(accept(&pinned, n, O), "removed entry edited");
    // Fields the per-entry rules do not freeze stay frozen once Removed.
    let n = edit(&pinned, |b| entry(b, M).account_kem_hash = [1; 32]);
    denied(accept(&pinned, n, O), "removed kem hash edited");
    let n = edit(&pinned, |b| entry(b, M).account_identity_pub = None);
    denied(accept(&pinned, n, O), "removed identity dropped");
}

#[test]
fn removed_by_must_be_signer() {
    let n = edit(base(), |b| removed_by(b, M, A));
    denied(accept(base(), n, O), "by A, signed by O");
    let n = edit(base(), |b| removed_by(b, M, O));
    assert!(accept(base(), n, O).is_ok());
    let n = edit(base(), |b| removed_by(b, M, O));
    denied(accept(base(), n, P), "P signs a removal by O");
}

#[test]
fn state_transitions() {
    let pinned = r(6); // X Invited, the others Active.
    let n = edit(pinned, |b| {
        activate(entry(b, X), &member_ref(X, &[&device(0x61)]))
    });
    assert!(accept(pinned, n, O).is_ok(), "Invited -> Active");
    let n = edit(pinned, |b| removed_by(b, X, A));
    assert!(accept(pinned, n, A).is_ok(), "Invited -> Removed");
    let n = edit(base(), |b| set_state(b, M, MemberState::Suspended));
    let suspended = accept(base(), n, A).unwrap();
    let n = edit(&suspended, |b| set_state(b, M, MemberState::Active));
    assert!(accept(&suspended, n, A).is_ok(), "Suspended -> Active");
    let n = edit(&suspended, |b| removed_by(b, M, A));
    assert!(accept(&suspended, n, A).is_ok(), "Suspended -> Removed");
    let n = edit(base(), |b| removed_by(b, M, A));
    assert!(accept(base(), n, A).is_ok(), "Active -> Removed");

    let n = edit(pinned, |b| {
        let e = entry(b, X);
        activate(e, &member_ref(X, &[&device(0x62)]));
        e.state = MemberState::Suspended;
    });
    assert!(n.check().is_ok());
    denied(accept(pinned, n, O), "Invited -> Suspended");
    let n = edit(base(), |b| {
        let e = entry(b, M);
        e.state = MemberState::Invited;
        e.account_identity_pub = None;
        e.account_kem_hash = [0; 32];
        e.devices.clear();
    });
    assert!(n.check().is_ok());
    denied(accept(base(), n, O), "Active -> Invited");
}

#[test]
fn immutable_member_fields() {
    let n = edit(base(), |b| entry(b, M).account_id = Id([0x70; 16]));
    denied(accept(base(), n, O), "account_id");
    let n = edit(base(), |b| entry(b, M).scim_id_hash = [1; 32]);
    denied(accept(base(), n, O), "scim_id_hash");
    let n = edit(base(), |b| entry(b, M).invite_commit = [1; 32]);
    denied(accept(base(), n, O), "invite_commit");
}

#[test]
fn org_head_must_be_known_and_not_older() {
    let org = org();
    let l1 = &org.lineages[1];
    let n = edit(base(), |b| b.org_head = [0xAB; 32]);
    not_found(accept(base(), n, O), "unknown head");
    let n = edit(base(), |b| b.org_head = l1.head().hash);
    let pinned = accept_in(l1, base(), n, O).unwrap();
    let n = edit(&pinned, |b| b.org_head = l0().head().hash);
    assert_eq!(
        integrity_err(accept_in(l1, &pinned, n, O)),
        IntegrityError::OrgLineageRollback
    );
    let mut other = base().next().unwrap();
    other.org_id = OrgId([8; 16]);
    let rec = sign_roster(other, &org.o.public, &org.o.keys).unwrap();
    assert_eq!(
        integrity_err(accept_next_roster(l0(), base(), &rec)),
        IntegrityError::WrongContext
    );
}

#[test]
fn roster_with_unknown_head_asks_for_lineage() {
    let org = org();
    // Generation 2 exists, but this client's lineage stops at 1.
    let n = edit(base(), |b| {
        b.org_head = org.lineages[2].head().hash;
        add_role(b, M, Role::Owner);
    });
    not_found(
        accept_in(&org.lineages[1], base(), n.clone(), O),
        "head not applied yet",
    );
    // Once the lineage has it, the same roster is fine.
    assert!(accept_in(&org.lineages[2], base(), n, O).is_ok());
}

#[test]
fn replayed_older_roster_is_rollback() {
    let org = org();
    assert_eq!(
        integrity_err(accept_next_roster(l0(), r(5), &org.chain[3])),
        IntegrityError::OrgRosterRollback
    );
    assert_eq!(
        &accept_next_roster(l0(), r(5), &org.chain[4]).unwrap(),
        r(5)
    );
    assert_eq!(
        integrity_err(accept_roster_chain(
            l0(),
            r(4),
            &org.chain[4..6]
                .iter()
                .chain(&org.chain[4..5])
                .cloned()
                .collect::<Vec<_>>()
        )),
        IntegrityError::OrgRosterRollback
    );
}

#[test]
fn same_seq_other_body_is_fork() {
    let mut other = r(4).next().unwrap();
    upsert(&mut other, invite(X, RoleSet::EMPTY));
    assert_eq!(other.seq, 5);
    let o = &org().o;
    let rec = sign_roster(other, &o.public, &o.keys).unwrap();
    assert_eq!(
        integrity_err(accept_next_roster(l0(), r(5), &rec)),
        IntegrityError::OrgRosterFork
    );
}

#[test]
fn next_with_wrong_prev_hash_is_fork() {
    let mut n = r(5).next().unwrap();
    n.prev_hash = [1; 32];
    assert_eq!(n.seq, 6);
    let o = &org().o;
    let rec = sign_roster(n, &o.public, &o.keys).unwrap();
    assert_eq!(
        integrity_err(accept_next_roster(l0(), r(5), &rec)),
        IntegrityError::OrgRosterFork
    );
}

#[test]
fn gap_asks_for_intermediate() {
    let org = org();
    not_found(accept_next_roster(l0(), r(5), &org.chain[6]), "seq 7 on 5");
    assert_eq!(
        &accept_roster_chain(l0(), r(5), &org.chain[5..7]).unwrap(),
        r(7)
    );
    assert_eq!(&accept_roster_chain(l0(), r(5), &[]).unwrap(), r(5));
}

#[test]
fn first_pin_from_owner_signed_roster() {
    let org = org();
    assert_eq!(&accept_first_roster(l0(), &org.chain[4..7]).unwrap(), r(7));
    denied(
        accept_first_roster(l0(), &org.chain[5..7]),
        "starting at r6 by A",
    );
    // An owner device of another generation's owners does not count: M is
    // an owner at generation 2 only.
    let n = edit(r(5), |_| {});
    let rec = sign_roster(n, &org.m.public, &org.m.keys).unwrap();
    denied(accept_first_roster(&org.lineages[2], &[rec]), "M at gen 0");
    // A first roster whose owner bits do not mirror its generation.
    let n = edit(r(5), |b| add_role(b, M, Role::Owner));
    let rec = sign_roster(n, &org.o.public, &org.o.keys).unwrap();
    denied(accept_first_roster(l0(), &[rec]), "mirror broken");
}
