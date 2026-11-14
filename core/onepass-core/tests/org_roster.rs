//! The signed org roster (Business E1, plan B Task 6): roles as a bit set,
//! member shape rules, the strict codec and the caps.

mod org_common;

use std::sync::OnceLock;

use onepass_core::crypto::IdentityVerifyingKey;
use onepass_core::org::{
    DeviceFpr, MAX_MEMBER_DEVICES, MAX_ORG_RECORD_BYTES, MAX_ROSTER_MEMBERS, MemberState, OrgId,
    OrgMember, Role, RoleSet, RosterBody, SignedRoster, invite_commit, member_kem_hash,
    scim_id_hash, sign_roster,
};
use onepass_core::{Error, Id};
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
