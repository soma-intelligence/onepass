//! Invitation and join request (Business E1, plan B Task 9): an invited
//! member joins with a managed genesis (format 2) bound to the invitation's
//! org and account, signed by the genesis creator device; the admin
//! verifies it against the pinned roster and org fingerprint, then
//! activates the member. Then pinning (Task 10): MDM, DNS TXT or TOFU,
//! and `OrgPin::advance`; a pinned fingerprint is never followed when it
//! changes.

mod org_common;

use std::sync::OnceLock;

use onepass_core::device_keys::DeviceKeys;
use onepass_core::generator::Wordlist;
use onepass_core::lineage::{GenesisBody, LineageRecord, RotationBody, RotationReason, Signed};
use onepass_core::org::{
    Invitation, JoinRequestBody, MAX_ORG_RECORD_BYTES, MemberState, ORG_JOIN_CODE_PREFIX,
    ORG_JOIN_DOMAIN, OrgChangeBody, OrgChangeKind, OrgGenesisBody, OrgId, OrgLineage, OrgMember,
    OrgPin, OrgSecrets, PinSource, Role, RoleSet, RosterBody, SignedJoinRequest, SignedOrgRecord,
    SignedRoster, accept_next_roster, activate_member, dns_fingerprint, dns_txt_value,
    fingerprint_base32, fingerprint_words, founding_roster, invite_commit, invite_member,
    join_code, join_code_of, member_kem_hash, parse_dns_txt, pin_org, scim_id_hash,
    sign_join_request, sign_org_change, sign_org_genesis, sign_roster, verify_join_request,
    verify_org_genesis,
};
use onepass_core::repo::ManagedGenesis;
use onepass_core::{Error, Id, IntegrityError};
use org_common::*;

const ORG: OrgId = OrgId([7; 16]);
const O: u8 = 1;
const U: u8 = 3;

/// The fixture org: owner O, UserManager U (Active since r3); r4 is U's
/// invitation of a new member with roles {UserManager}; `joiner` is that
/// member's managed account, created for the invitation's account id.
struct Fx {
    o: TestDevice,
    u: TestDevice,
    lineage: OrgLineage,
    org_fpr: [u8; 32],
    r3: RosterBody,
    r4: RosterBody,
    invitation: Invitation,
    joiner: Joiner,
}

fn fx() -> &'static Fx {
    static CELL: OnceLock<Fx> = OnceLock::new();
    CELL.get_or_init(|| {
        let (o, u) = (device(0x10), device(0x30));
        let secrets = org_secrets();
        let genesis = sign_org_genesis(
            OrgGenesisBody {
                format: 1,
                org_id: ORG,
                name: "Acme".to_string(),
                org_identity_pub: secrets.identity.verifying_key(),
                audit_kem_pub: secrets.audit.public().unwrap(),
                owners: vec![member_ref(O, &[&o])],
                created_at: 1_700_000_000,
            },
            &secrets.identity,
            &[(&o.public, &o.keys)],
        )
        .unwrap();
        let lineage = verify_org_genesis(&genesis).unwrap();
        let org_fpr = sha256(&[b"onepass/org-fingerprint/v1", &genesis.hash()]);
        let r1 = founding_roster(&lineage).unwrap();
        let mut r2 = r1.next().unwrap();
        let u_id = Id([U; 16]);
        r2.members.push(OrgMember {
            account_id: u_id,
            account_identity_pub: None,
            scim_id_hash: [0; 32],
            invite_commit: invite_commit(ORG, u_id, &[U; 32]),
            account_kem_hash: [0; 32],
            roles: RoleSet::of(&[Role::UserManager]),
            state: MemberState::Invited,
            devices: vec![],
        });
        r2.members.sort_by_key(|m| m.account_id);
        let mut r3 = r2.next().unwrap();
        let u_ref = member_ref(U, &[&u]);
        let e = r3
            .members
            .iter_mut()
            .find(|m| m.account_id == u_id)
            .unwrap();
        e.state = MemberState::Active;
        e.account_identity_pub = Some(u_ref.account_identity_pub.clone());
        e.account_kem_hash = member_kem_hash(&u_ref.account_kem_pub);
        e.devices = u_ref.devices.clone();
        r3.check().unwrap();
        let (r4, invitation) = invite_member(
            &r3,
            scim_id_hash(ORG, "camille"),
            RoleSet::of(&[Role::UserManager]),
        )
        .unwrap();
        let joiner = create(Some(ManagedGenesis {
            org_id: ORG,
            account_id: invitation.account_id,
        }));
        Fx {
            o,
            u,
            lineage,
            org_fpr,
            r3,
            r4,
            invitation,
            joiner,
        }
    })
}

fn other_account() -> &'static Joiner {
    static CELL: OnceLock<Joiner> = OnceLock::new();
    CELL.get_or_init(|| {
        create(Some(ManagedGenesis {
            org_id: ORG,
            account_id: Id([0x77; 16]),
        }))
    })
}

fn other_org() -> &'static Joiner {
    static CELL: OnceLock<Joiner> = OnceLock::new();
    CELL.get_or_init(|| {
        create(Some(ManagedGenesis {
            org_id: OrgId([8; 16]),
            account_id: fx().invitation.account_id,
        }))
    })
}

fn personal() -> &'static Joiner {
    static CELL: OnceLock<Joiner> = OnceLock::new();
    CELL.get_or_init(|| create(None))
}

/// The join request body of `j` for the fixture invitation.
fn body_of(j: &Joiner) -> JoinRequestBody {
    let f = fx();
    JoinRequestBody {
        format: 1,
        org_id: ORG,
        account_id: f.invitation.account_id,
        invite_nonce: f.invitation.nonce,
        pinned_fpr: f.org_fpr,
        account_genesis: j.genesis.clone(),
        devices: vec![j.device.clone()],
        display_name: "Camille Durand".to_string(),
        mailbox_credential: [0x42; 32],
        account_kem_pub: j.kem.clone(),
        issued_at: 1_700_000_900,
    }
}

fn body() -> JoinRequestBody {
    body_of(&fx().joiner)
}

fn signed(body: JoinRequestBody, keys: &DeviceKeys) -> SignedJoinRequest {
    sign_join_request(body, keys).unwrap()
}

fn request() -> &'static SignedJoinRequest {
    static CELL: OnceLock<SignedJoinRequest> = OnceLock::new();
    CELL.get_or_init(|| signed(body(), &fx().joiner.keys))
}

fn verify(req: &SignedJoinRequest) -> onepass_core::Result<onepass_core::org::VerifiedJoin> {
    verify_join_request(req, &fx().r4, &fx().org_fpr)
}

fn integrity<T: std::fmt::Debug>(r: onepass_core::Result<T>, want: IntegrityError, what: &str) {
    match r {
        Err(Error::Integrity(e)) if e == want => {}
        other => panic!("{what}: expected Integrity({want:?}), got {other:?}"),
    }
}

fn member(b: &RosterBody, a: Id) -> &OrgMember {
    b.members.iter().find(|m| m.account_id == a).unwrap()
}

#[test]
fn join_round_trip() {
    let f = fx();
    // U's invitation is a valid roster change.
    let inv = member(&f.r4, f.invitation.account_id);
    assert_eq!(inv.state, MemberState::Invited);
    assert_eq!(
        inv.invite_commit,
        invite_commit(ORG, f.invitation.account_id, &f.invitation.nonce)
    );
    assert_eq!(inv.roles, RoleSet::of(&[Role::UserManager]));
    assert_eq!(inv.scim_id_hash, scim_id_hash(ORG, "camille"));
    assert_eq!(f.r4.seq, f.r3.seq + 1);
    assert_eq!(f.r4.prev_hash, f.r3.hash());
    let rec4 = sign_roster(f.r4.clone(), &f.u.public, &f.u.keys).unwrap();
    assert_eq!(accept_next_roster(&f.lineage, &f.r3, &rec4).unwrap(), f.r4);

    // The member's managed genesis names the org and the invited account.
    let LineageRecord::Genesis(g) = LineageRecord::decode(&f.joiner.genesis).unwrap() else {
        panic!("a genesis")
    };
    assert_eq!(g.body.format, 2);
    assert_eq!(g.body.org(), Some(ORG));
    assert_eq!(g.body.account_id, f.invitation.account_id);

    let req = request();
    let wire = req.encode();
    assert_eq!(&SignedJoinRequest::decode(&wire).unwrap(), req);
    let joined = verify(req).unwrap();
    assert_eq!(joined.account_id, f.invitation.account_id);
    assert_eq!(joined.account_identity_pub, f.joiner.identity);
    assert_eq!(joined.devices, vec![f.joiner.device.clone()]);

    let r5 = activate_member(&f.r4, &joined).unwrap();
    let rec5 = sign_roster(r5.clone(), &f.u.public, &f.u.keys).unwrap();
    assert_eq!(accept_next_roster(&f.lineage, &f.r4, &rec5).unwrap(), r5);
    let m = member(&r5, f.invitation.account_id);
    assert_eq!(m.state, MemberState::Active);
    assert_eq!(m.account_identity_pub.as_ref(), Some(&f.joiner.identity));
    assert_eq!(m.devices, vec![f.joiner.device.fingerprint()]);
    assert_eq!(m.roles, RoleSet::of(&[Role::UserManager]));
    // Everything else kept.
    let mut rest = r5.clone();
    rest.members
        .retain(|x| x.account_id != f.invitation.account_id);
    let mut before = f.r4.next().unwrap();
    before
        .members
        .retain(|x| x.account_id != f.invitation.account_id);
    assert_eq!(rest, before);
    // The owner may sign it too.
    let rec5o = sign_roster(r5.clone(), &f.o.public, &f.o.keys).unwrap();
    assert!(accept_next_roster(&f.lineage, &f.r4, &rec5o).is_ok());
}

#[test]
fn join_wrong_nonce_refused() {
    let mut b = body();
    b.invite_nonce[0] ^= 1;
    integrity(
        verify(&signed(b, &fx().joiner.keys)),
        IntegrityError::WrongContext,
        "wrong nonce",
    );
}

#[test]
fn join_pinned_other_org_refused() {
    let mut b = body();
    b.pinned_fpr = [0x55; 32];
    integrity(
        verify(&signed(b, &fx().joiner.keys)),
        IntegrityError::OrgPinMismatch,
        "pinned another org",
    );
    // The admin's own pin differs from the one the member pinned.
    integrity(
        verify_join_request(request(), &fx().r4, &[0x55; 32]),
        IntegrityError::OrgPinMismatch,
        "admin pin differs",
    );
}

#[test]
fn join_personal_genesis_refused() {
    let j = personal();
    integrity(
        verify(&signed(body_of(j), &j.keys)),
        IntegrityError::WrongContext,
        "personal genesis",
    );
}

#[test]
fn join_genesis_other_org_refused() {
    let j = other_org();
    integrity(
        verify(&signed(body_of(j), &j.keys)),
        IntegrityError::WrongContext,
        "genesis of another org",
    );
}

#[test]
fn join_genesis_other_account_refused() {
    let j = other_account();
    integrity(
        verify(&signed(body_of(j), &j.keys)),
        IntegrityError::WrongContext,
        "genesis of another account",
    );
}

#[test]
fn join_device_not_creator_refused() {
    let d = device(0x90);
    let mut b = body();
    b.devices = vec![d.public.clone()];
    integrity(
        verify(&signed(b, &d.keys)),
        IntegrityError::WrongContext,
        "device is not the genesis creator",
    );
}

#[test]
fn join_signed_by_other_device_refused() {
    let d = device(0x91);
    let b = body();
    // sign_join_request refuses keys that do not match devices[0].
    assert!(matches!(
        sign_join_request(b.clone(), &d.keys),
        Err(Error::Validation(_))
    ));
    let msg = postcard::to_allocvec(&b).unwrap();
    let forged = SignedJoinRequest {
        device_sig: d.keys.sign(ORG_JOIN_DOMAIN, &msg).unwrap(),
        body: b,
    };
    integrity(verify(&forged), IntegrityError::Signature, "other device");
    // A signature under another domain fails too.
    let msg = postcard::to_allocvec(&body()).unwrap();
    let wrong_domain = SignedJoinRequest {
        device_sig: fx()
            .joiner
            .keys
            .sign(b"onepass/org-roster/v1", &msg)
            .unwrap(),
        body: body(),
    };
    integrity(
        verify(&wrong_domain),
        IntegrityError::Signature,
        "wrong domain",
    );
}

#[test]
fn join_for_active_member_refused() {
    let f = fx();
    let joined = verify(request()).unwrap();
    let r5 = activate_member(&f.r4, &joined).unwrap();
    assert!(matches!(
        verify_join_request(request(), &r5, &f.org_fpr),
        Err(Error::Validation(_))
    ));
    assert!(matches!(
        activate_member(&r5, &joined),
        Err(Error::Validation(_))
    ));
    // Not in the roster at all.
    assert!(matches!(
        verify_join_request(request(), &f.r3, &f.org_fpr),
        Err(Error::Validation(_))
    ));
}

#[test]
fn join_decode_strict() {
    let req = request();
    let enc = req.encode();
    assert_eq!(&SignedJoinRequest::decode(&enc).unwrap(), req);

    let invalid = |what: &str, r: onepass_core::Result<SignedJoinRequest>| {
        assert!(
            matches!(r, Err(Error::InvalidFormat(_))),
            "{what}: got {r:?}"
        );
    };
    let refused = |what: &str, f: &dyn Fn(&mut JoinRequestBody)| {
        let mut r = req.clone();
        f(&mut r.body);
        invalid(what, SignedJoinRequest::decode(&r.encode()));
        assert!(
            sign_join_request(r.body.clone(), &fx().joiner.keys).is_err(),
            "sign: {what}"
        );
        assert!(verify(&r).is_err(), "verify: {what}");
    };

    let mut trailing = enc.clone();
    trailing.push(0);
    invalid("trailing byte", SignedJoinRequest::decode(&trailing));
    invalid(
        "truncated",
        SignedJoinRequest::decode(&enc[..enc.len() - 1]),
    );
    invalid(
        "oversize input",
        SignedJoinRequest::decode(&vec![0u8; MAX_ORG_RECORD_BYTES + 1]),
    );
    refused("two devices", &|b| b.devices.push(device(0x92).public));
    refused("no device", &|b| b.devices.clear());
    refused("oversize genesis", &|b| {
        b.account_genesis = vec![0; 64 * 1024 + 1]
    });
    refused("format 2", &|b| b.format = 2);
    refused("format 0", &|b| b.format = 0);
    refused("65-byte name", &|b| b.display_name = "a".repeat(65));
    refused("name with a control char", &|b| {
        b.display_name = "Camille\u{7}".to_string()
    });
    refused("name with a newline", &|b| {
        b.display_name = "Camille\nDurand".to_string()
    });
    for c in [
        '\u{00AD}', '\u{200B}', '\u{200D}', '\u{200F}', '\u{202A}', '\u{202E}', '\u{2060}',
        '\u{2064}', '\u{2066}', '\u{2069}', '\u{FEFF}',
    ] {
        refused(&format!("name with U+{:04X}", c as u32), &|b| {
            b.display_name = format!("Cam{c}ille")
        });
    }
    // Neighbours of the refused ranges stay allowed.
    for c in ['\u{2010}', '\u{2070}', '\u{2065}', '\u{202F}'] {
        let mut b = body();
        b.display_name = format!("Cam{c}ille");
        let ok = signed(b, &fx().joiner.keys);
        assert_eq!(SignedJoinRequest::decode(&ok.encode()).unwrap(), ok);
    }
    refused("short KEM key", &|b| {
        b.account_kem_pub.mlkem.pop();
    });
    refused("short device signing key", &|b| {
        b.devices[0].sign_pub.mldsa.pop();
    });
    let mut short_sig = req.clone();
    short_sig.device_sig.mldsa.pop();
    invalid(
        "short signature",
        SignedJoinRequest::decode(&short_sig.encode()),
    );

    // 64 bytes of UTF-8 (32 two-byte chars) is the cap.
    let mut b = body();
    b.display_name = "\u{e9}".repeat(32);
    assert_eq!(b.display_name.len(), 64);
    let ok = signed(b, &fx().joiner.keys);
    assert_eq!(SignedJoinRequest::decode(&ok.encode()).unwrap(), ok);
    let mut b = body();
    b.display_name = "\u{e9}".repeat(32) + "a";
    assert!(sign_join_request(b, &fx().joiner.keys).is_err());
}

#[test]
fn join_carries_name_credential_kem() {
    let f = fx();
    let joined = verify(request()).unwrap();
    assert_eq!(joined.display_name, "Camille Durand");
    assert_eq!(joined.mailbox_credential, [0x42; 32]);
    assert_eq!(joined.account_kem_pub, f.joiner.kem);
    let r5 = activate_member(&f.r4, &joined).unwrap();
    assert_eq!(
        member(&r5, f.invitation.account_id).account_kem_hash,
        member_kem_hash(&f.joiner.kem)
    );
}

#[test]
fn join_code_is_stable_and_bound() {
    let f = fx();
    let req = request();
    let list = Wordlist::EffEnglish;
    let code = join_code_of(req, list).unwrap();
    assert_eq!(code, join_code_of(&req.clone(), list).unwrap());
    assert_eq!(
        code,
        join_code(f.invitation.account_id, &f.joiner.identity, list)
    );
    // Independent recomputation.
    let h = sha256(&[
        ORG_JOIN_CODE_PREFIX,
        &f.invitation.account_id.0,
        &postcard::to_allocvec(&f.joiner.identity).unwrap(),
    ]);
    assert_eq!(code, fingerprint_words(&h, list)[0]);
    assert!(code.iter().all(|w| !w.is_empty()));
    // Only the identity counts: another issued_at, credential, nonce or
    // signature with the same genesis gives the same words.
    let mut later = body();
    later.issued_at += 1;
    let later = signed(later, &f.joiner.keys);
    assert_eq!(join_code_of(&later, list).unwrap(), code);
    let mut cred = req.clone();
    cred.body.mailbox_credential[0] ^= 1;
    assert_eq!(join_code_of(&cred, list).unwrap(), code);
    let mut nonce = req.clone();
    nonce.body.invite_nonce[31] ^= 1;
    nonce.device_sig.ed25519[0] ^= 1;
    assert_eq!(join_code_of(&nonce, list).unwrap(), code);
    // Another account's genesis: other words.
    let j = other_account();
    let other = signed(body_of(j), &j.keys);
    assert_ne!(join_code_of(&other, list).unwrap(), code);
    assert_ne!(
        join_code(Id([0x77; 16]), &f.joiner.identity, list),
        code,
        "the account id counts"
    );
    assert_ne!(join_code_of(req, Wordlist::FrenchDiceware).unwrap(), code);
    // Not a genesis: an error, never a code.
    let mut garbage = req.clone();
    garbage.body.account_genesis = vec![0; 10];
    assert!(join_code_of(&garbage, list).is_err());
    let mut rot = req.clone();
    rot.body.account_genesis = rotation_record(&f.joiner);
    integrity(
        join_code_of(&rot, list),
        IntegrityError::WrongContext,
        "rotation code",
    );
}

/// The joiner's genesis as a `Signed<GenesisBody>`.
fn genesis_of(j: &Joiner) -> Signed<GenesisBody> {
    match LineageRecord::decode(&j.genesis).unwrap() {
        LineageRecord::Genesis(g) => g,
        LineageRecord::Rotation(_) => panic!("a genesis"),
    }
}

/// A well-shaped Rotation record of `j`'s account (it passes the strict
/// decoder; its signatures are the genesis's, never checked here).
fn rotation_record(j: &Joiner) -> Vec<u8> {
    let g = genesis_of(j);
    let rec = LineageRecord::Rotation(Signed {
        body: RotationBody {
            format: 1,
            account_id: g.body.account_id,
            generation: 1,
            parent: LineageRecord::Genesis(g.clone()).hash(),
            rotator: g.body.creator.device_id,
            reason: RotationReason::Rotate,
            revoked: vec![],
            roster: vec![g.body.creator.clone()],
            identity_pub: g.body.identity_pub.clone(),
            params_hash: [1; 32],
            keyset_hash: [2; 32],
            deliveries: vec![],
            from_heads: Default::default(),
            issued_at: 1_700_000_800,
        },
        device_sig: g.device_sig.clone(),
        identity_sig: g.identity_sig.clone(),
    });
    let enc = rec.encode();
    assert!(matches!(
        LineageRecord::decode(&enc).unwrap(),
        LineageRecord::Rotation(_)
    ));
    enc
}

#[test]
fn join_genesis_bad_signature_refused() {
    let f = fx();
    let other = genesis_of(other_account());
    let mine = genesis_of(&f.joiner);
    // The other account's identity key in our genesis.
    let mut swapped_key = mine.clone();
    swapped_key.body.identity_pub = other.body.identity_pub.clone();
    // The other genesis's identity signature on ours.
    let mut swapped_sig = mine.clone();
    swapped_sig.identity_sig = other.identity_sig.clone();
    // The other genesis's device signature on ours.
    let mut swapped_dev = mine.clone();
    swapped_dev.device_sig = other.device_sig.clone();
    for (what, g) in [
        ("identity key swapped", swapped_key),
        ("identity signature swapped", swapped_sig),
        ("device signature swapped", swapped_dev),
    ] {
        let mut b = body();
        b.account_genesis = LineageRecord::Genesis(g).encode();
        integrity(
            verify(&signed(b, &f.joiner.keys)),
            IntegrityError::Signature,
            what,
        );
    }
}

#[test]
fn join_genesis_rotation_refused() {
    let f = fx();
    let mut b = body();
    b.account_genesis = rotation_record(&f.joiner);
    integrity(
        verify(&signed(b, &f.joiner.keys)),
        IntegrityError::WrongContext,
        "rotation instead of genesis",
    );
}

#[test]
fn invite_member_is_fresh() {
    let f = fx();
    let (a, ia) = invite_member(&f.r3, [0; 32], RoleSet::EMPTY).unwrap();
    let (b, ib) = invite_member(&f.r3, [0; 32], RoleSet::EMPTY).unwrap();
    assert_ne!(ia.account_id, ib.account_id);
    assert_ne!(ia.nonce, ib.nonce);
    assert_eq!(a.seq, f.r3.seq + 1);
    assert_eq!(a.members.len(), f.r3.members.len() + 1);
    assert_ne!(a, b);
    a.check().unwrap();
    let m = member(&a, ia.account_id);
    assert_eq!(m.state, MemberState::Invited);
    assert_eq!(m.account_identity_pub, None);
    assert!(m.devices.is_empty());
    assert_eq!(m.account_kem_hash, [0; 32]);
    // A RecoveryOfficer invitation is refused (D8).
    assert!(invite_member(&f.r3, [0; 32], RoleSet::of(&[Role::RecoveryOfficer])).is_err());
}

// ---------------------------------------------------------------------------
// Pinning (plan B Task 10): MDM, DNS TXT, TOFU, and `OrgPin::advance`.
// ---------------------------------------------------------------------------

/// The pinning fixture org: owner P (one device), genesis g0, g1 (audit
/// key rotated, same owners), rosters 1..=3 signed by P's device (r1 the
/// founding roster under g0, r2 and r3 under g1), and `rogue`: the genesis
/// of a new org identity under the same org id and owner.
struct PinFx {
    p: TestDevice,
    fpr: [u8; 32],
    g0: Vec<u8>,
    g1: Vec<u8>,
    rosters: Vec<Vec<u8>>,
    rogue: Vec<u8>,
}

const P: u8 = 2;

fn pin_fx() -> &'static PinFx {
    static CELL: OnceLock<PinFx> = OnceLock::new();
    CELL.get_or_init(|| {
        let p = device(0x20);
        let genesis_body = |secrets: &OrgSecrets| OrgGenesisBody {
            format: 1,
            org_id: ORG,
            name: "Acme".to_string(),
            org_identity_pub: secrets.identity.verifying_key(),
            audit_kem_pub: secrets.audit.public().unwrap(),
            owners: vec![member_ref(P, &[&p])],
            created_at: 1_700_000_000,
        };
        let secrets = org_secrets();
        let g0 = sign_org_genesis(
            genesis_body(secrets),
            &secrets.identity,
            &[(&p.public, &p.keys)],
        )
        .unwrap();
        let l0 = verify_org_genesis(&g0).unwrap();
        let g1 = sign_org_change(
            OrgChangeBody {
                format: 1,
                org_id: ORG,
                generation: 1,
                parent: g0.hash(),
                kind: OrgChangeKind::AuditKeyRotated {
                    audit_kem_pub: kem_pool(2).1.clone(),
                },
                issued_at: 1_700_000_100,
            },
            &secrets.identity,
            &[(&p.public, &p.keys)],
        )
        .unwrap();
        let l1 = l0.apply(&g1).unwrap();
        let r1 = founding_roster(&l0).unwrap();
        let mut r2 = r1.next().unwrap();
        r2.org_head = l1.head().hash;
        let r3 = r2.next().unwrap();
        let rosters = [r1, r2, r3]
            .into_iter()
            .map(|b| sign_roster(b, &p.public, &p.keys).unwrap().encode())
            .collect();
        let other = OrgSecrets::generate().unwrap();
        let rogue = sign_org_genesis(
            genesis_body(&other),
            &other.identity,
            &[(&p.public, &p.keys)],
        )
        .unwrap();
        PinFx {
            fpr: l0.fingerprint,
            g0: g0.encode(),
            g1: g1.encode(),
            rosters,
            rogue: rogue.encode(),
            p,
        }
    })
}

fn mdm_pin() -> OrgPin {
    let f = pin_fx();
    pin_org(PinSource::Mdm, Some(f.fpr), &f.g0).unwrap()
}

/// `(seq, bytes)` of the fixture rosters `seqs`.
fn rosters(seqs: &[u64]) -> Vec<(u64, Vec<u8>)> {
    seqs.iter()
        .map(|s| (*s, pin_fx().rosters[*s as usize - 1].clone()))
        .collect()
}

fn lineage_list(gens: &[u64]) -> Vec<(u64, Vec<u8>)> {
    let f = pin_fx();
    gens.iter()
        .map(|g| (*g, if *g == 0 { f.g0.clone() } else { f.g1.clone() }))
        .collect()
}

fn invalid_format<T: std::fmt::Debug>(r: onepass_core::Result<T>, what: &str) {
    match r {
        Err(Error::InvalidFormat(_)) => {}
        other => panic!("{what}: expected InvalidFormat, got {other:?}"),
    }
}

fn validation<T: std::fmt::Debug>(r: onepass_core::Result<T>, what: &str) {
    match r {
        Err(Error::Validation(_)) => {}
        other => panic!("{what}: expected Validation, got {other:?}"),
    }
}

const F: [u8; 32] = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
];

#[test]
fn dns_txt_round_trip() {
    let b32 = fingerprint_base32(&F);
    assert_eq!(b32.len(), 52);
    assert!(
        b32.chars()
            .all(|c| c.is_ascii_uppercase() || ('2'..='7').contains(&c))
    );
    assert_eq!(dns_txt_value(&F), format!("v=op1; org={b32}"));
    assert_eq!(parse_dns_txt(&dns_txt_value(&F)).unwrap(), F);
    let g = [0xA5; 32];
    assert_eq!(parse_dns_txt(&dns_txt_value(&g)).unwrap(), g);
}

#[test]
fn dns_txt_tolerant_forms() {
    let b32 = fingerprint_base32(&F);
    let lower = b32.to_ascii_lowercase();
    assert_eq!(parse_dns_txt(&format!(" v=op1 ;org={lower} ")).unwrap(), F);
    assert_eq!(parse_dns_txt(&format!("v=op1; org={b32}; x=1")).unwrap(), F);
    assert_eq!(parse_dns_txt(&format!("v=op1; x=1; org={b32}")).unwrap(), F);
    assert_eq!(parse_dns_txt(&format!("v = op1 ; org = {b32}")).unwrap(), F);
    assert_eq!(parse_dns_txt(&format!("v=op1;\torg={b32};")).unwrap(), F);
}

#[test]
fn dns_txt_refused_forms() {
    let b32 = fingerprint_base32(&F);
    let refused = [
        ("missing v", format!("org={b32}")),
        ("v=op2", format!("v=op2; org={b32}")),
        ("v not first", format!("org={b32}; v=op1")),
        ("org twice", format!("v=op1; org={b32}; org={b32}")),
        ("v twice", format!("v=op1; v=op1; org={b32}")),
        ("x twice", format!("v=op1; x=1; x=2; org={b32}")),
        ("no org", "v=op1; x=1".to_string()),
        ("51 chars", format!("v=op1; org={}", &b32[..51])),
        ("53 chars", format!("v=op1; org={b32}A")),
        ("padding", format!("v=op1; org={b32}====")),
        ("non-base32 char", format!("v=op1; org={}1", &b32[..51])),
        ("no equal sign", format!("v=op1; org {b32}")),
        ("empty", String::new()),
        (
            "over 255 bytes",
            format!("v=op1; org={b32}; x={}", "a".repeat(200)),
        ),
    ];
    for (what, txt) in refused {
        invalid_format(parse_dns_txt(&txt), what);
    }
    // 255 bytes exactly still parses.
    let base = format!("v=op1; org={b32}; x=");
    let exact = format!("{base}{}", "a".repeat(255 - base.len()));
    assert_eq!(exact.len(), 255);
    assert_eq!(parse_dns_txt(&exact).unwrap(), F);
}

#[test]
fn dns_records_mixed_and_cased() {
    let lowered = dns_txt_value(&F).to_ascii_lowercase();
    assert_eq!(
        dns_fingerprint(&["v=spf1 -all", &lowered]).unwrap(),
        F,
        "other TXT records are skipped, case does not matter"
    );
    assert_eq!(
        dns_fingerprint(&["google-site-verification=abc", &dns_txt_value(&F), &lowered]).unwrap(),
        F,
        "two records naming the same org agree"
    );
    // A record of another version is not ours.
    let v2 = format!("v=op2; org={}", fingerprint_base32(&[1; 32]));
    assert_eq!(dns_fingerprint(&[&v2, &dns_txt_value(&F)]).unwrap(), F);
    // A malformed v=op1 record is refused, not skipped.
    let broken = format!("v=op1; org={}", &fingerprint_base32(&F)[..51]);
    invalid_format(
        dns_fingerprint(&[&dns_txt_value(&F), &broken]),
        "malformed op1",
    );
}

#[test]
fn dns_records_disagree() {
    let a = dns_txt_value(&F);
    let b = dns_txt_value(&[0x42; 32]);
    integrity(
        dns_fingerprint(&[&a, &b]),
        IntegrityError::OrgPinMismatch,
        "two v=op1 records",
    );
    integrity(
        dns_fingerprint(&[&b, "v=spf1 -all", &a]),
        IntegrityError::OrgPinMismatch,
        "two v=op1 records, any order",
    );
    assert!(matches!(dns_fingerprint(&[]), Err(Error::NotFound)));
    assert!(matches!(
        dns_fingerprint(&["v=spf1 -all", "hello"]),
        Err(Error::NotFound)
    ));
}

#[test]
fn pin_mdm_and_dns_check_fingerprint() {
    let f = pin_fx();
    for source in [PinSource::Mdm, PinSource::Dns] {
        let pin = pin_org(source, Some(f.fpr), &f.g0).unwrap();
        assert_eq!(pin.source(), source);
        assert_eq!(pin.fingerprint(), f.fpr);
        integrity(
            pin_org(source, Some([0x42; 32]), &f.g0),
            IntegrityError::OrgPinMismatch,
            "expected differs",
        );
        integrity(
            pin_org(source, Some(f.fpr), &f.rogue),
            IntegrityError::OrgPinMismatch,
            "served genesis of another identity",
        );
        validation(pin_org(source, None, &f.g0), "no expected fingerprint");
    }
    // Not a genesis: never pinned.
    assert!(pin_org(PinSource::Mdm, Some(f.fpr), &f.g1).is_err());
    invalid_format(
        pin_org(PinSource::Mdm, Some(f.fpr), &[0; 10]),
        "garbage genesis",
    );
}

#[test]
fn pin_tofu_starts_unverified() {
    let f = pin_fx();
    let pin = pin_org(PinSource::Tofu { verified: false }, None, &f.g0).unwrap();
    assert_eq!(pin.source(), PinSource::Tofu { verified: false });
    assert_eq!(pin.fingerprint(), f.fpr);
    validation(
        pin_org(PinSource::Tofu { verified: true }, None, &f.g0),
        "verified at pin time",
    );
    validation(
        pin_org(PinSource::Tofu { verified: false }, Some(f.fpr), &f.g0),
        "tofu with an expected fingerprint",
    );
    validation(
        pin_org(PinSource::Tofu { verified: true }, Some(f.fpr), &f.g0),
        "verified tofu with an expected fingerprint",
    );
}

#[test]
fn confirm_tofu() {
    let f = pin_fx();
    let pin = pin_org(PinSource::Tofu { verified: false }, None, &f.g0).unwrap();
    let before = pin.clone();
    integrity(
        pin.confirm_tofu(&[0x42; 32]),
        IntegrityError::OrgPinMismatch,
        "wrong admin fingerprint",
    );
    assert_eq!(pin, before, "pin unchanged");
    let ok = pin.confirm_tofu(&f.fpr).unwrap();
    assert_eq!(ok.source(), PinSource::Tofu { verified: true });
    assert_eq!(ok.lineage(), pin.lineage());
    assert_eq!(ok.fingerprint(), pin.fingerprint());
    // Confirming again changes nothing; an MDM pin has nothing to confirm.
    assert_eq!(ok.confirm_tofu(&f.fpr).unwrap(), ok);
    validation(mdm_pin().confirm_tofu(&f.fpr), "mdm pin");
}

#[test]
fn fingerprint_change_never_followed() {
    let f = pin_fx();
    for pin in [
        mdm_pin(),
        pin_org(PinSource::Tofu { verified: false }, None, &f.g0).unwrap(),
    ] {
        pin.check_served_genesis(&f.g0).unwrap();
        integrity(
            pin.check_served_genesis(&f.rogue),
            IntegrityError::OrgPinMismatch,
            "check new identity",
        );
        integrity(
            pin.advance(&[(0, f.rogue.clone())], &[]),
            IntegrityError::OrgPinMismatch,
            "advance onto new identity",
        );
        integrity(
            pin.advance(&[(0, f.rogue.clone()), (1, f.g1.clone())], &rosters(&[1])),
            IntegrityError::OrgPinMismatch,
            "advance onto new identity with more records",
        );
        // Still the same after advancing for real.
        let moved = pin
            .advance(&lineage_list(&[0, 1]), &rosters(&[1, 2]))
            .unwrap();
        assert_eq!(moved.fingerprint(), f.fpr);
        assert_eq!(moved.source(), pin.source());
        integrity(
            moved.check_served_genesis(&f.rogue),
            IntegrityError::OrgPinMismatch,
            "check after advance",
        );
        moved.check_served_genesis(&f.g0).unwrap();
    }
}

#[test]
fn advance_lineage_then_roster() {
    let f = pin_fx();
    let pin = mdm_pin();
    let g1_hash = SignedOrgRecord::decode(&f.g1).unwrap().hash();
    let moved = pin
        .advance(&lineage_list(&[0, 1]), &rosters(&[1, 2]))
        .unwrap();
    assert_eq!(moved.head().generation, 1);
    assert_eq!(moved.head().hash, g1_hash);
    assert_eq!(moved.lineage().audit_kem_pub, kem_pool(2).1);
    assert_eq!(moved.roster_seq(), Some(2));
    assert_eq!(moved.roster().unwrap().org_head, g1_hash);
    // The old pin is untouched.
    assert_eq!(pin.head().generation, 0);
    assert_eq!(pin.roster(), None);
    // Next sync: the lineage from the pinned head, the roster from the
    // pinned seq (the pinned roster again changes nothing).
    let next = moved
        .advance(&lineage_list(&[1]), &rosters(&[2, 3]))
        .unwrap();
    assert_eq!(next.roster_seq(), Some(3));
    assert_eq!(next.head().generation, 1);
    // Older rosters that chain to the pinned one are ignored.
    let same = next
        .advance(&lineage_list(&[1]), &rosters(&[1, 2, 3]))
        .unwrap();
    assert_eq!(same, next);
    // An empty roster list keeps the roster.
    assert_eq!(moved.advance(&lineage_list(&[1]), &[]).unwrap(), moved);
    // A wrong key in the list is refused.
    invalid_format(
        moved.advance(&lineage_list(&[1]), &[(5, f.rosters[2].clone())]),
        "roster key mismatch",
    );
    invalid_format(
        pin.advance(&[(1, f.g0.clone())], &[]),
        "lineage key mismatch",
    );
    // A roster seq 2 of another body: fork.
    let other = {
        let mut b = SignedRoster::decode(&f.rosters[1]).unwrap().body;
        b.org_head = SignedOrgRecord::decode(&f.g0).unwrap().hash();
        sign_roster(b, &f.p.public, &f.p.keys).unwrap().encode()
    };
    integrity(
        next.advance(
            &lineage_list(&[1]),
            &[(2, other), (3, f.rosters[2].clone())],
        ),
        IntegrityError::OrgRosterFork,
        "forked older roster",
    );
}

#[test]
fn advance_requires_pinned_head() {
    let f = pin_fx();
    let pin = mdm_pin();
    integrity(
        pin.advance(&[], &[]),
        IntegrityError::OrgLineageRollback,
        "empty lineage list",
    );
    integrity(
        pin.advance(&lineage_list(&[1]), &[]),
        IntegrityError::OrgLineageRollback,
        "starting above the pinned generation",
    );
    let at1 = pin.advance(&lineage_list(&[0, 1]), &[]).unwrap();
    integrity(
        at1.advance(&lineage_list(&[0, 1]), &[]),
        IntegrityError::OrgLineageRollback,
        "starting below the pinned generation",
    );
    integrity(
        at1.advance(&[], &[]),
        IntegrityError::OrgLineageRollback,
        "empty lineage list at g1",
    );
    // The pinned head with another hash: a fork.
    let g1_other = {
        let secrets = org_secrets();
        let g0 = SignedOrgRecord::decode(&f.g0).unwrap();
        sign_org_change(
            OrgChangeBody {
                format: 1,
                org_id: ORG,
                generation: 1,
                parent: g0.hash(),
                kind: OrgChangeKind::AuditKeyRotated {
                    audit_kem_pub: kem_pool(1).1.clone(),
                },
                issued_at: 1_700_000_200,
            },
            &secrets.identity,
            &[(&f.p.public, &f.p.keys)],
        )
        .unwrap()
        .encode()
    };
    integrity(
        at1.advance(&[(1, g1_other)], &[]),
        IntegrityError::OrgLineageFork,
        "pinned generation, other hash",
    );
    // A record repeated after the head: a rollback.
    integrity(
        pin.advance(&lineage_list(&[0, 1, 1]), &[]),
        IntegrityError::OrgLineageRollback,
        "repeated record",
    );
}

#[test]
fn advance_replayed_roster() {
    let pin = mdm_pin()
        .advance(&lineage_list(&[0, 1]), &rosters(&[1, 2, 3]))
        .unwrap();
    assert_eq!(pin.roster_seq(), Some(3));
    integrity(
        pin.advance(&lineage_list(&[1]), &rosters(&[2])),
        IntegrityError::OrgRosterRollback,
        "only seq 2 offered",
    );
    integrity(
        pin.advance(&lineage_list(&[1]), &rosters(&[1, 2])),
        IntegrityError::OrgRosterRollback,
        "seq 1 and 2 offered",
    );
    // A replayed roster after a newer one in the list.
    let at2 = mdm_pin()
        .advance(&lineage_list(&[0, 1]), &rosters(&[1, 2]))
        .unwrap();
    integrity(
        at2.advance(
            &lineage_list(&[1]),
            &[
                (3, pin_fx().rosters[2].clone()),
                (2, pin_fx().rosters[1].clone()),
            ],
        ),
        IntegrityError::OrgRosterRollback,
        "out of order list",
    );
}

#[test]
fn pin_round_trips() {
    let pins = [
        mdm_pin(),
        pin_org(PinSource::Tofu { verified: false }, None, &pin_fx().g0).unwrap(),
        mdm_pin()
            .advance(&lineage_list(&[0, 1]), &rosters(&[1, 2]))
            .unwrap(),
    ];
    for pin in &pins {
        let b = pin.encode();
        assert_eq!(b[0], 1);
        assert_eq!(&OrgPin::decode(&b).unwrap(), pin);
        let mut v2 = b.clone();
        v2[0] = 2;
        assert!(matches!(
            OrgPin::decode(&v2),
            Err(Error::InvalidFormat("org pin version"))
        ));
        let mut trailing = b.clone();
        trailing.push(0);
        invalid_format(OrgPin::decode(&trailing), "trailing byte");
        invalid_format(OrgPin::decode(&b[..b.len() - 1]), "truncated");
    }
    invalid_format(OrgPin::decode(&[]), "empty");

    // Corrupted local state never panics and is refused.
    let pin = &pins[2];
    let state = |lineage: &OrgLineage, roster: Option<&RosterBody>| {
        let mut out = vec![1u8];
        out.extend(postcard::to_allocvec(&(pin.source(), lineage, roster)).unwrap());
        out
    };
    let good = state(pin.lineage(), pin.roster());
    assert_eq!(good, pin.encode());
    let mut no_heads = pin.lineage().clone();
    no_heads.heads.clear();
    invalid_format(OrgPin::decode(&state(&no_heads, None)), "no heads");
    let mut gap = pin.lineage().clone();
    gap.heads[1].generation = 2;
    invalid_format(OrgPin::decode(&state(&gap, None)), "generation gap");
    let mut no_genesis = pin.lineage().clone();
    no_genesis.heads.remove(0);
    invalid_format(OrgPin::decode(&state(&no_genesis, None)), "no genesis");
    let mut no_owner = pin.lineage().clone();
    no_owner.heads[1].owners.clear();
    invalid_format(OrgPin::decode(&state(&no_owner, None)), "no owner");
    let mut bad_name = pin.lineage().clone();
    bad_name.name = String::new();
    invalid_format(OrgPin::decode(&state(&bad_name, None)), "empty name");
    let mut zero_fpr = pin.lineage().clone();
    zero_fpr.fingerprint = [0; 32];
    invalid_format(OrgPin::decode(&state(&zero_fpr, None)), "zero fingerprint");
    let mut unknown_head = pin.roster().unwrap().clone();
    unknown_head.org_head = [9; 32];
    invalid_format(
        OrgPin::decode(&state(pin.lineage(), Some(&unknown_head))),
        "roster under an unknown head",
    );
    let mut other_org = pin.roster().unwrap().clone();
    other_org.org_id = OrgId([8; 16]);
    invalid_format(
        OrgPin::decode(&state(pin.lineage(), Some(&other_org))),
        "roster of another org",
    );
    let mut bad_roster = pin.roster().unwrap().clone();
    bad_roster.seq = 0;
    invalid_format(
        OrgPin::decode(&state(pin.lineage(), Some(&bad_roster))),
        "roster shape",
    );
    // An unknown source variant.
    let mut bad_source = good.clone();
    bad_source[1] = 9;
    invalid_format(OrgPin::decode(&bad_source), "unknown source");
}

#[test]
fn pin_accessors() {
    let f = pin_fx();
    let pin = mdm_pin();
    assert_eq!(pin.fingerprint(), f.fpr);
    assert_eq!(pin.source(), PinSource::Mdm);
    assert_eq!(pin.head().generation, 0);
    assert_eq!(pin.lineage().org_id, ORG);
    assert_eq!(pin.lineage().fingerprint, f.fpr);
    assert_eq!(pin.roster_seq(), None);
    assert_eq!(pin.roster(), None);
    let moved = pin
        .advance(&lineage_list(&[0, 1]), &rosters(&[1, 2]))
        .unwrap();
    assert_eq!(moved.roster_seq(), Some(2));
    assert_eq!(moved.head().generation, 1);
    assert_eq!(moved.fingerprint(), f.fpr);
    assert_eq!(moved.source(), PinSource::Mdm);
}
