//! Invitation and join request (Business E1, plan B Task 9): an invited
//! member joins with a managed genesis (format 2) bound to the invitation's
//! org and account, signed by the genesis creator device; the admin
//! verifies it against the pinned roster and org fingerprint, then
//! activates the member.

mod org_common;

use std::sync::OnceLock;

use onepass_core::crypto::{HybridKemPublic, IdentityVerifyingKey, KdfParams, random_array};
use onepass_core::device_keys::{DeviceKeys, DevicePublic};
use onepass_core::devices::{DeviceKind, DeviceMode};
use onepass_core::generator::Wordlist;
use onepass_core::lineage::{
    GenesisBody, LineageRecord, RotationBody, RotationReason, Signed, verify_genesis,
};
use onepass_core::org::{
    Invitation, JoinRequestBody, MAX_ORG_RECORD_BYTES, MemberState, ORG_JOIN_CODE_PREFIX,
    ORG_JOIN_DOMAIN, OrgGenesisBody, OrgId, OrgLineage, OrgMember, Role, RoleSet, RosterBody,
    SignedJoinRequest, accept_next_roster, activate_member, fingerprint_words, founding_roster,
    invite_commit, invite_member, join_code, join_code_of, member_kem_hash, org_fingerprint,
    scim_id_hash, sign_join_request, sign_org_genesis, sign_roster, verify_join_request,
    verify_org_genesis,
};
use onepass_core::repo::{ManagedGenesis, Repository};
use onepass_core::store::{RecordKind, RecordStore, SqliteStore};
use onepass_core::{Error, Id, IntegrityError};
use org_common::*;

const ORG: OrgId = OrgId([7; 16]);
const O: u8 = 1;
const U: u8 = 3;
const PASSWORD: &str = "Projet Atlas, Camille Durand";

/// A managed (or personal) account as the join request needs it: the
/// creator device's keys and public half, the genesis record bytes, the
/// account KEM key and identity.
struct Joiner {
    keys: DeviceKeys,
    device: DevicePublic,
    genesis: Vec<u8>,
    kem: HybridKemPublic,
    identity: IdentityVerifyingKey,
}

fn create(org: Option<ManagedGenesis>) -> Joiner {
    let dir = tempfile::tempdir().unwrap();
    let store = SqliteStore::open(&dir.path().join("vault.db")).unwrap();
    let keys = DeviceKeys::generate_software().unwrap();
    let kdf = KdfParams {
        m_kib: 8192,
        t: 1,
        p: 1,
        salt: random_array().unwrap(),
    };
    let (repo, _sk) = Repository::create_account_v2_with_org(
        store,
        PASSWORD,
        kdf,
        &keys,
        "iPhone de Camille",
        DeviceKind::Phone,
        DeviceMode::Personal,
        org,
    )
    .unwrap();
    let lineage = repo.store().list(RecordKind::Lineage).unwrap();
    assert_eq!(lineage.len(), 1);
    let genesis = lineage[0].data.clone();
    let LineageRecord::Genesis(g) = LineageRecord::decode(&genesis).unwrap() else {
        panic!("a genesis")
    };
    verify_genesis(&g).unwrap();
    let c = &g.body.creator;
    let device = DevicePublic {
        device_id: c.device_id,
        sign_pub: c.sign_pub.clone(),
        kem_pub: c.kem_pub.clone(),
    };
    assert_eq!(keys.public(c.device_id).unwrap(), device);
    Joiner {
        keys,
        device,
        genesis,
        kem: repo.account().params.kem_pub.clone(),
        identity: g.body.identity_pub.clone(),
    }
}

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
        let org_fpr = org_fingerprint(&secrets.public(ORG).unwrap());
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
