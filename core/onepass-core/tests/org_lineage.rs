//! Org identity, fingerprint and fingerprint words, and the org lineage
//! with its owner quorum (Business E1).
//!
//! The words vector in `tests/vectors/org/words.hex` was written once by
//! `generate_org_vectors` (ignored) and is frozen: the tests read it back.

mod org_common;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::OnceLock;

use data_encoding::HEXLOWER;
use onepass_core::crypto::{IdentityKey, IdentitySignature};
use onepass_core::device_keys::{DeviceKeys, DevicePublic};
use onepass_core::generator::Wordlist;
use onepass_core::org::{
    MAX_ORG_RECORD_BYTES, MemberRef, ORG_CHANGE_DOMAIN, ORG_GENESIS_DOMAIN, OrgChangeBody,
    OrgChangeKind, OrgGenesisBody, OrgId, OrgKeyset, OrgLineage, OrgRecordBody, RosterCheckpoint,
    SealedOrgKeyset, SignedOrgRecord, add_owner_signature, fingerprint_words, open_org_keyset,
    org_fingerprint, quorum, seal_org_keyset, sign_org_change, sign_org_genesis, verify_org_chain,
    verify_org_genesis,
};
use onepass_core::{Error, Id, IntegrityError};
use org_common::*;
use sha3::Shake256;
use sha3::digest::{ExtendableOutput, Update, XofReader};

const EFF_TEXT: &str = include_str!("../data/eff_large_wordlist.txt");

/// The word derivation, written from the plan independently of the crate:
/// SHAKE256("onepass/org-words/v1" || fpr), 2-byte big-endian draws, a draw
/// below 62208 picks word `v % 7776`, others are skipped, 20 words in 4
/// groups of 5. Also returns how many draws were rejected.
fn reference_words_counted(fpr: &[u8; 32]) -> ([[String; 5]; 4], usize) {
    let words: Vec<&str> = EFF_TEXT.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(words.len(), 7776);
    let mut xof = Shake256::default();
    xof.update(b"onepass/org-words/v1");
    xof.update(fpr);
    let mut reader = xof.finalize_xof();
    let mut out: Vec<String> = Vec::new();
    let mut rejected = 0;
    while out.len() < 20 {
        let mut b = [0u8; 2];
        reader.read(&mut b);
        let v = u32::from(u16::from_be_bytes(b));
        if v < 62208 {
            out.push(words[(v % 7776) as usize].to_string());
        } else {
            rejected += 1;
        }
    }
    let groups: [[String; 5]; 4] =
        std::array::from_fn(|g| std::array::from_fn(|i| out[g * 5 + i].clone()));
    (groups, rejected)
}

fn reference_words(fpr: &[u8; 32]) -> [[String; 5]; 4] {
    reference_words_counted(fpr).0
}

fn vectors_dir() -> PathBuf {
    std::env::var_os("ONEPASS_CORE_VECTORS")
        .map_or_else(
            || PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors"),
            PathBuf::from,
        )
        .join("org")
}

fn read_vector(name: &str) -> BTreeMap<String, String> {
    let text = std::fs::read_to_string(vectors_dir().join(name)).unwrap();
    text.lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| {
            let (k, v) = l.split_once('=').unwrap();
            (k.to_string(), v.to_string())
        })
        .collect()
}

fn ascending_fpr() -> [u8; 32] {
    std::array::from_fn(|i| i as u8)
}

fn joined(words: &[[String; 5]; 4]) -> String {
    words
        .iter()
        .flatten()
        .cloned()
        .collect::<Vec<_>>()
        .join(" ")
}

#[test]
fn fingerprint_is_prefixed_genesis_hash() {
    let w = world();
    let OrgRecordBody::Genesis(g) = &w.genesis.body else {
        panic!("genesis expected")
    };
    let genesis_hash = sha256(&[
        b"onepass/org-genesis/v1",
        &postcard::to_allocvec(g).unwrap(),
    ]);
    assert_eq!(genesis_hash, w.genesis.hash());
    assert_eq!(
        org_fingerprint(g),
        sha256(&[b"onepass/org-fingerprint/v1", &genesis_hash])
    );
    // X16: every genesis field counts, the owners included.
    let mut variants = Vec::new();
    let mut v = g.clone();
    v.org_id = OrgId([2; 16]);
    variants.push(v);
    let mut v = g.clone();
    v.name = "Acme bis".to_string();
    variants.push(v);
    let mut v = g.clone();
    v.owners[0].devices.push([0xEE; 32]);
    variants.push(v);
    let mut v = g.clone();
    v.created_at += 1;
    variants.push(v);
    for v in &variants {
        assert_ne!(org_fingerprint(v), org_fingerprint(g));
    }
}

#[test]
fn public_carries_the_secret_halves() {
    let s = org_secrets();
    let p = s.public(OrgId([3; 16])).unwrap();
    assert_eq!(p.org_id, OrgId([3; 16]));
    assert_eq!(p.identity_pub, s.identity.verifying_key());
    assert_eq!(p.audit_kem_pub, s.audit.public().unwrap());
}

#[test]
fn words_follow_the_reference_algorithm() {
    for seed in 0u8..32 {
        let fpr = [seed; 32];
        assert_eq!(
            fingerprint_words(&fpr, Wordlist::EffEnglish),
            reference_words(&fpr)
        );
    }
}

#[test]
fn words_work_on_the_french_list() {
    let w = fingerprint_words(&ascending_fpr(), Wordlist::FrenchDiceware);
    assert_eq!(w.iter().flatten().count(), 20);
    assert_ne!(
        joined(&w),
        joined(&fingerprint_words(&ascending_fpr(), Wordlist::EffEnglish))
    );
}

#[test]
fn words_frozen_vector() {
    let v = read_vector("words.hex");
    let fpr = ascending_fpr();
    assert_eq!(v["fpr"], HEXLOWER.encode(&fpr));
    let words = fingerprint_words(&fpr, Wordlist::EffEnglish);
    assert_eq!(joined(&words), v["words"]);
    assert_eq!(v["words"].split(' ').count(), 20);
}

#[test]
fn words_reject_high_draws() {
    let seed = (0u8..=255)
        .find(|s| reference_words_counted(&[*s; 32]).1 > 0)
        .expect("a seed whose stream has a draw >= 62208");
    let fpr = [seed; 32];
    assert_eq!(
        fingerprint_words(&fpr, Wordlist::EffEnglish),
        reference_words(&fpr)
    );
}

/// Run once to (re)create the frozen file: `cargo test -p onepass-core
/// --features dev-fast-kdf --test org_lineage -- --ignored
/// generate_org_vectors`. The file is committed; the tests only read it.
#[test]
#[ignore]
fn generate_org_vectors() {
    let fpr = ascending_fpr();
    let words = fingerprint_words(&fpr, Wordlist::EffEnglish);
    let s = format!(
        "# frozen org words vector, do not regenerate\nfpr={}\nwords={}\n",
        HEXLOWER.encode(&fpr),
        joined(&words)
    );
    std::fs::create_dir_all(vectors_dir()).unwrap();
    std::fs::write(vectors_dir().join("words.hex"), s).unwrap();
}

// ---------------------------------------------------------------------
// Org lineage and owner quorum (Task 4).
// ---------------------------------------------------------------------

const ORG: OrgId = OrgId([7; 16]);

/// Owners A (two devices), B, C; D and an outsider device for the tests
/// that bring in someone else. The genesis and two audit key rotations
/// are signed once per binary (SLH-DSA signing is slow).
struct World {
    a1: TestDevice,
    a2: TestDevice,
    b: TestDevice,
    c: TestDevice,
    d: TestDevice,
    outsider: TestDevice,
    owners: Vec<MemberRef>,
    genesis: SignedOrgRecord,
    g1: SignedOrgRecord,
    g2: SignedOrgRecord,
}

fn identity() -> &'static IdentityKey {
    &org_secrets().identity
}

fn signers<'a>(ds: &[&'a TestDevice]) -> Vec<(&'a DevicePublic, &'a DeviceKeys)> {
    ds.iter().map(|d| (&d.public, &d.keys)).collect()
}

fn genesis_body(owners: Vec<MemberRef>) -> OrgGenesisBody {
    OrgGenesisBody {
        format: 1,
        org_id: ORG,
        name: "Acme".to_string(),
        org_identity_pub: identity().verifying_key(),
        audit_kem_pub: org_secrets().audit.public().unwrap(),
        owners,
        created_at: 1_700_000_000,
    }
}

fn change_body(generation: u64, parent: [u8; 32], kind: OrgChangeKind) -> OrgChangeBody {
    OrgChangeBody {
        format: 1,
        org_id: ORG,
        generation,
        parent,
        kind,
        issued_at: 1_700_000_000 + generation as i64,
    }
}

fn rotate_to(i: usize) -> OrgChangeKind {
    OrgChangeKind::AuditKeyRotated {
        audit_kem_pub: kem_pool(i).1.clone(),
    }
}

fn world() -> &'static World {
    static CELL: OnceLock<World> = OnceLock::new();
    CELL.get_or_init(|| {
        let (a1, a2, b, c, d, outsider) = (
            device(1),
            device(2),
            device(3),
            device(4),
            device(5),
            device(6),
        );
        let owners = vec![
            member_ref(1, &[&a1, &a2]),
            member_ref(2, &[&b]),
            member_ref(3, &[&c]),
        ];
        let genesis = sign_org_genesis(
            genesis_body(owners.clone()),
            identity(),
            &signers(&[&a1, &b]),
        )
        .unwrap();
        let g1 = sign_org_change(
            change_body(1, genesis.hash(), rotate_to(1)),
            identity(),
            &signers(&[&a1, &b]),
        )
        .unwrap();
        let g2 = sign_org_change(
            change_body(2, g1.hash(), rotate_to(2)),
            identity(),
            &signers(&[&b, &c]),
        )
        .unwrap();
        World {
            a1,
            a2,
            b,
            c,
            d,
            outsider,
            owners,
            genesis,
            g1,
            g2,
        }
    })
}

/// The lineage verified up to generation `n` (0, 1 or 2).
fn lineage_at(n: usize) -> OrgLineage {
    let w = world();
    let chain = [w.genesis.clone(), w.g1.clone(), w.g2.clone()];
    verify_org_chain(&chain[..=n]).unwrap()
}

fn integrity(r: Result<OrgLineage, Error>) -> IntegrityError {
    match r {
        Err(Error::Integrity(e)) => e,
        other => panic!("expected an integrity error, got {other:?}"),
    }
}

/// A change after the genesis replacing the owners by `owners`.
fn owners_change(owners: Vec<MemberRef>) -> OrgChangeBody {
    change_body(
        1,
        world().genesis.hash(),
        OrgChangeKind::OwnersChanged {
            owners,
            roster_checkpoint: RosterCheckpoint::NONE,
        },
    )
}

#[test]
fn quorum_counts() {
    assert_eq!(
        (quorum(1), quorum(2), quorum(3), quorum(4), quorum(8)),
        (1, 2, 2, 3, 5)
    );
}

#[test]
fn genesis_signed_by_identity_and_owner_verifies() {
    let w = world();
    let l = verify_org_genesis(&w.genesis).unwrap();
    assert_eq!(l.org_id, ORG);
    assert_eq!(l.name, "Acme");
    assert_eq!(
        l.fingerprint,
        sha256(&[b"onepass/org-fingerprint/v1", &w.genesis.hash()])
    );
    assert_eq!(l.identity_pub, identity().verifying_key());
    assert_eq!(l.audit_kem_pub, org_secrets().audit.public().unwrap());
    assert_eq!(l.heads.len(), 1);
    assert_eq!(l.head().generation, 0);
    assert_eq!(l.head().hash, w.genesis.hash());
    assert_eq!(l.head().owners, w.owners);
    assert_eq!(l.find(&w.genesis.hash()), Some(l.head()));
}

#[test]
fn genesis_below_quorum_refused() {
    let w = world();
    let g = sign_org_genesis(
        genesis_body(w.owners.clone()),
        identity(),
        &signers(&[&w.c]),
    )
    .unwrap();
    assert_eq!(integrity(verify_org_genesis(&g)), IntegrityError::OrgQuorum);
}

#[test]
fn change_needs_identity_signature() {
    let w = world();
    let rec = sign_org_change(
        change_body(1, w.genesis.hash(), rotate_to(1)),
        &identity_pool(0).0,
        &signers(&[&w.a1, &w.b]),
    )
    .unwrap();
    assert_eq!(
        integrity(lineage_at(0).apply(&rec)),
        IntegrityError::Signature
    );
}

#[test]
fn change_below_quorum_refused() {
    let w = world();
    let rec = sign_org_change(
        change_body(1, w.genesis.hash(), rotate_to(1)),
        identity(),
        &signers(&[&w.c]),
    )
    .unwrap();
    assert_eq!(
        integrity(lineage_at(0).apply(&rec)),
        IntegrityError::OrgQuorum
    );
}

#[test]
fn change_at_quorum_accepted() {
    let w = world();
    let new_owners = vec![
        member_ref(1, &[&w.a1, &w.a2]),
        member_ref(2, &[&w.b]),
        member_ref(4, &[&w.d]),
    ];
    // A signs, then B co-signs on its own device.
    let mut rec = sign_org_change(
        owners_change(new_owners.clone()),
        identity(),
        &signers(&[&w.a2]),
    )
    .unwrap();
    add_owner_signature(&mut rec, &w.b.public, &w.b.keys).unwrap();
    let l = lineage_at(0).apply(&rec).unwrap();
    assert_eq!(l.head().generation, 1);
    assert_eq!(l.head().hash, rec.hash());
    assert_eq!(l.head().owners, new_owners);
    assert_eq!(l.heads.len(), 2);
}

#[test]
fn two_devices_of_one_owner_count_once() {
    let w = world();
    let rec = sign_org_change(
        change_body(1, w.genesis.hash(), rotate_to(1)),
        identity(),
        &signers(&[&w.a1, &w.a2]),
    )
    .unwrap();
    assert_eq!(rec.owner_sigs.len(), 2);
    assert_eq!(
        integrity(lineage_at(0).apply(&rec)),
        IntegrityError::OrgQuorum
    );
}

#[test]
fn unknown_signer_device_refused() {
    let w = world();
    // A and B meet the quorum; the outsider's signature still sinks it.
    let rec = sign_org_change(
        change_body(1, w.genesis.hash(), rotate_to(1)),
        identity(),
        &signers(&[&w.a1, &w.b, &w.outsider]),
    )
    .unwrap();
    assert_eq!(
        integrity(lineage_at(0).apply(&rec)),
        IntegrityError::OrgQuorum
    );
}

#[test]
fn bad_owner_signature_refused() {
    let w = world();
    let mut rec = sign_org_change(
        change_body(1, w.genesis.hash(), rotate_to(1)),
        identity(),
        &signers(&[&w.a1, &w.b, &w.c]),
    )
    .unwrap();
    // C's signature over another body: A and B alone would meet the quorum.
    let other = w.c.keys.sign(ORG_CHANGE_DOMAIN, b"another body").unwrap();
    let c_fpr = w.c.public.fingerprint();
    let slot = rec
        .owner_sigs
        .iter_mut()
        .find(|(p, _)| p.fingerprint() == c_fpr)
        .unwrap();
    slot.1 = other;
    assert_eq!(
        integrity(lineage_at(0).apply(&rec)),
        IntegrityError::Signature
    );
}

#[test]
fn quorum_uses_parent_owners() {
    let w = world();
    let body = owners_change(vec![member_ref(4, &[&w.d])]);
    // D is an owner of g1 only: it cannot approve its own promotion.
    let by_d = sign_org_change(body.clone(), identity(), &signers(&[&w.d])).unwrap();
    assert_eq!(
        integrity(lineage_at(0).apply(&by_d)),
        IntegrityError::OrgQuorum
    );
    let by_ab = sign_org_change(body, identity(), &signers(&[&w.a1, &w.b])).unwrap();
    let l = lineage_at(0).apply(&by_ab).unwrap();
    // From now on D alone is the whole owner set (quorum(1) == 1).
    let g2 = sign_org_change(
        change_body(2, by_ab.hash(), rotate_to(2)),
        identity(),
        &signers(&[&w.d]),
    )
    .unwrap();
    let l = l.apply(&g2).unwrap();
    assert_eq!(l.head().generation, 2);
    assert_eq!(l.head().owners, vec![member_ref(4, &[&w.d])]);
    // The old owners no longer count.
    let g3 = sign_org_change(
        change_body(3, g2.hash(), rotate_to(0)),
        identity(),
        &signers(&[&w.a1, &w.b]),
    )
    .unwrap();
    assert_eq!(integrity(l.apply(&g3)), IntegrityError::OrgQuorum);
}

#[test]
fn same_generation_other_record_is_fork() {
    let w = world();
    let other_g1 = sign_org_change(
        change_body(1, w.genesis.hash(), rotate_to(2)),
        identity(),
        &signers(&[&w.a1, &w.b]),
    )
    .unwrap();
    assert_ne!(other_g1.hash(), w.g1.hash());
    let l = lineage_at(1);
    assert_eq!(
        integrity(l.apply(&other_g1)),
        IntegrityError::OrgLineageFork
    );
    // The very same head again changes nothing.
    assert_eq!(l.apply(&w.g1).unwrap(), l);
    // Another body at generation 1 without the identity signature: a
    // signature error, not a fork alarm (minor 3).
    let mut unsigned = w.g1.clone();
    let OrgRecordBody::Change(c) = &mut unsigned.body else {
        unreachable!()
    };
    c.issued_at += 1;
    assert_eq!(integrity(l.apply(&unsigned)), IntegrityError::Signature);
}

#[test]
fn older_generation_is_rollback() {
    let w = world();
    assert_eq!(
        integrity(lineage_at(2).apply(&w.g1)),
        IntegrityError::OrgLineageRollback
    );
    assert_eq!(
        integrity(lineage_at(2).apply(&w.genesis)),
        IntegrityError::OrgLineageRollback
    );
}

#[test]
fn wrong_parent_is_fork() {
    let w = world();
    let mut rec = w.g2.clone();
    let OrgRecordBody::Change(c) = &mut rec.body else {
        unreachable!()
    };
    c.parent = [9; 32];
    // Not signed by the org identity: no fork evidence (minor 3).
    assert_eq!(
        integrity(lineage_at(1).apply(&rec)),
        IntegrityError::Signature
    );
    // Signed by the identity: a fork.
    let signed = sign_org_change(
        change_body(2, [9; 32], rotate_to(2)),
        identity(),
        &signers(&[&w.b, &w.c]),
    )
    .unwrap();
    assert_eq!(
        integrity(lineage_at(1).apply(&signed)),
        IntegrityError::OrgLineageFork
    );
}

#[test]
fn generation_gap_asks_for_more() {
    let w = world();
    let mut rec = w.g2.clone();
    let OrgRecordBody::Change(c) = &mut rec.body else {
        unreachable!()
    };
    c.generation = 3;
    assert!(matches!(lineage_at(1).apply(&rec), Err(Error::NotFound)));
}

#[test]
fn other_org_is_wrong_context() {
    let w = world();
    let rec = sign_org_change(
        OrgChangeBody {
            org_id: OrgId([8; 16]),
            ..change_body(1, w.genesis.hash(), rotate_to(1))
        },
        identity(),
        &signers(&[&w.a1, &w.b]),
    )
    .unwrap();
    assert_eq!(
        integrity(lineage_at(0).apply(&rec)),
        IntegrityError::WrongContext
    );
}

#[test]
fn audit_key_rotation_updates_head() {
    let w = world();
    let l0 = lineage_at(0);
    let l1 = lineage_at(1);
    assert_eq!(l0.audit_kem_pub, org_secrets().audit.public().unwrap());
    assert_eq!(l1.audit_kem_pub, kem_pool(1).1);
    assert_eq!(l1.fingerprint, l0.fingerprint);
    assert_eq!(l1.head().owners, w.owners);
    assert_eq!(l1.head().generation, 1);
    assert_eq!(l1.head().hash, w.g1.hash());
    let l2 = lineage_at(2);
    assert_eq!(l2.audit_kem_pub, kem_pool(2).1);
    assert_eq!(l2.heads.len(), 3);
    assert_eq!(l2.find(&w.g1.hash()), Some(&l1.heads[1]));
    assert_eq!(l2.identity_pub, identity().verifying_key());
}

#[test]
fn chain_must_start_with_a_genesis() {
    let w = world();
    assert!(matches!(verify_org_chain(&[]), Err(Error::NotFound)));
    assert!(matches!(
        verify_org_chain(std::slice::from_ref(&w.g1)),
        Err(Error::InvalidFormat("org genesis expected"))
    ));
    assert_eq!(
        integrity(verify_org_chain(&[
            w.genesis.clone(),
            w.g1.clone(),
            w.g1.clone()
        ])),
        IntegrityError::OrgLineageRollback
    );
}

fn refused(b: &[u8]) -> bool {
    matches!(SignedOrgRecord::decode(b), Err(Error::InvalidFormat(_)))
}

fn genesis_with(f: impl FnOnce(&mut OrgGenesisBody)) -> Vec<u8> {
    let mut rec = world().genesis.clone();
    let OrgRecordBody::Genesis(g) = &mut rec.body else {
        unreachable!()
    };
    f(g);
    rec.encode()
}

fn change_with(f: impl FnOnce(&mut OrgChangeBody)) -> Vec<u8> {
    let mut rec = world().g1.clone();
    let OrgRecordBody::Change(c) = &mut rec.body else {
        unreachable!()
    };
    f(c);
    rec.encode()
}

fn sigs_with(
    f: impl FnOnce(&mut Vec<(DevicePublic, onepass_core::crypto::HybridSignature)>),
) -> Vec<u8> {
    let mut rec = world().genesis.clone();
    f(&mut rec.owner_sigs);
    rec.encode()
}

#[test]
fn decode_is_strict() {
    let w = world();
    // The unmodified records decode.
    assert!(SignedOrgRecord::decode(&w.genesis.encode()).is_ok());
    assert!(SignedOrgRecord::decode(&w.g1.encode()).is_ok());
    assert!(SignedOrgRecord::decode(&genesis_with(|g| g.name = "a".repeat(128))).is_ok());

    let mut trailing = w.genesis.encode();
    trailing.push(0);
    assert!(refused(&trailing), "trailing byte");

    assert!(refused(&sigs_with(|s| s.reverse())), "unsorted owner_sigs");
    assert!(
        refused(&sigs_with(|s| s[1] = s[0].clone())),
        "duplicate sig device"
    );
    assert!(refused(&sigs_with(|s| s.clear())), "no owner signature");
    assert!(
        refused(&sigs_with(|s| {
            s[0].0.sign_pub.mldsa.pop();
        })),
        "bad signer key length"
    );
    assert!(
        refused(&sigs_with(|s| {
            s[0].1.mldsa.pop();
        })),
        "bad signature length"
    );
    assert!(
        refused(
            &genesis_with(|_| ())
                .iter()
                .copied()
                .take(10)
                .collect::<Vec<_>>()
        ),
        "truncated"
    );

    assert!(refused(&genesis_with(|g| g.owners.clear())), "0 owners");
    let nine: Vec<TestDevice> = (10..19).map(device).collect();
    let nine_owners: Vec<MemberRef> = nine
        .iter()
        .enumerate()
        .map(|(i, d)| member_ref(i as u8 + 1, &[d]))
        .collect();
    assert!(
        SignedOrgRecord::decode(&genesis_with(|g| g.owners = nine_owners[..8].to_vec())).is_ok(),
        "8 owners are fine"
    );
    assert!(
        refused(&genesis_with(|g| g.owners = nine_owners.clone())),
        "9 owners"
    );
    assert!(
        refused(&genesis_with(|g| g.owners.swap(0, 1))),
        "owners unsorted"
    );
    assert!(
        refused(&genesis_with(
            |g| g.owners[1].account_id = g.owners[0].account_id
        )),
        "owner repeated"
    );
    assert!(
        refused(&genesis_with(
            |g| g.owners[2].devices = g.owners[1].devices.clone()
        )),
        "fingerprint repeated across owners"
    );
    assert!(
        refused(&genesis_with(|g| g.owners[0].devices.reverse())),
        "member devices unsorted"
    );
    assert!(
        refused(&genesis_with(|g| g.owners[1].devices.clear())),
        "member without device"
    );
    let eight: Vec<[u8; 32]> = (1u8..=8).map(|i| [i; 32]).collect();
    assert!(
        SignedOrgRecord::decode(&genesis_with(|g| g.owners[0].devices = eight.clone())).is_ok(),
        "8 devices are fine"
    );
    let nine_fprs: Vec<[u8; 32]> = (1u8..=9).map(|i| [i; 32]).collect();
    assert!(
        refused(&genesis_with(|g| g.owners[0].devices = nine_fprs)),
        "9 devices"
    );
    assert!(
        refused(&genesis_with(
            |g| g.owners[0].account_identity_pub = identity_with_len(31)
        )),
        "member identity key length"
    );

    assert!(
        refused(&genesis_with(|g| g.name = "a".repeat(129))),
        "name of 129 chars"
    );
    assert!(
        refused(&genesis_with(|g| g.name = String::new())),
        "empty name"
    );
    assert!(
        refused(&genesis_with(|g| g.name = "Ac\nme".into())),
        "control char in name"
    );
    assert!(refused(&genesis_with(|g| g.format = 2)), "genesis format 2");
    assert!(
        refused(&genesis_with(|g| g.org_identity_pub = identity_with_len(63))),
        "org identity key length"
    );

    assert!(refused(&change_with(|c| c.format = 2)), "change format 2");
    assert!(
        refused(&change_with(|c| c.generation = 0)),
        "generation 0 in a Change"
    );
    assert!(
        refused(&change_with(|c| c.kind = OrgChangeKind::OwnersChanged {
            owners: vec![],
            roster_checkpoint: RosterCheckpoint::NONE,
        })),
        "OwnersChanged empty"
    );
    let owners = w.owners.clone();
    let with_checkpoint = |seq: u64, hash: [u8; 32]| {
        let owners = owners.clone();
        change_with(move |c| {
            c.kind = OrgChangeKind::OwnersChanged {
                owners,
                roster_checkpoint: RosterCheckpoint { seq, hash },
            }
        })
    };
    // X17: a zero hash only with seq 0, and seq 0 only with a zero hash.
    assert!(
        refused(&with_checkpoint(5, [0; 32])),
        "checkpoint seq 5, zero hash"
    );
    assert!(
        refused(&with_checkpoint(0, [1; 32])),
        "checkpoint seq 0, non-zero hash"
    );
    assert!(!refused(&with_checkpoint(0, [0; 32])), "no roster yet");
    assert!(!refused(&with_checkpoint(5, [1; 32])), "checkpoint (5, h)");

    let mut bad_id_sig = w.g1.clone();
    bad_id_sig.identity_sig = postcard::from_bytes::<IdentitySignature>(&[1, 0]).unwrap();
    assert!(refused(&bad_id_sig.encode()), "identity signature length");

    assert!(
        refused(&vec![0u8; MAX_ORG_RECORD_BYTES + 1]),
        "over MAX_ORG_RECORD_BYTES"
    );
}

/// An identity verifying key of `len` bytes (decode refuses it).
fn identity_with_len(len: usize) -> onepass_core::crypto::IdentityVerifyingKey {
    let enc = postcard::to_allocvec(&serde_bytes::ByteBuf::from(vec![1u8; len])).unwrap();
    postcard::from_bytes(&enc).unwrap()
}

#[test]
fn record_round_trips() {
    let w = world();
    for (rec, domain) in [
        (&w.genesis, ORG_GENESIS_DOMAIN),
        (&w.g1, ORG_CHANGE_DOMAIN),
        (&w.g2, ORG_CHANGE_DOMAIN),
    ] {
        let back = SignedOrgRecord::decode(&rec.encode()).unwrap();
        assert_eq!(&back, rec);
        assert_eq!(back.hash(), rec.hash());
        let body = match &rec.body {
            OrgRecordBody::Genesis(g) => postcard::to_allocvec(g).unwrap(),
            OrgRecordBody::Change(c) => postcard::to_allocvec(c).unwrap(),
        };
        assert_eq!(rec.hash(), sha256(&[domain, &body]));
        assert_eq!(rec.org_id(), ORG);
    }
    assert_eq!(w.genesis.generation(), 0);
    assert_eq!(w.g2.generation(), 2);
    // owner_sigs are sorted by device fingerprint.
    let fprs: Vec<[u8; 32]> = w
        .genesis
        .owner_sigs
        .iter()
        .map(|(p, _)| p.fingerprint())
        .collect();
    assert!(fprs.windows(2).all(|p| p[0] < p[1]));
}

fn keyset() -> OrgKeyset {
    // Same keys as org_secrets(), rebuilt from bytes (OrgSecrets is not Clone).
    let s = org_secrets();
    OrgKeyset {
        org_id: ORG,
        secrets: onepass_core::org::OrgSecrets {
            identity: IdentityKey::from_bytes(&s.identity.to_bytes()).unwrap(),
            audit: onepass_core::crypto::HybridKemSecret::from_bytes(&s.audit.to_bytes()).unwrap(),
        },
    }
}

fn sealed_for(account: u8) -> SealedOrgKeyset {
    let i = usize::from(account % 3);
    seal_org_keyset(&keyset(), Id([account; 16]), &kem_pool(i).1).unwrap()
}

#[test]
fn keyset_seals_to_one_owner() {
    let sealed = sealed_for(1);
    let back = SealedOrgKeyset::decode(&sealed.encode()).unwrap();
    assert_eq!(back, sealed);
    let opened = open_org_keyset(&back, ORG, Id([1; 16]), &kem_pool(1).0).unwrap();
    assert_eq!(opened.org_id, ORG);
    assert_eq!(
        opened.secrets.public(ORG).unwrap(),
        org_secrets().public(ORG).unwrap()
    );
    opened.check_against(&lineage_at(0)).unwrap();
    assert!(!format!("{opened:?}").contains("identity"));
}

/// The integrity error of a refused keyset.
fn keyset_refused<T: std::fmt::Debug>(
    r: onepass_core::Result<T>,
    want: IntegrityError,
    what: &str,
) {
    match r {
        Err(Error::Integrity(e)) if e == want => {}
        other => panic!("{what}: expected Integrity({want:?}), got {other:?}"),
    }
}

#[test]
fn keyset_bound_to_owner_and_org() {
    let sealed = sealed_for(1);
    let k = &kem_pool(1).0;
    use IntegrityError::{Commitment, WrongContext};
    keyset_refused(
        open_org_keyset(&sealed, ORG, Id([2; 16]), k),
        WrongContext,
        "other owner account",
    );
    keyset_refused(
        open_org_keyset(&sealed, OrgId([0xee; 16]), Id([1; 16]), k),
        WrongContext,
        "other org",
    );
    keyset_refused(
        open_org_keyset(&sealed, ORG, Id([1; 16]), &kem_pool(2).0),
        Commitment,
        "other KEM secret",
    );
    // Relabelled record fields do not rescue a swapped context either: the
    // KEM context and the AEAD data still name the sealing owner and org.
    let mut relabelled = sealed.clone();
    relabelled.account_id = Id([2; 16]);
    keyset_refused(
        open_org_keyset(&relabelled, ORG, Id([2; 16]), k),
        Commitment,
        "relabelled account",
    );
    let mut other_org = sealed.clone();
    other_org.org_id = OrgId([0xee; 16]);
    keyset_refused(
        open_org_keyset(&other_org, OrgId([0xee; 16]), Id([1; 16]), k),
        Commitment,
        "relabelled org",
    );
}

#[test]
fn keyset_blob_swap_refused() {
    let a = sealed_for(1);
    let b = sealed_for(2);
    let mut franken = a.clone();
    franken.blob = b.blob.clone();
    keyset_refused(
        open_org_keyset(&franken, ORG, Id([1; 16]), &kem_pool(1).0),
        IntegrityError::Commitment,
        "blob of another owner",
    );
    let mut franken = b.clone();
    franken.envelope = a.envelope.clone();
    keyset_refused(
        open_org_keyset(&franken, ORG, Id([2; 16]), &kem_pool(2).0),
        IntegrityError::Commitment,
        "envelope of another owner",
    );
}

#[test]
fn keyset_from_other_org_refused() {
    let other = OrgKeyset {
        org_id: ORG,
        secrets: onepass_core::org::OrgSecrets::generate().unwrap(),
    };
    assert!(matches!(
        other.check_against(&lineage_at(0)),
        Err(Error::Integrity(IntegrityError::OrgPinMismatch))
    ));
    // Same identity, other audit key: also refused.
    let s = org_secrets();
    let half = OrgKeyset {
        org_id: ORG,
        secrets: onepass_core::org::OrgSecrets {
            identity: IdentityKey::from_bytes(&s.identity.to_bytes()).unwrap(),
            audit: onepass_core::crypto::HybridKemSecret::generate().unwrap(),
        },
    };
    assert!(matches!(
        half.check_against(&lineage_at(0)),
        Err(Error::Integrity(IntegrityError::OrgPinMismatch))
    ));
}

#[test]
fn sealed_keyset_decode_strict() {
    let sealed = sealed_for(1);
    let good = sealed.encode();
    let mut trailing = good.clone();
    trailing.push(0);
    let mut format2 = sealed.clone();
    format2.format = 2;
    let mut short = sealed.clone();
    short.envelope.pop();
    let mut long = sealed.clone();
    long.envelope.push(0);
    let oversize = vec![0u8; MAX_ORG_RECORD_BYTES + 1];
    for bad in [
        trailing,
        format2.encode(),
        short.encode(),
        long.encode(),
        oversize,
    ] {
        assert!(matches!(
            SealedOrgKeyset::decode(&bad),
            Err(Error::InvalidFormat(_))
        ));
    }
    assert!(matches!(
        open_org_keyset(&format2, ORG, Id([1; 16]), &kem_pool(1).0),
        Err(Error::InvalidFormat("org keyset"))
    ));
}
