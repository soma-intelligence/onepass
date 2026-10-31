//! Contact cards (sharing spec 5.2, plan rulings A-3, A-4, A-6): strict
//! codec, domain-separated identity signature, keys from the signed params,
//! name rules, fingerprints, safety numbers, pair ids, frozen vectors, the
//! account's own card, and following another account's lineage (spec 5.5).
//!
//! The vectors in `tests/vectors/contact/*.hex` were generated once by
//! `generate_vectors` (ignored) from fixed ids, names and dates over
//! throwaway test accounts, and are frozen: the tests read them back.

mod common;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::OnceLock;

use aws_lc_rs::digest::{SHA256, digest};
use common::{Device, kdf};
use data_encoding::HEXLOWER;
use onepass_core::account::Account;
use onepass_core::contact::{
    CONTACT_CARD_DOMAIN, ContactCard, ForeignLineage, ForeignPin, LegacyIntros, MAX_FOREIGN_COPIES,
    SignedContactCard, accept_legacy_intros, fingerprint, follow_foreign, format_safety_number,
    pair_id, roster_at, safety_number,
};
use onepass_core::crypto::HybridSigningKey;
use onepass_core::crypto::{IdentityKey, IdentitySignature};
use onepass_core::device_keys::{DeviceKeys, DevicePublic, sign_pop};
use onepass_core::devices::{DeviceKind, DeviceMode};
use onepass_core::lineage::{
    GENESIS_IDENTITY_DOMAIN, GenesisBody, IntroBody, LINEAGE_FORMAT, LegacyIntroBody,
    LineageRecord, RosterEntry, RotationBody, RotationReason, SignedIntro, SignedLegacyIntro,
    identity_id, intro_id, sign_genesis, sign_intro, sign_legacy_intro, sign_rotation,
    verify_rotation,
};
use onepass_core::store::{Record, RecordKind, RecordStore};
use onepass_core::trust::{DeviceLineageState, LineageHead, TrustLevel, TrustState};
use onepass_core::{Error, Id, IntegrityError};

const T0: i64 = 1_793_000_000;

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let all: Vec<u8> = parts.concat();
    let mut out = [0u8; 32];
    out.copy_from_slice(digest(&SHA256, &all).as_ref());
    out
}

fn id(n: u8) -> Id {
    Id([n; 16])
}

fn entry(keys: &DevicePublic, name: &str) -> RosterEntry {
    RosterEntry {
        device_id: keys.device_id,
        sign_pub: keys.sign_pub.clone(),
        kem_pub: keys.kem_pub.clone(),
        name: name.into(),
        kind: DeviceKind::Phone,
        mode: DeviceMode::Personal,
        introduced_by: None,
    }
}

/// The lineage of the common case (sharing review I-1): the iPhone creates
/// the account under a first identity (generation 0), introduces the Mac
/// under the genesis, then the Mac rotates to `head_identity` (generation
/// 1). The Mac's intro is bound to the genesis, not to the head.
struct Chain {
    lineage: Vec<LineageRecord>,
    mac_intro: SignedIntro,
    iphone: (DeviceKeys, DevicePublic),
    mac: (DeviceKeys, DevicePublic),
}

fn rotated_chain(account_id: Id, head_identity: &IdentityKey, params: &[u8], first: u8) -> Chain {
    let first_identity = IdentityKey::generate().unwrap();
    let iphone_keys = DeviceKeys::generate_software().unwrap();
    let iphone = iphone_keys.public(id(first)).unwrap();
    let mac_keys = DeviceKeys::generate_software().unwrap();
    let mac = mac_keys.public(id(first + 1)).unwrap();
    let genesis = LineageRecord::Genesis(
        sign_genesis(
            GenesisBody {
                format: LINEAGE_FORMAT,
                account_id,
                identity_pub: first_identity.verifying_key(),
                creator: entry(&iphone, "iPhone"),
                created_at: T0,
            },
            &iphone_keys,
            &first_identity,
        )
        .unwrap(),
    );
    let mut mac_entry = entry(&mac, "Mac");
    mac_entry.introduced_by = Some(iphone.device_id);
    let mac_intro = sign_intro(
        IntroBody {
            format: LINEAGE_FORMAT,
            account_id,
            head: genesis.hash(),
            entry: mac_entry.clone(),
            introducer: iphone.device_id,
            pop: sign_pop(&mac_keys, &account_id.0, &mac).unwrap(),
        },
        &iphone_keys,
        None,
    )
    .unwrap();
    let mut roster = vec![entry(&iphone, "iPhone"), mac_entry];
    roster.sort_by_key(|e| e.device_id);
    let deliveries = roster
        .iter()
        .filter(|e| e.device_id != mac.device_id)
        .map(|e| (e.device_id, [0x5A; 32]))
        .collect();
    let rotation = LineageRecord::Rotation(
        sign_rotation(
            RotationBody {
                format: LINEAGE_FORMAT,
                account_id,
                generation: 1,
                parent: genesis.hash(),
                rotator: mac.device_id,
                reason: RotationReason::Rotate,
                revoked: vec![],
                roster,
                identity_pub: head_identity.verifying_key(),
                params_hash: sha256(&[params]),
                keyset_hash: [0x4B; 32],
                deliveries,
                from_heads: BTreeMap::new(),
                issued_at: T0 + 30,
            },
            &mac_keys,
            head_identity,
        )
        .unwrap(),
    );
    Chain {
        lineage: vec![genesis, rotation],
        mac_intro,
        iphone: (iphone_keys, iphone),
        mac: (mac_keys, mac),
    }
}

/// A test account and the lineage of its card. SLH-DSA signing is slow:
/// each party is built once per process.
struct Party {
    account_id: Id,
    /// The identity of the head.
    identity: IdentityKey,
    params: Vec<u8>,
    lineage: Vec<LineageRecord>,
    intros: Vec<SignedIntro>,
}

/// `rotated`: the chain of `rotated_chain`, the Mac's intro carried.
/// Otherwise a lone genesis by the account's identity, no intro.
fn party(device: u8, rotated: bool) -> Party {
    let n = Account::create_with_params("Projet Atlas, Camille Durand", kdf()).unwrap();
    let account_id = n.account.params.account_id;
    let identity = IdentityKey::from_bytes(&n.account.keyset().identity.to_bytes()).unwrap();
    let (lineage, intros) = if rotated {
        let c = rotated_chain(account_id, &identity, &n.params_record, device);
        (c.lineage, vec![c.mac_intro])
    } else {
        let keys = DeviceKeys::generate_software().unwrap();
        let public = keys.public(id(device)).unwrap();
        let genesis = LineageRecord::Genesis(
            sign_genesis(
                GenesisBody {
                    format: LINEAGE_FORMAT,
                    account_id,
                    identity_pub: identity.verifying_key(),
                    creator: entry(&public, "iPhone"),
                    created_at: T0,
                },
                &keys,
                &identity,
            )
            .unwrap(),
        );
        (vec![genesis], vec![])
    };
    Party {
        account_id,
        identity,
        params: n.params_record,
        lineage,
        intros,
    }
}

fn card_of(p: &Party, name: &str) -> ContactCard {
    let last = p.lineage.last().unwrap();
    ContactCard {
        format: 1,
        account_id: p.account_id,
        genesis: p.lineage[0].hash(),
        head: LineageHead {
            generation: last.generation(),
            hash: last.hash(),
        },
        identity_pub: p.identity.verifying_key(),
        params: p.params.clone(),
        lineage: p.lineage.clone(),
        intros: p.intros.clone(),
        legacy_intros: vec![],
        genesis_params: None,
        name: name.into(),
        issued_at: T0 + 60,
    }
}

/// Alice: generation 1, carrying the Mac's intro under generation 0.
fn alice() -> &'static (Party, SignedContactCard) {
    static A: OnceLock<(Party, SignedContactCard)> = OnceLock::new();
    A.get_or_init(|| {
        let p = party(0x11, true);
        let card = SignedContactCard::sign(card_of(&p, "Alice"), &p.identity).unwrap();
        (p, card)
    })
}

/// Bob: a lone genesis.
fn bob() -> &'static Party {
    static B: OnceLock<Party> = OnceLock::new();
    B.get_or_init(|| party(0x21, false))
}

/// A signature of the right length that verifies nowhere: enough for the
/// shape checks of `decode`.
fn dummy_sig() -> IdentitySignature {
    postcard::from_bytes(
        &postcard::to_allocvec(&serde_bytes::ByteBuf::from(vec![0u8; 29792])).unwrap(),
    )
    .unwrap()
}

fn unsigned(card: ContactCard) -> SignedContactCard {
    SignedContactCard {
        card,
        identity_sig: dummy_sig(),
    }
}

fn is_format(r: Result<SignedContactCard, Error>) -> bool {
    matches!(r, Err(Error::InvalidFormat(_)))
}

// ---------------------------------------------------------------- codec

#[test]
fn card_round_trip_and_strict() {
    let (_, signed) = alice();
    let bytes = signed.encode();
    assert_eq!(&SignedContactCard::decode(&bytes).unwrap(), signed);
    signed.keys().unwrap();

    let mut long = bytes.clone();
    long.push(0);
    assert!(is_format(SignedContactCard::decode(&long)));

    // `issued_at` is the last field of the card, a zigzag varint: pad it
    // (same value, longer encoding). Only the canonical re-encoding check
    // can refuse it.
    let card_len = postcard::to_allocvec(&signed.card).unwrap().len();
    let tail = postcard::to_allocvec(&signed.card.issued_at).unwrap();
    let pos = card_len - tail.len();
    assert_eq!(&bytes[pos..card_len], tail.as_slice());
    let mut t = tail.clone();
    *t.last_mut().unwrap() |= 0x80;
    t.push(0x00);
    assert_eq!(
        postcard::from_bytes::<i64>(&t).unwrap(),
        signed.card.issued_at
    );
    let mut padded = bytes[..pos].to_vec();
    padded.extend_from_slice(&t);
    padded.extend_from_slice(&bytes[card_len..]);
    assert!(is_format(SignedContactCard::decode(&padded)));

    // A short signature.
    let mut short = signed.clone();
    short.identity_sig = postcard::from_bytes(&[1, 0]).unwrap();
    assert!(is_format(SignedContactCard::decode(&short.encode())));
}

#[test]
fn card_shape_refused() {
    let (a, _) = alice();
    let good = card_of(a, "Alice");
    SignedContactCard::decode(&unsigned(good.clone()).encode()).unwrap();

    let refused = |f: &dyn Fn(&mut ContactCard)| {
        let mut c = good.clone();
        f(&mut c);
        assert!(is_format(SignedContactCard::decode(&unsigned(c).encode())));
    };
    refused(&|c| c.format = 2);
    refused(&|c| c.lineage.clear());
    refused(&|c| c.genesis = [9; 32]);
    refused(&|c| c.head.hash = [9; 32]);
    refused(&|c| c.head.generation += 1);
    refused(&|c| c.lineage.truncate(1));
    refused(&|c| c.lineage.reverse());
    refused(&|c| c.account_id = id(0xEE));
    refused(&|c| c.identity_pub = bob().identity.verifying_key());
    refused(&|c| c.params = vec![1, 2, 3]);
    refused(&|c| c.lineage.push(c.lineage[0].clone()));
    refused(&|c| c.intros.push(c.intros[0].clone()));
    // An intro bound to a hash that is not in the lineage.
    refused(&|c| c.intros[0].body.head = [9; 32]);
    refused(&|c| c.intros[0].body.account_id = id(0xEE));
}

#[test]
fn card_carries_intros_from_older_generations() {
    // Generation 1, the Mac's intro bound to generation 0 (review I-1):
    // the signed card decodes and yields its keys.
    let (a, signed) = alice();
    assert_eq!(signed.card.head.generation, 1);
    assert_eq!(signed.card.intros.len(), 1);
    assert_eq!(signed.card.intros[0].body.head, a.lineage[0].hash());
    let back = SignedContactCard::decode(&signed.encode()).unwrap();
    back.keys().unwrap();
    // Also bound to the head: accepted.
    let mut c = card_of(a, "Alice");
    c.intros[0].body.head = a.lineage[1].hash();
    SignedContactCard::decode(&unsigned(c).encode()).unwrap();
}

#[test]
fn card_intros_capped_per_record() {
    // 64 intros under one record decode, 65 do not; 64 under each of two
    // records do.
    let (a, _) = alice();
    let many = |head: [u8; 32], n: usize, tag: &str| -> Vec<SignedIntro> {
        (0..n)
            .map(|i| {
                let mut x = a.intros[0].clone();
                x.body.head = head;
                x.body.entry.name = format!("{tag}{i}");
                x
            })
            .collect()
    };
    let decode = |intros: Vec<SignedIntro>| {
        let mut intros = intros;
        intros.sort_by_key(|i| intro_id(&i.body));
        let mut c = card_of(a, "Alice");
        c.intros = intros;
        SignedContactCard::decode(&unsigned(c).encode())
    };
    let (g0, g1) = (a.lineage[0].hash(), a.lineage[1].hash());
    decode(many(g0, 64, "a")).unwrap();
    assert!(is_format(decode(many(g0, 65, "a"))));
    let mut both = many(g0, 64, "a");
    both.extend(many(g1, 64, "b"));
    decode(both).unwrap();
}

#[test]
fn card_intros_sorted() {
    // Two intros under the genesis, in both orders: only the sorted one.
    let (a, _) = alice();
    let mut second = a.intros[0].clone();
    second.body.entry.name = "iPad".into();
    let mut sorted = vec![a.intros[0].clone(), second];
    sorted.sort_by_key(|i| intro_id(&i.body));
    let mut c = card_of(a, "Alice");
    c.intros = sorted.clone();
    SignedContactCard::decode(&unsigned(c.clone()).encode()).unwrap();
    c.intros.reverse();
    assert!(is_format(SignedContactCard::decode(&unsigned(c).encode())));
}

// ---------------------------------------------------------------- signatures

#[test]
fn card_signature_domain_separated() {
    let (a, signed) = alice();
    let msg = postcard::to_allocvec(&signed.card).unwrap();
    // The same card bytes under the genesis identity domain.
    let wrong = SignedContactCard {
        card: signed.card.clone(),
        identity_sig: a.identity.sign(GENESIS_IDENTITY_DOMAIN, &msg).unwrap(),
    };
    assert_eq!(
        SignedContactCard::decode(&wrong.encode())
            .unwrap()
            .keys()
            .unwrap_err(),
        Error::Integrity(IntegrityError::Signature)
    );
    // Signed by another identity under the card domain.
    let other = SignedContactCard {
        card: signed.card.clone(),
        identity_sig: bob().identity.sign(CONTACT_CARD_DOMAIN, &msg).unwrap(),
    };
    assert_eq!(
        other.keys().unwrap_err(),
        Error::Integrity(IntegrityError::Signature)
    );
    // `sign` refuses a key that is not the card's identity.
    assert!(matches!(
        SignedContactCard::sign(signed.card.clone(), &bob().identity),
        Err(Error::Validation(_))
    ));
}

#[test]
fn card_params_of_other_identity_refused() {
    let (a, _) = alice();
    let b = bob();
    // Alice's card carrying Bob's params (signed by Bob's identity).
    let mut c = card_of(a, "Alice");
    c.params = b.params.clone();
    let signed = SignedContactCard::sign(c, &a.identity).unwrap();
    assert_eq!(
        signed.keys().unwrap_err(),
        Error::Integrity(IntegrityError::Signature)
    );

    // Bob's identity, params and lineage, but under Alice's account id:
    // every signature holds, the params name another account.
    let keys = DeviceKeys::generate_software().unwrap();
    let public = keys.public(id(0x31)).unwrap();
    let genesis = LineageRecord::Genesis(
        sign_genesis(
            GenesisBody {
                format: LINEAGE_FORMAT,
                account_id: a.account_id,
                identity_pub: b.identity.verifying_key(),
                creator: entry(&public, "iPhone"),
                created_at: T0,
            },
            &keys,
            &b.identity,
        )
        .unwrap(),
    );
    let card = ContactCard {
        format: 1,
        account_id: a.account_id,
        genesis: genesis.hash(),
        head: LineageHead {
            generation: 0,
            hash: genesis.hash(),
        },
        identity_pub: b.identity.verifying_key(),
        params: b.params.clone(),
        lineage: vec![genesis],
        intros: vec![],
        legacy_intros: vec![],
        genesis_params: None,
        name: "Bob".into(),
        issued_at: T0,
    };
    let signed = SignedContactCard::sign(card, &b.identity).unwrap();
    assert_eq!(
        signed.keys().unwrap_err(),
        Error::Integrity(IntegrityError::WrongContext)
    );
}

#[test]
fn card_name_rules() {
    let (a, _) = alice();
    let decode =
        |name: &str| SignedContactCard::decode(&unsigned(card_of(a, name)).encode()).map(|_| ());
    decode(&"é".repeat(64)).unwrap();
    for name in [
        "é".repeat(65),
        "Al\u{0007}ice".into(),
        "Al\nice".into(),
        String::new(),
    ] {
        assert!(
            matches!(decode(&name), Err(Error::InvalidFormat(_))),
            "{name:?}"
        );
        // `sign` refuses it too, before signing.
        assert!(matches!(
            SignedContactCard::sign(card_of(a, &name), &a.identity),
            Err(Error::InvalidFormat(_))
        ));
    }
}

// ---------------------------------------------------------------- numbers

#[test]
fn fingerprint_formula() {
    let (a, g, i) = (id(0xA0), [7u8; 32], id(0x1D));
    assert_eq!(
        fingerprint(a, &g, i),
        sha256(&[b"onepass/contact-fpr/v1", &a.0, &g, &i.0])
    );
    assert_ne!(fingerprint(a, &g, i), fingerprint(id(0xA1), &g, i));
    assert_ne!(fingerprint(a, &g, i), fingerprint(a, &[8; 32], i));
}

#[test]
fn safety_number_symmetric() {
    let (fa, fb) = ([1u8; 32], [2u8; 32]);
    let n = safety_number(&fa, &fb);
    assert_eq!(n, safety_number(&fb, &fa));
    assert_eq!(n.len(), 12);
    assert!(n.iter().all(|g| *g < 100_000));
    // Frozen: computed outside the crate from ruling A-4.
    assert_eq!(
        n,
        [
            81560, 78355, 68367, 671, 56336, 18364, 25867, 45031, 46810, 10286, 291, 38878
        ]
    );
    assert_eq!(
        format_safety_number(&n),
        "81560 78355 68367 00671 56336 18364 25867 45031 46810 10286 00291 38878"
    );
}

#[test]
fn safety_number_changes_with_identity() {
    let (acct, g) = (id(0xA0), [7u8; 32]);
    let other = fingerprint(id(0xB0), &[8; 32], id(0x2D));
    let before = safety_number(&fingerprint(acct, &g, id(0x1D)), &other);
    let after = safety_number(&fingerprint(acct, &g, id(0x1E)), &other);
    assert_ne!(before, after);
}

#[test]
fn pair_id_symmetric_and_prefixed() {
    let (a, b) = (id(0xA0), id(0xB0));
    assert_eq!(pair_id(a, b), pair_id(b, a));
    assert_eq!(
        pair_id(a, b).0,
        sha256(&[b"onepass/contact-pair/v1", &a.0, &b.0])[..16]
    );
    assert_ne!(pair_id(a, b), pair_id(a, id(0xB1)));
}

// ---------------------------------------------------------------- vectors

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/contact")
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

#[test]
fn golden_vectors() {
    let mut fprs = Vec::new();
    let mut frozen_safety = Vec::new();
    for name in ["alice.hex", "bob.hex"] {
        let v = read_vector(name);
        let bytes = HEXLOWER.decode(v["card"].as_bytes()).unwrap();
        let signed = SignedContactCard::decode(&bytes).unwrap();
        assert_eq!(signed.encode(), bytes);
        let keys = signed.keys().unwrap();
        assert_eq!(HEXLOWER.encode(&keys.identity_id.0), v["identity_id"]);
        let c = &signed.card;
        let fpr = fingerprint(c.account_id, &c.genesis, keys.identity_id);
        assert_eq!(HEXLOWER.encode(&fpr), v["fingerprint"]);
        fprs.push(fpr);
        frozen_safety.push(v["safety"].clone());
    }
    let n = format_safety_number(&safety_number(&fprs[0], &fprs[1]));
    assert_eq!(n, frozen_safety[0]);
    assert_eq!(n, frozen_safety[1]);
}

/// Run once to (re)create the frozen files: `cargo test -p onepass-core
/// --features dev-fast-kdf --test contact_vectors -- --ignored
/// generate_vectors`. The files are committed; the tests only read them.
#[test]
#[ignore]
fn generate_vectors() {
    let (_, alice_card) = alice();
    let b = bob();
    let bob_card = SignedContactCard::sign(card_of(b, "Bob"), &b.identity).unwrap();
    let fpr = |s: &SignedContactCard| {
        let k = s.keys().unwrap();
        (
            fingerprint(s.card.account_id, &s.card.genesis, k.identity_id),
            k.identity_id,
        )
    };
    let (fa, ia) = fpr(alice_card);
    let (fb, ib) = fpr(&bob_card);
    let safety = format_safety_number(&safety_number(&fa, &fb));
    std::fs::create_dir_all(vectors_dir()).unwrap();
    for (name, card, f, i) in [
        ("alice.hex", alice_card, fa, ia),
        ("bob.hex", &bob_card, fb, ib),
    ] {
        let s = format!(
            "# frozen contact card vector (throwaway test account), do not regenerate\n\
             card={}\nidentity_id={}\nfingerprint={}\nsafety={}\n",
            HEXLOWER.encode(&card.encode()),
            HEXLOWER.encode(&i.0),
            HEXLOWER.encode(&f),
            safety
        );
        std::fs::write(vectors_dir().join(name), s).unwrap();
    }
}

// ---------------------------------------------------------------- own card

#[test]
fn own_card_at_pinned_head() {
    let (mut d, _sk) = Device::create();
    let repo = d.repo();
    // No trust state yet: refused.
    assert!(matches!(
        repo.own_contact_card("Alice", T0),
        Err(Error::Validation(_))
    ));

    // The session identity is the head of a rotated chain: generation 0
    // under a first identity, the Mac introduced there, the Mac's rotation
    // to the session identity at generation 1.
    let account_id = repo.account().params.account_id;
    let identity = IdentityKey::from_bytes(&repo.account().keyset().identity.to_bytes()).unwrap();
    let params = repo
        .store()
        .get(RecordKind::AccountParams, account_id)
        .unwrap()
        .unwrap()
        .data;
    let chain = rotated_chain(account_id, &identity, &params, 0x41);
    let (genesis, rotation) = (&chain.lineage[0], &chain.lineage[1]);
    let (mac_keys, mac) = &chain.mac;
    let (iphone_keys, iphone) = &chain.iphone;

    let device = |n: u8| {
        let k = DeviceKeys::generate_software().unwrap();
        let p = k.public(id(n)).unwrap();
        (k, p)
    };
    let intro =
        |head: [u8; 32], by: (&DeviceKeys, &DevicePublic), new: (&DeviceKeys, &DevicePublic)| {
            let mut e = entry(new.1, "device");
            e.introduced_by = Some(by.1.device_id);
            sign_intro(
                IntroBody {
                    format: LINEAGE_FORMAT,
                    account_id,
                    head,
                    entry: e,
                    introducer: by.1.device_id,
                    pop: sign_pop(new.0, &account_id.0, new.1).unwrap(),
                },
                by.0,
                None,
            )
            .unwrap()
        };
    let (ipad_keys, ipad) = device(0x51);
    let (watch_keys, watch) = device(0x52);
    let (tv_keys, tv) = device(0x53);
    let (stranger_keys, stranger) = device(0x54);
    // Under the head, by the Mac: the iPad (trusted here) and the Watch
    // (never accepted on this device).
    let ipad_intro = intro(rotation.hash(), (mac_keys, mac), (&ipad_keys, &ipad));
    let watch_intro = intro(rotation.hash(), (mac_keys, mac), (&watch_keys, &watch));
    // Under the genesis: a TV introduced by a device that was never a
    // member there (signature by a stranger, introducer named as the
    // iPhone): dropped.
    let mut forged = intro(genesis.hash(), (iphone_keys, iphone), (&tv_keys, &tv));
    forged.sig = intro(genesis.hash(), (&stranger_keys, &stranger), (&tv_keys, &tv)).sig;
    // Bound to a hash outside the lineage: dropped.
    let elsewhere = intro([9; 32], (iphone_keys, iphone), (&tv_keys, &tv));

    let LineageRecord::Rotation(r) = rotation else {
        unreachable!()
    };
    let mut roster = r.body.roster.clone();
    let mut ipad_entry = entry(&ipad, "device");
    ipad_entry.introduced_by = Some(mac.device_id);
    roster.push(ipad_entry);
    roster.sort_by_key(|e| e.device_id);
    let head = LineageHead {
        generation: 1,
        hash: rotation.hash(),
    };
    // This device is the Mac.
    let mut trust = TrustState::new(
        account_id,
        mac.clone(),
        head,
        identity.verifying_key(),
        roster.clone(),
        DeviceLineageState::Current,
    );
    for e in &roster {
        trust.levels.insert(e.device_id, TrustLevel::Verified);
    }
    let rec = |kind, id, data| {
        (
            Record {
                id,
                kind,
                version: 0,
                data,
            },
            None,
        )
    };
    let mut writes = vec![
        rec(RecordKind::Lineage, genesis.record_id(), genesis.encode()),
        rec(RecordKind::Lineage, rotation.record_id(), rotation.encode()),
    ];
    for i in [
        &chain.mac_intro,
        &ipad_intro,
        &watch_intro,
        &forged,
        &elsewhere,
    ] {
        writes.push(rec(RecordKind::DeviceIntro, intro_id(&i.body), i.encode()));
    }
    repo.store_mut()
        .put_all_if_version_with_trust(writes, vec![], None, &trust)
        .unwrap();

    let card = repo.own_contact_card("Alice", T0 + 5).unwrap();
    let c = &card.card;
    assert_eq!(c.account_id, account_id);
    assert_eq!(c.genesis, genesis.hash());
    assert_eq!(c.head, head);
    assert_eq!(c.lineage, chain.lineage);
    let mut expected = vec![chain.mac_intro.clone(), ipad_intro];
    expected.sort_by_key(|i| intro_id(&i.body));
    assert_eq!(c.intros, expected);
    assert_eq!(c.name, "Alice");
    assert_eq!(c.issued_at, T0 + 5);
    assert_eq!(SignedContactCard::decode(&card.encode()).unwrap(), card);
    let keys = card.keys().unwrap();
    assert_eq!(keys.identity_id, identity_id(&identity.verifying_key()));
    assert_eq!(keys.sign_pub, repo.account().params.signing_pub);
    assert_eq!(keys.kem_pub, repo.account().params.kem_pub);

    // A name the card rules refuse.
    assert!(matches!(
        repo.own_contact_card("", T0),
        Err(Error::InvalidFormat(_))
    ));
}

// ------------------------------------------- another account's lineage

/// A foreign account's lineage (sharing spec 5.5), signed once per process.
///
/// Devices: A (iPhone, creator), B (iPad, introduced under the genesis by
/// A), C (Mac, introduced under generation 1 by A), X (outside the account).
///
/// - `g`: genesis by A.
/// - `r1`: generation 1 by A, revokes B.
/// - `r1_sibling`: generation 1 by B, revokes nobody (a sibling of `r1`).
/// - `r1_unknown`: generation 1 by X, a device in no roster.
/// - `r1_body_key`: generation 1 naming A as rotator, A's roster entry
///   carrying X's key, signed by X.
/// - `r2`: generation 2 by C (known only through its intro under `r1`).
/// - `r2_by_b`: generation 2 under `r1` by B, revoked by `r1`.
struct Foreign {
    account_id: Id,
    identities: Vec<IdentityKey>,
    g: LineageRecord,
    r1: LineageRecord,
    r1_sibling: LineageRecord,
    r1_unknown: LineageRecord,
    r1_body_key: LineageRecord,
    r2: LineageRecord,
    r2_by_b: LineageRecord,
    /// B under the genesis, by A.
    intro_b_g: SignedIntro,
    /// C under `r1`, by A.
    intro_c_r1: SignedIntro,
    /// B again under `r1`, by A (a revoked device back in a roster).
    intro_b_r1: SignedIntro,
}

fn rotation(
    account_id: Id,
    parent: &LineageRecord,
    rotator: (&DeviceKeys, Id),
    revoked: Vec<Id>,
    mut roster: Vec<RosterEntry>,
    identity: &IdentityKey,
) -> LineageRecord {
    roster.sort_by_key(|e| e.device_id);
    let deliveries = roster
        .iter()
        .filter(|e| e.device_id != rotator.1)
        .map(|e| (e.device_id, [0x5A; 32]))
        .collect();
    LineageRecord::Rotation(
        sign_rotation(
            RotationBody {
                format: LINEAGE_FORMAT,
                account_id,
                generation: parent.generation() + 1,
                parent: parent.hash(),
                rotator: rotator.1,
                reason: RotationReason::Revoke,
                revoked,
                roster,
                identity_pub: identity.verifying_key(),
                params_hash: [0x50; 32],
                keyset_hash: [0x4B; 32],
                deliveries,
                from_heads: BTreeMap::new(),
                issued_at: T0 + 30,
            },
            rotator.0,
            identity,
        )
        .unwrap(),
    )
}

fn intro(
    account_id: Id,
    under: &LineageRecord,
    introducer: (&DeviceKeys, Id),
    new: (&DeviceKeys, &DevicePublic, &str),
) -> SignedIntro {
    let mut e = entry(new.1, new.2);
    e.introduced_by = Some(introducer.1);
    sign_intro(
        IntroBody {
            format: LINEAGE_FORMAT,
            account_id,
            head: under.hash(),
            entry: e,
            introducer: introducer.1,
            pop: sign_pop(new.0, &account_id.0, new.1).unwrap(),
        },
        introducer.0,
        None,
    )
    .unwrap()
}

fn foreign() -> &'static Foreign {
    static F: OnceLock<Foreign> = OnceLock::new();
    F.get_or_init(|| {
        let account_id = id(0x70);
        let identities: Vec<IdentityKey> =
            (0..6).map(|_| IdentityKey::generate().unwrap()).collect();
        let dev = |n: u8| {
            let k = DeviceKeys::generate_software().unwrap();
            let p = k.public(id(n)).unwrap();
            (k, p)
        };
        let (ka, a) = dev(0x71);
        let (kb, b) = dev(0x72);
        let (kc, c) = dev(0x73);
        let (kx, x) = dev(0x74);
        let g = LineageRecord::Genesis(
            sign_genesis(
                GenesisBody {
                    format: LINEAGE_FORMAT,
                    account_id,
                    identity_pub: identities[0].verifying_key(),
                    creator: entry(&a, "iPhone"),
                    created_at: T0,
                },
                &ka,
                &identities[0],
            )
            .unwrap(),
        );
        let intro_b_g = intro(account_id, &g, (&ka, a.device_id), (&kb, &b, "iPad"));
        let r1 = rotation(
            account_id,
            &g,
            (&ka, a.device_id),
            vec![b.device_id],
            vec![entry(&a, "iPhone")],
            &identities[1],
        );
        let r1_sibling = rotation(
            account_id,
            &g,
            (&kb, b.device_id),
            vec![],
            vec![entry(&a, "iPhone"), entry(&b, "iPad")],
            &identities[2],
        );
        let r1_unknown = rotation(
            account_id,
            &g,
            (&kx, x.device_id),
            vec![],
            vec![entry(&x, "Inconnu")],
            &identities[3],
        );
        let mut forged_a = entry(&a, "iPhone");
        forged_a.sign_pub = x.sign_pub.clone();
        let r1_body_key = rotation(
            account_id,
            &g,
            (&kx, a.device_id),
            vec![],
            vec![forged_a],
            &identities[3],
        );
        let intro_c_r1 = intro(account_id, &r1, (&ka, a.device_id), (&kc, &c, "Mac"));
        let intro_b_r1 = intro(account_id, &r1, (&ka, a.device_id), (&kb, &b, "iPad"));
        let r2 = rotation(
            account_id,
            &r1,
            (&kc, c.device_id),
            vec![],
            vec![entry(&a, "iPhone"), entry(&c, "Mac")],
            &identities[4],
        );
        let r2_by_b = rotation(
            account_id,
            &r1,
            (&kb, b.device_id),
            vec![],
            vec![entry(&a, "iPhone"), entry(&b, "iPad")],
            &identities[5],
        );
        Foreign {
            account_id,
            identities,
            g,
            r1,
            r1_sibling,
            r1_unknown,
            r1_body_key,
            r2,
            r2_by_b,
            intro_b_g,
            intro_c_r1,
            intro_b_r1,
        }
    })
}

fn follow(pin: &ForeignPin, records: &[LineageRecord], intros: &[SignedIntro]) -> ForeignLineage {
    follow_foreign(pin, records, intros, &LegacyIntros::default())
}

fn roster(
    records: &[LineageRecord],
    intros: &[SignedIntro],
    head: &[u8; 32],
) -> Result<Vec<RosterEntry>, Error> {
    roster_at(records, intros, &LegacyIntros::default(), head)
}

fn pin_at(f: &Foreign, r: &LineageRecord) -> ForeignPin {
    ForeignPin {
        account_id: f.account_id,
        genesis: f.g.hash(),
        head: LineageHead {
            generation: r.generation(),
            hash: r.hash(),
        },
        identity_pub: r.identity_pub().clone(),
    }
}

fn all_intros(f: &Foreign) -> Vec<SignedIntro> {
    vec![
        f.intro_b_g.clone(),
        f.intro_c_r1.clone(),
        f.intro_b_r1.clone(),
    ]
}

fn advanced_chain(l: &ForeignLineage) -> Option<&[[u8; 32]]> {
    match l {
        ForeignLineage::Advanced { chain, .. } => Some(chain),
        _ => None,
    }
}

#[test]
fn same_head_is_same() {
    let f = foreign();
    let records = [f.g.clone(), f.r1.clone()];
    assert_eq!(
        follow(&pin_at(f, &f.r1), &records, &all_intros(f)),
        ForeignLineage::Same
    );
    assert_eq!(
        follow(&pin_at(f, &f.g), std::slice::from_ref(&f.g), &[]),
        ForeignLineage::Same
    );
}

#[test]
fn one_rotation_advances() {
    let f = foreign();
    let records = [f.g.clone(), f.r1.clone()];
    let got = follow(
        &pin_at(f, &f.g),
        &records,
        std::slice::from_ref(&f.intro_b_g),
    );
    let ForeignLineage::Advanced {
        chain,
        head,
        identity_pub,
        last_rotation,
    } = got
    else {
        panic!("expected Advanced, got {got:?}");
    };
    assert_eq!(chain, vec![f.r1.hash()]);
    assert_eq!(
        head,
        LineageHead {
            generation: 1,
            hash: f.r1.hash()
        }
    );
    assert_eq!(identity_pub, f.identities[1].verifying_key());
    assert_eq!(last_rotation.revoked, vec![id(0x72)]);
    // Without B's intro, `r1` revokes a device the genesis roster does not
    // know: still valid (an unknown revoked id only shrinks later rosters).
    let got = follow(&pin_at(f, &f.g), &records, &[]);
    assert_eq!(advanced_chain(&got), Some(&[f.r1.hash()][..]));
}

#[test]
fn two_rotations_advance_in_order() {
    let f = foreign();
    // Given out of order: the result follows the generations.
    let records = [f.r2.clone(), f.g.clone(), f.r1.clone()];
    let got = follow(&pin_at(f, &f.g), &records, &all_intros(f));
    assert_eq!(advanced_chain(&got), Some(&[f.r1.hash(), f.r2.hash()][..]));
    let ForeignLineage::Advanced {
        head, identity_pub, ..
    } = got
    else {
        unreachable!()
    };
    assert_eq!(head.generation, 2);
    assert_eq!(identity_pub, f.identities[4].verifying_key());
    // From `r1`, one step.
    let got = follow(&pin_at(f, &f.r1), &records, &all_intros(f));
    assert_eq!(advanced_chain(&got), Some(&[f.r2.hash()][..]));
}

#[test]
fn rotation_by_unknown_device_ignored() {
    let f = foreign();
    let records = [f.g.clone(), f.r1_unknown.clone()];
    assert_eq!(
        follow(&pin_at(f, &f.g), &records, &all_intros(f)),
        ForeignLineage::Same
    );
}

#[test]
fn rotation_signed_with_key_from_body_ignored() {
    let f = foreign();
    // The body's roster gives A the key that signed it: it verifies under
    // that key, never under A's key from the genesis.
    let LineageRecord::Rotation(s) = &f.r1_body_key else {
        unreachable!()
    };
    verify_rotation(s, &s.body.roster[0].sign_pub).unwrap();
    let records = [f.g.clone(), f.r1_body_key.clone()];
    assert_eq!(
        follow(&pin_at(f, &f.g), &records, &all_intros(f)),
        ForeignLineage::Same
    );
}

#[test]
fn intro_extends_roster() {
    let f = foreign();
    let records = [f.g.clone(), f.r1.clone(), f.r2.clone()];
    // C signs `r2`; C is known only by A's intro under `r1`.
    let got = follow(
        &pin_at(f, &f.r1),
        &records,
        std::slice::from_ref(&f.intro_c_r1),
    );
    assert_eq!(advanced_chain(&got), Some(&[f.r2.hash()][..]));
    // Without it, C is unknown.
    assert_eq!(
        follow(&pin_at(f, &f.r1), &records, &[]),
        ForeignLineage::Same
    );
    // An intro bound to another record does not count under `r1`.
    let mut moved = f.intro_c_r1.clone();
    moved.body.head = f.g.hash();
    assert_eq!(
        follow(&pin_at(f, &f.r1), &records, &[moved]),
        ForeignLineage::Same
    );

    // roster_at: the record's roster plus the intros accepted under it.
    let ids = |r: Vec<RosterEntry>| r.into_iter().map(|e| e.device_id).collect::<Vec<_>>();
    assert_eq!(
        ids(roster(&records, &all_intros(f), &f.r1.hash()).unwrap()),
        vec![id(0x71), id(0x72), id(0x73)]
    );
    assert_eq!(
        ids(roster(&records, &[], &f.r1.hash()).unwrap()),
        vec![id(0x71)]
    );
    assert_eq!(
        ids(roster(&records, &all_intros(f), &f.g.hash()).unwrap()),
        vec![id(0x71), id(0x72)]
    );
    assert!(matches!(
        roster(&records, &[], &[9; 32]),
        Err(Error::NotFound)
    ));
}

#[test]
fn roster_at_identity_intro_rules() {
    let f = foreign();
    let records = [f.g.clone(), f.r1.clone()];
    let ids = |r: Vec<RosterEntry>| r.into_iter().map(|e| e.device_id).collect::<Vec<_>>();
    let kd = DeviceKeys::generate_software().unwrap();
    let d = kd.public(id(0x75)).unwrap();
    let self_intro = |identity: Option<&IdentityKey>| {
        sign_intro(
            IntroBody {
                format: LINEAGE_FORMAT,
                account_id: f.account_id,
                head: f.r1.hash(),
                entry: entry(&d, "Kit"),
                introducer: d.device_id,
                pop: sign_pop(&kd, &f.account_id.0, &d).unwrap(),
            },
            &kd,
            identity,
        )
        .unwrap()
    };
    // A kit self-intro signed by the identity of `r1`: accepted.
    let good = self_intro(Some(&f.identities[1]));
    assert_eq!(
        ids(roster(&records, &[good], &f.r1.hash()).unwrap()),
        vec![id(0x71), id(0x75)]
    );
    // By another identity, or without one: refused.
    for bad in [self_intro(Some(&f.identities[0])), self_intro(None)] {
        assert_eq!(
            ids(roster(&records, &[bad], &f.r1.hash()).unwrap()),
            vec![id(0x71)]
        );
    }
}

#[test]
fn sibling_rotations_fork() {
    let f = foreign();
    let records = [f.g.clone(), f.r1.clone(), f.r1_sibling.clone()];
    let mut expected = vec![f.r1.hash(), f.r1_sibling.hash()];
    expected.sort();
    // `r1` revokes B, the signer of its sibling: never picked, the user
    // decides (spec 12.3 point 4).
    assert_eq!(
        follow(&pin_at(f, &f.g), &records, &all_intros(f)),
        ForeignLineage::Forked { siblings: expected }
    );
}

#[test]
fn revoked_device_rotation_after_revocation_ignored() {
    let f = foreign();
    let records = [f.g.clone(), f.r1.clone(), f.r2_by_b.clone()];
    // B is not in `r1`'s roster.
    assert_eq!(
        follow(
            &pin_at(f, &f.r1),
            &records,
            std::slice::from_ref(&f.intro_b_g)
        ),
        ForeignLineage::Same
    );
    // B is back under `r1` through an intro: still revoked by an ancestor.
    let intros = [f.intro_b_g.clone(), f.intro_b_r1.clone()];
    assert_eq!(
        follow(&pin_at(f, &f.r1), &records, &intros),
        ForeignLineage::Same
    );
    // From the genesis, the walk stops at `r1`.
    let got = follow(&pin_at(f, &f.g), &records, &intros);
    assert_eq!(advanced_chain(&got), Some(&[f.r1.hash()][..]));
}

#[test]
fn older_card_never_replaces_pinned_head() {
    let f = foreign();
    assert_eq!(
        follow(
            &pin_at(f, &f.r2),
            &[f.g.clone(), f.r1.clone()],
            &all_intros(f)
        ),
        ForeignLineage::Unknown
    );
    assert_eq!(
        follow(
            &pin_at(f, &f.r1),
            std::slice::from_ref(&f.g),
            &all_intros(f)
        ),
        ForeignLineage::Unknown
    );
    // A path that skips a record, or a pin on another genesis.
    assert_eq!(
        follow(
            &pin_at(f, &f.r2),
            &[f.g.clone(), f.r2.clone()],
            &all_intros(f)
        ),
        ForeignLineage::Unknown
    );
    let mut other = pin_at(f, &f.r1);
    other.genesis = [9; 32];
    assert_eq!(
        follow(&other, &[f.g.clone(), f.r1.clone()], &all_intros(f)),
        ForeignLineage::Unknown
    );
    // Records of another account are not this one's.
    let mut stranger = pin_at(f, &f.g);
    stranger.account_id = id(0x01);
    assert_eq!(
        follow(&stranger, &[f.g.clone(), f.r1.clone()], &all_intros(f)),
        ForeignLineage::Unknown
    );
    // A pin whose identity is not its head's.
    let mut wrong = pin_at(f, &f.r1);
    wrong.identity_pub = f.identities[0].verifying_key();
    assert_eq!(
        follow(&wrong, &[f.g.clone(), f.r1.clone()], &all_intros(f)),
        ForeignLineage::Unknown
    );
}

/// Withholding records or intros (any subset) only stops the walk early:
/// `Same`, `Unknown` or an `Advanced` whose chain is a prefix of the full
/// one. Never a fork or an identity off the full chain.
#[test]
fn withholding_never_yields_another_identity() {
    let f = foreign();
    let records = [
        f.g.clone(),
        f.r1.clone(),
        f.r2.clone(),
        f.r2_by_b.clone(),
        f.r1_unknown.clone(),
        f.r1_body_key.clone(),
    ];
    let intros = all_intros(f);
    for pin in [pin_at(f, &f.g), pin_at(f, &f.r1)] {
        let full = follow(&pin, &records, &intros);
        let full_chain = advanced_chain(&full)
            .expect("the full set advances")
            .to_vec();
        for rmask in 0u32..(1 << records.len()) {
            let rs: Vec<LineageRecord> = (0..records.len())
                .filter(|i| rmask & (1 << i) != 0)
                .map(|i| records[i].clone())
                .collect();
            for imask in 0u32..(1 << intros.len()) {
                let is: Vec<SignedIntro> = (0..intros.len())
                    .filter(|i| imask & (1 << i) != 0)
                    .map(|i| intros[i].clone())
                    .collect();
                match follow(&pin, &rs, &is) {
                    ForeignLineage::Same | ForeignLineage::Unknown => {}
                    ForeignLineage::Advanced {
                        chain,
                        head,
                        identity_pub,
                        last_rotation,
                    } => {
                        assert!(full_chain.starts_with(&chain), "{rmask:b} {imask:b}");
                        assert_eq!(head.hash, *chain.last().unwrap());
                        let at = records.iter().find(|r| r.hash() == head.hash).unwrap();
                        assert_eq!(&identity_pub, at.identity_pub());
                        assert_eq!(&identity_pub, &last_rotation.identity_pub);
                    }
                    other => panic!("{rmask:b} {imask:b}: {other:?}"),
                }
            }
        }
    }
}

/// With a fork in the full set, a subset may hide one side; whatever it
/// yields stays on a valid branch of the full set.
#[test]
fn withholding_a_sibling_stays_on_a_branch() {
    let f = foreign();
    let records = [
        f.g.clone(),
        f.r1.clone(),
        f.r1_sibling.clone(),
        f.r2.clone(),
    ];
    let intros = all_intros(f);
    let pin = pin_at(f, &f.g);
    let branches = [vec![f.r1.hash(), f.r2.hash()], vec![f.r1_sibling.hash()]];
    for rmask in 0u32..(1 << records.len()) {
        let rs: Vec<LineageRecord> = (0..records.len())
            .filter(|i| rmask & (1 << i) != 0)
            .map(|i| records[i].clone())
            .collect();
        match follow(&pin, &rs, &intros) {
            ForeignLineage::Advanced { chain, .. } => {
                assert!(branches.iter().any(|b| b.starts_with(&chain)), "{rmask:b}");
            }
            ForeignLineage::Forked { siblings } => {
                let mut expected = vec![f.r1.hash(), f.r1_sibling.hash()];
                expected.sort();
                assert_eq!(siblings, expected);
            }
            ForeignLineage::Same | ForeignLineage::Unknown => {}
        }
    }
}

// ------------------------------------------------- legacy (TOFU) devices

/// An account migrated from before key rotation v2 (rotation spec 15,
/// owner ruling O4): a legacy genesis by A under the account's identity,
/// the Mac L added by a legacy intro signed by the account signing key.
///
/// - `lintro_l`: L, by the account key.
/// - `lintro_l_other_keys`: L's id with M's keys, by the account key
///   (two key pairs for one id).
/// - `forged_m`: M, by a key that is not the account's.
/// - `r_revokes_l`: generation 1 by A, revokes L.
/// - `r_by_l`: generation 1 by L.
/// - `intro_n`, `intro_n_other_keys`: A introduces N under the genesis,
///   once with N's keys, once with M's keys under N's id.
struct Legacy {
    account_id: Id,
    identity: IdentityKey,
    params: Vec<u8>,
    g: LineageRecord,
    lintro_l: SignedLegacyIntro,
    lintro_l_other_keys: SignedLegacyIntro,
    forged_m: SignedLegacyIntro,
    r_revokes_l: LineageRecord,
    r_by_l: LineageRecord,
    intro_n: SignedIntro,
    intro_n_other_keys: SignedIntro,
}

fn legacy_intro(
    account_id: Id,
    g: &LineageRecord,
    keys: &DeviceKeys,
    public: &DevicePublic,
    by: &HybridSigningKey,
) -> SignedLegacyIntro {
    sign_legacy_intro(
        LegacyIntroBody {
            account_id,
            genesis_hash: g.hash(),
            entry: entry(public, "Mac"),
            pop: sign_pop(keys, &account_id.0, public).unwrap(),
        },
        by,
    )
    .unwrap()
}

fn legacy() -> &'static Legacy {
    static L: OnceLock<Legacy> = OnceLock::new();
    L.get_or_init(|| {
        let n = Account::create_with_params("Projet Atlas, Camille Durand", kdf()).unwrap();
        let account_id = n.account.params.account_id;
        let keyset = n.account.keyset();
        let identity = IdentityKey::from_bytes(&keyset.identity.to_bytes()).unwrap();
        let dev = |k: &DeviceKeys, n: u8| k.public(id(n)).unwrap();
        let ka = DeviceKeys::generate_software().unwrap();
        let kl = DeviceKeys::generate_software().unwrap();
        let km = DeviceKeys::generate_software().unwrap();
        let kn = DeviceKeys::generate_software().unwrap();
        let (a, l, m, nn) = (
            dev(&ka, 0x81),
            dev(&kl, 0x82),
            dev(&km, 0x83),
            dev(&kn, 0x84),
        );
        let g = LineageRecord::Genesis(
            sign_genesis(
                GenesisBody {
                    format: LINEAGE_FORMAT,
                    account_id,
                    identity_pub: identity.verifying_key(),
                    creator: entry(&a, "iPhone"),
                    created_at: T0,
                },
                &ka,
                &identity,
            )
            .unwrap(),
        );
        let lintro_l = legacy_intro(account_id, &g, &kl, &l, &keyset.signing);
        let l_with_m_keys = km.public(l.device_id).unwrap();
        let lintro_l_other_keys =
            legacy_intro(account_id, &g, &km, &l_with_m_keys, &keyset.signing);
        let stranger = HybridSigningKey::generate().unwrap();
        let forged_m = legacy_intro(account_id, &g, &km, &m, &stranger);
        let i1 = IdentityKey::generate().unwrap();
        let i2 = IdentityKey::generate().unwrap();
        let r_revokes_l = rotation(
            account_id,
            &g,
            (&ka, a.device_id),
            vec![l.device_id],
            vec![entry(&a, "iPhone")],
            &i1,
        );
        let r_by_l = rotation(
            account_id,
            &g,
            (&kl, l.device_id),
            vec![],
            vec![entry(&a, "iPhone"), entry(&l, "Mac")],
            &i2,
        );
        let intro_n = intro(account_id, &g, (&ka, a.device_id), (&kn, &nn, "iPad"));
        let n_with_m_keys = km.public(nn.device_id).unwrap();
        let intro_n_other_keys = intro(
            account_id,
            &g,
            (&ka, a.device_id),
            (&km, &n_with_m_keys, "iPad"),
        );
        Legacy {
            account_id,
            identity,
            params: n.params_record,
            g,
            lintro_l,
            lintro_l_other_keys,
            forged_m,
            r_revokes_l,
            r_by_l,
            intro_n,
            intro_n_other_keys,
        }
    })
}

fn legacy_pin(l: &Legacy) -> ForeignPin {
    ForeignPin {
        account_id: l.account_id,
        genesis: l.g.hash(),
        head: LineageHead {
            generation: 0,
            hash: l.g.hash(),
        },
        identity_pub: l.identity.verifying_key(),
    }
}

fn with_params<'a>(l: &'a Legacy, intros: &'a [SignedLegacyIntro]) -> LegacyIntros<'a> {
    LegacyIntros {
        intros,
        genesis_params: Some(&l.params),
    }
}

fn ids(r: Vec<RosterEntry>) -> Vec<Id> {
    r.into_iter().map(|e| e.device_id).collect()
}

#[test]
fn creator_revokes_legacy_device_advances() {
    let l = legacy();
    let records = [l.g.clone(), l.r_revokes_l.clone()];
    let intros = [l.lintro_l.clone()];
    let got = follow_foreign(&legacy_pin(l), &records, &[], &with_params(l, &intros));
    assert_eq!(advanced_chain(&got), Some(&[l.r_revokes_l.hash()][..]));
    let ForeignLineage::Advanced { last_rotation, .. } = got else {
        unreachable!()
    };
    assert_eq!(last_rotation.revoked, vec![id(0x82)]);
    // Without the legacy intro too: an unknown revoked id is no reason to
    // keep the old identity.
    let got = follow_foreign(&legacy_pin(l), &records, &[], &LegacyIntros::default());
    assert_eq!(advanced_chain(&got), Some(&[l.r_revokes_l.hash()][..]));
}

#[test]
fn legacy_device_rotation_advances() {
    let l = legacy();
    let records = [l.g.clone(), l.r_by_l.clone()];
    let intros = [l.lintro_l.clone()];
    let got = follow_foreign(&legacy_pin(l), &records, &[], &with_params(l, &intros));
    assert_eq!(advanced_chain(&got), Some(&[l.r_by_l.hash()][..]));
    assert_eq!(
        ids(roster_at(&records, &[], &with_params(l, &intros), &l.g.hash()).unwrap()),
        vec![id(0x81), id(0x82)]
    );
    // An intro naming L as introducer but signed by A: refused, the
    // signature is checked under L's key from the legacy intro.
    let mut n_by_l = l.intro_n.clone();
    n_by_l.body.introducer = id(0x82);
    assert_eq!(
        ids(roster_at(&records, &[n_by_l], &with_params(l, &intros), &l.g.hash()).unwrap()),
        vec![id(0x81), id(0x82)]
    );
    // No legacy intro, no params, or params that are not the genesis
    // identity's: L is unknown, the pin stays.
    let same = |legacy: &LegacyIntros<'_>| {
        assert_eq!(
            follow_foreign(&legacy_pin(l), &records, &[], legacy),
            ForeignLineage::Same
        );
    };
    same(&LegacyIntros::default());
    same(&LegacyIntros {
        intros: &intros,
        genesis_params: None,
    });
    same(&LegacyIntros {
        intros: &intros,
        genesis_params: Some(&bob().params),
    });
    // Legacy intros never count under a rotation.
    let r = [l.g.clone(), l.r_by_l.clone()];
    assert_eq!(
        ids(roster_at(&r, &[], &with_params(l, &intros), &l.r_by_l.hash()).unwrap()),
        vec![id(0x81), id(0x82)]
    );
}

#[test]
fn forged_legacy_intro_refused() {
    let l = legacy();
    let LineageRecord::Genesis(g) = &l.g else {
        unreachable!()
    };
    let params = onepass_core::account::AccountParams::decode_verified(
        &l.params,
        &l.identity.verifying_key(),
    )
    .unwrap();
    // Signed by a key that is not the account's.
    let got = accept_legacy_intros(g, &params.signing_pub, std::slice::from_ref(&l.forged_m));
    assert!(got.entries.is_empty() && got.conflicting.is_empty());
    let records = [l.g.clone()];
    let forged = [l.forged_m.clone()];
    assert_eq!(
        ids(roster_at(&records, &[], &with_params(l, &forged), &l.g.hash()).unwrap()),
        vec![id(0x81)]
    );
    // Bound to another genesis, or to another account.
    let mut elsewhere = l.lintro_l.clone();
    elsewhere.body.genesis_hash = [9; 32];
    let mut stranger = l.lintro_l.clone();
    stranger.body.account_id = id(0x01);
    for bad in [elsewhere, stranger] {
        assert!(
            accept_legacy_intros(g, &params.signing_pub, &[bad])
                .entries
                .is_empty()
        );
    }
    // The good one, under the same key.
    let got = accept_legacy_intros(g, &params.signing_pub, std::slice::from_ref(&l.lintro_l));
    assert_eq!(ids(got.entries), vec![id(0x82)]);
}

#[test]
fn legacy_conflicting_keys_refused_in_both_orders() {
    let l = legacy();
    let records = [l.g.clone(), l.r_by_l.clone()];
    for intros in [
        [l.lintro_l.clone(), l.lintro_l_other_keys.clone()],
        [l.lintro_l_other_keys.clone(), l.lintro_l.clone()],
    ] {
        let legacy = with_params(l, &intros);
        assert_eq!(
            ids(roster_at(&records, &[], &legacy, &l.g.hash()).unwrap()),
            vec![id(0x81)]
        );
        assert_eq!(
            follow_foreign(&legacy_pin(l), &records, &[], &legacy),
            ForeignLineage::Same
        );
    }
}

#[test]
fn intro_with_two_keys_for_one_id_refused_in_both_orders() {
    let l = legacy();
    let records = [l.g.clone()];
    let none = LegacyIntros::default();
    assert_eq!(
        ids(roster_at(
            &records,
            std::slice::from_ref(&l.intro_n),
            &none,
            &l.g.hash()
        )
        .unwrap()),
        vec![id(0x81), id(0x84)]
    );
    for intros in [
        [l.intro_n.clone(), l.intro_n_other_keys.clone()],
        [l.intro_n_other_keys.clone(), l.intro_n.clone()],
    ] {
        assert_eq!(
            ids(roster_at(&records, &intros, &none, &l.g.hash()).unwrap()),
            vec![id(0x81)]
        );
    }
}

fn legacy_card(l: &Legacy) -> ContactCard {
    ContactCard {
        format: 1,
        account_id: l.account_id,
        genesis: l.g.hash(),
        head: LineageHead {
            generation: 0,
            hash: l.g.hash(),
        },
        identity_pub: l.identity.verifying_key(),
        params: l.params.clone(),
        lineage: vec![l.g.clone()],
        intros: vec![],
        legacy_intros: vec![l.lintro_l.clone()],
        genesis_params: Some(l.params.clone()),
        name: "Camille".into(),
        issued_at: T0 + 60,
    }
}

#[test]
fn card_carries_legacy_intros() {
    let l = legacy();
    let signed = SignedContactCard::sign(legacy_card(l), &l.identity).unwrap();
    let back = SignedContactCard::decode(&signed.encode()).unwrap();
    assert_eq!(back, signed);
    back.keys().unwrap();
    // A contact pinned at the genesis follows L's rotation from the card.
    let records = [l.g.clone(), l.r_by_l.clone()];
    let got = follow_foreign(
        &legacy_pin(l),
        &records,
        &back.card.intros,
        &back.card.legacy(),
    );
    assert_eq!(advanced_chain(&got), Some(&[l.r_by_l.hash()][..]));

    let refused = |f: &dyn Fn(&mut ContactCard)| {
        let mut c = legacy_card(l);
        f(&mut c);
        assert!(is_format(SignedContactCard::decode(&unsigned(c).encode())));
    };
    refused(&|c| c.genesis_params = None);
    refused(&|c| c.legacy_intros.clear());
    refused(&|c| c.genesis_params = Some(vec![1, 2, 3]));
    refused(&|c| c.legacy_intros[0].body.genesis_hash = [9; 32]);
    refused(&|c| c.legacy_intros[0].body.account_id = id(0xEE));
    refused(&|c| c.legacy_intros.push(c.legacy_intros[0].clone()));
    refused(&|c| {
        c.legacy_intros.insert(0, l.lintro_l_other_keys.clone());
    });
    // Without legacy intros, no genesis params: the plain shape.
    let mut c = legacy_card(l);
    c.legacy_intros.clear();
    c.genesis_params = None;
    SignedContactCard::decode(&unsigned(c).encode()).unwrap();
}

#[test]
fn own_card_carries_legacy_intros() {
    let (mut d, _sk) = Device::create();
    let repo = d.repo();
    let account_id = repo.account().params.account_id;
    let identity = IdentityKey::from_bytes(&repo.account().keyset().identity.to_bytes()).unwrap();
    let signing = &repo.account().keyset().signing;
    let creator_keys = DeviceKeys::generate_software().unwrap();
    let creator = creator_keys.public(id(0x91)).unwrap();
    let g = LineageRecord::Genesis(
        sign_genesis(
            GenesisBody {
                format: LINEAGE_FORMAT,
                account_id,
                identity_pub: identity.verifying_key(),
                creator: entry(&creator, "iPhone"),
                created_at: T0,
            },
            &creator_keys,
            &identity,
        )
        .unwrap(),
    );
    let kl = DeviceKeys::generate_software().unwrap();
    let mac = kl.public(id(0x92)).unwrap();
    let lintro = legacy_intro(account_id, &g, &kl, &mac, signing);
    // Not trusted on this device: dropped at the head.
    let kw = DeviceKeys::generate_software().unwrap();
    let watch = kw.public(id(0x93)).unwrap();
    let untrusted = legacy_intro(account_id, &g, &kw, &watch, signing);
    // Signed by another key: dropped.
    let ks = DeviceKeys::generate_software().unwrap();
    let tv = ks.public(id(0x94)).unwrap();
    let forged = legacy_intro(
        account_id,
        &g,
        &ks,
        &tv,
        &HybridSigningKey::generate().unwrap(),
    );

    let roster = vec![
        entry(&creator, "iPhone"),
        entry(&mac, "Mac"),
        entry(&tv, "Mac"),
    ];
    let mut trust = TrustState::new(
        account_id,
        creator.clone(),
        LineageHead {
            generation: 0,
            hash: g.hash(),
        },
        identity.verifying_key(),
        roster.clone(),
        DeviceLineageState::Current,
    );
    for e in &roster {
        trust.levels.insert(e.device_id, TrustLevel::Tofu);
    }
    let rec = |kind, id, data| {
        (
            Record {
                id,
                kind,
                version: 0,
                data,
            },
            None,
        )
    };
    let mut writes = vec![rec(RecordKind::Lineage, g.record_id(), g.encode())];
    for (n, i) in [&lintro, &untrusted, &forged].into_iter().enumerate() {
        writes.push(rec(RecordKind::DeviceIntro, id(0xA0 + n as u8), i.encode()));
    }
    repo.store_mut()
        .put_all_if_version_with_trust(writes, vec![], None, &trust)
        .unwrap();

    let card = repo.own_contact_card("Camille", T0 + 5).unwrap();
    assert_eq!(card.card.legacy_intros, vec![lintro]);
    let params = repo
        .store()
        .get(RecordKind::AccountParams, account_id)
        .unwrap()
        .unwrap()
        .data;
    assert_eq!(card.card.genesis_params, Some(params));
    let back = SignedContactCard::decode(&card.encode()).unwrap();
    assert_eq!(
        ids(roster_at(&back.card.lineage, &[], &back.card.legacy(), &g.hash()).unwrap()),
        vec![id(0x91), id(0x92)]
    );
}

#[test]
fn forged_intro_never_blocks_an_honest_one() {
    let l = legacy();
    let records = [l.g.clone()];
    let none = LegacyIntros::default();
    // N's id with other keys, a signature that verifies nowhere.
    let mut forged = l.intro_n_other_keys.clone();
    forged.sig.mldsa[0] ^= 1;
    for intros in [
        [l.intro_n.clone(), forged.clone()],
        [forged.clone(), l.intro_n.clone()],
    ] {
        assert_eq!(
            ids(roster_at(&records, &intros, &none, &l.g.hash()).unwrap()),
            vec![id(0x81), id(0x84)]
        );
    }
}

/// Copies of `r` (same body) whose device signature verifies nowhere,
/// split by where their encoding's SHA-256 falls against `r`'s.
fn bad_copies(r: &LineageRecord) -> (Vec<LineageRecord>, Vec<LineageRecord>) {
    let key = |r: &LineageRecord| sha256(&[&r.encode()]);
    let good = key(r);
    let (mut below, mut above) = (Vec::new(), Vec::new());
    for k in 0..256 {
        let LineageRecord::Rotation(mut s) = r.clone() else {
            unreachable!()
        };
        s.device_sig.mldsa[k] ^= 1;
        let bad = LineageRecord::Rotation(s);
        if key(&bad) < good {
            below.push(bad);
        } else {
            above.push(bad);
        }
        if below.len() >= MAX_FOREIGN_COPIES && above.len() >= MAX_FOREIGN_COPIES {
            break;
        }
    }
    (below, above)
}

#[test]
fn copies_capped() {
    let f = foreign();
    let (below, above) = bad_copies(&f.r1);
    let pin = pin_at(f, &f.g);
    let intros = [f.intro_b_g.clone()];
    let run = |extra: &[LineageRecord]| {
        let mut rs = vec![f.g.clone(), f.r1.clone()];
        rs.extend_from_slice(extra);
        follow(&pin, &rs, &intros)
    };
    // The good copy among the kept ones: found.
    let mut kept = below[..MAX_FOREIGN_COPIES - 1].to_vec();
    kept.extend_from_slice(&above);
    // Exact duplicates count once.
    for _ in 0..20 {
        kept.push(below[0].clone());
    }
    assert_eq!(advanced_chain(&run(&kept)), Some(&[f.r1.hash()][..]));
    // Pushed out by `MAX_FOREIGN_COPIES` smaller bad copies: the record is
    // hidden, as if withheld, never accepted wrongly.
    assert_eq!(run(&below[..MAX_FOREIGN_COPIES]), ForeignLineage::Same);
}
