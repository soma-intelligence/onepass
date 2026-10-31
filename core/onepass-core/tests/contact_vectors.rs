//! Contact cards (sharing spec 5.2, plan rulings A-3, A-4, A-6): strict
//! codec, domain-separated identity signature, keys from the signed params,
//! name rules, fingerprints, safety numbers, pair ids, frozen vectors, and
//! the account's own card.
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
    CONTACT_CARD_DOMAIN, ContactCard, SignedContactCard, fingerprint, format_safety_number,
    pair_id, safety_number,
};
use onepass_core::crypto::{IdentityKey, IdentitySignature};
use onepass_core::device_keys::{DeviceKeys, DevicePublic, sign_pop};
use onepass_core::devices::{DeviceKind, DeviceMode};
use onepass_core::lineage::{
    GENESIS_IDENTITY_DOMAIN, GenesisBody, IntroBody, LINEAGE_FORMAT, LineageRecord, RosterEntry,
    SignedIntro, identity_id, intro_id, sign_genesis, sign_intro,
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

/// A test account with a signed genesis and, optionally, one intro under
/// it. SLH-DSA signing is slow: each party is built once per process.
struct Party {
    account_id: Id,
    identity: IdentityKey,
    params: Vec<u8>,
    genesis: LineageRecord,
    intros: Vec<SignedIntro>,
}

fn party(device: u8, with_intro: bool) -> Party {
    let n = Account::create_with_params("Projet Atlas, Camille Durand", kdf()).unwrap();
    let account_id = n.account.params.account_id;
    let identity = IdentityKey::from_bytes(&n.account.keyset().identity.to_bytes()).unwrap();
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
    let mut intros = Vec::new();
    if with_intro {
        let other = DeviceKeys::generate_software().unwrap();
        let other_pub = other.public(id(device + 1)).unwrap();
        let mut e = entry(&other_pub, "Mac");
        e.introduced_by = Some(public.device_id);
        intros.push(
            sign_intro(
                IntroBody {
                    format: LINEAGE_FORMAT,
                    account_id,
                    head: genesis.hash(),
                    entry: e,
                    introducer: public.device_id,
                    pop: sign_pop(&other, &account_id.0, &other_pub).unwrap(),
                },
                &keys,
                None,
            )
            .unwrap(),
        );
    }
    Party {
        account_id,
        identity,
        params: n.params_record,
        genesis,
        intros,
    }
}

fn card_of(p: &Party, name: &str) -> ContactCard {
    ContactCard {
        format: 1,
        account_id: p.account_id,
        genesis: p.genesis.hash(),
        head: LineageHead {
            generation: 0,
            hash: p.genesis.hash(),
        },
        identity_pub: p.identity.verifying_key(),
        params: p.params.clone(),
        lineage: vec![p.genesis.clone()],
        intros: p.intros.clone(),
        name: name.into(),
        issued_at: T0 + 60,
    }
}

fn alice() -> &'static (Party, SignedContactCard) {
    static A: OnceLock<(Party, SignedContactCard)> = OnceLock::new();
    A.get_or_init(|| {
        let p = party(0x11, true);
        let card = SignedContactCard::sign(card_of(&p, "Alice"), &p.identity).unwrap();
        (p, card)
    })
}

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
    refused(&|c| c.head.generation = 1);
    refused(&|c| c.account_id = id(0xEE));
    refused(&|c| c.identity_pub = bob().identity.verifying_key());
    refused(&|c| c.params = vec![1, 2, 3]);
    refused(&|c| c.lineage.push(c.lineage[0].clone()));
    refused(&|c| c.intros.push(c.intros[0].clone()));
    refused(&|c| c.intros[0].body.head = [9; 32]);
}

#[test]
fn card_intros_sorted() {
    // Two intros under the head, in both orders: only the sorted one.
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

    let account_id = repo.account().params.account_id;
    let identity = &IdentityKey::from_bytes(&repo.account().keyset().identity.to_bytes()).unwrap();
    let me_keys = DeviceKeys::generate_software().unwrap();
    let me = me_keys
        .public(repo.chain().device_id.unwrap_or_else(Id::new))
        .unwrap();
    let mac_keys = DeviceKeys::generate_software().unwrap();
    let mac = mac_keys.public(Id::new()).unwrap();
    let ipad_keys = DeviceKeys::generate_software().unwrap();
    let ipad = ipad_keys.public(Id::new()).unwrap();
    let genesis = LineageRecord::Genesis(
        sign_genesis(
            GenesisBody {
                format: LINEAGE_FORMAT,
                account_id,
                identity_pub: identity.verifying_key(),
                creator: entry(&me, "iPhone"),
                created_at: T0,
            },
            &me_keys,
            identity,
        )
        .unwrap(),
    );
    let intro_of = |p: &DevicePublic, k: &DeviceKeys, name: &str| {
        let mut e = entry(p, name);
        e.introduced_by = Some(me.device_id);
        sign_intro(
            IntroBody {
                format: LINEAGE_FORMAT,
                account_id,
                head: genesis.hash(),
                entry: e,
                introducer: me.device_id,
                pop: sign_pop(k, &account_id.0, p).unwrap(),
            },
            &me_keys,
            None,
        )
        .unwrap()
    };
    // The Mac is in the roster; the iPad's intro was never accepted.
    let mac_intro = intro_of(&mac, &mac_keys, "Mac");
    let ipad_intro = intro_of(&ipad, &ipad_keys, "iPad");
    let mut roster = vec![entry(&me, "iPhone"), {
        let mut e = entry(&mac, "Mac");
        e.introduced_by = Some(me.device_id);
        e
    }];
    roster.sort_by_key(|e| e.device_id);
    let head = LineageHead {
        generation: 0,
        hash: genesis.hash(),
    };
    let mut trust = TrustState::new(
        account_id,
        me.clone(),
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
    let writes = vec![
        rec(RecordKind::Lineage, genesis.record_id(), genesis.encode()),
        rec(
            RecordKind::DeviceIntro,
            intro_id(&mac_intro.body),
            mac_intro.encode(),
        ),
        rec(
            RecordKind::DeviceIntro,
            intro_id(&ipad_intro.body),
            ipad_intro.encode(),
        ),
    ];
    repo.store_mut()
        .put_all_if_version_with_trust(writes, vec![], None, &trust)
        .unwrap();

    let card = repo.own_contact_card("Alice", T0 + 5).unwrap();
    let c = &card.card;
    assert_eq!(c.account_id, account_id);
    assert_eq!(c.genesis, genesis.hash());
    assert_eq!(c.head, head);
    assert_eq!(c.lineage, vec![genesis.clone()]);
    assert_eq!(c.intros, vec![mac_intro]);
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
