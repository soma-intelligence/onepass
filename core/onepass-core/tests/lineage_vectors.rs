//! Lineage records (key rotation v2, spec 6.1 to 6.5 and 15): hashes,
//! frozen vectors, domain separation, structural refusals, strict codecs.
//!
//! The vectors in `tests/vectors/lineage/*.hex` were generated once by
//! `generate_vectors` (ignored) and are frozen: the tests read them back.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::OnceLock;

use aws_lc_rs::digest::{SHA256, digest};
use data_encoding::HEXLOWER;
use onepass_core::crypto::{
    HybridSignature, HybridSigningKey, HybridVerifyingKey, IdentityKey, IdentitySignature,
    IdentityVerifyingKey,
};
use onepass_core::device_keys::{DEVICE_POP_DOMAIN, DeviceKeys, DevicePublic, sign_pop};
use onepass_core::devices::{DeviceKind, DeviceMode};
use onepass_core::lineage::{
    GENESIS_DOMAIN, GENESIS_IDENTITY_DOMAIN, GenesisBody, INTRO_DOMAIN, IntroBody,
    LEGACY_DEVICE_DOMAIN, LegacyIntroBody, LineageRecord, ROTATION_DOMAIN,
    ROTATION_IDENTITY_DOMAIN, RosterEntry, RotationBody, RotationReason, Signed, SignedIntro,
    SignedLegacyIntro, delivery_id, identity_id, intro_id, rotation_code, sign_genesis, sign_intro,
    sign_legacy_intro, sign_rotation, verify_genesis, verify_intro, verify_intro_identity,
    verify_legacy_intro, verify_rotation,
};
use onepass_core::manifest::SeenManifest;
use onepass_core::{Error, Id, IntegrityError};

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let all: Vec<u8> = parts.concat();
    let mut out = [0u8; 32];
    out.copy_from_slice(digest(&SHA256, &all).as_ref());
    out
}

fn postcard_of<T: serde::Serialize>(v: &T) -> Vec<u8> {
    postcard::to_allocvec(v).unwrap()
}

fn id(n: u8) -> Id {
    Id([n; 16])
}

struct Dev {
    keys: DeviceKeys,
    public: DevicePublic,
}

fn dev(n: u8) -> Dev {
    let keys = DeviceKeys::generate_software().unwrap();
    let public = keys.public(id(n)).unwrap();
    Dev { keys, public }
}

fn entry(d: &Dev, name: &str) -> RosterEntry {
    RosterEntry {
        device_id: d.public.device_id,
        sign_pub: d.public.sign_pub.clone(),
        kem_pub: d.public.kem_pub.clone(),
        name: name.to_string(),
        kind: DeviceKind::Phone,
        mode: DeviceMode::Personal,
        introduced_by: None,
    }
}

/// One identity key for the whole file: SLH-DSA key generation is slow.
fn identity() -> &'static (IdentityKey, IdentityVerifyingKey) {
    static ID: OnceLock<(IdentityKey, IdentityVerifyingKey)> = OnceLock::new();
    ID.get_or_init(|| {
        let k = IdentityKey::generate().unwrap();
        let v = k.verifying_key();
        (k, v)
    })
}

/// A signature of the right shape that verifies nowhere: enough for the
/// structural checks, which run before any signature check.
fn dummy_hybrid() -> HybridSignature {
    HybridSignature {
        mldsa: vec![0; 4627],
        ed25519: [0; 64],
    }
}

fn dummy_identity_sig() -> IdentitySignature {
    postcard::from_bytes(&postcard_of(&serde_bytes::ByteBuf::from(vec![0u8; 29792]))).unwrap()
}

fn rotation_body(devs: &[&Dev]) -> RotationBody {
    // devs[0] is the rotator.
    let mut roster: Vec<RosterEntry> = devs.iter().map(|d| entry(d, "device")).collect();
    roster.sort_by_key(|e| e.device_id);
    let rotator = devs[0].public.device_id;
    let deliveries = roster
        .iter()
        .filter(|e| e.device_id != rotator)
        .map(|e| (e.device_id, [e.device_id.0[0]; 32]))
        .collect();
    RotationBody {
        format: 1,
        account_id: id(0xA0),
        generation: 1,
        parent: [7; 32],
        rotator,
        reason: RotationReason::Revoke,
        revoked: vec![id(0xF1)],
        roster,
        identity_pub: identity().1.clone(),
        params_hash: [1; 32],
        keyset_hash: [2; 32],
        deliveries,
        from_heads: BTreeMap::from([(
            id(0xC0),
            SeenManifest {
                seq: 4,
                hash: [9; 32],
            },
        )]),
        issued_at: 1_761_800_000,
    }
}

fn unsigned_rotation(body: RotationBody) -> LineageRecord {
    LineageRecord::Rotation(Signed {
        body,
        device_sig: dummy_hybrid(),
        identity_sig: dummy_identity_sig(),
    })
}

/// The vector directory. `ONEPASS_CORE_VECTORS` points at a copy of
/// `tests/vectors` when the test runs away from the source tree (the Android
/// emulator, see android/scripts/test-core-emulator.sh).
fn vectors_root() -> PathBuf {
    std::env::var_os("ONEPASS_CORE_VECTORS").map_or_else(
        || PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors"),
        PathBuf::from,
    )
}

fn vectors_dir() -> PathBuf {
    vectors_root().join("lineage")
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

fn hex(v: &BTreeMap<String, String>, key: &str) -> Vec<u8> {
    HEXLOWER.decode(v[key].as_bytes()).unwrap()
}

#[test]
fn lineage_hash_prefixes() {
    let a = dev(1);
    let b = dev(2);
    let genesis = LineageRecord::Genesis(Signed {
        body: GenesisBody {
            format: 1,
            account_id: id(0xA0),
            identity_pub: identity().1.clone(),
            creator: entry(&a, "iPhone"),
            created_at: 1_761_000_000,
        },
        device_sig: dummy_hybrid(),
        identity_sig: dummy_identity_sig(),
    });
    let LineageRecord::Genesis(g) = &genesis else {
        unreachable!()
    };
    assert_eq!(
        genesis.hash(),
        sha256(&[b"onepass/lineage/v1", &[0x00], &postcard_of(&g.body)])
    );
    assert_eq!(genesis.generation(), 0);
    assert_eq!(genesis.parent(), None);

    let rotation = unsigned_rotation(rotation_body(&[&a, &b]));
    let LineageRecord::Rotation(r) = &rotation else {
        unreachable!()
    };
    assert_eq!(
        rotation.hash(),
        sha256(&[b"onepass/lineage/v1", &[0x01], &postcard_of(&r.body)])
    );
    assert_ne!(genesis.hash(), rotation.hash());
    assert_eq!(rotation.generation(), 1);
    assert_eq!(rotation.parent(), Some([7; 32]));
    assert_eq!(&rotation.record_id().0, &rotation.hash()[..16]);
}

#[test]
fn derived_ids_use_their_prefixes() {
    let a = dev(1);
    let h = [3u8; 32];
    assert_eq!(
        delivery_id(&h, id(5)).0,
        sha256(&[b"onepass/delivery-id/v1", &h, &id(5).0])[..16]
    );
    assert_ne!(delivery_id(&h, id(5)), delivery_id(&h, id(6)));
    let v = &identity().1;
    assert_eq!(
        identity_id(v).0,
        sha256(&[b"onepass/identity-id/v1", v.as_bytes()])[..16]
    );
    let body = IntroBody {
        format: 1,
        account_id: id(0xA0),
        head: h,
        entry: entry(&a, "iPhone"),
        introducer: id(9),
        pop: dummy_hybrid(),
    };
    assert_eq!(
        intro_id(&body).0,
        sha256(&[b"onepass/intro-id/v1", &postcard_of(&body)])[..16]
    );
}

#[test]
fn golden_vectors() {
    for name in ["genesis.hex", "rotation.hex"] {
        let v = read_vector(name);
        let bytes = hex(&v, "record");
        let rec = LineageRecord::decode(&bytes).unwrap();
        assert_eq!(rec.encode(), bytes, "{name}");
        assert_eq!(rec.hash().as_slice(), hex(&v, "hash"), "{name} hash");
        assert_eq!(rec.record_id().0.as_slice(), hex(&v, "id"), "{name} id");
        assert_eq!(
            rotation_code(&rec.hash()).to_string(),
            v["code"],
            "{name} code"
        );
        assert_eq!(rec.generation().to_string(), v["generation"], "{name}");
        match &rec {
            LineageRecord::Genesis(g) => {
                verify_genesis(g).unwrap();
                assert_eq!(
                    identity_id(&g.body.identity_pub).0.as_slice(),
                    hex(&v, "identity_id")
                );
            }
            LineageRecord::Rotation(r) => {
                let rotator = r
                    .body
                    .roster
                    .iter()
                    .find(|e| e.device_id == r.body.rotator)
                    .unwrap();
                verify_rotation(r, &rotator.sign_pub).unwrap();
                let (to, _) = r.body.deliveries[0];
                assert_eq!(
                    delivery_id(&rec.hash(), to).0.as_slice(),
                    hex(&v, "delivery_id")
                );
            }
        }
    }

    let v = read_vector("intro.hex");
    let bytes = hex(&v, "record");
    let intro = SignedIntro::decode(&bytes).unwrap();
    assert_eq!(intro.encode(), bytes);
    assert_eq!(intro_id(&intro.body).0.as_slice(), hex(&v, "id"));
    let introducer: HybridVerifyingKey = postcard::from_bytes(&hex(&v, "introducer_pub")).unwrap();
    verify_intro(&intro, &introducer).unwrap();

    let v = read_vector("legacy_intro.hex");
    let bytes = hex(&v, "record");
    let legacy = SignedLegacyIntro::decode(&bytes).unwrap();
    assert_eq!(legacy.encode(), bytes);
    let account: HybridVerifyingKey = postcard::from_bytes(&hex(&v, "account_pub")).unwrap();
    verify_legacy_intro(&legacy, &account).unwrap();
}

#[test]
fn rotation_code_known_value() {
    let v = read_vector("rotation_code_zero.hex");
    let code = rotation_code(&[0u8; 32]);
    assert_eq!(code.to_string(), v["code"]);
    assert!(code < 1_000_000);
}

#[test]
fn every_domain_is_separated() {
    let msg = b"the same message under every domain";
    let hybrid_domains: [&[u8]; 5] = [
        DEVICE_POP_DOMAIN,
        INTRO_DOMAIN,
        GENESIS_DOMAIN,
        ROTATION_DOMAIN,
        LEGACY_DEVICE_DOMAIN,
    ];
    let d = dev(1);
    for (i, a) in hybrid_domains.iter().enumerate() {
        let sig = d.keys.sign(a, msg).unwrap();
        for (j, b) in hybrid_domains.iter().enumerate() {
            let r = d.public.sign_pub.verify(b, msg, &sig);
            if i == j {
                r.unwrap();
            } else {
                assert_eq!(
                    r,
                    Err(Error::Integrity(IntegrityError::Signature)),
                    "{} accepted under {}",
                    String::from_utf8_lossy(a),
                    String::from_utf8_lossy(b)
                );
            }
        }
    }
    let identity_domains: [&[u8]; 3] = [
        GENESIS_IDENTITY_DOMAIN,
        ROTATION_IDENTITY_DOMAIN,
        INTRO_DOMAIN,
    ];
    let (key, vk) = identity();
    for (i, a) in identity_domains.iter().enumerate() {
        let sig = key.sign(a, msg).unwrap();
        for (j, b) in identity_domains.iter().enumerate() {
            let r = vk.verify(b, msg, &sig);
            if i == j {
                r.unwrap();
            } else {
                assert_eq!(r, Err(Error::Integrity(IntegrityError::Signature)));
            }
        }
    }
}

#[test]
fn signatures_made_under_another_domain_are_refused() {
    let a = dev(1);
    let b = dev(2);
    let (ikey, _) = identity();
    let body = rotation_body(&[&a, &b]);
    let msg = postcard_of(&body);
    let good = sign_rotation(body.clone(), &a.keys, ikey).unwrap();
    verify_rotation(&good, &a.public.sign_pub).unwrap();

    // Device signature under the genesis domain.
    let mut forged = good.clone();
    forged.device_sig = a.keys.sign(GENESIS_DOMAIN, &msg).unwrap();
    assert_eq!(
        verify_rotation(&forged, &a.public.sign_pub),
        Err(Error::Integrity(IntegrityError::Signature))
    );
    // Identity signature under the genesis identity domain.
    let mut forged = good.clone();
    forged.identity_sig = ikey.sign(GENESIS_IDENTITY_DOMAIN, &msg).unwrap();
    assert_eq!(
        verify_rotation(&forged, &a.public.sign_pub),
        Err(Error::Integrity(IntegrityError::Signature))
    );
    // Wrong rotator key.
    assert_eq!(
        verify_rotation(&good, &b.public.sign_pub),
        Err(Error::Integrity(IntegrityError::Signature))
    );
    // Body tampered after signing.
    let mut forged = good;
    forged.body.issued_at += 1;
    assert_eq!(
        verify_rotation(&forged, &a.public.sign_pub),
        Err(Error::Integrity(IntegrityError::Signature))
    );
}

fn refused(body: RotationBody) {
    let bytes = unsigned_rotation(body).encode();
    assert!(
        matches!(LineageRecord::decode(&bytes), Err(Error::InvalidFormat(_))),
        "structural check let a bad body through"
    );
}

#[test]
fn structural_checks_refuse() {
    let a = dev(1);
    let b = dev(2);
    let c = dev(3);
    let good = rotation_body(&[&a, &b, &c]);
    LineageRecord::decode(&unsigned_rotation(good.clone()).encode()).unwrap();
    let rotator = good.rotator;

    // revoked unsorted
    let mut x = good.clone();
    x.revoked = vec![id(0xF2), id(0xF1)];
    refused(x);
    // revoked with a duplicate
    let mut x = good.clone();
    x.revoked = vec![id(0xF1), id(0xF1)];
    refused(x);
    // rotator in revoked
    let mut x = good.clone();
    x.revoked = vec![rotator];
    refused(x);
    // roster without the rotator (deliveries follow the roster)
    let mut x = good.clone();
    x.roster.retain(|e| e.device_id != rotator);
    x.deliveries = x.roster.iter().map(|e| (e.device_id, [1; 32])).collect();
    refused(x);
    // roster containing a revoked id
    let mut x = good.clone();
    x.revoked = vec![b.public.device_id];
    refused(x);
    // roster with 65 entries
    let mut x = good.clone();
    x.roster = (1..=65u8)
        .map(|n| {
            let mut e = entry(&a, "d");
            e.device_id = id(n);
            e
        })
        .collect();
    x.rotator = x.roster[0].device_id;
    x.deliveries = x.roster[1..]
        .iter()
        .map(|e| (e.device_id, [1; 32]))
        .collect();
    assert_eq!(x.roster.len(), 65);
    refused(x);
    // a name of 65 chars
    let mut x = good.clone();
    x.roster[0].name = "é".repeat(65);
    refused(x);
    // deliveries naming the rotator
    let mut x = good.clone();
    x.deliveries.push((rotator, [1; 32]));
    x.deliveries.sort();
    refused(x);
    // deliveries not equal to roster minus rotator
    let mut x = good.clone();
    x.deliveries.pop();
    refused(x);
    let mut x = good.clone();
    x.deliveries[0].0 = id(0xEE);
    refused(x);
    // generation 0 on a rotation
    let mut x = good.clone();
    x.generation = 0;
    refused(x);
    // unknown format
    let mut x = good.clone();
    x.format = 2;
    refused(x);
    // roster unsorted
    let mut x = good;
    x.roster.reverse();
    refused(x);

    // A name of exactly 64 chars is fine.
    let mut ok = rotation_body(&[&a, &b]);
    ok.roster[0].name = "é".repeat(64);
    LineageRecord::decode(&unsigned_rotation(ok).encode()).unwrap();
}

#[test]
fn trailing_bytes_refused() {
    let a = dev(1);
    let b = dev(2);
    let mut bytes = unsigned_rotation(rotation_body(&[&a, &b])).encode();
    bytes.push(0);
    assert!(matches!(
        LineageRecord::decode(&bytes),
        Err(Error::InvalidFormat(_))
    ));
    let v = read_vector("intro.hex");
    let mut bytes = hex(&v, "record");
    bytes.push(0);
    assert!(SignedIntro::decode(&bytes).is_err());
    let v = read_vector("legacy_intro.hex");
    let mut bytes = hex(&v, "record");
    bytes.push(0);
    assert!(SignedLegacyIntro::decode(&bytes).is_err());
}

#[test]
fn non_canonical_refused() {
    let a = dev(1);
    let b = dev(2);
    let body = rotation_body(&[&a, &b]);
    let good = unsigned_rotation(body.clone()).encode();
    LineageRecord::decode(&good).unwrap();

    // `issued_at` is the last field, a zigzag varint: 1_761_800_000 takes
    // 5 bytes. Re-encode the same value with a padded varint: same value,
    // longer encoding.
    let tail = postcard_of(&body.issued_at);
    // Record = variant tag (1 byte) || body || signatures.
    let end = 1 + postcard_of(&body).len();
    let pos = end - tail.len();
    assert_eq!(&good[pos..end], tail.as_slice());
    let mut padded = good[..pos].to_vec();
    let mut t = tail.clone();
    *t.last_mut().unwrap() |= 0x80;
    padded.extend_from_slice(&t);
    padded.push(0x00);
    // postcard itself reads the padded varint as the same value, so only
    // the canonical re-encoding check can refuse it.
    let mut v = t.clone();
    v.push(0x00);
    assert_eq!(postcard::from_bytes::<i64>(&v).unwrap(), body.issued_at);
    padded.extend_from_slice(&good[end..]);
    assert_ne!(padded, good);
    assert!(
        LineageRecord::decode(&padded).is_err(),
        "an over-long varint must be refused"
    );

    // An unsorted map re-encodes sorted, so it differs from its input.
    let mut two = body.clone();
    two.from_heads.insert(
        id(0xC1),
        SeenManifest {
            seq: 1,
            hash: [1; 32],
        },
    );
    let enc = unsigned_rotation(two.clone()).encode();
    // Swap the two map entries in the byte stream.
    let e0 = postcard_of(&(
        id(0xC0),
        SeenManifest {
            seq: 4,
            hash: [9; 32],
        },
    ));
    let e1 = postcard_of(&(
        id(0xC1),
        SeenManifest {
            seq: 1,
            hash: [1; 32],
        },
    ));
    let sorted: Vec<u8> = [e0.clone(), e1.clone()].concat();
    let swapped: Vec<u8> = [e1, e0].concat();
    let pos = enc
        .windows(sorted.len())
        .position(|w| w == sorted.as_slice())
        .unwrap();
    let mut forged = enc.clone();
    forged[pos..pos + sorted.len()].copy_from_slice(&swapped);
    LineageRecord::decode(&enc).unwrap();
    assert!(LineageRecord::decode(&forged).is_err());

    // A wrong-length signature is refused at decode.
    let mut short = unsigned_rotation(body);
    if let LineageRecord::Rotation(r) = &mut short {
        r.device_sig.mldsa.pop();
    }
    assert!(LineageRecord::decode(&short.encode()).is_err());
}

#[test]
fn genesis_and_intros_sign_and_verify() {
    let a = dev(1);
    let b = dev(2);
    let (ikey, ivk) = identity();

    let genesis = sign_genesis(
        GenesisBody {
            format: 1,
            account_id: id(0xA0),
            identity_pub: ivk.clone(),
            creator: entry(&a, "iPhone"),
            created_at: 1,
        },
        &a.keys,
        ikey,
    )
    .unwrap();
    verify_genesis(&genesis).unwrap();
    let mut other = genesis.clone();
    other.body.created_at = 2;
    assert_eq!(
        verify_genesis(&other),
        Err(Error::Integrity(IntegrityError::Signature))
    );

    // B introduced by A.
    let account = id(0xA0);
    let pop = sign_pop(&b.keys, &account.0, &b.public).unwrap();
    let mut e = entry(&b, "Mac");
    e.introduced_by = Some(a.public.device_id);
    let body = IntroBody {
        format: 1,
        account_id: account,
        head: [5; 32],
        entry: e,
        introducer: a.public.device_id,
        pop,
    };
    let intro = sign_intro(body.clone(), &a.keys, None).unwrap();
    verify_intro(&intro, &a.public.sign_pub).unwrap();
    assert_eq!(SignedIntro::decode(&intro.encode()).unwrap(), intro);
    assert_eq!(
        verify_intro(&intro, &b.public.sign_pub),
        Err(Error::Integrity(IntegrityError::Signature))
    );
    // No identity signature on an ordinary intro.
    assert_eq!(
        verify_intro_identity(&intro, ivk),
        Err(Error::Integrity(IntegrityError::Signature))
    );
    // A pop made for another account is refused.
    let mut wrong = body.clone();
    wrong.pop = sign_pop(&b.keys, &id(0xA1).0, &b.public).unwrap();
    let intro = sign_intro(wrong, &a.keys, None).unwrap();
    assert_eq!(
        verify_intro(&intro, &a.public.sign_pub),
        Err(Error::Integrity(IntegrityError::Signature))
    );
    // Kit self-intro: introducer = self, signed also by the identity.
    let mut selfie = body;
    selfie.introducer = b.public.device_id;
    let intro = sign_intro(selfie, &b.keys, Some(ikey)).unwrap();
    verify_intro(&intro, &b.public.sign_pub).unwrap();
    verify_intro_identity(&intro, ivk).unwrap();
    assert_eq!(SignedIntro::decode(&intro.encode()).unwrap(), intro);

    // Legacy intro.
    let account_key = HybridSigningKey::generate().unwrap();
    let legacy = sign_legacy_intro(
        LegacyIntroBody {
            account_id: account,
            genesis_hash: [8; 32],
            entry: entry(&b, "Mac"),
            pop: sign_pop(&b.keys, &account.0, &b.public).unwrap(),
        },
        &account_key,
    )
    .unwrap();
    let avk = account_key.verifying_key().unwrap();
    verify_legacy_intro(&legacy, &avk).unwrap();
    assert_eq!(SignedLegacyIntro::decode(&legacy.encode()).unwrap(), legacy);
    assert_eq!(
        verify_legacy_intro(&legacy, &a.public.sign_pub),
        Err(Error::Integrity(IntegrityError::Signature))
    );
}

/// Run once to (re)create the frozen files: `cargo test -p onepass-core
/// --test lineage_vectors -- --ignored generate_vectors`. The files are
/// committed; the tests above only read them.
#[test]
#[ignore]
fn generate_vectors() {
    let a = dev(0x11);
    let b = dev(0x22);
    let (ikey, ivk) = identity();
    let account = id(0xA0);
    let h = |b: &[u8]| HEXLOWER.encode(b);
    let write = |name: &str, lines: Vec<(&str, String)>| {
        let mut s = String::from("# frozen lineage vector, do not regenerate\n");
        for (k, v) in lines {
            s.push_str(&format!("{k}={v}\n"));
        }
        std::fs::write(vectors_dir().join(name), s).unwrap();
    };

    let genesis = sign_genesis(
        GenesisBody {
            format: 1,
            account_id: account,
            identity_pub: ivk.clone(),
            creator: entry(&a, "iPhone"),
            created_at: 1_761_000_000,
        },
        &a.keys,
        ikey,
    )
    .unwrap();
    let genesis = LineageRecord::Genesis(genesis);
    write(
        "genesis.hex",
        vec![
            ("record", h(&genesis.encode())),
            ("hash", h(&genesis.hash())),
            ("id", h(&genesis.record_id().0)),
            ("code", rotation_code(&genesis.hash()).to_string()),
            ("generation", "0".into()),
            ("identity_id", h(&identity_id(ivk).0)),
        ],
    );

    let mut body = rotation_body(&[&a, &b]);
    body.parent = genesis.hash();
    let rotation = LineageRecord::Rotation(sign_rotation(body, &a.keys, ikey).unwrap());
    let LineageRecord::Rotation(r) = &rotation else {
        unreachable!()
    };
    let (to, _) = r.body.deliveries[0];
    write(
        "rotation.hex",
        vec![
            ("record", h(&rotation.encode())),
            ("hash", h(&rotation.hash())),
            ("id", h(&rotation.record_id().0)),
            ("code", rotation_code(&rotation.hash()).to_string()),
            ("generation", "1".into()),
            ("delivery_id", h(&delivery_id(&rotation.hash(), to).0)),
        ],
    );

    let mut e = entry(&b, "Mac");
    e.introduced_by = Some(a.public.device_id);
    let intro = sign_intro(
        IntroBody {
            format: 1,
            account_id: account,
            head: rotation.hash(),
            entry: e,
            introducer: a.public.device_id,
            pop: sign_pop(&b.keys, &account.0, &b.public).unwrap(),
        },
        &a.keys,
        None,
    )
    .unwrap();
    write(
        "intro.hex",
        vec![
            ("record", h(&intro.encode())),
            ("id", h(&intro_id(&intro.body).0)),
            ("introducer_pub", h(&postcard_of(&a.public.sign_pub))),
        ],
    );

    let account_key = HybridSigningKey::generate().unwrap();
    let legacy = sign_legacy_intro(
        LegacyIntroBody {
            account_id: account,
            genesis_hash: genesis.hash(),
            entry: entry(&b, "Mac"),
            pop: sign_pop(&b.keys, &account.0, &b.public).unwrap(),
        },
        &account_key,
    )
    .unwrap();
    write(
        "legacy_intro.hex",
        vec![
            ("record", h(&legacy.encode())),
            (
                "account_pub",
                h(&postcard_of(&account_key.verifying_key().unwrap())),
            ),
        ],
    );

    write(
        "rotation_code_zero.hex",
        vec![("code", rotation_code(&[0u8; 32]).to_string())],
    );
}

/// Sharing plan 3 Task 3 (ruling B-3): `Recover` is appended to the
/// reasons, so the other four keep their encoding (the golden vectors
/// above still hold) and it takes the next index.
#[test]
fn recover_reason_encoding_appended() {
    let reasons = [
        RotationReason::Revoke,
        RotationReason::Rotate,
        RotationReason::RotateWithPassword,
        RotationReason::Reapply,
        RotationReason::Finish,
        RotationReason::Recover,
    ];
    for (n, r) in reasons.iter().enumerate() {
        assert_eq!(postcard_of(r), vec![n as u8]);
    }
    let a = dev(1);
    let mut body = rotation_body(&[&a]);
    body.reason = RotationReason::Recover;
    let bytes = unsigned_rotation(body.clone()).encode();
    assert_eq!(
        LineageRecord::decode(&bytes).unwrap(),
        unsigned_rotation(body)
    );
}

/// Ruling B-3: the roster of a `Recover` rotation is its rotator alone.
#[test]
fn recover_roster_is_rotator_only() {
    let a = dev(1);
    let b = dev(2);
    let mut body = rotation_body(&[&a, &b]);
    body.reason = RotationReason::Recover;
    refused(body.clone());
    // The same roster is fine for any other reason.
    body.reason = RotationReason::Revoke;
    LineageRecord::decode(&unsigned_rotation(body).encode()).unwrap();
}
