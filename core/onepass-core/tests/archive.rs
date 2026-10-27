//! Encrypted OnePass archive (spec 5): round trips, refusals and the pinned
//! wire encoding. Accounts and archives use the dev KDF floor.

use std::sync::OnceLock;

use onepass_core::account::{Account, NewAccount};
use onepass_core::archive::format::{
    FORMAT, Header, MAGIC, Payload, Recipient, SIGN_DOMAIN, Signed, decode_container,
    encode_container, envelope_context, signed_digest,
};
use onepass_core::archive::{
    ArchiveKind, ArchivedVault, CURRENT_SCHEMA, Contents, Unlock, backup, export, inspect, open,
    restore_plan,
};
use onepass_core::crypto::{
    Aad, BlobKind, HybridSignature, KdfParams, SymmetricKey, random_array, seal, wrap_key,
};
use onepass_core::model::{FieldValue, Item, ItemType, new_item};
use onepass_core::vault::VaultMeta;
use onepass_core::{Error, Id, IntegrityError, ValidationError};
use zeroize::Zeroizing;

const PASSPHRASE: &str = "quartz lantern oyster meadow 91";
const OTHER_PASSPHRASE: &str = "violet harbor cobalt thistle 27";

fn kdf() -> KdfParams {
    KdfParams {
        m_kib: 8192,
        t: 1,
        p: 1,
        salt: random_array().unwrap(),
    }
}

/// Two accounts shared by the tests: identity signing is slow in debug.
fn alice() -> &'static NewAccount {
    static A: OnceLock<NewAccount> = OnceLock::new();
    A.get_or_init(|| Account::create_with_params("alice pw", kdf()).unwrap())
}

fn bob() -> &'static NewAccount {
    static B: OnceLock<NewAccount> = OnceLock::new();
    B.get_or_init(|| Account::create_with_params("bob pw", kdf()).unwrap())
}

fn meta(name: &str) -> VaultMeta {
    VaultMeta {
        name: name.into(),
        icon: "key".into(),
        color: "blue".into(),
        travel_safe: false,
        mcp_access: false,
    }
}

fn set(item: &mut Item, field: &str, value: FieldValue) {
    item.field_mut(field).unwrap().value = value;
}

/// Two vaults with items of several types, secrets included.
fn vaults() -> Vec<ArchivedVault> {
    let v1 = Id::new();
    let v2 = Id::new();

    let mut login = new_item(ItemType::Login, v1, "Example");
    set(
        &mut login,
        "username",
        FieldValue::Text("alice@example.com".into()),
    );
    set(
        &mut login,
        "password",
        FieldValue::Password(Zeroizing::new("s3cret-example-pw".into())),
    );
    let mut note = new_item(ItemType::SecureNote, v1, "Note");
    note.notes = "synthetic note".into();
    let mut card = new_item(ItemType::CreditCard, v2, "Card");
    set(
        &mut card,
        "number",
        FieldValue::Concealed(Zeroizing::new("4111111111111111".into())),
    );
    set(
        &mut card,
        "cvv",
        FieldValue::Concealed(Zeroizing::new("123".into())),
    );
    let mut trashed = new_item(ItemType::Password, v2, "Old");
    trashed.archived = true;

    vec![
        ArchivedVault {
            id: v1,
            meta: meta("Personnel"),
            items: vec![login, note],
        },
        ArchivedVault {
            id: v2,
            meta: meta("Travail"),
            items: vec![card, trashed],
        },
    ]
}

fn alice_backup(passphrase: bool) -> (Vec<ArchivedVault>, Vec<u8>) {
    let v = vaults();
    let pp = passphrase.then(|| (PASSPHRASE, kdf()));
    let bytes = backup(&alice().account, v.clone(), pp).unwrap();
    (v, bytes)
}

fn payload(header: &Header, vaults: Vec<ArchivedVault>) -> Payload {
    Payload {
        archive_id: header.archive_id,
        kind: header.kind,
        created_at: header.created_at,
        payload_schema: header.payload_schema,
        source_account: Some(alice().account.params.account_id),
        vaults,
    }
}

/// An archive built by hand for Alice: account recipient wrapped to her
/// public KEM key, payload sealed under the given schema.
fn forge(
    schema_in_header: u16,
    payload_schema: u16,
    sign: impl FnOnce(&Header, &[u8]) -> Option<Signed>,
) -> Vec<u8> {
    let a = &alice().account;
    let k = SymmetricKey::generate().unwrap();
    let archive_id = Id::new();
    let mut header = Header {
        archive_id,
        kind: ArchiveKind::Backup,
        created_at: 1_700_000_000,
        payload_schema: schema_in_header,
        recipients: vec![Recipient::Account {
            account_id: a.params.account_id,
            envelope: wrap_key(&a.params.kem_pub, &k, &envelope_context(archive_id)).unwrap(),
        }],
        signature: None,
    };
    let mut p = payload(&header, vaults());
    p.payload_schema = payload_schema;
    let sealed = seal(
        &k,
        BlobKind::Archive,
        &Aad {
            blob_id: archive_id,
            vault_id: None,
            schema: schema_in_header,
        },
        &postcard::to_allocvec(&p).unwrap(),
    )
    .unwrap();
    header.signature = sign(&header, &sealed);
    encode_container(&header, &sealed).unwrap()
}

fn sign_as(who: &NewAccount, signer_id: Id) -> impl FnOnce(&Header, &[u8]) -> Option<Signed> {
    move |h, sealed| {
        let digest = signed_digest(h, sealed).unwrap();
        Some(Signed {
            account_id: signer_id,
            signature: who
                .account
                .keyset()
                .signing
                .sign(SIGN_DOMAIN, &digest)
                .unwrap(),
        })
    }
}

fn as_alice() -> Unlock<'static> {
    Unlock::Account(&alice().account)
}

#[test]
fn export_roundtrip() {
    let v = vaults();
    let bytes = export(v.clone(), PASSPHRASE, kdf()).unwrap();
    assert_eq!(&bytes[..6], b"OPARCH");
    assert_eq!(bytes[6], 1);
    let c: Contents = open(&bytes, Unlock::Passphrase(PASSPHRASE)).unwrap();
    assert_eq!(c.kind, ArchiveKind::Export);
    assert_eq!(c.source_account, None);
    assert_eq!(c.vaults, v);
    assert_eq!(
        postcard::to_allocvec(&c.vaults).unwrap(),
        postcard::to_allocvec(&v).unwrap()
    );
    let info = inspect(&bytes).unwrap();
    assert_eq!(info.archive_id, c.archive_id);
    assert_eq!(info.created_at, c.created_at);
    assert!(info.passphrase && !info.signed && info.account.is_none());
    // An export has no account recipient: opening by account is refused.
    assert_eq!(open(&bytes, as_alice()).unwrap_err(), Error::WrongPassword);
}

#[test]
fn backup_roundtrip_account() {
    let (v, bytes) = alice_backup(false);
    let c = open(&bytes, as_alice()).unwrap();
    assert_eq!(c.kind, ArchiveKind::Backup);
    assert_eq!(c.source_account, Some(alice().account.params.account_id));
    assert_eq!(c.vaults, v);
    let info = inspect(&bytes).unwrap();
    assert_eq!(info.kind, ArchiveKind::Backup);
    assert_eq!(info.payload_schema, CURRENT_SCHEMA);
    assert_eq!(info.account, Some(alice().account.params.account_id));
    assert!(info.signed && !info.passphrase);
    // No passphrase recipient.
    assert_eq!(
        open(&bytes, Unlock::Passphrase(PASSPHRASE)).unwrap_err(),
        Error::WrongPassword
    );
}

#[test]
fn backup_with_extra_passphrase_opens_both_ways() {
    let (v, bytes) = alice_backup(true);
    let by_account = open(&bytes, as_alice()).unwrap();
    let by_phrase = open(&bytes, Unlock::Passphrase(PASSPHRASE)).unwrap();
    assert_eq!(by_account, by_phrase);
    assert_eq!(by_account.vaults, v);
    let info = inspect(&bytes).unwrap();
    assert!(info.passphrase && info.signed);
}

#[test]
fn wrong_passphrase() {
    let bytes = export(vaults(), PASSPHRASE, kdf()).unwrap();
    assert_eq!(
        open(&bytes, Unlock::Passphrase(OTHER_PASSPHRASE)).unwrap_err(),
        Error::WrongPassword
    );
}

#[test]
fn other_account_refused() {
    let (_, bytes) = alice_backup(false);
    assert_eq!(
        open(&bytes, Unlock::Account(&bob().account)).unwrap_err(),
        Error::WrongPassword
    );
}

#[test]
fn forged_with_public_key_refused() {
    let sig = Error::Integrity(IntegrityError::Signature);
    // Sanity: the forger's construction opens when signed by Alice herself.
    let genuine = forge(1, 1, sign_as(alice(), alice().account.params.account_id));
    open(&genuine, as_alice()).unwrap();

    let unsigned = forge(1, 1, |_, _| None);
    assert_eq!(open(&unsigned, as_alice()).unwrap_err(), sig);

    let bob_claims_alice = forge(1, 1, sign_as(bob(), alice().account.params.account_id));
    assert_eq!(open(&bob_claims_alice, as_alice()).unwrap_err(), sig);

    let bob_as_bob = forge(1, 1, sign_as(bob(), bob().account.params.account_id));
    assert_eq!(open(&bob_as_bob, as_alice()).unwrap_err(), sig);

    // Alice's signature under a claimed other signer id.
    let wrong_id = forge(1, 1, sign_as(alice(), bob().account.params.account_id));
    assert_eq!(open(&wrong_id, as_alice()).unwrap_err(), sig);

    // A malformed signature.
    let garbage = forge(1, 1, |_, _| {
        Some(Signed {
            account_id: alice().account.params.account_id,
            signature: HybridSignature {
                mldsa: vec![0; 10],
                ed25519: [0; 64],
            },
        })
    });
    assert_eq!(open(&garbage, as_alice()).unwrap_err(), sig);
}

#[test]
fn flipped_bit_anywhere_refused() {
    let (_, bytes) = alice_backup(false);
    for i in (0..bytes.len()).step_by(97) {
        let mut b = bytes.clone();
        b[i] ^= 0x01;
        assert!(open(&b, as_alice()).is_err(), "byte {i}");
    }
    let bytes = export(vaults(), PASSPHRASE, kdf()).unwrap();
    for i in (0..bytes.len()).step_by(97) {
        let mut b = bytes.clone();
        b[i] ^= 0x01;
        assert!(
            open(&b, Unlock::Passphrase(PASSPHRASE)).is_err(),
            "byte {i}"
        );
    }
}

#[test]
fn truncated_refused() {
    let (_, bytes) = alice_backup(false);
    for len in [0, 5, 6, 7, 10, 11, 100, bytes.len() / 2, bytes.len() - 1] {
        assert!(open(&bytes[..len], as_alice()).is_err(), "len {len}");
        if len < 200 {
            assert!(inspect(&bytes[..len]).is_err(), "len {len}");
        }
    }
}

#[test]
fn trailing_bytes_refused() {
    let (_, mut bytes) = alice_backup(false);
    bytes.push(0);
    assert!(open(&bytes, as_alice()).is_err());

    // Trailing bytes inside the declared header length.
    let (_, bytes) = alice_backup(false);
    let (header, sealed) = decode_container(&bytes).unwrap();
    let mut h = postcard::to_allocvec(&header).unwrap();
    h.push(0);
    let mut forged = Vec::new();
    forged.extend_from_slice(MAGIC);
    forged.push(FORMAT);
    forged.extend_from_slice(&(h.len() as u32).to_be_bytes());
    forged.extend_from_slice(&h);
    forged.extend_from_slice(sealed);
    assert_eq!(
        open(&forged, as_alice()).unwrap_err(),
        Error::InvalidFormat("archive header")
    );
    assert!(inspect(&forged).is_err());
}

#[test]
fn future_schema_refused() {
    let newer = Error::InvalidFormat("archive from a newer version");
    // Schema 2 in the header: refused before any decryption.
    let both = forge(2, 2, sign_as(alice(), alice().account.params.account_id));
    assert_eq!(open(&both, as_alice()).unwrap_err(), newer);
    assert_eq!(inspect(&both).unwrap().payload_schema, 2);
    // Schema 2 only inside the sealed payload: refused after decryption.
    let inner = forge(1, 2, sign_as(alice(), alice().account.params.account_id));
    assert_eq!(open(&inner, as_alice()).unwrap_err(), newer);
}

#[test]
fn damaged_payload_is_not_wrong_password() {
    let bytes = export(vaults(), PASSPHRASE, kdf()).unwrap();
    // Flip a byte in the payload ciphertext (the last bytes are its tag).
    let mut b = bytes.clone();
    let last = b.len() - 1;
    b[last] ^= 0x80;
    let e = open(&b, Unlock::Passphrase(PASSPHRASE)).unwrap_err();
    assert_ne!(e, Error::WrongPassword);
    assert!(matches!(e, Error::Integrity(_)), "{e:?}");

    let (_, bytes) = alice_backup(true);
    let mut b = bytes.clone();
    let last = b.len() - 1;
    b[last] ^= 0x80;
    // Signature covers the payload: the account path refuses on it.
    assert_eq!(
        open(&b, as_alice()).unwrap_err(),
        Error::Integrity(IntegrityError::Signature)
    );
    let e = open(&b, Unlock::Passphrase(PASSPHRASE)).unwrap_err();
    assert!(matches!(e, Error::Integrity(_)), "{e:?}");
}

#[test]
fn weak_passphrase_refused() {
    let weak = Error::Validation(ValidationError {
        field: "passphrase".into(),
        reason: "too weak",
    });
    assert_eq!(export(vaults(), "password", kdf()).unwrap_err(), weak);
    assert_eq!(
        backup(&alice().account, vaults(), Some(("123456", kdf()))).unwrap_err(),
        weak
    );
    // Below the enforced (dev) floor.
    let low = KdfParams {
        m_kib: 4096,
        ..kdf()
    };
    assert_eq!(
        export(vaults(), PASSPHRASE, low).unwrap_err(),
        Error::InvalidFormat("kdf params")
    );
}

#[test]
fn kdf_above_ceiling_refused() {
    let bytes = export(vaults(), PASSPHRASE, kdf()).unwrap();
    let (mut header, sealed) = decode_container(&bytes).unwrap();
    let sealed = sealed.to_vec();
    match header.recipients.first_mut().unwrap() {
        Recipient::Passphrase { kdf, .. } => kdf.m_kib = 4 * 1024 * 1024,
        Recipient::Account { .. } => panic!("export has a passphrase recipient"),
    }
    let forged = encode_container(&header, &sealed).unwrap();
    let start = std::time::Instant::now();
    assert_eq!(
        open(&forged, Unlock::Passphrase(PASSPHRASE)).unwrap_err(),
        Error::InvalidFormat("kdf params")
    );
    // Refused before Argon2 runs (4 GiB would take far longer or fail).
    assert!(start.elapsed() < std::time::Duration::from_secs(2));
}

#[test]
fn inspect_reveals_no_secret() {
    let (_, bytes) = alice_backup(true);
    let info = inspect(&bytes).unwrap();
    let shown = format!("{info:?}");
    for secret in [
        "s3cret-example-pw",
        "4111111111111111",
        "Personnel",
        "Example",
    ] {
        assert!(!shown.contains(secret));
    }
    // The archive bytes themselves carry no plaintext either.
    for secret in ["s3cret-example-pw", "4111111111111111", "Personnel"] {
        assert!(!bytes.windows(secret.len()).any(|w| w == secret.as_bytes()));
    }
    let unlock = format!("{:?}", Unlock::Passphrase(PASSPHRASE));
    assert!(!unlock.contains(PASSPHRASE));
}

#[test]
fn golden_header() {
    let header = Header {
        archive_id: Id([0x11; 16]),
        kind: ArchiveKind::Backup,
        created_at: 1_761_436_800,
        payload_schema: 1,
        recipients: vec![
            Recipient::Account {
                account_id: Id([0x22; 16]),
                envelope: vec![0xAA, 0xBB, 0xCC],
            },
            Recipient::Passphrase {
                kdf: KdfParams {
                    m_kib: 262144,
                    t: 4,
                    p: 4,
                    salt: [0x33; 32],
                },
                wrapped_key: vec![0xDD, 0xEE],
            },
        ],
        signature: None,
    };
    let hex = data_encoding::HEXLOWER.encode(&postcard::to_allocvec(&header).unwrap());
    assert_eq!(hex, GOLDEN_HEADER);

    let p = Payload {
        archive_id: Id([0x11; 16]),
        kind: ArchiveKind::Export,
        created_at: 1_761_436_800,
        payload_schema: 1,
        source_account: None,
        vaults: vec![ArchivedVault {
            id: Id([0x44; 16]),
            meta: meta("V"),
            items: vec![],
        }],
    };
    let hex = data_encoding::HEXLOWER.encode(&postcard::to_allocvec(&p).unwrap());
    assert_eq!(hex, GOLDEN_PAYLOAD);

    // The container framing around a header.
    let framed = encode_container(&header, &[0x99]).unwrap();
    let h = postcard::to_allocvec(&header).unwrap();
    assert_eq!(&framed[..7], b"OPARCH\x01");
    assert_eq!(&framed[7..11], &(h.len() as u32).to_be_bytes());
    assert_eq!(&framed[11..11 + h.len()], &h[..]);
    assert_eq!(&framed[11 + h.len()..], &[0x99]);
}

const GOLDEN_HEADER: &str = "11111111111111111111111111111111018092eb8f0d0102012222222222222222222222222222222203aabbcc008080100404333333333333333333333333333333333333333333333333333333333333333302ddee00";
const GOLDEN_PAYLOAD: &str = "11111111111111111111111111111111008092eb8f0d010001444444444444444444444444444444440156036b657904626c7565000000";

fn item_in(vault: Id, title: &str) -> Item {
    new_item(ItemType::SecureNote, vault, title)
}

fn contents(vaults: Vec<ArchivedVault>) -> Contents {
    Contents {
        archive_id: Id::new(),
        kind: ArchiveKind::Backup,
        created_at: 0,
        source_account: None,
        vaults,
    }
}

#[test]
fn restore_skips_existing() {
    let v = Id::new();
    let a = item_in(v, "a");
    let b = item_in(v, "b");
    let c = item_in(v, "c");
    let archive = contents(vec![ArchivedVault {
        id: v,
        meta: meta("V"),
        items: vec![a.clone(), b.clone(), c.clone()],
    }]);
    let other = Id::new();
    let existing = vec![(other, vec![a.id]), (v, vec![Id::new(), b.id])];
    let plan = restore_plan(&archive, &existing);
    assert!(plan.new_vaults.is_empty());
    // `a` exists in another vault of the account, `b` in the target vault.
    assert_eq!(plan.writes, vec![(v, c)]);
    assert_eq!(plan.skipped, 2);
    // Order of `existing` is irrelevant.
    let reversed: Vec<_> = existing.iter().rev().cloned().collect();
    assert_eq!(restore_plan(&archive, &reversed), plan);
}

#[test]
fn restore_creates_missing_vaults() {
    let kept = Id::new();
    let fresh = Id::new();
    let x = item_in(fresh, "x");
    let y = item_in(fresh, "y");
    let z = item_in(kept, "z");
    let archive = contents(vec![
        ArchivedVault {
            id: fresh,
            meta: meta("Neuf"),
            items: vec![x.clone(), y.clone()],
        },
        ArchivedVault {
            id: kept,
            meta: meta("Garde"),
            items: vec![z.clone()],
        },
    ]);
    let plan = restore_plan(&archive, &[(kept, vec![])]);
    assert_eq!(plan.new_vaults, vec![(fresh, meta("Neuf"))]);
    assert_eq!(plan.writes, vec![(fresh, x), (fresh, y), (kept, z)]);
    assert_eq!(plan.skipped, 0);
}

#[test]
fn restore_writes_an_id_shared_by_two_archive_vaults_once() {
    let v1 = Id::new();
    let v2 = Id::new();
    let a = item_in(v1, "a");
    let mut a_again = a.clone();
    a_again.vault_id = v2;
    let b = item_in(v2, "b");
    let archive = contents(vec![
        ArchivedVault {
            id: v1,
            meta: meta("Un"),
            items: vec![a.clone()],
        },
        ArchivedVault {
            id: v2,
            meta: meta("Deux"),
            items: vec![a_again, b.clone()],
        },
    ]);
    let plan = restore_plan(&archive, &[]);
    assert_eq!(plan.new_vaults, vec![(v1, meta("Un")), (v2, meta("Deux"))]);
    assert_eq!(plan.writes, vec![(v1, a), (v2, b)]);
    assert_eq!(plan.skipped, 1);
}

#[test]
fn passphrase_strength_scores_the_first_128_chars() {
    let weak = Error::Validation(ValidationError {
        field: "passphrase".into(),
        reason: "too weak",
    });
    let long = "a".repeat(129);
    assert_eq!(export(vaults(), &long, kdf()).unwrap_err(), weak);
    // Multi-byte characters past the bound: cut on a char boundary.
    let mixed = format!("{}é{}", "a".repeat(127), "é".repeat(10));
    assert_eq!(export(vaults(), &mixed, kdf()).unwrap_err(), weak);
}
