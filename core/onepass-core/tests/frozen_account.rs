//! A frozen account (crypto review, F2): records generated once by this
//! crate and never regenerated. Whatever changes in the dependencies, an
//! account already stored must keep unlocking, and the public keys
//! recomputed from its keyset must stay the pinned ones.
//!
//! The fixture uses the dev KDF floor, hence `required-features =
//! ["dev-fast-kdf"]`. See `tests/fixtures/frozen-account/README.md`.

use std::fs;
use std::path::PathBuf;

use aws_lc_rs::digest::{SHA256, digest};
use data_encoding::HEXLOWER;
use onepass_core::Error;
use onepass_core::account::{Account, AccountParams, PinnedAccount};
use onepass_core::crypto::{
    IdentityVerifyingKey, KdfParams, SecretKey, SymmetricKey, unwrap_key, wrap_key,
};

const SIGN_DOMAIN: &[u8] = b"onepass/test/frozen-account";

/// Pinned values of the fixture.
const ACCOUNT_ID: &str = "01a17a96219d71c8bdaaa2259927af15";
const KDF: (u32, u32, u32) = (8192, 1, 1);
const MLDSA_PUB_SHA256: &str = "e5cc4bd8ae2dbbe241fd8e7d2dc2eee0e591c9058679f349789242be5eb8ae3d";
const ED25519_PUB: &str = "9b32c54de70245f32dbb696c2c9bb68f95655376abd28b0b3a43b797d8e37012";
const MLKEM_PUB_SHA256: &str = "bd9cdc5f21044395e563c1f8732d456f58d5b56755fdcae22fc565b59a937912";
const X25519_PUB: &str = "1fac92c3b2203b4ae00acca7bdf96b4fbeba015035dda09c297ec15d095ba862";
const IDENTITY_PUB: &str = concat!(
    "cfea468c0ef77a1322ef6316bc155cbd10ecedd155753e8161b7cdb8bc2f5f4b",
    "ec24226c09e048fdf7c3c592eb77d76965cd61c7716bfe0558705db18085c58a",
);

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/frozen-account")
}

struct Fixture {
    password: String,
    secret_key: SecretKey,
    params: Vec<u8>,
    keyset: Vec<u8>,
}

fn fixture() -> Fixture {
    let read = |name: &str| fs::read(dir().join(name)).unwrap();
    let text = |name: &str| String::from_utf8(read(name)).unwrap().trim().to_owned();
    Fixture {
        password: text("password.txt"),
        secret_key: SecretKey::parse(&text("secret_key.txt")).unwrap(),
        params: read("params.bin"),
        keyset: read("keyset.bin"),
    }
}

fn sha256_hex(b: &[u8]) -> String {
    HEXLOWER.encode(digest(&SHA256, b).as_ref())
}

/// Raw bytes of an identity public key (postcard: one length byte, bytes).
fn identity_bytes(pk: &IdentityVerifyingKey) -> Vec<u8> {
    let enc = postcard::to_allocvec(pk).unwrap();
    assert_eq!(usize::from(enc[0]), enc.len() - 1);
    enc[1..].to_vec()
}

fn assert_pinned(params: &AccountParams) {
    assert_eq!(HEXLOWER.encode(&params.account_id.0), ACCOUNT_ID);
    assert_eq!((params.kdf.m_kib, params.kdf.t, params.kdf.p), KDF);
    assert_eq!(sha256_hex(&params.signing_pub.mldsa), MLDSA_PUB_SHA256);
    assert_eq!(HEXLOWER.encode(&params.signing_pub.ed25519), ED25519_PUB);
    assert_eq!(sha256_hex(&params.kem_pub.mlkem), MLKEM_PUB_SHA256);
    assert_eq!(HEXLOWER.encode(&params.kem_pub.x25519), X25519_PUB);
    assert_eq!(
        HEXLOWER.encode(&identity_bytes(&params.identity_pub)),
        IDENTITY_PUB
    );
}

#[test]
fn frozen_account_unlocks_with_pinned_keys() {
    let f = fixture();
    let account = Account::unlock(&f.password, &f.secret_key, &f.params, &f.keyset, None).unwrap();
    assert_pinned(&account.params);

    // Unlock already compares the recomputed keys to the signed ones; check
    // them against the pins too, independently of the params record.
    let ks = account.keyset();
    let kem_pub = ks.kem.public().unwrap();
    let signing_pub = ks.signing.verifying_key().unwrap();
    assert_eq!(kem_pub, account.params.kem_pub);
    assert_eq!(signing_pub, account.params.signing_pub);
    assert_eq!(ks.identity.verifying_key(), account.params.identity_pub);
    assert_eq!(sha256_hex(&signing_pub.mldsa), MLDSA_PUB_SHA256);
    assert_eq!(HEXLOWER.encode(&signing_pub.ed25519), ED25519_PUB);
    assert_eq!(sha256_hex(&kem_pub.mlkem), MLKEM_PUB_SHA256);
    assert_eq!(HEXLOWER.encode(&kem_pub.x25519), X25519_PUB);
    assert_eq!(
        HEXLOWER.encode(&identity_bytes(&ks.identity.verifying_key())),
        IDENTITY_PUB
    );

    // The unlocked keys still work together.
    let sig = ks.signing.sign(SIGN_DOMAIN, b"frozen").unwrap();
    signing_pub.verify(SIGN_DOMAIN, b"frozen", &sig).unwrap();
    let k = SymmetricKey::generate().unwrap();
    let env = wrap_key(&kem_pub, &k, b"vault:frozen").unwrap();
    assert_eq!(
        unwrap_key(&ks.kem, &env, b"vault:frozen").unwrap().expose(),
        k.expose()
    );
}

#[test]
fn frozen_account_unlocks_pinned_and_with_auk() {
    let f = fixture();
    let params = AccountParams::decode(&f.params).unwrap();
    let pin = PinnedAccount {
        account_id: params.account_id,
        identity_pub: params.identity_pub.clone(),
        kdf_floor: params.kdf.clone(),
    };
    let (account, auk) =
        Account::unlock_exporting_auk(&f.password, &f.secret_key, &f.params, &f.keyset, Some(&pin))
            .unwrap();
    assert_pinned(&account.params);
    let again = Account::unlock_with_auk(&auk, &f.params, &f.keyset, Some(&pin)).unwrap();
    assert_eq!(again.params, account.params);
}

#[test]
fn frozen_account_refuses_a_wrong_password() {
    let f = fixture();
    let err = Account::unlock(
        "not the password",
        &f.secret_key,
        &f.params,
        &f.keyset,
        None,
    )
    .unwrap_err();
    assert_eq!(err, Error::WrongPassword);
}

/// Writes a new fixture. Run once, by hand, and never again: the point of
/// the fixture is that it does not change. Does nothing unless
/// `ONEPASS_REGEN_FIXTURE=1` (so `cargo test -- --ignored` leaves it
/// alone), and refuses to overwrite an existing fixture: delete it first,
/// knowingly.
#[test]
#[ignore = "generates the fixture; never rerun"]
fn generate_fixture() {
    if std::env::var("ONEPASS_REGEN_FIXTURE").as_deref() != Ok("1") {
        eprintln!("skipped: set ONEPASS_REGEN_FIXTURE=1 to write a new fixture");
        return;
    }
    assert!(
        !dir().join("params.bin").exists(),
        "the fixture exists: it must never change; delete it first to regenerate"
    );
    let password = "Frozen fixture, Lucie Martin";
    let kdf = KdfParams {
        m_kib: KDF.0,
        t: KDF.1,
        p: KDF.2,
        salt: onepass_core::crypto::random_array().unwrap(),
    };
    let new = Account::create_with_params(password, kdf).unwrap();
    let d = dir();
    fs::create_dir_all(&d).unwrap();
    fs::write(d.join("password.txt"), format!("{password}\n")).unwrap();
    fs::write(
        d.join("secret_key.txt"),
        format!("{}\n", new.secret_key.to_display()),
    )
    .unwrap();
    fs::write(d.join("params.bin"), &new.params_record).unwrap();
    fs::write(d.join("keyset.bin"), &new.keyset_record).unwrap();
    let p = &new.account.params;
    println!("ACCOUNT_ID {}", HEXLOWER.encode(&p.account_id.0));
    println!("MLDSA_PUB_SHA256 {}", sha256_hex(&p.signing_pub.mldsa));
    println!("ED25519_PUB {}", HEXLOWER.encode(&p.signing_pub.ed25519));
    println!("MLKEM_PUB_SHA256 {}", sha256_hex(&p.kem_pub.mlkem));
    println!("X25519_PUB {}", HEXLOWER.encode(&p.kem_pub.x25519));
    println!(
        "IDENTITY_PUB {}",
        HEXLOWER.encode(&identity_bytes(&p.identity_pub))
    );
}
