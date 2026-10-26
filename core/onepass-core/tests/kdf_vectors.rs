use onepass_core::Error;
use onepass_core::crypto::{KDF_FLOOR, KdfParams, SecretKey, derive_auk};

fn fast_params() -> KdfParams {
    KdfParams {
        m_kib: 8192,
        t: 1,
        p: 1,
        salt: [1u8; 32],
    }
}

#[test]
fn auk_depends_on_both_secrets() {
    let sk1 = SecretKey::parse(&SecretKey::generate().unwrap().to_display()).unwrap();
    let sk2 = SecretKey::generate().unwrap();
    let a = derive_auk("hunter2", &sk1, &fast_params()).unwrap();
    assert_ne!(
        a.expose(),
        derive_auk("hunter3", &sk1, &fast_params())
            .unwrap()
            .expose()
    );
    assert_ne!(
        a.expose(),
        derive_auk("hunter2", &sk2, &fast_params())
            .unwrap()
            .expose()
    );
}

#[test]
fn auk_depends_on_the_salt() {
    let sk = SecretKey::generate().unwrap();
    let other = KdfParams {
        salt: [2u8; 32],
        ..fast_params()
    };
    assert_ne!(
        derive_auk("hunter2", &sk, &fast_params()).unwrap().expose(),
        derive_auk("hunter2", &sk, &other).unwrap().expose()
    );
}

#[test]
fn nfc_and_nfd_passwords_match() {
    let sk = SecretKey::generate().unwrap();
    let nfc = "caf\u{e9}";
    let nfd = "cafe\u{301}";
    assert_eq!(
        derive_auk(nfc, &sk, &fast_params()).unwrap().expose(),
        derive_auk(nfd, &sk, &fast_params()).unwrap().expose()
    );
}

#[test]
fn default_params_meet_floor() {
    let p = KdfParams::new_default().unwrap();
    assert_eq!((p.m_kib, p.t, p.p), KDF_FLOOR);
    let weaker = KdfParams {
        m_kib: 65536,
        ..p.clone()
    };
    assert!(!weaker.is_at_least(&p));
    assert!(p.is_at_least(&p));
}

#[test]
fn default_params_use_a_fresh_salt() {
    assert_ne!(
        KdfParams::new_default().unwrap().salt,
        KdfParams::new_default().unwrap().salt
    );
}

#[test]
fn invalid_argon2_params_are_a_crypto_error() {
    let sk = SecretKey::generate().unwrap();
    let bad = KdfParams {
        m_kib: 1,
        ..fast_params()
    };
    assert_eq!(derive_auk("pw", &sk, &bad).unwrap_err(), Error::Crypto);
}

#[test]
fn auk_matches_independent_vector() {
    // Computed independently with Python argon2-cffi 25.1.0 (hash_secret_raw,
    // Argon2id, version 19, m=8192, t=1, p=1, 32 bytes) and hmac/hashlib HKDF:
    // password "hunter2", secret key bytes 0..=31, salt [1; 32],
    // info "onepass/auk/v1", L = 32.
    let sk = SecretKey::parse("AAAQ-EAYE-AUDA-OCAJ-BIFQ-YDIO-B4IB-CEQT-CQKR-MFYY-DENB-WHA5-DYPQ-B")
        .unwrap();
    let expected: [u8; 32] = [
        0x33, 0x8e, 0xae, 0x36, 0x16, 0x6f, 0x61, 0x4f, 0xf4, 0x2c, 0xe5, 0xfc, 0x94, 0x83, 0x6e,
        0xf6, 0x12, 0x0d, 0x3d, 0xa5, 0x3e, 0x75, 0x41, 0x58, 0x90, 0x0c, 0xaf, 0x89, 0xd3, 0x65,
        0xf8, 0x1d,
    ];
    assert_eq!(
        derive_auk("hunter2", &sk, &fast_params()).unwrap().expose(),
        &expected
    );
}

#[test]
#[ignore = "performance reference, run by hand in release mode"]
fn default_params_take_under_3s() {
    let sk = SecretKey::generate().unwrap();
    let p = KdfParams::new_default().unwrap();
    let start = std::time::Instant::now();
    derive_auk("hunter2", &sk, &p).unwrap();
    let elapsed = start.elapsed();
    eprintln!("derive_auk with default params: {elapsed:?}");
    assert!(elapsed.as_secs_f64() < 3.0, "took {elapsed:?}");
}
