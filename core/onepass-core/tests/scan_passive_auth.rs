//! Passive authentication of an eMRTD chip (ICAO 9303 part 11 section 5.1)
//! against a CSCA master list (part 12). Every certificate, EF.SOD and
//! master list here is a throwaway one built at test time: no real document.

use std::sync::OnceLock;

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::rsa::{KeyPair as RsaKeyPair, KeySize};
use aws_lc_rs::signature::{KeyPair as _, RSA_PKCS1_SHA256, RSA_PSS_SHA256};
use ecdsa::signature::Signer as _;
use onepass_core::scan::icao::{ChipStatus, load_master_list, verify_sod};
use onepass_core::scan::tlv::encode;
use sha2::{Digest, Sha256};
use time::macros::date;

// ---------------------------------------------------------------- DER bits

fn t(tag: u32, parts: &[&[u8]]) -> Vec<u8> {
    encode(tag, &parts.concat())
}

fn seq(parts: &[&[u8]]) -> Vec<u8> {
    t(0x30, parts)
}

fn set(parts: &[&[u8]]) -> Vec<u8> {
    t(0x31, parts)
}

fn oid(dotted: &str) -> Vec<u8> {
    let arcs: Vec<u64> = dotted.split('.').map(|a| a.parse().unwrap()).collect();
    let mut body = vec![(arcs[0] * 40 + arcs[1]) as u8];
    for &arc in &arcs[2..] {
        let mut chunk = vec![(arc & 0x7F) as u8];
        let mut v = arc >> 7;
        while v > 0 {
            chunk.push(((v & 0x7F) as u8) | 0x80);
            v >>= 7;
        }
        chunk.reverse();
        body.extend(chunk);
    }
    encode(0x06, &body)
}

fn int(bytes: &[u8]) -> Vec<u8> {
    let mut b: &[u8] = bytes;
    while b.len() > 1 && b[0] == 0 {
        b = &b[1..];
    }
    let mut v = Vec::new();
    if b[0] & 0x80 != 0 {
        v.push(0);
    }
    v.extend_from_slice(b);
    encode(0x02, &v)
}

fn int_u(n: u64) -> Vec<u8> {
    int(&n.to_be_bytes())
}

fn octets(b: &[u8]) -> Vec<u8> {
    encode(0x04, b)
}

fn bits(b: &[u8]) -> Vec<u8> {
    t(0x03, &[&[0], b])
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

fn name(country: &str, cn: &str) -> Vec<u8> {
    seq(&[
        &set(&[&seq(&[&oid("2.5.4.6"), &encode(0x13, country.as_bytes())])]),
        &set(&[&seq(&[&oid("2.5.4.3"), &encode(0x0C, cn.as_bytes())])]),
    ])
}

const SHA256: &str = "2.16.840.1.101.3.4.2.1";
const LDS_SO: &str = "2.23.136.1.1.1";
const CSCA_ML: &str = "2.23.136.1.1.2";

fn alg(oid_s: &str, params: Option<&[u8]>) -> Vec<u8> {
    match params {
        Some(p) => seq(&[&oid(oid_s), p]),
        None => seq(&[&oid(oid_s)]),
    }
}

fn sha256(b: &[u8]) -> Vec<u8> {
    Sha256::digest(b).to_vec()
}

// ---------------------------------------------------------------- keys

#[derive(Clone, Copy, PartialEq)]
enum Scheme {
    Pkcs1,
    Pss,
    /// ECDSA, DER signature.
    Ecdsa,
    /// ECDSA, plain r||s signature (BSI TR-03111).
    EcdsaPlain,
}

enum Key {
    Rsa(&'static RsaKeyPair),
    P256(p256::ecdsa::SigningKey),
    Bp256(ecdsa::SigningKey<bp256::BrainpoolP256r1>),
}

const P256_P: &str = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff";
const P256_A: &str = "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc";
const P256_B: &str = "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b";
const P256_GX: &str = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
const P256_GY: &str = "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";
const P256_N: &str = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";

const BP256_P: &str = "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377";
const BP256_A: &str = "7d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9";
const BP256_B: &str = "26dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b6";
const BP256_GX: &str = "8bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262";
const BP256_GY: &str = "547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997";
const BP256_N: &str = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7";

/// ECParameters with the curve spelled out instead of a named OID.
fn explicit_params(p: &str, a: &str, b: &str, gx: &str, gy: &str, n: &str) -> Vec<u8> {
    let mut g = vec![0x04];
    g.extend(unhex(gx));
    g.extend(unhex(gy));
    seq(&[
        &int_u(1),
        &seq(&[&oid("1.2.840.10045.1.1"), &int(&unhex(p))]),
        &seq(&[&octets(&unhex(a)), &octets(&unhex(b))]),
        &octets(&g),
        &int(&unhex(n)),
        &int_u(1),
    ])
}

impl Key {
    fn spki(&self, explicit: bool) -> Vec<u8> {
        match self {
            Key::Rsa(k) => seq(&[
                &alg("1.2.840.113549.1.1.1", Some(&[0x05, 0x00])),
                &bits(k.public_key().as_ref()),
            ]),
            Key::P256(k) => {
                let params = if explicit {
                    explicit_params(P256_P, P256_A, P256_B, P256_GX, P256_GY, P256_N)
                } else {
                    oid("1.2.840.10045.3.1.7")
                };
                let point = k.verifying_key().to_sec1_point(false);
                seq(&[
                    &alg("1.2.840.10045.2.1", Some(&params)),
                    &bits(point.as_bytes()),
                ])
            }
            Key::Bp256(k) => {
                let params = if explicit {
                    explicit_params(BP256_P, BP256_A, BP256_B, BP256_GX, BP256_GY, BP256_N)
                } else {
                    oid("1.3.36.3.3.2.8.1.1.7")
                };
                let point = k.verifying_key().to_sec1_point(false);
                seq(&[
                    &alg("1.2.840.10045.2.1", Some(&params)),
                    &bits(point.as_bytes()),
                ])
            }
        }
    }

    /// AlgorithmIdentifier of the signature this key makes under `scheme`.
    fn sig_alg(&self, scheme: Scheme) -> Vec<u8> {
        match scheme {
            Scheme::Pkcs1 => alg("1.2.840.113549.1.1.11", Some(&[0x05, 0x00])),
            Scheme::Pss => {
                let sha = alg(SHA256, Some(&[0x05, 0x00]));
                let params = seq(&[
                    &t(0xA0, &[&sha]),
                    &t(0xA1, &[&alg("1.2.840.113549.1.1.8", Some(&sha))]),
                    &t(0xA2, &[&int_u(32)]),
                ]);
                alg("1.2.840.113549.1.1.10", Some(&params))
            }
            Scheme::Ecdsa => alg("1.2.840.10045.4.3.2", None),
            Scheme::EcdsaPlain => alg("0.4.0.127.0.7.1.1.4.1.3", None),
        }
    }

    fn sign(&self, scheme: Scheme, msg: &[u8]) -> Vec<u8> {
        let rs = |r: &[u8], s: &[u8]| -> Vec<u8> {
            if scheme == Scheme::EcdsaPlain {
                [r, s].concat()
            } else {
                seq(&[&int(r), &int(s)])
            }
        };
        match self {
            Key::Rsa(k) => {
                let pad = match scheme {
                    Scheme::Pkcs1 => &RSA_PKCS1_SHA256,
                    Scheme::Pss => &RSA_PSS_SHA256,
                    _ => panic!("RSA key, EC scheme"),
                };
                let mut sig = vec![0u8; k.public_modulus_len()];
                k.sign(pad, &SystemRandom::new(), msg, &mut sig).unwrap();
                sig
            }
            Key::P256(k) => {
                let sig: p256::ecdsa::Signature = k.sign(msg);
                let (r, s) = sig.split_bytes();
                rs(&r, &s)
            }
            Key::Bp256(k) => {
                // No DigestAlgorithm for brainpool in this build: RFC 6979
                // over a SHA-256 prehash.
                let (sig, _) = ecdsa::hazmat::sign_prehashed_rfc6979::<
                    bp256::BrainpoolP256r1,
                    Sha256,
                >(k.as_nonzero_scalar(), &sha256(msg), &[]);
                let (r, s) = sig.split_bytes();
                rs(&r, &s)
            }
        }
    }
}

fn rsa_key(i: usize) -> &'static RsaKeyPair {
    static KEYS: OnceLock<Vec<RsaKeyPair>> = OnceLock::new();
    &KEYS.get_or_init(|| {
        (0..3)
            .map(|_| RsaKeyPair::generate(KeySize::Rsa2048).unwrap())
            .collect()
    })[i]
}

fn p256_key(seed: u8) -> Key {
    Key::P256(p256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap())
}

fn bp256_key(seed: u8) -> Key {
    Key::Bp256(ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap())
}

// ---------------------------------------------------------------- certificates

struct CertSpec<'a> {
    serial: u64,
    issuer: &'a [u8],
    subject: &'a [u8],
    not_before: &'a str,
    not_after: &'a str,
    ski: &'a [u8],
    aki: Option<&'a [u8]>,
    explicit: bool,
}

fn cert(spec: &CertSpec, key: &Key, issuer_key: &Key, scheme: Scheme) -> Vec<u8> {
    let mut exts = vec![seq(&[&oid("2.5.29.14"), &octets(&octets(spec.ski))])];
    if let Some(aki) = spec.aki {
        exts.push(seq(&[
            &oid("2.5.29.35"),
            &octets(&seq(&[&encode(0x80, aki)])),
        ]));
    }
    let ext_refs: Vec<&[u8]> = exts.iter().map(Vec::as_slice).collect();
    let sig_alg = issuer_key.sig_alg(scheme);
    let tbs = seq(&[
        &t(0xA0, &[&int_u(2)]),
        &int_u(spec.serial),
        &sig_alg,
        spec.issuer,
        &seq(&[
            &encode(0x17, spec.not_before.as_bytes()),
            &encode(0x17, spec.not_after.as_bytes()),
        ]),
        spec.subject,
        &key.spki(spec.explicit),
        &t(0xA3, &[&seq(&ext_refs)]),
    ]);
    let sig = issuer_key.sign(scheme, &tbs);
    seq(&[&tbs, &sig_alg, &bits(&sig)])
}

// ---------------------------------------------------------------- CMS

struct SignerSpec<'a> {
    cert: &'a [u8],
    issuer: &'a [u8],
    serial: u64,
    key: &'a Key,
    scheme: Scheme,
    signing_time: Option<&'a str>,
}

fn signed_data(econtent_type: &str, econtent: &[u8], s: &SignerSpec) -> Vec<u8> {
    let digest_alg = alg(SHA256, Some(&[0x05, 0x00]));
    let mut attrs = vec![
        seq(&[&oid("1.2.840.113549.1.9.3"), &set(&[&oid(econtent_type)])]),
        seq(&[
            &oid("1.2.840.113549.1.9.4"),
            &set(&[&octets(&sha256(econtent))]),
        ]),
    ];
    if let Some(st) = s.signing_time {
        attrs.push(seq(&[
            &oid("1.2.840.113549.1.9.5"),
            &set(&[&encode(0x17, st.as_bytes())]),
        ]));
    }
    let attr_refs: Vec<&[u8]> = attrs.iter().map(Vec::as_slice).collect();
    let signed_attrs = set(&attr_refs);
    let sig = s.key.sign(s.scheme, &signed_attrs);
    let mut implicit = signed_attrs.clone();
    implicit[0] = 0xA0;
    let signer_info = seq(&[
        &int_u(1),
        &seq(&[s.issuer, &int_u(s.serial)]),
        &digest_alg,
        &implicit,
        &s.key.sig_alg(s.scheme),
        &octets(&sig),
    ]);
    let sd = seq(&[
        &int_u(3),
        &set(&[&digest_alg]),
        &seq(&[&oid(econtent_type), &t(0xA0, &[&octets(econtent)])]),
        &t(0xA0, &[s.cert]),
        &set(&[&signer_info]),
    ]);
    seq(&[&oid("1.2.840.113549.1.7.2"), &t(0xA0, &[&sd])])
}

// ---------------------------------------------------------------- the world

const SKI_CSCA_RSA: &[u8] = b"csca-rsa-key-id";
const SKI_CSCA_P256: &[u8] = b"csca-p256-key-id";
const SKI_CSCA_BP: &[u8] = b"csca-bp256-key-id";
const SKI_OTHER: &[u8] = b"other-csca-key-id";

struct Csca {
    name: Vec<u8>,
    key: Key,
    ski: &'static [u8],
    cert: Vec<u8>,
    scheme: Scheme,
}

fn csca(cn: &str, key: Key, ski: &'static [u8], scheme: Scheme, not_after: &str) -> Csca {
    let name = name("UT", cn);
    let cert = cert(
        &CertSpec {
            serial: 1,
            issuer: &name,
            subject: &name,
            not_before: "200101000000Z",
            not_after,
            ski,
            aki: Some(ski),
            explicit: false,
        },
        &key,
        &key,
        scheme,
    );
    Csca {
        name,
        key,
        ski,
        cert,
        scheme,
    }
}

fn csca_rsa() -> Csca {
    csca(
        "CSCA RSA",
        Key::Rsa(rsa_key(0)),
        SKI_CSCA_RSA,
        Scheme::Pkcs1,
        "400101000000Z",
    )
}

fn csca_p256() -> Csca {
    csca(
        "CSCA P256",
        p256_key(7),
        SKI_CSCA_P256,
        Scheme::Ecdsa,
        "400101000000Z",
    )
}

fn csca_bp() -> Csca {
    csca(
        "CSCA BP",
        bp256_key(9),
        SKI_CSCA_BP,
        Scheme::Ecdsa,
        "400101000000Z",
    )
}

fn csca_other() -> Csca {
    csca(
        "CSCA OTHER",
        p256_key(3),
        SKI_OTHER,
        Scheme::Ecdsa,
        "400101000000Z",
    )
}

/// Master list holding `cscas`, signed by an ML signer the first CSCA issued.
fn master_list(cscas: &[&Csca]) -> Vec<u8> {
    let issuer = cscas[0];
    let signer_key = Key::Rsa(rsa_key(2));
    let signer_name = name("UT", "ML SIGNER");
    let signer_cert = cert(
        &CertSpec {
            serial: 77,
            issuer: &issuer.name,
            subject: &signer_name,
            not_before: "240101000000Z",
            not_after: "340101000000Z",
            ski: b"ml-signer",
            aki: Some(issuer.ski),
            explicit: false,
        },
        &signer_key,
        &issuer.key,
        issuer.scheme,
    );
    let certs: Vec<&[u8]> = cscas.iter().map(|c| c.cert.as_slice()).collect();
    let content = seq(&[&int_u(0), &set(&certs)]);
    signed_data(
        CSCA_ML,
        &content,
        &SignerSpec {
            cert: &signer_cert,
            issuer: &issuer.name,
            serial: 77,
            key: &signer_key,
            scheme: Scheme::Pss,
            signing_time: None,
        },
    )
}

const DG1: &[u8] = b"\x61\x05\x5f\x1f\x02AB";
const DG2: &[u8] = b"\x75\x06\x7f\x61\x03\x02\x01\x01";

struct Ds<'a> {
    csca: &'a Csca,
    key: Key,
    explicit: bool,
    cert_scheme: Scheme,
    sod_scheme: Scheme,
    not_before: &'a str,
}

/// EF.SOD over DG1 and DG2, signed by a DS that `ds.csca` issued.
fn sod(ds: &Ds) -> Vec<u8> {
    let ds_name = name("UT", "DS");
    let ds_cert = cert(
        &CertSpec {
            serial: 4242,
            issuer: &ds.csca.name,
            subject: &ds_name,
            not_before: ds.not_before,
            not_after: "350101000000Z",
            ski: b"ds-key",
            aki: Some(ds.csca.ski),
            explicit: ds.explicit,
        },
        &ds.key,
        &ds.csca.key,
        ds.cert_scheme,
    );
    let lso = seq(&[
        &int_u(0),
        &alg(SHA256, Some(&[0x05, 0x00])),
        &seq(&[
            &seq(&[&int_u(1), &octets(&sha256(DG1))]),
            &seq(&[&int_u(2), &octets(&sha256(DG2))]),
        ]),
    ]);
    let ci = signed_data(
        LDS_SO,
        &lso,
        &SignerSpec {
            cert: &ds_cert,
            issuer: &ds.csca.name,
            serial: 4242,
            key: &ds.key,
            scheme: ds.sod_scheme,
            signing_time: Some("250601000000Z"),
        },
    );
    encode(0x77, &ci)
}

fn all_cscas() -> (Csca, Csca, Csca) {
    (csca_rsa(), csca_p256(), csca_bp())
}

const AT: time::Date = date!(2026 - 11 - 21);

fn check(sod: &[u8], ml: &[u8]) -> ChipStatus {
    let ml = load_master_list(ml).expect("test master list loads");
    verify_sod(sod, &[(1, DG1), (2, DG2)], &ml, AT)
}

// ---------------------------------------------------------------- tests

#[test]
fn passive_auth_rsa_verified() {
    let (rsa, p, bp) = all_cscas();
    let s = sod(&Ds {
        csca: &rsa,
        key: Key::Rsa(rsa_key(1)),
        explicit: false,
        cert_scheme: Scheme::Pkcs1,
        sod_scheme: Scheme::Pss,
        not_before: "250101000000Z",
    });
    assert_eq!(
        check(&s, &master_list(&[&rsa, &p, &bp])),
        ChipStatus::Verified
    );
}

#[test]
fn passive_auth_ecdsa_p256_verified() {
    let (rsa, p, bp) = all_cscas();
    let s = sod(&Ds {
        csca: &p,
        key: p256_key(21),
        explicit: false,
        cert_scheme: Scheme::Ecdsa,
        sod_scheme: Scheme::Ecdsa,
        not_before: "250101000000Z",
    });
    assert_eq!(
        check(&s, &master_list(&[&rsa, &p, &bp])),
        ChipStatus::Verified
    );
}

#[test]
fn passive_auth_ecdsa_brainpool() {
    let (rsa, p, bp) = all_cscas();
    // DS key with explicit domain parameters, SOD signed in plain r||s.
    let s = sod(&Ds {
        csca: &bp,
        key: bp256_key(33),
        explicit: true,
        cert_scheme: Scheme::Ecdsa,
        sod_scheme: Scheme::EcdsaPlain,
        not_before: "250101000000Z",
    });
    assert_eq!(
        check(&s, &master_list(&[&rsa, &p, &bp])),
        ChipStatus::Verified
    );
}

#[test]
fn passive_auth_explicit_p256_params_verified() {
    let (rsa, p, bp) = all_cscas();
    let s = sod(&Ds {
        csca: &p,
        key: p256_key(44),
        explicit: true,
        cert_scheme: Scheme::Ecdsa,
        sod_scheme: Scheme::Ecdsa,
        not_before: "250101000000Z",
    });
    assert_eq!(
        check(&s, &master_list(&[&rsa, &p, &bp])),
        ChipStatus::Verified
    );
}

fn p256_sod(csca: &Csca) -> Vec<u8> {
    sod(&Ds {
        csca,
        key: p256_key(21),
        explicit: false,
        cert_scheme: Scheme::Ecdsa,
        sod_scheme: Scheme::Ecdsa,
        not_before: "250101000000Z",
    })
}

#[test]
fn tampered_dg2_is_invalid() {
    let (rsa, p, bp) = all_cscas();
    let s = p256_sod(&p);
    let ml = load_master_list(&master_list(&[&rsa, &p, &bp])).unwrap();
    let mut dg2 = DG2.to_vec();
    *dg2.last_mut().unwrap() ^= 1;
    assert_eq!(
        verify_sod(&s, &[(1, DG1), (2, &dg2)], &ml, AT),
        ChipStatus::Invalid
    );
    // A DG the SOD does not list is no better.
    assert_eq!(
        verify_sod(&s, &[(1, DG1), (3, DG2)], &ml, AT),
        ChipStatus::Invalid
    );
}

#[test]
fn tampered_sod_signature_is_invalid() {
    let (rsa, p, bp) = all_cscas();
    let mut s = p256_sod(&p);
    // The SOD signature (ECDSA, DER) is the last element: flip its last byte.
    *s.last_mut().unwrap() ^= 1;
    assert_eq!(
        check(&s, &master_list(&[&rsa, &p, &bp])),
        ChipStatus::Invalid
    );
}

#[test]
fn unknown_csca_is_unverifiable() {
    let (rsa, p, bp) = all_cscas();
    let s = p256_sod(&csca_other());
    assert_eq!(
        check(&s, &master_list(&[&rsa, &p, &bp])),
        ChipStatus::Unverifiable
    );
}

#[test]
fn ds_forged_under_known_csca_is_invalid() {
    let (rsa, p, bp) = all_cscas();
    // Same name and key id as the listed P-256 CSCA, another key.
    let mut forger = csca_other();
    forger.name = p.name.clone();
    forger.ski = SKI_CSCA_P256;
    let s = p256_sod(&forger);
    assert_eq!(
        check(&s, &master_list(&[&rsa, &p, &bp])),
        ChipStatus::Invalid
    );
}

#[test]
fn csca_expired_when_ds_issued_is_unverifiable() {
    let (rsa, _, bp) = all_cscas();
    let p = csca(
        "CSCA P256",
        p256_key(7),
        SKI_CSCA_P256,
        Scheme::Ecdsa,
        "241231000000Z",
    );
    let s = p256_sod(&p);
    assert_eq!(
        check(&s, &master_list(&[&rsa, &p, &bp])),
        ChipStatus::Unverifiable
    );
}

#[test]
fn malformed_sod_never_verifies() {
    let (rsa, p, bp) = all_cscas();
    let s = p256_sod(&p);
    let ml = load_master_list(&master_list(&[&rsa, &p, &bp])).unwrap();
    for cut in 0..s.len() {
        let st = verify_sod(&s[..cut], &[(1, DG1), (2, DG2)], &ml, AT);
        assert_ne!(st, ChipStatus::Verified, "truncated at {cut}");
    }
    // Flipped bytes: never a panic. Some bytes are not signed (SignedData
    // version, digestAlgorithms), so a flip there may still verify.
    for i in 0..s.len() {
        let mut m = s.clone();
        m[i] ^= 0x41;
        let _ = verify_sod(&m, &[(1, DG1), (2, DG2)], &ml, AT);
    }
    // Same for an RSA chain (key and PSS parameter parsing) and the list.
    let r = sod(&Ds {
        csca: &rsa,
        key: Key::Rsa(rsa_key(1)),
        explicit: false,
        cert_scheme: Scheme::Pkcs1,
        sod_scheme: Scheme::Pss,
        not_before: "250101000000Z",
    });
    for i in 0..r.len() {
        for x in [0x01, 0x80, 0xFF] {
            let mut m = r.clone();
            m[i] ^= x;
            let _ = verify_sod(&m, &[(1, DG1), (2, DG2)], &ml, AT);
        }
    }
    let list = master_list(&[&rsa, &p, &bp]);
    for i in (0..list.len()).step_by(3) {
        let mut m = list.clone();
        m[i] ^= 0x80;
        let _ = load_master_list(&m);
        let _ = load_master_list(&list[..i]);
    }
}

#[test]
fn master_list_loads_test_list() {
    let (rsa, p, bp) = all_cscas();
    let ml = load_master_list(&master_list(&[&rsa, &p, &bp])).unwrap();
    assert_eq!(ml.len(), 3);
    assert!(!ml.is_empty());
}

#[test]
fn master_list_with_bad_signature_is_rejected() {
    let (rsa, p, bp) = all_cscas();
    let mut ml = master_list(&[&rsa, &p, &bp]);
    // The signer's PSS signature closes the file.
    *ml.last_mut().unwrap() ^= 1;
    assert!(load_master_list(&ml).is_err());
    // A list whose signer no listed CSCA issued is refused too.
    let ml2 = signed_ml_with_foreign_signer(&rsa, &p);
    assert!(load_master_list(&ml2).is_err());
    assert!(load_master_list(b"not cms").is_err());
    assert!(load_master_list(&[]).is_err());
}

/// A master list holding only `listed`, signed by a signer `issuer` issued.
fn signed_ml_with_foreign_signer(issuer: &Csca, listed: &Csca) -> Vec<u8> {
    let signer_key = Key::Rsa(rsa_key(2));
    let signer_name = name("UT", "ML SIGNER");
    let signer_cert = cert(
        &CertSpec {
            serial: 78,
            issuer: &issuer.name,
            subject: &signer_name,
            not_before: "240101000000Z",
            not_after: "340101000000Z",
            ski: b"ml-signer",
            aki: Some(issuer.ski),
            explicit: false,
        },
        &signer_key,
        &issuer.key,
        issuer.scheme,
    );
    let content = seq(&[&int_u(0), &set(&[&listed.cert])]);
    signed_data(
        CSCA_ML,
        &content,
        &SignerSpec {
            cert: &signer_cert,
            issuer: &issuer.name,
            serial: 78,
            key: &signer_key,
            scheme: Scheme::Pss,
            signing_time: None,
        },
    )
}
