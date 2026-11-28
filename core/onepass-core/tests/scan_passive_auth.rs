//! Passive authentication of an eMRTD chip (ICAO 9303 part 11 section 5.1)
//! against a CSCA master list (part 12). Every certificate, EF.SOD and
//! master list here is a throwaway one built at test time: no real document.

use std::sync::OnceLock;

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::rsa::{KeyPair as RsaKeyPair, KeySize};
use aws_lc_rs::signature::{KeyPair as _, RSA_PKCS1_SHA256, RSA_PSS_SHA256};
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
enum H {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl H {
    fn digest(self, b: &[u8]) -> Vec<u8> {
        match self {
            H::Sha1 => sha1::Sha1::digest(b).to_vec(),
            H::Sha256 => Sha256::digest(b).to_vec(),
            H::Sha384 => sha2::Sha384::digest(b).to_vec(),
            H::Sha512 => sha2::Sha512::digest(b).to_vec(),
        }
    }

    fn oid(self) -> &'static str {
        match self {
            H::Sha1 => "1.3.14.3.2.26",
            H::Sha256 => SHA256,
            H::Sha384 => "2.16.840.1.101.3.4.2.2",
            H::Sha512 => "2.16.840.1.101.3.4.2.3",
        }
    }

    /// The DigestInfo prefix of a PKCS#1 v1.5 signature.
    fn digest_info_prefix(self) -> Vec<u8> {
        let zero = vec![0u8; self.digest(b"").len()];
        let full = seq(&[&alg(self.oid(), Some(&[0x05, 0x00])), &octets(&zero)]);
        full[..full.len() - zero.len()].to_vec()
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Scheme {
    Pkcs1(H),
    /// RSA-PSS, SHA-256, salt 32.
    Pss,
    /// ECDSA, DER signature, ecdsa-with-SHA*.
    Ecdsa(H),
    /// ECDSA, plain r||s signature, BSI TR-03111 OIDs.
    EcdsaPlain(H),
    /// A plain r||s signature labelled ecdsa-with-SHA256 (must not verify).
    EcdsaRawMislabeled,
}

enum Key {
    Rsa(&'static RsaKeyPair),
    /// RSA 2048 from fixed primes: aws-lc-rs signs no SHA-1.
    RsaFixed(&'static rsa::PrivateKey),
    P256(p256::ecdsa::SigningKey),
    P384(ecdsa::SigningKey<p384::NistP384>),
    Bp256(ecdsa::SigningKey<bp256::BrainpoolP256r1>),
    Bp384(ecdsa::SigningKey<bp384::BrainpoolP384r1>),
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

const BP384_P: &str = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53";
const BP384_A: &str = "7bc382c63d8c150c3c72080ace05afa0c2bea28e4fb22787139165efba91f90f8aa5814a503ad4eb04a8c7dd22ce2826";
const BP384_B: &str = "04a8c7dd22ce28268b39b55416f0447c2fb77de107dcd2a62e880ea53eeb62d57cb4390295dbc9943ab78696fa504c11";
const BP384_GX: &str = "1d1c64f068cf45ffa2a63a81b7c13f6b8847a3e77ef14fe3db7fcafe0cbd10e8e826e03436d646aaef87b2e247d4af1e";
const BP384_GY: &str = "8abe1d7520f9c2a45cb1eb8e95cfd55262b70b29feec5864e19c054ff99129280e4646217791811142820341263c5315";
const BP384_N: &str = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565";

// Two 1024-bit primes and their product, made once offline for the SHA-1
// test CSCA (test only).
const RSA_FIXED_P: &str = "f1239d5f9f64fcf89b345f73d391428a455a9c9b691aca1cdd406cbabdccc78fff497233acc1acc5dabe59fe389c6058d5fe73453b2a7d8eb36b80cf9e8bf67aa79ddc0b49bae6763a43631bed4565be2c0ac612bc66f9ff2c5d8230206657d6b7edf4e474f6ae7330722a7150c9c653d17351f1c1260a9b77831983ab078ff1";
const RSA_FIXED_Q: &str = "c18243d6b84501fdbb83201901f897a836ae2e5f6d14a78857090e079698ab3202efa27a0093d4c9ea45d42e00e7db7fadf59c30b2a84e5db99f8f2d77efe8e1d5165f71d0d80f88d52d767f5f18e0ac9ad9170899463d159a5479922579dab329d4a8477c34d848a05f33e643b7c03df8d1b58a1c6b38ac3bcbe18a2dcbf049";
const RSA_FIXED_N: &str = "b6468da19542423cd9a8cf946bce76d7ffcb15f823798086f5847e22e8e8f71c05b3aa2483e82128c6b214410f371b1e5fc7feab0ce976fdf8bc3fcd7cf13473af9ef1478dd2135e87d15e96f3223d0ea86143a54da8a9f3262c4a32fb35dfb742cfb83420a1745069aec7f117c53f7fb2ba8e42aff16aab5536ce8a75f0908e10182ba8185ebc606b47d54b3a30139fac5ac554510cd44e769cd0576d164cf6c4f9aac6a83857326adca137641ceaf861dbaf465276cc15c9b08abe1c4afba46d8d87b27908fdf25c70bb3a8a7418a5dcd1ddb46b364cbebb038e8027c56516739790a6fb21b08e87aa8e8e960359edad05726ccb4cdc34e37813195d34fbb9";

fn rsa_fixed() -> &'static rsa::PrivateKey {
    static KEY: OnceLock<rsa::PrivateKey> = OnceLock::new();
    KEY.get_or_init(|| {
        let n = |h: &str| rsa::BoxedUint::from_be_slice_vartime(&unhex(h));
        rsa::PrivateKey::from_p_q(n(RSA_FIXED_P), n(RSA_FIXED_Q), n("010001")).unwrap()
    })
}

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

fn ec_spki(params: Vec<u8>, point: &[u8]) -> Vec<u8> {
    seq(&[&alg("1.2.840.10045.2.1", Some(&params)), &bits(point)])
}

/// Signs `msg` hashed with `h`, RFC 6979 nonce: (r, s).
macro_rules! ec_sign {
    ($curve:ty, $k:expr, $h:expr, $msg:expr) => {{
        let (sig, _) = ecdsa::hazmat::sign_prehashed_rfc6979::<$curve, Sha256>(
            $k.as_nonzero_scalar(),
            &$h.digest($msg),
            &[],
        );
        let (r, s) = sig.split_bytes();
        (r.to_vec(), s.to_vec())
    }};
}

impl Key {
    fn spki(&self, explicit: bool) -> Vec<u8> {
        match self {
            Key::Rsa(k) => seq(&[
                &alg("1.2.840.113549.1.1.1", Some(&[0x05, 0x00])),
                &bits(k.public_key().as_ref()),
            ]),
            Key::RsaFixed(_) => seq(&[
                &alg("1.2.840.113549.1.1.1", Some(&[0x05, 0x00])),
                &bits(&seq(&[&int(&unhex(RSA_FIXED_N)), &int_u(65537)])),
            ]),
            Key::P256(k) => {
                let params = if explicit {
                    explicit_params(P256_P, P256_A, P256_B, P256_GX, P256_GY, P256_N)
                } else {
                    oid("1.2.840.10045.3.1.7")
                };
                ec_spki(params, k.verifying_key().to_sec1_point(false).as_bytes())
            }
            Key::P384(k) => ec_spki(
                oid("1.3.132.0.34"),
                k.verifying_key().to_sec1_point(false).as_bytes(),
            ),
            Key::Bp256(k) => {
                let params = if explicit {
                    explicit_params(BP256_P, BP256_A, BP256_B, BP256_GX, BP256_GY, BP256_N)
                } else {
                    oid("1.3.36.3.3.2.8.1.1.7")
                };
                ec_spki(params, k.verifying_key().to_sec1_point(false).as_bytes())
            }
            Key::Bp384(k) => {
                let params = if explicit {
                    explicit_params(BP384_P, BP384_A, BP384_B, BP384_GX, BP384_GY, BP384_N)
                } else {
                    oid("1.3.36.3.3.2.8.1.1.11")
                };
                ec_spki(params, k.verifying_key().to_sec1_point(false).as_bytes())
            }
        }
    }

    /// AlgorithmIdentifier of the signature this key makes under `scheme`.
    fn sig_alg(&self, scheme: Scheme) -> Vec<u8> {
        let ix = |h: H, l: [&str; 4]| {
            match h {
                H::Sha1 => l[0],
                H::Sha256 => l[1],
                H::Sha384 => l[2],
                H::Sha512 => l[3],
            }
            .to_string()
        };
        match scheme {
            Scheme::Pkcs1(h) => {
                let o = ix(
                    h,
                    [
                        "1.2.840.113549.1.1.5",
                        "1.2.840.113549.1.1.11",
                        "1.2.840.113549.1.1.12",
                        "1.2.840.113549.1.1.13",
                    ],
                );
                alg(&o, Some(&[0x05, 0x00]))
            }
            Scheme::Pss => {
                let sha = alg(SHA256, Some(&[0x05, 0x00]));
                let params = seq(&[
                    &t(0xA0, &[&sha]),
                    &t(0xA1, &[&alg("1.2.840.113549.1.1.8", Some(&sha))]),
                    &t(0xA2, &[&int_u(32)]),
                ]);
                alg("1.2.840.113549.1.1.10", Some(&params))
            }
            Scheme::Ecdsa(h) => alg(
                &ix(
                    h,
                    [
                        "1.2.840.10045.4.1",
                        "1.2.840.10045.4.3.2",
                        "1.2.840.10045.4.3.3",
                        "1.2.840.10045.4.3.4",
                    ],
                ),
                None,
            ),
            Scheme::EcdsaPlain(h) => alg(
                &ix(
                    h,
                    [
                        "0.4.0.127.0.7.1.1.4.1.1",
                        "0.4.0.127.0.7.1.1.4.1.3",
                        "0.4.0.127.0.7.1.1.4.1.4",
                        "0.4.0.127.0.7.1.1.4.1.5",
                    ],
                ),
                None,
            ),
            Scheme::EcdsaRawMislabeled => alg("1.2.840.10045.4.3.2", None),
        }
    }

    fn sign(&self, scheme: Scheme, msg: &[u8]) -> Vec<u8> {
        let (h, plain) = match scheme {
            Scheme::Ecdsa(h) => (h, false),
            Scheme::EcdsaPlain(h) => (h, true),
            Scheme::EcdsaRawMislabeled => (H::Sha256, true),
            Scheme::Pkcs1(h) => (h, false),
            Scheme::Pss => (H::Sha256, false),
        };
        let (r, s) = match self {
            Key::Rsa(k) => {
                let pad = match scheme {
                    Scheme::Pkcs1(H::Sha256) => &RSA_PKCS1_SHA256,
                    Scheme::Pss => &RSA_PSS_SHA256,
                    _ => panic!("scheme not available for this test key"),
                };
                let mut sig = vec![0u8; k.public_modulus_len()];
                k.sign(pad, &SystemRandom::new(), msg, &mut sig).unwrap();
                return sig;
            }
            Key::RsaFixed(k) => {
                let Scheme::Pkcs1(h) = scheme else {
                    panic!("fixed RSA key signs PKCS#1 v1.5 only");
                };
                let pad = rsa::Pkcs1v15Sign {
                    hash_len: Some(h.digest(b"").len()),
                    prefix: h.digest_info_prefix().into_boxed_slice(),
                };
                return k.sign(pad, &h.digest(msg)).unwrap();
            }
            Key::P256(k) => ec_sign!(p256::NistP256, k, h, msg),
            Key::P384(k) => ec_sign!(p384::NistP384, k, h, msg),
            Key::Bp256(k) => ec_sign!(bp256::BrainpoolP256r1, k, h, msg),
            Key::Bp384(k) => ec_sign!(bp384::BrainpoolP384r1, k, h, msg),
        };
        if plain {
            [r, s].concat()
        } else {
            seq(&[&int(&r), &int(&s)])
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

fn p384_key(seed: u8) -> Key {
    Key::P384(ecdsa::SigningKey::from_slice(&[seed; 48]).unwrap())
}

fn bp256_key(seed: u8) -> Key {
    Key::Bp256(ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap())
}

fn bp384_key(seed: u8) -> Key {
    Key::Bp384(ecdsa::SigningKey::from_slice(&[seed; 48]).unwrap())
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
    /// Outer signatureAlgorithm with NULL parameters the TBS one lacks.
    outer_null: bool,
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
    let outer = if spec.outer_null {
        let mut v = sig_alg[2..].to_vec();
        v.extend([0x05, 0x00]);
        seq(&[&v])
    } else {
        sig_alg
    };
    seq(&[&tbs, &outer, &bits(&sig)])
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
            outer_null: false,
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
        Scheme::Pkcs1(H::Sha256),
        "400101000000Z",
    )
}

fn csca_p256() -> Csca {
    csca(
        "CSCA P256",
        p256_key(7),
        SKI_CSCA_P256,
        Scheme::Ecdsa(H::Sha256),
        "400101000000Z",
    )
}

fn csca_bp() -> Csca {
    csca(
        "CSCA BP",
        bp256_key(9),
        SKI_CSCA_BP,
        Scheme::Ecdsa(H::Sha256),
        "400101000000Z",
    )
}

fn csca_other() -> Csca {
    csca(
        "CSCA OTHER",
        p256_key(3),
        SKI_OTHER,
        Scheme::Ecdsa(H::Sha256),
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
            outer_null: false,
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
    /// Hash of the LDSSecurityObject.
    lds: H,
    /// AKI of the DS certificate when not the issuing CSCA's key id.
    aki: Option<&'static [u8]>,
    outer_null: bool,
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
            aki: Some(ds.aki.unwrap_or(ds.csca.ski)),
            explicit: ds.explicit,
            outer_null: ds.outer_null,
        },
        &ds.key,
        &ds.csca.key,
        ds.cert_scheme,
    );
    let lso = seq(&[
        &int_u(0),
        &alg(ds.lds.oid(), Some(&[0x05, 0x00])),
        &seq(&[
            &seq(&[&int_u(1), &octets(&ds.lds.digest(DG1))]),
            &seq(&[&int_u(2), &octets(&ds.lds.digest(DG2))]),
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
        cert_scheme: Scheme::Pkcs1(H::Sha256),
        sod_scheme: Scheme::Pss,
        not_before: "250101000000Z",
        lds: H::Sha256,
        aki: None,
        outer_null: false,
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
        cert_scheme: Scheme::Ecdsa(H::Sha256),
        sod_scheme: Scheme::Ecdsa(H::Sha256),
        not_before: "250101000000Z",
        lds: H::Sha256,
        aki: None,
        outer_null: false,
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
        cert_scheme: Scheme::Ecdsa(H::Sha256),
        sod_scheme: Scheme::EcdsaPlain(H::Sha256),
        not_before: "250101000000Z",
        lds: H::Sha256,
        aki: None,
        outer_null: false,
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
        cert_scheme: Scheme::Ecdsa(H::Sha256),
        sod_scheme: Scheme::Ecdsa(H::Sha256),
        not_before: "250101000000Z",
        lds: H::Sha256,
        aki: None,
        outer_null: false,
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
        cert_scheme: Scheme::Ecdsa(H::Sha256),
        sod_scheme: Scheme::Ecdsa(H::Sha256),
        not_before: "250101000000Z",
        lds: H::Sha256,
        aki: None,
        outer_null: false,
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
        Scheme::Ecdsa(H::Sha256),
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
        cert_scheme: Scheme::Pkcs1(H::Sha256),
        sod_scheme: Scheme::Pss,
        not_before: "250101000000Z",
        lds: H::Sha256,
        aki: None,
        outer_null: false,
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
            outer_null: false,
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

// ---------------------------------------------------------------- review round 1

fn ds_of(csca: &Csca, key: Key, cert_scheme: Scheme, sod_scheme: Scheme) -> Ds<'_> {
    Ds {
        csca,
        key,
        explicit: false,
        cert_scheme,
        sod_scheme,
        not_before: "250101000000Z",
        lds: H::Sha256,
        aki: None,
        outer_null: false,
    }
}

#[test]
fn sod_without_dg1_is_unverifiable() {
    let (rsa, p, bp) = all_cscas();
    let s = p256_sod(&p);
    let ml = load_master_list(&master_list(&[&rsa, &p, &bp])).unwrap();
    assert_eq!(
        verify_sod(&s, &[(2, DG2)], &ml, AT),
        ChipStatus::Unverifiable
    );
    assert_eq!(verify_sod(&s, &[], &ml, AT), ChipStatus::Unverifiable);
    // A wrong hash still wins over the missing DG1.
    assert_eq!(verify_sod(&s, &[(2, DG1)], &ml, AT), ChipStatus::Invalid);
}

#[test]
fn passive_auth_ecdsa_p384_sha384_verified() {
    let (rsa, p, bp) = all_cscas();
    let s = sod(&ds_of(
        &p,
        p384_key(51),
        Scheme::Ecdsa(H::Sha256),
        Scheme::Ecdsa(H::Sha384),
    ));
    assert_eq!(
        check(&s, &master_list(&[&rsa, &p, &bp])),
        ChipStatus::Verified
    );
}

#[test]
fn passive_auth_brainpool384_explicit_sha384_verified() {
    let (rsa, p, bp) = all_cscas();
    let mut ds = ds_of(
        &bp,
        bp384_key(52),
        Scheme::Ecdsa(H::Sha384),
        Scheme::Ecdsa(H::Sha384),
    );
    ds.explicit = true;
    assert_eq!(
        check(&sod(&ds), &master_list(&[&rsa, &p, &bp])),
        ChipStatus::Verified
    );
    // Same key, plain r||s under the BSI OID.
    ds.sod_scheme = Scheme::EcdsaPlain(H::Sha384);
    assert_eq!(
        check(&sod(&ds), &master_list(&[&rsa, &p, &bp])),
        ChipStatus::Verified
    );
}

#[test]
fn lds_hashes_in_sha512_verified() {
    let (rsa, p, bp) = all_cscas();
    let mut ds = ds_of(
        &p,
        p256_key(21),
        Scheme::Ecdsa(H::Sha256),
        Scheme::Ecdsa(H::Sha512),
    );
    ds.lds = H::Sha512;
    assert_eq!(
        check(&sod(&ds), &master_list(&[&rsa, &p, &bp])),
        ChipStatus::Verified
    );
}

#[test]
fn csca_rsa_pkcs1_sha1_verified() {
    let (rsa, p, bp) = all_cscas();
    let old = csca(
        "CSCA RSA SHA1",
        Key::RsaFixed(rsa_fixed()),
        b"csca-rsa-sha1",
        Scheme::Pkcs1(H::Sha1),
        "400101000000Z",
    );
    let s = sod(&ds_of(
        &old,
        p256_key(21),
        Scheme::Pkcs1(H::Sha1),
        Scheme::Ecdsa(H::Sha1),
    ));
    assert_eq!(
        check(&s, &master_list(&[&rsa, &p, &bp, &old])),
        ChipStatus::Verified
    );
}

#[test]
fn aki_collision_falls_back_to_issuer_name() {
    let (rsa, p, bp) = all_cscas();
    let ml = master_list(&[&rsa, &p, &bp]);
    // Issued by the brainpool CSCA, AKI naming the P-256 CSCA's key.
    let mut ds = ds_of(
        &bp,
        bp256_key(33),
        Scheme::Ecdsa(H::Sha256),
        Scheme::Ecdsa(H::Sha256),
    );
    ds.aki = Some(SKI_CSCA_P256);
    assert_eq!(check(&sod(&ds), &ml), ChipStatus::Verified);
    // Issued by an unlisted CSCA under another name, same AKI: the key id
    // match alone does not make it a forgery.
    let other = csca_other();
    let mut ds = ds_of(
        &other,
        p256_key(21),
        Scheme::Ecdsa(H::Sha256),
        Scheme::Ecdsa(H::Sha256),
    );
    ds.aki = Some(SKI_CSCA_P256);
    assert_eq!(check(&sod(&ds), &ml), ChipStatus::Unverifiable);
}

#[test]
fn raw_signature_under_der_oid_is_invalid() {
    let (rsa, p, bp) = all_cscas();
    let s = sod(&ds_of(
        &p,
        p256_key(21),
        Scheme::Ecdsa(H::Sha256),
        Scheme::EcdsaRawMislabeled,
    ));
    assert_eq!(
        check(&s, &master_list(&[&rsa, &p, &bp])),
        ChipStatus::Invalid
    );
}

#[test]
fn tbs_and_outer_signature_algorithms_must_match() {
    let (rsa, p, bp) = all_cscas();
    let mut ds = ds_of(
        &p,
        p256_key(21),
        Scheme::Ecdsa(H::Sha256),
        Scheme::Ecdsa(H::Sha256),
    );
    ds.outer_null = true;
    assert_eq!(
        check(&sod(&ds), &master_list(&[&rsa, &p, &bp])),
        ChipStatus::Invalid
    );
}
