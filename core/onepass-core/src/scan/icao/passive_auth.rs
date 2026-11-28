//! Passive authentication (ICAO 9303 part 11 section 5.1): the Document
//! Signer's signature over EF.SOD, each data group hash against the
//! `LDSSecurityObject`, and the DS certificate up to a CSCA of the master
//! list.
//!
//! The DER is walked by hand over the raw bytes on purpose: a signature
//! covers the exact bytes the chip holds (the TBS certificate, the signed
//! attributes), which a decode and re-encode may not reproduce, and real
//! certificates break strict profiles often enough. Nothing here panics on
//! malformed input or logs certificate content.

use rsa::{BoxedUint, Pkcs1v15Sign, Pss};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};
use time::{Date, Month};
use x509_cert::der::oid::ObjectIdentifier as Oid;

use super::master_list::MasterList;
use crate::scan::tlv;

/// Outcome of passive authentication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChipStatus {
    /// Hashes, DS signature and chain to a listed CSCA all check out.
    Verified,
    /// Nothing is wrong, but the chain cannot be checked: no CSCA for the
    /// issuer, a CSCA or DS outside its validity, or an unsupported algorithm.
    Unverifiable,
    /// A hash or a signature is wrong, or EF.SOD is malformed.
    Invalid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Fail {
    Invalid,
    Unverifiable,
}

// ------------------------------------------------------------------ OIDs

const LDS_SECURITY_OBJECT: Oid = Oid::new_unwrap("2.23.136.1.1.1");
const SIGNED_DATA: Oid = Oid::new_unwrap("1.2.840.113549.1.7.2");
const ATTR_CONTENT_TYPE: Oid = Oid::new_unwrap("1.2.840.113549.1.9.3");
const ATTR_MESSAGE_DIGEST: Oid = Oid::new_unwrap("1.2.840.113549.1.9.4");
const ATTR_SIGNING_TIME: Oid = Oid::new_unwrap("1.2.840.113549.1.9.5");
const EXT_SKI: Oid = Oid::new_unwrap("2.5.29.14");
const EXT_AKI: Oid = Oid::new_unwrap("2.5.29.35");

const SHA1: Oid = Oid::new_unwrap("1.3.14.3.2.26");
const SHA256: Oid = Oid::new_unwrap("2.16.840.1.101.3.4.2.1");
const SHA384: Oid = Oid::new_unwrap("2.16.840.1.101.3.4.2.2");
const SHA512: Oid = Oid::new_unwrap("2.16.840.1.101.3.4.2.3");

const RSA_ENCRYPTION: Oid = Oid::new_unwrap("1.2.840.113549.1.1.1");
const RSA_SHA1: Oid = Oid::new_unwrap("1.2.840.113549.1.1.5");
const RSA_SHA256: Oid = Oid::new_unwrap("1.2.840.113549.1.1.11");
const RSA_SHA384: Oid = Oid::new_unwrap("1.2.840.113549.1.1.12");
const RSA_SHA512: Oid = Oid::new_unwrap("1.2.840.113549.1.1.13");
const RSA_PSS: Oid = Oid::new_unwrap("1.2.840.113549.1.1.10");
const MGF1: Oid = Oid::new_unwrap("1.2.840.113549.1.1.8");

const EC_PUBLIC_KEY: Oid = Oid::new_unwrap("1.2.840.10045.2.1");
const PRIME_FIELD: Oid = Oid::new_unwrap("1.2.840.10045.1.1");
const ECDSA_SHA1: Oid = Oid::new_unwrap("1.2.840.10045.4.1");
const ECDSA_SHA256: Oid = Oid::new_unwrap("1.2.840.10045.4.3.2");
const ECDSA_SHA384: Oid = Oid::new_unwrap("1.2.840.10045.4.3.3");
const ECDSA_SHA512: Oid = Oid::new_unwrap("1.2.840.10045.4.3.4");
// BSI TR-03111 ecdsa-plain-signatures (r||s).
const ECDSA_PLAIN_SHA1: Oid = Oid::new_unwrap("0.4.0.127.0.7.1.1.4.1.1");
const ECDSA_PLAIN_SHA256: Oid = Oid::new_unwrap("0.4.0.127.0.7.1.1.4.1.3");
const ECDSA_PLAIN_SHA384: Oid = Oid::new_unwrap("0.4.0.127.0.7.1.1.4.1.4");
const ECDSA_PLAIN_SHA512: Oid = Oid::new_unwrap("0.4.0.127.0.7.1.1.4.1.5");

const P256: Oid = Oid::new_unwrap("1.2.840.10045.3.1.7");
const P384: Oid = Oid::new_unwrap("1.3.132.0.34");
const BP256R1: Oid = Oid::new_unwrap("1.3.36.3.3.2.8.1.1.7");
const BP384R1: Oid = Oid::new_unwrap("1.3.36.3.3.2.8.1.1.11");

fn is(content: &[u8], oid: &Oid) -> bool {
    content == oid.as_bytes()
}

// ------------------------------------------------------------------ DER walk

/// One DER element: its tag, value and the whole encoding.
#[derive(Debug, Clone, Copy)]
pub(super) struct El<'a> {
    pub tag: u32,
    pub value: &'a [u8],
    pub raw: &'a [u8],
}

pub(super) fn read(b: &[u8]) -> Option<(El<'_>, &[u8])> {
    let (t, rest) = tlv::parse_one(b).ok()?;
    let raw = &b[..b.len() - rest.len()];
    Some((
        El {
            tag: t.tag,
            value: t.value,
            raw,
        },
        rest,
    ))
}

/// The single element `b` holds, nothing after it.
pub(super) fn only(b: &[u8]) -> Option<El<'_>> {
    match read(b)? {
        (e, []) => Some(e),
        _ => None,
    }
}

/// The elements of a constructed value.
pub(super) fn items(mut b: &[u8]) -> Option<Vec<El<'_>>> {
    let mut out = Vec::new();
    while !b.is_empty() {
        let (e, rest) = read(b)?;
        out.push(e);
        b = rest;
    }
    Some(out)
}

fn expect(e: El<'_>, tag: u32) -> Option<El<'_>> {
    (e.tag == tag).then_some(e)
}

/// INTEGER content without its sign padding.
fn uint(b: &[u8]) -> &[u8] {
    let n = b.iter().take_while(|&&x| x == 0).count();
    &b[n.min(b.len().saturating_sub(1))..]
}

fn small_int(e: El<'_>) -> Option<u64> {
    let e = expect(e, 0x02)?;
    let v = uint(e.value);
    if v.len() > 8 || (v.first()? & 0x80 != 0 && e.value.len() == v.len()) {
        return None;
    }
    Some(v.iter().fold(0u64, |a, &x| (a << 8) | u64::from(x)))
}

fn bit_string(e: El<'_>) -> Option<&[u8]> {
    let e = expect(e, 0x03)?;
    match e.value.split_first()? {
        (0, rest) => Some(rest),
        _ => None,
    }
}

fn digits(b: &[u8]) -> Option<u32> {
    if b.is_empty() || !b.iter().all(u8::is_ascii_digit) {
        return None;
    }
    Some(b.iter().fold(0, |a, &d| a * 10 + u32::from(d - b'0')))
}

/// UTCTime or GeneralizedTime, to the day.
fn date(e: El<'_>) -> Option<Date> {
    let (year, rest) = match e.tag {
        0x17 => {
            let yy = digits(e.value.get(..2)?)?;
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, &e.value[2..])
        }
        0x18 => (digits(e.value.get(..4)?)?, &e.value[4..]),
        _ => return None,
    };
    let month = Month::try_from(u8::try_from(digits(rest.get(..2)?)?).ok()?).ok()?;
    let day = u8::try_from(digits(rest.get(2..4)?)?).ok()?;
    Date::from_calendar_date(i32::try_from(year).ok()?, month, day).ok()
}

// ------------------------------------------------------------------ algorithms

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Hash {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl Hash {
    fn from_oid(oid: &[u8]) -> Option<Hash> {
        [
            (SHA1, Hash::Sha1),
            (SHA256, Hash::Sha256),
            (SHA384, Hash::Sha384),
            (SHA512, Hash::Sha512),
        ]
        .into_iter()
        .find_map(|(o, h)| is(oid, &o).then_some(h))
    }

    fn oid(self) -> Oid {
        match self {
            Hash::Sha1 => SHA1,
            Hash::Sha256 => SHA256,
            Hash::Sha384 => SHA384,
            Hash::Sha512 => SHA512,
        }
    }

    pub(super) fn digest(self, b: &[u8]) -> Vec<u8> {
        match self {
            Hash::Sha1 => Sha1::digest(b).to_vec(),
            Hash::Sha256 => Sha256::digest(b).to_vec(),
            Hash::Sha384 => Sha384::digest(b).to_vec(),
            Hash::Sha512 => Sha512::digest(b).to_vec(),
        }
    }

    fn len(self) -> usize {
        match self {
            Hash::Sha1 => 20,
            Hash::Sha256 => 32,
            Hash::Sha384 => 48,
            Hash::Sha512 => 64,
        }
    }
}

/// AlgorithmIdentifier: the OID content and its parameters (NULL dropped).
#[derive(Debug, Clone, Copy)]
pub(super) struct AlgId<'a> {
    oid: &'a [u8],
    params: Option<El<'a>>,
}

fn alg_id(e: El<'_>) -> Option<AlgId<'_>> {
    let e = expect(e, 0x30)?;
    let parts = items(e.value)?;
    let oid = expect(*parts.first()?, 0x06)?.value;
    let params = match parts.get(1..)? {
        [] => None,
        [p] if p.tag == 0x05 => None,
        [p] => Some(*p),
        _ => return None,
    };
    Some(AlgId { oid, params })
}

/// The hash an AlgorithmIdentifier of a digest names.
fn hash_alg(a: &AlgId<'_>) -> Result<Hash, Fail> {
    Hash::from_oid(a.oid).ok_or(Fail::Unverifiable)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scheme {
    Pkcs1(Hash),
    Pss {
        hash: Hash,
        salt: usize,
    },
    /// `plain`: BSI TR-03111 r||s encoding, otherwise X9.62 DER.
    Ecdsa {
        hash: Hash,
        plain: bool,
    },
}

/// The signature scheme of `sig_alg`. `digest` is the SignerInfo digest
/// algorithm, for the bare key OIDs some issuers put there.
fn scheme(sig_alg: &AlgId<'_>, digest: Option<Hash>) -> Result<Scheme, Fail> {
    let o = sig_alg.oid;
    let table = [
        (RSA_SHA1, Scheme::Pkcs1(Hash::Sha1)),
        (RSA_SHA256, Scheme::Pkcs1(Hash::Sha256)),
        (RSA_SHA384, Scheme::Pkcs1(Hash::Sha384)),
        (RSA_SHA512, Scheme::Pkcs1(Hash::Sha512)),
        (
            ECDSA_SHA1,
            Scheme::Ecdsa {
                hash: Hash::Sha1,
                plain: false,
            },
        ),
        (
            ECDSA_SHA256,
            Scheme::Ecdsa {
                hash: Hash::Sha256,
                plain: false,
            },
        ),
        (
            ECDSA_SHA384,
            Scheme::Ecdsa {
                hash: Hash::Sha384,
                plain: false,
            },
        ),
        (
            ECDSA_SHA512,
            Scheme::Ecdsa {
                hash: Hash::Sha512,
                plain: false,
            },
        ),
        (
            ECDSA_PLAIN_SHA1,
            Scheme::Ecdsa {
                hash: Hash::Sha1,
                plain: true,
            },
        ),
        (
            ECDSA_PLAIN_SHA256,
            Scheme::Ecdsa {
                hash: Hash::Sha256,
                plain: true,
            },
        ),
        (
            ECDSA_PLAIN_SHA384,
            Scheme::Ecdsa {
                hash: Hash::Sha384,
                plain: true,
            },
        ),
        (
            ECDSA_PLAIN_SHA512,
            Scheme::Ecdsa {
                hash: Hash::Sha512,
                plain: true,
            },
        ),
    ];
    if let Some(s) = table
        .into_iter()
        .find_map(|(oid, s)| is(o, &oid).then_some(s))
    {
        return Ok(s);
    }
    if is(o, &RSA_PSS) {
        return pss_params(sig_alg.params);
    }
    let hash = digest.ok_or(Fail::Unverifiable);
    if is(o, &RSA_ENCRYPTION) {
        return Ok(Scheme::Pkcs1(hash?));
    }
    if is(o, &EC_PUBLIC_KEY) {
        return Ok(Scheme::Ecdsa {
            hash: hash?,
            plain: false,
        });
    }
    Err(Fail::Unverifiable)
}

/// RSASSA-PSS-params (RFC 4055): every field has a SHA-1 era default.
fn pss_params(params: Option<El<'_>>) -> Result<Scheme, Fail> {
    let mut hash = Hash::Sha1;
    let mut mgf_hash = Hash::Sha1;
    let mut salt = 20usize;
    if let Some(p) = params {
        let p = expect(p, 0x30).ok_or(Fail::Invalid)?;
        for f in items(p.value).ok_or(Fail::Invalid)? {
            let inner = only(f.value).ok_or(Fail::Invalid)?;
            match f.tag {
                0xA0 => hash = hash_alg(&alg_id(inner).ok_or(Fail::Invalid)?)?,
                0xA1 => {
                    let mgf = alg_id(inner).ok_or(Fail::Invalid)?;
                    if !is(mgf.oid, &MGF1) {
                        return Err(Fail::Unverifiable);
                    }
                    let h = mgf.params.and_then(alg_id).ok_or(Fail::Invalid)?;
                    mgf_hash = hash_alg(&h)?;
                }
                0xA2 => {
                    salt = small_int(inner)
                        .and_then(|s| usize::try_from(s).ok())
                        .ok_or(Fail::Invalid)?;
                }
                0xA3 => {
                    if small_int(inner) != Some(1) {
                        return Err(Fail::Unverifiable);
                    }
                }
                _ => return Err(Fail::Invalid),
            }
        }
    }
    if hash != mgf_hash {
        // The RSA crate ties MGF1 to the message hash.
        return Err(Fail::Unverifiable);
    }
    Ok(Scheme::Pss { hash, salt })
}

// ------------------------------------------------------------------ keys

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Curve {
    P256,
    P384,
    Bp256,
    Bp384,
}

struct CurveParams {
    curve: Curve,
    p: &'static str,
    a: &'static str,
    b: &'static str,
    gx: &'static str,
    n: &'static str,
}

/// Domain parameters of the four curves, to recognise explicit ones.
const CURVES: [CurveParams; 4] = [
    CurveParams {
        curve: Curve::P256,
        p: "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
        a: "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
        b: "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
        gx: "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        n: "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
    },
    CurveParams {
        curve: Curve::P384,
        p: "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff",
        a: "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc",
        b: "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef",
        gx: "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7",
        n: "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
    },
    CurveParams {
        curve: Curve::Bp256,
        p: "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377",
        a: "7d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9",
        b: "26dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b6",
        gx: "8bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262",
        n: "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7",
    },
    CurveParams {
        curve: Curve::Bp384,
        p: "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53",
        a: "7bc382c63d8c150c3c72080ace05afa0c2bea28e4fb22787139165efba91f90f8aa5814a503ad4eb04a8c7dd22ce2826",
        b: "04a8c7dd22ce28268b39b55416f0447c2fb77de107dcd2a62e880ea53eeb62d57cb4390295dbc9943ab78696fa504c11",
        gx: "1d1c64f068cf45ffa2a63a81b7c13f6b8847a3e77ef14fe3db7fcafe0cbd10e8e826e03436d646aaef87b2e247d4af1e",
        n: "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565",
    },
];

impl Curve {
    fn field_len(self) -> usize {
        match self {
            Curve::P256 | Curve::Bp256 => 32,
            Curve::P384 | Curve::Bp384 => 48,
        }
    }
}

/// Same unsigned value: `bytes` (any leading zeros) against lowercase hex.
fn same(bytes: &[u8], hex: &str) -> bool {
    let b = uint(bytes);
    let h = hex.trim_start_matches('0');
    if h.len().div_ceil(2) != b.len() {
        return false;
    }
    let padded = format!("{h:0>width$}", width = b.len() * 2);
    b.iter().zip(padded.as_bytes().chunks(2)).all(|(x, pair)| {
        std::str::from_utf8(pair)
            .ok()
            .and_then(|s| u8::from_str_radix(s, 16).ok())
            == Some(*x)
    })
}

/// The curve of id-ecPublicKey parameters: a named OID or explicit
/// ECParameters matched value by value.
fn curve(params: Option<El<'_>>) -> Result<Curve, Fail> {
    let p = params.ok_or(Fail::Unverifiable)?;
    if p.tag == 0x06 {
        return [
            (P256, Curve::P256),
            (P384, Curve::P384),
            (BP256R1, Curve::Bp256),
            (BP384R1, Curve::Bp384),
        ]
        .into_iter()
        .find_map(|(o, c)| is(p.value, &o).then_some(c))
        .ok_or(Fail::Unverifiable);
    }
    explicit_curve(p).ok_or(Fail::Unverifiable)
}

fn explicit_curve(p: El<'_>) -> Option<Curve> {
    let parts = items(expect(p, 0x30)?.value)?;
    // version, fieldID, curve, base, order, cofactor?
    let field = items(expect(*parts.get(1)?, 0x30)?.value)?;
    if !is(expect(*field.first()?, 0x06)?.value, &PRIME_FIELD) {
        return None;
    }
    let prime = expect(*field.get(1)?, 0x02)?.value;
    let ab = items(expect(*parts.get(2)?, 0x30)?.value)?;
    let a = expect(*ab.first()?, 0x04)?.value;
    let b = expect(*ab.get(1)?, 0x04)?.value;
    let base = expect(*parts.get(3)?, 0x04)?.value;
    let order = expect(*parts.get(4)?, 0x02)?.value;
    CURVES.iter().find_map(|c| {
        let len = c.curve.field_len();
        // Uncompressed (04) or compressed (02, 03) base point: x follows.
        let gx = match base.first()? {
            0x04 if base.len() == 1 + 2 * len => &base[1..=len],
            0x02 | 0x03 if base.len() == 1 + len => &base[1..],
            _ => return None,
        };
        (same(prime, c.p) && same(a, c.a) && same(b, c.b) && same(gx, c.gx) && same(order, c.n))
            .then_some(c.curve)
    })
}

enum Key {
    Rsa(rsa::PublicKey),
    Ec(Curve, Vec<u8>),
}

fn public_key(spki: &[u8]) -> Result<Key, Fail> {
    let parts = only(spki)
        .and_then(|e| expect(e, 0x30))
        .and_then(|e| items(e.value))
        .ok_or(Fail::Invalid)?;
    let [alg, key] = parts.as_slice() else {
        return Err(Fail::Invalid);
    };
    let alg = alg_id(*alg).ok_or(Fail::Invalid)?;
    let key = bit_string(*key).ok_or(Fail::Invalid)?;
    if is(alg.oid, &RSA_ENCRYPTION) || is(alg.oid, &RSA_PSS) {
        let nums = only(key)
            .and_then(|e| expect(e, 0x30))
            .and_then(|e| items(e.value))
            .ok_or(Fail::Invalid)?;
        let [n, e] = nums.as_slice() else {
            return Err(Fail::Invalid);
        };
        let n = uint(expect(*n, 0x02).ok_or(Fail::Invalid)?.value);
        let e = uint(expect(*e, 0x02).ok_or(Fail::Invalid)?.value);
        let k = rsa::PublicKey::new_with_size_limits(
            BoxedUint::from_be_slice_vartime(n),
            BoxedUint::from_be_slice_vartime(e),
            1024..=8192,
        )
        .map_err(|_| Fail::Unverifiable)?;
        return Ok(Key::Rsa(k));
    }
    if is(alg.oid, &EC_PUBLIC_KEY) {
        return Ok(Key::Ec(curve(alg.params)?, key.to_vec()));
    }
    Err(Fail::Unverifiable)
}

/// r||s from the encoding the signature algorithm names: a plain r||s of
/// the right length (BSI OIDs) or a DER ECDSA-Sig-Value (X9.62 OIDs).
fn ec_rs(sig: &[u8], len: usize, plain: bool) -> Option<Vec<u8>> {
    if plain {
        return (sig.len() == 2 * len).then(|| sig.to_vec());
    }
    only(sig)
        .and_then(|e| expect(e, 0x30))
        .and_then(|e| items(e.value))
        .and_then(|parts| match parts.as_slice() {
            [r, s] => {
                let r = uint(expect(*r, 0x02)?.value);
                let s = uint(expect(*s, 0x02)?.value);
                if r.len() > len || s.len() > len {
                    return None;
                }
                let mut out = vec![0u8; 2 * len];
                out[len - r.len()..len].copy_from_slice(r);
                out[2 * len - s.len()..].copy_from_slice(s);
                Some(out)
            }
            _ => None,
        })
}

macro_rules! ec_verify {
    ($curve:ty, $point:expr, $z:expr, $rs:expr) => {{
        use ecdsa::signature::hazmat::PrehashVerifier;
        let vk =
            ecdsa::VerifyingKey::<$curve>::from_sec1_bytes($point).map_err(|_| Fail::Invalid)?;
        let sig = ecdsa::Signature::<$curve>::from_slice($rs).map_err(|_| Fail::Invalid)?;
        vk.verify_prehash($z, &sig).map_err(|_| Fail::Invalid)
    }};
}

/// PKCS#1 v1.5 DigestInfo prefix for `hash`, with or without the NULL
/// parameters (both are seen in the field).
fn digest_info_prefix(hash: Hash, with_null: bool) -> Vec<u8> {
    let oid = tlv::encode(0x06, hash.oid().as_bytes());
    let alg = if with_null {
        tlv::encode(0x30, &[oid.as_slice(), &[0x05, 0x00]].concat())
    } else {
        tlv::encode(0x30, &oid)
    };
    let zero = vec![0u8; hash.len()];
    let full = tlv::encode(0x30, &[alg, tlv::encode(0x04, &zero)].concat());
    full[..full.len() - hash.len()].to_vec()
}

fn pss_verify<D: Digest + sha2::digest::FixedOutputReset>(
    key: &rsa::PublicKey,
    salt: usize,
    hashed: &[u8],
    sig: &[u8],
) -> bool {
    let scheme = Pss::<D> {
        blinded: false,
        digest: D::new(),
        salt_len: Some(salt),
    };
    key.verify(scheme, hashed, sig).is_ok()
}

/// Verifies `sig` over `msg` with the key in `spki` under `sig_alg`.
pub(super) fn verify(
    spki: &[u8],
    sig_alg: &AlgId<'_>,
    digest: Option<Hash>,
    msg: &[u8],
    sig: &[u8],
) -> Result<(), Fail> {
    let scheme = scheme(sig_alg, digest)?;
    let key = public_key(spki)?;
    match (scheme, key) {
        (Scheme::Pkcs1(h), Key::Rsa(k)) => {
            let hashed = h.digest(msg);
            let ok = [true, false].into_iter().any(|with_null| {
                let pad = Pkcs1v15Sign {
                    hash_len: Some(h.len()),
                    prefix: digest_info_prefix(h, with_null).into_boxed_slice(),
                };
                k.verify(pad, &hashed, sig).is_ok()
            });
            ok.then_some(()).ok_or(Fail::Invalid)
        }
        (Scheme::Pss { hash, salt }, Key::Rsa(k)) => {
            let hashed = hash.digest(msg);
            let ok = match hash {
                Hash::Sha1 => pss_verify::<Sha1>(&k, salt, &hashed, sig),
                Hash::Sha256 => pss_verify::<Sha256>(&k, salt, &hashed, sig),
                Hash::Sha384 => pss_verify::<Sha384>(&k, salt, &hashed, sig),
                Hash::Sha512 => pss_verify::<Sha512>(&k, salt, &hashed, sig),
            };
            ok.then_some(()).ok_or(Fail::Invalid)
        }
        (Scheme::Ecdsa { hash, plain }, Key::Ec(curve, point)) => {
            let z = hash.digest(msg);
            let rs = ec_rs(sig, curve.field_len(), plain).ok_or(Fail::Invalid)?;
            match curve {
                Curve::P256 => ec_verify!(p256::NistP256, &point, &z, &rs),
                Curve::P384 => ec_verify!(p384::NistP384, &point, &z, &rs),
                Curve::Bp256 => ec_verify!(bp256::BrainpoolP256r1, &point, &z, &rs),
                Curve::Bp384 => ec_verify!(bp384::BrainpoolP384r1, &point, &z, &rs),
            }
        }
        // The algorithm does not fit the key.
        _ => Err(Fail::Invalid),
    }
}

// ------------------------------------------------------------------ certificates

/// The parts of an X.509 certificate passive authentication needs, as
/// views into the original bytes.
pub(super) struct Cert<'a> {
    pub tbs: &'a [u8],
    pub sig_alg: AlgId<'a>,
    pub sig: &'a [u8],
    pub serial: &'a [u8],
    pub issuer: &'a [u8],
    pub subject: &'a [u8],
    pub not_before: Date,
    pub not_after: Date,
    pub spki: &'a [u8],
    pub ski: Option<&'a [u8]>,
    pub aki: Option<&'a [u8]>,
    /// The TBS `signature` field is byte for byte the outer
    /// `signatureAlgorithm` (RFC 5280 4.1.1.2).
    pub algs_match: bool,
}

impl<'a> Cert<'a> {
    pub(super) fn parse(der: &'a [u8]) -> Option<Cert<'a>> {
        let outer = items(expect(only(der)?, 0x30)?.value)?;
        let [tbs, sig_alg, sig] = outer.as_slice() else {
            return None;
        };
        let tbs = expect(*tbs, 0x30)?;
        let outer_alg = sig_alg.raw;
        let sig_alg = alg_id(*sig_alg)?;
        let sig = bit_string(*sig)?;

        let mut f = items(tbs.value)?.into_iter().peekable();
        if f.peek()?.tag == 0xA0 {
            f.next();
        }
        let serial = uint(expect(f.next()?, 0x02)?.value);
        let inner_alg = f.next()?;
        alg_id(inner_alg)?;
        let issuer = expect(f.next()?, 0x30)?.raw;
        let validity = items(expect(f.next()?, 0x30)?.value)?;
        let [nb, na] = validity.as_slice() else {
            return None;
        };
        let not_before = date(*nb)?;
        let not_after = date(*na)?;
        let subject = expect(f.next()?, 0x30)?.raw;
        let spki = expect(f.next()?, 0x30)?.raw;
        let mut ski = None;
        let mut aki = None;
        for e in f {
            if e.tag != 0xA3 {
                continue;
            }
            for ext in items(expect(only(e.value)?, 0x30)?.value)? {
                let parts = items(expect(ext, 0x30)?.value)?;
                let id = expect(*parts.first()?, 0x06)?.value;
                let value = expect(*parts.last()?, 0x04)?.value;
                if is(id, &EXT_SKI) {
                    ski = Some(expect(only(value)?, 0x04)?.value);
                } else if is(id, &EXT_AKI) {
                    aki = items(expect(only(value)?, 0x30)?.value)?
                        .into_iter()
                        .find(|k| k.tag == 0x80)
                        .map(|k| k.value);
                }
            }
        }
        Some(Cert {
            tbs: tbs.raw,
            sig_alg,
            sig,
            serial,
            issuer,
            subject,
            not_before,
            not_after,
            spki,
            ski,
            aki,
            algs_match: inner_alg.raw == outer_alg,
        })
    }

    pub(super) fn valid_on(&self, d: Date) -> bool {
        self.not_before <= d && d <= self.not_after
    }
}

/// Finds the CSCA in `ml` that issued `cert` and checks the certificate
/// signature with it. `valid` says whether a CSCA that signed it is usable
/// (its validity). Candidates are the CSCAs whose key identifier matches the
/// certificate AKI and those whose subject matches its issuer name.
///
/// `Invalid` only when a CSCA matching both the AKI and the issuer name
/// fails the signature: a forged certificate. A failure against a CSCA
/// matched one way only may be a key id collision or another key of the
/// same authority: `Unverifiable`. A certificate whose TBS and outer
/// signature algorithms differ is `Invalid`.
pub(super) fn check_issuer(
    cert: &Cert<'_>,
    ml: &MasterList,
    valid: impl Fn(&Cert<'_>) -> bool,
) -> Result<(), Fail> {
    if !cert.algs_match {
        return Err(Fail::Invalid);
    }
    let mut forged = false;
    for (der, by_key_id) in ml.candidates(cert.aki, cert.issuer) {
        let Some(ca) = Cert::parse(der) else {
            continue;
        };
        match verify(ca.spki, &cert.sig_alg, None, cert.tbs, cert.sig) {
            Ok(()) if valid(&ca) => return Ok(()),
            Ok(()) => {}
            Err(Fail::Invalid) if by_key_id && ca.subject == cert.issuer => forged = true,
            Err(_) => {}
        }
    }
    if forged {
        Err(Fail::Invalid)
    } else {
        Err(Fail::Unverifiable)
    }
}

// ------------------------------------------------------------------ CMS

enum Sid<'a> {
    IssuerSerial { issuer: &'a [u8], serial: &'a [u8] },
    KeyId(&'a [u8]),
}

struct SignerInfo<'a> {
    sid: Sid<'a>,
    digest: AlgId<'a>,
    signed_attrs: El<'a>,
    sig_alg: AlgId<'a>,
    sig: &'a [u8],
}

/// A CMS ContentInfo holding SignedData with one signer.
pub(super) struct Signed<'a> {
    pub econtent_type: &'a [u8],
    pub econtent: &'a [u8],
    certs: Vec<&'a [u8]>,
    signer: SignerInfo<'a>,
}

pub(super) fn parse_signed(b: &[u8]) -> Option<Signed<'_>> {
    let ci = items(expect(only(b)?, 0x30)?.value)?;
    let [ct, content] = ci.as_slice() else {
        return None;
    };
    if !is(expect(*ct, 0x06)?.value, &SIGNED_DATA) {
        return None;
    }
    let sd = expect(only(expect(*content, 0xA0)?.value)?, 0x30)?;
    let mut f = items(sd.value)?.into_iter();
    small_int(f.next()?)?;
    expect(f.next()?, 0x31)?;
    let encap = items(expect(f.next()?, 0x30)?.value)?;
    let econtent_type = expect(*encap.first()?, 0x06)?.value;
    let econtent = expect(only(expect(*encap.get(1)?, 0xA0)?.value)?, 0x04)?.value;
    let mut certs = Vec::new();
    let mut signer_infos = None;
    for e in f {
        match e.tag {
            0xA0 => certs.extend(
                items(e.value)?
                    .into_iter()
                    .filter(|c| c.tag == 0x30)
                    .map(|c| c.raw),
            ),
            0xA1 => {}
            0x31 => signer_infos = Some(e),
            _ => return None,
        }
    }
    let si = *items(signer_infos?.value)?.first()?;
    let mut f = items(expect(si, 0x30)?.value)?.into_iter();
    small_int(f.next()?)?;
    let sid = f.next()?;
    let sid = match sid.tag {
        0x30 => {
            let parts = items(sid.value)?;
            let [issuer, serial] = parts.as_slice() else {
                return None;
            };
            Sid::IssuerSerial {
                issuer: expect(*issuer, 0x30)?.raw,
                serial: uint(expect(*serial, 0x02)?.value),
            }
        }
        0x80 => Sid::KeyId(sid.value),
        _ => return None,
    };
    let digest = alg_id(f.next()?)?;
    let signed_attrs = expect(f.next()?, 0xA0)?;
    let sig_alg = alg_id(f.next()?)?;
    let sig = expect(f.next()?, 0x04)?.value;
    Some(Signed {
        econtent_type,
        econtent,
        certs,
        signer: SignerInfo {
            sid,
            digest,
            signed_attrs,
            sig_alg,
            sig,
        },
    })
}

/// Checks the signed attributes and the signer's signature. Returns the
/// signer certificate and the signing time, if the attributes carry one.
pub(super) fn check_signer<'a>(s: &Signed<'a>) -> Result<(Cert<'a>, Option<Date>), Fail> {
    let si = &s.signer;
    let digest = hash_alg(&si.digest)?;
    let mut content_type = None;
    let mut message_digest = None;
    let mut signing_time = None;
    for attr in items(si.signed_attrs.value).ok_or(Fail::Invalid)? {
        let parts = expect(attr, 0x30)
            .and_then(|a| items(a.value))
            .ok_or(Fail::Invalid)?;
        let [id, values] = parts.as_slice() else {
            return Err(Fail::Invalid);
        };
        let id = expect(*id, 0x06).ok_or(Fail::Invalid)?.value;
        let value = expect(*values, 0x31)
            .and_then(|v| only(v.value))
            .ok_or(Fail::Invalid)?;
        if is(id, &ATTR_CONTENT_TYPE) {
            content_type = Some(expect(value, 0x06).ok_or(Fail::Invalid)?.value);
        } else if is(id, &ATTR_MESSAGE_DIGEST) {
            message_digest = Some(expect(value, 0x04).ok_or(Fail::Invalid)?.value);
        } else if is(id, &ATTR_SIGNING_TIME) {
            signing_time = Some(date(value).ok_or(Fail::Invalid)?);
        }
    }
    if content_type != Some(s.econtent_type) {
        return Err(Fail::Invalid);
    }
    if message_digest != Some(digest.digest(s.econtent).as_slice()) {
        return Err(Fail::Invalid);
    }

    let certs: Vec<Cert<'a>> = s.certs.iter().filter_map(|c| Cert::parse(c)).collect();
    let pick = certs.iter().position(|c| match si.sid {
        Sid::IssuerSerial { issuer, serial } => c.issuer == issuer && c.serial == serial,
        Sid::KeyId(id) => c.ski == Some(id),
    });
    let pick = match (pick, certs.len()) {
        (Some(i), _) => i,
        (None, 1) => 0,
        _ => return Err(Fail::Unverifiable),
    };
    let cert = certs.into_iter().nth(pick).ok_or(Fail::Unverifiable)?;

    // The signature covers the attributes DER-encoded as a SET, not [0].
    let mut signed = si.signed_attrs.raw.to_vec();
    signed[0] = 0x31;
    verify(cert.spki, &si.sig_alg, Some(digest), &signed, si.sig)?;
    Ok((cert, signing_time))
}

// ------------------------------------------------------------------ EF.SOD

/// Passive authentication of a chip: the DS signature over EF.SOD, the hash
/// of each data group read (`(number, file bytes)`), and the DS certificate
/// up to a CSCA of `ml`.
///
/// The CSCA must be valid when it issued the DS (the DS `notBefore`); the
/// DS must be valid at the SOD signing time when the SOD carries one,
/// otherwise at `at`. Outside either: `Unverifiable`. `dgs` must hold DG1,
/// or the result is at best `Unverifiable`.
pub fn verify_sod(sod: &[u8], dgs: &[(u8, &[u8])], ml: &MasterList, at: Date) -> ChipStatus {
    match run(sod, dgs, ml, at) {
        Ok(()) => ChipStatus::Verified,
        Err(Fail::Invalid) => ChipStatus::Invalid,
        Err(Fail::Unverifiable) => ChipStatus::Unverifiable,
    }
}

/// `(data group number, hash)` pairs of an LDSSecurityObject.
type DgHashes<'a> = Vec<(u64, &'a [u8])>;

/// LDSSecurityObject: the hash algorithm and the hash of each DG.
fn lds_security_object(b: &[u8]) -> Option<(AlgId<'_>, DgHashes<'_>)> {
    let parts = items(expect(only(b)?, 0x30)?.value)?;
    small_int(*parts.first()?)?;
    let alg = alg_id(*parts.get(1)?)?;
    let hashes = items(expect(*parts.get(2)?, 0x30)?.value)?
        .into_iter()
        .map(|h| {
            let pair = items(expect(h, 0x30)?.value)?;
            let [n, v] = pair.as_slice() else {
                return None;
            };
            Some((small_int(*n)?, expect(*v, 0x04)?.value))
        })
        .collect::<Option<Vec<_>>>()?;
    Some((alg, hashes))
}

fn run(sod: &[u8], dgs: &[(u8, &[u8])], ml: &MasterList, at: Date) -> Result<(), Fail> {
    let outer = only(sod).ok_or(Fail::Invalid)?;
    let ci = match outer.tag {
        0x77 => outer.value,
        0x30 => sod,
        _ => return Err(Fail::Invalid),
    };
    let signed = parse_signed(ci).ok_or(Fail::Invalid)?;
    if !is(signed.econtent_type, &LDS_SECURITY_OBJECT) {
        return Err(Fail::Invalid);
    }
    let (alg, hashes) = lds_security_object(signed.econtent).ok_or(Fail::Invalid)?;
    let hash = hash_alg(&alg)?;
    for &(n, data) in dgs {
        let want = hashes
            .iter()
            .find(|(k, _)| *k == u64::from(n))
            .map(|(_, h)| *h)
            .ok_or(Fail::Invalid)?;
        if hash.digest(data) != want {
            return Err(Fail::Invalid);
        }
    }
    let (ds, signing_time) = check_signer(&signed)?;
    check_issuer(&ds, ml, |csca| csca.valid_on(ds.not_before))?;
    if !ds.valid_on(signing_time.unwrap_or(at)) {
        return Err(Fail::Unverifiable);
    }
    // Without DG1 nothing ties the verified chip to the document read.
    if !dgs.iter().any(|&(n, _)| n == 1) {
        return Err(Fail::Unverifiable);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_parse_both_time_types() {
        let utc = tlv::encode(0x17, b"250601120000Z");
        assert_eq!(
            date(only(&utc).unwrap()),
            Date::from_calendar_date(2025, Month::June, 1).ok()
        );
        let old = tlv::encode(0x17, b"990101000000Z");
        assert_eq!(date(only(&old).unwrap()).unwrap().year(), 1999);
        let gen_time = tlv::encode(0x18, b"20510228000000Z");
        assert_eq!(date(only(&gen_time).unwrap()).unwrap().year(), 2051);
        assert!(date(only(&tlv::encode(0x17, b"2513")).unwrap()).is_none());
        assert!(date(only(&tlv::encode(0x17, b"25x30100Z")).unwrap()).is_none());
    }

    #[test]
    fn digest_info_prefix_matches_rfc8017() {
        assert_eq!(
            digest_info_prefix(Hash::Sha256, true),
            [
                0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x01, 0x05, 0x00, 0x04, 0x20
            ]
        );
        assert_eq!(
            digest_info_prefix(Hash::Sha1, true),
            [
                0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04,
                0x14
            ]
        );
    }

    #[test]
    fn same_ignores_sign_padding() {
        assert!(same(&[0x00, 0xff, 0x01], "ff01"));
        assert!(same(&[0x01], "0001"));
        assert!(!same(&[0xff, 0x02], "ff01"));
        assert!(!same(&[], "01"));
    }

    #[test]
    fn garbage_is_invalid_not_a_panic() {
        let ml = MasterList::default();
        let at = Date::from_calendar_date(2026, Month::January, 1).unwrap();
        for b in [
            &[][..],
            &[0x77],
            &[0x77, 0x00],
            &[0x30, 0x80],
            &[0x77, 0x82, 0xff],
        ] {
            assert_eq!(verify_sod(b, &[], &ml, at), ChipStatus::Invalid);
        }
    }
}
