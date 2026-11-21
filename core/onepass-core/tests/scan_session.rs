//! The `IcaoSession` state machine against `FakeChip`, a simulated ePassport
//! that speaks BAC, PACE (ECDH generic mapping on P-256, AES-128) and secure
//! messaging, written here from the ICAO 9303 part 11 text on top of the raw
//! cipher crates (not the session's own code).
//!
//! Every document here is synthetic: the ICAO specimen identity (ERIKSSON
//! ANNA MARIA, L898902C3), made-up portrait bytes and throwaway CSCA, DS and
//! master list signer keys built at test time.

use std::collections::HashMap;

use aes::Aes128;
use aes::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use cmac::{Cmac, Mac};
use des::{Des, TdesEde2};
use onepass_core::scan::apdu::{AID_EMRTD, EF_CARD_ACCESS, EF_COM, EF_DG1, EF_DG2, EF_SOD};
use onepass_core::scan::icao::dg::ImageFormat;
use onepass_core::scan::icao::session::{AccessKey, ChipRead, IcaoSession, SessionRandom, Step};
use onepass_core::scan::icao::{ChipStatus, IcaoError, MasterList, load_master_list};
use onepass_core::scan::mrz::{Mrz, check_digit, parse_td3};
use onepass_core::scan::tlv::{encode, parse_one};
use p256::elliptic_curve::point::AffineCoordinates;
use p256::elliptic_curve::sec1::{FromSec1Point, ToSec1Point};
use p256::elliptic_curve::{Group, PrimeField};
use p256::{AffinePoint, FieldBytes, NonZeroScalar, ProjectivePoint, Scalar};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use time::macros::date;

const TODAY: time::Date = date!(2026 - 11 - 21);

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02X}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

// ---------------------------------------------------------------- MRZ

const SURNAME: &str = "ERIKSSON";
const GIVEN: &str = "ANNA<MARIA";
const NUMBER: &str = "L898902C3";
const BIRTH: &str = "740812";
const EXPIRY: &str = "120415";

fn cd(s: &str) -> char {
    char::from(b'0' + check_digit(s))
}

/// The two TD3 lines of a synthetic document, check digits computed.
fn mrz_lines(surname: &str, given: &str, number: &str) -> [String; 2] {
    let l1 = format!("P<UTO{:<<39}", format!("{surname}<<{given}"));
    let num = format!("{number:<<9}");
    let opt = "ZE184226B<<<<<";
    let mut l2 = String::new();
    l2.push_str(&num);
    l2.push(cd(&num));
    l2.push_str("UTO");
    l2.push_str(BIRTH);
    l2.push(cd(BIRTH));
    l2.push('F');
    l2.push_str(EXPIRY);
    l2.push(cd(EXPIRY));
    l2.push_str(opt);
    l2.push(cd(opt));
    let composite = format!("{}{}{}", &l2[0..10], &l2[13..20], &l2[21..43]);
    l2.push(cd(&composite));
    [l1, l2]
}

fn mrz(lines: &[String; 2]) -> Mrz {
    parse_td3(&[&lines[0], &lines[1]]).expect("synthetic MRZ is valid")
}

fn specimen() -> [String; 2] {
    mrz_lines(SURNAME, GIVEN, NUMBER)
}

/// The BAC / PACE password: number, birth and expiry with check digits.
fn seed_of(lines: &[String; 2]) -> String {
    mrz(lines).bac_key_seed_input()
}

// ---------------------------------------------------------------- DER, PKI

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

fn name(cn: &str) -> Vec<u8> {
    seq(&[
        &set(&[&seq(&[&oid("2.5.4.6"), &encode(0x13, b"UT")])]),
        &set(&[&seq(&[&oid("2.5.4.3"), &encode(0x0C, cn.as_bytes())])]),
    ])
}

const SHA256_OID: &str = "2.16.840.1.101.3.4.2.1";
const ECDSA_SHA256: &str = "1.2.840.10045.4.3.2";

fn sha256(b: &[u8]) -> Vec<u8> {
    Sha256::digest(b).to_vec()
}

fn key(seed: u8) -> p256::ecdsa::SigningKey {
    p256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap()
}

fn spki(k: &p256::ecdsa::SigningKey) -> Vec<u8> {
    seq(&[
        &seq(&[&oid("1.2.840.10045.2.1"), &oid("1.2.840.10045.3.1.7")]),
        &bits(k.verifying_key().to_sec1_point(false).as_bytes()),
    ])
}

/// ECDSA P-256 over SHA-256, RFC 6979 nonce (deterministic), DER.
fn sign(k: &p256::ecdsa::SigningKey, msg: &[u8]) -> Vec<u8> {
    let (sig, _) = ecdsa::hazmat::sign_prehashed_rfc6979::<p256::NistP256, Sha256>(
        k.as_nonzero_scalar(),
        &sha256(msg),
        &[],
    );
    let (r, s) = sig.split_bytes();
    seq(&[&int(&r), &int(&s)])
}

struct Cert<'a> {
    serial: u64,
    issuer: &'a [u8],
    subject: &'a [u8],
    not_before: &'a str,
    not_after: &'a str,
    ski: &'a [u8],
    aki: &'a [u8],
}

fn cert(c: &Cert, key: &p256::ecdsa::SigningKey, issuer: &p256::ecdsa::SigningKey) -> Vec<u8> {
    let exts = [
        seq(&[&oid("2.5.29.14"), &octets(&octets(c.ski))]),
        seq(&[&oid("2.5.29.35"), &octets(&seq(&[&encode(0x80, c.aki)]))]),
    ];
    let sig_alg = seq(&[&oid(ECDSA_SHA256)]);
    let tbs = seq(&[
        &t(0xA0, &[&int_u(2)]),
        &int_u(c.serial),
        &sig_alg,
        c.issuer,
        &seq(&[
            &encode(0x17, c.not_before.as_bytes()),
            &encode(0x17, c.not_after.as_bytes()),
        ]),
        c.subject,
        &spki(key),
        &t(0xA3, &[&seq(&[&exts[0], &exts[1]])]),
    ]);
    let sig = sign(issuer, &tbs);
    seq(&[&tbs, &sig_alg, &bits(&sig)])
}

fn signed_data(
    econtent_type: &str,
    econtent: &[u8],
    signer_cert: &[u8],
    issuer: &[u8],
    serial: u64,
    key: &p256::ecdsa::SigningKey,
) -> Vec<u8> {
    let digest_alg = seq(&[&oid(SHA256_OID), &[0x05, 0x00]]);
    let signed_attrs = set(&[
        &seq(&[&oid("1.2.840.113549.1.9.3"), &set(&[&oid(econtent_type)])]),
        &seq(&[
            &oid("1.2.840.113549.1.9.4"),
            &set(&[&octets(&sha256(econtent))]),
        ]),
        &seq(&[
            &oid("1.2.840.113549.1.9.5"),
            &set(&[&encode(0x17, b"250601000000Z")]),
        ]),
    ]);
    let sig = sign(key, &signed_attrs);
    let mut implicit = signed_attrs.clone();
    implicit[0] = 0xA0;
    let signer_info = seq(&[
        &int_u(1),
        &seq(&[issuer, &int_u(serial)]),
        &digest_alg,
        &implicit,
        &seq(&[&oid(ECDSA_SHA256)]),
        &octets(&sig),
    ]);
    let sd = seq(&[
        &int_u(3),
        &set(&[&digest_alg]),
        &seq(&[&oid(econtent_type), &t(0xA0, &[&octets(econtent)])]),
        &t(0xA0, &[signer_cert]),
        &set(&[&signer_info]),
    ]);
    seq(&[&oid("1.2.840.113549.1.7.2"), &t(0xA0, &[&sd])])
}

const CSCA_SKI: &[u8] = b"csca-p256-key-id";

fn csca_name() -> Vec<u8> {
    name("CSCA SPECIMEN")
}

fn csca_cert() -> Vec<u8> {
    let n = csca_name();
    cert(
        &Cert {
            serial: 1,
            issuer: &n,
            subject: &n,
            not_before: "200101000000Z",
            not_after: "400101000000Z",
            ski: CSCA_SKI,
            aki: CSCA_SKI,
        },
        &key(7),
        &key(7),
    )
}

/// The trusted test master list: the specimen CSCA, signed by a list
/// signer it issued.
fn master_list_bytes() -> Vec<u8> {
    let signer = key(5);
    let signer_cert = cert(
        &Cert {
            serial: 77,
            issuer: &csca_name(),
            subject: &name("ML SIGNER"),
            not_before: "240101000000Z",
            not_after: "340101000000Z",
            ski: b"ml-signer",
            aki: CSCA_SKI,
        },
        &signer,
        &key(7),
    );
    let content = seq(&[&int_u(0), &set(&[&csca_cert()])]);
    signed_data(
        "2.23.136.1.1.2",
        &content,
        &signer_cert,
        &csca_name(),
        77,
        &signer,
    )
}

fn master_list() -> MasterList {
    load_master_list(&master_list_bytes()).expect("test master list loads")
}

/// EF.SOD over DG1 and DG2, signed by a DS the specimen CSCA issued.
fn sod(dg1: &[u8], dg2: &[u8]) -> Vec<u8> {
    let ds = key(21);
    let ds_cert = cert(
        &Cert {
            serial: 4242,
            issuer: &csca_name(),
            subject: &name("DS"),
            not_before: "250101000000Z",
            not_after: "350101000000Z",
            ski: b"ds-key",
            aki: CSCA_SKI,
        },
        &ds,
        &key(7),
    );
    let lso = seq(&[
        &int_u(0),
        &seq(&[&oid(SHA256_OID), &[0x05, 0x00]]),
        &seq(&[
            &seq(&[&int_u(1), &octets(&sha256(dg1))]),
            &seq(&[&int_u(2), &octets(&sha256(dg2))]),
        ]),
    ]);
    let ci = signed_data("2.23.136.1.1.1", &lso, &ds_cert, &csca_name(), 4242, &ds);
    encode(0x77, &ci)
}

// ---------------------------------------------------------------- LDS files

fn dg1(lines: &[String; 2]) -> Vec<u8> {
    let joined = format!("{}{}", lines[0], lines[1]);
    encode(0x61, &encode(0x5F1F, joined.as_bytes()))
}

/// A synthetic "JPEG": the SOI marker then filler bytes, `len` in all.
fn portrait_bytes(len: usize) -> Vec<u8> {
    let mut v = vec![0xFF, 0xD8, 0xFF, 0xE0];
    v.extend((0..len.saturating_sub(6)).map(|i| (i * 31 % 251) as u8));
    v.extend([0xFF, 0xD9]);
    v
}

/// DG2: 75 / 7F61 { 02 count, 7F60 { 5F2E ISO 19794-5 block } }.
fn dg2(jpeg: &[u8]) -> Vec<u8> {
    let mut block = b"FAC\x00".to_vec();
    block.extend([0u8; 10]); // rest of the 14-byte general header
    block.extend([0u8; 20]); // facial information, 0 feature points
    block.extend([0u8; 12]); // image information
    block.extend_from_slice(jpeg);
    let bit = encode(0x7F60, &encode(0x5F2E, &block));
    encode(0x75, &encode(0x7F61, &[encode(0x02, &[1]), bit].concat()))
}

fn ef_com() -> Vec<u8> {
    encode(
        0x60,
        &[
            encode(0x5F01, b"0107"),
            encode(0x5F36, b"040000"),
            encode(0x5C, &[0x61, 0x75]),
        ]
        .concat(),
    )
}

/// id-PACE-ECDH-GM-AES-CBC-CMAC-128 content octets.
const PACE_OID: [u8; 10] = [0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x02];

fn card_access(param_ids: &[u8]) -> Vec<u8> {
    let infos: Vec<Vec<u8>> = param_ids
        .iter()
        .map(|&id| {
            seq(&[
                &encode(0x06, &PACE_OID),
                &encode(0x02, &[2]),
                &encode(0x02, &[id]),
            ])
        })
        .collect();
    let refs: Vec<&[u8]> = infos.iter().map(Vec::as_slice).collect();
    set(&refs)
}

// ---------------------------------------------------------------- chip crypto

#[derive(Clone, Copy, Debug, PartialEq)]
enum Cip {
    Tdes,
    Aes,
}

impl Cip {
    fn bs(self) -> usize {
        match self {
            Cip::Tdes => 8,
            Cip::Aes => 16,
        }
    }
}

fn pad(mut v: Vec<u8>, bs: usize) -> Vec<u8> {
    v.push(0x80);
    while !v.len().is_multiple_of(bs) {
        v.push(0);
    }
    v
}

fn unpad(v: &[u8]) -> Option<Vec<u8>> {
    let end = v.iter().rposition(|&b| b != 0)?;
    (v[end] == 0x80).then(|| v[..end].to_vec())
}

fn ecb(c: Cip, key: &[u8], blk: &mut [u8], enc: bool) {
    match c {
        Cip::Tdes => {
            let k = TdesEde2::new_from_slice(key).unwrap();
            if enc {
                k.encrypt_block(blk.try_into().unwrap());
            } else {
                k.decrypt_block(blk.try_into().unwrap());
            }
        }
        Cip::Aes => {
            let k = Aes128::new_from_slice(key).unwrap();
            if enc {
                k.encrypt_block(blk.try_into().unwrap());
            } else {
                k.decrypt_block(blk.try_into().unwrap());
            }
        }
    }
}

fn cbc_enc(c: Cip, key: &[u8], iv: &[u8], data: &[u8]) -> Vec<u8> {
    let mut out = data.to_vec();
    let mut prev = iv.to_vec();
    for blk in out.chunks_mut(c.bs()) {
        for (b, p) in blk.iter_mut().zip(&prev) {
            *b ^= p;
        }
        ecb(c, key, blk, true);
        prev = blk.to_vec();
    }
    out
}

fn cbc_dec(c: Cip, key: &[u8], iv: &[u8], data: &[u8]) -> Vec<u8> {
    let mut out = data.to_vec();
    let mut prev = iv.to_vec();
    for blk in out.chunks_mut(c.bs()) {
        let cur = blk.to_vec();
        ecb(c, key, blk, false);
        for (b, p) in blk.iter_mut().zip(&prev) {
            *b ^= p;
        }
        prev = cur;
    }
    out
}

/// Retail MAC (ISO 9797-1 alg 3) or AES-CMAC, 8 bytes, over padded input.
fn mac8(c: Cip, key: &[u8], padded: &[u8]) -> Vec<u8> {
    match c {
        Cip::Tdes => {
            let k1 = Des::new_from_slice(&key[..8]).unwrap();
            let k2 = Des::new_from_slice(&key[8..]).unwrap();
            let mut h = [0u8; 8];
            for blk in padded.chunks(8) {
                for i in 0..8 {
                    h[i] ^= blk[i];
                }
                k1.encrypt_block((&mut h).into());
            }
            k2.decrypt_block((&mut h).into());
            k1.encrypt_block((&mut h).into());
            h.to_vec()
        }
        Cip::Aes => {
            let mut m = <Cmac<Aes128> as cmac::KeyInit>::new_from_slice(key).unwrap();
            m.update(padded);
            m.finalize().into_bytes()[..8].to_vec()
        }
    }
}

fn sha1(parts: &[&[u8]]) -> Vec<u8> {
    let mut h = Sha1::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().to_vec()
}

/// 3DES key from SHA-1(seed || counter), odd parity.
fn kdf_tdes(seed: &[u8], counter: u32) -> Vec<u8> {
    let mut k = sha1(&[seed, &counter.to_be_bytes()])[..16].to_vec();
    for b in &mut k {
        let ones = (*b >> 1).count_ones();
        *b = (*b & 0xFE) | u8::from(ones % 2 == 0);
    }
    k
}

/// AES-128 key from SHA-1(k || counter).
fn kdf_aes(k: &[u8], counter: u32) -> Vec<u8> {
    sha1(&[k, &counter.to_be_bytes()])[..16].to_vec()
}

fn point(b: &[u8]) -> Option<ProjectivePoint> {
    if b.len() != 65 || b[0] != 0x04 {
        return None;
    }
    let a: Option<AffinePoint> = AffinePoint::from_sec1_bytes(b).ok();
    a.map(ProjectivePoint::from)
}

fn enc_point(p: &ProjectivePoint) -> Vec<u8> {
    p.to_affine().to_sec1_point(false).as_bytes().to_vec()
}

fn scalar(b: &[u8]) -> NonZeroScalar {
    NonZeroScalar::try_from(b).unwrap()
}

fn token_input(pk: &[u8]) -> Vec<u8> {
    encode(
        0x7F49,
        &[encode(0x06, &PACE_OID), encode(0x86, pk)].concat(),
    )
}

// ---------------------------------------------------------------- FakeChip

/// The chip side of secure messaging.
struct ChipSm {
    c: Cip,
    enc: Vec<u8>,
    mac: Vec<u8>,
    ssc: Vec<u8>,
}

impl ChipSm {
    fn inc(&mut self) {
        for b in self.ssc.iter_mut().rev() {
            *b = b.wrapping_add(1);
            if *b != 0 {
                break;
            }
        }
    }

    fn iv(&self) -> Vec<u8> {
        match self.c {
            Cip::Tdes => vec![0; 8],
            Cip::Aes => {
                let mut b = self.ssc.clone();
                ecb(Cip::Aes, &self.enc, &mut b, true);
                b
            }
        }
    }

    /// Check and decrypt a protected command: (data, Le), or `None`.
    fn unwrap_cmd(&mut self, header: [u8; 4], body: &[u8]) -> Option<(Vec<u8>, Option<usize>)> {
        self.inc();
        let bs = self.c.bs();
        let mut rest = body;
        let mut raws = Vec::new();
        let mut crypto: Option<(u32, Vec<u8>)> = None;
        let mut le = None;
        let mut mac = None;
        while !rest.is_empty() {
            let start = body.len() - rest.len();
            let (el, after) = parse_one(rest).ok()?;
            let raw = &body[start..body.len() - after.len()];
            match el.tag {
                0x85 | 0x87 => {
                    crypto = Some((el.tag, el.value.to_vec()));
                    raws.extend_from_slice(raw);
                }
                0x97 => {
                    le = Some(match el.value {
                        [0] => 256,
                        [n] => usize::from(*n),
                        [a, b] => usize::from(u16::from_be_bytes([*a, *b])),
                        _ => return None,
                    });
                    raws.extend_from_slice(raw);
                }
                0x8E => mac = Some(el.value.to_vec()),
                _ => return None,
            }
            rest = after;
        }
        let mut mi = self.ssc.clone();
        mi.extend(pad(header.to_vec(), bs));
        mi.extend_from_slice(&raws);
        if mac? != mac8(self.c, &self.mac, &pad(mi, bs)) {
            return None;
        }
        let data = match crypto {
            None => Vec::new(),
            Some((tag, v)) => {
                let ct = if tag == 0x87 {
                    if v.first() != Some(&0x01) {
                        return None;
                    }
                    &v[1..]
                } else {
                    &v[..]
                };
                if ct.is_empty() || ct.len() % bs != 0 {
                    return None;
                }
                unpad(&cbc_dec(self.c, &self.enc, &self.iv(), ct))?
            }
        };
        Some((data, le))
    }

    /// Protect a response: DO85 (odd INS) or DO87, DO99, DO8E, then 9000.
    fn wrap_resp(&mut self, ins: u8, data: &[u8], sw: u16) -> Vec<u8> {
        self.inc();
        let bs = self.c.bs();
        let mut body = Vec::new();
        if !data.is_empty() {
            let ct = cbc_enc(self.c, &self.enc, &self.iv(), &pad(data.to_vec(), bs));
            if ins & 1 == 1 {
                body.extend(encode(0x85, &ct));
            } else {
                body.extend(encode(0x87, &[&[0x01][..], &ct].concat()));
            }
        }
        body.extend(encode(0x99, &sw.to_be_bytes()));
        let mut mi = self.ssc.clone();
        mi.extend_from_slice(&body);
        let m = mac8(self.c, &self.mac, &pad(mi, bs));
        body.extend(encode(0x8E, &m));
        body.extend([0x90, 0x00]);
        body
    }
}

#[derive(Default)]
struct PaceChip {
    step: u8,
    nonce: Vec<u8>,
    g_hat: Option<ProjectivePoint>,
    eph_pk: Vec<u8>,
    ks_enc: Vec<u8>,
    ks_mac: Vec<u8>,
    with_reference: bool,
}

/// Chip-side randoms, fixed so a read is reproducible.
const RND_ICC: [u8; 8] = [0x46, 0x08, 0xF9, 0x19, 0x88, 0x70, 0x22, 0x12];
const K_ICC: [u8; 16] = [0x0B; 16];
const PACE_NONCE: [u8; 16] = [0x5A; 16];
const CHIP_MAP_SK: [u8; 32] = [0x33; 32];
const CHIP_EPH_SK: [u8; 32] = [0x44; 32];

#[derive(Clone, Copy, PartialEq)]
enum Quirk {
    None,
    /// Answers the first GENERAL AUTHENTICATE with 6982.
    PaceBroken,
    /// Answers the first plain READ BINARY with 6Cxx (the right Le).
    WrongLeOnce,
    /// Answers GET CHALLENGE with 6108, then GET RESPONSE.
    ChallengeViaGetResponse,
}

struct FakeChip {
    /// BAC / PACE password of the document in the chip.
    seed: String,
    card_access: Option<Vec<u8>>,
    files: HashMap<u16, Vec<u8>>,
    quirk: Quirk,
    quirk_used: bool,
    applet: bool,
    selected: Option<u16>,
    sm: Option<ChipSm>,
    rnd_icc: Option<[u8; 8]>,
    pace: PaceChip,
    pending: Vec<u8>,
    log: Vec<(Vec<u8>, Vec<u8>)>,
}

impl FakeChip {
    fn passport(lines: &[String; 2], jpeg: &[u8]) -> Self {
        let d1 = dg1(lines);
        let d2 = dg2(jpeg);
        let s = sod(&d1, &d2);
        let mut files = HashMap::new();
        files.insert(EF_COM, ef_com());
        files.insert(EF_SOD, s);
        files.insert(EF_DG1, d1);
        files.insert(EF_DG2, d2);
        FakeChip {
            seed: seed_of(lines),
            card_access: Some(card_access(&[12])),
            files,
            quirk: Quirk::None,
            quirk_used: false,
            applet: false,
            selected: None,
            sm: None,
            rnd_icc: None,
            pace: PaceChip::default(),
            pending: Vec::new(),
            log: Vec::new(),
        }
    }

    fn specimen() -> Self {
        FakeChip::passport(&specimen(), &portrait_bytes(1200))
    }

    fn transmit(&mut self, apdu: &[u8]) -> Vec<u8> {
        let mut out = self.process(apdu);
        // A short APDU answer holds at most 256 data bytes.
        if out.len() > SHORT_MAX + 2 {
            out = vec![0x67, 0x00];
        }
        self.log.push((apdu.to_vec(), out.clone()));
        out
    }

    fn sw(data: &[u8], sw: u16) -> Vec<u8> {
        let mut v = data.to_vec();
        v.extend(sw.to_be_bytes());
        v
    }

    fn process(&mut self, apdu: &[u8]) -> Vec<u8> {
        if apdu.len() < 4 {
            return Self::sw(&[], 0x6700);
        }
        let header = [apdu[0], apdu[1], apdu[2], apdu[3]];
        let rest = &apdu[4..];
        let (data, le): (Vec<u8>, Option<usize>) = match rest.len() {
            0 => (Vec::new(), None),
            1 => (
                Vec::new(),
                Some(if rest[0] == 0 {
                    256
                } else {
                    usize::from(rest[0])
                }),
            ),
            _ => {
                let lc = usize::from(rest[0]);
                let Some(d) = rest.get(1..1 + lc) else {
                    return Self::sw(&[], 0x6700);
                };
                let le = match rest.get(1 + lc..) {
                    Some([]) => None,
                    Some([0]) => Some(256),
                    Some([n]) => Some(usize::from(*n)),
                    _ => return Self::sw(&[], 0x6700),
                };
                (d.to_vec(), le)
            }
        };
        if header[0] & 0x0C == 0x0C {
            let Some(mut sm) = self.sm.take() else {
                return Self::sw(&[], 0x6982);
            };
            let Some((plain, le)) = sm.unwrap_cmd(header, &data) else {
                // SM error: the chip drops the session.
                return Self::sw(&[], 0x6988);
            };
            let (out, sw) = self.exec(header, &plain, le, true);
            let resp = sm.wrap_resp(header[1], &out, sw);
            if self.sm.is_none() {
                self.sm = Some(sm);
            }
            return resp;
        }
        if self.sm.is_some() {
            // A plain command ends secure messaging.
            self.sm = None;
        }
        let (out, sw) = self.exec(header, &data, le, false);
        Self::sw(&out, sw)
    }

    fn exec(
        &mut self,
        h: [u8; 4],
        data: &[u8],
        le: Option<usize>,
        protected: bool,
    ) -> (Vec<u8>, u16) {
        let [_, ins, p1, p2] = h;
        match ins {
            0xA4 => self.select(p1, data, protected),
            0xB0 => {
                let off = (usize::from(p1 & 0x7F) << 8) | usize::from(p2);
                self.read(off, le.unwrap_or(256), protected, false)
            }
            0xB1 => {
                let Ok((el, _)) = parse_one(data) else {
                    return (vec![], 0x6A80);
                };
                if el.tag != 0x54 || el.value.is_empty() || el.value.len() > 3 {
                    return (vec![], 0x6A80);
                }
                let off = el
                    .value
                    .iter()
                    .fold(0usize, |a, &b| (a << 8) | usize::from(b));
                let le = le.unwrap_or(256);
                let n = if le >= 0x83 {
                    le - 3
                } else {
                    le.saturating_sub(2)
                };
                let (d, sw) = self.read(off, n, protected, true);
                if sw != 0x9000 && sw != 0x6282 {
                    return (d, sw);
                }
                (encode(0x53, &d), sw)
            }
            0x84 => {
                self.rnd_icc = Some(RND_ICC);
                if self.quirk == Quirk::ChallengeViaGetResponse && !self.quirk_used {
                    self.quirk_used = true;
                    self.pending = RND_ICC.to_vec();
                    return (vec![], 0x6108);
                }
                (RND_ICC.to_vec(), 0x9000)
            }
            0xC0 => {
                let d = std::mem::take(&mut self.pending);
                if d.is_empty() {
                    return (vec![], 0x6985);
                }
                (d, 0x9000)
            }
            0x82 => self.mutual_auth(data),
            0x22 => self.mse_set_at(p1, p2, data),
            0x86 => self.general_authenticate(data),
            _ => (vec![], 0x6D00),
        }
    }

    fn select(&mut self, p1: u8, data: &[u8], protected: bool) -> (Vec<u8>, u16) {
        match p1 {
            0x04 => {
                if data != AID_EMRTD {
                    return (vec![], 0x6A82);
                }
                self.applet = true;
                self.selected = None;
                (vec![], 0x9000)
            }
            0x02 if data.len() == 2 => {
                let fid = u16::from_be_bytes([data[0], data[1]]);
                if fid == EF_CARD_ACCESS {
                    if self.card_access.is_none() || self.applet {
                        return (vec![], 0x6A82);
                    }
                    self.selected = Some(fid);
                    return (vec![], 0x9000);
                }
                if !protected {
                    return (vec![], 0x6982);
                }
                if !self.applet || !self.files.contains_key(&fid) {
                    return (vec![], 0x6A82);
                }
                self.selected = Some(fid);
                (vec![], 0x9000)
            }
            _ => (vec![], 0x6A86),
        }
    }

    fn read(&mut self, off: usize, n: usize, protected: bool, odd: bool) -> (Vec<u8>, u16) {
        let Some(fid) = self.selected else {
            return (vec![], 0x6986);
        };
        let file = if fid == EF_CARD_ACCESS {
            if !odd && self.quirk == Quirk::WrongLeOnce && !self.quirk_used {
                self.quirk_used = true;
                return (vec![], 0x6C00 | n as u16);
            }
            self.card_access.clone().unwrap()
        } else {
            if !protected {
                return (vec![], 0x6982);
            }
            self.files[&fid].clone()
        };
        if off > file.len() {
            return (vec![], 0x6B00);
        }
        let end = (off + n).min(file.len());
        let sw = if end - off < n { 0x6282 } else { 0x9000 };
        (file[off..end].to_vec(), sw)
    }

    fn bac_keys(&self) -> (Vec<u8>, Vec<u8>) {
        let kseed = sha1(&[self.seed.as_bytes()])[..16].to_vec();
        (kdf_tdes(&kseed, 1), kdf_tdes(&kseed, 2))
    }

    fn mutual_auth(&mut self, data: &[u8]) -> (Vec<u8>, u16) {
        let Some(rnd_icc) = self.rnd_icc.take() else {
            return (vec![], 0x6985);
        };
        if data.len() != 40 {
            return (vec![], 0x6700);
        }
        let (k_enc, k_mac) = self.bac_keys();
        let (e_ifd, m_ifd) = data.split_at(32);
        if mac8(Cip::Tdes, &k_mac, &pad(e_ifd.to_vec(), 8)) != m_ifd {
            return (vec![], 0x6300);
        }
        let s = cbc_dec(Cip::Tdes, &k_enc, &[0; 8], e_ifd);
        if s[8..16] != rnd_icc {
            return (vec![], 0x6300);
        }
        let rnd_ifd = &s[..8];
        let k_ifd = &s[16..32];
        let r = [&rnd_icc[..], rnd_ifd, &K_ICC].concat();
        let e_icc = cbc_enc(Cip::Tdes, &k_enc, &[0; 8], &r);
        let m_icc = mac8(Cip::Tdes, &k_mac, &pad(e_icc.clone(), 8));
        let seed: Vec<u8> = k_ifd.iter().zip(K_ICC).map(|(a, b)| a ^ b).collect();
        let mut ssc = rnd_icc[4..].to_vec();
        ssc.extend_from_slice(&rnd_ifd[4..]);
        self.sm = Some(ChipSm {
            c: Cip::Tdes,
            enc: kdf_tdes(&seed, 1),
            mac: kdf_tdes(&seed, 2),
            ssc,
        });
        ([e_icc, m_icc].concat(), 0x9000)
    }

    fn mse_set_at(&mut self, p1: u8, p2: u8, data: &[u8]) -> (Vec<u8>, u16) {
        if (p1, p2) != (0xC1, 0xA4) || self.card_access.is_none() {
            return (vec![], 0x6A86);
        }
        let mut oid_ok = false;
        let mut pwd_ok = false;
        let mut reference = false;
        let mut rest = data;
        while !rest.is_empty() {
            let Ok((el, after)) = parse_one(rest) else {
                return (vec![], 0x6A80);
            };
            match el.tag {
                0x80 => oid_ok = el.value == PACE_OID,
                0x83 => pwd_ok = el.value == [0x01],
                0x84 => reference = el.value == [12],
                _ => return (vec![], 0x6A80),
            }
            rest = after;
        }
        if !oid_ok || !pwd_ok {
            return (vec![], 0x6A80);
        }
        self.pace = PaceChip {
            step: 1,
            with_reference: reference,
            ..PaceChip::default()
        };
        (vec![], 0x9000)
    }

    fn general_authenticate(&mut self, data: &[u8]) -> (Vec<u8>, u16) {
        let Ok((outer, _)) = parse_one(data) else {
            return (vec![], 0x6A80);
        };
        if outer.tag != 0x7C {
            return (vec![], 0x6A80);
        }
        let inner = outer.value;
        let obj = |tag: u32| -> Option<Vec<u8>> {
            let (el, _) = parse_one(inner).ok()?;
            (el.tag == tag).then(|| el.value.to_vec())
        };
        let ok = |tag: u32, v: &[u8]| (encode(0x7C, &encode(tag, v)), 0x9000);
        match self.pace.step {
            1 => {
                if self.quirk == Quirk::PaceBroken {
                    self.pace = PaceChip::default();
                    return (vec![], 0x6982);
                }
                if !inner.is_empty() {
                    return (vec![], 0x6A80);
                }
                let k = sha1(&[self.seed.as_bytes()]);
                let k_pi = kdf_aes(&k, 3);
                self.pace.nonce = PACE_NONCE.to_vec();
                self.pace.step = 2;
                ok(0x80, &cbc_enc(Cip::Aes, &k_pi, &[0; 16], &PACE_NONCE))
            }
            2 => {
                let Some(t) = obj(0x81).as_deref().and_then(point) else {
                    return (vec![], 0x6A80);
                };
                let sk = scalar(&CHIP_MAP_SK);
                let h = t * *sk;
                let mut fb = FieldBytes::default();
                fb[16..].copy_from_slice(&self.pace.nonce);
                let s: Scalar = Scalar::from_repr(fb).unwrap();
                self.pace.g_hat = Some(ProjectivePoint::generator() * s + h);
                self.pace.step = 3;
                ok(0x82, &enc_point(&(ProjectivePoint::generator() * *sk)))
            }
            3 => {
                let Some(t) = obj(0x83).as_deref().and_then(point) else {
                    return (vec![], 0x6A80);
                };
                let sk = scalar(&CHIP_EPH_SK);
                let pk = enc_point(&(self.pace.g_hat.unwrap() * *sk));
                let k = (t * *sk).to_affine().x().to_vec();
                self.pace.ks_enc = kdf_aes(&k, 1);
                self.pace.ks_mac = kdf_aes(&k, 2);
                self.pace.eph_pk = obj(0x83).unwrap();
                self.pace.step = 4;
                let r = ok(0x84, &pk);
                self.pace.g_hat = Some(point(&pk).unwrap()); // keep the chip key
                r
            }
            4 => {
                let chip_pk = enc_point(&self.pace.g_hat.unwrap());
                let want = mac8(Cip::Aes, &self.pace.ks_mac, &token_input(&chip_pk));
                if obj(0x85).as_deref() != Some(&want[..]) {
                    self.pace = PaceChip::default();
                    return (vec![], 0x6300);
                }
                let t_ic = mac8(Cip::Aes, &self.pace.ks_mac, &token_input(&self.pace.eph_pk));
                self.sm = Some(ChipSm {
                    c: Cip::Aes,
                    enc: self.pace.ks_enc.clone(),
                    mac: self.pace.ks_mac.clone(),
                    ssc: vec![0; 16],
                });
                self.pace.step = 0;
                ok(0x86, &t_ic)
            }
            _ => (vec![], 0x6985),
        }
    }

    fn used_pace(&self) -> bool {
        self.log.iter().any(|(c, _)| c.get(1) == Some(&0x22))
    }

    fn used_bac(&self) -> bool {
        self.log.iter().any(|(c, _)| c.get(1) == Some(&0x82))
    }
}

// ---------------------------------------------------------------- driver

fn rng() -> SessionRandom {
    SessionRandom {
        bac_rnd_ifd: [0x78, 0x17, 0x23, 0x86, 0x0C, 0x06, 0xC2, 0x26],
        bac_k_ifd: [0x0B; 16],
        pace_map_sk: vec![0x11; 32],
        pace_eph_sk: vec![0x22; 32],
    }
}

fn session_for(lines: &[String; 2]) -> IcaoSession {
    IcaoSession::new(AccessKey::Mrz(mrz(lines)), master_list(), TODAY).with_rng(rng())
}

/// Drives the session to the end; returns the last step and every
/// progress value seen after each response.
fn run(s: &mut IcaoSession, chip: &mut FakeChip) -> (Step, Vec<f32>) {
    let mut progress = vec![s.progress()];
    let mut step = s.start();
    for _ in 0..2000 {
        match step {
            Step::Send(apdu) => {
                let resp = chip.transmit(&apdu);
                step = s.on_response(&resp);
                progress.push(s.progress());
            }
            other => return (other, progress),
        }
    }
    panic!("session never ended");
}

fn read_ok(step: Step) -> ChipRead {
    match step {
        Step::Done(r) => r,
        Step::Failed(e) => panic!("read failed: {e}"),
        Step::Send(_) => panic!("still sending"),
    }
}

// ---------------------------------------------------------------- tests

#[test]
fn reads_passport_with_pace() {
    let mut chip = FakeChip::specimen();
    let (step, _) = run(&mut session_for(&specimen()), &mut chip);
    let r = read_ok(step);
    assert_eq!(r.status, ChipStatus::Verified);
    assert!(r.mrz == mrz(&specimen()));
    assert_eq!(r.mrz.document_number, NUMBER);
    let p = r.portrait.expect("portrait present");
    assert_eq!(p.format, ImageFormat::Jpeg);
    assert_eq!(p.bytes, portrait_bytes(1200));
    assert_eq!(r.progress_files, vec![EF_COM, EF_SOD, EF_DG1, EF_DG2]);
    assert!(chip.used_pace());
    assert!(!chip.used_bac());
    assert!(!chip.pace.with_reference, "one parameter set: no DO84");
}

#[test]
fn falls_back_to_bac_without_card_access() {
    let mut chip = FakeChip::specimen();
    chip.card_access = None;
    let (step, _) = run(&mut session_for(&specimen()), &mut chip);
    let r = read_ok(step);
    assert_eq!(r.status, ChipStatus::Verified);
    assert!(r.portrait.is_some());
    assert!(chip.used_bac());
    assert!(!chip.used_pace());
}

#[test]
fn falls_back_to_bac_when_pace_fails() {
    let mut chip = FakeChip::specimen();
    chip.quirk = Quirk::PaceBroken;
    let (step, _) = run(&mut session_for(&specimen()), &mut chip);
    let r = read_ok(step);
    assert_eq!(r.status, ChipStatus::Verified);
    assert!(chip.used_pace());
    assert!(chip.used_bac());
}

#[test]
fn wrong_mrz_is_access_denied() {
    let mut chip = FakeChip::specimen();
    let wrong = mrz_lines(SURNAME, GIVEN, "L898902C4");
    let (step, _) = run(&mut session_for(&wrong), &mut chip);
    assert!(matches!(step, Step::Failed(IcaoError::AccessDenied)));
    // PACE was refused, then the single BAC fallback was refused too.
    assert!(chip.used_pace());
    assert!(chip.used_bac());
    assert_eq!(
        chip.log
            .iter()
            .filter(|(c, _)| c.get(1) == Some(&0x22))
            .count(),
        1
    );
}

#[test]
fn wrong_mrz_without_pace_is_access_denied() {
    let mut chip = FakeChip::specimen();
    chip.card_access = None;
    let wrong = mrz_lines(SURNAME, GIVEN, "L898902C4");
    let (step, _) = run(&mut session_for(&wrong), &mut chip);
    assert!(matches!(step, Step::Failed(IcaoError::AccessDenied)));
}

#[test]
fn reads_file_in_chunks_with_long_length() {
    let jpeg = portrait_bytes(40 * 1024);
    let mut chip = FakeChip::passport(&specimen(), &jpeg);
    let dg2_len = chip.files[&EF_DG2].len();
    assert!(dg2_len > 0x7FFF, "DG2 must need offsets above 32767");
    let (step, _) = run(&mut session_for(&specimen()), &mut chip);
    let r = read_ok(step);
    assert_eq!(r.status, ChipStatus::Verified);
    assert_eq!(r.portrait.unwrap().bytes, jpeg);
    // Offsets above 0x7FFF go through READ BINARY with odd INS.
    assert!(chip.log.iter().any(|(c, _)| c.get(1) == Some(&0xB1)));
    // Every read asks for at most 0xE0 bytes (Le in DO97 of the wrapped
    // command is checked by the chip: nothing above E0 + 3 for B1).
    let reads = chip
        .log
        .iter()
        .filter(|(c, _)| matches!(c.get(1), Some(0xB0 | 0xB1)))
        .count();
    assert!(reads >= dg2_len / 0xE0);
}

#[test]
fn dg1_mismatch_fails() {
    // The chip opens with the scanned keys, but its DG1 holds another
    // document number (SOD re-signed over it, so only the check catches it).
    let mut chip = FakeChip::specimen();
    let d1 = dg1(&mrz_lines(SURNAME, GIVEN, "L898902C4"));
    let s = sod(&d1, &chip.files[&EF_DG2]);
    chip.files.insert(EF_DG1, d1);
    chip.files.insert(EF_SOD, s);
    let (step, _) = run(&mut session_for(&specimen()), &mut chip);
    assert!(matches!(step, Step::Failed(IcaoError::AccessDenied)));
}

#[test]
fn dg1_name_difference_is_accepted() {
    // Same document number and dates, another name (an OCR slip the check
    // digits do not cover): the read goes on and returns the chip's MRZ.
    let other = mrz_lines("ERIKSON", GIVEN, NUMBER);
    let mut chip = FakeChip::passport(&other, &portrait_bytes(800));
    let (step, _) = run(&mut session_for(&specimen()), &mut chip);
    let r = read_ok(step);
    assert_eq!(r.status, ChipStatus::Verified);
    assert_eq!(r.mrz.surname, "ERIKSON");
    assert!(r.mrz == mrz(&other));
}

/// Largest data field of a short response APDU.
const SHORT_MAX: usize = 256;

#[test]
fn chunks_fit_short_apdu_under_aes() {
    // PACE (AES) then BAC (3DES), DG2 past offset 0x7FFF so both B0 and
    // B1 reads run: every answer fits a short APDU and full chunks are used.
    for card_access in [true, false] {
        let jpeg = portrait_bytes(40 * 1024);
        let mut chip = FakeChip::passport(&specimen(), &jpeg);
        if !card_access {
            chip.card_access = None;
        }
        let (step, _) = run(&mut session_for(&specimen()), &mut chip);
        let r = read_ok(step);
        assert_eq!(r.portrait.unwrap().bytes, jpeg);
        assert!(chip.log.iter().all(|(_, r)| r.len() <= SHORT_MAX + 2));
        assert!(!chip.log.iter().any(|(_, r)| r == &[0x67, 0x00]));
        // A full B0 chunk (223 bytes) wraps to 242 bytes plus 9000.
        let reads = |ins: u8| {
            chip.log
                .iter()
                .filter(move |(c, _)| c.get(1) == Some(&ins))
                .map(|(_, r)| r.len())
                .max()
                .unwrap()
        };
        assert_eq!(reads(0xB0), 244);
        assert_eq!(reads(0xB1), 243);
    }
}

#[test]
fn oversized_card_access_falls_back_to_bac() {
    let mut chip = FakeChip::specimen();
    let mut ca = card_access(&[12]);
    // Declares a 5000-byte SET: past the 4096-byte cap.
    ca = [vec![0x31, 0x82, 0x13, 0x88], ca[2..].to_vec()].concat();
    ca.resize(5004, 0);
    chip.card_access = Some(ca);
    let (step, _) = run(&mut session_for(&specimen()), &mut chip);
    read_ok(step);
    assert!(chip.used_bac());
    assert!(!chip.used_pace());
    // Only the header was read before giving up.
    let ca_reads = chip
        .log
        .iter()
        .filter(|(c, _)| c.starts_with(&[0x00, 0xB0]))
        .count();
    assert_eq!(ca_reads, 1);
}

#[test]
fn progress_reaches_one() {
    let mut chip = FakeChip::passport(&specimen(), &portrait_bytes(9000));
    let mut s = session_for(&specimen());
    assert_eq!(s.progress(), 0.0);
    let (step, progress) = run(&mut s, &mut chip);
    read_ok(step);
    assert_eq!(s.progress(), 1.0);
    assert!(progress.windows(2).all(|w| w[0] <= w[1]), "monotonic");
    assert!(progress.iter().all(|p| (0.0..=1.0).contains(p)));
    // Some value strictly between, while DG2 is read.
    assert!(progress.iter().any(|&p| p > 0.3 && p < 0.99));
}

#[test]
fn tampered_dg2_reads_but_is_invalid() {
    let mut chip = FakeChip::specimen();
    let dg2 = chip.files.get_mut(&EF_DG2).unwrap();
    let n = dg2.len();
    dg2[n - 3] ^= 0x01;
    let (step, _) = run(&mut session_for(&specimen()), &mut chip);
    let r = read_ok(step);
    assert_eq!(r.status, ChipStatus::Invalid);
}

#[test]
fn two_pace_parameter_sets_send_the_reference() {
    let mut chip = FakeChip::specimen();
    chip.card_access = Some(card_access(&[12, 13]));
    let (step, _) = run(&mut session_for(&specimen()), &mut chip);
    read_ok(step);
    assert!(chip.used_pace());
    assert!(!chip.used_bac());
    assert!(chip.pace.with_reference);
}

#[test]
fn wrong_le_is_resent_with_the_chip_length() {
    let mut chip = FakeChip::specimen();
    chip.quirk = Quirk::WrongLeOnce;
    let (step, _) = run(&mut session_for(&specimen()), &mut chip);
    read_ok(step);
    assert!(chip.quirk_used);
    assert!(chip.used_pace());
}

#[test]
fn get_response_is_followed() {
    let mut chip = FakeChip::specimen();
    chip.card_access = None;
    chip.quirk = Quirk::ChallengeViaGetResponse;
    let (step, _) = run(&mut session_for(&specimen()), &mut chip);
    read_ok(step);
    assert!(chip.log.iter().any(|(c, _)| c.get(1) == Some(&0xC0)));
}

#[test]
fn garbage_responses_fail_cleanly() {
    // Replace the chip's answer at each position with junk: the session
    // must end in Failed (or, for a few harmless positions, still read),
    // and never panic.
    let junk: [&[u8]; 6] = [
        &[],
        &[0x90],
        &[0x90, 0x00],
        &[0x61, 0x00],
        &[0x01, 0x02, 0x03, 0x90, 0x00],
        &[0x6C, 0x00],
    ];
    let mut clean = FakeChip::specimen();
    run(&mut session_for(&specimen()), &mut clean);
    let n = clean.log.len();
    for at in 0..n {
        for j in junk {
            let mut chip = FakeChip::specimen();
            let mut s = session_for(&specimen());
            let mut step = s.start();
            let mut i = 0;
            let end = loop {
                match step {
                    Step::Send(apdu) => {
                        let resp = chip.transmit(&apdu);
                        let resp = if i == at { j.to_vec() } else { resp };
                        i += 1;
                        step = s.on_response(&resp);
                        assert!(i < 4000, "no end");
                    }
                    other => break other,
                }
            };
            match end {
                Step::Failed(_) | Step::Done(_) => {}
                Step::Send(_) => unreachable!(),
            }
            // After the end, more input is refused, not a panic.
            assert!(matches!(s.on_response(&[0x90, 0x00]), Step::Failed(_)));
        }
    }
}

// ---------------------------------------------------------------- fixture

const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/icao/session_pace.json"
);

fn fixture_value() -> serde_json::Value {
    let mut chip = FakeChip::specimen();
    let (step, _) = run(&mut session_for(&specimen()), &mut chip);
    let r = read_ok(step);
    assert_eq!(r.status, ChipStatus::Verified);
    let rnd = rng();
    let lines = specimen();
    let exchange: Vec<serde_json::Value> = chip
        .log
        .iter()
        .map(|(c, r)| serde_json::json!({ "command": hex(c), "response": hex(r) }))
        .collect();
    serde_json::json!({
        "description": "Synthetic PACE read (P-256, AES-128) of a fake passport holding the ICAO specimen identity and made-up portrait bytes. Generated by tests/scan_session.rs; regenerate with ONEPASS_REGEN_FIXTURES=1.",
        "mrz": [lines[0], lines[1]],
        "today": "2026-11-21",
        "random": {
            "bac_rnd_ifd": hex(&rnd.bac_rnd_ifd),
            "bac_k_ifd": hex(&rnd.bac_k_ifd),
            "pace_map_sk": hex(&rnd.pace_map_sk),
            "pace_eph_sk": hex(&rnd.pace_eph_sk),
        },
        "master_list": hex(&master_list_bytes()),
        "expect": {
            "status": "verified",
            "portrait_sha256": hex(&sha256(&portrait_bytes(1200))),
        },
        "exchange": exchange,
    })
}

#[test]
fn session_fixture_is_current() {
    let want = fixture_value();
    if std::env::var("ONEPASS_REGEN_FIXTURES").as_deref() == Ok("1") {
        let mut s = serde_json::to_string_pretty(&want).unwrap();
        s.push('\n');
        std::fs::write(FIXTURE, s).unwrap();
        return;
    }
    let have = std::fs::read_to_string(FIXTURE)
        .expect("fixture missing: run with ONEPASS_REGEN_FIXTURES=1");
    let have: serde_json::Value = serde_json::from_str(&have).unwrap();
    assert!(have == want, "session_pace.json is stale: regenerate it");
}

#[test]
fn fixture_replays_against_a_fresh_session() {
    // What Task 9 does in Swift: feed the recorded responses in order and
    // check every command matches.
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(FIXTURE).unwrap()).unwrap();
    let ml = load_master_list(&unhex(v["master_list"].as_str().unwrap())).unwrap();
    let l1 = v["mrz"][0].as_str().unwrap();
    let l2 = v["mrz"][1].as_str().unwrap();
    let key = AccessKey::Mrz(parse_td3(&[l1, l2]).unwrap());
    let mut s = IcaoSession::new(key, ml, TODAY).with_rng(rng());
    let mut step = s.start();
    for e in v["exchange"].as_array().unwrap() {
        let Step::Send(cmd) = step else {
            panic!("session ended early");
        };
        assert_eq!(hex(&cmd), e["command"].as_str().unwrap());
        step = s.on_response(&unhex(e["response"].as_str().unwrap()));
    }
    assert_eq!(read_ok(step).status, ChipStatus::Verified);
}
