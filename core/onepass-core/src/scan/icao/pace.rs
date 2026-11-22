//! PACE with ECDH generic mapping (ICAO 9303-11, 4.4; worked example in
//! appendix G.1).
//!
//! Only `id-PACE-ECDH-GM-AES-CBC-CMAC-128/192/256` on the standardized
//! curves P-256 (12), brainpoolP256r1 (13), P-384 (15) and brainpoolP384r1
//! (16) are supported; anything else is `Protocol("pace-unsupported")` and
//! the caller falls back to BAC.
//!
//! Flow: MSE:Set AT, then a chain of four GENERAL AUTHENTICATE commands
//! (encrypted nonce, map nonce, key agreement, mutual authentication).
//! Generic mapping: `G' = s.G + H` with `H` the ECDH point of the mapping
//! keys. Session keys come from the x-coordinate of the ephemeral ECDH
//! point; the tokens are CMACs over the peer's public key in a 7F49
//! template. The secure channel starts with SSC 0.
//!
//! The caller supplies the private scalars (`PaceRandom`), from the OS
//! CSPRNG in real use, fixed in tests. K_pi, the nonce, the scalars, every
//! shared point and the session keys sit in zeroize-on-drop buffers.
//! Nothing here logs keys, nonces, APDU bytes or the password.

use p256::elliptic_curve::point::AffineCoordinates;
use p256::elliptic_curve::sec1::{FromSec1Point, ModulusSize, ToSec1Point};
use p256::elliptic_curve::{
    AffinePoint, CurveArithmetic, CurveGroup, FieldBytes, FieldBytesSize, Group, NonZeroScalar,
    PrimeField, ProjectivePoint, Scalar,
};
use sha1::{Digest, Sha1};
use sha2::Sha256;
use x509_cert::der::oid::ObjectIdentifier;
use zeroize::Zeroizing;

use super::IcaoError;
use super::card_access::PaceInfo;
use super::sm::{Cipher, Prim, SecureChannel, cbc_decrypt, ct_eq, mac8};
use crate::scan::apdu::{Command, Response};
use crate::scan::tlv;

#[cfg(test)]
use super::sm::cbc_encrypt;

/// id-PACE-ECDH-GM (0.4.0.127.0.7.2.2.4.2) in DER content octets.
const ID_PACE_ECDH_GM: [u8; 9] = [0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02];

const UNSUPPORTED: IcaoError = IcaoError::Protocol("pace-unsupported");
const BAD_POINT: IcaoError = IcaoError::Protocol("pace-bad-point");

/// The standardized PACE curves (9303-11, 9.5.1, table 12).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaceCurve {
    P256,
    P384,
    Brainpool256,
    Brainpool384,
}

/// Run a generic function on the concrete curve type.
macro_rules! on_curve {
    ($curve:expr, $f:ident ( $($a:expr),* )) => {
        match $curve {
            PaceCurve::P256 => $f::<p256::NistP256>($($a),*),
            PaceCurve::P384 => $f::<p384::NistP384>($($a),*),
            PaceCurve::Brainpool256 => $f::<bp256::BrainpoolP256r1>($($a),*),
            PaceCurve::Brainpool384 => $f::<bp384::BrainpoolP384r1>($($a),*),
        }
    };
}

impl PaceCurve {
    /// Standardized domain parameter ID: 12, 13, 15 or 16.
    pub fn from_parameter_id(id: u8) -> Option<Self> {
        match id {
            12 => Some(PaceCurve::P256),
            13 => Some(PaceCurve::Brainpool256),
            15 => Some(PaceCurve::P384),
            16 => Some(PaceCurve::Brainpool384),
            _ => None,
        }
    }

    /// Byte length of a field element (and of a private scalar).
    pub fn field_len(self) -> usize {
        match self {
            PaceCurve::P256 | PaceCurve::Brainpool256 => 32,
            PaceCurve::P384 | PaceCurve::Brainpool384 => 48,
        }
    }

    fn valid_scalar(self, sk: &[u8]) -> bool {
        on_curve!(self, is_scalar(sk))
    }

    /// Uncompressed `sk.G`, or `sk.gen` when a (mapped) generator is given.
    pub(crate) fn public_key(
        self,
        sk: &[u8],
        generator: Option<&[u8]>,
    ) -> Result<Vec<u8>, IcaoError> {
        on_curve!(self, public_key(sk, generator))
    }

    /// Generic mapping: `G' = s.G + sk.chip_pk`, uncompressed.
    pub(crate) fn map_generator(
        self,
        sk: &[u8],
        chip_pk: &[u8],
        s: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, IcaoError> {
        on_curve!(self, map_generator(sk, chip_pk, s))
    }

    /// ECDH: the x-coordinate of `sk.peer`.
    pub(crate) fn agree(self, sk: &[u8], peer: &[u8]) -> Result<Zeroizing<Vec<u8>>, IcaoError> {
        on_curve!(self, agree(sk, peer))
    }
}

/// A private scalar in [1, n-1], big-endian, exactly the field length.
fn scalar<C>(sk: &[u8]) -> Result<Zeroizing<NonZeroScalar<C>>, IcaoError>
where
    C: CurveArithmetic,
{
    NonZeroScalar::<C>::try_from(sk)
        .map(Zeroizing::new)
        .map_err(|_| IcaoError::Crypto)
}

fn is_scalar<C: CurveArithmetic>(sk: &[u8]) -> bool {
    scalar::<C>(sk).is_ok()
}

/// Decode a received point: uncompressed only, on the curve, not the
/// identity.
fn point<C>(b: &[u8]) -> Result<ProjectivePoint<C>, IcaoError>
where
    C: CurveArithmetic,
    AffinePoint<C>: FromSec1Point<C> + ToSec1Point<C>,
    FieldBytesSize<C>: ModulusSize,
{
    let n = FieldBytes::<C>::default().len();
    if b.len() != 1 + 2 * n || b[0] != 0x04 {
        return Err(BAD_POINT);
    }
    let a = AffinePoint::<C>::from_sec1_bytes(b).map_err(|_| BAD_POINT)?;
    let p = ProjectivePoint::<C>::from(a);
    if bool::from(p.is_identity()) {
        return Err(BAD_POINT);
    }
    Ok(p)
}

fn encode<C>(p: &ProjectivePoint<C>) -> Result<Vec<u8>, IcaoError>
where
    C: CurveArithmetic,
    AffinePoint<C>: FromSec1Point<C> + ToSec1Point<C>,
    FieldBytesSize<C>: ModulusSize,
{
    if bool::from(p.is_identity()) {
        return Err(BAD_POINT);
    }
    Ok(p.to_affine().to_sec1_point(false).as_bytes().to_vec())
}

fn public_key<C>(sk: &[u8], generator: Option<&[u8]>) -> Result<Vec<u8>, IcaoError>
where
    C: CurveArithmetic,
    AffinePoint<C>: FromSec1Point<C> + ToSec1Point<C>,
    FieldBytesSize<C>: ModulusSize,
{
    let k = scalar::<C>(sk)?;
    let g = match generator {
        Some(b) => point::<C>(b)?,
        None => ProjectivePoint::<C>::generator(),
    };
    encode::<C>(&(g * k.as_ref()))
}

fn map_generator<C>(sk: &[u8], chip_pk: &[u8], s: &[u8]) -> Result<Zeroizing<Vec<u8>>, IcaoError>
where
    C: CurveArithmetic,
    AffinePoint<C>: FromSec1Point<C> + ToSec1Point<C>,
    FieldBytesSize<C>: ModulusSize,
{
    let k = scalar::<C>(sk)?;
    let h = Zeroizing::new(point::<C>(chip_pk)? * k.as_ref());
    if bool::from(h.is_identity()) {
        return Err(BAD_POINT);
    }
    let mut repr = Zeroizing::new(FieldBytes::<C>::default());
    let n = repr.len();
    if s.is_empty() || s.len() > n {
        return Err(IcaoError::Protocol("pace-bad-nonce"));
    }
    repr[n - s.len()..].copy_from_slice(s);
    let s: Option<Scalar<C>> = Scalar::<C>::from_repr(*repr).into();
    let s = Zeroizing::new(s.ok_or(IcaoError::Protocol("pace-bad-nonce"))?);
    let g_hat = Zeroizing::new(ProjectivePoint::<C>::generator() * *s + *h);
    Ok(Zeroizing::new(encode::<C>(&g_hat)?))
}

fn agree<C>(sk: &[u8], peer: &[u8]) -> Result<Zeroizing<Vec<u8>>, IcaoError>
where
    C: CurveArithmetic,
    AffinePoint<C>: FromSec1Point<C> + ToSec1Point<C>,
    FieldBytesSize<C>: ModulusSize,
{
    let k = scalar::<C>(sk)?;
    let shared = Zeroizing::new(point::<C>(peer)? * k.as_ref());
    if bool::from(shared.is_identity()) {
        return Err(BAD_POINT);
    }
    let x = Zeroizing::new(shared.to_affine().x());
    Ok(Zeroizing::new(x.to_vec()))
}

/// KDF(K, c) (9303-11, 9.7.1): SHA-1 for AES-128, SHA-256 for AES-192
/// and AES-256, truncated to the key length.
fn kdf(cipher: Cipher, k: &[u8], counter: u32) -> Zeroizing<Vec<u8>> {
    let mut input = Zeroizing::new(Vec::with_capacity(k.len() + 4));
    input.extend_from_slice(k);
    input.extend_from_slice(&counter.to_be_bytes());
    let (digest, len) = match cipher {
        Cipher::Aes192 => (Zeroizing::new(Sha256::digest(&*input).to_vec()), 24),
        Cipher::Aes256 => (Zeroizing::new(Sha256::digest(&*input).to_vec()), 32),
        Cipher::Aes128 | Cipher::TripleDes => (Zeroizing::new(Sha1::digest(&*input).to_vec()), 16),
    };
    Zeroizing::new(digest[..len].to_vec())
}

/// K_pi = KDF(SHA-1(MRZ seed input), 3) (9303-11, 9.7.3).
fn k_pi(cipher: Cipher, password: &[u8]) -> Zeroizing<Vec<u8>> {
    let k = Zeroizing::new(Sha1::digest(password).to_vec());
    kdf(cipher, &k, 3)
}

/// s = D(K_pi, z): the block cipher in CBC mode with a zero IV.
fn decrypt_nonce(cipher: Cipher, k_pi: &[u8], z: &[u8]) -> Result<Zeroizing<Vec<u8>>, IcaoError> {
    let bs = cipher.block_size();
    if z.is_empty() || !z.len().is_multiple_of(bs) {
        return Err(IcaoError::Protocol("pace-bad-nonce"));
    }
    let prim = Prim::new(cipher, k_pi)?;
    let mut s = Zeroizing::new(z.to_vec());
    cbc_decrypt(&prim, &vec![0u8; bs], &mut s);
    Ok(s)
}

/// Authentication token input: 7F49 { 06 OID, 86 public point }.
fn token_input(oid: &ObjectIdentifier, pk: &[u8]) -> Vec<u8> {
    let mut inner = tlv::encode(0x06, oid.as_bytes());
    inner.extend_from_slice(&tlv::encode(0x86, pk));
    tlv::encode(0x7F49, &inner)
}

/// The cipher of a supported PACE OID, or `pace-unsupported`.
pub(super) fn cipher_for(oid: &ObjectIdentifier) -> Result<Cipher, IcaoError> {
    let b = oid.as_bytes();
    if b.len() != ID_PACE_ECDH_GM.len() + 1 || b[..ID_PACE_ECDH_GM.len()] != ID_PACE_ECDH_GM {
        return Err(UNSUPPORTED);
    }
    match b[ID_PACE_ECDH_GM.len()] {
        2 => Ok(Cipher::Aes128),
        3 => Ok(Cipher::Aes192),
        4 => Ok(Cipher::Aes256),
        _ => Err(UNSUPPORTED),
    }
}

/// The terminal's private scalars for one PACE run: the mapping key and
/// the ephemeral key-agreement key, each big-endian of the curve's field
/// length and in [1, n-1].
pub struct PaceRandom {
    map_sk: Zeroizing<Vec<u8>>,
    eph_sk: Zeroizing<Vec<u8>>,
}

impl PaceRandom {
    /// Fixed scalars (tests, or randoms drawn by the caller).
    pub fn new(map_sk: &[u8], eph_sk: &[u8]) -> Self {
        PaceRandom {
            map_sk: Zeroizing::new(map_sk.to_vec()),
            eph_sk: Zeroizing::new(eph_sk.to_vec()),
        }
    }

    /// Two fresh scalars for `curve` from the hedged generator (`crypto::random`).
    pub fn generate(curve: PaceCurve) -> Result<Self, IcaoError> {
        let draw = || -> Result<Zeroizing<Vec<u8>>, IcaoError> {
            let mut b = Zeroizing::new(vec![0u8; curve.field_len()]);
            // Rejection sampling: brainpool orders sit well below 2^n.
            for _ in 0..128 {
                crate::crypto::fill_random(&mut b).map_err(|_| IcaoError::Crypto)?;
                if curve.valid_scalar(&b) {
                    return Ok(b);
                }
            }
            Err(IcaoError::Crypto)
        };
        Ok(PaceRandom {
            map_sk: draw()?,
            eph_sk: draw()?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    SetAt,
    Nonce,
    Map,
    Key,
    Token,
}

const OUT_OF_ORDER: IcaoError = IcaoError::Protocol("pace-out-of-order");

pub struct PaceExchange {
    oid: ObjectIdentifier,
    parameter_id: u8,
    with_reference: bool,
    cipher: Cipher,
    curve: PaceCurve,
    rnd: PaceRandom,
    k_pi: Zeroizing<Vec<u8>>,
    step: Step,
    nonce: Zeroizing<Vec<u8>>,
    eph_pk: Vec<u8>,
    ks_enc: Zeroizing<Vec<u8>>,
    ks_mac: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for PaceExchange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PaceExchange({:?}, {:?})", self.curve, self.cipher)
    }
}

/// GENERAL AUTHENTICATE with `inner` in a 7C template; chained except
/// for the last step.
fn general_authenticate(last: bool, inner: &[u8]) -> Command {
    Command {
        cla: if last { 0x00 } else { 0x10 },
        ins: 0x86,
        p1: 0x00,
        p2: 0x00,
        data: tlv::encode(0x7C, inner),
        le: Some(256),
    }
}

/// The data object `tag` inside the 7C response template.
fn response_object(r: &Response, tag: u32) -> Result<&[u8], IcaoError> {
    if !r.ok() {
        return Err(IcaoError::Chip(r.sw));
    }
    tlv::find(&r.data, &[0x7C, tag]).ok_or(IcaoError::Protocol("pace-missing-object"))
}

impl PaceExchange {
    /// `password` is the MRZ seed input (`Mrz::bac_key_seed_input`).
    pub fn new(info: &PaceInfo, password: &[u8], rnd: PaceRandom) -> Result<Self, IcaoError> {
        let cipher = cipher_for(&info.oid)?;
        let curve = PaceCurve::from_parameter_id(info.parameter_id).ok_or(UNSUPPORTED)?;
        if !curve.valid_scalar(&rnd.map_sk) || !curve.valid_scalar(&rnd.eph_sk) {
            return Err(IcaoError::Crypto);
        }
        Ok(PaceExchange {
            oid: info.oid,
            parameter_id: info.parameter_id,
            with_reference: false,
            cipher,
            curve,
            rnd,
            k_pi: k_pi(cipher, password),
            step: Step::SetAt,
            nonce: Zeroizing::new(Vec::new()),
            eph_pk: Vec::new(),
            ks_enc: Zeroizing::new(Vec::new()),
            ks_mac: Zeroizing::new(Vec::new()),
        })
    }

    /// Also send the domain parameter reference (DO84) in MSE:Set AT.
    /// 9303-11 4.4.4.1 requires it when the chip offers more than one set
    /// of domain parameters for PACE: set it exactly when
    /// `parse_card_access` yields more than one distinct `parameter_id`.
    pub fn with_parameter_reference(mut self) -> Self {
        self.with_reference = true;
        self
    }

    /// MSE:Set AT: the PACE OID (80), the MRZ as password (83 01 01) and,
    /// with `with_parameter_reference`, the parameter ID (84 01 id).
    pub fn msg_set_at(&self) -> Result<Command, IcaoError> {
        if self.step != Step::SetAt {
            return Err(OUT_OF_ORDER);
        }
        let mut data = tlv::encode(0x80, self.oid.as_bytes());
        data.extend_from_slice(&tlv::encode(0x83, &[0x01]));
        if self.with_reference {
            data.extend_from_slice(&tlv::encode(0x84, &[self.parameter_id]));
        }
        Ok(Command {
            cla: 0x00,
            ins: 0x22,
            p1: 0xC1,
            p2: 0xA4,
            data,
            le: None,
        })
    }

    pub fn on_set_at(&mut self, r: &Response) -> Result<(), IcaoError> {
        if self.step != Step::SetAt {
            return Err(OUT_OF_ORDER);
        }
        if !r.ok() {
            return Err(IcaoError::Chip(r.sw));
        }
        self.step = Step::Nonce;
        Ok(())
    }

    /// Step 1: ask for the encrypted nonce (empty 7C).
    pub fn msg_nonce(&self) -> Result<Command, IcaoError> {
        if self.step != Step::Nonce {
            return Err(OUT_OF_ORDER);
        }
        Ok(general_authenticate(false, &[]))
    }

    /// Decrypt the nonce and answer with the terminal's mapping key (81).
    pub fn on_nonce(&mut self, r: &Response) -> Result<Command, IcaoError> {
        if self.step != Step::Nonce {
            return Err(OUT_OF_ORDER);
        }
        let z = response_object(r, 0x80)?;
        self.nonce = decrypt_nonce(self.cipher, &self.k_pi, z)?;
        let pk = self.curve.public_key(&self.rnd.map_sk, None)?;
        self.step = Step::Map;
        Ok(general_authenticate(false, &tlv::encode(0x81, &pk)))
    }

    /// Map the nonce with the chip's mapping key (82) and answer with the
    /// terminal's ephemeral key on the mapped generator (83).
    pub fn on_map(&mut self, r: &Response) -> Result<Command, IcaoError> {
        if self.step != Step::Map {
            return Err(OUT_OF_ORDER);
        }
        let chip_pk = response_object(r, 0x82)?;
        let g_hat = self
            .curve
            .map_generator(&self.rnd.map_sk, chip_pk, &self.nonce)?;
        self.nonce = Zeroizing::new(Vec::new());
        self.eph_pk = self.curve.public_key(&self.rnd.eph_sk, Some(&g_hat))?;
        self.step = Step::Key;
        Ok(general_authenticate(
            false,
            &tlv::encode(0x83, &self.eph_pk),
        ))
    }

    /// Agree on the session keys with the chip's ephemeral key (84) and
    /// answer with the terminal's token (85).
    pub fn on_key(&mut self, r: &Response) -> Result<Command, IcaoError> {
        if self.step != Step::Key {
            return Err(OUT_OF_ORDER);
        }
        let chip_pk = response_object(r, 0x84)?;
        // 9303-11, 4.4.3.4: the two ephemeral public keys must differ.
        if ct_eq(chip_pk, &self.eph_pk) {
            return Err(IcaoError::Protocol("pace-same-key"));
        }
        let k = self.curve.agree(&self.rnd.eph_sk, chip_pk)?;
        self.ks_enc = kdf(self.cipher, &k, 1);
        self.ks_mac = kdf(self.cipher, &k, 2);
        let t_ifd = mac8(self.cipher, &self.ks_mac, &token_input(&self.oid, chip_pk))?;
        self.step = Step::Token;
        Ok(general_authenticate(true, &tlv::encode(0x85, &t_ifd)))
    }

    /// Check the chip's token (86) and open the secure channel (SSC 0).
    pub fn on_token(self, r: &Response) -> Result<SecureChannel, IcaoError> {
        if self.step != Step::Token {
            return Err(OUT_OF_ORDER);
        }
        if matches!(r.sw, 0x6300 | 0x6982) {
            return Err(IcaoError::AccessDenied);
        }
        let t_ic = response_object(r, 0x86)?;
        let want = mac8(
            self.cipher,
            &self.ks_mac,
            &token_input(&self.oid, &self.eph_pk),
        )?;
        if !ct_eq(&want, t_ic) {
            return Err(IcaoError::AccessDenied);
        }
        let ssc = [0u8; 16];
        SecureChannel::new(self.cipher, &self.ks_enc, &self.ks_mac, &ssc)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::scan::icao::testutil::{hex, unhex};

    const G1: &str = include_str!("../../../tests/fixtures/icao/pace_appendix_g1.json");

    /// A hex vector from the appendix G.1 fixture. Points come back as
    /// the uncompressed encoding 04 || x || y.
    pub(crate) fn g1(name: &str) -> String {
        let v: serde_json::Value = serde_json::from_str(G1).unwrap();
        let e = &v["vectors"][name];
        if let Some(h) = e["hex"].as_str() {
            return h.to_string();
        }
        let (x, y) = (e["x"].as_str(), e["y"].as_str());
        format!("04{}{}", x.expect(name), y.expect(name))
    }

    fn b(name: &str) -> Vec<u8> {
        unhex(&g1(name))
    }

    fn resp(name: &str) -> Response {
        Response::parse(&b(name)).unwrap()
    }

    fn seed() -> String {
        let v: serde_json::Value = serde_json::from_str(G1).unwrap();
        v["mrz"]["seed_input"].as_str().unwrap().to_string()
    }

    fn info_g1() -> PaceInfo {
        PaceInfo {
            oid: ObjectIdentifier::new_unwrap("0.4.0.127.0.7.2.2.4.2.2"),
            parameter_id: 13,
        }
    }

    fn exchange_g1() -> PaceExchange {
        let rnd = PaceRandom::new(&b("map_terminal_sk"), &b("ka_terminal_sk"));
        PaceExchange::new(&info_g1(), seed().as_bytes(), rnd).unwrap()
    }

    #[test]
    fn pace_k_pi_and_nonce_appendix_g() {
        let k_pi = k_pi(Cipher::Aes128, seed().as_bytes());
        assert_eq!(hex(&k_pi), g1("k_pi"));
        let s = decrypt_nonce(Cipher::Aes128, &k_pi, &b("nonce_z")).unwrap();
        assert_eq!(hex(&s), g1("nonce_s"));
    }

    #[test]
    fn pace_mapping_and_agreement_appendix_g() {
        let c = PaceCurve::Brainpool256;
        assert_eq!(
            hex(&c.public_key(&b("map_terminal_sk"), None).unwrap()),
            g1("map_terminal_pk")
        );
        let g_hat = c
            .map_generator(&b("map_terminal_sk"), &b("map_chip_pk"), &b("nonce_s"))
            .unwrap();
        assert_eq!(hex(&g_hat), g1("mapped_generator"));
        assert_eq!(
            hex(&c.public_key(&b("ka_terminal_sk"), Some(&g_hat)).unwrap()),
            g1("ka_terminal_pk")
        );
        let k = c.agree(&b("ka_terminal_sk"), &b("ka_chip_pk")).unwrap();
        assert_eq!(hex(&k), g1("shared_secret"));
        assert_eq!(hex(&kdf(Cipher::Aes128, &k, 1)), g1("ks_enc"));
        assert_eq!(hex(&kdf(Cipher::Aes128, &k, 2)), g1("ks_mac"));
        let oid = info_g1().oid;
        assert_eq!(
            hex(&token_input(&oid, &b("ka_chip_pk"))),
            g1("token_input_ifd")
        );
        assert_eq!(
            hex(&token_input(&oid, &b("ka_terminal_pk"))),
            g1("token_input_ic")
        );
    }

    #[test]
    fn pace_gm_brainpool_appendix_g() {
        let mut x = exchange_g1();
        assert_eq!(
            hex(&x.msg_set_at().unwrap().to_bytes()),
            g1("mse_set_at_cmd")
        );
        x.on_set_at(&resp("mse_set_at_resp")).unwrap();
        assert_eq!(hex(&x.msg_nonce().unwrap().to_bytes()), g1("ga1_cmd"));
        let map = x.on_nonce(&resp("ga1_resp")).unwrap();
        assert_eq!(hex(&map.to_bytes()), g1("ga2_cmd"));
        let key = x.on_map(&resp("ga2_resp")).unwrap();
        assert_eq!(hex(&key.to_bytes()), g1("ga3_cmd"));
        let token = x.on_key(&resp("ga3_resp")).unwrap();
        assert_eq!(hex(&token.to_bytes()), g1("ga4_cmd"));
        let ch = x.on_token(&resp("ga4_resp")).unwrap();
        assert_eq!(ch.cipher(), Cipher::Aes128);
        assert_eq!(hex(ch.ks_enc()), g1("ks_enc"));
        assert_eq!(hex(ch.ks_mac()), g1("ks_mac"));
        assert_eq!(ch.ssc(), &[0u8; 16]);
    }

    #[test]
    fn pace_set_at_with_parameter_reference() {
        // The G.1 command with DO84 = 84 01 0D after DO83, Lc 0F + 3 = 12.
        let x = exchange_g1().with_parameter_reference();
        let mut want = b("mse_set_at_cmd");
        assert_eq!(want[4], 0x0F);
        want[4] = 0x12;
        want.extend_from_slice(&[0x84, 0x01, 0x0D]);
        assert_eq!(hex(&x.msg_set_at().unwrap().to_bytes()), hex(&want));
        assert_eq!(
            hex(&exchange_g1().msg_set_at().unwrap().to_bytes()),
            g1("mse_set_at_cmd")
        );
    }

    #[test]
    fn pace_messages_check_the_step() {
        let mut x = exchange_g1();
        assert!(matches!(x.msg_nonce(), Err(IcaoError::Protocol(_))));
        x.on_set_at(&resp("mse_set_at_resp")).unwrap();
        assert!(matches!(x.msg_set_at(), Err(IcaoError::Protocol(_))));
        assert!(x.msg_nonce().is_ok());
    }

    fn run_to_token(x: &mut PaceExchange) {
        x.on_set_at(&resp("mse_set_at_resp")).unwrap();
        x.on_nonce(&resp("ga1_resp")).unwrap();
        x.on_map(&resp("ga2_resp")).unwrap();
        x.on_key(&resp("ga3_resp")).unwrap();
    }

    #[test]
    fn pace_rejects_wrong_token() {
        let mut x = exchange_g1();
        run_to_token(&mut x);
        let mut bad = b("ga4_resp");
        bad[11] ^= 0x01;
        let r = Response::parse(&bad).unwrap();
        assert!(matches!(x.on_token(&r), Err(IcaoError::AccessDenied)));

        // The chip refusing the terminal's token (wrong MRZ) is the same.
        let mut x = exchange_g1();
        run_to_token(&mut x);
        let r = Response {
            data: vec![],
            sw: 0x6300,
        };
        assert!(matches!(x.on_token(&r), Err(IcaoError::AccessDenied)));
    }

    #[test]
    fn pace_wrong_password_fails_at_token() {
        let rnd = PaceRandom::new(&b("map_terminal_sk"), &b("ka_terminal_sk"));
        let mut x = PaceExchange::new(&info_g1(), b"T22000129364081251010319", rnd).unwrap();
        x.on_set_at(&resp("mse_set_at_resp")).unwrap();
        x.on_nonce(&resp("ga1_resp")).unwrap();
        x.on_map(&resp("ga2_resp")).unwrap();
        x.on_key(&resp("ga3_resp")).unwrap();
        assert!(matches!(
            x.on_token(&resp("ga4_resp")),
            Err(IcaoError::AccessDenied)
        ));
    }

    #[test]
    fn pace_unsupported_oid_is_protocol_error() {
        let rnd = || PaceRandom::new(&b("map_terminal_sk"), &b("ka_terminal_sk"));
        // id-PACE-DH-GM-AES-CBC-CMAC-128.
        let dh = PaceInfo {
            oid: ObjectIdentifier::new_unwrap("0.4.0.127.0.7.2.2.4.1.2"),
            parameter_id: 13,
        };
        assert!(matches!(
            PaceExchange::new(&dh, seed().as_bytes(), rnd()),
            Err(IcaoError::Protocol("pace-unsupported"))
        ));
        // id-PACE-ECDH-GM-3DES-CBC-CBC and id-PACE-ECDH-IM-AES-CBC-CMAC-128.
        for o in ["0.4.0.127.0.7.2.2.4.2.1", "0.4.0.127.0.7.2.2.4.4.2"] {
            let i = PaceInfo {
                oid: ObjectIdentifier::new_unwrap(o),
                parameter_id: 13,
            };
            assert!(matches!(
                PaceExchange::new(&i, seed().as_bytes(), rnd()),
                Err(IcaoError::Protocol("pace-unsupported"))
            ));
        }
        // A supported OID on an unsupported curve (P-224, id 11).
        let p224 = PaceInfo {
            oid: info_g1().oid,
            parameter_id: 11,
        };
        assert!(matches!(
            PaceExchange::new(&p224, seed().as_bytes(), rnd()),
            Err(IcaoError::Protocol("pace-unsupported"))
        ));
    }

    #[test]
    fn pace_rejects_bad_points() {
        let c = PaceCurve::Brainpool256;
        let sk = b("map_terminal_sk");
        let s = b("nonce_s");
        // Off the curve: flip a bit of y.
        let mut off = b("map_chip_pk");
        off[64] ^= 0x01;
        assert!(matches!(
            c.map_generator(&sk, &off, &s),
            Err(IcaoError::Protocol(_))
        ));
        // The identity (SEC1 encoding 00).
        assert!(matches!(
            c.map_generator(&sk, &[0x00], &s),
            Err(IcaoError::Protocol(_))
        ));
        assert!(matches!(c.agree(&sk, &[0x00]), Err(IcaoError::Protocol(_))));
        // A point of the wrong size (P-256 generator on brainpool).
        let p256_g = PaceCurve::P256.public_key(&[1u8; 32], None).unwrap();
        assert!(matches!(c.agree(&sk, &p256_g), Err(IcaoError::Protocol(_))));

        // In the exchange: the chip echoing the terminal's own ephemeral
        // key is refused (9303-11, 4.4.3.4).
        let mut x = exchange_g1();
        x.on_set_at(&resp("mse_set_at_resp")).unwrap();
        x.on_nonce(&resp("ga1_resp")).unwrap();
        x.on_map(&resp("ga2_resp")).unwrap();
        let mut echo = tlv::encode(0x7C, &tlv::encode(0x84, &b("ka_terminal_pk")));
        echo.extend_from_slice(&[0x90, 0x00]);
        assert!(matches!(
            x.on_key(&Response::parse(&echo).unwrap()),
            Err(IcaoError::Protocol(_))
        ));
    }

    #[test]
    fn pace_steps_out_of_order_are_refused() {
        let mut x = exchange_g1();
        assert!(matches!(
            x.on_map(&resp("ga2_resp")),
            Err(IcaoError::Protocol(_))
        ));
    }

    #[test]
    fn pace_all_four_curves_round_trip() {
        // Simulate a chip with the same generic code on each curve: the
        // terminal and the chip must agree on the session keys and tokens.
        for (id, curve) in [
            (12u8, PaceCurve::P256),
            (13, PaceCurve::Brainpool256),
            (15, PaceCurve::P384),
            (16, PaceCurve::Brainpool384),
        ] {
            assert_eq!(PaceCurve::from_parameter_id(id), Some(curve));
            for (arc, cipher) in [
                (2, Cipher::Aes128),
                (3, Cipher::Aes192),
                (4, Cipher::Aes256),
            ] {
                let info = PaceInfo {
                    oid: ObjectIdentifier::new_unwrap(&format!("0.4.0.127.0.7.2.2.4.2.{arc}")),
                    parameter_id: id,
                };
                let n = curve.field_len();
                let t_map = vec![0x11; n];
                let t_eph = vec![0x22; n];
                let c_map = vec![0x33; n];
                let c_eph = vec![0x44; n];
                let pwd = seed();
                let mut x =
                    PaceExchange::new(&info, pwd.as_bytes(), PaceRandom::new(&t_map, &t_eph))
                        .unwrap();
                x.on_set_at(&Response {
                    data: vec![],
                    sw: 0x9000,
                })
                .unwrap();

                // Chip side.
                let kp = k_pi(cipher, pwd.as_bytes());
                let s = vec![0x5A; 16];
                let mut z = s.clone();
                let prim = Prim::new(cipher, &kp).unwrap();
                cbc_encrypt(&prim, &[0u8; 16], &mut z);
                let ok = |inner: Vec<u8>| {
                    let mut d = tlv::encode(0x7C, &inner);
                    d.extend_from_slice(&[0x90, 0x00]);
                    Response::parse(&d).unwrap()
                };
                let map_cmd = x.on_nonce(&ok(tlv::encode(0x80, &z))).unwrap();
                let t_map_pk = tlv::find(&map_cmd.data, &[0x7C, 0x81]).unwrap().to_vec();
                let c_map_pk = curve.public_key(&c_map, None).unwrap();
                let g_hat = curve.map_generator(&c_map, &t_map_pk, &s).unwrap();
                let key_cmd = x.on_map(&ok(tlv::encode(0x82, &c_map_pk))).unwrap();
                let t_eph_pk = tlv::find(&key_cmd.data, &[0x7C, 0x83]).unwrap().to_vec();
                let c_eph_pk = curve.public_key(&c_eph, Some(&g_hat)).unwrap();
                let k = curve.agree(&c_eph, &t_eph_pk).unwrap();
                let ks_mac = kdf(cipher, &k, 2);
                let tok_cmd = x.on_key(&ok(tlv::encode(0x84, &c_eph_pk))).unwrap();
                let t_ifd = tlv::find(&tok_cmd.data, &[0x7C, 0x85]).unwrap();
                let want = mac8(cipher, &ks_mac, &token_input(&info.oid, &c_eph_pk)).unwrap();
                assert_eq!(t_ifd, want, "terminal token on {curve:?} {cipher:?}");
                let t_ic = mac8(cipher, &ks_mac, &token_input(&info.oid, &t_eph_pk)).unwrap();
                let ch = x.on_token(&ok(tlv::encode(0x86, &t_ic))).unwrap();
                assert_eq!(ch.cipher(), cipher);
                assert_eq!(ch.ks_enc(), &kdf(cipher, &k, 1)[..]);
            }
        }
    }
}
