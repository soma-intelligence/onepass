//! SSH keys: generation, import (OpenSSH, PEM PKCS#8 / PKCS#1 / SEC1),
//! OpenSSH export, signing and verification.
//!
//! All the cryptography goes through aws-lc-rs. Signature blobs follow
//! RFC 4253 6.6, RFC 5656 3.1.2, RFC 8332 3 and RFC 8709 6.

use std::fmt;
use std::str::FromStr;

use aws_lc_rs::encoding::{AsBigEndian, AsDer};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::rsa::{KeyPair as RsaKeyPair, KeyPairComponents, KeySize, PublicKeyComponents};
use aws_lc_rs::signature::{
    self, EcdsaKeyPair, EcdsaSigningAlgorithm, EcdsaVerificationAlgorithm, Ed25519KeyPair,
    KeyPair as _, RsaPublicKeyComponents, UnparsedPublicKey,
};
use crypto_bigint::{BoxedUint, NonZero};
use data_encoding::BASE64_NOPAD;
use zeroize::{Zeroize, Zeroizing};

use crate::der;
use crate::openssh::{self, Container, OPENSSH_LABEL};
use crate::wire::{SSH_AGENT_RSA_SHA2_256, SSH_AGENT_RSA_SHA2_512, SshReader, SshWriter};

const ED25519: &str = "ssh-ed25519";
const SSH_RSA: &str = "ssh-rsa";
const RSA_SHA2_256: &str = "rsa-sha2-256";
const RSA_SHA2_512: &str = "rsa-sha2-512";

/// Key type accepted by [`AgentKey::generate`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    /// Ed25519 (`ssh-ed25519`).
    Ed25519,
    /// ECDSA over NIST P-256 (`ecdsa-sha2-nistp256`).
    EcdsaP256,
    /// ECDSA over NIST P-384 (`ecdsa-sha2-nistp384`).
    EcdsaP384,
    /// ECDSA over NIST P-521 (`ecdsa-sha2-nistp521`).
    EcdsaP521,
    /// RSA, 3072-bit modulus (`ssh-rsa`).
    Rsa3072,
    /// RSA, 4096-bit modulus (`ssh-rsa`).
    Rsa4096,
}

impl FromStr for KeyType {
    type Err = KeyError;

    fn from_str(s: &str) -> Result<Self, KeyError> {
        Ok(match s {
            "ed25519" => KeyType::Ed25519,
            "ecdsa-p256" => KeyType::EcdsaP256,
            "ecdsa-p384" => KeyType::EcdsaP384,
            "ecdsa-p521" => KeyType::EcdsaP521,
            "rsa-3072" => KeyType::Rsa3072,
            "rsa-4096" => KeyType::Rsa4096,
            _ => return Err(KeyError::Unsupported("key type")),
        })
    }
}

/// Key error. `Display` never includes key material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyError {
    /// A valid but unsupported key, format or algorithm.
    Unsupported(&'static str),
    /// Malformed or inconsistent key data.
    BadKey,
    /// Wrong passphrase for an encrypted key.
    BadPassphrase,
    /// The key is encrypted and no passphrase was given.
    NeedPassphrase,
    /// A cryptographic operation failed, or a signature did not verify.
    Crypto,
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyError::Unsupported(what) => write!(f, "unsupported: {what}"),
            KeyError::BadKey => f.write_str("malformed or inconsistent SSH key"),
            KeyError::BadPassphrase => f.write_str("wrong passphrase"),
            KeyError::NeedPassphrase => f.write_str("the key is encrypted: a passphrase is needed"),
            KeyError::Crypto => f.write_str("cryptographic operation failed"),
        }
    }
}

impl std::error::Error for KeyError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Curve {
    P256,
    P384,
    P521,
}

impl Curve {
    const ALL: [Curve; 3] = [Curve::P256, Curve::P384, Curve::P521];

    fn identifier(self) -> &'static str {
        match self {
            Curve::P256 => "nistp256",
            Curve::P384 => "nistp384",
            Curve::P521 => "nistp521",
        }
    }

    fn algorithm_name(self) -> &'static str {
        match self {
            Curve::P256 => "ecdsa-sha2-nistp256",
            Curve::P384 => "ecdsa-sha2-nistp384",
            Curve::P521 => "ecdsa-sha2-nistp521",
        }
    }

    fn from_algorithm_name(name: &str) -> Option<Self> {
        Curve::ALL.into_iter().find(|c| c.algorithm_name() == name)
    }

    /// Field element length in bytes.
    fn field_len(self) -> usize {
        match self {
            Curve::P256 => 32,
            Curve::P384 => 48,
            Curve::P521 => 66,
        }
    }

    fn signing(self) -> &'static EcdsaSigningAlgorithm {
        match self {
            Curve::P256 => &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            Curve::P384 => &signature::ECDSA_P384_SHA384_FIXED_SIGNING,
            Curve::P521 => &signature::ECDSA_P521_SHA512_FIXED_SIGNING,
        }
    }

    fn verifying(self) -> &'static EcdsaVerificationAlgorithm {
        match self {
            Curve::P256 => &signature::ECDSA_P256_SHA256_FIXED,
            Curve::P384 => &signature::ECDSA_P384_SHA384_FIXED,
            Curve::P521 => &signature::ECDSA_P521_SHA512_FIXED,
        }
    }
}

enum Inner {
    Ed25519 {
        pair: Ed25519KeyPair,
        seed: Zeroizing<[u8; 32]>,
        public: [u8; 32],
    },
    Ecdsa {
        curve: Curve,
        pair: EcdsaKeyPair,
        /// Private scalar, big-endian, padded to the field length.
        scalar: Zeroizing<Vec<u8>>,
        /// Uncompressed SEC1 public point.
        point: Vec<u8>,
    },
    Rsa {
        pair: RsaKeyPair,
        n: Vec<u8>,
        e: Vec<u8>,
        d: Zeroizing<Vec<u8>>,
        p: Zeroizing<Vec<u8>>,
        q: Zeroizing<Vec<u8>>,
        iqmp: Zeroizing<Vec<u8>>,
    },
}

/// A private SSH key. Private material lives in zeroizing buffers (and in
/// aws-lc key objects, which clear it when freed), so it is wiped on drop.
/// `Debug` shows only the algorithm and the fingerprint.
pub struct AgentKey {
    inner: Inner,
}

impl fmt::Debug for AgentKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AgentKey")
            .field("algorithm", &self.algorithm_name())
            .field("fingerprint", &self.fingerprint())
            .finish()
    }
}

fn rejected<T>(_: T) -> KeyError {
    KeyError::BadKey
}

fn crypto<T>(_: T) -> KeyError {
    KeyError::Crypto
}

const RSA_KEY_SIZE: KeyError = KeyError::Unsupported("RSA key size");
/// RSA moduli accepted at import (aws-lc-rs supports 2048 to 8192 bits).
const RSA_MIN_BITS: usize = 2048;
const RSA_MAX_BITS: usize = 8192;

/// Maps an aws-lc-rs RSA rejection: a modulus outside 2048..=8192 bits is
/// unsupported rather than malformed.
fn rsa_rejected(e: aws_lc_rs::error::KeyRejected) -> KeyError {
    match e.description_() {
        "TooSmall" | "TooLarge" => RSA_KEY_SIZE,
        _ => KeyError::BadKey,
    }
}

/// Bit length of a big-endian magnitude without leading zero bytes.
fn bit_len(magnitude: &[u8]) -> usize {
    match magnitude.first() {
        None => 0,
        Some(&b) => magnitude.len() * 8 - b.leading_zeros() as usize,
    }
}

impl AgentKey {
    /// Generates a new key with aws-lc-rs.
    pub fn generate(t: KeyType) -> Result<AgentKey, KeyError> {
        match t {
            KeyType::Ed25519 => {
                let pair = Ed25519KeyPair::generate().map_err(crypto)?;
                Self::from_ed25519_pair(pair)
            }
            KeyType::EcdsaP256 | KeyType::EcdsaP384 | KeyType::EcdsaP521 => {
                let curve = match t {
                    KeyType::EcdsaP256 => Curve::P256,
                    KeyType::EcdsaP384 => Curve::P384,
                    _ => Curve::P521,
                };
                let pair = EcdsaKeyPair::generate(curve.signing()).map_err(crypto)?;
                Self::from_ecdsa_pair(curve, pair)
            }
            KeyType::Rsa3072 | KeyType::Rsa4096 => {
                let size = if t == KeyType::Rsa3072 {
                    KeySize::Rsa3072
                } else {
                    KeySize::Rsa4096
                };
                let pair = RsaKeyPair::generate(size).map_err(crypto)?;
                Self::from_rsa_pair(pair)
            }
        }
    }

    /// Reads a private key: OpenSSH (`OPENSSH PRIVATE KEY`, encrypted or
    /// not), or unencrypted PEM `PRIVATE KEY` (PKCS#8), `RSA PRIVATE KEY`
    /// (PKCS#1) and `EC PRIVATE KEY` (SEC1).
    pub fn from_private_text(text: &str, passphrase: Option<&str>) -> Result<AgentKey, KeyError> {
        let pem = openssh::pem_find(text, |l| {
            matches!(
                l,
                OPENSSH_LABEL
                    | "PRIVATE KEY"
                    | "RSA PRIVATE KEY"
                    | "EC PRIVATE KEY"
                    | "ENCRYPTED PRIVATE KEY"
            )
        })?
        .ok_or(KeyError::Unsupported("no private key block found"))?;
        if pem.encrypted_headers || pem.label == "ENCRYPTED PRIVATE KEY" {
            return Err(KeyError::Unsupported("encrypted PEM key"));
        }
        match pem.label.as_str() {
            OPENSSH_LABEL => Self::from_openssh_bin(&pem.der, passphrase),
            "PRIVATE KEY" => Self::from_pkcs8(&pem.der),
            "RSA PRIVATE KEY" => {
                Self::from_rsa_pair(RsaKeyPair::from_der(&pem.der).map_err(rsa_rejected)?)
            }
            _ => Self::from_sec1(&pem.der),
        }
    }

    fn from_openssh_bin(bin: &[u8], passphrase: Option<&str>) -> Result<AgentKey, KeyError> {
        let container = Container::parse(bin)?;
        let section = container.private_section(passphrase)?;
        // Mismatched check integers mean a wrong passphrase only when the
        // section was encrypted; otherwise the file is corrupt.
        let mut r = openssh::open_private_section(&section).map_err(|e| {
            if e == KeyError::BadPassphrase && !container.is_encrypted() {
                KeyError::BadKey
            } else {
                e
            }
        })?;
        let key = Self::read_openssh_fields(&mut r)?;
        openssh::close_private_section(r)?;
        if key.public_blob() != container.public {
            return Err(KeyError::BadKey);
        }
        Ok(key)
    }

    fn read_openssh_fields(r: &mut SshReader<'_>) -> Result<AgentKey, KeyError> {
        let name = r.utf8().map_err(rejected)?;
        match name {
            ED25519 => {
                let public = r.string().map_err(rejected)?;
                let private = r.string().map_err(rejected)?;
                if public.len() != 32 || private.len() != 64 || &private[32..] != public {
                    return Err(KeyError::BadKey);
                }
                let pair = Ed25519KeyPair::from_seed_and_public_key(&private[..32], public)
                    .map_err(rejected)?;
                Self::from_ed25519_pair(pair)
            }
            SSH_RSA => {
                let n = r.mpint().map_err(rejected)?;
                let e = r.mpint().map_err(rejected)?;
                let d = r.mpint().map_err(rejected)?;
                let iqmp = r.mpint().map_err(rejected)?;
                let p = r.mpint().map_err(rejected)?;
                let q = r.mpint().map_err(rejected)?;
                // Bound the sizes before any arithmetic on them.
                let bits = bit_len(n);
                if !(RSA_MIN_BITS..=RSA_MAX_BITS).contains(&bits)
                    || d.len() > RSA_MAX_BITS / 8
                    || p.len() > RSA_MAX_BITS / 16
                    || q.len() > RSA_MAX_BITS / 16
                {
                    return Err(RSA_KEY_SIZE);
                }
                let dp = crt_exponent(d, p)?;
                let dq = crt_exponent(d, q)?;
                let components = KeyPairComponents {
                    public_key: PublicKeyComponents { n, e },
                    d,
                    p,
                    q,
                    dP: dp.as_slice(),
                    dQ: dq.as_slice(),
                    qInv: iqmp,
                };
                let pair = RsaKeyPair::from_components(&components).map_err(rsa_rejected)?;
                Self::from_rsa_pair(pair)
            }
            _ => {
                let curve = Curve::from_algorithm_name(name)
                    .ok_or(KeyError::Unsupported("OpenSSH key algorithm"))?;
                let ident = r.string().map_err(rejected)?;
                let point = r.string().map_err(rejected)?;
                let scalar = r.mpint().map_err(rejected)?;
                if ident != curve.identifier().as_bytes() || scalar.len() > curve.field_len() {
                    return Err(KeyError::BadKey);
                }
                let mut padded = Zeroizing::new(vec![0u8; curve.field_len()]);
                padded[curve.field_len() - scalar.len()..].copy_from_slice(scalar);
                let pair =
                    EcdsaKeyPair::from_private_key_and_public_key(curve.signing(), &padded, point)
                        .map_err(rejected)?;
                Self::from_ecdsa_pair(curve, pair)
            }
        }
    }

    fn from_pkcs8(der: &[u8]) -> Result<AgentKey, KeyError> {
        if let Ok(pair) = Ed25519KeyPair::from_pkcs8_maybe_unchecked(der) {
            return Self::from_ed25519_pair(pair);
        }
        for curve in Curve::ALL {
            if let Ok(pair) = EcdsaKeyPair::from_pkcs8(curve.signing(), der) {
                return Self::from_ecdsa_pair(curve, pair);
            }
        }
        Self::from_rsa_pair(RsaKeyPair::from_pkcs8(der).map_err(rsa_rejected)?)
    }

    fn from_sec1(der: &[u8]) -> Result<AgentKey, KeyError> {
        for curve in Curve::ALL {
            if let Ok(pair) = EcdsaKeyPair::from_private_key_der(curve.signing(), der) {
                return Self::from_ecdsa_pair(curve, pair);
            }
        }
        Err(KeyError::BadKey)
    }

    fn from_ed25519_pair(pair: Ed25519KeyPair) -> Result<AgentKey, KeyError> {
        let seed_bin = pair.seed().map_err(crypto)?.as_be_bytes().map_err(crypto)?;
        let seed: [u8; 32] = seed_bin.as_ref().try_into().map_err(rejected)?;
        let seed = Zeroizing::new(seed);
        let public: [u8; 32] = pair.public_key().as_ref().try_into().map_err(rejected)?;
        Ok(AgentKey {
            inner: Inner::Ed25519 { pair, seed, public },
        })
    }

    fn from_ecdsa_pair(curve: Curve, pair: EcdsaKeyPair) -> Result<AgentKey, KeyError> {
        let bin = pair.private_key().as_be_bytes().map_err(crypto)?;
        let scalar = Zeroizing::new(bin.as_ref().to_vec());
        if scalar.len() != curve.field_len() {
            return Err(KeyError::BadKey);
        }
        let point = pair.public_key().as_ref().to_vec();
        Ok(AgentKey {
            inner: Inner::Ecdsa {
                curve,
                pair,
                scalar,
                point,
            },
        })
    }

    fn from_rsa_pair(pair: RsaKeyPair) -> Result<AgentKey, KeyError> {
        if !(RSA_MIN_BITS..=RSA_MAX_BITS).contains(&(pair.public_modulus_len() * 8)) {
            return Err(RSA_KEY_SIZE);
        }
        let pkcs8 = pair.as_der().map_err(crypto)?;
        let pkcs1 = der::pkcs8_private_key(pkcs8.as_ref()).map_err(rejected)?;
        let parts = der::rsa_private_key(pkcs1).map_err(rejected)?;
        Ok(AgentKey {
            inner: Inner::Rsa {
                pair,
                n: parts.n,
                e: parts.e,
                d: parts.d,
                p: parts.p,
                q: parts.q,
                iqmp: parts.iqmp,
            },
        })
    }

    /// SSH algorithm name of the key: `ssh-ed25519`, `ecdsa-sha2-nistp256`,
    /// `ecdsa-sha2-nistp384`, `ecdsa-sha2-nistp521` or `ssh-rsa`.
    pub fn algorithm_name(&self) -> &'static str {
        match &self.inner {
            Inner::Ed25519 { .. } => ED25519,
            Inner::Ecdsa { curve, .. } => curve.algorithm_name(),
            Inner::Rsa { .. } => SSH_RSA,
        }
    }

    /// Public key blob (RFC 4253 6.6, RFC 5656 3.1, RFC 8709 4).
    pub fn public_blob(&self) -> Vec<u8> {
        let mut w = SshWriter::new();
        w.string(self.algorithm_name().as_bytes());
        match &self.inner {
            Inner::Ed25519 { public, .. } => {
                w.string(public);
            }
            Inner::Ecdsa { curve, point, .. } => {
                w.string(curve.identifier().as_bytes()).string(point);
            }
            Inner::Rsa { n, e, .. } => {
                w.mpint(e).mpint(n);
            }
        }
        w.into_vec()
    }

    /// One `authorized_keys` line: algorithm, base64 blob and comment (if
    /// any), without a trailing newline.
    pub fn public_openssh(&self, comment: &str) -> String {
        let mut line = format!(
            "{} {}",
            self.algorithm_name(),
            data_encoding::BASE64.encode(&self.public_blob())
        );
        if !comment.is_empty() {
            line.push(' ');
            line.push_str(comment);
        }
        line
    }

    /// `SHA256:` fingerprint, as printed by `ssh-keygen -l`.
    pub fn fingerprint(&self) -> String {
        fingerprint_of_blob(&self.public_blob())
    }

    /// The key as an unencrypted OpenSSH private key file.
    ///
    /// # Errors
    /// [`KeyError::Crypto`] if the system random generator (used for the
    /// check integers of the private section) fails.
    pub fn to_openssh_private(&self, comment: &str) -> Result<Zeroizing<String>, KeyError> {
        let mut w = SshWriter::with_capacity(self.private_fields_len());
        let initial = w.capacity();
        w.string(self.algorithm_name().as_bytes());
        match &self.inner {
            Inner::Ed25519 { seed, public, .. } => {
                let mut private = Zeroizing::new([0u8; 64]);
                private[..32].copy_from_slice(&seed[..]);
                private[32..].copy_from_slice(public);
                w.string(public).string(&private[..]);
            }
            Inner::Ecdsa {
                curve,
                scalar,
                point,
                ..
            } => {
                w.string(curve.identifier().as_bytes())
                    .string(point)
                    .mpint(scalar);
            }
            Inner::Rsa {
                n,
                e,
                d,
                p,
                q,
                iqmp,
                ..
            } => {
                w.mpint(n).mpint(e).mpint(d).mpint(iqmp).mpint(p).mpint(q);
            }
        }
        debug_assert_eq!(w.capacity(), initial, "private fields reallocated");
        let fields = Zeroizing::new(w.into_vec());
        openssh::encode_unencrypted(&self.public_blob(), &fields, comment)
    }

    /// Upper bound of the OpenSSH private key fields length, so the writer
    /// holding them never reallocates. Each field costs its length plus 4
    /// (string length) plus 1 (possible mpint sign byte).
    fn private_fields_len(&self) -> usize {
        let field = |len: usize| len + 5;
        field(self.algorithm_name().len())
            + match &self.inner {
                Inner::Ed25519 { .. } => field(32) + field(64),
                Inner::Ecdsa {
                    curve,
                    scalar,
                    point,
                    ..
                } => field(curve.identifier().len()) + field(point.len()) + field(scalar.len()),
                Inner::Rsa {
                    n,
                    e,
                    d,
                    p,
                    q,
                    iqmp,
                    ..
                } => [n.len(), e.len(), d.len(), iqmp.len(), p.len(), q.len()]
                    .into_iter()
                    .map(field)
                    .sum(),
            }
    }

    /// Signs `data` and returns the complete SSH signature blob. For RSA,
    /// `flags` must ask for SHA-2 (`SSH_AGENT_RSA_SHA2_256` or `_512`);
    /// other key types ignore it.
    pub fn sign(&self, data: &[u8], flags: u32) -> Result<Vec<u8>, KeyError> {
        let mut w = SshWriter::new();
        match &self.inner {
            Inner::Ed25519 { pair, .. } => {
                let sig = pair.try_sign(data).map_err(crypto)?;
                w.string(ED25519.as_bytes()).string(sig.as_ref());
            }
            Inner::Ecdsa { curve, pair, .. } => {
                let sig = pair.sign(&SystemRandom::new(), data).map_err(crypto)?;
                let (r, s) = sig.as_ref().split_at(curve.field_len());
                let mut inner = SshWriter::new();
                inner.mpint(r).mpint(s);
                w.string(curve.algorithm_name().as_bytes())
                    .string(inner.as_slice());
            }
            Inner::Rsa { pair, .. } => {
                let (name, alg): (&str, &'static dyn signature::RsaEncoding) =
                    if flags & SSH_AGENT_RSA_SHA2_256 != 0 {
                        (RSA_SHA2_256, &signature::RSA_PKCS1_SHA256)
                    } else if flags & SSH_AGENT_RSA_SHA2_512 != 0 {
                        (RSA_SHA2_512, &signature::RSA_PKCS1_SHA512)
                    } else {
                        return Err(KeyError::Unsupported("ssh-rsa with SHA-1"));
                    };
                let mut sig = vec![0u8; pair.public_modulus_len()];
                pair.sign(alg, &SystemRandom::new(), data, &mut sig)
                    .map_err(crypto)?;
                w.string(name.as_bytes()).string(&sig);
            }
        }
        Ok(w.into_vec())
    }
}

/// `d mod (m - 1)` for the RSA CRT exponents.
fn crt_exponent(d: &[u8], m: &[u8]) -> Result<Zeroizing<Vec<u8>>, KeyError> {
    if m.is_empty() || d.is_empty() {
        return Err(KeyError::BadKey);
    }
    let mut d = BoxedUint::from_be_slice_vartime(d);
    let mut m = BoxedUint::from_be_slice_vartime(m);
    let m1 = m.wrapping_sub(BoxedUint::one());
    m.zeroize();
    // `None` only when m - 1 is zero, so nothing secret is dropped there.
    let mut modulus = NonZero::new(m1).into_option().ok_or(KeyError::BadKey)?;
    let (mut quotient, mut rem) = d.div_rem(&modulus);
    quotient.zeroize();
    d.zeroize();
    modulus.zeroize();
    let out = Zeroizing::new(rem.to_be_bytes().into_vec());
    rem.zeroize();
    Ok(out)
}

/// Whether a private key text is encrypted (OpenSSH with a cipher, or
/// encrypted PEM). Unreadable text counts as not encrypted.
pub fn is_encrypted(text: &str) -> bool {
    let Ok(Some(pem)) = openssh::pem_find(text, |l| {
        matches!(
            l,
            OPENSSH_LABEL
                | "PRIVATE KEY"
                | "RSA PRIVATE KEY"
                | "EC PRIVATE KEY"
                | "ENCRYPTED PRIVATE KEY"
        )
    }) else {
        return false;
    };
    if pem.label == OPENSSH_LABEL {
        Container::parse(&pem.der).is_ok_and(|c| c.is_encrypted())
    } else {
        pem.encrypted_headers || pem.label == "ENCRYPTED PRIVATE KEY"
    }
}

/// `SHA256:` followed by the unpadded base64 SHA-256 of a public key blob.
pub fn fingerprint_of_blob(blob: &[u8]) -> String {
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, blob);
    format!("SHA256:{}", BASE64_NOPAD.encode(digest.as_ref()))
}

/// Verifies an SSH signature blob over `data` with a public key blob.
/// Accepts Ed25519, ECDSA P-256/384/521, `rsa-sha2-256` and `rsa-sha2-512`.
pub fn verify_signature(public_blob: &[u8], data: &[u8], sig_blob: &[u8]) -> Result<(), KeyError> {
    let mut key = SshReader::new(public_blob);
    let key_alg = key.utf8().map_err(rejected)?;
    let mut sig = SshReader::new(sig_blob);
    let sig_alg = sig.utf8().map_err(rejected)?;
    let sig_bytes = sig.string().map_err(rejected)?;
    sig.finish().map_err(rejected)?;

    match key_alg {
        ED25519 => {
            let public = key.string().map_err(rejected)?;
            key.finish().map_err(rejected)?;
            if sig_alg != ED25519 || public.len() != 32 {
                return Err(KeyError::BadKey);
            }
            UnparsedPublicKey::new(&signature::ED25519, public)
                .verify(data, sig_bytes)
                .map_err(crypto)
        }
        SSH_RSA => {
            let e = key.mpint().map_err(rejected)?;
            let n = key.mpint().map_err(rejected)?;
            key.finish().map_err(rejected)?;
            let alg: &signature::RsaParameters = match sig_alg {
                RSA_SHA2_256 => &signature::RSA_PKCS1_2048_8192_SHA256,
                RSA_SHA2_512 => &signature::RSA_PKCS1_2048_8192_SHA512,
                SSH_RSA => return Err(KeyError::Unsupported("ssh-rsa with SHA-1")),
                _ => return Err(KeyError::BadKey),
            };
            // OpenSSH accepts signatures shorter than the modulus (leading
            // zero bytes dropped) and pads them; longer ones are malformed.
            let modulus_len = n.len();
            if sig_bytes.len() > modulus_len {
                return Err(KeyError::BadKey);
            }
            let mut padded = vec![0u8; modulus_len];
            padded[modulus_len - sig_bytes.len()..].copy_from_slice(sig_bytes);
            RsaPublicKeyComponents { n, e }
                .verify(alg, data, &padded)
                .map_err(crypto)
        }
        _ => {
            let curve = Curve::from_algorithm_name(key_alg)
                .ok_or(KeyError::Unsupported("SSH key algorithm"))?;
            let ident = key.string().map_err(rejected)?;
            let point = key.string().map_err(rejected)?;
            key.finish().map_err(rejected)?;
            if ident != curve.identifier().as_bytes() || sig_alg != key_alg {
                return Err(KeyError::BadKey);
            }
            let mut rs = SshReader::new(sig_bytes);
            let r = rs.mpint().map_err(rejected)?;
            let s = rs.mpint().map_err(rejected)?;
            rs.finish().map_err(rejected)?;
            let n = curve.field_len();
            if r.len() > n || s.len() > n {
                return Err(KeyError::BadKey);
            }
            let mut fixed = vec![0u8; 2 * n];
            fixed[n - r.len()..n].copy_from_slice(r);
            fixed[2 * n - s.len()..].copy_from_slice(s);
            UnparsedPublicKey::new(curve.verifying(), point)
                .verify(data, &fixed)
                .map_err(crypto)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [KeyType; 6] = [
        KeyType::Ed25519,
        KeyType::EcdsaP256,
        KeyType::EcdsaP384,
        KeyType::EcdsaP521,
        KeyType::Rsa3072,
        KeyType::Rsa4096,
    ];

    /// RSA generation is slow in debug builds: generate each type once.
    fn keys() -> &'static [(KeyType, AgentKey)] {
        static KEYS: std::sync::OnceLock<Vec<(KeyType, AgentKey)>> = std::sync::OnceLock::new();
        KEYS.get_or_init(|| {
            ALL.iter()
                .map(|&t| (t, AgentKey::generate(t).unwrap()))
                .collect()
        })
    }

    fn sig_name(sig: &[u8]) -> String {
        SshReader::new(sig).utf8().unwrap().to_owned()
    }

    #[test]
    fn key_type_from_str() {
        let names = [
            "ed25519",
            "ecdsa-p256",
            "ecdsa-p384",
            "ecdsa-p521",
            "rsa-3072",
            "rsa-4096",
        ];
        for (name, t) in names.iter().zip(ALL) {
            assert_eq!(name.parse::<KeyType>().unwrap(), t);
        }
        assert!("rsa-2048".parse::<KeyType>().is_err());
        assert!("dsa".parse::<KeyType>().is_err());
    }

    #[test]
    fn generated_key_signs_and_verifies() {
        for (t, key) in keys() {
            let sig = key.sign(b"payload", SSH_AGENT_RSA_SHA2_512).unwrap();
            verify_signature(&key.public_blob(), b"payload", &sig)
                .unwrap_or_else(|e| panic!("{t:?}: {e}"));
            assert_eq!(
                verify_signature(&key.public_blob(), b"other", &sig),
                Err(KeyError::Crypto),
                "{t:?}"
            );
        }
    }

    #[test]
    fn algorithm_names() {
        let expected = [
            "ssh-ed25519",
            "ecdsa-sha2-nistp256",
            "ecdsa-sha2-nistp384",
            "ecdsa-sha2-nistp521",
            "ssh-rsa",
            "ssh-rsa",
        ];
        for ((_, key), name) in keys().iter().zip(expected) {
            assert_eq!(key.algorithm_name(), name);
            assert!(key.public_openssh("c").starts_with(&format!("{name} ")));
            assert!(key.public_openssh("c").ends_with(" c"));
        }
    }

    #[test]
    fn openssh_roundtrip_each_type() {
        for (t, key) in keys() {
            let text = key.to_openssh_private("comment").unwrap();
            assert!(text.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----\n"));
            assert!(!is_encrypted(&text));
            let back = AgentKey::from_private_text(&text, None).unwrap();
            assert_eq!(back.public_blob(), key.public_blob(), "{t:?}");
            let sig = back.sign(b"x", SSH_AGENT_RSA_SHA2_256).unwrap();
            verify_signature(&key.public_blob(), b"x", &sig).unwrap();
        }
    }

    #[test]
    fn rsa_sha1_refused() {
        let (_, key) = keys().iter().find(|(t, _)| *t == KeyType::Rsa3072).unwrap();
        assert_eq!(
            key.sign(b"x", 0),
            Err(KeyError::Unsupported("ssh-rsa with SHA-1"))
        );
        // A forged "ssh-rsa" signature blob is refused at verification too.
        let mut w = SshWriter::new();
        w.string(b"ssh-rsa").string(&[0u8; 384]);
        assert_eq!(
            verify_signature(&key.public_blob(), b"x", w.as_slice()),
            Err(KeyError::Unsupported("ssh-rsa with SHA-1"))
        );
    }

    #[test]
    fn rsa_flags_pick_hash() {
        let (_, key) = keys().iter().find(|(t, _)| *t == KeyType::Rsa3072).unwrap();
        let s256 = key.sign(b"x", SSH_AGENT_RSA_SHA2_256).unwrap();
        let s512 = key.sign(b"x", SSH_AGENT_RSA_SHA2_512).unwrap();
        assert_eq!(sig_name(&s256), "rsa-sha2-256");
        assert_eq!(sig_name(&s512), "rsa-sha2-512");
        // A signature labeled with the other hash does not verify.
        let mut forged = SshWriter::new();
        let mut r = SshReader::new(&s256);
        r.string().unwrap();
        forged.string(b"rsa-sha2-512").string(r.string().unwrap());
        assert_eq!(
            verify_signature(&key.public_blob(), b"x", forged.as_slice()),
            Err(KeyError::Crypto)
        );
    }

    #[test]
    fn ecdsa_and_ed25519_ignore_flags() {
        for (t, key) in keys()
            .iter()
            .filter(|(t, _)| !matches!(t, KeyType::Rsa3072 | KeyType::Rsa4096))
        {
            let sig = key.sign(b"x", 0).unwrap();
            assert_eq!(sig_name(&sig), key.algorithm_name(), "{t:?}");
        }
    }

    #[test]
    fn fingerprint_format() {
        for (_, key) in keys() {
            let fp = key.fingerprint();
            let b64 = fp.strip_prefix("SHA256:").unwrap();
            assert_eq!(b64.len(), 43);
            assert!(!b64.contains('='));
            assert_eq!(fp, fingerprint_of_blob(&key.public_blob()));
        }
    }

    #[test]
    fn debug_shows_no_private_material() {
        let (_, key) = &keys()[0];
        let dbg = format!("{key:?}");
        assert!(dbg.contains("ssh-ed25519"));
        assert!(dbg.contains(&key.fingerprint()));
        let Inner::Ed25519 { seed, .. } = &key.inner else {
            unreachable!()
        };
        assert!(!dbg.contains(&data_encoding::HEXLOWER.encode(&seed[..])));
        assert!(!dbg.contains("seed"));
    }

    #[test]
    fn mismatched_public_key_is_rejected() {
        let a = &keys()[0].1;
        let b = AgentKey::generate(KeyType::Ed25519).unwrap();
        // Swap the outer public blob of a's file for b's.
        let text = a.to_openssh_private("").unwrap();
        let pem = openssh::pem_find(&text, |_| true).unwrap().unwrap();
        let mut bin = pem.der.to_vec();
        let (pa, pb) = (a.public_blob(), b.public_blob());
        let at = bin
            .windows(pa.len())
            .position(|w| w == pa.as_slice())
            .unwrap();
        bin[at..at + pb.len()].copy_from_slice(&pb);
        let forged = openssh::pem_encode(OPENSSH_LABEL, &bin, 70);
        assert_eq!(
            AgentKey::from_private_text(&forged, None).err(),
            Some(KeyError::BadKey)
        );
    }

    #[test]
    fn verify_rejects_mismatched_algorithms() {
        let ed = &keys()[0].1;
        let p256 = &keys()[1].1;
        let sig = ed.sign(b"x", 0).unwrap();
        assert_eq!(
            verify_signature(&p256.public_blob(), b"x", &sig),
            Err(KeyError::BadKey)
        );
        let sig = p256.sign(b"x", 0).unwrap();
        assert_eq!(
            verify_signature(&ed.public_blob(), b"x", &sig),
            Err(KeyError::BadKey)
        );
        let mut trailing = sig.clone();
        trailing.push(0);
        assert_eq!(
            verify_signature(&p256.public_blob(), b"x", &trailing),
            Err(KeyError::BadKey)
        );
    }

    #[test]
    fn unsupported_texts() {
        assert_eq!(
            AgentKey::from_private_text("hello", None).err(),
            Some(KeyError::Unsupported("no private key block found"))
        );
        let enc =
            "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n";
        assert!(is_encrypted(enc));
        assert_eq!(
            AgentKey::from_private_text(enc, None).err(),
            Some(KeyError::Unsupported("encrypted PEM key"))
        );
        assert!(!is_encrypted("hello"));
    }

    #[test]
    fn pkcs8_import_of_generated_keys() {
        let ed = Ed25519KeyPair::generate().unwrap();
        let der = ed.to_pkcs8().unwrap();
        let text = openssh::pem_encode("PRIVATE KEY", der.as_ref(), 64);
        let key = AgentKey::from_private_text(&text, None).unwrap();
        assert_eq!(key.algorithm_name(), "ssh-ed25519");

        let ec = EcdsaKeyPair::generate(&signature::ECDSA_P384_SHA384_FIXED_SIGNING).unwrap();
        let der = ec.to_pkcs8v1().unwrap();
        let text = openssh::pem_encode("PRIVATE KEY", der.as_ref(), 64);
        let key = AgentKey::from_private_text(&text, None).unwrap();
        assert_eq!(key.algorithm_name(), "ecdsa-sha2-nistp384");

        let sec1 = ec.private_key().as_der().unwrap();
        let text = openssh::pem_encode("EC PRIVATE KEY", sec1.as_ref(), 64);
        let key = AgentKey::from_private_text(&text, None).unwrap();
        assert_eq!(key.algorithm_name(), "ecdsa-sha2-nistp384");
    }

    #[test]
    fn crt_exponent_small_values() {
        // 1000 mod (7 - 1) = 4; 1000 mod (13 - 1) = 4; 77 mod (11 - 1) = 7.
        assert_eq!(strip(&crt_exponent(&[0x03, 0xe8], &[7]).unwrap()), vec![4]);
        assert_eq!(strip(&crt_exponent(&[0x03, 0xe8], &[13]).unwrap()), vec![4]);
        assert_eq!(strip(&crt_exponent(&[77], &[11]).unwrap()), vec![7]);
        assert_eq!(crt_exponent(&[5], &[1]), Err(KeyError::BadKey));
        assert_eq!(crt_exponent(&[5], &[]), Err(KeyError::BadKey));
    }

    /// Test-only RSA 1024 key made with ssh-keygen, in three formats.
    const RSA1024_OPENSSH: &str = include_str!("../tests/data/rsa1024_openssh");
    const RSA1024_PKCS1: &str = include_str!("../tests/data/rsa1024_pkcs1.pem");
    const RSA1024_PKCS8: &str = include_str!("../tests/data/rsa1024_pkcs8.pem");

    #[test]
    fn rsa_below_2048_bits_is_unsupported() {
        for text in [RSA1024_OPENSSH, RSA1024_PKCS1, RSA1024_PKCS8] {
            assert_eq!(
                AgentKey::from_private_text(text, None).err(),
                Some(KeyError::Unsupported("RSA key size"))
            );
        }
    }

    fn rsa_openssh_text(n: &[u8], d: &[u8], p: &[u8], q: &[u8]) -> String {
        let mut fields = SshWriter::new();
        fields
            .string(b"ssh-rsa")
            .mpint(n)
            .mpint(&[1, 0, 1])
            .mpint(d)
            .mpint(&[3])
            .mpint(p)
            .mpint(q);
        let text = openssh::encode_unencrypted(b"public", fields.as_slice(), "").unwrap();
        text.to_string()
    }

    #[test]
    fn oversized_rsa_components_are_unsupported() {
        let ok_n = vec![0xC5u8; 384];
        let cases = [
            (
                "n above 8192 bits",
                vec![0xC5u8; 1025],
                vec![7; 300],
                vec![9; 192],
                vec![9; 192],
            ),
            (
                "n below 2048 bits",
                vec![0x7F; 256],
                vec![7; 200],
                vec![9; 128],
                vec![9; 128],
            ),
            (
                "d too long",
                ok_n.clone(),
                vec![7; 1025],
                vec![9; 192],
                vec![9; 192],
            ),
            (
                "p too long",
                ok_n.clone(),
                vec![7; 300],
                vec![9; 513],
                vec![9; 192],
            ),
            (
                "q too long",
                ok_n.clone(),
                vec![7; 300],
                vec![9; 192],
                vec![9; 513],
            ),
        ];
        for (what, n, d, p, q) in cases {
            assert_eq!(
                AgentKey::from_private_text(&rsa_openssh_text(&n, &d, &p, &q), None).err(),
                Some(KeyError::Unsupported("RSA key size")),
                "{what}"
            );
        }
        // In range but inconsistent: malformed, not unsupported.
        assert_eq!(
            AgentKey::from_private_text(
                &rsa_openssh_text(&ok_n, &[7; 300], &[9; 192], &[11; 192]),
                None
            )
            .err(),
            Some(KeyError::BadKey)
        );
    }

    #[test]
    fn short_rsa_signature_is_padded() {
        let (_, key) = keys().iter().find(|(t, _)| *t == KeyType::Rsa3072).unwrap();
        let blob = key.public_blob();
        let parts = |sig: &[u8]| {
            let mut r = SshReader::new(sig);
            let name = r.string().unwrap().to_vec();
            (name, r.string().unwrap().to_vec())
        };
        let rebuild = |name: &[u8], s: &[u8]| {
            let mut w = SshWriter::new();
            w.string(name).string(s);
            w.into_vec()
        };
        // Find a signature with a leading zero byte (about 1 in 256).
        let (msg, name, raw) = (0u32..)
            .find_map(|i| {
                let msg = i.to_be_bytes();
                let (name, raw) = parts(&key.sign(&msg, SSH_AGENT_RSA_SHA2_256).unwrap());
                (raw[0] == 0).then_some((msg, name, raw))
            })
            .unwrap();
        verify_signature(&blob, &msg, &rebuild(&name, &raw)).unwrap();
        verify_signature(&blob, &msg, &rebuild(&name, &raw[1..])).unwrap();
        let mut long = vec![0u8];
        long.extend_from_slice(&raw);
        assert_eq!(
            verify_signature(&blob, &msg, &rebuild(&name, &long)),
            Err(KeyError::BadKey)
        );
    }

    #[test]
    fn crt_exponent_large_values() {
        // d = 2^64 + 5, p = 2^32 + 1: d mod 2^32 = 5.
        let d = [1u8, 0, 0, 0, 0, 0, 0, 0, 5];
        assert_eq!(strip(&crt_exponent(&d, &[1, 0, 0, 0, 1]).unwrap()), vec![5]);
    }

    fn strip(v: &[u8]) -> Vec<u8> {
        v.iter().copied().skip_while(|&b| b == 0).collect()
    }

    /// Test-only keys made with `ssh-keygen -t ed25519 -N 'pass phrase'`
    /// (`-Z aes256-ctr`, default, and `-Z aes256-gcm@openssh.com`).
    const ENCRYPTED_CTR: &str = include_str!("../tests/data/ed25519_aes256_ctr");
    const ENCRYPTED_GCM: &str = include_str!("../tests/data/ed25519_aes256_gcm");
    const ENCRYPTED_PUB: &str = include_str!("../tests/data/ed25519_encrypted.pub");

    #[test]
    fn encrypted_openssh_keys() {
        let expected = ENCRYPTED_PUB
            .split_whitespace()
            .take(2)
            .collect::<Vec<_>>()
            .join(" ");
        for text in [ENCRYPTED_CTR, ENCRYPTED_GCM] {
            assert!(is_encrypted(text));
            assert_eq!(
                AgentKey::from_private_text(text, None).err(),
                Some(KeyError::NeedPassphrase)
            );
            assert_eq!(
                AgentKey::from_private_text(text, Some("wrong")).err(),
                Some(KeyError::BadPassphrase)
            );
            let key = AgentKey::from_private_text(text, Some("pass phrase")).unwrap();
            assert_eq!(key.public_openssh(""), expected);
        }
    }
}
