//! Hybrid KEM: ML-KEM-1024 + X25519, used to wrap keys to a recipient.
//!
//! Envelope: `ct_mlkem (1568) || eph_x25519_pub (32) || blob`, where `blob`
//! seals the wrapped key under
//! `HKDF-SHA256(salt = empty, ikm = ss_mlkem || ss_x25519 || ct_mlkem ||
//! eph_x25519_pub || recipient_x25519, info = "onepass/kem/v1" || context)`.
//!
//! Labeled envelopes (`wrap_key_labeled`) use the same layout and combiner
//! with `info = label || u32_be(len(context)) || context`, and bind the
//! inner blob to that whole info string.

use std::fmt;

use aws_lc_rs::agreement::{self, PrivateKey, UnparsedPublicKey, X25519};
use aws_lc_rs::constant_time::verify_slices_are_equal;
use aws_lc_rs::digest::{self, SHA3_256, SHA256};
use aws_lc_rs::encoding::{AsBigEndian, Curve25519SeedBin};
use aws_lc_rs::kem::{Ciphertext, DecapsulationKey, EncapsulationKey, ML_KEM_1024};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::aead::{Aad, BlobKind, HEADER_LEN, LEN_PREFIX, TAG_LEN, open, padded_len, seal};
use super::key::{SymmetricKey, hkdf32};
use crate::{Error, Id, Result};

const MLKEM_PUBLIC_LEN: usize = 1568;
const MLKEM_SECRET_LEN: usize = 3168;
const MLKEM_CT_LEN: usize = 1568;
const X25519_LEN: usize = 32;
const SECRET_LEN: usize = MLKEM_SECRET_LEN + X25519_LEN;
/// FIPS 203 decapsulation key layout (k = 4):
/// `dk_pke (1536) || ek (1568) || H(ek) (32) || z (32)`.
const MLKEM_EK_START: usize = 1536;
const MLKEM_EK_END: usize = MLKEM_EK_START + MLKEM_PUBLIC_LEN;
const MLKEM_HASH_END: usize = MLKEM_EK_END + 32;
/// HKDF info prefix of the combiner (`wrap_key`). The context follows it
/// unframed. Three context families use it, each a fixed prefix followed by
/// a 16-byte id:
/// - `"vault:" || vault_id` (22 bytes, `vault::kem_context`),
/// - `"travel:" || account_id` (23 bytes, `repo::travel::kem_context`),
/// - `"onepass/archive/v1" || archive_id` (34 bytes,
///   `archive::format::envelope_context`).
///
/// This stays unambiguous only while no family's context can be a prefix
/// of (or equal to) another's: the lengths and prefixes differ, which
/// `tests::unframed_context_families_are_disjoint` checks. A new family
/// (device pairing, sharing) must use `wrap_key_labeled` under a label of
/// its own, never this unframed form.
const KEM_INFO: &[u8] = b"onepass/kem/v1";
const SCHEMA: u16 = 1;

/// Recipient secret: raw key bytes, aws-lc keys are rebuilt at use.
pub struct HybridKemSecret {
    mlkem: Zeroizing<Vec<u8>>,
    x25519: Zeroizing<[u8; 32]>,
}

/// Recipient public key. `mlkem` is 1568 bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HybridKemPublic {
    pub mlkem: Vec<u8>,
    pub x25519: [u8; 32],
}

impl HybridKemSecret {
    pub fn generate() -> Result<HybridKemSecret> {
        let dk = DecapsulationKey::generate(&ML_KEM_1024).map_err(|_| Error::Crypto)?;
        let dk_bytes = dk.key_bytes().map_err(|_| Error::Crypto)?;
        let x = PrivateKey::generate(&X25519).map_err(|_| Error::Crypto)?;
        let seed: Curve25519SeedBin<'static> = x.as_be_bytes().map_err(|_| Error::Crypto)?;
        Self::from_parts(dk_bytes.as_ref(), seed.as_ref())
    }

    /// `mlkem (3168) || x25519 (32)`.
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(SECRET_LEN));
        out.extend_from_slice(&self.mlkem);
        out.extend_from_slice(&*self.x25519);
        out
    }

    pub fn from_bytes(b: &[u8]) -> Result<HybridKemSecret> {
        if b.len() != SECRET_LEN {
            return Err(Error::InvalidFormat("kem secret length"));
        }
        Self::from_parts(&b[..MLKEM_SECRET_LEN], &b[MLKEM_SECRET_LEN..])
    }

    fn from_parts(mlkem: &[u8], x25519: &[u8]) -> Result<HybridKemSecret> {
        if mlkem.len() != MLKEM_SECRET_LEN || x25519.len() != X25519_LEN {
            return Err(Error::InvalidFormat("kem secret length"));
        }
        // FIPS 203 input check: the embedded public key matches its hash.
        let h = digest::digest(&SHA3_256, &mlkem[MLKEM_EK_START..MLKEM_EK_END]);
        verify_slices_are_equal(h.as_ref(), &mlkem[MLKEM_EK_END..MLKEM_HASH_END])
            .map_err(|_| Error::InvalidFormat("kem secret"))?;
        DecapsulationKey::new(&ML_KEM_1024, mlkem)
            .map_err(|_| Error::InvalidFormat("kem secret"))?;
        PrivateKey::from_private_key(&X25519, x25519)
            .map_err(|_| Error::InvalidFormat("kem secret"))?;
        let mut x = Zeroizing::new([0u8; 32]);
        x.copy_from_slice(x25519);
        Ok(HybridKemSecret {
            mlkem: Zeroizing::new(mlkem.to_vec()),
            x25519: x,
        })
    }

    pub fn public(&self) -> Result<HybridKemPublic> {
        Ok(HybridKemPublic {
            mlkem: self.mlkem[MLKEM_EK_START..MLKEM_EK_END].to_vec(),
            x25519: x25519_public(&self.x25519_key()?)?,
        })
    }

    fn x25519_key(&self) -> Result<PrivateKey> {
        PrivateKey::from_private_key(&X25519, &*self.x25519).map_err(|_| Error::Crypto)
    }
}

impl HybridKemPublic {
    /// `mlkem (1568) || x25519 (32)`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(MLKEM_PUBLIC_LEN + X25519_LEN);
        out.extend_from_slice(&self.mlkem);
        out.extend_from_slice(&self.x25519);
        out
    }

    /// Inverse of `to_bytes`: 1600 bytes whose ML-KEM part parses as an
    /// encapsulation key.
    pub fn from_bytes(b: &[u8]) -> Result<HybridKemPublic> {
        if b.len() != MLKEM_PUBLIC_LEN + X25519_LEN {
            return Err(Error::InvalidFormat("kem public key length"));
        }
        let (mlkem, x) = b.split_at(MLKEM_PUBLIC_LEN);
        EncapsulationKey::new(&ML_KEM_1024, mlkem)
            .map_err(|_| Error::InvalidFormat("mlkem public key"))?;
        Ok(HybridKemPublic {
            mlkem: mlkem.to_vec(),
            x25519: x
                .try_into()
                .map_err(|_| Error::InvalidFormat("kem public key length"))?,
        })
    }
}

impl fmt::Debug for HybridKemSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HybridKemSecret(**)")
    }
}

fn x25519_public(key: &PrivateKey) -> Result<[u8; 32]> {
    let pk = key.compute_public_key().map_err(|_| Error::Crypto)?;
    pk.as_ref().try_into().map_err(|_| Error::Crypto)
}

fn x25519_agree(key: &PrivateKey, peer: &[u8; 32]) -> Result<Zeroizing<Vec<u8>>> {
    agreement::agree(
        key,
        UnparsedPublicKey::new(&X25519, peer),
        Error::Crypto,
        |s| Ok(Zeroizing::new(s.to_vec())),
    )
}

/// Combiner: HKDF-SHA256 over both shared secrets and the transcript.
fn combine(
    ss_mlkem: &[u8],
    ss_x25519: &[u8],
    ct_mlkem: &[u8],
    eph_pub: &[u8; 32],
    recipient_x25519: &[u8; 32],
    info: &[&[u8]],
) -> Result<SymmetricKey> {
    let mut ikm = Zeroizing::new(Vec::with_capacity(
        ss_mlkem.len() + ss_x25519.len() + ct_mlkem.len() + 2 * X25519_LEN,
    ));
    ikm.extend_from_slice(ss_mlkem);
    ikm.extend_from_slice(ss_x25519);
    ikm.extend_from_slice(ct_mlkem);
    ikm.extend_from_slice(eph_pub);
    ikm.extend_from_slice(recipient_x25519);
    hkdf32(&[], &ikm, info)
}

/// Blob context: blob id = first 16 bytes of SHA-256(context).
fn blob_aad(context: &[u8]) -> Aad {
    let h = digest::digest(&SHA256, context);
    let mut id = [0u8; 16];
    id.copy_from_slice(&h.as_ref()[..16]);
    Aad {
        blob_id: Id(id),
        vault_id: None,
        schema: SCHEMA,
    }
}

/// Length of every envelope: it wraps a 32-byte key.
pub(crate) fn envelope_len() -> usize {
    MLKEM_CT_LEN + X25519_LEN + HEADER_LEN + padded_len(LEN_PREFIX + 32) + TAG_LEN
}

/// Wrap `key` to `recipient`, bound to `context`.
pub fn wrap_key(
    recipient: &HybridKemPublic,
    key: &SymmetricKey,
    context: &[u8],
) -> Result<Vec<u8>> {
    wrap_with_info(recipient, key, &[KEM_INFO, context], context)
}

/// Unwrap a key wrapped to `secret` under `context`.
pub fn unwrap_key(
    secret: &HybridKemSecret,
    envelope: &[u8],
    context: &[u8],
) -> Result<SymmetricKey> {
    unwrap_with_info(secret, envelope, &[KEM_INFO, context], context)
}

/// `label || u32_be(len(context)) || context`. The length prefix makes
/// the split between label and context unambiguous, and the info differs
/// from the unframed `KEM_INFO || context` of `wrap_key` for the same
/// context. Callers use a label of their own, never `KEM_INFO`.
fn labeled_info(label: &[u8], context: &[u8]) -> Result<Vec<u8>> {
    let len = u32::try_from(context.len()).map_err(|_| Error::InvalidFormat("kem context"))?;
    let mut info = Vec::with_capacity(label.len() + 4 + context.len());
    info.extend_from_slice(label);
    info.extend_from_slice(&len.to_be_bytes());
    info.extend_from_slice(context);
    Ok(info)
}

/// Wrap `key` to `recipient` under a label of its own (a context family
/// other than the vault keys), bound to `context`.
pub fn wrap_key_labeled(
    recipient: &HybridKemPublic,
    key: &SymmetricKey,
    label: &[u8],
    context: &[u8],
) -> Result<Vec<u8>> {
    let info = labeled_info(label, context)?;
    wrap_with_info(recipient, key, &[&info], &info)
}

/// Unwrap a key wrapped with `wrap_key_labeled` under `label` and `context`.
pub fn unwrap_key_labeled(
    secret: &HybridKemSecret,
    envelope: &[u8],
    label: &[u8],
    context: &[u8],
) -> Result<SymmetricKey> {
    let info = labeled_info(label, context)?;
    unwrap_with_info(secret, envelope, &[&info], &info)
}

fn wrap_with_info(
    recipient: &HybridKemPublic,
    key: &SymmetricKey,
    info: &[&[u8]],
    aad_context: &[u8],
) -> Result<Vec<u8>> {
    if recipient.mlkem.len() != MLKEM_PUBLIC_LEN {
        return Err(Error::InvalidFormat("mlkem public key length"));
    }
    let ek = EncapsulationKey::new(&ML_KEM_1024, &recipient.mlkem)
        .map_err(|_| Error::InvalidFormat("mlkem public key"))?;
    let (ct, ss_mlkem) = ek.encapsulate().map_err(|_| Error::Crypto)?;

    let eph = PrivateKey::generate(&X25519).map_err(|_| Error::Crypto)?;
    let eph_pub = x25519_public(&eph)?;
    let ss_x25519 = x25519_agree(&eph, &recipient.x25519)?;

    let ss = combine(
        ss_mlkem.as_ref(),
        &ss_x25519,
        ct.as_ref(),
        &eph_pub,
        &recipient.x25519,
        info,
    )?;
    let blob = seal(
        &ss,
        BlobKind::VaultKey,
        &blob_aad(aad_context),
        key.expose(),
    )?;

    let mut out = Vec::with_capacity(MLKEM_CT_LEN + X25519_LEN + blob.len());
    out.extend_from_slice(ct.as_ref());
    out.extend_from_slice(&eph_pub);
    out.extend_from_slice(&blob);
    Ok(out)
}

fn unwrap_with_info(
    secret: &HybridKemSecret,
    envelope: &[u8],
    info: &[&[u8]],
    aad_context: &[u8],
) -> Result<SymmetricKey> {
    if envelope.len() != envelope_len() {
        return Err(Error::InvalidFormat("kem envelope length"));
    }
    let (ct, rest) = envelope.split_at(MLKEM_CT_LEN);
    let (eph, blob) = rest.split_at(X25519_LEN);
    let eph_pub: [u8; 32] = eph
        .try_into()
        .map_err(|_| Error::InvalidFormat("kem envelope"))?;

    let dk = DecapsulationKey::new(&ML_KEM_1024, &secret.mlkem).map_err(|_| Error::Crypto)?;
    let ss_mlkem = dk
        .decapsulate(Ciphertext::from(ct))
        .map_err(|_| Error::Crypto)?;

    let x = secret.x25519_key()?;
    let own_pub = x25519_public(&x)?;
    let ss_x25519 = x25519_agree(&x, &eph_pub)?;

    let ss = combine(ss_mlkem.as_ref(), &ss_x25519, ct, &eph_pub, &own_pub, info)?;
    let plain = open(&ss, BlobKind::VaultKey, &blob_aad(aad_context), blob)?;
    if plain.len() != 32 {
        return Err(Error::InvalidFormat("wrapped key length"));
    }
    // Straight into the key buffer: no [u8; 32] temporary.
    let mut key = SymmetricKey::zeroed();
    key.bytes_mut().copy_from_slice(&plain);
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Error, IntegrityError};

    #[test]
    fn wrap_unwrap_roundtrip() {
        let sk = HybridKemSecret::generate().unwrap();
        let k = SymmetricKey::generate().unwrap();
        let env = wrap_key(&sk.public().unwrap(), &k, b"vault:1").unwrap();
        assert_eq!(
            unwrap_key(&sk, &env, b"vault:1").unwrap().expose(),
            k.expose()
        );
    }

    #[test]
    fn wrong_context_or_recipient_fails() {
        let sk = HybridKemSecret::generate().unwrap();
        let env = wrap_key(
            &sk.public().unwrap(),
            &SymmetricKey::generate().unwrap(),
            b"vault:1",
        )
        .unwrap();
        assert!(matches!(
            unwrap_key(&sk, &env, b"vault:2"),
            Err(Error::Integrity(_))
        ));
        assert!(unwrap_key(&HybridKemSecret::generate().unwrap(), &env, b"vault:1").is_err());
    }

    #[test]
    fn secret_bytes_roundtrip() {
        let sk = HybridKemSecret::generate().unwrap();
        let again = HybridKemSecret::from_bytes(&sk.to_bytes()).unwrap();
        assert_eq!(sk.public().unwrap(), again.public().unwrap());
        assert_eq!(sk.public().unwrap().mlkem.len(), 1568);
    }

    #[test]
    fn wrong_recipient_fails_on_commitment() {
        let sk = HybridKemSecret::generate().unwrap();
        let env = wrap_key(
            &sk.public().unwrap(),
            &SymmetricKey::generate().unwrap(),
            b"v",
        )
        .unwrap();
        let other = HybridKemSecret::generate().unwrap();
        assert_eq!(
            unwrap_key(&other, &env, b"v").unwrap_err(),
            Error::Integrity(IntegrityError::Commitment)
        );
    }

    #[test]
    fn wrong_length_envelope_is_rejected() {
        let sk = HybridKemSecret::generate().unwrap();
        let env = wrap_key(
            &sk.public().unwrap(),
            &SymmetricKey::generate().unwrap(),
            b"v",
        )
        .unwrap();
        for bad in [&[][..], &env[..1599], &env[..1600], &env[..env.len() - 1]] {
            assert!(matches!(
                unwrap_key(&sk, bad, b"v"),
                Err(Error::InvalidFormat(_))
            ));
        }
        let mut longer = env.clone();
        longer.push(0);
        assert!(matches!(
            unwrap_key(&sk, &longer, b"v"),
            Err(Error::InvalidFormat(_))
        ));
    }

    #[test]
    fn tampered_envelope_fails_integrity() {
        let sk = HybridKemSecret::generate().unwrap();
        let env = wrap_key(
            &sk.public().unwrap(),
            &SymmetricKey::generate().unwrap(),
            b"v",
        )
        .unwrap();
        for i in [0, 1567, 1568, 1599, env.len() - 1] {
            let mut t = env.clone();
            t[i] ^= 1;
            assert!(unwrap_key(&sk, &t, b"v").is_err(), "byte {i}");
        }
    }

    #[test]
    fn public_key_lengths_are_validated() {
        let mut pk = HybridKemSecret::generate().unwrap().public().unwrap();
        pk.mlkem.pop();
        let k = SymmetricKey::generate().unwrap();
        assert!(matches!(
            wrap_key(&pk, &k, b"v"),
            Err(Error::InvalidFormat(_))
        ));
    }

    #[test]
    fn secret_from_bytes_rejects_bad_input() {
        let sk = HybridKemSecret::generate().unwrap();
        let bytes = sk.to_bytes();
        assert!(HybridKemSecret::from_bytes(&bytes[..bytes.len() - 1]).is_err());
        let mut longer = bytes.to_vec();
        longer.push(0);
        assert!(HybridKemSecret::from_bytes(&longer).is_err());
        // Corrupting the embedded public key breaks the FIPS 203 hash check.
        let mut corrupt = bytes.to_vec();
        corrupt[2000] ^= 1;
        assert!(HybridKemSecret::from_bytes(&corrupt).is_err());
    }

    #[test]
    fn public_matches_aws_lc_encapsulation_key() {
        let sk = HybridKemSecret::generate().unwrap();
        // aws-lc cannot give the public key of a key rebuilt from raw bytes,
        // which is why public() reads it from the FIPS 203 layout.
        let rebuilt = DecapsulationKey::new(&ML_KEM_1024, &sk.mlkem).unwrap();
        assert!(rebuilt.encapsulation_key().is_err());
        let fresh = DecapsulationKey::generate(&ML_KEM_1024).unwrap();
        let ek = fresh.encapsulation_key().unwrap().key_bytes().unwrap();
        let raw = fresh.key_bytes().unwrap();
        assert_eq!(&raw.as_ref()[MLKEM_EK_START..MLKEM_EK_END], ek.as_ref());
    }

    #[test]
    fn debug_never_prints_bytes() {
        let sk = HybridKemSecret::generate().unwrap();
        assert_eq!(format!("{sk:?}"), "HybridKemSecret(**)");
    }

    #[test]
    fn labeled_round_trip() {
        let sk = HybridKemSecret::generate().unwrap();
        let k = SymmetricKey::generate().unwrap();
        let env = wrap_key_labeled(&sk.public().unwrap(), &k, b"onepass/test/v1", b"ctx").unwrap();
        let got = unwrap_key_labeled(&sk, &env, b"onepass/test/v1", b"ctx").unwrap();
        assert_eq!(got.expose(), k.expose());
    }

    #[test]
    fn labeled_rejects_other_label_or_context() {
        let sk = HybridKemSecret::generate().unwrap();
        let k = SymmetricKey::generate().unwrap();
        let env = wrap_key_labeled(&sk.public().unwrap(), &k, b"label/a", b"ctx").unwrap();
        assert!(unwrap_key_labeled(&sk, &env, b"label/b", b"ctx").is_err());
        assert!(unwrap_key_labeled(&sk, &env, b"label/a", b"ctx2").is_err());
        // Moving bytes between label and context changes the framing.
        assert!(unwrap_key_labeled(&sk, &env, b"label/ac", b"tx").is_err());
        let other = HybridKemSecret::generate().unwrap();
        assert!(unwrap_key_labeled(&other, &env, b"label/a", b"ctx").is_err());
    }

    #[test]
    fn wrap_key_unchanged() {
        let sk = HybridKemSecret::generate().unwrap();
        let k = SymmetricKey::generate().unwrap();
        let env = wrap_key(&sk.public().unwrap(), &k, b"vault:1").unwrap();
        assert_eq!(env.len(), envelope_len());
        assert_eq!(
            unwrap_key(&sk, &env, b"vault:1").unwrap().expose(),
            k.expose()
        );
        // Same combiner bytes as before the refactor: info is the plain
        // concatenation `KEM_INFO || context`.
        let ss_a = combine(
            b"a",
            b"b",
            b"c",
            &[1; 32],
            &[2; 32],
            &[KEM_INFO, b"vault:1"],
        )
        .unwrap();
        let ss_b = hkdf32(
            &[],
            &[&b"abc"[..], &[1; 32], &[2; 32]].concat(),
            &[b"onepass/kem/v1vault:1"],
        )
        .unwrap();
        assert_eq!(ss_a.expose(), ss_b.expose());
    }

    #[test]
    fn labeled_is_not_interchangeable() {
        let sk = HybridKemSecret::generate().unwrap();
        let k = SymmetricKey::generate().unwrap();
        let pk = sk.public().unwrap();
        let env = wrap_key_labeled(&pk, &k, KEM_INFO, b"vault:1").unwrap();
        assert!(unwrap_key(&sk, &env, b"vault:1").is_err());
        let env = wrap_key(&pk, &k, b"vault:1").unwrap();
        assert!(unwrap_key_labeled(&sk, &env, KEM_INFO, b"vault:1").is_err());
    }

    #[test]
    fn public_bytes_roundtrip() {
        let pk = HybridKemSecret::generate().unwrap().public().unwrap();
        let bytes = pk.to_bytes();
        assert_eq!(bytes.len(), 1600);
        assert_eq!(&bytes[..1568], &pk.mlkem[..]);
        assert_eq!(&bytes[1568..], &pk.x25519[..]);
        assert_eq!(HybridKemPublic::from_bytes(&bytes).unwrap(), pk);
        assert!(HybridKemPublic::from_bytes(&bytes[..1599]).is_err());
        let mut longer = bytes.clone();
        longer.push(0);
        assert!(HybridKemPublic::from_bytes(&longer).is_err());
    }

    type Family = (&'static str, fn(Id) -> Vec<u8>);

    /// Every production context family of the unframed `wrap_key`.
    fn unframed_families() -> [Family; 3] {
        [
            ("vault", crate::vault::kem_context),
            ("travel", crate::repo::travel::kem_context),
            ("archive", crate::archive::format::envelope_context),
        ]
    }

    #[test]
    fn unframed_context_families_have_fixed_shapes() {
        let id = Id([0xA5; 16]);
        let expected: [(&[u8], usize); 3] = [
            (b"vault:", 22),
            (b"travel:", 23),
            (b"onepass/archive/v1", 34),
        ];
        for ((name, family), (prefix, len)) in unframed_families().into_iter().zip(expected) {
            let ctx = family(id);
            assert_eq!(ctx.len(), len, "{name} length");
            assert!(ctx.starts_with(prefix), "{name} prefix");
            assert_eq!(&ctx[prefix.len()..], &id.0, "{name} id");
        }
        // No family's fixed prefix is a prefix of another's.
        for (i, (a, _)) in expected.iter().enumerate() {
            for (b, _) in &expected[i + 1..] {
                assert!(!a.starts_with(b) && !b.starts_with(a));
            }
        }
    }

    proptest::proptest! {
        /// For any ids, a context of one family is never a prefix of (nor
        /// equal to) a context of another family, and each family is
        /// injective. With the shared unframed `KEM_INFO`, this is what
        /// keeps the HKDF info strings and the blob ids apart.
        #[test]
        fn unframed_context_families_are_disjoint(
            a in proptest::prelude::any::<[u8; 16]>(),
            b in proptest::prelude::any::<[u8; 16]>(),
        ) {
            let families = unframed_families();
            for (i, (name_f, f)) in families.iter().enumerate() {
                let fa = f(Id(a));
                let fb = f(Id(b));
                proptest::prop_assert_eq!(fa == fb, a == b, "{} not injective", name_f);
                for (j, (name_g, g)) in families.iter().enumerate() {
                    if i == j {
                        continue;
                    }
                    let gb = g(Id(b));
                    proptest::prop_assert!(
                        !gb.starts_with(&fa),
                        "{} context is a prefix of a {} context",
                        name_f,
                        name_g
                    );
                }
            }
        }
    }

    #[test]
    fn wrap_key_golden_vector() {
        const V: &str = include_str!("../../tests/vectors/kem_wrap_key_v1.hex");
        let hex = |l: &str| data_encoding::HEXLOWER.decode(l.as_bytes()).unwrap();
        let lines: Vec<Vec<u8>> = V.lines().map(hex).collect();
        let [secret, key, context, envelope] = &lines[..] else {
            panic!("four lines");
        };
        let sk = HybridKemSecret::from_bytes(secret).unwrap();
        let got = unwrap_key(&sk, envelope, context).unwrap();
        assert_eq!(&got.expose()[..], &key[..]);
        assert!(unwrap_key_labeled(&sk, envelope, KEM_INFO, context).is_err());
    }
}
