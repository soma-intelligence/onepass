//! Hybrid KEM: ML-KEM-1024 + X25519, used to wrap keys to a recipient.
//!
//! Envelope: `ct_mlkem (1568) || eph_x25519_pub (32) || blob`, where `blob`
//! seals the wrapped key under
//! `HKDF-SHA256(salt = empty, ikm = ss_mlkem || ss_x25519 || ct_mlkem ||
//! eph_x25519_pub || recipient_x25519, info = "onepass/kem/v1" || context)`.

use std::fmt;

use aws_lc_rs::agreement::{self, PrivateKey, UnparsedPublicKey, X25519};
use aws_lc_rs::constant_time::verify_slices_are_equal;
use aws_lc_rs::digest::{self, SHA3_256, SHA256};
use aws_lc_rs::encoding::{AsBigEndian, Curve25519SeedBin};
use aws_lc_rs::hkdf::{HKDF_SHA256, KeyType, Salt};
use aws_lc_rs::kem::{Ciphertext, DecapsulationKey, EncapsulationKey, ML_KEM_1024};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::aead::{Aad, BlobKind, HEADER_LEN, open, padded_len, seal};
use super::key::SymmetricKey;
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
/// AEAD tag length of a blob.
const TAG_LEN: usize = 16;
/// Length prefix inside a blob's padded plaintext.
const LEN_PREFIX: usize = 4;
const KEM_INFO: &[u8] = b"onepass/kem/v1";
const SCHEMA: u16 = 1;

/// HKDF output length marker: 32 bytes.
struct Len32;

impl KeyType for Len32 {
    fn len(&self) -> usize {
        32
    }
}

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
    context: &[u8],
) -> Result<SymmetricKey> {
    let mut ikm = Zeroizing::new(Vec::with_capacity(
        ss_mlkem.len() + ss_x25519.len() + ct_mlkem.len() + 2 * X25519_LEN,
    ));
    ikm.extend_from_slice(ss_mlkem);
    ikm.extend_from_slice(ss_x25519);
    ikm.extend_from_slice(ct_mlkem);
    ikm.extend_from_slice(eph_pub);
    ikm.extend_from_slice(recipient_x25519);
    let prk = Salt::new(HKDF_SHA256, &[]).extract(&ikm);
    let info = [KEM_INFO, context];
    let okm = prk.expand(&info, Len32).map_err(|_| Error::Crypto)?;
    let mut key = SymmetricKey([0u8; 32]);
    okm.fill(&mut key.0).map_err(|_| Error::Crypto)?;
    Ok(key)
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

fn envelope_len() -> usize {
    MLKEM_CT_LEN + X25519_LEN + HEADER_LEN + padded_len(LEN_PREFIX + 32) + TAG_LEN
}

/// Wrap `key` to `recipient`, bound to `context`.
pub fn wrap_key(
    recipient: &HybridKemPublic,
    key: &SymmetricKey,
    context: &[u8],
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
        context,
    )?;
    let blob = seal(&ss, BlobKind::VaultKey, &blob_aad(context), key.expose())?;

    let mut out = Vec::with_capacity(MLKEM_CT_LEN + X25519_LEN + blob.len());
    out.extend_from_slice(ct.as_ref());
    out.extend_from_slice(&eph_pub);
    out.extend_from_slice(&blob);
    Ok(out)
}

/// Unwrap a key wrapped to `secret` under `context`.
pub fn unwrap_key(
    secret: &HybridKemSecret,
    envelope: &[u8],
    context: &[u8],
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

    let ss = combine(
        ss_mlkem.as_ref(),
        &ss_x25519,
        ct,
        &eph_pub,
        &own_pub,
        context,
    )?;
    let plain = open(&ss, BlobKind::VaultKey, &blob_aad(context), blob)?;
    let bytes: [u8; 32] = plain[..]
        .try_into()
        .map_err(|_| Error::InvalidFormat("wrapped key length"))?;
    Ok(SymmetricKey(bytes))
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
}
