//! Signatures: hybrid ML-DSA-87 + Ed25519 for everyday signing, and
//! SLH-DSA-SHA2-256s for the root identity (signs only keys and parameters).
//!
//! Every scheme signs the same framed message:
//! `"onepass/sig/v1" || len(domain) as u16 BE || domain || msg`.
//! ML-DSA and SLH-DSA use the pure variants with an empty FIPS context.

use std::fmt;
use std::hint::black_box;

use aws_lc_rs::signature::{
    ED25519, Ed25519KeyPair, KeyPair, ML_DSA_87, ML_DSA_87_SIGNING, PqdsaKeyPair, UnparsedPublicKey,
};
use serde::{Deserialize, Serialize};
use slh_dsa::{Sha2_256s, Signature as SlhSignature, SigningKey, VerifyingKey};
use zeroize::Zeroizing;

use super::random::fill_random;
use crate::{Error, IntegrityError, Result};

const SIG_PREFIX: &[u8] = b"onepass/sig/v1";
const SEED_LEN: usize = 32;
const HYBRID_SECRET_LEN: usize = 2 * SEED_LEN;
const MLDSA_PUBLIC_LEN: usize = 2592;
const MLDSA_SIG_LEN: usize = 4627;
/// SLH-DSA-SHA2-256s: n = 32.
const SLH_N: usize = 32;
/// `sk_seed || sk_prf || pk_seed || pk_root`.
const SLH_SECRET_LEN: usize = 4 * SLH_N;
/// `pk_seed || pk_root`.
const SLH_PUBLIC_LEN: usize = 2 * SLH_N;
const SLH_SIG_LEN: usize = 29792;

type SlhSigningKey = SigningKey<Sha2_256s>;
type SlhVerifyingKey = VerifyingKey<Sha2_256s>;

/// Frame `msg` under `domain`. Domains longer than `u16::MAX` are rejected.
fn signed_message(domain: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
    let len = u16::try_from(domain.len())
        .map_err(|_| Error::InvalidFormat("signature domain too long"))?;
    let mut out = Vec::with_capacity(SIG_PREFIX.len() + 2 + domain.len() + msg.len());
    out.extend_from_slice(SIG_PREFIX);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(domain);
    out.extend_from_slice(msg);
    Ok(out)
}

fn bad_signature() -> Error {
    Error::Integrity(IntegrityError::Signature)
}

/// Hybrid signing key: the two 32-byte seeds, aws-lc keys are rebuilt at use.
pub struct HybridSigningKey {
    mldsa_seed: Zeroizing<[u8; 32]>,
    ed25519_seed: Zeroizing<[u8; 32]>,
}

/// Hybrid verifying key. `mldsa` is 2592 bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HybridVerifyingKey {
    #[serde(with = "serde_bytes")]
    pub mldsa: Vec<u8>,
    pub ed25519: [u8; 32],
}

/// Hybrid signature. `mldsa` is 4627 bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HybridSignature {
    #[serde(with = "serde_bytes")]
    pub mldsa: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub ed25519: [u8; 64],
}

impl HybridSigningKey {
    pub fn generate() -> Result<HybridSigningKey> {
        let mut mldsa_seed = Zeroizing::new([0u8; SEED_LEN]);
        let mut ed25519_seed = Zeroizing::new([0u8; SEED_LEN]);
        fill_random(&mut *mldsa_seed)?;
        fill_random(&mut *ed25519_seed)?;
        Ok(HybridSigningKey {
            mldsa_seed,
            ed25519_seed,
        })
    }

    /// `mldsa_seed (32) || ed25519_seed (32)`.
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(HYBRID_SECRET_LEN));
        out.extend_from_slice(&*self.mldsa_seed);
        out.extend_from_slice(&*self.ed25519_seed);
        out
    }

    pub fn from_bytes(b: &[u8]) -> Result<HybridSigningKey> {
        if b.len() != HYBRID_SECRET_LEN {
            return Err(Error::InvalidFormat("signing key length"));
        }
        let mut mldsa_seed = Zeroizing::new([0u8; SEED_LEN]);
        let mut ed25519_seed = Zeroizing::new([0u8; SEED_LEN]);
        mldsa_seed.copy_from_slice(&b[..SEED_LEN]);
        ed25519_seed.copy_from_slice(&b[SEED_LEN..]);
        let key = HybridSigningKey {
            mldsa_seed,
            ed25519_seed,
        };
        key.mldsa_key()
            .map_err(|_| Error::InvalidFormat("signing key"))?;
        key.ed25519_key()
            .map_err(|_| Error::InvalidFormat("signing key"))?;
        Ok(key)
    }

    pub fn verifying_key(&self) -> Result<HybridVerifyingKey> {
        let mldsa = self.mldsa_key()?.public_key().as_ref().to_vec();
        let ed25519 = self
            .ed25519_key()?
            .public_key()
            .as_ref()
            .try_into()
            .map_err(|_| Error::Crypto)?;
        Ok(HybridVerifyingKey { mldsa, ed25519 })
    }

    pub fn sign(&self, domain: &[u8], msg: &[u8]) -> Result<HybridSignature> {
        let m = signed_message(domain, msg)?;
        let mut mldsa = vec![0u8; MLDSA_SIG_LEN];
        let n = self
            .mldsa_key()?
            .sign(&m, &mut mldsa)
            .map_err(|_| Error::Crypto)?;
        if n != MLDSA_SIG_LEN {
            return Err(Error::Crypto);
        }
        let ed = self
            .ed25519_key()?
            .try_sign(&m)
            .map_err(|_| Error::Crypto)?;
        let ed25519 = ed.as_ref().try_into().map_err(|_| Error::Crypto)?;
        Ok(HybridSignature { mldsa, ed25519 })
    }

    fn mldsa_key(&self) -> Result<PqdsaKeyPair> {
        PqdsaKeyPair::from_seed(&ML_DSA_87_SIGNING, &*self.mldsa_seed).map_err(|_| Error::Crypto)
    }

    fn ed25519_key(&self) -> Result<Ed25519KeyPair> {
        Ed25519KeyPair::from_seed_unchecked(&*self.ed25519_seed).map_err(|_| Error::Crypto)
    }
}

impl fmt::Debug for HybridSigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HybridSigningKey(**)")
    }
}

impl HybridVerifyingKey {
    /// Both halves must verify. Malformed signatures fail as `Signature`,
    /// a malformed key as `InvalidFormat`.
    pub fn verify(&self, domain: &[u8], msg: &[u8], sig: &HybridSignature) -> Result<()> {
        if self.mldsa.len() != MLDSA_PUBLIC_LEN {
            return Err(Error::InvalidFormat("mldsa public key length"));
        }
        let m = signed_message(domain, msg)?;
        if sig.mldsa.len() != MLDSA_SIG_LEN {
            return Err(bad_signature());
        }
        let mldsa_ok = UnparsedPublicKey::new(&ML_DSA_87, &self.mldsa)
            .verify(&m, &sig.mldsa)
            .is_ok();
        let ed25519_ok = UnparsedPublicKey::new(&ED25519, &self.ed25519)
            .verify(&m, &sig.ed25519)
            .is_ok();
        if mldsa_ok && ed25519_ok {
            Ok(())
        } else {
            Err(bad_signature())
        }
    }
}

/// Root identity key (SLH-DSA-SHA2-256s), stored as its FIPS 205 encoding
/// `sk_seed || sk_prf || pk_seed || pk_root`. The crate's key type has no
/// `Zeroize`, so it is rebuilt at use and overwritten on drop.
pub struct IdentityKey {
    sk: Zeroizing<[u8; SLH_SECRET_LEN]>,
}

/// Identity verifying key: `pk_seed || pk_root` (64 bytes).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityVerifyingKey(#[serde(with = "serde_bytes")] Vec<u8>);

/// Identity signature (29792 bytes).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentitySignature(#[serde(with = "serde_bytes")] Vec<u8>);

/// Holds a rebuilt crate signing key and overwrites it on drop. Best effort:
/// copies made inside the crate while signing are outside our control.
struct SlhKeyGuard(SlhSigningKey);

impl Drop for SlhKeyGuard {
    fn drop(&mut self) {
        if let Ok(zero) = SlhSigningKey::try_from(&[0u8; SLH_SECRET_LEN][..]) {
            self.0 = zero;
        }
        black_box(&self.0);
    }
}

impl IdentityKey {
    pub fn generate() -> Result<IdentityKey> {
        let mut seeds = Zeroizing::new([0u8; 3 * SLH_N]);
        fill_random(&mut *seeds)?;
        Self::from_seeds(&seeds[..])
    }

    /// FIPS 205 `slh_keygen_internal` over `sk_seed || sk_prf || pk_seed`.
    fn from_seeds(seeds: &[u8]) -> Result<IdentityKey> {
        if seeds.len() != 3 * SLH_N {
            return Err(Error::Crypto);
        }
        let key = SlhKeyGuard(SlhSigningKey::slh_keygen_internal(
            &seeds[..SLH_N],
            &seeds[SLH_N..2 * SLH_N],
            &seeds[2 * SLH_N..],
        ));
        let vk = AsRef::<SlhVerifyingKey>::as_ref(&key.0).to_bytes();
        let mut sk = Zeroizing::new([0u8; SLH_SECRET_LEN]);
        sk[..2 * SLH_N].copy_from_slice(&seeds[..2 * SLH_N]);
        sk[2 * SLH_N..].copy_from_slice(&vk);
        Ok(IdentityKey { sk })
    }

    /// FIPS 205 encoding, 128 bytes.
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.sk.to_vec())
    }

    /// Rejects a wrong length and a `pk_root` that does not match the seeds.
    pub fn from_bytes(b: &[u8]) -> Result<IdentityKey> {
        if b.len() != SLH_SECRET_LEN {
            return Err(Error::InvalidFormat("identity key length"));
        }
        let key = Self::from_seeds(&b[..3 * SLH_N])?;
        // Seeds are copied as is; only the public root can differ.
        if key.sk[3 * SLH_N..] != b[3 * SLH_N..] {
            return Err(Error::InvalidFormat("identity key"));
        }
        Ok(key)
    }

    pub fn verifying_key(&self) -> IdentityVerifyingKey {
        IdentityVerifyingKey(self.sk[2 * SLH_N..].to_vec())
    }

    pub fn sign(&self, domain: &[u8], msg: &[u8]) -> Result<IdentitySignature> {
        let m = signed_message(domain, msg)?;
        let key = SlhKeyGuard(SlhSigningKey::try_from(&self.sk[..]).map_err(|_| Error::Crypto)?);
        // Hedged signing (FIPS 205 default): fresh randomness per signature.
        let mut rand = Zeroizing::new([0u8; SLH_N]);
        fill_random(&mut *rand)?;
        let sig = key
            .0
            .try_sign_with_context(&m, &[], Some(&rand[..]))
            .map_err(|_| Error::Crypto)?;
        Ok(IdentitySignature(sig.to_vec()))
    }
}

impl fmt::Debug for IdentityKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("IdentityKey(**)")
    }
}

impl IdentityVerifyingKey {
    /// Malformed signatures fail as `Signature`, a malformed key as
    /// `InvalidFormat`.
    pub fn verify(&self, domain: &[u8], msg: &[u8], sig: &IdentitySignature) -> Result<()> {
        if self.0.len() != SLH_PUBLIC_LEN {
            return Err(Error::InvalidFormat("identity public key length"));
        }
        let vk = SlhVerifyingKey::try_from(&self.0[..])
            .map_err(|_| Error::InvalidFormat("identity public key"))?;
        let m = signed_message(domain, msg)?;
        if sig.0.len() != SLH_SIG_LEN {
            return Err(bad_signature());
        }
        let sig = SlhSignature::<Sha2_256s>::try_from(&sig.0[..]).map_err(|_| bad_signature())?;
        vk.try_verify_with_context(&m, &[], &sig)
            .map_err(|_| bad_signature())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::IntegrityError;

    #[test]
    fn hybrid_sign_verify_and_domain_separation() {
        let sk = HybridSigningKey::generate().unwrap();
        let vk = sk.verifying_key().unwrap();
        let sig = sk.sign(b"manifest", b"hello").unwrap();
        vk.verify(b"manifest", b"hello", &sig).unwrap();
        assert!(vk.verify(b"params", b"hello", &sig).is_err());
        assert!(vk.verify(b"manifest", b"hellp", &sig).is_err());
    }

    #[test]
    fn hybrid_rejects_if_either_half_is_bad() {
        let sk = HybridSigningKey::generate().unwrap();
        let vk = sk.verifying_key().unwrap();
        let mut sig = sk.sign(b"d", b"m").unwrap();
        sig.ed25519[0] ^= 1;
        assert!(vk.verify(b"d", b"m", &sig).is_err());
        let mut sig = sk.sign(b"d", b"m").unwrap();
        sig.mldsa[0] ^= 1;
        assert!(vk.verify(b"d", b"m", &sig).is_err());
    }

    #[test]
    fn identity_sign_verify() {
        let id = IdentityKey::generate().unwrap();
        let sig = id.sign(b"keyset", b"pubkeys").unwrap();
        id.verifying_key()
            .verify(b"keyset", b"pubkeys", &sig)
            .unwrap();
        assert!(
            id.verifying_key()
                .verify(b"keyset", b"other", &sig)
                .is_err()
        );
    }

    fn sig_err() -> Error {
        Error::Integrity(IntegrityError::Signature)
    }

    #[test]
    fn signed_message_framing_is_exact() {
        assert_eq!(
            signed_message(b"d", b"m").unwrap(),
            b"onepass/sig/v1\x00\x01dm".to_vec()
        );
        let long = vec![7u8; 300];
        let m = signed_message(&long, b"").unwrap();
        assert_eq!(&m[14..16], &[0x01, 0x2c]);
        assert_eq!(m.len(), 14 + 2 + 300);
    }

    #[test]
    fn hybrid_halves_sign_the_framed_message() {
        let sk = HybridSigningKey::generate().unwrap();
        let vk = sk.verifying_key().unwrap();
        let sig = sk.sign(b"manifest", b"hello").unwrap();
        let m = signed_message(b"manifest", b"hello").unwrap();
        UnparsedPublicKey::new(&ML_DSA_87, &vk.mldsa)
            .verify(&m, &sig.mldsa)
            .unwrap();
        UnparsedPublicKey::new(&ED25519, &vk.ed25519)
            .verify(&m, &sig.ed25519)
            .unwrap();
        assert!(
            UnparsedPublicKey::new(&ED25519, &vk.ed25519)
                .verify(b"hello", &sig.ed25519)
                .is_err()
        );
    }

    #[test]
    fn hybrid_lengths_and_exact_errors() {
        let sk = HybridSigningKey::generate().unwrap();
        let vk = sk.verifying_key().unwrap();
        let sig = sk.sign(b"d", b"m").unwrap();
        assert_eq!(vk.mldsa.len(), MLDSA_PUBLIC_LEN);
        assert_eq!(sig.mldsa.len(), MLDSA_SIG_LEN);

        let mut t = sig.clone();
        t.ed25519[63] ^= 1;
        assert_eq!(vk.verify(b"d", b"m", &t).unwrap_err(), sig_err());
        let mut t = sig.clone();
        let last = t.mldsa.len() - 1;
        t.mldsa[last] ^= 1;
        assert_eq!(vk.verify(b"d", b"m", &t).unwrap_err(), sig_err());

        let other = HybridSigningKey::generate().unwrap();
        let other_vk = other.verifying_key().unwrap();
        assert_eq!(other_vk.verify(b"d", b"m", &sig).unwrap_err(), sig_err());
        // One half from another key is still rejected.
        let mixed = HybridSignature {
            mldsa: sig.mldsa.clone(),
            ed25519: other.sign(b"d", b"m").unwrap().ed25519,
        };
        assert_eq!(vk.verify(b"d", b"m", &mixed).unwrap_err(), sig_err());
    }

    #[test]
    fn hybrid_malformed_inputs_never_panic() {
        let sk = HybridSigningKey::generate().unwrap();
        let vk = sk.verifying_key().unwrap();
        let sig = sk.sign(b"d", b"m").unwrap();
        for len in [0, 1, MLDSA_SIG_LEN - 1, MLDSA_SIG_LEN + 1] {
            let mut t = sig.clone();
            t.mldsa.resize(len, 0);
            assert_eq!(vk.verify(b"d", b"m", &t).unwrap_err(), sig_err(), "{len}");
        }
        for len in [0, MLDSA_PUBLIC_LEN - 1, MLDSA_PUBLIC_LEN + 1] {
            let mut bad = vk.clone();
            bad.mldsa.resize(len, 0);
            assert!(matches!(
                bad.verify(b"d", b"m", &sig),
                Err(Error::InvalidFormat(_))
            ));
        }
        let garbage = HybridVerifyingKey {
            mldsa: vec![0xff; MLDSA_PUBLIC_LEN],
            ed25519: [0xff; 32],
        };
        assert!(garbage.verify(b"d", b"m", &sig).is_err());
        let zero_sig = HybridSignature {
            mldsa: vec![0; MLDSA_SIG_LEN],
            ed25519: [0; 64],
        };
        assert_eq!(vk.verify(b"d", b"m", &zero_sig).unwrap_err(), sig_err());
    }

    #[test]
    fn domain_longer_than_u16_is_rejected() {
        let sk = HybridSigningKey::generate().unwrap();
        let vk = sk.verifying_key().unwrap();
        let max = vec![1u8; usize::from(u16::MAX)];
        let sig = sk.sign(&max, b"m").unwrap();
        vk.verify(&max, b"m", &sig).unwrap();
        let over = vec![1u8; usize::from(u16::MAX) + 1];
        assert!(matches!(sk.sign(&over, b"m"), Err(Error::InvalidFormat(_))));
        assert!(matches!(
            vk.verify(&over, b"m", &sig),
            Err(Error::InvalidFormat(_))
        ));
    }

    #[test]
    fn hybrid_key_bytes_roundtrip() {
        let sk = HybridSigningKey::generate().unwrap();
        let bytes = sk.to_bytes();
        assert_eq!(bytes.len(), HYBRID_SECRET_LEN);
        let again = HybridSigningKey::from_bytes(&bytes).unwrap();
        assert_eq!(sk.verifying_key().unwrap(), again.verifying_key().unwrap());
        let sig = again.sign(b"d", b"m").unwrap();
        sk.verifying_key()
            .unwrap()
            .verify(b"d", b"m", &sig)
            .unwrap();
        for bad in [&bytes[..63], &[][..]] {
            assert!(matches!(
                HybridSigningKey::from_bytes(bad),
                Err(Error::InvalidFormat(_))
            ));
        }
        let mut longer = bytes.to_vec();
        longer.push(0);
        assert!(matches!(
            HybridSigningKey::from_bytes(&longer),
            Err(Error::InvalidFormat(_))
        ));
    }

    #[test]
    fn hybrid_public_types_roundtrip_through_postcard() {
        let sk = HybridSigningKey::generate().unwrap();
        let vk = sk.verifying_key().unwrap();
        let sig = sk.sign(b"d", b"m").unwrap();
        let vk2: HybridVerifyingKey =
            postcard::from_bytes(&postcard::to_allocvec(&vk).unwrap()).unwrap();
        let sig2: HybridSignature =
            postcard::from_bytes(&postcard::to_allocvec(&sig).unwrap()).unwrap();
        assert_eq!(vk2, vk);
        assert_eq!(sig2, sig);
        vk2.verify(b"d", b"m", &sig2).unwrap();
    }

    #[test]
    fn signing_key_debug_is_redacted() {
        let sk = HybridSigningKey::generate().unwrap();
        assert_eq!(format!("{sk:?}"), "HybridSigningKey(**)");
    }

    // SLH-DSA-SHA2-256s signing is slow in debug builds: this test signs
    // nothing, the next one signs once.
    #[test]
    fn identity_key_bytes_and_malformed_inputs() {
        let id = IdentityKey::generate().unwrap();
        assert_eq!(format!("{id:?}"), "IdentityKey(**)");
        let bytes = id.to_bytes();
        assert_eq!(bytes.len(), SLH_SECRET_LEN);
        let again = IdentityKey::from_bytes(&bytes).unwrap();
        assert_eq!(again.verifying_key(), id.verifying_key());
        assert_eq!(id.verifying_key().0.len(), SLH_PUBLIC_LEN);

        assert!(matches!(
            IdentityKey::from_bytes(&bytes[..SLH_SECRET_LEN - 1]),
            Err(Error::InvalidFormat(_))
        ));
        // A flipped secret seed or public root no longer matches.
        for i in [0, SLH_SECRET_LEN - 1] {
            let mut t = bytes.to_vec();
            t[i] ^= 1;
            assert!(
                matches!(IdentityKey::from_bytes(&t), Err(Error::InvalidFormat(_))),
                "byte {i}"
            );
        }

        assert!(matches!(
            id.sign(&vec![0u8; usize::from(u16::MAX) + 1], b"m"),
            Err(Error::InvalidFormat(_))
        ));
        let vk = id.verifying_key();
        for len in [0, 1, SLH_SIG_LEN - 1, SLH_SIG_LEN + 1] {
            let sig = IdentitySignature(vec![0; len]);
            assert_eq!(vk.verify(b"d", b"m", &sig).unwrap_err(), sig_err(), "{len}");
        }
        let zero = IdentitySignature(vec![0; SLH_SIG_LEN]);
        assert_eq!(vk.verify(b"d", b"m", &zero).unwrap_err(), sig_err());
        for len in [0, SLH_PUBLIC_LEN - 1, SLH_PUBLIC_LEN + 1] {
            let bad = IdentityVerifyingKey(vec![0; len]);
            assert!(matches!(
                bad.verify(b"d", b"m", &zero),
                Err(Error::InvalidFormat(_))
            ));
        }
    }

    #[test]
    fn identity_signature_is_bound_to_domain_key_and_bytes() {
        let id = IdentityKey::generate().unwrap();
        let vk = id.verifying_key();
        let sig = id.sign(b"keyset", b"pubkeys").unwrap();
        assert_eq!(sig.0.len(), SLH_SIG_LEN);
        assert_eq!(
            vk.verify(b"params", b"pubkeys", &sig).unwrap_err(),
            sig_err()
        );
        for i in [0, sig.0.len() - 1] {
            let mut t = sig.clone();
            t.0[i] ^= 1;
            assert_eq!(vk.verify(b"keyset", b"pubkeys", &t).unwrap_err(), sig_err());
        }
        let other = IdentityKey::generate().unwrap().verifying_key();
        assert_eq!(
            other.verify(b"keyset", b"pubkeys", &sig).unwrap_err(),
            sig_err()
        );
        let vk2: IdentityVerifyingKey =
            postcard::from_bytes(&postcard::to_allocvec(&vk).unwrap()).unwrap();
        let sig2: IdentitySignature =
            postcard::from_bytes(&postcard::to_allocvec(&sig).unwrap()).unwrap();
        assert_eq!((&vk2, &sig2), (&vk, &sig));
        vk2.verify(b"keyset", b"pubkeys", &sig2).unwrap();
    }
}
