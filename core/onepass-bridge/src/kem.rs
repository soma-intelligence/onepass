//! Hybrid KEM of the bridge (spec 6.2): ML-KEM-1024 + X25519, combined by
//! HKDF-SHA256 under the label `onepass/bridge/kem/v1`.
//!
//! This is the bridge's own construction, distinct from `onepass_core`'s
//! `onepass/kem/v1` wrapping. Public key: `ek_mlkem (1568) || pk_x25519
//! (32)`. Ciphertext: `ct_mlkem (1568) || E_x25519 (32)`. Shared secret:
//! `HKDF-SHA256(salt = label, ikm = ss_m || ss_x, info = SHA-256(ct ||
//! pk_x))`.
//!
//! The production path uses `aws-lc-rs` only. `aws-lc-rs` has no seeded
//! ML-KEM key generation or encapsulation, so the deterministic helpers
//! (`from_seeds`, `encapsulate_deterministic`), compiled only under `test`
//! or feature `vectors`, take the ML-KEM step from `libcrux-ml-kem` (an
//! optional dependency enabled by `vectors`, never in a shipped build).
//! Both paths feed the same combiner and are interoperable: tests
//! decapsulate deterministic ciphertexts with an `aws-lc-rs` secret and the
//! reverse.

use aws_lc_rs::agreement::{self, PrivateKey, UnparsedPublicKey, X25519};
use aws_lc_rs::digest::{self, SHA256};
use aws_lc_rs::encoding::{AsBigEndian, Curve25519SeedBin};
use aws_lc_rs::kem::{Ciphertext, DecapsulationKey, EncapsulationKey, ML_KEM_1024};
use zeroize::Zeroizing;

use crate::{BridgeError, Result};

const MLKEM_PUBLIC_LEN: usize = 1568;
const MLKEM_SECRET_LEN: usize = 3168;
const MLKEM_CT_LEN: usize = 1568;
const X25519_LEN: usize = 32;
/// Hybrid public key length: `ek_mlkem || pk_x25519`.
pub const PUBLIC_LEN: usize = MLKEM_PUBLIC_LEN + X25519_LEN;
/// Hybrid ciphertext length: `ct_mlkem || E_x25519`.
pub const CT_LEN: usize = MLKEM_CT_LEN + X25519_LEN;
/// FIPS 203 decapsulation key layout (k = 4):
/// `dk_pke (1536) || ek (1568) || H(ek) (32) || z (32)`.
const MLKEM_EK_START: usize = 1536;
const MLKEM_EK_END: usize = MLKEM_EK_START + MLKEM_PUBLIC_LEN;
const KEM_LABEL: &[u8] = b"onepass/bridge/kem/v1";

/// Hybrid public key.
#[derive(Clone, PartialEq, Eq)]
pub struct KemPublic {
    bytes: [u8; PUBLIC_LEN],
}

/// Hybrid secret key: raw bytes, aws-lc keys are rebuilt at use.
pub struct KemSecret {
    mlkem: Zeroizing<Vec<u8>>,
    x25519: Zeroizing<[u8; 32]>,
    public: KemPublic,
}

impl std::fmt::Debug for KemPublic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KemPublic(..)")
    }
}

impl std::fmt::Debug for KemSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KemSecret(**)")
    }
}

impl KemPublic {
    pub fn to_bytes(&self) -> [u8; PUBLIC_LEN] {
        self.bytes
    }

    pub fn from_bytes(b: &[u8]) -> Result<KemPublic> {
        let bytes: [u8; PUBLIC_LEN] = b
            .try_into()
            .map_err(|_| BridgeError::BadFrame("kem public key length"))?;
        EncapsulationKey::new(&ML_KEM_1024, &bytes[..MLKEM_PUBLIC_LEN])
            .map_err(|_| BridgeError::BadFrame("kem public key"))?;
        Ok(KemPublic { bytes })
    }

    fn x25519(&self) -> [u8; 32] {
        let mut x = [0u8; 32];
        x.copy_from_slice(&self.bytes[MLKEM_PUBLIC_LEN..]);
        x
    }
}

impl KemSecret {
    pub fn generate() -> Result<KemSecret> {
        let dk = DecapsulationKey::generate(&ML_KEM_1024).map_err(|_| BridgeError::Crypto)?;
        let dk_bytes = dk.key_bytes().map_err(|_| BridgeError::Crypto)?;
        let x = PrivateKey::generate(&X25519).map_err(|_| BridgeError::Crypto)?;
        let seed: Curve25519SeedBin<'static> = x.as_be_bytes().map_err(|_| BridgeError::Crypto)?;
        Self::from_parts(dk_bytes.as_ref(), seed.as_ref())
    }

    fn from_parts(mlkem: &[u8], x25519: &[u8]) -> Result<KemSecret> {
        if mlkem.len() != MLKEM_SECRET_LEN || x25519.len() != X25519_LEN {
            return Err(BridgeError::Crypto);
        }
        DecapsulationKey::new(&ML_KEM_1024, mlkem).map_err(|_| BridgeError::Crypto)?;
        let x = PrivateKey::from_private_key(&X25519, x25519).map_err(|_| BridgeError::Crypto)?;
        let mut bytes = [0u8; PUBLIC_LEN];
        bytes[..MLKEM_PUBLIC_LEN].copy_from_slice(&mlkem[MLKEM_EK_START..MLKEM_EK_END]);
        bytes[MLKEM_PUBLIC_LEN..].copy_from_slice(x25519_public(&x)?.as_ref());
        let mut seed = Zeroizing::new([0u8; 32]);
        seed.copy_from_slice(x25519);
        Ok(KemSecret {
            mlkem: Zeroizing::new(mlkem.to_vec()),
            x25519: seed,
            public: KemPublic { bytes },
        })
    }

    pub fn public(&self) -> KemPublic {
        self.public.clone()
    }

    /// Decapsulate a 1600 byte ciphertext. ML-KEM rejects implicitly: a
    /// tampered ciphertext gives an unrelated secret, which then fails the
    /// MAC check of the handshake.
    pub fn decapsulate(&self, ct: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
        let ct: &[u8; CT_LEN] = ct
            .try_into()
            .map_err(|_| BridgeError::BadFrame("kem ciphertext length"))?;
        let (ct_m, eph) = ct.split_at(MLKEM_CT_LEN);
        let dk =
            DecapsulationKey::new(&ML_KEM_1024, &self.mlkem).map_err(|_| BridgeError::Crypto)?;
        let ss_m = dk
            .decapsulate(Ciphertext::from(ct_m))
            .map_err(|_| BridgeError::Crypto)?;
        let x = PrivateKey::from_private_key(&X25519, &*self.x25519)
            .map_err(|_| BridgeError::Crypto)?;
        let eph: [u8; 32] = eph.try_into().map_err(|_| BridgeError::Crypto)?;
        let ss_x = x25519_agree(&x, &eph)?;
        combine(ct, &self.public.x25519(), ss_m.as_ref(), &ss_x)
    }

    /// Deterministic key pair for test vectors: `mlkem_seed` is `d || z` of
    /// FIPS 203 `KeyGen_internal`, `x25519` the private scalar seed.
    #[cfg(any(test, feature = "vectors"))]
    pub fn from_seeds(mlkem_seed: &[u8; 64], x25519: &[u8; 32]) -> Result<KemSecret> {
        let pair = libcrux_ml_kem::mlkem1024::generate_key_pair(*mlkem_seed);
        Self::from_parts(pair.sk(), x25519)
    }
}

fn x25519_public(key: &PrivateKey) -> Result<[u8; 32]> {
    let pk = key.compute_public_key().map_err(|_| BridgeError::Crypto)?;
    pk.as_ref().try_into().map_err(|_| BridgeError::Crypto)
}

fn x25519_agree(key: &PrivateKey, peer: &[u8; 32]) -> Result<Zeroizing<Vec<u8>>> {
    agreement::agree(
        key,
        UnparsedPublicKey::new(&X25519, peer),
        BridgeError::Crypto,
        |s| Ok(Zeroizing::new(s.to_vec())),
    )
}

/// Spec 6.2 step 4:
/// `HKDF-SHA256(salt = label, ikm = ss_m || ss_x, info = SHA-256(ct || pk_x))`.
fn combine(
    ct: &[u8; CT_LEN],
    pk_x: &[u8; 32],
    ss_m: &[u8],
    ss_x: &[u8],
) -> Result<Zeroizing<[u8; 32]>> {
    let mut ikm = Zeroizing::new(Vec::with_capacity(ss_m.len() + ss_x.len()));
    ikm.extend_from_slice(ss_m);
    ikm.extend_from_slice(ss_x);
    let mut h = digest::Context::new(&SHA256);
    h.update(ct);
    h.update(pk_x);
    let info = h.finish();
    crate::kdf::hkdf32(KEM_LABEL, &ikm, info.as_ref())
}

/// X25519 half and combiner, shared by the random and the seeded paths.
fn finish_encaps(
    pk: &KemPublic,
    ct_m: &[u8],
    ss_m: &[u8],
    eph: &PrivateKey,
) -> Result<([u8; CT_LEN], Zeroizing<[u8; 32]>)> {
    if ct_m.len() != MLKEM_CT_LEN {
        return Err(BridgeError::Crypto);
    }
    let pk_x = pk.x25519();
    let ss_x = x25519_agree(eph, &pk_x)?;
    let mut ct = [0u8; CT_LEN];
    ct[..MLKEM_CT_LEN].copy_from_slice(ct_m);
    ct[MLKEM_CT_LEN..].copy_from_slice(&x25519_public(eph)?);
    let ss = combine(&ct, &pk_x, ss_m, &ss_x)?;
    Ok((ct, ss))
}

/// Encapsulate to `pk`: the 1600 byte ciphertext and the 32 byte secret.
pub fn encapsulate(pk: &KemPublic) -> Result<([u8; CT_LEN], Zeroizing<[u8; 32]>)> {
    let ek = EncapsulationKey::new(&ML_KEM_1024, &pk.bytes[..MLKEM_PUBLIC_LEN])
        .map_err(|_| BridgeError::BadFrame("kem public key"))?;
    let (ct_m, ss_m) = ek.encapsulate().map_err(|_| BridgeError::Crypto)?;
    let eph = PrivateKey::generate(&X25519).map_err(|_| BridgeError::Crypto)?;
    finish_encaps(pk, ct_m.as_ref(), ss_m.as_ref(), &eph)
}

/// Encapsulation with fixed randomness, for test vectors only.
#[cfg(any(test, feature = "vectors"))]
pub fn encapsulate_deterministic(
    pk: &KemPublic,
    mlkem_seed: &[u8; 32],
    x25519_eph: &[u8; 32],
) -> Result<([u8; CT_LEN], Zeroizing<[u8; 32]>)> {
    let ek = libcrux_ml_kem::mlkem1024::MlKem1024PublicKey::try_from(&pk.bytes[..MLKEM_PUBLIC_LEN])
        .map_err(|_| BridgeError::BadFrame("kem public key"))?;
    let (ct_m, ss_m) = libcrux_ml_kem::mlkem1024::encapsulate(&ek, *mlkem_seed);
    let eph = PrivateKey::from_private_key(&X25519, x25519_eph).map_err(|_| BridgeError::Crypto)?;
    finish_encaps(pk, ct_m.as_slice(), &ss_m, &eph)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pk_x(pk: &KemPublic) -> [u8; 32] {
        pk.to_bytes()[MLKEM_PUBLIC_LEN..].try_into().unwrap()
    }

    #[test]
    fn kem_round_trip() {
        let sk = KemSecret::generate().unwrap();
        let pk = sk.public();
        assert_eq!(pk.to_bytes().len(), 1600);
        let (ct, ss) = encapsulate(&pk).unwrap();
        assert_eq!(ct.len(), 1600);
        assert_eq!(*sk.decapsulate(&ct).unwrap(), *ss);
        // Fresh randomness each time.
        let (ct2, ss2) = encapsulate(&pk).unwrap();
        assert_ne!(ct, ct2);
        assert_ne!(*ss, *ss2);
    }

    #[test]
    fn public_bytes_round_trip() {
        let pk = KemSecret::generate().unwrap().public();
        let again = KemPublic::from_bytes(&pk.to_bytes()).unwrap();
        assert!(pk == again);
    }

    #[test]
    fn kem_ct_bitflip_gives_other_secret_or_error() {
        let sk = KemSecret::generate().unwrap();
        let (ct, ss) = encapsulate(&sk.public()).unwrap();
        // ML-KEM half: implicit rejection, so decapsulation must succeed
        // and give an unrelated secret.
        for i in [0, 700, MLKEM_CT_LEN - 1] {
            let mut bad = ct;
            bad[i] ^= 1;
            let other = sk
                .decapsulate(&bad)
                .unwrap_or_else(|e| panic!("byte {i}: {e}"));
            assert_ne!(*other, *ss, "byte {i}");
        }
        // X25519 half: a flipped point may be refused (low order) or give
        // another secret, never the original one.
        for i in [MLKEM_CT_LEN, CT_LEN - 1] {
            let mut bad = ct;
            bad[i] ^= 1;
            if let Ok(other) = sk.decapsulate(&bad) {
                assert_ne!(*other, *ss, "byte {i}");
            }
        }
    }

    #[test]
    fn kem_bad_lengths() {
        let sk = KemSecret::generate().unwrap();
        let pk = sk.public();
        let (ct, _) = encapsulate(&pk).unwrap();
        for bad in [&[][..], &ct[..1599], &ct[..1568], &[0u8; 1601][..]] {
            assert!(sk.decapsulate(bad).is_err());
        }
        let b = pk.to_bytes();
        for bad in [&[][..], &b[..1599], &b[..1568], &[0u8; 1601][..]] {
            assert!(KemPublic::from_bytes(bad).is_err());
        }
    }

    #[test]
    fn wrong_recipient_gets_another_secret() {
        let sk = KemSecret::generate().unwrap();
        let other = KemSecret::generate().unwrap();
        let (ct, ss) = encapsulate(&sk.public()).unwrap();
        if let Ok(o) = other.decapsulate(&ct) {
            assert_ne!(*o, *ss);
        }
    }

    #[test]
    fn deterministic_is_reproducible() {
        let sk = KemSecret::from_seeds(&[1u8; 64], &[2u8; 32]).unwrap();
        let sk2 = KemSecret::from_seeds(&[1u8; 64], &[2u8; 32]).unwrap();
        assert!(sk.public() == sk2.public());
        let a = encapsulate_deterministic(&sk.public(), &[3u8; 32], &[4u8; 32]).unwrap();
        let b = encapsulate_deterministic(&sk.public(), &[3u8; 32], &[4u8; 32]).unwrap();
        assert_eq!(a.0, b.0);
        assert_eq!(*a.1, *b.1);
        let c = encapsulate_deterministic(&sk.public(), &[3u8; 32], &[5u8; 32]).unwrap();
        assert_ne!(a.0, c.0);
        assert_ne!(*a.1, *c.1);
    }

    #[test]
    fn deterministic_encaps_decapsulated_by_aws_secret() {
        // The public key of an aws-lc generated secret, deterministic encaps.
        let sk = KemSecret::generate().unwrap();
        let (ct, ss) = encapsulate_deterministic(&sk.public(), &[9u8; 32], &[8u8; 32]).unwrap();
        assert_eq!(*sk.decapsulate(&ct).unwrap(), *ss);
    }

    #[test]
    fn aws_encaps_decapsulated_by_seeded_secret() {
        // A libcrux seeded key pair, loaded and used through aws-lc.
        let sk = KemSecret::from_seeds(&[7u8; 64], &[6u8; 32]).unwrap();
        let (ct, ss) = encapsulate(&sk.public()).unwrap();
        assert_eq!(*sk.decapsulate(&ct).unwrap(), *ss);
    }

    #[test]
    fn combiner_matches_spec() {
        // Recompute spec 6.2 by hand from the parts of a deterministic run.
        let sk = KemSecret::from_seeds(&[11u8; 64], &[12u8; 32]).unwrap();
        let pk = sk.public();
        let (ct, ss) = encapsulate_deterministic(&pk, &[13u8; 32], &[14u8; 32]).unwrap();

        let lx_pk = libcrux_ml_kem::mlkem1024::MlKem1024PublicKey::try_from(&pk.to_bytes()[..1568])
            .unwrap();
        let (lx_ct, ss_m) = libcrux_ml_kem::mlkem1024::encapsulate(&lx_pk, [13u8; 32]);
        assert_eq!(&ct[..1568], lx_ct.as_slice());
        let e = PrivateKey::from_private_key(&X25519, &[14u8; 32]).unwrap();
        assert_eq!(&ct[1568..], e.compute_public_key().unwrap().as_ref());
        let ss_x = agreement::agree(&e, UnparsedPublicKey::new(&X25519, pk_x(&pk)), (), |s| {
            Ok(s.to_vec())
        })
        .unwrap();

        let mut ikm = ss_m.to_vec();
        ikm.extend_from_slice(&ss_x);
        let mut h = digest::Context::new(&SHA256);
        h.update(&ct);
        h.update(&pk_x(&pk));
        let info = h.finish();
        let want = crate::kdf::hkdf32(KEM_LABEL, &ikm, info.as_ref()).unwrap();
        assert_eq!(*ss, *want);
    }
}
