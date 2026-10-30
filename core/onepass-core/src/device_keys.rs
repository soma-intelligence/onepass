//! Per-device hybrid keys: ML-DSA-87 + Ed25519 for signing, ML-KEM-1024 +
//! X25519 for key delivery. The post-quantum half sits behind
//! [`PqDeviceHalf`] because on Apple it lives in the Secure Enclave and its
//! secret never crosses into Rust bytes. The classical halves are plain
//! 32-byte secrets held here.
//!
//! Outputs are byte-compatible with the account keys: a split signature
//! verifies under `HybridVerifyingKey::verify`, and a `wrap_key_labeled`
//! envelope opens with [`DeviceKeys::unwrap_key_labeled`].

use std::fmt;

use aws_lc_rs::digest::{self, SHA256};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto::SymmetricKey;
use crate::crypto::kem::{self, HybridKemPublic};
use crate::crypto::random::fill_random;
use crate::crypto::sign::{
    self, HybridSignature, HybridVerifyingKey, MLDSA_PUBLIC_LEN, MLDSA_SIG_LEN,
};
use crate::{Error, Id, Result};

/// Signature domain of the proof of possession of a device key.
pub const DEVICE_POP_DOMAIN: &[u8] = b"onepass/device-pop/v1";
/// Hash prefix of the device fingerprint.
const DEVICE_FPR_PREFIX: &[u8] = b"onepass/device-fpr/v1";

const CLASSICAL_VERSION: u8 = 1;
const CLASSICAL_LEN: usize = 1 + 32 + 32;
const MLDSA_SEED_LEN: usize = 32;
const MLKEM_SECRET_LEN: usize = 3168;
const MLKEM_SHARED_LEN: usize = 32;

/// The post-quantum half of a device's keys. Pure ML-DSA-87 with an empty
/// context, and FIPS 203 ML-KEM-1024. The Apple app implements it with the
/// Secure Enclave; [`SoftwarePqHalf`] with aws-lc.
pub trait PqDeviceHalf: Send + Sync {
    /// ML-DSA-87 public key, 2592 bytes.
    fn mldsa_public(&self) -> Result<Vec<u8>>;
    /// ML-KEM-1024 encapsulation key, 1568 bytes.
    fn mlkem_public(&self) -> Result<Vec<u8>>;
    /// Pure ML-DSA-87 signature (empty context) over `message`, 4627 bytes.
    fn mldsa_sign(&self, message: &[u8]) -> Result<Vec<u8>>;
    /// FIPS 203 decapsulation: the 32-byte shared secret of `ciphertext`.
    fn mlkem_decapsulate(&self, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>>;
}

/// Software post-quantum half, for the CLI, tests and Apple devices
/// without a Secure Enclave.
pub struct SoftwarePqHalf {
    mldsa_seed: Zeroizing<[u8; MLDSA_SEED_LEN]>,
    /// FIPS 203 decapsulation key, 3168 bytes.
    mlkem: Zeroizing<Vec<u8>>,
}

impl SoftwarePqHalf {
    pub fn generate() -> Result<SoftwarePqHalf> {
        let mut mldsa_seed = Zeroizing::new([0u8; MLDSA_SEED_LEN]);
        fill_random(&mut *mldsa_seed)?;
        Ok(SoftwarePqHalf {
            mldsa_seed,
            mlkem: kem::mlkem_generate()?,
        })
    }

    /// `mldsa_seed (32) || mlkem decapsulation key (3168)`.
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(MLDSA_SEED_LEN + MLKEM_SECRET_LEN));
        out.extend_from_slice(&*self.mldsa_seed);
        out.extend_from_slice(&self.mlkem);
        out
    }

    pub fn from_bytes(b: &[u8]) -> Result<SoftwarePqHalf> {
        if b.len() != MLDSA_SEED_LEN + MLKEM_SECRET_LEN {
            return Err(Error::InvalidFormat("device pq key length"));
        }
        let (seed, dk) = b.split_at(MLDSA_SEED_LEN);
        sign::mldsa_from_seed(seed).map_err(|_| Error::InvalidFormat("device pq key"))?;
        kem::mlkem_check_secret(dk)?;
        let mut mldsa_seed = Zeroizing::new([0u8; MLDSA_SEED_LEN]);
        mldsa_seed.copy_from_slice(seed);
        Ok(SoftwarePqHalf {
            mldsa_seed,
            mlkem: Zeroizing::new(dk.to_vec()),
        })
    }
}

impl PqDeviceHalf for SoftwarePqHalf {
    fn mldsa_public(&self) -> Result<Vec<u8>> {
        use aws_lc_rs::signature::KeyPair;
        Ok(sign::mldsa_from_seed(&*self.mldsa_seed)?
            .public_key()
            .as_ref()
            .to_vec())
    }

    fn mlkem_public(&self) -> Result<Vec<u8>> {
        kem::mlkem_check_secret(&self.mlkem)
    }

    fn mldsa_sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let mut sig = vec![0u8; MLDSA_SIG_LEN];
        let n = sign::mldsa_from_seed(&*self.mldsa_seed)?
            .sign(message, &mut sig)
            .map_err(|_| Error::Crypto)?;
        sig.truncate(n);
        Ok(sig)
    }

    fn mlkem_decapsulate(&self, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        kem::mlkem_decapsulate(&self.mlkem, ciphertext)
    }
}

impl fmt::Debug for SoftwarePqHalf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SoftwarePqHalf(**)")
    }
}

/// Ed25519 seed and X25519 secret.
struct ClassicalDeviceKeys {
    ed25519: Zeroizing<[u8; 32]>,
    x25519: Zeroizing<[u8; 32]>,
}

/// A device's signing and KEM keys. Not `Clone`, and no whole-key
/// serialization: the post-quantum secret is never exported as bytes.
pub struct DeviceKeys {
    classical: ClassicalDeviceKeys,
    pq: Box<dyn PqDeviceHalf>,
}

impl DeviceKeys {
    /// Fully software keys.
    pub fn generate_software() -> Result<DeviceKeys> {
        DeviceKeys::new(
            &DeviceKeys::generate_classical()?,
            Box::new(SoftwarePqHalf::generate()?),
        )
    }

    /// Fresh classical halves in the layout `classical_bytes` returns.
    pub fn generate_classical() -> Result<Zeroizing<Vec<u8>>> {
        let mut out = Zeroizing::new(vec![0u8; CLASSICAL_LEN]);
        out[0] = CLASSICAL_VERSION;
        fill_random(&mut out[1..]).map_err(|_| Error::Crypto)?;
        Ok(out)
    }

    /// Classical halves from `classical_bytes` plus a post-quantum half.
    pub fn new(classical: &[u8], pq: Box<dyn PqDeviceHalf>) -> Result<DeviceKeys> {
        if classical.len() != CLASSICAL_LEN || classical[0] != CLASSICAL_VERSION {
            return Err(Error::InvalidFormat("device classical key"));
        }
        let mut ed25519 = Zeroizing::new([0u8; 32]);
        let mut x25519 = Zeroizing::new([0u8; 32]);
        ed25519.copy_from_slice(&classical[1..33]);
        x25519.copy_from_slice(&classical[33..]);
        sign::ed25519_public_of(&ed25519)
            .map_err(|_| Error::InvalidFormat("device classical key"))?;
        kem::x25519_public_of(&x25519).map_err(|_| Error::InvalidFormat("device classical key"))?;
        Ok(DeviceKeys {
            classical: ClassicalDeviceKeys { ed25519, x25519 },
            pq,
        })
    }

    /// `version (1) || ed25519 seed (32) || x25519 secret (32)`.
    pub fn classical_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(CLASSICAL_LEN));
        out.push(CLASSICAL_VERSION);
        out.extend_from_slice(&*self.classical.ed25519);
        out.extend_from_slice(&*self.classical.x25519);
        out
    }

    pub fn public(&self, device_id: Id) -> Result<DevicePublic> {
        let mldsa = self.pq.mldsa_public()?;
        let mlkem = self.pq.mlkem_public()?;
        if mldsa.len() != MLDSA_PUBLIC_LEN || mlkem.len() != kem::MLKEM_PUBLIC_LEN {
            return Err(Error::Crypto);
        }
        Ok(DevicePublic {
            device_id,
            sign_pub: HybridVerifyingKey {
                mldsa,
                ed25519: sign::ed25519_public_of(&self.classical.ed25519)?,
            },
            kem_pub: HybridKemPublic {
                mlkem,
                x25519: kem::x25519_public_of(&self.classical.x25519)?,
            },
        })
    }

    /// Hybrid signature over the framed message, `HybridSignature` as any
    /// other: the ML-DSA half comes from the post-quantum half.
    pub fn sign(&self, domain: &[u8], msg: &[u8]) -> Result<HybridSignature> {
        let m = sign::signed_message(domain, msg)?;
        let mldsa = self.pq.mldsa_sign(&m)?;
        if mldsa.len() != MLDSA_SIG_LEN {
            return Err(Error::Crypto);
        }
        let ed25519 = sign::ed25519_sign(&self.classical.ed25519, &m)?;
        Ok(HybridSignature { mldsa, ed25519 })
    }

    /// Open a `wrap_key_labeled` envelope addressed to this device.
    pub fn unwrap_key_labeled(
        &self,
        label: &[u8],
        context: &[u8],
        blob: &[u8],
    ) -> Result<SymmetricKey> {
        kem::unwrap_key_labeled_split(&self.classical.x25519, blob, label, context, |ct| {
            let ss = self.pq.mlkem_decapsulate(ct)?;
            if ss.len() != MLKEM_SHARED_LEN {
                return Err(Error::Crypto);
            }
            Ok(ss)
        })
    }
}

impl fmt::Debug for DeviceKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DeviceKeys(**)")
    }
}

/// What the other devices pin about a device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DevicePublic {
    pub device_id: Id,
    pub sign_pub: HybridVerifyingKey,
    pub kem_pub: HybridKemPublic,
}

impl DevicePublic {
    /// Canonical postcard encoding.
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("device public encodes")
    }

    /// Strict: the whole buffer, key lengths, a parsable ML-KEM key and a
    /// canonical re-encoding equal to the input.
    pub fn decode(b: &[u8]) -> Result<DevicePublic> {
        const BAD: Error = Error::InvalidFormat("device public");
        let (public, rest) = postcard::take_from_bytes::<DevicePublic>(b).map_err(|_| BAD)?;
        if !rest.is_empty() || public.sign_pub.mldsa.len() != MLDSA_PUBLIC_LEN {
            return Err(BAD);
        }
        HybridKemPublic::from_bytes(&public.kem_pub.to_bytes()).map_err(|_| BAD)?;
        if public.encode() != b {
            return Err(BAD);
        }
        Ok(public)
    }

    /// `SHA-256("onepass/device-fpr/v1" || postcard(self))`.
    pub fn fingerprint(&self) -> [u8; 32] {
        let mut ctx = digest::Context::new(&SHA256);
        ctx.update(DEVICE_FPR_PREFIX);
        ctx.update(&self.encode());
        let mut out = [0u8; 32];
        out.copy_from_slice(ctx.finish().as_ref());
        out
    }
}

/// `postcard((context, public))`, the message of a proof of possession.
fn pop_message(context: &[u8], public: &DevicePublic) -> Result<Vec<u8>> {
    postcard::to_allocvec(&(serde_bytes::Bytes::new(context), public))
        .map_err(|_| Error::InvalidFormat("device pop"))
}

/// The device signs its own public keys together with `context` (a
/// pairing transcript hash or an account id).
pub fn sign_pop(
    keys: &DeviceKeys,
    context: &[u8],
    public: &DevicePublic,
) -> Result<HybridSignature> {
    keys.sign(DEVICE_POP_DOMAIN, &pop_message(context, public)?)
}

pub fn verify_pop(context: &[u8], public: &DevicePublic, sig: &HybridSignature) -> Result<()> {
    public
        .sign_pub
        .verify(DEVICE_POP_DOMAIN, &pop_message(context, public)?, sig)
}

#[cfg(test)]
mod tests {
    use zeroize::Zeroizing;

    use super::*;
    use crate::crypto::kem::wrap_key_labeled;
    use crate::crypto::{HybridSignature, SymmetricKey};
    use crate::{Error, Id, IntegrityError, Result};

    const LABEL: &[u8] = b"onepass/rotation/secret-key/v1";

    fn keys() -> (DeviceKeys, Zeroizing<Vec<u8>>) {
        let classical = DeviceKeys::generate_classical().unwrap();
        let pq = SoftwarePqHalf::generate().unwrap();
        let pq_bytes = pq.to_bytes();
        (DeviceKeys::new(&classical, Box::new(pq)).unwrap(), pq_bytes)
    }

    fn sha256(b: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, b).as_ref());
        out
    }

    /// A foreign half that returns fixed, wrong-sized outputs.
    struct BadLengths;

    impl PqDeviceHalf for BadLengths {
        fn mldsa_public(&self) -> Result<Vec<u8>> {
            Ok(vec![0; 2592])
        }
        fn mlkem_public(&self) -> Result<Vec<u8>> {
            Ok(vec![0; 1568])
        }
        fn mldsa_sign(&self, _message: &[u8]) -> Result<Vec<u8>> {
            Ok(vec![0; 10])
        }
        fn mlkem_decapsulate(&self, _ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
            Ok(Zeroizing::new(vec![0; 31]))
        }
    }

    /// A foreign half that fails on every call.
    struct Failing;

    impl PqDeviceHalf for Failing {
        fn mldsa_public(&self) -> Result<Vec<u8>> {
            Err(Error::Crypto)
        }
        fn mlkem_public(&self) -> Result<Vec<u8>> {
            Err(Error::Crypto)
        }
        fn mldsa_sign(&self, _message: &[u8]) -> Result<Vec<u8>> {
            Err(Error::Crypto)
        }
        fn mlkem_decapsulate(&self, _ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
            Err(Error::Crypto)
        }
    }

    #[test]
    fn round_trip() {
        let (k, pq_bytes) = keys();
        let id = Id::new();
        let again = DeviceKeys::new(
            &k.classical_bytes(),
            Box::new(SoftwarePqHalf::from_bytes(&pq_bytes).unwrap()),
        )
        .unwrap();
        assert_eq!(again.public(id).unwrap(), k.public(id).unwrap());
    }

    #[test]
    fn split_signature_verifies_as_hybrid() {
        let (k, _) = keys();
        let public = k.public(Id::new()).unwrap();
        let sig = k.sign(b"some/domain", b"message").unwrap();
        public
            .sign_pub
            .verify(b"some/domain", b"message", &sig)
            .unwrap();
        assert_eq!(
            public.sign_pub.verify(b"some/domain", b"messagf", &sig),
            Err(Error::Integrity(IntegrityError::Signature))
        );
    }

    #[test]
    fn split_unwrap_matches_kem() {
        let (k, _) = keys();
        let public = k.public(Id::new()).unwrap();
        let key = SymmetricKey::generate().unwrap();
        let blob = wrap_key_labeled(&public.kem_pub, &key, LABEL, b"ctx").unwrap();
        let out = k.unwrap_key_labeled(LABEL, b"ctx", &blob).unwrap();
        assert_eq!(out.expose(), key.expose());
        assert!(k.unwrap_key_labeled(b"other/label", b"ctx", &blob).is_err());
        assert!(k.unwrap_key_labeled(LABEL, b"other", &blob).is_err());
    }

    #[test]
    fn foreign_signature_of_wrong_length_refused() {
        let k = DeviceKeys::new(
            &DeviceKeys::generate_classical().unwrap(),
            Box::new(BadLengths),
        )
        .unwrap();
        assert!(matches!(k.sign(b"d", b"m"), Err(Error::Crypto)));
        let (real, _) = keys();
        let public = real.public(Id::new()).unwrap();
        let blob = wrap_key_labeled(
            &public.kem_pub,
            &SymmetricKey::generate().unwrap(),
            LABEL,
            b"c",
        )
        .unwrap();
        assert!(matches!(
            k.unwrap_key_labeled(LABEL, b"c", &blob),
            Err(Error::Crypto)
        ));
    }

    #[test]
    fn foreign_error_surfaces() {
        let k = DeviceKeys::new(
            &DeviceKeys::generate_classical().unwrap(),
            Box::new(Failing),
        )
        .unwrap();
        assert!(matches!(k.public(Id::new()), Err(Error::Crypto)));
        assert!(matches!(k.sign(b"d", b"m"), Err(Error::Crypto)));
        let (real, _) = keys();
        let public = real.public(Id::new()).unwrap();
        let blob = wrap_key_labeled(
            &public.kem_pub,
            &SymmetricKey::generate().unwrap(),
            LABEL,
            b"c",
        )
        .unwrap();
        assert!(matches!(
            k.unwrap_key_labeled(LABEL, b"c", &blob),
            Err(Error::Crypto)
        ));
    }

    #[test]
    fn classical_bytes_hold_no_pq_secret() {
        let (k, _) = keys();
        assert_eq!(k.classical_bytes().len(), 1 + 32 + 32);
    }

    #[test]
    fn public_decode_is_strict() {
        let (k, _) = keys();
        let public = k.public(Id::new()).unwrap();
        let enc = public.encode();
        assert_eq!(DevicePublic::decode(&enc).unwrap(), public);
        assert!(matches!(
            DevicePublic::decode(&[enc.clone(), vec![0]].concat()),
            Err(Error::InvalidFormat(_))
        ));
        assert!(matches!(
            DevicePublic::decode(&enc[..enc.len() - 1]),
            Err(Error::InvalidFormat(_))
        ));
        assert!(matches!(
            DevicePublic::decode(&[]),
            Err(Error::InvalidFormat(_))
        ));
    }

    #[test]
    fn public_with_wrong_key_length_refused() {
        let (k, _) = keys();
        let mut public = k.public(Id::new()).unwrap();
        public.sign_pub.mldsa.pop();
        let enc = postcard::to_allocvec(&public).unwrap();
        assert!(matches!(
            DevicePublic::decode(&enc),
            Err(Error::InvalidFormat(_))
        ));
    }

    #[test]
    fn fingerprint_is_domain_separated() {
        let (k, _) = keys();
        let public = k.public(Id::new()).unwrap();
        let body = postcard::to_allocvec(&public).unwrap();
        let expected = sha256(&[b"onepass/device-fpr/v1".as_slice(), &body].concat());
        assert_eq!(public.fingerprint(), expected);
        assert_ne!(public.fingerprint(), sha256(&body));
    }

    #[test]
    fn pop_verifies() {
        let (k, _) = keys();
        let public = k.public(Id::new()).unwrap();
        let sig = sign_pop(&k, b"transcript-hash", &public).unwrap();
        verify_pop(b"transcript-hash", &public, &sig).unwrap();
    }

    #[test]
    fn pop_other_context_refused() {
        let (k, _) = keys();
        let public = k.public(Id::new()).unwrap();
        let sig = sign_pop(&k, b"transcript-hash", &public).unwrap();
        assert_eq!(
            verify_pop(b"other-transcript", &public, &sig),
            Err(Error::Integrity(IntegrityError::Signature))
        );
    }

    #[test]
    fn pop_other_domain_refused() {
        let (k, _) = keys();
        let public = k.public(Id::new()).unwrap();
        let msg = postcard::to_allocvec(&(b"transcript-hash".as_slice(), &public)).unwrap();
        let sig: HybridSignature = k.sign(b"onepass/device-intro/v1", &msg).unwrap();
        assert_eq!(
            verify_pop(b"transcript-hash", &public, &sig),
            Err(Error::Integrity(IntegrityError::Signature))
        );
        let ok = k.sign(DEVICE_POP_DOMAIN, &msg).unwrap();
        verify_pop(b"transcript-hash", &public, &ok).unwrap();
    }
}
