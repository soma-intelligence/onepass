//! Frozen seed-to-key derivation (crypto review, F2).
//!
//! The keyset stores seeds (ML-DSA-87, Ed25519, SLH-DSA) and raw keys
//! (ML-KEM-1024, X25519); unlock recomputes the public keys and compares them
//! to the signed account parameters. If a dependency update changed a
//! derivation, every account would fail to unlock. These tests pin the public
//! keys of fixed seeds, as published vectors where they exist (RFC 8032,
//! RFC 7748) and otherwise as hex checked against an independent
//! implementation (libcrux for ML-DSA and ML-KEM, the `slh-dsa` 0.2 release
//! candidate for SLH-DSA). Long keys are pinned by their SHA-256.
//!
//! NIST ACVP `SLH-DSA-keyGen-FIPS205` and `SLH-DSA-sigGen-FIPS205` vectors for
//! SLH-DSA-SHA2-256s are not included: the only offline copies (the sample
//! files shipped in the `slh-dsa` 0.1.0 crate) cover other parameter sets.

use aws_lc_rs::agreement::{PrivateKey, X25519};
use aws_lc_rs::digest::{SHA256, digest};
use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair, ML_DSA_87_SIGNING, PqdsaKeyPair};
use data_encoding::HEXLOWER;
use onepass_core::crypto::{HybridKemSecret, HybridSigningKey, IdentityKey, IdentityVerifyingKey};

use libcrux_ml_dsa::ml_dsa_87 as lx_dsa;
use libcrux_ml_kem::mlkem1024 as lx_kem;
use slh_dsa_next::{Sha2_256s, SigningKey as NextSigningKey, VerifyingKey as NextVerifyingKey};

fn hex(s: &str) -> Vec<u8> {
    HEXLOWER.decode(s.as_bytes()).unwrap()
}

fn sha256_hex(b: &[u8]) -> String {
    HEXLOWER.encode(digest(&SHA256, b).as_ref())
}

/// `start, start + 1, ...` (wrapping), a fixed synthetic seed.
fn counting<const N: usize>(start: u8) -> [u8; N] {
    let mut s = [0u8; N];
    for (i, b) in s.iter_mut().enumerate() {
        *b = start.wrapping_add(i as u8);
    }
    s
}

/// RFC 8032, section 7.1, tests 1 and 2: (secret seed, public key).
const ED25519_RFC8032: [(&str, &str); 2] = [
    (
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    ),
    (
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
    ),
];

/// RFC 7748, section 6.1: Alice's and Bob's (private, public) keys.
const X25519_RFC7748: [(&str, &str); 2] = [
    (
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
        "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
    ),
    (
        "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
        "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
    ),
];

/// SHA-256 of the ML-DSA-87 public key of `counting::<32>(0)`.
const MLDSA87_PK_SHA256: &str = "91dc389cfaa01470b7f66eee45a4ae9026d154817c754dfe22298b3fa241ffcd";

/// SHA-256 of the ML-KEM-1024 encapsulation key and decapsulation key of the
/// FIPS 203 key-generation seed `d || z = counting::<64>(0x40)`.
const MLKEM1024_EK_SHA256: &str =
    "b88cea32bb54ed0f4224e9a3d9256a636505c22e339d1e1dbba7307a82823bc0";
const MLKEM1024_DK_SHA256: &str =
    "e0f8b33a49e31ddd6fb7ebda01d3ab85c11c183d054f66b3cda7573b9910eb2e";

/// SLH-DSA-SHA2-256s public key `pk_seed || pk_root` of
/// `sk_seed || sk_prf || pk_seed = counting::<96>(0x80)`.
const SLHDSA_PK: &str = concat!(
    "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf",
    "96f5576ce0c7b1c9b815b435918aafb1cfb296a11d1e72b67823a001e63bd0fd",
);

#[test]
fn ed25519_from_seed_matches_rfc8032() {
    for (seed, public) in ED25519_RFC8032 {
        let seed = hex(seed);
        let kp = Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
        assert_eq!(kp.public_key().as_ref(), &hex(public)[..]);
        // Through the keyset encoding: `mldsa_seed || ed25519_seed`.
        let key = HybridSigningKey::from_bytes(&[&counting::<32>(0)[..], &seed].concat()).unwrap();
        assert_eq!(&key.verifying_key().unwrap().ed25519[..], &hex(public)[..]);
    }
}

#[test]
fn mldsa87_from_seed_is_pinned_and_matches_libcrux() {
    let seed = counting::<32>(0);
    let aws = PqdsaKeyPair::from_seed(&ML_DSA_87_SIGNING, &seed).unwrap();
    let aws_pk = aws.public_key().as_ref().to_vec();
    assert_eq!(aws_pk.len(), 2592);
    let lx = lx_dsa::generate_key_pair(seed);
    assert_eq!(
        &aws_pk[..],
        lx.verification_key.as_ref(),
        "aws-lc vs libcrux"
    );
    assert_eq!(sha256_hex(&aws_pk), MLDSA87_PK_SHA256);
    let ed_seed = hex(ED25519_RFC8032[0].0);
    let key = HybridSigningKey::from_bytes(&[&seed[..], &ed_seed].concat()).unwrap();
    assert_eq!(key.verifying_key().unwrap().mldsa, aws_pk);
}

#[test]
fn x25519_public_matches_rfc7748() {
    let mlkem = lx_kem::generate_key_pair(counting::<64>(0x40));
    for (private, public) in X25519_RFC7748 {
        let private = hex(private);
        let key = PrivateKey::from_private_key(&X25519, &private).unwrap();
        assert_eq!(key.compute_public_key().unwrap().as_ref(), &hex(public)[..]);
        // Through the keyset encoding: `mlkem_dk (3168) || x25519 (32)`.
        let sk =
            HybridKemSecret::from_bytes(&[mlkem.sk().as_ref(), &private[..]].concat()).unwrap();
        assert_eq!(&sk.public().unwrap().x25519[..], &hex(public)[..]);
    }
}

#[test]
fn mlkem1024_keyset_public_is_pinned_and_matches_libcrux() {
    // The keyset stores the decapsulation key itself, not a seed: what must
    // not drift is reading the encapsulation key out of it (FIPS 203 layout).
    let pair = lx_kem::generate_key_pair(counting::<64>(0x40));
    let dk = pair.sk().as_ref();
    let ek = pair.pk().as_ref();
    assert_eq!(sha256_hex(ek), MLKEM1024_EK_SHA256);
    assert_eq!(sha256_hex(dk), MLKEM1024_DK_SHA256);
    let x25519 = hex(X25519_RFC7748[0].0);
    let sk = HybridKemSecret::from_bytes(&[dk, &x25519[..]].concat()).unwrap();
    assert_eq!(&sk.public().unwrap().mlkem[..], ek);
}

#[test]
fn slhdsa_keygen_is_pinned_and_matches_next() {
    let seeds = counting::<96>(0x80);
    let (sk_seed, rest) = seeds.split_at(32);
    let (sk_prf, pk_seed) = rest.split_at(32);
    let next = NextSigningKey::<Sha2_256s>::slh_keygen_internal(sk_seed, sk_prf, pk_seed);
    let next_pk = AsRef::<NextVerifyingKey<Sha2_256s>>::as_ref(&next).to_bytes();
    assert_eq!(HEXLOWER.encode(&next_pk), SLHDSA_PK, "slh-dsa 0.2 keyGen");
    // `IdentityKey::from_bytes` recomputes `pk_root` from the seeds with
    // slh-dsa 0.1 and refuses a mismatch.
    let encoded = [&seeds[..], &next_pk[32..]].concat();
    let id = IdentityKey::from_bytes(&encoded).unwrap();
    assert_eq!(id.verifying_key(), identity_public(&next_pk));
    assert_eq!(&id.to_bytes()[..], &encoded[..]);
    // A wrong root is refused, so the comparison above is meaningful.
    let mut wrong = encoded.clone();
    wrong[127] ^= 1;
    assert!(IdentityKey::from_bytes(&wrong).is_err());
}

/// `IdentityVerifyingKey` from its 64 raw bytes (postcard: length, bytes).
fn identity_public(pk: &[u8]) -> IdentityVerifyingKey {
    let mut enc = vec![u8::try_from(pk.len()).unwrap()];
    enc.extend_from_slice(pk);
    postcard::from_bytes(&enc).unwrap()
}
