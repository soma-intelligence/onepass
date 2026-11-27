//! OPRF of RFC 9497, mode OPRF (0x00), suite ristretto255-SHA512, made
//! threshold (Guarded Kit spec, section 4).
//!
//! Written on `curve25519-dalek` for the group and aws-lc's SHA-512 for the
//! hashes, with `expand_message_xmd` of RFC 9380 for HashToGroup and
//! HashToScalar. Checked against the test vectors of RFC 9497, appendix
//! A.1.1. (The `voprf` crate was tried first: its 0.5 release pulls
//! `elliptic-curve` 0.13 and `crypto-bigint` 0.5, which RUSTSEC-2026-0387
//! flags, for code this suite never runs.)
//!
//! Threshold: the OPRF key `k` is drawn by the registering client and
//! Shamir-shared over the ristretto255 scalar field, so realm `i` holds `k_i`
//! only. A restoring client gets `B * k_i` from T realms and combines them
//! with Lagrange coefficients in the exponent into `B * k`, then finalizes
//! as RFC 9497. No single realm can compute the OPRF, so a realm insider
//! with its share and its tag cannot test passwords offline: it takes T
//! realms.

use aws_lc_rs::digest::{Context, SHA512};
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use zeroize::{Zeroize, Zeroizing};

use super::GuardError;
use crate::crypto::fill_random;

/// Serialized OPRF key length (a ristretto255 scalar).
pub const KEY_LEN: usize = 32;
/// Serialized blinded and evaluated element length.
pub const ELEMENT_LEN: usize = 32;
/// OPRF output length (SHA-512).
pub const OUTPUT_LEN: usize = 64;

/// `"OPRFV1-" || I2OSP(mode = 0, 1) || "-" || "ristretto255-SHA512"`.
const CONTEXT: &[u8] = b"OPRFV1-\x00-ristretto255-SHA512";

fn sha512(parts: &[&[u8]]) -> [u8; 64] {
    let mut c = Context::new(&SHA512);
    for p in parts {
        c.update(p);
    }
    let d = c.finish();
    let mut out = [0u8; 64];
    out.copy_from_slice(d.as_ref());
    out
}

/// `expand_message_xmd` (RFC 9380, 5.3.1) with SHA-512, 64 output bytes
/// (one block: `ell = 1`). DSTs here are always under 256 bytes.
fn expand_xmd_64(msg: &[&[u8]], dst: &[u8]) -> Zeroizing<[u8; 64]> {
    debug_assert!(dst.len() < 256);
    let dst_len = [dst.len() as u8];
    let z_pad = [0u8; 128];
    let mut c = Context::new(&SHA512);
    c.update(&z_pad);
    for m in msg {
        c.update(m);
    }
    c.update(&64u16.to_be_bytes());
    c.update(&[0u8]);
    c.update(dst);
    c.update(&dst_len);
    let b0 = c.finish();
    let b1 = sha512(&[b0.as_ref(), &[1u8], dst, &dst_len]);
    Zeroizing::new(b1)
}

fn hash_to_group(input: &[u8]) -> RistrettoPoint {
    let mut dst = b"HashToGroup-".to_vec();
    dst.extend_from_slice(CONTEXT);
    RistrettoPoint::from_uniform_bytes(&expand_xmd_64(&[input], &dst))
}

fn hash_to_scalar(msg: &[&[u8]], dst: &[u8]) -> Scalar {
    Scalar::from_bytes_mod_order_wide(&expand_xmd_64(msg, dst))
}

fn finalize_hash(
    input: &[u8],
    element: &RistrettoPoint,
) -> Result<Zeroizing<[u8; OUTPUT_LEN]>, GuardError> {
    let len = u16::try_from(input.len()).map_err(|_| GuardError::Config("oprf input length"))?;
    let e = element.compress().to_bytes();
    Ok(Zeroizing::new(sha512(&[
        &len.to_be_bytes(),
        input,
        &(ELEMENT_LEN as u16).to_be_bytes(),
        &e,
        b"Finalize",
    ])))
}

/// DeserializeElement: a canonical encoding of a point other than the
/// identity.
fn element(bytes: &[u8]) -> Result<RistrettoPoint, GuardError> {
    let b: [u8; ELEMENT_LEN] = bytes
        .try_into()
        .map_err(|_| GuardError::Malformed("element"))?;
    let p = CompressedRistretto(b)
        .decompress()
        .ok_or(GuardError::Malformed("element"))?;
    if p == RistrettoPoint::identity() {
        return Err(GuardError::Malformed("element"));
    }
    Ok(p)
}

/// A canonical, nonzero scalar.
fn key_scalar(bytes: &[u8; KEY_LEN]) -> Result<Scalar, GuardError> {
    let s = Option::<Scalar>::from(Scalar::from_canonical_bytes(*bytes))
        .ok_or(GuardError::Malformed("oprf key"))?;
    if s == Scalar::ZERO {
        return Err(GuardError::Malformed("oprf key"));
    }
    Ok(s)
}

fn random_scalar() -> Result<Scalar, GuardError> {
    loop {
        let mut wide = Zeroizing::new([0u8; 64]);
        fill_random(wide.as_mut_slice()).map_err(|_| GuardError::Crypto)?;
        let s = Scalar::from_bytes_mod_order_wide(&wide);
        if s != Scalar::ZERO {
            return Ok(s);
        }
    }
}

/// Client state between blinding and finalizing.
pub struct Blinded {
    blind: Scalar,
    /// The blinded element to send.
    pub message: [u8; ELEMENT_LEN],
}

impl Drop for Blinded {
    fn drop(&mut self) {
        self.blind.zeroize();
    }
}

fn blind_with(input: &[u8], blind: Scalar) -> Result<Blinded, GuardError> {
    let p = hash_to_group(input);
    if p == RistrettoPoint::identity() {
        return Err(GuardError::Crypto);
    }
    Ok(Blinded {
        message: (p * blind).compress().to_bytes(),
        blind,
    })
}

/// Blind `input` (RFC 9497 Blind) under a fresh random blind.
pub fn blind(input: &[u8]) -> Result<Blinded, GuardError> {
    blind_with(input, random_scalar()?)
}

impl Blinded {
    /// Unblind the evaluation into the OPRF output of `input` (RFC 9497
    /// Finalize).
    pub fn finalize(
        &self,
        input: &[u8],
        evaluation: &[u8],
    ) -> Result<Zeroizing<[u8; OUTPUT_LEN]>, GuardError> {
        let z = element(evaluation)?;
        finalize_hash(input, &(z * self.blind.invert()))
    }
}

/// A fresh, nonzero OPRF key.
pub fn new_key() -> Result<Zeroizing<[u8; KEY_LEN]>, GuardError> {
    Ok(Zeroizing::new(random_scalar()?.to_bytes()))
}

/// RFC 9497 DeriveKeyPair (secret key only). Used by the test vectors.
pub fn derive_key(seed: &[u8; 32], info: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>, GuardError> {
    let info_len = u16::try_from(info.len()).map_err(|_| GuardError::Config("info length"))?;
    let mut dst = b"DeriveKeyPair".to_vec();
    dst.extend_from_slice(CONTEXT);
    for counter in 0..=255u8 {
        let s = hash_to_scalar(&[seed, &info_len.to_be_bytes(), info, &[counter]], &dst);
        if s != Scalar::ZERO {
            return Ok(Zeroizing::new(s.to_bytes()));
        }
    }
    Err(GuardError::Crypto)
}

/// One realm's share of the OPRF key: its index (1 to 255) and `k_i`.
pub struct KeyShare {
    pub index: u8,
    pub key: Zeroizing<[u8; KEY_LEN]>,
}

/// Shamir-share `key` over the scalar field, `threshold` of `n`. Every
/// share is nonzero (a zero share would be refused by the realm): the
/// polynomial is redrawn in that case, with probability about 2^-252.
pub fn split_key(key: &[u8; KEY_LEN], threshold: u8, n: u8) -> Result<Vec<KeyShare>, GuardError> {
    if threshold < 2 || threshold > n {
        return Err(GuardError::Config("threshold"));
    }
    let k = key_scalar(key)?;
    'draw: loop {
        let mut coeffs = Vec::with_capacity(usize::from(threshold) - 1);
        for _ in 1..threshold {
            coeffs.push(random_scalar()?);
        }
        let mut shares = Vec::with_capacity(usize::from(n));
        for i in 1..=n {
            let x = Scalar::from(u64::from(i));
            // Horner over c_{t-1} .. c_1, then the constant term k.
            let mut acc = Scalar::ZERO;
            for c in coeffs.iter().rev() {
                acc = (acc + c) * x;
            }
            let ki = acc + k;
            if ki == Scalar::ZERO {
                coeffs.iter_mut().for_each(Zeroize::zeroize);
                continue 'draw;
            }
            shares.push(KeyShare {
                index: i,
                key: Zeroizing::new(ki.to_bytes()),
            });
        }
        coeffs.iter_mut().for_each(Zeroize::zeroize);
        return Ok(shares);
    }
}

/// Lagrange coefficient at 0 of `index` among `indices`.
fn lagrange_at_zero(index: u8, indices: &[u8]) -> Scalar {
    let xi = Scalar::from(u64::from(index));
    let mut num = Scalar::ONE;
    let mut den = Scalar::ONE;
    for &j in indices {
        if j != index {
            let xj = Scalar::from(u64::from(j));
            num *= xj;
            den *= xj - xi;
        }
    }
    num * den.invert()
}

/// Combine the evaluations `(index, B * k_i)` of distinct realms into
/// `B * k`. With fewer than the threshold, the result is a wrong element
/// and every tag check fails.
pub fn combine_evaluations(
    evals: &[(u8, [u8; ELEMENT_LEN])],
) -> Result<[u8; ELEMENT_LEN], GuardError> {
    let indices: Vec<u8> = evals.iter().map(|(i, _)| *i).collect();
    for (n, i) in indices.iter().enumerate() {
        if *i == 0 || indices[..n].contains(i) {
            return Err(GuardError::Config("evaluation indices"));
        }
    }
    let mut sum = RistrettoPoint::identity();
    for (i, e) in evals {
        sum += element(e)? * lagrange_at_zero(*i, &indices);
    }
    Ok(sum.compress().to_bytes())
}

/// The OPRF output of `input` under the whole key `k` (RFC 9497 Evaluate,
/// by the registering client, which knows `k` until the shares are sent).
pub fn evaluate_full(
    key: &[u8; KEY_LEN],
    input: &[u8],
) -> Result<Zeroizing<[u8; OUTPUT_LEN]>, GuardError> {
    let k = key_scalar(key)?;
    let p = hash_to_group(input);
    if p == RistrettoPoint::identity() {
        return Err(GuardError::Crypto);
    }
    finalize_hash(input, &(p * k))
}

/// Evaluate a blinded element under `key` or a key share (realm side, RFC
/// 9497 BlindEvaluate).
pub fn evaluate(key: &[u8; KEY_LEN], blinded: &[u8]) -> Result<[u8; ELEMENT_LEN], GuardError> {
    let k = key_scalar(key)?;
    Ok((element(blinded)? * k).compress().to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        data_encoding::HEXLOWER.decode(s.as_bytes()).unwrap()
    }

    fn arr32(s: &str) -> [u8; 32] {
        hex(s).try_into().unwrap()
    }

    /// RFC 9497 appendix A.1.1 (ristretto255-SHA512, OPRF mode).
    #[test]
    fn rfc9497_vectors() {
        let seed = arr32("a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3");
        let sk = derive_key(&seed, &hex("74657374206b6579")).unwrap();
        assert_eq!(
            sk.as_slice(),
            hex("5ebcea5ee37023ccb9fc2d2019f9d7737be85591ae8652ffa9ef0f4d37063b0e").as_slice()
        );

        // Test vector 1.
        let input = hex("00");
        let blind = Scalar::from_canonical_bytes(arr32(
            "64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706",
        ))
        .unwrap();
        let b = blind_with(&input, blind).unwrap();
        assert_eq!(
            b.message.as_slice(),
            hex("609a0ae68c15a3cf6903766461307e5c8bb2f95e7e6550e1ffa2dc99e412803c").as_slice()
        );
        let ev = evaluate(&sk, &b.message).unwrap();
        assert_eq!(
            ev.as_slice(),
            hex("7ec6578ae5120958eb2db1745758ff379e77cb64fe77b0b2d8cc917ea0869c7e").as_slice()
        );
        let expected = hex(
            "527759c3d9366f277d8c6020418d96bb393ba2afb20ff90df23fb7708264e2f3ab9135e3bd69955851de4b1f9fe8a0973396719b7912ba9ee8aa7d0b5e24bcf6",
        );
        assert_eq!(
            b.finalize(&input, &ev).unwrap().as_slice(),
            expected.as_slice()
        );
        assert_eq!(
            evaluate_full(&sk, &input).unwrap().as_slice(),
            expected.as_slice()
        );
    }

    #[test]
    fn round_trip_is_deterministic_per_key() {
        let k = new_key().unwrap();
        let a = blind(b"input").unwrap();
        let b = blind(b"input").unwrap();
        assert_ne!(a.message, b.message, "blinds are fresh");
        let ya = a
            .finalize(b"input", &evaluate(&k, &a.message).unwrap())
            .unwrap();
        assert_eq!(*ya, *evaluate_full(&k, b"input").unwrap());
        let yb = b
            .finalize(b"input", &evaluate(&k, &b.message).unwrap())
            .unwrap();
        assert_eq!(*ya, *yb);

        let c = blind(b"other").unwrap();
        let yc = c
            .finalize(b"other", &evaluate(&k, &c.message).unwrap())
            .unwrap();
        assert_ne!(*ya, *yc);

        let k2 = new_key().unwrap();
        assert_ne!(*ya, *evaluate_full(&k2, b"input").unwrap());
    }

    #[test]
    fn threshold_matches_full_key() {
        let k = new_key().unwrap();
        let shares = split_key(&k, 2, 3).unwrap();
        let full = evaluate_full(&k, b"input").unwrap();
        for (a, b) in [(0usize, 1usize), (0, 2), (2, 1)] {
            let bl = blind(b"input").unwrap();
            let ea = evaluate(&shares[a].key, &bl.message).unwrap();
            let eb = evaluate(&shares[b].key, &bl.message).unwrap();
            let e = combine_evaluations(&[(shares[a].index, ea), (shares[b].index, eb)]).unwrap();
            assert_eq!(*bl.finalize(b"input", &e).unwrap(), *full);
        }
        // One share alone is not the key.
        let bl = blind(b"input").unwrap();
        let e0 = evaluate(&shares[0].key, &bl.message).unwrap();
        let single = combine_evaluations(&[(shares[0].index, e0)]).unwrap();
        assert_ne!(*bl.finalize(b"input", &single).unwrap(), *full);
        assert_ne!(*evaluate_full(&shares[0].key, b"input").unwrap(), *full);
    }

    #[test]
    fn three_of_five_keys() {
        let k = new_key().unwrap();
        let shares = split_key(&k, 3, 5).unwrap();
        let full = evaluate_full(&k, b"x").unwrap();
        let bl = blind(b"x").unwrap();
        let evals: Vec<(u8, [u8; 32])> = [4usize, 0, 2]
            .iter()
            .map(|&i| {
                (
                    shares[i].index,
                    evaluate(&shares[i].key, &bl.message).unwrap(),
                )
            })
            .collect();
        let e = combine_evaluations(&evals).unwrap();
        assert_eq!(*bl.finalize(b"x", &e).unwrap(), *full);
        assert!(combine_evaluations(&[(1, evals[0].1), (1, evals[1].1)]).is_err());
    }

    #[test]
    fn garbage_refused() {
        let k = new_key().unwrap();
        // Not a canonical encoding, and the identity.
        assert!(evaluate(&k, &[0xffu8; 32]).is_err());
        assert!(evaluate(&k, &[0u8; 32]).is_err());
        assert!(evaluate(&[0u8; 32], &blind(b"x").unwrap().message).is_err());
        assert!(evaluate(&[0xffu8; 32], &blind(b"x").unwrap().message).is_err());
        let a = blind(b"x").unwrap();
        assert!(a.finalize(b"x", &[0xffu8; 32]).is_err());
        assert!(split_key(&[0u8; 32], 2, 3).is_err());
    }
}
