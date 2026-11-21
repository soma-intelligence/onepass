//! Shamir secret sharing of a 32-byte secret over GF(2^8), byte by byte
//! (Guarded Kit spec, section 4).
//!
//! Field: GF(2^8) with the AES polynomial `x^8 + x^4 + x^3 + x + 1`. Share
//! `i` is the evaluation at `x = i` (1 to 255) of a random polynomial of
//! degree `threshold - 1` whose constant term is the secret byte. Field
//! arithmetic runs without secret-dependent branches or table lookups.

use zeroize::{Zeroize, Zeroizing};

use super::GuardError;
use crate::crypto::fill_random;

/// Secret length in bytes.
pub const SECRET_LEN: usize = 32;

/// One share: its evaluation point and 32 bytes.
#[derive(Clone, PartialEq, Eq, Zeroize)]
#[zeroize(drop)]
pub struct Share {
    pub x: u8,
    pub y: [u8; SECRET_LEN],
}

impl std::fmt::Debug for Share {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Share(x = {}, ..)", self.x)
    }
}

/// GF(2^8) product, constant time.
fn mul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    for _ in 0..8 {
        p ^= a & 0u8.wrapping_sub(b & 1);
        let carry = 0u8.wrapping_sub(a >> 7);
        a = (a << 1) ^ (0x1b & carry);
        b >>= 1;
    }
    p
}

/// GF(2^8) inverse as `a^254` (0 maps to 0), constant time.
fn inv(a: u8) -> u8 {
    let mut result = 1u8;
    let mut base = a;
    let mut e = 254u8;
    for _ in 0..8 {
        let bit = 0u8.wrapping_sub(e & 1);
        let m = mul(result, base);
        result = (m & bit) | (result & !bit);
        base = mul(base, base);
        e >>= 1;
    }
    result
}

/// Split `secret` into `n` shares, any `threshold` of which rebuild it.
///
/// Errors: `threshold` below 2 or above `n`, or `n` above 255.
pub fn split(
    secret: &[u8; SECRET_LEN],
    threshold: u8,
    n: u8,
) -> Result<Vec<Share>, GuardError> {
    if threshold < 2 || threshold > n {
        return Err(GuardError::Config("threshold"));
    }
    let t = usize::from(threshold);
    // coeffs[j][k]: coefficient of x^k for byte j, k >= 1 (k = 0 is the secret).
    let mut coeffs: Zeroizing<Vec<u8>> = Zeroizing::new(vec![0u8; SECRET_LEN * (t - 1)]);
    fill_random(&mut coeffs).map_err(|_| GuardError::Crypto)?;
    let mut shares = Vec::with_capacity(usize::from(n));
    for x in 1..=n {
        let mut y = [0u8; SECRET_LEN];
        for (j, out) in y.iter_mut().enumerate() {
            // Horner, highest degree first.
            let mut acc = 0u8;
            for k in (1..t).rev() {
                acc = mul(acc, x) ^ coeffs[j * (t - 1) + (k - 1)];
            }
            *out = mul(acc, x) ^ secret[j];
        }
        shares.push(Share { x, y });
    }
    Ok(shares)
}

/// Rebuild the secret from `shares` (Lagrange at 0). The caller passes at
/// least the threshold; with fewer, the result is a wrong secret, which the
/// keyset check of the caller refuses.
///
/// Errors: no share, a share at `x = 0`, or two shares at the same `x`.
pub fn combine(shares: &[&Share]) -> Result<Zeroizing<[u8; SECRET_LEN]>, GuardError> {
    if shares.is_empty() {
        return Err(GuardError::Config("no share"));
    }
    for (i, a) in shares.iter().enumerate() {
        if a.x == 0 || shares[..i].iter().any(|b| b.x == a.x) {
            return Err(GuardError::Config("share points"));
        }
    }
    let mut out = Zeroizing::new([0u8; SECRET_LEN]);
    for (i, si) in shares.iter().enumerate() {
        // l_i(0) = prod_{j != i} x_j / (x_j - x_i); subtraction is xor.
        let mut num = 1u8;
        let mut den = 1u8;
        for (j, sj) in shares.iter().enumerate() {
            if i != j {
                num = mul(num, sj.x);
                den = mul(den, sj.x ^ si.x);
            }
        }
        let l = mul(num, inv(den));
        for (o, y) in out.iter_mut().zip(si.y.iter()) {
            *o ^= mul(l, *y);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slow_mul(a: u8, b: u8) -> u8 {
        let mut p: u16 = 0;
        for i in 0..8 {
            if b >> i & 1 == 1 {
                p ^= u16::from(a) << i;
            }
        }
        for i in (8..16).rev() {
            if p >> i & 1 == 1 {
                p ^= 0x11b << (i - 8);
            }
        }
        p as u8
    }

    #[test]
    fn field_matches_reference() {
        for a in 0..=255u8 {
            for b in 0..=255u8 {
                assert_eq!(mul(a, b), slow_mul(a, b));
            }
            if a != 0 {
                assert_eq!(mul(a, inv(a)), 1);
            }
        }
        // FIPS 197 example: {57} x {83} = {c1}.
        assert_eq!(mul(0x57, 0x83), 0xc1);
    }

    #[test]
    fn any_two_of_three_rebuild() {
        let secret = [7u8; SECRET_LEN];
        let s = split(&secret, 2, 3).unwrap();
        for (a, b) in [(0, 1), (0, 2), (1, 2), (2, 0)] {
            assert_eq!(*combine(&[&s[a], &s[b]]).unwrap(), secret);
        }
        assert_eq!(*combine(&[&s[0], &s[1], &s[2]]).unwrap(), secret);
    }

    #[test]
    fn one_share_is_not_the_secret() {
        let secret = [9u8; SECRET_LEN];
        let s = split(&secret, 2, 3).unwrap();
        assert_ne!(*combine(&[&s[0]]).unwrap(), secret);
    }

    #[test]
    fn three_of_five() {
        let mut secret = [0u8; SECRET_LEN];
        fill_random(&mut secret).unwrap();
        let s = split(&secret, 3, 5).unwrap();
        assert_eq!(*combine(&[&s[4], &s[1], &s[3]]).unwrap(), secret);
        assert_ne!(*combine(&[&s[4], &s[1]]).unwrap(), secret);
    }

    #[test]
    fn bad_parameters_refused() {
        let secret = [1u8; SECRET_LEN];
        assert!(split(&secret, 1, 3).is_err());
        assert!(split(&secret, 4, 3).is_err());
        let s = split(&secret, 2, 3).unwrap();
        assert!(combine(&[&s[0], &s[0]]).is_err());
        assert!(combine(&[]).is_err());
    }
}
