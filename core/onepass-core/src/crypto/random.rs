//! Operating system CSPRNG, through aws-lc.

use crate::{Error, Result};

/// Fill `buf` with cryptographically secure random bytes.
pub fn fill_random(buf: &mut [u8]) -> Result<()> {
    aws_lc_rs::rand::fill(buf).map_err(|_| Error::Crypto)
}

/// Return `N` cryptographically secure random bytes.
///
/// The returned array is a plain copy that is not wiped. For secret material,
/// use `fill_random` into a zeroizing buffer instead.
pub fn random_array<const N: usize>() -> Result<[u8; N]> {
    let mut out = [0u8; N];
    fill_random(&mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arrays_differ_and_are_not_zero() {
        let a = random_array::<32>().unwrap();
        let b = random_array::<32>().unwrap();
        assert_ne!(a, b);
        assert_ne!(a, [0u8; 32]);
    }

    #[test]
    fn fill_handles_empty_buffer() {
        fill_random(&mut []).unwrap();
    }
}
