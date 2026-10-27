//! 256-bit symmetric key.

use std::fmt;

use aws_lc_rs::hkdf::{HKDF_SHA256, KeyType, Salt};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::locked::LockedSlot;
use super::random::fill_random;
use crate::{Error, Result};

/// HKDF output length marker: 32 bytes.
struct Len32;

impl KeyType for Len32 {
    fn len(&self) -> usize {
        32
    }
}

/// HKDF-SHA256 with 32 output bytes, written straight into a key buffer.
/// `info` is the concatenation of its parts.
pub(crate) fn hkdf32(salt: &[u8], ikm: &[u8], info: &[&[u8]]) -> Result<SymmetricKey> {
    let prk = Salt::new(HKDF_SHA256, salt).extract(ikm);
    let okm = prk.expand(info, Len32).map_err(|_| Error::Crypto)?;
    let mut key = SymmetricKey::zeroed();
    okm.fill(key.bytes_mut()).map_err(|_| Error::Crypto)?;
    Ok(key)
}

/// A 256-bit symmetric key in a page-locked slot ([`super::locked`]),
/// wiped from memory on drop.
pub struct SymmetricKey(LockedSlot);

impl SymmetricKey {
    /// An all-zero key, to be filled in place through [`Self::bytes_mut`].
    pub(crate) fn zeroed() -> SymmetricKey {
        SymmetricKey(LockedSlot::new())
    }

    /// Write access to the key bytes, for in-place filling in the crate.
    pub(crate) fn bytes_mut(&mut self) -> &mut [u8; 32] {
        self.0.as_bytes_mut()
    }

    pub fn generate() -> Result<SymmetricKey> {
        let mut k = SymmetricKey::zeroed();
        fill_random(k.bytes_mut())?;
        Ok(k)
    }

    pub fn from_bytes(mut b: [u8; 32]) -> SymmetricKey {
        let mut k = SymmetricKey::zeroed();
        k.bytes_mut().copy_from_slice(&b);
        b.zeroize();
        k
    }

    pub fn expose(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    /// Explicit copy. `Clone` is deliberately not implemented.
    pub fn duplicate(&self) -> SymmetricKey {
        let mut k = SymmetricKey::zeroed();
        k.bytes_mut().copy_from_slice(self.expose());
        k
    }

    /// HKDF-SHA256 with an empty salt, 32 output bytes.
    pub fn derive(&self, info: &[u8]) -> Result<SymmetricKey> {
        hkdf32(&[], self.expose(), &[info])
    }
}

impl Zeroize for SymmetricKey {
    fn zeroize(&mut self) {
        self.bytes_mut().zeroize();
    }
}

/// The slot is wiped when the inner [`LockedSlot`] drops.
impl ZeroizeOnDrop for SymmetricKey {}

impl fmt::Debug for SymmetricKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SymmetricKey(**)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_keys_differ() {
        assert_ne!(
            SymmetricKey::generate().unwrap().expose(),
            SymmetricKey::generate().unwrap().expose()
        );
    }

    #[test]
    fn derive_is_deterministic_and_domain_separated() {
        let k = SymmetricKey::from_bytes([7u8; 32]);
        assert_eq!(
            k.derive(b"a").unwrap().expose(),
            k.derive(b"a").unwrap().expose()
        );
        assert_ne!(
            k.derive(b"a").unwrap().expose(),
            k.derive(b"b").unwrap().expose()
        );
    }

    #[test]
    fn debug_never_prints_bytes() {
        assert_eq!(
            format!("{:?}", SymmetricKey::from_bytes([0xAB; 32])),
            "SymmetricKey(**)"
        );
    }

    #[test]
    fn duplicate_copies_the_bytes() {
        let k = SymmetricKey::from_bytes([9u8; 32]);
        assert_eq!(k.duplicate().expose(), k.expose());
    }

    #[test]
    fn zeroize_wipes_the_key() {
        let mut k = SymmetricKey::from_bytes([3u8; 32]);
        k.zeroize();
        assert_eq!(k.expose(), &[0u8; 32]);
    }

    #[test]
    fn keys_are_send_and_sync() {
        fn check<T: Send + Sync>() {}
        check::<SymmetricKey>();
    }

    #[test]
    fn derive_matches_independent_hkdf_vector() {
        // HMAC-SHA256 based HKDF computed independently (Python hmac/hashlib):
        // salt empty, ikm = [7; 32], info = "a", L = 32.
        let k = SymmetricKey::from_bytes([7u8; 32]);
        let expected: [u8; 32] = [
            0xbf, 0xcc, 0x2b, 0x9c, 0x9c, 0xc8, 0x00, 0xdb, 0x95, 0x69, 0x27, 0x1b, 0xbf, 0xa6,
            0x3b, 0xdc, 0x57, 0x09, 0x2f, 0x19, 0xb8, 0xb8, 0x63, 0xbf, 0x17, 0xd9, 0x8f, 0xb6,
            0x4c, 0x2b, 0x5e, 0x5d,
        ];
        assert_eq!(k.derive(b"a").unwrap().expose(), &expected);
    }
}
