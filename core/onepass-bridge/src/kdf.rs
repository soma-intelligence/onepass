//! HKDF, HMAC and SAS helpers of the bridge protocol (spec 6.4, 6.5).

use aws_lc_rs::constant_time::verify_slices_are_equal;
use aws_lc_rs::hkdf::{HKDF_SHA256, KeyType, Salt};
use aws_lc_rs::hmac;
use zeroize::Zeroizing;

use crate::{BridgeError, Result};

/// HKDF output length marker: 32 bytes.
struct Len32;

impl KeyType for Len32 {
    fn len(&self) -> usize {
        32
    }
}

/// HKDF-SHA256 extract and expand, 32 output bytes, raw `info`.
///
/// Fails with `BridgeError::Crypto` if aws-lc refuses the expansion; the
/// output buffer is never handed out in that case.
pub(crate) fn hkdf32(salt: &[u8], ikm: &[u8], info: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let mut out = Zeroizing::new([0u8; 32]);
    let prk = Salt::new(HKDF_SHA256, salt).extract(ikm);
    let info = [info];
    let okm = prk.expand(&info, Len32).map_err(|_| BridgeError::Crypto)?;
    okm.fill(out.as_mut_slice())
        .map_err(|_| BridgeError::Crypto)?;
    Ok(out)
}

/// `HKDF-SHA256(salt, ikm).expand(info = label, 32)`, failing explicitly.
/// The protocol code of this crate derives every key through this function.
pub fn try_expand(salt: &[u8], ikm: &[u8], label: &str) -> Result<Zeroizing<[u8; 32]>> {
    hkdf32(salt, ikm, label.as_bytes())
}

/// `HKDF-SHA256(salt, ikm).expand(info = label, 32)`.
///
/// # Panics
///
/// Never in practice: HKDF-SHA256 only refuses outputs longer than 255
/// blocks of 32 bytes, and this output is exactly one block, whatever the
/// inputs. The unreachable failure panics (with a debug assertion first)
/// rather than return a zero key. Prefer [`try_expand`] in new code.
pub fn expand(salt: &[u8], ikm: &[u8], label: &str) -> Zeroizing<[u8; 32]> {
    match try_expand(salt, ikm, label) {
        Ok(key) => key,
        Err(_) => {
            debug_assert!(false, "HKDF-SHA256 refused a 32 byte output");
            panic!("HKDF-SHA256 refused a 32 byte output")
        }
    }
}

fn signed(key: &[u8; 32], role: &[u8], t: &[u8; 32]) -> hmac::Tag {
    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let mut ctx = hmac::Context::with_key(&key);
    ctx.update(role);
    ctx.update(t);
    ctx.sign()
}

/// `HMAC-SHA256(key, role || t)`.
pub fn hmac(key: &[u8; 32], role: &[u8], t: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(signed(key, role, t).as_ref());
    out
}

/// Constant-time check of `tag` against `HMAC-SHA256(key, role || t)`.
pub fn verify_hmac(key: &[u8; 32], role: &[u8], t: &[u8; 32], tag: &[u8]) -> bool {
    let want = signed(key, role, t);
    verify_slices_are_equal(want.as_ref(), tag).is_ok()
}

/// Six digit code shown on both screens: the first four bytes of the key as
/// a big-endian integer, modulo one million, as `"123 456"`.
pub fn sas(code_key: &[u8; 32]) -> String {
    let n = u32::from_be_bytes([code_key[0], code_key[1], code_key[2], code_key[3]]) % 1_000_000;
    format!("{:03} {:03}", n / 1000, n % 1000)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sas_format() {
        let mut key = [0xAAu8; 32];
        key[..4].copy_from_slice(&12345u32.to_be_bytes());
        assert_eq!(sas(&key), "012 345");
        key[..4].copy_from_slice(&(1_000_000u32 + 999_999).to_be_bytes());
        assert_eq!(sas(&key), "999 999");
        key[..4].copy_from_slice(&0u32.to_be_bytes());
        assert_eq!(sas(&key), "000 000");
    }

    #[test]
    fn hmac_verify_accepts_and_rejects_flip() {
        let key = [7u8; 32];
        let t = [9u8; 32];
        let tag = hmac(&key, b"host", &t);
        assert!(verify_hmac(&key, b"host", &t, &tag));
        for i in 0..tag.len() {
            let mut bad = tag;
            bad[i] ^= 1;
            assert!(!verify_hmac(&key, b"host", &t, &bad));
        }
        // Role and transcript are bound.
        assert!(!verify_hmac(&key, b"ext", &t, &tag));
        let mut t2 = t;
        t2[0] ^= 1;
        assert!(!verify_hmac(&key, b"host", &t2, &tag));
        // Wrong tag length is refused, not a panic.
        assert!(!verify_hmac(&key, b"host", &t, &tag[..31]));
    }

    #[test]
    fn expand_is_label_and_input_separated() {
        let a = expand(b"salt", b"ikm", "onepass/bridge/session/e2h/v1");
        let b = expand(b"salt", b"ikm", "onepass/bridge/session/h2e/v1");
        let c = expand(b"salt2", b"ikm", "onepass/bridge/session/e2h/v1");
        let d = expand(b"salt", b"ikm2", "onepass/bridge/session/e2h/v1");
        assert_ne!(*a, *b);
        assert_ne!(*a, *c);
        assert_ne!(*a, *d);
        assert_eq!(
            *a,
            *expand(b"salt", b"ikm", "onepass/bridge/session/e2h/v1")
        );
    }

    #[test]
    fn try_expand_agrees_with_expand() {
        let a = try_expand(b"salt", b"ikm", "onepass/bridge/sas/v1").unwrap();
        let b = expand(b"salt", b"ikm", "onepass/bridge/sas/v1");
        assert_eq!(*a, *b);
        assert_ne!(*a, [0u8; 32]);
    }

    #[test]
    fn expand_matches_rfc5869_case_1() {
        // RFC 5869 test case 1, through the raw-info helper.
        let ikm = [0x0bu8; 22];
        let salt: Vec<u8> = (0x00..=0x0c).collect();
        let info: Vec<u8> = (0xf0..=0xf9).collect();
        let okm = hkdf32(&salt, &ikm, &info).unwrap();
        let expected = [
            0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
            0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
            0xec, 0xc4, 0xc5, 0xbf,
        ];
        assert_eq!(*okm, expected);
    }
}
