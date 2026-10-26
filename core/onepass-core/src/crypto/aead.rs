//! Encrypted blobs: AES-256-GCM-SIV with an HMAC-SHA256 key commitment and
//! length-hiding padding.
//!
//! Layout: `header (50) || ciphertext (padded plaintext) || tag (16)`, where
//! the header is `magic "OPB" || format || algorithm || kind || nonce (12) ||
//! commitment (32)`.

use aws_lc_rs::aead::{self, AES_256_GCM_SIV, LessSafeKey, Nonce, UnboundKey};
use aws_lc_rs::constant_time::verify_slices_are_equal;
use aws_lc_rs::hmac::{self, HMAC_SHA256};
use zeroize::Zeroizing;

use super::key::SymmetricKey;
use super::random::fill_random;
use crate::{Error, Id, IntegrityError, Result};

/// Record kind, bound into every blob header.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlobKind {
    Keyset = 1,
    VaultKey = 2,
    VaultMeta = 3,
    ItemKey = 4,
    Item = 5,
    Manifest = 6,
    Attachment = 7,
    DeviceState = 8,
}

/// Context a blob is bound to. Opening under any other context fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Aad {
    pub blob_id: Id,
    pub vault_id: Option<Id>,
    pub schema: u16,
}

/// Header length: magic 3, format 1, algorithm 1, kind 1, nonce 12, commitment 32.
pub const HEADER_LEN: usize = 50;

const MAGIC: &[u8; 3] = b"OPB";
const FORMAT: u8 = 1;
const ALGORITHM: u8 = 1;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
/// Bytes of the header that are covered by the commitment.
const PREFIX_LEN: usize = 18;
/// Bytes of the big-endian length prefix inside the padded plaintext.
const LEN_PREFIX: usize = 4;
const MIN_PADDED: usize = 256;
const LARGE_STEP: usize = 65536;

const ENC_INFO: &[u8] = b"onepass/blob/enc/v1";
const COMMIT_INFO: &[u8] = b"onepass/blob/commit/v1";

/// Padded size for `len` bytes, length prefix included: at least 256, then the
/// next power of two up to 65536, then the next multiple of 65536.
pub fn padded_len(len: usize) -> usize {
    if len <= MIN_PADDED {
        MIN_PADDED
    } else if len <= LARGE_STEP {
        len.next_power_of_two()
    } else {
        len.div_ceil(LARGE_STEP).saturating_mul(LARGE_STEP)
    }
}

/// `header[0..18] || blob_id || vault_id or 16 zero bytes || schema_be`.
fn aad_bytes(prefix: &[u8], aad: &Aad) -> Vec<u8> {
    let mut out = Vec::with_capacity(PREFIX_LEN + 16 + 16 + 2);
    out.extend_from_slice(prefix);
    out.extend_from_slice(&aad.blob_id.0);
    out.extend_from_slice(&aad.vault_id.map_or([0u8; 16], |v| v.0));
    out.extend_from_slice(&aad.schema.to_be_bytes());
    out
}

fn commitment(k_com: &SymmetricKey, aad_bytes: &[u8]) -> hmac::Tag {
    hmac::sign(&hmac::Key::new(HMAC_SHA256, k_com.expose()), aad_bytes)
}

fn aead_key(k_enc: &SymmetricKey) -> Result<LessSafeKey> {
    let unbound = UnboundKey::new(&AES_256_GCM_SIV, k_enc.expose()).map_err(|_| Error::Crypto)?;
    Ok(LessSafeKey::new(unbound))
}

/// Seal `plaintext` as a blob of `kind`, bound to `aad`.
pub fn seal(key: &SymmetricKey, kind: BlobKind, aad: &Aad, plaintext: &[u8]) -> Result<Vec<u8>> {
    let k_enc = key.derive(ENC_INFO)?;
    let k_com = key.derive(COMMIT_INFO)?;

    // The prefixed length must itself fit in the u32 prefix.
    let len = u32::try_from(plaintext.len() + LEN_PREFIX)
        .map(|l| l - LEN_PREFIX as u32)
        .map_err(|_| Error::InvalidFormat("plaintext too large"))?;
    let padded = padded_len(plaintext.len() + LEN_PREFIX);

    let mut nonce = [0u8; NONCE_LEN];
    fill_random(&mut nonce)?;

    let mut prefix = [0u8; PREFIX_LEN];
    prefix[0..3].copy_from_slice(MAGIC);
    prefix[3] = FORMAT;
    prefix[4] = ALGORITHM;
    prefix[5] = kind as u8;
    prefix[6..PREFIX_LEN].copy_from_slice(&nonce);

    let mut full_aad = aad_bytes(&prefix, aad);
    let commit = commitment(&k_com, &full_aad);
    full_aad.extend_from_slice(commit.as_ref());

    // The output buffer holds plaintext until it is sealed in place, so it is
    // wiped on every early return. Capacity is reserved up front so the tag
    // append never reallocates.
    let mut out = Zeroizing::new(Vec::with_capacity(HEADER_LEN + padded + TAG_LEN));
    out.extend_from_slice(&prefix);
    out.extend_from_slice(commit.as_ref());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(plaintext);
    out.resize(HEADER_LEN + padded, 0);

    let tag = aead_key(&k_enc)?
        .seal_in_place_separate_tag(
            Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(&full_aad[..]),
            &mut out[HEADER_LEN..],
        )
        .map_err(|_| Error::Crypto)?;
    out.extend_from_slice(tag.as_ref());

    Ok(std::mem::take(&mut *out))
}

/// Open a blob of `kind` bound to `aad`.
///
/// Checks, in order: minimum length, magic, format, algorithm, kind, key
/// commitment (constant time), AEAD, padding.
pub fn open(
    key: &SymmetricKey,
    kind: BlobKind,
    aad: &Aad,
    blob: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if blob.len() < HEADER_LEN + TAG_LEN {
        return Err(Error::InvalidFormat("blob too short"));
    }
    if &blob[0..3] != MAGIC {
        return Err(Error::InvalidFormat("magic"));
    }
    if blob[3] != FORMAT {
        return Err(Error::InvalidFormat("format"));
    }
    if blob[4] != ALGORITHM {
        return Err(Error::InvalidFormat("algorithm"));
    }
    if blob[5] != kind as u8 {
        return Err(IntegrityError::WrongKind.into());
    }

    let k_enc = key.derive(ENC_INFO)?;
    let k_com = key.derive(COMMIT_INFO)?;

    let mut full_aad = aad_bytes(&blob[0..PREFIX_LEN], aad);
    let expected = commitment(&k_com, &full_aad);
    let stored = &blob[PREFIX_LEN..HEADER_LEN];
    verify_slices_are_equal(expected.as_ref(), stored)
        .map_err(|_| Error::Integrity(IntegrityError::Commitment))?;
    full_aad.extend_from_slice(stored);

    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&blob[6..PREFIX_LEN]);

    let mut buf = Zeroizing::new(blob[HEADER_LEN..].to_vec());
    let pt_len = aead_key(&k_enc)?
        .open_in_place(
            Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(&full_aad[..]),
            &mut buf[..],
        )
        .map_err(|_| Error::Integrity(IntegrityError::Aead))?
        .len();
    buf.truncate(pt_len);

    unpad(buf)
}

/// Strip the length prefix and the zero padding, checking both are canonical.
fn unpad(mut buf: Zeroizing<Vec<u8>>) -> Result<Zeroizing<Vec<u8>>> {
    const BAD: Error = Error::InvalidFormat("padding");
    let prefix: [u8; LEN_PREFIX] = buf
        .get(..LEN_PREFIX)
        .and_then(|p| p.try_into().ok())
        .ok_or(BAD)?;
    let len = u32::from_be_bytes(prefix) as usize;
    let end = len.checked_add(LEN_PREFIX).ok_or(BAD)?;
    if end > buf.len() || padded_len(end) != buf.len() || buf[end..].iter().any(|&b| b != 0) {
        return Err(BAD);
    }
    buf.copy_within(LEN_PREFIX..end, 0);
    buf.truncate(len);
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> Aad {
        Aad {
            blob_id: Id([1; 16]),
            vault_id: None,
            schema: 1,
        }
    }

    #[test]
    fn header_layout_is_exact() {
        let k = SymmetricKey::from_bytes([3; 32]);
        let blob = seal(&k, BlobKind::Manifest, &ctx(), b"abc").unwrap();
        assert_eq!(&blob[0..6], &[b'O', b'P', b'B', 1, 1, 6]);
        let aad_bytes = aad_bytes(&blob[0..PREFIX_LEN], &ctx());
        assert_eq!(aad_bytes.len(), 52);
        assert_eq!(
            &aad_bytes[34..50],
            &[0u8; 16],
            "absent vault id is 16 zeros"
        );
        let commit = commitment(&k.derive(COMMIT_INFO).unwrap(), &aad_bytes);
        assert_eq!(&blob[PREFIX_LEN..HEADER_LEN], commit.as_ref());
    }

    #[test]
    fn short_and_garbage_inputs_never_panic() {
        let k = SymmetricKey::from_bytes([3; 32]);
        for len in [0, 1, 3, 17, 49, 50, 65, 66, 67, 300] {
            let mut junk = vec![0xEEu8; len];
            assert!(open(&k, BlobKind::Item, &ctx(), &junk).is_err());
            if len >= 6 {
                junk[0..6].copy_from_slice(&[b'O', b'P', b'B', 1, 1, 5]);
                assert!(open(&k, BlobKind::Item, &ctx(), &junk).is_err());
            }
        }
    }

    #[test]
    fn header_checks_run_in_order() {
        let k = SymmetricKey::from_bytes([3; 32]);
        let blob = seal(&k, BlobKind::Item, &ctx(), b"abc").unwrap();
        let expect = |i: usize, e: Error| {
            let mut b = blob.clone();
            b[i] ^= 0x80;
            b[5] ^= 0x01; // a wrong kind too: the earlier check must win
            assert_eq!(open(&k, BlobKind::Item, &ctx(), &b), Err(e));
        };
        expect(0, Error::InvalidFormat("magic"));
        expect(3, Error::InvalidFormat("format"));
        expect(4, Error::InvalidFormat("algorithm"));
        assert_eq!(
            open(
                &k,
                BlobKind::Item,
                &ctx(),
                &blob[..HEADER_LEN + TAG_LEN - 1]
            ),
            Err(Error::InvalidFormat("blob too short"))
        );
    }

    /// Seal raw padded bytes with the real construction, to reach the
    /// padding check past AEAD.
    fn seal_raw(k: &SymmetricKey, padded: &[u8]) -> Vec<u8> {
        let k_enc = k.derive(ENC_INFO).unwrap();
        let k_com = k.derive(COMMIT_INFO).unwrap();
        let mut prefix = [0u8; PREFIX_LEN];
        prefix[0..6].copy_from_slice(&[b'O', b'P', b'B', 1, 1, 5]);
        let mut full = aad_bytes(&prefix, &ctx());
        let commit = commitment(&k_com, &full);
        full.extend_from_slice(commit.as_ref());
        let mut body = padded.to_vec();
        aead_key(&k_enc)
            .unwrap()
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key([0; NONCE_LEN]),
                aead::Aad::from(&full[..]),
                &mut body,
            )
            .unwrap();
        [&prefix[..], commit.as_ref(), &body].concat()
    }

    #[test]
    fn inconsistent_padding_is_rejected_after_aead() {
        let k = SymmetricKey::from_bytes([3; 32]);
        let bad = Err(Error::InvalidFormat("padding"));
        // Length prefix larger than the buffer, including u32::MAX.
        for len in [253u32, 1000, u32::MAX] {
            let mut p = vec![0u8; 256];
            p[0..4].copy_from_slice(&len.to_be_bytes());
            assert_eq!(open(&k, BlobKind::Item, &ctx(), &seal_raw(&k, &p)), bad);
        }
        // Padded too far: 3 bytes need 256, not 512.
        let mut p = vec![0u8; 512];
        p[0..4].copy_from_slice(&3u32.to_be_bytes());
        assert_eq!(open(&k, BlobKind::Item, &ctx(), &seal_raw(&k, &p)), bad);
        // Non-zero padding byte.
        let mut p = vec![0u8; 256];
        p[0..4].copy_from_slice(&3u32.to_be_bytes());
        p[255] = 1;
        assert_eq!(open(&k, BlobKind::Item, &ctx(), &seal_raw(&k, &p)), bad);
        // Shorter than the length prefix.
        assert_eq!(
            open(&k, BlobKind::Item, &ctx(), &seal_raw(&k, &[0, 0])),
            bad
        );
        // Sanity: the raw sealer produces valid blobs.
        let mut p = vec![0u8; 256];
        p[0..4].copy_from_slice(&3u32.to_be_bytes());
        p[4..7].copy_from_slice(b"abc");
        assert_eq!(
            &open(&k, BlobKind::Item, &ctx(), &seal_raw(&k, &p)).unwrap()[..],
            b"abc"
        );
    }

    #[test]
    fn padded_len_never_overflows() {
        assert_eq!(padded_len(0), 256);
        assert_eq!(padded_len(usize::MAX), usize::MAX);
    }
}
