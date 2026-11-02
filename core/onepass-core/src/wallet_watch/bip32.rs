//! BIP32 extended public keys (xpub, ypub, zpub) and the non-hardened
//! public derivation of receive and change addresses (BIP44, BIP49, BIP84).
//! An extended private key is refused: it never belongs in a watch field.

use aws_lc_rs::digest::{SHA256, digest};
use aws_lc_rs::hmac::{self, HMAC_SHA512};
use k256::elliptic_curve::PrimeField;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{ProjectivePoint, PublicKey, Scalar};
use ripemd::Ripemd160;
use sha3::Digest;

use super::encoding::{b58check_decode, b58check_encode, segwit_encode};
use super::{AddressKind, MAX_DERIVED};
use crate::{Error, Result};

pub const XPUB: [u8; 4] = [0x04, 0x88, 0xB2, 0x1E];
pub const YPUB: [u8; 4] = [0x04, 0x9D, 0x7C, 0xB2];
pub const ZPUB: [u8; 4] = [0x04, 0xB2, 0x47, 0x46];
/// Private versions (xprv, yprv, zprv, and the testnet tprv, uprv, vprv).
const PRIVATE: [[u8; 4]; 6] = [
    [0x04, 0x88, 0xAD, 0xE4],
    [0x04, 0x9D, 0x78, 0x78],
    [0x04, 0xB2, 0x43, 0x0C],
    [0x04, 0x35, 0x83, 0x94],
    [0x04, 0x4A, 0x4E, 0x28],
    [0x04, 0x5F, 0x18, 0xBC],
];

const BAD: Error = Error::InvalidFormat("extended public key");
pub const PRIVATE_REFUSED: Error = Error::InvalidFormat("extended private key");

/// Address script an extended key's version stands for.
pub fn script_of(version: [u8; 4]) -> Option<AddressKind> {
    match version {
        XPUB => Some(AddressKind::P2pkh),
        YPUB => Some(AddressKind::P2shP2wpkh),
        ZPUB => Some(AddressKind::P2wpkh),
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedPub {
    pub version: [u8; 4],
    pub depth: u8,
    pub parent_fingerprint: [u8; 4],
    pub child_number: u32,
    pub chain_code: [u8; 32],
    /// SEC1 compressed point.
    pub key: [u8; 33],
}

pub fn hash160(data: &[u8]) -> [u8; 20] {
    let sha = digest(&SHA256, data);
    let rip = Ripemd160::digest(sha.as_ref());
    let mut out = [0u8; 20];
    out.copy_from_slice(&rip);
    out
}

fn hmac512(key: &[u8], parts: &[&[u8]]) -> [u8; 64] {
    let key = hmac::Key::new(HMAC_SHA512, key);
    let mut ctx = hmac::Context::with_key(&key);
    for p in parts {
        ctx.update(p);
    }
    let tag = ctx.sign();
    let mut out = [0u8; 64];
    out.copy_from_slice(tag.as_ref());
    out
}

/// IL of a derivation as a scalar, refused when it is not below the order.
pub(crate) fn scalar(bytes: &[u8]) -> Result<Scalar> {
    let arr: [u8; 32] = bytes.try_into().map_err(|_| Error::Crypto)?;
    Option::from(Scalar::from_repr(arr.into())).ok_or(Error::Crypto)
}

pub(crate) fn compressed(point: &ProjectivePoint) -> Result<[u8; 33]> {
    let enc = point.to_affine().to_encoded_point(true);
    enc.as_bytes().try_into().map_err(|_| Error::Crypto)
}

impl ExtendedPub {
    pub fn parse(text: &str) -> Result<ExtendedPub> {
        let data = b58check_decode(text.trim()).ok_or(BAD)?;
        if data.len() != 78 {
            return Err(BAD);
        }
        let version: [u8; 4] = data[0..4].try_into().map_err(|_| BAD)?;
        if PRIVATE.contains(&version) {
            return Err(PRIVATE_REFUSED);
        }
        script_of(version).ok_or(BAD)?;
        let key: [u8; 33] = data[45..78].try_into().map_err(|_| BAD)?;
        PublicKey::from_sec1_bytes(&key).map_err(|_| BAD)?;
        Ok(ExtendedPub {
            version,
            depth: data[4],
            parent_fingerprint: data[5..9].try_into().map_err(|_| BAD)?,
            child_number: u32::from_be_bytes(data[9..13].try_into().map_err(|_| BAD)?),
            chain_code: data[13..45].try_into().map_err(|_| BAD)?,
            key,
        })
    }

    pub fn serialize(&self) -> String {
        let mut data = Vec::with_capacity(78);
        data.extend_from_slice(&self.version);
        data.push(self.depth);
        data.extend_from_slice(&self.parent_fingerprint);
        data.extend_from_slice(&self.child_number.to_be_bytes());
        data.extend_from_slice(&self.chain_code);
        data.extend_from_slice(&self.key);
        b58check_encode(&data)
    }

    pub fn script(&self) -> AddressKind {
        script_of(self.version).unwrap_or(AddressKind::P2pkh)
    }

    /// CKDpub (non-hardened `index` only).
    pub fn child(&self, index: u32) -> Result<ExtendedPub> {
        if index >= 0x8000_0000 || self.depth == u8::MAX {
            return Err(Error::InvalidFormat("hardened public derivation"));
        }
        let i = hmac512(&self.chain_code, &[&self.key, &index.to_be_bytes()]);
        let tweak = scalar(&i[..32])?;
        let parent = PublicKey::from_sec1_bytes(&self.key).map_err(|_| BAD)?;
        let point = ProjectivePoint::GENERATOR * tweak + parent.to_projective();
        if point == ProjectivePoint::IDENTITY {
            return Err(Error::Crypto);
        }
        let fp = hash160(&self.key);
        Ok(ExtendedPub {
            version: self.version,
            depth: self.depth + 1,
            parent_fingerprint: fp[..4].try_into().map_err(|_| BAD)?,
            child_number: index,
            chain_code: i[32..].try_into().map_err(|_| BAD)?,
            key: compressed(&point)?,
        })
    }
}

/// Mainnet address of a compressed public key for a script kind.
pub fn address(key: &[u8; 33], kind: AddressKind) -> Result<String> {
    let h = hash160(key);
    match kind {
        AddressKind::P2pkh => {
            let mut p = vec![0x00];
            p.extend_from_slice(&h);
            Ok(b58check_encode(&p))
        }
        AddressKind::P2shP2wpkh => {
            let mut redeem = vec![0x00, 0x14];
            redeem.extend_from_slice(&h);
            let mut p = vec![0x05];
            p.extend_from_slice(&hash160(&redeem));
            Ok(b58check_encode(&p))
        }
        AddressKind::P2wpkh => segwit_encode("bc", 0, &h).ok_or(Error::Crypto),
        _ => Err(Error::InvalidFormat("address kind")),
    }
}

/// `count` addresses of the receive (`change` false, path `0/i`) or change
/// (`1/i`) chain of an account-level extended public key, from `start`.
pub fn derive_addresses(xpub: &str, change: bool, start: u32, count: u32) -> Result<Vec<String>> {
    let end = start
        .checked_add(count)
        .ok_or(Error::InvalidFormat("range"))?;
    if count > MAX_DERIVED || end > 0x8000_0000 {
        return Err(Error::InvalidFormat("range"));
    }
    let account = ExtendedPub::parse(xpub)?;
    let kind = account.script();
    let branch = account.child(u32::from(change))?;
    (start..end)
        .map(|i| address(&branch.child(i)?.key, kind))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bip32_vector_1_public_derivation() {
        // BIP32 test vector 1: m/0H, and its public child m/0H/1.
        let m0h = ExtendedPub::parse("xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw").unwrap();
        assert_eq!(
            m0h.child(1).unwrap().serialize(),
            "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ"
        );
        let master = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
        assert_eq!(ExtendedPub::parse(master).unwrap().serialize(), master);
    }

    #[test]
    fn bip84_vector_addresses() {
        // BIP84 test vector (mnemonic "abandon ... about"), account 0.
        let zpub = "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs";
        assert_eq!(
            derive_addresses(zpub, false, 0, 2).unwrap(),
            vec![
                "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
                "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g"
            ]
        );
        assert_eq!(
            derive_addresses(zpub, true, 0, 1).unwrap(),
            vec!["bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el"]
        );
    }

    #[test]
    fn refuses_private_keys_and_hardened_children() {
        let xprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
        assert_eq!(ExtendedPub::parse(xprv).unwrap_err(), PRIVATE_REFUSED);
        let master = ExtendedPub::parse("xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8").unwrap();
        assert!(master.child(0x8000_0000).is_err());
        assert!(ExtendedPub::parse("xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet9").is_err());
    }

    #[test]
    fn range_is_bounded() {
        let zpub = "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs";
        assert!(derive_addresses(zpub, false, 0, MAX_DERIVED + 1).is_err());
        assert!(derive_addresses(zpub, false, u32::MAX, 2).is_err());
    }
}
