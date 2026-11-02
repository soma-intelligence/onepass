//! "Dériver les adresses publiques de cette phrase": the one explicit path
//! from a stored recovery phrase to public watch data. Runs only when the
//! user asks; every secret (seed, private keys, chain codes) lives in
//! zeroized buffers inside this call, and only public data comes out:
//! the BIP84 account zpub (m/84'/0'/0'), the first Ethereum account
//! (m/44'/60'/0'/0/0) and the first Solana account (m/44'/501'/0'/0',
//! SLIP-0010 ed25519, the path of Phantom and Solflare).

use std::num::NonZeroU32;

use aws_lc_rs::hmac::{self, HMAC_SHA512};
use aws_lc_rs::pbkdf2::{PBKDF2_HMAC_SHA512, derive};
use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{ProjectivePoint, Scalar};
use sha3::{Digest, Keccak256};
use unicode_normalization::UnicodeNormalization;
use zeroize::{Zeroize, Zeroizing};

use super::address::eip55;
use super::bip32::{ExtendedPub, ZPUB, compressed, hash160, scalar};
use super::encoding::b58_encode;
use crate::model::checks::bip39_valid;
use crate::{Error, Result};

const HARD: u32 = 0x8000_0000;

/// Public data derived from a phrase. Nothing secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletPublic {
    pub bitcoin_zpub: String,
    pub ethereum_address: String,
    pub solana_address: String,
}

/// A BIP32 private node: key and chain code, both wiped on drop.
struct Node {
    key: Zeroizing<[u8; 32]>,
    chain: Zeroizing<[u8; 32]>,
}

fn hmac512(key: &[u8], parts: &[&[u8]]) -> Zeroizing<[u8; 64]> {
    let key = hmac::Key::new(HMAC_SHA512, key);
    let mut ctx = hmac::Context::with_key(&key);
    for p in parts {
        ctx.update(p);
    }
    let tag = ctx.sign();
    let mut out = Zeroizing::new([0u8; 64]);
    out.copy_from_slice(tag.as_ref());
    out
}

fn split(i: &[u8; 64]) -> Node {
    let mut key = Zeroizing::new([0u8; 32]);
    let mut chain = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&i[..32]);
    chain.copy_from_slice(&i[32..]);
    Node { key, chain }
}

fn public_point(key: &[u8; 32]) -> Result<ProjectivePoint> {
    let k = scalar(key)?;
    if bool::from(k.is_zero()) {
        return Err(Error::Crypto);
    }
    Ok(ProjectivePoint::GENERATOR * k)
}

impl Node {
    fn secp_master(seed: &[u8]) -> Result<Node> {
        let node = split(&hmac512(b"Bitcoin seed", &[seed]));
        public_point(&node.key)?;
        Ok(node)
    }

    fn secp_child(&self, index: u32) -> Result<Node> {
        let i = if index >= HARD {
            hmac512(&*self.chain, &[&[0u8], &*self.key, &index.to_be_bytes()])
        } else {
            let pubkey = compressed(&public_point(&self.key)?)?;
            hmac512(&*self.chain, &[&pubkey, &index.to_be_bytes()])
        };
        let tweak = scalar(&i[..32])?;
        let child: Scalar = tweak + scalar(&self.key[..])?;
        if bool::from(child.is_zero()) {
            return Err(Error::Crypto);
        }
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&child.to_bytes());
        let mut chain = Zeroizing::new([0u8; 32]);
        chain.copy_from_slice(&i[32..]);
        Ok(Node { key, chain })
    }

    fn secp_path(seed: &[u8], path: &[u32]) -> Result<(Node, Option<Node>)> {
        let mut parent = None;
        let mut node = Node::secp_master(seed)?;
        for &i in path {
            let next = node.secp_child(i)?;
            parent = Some(std::mem::replace(&mut node, next));
        }
        Ok((node, parent))
    }

    fn ed_master(seed: &[u8]) -> Node {
        split(&hmac512(b"ed25519 seed", &[seed]))
    }

    /// SLIP-0010 ed25519: hardened children only.
    fn ed_child(&self, index: u32) -> Node {
        split(&hmac512(
            &*self.chain,
            &[&[0u8], &*self.key, &(index | HARD).to_be_bytes()],
        ))
    }

    fn ed_public(&self) -> Result<[u8; 32]> {
        let pair = Ed25519KeyPair::from_seed_unchecked(&*self.key).map_err(|_| Error::Crypto)?;
        pair.public_key()
            .as_ref()
            .try_into()
            .map_err(|_| Error::Crypto)
    }
}

/// BIP39 seed of a phrase (NFKD, PBKDF2-HMAC-SHA512, 2048 rounds).
fn bip39_seed(phrase: &str, passphrase: &str) -> Result<Zeroizing<[u8; 64]>> {
    let words = Zeroizing::new(phrase.split_whitespace().collect::<Vec<_>>().join(" "));
    if !bip39_valid(&words) {
        return Err(Error::InvalidFormat("recovery phrase"));
    }
    let mnemonic = Zeroizing::new(words.to_lowercase().nfkd().collect::<String>());
    let salt = Zeroizing::new(format!("mnemonic{}", passphrase.nfkd().collect::<String>()));
    let mut seed = Zeroizing::new([0u8; 64]);
    let rounds = NonZeroU32::new(2048).ok_or(Error::Crypto)?;
    derive(
        PBKDF2_HMAC_SHA512,
        rounds,
        salt.as_bytes(),
        mnemonic.as_bytes(),
        &mut *seed,
    );
    Ok(seed)
}

fn bitcoin_zpub(seed: &[u8]) -> Result<String> {
    let (account, parent) = Node::secp_path(seed, &[84 | HARD, HARD, HARD])?;
    let parent = parent.ok_or(Error::Crypto)?;
    let parent_key = compressed(&public_point(&parent.key)?)?;
    let fp = hash160(&parent_key);
    let mut chain_code = *account.chain;
    let xpub = ExtendedPub {
        version: ZPUB,
        depth: 3,
        parent_fingerprint: fp[..4].try_into().map_err(|_| Error::Crypto)?,
        child_number: HARD,
        chain_code,
        key: compressed(&public_point(&account.key)?)?,
    };
    chain_code.zeroize();
    Ok(xpub.serialize())
}

fn ethereum_address(seed: &[u8]) -> Result<String> {
    let (node, _) = Node::secp_path(seed, &[44 | HARD, 60 | HARD, HARD, 0, 0])?;
    let point = public_point(&node.key)?.to_affine().to_encoded_point(false);
    let hash = Keccak256::digest(&point.as_bytes()[1..]);
    let addr: [u8; 20] = hash[12..].try_into().map_err(|_| Error::Crypto)?;
    Ok(eip55(&addr))
}

fn solana_address(seed: &[u8]) -> Result<String> {
    let mut node = Node::ed_master(seed);
    for i in [44, 501, 0, 0] {
        node = node.ed_child(i);
    }
    Ok(b58_encode(&node.ed_public()?))
}

/// Public watch data of a recovery phrase and its optional BIP39
/// passphrase. The phrase must pass the BIP39 checksum.
pub fn derive_public(phrase: &str, passphrase: &str) -> Result<WalletPublic> {
    let seed = bip39_seed(phrase, passphrase)?;
    Ok(WalletPublic {
        bitcoin_zpub: bitcoin_zpub(&*seed)?,
        ethereum_address: ethereum_address(&*seed)?,
        solana_address: solana_address(&*seed)?,
    })
}

#[cfg(test)]
mod tests {
    use super::super::AddressKind;
    use super::super::bip32::{YPUB, address, derive_addresses};
    use super::*;

    const ABANDON: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn hex(s: &str) -> Vec<u8> {
        data_encoding::HEXLOWER.decode(s.as_bytes()).unwrap()
    }

    #[test]
    fn bip39_seed_official_vector() {
        // Trezor BIP39 vectors: first entry, passphrase "TREZOR".
        let seed = bip39_seed(ABANDON, "TREZOR").unwrap();
        assert_eq!(
            &seed[..],
            &hex(
                "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
            )[..]
        );
    }

    #[test]
    fn bip84_account_and_first_address() {
        let public = derive_public(ABANDON, "").unwrap();
        assert_eq!(
            public.bitcoin_zpub,
            "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs"
        );
        assert_eq!(
            derive_addresses(&public.bitcoin_zpub, false, 0, 1).unwrap()[0],
            "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
        );
    }

    #[test]
    fn bip44_and_bip49_first_addresses_from_the_same_seed() {
        let seed = bip39_seed(ABANDON, "").unwrap();
        let (n, _) = Node::secp_path(&*seed, &[44 | HARD, HARD, HARD, 0, 0]).unwrap();
        let key = compressed(&public_point(&n.key).unwrap()).unwrap();
        assert_eq!(
            address(&key, AddressKind::P2pkh).unwrap(),
            "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA"
        );
        let (n, _) = Node::secp_path(&*seed, &[49 | HARD, HARD, HARD, 0, 0]).unwrap();
        let key = compressed(&public_point(&n.key).unwrap()).unwrap();
        assert_eq!(
            address(&key, AddressKind::P2shP2wpkh).unwrap(),
            "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf"
        );
        let _ = YPUB;
    }

    #[test]
    fn ethereum_first_account() {
        assert_eq!(
            derive_public(ABANDON, "").unwrap().ethereum_address,
            "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"
        );
    }

    #[test]
    fn slip10_ed25519_vector_1() {
        // SLIP-0010 test vector 1 for ed25519 (seed 000102...0f): m and m/0H.
        let seed = hex("000102030405060708090a0b0c0d0e0f");
        let m = Node::ed_master(&seed);
        assert_eq!(
            data_encoding::HEXLOWER.encode(&m.ed_public().unwrap()),
            "a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed"
        );
        assert_eq!(
            data_encoding::HEXLOWER.encode(&m.ed_child(0).ed_public().unwrap()),
            "8c8a13df77a28f3445213a0f432fde644acaa215fc72dcdf300d5efaa85d350c"
        );
    }

    #[test]
    fn solana_first_account() {
        assert_eq!(
            derive_public(ABANDON, "").unwrap().solana_address,
            "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk"
        );
    }

    #[test]
    fn refuses_an_invalid_phrase() {
        assert_eq!(
            derive_public("abandon abandon abandon", "").unwrap_err(),
            Error::InvalidFormat("recovery phrase")
        );
    }
}
