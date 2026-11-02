//! Format checks of public addresses, per chain, with their checksums:
//! Bitcoin Base58Check (P2PKH, P2SH) and Bech32/Bech32m (segwit v0 and
//! v1+), Ethereum EIP-55, Solana Base58 of 32 bytes. Mainnet only.

use sha3::{Digest, Keccak256};

use super::encoding::{b58_decode, b58_encode, b58check_decode, segwit_decode};
use super::{AddressKind, Chain};
use crate::{Error, Result};

const BAD: Error = Error::InvalidFormat("address");

/// The address in its canonical form (Bech32 lower case, EIP-55 mixed case)
/// and its script kind.
pub fn validate(chain: Chain, text: &str) -> Result<(String, AddressKind)> {
    let text = text.trim();
    match chain {
        Chain::Bitcoin => bitcoin(text),
        Chain::Ethereum => ethereum(text).map(|a| (a, AddressKind::Account)),
        Chain::Solana => solana(text).map(|a| (a, AddressKind::Account)),
    }
}

/// The chain of a bare address: `0x` is Ethereum, `bc1` and Base58Check of
/// version 0 or 5 are Bitcoin, Base58 of 32 bytes is Solana.
pub fn detect(text: &str) -> Option<Chain> {
    let text = text.trim();
    if text.len() > 2 && text[..2].eq_ignore_ascii_case("0x") {
        return Some(Chain::Ethereum);
    }
    if text.len() > 3 && text[..3].eq_ignore_ascii_case("bc1") {
        return Some(Chain::Bitcoin);
    }
    if bitcoin(text).is_ok() {
        return Some(Chain::Bitcoin);
    }
    solana(text).ok().map(|_| Chain::Solana)
}

fn bitcoin(text: &str) -> Result<(String, AddressKind)> {
    if text.len() > 3 && text[..3].eq_ignore_ascii_case("bc1") {
        let (version, program) = segwit_decode("bc", text).ok_or(BAD)?;
        let kind = match (version, program.len()) {
            (0, 20) => AddressKind::P2wpkh,
            (0, _) => AddressKind::P2wsh,
            (1, 32) => AddressKind::P2tr,
            _ => AddressKind::SegwitOther,
        };
        return Ok((text.to_ascii_lowercase(), kind));
    }
    let payload = b58check_decode(text).ok_or(BAD)?;
    match (payload.len(), payload.first()) {
        (21, Some(0x00)) => Ok((text.to_owned(), AddressKind::P2pkh)),
        (21, Some(0x05)) => Ok((text.to_owned(), AddressKind::P2sh)),
        _ => Err(BAD),
    }
}

/// EIP-55 checksummed form of 20 address bytes.
pub fn eip55(bytes: &[u8; 20]) -> String {
    let lower = data_encoding::HEXLOWER.encode(bytes);
    let hash = Keccak256::digest(lower.as_bytes());
    let mut out = String::with_capacity(42);
    out.push_str("0x");
    for (i, c) in lower.chars().enumerate() {
        let nibble = (hash[i / 2] >> (if i % 2 == 0 { 4 } else { 0 })) & 0x0f;
        out.push(if nibble >= 8 {
            c.to_ascii_uppercase()
        } else {
            c
        });
    }
    out
}

fn ethereum(text: &str) -> Result<String> {
    let hex = text
        .strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))
        .ok_or(BAD)?;
    if hex.len() != 40 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(BAD);
    }
    let raw = data_encoding::HEXLOWER
        .decode(hex.to_ascii_lowercase().as_bytes())
        .map_err(|_| BAD)?;
    let bytes: [u8; 20] = raw.try_into().map_err(|_| BAD)?;
    let canonical = eip55(&bytes);
    let mixed =
        hex.bytes().any(|b| b.is_ascii_lowercase()) && hex.bytes().any(|b| b.is_ascii_uppercase());
    // All lower or all upper case carries no checksum; mixed case must be EIP-55.
    if mixed && canonical[2..] != *hex {
        return Err(Error::InvalidFormat("address checksum"));
    }
    Ok(canonical)
}

fn solana(text: &str) -> Result<String> {
    if !(32..=44).contains(&text.len()) {
        return Err(BAD);
    }
    let bytes = b58_decode(text).ok_or(BAD)?;
    if bytes.len() != 32 || b58_encode(&bytes) != text {
        return Err(BAD);
    }
    Ok(text.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eip55_official_vectors() {
        // EIP-55 specification, "Test cases".
        for a in [
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
            "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
            "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
            "0x52908400098527886E0F7030069857D2E4169EE7",
            "0x8617E340B3D01FA5F11F306F4090FD50E238070D",
            "0xde709f2102306220921060314715629080e2fb77",
            "0x27b1fdb04752bbc536007a920d24acb045561c26",
        ] {
            let (norm, _) = validate(Chain::Ethereum, a).unwrap();
            assert_eq!(norm.to_ascii_lowercase(), a.to_ascii_lowercase());
            // Mixed-case vectors are already canonical.
            if a[2..].bytes().any(|b| b.is_ascii_lowercase())
                && a[2..].bytes().any(|b| b.is_ascii_uppercase())
            {
                assert_eq!(norm, a);
            }
        }
    }

    #[test]
    fn ethereum_rejects_a_wrong_checksum_and_bad_lengths() {
        assert_eq!(
            validate(
                Chain::Ethereum,
                "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD"
            )
            .unwrap_err(),
            Error::InvalidFormat("address checksum")
        );
        assert!(validate(Chain::Ethereum, "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeA").is_err());
        assert!(validate(Chain::Ethereum, "5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed").is_err());
        assert!(
            validate(
                Chain::Ethereum,
                "0xZZAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
            )
            .is_err()
        );
        // Lower case is accepted and returned checksummed.
        assert_eq!(
            validate(
                Chain::Ethereum,
                "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed"
            )
            .unwrap()
            .0,
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
        );
    }

    #[test]
    fn bitcoin_kinds() {
        let ok = [
            ("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", AddressKind::P2pkh),
            ("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", AddressKind::P2sh),
            (
                "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
                AddressKind::P2wpkh,
            ),
            (
                "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4",
                AddressKind::P2wpkh,
            ),
            (
                "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3",
                AddressKind::P2wsh,
            ),
            (
                "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
                AddressKind::P2tr,
            ),
        ];
        for (a, kind) in ok {
            let (norm, k) = validate(Chain::Bitcoin, a).unwrap();
            assert_eq!(k, kind, "{a}");
            assert_eq!(
                norm,
                if a.starts_with('B') {
                    a.to_ascii_lowercase()
                } else {
                    a.to_owned()
                }
            );
        }
        for a in [
            "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN3",         // checksum
            "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn",         // testnet
            "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", // testnet segwit
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh", // bech32m on v0
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
        ] {
            assert!(validate(Chain::Bitcoin, a).is_err(), "{a}");
        }
    }

    #[test]
    fn solana_needs_32_bytes() {
        let ok = [
            "11111111111111111111111111111111",
            "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
            "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
        ];
        for a in ok {
            assert_eq!(validate(Chain::Solana, a).unwrap().0, a);
        }
        for a in [
            "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
            "1111111111111111111111111111111",   // 31 bytes
            "111111111111111111111111111111111", // 33 bytes
            "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1vO",
        ] {
            assert!(validate(Chain::Solana, a).is_err(), "{a}");
        }
    }

    #[test]
    fn detects_the_chain() {
        assert_eq!(
            detect("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"),
            Some(Chain::Bitcoin)
        );
        assert_eq!(
            detect("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"),
            Some(Chain::Bitcoin)
        );
        assert_eq!(
            detect("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"),
            Some(Chain::Ethereum)
        );
        assert_eq!(
            detect("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"),
            Some(Chain::Solana)
        );
        assert_eq!(detect("hello"), None);
    }
}
