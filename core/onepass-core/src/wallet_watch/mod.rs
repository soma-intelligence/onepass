//! Watch-only data of a crypto wallet item (spec 2026-11-02-crypto-watch):
//! public addresses and account-level extended public keys, their format
//! checks, and the local derivation of addresses from an xpub. Nothing here
//! signs, sends or holds a key that can move funds: an extended private key
//! is refused, and a recovery phrase is read only by the explicit
//! [`seed::derive_public`], which returns public data alone.
//!
//! The data lives in the item's existing fields: `public_addresses`
//! (repeatable, one `"<réseau>, <adresse>"` entry each, or a bare address)
//! and `xpub`.

pub mod address;
pub mod bip32;
pub mod encoding;
pub mod seed;

use crate::model::{FieldValue, Item, ItemType};
use crate::{Error, Result};

/// Reserved tags of the per-item Travel Mode protection (spec
/// 2026-11-02-travel-detection-and-items): an item that leaves the device in
/// Travel Mode, and one behind extra protection. Read here by their text so
/// the check works whether or not the travel feature is on this build.
const TRAVEL_PROTECTION_TAGS: [&str; 2] = ["onepass:travel-hidden", "onepass:travel-guard"];

/// Largest number of addresses one derivation call returns (a gap-limit
/// scan asks again for more).
pub const MAX_DERIVED: u32 = 1000;
/// BIP44 gap limit: a scan stops after this many unused addresses in a row.
pub const GAP_LIMIT: u32 = 20;

/// Chains the watch supports. New ones (EVM networks share Ethereum's
/// address format) add a variant and a provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Chain {
    Bitcoin,
    Ethereum,
    Solana,
}

impl Chain {
    pub const ALL: [Chain; 3] = [Chain::Bitcoin, Chain::Ethereum, Chain::Solana];

    /// The network word written before an address in `public_addresses`.
    pub fn label(self) -> &'static str {
        match self {
            Chain::Bitcoin => "Bitcoin",
            Chain::Ethereum => "Ethereum",
            Chain::Solana => "Solana",
        }
    }

    /// A network word typed by the user (any case): the name, the ticker,
    /// or a common alias.
    pub fn from_word(word: &str) -> Option<Chain> {
        match word.trim().to_lowercase().as_str() {
            "bitcoin" | "btc" | "xbt" => Some(Chain::Bitcoin),
            "ethereum" | "eth" | "ether" | "erc20" | "erc-20" => Some(Chain::Ethereum),
            "solana" | "sol" => Some(Chain::Solana),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressKind {
    /// Legacy `1...`.
    P2pkh,
    /// Script hash `3...` (a ypub's addresses are of this form).
    P2sh,
    /// P2SH-wrapped segwit, the script of a ypub.
    P2shP2wpkh,
    /// Native segwit `bc1q...` of 20 bytes.
    P2wpkh,
    /// Native segwit `bc1q...` of 32 bytes.
    P2wsh,
    /// Taproot `bc1p...`.
    P2tr,
    /// A future segwit version.
    SegwitOther,
    /// An account-model chain (Ethereum, Solana).
    Account,
}

/// One watched address, canonical.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchAddress {
    pub chain: Chain,
    pub address: String,
    pub kind: AddressKind,
}

const UNKNOWN_NETWORK: Error = Error::InvalidFormat("network");

/// Parse one `public_addresses` entry: `"<réseau>, <adresse>"`,
/// `"<réseau>: <adresse>"`, or a bare address whose chain is detected. A
/// named network must match the address's format.
pub fn parse_entry(text: &str) -> Result<WatchAddress> {
    let text = text.trim();
    let (chain, addr) = match text.split_once([',', ':', ';']) {
        Some((network, addr)) => (
            Chain::from_word(network).ok_or(UNKNOWN_NETWORK)?,
            addr.trim(),
        ),
        None => (
            address::detect(text).ok_or(Error::InvalidFormat("address"))?,
            text,
        ),
    };
    let (address, kind) = address::validate(chain, addr)?;
    Ok(WatchAddress {
        chain,
        address,
        kind,
    })
}

/// The entry text stored for an address: `"Bitcoin, bc1q..."`.
pub fn entry_text(addr: &WatchAddress) -> String {
    format!("{}, {}", addr.chain.label(), addr.address)
}

/// Watchtower (spec section 7): a crypto wallet item that stores a
/// recovery phrase without per-item Travel Mode protection. The app raises
/// the alert only for wallets whose watched balance is not zero.
pub fn phrase_unprotected(item: &Item) -> bool {
    if item.item_type != ItemType::CryptoWallet || item.trashed_at.is_some() {
        return false;
    }
    let has_phrase = item
        .field("recovery_phrase")
        .is_some_and(|f| matches!(&f.value, FieldValue::Mnemonic(s) if !s.trim().is_empty()));
    has_phrase
        && !item
            .tags
            .iter()
            .any(|t| TRAVEL_PROTECTION_TAGS.contains(&t.as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Id;
    use crate::model::new_item;
    use zeroize::Zeroizing;

    #[test]
    fn phrase_without_travel_protection() {
        let mut item = new_item(ItemType::CryptoWallet, Id::new(), "Ledger");
        assert!(!phrase_unprotected(&item), "no phrase");
        for f in item.sections.iter_mut().flat_map(|s| s.fields.iter_mut()) {
            if f.id == "recovery_phrase" {
                f.value = FieldValue::Mnemonic(Zeroizing::new("abandon about".into()));
            }
        }
        assert!(phrase_unprotected(&item));
        for tag in TRAVEL_PROTECTION_TAGS {
            let mut tagged = item.clone();
            tagged.tags.push(tag.into());
            assert!(!phrase_unprotected(&tagged), "{tag}");
        }
        let login = new_item(ItemType::Login, Id::new(), "x");
        assert!(!phrase_unprotected(&login));
    }

    #[test]
    fn parses_named_and_bare_entries() {
        let a = parse_entry("Ethereum, 0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed").unwrap();
        assert_eq!(a.chain, Chain::Ethereum);
        assert_eq!(a.address, "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed");
        assert_eq!(
            entry_text(&a),
            "Ethereum, 0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
        );

        let b = parse_entry("  btc: bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq ").unwrap();
        assert_eq!((b.chain, b.kind), (Chain::Bitcoin, AddressKind::P2wpkh));

        let s = parse_entry("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v").unwrap();
        assert_eq!(s.chain, Chain::Solana);
    }

    #[test]
    fn a_named_network_must_match_the_address() {
        assert!(parse_entry("Solana, bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq").is_err());
        assert_eq!(
            parse_entry("Dogecoin, DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L").unwrap_err(),
            UNKNOWN_NETWORK
        );
        assert!(parse_entry("not an address").is_err());
    }
}
