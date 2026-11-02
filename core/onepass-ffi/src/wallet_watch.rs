//! Watch-only crypto balances (spec 2026-11-02-crypto-watch): format
//! checks of the public data of a crypto wallet item, addresses derived
//! from an xpub, and the explicit derivation of public data from the
//! item's recovery phrase. Nothing here signs or moves funds; the phrase
//! never crosses into Swift for this.

use onepass_core::model::{FieldValue, ItemType};
use onepass_core::wallet_watch::{self, AddressKind, Chain, bip32, seed};
use zeroize::Zeroizing;

use crate::convert::parse_id;
use crate::error::{OnePassError, invalid};
use crate::session::{Session, find_item, find_vault};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, uniffi::Enum)]
pub enum FfiWatchChain {
    Bitcoin,
    Ethereum,
    Solana,
}

impl From<Chain> for FfiWatchChain {
    fn from(c: Chain) -> Self {
        match c {
            Chain::Bitcoin => Self::Bitcoin,
            Chain::Ethereum => Self::Ethereum,
            Chain::Solana => Self::Solana,
        }
    }
}

impl From<FfiWatchChain> for Chain {
    fn from(c: FfiWatchChain) -> Self {
        match c {
            FfiWatchChain::Bitcoin => Self::Bitcoin,
            FfiWatchChain::Ethereum => Self::Ethereum,
            FfiWatchChain::Solana => Self::Solana,
        }
    }
}

/// One canonical watched address.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiWatchAddress {
    pub chain: FfiWatchChain,
    pub address: String,
    /// `p2pkh`, `p2sh`, `p2wpkh`, `p2wsh`, `p2tr`, `segwit` or `account`.
    pub kind: String,
    /// The text to store in `public_addresses`: `"Bitcoin, bc1q..."`.
    pub entry: String,
}

/// Public data derived from the item's phrase.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiWalletPublic {
    pub bitcoin_zpub: String,
    pub ethereum_address: String,
    pub solana_address: String,
}

fn kind_name(k: AddressKind) -> &'static str {
    match k {
        AddressKind::P2pkh => "p2pkh",
        AddressKind::P2sh | AddressKind::P2shP2wpkh => "p2sh",
        AddressKind::P2wpkh => "p2wpkh",
        AddressKind::P2wsh => "p2wsh",
        AddressKind::P2tr => "p2tr",
        AddressKind::SegwitOther => "segwit",
        AddressKind::Account => "account",
    }
}

fn to_ffi(a: &wallet_watch::WatchAddress) -> FfiWatchAddress {
    FfiWatchAddress {
        chain: a.chain.into(),
        address: a.address.clone(),
        kind: kind_name(a.kind).to_owned(),
        entry: wallet_watch::entry_text(a),
    }
}

/// One `public_addresses` entry (`"<réseau>, <adresse>"` or a bare
/// address), checked with its checksum and made canonical.
#[uniffi::export]
pub fn watch_parse_entry(text: String) -> Result<FfiWatchAddress, OnePassError> {
    Ok(to_ffi(&wallet_watch::parse_entry(&text)?))
}

/// An address of `chain`, checked and made canonical.
#[uniffi::export]
pub fn watch_validate_address(
    chain: FfiWatchChain,
    text: String,
) -> Result<FfiWatchAddress, OnePassError> {
    let chain: Chain = chain.into();
    let (address, kind) = wallet_watch::address::validate(chain, &text)?;
    Ok(to_ffi(&wallet_watch::WatchAddress {
        chain,
        address,
        kind,
    }))
}

/// Script of an account-level xpub/ypub/zpub (`p2pkh`, `p2sh`, `p2wpkh`).
/// An extended private key is refused (`InvalidInput`, "extended private
/// key").
#[uniffi::export]
pub fn watch_xpub_kind(xpub: String) -> Result<String, OnePassError> {
    Ok(kind_name(bip32::ExtendedPub::parse(&xpub)?.script()).to_owned())
}

/// `count` (at most 1000) receive or change addresses of an account-level
/// extended public key, from index `start`.
#[uniffi::export]
pub fn watch_xpub_addresses(
    xpub: String,
    change: bool,
    start: u32,
    count: u32,
) -> Result<Vec<String>, OnePassError> {
    Ok(bip32::derive_addresses(&xpub, change, start, count)?)
}

/// BIP44 gap limit the scans use.
#[uniffi::export]
pub fn watch_gap_limit() -> u32 {
    wallet_watch::GAP_LIMIT
}

fn text(value: &FieldValue) -> Option<&str> {
    match value {
        FieldValue::Mnemonic(s) | FieldValue::Concealed(s) | FieldValue::Password(s) => Some(s),
        FieldValue::Text(s) => Some(s),
        _ => None,
    }
}

/// An item the app holds a non-zero watched balance for.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiItemKey {
    pub vault_id: String,
    pub item_id: String,
}

#[uniffi::export]
impl Session {
    /// Watchtower: among `funded` (wallets with a non-zero watched balance),
    /// those that store a recovery phrase without per-item Travel Mode
    /// protection. Unknown or unreadable items are left out.
    pub fn watch_unprotected_wallets(
        &self,
        funded: Vec<FfiItemKey>,
    ) -> Result<Vec<FfiItemKey>, OnePassError> {
        self.with(|repo| {
            let mut out = Vec::new();
            for key in &funded {
                let (Ok(vid), Ok(iid)) = (parse_id(&key.vault_id), parse_id(&key.item_id)) else {
                    continue;
                };
                let Ok(vault) = find_vault(repo, vid) else {
                    continue;
                };
                if let Ok(item) = find_item(repo, &vault, iid)
                    && wallet_watch::phrase_unprotected(&item)
                {
                    out.push(key.clone());
                }
            }
            Ok(out)
        })
    }

    /// "Dériver les adresses publiques de cette phrase": reads the stored
    /// recovery phrase (and BIP39 passphrase) of a crypto wallet item in
    /// memory, derives the public watch data, wipes the secrets and returns
    /// public data only. Stores nothing: the app adds the result to the
    /// item's `xpub` and `public_addresses` fields and saves.
    pub fn watch_derive_public(
        &self,
        vault_id: String,
        item_id: String,
    ) -> Result<FfiWalletPublic, OnePassError> {
        let (vault_id, item_id) = (parse_id(&vault_id)?, parse_id(&item_id)?);
        self.with(|repo| {
            let vault = find_vault(repo, vault_id)?;
            let item = find_item(repo, &vault, item_id)?;
            if item.item_type != ItemType::CryptoWallet {
                return Err(invalid("not a crypto wallet"));
            }
            let field = |id: &str| {
                Zeroizing::new(
                    item.sections
                        .iter()
                        .flat_map(|s| s.fields.iter())
                        .find(|f| f.id == id)
                        .and_then(|f| text(&f.value))
                        .unwrap_or_default()
                        .to_owned(),
                )
            };
            let phrase = field("recovery_phrase");
            let passphrase = field("bip39_passphrase");
            if phrase.trim().is_empty() {
                return Err(invalid("recovery phrase"));
            }
            let public = seed::derive_public(&phrase, &passphrase)?;
            Ok(FfiWalletPublic {
                bitcoin_zpub: public.bitcoin_zpub,
                ethereum_address: public.ethereum_address,
                solana_address: public.solana_address,
            })
        })
    }
}
