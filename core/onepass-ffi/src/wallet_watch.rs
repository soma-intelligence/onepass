//! Watch-only crypto balances (spec 2026-11-02-crypto-watch): format
//! checks of the public data of a crypto wallet item, addresses derived
//! from an xpub, and the explicit derivation of public data from the
//! item's recovery phrase. Nothing here signs or moves funds; the phrase
//! never crosses into Swift for this.

use onepass_core::model::{FieldValue, ItemType};
use onepass_core::wallet_watch::{self, AddressKind, Chain, bip32, seed};
use zeroize::Zeroizing;

use crate::convert::{id_hex, parse_id};
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

/// A new 256-bit key for the app's encrypted balance cache, from the core's
/// hedged random source (`crypto::random`). The app keeps it in its keychain.
#[uniffi::export]
pub fn watch_cache_key() -> Result<Vec<u8>, OnePassError> {
    let mut key = Zeroizing::new(vec![0u8; 32]);
    onepass_core::crypto::random::fill_random(&mut key)?;
    Ok(key.to_vec())
}

fn text(value: &FieldValue) -> Option<&str> {
    match value {
        FieldValue::Mnemonic(s) | FieldValue::Concealed(s) | FieldValue::Password(s) => Some(s),
        FieldValue::Text(s) => Some(s),
        _ => None,
    }
}

/// The public watch data of one crypto wallet item. Read from its public
/// fields only: the phrase and keys never leave the core for this.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiWalletWatch {
    pub vault_id: String,
    pub item_id: String,
    pub title: String,
    /// Valid `public_addresses` entries, canonical, without duplicates.
    pub addresses: Vec<FfiWatchAddress>,
    /// Entries that fail their format check (shown as such, never queried).
    pub invalid_entries: Vec<String>,
    /// The `xpub` field when it parses as an account-level xpub/ypub/zpub.
    pub xpub: Option<String>,
    /// The `xpub` field is filled but does not parse (or is a private key).
    pub xpub_invalid: bool,
    /// A recovery phrase is stored ("Dériver les adresses publiques" can run).
    pub has_phrase: bool,
    /// The phrase is stored without per-item Travel Mode protection.
    pub phrase_unprotected: bool,
}

/// An item the app holds a non-zero watched balance for.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiItemKey {
    pub vault_id: String,
    pub item_id: String,
}

fn wallet_watch_of(item: &onepass_core::model::Item) -> FfiWalletWatch {
    let fields = || item.sections.iter().flat_map(|s| s.fields.iter());
    let mut addresses: Vec<FfiWatchAddress> = Vec::new();
    let mut invalid_entries = Vec::new();
    for f in fields().filter(|f| f.id == "public_addresses") {
        let FieldValue::Text(t) = &f.value else {
            continue;
        };
        if t.trim().is_empty() {
            continue;
        }
        match wallet_watch::parse_entry(t) {
            Ok(a) => {
                let a = to_ffi(&a);
                if !addresses
                    .iter()
                    .any(|b| b.chain == a.chain && b.address == a.address)
                {
                    addresses.push(a);
                }
            }
            Err(_) => invalid_entries.push(t.trim().to_owned()),
        }
    }
    let xpub_text = fields()
        .find(|f| f.id == "xpub")
        .and_then(|f| match &f.value {
            FieldValue::Text(t) if !t.trim().is_empty() => Some(t.trim().to_owned()),
            _ => None,
        });
    let xpub = xpub_text
        .as_ref()
        .filter(|t| bip32::ExtendedPub::parse(t).is_ok())
        .cloned();
    let has_phrase = fields().any(|f| {
        f.id == "recovery_phrase"
            && matches!(&f.value, FieldValue::Mnemonic(s) if !s.trim().is_empty())
    });
    FfiWalletWatch {
        vault_id: id_hex(item.vault_id),
        item_id: id_hex(item.id),
        title: item.title.clone(),
        addresses,
        invalid_entries,
        xpub_invalid: xpub_text.is_some() && xpub.is_none(),
        xpub,
        has_phrase,
        phrase_unprotected: wallet_watch::phrase_unprotected(item),
    }
}

#[uniffi::export]
impl Session {
    /// The watch data of every crypto wallet item not in the trash (archived
    /// ones included), vault by vault.
    pub fn watch_wallets(&self) -> Result<Vec<FfiWalletWatch>, OnePassError> {
        self.with(|repo| {
            let mut out = Vec::new();
            for vault in repo.vaults()? {
                for item in repo.items(&vault)? {
                    if item.item_type != ItemType::CryptoWallet || item.trashed_at.is_some() {
                        continue;
                    }
                    out.push(wallet_watch_of(&item));
                }
            }
            Ok(out)
        })
    }

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
