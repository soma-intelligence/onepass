//! UniFFI surface of OnePass for the Swift package VaultKit. Swift never
//! sees vault keys, item keys or the keyset: it gets decrypted items for
//! display and editing only.

mod convert;
mod error;
mod session;
mod types;

use std::path::Path;
use std::sync::Arc;

use onepass_core::account::Auk;
use onepass_core::crypto::{KdfParams, SecretKey};
use onepass_core::generator::{self, CharsetOptions, PassphraseOptions, Recipe, Wordlist};
use onepass_core::model::{self, ItemType, checks::CardBrand};
use onepass_core::repo::Repository;
use onepass_core::sync::SyncStore;
use onepass_core::totp;

use convert::{sections_to_ffi, type_label};
pub use error::OnePassError;
use error::invalid;
pub use session::{Session, SyncStoreHandle};
pub use types::*;

uniffi::setup_scaffolding!();

fn open_store(db_path: &str) -> Result<SyncStore, OnePassError> {
    Ok(SyncStore::open(Path::new(db_path))?)
}

fn create(
    db_path: &str,
    password: &str,
    kdf: KdfParams,
) -> Result<FfiCreatedAccount, OnePassError> {
    let store = open_store(db_path)?;
    if store.has_account()? {
        return Err(invalid("account exists"));
    }
    let (mut repo, secret_key) = Repository::create_account(store, password, kdf)?;
    repo.persist_device_state()?;
    let session = Session::new(repo)?;
    Ok(FfiCreatedAccount {
        account_id: session.account_id(),
        secret_key: secret_key.to_display(),
        session,
    })
}

/// New account with the default (floor) Argon2id parameters. Refuses a
/// store that already holds an account.
#[uniffi::export]
pub fn create_account(
    db_path: String,
    password: String,
) -> Result<FfiCreatedAccount, OnePassError> {
    create(&db_path, &password, KdfParams::new_default()?)
}

/// New account with explicit Argon2id parameters (fresh salt). The core
/// refuses parameters under its floor, except in debug builds with the
/// `dev-fast-kdf` feature: this is how tests make fast accounts.
#[uniffi::export]
pub fn create_account_with_kdf(
    db_path: String,
    password: String,
    kdf: FfiKdfParams,
) -> Result<FfiCreatedAccount, OnePassError> {
    let mut params = KdfParams::new_default()?;
    params.m_kib = kdf.m_kib;
    params.t = kdf.t;
    params.p = kdf.p;
    create(&db_path, &password, params)
}

#[uniffi::export]
pub fn unlock_with_password(
    db_path: String,
    password: String,
    secret_key: String,
) -> Result<FfiUnlocked, OnePassError> {
    let store = open_store(&db_path)?;
    let secret_key = SecretKey::parse(&secret_key)?;
    let device = store.device_state()?;
    let (mut repo, auk) = Repository::unlock_exporting_auk(store, &password, &secret_key, device)?;
    repo.persist_device_state()?;
    Ok(FfiUnlocked {
        session: Session::new(repo)?,
        auk: auk.as_bytes().to_vec(),
    })
}

#[uniffi::export]
pub fn unlock_with_auk(db_path: String, auk: Vec<u8>) -> Result<Arc<Session>, OnePassError> {
    let bytes: [u8; 32] = auk.try_into().map_err(|_| invalid("auk"))?;
    let store = open_store(&db_path)?;
    let device = store.device_state()?;
    let mut repo = Repository::unlock_with_auk(store, &Auk::from_bytes(bytes), device)?;
    repo.persist_device_state()?;
    Session::new(repo)
}

#[uniffi::export]
pub fn has_account(db_path: String) -> Result<bool, OnePassError> {
    Ok(open_store(&db_path)?.has_account()?)
}

#[uniffi::export]
pub fn open_sync_store(db_path: String) -> Result<Arc<SyncStoreHandle>, OnePassError> {
    SyncStoreHandle::open(Path::new(&db_path))
}

/// The canonical display form of a typed Secret Key (lower case, spaces and
/// missing dashes accepted).
#[uniffi::export]
pub fn normalize_secret_key(text: String) -> Result<String, OnePassError> {
    Ok(SecretKey::parse(&text)?.to_display())
}

fn recipe_to_core(r: &FfiPasswordRecipe) -> Result<Recipe, OnePassError> {
    let small = |n: u32| u8::try_from(n).map_err(|_| invalid("recipe"));
    Ok(match r {
        FfiPasswordRecipe::Characters {
            length,
            digits,
            symbols,
            avoid_ambiguous,
        } => Recipe::Random(CharsetOptions {
            length: small(*length)?,
            lower: true,
            upper: true,
            digits: *digits,
            symbols: *symbols,
            avoid_ambiguous: *avoid_ambiguous,
        }),
        FfiPasswordRecipe::Words {
            count,
            separator,
            french,
            capitalize,
        } => Recipe::Passphrase(PassphraseOptions {
            words: small(*count)?,
            separator: separator.clone(),
            capitalize: *capitalize,
            include_digit: false,
            list: if *french {
                Wordlist::FrenchDiceware
            } else {
                Wordlist::EffEnglish
            },
        }),
        FfiPasswordRecipe::Pin { length } => Recipe::Pin {
            digits: small(*length)?,
        },
    })
}

#[uniffi::export]
pub fn generate_password(recipe: FfiPasswordRecipe) -> Result<String, OnePassError> {
    Ok(generator::generate(&recipe_to_core(&recipe)?)?.to_string())
}

/// Entropy in bits; 0 for a recipe the generator would refuse.
#[uniffi::export]
pub fn password_entropy_bits(recipe: FfiPasswordRecipe) -> f64 {
    recipe_to_core(&recipe).map_or(0.0, |r| generator::entropy_bits(&r))
}

/// The code at `unix_seconds` for a bare base32 secret or an `otpauth://`
/// URI.
#[uniffi::export]
pub fn totp_now(secret_or_uri: String, unix_seconds: u64) -> Result<FfiTotpCode, OnePassError> {
    let text = secret_or_uri.trim();
    let is_uri = text
        .get(..10)
        .is_some_and(|p| p.eq_ignore_ascii_case("otpauth://"));
    let cfg = if is_uri {
        totp::parse_otpauth(text)?
    } else {
        totp::totp_from_secret(text)?
    };
    Ok(FfiTotpCode {
        code: totp::code_at(&cfg, unix_seconds)?,
        remaining: totp::seconds_remaining(&cfg, unix_seconds),
        period: cfg.period,
    })
}

/// The 26 types in the order of the spec.
#[uniffi::export]
pub fn item_types() -> Vec<FfiItemTypeInfo> {
    ItemType::ALL
        .iter()
        .map(|t| FfiItemTypeInfo {
            item_type: (*t).into(),
            label: type_label(*t).to_owned(),
        })
        .collect()
}

#[uniffi::export]
pub fn template(item_type: FfiItemType) -> Vec<FfiSection> {
    sections_to_ffi(&model::template(item_type.into()))
}

#[uniffi::export]
pub fn menu_options(item_type: FfiItemType, field_id: String) -> Vec<String> {
    model::menu_options(item_type.into(), &field_id)
        .iter()
        .map(|s| (*s).to_owned())
        .collect()
}

#[uniffi::export]
pub fn card_brand(number: String) -> String {
    match model::checks::card_brand(&number) {
        CardBrand::Visa => "visa",
        CardBrand::Mastercard => "mastercard",
        CardBrand::Amex => "amex",
        CardBrand::Discover => "discover",
        CardBrand::Jcb => "jcb",
        CardBrand::DinersClub => "diners_club",
        CardBrand::UnionPay => "union_pay",
        CardBrand::Maestro => "maestro",
        CardBrand::CartesBancaires => "cartes_bancaires",
        CardBrand::Unknown => "unknown",
    }
    .to_owned()
}

/// The first problem of an item, as a `Validation` error naming the field
/// (never its value), or `None` when it is valid.
#[uniffi::export]
pub fn validate_item(item: FfiItem) -> Option<OnePassError> {
    let now = time::OffsetDateTime::now_utc();
    let core = match convert::item_to_core(&item, &convert::Kept::new(None, true), now) {
        Ok(c) => c,
        Err(e) => return Some(e),
    };
    model::validate(&core).err().map(OnePassError::from)
}
