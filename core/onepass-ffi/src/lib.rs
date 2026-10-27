//! UniFFI surface of OnePass for the Swift package VaultKit. Swift never
//! sees vault keys, item keys or the keyset: it gets decrypted items for
//! display and editing only.

// This crate writes no `unsafe` (the UniFFI scaffolding builds under the lint).
#![deny(unsafe_code)]

mod autofill;
mod companion;
mod convert;
mod error;
mod hardening;
mod import;
mod rules;
mod session;
pub mod timeline;
mod types;
pub mod watchtower;

use std::path::Path;
use std::sync::Arc;

use onepass_core::account::Auk;
use onepass_core::crypto::{KdfParams, SecretKey};
use onepass_core::generator::{self, CharsetOptions, PassphraseOptions, Recipe, Wordlist};
use onepass_core::model::{self, ItemType, checks::CardBrand};
use onepass_core::repo::Repository;
use onepass_core::sync::{AccountState, SyncStore};
use onepass_core::totp;
use zeroize::Zeroizing;

pub use companion::*;
use convert::{sections_to_ffi, type_label};
pub use error::OnePassError;
use error::invalid;
pub use hardening::*;
pub use import::*;
pub use rules::password_from_rules;
pub use session::{Session, SyncStoreHandle};
pub use types::*;

uniffi::setup_scaffolding!();

fn open_store(db_path: &str) -> Result<SyncStore, OnePassError> {
    Ok(SyncStore::open(Path::new(db_path))?)
}

pub(crate) fn create(
    db_path: &str,
    password: &str,
    kdf: KdfParams,
) -> Result<FfiCreatedAccount, OnePassError> {
    let store = open_store(db_path)?;
    match store.account_state()? {
        AccountState::Empty => {}
        AccountState::Present => return Err(invalid("account exists")),
        // This device knew an account the store no longer shows: creating a
        // second one over it is exactly what a hostile store would want.
        AccountState::PinnedButMissing => return Err(account_missing()),
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
    let password = Zeroizing::new(password);
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
    let password = Zeroizing::new(password);
    create(&db_path, &password, kdf_params(kdf)?)
}

/// Explicit Argon2id parameters with a fresh salt. The core checks them
/// against its floor where they are used.
pub(crate) fn kdf_params(kdf: FfiKdfParams) -> Result<KdfParams, OnePassError> {
    let mut params = KdfParams::new_default()?;
    params.m_kib = kdf.m_kib;
    params.t = kdf.t;
    params.p = kdf.p;
    Ok(params)
}

#[uniffi::export]
pub fn unlock_with_password(
    db_path: String,
    password: String,
    secret_key: String,
) -> Result<FfiUnlocked, OnePassError> {
    let (password, secret_key) = (Zeroizing::new(password), Zeroizing::new(secret_key));
    unlock_password(&db_path, &password, &secret_key)
}

pub(crate) fn unlock_password(
    db_path: &str,
    password: &str,
    secret_key: &str,
) -> Result<FfiUnlocked, OnePassError> {
    let store = open_store(db_path)?;
    let secret_key = SecretKey::parse(secret_key)?;
    let device = store.device_state()?;
    let (mut repo, auk) = Repository::unlock_exporting_auk(store, password, &secret_key, device)?;
    repo.persist_device_state()?;
    Ok(FfiUnlocked {
        session: Session::new(repo)?,
        auk: auk.as_bytes().to_vec(),
    })
}

/// Checks a master password and Secret Key against the stored account and
/// returns the Account Unlock Key, without opening a session and without
/// persisting the device state: a throwaway check (reprompt, biometric
/// enrollment) must never write back a device state it read before the
/// Argon2id run, while the live session keeps moving `last_seen` forward.
#[uniffi::export]
pub fn verify_password(
    db_path: String,
    password: String,
    secret_key: String,
) -> Result<Vec<u8>, OnePassError> {
    let (password, secret_key) = (Zeroizing::new(password), Zeroizing::new(secret_key));
    verify(&db_path, &password, &secret_key)
}

pub(crate) fn verify(
    db_path: &str,
    password: &str,
    secret_key: &str,
) -> Result<Vec<u8>, OnePassError> {
    let store = open_store(db_path)?;
    let secret_key = SecretKey::parse(secret_key)?;
    let device = store.device_state()?;
    let (repo, auk) = Repository::unlock_exporting_auk(store, password, &secret_key, device)?;
    drop(repo);
    Ok(auk.as_bytes().to_vec())
}

#[uniffi::export]
pub fn unlock_with_auk(db_path: String, auk: Vec<u8>) -> Result<Arc<Session>, OnePassError> {
    let auk = Zeroizing::new(auk);
    if auk.len() != 32 {
        return Err(invalid("auk"));
    }
    let mut bytes = Zeroizing::new([0u8; 32]);
    bytes.copy_from_slice(&auk);
    let store = open_store(&db_path)?;
    let device = store.device_state()?;
    let mut repo = Repository::unlock_with_auk(store, &Auk::from_bytes(*bytes), device)?;
    repo.persist_device_state()?;
    Session::new(repo)
}

#[uniffi::export]
pub fn has_account(db_path: String) -> Result<bool, OnePassError> {
    Ok(open_store(&db_path)?.has_account()?)
}

/// What the store at `db_path` holds before any unlock: nothing, an account,
/// or (integrity fault) the account this device pinned has disappeared.
#[uniffi::export]
pub fn store_state(db_path: String) -> Result<FfiStoreState, OnePassError> {
    Ok(open_store(&db_path)?.account_state()?.into())
}

/// Empty every table of the store in one transaction, leaving the file in
/// place: connections other parts of the app hold on it (the sync handle)
/// keep working. For an account creation that has to be undone.
#[uniffi::export]
pub fn reset_store(db_path: String) -> Result<(), OnePassError> {
    Ok(open_store(&db_path)?.reset()?)
}

/// "Repartir" from the account-missing screen: empties every table in one
/// transaction, device state included (the pinned account and the last seen
/// manifests), so the Emergency Kit restore (data fetched again) or a new
/// account can start from an empty store. The file stays in place, like
/// `reset_store`. Refused (`InvalidInput`) while the store shows an account:
/// a readable account is never wiped by this path.
#[uniffi::export]
pub fn reset_store_for_recovery(db_path: String) -> Result<(), OnePassError> {
    Ok(open_store(&db_path)?.reset_for_recovery()?)
}

fn account_missing() -> OnePassError {
    OnePassError::Integrity {
        kind: "account_missing".to_owned(),
    }
}

#[uniffi::export]
pub fn open_sync_store(db_path: String) -> Result<Arc<SyncStoreHandle>, OnePassError> {
    SyncStoreHandle::open(Path::new(&db_path))
}

/// The canonical display form of a typed Secret Key (lower case, spaces and
/// missing dashes accepted).
#[uniffi::export]
pub fn normalize_secret_key(text: String) -> Result<String, OnePassError> {
    let text = Zeroizing::new(text);
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

/// Entropy in bits; 0 for a recipe `generate_password` would refuse.
#[uniffi::export]
pub fn password_entropy_bits(recipe: FfiPasswordRecipe) -> f64 {
    let in_range = match &recipe {
        FfiPasswordRecipe::Characters { length, .. } => (8..=100).contains(length),
        FfiPasswordRecipe::Words { count, .. } => (3..=20).contains(count),
        FfiPasswordRecipe::Pin { length } => (4..=12).contains(length),
    };
    if !in_range {
        return 0.0;
    }
    recipe_to_core(&recipe).map_or(0.0, |r| generator::entropy_bits(&r))
}

/// Strength estimate of a typed or stored password in bits, on the scale of
/// `password_entropy_bits`: a generated password gets the bits of its recipe
/// (see `generator::strength_bits`). Never logged.
#[uniffi::export]
pub fn password_strength_bits(password: String) -> f64 {
    let password = Zeroizing::new(password);
    generator::strength_bits(&password)
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
    validate_for_save(core).err().map(OnePassError::from)
}

/// Until attachments exist (milestone 5) the apps cannot fill a `File` field, so a required one
/// counts as satisfied: the item is returned with its empty `File` fields marked not required
/// (the core seals only valid items, so this relaxed copy is what gets stored), then validated.
/// The template itself is unchanged.
pub(crate) fn relax_file_fields(mut item: model::Item) -> model::Item {
    for field in item.sections.iter_mut().flat_map(|s| s.fields.iter_mut()) {
        if field.kind == model::FieldType::File && field.value == model::FieldValue::Empty {
            field.required = false;
        }
    }
    item
}

/// `model::validate` on the relaxed item (see `relax_file_fields`).
pub(crate) fn validate_for_save(item: model::Item) -> onepass_core::Result<model::Item> {
    let relaxed = relax_file_fields(item);
    model::validate(&relaxed)?;
    Ok(relaxed)
}
