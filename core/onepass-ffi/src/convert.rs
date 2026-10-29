//! Conversions between the core model and the FFI records.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};

use onepass_core::Id;
use onepass_core::model::{
    Address, AttachmentRef, BarcodeFormat, Field, FieldType, FieldValue, Item, ItemType, ItemUrl,
    Location, LoginMethod, MatchRule, PasskeyCredential, PasswordHistoryEntry, Provider, Section,
    SshKeyValue,
};
use onepass_core::vault::{Vault, VaultMeta};
use time::{Date, Month, OffsetDateTime};
use zeroize::Zeroizing;

use crate::error::{OnePassError, invalid};
use crate::types::*;

// ---- ids, hex, time -------------------------------------------------------

/// 32 lowercase hex characters, no hyphens.
pub(crate) fn id_hex(id: Id) -> String {
    bytes_hex(&id.0)
}

pub(crate) fn bytes_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit(u32::from(b >> 4), 16).unwrap_or('0'));
        s.push(char::from_digit(u32::from(b & 15), 16).unwrap_or('0'));
    }
    s
}

pub(crate) fn hex_bytes(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.is_ascii() {
        return None;
    }
    s.as_bytes()
        .chunks(2)
        .map(|c| {
            let hi = (c[0] as char).to_digit(16)?;
            let lo = (c[1] as char).to_digit(16)?;
            u8::try_from(hi * 16 + lo).ok()
        })
        .collect()
}

pub(crate) fn parse_id(s: &str) -> Result<Id, OnePassError> {
    if s.len() != 32 {
        return Err(invalid("id"));
    }
    let bytes = hex_bytes(s).ok_or_else(|| invalid("id"))?;
    let arr: [u8; 16] = bytes.try_into().map_err(|_| invalid("id"))?;
    Ok(Id(arr))
}

pub(crate) fn ts(t: OffsetDateTime) -> i64 {
    t.unix_timestamp()
}

pub(crate) fn from_ts(secs: i64) -> Result<OffsetDateTime, OnePassError> {
    OffsetDateTime::from_unix_timestamp(secs).map_err(|_| invalid("timestamp"))
}

fn date_to_ffi(d: Date) -> FfiDate {
    FfiDate {
        year: d.year(),
        month: u8::from(d.month()),
        day: d.day(),
    }
}

fn date_to_core(d: &FfiDate) -> Result<Date, OnePassError> {
    let month = Month::try_from(d.month).map_err(|_| invalid("date"))?;
    Date::from_calendar_date(d.year, month, d.day).map_err(|_| invalid("date"))
}

// ---- unit enums -----------------------------------------------------------

macro_rules! mirror {
    ($core:ty, $ffi:ty, [$($v:ident),* $(,)?]) => {
        impl From<$core> for $ffi {
            fn from(v: $core) -> Self {
                match v { $(<$core>::$v => <$ffi>::$v),* }
            }
        }
        impl From<$ffi> for $core {
            fn from(v: $ffi) -> Self {
                match v { $(<$ffi>::$v => <$core>::$v),* }
            }
        }
    };
}

mirror!(
    ItemType,
    FfiItemType,
    [
        Login,
        SecureNote,
        Password,
        Email,
        Server,
        Database,
        Router,
        ApiCredential,
        SshKey,
        CreditCard,
        BankAccount,
        CryptoWallet,
        Subscription,
        Identity,
        IdCard,
        Passport,
        DriverLicense,
        SocialSecurityNumber,
        MedicalRecord,
        Membership,
        RewardProgram,
        Insurance,
        Vehicle,
        AccessCode,
        Document,
        SoftwareLicense,
    ]
);

mirror!(
    FieldType,
    FfiFieldType,
    [
        Text, Concealed, Password, Url, Email, Phone, Date, MonthYear, Number, Money, Address,
        Menu, Otp, Passkey, SshKey, File, Location, Mnemonic, Barcode, ItemLink,
    ]
);

mirror!(
    MatchRule,
    FfiMatchRule,
    [Domain, ExactHost, ExactUrl, Never]
);

mirror!(
    BarcodeFormat,
    FfiBarcodeFormat,
    [Qr, Code128, Pdf417, Aztec, Ean13]
);

/// Singular French label of an item type, for the "new item" picker.
pub(crate) fn type_label(t: ItemType) -> &'static str {
    match t {
        ItemType::Login => "Connexion",
        ItemType::SecureNote => "Note sécurisée",
        ItemType::Password => "Mot de passe",
        ItemType::Email => "Compte email",
        ItemType::Server => "Serveur",
        ItemType::Database => "Base de données",
        ItemType::Router => "Routeur Wi-Fi",
        ItemType::ApiCredential => "Identifiant d'API",
        ItemType::SshKey => "Clé SSH",
        ItemType::CreditCard => "Carte bancaire",
        ItemType::BankAccount => "Compte bancaire",
        ItemType::CryptoWallet => "Portefeuille crypto",
        ItemType::Subscription => "Abonnement",
        ItemType::Identity => "Identité",
        ItemType::IdCard => "Carte d'identité",
        ItemType::Passport => "Passeport",
        ItemType::DriverLicense => "Permis de conduire",
        ItemType::SocialSecurityNumber => "Numéro de sécurité sociale",
        ItemType::MedicalRecord => "Dossier médical",
        ItemType::Membership => "Adhésion",
        ItemType::RewardProgram => "Programme de fidélité",
        ItemType::Insurance => "Assurance",
        ItemType::Vehicle => "Véhicule",
        ItemType::AccessCode => "Code d'accès",
        ItemType::Document => "Document",
        ItemType::SoftwareLicense => "Licence logicielle",
    }
}

// ---- providers ------------------------------------------------------------

fn provider_to_string(p: &Provider) -> String {
    match p {
        Provider::Google => "google".into(),
        Provider::Apple => "apple".into(),
        Provider::Microsoft => "microsoft".into(),
        Provider::GitHub => "github".into(),
        Provider::Facebook => "facebook".into(),
        Provider::X => "x".into(),
        Provider::LinkedIn => "linkedin".into(),
        Provider::Discord => "discord".into(),
        Provider::Slack => "slack".into(),
        Provider::Okta => "okta".into(),
        Provider::EntraId => "entra_id".into(),
        Provider::CustomOidc(d) => format!("oidc:{d}"),
        Provider::CustomSaml(d) => format!("saml:{d}"),
    }
}

fn provider_from_string(s: &str) -> Result<Provider, OnePassError> {
    Ok(match s {
        "google" => Provider::Google,
        "apple" => Provider::Apple,
        "microsoft" => Provider::Microsoft,
        "github" => Provider::GitHub,
        "facebook" => Provider::Facebook,
        "x" => Provider::X,
        "linkedin" => Provider::LinkedIn,
        "discord" => Provider::Discord,
        "slack" => Provider::Slack,
        "okta" => Provider::Okta,
        "entra_id" => Provider::EntraId,
        _ => match s.split_once(':') {
            Some(("oidc", d)) => Provider::CustomOidc(d.to_owned()),
            Some(("saml", d)) => Provider::CustomSaml(d.to_owned()),
            _ => return Err(invalid("provider")),
        },
    })
}

// ---- small records --------------------------------------------------------

fn location_to_ffi(l: &Location) -> FfiLocation {
    FfiLocation {
        label: l.label.clone(),
        address: l.address.clone(),
        lat: l.lat,
        lon: l.lon,
        radius_m: l.radius_m,
        suggest_nearby: l.suggest_nearby,
    }
}

fn location_to_core(l: &FfiLocation) -> Location {
    Location {
        label: l.label.clone(),
        address: l.address.clone(),
        lat: l.lat,
        lon: l.lon,
        radius_m: l.radius_m,
        suggest_nearby: l.suggest_nearby,
    }
}

fn address_to_ffi(a: &Address) -> FfiAddress {
    FfiAddress {
        line1: a.line1.clone(),
        line2: a.line2.clone(),
        city: a.city.clone(),
        postal_code: a.postal_code.clone(),
        region: a.region.clone(),
        country: a.country.clone(),
    }
}

fn address_to_core(a: &FfiAddress) -> Address {
    Address {
        line1: a.line1.clone(),
        line2: a.line2.clone(),
        city: a.city.clone(),
        postal_code: a.postal_code.clone(),
        region: a.region.clone(),
        country: a.country.clone(),
    }
}

fn attachment_to_ffi(a: &AttachmentRef) -> FfiAttachment {
    FfiAttachment {
        id: id_hex(a.id),
        name: a.name.clone(),
        size: a.size,
        mime: a.mime.clone(),
    }
}

fn attachment_to_core(a: &FfiAttachment) -> Result<AttachmentRef, OnePassError> {
    Ok(AttachmentRef {
        id: parse_id(&a.id)?,
        name: a.name.clone(),
        size: a.size,
        mime: a.mime.clone(),
    })
}

// ---- field values ---------------------------------------------------------

fn secret(s: &str) -> Zeroizing<String> {
    Zeroizing::new(s.to_owned())
}

pub(crate) fn value_to_ffi(v: &FieldValue) -> FfiFieldValue {
    match v {
        FieldValue::Text(s) => FfiFieldValue::Text { value: s.clone() },
        FieldValue::Concealed(s) => FfiFieldValue::Concealed {
            value: s.to_string(),
        },
        FieldValue::Password(s) => FfiFieldValue::Password {
            value: s.to_string(),
        },
        FieldValue::Url(s) => FfiFieldValue::Url { value: s.clone() },
        FieldValue::Email(s) => FfiFieldValue::Email { value: s.clone() },
        FieldValue::Phone(s) => FfiFieldValue::Phone { value: s.clone() },
        FieldValue::Date(d) => FfiFieldValue::Date {
            value: date_to_ffi(*d),
        },
        FieldValue::MonthYear { year, month } => FfiFieldValue::MonthYear {
            year: *year,
            month: *month,
        },
        FieldValue::Number(n) => FfiFieldValue::Number { value: *n },
        FieldValue::Money {
            minor_units,
            currency,
        } => FfiFieldValue::Money {
            minor_units: *minor_units,
            currency: currency.clone(),
        },
        FieldValue::Address(a) => FfiFieldValue::Address {
            value: address_to_ffi(a),
        },
        FieldValue::Menu(s) => FfiFieldValue::Menu { value: s.clone() },
        FieldValue::Otp(s) => FfiFieldValue::Otp {
            value: s.to_string(),
        },
        FieldValue::Passkey(p) => FfiFieldValue::Passkey {
            value: FfiPasskey {
                rp_id: p.rp_id.clone(),
                user_name: p.user_name.clone(),
                credential_id_hex: bytes_hex(&p.credential_id),
                created_at: ts(p.created_at),
            },
        },
        FieldValue::SshKey(k) => FfiFieldValue::SshKey {
            value: FfiSshKey {
                private_pem: k.private_pem.to_string(),
                public_openssh: k.public_openssh.clone(),
                fingerprint_sha256: k.fingerprint_sha256.clone(),
            },
        },
        FieldValue::File(a) => FfiFieldValue::File {
            value: attachment_to_ffi(a),
        },
        FieldValue::Location(l) => FfiFieldValue::Location {
            value: location_to_ffi(l),
        },
        FieldValue::Mnemonic(s) => FfiFieldValue::Mnemonic {
            value: s.to_string(),
        },
        FieldValue::Barcode { value, format } => FfiFieldValue::Barcode {
            value: value.clone(),
            format: (*format).into(),
        },
        FieldValue::ItemLink(id) => FfiFieldValue::ItemLink {
            item_id: id_hex(*id),
        },
        FieldValue::Empty => FfiFieldValue::Empty,
    }
}

/// What a save keeps from the stored item and cannot get from the UI.
pub(crate) struct Kept<'a> {
    stored: Option<&'a Item>,
    passkeys: HashMap<Vec<u8>, &'a PasskeyCredential>,
    /// Unknown passkeys become empty ones instead of an error (validation
    /// only: such an item is never written).
    lenient: bool,
    /// Credential ids met so far in this item: a duplicate is refused.
    seen: RefCell<HashSet<Vec<u8>>>,
}

impl<'a> Kept<'a> {
    pub(crate) fn new(stored: Option<&'a Item>, lenient: bool) -> Kept<'a> {
        let mut passkeys = HashMap::new();
        if let Some(item) = stored {
            for f in item.sections.iter().flat_map(|s| s.fields.iter()) {
                if let FieldValue::Passkey(p) = &f.value {
                    passkeys.insert(p.credential_id.clone(), p);
                }
            }
        }
        Kept {
            stored,
            passkeys,
            lenient,
            seen: RefCell::new(HashSet::new()),
        }
    }
}

fn value_to_core(v: &FfiFieldValue, kept: &Kept<'_>) -> Result<FieldValue, OnePassError> {
    Ok(match v {
        FfiFieldValue::Text { value } => FieldValue::Text(value.clone()),
        FfiFieldValue::Concealed { value } => FieldValue::Concealed(secret(value)),
        FfiFieldValue::Password { value } => FieldValue::Password(secret(value)),
        FfiFieldValue::Url { value } => FieldValue::Url(value.clone()),
        FfiFieldValue::Email { value } => FieldValue::Email(value.clone()),
        FfiFieldValue::Phone { value } => FieldValue::Phone(value.clone()),
        FfiFieldValue::Date { value } => FieldValue::Date(date_to_core(value)?),
        FfiFieldValue::MonthYear { year, month } => {
            if !(1..=12).contains(month) {
                return Err(invalid("month"));
            }
            FieldValue::MonthYear {
                year: *year,
                month: *month,
            }
        }
        FfiFieldValue::Number { value } => FieldValue::Number(*value),
        FfiFieldValue::Money {
            minor_units,
            currency,
        } => FieldValue::Money {
            minor_units: *minor_units,
            currency: currency.clone(),
        },
        FfiFieldValue::Address { value } => FieldValue::Address(address_to_core(value)),
        FfiFieldValue::Menu { value } => FieldValue::Menu(value.clone()),
        FfiFieldValue::Otp { value } => FieldValue::Otp(secret(value)),
        FfiFieldValue::Passkey { value } => {
            let cred_id = hex_bytes(&value.credential_id_hex).ok_or_else(|| invalid("passkey"))?;
            if !kept.seen.borrow_mut().insert(cred_id.clone()) {
                return Err(invalid("passkey"));
            }
            match kept.passkeys.get(&cred_id) {
                // Only the display name is editable.
                Some(old) => FieldValue::Passkey(PasskeyCredential {
                    rp_id: old.rp_id.clone(),
                    user_name: value.user_name.clone(),
                    user_handle: old.user_handle.clone(),
                    credential_id: cred_id,
                    private_key: old.private_key.clone(),
                    created_at: old.created_at,
                }),
                None if kept.lenient => FieldValue::Passkey(PasskeyCredential {
                    rp_id: value.rp_id.clone(),
                    user_name: value.user_name.clone(),
                    user_handle: Vec::new(),
                    credential_id: cred_id,
                    private_key: Zeroizing::new(Vec::new()),
                    created_at: from_ts(value.created_at)?,
                }),
                None => return Err(invalid("passkey")),
            }
        }
        FfiFieldValue::SshKey { value } => FieldValue::SshKey(SshKeyValue {
            private_pem: secret(&value.private_pem),
            public_openssh: value.public_openssh.clone(),
            fingerprint_sha256: value.fingerprint_sha256.clone(),
        }),
        FfiFieldValue::File { value } => FieldValue::File(attachment_to_core(value)?),
        FfiFieldValue::Location { value } => FieldValue::Location(location_to_core(value)),
        FfiFieldValue::Mnemonic { value } => FieldValue::Mnemonic(secret(value)),
        FfiFieldValue::Barcode { value, format } => FieldValue::Barcode {
            value: value.clone(),
            format: (*format).into(),
        },
        FfiFieldValue::ItemLink { item_id } => FieldValue::ItemLink(parse_id(item_id)?),
        FfiFieldValue::Empty => FieldValue::Empty,
    })
}

// ---- sections -------------------------------------------------------------

pub(crate) fn sections_to_ffi(sections: &[Section]) -> Vec<FfiSection> {
    sections
        .iter()
        .map(|s| FfiSection {
            id: s.id.clone(),
            label: s.label.clone(),
            fields: s
                .fields
                .iter()
                .map(|f| FfiField {
                    id: f.id.clone(),
                    label: f.label.clone(),
                    kind: f.kind.into(),
                    value: value_to_ffi(&f.value),
                    required: f.required,
                    repeatable: f.repeatable,
                    autofill: f.autofill,
                })
                .collect(),
        })
        .collect()
}

fn sections_to_core(
    sections: &[FfiSection],
    kept: &Kept<'_>,
) -> Result<Vec<Section>, OnePassError> {
    sections
        .iter()
        .map(|s| {
            Ok(Section {
                id: s.id.clone(),
                label: s.label.clone(),
                fields: s
                    .fields
                    .iter()
                    .map(|f| {
                        Ok(Field {
                            id: f.id.clone(),
                            label: f.label.clone(),
                            kind: f.kind.into(),
                            value: value_to_core(&f.value, kept)?,
                            required: f.required,
                            repeatable: f.repeatable,
                            autofill: f.autofill,
                        })
                    })
                    .collect::<Result<Vec<_>, OnePassError>>()?,
            })
        })
        .collect()
}

// ---- items ----------------------------------------------------------------

fn login_method_to_ffi(m: &LoginMethod) -> FfiLoginMethod {
    match m {
        LoginMethod::Password => FfiLoginMethod::Password,
        LoginMethod::Passkey => FfiLoginMethod::Passkey,
        LoginMethod::Provider {
            provider,
            account,
            relay_email,
        } => FfiLoginMethod::Provider {
            provider: provider_to_string(provider),
            account_item_id: id_hex(*account),
            relay_email: relay_email.clone(),
        },
    }
}

fn login_method_to_core(m: &FfiLoginMethod) -> Result<LoginMethod, OnePassError> {
    Ok(match m {
        FfiLoginMethod::Password => LoginMethod::Password,
        FfiLoginMethod::Passkey => LoginMethod::Passkey,
        FfiLoginMethod::Provider {
            provider,
            account_item_id,
            relay_email,
        } => LoginMethod::Provider {
            provider: provider_from_string(provider)?,
            account: parse_id(account_item_id)?,
            relay_email: relay_email.clone(),
        },
    })
}

fn count(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

pub(crate) fn item_to_ffi(i: &Item) -> FfiItem {
    FfiItem {
        id: id_hex(i.id),
        vault_id: id_hex(i.vault_id),
        item_type: i.item_type.into(),
        title: i.title.clone(),
        tags: i.tags.clone(),
        favorite: i.favorite,
        color: i.color.clone(),
        notes: i.notes.clone(),
        urls: i
            .urls
            .iter()
            .map(|u| FfiUrl {
                label: u.label.clone(),
                url: u.url.clone(),
                rule: u.rule.into(),
                primary: u.primary,
            })
            .collect(),
        apps: i.apps.clone(),
        locations: i.locations.iter().map(location_to_ffi).collect(),
        login_methods: i.login_methods.iter().map(login_method_to_ffi).collect(),
        sections: sections_to_ffi(&i.sections),
        expires: i.expires.map(date_to_ffi),
        rotate_every_days: i.rotate_every_days,
        reprompt: i.reprompt,
        hide_from_autofill: i.hide_from_autofill,
        watchtower_exclusions: i.watchtower_exclusions.clone(),
        on_watch: i.on_watch,
        archived: i.archived,
        trashed_at: i.trashed_at.map(ts),
        created_at: ts(i.created_at),
        updated_at: ts(i.updated_at),
        password_history_count: count(i.password_history.len()),
        attachment_count: count(i.attachments.len()),
    }
}

pub(crate) fn summary(i: &Item) -> FfiItemSummary {
    let primary = i
        .urls
        .iter()
        .find(|u| u.primary)
        .or_else(|| i.urls.first())
        .map(|u| u.url.clone());
    FfiItemSummary {
        id: id_hex(i.id),
        vault_id: id_hex(i.vault_id),
        item_type: i.item_type.into(),
        title: i.title.clone(),
        subtitle: i.subtitle(),
        favorite: i.favorite,
        tags: i.tags.clone(),
        primary_url: primary,
        archived: i.archived,
        trashed_at: i.trashed_at.map(ts),
        created_at: ts(i.created_at),
        updated_at: ts(i.updated_at),
        sign_in_provider: i.login_methods.iter().find_map(|m| match m {
            LoginMethod::Provider { provider, .. } => Some(provider_to_string(provider)),
            _ => None,
        }),
    }
}

fn password_of(item: &Item) -> Option<&str> {
    if !matches!(item.item_type, ItemType::Login | ItemType::Password) {
        return None;
    }
    match item.field("password").map(|f| &f.value) {
        Some(FieldValue::Password(p)) => Some(p.as_str()),
        _ => None,
    }
}

/// Build the core item to write. What the UI cannot carry comes from the
/// stored item: custom icon, attachments, password history, passkey
/// private keys, creation date, archive and trash state. A changed password
/// pushes the old value onto the history. `updated_at` is `now`.
pub(crate) fn item_to_core(
    f: &FfiItem,
    kept: &Kept<'_>,
    now: OffsetDateTime,
) -> Result<Item, OnePassError> {
    let stored = kept.stored;
    let mut item = Item {
        id: parse_id(&f.id)?,
        vault_id: parse_id(&f.vault_id)?,
        item_type: f.item_type.into(),
        title: f.title.clone(),
        tags: f.tags.clone(),
        favorite: f.favorite,
        color: f.color.clone(),
        custom_icon: stored.and_then(|s| s.custom_icon.clone()),
        notes: f.notes.clone(),
        urls: f
            .urls
            .iter()
            .map(|u| ItemUrl {
                label: u.label.clone(),
                url: u.url.clone(),
                rule: u.rule.into(),
                primary: u.primary,
            })
            .collect(),
        apps: f.apps.clone(),
        locations: f.locations.iter().map(location_to_core).collect(),
        login_methods: f
            .login_methods
            .iter()
            .map(login_method_to_core)
            .collect::<Result<_, _>>()?,
        sections: sections_to_core(&f.sections, kept)?,
        attachments: stored.map(|s| s.attachments.clone()).unwrap_or_default(),
        expires: f.expires.as_ref().map(date_to_core).transpose()?,
        rotate_every_days: f.rotate_every_days,
        reprompt: f.reprompt,
        hide_from_autofill: f.hide_from_autofill,
        watchtower_exclusions: f.watchtower_exclusions.clone(),
        on_watch: f.on_watch,
        archived: stored.map_or(f.archived, |s| s.archived),
        trashed_at: match stored {
            Some(s) => s.trashed_at,
            None => f.trashed_at.map(from_ts).transpose()?,
        },
        created_at: match stored {
            Some(s) => s.created_at,
            None => from_ts(f.created_at)?,
        },
        updated_at: now,
        password_history: stored
            .map(|s| s.password_history.clone())
            .unwrap_or_default(),
        events: stored.map(|s| s.events.clone()).unwrap_or_default(),
        usage: stored.map(|s| s.usage.clone()).unwrap_or_default(),
        usage_forgotten: stored
            .map(|s| s.usage_forgotten.clone())
            .unwrap_or_default(),
    };
    if let Some(old) = stored.and_then(password_of)
        && !old.is_empty()
        && password_of(&item) != Some(old)
    {
        item.password_history.push(PasswordHistoryEntry {
            value: secret(old),
            replaced_at: now,
        });
    }
    Ok(item)
}

// ---- vaults ---------------------------------------------------------------

pub(crate) fn meta_to_ffi(m: &VaultMeta) -> FfiVaultMeta {
    FfiVaultMeta {
        name: m.name.clone(),
        icon: m.icon.clone(),
        color: m.color.clone(),
        travel_safe: m.travel_safe,
        mcp_access: m.mcp_access,
    }
}

pub(crate) fn meta_to_core(m: &FfiVaultMeta) -> VaultMeta {
    VaultMeta {
        name: m.name.clone(),
        icon: m.icon.clone(),
        color: m.color.clone(),
        travel_safe: m.travel_safe,
        mcp_access: m.mcp_access,
    }
}

pub(crate) fn vault_to_ffi(v: &Vault, item_count: u32) -> FfiVault {
    FfiVault {
        id: id_hex(v.id),
        meta: meta_to_ffi(&v.meta),
        item_count,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_hex_roundtrips_without_hyphens() {
        let id = Id::new();
        let h = id_hex(id);
        assert_eq!(h.len(), 32);
        assert!(!h.contains('-'));
        assert_eq!(h, h.to_lowercase());
        assert_eq!(parse_id(&h).unwrap(), id);
    }

    #[test]
    fn bad_ids_are_refused() {
        assert!(parse_id("zz").is_err());
        assert!(parse_id(&"g".repeat(32)).is_err());
        assert!(parse_id(&"é".repeat(16)).is_err());
    }
}
