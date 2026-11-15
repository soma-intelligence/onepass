//! What crosses the IPC to the web view (spec 2026-10-30 section 3.2): item
//! summaries without secrets, and item details whose secret fields carry no
//! value. A secret reaches the web view only through `reveal_field`, when
//! the user asks to see it; a copy never crosses (`copy_field`).

use onepass_ffi::{
    FfiFieldType, FfiFieldValue, FfiItem, FfiItemSummary, FfiItemType, FfiVault, OnePassError,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// An error the UI can show: a stable code, never a field value.
#[derive(Debug, Serialize)]
pub struct UiError {
    pub code: String,
    pub detail: String,
}

impl From<OnePassError> for UiError {
    fn from(e: OnePassError) -> Self {
        if let OnePassError::Validation { field, reason } = &e {
            return UiError {
                code: "Validation".into(),
                detail: format!("{field}: {reason}"),
            };
        }
        // The FFI error's Debug never carries a value (onepass-ffi error.rs).
        let detail = format!("{e:?}");
        let code = detail
            .split(|c: char| !c.is_ascii_alphanumeric())
            .next()
            .unwrap_or("Error")
            .to_owned();
        UiError { code, detail }
    }
}

impl From<String> for UiError {
    fn from(detail: String) -> Self {
        UiError {
            code: "Device".into(),
            detail,
        }
    }
}

impl From<&str> for UiError {
    fn from(detail: &str) -> Self {
        detail.to_owned().into()
    }
}

pub type UiResult<T> = Result<T, UiError>;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultView {
    pub id: String,
    pub name: String,
    pub icon: String,
    pub color: String,
    pub item_count: u32,
}

impl From<FfiVault> for VaultView {
    fn from(v: FfiVault) -> Self {
        VaultView {
            id: v.id,
            name: v.meta.name,
            icon: v.meta.icon,
            color: v.meta.color,
            item_count: v.item_count,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SummaryView {
    pub id: String,
    pub vault_id: String,
    pub item_type: &'static str,
    pub title: String,
    pub subtitle: String,
    pub favorite: bool,
    pub primary_url: Option<String>,
    pub archived: bool,
    pub trashed: bool,
    pub trashed_at: Option<i64>,
    pub updated_at: i64,
    pub tags: Vec<String>,
}

impl From<FfiItemSummary> for SummaryView {
    fn from(s: FfiItemSummary) -> Self {
        SummaryView {
            id: s.id,
            vault_id: s.vault_id,
            item_type: type_key(s.item_type),
            title: s.title,
            subtitle: s.subtitle,
            favorite: s.favorite,
            primary_url: s.primary_url,
            archived: s.archived,
            trashed: s.trashed_at.is_some(),
            trashed_at: s.trashed_at,
            updated_at: s.updated_at,
            tags: s.tags,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FieldView {
    pub id: String,
    pub label: String,
    pub kind: &'static str,
    /// `None` for a secret field (and for an empty one).
    pub value: Option<String>,
    pub secret: bool,
    pub has_value: bool,
    /// For a password: its strength level, 0 (too short) to 4 (excellent).
    /// The level only, never the value.
    pub strength: Option<u8>,
    /// The parts of a date, month-year or address, for the editor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<FieldInput>,
    /// The choices of a menu field.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub options: Vec<String>,
}

/// A value the editor sends (and, for the structured kinds, receives). A
/// text is read according to the kind of the field it goes to.
#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum FieldInput {
    Text {
        value: Zeroizing<String>,
    },
    Date {
        year: i32,
        month: u8,
        day: u8,
    },
    MonthYear {
        year: u16,
        month: u8,
    },
    #[serde(rename_all = "camelCase")]
    Address {
        line1: String,
        line2: String,
        postal_code: String,
        city: String,
        region: String,
        country: String,
    },
    Empty,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentView {
    pub id: String,
    pub name: String,
    pub size: u64,
    pub mime: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SectionView {
    pub id: String,
    pub label: String,
    pub fields: Vec<FieldView>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UrlView {
    pub label: String,
    pub url: String,
    pub rule: &'static str,
}

pub fn rule_key(r: onepass_ffi::FfiMatchRule) -> &'static str {
    use onepass_ffi::FfiMatchRule as R;
    match r {
        R::Domain => "domain",
        R::ExactHost => "exactHost",
        R::ExactUrl => "exactUrl",
        R::Never => "never",
    }
}

pub fn rule_from_key(k: &str) -> Option<onepass_ffi::FfiMatchRule> {
    use onepass_ffi::FfiMatchRule as R;
    Some(match k {
        "domain" => R::Domain,
        "exactHost" => R::ExactHost,
        "exactUrl" => R::ExactUrl,
        "never" => R::Never,
        _ => return None,
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemView {
    pub id: String,
    pub vault_id: String,
    pub item_type: &'static str,
    pub title: String,
    pub favorite: bool,
    pub notes: String,
    pub tags: Vec<String>,
    pub urls: Vec<UrlView>,
    pub sections: Vec<SectionView>,
    pub created_at: i64,
    pub updated_at: i64,
    pub trashed: bool,
    pub archived: bool,
    pub password_history_count: u32,
    pub attachments: Vec<AttachmentView>,
    pub travel_hidden: bool,
    pub travel_guard: bool,
}

/// The iPhone strength meter's levels: thresholds at 40, 60, 80 and 100 bits.
pub fn strength_level(bits: f64) -> u8 {
    [40.0, 60.0, 80.0, 100.0]
        .iter()
        .filter(|t| bits >= **t)
        .count() as u8
}

impl From<&FfiItem> for ItemView {
    fn from(i: &FfiItem) -> Self {
        ItemView {
            id: i.id.clone(),
            vault_id: i.vault_id.clone(),
            item_type: type_key(i.item_type),
            title: i.title.clone(),
            favorite: i.favorite,
            notes: i.notes.clone(),
            tags: i.tags.clone(),
            urls: i
                .urls
                .iter()
                .map(|u| UrlView {
                    label: u.label.clone(),
                    url: u.url.clone(),
                    rule: rule_key(u.rule),
                })
                .collect(),
            sections: i
                .sections
                .iter()
                .map(|s| SectionView {
                    id: s.id.clone(),
                    label: s.label.clone(),
                    fields: s
                        .fields
                        .iter()
                        .map(|f| {
                            let secret = is_secret(f.kind);
                            let has_value = f.value != FfiFieldValue::Empty;
                            FieldView {
                                id: f.id.clone(),
                                label: f.label.clone(),
                                kind: kind_key(f.kind),
                                value: if secret { None } else { display(&f.value) },
                                secret,
                                has_value,
                                strength: match &f.value {
                                    FfiFieldValue::Password { value } if !value.is_empty() => {
                                        Some(strength_level(onepass_ffi::password_strength_bits(
                                            value.clone(),
                                        )))
                                    }
                                    _ => None,
                                },
                                data: structured(&f.value),
                                options: if f.kind == FfiFieldType::Menu {
                                    onepass_ffi::menu_options(i.item_type, f.id.clone())
                                } else {
                                    vec![]
                                },
                            }
                        })
                        .collect(),
                })
                .collect(),
            created_at: i.created_at,
            updated_at: i.updated_at,
            trashed: i.trashed_at.is_some(),
            archived: i.archived,
            password_history_count: i.password_history_count,
            attachments: i
                .attachments
                .iter()
                .map(|a| AttachmentView {
                    id: a.id.clone(),
                    name: a.name.clone(),
                    size: a.size,
                    mime: a.mime.clone(),
                })
                .collect(),
            travel_hidden: i.travel_hidden,
            travel_guard: i.travel_guard,
        }
    }
}

/// Field kinds whose value stays out of the web view until revealed.
pub fn is_secret(kind: FfiFieldType) -> bool {
    matches!(
        kind,
        FfiFieldType::Password
            | FfiFieldType::Concealed
            | FfiFieldType::Otp
            | FfiFieldType::Mnemonic
            | FfiFieldType::SshKey
    )
}

/// The value as one line of text, for display, reveal and copy. `None` for
/// an empty field or a kind that has no text form here (passkey, file).
pub fn display(v: &FfiFieldValue) -> Option<String> {
    use FfiFieldValue as V;
    let s = match v {
        V::Text { value }
        | V::Concealed { value }
        | V::Password { value }
        | V::Url { value }
        | V::Email { value }
        | V::Phone { value }
        | V::Menu { value }
        | V::Otp { value }
        | V::Mnemonic { value } => value.clone(),
        V::Date { value } => format!("{:04}-{:02}-{:02}", value.year, value.month, value.day),
        V::MonthYear { year, month } => format!("{month:02}/{year:04}"),
        V::Number { value } => value.to_string(),
        V::Money {
            minor_units,
            currency,
        } => format!(
            "{}.{:02} {currency}",
            minor_units / 100,
            (minor_units % 100).abs()
        ),
        V::Address { value } => [
            value.line1.as_str(),
            value.line2.as_str(),
            value.postal_code.as_str(),
            value.city.as_str(),
            value.region.as_str(),
            value.country.as_str(),
        ]
        .iter()
        .filter(|p| !p.is_empty())
        .copied()
        .collect::<Vec<_>>()
        .join(", "),
        V::SshKey { value } => value.private_pem.clone(),
        V::Location { value } => value.address.clone().unwrap_or_else(|| value.label.clone()),
        V::Barcode { value, .. } => value.clone(),
        V::Passkey { value } => format!("{} ({})", value.user_name, value.rp_id),
        V::File { value } => value.name.clone(),
        V::ItemLink { .. } | V::Empty => return None,
    };
    (!s.is_empty()).then_some(s)
}

/// The parts of a date, month-year or address (never a secret kind).
fn structured(v: &FfiFieldValue) -> Option<FieldInput> {
    match v {
        FfiFieldValue::Date { value } => Some(FieldInput::Date {
            year: value.year,
            month: value.month,
            day: value.day,
        }),
        FfiFieldValue::MonthYear { year, month } => Some(FieldInput::MonthYear {
            year: *year,
            month: *month,
        }),
        FfiFieldValue::Address { value } => Some(FieldInput::Address {
            line1: value.line1.clone(),
            line2: value.line2.clone(),
            postal_code: value.postal_code.clone(),
            city: value.city.clone(),
            region: value.region.clone(),
            country: value.country.clone(),
        }),
        _ => None,
    }
}

/// The value an editor input gives a field of `kind`. `None` when the
/// input does not fit the kind (a date for a text field, a bad number).
pub fn input_value(kind: FfiFieldType, input: FieldInput) -> Option<FfiFieldValue> {
    use FfiFieldType as K;
    use FfiFieldValue as V;
    Some(match (kind, input) {
        (_, FieldInput::Empty) => V::Empty,
        (_, FieldInput::Text { value }) => return text_value(kind, value.to_string()),
        (K::Date, FieldInput::Date { year, month, day }) => {
            if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
                return None;
            }
            V::Date {
                value: onepass_ffi::FfiDate { year, month, day },
            }
        }
        (K::MonthYear, FieldInput::MonthYear { year, month }) => {
            if !(1..=12).contains(&month) {
                return None;
            }
            V::MonthYear { year, month }
        }
        (
            K::Address,
            FieldInput::Address {
                line1,
                line2,
                postal_code,
                city,
                region,
                country,
            },
        ) => {
            let a = onepass_ffi::FfiAddress {
                line1: line1.trim().to_owned(),
                line2: line2.trim().to_owned(),
                city: city.trim().to_owned(),
                postal_code: postal_code.trim().to_owned(),
                region: region.trim().to_owned(),
                country: country.trim().to_owned(),
            };
            if [
                &a.line1,
                &a.line2,
                &a.city,
                &a.postal_code,
                &a.region,
                &a.country,
            ]
            .iter()
            .all(|p| p.is_empty())
            {
                V::Empty
            } else {
                V::Address { value: a }
            }
        }
        _ => return None,
    })
}

/// "12.50 EUR", "-3 USD", "1234,5 €" as minor units and a currency.
fn parse_money(text: &str) -> Option<(i64, String)> {
    let text = text.trim();
    let (amount, currency) = match text.rsplit_once(char::is_whitespace) {
        Some((a, c)) if !c.chars().any(|ch| ch.is_ascii_digit()) => (a.trim(), c.trim()),
        _ => (text, ""),
    };
    let amount = amount.replace(',', ".");
    let negative = amount.starts_with('-');
    let digits = amount.trim_start_matches('-');
    let (units, cents) = digits.split_once('.').unwrap_or((digits, ""));
    if units.is_empty() && cents.is_empty()
        || !units.chars().all(|c| c.is_ascii_digit())
        || !cents.chars().all(|c| c.is_ascii_digit())
        || cents.len() > 2
    {
        return None;
    }
    let units: i64 = if units.is_empty() {
        0
    } else {
        units.parse().ok()?
    };
    let cents: i64 = format!("{cents:0<2}").parse().ok()?;
    let minor = units.checked_mul(100)?.checked_add(cents)?;
    Some((if negative { -minor } else { minor }, currency.to_owned()))
}

/// Kinds the editor writes as text.
pub fn text_value(kind: FfiFieldType, text: String) -> Option<FfiFieldValue> {
    use FfiFieldType as K;
    use FfiFieldValue as V;
    if text.is_empty() {
        return Some(V::Empty);
    }
    Some(match kind {
        K::Text => V::Text { value: text },
        K::Concealed => V::Concealed { value: text },
        K::Password => V::Password { value: text },
        K::Url => V::Url { value: text },
        K::Email => V::Email { value: text },
        K::Phone => V::Phone { value: text },
        K::Menu => V::Menu { value: text },
        K::Otp => V::Otp { value: text },
        K::Mnemonic => V::Mnemonic { value: text },
        K::Number => V::Number {
            value: text.trim().parse().ok()?,
        },
        K::Money => {
            let (minor_units, currency) = parse_money(&text)?;
            V::Money {
                minor_units,
                currency,
            }
        }
        _ => return None,
    })
}

pub fn kind_key(k: FfiFieldType) -> &'static str {
    use FfiFieldType as K;
    match k {
        K::Text => "text",
        K::Concealed => "concealed",
        K::Password => "password",
        K::Url => "url",
        K::Email => "email",
        K::Phone => "phone",
        K::Date => "date",
        K::MonthYear => "monthYear",
        K::Number => "number",
        K::Money => "money",
        K::Address => "address",
        K::Menu => "menu",
        K::Otp => "otp",
        K::Passkey => "passkey",
        K::SshKey => "sshKey",
        K::File => "file",
        K::Location => "location",
        K::Mnemonic => "mnemonic",
        K::Barcode => "barcode",
        K::ItemLink => "itemLink",
    }
}

pub const TYPES: [(FfiItemType, &str); 26] = [
    (FfiItemType::Login, "login"),
    (FfiItemType::SecureNote, "secureNote"),
    (FfiItemType::Password, "password"),
    (FfiItemType::Email, "email"),
    (FfiItemType::Server, "server"),
    (FfiItemType::Database, "database"),
    (FfiItemType::Router, "router"),
    (FfiItemType::ApiCredential, "apiCredential"),
    (FfiItemType::SshKey, "sshKey"),
    (FfiItemType::CreditCard, "creditCard"),
    (FfiItemType::BankAccount, "bankAccount"),
    (FfiItemType::CryptoWallet, "cryptoWallet"),
    (FfiItemType::Subscription, "subscription"),
    (FfiItemType::Identity, "identity"),
    (FfiItemType::IdCard, "idCard"),
    (FfiItemType::Passport, "passport"),
    (FfiItemType::DriverLicense, "driverLicense"),
    (FfiItemType::SocialSecurityNumber, "socialSecurityNumber"),
    (FfiItemType::MedicalRecord, "medicalRecord"),
    (FfiItemType::Membership, "membership"),
    (FfiItemType::RewardProgram, "rewardProgram"),
    (FfiItemType::Insurance, "insurance"),
    (FfiItemType::Vehicle, "vehicle"),
    (FfiItemType::AccessCode, "accessCode"),
    (FfiItemType::Document, "document"),
    (FfiItemType::SoftwareLicense, "softwareLicense"),
];

pub fn type_key(t: FfiItemType) -> &'static str {
    TYPES
        .iter()
        .find(|(k, _)| *k == t)
        .map_or("login", |(_, s)| s)
}

pub fn type_from_key(s: &str) -> Option<FfiItemType> {
    TYPES.iter().find(|(_, k)| *k == s).map(|(t, _)| *t)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn editor_inputs_fit_their_kind() {
        let date = FieldInput::Date {
            year: 1990,
            month: 5,
            day: 17,
        };
        assert!(matches!(
            input_value(FfiFieldType::Date, date),
            Some(FfiFieldValue::Date { .. })
        ));
        let bad = FieldInput::Date {
            year: 1990,
            month: 13,
            day: 1,
        };
        assert!(input_value(FfiFieldType::Date, bad).is_none());
        let my = FieldInput::MonthYear {
            year: 2030,
            month: 3,
        };
        assert!(input_value(FfiFieldType::Text, my).is_none());
        let blank = FieldInput::Address {
            line1: " ".into(),
            line2: String::new(),
            postal_code: String::new(),
            city: String::new(),
            region: String::new(),
            country: String::new(),
        };
        assert_eq!(
            input_value(FfiFieldType::Address, blank),
            Some(FfiFieldValue::Empty)
        );
        assert_eq!(
            text_value(FfiFieldType::Number, "42".into()),
            Some(FfiFieldValue::Number { value: 42 })
        );
        assert!(text_value(FfiFieldType::Number, "4x".into()).is_none());
    }

    #[test]
    fn amounts_parse_to_minor_units() {
        assert_eq!(parse_money("1500,50 EUR"), Some((150_050, "EUR".into())));
        assert_eq!(parse_money("12.5"), Some((1250, String::new())));
        assert_eq!(parse_money("-3 USD"), Some((-300, "USD".into())));
        assert_eq!(parse_money("1.234 EUR"), None);
        assert_eq!(parse_money("abc"), None);
    }

    #[test]
    fn every_type_has_a_distinct_key() {
        for (t, k) in TYPES {
            assert_eq!(type_from_key(k), Some(t));
        }
    }

    #[test]
    fn secret_values_do_not_reach_the_view() {
        let item = FfiItem {
            id: "a".into(),
            vault_id: "v".into(),
            item_type: FfiItemType::Login,
            title: "Example".into(),
            tags: vec![],
            favorite: false,
            color: None,
            notes: String::new(),
            urls: vec![],
            apps: vec![],
            locations: vec![],
            login_methods: vec![],
            sections: vec![onepass_ffi::FfiSection {
                id: "s".into(),
                label: String::new(),
                fields: vec![
                    onepass_ffi::FfiField {
                        id: "username".into(),
                        label: "Username".into(),
                        kind: FfiFieldType::Text,
                        value: FfiFieldValue::Text {
                            value: "alice".into(),
                        },
                        required: false,
                        repeatable: false,
                        autofill: true,
                    },
                    onepass_ffi::FfiField {
                        id: "password".into(),
                        label: "Password".into(),
                        kind: FfiFieldType::Password,
                        value: FfiFieldValue::Password {
                            value: "hunter2".into(),
                        },
                        required: false,
                        repeatable: false,
                        autofill: true,
                    },
                ],
            }],
            expires: None,
            rotate_every_days: None,
            reprompt: false,
            hide_from_autofill: false,
            watchtower_exclusions: vec![],
            on_watch: false,
            archived: false,
            trashed_at: None,
            created_at: 0,
            updated_at: 0,
            password_history_count: 0,
            attachment_count: 0,
            attachments: vec![],
            travel_hidden: false,
            travel_guard: false,
        };
        let json = serde_json::to_string(&ItemView::from(&item)).unwrap();
        assert!(json.contains("alice"));
        assert!(!json.contains("hunter2"));
    }
}
