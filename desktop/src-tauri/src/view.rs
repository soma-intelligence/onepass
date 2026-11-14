//! What crosses the IPC to the web view (spec 2026-10-30 section 3.2): item
//! summaries without secrets, and item details whose secret fields carry no
//! value. A secret reaches the web view only through `reveal_field`, when
//! the user asks to see it; a copy never crosses (`copy_field`).

use onepass_ffi::{
    FfiFieldType, FfiFieldValue, FfiItem, FfiItemSummary, FfiItemType, FfiVault, OnePassError,
};
use serde::Serialize;

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
    pub updated_at: i64,
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
            updated_at: s.updated_at,
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
                            }
                        })
                        .collect(),
                })
                .collect(),
            created_at: i.created_at,
            updated_at: i.updated_at,
            trashed: i.trashed_at.is_some(),
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

/// Kinds the editor of this first version writes as plain text.
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
