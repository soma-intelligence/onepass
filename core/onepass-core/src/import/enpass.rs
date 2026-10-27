//! Enpass JSON export (Enpass 6).
//!
//! Root `{ folders, items }`. An item has a `category` (`login`,
//! `password`, `creditcard`, `note`, `identity`, and others), a `title`, a
//! `note`, flags (`favorite`, `archived`, `trashed`), Unix times
//! (`createdAt`, `updated_at`), folder ids, and a list of `fields`, each
//! with a `type` (`username`, `email`, `password`, `url`, `totp`, `pin`,
//! `ccNumber`, ...), a `label`, a `value` and a `sensitive` flag. Fields are
//! mapped by type, identities by label; every other field lands in
//! `imported`, masked when Enpass marks it sensitive. Every key is optional
//! and unknown keys are ignored. Trashed items are skipped.

use std::collections::HashMap;

use serde::Deserialize;
use time::OffsetDateTime;

use crate::error::{Error, Result};
use crate::model::ItemType;

use super::bitwarden::lenient;
use super::build::Draft;
use super::limits::{MAX_INPUT, MAX_RECORDS};
use super::{Import, Warning};

#[derive(Deserialize, Default)]
#[serde(default)]
struct Root {
    folders: Vec<Folder>,
    items: Vec<RawItem>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Folder {
    #[serde(deserialize_with = "lenient")]
    uuid: Option<String>,
    #[serde(deserialize_with = "lenient")]
    title: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct RawItem {
    #[serde(deserialize_with = "lenient")]
    category: Option<String>,
    #[serde(deserialize_with = "lenient")]
    title: Option<String>,
    #[serde(deserialize_with = "lenient")]
    note: Option<String>,
    #[serde(deserialize_with = "lenient")]
    favorite: Option<String>,
    #[serde(deserialize_with = "lenient")]
    archived: Option<String>,
    #[serde(deserialize_with = "lenient")]
    trashed: Option<String>,
    #[serde(rename = "createdAt", deserialize_with = "lenient")]
    created_at: Option<String>,
    #[serde(deserialize_with = "lenient")]
    updated_at: Option<String>,
    folders: Vec<serde_json::Value>,
    fields: Vec<RawField>,
    attachments: Vec<serde::de::IgnoredAny>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct RawField {
    #[serde(rename = "type", deserialize_with = "lenient")]
    kind: Option<String>,
    #[serde(deserialize_with = "lenient")]
    label: Option<String>,
    #[serde(deserialize_with = "lenient")]
    value: Option<String>,
    #[serde(deserialize_with = "lenient")]
    sensitive: Option<String>,
    #[serde(deserialize_with = "lenient")]
    deleted: Option<String>,
}

fn some(s: &Option<String>) -> &str {
    s.as_deref().unwrap_or("")
}

/// `1` or `true`.
fn flag(s: &Option<String>) -> bool {
    matches!(some(s).trim(), "1" | "true")
}

fn unix(s: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::from_unix_timestamp(s.trim().parse().ok()?).ok()
}

/// Item type of an Enpass category. Unknown categories are a Login when
/// they hold a username or a password, a SecureNote otherwise.
fn kind_of(raw: &RawItem) -> ItemType {
    match some(&raw.category).to_lowercase().as_str() {
        "login" | "password" => ItemType::Login,
        "creditcard" => ItemType::CreditCard,
        "note" => ItemType::SecureNote,
        "identity" => ItemType::Identity,
        _ => {
            let has_secret = raw.fields.iter().any(|f| {
                matches!(some(&f.kind), "username" | "password")
                    && !some(&f.value).trim().is_empty()
            });
            if has_secret {
                ItemType::Login
            } else {
                ItemType::SecureNote
            }
        }
    }
}

/// Template field id for a field of type `t` (and lower-cased label
/// `label`) in an item of kind `kind`.
fn slot(kind: ItemType, t: &str, label: &str) -> Option<&'static str> {
    Some(match (kind, t) {
        (ItemType::Login, "username") => "username",
        (ItemType::Login, "password") => "password",
        (ItemType::Login | ItemType::Identity, "email") => "email",
        (ItemType::Login, "totp") => "totp",
        (ItemType::Login | ItemType::CreditCard, "pin" | "ccPin") => "pin",
        (ItemType::CreditCard, "ccName") => "cardholder",
        (ItemType::CreditCard, "ccNumber") => "number",
        (ItemType::CreditCard, "ccCvc") => "cvv",
        (ItemType::CreditCard, "ccExpiry") => "expiry",
        (ItemType::CreditCard, "ccBankname") => "issuer",
        (ItemType::Identity, "phone") => "mobile_phone",
        (ItemType::Identity, _) => match label {
            "first name" | "firstname" => "first_name",
            "middle name" => "middle_name",
            "last name" | "lastname" | "surname" => "last_name",
            "birthday" | "date of birth" | "birth date" => "birth_date",
            "company" | "organization" => "company",
            "job title" | "occupation" => "job_title",
            "website" => "website",
            _ => return None,
        },
        _ => return None,
    })
}

fn item_draft(raw: &RawItem, folders: &HashMap<String, String>) -> Draft {
    let kind = kind_of(raw);
    let mut d = Draft::new(kind);
    d.title(some(&raw.title));
    if kind == ItemType::SecureNote {
        d.set("content", some(&raw.note));
    } else {
        d.notes(some(&raw.note));
    }
    d.favorite(flag(&raw.favorite));
    d.archived(flag(&raw.archived));
    for (label, value, apply) in [
        (
            "createdAt",
            &raw.created_at,
            Draft::created as fn(&mut Draft, OffsetDateTime),
        ),
        ("updated_at", &raw.updated_at, Draft::updated),
    ] {
        let value = some(value);
        if value.trim().is_empty() {
            continue;
        }
        match unix(value) {
            Some(t) => apply(&mut d, t),
            None => d.bad_value(label, value),
        }
    }
    if let Some(name) = raw
        .folders
        .iter()
        .find_map(|f| f.as_str().and_then(|id| folders.get(id)))
    {
        d.folder(name);
    }
    let mut email = None;
    let mut has_username = false;
    for f in &raw.fields {
        let (t, value) = (some(&f.kind), some(&f.value));
        if flag(&f.deleted) || t == "section" || value.trim().is_empty() {
            continue;
        }
        let label = some(&f.label).trim();
        if t == "url" {
            d.url(value);
            continue;
        }
        match slot(kind, t, &label.to_lowercase()) {
            Some(id) => {
                has_username |= id == "username";
                if id == "email" && email.is_none() {
                    email = Some(value);
                }
                d.set(id, value);
            }
            None => d.extra(
                if label.is_empty() { t } else { label },
                value,
                flag(&f.sensitive),
            ),
        }
    }
    // Enpass logins often carry only an email: it is the username too.
    if let Some(email) = email
        && kind == ItemType::Login
        && !has_username
    {
        d.set("username", email);
    }
    d
}

/// Enpass JSON: logins, cards, secure notes, identities; other categories
/// by content. Attachments are not in the export and are reported.
pub(crate) fn parse_enpass_json(b: &[u8]) -> Result<Import> {
    if b.len() > MAX_INPUT {
        return Err(Error::InvalidFormat("import file too large"));
    }
    let root: Root = serde_json::from_slice(b).map_err(|_| Error::InvalidFormat("enpass json"))?;
    if root.items.len() > MAX_RECORDS {
        return Err(Error::InvalidFormat("too many enpass items"));
    }
    let folders: HashMap<String, String> = root
        .folders
        .into_iter()
        .filter_map(|f| Some((f.uuid?, f.title?)))
        .collect();
    let mut out = Import::default();
    for (index, raw) in root.items.iter().enumerate() {
        let entry = u32::try_from(index).unwrap_or(u32::MAX);
        if flag(&raw.trashed) {
            out.skipped += 1;
            continue;
        }
        if !raw.attachments.is_empty() {
            out.warnings.push(Warning {
                entry,
                code: "attachment_skipped",
            });
        }
        item_draft(raw, &folders).finish(entry, &mut out);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use time::macros::datetime;

    use super::*;
    use crate::model::{FieldValue, Item, validate};

    const ENPASS: &[u8] = include_bytes!("../../tests/fixtures/import/enpass.json");

    fn text(item: &Item, id: &str) -> String {
        match item.field(id).map(|f| &f.value) {
            Some(FieldValue::Text(s) | FieldValue::Email(s) | FieldValue::Phone(s)) => s.clone(),
            Some(FieldValue::Password(s) | FieldValue::Concealed(s) | FieldValue::Otp(s)) => {
                s.to_string()
            }
            _ => String::new(),
        }
    }

    fn imported(item: &Item) -> Vec<(String, FieldValue)> {
        item.sections
            .iter()
            .filter(|s| s.id == "imported")
            .flat_map(|s| s.fields.iter().map(|f| (f.label.clone(), f.value.clone())))
            .collect()
    }

    #[test]
    fn categories_map() {
        let imp = parse_enpass_json(ENPASS).unwrap();
        assert_eq!(imp.items.len(), 5);
        assert_eq!(imp.skipped, 1);
        assert_eq!(
            imp.warnings,
            vec![Warning {
                entry: 0,
                code: "attachment_skipped"
            }]
        );
        for it in &imp.items {
            validate(&it.item).unwrap();
        }

        let a = &imp.items[0];
        assert_eq!(a.item.item_type, ItemType::Login);
        assert_eq!(a.item.title, "Example Mail");
        assert_eq!(a.folder.as_deref(), Some("Personal"));
        assert!(a.item.favorite);
        assert_eq!(text(&a.item, "username"), "alice");
        assert_eq!(text(&a.item, "email"), "alice@example.com");
        assert_eq!(text(&a.item, "password"), "Enpass-Invented-1");
        assert_eq!(a.item.urls[0].url, "https://mail.example.com");
        assert!(text(&a.item, "totp").starts_with("otpauth://totp/"));
        assert_eq!(a.item.notes, "Main mailbox");
        assert_eq!(a.item.created_at, datetime!(2023-11-14 22:13:20 UTC));
        assert_eq!(a.item.updated_at, datetime!(2023-11-14 22:21:40 UTC));
        let extras = imported(&a.item);
        assert!(extras.iter().any(|(l, v)| l == "Security answer"
            && *v == FieldValue::Concealed("Invented".to_owned().into())));
        // A deleted field is not imported.
        assert!(!extras.iter().any(|(l, _)| l == "Old"));

        let card = &imp.items[1].item;
        assert_eq!(card.item_type, ItemType::CreditCard);
        assert_eq!(text(card, "cardholder"), "Alice Example");
        assert_eq!(text(card, "number"), "4111111111111111");
        assert_eq!(text(card, "cvv"), "123");

        let note = &imp.items[2].item;
        assert_eq!(note.item_type, ItemType::SecureNote);
        assert_eq!(text(note, "content"), "Invented note body");
        assert!(note.archived);

        let id = &imp.items[3].item;
        assert_eq!(id.item_type, ItemType::Identity);
        assert_eq!(text(id, "first_name"), "Alice");
        assert_eq!(text(id, "last_name"), "Example");
        assert_eq!(text(id, "email"), "alice@example.org");

        // Email only: it is the username too.
        let shop = &imp.items[4].item;
        assert_eq!(shop.item_type, ItemType::Login);
        assert_eq!(text(shop, "username"), "bob@example.org");
    }

    #[test]
    fn garbage_is_refused() {
        assert!(parse_enpass_json(b"[1,2]").is_err());
        assert!(parse_enpass_json(br#"{"items":[{"fields":"nope"}]}"#).is_err());
    }
}
