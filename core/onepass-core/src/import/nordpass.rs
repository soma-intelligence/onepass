//! NordPass CSV export.
//!
//! One file for every kind of item. Columns `name,url,additional_urls,
//! username,password,note,cardholdername,cardnumber,cvc,pin,expirydate,
//! zipcode,folder,full_name,phone_number,email,address1,address2,city,
//! country,state,type,custom_fields[,totp]`. The `type` column says what a
//! row is: `password` (Login), `credit_card`, `note`, `identity`, or
//! `folder` (a folder declaration, no data of its own). Columns are read by
//! name, so a reordered or extended header still imports; a cell the row's
//! type has no slot for lands in `imported`.

use serde::Deserialize;

use crate::error::Result;
use crate::model::{Address, FieldValue, ItemType};

use super::Import;
use super::bitwarden::lenient;
use super::build::Draft;
use super::limits::csv_records;

/// Whether a lower-cased CSV header is a NordPass export: its card and
/// identity columns are found in no other format.
pub(crate) fn is_nordpass_header(header: &[String]) -> bool {
    let has = |c: &str| header.iter().any(|h| h == c);
    [
        "name",
        "url",
        "username",
        "password",
        "note",
        "cardholdername",
        "cardnumber",
        "type",
    ]
    .iter()
    .all(|c| has(c))
}

/// A row seen through its header.
struct Row<'a> {
    header: &'a [String],
    cells: &'a [String],
}

impl<'a> Row<'a> {
    /// Trimmed cell of column `col`, or `""`.
    fn get(&self, col: &str) -> &'a str {
        self.header
            .iter()
            .position(|h| h == col)
            .and_then(|i| self.cells.get(i))
            .map_or("", |c| c.trim())
    }

    fn pairs(&self) -> impl Iterator<Item = (&'a str, &'a str)> {
        self.header
            .iter()
            .zip(self.cells)
            .map(|(h, c)| (h.as_str(), c.as_str()))
    }

    fn overflow(&self, d: &mut Draft) {
        for (i, cell) in self.cells.iter().enumerate().skip(self.header.len()) {
            d.extra(&format!("column {}", i + 1), cell, false);
        }
    }

    fn is_blank(&self) -> bool {
        self.cells.iter().all(|c| c.trim().is_empty())
    }
}

/// One entry of the `custom_fields` cell (a JSON array).
#[derive(Deserialize, Default)]
#[serde(default)]
struct Custom {
    #[serde(deserialize_with = "lenient")]
    label: Option<String>,
    #[serde(rename = "type", deserialize_with = "lenient")]
    kind: Option<String>,
    #[serde(deserialize_with = "lenient")]
    value: Option<String>,
}

/// The `custom_fields` cell: a JSON array of `{label, type, value}`. A
/// `hidden` field is masked. A cell that is not such an array is kept whole,
/// masked (it may hold hidden values).
fn custom_fields(d: &mut Draft, raw: &str) {
    if raw.trim().is_empty() {
        return;
    }
    match serde_json::from_str::<Vec<Custom>>(raw) {
        Ok(list) => {
            for c in list {
                let label = c.label.as_deref().filter(|l| !l.trim().is_empty());
                let secret = c
                    .kind
                    .as_deref()
                    .is_some_and(|k| k.eq_ignore_ascii_case("hidden"));
                d.extra(
                    label.unwrap_or("custom field"),
                    c.value.as_deref().unwrap_or(""),
                    secret,
                );
            }
        }
        Err(_) => d.extra("custom_fields", raw, true),
    }
}

/// The `additional_urls` cell: a JSON array of strings, or failing that a
/// comma or line separated list.
fn additional_urls(d: &mut Draft, raw: &str) {
    if raw.trim().is_empty() {
        return;
    }
    match serde_json::from_str::<Vec<String>>(raw) {
        Ok(list) => list.iter().for_each(|u| d.url(u)),
        Err(_) => raw.split([',', '\n']).for_each(|u| d.url(u)),
    }
}

/// Item type of a `type` cell. `None` for a folder row. An unknown type is
/// read as a Login: the builder falls back to Password or SecureNote, and
/// nothing is lost.
fn kind_of(t: &str) -> Option<ItemType> {
    match t.to_lowercase().as_str() {
        "folder" => None,
        "credit_card" | "creditcard" | "card" => Some(ItemType::CreditCard),
        "note" | "secure_note" => Some(ItemType::SecureNote),
        "identity" | "personal_info" => Some(ItemType::Identity),
        _ => Some(ItemType::Login),
    }
}

/// First word as first name, the rest as last name.
fn split_name(full: &str) -> (&str, &str) {
    let full = full.trim();
    match full.split_once(char::is_whitespace) {
        Some((first, last)) => (first, last.trim()),
        None => (full, ""),
    }
}

const SECRET_COLS: [&str; 5] = ["password", "totp", "cvc", "pin", "cardnumber"];

const ADDRESS_COLS: [&str; 6] = [
    "address1", "address2", "city", "zipcode", "state", "country",
];

fn row_draft(row: &Row, kind: ItemType) -> Draft {
    let mut d = Draft::new(kind);
    let card = kind == ItemType::CreditCard;
    let identity = kind == ItemType::Identity;
    let known_type = matches!(
        row.get("type").to_lowercase().as_str(),
        "password"
            | "login"
            | "credit_card"
            | "creditcard"
            | "card"
            | "note"
            | "secure_note"
            | "identity"
            | "personal_info"
    );
    for (col, val) in row.pairs() {
        match col {
            "type" if known_type => {}
            "name" => d.title(val),
            "folder" => d.folder(val),
            "url" => d.url(val),
            "additional_urls" => additional_urls(&mut d, val),
            "note" if kind == ItemType::SecureNote => d.set("content", val),
            "note" => d.notes(val),
            "custom_fields" => custom_fields(&mut d, val),
            "username" if kind == ItemType::Login => d.set("username", val),
            "password" if kind == ItemType::Login => d.set("password", val),
            "totp" if kind == ItemType::Login => d.set("totp", val),
            "email" if kind == ItemType::Login || identity => d.set("email", val),
            "cardholdername" if card => d.set("cardholder", val),
            "cardnumber" if card => d.set("number", val),
            "cvc" if card => d.set("cvv", val),
            "pin" if card || kind == ItemType::Login => d.set("pin", val),
            "expirydate" if card => d.set("expiry", val),
            "full_name" if identity => {
                let (first, last) = split_name(val);
                d.set("first_name", first);
                d.set("last_name", last);
            }
            "phone_number" if identity => d.set("mobile_phone", val),
            c if (identity || card) && ADDRESS_COLS.contains(&c) => {}
            // A secret column on a row whose type has no slot for it stays
            // concealed, whatever the hints make of its name.
            _ => d.extra(col, val, SECRET_COLS.contains(&col)),
        }
    }
    if identity || card {
        let address = Address {
            line1: row.get("address1").to_owned(),
            line2: row.get("address2").to_owned(),
            city: row.get("city").to_owned(),
            postal_code: row.get("zipcode").to_owned(),
            region: row.get("state").to_owned(),
            country: row.get("country").to_owned(),
        };
        let blank = [
            &address.line1,
            &address.line2,
            &address.city,
            &address.postal_code,
            &address.region,
            &address.country,
        ]
        .iter()
        .all(|s| s.is_empty());
        if !blank {
            let id = if card { "billing_address" } else { "address" };
            d.set_value(id, FieldValue::Address(address));
        }
    }
    row.overflow(&mut d);
    d
}

/// NordPass CSV: logins, cards, secure notes and identities. Folder rows
/// only declare a folder (the items name theirs) and are counted as skipped.
pub(crate) fn parse_nordpass_csv(b: &[u8]) -> Result<Import> {
    let (header, rows) = csv_records(b)?;
    let mut out = Import::default();
    for (index, cells) in rows.iter().enumerate() {
        let entry = u32::try_from(index).unwrap_or(u32::MAX);
        let row = Row {
            header: &header,
            cells,
        };
        if row.is_blank() {
            out.skipped += 1;
            continue;
        }
        let Some(kind) = kind_of(row.get("type")) else {
            out.skipped += 1;
            continue;
        };
        row_draft(&row, kind).finish(entry, &mut out);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::import::limits::csv_records;
    use crate::model::{Item, validate};

    const NORDPASS: &[u8] = include_bytes!("../../tests/fixtures/import/nordpass.csv");

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
    fn header_is_recognised() {
        let (header, _) = csv_records(NORDPASS).unwrap();
        assert!(is_nordpass_header(&header));
        assert!(!is_nordpass_header(
            &csv_records(b"name,url,username,password\n").unwrap().0
        ));
    }

    #[test]
    fn secret_columns_stay_concealed_on_any_row() {
        let csv = b"name,url,additional_urls,username,password,note,cardholdername,cardnumber,cvc,pin,expirydate,zipcode,folder,full_name,phone_number,email,address1,address2,city,country,state,type,custom_fields,totp\n\
Locker,,,,,a note,,4111111111111111,123,,,,,,,,,,,,,note,,JBSWY3DPEHPK3PXP\n";
        let imp = parse_nordpass_csv(csv).unwrap();
        let fields = imported(&imp.items[0].item);
        for label in ["cardnumber", "cvc", "totp"] {
            let value = fields.iter().find(|(l, _)| l == label).map(|(_, v)| v);
            assert!(
                matches!(value, Some(FieldValue::Concealed(_))),
                "{label} is {value:?}"
            );
        }
    }

    #[test]
    fn every_type_maps() {
        let imp = parse_nordpass_csv(NORDPASS).unwrap();
        // Folder row and blank row skipped.
        assert_eq!(imp.skipped, 2);
        assert_eq!(imp.items.len(), 5);
        for it in &imp.items {
            validate(&it.item).unwrap();
        }

        let login = &imp.items[0];
        assert_eq!(login.item.item_type, ItemType::Login);
        assert_eq!(login.item.title, "Example Mail");
        assert_eq!(login.folder.as_deref(), Some("Personal"));
        assert_eq!(text(&login.item, "username"), "alice@example.com");
        assert_eq!(text(&login.item, "password"), "Nord-Invented-1");
        assert_eq!(login.item.notes, "Main mailbox");
        assert_eq!(login.item.urls.len(), 3);
        assert_eq!(login.item.urls[1].url, "https://alt.example.com");
        assert!(text(&login.item, "totp").starts_with("otpauth://totp/"));
        let extras = imported(&login.item);
        assert!(
            extras.iter().any(|(l, v)| l == "Recovery PIN"
                && *v == FieldValue::Concealed("4321".to_owned().into()))
        );
        assert!(
            extras
                .iter()
                .any(|(l, v)| l == "Hint" && *v == FieldValue::Text("blue".into()))
        );

        let card = &imp.items[1].item;
        assert_eq!(card.item_type, ItemType::CreditCard);
        assert_eq!(text(card, "cardholder"), "Alice Example");
        assert_eq!(text(card, "number"), "4111111111111111");
        assert_eq!(text(card, "cvv"), "123");
        assert!(matches!(
            card.field("billing_address").map(|f| &f.value),
            Some(FieldValue::Address(a)) if a.postal_code == "75001"
        ));

        let note = &imp.items[2].item;
        assert_eq!(note.item_type, ItemType::SecureNote);
        assert_eq!(text(note, "content"), "Invented note body");

        let id = &imp.items[3].item;
        assert_eq!(id.item_type, ItemType::Identity);
        assert_eq!(text(id, "first_name"), "Alice");
        assert_eq!(text(id, "last_name"), "Marie Example");
        assert_eq!(text(id, "email"), "alice@example.org");
        assert!(matches!(
            id.field("address").map(|f| &f.value),
            Some(FieldValue::Address(a)) if a.city == "Paris" && a.line1 == "1 rue Exemple"
        ));

        // Unknown type: read as a Login, the type name kept.
        let other = &imp.items[4].item;
        assert!(imported(other).iter().any(|(l, _)| l == "type"));
    }

    #[test]
    fn plain_url_list_and_bad_custom_fields_are_kept() {
        let csv = b"name,url,additional_urls,username,password,note,cardholdername,cardnumber,type,custom_fields\n\
            A,https://a.example.com,\"https://b.example.com,https://c.example.com\",u,p,,,,password,not json\n";
        let imp = parse_nordpass_csv(csv).unwrap();
        let it = &imp.items[0].item;
        assert_eq!(it.urls.len(), 3);
        assert!(
            imported(it)
                .iter()
                .any(|(l, v)| l == "custom_fields" && matches!(v, FieldValue::Concealed(_)))
        );
    }
}
