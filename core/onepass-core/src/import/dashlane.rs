//! Dashlane CSV exports (spec 4.3): `credentials.csv`, `securenotes.csv`,
//! `payments.csv`, `ids.csv` and `personalInfo.csv`, alone or together in a
//! zip.
//!
//! A single CSV is recognised by its header. In a zip, files are matched
//! by base name (case-insensitive) and processed in the order credentials,
//! securenotes, payments, ids, personalinfo. Warning entry indexes are
//! per-file row numbers (zero-based, header excluded), except for an
//! `unsupported_entry` raised for an unknown zip entry, which carries the
//! zero-based position of that entry in the archive.

use crate::error::{Error, Result};
use crate::model::{Address, FieldValue, ItemType};

use super::build::Draft;
use super::limits::{csv_records, zip_entries};
use super::{Import, Warning};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Credentials,
    SecureNotes,
    Payments,
    Ids,
    PersonalInfo,
}

/// Zip processing order and the base name of each file.
const ZIP_FILES: [(Kind, &str); 5] = [
    (Kind::Credentials, "credentials.csv"),
    (Kind::SecureNotes, "securenotes.csv"),
    (Kind::Payments, "payments.csv"),
    (Kind::Ids, "ids.csv"),
    (Kind::PersonalInfo, "personalinfo.csv"),
];

/// A CSV row seen through its header.
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

    /// Cells beyond the header width go to `imported` as `column N`.
    fn overflow(&self, d: &mut Draft) {
        for (i, cell) in self.cells.iter().enumerate().skip(self.header.len()) {
            d.extra(&format!("column {}", i + 1), cell, false);
        }
    }

    fn is_blank(&self) -> bool {
        self.cells.iter().all(|c| c.trim().is_empty())
    }
}

fn reject_encrypted(b: &[u8]) -> Result<()> {
    if b.starts_with(b"DASH") {
        return Err(Error::InvalidFormat(
            "encrypted dashlane export, export as csv",
        ));
    }
    Ok(())
}

/// File kind of a lower-cased header. The real Dashlane column sets are
/// required so that other managers' CSVs (title and password columns) are
/// not mistaken for Dashlane.
fn kind_of_header(h: &[String]) -> Option<Kind> {
    let has = |c: &str| h.iter().any(|x| x == c);
    let all = |cs: &[&str]| cs.iter().all(|c| has(c));
    let any = |cs: &[&str]| cs.iter().any(|c| has(c));
    if (has("cc_number") || has("account_number")) && has("account_name") {
        Some(Kind::Payments)
    } else if all(&["type", "number", "name"]) && any(&["issue_date", "expiration_date"]) {
        Some(Kind::Ids)
    } else if all(&["type", "first_name", "last_name"]) {
        Some(Kind::PersonalInfo)
    } else if all(&["username", "title", "password", "url"])
        && any(&["username2", "otpsecret", "otpurl", "category"])
    {
        Some(Kind::Credentials)
    } else if h.len() >= 2
        && h.len() <= 3
        && all(&["title", "note"])
        && (h.len() == 2 || has("category"))
    {
        Some(Kind::SecureNotes)
    } else {
        None
    }
}

/// Whether a lower-cased CSV header is one of the five Dashlane files.
pub(crate) fn is_dashlane_header(header: &[String]) -> bool {
    kind_of_header(header).is_some()
}

/// Whether a zip entry name is one of the five Dashlane CSV files.
pub(crate) fn is_dashlane_entry(name: &str) -> bool {
    let base = base_name(name);
    ZIP_FILES.iter().any(|(_, n)| *n == base)
}

/// One Dashlane CSV file, recognised by its header.
pub(crate) fn parse_dashlane_csv(b: &[u8]) -> Result<Import> {
    reject_encrypted(b)?;
    let (header, rows) = csv_records(b)?;
    let kind = kind_of_header(&header).ok_or(Error::InvalidFormat("not a dashlane csv"))?;
    let mut out = Import::default();
    parse_rows(kind, &header, &rows, &mut out);
    Ok(out)
}

/// A Dashlane zip: the known CSV files are parsed in a fixed order, any
/// other entry is skipped with an `unsupported_entry` warning.
pub(crate) fn parse_dashlane_zip(b: &[u8]) -> Result<Import> {
    reject_encrypted(b)?;
    let entries = zip_entries(b)?;
    let mut out = Import::default();
    let mut known = vec![false; entries.len()];
    let mut found = false;
    for (kind, name) in ZIP_FILES {
        for (i, (entry_name, data)) in entries.iter().enumerate() {
            if base_name(entry_name) != name {
                continue;
            }
            if let Some(flag) = known.get_mut(i) {
                *flag = true;
            }
            found = true;
            reject_encrypted(data)?;
            let (header, rows) = csv_records(data)?;
            parse_rows(kind, &header, &rows, &mut out);
        }
    }
    if !found {
        return Err(Error::InvalidFormat("no dashlane csv in zip"));
    }
    for (i, is_known) in known.iter().enumerate() {
        if !is_known {
            out.warnings.push(Warning {
                entry: u32::try_from(i).unwrap_or(u32::MAX),
                code: "unsupported_entry",
            });
            out.skipped += 1;
        }
    }
    Ok(out)
}

/// Lower-cased last path component. The name is never used as a path.
fn base_name(name: &str) -> String {
    name.rsplit(['/', '\\'])
        .next()
        .unwrap_or(name)
        .to_lowercase()
}

fn parse_rows(kind: Kind, header: &[String], rows: &[Vec<String>], out: &mut Import) {
    if kind == Kind::PersonalInfo {
        return personal_info(header, rows, out);
    }
    for (index, cells) in rows.iter().enumerate() {
        let entry = u32::try_from(index).unwrap_or(u32::MAX);
        let row = Row { header, cells };
        if row.is_blank() {
            out.skipped += 1;
            continue;
        }
        let draft = match kind {
            Kind::Credentials => Some(credentials(&row)),
            Kind::SecureNotes => Some(secure_note(&row)),
            Kind::Payments => payment(&row),
            Kind::Ids => id_document(&row),
            Kind::PersonalInfo => None,
        };
        match draft {
            Some(d) => d.finish(entry, out),
            None => unsupported(entry, out),
        }
    }
}

fn unsupported(entry: u32, out: &mut Import) {
    out.warnings.push(Warning {
        entry,
        code: "unsupported_entry",
    });
    out.skipped += 1;
}

fn credentials(row: &Row) -> Draft {
    let mut d = Draft::new(ItemType::Login);
    // Some exports leave `username` empty and fill `username2`.
    let user_empty = row.get("username").is_empty();
    for (col, val) in row.pairs() {
        match col {
            "username" => d.set("username", val),
            "username2" if user_empty => d.set("username", val),
            "title" => d.title(val),
            "password" => d.set("password", val),
            "note" => d.notes(val),
            "url" => d.url(val),
            "category" => d.folder(val),
            "otpurl" | "otpsecret" => d.set("totp", val),
            _ => d.extra(col, val, false),
        }
    }
    row.overflow(&mut d);
    d
}

fn secure_note(row: &Row) -> Draft {
    let mut d = Draft::new(ItemType::SecureNote);
    for (col, val) in row.pairs() {
        match col {
            "title" => d.title(val),
            "note" => d.set("content", val),
            "category" => d.folder(val),
            _ => d.extra(col, val, false),
        }
    }
    row.overflow(&mut d);
    d
}

/// `payment_card` becomes a CreditCard and `bank` a BankAccount; anything
/// else is unsupported.
fn payment(row: &Row) -> Option<Draft> {
    let kind = match row.get("type").to_lowercase().as_str() {
        "payment_card" => ItemType::CreditCard,
        "bank" => ItemType::BankAccount,
        _ => return None,
    };
    let card = kind == ItemType::CreditCard;
    let mut d = Draft::new(kind);
    for (col, val) in row.pairs() {
        match col {
            "type" => {}
            "account_name" => d.title(val),
            "account_holder" => d.set(if card { "cardholder" } else { "holder" }, val),
            "cc_number" if card => d.set("number", val),
            "code" if card => d.set("cvv", val),
            "issuing_bank" => d.set(if card { "issuer" } else { "bank" }, val),
            "routing_number" if !card => d.set("routing_number", val),
            "account_number" if !card => d.set("account_number", val),
            "expiration_month" | "expiration_year" if card => {}
            _ => d.extra(col, val, false),
        }
    }
    if card {
        let (month, year) = (row.get("expiration_month"), row.get("expiration_year"));
        if !month.is_empty() && !year.is_empty() {
            d.set("expiry", &format!("{month:0>2}/{year}"));
        } else {
            d.extra("expiration_month", month, false);
            d.extra("expiration_year", year, false);
        }
    }
    row.overflow(&mut d);
    Some(d)
}

/// `card`, `passport`, `license` and `social_security`; anything else is
/// unsupported.
fn id_document(row: &Row) -> Option<Draft> {
    let kind = match row.get("type").to_lowercase().as_str() {
        "card" => ItemType::IdCard,
        "passport" => ItemType::Passport,
        "license" => ItemType::DriverLicense,
        "social_security" => ItemType::SocialSecurityNumber,
        _ => return None,
    };
    let mut d = Draft::new(kind);
    for (col, val) in row.pairs() {
        match (col, kind) {
            ("type", _) => {}
            ("number", _) => d.set("number", val),
            // The source gives one full name: it titles the item, and is
            // the typed name where the template has one.
            ("name", _) => {
                d.title(val);
                match kind {
                    ItemType::DriverLicense => d.set("full_name", val),
                    ItemType::SocialSecurityNumber => d.set("name", val),
                    _ => {}
                }
            }
            ("issue_date", _) => d.set("issued_on", val),
            ("expiration_date", _) => d.set("expiry", val),
            ("place_of_issue", ItemType::Passport) => d.set("issuing_country", val),
            ("place_of_issue", _) => d.set("country", val),
            ("state", ItemType::DriverLicense) => d.set("region", val),
            _ => d.extra(col, val, false),
        }
    }
    row.overflow(&mut d);
    Some(d)
}

/// An Identity being assembled from consecutive `personalInfo` rows.
struct Identity {
    draft: Draft,
    entry: u32,
    phones: usize,
    has_address: bool,
}

const PHONE_IDS: [&str; 3] = ["mobile_phone", "home_phone", "work_phone"];

impl Identity {
    fn new(row: &Row, entry: u32) -> Identity {
        let mut d = Draft::new(ItemType::Identity);
        d.set("honorific", row.get("title"));
        d.set("first_name", row.get("first_name"));
        d.set("middle_name", row.get("middle_name"));
        d.set("last_name", row.get("last_name"));
        d.set("birth_date", row.get("date_of_birth"));
        d.set("birth_place", row.get("place_of_birth"));
        d.extra("login", row.get("login"), false);
        let name = [row.get("first_name"), row.get("last_name")]
            .iter()
            .filter(|s| !s.is_empty())
            .copied()
            .collect::<Vec<_>>()
            .join(" ");
        d.title(&name);
        Identity {
            draft: d,
            entry,
            phones: 0,
            has_address: false,
        }
    }

    /// Adds what a row of kind `kind` carries.
    fn attach(&mut self, kind: &str, row: &Row) {
        let d = &mut self.draft;
        match kind {
            "email" => d.set("email", row.get("email")),
            "number" => {
                let phone = row.get("phone_number");
                match PHONE_IDS.get(self.phones) {
                    Some(id) => d.set(id, phone),
                    None => d.extra("phone_number", phone, false),
                }
                if !phone.is_empty() {
                    self.phones += 1;
                }
            }
            "address" => {
                let (line1, city) = (row.get("address"), row.get("city"));
                let (zip, state, country) = (row.get("zip"), row.get("state"), row.get("country"));
                if [line1, city, zip, state, country]
                    .iter()
                    .all(|s| s.is_empty())
                {
                    return;
                }
                if self.has_address {
                    let text = [line1, zip, city, state, country]
                        .iter()
                        .filter(|s| !s.is_empty())
                        .copied()
                        .collect::<Vec<_>>()
                        .join(", ");
                    d.extra("address", &text, false);
                } else {
                    self.has_address = true;
                    d.set_value(
                        "address",
                        FieldValue::Address(Address {
                            line1: line1.to_owned(),
                            line2: String::new(),
                            city: city.to_owned(),
                            postal_code: zip.to_owned(),
                            region: state.to_owned(),
                            country: country.to_owned(),
                        }),
                    );
                }
            }
            "website" => d.set("website", row.get("url")),
            _ => return,
        }
        if kind != "number" {
            d.extra("email_type", row.get("email_type"), false);
        }
        d.extra("item_name", row.get("item_name"), false);
    }
}

fn personal_info(header: &[String], rows: &[Vec<String>], out: &mut Import) {
    let mut current: Option<Identity> = None;
    let flush = |current: &mut Option<Identity>, out: &mut Import| {
        if let Some(id) = current.take() {
            id.draft.finish(id.entry, out);
        }
    };
    for (index, cells) in rows.iter().enumerate() {
        let entry = u32::try_from(index).unwrap_or(u32::MAX);
        let row = Row { header, cells };
        if row.is_blank() {
            out.skipped += 1;
            continue;
        }
        let kind = row.get("type").to_lowercase();
        let attachable = matches!(kind.as_str(), "email" | "number" | "address" | "website");
        // `joined` is false for a lone Identity, finished at once.
        let (mut target, joined) = if kind == "name" {
            flush(&mut current, out);
            (Identity::new(&row, entry), true)
        } else if let Some(id) = attachable.then(|| current.take()).flatten() {
            (id, true)
        } else if !row.get("first_name").is_empty() {
            // Attaches to nothing but names a person: a lone Identity.
            (Identity::new(&row, entry), false)
        } else {
            unsupported(entry, out);
            continue;
        };
        target.attach(&kind, &row);
        target.draft.set("job_title", row.get("job_title"));
        row.overflow(&mut target.draft);
        if joined {
            current = Some(target);
        } else {
            target.draft.finish(target.entry, out);
        }
    }
    flush(&mut current, out);
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Write};

    use zip::CompressionMethod;
    use zip::write::{SimpleFileOptions, ZipWriter};

    use super::*;
    use crate::model::Item;

    const CREDENTIALS: &[u8] =
        include_bytes!("../../tests/fixtures/import/dashlane/credentials.csv");
    const NOTES: &[u8] = include_bytes!("../../tests/fixtures/import/dashlane/securenotes.csv");
    const PAYMENTS: &[u8] = include_bytes!("../../tests/fixtures/import/dashlane/payments.csv");
    const IDS: &[u8] = include_bytes!("../../tests/fixtures/import/dashlane/ids.csv");
    const PERSONAL: &[u8] = include_bytes!("../../tests/fixtures/import/dashlane/personalInfo.csv");

    fn text(item: &Item, id: &str) -> String {
        match item.field(id).map(|f| &f.value) {
            Some(FieldValue::Text(s) | FieldValue::Email(s) | FieldValue::Phone(s)) => s.clone(),
            Some(FieldValue::Url(s) | FieldValue::Menu(s)) => s.clone(),
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

    fn by_title<'a>(imp: &'a Import, title: &str) -> &'a super::super::ImportedItem {
        imp.items
            .iter()
            .find(|i| i.item.title == title)
            .expect("item present")
    }

    fn count(imp: &Import, t: ItemType) -> usize {
        imp.items.iter().filter(|i| i.item.item_type == t).count()
    }

    fn zip_of(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut w = ZipWriter::new(Cursor::new(Vec::new()));
        let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
        for (name, data) in entries {
            w.start_file(*name, opts).unwrap();
            w.write_all(data).unwrap();
        }
        w.finish().unwrap().into_inner()
    }

    #[test]
    fn credentials_csv_alone() {
        let imp = parse_dashlane_csv(CREDENTIALS).unwrap();
        assert_eq!(imp.items.len(), 3);
        assert_eq!(imp.skipped, 1);
        let it = by_title(&imp, "Example Mail");
        assert_eq!(it.folder.as_deref(), Some("Personal"));
        let item = &it.item;
        assert_eq!(item.item_type, ItemType::Login);
        assert_eq!(text(item, "username"), "alice@example.com");
        assert_eq!(text(item, "password"), "Tr0ub4dor-Invented1");
        assert!(text(item, "totp").starts_with("otpauth://totp/"));
        assert_eq!(item.urls[0].url, "https://mail.example.com/login");
        assert_eq!(item.notes, "Recovery code in the drawer");
        let extra = imported(item);
        assert!(extra.iter().any(
            |(l, v)| l == "username2" && *v == FieldValue::Text("alice.alt@example.com".into())
        ));
        assert!(extra.iter().any(|(l, _)| l == "username3"));
    }

    #[test]
    fn empty_username_uses_username2() {
        let imp = parse_dashlane_csv(CREDENTIALS).unwrap();
        let item = &by_title(&imp, "Example Shop").item;
        assert_eq!(item.item_type, ItemType::Login);
        assert_eq!(text(item, "username"), "backup-user");
        assert!(imported(item).iter().all(|(l, _)| l != "username2"));
        // Row numbers are per file: the blank row 2 is skipped, row 3 is
        // the last.
        assert!(imp.warnings.iter().all(|w| w.entry < 4));
    }

    #[test]
    fn otpsecret_column_and_wide_row() {
        let csv =
            "username,title,password,url,otpsecret\nbob,Site,pw-Invented,,JBSWY3DPEHPK3PXP,tail\n";
        let imp = parse_dashlane_csv(csv.as_bytes()).unwrap();
        let item = &imp.items[0].item;
        assert!(text(item, "totp").starts_with("otpauth://"));
        assert!(
            imported(item)
                .iter()
                .any(|(l, v)| l == "column 6" && *v == FieldValue::Text("tail".into()))
        );
    }

    #[test]
    fn secure_notes() {
        let imp = parse_dashlane_csv(NOTES).unwrap();
        assert_eq!(imp.items.len(), 2);
        let item = &by_title(&imp, "Example Note").item;
        assert_eq!(item.item_type, ItemType::SecureNote);
        assert_eq!(text(item, "content"), "first line\nsecond line");
    }

    #[test]
    fn payment_card_to_credit_card() {
        let imp = parse_dashlane_csv(PAYMENTS).unwrap();
        let item = &by_title(&imp, "Example Visa").item;
        assert_eq!(item.item_type, ItemType::CreditCard);
        assert_eq!(text(item, "cardholder"), "Alice Example");
        assert_eq!(text(item, "number"), "4111111111111111");
        assert_eq!(text(item, "cvv"), "123");
        assert_eq!(text(item, "issuer"), "Example Bank");
        assert_eq!(
            item.field("expiry").unwrap().value,
            FieldValue::MonthYear {
                year: 2027,
                month: 6
            }
        );
        assert!(imported(item).iter().any(|(l, _)| l == "country"));
    }

    #[test]
    fn bank_and_unsupported_payment() {
        let imp = parse_dashlane_csv(PAYMENTS).unwrap();
        assert_eq!(imp.items.len(), 2);
        let item = &by_title(&imp, "Example Checking").item;
        assert_eq!(item.item_type, ItemType::BankAccount);
        assert_eq!(text(item, "holder"), "Alice Example");
        assert_eq!(text(item, "bank"), "Example Bank");
        assert_eq!(text(item, "routing_number"), "021000021");
        assert_eq!(text(item, "account_number"), "12345678");
        assert_eq!(imp.skipped, 1);
        assert_eq!(
            imp.warnings,
            vec![Warning {
                entry: 2,
                code: "unsupported_entry"
            }]
        );
    }

    #[test]
    fn id_kinds() {
        let imp = parse_dashlane_csv(IDS).unwrap();
        assert_eq!(imp.items.len(), 4);
        assert_eq!(imp.skipped, 1);
        assert_eq!(count(&imp, ItemType::IdCard), 1);
        assert_eq!(count(&imp, ItemType::Passport), 1);
        assert_eq!(count(&imp, ItemType::DriverLicense), 1);
        assert_eq!(count(&imp, ItemType::SocialSecurityNumber), 1);
        let card = &imp.items[0].item;
        assert_eq!(card.item_type, ItemType::IdCard);
        assert_eq!(text(card, "number"), "ID-123456");
        assert_eq!(text(card, "country"), "France");
        assert!(card.field("expiry").is_some());
        assert!(card.field("issued_on").is_some());
        let passport = &imp.items[1].item;
        assert_eq!(text(passport, "issuing_country"), "France");
        assert_eq!(text(passport, "number"), "P1234567");
        let license = &imp.items[2].item;
        assert_eq!(text(license, "full_name"), "Alice Example");
        assert_eq!(text(license, "region"), "CA");
        assert_eq!(text(license, "country"), "US");
        let ssn = &imp.items[3].item;
        assert_eq!(text(ssn, "name"), "Alice Example");
        assert_eq!(text(ssn, "number"), "078-05-1120");
        assert_eq!(
            imp.warnings.last(),
            Some(&Warning {
                entry: 4,
                code: "unsupported_entry"
            })
        );
    }

    #[test]
    fn personal_info_builds_identities() {
        let imp = parse_dashlane_csv(PERSONAL).unwrap();
        assert_eq!(imp.items.len(), 2);
        let item = &by_title(&imp, "Alice Example").item;
        assert_eq!(item.item_type, ItemType::Identity);
        assert_eq!(text(item, "first_name"), "Alice");
        assert_eq!(text(item, "middle_name"), "Marie");
        assert_eq!(text(item, "last_name"), "Example");
        assert_eq!(text(item, "honorific"), "MR");
        assert_eq!(text(item, "birth_place"), "Paris");
        assert!(item.field("birth_date").is_some());
        assert_eq!(text(item, "email"), "alice@example.com");
        assert_eq!(text(item, "mobile_phone"), "+15551230000");
        assert_eq!(text(item, "website"), "https://alice.example.com");
        assert_eq!(text(item, "job_title"), "Engineer");
        match &item.field("address").unwrap().value {
            FieldValue::Address(a) => {
                assert_eq!(a.line1, "1 Example Street");
                assert_eq!(a.city, "Springfield");
                assert_eq!(a.postal_code, "90210");
                assert_eq!(a.region, "CA");
                assert_eq!(a.country, "US");
            }
            other => panic!("unexpected {other:?}"),
        }
        let bob = &by_title(&imp, "Bob Sample").item;
        assert_eq!(text(bob, "email"), "bob@example.org");
    }

    #[test]
    fn orphan_personal_rows() {
        let header = "type,first_name,last_name,email\n";
        let csv = format!("{header}email,,,orphan@example.com\nemail,Carol,,carol@example.com\n");
        let imp = parse_dashlane_csv(csv.as_bytes()).unwrap();
        assert_eq!(imp.items.len(), 1);
        assert_eq!(imp.items[0].item.item_type, ItemType::Identity);
        assert_eq!(text(&imp.items[0].item, "first_name"), "Carol");
        assert_eq!(imp.skipped, 1);
        assert_eq!(imp.warnings[0].entry, 0);
        assert_eq!(imp.warnings[0].code, "unsupported_entry");
    }

    #[test]
    fn zip_of_all_files() {
        let bytes = zip_of(&[
            ("Dashlane/credentials.csv", CREDENTIALS),
            ("Dashlane/securenotes.csv", NOTES),
            ("Dashlane/PAYMENTS.csv", PAYMENTS),
            ("Dashlane/ids.csv", IDS),
            ("Dashlane/personalInfo.csv", PERSONAL),
        ]);
        let imp = parse_dashlane_zip(&bytes).unwrap();
        assert_eq!(count(&imp, ItemType::Login), 3);
        assert_eq!(count(&imp, ItemType::SecureNote), 2);
        assert_eq!(count(&imp, ItemType::CreditCard), 1);
        assert_eq!(count(&imp, ItemType::BankAccount), 1);
        assert_eq!(count(&imp, ItemType::IdCard), 1);
        assert_eq!(count(&imp, ItemType::Passport), 1);
        assert_eq!(count(&imp, ItemType::DriverLicense), 1);
        assert_eq!(count(&imp, ItemType::SocialSecurityNumber), 1);
        assert_eq!(count(&imp, ItemType::Identity), 2);
        assert_eq!(imp.items.len(), 13);
        // Processing order is fixed: logins first, identities last.
        assert_eq!(imp.items[0].item.item_type, ItemType::Login);
        assert_eq!(imp.items[12].item.item_type, ItemType::Identity);
    }

    #[test]
    fn zip_order_ignores_archive_order_and_flags_unknown_entries() {
        let bytes = zip_of(&[
            ("personalinfo.csv", PERSONAL),
            ("readme.txt", b"hello"),
            ("credentials.csv", CREDENTIALS),
        ]);
        let imp = parse_dashlane_zip(&bytes).unwrap();
        assert_eq!(imp.items[0].item.item_type, ItemType::Login);
        assert_eq!(imp.items.len(), 5);
        let unknown: Vec<_> = imp
            .warnings
            .iter()
            .filter(|w| w.code == "unsupported_entry")
            .collect();
        assert_eq!(unknown.len(), 1);
        assert_eq!(unknown[0].entry, 1);
        // One blank credentials row plus the unknown entry.
        assert_eq!(imp.skipped, 2);
    }

    #[test]
    fn zip_without_dashlane_files_is_rejected() {
        let bytes = zip_of(&[("other.csv", b"a,b\n1,2\n")]);
        assert!(matches!(
            parse_dashlane_zip(&bytes),
            Err(Error::InvalidFormat(_))
        ));
    }

    #[test]
    fn encrypted_dash_rejected() {
        assert!(matches!(
            parse_dashlane_csv(b"DASH\x01\x02binary"),
            Err(Error::InvalidFormat(_))
        ));
        assert!(matches!(
            parse_dashlane_zip(b"DASH\x01\x02binary"),
            Err(Error::InvalidFormat(_))
        ));
        assert!(matches!(
            parse_dashlane_csv(&[0xff, 0xfe, 0x00, 0x41]),
            Err(Error::InvalidFormat(_))
        ));
    }

    #[test]
    fn unknown_header_rejected() {
        assert!(matches!(
            parse_dashlane_csv(b"foo,bar\n1,2\n"),
            Err(Error::InvalidFormat(_))
        ));
        assert!(matches!(
            parse_dashlane_csv(b""),
            Err(Error::InvalidFormat(_))
        ));
    }
}
