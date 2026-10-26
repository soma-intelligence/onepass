//! LastPass CSV export (spec 4.3): logins plus typed secure notes.
//!
//! Columns `url,username,password,totp,extra,name,grouping,fav`. A row
//! whose URL is `http://sn` is a secure note; its `extra` cell starts with
//! `NoteType:<type>` followed by `Key:Value` lines. The `Notes` key takes
//! every line after it, and a line without a key continues the previous
//! value (SSH private keys span lines).

use zeroize::Zeroizing;

use crate::error::Result;
use crate::model::{FieldValue, ItemType, SshKeyValue};

use super::Import;
use super::build::Draft;
use super::limits::csv_records;

const NOTE_URL: &str = "http://sn";
/// Longest text taken for a `Key:` before a colon, so prose with a colon in
/// a continuation line stays a value.
const MAX_KEY_LEN: usize = 40;
/// Template ids that hold dates; their English text is normalized.
const DATE_IDS: [&str; 4] = ["expiry", "birth_date", "issued_on", "renewal_date"];

const MONTHS: [&str; 12] = [
    "january",
    "february",
    "march",
    "april",
    "may",
    "june",
    "july",
    "august",
    "september",
    "october",
    "november",
    "december",
];

/// Key of a typed note and the template field id it fills.
type KeyMap = &'static [(&'static str, &'static str)];

/// Type and key table of a `NoteType`; `None` for an unknown one.
fn note_type(name: &str) -> Option<(ItemType, KeyMap)> {
    let t = match name.trim().to_lowercase().as_str() {
        "credit card" => (
            ItemType::CreditCard,
            &[
                ("Name on Card", "cardholder"),
                ("Number", "number"),
                ("Security Code", "cvv"),
                ("Expiration Date", "expiry"),
                ("Type", "card_type"),
            ][..],
        ),
        "bank account" => (
            ItemType::BankAccount,
            &[
                ("Bank Name", "bank"),
                ("Account Number", "account_number"),
                ("Routing Number", "routing_number"),
                ("SWIFT Code", "bic"),
                ("IBAN Number", "iban"),
                ("PIN", "pin"),
                ("Account Type", "account_type"),
            ][..],
        ),
        "wi-fi password" => (
            ItemType::Router,
            &[
                ("SSID", "ssid"),
                ("Password", "wifi_password"),
                ("Connection Type", "security"),
            ][..],
        ),
        "server" => (
            ItemType::Server,
            &[
                ("Hostname", "host"),
                ("Username", "username"),
                ("Password", "password"),
            ][..],
        ),
        "database" => (
            ItemType::Database,
            &[
                ("Type", "engine"),
                ("Hostname", "host"),
                ("Port", "port"),
                ("Database", "database"),
                ("Username", "username"),
                ("Password", "password"),
                ("SID", "service_name"),
                ("Alias", "alias"),
            ][..],
        ),
        // The public key is merged into the private key value.
        "ssh key" => (
            ItemType::SshKey,
            &[("Private Key", "private_key"), ("Passphrase", "passphrase")][..],
        ),
        "passport" => (
            ItemType::Passport,
            &[
                ("Number", "number"),
                ("Country", "issuing_country"),
                ("Expiration Date", "expiry"),
                ("Name", "last_name"),
                ("Date of Birth", "birth_date"),
                ("Issued Date", "issued_on"),
            ][..],
        ),
        "driver's license" => (
            ItemType::DriverLicense,
            &[
                ("Number", "number"),
                ("Name", "full_name"),
                ("Expiration Date", "expiry"),
                ("State", "region"),
                ("Country", "country"),
            ][..],
        ),
        "social security" => (
            ItemType::SocialSecurityNumber,
            &[("Name", "name"), ("Number", "number")][..],
        ),
        "email account" => (
            ItemType::Email,
            &[
                ("Username", "address"),
                ("Password", "password"),
                ("Server", "incoming_server"),
                ("Port", "incoming_port"),
                ("SMTP Server", "smtp_server"),
                ("SMTP Port", "smtp_port"),
            ][..],
        ),
        "software license" => (
            ItemType::SoftwareLicense,
            &[
                ("License Key", "license_key"),
                ("Licensee", "licensee_name"),
                ("Version", "version"),
            ][..],
        ),
        "membership" => (
            ItemType::Membership,
            &[
                ("Organization", "organization"),
                ("Membership Number", "member_number"),
                ("Member Name", "member_name"),
                ("Expiration Date", "expiry"),
            ][..],
        ),
        "insurance" => (
            ItemType::Insurance,
            &[
                ("Company", "insurer"),
                ("Policy Number", "policy_number"),
                ("Expiration", "renewal_date"),
            ][..],
        ),
        _ => return None,
    };
    Some(t)
}

/// `Month,YYYY` or `Month YYYY` in English: year and month number.
pub(super) fn month_year(s: &str) -> Option<(u16, u8)> {
    let (m, y) = s.trim().split_once([',', ' '])?;
    let month = month_number(m)?;
    let year: u16 = y.trim().parse().ok()?;
    (1000..=9999).contains(&year).then_some((year, month))
}

fn month_number(name: &str) -> Option<u8> {
    let name = name.trim().to_lowercase();
    let i = MONTHS.iter().position(|m| *m == name)?;
    u8::try_from(i + 1).ok()
}

/// `Month D, YYYY` in English as `YYYY-MM-DD`.
pub(super) fn full_date(s: &str) -> Option<String> {
    let (m, rest) = s.trim().split_once(' ')?;
    let (d, y) = rest.split_once(',')?;
    let day: u8 = d.trim().parse().ok()?;
    let year: u16 = y.trim().parse().ok()?;
    let month = month_number(m)?;
    ((1..=31).contains(&day) && (1000..=9999).contains(&year))
        .then(|| format!("{year:04}-{month:02}-{day:02}"))
}

/// Source text of a date field, rewritten to a form the builder reads.
/// A card expiry (month and year) becomes `MM/YYYY`; any other text is
/// left for the builder, which keeps it in `imported` when unreadable.
fn normalized(kind: ItemType, id: &str, raw: &str) -> String {
    if !DATE_IDS.contains(&id) {
        return raw.to_owned();
    }
    if kind == ItemType::CreditCard
        && let Some((year, month)) = month_year(raw)
    {
        return format!("{month:02}/{year:04}");
    }
    full_date(raw).unwrap_or_else(|| raw.to_owned())
}

/// `Key:Value` pairs of the `extra` cell after the `NoteType` line, and the
/// `Notes` text. A line with no usable key continues the previous value;
/// one that comes before any pair is kept in `loose`, never dropped.
struct NoteBody {
    pairs: Vec<(String, String)>,
    notes: String,
    loose: Vec<String>,
}

fn parse_body(lines: &[&str]) -> NoteBody {
    let mut pairs: Vec<(String, String)> = Vec::new();
    let mut loose: Vec<String> = Vec::new();
    let mut notes = String::new();
    let mut in_notes = false;
    // Inside a PEM block every line is part of the value, colons included
    // (`Proc-Type: 4,ENCRYPTED`, `DEK-Info: ...`), up to `-----END`.
    let mut in_pem = false;
    for line in lines {
        if in_notes {
            notes.push('\n');
            notes.push_str(line);
            continue;
        }
        if in_pem {
            if let Some((_, v)) = pairs.last_mut() {
                v.push('\n');
                v.push_str(line);
            }
            in_pem = !line.trim_start().starts_with("-----END");
            continue;
        }
        let key = line
            .split_once(':')
            .filter(|(k, _)| !k.trim().is_empty() && k.len() <= MAX_KEY_LEN);
        match key {
            Some((k, v)) if k.trim() == "Notes" => {
                in_notes = true;
                notes.push_str(v.trim_start());
            }
            Some((k, v)) => {
                let v = v.trim_start();
                in_pem = v.starts_with("-----BEGIN") && !v.contains("-----END");
                pairs.push((k.trim().to_owned(), v.to_owned()));
            }
            None => {
                if let Some((_, v)) = pairs.last_mut() {
                    v.push('\n');
                    v.push_str(line);
                } else if !line.trim().is_empty() {
                    loose.push((*line).to_owned());
                }
            }
        }
    }
    for (_, v) in &mut pairs {
        v.truncate(v.trim_end().len());
    }
    notes.truncate(notes.trim_end().len());
    NoteBody {
        pairs,
        notes,
        loose,
    }
}

/// Fills `d` from the note body of a known `NoteType`.
fn fill_typed(d: &mut Draft, kind: ItemType, keys: KeyMap, body: &NoteBody, row_name: &str) {
    let mut private_key = None;
    let mut public_key = String::new();
    for (key, value) in &body.pairs {
        let id = keys
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
            .map(|(_, id)| *id);
        match id {
            Some("private_key") => private_key = Some(Zeroizing::new(value.clone())),
            Some(id) => {
                d.set(id, &normalized(kind, id, value));
            }
            None if kind == ItemType::SshKey && key.eq_ignore_ascii_case("Public Key") => {
                public_key.clone_from(value);
            }
            None => d.extra(key, value, false),
        }
    }
    let private_key = private_key.filter(|k| !k.trim().is_empty());
    if private_key.is_none() {
        // No key to attach it to: keep the public half.
        d.extra("Public Key", &public_key, false);
    }
    if let Some(private_pem) = private_key {
        d.set_value(
            "private_key",
            FieldValue::SshKey(SshKeyValue {
                private_pem,
                public_openssh: public_key.trim().to_owned(),
                fingerprint_sha256: String::new(),
            }),
        );
    }
    match kind {
        ItemType::BankAccount => d.set("holder", row_name),
        ItemType::SoftwareLicense => d.set("software", row_name),
        _ => {}
    }
    d.extra("note", &body.loose.join("\n"), false);
    d.notes(&body.notes);
}

/// Splits the `extra` cell of a note row into its `NoteType` name (when the
/// first non-blank line carries one) and the remaining lines.
fn split_note(extra: &str) -> (Option<&str>, Vec<&str>) {
    let mut lines = extra.lines();
    let first = lines.by_ref().find(|l| !l.trim().is_empty());
    match first.and_then(|l| l.strip_prefix("NoteType:")) {
        Some(name) => (Some(name), lines.collect()),
        None => (None, first.into_iter().chain(lines).collect()),
    }
}

fn cell<'a>(header: &[String], row: &'a [String], name: &str) -> &'a str {
    header
        .iter()
        .position(|h| h == name)
        .and_then(|i| row.get(i))
        .map_or("", |c| c.as_str())
}

fn row_draft(header: &[String], row: &[String]) -> Draft {
    let name = cell(header, row, "name").trim();
    let extra = cell(header, row, "extra");
    let is_note = cell(header, row, "url").trim() == NOTE_URL;

    let mut d;
    if is_note {
        let (type_name, lines) = split_note(extra);
        let known = type_name.and_then(note_type);
        match known {
            Some((kind, keys)) => {
                d = Draft::new(kind);
                fill_typed(&mut d, kind, keys, &parse_body(&lines), name);
            }
            None if type_name.is_some() => {
                d = Draft::new(ItemType::SecureNote);
                let body = parse_body(&lines);
                for (k, v) in &body.pairs {
                    d.extra(k, v, false);
                }
                d.extra("note", &body.loose.join("\n"), false);
                d.set("content", &body.notes);
            }
            None => {
                d = Draft::new(ItemType::SecureNote);
                d.set("content", &lines.join("\n"));
            }
        }
    } else {
        d = Draft::new(ItemType::Login);
        d.notes(extra);
    }

    for (col, val) in header.iter().zip(row) {
        match col.as_str() {
            "name" => d.title(val),
            "grouping" => d.folder(val),
            "fav" => d.favorite(val.trim() == "1"),
            "extra" => {}
            "url" if !is_note => d.url(val),
            "url" => {}
            "username" | "password" | "totp" if !is_note => d.set(col, val),
            _ => d.extra(col, val, false),
        }
    }
    for (i, val) in row.iter().enumerate().skip(header.len()) {
        d.extra(&format!("column {}", i + 1), val, false);
    }
    d
}

/// LastPass CSV: logins, and secure notes mapped by their `NoteType`.
/// Whether a lower-cased CSV header is a LastPass export (older exports
/// lack the `totp` column).
pub(crate) fn is_lastpass_header(header: &[String]) -> bool {
    const NEW: [&str; 8] = [
        "url", "username", "password", "totp", "extra", "name", "grouping", "fav",
    ];
    const OLD: [&str; 7] = [
        "url", "username", "password", "extra", "name", "grouping", "fav",
    ];
    header.iter().map(String::as_str).eq(NEW) || header.iter().map(String::as_str).eq(OLD)
}

pub(crate) fn parse_lastpass(b: &[u8]) -> Result<Import> {
    let (header, rows) = csv_records(b)?;
    let mut out = Import::default();
    for (index, row) in rows.iter().enumerate() {
        let entry = u32::try_from(index).unwrap_or(u32::MAX);
        if row.iter().all(|c| c.trim().is_empty()) {
            out.skipped += 1;
            continue;
        }
        row_draft(&header, row).finish(entry, &mut out);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{FieldValue, Item, ItemType, template};

    const LASTPASS: &[u8] = include_bytes!("../../tests/fixtures/import/lastpass.csv");

    fn text(item: &Item, id: &str) -> String {
        match item.field(id).map(|f| &f.value) {
            Some(FieldValue::Text(s) | FieldValue::Email(s) | FieldValue::Menu(s)) => s.clone(),
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

    #[test]
    fn login_row() {
        let imp = parse_lastpass(LASTPASS).unwrap();
        assert_eq!(imp.items.len(), 8);
        assert_eq!(imp.skipped, 1);
        let it = by_title(&imp, "Example Mail");
        assert_eq!(it.folder.as_deref(), Some("Personal"));
        let item = &it.item;
        assert_eq!(item.item_type, ItemType::Login);
        assert!(item.favorite);
        assert_eq!(text(item, "username"), "alice@example.com");
        assert_eq!(text(item, "password"), "Tr0ub4dor-Invented1");
        assert!(text(item, "totp").starts_with("otpauth://totp/"));
        assert_eq!(item.urls[0].url, "https://mail.example.com/login");
        assert_eq!(item.notes, "Recovery code in the drawer");
    }

    #[test]
    fn credit_card_note() {
        let imp = parse_lastpass(LASTPASS).unwrap();
        let it = by_title(&imp, "Example Visa");
        assert_eq!(it.folder.as_deref(), Some("Finance"));
        let item = &it.item;
        assert_eq!(item.item_type, ItemType::CreditCard);
        assert!(!item.favorite);
        assert_eq!(text(item, "cardholder"), "Alice Example");
        assert_eq!(text(item, "number"), "4111111111111111");
        assert_eq!(text(item, "cvv"), "123");
        assert_eq!(
            item.field("expiry").unwrap().value,
            FieldValue::MonthYear {
                year: 2027,
                month: 6
            }
        );
        assert_eq!(item.notes, "Test card\nSecond line: with a colon");
        // Keys with no slot are kept, not dropped.
        let extra = imported(item);
        assert!(extra.iter().any(|(l, _)| l == "Start Date"));
        assert!(extra.iter().any(|(l, _)| l == "Language"));
    }

    #[test]
    fn wifi_note_to_router() {
        let imp = parse_lastpass(LASTPASS).unwrap();
        let item = &by_title(&imp, "Home Wi-Fi").item;
        assert_eq!(item.item_type, ItemType::Router);
        assert_eq!(text(item, "ssid"), "ExampleNet");
        assert_eq!(text(item, "wifi_password"), "wifi-Invented-3");
        assert_eq!(text(item, "security"), "WPA2");
        assert_eq!(item.notes, "Living room");
    }

    #[test]
    fn unknown_note_type_secure_note() {
        let imp = parse_lastpass(LASTPASS).unwrap();
        let item = &by_title(&imp, "Odd Note").item;
        assert_eq!(item.item_type, ItemType::SecureNote);
        assert_eq!(text(item, "content"), "hello\nworld");
        let extra = imported(item);
        assert!(
            extra
                .iter()
                .any(|(l, v)| l == "Foo" && *v == FieldValue::Text("bar".into()))
        );
        // A secret-looking key is masked.
        assert!(
            extra
                .iter()
                .any(|(l, v)| l == "Secret Code" && matches!(v, FieldValue::Concealed(_)))
        );
    }

    #[test]
    fn notes_key_absorbs_following_lines() {
        let imp = parse_lastpass(LASTPASS).unwrap();
        // "Second line: with a colon" must not become a key.
        let item = &by_title(&imp, "Example Visa").item;
        assert!(imported(item).iter().all(|(l, _)| l != "Second line"));
        assert_eq!(item.notes, "Test card\nSecond line: with a colon");
    }

    #[test]
    fn ssh_key_note() {
        let imp = parse_lastpass(LASTPASS).unwrap();
        let item = &by_title(&imp, "Example Deploy Key").item;
        assert_eq!(item.item_type, ItemType::SshKey);
        match &item.field("private_key").unwrap().value {
            FieldValue::SshKey(k) => {
                assert_eq!(
                    k.private_pem.as_str(),
                    "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAAFAKEFAKEFAKE\n-----END OPENSSH PRIVATE KEY-----"
                );
                assert_eq!(k.public_openssh, "ssh-ed25519 AAAAFAKE alice@example.com");
                assert!(k.fingerprint_sha256.is_empty());
            }
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(text(item, "passphrase"), "pass-Invented-4");
        assert_eq!(item.notes, "Deploy key");
        let labels: Vec<String> = imported(item).into_iter().map(|(l, _)| l).collect();
        assert!(labels.contains(&"Hostname".to_owned()));
    }

    #[test]
    fn bank_account_holder_defaults_to_row_name() {
        let imp = parse_lastpass(LASTPASS).unwrap();
        let item = &by_title(&imp, "Example Checking").item;
        assert_eq!(item.item_type, ItemType::BankAccount);
        assert_eq!(text(item, "bank"), "Example Bank");
        assert_eq!(text(item, "holder"), "Example Checking");
        assert_eq!(text(item, "routing_number"), "021000021");
        assert_eq!(text(item, "account_number"), "12345678");
        assert_eq!(text(item, "pin"), "4321");
    }

    #[test]
    fn untyped_note_and_wide_row() {
        let imp = parse_lastpass(LASTPASS).unwrap();
        let note = &by_title(&imp, "Plain Note").item;
        assert_eq!(note.item_type, ItemType::SecureNote);
        assert_eq!(
            text(note, "content"),
            "Just a free-form note: no type line\nsecond line"
        );
        let shop = &by_title(&imp, "Example Shop").item;
        assert_eq!(shop.item_type, ItemType::Login);
        assert!(
            imported(shop)
                .iter()
                .any(|(l, v)| l == "column 9" && *v == FieldValue::Text("spare cell".into()))
        );
    }

    #[test]
    fn english_dates() {
        assert_eq!(super::month_year("June,2027"), Some((2027, 6)));
        assert_eq!(super::month_year(" december, 2031 "), Some((2031, 12)));
        assert_eq!(super::month_year("Smarch,2027"), None);
        assert_eq!(
            super::full_date("January 5, 2024").as_deref(),
            Some("2024-01-05")
        );
        assert_eq!(super::full_date("nope"), None);
    }

    fn one_note(extra: &str, name: &str) -> Import {
        let csv = format!(
            "url,username,password,totp,extra,name,grouping,fav\nhttp://sn,,,,\"{}\",{name},,0\n",
            extra.replace('"', "\"\"")
        );
        parse_lastpass(csv.as_bytes()).unwrap()
    }

    #[test]
    fn encrypted_pem_headers_and_blank_lines_stay_in_the_key() {
        let pem = "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,0123ABCD\n\nAAAAFAKE\nhttp://example.com/x\n-----END RSA PRIVATE KEY-----";
        let imp = one_note(
            &format!(
                "NoteType:SSH Key\nPrivate Key: {pem}\nPublic Key:  ssh-ed25519 AAAA\nNotes:n"
            ),
            "K",
        );
        let item = &imp.items[0].item;
        match &item.field("private_key").unwrap().value {
            FieldValue::SshKey(k) => {
                assert_eq!(k.private_pem.as_str(), pem);
                assert_eq!(k.public_openssh, "ssh-ed25519 AAAA");
            }
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(item.notes, "n");
    }

    #[test]
    fn keyless_lines_are_kept() {
        let imp = one_note("NoteType:Custom\n:foo\nsome prose\nA:  b", "N");
        let item = &imp.items[0].item;
        assert_eq!(item.item_type, ItemType::SecureNote);
        let extra = imported(item);
        assert!(extra.contains(&(
            "note".to_owned(),
            FieldValue::Text(":foo\nsome prose".into())
        )));
        // Leading space after the colon is dropped.
        assert!(extra.contains(&("A".to_owned(), FieldValue::Text("b".into()))));
    }

    #[test]
    fn public_key_without_private_key_is_kept() {
        let imp = one_note("NoteType:SSH Key\nPublic Key:ssh-ed25519 AAAA", "P");
        let labels: Vec<String> = imported(&imp.items[0].item)
            .into_iter()
            .map(|(l, _)| l)
            .collect();
        assert!(labels.contains(&"Public Key".to_owned()));
    }

    #[test]
    fn note_type_table_ids_exist_in_templates() {
        let names = [
            "Credit Card",
            "Bank Account",
            "Wi-Fi Password",
            "Server",
            "Database",
            "SSH Key",
            "Passport",
            "Driver's License",
            "Social Security",
            "Email Account",
            "Software License",
            "Membership",
            "Insurance",
        ];
        for name in names {
            let (kind, keys) = note_type(name).expect(name);
            let ids: Vec<String> = template(kind)
                .into_iter()
                .flat_map(|s| s.fields.into_iter().map(|f| f.id))
                .collect();
            for (key, id) in keys {
                assert!(ids.iter().any(|i| i == id), "{name}: {key} -> {id}");
            }
        }
    }

    #[test]
    fn server_and_passport_notes() {
        let imp = one_note(
            "NoteType:Server\nHostname:db.example.com\nUsername:root\nPassword:srv-Invented-5",
            "Srv",
        );
        let item = &imp.items[0].item;
        assert_eq!(item.item_type, ItemType::Server);
        assert_eq!(text(item, "host"), "db.example.com");
        assert_eq!(text(item, "username"), "root");
        assert_eq!(text(item, "password"), "srv-Invented-5");

        let imp = one_note(
            "NoteType:Passport\nNumber:X1234567\nCountry:Exampleland\nExpiration Date:January 5, 2031\nName:Example\nDate of Birth:March 2, 1990",
            "Pass",
        );
        let item = &imp.items[0].item;
        assert_eq!(item.item_type, ItemType::Passport);
        assert_eq!(text(item, "number"), "X1234567");
        assert_eq!(text(item, "issuing_country"), "Exampleland");
        assert_eq!(text(item, "last_name"), "Example");
        assert!(item.field("expiry").is_some());
        assert!(item.field("birth_date").is_some());
    }
}
