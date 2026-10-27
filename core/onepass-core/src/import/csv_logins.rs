//! CSV login exports (spec 4.3): Chrome/Edge/Brave, Safari/Apple, Firefox,
//! 1Password CSV, Bitwarden CSV, Proton Pass CSV and the OnePass CSV
//! export (`export::csv_plaintext`).

use time::OffsetDateTime;

use crate::error::{Error, Result};
use crate::model::ItemType;

use super::build::{Draft, host_of};
use super::limits::{csv_records, zip_entries};
use super::{Format, Import, Warning};

/// Column handler of one format: fills `d` from column `col` (lower-case
/// header name) and returns `false` for a column it does not know, which
/// then lands in `imported`.
type Apply = fn(&mut Draft, ItemType, &str, &str) -> bool;

/// Parses `bytes` and turns every row into a [`Draft`] through `apply`.
/// `kind_col` names a column that selects `login` or `note` (anything else
/// is an unsupported entry); without it every row is a login.
fn login_rows(bytes: &[u8], kind_col: Option<&str>, apply: Apply) -> Result<Import> {
    let (header, rows) = csv_records(bytes)?;
    Ok(login_records(&header, &rows, kind_col, apply))
}

/// [`login_rows`] over already read records.
fn login_records(
    header: &[String],
    rows: &[Vec<String>],
    kind_col: Option<&str>,
    apply: Apply,
) -> Import {
    let mut out = Import::default();
    for (index, row) in rows.iter().enumerate() {
        let entry = u32::try_from(index).unwrap_or(u32::MAX);
        if row.iter().all(|c| c.trim().is_empty()) {
            out.skipped += 1;
            continue;
        }
        let kind = match kind_col {
            None => Some(ItemType::Login),
            Some(col) => {
                let cell = header
                    .iter()
                    .position(|h| h == col)
                    .and_then(|i| row.get(i))
                    .map_or("", |c| c.trim());
                match cell.to_lowercase().as_str() {
                    "login" => Some(ItemType::Login),
                    "note" => Some(ItemType::SecureNote),
                    _ => None,
                }
            }
        };
        let Some(kind) = kind else {
            out.warnings.push(Warning {
                entry,
                code: "unsupported_entry",
            });
            out.skipped += 1;
            continue;
        };
        let mut d = Draft::new(kind);
        for (col, val) in header.iter().zip(row) {
            if !apply(&mut d, kind, col, val) {
                d.extra(col, val, false);
            }
        }
        // Cells past the header width are kept, named by position.
        for (i, val) in row.iter().enumerate().skip(header.len()) {
            d.extra(&format!("column {}", i + 1), val, false);
        }
        d.finish(entry, &mut out);
    }
    out
}

fn truthy(s: &str) -> bool {
    matches!(s.trim().to_lowercase().as_str(), "true" | "1" | "yes")
}

/// Unix time in `unit` ticks per second; `None` when not a number or out
/// of range.
fn unix_time(s: &str, ticks_per_second: i128) -> Option<OffsetDateTime> {
    let n: i128 = s.trim().parse().ok()?;
    OffsetDateTime::from_unix_timestamp_nanos(n.checked_mul(1_000_000_000 / ticks_per_second)?).ok()
}

/// Notes go to `content` for a secure note and to the notes otherwise.
fn note(d: &mut Draft, kind: ItemType, val: &str) {
    if kind == ItemType::SecureNote {
        d.set("content", val);
    } else {
        d.notes(val);
    }
}

/// Columns shared by every login format. `None` when `col` is not one.
fn common(d: &mut Draft, col: &str, val: &str) -> Option<()> {
    match col {
        "username" => d.set("username", val),
        "password" => d.set("password", val),
        "url" => d.url(val),
        _ => return None,
    }
    Some(())
}

fn chrome_apply(d: &mut Draft, _: ItemType, col: &str, val: &str) -> bool {
    match col {
        "name" => d.title(val),
        "note" => d.notes(val),
        _ => return common(d, col, val).is_some(),
    }
    true
}

fn safari_apply(d: &mut Draft, _: ItemType, col: &str, val: &str) -> bool {
    match col {
        "title" => d.title(val),
        "notes" => d.notes(val),
        "otpauth" => d.set("totp", val),
        _ => return common(d, col, val).is_some(),
    }
    true
}

fn firefox_apply(d: &mut Draft, _: ItemType, col: &str, val: &str) -> bool {
    match col {
        "url" => {
            d.url(val);
            if let Some(host) = host_of(val) {
                d.title(&host);
            }
        }
        "timecreated" => match unix_time(val, 1000) {
            Some(t) => d.created(t),
            None => d.bad_value(col, val),
        },
        "timepasswordchanged" => match unix_time(val, 1000) {
            Some(t) => d.updated(t),
            None => d.bad_value(col, val),
        },
        "httprealm" | "formactionorigin" | "guid" | "timelastused" => {}
        _ => return common(d, col, val).is_some(),
    }
    true
}

fn onepassword_apply(d: &mut Draft, _: ItemType, col: &str, val: &str) -> bool {
    match col {
        "title" => d.title(val),
        "notes" => d.notes(val),
        "otpauth" => d.set("totp", val),
        "favorite" => d.favorite(truthy(val)),
        "archived" => d.archived(truthy(val)),
        "tags" => val.split([',', ';']).for_each(|t| d.tag(t)),
        _ => return common(d, col, val).is_some(),
    }
    true
}

fn bitwarden_apply(d: &mut Draft, kind: ItemType, col: &str, val: &str) -> bool {
    match col {
        "type" | "reprompt" => {}
        "folder" => d.folder(val),
        "favorite" => d.favorite(truthy(val)),
        "name" => d.title(val),
        "notes" => note(d, kind, val),
        "fields" => {
            for line in val.lines().filter(|l| !l.trim().is_empty()) {
                match line.split_once(": ") {
                    Some((name, value)) => d.extra(name.trim(), value, false),
                    None => d.extra("fields", line, false),
                }
            }
        }
        "login_uri" => val.split([',', '\n']).for_each(|u| d.url(u)),
        "login_username" => d.set("username", val),
        "login_password" => d.set("password", val),
        "login_totp" => d.set("totp", val),
        _ => return false,
    }
    true
}

fn protonpass_apply(d: &mut Draft, kind: ItemType, col: &str, val: &str) -> bool {
    match col {
        "type" => {}
        "name" => d.title(val),
        "url" => d.url(val),
        "email" => d.set("email", val),
        "username" => d.set("username", val),
        "password" => d.set("password", val),
        "note" => note(d, kind, val),
        "totp" => d.set("totp", val),
        "createtime" => match unix_time(val, 1) {
            Some(t) => d.created(t),
            None => d.bad_value(col, val),
        },
        "modifytime" => match unix_time(val, 1) {
            Some(t) => d.updated(t),
            None => d.bad_value(col, val),
        },
        "vault" => d.folder(val),
        _ => return false,
    }
    true
}

/// Whether `key` looks like a field id written by the OnePass export
/// (`id=value` lines of the `extra` column).
fn is_extra_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= 64
        && key
            .chars()
            .all(|c| c.is_alphanumeric() || matches!(c, '_' | '-' | ' ' | '.'))
}

/// The `extra` cell of the OnePass export: `id=value` lines. A line that
/// does not start with an id continues the previous value (multi-line
/// values such as notes or keys). `url` lines are extra URLs; every other
/// value lands in `imported`, masked.
fn onepass_extra(d: &mut Draft, val: &str) {
    let mut entries: Vec<(String, String)> = Vec::new();
    for line in val.split('\n') {
        match (line.split_once('='), entries.last_mut()) {
            (Some((key, value)), _) if is_extra_key(key) => {
                entries.push((key.to_owned(), value.to_owned()));
            }
            (_, Some((_, value))) => {
                value.push('\n');
                value.push_str(line);
            }
            (_, None) => entries.push(("extra".to_owned(), line.to_owned())),
        }
    }
    for (key, value) in entries {
        if key == "url" {
            d.url(&value);
        } else {
            d.extra(&key, &value, true);
        }
    }
}

fn onepass_apply(d: &mut Draft, _: ItemType, col: &str, val: &str) -> bool {
    match col {
        "title" => d.title(val),
        "type" if val.trim().eq_ignore_ascii_case("login") => {}
        "type" => d.extra("type", val.trim(), false),
        "vault" => d.folder(val),
        "otpauth" => d.set("totp", val),
        "notes" => d.notes(val),
        "tags" => val.split(';').for_each(|t| d.tag(t)),
        "extra" => onepass_extra(d, val),
        _ => return common(d, col, val).is_some(),
    }
    true
}

/// Columns of the OnePass CSV export, in order.
const ONEPASS_HEADER: [&str; 10] = [
    "title", "type", "vault", "url", "username", "password", "otpauth", "notes", "tags", "extra",
];

/// Chrome, Edge and Brave: `name,url,username,password[,note]`.
pub(crate) fn parse_chrome(b: &[u8]) -> Result<Import> {
    login_rows(b, None, chrome_apply)
}

/// Safari and Apple Passwords. Also the zip of Safari's "Export Browsing
/// Data", whose `Passwords.csv` entry is read (the other entries, such as
/// bookmarks and history, are not passwords and are left out).
pub(crate) fn parse_safari(b: &[u8]) -> Result<Import> {
    if b.starts_with(b"PK\x03\x04") {
        let entries = zip_entries(b)?;
        let (_, csv) = entries
            .iter()
            .find(|(name, _)| is_safari_passwords_entry(name))
            .ok_or(Error::InvalidFormat("no Passwords.csv in zip"))?;
        return login_rows(csv, None, safari_apply);
    }
    login_rows(b, None, safari_apply)
}

/// Whether a zip entry is the `Passwords.csv` of a Safari export (base
/// name, any case).
pub(crate) fn is_safari_passwords_entry(name: &str) -> bool {
    name.rsplit(['/', '\\'])
        .next()
        .is_some_and(|base| base.eq_ignore_ascii_case("passwords.csv"))
}

/// Firefox: the title is the host of the URL.
pub(crate) fn parse_firefox(b: &[u8]) -> Result<Import> {
    login_rows(b, None, firefox_apply)
}

pub(crate) fn parse_onepassword_csv(b: &[u8]) -> Result<Import> {
    login_rows(b, None, onepassword_apply)
}

pub(crate) fn parse_bitwarden_csv(b: &[u8]) -> Result<Import> {
    login_rows(b, Some("type"), bitwarden_apply)
}

/// Proton Pass: a login row with an empty username and an email uses the
/// email as username (the email field is kept too).
pub(crate) fn parse_protonpass_csv(b: &[u8]) -> Result<Import> {
    let (header, mut rows) = csv_records(b)?;
    let col = |name: &str| header.iter().position(|h| h == name);
    if let (Some(email), Some(user)) = (col("email"), col("username")) {
        for row in &mut rows {
            let is_login = col("type")
                .and_then(|t| row.get(t))
                .is_some_and(|t| t.trim().eq_ignore_ascii_case("login"));
            if !is_login {
                continue;
            }
            let email = row.get(email).filter(|e| !e.trim().is_empty()).cloned();
            if let (Some(email), Some(cell)) = (email, row.get_mut(user))
                && cell.trim().is_empty()
            {
                *cell = email;
            }
        }
    }
    Ok(login_records(
        &header,
        &rows,
        Some("type"),
        protonpass_apply,
    ))
}

/// OnePass CSV export. Every row is read as a login; a row of another type
/// keeps its type name in `imported` and falls back per the builder rules.
pub(crate) fn parse_onepass_csv(b: &[u8]) -> Result<Import> {
    login_rows(b, None, onepass_apply)
}

/// Format of a lower-cased CSV header among the seven of this module, or
/// `None` (LastPass and Dashlane are told apart by the dispatcher). Chrome
/// and Safari need the exact column set; the others are recognised by
/// their distinctive columns.
pub(crate) fn sniff(header: &[String]) -> Option<Format> {
    let has = |c: &str| header.iter().any(|h| h == c);
    let all = |cs: &[&str]| cs.iter().all(|c| has(c));
    let exactly = |cs: &[&str]| header.len() == cs.len() && all(cs);
    if header == ONEPASS_HEADER {
        Some(Format::OnePassCsv)
    } else if all(&[
        "folder",
        "favorite",
        "type",
        "name",
        "login_uri",
        "login_username",
        "login_password",
        "login_totp",
    ]) {
        Some(Format::BitwardenCsv)
    } else if all(&[
        "type",
        "name",
        "url",
        "email",
        "username",
        "password",
        "note",
        "totp",
        "createtime",
        "modifytime",
        "vault",
    ]) {
        Some(Format::ProtonPassCsv)
    } else if all(&[
        "url",
        "username",
        "password",
        "httprealm",
        "formactionorigin",
        "guid",
    ]) {
        Some(Format::FirefoxCsv)
    } else if all(&[
        "title", "url", "username", "password", "otpauth", "favorite", "archived", "tags",
    ]) {
        Some(Format::OnePasswordCsv)
    } else if exactly(&["title", "url", "username", "password", "notes", "otpauth"]) {
        Some(Format::SafariCsv)
    } else if exactly(&["name", "url", "username", "password"])
        || exactly(&["name", "url", "username", "password", "note"])
    {
        Some(Format::ChromeCsv)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use time::macros::datetime;

    use super::*;
    use crate::import::Warning;
    use crate::import::limits::csv_records;
    use crate::model::{FieldValue, Item, ItemType};

    const CHROME: &[u8] = include_bytes!("../../tests/fixtures/import/chrome.csv");
    const SAFARI: &[u8] = include_bytes!("../../tests/fixtures/import/safari.csv");
    const FIREFOX: &[u8] = include_bytes!("../../tests/fixtures/import/firefox.csv");
    const ONEPASSWORD: &[u8] = include_bytes!("../../tests/fixtures/import/1password.csv");
    const BITWARDEN: &[u8] = include_bytes!("../../tests/fixtures/import/bitwarden.csv");
    const PROTON: &[u8] = include_bytes!("../../tests/fixtures/import/protonpass.csv");

    fn text(item: &Item, id: &str) -> String {
        match item.field(id).map(|f| &f.value) {
            Some(FieldValue::Text(s) | FieldValue::Email(s)) => s.clone(),
            Some(FieldValue::Password(s) | FieldValue::Concealed(s) | FieldValue::Otp(s)) => {
                s.to_string()
            }
            _ => String::new(),
        }
    }

    fn url0(item: &Item) -> &str {
        item.urls.first().map_or("", |u| u.url.as_str())
    }

    fn imported_labels(item: &Item) -> Vec<String> {
        item.sections
            .iter()
            .filter(|s| s.id == "imported")
            .flat_map(|s| s.fields.iter().map(|f| f.label.clone()))
            .collect()
    }

    #[test]
    fn chrome_without_note_column() {
        let imp = parse_chrome(CHROME).unwrap();
        assert_eq!(imp.items.len(), 3);
        assert_eq!(imp.skipped, 1);
        assert!(imp.warnings.is_empty());
        let it = &imp.items[0].item;
        assert_eq!(it.title, "Example Mail");
        assert_eq!(text(it, "username"), "alice@example.com");
        assert_eq!(text(it, "password"), "Tr0ub4dor-Invented1");
        assert_eq!(url0(it), "https://mail.example.com/login");
        assert_eq!(it.notes, "");
        assert_eq!(imp.items[0].folder, None);
    }

    #[test]
    fn chrome_note_column_is_notes() {
        let imp =
            parse_chrome(b"name,url,username,password,note\nA,https://a.example.com,u,p,hello\n")
                .unwrap();
        assert_eq!(imp.items[0].item.notes, "hello");
    }

    #[test]
    fn safari_keeps_otpauth() {
        let imp = parse_safari(SAFARI).unwrap();
        assert_eq!(imp.items.len(), 2);
        let it = &imp.items[0].item;
        assert_eq!(it.title, "Example Mail (alice@example.com)");
        assert_eq!(text(it, "username"), "alice@example.com");
        assert_eq!(text(it, "password"), "Safari-Invented-1");
        assert_eq!(url0(it), "https://mail.example.com");
        assert_eq!(it.notes, "Recovery by phone");
        assert!(text(it, "totp").starts_with("otpauth://totp/"));
        assert!(text(&imp.items[1].item, "totp").is_empty());
    }

    #[test]
    fn firefox_title_is_host_with_dates() {
        let imp = parse_firefox(FIREFOX).unwrap();
        assert_eq!(imp.items.len(), 2);
        let it = &imp.items[0].item;
        assert_eq!(it.title, "www.example.com");
        assert_eq!(text(it, "username"), "alice");
        assert_eq!(text(it, "password"), "Fox-Invented-1");
        assert_eq!(url0(it), "https://www.example.com");
        assert_eq!(it.notes, "");
        assert_eq!(it.created_at, datetime!(2023-11-14 22:13:20 UTC));
        assert_eq!(it.updated_at, datetime!(2023-11-14 22:16:40 UTC));
        assert_eq!(imp.items[1].item.title, "login.example.org");
        // httprealm, formactionorigin, guid, timelastused are ignored.
        assert!(imported_labels(it).is_empty());
    }

    #[test]
    fn onepassword_favorite_and_tags() {
        let imp = parse_onepassword_csv(ONEPASSWORD).unwrap();
        assert_eq!(imp.items.len(), 2);
        let it = &imp.items[0].item;
        assert_eq!(it.title, "Example Mail");
        assert_eq!(text(it, "username"), "alice@example.com");
        assert_eq!(text(it, "password"), "OnePw-Invented-1");
        assert_eq!(url0(it), "https://mail.example.com");
        assert_eq!(it.notes, "Main mailbox");
        assert!(it.favorite);
        assert!(!it.archived);
        assert_eq!(it.tags, vec!["mail", "personal"]);
        assert!(text(it, "totp").starts_with("otpauth://"));
        let b = &imp.items[1].item;
        assert!(!b.favorite);
        assert!(b.archived);
        assert_eq!(b.tags, vec!["work", "legacy"]);
    }

    #[test]
    fn bitwarden_login_note_and_unsupported() {
        let imp = parse_bitwarden_csv(BITWARDEN).unwrap();
        assert_eq!(imp.items.len(), 2);
        assert_eq!(imp.skipped, 1);
        assert_eq!(
            imp.warnings,
            vec![Warning {
                entry: 2,
                code: "unsupported_entry"
            }]
        );
        let it = &imp.items[0].item;
        assert_eq!(it.item_type, ItemType::Login);
        assert_eq!(it.title, "Example Mail");
        assert_eq!(text(it, "username"), "alice@example.com");
        assert_eq!(text(it, "password"), "Bw-Invented-1");
        assert_eq!(url0(it), "https://mail.example.com");
        assert_eq!(it.urls.len(), 2);
        assert_eq!(it.urls[1].url, "https://mail2.example.com");
        assert_eq!(it.notes, "Main mailbox");
        assert!(it.favorite);
        assert_eq!(imp.items[0].folder.as_deref(), Some("Personal"));
        let labels = imported_labels(it);
        assert!(labels.contains(&"Security question".to_owned()));
        assert!(labels.contains(&"PIN".to_owned()));
        assert!(text(it, "totp").starts_with("otpauth://"));
        let n = &imp.items[1].item;
        assert_eq!(n.item_type, ItemType::SecureNote);
        assert_eq!(n.title, "Wifi instructions");
        assert_eq!(
            text(n, "content"),
            "Ask the front desk for the invented code"
        );
        assert_eq!(imp.items[1].folder.as_deref(), Some("Work"));
    }

    #[test]
    fn proton_email_vault_and_times() {
        let imp = parse_protonpass_csv(PROTON).unwrap();
        assert_eq!(imp.items.len(), 2);
        assert_eq!(imp.skipped, 1);
        let it = &imp.items[0].item;
        assert_eq!(it.title, "Example Mail");
        assert_eq!(text(it, "username"), "alice");
        assert_eq!(text(it, "email"), "alice@example.com");
        assert_eq!(text(it, "password"), "Proton-Invented-1");
        assert_eq!(url0(it), "https://mail.example.com");
        assert_eq!(it.notes, "Main mailbox");
        assert_eq!(imp.items[0].folder.as_deref(), Some("Personal"));
        assert_eq!(it.created_at, datetime!(2023-11-14 22:13:20 UTC));
        assert_eq!(it.updated_at, datetime!(2023-11-14 22:21:40 UTC));
        let n = &imp.items[1].item;
        assert_eq!(n.item_type, ItemType::SecureNote);
        assert_eq!(text(n, "content"), "Invented note body");
        assert_eq!(imp.items[1].folder.as_deref(), Some("Work"));
    }

    #[test]
    fn unknown_column_goes_to_imported() {
        let imp = parse_chrome(b"name,url,username,password,extra thing\nA,,u,p,v\n").unwrap();
        assert_eq!(imported_labels(&imp.items[0].item), vec!["extra thing"]);
    }

    #[test]
    fn short_and_blank_rows() {
        let imp = parse_chrome(b"name,url,username,password\nA\n , ,,\n").unwrap();
        assert_eq!(imp.items.len(), 1);
        assert_eq!(imp.skipped, 1);
        assert_eq!(imp.items[0].item.title, "A");
    }

    #[test]
    fn unparsable_timestamp_is_kept_with_warning() {
        let imp = parse_firefox(
            b"url,username,password,httpRealm,formActionOrigin,guid,timeCreated,timeLastUsed,timePasswordChanged\n\
              https://example.com,u,p,,,,soon,,\n",
        )
        .unwrap();
        assert_eq!(imp.items.len(), 1);
        assert_eq!(imp.warnings.len(), 1);
        assert_eq!(imp.warnings[0].code, "bad_date");
        assert_eq!(imported_labels(&imp.items[0].item), vec!["timecreated"]);
    }

    #[test]
    fn cells_past_header_width_are_kept() {
        let imp = parse_chrome(b"name,url,username,password\nA,,u,p,spare,more\n").unwrap();
        assert_eq!(
            imported_labels(&imp.items[0].item),
            vec!["column 5", "column 6"]
        );
    }

    #[test]
    fn proton_empty_username_takes_email() {
        let imp = parse_protonpass_csv(
            b"type,name,url,email,username,password,note,totp,createTime,modifyTime,vault\n\
              login,Mail,https://mail.example.com,bob@example.com,,Pw-Invented-2,,,,,\n",
        )
        .unwrap();
        let it = &imp.items[0].item;
        assert_eq!(it.item_type, ItemType::Login);
        assert_eq!(text(it, "username"), "bob@example.com");
        assert_eq!(text(it, "email"), "bob@example.com");
    }

    const ONEPASS_HEAD: &str = "title,type,vault,url,username,password,otpauth,notes,tags,extra\n";

    #[test]
    fn onepass_csv_login_row() {
        let csv = format!(
            "{ONEPASS_HEAD}Mail,login,Perso,https://mail.example.com,alice,Pw-Invented-1,\
             otpauth://totp/x?secret=JBSWY3DPEHPK3PXP,hello,a;b,\"pin=1234\nurl=https://alt.example.com\nnote=line one\nline two\"\n"
        );
        let imp = parse_onepass_csv(csv.as_bytes()).unwrap();
        assert_eq!(imp.items.len(), 1);
        let it = &imp.items[0].item;
        assert_eq!(it.item_type, ItemType::Login);
        assert_eq!(it.title, "Mail");
        assert_eq!(imp.items[0].folder.as_deref(), Some("Perso"));
        assert_eq!(text(it, "username"), "alice");
        assert_eq!(text(it, "password"), "Pw-Invented-1");
        assert!(text(it, "totp").starts_with("otpauth://totp/"));
        assert_eq!(it.notes, "hello");
        assert_eq!(it.tags, vec!["a", "b"]);
        assert_eq!(it.urls.len(), 2);
        assert_eq!(it.urls[1].url, "https://alt.example.com");
        let imported: Vec<_> = it
            .sections
            .iter()
            .filter(|s| s.id == "imported")
            .flat_map(|s| s.fields.iter())
            .map(|f| (f.label.clone(), f.value.clone()))
            .collect();
        assert!(
            imported
                .iter()
                .any(|(l, v)| l == "pin" && *v == FieldValue::Concealed("1234".to_owned().into()))
        );
        assert!(imported.iter().any(|(l, v)| l == "note"
            && *v == FieldValue::Concealed("line one\nline two".to_owned().into())));
    }

    #[test]
    fn onepass_csv_other_type_keeps_type_name() {
        let csv = format!("{ONEPASS_HEAD}Card,credit-card,Perso,,,,,,,number=4111\n");
        let imp = parse_onepass_csv(csv.as_bytes()).unwrap();
        let it = &imp.items[0].item;
        assert!(imported_labels(it).contains(&"type".to_owned()));
        assert!(imported_labels(it).contains(&"number".to_owned()));
        assert!(crate::model::validate(it).is_ok());
    }

    fn header(b: &[u8]) -> Vec<String> {
        csv_records(b).unwrap().0
    }

    #[test]
    fn sniff_recognises_each_format() {
        assert_eq!(sniff(&header(CHROME)), Some(Format::ChromeCsv));
        assert_eq!(
            sniff(&header(b"name,url,username,password,note\n")),
            Some(Format::ChromeCsv)
        );
        assert_eq!(sniff(&header(SAFARI)), Some(Format::SafariCsv));
        assert_eq!(sniff(&header(FIREFOX)), Some(Format::FirefoxCsv));
        assert_eq!(sniff(&header(ONEPASSWORD)), Some(Format::OnePasswordCsv));
        assert_eq!(sniff(&header(BITWARDEN)), Some(Format::BitwardenCsv));
        assert_eq!(sniff(&header(PROTON)), Some(Format::ProtonPassCsv));
        assert_eq!(
            sniff(&header(ONEPASS_HEAD.as_bytes())),
            Some(Format::OnePassCsv)
        );
        assert_eq!(sniff(&header(b"a,b,c\n")), None);
        assert_eq!(sniff(&[]), None);
        // LastPass and Dashlane are told apart by the dispatcher.
        assert_eq!(
            sniff(&header(b"url,username,password,extra,name,grouping,fav\n")),
            None
        );
    }
}
