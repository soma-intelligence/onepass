//! CSV login exports (spec 4.3): Chrome/Edge/Brave, Safari/Apple, Firefox,
//! 1Password CSV, Bitwarden CSV and Proton Pass CSV.

// `sniff` and the parsers are consumed by the import dispatcher (task 9).
#![allow(dead_code)]

use time::OffsetDateTime;

use crate::error::Result;
use crate::model::ItemType;

use super::build::{Draft, host_of};
use super::limits::csv_records;
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
        d.finish(entry, &mut out);
    }
    Ok(out)
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
        "timecreated" => {
            if let Some(t) = unix_time(val, 1000) {
                d.created(t);
            }
        }
        "timepasswordchanged" => {
            if let Some(t) = unix_time(val, 1000) {
                d.updated(t);
            }
        }
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
        "createtime" => {
            if let Some(t) = unix_time(val, 1) {
                d.created(t);
            }
        }
        "modifytime" => {
            if let Some(t) = unix_time(val, 1) {
                d.updated(t);
            }
        }
        "vault" => d.folder(val),
        _ => return false,
    }
    true
}

/// Chrome, Edge and Brave: `name,url,username,password[,note]`.
pub(crate) fn parse_chrome(b: &[u8]) -> Result<Import> {
    login_rows(b, None, chrome_apply)
}

/// Safari and Apple Passwords.
pub(crate) fn parse_safari(b: &[u8]) -> Result<Import> {
    login_rows(b, None, safari_apply)
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

pub(crate) fn parse_protonpass_csv(b: &[u8]) -> Result<Import> {
    login_rows(b, Some("type"), protonpass_apply)
}

/// Format of a lower-cased CSV header among the six of this module, or
/// `None` (LastPass and Dashlane are told apart by the dispatcher). Chrome
/// and Safari need the exact column set; the others are recognised by
/// their distinctive columns.
pub(crate) fn sniff(header: &[String]) -> Option<Format> {
    let has = |c: &str| header.iter().any(|h| h == c);
    let all = |cs: &[&str]| cs.iter().all(|c| has(c));
    let exactly = |cs: &[&str]| header.len() == cs.len() && all(cs);
    if all(&[
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
        assert_eq!(sniff(&header(b"a,b,c\n")), None);
        assert_eq!(sniff(&[]), None);
        // LastPass and Dashlane belong to task 9.
        assert_eq!(
            sniff(&header(b"url,username,password,extra,name,grouping,fav\n")),
            None
        );
    }
}
