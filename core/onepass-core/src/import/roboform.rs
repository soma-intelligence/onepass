//! RoboForm CSV export (Logins and Safenotes).
//!
//! Columns `Name,Url,MatchUrl,Login,Pwd,Note,Folder,RfFieldsV2`, read by
//! name. A row without URL, login or password is a Safenote and becomes a
//! SecureNote. Folders are paths starting with `/`, which is dropped.
//! `RfFieldsV2` (the form fields RoboForm fills) is kept whole, masked: it
//! can hold typed values.

use crate::error::Result;
use crate::model::ItemType;

use super::Import;
use super::build::Draft;
use super::limits::csv_records;

/// Whether a lower-cased CSV header is a RoboForm export.
pub(crate) fn is_roboform_header(header: &[String]) -> bool {
    let has = |c: &str| header.iter().any(|h| h == c);
    ["name", "url", "matchurl", "login", "pwd"]
        .iter()
        .all(|c| has(c))
}

pub(crate) fn parse_roboform_csv(b: &[u8]) -> Result<Import> {
    let (header, rows) = csv_records(b)?;
    let col = |name: &str| header.iter().position(|h| h == name);
    let mut out = Import::default();
    for (index, row) in rows.iter().enumerate() {
        let entry = u32::try_from(index).unwrap_or(u32::MAX);
        if row.iter().all(|c| c.trim().is_empty()) {
            out.skipped += 1;
            continue;
        }
        let get = |name: &str| col(name).and_then(|i| row.get(i)).map_or("", |c| c.trim());
        let is_note = ["url", "matchurl", "login", "pwd"]
            .iter()
            .all(|c| get(c).is_empty());
        let kind = if is_note {
            ItemType::SecureNote
        } else {
            ItemType::Login
        };
        let mut d = Draft::new(kind);
        for (name, val) in header.iter().zip(row) {
            match name.as_str() {
                "name" => d.title(val),
                "url" => d.url(val),
                // The page the login form is on: a second URL when it
                // differs from the first.
                "matchurl" if val.trim() != get("url") => d.url(val),
                "matchurl" => {}
                "login" => d.set("username", val),
                "pwd" => d.set("password", val),
                "note" if is_note => d.set("content", val),
                "note" => d.notes(val),
                "folder" => d.folder(val.trim().trim_start_matches('/')),
                "rffieldsv2" => d.extra("RfFieldsV2", val, true),
                _ => d.extra(name, val, false),
            }
        }
        for (i, val) in row.iter().enumerate().skip(header.len()) {
            d.extra(&format!("column {}", i + 1), val, false);
        }
        d.finish(entry, &mut out);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::import::limits::csv_records;
    use crate::model::{FieldValue, Item, validate};

    const ROBOFORM: &[u8] = include_bytes!("../../tests/fixtures/import/roboform.csv");

    fn text(item: &Item, id: &str) -> String {
        match item.field(id).map(|f| &f.value) {
            Some(FieldValue::Text(s)) => s.clone(),
            Some(FieldValue::Password(s) | FieldValue::Concealed(s)) => s.to_string(),
            _ => String::new(),
        }
    }

    #[test]
    fn logins_and_safenotes() {
        assert!(is_roboform_header(&csv_records(ROBOFORM).unwrap().0));
        let imp = parse_roboform_csv(ROBOFORM).unwrap();
        assert_eq!(imp.items.len(), 3);
        assert_eq!(imp.skipped, 1);
        for it in &imp.items {
            validate(&it.item).unwrap();
        }
        let a = &imp.items[0];
        assert_eq!(a.item.item_type, ItemType::Login);
        assert_eq!(a.item.title, "Example Mail");
        assert_eq!(a.folder.as_deref(), Some("Personal"));
        assert_eq!(text(&a.item, "username"), "alice@example.com");
        assert_eq!(text(&a.item, "password"), "Robo-Invented-1");
        assert_eq!(a.item.notes, "Main mailbox");
        assert_eq!(a.item.urls.len(), 2);
        assert_eq!(a.item.urls[1].url, "https://mail.example.com/login");
        assert!(a.item.sections.iter().any(|s| {
            s.id == "imported"
                && s.fields
                    .iter()
                    .any(|f| f.label == "RfFieldsV2" && matches!(f.value, FieldValue::Concealed(_)))
        }));

        let b = &imp.items[1];
        assert_eq!(b.folder.as_deref(), Some("Work/Shops"));
        assert_eq!(b.item.urls.len(), 1);

        let n = &imp.items[2].item;
        assert_eq!(n.item_type, ItemType::SecureNote);
        assert_eq!(text(n, "content"), "Invented note body");
    }
}
