//! Keeper CSV export.
//!
//! Keeper writes no header: each row is `folder, title, login, password,
//! website address, notes, shared folder`, then custom fields as name and
//! value pairs. A custom field named `TFC:Keeper` holds the TOTP URI. Some
//! exports start with a header row naming those columns: it is recognised
//! and skipped. Every row is a Login (the builder falls back to Password
//! or SecureNote when the row has no username or no password).

use crate::error::Result;
use crate::model::ItemType;

use super::Import;
use super::build::Draft;
use super::limits::csv_rows;

/// Name of the custom field Keeper stores the TOTP URI under.
const TOTP_FIELD: &str = "TFC:Keeper";

/// Leading columns of a Keeper header row, lower-cased.
const HEADER: [&str; 5] = ["folder", "title", "login", "password", "website address"];

/// Whether a lower-cased first CSV line is a Keeper header. A header-less
/// export cannot be told from other CSVs: it is imported only when the
/// format is chosen explicitly.
pub(crate) fn is_keeper_header(header: &[String]) -> bool {
    header.len() >= HEADER.len() && header.iter().zip(HEADER).all(|(h, k)| h == k)
}

fn cell(row: &[String], i: usize) -> &str {
    row.get(i).map_or("", String::as_str)
}

pub(crate) fn parse_keeper_csv(b: &[u8]) -> Result<Import> {
    let rows = csv_rows(b)?;
    let mut out = Import::default();
    let mut rows = rows.iter().peekable();
    if let Some(first) = rows.peek() {
        let lower: Vec<String> = first.iter().map(|c| c.trim().to_lowercase()).collect();
        if is_keeper_header(&lower) {
            rows.next();
        }
    }
    for (index, row) in rows.enumerate() {
        let entry = u32::try_from(index).unwrap_or(u32::MAX);
        if row.iter().all(|c| c.trim().is_empty()) {
            out.skipped += 1;
            continue;
        }
        let mut d = Draft::new(ItemType::Login);
        let (folder, shared) = (cell(row, 0).trim(), cell(row, 6).trim());
        if folder.is_empty() {
            d.folder(shared);
        } else {
            d.folder(folder);
            if shared != folder {
                d.extra("Shared Folder", shared, false);
            }
        }
        d.title(cell(row, 1));
        d.set("username", cell(row, 2));
        d.set("password", cell(row, 3));
        d.url(cell(row, 4));
        d.notes(cell(row, 5));
        let mut custom = row.iter().skip(7);
        let mut position = 8usize;
        while let Some(name) = custom.next() {
            match custom.next() {
                Some(value) if name.trim() == TOTP_FIELD => d.set("totp", value),
                Some(value) => {
                    let name = name.trim();
                    if name.is_empty() {
                        d.extra(&format!("column {}", position + 1), value, false);
                    } else {
                        d.extra(name, value, false);
                    }
                }
                // A name without a value: kept, named by position.
                None => d.extra(&format!("column {position}"), name, false),
            }
            position += 2;
        }
        d.finish(entry, &mut out);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{FieldValue, Item, validate};

    const KEEPER: &[u8] = include_bytes!("../../tests/fixtures/import/keeper.csv");

    fn text(item: &Item, id: &str) -> String {
        match item.field(id).map(|f| &f.value) {
            Some(FieldValue::Text(s)) => s.clone(),
            Some(FieldValue::Password(s) | FieldValue::Otp(s)) => s.to_string(),
            _ => String::new(),
        }
    }

    fn labels(item: &Item) -> Vec<String> {
        item.sections
            .iter()
            .filter(|s| s.id == "imported")
            .flat_map(|s| s.fields.iter().map(|f| f.label.clone()))
            .collect()
    }

    #[test]
    fn rows_without_header() {
        let imp = parse_keeper_csv(KEEPER).unwrap();
        assert_eq!(imp.items.len(), 3);
        assert_eq!(imp.skipped, 1);
        for it in &imp.items {
            validate(&it.item).unwrap();
        }
        let a = &imp.items[0];
        assert_eq!(a.item.title, "Example Mail");
        assert_eq!(a.folder.as_deref(), Some("Personal"));
        assert_eq!(text(&a.item, "username"), "alice@example.com");
        assert_eq!(text(&a.item, "password"), "Keeper-Invented-1");
        assert_eq!(a.item.urls[0].url, "https://mail.example.com");
        assert_eq!(a.item.notes, "Main mailbox");
        assert!(text(&a.item, "totp").starts_with("otpauth://totp/"));
        assert_eq!(labels(&a.item), vec!["Security question"]);

        let b = &imp.items[1];
        assert_eq!(b.folder.as_deref(), Some("Team"));
        assert!(labels(&b.item).is_empty());

        // No username: falls back, keeping the password.
        let c = &imp.items[2].item;
        assert_eq!(c.item_type, ItemType::Password);
        assert!(labels(c).contains(&"column 10".to_owned()));
    }

    #[test]
    fn header_row_is_skipped() {
        let csv =
            b"Folder,Title,Login,Password,Website Address,Notes,Shared Folder,Custom Fields\n\
            ,Shop,bob,Pw-Invented-2,https://shop.example.org,,,\n";
        let imp = parse_keeper_csv(csv).unwrap();
        assert_eq!(imp.items.len(), 1);
        assert_eq!(imp.items[0].item.title, "Shop");
        let lower: Vec<String> = "folder,title,login,password,website address,notes"
            .split(',')
            .map(str::to_owned)
            .collect();
        assert!(is_keeper_header(&lower));
        assert!(!is_keeper_header(&lower[..4]));
    }
}
