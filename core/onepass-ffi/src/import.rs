//! Import of other password managers' exports: detection, a preview that
//! only counts, and the import into one vault of the session.
//!
//! Nothing here returns or logs a value of the file: summaries hold counts
//! and static warning codes. The bytes handed over by Swift are wiped when
//! the call returns.

use std::collections::BTreeMap;

use onepass_core::Id;
use onepass_core::import::reimport::{self, Outcome};
use onepass_core::import::{self, Format, Import};
use onepass_core::model::{Item, ItemType};
use zeroize::Zeroizing;

use crate::convert::parse_id;
use crate::error::{OnePassError, invalid};
use crate::session::{Session, find_vault};
use crate::types::FfiItemType;

/// How many items of one type an import holds.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiImportTypeCount {
    pub item_type: FfiItemType,
    pub count: u32,
}

/// How many times one warning code was raised. Codes: `field_moved`,
/// `login_to_password`, `to_secure_note`, `totp_moved`,
/// `attachment_skipped`, `unsupported_entry`, `bad_date`.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiImportWarningCount {
    pub code: String,
    pub count: u32,
}

/// Counts of an import (preview or done): never a value.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiImportSummary {
    /// Format name (`import_formats`).
    pub format: String,
    /// Items read (preview) or written (import).
    pub items: u32,
    /// Most common type first.
    pub by_type: Vec<FfiImportTypeCount>,
    pub warnings: Vec<FfiImportWarningCount>,
    /// Blank rows, folder rows, trashed and unsupported entries.
    pub skipped: u32,
    /// Items that stand for one already in the vault from an earlier import
    /// of the same source: `fixed + converted + unchanged` (counted by
    /// `Session::preview_import_into` and `Session::import_items`; 0 in
    /// `preview_import`). `items - updated` are new.
    pub updated: u32,
    /// Items new in the vault (all of them in `preview_import`).
    pub added: u32,
    /// Vault items of the same type the import updates in place: a passkey,
    /// a sign-in method, a blank field added, a value the source changed.
    pub fixed: u32,
    /// Secure notes (or passwords) an older import made instead of a login,
    /// turned back into it in place; the note is archived as it was.
    pub converted: u32,
    /// Exact duplicates (same type, site, username and password) folded
    /// into one item by this import and archived, never deleted.
    pub archived_duplicates: u32,
    /// Vault items that already hold everything: not written.
    pub unchanged: u32,
}

fn count(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

fn summary(format: Format, import: &Import) -> FfiImportSummary {
    let mut by_type: Vec<(ItemType, usize)> = ItemType::ALL
        .iter()
        .map(|t| {
            let n = import
                .items
                .iter()
                .filter(|it| it.item.item_type == *t)
                .count();
            (*t, n)
        })
        .filter(|(_, n)| *n > 0)
        .collect();
    // Stable: equal counts keep the order of the spec.
    by_type.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
    let mut warnings: BTreeMap<&'static str, usize> = BTreeMap::new();
    for w in &import.warnings {
        *warnings.entry(w.code).or_default() += 1;
    }
    FfiImportSummary {
        format: format.name().to_owned(),
        items: count(import.items.len()),
        by_type: by_type
            .into_iter()
            .map(|(t, n)| FfiImportTypeCount {
                item_type: t.into(),
                count: count(n),
            })
            .collect(),
        warnings: warnings
            .into_iter()
            .map(|(code, n)| FfiImportWarningCount {
                code: code.to_owned(),
                count: count(n),
            })
            .collect(),
        skipped: import.skipped,
        updated: 0,
        added: count(import.items.len()),
        fixed: 0,
        converted: 0,
        unchanged: 0,
        archived_duplicates: 0,
    }
}

/// A format `parse` accepts. The OnePass archive needs a passphrase and
/// goes through its own path.
fn importable(name: &str) -> Result<Format, OnePassError> {
    match Format::from_name(name) {
        Some(Format::OnePassArchive) => Err(invalid("onepass archive")),
        Some(f) => Ok(f),
        None => Err(invalid("import format")),
    }
}

fn parse(format: &str, bytes: Vec<u8>) -> Result<(Format, Import), OnePassError> {
    let bytes = Zeroizing::new(bytes);
    let format = importable(format)?;
    Ok((format, import::parse(format, &bytes)?))
}

/// Names of the formats `preview_import` and `Session::import_items` take,
/// in the core's order.
#[uniffi::export]
pub fn import_formats() -> Vec<String> {
    Format::ALL
        .iter()
        .filter(|f| **f != Format::OnePassArchive)
        .map(|f| f.name().to_owned())
        .collect()
}

/// The format of an export, guessed from its content (the file name is not
/// trusted). `None` when unknown. A OnePass archive is reported as
/// `onepass`, which the import functions refuse.
#[uniffi::export]
pub fn detect_import_format(file_name: String, bytes: Vec<u8>) -> Option<String> {
    let bytes = Zeroizing::new(bytes);
    import::detect(&file_name, &bytes).map(|f| f.name().to_owned())
}

/// Parses the export and counts what it holds, without a session and
/// without writing anything. An encrypted or damaged export is
/// `InvalidInput`, whose `what` says why (in English, no value).
#[uniffi::export]
pub fn preview_import(format: String, bytes: Vec<u8>) -> Result<FfiImportSummary, OnePassError> {
    let (format, import) = parse(&format, bytes)?;
    Ok(summary(format, &import))
}

/// What an import writes: the imported items to save, then the archived
/// ones (converted notes as they were, folded exact duplicates).
struct Prepared {
    items: Vec<Item>,
    archived: Vec<Item>,
    counts: reimport::Counts,
}

/// The items of an import ready for `vault`, matched against `existing`
/// (the vault's items, `import::reimport`): an item an earlier import of the
/// same source made is updated in place (same id), a fallback secure note
/// becomes the login it stood for (the note archived as it was), exact
/// duplicates fold into one (the others archived), and an item holding
/// nothing new is left out. Nothing is ever deleted. Every item to write is
/// validated before the first write, so an invalid one refuses the whole
/// import.
fn prepared(
    format: Format,
    import: Import,
    vault: Id,
    existing: &[Item],
) -> Result<Prepared, OnePassError> {
    let now = time::OffsetDateTime::now_utc();
    let plan = reimport::reconcile(format, import, vault, existing, now);
    let counts = plan.counts();
    let valid = |item: Item| Ok(crate::validate_for_save(item)?);
    let items = plan
        .items
        .into_iter()
        .filter(|p| p.outcome != Outcome::Unchanged)
        .map(|p| valid(p.item))
        .collect::<Result<Vec<_>, OnePassError>>()?;
    let archived = plan
        .archived_notes
        .into_iter()
        .chain(plan.archived_duplicates)
        .map(valid)
        .collect::<Result<Vec<_>, OnePassError>>()?;
    Ok(Prepared {
        items,
        archived,
        counts,
    })
}

/// Fills the outcome counts of a summary: the dry run shown before
/// writing, and the result after.
fn with_counts(mut s: FfiImportSummary, c: reimport::Counts) -> FfiImportSummary {
    s.added = c.added;
    s.fixed = c.fixed;
    s.converted = c.converted;
    s.unchanged = c.unchanged;
    s.archived_duplicates = c.archived_duplicates;
    s.updated = c
        .fixed
        .saturating_add(c.converted)
        .saturating_add(c.unchanged);
    s
}

#[uniffi::export]
impl Session {
    /// Counts what importing the export into `vault_id` would do, like
    /// `preview_import`, plus how many items would replace their copy from
    /// an earlier import of the same source (`updated`). Writes nothing.
    pub fn preview_import_into(
        &self,
        format: String,
        bytes: Vec<u8>,
        vault_id: String,
    ) -> Result<FfiImportSummary, OnePassError> {
        let vault_id = parse_id(&vault_id)?;
        let (format, import) = parse(&format, bytes)?;
        let out = summary(format, &import);
        let existing = self.with(|repo| {
            let vault = find_vault(repo, vault_id)?;
            Ok(repo.items(&vault)?)
        })?;
        let counts = prepared(format, import, vault_id, &existing)?.counts;
        Ok(with_counts(out, counts))
    }

    /// Imports an export into the vault `vault_id`. An item that an earlier
    /// import of the same source already made is updated in place (same
    /// id, `import::reimport`); every other item gets a new id. The source
    /// folder becomes a tag. Nothing is written when one item does not
    /// validate. Returns the counts: `items` handled (written or already
    /// up to date), and how many were added, fixed or unchanged.
    pub fn import_items(
        &self,
        format: String,
        bytes: Vec<u8>,
        vault_id: String,
    ) -> Result<FfiImportSummary, OnePassError> {
        let vault_id = parse_id(&vault_id)?;
        let (format, import) = parse(&format, bytes)?;
        let mut done = summary(format, &import);
        let existing = self.with(|repo| {
            let vault = find_vault(repo, vault_id)?;
            Ok(repo.items(&vault)?)
        })?;
        let Prepared {
            items,
            archived,
            counts,
        } = prepared(format, import, vault_id, &existing)?;
        done = with_counts(done, counts);
        let imported = items.len();
        let items: Vec<Item> = items.into_iter().chain(archived).collect();
        // `with` runs the closure again after a conflict: it resumes after
        // the last item written instead of writing the first ones twice.
        let mut next = 0usize;
        let now = time::OffsetDateTime::now_utc();
        self.with(|repo| {
            let vault = find_vault(repo, vault_id)?;
            while let Some(item) = items.get(next) {
                let mut item = item.clone();
                let kind = if next < imported {
                    onepass_core::model::EventKind::Imported {
                        format: format.name().to_owned(),
                    }
                } else {
                    onepass_core::model::EventKind::Archived
                };
                item.record(now, kind);
                repo.save_item(&vault, item)?;
                next += 1;
            }
            Ok(())
        })?;
        done.items = counts
            .added
            .saturating_add(counts.fixed)
            .saturating_add(counts.converted)
            .saturating_add(counts.unchanged);
        Ok(done)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn archive_and_unknown_formats_are_refused() {
        assert!(!import_formats().contains(&"onepass".to_owned()));
        assert!(import_formats().contains(&"nordpass-csv".to_owned()));
        assert!(import_formats().contains(&"pdf-text".to_owned()));
        assert_eq!(
            preview_import("onepass".into(), b"OPARCH".to_vec()),
            Err(invalid("onepass archive"))
        );
        assert_eq!(
            preview_import("nope".into(), Vec::new()),
            Err(invalid("import format"))
        );
    }

    #[test]
    fn preview_counts_by_type() {
        let csv = b"name,url,username,password\nA,https://a.example.com,u,p\nB,,v,q\n".to_vec();
        assert_eq!(
            detect_import_format("x.csv".into(), csv.clone()).as_deref(),
            Some("chrome-csv")
        );
        let p = preview_import("chrome-csv".into(), csv).unwrap();
        assert_eq!(p.items, 2);
        assert_eq!(
            p.by_type,
            vec![FfiImportTypeCount {
                item_type: FfiItemType::Login,
                count: 2
            }]
        );
        assert!(p.warnings.is_empty());
    }

    fn imported(title: &str, t: ItemType, created: i64) -> import::ImportedItem {
        let mut item = onepass_core::model::new_item(t, Id::new(), title);
        item.created_at = time::OffsetDateTime::from_unix_timestamp(created).unwrap();
        if let Some(f) = item.field_mut("content") {
            f.value = onepass_core::model::FieldValue::Text("Invented".into());
        }
        import::ImportedItem {
            item,
            folder: Some("Personal".into()),
        }
    }

    #[test]
    fn earlier_fallback_copies_are_replaced_once() {
        let vault = Id::new();
        // What an older importer left: a login it turned into a secure note, and an unrelated
        // note with the same title made at another time.
        let mut old = imported("Notes app", ItemType::SecureNote, 1_700_000_200).item;
        old.tags = vec!["Personal".into(), "mine".into()];
        let mut other = imported("Notes app", ItemType::SecureNote, 1_600_000_000).item;
        other.tags = vec!["Personal".into()];
        let existing = vec![old.clone(), other.clone()];
        let import = Import {
            items: vec![
                imported("Notes app", ItemType::Login, 1_700_000_200),
                imported("Notes app", ItemType::Login, 1_700_000_200),
            ],
            ..Import::default()
        };
        // `prepared` validates: the logins need what makes them valid.
        let import = Import {
            items: import
                .items
                .into_iter()
                .map(|mut it| {
                    it.item.field_mut("username").unwrap().value =
                        onepass_core::model::FieldValue::Text("u".into());
                    it
                })
                .collect(),
            ..Import::default()
        };
        let Prepared {
            items,
            archived,
            counts,
        } = prepared(Format::OnePasswordPux, import, vault, &existing).unwrap();
        assert_eq!(
            (counts.added, counts.converted, counts.unchanged),
            (1, 1, 0),
            "one source item claims one copy"
        );
        // The converted note is kept, archived, under a new id.
        assert_eq!(archived.len(), 1);
        assert!(archived[0].archived);
        assert_ne!(archived[0].id, old.id);
        assert_eq!(items[0].id, old.id);
        assert_eq!(items[0].item_type, ItemType::Login);
        assert_eq!(
            items[0].tags,
            vec!["Personal".to_owned(), "mine".to_owned()]
        );
        assert_ne!(items[1].id, old.id);
        assert_ne!(items[1].id, other.id);
        // Other formats never match: a CSV re-import adds.
        let csv = Import {
            items: vec![imported("Notes app", ItemType::SecureNote, 1_700_000_200)],
            ..Import::default()
        };
        assert_eq!(
            prepared(Format::ChromeCsv, csv, vault, &existing)
                .unwrap()
                .counts
                .added,
            1
        );
    }

    #[test]
    fn pdf_is_detected_and_its_text_previewed() {
        assert_eq!(
            detect_import_format("kit.pdf".into(), b"%PDF-1.7\n".to_vec()).as_deref(),
            Some("pdf-text")
        );
        let text =
            b"Title: Mail\nUsername: u\nPassword: p\nTitle: Shop\nUsername: v\nPassword: q\n";
        assert_eq!(
            preview_import("pdf-text".into(), text.to_vec())
                .unwrap()
                .items,
            2
        );
        assert!(preview_import("pdf-text".into(), b"%PDF-1.7\n".to_vec()).is_err());
    }

    #[test]
    fn encrypted_export_says_why() {
        let b = br#"{"encrypted":true,"passwordProtected":true,"data":"2.x"}"#.to_vec();
        let Err(OnePassError::InvalidInput { what }) = preview_import("bitwarden-json".into(), b)
        else {
            panic!("expected InvalidInput");
        };
        assert!(what.contains("encrypted"));
    }
}
