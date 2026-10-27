//! Import of other password managers' exports: detection, a preview that
//! only counts, and the import into one vault of the session.
//!
//! Nothing here returns or logs a value of the file: summaries hold counts
//! and static warning codes. The bytes handed over by Swift are wiped when
//! the call returns.

use std::collections::BTreeMap;

use onepass_core::Id;
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

/// The items of an import ready for `vault`: new ids, the vault set, the
/// source folder kept as a tag. Every item is validated before the first
/// write, so an invalid one refuses the whole import.
fn prepared(import: Import, vault: Id) -> Result<Vec<Item>, OnePassError> {
    import
        .items
        .into_iter()
        .map(|it| {
            let mut item = it.item;
            item.id = Id::new();
            item.vault_id = vault;
            if let Some(folder) = it.folder.as_deref().map(str::trim)
                && !folder.is_empty()
                && !item.tags.iter().any(|t| t == folder)
            {
                item.tags.push(folder.to_owned());
            }
            Ok(crate::validate_for_save(item)?)
        })
        .collect()
}

#[uniffi::export]
impl Session {
    /// Imports an export into the vault `vault_id`. Every item gets a new
    /// id, so nothing in the account is overwritten; the source folder
    /// becomes a tag. Nothing is written when one item does not validate.
    /// Returns the counts of what was written.
    pub fn import_items(
        &self,
        format: String,
        bytes: Vec<u8>,
        vault_id: String,
    ) -> Result<FfiImportSummary, OnePassError> {
        let vault_id = parse_id(&vault_id)?;
        let (format, import) = parse(&format, bytes)?;
        let mut done = summary(format, &import);
        let items = prepared(import, vault_id)?;
        // `with` runs the closure again after a conflict: it resumes after
        // the last item written instead of writing the first ones twice.
        let mut next = 0usize;
        let now = time::OffsetDateTime::now_utc();
        self.with(|repo| {
            let vault = find_vault(repo, vault_id)?;
            while let Some(item) = items.get(next) {
                let mut item = item.clone();
                item.record(
                    now,
                    onepass_core::model::EventKind::Imported {
                        format: format.name().to_owned(),
                    },
                );
                repo.save_item(&vault, item)?;
                next += 1;
            }
            Ok(())
        })?;
        done.items = count(next);
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
