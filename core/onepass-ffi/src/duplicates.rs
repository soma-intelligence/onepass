//! Possible duplicates over the UniFFI surface (spec 2026-11-03-duplicates).
//!
//! A group lists its copies, the suggested primary first, with what differs
//! in each (never a value). Merge, archive, trash and "not duplicates" go
//! through the core, which refuses any write to a read-only shared copy.

#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

use onepass_core::duplicates::{
    Aspect, Choice, Confidence, Row, RowKind, Signal, differences, review,
};
use onepass_core::model::FieldValue;
use onepass_core::repo::duplicates::ItemKey;

use crate::convert::{item_to_ffi, parse_id, summary, value_to_ffi};
use crate::error::OnePassError;
use crate::session::Session;
use crate::types::{FfiFieldValue, FfiItem, FfiItemSummary};
// The vault and id of an item, shared with the crypto watch list.
use crate::wallet_watch::FfiItemKey;

/// Why the copies were grouped, from the strongest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiDuplicateSignal {
    SameTotp,
    SameCardNumber,
    SameDocumentNumber,
    SameLogin,
    SameTitleAndUsername,
}

/// What differs in a copy from the suggested primary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiDuplicateAspect {
    Title,
    Username,
    Password,
    Websites,
    Totp,
    Passkeys,
    Notes,
    Fields,
    Attachments,
    Tags,
}

/// One copy of a group.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiDuplicateCopy {
    pub summary: FfiItemSummary,
    pub vault_name: String,
    /// False in a shared vault where this account is Read only: it can be
    /// neither the primary nor archived, trashed or merged away.
    pub writable: bool,
    /// Empty for the suggested primary.
    pub differences: Vec<FfiDuplicateAspect>,
    pub has_totp: bool,
    pub attachment_count: u32,
    pub field_count: u32,
    /// The item asks for biometrics or the master password before anything
    /// about it shows: the review never reveals its secrets.
    pub reprompt: bool,
}

/// How sure the merge of a group can be (spec 2026-11-08-duplicates-review).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiDuplicateConfidence {
    /// The copies only add to one another: merge in a batch.
    Sure,
    /// At least one conflict to answer.
    Review,
}

/// What a line of the review is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiDuplicateRowKind {
    /// One copy brings something: kept by the merge.
    Added,
    /// The copies differ, one wins without a question.
    Kept,
    /// The user picks.
    Conflict,
}

/// One line where the copies differ.
#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct FfiDuplicateRow {
    pub aspect: FfiDuplicateAspect,
    /// What a choice names (`title`, `notes`, `password` or a field id);
    /// empty for a list, which is always the union.
    pub subject: String,
    /// The field's label, empty for the title, password, notes and lists.
    pub label: String,
    pub kind: FfiDuplicateRowKind,
    /// One per copy, in the order of `copies`; `None` when that copy has
    /// nothing here. A list is one text, one entry per line.
    pub values: Vec<Option<FfiFieldValue>>,
    /// A secret: shown masked.
    pub concealed: bool,
    /// Index into `copies` of the value kept by default; `None` for a list
    /// and for two different notes (both kept by default).
    pub winner: Option<u32>,
}

/// One answer: the value of `subject` comes from the copy `from_item_id`
/// (hex). `None` on `notes` keeps every note.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiDuplicateChoice {
    pub subject: String,
    pub from_item_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct FfiDuplicateGroup {
    /// Stable for the same set of items.
    pub id: String,
    pub signals: Vec<FfiDuplicateSignal>,
    /// The registrable domain shared (a `SameLogin` group).
    pub domain: Option<String>,
    /// The suggested primary first.
    pub copies: Vec<FfiDuplicateCopy>,
    pub confidence: FfiDuplicateConfidence,
    /// Only the lines where the copies differ.
    pub rows: Vec<FfiDuplicateRow>,
}

/// What a merge would save, nothing written.
#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct FfiMergePreview {
    /// The primary as it would be saved (files of the others not counted in
    /// `merged.attachment_count`: see `copied_attachments`).
    pub merged: FfiItem,
    /// Copies that would be archived.
    pub archived_count: u32,
    /// Files that would be copied into the primary.
    pub copied_attachments: u32,
    /// Passwords of the others added to the primary's history.
    pub history_added: u32,
    /// Websites the primary gains.
    pub websites_added: u32,
    /// Conflicting values kept as extra fields.
    pub extra_fields: u32,
    /// Read-only copies left as they are.
    pub read_only_left: u32,
}

pub(crate) fn signal(s: Signal) -> FfiDuplicateSignal {
    match s {
        Signal::SameTotp => FfiDuplicateSignal::SameTotp,
        Signal::SameCardNumber => FfiDuplicateSignal::SameCardNumber,
        Signal::SameDocumentNumber => FfiDuplicateSignal::SameDocumentNumber,
        Signal::SameLogin => FfiDuplicateSignal::SameLogin,
        Signal::SameTitleAndUsername => FfiDuplicateSignal::SameTitleAndUsername,
    }
}

pub(crate) fn aspect(a: Aspect) -> FfiDuplicateAspect {
    match a {
        Aspect::Title => FfiDuplicateAspect::Title,
        Aspect::Username => FfiDuplicateAspect::Username,
        Aspect::Password => FfiDuplicateAspect::Password,
        Aspect::Websites => FfiDuplicateAspect::Websites,
        Aspect::Totp => FfiDuplicateAspect::Totp,
        Aspect::Passkeys => FfiDuplicateAspect::Passkeys,
        Aspect::Notes => FfiDuplicateAspect::Notes,
        Aspect::Fields => FfiDuplicateAspect::Fields,
        Aspect::Attachments => FfiDuplicateAspect::Attachments,
        Aspect::Tags => FfiDuplicateAspect::Tags,
    }
}

fn row_to_ffi(r: &Row) -> FfiDuplicateRow {
    FfiDuplicateRow {
        aspect: aspect(r.aspect),
        subject: r.subject.clone(),
        label: r.label.clone(),
        kind: match r.kind {
            RowKind::Added => FfiDuplicateRowKind::Added,
            RowKind::Kept => FfiDuplicateRowKind::Kept,
            RowKind::Conflict => FfiDuplicateRowKind::Conflict,
        },
        values: r
            .values
            .iter()
            .map(|v| v.as_ref().map(value_to_ffi))
            .collect(),
        concealed: r.concealed,
        winner: r.winner.map(count),
    }
}

fn choices(list: &[FfiDuplicateChoice]) -> Result<Vec<Choice>, OnePassError> {
    list.iter()
        .map(|c| {
            Ok(Choice {
                subject: c.subject.clone(),
                from: c.from_item_id.as_deref().map(parse_id).transpose()?,
            })
        })
        .collect()
}

fn count(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

fn key(k: &FfiItemKey) -> Result<ItemKey, OnePassError> {
    Ok(ItemKey {
        vault_id: parse_id(&k.vault_id)?,
        item_id: parse_id(&k.item_id)?,
    })
}

fn keys(list: &[FfiItemKey]) -> Result<Vec<ItemKey>, OnePassError> {
    list.iter().map(key).collect()
}

#[uniffi::export]
impl Session {
    /// The groups of possible duplicates of this account, the vaults
    /// `excluded_vault_ids` (hidden ones) left out.
    pub fn duplicate_groups(
        &self,
        excluded_vault_ids: Vec<String>,
    ) -> Result<Vec<FfiDuplicateGroup>, OnePassError> {
        let excluded = excluded_vault_ids
            .iter()
            .map(|s| parse_id(s))
            .collect::<Result<Vec<_>, _>>()?;
        let scan = self.with(|repo| Ok(repo.duplicate_scan(&excluded)?))?;
        let mut out = Vec::with_capacity(scan.groups.len());
        for g in &scan.groups {
            let members: Vec<_> = g
                .members
                .iter()
                .filter_map(|&i| scan.items.get(i))
                .collect();
            let Some(primary) = members.first() else {
                continue;
            };
            let copies = members
                .iter()
                .map(|m| {
                    let fields: Vec<_> = m
                        .item
                        .sections
                        .iter()
                        .flat_map(|s| s.fields.iter())
                        .filter(|f| !matches!(f.value, FieldValue::Empty))
                        .collect();
                    FfiDuplicateCopy {
                        summary: summary(&m.item),
                        vault_name: m.vault_name.clone(),
                        writable: m.writable,
                        differences: differences(&primary.item, &m.item)
                            .into_iter()
                            .map(aspect)
                            .collect(),
                        has_totp: fields.iter().any(|f| matches!(f.value, FieldValue::Otp(_))),
                        attachment_count: count(m.item.attachments.len()),
                        field_count: count(fields.len()),
                        reprompt: m.item.reprompt,
                    }
                })
                .collect();
            let items: Vec<_> = members.iter().map(|m| &m.item).collect();
            let r = review(&items);
            out.push(FfiDuplicateGroup {
                id: g.id.clone(),
                signals: g.signals.iter().copied().map(signal).collect(),
                domain: g.domain.clone(),
                copies,
                confidence: match r.confidence {
                    Confidence::Sure => FfiDuplicateConfidence::Sure,
                    Confidence::Review => FfiDuplicateConfidence::Review,
                },
                rows: r.rows.iter().map(row_to_ffi).collect(),
            });
        }
        Ok(out)
    }

    /// What merging `others` into `primary` would save. Writes nothing.
    pub fn merge_duplicates_preview(
        &self,
        primary: FfiItemKey,
        others: Vec<FfiItemKey>,
    ) -> Result<FfiMergePreview, OnePassError> {
        self.merge_duplicates_preview_with(primary, others, Vec::new())
    }

    /// `merge_duplicates_preview` with the answers of the review.
    pub fn merge_duplicates_preview_with(
        &self,
        primary: FfiItemKey,
        others: Vec<FfiItemKey>,
        answers: Vec<FfiDuplicateChoice>,
    ) -> Result<FfiMergePreview, OnePassError> {
        let (p, o, c) = (key(&primary)?, keys(&others)?, choices(&answers)?);
        self.with(|repo| {
            let before = repo
                .vaults()?
                .into_iter()
                .find(|v| v.id == p.vault_id)
                .ok_or(OnePassError::NotFound)
                .and_then(|v| crate::session::find_item(repo, &v, p.item_id))?;
            let plan = repo.merge_preview(p, &o, &c, "")?;
            let m = &plan.merge;
            Ok(FfiMergePreview {
                merged: item_to_ffi(&m.merged),
                archived_count: count(m.archived.len()),
                copied_attachments: count(m.attachments.len()),
                history_added: count(
                    m.merged
                        .password_history
                        .len()
                        .saturating_sub(before.password_history.len()),
                ),
                websites_added: count(m.merged.urls.len().saturating_sub(before.urls.len())),
                extra_fields: count(
                    m.merged
                        .sections
                        .iter()
                        .filter(|s| s.id == onepass_core::duplicates::MERGED_SECTION_ID)
                        .map(|s| s.fields.len())
                        .sum(),
                ),
                read_only_left: count(plan.read_only_left),
            })
        })
    }

    /// Merge `others` into `primary` (core `merge_duplicates`): the others
    /// are archived with `note` ("Merged into <title>" in the app's
    /// language). Returns the primary as saved.
    pub fn merge_duplicates(
        &self,
        primary: FfiItemKey,
        others: Vec<FfiItemKey>,
        note: String,
    ) -> Result<FfiItem, OnePassError> {
        let (p, o) = (key(&primary)?, keys(&others)?);
        self.with(|repo| Ok(item_to_ffi(&repo.merge_duplicates(p, &o, &note)?)))
    }

    /// `merge_duplicates` with the answers of the review: each names the
    /// copy whose value wins for its subject.
    pub fn merge_duplicates_with(
        &self,
        primary: FfiItemKey,
        others: Vec<FfiItemKey>,
        answers: Vec<FfiDuplicateChoice>,
        note: String,
    ) -> Result<FfiItem, OnePassError> {
        let (p, o, c) = (key(&primary)?, keys(&others)?, choices(&answers)?);
        self.with(|repo| Ok(item_to_ffi(&repo.merge_duplicates_with(p, &o, &c, &note)?)))
    }

    /// Merge every group of `group_ids` that a fresh scan still finds sure,
    /// with the default answers. `note_template` is the note of the
    /// archived copies, `{title}` replaced by the kept copy's title.
    /// Returns the ids of the groups merged.
    pub fn merge_sure_duplicates(
        &self,
        group_ids: Vec<String>,
        excluded_vault_ids: Vec<String>,
        note_template: String,
    ) -> Result<Vec<String>, OnePassError> {
        let excluded = excluded_vault_ids
            .iter()
            .map(|s| parse_id(s))
            .collect::<Result<Vec<_>, _>>()?;
        self.with(|repo| {
            Ok(repo.merge_sure_duplicates(&group_ids, &excluded, |t| {
                note_template.replace("{title}", t.trim())
            })?)
        })
    }

    /// Archive the extra copies.
    pub fn archive_duplicates(&self, items: Vec<FfiItemKey>) -> Result<(), OnePassError> {
        let k = keys(&items)?;
        self.with(|repo| Ok(repo.archive_duplicates(&k)?))
    }

    /// Put the extra copies in the trash (restorable).
    pub fn trash_duplicates(&self, items: Vec<FfiItemKey>) -> Result<(), OnePassError> {
        let k = keys(&items)?;
        self.with(|repo| Ok(repo.trash_duplicates(&k)?))
    }

    /// "Not duplicates": remembered on the items, synced.
    pub fn dismiss_duplicates(&self, members: Vec<FfiItemKey>) -> Result<(), OnePassError> {
        let k = keys(&members)?;
        self.with(|repo| Ok(repo.dismiss_duplicates(&k)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_signal_and_aspect_maps() {
        for s in [
            Signal::SameTotp,
            Signal::SameCardNumber,
            Signal::SameDocumentNumber,
            Signal::SameLogin,
            Signal::SameTitleAndUsername,
        ] {
            assert_eq!(format!("{s:?}"), format!("{:?}", signal(s)));
        }
        for a in [
            Aspect::Title,
            Aspect::Username,
            Aspect::Password,
            Aspect::Websites,
            Aspect::Totp,
            Aspect::Passkeys,
            Aspect::Notes,
            Aspect::Fields,
            Aspect::Attachments,
            Aspect::Tags,
        ] {
            assert_eq!(format!("{a:?}"), format!("{:?}", aspect(a)));
        }
    }

    #[test]
    fn bad_keys_are_refused() {
        let k = FfiItemKey {
            vault_id: "zz".into(),
            item_id: crate::convert::id_hex(onepass_core::Id::new()),
        };
        assert!(key(&k).is_err());
    }
}
