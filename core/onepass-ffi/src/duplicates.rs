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

use onepass_core::duplicates::{Aspect, Signal, differences};
use onepass_core::model::FieldValue;
use onepass_core::repo::duplicates::ItemKey;

use crate::convert::{item_to_ffi, parse_id, summary};
use crate::error::OnePassError;
use crate::session::Session;
use crate::types::{FfiItem, FfiItemSummary};
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
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiDuplicateGroup {
    /// Stable for the same set of items.
    pub id: String,
    pub signals: Vec<FfiDuplicateSignal>,
    /// The registrable domain shared (a `SameLogin` group).
    pub domain: Option<String>,
    /// The suggested primary first.
    pub copies: Vec<FfiDuplicateCopy>,
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

fn signal(s: Signal) -> FfiDuplicateSignal {
    match s {
        Signal::SameTotp => FfiDuplicateSignal::SameTotp,
        Signal::SameCardNumber => FfiDuplicateSignal::SameCardNumber,
        Signal::SameDocumentNumber => FfiDuplicateSignal::SameDocumentNumber,
        Signal::SameLogin => FfiDuplicateSignal::SameLogin,
        Signal::SameTitleAndUsername => FfiDuplicateSignal::SameTitleAndUsername,
    }
}

fn aspect(a: Aspect) -> FfiDuplicateAspect {
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
                    }
                })
                .collect();
            out.push(FfiDuplicateGroup {
                id: g.id.clone(),
                signals: g.signals.iter().copied().map(signal).collect(),
                domain: g.domain.clone(),
                copies,
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
        let (p, o) = (key(&primary)?, keys(&others)?);
        self.with(|repo| {
            let before = repo
                .vaults()?
                .into_iter()
                .find(|v| v.id == p.vault_id)
                .ok_or(OnePassError::NotFound)
                .and_then(|v| crate::session::find_item(repo, &v, p.item_id))?;
            let plan = repo.merge_preview(p, &o, "")?;
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
