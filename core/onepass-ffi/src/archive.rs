//! OnePass archives over the UniFFI surface (milestone 5, apps side): the
//! clear header, the preview and the restore of an encrypted backup or
//! export, and the plaintext CSV export.
//!
//! An archive whose account recipient is the open account is opened by the
//! account, which verifies its hybrid signature and needs no passphrase.
//! Any other archive needs its passphrase. Restoring never overwrites: an
//! item whose id exists is skipped and counted (core spec 5.5).
//!
//! Summaries hold counts, never a value. The bytes and the passphrase handed
//! over by Swift are wiped when the call returns.

#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

use std::collections::HashMap;

use onepass_core::Id;
use onepass_core::archive::{
    self, ArchiveKind, ArchivedVault, CURRENT_SCHEMA, Contents, HeaderInfo, RestorePlan, Unlock,
    restore_plan,
};
use onepass_core::epoch::EpochReason;
use onepass_core::export::csv_plaintext;
use onepass_core::model::{Item, ItemType};
use onepass_core::vault::Vault;
use zeroize::Zeroizing;

use crate::convert::parse_id;
use crate::error::{OnePassError, invalid};
use crate::import::FfiImportTypeCount;
use crate::session::{Repo, Session};

/// What an archive is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiArchiveKind {
    /// Portable export: passphrase only, unsigned.
    Export,
    /// Account backup: signed by its account, passphrase optional.
    Backup,
}

impl From<ArchiveKind> for FfiArchiveKind {
    fn from(k: ArchiveKind) -> Self {
        match k {
            ArchiveKind::Export => Self::Export,
            ArchiveKind::Backup => Self::Backup,
        }
    }
}

/// The clear header of an archive: no key material, no item.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiArchiveInfo {
    pub kind: FfiArchiveKind,
    /// Unix seconds.
    pub created_at: i64,
    /// Written by a newer OnePass: it will not open here.
    pub newer_version: bool,
    /// A passphrase recipient is present.
    pub has_passphrase: bool,
    /// The header carries an account signature.
    pub signed: bool,
    /// The account recipient is the open account (always false without a
    /// session): it opens without a passphrase and its signature is checked.
    pub for_this_account: bool,
}

/// Counts of a restore (preview or done): never a value.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiRestoreSummary {
    pub kind: FfiArchiveKind,
    pub created_at: i64,
    /// Vaults of the archive absent from the account, created by the restore.
    pub vaults_created: u32,
    /// Items to write (preview) or written (restore).
    pub items: u32,
    /// Most common type first.
    pub by_type: Vec<FfiImportTypeCount>,
    /// Items already in the account, left untouched.
    pub skipped: u32,
    /// Opened by the account: its signature was verified.
    pub signature_verified: bool,
    /// The restore epoch issued after the writes (`None` in a preview, or
    /// when issuing it failed: the items stay written, issue it again).
    pub epoch: Option<u64>,
}

fn count(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

fn info_of(header: &HeaderInfo, account: Option<Id>) -> FfiArchiveInfo {
    FfiArchiveInfo {
        kind: header.kind.into(),
        created_at: header.created_at,
        newer_version: header.payload_schema > CURRENT_SCHEMA,
        has_passphrase: header.passphrase,
        signed: header.signed,
        for_this_account: account.is_some() && header.account == account,
    }
}

/// Reads the clear header of an archive, without a session. Not a
/// OnePass archive: `InvalidInput`.
#[uniffi::export]
pub fn inspect_archive(bytes: Vec<u8>) -> Result<FfiArchiveInfo, OnePassError> {
    let bytes = Zeroizing::new(bytes);
    Ok(info_of(&archive::inspect(&bytes)?, None))
}

/// Items by type, most common first (ties keep the core's order).
pub(crate) fn by_type<'a>(
    items: impl Iterator<Item = &'a Item> + Clone,
) -> Vec<FfiImportTypeCount> {
    let mut counts: Vec<(ItemType, usize)> = ItemType::ALL
        .iter()
        .map(|t| (*t, items.clone().filter(|i| i.item_type == *t).count()))
        .filter(|(_, n)| *n > 0)
        .collect();
    counts.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
    counts
        .into_iter()
        .map(|(t, n)| FfiImportTypeCount {
            item_type: t.into(),
            count: count(n),
        })
        .collect()
}

/// Opens `bytes` for `repo`'s account: by the account when it is the
/// recipient (signature checked), else by `passphrase`.
fn open_for(
    repo: &Repo,
    bytes: &[u8],
    passphrase: Option<&Zeroizing<Vec<u8>>>,
) -> Result<(Contents, bool), OnePassError> {
    let header = archive::inspect(bytes)?;
    if header.payload_schema > CURRENT_SCHEMA {
        return Err(invalid("archive from a newer version"));
    }
    let account = repo.account();
    if header.account == Some(account.params.account_id) {
        return Ok((archive::open(bytes, Unlock::Account(account))?, true));
    }
    if !header.passphrase {
        return Err(invalid("archive of another account"));
    }
    let Some(passphrase) = passphrase else {
        return Err(invalid("archive passphrase"));
    };
    let passphrase = std::str::from_utf8(passphrase).map_err(|_| invalid("passphrase"))?;
    Ok((archive::open(bytes, Unlock::Passphrase(passphrase))?, false))
}

/// The restore plan of `contents` against every vault of the account.
fn plan_for(repo: &mut Repo, contents: &Contents) -> Result<RestorePlan, OnePassError> {
    let mut existing = Vec::new();
    for v in repo.vaults()? {
        let ids = repo.items(&v)?.iter().map(|i| i.id).collect();
        existing.push((v.id, ids));
    }
    Ok(restore_plan(contents, &existing))
}

fn summary(contents: &Contents, plan: &RestorePlan, verified: bool) -> FfiRestoreSummary {
    FfiRestoreSummary {
        kind: contents.kind.into(),
        created_at: contents.created_at,
        vaults_created: count(plan.new_vaults.len()),
        items: count(plan.writes.len()),
        by_type: by_type(plan.writes.iter().map(|(_, i)| i)),
        skipped: plan.skipped,
        signature_verified: verified,
        epoch: None,
    }
}

#[uniffi::export]
impl Session {
    /// `inspect_archive`, plus whether the archive is for the open account.
    pub fn archive_info(&self, bytes: Vec<u8>) -> Result<FfiArchiveInfo, OnePassError> {
        let bytes = Zeroizing::new(bytes);
        let header = archive::inspect(&bytes)?;
        self.with(|repo| Ok(info_of(&header, Some(repo.account().params.account_id))))
    }

    /// Opens the archive and counts what a restore would write, without
    /// writing. Errors: a bad or missing signature is
    /// `Integrity { kind: "signature" }`, a damaged archive another
    /// integrity kind or `InvalidInput`, a wrong passphrase `WrongPassword`,
    /// a missing one `InvalidInput("archive passphrase")`.
    pub fn preview_restore(
        &self,
        bytes: Vec<u8>,
        passphrase: Option<Vec<u8>>,
    ) -> Result<FfiRestoreSummary, OnePassError> {
        let bytes = Zeroizing::new(bytes);
        let passphrase = passphrase.map(Zeroizing::new);
        self.with(|repo| {
            let (contents, verified) = open_for(repo, &bytes, passphrase.as_ref())?;
            let plan = plan_for(repo, &contents)?;
            Ok(summary(&contents, &plan, verified))
        })
    }

    /// Restores the archive: missing vaults are created with the archive's
    /// meta, every item absent from the account is written with its id
    /// (trashed and archived ones as they were), the others are skipped.
    /// Every item is validated before the first write. A restore epoch is
    /// then issued; when that fails the items stay written and `epoch` is
    /// `None`.
    pub fn restore_archive(
        &self,
        bytes: Vec<u8>,
        passphrase: Option<Vec<u8>>,
    ) -> Result<FfiRestoreSummary, OnePassError> {
        let bytes = Zeroizing::new(bytes);
        let passphrase = passphrase.map(Zeroizing::new);
        let (contents, verified) = {
            let guard = self.guard();
            let repo = guard.as_ref().ok_or(OnePassError::Locked)?;
            open_for(repo, &bytes, passphrase.as_ref())?
        };
        // `with` runs the closure again after a conflict: the plan is made
        // again then, so the items written by the first run are skipped and
        // the vaults it created are reused.
        let mut created: HashMap<Id, Id> = HashMap::new();
        let mut vaults_created = 0usize;
        self.with(|repo| {
            let plan = plan_for(repo, &contents)?;
            let mut done = summary(&contents, &plan, verified);
            let mut plan = plan;
            plan.new_vaults.retain(|(id, _)| !created.contains_key(id));
            let writes = plan
                .writes
                .into_iter()
                .map(|(v, item)| Ok((v, crate::validate_for_save(item)?)))
                .collect::<Result<Vec<_>, OnePassError>>()?;
            for (archive_id, meta) in plan.new_vaults {
                let vault = repo.create_vault(meta)?;
                created.insert(archive_id, vault.id);
                vaults_created += 1;
            }
            let mut targets: HashMap<Id, Vault> =
                repo.vaults()?.into_iter().map(|v| (v.id, v)).collect();
            for (archive_id, id) in &created {
                if let Some(vault) = targets.remove(id) {
                    targets.insert(*archive_id, vault);
                }
            }
            let mut written = 0usize;
            for (archive_id, mut item) in writes {
                let vault = targets
                    .get(&archive_id)
                    .ok_or_else(|| invalid("archive vault"))?;
                item.vault_id = vault.id;
                repo.save_item(vault, item)?;
                written += 1;
            }
            done.items = count(written);
            done.vaults_created = count(vaults_created);
            done.epoch = repo
                .issue_restore_epoch(EpochReason::Restore)
                .ok()
                .map(|e| e.epoch);
            Ok(done)
        })
    }

    /// The plaintext CSV export of `vault_ids` (every vault when empty),
    /// trashed items left out. Columns
    /// `title,type,vault,url,username,password,otpauth,notes,tags,extra`.
    ///
    /// WARNING: the result is every secret in clear. Whoever or whatever
    /// reads the file reads the vault; a spreadsheet may run a cell that
    /// starts with `=`. Passkeys and locations are not in it.
    pub fn export_plaintext_csv(&self, vault_ids: Vec<String>) -> Result<Vec<u8>, OnePassError> {
        let wanted = vault_ids
            .iter()
            .map(|id| parse_id(id))
            .collect::<Result<Vec<Id>, _>>()?;
        let vaults = self.with(|repo| {
            let mut out = Vec::new();
            for v in repo.vaults()? {
                if !wanted.is_empty() && !wanted.contains(&v.id) {
                    continue;
                }
                let items = repo
                    .items(&v)?
                    .into_iter()
                    .filter(|i| i.trashed_at.is_none())
                    .collect();
                out.push(ArchivedVault {
                    id: v.id,
                    meta: v.meta.clone(),
                    items,
                });
            }
            Ok(out)
        })?;
        if !wanted.is_empty() && vaults.len() != wanted.len() {
            return Err(OnePassError::NotFound);
        }
        let csv = csv_plaintext(&vaults)?;
        Ok(csv.to_vec())
    }
}
