//! `onepass backup`: signed account backups (spec 5.5).
//!
//! `create` writes every vault with every item, trashed and archived
//! included, to a new file (mode 0600, never over an existing one).
//! `restore` writes back only the items whose id is absent from the
//! account: nothing is overwritten. It then issues a signed restore epoch
//! (`Restore`), so the other devices accept the restored state. `inspect` reads the clear header and
//! needs neither an account nor a password.

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
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use clap::Subcommand;
use onepass_core::Id;
use onepass_core::archive::{
    self, ArchiveKind, ArchivedVault, HeaderInfo, Unlock, inspect as read_header, restore_plan,
};
use onepass_core::epoch::EpochReason;
use onepass_core::model::validate;
use serde_json::json;
use time::OffsetDateTime;
use zeroize::Zeroizing;

use super::import::{ARCHIVE_PASSPHRASE_ENV, partial};
use super::vault::all;
use crate::session::{
    CliError, Ctx, env_secrets_allowed, exclude_servers, kdf_params, read_secret, stored,
    with_session,
};

/// Largest archive read: the 1 GiB payload cap plus room for the header.
const MAX_ARCHIVE: u64 = (1 << 30) + (1 << 20);

#[derive(Subcommand)]
pub enum BackupCmd {
    /// Back up every vault of the account to a new file.
    Create {
        /// Output file; must not exist.
        #[arg(long)]
        out: PathBuf,
        /// Also let a passphrase (asked twice) open the backup.
        #[arg(long)]
        passphrase: bool,
    },
    /// Restore the items of a backup that the account lacks.
    Restore { file: PathBuf },
    /// Show the clear header of an archive (no password needed).
    Inspect { file: PathBuf },
}

pub fn run(ctx: &Ctx, cmd: BackupCmd) -> Result<(), CliError> {
    match cmd {
        BackupCmd::Create { out, passphrase } => create(ctx, &out, passphrase),
        BackupCmd::Restore { file } => restore(ctx, &file),
        BackupCmd::Inspect { file } => inspect(ctx, &file),
    }
}

fn create(ctx: &Ctx, out: &Path, with_passphrase: bool) -> Result<(), CliError> {
    if fs::symlink_metadata(out).is_ok() {
        return Err(already_exists(out));
    }
    // Settled before unlocking, so a typo costs nothing.
    let passphrase = if with_passphrase {
        Some((passphrase_twice()?, kdf_params()?))
    } else {
        None
    };
    let (bytes, vaults, items) = with_session(ctx, |repo| {
        if ctx.travel_path().exists() {
            eprintln!(
                "warning: Travel Mode is on: the hidden vaults are not included in this backup"
            );
        }
        let mut archived = Vec::new();
        for v in all(repo)? {
            let items = stored(repo.items(&v))?;
            archived.push(ArchivedVault {
                id: v.id,
                meta: v.meta,
                items,
            });
        }
        let vaults = archived.len();
        let items: usize = archived.iter().map(|v| v.items.len()).sum();
        let p = passphrase
            .as_ref()
            .map(|(p, kdf)| (p.as_str(), kdf.clone()));
        let bytes = archive::backup(repo.account(), archived, p)?;
        Ok((Zeroizing::new(bytes), vaults, items))
    })?;
    write_new(out, &bytes)?;
    if ctx.json {
        crate::out!(
            "{}",
            json!({
                "items": items,
                "vaults": vaults,
                "passphrase": with_passphrase,
                "out": out.display().to_string(),
            })
        );
    } else {
        crate::out!(
            "Backed up {items} items from {vaults} vaults to {}",
            out.display()
        );
    }
    Ok(())
}

fn restore(ctx: &Ctx, file: &Path) -> Result<(), CliError> {
    let bytes = read_capped(file)?;
    let info = read_header(&bytes)?;
    let (created, restored, skipped, epoch) = with_session(ctx, |repo| {
        // A running server would write back last seen manifests of what
        // this changes; during Travel Mode, restored vaults would sit beside
        // the hidden ones.
        let _servers = exclude_servers(ctx)?;
        if ctx.travel_path().exists() {
            return Err(CliError::usage(
                "Travel Mode is on: run `onepass travel off --upstream <file>` before restoring a backup",
            ));
        }
        let account_id = repo.account().params.account_id;
        let contents = if info.account == Some(account_id) {
            archive::open(&bytes, Unlock::Account(repo.account()))?
        } else if info.passphrase {
            let p = read_secret("Archive passphrase: ", ARCHIVE_PASSPHRASE_ENV)?;
            archive::open(&bytes, Unlock::Passphrase(&p))?
        } else {
            return Err(CliError {
                code: 2,
                msg: "this backup belongs to another account and has no passphrase".to_owned(),
            });
        };
        let mut vaults = all(repo)?;
        let mut existing = Vec::with_capacity(vaults.len());
        for v in &vaults {
            let ids: Vec<Id> = stored(repo.items(v))?.iter().map(|i| i.id).collect();
            existing.push((v.id, ids));
        }
        let plan = restore_plan(&contents, &existing);
        drop(contents);
        // Every item is checked before the first write (vaults included).
        for (i, (_, item)) in plan.writes.iter().enumerate() {
            if validate(item).is_err() {
                return Err(CliError::usage(format!(
                    "item {} of the backup is invalid: nothing written",
                    i + 1
                )));
            }
        }
        let total = plan.writes.len();
        let mut index: HashMap<Id, usize> =
            vaults.iter().enumerate().map(|(i, v)| (v.id, i)).collect();
        for (archive_id, meta) in plan.new_vaults.iter().cloned() {
            let v = stored(repo.create_vault(meta)).map_err(|e| partial(e, 0, total))?;
            vaults.push(v);
            index.insert(archive_id, vaults.len() - 1);
        }
        let mut restored = 0u64;
        for (archive_id, mut item) in plan.writes {
            let target = index
                .get(&archive_id)
                .and_then(|&i| vaults.get(i))
                .ok_or_else(|| CliError::usage("restore plan names an unknown vault"))?;
            item.vault_id = target.id;
            stored(repo.save_item(target, item))
                .map_err(|e| partial(e, usize::try_from(restored).unwrap_or(usize::MAX), total))?;
            restored += 1;
        }
        // After every write: the epoch's heads are the restored state. A
        // failure here keeps the items written (and the device state saved):
        // it is reported once the counts are out.
        let epoch = stored(repo.issue_restore_epoch(EpochReason::Restore)).map(|e| e.epoch);
        Ok((plan.new_vaults.len(), restored, plan.skipped, epoch))
    })?;
    let issued = epoch.as_ref().ok().copied();
    if ctx.json {
        crate::out!(
            "{}",
            json!({
                "vaults_created": created,
                "restored": restored,
                "skipped": skipped,
                "epoch": issued,
            })
        );
    } else {
        crate::out!("Created {created} vaults");
        crate::out!("Restored {restored} items");
        crate::out!("Skipped {skipped} items (already in the account)");
        if let Some(n) = issued {
            crate::out!("Restore epoch {n}");
        }
    }
    epoch.map(|_| ()).map_err(epoch_not_issued)
}

/// The restore wrote its items but could not issue the epoch: the other
/// devices may refuse the restored state until it is issued.
fn epoch_not_issued(e: CliError) -> CliError {
    CliError {
        code: e.code,
        msg: "items restored, epoch not issued: run sync and retry".to_owned(),
    }
}

/// `backup inspect`: no data directory, no password.
pub fn inspect(ctx: &Ctx, file: &Path) -> Result<(), CliError> {
    let bytes = read_capped(file)?;
    let info: HeaderInfo = read_header(&bytes)?;
    let kind = match info.kind {
        ArchiveKind::Backup => "backup",
        ArchiveKind::Export => "export",
    };
    let account = info.account.map(|a| a.to_string());
    if ctx.json {
        crate::out!(
            "{}",
            json!({
                "archive_id": info.archive_id.to_string(),
                "kind": kind,
                "created_at": info.created_at,
                "payload_schema": info.payload_schema,
                "passphrase": info.passphrase,
                "account": account,
                "signed": info.signed,
            })
        );
        return Ok(());
    }
    let yes_no = |b: bool| if b { "yes" } else { "no" };
    crate::out!("Archive: {}", info.archive_id);
    crate::out!("Kind: {kind}");
    crate::out!("Created: {}", created_text(info.created_at));
    crate::out!("Schema: {}", info.payload_schema);
    crate::out!("Passphrase: {}", yes_no(info.passphrase));
    crate::out!("Account: {}", account.as_deref().unwrap_or("none"));
    crate::out!("Signed: {}", yes_no(info.signed));
    Ok(())
}

/// `YYYY-MM-DD HH:MM:SS UTC`, or the raw seconds when out of range.
fn created_text(unix: i64) -> String {
    match OffsetDateTime::from_unix_timestamp(unix) {
        Ok(t) => format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
            t.year(),
            u8::from(t.month()),
            t.day(),
            t.hour(),
            t.minute(),
            t.second()
        ),
        Err(_) => unix.to_string(),
    }
}

/// The backup passphrase: asked twice on a terminal, once from the
/// environment (tests).
fn passphrase_twice() -> Result<Zeroizing<String>, CliError> {
    let from_env = env_secrets_allowed()? && std::env::var_os(ARCHIVE_PASSPHRASE_ENV).is_some();
    let p = read_secret("Backup passphrase: ", ARCHIVE_PASSPHRASE_ENV)?;
    if !from_env {
        let again = read_secret("Repeat the backup passphrase: ", ARCHIVE_PASSPHRASE_ENV)?;
        if *again != *p {
            return Err(CliError::usage("the two passphrases differ"));
        }
    }
    Ok(p)
}

fn read_capped(path: &Path) -> Result<Vec<u8>, CliError> {
    let unreadable = || CliError::usage(format!("cannot read {}", path.display()));
    let too_large = || CliError::usage("archive too large");
    let meta = fs::metadata(path).map_err(|_| unreadable())?;
    if !meta.is_file() {
        return Err(unreadable());
    }
    if meta.len() > MAX_ARCHIVE {
        return Err(too_large());
    }
    let mut bytes = Vec::new();
    fs::File::open(path)
        .map_err(|_| unreadable())?
        .take(MAX_ARCHIVE + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| unreadable())?;
    if bytes.len() as u64 > MAX_ARCHIVE {
        return Err(too_large());
    }
    Ok(bytes)
}

fn already_exists(path: &Path) -> CliError {
    CliError::usage(format!(
        "{} already exists, choose a new file",
        path.display()
    ))
}

/// Create `path` (mode 0600, never over an existing file), write and sync.
/// A failed write removes the partial file.
fn write_new(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                already_exists(path)
            } else {
                CliError::from(e)
            }
        })?;
    let written = f.write_all(bytes).and_then(|()| f.sync_all());
    if let Err(e) = written {
        drop(f);
        let _ = fs::remove_file(path);
        return Err(CliError::from(e));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn created_text_is_utc() {
        assert_eq!(created_text(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(created_text(i64::MAX), i64::MAX.to_string());
    }
}
