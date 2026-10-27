//! `onepass export`: encrypted OnePass archive, or plaintext CSV behind
//! `--plaintext`. The output file is created (never overwritten) with mode
//! 0600. Trashed items are left out.

#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use clap::{Args, ValueEnum};
use onepass_core::archive::{self, ArchivedVault};
use onepass_core::export::csv_plaintext;
use onepass_core::generator::{PassphraseOptions, Recipe, Wordlist, generate};
use serde_json::json;
use zeroize::Zeroizing;

use super::import::ARCHIVE_PASSPHRASE_ENV;
use super::vault::{all, find_vault};
use crate::session::{
    CliError, Ctx, env_secrets_allowed, kdf_params, read_secret, stored, with_session,
};

/// Printed on stderr before a plaintext export is written.
const PLAINTEXT_WARNING: &str = "WARNING: this file holds every secret in clear text. \
Opening it in a spreadsheet can run formulas stored in it; keep it off shared \
or synced folders and delete it once used. It is not a full backup: passkey \
private keys and location values are left out.";

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ExportFormat {
    /// Encrypted OnePass archive (passphrase).
    Onepass,
    /// Plaintext CSV (needs --plaintext).
    Csv,
}

#[derive(Args)]
pub struct ExportArgs {
    /// Output file; must not exist.
    #[arg(long)]
    out: PathBuf,
    /// Export this vault only (default: every vault).
    #[arg(long)]
    vault: Option<String>,
    #[arg(long, value_enum, default_value_t = ExportFormat::Onepass)]
    format: ExportFormat,
    /// Confirm a plaintext CSV export.
    #[arg(long)]
    plaintext: bool,
    /// Generate the archive passphrase (6 words) and print it once on stderr.
    #[arg(long)]
    generate_passphrase: bool,
}

pub fn run(ctx: &Ctx, a: ExportArgs) -> Result<(), CliError> {
    match a.format {
        ExportFormat::Csv if !a.plaintext => {
            return Err(CliError::usage(
                "a CSV export writes every secret in clear text; pass --plaintext to confirm",
            ));
        }
        ExportFormat::Csv if a.generate_passphrase => {
            return Err(CliError::usage(
                "--generate-passphrase only applies to --format onepass",
            ));
        }
        ExportFormat::Onepass if a.plaintext => {
            return Err(CliError::usage("--plaintext only applies to --format csv"));
        }
        _ => {}
    }
    if fs::symlink_metadata(&a.out).is_ok() {
        return Err(CliError::usage(format!(
            "{} already exists, choose a new file",
            a.out.display()
        )));
    }
    // The passphrase is settled before unlocking, so a typo costs nothing.
    let passphrase = match a.format {
        ExportFormat::Onepass => Some(archive_passphrase(a.generate_passphrase)?),
        ExportFormat::Csv => None,
    };
    let vaults = with_session(ctx, |repo| {
        let vaults = all(repo)?;
        let chosen: Vec<usize> = match a.vault.as_deref() {
            Some(v) => vec![find_vault(&vaults, v)?],
            None => (0..vaults.len()).collect(),
        };
        let mut out = Vec::new();
        for i in chosen {
            let Some(v) = vaults.get(i) else { continue };
            let items = stored(repo.items(v))?
                .into_iter()
                .filter(|item| item.trashed_at.is_none())
                .collect();
            out.push(ArchivedVault {
                id: v.id,
                meta: v.meta.clone(),
                items,
            });
        }
        Ok(out)
    })?;
    let count: usize = vaults.iter().map(|v| v.items.len()).sum();
    let bytes: Zeroizing<Vec<u8>> = match &passphrase {
        Some((p, _)) => Zeroizing::new(archive::export(vaults, p, kdf_params()?)?),
        None => {
            let csv = csv_plaintext(&vaults)?;
            eprintln!("{PLAINTEXT_WARNING}");
            csv
        }
    };
    write_new(&a.out, &bytes)?;
    if let Some((p, true)) = &passphrase {
        eprintln!("Archive passphrase: {}", p.as_str());
    }
    let format = match a.format {
        ExportFormat::Onepass => "onepass",
        ExportFormat::Csv => "csv",
    };
    if ctx.json {
        crate::out!(
            "{}",
            json!({ "exported": count, "format": format, "out": a.out.display().to_string() })
        );
    } else {
        crate::out!("Exported {count} items to {}", a.out.display());
    }
    Ok(())
}

/// The archive passphrase and whether it was generated. Typed: asked twice
/// on a terminal, once from the environment (tests).
fn archive_passphrase(generated: bool) -> Result<(Zeroizing<String>, bool), CliError> {
    if generated {
        let p = generate(&Recipe::Passphrase(PassphraseOptions {
            words: 6,
            separator: "-".into(),
            capitalize: false,
            include_digit: false,
            list: Wordlist::EffEnglish,
        }))?;
        return Ok((p, true));
    }
    let from_env = env_secrets_allowed()? && std::env::var_os(ARCHIVE_PASSPHRASE_ENV).is_some();
    let p = read_secret("Archive passphrase: ", ARCHIVE_PASSPHRASE_ENV)?;
    if !from_env {
        let again = read_secret("Repeat the archive passphrase: ", ARCHIVE_PASSPHRASE_ENV)?;
        if *again != *p {
            return Err(CliError::usage("the two passphrases differ"));
        }
    }
    Ok((p, false))
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
                CliError::usage(format!(
                    "{} already exists, choose a new file",
                    path.display()
                ))
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
