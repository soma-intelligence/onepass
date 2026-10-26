//! `onepass import`: other managers' exports, OnePass archives and, on a
//! Mac, the Wi-Fi networks of the keychain.
//!
//! The report holds counts and warning codes only, never an item value.

#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use clap::Args;
use onepass_core::Id;
use onepass_core::archive::{self, Unlock};
use onepass_core::export::type_name;
use onepass_core::import::text::{
    WifiNetwork, parse_hardware_ports, parse_preferred_networks, router_item,
};
use onepass_core::import::{Format, Import, ImportedItem, Warning, detect, parse};
use onepass_core::model::validate;
use onepass_core::repo::Repository;
use onepass_core::store::SqliteStore;
use onepass_core::vault::{Vault, VaultMeta};
use serde_json::json;
use zeroize::Zeroizing;

use super::display::clean;
use super::exec::{CommandRunner, NETWORKSETUP, SECURITY, runner};
use super::vault::{all, find_vault};
use crate::session::{CliError, Ctx, read_secret, stored, with_session};

/// Largest import file read.
const MAX_INPUT: u64 = 256 * 1024 * 1024;

/// Environment variable of the archive passphrase (tests only).
pub const ARCHIVE_PASSPHRASE_ENV: &str = "ONEPASS_ARCHIVE_PASSPHRASE";

/// Warning code of a keychain network whose password could not be read.
const PASSWORD_UNAVAILABLE: &str = "password_unavailable";

#[derive(Args)]
pub struct ImportArgs {
    /// File to import.
    #[arg(required_unless_present = "wifi_keychain")]
    file: Option<PathBuf>,
    /// Force the source format (default: detected from the content).
    #[arg(long, conflicts_with = "wifi_keychain")]
    format: Option<String>,
    /// Target vault (default: one vault per source folder, else the first).
    #[arg(long)]
    vault: Option<String>,
    /// Report what would be imported, write nothing.
    #[arg(long)]
    dry_run: bool,
    /// Import the Wi-Fi networks of the macOS keychain.
    #[arg(long, conflicts_with = "file")]
    wifi_keychain: bool,
}

pub fn run(ctx: &Ctx, a: ImportArgs) -> Result<(), CliError> {
    let import = match (&a.file, a.wifi_keychain) {
        (Some(file), false) => read_import(file, a.format.as_deref())?,
        (None, true) => {
            if !cfg!(target_os = "macos") {
                return Err(CliError::usage("--wifi-keychain only works on macOS"));
            }
            let mut r = runner()?;
            wifi_keychain(r.as_mut())?
        }
        _ => return Err(CliError::usage("give a file or --wifi-keychain")),
    };
    let summary = Summary::of(&import);
    let created = with_session(ctx, |repo| {
        store_items(repo, import.items, a.vault.as_deref(), a.dry_run)
    })?;
    summary.print(ctx, &created, a.dry_run)
}

/// Read and parse an import file (any format, archives included).
fn read_import(path: &Path, format: Option<&str>) -> Result<Import, CliError> {
    let bytes = read_capped(path)?;
    let format = match format {
        Some(name) => Format::from_name(name).ok_or_else(|| {
            let names: Vec<&str> = Format::ALL.iter().map(|f| f.name()).collect();
            CliError::usage(format!(
                "unknown format '{name}', expected one of: {}",
                names.join(", ")
            ))
        })?,
        None => {
            let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            detect(file_name, &bytes).ok_or_else(|| {
                CliError::usage("cannot detect the format of this file; pass --format")
            })?
        }
    };
    if format == Format::OnePassArchive {
        // An account backup without a passphrase recipient opens only with
        // its account key: that is `backup restore`, not an import.
        if !archive::inspect(&bytes)?.passphrase {
            return Err(CliError::usage(
                "this is an account backup without passphrase: use `onepass backup restore`",
            ));
        }
        let passphrase = read_secret("Archive passphrase: ", ARCHIVE_PASSPHRASE_ENV)?;
        let contents = archive::open(&bytes, Unlock::Passphrase(&passphrase))?;
        // An import copies: every item gets a new id, so nothing in the
        // account is overwritten. Archive vaults become folders.
        let mut out = Import::default();
        for v in contents.vaults {
            for mut item in v.items {
                if item.trashed_at.is_some() {
                    continue;
                }
                item.id = Id::new();
                out.items.push(ImportedItem {
                    item,
                    folder: Some(v.meta.name.clone()),
                });
            }
        }
        return Ok(out);
    }
    Ok(parse(format, &bytes)?)
}

/// The file content, refused over 256 MiB (checked on the metadata, then
/// on the bytes read). A missing or unreadable file is a usage error.
fn read_capped(path: &Path) -> Result<Zeroizing<Vec<u8>>, CliError> {
    let unreadable = || CliError::usage(format!("cannot read {}", path.display()));
    let meta = fs::metadata(path).map_err(|_| unreadable())?;
    if !meta.is_file() {
        return Err(unreadable());
    }
    if meta.len() > MAX_INPUT {
        return Err(CliError::usage("import file too large (over 256 MiB)"));
    }
    let f = fs::File::open(path).map_err(|_| unreadable())?;
    let mut bytes = Zeroizing::new(Vec::new());
    f.take(MAX_INPUT + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| unreadable())?;
    if bytes.len() as u64 > MAX_INPUT {
        return Err(CliError::usage("import file too large (over 256 MiB)"));
    }
    Ok(bytes)
}

/// Router items of the networks known to the keychain. A password that
/// cannot be read (refused, missing) leaves the network without one and
/// adds a `password_unavailable` warning.
fn wifi_keychain(r: &mut dyn CommandRunner) -> Result<Import, CliError> {
    let ports = r.run(NETWORKSETUP, &["-listallhardwareports"])?;
    let device = parse_hardware_ports(&String::from_utf8_lossy(&ports))
        .ok_or_else(|| CliError::usage("no Wi-Fi interface found"))?;
    let listed = r.run(NETWORKSETUP, &["-listpreferredwirelessnetworks", &device])?;
    let mut out = Import::default();
    for (entry, ssid) in parse_preferred_networks(&String::from_utf8_lossy(&listed))
        .into_iter()
        .enumerate()
    {
        let entry = u32::try_from(entry).unwrap_or(u32::MAX);
        let password = r
            .run(
                SECURITY,
                &[
                    "find-generic-password",
                    "-D",
                    "AirPort network password",
                    "-a",
                    &ssid,
                    "-w",
                ],
            )
            .ok()
            .map(|raw| {
                let raw = Zeroizing::new(raw);
                let text = Zeroizing::new(String::from_utf8_lossy(&raw).into_owned());
                Zeroizing::new(text.trim_end_matches(['\n', '\r']).to_owned())
            })
            .filter(|p| !p.is_empty());
        if password.is_none() {
            out.warnings.push(Warning {
                entry,
                code: PASSWORD_UNAVAILABLE,
            });
        }
        // The keychain does not tell the security type: left empty.
        let item = router_item(&WifiNetwork {
            ssid,
            password,
            security: String::new(),
            hidden: false,
        });
        out.items.push(ImportedItem { item, folder: None });
    }
    Ok(out)
}

/// Refuses the whole import when one item does not validate, before
/// anything is written. Parser output always validates; an archive is
/// opaque data and may not.
fn validate_all(items: &[ImportedItem]) -> Result<(), CliError> {
    for (i, it) in items.iter().enumerate() {
        if validate(&it.item).is_err() {
            return Err(CliError::usage(format!(
                "item {} of the import is invalid: nothing written",
                i + 1
            )));
        }
    }
    Ok(())
}

/// A write error after `written` of `total` items: the message says how
/// far the import went, the exit code stays the one of `e`.
pub(crate) fn partial(e: CliError, written: usize, total: usize) -> CliError {
    CliError {
        code: e.code,
        msg: format!("{} ({written} of {total} items written)", e.msg),
    }
}

/// Put each item in its vault: `--vault`, else the vault named like its
/// folder (ignoring case, created when absent), else the first vault.
/// Returns the names of the vaults created (or that a dry run would
/// create). A dry run writes nothing. Every item is validated before the
/// first write; a write error reports how many items were written.
fn store_items(
    repo: &mut Repository<SqliteStore>,
    items: Vec<ImportedItem>,
    vault: Option<&str>,
    dry_run: bool,
) -> Result<Vec<String>, CliError> {
    validate_all(&items)?;
    let total = items.len();
    let mut written = 0usize;
    let mut vaults = all(repo)?;
    let forced = match vault {
        Some(v) => Some(find_vault(&vaults, v)?),
        None => None,
    };
    let mut created: Vec<String> = Vec::new();
    for ImportedItem { mut item, folder } in items {
        let index = match (forced, folder) {
            (Some(i), _) => i,
            (None, Some(folder)) if !folder.trim().is_empty() => {
                let wanted = folder.to_lowercase();
                match vaults
                    .iter()
                    .position(|v| v.meta.name.to_lowercase() == wanted)
                {
                    Some(i) => i,
                    None if dry_run => {
                        if !created.iter().any(|c| c.to_lowercase() == wanted) {
                            created.push(folder);
                        }
                        continue;
                    }
                    None => {
                        let v = stored(repo.create_vault(VaultMeta {
                            name: folder.clone(),
                            icon: "folder".into(),
                            color: "gray".into(),
                            travel_safe: false,
                            mcp_access: false,
                        }))
                        .map_err(|e| partial(e, written, total))?;
                        created.push(folder);
                        vaults.push(v);
                        vaults.len() - 1
                    }
                }
            }
            (None, _) => {
                if vaults.is_empty() {
                    return Err(CliError::usage("the account has no vault"));
                }
                0
            }
        };
        if dry_run {
            continue;
        }
        let target: &Vault = vaults
            .get(index)
            .ok_or_else(|| CliError::usage("the account has no vault"))?;
        item.vault_id = target.id;
        stored(repo.save_item(target, item)).map_err(|e| partial(e, written, total))?;
        written += 1;
    }
    Ok(created)
}

/// Counts of an import: never a value.
struct Summary {
    imported: usize,
    by_type: BTreeMap<&'static str, u64>,
    warnings: BTreeMap<&'static str, u64>,
    skipped: u32,
}

impl Summary {
    fn of(import: &Import) -> Summary {
        let mut by_type: BTreeMap<&'static str, u64> = BTreeMap::new();
        for i in &import.items {
            *by_type.entry(type_name(i.item.item_type)).or_default() += 1;
        }
        let mut warnings: BTreeMap<&'static str, u64> = BTreeMap::new();
        for w in &import.warnings {
            *warnings.entry(w.code).or_default() += 1;
        }
        Summary {
            imported: import.items.len(),
            by_type,
            warnings,
            skipped: import.skipped,
        }
    }

    fn print(&self, ctx: &Ctx, created: &[String], dry_run: bool) -> Result<(), CliError> {
        if ctx.json {
            crate::out!(
                "{}",
                json!({
                    "imported": self.imported,
                    "by_type": self.by_type,
                    "warnings": self.warnings,
                    "skipped": self.skipped,
                    "dry_run": dry_run,
                })
            );
            return Ok(());
        }
        let suffix = if dry_run { " (dry run)" } else { "" };
        crate::out!("Imported {} items{suffix}", self.imported);
        for (t, count) in &self.by_type {
            crate::out!("  {t}: {count}");
        }
        for name in created {
            crate::out!("Created vault: {}{suffix}", clean(name));
        }
        for (code, count) in &self.warnings {
            crate::out!("Warnings: {code} x {count}");
        }
        crate::out!("Skipped: {}", self.skipped);
        Ok(())
    }
}
