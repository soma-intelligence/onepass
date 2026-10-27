//! `onepass travel`: Travel Mode over an explicit upstream SQLite file.
//!
//! In production the upstream is the sync (milestone 2); in development it
//! is a file given with `--upstream`. The sealed `TravelState` lives in
//! `<data-dir>/travel.bin` (mode 0600, fixed size, written atomically like
//! `device.bin`).

use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use clap::Subcommand;
use onepass_core::Error;
use onepass_core::repo::Repository;
use onepass_core::repo::travel::{SEALED_TRAVEL_STATE_LEN, TravelState};
use onepass_core::store::{RecordKind, RecordStore, SqliteStore};
use zeroize::Zeroizing;

use crate::session::{CliError, Ctx, exclude_servers, stored, with_session, with_session_then};

#[derive(Subcommand)]
pub enum TravelCmd {
    /// Copy every local record to the upstream file (simulates the sync).
    /// Never deletes anything upstream.
    Push {
        /// Upstream SQLite file (created with mode 0600 if absent).
        #[arg(long)]
        upstream: PathBuf,
    },
    /// Hide the vaults without travel-safe: they must be in the upstream
    /// byte for byte. Refuses if Travel Mode is already on.
    On {
        #[arg(long)]
        upstream: PathBuf,
    },
    /// Bring the hidden vaults back from the upstream, verified.
    Off {
        #[arg(long)]
        upstream: PathBuf,
        /// Without travel.bin, accept the upstream vaults as never seen
        /// (an old authentic manifest would be accepted).
        #[arg(long)]
        accept_unpinned: bool,
    },
    /// Say whether Travel Mode is on and how many vaults are hidden.
    Status,
}

fn travel_path(ctx: &Ctx) -> PathBuf {
    ctx.travel_path()
}

/// What `status` prints when travel.bin and the device disagree.
const INCONSISTENT: &str =
    "travel mode: inconsistent (travel.bin present but hidden vaults are on this device)";

/// Whether travel.bin claims vaults are hidden while the device shows
/// otherwise: a parked vault has its key record here, or a vault without
/// `travel_safe` is listed (a leftover or replayed travel.bin, or a vault
/// created or restored during the trip).
fn inconsistent(repo: &Repository<SqliteStore>, state: &TravelState) -> Result<bool, CliError> {
    for id in state.parked.keys() {
        if stored(repo.store().get(RecordKind::VaultKey, *id))?.is_some() {
            return Ok(true);
        }
    }
    Ok(stored(repo.vaults())?.iter().any(|v| !v.meta.travel_safe))
}

pub fn run(ctx: &Ctx, cmd: TravelCmd) -> Result<(), CliError> {
    match cmd {
        TravelCmd::Push { upstream } => push(ctx, &upstream),
        TravelCmd::On { upstream } => on(ctx, &upstream),
        TravelCmd::Off {
            upstream,
            accept_unpinned,
        } => off(ctx, &upstream, accept_unpinned),
        TravelCmd::Status => status(ctx),
    }
}

/// Set mode 0600 on an upstream file and its WAL siblings.
fn harden_upstream(path: &Path) -> Result<(), CliError> {
    for suffix in ["", "-wal", "-shm"] {
        let mut p = path.as_os_str().to_owned();
        p.push(suffix);
        let p = PathBuf::from(p);
        if p.exists() {
            fs::set_permissions(&p, fs::Permissions::from_mode(0o600))?;
        }
    }
    Ok(())
}

/// Open an upstream that must already exist (`on` and `off` never create
/// one: an empty file would only hide a typo).
fn open_existing(path: &Path) -> Result<SqliteStore, CliError> {
    if !path.is_file() {
        return Err(CliError::usage(format!(
            "upstream file {} does not exist; run `onepass travel push` first",
            path.display()
        )));
    }
    let store = stored(SqliteStore::open(path))?;
    harden_upstream(path)?;
    Ok(store)
}

/// Create the upstream file with mode 0600 if absent, before SQLite
/// creates it with the umask's mode.
fn create_upstream(path: &Path) -> Result<(), CliError> {
    fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path)?;
    Ok(())
}

/// The CLI error of a core error on stored data (integrity maps to 3).
fn store_error(e: Error) -> CliError {
    match stored::<()>(Err(e)) {
        Err(e) => e,
        Ok(()) => unreachable!("an Err stays an Err"),
    }
}

/// Read and open the sealed state of `travel.bin`: wrong length, bad
/// signature or a state that does not open all exit 3.
fn read_state(ctx: &Ctx, repo: &Repository<SqliteStore>) -> Result<TravelState, CliError> {
    let bytes = Zeroizing::new(fs::read(travel_path(ctx))?);
    if bytes.len() != SEALED_TRAVEL_STATE_LEN {
        return Err(store_error(Error::InvalidFormat("travel state")));
    }
    stored(repo.open_travel_state(&bytes))
}

fn push(ctx: &Ctx, upstream: &Path) -> Result<(), CliError> {
    let count = with_session(ctx, |_repo| {
        // The repository keeps its store private: a second connection to
        // the same file reads the records (WAL allows it).
        let local = stored(SqliteStore::open(&ctx.store_path()))?;
        create_upstream(upstream)?;
        let mut up = stored(SqliteStore::open(upstream))?;
        harden_upstream(upstream)?;
        let mut n = 0usize;
        for kind in [
            RecordKind::AccountParams,
            RecordKind::Keyset,
            RecordKind::VaultKey,
            RecordKind::VaultMeta,
            RecordKind::Item,
            RecordKind::Manifest,
            RecordKind::RestoreEpoch,
        ] {
            for r in stored(local.list(kind))? {
                stored(up.put(r))?;
                n += 1;
            }
        }
        harden_upstream(upstream)?;
        Ok(n)
    })?;
    if ctx.json {
        crate::out!("{}", serde_json::json!({ "records": count }));
    } else {
        crate::out!("pushed {count} records");
    }
    Ok(())
}

/// Write `travel.bin` (0600, atomically, file and directory synced).
fn write_state(ctx: &Ctx, bytes: &[u8]) -> Result<(), CliError> {
    let path = travel_path(ctx);
    let tmp = path.with_extension("bin.tmp");
    let _ = fs::remove_file(&tmp);
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    fs::rename(&tmp, &path)?;
    sync_dir(ctx)
}

fn sync_dir(ctx: &Ctx) -> Result<(), CliError> {
    fs::File::open(&ctx.data_dir)?.sync_all()?;
    Ok(())
}

fn on(ctx: &Ctx, upstream: &Path) -> Result<(), CliError> {
    // (vaults hidden, whether Travel Mode was already on)
    let (hidden, was_on) = with_session(ctx, |repo| {
        let _servers = exclude_servers(ctx)?;
        if travel_path(ctx).exists() {
            // Already on: if the state opens and matches the device, only
            // retry the compaction a failed run may have skipped.
            let state = read_state(ctx, repo)?;
            if inconsistent(repo, &state)? {
                return Err(CliError {
                    code: 3,
                    msg: "travel.bin is present but hidden vaults are on this device; run \
                          `onepass travel off --upstream <file>` (it verifies and merges), or \
                          remove travel.bin if it is stale"
                        .to_owned(),
                });
            }
            compact_local(ctx)?;
            return Ok((state.parked.len(), true));
        }
        let up = open_existing(upstream)?;
        let state = match repo.enter_travel(&up) {
            Ok(s) => s,
            // The upstream lacks a vault or holds it differently: a usage
            // problem (push first), not tampering with the local store.
            Err(Error::InvalidFormat(m)) if m.starts_with("upstream") => {
                return Err(CliError::usage(format!(
                    "{m}; run `onepass travel push` first, nothing was hidden"
                )));
            }
            Err(e) => return Err(store_error(e)),
        };
        // The local copies are gone and their pins dropped in memory: the
        // sealed state must reach the disk, or everything is put back.
        let written = stored(repo.seal_travel_state(&state))
            .map(Zeroizing::new)
            .and_then(|sealed| write_state(ctx, &sealed));
        if let Err(e) = written {
            return match repo.exit_travel(&up, &state) {
                Ok(()) => Err(e),
                Err(_) => Err(CliError::usage(
                    "travel.bin could not be written and the hidden vaults could not be \
                     restored; they are recoverable with `onepass travel off --upstream \
                     <file> --accept-unpinned`",
                )),
            };
        }
        // `enter_travel` deleted the rows: compact so they do not linger in
        // free pages or the WAL.
        compact_local(ctx)?;
        Ok((state.parked.len(), false))
    })?;
    if ctx.json {
        crate::out!(
            "{}",
            serde_json::json!({ "hidden": hidden, "already_on": was_on })
        );
    } else if was_on {
        crate::out!("travel mode is already on; local database compacted");
    } else {
        crate::out!("travel mode on: {hidden} vaults hidden");
    }
    Ok(())
}

/// Compact the local store through a second connection. A failure leaves
/// Travel Mode on (travel.bin is written) with rows possibly lingering.
fn compact_local(ctx: &Ctx) -> Result<(), CliError> {
    let store = stored(SqliteStore::open(&ctx.store_path()))?;
    stored(store.compact()).map_err(|e| {
        CliError::usage(format!(
            "travel mode is on, but compacting the local database failed: {}; \
             run `onepass travel on` again to retry compaction",
            e.msg
        ))
    })
}

fn off(ctx: &Ctx, upstream: &Path, accept_unpinned: bool) -> Result<(), CliError> {
    let path = travel_path(ctx);
    let restored = with_session_then(
        ctx,
        |repo| {
            let _servers = exclude_servers(ctx)?;
            let up = open_existing(upstream)?;
            if path.exists() {
                let state = read_state(ctx, repo)?;
                stored(repo.exit_travel(&up, &state))?;
                Ok(state.parked.len())
            } else if accept_unpinned {
                Ok(stored(repo.exit_travel_unpinned(&up))?.len())
            } else {
                Err(CliError::usage(
                    "no travel.bin: the hidden vaults cannot be checked against what this \
                     device last saw; pass --accept-unpinned to restore them anyway",
                ))
            }
        },
        // Only once device.bin holds the restored pins: a crash before
        // this leaves travel.bin and a valid retry, never lost pins.
        || {
            if path.exists() {
                fs::remove_file(&path)?;
                sync_dir(ctx)?;
            }
            Ok(())
        },
    )?;
    if ctx.json {
        crate::out!("{}", serde_json::json!({ "restored": restored }));
    } else {
        crate::out!("travel mode off: {restored} vaults restored");
    }
    Ok(())
}

fn status(ctx: &Ctx) -> Result<(), CliError> {
    if !travel_path(ctx).exists() {
        if ctx.json {
            crate::out!("{}", serde_json::json!({ "travel": false }));
        } else {
            crate::out!("travel mode: off");
        }
        return Ok(());
    }
    let (state, bad) = with_session(ctx, |repo| {
        let state = read_state(ctx, repo)?;
        let bad = inconsistent(repo, &state)?;
        Ok((state, bad))
    })?;
    if bad {
        if ctx.json {
            crate::out!(
                "{}",
                serde_json::json!({ "travel": "inconsistent", "hidden": state.parked.len() })
            );
        } else {
            crate::out!("{INCONSISTENT}");
        }
        return Err(CliError {
            code: 3,
            msg: "travel.bin is present but hidden vaults are on this device; run \
                  `onepass travel off --upstream <file>`, or remove travel.bin if it is stale"
                .to_owned(),
        });
    }
    let since = rfc3339(state.entered_at);
    if ctx.json {
        crate::out!(
            "{}",
            serde_json::json!({
                "travel": true,
                "hidden": state.parked.len(),
                "since": since,
            })
        );
    } else {
        crate::out!(
            "travel mode: on ({} vaults hidden since {since})",
            state.parked.len()
        );
    }
    Ok(())
}

/// UTC date and time of Unix seconds, RFC 3339 (`2026-10-26T09:30:00Z`).
fn rfc3339(secs: i64) -> String {
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

#[cfg(test)]
mod tests {
    use super::rfc3339;

    #[test]
    fn formats_utc_dates() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(1_000_000_000), "2001-09-09T01:46:40Z");
        assert_eq!(rfc3339(1_709_210_096), "2024-02-29T12:34:56Z");
    }
}
