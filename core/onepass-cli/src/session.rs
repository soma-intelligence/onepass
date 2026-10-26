//! Development session: the data directory, `device.bin` and unlocking.
//!
//! Dev mode keeps the Secret Key in clear in `<data-dir>/device.bin`
//! (mode 0600), next to the `DeviceState`. This is the assumed limit of the
//! milestone 1 CLI: the Mac app with Touch ID replaces it in milestone 2.

use std::fmt;
use std::fs;
use std::io::{IsTerminal, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use onepass_core::Error;
use onepass_core::crypto::{KdfParams, SecretKey};
use onepass_core::repo::{DeviceState, Repository};
use onepass_core::store::SqliteStore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const DEVICE_FILE: &str = "device.bin";
const STORE_FILE: &str = "vault.sqlite";
const LOCK_FILE: &str = "lock";

/// Global options shared by every command.
pub struct Ctx {
    pub data_dir: PathBuf,
    pub json: bool,
}

impl Ctx {
    pub fn device_path(&self) -> PathBuf {
        self.data_dir.join(DEVICE_FILE)
    }

    pub fn store_path(&self) -> PathBuf {
        self.data_dir.join(STORE_FILE)
    }

    pub fn lock_path(&self) -> PathBuf {
        self.data_dir.join(LOCK_FILE)
    }

    /// Whether the data directory holds an account (device file and store).
    pub fn has_account(&self) -> bool {
        self.device_path().is_file() && self.store_path().is_file()
    }

    pub fn banner(&self) {
        eprintln!(
            "DEV MODE: secrets stored unprotected in {}",
            self.data_dir.display()
        );
    }
}

/// A failure with the exit code it maps to: 1 usage, 2 wrong password,
/// 3 integrity, 4 not found, 5 concurrent write (retry). The message never
/// holds a secret.
#[derive(Debug)]
pub struct CliError {
    pub code: i32,
    pub msg: String,
}

impl CliError {
    pub fn usage(msg: impl fmt::Display) -> CliError {
        CliError {
            code: 1,
            msg: msg.to_string(),
        }
    }

    pub fn not_found(msg: impl fmt::Display) -> CliError {
        CliError {
            code: 4,
            msg: msg.to_string(),
        }
    }
}

impl From<Error> for CliError {
    fn from(e: Error) -> CliError {
        match e {
            Error::WrongPassword => CliError {
                code: 2,
                msg: e.to_string(),
            },
            Error::Integrity(_) => CliError {
                code: 3,
                msg: "stored data failed verification, possible tampering".to_owned(),
            },
            Error::NotFound => CliError::not_found("not found"),
            Error::Conflict => CliError {
                code: 5,
                msg: e.to_string(),
            },
            Error::Validation(_) | Error::InvalidFormat(_) | Error::Crypto | Error::Store(_) => {
                CliError::usage(e)
            }
        }
    }
}

impl CliError {
    /// Stdout was closed by its reader (`onepass read ... | head -c1`):
    /// nothing is wrong, the command stops quietly with exit code 0.
    pub fn quiet() -> CliError {
        CliError {
            code: 0,
            msg: String::new(),
        }
    }
}

impl From<std::io::Error> for CliError {
    fn from(e: std::io::Error) -> CliError {
        if e.kind() == std::io::ErrorKind::BrokenPipe {
            return CliError::quiet();
        }
        CliError::usage(format!("i/o error: {}", e.kind()))
    }
}

/// Write one line to stdout. Unlike `println!`, a closed stdout is an
/// error (`CliError::quiet`), not a panic: the release profile aborts on
/// panic.
pub fn emit(line: std::fmt::Arguments<'_>) -> Result<(), CliError> {
    let mut out = std::io::stdout().lock();
    out.write_fmt(format_args!("{line}\n"))?;
    out.flush()?;
    Ok(())
}

/// `println!` through `emit`, returning early on error.
#[macro_export]
macro_rules! out {
    ($($arg:tt)*) => {
        $crate::session::emit(format_args!($($arg)*))?
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conflict_exits_5_and_stays_out_of_the_tampering_path() {
        let e = stored::<()>(Err(Error::Conflict)).unwrap_err();
        assert_eq!(e.code, 5);
        assert_eq!(e.msg, "concurrent write, retry");
        assert_eq!(CliError::from(Error::NotFound).code, 4);
    }
}

/// What `device.bin` holds, encoded with postcard.
#[derive(Serialize, Deserialize)]
struct DeviceFile {
    secret_key: Zeroizing<String>,
    state: DeviceState,
}

fn encode(
    secret_key: &Zeroizing<String>,
    state: &DeviceState,
) -> Result<Zeroizing<Vec<u8>>, CliError> {
    // Borrowed copy of the fields, so the secret is encoded without a clone.
    #[derive(Serialize)]
    struct Ref<'a> {
        secret_key: &'a str,
        state: &'a DeviceState,
    }
    let bytes = postcard::to_allocvec(&Ref { secret_key, state })
        .map_err(|_| CliError::usage("cannot encode device.bin"))?;
    Ok(Zeroizing::new(bytes))
}

/// Errors of a repository call on stored data. A corrupted or tampered
/// store can surface as `InvalidFormat`, `Store` or `Crypto` as well as
/// `Integrity`: all of them exit 3. A wrong password stays 2, not found 4,
/// and a rejected input (`Validation`) stays 1. Calls that only parse user
/// input must not go through here.
pub fn stored<T>(r: onepass_core::Result<T>) -> Result<T, CliError> {
    r.map_err(|e| match e {
        Error::InvalidFormat(_) | Error::Store(_) | Error::Crypto => {
            CliError::from(Error::Integrity(onepass_core::IntegrityError::WrongKind))
        }
        other => CliError::from(other),
    })
}

/// Take the exclusive lock of the data directory (`<data-dir>/lock`, mode
/// 0600), waiting for any other `onepass` process to release it. The lock
/// is held until the returned file is dropped, and released by the system
/// if the process dies. Every command that opens the store holds it for
/// its whole run, readers included, so two commands never interleave.
pub fn lock(ctx: &Ctx) -> Result<fs::File, CliError> {
    let f = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(ctx.lock_path())?;
    f.lock()?;
    Ok(f)
}

/// Create the data directory (and parents) with mode 0700.
pub fn ensure_dir(dir: &Path) -> Result<(), CliError> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;
    set_mode(dir, 0o700)
}

fn set_mode(path: &Path, mode: u32) -> Result<(), CliError> {
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

/// Tighten an existing data directory: 0700 for the directory, 0600 for
/// the store (with its WAL files) and `device.bin`.
pub fn harden(ctx: &Ctx) -> Result<(), CliError> {
    set_mode(&ctx.data_dir, 0o700)?;
    for suffix in ["", "-wal", "-shm"] {
        let mut p = ctx.store_path().into_os_string();
        p.push(suffix);
        let p = PathBuf::from(p);
        if p.exists() {
            set_mode(&p, 0o600)?;
        }
    }
    for p in [ctx.device_path(), ctx.lock_path()] {
        if p.exists() {
            set_mode(&p, 0o600)?;
        }
    }
    Ok(())
}

/// An unlocked repository plus what is needed to save the device state.
pub struct Session {
    pub repo: Repository<SqliteStore>,
    secret_key: Zeroizing<String>,
    device_path: PathBuf,
    /// The bytes on disk, so an unchanged state is not rewritten.
    on_disk: Option<Zeroizing<Vec<u8>>>,
}

impl Session {
    /// Session of a freshly created account: nothing is on disk yet.
    pub fn created(ctx: &Ctx, repo: Repository<SqliteStore>, key: &SecretKey) -> Session {
        Session {
            repo,
            secret_key: Zeroizing::new(key.to_display()),
            device_path: ctx.device_path(),
            on_disk: None,
        }
    }

    /// Unlock the account of the data directory.
    pub fn open(ctx: &Ctx) -> Result<Session, CliError> {
        let device_path = ctx.device_path();
        if !ctx.has_account() {
            return Err(no_account(ctx));
        }
        let bytes = Zeroizing::new(fs::read(&device_path)?);
        let file: DeviceFile = postcard::from_bytes(&bytes)
            .map_err(|_| CliError::usage("device.bin is unreadable"))?;
        let key = SecretKey::parse(&file.secret_key)?;
        let password = read_password("Password: ")?;
        let store = stored(SqliteStore::open(&ctx.store_path()))?;
        harden(ctx)?;
        let repo = stored(Repository::unlock(store, &password, &key, file.state))?;
        Ok(Session {
            repo,
            secret_key: file.secret_key,
            device_path,
            on_disk: Some(bytes),
        })
    }

    /// Write `device.bin` (0600, atomically, file and directory synced) if
    /// the device state changed.
    pub fn persist(&self) -> Result<(), CliError> {
        let bytes = encode(&self.secret_key, self.repo.device_state())?;
        if self.on_disk.as_deref() == Some(&*bytes) {
            return Ok(());
        }
        let tmp = self.device_path.with_extension("bin.tmp");
        let _ = fs::remove_file(&tmp);
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(&bytes)?;
        f.sync_all()?;
        fs::rename(&tmp, &self.device_path)?;
        // The rename lives in the directory: sync it too, or a power loss
        // can bring back the old device.bin (and an older last seen state).
        let dir = match self.device_path.parent() {
            Some(d) if !d.as_os_str().is_empty() => d,
            _ => Path::new("."),
        };
        fs::File::open(dir)?.sync_all()?;
        Ok(())
    }
}

fn no_account(ctx: &Ctx) -> CliError {
    CliError::usage(format!(
        "no account in {}; run `onepass account create` first",
        ctx.data_dir.display()
    ))
}

/// Lock the data directory, unlock, run `f`, then save the device state.
/// The state is saved even when `f` fails, because reading items updates
/// the last manifest seen. The lock is held until the state is saved.
pub fn with_session<T>(
    ctx: &Ctx,
    f: impl FnOnce(&mut Repository<SqliteStore>) -> Result<T, CliError>,
) -> Result<T, CliError> {
    // Checked before taking the lock, so no lock file lands in a directory
    // that holds no account.
    if !ctx.has_account() {
        return Err(no_account(ctx));
    }
    let _lock = lock(ctx)?;
    let mut session = Session::open(ctx)?;
    let result = f(&mut session.repo);
    let saved = harden(ctx).and_then(|()| session.persist());
    match result {
        Ok(v) => saved.map(|()| v),
        Err(e) => Err(e),
    }
}

/// The password: `ONEPASS_PASSWORD` only when `ONEPASS_DEV_ALLOW_ENV_PASSWORD`
/// is `1` (tests), otherwise a masked prompt on the terminal.
pub fn read_password(prompt: &str) -> Result<Zeroizing<String>, CliError> {
    if std::env::var("ONEPASS_DEV_ALLOW_ENV_PASSWORD").as_deref() == Ok("1")
        && let Ok(p) = std::env::var("ONEPASS_PASSWORD")
    {
        return Ok(Zeroizing::new(p));
    }
    if !std::io::stdin().is_terminal() {
        return Err(CliError::usage("no terminal to read the password from"));
    }
    let p = rpassword::prompt_password(prompt)?;
    Ok(Zeroizing::new(p))
}

/// Argon2 parameters of a new account: the floor, or the fast test ones
/// when `ONEPASS_DEV_FAST_KDF=1` (debug builds only).
pub fn kdf_params() -> Result<KdfParams, CliError> {
    let mut kdf = KdfParams::new_default()?;
    if std::env::var("ONEPASS_DEV_FAST_KDF").as_deref() == Ok("1") {
        if !cfg!(debug_assertions) {
            return Err(CliError::usage(
                "ONEPASS_DEV_FAST_KDF is refused in a release build",
            ));
        }
        kdf.m_kib = 8192;
        kdf.t = 1;
        kdf.p = 1;
    }
    Ok(kdf)
}
