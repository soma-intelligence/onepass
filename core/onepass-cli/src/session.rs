//! Development session: the data directory, `device.bin` and unlocking.
//!
//! Dev mode keeps the Secret Key in clear in `<data-dir>/device.bin`
//! (mode 0600), next to the `DeviceState`. This is the assumed limit of the
//! milestone 1 CLI: the Mac app with Touch ID replaces it in milestone 2.

use std::fmt;
use std::fs;
use std::io::{IsTerminal, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use onepass_core::Error;
use onepass_core::crypto::{KdfParams, SecretKey};
use onepass_core::repo::{DeviceState, Repository};
use onepass_core::store::SqliteStore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const DEVICE_FILE: &str = "device.bin";
const STORE_FILE: &str = "vault.sqlite";

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

    pub fn banner(&self) {
        eprintln!(
            "DEV MODE: secrets stored unprotected in {}",
            self.data_dir.display()
        );
    }
}

/// A failure with the exit code it maps to: 1 usage, 2 wrong password,
/// 3 integrity, 4 not found. The message never holds a secret.
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
            Error::Validation(_) | Error::InvalidFormat(_) | Error::Crypto | Error::Store(_) => {
                CliError::usage(e)
            }
        }
    }
}

impl From<std::io::Error> for CliError {
    fn from(e: std::io::Error) -> CliError {
        CliError::usage(format!("i/o error: {}", e.kind()))
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

/// Create the data directory (and parents) with mode 0700.
pub fn ensure_dir(dir: &Path) -> Result<(), CliError> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;
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
        if !device_path.is_file() || !ctx.store_path().is_file() {
            return Err(CliError::usage(format!(
                "no account in {}; run `onepass account create` first",
                ctx.data_dir.display()
            )));
        }
        let bytes = Zeroizing::new(fs::read(&device_path)?);
        let file: DeviceFile = postcard::from_bytes(&bytes)
            .map_err(|_| CliError::usage("device.bin is unreadable"))?;
        let key = SecretKey::parse(&file.secret_key)?;
        let password = read_password("Password: ")?;
        let store = SqliteStore::open(&ctx.store_path())?;
        let repo = Repository::unlock(store, &password, &key, file.state)?;
        Ok(Session {
            repo,
            secret_key: file.secret_key,
            device_path,
            on_disk: Some(bytes),
        })
    }

    /// Write `device.bin` (0600, atomically) if the device state changed.
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
        Ok(())
    }
}

/// Unlock, run `f`, then save the device state. The state is saved even
/// when `f` fails, because reading items updates the last manifest seen.
pub fn with_session<T>(
    ctx: &Ctx,
    f: impl FnOnce(&mut Repository<SqliteStore>) -> Result<T, CliError>,
) -> Result<T, CliError> {
    let mut session = Session::open(ctx)?;
    let result = f(&mut session.repo);
    let saved = session.persist();
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
