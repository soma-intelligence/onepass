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
use onepass_core::repo::travel::SEALED_TRAVEL_STATE_LEN;
use onepass_core::repo::{DeviceState, Repository};
use onepass_core::store::SqliteStore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const DEVICE_FILE: &str = "device.bin";
const STORE_FILE: &str = "vault.sqlite";
const LOCK_FILE: &str = "lock";
const SERVERS_LOCK_FILE: &str = "servers.lock";
const TRAVEL_FILE: &str = "travel.bin";

/// Refusal of a command that must not run under a long-running server.
pub const SERVER_RUNNING: &str =
    "a long-running onepass server (mcp or ssh-agent) is running; stop it first";
/// Refusal of a server request once `travel.bin` appeared or vanished.
pub const TRAVEL_CHANGED: &str = "Travel Mode changed while this server was running; restart it";

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

    /// `<data-dir>/servers.lock`: shared by every running server, taken
    /// exclusively by the commands a server must not see happen.
    pub fn servers_lock_path(&self) -> PathBuf {
        self.data_dir.join(SERVERS_LOCK_FILE)
    }

    /// `<data-dir>/travel.bin`, present while Travel Mode is on.
    pub fn travel_path(&self) -> PathBuf {
        self.data_dir.join(TRAVEL_FILE)
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
        CliError::usage(format!("i/o error: {}", e.kind()))
    }
}

/// The error of a write to stdout: a broken pipe there means the reader
/// went away (`CliError::quiet`); anything else, and any broken pipe
/// elsewhere, stays an error.
pub fn stdout_error(e: std::io::Error) -> CliError {
    if e.kind() == std::io::ErrorKind::BrokenPipe {
        CliError::quiet()
    } else {
        CliError::from(e)
    }
}

/// Write one line to stdout and flush it, raw I/O result.
pub fn write_line(line: std::fmt::Arguments<'_>) -> std::io::Result<()> {
    let mut out = std::io::stdout().lock();
    out.write_fmt(format_args!("{line}\n"))?;
    out.flush()
}

/// Write one line to stdout. Unlike `println!`, a closed stdout is an
/// error (`CliError::quiet`), not a panic: the release profile aborts on
/// panic.
pub fn emit(line: std::fmt::Arguments<'_>) -> Result<(), CliError> {
    write_line(line).map_err(stdout_error)
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
    fn env_password_switch_is_debug_only() {
        assert!(env_secrets_allowed_with(true, Some("1")).unwrap());
        assert!(!env_secrets_allowed_with(true, None).unwrap());
        assert!(!env_secrets_allowed_with(true, Some("0")).unwrap());
        assert!(!env_secrets_allowed_with(false, None).unwrap());
        assert!(!env_secrets_allowed_with(false, Some("yes")).unwrap());
        let e = env_secrets_allowed_with(false, Some("1")).unwrap_err();
        assert_eq!(e.code, 1);
        assert_eq!(
            e.msg,
            "ONEPASS_DEV_ALLOW_ENV_PASSWORD is refused in a release build"
        );
    }

    /// A `device.bin` written before the versioned state: Secret Key "sk",
    /// then the version 1 state inline,
    /// `{ pinned: None, last_seen: { [1; 16]: (7, [0xab; 32]) } }`.
    const LEGACY_DEVICE_BIN_HEX: &str = concat!(
        "02736b",
        "00",
        "01",
        "01010101010101010101010101010101",
        "07",
        "abababababababababababababababababababababababababababababababab",
    );

    fn from_hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn fixed_state() -> DeviceState {
        let mut state = DeviceState::default();
        state.last_seen.insert(
            onepass_core::Id([1; 16]),
            onepass_core::manifest::SeenManifest {
                seq: 7,
                hash: [0xab; 32],
            },
        );
        state
    }

    #[test]
    fn legacy_device_bin_reads() {
        let mut bytes = from_hex(LEGACY_DEVICE_BIN_HEX);
        let file = decode(&bytes).unwrap();
        assert_eq!(file.secret_key.as_str(), "sk");
        assert_eq!(file.state, fixed_state());
        assert_eq!(file.state.epoch, 0);
        // Rewritten in the current layout, which reads back the same.
        let new = encode(&file.secret_key, &file.state).unwrap();
        assert_eq!(&new[..3], b"\x02sk");
        assert_eq!(&new[4..8], b"ODS\x02");
        let again = decode(&new).unwrap();
        assert_eq!(again.state, file.state);
        bytes.push(0);
        assert!(decode(&bytes).is_err());
    }

    #[test]
    fn device_bin_roundtrips() {
        let mut state = fixed_state();
        state.epoch = 9;
        let key = Zeroizing::new("sk".to_string());
        let mut bytes = encode(&key, &state).unwrap();
        let file = decode(&bytes).unwrap();
        assert_eq!(file.secret_key.as_str(), "sk");
        assert_eq!(file.state, state);
        bytes.push(0);
        assert!(decode(&bytes).is_err());
    }

    #[test]
    fn only_a_broken_stdout_is_quiet() {
        use std::io::{Error as IoError, ErrorKind};
        assert_eq!(stdout_error(IoError::from(ErrorKind::BrokenPipe)).code, 0);
        assert_eq!(stdout_error(IoError::from(ErrorKind::Other)).code, 1);
        // A broken pipe anywhere else is an error.
        let e = CliError::from(IoError::from(ErrorKind::BrokenPipe));
        assert_eq!(e.code, 1);
        assert!(e.msg.contains("broken pipe"));
    }

    #[test]
    fn conflict_exits_5_and_stays_out_of_the_tampering_path() {
        let e = stored::<()>(Err(Error::Conflict)).unwrap_err();
        assert_eq!(e.code, 5);
        assert_eq!(e.msg, "concurrent write, retry");
        assert_eq!(CliError::from(Error::NotFound).code, 4);
    }
}

/// What `device.bin` holds, encoded with postcard: the Secret Key, then the
/// device state as the byte string of `DeviceState::encode` (versioned).
#[derive(Serialize, Deserialize)]
struct DeviceFile {
    secret_key: Zeroizing<String>,
    #[serde(with = "onepass_core::format::device_state_bytes")]
    state: DeviceState,
}

/// `device.bin` before the versioned state: the version 1 state inline.
/// Read only, migrated with `epoch = 0`; the next write uses `DeviceFile`.
#[derive(Deserialize)]
struct LegacyDeviceFile {
    secret_key: Zeroizing<String>,
    #[serde(deserialize_with = "onepass_core::format::device_state_v1_inline::deserialize")]
    state: DeviceState,
}

/// Decode `device.bin`: the current layout (whole buffer), else the legacy
/// one.
fn decode(bytes: &[u8]) -> Result<DeviceFile, CliError> {
    if let Ok((file, [])) = postcard::take_from_bytes::<DeviceFile>(bytes) {
        return Ok(file);
    }
    match postcard::take_from_bytes::<LegacyDeviceFile>(bytes) {
        Ok((old, [])) => Ok(DeviceFile {
            secret_key: old.secret_key,
            state: old.state,
        }),
        _ => Err(CliError::usage("device.bin is unreadable")),
    }
}

fn encode(
    secret_key: &Zeroizing<String>,
    state: &DeviceState,
) -> Result<Zeroizing<Vec<u8>>, CliError> {
    // Borrowed copy of the fields, so the secret is encoded without a clone.
    #[derive(Serialize)]
    struct Ref<'a> {
        secret_key: &'a str,
        #[serde(with = "onepass_core::format::device_state_bytes")]
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

fn open_servers_lock(ctx: &Ctx) -> Result<fs::File, CliError> {
    let f = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(ctx.servers_lock_path())?;
    set_mode(&ctx.servers_lock_path(), 0o600)?;
    Ok(f)
}

/// Take `servers.lock` exclusively without waiting: refused with
/// [`SERVER_RUNNING`] while an `onepass mcp` or `onepass ssh-agent` holds it
/// shared. For the commands that change what a server's in-memory state
/// relies on (`travel on`, `travel off`, `backup restore`); the caller holds
/// the data directory lock, and keeps the returned file until it is done.
pub fn exclude_servers(ctx: &Ctx) -> Result<fs::File, CliError> {
    let f = open_servers_lock(ctx)?;
    match f.try_lock() {
        Ok(()) => Ok(f),
        Err(fs::TryLockError::WouldBlock) => Err(CliError::usage(SERVER_RUNNING)),
        Err(fs::TryLockError::Error(e)) => Err(e.into()),
    }
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
    for p in [ctx.device_path(), ctx.lock_path(), ctx.servers_lock_path()] {
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

    /// Unlock the account of the data directory with `password`. The
    /// caller holds the data directory lock: this reads `device.bin` and
    /// the store.
    pub fn open(ctx: &Ctx, password: &str) -> Result<Session, CliError> {
        let device_path = ctx.device_path();
        if !ctx.has_account() {
            return Err(no_account(ctx));
        }
        let bytes = Zeroizing::new(fs::read(&device_path)?);
        let file = decode(&bytes)?;
        let key = SecretKey::parse(&file.secret_key)?;
        let store = stored(SqliteStore::open(&ctx.store_path()))?;
        harden(ctx)?;
        let mut repo = stored(Repository::unlock(store, password, &key, file.state))?;
        resume_travel(ctx, &mut repo);
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

/// While Travel Mode is on, tell the repository which vaults are hidden on
/// purpose (`Repository::resume_travel`), so the signed vault list does not
/// report them missing. A `travel.bin` that does not open is left to the
/// travel commands: without it the hidden vaults stay expected, and reading
/// the vaults fails (`VaultMissing`) rather than accepting their absence.
fn resume_travel(ctx: &Ctx, repo: &mut Repository<SqliteStore>) {
    let Ok(bytes) = fs::read(ctx.travel_path()).map(Zeroizing::new) else {
        return;
    };
    if bytes.len() != SEALED_TRAVEL_STATE_LEN {
        return;
    }
    if let Ok(state) = repo.open_travel_state(&bytes) {
        repo.resume_travel(&state);
    }
}

fn no_account(ctx: &Ctx) -> CliError {
    CliError::usage(format!(
        "no account in {}; run `onepass account create` first",
        ctx.data_dir.display()
    ))
}

/// Read the password, lock the data directory, unlock, run `f`, then save
/// the device state. The state is saved even when `f` fails, because
/// reading items updates the last manifest seen. The lock is taken after
/// the prompt (a pending prompt never blocks other commands) and held from
/// the first read of `device.bin` until the state is saved.
pub fn with_session<T>(
    ctx: &Ctx,
    f: impl FnOnce(&mut Repository<SqliteStore>) -> Result<T, CliError>,
) -> Result<T, CliError> {
    with_session_then(ctx, f, || Ok(()))
}

/// Like [`with_session`], and runs `after` under the same lock once `f`
/// succeeded and the device state is saved (never when either failed).
/// For steps that must only follow a durable `device.bin`.
pub fn with_session_then<T>(
    ctx: &Ctx,
    f: impl FnOnce(&mut Repository<SqliteStore>) -> Result<T, CliError>,
    after: impl FnOnce() -> Result<(), CliError>,
) -> Result<T, CliError> {
    // Checked before taking the lock, so no lock file lands in a directory
    // that holds no account.
    if !ctx.has_account() {
        return Err(no_account(ctx));
    }
    let password = read_password("Password: ")?;
    let _lock = lock(ctx)?;
    let mut session = Session::open(ctx, &password)?;
    let result = f(&mut session.repo);
    let v = save_after(ctx, &session, result)?;
    after()?;
    Ok(v)
}

/// The tail of a locked request: harden the directory and save the device
/// state whatever `result` is (reads move the last seen manifests too),
/// then return `result`, or the save error if only the save failed.
fn save_after<T>(ctx: &Ctx, session: &Session, result: Result<T, CliError>) -> Result<T, CliError> {
    let saved = harden(ctx).and_then(|()| session.persist());
    match result {
        Ok(v) => saved.map(|()| v),
        Err(e) => Err(e),
    }
}

/// The password: `ONEPASS_PASSWORD` only when `ONEPASS_DEV_ALLOW_ENV_PASSWORD`
/// is `1` (tests), otherwise a masked prompt on the terminal.
pub fn read_password(prompt: &str) -> Result<Zeroizing<String>, CliError> {
    if env_secrets_allowed()?
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

/// The test switch letting secrets come from the environment.
pub const ENV_PASSWORD_SWITCH: &str = "ONEPASS_DEV_ALLOW_ENV_PASSWORD";

/// Whether secrets may come from the environment (tests only):
/// `ONEPASS_DEV_ALLOW_ENV_PASSWORD` is `1` in a debug build. A release
/// build refuses the switch instead of ignoring it, so a misconfigured
/// launcher fails loudly rather than reading secrets from the environment.
pub fn env_secrets_allowed() -> Result<bool, CliError> {
    env_secrets_allowed_with(
        cfg!(debug_assertions),
        std::env::var(ENV_PASSWORD_SWITCH).ok().as_deref(),
    )
}

/// [`env_secrets_allowed`] with the build kind and the switch value given.
pub fn env_secrets_allowed_with(debug: bool, var: Option<&str>) -> Result<bool, CliError> {
    match var {
        Some("1") if debug => Ok(true),
        Some("1") => Err(CliError::usage(
            "ONEPASS_DEV_ALLOW_ENV_PASSWORD is refused in a release build",
        )),
        _ => Ok(false),
    }
}

/// A secret other than the account password: `env_var` only when
/// `ONEPASS_DEV_ALLOW_ENV_PASSWORD` is `1` (tests), otherwise a masked
/// prompt on the terminal.
pub fn read_secret(prompt: &str, env_var: &str) -> Result<Zeroizing<String>, CliError> {
    if env_secrets_allowed()?
        && let Ok(p) = std::env::var(env_var)
    {
        return Ok(Zeroizing::new(p));
    }
    if !std::io::stdin().is_terminal() {
        return Err(CliError::usage("no terminal to read the secret from"));
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

/// The password of a server whose stdin and stdout carry a protocol:
/// `ONEPASS_PASSWORD` under the same test switch as [`read_password`],
/// otherwise a masked prompt on `/dev/tty`, never on stdin.
pub fn read_password_tty(prompt: &str) -> Result<Zeroizing<String>, CliError> {
    if env_secrets_allowed()?
        && let Ok(p) = std::env::var("ONEPASS_PASSWORD")
    {
        return Ok(Zeroizing::new(p));
    }
    let no_tty = || {
        CliError::usage(
            "cannot open /dev/tty to read the password (stdin and stdout carry the protocol)",
        )
    };
    // Tests only: behave as if there were no controlling terminal, since
    // the one of the developer running the tests may still be reachable.
    if cfg!(debug_assertions) && std::env::var("ONEPASS_DEV_NO_TTY").as_deref() == Ok("1") {
        return Err(no_tty());
    }
    if fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .is_err()
    {
        return Err(no_tty());
    }
    let p = rpassword::prompt_password(prompt).map_err(|_| no_tty())?;
    Ok(Zeroizing::new(p))
}

/// The device state saved in `device.bin`. The caller holds the lock.
pub fn read_device_state(ctx: &Ctx) -> Result<DeviceState, CliError> {
    let bytes = Zeroizing::new(fs::read(ctx.device_path())?);
    Ok(decode(&bytes)?.state)
}

/// An unlocked account for a long-running server (`onepass mcp`). It is
/// unlocked once, then every request takes the data directory lock, merges
/// the state other commands saved in `device.bin`, runs, saves the state
/// and releases the lock: the rest of the CLI stays usable meanwhile, and
/// no last seen manifest ever goes back.
///
/// While it lives it holds `servers.lock` shared, so `travel on`, `travel
/// off` and `backup restore` refuse to run under it. As a second line of
/// defense, it remembers whether `travel.bin` existed at unlock and refuses
/// every request once that changed ([`TRAVEL_CHANGED`]): its in-memory last
/// seen manifests would otherwise write hidden vault ids back to
/// `device.bin`.
pub struct LongSession {
    session: Session,
    ctx: Ctx,
    travel_at_unlock: bool,
    travel_changed: bool,
    _servers: fs::File,
}

impl LongSession {
    /// Read the password on `/dev/tty` (no lock held while prompting),
    /// then unlock under the lock and release it.
    pub fn open(ctx: &Ctx) -> Result<LongSession, CliError> {
        if !ctx.has_account() {
            return Err(no_account(ctx));
        }
        let password = read_password_tty("Password: ")?;
        let _lock = lock(ctx)?;
        let session = Session::open(ctx, &password)?;
        harden(ctx)?;
        session.persist()?;
        let travel_at_unlock = ctx.travel_path().exists();
        // Exclusive holders take it under the data directory lock, which
        // is held here: this never waits.
        let servers = open_servers_lock(ctx)?;
        servers.lock_shared()?;
        Ok(LongSession {
            session,
            ctx: Ctx {
                data_dir: ctx.data_dir.clone(),
                json: ctx.json,
            },
            travel_at_unlock,
            travel_changed: false,
            _servers: servers,
        })
    }

    /// Whether a request was refused because Travel Mode changed: the
    /// server must stop.
    pub fn travel_changed(&self) -> bool {
        self.travel_changed
    }

    /// The global options this session was opened with.
    pub fn ctx(&self) -> &Ctx {
        &self.ctx
    }

    /// The unlocked repository, for calls that touch neither the store nor
    /// the device state (local signatures).
    pub fn repo(&self) -> &Repository<SqliteStore> {
        &self.session.repo
    }

    /// One request: lock, check Travel Mode did not change since unlock
    /// (else [`TRAVEL_CHANGED`], and every later request too), merge
    /// `device.bin`, run `f`, save the state
    /// (even when `f` fails, reads move the last seen manifests too),
    /// unlock.
    pub fn with_repo<T>(
        &mut self,
        f: impl FnOnce(&mut Repository<SqliteStore>) -> Result<T, CliError>,
    ) -> Result<T, CliError> {
        let _lock = lock(&self.ctx)?;
        if self.travel_changed || self.ctx.travel_path().exists() != self.travel_at_unlock {
            self.travel_changed = true;
            return Err(CliError::usage(TRAVEL_CHANGED));
        }
        let state = read_device_state(&self.ctx)?;
        stored(self.session.repo.adopt_device_state(&state))?;
        // What is on disk now (same encoding, same key), so an unchanged
        // state is not rewritten and a changed one always is.
        self.session.on_disk = Some(encode(&self.session.secret_key, &state)?);
        let result = f(&mut self.session.repo);
        save_after(&self.ctx, &self.session, result)
    }
}
