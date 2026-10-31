//! Development session: the data directory, `device.bin` and unlocking.
//!
//! `<data-dir>/device.bin` (mode 0600) holds the `DeviceState` and says
//! where the Secret Key is: in the secret store of the system
//! (`secret_store.rs`), or, only when the user chose it with
//! `--insecure-file-secret-key`, in clear in the file itself. A Secret Key
//! still in clear from an older CLI moves into the store at the next unlock
//! (spec `docs/superpowers/specs/2026-10-28-cli-secret-key-design.md`).

use std::fmt;
use std::fs;
use std::io::{IsTerminal, Seek, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use onepass_core::crypto::{KdfParams, SecretKey};
use onepass_core::repo::travel::SEALED_TRAVEL_STATE_LEN;
use onepass_core::repo::{DeviceState, Repository};
use onepass_core::store::SqliteStore;
use onepass_core::{Error, Id};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::secret_store::{SecretStore, StoreError, entry_name};

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

/// The global option keeping the Secret Key in clear in `device.bin`.
pub const INSECURE_FILE_KEY_OPTION: &str = "--insecure-file-secret-key";

/// Global options shared by every command.
pub struct Ctx {
    pub data_dir: PathBuf,
    pub json: bool,
    /// Where Secret Keys are kept.
    pub secrets: Arc<dyn SecretStore>,
    /// `--insecure-file-secret-key`: keep the Secret Key in clear in
    /// `device.bin`, never in the store.
    pub insecure_file_key: bool,
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
            "DEV MODE: development CLI, data in {}",
            self.data_dir.display()
        );
    }

    /// The same options, for a server that outlives the command.
    pub fn clone_options(&self) -> Ctx {
        Ctx {
            data_dir: self.data_dir.clone(),
            json: self.json,
            secrets: Arc::clone(&self.secrets),
            insecure_file_key: self.insecure_file_key,
        }
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
            Error::Validation(_)
            | Error::InvalidFormat(_)
            | Error::Crypto
            | Error::Store(_)
            | Error::ReadOnly
            | Error::OutdatedKit { .. } => CliError::usage(e),
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
    use crate::secret_store::memory::MemoryStore;
    use crate::secret_store::{NoStore, StoreError, entry_name};

    #[test]
    fn fast_kdf_switch_is_debug_only() {
        let fast = |kdf: KdfParams| (kdf.m_kib, kdf.t, kdf.p);
        assert_eq!(
            fast(kdf_params_with(true, Some("1")).unwrap()),
            (8192, 1, 1)
        );
        let floor = fast(KdfParams::new_default().unwrap());
        assert_eq!(fast(kdf_params_with(true, None).unwrap()), floor);
        assert_eq!(fast(kdf_params_with(true, Some("0")).unwrap()), floor);
        let e = kdf_params_with(false, Some("1")).unwrap_err();
        assert_eq!(e.msg, "ONEPASS_DEV_FAST_KDF is refused in a release build");
    }

    #[test]
    fn fast_kdf_refused_by_the_core_names_the_feature() {
        let e = account_kdf_error(Error::InvalidFormat("kdf params"), true);
        assert_eq!(e.code, 1);
        assert_eq!(
            e.msg,
            "ONEPASS_DEV_FAST_KDF needs a build with the dev-fast-kdf feature \
             (cargo run -p onepass-cli --features dev-fast-kdf)"
        );
        // Without the switch, the core error stays as it is.
        let e = account_kdf_error(Error::InvalidFormat("kdf params"), false);
        assert_ne!(e.msg, "");
        assert!(!e.msg.contains("dev-fast-kdf"));
        let e = account_kdf_error(Error::WrongPassword, true);
        assert_eq!(e.code, 2);
    }

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
        assert_eq!(file.key, Stored::Legacy(Zeroizing::new("sk".to_owned())));
        assert_eq!(file.state, fixed_state());
        assert_eq!(file.state.epoch, 0);
        // The version 2 layout reads back the same.
        let v2 = encode_v2("sk", &file.state);
        assert_eq!(&v2[..3], b"\x02sk");
        assert_eq!(&v2[4..8], b"ODS\x02");
        let again = decode(&v2).unwrap();
        assert_eq!(again.state, file.state);
        assert_eq!(again.key, Stored::Legacy(Zeroizing::new("sk".to_owned())));
        bytes.push(0);
        assert!(decode(&bytes).is_err());
    }

    #[test]
    fn device_bin_roundtrips() {
        let mut state = fixed_state();
        state.epoch = 9;
        for key in [
            KeyAt::Store {
                account_id: onepass_core::Id([7; 16]),
            },
            KeyAt::File {
                secret_key: Zeroizing::new("sk".to_owned()),
            },
        ] {
            let mut bytes = encode(&key, &state).unwrap();
            assert_eq!(&bytes[..4], DEVICE_MAGIC);
            let file = decode(&bytes).unwrap();
            assert_eq!(file.state, state);
            assert_eq!(file.key, Stored::from(key));
            bytes.push(0);
            assert!(decode(&bytes).is_err());
        }
    }

    /// The version 2 layout (Secret Key in clear, then the versioned
    /// state), as every CLI before this one wrote it.
    fn encode_v2(secret_key: &str, state: &DeviceState) -> Vec<u8> {
        #[derive(Serialize)]
        struct V2<'a> {
            secret_key: &'a str,
            #[serde(with = "onepass_core::format::device_state_bytes")]
            state: &'a DeviceState,
        }
        postcard::to_allocvec(&V2 { secret_key, state }).unwrap()
    }

    const PASSWORD: &str = "correct horse battery staple";

    fn ctx(dir: &Path, store: Arc<dyn SecretStore>, insecure: bool) -> Ctx {
        Ctx {
            data_dir: dir.to_owned(),
            json: false,
            secrets: store,
            insecure_file_key: insecure,
        }
    }

    fn fast_kdf() -> KdfParams {
        kdf_params_with(true, Some("1")).unwrap()
    }

    /// A new account in `ctx`, saved like `account create` does; returns
    /// its Secret Key as shown.
    fn new_account(ctx: &Ctx) -> Result<Zeroizing<String>, CliError> {
        ensure_dir(&ctx.data_dir)?;
        let store = SqliteStore::open(&ctx.store_path())?;
        let (repo, key) = Repository::create_account(store, PASSWORD, fast_kdf())?;
        let shown = Zeroizing::new(key.to_display());
        Session::create(ctx, repo, &key)?.persist()?;
        Ok(shown)
    }

    /// Whether `bytes` hold the Secret Key in any of its text forms.
    fn holds_key(bytes: &[u8], shown: &str) -> bool {
        let bare: String = shown.chars().filter(|c| *c != '-').collect();
        [
            shown.to_owned(),
            bare.clone(),
            bare.to_lowercase(),
            shown.to_lowercase(),
        ]
        .iter()
        .any(|form| bytes.windows(form.len()).any(|w| w == form.as_bytes()))
    }

    /// Rewrite `device.bin` of `ctx` in the version 2 layout, key in clear.
    fn write_legacy(ctx: &Ctx, shown: &str) -> Vec<u8> {
        let state = read_device_state(ctx).unwrap();
        let bytes = encode_v2(shown, &state);
        fs::write(ctx.device_path(), &bytes).unwrap();
        bytes
    }

    fn memory() -> Arc<MemoryStore> {
        Arc::new(MemoryStore::default())
    }

    fn entries(store: &MemoryStore) -> Vec<(String, String)> {
        let mut v: Vec<_> = store
            .entries
            .lock()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.as_str().to_owned()))
            .collect();
        v.sort();
        v
    }

    #[test]
    fn device_bin_of_a_new_account_holds_no_secret_key() {
        let tmp = tempfile::tempdir().unwrap();
        let store = memory();
        let c = ctx(tmp.path(), store.clone(), false);
        let shown = new_account(&c).unwrap();
        let bytes = fs::read(c.device_path()).unwrap();
        assert!(!holds_key(&bytes, &shown));
        let id = match decode(&bytes).unwrap().key {
            Stored::Store(id) => id,
            other => panic!("expected the store layout, got {other:?}"),
        };
        assert_eq!(
            entries(&store),
            vec![(entry_name(id), shown.as_str().to_owned())]
        );
        // The store's key unlocks; nothing else changes on disk.
        let session = Session::open(&c, PASSWORD).unwrap();
        assert_eq!(session.repo.account_id(), id);
        session.persist().unwrap();
        assert!(!holds_key(&fs::read(c.device_path()).unwrap(), &shown));
    }

    #[test]
    fn a_new_account_without_a_store_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let none: Arc<dyn SecretStore> = Arc::new(NoStore::new("no store here"));
        let e = new_account(&ctx(tmp.path(), none, false)).unwrap_err();
        assert_eq!(e.code, 1);
        assert!(e.msg.contains("no store here"), "{}", e.msg);
        assert!(e.msg.contains("--insecure-file-secret-key"), "{}", e.msg);
        assert!(!tmp.path().join(DEVICE_FILE).exists());
    }

    #[test]
    fn insecure_file_key_is_an_explicit_choice() {
        let tmp = tempfile::tempdir().unwrap();
        let none: Arc<dyn SecretStore> = Arc::new(NoStore::new("no store here"));
        let c = ctx(tmp.path(), none.clone(), true);
        let shown = new_account(&c).unwrap();
        let bytes = fs::read(c.device_path()).unwrap();
        assert!(holds_key(&bytes, &shown));
        assert!(matches!(decode(&bytes).unwrap().key, Stored::File(_)));
        // Still no store: a later command without the option keeps going
        // on the explicit choice, and keeps the file as it is.
        let session = Session::open(&ctx(tmp.path(), none, false), PASSWORD).unwrap();
        session.persist().unwrap();
        assert_eq!(fs::read(c.device_path()).unwrap(), bytes);
    }

    #[test]
    fn a_legacy_device_bin_moves_into_the_store_on_unlock() {
        let tmp = tempfile::tempdir().unwrap();
        let first = memory();
        let c = ctx(tmp.path(), first.clone(), false);
        let shown = new_account(&c).unwrap();
        let legacy = write_legacy(&c, &shown);
        // Another link to the old file: the old content must be wiped,
        // not only unlinked.
        let old_link = tmp.path().join("device.bin.old-link");
        fs::hard_link(c.device_path(), &old_link).unwrap();

        // A machine whose store does not know the key yet.
        let store = memory();
        let c = ctx(tmp.path(), store.clone(), false);
        let session = Session::open(&c, PASSWORD).unwrap();
        let id = session.repo.account_id();
        assert_eq!(
            entries(&store),
            vec![(entry_name(id), shown.as_str().to_owned())]
        );
        let bytes = fs::read(c.device_path()).unwrap();
        assert!(!holds_key(&bytes, &shown));
        assert_eq!(decode(&bytes).unwrap().key, Stored::Store(id));
        let old = fs::read(&old_link).unwrap();
        assert_eq!(old.len(), legacy.len());
        assert!(old.iter().all(|b| *b == 0), "old device.bin not wiped");
        // The state survived the move, and the next unlock reads the store.
        assert_eq!(
            decode(&bytes).unwrap().state,
            decode(&legacy).unwrap().state
        );
        drop(session);
        Session::open(&c, PASSWORD).unwrap();
    }

    #[test]
    fn a_legacy_device_bin_without_a_store_is_refused_and_left_alone() {
        let tmp = tempfile::tempdir().unwrap();
        let c = ctx(tmp.path(), memory(), false);
        let shown = new_account(&c).unwrap();
        let legacy = write_legacy(&c, &shown);
        for store in [
            Arc::new(MemoryStore::failing(StoreError::Unavailable(
                "no store here".to_owned(),
            ))),
            Arc::new(MemoryStore::failing(StoreError::Failed(
                "keychain locked".to_owned(),
            ))),
        ] {
            let e = Session::open(&ctx(tmp.path(), store, false), PASSWORD)
                .err()
                .unwrap();
            assert_eq!(e.code, 1);
            assert!(e.msg.contains("--insecure-file-secret-key"), "{}", e.msg);
            assert_eq!(fs::read(c.device_path()).unwrap(), legacy);
        }
    }

    #[test]
    fn a_legacy_device_bin_with_the_option_becomes_an_explicit_file_key() {
        let tmp = tempfile::tempdir().unwrap();
        let c = ctx(tmp.path(), memory(), false);
        let shown = new_account(&c).unwrap();
        write_legacy(&c, &shown);
        let store = memory();
        let session = Session::open(&ctx(tmp.path(), store.clone(), true), PASSWORD).unwrap();
        session.persist().unwrap();
        let bytes = fs::read(c.device_path()).unwrap();
        assert_eq!(
            decode(&bytes).unwrap().key,
            Stored::File(Zeroizing::new(shown.as_str().to_owned()))
        );
        assert!(entries(&store).is_empty(), "the option keeps the store out");
    }

    #[test]
    fn a_file_key_moves_into_the_store_once_one_is_reachable() {
        let tmp = tempfile::tempdir().unwrap();
        let none: Arc<dyn SecretStore> = Arc::new(NoStore::new("no store here"));
        let shown = new_account(&ctx(tmp.path(), none, true)).unwrap();
        let store = memory();
        let c = ctx(tmp.path(), store.clone(), false);
        let session = Session::open(&c, PASSWORD).unwrap();
        assert_eq!(entries(&store).len(), 1);
        let bytes = fs::read(c.device_path()).unwrap();
        assert!(!holds_key(&bytes, &shown));
        assert_eq!(
            decode(&bytes).unwrap().key,
            Stored::Store(session.repo.account_id())
        );
    }

    #[test]
    fn a_store_key_missing_from_the_store_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        new_account(&ctx(tmp.path(), memory(), false)).unwrap();
        let e = Session::open(&ctx(tmp.path(), memory(), false), PASSWORD)
            .err()
            .unwrap();
        assert_eq!(e.code, 1);
        assert!(e.msg.contains("secretkey."), "{}", e.msg);
        assert!(e.msg.contains("is not in the memory store"), "{}", e.msg);
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

/// Header of the version 3 `device.bin`. The older layouts start with the
/// length of the Secret Key in clear (53 characters, `0x35`), never `O`.
const DEVICE_MAGIC: &[u8; 4] = b"ODF\x03";

/// Where the Secret Key is, as `device.bin` version 3 records it.
#[derive(Serialize, Deserialize)]
enum KeyAt {
    /// In the secret store, entry `secretkey.<account_id>`.
    Store { account_id: Id },
    /// In clear in `device.bin` (`--insecure-file-secret-key`).
    File { secret_key: Zeroizing<String> },
}

/// `device.bin` version 3, after its header, encoded with postcard: the
/// device state first (as the byte string of `DeviceState::encode`), so a
/// reader that only wants the state need not know the rest.
#[derive(Deserialize)]
struct DeviceFile {
    #[serde(with = "onepass_core::format::device_state_bytes")]
    state: DeviceState,
    secret_key: KeyAt,
}

/// `device.bin` version 2: the Secret Key in clear, then the versioned
/// state. Read only; the Secret Key moves into the store on unlock.
#[derive(Deserialize)]
struct DeviceFileV2 {
    secret_key: Zeroizing<String>,
    #[serde(with = "onepass_core::format::device_state_bytes")]
    state: DeviceState,
}

/// `device.bin` version 1: the Secret Key in clear, then the version 1
/// state inline. Read only, migrated with `epoch = 0`.
#[derive(Deserialize)]
struct DeviceFileV1 {
    secret_key: Zeroizing<String>,
    #[serde(deserialize_with = "onepass_core::format::device_state_v1_inline::deserialize")]
    state: DeviceState,
}

/// Where a decoded `device.bin` says the Secret Key is.
#[derive(PartialEq, Eq)]
enum Stored {
    Store(Id),
    /// In clear, by explicit choice (`--insecure-file-secret-key`).
    File(Zeroizing<String>),
    /// In clear, written by an older CLI (version 1 or 2).
    Legacy(Zeroizing<String>),
}

impl fmt::Debug for Stored {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Stored::Store(id) => write!(f, "Store({id})"),
            Stored::File(_) => f.write_str("File(..)"),
            Stored::Legacy(_) => f.write_str("Legacy(..)"),
        }
    }
}

impl From<KeyAt> for Stored {
    fn from(k: KeyAt) -> Stored {
        match k {
            KeyAt::Store { account_id } => Stored::Store(account_id),
            KeyAt::File { secret_key } => Stored::File(secret_key),
        }
    }
}

/// A decoded `device.bin`.
struct Decoded {
    state: DeviceState,
    key: Stored,
}

/// Decode `device.bin`: version 3 behind its header (whole buffer), else
/// version 2, else version 1.
fn decode(bytes: &[u8]) -> Result<Decoded, CliError> {
    let unreadable = || CliError::usage("device.bin is unreadable");
    if let Some(body) = bytes.strip_prefix(DEVICE_MAGIC) {
        return match postcard::take_from_bytes::<DeviceFile>(body) {
            Ok((file, [])) => Ok(Decoded {
                state: file.state,
                key: file.secret_key.into(),
            }),
            _ => Err(unreadable()),
        };
    }
    if let Ok((file, [])) = postcard::take_from_bytes::<DeviceFileV2>(bytes) {
        return Ok(Decoded {
            state: file.state,
            key: Stored::Legacy(file.secret_key),
        });
    }
    match postcard::take_from_bytes::<DeviceFileV1>(bytes) {
        Ok((old, [])) => Ok(Decoded {
            state: old.state,
            key: Stored::Legacy(old.secret_key),
        }),
        _ => Err(unreadable()),
    }
}

/// Encode `device.bin` version 3.
fn encode(key: &KeyAt, state: &DeviceState) -> Result<Zeroizing<Vec<u8>>, CliError> {
    // Borrowed copy of the fields, so the state is encoded without a clone.
    #[derive(Serialize)]
    struct Ref<'a> {
        #[serde(with = "onepass_core::format::device_state_bytes")]
        state: &'a DeviceState,
        secret_key: &'a KeyAt,
    }
    let body = Zeroizing::new(
        postcard::to_allocvec(&Ref {
            state,
            secret_key: key,
        })
        .map_err(|_| CliError::usage("cannot encode device.bin"))?,
    );
    let mut bytes = Zeroizing::new(Vec::with_capacity(DEVICE_MAGIC.len() + body.len()));
    bytes.extend_from_slice(DEVICE_MAGIC);
    bytes.extend_from_slice(&body);
    Ok(bytes)
}

/// The refusal of a Secret Key that has no store to go to.
fn no_store(ctx: &Ctx, e: &StoreError, what: &str) -> CliError {
    let store = match e {
        StoreError::Unavailable(why) => why.clone(),
        StoreError::Failed(why) => format!("{}: {why}", ctx.secrets.name()),
    };
    CliError::usage(format!(
        "{store}; {what}. Make a secret store reachable, or pass \
         {INSECURE_FILE_KEY_OPTION} to keep the Secret Key in clear in device.bin \
         (anyone who reads that file then needs only the password)"
    ))
}

/// Say on stderr that the Secret Key sits in clear in `device.bin`.
fn warn_file_key(ctx: &Ctx) {
    eprintln!(
        "WARNING: the Secret Key is in clear in {} ({INSECURE_FILE_KEY_OPTION}): \
         anyone who reads that file needs only the password",
        ctx.device_path().display()
    );
}

/// Write `key` to the store under the entry of `account`, then read it
/// back: a key the store does not give back unchanged is not stored.
fn put_key(ctx: &Ctx, account: Id, key: &str) -> Result<(), StoreError> {
    let entry = entry_name(account);
    ctx.secrets.set(&entry, key)?;
    match ctx.secrets.get(&entry)? {
        Some(back) if back.as_str() == key => Ok(()),
        _ => Err(StoreError::Failed(
            "the stored Secret Key did not read back unchanged".to_owned(),
        )),
    }
}

/// The Secret Key of `account` from the store.
fn fetch_key(ctx: &Ctx, account: Id) -> Result<Zeroizing<String>, CliError> {
    let entry = entry_name(account);
    match ctx.secrets.get(&entry) {
        Ok(Some(key)) => Ok(key),
        Ok(None) => Err(CliError::usage(format!(
            "the Secret Key of this account is not in the {} (entry {entry}, service {}); \
             was the data directory copied from another machine?",
            ctx.secrets.name(),
            crate::secret_store::SERVICE
        ))),
        Err(e) => Err(CliError::usage(format!(
            "cannot read the Secret Key from the {}: {e}",
            ctx.secrets.name()
        ))),
    }
}

/// Remove the store entry of `account`, best effort: for an account
/// creation being undone.
pub fn forget_key(ctx: &Ctx, account: Id) {
    let _ = ctx.secrets.delete(&entry_name(account));
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
    key_at: KeyAt,
    device_path: PathBuf,
    /// The bytes on disk, so an unchanged state is not rewritten.
    on_disk: Option<Zeroizing<Vec<u8>>>,
}

impl Session {
    /// Session of a freshly created account: its Secret Key goes into the
    /// store (or, with `--insecure-file-secret-key`, stays for
    /// `device.bin`). Nothing is on disk yet: `persist` writes it. The
    /// caller removes the store entry ([`forget_key`]) if the creation is
    /// undone.
    pub fn create(
        ctx: &Ctx,
        repo: Repository<SqliteStore>,
        key: &SecretKey,
    ) -> Result<Session, CliError> {
        let shown = Zeroizing::new(key.to_display());
        let key_at = if ctx.insecure_file_key {
            warn_file_key(ctx);
            KeyAt::File { secret_key: shown }
        } else {
            let account = repo.account_id();
            if let Err(e) = put_key(ctx, account, &shown) {
                forget_key(ctx, account);
                return Err(no_store(ctx, &e, "the account was not created"));
            }
            KeyAt::Store {
                account_id: account,
            }
        };
        Ok(Session {
            repo,
            key_at,
            device_path: ctx.device_path(),
            on_disk: None,
        })
    }

    /// Unlock the account of the data directory with `password`. The
    /// caller holds the data directory lock: this reads `device.bin` and
    /// the store. A Secret Key in clear moves into the store here, once
    /// the unlock proved it right (unless `--insecure-file-secret-key`).
    pub fn open(ctx: &Ctx, password: &str) -> Result<Session, CliError> {
        let device_path = ctx.device_path();
        if !ctx.has_account() {
            return Err(no_account(ctx));
        }
        let bytes = Zeroizing::new(fs::read(&device_path)?);
        let Decoded {
            state,
            key: at_rest,
        } = decode(&bytes)?;
        let key_text = match &at_rest {
            Stored::Store(account) => fetch_key(ctx, *account)?,
            Stored::File(k) | Stored::Legacy(k) => k.clone(),
        };
        let key = SecretKey::parse(&key_text)?;
        let store = stored(SqliteStore::open(&ctx.store_path()))?;
        harden(ctx)?;
        let mut repo = stored(Repository::unlock(store, password, &key, state))?;
        resume_travel(ctx, &mut repo);
        let (key_at, moved) = settle_key(ctx, at_rest, &key_text, repo.account_id())?;
        let mut session = Session {
            repo,
            key_at,
            device_path,
            on_disk: Some(bytes),
        };
        if moved {
            session.on_disk = Some(session.write(true)?);
            eprintln!(
                "The Secret Key moved from device.bin into the {}. Copies of device.bin \
                 made before now (backups, snapshots, synced folders) still hold it in clear.",
                ctx.secrets.name()
            );
        }
        Ok(session)
    }

    /// Write `device.bin` (0600, atomically, file and directory synced) if
    /// the device state changed.
    pub fn persist(&self) -> Result<(), CliError> {
        self.write(false).map(|_| ())
    }

    /// Write `device.bin` unless unchanged, and return what is on disk.
    /// With `wipe`, the replaced file is overwritten with zeros once the
    /// new one is in place: through a descriptor opened before the rename,
    /// so `device.bin` is whole at every instant.
    fn write(&self, wipe: bool) -> Result<Zeroizing<Vec<u8>>, CliError> {
        let bytes = encode(&self.key_at, self.repo.device_state())?;
        if self.on_disk.as_deref() == Some(&*bytes) {
            return Ok(bytes);
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
        let old = if wipe {
            fs::OpenOptions::new()
                .write(true)
                .open(&self.device_path)
                .ok()
        } else {
            None
        };
        fs::rename(&tmp, &self.device_path)?;
        // The rename lives in the directory: sync it too, or a power loss
        // can bring back the old device.bin (and an older last seen state).
        let dir = match self.device_path.parent() {
            Some(d) if !d.as_os_str().is_empty() => d,
            _ => Path::new("."),
        };
        fs::File::open(dir)?.sync_all()?;
        if let Some(mut old) = old {
            let len = usize::try_from(old.metadata()?.len())
                .map_err(|_| CliError::usage("device.bin is too large"))?;
            old.rewind()?;
            old.write_all(&vec![0u8; len])?;
            old.sync_all()?;
        }
        Ok(bytes)
    }
}

/// Where the Secret Key goes after an unlock with `key`, and whether it
/// just moved into the store (`device.bin` must then be rewritten and the
/// old file wiped).
fn settle_key(
    ctx: &Ctx,
    stored: Stored,
    key: &str,
    account: Id,
) -> Result<(KeyAt, bool), CliError> {
    let (in_clear, legacy) = match stored {
        Stored::Store(account_id) => return Ok((KeyAt::Store { account_id }, false)),
        Stored::File(k) => (k, false),
        Stored::Legacy(k) => (k, true),
    };
    if ctx.insecure_file_key {
        warn_file_key(ctx);
        return Ok((
            KeyAt::File {
                secret_key: in_clear,
            },
            false,
        ));
    }
    match put_key(ctx, account, key) {
        Ok(()) => Ok((
            KeyAt::Store {
                account_id: account,
            },
            true,
        )),
        // An older CLI wrote this key in clear: keeping it there needs
        // the explicit choice.
        Err(e) if legacy => Err(no_store(
            ctx,
            &e,
            "the Secret Key in clear in device.bin cannot move into it",
        )),
        // An earlier explicit choice: keep it, and keep saying so.
        Err(e) => {
            eprintln!("WARNING: {e}");
            warn_file_key(ctx);
            Ok((
                KeyAt::File {
                    secret_key: in_clear,
                },
                false,
            ))
        }
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
/// when `ONEPASS_DEV_FAST_KDF=1` (debug builds only; the core accepts them
/// only with its `dev-fast-kdf` feature, see [`account_kdf_error`]).
pub fn kdf_params() -> Result<KdfParams, CliError> {
    kdf_params_with(cfg!(debug_assertions), fast_kdf_requested().as_deref())
}

/// The value of `ONEPASS_DEV_FAST_KDF`.
pub fn fast_kdf_requested() -> Option<String> {
    std::env::var("ONEPASS_DEV_FAST_KDF").ok()
}

/// [`kdf_params`] with the build kind and the switch value given.
pub fn kdf_params_with(debug: bool, var: Option<&str>) -> Result<KdfParams, CliError> {
    let mut kdf = KdfParams::new_default()?;
    if var == Some("1") {
        if !debug {
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

/// The error of an account creation. With `ONEPASS_DEV_FAST_KDF=1`, a core
/// built without `dev-fast-kdf` (the default of the CLI) refuses the fast
/// parameters as `InvalidFormat("kdf params")`: say which feature is missing.
pub fn account_kdf_error(e: Error, fast_requested: bool) -> CliError {
    match e {
        Error::InvalidFormat("kdf params") if fast_requested => CliError::usage(
            "ONEPASS_DEV_FAST_KDF needs a build with the dev-fast-kdf feature \
             (cargo run -p onepass-cli --features dev-fast-kdf)",
        ),
        other => CliError::from(other),
    }
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
#[cfg(test)]
fn read_device_state(ctx: &Ctx) -> Result<DeviceState, CliError> {
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
            ctx: ctx.clone_options(),
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
        let bytes = Zeroizing::new(fs::read(self.ctx.device_path())?);
        let Decoded { state, key } = decode(&bytes)?;
        // Another command moved the Secret Key into the store: never write
        // it back in clear.
        if let Stored::Store(account_id) = key {
            self.session.key_at = KeyAt::Store { account_id };
        }
        stored(self.session.repo.adopt_device_state(&state))?;
        // What is on disk now (same encoding, same key), so an unchanged
        // state is not rewritten and a changed one always is.
        self.session.on_disk = Some(encode(&self.session.key_at, &state)?);
        let result = f(&mut self.session.repo);
        save_after(&self.ctx, &self.session, result)
    }
}
