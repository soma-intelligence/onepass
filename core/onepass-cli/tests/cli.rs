//! End-to-end tests of the `onepass` binary.
//!
//! Creating an account signs with SLH-DSA, which takes seconds in a debug
//! build. The account (and one login item) is therefore created once, in a
//! template directory, and every test works on its own copy of it.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use assert_cmd::Command;
use predicates::prelude::*;

/// The development secret store of every test run (`secret_store.rs`):
/// a directory standing in for the keychain or the Secret Service.
const SECRET_STORE: &str = concat!("dir:", env!("CARGO_TARGET_TMPDIR"), "/secret-store");

const PASSWORD: &str = "correct horse battery";
const TOTP_SECRET: &str = "JBSWY3DPEHPK3PXP";

struct Out {
    code: i32,
    stdout: String,
    stderr: String,
}

struct Template {
    dir: PathBuf,
    account: Out,
    item: Out,
}

fn onepass(dir: &Path, password: &str) -> Command {
    let mut c = Command::cargo_bin("onepass").unwrap();
    c.env("ONEPASS_DEV_ALLOW_ENV_PASSWORD", "1")
        .env("ONEPASS_PASSWORD", password)
        .env("ONEPASS_DEV_FAST_KDF", "1")
        .env("ONEPASS_DEV_SECRET_STORE", SECRET_STORE)
        .arg("--data-dir")
        .arg(dir);
    c
}

fn run(dir: &Path, args: &[&str]) -> Out {
    let o = onepass(dir, PASSWORD).args(args).output().unwrap();
    Out {
        code: o.status.code().unwrap(),
        stdout: String::from_utf8(o.stdout).unwrap(),
        stderr: String::from_utf8(o.stderr).unwrap(),
    }
}

fn template() -> &'static Template {
    static T: OnceLock<Template> = OnceLock::new();
    T.get_or_init(|| {
        let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("cli-template-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let account = run(&dir, &["account", "create"]);
        let item = run(
            &dir,
            &[
                "item",
                "create",
                "login",
                "--title",
                "GitHub",
                "--field",
                "username=q",
                "--field",
                "password=hunter2",
            ],
        );
        Template { dir, account, item }
    })
}

/// A private copy of the template directory.
fn fresh() -> tempfile::TempDir {
    let t = template();
    let tmp = tempfile::tempdir().unwrap();
    for entry in fs::read_dir(&t.dir).unwrap() {
        let entry = entry.unwrap();
        fs::copy(entry.path(), tmp.path().join(entry.file_name())).unwrap();
    }
    tmp
}

#[test]
fn full_flow() {
    let t = template();

    // account create: Secret Key once on stdout, banner on stderr.
    assert_eq!(t.account.code, 0, "{}", t.account.stderr);
    let key = t
        .account
        .stdout
        .lines()
        .find_map(|l| l.strip_prefix("Secret Key: "))
        .expect("a Secret Key line");
    assert_eq!(key.replace('-', "").len(), 53);
    assert!(t.account.stderr.contains("DEV MODE"));
    let device = t.dir.join("device.bin");
    assert!(device.exists());
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&device), 0o600);
        assert_eq!(mode(&t.dir), 0o700);
    }

    assert_eq!(t.item.code, 0, "{}", t.item.stderr);
    assert!(t.item.stderr.contains("DEV MODE"));

    let tmp = fresh();
    let dir = tmp.path();

    // read: the bare value, no trailing newline when stdout is a pipe.
    onepass(dir, PASSWORD)
        .args(["read", "onepass://Personnel/GitHub/password"])
        .assert()
        .success()
        .stdout(predicate::eq("hunter2"));

    // get: secrets masked.
    onepass(dir, PASSWORD)
        .args(["item", "get", "GitHub"])
        .assert()
        .success()
        .stdout(predicate::str::contains("hunter2").not())
        .stdout(predicate::str::contains("••••••••"))
        .stdout(predicate::str::contains("GitHub"));

    // get --reveal --json: the secret appears.
    let out = onepass(dir, PASSWORD)
        .args(["item", "get", "github", "--reveal", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert!(json.to_string().contains("hunter2"));
    assert_eq!(json["title"], "GitHub");

    // get --json without --reveal stays masked.
    onepass(dir, PASSWORD)
        .args(["item", "get", "GitHub", "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("hunter2").not());

    // list and vaults.
    onepass(dir, PASSWORD)
        .args(["item", "list", "--type", "login"])
        .assert()
        .success()
        .stdout(predicate::str::contains("GitHub"));
    onepass(dir, PASSWORD)
        .args(["item", "list", "--type", "credit-card"])
        .assert()
        .success()
        .stdout(predicate::str::contains("GitHub").not());
    onepass(dir, PASSWORD)
        .args(["vault", "create", "Travail"])
        .assert()
        .success();
    onepass(dir, PASSWORD)
        .args(["vault", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Personnel"))
        .stdout(predicate::str::contains("Travail"));
}

#[test]
fn edit_move_delete_flow() {
    let tmp = fresh();
    let d = tmp.path();
    assert_eq!(run(d, &["vault", "create", "Travail"]).code, 0);
    assert_eq!(
        run(d, &["item", "edit", "GitHub", "--field", "password=n3w"]).code,
        0
    );
    assert_eq!(
        run(d, &["read", "onepass://Personnel/GitHub/password"]).stdout,
        "n3w"
    );
    assert_eq!(
        run(d, &["item", "move", "GitHub", "--to", "Travail"]).code,
        0
    );
    assert_eq!(
        run(d, &["read", "onepass://Travail/GitHub/password"]).stdout,
        "n3w"
    );
    let gone = run(d, &["read", "onepass://Personnel/GitHub/password"]);
    assert_eq!(gone.code, 4);
    assert_eq!(run(d, &["item", "delete", "GitHub"]).code, 0);
    assert_eq!(run(d, &["item", "get", "GitHub"]).code, 4);
    assert!(!run(d, &["item", "list"]).stdout.contains("GitHub"));
}

#[test]
fn totp_and_usage_errors() {
    let tmp = fresh();
    let d = tmp.path();
    let totp = format!("totp={TOTP_SECRET}");
    let made = run(
        d,
        &[
            "item",
            "create",
            "login",
            "--title",
            "Two",
            "--field",
            "username=a",
            "--field",
            &totp,
        ],
    );
    assert_eq!(made.code, 0, "{}", made.stderr);
    let code = run(d, &["totp", "Two"]);
    assert_eq!(code.code, 0, "{}", code.stderr);
    let digits = code.stdout.trim();
    assert_eq!(digits.len(), 6);
    assert!(digits.chars().all(|c| c.is_ascii_digit()));
    // An item without a one-time password field.
    assert_eq!(run(d, &["totp", "GitHub"]).code, 4);

    // Unknown field id, unsupported kind, bad number: usage errors.
    let unknown = run(
        d,
        &[
            "item", "create", "login", "--title", "X", "--field", "nope=1",
        ],
    );
    assert_eq!(unknown.code, 1);
    assert!(unknown.stderr.contains("nope"));
    let passkey = run(
        d,
        &[
            "item",
            "create",
            "login",
            "--title",
            "X",
            "--field",
            "passkeys=1",
        ],
    );
    assert_eq!(passkey.code, 1);
    assert!(passkey.stderr.contains("not supported"));
    assert_eq!(
        run(d, &["item", "create", "no-such-type", "--title", "X"]).code,
        1
    );
    assert_eq!(run(d, &["item", "get"]).code, 1);

    // Ambiguous title: exit 1, the id still works.
    for _ in 0..2 {
        let r = run(
            d,
            &[
                "item",
                "create",
                "login",
                "--title",
                "Dup",
                "--field",
                "username=u",
            ],
        );
        assert_eq!(r.code, 0);
    }
    let amb = run(d, &["item", "get", "Dup"]);
    assert_eq!(amb.code, 1);
    assert!(amb.stderr.contains("ambiguous"));

    // No account in the directory: usage error, nothing is created.
    let empty = tempfile::tempdir().unwrap();
    let none = run(empty.path(), &["item", "list"]);
    assert_eq!(none.code, 1);
    assert!(none.stderr.contains("account create"));
    assert!(!empty.path().join("vault.sqlite").exists());

    // A second account in the same directory is refused.
    assert_eq!(run(d, &["account", "create"]).code, 1);
}

#[test]
fn password_from_environment_needs_the_dev_switch() {
    let tmp = fresh();
    // Without the switch the variable is ignored and the prompt cannot be
    // answered (no terminal): a usage error, not a login.
    Command::cargo_bin("onepass")
        .unwrap()
        .env_remove("ONEPASS_DEV_ALLOW_ENV_PASSWORD")
        .env("ONEPASS_PASSWORD", PASSWORD)
        .arg("--data-dir")
        .arg(tmp.path())
        .args(["item", "list"])
        .assert()
        .code(1);
}

#[test]
fn wrong_password_exit_code_2() {
    let tmp = fresh();
    onepass(tmp.path(), "not the password")
        .args(["item", "list"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("wrong password"));
}

#[test]
fn tampered_db_exit_code_3() {
    let tmp = fresh();
    {
        let conn = rusqlite::Connection::open(tmp.path().join("vault.sqlite")).unwrap();
        let mut data: Vec<u8> = conn
            .query_row("SELECT data FROM records WHERE kind = 5", [], |r| r.get(0))
            .unwrap();
        let last = data.len() - 1;
        data[last] ^= 0x01;
        let n = conn
            .execute("UPDATE records SET data = ?1 WHERE kind = 5", [&data])
            .unwrap();
        assert_eq!(n, 1);
    }
    onepass(tmp.path(), PASSWORD)
        .args(["item", "list"])
        .assert()
        .code(3)
        .stderr(predicate::str::contains(
            "stored data failed verification, possible tampering",
        ));
}

#[test]
fn generate_without_account() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("never-created");
    let out = onepass(&dir, PASSWORD)
        .args(["generate", "--length", "24"])
        .assert()
        .success()
        .stderr(predicate::str::contains("DEV MODE").not())
        .get_output()
        .stdout
        .clone();
    assert_eq!(
        String::from_utf8(out).unwrap().trim_end().chars().count(),
        24
    );
    assert!(!dir.exists());

    let no_symbols = onepass(&dir, PASSWORD)
        .args(["generate", "--length", "40", "--no-symbols"])
        .output()
        .unwrap();
    let s = String::from_utf8(no_symbols.stdout).unwrap();
    assert!(s.trim_end().chars().all(|c| c.is_ascii_alphanumeric()));

    let words = onepass(&dir, PASSWORD)
        .args(["generate", "--words", "5"])
        .output()
        .unwrap();
    let s = String::from_utf8(words.stdout).unwrap();
    assert_eq!(s.trim_end().split('-').count(), 5);

    let pin = onepass(&dir, PASSWORD)
        .args(["generate", "--pin", "6"])
        .output()
        .unwrap();
    let s = String::from_utf8(pin.stdout).unwrap();
    assert!(s.trim_end().len() == 6 && s.trim_end().chars().all(|c| c.is_ascii_digit()));

    onepass(&dir, PASSWORD)
        .args(["generate", "--length", "3"])
        .assert()
        .code(1);
}

/// Flip the last byte of the data of every record of `kind`.
fn corrupt(dir: &Path, kind: i64, how: &str) {
    let conn = rusqlite::Connection::open(dir.join("vault.sqlite")).unwrap();
    let n = conn
        .execute(
            &format!("UPDATE records SET data = {how} WHERE kind = ?1"),
            [kind],
        )
        .unwrap();
    assert!(n >= 1);
}

#[test]
fn damaged_records_exit_code_3() {
    // Account params: last byte flipped (the signature).
    let tmp = fresh();
    corrupt(
        tmp.path(),
        1,
        "substr(data, 1, length(data) - 1) || char(unicode(substr(data, -1)) + 1)",
    );
    let bad = run(tmp.path(), &["item", "list"]);
    assert_eq!(bad.code, 3, "{}", bad.stderr);
    assert!(bad.stderr.contains("possible tampering"));

    // An item record cut short: a malformed header, not a failed tag.
    let tmp = fresh();
    corrupt(tmp.path(), 5, "substr(data, 1, 3)");
    assert_eq!(run(tmp.path(), &["item", "list"]).code, 3);

    // Garbage that is not a database at all.
    let tmp = fresh();
    fs::write(tmp.path().join("vault.sqlite"), vec![0x42u8; 4096]).unwrap();
    for f in ["vault.sqlite-wal", "vault.sqlite-shm"] {
        let _ = fs::remove_file(tmp.path().join(f));
    }
    assert_eq!(run(tmp.path(), &["item", "list"]).code, 3);

    // Bad user input stays a usage error, never a tampering report.
    let tmp = fresh();
    assert_eq!(run(tmp.path(), &["read", "http://nope"]).code, 1);
}

#[test]
fn existing_directory_is_hardened() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = fresh();
    let d = tmp.path();
    let set = |p: &Path, m: u32| fs::set_permissions(p, fs::Permissions::from_mode(m)).unwrap();
    set(d, 0o755);
    set(&d.join("vault.sqlite"), 0o644);
    set(&d.join("device.bin"), 0o644);
    assert_eq!(run(d, &["item", "list"]).code, 0);
    let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(d), 0o700);
    assert_eq!(mode(&d.join("vault.sqlite")), 0o600);
    assert_eq!(mode(&d.join("device.bin")), 0o600);
    for f in ["vault.sqlite-wal", "vault.sqlite-shm"] {
        if d.join(f).exists() {
            assert_eq!(mode(&d.join(f)), 0o600);
        }
    }
}

#[test]
fn device_state_detects_a_restored_old_database() {
    let tmp = fresh();
    let d = tmp.path();
    let snapshot = |from: &Path, to: &Path| {
        for f in ["vault.sqlite", "vault.sqlite-wal", "vault.sqlite-shm"] {
            let _ = fs::remove_file(to.join(f));
            if from.join(f).exists() {
                fs::copy(from.join(f), to.join(f)).unwrap();
            }
        }
    };
    // Read once so the device has seen the current manifest, then snapshot.
    assert_eq!(run(d, &["item", "list"]).code, 0);
    let old = tempfile::tempdir().unwrap();
    snapshot(d, old.path());
    let device_before = fs::read(d.join("device.bin")).unwrap();

    // A write, then a read: the device remembers the newer manifest.
    let made = run(
        d,
        &[
            "item",
            "create",
            "login",
            "--title",
            "Later",
            "--field",
            "username=u",
        ],
    );
    assert_eq!(made.code, 0, "{}", made.stderr);
    assert_eq!(run(d, &["item", "list"]).code, 0);
    assert_ne!(fs::read(d.join("device.bin")).unwrap(), device_before);

    // The old database comes back; device.bin still knows better.
    snapshot(old.path(), d);
    let rolled = run(d, &["item", "list"]);
    assert_eq!(rolled.code, 3, "{}", rolled.stderr);
    assert!(rolled.stderr.contains("possible tampering"));
}

#[test]
fn parallel_writers_lose_nothing() {
    let tmp = fresh();
    let dir = tmp.path();
    let children: Vec<_> = (0..6)
        .map(|n| {
            let mut c = std::process::Command::new(assert_cmd::cargo::cargo_bin("onepass"));
            c.env("ONEPASS_DEV_ALLOW_ENV_PASSWORD", "1")
                .env("ONEPASS_PASSWORD", PASSWORD)
                .env("ONEPASS_DEV_FAST_KDF", "1")
                .env("ONEPASS_DEV_SECRET_STORE", SECRET_STORE)
                .arg("--data-dir")
                .arg(dir)
                .args(["item", "create", "login", "--title"])
                .arg(format!("parallel {n}"))
                .args(["--field", "username=u"])
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped());
            c.spawn().unwrap()
        })
        .collect();
    for child in children {
        let out = child.wait_with_output().unwrap();
        assert_eq!(
            out.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let list = run(dir, &["item", "list", "--json"]);
    assert_eq!(list.code, 0, "{}", list.stderr);
    let rows: serde_json::Value = serde_json::from_str(&list.stdout).unwrap();
    // The template's GitHub item plus the six.
    assert_eq!(rows.as_array().unwrap().len(), 7, "{}", list.stdout);
    assert!(dir.join("lock").exists());
}

/// Run `args` with stdout a pipe whose reading end is closed before the
/// command writes anything, as `onepass ... | head -c1` ends up doing.
fn run_closed_stdout(dir: &Path, args: &[&str]) -> Out {
    let mut child = std::process::Command::new(assert_cmd::cargo::cargo_bin("onepass"))
        .env("ONEPASS_DEV_ALLOW_ENV_PASSWORD", "1")
        .env("ONEPASS_PASSWORD", PASSWORD)
        .env("ONEPASS_DEV_FAST_KDF", "1")
        .env("ONEPASS_DEV_SECRET_STORE", SECRET_STORE)
        .arg("--data-dir")
        .arg(dir)
        .args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    // Unlocking takes far longer than this: the command writes into a pipe
    // nobody reads any more.
    drop(child.stdout.take());
    let o = child.wait_with_output().unwrap();
    Out {
        code: o.status.code().unwrap_or(-1),
        stdout: String::new(),
        stderr: String::from_utf8(o.stderr).unwrap(),
    }
}

#[test]
fn closed_stdout_exits_quietly() {
    let tmp = fresh();
    let dir = tmp.path();
    for args in [
        &["read", "onepass://Personnel/GitHub/password"][..],
        &["item", "list"][..],
        &["item", "get", "GitHub"][..],
    ] {
        let out = run_closed_stdout(dir, args);
        assert_eq!(out.code, 0, "{args:?}: {}", out.stderr);
        assert!(!out.stderr.contains("panicked"), "{}", out.stderr);
        assert!(!out.stderr.contains("error"), "{}", out.stderr);
    }
    // The device state was still saved: later commands work.
    assert_eq!(run(dir, &["item", "list"]).code, 0);
}

#[test]
fn account_create_with_closed_stdout_fails_and_leaves_no_account() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("data");
    let out = run_closed_stdout(&dir, &["account", "create"]);
    assert_ne!(out.code, 0, "{}", out.stderr);
    assert!(
        out.stderr.contains("the account was not created"),
        "{}",
        out.stderr
    );
    assert!(!dir.join("device.bin").exists());
    assert!(!dir.join("vault.sqlite").exists());
    // The directory is usable for a new attempt.
    assert_eq!(run(&dir, &["account", "create"]).code, 0);
}

#[test]
fn a_pending_password_prompt_does_not_hold_the_lock() {
    let tmp = fresh();
    let dir = tmp.path();
    // Another process holds the data directory lock.
    let held = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(dir.join("lock"))
        .unwrap();
    held.lock().unwrap();
    // No env password and no terminal: the prompt fails at once. It must
    // fail before waiting for the lock, not hang behind it.
    let mut child = std::process::Command::new(assert_cmd::cargo::cargo_bin("onepass"))
        .arg("--data-dir")
        .arg(dir)
        .args(["item", "list"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    let status = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break Some(s);
        }
        if std::time::Instant::now() > deadline {
            child.kill().unwrap();
            break None;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    };
    let status = status.expect("the command waited on the lock before prompting");
    assert_eq!(status.code(), Some(1));
    drop(held);
}

/// Whether `bytes` hold the Secret Key `shown`, dashed or bare.
fn holds_key(bytes: &[u8], shown: &str) -> bool {
    let bare: String = shown.chars().filter(|c| *c != '-').collect();
    [shown.to_owned(), bare]
        .iter()
        .any(|form| bytes.windows(form.len()).any(|w| w == form.as_bytes()))
}

fn shown_key(out: &str) -> String {
    out.lines()
        .find_map(|l| l.strip_prefix("Secret Key: "))
        .expect("a Secret Key line")
        .to_owned()
}

fn output(mut c: Command) -> Out {
    let o = c.output().unwrap();
    Out {
        code: o.status.code().unwrap(),
        stdout: String::from_utf8(o.stdout).unwrap(),
        stderr: String::from_utf8(o.stderr).unwrap(),
    }
}

#[test]
fn account_create_keeps_the_secret_key_out_of_device_bin() {
    let t = template();
    assert_eq!(t.account.code, 0, "{}", t.account.stderr);
    let key = shown_key(&t.account.stdout);
    let device = fs::read(t.dir.join("device.bin")).unwrap();
    assert!(!holds_key(&device, &key), "Secret Key found in device.bin");
    let store = PathBuf::from(SECRET_STORE.strip_prefix("dir:").unwrap());
    let in_store = fs::read_dir(&store)
        .unwrap()
        .map(|e| e.unwrap())
        .filter(|e| e.file_name().to_string_lossy().starts_with("secretkey."))
        .any(|e| fs::read_to_string(e.path()).unwrap() == key);
    assert!(in_store, "Secret Key not in the store");
}

#[test]
fn without_a_secret_store_the_key_stays_in_clear_only_by_choice() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("data");

    // No store: refused, nothing left behind.
    let mut c = onepass(&dir, PASSWORD);
    c.env("ONEPASS_DEV_SECRET_STORE", "none")
        .args(["account", "create"]);
    let out = output(c);
    assert_eq!(out.code, 1, "{}", out.stderr);
    assert!(
        out.stderr.contains("--insecure-file-secret-key"),
        "{}",
        out.stderr
    );
    assert!(out.stdout.is_empty());
    assert!(!dir.join("device.bin").exists());
    assert!(!dir.join("vault.sqlite").exists());

    // The explicit choice: the key sits in device.bin, and it is said.
    let mut c = onepass(&dir, PASSWORD);
    c.env("ONEPASS_DEV_SECRET_STORE", "none").args([
        "--insecure-file-secret-key",
        "account",
        "create",
    ]);
    let out = output(c);
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert!(out.stderr.contains("WARNING"), "{}", out.stderr);
    let key = shown_key(&out.stdout);
    assert!(holds_key(&fs::read(dir.join("device.bin")).unwrap(), &key));

    // Still no store, no option: the earlier choice holds, and is said.
    let mut c = onepass(&dir, PASSWORD);
    c.env("ONEPASS_DEV_SECRET_STORE", "none")
        .args(["vault", "list"]);
    let out = output(c);
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert!(out.stderr.contains("WARNING"), "{}", out.stderr);

    // A store appears: the key moves into it at the next unlock.
    let store = tmp.path().join("store");
    let mut c = onepass(&dir, PASSWORD);
    c.env(
        "ONEPASS_DEV_SECRET_STORE",
        format!("dir:{}", store.display()),
    )
    .args(["vault", "list"]);
    let out = output(c);
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert!(out.stderr.contains("moved"), "{}", out.stderr);
    assert!(!out.stderr.contains("WARNING"), "{}", out.stderr);
    assert!(!holds_key(&fs::read(dir.join("device.bin")).unwrap(), &key));
    let entries: Vec<_> = fs::read_dir(&store).unwrap().map(|e| e.unwrap()).collect();
    assert_eq!(entries.len(), 1);
    assert_eq!(fs::read_to_string(entries[0].path()).unwrap(), key);

    // From then on, the store is required: without it, a clear refusal.
    let mut c = onepass(&dir, PASSWORD);
    c.env("ONEPASS_DEV_SECRET_STORE", "none")
        .args(["vault", "list"]);
    let out = output(c);
    assert_eq!(out.code, 1, "{}", out.stderr);
}

// ---------------------------------------------------------------------
// Key rotation v2 (spec 10.8): device keys in device.bin, rotate-keys,
// remove-device, and the states a rotation made elsewhere leaves.
//
// These tests change the Secret Key of their account, so each works on a
// copy of the template directory with a secret store of its own: the shared
// one would change the key of every other test's copy.
// ---------------------------------------------------------------------

use onepass_core::device_keys::{DeviceKeys, DevicePublic};
use onepass_core::devices::{DeviceKind, DeviceMode};
use onepass_core::lineage::{LineageRecord, RosterEntry, RotationReason};
use onepass_core::repo::{DeviceState, Repository, RotateRequest};
use onepass_core::store::{RecordKind, RecordStore, SqliteStore};
use onepass_core::trust::{DeviceLineageState, TrustLevel, TrustState};
use onepass_core::{Id, crypto::SecretKey};

/// A copy of the template account with its own secret store.
struct Rot {
    tmp: tempfile::TempDir,
    key: String,
}

impl Rot {
    fn new() -> Rot {
        let t = template();
        let key = shown_key(&t.account.stdout);
        let tmp = fresh();
        // `fresh` copies the files into the root of the temp dir: move them
        // under `data/`, next to a `secrets/` of this test alone.
        let data = tmp.path().join("data");
        fs::create_dir(&data).unwrap();
        for e in fs::read_dir(tmp.path()).unwrap() {
            let e = e.unwrap();
            if e.file_name() != "data" {
                fs::rename(e.path(), data.join(e.file_name())).unwrap();
            }
        }
        let secrets = tmp.path().join("secrets");
        fs::create_dir(&secrets).unwrap();
        let shared = PathBuf::from(SECRET_STORE.strip_prefix("dir:").unwrap());
        for e in fs::read_dir(shared).unwrap() {
            let p = e.unwrap().path();
            if fs::read_to_string(&p).is_ok_and(|k| k == key) {
                fs::copy(&p, secrets.join(p.file_name().unwrap())).unwrap();
            }
        }
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&data, fs::Permissions::from_mode(0o700)).unwrap();
        Rot { tmp, key }
    }

    fn data(&self) -> PathBuf {
        self.tmp.path().join("data")
    }

    fn secrets(&self) -> PathBuf {
        self.tmp.path().join("secrets")
    }

    fn cmd(&self) -> Command {
        let mut c = onepass(&self.data(), PASSWORD);
        c.env(
            "ONEPASS_DEV_SECRET_STORE",
            format!("dir:{}", self.secrets().display()),
        );
        c
    }

    fn run(&self, args: &[&str]) -> Out {
        let mut c = self.cmd();
        c.args(args);
        output(c)
    }

    fn sqlite(&self) -> PathBuf {
        self.data().join("vault.sqlite")
    }

    fn trust(&self) -> TrustState {
        SqliteStore::open(&self.sqlite())
            .unwrap()
            .trust_state()
            .unwrap()
            .expect("a trust state")
    }

    fn set_trust(&self, trust: &TrustState) {
        let c = rusqlite::Connection::open(self.sqlite()).unwrap();
        c.execute(
            "UPDATE meta SET value = ?1 WHERE key = 'trust'",
            rusqlite::params![trust.encode()],
        )
        .unwrap();
    }

    /// The secret store entries of the account (Secret Key, pending key).
    fn store_entries(&self) -> Vec<(String, String)> {
        let mut v: Vec<_> = fs::read_dir(self.secrets())
            .unwrap()
            .map(|e| e.unwrap().path())
            .map(|p| {
                (
                    p.file_name().unwrap().to_string_lossy().into_owned(),
                    fs::read_to_string(&p).unwrap(),
                )
            })
            .collect();
        v.sort();
        v
    }
}

/// Another device of the account, with keys the test holds.
struct Other {
    keys: DeviceKeys,
    public: DevicePublic,
}

fn other_device(name: &str) -> (Other, RosterEntry) {
    let keys = DeviceKeys::generate_software().unwrap();
    let public = keys.public(Id::new()).unwrap();
    let entry = RosterEntry {
        device_id: public.device_id,
        sign_pub: public.sign_pub.clone(),
        kem_pub: public.kem_pub.clone(),
        name: name.to_owned(),
        kind: DeviceKind::Phone,
        mode: DeviceMode::Personal,
        introduced_by: None,
    };
    (Other { keys, public }, entry)
}

/// Pin `entry` in the roster of the CLI's account, as a pairing or a
/// migration would have.
fn trust_device(rot: &Rot, entry: &RosterEntry, level: TrustLevel) {
    let mut t = rot.trust();
    t.roster.push(entry.clone());
    t.roster.sort_by_key(|e| e.device_id);
    t.levels.insert(entry.device_id, level);
    rot.set_trust(&t);
}

#[test]
fn a_new_account_keeps_its_device_keys_in_device_bin() {
    use serde::Deserialize;
    // device.bin version 4: state, where the Secret Key is, the device keys
    // (classical bytes, software post-quantum half), no pending key.
    #[derive(Deserialize)]
    enum KeyAt {
        Store { _account_id: [u8; 16] },
        File { _secret_key: String },
    }
    #[derive(Deserialize)]
    struct Blob {
        classical: Vec<u8>,
        pq: Vec<u8>,
    }
    #[derive(Deserialize)]
    struct File {
        _state: Vec<u8>,
        _key: KeyAt,
        device: Option<Blob>,
        pending: Option<u8>,
    }
    let rot = Rot::new();
    let path = rot.data().join("device.bin");
    let bytes = fs::read(&path).unwrap();
    let body = bytes.strip_prefix(b"ODF\x04").expect("version 4 header");
    let (file, rest) = postcard::take_from_bytes::<File>(body).unwrap();
    assert!(rest.is_empty());
    assert!(file.pending.is_none());
    let blob = file.device.expect("device keys in device.bin");
    assert_eq!(
        blob.classical.len(),
        65,
        "version, Ed25519 seed, X25519 secret"
    );
    assert_eq!(
        blob.pq.len(),
        32 + 3168,
        "ML-DSA seed, ML-KEM decapsulation key"
    );
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    // They are the keys the account's genesis was signed with.
    let trust = rot.trust();
    let pq = onepass_core::device_keys::SoftwarePqHalf::from_bytes(&blob.pq).unwrap();
    let keys = DeviceKeys::new(&blob.classical, Box::new(pq)).unwrap();
    assert_eq!(keys.public(trust.me.device_id).unwrap(), trust.me);
    assert_eq!(trust.roster.len(), 1);
    assert_eq!(trust.head.generation, 0);
    assert_eq!(trust.state, DeviceLineageState::Current);
    let genesis = SqliteStore::open(&rot.sqlite())
        .unwrap()
        .list(RecordKind::Lineage)
        .unwrap();
    assert_eq!(genesis.len(), 1);
    assert!(matches!(
        LineageRecord::decode(&genesis[0].data).unwrap(),
        LineageRecord::Genesis(_)
    ));
}

/// The numbers of an output line, `Rotation code: 123456`.
fn rotation_code(out: &str) -> String {
    out.lines()
        .find_map(|l| l.strip_prefix("Rotation code: "))
        .expect("a rotation code line")
        .to_owned()
}

fn kit_path(out: &str) -> PathBuf {
    PathBuf::from(
        out.lines()
            .find_map(|l| l.strip_prefix("Emergency Kit: "))
            .expect("an Emergency Kit line"),
    )
}

#[test]
fn rotate_keys_writes_the_kit_and_prints_the_code() {
    let rot = Rot::new();
    let old_key = rot.key.clone();
    let out = rot.run(&["account", "rotate-keys"]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    let code = rotation_code(&out.stdout);
    assert_eq!(code.len(), 6);
    assert!(code.chars().all(|c| c.is_ascii_digit()));
    let kit = kit_path(&out.stdout);
    assert!(kit.starts_with(rot.data()) && kit.is_file(), "{kit:?}");
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&kit).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    // The new Secret Key is in the kit and in the store; the old one is in
    // neither; the Secret Key never goes to stdout or stderr.
    let text = fs::read_to_string(&kit).unwrap();
    let new_key = text
        .lines()
        .find_map(|l| l.strip_prefix("Secret Key: "))
        .expect("a Secret Key line in the kit")
        .to_owned();
    assert_ne!(new_key, old_key);
    assert!(!holds_key(text.as_bytes(), &old_key));
    for stream in [&out.stdout, &out.stderr] {
        assert!(!holds_key(stream.as_bytes(), &new_key), "{stream}");
        assert!(!holds_key(stream.as_bytes(), &old_key), "{stream}");
    }
    let entries = rot.store_entries();
    assert_eq!(entries.len(), 1, "no pending entry left: {entries:?}");
    assert_eq!(entries[0].1, new_key);
    assert!(!holds_key(
        &fs::read(rot.data().join("device.bin")).unwrap(),
        &new_key
    ));
    // The account opens with the new keys and still holds its items.
    let read = rot.run(&["read", "onepass://Personnel/GitHub/password"]);
    assert_eq!(read.code, 0, "{}", read.stderr);
    assert_eq!(read.stdout, "hunter2");
    // One rotation: generation 1, the head moved, this device is Current.
    let trust = rot.trust();
    assert_eq!(trust.head.generation, 1);
    assert_eq!(trust.state, DeviceLineageState::Current);
    // A second rotation works the same way (and the kit is never overwritten).
    let again = rot.run(&["account", "rotate-keys"]);
    assert_eq!(again.code, 0, "{}", again.stderr);
    assert_ne!(kit_path(&again.stdout), kit);
    assert_eq!(rot.trust().head.generation, 2);
    let read = rot.run(&["read", "onepass://Personnel/GitHub/password"]);
    assert_eq!(read.stdout, "hunter2");
}

#[test]
fn rotate_keys_json_and_explicit_kit_path() {
    let rot = Rot::new();
    let kit = rot.tmp.path().join("kit.txt");
    let kit_arg = kit.to_str().unwrap();
    let out = rot.run(&["--json", "account", "rotate-keys", "--kit-path", kit_arg]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    let v: serde_json::Value = serde_json::from_str(out.stdout.trim()).unwrap();
    assert_eq!(v["emergency_kit"], kit_arg);
    assert_eq!(v["rotation_code"].as_str().unwrap().len(), 6);
    assert!(kit.is_file());
    // Never over an existing file, nor into a missing folder: the refusal
    // happens before anything changes (generation, Secret Key, kit file).
    let generation = rot.trust().head.generation;
    let entries = rot.store_entries();
    let missing = format!("{}/missing/kit.txt", rot.tmp.path().display());
    for bad in [kit_arg, missing.as_str()] {
        let again = rot.run(&["account", "rotate-keys", "--kit-path", bad]);
        assert_eq!(again.code, 1, "{}", again.stderr);
        assert!(
            again.stderr.contains("nothing was changed"),
            "{}",
            again.stderr
        );
        assert_eq!(rot.trust().head.generation, generation);
        assert_eq!(rot.store_entries(), entries);
    }
    assert!(fs::read_to_string(&kit).unwrap().contains("Secret Key: "));
}

#[test]
fn a_wrong_password_rotates_nothing() {
    let rot = Rot::new();
    let mut c = rot.cmd();
    c.env("ONEPASS_PASSWORD", "not the password")
        .args(["account", "rotate-keys"]);
    let out = output(c);
    assert_eq!(out.code, 2, "{}", out.stderr);
    assert_eq!(rot.trust().head.generation, 0);
    assert_eq!(rot.store_entries().len(), 1);
}

#[test]
fn remove_device_rotates_with_reason_revoke() {
    let rot = Rot::new();
    let (other, entry) = other_device("iPhone de test");
    trust_device(&rot, &entry, TrustLevel::Verified);
    let listed = rot.run(&["account", "devices"]);
    assert_eq!(listed.code, 0, "{}", listed.stderr);
    assert!(listed.stdout.contains(&other.public.device_id.to_string()));
    assert!(listed.stdout.contains("iPhone de test"));
    assert!(listed.stdout.contains("(this device)"));
    assert_eq!(listed.stdout.lines().count(), 2);

    let id = other.public.device_id.to_string();
    let out = rot.run(&["account", "remove-device", &id]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    let kit = kit_path(&out.stdout);
    assert!(kit.is_file());
    assert_eq!(rotation_code(&out.stdout).len(), 6);

    // The removal is a rotation record with reason Revoke, never the list
    // revocation of milestone 2b.
    let trust = rot.trust();
    assert!(trust.revoked.contains(&other.public.device_id));
    assert!(
        !trust
            .roster
            .iter()
            .any(|e| e.device_id == other.public.device_id)
    );
    assert_eq!(trust.head.generation, 1);
    let records = SqliteStore::open(&rot.sqlite())
        .unwrap()
        .list(RecordKind::Lineage)
        .unwrap();
    let reasons: Vec<RotationReason> = records
        .iter()
        .filter_map(|r| match LineageRecord::decode(&r.data).unwrap() {
            LineageRecord::Rotation(s) => Some(s.body.reason),
            LineageRecord::Genesis(_) => None,
        })
        .collect();
    assert_eq!(reasons, vec![RotationReason::Revoke]);
    let after = rot.run(&["account", "devices"]);
    assert_eq!(after.stdout.lines().count(), 1);
    let read = rot.run(&["read", "onepass://Personnel/GitHub/password"]);
    assert_eq!(read.stdout, "hunter2");
}

#[test]
fn remove_device_refuses_unknown_and_own_ids() {
    let rot = Rot::new();
    let unknown = Id::new().to_string();
    let out = rot.run(&["account", "remove-device", &unknown]);
    assert_eq!(out.code, 1);
    assert!(
        out.stderr.contains("not a device of this account"),
        "{}",
        out.stderr
    );
    let me = rot.trust().me.device_id.to_string();
    let out = rot.run(&["account", "remove-device", &me]);
    assert_eq!(out.code, 1);
    assert!(
        out.stderr.contains("cannot remove itself"),
        "{}",
        out.stderr
    );
    let out = rot.run(&["account", "remove-device", "not-an-id"]);
    assert_eq!(out.code, 1);
    assert_eq!(rot.trust().head.generation, 0);
    assert_eq!(rot.store_entries().len(), 1);
}

#[test]
fn unverified_devices_are_kept_only_by_explicit_confirmation() {
    let rot = Rot::new();
    let (a, entry_a) = other_device("Legacy A");
    let (b, entry_b) = other_device("Legacy B");
    trust_device(&rot, &entry_a, TrustLevel::Tofu);
    trust_device(&rot, &entry_b, TrustLevel::Tofu);
    let listed = rot.run(&["account", "devices"]);
    assert_eq!(
        listed.stdout.matches("unverified").count(),
        2,
        "{}",
        listed.stdout
    );

    // Not a tofu device (or not a device at all): refused, nothing written.
    let me = rot.trust().me.device_id.to_string();
    for bad in [me, Id::new().to_string()] {
        let out = rot.run(&["account", "rotate-keys", "--keep-tofu", &bad]);
        assert_eq!(out.code, 1);
        assert!(
            out.stderr.contains("not an unverified device"),
            "{}",
            out.stderr
        );
    }
    assert_eq!(rot.trust().head.generation, 0);

    // One kept by flag, the other dropped and said so.
    let id_a = a.public.device_id.to_string();
    let out = rot.run(&["account", "rotate-keys", "--keep-tofu", &id_a]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert!(out.stderr.contains("Legacy B"), "{}", out.stderr);
    let trust = rot.trust();
    let ids: Vec<Id> = trust.roster.iter().map(|e| e.device_id).collect();
    assert!(ids.contains(&a.public.device_id));
    assert!(!ids.contains(&b.public.device_id));

    // No flag and no terminal: none is kept, and it is said.
    let out = rot.run(&["account", "rotate-keys"]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert!(out.stderr.contains("No terminal"), "{}", out.stderr);
    let trust = rot.trust();
    assert!(
        !trust
            .roster
            .iter()
            .any(|e| e.device_id == a.public.device_id)
    );
}

/// How the rotation made elsewhere treats the CLI's device.
#[derive(Clone, Copy, PartialEq)]
enum Fate {
    Keeps,
    Revokes,
    Drops,
}

/// Another device of the account rotates the keys and the CLI fetches what
/// it wrote: the other device is a copy of the store, with its own device
/// keys pinned as `me`, rotating through the core, and every record the CLI
/// has not got yet goes into its store (a fetch, minus the rows a sync
/// keeps aside).
fn rotated_elsewhere(rot: &Rot, fate: Fate) -> Other {
    let (other, entry) = other_device("iPhone de test");
    trust_device(rot, &entry, TrustLevel::Verified);
    let cli = rot.trust();

    let there = rot.tmp.path().join("there");
    fs::create_dir(&there).unwrap();
    let there_db = there.join("vault.sqlite");
    fs::copy(rot.sqlite(), &there_db).unwrap();
    {
        let c = rusqlite::Connection::open(&there_db).unwrap();
        // Same chain state (the other device is another process on a copy).
        let mut t = cli.clone();
        t.me = other.public.clone();
        if fate == Fate::Drops {
            // The other device only trusts the CLI on first use: its
            // rotation keeps no unverified device unless asked to.
            t.levels.insert(cli.me.device_id, TrustLevel::Tofu);
        }
        c.execute(
            "UPDATE meta SET value = ?1 WHERE key = 'trust'",
            rusqlite::params![t.encode()],
        )
        .unwrap();
        c.execute("DELETE FROM meta WHERE key = 'chain'", [])
            .unwrap();
    }
    let key = SecretKey::parse(&rot.key).unwrap();
    let next = SecretKey::generate().unwrap();
    let store = SqliteStore::open(&there_db).unwrap();
    let mut repo = Repository::unlock(store, PASSWORD, &key, DeviceState::default()).unwrap();
    let (revoke, reason) = match fate {
        Fate::Revokes => (vec![cli.me.device_id], RotationReason::Revoke),
        _ => (Vec::new(), RotationReason::Rotate),
    };
    repo.rotate(RotateRequest {
        revoke,
        new_password: None,
        password: PASSWORD,
        secret_key: &key,
        new_secret_key: &next,
        device_keys: &other.keys,
        reason,
        keep_tofu: &[],
    })
    .unwrap();
    drop(repo);

    let c = rusqlite::Connection::open(rot.sqlite()).unwrap();
    c.execute("ATTACH DATABASE ?1 AS there", [there_db.to_str().unwrap()])
        .unwrap();
    // The records a rotation adds under new ids (the lineage, the
    // deliveries, the params, keyset and lists of the new identity): not
    // the vault content, which a sync keeps aside until the device follows.
    c.execute(
        "INSERT OR IGNORE INTO records SELECT kind, id, version, data FROM there.records
         WHERE kind IN (1, 2, 7, 8, 9, 10, 11, 12)",
        [],
    )
    .unwrap();
    other
}

#[test]
fn a_rotation_waiting_makes_the_cli_read_only_and_names_the_emergency_kit() {
    let rot = Rot::new();
    rotated_elsewhere(&rot, Fate::Keeps);
    // Reads go on with the keys this device still holds...
    let read = rot.run(&["read", "onepass://Personnel/GitHub/password"]);
    assert_eq!(read.code, 0, "{}", read.stderr);
    assert_eq!(read.stdout, "hunter2");
    assert!(read.stderr.contains("read only"), "{}", read.stderr);
    // ...writes are refused, with the way out.
    let write = rot.run(&[
        "item",
        "create",
        "login",
        "--title",
        "Nope",
        "--field",
        "username=x",
    ]);
    assert_eq!(write.code, 1, "{}", write.stderr);
    assert!(write.stderr.contains("Emergency Kit"), "{}", write.stderr);
    assert!(write.stderr.contains("not-me"), "{}", write.stderr);
    // Rotating from this device is refused too.
    let rotate = rot.run(&["account", "rotate-keys"]);
    assert_eq!(rotate.code, 1, "{}", rotate.stderr);
    assert!(rotate.stderr.contains("Emergency Kit"), "{}", rotate.stderr);
    assert_eq!(rot.store_entries().len(), 1, "no pending key left behind");
    // "Ce n'etait pas moi": the rotation is ignored, writes work again.
    let answer = rot.run(&["account", "not-me"]);
    assert_eq!(answer.code, 0, "{}", answer.stderr);
    let write = rot.run(&[
        "item",
        "create",
        "login",
        "--title",
        "Back",
        "--field",
        "username=x",
    ]);
    assert_eq!(write.code, 0, "{}", write.stderr);
}

#[test]
fn a_device_left_behind_reads_and_refuses_writes() {
    let rot = Rot::new();
    rotated_elsewhere(&rot, Fate::Drops);
    let read = rot.run(&["read", "onepass://Personnel/GitHub/password"]);
    assert_eq!(read.code, 0, "{}", read.stderr);
    assert_eq!(read.stdout, "hunter2");
    assert!(
        read.stderr.contains("left this device behind"),
        "{}",
        read.stderr
    );
    let write = rot.run(&[
        "item",
        "create",
        "login",
        "--title",
        "Nope",
        "--field",
        "username=x",
    ]);
    assert_eq!(write.code, 1, "{}", write.stderr);
    assert!(write.stderr.contains("Emergency Kit"), "{}", write.stderr);
    // It never erases: a left-behind device has no clock.
    assert!(matches!(
        rot.trust().state,
        DeviceLineageState::Orphaned { .. }
    ));
    let answer = rot.run(&["account", "not-me"]);
    assert_eq!(answer.code, 0, "{}", answer.stderr);
    let write = rot.run(&[
        "item",
        "create",
        "login",
        "--title",
        "Back",
        "--field",
        "username=x",
    ]);
    assert_eq!(write.code, 0, "{}", write.stderr);
}

#[test]
fn a_quarantined_cli_shows_the_erase_date_and_can_answer_not_me() {
    let rot = Rot::new();
    let other = rotated_elsewhere(&rot, Fate::Revokes);
    let before = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let read = rot.run(&["read", "onepass://Personnel/GitHub/password"]);
    assert_eq!(read.code, 1, "{}", read.stderr);
    assert!(read.stdout.is_empty());
    assert!(read.stderr.contains("erases itself on"), "{}", read.stderr);
    assert!(read.stderr.contains("not-me"), "{}", read.stderr);
    let since = match rot.trust().state {
        DeviceLineageState::Quarantined { since, rotator, .. } => {
            assert_eq!(rotator, other.public.device_id);
            since
        }
        s => panic!("expected a quarantine, got {s:?}"),
    };
    assert!(since >= before && since <= before + 600);
    // The date shown is `since` + 7 days.
    let erase =
        time::OffsetDateTime::from_unix_timestamp(i64::try_from(since + 7 * 86_400).unwrap())
            .unwrap();
    assert!(
        read.stderr.contains(&format!(
            "{:04}-{:02}-{:02}",
            erase.year(),
            u8::from(erase.month()),
            erase.day()
        )),
        "{}",
        read.stderr
    );
    // The answer needs the master password...
    let mut c = rot.cmd();
    c.env("ONEPASS_PASSWORD", "wrong")
        .args(["account", "not-me"]);
    assert_eq!(output(c).code, 2);
    assert!(matches!(
        rot.trust().state,
        DeviceLineageState::Quarantined { .. }
    ));
    // ...and cancels the erase: the device opens again.
    let answer = rot.run(&["account", "not-me"]);
    assert_eq!(answer.code, 0, "{}", answer.stderr);
    let read = rot.run(&["read", "onepass://Personnel/GitHub/password"]);
    assert_eq!(read.code, 0, "{}", read.stderr);
    assert_eq!(read.stdout, "hunter2");
    assert!(rot.trust().excluded.contains(&other.public.device_id));
}

#[test]
fn a_quarantined_cli_erases_itself_after_seven_days() {
    let rot = Rot::new();
    rotated_elsewhere(&rot, Fate::Revokes);
    // First sight: locked, not erased.
    assert_eq!(rot.run(&["vault", "list"]).code, 1);
    let mut t = rot.trust();
    let DeviceLineageState::Quarantined {
        by,
        rotator,
        resume,
        ..
    } = t.state.clone()
    else {
        panic!("expected a quarantine");
    };
    // A clock moved to 6 days: still waiting.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    t.state = DeviceLineageState::Quarantined {
        by,
        rotator,
        since: now - 6 * 86_400,
        resume,
    };
    rot.set_trust(&t);
    let out = rot.run(&["vault", "list"]);
    assert_eq!(out.code, 1);
    assert!(out.stderr.contains("erases itself on"), "{}", out.stderr);
    assert!(rot.data().join("device.bin").exists());
    // 8 days: it erases itself, and the secrets go with it.
    t.state = DeviceLineageState::Quarantined {
        by,
        rotator,
        since: now - 8 * 86_400,
        resume,
    };
    rot.set_trust(&t);
    let out = rot.run(&["vault", "list"]);
    assert_eq!(out.code, 1);
    assert!(out.stderr.contains("erased itself"), "{}", out.stderr);
    assert!(!rot.data().join("device.bin").exists());
    assert!(rot.store_entries().is_empty(), "{:?}", rot.store_entries());
    let c = rusqlite::Connection::open(rot.sqlite()).unwrap();
    let rows: i64 = c
        .query_row("SELECT count(*) FROM records", [], |r| r.get(0))
        .unwrap();
    assert_eq!(rows, 0);
    // The next command finds no account at all.
    let out = rot.run(&["vault", "list"]);
    assert_eq!(out.code, 1);
    assert!(out.stderr.contains("no account"), "{}", out.stderr);
}

#[test]
fn a_late_not_me_does_not_save_an_expired_quarantine() {
    let rot = Rot::new();
    rotated_elsewhere(&rot, Fate::Revokes);
    assert_eq!(rot.run(&["vault", "list"]).code, 1);
    let mut t = rot.trust();
    let DeviceLineageState::Quarantined {
        by,
        rotator,
        resume,
        ..
    } = t.state.clone()
    else {
        panic!("expected a quarantine");
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    t.state = DeviceLineageState::Quarantined {
        by,
        rotator,
        since: now - 8 * 86_400,
        resume,
    };
    rot.set_trust(&t);
    let out = rot.run(&["account", "not-me"]);
    assert_eq!(out.code, 1);
    assert!(out.stderr.contains("erased itself"), "{}", out.stderr);
    assert!(!rot.data().join("device.bin").exists());
}

#[test]
fn not_me_without_anything_to_answer_is_refused() {
    let rot = Rot::new();
    let out = rot.run(&["account", "not-me"]);
    assert_eq!(out.code, 1);
    assert!(out.stderr.contains("nothing to answer"), "{}", out.stderr);
}

#[test]
fn an_older_device_bin_opens_and_gains_device_keys() {
    // An account made before key rotation v2: no trust state in the store,
    // a device.bin without device keys (version 3).
    let rot = Rot::new();
    let c = rusqlite::Connection::open(rot.sqlite()).unwrap();
    c.execute_batch(
        "DELETE FROM meta WHERE key IN ('trust', 'chain');
         DELETE FROM records WHERE kind IN (10, 11, 12);",
    )
    .unwrap();
    drop(c);
    // Back to a generation 0 device list: an old CLI never registered itself.
    // (The signed device list written at creation stays: it is a valid list
    // a legacy device may find.)
    let bytes = fs::read(rot.data().join("device.bin")).unwrap();
    let body = bytes.strip_prefix(b"ODF\x04").unwrap();
    #[derive(serde::Deserialize, serde::Serialize)]
    enum KeyAt {
        Store { account_id: [u8; 16] },
        File { secret_key: String },
    }
    #[derive(serde::Deserialize)]
    struct Blob {
        _classical: Vec<u8>,
        _pq: Vec<u8>,
    }
    #[derive(serde::Deserialize)]
    struct V4 {
        state: Vec<u8>,
        key: KeyAt,
        _device: Option<Blob>,
        _pending: Option<u8>,
    }
    #[derive(serde::Serialize)]
    struct V3 {
        state: Vec<u8>,
        key: KeyAt,
    }
    let (v4, _) = postcard::take_from_bytes::<V4>(body).unwrap();
    let mut v3 = b"ODF\x03".to_vec();
    v3.extend(
        postcard::to_allocvec(&V3 {
            state: v4.state,
            key: v4.key,
        })
        .unwrap(),
    );
    fs::write(rot.data().join("device.bin"), v3).unwrap();

    let read = rot.run(&["read", "onepass://Personnel/GitHub/password"]);
    assert_eq!(read.code, 0, "{}", read.stderr);
    assert_eq!(read.stdout, "hunter2");
    assert!(read.stderr.contains("device keys"), "{}", read.stderr);
    // device.bin is version 4 now, with the keys; the genesis is signed by
    // them, and the device can rotate.
    let bytes = fs::read(rot.data().join("device.bin")).unwrap();
    assert!(bytes.starts_with(b"ODF\x04"));
    let trust = rot.trust();
    assert_eq!(trust.head.generation, 0);
    assert_eq!(trust.state, DeviceLineageState::Current);
    let out = rot.run(&["account", "rotate-keys"]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert_eq!(rot.trust().head.generation, 1);
    let read = rot.run(&["read", "onepass://Personnel/GitHub/password"]);
    assert_eq!(read.stdout, "hunter2");
}
