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
        let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("cli-template");
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
