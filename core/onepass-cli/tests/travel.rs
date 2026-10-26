//! End-to-end tests of `onepass travel`: the real binary, with a SQLite
//! file as the upstream.
//!
//! The account (vault `Voyage` with `--travel-safe` and the default `Personnel`, one
//! item in each) is created once in a template directory; every test works
//! on its own copy.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use assert_cmd::Command;

const PASSWORD: &str = "correct horse battery";

struct Out {
    code: i32,
    stdout: String,
    stderr: String,
}

fn onepass(dir: &Path) -> Command {
    let mut c = Command::cargo_bin("onepass").unwrap();
    c.env("ONEPASS_DEV_ALLOW_ENV_PASSWORD", "1")
        .env("ONEPASS_PASSWORD", PASSWORD)
        .env("ONEPASS_DEV_FAST_KDF", "1")
        .arg("--data-dir")
        .arg(dir);
    c
}

fn run(dir: &Path, args: &[&str]) -> Out {
    let o = onepass(dir).args(args).output().unwrap();
    Out {
        code: o.status.code().unwrap(),
        stdout: String::from_utf8(o.stdout).unwrap(),
        stderr: String::from_utf8(o.stderr).unwrap(),
    }
}

fn ok(dir: &Path, args: &[&str]) -> Out {
    let o = run(dir, args);
    assert_eq!(o.code, 0, "{args:?}: {}", o.stderr);
    o
}

fn add_item(dir: &Path, vault: &str, title: &str) {
    ok(
        dir,
        &[
            "item",
            "create",
            "login",
            "--title",
            title,
            "--vault",
            vault,
            "--field",
            "username=u",
        ],
    );
}

fn template() -> &'static PathBuf {
    static T: OnceLock<PathBuf> = OnceLock::new();
    T.get_or_init(|| {
        let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("travel-template");
        let _ = fs::remove_dir_all(&dir);
        ok(&dir, &["account", "create"]);
        ok(&dir, &["vault", "create", "Voyage", "--travel-safe"]);
        add_item(&dir, "Voyage", "BoardingPass");
        add_item(&dir, "Personnel", "BankLogin");
        dir
    })
}

fn fresh() -> tempfile::TempDir {
    let t = template();
    let tmp = tempfile::tempdir().unwrap();
    for entry in fs::read_dir(t).unwrap() {
        let entry = entry.unwrap();
        fs::copy(entry.path(), tmp.path().join(entry.file_name())).unwrap();
    }
    tmp
}

fn upstream(tmp: &tempfile::TempDir) -> String {
    tmp.path()
        .join("upstream")
        .join("up.sqlite")
        .display()
        .to_string()
}

fn prep_upstream_dir(tmp: &tempfile::TempDir) {
    fs::create_dir_all(tmp.path().join("upstream")).unwrap();
}

fn items(dir: &Path) -> String {
    ok(dir, &["item", "list"]).stdout
}

#[test]
fn travel_roundtrip() {
    let tmp = fresh();
    let d = tmp.path();
    prep_upstream_dir(&tmp);
    let up = upstream(&tmp);
    assert_eq!(
        ok(d, &["travel", "status"]).stdout.trim(),
        "travel mode: off"
    );
    ok(d, &["travel", "push", "--upstream", &up]);
    use std::os::unix::fs::PermissionsExt;
    let mode = fs::metadata(&up).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    let on = ok(d, &["travel", "on", "--upstream", &up]);
    assert!(on.stdout.contains("1 vault"), "{}", on.stdout);
    let list = items(d);
    assert!(!list.contains("BankLogin"), "{list}");
    assert!(list.contains("BoardingPass"), "{list}");
    let mode = fs::metadata(d.join("travel.bin"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600);
    let status = ok(d, &["travel", "status"]).stdout;
    assert!(
        status.starts_with("travel mode: on (1 vaults hidden since "),
        "{status}"
    );
    ok(d, &["travel", "off", "--upstream", &up]);
    assert!(!d.join("travel.bin").exists());
    assert!(items(d).contains("BankLogin"));
    assert_eq!(
        ok(d, &["travel", "status"]).stdout.trim(),
        "travel mode: off"
    );
}

#[test]
fn travel_on_refuses_missing_upstream_file() {
    let tmp = fresh();
    let d = tmp.path();
    prep_upstream_dir(&tmp);
    let up = upstream(&tmp);
    let before = items(d);
    let o = run(d, &["travel", "on", "--upstream", &up]);
    assert_ne!(o.code, 0);
    assert_eq!(items(d), before);
    assert!(!d.join("travel.bin").exists());
}

#[test]
fn travel_off_refuses_replayed_upstream() {
    let tmp = fresh();
    let d = tmp.path();
    prep_upstream_dir(&tmp);
    let up = upstream(&tmp);
    ok(d, &["travel", "push", "--upstream", &up]);
    let old = fs::read(&up).unwrap();
    add_item(d, "Personnel", "Newer");
    ok(d, &["travel", "push", "--upstream", &up]);
    let recent = fs::read(&up).unwrap();
    ok(d, &["travel", "on", "--upstream", &up]);
    fs::write(&up, &old).unwrap();
    let o = run(d, &["travel", "off", "--upstream", &up]);
    assert_eq!(o.code, 3, "{}", o.stderr);
    assert!(d.join("travel.bin").exists());
    assert!(
        ok(d, &["travel", "status"])
            .stdout
            .contains("travel mode: on")
    );
    fs::write(&up, &recent).unwrap();
    ok(d, &["travel", "off", "--upstream", &up]);
    let list = items(d);
    assert!(
        list.contains("Newer") && list.contains("BankLogin"),
        "{list}"
    );
}

#[test]
fn travel_bin_tampered_refused() {
    let tmp = fresh();
    let d = tmp.path();
    prep_upstream_dir(&tmp);
    let up = upstream(&tmp);
    ok(d, &["travel", "push", "--upstream", &up]);
    ok(d, &["travel", "on", "--upstream", &up]);
    let mut bytes = fs::read(d.join("travel.bin")).unwrap();
    assert_eq!(
        bytes.len(),
        onepass_core::repo::travel::SEALED_TRAVEL_STATE_LEN
    );
    bytes[100] ^= 1;
    fs::write(d.join("travel.bin"), &bytes).unwrap();
    let o = run(d, &["travel", "off", "--upstream", &up]);
    assert_eq!(o.code, 3, "{}", o.stderr);
    assert!(d.join("travel.bin").exists());
}

#[test]
fn travel_off_without_state_needs_flag() {
    let tmp = fresh();
    let d = tmp.path();
    prep_upstream_dir(&tmp);
    let up = upstream(&tmp);
    ok(d, &["travel", "push", "--upstream", &up]);
    ok(d, &["travel", "on", "--upstream", &up]);
    fs::remove_file(d.join("travel.bin")).unwrap();
    let o = run(d, &["travel", "off", "--upstream", &up]);
    assert_ne!(o.code, 0);
    assert!(o.stderr.contains("--accept-unpinned"), "{}", o.stderr);
    assert!(!items(d).contains("BankLogin"));
    ok(
        d,
        &["travel", "off", "--upstream", &up, "--accept-unpinned"],
    );
    assert!(items(d).contains("BankLogin"));
}

/// The sqlite files (store and WAL) of a data directory, concatenated.
fn store_bytes(d: &Path) -> Vec<u8> {
    let mut all = Vec::new();
    for name in ["vault.sqlite", "vault.sqlite-wal"] {
        if let Ok(b) = fs::read(d.join(name)) {
            all.extend(b);
        }
    }
    all
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn hidden_vault_bytes_gone_from_sqlite_file() {
    let tmp = fresh();
    let d = tmp.path();
    prep_upstream_dir(&tmp);
    let up = upstream(&tmp);
    ok(d, &["travel", "push", "--upstream", &up]);
    // The wrapped key of the hidden vault (the kind code of VaultKey is 3),
    // as the upstream holds it.
    let conn = rusqlite::Connection::open(&up).unwrap();
    let mut stmt = conn.prepare("SELECT kind, data FROM records").unwrap();
    let rows: Vec<(i64, Vec<u8>)> = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    drop(stmt);
    drop(conn);
    let keys: Vec<&Vec<u8>> = rows
        .iter()
        .filter(|(k, _)| *k == 3)
        .map(|(_, d)| d)
        .collect();
    assert_eq!(keys.len(), 2, "two vault keys");
    let before = store_bytes(d);
    for k in &keys {
        assert!(contains(&before, k), "key present before");
    }
    ok(d, &["travel", "on", "--upstream", &up]);
    let after = store_bytes(d);
    let gone = keys.iter().filter(|k| !contains(&after, k)).count();
    assert_eq!(gone, 1, "exactly the hidden vault key is gone");
}

/// `last_seen` of `device.bin`, decoded like `session.rs` does.
fn last_seen(
    dir: &Path,
) -> std::collections::BTreeMap<onepass_core::Id, onepass_core::manifest::SeenManifest> {
    #[derive(serde::Deserialize)]
    struct DeviceFile {
        #[allow(dead_code)]
        secret_key: String,
        state: onepass_core::repo::DeviceState,
    }
    let bytes = fs::read(dir.join("device.bin")).unwrap();
    let file: DeviceFile = postcard::from_bytes(&bytes).unwrap();
    file.state.last_seen
}

#[test]
fn travel_on_refuses_altered_upstream_record() {
    let tmp = fresh();
    let d = tmp.path();
    prep_upstream_dir(&tmp);
    let up = upstream(&tmp);
    ok(d, &["travel", "push", "--upstream", &up]);
    let conn = rusqlite::Connection::open(&up).unwrap();
    // Kind 5 is Item: alter the last created item (Personnel's).
    let n = conn
        .execute(
            "UPDATE records SET data = CAST(data || x'00' AS BLOB) WHERE kind = 5 AND rowid = (SELECT max(rowid) FROM records WHERE kind = 5)",
            [],
        )
        .unwrap();
    assert_eq!(n, 1);
    drop(conn);
    let before = items(d);
    let o = run(d, &["travel", "on", "--upstream", &up]);
    assert_eq!(o.code, 1, "{}", o.stderr);
    assert_eq!(items(d), before);
    assert!(!d.join("travel.bin").exists());
}

#[test]
fn travel_on_restores_everything_when_travel_bin_cannot_be_written() {
    let tmp = fresh();
    let d = tmp.path();
    prep_upstream_dir(&tmp);
    let up = upstream(&tmp);
    ok(d, &["travel", "push", "--upstream", &up]);
    let pins = last_seen(d);
    // A directory where the temporary file goes: the write fails.
    fs::create_dir(d.join("travel.bin.tmp")).unwrap();
    let o = run(d, &["travel", "on", "--upstream", &up]);
    assert_ne!(o.code, 0);
    assert!(items(d).contains("BankLogin"));
    assert!(!d.join("travel.bin").exists());
    assert_eq!(last_seen(d), pins, "pins are back in device.bin");
}

#[test]
fn travel_on_again_only_compacts() {
    let tmp = fresh();
    let d = tmp.path();
    prep_upstream_dir(&tmp);
    let up = upstream(&tmp);
    ok(d, &["travel", "push", "--upstream", &up]);
    ok(d, &["travel", "on", "--upstream", &up]);
    let o = ok(d, &["travel", "on", "--upstream", &up]);
    assert!(o.stdout.contains("already on; local database compacted"));
    assert!(!items(d).contains("BankLogin"));
}

#[test]
fn push_never_deletes_upstream_records() {
    let tmp = fresh();
    let d = tmp.path();
    prep_upstream_dir(&tmp);
    let up = upstream(&tmp);
    ok(d, &["travel", "push", "--upstream", &up]);
    let count = |p: &str| -> i64 {
        rusqlite::Connection::open(p)
            .unwrap()
            .query_row("SELECT count(*) FROM records WHERE kind = 5", [], |r| {
                r.get(0)
            })
            .unwrap()
    };
    let before = count(&up);
    assert_eq!(before, 2);
    let local = rusqlite::Connection::open(d.join("vault.sqlite")).unwrap();
    local
        .execute(
            "DELETE FROM records WHERE rowid = (SELECT min(rowid) FROM records WHERE kind = 5)",
            [],
        )
        .unwrap();
    drop(local);
    ok(d, &["travel", "push", "--upstream", &up]);
    assert_eq!(count(&up), before);
}
