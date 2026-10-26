//! End-to-end tests of `onepass import` and `onepass export` (milestone 5).
//!
//! Same harness as `tests/cli.rs`: the account is created once in a
//! template directory (SLH-DSA signing is slow in a debug build) and every
//! test works on its own copy. Import fixtures are the synthetic ones of
//! `onepass-core`.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use assert_cmd::Command;
use serde_json::Value;

const PASSWORD: &str = "correct horse battery";
const ARCHIVE_PASSPHRASE: &str = "invented-lantern-orbit-quartz-meadow";

struct Out {
    code: i32,
    stdout: String,
    stderr: String,
}

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../onepass-core/tests/fixtures/import")
        .join(name)
}

fn onepass(dir: &Path) -> Command {
    let mut c = Command::cargo_bin("onepass").unwrap();
    c.env("ONEPASS_DEV_ALLOW_ENV_PASSWORD", "1")
        .env("ONEPASS_PASSWORD", PASSWORD)
        .env("ONEPASS_DEV_FAST_KDF", "1")
        .env("ONEPASS_ARCHIVE_PASSPHRASE", ARCHIVE_PASSPHRASE)
        .env_remove("ONEPASS_DEV_FAKE_EXEC_DIR")
        .arg("--data-dir")
        .arg(dir);
    c
}

fn output(mut c: Command) -> Out {
    let o = c.output().unwrap();
    Out {
        code: o.status.code().unwrap(),
        stdout: String::from_utf8(o.stdout).unwrap(),
        stderr: String::from_utf8(o.stderr).unwrap(),
    }
}

fn run(dir: &Path, args: &[&str]) -> Out {
    let mut c = onepass(dir);
    c.args(args);
    output(c)
}

fn json(out: &Out) -> Value {
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    serde_json::from_str(&out.stdout).unwrap()
}

fn template() -> &'static PathBuf {
    static T: OnceLock<PathBuf> = OnceLock::new();
    T.get_or_init(|| {
        let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("m5-template");
        let _ = fs::remove_dir_all(&dir);
        let account = run(&dir, &["account", "create"]);
        assert_eq!(account.code, 0, "{}", account.stderr);
        dir
    })
}

/// A private copy of the template directory.
fn fresh() -> tempfile::TempDir {
    let t = template();
    let tmp = tempfile::tempdir().unwrap();
    for entry in fs::read_dir(t).unwrap() {
        let entry = entry.unwrap();
        fs::copy(entry.path(), tmp.path().join(entry.file_name())).unwrap();
    }
    tmp
}

fn path_str(p: &Path) -> &str {
    p.to_str().unwrap()
}

fn titles(dir: &Path, extra: &[&str]) -> Vec<String> {
    let mut args = vec!["item", "list", "--json"];
    args.extend_from_slice(extra);
    let list = json(&run(dir, &args));
    let mut t: Vec<String> = list
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["title"].as_str().unwrap().to_owned())
        .collect();
    t.sort();
    t
}

fn vault_names(dir: &Path) -> Vec<String> {
    let list = json(&run(dir, &["vault", "list", "--json"]));
    let mut v: Vec<String> = list
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["name"].as_str().unwrap().to_owned())
        .collect();
    v.sort();
    v
}

fn mode(p: &Path) -> u32 {
    fs::metadata(p).unwrap().permissions().mode() & 0o777
}

#[test]
fn import_chrome_csv_then_list() {
    let tmp = fresh();
    let dir = tmp.path();
    let chrome = fixture("chrome.csv");

    let out = run(dir, &["import", path_str(&chrome), "--json"]);
    let report = json(&out);
    assert_eq!(report["imported"], 3);
    assert_eq!(report["by_type"]["login"], 3);
    assert_eq!(report["skipped"], 1);
    assert_eq!(report["dry_run"], false);
    assert!(report["warnings"].is_object());

    assert_eq!(
        titles(dir, &[]),
        ["Example Mail", "Example Shop", "Unlisted Site"]
    );

    // Text output: stable summary lines.
    let tmp2 = fresh();
    let out = run(tmp2.path(), &["import", path_str(&chrome)]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert!(out.stdout.contains("Imported 3 items"), "{}", out.stdout);
    assert!(out.stdout.contains("  login: 3"), "{}", out.stdout);
    assert!(out.stdout.contains("Skipped: 1"), "{}", out.stdout);
    // No value of an item ever appears in the report.
    assert!(!out.stdout.contains("Invented-Pw-3"));

    // A forced format is used as given.
    let tmp3 = fresh();
    let out = run(
        tmp3.path(),
        &[
            "import",
            path_str(&chrome),
            "--format",
            "chrome-csv",
            "--json",
        ],
    );
    assert_eq!(json(&out)["imported"], 3);
}

#[test]
fn import_dry_run_writes_nothing() {
    let tmp = fresh();
    let dir = tmp.path();
    let before = vault_names(dir);

    let out = run(
        dir,
        &[
            "import",
            path_str(&fixture("bitwarden.json")),
            "--dry-run",
            "--json",
        ],
    );
    let report = json(&out);
    assert_eq!(report["dry_run"], true);
    assert!(report["imported"].as_u64().unwrap() > 0);

    let out = run(
        dir,
        &["import", path_str(&fixture("chrome.csv")), "--dry-run"],
    );
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert!(out.stdout.contains("(dry run)"), "{}", out.stdout);

    assert!(titles(dir, &[]).is_empty());
    assert_eq!(vault_names(dir), before);
}

#[test]
fn import_folders_become_vaults() {
    let tmp = fresh();
    let dir = tmp.path();
    let report = json(&run(
        dir,
        &["import", path_str(&fixture("bitwarden.json")), "--json"],
    ));
    assert!(report["imported"].as_u64().unwrap() >= 3);

    let vaults = vault_names(dir);
    assert!(vaults.contains(&"Personal".to_owned()), "{vaults:?}");
    assert!(vaults.contains(&"Work".to_owned()), "{vaults:?}");
    assert!(titles(dir, &["--vault", "Personal"]).contains(&"Example Mail".to_owned()));
    assert!(titles(dir, &["--vault", "Work"]).contains(&"Wifi instructions".to_owned()));
    // No folder: the first vault.
    assert!(titles(dir, &["--vault", "Personnel"]).contains(&"Invented Card".to_owned()));

    // A second import reuses the vaults (case-insensitive name match).
    json(&run(
        dir,
        &["import", path_str(&fixture("bitwarden.json")), "--json"],
    ));
    assert_eq!(vault_names(dir), vaults);

    // --vault puts everything in one vault.
    let tmp2 = fresh();
    let report = json(&run(
        tmp2.path(),
        &[
            "import",
            path_str(&fixture("bitwarden.json")),
            "--vault",
            "Personnel",
            "--json",
        ],
    ));
    assert_eq!(vault_names(tmp2.path()), ["Personnel"]);
    assert_eq!(
        titles(tmp2.path(), &[]).len() as u64,
        report["imported"].as_u64().unwrap()
    );
}

#[test]
fn import_unknown_format_exit_1() {
    let tmp = fresh();
    let dir = tmp.path();
    let junk = dir.join("junk.txt");
    fs::write(&junk, "nothing to see here\njust invented words\n").unwrap();

    let out = run(dir, &["import", path_str(&junk)]);
    assert_eq!(out.code, 1, "{}", out.stderr);
    assert!(out.stderr.contains("--format"), "{}", out.stderr);

    let out = run(dir, &["import", path_str(&junk), "--format", "bogus"]);
    assert_eq!(out.code, 1);
    assert!(out.stderr.contains("chrome-csv"), "{}", out.stderr);

    let out = run(dir, &["import", path_str(&dir.join("missing.csv"))]);
    assert_eq!(out.code, 1, "{}", out.stderr);

    // A file or --wifi-keychain, not both, not neither.
    assert_eq!(run(dir, &["import"]).code, 1);
    let both = run(
        dir,
        &[
            "import",
            path_str(&fixture("chrome.csv")),
            "--wifi-keychain",
        ],
    );
    assert_eq!(both.code, 1);
    assert!(titles(dir, &[]).is_empty());
}

#[test]
fn export_onepass_then_import_roundtrip() {
    let src = fresh();
    let dst = fresh();
    json(&run(
        src.path(),
        &["import", path_str(&fixture("chrome.csv")), "--json"],
    ));
    let out_dir = tempfile::tempdir().unwrap();
    let archive = out_dir.path().join("export.onepass");

    let out = run(src.path(), &["export", "--out", path_str(&archive)]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert_eq!(mode(&archive), 0o600);
    let bytes = fs::read(&archive).unwrap();
    assert!(!String::from_utf8_lossy(&bytes).contains("Tr0ub4dor-Invented1"));

    // Wrong passphrase: exit 2, nothing written.
    let mut c = onepass(dst.path());
    c.env(
        "ONEPASS_ARCHIVE_PASSPHRASE",
        "not-the-right-one-at-all-really",
    )
    .args(["import", path_str(&archive)]);
    assert_eq!(output(c).code, 2);
    assert!(titles(dst.path(), &[]).is_empty());

    let report = json(&run(dst.path(), &["import", path_str(&archive), "--json"]));
    assert_eq!(report["imported"], 3);
    assert_eq!(
        titles(dst.path(), &["--vault", "Personnel"]),
        ["Example Mail", "Example Shop", "Unlisted Site"]
    );
    let got = json(&run(
        dst.path(),
        &["item", "get", "Example Mail", "--reveal", "--json"],
    ));
    assert!(got.to_string().contains("Tr0ub4dor-Invented1"));

    // A weak passphrase is refused.
    let mut c = onepass(src.path());
    c.env("ONEPASS_ARCHIVE_PASSPHRASE", "password").args([
        "export",
        "--out",
        path_str(&out_dir.path().join("weak.onepass")),
    ]);
    assert_eq!(output(c).code, 1);
    assert!(!out_dir.path().join("weak.onepass").exists());
}

#[test]
fn export_generated_passphrase_opens() {
    let src = fresh();
    json(&run(
        src.path(),
        &["import", path_str(&fixture("chrome.csv")), "--json"],
    ));
    let out_dir = tempfile::tempdir().unwrap();
    let archive = out_dir.path().join("gen.onepass");
    let out = run(
        src.path(),
        &[
            "export",
            "--out",
            path_str(&archive),
            "--generate-passphrase",
        ],
    );
    assert_eq!(out.code, 0, "{}", out.stderr);
    let lines: Vec<&str> = out
        .stderr
        .lines()
        .filter_map(|l| l.strip_prefix("Archive passphrase: "))
        .collect();
    assert_eq!(lines.len(), 1, "{}", out.stderr);
    let phrase = lines[0];
    assert_eq!(phrase.split('-').count(), 6, "{phrase}");
    assert!(!out.stdout.contains(phrase));

    let dst = fresh();
    let mut c = onepass(dst.path());
    c.env("ONEPASS_ARCHIVE_PASSPHRASE", phrase)
        .args(["import", path_str(&archive), "--json"]);
    let report = json(&output(c));
    assert_eq!(report["imported"], 3);
}

#[test]
fn export_csv_needs_plaintext_flag() {
    let tmp = fresh();
    let dir = tmp.path();
    let out_file = dir.join("plain.csv");
    let out = run(
        dir,
        &["export", "--out", path_str(&out_file), "--format", "csv"],
    );
    assert_eq!(out.code, 1);
    assert!(out.stderr.contains("--plaintext"), "{}", out.stderr);
    assert!(!out_file.exists());
}

#[test]
fn export_csv_warns_and_is_0600() {
    let tmp = fresh();
    let dir = tmp.path();
    json(&run(
        dir,
        &["import", path_str(&fixture("chrome.csv")), "--json"],
    ));
    // A trashed item is left out of the export.
    assert_eq!(run(dir, &["item", "delete", "Example Shop"]).code, 0);

    let out_dir = tempfile::tempdir().unwrap();
    let out_file = out_dir.path().join("plain.csv");
    let out = run(
        dir,
        &[
            "export",
            "--out",
            path_str(&out_file),
            "--format",
            "csv",
            "--plaintext",
        ],
    );
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert!(
        out.stderr
            .contains("WARNING: this file holds every secret in clear text."),
        "{}",
        out.stderr
    );
    assert!(out.stderr.contains("spreadsheet"), "{}", out.stderr);
    assert_eq!(mode(&out_file), 0o600);
    let csv = fs::read_to_string(&out_file).unwrap();
    assert!(csv.starts_with("title,type,vault,url,username,password"));
    assert!(csv.contains("Tr0ub4dor-Invented1"));
    assert!(!csv.contains("Example Shop"));
    assert!(!csv.contains("Sh0p-Invented-2"));
}

#[test]
fn export_refuses_existing_file() {
    let tmp = fresh();
    let dir = tmp.path();
    let out_dir = tempfile::tempdir().unwrap();
    let existing = out_dir.path().join("existing.onepass");
    fs::write(&existing, "keep me").unwrap();
    let out = run(dir, &["export", "--out", path_str(&existing)]);
    assert_eq!(out.code, 1, "{}", out.stderr);
    assert_eq!(fs::read_to_string(&existing).unwrap(), "keep me");

    let out = run(
        dir,
        &[
            "export",
            "--out",
            path_str(&existing),
            "--format",
            "csv",
            "--plaintext",
        ],
    );
    assert_eq!(out.code, 1);
    assert_eq!(fs::read_to_string(&existing).unwrap(), "keep me");
}

#[cfg(target_os = "macos")]
#[test]
fn wifi_keychain_with_fake_exec() {
    let tmp = fresh();
    let dir = tmp.path();
    let fake = tempfile::tempdir().unwrap();
    let f = |name: &str, body: &str| fs::write(fake.path().join(name), body).unwrap();
    f(
        "networksetup--listallhardwareports.out",
        "\nHardware Port: Ethernet\nDevice: en0\nEthernet Address: 00:00:5e:00:53:01\n\n\
         Hardware Port: Wi-Fi\nDevice: en1\nEthernet Address: 00:00:5e:00:53:02\n",
    );
    f(
        "networksetup--listpreferredwirelessnetworks_en1.out",
        "Preferred networks on en1:\n\tInventedHome\n\tInvented Cafe\n",
    );
    f(
        "security-find-generic-password_-D_AirPort_network_password_-a_InventedHome_-w.out",
        "invented-wifi-pass\n",
    );
    // No file for "Invented Cafe": the fake `security` fails.

    let mut c = onepass(dir);
    c.env("ONEPASS_DEV_FAKE_EXEC_DIR", fake.path())
        .args(["import", "--wifi-keychain", "--json"]);
    let report = json(&output(c));
    assert_eq!(report["imported"], 2);
    assert_eq!(report["by_type"]["router"], 2);
    assert_eq!(report["warnings"]["password_unavailable"], 1);

    assert_eq!(
        titles(dir, &["--type", "router"]),
        ["Invented Cafe", "InventedHome"]
    );
    let home = json(&run(
        dir,
        &["item", "get", "InventedHome", "--reveal", "--json"],
    ));
    assert!(home.to_string().contains("invented-wifi-pass"));
    let cafe = json(&run(
        dir,
        &["item", "get", "Invented Cafe", "--reveal", "--json"],
    ));
    assert!(!cafe.to_string().contains("invented-wifi-pass"));
    let has_password = cafe["fields"]
        .as_array()
        .unwrap()
        .iter()
        .any(|f| f["id"] == "wifi_password" && !f["value"].is_null());
    assert!(!has_password, "{cafe}");
}
