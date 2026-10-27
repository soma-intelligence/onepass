//! End-to-end tests of `onepass import`, `export`, `watchtower` and
//! `backup` (milestone 5).
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

/// A second account, for the cross-account backup tests.
fn template2() -> &'static PathBuf {
    static T: OnceLock<PathBuf> = OnceLock::new();
    T.get_or_init(|| {
        let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("m5-template-2");
        let _ = fs::remove_dir_all(&dir);
        let account = run(&dir, &["account", "create"]);
        assert_eq!(account.code, 0, "{}", account.stderr);
        dir
    })
}

/// A private copy of the data directory `from`.
fn copy_dir(from: &Path) -> tempfile::TempDir {
    let tmp = tempfile::tempdir().unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_file() {
            fs::copy(entry.path(), tmp.path().join(entry.file_name())).unwrap();
        }
    }
    tmp
}

/// A private copy of the template directory.
fn fresh() -> tempfile::TempDir {
    copy_dir(template())
}

/// A private copy of the second account.
fn fresh_other() -> tempfile::TempDir {
    copy_dir(template2())
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
    assert!(out.stderr.contains("passkey"), "{}", out.stderr);
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

// ---- watchtower ----

/// Synthetic passwords and their SHA-1 (upper-case hex), precomputed so
/// the tests need no hash crate.
const REUSED_PW: &str = "Invented-Reused-Pw-71";
const REUSED_SHA1: &str = "DEB5FAE6E77D742376566E8F575E672A56EACFC8";
const PWNED_PW: &str = "Invented-Pwned-Pw-42";
const PWNED_SHA1: &str = "2AABA3D062180A052C22CE6EB2364901F9855FC0";

/// Three logins: two share a password, the third uses `http://`.
fn watchtower_dir() -> tempfile::TempDir {
    let tmp = fresh();
    let csv = tmp.path().join("logins.csv");
    fs::write(
        &csv,
        format!(
            "name,url,username,password\n\
             Reuse One,https://one.example.com,alice,{REUSED_PW}\n\
             Reuse Two,https://two.example.org,bob,{REUSED_PW}\n\
             Plain Site,http://plain.example.net,carol,{PWNED_PW}\n"
        ),
    )
    .unwrap();
    let report = json(&run(tmp.path(), &["import", path_str(&csv), "--json"]));
    assert_eq!(report["imported"], 3);
    fs::remove_file(&csv).unwrap();
    tmp
}

/// A range directory with both prefixes: the pwned suffix seen 42 times,
/// the reused one absent (only padding).
fn range_dir() -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    let (p1, s1) = PWNED_SHA1.split_at(5);
    let (p2, _) = REUSED_SHA1.split_at(5);
    fs::write(
        d.path().join(format!("{p1}.txt")),
        format!("0000000000000000000000000000000000A:3\r\n{s1}:42\r\n"),
    )
    .unwrap();
    fs::write(
        d.path().join(format!("{p2}.txt")),
        "0000000000000000000000000000000000B:0\r\n",
    )
    .unwrap();
    d
}

fn checks_of(report: &Value) -> Vec<(String, String)> {
    report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            (
                f["check"].as_str().unwrap().to_owned(),
                f["title"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

fn assert_no_password(out: &Out) {
    for pw in [REUSED_PW, PWNED_PW] {
        assert!(!out.stdout.contains(pw), "{}", out.stdout);
        assert!(!out.stderr.contains(pw), "{}", out.stderr);
    }
}

#[test]
fn watchtower_offline_report() {
    let tmp = watchtower_dir();
    let ranges = range_dir();
    let out = run(
        tmp.path(),
        &[
            "watchtower",
            "--offline",
            "--hibp-dir",
            path_str(ranges.path()),
            "--json",
        ],
    );
    assert_no_password(&out);
    let report = json(&out);
    assert_eq!(report["pwned"], "checked");
    assert_eq!(report["sites_checked"], false);
    assert_eq!(report["breaches_checked"], false);
    let checks = checks_of(&report);
    assert!(
        checks.contains(&("compromised".into(), "Plain Site".into())),
        "{checks:?}"
    );
    assert!(
        checks.contains(&("reused".into(), "Reuse One".into())),
        "{checks:?}"
    );
    assert!(
        checks.contains(&("reused".into(), "Reuse Two".into())),
        "{checks:?}"
    );
    assert!(
        checks.contains(&("insecure_url".into(), "Plain Site".into())),
        "{checks:?}"
    );
    let compromised = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["check"] == "compromised")
        .unwrap();
    assert_eq!(compromised["severity"], "critical");
    assert_eq!(compromised["vault"], "Personnel");
    assert_eq!(compromised["field"], "password");
    assert_eq!(compromised["detail"]["count"], 42);
    // Ids are hyphenated text.
    assert_eq!(compromised["item_id"].as_str().unwrap().len(), 36);
    let vaults = report["vaults"].as_array().unwrap();
    assert_eq!(vaults.len(), 1);
    assert_eq!(vaults[0]["name"], "Personnel");
    assert_eq!(vaults[0]["items"], 3);
    assert_eq!(vaults[0]["id"].as_str().unwrap().len(), 36);
    let score = report["score"].as_u64().unwrap();
    assert!(score < 100, "{score}");
    assert_eq!(vaults[0]["score"].as_u64().unwrap(), score);

    // Text output.
    let out = run(
        tmp.path(),
        &[
            "watchtower",
            "--offline",
            "--hibp-dir",
            path_str(ranges.path()),
        ],
    );
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert_no_password(&out);
    assert!(
        out.stdout.contains(&format!("Score: {score}/100")),
        "{}",
        out.stdout
    );
    assert!(
        out.stdout
            .contains(&format!("  Personnel: {score}/100 (3 items)")),
        "{}",
        out.stdout
    );
    assert!(out.stdout.contains("compromised (1)"), "{}", out.stdout);
    assert!(
        out.stdout
            .contains("  - Plain Site [Personnel] password seen 42 times"),
        "{}",
        out.stdout
    );
    assert!(out.stdout.contains("reused (2)"), "{}", out.stdout);
}

#[test]
fn watchtower_offline_without_sources() {
    let tmp = watchtower_dir();
    let out = run(tmp.path(), &["watchtower", "--offline", "--json"]);
    assert_no_password(&out);
    let report = json(&out);
    assert_eq!(report["pwned"], "disabled");
    assert_eq!(report["sites_checked"], false);
    assert_eq!(report["breaches_checked"], false);
    let checks = checks_of(&report);
    assert!(!checks.iter().any(|(c, _)| c == "compromised"));
    assert!(checks.iter().any(|(c, _)| c == "reused"));

    // Catalog files are used offline.
    let files = tempfile::tempdir().unwrap();
    let sites = files.path().join("sites.json");
    fs::write(&sites, r#"{"one.example.com": {"methods": ["totp"]}}"#).unwrap();
    let breaches = files.path().join("breaches.json");
    fs::write(
        &breaches,
        r#"[{"Name": "InventedLeak", "Domain": "two.example.org", "BreachDate": "2001-01-01", "IsVerified": true}]"#,
    )
    .unwrap();
    let report = json(&run(
        tmp.path(),
        &[
            "watchtower",
            "--offline",
            "--sites",
            path_str(&sites),
            "--breaches",
            path_str(&breaches),
            "--json",
        ],
    ));
    assert_eq!(report["sites_checked"], true);
    assert_eq!(report["breaches_checked"], true);
    let checks = checks_of(&report);
    assert!(
        checks.contains(&("missing_2fa".into(), "Reuse One".into())),
        "{checks:?}"
    );

    // --vault restricts the analysis; an unknown vault is not found.
    let report = json(&run(
        tmp.path(),
        &["watchtower", "--offline", "--vault", "Personnel", "--json"],
    ));
    assert_eq!(report["vaults"].as_array().unwrap().len(), 1);
    assert_eq!(
        run(tmp.path(), &["watchtower", "--offline", "--vault", "Nope"]).code,
        4
    );

    // --offline never runs curl: a fake exec directory with no answer
    // would make any call fail, and nothing changes.
    let fake = tempfile::tempdir().unwrap();
    let mut c = onepass(tmp.path());
    c.env("ONEPASS_DEV_FAKE_EXEC_DIR", fake.path())
        .args(["watchtower", "--offline", "--json"]);
    let out = output(c);
    let report = json(&out);
    assert_eq!(report["pwned"], "disabled");
    assert!(!out.stderr.contains("unavailable"), "{}", out.stderr);
}

/// Name of the fake answer of `curl <flags> <url>` (see `commands::exec`).
fn curl_fake_name(padding: bool, url: &str) -> String {
    let mut args = vec!["-sS", "--fail", "--max-time", "15"];
    if padding {
        args.extend(["-H", "Add-Padding: true"]);
    }
    args.extend(["-H", "User-Agent: onepass-cli", url]);
    let raw = format!("curl-{}", args.join("_"));
    let mut name: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    name.push_str(".out");
    name
}

#[test]
fn watchtower_online_uses_fake_curl() {
    let tmp = watchtower_dir();
    let fake = tempfile::tempdir().unwrap();
    // Range answers exist only for the two 5-hex prefixes: a request for
    // anything else (a longer hash, a lower-case prefix, a password) finds
    // no file and makes the lookup partial.
    let ranges = range_dir();
    for entry in fs::read_dir(ranges.path()).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name().into_string().unwrap();
        let prefix = name.strip_suffix(".txt").unwrap();
        assert!(prefix.len() == 5 && prefix.bytes().all(|b| b.is_ascii_hexdigit()));
        fs::copy(
            entry.path(),
            fake.path().join(curl_fake_name(
                true,
                &format!("https://api.pwnedpasswords.com/range/{prefix}"),
            )),
        )
        .unwrap();
    }
    fs::write(
        fake.path().join(curl_fake_name(
            false,
            "https://api.2fa.directory/v4/all.json",
        )),
        r#"{"one.example.com": {"methods": ["totp"]}}"#,
    )
    .unwrap();
    fs::write(
        fake.path().join(curl_fake_name(
            false,
            "https://passkeys-api.2fa.directory/v1/all.json",
        )),
        r#"{"two.example.org": {"passwordless": "allowed"}}"#,
    )
    .unwrap();
    // No answer for the breach catalog: that source is absent, reported.

    let mut c = onepass(tmp.path());
    c.env("ONEPASS_DEV_FAKE_EXEC_DIR", fake.path())
        .args(["watchtower", "--json"]);
    let out = output(c);
    assert_no_password(&out);
    let report = json(&out);
    assert_eq!(report["pwned"], "checked", "{}", out.stderr);
    assert_eq!(report["sites_checked"], true);
    assert_eq!(report["breaches_checked"], false);
    assert!(
        out.stderr.contains("breach catalog unavailable"),
        "{}",
        out.stderr
    );
    let checks = checks_of(&report);
    assert!(
        checks.contains(&("compromised".into(), "Plain Site".into())),
        "{checks:?}"
    );
    assert!(
        checks.contains(&("missing_2fa".into(), "Reuse One".into())),
        "{checks:?}"
    );
    assert!(
        checks.contains(&("passkey_available".into(), "Reuse Two".into())),
        "{checks:?}"
    );

    // Without range answers the lookup is unavailable, not an error.
    let empty = tempfile::tempdir().unwrap();
    let mut c = onepass(tmp.path());
    c.env("ONEPASS_DEV_FAKE_EXEC_DIR", empty.path())
        .args(["watchtower", "--json"]);
    let report = json(&output(c));
    assert_eq!(report["pwned"], "unavailable");
    assert_eq!(report["sites_checked"], false);
}

// ---- backup ----

#[test]
fn backup_create_restore_into_fresh_account_fails_other_account() {
    let src = fresh();
    json(&run(
        src.path(),
        &["import", path_str(&fixture("chrome.csv")), "--json"],
    ));
    let out_dir = tempfile::tempdir().unwrap();
    let backup = out_dir.path().join("b.onepass");
    let out = run(
        src.path(),
        &["backup", "create", "--out", path_str(&backup)],
    );
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert_eq!(mode(&backup), 0o600);
    assert!(!String::from_utf8_lossy(&fs::read(&backup).unwrap()).contains("Tr0ub4dor-Invented1"));

    // An existing file is never overwritten.
    let again = run(
        src.path(),
        &["backup", "create", "--out", path_str(&backup)],
    );
    assert_eq!(again.code, 1, "{}", again.stderr);

    let other = fresh_other();
    let out = run(other.path(), &["backup", "restore", path_str(&backup)]);
    assert_eq!(out.code, 2, "{}", out.stderr);
    assert!(out.stderr.contains("another account"), "{}", out.stderr);
    assert!(titles(other.path(), &[]).is_empty());
}

#[test]
fn backup_roundtrip_same_account() {
    let src = fresh();
    let dir = src.path();
    json(&run(
        dir,
        &["import", path_str(&fixture("chrome.csv")), "--json"],
    ));
    // Snapshot of the account before the last item exists: restoring into
    // it is the state after that item was deleted for good.
    let before = copy_dir(dir);
    let created = run(
        dir,
        &[
            "item",
            "create",
            "secure-note",
            "--title",
            "Invented Note",
            "--field",
            "content=invented note body",
        ],
    );
    assert_eq!(created.code, 0, "{}", created.stderr);
    // A trashed item is backed up too.
    assert_eq!(run(dir, &["item", "delete", "Example Shop"]).code, 0);

    let out_dir = tempfile::tempdir().unwrap();
    let backup = out_dir.path().join("b.onepass");
    let out = run(
        dir,
        &["backup", "create", "--out", path_str(&backup), "--json"],
    );
    let made = json(&out);
    assert_eq!(made["items"], 4);

    // Same account, everything present: all skipped.
    let report = json(&run(
        dir,
        &["backup", "restore", path_str(&backup), "--json"],
    ));
    assert_eq!(report["restored"], 0);
    assert_eq!(report["skipped"], 4);
    assert_eq!(report["vaults_created"], 0);
    // Every restore issues the next signed restore epoch.
    assert_eq!(report["epoch"], 1);
    let again = json(&run(
        dir,
        &["backup", "restore", path_str(&backup), "--json"],
    ));
    assert_eq!(again["epoch"], 2);
    assert_eq!(again["skipped"], 4);

    // Into the snapshot: the note comes back, the others are skipped.
    let report = json(&run(
        before.path(),
        &["backup", "restore", path_str(&backup), "--json"],
    ));
    assert_eq!(report["restored"], 1);
    assert_eq!(report["skipped"], 3);
    assert_eq!(report["vaults_created"], 0);
    assert!(titles(before.path(), &[]).contains(&"Invented Note".to_owned()));

    // Text output.
    let fresh_copy = copy_dir(template());
    let out = run(fresh_copy.path(), &["backup", "restore", path_str(&backup)]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert!(out.stdout.contains("Restored 4 items"), "{}", out.stdout);
    assert!(out.stdout.contains("Skipped 0 items"), "{}", out.stdout);
    // The trashed item is restored as trashed.
    assert_eq!(
        titles(fresh_copy.path(), &[]),
        ["Example Mail", "Invented Note", "Unlisted Site"]
    );
}

#[test]
fn backup_with_passphrase_restores_elsewhere() {
    let src = fresh();
    json(&run(
        src.path(),
        &["import", path_str(&fixture("chrome.csv")), "--json"],
    ));
    let out_dir = tempfile::tempdir().unwrap();
    let backup = out_dir.path().join("p.onepass");
    let out = run(
        src.path(),
        &[
            "backup",
            "create",
            "--out",
            path_str(&backup),
            "--passphrase",
        ],
    );
    assert_eq!(out.code, 0, "{}", out.stderr);

    // Wrong passphrase in another account: exit 2, nothing written.
    let other = fresh_other();
    let mut c = onepass(other.path());
    c.env(
        "ONEPASS_ARCHIVE_PASSPHRASE",
        "not-the-right-one-at-all-really",
    )
    .args(["backup", "restore", path_str(&backup)]);
    assert_eq!(output(c).code, 2);
    assert!(titles(other.path(), &[]).is_empty());

    let report = json(&run(
        other.path(),
        &["backup", "restore", path_str(&backup), "--json"],
    ));
    assert_eq!(report["restored"], 3);
    assert_eq!(report["skipped"], 0);
    assert_eq!(report["vaults_created"], 1);
    assert_eq!(
        titles(other.path(), &[]),
        ["Example Mail", "Example Shop", "Unlisted Site"]
    );
    let got = json(&run(
        other.path(),
        &["item", "get", "Example Mail", "--reveal", "--json"],
    ));
    assert!(got.to_string().contains("Tr0ub4dor-Invented1"));

    // A weak passphrase is refused, no file written.
    let mut c = onepass(src.path());
    c.env("ONEPASS_ARCHIVE_PASSPHRASE", "password").args([
        "backup",
        "create",
        "--out",
        path_str(&out_dir.path().join("weak.onepass")),
        "--passphrase",
    ]);
    assert_eq!(output(c).code, 1);
    assert!(!out_dir.path().join("weak.onepass").exists());
}

#[test]
fn backup_inspect_needs_no_password() {
    let src = fresh();
    let out_dir = tempfile::tempdir().unwrap();
    let backup = out_dir.path().join("i.onepass");
    let out = run(
        src.path(),
        &[
            "backup",
            "create",
            "--out",
            path_str(&backup),
            "--passphrase",
        ],
    );
    assert_eq!(out.code, 0, "{}", out.stderr);

    // No password, no account in the data directory.
    let empty = tempfile::tempdir().unwrap();
    let mut c = Command::cargo_bin("onepass").unwrap();
    c.env_remove("ONEPASS_PASSWORD")
        .env_remove("ONEPASS_DEV_ALLOW_ENV_PASSWORD")
        .arg("--data-dir")
        .arg(empty.path())
        .args(["backup", "inspect", path_str(&backup), "--json"]);
    let info = json(&output(c));
    assert_eq!(info["kind"], "backup");
    assert_eq!(info["passphrase"], true);
    assert_eq!(info["signed"], true);
    assert_eq!(info["payload_schema"], 1);
    assert_eq!(info["account"].as_str().unwrap().len(), 36);
    assert_eq!(info["archive_id"].as_str().unwrap().len(), 36);
    assert!(info["created_at"].as_i64().unwrap() > 0);
    assert_eq!(fs::read_dir(empty.path()).unwrap().count(), 0);

    let mut c = Command::cargo_bin("onepass").unwrap();
    c.env_remove("ONEPASS_PASSWORD")
        .env_remove("ONEPASS_DEV_ALLOW_ENV_PASSWORD")
        .args(["backup", "inspect", path_str(&backup)]);
    let out = output(c);
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert!(out.stdout.contains("Kind: backup"), "{}", out.stdout);
    assert!(out.stdout.contains("Signed: yes"), "{}", out.stdout);
    assert!(out.stdout.contains("Passphrase: yes"), "{}", out.stdout);

    // Not an archive: usage error.
    let junk = out_dir.path().join("junk.bin");
    fs::write(&junk, "not an archive").unwrap();
    let mut c = Command::cargo_bin("onepass").unwrap();
    c.args(["backup", "inspect", path_str(&junk)]);
    assert_eq!(output(c).code, 1);
}

#[test]
fn text_output_never_carries_control_characters() {
    let tmp = fresh();
    let dir = tmp.path();
    let csv = dir.join("esc.csv");
    fs::write(
        &csv,
        "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n\
         Evil\x1b[31mVault,,login,Esc\x1b[2JOne,,,,https://one.example.com,alice,Reused-Invented-9,\n\
         Evil\x1b[31mVault,,login,Esc\x1b[2JTwo,,,,https://two.example.com,bob,Reused-Invented-9,\n",
    )
    .unwrap();
    let out = run(dir, &["import", path_str(&csv)]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert!(!out.stdout.contains('\x1b'), "{:?}", out.stdout);
    assert!(
        out.stdout.contains("Created vault: Evil\u{FFFD}[31mVault"),
        "{:?}",
        out.stdout
    );
    let out = run(dir, &["watchtower", "--offline"]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert!(!out.stdout.contains('\x1b'), "{:?}", out.stdout);
    assert!(out.stdout.contains("Esc\u{FFFD}[2JOne"), "{:?}", out.stdout);
    // JSON keeps the exact title, escaped by serde.
    let report = json(&run(dir, &["watchtower", "--offline", "--json"]));
    assert!(checks_of(&report).iter().any(|(_, t)| t == "Esc\x1b[2JOne"));
}

/// An export archive (passphrase recipient) of `items` in one vault.
fn crafted_archive(items: Vec<onepass_core::model::Item>) -> Vec<u8> {
    use onepass_core::archive::{ArchivedVault, export};
    use onepass_core::crypto::kdf::KdfParams;
    use onepass_core::vault::VaultMeta;
    let mut kdf = KdfParams::new_default().unwrap();
    kdf.m_kib = 8192;
    kdf.t = 1;
    kdf.p = 1;
    let vault = ArchivedVault {
        id: onepass_core::Id::new(),
        meta: VaultMeta {
            name: "Crafted".into(),
            icon: String::new(),
            color: String::new(),
            travel_safe: false,
            mcp_access: false,
        },
        items,
    };
    export(vec![vault], ARCHIVE_PASSPHRASE, kdf).unwrap()
}

#[test]
fn import_archive_with_invalid_item_writes_nothing() {
    use onepass_core::Id;
    use onepass_core::model::{ItemType, new_item};
    let tmp = fresh();
    let dir = tmp.path();
    let good = new_item(ItemType::SecureNote, Id::new(), "Fine note");
    // An empty title never validates.
    let bad = new_item(ItemType::SecureNote, Id::new(), " ");
    let file = dir.join("crafted.onepass");
    fs::write(&file, crafted_archive(vec![good, bad])).unwrap();
    let out = run(dir, &["import", path_str(&file)]);
    assert_eq!(out.code, 1, "{}", out.stderr);
    assert!(out.stderr.contains("nothing written"), "{}", out.stderr);
    assert!(titles(dir, &[]).is_empty());
    assert!(!vault_names(dir).contains(&"Crafted".to_owned()));
}

#[test]
fn import_of_account_backup_without_passphrase_points_to_restore() {
    let tmp = fresh();
    let dir = tmp.path();
    json(&run(
        dir,
        &["import", path_str(&fixture("chrome.csv")), "--json"],
    ));
    let out_dir = tempfile::tempdir().unwrap();
    let backup = out_dir.path().join("b.onepass");
    let out = run(dir, &["backup", "create", "--out", path_str(&backup)]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    let out = run(dir, &["import", path_str(&backup)]);
    assert_eq!(out.code, 1, "{}", out.stderr);
    assert!(
        out.stderr
            .contains("this is an account backup without passphrase: use `onepass backup restore`"),
        "{}",
        out.stderr
    );
}

#[test]
fn csv_export_imports_back() {
    let src = fresh();
    json(&run(
        src.path(),
        &["import", path_str(&fixture("chrome.csv")), "--json"],
    ));
    let out_dir = tempfile::tempdir().unwrap();
    let csv = out_dir.path().join("plain.csv");
    let out = run(
        src.path(),
        &[
            "export",
            "--out",
            path_str(&csv),
            "--format",
            "csv",
            "--plaintext",
        ],
    );
    assert_eq!(out.code, 0, "{}", out.stderr);
    let dst = fresh();
    let report = json(&run(dst.path(), &["import", path_str(&csv), "--json"]));
    assert_eq!(report["imported"], 3);
    assert_eq!(titles(dst.path(), &[]), titles(src.path(), &[]));
}
