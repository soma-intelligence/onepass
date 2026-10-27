//! End-to-end tests of `onepass mcp` and the vault flags: the real binary,
//! driven over stdin and stdout like an MCP client would.
//!
//! As in `tests/cli.rs`, the account (with an MCP vault `Dev` holding one
//! login) is created once in a template directory, and every test works on
//! its own copy.

use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command as StdCommand, Stdio};
use std::sync::OnceLock;
use std::sync::mpsc;
use std::time::Duration;

use assert_cmd::Command;
use onepass_core::Id;
use onepass_core::manifest::SeenManifest;
use onepass_core::repo::DeviceState;
use serde_json::{Value, json};

const PASSWORD: &str = "correct horse battery";
const SERVER_PW: &str = "s3cr3t-server-value-42";

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
        .env("ONEPASS_DEV_AUTO_APPROVE", "once")
        .env("ONEPASS_DEV_STRONG_AUTH", "allow")
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

fn template() -> &'static PathBuf {
    static T: OnceLock<PathBuf> = OnceLock::new();
    T.get_or_init(|| {
        let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("mcp-template");
        let _ = fs::remove_dir_all(&dir);
        ok(&dir, &["account", "create"]);
        ok(&dir, &["vault", "create", "Dev", "--mcp-access"]);
        ok(
            &dir,
            &[
                "item",
                "create",
                "login",
                "--title",
                "Server",
                "--vault",
                "Dev",
                "--field",
                "username=deploy",
                "--field",
                &format!("password={SERVER_PW}"),
            ],
        );
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

/// `last_seen` of `device.bin`, decoded like `session.rs` does.
fn last_seen(dir: &Path) -> BTreeMap<Id, SeenManifest> {
    #[derive(serde::Deserialize)]
    struct DeviceFile {
        #[allow(dead_code)]
        secret_key: String,
        #[serde(with = "onepass_core::format::device_state_bytes")]
        state: DeviceState,
    }
    let bytes = fs::read(dir.join("device.bin")).unwrap();
    let file: DeviceFile = postcard::from_bytes(&bytes).unwrap();
    file.state.last_seen
}

/// A running `onepass mcp`, spoken to line by line.
struct Server {
    child: Child,
    stdin: Option<ChildStdin>,
    lines: mpsc::Receiver<String>,
    next_id: u64,
}

impl Server {
    fn start(dir: &Path, extra: &[&str]) -> Server {
        let mut child = StdCommand::new(assert_cmd::cargo::cargo_bin("onepass"))
            .env("ONEPASS_DEV_ALLOW_ENV_PASSWORD", "1")
            .env("ONEPASS_PASSWORD", PASSWORD)
            .env("ONEPASS_DEV_AUTO_APPROVE", "once")
            .env("ONEPASS_DEV_STRONG_AUTH", "allow")
            .arg("--data-dir")
            .arg(dir)
            .arg("mcp")
            .args(extra)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        let stdin = child.stdin.take();
        let mut s = Server {
            child,
            stdin,
            lines: rx,
            next_id: 1,
        };
        let init = s.request(
            "initialize",
            json!({
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "e2e-test", "version": "1.0"},
            }),
        );
        assert_eq!(init["result"]["serverInfo"]["name"], "onepass", "{init}");
        s.send(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}));
        s
    }

    fn send(&mut self, v: &Value) {
        let stdin = self.stdin.as_mut().unwrap();
        writeln!(stdin, "{v}").unwrap();
        stdin.flush().unwrap();
    }

    fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        self.send(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}));
        let line = self
            .lines
            .recv_timeout(Duration::from_secs(120))
            .expect("a reply from the server");
        let v: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["id"], id, "{v}");
        v
    }

    fn call(&mut self, tool: &str, args: Value) -> Value {
        let r = self.request("tools/call", json!({"name": tool, "arguments": args}));
        r["result"].clone()
    }

    /// Close stdin (EOF) and wait: exit code and stderr.
    fn finish(mut self) -> (i32, String) {
        drop(self.stdin.take());
        let out = self.child.wait_with_output().unwrap();
        (
            out.status.code().unwrap(),
            String::from_utf8(out.stderr).unwrap(),
        )
    }
}

#[test]
fn vault_create_flags() {
    let tmp = fresh();
    let d = tmp.path();
    ok(d, &["vault", "create", "Plain"]);
    ok(
        d,
        &["vault", "create", "Trip", "--travel-safe", "--mcp-access"],
    );
    let show = ok(d, &["mcp", "policy", "show"]).stdout;
    assert!(show.contains("Dev"), "{show}");
    assert!(show.contains("Trip"), "{show}");
    assert!(!show.contains("Plain"), "{show}");
    assert!(!show.contains("Personnel"), "{show}");
    // Default scopes without a policy file.
    assert!(show.contains("metadata,use"), "{show}");
}

#[test]
fn mcp_stdio_end_to_end() {
    let tmp = fresh();
    let d = tmp.path();
    let mut s = Server::start(d, &[]);

    let list = s.request("tools/list", json!({}));
    let names: Vec<&str> = list["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    for tool in [
        "list_vaults",
        "list_items",
        "search_items",
        "get_item",
        "run_with_secrets",
        "fill_template",
        "create_login",
        "generate_password",
        "totp_code",
        "reveal_secret",
    ] {
        assert!(names.contains(&tool), "{tool} missing from {names:?}");
    }
    assert_eq!(names.len(), 10);

    let items = s.call("list_items", json!({}));
    assert_eq!(items["isError"], false, "{items}");
    let text = items["structuredContent"].to_string();
    assert!(text.contains("Server"), "{text}");
    assert!(!text.contains("GitHub"), "Personnel is not an MCP vault");
    assert!(!text.contains(SERVER_PW));

    let run = s.call(
        "run_with_secrets",
        json!({
            "command": ["sh", "-c", "printf %s \"$PW\""],
            "env": {"PW": "onepass://Dev/Server/password"},
        }),
    );
    assert_eq!(run["isError"], false, "{run}");
    assert_eq!(
        run["structuredContent"]["stdout"], "<concealed:PW>",
        "{run}"
    );
    assert_eq!(run["structuredContent"]["exit_code"], 0);
    assert!(!run.to_string().contains(SERVER_PW));

    let reveal = s.call(
        "reveal_secret",
        json!({"reference": "onepass://Dev/Server/password"}),
    );
    assert_eq!(reveal["isError"], true, "{reveal}");
    assert!(!reveal.to_string().contains(SERVER_PW));

    let (code, stderr) = s.finish();
    assert_eq!(code, 0, "{stderr}");
    assert!(stderr.contains("onepass mcp: ready (1 vaults)"), "{stderr}");
    assert!(!stderr.contains(SERVER_PW));
}

/// Start `onepass mcp` with an empty stdin: exit code and stderr.
fn start_and_eof(dir: &Path) -> (Option<i32>, String) {
    let o = onepass(dir).arg("mcp").write_stdin("").output().unwrap();
    (o.status.code(), String::from_utf8(o.stderr).unwrap())
}

#[test]
fn mcp_refuses_tampered_policy() {
    let tmp = fresh();
    let d = tmp.path();
    ok(
        d,
        &[
            "mcp", "policy", "set", "--vault", "Dev", "--scopes", "metadata",
        ],
    );
    let path = d.join("mcp-policy.json");
    let text = fs::read_to_string(&path).unwrap();
    // A well-formed policy that grants more: only the signature can tell.
    let edited = text.replacen(r#"\"metadata\""#, r#"\"reveal\""#, 1);
    assert_ne!(edited, text, "the scope in the signed payload");
    let envelope: Value = serde_json::from_str(&edited).unwrap();
    let payload: Value = serde_json::from_str(envelope["payload"].as_str().unwrap()).unwrap();
    assert!(
        payload["vaults"].to_string().contains("reveal"),
        "{payload}"
    );
    fs::write(&path, edited).unwrap();

    let (code, stderr) = start_and_eof(d);
    assert_eq!(code, Some(3), "{stderr}");
    assert!(
        stderr.contains("mcp policy failed verification"),
        "{stderr}"
    );
    // policy show and policy set refuse it too.
    assert_eq!(run(d, &["mcp", "policy", "show"]).code, 3);
    assert_eq!(
        run(
            d,
            &["mcp", "policy", "set", "--vault", "Dev", "--scopes", "use"]
        )
        .code,
        3
    );
}

/// A second account, with an MCP vault `Dev` and a signed policy.
fn other_account() -> &'static PathBuf {
    static T: OnceLock<PathBuf> = OnceLock::new();
    T.get_or_init(|| {
        let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("mcp-other-account");
        let _ = fs::remove_dir_all(&dir);
        ok(&dir, &["account", "create"]);
        ok(&dir, &["vault", "create", "Dev", "--mcp-access"]);
        ok(
            &dir,
            &[
                "mcp", "policy", "set", "--vault", "Dev", "--scopes", "reveal",
            ],
        );
        dir
    })
}

#[test]
fn mcp_refuses_policy_of_another_account() {
    let tmp = fresh();
    let d = tmp.path();
    fs::copy(
        other_account().join("mcp-policy.json"),
        d.join("mcp-policy.json"),
    )
    .unwrap();
    let (code, stderr) = start_and_eof(d);
    assert_eq!(code, Some(3), "{stderr}");
    assert!(
        stderr.contains("mcp policy failed verification"),
        "{stderr}"
    );
    assert_eq!(run(d, &["mcp", "policy", "show"]).code, 3);
}

#[test]
fn mcp_policy_set_and_show() {
    let tmp = fresh();
    let d = tmp.path();
    ok(
        d,
        &[
            "mcp",
            "policy",
            "set",
            "--vault",
            "Dev",
            "--scopes",
            "metadata,reveal",
            "--allow-generate",
            "false",
        ],
    );
    let show = ok(d, &["mcp", "policy", "show"]).stdout;
    assert!(show.contains("metadata,reveal"), "{show}");
    assert!(show.contains("allow_generate: false"), "{show}");

    // Only MCP vaults, unknown scopes refused.
    let o = run(
        d,
        &[
            "mcp",
            "policy",
            "set",
            "--vault",
            "Personnel",
            "--scopes",
            "use",
        ],
    );
    assert_eq!(o.code, 4, "{}", o.stderr);
    assert!(
        o.stderr.contains("no MCP vault named 'Personnel'"),
        "{}",
        o.stderr
    );
    let o = run(
        d,
        &[
            "mcp",
            "policy",
            "set",
            "--vault",
            "Dev",
            "--scopes",
            "use,admin",
        ],
    );
    assert_eq!(o.code, 1, "{}", o.stderr);

    // The server applies the new policy: reveal is granted now.
    let mut s = Server::start(d, &[]);
    let r = s.call(
        "reveal_secret",
        json!({"reference": "onepass://Dev/Server/password"}),
    );
    assert_eq!(r["isError"], false, "{r}");
    assert!(r.to_string().contains(SERVER_PW));
    // A launch narrowing can still drop it.
    let (code, _) = s.finish();
    assert_eq!(code, 0);
    let mut s = Server::start(d, &["--scopes", "metadata"]);
    let r = s.call(
        "reveal_secret",
        json!({"reference": "onepass://Dev/Server/password"}),
    );
    assert_eq!(r["isError"], true, "{r}");
    assert_eq!(s.finish().0, 0);
    // An unknown or non-MCP --vault name exits 4.
    let o = onepass(d)
        .args(["mcp", "--vault", "Personnel"])
        .write_stdin("")
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(4));
    assert!(
        String::from_utf8(o.stderr)
            .unwrap()
            .contains("no MCP vault named 'Personnel'")
    );
}

#[test]
fn mcp_audit_verify() {
    let tmp = fresh();
    let d = tmp.path();
    let mut s = Server::start(d, &[]);
    s.call("list_items", json!({}));
    s.call(
        "run_with_secrets",
        json!({
            "command": ["true"],
            "env": {"PW": "onepass://Dev/Server/password"},
        }),
    );
    s.call(
        "reveal_secret",
        json!({"reference": "onepass://Dev/Server/password"}),
    );
    assert_eq!(s.finish().0, 0);

    let o = ok(d, &["mcp", "audit", "--verify"]);
    assert!(
        o.stdout.contains("audit log verified (3 entries)"),
        "{}",
        o.stdout
    );
    // Without --verify: the entries, titles resolved, then the verdict.
    let o = ok(d, &["mcp", "audit"]);
    assert!(o.stdout.contains("run_with_secrets"), "{}", o.stdout);
    assert!(o.stdout.contains("Server"), "{}", o.stdout);
    assert!(o.stdout.contains("e2e-test"), "{}", o.stdout);
    assert!(o.stdout.contains("audit log verified (3 entries)"));
    assert!(!o.stdout.contains(SERVER_PW));

    // One line edited: verification fails.
    let log = d.join("audit.log");
    let text = fs::read_to_string(&log).unwrap();
    let edited = text.replacen("list_items", "list_itemz", 1);
    assert_ne!(edited, text);
    fs::write(&log, edited).unwrap();
    let o = run(d, &["mcp", "audit", "--verify"]);
    assert_eq!(o.code, 3, "{}", o.stdout);
    assert!(
        o.stderr.contains("audit log failed verification"),
        "{}",
        o.stderr
    );
    let o = run(d, &["mcp", "audit"]);
    assert_eq!(o.code, 3);
    assert!(
        !o.stdout.contains("list_itemz"),
        "no unverified entry shown"
    );

    // A log that cannot be read is an i/o error (1), not tampering (3).
    fs::remove_file(&log).unwrap();
    fs::create_dir(&log).unwrap();
    let o = run(d, &["mcp", "audit", "--verify"]);
    assert_eq!(o.code, 1, "{}", o.stderr);
    assert!(o.stderr.contains("cannot read audit log"), "{}", o.stderr);
}

#[test]
fn cli_runs_while_mcp_server_is_up_and_last_seen_never_regresses() {
    let tmp = fresh();
    let d = tmp.path();
    let mut s = Server::start(d, &[]);
    let mut max: BTreeMap<Id, u64> = BTreeMap::new();
    let mut observe = |dir: &Path| {
        for (id, seen) in last_seen(dir) {
            let m = max.entry(id).or_insert(0);
            assert!(seen.seq >= *m, "last_seen went back for {id}");
            *m = seen.seq;
        }
    };
    observe(d);

    // The CLI writes in both vaults while the server is up (and unlocked).
    ok(
        d,
        &[
            "item",
            "create",
            "login",
            "--title",
            "Fresh",
            "--vault",
            "Dev",
            "--field",
            "username=x",
        ],
    );
    ok(
        d,
        &[
            "item",
            "create",
            "login",
            "--title",
            "Elsewhere",
            "--field",
            "username=y",
        ],
    );
    observe(d);

    // The server sees the new item, and saves no stale state.
    let items = s.call("list_items", json!({"vault": "Dev"}));
    assert_eq!(items["isError"], false, "{items}");
    assert!(items.to_string().contains("Fresh"), "{items}");
    observe(d);
    assert_eq!(s.finish().0, 0);
    observe(d);
    assert_eq!(max.len(), 2, "both vaults are tracked");
}

#[test]
fn mcp_without_tty_or_env_password_fails_cleanly() {
    let tmp = fresh();
    let o = StdCommand::new(assert_cmd::cargo::cargo_bin("onepass"))
        .env_remove("ONEPASS_DEV_ALLOW_ENV_PASSWORD")
        .env_remove("ONEPASS_PASSWORD")
        .env("ONEPASS_DEV_NO_TTY", "1")
        .arg("--data-dir")
        .arg(tmp.path())
        .arg("mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(1));
    let stderr = String::from_utf8(o.stderr).unwrap();
    assert!(stderr.contains("/dev/tty"), "{stderr}");
    assert!(o.stdout.is_empty(), "nothing on the protocol channel");
}

#[test]
fn mcp_refuses_then_stops_when_travel_mode_changes_under_it() {
    let tmp = fresh();
    let d = tmp.path();
    let mut s = Server::start(d, &[]);
    let listed = s.call("list_vaults", json!({}));
    assert_eq!(listed["isError"], false, "{listed}");
    // travel.bin appears behind the server's back (the lock was bypassed).
    fs::write(d.join("travel.bin"), b"x").unwrap();
    let refused = s.call("list_vaults", json!({}));
    assert_eq!(refused["isError"], true, "{refused}");
    assert!(
        refused
            .to_string()
            .contains("Travel Mode changed while this server was running; restart it"),
        "{refused}"
    );
    // The server stops on its own, stdin still open.
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(st) = s.child.try_wait().unwrap() {
            break st;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the server kept running"
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    assert_eq!(status.code(), Some(1));
}

#[test]
fn unusable_audit_log_blocks_secret_tools_until_rotated() {
    let tmp = fresh();
    let d = tmp.path();
    let run_args = json!({
        "command": ["true"],
        "env": {"PW": "onepass://Dev/Server/password"},
    });
    let mut s = Server::start(d, &[]);
    let r = s.call("run_with_secrets", run_args.clone());
    assert_eq!(r["isError"], false, "{r}");
    assert_eq!(s.finish().0, 0);

    // One byte of the last entry changes: the log no longer matches its head.
    let log = d.join("audit.log");
    let mut bytes = fs::read(&log).unwrap();
    let at = bytes.len() - 10;
    bytes[at] ^= 0x01;
    fs::write(&log, &bytes).unwrap();

    let mut s = Server::start(d, &[]);
    let r = s.call("run_with_secrets", run_args.clone());
    assert_eq!(r["isError"], true, "{r}");
    assert!(
        r.to_string()
            .contains("audit log unusable; run onepass mcp audit --rotate"),
        "{r}"
    );
    // Metadata tools stay available.
    let l = s.call("list_items", json!({}));
    assert_eq!(l["isError"], false, "{l}");
    assert_eq!(s.finish().0, 0);

    let o = ok(d, &["mcp", "audit", "--rotate"]);
    assert!(o.stdout.contains("archived"), "{}", o.stdout);
    let archived: Vec<String> = fs::read_dir(d)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("audit.log.") && n.contains(".bad"))
        .collect();
    assert_eq!(archived.len(), 2, "{archived:?}");
    assert!(archived.iter().any(|n| n.ends_with(".bad")));
    assert!(archived.iter().any(|n| n.ends_with(".bad.head")));
    let bad = archived.iter().find(|n| n.ends_with(".bad")).unwrap();
    assert_eq!(fs::read(d.join(bad)).unwrap(), bytes);
    assert_eq!(fs::read(&log).unwrap(), b"");
    assert!(!d.join("audit.log.head").exists());

    let mut s = Server::start(d, &[]);
    let r = s.call("run_with_secrets", run_args);
    assert_eq!(r["isError"], false, "{r}");
    assert_eq!(s.finish().0, 0);
    let o = ok(d, &["mcp", "audit", "--verify"]);
    assert!(
        o.stdout.contains("audit log verified (1 entries)"),
        "{}",
        o.stdout
    );
}
