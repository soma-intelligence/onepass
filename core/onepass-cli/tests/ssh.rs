//! End-to-end tests of `onepass ssh-key` and `onepass ssh-agent`: the real
//! binary, with the real `ssh-keygen` and `ssh-add` where they exist (the
//! tests that need them say so and skip when they are missing).
//!
//! As in `tests/cli.rs`, the account is created once in a template
//! directory and every test works on its own copy. `HOME` always points to
//! an empty temporary directory: nothing here reads or writes `~/.ssh`.

use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command as StdCommand, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use assert_cmd::Command;
use serde_json::Value;

const PASSWORD: &str = "correct horse battery";
const PASSPHRASE: &str = "key pass phrase 7";

struct Out {
    code: i32,
    stdout: String,
    stderr: String,
}

/// The CLI on `dir`, with `HOME` set to `home` (an empty directory).
fn onepass(dir: &Path, home: &Path) -> Command {
    let mut c = Command::cargo_bin("onepass").unwrap();
    c.env("ONEPASS_DEV_ALLOW_ENV_PASSWORD", "1")
        .env("ONEPASS_PASSWORD", PASSWORD)
        .env("ONEPASS_DEV_FAST_KDF", "1")
        .env("ONEPASS_DEV_NO_TTY", "1")
        .env_remove("ONEPASS_DEV_SSH_PASSPHRASE")
        .env_remove("SSH_AUTH_SOCK")
        .env("HOME", home)
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

/// A test data directory and the empty home that goes with it.
struct Env {
    dir: tempfile::TempDir,
    home: tempfile::TempDir,
}

impl Env {
    fn path(&self) -> &Path {
        self.dir.path()
    }

    fn cmd(&self, args: &[&str]) -> Command {
        let mut c = onepass(self.dir.path(), self.home.path());
        c.args(args);
        c
    }

    fn run(&self, args: &[&str]) -> Out {
        output(self.cmd(args))
    }

    fn ok(&self, args: &[&str]) -> Out {
        let o = self.run(args);
        assert_eq!(o.code, 0, "{args:?}: {}", o.stderr);
        o
    }

    /// The home directory is still empty: no `.ssh` was created or used.
    fn assert_home_untouched(&self) {
        let left: Vec<_> = fs::read_dir(self.home.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert!(left.is_empty(), "HOME was written to: {left:?}");
    }
}

fn template() -> &'static PathBuf {
    static T: OnceLock<PathBuf> = OnceLock::new();
    T.get_or_init(|| {
        let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("ssh-template");
        let _ = fs::remove_dir_all(&dir);
        let home = tempfile::tempdir().unwrap();
        let o = output({
            let mut c = onepass(&dir, home.path());
            c.args(["account", "create"]);
            c
        });
        assert_eq!(o.code, 0, "{}", o.stderr);
        dir
    })
}

/// A private copy of the template directory.
fn fresh() -> Env {
    let t = template();
    let dir = tempfile::tempdir().unwrap();
    for entry in fs::read_dir(t).unwrap() {
        let entry = entry.unwrap();
        fs::copy(entry.path(), dir.path().join(entry.file_name())).unwrap();
    }
    Env {
        dir,
        home: tempfile::tempdir().unwrap(),
    }
}

/// Whether an OpenSSH tool is on the PATH.
fn have(tool: &str) -> bool {
    let found = StdCommand::new("sh")
        .arg("-c")
        .arg(format!("command -v {tool}"))
        .stdout(Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    if !found {
        eprintln!("skipped: {tool} not found");
    }
    found
}

/// The first JSON object printed on stdout.
fn json(o: &Out) -> Value {
    serde_json::from_str(o.stdout.trim()).unwrap()
}

/// `algorithm base64` of a public key line, without the comment.
fn key_part(line: &str) -> String {
    line.split_whitespace()
        .take(2)
        .collect::<Vec<_>>()
        .join(" ")
}

fn mode(p: &Path) -> u32 {
    fs::metadata(p).unwrap().permissions().mode() & 0o777
}

#[test]
fn generate_each_type_creates_item() {
    let e = fresh();
    for (t, algorithm) in [
        ("ed25519", "ssh-ed25519"),
        ("ecdsa-p256", "ecdsa-sha2-nistp256"),
        ("ecdsa-p384", "ecdsa-sha2-nistp384"),
        ("ecdsa-p521", "ecdsa-sha2-nistp521"),
        ("rsa-3072", "ssh-rsa"),
        ("rsa-4096", "ssh-rsa"),
    ] {
        let title = format!("key {t}");
        let o = e.ok(&[
            "--json",
            "ssh-key",
            "generate",
            "--type",
            t,
            "--title",
            &title,
            "--agent",
            "--comment",
            "dev@onepass.test",
        ]);
        let created = json(&o);
        let fingerprint = created["fingerprint"].as_str().unwrap().to_owned();
        assert!(fingerprint.starts_with("SHA256:"), "{fingerprint}");
        let public = e.ok(&["ssh-key", "public", &title]).stdout;
        let line = public.trim();
        assert!(line.starts_with(&format!("{algorithm} ")), "{t}: {line}");
        assert!(line.ends_with(" dev@onepass.test"), "{line}");
        assert_eq!(public.lines().count(), 1);
        // The item: algorithm, comment and agent settings as menus, the
        // private key hidden unless revealed.
        let item = json(&e.ok(&["--json", "item", "get", &title]));
        let field = |id: &str| -> Value {
            item["fields"]
                .as_array()
                .unwrap()
                .iter()
                .find(|f| f["id"] == id)
                .map(|f| f["value"].clone())
                .unwrap()
        };
        assert_eq!(field("algorithm"), algorithm);
        assert_eq!(field("comment"), "dev@onepass.test");
        assert_eq!(field("use_in_agent"), "yes");
        assert_eq!(field("confirm_each_use"), "no");
        let hidden = field("private_key");
        assert!(hidden.as_str().unwrap().contains(&fingerprint), "{hidden}");
        let revealed = json(&e.ok(&["--json", "item", "get", &title, "--reveal"]));
        let pem = revealed["fields"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["id"] == "private_key")
            .unwrap()["value"]
            .as_str()
            .unwrap()
            .to_owned();
        assert!(pem.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"));
    }
    // The defaults: ed25519, the title as comment, Personnel vault.
    let o = e.ok(&[
        "ssh-key",
        "generate",
        "--title",
        "Default",
        "--confirm-each-use",
    ]);
    assert!(o.stdout.contains("created "), "{}", o.stdout);
    let public = e.ok(&["ssh-key", "public", "Default", "--vault", "Personnel"]);
    assert!(public.stdout.starts_with("ssh-ed25519 "));
    assert!(public.stdout.trim_end().ends_with(" Default"));
    let item = json(&e.ok(&["--json", "item", "get", "Default"]));
    assert_eq!(item["vault"], "Personnel");
    let use_in_agent = item["fields"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["id"] == "use_in_agent")
        .unwrap()["value"]
        .clone();
    assert_eq!(use_in_agent, "no");
    // `public` of something that is not an SSH key, or of nothing.
    e.ok(&[
        "item",
        "create",
        "login",
        "--title",
        "Site",
        "--field",
        "username=u",
    ]);
    assert_eq!(e.run(&["ssh-key", "public", "Site"]).code, 1);
    assert_eq!(e.run(&["ssh-key", "public", "Nothing"]).code, 4);
    e.assert_home_untouched();
}

#[test]
fn rsa_2048_is_not_offered() {
    let e = fresh();
    let o = e.run(&[
        "ssh-key", "generate", "--type", "rsa-2048", "--title", "Weak",
    ]);
    assert_eq!(o.code, 1, "{}", o.stderr);
    assert!(o.stderr.contains("rsa-2048"), "{}", o.stderr);
    assert!(o.stderr.contains("rsa-3072"), "{}", o.stderr);
    for bad in ["dsa", "rsa", "ED25519"] {
        assert_eq!(
            e.run(&["ssh-key", "generate", "--type", bad, "--title", "X"])
                .code,
            1
        );
    }
    // Nothing was created.
    let list = e.ok(&["item", "list"]);
    assert!(list.stdout.trim().is_empty(), "{}", list.stdout);
}

/// `ssh-keygen` in `dir` writing `name` (and `name.pub`).
fn keygen(dir: &Path, name: &str, extra: &[&str], passphrase: &str) -> PathBuf {
    let path = dir.join(name);
    let st = StdCommand::new("ssh-keygen")
        .args(["-q", "-C", "imported@onepass.test", "-N", passphrase, "-f"])
        .arg(&path)
        .args(extra)
        .env("HOME", dir)
        .stdin(Stdio::null())
        .status()
        .unwrap();
    assert!(st.success());
    path
}

#[test]
fn import_ssh_keygen_key_and_encrypted_key() {
    if !have("ssh-keygen") {
        return;
    }
    let e = fresh();
    let keys = tempfile::tempdir().unwrap();
    let pubkey = |p: &Path| {
        let mut s = p.as_os_str().to_owned();
        s.push(".pub");
        key_part(&fs::read_to_string(PathBuf::from(s)).unwrap())
    };

    // Unencrypted OpenSSH key.
    let plain = keygen(keys.path(), "plain", &["-t", "ed25519"], "");
    let o = e.ok(&[
        "--json",
        "ssh-key",
        "import",
        plain.to_str().unwrap(),
        "--title",
        "Plain",
        "--agent",
        "--host",
        "git.example.test",
    ]);
    assert!(
        json(&o)["fingerprint"]
            .as_str()
            .unwrap()
            .starts_with("SHA256:")
    );
    let public = e.ok(&["ssh-key", "public", "Plain"]).stdout;
    assert_eq!(key_part(&public), pubkey(&plain));
    // The fingerprint matches what ssh-keygen computes.
    let lf = StdCommand::new("ssh-keygen")
        .env("HOME", keys.path())
        .arg("-lf")
        .arg(&plain)
        .output()
        .unwrap();
    let lf = String::from_utf8(lf.stdout).unwrap();
    assert!(
        lf.contains(json(&o)["fingerprint"].as_str().unwrap()),
        "{lf}"
    );

    // Encrypted OpenSSH key: no passphrase source, a wrong one, the right one.
    let enc = keygen(
        keys.path(),
        "enc",
        &["-t", "ecdsa", "-b", "384"],
        PASSPHRASE,
    );
    let enc_s = enc.to_str().unwrap();
    let o = e.run(&["ssh-key", "import", enc_s, "--title", "Enc"]);
    assert_eq!(o.code, 1, "{}", o.stderr);
    assert!(o.stderr.contains("passphrase"), "{}", o.stderr);
    let mut c = e.cmd(&["ssh-key", "import", enc_s, "--title", "Enc"]);
    c.env("ONEPASS_DEV_SSH_PASSPHRASE", "not it");
    let o = output(c);
    assert_eq!(o.code, 1, "{}", o.stderr);
    assert!(o.stderr.contains("wrong passphrase"), "{}", o.stderr);
    assert!(!o.stderr.contains("not it"));
    // The env passphrase needs the dev switch.
    let mut c = e.cmd(&["ssh-key", "import", enc_s, "--title", "Enc"]);
    c.env("ONEPASS_DEV_SSH_PASSPHRASE", PASSPHRASE)
        .env_remove("ONEPASS_DEV_ALLOW_ENV_PASSWORD");
    assert_ne!(output(c).code, 0);
    let mut c = e.cmd(&["ssh-key", "import", enc_s, "--title", "Enc"]);
    c.env("ONEPASS_DEV_SSH_PASSPHRASE", PASSPHRASE);
    let o = output(c);
    assert_eq!(o.code, 0, "{}", o.stderr);
    let public = e.ok(&["ssh-key", "public", "Enc"]).stdout;
    assert_eq!(key_part(&public), pubkey(&enc));
    // Stored unencrypted, the passphrase kept nowhere.
    let revealed = e.ok(&["--json", "item", "get", "Enc", "--reveal"]).stdout;
    assert!(!revealed.contains(PASSPHRASE));
    let item: Value = serde_json::from_str(revealed.trim()).unwrap();
    let field = |id: &str| -> Value {
        item["fields"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["id"] == id)
            .unwrap()["value"]
            .clone()
    };
    assert_eq!(field("passphrase"), Value::Null);
    assert_eq!(field("algorithm"), "ecdsa-sha2-nistp384");
    let pem = field("private_key");
    assert!(
        pem.as_str()
            .unwrap()
            .starts_with("-----BEGIN OPENSSH PRIVATE KEY-----")
    );
    // ssh-keygen reads the stored key back without a passphrase.
    let back = keys.path().join("back");
    fs::write(&back, pem.as_str().unwrap()).unwrap();
    fs::set_permissions(&back, fs::Permissions::from_mode(0o600)).unwrap();
    let y = StdCommand::new("ssh-keygen")
        .env("HOME", keys.path())
        .args(["-y", "-P", "", "-f"])
        .arg(&back)
        .output()
        .unwrap();
    assert!(y.status.success(), "{}", String::from_utf8_lossy(&y.stderr));
    assert_eq!(
        key_part(&String::from_utf8(y.stdout).unwrap()),
        pubkey(&enc)
    );

    // PEM PKCS#1 RSA 2048: accepted at import (refused only at generation).
    let rsa = keygen(
        keys.path(),
        "rsa",
        &["-t", "rsa", "-b", "2048", "-m", "PEM"],
        "",
    );
    assert!(
        fs::read_to_string(&rsa)
            .unwrap()
            .starts_with("-----BEGIN RSA PRIVATE KEY-----")
    );
    e.ok(&["ssh-key", "import", rsa.to_str().unwrap(), "--title", "Rsa"]);
    let public = e.ok(&["ssh-key", "public", "Rsa"]).stdout;
    assert_eq!(key_part(&public), pubkey(&rsa));

    // A file that is no key, a missing file.
    let junk = keys.path().join("junk");
    fs::write(&junk, "hello").unwrap();
    assert_eq!(
        e.run(&["ssh-key", "import", junk.to_str().unwrap(), "--title", "J"])
            .code,
        1
    );
    assert_eq!(
        e.run(&["ssh-key", "import", "/nonexistent/key", "--title", "J"])
            .code,
        1
    );
    e.assert_home_untouched();
}

#[test]
fn bookmark_add_remove_and_config() {
    let e = fresh();
    e.ok(&[
        "ssh-key",
        "generate",
        "--title",
        "Git",
        "--agent",
        "--host",
        "git.example.test",
    ]);
    e.ok(&["ssh-key", "bookmark", "add", "Git", "*.old.example.test"]);
    e.ok(&["ssh-key", "bookmark", "add", "Git", "ci.example.test"]);
    // Adding twice changes nothing.
    e.ok(&["ssh-key", "bookmark", "add", "Git", "ci.example.test"]);
    e.ok(&["ssh-key", "bookmark", "remove", "Git", "*.old.example.test"]);
    assert_eq!(
        e.run(&[
            "ssh-key",
            "bookmark",
            "remove",
            "Git",
            "absent.example.test"
        ])
        .code,
        4
    );
    // A bookmark that would break the generated config.
    for bad in ["two words", "", "quo\"te", "new\nline"] {
        assert_eq!(
            e.run(&["ssh-key", "bookmark", "add", "Git", bad]).code,
            1,
            "{bad:?}"
        );
    }
    let item = json(&e.ok(&["--json", "item", "get", "Git"]));
    let hosts: Vec<Value> = item["fields"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["id"] == "hosts")
        .map(|f| f["value"].clone())
        .collect();
    assert_eq!(hosts, ["git.example.test", "ci.example.test"]);
    // Keys without a bookmark, or not in the agent, get no Host block.
    e.ok(&["ssh-key", "generate", "--title", "Loose", "--agent"]);
    e.ok(&[
        "ssh-key",
        "generate",
        "--title",
        "Off",
        "--host",
        "off.example.test",
    ]);

    let out_dir = tempfile::tempdir().unwrap();
    // Created by the command, 0700.
    let out = out_dir.path().join("cfg");
    let o = e.ok(&["ssh-key", "config", "--out", out.to_str().unwrap()]);
    let config_path = out.join("config");
    assert!(
        o.stdout
            .contains(&format!("Include \"{}\"", config_path.display())),
        "{}",
        o.stdout
    );
    let config = fs::read_to_string(&config_path).unwrap();
    assert!(
        config.contains("Host git.example.test ci.example.test"),
        "{config}"
    );
    assert!(!config.contains("old.example.test"), "{config}");
    assert!(!config.contains("off.example.test"), "{config}");
    assert!(config.contains("IdentitiesOnly yes"), "{config}");
    let socket = e.path().join("ssh-agent.sock");
    assert!(
        config.contains(&format!("IdentityAgent \"{}\"", socket.display())),
        "{config}"
    );
    let public = e.ok(&["ssh-key", "public", "Git"]).stdout;
    let fingerprint = json(&e.ok(&["--json", "item", "get", "Git"]))["fields"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["id"] == "private_key")
        .unwrap()["value"]
        .as_str()
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .to_owned();
    let stem = fingerprint
        .trim_start_matches("SHA256:")
        .replace('/', "_")
        .replace('+', "-");
    let pub_path = out.join(format!("{stem}.pub"));
    assert!(
        config.contains(&format!("IdentityFile \"{}\"", pub_path.display())),
        "{config}"
    );
    assert_eq!(
        key_part(&fs::read_to_string(&pub_path).unwrap()),
        key_part(&public)
    );
    assert_eq!(mode(&out), 0o700);
    assert_eq!(mode(&config_path), 0o600);
    assert_eq!(mode(&pub_path), 0o600);
    // Only the Git key has a Host block: config and one public key.
    assert_eq!(fs::read_dir(&out).unwrap().count(), 2);

    // An explicit socket, and a second run over the same directory.
    e.ok(&[
        "ssh-key",
        "config",
        "--out",
        out.to_str().unwrap(),
        "--socket",
        "/run/onepass/agent.sock",
    ]);
    let config = fs::read_to_string(&config_path).unwrap();
    assert!(config.contains("IdentityAgent \"/run/onepass/agent.sock\""));

    // The out directory may not be ~/.ssh, whose config it would replace.
    let o = e.run(&[
        "ssh-key",
        "config",
        "--out",
        e.home.path().join(".ssh").to_str().unwrap(),
    ]);
    assert_eq!(o.code, 1, "{}", o.stderr);
    e.assert_home_untouched();
}

#[test]
fn config_never_replaces_foreign_files_nor_loosens_directories() {
    let e = fresh();
    e.ok(&[
        "ssh-key",
        "generate",
        "--title",
        "Git",
        "--agent",
        "--host",
        "git.example.test",
    ]);
    let work = tempfile::tempdir().unwrap();
    let out_arg = |p: &Path| p.to_str().unwrap().to_owned();

    // A directory holding someone else's `config` (a kubeconfig, say).
    let foreign = work.path().join("foreign");
    fs::create_dir(&foreign).unwrap();
    fs::set_permissions(&foreign, fs::Permissions::from_mode(0o700)).unwrap();
    let theirs = "apiVersion: v1\nclusters: []\n";
    fs::write(foreign.join("config"), theirs).unwrap();
    let o = e.run(&["ssh-key", "config", "--out", &out_arg(&foreign)]);
    assert_eq!(o.code, 1, "{}", o.stderr);
    assert_eq!(fs::read_to_string(foreign.join("config")).unwrap(), theirs);
    assert_eq!(fs::read_dir(&foreign).unwrap().count(), 1);

    // An existing directory that is not 0700 is neither used nor chmodded.
    let open = work.path().join("open");
    fs::create_dir(&open).unwrap();
    fs::set_permissions(&open, fs::Permissions::from_mode(0o755)).unwrap();
    let o = e.run(&["ssh-key", "config", "--out", &out_arg(&open)]);
    assert_eq!(o.code, 1, "{}", o.stderr);
    assert_eq!(mode(&open), 0o755);
    assert_eq!(fs::read_dir(&open).unwrap().count(), 0);

    // `..` and symlinks do not lead into ~/.ssh.
    let dotdot = e.home.path().join("nonexistent").join("..").join(".ssh");
    let o = e.run(&["ssh-key", "config", "--out", &out_arg(&dotdot)]);
    assert_eq!(o.code, 1, "{}", o.stderr);
    let link = work.path().join("home-link");
    std::os::unix::fs::symlink(e.home.path(), &link).unwrap();
    let o = e.run(&["ssh-key", "config", "--out", &out_arg(&link.join(".ssh"))]);
    assert_eq!(o.code, 1, "{}", o.stderr);
    e.assert_home_untouched();

    // A directory the command made, then a rerun over its own config.
    let mine = work.path().join("a").join("b");
    e.ok(&["ssh-key", "config", "--out", &out_arg(&mine)]);
    assert_eq!(mode(&mine), 0o700);
    e.ok(&["ssh-key", "config", "--out", &out_arg(&mine)]);
    // A config symlinked elsewhere is refused, its target untouched.
    let target = work.path().join("target");
    fs::write(&target, theirs).unwrap();
    fs::remove_file(mine.join("config")).unwrap();
    std::os::unix::fs::symlink(&target, mine.join("config")).unwrap();
    assert_eq!(
        e.run(&["ssh-key", "config", "--out", &out_arg(&mine)]).code,
        1
    );
    assert_eq!(fs::read_to_string(&target).unwrap(), theirs);
}

/// A running `onepass ssh-agent`.
struct AgentProc {
    child: Child,
    socket: PathBuf,
    _sock_dir: tempfile::TempDir,
}

impl AgentProc {
    fn start(e: &Env) -> AgentProc {
        // Socket paths are short on macOS (104 bytes): a fresh short dir.
        let sock_dir = tempfile::Builder::new()
            .prefix("opa")
            .tempdir_in("/tmp")
            .unwrap();
        let socket = sock_dir.path().join("s").join("agent.sock");
        let child = StdCommand::new(assert_cmd::cargo::cargo_bin("onepass"))
            .env("ONEPASS_DEV_ALLOW_ENV_PASSWORD", "1")
            .env("ONEPASS_PASSWORD", PASSWORD)
            .env("ONEPASS_DEV_AUTO_APPROVE", "once")
            .env("HOME", e.home.path())
            .env_remove("SSH_AUTH_SOCK")
            .arg("--data-dir")
            .arg(e.path())
            .arg("ssh-agent")
            .arg("--socket")
            .arg(&socket)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(60);
        while UnixStream::connect(&socket).is_err() {
            assert!(Instant::now() < deadline, "the agent never listened");
            std::thread::sleep(Duration::from_millis(50));
        }
        AgentProc {
            child,
            socket,
            _sock_dir: sock_dir,
        }
    }

    fn ssh_tool(&self, tool: &str, home: &Path) -> StdCommand {
        let mut c = StdCommand::new(tool);
        c.env("SSH_AUTH_SOCK", &self.socket)
            .env("HOME", home)
            .stdin(Stdio::null());
        c
    }

    /// Send `signal` (`TERM`, `INT`), then the exit status, stdout and
    /// stderr.
    fn terminate(mut self, signal: &str) -> (i32, String, String) {
        let st = StdCommand::new("kill")
            .arg(format!("-{signal}"))
            .arg(self.child.id().to_string())
            .status()
            .unwrap();
        assert!(st.success());
        let deadline = Instant::now() + Duration::from_secs(10);
        let status = loop {
            if let Some(s) = self.child.try_wait().unwrap() {
                break s;
            }
            assert!(Instant::now() < deadline, "the agent did not stop");
            std::thread::sleep(Duration::from_millis(50));
        };
        let mut out = String::new();
        let mut err = String::new();
        self.child
            .stdout
            .take()
            .unwrap()
            .read_to_string(&mut out)
            .unwrap();
        self.child
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut err)
            .unwrap();
        (status.code().unwrap_or(-1), out, err)
    }
}

impl Drop for AgentProc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// REQUEST_IDENTITIES over the raw protocol: the comments of the keys.
fn identities(socket: &Path) -> Vec<String> {
    let mut s = UnixStream::connect(socket).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    s.write_all(&[0, 0, 0, 1, 11]).unwrap();
    let mut len = [0u8; 4];
    s.read_exact(&mut len).unwrap();
    let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
    s.read_exact(&mut body).unwrap();
    assert_eq!(body[0], 12, "IDENTITIES_ANSWER");
    let u32_at = |b: &[u8], at: usize| u32::from_be_bytes(b[at..at + 4].try_into().unwrap());
    let n = u32_at(&body, 1);
    let mut at = 5;
    let mut comments = Vec::new();
    for _ in 0..n {
        let blob_len = u32_at(&body, at) as usize;
        at += 4 + blob_len;
        let c_len = u32_at(&body, at) as usize;
        at += 4;
        comments.push(String::from_utf8(body[at..at + c_len].to_vec()).unwrap());
        at += c_len;
    }
    assert_eq!(at, body.len());
    comments
}

#[test]
fn agent_end_to_end_with_ssh_add() {
    if !have("ssh-add") || !have("ssh-keygen") {
        return;
    }
    let e = fresh();
    e.ok(&["ssh-key", "generate", "--title", "Agent key", "--agent"]);
    e.ok(&[
        "ssh-key",
        "generate",
        "--type",
        "ecdsa-p256",
        "--title",
        "Second",
        "--agent",
    ]);
    let public = e.ok(&["ssh-key", "public", "Agent key"]).stdout;
    let agent = AgentProc::start(&e);
    let work = tempfile::tempdir().unwrap();

    let l = agent
        .ssh_tool("ssh-add", work.path())
        .arg("-l")
        .output()
        .unwrap();
    assert!(l.status.success(), "{}", String::from_utf8_lossy(&l.stderr));
    let listed = String::from_utf8(l.stdout).unwrap();
    let fingerprint = json(&e.ok(&["--json", "item", "get", "Agent key"]))["fields"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["id"] == "private_key")
        .unwrap()["value"]
        .as_str()
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .to_owned();
    assert!(listed.contains(&fingerprint), "{listed}");
    assert!(listed.contains("Agent key"), "{listed}");
    assert!(listed.contains("Second"), "{listed}");
    let big_l = agent
        .ssh_tool("ssh-add", work.path())
        .arg("-L")
        .output()
        .unwrap();
    let big_l = String::from_utf8(big_l.stdout).unwrap();
    assert!(big_l.contains(&key_part(&public)), "{big_l}");

    // Clients cannot add keys: they come from the vault.
    let extra = keygen(work.path(), "extra", &["-t", "ed25519"], "");
    let add = agent
        .ssh_tool("ssh-add", work.path())
        .arg(&extra)
        .output()
        .unwrap();
    assert!(!add.status.success());

    // ssh-keygen -Y sign through the agent, then -Y verify.
    let pub_file = work.path().join("agent_key.pub");
    fs::write(&pub_file, &public).unwrap();
    let data = work.path().join("data.txt");
    fs::write(&data, b"signed through the onepass agent\n").unwrap();
    let sign = agent
        .ssh_tool("ssh-keygen", work.path())
        .args(["-Y", "sign", "-n", "file", "-f"])
        .arg(&pub_file)
        .arg(&data)
        .output()
        .unwrap();
    assert!(
        sign.status.success(),
        "{}",
        String::from_utf8_lossy(&sign.stderr)
    );
    let sig = work.path().join("data.txt.sig");
    assert!(sig.exists());
    let allowed = work.path().join("allowed_signers");
    fs::write(
        &allowed,
        format!("dev@onepass.test {}\n", key_part(&public)),
    )
    .unwrap();
    let verify = StdCommand::new("ssh-keygen")
        .env("HOME", work.path())
        .args(["-Y", "verify", "-n", "file", "-I", "dev@onepass.test", "-f"])
        .arg(&allowed)
        .arg("-s")
        .arg(&sig)
        .stdin(fs::File::open(&data).unwrap())
        .output()
        .unwrap();
    assert!(
        verify.status.success(),
        "{}{}",
        String::from_utf8_lossy(&verify.stdout),
        String::from_utf8_lossy(&verify.stderr)
    );

    let socket = agent.socket.clone();
    let (code, stdout, stderr) = agent.terminate("TERM");
    assert_eq!(code, 0, "{stderr}");
    assert!(stdout.is_empty(), "{stdout}");
    assert!(
        stderr.contains(&format!(
            "SSH_AUTH_SOCK='{}'; export SSH_AUTH_SOCK;",
            socket.display()
        )),
        "{stderr}"
    );
    assert!(!socket.exists(), "the socket was left behind");
    // The signature was audited.
    let audit = e.ok(&["mcp", "audit"]).stdout;
    assert!(audit.contains("ssh"), "{audit}");
    assert!(audit.contains("action=ssh_sign"), "{audit}");
    e.assert_home_untouched();
}

#[test]
fn agent_lists_only_use_in_agent_keys() {
    let e = fresh();
    e.ok(&["ssh-key", "generate", "--title", "In agent", "--agent"]);
    e.ok(&["ssh-key", "generate", "--title", "Not in agent"]);
    e.ok(&["ssh-key", "generate", "--title", "Trashed", "--agent"]);
    e.ok(&["item", "delete", "Trashed"]);
    let agent = AgentProc::start(&e);
    assert_eq!(identities(&agent.socket), ["In agent"]);
    // Read again at each request: a key generated while the agent runs
    // shows up, and the CLI stays usable meanwhile.
    e.ok(&["ssh-key", "generate", "--title", "Later", "--agent"]);
    let mut now = identities(&agent.socket);
    now.sort();
    assert_eq!(now, ["In agent", "Later"]);
    let socket = agent.socket.clone();
    let (code, _, stderr) = agent.terminate("INT");
    assert_eq!(code, 0, "{stderr}");
    assert!(!socket.exists(), "the socket was left behind");
}
