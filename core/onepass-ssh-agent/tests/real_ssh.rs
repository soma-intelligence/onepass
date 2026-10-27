//! The agent against the real OpenSSH tools: `ssh-add`, `ssh-keygen -Y`
//! and an unprivileged `sshd` on 127.0.0.1. Each test prints a message and
//! passes when a tool is missing or cannot start.
//!
//! Nothing touches the user's `~/.ssh`: every child gets `HOME` set to a
//! temporary directory, `ssh` runs with `-F /dev/null` and explicit
//! identity, known_hosts and authorized_keys files under that directory.

mod common;

use std::fs;
use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use common::*;
use onepass_guard::{ApprovalRequest, Approver, Decision, DevAutoApprover};
use onepass_ssh_agent::keys::{AgentKey, KeyType, fingerprint_of_blob};
use onepass_ssh_agent::{Agent, AgentConfig, bind_socket, serve};
use tempfile::TempDir;

const SSHD: &str = "/usr/sbin/sshd";

/// `DevAutoApprover(AllowOnce)` that also keeps the requests it saw.
struct Recording {
    inner: DevAutoApprover,
    seen: Mutex<Vec<ApprovalRequest>>,
}

impl Approver for Recording {
    fn approve(&self, req: &ApprovalRequest) -> Decision {
        self.seen.lock().unwrap().push(req.clone());
        self.inner.approve(req)
    }
}

/// A running agent on a temporary socket.
struct Running {
    dir: TempDir,
    socket: PathBuf,
    audit: SharedAudit,
    approver: Arc<Recording>,
    stop: Arc<AtomicBool>,
    server: Option<JoinHandle<std::io::Result<()>>>,
}

impl Running {
    fn start(source: FakeSource, known_hosts: Vec<PathBuf>, dir: TempDir) -> Running {
        let socket = dir.path().join("agent").join("s.sock");
        let listener = bind_socket(&socket).unwrap();
        let audit = SharedAudit::default();
        let approver = Arc::new(Recording {
            inner: DevAutoApprover(Decision::AllowOnce),
            seen: Mutex::new(Vec::new()),
        });
        let agent = Agent::new(
            source,
            approver.clone(),
            Box::new(audit.clone()),
            AgentConfig {
                known_hosts,
                ..AgentConfig::default()
            },
        );
        let stop = Arc::new(AtomicBool::new(false));
        let server = {
            let stop = stop.clone();
            let agent = Arc::new(Mutex::new(agent));
            thread::spawn(move || serve(listener, agent, stop))
        };
        Running {
            dir,
            socket,
            audit,
            approver,
            stop,
            server: Some(server),
        }
    }

    fn home(&self) -> &Path {
        self.dir.path()
    }

    /// A command with `HOME` in the temporary directory and the agent
    /// socket as `SSH_AUTH_SOCK`.
    fn command(&self, program: &str) -> Command {
        let mut c = Command::new(program);
        c.env("HOME", self.home())
            .env("SSH_AUTH_SOCK", &self.socket)
            .current_dir(self.home())
            .stdin(Stdio::null());
        c
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.server.take() {
            let _ = h.join();
        }
    }
}

/// A temporary directory with a short path (Unix socket paths are limited
/// to about 100 bytes).
fn short_tempdir() -> TempDir {
    let dir = TempDir::new().unwrap();
    if dir.path().as_os_str().len() < 60 {
        return dir;
    }
    tempfile::Builder::new()
        .prefix("opssh")
        .tempdir_in("/tmp")
        .unwrap()
}

fn have(program: &str, probe: &[&str]) -> bool {
    let found = Command::new(program)
        .args(probe)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok();
    if !found {
        eprintln!("skipping: {program} not found");
    }
    found
}

fn check(out: &Output, what: &str) {
    assert!(
        out.status.success(),
        "{what} failed ({:?}): stdout {} stderr {}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

fn write_private(path: &Path, text: &str) {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    f.write_all(text.as_bytes()).unwrap();
}

#[test]
fn ssh_add_lists_vault_keys() {
    if !have("ssh-add", &["-h"]) {
        return;
    }
    let agent = Running::start(FakeSource::all(), vec![], short_tempdir());
    let out = agent.command("ssh-add").arg("-l").output().unwrap();
    check(&out, "ssh-add -l");
    let listing = String::from_utf8(out.stdout).unwrap();
    for t in TYPES {
        let line = listing
            .lines()
            .find(|l| l.contains(&key(t).fingerprint()))
            .unwrap_or_else(|| panic!("{t:?} missing from ssh-add -l:\n{listing}"));
        assert!(line.contains(&title_of(t)), "{line}");
    }
    assert_eq!(listing.lines().count(), TYPES.len());
    // ssh-add -L prints the public keys with their titles.
    let out = agent.command("ssh-add").arg("-L").output().unwrap();
    check(&out, "ssh-add -L");
    let public = String::from_utf8(out.stdout).unwrap();
    for t in TYPES {
        let expected = key(t).public_openssh(&title_of(t));
        assert!(
            public.lines().any(|l| l == expected),
            "{expected}\n{public}"
        );
    }
    // Adding a key is refused.
    let extra = agent.home().join("extra");
    write_private(
        &extra,
        &AgentKey::generate(KeyType::Ed25519)
            .unwrap()
            .to_openssh_private("x")
            .unwrap(),
    );
    let out = agent.command("ssh-add").arg(&extra).output().unwrap();
    assert!(!out.status.success());
    assert!(agent.approver.seen.lock().unwrap().is_empty());
}

#[test]
fn ssh_keygen_signs_through_agent() {
    if !have("ssh-keygen", &["-?"]) {
        return;
    }
    let agent = Running::start(FakeSource::all(), vec![], short_tempdir());
    let home = agent.home().to_path_buf();
    for t in [KeyType::Ed25519, KeyType::EcdsaP256, KeyType::Rsa3072] {
        let k = key(t);
        let name = format!("{t:?}").to_lowercase();
        let public = home.join(format!("{name}.pub"));
        fs::write(&public, k.public_openssh("signer") + "\n").unwrap();
        let message = home.join(format!("{name}.txt"));
        fs::write(&message, b"commit message to sign\n").unwrap();

        let out = agent
            .command("ssh-keygen")
            .args(["-Y", "sign", "-n", "git", "-f"])
            .arg(&public)
            .arg(&message)
            .output()
            .unwrap();
        check(&out, "ssh-keygen -Y sign");
        let signature = home.join(format!("{name}.txt.sig"));
        assert!(signature.exists());

        let allowed = home.join(format!("{name}.allowed"));
        fs::write(
            &allowed,
            format!(
                "signer@example.test namespaces=\"git\" {}\n",
                k.public_openssh("")
            ),
        )
        .unwrap();
        let out = agent
            .command("ssh-keygen")
            .args([
                "-Y",
                "verify",
                "-I",
                "signer@example.test",
                "-n",
                "git",
                "-f",
            ])
            .arg(&allowed)
            .arg("-s")
            .arg(&signature)
            .stdin(fs::File::open(&message).unwrap())
            .output()
            .unwrap();
        check(&out, "ssh-keygen -Y verify");

        let seen = agent.approver.seen.lock().unwrap().clone();
        let call = seen.last().unwrap();
        assert!(
            call.details
                .iter()
                .any(|(l, v)| l == "namespace" && v == "git"),
            "{call:?}"
        );
        assert_eq!(
            call.details
                .iter()
                .find(|(l, _)| l == "fingerprint")
                .map(|(_, v)| v.clone()),
            Some(k.fingerprint())
        );
    }
    let audit = agent.audit.entries();
    assert_eq!(audit.len(), 3);
    assert!(
        audit
            .iter()
            .all(|e| e.action == "ssh_sign" && e.outcome == "ok")
    );
}

/// Kills and reaps the test sshd on every exit path.
struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn current_user(home: &Path) -> Option<String> {
    let out = Command::new("id")
        .arg("-un")
        .env("HOME", home)
        .stdin(Stdio::null())
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_owned())
        .filter(|u| !u.is_empty())
}

/// Starts sshd and waits until it listens, or `None` with a message.
fn start_sshd(home: &Path, config: &Path, port: u16) -> Option<Daemon> {
    let test = Command::new(SSHD)
        .arg("-t")
        .arg("-f")
        .arg(config)
        .env("HOME", home)
        .stdin(Stdio::null())
        .output();
    match test {
        Ok(out) if out.status.success() => {}
        Ok(out) => {
            eprintln!(
                "skipping: {SSHD} -t rejected the test config: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            return None;
        }
        Err(e) => {
            eprintln!("skipping: cannot run {SSHD}: {e}");
            return None;
        }
    }
    let child = Command::new(SSHD)
        .args(["-D", "-e", "-f"])
        .arg(config)
        .arg("-p")
        .arg(port.to_string())
        .env("HOME", home)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(fs::File::create(home.join("sshd.log")).unwrap())
        .spawn();
    let mut daemon = match child {
        Ok(c) => Daemon(c),
        Err(e) => {
            eprintln!("skipping: cannot start {SSHD}: {e}");
            return None;
        }
    };
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if let Ok(Some(status)) = daemon.0.try_wait() {
            eprintln!(
                "skipping: {SSHD} exited ({status}): {}",
                fs::read_to_string(home.join("sshd.log")).unwrap_or_default()
            );
            return None;
        }
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return Some(daemon);
        }
        thread::sleep(Duration::from_millis(50));
    }
    eprintln!("skipping: {SSHD} did not listen on 127.0.0.1:{port} within 5 s");
    None
}

#[test]
fn ssh_connects_to_local_sshd() {
    if !Path::new(SSHD).exists() {
        eprintln!("skipping: {SSHD} not found");
        return;
    }
    if !have("ssh", &["-V"]) {
        return;
    }
    let dir = short_tempdir();
    let home = dir.path().to_path_buf();
    let Some(user) = current_user(&home) else {
        eprintln!("skipping: cannot tell the current user name");
        return;
    };

    let host_key = AgentKey::generate(KeyType::Ed25519).unwrap();
    let host_key_path = home.join("host_ed25519");
    write_private(
        &host_key_path,
        &host_key.to_openssh_private("host").unwrap(),
    );
    let user_key = key(KeyType::Ed25519);
    let authorized = home.join("authorized_keys");
    fs::write(&authorized, user_key.public_openssh("onepass test") + "\n").unwrap();
    let identity = home.join("id_ed25519.pub");
    fs::write(&identity, user_key.public_openssh("onepass test") + "\n").unwrap();
    let known_hosts = home.join("known_hosts");
    let port = free_port();
    let config = home.join("sshd_config");
    fs::write(
        &config,
        format!(
            "HostKey {}\n\
             AuthorizedKeysFile {}\n\
             PidFile {}\n\
             UsePAM no\n\
             StrictModes no\n\
             ListenAddress 127.0.0.1\n\
             PubkeyAuthentication yes\n\
             PasswordAuthentication no\n\
             KbdInteractiveAuthentication no\n\
             PermitUserRC no\n\
             PermitUserEnvironment no\n\
             AllowAgentForwarding no\n\
             AllowTcpForwarding no\n\
             X11Forwarding no\n\
             PrintMotd no\n",
            host_key_path.display(),
            authorized.display(),
            home.join("sshd.pid").display(),
        ),
    )
    .unwrap();
    let Some(_daemon) = start_sshd(&home, &config, port) else {
        return;
    };

    let source = FakeSource::with(&[KeyType::Ed25519]);
    source.edit(KeyType::Ed25519, |k| k.hosts = vec!["127.0.0.1".into()]);
    let agent = Running::start(source, vec![known_hosts.clone()], dir);
    // The agent is proven reachable and listing the key before the ssh
    // attempt: only then may an sshd refusal be blamed on the environment.
    let listed = have("ssh-add", &["-h"]) && {
        let l = agent.command("ssh-add").arg("-l").output().unwrap();
        l.status.success()
            && String::from_utf8_lossy(&l.stdout)
                .contains(&fingerprint_of_blob(&user_key.public_blob()))
    };
    let out = agent
        .command("ssh")
        .arg("-F")
        .arg("/dev/null")
        .arg("-o")
        .arg(format!("IdentityAgent={}", agent.socket.display()))
        .args(["-o", "IdentitiesOnly=no"])
        .arg("-o")
        .arg(format!("IdentityFile={}", identity.display()))
        .arg("-o")
        .arg(format!("UserKnownHostsFile={}", known_hosts.display()))
        .args(["-o", "GlobalKnownHostsFile=/dev/null"])
        .args(["-o", "StrictHostKeyChecking=accept-new"])
        .args(["-o", "BatchMode=yes"])
        .args(["-o", "ConnectTimeout=10"])
        .arg("-p")
        .arg(port.to_string())
        .arg(format!("{user}@127.0.0.1"))
        .arg("true")
        .output()
        .unwrap();
    if !out.status.success() {
        let log = fs::read_to_string(agent.home().join("sshd.log")).unwrap_or_default();
        eprintln!("sshd log:\n{log}");
        // Skipped only when the agent listed the key, was never asked to
        // sign (so no signature or agent error is possible), and sshd logs
        // an environmental refusal. Anything else fails below.
        let asked_to_sign = agent.audit.entries().iter().any(|e| e.action == "ssh_sign");
        if listed
            && !asked_to_sign
            && let Some(reason) = environmental_refusal(&log)
        {
            eprintln!("skipping: the test sshd refused the session ({reason})");
            return;
        }
    }
    check(&out, "ssh to the test sshd");

    let audit = agent.audit.entries();
    assert!(
        audit
            .iter()
            .any(|e| e.action == "ssh_sign" && e.outcome == "ok"),
        "{audit:?}"
    );
    // The signature was asked on a connection bound to the test sshd.
    let host_fp = fingerprint_of_blob(&host_key.public_blob());
    let seen = agent.approver.seen.lock().unwrap().clone();
    let destination = seen
        .iter()
        .find_map(|r| {
            r.details
                .iter()
                .find(|(l, _)| l == "destination")
                .map(|(_, v)| v.clone())
        })
        .expect("a bound signature request");
    assert_eq!(destination, format!("{host_fp} (127.0.0.1)"));
}

/// Reasons the local `sshd` may refuse a session that have nothing to do with
/// the agent (CI accounts that are locked, privilege separation or PAM set
/// up differently, file ownership checks). `None` when the log shows none.
fn environmental_refusal(sshd_log: &str) -> Option<&'static str> {
    // Lower case: the log is lowered before matching.
    const PATTERNS: [(&str, &str); 9] = [
        ("account is locked", "account locked"),
        ("account has expired", "account expired"),
        // sshd: "User <name> not allowed because ...".
        ("not allowed because", "user not allowed"),
        ("privilege separation", "privilege separation"),
        ("privsep", "privilege separation"),
        ("pam: ", "PAM"),
        ("pam_", "PAM"),
        ("bad ownership or modes", "permissions or ownership"),
        ("bad permissions", "permissions or ownership"),
    ];
    let log = sshd_log.to_ascii_lowercase();
    PATTERNS
        .iter()
        .find(|(needle, _)| log.contains(needle))
        .map(|(_, reason)| *reason)
}

#[test]
fn environmental_refusals_are_recognized() {
    assert_eq!(
        environmental_refusal("User runner not allowed because account is locked"),
        Some("account locked")
    );
    assert_eq!(
        environmental_refusal("fatal: Privilege separation user sshd does not exist"),
        Some("privilege separation")
    );
    assert_eq!(
        environmental_refusal("Authentication refused: bad ownership or modes for directory /x"),
        Some("permissions or ownership")
    );
    assert_eq!(
        environmental_refusal("error: PAM: Authentication failure for runner"),
        Some("PAM")
    );
    assert_eq!(
        environmental_refusal("Failed publickey for runner from 127.0.0.1: signature mismatch"),
        None
    );
    assert_eq!(
        environmental_refusal("sshd[1]: pam_unix(sshd:account): account expired"),
        Some("PAM")
    );
    // A bare "pam" inside another word is not a PAM refusal.
    assert_eq!(
        environmental_refusal("Received disconnect: spam filter"),
        None
    );
    assert_eq!(environmental_refusal(""), None);
}
