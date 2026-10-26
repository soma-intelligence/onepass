//! Kernel credentials and code-signing identity of real processes: the test
//! binary itself (unsigned or ad hoc), a system binary, copies of the test
//! binary, a socket pair, and the MCP client behind a shell.
//!
//! Helper processes are this test binary re-invoked with `HELPER_ENV` set,
//! which turns `peer_test_helper` into a sleeper or an identity printer.
//! Every child is waited for with a deadline and killed only by its own pid.

use std::io::Write;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use onepass_peer::{
    ClientIdentity, CodeIdentity, PeerError, effective_uid, file_sha256, identify_mcp_parent,
    identify_peer, identify_pid, parent_of, parent_pid, peer_cred,
};

const HELPER_ENV: &str = "ONEPASS_PEER_TEST_HELPER";
/// Longest a sleeping helper lives if nobody kills it.
const HELPER_SLEEP: Duration = Duration::from_secs(20);
/// Longest a test waits for a child to finish.
const CHILD_DEADLINE: Duration = Duration::from_secs(60);

/// Not a real test: inert unless `HELPER_ENV` is set, in which case this
/// process acts as a helper for another test of this binary.
#[test]
fn peer_test_helper() {
    match std::env::var(HELPER_ENV).as_deref() {
        Ok("sleep") => std::thread::sleep(HELPER_SLEEP),
        Ok("print-identity") => match identify_mcp_parent() {
            Ok(id) => println!(
                "IDENTITY pid={} id={} chain={}",
                id.pid,
                id.code.client_id(),
                id.chain.join(",")
            ),
            Err(e) => println!("IDENTITY error={e}"),
        },
        _ => {}
    }
}

fn helper_command(exe: &Path, mode: &str) -> Command {
    let mut c = Command::new(exe);
    c.args([
        "peer_test_helper",
        "--exact",
        "--nocapture",
        "--test-threads=1",
    ])
    .env(HELPER_ENV, mode)
    .stdin(Stdio::null())
    .stdout(Stdio::null())
    .stderr(Stdio::null());
    c
}

/// Kills `child` by its own pid and reaps it.
fn kill(mut child: Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/// Waits for `child` with a deadline; past it, kills it and fails.
fn wait_output(mut child: Child) -> Output {
    let start = Instant::now();
    loop {
        match child.try_wait().expect("try_wait") {
            Some(_) => return child.wait_with_output().expect("output"),
            None if start.elapsed() > CHILD_DEADLINE => {
                kill(child);
                panic!("child did not finish in time");
            }
            None => std::thread::sleep(Duration::from_millis(20)),
        }
    }
}

fn unsigned_sha(id: &ClientIdentity) -> &str {
    match &id.code {
        CodeIdentity::Unsigned { sha256, .. } => sha256,
        other => panic!("expected an unsigned identity, got {other:?}"),
    }
}

fn current_exe() -> PathBuf {
    std::env::current_exe()
        .expect("current exe")
        .canonicalize()
        .expect("canonical exe")
}

#[test]
fn client_id_formats() {
    let platform = CodeIdentity::Platform {
        identifier: "com.apple.ssh".into(),
    };
    let team = CodeIdentity::Team {
        team_id: "ABCDE12345".into(),
        identifier: "com.example.client".into(),
    };
    let unsigned = CodeIdentity::Unsigned {
        path: PathBuf::from("/tmp/x"),
        sha256: "ab".repeat(32),
    };
    assert_eq!(platform.client_id(), "platform:com.apple.ssh");
    assert_eq!(team.client_id(), "team:ABCDE12345:com.example.client");
    assert_eq!(
        unsigned.client_id(),
        format!("unsigned:{}", "ab".repeat(32))
    );
    assert!(platform.is_signed());
    assert!(team.is_signed());
    assert!(!unsigned.is_signed());
}

#[test]
fn file_sha256_is_lowercase_hex_of_contents() {
    let dir = tempfile::tempdir().expect("tempdir");
    let p = dir.path().join("f");
    std::fs::write(&p, b"abc").expect("write");
    assert_eq!(
        file_sha256(&p).expect("hash"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn identifies_platform_binary() {
    let child = Command::new("/bin/sleep")
        .arg("5")
        .stdin(Stdio::null())
        .spawn()
        .expect("spawn sleep");
    let pid = child.id() as i32;
    let id = identify_pid(pid);
    let parent = parent_of(pid);
    kill(child);
    let id = id.expect("identify sleep");
    assert_eq!(id.pid, pid);
    assert_eq!(parent, Some(std::process::id() as i32));
    #[cfg(target_os = "macos")]
    {
        assert_eq!(
            id.code,
            CodeIdentity::Platform {
                identifier: "com.apple.sleep".into()
            }
        );
        assert_eq!(id.exe.as_deref(), Some(Path::new("/bin/sleep")));
    }
    #[cfg(not(target_os = "macos"))]
    {
        let exe = id.exe.clone().expect("exe of sleep");
        assert_eq!(unsigned_sha(&id), file_sha256(&exe).expect("hash sleep"));
    }
    assert!(id.chain.is_empty());
}

#[test]
fn gone_process_is_reported() {
    let mut child = Command::new("/bin/sleep")
        .arg("5")
        .stdin(Stdio::null())
        .spawn()
        .expect("spawn sleep");
    let pid = child.id() as i32;
    child.kill().expect("kill");
    child.wait().expect("reap");
    assert_eq!(identify_pid(pid), Err(PeerError::Gone));
    assert_eq!(parent_of(pid), None);
}

#[test]
fn test_binary_is_unsigned_with_sha256() {
    let id = identify_pid(std::process::id() as i32).expect("identify self");
    let exe = current_exe();
    assert_eq!(unsigned_sha(&id), file_sha256(&exe).expect("hash self"));
    match &id.code {
        CodeIdentity::Unsigned { path, .. } => {
            assert_eq!(path.canonicalize().expect("canonical"), exe);
        }
        _ => unreachable!(),
    }
    assert!(!id.code.is_signed());
    assert_eq!(id.pid, std::process::id() as i32);
}

#[test]
fn modified_binary_changes_identity() {
    let dir = tempfile::tempdir().expect("tempdir");
    let original = dir.path().join("peer-copy");
    let modified = dir.path().join("peer-copy-modified");
    std::fs::copy(current_exe(), &original).expect("copy");
    std::fs::copy(current_exe(), &modified).expect("copy");
    std::fs::OpenOptions::new()
        .append(true)
        .open(&modified)
        .expect("open copy")
        .write_all(&[0])
        .expect("append");

    let identify_running = |exe: &Path| {
        let child = helper_command(exe, "sleep").spawn().expect("spawn copy");
        let id = identify_pid(child.id() as i32);
        kill(child);
        id.expect("identify copy")
    };
    let a = identify_running(&original);
    let b = identify_running(&modified);
    assert_eq!(unsigned_sha(&a), file_sha256(&original).expect("hash"));
    assert_eq!(unsigned_sha(&b), file_sha256(&modified).expect("hash"));
    assert_ne!(a.code.client_id(), b.code.client_id());
}

#[test]
fn peer_cred_over_socketpair() {
    let (a, _b) = UnixStream::pair().expect("socketpair");
    let cred = peer_cred(&a);
    assert_eq!(cred.uid, Some(effective_uid()));
    assert_eq!(cred.pid, Some(std::process::id() as i32));
    #[cfg(target_os = "macos")]
    assert!(cred.audit_token.is_some());
    #[cfg(not(target_os = "macos"))]
    assert!(cred.audit_token.is_none());

    let by_peer = identify_peer(&cred).expect("identify peer");
    let by_pid = identify_pid(std::process::id() as i32).expect("identify self");
    assert_eq!(by_peer.code, by_pid.code);
    assert_eq!(by_peer.pid, by_pid.pid);
}

#[test]
fn parent_pid_matches_parent_of_self() {
    assert_eq!(parent_of(std::process::id() as i32), Some(parent_pid()));
}

#[test]
fn mcp_parent_skips_launchers() {
    let exe = current_exe();
    // `; exit 0` keeps the shell from exec-ing the helper in its place, so
    // the helper's parent is the shell and the shell's parent is this test.
    let script = format!(
        "'{}' peer_test_helper --exact --nocapture --test-threads=1; exit 0",
        exe.display()
    );
    let child = Command::new("/bin/sh")
        .args(["-c", &script])
        .env(HELPER_ENV, "print-identity")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn sh");
    let sh_pid = child.id() as i32;
    let out = wait_output(child);
    let stdout = String::from_utf8(out.stdout).expect("utf8");
    // libtest prints "test peer_test_helper ... " before the helper's line.
    let line = stdout
        .lines()
        .find_map(|l| l.find("IDENTITY ").map(|i| &l[i..]))
        .unwrap_or_else(|| panic!("no identity line in {stdout:?}"));
    let field = |name: &str| {
        line.split(' ')
            .find_map(|kv| kv.strip_prefix(&format!("{name}=")))
            .unwrap_or_else(|| panic!("no {name} in {line:?}"))
            .to_string()
    };
    let chain: Vec<String> = field("chain").split(',').map(str::to_string).collect();
    let me = identify_pid(std::process::id() as i32).expect("identify self");

    #[cfg(target_os = "macos")]
    {
        let _ = sh_pid;
        // /bin/sh is itself com.apple.sh, but it re-executes the shell that
        // /private/var/select/sh names (bash by default) in the same process.
        let shells = [
            "platform:com.apple.sh",
            "platform:com.apple.bash",
            "platform:com.apple.zsh",
            "platform:com.apple.dash",
        ];
        assert!(shells.contains(&chain[0].as_str()), "chain {chain:?}");
        assert_eq!(field("pid"), std::process::id().to_string());
        assert_eq!(field("id"), me.code.client_id());
        assert_eq!(chain.last(), Some(&me.code.client_id()));
        assert_eq!(chain.len(), 2);
    }
    // Linux has no code signatures, so no process is known to be a
    // launcher: the shell itself is the client.
    #[cfg(not(target_os = "macos"))]
    {
        let _ = me;
        assert_eq!(field("pid"), sh_pid.to_string());
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0], field("id"));
    }
}
