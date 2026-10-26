//! Kernel credentials and code-signing identity of real processes: the test
//! binary itself (ad hoc on macOS, unsigned on Linux), a system binary,
//! copies of the test binary (re-signed, or renamed over while running), a
//! socket pair, and the MCP client behind a shell.
//!
//! Helper processes are this test binary re-invoked with `HELPER_ENV` set,
//! which turns `peer_test_helper` into a sleeper or an identity printer.
//! Every child is waited for with a deadline and killed only by its own pid.

#[cfg(not(target_os = "macos"))]
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use onepass_peer::{
    CodeIdentity, PeerError, effective_uid, file_sha256, identify_mcp_parent, identify_peer,
    identify_pid, identity_of_file, parent_of, parent_pid, peer_cred,
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

/// The image SHA-256 of a Linux identity.
#[cfg(not(target_os = "macos"))]
fn pin(code: &CodeIdentity) -> &str {
    match code {
        CodeIdentity::Unsigned { sha256, .. } => sha256,
        other => panic!("expected an unsigned identity, got {other:?}"),
    }
}

#[cfg(target_os = "macos")]
/// Runs `cmd` to completion within the deadline and requires success.
fn run_ok(cmd: &mut Command) {
    let child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn");
    assert!(wait_output(child).status.success(), "{cmd:?} failed");
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
    let adhoc = CodeIdentity::AdHoc {
        path: PathBuf::from("/tmp/x"),
        cdhash: "cd".repeat(20),
        hardened: true,
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
    // `hardened` is reported, not part of the pin.
    assert_eq!(adhoc.client_id(), format!("adhoc:{}", "cd".repeat(20)));
    assert!(platform.is_signed());
    assert!(team.is_signed());
    assert!(!adhoc.is_signed());
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
        assert_eq!(pin(&id.code), file_sha256(&exe).expect("hash sleep"));
    }
    let file = identity_of_file(Path::new("/bin/sleep")).expect("file identity");
    assert_eq!(file.client_id(), id.code.client_id());
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
fn test_binary_is_pinned_by_its_running_image() {
    let id = identify_pid(std::process::id() as i32).expect("identify self");
    let exe = current_exe();
    #[cfg(target_os = "macos")]
    assert!(
        matches!(id.code, CodeIdentity::AdHoc { .. }),
        "{:?}",
        id.code
    );
    #[cfg(not(target_os = "macos"))]
    assert_eq!(pin(&id.code), file_sha256(&exe).expect("hash self"));
    // The file's identity is the running one: what `--exe` pairing records.
    let file = identity_of_file(&exe).expect("file identity");
    assert_eq!(file.client_id(), id.code.client_id());
    let path = match &id.code {
        CodeIdentity::AdHoc { path, .. } | CodeIdentity::Unsigned { path, .. } => path,
        _ => unreachable!(),
    };
    assert_eq!(path.canonicalize().expect("canonical"), exe);
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
    // macOS pins the code directory, which bytes appended past the
    // signature do not change: modify by re-signing with another
    // identifier. Linux pins the file bytes: append one.
    #[cfg(target_os = "macos")]
    run_ok(
        Command::new("/usr/bin/codesign")
            .args([
                "--force",
                "--sign",
                "-",
                "--identifier",
                "onepass.peer.modified",
            ])
            .arg(&modified),
    );
    #[cfg(not(target_os = "macos"))]
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
    assert_eq!(
        a.code.client_id(),
        identity_of_file(&original).expect("file").client_id()
    );
    assert_eq!(
        b.code.client_id(),
        identity_of_file(&modified).expect("file").client_id()
    );
    assert_ne!(a.code.client_id(), b.code.client_id());
}

#[cfg(target_os = "macos")]
#[test]
fn hardened_runtime_is_reported_for_ad_hoc_code() {
    let dir = tempfile::tempdir().expect("tempdir");
    let plain = dir.path().join("peer-plain");
    let hardened = dir.path().join("peer-hardened");
    std::fs::copy(current_exe(), &plain).expect("copy");
    std::fs::copy(current_exe(), &hardened).expect("copy");
    run_ok(
        Command::new("/usr/bin/codesign")
            .args(["--force", "--sign", "-", "--options", "runtime"])
            .arg(&hardened),
    );
    let flag = |code: &CodeIdentity| match code {
        CodeIdentity::AdHoc { hardened, .. } => *hardened,
        other => panic!("expected an ad hoc identity, got {other:?}"),
    };
    for (exe, expected) in [(&plain, false), (&hardened, true)] {
        let child = helper_command(exe, "sleep").spawn().expect("spawn copy");
        let id = identify_pid(child.id() as i32);
        kill(child);
        let id = id.expect("identify copy");
        assert_eq!(flag(&id.code), expected, "{exe:?}");
        let file = identity_of_file(exe).expect("file identity");
        assert_eq!(flag(&file), expected, "{exe:?}");
        assert_eq!(file.client_id(), id.code.client_id());
    }
}

#[test]
fn renaming_over_a_running_binary_keeps_its_identity() {
    let dir = tempfile::tempdir().expect("tempdir");
    let victim = dir.path().join("peer-running");
    let replacement = dir.path().join("peer-replacement");
    std::fs::copy(current_exe(), &victim).expect("copy");
    // The replacement is a genuine Apple binary: if identity were read back
    // from the path, the running ad hoc process would pass for it.
    std::fs::copy("/bin/sleep", &replacement).expect("copy sleep");

    let child = helper_command(&victim, "sleep")
        .spawn()
        .expect("spawn copy");
    let pid = child.id() as i32;
    let before = identify_pid(pid);
    let renamed = std::fs::rename(&replacement, &victim);
    let after = identify_pid(pid);
    kill(child);
    renamed.expect("rename over");
    let (before, after) = (before.expect("before"), after.expect("after"));

    // Compare pins, not paths: on Linux the running image's path now
    // reads "<path> (deleted)".
    assert_eq!(after.code.client_id(), before.code.client_id());
    assert!(!after.code.is_signed());
    let file = identity_of_file(&victim).expect("replacement identity");
    assert_ne!(file.client_id(), after.code.client_id());
    #[cfg(target_os = "macos")]
    assert_eq!(file.client_id(), "platform:com.apple.sleep");
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

    // Both platforms skip the shell: by signature on macOS, by path on
    // Linux. The client is this test process.
    assert_eq!(field("pid"), std::process::id().to_string());
    assert_eq!(field("id"), me.code.client_id());
    assert_eq!(chain.last(), Some(&me.code.client_id()));
    assert_eq!(chain.len(), 2, "chain {chain:?}");
    // /bin/sh is itself com.apple.sh, but it re-executes the shell that
    // /private/var/select/sh names (bash by default) in the same process.
    #[cfg(target_os = "macos")]
    {
        let shells = [
            "platform:com.apple.sh",
            "platform:com.apple.bash",
            "platform:com.apple.zsh",
            "platform:com.apple.dash",
        ];
        assert!(shells.contains(&chain[0].as_str()), "chain {chain:?}");
    }
}
