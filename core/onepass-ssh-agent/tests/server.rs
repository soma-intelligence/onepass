//! Unix socket server: socket creation and modes, the accept loop over a
//! real socket, and peer credentials.

mod common;

use std::fs;
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use common::*;
use onepass_guard::{Decision, DevAutoApprover};
use onepass_ssh_agent::keys::{KeyType, verify_signature};
use onepass_ssh_agent::{Agent, AgentConfig, bind_socket, peer_info, serve};
use tempfile::TempDir;

fn mode(p: &std::path::Path) -> u32 {
    fs::metadata(p).unwrap().permissions().mode() & 0o777
}

#[test]
fn bind_replaces_stale_socket_but_not_a_regular_file() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("agent").join("s.sock");
    let first = bind_socket(&path).unwrap();
    drop(first);
    // The stale socket file is still there and gets replaced.
    assert!(fs::symlink_metadata(&path).is_ok());
    let second = bind_socket(&path).unwrap();
    drop(second);

    let file = dir.path().join("agent").join("regular");
    fs::write(&file, b"keep me").unwrap();
    let err = bind_socket(&file).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
    assert_eq!(fs::read(&file).unwrap(), b"keep me");

    // A symlink to a socket is not a socket: refused, link kept.
    let link = dir.path().join("agent").join("link.sock");
    std::os::unix::fs::symlink(&path, &link).unwrap();
    assert_eq!(
        bind_socket(&link).unwrap_err().kind(),
        io::ErrorKind::AlreadyExists
    );
    assert!(
        fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink()
    );

    // A bare file name is refused (its parent would be the current
    // directory).
    assert_eq!(
        bind_socket(std::path::Path::new("s.sock"))
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidInput
    );
}

#[test]
fn bind_refuses_a_socket_that_answers() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("agent").join("s.sock");
    let live = bind_socket(&path).unwrap();
    let err = bind_socket(&path).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::AddrInUse);
    assert_eq!(err.to_string(), "another agent is serving this socket");
    // The live socket was left in place and still accepts connections.
    let _c = UnixStream::connect(&path).unwrap();
    assert!(live.accept().is_ok());
}

#[test]
fn socket_and_parent_modes() {
    let dir = TempDir::new().unwrap();
    let parent = dir.path().join("new").join("deeper");
    let path = parent.join("s.sock");
    let _l = bind_socket(&path).unwrap();
    assert_eq!(mode(&parent), 0o700);
    assert_eq!(mode(&path), 0o600);

    // An existing parent of this user is tightened to 0700.
    let loose = dir.path().join("loose");
    fs::create_dir(&loose).unwrap();
    fs::set_permissions(&loose, fs::Permissions::from_mode(0o755)).unwrap();
    let path = loose.join("s.sock");
    let _l2 = bind_socket(&path).unwrap();
    assert_eq!(mode(&loose), 0o700);
    assert_eq!(mode(&path), 0o600);
}

#[test]
fn serve_answers_over_socket() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("a").join("s.sock");
    let listener = bind_socket(&path).unwrap();
    let audit = SharedAudit::default();
    let agent = Agent::new(
        FakeSource::with(&[KeyType::Ed25519, KeyType::EcdsaP256]),
        Arc::new(DevAutoApprover(Decision::AllowOnce)),
        Box::new(audit.clone()),
        AgentConfig::default(),
    );
    let agent = Arc::new(Mutex::new(agent));
    let stop = Arc::new(AtomicBool::new(false));
    let server = {
        let (agent, stop) = (agent.clone(), stop.clone());
        thread::spawn(move || serve(listener, agent, stop))
    };

    let mut client = UnixStream::connect(&path).unwrap();
    send(&mut client, &identities_request());
    let ids = parse_identities(&recv(&mut client));
    assert_eq!(
        ids,
        vec![
            (
                key(KeyType::Ed25519).public_blob(),
                title_of(KeyType::Ed25519)
            ),
            (
                key(KeyType::EcdsaP256).public_blob(),
                title_of(KeyType::EcdsaP256)
            ),
        ]
    );
    for t in [KeyType::Ed25519, KeyType::EcdsaP256] {
        let blob = key(t).public_blob();
        send(&mut client, &sign_request(&blob, b"over the socket", 0));
        let sig = parse_signature(&recv(&mut client));
        verify_signature(&blob, b"over the socket", &sig).unwrap();
    }
    // The audit names this test binary as the client.
    let exe = std::env::current_exe().unwrap().canonicalize().unwrap();
    let entries = audit.entries();
    assert_eq!(entries.len(), 2);
    assert!(entries.iter().all(|e| e.outcome == "ok"));
    assert_eq!(
        std::path::Path::new(&entries[0].client)
            .canonicalize()
            .unwrap(),
        exe
    );

    // A malformed message closes the connection; a new one still works.
    send(&mut client, &[13, 0, 0]);
    let mut buf = [0u8; 1];
    assert_eq!(io::Read::read(&mut client, &mut buf).unwrap(), 0);
    let mut again = UnixStream::connect(&path).unwrap();
    send(&mut again, &identities_request());
    assert_eq!(parse_identities(&recv(&mut again)).len(), 2);

    stop.store(true, Ordering::SeqCst);
    server.join().unwrap().unwrap();
}

#[test]
fn peer_info_reports_own_uid_and_pid() {
    let (a, _b) = UnixStream::pair().unwrap();
    let info = peer_info(&a);
    let dir = TempDir::new().unwrap();
    let probe = dir.path().join("probe");
    fs::write(&probe, b"").unwrap();
    assert_eq!(info.uid, Some(fs::metadata(&probe).unwrap().uid()));
    assert_eq!(info.pid, Some(std::process::id() as i32));
    let exe = info.exe.expect("executable path");
    assert_eq!(
        std::path::Path::new(&exe).canonicalize().unwrap(),
        std::env::current_exe().unwrap().canonicalize().unwrap()
    );
}
