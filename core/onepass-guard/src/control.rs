//! Signed control channel: pushes revocations and unpairings into running
//! servers.
//!
//! The grants file and the client registry carry a generation, but a server
//! only knows the generations it has read or written itself. A same-uid
//! attacker who restores the file from before a revocation, before the
//! server rereads it, would undo the revocation. So the command that revokes
//! or unpairs tells every running server the new generation, and each server
//! raises its replay floor before acknowledging.
//!
//! - Each server binds `<data-dir>/run/<pid>.sock` (directory 0700, socket
//!   0600; a live socket is never replaced, a stale one is).
//! - Notification: one JSON line `{ "kind": "grants"|"clients", "generation",
//!   "nonce": <32 hex>, "sig": <base64> }`, signed under `control-notify`
//!   over `kind|generation|nonce`. On a valid signature the server calls its
//!   callback (which raises the floor), then answers one JSON line
//!   `{ "nonce", "pid", "generation", "sig" }`, signed under `control-ack`
//!   over `nonce|pid|generation`. Anything invalid closes the connection
//!   without an answer.
//! - Fail closed: [`ControlServer::alive`] is false once the socket path no
//!   longer names the socket this server bound (deleted or replaced), and
//!   stays false. Servers call it on every request, and a watchdog thread
//!   checks it every second and calls the `on_lost` callback; the server must
//!   then stop, since notifications could no longer reach it.

use crate::{GuardError, LocalSigner};
use data_encoding::{BASE64, HEXLOWER};
use serde::{Deserialize, Serialize};
use std::fs::{self, DirBuilder, Permissions};
use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

/// Signature domain of notifications.
pub const NOTIFY_DOMAIN: &[u8] = b"control-notify";
/// Signature domain of acknowledgements.
pub const ACK_DOMAIN: &[u8] = b"control-ack";

/// Longest line accepted on the control channel.
const MAX_LINE: u64 = 4096;
/// Read and write timeout of a server-side connection.
const SERVER_IO_TIMEOUT: Duration = Duration::from_secs(2);
/// Pause between two non-blocking `accept` calls.
const ACCEPT_POLL: Duration = Duration::from_millis(50);
/// Period of the watchdog.
const WATCHDOG_PERIOD: Duration = Duration::from_secs(1);

/// Which signed file changed.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ControlKind {
    /// `grants.json`.
    Grants,
    /// `clients.json`.
    Clients,
}

impl ControlKind {
    fn label(self) -> &'static str {
        match self {
            ControlKind::Grants => "grants",
            ControlKind::Clients => "clients",
        }
    }
}

/// Called with each verified notification, before it is acknowledged.
pub type NotifyFn = Arc<dyn Fn(ControlKind, u64) + Send + Sync>;
/// Called once when the server loses its socket.
pub type LostFn = Box<dyn Fn() + Send + Sync>;
/// A signer shared with the server threads.
pub type SharedSigner = Arc<dyn LocalSigner + Send + Sync>;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Notify {
    kind: ControlKind,
    generation: u64,
    nonce: String,
    sig: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ack {
    nonce: String,
    pid: u32,
    generation: u64,
    sig: String,
}

fn notify_bytes(kind: ControlKind, generation: u64, nonce: &str) -> Vec<u8> {
    format!("{}|{generation}|{nonce}", kind.label()).into_bytes()
}

fn ack_bytes(nonce: &str, pid: u32, generation: u64) -> Vec<u8> {
    format!("{nonce}|{pid}|{generation}").into_bytes()
}

fn valid_nonce(n: &str) -> bool {
    n.len() == 32 && n.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn new_nonce() -> Result<String, GuardError> {
    let mut b = [0u8; 16];
    aws_lc_rs::rand::fill(&mut b).map_err(|_| GuardError::Format("random source"))?;
    Ok(HEXLOWER.encode(&b))
}

/// Reads one line of at most `MAX_LINE` bytes.
fn read_line(s: &UnixStream) -> Option<String> {
    let mut line = String::new();
    let n = BufReader::new(s.take(MAX_LINE)).read_line(&mut line).ok()?;
    if n == 0 || !line.ends_with('\n') {
        return None;
    }
    Some(line)
}

/// The listening side of the control channel of one server.
pub struct ControlServer {
    path: PathBuf,
    dev: u64,
    ino: u64,
    stop: Arc<AtomicBool>,
    lost: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
}

impl std::fmt::Debug for ControlServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControlServer")
            .field("path", &self.path)
            .field("lost", &self.lost.load(Ordering::SeqCst))
            .finish()
    }
}

impl ControlServer {
    /// Binds `<run_dir>/<pid>.sock` and starts serving (see [`Self::bind`]).
    pub fn start(
        run_dir: &Path,
        signer: SharedSigner,
        on_notify: NotifyFn,
        on_lost: Option<LostFn>,
    ) -> Result<Self, GuardError> {
        let path = run_dir.join(format!("{}.sock", std::process::id()));
        Self::bind(&path, signer, on_notify, on_lost)
    }

    /// Binds the socket at `path` and starts the accept thread and the 1 s
    /// watchdog. `on_notify` runs for each verified notification before the
    /// acknowledgement; `on_lost` runs once when the watchdog finds the
    /// socket gone.
    pub fn bind(
        path: &Path,
        signer: SharedSigner,
        on_notify: NotifyFn,
        on_lost: Option<LostFn>,
    ) -> Result<Self, GuardError> {
        let listener = bind_control_socket(path)?;
        let meta = fs::symlink_metadata(path)?;
        listener.set_nonblocking(true)?;
        let stop = Arc::new(AtomicBool::new(false));
        let lost = Arc::new(AtomicBool::new(false));
        let mut server = ControlServer {
            path: path.to_owned(),
            dev: meta.dev(),
            ino: meta.ino(),
            stop: stop.clone(),
            lost: lost.clone(),
            threads: Vec::new(),
        };

        let accept_stop = stop.clone();
        server.threads.push(thread::spawn(move || {
            accept_loop(listener, signer, on_notify, accept_stop)
        }));

        let (wpath, dev, ino) = (server.path.clone(), server.dev, server.ino);
        server.threads.push(thread::spawn(move || {
            watchdog(&wpath, dev, ino, &stop, &lost, on_lost)
        }));
        Ok(server)
    }

    /// The socket path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// True while the socket path still names the socket this server bound.
    /// Once false it stays false: the server must stop serving.
    pub fn alive(&self) -> bool {
        if self.lost.load(Ordering::SeqCst) {
            return false;
        }
        if same_socket(&self.path, self.dev, self.ino) {
            return true;
        }
        self.lost.store(true, Ordering::SeqCst);
        false
    }

    /// The flag set when the socket is lost (by [`Self::alive`] or the
    /// watchdog), for a server loop to poll.
    pub fn lost_flag(&self) -> Arc<AtomicBool> {
        self.lost.clone()
    }
}

impl Drop for ControlServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
        if same_socket(&self.path, self.dev, self.ino) {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn same_socket(path: &Path, dev: u64, ino: u64) -> bool {
    match fs::symlink_metadata(path) {
        Ok(m) => m.file_type().is_socket() && m.dev() == dev && m.ino() == ino,
        Err(_) => false,
    }
}

fn watchdog(
    path: &Path,
    dev: u64,
    ino: u64,
    stop: &AtomicBool,
    lost: &AtomicBool,
    on_lost: Option<LostFn>,
) {
    let step = ACCEPT_POLL;
    let mut waited = Duration::ZERO;
    while !stop.load(Ordering::SeqCst) {
        thread::sleep(step);
        waited += step;
        if waited < WATCHDOG_PERIOD && !lost.load(Ordering::SeqCst) {
            continue;
        }
        waited = Duration::ZERO;
        if lost.load(Ordering::SeqCst) || !same_socket(path, dev, ino) {
            lost.store(true, Ordering::SeqCst);
            if let Some(f) = &on_lost {
                f();
            }
            return;
        }
    }
}

fn accept_loop(
    listener: UnixListener,
    signer: SharedSigner,
    on_notify: NotifyFn,
    stop: Arc<AtomicBool>,
) {
    while !stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _)) => {
                let (signer, on_notify) = (signer.clone(), on_notify.clone());
                // One thread per connection: a client that stalls cannot
                // delay a genuine notification.
                thread::spawn(move || handle(stream, &*signer, &*on_notify));
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => thread::sleep(ACCEPT_POLL),
            Err(_) => thread::sleep(ACCEPT_POLL),
        }
    }
}

/// Serves one connection: one verified notification, one acknowledgement.
fn handle(
    stream: UnixStream,
    signer: &dyn LocalSigner,
    on_notify: &(dyn Fn(ControlKind, u64) + Send + Sync),
) {
    if stream.set_nonblocking(false).is_err()
        || stream.set_read_timeout(Some(SERVER_IO_TIMEOUT)).is_err()
        || stream.set_write_timeout(Some(SERVER_IO_TIMEOUT)).is_err()
    {
        return;
    }
    let Some(line) = read_line(&stream) else {
        return;
    };
    let Ok(msg) = serde_json::from_str::<Notify>(&line) else {
        return;
    };
    if !valid_nonce(&msg.nonce) {
        return;
    }
    let Ok(sig) = BASE64.decode(msg.sig.as_bytes()) else {
        return;
    };
    if signer
        .verify(
            NOTIFY_DOMAIN,
            &notify_bytes(msg.kind, msg.generation, &msg.nonce),
            &sig,
        )
        .is_err()
    {
        return;
    }
    on_notify(msg.kind, msg.generation);
    let pid = std::process::id();
    let Ok(ack_sig) = signer.sign(ACK_DOMAIN, &ack_bytes(&msg.nonce, pid, msg.generation)) else {
        return;
    };
    let ack = Ack {
        nonce: msg.nonce,
        pid,
        generation: msg.generation,
        sig: BASE64.encode(&ack_sig),
    };
    if let Ok(mut text) = serde_json::to_string(&ack) {
        text.push('\n');
        let mut s = &stream;
        let _ = s.write_all(text.as_bytes());
    }
}

/// Creates the control socket at `path`: parent directory created 0700 (and
/// set to 0700 if it exists, which fails if it is not ours), a live socket
/// at `path` is never replaced (`AddrInUse`), a stale one is, anything else
/// is left alone (`AlreadyExists`). The socket is 0600.
fn bind_control_socket(path: &Path) -> Result<UnixListener, GuardError> {
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => return Err(GuardError::Io(ErrorKind::InvalidInput)),
    };
    match fs::symlink_metadata(parent) {
        Ok(m) if m.is_dir() => fs::set_permissions(parent, Permissions::from_mode(0o700))?,
        Ok(_) => return Err(GuardError::Io(ErrorKind::NotADirectory)),
        Err(e) if e.kind() == ErrorKind::NotFound => {
            DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)?;
            // The mode above is filtered by the umask.
            fs::set_permissions(parent, Permissions::from_mode(0o700))?;
        }
        Err(e) => return Err(e.into()),
    }
    match fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_socket() => {
            if UnixStream::connect(path).is_ok() {
                return Err(GuardError::Io(ErrorKind::AddrInUse));
            }
            fs::remove_file(path)?;
        }
        Ok(_) => return Err(GuardError::Io(ErrorKind::AlreadyExists)),
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    let listener = UnixListener::bind(path)?;
    fs::set_permissions(path, Permissions::from_mode(0o600))?;
    Ok(listener)
}

/// What [`notify_servers`] reached.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NotifyOutcome {
    /// Servers that acknowledged with a valid signature.
    pub reached: usize,
    /// Socket file names that did not (no answer, bad answer, timeout).
    pub failed: Vec<String>,
}

/// Tells every server with a socket in `run_dir` that `kind` is now at
/// `generation`, and verifies each acknowledgement (signature, nonce,
/// generation). A socket nobody listens on (connection refused) is a stale
/// one and is removed; it counts neither as reached nor as failed. A missing
/// `run_dir` reaches nobody.
pub fn notify_servers(
    run_dir: &Path,
    signer: &dyn LocalSigner,
    kind: ControlKind,
    generation: u64,
    timeout: Duration,
) -> Result<NotifyOutcome, GuardError> {
    let mut out = NotifyOutcome::default();
    let entries = match fs::read_dir(run_dir) {
        Ok(e) => e,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(e.into()),
    };
    let mut paths: Vec<PathBuf> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "sock"))
        .collect();
    paths.sort();
    for path in paths {
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        match fs::symlink_metadata(&path) {
            Ok(m) if m.file_type().is_socket() => {}
            _ => continue,
        }
        let stream = match UnixStream::connect(&path) {
            Ok(s) => s,
            Err(e) if e.kind() == ErrorKind::ConnectionRefused => {
                if fs::symlink_metadata(&path).is_ok_and(|m| m.file_type().is_socket()) {
                    let _ = fs::remove_file(&path);
                }
                continue;
            }
            Err(e) if e.kind() == ErrorKind::NotFound => continue,
            Err(_) => {
                out.failed.push(name);
                continue;
            }
        };
        if notify_one(&stream, signer, kind, generation, timeout)? {
            out.reached += 1;
        } else {
            out.failed.push(name);
        }
    }
    Ok(out)
}

/// Sends one notification on `stream`; true if the answer verifies. Only a
/// local failure to sign or draw a nonce is an error.
fn notify_one(
    stream: &UnixStream,
    signer: &dyn LocalSigner,
    kind: ControlKind,
    generation: u64,
    timeout: Duration,
) -> Result<bool, GuardError> {
    let nonce = new_nonce()?;
    let sig = signer.sign(NOTIFY_DOMAIN, &notify_bytes(kind, generation, &nonce))?;
    let msg = Notify {
        kind,
        generation,
        nonce: nonce.clone(),
        sig: BASE64.encode(&sig),
    };
    let mut line = serde_json::to_string(&msg).map_err(|_| GuardError::Format("notification"))?;
    line.push('\n');
    if stream.set_read_timeout(Some(timeout)).is_err()
        || stream.set_write_timeout(Some(timeout)).is_err()
    {
        return Ok(false);
    }
    let mut w = stream;
    if w.write_all(line.as_bytes()).is_err() {
        return Ok(false);
    }
    let Some(answer) = read_line(stream) else {
        return Ok(false);
    };
    let Ok(ack) = serde_json::from_str::<Ack>(&answer) else {
        return Ok(false);
    };
    if ack.nonce != nonce || ack.generation != generation {
        return Ok(false);
    }
    let Ok(ack_sig) = BASE64.decode(ack.sig.as_bytes()) else {
        return Ok(false);
    };
    Ok(signer
        .verify(
            ACK_DOMAIN,
            &ack_bytes(&ack.nonce, ack.pid, ack.generation),
            &ack_sig,
        )
        .is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approval::Surface;
    use crate::clients::{ClientRecord, ClientRegistry, ClientRegistryLoader, save_clients};
    use crate::clock::testing::FakeClock;
    use crate::grants::{DEFAULT_GRANT_TTL, GrantCheck, GrantRequest, GrantStore, Revoke};
    use crate::testutil::TestSigner;
    use std::sync::Mutex;
    use std::sync::atomic::AtomicUsize;
    use std::time::Instant;

    const TIMEOUT: Duration = Duration::from_secs(2);

    fn signer() -> SharedSigner {
        Arc::new(TestSigner::new())
    }

    fn req(client: &str, key: &str) -> GrantRequest {
        GrantRequest {
            client_id: client.to_owned(),
            surface: Surface::Mcp,
            action: "use".to_owned(),
            key: key.to_owned(),
            vault_id: None,
        }
    }

    fn counter() -> (Arc<AtomicUsize>, NotifyFn) {
        let n = Arc::new(AtomicUsize::new(0));
        let n2 = n.clone();
        (
            n,
            Arc::new(move |_, _| {
                n2.fetch_add(1, Ordering::SeqCst);
            }),
        )
    }

    #[test]
    fn revoke_pushed_to_server_defeats_restored_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("grants.json");
        let run = dir.path().join("run");
        let s = TestSigner::new();
        let c = FakeClock::new(1_800_000_000);

        // The server issues grant G (generation N).
        let server = Arc::new(Mutex::new(GrantStore::open(&path, "acc")));
        let g = server
            .lock()
            .unwrap()
            .add(&s, &c, req("platform:a", "k1"), DEFAULT_GRANT_TTL)
            .unwrap();
        let before_revoke = fs::read(&path).unwrap();
        let shared = server.clone();
        let control = ControlServer::bind(
            &run.join("1.sock"),
            signer(),
            Arc::new(move |kind, generation| {
                if kind == ControlKind::Grants {
                    shared.lock().unwrap().raise_floor(generation);
                }
            }),
            None,
        )
        .unwrap();
        // A second server that is not notified shows the attack.
        let mut unnotified = GrantStore::open(&path, "acc");
        assert!(matches!(
            unnotified.check(&s, &c, "platform:a", Surface::Mcp, "use", "k1"),
            GrantCheck::Valid(_)
        ));

        // The CLI revokes (generation N + 1) and notifies.
        let mut cli = GrantStore::open(&path, "acc");
        assert_eq!(cli.revoke(&s, &c, Revoke::Id(g.id)).unwrap(), 1);
        let out = notify_servers(
            &run,
            &s,
            ControlKind::Grants,
            cli.generation_seen(),
            TIMEOUT,
        )
        .unwrap();
        assert_eq!(
            out,
            NotifyOutcome {
                reached: 1,
                failed: vec![]
            }
        );
        assert_eq!(
            server.lock().unwrap().generation_seen(),
            cli.generation_seen()
        );

        // The attacker restores generation N before the next request.
        fs::write(&path, &before_revoke).unwrap();
        assert!(!matches!(
            server
                .lock()
                .unwrap()
                .check(&s, &c, "platform:a", Surface::Mcp, "use", "k1"),
            GrantCheck::Valid(_)
        ));
        // Without the notification the restored file would have been accepted.
        assert!(matches!(
            unnotified.check(&s, &c, "platform:a", Surface::Mcp, "use", "k1"),
            GrantCheck::Valid(_)
        ));
        assert!(control.alive());
    }

    #[test]
    fn unpair_pushed_to_server_defeats_restored_registry() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("clients.json");
        let run = dir.path().join("run");
        let s = TestSigner::new();
        let mut reg = ClientRegistry::empty("acc");
        reg.clients.push(ClientRecord {
            id: "platform:a".into(),
            surface: Surface::Mcp,
            label: "a".into(),
            code: serde_json::json!({}),
            paired_at: 0,
            mcp_scopes: None,
            ssh_keys: None,
        });
        save_clients(&path, &s, &mut reg).unwrap();
        let paired = fs::read(&path).unwrap();
        let loader = Arc::new(Mutex::new(ClientRegistryLoader::new()));
        loader.lock().unwrap().load(&path, &s, "acc").unwrap();
        let shared = loader.clone();
        let _control = ControlServer::bind(
            &run.join("1.sock"),
            signer(),
            Arc::new(move |kind, generation| {
                if kind == ControlKind::Clients {
                    shared.lock().unwrap().raise_floor(generation);
                }
            }),
            None,
        )
        .unwrap();
        reg.clients.clear();
        save_clients(&path, &s, &mut reg).unwrap();
        let out = notify_servers(&run, &s, ControlKind::Clients, reg.generation, TIMEOUT).unwrap();
        assert_eq!(out.reached, 1);
        fs::write(&path, &paired).unwrap();
        assert!(matches!(
            loader.lock().unwrap().load(&path, &s, "acc"),
            Err(GuardError::Tampered(_))
        ));
    }

    #[test]
    fn forged_notification_ignored_and_not_acked() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("run").join("1.sock");
        let (n, cb) = counter();
        let _control = ControlServer::bind(&sock, signer(), cb, None).unwrap();

        let send = |line: &str| -> String {
            let mut st = UnixStream::connect(&sock).unwrap();
            st.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            st.write_all(line.as_bytes()).unwrap();
            let mut answer = String::new();
            let _ = st.read_to_string(&mut answer);
            answer
        };
        // Signed with another key.
        let nonce = "0123456789abcdef0123456789abcdef";
        let bad = TestSigner([9u8; 32])
            .sign(NOTIFY_DOMAIN, &notify_bytes(ControlKind::Grants, 99, nonce))
            .unwrap();
        let forged = format!(
            "{{\"kind\":\"grants\",\"generation\":99,\"nonce\":\"{nonce}\",\"sig\":\"{}\"}}\n",
            BASE64.encode(&bad)
        );
        assert_eq!(send(&forged), "");
        // Right key, wrong domain (an ack signature replayed as a notification).
        let wrong_domain = TestSigner::new()
            .sign(ACK_DOMAIN, &notify_bytes(ControlKind::Grants, 99, nonce))
            .unwrap();
        let replayed = format!(
            "{{\"kind\":\"grants\",\"generation\":99,\"nonce\":\"{nonce}\",\"sig\":\"{}\"}}\n",
            BASE64.encode(&wrong_domain)
        );
        assert_eq!(send(&replayed), "");
        assert_eq!(send("not json\n"), "");
        assert_eq!(n.load(Ordering::SeqCst), 0);

        // A genuine one is acked.
        let out = notify_servers(
            sock.parent().unwrap(),
            &TestSigner::new(),
            ControlKind::Grants,
            7,
            TIMEOUT,
        )
        .unwrap();
        assert_eq!(out.reached, 1);
        assert_eq!(n.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn lost_socket_makes_server_not_alive() {
        let dir = tempfile::tempdir().unwrap();
        let run = dir.path().join("run");
        let sock = run.join("1.sock");
        let (_n, cb) = counter();
        let lost_calls = Arc::new(AtomicUsize::new(0));
        let lc = lost_calls.clone();
        let control = ControlServer::bind(
            &sock,
            signer(),
            cb,
            Some(Box::new(move || {
                lc.fetch_add(1, Ordering::SeqCst);
            })),
        )
        .unwrap();
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&run), 0o700);
        assert_eq!(mode(&sock), 0o600);
        assert!(control.alive());

        // Deleted, then replaced by another socket at the same path.
        fs::remove_file(&sock).unwrap();
        let _other = UnixListener::bind(&sock).unwrap();
        assert!(!control.alive());
        assert!(control.lost_flag().load(Ordering::SeqCst));

        let t = Instant::now();
        while lost_calls.load(Ordering::SeqCst) == 0 && t.elapsed() < Duration::from_secs(5) {
            thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(lost_calls.load(Ordering::SeqCst), 1);
        // Dropping the server leaves the foreign socket alone.
        drop(control);
        assert!(sock.exists());
    }

    #[test]
    fn watchdog_detects_deletion_within_two_seconds() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("run").join("1.sock");
        let (_n, cb) = counter();
        let control = ControlServer::bind(&sock, signer(), cb, None).unwrap();
        let flag = control.lost_flag();
        fs::remove_file(&sock).unwrap();
        let t = Instant::now();
        while !flag.load(Ordering::SeqCst) && t.elapsed() < Duration::from_secs(5) {
            thread::sleep(Duration::from_millis(20));
        }
        assert!(flag.load(Ordering::SeqCst));
        assert!(t.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn stale_socket_removed_by_notify() {
        let dir = tempfile::tempdir().unwrap();
        let run = dir.path().join("run");
        fs::create_dir(&run).unwrap();
        let stale = run.join("424242.sock");
        drop(UnixListener::bind(&stale).unwrap());
        assert!(stale.exists());
        // A regular file with the extension is left alone.
        fs::write(run.join("note.sock"), b"x").unwrap();
        let out =
            notify_servers(&run, &TestSigner::new(), ControlKind::Grants, 3, TIMEOUT).unwrap();
        assert_eq!(
            out,
            NotifyOutcome {
                reached: 0,
                failed: vec![]
            }
        );
        assert!(!stale.exists());
        assert!(run.join("note.sock").exists());
        // A missing run directory reaches nobody.
        let none = notify_servers(
            &dir.path().join("absent"),
            &TestSigner::new(),
            ControlKind::Grants,
            3,
            TIMEOUT,
        )
        .unwrap();
        assert_eq!(none, NotifyOutcome::default());
    }

    #[test]
    fn fake_listener_cannot_ack() {
        let dir = tempfile::tempdir().unwrap();
        let run = dir.path().join("run");
        fs::create_dir(&run).unwrap();
        let fake = UnixListener::bind(run.join("fake.sock")).unwrap();
        let t = thread::spawn(move || {
            // Answers twice: with a key of its own, then echoing a bad sig.
            for key in [[9u8; 32], [7u8; 32]] {
                let (st, _) = fake.accept().unwrap();
                let line = read_line(&st).unwrap();
                let msg: Notify = serde_json::from_str(&line).unwrap();
                let sig = if key == [9u8; 32] {
                    TestSigner(key)
                        .sign(ACK_DOMAIN, &ack_bytes(&msg.nonce, 1, msg.generation))
                        .unwrap()
                } else {
                    // The notification signature, valid under another domain.
                    BASE64.decode(msg.sig.as_bytes()).unwrap()
                };
                let ack = Ack {
                    nonce: msg.nonce,
                    pid: 1,
                    generation: msg.generation,
                    sig: BASE64.encode(&sig),
                };
                let mut w = &st;
                w.write_all(format!("{}\n", serde_json::to_string(&ack).unwrap()).as_bytes())
                    .unwrap();
            }
        });
        for _ in 0..2 {
            let out =
                notify_servers(&run, &TestSigner::new(), ControlKind::Grants, 5, TIMEOUT).unwrap();
            assert_eq!(
                out,
                NotifyOutcome {
                    reached: 0,
                    failed: vec!["fake.sock".into()]
                }
            );
        }
        t.join().unwrap();
    }

    #[test]
    fn bind_never_replaces_a_live_socket_or_a_file() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("run").join("1.sock");
        let (_n, cb) = counter();
        let _live = ControlServer::bind(&sock, signer(), cb.clone(), None).unwrap();
        assert_eq!(
            ControlServer::bind(&sock, signer(), cb.clone(), None).unwrap_err(),
            GuardError::Io(ErrorKind::AddrInUse)
        );
        let file = dir.path().join("run").join("2.sock");
        fs::write(&file, b"x").unwrap();
        assert_eq!(
            ControlServer::bind(&file, signer(), cb, None).unwrap_err(),
            GuardError::Io(ErrorKind::AlreadyExists)
        );
    }
}
