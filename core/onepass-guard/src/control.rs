//! Signed control channel: pushes revocations and unpairings into running
//! servers.
//!
//! The grants file and the client registry are signed and carry a
//! generation, but a same-uid attacker can restore an older authentic file,
//! or launder it by letting a fresh process rewrite it at a new generation.
//! Only a running server can hold what it was told, so the command that
//! revokes or unpairs sends the revocation itself to every running server,
//! which keeps it in memory (see `GrantStore::apply_revocations` and
//! `ClientRegistryLoader::apply_unpairs`).
//!
//! - Each server binds `<data-dir>/run/<pid>.sock`. The protection is the
//!   directory: created 0700, or set to 0700 through a descriptor opened
//!   with `O_NOFOLLOW`, so only this user can reach the socket whatever its
//!   own mode (left to the umask; no path-based chmod, which could follow a
//!   swapped path). A live socket is never replaced, a stale one is.
//! - Notification, one JSON line signed under `control-notify` over the
//!   canonical JSON of every field but `sig`:
//!   `{ "account_id", "kind": "grants", "generation", "nonce", "revoked": [{ "id", "expires_at" }], "selectors": [RevokeSelector], "sig" }`
//!   or `{ "account_id", "kind": "clients", "generation", "nonce", "unpaired": [{ "client_id", "at" }], "sig" }`.
//!   The account must be the server's own. The server calls its callback,
//!   then answers `{ "nonce", "pid", "generation", "sig" }` signed under
//!   `control-ack` over `nonce|pid|generation`. Anything invalid closes the
//!   connection without an answer. At most 8 connections are served at once
//!   (more are closed at once), each within 2 s overall.
//! - [`notify_servers`] contacts every `<pid>.sock` of the run directory
//!   whose pid exists, at once (256 at most), within one overall deadline, counts a server as reached
//!   only if its signed pid is the one in its socket name, and never deletes
//!   anything (each server removes its own socket when it stops).
//! - Fail closed: a watchdog thread pings the server's own socket path every
//!   second with a fresh signed nonce. [`ControlServer::alive`] is true only
//!   if the accept loop received the last nonce less than 2 s ago, so a
//!   deleted or replaced socket path is noticed within about 2 s; once false
//!   it stays false and the server must stop. One limit remains: an attacker
//!   who renames the socket and relays to it from the original path keeps
//!   pings flowing while dropping notifications; the relay itself is then
//!   the server's only entrance, which this check cannot tell apart.

use crate::clients::Unpaired;
use crate::grants::{RevokeSelector, RevokedGrant};
use crate::{GuardError, LocalSigner};
use data_encoding::{BASE64, HEXLOWER};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs::{self, DirBuilder, File, OpenOptions, Permissions};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// Signature domain of notifications.
pub const NOTIFY_DOMAIN: &[u8] = b"control-notify";
/// Signature domain of acknowledgements.
pub const ACK_DOMAIN: &[u8] = b"control-ack";
/// Signature domain of the self-ping.
pub const PING_DOMAIN: &[u8] = b"control-ping";
/// Default overall deadline of [`notify_servers`].
pub const DEFAULT_NOTIFY_DEADLINE: Duration = Duration::from_secs(3);
/// Most sockets [`notify_servers`] contacts; more is an error.
pub const MAX_CONTROL_SOCKETS: usize = 256;

/// Longest line accepted on the control channel.
const MAX_LINE: usize = 256 * 1024;
/// Overall deadline of one server-side connection.
const SERVER_CONN_DEADLINE: Duration = Duration::from_secs(2);
/// Most control connections a server serves at once.
const MAX_SERVER_CONNS: usize = 8;
/// Pause between two non-blocking `accept` calls.
const ACCEPT_POLL: Duration = Duration::from_millis(50);
/// Period of the self-ping.
const WATCHDOG_PERIOD: Duration = Duration::from_secs(1);
/// A self-ping older than this means the socket path no longer reaches us.
const ALIVE_WINDOW: Duration = Duration::from_secs(2);
/// Deadline to send one self-ping.
const PING_SEND_DEADLINE: Duration = Duration::from_secs(1);
/// `sun_path` size, terminating NUL included.
#[cfg(target_os = "macos")]
const SUN_PATH_LEN: usize = 104;
#[cfg(not(target_os = "macos"))]
const SUN_PATH_LEN: usize = 108;

const PATH_TOO_LONG: &str = "data directory path too long for a control socket";

/// A change pushed to running servers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ControlChange {
    /// The grants file is at `generation` and these grants are revoked.
    Grants {
        /// Generation of the grants file after the revocation.
        generation: u64,
        /// The revoked grants the command found in the file it read.
        revoked: Vec<RevokedGrant>,
        /// What the revocation covers, including grants the command did not
        /// see.
        selectors: Vec<RevokeSelector>,
    },
    /// The client registry is at `generation` and these clients are unpaired.
    Clients {
        /// Generation of the registry after the change.
        generation: u64,
        /// The unpaired clients.
        unpaired: Vec<Unpaired>,
    },
}

impl ControlChange {
    /// The generation announced.
    pub fn generation(&self) -> u64 {
        match self {
            ControlChange::Grants { generation, .. }
            | ControlChange::Clients { generation, .. } => *generation,
        }
    }
}

/// Called with each verified notification, before it is acknowledged.
pub type NotifyFn = Arc<dyn Fn(&ControlChange) + Send + Sync>;
/// Called once when the server finds its socket path no longer reaches it.
pub type LostFn = Box<dyn Fn() + Send + Sync>;
/// A signer shared with the server threads.
pub type SharedSigner = Arc<dyn LocalSigner + Send + Sync>;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum Kind {
    Grants,
    Clients,
}

/// What the notification signature covers: every field but `sig`, in this
/// order.
#[derive(Serialize)]
struct NotifyBody<'a> {
    account_id: &'a str,
    kind: Kind,
    generation: u64,
    nonce: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    revoked: Option<&'a [RevokedGrant]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    selectors: Option<&'a [RevokeSelector]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    unpaired: Option<&'a [Unpaired]>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct Notify {
    account_id: String,
    kind: Kind,
    generation: u64,
    nonce: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    revoked: Option<Vec<RevokedGrant>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    selectors: Option<Vec<RevokeSelector>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    unpaired: Option<Vec<Unpaired>>,
    sig: String,
}

impl Notify {
    fn body_bytes(&self) -> Result<Vec<u8>, GuardError> {
        serde_json::to_vec(&NotifyBody {
            account_id: &self.account_id,
            kind: self.kind,
            generation: self.generation,
            nonce: &self.nonce,
            revoked: self.revoked.as_deref(),
            selectors: self.selectors.as_deref(),
            unpaired: self.unpaired.as_deref(),
        })
        .map_err(|_| GuardError::Format("notification"))
    }

    /// The change carried, if the kind and the list agree.
    fn change(&self) -> Option<ControlChange> {
        match (self.kind, &self.revoked, &self.selectors, &self.unpaired) {
            (Kind::Grants, Some(r), Some(sel), None) => Some(ControlChange::Grants {
                generation: self.generation,
                revoked: r.clone(),
                selectors: sel.clone(),
            }),
            (Kind::Clients, None, None, Some(u)) => Some(ControlChange::Clients {
                generation: self.generation,
                unpaired: u.clone(),
            }),
            _ => None,
        }
    }

    /// A signed notification of `change` for `account_id`.
    fn signed(
        signer: &dyn LocalSigner,
        account_id: &str,
        change: &ControlChange,
        nonce: &str,
    ) -> Result<Notify, GuardError> {
        let (kind, revoked, selectors, unpaired) = match change {
            ControlChange::Grants {
                revoked, selectors, ..
            } => (
                Kind::Grants,
                Some(revoked.clone()),
                Some(selectors.clone()),
                None,
            ),
            ControlChange::Clients { unpaired, .. } => {
                (Kind::Clients, None, None, Some(unpaired.clone()))
            }
        };
        let mut n = Notify {
            account_id: account_id.to_owned(),
            kind,
            generation: change.generation(),
            nonce: nonce.to_owned(),
            revoked,
            selectors,
            unpaired,
            sig: String::new(),
        };
        n.sig = BASE64.encode(&signer.sign(NOTIFY_DOMAIN, &n.body_bytes()?)?);
        Ok(n)
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct Ack {
    nonce: String,
    pid: u32,
    generation: u64,
    sig: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct Ping {
    ping: String,
    sig: String,
}

#[derive(Deserialize, Debug)]
#[serde(untagged)]
enum Incoming {
    Ping(Ping),
    Notify(Notify),
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

fn remaining(deadline: Instant) -> Option<Duration> {
    let now = Instant::now();
    (now < deadline).then(|| deadline - now)
}

/// Writes all of `data` before `deadline` (total budget, not per call).
fn write_deadline(s: &UnixStream, data: &[u8], deadline: Instant) -> bool {
    let mut off = 0;
    while off < data.len() {
        let Some(r) = remaining(deadline) else {
            return false;
        };
        // See `read_line_deadline`: EINVAL once the peer has closed.
        let _ = s.set_write_timeout(Some(r));
        let mut w = s;
        match w.write(&data[off..]) {
            Ok(0) => return false,
            Ok(n) => off += n,
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(_) => return false,
        }
    }
    true
}

/// Reads one line (at most `MAX_LINE` bytes) before `deadline` (total
/// budget, not per call).
fn read_line_deadline(s: &UnixStream, deadline: Instant) -> Option<String> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let r = remaining(deadline)?;
        // macOS refuses the option (EINVAL) once the peer has closed; the
        // read then returns at once, so the error is harmless.
        let _ = s.set_read_timeout(Some(r));
        let mut rd = s;
        match rd.read(&mut chunk) {
            Ok(0) => return None,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if let Some(pos) = buf.iter().position(|&b| b == b'\n') {
                    buf.truncate(pos + 1);
                    return String::from_utf8(buf).ok();
                }
                if buf.len() > MAX_LINE {
                    return None;
                }
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(_) => return None,
        }
    }
}

#[derive(Default)]
struct PingState {
    expected: Option<String>,
    last_ok: Option<Instant>,
}

struct Shared {
    account_id: String,
    signer: SharedSigner,
    on_notify: NotifyFn,
    active: AtomicUsize,
    ping: Mutex<PingState>,
    stop: AtomicBool,
    lost: Arc<AtomicBool>,
}

impl Shared {
    fn ping_state(&self) -> std::sync::MutexGuard<'_, PingState> {
        self.ping.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// True if the last self-ping came back less than `ALIVE_WINDOW` ago.
    fn fresh(&self) -> bool {
        self.ping_state()
            .last_ok
            .is_some_and(|t| t.elapsed() < ALIVE_WINDOW)
    }
}

/// The listening side of the control channel of one server.
pub struct ControlServer {
    path: PathBuf,
    /// Identity of the bound socket, only to remove it on drop.
    dev: u64,
    ino: u64,
    shared: Arc<Shared>,
    threads: Vec<JoinHandle<()>>,
}

impl std::fmt::Debug for ControlServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControlServer")
            .field("path", &self.path)
            .field("lost", &self.shared.lost.load(Ordering::SeqCst))
            .finish()
    }
}

impl ControlServer {
    /// Binds `<run_dir>/<pid>.sock` and starts serving (see [`Self::bind`]).
    pub fn start(
        run_dir: &Path,
        account_id: &str,
        signer: SharedSigner,
        on_notify: NotifyFn,
        on_lost: Option<LostFn>,
    ) -> Result<Self, GuardError> {
        let path = run_dir.join(format!("{}.sock", std::process::id()));
        Self::bind(&path, account_id, signer, on_notify, on_lost)
    }

    /// Binds the socket at `path`, starts the accept loop, proves with one
    /// self-ping that `path` reaches it (or fails), then starts the 1 s
    /// watchdog. Only notifications for `account_id` are accepted.
    /// `on_notify` runs for each verified notification before the
    /// acknowledgement; `on_lost` runs once when the watchdog finds the
    /// socket path no longer reaches this server.
    pub fn bind(
        path: &Path,
        account_id: &str,
        signer: SharedSigner,
        on_notify: NotifyFn,
        on_lost: Option<LostFn>,
    ) -> Result<Self, GuardError> {
        if path.as_os_str().len() >= SUN_PATH_LEN {
            return Err(GuardError::Config(PATH_TOO_LONG));
        }
        let listener = bind_control_socket(path)?;
        let meta = fs::symlink_metadata(path)?;
        listener.set_nonblocking(true)?;
        let shared = Arc::new(Shared {
            account_id: account_id.to_owned(),
            signer,
            on_notify,
            active: AtomicUsize::new(0),
            ping: Mutex::new(PingState::default()),
            stop: AtomicBool::new(false),
            lost: Arc::new(AtomicBool::new(false)),
        });
        let mut server = ControlServer {
            path: path.to_owned(),
            dev: meta.dev(),
            ino: meta.ino(),
            shared: shared.clone(),
            threads: Vec::new(),
        };
        let accept_shared = shared.clone();
        server
            .threads
            .push(thread::spawn(move || accept_loop(listener, accept_shared)));

        // The path must reach this server before anything is reported.
        let started = Instant::now();
        ping_once(&shared, path);
        while !shared.fresh() && started.elapsed() < ALIVE_WINDOW {
            thread::sleep(Duration::from_millis(10));
        }
        if !shared.fresh() {
            // Dropping `server` stops the accept loop.
            return Err(GuardError::Config(
                "control socket does not answer its own ping",
            ));
        }
        // No chmod of the socket path: the 0700 directory is the
        // protection (see the module documentation).

        let (wshared, wpath) = (shared, server.path.clone());
        server
            .threads
            .push(thread::spawn(move || watchdog(&wshared, &wpath, on_lost)));
        Ok(server)
    }

    /// The socket path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// True while the socket path still reaches this server (last self-ping
    /// back less than 2 s ago). Once false it stays false: the server must
    /// stop serving.
    pub fn alive(&self) -> bool {
        if self.shared.lost.load(Ordering::SeqCst) {
            return false;
        }
        if self.shared.fresh() {
            return true;
        }
        self.shared.lost.store(true, Ordering::SeqCst);
        false
    }

    /// The flag set when the socket path is lost (by [`Self::alive`] or the
    /// watchdog), for a server loop to poll.
    pub fn lost_flag(&self) -> Arc<AtomicBool> {
        self.shared.lost.clone()
    }
}

impl Drop for ControlServer {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::SeqCst);
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
        if let Ok(m) = fs::symlink_metadata(&self.path)
            && m.file_type().is_socket()
            && m.dev() == self.dev
            && m.ino() == self.ino
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// Sends one signed self-ping with a fresh nonce to `path`.
fn ping_once(shared: &Shared, path: &Path) {
    let Ok(nonce) = new_nonce() else {
        return;
    };
    let Ok(sig) = shared.signer.sign(PING_DOMAIN, nonce.as_bytes()) else {
        return;
    };
    shared.ping_state().expected = Some(nonce.clone());
    let Ok(mut line) = serde_json::to_string(&Ping {
        ping: nonce,
        sig: BASE64.encode(&sig),
    }) else {
        return;
    };
    line.push('\n');
    if let Ok(s) = UnixStream::connect(path) {
        let _ = write_deadline(&s, line.as_bytes(), Instant::now() + PING_SEND_DEADLINE);
    }
}

fn watchdog(shared: &Shared, path: &Path, on_lost: Option<LostFn>) {
    loop {
        let wake = Instant::now() + WATCHDOG_PERIOD;
        while Instant::now() < wake {
            if shared.stop.load(Ordering::SeqCst) {
                return;
            }
            thread::sleep(ACCEPT_POLL);
        }
        let sent = Instant::now();
        ping_once(shared, path);
        // Give the accept loop a moment to see it.
        while sent.elapsed() < Duration::from_millis(500)
            && !shared.ping_state().last_ok.is_some_and(|t| t >= sent)
        {
            thread::sleep(Duration::from_millis(10));
        }
        if shared.lost.load(Ordering::SeqCst) || !shared.fresh() {
            shared.lost.store(true, Ordering::SeqCst);
            if let Some(f) = &on_lost {
                f();
            }
            return;
        }
    }
}

/// Decrements the count of active connections when a handler ends.
struct ActiveGuard(Arc<Shared>);

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::SeqCst);
    }
}

fn accept_loop(listener: UnixListener, shared: Arc<Shared>) {
    while !shared.stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _)) => {
                if shared.active.fetch_add(1, Ordering::SeqCst) >= MAX_SERVER_CONNS {
                    shared.active.fetch_sub(1, Ordering::SeqCst);
                    drop(stream);
                    continue;
                }
                let guard = ActiveGuard(shared.clone());
                thread::spawn(move || {
                    handle(&stream, &guard.0);
                    drop(guard);
                });
            }
            Err(_) => thread::sleep(ACCEPT_POLL),
        }
    }
}

/// Serves one connection within `SERVER_CONN_DEADLINE`: a self-ping, or one
/// verified notification and its acknowledgement.
fn handle(stream: &UnixStream, shared: &Shared) {
    let deadline = Instant::now() + SERVER_CONN_DEADLINE;
    if stream.set_nonblocking(false).is_err() {
        return;
    }
    let Some(line) = read_line_deadline(stream, deadline) else {
        return;
    };
    match serde_json::from_str::<Incoming>(&line) {
        Ok(Incoming::Ping(p)) => {
            let Ok(sig) = BASE64.decode(p.sig.as_bytes()) else {
                return;
            };
            if shared
                .signer
                .verify(PING_DOMAIN, p.ping.as_bytes(), &sig)
                .is_err()
            {
                return;
            }
            let mut st = shared.ping_state();
            if st.expected.as_deref() == Some(p.ping.as_str()) {
                st.last_ok = Some(Instant::now());
            }
        }
        Ok(Incoming::Notify(n)) => {
            if n.account_id != shared.account_id || !valid_nonce(&n.nonce) {
                return;
            }
            let Some(change) = n.change() else {
                return;
            };
            let (Ok(body), Ok(sig)) = (n.body_bytes(), BASE64.decode(n.sig.as_bytes())) else {
                return;
            };
            if shared.signer.verify(NOTIFY_DOMAIN, &body, &sig).is_err() {
                return;
            }
            (shared.on_notify)(&change);
            let pid = std::process::id();
            let Ok(ack_sig) = shared
                .signer
                .sign(ACK_DOMAIN, &ack_bytes(&n.nonce, pid, n.generation))
            else {
                return;
            };
            let ack = Ack {
                nonce: n.nonce,
                pid,
                generation: n.generation,
                sig: BASE64.encode(&ack_sig),
            };
            if let Ok(mut text) = serde_json::to_string(&ack) {
                text.push('\n');
                let _ = write_deadline(stream, text.as_bytes(), deadline);
            }
        }
        Err(_) => {}
    }
}

/// Prepares the parent directory (created 0700, or set to 0700 through a
/// descriptor opened without following a symlink) and binds the socket at
/// `path`. A live socket at `path` is never replaced (`AddrInUse`), a stale
/// one is, anything else is left alone (`AlreadyExists`).
fn bind_control_socket(path: &Path) -> Result<UnixListener, GuardError> {
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => return Err(GuardError::Io(ErrorKind::InvalidInput)),
    };
    if let Err(e) = fs::symlink_metadata(parent) {
        if e.kind() != ErrorKind::NotFound {
            return Err(e.into());
        }
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)?;
    }
    let dir: File = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open(parent)?;
    if !dir.metadata()?.is_dir() {
        return Err(GuardError::Io(ErrorKind::NotADirectory));
    }
    // fchmod: fails if the directory is not ours; the creation mode above is
    // filtered by the umask.
    dir.set_permissions(Permissions::from_mode(0o700))?;
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
    Ok(UnixListener::bind(path)?)
}

/// What [`notify_servers`] reached.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NotifyOutcome {
    /// Pids of the servers that acknowledged with a valid signature and the
    /// pid of their socket name.
    pub reached: BTreeSet<u32>,
    /// Socket file names that did not (refused, no answer in time, bad
    /// answer), sorted.
    pub failed: Vec<String>,
}

/// The pid named by a socket file name `^[0-9]{1,10}\.sock$`.
fn socket_pid(name: &str) -> Option<u32> {
    let digits = name.strip_suffix(".sock")?;
    if digits.is_empty() || digits.len() > 10 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

/// Sends `change` for `account_id` to every socket of `run_dir` named
/// `<pid>.sock` (1 to 10 digits) whose pid `pid_alive` says exists (the
/// caller passes `kill(pid, 0)` succeeding or failing with `EPERM`, for
/// example `onepass_peer::pid_exists`; this crate holds no `unsafe`), all at
/// once, and verifies each acknowledgement (signature, nonce, generation,
/// pid equal to the socket name). Other names are ignored. Nothing is ever
/// deleted. More than [`MAX_CONTROL_SOCKETS`] such sockets is an error. A
/// missing `run_dir` reaches nobody.
///
/// `deadline` bounds the whole call: the result is returned by then, and
/// each exchange's write and read use what is left of it. A blocking
/// `connect` cannot be bounded that way (a listener whose backlog is full
/// can hold it on some systems); its thread is then abandoned and may
/// outlive the call, which is acceptable for the one-shot command that
/// calls this, not for a long-running process.
pub fn notify_servers(
    run_dir: &Path,
    account_id: &str,
    signer: &dyn LocalSigner,
    change: &ControlChange,
    deadline: Duration,
    pid_alive: &dyn Fn(u32) -> bool,
) -> Result<NotifyOutcome, GuardError> {
    let until = Instant::now() + deadline;
    let mut out = NotifyOutcome::default();
    let entries = match fs::read_dir(run_dir) {
        Ok(e) => e,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(e.into()),
    };
    let mut sockets: Vec<(String, PathBuf)> = Vec::new();
    for e in entries.filter_map(|e| e.ok()) {
        let path = e.path();
        let Some(name) = e.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Some(pid) = socket_pid(&name) else {
            continue;
        };
        if !fs::symlink_metadata(&path).is_ok_and(|m| m.file_type().is_socket()) {
            continue;
        }
        if !pid_alive(pid) {
            continue;
        }
        sockets.push((name, path));
    }
    if sockets.len() > MAX_CONTROL_SOCKETS {
        return Err(GuardError::Config(
            "too many control sockets in the run directory",
        ));
    }
    sockets.sort();

    let nonce = new_nonce()?;
    let msg = Notify::signed(signer, account_id, change, &nonce)?;
    let mut line = serde_json::to_string(&msg).map_err(|_| GuardError::Format("notification"))?;
    line.push('\n');

    let (tx, rx) = mpsc::channel::<(usize, Option<String>)>();
    for (i, (_, path)) in sockets.iter().enumerate() {
        let (tx, path, line) = (tx.clone(), path.clone(), line.clone());
        // Detached: the result is collected only until the deadline. Writes
        // and reads use what is left of it; a blocking connect does not, so
        // this thread may outlive the call (see the function documentation).
        thread::spawn(move || {
            let answer = UnixStream::connect(&path).ok().and_then(|s| {
                if write_deadline(&s, line.as_bytes(), until) {
                    read_line_deadline(&s, until)
                } else {
                    None
                }
            });
            let _ = tx.send((i, answer));
        });
    }
    drop(tx);

    let mut answers: Vec<Option<String>> = vec![None; sockets.len()];
    let mut pending = sockets.len();
    while pending > 0 {
        let Some(r) = remaining(until) else {
            break;
        };
        match rx.recv_timeout(r) {
            Ok((i, a)) => {
                answers[i] = a;
                pending -= 1;
            }
            Err(_) => break,
        }
    }

    for ((name, _), answer) in sockets.iter().zip(answers) {
        let pid = socket_pid(name);
        let ok = match (pid, answer) {
            (Some(pid), Some(a)) => verify_ack(signer, &a, &nonce, change.generation(), pid),
            _ => false,
        };
        match (ok, pid) {
            (true, Some(pid)) => {
                out.reached.insert(pid);
            }
            _ => out.failed.push(name.clone()),
        }
    }
    Ok(out)
}

fn verify_ack(
    signer: &dyn LocalSigner,
    line: &str,
    nonce: &str,
    generation: u64,
    pid: u32,
) -> bool {
    let Ok(ack) = serde_json::from_str::<Ack>(line) else {
        return false;
    };
    if ack.nonce != nonce || ack.generation != generation || ack.pid != pid {
        return false;
    }
    let Ok(sig) = BASE64.decode(ack.sig.as_bytes()) else {
        return false;
    };
    signer
        .verify(
            ACK_DOMAIN,
            &ack_bytes(&ack.nonce, ack.pid, ack.generation),
            &sig,
        )
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approval::Surface;
    use crate::clients::{
        ClientRecord, ClientRegistry, ClientRegistryLoader, load_clients, save_clients,
    };
    use crate::clock::Clock;
    use crate::clock::testing::FakeClock;
    use crate::grants::{DEFAULT_GRANT_TTL, GrantCheck, GrantRequest, GrantStore, Revoke};
    use crate::testutil::TestSigner;

    const ACC: &str = "acc";

    fn signer() -> SharedSigner {
        Arc::new(TestSigner::new())
    }

    fn me() -> u32 {
        std::process::id()
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
            Arc::new(move |_| {
                n2.fetch_add(1, Ordering::SeqCst);
            }),
        )
    }

    fn grants_change(generation: u64) -> ControlChange {
        ControlChange::Grants {
            generation,
            revoked: vec![],
            selectors: vec![],
        }
    }

    fn reached_me() -> BTreeSet<u32> {
        BTreeSet::from([me()])
    }

    /// A server process holding a grant store, wired to the control channel.
    fn grant_server(
        path: &Path,
        run: &Path,
        clock: &Arc<FakeClock>,
    ) -> (Arc<Mutex<GrantStore>>, ControlServer) {
        let store = Arc::new(Mutex::new(GrantStore::open(path, ACC)));
        let shared = store.clone();
        let clock = clock.clone();
        let control = ControlServer::start(
            run,
            ACC,
            signer(),
            Arc::new(move |ch: &ControlChange| {
                if let ControlChange::Grants {
                    generation,
                    revoked,
                    selectors,
                } = ch
                {
                    shared.lock().unwrap().apply_revocations(
                        &clock,
                        *generation,
                        revoked,
                        selectors,
                    );
                }
            }),
            None,
        )
        .unwrap();
        (store, control)
    }

    fn server_check(st: &Arc<Mutex<GrantStore>>, s: &TestSigner, c: &dyn Clock) -> GrantCheck {
        st.lock()
            .unwrap()
            .check(s, c, "platform:a", Surface::Mcp, "use", "k1")
    }

    #[test]
    fn pushed_revocation_defeats_restored_and_laundered_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("grants.json");
        let run = dir.path().join("run");
        let s = TestSigner::new();
        let c = Arc::new(FakeClock::new(1_800_000_000));
        let (server, control) = grant_server(&path, &run, &c);
        let g = server
            .lock()
            .unwrap()
            .add(&s, &c, req("platform:a", "k1"), DEFAULT_GRANT_TTL)
            .unwrap();
        let before = fs::read(&path).unwrap();
        // Another server that is not notified shows the attack.
        let mut unnotified = GrantStore::open(&path, ACC);
        assert!(matches!(
            unnotified.check(&s, &c, "platform:a", Surface::Mcp, "use", "k1"),
            GrantCheck::Valid(_)
        ));

        let mut cli = GrantStore::open(&path, ACC);
        let out = cli.revoke(&s, &c, Revoke::Id(g.id)).unwrap();
        let change = ControlChange::Grants {
            generation: out.generation,
            revoked: out.revoked,
            selectors: vec![out.selector],
        };
        let n = notify_servers(&run, ACC, &s, &change, DEFAULT_NOTIFY_DEADLINE, &|_| true).unwrap();
        assert_eq!(n.reached, reached_me());
        assert!(n.failed.is_empty());

        // Restored generation N.
        fs::write(&path, &before).unwrap();
        assert!(!matches!(
            server_check(&server, &s, &c),
            GrantCheck::Valid(_)
        ));
        assert!(matches!(
            unnotified.check(&s, &c, "platform:a", Surface::Mcp, "use", "k1"),
            GrantCheck::Valid(_)
        ));
        // Laundered: a fresh process rewrites it at N + 1 with G live.
        GrantStore::open(&path, ACC)
            .add(&s, &c, req("platform:z", "kz"), DEFAULT_GRANT_TTL)
            .unwrap();
        assert_eq!(server_check(&server, &s, &c), GrantCheck::Revoked);
        assert!(control.alive());
    }

    #[test]
    fn late_notification_still_revokes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("grants.json");
        let run = dir.path().join("run");
        let s = TestSigner::new();
        let c = Arc::new(FakeClock::new(1_800_000_000));
        let (server, _control) = grant_server(&path, &run, &c);
        let g = server
            .lock()
            .unwrap()
            .add(&s, &c, req("platform:a", "k1"), DEFAULT_GRANT_TTL)
            .unwrap();
        let before = fs::read(&path).unwrap();
        let out = GrantStore::open(&path, ACC)
            .revoke(&s, &c, Revoke::Id(g.id))
            .unwrap();
        // The attacker restores before the notification arrives.
        fs::write(&path, &before).unwrap();
        let change = ControlChange::Grants {
            generation: out.generation,
            revoked: out.revoked,
            selectors: vec![out.selector],
        };
        let n = notify_servers(&run, ACC, &s, &change, DEFAULT_NOTIFY_DEADLINE, &|_| true).unwrap();
        assert_eq!(n.reached, reached_me());
        assert!(!matches!(
            server_check(&server, &s, &c),
            GrantCheck::Valid(_)
        ));
        // And a laundered rewrite after it changes nothing.
        GrantStore::open(&path, ACC)
            .add(&s, &c, req("platform:z", "kz"), DEFAULT_GRANT_TTL)
            .unwrap();
        assert_eq!(server_check(&server, &s, &c), GrantCheck::Revoked);
    }

    #[test]
    fn pushed_unpair_defeats_laundered_registry_and_allows_repair() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("clients.json");
        let run = dir.path().join("run");
        let s = TestSigner::new();
        let rec = |paired_at| ClientRecord {
            id: "platform:a".into(),
            surface: Surface::Mcp,
            label: "a".into(),
            code: serde_json::json!({}),
            paired_at,
            mcp_scopes: None,
            ssh_keys: None,
        };
        let mut reg = ClientRegistry::empty(ACC);
        reg.clients.push(rec(1_000));
        save_clients(&path, &s, &mut reg).unwrap();
        let paired = fs::read(&path).unwrap();
        let loader = Arc::new(Mutex::new(ClientRegistryLoader::new()));
        loader.lock().unwrap().load(&path, &s, ACC).unwrap();
        let shared = loader.clone();
        let _control = ControlServer::start(
            &run,
            ACC,
            signer(),
            Arc::new(move |ch: &ControlChange| {
                if let ControlChange::Clients {
                    generation,
                    unpaired,
                } = ch
                {
                    shared.lock().unwrap().apply_unpairs(*generation, unpaired);
                }
            }),
            None,
        )
        .unwrap();
        let u = reg.unpair("platform:a", 2_000);
        save_clients(&path, &s, &mut reg).unwrap();
        let change = ControlChange::Clients {
            generation: reg.generation,
            unpaired: vec![u],
        };
        let n = notify_servers(&run, ACC, &s, &change, DEFAULT_NOTIFY_DEADLINE, &|_| true).unwrap();
        assert_eq!(n.reached, reached_me());

        let found = |l: &Arc<Mutex<ClientRegistryLoader>>| {
            l.lock()
                .unwrap()
                .load(&path, &s, ACC)
                .map(|r| r.find(Surface::Mcp, "platform:a").is_some())
        };
        // Restored: older generation, refused.
        fs::write(&path, &paired).unwrap();
        assert!(matches!(found(&loader), Err(GuardError::Tampered(_))));
        // Laundered at the same generation: the record is ignored.
        let mut laundered = load_clients(&path, &s, ACC).unwrap();
        save_clients(&path, &s, &mut laundered).unwrap();
        assert_eq!(found(&loader), Ok(false));
        // Re-paired later than the unpairing: accepted.
        let mut again = load_clients(&path, &s, ACC).unwrap();
        again.clients = vec![rec(2_001)];
        save_clients(&path, &s, &mut again).unwrap();
        assert_eq!(found(&loader), Ok(true));
    }

    #[test]
    fn forged_notifications_ignored_and_not_acked() {
        let dir = tempfile::tempdir().unwrap();
        let run = dir.path().join("run");
        let (n, cb) = counter();
        let control = ControlServer::start(&run, ACC, signer(), cb, None).unwrap();
        let sock = control.path().to_owned();
        let send = |line: String| -> String {
            let mut st = UnixStream::connect(&sock).unwrap();
            st.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            st.write_all(line.as_bytes()).unwrap();
            let mut answer = String::new();
            let _ = st.read_to_string(&mut answer);
            answer
        };
        let nonce = "0123456789abcdef0123456789abcdef";
        let line = |n: &Notify| format!("{}\n", serde_json::to_string(n).unwrap());
        let change = grants_change(99);

        // Signed with another key.
        let other = Notify::signed(&TestSigner([9u8; 32]), ACC, &change, nonce).unwrap();
        assert_eq!(send(line(&other)), "");
        // Right key, another account.
        let foreign = Notify::signed(&TestSigner::new(), "other", &change, nonce).unwrap();
        assert_eq!(send(line(&foreign)), "");
        // Right key, edited after signing (generation raised).
        let mut edited = Notify::signed(&TestSigner::new(), ACC, &change, nonce).unwrap();
        edited.generation = 1_000;
        assert_eq!(send(line(&edited)), "");
        // Kind and list disagree.
        let mut mixed = Notify::signed(&TestSigner::new(), ACC, &change, nonce).unwrap();
        mixed.unpaired = Some(vec![]);
        mixed.sig = BASE64.encode(
            &TestSigner::new()
                .sign(NOTIFY_DOMAIN, &mixed.body_bytes().unwrap())
                .unwrap(),
        );
        assert_eq!(send(line(&mixed)), "");
        // Signed under the ack domain.
        let mut wrong_domain = Notify::signed(&TestSigner::new(), ACC, &change, nonce).unwrap();
        wrong_domain.sig = BASE64.encode(
            &TestSigner::new()
                .sign(ACK_DOMAIN, &wrong_domain.body_bytes().unwrap())
                .unwrap(),
        );
        assert_eq!(send(line(&wrong_domain)), "");
        assert_eq!(send("not json\n".into()), "");
        assert_eq!(n.load(Ordering::SeqCst), 0);

        let ok = notify_servers(
            &run,
            ACC,
            &TestSigner::new(),
            &change,
            DEFAULT_NOTIFY_DEADLINE,
            &|_| true,
        )
        .unwrap();
        assert_eq!(ok.reached, reached_me());
        assert_eq!(n.load(Ordering::SeqCst), 1);
    }

    fn wait_for(flag: impl Fn() -> bool, limit: Duration) -> Duration {
        let t = Instant::now();
        while !flag() && t.elapsed() < limit {
            thread::sleep(Duration::from_millis(20));
        }
        t.elapsed()
    }

    #[test]
    fn deleted_socket_detected_by_self_ping() {
        let dir = tempfile::tempdir().unwrap();
        let run = dir.path().join("run");
        let (_n, cb) = counter();
        let lost_calls = Arc::new(AtomicUsize::new(0));
        let lc = lost_calls.clone();
        let control = ControlServer::start(
            &run,
            ACC,
            signer(),
            cb,
            Some(Box::new(move || {
                lc.fetch_add(1, Ordering::SeqCst);
            })),
        )
        .unwrap();
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&run), 0o700);
        // The socket's own mode is left to the umask: the 0700 directory
        // is the protection.
        assert!(control.alive());
        // Still alive a few periods later.
        thread::sleep(Duration::from_millis(2500));
        assert!(control.alive());

        fs::remove_file(control.path()).unwrap();
        let took = wait_for(
            || lost_calls.load(Ordering::SeqCst) > 0,
            lost_bound() + Duration::from_secs(2),
        );
        assert_eq!(lost_calls.load(Ordering::SeqCst), 1);
        assert!(took < lost_bound(), "{took:?}");
        assert!(!control.alive());
        assert!(control.lost_flag().load(Ordering::SeqCst));
    }

    /// Worst case to notice a lost socket: the last good ping just landed,
    /// the window runs out, the next tick waits a period and its send its
    /// deadline. One second of slack for loaded CI runners.
    fn lost_bound() -> Duration {
        ALIVE_WINDOW + WATCHDOG_PERIOD + PING_SEND_DEADLINE + Duration::from_secs(1)
    }

    #[test]
    fn replaced_socket_detected_by_self_ping() {
        let dir = tempfile::tempdir().unwrap();
        let run = dir.path().join("run");
        let (_n, cb) = counter();
        let control = ControlServer::start(&run, ACC, signer(), cb, None).unwrap();
        let path = control.path().to_owned();
        fs::remove_file(&path).unwrap();
        // A foreign listener that accepts and reads everything.
        let foreign = UnixListener::bind(&path).unwrap();
        thread::spawn(move || {
            for s in foreign.incoming().flatten() {
                let mut sink = Vec::new();
                let _ = (&s).take(1 << 16).read_to_end(&mut sink);
            }
        });
        let flag = control.lost_flag();
        let took = wait_for(
            || flag.load(Ordering::SeqCst),
            lost_bound() + Duration::from_secs(2),
        );
        assert!(flag.load(Ordering::SeqCst));
        assert!(took < lost_bound(), "{took:?}");
        assert!(!control.alive());
        // Dropping the server leaves the foreign socket alone.
        drop(control);
        assert!(path.exists());
    }

    #[test]
    fn stalling_and_dead_sockets_bounded_by_one_deadline() {
        let dir = tempfile::tempdir().unwrap();
        let run = dir.path().join("run");
        let (_n, cb) = counter();
        let _control = ControlServer::start(&run, ACC, signer(), cb, None).unwrap();
        // 1.sock accepts and never answers; 2.sock never accepts; 3.sock is
        // stale (nobody listens).
        let stalling = UnixListener::bind(run.join("1.sock")).unwrap();
        thread::spawn(move || {
            let mut held = Vec::new();
            for s in stalling.incoming().flatten() {
                held.push(s);
            }
        });
        let _backlog = UnixListener::bind(run.join("2.sock")).unwrap();
        drop(UnixListener::bind(run.join("3.sock")).unwrap());

        let t = Instant::now();
        let out = notify_servers(
            &run,
            ACC,
            &TestSigner::new(),
            &grants_change(4),
            Duration::from_millis(500),
            &|_| true,
        )
        .unwrap();
        let took = t.elapsed();
        assert!(took < Duration::from_millis(1500), "{took:?}");
        assert_eq!(out.reached, reached_me());
        assert_eq!(out.failed, vec!["1.sock", "2.sock", "3.sock"]);
        // Nothing deleted.
        for n in ["1.sock", "2.sock", "3.sock"] {
            assert!(run.join(n).exists());
        }
    }

    #[test]
    fn ack_with_another_pid_is_not_counted() {
        let dir = tempfile::tempdir().unwrap();
        let run = dir.path().join("run");
        let (n, cb) = counter();
        // A genuine server whose socket name is not its pid.
        let _control = ControlServer::bind(&run.join("1.sock"), ACC, signer(), cb, None).unwrap();
        let out = notify_servers(
            &run,
            ACC,
            &TestSigner::new(),
            &grants_change(2),
            DEFAULT_NOTIFY_DEADLINE,
            &|_| true,
        )
        .unwrap();
        assert!(out.reached.is_empty());
        assert_eq!(out.failed, vec!["1.sock"]);
        assert_eq!(n.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn fake_listener_cannot_ack() {
        let dir = tempfile::tempdir().unwrap();
        let run = dir.path().join("run");
        fs::create_dir(&run).unwrap();
        let fake = UnixListener::bind(run.join("4242.sock")).unwrap();
        let t = thread::spawn(move || {
            for round in 0..2 {
                let (st, _) = fake.accept().unwrap();
                let line =
                    read_line_deadline(&st, Instant::now() + Duration::from_secs(5)).unwrap();
                let msg: Notify = serde_json::from_str(&line).unwrap();
                let sig = if round == 0 {
                    // Its own key.
                    TestSigner([9u8; 32])
                        .sign(ACK_DOMAIN, &ack_bytes(&msg.nonce, 4242, msg.generation))
                        .unwrap()
                } else {
                    // The notification signature echoed back.
                    BASE64.decode(msg.sig.as_bytes()).unwrap()
                };
                let ack = Ack {
                    nonce: msg.nonce,
                    pid: 4242,
                    generation: msg.generation,
                    sig: BASE64.encode(&sig),
                };
                let text = format!("{}\n", serde_json::to_string(&ack).unwrap());
                assert!(write_deadline(
                    &st,
                    text.as_bytes(),
                    Instant::now() + Duration::from_secs(5)
                ));
            }
        });
        for _ in 0..2 {
            let out = notify_servers(
                &run,
                ACC,
                &TestSigner::new(),
                &grants_change(5),
                DEFAULT_NOTIFY_DEADLINE,
                &|_| true,
            )
            .unwrap();
            assert!(out.reached.is_empty());
            assert_eq!(out.failed, vec!["4242.sock"]);
        }
        t.join().unwrap();
    }

    #[test]
    fn too_many_sockets_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let run = dir.path().join("run");
        fs::create_dir(&run).unwrap();
        for i in 0..=MAX_CONTROL_SOCKETS {
            drop(UnixListener::bind(run.join(format!("{}.sock", 10_000 + i))).unwrap());
        }
        assert!(matches!(
            notify_servers(
                &run,
                ACC,
                &TestSigner::new(),
                &grants_change(1),
                DEFAULT_NOTIFY_DEADLINE,
                &|_| true
            ),
            Err(GuardError::Config(_))
        ));
        let none = notify_servers(
            &dir.path().join("absent"),
            ACC,
            &TestSigner::new(),
            &grants_change(1),
            DEFAULT_NOTIFY_DEADLINE,
            &|_| true,
        )
        .unwrap();
        assert_eq!(none, NotifyOutcome::default());
    }

    #[test]
    fn server_caps_concurrent_connections() {
        let dir = tempfile::tempdir().unwrap();
        let run = dir.path().join("run");
        let (_n, cb) = counter();
        let control = ControlServer::start(&run, ACC, signer(), cb, None).unwrap();
        let held: Vec<UnixStream> = (0..MAX_SERVER_CONNS)
            .map(|_| UnixStream::connect(control.path()).unwrap())
            .collect();
        thread::sleep(Duration::from_millis(200));
        let mut extra = UnixStream::connect(control.path()).unwrap();
        extra
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let t = Instant::now();
        let mut b = [0u8; 1];
        assert_eq!(extra.read(&mut b).unwrap(), 0);
        assert!(
            t.elapsed() < Duration::from_millis(1000),
            "{:?}",
            t.elapsed()
        );
        drop(held);
        thread::sleep(Duration::from_millis(200));
        let out = notify_servers(
            &run,
            ACC,
            &TestSigner::new(),
            &grants_change(1),
            DEFAULT_NOTIFY_DEADLINE,
            &|_| true,
        )
        .unwrap();
        assert_eq!(out.reached, reached_me());
    }

    #[test]
    fn slow_client_cut_after_two_seconds() {
        let dir = tempfile::tempdir().unwrap();
        let run = dir.path().join("run");
        let (_n, cb) = counter();
        let control = ControlServer::start(&run, ACC, signer(), cb, None).unwrap();
        let st = UnixStream::connect(control.path()).unwrap();
        let t = Instant::now();
        // One byte every 100 ms, never a newline.
        let mut w = &st;
        while w.write_all(b"{").is_ok() && t.elapsed() < Duration::from_secs(6) {
            thread::sleep(Duration::from_millis(100));
        }
        let took = t.elapsed();
        assert!(took >= Duration::from_millis(1900), "{took:?}");
        assert!(took < Duration::from_millis(3500), "{took:?}");
    }

    #[test]
    fn socket_path_too_long_is_a_clear_error() {
        let dir = tempfile::tempdir().unwrap();
        let run = dir.path().join("r".repeat(SUN_PATH_LEN));
        let (_n, cb) = counter();
        let err = ControlServer::start(&run, ACC, signer(), cb, None).unwrap_err();
        assert_eq!(err, GuardError::Config(PATH_TOO_LONG));
        assert_eq!(
            err.to_string(),
            "data directory path too long for a control socket"
        );
    }

    #[test]
    fn bind_never_replaces_a_live_socket_or_a_file() {
        let dir = tempfile::tempdir().unwrap();
        let run = dir.path().join("run");
        let (_n, cb) = counter();
        let live = ControlServer::start(&run, ACC, signer(), cb.clone(), None).unwrap();
        assert_eq!(
            ControlServer::bind(live.path(), ACC, signer(), cb.clone(), None).unwrap_err(),
            GuardError::Io(ErrorKind::AddrInUse)
        );
        let file = run.join("2.sock");
        fs::write(&file, b"x").unwrap();
        assert_eq!(
            ControlServer::bind(&file, ACC, signer(), cb.clone(), None).unwrap_err(),
            GuardError::Io(ErrorKind::AlreadyExists)
        );
        // A stale socket is replaced, and the server removes its own on drop.
        let stale = run.join("3.sock");
        drop(UnixListener::bind(&stale).unwrap());
        let s3 = ControlServer::bind(&stale, ACC, signer(), cb, None).unwrap();
        assert!(s3.alive());
        drop(s3);
        assert!(!stale.exists());
    }

    #[test]
    fn pushed_selector_refuses_grant_the_revoking_command_never_saw() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("grants.json");
        let run = dir.path().join("run");
        let s = TestSigner::new();
        let c = Arc::new(FakeClock::new(1_800_000_000));
        let (server, _control) = grant_server(&path, &run, &c);
        // F0 without G, F1 with G.
        server
            .lock()
            .unwrap()
            .add(&s, &c, req("platform:o", "ko"), DEFAULT_GRANT_TTL)
            .unwrap();
        let f0 = fs::read(&path).unwrap();
        c.advance(Duration::from_secs(5));
        server
            .lock()
            .unwrap()
            .add(&s, &c, req("platform:a", "k1"), DEFAULT_GRANT_TTL)
            .unwrap();
        let f1 = fs::read(&path).unwrap();
        // F0 restored, then `revoke --all` sees no G.
        fs::write(&path, &f0).unwrap();
        c.advance(Duration::from_secs(5));
        let out = GrantStore::open(&path, ACC)
            .revoke(&s, &c, Revoke::All)
            .unwrap();
        let change = ControlChange::Grants {
            generation: out.generation,
            revoked: out.revoked,
            selectors: vec![out.selector],
        };
        let n = notify_servers(&run, ACC, &s, &change, DEFAULT_NOTIFY_DEADLINE, &|_| true).unwrap();
        assert_eq!(n.reached, reached_me());
        // F1 restored: G is refused.
        fs::write(&path, &f1).unwrap();
        assert_eq!(server_check(&server, &s, &c), GrantCheck::Revoked);
    }

    #[test]
    fn only_live_pid_sockets_are_contacted() {
        let dir = tempfile::tempdir().unwrap();
        let run = dir.path().join("run");
        let (_n, cb) = counter();
        let _control = ControlServer::start(&run, ACC, signer(), cb, None).unwrap();
        for name in [
            "abc.sock",
            "12345678901.sock",
            "-1.sock",
            "7.sock.bak",
            "77.sock",
        ] {
            drop(UnixListener::bind(run.join(name)).unwrap());
        }
        let asked = Mutex::new(Vec::new());
        let alive = |pid: u32| {
            asked.lock().unwrap().push(pid);
            pid == me()
        };
        let out = notify_servers(
            &run,
            ACC,
            &TestSigner::new(),
            &grants_change(1),
            DEFAULT_NOTIFY_DEADLINE,
            &alive,
        )
        .unwrap();
        assert_eq!(out.reached, reached_me());
        assert!(out.failed.is_empty());
        let mut asked = asked.into_inner().unwrap();
        asked.sort();
        assert_eq!(asked, {
            let mut v = vec![77, me()];
            v.sort();
            v
        });
        assert_eq!(socket_pid("4294967295.sock"), Some(u32::MAX));
        assert_eq!(socket_pid("4294967296.sock"), None);
        assert_eq!(socket_pid(".sock"), None);
        assert_eq!(socket_pid("+1.sock"), None);
    }
}
