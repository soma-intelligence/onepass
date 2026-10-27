//! The agent's Unix socket (spec 6.2): parent directory `0700`, socket
//! `0600`, one thread per connection.

use std::fs::{self, DirBuilder, Permissions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use onepass_peer::{effective_uid, exe_path, peer_cred};

use crate::agent::{Agent, ConnState, KeySource, PeerInfo};
use crate::wire::{decode_request, encode_response, read_frame};

/// Credentials of the peer of `s`: uid, pid and executable path.
pub fn peer_info(s: &UnixStream) -> PeerInfo {
    let cred = peer_cred(s);
    PeerInfo {
        uid: cred.uid,
        pid: cred.pid,
        exe: cred
            .pid
            .and_then(exe_path)
            .and_then(|p| p.into_os_string().into_string().ok()),
    }
}

/// Pause between two non-blocking `accept` calls, when `stop` is checked.
const POLL: Duration = Duration::from_millis(100);

/// Creates the socket at `path`, which must name its directory. The parent
/// directory is created `0700` if missing, and set to `0700` if it exists
/// and belongs to this user. An existing socket at `path` is replaced only
/// when nothing answers on it (a stale agent); if a connection succeeds the
/// call fails with `AddrInUse`. Anything else at `path` is left alone and
/// the call fails with `AlreadyExists`. The socket is `0600`.
pub fn bind_socket(path: &Path) -> io::Result<UnixListener> {
    // A bare file name would make the current directory the parent and
    // change its mode: ask for an explicit directory instead.
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "the socket path needs a parent directory",
            ));
        }
    };
    match fs::metadata(parent) {
        Ok(m) => {
            if !m.is_dir() {
                return Err(io::Error::new(
                    io::ErrorKind::NotADirectory,
                    "socket parent is not a directory",
                ));
            }
            if m.uid() == effective_uid() && m.permissions().mode() & 0o777 != 0o700 {
                fs::set_permissions(parent, Permissions::from_mode(0o700))?;
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)?;
            // The mode above is filtered by the umask.
            fs::set_permissions(parent, Permissions::from_mode(0o700))?;
        }
        Err(e) => return Err(e),
    }
    match fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_socket() => {
            if UnixStream::connect(path).is_ok() {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    "another agent is serving this socket",
                ));
            }
            fs::remove_file(path)?
        }
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "a file that is not a socket exists at the socket path",
            ));
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let listener = UnixListener::bind(path)?;
    fs::set_permissions(path, Permissions::from_mode(0o600))?;
    Ok(listener)
}

/// Accepts connections until `stop` is set, checked every 100 ms between
/// non-blocking `accept` calls. Each connection gets its own thread; all of
/// them share `agent`, so approval prompts are serialized. Connections
/// already open when `stop` is set are not interrupted.
pub fn serve<K: KeySource + 'static>(
    listener: UnixListener,
    agent: Arc<Mutex<Agent<K>>>,
    stop: Arc<AtomicBool>,
) -> io::Result<()> {
    listener.set_nonblocking(true)?;
    while !stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _)) => {
                // BSD sockets inherit O_NONBLOCK from the listener. A
                // connection that cannot be set up is dropped, the agent
                // keeps serving.
                if stream.set_nonblocking(false).is_err() {
                    continue;
                }
                let agent = Arc::clone(&agent);
                let spawned = thread::Builder::new()
                    .name("ssh-agent-conn".into())
                    .spawn(move || connection(stream, &agent));
                drop(spawned);
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            // WouldBlock: nothing to accept. Other errors (a client gone
            // before accept, too many open files) are transient for a
            // long-running agent: wait and retry.
            Err(_) => thread::sleep(POLL),
        }
    }
    Ok(())
}

/// Serves one client until it disconnects, sends a malformed message, or
/// the agent asks to close.
fn connection<K: KeySource>(mut stream: UnixStream, agent: &Mutex<Agent<K>>) {
    let peer = peer_info(&stream);
    let mut conn = ConnState::default();
    loop {
        let body = match read_frame(&mut stream) {
            Ok(Some(body)) => body,
            Ok(None) | Err(_) => return,
        };
        // Spec 6.2: any decoding error closes the connection.
        let Ok(request) = decode_request(&body) else {
            return;
        };
        let reply = {
            // A panic under the lock leaves the agent state suspect: stop
            // serving this client rather than reuse it.
            let Ok(mut agent) = agent.lock() else {
                return;
            };
            agent.handle(&mut conn, &peer, request)
        };
        if stream.write_all(&encode_response(&reply.response)).is_err() || reply.close {
            return;
        }
    }
}
