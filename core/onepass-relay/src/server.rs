//! The app's listener on `bridge.sock`, and the client side used by the
//! relay (and the tests).
//!
//! The listener checks each client's code signature before reading
//! anything from it, then reads the opening frame within a short delay,
//! then hands the connection to the bridge host loop on a thread of its
//! own (16 MiB of stack: the core verifies SLH-DSA signatures on it). At
//! most `max_connections` connections are served at once; any other one is
//! closed at once.

use std::fs;
use std::io::{self, ErrorKind, Read, Write};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use onepass_bridge::framing::{read_frame, write_frame};
use onepass_peer::{CodeIdentity, PeerError};

use crate::preamble::Preamble;
use crate::rendezvous::{Client, SAFARI_EXTENSION_ID, classify_client, is_app};

/// Stack of each connection thread.
pub const CONNECTION_STACK: usize = 16 << 20;
/// Connections served at once (spec P-14).
pub const MAX_CONNECTIONS: usize = 8;
/// Longest wait for the opening frame.
pub const OPENING_TIMEOUT: Duration = Duration::from_secs(5);

/// How the peer of a stream is identified (the audit token in production;
/// tests inject a fixed identity, since test binaries are signed ad hoc).
pub type Identify = Arc<dyn Fn(&UnixStream) -> Result<CodeIdentity, PeerError> + Send + Sync>;
/// Journal of the listener: fixed messages only.
pub type Note = Arc<dyn Fn(&str) + Send + Sync>;

/// A client that passed the checks.
pub struct Accepted {
    pub client: Client,
    /// `safari` for Safari, the browser-given id for the relay.
    pub extension_id: String,
    pub stream: UnixStream,
}

pub struct ServerConfig {
    pub path: PathBuf,
    /// The team the clients must be signed by (the app's own).
    pub team: String,
    pub max_connections: usize,
    pub opening_timeout: Duration,
    pub identify: Identify,
    pub note: Note,
}

/// A running listener. Dropping it stops it and removes the socket file.
pub struct Server {
    path: PathBuf,
    stop: Arc<AtomicBool>,
    accept: Option<JoinHandle<()>>,
}

/// Bind `path`: a stale socket left by a crash is replaced, a live one
/// (another instance of the app) is not, and anything that is not a socket
/// is never removed.
fn bind(path: &Path) -> io::Result<UnixListener> {
    match fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_socket() => {
            if UnixStream::connect(path).is_ok() {
                return Err(io::Error::new(ErrorKind::AddrInUse, "bridge socket in use"));
            }
            fs::remove_file(path)?;
        }
        Ok(_) => {
            return Err(io::Error::new(
                ErrorKind::AlreadyExists,
                "bridge socket path is taken by another file",
            ));
        }
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let l = UnixListener::bind(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(l)
}

/// Releases a connection slot when the connection ends.
struct Slot(Arc<AtomicUsize>);

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Identify, classify and read the opening frame of `stream`.
fn admit(stream: UnixStream, cfg: &ServerConfig) -> Result<Accepted, &'static str> {
    let id = (cfg.identify)(&stream).map_err(|_| "client not identified")?;
    let client = classify_client(&id, &cfg.team).ok_or("client refused by code signature")?;
    stream
        .set_read_timeout(Some(cfg.opening_timeout))
        .map_err(|_| "socket error")?;
    let first = read_frame(&mut &stream)
        .map_err(|_| "no opening frame")?
        .ok_or("no opening frame")?;
    let p = Preamble::parse(&first).ok_or("bad opening frame")?;
    let extension_id = match (client, p.extension) {
        (Client::Safari, None) => SAFARI_EXTENSION_ID.to_owned(),
        (Client::Relay, Some(id)) => id,
        _ => return Err("opening frame does not fit the client"),
    };
    stream.set_read_timeout(None).map_err(|_| "socket error")?;
    Ok(Accepted {
        client,
        extension_id,
        stream,
    })
}

impl Server {
    pub fn start(
        cfg: ServerConfig,
        handler: Arc<dyn Fn(Accepted) + Send + Sync>,
    ) -> io::Result<Server> {
        let listener = bind(&cfg.path)?;
        let stop = Arc::new(AtomicBool::new(false));
        let path = cfg.path.clone();
        let flag = stop.clone();
        let cfg = Arc::new(cfg);
        let active = Arc::new(AtomicUsize::new(0));
        let accept = thread::Builder::new()
            .name("me.somalabs.onepass.bridge.accept".into())
            .spawn(move || {
                for conn in listener.incoming() {
                    if flag.load(Ordering::SeqCst) {
                        return;
                    }
                    let Ok(stream) = conn else { continue };
                    if active.fetch_add(1, Ordering::SeqCst) >= cfg.max_connections {
                        active.fetch_sub(1, Ordering::SeqCst);
                        (cfg.note)("too many bridge connections, closing one");
                        continue;
                    }
                    let slot = Slot(active.clone());
                    let (cfg, handler) = (cfg.clone(), handler.clone());
                    let spawned = thread::Builder::new()
                        .name("me.somalabs.onepass.bridge.conn".into())
                        .stack_size(CONNECTION_STACK)
                        .spawn(move || {
                            let _slot = slot;
                            match admit(stream, &cfg) {
                                Ok(a) => handler(a),
                                Err(why) => (cfg.note)(why),
                            }
                        });
                    if spawned.is_err() {
                        // The slot was moved into the closure, dropped with it.
                        continue;
                    }
                }
            })?;
        Ok(Server {
            path,
            stop,
            accept: Some(accept),
        })
    }

    /// Stop accepting and remove the socket file. Connections already
    /// served run to their end.
    pub fn stop(&mut self) {
        if self.stop.swap(true, Ordering::SeqCst) {
            return;
        }
        // Wake the blocking accept. When the socket file is already gone
        // nothing can reach the listener any more: leave its thread parked.
        let woken = UnixStream::connect(&self.path).is_ok();
        if let Some(t) = self.accept.take()
            && woken
        {
            let _ = t.join();
        }
        let _ = fs::remove_file(&self.path);
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Connect to the app at `path`, check that the listener is the OnePass app
/// signed by `team`, and send the opening frame.
pub fn connect(
    path: &Path,
    team: &str,
    identify: &dyn Fn(&UnixStream) -> Result<CodeIdentity, PeerError>,
    preamble: &Preamble,
) -> io::Result<UnixStream> {
    let stream = UnixStream::connect(path)?;
    let id = identify(&stream).map_err(|_| io::Error::from(ErrorKind::PermissionDenied))?;
    if !is_app(&id, team) {
        return Err(io::Error::from(ErrorKind::PermissionDenied));
    }
    write_frame(&mut &stream, &preamble.to_bytes())
        .map_err(|_| io::Error::from(ErrorKind::BrokenPipe))?;
    Ok(stream)
}

/// Copy frames both ways until either side ends: `input` (the browser) to
/// the app, the app to `output`. Frames are never parsed; each is at most
/// 1 MiB, a longer one ends the relay. Returns when the app's side ends;
/// the end of `input` half-closes the socket so the app sees it.
pub fn pump<R, W>(input: R, mut output: W, stream: UnixStream) -> io::Result<()>
where
    R: Read + Send + 'static,
    W: Write,
{
    let to_app = stream.try_clone()?;
    thread::spawn(move || {
        let mut input = input;
        let mut to_app = to_app;
        while let Ok(Some(f)) = read_frame(&mut input) {
            if write_frame(&mut to_app, &f).is_err() {
                break;
            }
        }
        let _ = to_app.shutdown(std::net::Shutdown::Both);
    });
    let mut from_app = stream;
    while let Ok(Some(f)) = read_frame(&mut from_app) {
        if write_frame(&mut output, &f).is_err() {
            break;
        }
    }
    let _ = from_app.shutdown(std::net::Shutdown::Both);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::sync::mpsc::channel;

    use crate::rendezvous::{APP_ID, RELAY_ID, SAFARI_ID};

    const TEAM: &str = "ABCDE12345";

    fn team(id: &str) -> CodeIdentity {
        CodeIdentity::Team {
            team_id: TEAM.into(),
            identifier: id.into(),
        }
    }

    fn fixed(id: CodeIdentity) -> Identify {
        Arc::new(move |_| Ok(id.clone()))
    }

    // Fields drop in order: the server stops before its directory goes.
    struct Rig {
        server: Server,
        _dir: tempfile::TempDir,
        path: PathBuf,
        accepted: std::sync::mpsc::Receiver<(Client, String)>,
        notes: Arc<Mutex<Vec<String>>>,
    }

    /// A server whose clients all look like `client`; each accepted
    /// connection echoes frames back until its end.
    fn rig(client: CodeIdentity, max: usize) -> Rig {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("b.sock");
        let (tx, accepted) = channel();
        let tx = Mutex::new(tx);
        let notes = Arc::new(Mutex::new(Vec::new()));
        let n = notes.clone();
        let server = Server::start(
            ServerConfig {
                path: path.clone(),
                team: TEAM.into(),
                max_connections: max,
                opening_timeout: Duration::from_millis(300),
                identify: fixed(client),
                note: Arc::new(move |m| n.lock().unwrap().push(m.to_owned())),
            },
            Arc::new(move |a: Accepted| {
                tx.lock()
                    .unwrap()
                    .send((a.client, a.extension_id.clone()))
                    .unwrap();
                let mut s = a.stream;
                while let Ok(Some(f)) = read_frame(&mut s) {
                    if write_frame(&mut s, &f).is_err() {
                        break;
                    }
                }
            }),
        )
        .unwrap();
        Rig {
            server,
            _dir: dir,
            path,
            accepted,
            notes,
        }
    }

    fn app() -> impl Fn(&UnixStream) -> Result<CodeIdentity, PeerError> {
        |_| Ok(team(APP_ID))
    }

    #[test]
    fn relay_client_is_admitted_with_its_extension_id_and_frames_flow() {
        let rig = rig(team(RELAY_ID), 8);
        let mut s = connect(&rig.path, TEAM, &app(), &Preamble::new(Some("abc".into()))).unwrap();
        let (client, ext) = rig.accepted.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!((client, ext.as_str()), (Client::Relay, "abc"));
        write_frame(&mut s, br#"{"v":1}"#).unwrap();
        assert_eq!(read_frame(&mut s).unwrap().unwrap(), br#"{"v":1}"#);
        let mode = fs::metadata(&rig.path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn safari_client_is_admitted_as_safari() {
        let rig = rig(team(SAFARI_ID), 8);
        let _s = connect(&rig.path, TEAM, &app(), &Preamble::new(None)).unwrap();
        let (client, ext) = rig.accepted.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(
            (client, ext.as_str()),
            (Client::Safari, SAFARI_EXTENSION_ID)
        );
    }

    fn refused(rig: &Rig, preamble: &Preamble) {
        let mut s = connect(&rig.path, TEAM, &app(), preamble).unwrap();
        // The server closes without a byte.
        assert!(matches!(read_frame(&mut s), Ok(None) | Err(_)));
        assert!(rig.accepted.try_recv().is_err());
    }

    #[test]
    fn unknown_signatures_are_closed_before_any_read() {
        for id in [
            team(APP_ID),
            team("me.somalabs.onepass.autofill"),
            CodeIdentity::Team {
                team_id: "AAAAAAAAAA".into(),
                identifier: SAFARI_ID.into(),
            },
            CodeIdentity::AdHoc {
                path: "/tmp/x".into(),
                cdhash: "00".into(),
                hardened: true,
            },
        ] {
            let rig = rig(id, 8);
            refused(&rig, &Preamble::new(None));
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            while rig.notes.lock().unwrap().is_empty() {
                assert!(std::time::Instant::now() < deadline);
                thread::sleep(Duration::from_millis(5));
            }
            assert_eq!(
                rig.notes.lock().unwrap()[0],
                "client refused by code signature"
            );
        }
    }

    #[test]
    fn opening_frame_must_fit_the_client() {
        // Safari never names an extension; the relay always does.
        refused(&rig(team(SAFARI_ID), 8), &Preamble::new(Some("abc".into())));
        refused(&rig(team(RELAY_ID), 8), &Preamble::new(None));
    }

    #[test]
    fn silent_client_is_dropped_after_the_opening_timeout() {
        let rig = rig(team(RELAY_ID), 8);
        let mut s = UnixStream::connect(&rig.path).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        assert!(matches!(read_frame(&mut s), Ok(None)));
        assert!(rig.accepted.try_recv().is_err());
    }

    #[test]
    fn client_refuses_a_listener_that_is_not_the_app() {
        let rig = rig(team(RELAY_ID), 8);
        for wrong in [
            team(RELAY_ID),
            CodeIdentity::Team {
                team_id: "AAAAAAAAAA".into(),
                identifier: APP_ID.into(),
            },
        ] {
            let id = move |_: &UnixStream| Ok(wrong.clone());
            let e = connect(&rig.path, TEAM, &id, &Preamble::new(Some("abc".into()))).unwrap_err();
            assert_eq!(e.kind(), ErrorKind::PermissionDenied);
        }
    }

    #[test]
    fn connections_beyond_the_cap_are_closed() {
        let rig = rig(team(RELAY_ID), 1);
        let _first = connect(&rig.path, TEAM, &app(), &Preamble::new(Some("a".into()))).unwrap();
        rig.accepted.recv_timeout(Duration::from_secs(2)).unwrap();
        // The server may close the extra connection before the client's
        // preamble is written (BrokenPipe on Linux) or right after it.
        if let Ok(mut second) = connect(&rig.path, TEAM, &app(), &Preamble::new(Some("b".into()))) {
            assert!(matches!(read_frame(&mut second), Ok(None) | Err(_)));
        }
        assert!(rig.accepted.try_recv().is_err());
    }

    #[test]
    fn live_socket_is_not_stolen_and_stale_one_is_replaced() {
        let rig = rig(team(RELAY_ID), 8);
        let e = bind(&rig.path).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::AddrInUse);
        let path = rig.path.clone();
        let mut server = rig.server;
        server.stop();
        assert!(!path.exists());
        // A stale socket file (no listener) is replaced.
        drop(UnixListener::bind(&path).unwrap());
        assert!(path.exists());
        drop(bind(&path).unwrap());
        // Any other file is left alone.
        fs::remove_file(&path).unwrap();
        fs::write(&path, b"x").unwrap();
        assert_eq!(bind(&path).unwrap_err().kind(), ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&path).unwrap(), b"x");
    }

    #[test]
    fn pump_relays_both_ways_and_half_closes() {
        let (app_side, relay_side) = UnixStream::pair().unwrap();
        let (mut browser_in, pump_in) = UnixStream::pair().unwrap();
        let (pump_out, mut browser_out) = UnixStream::pair().unwrap();
        let t = thread::spawn(move || pump(pump_in, pump_out, relay_side).unwrap());
        let mut app = app_side;
        write_frame(&mut browser_in, b"to-app").unwrap();
        assert_eq!(read_frame(&mut app).unwrap().unwrap(), b"to-app");
        write_frame(&mut app, b"to-browser").unwrap();
        assert_eq!(
            read_frame(&mut browser_out).unwrap().unwrap(),
            b"to-browser"
        );
        // The browser ends: the app sees the end, closes, the pump returns.
        drop(browser_in);
        assert!(matches!(read_frame(&mut app), Ok(None)));
        drop(app);
        t.join().unwrap();
        assert!(matches!(read_frame(&mut browser_out), Ok(None)));
    }

    #[test]
    fn pump_stops_on_an_oversized_frame() {
        let (app_side, relay_side) = UnixStream::pair().unwrap();
        let (mut browser_in, pump_in) = UnixStream::pair().unwrap();
        let (pump_out, mut browser_out) = UnixStream::pair().unwrap();
        let t = thread::spawn(move || pump(pump_in, pump_out, relay_side).unwrap());
        let mut app = app_side;
        let too_big = (onepass_bridge::framing::MAX_FRAME as u32 + 1).to_le_bytes();
        app.write_all(&too_big).unwrap();
        t.join().unwrap();
        assert!(matches!(read_frame(&mut browser_out), Ok(None)));
        drop(browser_in.write_all(b"x"));
    }
}
