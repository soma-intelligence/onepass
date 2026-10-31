//! The "app open" wake channel (spec 4.10): the public Realtime broadcast
//! channel `mbx:<hex wake_topic>`, over a WebSocket and the Phoenix v1
//! protocol, with the publishable key.
//!
//! A wake means only "fetch". Of each message the listener reads the
//! topic, the event and, for a broadcast, the broadcast's event name;
//! never its payload, which the real `realtime.send` fills with an `id`
//! and a hostile server with anything. One thread per listener, blocking
//! I/O, TLS 1.3 through the client's own `rustls` configuration.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use onepass_mailbox_proto::hex;
use rustls::pki_types::ServerName;
use rustls::{ClientConnection, StreamOwned};
use serde::Deserialize;
use tungstenite::client::IntoClientRequest;
use tungstenite::protocol::WebSocketConfig;
use tungstenite::{Message, WebSocket};

use crate::MailboxError;
use crate::http::{Endpoint, check_url, tls_client_config};

/// Phoenix heartbeat period.
const HEARTBEAT: Duration = Duration::from_secs(25);
/// A join with no reply by then is given up (as the Phoenix JS client).
const JOIN_TIMEOUT: Duration = Duration::from_secs(10);
/// Waits before each reconnection, the last one repeated.
const BACKOFF: [Duration; 5] = [
    Duration::from_secs(1),
    Duration::from_secs(2),
    Duration::from_secs(5),
    Duration::from_secs(10),
    Duration::from_secs(30),
];
/// A joined connection must last this long for the waits to start over:
/// a server that accepts the join then drops cannot make the listener
/// (and its catch-up wake) spin.
const STABLE: Duration = Duration::from_secs(60);
/// One deadline for TCP connect (every address), TLS and the WebSocket
/// upgrade together.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Longest TCP connect to one address.
const CONNECT_ONE: Duration = Duration::from_secs(5);
/// Longest blocking write once connected.
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
/// How often the reading loop looks at the clock and the stop flag.
const TICK: Duration = Duration::from_millis(100);
/// Longest `stop` (or a drop) waits for the thread before leaving it.
const STOP_WAIT: Duration = Duration::from_secs(1);
/// Largest message or frame taken from the server.
const MESSAGE_MAX: usize = 64 * 1024;
/// Longest publishable key taken.
const KEY_MAX: usize = 1024;

/// The time the listener goes by: injected in tests.
pub(crate) trait WakeClock: Send + Sync {
    fn now(&self) -> Duration;
    fn sleep(&self, d: Duration);
}

struct SystemClock(Instant);

impl WakeClock for SystemClock {
    fn now(&self) -> Duration {
        self.0.elapsed()
    }

    fn sleep(&self, d: Duration) {
        std::thread::sleep(d);
    }
}

type OnWake = Box<dyn Fn() + Send + Sync>;

/// Where to connect, checked once at `start`.
struct Target {
    /// `wss://.../websocket?apikey=...&vsn=1.0.0`.
    url: String,
    host: String,
    port: u16,
    tls: Option<Arc<rustls::ClientConfig>>,
    /// `realtime:mbx:<hex>`.
    topic: String,
    handshake: Duration,
}

/// What the listener and its thread share.
struct Shared {
    /// Checked by every loop of the thread.
    stop: AtomicBool,
    /// Set by `stop` under this lock; `on_wake` runs only under it while
    /// false, so no call starts once `stop` has returned.
    stopped: Mutex<bool>,
    /// The thread has ended.
    done: Mutex<bool>,
    ended: Condvar,
    on_wake: OnWake,
}

impl Shared {
    fn stopping(&self) -> bool {
        self.stop.load(Ordering::SeqCst)
    }

    /// Calls `on_wake` unless stopped. A panic in it is contained: the
    /// listener goes on.
    fn wake(&self) {
        let stopped = self.stopped.lock().unwrap_or_else(|e| e.into_inner());
        if !*stopped {
            let _ = catch_unwind(AssertUnwindSafe(|| (self.on_wake)()));
        }
    }
}

/// Marks the thread ended, however it ends.
struct Ended<'a>(&'a Shared);

impl Drop for Ended<'_> {
    fn drop(&mut self) {
        *self.0.done.lock().unwrap_or_else(|e| e.into_inner()) = true;
        self.0.ended.notify_all();
    }
}

/// Listens to one mailbox's wake channel until stopped, reconnecting after
/// 1, 2, 5, 10, then every 30 s (the waits start over once a connection
/// has lasted a minute). After a reconnection, `on_wake` runs once (a wake
/// may have been missed while the channel was down).
///
/// `on_wake` runs on the listener's thread and should return quickly:
/// `stop` waits for a call in progress.
pub struct WakeListener {
    shared: Arc<Shared>,
}

impl WakeListener {
    /// Starts listening on `realtime_url` (from `/v1/config`, `wss://`)
    /// with `publishable_key`. Only the URL and key are checked here; the
    /// connection is made, and made again, in the background.
    pub fn start(
        realtime_url: &str,
        publishable_key: &str,
        wake_topic: [u8; 16],
        on_wake: Box<dyn Fn() + Send + Sync>,
    ) -> Result<WakeListener, MailboxError> {
        WakeListener::start_with_ca(realtime_url, publishable_key, wake_topic, None, on_wake)
    }

    /// `start` for a self-host whose CA (PEM) is trusted on top of the web
    /// roots, as `Endpoint::extra_ca_pem`.
    pub fn start_with_ca(
        realtime_url: &str,
        publishable_key: &str,
        wake_topic: [u8; 16],
        extra_ca_pem: Option<String>,
        on_wake: Box<dyn Fn() + Send + Sync>,
    ) -> Result<WakeListener, MailboxError> {
        let target = target(realtime_url, publishable_key, wake_topic, extra_ca_pem)?;
        spawn(target, Arc::new(SystemClock(Instant::now())), on_wake)
    }

    /// Stops listening. Returns within about 1 s (plus an `on_wake` call
    /// in progress): a thread still in a connect or a write is left to end
    /// on its own. `on_wake` is never called once this returns.
    pub fn stop(self) {}
}

impl Drop for WakeListener {
    fn drop(&mut self) {
        let s = &self.shared;
        s.stop.store(true, Ordering::SeqCst);
        *s.stopped.lock().unwrap_or_else(|e| e.into_inner()) = true;
        let done = s.done.lock().unwrap_or_else(|e| e.into_inner());
        // Detached past the wait: it holds only its own share.
        let _ = s
            .ended
            .wait_timeout_while(done, STOP_WAIT, |done| !*done)
            .unwrap_or_else(|e| e.into_inner());
    }
}

fn spawn(
    target: Target,
    clock: Arc<dyn WakeClock>,
    on_wake: OnWake,
) -> Result<WakeListener, MailboxError> {
    let shared = Arc::new(Shared {
        stop: AtomicBool::new(false),
        stopped: Mutex::new(false),
        done: Mutex::new(false),
        ended: Condvar::new(),
        on_wake,
    });
    let s = Arc::clone(&shared);
    std::thread::Builder::new()
        .name("onepass-wake".into())
        .spawn(move || {
            let _ended = Ended(&s);
            run(&target, clock.as_ref(), &s);
        })
        .map_err(|_| MailboxError::Malformed("cannot start the wake thread"))?;
    Ok(WakeListener { shared })
}

/// Unreserved characters stay, everything else is percent-encoded.
fn percent(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn target(
    realtime_url: &str,
    key: &str,
    wake_topic: [u8; 16],
    extra_ca_pem: Option<String>,
) -> Result<Target, MailboxError> {
    let base = realtime_url.trim_end_matches('/');
    // The same rules as the HTTP endpoint, `ws` standing for `http`.
    let (tls, rest) = if let Some(rest) = base.strip_prefix("wss://") {
        (true, rest)
    } else if let Some(rest) = base.strip_prefix("ws://") {
        (false, rest)
    } else {
        return Err(MailboxError::Malformed("wss required"));
    };
    let as_http = format!("{}://{rest}", if tls { "https" } else { "http" });
    check_url(&as_http, false).map_err(|_| MailboxError::Malformed("realtime url"))?;
    if key.is_empty() || key.len() > KEY_MAX || !key.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
        return Err(MailboxError::Malformed("publishable key"));
    }
    let authority = rest.split('/').next().unwrap_or("");
    let (host, port) = split_authority(authority, if tls { 443 } else { 80 })?;
    let tls = if tls {
        let endpoint = Endpoint {
            base_url: as_http,
            extra_ca_pem,
        };
        Some(Arc::new(tls_client_config(&endpoint)?))
    } else {
        None
    };
    Ok(Target {
        url: format!("{base}/websocket?apikey={}&vsn=1.0.0", percent(key)),
        host,
        port,
        tls,
        topic: format!("realtime:mbx:{}", hex(&wake_topic)),
        handshake: HANDSHAKE_TIMEOUT,
    })
}

/// `host`, `host:port`, `[v6]` or `[v6]:port`.
fn split_authority(a: &str, default: u16) -> Result<(String, u16), MailboxError> {
    let bad = MailboxError::Malformed("realtime url");
    let (host, port) = if let Some(v6) = a.strip_prefix('[') {
        let (h, after) = v6.split_once(']').ok_or(bad.clone())?;
        match after {
            "" => (h, None),
            p => (h, Some(p.strip_prefix(':').ok_or(bad.clone())?)),
        }
    } else {
        match a.split_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (a, None),
        }
    };
    if host.is_empty() {
        return Err(bad);
    }
    let port = match port {
        None => default,
        Some(p) => p.parse().map_err(|_| bad)?,
    };
    Ok((host.to_string(), port))
}

// ----------------------------------------------------------- connection

/// The TCP stream under TLS and the WebSocket. Until the handshake is done
/// every read and write is bounded by what is left of one deadline.
struct Sock {
    tcp: TcpStream,
    deadline: Option<Instant>,
}

impl Sock {
    fn arm(&self, write: bool) -> io::Result<()> {
        let Some(d) = self.deadline else {
            return Ok(());
        };
        let left = d.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "handshake deadline",
            ));
        }
        if write {
            self.tcp.set_write_timeout(Some(left))
        } else {
            self.tcp.set_read_timeout(Some(left))
        }
    }

    /// The handshake is over: short reads (the loop's tick), bounded writes.
    fn connected(&mut self) -> io::Result<()> {
        self.deadline = None;
        self.tcp.set_read_timeout(Some(TICK))?;
        self.tcp.set_write_timeout(Some(WRITE_TIMEOUT))
    }
}

impl Read for Sock {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.arm(false)?;
        self.tcp.read(buf)
    }
}

impl Write for Sock {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.arm(true)?;
        self.tcp.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.tcp.flush()
    }
}

enum Conn {
    Plain(Sock),
    Tls(Box<StreamOwned<ClientConnection, Sock>>),
}

impl Conn {
    fn sock(&mut self) -> &mut Sock {
        match self {
            Conn::Plain(s) => s,
            Conn::Tls(s) => &mut s.sock,
        }
    }
}

impl Read for Conn {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Conn::Plain(s) => s.read(buf),
            Conn::Tls(s) => s.read(buf),
        }
    }
}

impl Write for Conn {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Conn::Plain(s) => s.write(buf),
            Conn::Tls(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Conn::Plain(s) => s.flush(),
            Conn::Tls(s) => s.flush(),
        }
    }
}

/// TCP (every resolved address), TLS and the WebSocket upgrade, all within
/// `t.handshake`. Name resolution uses the system resolver, which has no
/// timeout of its own: `stop` does not wait for it.
fn connect(t: &Target, shared: &Shared) -> Option<WebSocket<Conn>> {
    let addrs: Vec<SocketAddr> = (t.host.as_str(), t.port).to_socket_addrs().ok()?.collect();
    let deadline = Instant::now() + t.handshake;
    let tcp = addrs.iter().find_map(|a| {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() || shared.stopping() {
            return None;
        }
        TcpStream::connect_timeout(a, left.min(CONNECT_ONE)).ok()
    })?;
    let _ = tcp.set_nodelay(true);
    let sock = Sock {
        tcp,
        deadline: Some(deadline),
    };
    let conn = match &t.tls {
        None => Conn::Plain(sock),
        Some(cfg) => {
            let name = ServerName::try_from(t.host.clone()).ok()?;
            let c = ClientConnection::new(Arc::clone(cfg), name).ok()?;
            Conn::Tls(Box::new(StreamOwned::new(c, sock)))
        }
    };
    let config = WebSocketConfig::default()
        .max_message_size(Some(MESSAGE_MAX))
        .max_frame_size(Some(MESSAGE_MAX));
    let request = t.url.as_str().into_client_request().ok()?;
    let (mut ws, _) = tungstenite::client::client_with_config(request, conn, Some(config)).ok()?;
    ws.get_mut().sock().connected().ok()?;
    Some(ws)
}

// -------------------------------------------------------------- protocol

/// What the listener reads of a Phoenix message. Every other field, the
/// broadcast's payload first, is skipped unread.
#[derive(Deserialize)]
struct Envelope {
    topic: String,
    event: String,
    #[serde(default)]
    payload: Option<Inner>,
    #[serde(rename = "ref", default)]
    reference: Option<String>,
}

/// `payload.event` of a broadcast, `payload.status` of a reply.
#[derive(Deserialize)]
struct Inner {
    #[serde(default)]
    event: Option<String>,
    #[serde(default)]
    status: Option<String>,
}

fn phoenix(topic: &str, event: &str, payload: serde_json::Value, reference: u64) -> Message {
    Message::text(
        serde_json::json!({
            "topic": topic,
            "event": event,
            "payload": payload,
            "ref": reference.to_string(),
        })
        .to_string(),
    )
}

/// How a connection ended.
/// How a connection ended.
enum End {
    Stopped,
    /// `joined`: for how long the join had held, if it was acknowledged.
    Dropped {
        joined: Option<Duration>,
    },
}

fn run(t: &Target, clock: &dyn WakeClock, shared: &Shared) {
    let mut failures = 0usize;
    let mut joined_once = false;
    loop {
        if shared.stopping() {
            return;
        }
        let end = match connect(t, shared) {
            Some(ws) => session(ws, t, clock, shared, joined_once),
            None => End::Dropped { joined: None },
        };
        match end {
            End::Stopped => return,
            End::Dropped { joined: Some(up) } => {
                joined_once = true;
                if up >= STABLE {
                    failures = 0;
                }
            }
            End::Dropped { joined: None } => {}
        }
        let wait = BACKOFF[failures.min(BACKOFF.len() - 1)];
        failures += 1;
        if !pause(clock, wait, shared) {
            return;
        }
    }
}

/// Sleeps `d` in ticks; false when stopped meanwhile.
fn pause(clock: &dyn WakeClock, d: Duration, shared: &Shared) -> bool {
    let until = clock.now() + d;
    while clock.now() < until {
        if shared.stopping() {
            return false;
        }
        clock.sleep(TICK.min(until - clock.now()));
    }
    !shared.stopping()
}

fn session(
    mut ws: WebSocket<Conn>,
    t: &Target,
    clock: &dyn WakeClock,
    shared: &Shared,
    rejoin: bool,
) -> End {
    let mut next_ref = 1u64;
    let join_ref = next_ref.to_string();
    let join = serde_json::json!({ "config": { "broadcast": { "self": false } } });
    if ws
        .send(phoenix(&t.topic, "phx_join", join, next_ref))
        .is_err()
    {
        return End::Dropped { joined: None };
    }
    next_ref += 1;
    let join_sent = clock.now();
    let mut joined_at: Option<Duration> = None;
    let mut last_beat = clock.now();
    let mut beat_pending: Option<String> = None;
    let dropped = |joined_at: Option<Duration>| End::Dropped {
        joined: joined_at.map(|at| clock.now().saturating_sub(at)),
    };
    loop {
        if shared.stopping() {
            let _ = ws.close(None);
            let _ = ws.flush();
            return End::Stopped;
        }
        if joined_at.is_none() && clock.now().saturating_sub(join_sent) >= JOIN_TIMEOUT {
            return dropped(None);
        }
        if clock.now().saturating_sub(last_beat) >= HEARTBEAT {
            if beat_pending.is_some() {
                // The last beat went unanswered: the line is dead.
                return dropped(joined_at);
            }
            let r = next_ref;
            next_ref += 1;
            if ws
                .send(phoenix("phoenix", "heartbeat", serde_json::json!({}), r))
                .is_err()
            {
                return dropped(joined_at);
            }
            beat_pending = Some(r.to_string());
            last_beat = clock.now();
        }
        let text = match ws.read() {
            Ok(Message::Text(text)) => text,
            Ok(Message::Close(_)) => return dropped(joined_at),
            Ok(_) => continue,
            Err(tungstenite::Error::Io(e))
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                continue;
            }
            Err(_) => return dropped(joined_at),
        };
        // Anything that is not a Phoenix message is skipped.
        let Ok(m) = serde_json::from_str::<Envelope>(text.as_str()) else {
            continue;
        };
        let inner = m.payload.as_ref();
        match m.event.as_str() {
            "phx_reply" if m.reference.as_deref() == Some(join_ref.as_str()) => {
                if inner.and_then(|p| p.status.as_deref()) != Some("ok") {
                    return dropped(joined_at);
                }
                if joined_at.is_none() {
                    joined_at = Some(clock.now());
                    if rejoin {
                        shared.wake();
                    }
                }
            }
            "phx_reply" if m.reference.is_some() && m.reference == beat_pending => {
                beat_pending = None;
            }
            "broadcast"
                if joined_at.is_some()
                    && m.topic == t.topic
                    && inner.and_then(|p| p.event.as_deref()) == Some("wake") =>
            {
                shared.wake();
            }
            "phx_error" | "phx_close" if m.topic == t.topic => return dropped(joined_at),
            _ => {}
        }
    }
}

#[cfg(all(test, feature = "testing"))]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::sync::Mutex;
    use std::sync::atomic::AtomicUsize;
    use std::sync::mpsc;

    const TOPIC: [u8; 16] = [0xab; 16];
    const SECS5: Duration = Duration::from_secs(5);

    /// Time that moves only when told to (or when the listener sleeps).
    struct TestClock(Mutex<Duration>);

    impl TestClock {
        fn advance(&self, d: Duration) {
            *self.0.lock().unwrap() += d;
        }
    }

    impl WakeClock for TestClock {
        fn now(&self) -> Duration {
            *self.0.lock().unwrap()
        }

        fn sleep(&self, d: Duration) {
            self.advance(d);
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    type ServerWs = WebSocket<TcpStream>;

    /// A local WebSocket server: each accepted connection goes to the test.
    fn server() -> (String, mpsc::Receiver<ServerWs>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("ws://{}/realtime/v1", listener.local_addr().unwrap());
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            for s in listener.incoming() {
                let Ok(s) = s else { return };
                s.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
                let Ok(ws) = tungstenite::accept(s) else {
                    continue;
                };
                if tx.send(ws).is_err() {
                    return;
                }
            }
        });
        (url, rx)
    }

    /// The next text message, within `within`.
    fn next_text<S: Read + Write>(
        ws: &mut WebSocket<S>,
        within: Duration,
    ) -> Option<serde_json::Value> {
        let until = Instant::now() + within;
        while Instant::now() < until {
            match ws.read() {
                Ok(Message::Text(t)) => return Some(serde_json::from_str(t.as_str()).unwrap()),
                Ok(_) => {}
                Err(tungstenite::Error::Io(e))
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) => {}
                Err(_) => return None,
            }
        }
        None
    }

    fn send<S: Read + Write>(ws: &mut WebSocket<S>, v: serde_json::Value) {
        ws.send(Message::text(v.to_string())).unwrap();
    }

    /// Reads the join, checks it, answers ok.
    fn accept_join<S: Read + Write>(ws: &mut WebSocket<S>) {
        let join = next_text(ws, SECS5).expect("a join");
        assert_eq!(join["event"], "phx_join");
        assert_eq!(join["topic"], format!("realtime:mbx:{}", hex(&TOPIC)));
        assert_eq!(
            join["payload"],
            serde_json::json!({ "config": { "broadcast": { "self": false } } })
        );
        send(
            ws,
            serde_json::json!({
                "topic": join["topic"],
                "event": "phx_reply",
                "payload": { "status": "ok", "response": {} },
                "ref": join["ref"],
            }),
        );
    }

    fn broadcast<S: Read + Write>(ws: &mut WebSocket<S>, event: &str) {
        send(
            ws,
            serde_json::json!({
                "topic": format!("realtime:mbx:{}", hex(&TOPIC)),
                "event": "broadcast",
                // What the real realtime.send sends: an id in the payload.
                "payload": { "type": "broadcast", "event": event, "payload": { "id": "4f1c" } },
                "ref": null,
            }),
        );
    }

    fn listener(url: &str, clock: Arc<TestClock>) -> (WakeListener, Arc<AtomicUsize>) {
        listener_to(
            target(url, "sb_publishable_k=y", TOPIC, None).unwrap(),
            clock,
        )
    }

    fn listener_to(t: Target, clock: Arc<TestClock>) -> (WakeListener, Arc<AtomicUsize>) {
        let count = Arc::new(AtomicUsize::new(0));
        let c = Arc::clone(&count);
        let l = spawn(
            t,
            clock,
            Box::new(move || {
                c.fetch_add(1, Ordering::SeqCst);
            }),
        )
        .unwrap();
        (l, count)
    }

    fn eventually(what: &str, f: impl Fn() -> bool) {
        let until = Instant::now() + Duration::from_secs(5);
        while Instant::now() < until {
            if f() {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("{what}");
    }

    fn clock() -> Arc<TestClock> {
        Arc::new(TestClock(Mutex::new(Duration::ZERO)))
    }

    #[test]
    fn wake_parses_only_event_name() {
        let (url, conns) = server();
        let clock = clock();
        let (l, count) = listener(&url, Arc::clone(&clock));
        let mut ws = conns.recv_timeout(Duration::from_secs(5)).unwrap();
        accept_join(&mut ws);

        broadcast(&mut ws, "wake");
        eventually("one wake", || count.load(Ordering::SeqCst) == 1);
        broadcast(&mut ws, "other");
        send(&mut ws, serde_json::json!({ "topic": "x", "event": 3 }));
        ws.send(Message::text("{not json")).unwrap();
        ws.send(Message::binary(vec![1, 2, 3])).unwrap();
        // A wake on another topic is not ours.
        send(
            &mut ws,
            serde_json::json!({
                "topic": "realtime:mbx:00",
                "event": "broadcast",
                "payload": { "event": "wake" },
                "ref": null,
            }),
        );
        broadcast(&mut ws, "wake");
        eventually("a second wake, still listening", || {
            count.load(Ordering::SeqCst) == 2
        });
        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(count.load(Ordering::SeqCst), 2);

        // The heartbeat goes out within 25 s, not before.
        clock.advance(Duration::from_secs(24));
        assert_eq!(next_text(&mut ws, Duration::from_millis(400)), None);
        clock.advance(Duration::from_secs(1));
        let beat = next_text(&mut ws, SECS5).expect("a heartbeat");
        assert_eq!(beat["event"], "heartbeat");
        assert_eq!(beat["topic"], "phoenix");
        assert!(beat["ref"].is_string());
        l.stop();
    }

    #[test]
    fn wake_reconnects() {
        let (url, conns) = server();
        let clock = clock();
        let (l, count) = listener(&url, Arc::clone(&clock));
        let mut first = conns.recv_timeout(Duration::from_secs(5)).unwrap();
        accept_join(&mut first);
        // The server goes away.
        first.close(None).unwrap();
        let _ = first.flush();
        drop(first);
        let mut second = conns.recv_timeout(Duration::from_secs(5)).unwrap();
        accept_join(&mut second);
        // A wake may have been lost meanwhile: one is raised.
        eventually("a wake after rejoining", || {
            count.load(Ordering::SeqCst) == 1
        });
        broadcast(&mut second, "wake");
        eventually("wakes on the new connection", || {
            count.load(Ordering::SeqCst) == 2
        });
        // A beat left unanswered: the listener drops and comes back.
        clock.advance(HEARTBEAT);
        assert_eq!(next_text(&mut second, SECS5).unwrap()["event"], "heartbeat");
        clock.advance(HEARTBEAT);
        let mut third = conns.recv_timeout(Duration::from_secs(5)).unwrap();
        accept_join(&mut third);
        l.stop();
    }

    #[test]
    fn wake_backs_off_while_refused() {
        // A server that drops every connection before the handshake: the
        // tries come after 1, 2, 5, 10, 30, then 30 s again.
        let server = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("ws://{}/realtime/v1", server.local_addr().unwrap());
        let clock = clock();
        let (l, _) = listener(&url, Arc::clone(&clock));
        let mut at = Vec::new();
        for s in server.incoming().take(7) {
            at.push(clock.now().as_secs());
            drop(s);
        }
        assert_eq!(at, [0, 1, 3, 8, 18, 48, 78]);
        l.stop();
    }

    #[test]
    fn wake_target_is_checked() {
        let t = target("wss://p.example/realtime/v1/", "a+b&c/=", TOPIC, None).unwrap();
        assert_eq!(
            t.url,
            "wss://p.example/realtime/v1/websocket?apikey=a%2Bb%26c%2F%3D&vsn=1.0.0"
        );
        assert_eq!((t.host.as_str(), t.port), ("p.example", 443));
        assert!(t.tls.is_some());
        assert_eq!(t.topic, format!("realtime:mbx:{}", hex(&TOPIC)));
        for bad in [
            "https://p.example/realtime/v1",
            "ws://p.example/realtime/v1",
            "wss://p.example/realtime/v1?x=1",
            "wss://u@p.example/realtime/v1",
            "wss://",
        ] {
            assert!(target(bad, "k", TOPIC, None).is_err(), "{bad}");
        }
        assert!(target("wss://p.example", "", TOPIC, None).is_err());
        assert!(target("wss://p.example", "k\u{e9}", TOPIC, None).is_err());
        let t = target("ws://127.0.0.1:5432/rt", "k", TOPIC, None).unwrap();
        assert_eq!(
            (t.host.as_str(), t.port, t.tls.is_none()),
            ("127.0.0.1", 5432, true)
        );
    }

    /// A server that answers every connection with one byte every 2 s
    /// (a handshake that never ends). Each accept is reported.
    fn dripping_server() -> (String, mpsc::Receiver<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("ws://{}/realtime/v1", listener.local_addr().unwrap());
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            for s in listener.incoming() {
                let Ok(mut s) = s else { return };
                if tx.send(()).is_err() {
                    return;
                }
                std::thread::spawn(move || {
                    for b in b"HTTP/1.1 101 Switching Protocols\r\n".iter().cycle() {
                        if s.write_all(&[*b]).is_err() {
                            return;
                        }
                        std::thread::sleep(Duration::from_secs(2));
                    }
                });
            }
        });
        (url, rx)
    }

    #[test]
    fn wake_stop_is_prompt_during_a_dripping_handshake() {
        let (url, accepts) = dripping_server();
        let (l, count) = listener(&url, clock());
        accepts.recv_timeout(SECS5).unwrap();
        std::thread::sleep(Duration::from_millis(300));
        let start = Instant::now();
        l.stop();
        let took = start.elapsed();
        assert!(took < Duration::from_millis(1500), "stop took {took:?}");
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(count.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn wake_handshake_has_one_deadline() {
        // Every byte comes in time for a per-read timeout; the whole
        // handshake does not: the listener gives up and tries again.
        let (url, accepts) = dripping_server();
        let mut t = target(&url, "k", TOPIC, None).unwrap();
        t.handshake = Duration::from_secs(1);
        let (l, _) = listener_to(t, clock());
        accepts.recv_timeout(SECS5).unwrap();
        let start = Instant::now();
        accepts.recv_timeout(SECS5).expect("a second try");
        assert!(
            start.elapsed() < Duration::from_secs(4),
            "{:?}",
            start.elapsed()
        );
        l.stop();
    }

    #[test]
    fn wake_never_runs_after_stop() {
        // A slow callback is in progress when stop is called: stop returns
        // only once it is over, and no call starts afterwards.
        let (url, conns) = server();
        let running = Arc::new(AtomicUsize::new(0));
        let calls = Arc::new(AtomicUsize::new(0));
        let (r, c) = (Arc::clone(&running), Arc::clone(&calls));
        let t = target(&url, "k", TOPIC, None).unwrap();
        let l = spawn(
            t,
            clock(),
            Box::new(move || {
                r.fetch_add(1, Ordering::SeqCst);
                c.fetch_add(1, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(1500));
                r.fetch_sub(1, Ordering::SeqCst);
            }),
        )
        .unwrap();
        let mut ws = conns.recv_timeout(SECS5).unwrap();
        accept_join(&mut ws);
        broadcast(&mut ws, "wake");
        broadcast(&mut ws, "wake");
        eventually("a call in progress", || running.load(Ordering::SeqCst) == 1);
        l.stop();
        assert_eq!(running.load(Ordering::SeqCst), 0, "a call outlived stop");
        let after = calls.load(Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(calls.load(Ordering::SeqCst), after, "a call after stop");
        assert_eq!(after, 1);
    }

    #[test]
    fn wake_panicking_callback_keeps_listening() {
        let (url, conns) = server();
        let count = Arc::new(AtomicUsize::new(0));
        let c = Arc::clone(&count);
        let t = target(&url, "k", TOPIC, None).unwrap();
        let l = spawn(
            t,
            clock(),
            Box::new(move || {
                if c.fetch_add(1, Ordering::SeqCst) == 0 {
                    panic!("first wake panics");
                }
            }),
        )
        .unwrap();
        let mut ws = conns.recv_timeout(SECS5).unwrap();
        accept_join(&mut ws);
        broadcast(&mut ws, "wake");
        broadcast(&mut ws, "wake");
        eventually("the second wake after a panic", || {
            count.load(Ordering::SeqCst) == 2
        });
        l.stop();
    }

    #[test]
    fn wake_join_without_reply_is_given_up() {
        let (url, conns) = server();
        let clock = clock();
        let (l, _) = listener(&url, Arc::clone(&clock));
        let mut first = conns.recv_timeout(SECS5).unwrap();
        assert_eq!(next_text(&mut first, SECS5).unwrap()["event"], "phx_join");
        assert!(conns.recv_timeout(Duration::from_millis(300)).is_err());
        clock.advance(JOIN_TIMEOUT);
        let mut second = conns.recv_timeout(SECS5).expect("a new try");
        accept_join(&mut second);
        l.stop();
    }

    #[test]
    fn wake_flapping_server_backs_off() {
        // Joins are accepted, then the connection drops at once: the waits
        // grow as for a refused connection, one catch-up wake per rejoin.
        let (url, conns) = server();
        let clock = clock();
        let (l, count) = listener(&url, Arc::clone(&clock));
        let mut at = Vec::new();
        for _ in 0..4 {
            let mut ws = conns.recv_timeout(SECS5).unwrap();
            at.push(clock.now().as_secs());
            accept_join(&mut ws);
            std::thread::sleep(Duration::from_millis(50));
            let _ = ws.close(None);
            let _ = ws.flush();
        }
        assert_eq!(at, [0, 1, 3, 8]);
        eventually("three catch-up wakes", || count.load(Ordering::SeqCst) == 3);
        l.stop();
    }

    // ------------------------------------------------------------- wss

    const CA_PEM: &str = include_str!("../tests/fixtures/ca.pem");
    const LEAF_PEM: &str = include_str!("../tests/fixtures/leaf.pem");
    const LEAF_KEY: &str = include_str!("../tests/fixtures/leaf.key");

    type TlsWs = WebSocket<StreamOwned<rustls::ServerConnection, TcpStream>>;

    /// A loopback `wss` server (leaf for localhost, test CA). Every
    /// WebSocket that got through TLS and the upgrade goes to the test.
    fn tls_server(tls12_only: bool) -> (String, mpsc::Receiver<TlsWs>) {
        use rustls::pki_types::pem::PemObject;
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};
        let chain: Vec<CertificateDer<'static>> =
            CertificateDer::pem_slice_iter(LEAF_PEM.as_bytes())
                .chain(CertificateDer::pem_slice_iter(CA_PEM.as_bytes()))
                .collect::<Result<_, _>>()
                .unwrap();
        let key = PrivateKeyDer::from_pem_slice(LEAF_KEY.as_bytes()).unwrap();
        let mut provider = rustls::crypto::aws_lc_rs::default_provider();
        let versions: &[&rustls::SupportedProtocolVersion] = if tls12_only {
            provider
                .cipher_suites
                .retain(|s| s.version().version == rustls::ProtocolVersion::TLSv1_2);
            &[&rustls::version::TLS12]
        } else {
            &[&rustls::version::TLS13]
        };
        let config = Arc::new(
            rustls::ServerConfig::builder_with_provider(Arc::new(provider))
                .with_protocol_versions(versions)
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(chain, key)
                .unwrap(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!(
            "wss://localhost:{}/realtime/v1",
            listener.local_addr().unwrap().port()
        );
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            for s in listener.incoming() {
                let Ok(s) = s else { return };
                s.set_read_timeout(Some(SECS5)).unwrap();
                let conn = rustls::ServerConnection::new(Arc::clone(&config)).unwrap();
                let Ok(ws) = tungstenite::accept(StreamOwned::new(conn, s)) else {
                    continue;
                };
                ws.get_ref()
                    .sock
                    .set_read_timeout(Some(Duration::from_millis(50)))
                    .unwrap();
                if tx.send(ws).is_err() {
                    return;
                }
            }
        });
        (url, rx)
    }

    #[test]
    fn wake_over_wss_with_the_self_host_ca() {
        let (url, conns) = tls_server(false);
        let t = target(&url, "k", TOPIC, Some(CA_PEM.into())).unwrap();
        let (l, count) = listener_to(t, clock());
        let mut ws = conns.recv_timeout(SECS5).unwrap();
        assert_eq!(
            ws.get_ref().conn.protocol_version(),
            Some(rustls::ProtocolVersion::TLSv1_3)
        );
        accept_join(&mut ws);
        broadcast(&mut ws, "wake");
        eventually("a wake over wss", || count.load(Ordering::SeqCst) == 1);
        l.stop();
    }

    #[test]
    fn wake_over_wss_refuses_untrusted_and_tls12() {
        for (tls12, ca) in [(false, None), (true, Some(CA_PEM.to_string()))] {
            let (url, conns) = tls_server(tls12);
            let t = target(&url, "k", TOPIC, ca).unwrap();
            let (l, _) = listener_to(t, clock());
            assert!(
                conns.recv_timeout(Duration::from_millis(1500)).is_err(),
                "tls12 {tls12}: no WebSocket may get through"
            );
            l.stop();
        }
    }
}
