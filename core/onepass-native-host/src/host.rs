//! The stdio loop of one browser connection.
//!
//! The first frame is `pair_hello` (pairing, spec 6.4) or `hello` (session,
//! spec 6.5). Frames are read on a helper thread so that every handshake
//! step waits at most `Limits::step` and an idle session closes after
//! `IDLE_TIMEOUT_SECS` even when nothing arrives. Any failure closes the
//! connection; the process then exits 0.
//!
//! The journal only gets fixed messages: never a secret, never a value
//! sent by the extension (names, ids, frame content).

use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, RecvTimeoutError, TryRecvError, sync_channel};
use std::thread;
use std::time::{Duration, Instant};

use onepass_bridge::framing::{read_frame, write_frame};
use onepass_bridge::pairing::{HostPairing, PAIRING_TIMEOUT_SECS};
use onepass_bridge::service::{Service, VaultAccess};
use onepass_bridge::session::host_accept;
use onepass_bridge::wire::{self, Envelope, Hello, PairHello};
use onepass_bridge::{AppErrorCode, BridgeError};
use serde_json::json;

use crate::config::{Approval, Config, HostError};
use crate::log::{FileAudit, Log};
use crate::pairings::{Pairings, write_atomic};

pub const PENDING_FILE: &str = "pending-pairing.json";
pub const APPROVED_FILE: &str = "pairing-approved";

/// Waiting bounds of the loop.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Longest wait for the next frame of a pairing or session handshake.
    pub step: Duration,
    /// How often an open session checks its idle deadline.
    pub poll: Duration,
    /// Polling period of the `file` approval mode.
    pub approval_poll: Duration,
    /// Whole pairing deadline: bounds the steps that wait for a person
    /// (the `file` approval, then `pair_confirm`).
    pub approval_max: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            step: Duration::from_secs(30),
            poll: Duration::from_secs(1),
            approval_poll: Duration::from_millis(200),
            approval_max: Duration::from_secs(PAIRING_TIMEOUT_SECS),
        }
    }
}

/// One read of the helper thread: a frame, a clean end of stream
/// (`Ok(None)`), or a transport or framing error.
pub type Frame = Result<Option<Vec<u8>>, BridgeError>;

/// Read frames from `r` on a helper thread. The channel holds at most one
/// frame ahead; the thread stops after an end of stream or an error.
pub fn spawn_reader<R: Read + Send + 'static>(mut r: R) -> Receiver<Frame> {
    let (tx, rx) = sync_channel(1);
    thread::spawn(move || {
        loop {
            let f = read_frame(&mut r);
            let more = matches!(f, Ok(Some(_)));
            if tx.send(f).is_err() || !more {
                return;
            }
        }
    });
    rx
}

/// The connection is over (the reason is already logged).
struct Close;

type Flow<T = ()> = Result<T, Close>;

/// A fixed description of a bridge error, for the journal.
fn describe(e: &BridgeError) -> &'static str {
    match e {
        BridgeError::Io(_) => "transport error",
        BridgeError::FrameTooLarge(_) => "frame too large",
        BridgeError::Truncated => "truncated frame",
        BridgeError::Version => "unsupported protocol version",
        BridgeError::BadFrame(_) => "bad frame",
        BridgeError::BadMac => "bad mac",
        BridgeError::UnknownPairing => "unknown pairing",
        BridgeError::Crypto => "cryptographic failure",
        BridgeError::Replay => "replayed or out of order message",
        BridgeError::Expired => "expired",
        BridgeError::App(_) => "application error",
    }
}

/// The error frame for a handshake failure, if one is sent.
fn wire_code(e: &BridgeError) -> Option<AppErrorCode> {
    match e {
        BridgeError::Version => Some(AppErrorCode::Version),
        BridgeError::UnknownPairing => Some(AppErrorCode::UnknownPairing),
        BridgeError::BadMac => Some(AppErrorCode::BadMac),
        BridgeError::BadFrame(_) | BridgeError::Crypto => Some(AppErrorCode::BadFrame),
        BridgeError::App(code) => Some(*code),
        // Deadlines and transport failures: just close.
        _ => None,
    }
}

/// Everything one connection needs.
pub struct Conn<'a, W: Write> {
    pub cfg: &'a Config,
    /// The caller's extension id, from the launch arguments.
    pub extension_id: Option<String>,
    pub log: &'a Log,
    pub clock: &'a (dyn Fn() -> u64 + Sync),
    pub limits: Limits,
    pub pairings: Pairings,
    pub rx: Receiver<Frame>,
    pub out: W,
}

impl<W: Write> Conn<'_, W> {
    fn send(&mut self, env: &Envelope) -> Flow {
        write_frame(&mut self.out, &wire::to_bytes(env)).map_err(|e| {
            self.log.line(&format!("write failed: {}", describe(&e)));
            Close
        })
    }

    /// Send an error frame, then close.
    fn fail<T>(&mut self, code: AppErrorCode) -> Flow<T> {
        self.log.line(&format!("closing with error {code}"));
        let _ = self.send(&Envelope::error(code));
        Err(Close)
    }

    /// Log a handshake failure, send its error frame if it has one, close.
    fn reject<T>(&mut self, what: &str, e: BridgeError) -> Flow<T> {
        self.log.line(&format!("{what}: {}", describe(&e)));
        match wire_code(&e) {
            Some(code) => self.fail(code),
            None => Err(Close),
        }
    }

    /// The next raw frame within `timeout`, or close.
    fn next_raw(&mut self, timeout: Duration) -> Flow<Vec<u8>> {
        match self.rx.recv_timeout(timeout) {
            Ok(Ok(Some(f))) => Ok(f),
            Ok(Ok(None)) | Err(RecvTimeoutError::Disconnected) => {
                self.log.line("connection closed by the browser");
                Err(Close)
            }
            Ok(Err(e)) => {
                self.log.line(&format!("read failed: {}", describe(&e)));
                Err(Close)
            }
            Err(RecvTimeoutError::Timeout) => {
                self.log.line("handshake step timed out");
                Err(Close)
            }
        }
    }

    fn parse(&mut self, f: &[u8]) -> Flow<Envelope> {
        match wire::parse(f) {
            Ok(env) => Ok(env),
            Err(e) => self.reject("invalid envelope", e),
        }
    }

    /// The next handshake envelope, waiting at most one step.
    fn next(&mut self) -> Flow<Envelope> {
        let f = self.next_raw(self.limits.step)?;
        self.parse(&f)
    }

    /// Serve the connection until it closes.
    pub fn serve<V: VaultAccess>(&mut self, vault: impl FnOnce() -> Result<V, HostError>) {
        let _ = self.serve_inner(vault);
    }

    fn serve_inner<V: VaultAccess>(
        &mut self,
        vault: impl FnOnce() -> Result<V, HostError>,
    ) -> Flow {
        let first = self.next_raw(self.limits.step)?;
        let allowed = match &self.extension_id {
            Some(id) => self.cfg.is_allowed(id),
            None => false,
        };
        if !allowed {
            self.log.line("caller extension is not allowed");
            return self.fail(AppErrorCode::NotAllowed);
        }
        let env = match self.parse(&first)? {
            Envelope::PairHello(h) => {
                self.pairing(h)?;
                // The extension may open a session on the same port; no
                // second pairing.
                self.next()?
            }
            other => other,
        };
        match env {
            Envelope::Hello(h) => self.session(h, vault),
            _ => {
                self.log.line("unexpected envelope");
                self.fail(AppErrorCode::BadFrame)
            }
        }
    }

    fn pairing(&mut self, hello: PairHello) -> Flow {
        let ext_name = hello.ext_name.clone();
        let browser = hello.browser.clone();
        let (mut hp, offer) = match HostPairing::start(hello, (self.clock)()) {
            Ok(x) => x,
            Err(e) => return self.reject("pairing refused", e),
        };
        let deadline = Instant::now() + self.limits.approval_max;
        self.log.line("pairing started");
        self.send(&Envelope::PairOffer(offer))?;

        let Envelope::PairReveal(reveal) = self.next()? else {
            self.log.line("expected pair_reveal");
            return self.fail(AppErrorCode::BadFrame);
        };
        let sas = match hp.on_reveal(reveal, (self.clock)()) {
            Ok(s) => s,
            Err(e) => return self.reject("pairing failed", e),
        };
        self.send(&Envelope::PairSas)?;
        // The code is derived by the host: not extension input.
        self.log.line(&format!("pairing code: {}", sas.0));
        if self.cfg.approval == Approval::File {
            self.wait_file_approval(&sas.0, &ext_name, &browser, deadline)?;
        }
        let done = match hp.approve((self.clock)()) {
            Ok(d) => d,
            Err(e) => return self.reject("pairing failed", e),
        };
        self.send(&Envelope::PairDone(done))?;

        // The user compares the codes before the extension confirms: a
        // human step, bounded by the pairing deadline, not by `step`.
        let f = self.next_raw(deadline.saturating_duration_since(Instant::now()))?;
        let Envelope::PairConfirm(confirm) = self.parse(&f)? else {
            self.log.line("expected pair_confirm");
            return self.fail(AppErrorCode::BadFrame);
        };
        let record = match hp.on_confirm(confirm, (self.clock)()) {
            Ok(r) => r,
            Err(e) => return self.reject("pairing failed", e),
        };
        let ext_id = self.extension_id.clone().unwrap_or_default();
        if let Err(e) = self.pairings.add(&record, &ext_id) {
            self.log.line(&format!("cannot store the pairing: {e}"));
            return self.fail(AppErrorCode::Internal);
        }
        self.log.line("pairing stored");
        self.send(&Envelope::PairOk)
    }

    fn data_file(&self, name: &str) -> PathBuf {
        self.cfg.data_dir.join(name)
    }

    fn clear_approval_files(&self) {
        let _ = std::fs::remove_file(self.data_file(PENDING_FILE));
        let _ = std::fs::remove_file(self.data_file(APPROVED_FILE));
    }

    /// `file` mode: publish the code in `pending-pairing.json`, then wait
    /// for `pairing-approved` to hold the same code.
    fn wait_file_approval(
        &mut self,
        sas: &str,
        ext_name: &str,
        browser: &str,
        deadline: Instant,
    ) -> Flow {
        // A stale approval must not approve this pairing.
        self.clear_approval_files();
        let pending = json!({"sas": sas, "ext_name": ext_name, "browser": browser});
        if let Err(e) = write_atomic(
            &self.data_file(PENDING_FILE),
            pending.to_string().as_bytes(),
        ) {
            self.log
                .line(&format!("cannot write {PENDING_FILE}: {}", e.kind()));
            return self.fail(AppErrorCode::Internal);
        }
        self.log.line("waiting for pairing approval");
        let result: Result<(), Option<AppErrorCode>> = loop {
            match self.rx.try_recv() {
                Err(TryRecvError::Empty) => {}
                Err(TryRecvError::Disconnected) | Ok(Ok(None)) | Ok(Err(_)) => {
                    self.log.line("connection closed during approval");
                    break Err(None);
                }
                Ok(Ok(Some(_))) => {
                    self.log.line("unexpected frame during approval");
                    break Err(Some(AppErrorCode::BadFrame));
                }
            }
            if let Ok(code) = std::fs::read_to_string(self.data_file(APPROVED_FILE)) {
                if same_code(&code, sas) {
                    self.log.line("pairing approved");
                    break Ok(());
                }
                self.log.line("pairing refused: wrong code");
                break Err(Some(AppErrorCode::NotAllowed));
            }
            if Instant::now() >= deadline {
                self.log.line("pairing approval timed out");
                break Err(None);
            }
            thread::sleep(self.limits.approval_poll);
        };
        self.clear_approval_files();
        match result {
            Ok(()) => Ok(()),
            Err(Some(code)) => self.fail(code),
            Err(None) => Err(Close),
        }
    }

    fn session<V: VaultAccess>(
        &mut self,
        hello: Hello,
        vault: impl FnOnce() -> Result<V, HostError>,
    ) -> Flow {
        let pairing_id = hello.pairing_id.0;
        let accepted = host_accept(hello, |id| self.pairings.key(id));
        let (pending, welcome) = match accepted {
            Ok(x) => x,
            Err(e) => return self.reject("session refused", e),
        };
        self.send(&Envelope::Welcome(welcome))?;
        let Envelope::Finish(finish) = self.next()? else {
            self.log.line("expected finish");
            return self.fail(AppErrorCode::BadFrame);
        };
        let now = (self.clock)();
        let mut ch = match pending.on_finish(finish, now) {
            Ok(c) => c,
            Err(e) => return self.reject("session refused", e),
        };
        if let Err(e) = self.pairings.touch(&pairing_id, now) {
            self.log
                .line(&format!("cannot record the pairing use: {e}"));
        }
        self.log.line("session open");
        let vault = match vault() {
            Ok(v) => v,
            Err(e) => {
                self.log.line(&format!("vault unavailable: {e}"));
                return Err(Close);
            }
        };
        let mut service = Service::new(vault, Box::new(FileAudit::new(&self.cfg.data_dir)));

        loop {
            let f = match self.rx.recv_timeout(self.limits.poll) {
                Err(RecvTimeoutError::Timeout) => {
                    if ch.expired((self.clock)()) {
                        self.log.line("session idle, closing");
                        return Err(Close);
                    }
                    continue;
                }
                Err(RecvTimeoutError::Disconnected) | Ok(Ok(None)) => {
                    self.log.line("session closed by the browser");
                    return Ok(());
                }
                Ok(Err(e)) => {
                    self.log.line(&format!("read failed: {}", describe(&e)));
                    return Err(Close);
                }
                Ok(Ok(Some(f))) => f,
            };
            let now = (self.clock)();
            if ch.expired(now) {
                self.log.line("session idle, closing");
                return Err(Close);
            }
            ch.touch(now);
            let msg = match wire::parse(&f) {
                Ok(Envelope::Msg(m)) => m,
                Err(BridgeError::Version) => {
                    self.log.line("unsupported protocol version");
                    return self.fail(AppErrorCode::Version);
                }
                _ => {
                    self.log.line("channel error: unexpected frame");
                    return Err(Close);
                }
            };
            let plain = match ch.open(&msg) {
                Ok(p) => p,
                Err(e) => {
                    self.log.line(&format!("channel error: {}", describe(&e)));
                    return Err(Close);
                }
            };
            let reply = service.handle(&plain, now);
            let env = match ch.seal(&reply) {
                Ok(env) => env,
                Err(e) => {
                    self.log.line(&format!("channel error: {}", describe(&e)));
                    return Err(Close);
                }
            };
            // Touch before the reply leaves: once the extension holds it, the
            // idle clock no longer moves under it.
            ch.touch((self.clock)());
            self.send(&env)?;
        }
    }
}

/// Two codes are the same once spaces are removed (`123 456`, `123456`).
fn same_code(a: &str, b: &str) -> bool {
    let digits = |s: &str| -> String { s.chars().filter(|c| !c.is_whitespace()).collect() };
    let (a, b) = (digits(a), digits(b));
    !a.is_empty() && a == b
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::mpsc::{Receiver as Rx, Sender, SyncSender, channel};

    use onepass_bridge::channel::{Channel, IDLE_TIMEOUT_SECS};
    use onepass_bridge::pairing::PairingRecord;
    use onepass_bridge::service::{VaultInfo, VaultStatus};
    use onepass_bridge::session;
    use onepass_core::Id;
    use onepass_core::model::Item;
    use zeroize::Zeroizing;

    use crate::config::{Reprompt, Source};

    const T0: u64 = 1_800_000_000;

    struct Stub;

    impl VaultAccess for Stub {
        fn status(&self) -> VaultStatus {
            VaultStatus {
                locked: false,
                account: "alex@atlas.dev".into(),
                vaults: 0,
            }
        }
        fn unlock(&mut self) -> onepass_bridge::Result<bool> {
            Ok(true)
        }
        fn vaults(&self) -> onepass_bridge::Result<Vec<VaultInfo>> {
            Ok(vec![])
        }
        fn items(&mut self) -> onepass_bridge::Result<Vec<(VaultInfo, Item)>> {
            Ok(vec![])
        }
        fn save(&mut self, _: Id, _: Item) -> onepass_bridge::Result<()> {
            Ok(())
        }
        fn approve_reprompt(&mut self, _: Id) -> bool {
            false
        }
    }

    /// Collects written bytes, sends each complete frame on flush.
    struct FrameOut {
        buf: Vec<u8>,
        tx: Sender<Vec<u8>>,
    }

    impl Write for FrameOut {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.buf.extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            let body = self.buf.split_off(4);
            self.buf.clear();
            let _ = self.tx.send(body);
            Ok(())
        }
    }

    struct Rig {
        clock: Arc<AtomicU64>,
        to_host: SyncSender<Frame>,
        from_host: Rx<Vec<u8>>,
        done: thread::JoinHandle<()>,
        record: PairingRecord,
        _dir: tempfile::TempDir,
    }

    fn rig(limits: Limits) -> Rig {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("data");
        let record = PairingRecord {
            pairing_id: [4; 16],
            key: Zeroizing::new([5; 32]),
            ext_name: "OnePass".into(),
            browser: "Chromium".into(),
            created_at: T0,
        };
        let mut pairings = Pairings::load(&data).unwrap();
        pairings.add(&record, "ext").unwrap();
        let cfg = Config {
            data_dir: data,
            allowed_extensions: vec!["ext".into()],
            source: Source::Dev { path: None },
            approval: Approval::Auto,
            unlocked: true,
            reprompt: Reprompt::Deny,
        };
        let clock = Arc::new(AtomicU64::new(T0));
        let (to_host, rx) = sync_channel(4);
        let (tx, from_host) = channel();
        let c = clock.clone();
        let done = thread::spawn(move || {
            let log = Log::stderr();
            let clock_fn = move || c.load(Ordering::SeqCst);
            let mut conn = Conn {
                cfg: &cfg,
                extension_id: Some("ext".into()),
                log: &log,
                clock: &clock_fn,
                limits,
                pairings,
                rx,
                out: FrameOut {
                    buf: Vec::new(),
                    tx,
                },
            };
            conn.serve(|| Ok(Stub));
        });
        Rig {
            clock,
            to_host,
            from_host,
            done,
            record,
            _dir: dir,
        }
    }

    fn fast() -> Limits {
        Limits {
            step: Duration::from_millis(200),
            poll: Duration::from_millis(10),
            approval_poll: Duration::from_millis(10),
            approval_max: Duration::from_millis(200),
        }
    }

    impl Rig {
        fn send(&self, env: &Envelope) {
            self.to_host.send(Ok(Some(wire::to_bytes(env)))).unwrap();
        }

        fn recv(&self) -> Envelope {
            let f = self.from_host.recv_timeout(Duration::from_secs(5)).unwrap();
            wire::parse(&f).unwrap()
        }

        fn open(&self) -> Channel {
            let (pending, hello) = session::ext_hello(&self.record).unwrap();
            self.send(&Envelope::Hello(hello));
            let Envelope::Welcome(w) = self.recv() else {
                panic!("welcome")
            };
            let (ch, finish) = pending.on_welcome(w, T0).unwrap();
            self.send(&Envelope::Finish(finish));
            ch
        }

        fn status(&self, ch: &mut Channel, id: u64) -> Envelope {
            let req = format!(r#"{{"id":{id},"op":"status"}}"#);
            self.send(&ch.seal(req.as_bytes()).unwrap());
            self.recv()
        }

        /// The host thread ends within a second and sent nothing more.
        fn assert_closed(self) {
            let deadline = Instant::now() + Duration::from_secs(2);
            while !self.done.is_finished() {
                assert!(Instant::now() < deadline, "host still running");
                thread::sleep(Duration::from_millis(5));
            }
            assert!(self.from_host.try_recv().is_err(), "unexpected frame");
        }
    }

    #[test]
    fn session_serves_while_frames_keep_it_alive() {
        let rig = rig(fast());
        let mut ch = rig.open();
        // Each frame comes before the idle deadline: touch keeps it open
        // well past IDLE_TIMEOUT_SECS in total.
        for i in 0..4u64 {
            rig.clock
                .fetch_add(IDLE_TIMEOUT_SECS - 100, Ordering::SeqCst);
            let Envelope::Msg(m) = rig.status(&mut ch, i) else {
                panic!("msg")
            };
            let reply: serde_json::Value = serde_json::from_slice(&ch.open(&m).unwrap()).unwrap();
            assert_eq!(reply["ok"]["locked"], false);
        }
        drop(rig.to_host);
        rig.done.join().unwrap();
    }

    #[test]
    fn idle_session_closes_without_a_frame() {
        let rig = rig(fast());
        let mut ch = rig.open();
        assert!(matches!(rig.status(&mut ch, 1), Envelope::Msg(_)));
        rig.clock.fetch_add(IDLE_TIMEOUT_SECS + 1, Ordering::SeqCst);
        rig.assert_closed();
    }

    #[test]
    fn frame_after_idle_deadline_is_not_served() {
        // A long poll: the frame arrives before the idle check runs.
        let rig = rig(Limits {
            poll: Duration::from_secs(30),
            ..fast()
        });
        let mut ch = rig.open();
        // One round trip: the session is open before the clock moves.
        assert!(matches!(rig.status(&mut ch, 1), Envelope::Msg(_)));
        rig.clock.fetch_add(IDLE_TIMEOUT_SECS + 1, Ordering::SeqCst);
        let late = ch.seal(br#"{"id":2,"op":"status"}"#).unwrap();
        rig.send(&late);
        rig.assert_closed();
    }

    #[test]
    fn missing_finish_times_out() {
        let rig = rig(fast());
        let (_pending, hello) = session::ext_hello(&rig.record).unwrap();
        rig.send(&Envelope::Hello(hello));
        assert!(matches!(rig.recv(), Envelope::Welcome(_)));
        // No finish: the host gives up after one step.
        rig.assert_closed();
    }

    #[test]
    fn missing_first_frame_times_out() {
        let rig = rig(fast());
        rig.assert_closed();
    }

    #[test]
    fn missing_pair_reveal_times_out() {
        let rig = rig(fast());
        let (_ext, hello) =
            onepass_bridge::pairing::ExtPairing::start("OnePass", "Chromium", T0).unwrap();
        rig.send(&Envelope::PairHello(hello));
        assert!(matches!(rig.recv(), Envelope::PairOffer(_)));
        rig.assert_closed();
    }

    /// Pair up to `pair_done`, wait `pause`, then confirm.
    fn pair_slow_confirm(rig: &Rig, pause: Duration) -> Envelope {
        let (mut ext, hello) =
            onepass_bridge::pairing::ExtPairing::start("OnePass", "Chromium", T0).unwrap();
        rig.send(&Envelope::PairHello(hello));
        let Envelope::PairOffer(offer) = rig.recv() else {
            panic!("pair_offer")
        };
        let (reveal, _sas) = ext.on_offer(offer).unwrap();
        rig.send(&Envelope::PairReveal(reveal));
        assert_eq!(rig.recv(), Envelope::PairSas);
        let Envelope::PairDone(done) = rig.recv() else {
            panic!("pair_done")
        };
        ext.on_done(done, T0).unwrap();
        thread::sleep(pause);
        let (confirm, _) = ext.confirm(T0).unwrap();
        rig.send(&Envelope::PairConfirm(confirm));
        rig.recv()
    }

    #[test]
    fn pair_confirm_waits_for_the_pairing_deadline_not_one_step() {
        // step 200 ms, pairing deadline 3 s: a 600 ms human pause passes.
        let rig = rig(Limits {
            approval_max: Duration::from_secs(3),
            ..fast()
        });
        assert_eq!(
            pair_slow_confirm(&rig, Duration::from_millis(600)),
            Envelope::PairOk
        );
        drop(rig.to_host);
        rig.done.join().unwrap();
    }

    #[test]
    fn pair_confirm_after_the_pairing_deadline_closes() {
        let rig = rig(Limits {
            approval_max: Duration::from_millis(300),
            ..fast()
        });
        let (mut ext, hello) =
            onepass_bridge::pairing::ExtPairing::start("OnePass", "Chromium", T0).unwrap();
        rig.send(&Envelope::PairHello(hello));
        let Envelope::PairOffer(offer) = rig.recv() else {
            panic!("pair_offer")
        };
        let (reveal, _) = ext.on_offer(offer).unwrap();
        rig.send(&Envelope::PairReveal(reveal));
        assert_eq!(rig.recv(), Envelope::PairSas);
        assert!(matches!(rig.recv(), Envelope::PairDone(_)));
        // No pair_confirm: closed once the pairing deadline passes.
        rig.assert_closed();
    }

    #[test]
    fn second_pairing_on_the_same_port_is_refused() {
        let rig = rig(fast());
        assert_eq!(pair_slow_confirm(&rig, Duration::ZERO), Envelope::PairOk);
        let (_ext, hello) =
            onepass_bridge::pairing::ExtPairing::start("OnePass", "Chromium", T0).unwrap();
        rig.send(&Envelope::PairHello(hello));
        let Envelope::Error(e) = rig.recv() else {
            panic!("error")
        };
        assert_eq!(e.code, "bad_frame");
        rig.assert_closed();
    }

    #[test]
    fn hello_after_pairing_on_the_same_port_opens_a_session() {
        let rig = rig(fast());
        assert_eq!(pair_slow_confirm(&rig, Duration::ZERO), Envelope::PairOk);
        let mut ch = rig.open();
        assert!(matches!(rig.status(&mut ch, 1), Envelope::Msg(_)));
        drop(rig.to_host);
        rig.done.join().unwrap();
    }

    #[test]
    fn codes_compare_without_spaces() {
        assert!(same_code("123 456\n", "123 456"));
        assert!(same_code("123456", "123 456"));
        assert!(!same_code("123 457", "123 456"));
        assert!(!same_code("", ""));
    }
}
