//! The host side of one extension connection, whatever carries the frames:
//! the stdio of the development native host, or the socket of the Mac app
//! (production bridge, `docs/specs/2026-10-27-release-bridge-design.md`).
//!
//! The first frame is `pair_hello` (pairing, spec 6.4) or `hello` (session,
//! spec 6.5). Frames are read on a helper thread so that every handshake
//! step waits at most `Limits::step` and an idle session closes after
//! `IDLE_TIMEOUT_SECS` even when nothing arrives. Any failure closes the
//! connection.
//!
//! The journal only gets fixed messages: never a secret, never a value
//! sent by the extension (names, ids, frame content).

use std::io::{Read, Write};
use std::sync::mpsc::{Receiver, RecvTimeoutError, TryRecvError, sync_channel};
use std::thread;
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use crate::audit::AuditSink;
use crate::framing::{read_frame, write_frame};
use crate::pairing::{HostPairing, PAIRING_TIMEOUT_SECS, PairingRecord};
use crate::service::{Service, VaultAccess};
use crate::session::host_accept;
use crate::wire::{self, Envelope, Hello, PairHello};
use crate::{AppErrorCode, BridgeError};

/// Where the host keeps its pairings.
pub trait PairingStore {
    /// The pairing key of `id`, if paired.
    fn key(&self, id: &[u8; 16]) -> Option<Zeroizing<[u8; 32]>>;
    /// Store a completed pairing (replacing one with the same id). The
    /// error is a fixed description, for the journal.
    fn add(&mut self, record: &PairingRecord, extension_id: &str) -> Result<(), String>;
    /// Record a session opened with `id` at `now`.
    fn touch(&mut self, id: &[u8; 16], now: u64) -> Result<(), String>;
}

/// Answer of the person asked to approve a pairing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Approval {
    Pending,
    Approved,
    Refused,
}

/// How a pairing gets approved: the host shows the code with `begin`,
/// then polls until an answer or the pairing deadline; `end` always
/// follows a successful `begin`.
pub trait Approver {
    /// Show the code (derived by the host, never extension input) and the
    /// extension's self-declared name and browser. Error: a fixed
    /// description for the journal; the pairing fails with `internal`.
    fn begin(&mut self, sas: &str, ext_name: &str, browser: &str) -> Result<(), String>;
    fn poll(&mut self) -> Approval;
    /// The pairing is over (answered, timed out or closed).
    fn end(&mut self);
}

/// Approves at once. Development and tests only: approving without a code
/// comparison lets any local process pair.
pub struct AutoApprove;

impl Approver for AutoApprove {
    fn begin(&mut self, _: &str, _: &str, _: &str) -> Result<(), String> {
        Ok(())
    }
    fn poll(&mut self) -> Approval {
        Approval::Approved
    }
    fn end(&mut self) {}
}

/// The host journal: fixed messages only.
pub trait Journal {
    fn line(&self, msg: &str);
}

/// Waiting bounds of the loop.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Longest wait for the next frame of a pairing or session handshake.
    pub step: Duration,
    /// How often an open session checks its idle deadline.
    pub poll: Duration,
    /// Polling period of the approval.
    pub approval_poll: Duration,
    /// Whole pairing deadline: bounds the steps that wait for a person
    /// (the approval, then `pair_confirm`).
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
pub fn describe(e: &BridgeError) -> &'static str {
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
    /// Whether the caller may use the bridge at all (its extension id, or
    /// its code signature). A refused caller gets `not_allowed` after its
    /// first frame and never reaches the vault.
    pub allowed: bool,
    /// Stored with a new pairing.
    pub extension_id: String,
    pub journal: &'a dyn Journal,
    pub clock: &'a (dyn Fn() -> u64 + Sync),
    pub limits: Limits,
    pub pairings: &'a mut dyn PairingStore,
    pub approver: &'a mut dyn Approver,
    /// Journal of the session's disclosures, moved into its service.
    pub audit: Option<Box<dyn AuditSink>>,
    pub rx: Receiver<Frame>,
    pub out: W,
}

impl<W: Write> Conn<'_, W> {
    fn send(&mut self, env: &Envelope) -> Flow {
        write_frame(&mut self.out, &wire::to_bytes(env)).map_err(|e| {
            self.journal
                .line(&format!("write failed: {}", describe(&e)));
            Close
        })
    }

    /// Send an error frame, then close.
    fn fail<T>(&mut self, code: AppErrorCode) -> Flow<T> {
        self.journal.line(&format!("closing with error {code}"));
        let _ = self.send(&Envelope::error(code));
        Err(Close)
    }

    /// Log a handshake failure, send its error frame if it has one, close.
    fn reject<T>(&mut self, what: &str, e: BridgeError) -> Flow<T> {
        self.journal.line(&format!("{what}: {}", describe(&e)));
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
                self.journal.line("connection closed by the browser");
                Err(Close)
            }
            Ok(Err(e)) => {
                self.journal.line(&format!("read failed: {}", describe(&e)));
                Err(Close)
            }
            Err(RecvTimeoutError::Timeout) => {
                self.journal.line("handshake step timed out");
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

    /// Serve the connection until it closes. `vault` runs once, after a
    /// session is open (a refused caller or a failed handshake never
    /// loads the vault).
    pub fn serve<V: VaultAccess>(&mut self, vault: impl FnOnce() -> Result<V, String>) {
        let _ = self.serve_inner(vault);
    }

    fn serve_inner<V: VaultAccess>(&mut self, vault: impl FnOnce() -> Result<V, String>) -> Flow {
        let first = self.next_raw(self.limits.step)?;
        if !self.allowed {
            self.journal.line("caller is not allowed");
            return self.fail(AppErrorCode::NotAllowed);
        }
        let env = match self.parse(&first)? {
            Envelope::PairHello(h) => {
                self.pairing(h)?;
                // The extension may open a session on the same connection;
                // no second pairing.
                self.next()?
            }
            other => other,
        };
        match env {
            Envelope::Hello(h) => self.session(h, vault),
            _ => {
                self.journal.line("unexpected envelope");
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
        self.journal.line("pairing started");
        self.send(&Envelope::PairOffer(offer))?;

        let Envelope::PairReveal(reveal) = self.next()? else {
            self.journal.line("expected pair_reveal");
            return self.fail(AppErrorCode::BadFrame);
        };
        let sas = match hp.on_reveal(reveal, (self.clock)()) {
            Ok(s) => s,
            Err(e) => return self.reject("pairing failed", e),
        };
        self.send(&Envelope::PairSas)?;
        self.wait_approval(&sas.0, &ext_name, &browser, deadline)?;
        let done = match hp.approve((self.clock)()) {
            Ok(d) => d,
            Err(e) => return self.reject("pairing failed", e),
        };
        self.send(&Envelope::PairDone(done))?;

        // The user compares the codes before the extension confirms: a
        // human step, bounded by the pairing deadline, not by `step`.
        let f = self.next_raw(deadline.saturating_duration_since(Instant::now()))?;
        let Envelope::PairConfirm(confirm) = self.parse(&f)? else {
            self.journal.line("expected pair_confirm");
            return self.fail(AppErrorCode::BadFrame);
        };
        let record = match hp.on_confirm(confirm, (self.clock)()) {
            Ok(r) => r,
            Err(e) => return self.reject("pairing failed", e),
        };
        let ext_id = self.extension_id.clone();
        if let Err(e) = self.pairings.add(&record, &ext_id) {
            self.journal.line(&format!("cannot store the pairing: {e}"));
            return self.fail(AppErrorCode::Internal);
        }
        self.journal.line("pairing stored");
        self.send(&Envelope::PairOk)
    }

    /// Ask the approver, then poll it until an answer, the pairing
    /// deadline, or the end of the connection. A frame from the extension
    /// meanwhile is a protocol error.
    fn wait_approval(
        &mut self,
        sas: &str,
        ext_name: &str,
        browser: &str,
        deadline: Instant,
    ) -> Flow {
        if let Err(e) = self.approver.begin(sas, ext_name, browser) {
            self.journal
                .line(&format!("cannot ask for the pairing approval: {e}"));
            return self.fail(AppErrorCode::Internal);
        }
        self.journal.line("waiting for pairing approval");
        let result: Result<(), Option<AppErrorCode>> = loop {
            match self.approver.poll() {
                Approval::Approved => {
                    self.journal.line("pairing approved");
                    break Ok(());
                }
                Approval::Refused => {
                    self.journal.line("pairing refused");
                    break Err(Some(AppErrorCode::NotAllowed));
                }
                Approval::Pending => {}
            }
            match self.rx.try_recv() {
                Err(TryRecvError::Empty) => {}
                Err(TryRecvError::Disconnected) | Ok(Ok(None)) | Ok(Err(_)) => {
                    self.journal.line("connection closed during approval");
                    break Err(None);
                }
                Ok(Ok(Some(_))) => {
                    self.journal.line("unexpected frame during approval");
                    break Err(Some(AppErrorCode::BadFrame));
                }
            }
            if Instant::now() >= deadline {
                self.journal.line("pairing approval timed out");
                break Err(None);
            }
            thread::sleep(self.limits.approval_poll);
        };
        self.approver.end();
        match result {
            Ok(()) => Ok(()),
            Err(Some(code)) => self.fail(code),
            Err(None) => Err(Close),
        }
    }

    fn session<V: VaultAccess>(
        &mut self,
        hello: Hello,
        vault: impl FnOnce() -> Result<V, String>,
    ) -> Flow {
        let pairing_id = hello.pairing_id.0;
        let accepted = {
            let pairings = &*self.pairings;
            host_accept(hello, |id| pairings.key(id))
        };
        let (pending, welcome) = match accepted {
            Ok(x) => x,
            Err(e) => return self.reject("session refused", e),
        };
        self.send(&Envelope::Welcome(welcome))?;
        let Envelope::Finish(finish) = self.next()? else {
            self.journal.line("expected finish");
            return self.fail(AppErrorCode::BadFrame);
        };
        let now = (self.clock)();
        let mut ch = match pending.on_finish(finish, now) {
            Ok(c) => c,
            Err(e) => return self.reject("session refused", e),
        };
        if let Err(e) = self.pairings.touch(&pairing_id, now) {
            self.journal
                .line(&format!("cannot record the pairing use: {e}"));
        }
        self.journal.line("session open");
        let vault = match vault() {
            Ok(v) => v,
            Err(e) => {
                self.journal.line(&format!("vault unavailable: {e}"));
                return Err(Close);
            }
        };
        let Some(audit) = self.audit.take() else {
            self.journal.line("no audit journal");
            return Err(Close);
        };
        let mut service = Service::new(vault, audit);

        loop {
            let f = match self.rx.recv_timeout(self.limits.poll) {
                Err(RecvTimeoutError::Timeout) => {
                    if ch.expired((self.clock)()) {
                        self.journal.line("session idle, closing");
                        return Err(Close);
                    }
                    continue;
                }
                Err(RecvTimeoutError::Disconnected) | Ok(Ok(None)) => {
                    self.journal.line("session closed by the browser");
                    return Ok(());
                }
                Ok(Err(e)) => {
                    self.journal.line(&format!("read failed: {}", describe(&e)));
                    return Err(Close);
                }
                Ok(Ok(Some(f))) => f,
            };
            let now = (self.clock)();
            if ch.expired(now) {
                self.journal.line("session idle, closing");
                return Err(Close);
            }
            ch.touch(now);
            let msg = match wire::parse(&f) {
                Ok(Envelope::Msg(m)) => m,
                Err(BridgeError::Version) => {
                    self.journal.line("unsupported protocol version");
                    return self.fail(AppErrorCode::Version);
                }
                _ => {
                    self.journal.line("channel error: unexpected frame");
                    return Err(Close);
                }
            };
            let plain = match ch.open(&msg) {
                Ok(p) => p,
                Err(e) => {
                    self.journal
                        .line(&format!("channel error: {}", describe(&e)));
                    return Err(Close);
                }
            };
            let reply = service.handle(&plain, now);
            let env = match ch.seal(&reply) {
                Ok(env) => env,
                Err(e) => {
                    self.journal
                        .line(&format!("channel error: {}", describe(&e)));
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

/// In-memory pairings (tests, and a host that persists them elsewhere).
#[derive(Default)]
pub struct MemoryPairings {
    pub records: Vec<(PairingRecord, String, u64)>,
}

impl PairingStore for MemoryPairings {
    fn key(&self, id: &[u8; 16]) -> Option<Zeroizing<[u8; 32]>> {
        self.records
            .iter()
            .find(|(r, _, _)| &r.pairing_id == id)
            .map(|(r, _, _)| r.key.clone())
    }
    fn add(&mut self, record: &PairingRecord, extension_id: &str) -> Result<(), String> {
        self.records
            .retain(|(r, _, _)| r.pairing_id != record.pairing_id);
        let copy = PairingRecord {
            pairing_id: record.pairing_id,
            key: record.key.clone(),
            ext_name: record.ext_name.clone(),
            browser: record.browser.clone(),
            created_at: record.created_at,
        };
        self.records
            .push((copy, extension_id.to_owned(), record.created_at));
        Ok(())
    }
    fn touch(&mut self, id: &[u8; 16], now: u64) -> Result<(), String> {
        if let Some(e) = self
            .records
            .iter_mut()
            .find(|(r, _, _)| &r.pairing_id == id)
        {
            e.2 = now;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::mpsc::{Receiver as Rx, Sender, SyncSender, channel};

    use std::sync::Mutex;

    use crate::audit::MemoryAudit;
    use crate::channel::{Channel, IDLE_TIMEOUT_SECS};
    use crate::pairing::{ExtPairing, PairingRecord};
    use crate::service::{VaultInfo, VaultStatus};
    use crate::session;
    use onepass_core::Id;
    use onepass_core::model::Item;

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
        fn unlock(&mut self) -> crate::Result<bool> {
            Ok(true)
        }
        fn vaults(&self) -> crate::Result<Vec<VaultInfo>> {
            Ok(vec![])
        }
        fn items(&mut self) -> crate::Result<Vec<(VaultInfo, Item)>> {
            Ok(vec![])
        }
        fn save(&mut self, _: Id, _: Item) -> crate::Result<()> {
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
    }

    struct Quiet;

    impl Journal for Quiet {
        fn line(&self, _: &str) {}
    }

    /// Answers `answer` after `after` polls; records what it was shown.
    struct Scripted {
        answer: Approval,
        after: usize,
        polls: usize,
        shown: Arc<Mutex<Vec<String>>>,
        ended: Arc<Mutex<bool>>,
        fail_begin: bool,
    }

    impl Approver for Scripted {
        fn begin(&mut self, sas: &str, ext_name: &str, browser: &str) -> Result<(), String> {
            if self.fail_begin {
                return Err("no window".into());
            }
            self.shown
                .lock()
                .unwrap()
                .push(format!("{sas}|{ext_name}|{browser}"));
            Ok(())
        }
        fn poll(&mut self) -> Approval {
            self.polls += 1;
            if self.polls > self.after {
                self.answer
            } else {
                Approval::Pending
            }
        }
        fn end(&mut self) {
            *self.ended.lock().unwrap() = true;
        }
    }

    fn rig(limits: Limits) -> Rig {
        rig_with(limits, true, None)
    }

    fn rig_with(limits: Limits, allowed: bool, approver: Option<Scripted>) -> Rig {
        let record = PairingRecord {
            pairing_id: [4; 16],
            key: Zeroizing::new([5; 32]),
            ext_name: "OnePass".into(),
            browser: "Chromium".into(),
            created_at: T0,
        };
        let mut pairings = MemoryPairings::default();
        pairings.add(&record, "ext").unwrap();
        let clock = Arc::new(AtomicU64::new(T0));
        let (to_host, rx) = sync_channel(4);
        let (tx, from_host) = channel();
        let c = clock.clone();
        let done = thread::spawn(move || {
            let clock_fn = move || c.load(Ordering::SeqCst);
            let mut auto = AutoApprove;
            let mut scripted = approver;
            let approver: &mut dyn Approver = match scripted.as_mut() {
                Some(s) => s,
                None => &mut auto,
            };
            let mut conn = Conn {
                allowed,
                extension_id: "ext".into(),
                journal: &Quiet,
                clock: &clock_fn,
                limits,
                pairings: &mut pairings,
                approver,
                audit: Some(Box::new(MemoryAudit::new())),
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
        let (_ext, hello) = ExtPairing::start("OnePass", "Chromium", T0).unwrap();
        rig.send(&Envelope::PairHello(hello));
        assert!(matches!(rig.recv(), Envelope::PairOffer(_)));
        rig.assert_closed();
    }

    /// Pair up to `pair_done`, wait `pause`, then confirm.
    fn pair_slow_confirm(rig: &Rig, pause: Duration) -> Envelope {
        let (mut ext, hello) = ExtPairing::start("OnePass", "Chromium", T0).unwrap();
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
        let (mut ext, hello) = ExtPairing::start("OnePass", "Chromium", T0).unwrap();
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
        let (_ext, hello) = ExtPairing::start("OnePass", "Chromium", T0).unwrap();
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

    type Shown = Arc<Mutex<Vec<String>>>;

    fn scripted(answer: Approval, after: usize) -> (Scripted, Shown, Arc<Mutex<bool>>) {
        let shown = Arc::new(Mutex::new(Vec::new()));
        let ended = Arc::new(Mutex::new(false));
        let s = Scripted {
            answer,
            after,
            polls: 0,
            shown: shown.clone(),
            ended: ended.clone(),
            fail_begin: false,
        };
        (s, shown, ended)
    }

    /// Send `pair_hello` and `pair_reveal`; the extension's code.
    fn start_pairing(rig: &Rig) -> (ExtPairing, String) {
        let (mut ext, hello) = ExtPairing::start("OnePass", "Chromium", T0).unwrap();
        rig.send(&Envelope::PairHello(hello));
        let Envelope::PairOffer(offer) = rig.recv() else {
            panic!("pair_offer")
        };
        let (reveal, sas) = ext.on_offer(offer).unwrap();
        rig.send(&Envelope::PairReveal(reveal));
        assert_eq!(rig.recv(), Envelope::PairSas);
        (ext, sas.0)
    }

    #[test]
    fn approver_sees_the_code_and_approves_after_waiting() {
        let (s, shown, ended) = scripted(Approval::Approved, 3);
        let rig = rig_with(fast(), true, Some(s));
        let (mut ext, sas) = start_pairing(&rig);
        let Envelope::PairDone(done) = rig.recv() else {
            panic!("pair_done")
        };
        ext.on_done(done, T0).unwrap();
        let (confirm, _) = ext.confirm(T0).unwrap();
        rig.send(&Envelope::PairConfirm(confirm));
        assert_eq!(rig.recv(), Envelope::PairOk);
        assert_eq!(
            *shown.lock().unwrap(),
            vec![format!("{sas}|OnePass|Chromium")]
        );
        assert!(*ended.lock().unwrap());
        drop(rig.to_host);
        rig.done.join().unwrap();
    }

    #[test]
    fn refused_pairing_sends_not_allowed() {
        let (s, _, ended) = scripted(Approval::Refused, 1);
        let rig = rig_with(fast(), true, Some(s));
        let _ = start_pairing(&rig);
        let Envelope::Error(e) = rig.recv() else {
            panic!("error")
        };
        assert_eq!(e.code, "not_allowed");
        assert!(*ended.lock().unwrap());
        rig.assert_closed();
    }

    #[test]
    fn unanswered_approval_closes_at_the_pairing_deadline() {
        let (s, _, ended) = scripted(Approval::Approved, usize::MAX);
        let rig = rig_with(fast(), true, Some(s));
        let _ = start_pairing(&rig);
        rig.assert_closed();
        assert!(*ended.lock().unwrap());
    }

    #[test]
    fn approver_that_cannot_ask_fails_the_pairing() {
        let (mut s, _, ended) = scripted(Approval::Approved, 0);
        s.fail_begin = true;
        let rig = rig_with(fast(), true, Some(s));
        let _ = start_pairing(&rig);
        let Envelope::Error(e) = rig.recv() else {
            panic!("error")
        };
        assert_eq!(e.code, "internal");
        assert!(!*ended.lock().unwrap());
        rig.assert_closed();
    }

    #[test]
    fn caller_not_allowed_gets_not_allowed_and_no_session() {
        let rig = rig_with(fast(), false, None);
        let (_pending, hello) = session::ext_hello(&rig.record).unwrap();
        rig.send(&Envelope::Hello(hello));
        let Envelope::Error(e) = rig.recv() else {
            panic!("error")
        };
        assert_eq!(e.code, "not_allowed");
        rig.assert_closed();
    }
}
