//! Pairing transports in Rust (cross-platform spec 5.3): T-LAN (TCP on the
//! local network, announced in DNS-SD) and T-RDV (the rendezvous through
//! the mailbox), for the CLI, the desktop app and the cross tests.
//!
//! Both carry the opaque, sealed frames of the pairing channel (2b 5.2,
//! 5.5) and nothing else. Neither is trusted: nothing here authenticates a
//! peer or reads a frame. The key committed by the QR code and the short
//! code over the whole transcript are what bind the two devices; a
//! transport only keeps the framing, the caps (checked before any body is
//! read or allocated) and bounded timeouts.
//!
//! Try order (5.3): the approver tries T-LAN for `LAN_TRY`, then T-RDV
//! when a server is known. The newcomer offers both at once and keeps the
//! one on which the approver's first frame arrives; the other is closed.
//!
//! Everything blocks: the app calls this from a thread of its own.
#![deny(unsafe_code)]

mod frame;
mod lan;
mod rdv;

use std::fmt;
use std::net::{IpAddr, Shutdown, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use onepass_mailbox::{Endpoint, MailboxError, RdvRole, Rendezvous};

pub use lan::{
    LAN_CONNECT_TIMEOUT, LAN_IO_TIMEOUT, LanTransport, browse_and_connect, lan_address,
    publish_and_accept, publish_and_accept_on,
};
pub use rdv::{RDV_RECV_TIMEOUT, RdvTransport};

/// DNS-SD service type of T-LAN (`LocalNetworkPairingTransport.serviceType`
/// on the Swift side, in the `local.` domain).
pub const SERVICE_TYPE: &str = "_onepass-pair._tcp.local.";
/// Largest frame on any transport (`PairingFrame.maxBytes`, 64 MiB).
pub const MAX_FRAME: usize = 64 << 20;
/// Largest frame before the key exchange is validated
/// (`PairingFrame.maxHandshakeBytes`, 16 KiB).
pub const MAX_HANDSHAKE_FRAME: usize = 16 << 10;
/// How long the approver tries T-LAN before T-RDV (spec 5.3).
pub const LAN_TRY: Duration = Duration::from_secs(5);
/// How long one T-RDV read of the newcomer's race waits before it looks
/// whether T-LAN won: one long poll of the server (25 s) and a margin, so
/// the wait costs one request of the per-address budget, not one a second.
pub const RDV_SLICE: Duration = Duration::from_secs(26);
/// How long the newcomer waits for the losing worker to finish before it
/// leaves it to finish alone (see `newcomer_listen`).
pub const LOSER_GRACE: Duration = Duration::from_secs(3);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    Lan,
    Rendezvous,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairnetError {
    /// The connection or session ended (either side, or lost).
    Closed,
    /// A frame above the reader's cap or `MAX_FRAME`: the transport is closed.
    FrameTooLarge,
    /// No peer: nothing announced the service in time, or no transport
    /// could be tried.
    NotFound,
    /// Nothing came in time.
    Timeout,
    /// The mailbox refused or failed (T-RDV).
    Mailbox(MailboxError),
    /// A local network or DNS-SD error, or an invalid service name.
    Io(String),
}

impl fmt::Display for PairnetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed => f.write_str("pairing connection closed"),
            Self::FrameTooLarge => f.write_str("pairing frame too large"),
            Self::NotFound => f.write_str("pairing peer not found"),
            Self::Timeout => f.write_str("pairing peer did not answer in time"),
            Self::Mailbox(e) => write!(f, "pairing rendezvous: {e}"),
            Self::Io(e) => write!(f, "pairing network: {e}"),
        }
    }
}

impl std::error::Error for PairnetError {}

/// One pairing connection carrying opaque frames, in order.
pub trait FrameTransport: Send {
    /// Sends one frame (at most `MAX_FRAME`; above is `FrameTooLarge` and
    /// the transport is closed).
    fn send(&mut self, frame: &[u8]) -> Result<(), PairnetError>;
    /// The next frame, at most `min(max, MAX_FRAME)` bytes: a longer length
    /// closes the transport and is `FrameTooLarge`, before its body is read.
    fn recv(&mut self, max: usize) -> Result<Vec<u8>, PairnetError>;
    /// Closes both directions. Idempotent.
    fn close(&mut self);
    fn kind(&self) -> TransportKind;
}

/// Opens the rendezvous session when it is needed (the approver opens it
/// only once T-LAN failed).
pub type RdvOpener = Box<dyn FnOnce() -> Result<Rendezvous, MailboxError> + Send>;

/// What the tests can see of a race: the live DNS-SD announcements, the
/// worker threads still running and the address T-LAN listened on.
#[derive(Debug, Default)]
pub struct Probe {
    announced: AtomicIsize,
    workers: AtomicUsize,
    listen: Mutex<Option<SocketAddr>>,
}

impl Probe {
    /// DNS-SD announcements not withdrawn yet.
    pub fn announced(&self) -> usize {
        self.announced.load(Ordering::Acquire).max(0) as usize
    }

    /// Worker threads of `newcomer_listen` not finished yet.
    pub fn workers(&self) -> usize {
        self.workers.load(Ordering::Acquire)
    }

    /// The last address a T-LAN listener was bound to.
    pub fn listen_addr(&self) -> Option<SocketAddr> {
        *self.listen.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub(crate) fn announced_add(&self, n: isize) {
        self.announced.fetch_add(n, Ordering::AcqRel);
    }

    pub(crate) fn set_listen(&self, addr: SocketAddr) {
        *self.listen.lock().unwrap_or_else(|e| e.into_inner()) = Some(addr);
    }
}

/// The knobs of the try order. `Default` is the spec's.
#[derive(Debug, Clone)]
pub struct PairnetOptions {
    /// How long the approver tries T-LAN (`LAN_TRY`).
    pub lan_try: Duration,
    /// The newcomer's T-LAN address; `None` picks `lan_address()` (and
    /// offers no T-LAN when there is none).
    pub lan_ip: Option<IpAddr>,
    /// One T-RDV read of the newcomer's race (`RDV_SLICE`).
    pub rdv_slice: Duration,
    pub probe: Option<Arc<Probe>>,
}

impl Default for PairnetOptions {
    fn default() -> Self {
        PairnetOptions {
            lan_try: LAN_TRY,
            lan_ip: None,
            rdv_slice: RDV_SLICE,
            probe: None,
        }
    }
}

/// The approver's side: T-LAN for `LAN_TRY`, then T-RDV on `rdv` (the
/// mailbox and the session id of the QR) when given.
pub fn approver_connect(
    service_name: &str,
    rdv: Option<(Endpoint, [u8; 16])>,
) -> Result<Box<dyn FrameTransport>, PairnetError> {
    let opener = rdv.map(|(endpoint, session)| -> RdvOpener {
        Box::new(move || Rendezvous::new(endpoint, session, RdvRole::Approver))
    });
    approver_connect_with(service_name, opener, &PairnetOptions::default())
}

/// `approver_connect` with its rendezvous opened by `rdv` and the try
/// order of `options`. The session is opened only once T-LAN failed, so a
/// LAN pairing makes no request to the mailbox.
pub fn approver_connect_with(
    service_name: &str,
    rdv: Option<RdvOpener>,
    options: &PairnetOptions,
) -> Result<Box<dyn FrameTransport>, PairnetError> {
    lan::check_service_name(service_name)?;
    let lan_error = match browse_and_connect(service_name, options.lan_try) {
        Ok(t) => return Ok(Box::new(t)),
        Err(e) => e,
    };
    match rdv {
        Some(open) => Ok(Box::new(RdvTransport(open().map_err(rdv::rdv_error)?))),
        None => Err(lan_error),
    }
}

/// The newcomer's side: announces T-LAN and writes `hello` on T-RDV at the
/// same time, and returns the transport on which the approver's first
/// frame (at most `MAX_HANDSHAKE_FRAME`) arrives, with that frame. On
/// T-LAN, `hello` is sent once the connection is in.
pub fn newcomer_listen(
    service_name: &str,
    rdv: Option<(Endpoint, [u8; 16])>,
    hello: &[u8],
    timeout: Duration,
) -> Result<(Box<dyn FrameTransport>, Vec<u8>), PairnetError> {
    let opener = rdv.map(|(endpoint, session)| -> RdvOpener {
        Box::new(move || Rendezvous::new(endpoint, session, RdvRole::Newcomer))
    });
    newcomer_listen_with(
        service_name,
        opener,
        hello,
        timeout,
        &PairnetOptions::default(),
    )
}

type Won = (Box<dyn FrameTransport>, Vec<u8>);

/// What the two workers share with the race.
struct Race {
    stop: AtomicBool,
    /// The accepted T-LAN socket during its handshake, for the race to shut
    /// it down when T-RDV wins. Taken back by the worker once it won.
    lan_socket: Mutex<Option<TcpStream>>,
}

impl Race {
    fn socket(&self) -> std::sync::MutexGuard<'_, Option<TcpStream>> {
        self.lan_socket.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Counts a worker in the probe for as long as it lives.
struct WorkerMark(Option<Arc<Probe>>);

impl WorkerMark {
    fn new(probe: &Option<Arc<Probe>>) -> WorkerMark {
        if let Some(p) = probe {
            p.workers.fetch_add(1, Ordering::AcqRel);
        }
        WorkerMark(probe.clone())
    }
}

impl Drop for WorkerMark {
    fn drop(&mut self) {
        if let Some(p) = &self.0 {
            p.workers.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

/// `newcomer_listen` with its rendezvous opened by `rdv` and the knobs of
/// `options`.
///
/// One worker thread per transport. When one wins, the other is stopped:
/// the T-LAN worker within one listener poll (its socket is shut down, its
/// announcement withdrawn) and is always joined. The T-RDV worker stops
/// after its current read (`rdv_slice`, one long poll of the server) and
/// then closes its session; it is joined if it does so within
/// `LOSER_GRACE`, else left to finish alone, which it does after at most
/// that read, the 60 s write patience of the `hello` and the 30 s close
/// request. A late frame on the loser is dropped with it.
pub fn newcomer_listen_with(
    service_name: &str,
    rdv: Option<RdvOpener>,
    hello: &[u8],
    timeout: Duration,
    options: &PairnetOptions,
) -> Result<Won, PairnetError> {
    lan::check_service_name(service_name)?;
    if hello.len() > MAX_FRAME {
        return Err(PairnetError::FrameTooLarge);
    }
    let deadline = Instant::now() + timeout;
    let race = Arc::new(Race {
        stop: AtomicBool::new(false),
        lan_socket: Mutex::new(None),
    });
    let (tx, rx) = mpsc::channel::<Result<Won, PairnetError>>();
    let lan_ip = options.lan_ip.or_else(|| lan_address().ok());

    let lan_worker = lan_ip.map(|ip| {
        let (race, tx, probe) = (race.clone(), tx.clone(), options.probe.clone());
        let (name, hello) = (service_name.to_string(), hello.to_vec());
        let mark = WorkerMark::new(&probe);
        thread::spawn(move || {
            let _mark = mark;
            let won = lan_side(ip, &name, &hello, deadline, &race, probe.as_deref());
            let _ = tx.send(won);
        })
    });
    let rdv_worker = rdv.map(|open| {
        let (race, tx, slice) = (race.clone(), tx.clone(), options.rdv_slice);
        let hello = hello.to_vec();
        let mark = WorkerMark::new(&options.probe);
        thread::spawn(move || {
            let _mark = mark;
            let won = rdv_side(open, &hello, deadline, slice, &race);
            let _ = tx.send(won);
        })
    });
    drop(tx);

    let mut pending = usize::from(lan_worker.is_some()) + usize::from(rdv_worker.is_some());
    let mut errors = Vec::new();
    let outcome = loop {
        if pending == 0 {
            break Err(pick(errors));
        }
        let left = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(left) {
            Ok(Ok(won)) => break Ok(won),
            Ok(Err(e)) => {
                pending -= 1;
                errors.push(e);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => break Err(PairnetError::Timeout),
            Err(mpsc::RecvTimeoutError::Disconnected) => break Err(pick(errors)),
        }
    };

    // Stops the loser (or both, on a timeout).
    race.stop.store(true, Ordering::Release);
    if let Some(s) = race.socket().take() {
        let _ = s.shutdown(Shutdown::Both);
    }
    if let Some(w) = lan_worker {
        let _ = w.join();
    }
    if let Some(w) = rdv_worker {
        let grace = Instant::now() + LOSER_GRACE;
        while !w.is_finished() && Instant::now() < grace {
            thread::sleep(Duration::from_millis(10));
        }
        if w.is_finished() {
            let _ = w.join();
        }
    }
    // A late result of the loser is dropped (and closed) here.
    drop(rx);
    outcome
}

/// The whole race failed: a timeout on either side says more than the
/// other side's failure (no LAN, a squatter); else the first error.
fn pick(errors: Vec<PairnetError>) -> PairnetError {
    if errors.contains(&PairnetError::Timeout) {
        return PairnetError::Timeout;
    }
    errors.into_iter().next().unwrap_or(PairnetError::NotFound)
}

fn lan_side(
    ip: IpAddr,
    name: &str,
    hello: &[u8],
    deadline: Instant,
    race: &Race,
    probe: Option<&Probe>,
) -> Result<Won, PairnetError> {
    let mut t = lan::accept_one(ip, name, deadline, &race.stop, probe)?;
    *race.socket() = t.canceller();
    if race.stop.load(Ordering::Acquire) {
        return Err(PairnetError::Closed);
    }
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err(PairnetError::Timeout);
    }
    t.set_read_timeout(Some(left))?;
    t.send(hello)?;
    let first = t.recv(MAX_HANDSHAKE_FRAME)?;
    // Won: the race must no longer shut this socket down.
    race.socket().take();
    if race.stop.load(Ordering::Acquire) {
        return Err(PairnetError::Closed);
    }
    t.set_read_timeout(None)?;
    Ok((Box::new(t), first))
}

fn rdv_side(
    open: RdvOpener,
    hello: &[u8],
    deadline: Instant,
    slice: Duration,
    race: &Race,
) -> Result<Won, PairnetError> {
    if race.stop.load(Ordering::Acquire) {
        return Err(PairnetError::Closed);
    }
    let mut t = RdvTransport(open().map_err(rdv::rdv_error)?);
    t.send(hello)?;
    loop {
        if race.stop.load(Ordering::Acquire) {
            // Dropping `t` closes the session for both sides.
            return Err(PairnetError::Closed);
        }
        let now = Instant::now();
        if now >= deadline {
            return Err(PairnetError::Timeout);
        }
        let until = (now + slice.max(Duration::from_millis(1))).min(deadline);
        match t.recv_until(MAX_HANDSHAKE_FRAME, until) {
            Ok(first) => return Ok((Box::new(t), first)),
            Err(PairnetError::Timeout) => {}
            Err(e) => return Err(e),
        }
    }
}
