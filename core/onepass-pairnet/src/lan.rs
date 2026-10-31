//! T-LAN: TCP on the local network, announced in DNS-SD (spec 5.3, 2b 5.5).
//!
//! The newcomer binds an ephemeral port on one LAN address, announces it as
//! `<service name>._onepass-pair._tcp.local.`, takes exactly one connection
//! and withdraws the announcement at once. The approver browses for that
//! name (the session id from the QR, in hex) and connects.
//!
//! Untrusted on purpose: whoever answers on the LAN only moves sealed
//! frames. The pairing channel (key committed by the QR, short code over
//! the whole transcript) is what binds the two devices; this module keeps
//! only framing, caps and timeouts.
//!
//! What goes on the air: the instance name is the caller's random session
//! id, the host name is derived from it (`<service name>.local.`, never the
//! machine's own name, which often carries the owner's name), and there is
//! no TXT data. So the announcement carries no account or user data.
//!
//! Which address: the listener binds one address of one LAN interface
//! (`lan_address`), not `0.0.0.0`, so the port is not open on a VPN, a
//! public interface or a container bridge, and DNS-SD speaks on that
//! interface only. The price: on a machine with two LANs, the approver must
//! be on the chosen one; T-RDV covers the rest.

use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, SocketAddrV6, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use mdns_sd::{IfKind, ScopedIp, ServiceDaemon, ServiceEvent, ServiceInfo, TxtProperty};

use crate::frame::{io_error, read_frame, write_frame};
use crate::{FrameTransport, MAX_FRAME, PairnetError, Probe, SERVICE_TYPE, TransportKind};

/// Read and write timeout of a T-LAN connection: a pairing frame stays
/// readable 120 s on the rendezvous, and the session ends after 2 minutes.
pub const LAN_IO_TIMEOUT: Duration = Duration::from_secs(120);
/// Longest TCP connect to one announced address.
pub const LAN_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
/// Pause between two looks at the listener.
const ACCEPT_POLL: Duration = Duration::from_millis(20);
/// How long the withdrawal (goodbye packets) and the daemon stop may take.
const DAEMON_WAIT: Duration = Duration::from_secs(2);

/// One T-LAN connection. Every error closes it: after a refused length or a
/// timeout, the position in the stream is unknown.
#[derive(Debug)]
pub struct LanTransport {
    stream: Option<TcpStream>,
}

impl LanTransport {
    /// Connects to `addr` directly, without DNS-SD.
    pub fn connect(addr: SocketAddr, timeout: Duration) -> Result<LanTransport, PairnetError> {
        let timeout = timeout.clamp(Duration::from_millis(1), LAN_CONNECT_TIMEOUT);
        let stream = TcpStream::connect_timeout(&addr, timeout).map_err(connect_error)?;
        LanTransport::from_stream(stream)
    }

    /// Wraps a connected stream: blocking, no Nagle delay, read and write
    /// timeouts of `LAN_IO_TIMEOUT`.
    pub fn from_stream(stream: TcpStream) -> Result<LanTransport, PairnetError> {
        stream.set_nonblocking(false).map_err(io_error)?;
        stream.set_nodelay(true).map_err(io_error)?;
        stream
            .set_read_timeout(Some(LAN_IO_TIMEOUT))
            .map_err(io_error)?;
        stream
            .set_write_timeout(Some(LAN_IO_TIMEOUT))
            .map_err(io_error)?;
        Ok(LanTransport {
            stream: Some(stream),
        })
    }

    /// A second handle on the socket, for another thread to shut it down.
    pub(crate) fn canceller(&self) -> Option<TcpStream> {
        self.stream.as_ref().and_then(|s| s.try_clone().ok())
    }

    /// Bounds the next reads (a handshake under a deadline); `None` puts
    /// back `LAN_IO_TIMEOUT`.
    pub(crate) fn set_read_timeout(&self, t: Option<Duration>) -> Result<(), PairnetError> {
        let t = t.map_or(LAN_IO_TIMEOUT, |t| {
            t.clamp(Duration::from_millis(1), LAN_IO_TIMEOUT)
        });
        match &self.stream {
            Some(s) => s.set_read_timeout(Some(t)).map_err(io_error),
            None => Err(PairnetError::Closed),
        }
    }

    fn fail(&mut self, e: PairnetError) -> PairnetError {
        self.close();
        e
    }
}

impl FrameTransport for LanTransport {
    fn send(&mut self, frame: &[u8]) -> Result<(), PairnetError> {
        let Some(stream) = self.stream.as_mut() else {
            return Err(PairnetError::Closed);
        };
        write_frame(stream, frame).map_err(|e| self.fail(e))
    }

    fn recv(&mut self, max: usize) -> Result<Vec<u8>, PairnetError> {
        let Some(stream) = self.stream.as_mut() else {
            return Err(PairnetError::Closed);
        };
        read_frame(stream, max.min(MAX_FRAME)).map_err(|e| self.fail(e))
    }

    fn close(&mut self) {
        if let Some(s) = self.stream.take() {
            let _ = s.shutdown(Shutdown::Both);
        }
    }

    fn kind(&self) -> TransportKind {
        TransportKind::Lan
    }
}

impl Drop for LanTransport {
    fn drop(&mut self) {
        self.close();
    }
}

/// The address the listener binds to: an IPv4 address of an interface that
/// is up and not loopback, preferring 192.168/16, then 10/8, then
/// 172.16/12 (container bridges live there), then link-local 169.254/16.
/// Public addresses are never chosen. `NotFound` when there is none.
pub fn lan_address() -> Result<IpAddr, PairnetError> {
    let interfaces = if_addrs::get_if_addrs().map_err(io_error)?;
    interfaces
        .iter()
        .filter(|i| i.is_oper_up() && !i.is_loopback())
        .filter_map(|i| match i.ip() {
            IpAddr::V4(v4) => lan_rank(v4).map(|rank| (rank, v4)),
            IpAddr::V6(_) => None,
        })
        .min_by_key(|(rank, _)| *rank)
        .map(|(_, v4)| IpAddr::V4(v4))
        .ok_or(PairnetError::NotFound)
}

fn lan_rank(ip: Ipv4Addr) -> Option<u8> {
    let o = ip.octets();
    match o {
        [192, 168, ..] => Some(0),
        [10, ..] => Some(1),
        [172, b, ..] if (16..32).contains(&b) => Some(2),
        [169, 254, ..] => Some(3),
        _ => None,
    }
}

/// A DNS-SD instance name is one label here: 1 to 63 bytes of lowercase
/// letters, digits and `-` (a session id in hex fits). Anything else, a
/// name with dots or an address in it, is refused.
pub(crate) fn check_service_name(name: &str) -> Result<(), PairnetError> {
    let ok = (1..=63).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    if ok {
        Ok(())
    } else {
        Err(PairnetError::Io(
            "service name must be one DNS label in lowercase".into(),
        ))
    }
}

/// Announces `service_name` on a LAN address (`lan_address`), on an
/// ephemeral port, and returns the first connection; the announcement is
/// withdrawn and the port closed as soon as it arrives. `Timeout` when no
/// one connects in time.
pub fn publish_and_accept(
    service_name: &str,
    timeout: Duration,
) -> Result<LanTransport, PairnetError> {
    check_service_name(service_name)?;
    publish_and_accept_on(lan_address()?, service_name, timeout, None)
}

/// `publish_and_accept` on a chosen address (the tests use loopback), with
/// an optional probe that sees the listener and the announcement.
pub fn publish_and_accept_on(
    ip: IpAddr,
    service_name: &str,
    timeout: Duration,
    probe: Option<&Probe>,
) -> Result<LanTransport, PairnetError> {
    let never = AtomicBool::new(false);
    accept_one(ip, service_name, Instant::now() + timeout, &never, probe)
}

/// One connection, until `deadline` (`Timeout`) or until `stop` is set
/// (`Closed`). The listener and the announcement are gone when this
/// returns, whatever the outcome.
pub(crate) fn accept_one(
    ip: IpAddr,
    service_name: &str,
    deadline: Instant,
    stop: &AtomicBool,
    probe: Option<&Probe>,
) -> Result<LanTransport, PairnetError> {
    check_service_name(service_name)?;
    let listener = TcpListener::bind((ip, 0)).map_err(io_error)?;
    listener.set_nonblocking(true).map_err(io_error)?;
    let addr = listener.local_addr().map_err(io_error)?;
    let announcement = Announcement::start(ip, service_name, addr.port(), probe)?;
    if let Some(p) = probe {
        p.set_listen(addr);
    }
    let accepted = loop {
        match listener.accept() {
            Ok((stream, _)) => break Ok(stream),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if stop.load(Ordering::Acquire) {
                    break Err(PairnetError::Closed);
                }
                let now = Instant::now();
                if now >= deadline {
                    break Err(PairnetError::Timeout);
                }
                thread::sleep(ACCEPT_POLL.min(deadline - now));
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => break Err(io_error(e)),
        }
    };
    // Exactly one connection: the port closes, the announcement goes.
    drop(listener);
    drop(announcement);
    LanTransport::from_stream(accepted?)
}

/// A registered DNS-SD service; dropping it withdraws the service (goodbye
/// packets) and stops the daemon thread.
struct Announcement<'p> {
    daemon: Daemon,
    fullname: String,
    probe: Option<&'p Probe>,
}

impl<'p> Announcement<'p> {
    fn start(
        ip: IpAddr,
        name: &str,
        port: u16,
        probe: Option<&'p Probe>,
    ) -> Result<Announcement<'p>, PairnetError> {
        let daemon = Daemon::new()?;
        // Speak on the bound interface only.
        daemon
            .0
            .disable_interface(IfKind::All)
            .map_err(mdns_error)?;
        daemon
            .0
            .enable_interface(IfKind::Addr(ip))
            .map_err(mdns_error)?;
        let host = format!("{name}.local.");
        let info = ServiceInfo::new(
            SERVICE_TYPE,
            name,
            &host,
            ip,
            port,
            Vec::<TxtProperty>::new(),
        )
        .map_err(mdns_error)?;
        let fullname = info.get_fullname().to_string();
        daemon.0.register(info).map_err(mdns_error)?;
        if let Some(p) = probe {
            p.announced_add(1);
        }
        Ok(Announcement {
            daemon,
            fullname,
            probe,
        })
    }
}

impl Drop for Announcement<'_> {
    fn drop(&mut self) {
        if let Ok(status) = self.daemon.0.unregister(&self.fullname) {
            let _ = status.recv_timeout(DAEMON_WAIT);
        }
        if let Some(p) = self.probe {
            p.announced_add(-1);
        }
        // `self.daemon` drops next and stops its thread.
    }
}

/// A `ServiceDaemon` that is shut down (and its thread waited for, up to
/// `DAEMON_WAIT`) when dropped.
struct Daemon(ServiceDaemon);

impl Daemon {
    fn new() -> Result<Daemon, PairnetError> {
        ServiceDaemon::new().map(Daemon).map_err(mdns_error)
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        if let Ok(status) = self.0.shutdown() {
            let _ = status.recv_timeout(DAEMON_WAIT);
        }
    }
}

fn mdns_error(e: mdns_sd::Error) -> PairnetError {
    PairnetError::Io(format!("dns-sd: {e}"))
}

/// A refused or unreachable address is a peer that is not there.
fn connect_error(e: std::io::Error) -> PairnetError {
    match e.kind() {
        std::io::ErrorKind::ConnectionRefused
        | std::io::ErrorKind::HostUnreachable
        | std::io::ErrorKind::NetworkUnreachable
        | std::io::ErrorKind::AddrNotAvailable => PairnetError::NotFound,
        _ => io_error(e),
    }
}

/// Browses for `<service_name>._onepass-pair._tcp.local.` and connects to
/// the first address of it that answers. `NotFound` when nothing did in
/// `timeout`. The browse daemon is stopped before this returns.
pub fn browse_and_connect(
    service_name: &str,
    timeout: Duration,
) -> Result<LanTransport, PairnetError> {
    check_service_name(service_name)?;
    let deadline = Instant::now() + timeout;
    let daemon = Daemon::new()?;
    let events = daemon.0.browse(SERVICE_TYPE).map_err(mdns_error)?;
    let fullname = format!("{service_name}.{SERVICE_TYPE}");
    let found = loop {
        let now = Instant::now();
        if now >= deadline {
            break Err(PairnetError::NotFound);
        }
        let event = match events.recv_timeout(deadline - now) {
            Ok(e) => e,
            Err(mdns_sd::RecvTimeoutError::Timeout) => break Err(PairnetError::NotFound),
            Err(mdns_sd::RecvTimeoutError::Disconnected) => {
                break Err(PairnetError::Io("dns-sd daemon stopped".into()));
            }
        };
        let ServiceEvent::ServiceResolved(service) = event else {
            continue;
        };
        if !service.get_fullname().eq_ignore_ascii_case(&fullname) {
            continue;
        }
        let mut addrs: Vec<SocketAddr> = service
            .get_addresses()
            .iter()
            .map(|a| socket_addr(a, service.get_port()))
            .collect();
        // IPv4 first, then the stable order of the addresses.
        addrs.sort_by_key(|a| (a.is_ipv6(), *a));
        let mut connected = None;
        for addr in addrs {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            if let Ok(t) = LanTransport::connect(addr, left) {
                connected = Some(t);
                break;
            }
        }
        if let Some(t) = connected {
            break Ok(t);
        }
        // None answered: a later resolution may bring another address.
    };
    let _ = daemon.0.stop_browse(SERVICE_TYPE);
    drop(events);
    drop(daemon);
    found
}

fn socket_addr(ip: &ScopedIp, port: u16) -> SocketAddr {
    match ip {
        ScopedIp::V6(v6) => {
            let scope = if v6.addr().is_unicast_link_local() {
                v6.scope_id().index
            } else {
                0
            };
            SocketAddr::V6(SocketAddrV6::new(*v6.addr(), port, 0, scope))
        }
        other => SocketAddr::new(other.to_ip_addr(), port),
    }
}
