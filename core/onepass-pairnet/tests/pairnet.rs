//! T-LAN and T-RDV (cross-platform spec 5.3, frames of 2b 5.5).

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use onepass_mailbox::testing::FakeMailbox;
use onepass_mailbox::{RdvRole, Rendezvous};
use onepass_pairnet::{
    FrameTransport, LAN_TRY, LanTransport, MAX_FRAME, MAX_HANDSHAKE_FRAME, PairnetError,
    PairnetOptions, Probe, RdvOpener, SERVICE_TYPE, TransportKind, approver_connect_with,
    browse_and_connect, newcomer_listen_with, publish_and_accept_on,
};

const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// A fresh 128-bit session id; its hex is the service name.
fn session() -> ([u8; 16], String) {
    static N: AtomicU64 = AtomicU64::new(0);
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    let n = N.fetch_add(1, Ordering::Relaxed);
    let mut id = [0u8; 16];
    id[..8].copy_from_slice(&t.to_be_bytes());
    id[8..12].copy_from_slice(&std::process::id().to_be_bytes());
    id[12..].copy_from_slice(&(n as u32).to_be_bytes());
    let hex: String = id.iter().map(|b| format!("{b:02x}")).collect();
    (id, hex)
}

fn opener(fake: &FakeMailbox, id: [u8; 16], role: RdvRole) -> RdvOpener {
    let fake = fake.clone();
    Box::new(move || Ok(fake.rendezvous(id, role)))
}

fn options(probe: &Arc<Probe>) -> PairnetOptions {
    PairnetOptions {
        lan_try: Duration::from_millis(100),
        lan_ip: Some(LOOPBACK),
        rdv_slice: Duration::from_millis(200),
        probe: Some(probe.clone()),
    }
}

fn connected_pair() -> (LanTransport, LanTransport) {
    let listener = TcpListener::bind((LOOPBACK, 0)).unwrap();
    let addr = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        LanTransport::from_stream(stream).unwrap()
    });
    let client = LanTransport::connect(addr, Duration::from_secs(2)).unwrap();
    (server.join().unwrap(), client)
}

#[test]
fn constants_match_the_swift_side() {
    // apple/VaultKit PairingFrame and LocalNetworkPairingTransport.
    assert_eq!(SERVICE_TYPE, "_onepass-pair._tcp.local.");
    assert_eq!(MAX_FRAME, 64 << 20);
    assert_eq!(MAX_HANDSHAKE_FRAME, 16 << 10);
    assert_eq!(LAN_TRY, Duration::from_secs(5));
}

#[test]
fn lan_frames_over_loopback() {
    let (mut server, mut client) = connected_pair();
    assert_eq!(client.kind(), TransportKind::Lan);
    let big: Vec<u8> = (0..(3 << 20)).map(|i| (i % 251) as u8).collect();
    // The reader runs beside the writer: 3 MiB does not fit a socket buffer.
    let reader = thread::spawn(move || {
        assert_eq!(server.recv(MAX_HANDSHAKE_FRAME).unwrap(), b"hello");
        assert_eq!(server.recv(MAX_HANDSHAKE_FRAME).unwrap(), b"");
        let got = server.recv(MAX_FRAME).unwrap();
        server.send(b"back").unwrap();
        (server, got)
    });
    client.send(b"hello").unwrap();
    client.send(b"").unwrap();
    client.send(&big).unwrap();
    let (mut server, got) = reader.join().unwrap();
    assert_eq!(got, big);
    assert_eq!(client.recv(MAX_FRAME).unwrap(), b"back");

    server.close();
    assert_eq!(client.recv(MAX_FRAME), Err(PairnetError::Closed));
    assert_eq!(server.send(b"x"), Err(PairnetError::Closed));
}

#[test]
fn lan_refuses_a_frame_above_max_frame_on_send() {
    let (mut server, mut client) = connected_pair();
    let huge = vec![0u8; MAX_FRAME + 1];
    assert_eq!(client.send(&huge), Err(PairnetError::FrameTooLarge));
    // The connection is closed, as on the Swift side.
    assert_eq!(server.recv(MAX_FRAME), Err(PairnetError::Closed));
}

#[test]
fn lan_handshake_cap() {
    let listener = TcpListener::bind((LOOPBACK, 0)).unwrap();
    let addr = listener.local_addr().unwrap();
    let peer = thread::spawn(move || {
        let mut s = TcpStream::connect(addr).unwrap();
        // Only the header: the reader must refuse before reading a body.
        s.write_all(&((MAX_HANDSHAKE_FRAME + 1) as u32).to_be_bytes())
            .unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut buf = [0u8; 1];
        // The newcomer closed the connection: end of stream.
        matches!(s.read(&mut buf), Ok(0) | Err(_))
    });
    let (stream, _) = listener.accept().unwrap();
    let mut t = LanTransport::from_stream(stream).unwrap();
    assert_eq!(
        t.recv(MAX_HANDSHAKE_FRAME),
        Err(PairnetError::FrameTooLarge)
    );
    assert_eq!(t.recv(MAX_HANDSHAKE_FRAME), Err(PairnetError::Closed));
    assert!(peer.join().unwrap(), "connection not closed");
}

#[test]
fn lan_header_cut_short_is_closed() {
    let listener = TcpListener::bind((LOOPBACK, 0)).unwrap();
    let addr = listener.local_addr().unwrap();
    let peer = thread::spawn(move || {
        let mut s = TcpStream::connect(addr).unwrap();
        s.write_all(&[0, 0, 0, 9, 1, 2]).unwrap();
    });
    let (stream, _) = listener.accept().unwrap();
    let mut t = LanTransport::from_stream(stream).unwrap();
    peer.join().unwrap();
    assert_eq!(t.recv(MAX_FRAME), Err(PairnetError::Closed));
}

/// Real DNS-SD on the loopback interface. Needs multicast on lo0 / lo;
/// some sandboxes and CI runners have none.
#[test]
#[ignore = "needs multicast DNS on the loopback interface"]
fn lan_round_trip() {
    let (_, name) = session();
    let probe = Arc::new(Probe::default());
    let listen = {
        let name = name.clone();
        let probe = probe.clone();
        thread::spawn(move || {
            publish_and_accept_on(LOOPBACK, &name, Duration::from_secs(10), Some(&probe))
        })
    };
    let mut approver = browse_and_connect(&name, Duration::from_secs(10)).unwrap();
    let mut newcomer = listen.join().unwrap().unwrap();
    // The announcement is withdrawn once the connection is in.
    assert_eq!(probe.announced(), 0);
    newcomer.send(b"hello").unwrap();
    assert_eq!(approver.recv(MAX_HANDSHAKE_FRAME).unwrap(), b"hello");
    approver.send(b"key exchange").unwrap();
    assert_eq!(newcomer.recv(MAX_HANDSHAKE_FRAME).unwrap(), b"key exchange");
}

#[test]
fn publish_accepts_one_connection_then_withdraws() {
    let (_, name) = session();
    let probe = Arc::new(Probe::default());
    let listen = {
        let name = name.clone();
        let probe = probe.clone();
        thread::spawn(move || {
            publish_and_accept_on(LOOPBACK, &name, Duration::from_secs(5), Some(&probe))
        })
    };
    let addr = wait_listen(&probe);
    assert_ne!(addr.port(), 0);
    assert_eq!(addr.ip(), LOOPBACK, "bound to the chosen address only");
    let mut approver = LanTransport::connect(addr, Duration::from_secs(2)).unwrap();
    let mut newcomer = listen.join().unwrap().unwrap();
    assert_eq!(probe.announced(), 0);
    // The port is closed: a second approver cannot connect.
    assert!(TcpStream::connect_timeout(&addr, Duration::from_secs(1)).is_err());
    approver.send(b"one").unwrap();
    assert_eq!(newcomer.recv(MAX_HANDSHAKE_FRAME).unwrap(), b"one");
}

#[test]
fn publish_times_out_and_withdraws() {
    let (_, name) = session();
    let probe = Arc::new(Probe::default());
    let start = Instant::now();
    let r = publish_and_accept_on(LOOPBACK, &name, Duration::from_millis(300), Some(&probe));
    assert_eq!(r.err(), Some(PairnetError::Timeout));
    assert!(start.elapsed() >= Duration::from_millis(300));
    assert_eq!(probe.announced(), 0);
}

#[test]
fn service_name_must_be_a_dns_label() {
    let probe = Arc::new(Probe::default());
    for bad in ["", "Has.Dot", "user@example.com", &"a".repeat(64)] {
        let r = publish_and_accept_on(LOOPBACK, bad, Duration::from_millis(50), Some(&probe));
        assert!(matches!(r, Err(PairnetError::Io(_))), "{bad:?}");
        assert!(matches!(
            browse_and_connect(bad, Duration::from_millis(50)),
            Err(PairnetError::Io(_))
        ));
    }
}

#[test]
fn rdv_fallback_after_lan_try() {
    let fake = FakeMailbox::new();
    let (id, name) = session();
    let probe = Arc::new(Probe::default());
    let newcomer = {
        let fake = fake.clone();
        thread::spawn(move || {
            let mut rdv = fake.rendezvous(id, RdvRole::Newcomer);
            rdv.send_frame(b"hello").unwrap();
            let kex = rdv
                .recv_frame(MAX_HANDSHAKE_FRAME, Instant::now() + Duration::from_secs(5))
                .unwrap();
            assert_eq!(kex, b"key exchange");
        })
    };
    let start = Instant::now();
    let mut t = approver_connect_with(
        &name,
        Some(opener(&fake, id, RdvRole::Approver)),
        &options(&probe),
    )
    .unwrap();
    assert!(
        start.elapsed() >= Duration::from_millis(100),
        "T-LAN tried first"
    );
    assert_eq!(t.kind(), TransportKind::Rendezvous);
    assert_eq!(t.recv(MAX_HANDSHAKE_FRAME).unwrap(), b"hello");
    t.send(b"key exchange").unwrap();
    newcomer.join().unwrap();
    t.close();
    assert!(fake.rdv_closed(id));
}

#[test]
fn approver_without_rdv_is_not_found() {
    let (_, name) = session();
    let probe = Arc::new(Probe::default());
    let r = approver_connect_with(&name, None, &options(&probe));
    assert_eq!(r.err(), Some(PairnetError::NotFound));
}

#[test]
fn newcomer_first_frame_wins() {
    let fake = FakeMailbox::new();
    let (id, name) = session();
    let probe = Arc::new(Probe::default());
    let approver = {
        let fake = fake.clone();
        thread::spawn(move || {
            let mut rdv = fake.rendezvous(id, RdvRole::Approver);
            let hello = rdv
                .recv_frame(MAX_HANDSHAKE_FRAME, Instant::now() + Duration::from_secs(5))
                .unwrap();
            assert_eq!(hello, b"hello");
            rdv.send_frame(b"key exchange").unwrap();
            // Keeps the session open until the newcomer is done.
            rdv
        })
    };
    let (mut t, first) = newcomer_listen_with(
        &name,
        Some(opener(&fake, id, RdvRole::Newcomer)),
        b"hello",
        Duration::from_secs(5),
        &options(&probe),
    )
    .unwrap();
    assert_eq!(t.kind(), TransportKind::Rendezvous);
    assert_eq!(first, b"key exchange");
    // T-LAN was announced, and is withdrawn: no announcement, no listener,
    // no worker left.
    let lan = probe.listen_addr().expect("T-LAN was published");
    assert_eq!(probe.announced(), 0);
    assert_eq!(probe.workers(), 0);
    assert!(TcpStream::connect_timeout(&lan, Duration::from_secs(1)).is_err());

    let mut rdv = approver.join().unwrap();
    t.send(b"confirmed").unwrap();
    assert_eq!(
        rdv.recv_frame(MAX_FRAME, Instant::now() + Duration::from_secs(5))
            .unwrap(),
        b"confirmed"
    );
}

#[test]
fn newcomer_lan_wins_and_rdv_is_released() {
    let fake = FakeMailbox::new();
    let (id, name) = session();
    let probe = Arc::new(Probe::default());
    let approver = {
        let probe = probe.clone();
        thread::spawn(move || {
            let addr = wait_listen(&probe);
            let mut t = LanTransport::connect(addr, Duration::from_secs(2)).unwrap();
            assert_eq!(t.recv(MAX_HANDSHAKE_FRAME).unwrap(), b"hello");
            t.send(b"key exchange").unwrap();
            t
        })
    };
    let (mut t, first) = newcomer_listen_with(
        &name,
        Some(opener(&fake, id, RdvRole::Newcomer)),
        b"hello",
        Duration::from_secs(5),
        &options(&probe),
    )
    .unwrap();
    assert_eq!(t.kind(), TransportKind::Lan);
    assert_eq!(first, b"key exchange");
    assert_eq!(probe.announced(), 0);
    assert_eq!(probe.workers(), 0, "the T-RDV worker is joined");
    // The losing rendezvous was closed for both sides.
    assert!(fake.rdv_closed(id));

    let mut lan = approver.join().unwrap();
    t.send(b"confirmed").unwrap();
    assert_eq!(lan.recv(MAX_FRAME).unwrap(), b"confirmed");
}

#[test]
fn newcomer_lan_failure_falls_back_to_rdv() {
    // A hostile LAN peer takes the one connection and sends an oversized
    // handshake frame; the approver on T-RDV still gets through.
    let fake = FakeMailbox::new();
    let (id, name) = session();
    let probe = Arc::new(Probe::default());
    let squatter = {
        let probe = probe.clone();
        thread::spawn(move || {
            let addr = wait_listen(&probe);
            let mut s = TcpStream::connect(addr).unwrap();
            s.write_all(&u32::MAX.to_be_bytes()).unwrap();
            s
        })
    };
    let approver = {
        let fake = fake.clone();
        thread::spawn(move || {
            let mut rdv = fake.rendezvous(id, RdvRole::Approver);
            let hello = rdv
                .recv_frame(MAX_HANDSHAKE_FRAME, Instant::now() + Duration::from_secs(5))
                .unwrap();
            assert_eq!(hello, b"hello");
            // Lets the squatter lose first.
            thread::sleep(Duration::from_millis(300));
            rdv.send_frame(b"key exchange").unwrap();
            rdv
        })
    };
    let (t, first) = newcomer_listen_with(
        &name,
        Some(opener(&fake, id, RdvRole::Newcomer)),
        b"hello",
        Duration::from_secs(5),
        &options(&probe),
    )
    .unwrap();
    assert_eq!(t.kind(), TransportKind::Rendezvous);
    assert_eq!(first, b"key exchange");
    assert_eq!(probe.workers(), 0);
    drop(squatter.join().unwrap());
    drop(approver.join().unwrap());
}

#[test]
fn newcomer_times_out_and_releases_everything() {
    let fake = FakeMailbox::new();
    let (id, name) = session();
    let probe = Arc::new(Probe::default());
    let start = Instant::now();
    let r = newcomer_listen_with(
        &name,
        Some(opener(&fake, id, RdvRole::Newcomer)),
        b"hello",
        Duration::from_millis(500),
        &options(&probe),
    );
    assert_eq!(r.err(), Some(PairnetError::Timeout));
    assert!(start.elapsed() >= Duration::from_millis(500));
    assert!(start.elapsed() < Duration::from_secs(4));
    assert_eq!(probe.announced(), 0);
    assert_eq!(probe.workers(), 0);
    assert!(fake.rdv_closed(id));
}

#[test]
fn rdv_transport_maps_the_caps() {
    let fake = FakeMailbox::new();
    let (id, _) = session();
    let mut a = onepass_pairnet::RdvTransport(fake.rendezvous(id, RdvRole::Approver));
    let mut n: Rendezvous = fake.rendezvous(id, RdvRole::Newcomer);
    n.send_frame(&vec![7u8; MAX_HANDSHAKE_FRAME + 1]).unwrap();
    assert_eq!(
        a.recv(MAX_HANDSHAKE_FRAME),
        Err(PairnetError::FrameTooLarge)
    );
    assert_eq!(a.recv(MAX_HANDSHAKE_FRAME), Err(PairnetError::Closed));
    assert_eq!(a.kind(), TransportKind::Rendezvous);
}

fn wait_listen(probe: &Probe) -> SocketAddr {
    let start = Instant::now();
    loop {
        if let Some(a) = probe.listen_addr() {
            return a;
        }
        assert!(start.elapsed() < Duration::from_secs(5), "never listened");
        thread::sleep(Duration::from_millis(10));
    }
}
