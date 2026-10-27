//! Session handshake (spec 6.5) and encrypted channel (spec 6.6).

use onepass_bridge::BridgeError;
use onepass_bridge::channel::{Channel, IDLE_TIMEOUT_SECS};
use onepass_bridge::pairing::PairingRecord;
use onepass_bridge::session::{self, ExtPending, PendingSession};
use onepass_bridge::wire::{Envelope, Finish, Hello, Msg, Welcome};
use zeroize::Zeroizing;

const T0: u64 = 1_790_000_000;

fn record(key: u8) -> PairingRecord {
    PairingRecord {
        pairing_id: [0x42; 16],
        key: Zeroizing::new([key; 32]),
        ext_name: "OnePass".into(),
        browser: "Chromium".into(),
        created_at: T0,
    }
}

fn lookup(key: u8) -> impl Fn(&[u8; 16]) -> Option<Zeroizing<[u8; 32]>> {
    move |id| (*id == [0x42; 16]).then(|| Zeroizing::new([key; 32]))
}

fn handshake_parts(ext_key: u8, host_key: u8) -> (ExtPending, PendingSession, Welcome) {
    let (ext, hello) = session::ext_hello(&record(ext_key)).unwrap();
    let (pending, welcome) = session::host_accept(hello, lookup(host_key)).unwrap();
    (ext, pending, welcome)
}

/// (host channel, extension channel)
fn connect() -> (Channel, Channel) {
    let (ext, pending, welcome) = handshake_parts(7, 7);
    let (ext_ch, finish) = ext.on_welcome(welcome, T0).unwrap();
    let host_ch = pending.on_finish(finish, T0).unwrap();
    (host_ch, ext_ch)
}

fn msg(env: Envelope) -> Msg {
    match env {
        Envelope::Msg(m) => m,
        other => panic!("not a msg: {other:?}"),
    }
}

#[test]
fn session_happy_path_both_directions() {
    let (mut host, mut ext) = connect();
    assert_eq!(host.session_id(), ext.session_id());
    for i in 0..3u8 {
        let m = msg(ext.seal(&[b'q', i]).unwrap());
        assert_eq!(m.c, u64::from(i));
        assert_eq!(&*host.open(&m).unwrap(), &[b'q', i]);
        let m = msg(host.seal(&[b'r', i]).unwrap());
        assert_eq!(m.c, u64::from(i));
        assert_eq!(&*ext.open(&m).unwrap(), &[b'r', i]);
    }
    // Ciphertext is not the plaintext, and carries a 16 byte tag.
    let m = msg(ext.seal(b"secret").unwrap());
    assert_eq!(m.d.0.len(), 6 + 16);
    assert_ne!(&m.d.0[..6], b"secret");
    // Empty plaintext is fine.
    let m2 = msg(host.seal(b"").unwrap());
    assert_eq!(host.open(&m).unwrap().as_slice(), b"secret");
    assert!(ext.open(&m2).unwrap().is_empty());
}

#[test]
fn unknown_pairing() {
    let (_, hello) = session::ext_hello(&record(7)).unwrap();
    let r = session::host_accept(hello, |_| None);
    assert_eq!(r.map(|_| ()).unwrap_err(), BridgeError::UnknownPairing);
}

#[test]
fn wrong_pairing_key_fails_mac() {
    let (ext, _pending, welcome) = handshake_parts(7, 8);
    assert_eq!(
        ext.on_welcome(welcome, T0).map(|_| ()).unwrap_err(),
        BridgeError::BadMac
    );
}

#[test]
fn welcome_mac_flip() {
    let (ext, _pending, mut welcome) = handshake_parts(7, 7);
    welcome.mac.0[10] ^= 4;
    assert_eq!(
        ext.on_welcome(welcome, T0).map(|_| ()).unwrap_err(),
        BridgeError::BadMac
    );
    // Any other welcome field is bound by the transcript too.
    let (ext, _pending, mut welcome) = handshake_parts(7, 7);
    welcome.n.0[0] ^= 1;
    assert!(ext.on_welcome(welcome, T0).is_err());
    let (ext, _pending, mut welcome) = handshake_parts(7, 7);
    welcome.session_id.0[0] ^= 1;
    assert!(ext.on_welcome(welcome, T0).is_err());
}

#[test]
fn finish_mac_flip() {
    let (ext, pending, welcome) = handshake_parts(7, 7);
    let (_, Finish { mut mac }) = ext.on_welcome(welcome, T0).unwrap();
    mac.0[31] ^= 1;
    assert_eq!(
        pending
            .on_finish(Finish { mac }, T0)
            .map(|_| ())
            .unwrap_err(),
        BridgeError::BadMac
    );
}

#[test]
fn replayed_frame_closes() {
    let (mut host, mut ext) = connect();
    let m = msg(ext.seal(b"one").unwrap());
    host.open(&m).unwrap();
    assert_eq!(host.open(&m).unwrap_err(), BridgeError::Replay);
    assert_eq!(
        host.open(&msg(ext.seal(b"two").unwrap())).unwrap_err(),
        BridgeError::BadFrame("closed")
    );
}

#[test]
fn skipped_counter_closes() {
    let (mut host, mut ext) = connect();
    let _lost = ext.seal(b"zero").unwrap();
    let m1 = msg(ext.seal(b"one").unwrap());
    assert_eq!(host.open(&m1).unwrap_err(), BridgeError::Replay);
    assert!(host.seal(b"x").is_err());
}

#[test]
fn tampered_ciphertext_closes() {
    let (mut host, mut ext) = connect();
    let good = msg(ext.seal(b"payload").unwrap());
    for i in [0, good.d.0.len() - 1] {
        let (mut host, mut ext) = connect();
        let mut m = msg(ext.seal(b"payload").unwrap());
        m.d.0[i] ^= 1;
        assert_eq!(host.open(&m).unwrap_err(), BridgeError::BadMac);
    }
    // Truncated below the tag length.
    let short = Msg {
        c: 0,
        d: onepass_bridge::wire::B64Vec(vec![0u8; 5]),
    };
    assert!(host.open(&short).is_err());
    // Even the genuine frame no longer opens.
    assert_eq!(
        host.open(&good).unwrap_err(),
        BridgeError::BadFrame("closed")
    );
    let _ = ext.seal(b"").unwrap();
}

#[test]
fn reflected_frame_rejected() {
    // A frame the host sent, reflected back to the host, does not open:
    // each direction has its own key and its own byte in the AAD.
    let (mut host, _ext) = connect();
    let m = msg(host.seal(b"to ext").unwrap());
    assert!(host.open(&m).is_err());
}

#[test]
fn closed_channel_stays_closed() {
    let (mut host, mut ext) = connect();
    let mut m = msg(ext.seal(b"x").unwrap());
    m.d.0[0] ^= 1;
    assert!(host.open(&m).is_err());
    for _ in 0..3 {
        assert_eq!(
            host.seal(b"y").unwrap_err(),
            BridgeError::BadFrame("closed")
        );
        let m = msg(ext.seal(b"z").unwrap());
        assert_eq!(host.open(&m).unwrap_err(), BridgeError::BadFrame("closed"));
    }
    assert!(host.is_closed());
}

#[test]
fn replayed_hello_yields_different_keys() {
    let (ext, hello) = session::ext_hello(&record(7)).unwrap();
    let replay: Hello = hello.clone();
    let (pending1, welcome1) = session::host_accept(hello, lookup(7)).unwrap();
    let (pending2, welcome2) = session::host_accept(replay, lookup(7)).unwrap();
    assert_ne!(welcome1.n, welcome2.n);
    assert_ne!(welcome1.session_id, welcome2.session_id);
    assert_ne!(welcome1.mac, welcome2.mac);

    // The genuine extension completes session 1 only.
    let (mut ext_ch, finish) = ext.on_welcome(welcome1, T0).unwrap();
    // An attacker replaying the hello cannot finish session 2: the
    // extension's finish of session 1 does not verify there.
    assert_eq!(
        pending2
            .on_finish(finish.clone(), T0)
            .map(|_| ())
            .unwrap_err(),
        BridgeError::BadMac
    );
    let mut host_ch = pending1.on_finish(finish, T0).unwrap();
    let m = msg(ext_ch.seal(b"hi").unwrap());
    assert_eq!(&*host_ch.open(&m).unwrap(), b"hi");
}

#[test]
fn frames_do_not_cross_sessions() {
    let (mut host_a, _ext_a) = connect();
    let (_host_b, mut ext_b) = connect();
    let m = msg(ext_b.seal(b"x").unwrap());
    assert_eq!(host_a.open(&m).unwrap_err(), BridgeError::BadMac);
}

#[test]
fn idle_expiry_600s() {
    assert_eq!(IDLE_TIMEOUT_SECS, 600);
    let (mut host, _ext) = connect();
    assert!(!host.expired(T0));
    assert!(!host.expired(T0 + 600));
    assert!(host.expired(T0 + 601));
    host.touch(T0 + 500);
    assert!(!host.expired(T0 + 1100));
    assert!(host.expired(T0 + 1101));
    // A clock going backwards never expires a session by itself.
    assert!(!host.expired(T0));
}

#[test]
fn welcome_wire_round_trip() {
    let (_ext, hello) = session::ext_hello(&record(7)).unwrap();
    let env = Envelope::Hello(hello.clone());
    assert_eq!(
        onepass_bridge::wire::parse(&onepass_bridge::wire::to_bytes(&env)).unwrap(),
        env
    );
    let (_, welcome) = session::host_accept(hello, lookup(7)).unwrap();
    let env = Envelope::Welcome(welcome);
    assert_eq!(
        onepass_bridge::wire::parse(&onepass_bridge::wire::to_bytes(&env)).unwrap(),
        env
    );
}
