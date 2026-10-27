//! Pairing protocol (spec 6.4), both roles in Rust.

use onepass_bridge::BridgeError;
use onepass_bridge::pairing::{ExtPairing, HostPairing, PAIRING_TIMEOUT_SECS, PairingRecord};
use onepass_bridge::wire::{self, Envelope, PairConfirm, PairDone};

const T0: u64 = 1_790_000_000;

fn ext() -> (ExtPairing, wire::PairHello) {
    ExtPairing::start("OnePass", "Chromium", T0).unwrap()
}

/// Full run up to the host record and the extension record.
fn run() -> (PairingRecord, PairingRecord) {
    let (mut e, hello) = ext();
    let (mut h, offer) = HostPairing::start(hello, T0).unwrap();
    let (reveal, sas_e) = e.on_offer(offer).unwrap();
    let sas_h = h.on_reveal(reveal, T0 + 1).unwrap();
    assert_eq!(sas_e, sas_h);
    let done = h.approve(T0 + 2).unwrap();
    e.on_done(done, T0 + 2).unwrap();
    let (confirm, rec_e) = e.confirm(T0 + 3).unwrap();
    let rec_h = h.on_confirm(confirm, T0 + 3).unwrap();
    (rec_h, rec_e)
}

#[test]
fn pairing_happy_path_same_sas_same_key() {
    let (rec_h, rec_e) = run();
    assert_eq!(rec_h.pairing_id, rec_e.pairing_id);
    assert_eq!(*rec_h.key, *rec_e.key);
    assert_ne!(*rec_h.key, [0u8; 32]);
    assert_eq!(rec_h.ext_name, "OnePass");
    assert_eq!(rec_h.browser, "Chromium");
    assert_eq!(rec_h.created_at, T0 + 3);
    // Two pairings never share a key or an id.
    let (other, _) = run();
    assert_ne!(*other.key, *rec_h.key);
    assert_ne!(other.pairing_id, rec_h.pairing_id);
}

#[test]
fn sas_is_six_digits() {
    let (mut e, hello) = ext();
    let (_h, offer) = HostPairing::start(hello, T0).unwrap();
    let (_, sas) = e.on_offer(offer).unwrap();
    let s = sas.0.as_bytes();
    assert_eq!(s.len(), 7);
    assert_eq!(s[3], b' ');
    assert!(
        s.iter()
            .enumerate()
            .all(|(i, c)| i == 3 || c.is_ascii_digit())
    );
}

#[test]
fn wrong_commit_rejected() {
    let (mut e, hello) = ext();
    let (mut h, offer) = HostPairing::start(hello, T0).unwrap();
    let (mut reveal, _) = e.on_offer(offer).unwrap();
    reveal.n.0[0] ^= 1;
    assert_eq!(h.on_reveal(reveal, T0), Err(BridgeError::BadMac));
    // The host state is wiped: no way to continue.
    assert!(h.approve(T0).is_err());
}

#[test]
fn swapped_public_key_breaks_commit() {
    let (mut e, hello) = ext();
    let (mut h, offer) = HostPairing::start(hello, T0).unwrap();
    let (mut reveal, _) = e.on_offer(offer).unwrap();
    reveal.pk.0[5] ^= 0x10;
    assert!(h.on_reveal(reveal, T0).is_err());
}

#[test]
fn host_mac_flip_rejected_by_ext() {
    let (mut e, hello) = ext();
    let (mut h, offer) = HostPairing::start(hello, T0).unwrap();
    let (reveal, _) = e.on_offer(offer).unwrap();
    h.on_reveal(reveal, T0).unwrap();
    let PairDone { mut mac } = h.approve(T0).unwrap();
    mac.0[31] ^= 1;
    assert_eq!(e.on_done(PairDone { mac }, T0), Err(BridgeError::BadMac));
    // No confirmation can be produced afterwards.
    assert!(e.confirm(T0).is_err());
}

#[test]
fn ext_mac_flip_rejected_by_host() {
    let (mut e, hello) = ext();
    let (mut h, offer) = HostPairing::start(hello, T0).unwrap();
    let (reveal, _) = e.on_offer(offer).unwrap();
    h.on_reveal(reveal, T0).unwrap();
    let done = h.approve(T0).unwrap();
    e.on_done(done, T0).unwrap();
    let (PairConfirm { mut mac }, _) = e.confirm(T0).unwrap();
    mac.0[0] ^= 0x80;
    assert_eq!(
        h.on_confirm(PairConfirm { mac }, T0).map(|_| ()),
        Err(BridgeError::BadMac)
    );
}

#[test]
fn expired_after_120s() {
    // Each step past the deadline fails.
    let (mut e, hello) = ext();
    let (mut h, offer) = HostPairing::start(hello, T0).unwrap();
    let (reveal, _) = e.on_offer(offer).unwrap();
    let late = T0 + PAIRING_TIMEOUT_SECS + 1;
    assert_eq!(PAIRING_TIMEOUT_SECS, 120);
    assert_eq!(h.on_reveal(reveal, late), Err(BridgeError::Expired));

    // Exactly 120 s is still accepted, approval after the deadline is not.
    let (mut e, hello) = ext();
    let (mut h, offer) = HostPairing::start(hello, T0).unwrap();
    let (reveal, _) = e.on_offer(offer).unwrap();
    h.on_reveal(reveal, T0 + PAIRING_TIMEOUT_SECS).unwrap();
    assert_eq!(h.approve(late), Err(BridgeError::Expired));

    // Confirmation after the deadline: no record.
    let (mut e, hello) = ext();
    let (mut h, offer) = HostPairing::start(hello, T0).unwrap();
    let (reveal, _) = e.on_offer(offer).unwrap();
    h.on_reveal(reveal, T0).unwrap();
    let done = h.approve(T0).unwrap();
    e.on_done(done, T0).unwrap();
    let (confirm, _) = e.confirm(T0).unwrap();
    assert_eq!(
        h.on_confirm(confirm, late).map(|_| ()),
        Err(BridgeError::Expired)
    );

    // The extension side enforces the same deadline.
    let (mut e, hello) = ext();
    let (mut h, offer) = HostPairing::start(hello, T0).unwrap();
    let (reveal, _) = e.on_offer(offer).unwrap();
    h.on_reveal(reveal, T0).unwrap();
    let done = h.approve(T0).unwrap();
    assert_eq!(e.on_done(done, late), Err(BridgeError::Expired));
}

#[test]
fn confirm_before_approve_rejected() {
    let (mut e, hello) = ext();
    let (mut h, offer) = HostPairing::start(hello, T0).unwrap();
    let (reveal, _) = e.on_offer(offer).unwrap();
    h.on_reveal(reveal, T0).unwrap();
    // Forged confirmation before the user approved on the host.
    let forged = PairConfirm {
        mac: wire::B64([0u8; 32]),
    };
    assert!(h.on_confirm(forged, T0).is_err());
    // The extension cannot confirm before a verified pair_done either.
    assert!(e.confirm(T0).is_err());
}

#[test]
fn reveal_twice_rejected() {
    let (mut e, hello) = ext();
    let (mut h, offer) = HostPairing::start(hello, T0).unwrap();
    let (reveal, _) = e.on_offer(offer).unwrap();
    h.on_reveal(reveal.clone(), T0).unwrap();
    assert!(h.on_reveal(reveal, T0).is_err());
}

#[test]
fn hello_with_bad_names_rejected() {
    let (_, mut hello) = ext();
    hello.ext_name = String::new();
    assert!(HostPairing::start(hello, T0).is_err());
    let (_, mut hello) = ext();
    hello.browser = "x".repeat(1000);
    assert!(HostPairing::start(hello, T0).is_err());
}

#[test]
fn version_2_rejected() {
    let (_, hello) = ext();
    let bytes = wire::to_bytes(&Envelope::PairHello(hello));
    let mut v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["v"], 1);
    v["v"] = 2.into();
    let bad = serde_json::to_vec(&v).unwrap();
    assert_eq!(wire::parse(&bad).map(|_| ()), Err(BridgeError::Version));
    v.as_object_mut().unwrap().remove("v");
    let bad = serde_json::to_vec(&v).unwrap();
    assert_eq!(wire::parse(&bad).map(|_| ()), Err(BridgeError::Version));
}

#[test]
fn wire_round_trip_and_exact_shape() {
    let (mut e, hello) = ext();
    let env = Envelope::PairHello(hello);
    let bytes = wire::to_bytes(&env);
    assert_eq!(wire::parse(&bytes).unwrap(), env);
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["t"], "pair_hello");
    assert_eq!(v["ext_name"], "OnePass");
    // Standard base64 with padding: 32 bytes -> 44 characters ending in '='.
    let commit = v["commit"].as_str().unwrap();
    assert_eq!(commit.len(), 44);
    assert!(commit.ends_with('='));

    let (_h, offer) = HostPairing::start(
        match env {
            Envelope::PairHello(h) => h,
            _ => unreachable!(),
        },
        T0,
    )
    .unwrap();
    let env = Envelope::PairOffer(offer.clone());
    assert_eq!(wire::parse(&wire::to_bytes(&env)).unwrap(), env);
    let (reveal, _) = e.on_offer(offer).unwrap();
    let env = Envelope::PairReveal(reveal);
    assert_eq!(wire::parse(&wire::to_bytes(&env)).unwrap(), env);

    for (env, t) in [
        (Envelope::PairSas, "pair_sas"),
        (Envelope::PairOk, "pair_ok"),
    ] {
        let bytes = wire::to_bytes(&env);
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v, serde_json::json!({"v": 1, "t": t}));
        assert_eq!(wire::parse(&bytes).unwrap(), env);
    }
}

#[test]
fn wire_rejects_malformed_without_panic() {
    let cases: &[&[u8]] = &[
        b"",
        b"null",
        b"[]",
        b"{\"v\":1}",
        b"{\"v\":1,\"t\":\"nope\"}",
        b"{\"v\":1,\"t\":\"pair_done\"}",
        b"{\"v\":1,\"t\":\"pair_done\",\"mac\":\"AAAA\"}",
        b"{\"v\":1,\"t\":\"pair_done\",\"mac\":\"not base64!\"}",
        b"{\"v\":1,\"t\":\"pair_done\",\"mac\":7}",
        b"{\"v\":\"1\",\"t\":\"pair_ok\"}",
        b"{\"v\":1,\"t\":\"msg\",\"c\":-1,\"d\":\"\"}",
        b"\xff\xfe",
    ];
    for c in cases {
        assert!(wire::parse(c).is_err(), "{:?}", String::from_utf8_lossy(c));
    }
    // Unpadded base64 is refused: the format is padded standard base64.
    let mac = "A".repeat(43);
    let s = format!("{{\"v\":1,\"t\":\"pair_done\",\"mac\":\"{mac}\"}}");
    assert!(wire::parse(s.as_bytes()).is_err());
}

#[test]
fn mitm_two_sessions_get_independent_sas() {
    // A relay pairs with the extension as a host and with the host as an
    // extension, substituting its own public keys on both legs.
    let (mut e, hello_e) = ext();
    let (mut relay_host, offer_relay) = HostPairing::start(hello_e, T0).unwrap();
    let (mut relay_ext, hello_relay) = ExtPairing::start("OnePass", "Chromium", T0).unwrap();
    let (mut h, offer_h) = HostPairing::start(hello_relay, T0).unwrap();

    let (reveal_e, sas_e) = e.on_offer(offer_relay).unwrap();
    let (reveal_relay, sas_relay_ext) = relay_ext.on_offer(offer_h).unwrap();
    let sas_relay_host = relay_host.on_reveal(reveal_e, T0).unwrap();
    let sas_h = h.on_reveal(reveal_relay, T0).unwrap();
    assert_eq!(sas_e, sas_relay_host);
    assert_eq!(sas_h, sas_relay_ext);
    // The user compares sas_e (extension screen) with sas_h (app screen).
    // They are independent: equal only with probability 1e-6.
    assert_ne!(sas_e, sas_h);

    // Keys of the two legs differ.
    let done = relay_host.approve(T0).unwrap();
    e.on_done(done, T0).unwrap();
    let (_, rec_e) = e.confirm(T0).unwrap();
    let done = h.approve(T0).unwrap();
    relay_ext.on_done(done, T0).unwrap();
    let (confirm, _) = relay_ext.confirm(T0).unwrap();
    let rec_h = h.on_confirm(confirm, T0).unwrap();
    assert_ne!(*rec_e.key, *rec_h.key);

    // Forwarding the extension's reveal unchanged to the real host fails
    // the commitment the relay made to the host.
    let (mut e2, hello_e2) = ext();
    let (_relay2, offer2) = HostPairing::start(hello_e2, T0).unwrap();
    let (reveal_e2, _) = e2.on_offer(offer2).unwrap();
    let (_relay_ext2, hello_relay2) = ext();
    let (mut h2, _) = HostPairing::start(hello_relay2, T0).unwrap();
    assert_eq!(h2.on_reveal(reveal_e2, T0), Err(BridgeError::BadMac));
}

#[test]
fn record_debug_hides_key() {
    let (rec, _) = run();
    let s = format!("{rec:?}");
    assert!(!s.contains(&format!("{:?}", *rec.key)), "{s}");
    assert!(s.contains("key: \"**\""), "{s}");
}
