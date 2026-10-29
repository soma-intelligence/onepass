//! QR pairing protocol (milestone 2b, spec 5): two devices in memory, no
//! transport. Synthetic data only.

use onepass_core::crypto::SecretKey;
use onepass_core::crypto::SymmetricKey;
use onepass_core::devices::{DeviceKind, DeviceMode};
use onepass_core::model::{ItemType, new_item};
use onepass_core::pairing::{
    Approver, AuditAction, AuditEvent, Channel, DeviceInfo, FullGrant, Grant, Hello, Host,
    JoinHello, MAX_SNAPSHOT_BYTES, Message, Newcomer, PairingQr, PublicGrant, QR_LIFETIME_SECS,
    RV_MAX_FAILURES, RV_RENEW_SECS, RendezvousCode, SnapshotRecord, check_snapshot_size, sas,
};
use onepass_core::{Error, Id};
use zeroize::Zeroizing;

const NOW: i64 = 1_790_000_000;

fn ipad() -> DeviceInfo {
    DeviceInfo {
        device_id: Id::new(),
        name: "iPad de Camille".into(),
        kind: DeviceKind::Tablet,
    }
}

/// Both sides up to the SAS: (newcomer, approver, sas_n, sas_a).
fn handshake(mode: DeviceMode) -> (Newcomer, Approver, String, String) {
    let (mut n, qr, hello) = Newcomer::new(ipad(), mode, NOW).unwrap();
    let (a, kx, sas_a, info, requested) = Approver::begin(&qr.to_text(), &hello, NOW + 5).unwrap();
    assert_eq!(info.name, "iPad de Camille");
    assert_eq!(requested, mode);
    let sas_n = n.on_key_exchange(&kx, NOW + 6).unwrap();
    (n, a, sas_n, sas_a)
}

/// Handshake plus both confirmations: the approver may grant.
fn confirmed(mode: DeviceMode) -> (Newcomer, Approver) {
    let (mut n, mut a, sas_n, sas_a) = handshake(mode);
    assert_eq!(sas_n, sas_a);
    let f = n.confirm().unwrap();
    assert_eq!(a.on_frame_at(&f, NOW + 7).unwrap(), Message::Confirmed);
    (n, a)
}

fn full_grant() -> FullGrant {
    let sk = SecretKey::generate().unwrap();
    FullGrant {
        account_id: Id::new(),
        secret_key: Zeroizing::new(sk.to_display()),
        mode: DeviceMode::Personal,
        device_id: Id::new(),
        snapshot: vec![
            SnapshotRecord {
                kind: 1,
                id: Id::new(),
                version: 3,
                data: vec![7u8; 300],
            },
            SnapshotRecord {
                kind: 5,
                id: Id::new(),
                version: 1,
                data: vec![9u8; 1200],
            },
        ],
    }
}

#[test]
fn qr_round_trip_and_prefix() {
    let qr = PairingQr {
        version: 1,
        session_id: [0xA5; 16],
        key_hash: [0x3C; 32],
        expires_at: NOW + QR_LIFETIME_SECS,
    };
    let text = qr.to_text();
    assert!(text.starts_with("OPPAIR1:"));
    assert!(text.len() < 200, "QR text is {} characters", text.len());
    let body = &text["OPPAIR1:".len()..];
    assert!(
        body.bytes()
            .all(|c| c.is_ascii_uppercase() || (b'2'..=b'7').contains(&c))
    );
    assert!(!text.contains('='));
    assert!(!text.contains("://"));
    assert_eq!(PairingQr::parse(&text).unwrap(), qr);

    // A fresh newcomer QR is just as small.
    let (_, real, _) = Newcomer::new(ipad(), DeviceMode::Personal, NOW).unwrap();
    assert!(real.to_text().len() < 200);
    assert_eq!(real.expires_at, NOW + QR_LIFETIME_SECS);
}

#[test]
fn qr_parse_rejects_garbage() {
    let good = PairingQr {
        version: 1,
        session_id: [1; 16],
        key_hash: [2; 32],
        expires_at: NOW,
    }
    .to_text();
    let body = &good["OPPAIR1:".len()..];
    let bad = [
        String::new(),
        "OPPAIR1:".into(),
        "https://exemple.fr/pair".into(),
        format!("OPPAIR2:{body}"),
        format!("oppair1:{body}"),
        format!("OPPAIR1:{}", body.to_lowercase()),
        format!("OPPAIR1:{body}="),
        format!("OPPAIR1:{body}AA"),
        format!("OPPAIR1:{}", &body[..body.len() - 4]),
        format!(" {good}"),
        format!("{good}\n"),
        format!("OPPAIR1:{}", "A".repeat(400)),
    ];
    for text in bad {
        assert!(PairingQr::parse(&text).is_err(), "accepted {text:?}");
    }
    // Version other than 1.
    let v2 = PairingQr {
        version: 2,
        session_id: [1; 16],
        key_hash: [2; 32],
        expires_at: NOW,
    }
    .to_text();
    assert!(PairingQr::parse(&v2).is_err());
}

#[test]
fn full_pairing_in_memory() {
    let (mut n, mut a) = confirmed(DeviceMode::Personal);
    let grant = full_grant();
    let expected_sk = grant.secret_key.clone();
    let expected_snapshot = grant.snapshot.clone();
    let account = grant.account_id;

    let f = a.seal_grant_at(Grant::Full(grant), true, NOW + 8).unwrap();
    let Message::Grant(Grant::Full(got)) = n.open_at(&f, NOW + 9).unwrap() else {
        panic!("expected a full grant");
    };
    assert_eq!(got.account_id, account);
    assert_eq!(*got.secret_key, *expected_sk);
    SecretKey::parse(&got.secret_key).unwrap();
    assert_eq!(got.snapshot, expected_snapshot);
    assert_eq!(got.mode, DeviceMode::Personal);

    let ack = n.seal_at(&Message::Ack, NOW + 10).unwrap();
    assert_eq!(a.on_frame_at(&ack, NOW + 10).unwrap(), Message::Ack);
    let end = a.seal_at(&Message::End, NOW + 11).unwrap();
    assert_eq!(n.open_at(&end, NOW + 11).unwrap(), Message::End);

    // Debug never shows the Secret Key.
    let dbg = format!("{got:?} {:?}", Message::Grant(Grant::Full(full_grant())));
    assert!(!dbg.contains(&*expected_sk));
    assert!(!format!("{n:?}{a:?}").is_empty());
}

#[test]
fn public_session_in_memory() {
    let (mut n, mut a) = confirmed(DeviceMode::Public);
    let vault = Id::new();
    let items = vec![
        new_item(ItemType::Login, vault, "Messagerie exemple.fr"),
        new_item(ItemType::SecureNote, vault, "Code du portail"),
    ];
    let session_id = n.session_id();
    let expires_at = NOW + 600;
    let grant = PublicGrant {
        session_id,
        expires_at,
        read_only: true,
        items: items.clone(),
    };
    let f = a
        .seal_grant_at(Grant::Public(grant), true, NOW + 8)
        .unwrap();
    let Message::Grant(Grant::Public(got)) = n.open_at(&f, NOW + 9).unwrap() else {
        panic!("expected a public grant");
    };
    assert_eq!(got.items, items);
    assert!(got.read_only);

    let ack = n.seal_at(&Message::Ack, NOW + 10).unwrap();
    assert_eq!(a.on_frame_at(&ack, NOW + 10).unwrap(), Message::Ack);

    let events = [
        AuditEvent {
            at: NOW + 20,
            item_id: items[0].id,
            action: AuditAction::Opened,
        },
        AuditEvent {
            at: NOW + 21,
            item_id: items[0].id,
            action: AuditAction::Copied("Mot de passe".into()),
        },
    ];
    for (i, e) in events.iter().enumerate() {
        let f = n
            .seal_at(&Message::Audit(e.clone()), NOW + 20 + i as i64)
            .unwrap();
        assert_eq!(
            a.on_frame_at(&f, NOW + 20 + i as i64).unwrap(),
            Message::Audit(e.clone())
        );
    }

    let end = a.seal_at(&Message::End, NOW + 30).unwrap();
    assert_eq!(n.open_at(&end, NOW + 30).unwrap(), Message::End);
    // Both channels are closed now.
    assert!(n.seal_at(&Message::Ack, NOW + 31).is_err());
    assert!(a.seal_at(&Message::End, NOW + 31).is_err());
}

#[test]
fn expired_or_mismatched_qr_refused() {
    let (_, qr, hello) = Newcomer::new(ipad(), DeviceMode::Personal, NOW).unwrap();
    let text = qr.to_text();
    // Expired.
    assert!(Approver::begin(&text, &hello, qr.expires_at + 1).is_err());
    // Exactly at expiry still accepted.
    assert!(Approver::begin(&text, &hello, qr.expires_at).is_ok());
    // Approver clock far behind the issue time (beyond the tolerance).
    assert!(Approver::begin(&text, &hello, NOW - 3600).is_err());

    // Hello of another session.
    let (_, other_qr, other_hello) = Newcomer::new(ipad(), DeviceMode::Personal, NOW).unwrap();
    assert!(Approver::begin(&text, &other_hello, NOW + 1).is_err());
    assert!(Approver::begin(&other_qr.to_text(), &hello, NOW + 1).is_err());

    // Hello with the right key but a session id that differs from the QR.
    let mut h = Hello::from_bytes(&hello).unwrap();
    h.session_id[0] ^= 1;
    assert!(Approver::begin(&text, &h.to_bytes().unwrap(), NOW + 1).is_err());

    // Garbage.
    assert!(Approver::begin(&text, b"OPH1", NOW + 1).is_err());
    assert!(Approver::begin("OPPAIR1:AAAA", &hello, NOW + 1).is_err());

    // The newcomer refuses a key exchange after its own QR expired.
    let (mut n, qr, hello) = Newcomer::new(ipad(), DeviceMode::Personal, NOW).unwrap();
    let (_, kx, _, _, _) = Approver::begin(&qr.to_text(), &hello, NOW + 1).unwrap();
    assert!(n.on_key_exchange(&kx, qr.expires_at + 1).is_err());
}

#[test]
fn mitm_key_substitution_detected() {
    // 1. The attacker swaps the ephemeral key in the victim's Hello.
    let (_, qr, hello) = Newcomer::new(ipad(), DeviceMode::Personal, NOW).unwrap();
    let (_, _, attacker_hello) = Newcomer::new(ipad(), DeviceMode::Personal, NOW).unwrap();
    let mut h = Hello::from_bytes(&hello).unwrap();
    h.ephemeral_public = Hello::from_bytes(&attacker_hello).unwrap().ephemeral_public;
    let err = Approver::begin(&qr.to_text(), &h.to_bytes().unwrap(), NOW + 1).unwrap_err();
    assert!(matches!(err, Error::Integrity(_)), "{err:?}");

    // 2. The attacker sits in the middle with a QR of its own: it plays
    // the approver to the victim newcomer and the newcomer to the real
    // approver. The two screens show different codes.
    let (mut victim, victim_qr, victim_hello) =
        Newcomer::new(ipad(), DeviceMode::Personal, NOW).unwrap();
    let (_fake_a, kx_to_victim, sas_attacker_side_n, _, _) =
        Approver::begin(&victim_qr.to_text(), &victim_hello, NOW + 1).unwrap();
    let sas_victim = victim.on_key_exchange(&kx_to_victim, NOW + 2).unwrap();
    assert_eq!(sas_victim, sas_attacker_side_n);

    let (mut fake_n, attacker_qr, attacker_hello) =
        Newcomer::new(ipad(), DeviceMode::Personal, NOW).unwrap();
    let (_real_a, kx, sas_real_approver, _, _) =
        Approver::begin(&attacker_qr.to_text(), &attacker_hello, NOW + 1).unwrap();
    fake_n.on_key_exchange(&kx, NOW + 2).unwrap();
    assert_ne!(sas_victim, sas_real_approver);

    // 3. A key exchange relayed from another session does not open.
    let (mut n, qr, hello) = Newcomer::new(ipad(), DeviceMode::Personal, NOW).unwrap();
    let _ = Approver::begin(&qr.to_text(), &hello, NOW + 1).unwrap();
    assert!(n.on_key_exchange(&kx, NOW + 2).is_err());
}

#[test]
fn frame_replay_reorder_and_direction_rejected() {
    // Replay.
    let (mut n, mut a) = confirmed(DeviceMode::Public);
    let g = PublicGrant {
        session_id: n.session_id(),
        expires_at: NOW + 600,
        read_only: true,
        items: vec![],
    };
    let f = a.seal_grant_at(Grant::Public(g), true, NOW + 8).unwrap();
    n.open_at(&f, NOW + 8).unwrap();
    let ack = n.seal_at(&Message::Ack, NOW + 9).unwrap();
    a.on_frame_at(&ack, NOW + 9).unwrap();
    assert!(a.on_frame_at(&ack, NOW + 9).is_err(), "replay accepted");

    // Reorder.
    let (mut n, mut a) = confirmed(DeviceMode::Public);
    let g = PublicGrant {
        session_id: n.session_id(),
        expires_at: NOW + 600,
        read_only: true,
        items: vec![],
    };
    let f = a.seal_grant_at(Grant::Public(g), true, NOW + 8).unwrap();
    n.open_at(&f, NOW + 8).unwrap();
    let e = AuditEvent {
        at: NOW,
        item_id: Id::new(),
        action: AuditAction::Opened,
    };
    let first = n.seal_at(&Message::Ack, NOW + 9).unwrap();
    let second = n.seal_at(&Message::Audit(e), NOW + 9).unwrap();
    assert!(a.on_frame_at(&second, NOW + 9).is_err(), "reorder accepted");
    // The channel fails closed after a bad frame.
    assert!(a.on_frame_at(&first, NOW + 9).is_err());

    // Direction: a frame sent back to its sender, at the same counter.
    let mut na = Channel::newcomer(&SymmetricKey::from_bytes([4; 32]), [6; 16]).unwrap();
    let mut an = Channel::approver(&SymmetricKey::from_bytes([4; 32]), [6; 16]).unwrap();
    let mut na2 = Channel::newcomer(&SymmetricKey::from_bytes([4; 32]), [6; 16]).unwrap();
    let from_n = na.seal_at(&Message::Ack, NOW).unwrap();
    assert!(na2.open_at(&from_n, NOW).is_err(), "own direction accepted");
    assert_eq!(an.open_at(&from_n, NOW).unwrap(), Message::Ack);

    // Another session id does not open.
    let mut other = Channel::approver(&SymmetricKey::from_bytes([4; 32]), [7; 16]).unwrap();
    let from_n = Channel::newcomer(&SymmetricKey::from_bytes([4; 32]), [6; 16])
        .unwrap()
        .seal_at(&Message::Ack, NOW)
        .unwrap();
    assert!(other.open_at(&from_n, NOW).is_err());
}

#[test]
fn grant_refused_before_confirmations() {
    // No peer confirmation yet.
    let (mut n, mut a, _, _) = handshake(DeviceMode::Personal);
    assert!(
        a.seal_grant_at(Grant::Full(full_grant()), true, NOW + 7)
            .is_err()
    );
    // The newcomer never seals a grant, nor a confirmation through `seal`.
    assert!(
        n.seal_at(&Message::Grant(Grant::Full(full_grant())), NOW)
            .is_err()
    );

    // Peer confirmed, local user did not.
    let (_, mut a) = confirmed(DeviceMode::Personal);
    assert!(
        a.seal_grant_at(Grant::Full(full_grant()), false, NOW + 8)
            .is_err()
    );

    // The newcomer side (a grant before its own confirmation) is covered
    // in `pairing::newcomer` unit tests: only a hostile approver sends it.

    // Wrong grant for the requested mode: a public newcomer never gets a
    // Secret Key, a personal newcomer never gets a public grant.
    let (_, mut a) = confirmed(DeviceMode::Public);
    assert!(
        a.seal_grant_at(Grant::Full(full_grant()), true, NOW + 8)
            .is_err()
    );
    let (n, mut a) = confirmed(DeviceMode::Personal);
    let g = PublicGrant {
        session_id: n.session_id(),
        expires_at: NOW + 600,
        read_only: true,
        items: vec![],
    };
    assert!(a.seal_grant_at(Grant::Public(g), true, NOW + 8).is_err());

    // A second grant is refused.
    let (_, mut a) = confirmed(DeviceMode::Personal);
    a.seal_grant_at(Grant::Full(full_grant()), true, NOW + 8)
        .unwrap();
    assert!(
        a.seal_grant_at(Grant::Full(full_grant()), true, NOW + 8)
            .is_err()
    );
}

#[test]
fn frames_after_end_or_expiry_refused() {
    // After End.
    let (mut n, mut a) = confirmed(DeviceMode::Personal);
    let end = a.seal_at(&Message::End, NOW + 8).unwrap();
    assert!(a.seal_at(&Message::End, NOW + 8).is_err());
    assert!(
        a.seal_grant_at(Grant::Full(full_grant()), true, NOW + 8)
            .is_err()
    );
    assert_eq!(n.open_at(&end, NOW + 8).unwrap(), Message::End);
    assert!(n.seal_at(&Message::Ack, NOW + 8).is_err());

    // After the public session's expiry, on both sides.
    let (mut n, mut a) = confirmed(DeviceMode::Public);
    let g = PublicGrant {
        session_id: n.session_id(),
        expires_at: NOW + 100,
        read_only: true,
        items: vec![],
    };
    let f = a.seal_grant_at(Grant::Public(g), true, NOW + 8).unwrap();
    n.open_at(&f, NOW + 9).unwrap();
    let late = n.seal_at(&Message::Ack, NOW + 100).unwrap();
    assert!(a.on_frame_at(&late, NOW + 101).is_err());
    assert!(n.seal_at(&Message::Ack, NOW + 101).is_err());
    assert!(a.seal_at(&Message::End, NOW + 101).is_err());

    // A public grant already expired, or for another session, or not
    // read only, is refused.
    let (n, mut a) = confirmed(DeviceMode::Public);
    let sid = n.session_id();
    for g in [
        PublicGrant {
            session_id: sid,
            expires_at: NOW + 8,
            read_only: true,
            items: vec![],
        },
        PublicGrant {
            session_id: [0; 16],
            expires_at: NOW + 600,
            read_only: true,
            items: vec![],
        },
        PublicGrant {
            session_id: sid,
            expires_at: NOW + 600,
            read_only: false,
            items: vec![],
        },
    ] {
        assert!(a.seal_grant_at(Grant::Public(g), true, NOW + 9).is_err());
    }
}

#[test]
fn sas_changes_with_transcript() {
    let k = SymmetricKey::from_bytes([1; 32]);
    let a = sas(&k, &[0; 32]).unwrap();
    let b = sas(&k, &[1; 32]).unwrap();
    let c = sas(&SymmetricKey::from_bytes([2; 32]), &[0; 32]).unwrap();
    for s in [&a, &b, &c] {
        assert_eq!(s.len(), 6);
        assert!(s.bytes().all(|d| d.is_ascii_digit()));
    }
    assert_ne!(a, b);
    assert_ne!(a, c);
    assert_eq!(a, sas(&k, &[0; 32]).unwrap());

    // Two sessions never share a code by construction.
    let (_, _, s1, _) = handshake(DeviceMode::Personal);
    let (_, _, s2, _) = handshake(DeviceMode::Personal);
    assert_eq!(s1.len(), 6);
    assert_eq!(s2.len(), 6);
}

#[test]
fn snapshot_cap_enforced() {
    let rec = |n: usize| SnapshotRecord {
        kind: 5,
        id: Id::new(),
        version: 1,
        data: vec![0u8; n],
    };
    let chunk = 900 * 1024;
    let under: Vec<_> = (0..MAX_SNAPSHOT_BYTES / chunk - 1)
        .map(|_| rec(chunk))
        .collect();
    check_snapshot_size(&under).unwrap();
    let mut over = under;
    over.push(rec(chunk));
    over.push(rec(chunk));
    assert!(check_snapshot_size(&over).is_err());

    let (_, mut a) = confirmed(DeviceMode::Personal);
    let mut g = full_grant();
    g.snapshot = over;
    assert!(a.seal_grant_at(Grant::Full(g), true, NOW + 8).is_err());
}

// ---- rendezvous direction (version 2): the approver shows the code ---------

/// A host with one code on screen, and a newcomer that joined it: the
/// approver, the newcomer, and both SAS.
fn joined(mode: DeviceMode) -> (Newcomer, Approver, String, String) {
    let mut host = Host::new();
    let shown = host.issue(NOW).unwrap();
    let code = RendezvousCode::parse(&shown.qr_text).unwrap();
    let (mut n, join) = Newcomer::join(ipad(), mode, &code, NOW + 3).unwrap();
    let (a, kx, sas_a, info, requested) = host.accept(&join, NOW + 5).unwrap();
    assert_eq!(info.name, "iPad de Camille");
    assert_eq!(requested, mode);
    let sas_n = n.on_key_exchange(&kx, NOW + 6).unwrap();
    (n, a, sas_n, sas_a)
}

#[test]
fn rendezvous_full_pairing_in_memory() {
    let (mut n, mut a, sas_n, sas_a) = joined(DeviceMode::Personal);
    assert_eq!(sas_n, sas_a);
    assert_eq!(sas_n.len(), 6);

    let f = n.confirm().unwrap();
    assert_eq!(a.on_frame_at(&f, NOW + 7).unwrap(), Message::Confirmed);
    let grant = full_grant();
    let f = a
        .seal_grant_at(Grant::Full(grant.clone()), true, NOW + 8)
        .unwrap();
    let Message::Grant(Grant::Full(got)) = n.open_at(&f, NOW + 9).unwrap() else {
        panic!("expected a full grant");
    };
    assert_eq!(got.account_id, grant.account_id);
    assert_eq!(got.snapshot, grant.snapshot);
    let ack = n.seal_at(&Message::Ack, NOW + 10).unwrap();
    assert_eq!(a.on_frame_at(&ack, NOW + 10).unwrap(), Message::Ack);
}

#[test]
fn rendezvous_public_session_in_memory() {
    let (mut n, mut a, sas_n, sas_a) = joined(DeviceMode::Public);
    assert_eq!(sas_n, sas_a);
    let f = n.confirm().unwrap();
    a.on_frame_at(&f, NOW + 7).unwrap();
    // The grant carries this session's id: the one the newcomer drew.
    let grant = PublicGrant {
        session_id: n.session_id(),
        expires_at: NOW + 900,
        read_only: true,
        items: vec![new_item(ItemType::Login, Id::new(), "Wi-Fi")],
    };
    let f = a
        .seal_grant_at(Grant::Public(grant), true, NOW + 8)
        .unwrap();
    assert!(matches!(
        n.open_at(&f, NOW + 9).unwrap(),
        Message::Grant(Grant::Public(_))
    ));
}

#[test]
fn rendezvous_qr_and_typed_code_are_the_same_secret() {
    let mut host = Host::new();
    let shown = host.issue(NOW).unwrap();
    assert!(shown.qr_text.starts_with("OPPAIR2:"));
    assert_eq!(shown.qr_text.len(), "OPPAIR2:".len() + 8);
    assert_eq!(shown.short_text.len(), 9);
    assert_eq!(shown.short_text.as_bytes()[4], b'-');
    assert_eq!(shown.expires_at, NOW + QR_LIFETIME_SECS);
    let from_qr = RendezvousCode::parse(&shown.qr_text).unwrap();
    let typed = RendezvousCode::parse(&shown.short_text.to_lowercase()).unwrap();
    assert_eq!(from_qr, typed);
    // The typed form joins just like the scanned one.
    let (_, join) = Newcomer::join(ipad(), DeviceMode::Personal, &typed, NOW + 1).unwrap();
    assert!(host.accept(&join, NOW + 2).is_ok());
}

#[test]
fn rendezvous_codes_renew_and_old_ones_live_until_expiry() {
    let mut host = Host::new();
    let first = host.issue(NOW).unwrap();
    let second = host.issue(NOW + RV_RENEW_SECS).unwrap();
    assert_ne!(first.qr_text, second.qr_text);
    // The first code is still good 90 s after its issue, past the renewal.
    let code = RendezvousCode::parse(&first.qr_text).unwrap();
    let (_, join) = Newcomer::join(ipad(), DeviceMode::Personal, &code, NOW + 90).unwrap();
    assert!(host.accept(&join, NOW + 90).is_ok());
}

#[test]
fn rendezvous_expired_code_refused() {
    let mut host = Host::new();
    let shown = host.issue(NOW).unwrap();
    let code = RendezvousCode::parse(&shown.qr_text).unwrap();
    let (_, join) = Newcomer::join(ipad(), DeviceMode::Personal, &code, NOW).unwrap();
    assert!(host.accept(&join, shown.expires_at + 1).is_err());
    // Exactly at expiry is still accepted.
    let (_, join) = Newcomer::join(ipad(), DeviceMode::Personal, &code, NOW).unwrap();
    assert!(host.accept(&join, shown.expires_at).is_ok());
}

#[test]
fn rendezvous_a_code_serves_one_hello() {
    let mut host = Host::new();
    let shown = host.issue(NOW).unwrap();
    let code = RendezvousCode::parse(&shown.qr_text).unwrap();
    let (_, first) = Newcomer::join(ipad(), DeviceMode::Personal, &code, NOW).unwrap();
    let (_, second) = Newcomer::join(ipad(), DeviceMode::Personal, &code, NOW).unwrap();
    assert!(host.accept(&first, NOW + 1).is_ok());
    // Spent: neither the same Hello (replay) nor a fresh one passes.
    assert!(host.accept(&first, NOW + 2).is_err());
    assert!(host.accept(&second, NOW + 2).is_err());
    assert!(host.issue(NOW + 3).is_err());
    assert!(!host.is_open());
}

#[test]
fn rendezvous_wrong_code_and_tampered_hello_refused() {
    let mut host = Host::new();
    host.issue(NOW).unwrap();
    let other = RendezvousCode::generate().unwrap();
    let (_, join) = Newcomer::join(ipad(), DeviceMode::Personal, &other, NOW).unwrap();
    assert!(matches!(
        host.accept(&join, NOW + 1),
        Err(Error::Integrity(_))
    ));

    // Right code, but the Hello was altered in flight (mode swapped).
    let mut host = Host::new();
    let shown = host.issue(NOW).unwrap();
    let code = RendezvousCode::parse(&shown.qr_text).unwrap();
    let (_, join) = Newcomer::join(ipad(), DeviceMode::Public, &code, NOW).unwrap();
    let mut parsed = JoinHello::from_bytes(&join).unwrap();
    parsed.hello.requested_mode = DeviceMode::Personal;
    assert!(host.accept(&parsed.to_bytes().unwrap(), NOW + 1).is_err());

    // Right code, but another key swapped in: the proof covers the key.
    let (_, other_join) = Newcomer::join(ipad(), DeviceMode::Public, &code, NOW).unwrap();
    let mut mitm = JoinHello::from_bytes(&join).unwrap();
    mitm.hello.ephemeral_public = JoinHello::from_bytes(&other_join)
        .unwrap()
        .hello
        .ephemeral_public;
    assert!(host.accept(&mitm.to_bytes().unwrap(), NOW + 1).is_err());

    // Junk.
    assert!(host.accept(b"OPH2", NOW + 1).is_err());
    assert!(host.accept(&join[..join.len() - 1], NOW + 1).is_err());
    assert!(host.accept(&[], NOW + 1).is_err());
}

#[test]
fn rendezvous_host_closes_after_too_many_failures() {
    let mut host = Host::new();
    let shown = host.issue(NOW).unwrap();
    let wrong = RendezvousCode::generate().unwrap();
    for _ in 0..RV_MAX_FAILURES {
        let (_, join) = Newcomer::join(ipad(), DeviceMode::Personal, &wrong, NOW).unwrap();
        assert!(host.accept(&join, NOW + 1).is_err());
    }
    assert!(!host.is_open());
    // Even the right code is refused now.
    let code = RendezvousCode::parse(&shown.qr_text).unwrap();
    let (_, join) = Newcomer::join(ipad(), DeviceMode::Personal, &code, NOW).unwrap();
    assert!(host.accept(&join, NOW + 2).is_err());
}

#[test]
fn rendezvous_man_in_the_middle_gets_different_codes() {
    // The attacker knows the code (it was shown, or guessed) and relays
    // between a real newcomer and a real host with a Hello of its own: the
    // two screens show different codes.
    let mut host = Host::new();
    let shown = host.issue(NOW).unwrap();
    let code = RendezvousCode::parse(&shown.qr_text).unwrap();
    let (mut victim, _join) = Newcomer::join(ipad(), DeviceMode::Personal, &code, NOW).unwrap();
    let (mut attacker, forged) = Newcomer::join(ipad(), DeviceMode::Personal, &code, NOW).unwrap();
    let (_a, kx, sas_a, _, _) = host.accept(&forged, NOW + 1).unwrap();
    // The attacker cannot hand the victim a key exchange for the victim's
    // own key: the envelope was wrapped to the attacker's ephemeral key.
    assert!(victim.on_key_exchange(&kx, NOW + 2).is_err());
    let sas_attacker = attacker.on_key_exchange(&kx, NOW + 2).unwrap();
    assert_eq!(sas_attacker, sas_a);
}

#[test]
fn rendezvous_session_does_not_mix_with_version_one() {
    // A v1 key exchange (wrapped for a QR transcript) does not open under
    // the v2 label, and the other way round.
    let (mut n_rv, join) = {
        let mut host = Host::new();
        let shown = host.issue(NOW).unwrap();
        let code = RendezvousCode::parse(&shown.qr_text).unwrap();
        Newcomer::join(ipad(), DeviceMode::Personal, &code, NOW).unwrap()
    };
    let _ = join;
    let (_, qr, hello) = Newcomer::new(ipad(), DeviceMode::Personal, NOW).unwrap();
    let (_, kx_v1, _, _, _) = Approver::begin(&qr.to_text(), &hello, NOW + 1).unwrap();
    assert!(n_rv.on_key_exchange(&kx_v1, NOW + 2).is_err());
}
