//! QR pairing protocol (milestone 2b, spec 5): two devices in memory, no
//! transport. Synthetic data only.

use onepass_core::crypto::SecretKey;
use onepass_core::crypto::SymmetricKey;
use onepass_core::devices::{DeviceKind, DeviceMode};
use onepass_core::model::{ItemType, new_item};
use onepass_core::pairing::{
    Approver, AuditAction, AuditEvent, Channel, DeviceInfo, FullGrant, Grant, Hello,
    MAX_SNAPSHOT_BYTES, Message, Newcomer, PairingQr, PublicGrant, QR_LIFETIME_SECS,
    SnapshotRecord, check_snapshot_size, sas,
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

// ------------------------------------------------- pairing v2 (rotation v2)
//
// Key rotation v2, spec 5.2, 6.4, 7.4, 15, R16, ruling A9: device keys
// exchanged and pinned inside the SAS channel. Devices are SyncStore files
// of the two-device harness; their device keys and genesis trust state are
// seeded here (the genesis at account creation is Task 14).

mod common;

use common::{Device, PASSWORD, Server, pull, sync};
use onepass_core::device_keys::{DeviceKeys, DevicePublic};
use onepass_core::devices::DeviceEntry;
use onepass_core::lineage::{
    GenesisBody, LINEAGE_FORMAT, LineageRecord, RosterEntry, RotationReason, SignedIntro,
    sign_genesis, verify_intro,
};
use onepass_core::pairing::{FullGrantV2, import_full_v2, snapshot_from_store};
use onepass_core::repo::RotateRequest;
use onepass_core::repo::follow::{follow_rotation, pending_rotation};
use onepass_core::repo::pairing::repair_from_grant;
use onepass_core::store::{Record, RecordKind, RecordStore};
use onepass_core::sync::SyncStore;
use onepass_core::trust::{LineageHead, TrustLevel, TrustState};

struct Keys {
    keys: DeviceKeys,
    public: DevicePublic,
}

impl Keys {
    fn new(id: Id) -> Keys {
        let keys = DeviceKeys::generate_software().unwrap();
        let public = keys.public(id).unwrap();
        Keys { keys, public }
    }

    fn id(&self) -> Id {
        self.public.device_id
    }

    fn entry(&self, name: &str) -> RosterEntry {
        RosterEntry {
            device_id: self.id(),
            sign_pub: self.public.sign_pub.clone(),
            kem_pub: self.public.kem_pub.clone(),
            name: name.into(),
            kind: DeviceKind::Phone,
            mode: DeviceMode::Personal,
            introduced_by: None,
        }
    }

    fn info(&self, name: &str) -> DeviceInfo {
        DeviceInfo {
            device_id: self.id(),
            name: name.into(),
            kind: DeviceKind::Tablet,
        }
    }
}

/// A (the approver) on `server`, its genesis pinned with a roster of A, B
/// and C (all verified, `Current`); `others` are B and C.
struct V2 {
    server: Server,
    a: Device,
    sk: SecretKey,
    me: Keys,
    others: Vec<Keys>,
}

fn v2() -> V2 {
    let mut server = Server::default();
    let (mut a, _b, sk, _items) = common::setup(&mut server, &[("alice", common::T0)]);
    sync(&mut server, &mut a).unwrap();
    let me = Keys::new(a.repo().chain().device_id.unwrap_or_else(Id::new));
    let others: Vec<Keys> = (0..2).map(|_| Keys::new(Id::new())).collect();
    let mut roster = vec![me.entry("iPhone")];
    roster.extend(others.iter().zip(["iPad", "Mac"]).map(|(k, n)| k.entry(n)));
    roster.sort_by_key(|e| e.device_id);
    let account = a.repo().account();
    let account_id = account.params.account_id;
    let identity_pub = account.params.identity_pub.clone();
    let genesis = LineageRecord::Genesis(
        sign_genesis(
            GenesisBody {
                format: LINEAGE_FORMAT,
                account_id,
                identity_pub: identity_pub.clone(),
                creator: me.entry("iPhone"),
                created_at: common::T0,
            },
            &me.keys,
            &account.keyset().identity,
        )
        .unwrap(),
    );
    let mut trust = TrustState::new(
        account_id,
        me.public.clone(),
        LineageHead {
            generation: 0,
            hash: genesis.hash(),
        },
        identity_pub,
        roster.clone(),
        DeviceLineageState::Current,
    );
    for e in &roster {
        trust.levels.insert(e.device_id, TrustLevel::Verified);
    }
    let record = Record {
        id: genesis.record_id(),
        kind: RecordKind::Lineage,
        version: 0,
        data: genesis.encode(),
    };
    a.repo()
        .store_mut()
        .put_all_if_version_with_trust(vec![(record, None)], vec![], None, &trust)
        .unwrap();
    sync(&mut server, &mut a).unwrap();
    V2 {
        server,
        a,
        sk,
        me,
        others,
    }
}

use onepass_core::trust::DeviceLineageState;

/// A device of the server's account whose trust state is A's, seen from
/// `keys` (`edit` changes it before it is saved). Locked.
fn follower(v: &mut V2, who: usize, edit: impl FnOnce(&mut TrustState)) -> Device {
    let mut c = Device::empty();
    pull(&v.server, &mut c);
    c.unlock(&v.sk);
    let mut trust = v.a.store().trust_state().unwrap().unwrap();
    trust.me = v.others[who].public.clone();
    edit(&mut trust);
    c.repo()
        .store_mut()
        .put_all_if_version_with_trust(vec![], vec![], None, &trust)
        .unwrap();
    c.lock();
    c
}

fn trust(dev: &Device) -> TrustState {
    dev.store().trust_state().unwrap().unwrap()
}

/// A session up to the newcomer's `ConfirmedWithKey`, read by the
/// approver: (newcomer, approver).
fn confirmed_with_key(n_keys: &Keys, info: DeviceInfo) -> (Newcomer, Approver) {
    let (mut n, qr, hello) = Newcomer::new(info, DeviceMode::Personal, NOW).unwrap();
    let (mut a, kx, _, _, _) = Approver::begin(&qr.to_text(), &hello, NOW + 1).unwrap();
    n.on_key_exchange(&kx, NOW + 2).unwrap();
    let f = n.confirm_with_key(&n_keys.keys).unwrap();
    let Message::ConfirmedWithKey { device, .. } = a.on_frame_at(&f, NOW + 3).unwrap() else {
        panic!("expected ConfirmedWithKey");
    };
    assert_eq!(device, n_keys.public);
    assert_eq!(a.newcomer_key(), Some(&n_keys.public));
    (n, a)
}

/// The `FullV2` A grants: its synced rows, the Secret Key, its trust
/// snapshot.
fn grant_v2(a: &mut Device, sk: &SecretKey, device_id: Id) -> FullGrantV2 {
    let repo = a.repo();
    FullGrantV2 {
        full: FullGrant {
            account_id: repo.account().params.account_id,
            secret_key: Zeroizing::new(sk.to_display()),
            mode: DeviceMode::Personal,
            device_id,
            snapshot: snapshot_from_store(repo.store()).unwrap(),
        },
        trust: repo.trust_snapshot().unwrap(),
        sync: None,
        enroll: None,
    }
}

/// A full v2 pairing of a new device `n` with A: listed and granted in one
/// transaction, imported, acknowledged, introduced. Returns N's device.
fn pair_new(v: &mut V2, n: &Keys) -> Device {
    let (mut nc, mut ap, info, dev) = granted(v, n);
    // Its acknowledgment carries the pop over the account id: A introduces.
    let ack = nc.seal_key_ack_at(&n.keys, NOW + 6).unwrap();
    assert!(matches!(
        ap.on_frame_at(&ack, NOW + 6).unwrap(),
        Message::ConfirmedWithKey { .. }
    ));
    let pop = ap.newcomer_account_pop().unwrap().clone();
    let me_keys = &v.me.keys;
    v.a.repo()
        .introduce(&n.public, &info, DeviceMode::Personal, &pop, me_keys)
        .unwrap();
    dev
}

/// A pairing of `n` with A up to the newcomer's import of its `FullV2`
/// (listed and granted by A, pinned and opened by N), before its key
/// acknowledgment.
fn granted(v: &mut V2, n: &Keys) -> (Newcomer, Approver, DeviceInfo, Device) {
    let info = n.info("iPad de Camille");
    let (mut nc, mut ap) = confirmed_with_key(n, info.clone());
    let entry = DeviceEntry {
        device_id: n.id(),
        name: info.name.clone(),
        kind: info.kind,
        mode: DeviceMode::Personal,
        added_at: NOW,
        added_by: v.a.repo().this_device_id(),
        revoked_at: None,
    };
    let sk = &v.sk;
    let frame =
        v.a.repo()
            .add_device_then(entry, |repo| {
                let grant = FullGrantV2 {
                    full: FullGrant {
                        account_id: repo.account().params.account_id,
                        secret_key: Zeroizing::new(sk.to_display()),
                        mode: DeviceMode::Personal,
                        device_id: n.id(),
                        snapshot: snapshot_from_store(repo.store())?,
                    },
                    trust: repo.trust_snapshot()?,
                    sync: None,
                    enroll: None,
                };
                ap.seal_grant_at(Grant::FullV2(grant), true, NOW + 4)
            })
            .unwrap();
    let Message::Grant(Grant::FullV2(got)) = nc.open_at(&frame, NOW + 5).unwrap() else {
        panic!("expected a FullV2");
    };
    // The newcomer imports it into its empty store and opens it.
    let mut dev = Device::empty();
    {
        let mut store = SyncStore::open(&dev.path).unwrap();
        import_full_v2(&mut store, &got, &n.public, &info).unwrap();
    }
    dev.unlock(&SecretKey::parse(&got.full.secret_key).unwrap());
    dev.lock();
    (nc, ap, info, dev)
}

fn intros(store: &SyncStore) -> Vec<SignedIntro> {
    store
        .list(RecordKind::DeviceIntro)
        .unwrap()
        .iter()
        .map(|r| SignedIntro::decode(&r.data).unwrap())
        .collect()
}

#[test]
fn confirmed_encoding_unchanged() {
    // The legacy confirmation still pairs, byte for byte as before: the
    // approver reads `Confirmed`, grants a `Full`, takes `Ack`.
    let (mut n, mut a) = confirmed(DeviceMode::Personal);
    assert_eq!(a.newcomer_key(), None);
    let f = a
        .seal_grant_at(Grant::Full(full_grant()), true, NOW + 8)
        .unwrap();
    assert!(matches!(
        n.open_at(&f, NOW + 9).unwrap(),
        Message::Grant(Grant::Full(_))
    ));
    let ack = n.seal_at(&Message::Ack, NOW + 10).unwrap();
    assert_eq!(a.on_frame_at(&ack, NOW + 10).unwrap(), Message::Ack);
}

#[test]
fn intro_written_with_grant_ack() {
    let mut v = v2();
    let n = Keys::new(Id::new());
    let before = intros(&v.a.store()).len();
    let _dev = pair_new(&mut v, &n);
    // The device list lists N (written with the sealed grant)...
    assert!(
        v.a.repo()
            .devices()
            .unwrap()
            .iter()
            .any(|e| e.device_id == n.id())
    );
    // ...and the intro, signed by A under its head, with N in A's roster.
    let t = trust(&v.a);
    let all = intros(&v.a.store());
    assert_eq!(all.len(), before + 1);
    let i = all
        .iter()
        .find(|i| i.body.entry.device_id == n.id())
        .unwrap();
    assert_eq!(i.body.head, t.head.hash);
    assert_eq!(i.body.introducer, v.me.id());
    assert_eq!(i.body.entry.introduced_by, Some(v.me.id()));
    verify_intro(i, &v.me.public.sign_pub).unwrap();
    assert!(t.roster.iter().any(|e| e.device_id == n.id()));
    assert_eq!(t.levels.get(&n.id()), Some(&TrustLevel::Verified));
    // Pending for the server, with the rest of A's writes.
    let outbox = common::outbox(&v.a);
    assert!(
        outbox
            .iter()
            .any(|(c, _)| c.kind == RecordKind::DeviceIntro)
    );
}

#[test]
fn snapshot_pinned() {
    let mut v = v2();
    let n = Keys::new(Id::new());
    let dev = pair_new(&mut v, &n);
    let mine = trust(&dev);
    let theirs = trust(&v.a);
    assert_eq!(mine.head, theirs.head);
    assert_eq!(mine.roster, theirs.roster);
    assert_eq!(mine.identity_pub, theirs.identity_pub);
    assert_eq!(mine.me, n.public);
    assert_eq!(mine.state, DeviceLineageState::Current);
}

#[test]
fn intro_by_revoked_or_excluded_refused() {
    let mut v = v2();
    let mut c_ok = follower(&mut v, 1, |_| {});
    let a_id = v.me.id();
    let mut c_excl = follower(&mut v, 1, |t| {
        t.excluded.insert(a_id);
    });
    let mut c_rev = follower(&mut v, 1, |t| t.add_revoked(&[a_id]));
    let n = Keys::new(Id::new());
    let _dev = pair_new(&mut v, &n);
    sync(&mut v.server, &mut v.a).unwrap();
    for c in [&mut c_ok, &mut c_excl, &mut c_rev] {
        pull(&v.server, c);
        c.unlock(&v.sk);
        c.lock();
    }
    let has = |d: &Device| trust(d).roster.iter().any(|e| e.device_id == n.id());
    assert!(has(&c_ok), "a valid intro joins the roster");
    assert!(!has(&c_excl), "intro by an excluded device accepted");
    assert!(!has(&c_rev), "intro by a revoked device accepted");

    // The approver refuses to introduce a device it revoked or excluded.
    let info = n.info("iPad");
    let pop =
        onepass_core::device_keys::sign_pop(&n.keys, &trust(&v.a).account_id.0, &n.public).unwrap();
    let x = Keys::new(Id::new());
    let mut excluded_a = trust(&v.a);
    excluded_a.excluded.insert(x.id());
    let t = trust(&v.a);
    v.a.repo()
        .store_mut()
        .put_with_trust_cas(vec![], vec![], None, &t, &excluded_a)
        .unwrap();
    let xpop = onepass_core::device_keys::sign_pop(&x.keys, &t.account_id.0, &x.public).unwrap();
    let r = v.a.repo().introduce(
        &x.public,
        &x.info("Mac"),
        DeviceMode::Personal,
        &xpop,
        &v.me.keys,
    );
    assert!(matches!(r, Err(Error::Validation(_))), "{r:?}");
    // A pop over another key fails, a known key is a no-op.
    let r =
        v.a.repo()
            .introduce(&n.public, &info, DeviceMode::Personal, &xpop, &v.me.keys);
    assert!(matches!(r, Err(Error::Integrity(_))), "{r:?}");
    v.a.repo()
        .introduce(&n.public, &info, DeviceMode::Personal, &pop, &v.me.keys)
        .unwrap();
}

#[test]
fn old_peer_pairs_legacy() {
    let v = v2();
    let n = ipad();
    let (mut nc, qr, hello) = Newcomer::new(n.clone(), DeviceMode::Personal, NOW).unwrap();
    let (mut ap, kx, _, _, _) = Approver::begin(&qr.to_text(), &hello, NOW + 1).unwrap();
    nc.on_key_exchange(&kx, NOW + 2).unwrap();
    let f = nc.confirm().unwrap();
    assert_eq!(ap.on_frame_at(&f, NOW + 3).unwrap(), Message::Confirmed);
    // A `FullV2` would not decode on an older newcomer: refused.
    let mut a = v.a;
    let v2grant = grant_v2(&mut a, &v.sk, n.device_id);
    assert!(
        ap.seal_grant_at(Grant::FullV2(v2grant), true, NOW + 4)
            .is_err()
    );
    let entry = DeviceEntry {
        device_id: n.device_id,
        name: n.name.clone(),
        kind: n.kind,
        mode: DeviceMode::Personal,
        added_at: NOW,
        added_by: a.repo().this_device_id(),
        revoked_at: None,
    };
    let sk = &v.sk;
    let frame = a
        .repo()
        .add_device_then(entry, |repo| {
            repo.mark_legacy_device(n.device_id)?;
            let grant = FullGrant {
                account_id: repo.account().params.account_id,
                secret_key: Zeroizing::new(sk.to_display()),
                mode: DeviceMode::Personal,
                device_id: n.device_id,
                snapshot: snapshot_from_store(repo.store())?,
            };
            ap.seal_grant_at(Grant::Full(grant), true, NOW + 4)
        })
        .unwrap();
    assert!(matches!(
        nc.open_at(&frame, NOW + 5).unwrap(),
        Message::Grant(Grant::Full(_))
    ));
    let ack = nc.seal_at(&Message::Ack, NOW + 6).unwrap();
    assert_eq!(ap.on_frame_at(&ack, NOW + 6).unwrap(), Message::Ack);
    let t = trust(&a);
    assert_eq!(t.levels.get(&n.device_id), Some(&TrustLevel::Tofu));
    assert!(!t.roster.iter().any(|e| e.device_id == n.device_id));
    assert!(intros(&a.store()).is_empty());
}

#[test]
fn v2_session_refuses_downgrades() {
    let v = v2();
    // A public session pins no device key.
    let (mut pn, _pa, _, _) = handshake(DeviceMode::Public);
    assert!(pn.confirm_with_key(&Keys::new(Id::new()).keys).is_err());
    let n = Keys::new(Id::new());
    let (mut nc, mut ap) = confirmed_with_key(&n, n.info("iPad"));
    // The approver must not send a legacy `Full` to a newcomer with a key...
    assert!(
        ap.seal_grant_at(Grant::Full(full_grant()), true, NOW + 4)
            .is_err()
    );
    // ...nor take a legacy `Ack` for a `FullV2`.
    let mut a = v.a;
    let g = grant_v2(&mut a, &v.sk, n.id());
    let f = ap.seal_grant_at(Grant::FullV2(g), true, NOW + 4).unwrap();
    nc.open_at(&f, NOW + 5).unwrap();
    assert!(nc.seal_at(&Message::Ack, NOW + 6).is_err());
    // The key acknowledgment needs the confirmed key.
    let other = Keys::new(n.id());
    assert!(nc.seal_key_ack_at(&other.keys, NOW + 6).is_err());
    let ack = nc.seal_key_ack_at(&n.keys, NOW + 6).unwrap();
    ap.on_frame_at(&ack, NOW + 6).unwrap();
    assert!(
        nc.seal_key_ack_at(&n.keys, NOW + 7).is_err(),
        "acknowledged twice"
    );
}

#[test]
fn repair_of_known_account_is_a_follow() {
    let mut v = v2();
    let mut c = follower(&mut v, 1, |_| {});
    // C writes offline: its item never reaches the server.
    c.unlock(&v.sk);
    let vault = c.vault();
    let offline = common::login(vault.id, "offline", common::T0 + 50);
    c.save(&offline);
    c.lock();
    // A rotates (removing B) while C is away.
    let new_sk = SecretKey::generate().unwrap();
    let b = v.others[0].id();
    let out =
        v.a.repo()
            .rotate(RotateRequest {
                revoke: vec![b],
                new_password: None,
                password: PASSWORD,
                secret_key: &v.sk,
                new_secret_key: &new_sk,
                device_keys: &v.me.keys,
                reason: RotationReason::Revoke,
            })
            .unwrap();
    sync(&mut v.server, &mut v.a).unwrap();
    // C re-pairs from A under its own id: the grant is applied as a follow.
    let c_keys = &v.others[1];
    let (mut nc, mut ap) = confirmed_with_key(c_keys, c_keys.info("Mac"));
    let g = grant_v2(&mut v.a, &new_sk, c_keys.id());
    let f = ap.seal_grant_at(Grant::FullV2(g), true, NOW + 4).unwrap();
    let Message::Grant(Grant::FullV2(got)) = nc.open_at(&f, NOW + 5).unwrap() else {
        panic!("expected a FullV2");
    };
    c.unlock(&v.sk);
    let session = c.repo.take().unwrap();
    let (repo, _auk, sk) = repair_from_grant(session, &got, PASSWORD, &c_keys.keys).unwrap();
    assert_eq!(sk.to_display(), new_sk.to_display());
    c.repo = Some(repo);
    let t = trust(&c);
    assert_eq!(t.head.hash, out.head);
    assert_eq!(t.identity_pub, trust(&v.a).identity_pub);
    assert!(t.revoked.contains(&b));
    // The local item stays and is replayed under the new keys: A sees it.
    assert!(c.items().iter().any(|i| i.id == offline.id));
    sync(&mut v.server, &mut c).unwrap();
    sync(&mut v.server, &mut v.a).unwrap();
    assert!(v.a.items().iter().any(|i| i.id == offline.id));
    // The re-paired device opens with the new Secret Key only.
    c.lock();
    assert!(c.try_unlock(PASSWORD, &v.sk).is_err());
    c.try_unlock(PASSWORD, &new_sk).unwrap();
}

#[test]
fn reintro_after_adoption() {
    let mut v = v2();
    let mut c = follower(&mut v, 1, |_| {});
    // C introduces X; A rotates before it sees the intro.
    let x = Keys::new(Id::new());
    c.unlock(&v.sk);
    let account = trust(&c).account_id;
    let pop = onepass_core::device_keys::sign_pop(&x.keys, &account.0, &x.public).unwrap();
    let c_keys = &v.others[1].keys;
    c.repo()
        .introduce(
            &x.public,
            &x.info("Watch"),
            DeviceMode::Personal,
            &pop,
            c_keys,
        )
        .unwrap();
    assert!(trust(&c).roster.iter().any(|e| e.device_id == x.id()));
    c.lock();
    let new_sk = SecretKey::generate().unwrap();
    let out =
        v.a.repo()
            .rotate(RotateRequest {
                revoke: vec![v.others[0].id()],
                new_password: None,
                password: PASSWORD,
                secret_key: &v.sk,
                new_secret_key: &new_sk,
                device_keys: &v.me.keys,
                reason: RotationReason::Revoke,
            })
            .unwrap();
    sync(&mut v.server, &mut v.a).unwrap();
    assert!(!trust(&v.a).roster.iter().any(|e| e.device_id == x.id()));
    // C syncs (its intro goes out, A's rotation comes in) and follows.
    common::push(&mut v.server, &c).unwrap();
    pull(&v.server, &mut c);
    assert!(pending_rotation(&c.store()).unwrap().is_some());
    let (repo, _, _) = follow_rotation(c.store(), out.head, PASSWORD, c_keys).unwrap();
    c.repo = Some(repo);
    // C introduced X again under the new head.
    let t = trust(&c);
    assert!(t.roster.iter().any(|e| e.device_id == x.id()));
    let again = intros(&c.store());
    assert!(
        again
            .iter()
            .any(|i| i.body.entry.device_id == x.id() && i.body.head == out.head)
    );
    // A takes it: X joins A's roster at the new head.
    sync(&mut v.server, &mut c).unwrap();
    sync(&mut v.server, &mut v.a).unwrap();
    v.a.lock();
    v.a.unlock(&new_sk);
    assert!(trust(&v.a).roster.iter().any(|e| e.device_id == x.id()));
}

#[test]
fn tofu_level_carried() {
    // A trusts B on first use only: N pins B as `Tofu` too (O7).
    let mut v = v2();
    let b = v.others[0].id();
    let t = trust(&v.a);
    let mut tofu = t.clone();
    tofu.levels.insert(b, TrustLevel::Tofu);
    v.a.repo()
        .store_mut()
        .put_with_trust_cas(vec![], vec![], None, &t, &tofu)
        .unwrap();
    let snap = v.a.repo().trust_snapshot().unwrap();
    assert_eq!(snap.level(b), Some(TrustLevel::Tofu));
    assert_eq!(snap.level(v.me.id()), Some(TrustLevel::Verified));
    let n = Keys::new(Id::new());
    let dev = pair_new(&mut v, &n);
    let pinned = trust(&dev);
    assert_eq!(pinned.levels.get(&b), Some(&TrustLevel::Tofu));
    assert_eq!(pinned.levels.get(&v.me.id()), Some(&TrustLevel::Verified));
    assert_eq!(pinned.levels.get(&n.id()), Some(&TrustLevel::Verified));
}

#[test]
fn pairing_incomplete_until_intro_or_cancel() {
    let mut v = v2();
    // A device listed before key rotation v2 that this hand-seeded trust
    // state never marked `Tofu` (the harness's second device; a real
    // migration marks it, Task 14): the baseline.
    let base = v.a.repo().pairing_incomplete().unwrap();
    let with = |id: Id| {
        let mut l = base.clone();
        l.push(id);
        l.sort();
        l
    };
    // The session is cut after the grant, before the key acknowledgment.
    let n = Keys::new(Id::new());
    let (mut nc, mut ap, info, _dev) = granted(&mut v, &n);
    assert_eq!(v.a.repo().pairing_incomplete().unwrap(), with(n.id()));
    // Finishing (the acknowledgment, then the intro) clears it.
    let ack = nc.seal_key_ack_at(&n.keys, NOW + 6).unwrap();
    ap.on_frame_at(&ack, NOW + 6).unwrap();
    let pop = ap.newcomer_account_pop().unwrap().clone();
    let me_keys = &v.me.keys;
    v.a.repo()
        .introduce(&n.public, &info, DeviceMode::Personal, &pop, me_keys)
        .unwrap();
    assert_eq!(v.a.repo().pairing_incomplete().unwrap(), base);
    // A pinned device is not cancelled: it leaves by rotation.
    let r = v.a.repo().cancel_pairing(n.id());
    assert!(matches!(r, Err(Error::Validation(_))), "{r:?}");

    // Another cut session, then the user removes the device.
    let m = Keys::new(Id::new());
    let _ = granted(&mut v, &m);
    assert_eq!(v.a.repo().pairing_incomplete().unwrap(), with(m.id()));
    v.a.repo().cancel_pairing(m.id()).unwrap();
    assert_eq!(v.a.repo().pairing_incomplete().unwrap(), base);
    let listed = v.a.repo().devices().unwrap();
    let e = listed.iter().find(|e| e.device_id == m.id()).unwrap();
    assert!(e.revoked_at.is_some());
}

/// Task 13 review, carried to Task 14: `cancel_pairing` revokes the list
/// entry and excludes the device in one transaction; a late intro of the
/// cancelled device is refused, from this device and from another one.
#[test]
fn cancelled_pairing_refuses_a_late_intro() {
    use onepass_core::device_keys::sign_pop;
    use onepass_core::lineage::{IntroBody, sign_intro};

    let mut v = v2();
    let m = Keys::new(Id::new());
    let (mut nc, mut ap, info, _dev) = granted(&mut v, &m);
    let list_before = v.a.store().list(RecordKind::DeviceList).unwrap();
    v.a.repo().cancel_pairing(m.id()).unwrap();
    let t = trust(&v.a);
    assert!(t.excluded.contains(&m.id()));
    let listed = v.a.repo().devices().unwrap();
    assert!(
        listed
            .iter()
            .find(|e| e.device_id == m.id())
            .unwrap()
            .revoked_at
            .is_some()
    );
    // One list write went with the exclusion.
    let list_after = v.a.store().list(RecordKind::DeviceList).unwrap();
    assert_eq!(list_after[0].version, list_before[0].version + 1);

    // The session finishes late: its intro is refused here.
    let ack = nc.seal_key_ack_at(&m.keys, NOW + 6).unwrap();
    ap.on_frame_at(&ack, NOW + 6).unwrap();
    let pop = ap.newcomer_account_pop().unwrap().clone();
    let me_keys = &v.me.keys;
    let r =
        v.a.repo()
            .introduce(&m.public, &info, DeviceMode::Personal, &pop, me_keys);
    assert!(matches!(r, Err(Error::Validation(_))), "{r:?}");

    // Another roster device introduces it: not accepted here either.
    let b = &v.others[0];
    let account_id = t.account_id;
    let body = IntroBody {
        format: LINEAGE_FORMAT,
        account_id,
        head: t.head.hash,
        entry: RosterEntry {
            introduced_by: Some(b.id()),
            ..m.entry("iPad")
        },
        introducer: b.id(),
        pop: sign_pop(&m.keys, &account_id.0, &m.public).unwrap(),
    };
    let signed = sign_intro(body, &b.keys, None).unwrap();
    let record = Record {
        id: onepass_core::lineage::intro_id(&signed.body),
        kind: RecordKind::DeviceIntro,
        version: t.head.generation,
        data: signed.encode(),
    };
    v.a.repo().store_mut().put_if_version(record, None).unwrap();
    v.a.repo().refresh_pending_rotation().unwrap();
    assert!(!trust(&v.a).roster.iter().any(|e| e.device_id == m.id()));
}

#[test]
fn approver_refusals() {
    let mut v = v2();
    let t = trust(&v.a);
    // An approver waiting for the user or locked pins nobody.
    for state in [
        DeviceLineageState::Candidate {
            children: vec![[4; 32]],
            resume: None,
        },
        DeviceLineageState::Orphaned {
            child: [4; 32],
            rotator: v.others[0].id(),
            resume: None,
        },
    ] {
        let mut locked = t.clone();
        locked.state = state;
        v.a.repo()
            .store_mut()
            .put_with_trust_cas(vec![], vec![], None, &t, &locked)
            .unwrap();
        assert!(v.a.repo().trust_snapshot().is_err());
        v.a.repo()
            .store_mut()
            .put_with_trust_cas(vec![], vec![], None, &locked, &t)
            .unwrap();
    }
    // A revoked newcomer id is not introduced.
    let x = Keys::new(Id::new());
    let mut revoked = t.clone();
    revoked.add_revoked(&[x.id()]);
    v.a.repo()
        .store_mut()
        .put_with_trust_cas(vec![], vec![], None, &t, &revoked)
        .unwrap();
    let pop = onepass_core::device_keys::sign_pop(&x.keys, &t.account_id.0, &x.public).unwrap();
    let me_keys = &v.me.keys;
    let r = v.a.repo().introduce(
        &x.public,
        &x.info("Mac"),
        DeviceMode::Personal,
        &pop,
        me_keys,
    );
    assert!(matches!(r, Err(Error::Validation(_))), "{r:?}");
    // A `FullV2` listing the newcomer under another id than its Hello's.
    let n = Keys::new(Id::new());
    let (_nc, mut ap) = confirmed_with_key(&n, n.info("iPad"));
    let g = grant_v2(&mut v.a, &v.sk, Id::new());
    assert!(ap.seal_grant_at(Grant::FullV2(g), true, NOW + 4).is_err());
}

#[test]
fn repair_from_rotating_drops_the_abandoned_rotation() {
    let mut v = v2();
    let mut c = follower(&mut v, 1, |_| {});
    let c_keys = &v.others[1];
    // C rotates offline: its phase 1 never goes out.
    c.unlock(&v.sk);
    let c_sk = SecretKey::generate().unwrap();
    let mine = c
        .repo()
        .rotate(RotateRequest {
            revoke: vec![v.others[0].id()],
            new_password: None,
            password: PASSWORD,
            secret_key: &v.sk,
            new_secret_key: &c_sk,
            device_keys: &c_keys.keys,
            reason: RotationReason::Revoke,
        })
        .unwrap();
    assert!(matches!(
        trust(&c).state,
        DeviceLineageState::Rotating { .. }
    ));
    // A rotates too, and syncs.
    let a_sk = SecretKey::generate().unwrap();
    let theirs =
        v.a.repo()
            .rotate(RotateRequest {
                revoke: vec![v.others[0].id()],
                new_password: None,
                password: PASSWORD,
                secret_key: &v.sk,
                new_secret_key: &a_sk,
                device_keys: &v.me.keys,
                reason: RotationReason::Revoke,
            })
            .unwrap();
    sync(&mut v.server, &mut v.a).unwrap();
    // C re-pairs from A, from its open session on its own rotation.
    let (mut nc, mut ap) = confirmed_with_key(c_keys, c_keys.info("Mac"));
    let g = grant_v2(&mut v.a, &a_sk, c_keys.id());
    let f = ap.seal_grant_at(Grant::FullV2(g), true, NOW + 4).unwrap();
    let Message::Grant(Grant::FullV2(got)) = nc.open_at(&f, NOW + 5).unwrap() else {
        panic!("expected a FullV2");
    };
    let session = c.repo.take().unwrap();
    let (repo, _, _) = repair_from_grant(session, &got, PASSWORD, &c_keys.keys).unwrap();
    c.repo = Some(repo);
    assert_eq!(trust(&c).head.hash, theirs.head);
    assert_eq!(trust(&c).state, DeviceLineageState::Current);
    // Nothing of the abandoned rotation is pushed.
    let outbox = common::outbox(&c);
    let mut lineage_id = [0u8; 16];
    lineage_id.copy_from_slice(&mine.head[..16]);
    assert!(
        !outbox
            .iter()
            .any(|(ch, _)| ch.kind == RecordKind::Lineage && ch.id == Id(lineage_id))
    );
    assert!(
        !outbox
            .iter()
            .any(|(ch, _)| ch.kind == RecordKind::KeyDelivery)
    );
    sync(&mut v.server, &mut c).unwrap();
    assert!(v.server.live(RecordKind::Lineage, Id(lineage_id)).is_none());
    // A, after its own sync, is on its head with no prompt.
    sync(&mut v.server, &mut v.a).unwrap();
    assert_eq!(pending_rotation(&v.a.store()).unwrap(), None);
}
