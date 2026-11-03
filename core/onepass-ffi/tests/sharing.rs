//! Sharing over the UniFFI surface, called as plain Rust (plan 4): zones,
//! invite drops and the zone round (Task 1), contacts (Task 2), shared
//! vaults (Task 3).
//!
//! No network: `Shim` serves the in-memory `FakeMailbox` over loopback TLS,
//! so the real client signs and checks every request. Synthetic data only.
//! Run with `--features dev-fast-kdf`.

#![allow(dead_code, unused_imports)]

include!("support/mailbox_shim.rs");

use std::collections::HashMap as SeedMap;

/// The keychain of one device, in memory.
#[derive(Default)]
struct MemSeeds(Mutex<SeedMap<Vec<u8>, Vec<u8>>>);

impl FfiZoneSeedStore for MemSeeds {
    fn get(&self, mailbox_id: Vec<u8>) -> Option<Vec<u8>> {
        self.0.lock().unwrap().get(&mailbox_id).cloned()
    }

    fn put(&self, mailbox_id: Vec<u8>, seed: Vec<u8>) {
        self.0.lock().unwrap().insert(mailbox_id, seed);
    }

    fn delete(&self, mailbox_id: Vec<u8>) {
        self.0.lock().unwrap().remove(&mailbox_id);
    }
}

// ---- Task 1 -----------------------------------------------------------------

#[test]
fn zone_in_invalid_hex_is_invalid_input() {
    let bad = |kind, id: Option<&str>| {
        zone_normalized(FfiZone {
            kind,
            id: id.map(str::to_string),
        })
    };
    assert!(matches!(
        bad(FfiZoneKind::Vault, Some("not hex")),
        Err(OnePassError::InvalidInput { .. })
    ));
    assert!(matches!(
        bad(FfiZoneKind::Contact, None),
        Err(OnePassError::InvalidInput { .. })
    ));
    assert!(matches!(
        bad(FfiZoneKind::Private, Some(&"00".repeat(16))),
        Err(OnePassError::InvalidInput { .. })
    ));
    let ok = bad(FfiZoneKind::Family, Some(&"AB".repeat(16))).unwrap();
    assert_eq!(ok.id.as_deref(), Some("ab".repeat(16).as_str()));
    assert_eq!(
        bad(FfiZoneKind::Private, None).unwrap().kind,
        FfiZoneKind::Private
    );
}

#[test]
fn drop_round_trip() {
    let shim = Shim::start();
    let e = shim.endpoint();
    let id = vec![7u8; 16];
    let ca = e.extra_ca_pem.clone();
    assert_eq!(
        drop_get(e.base_url.clone(), id.clone(), 0, ca.clone()).unwrap(),
        None
    );
    drop_put(
        e.base_url.clone(),
        id.clone(),
        0,
        b"offre".to_vec(),
        ca.clone(),
    )
    .unwrap();
    assert_eq!(
        drop_get(e.base_url.clone(), id.clone(), 0, ca.clone()).unwrap(),
        Some(b"offre".to_vec())
    );
    // Write once: the first write stands.
    assert_eq!(
        drop_put(
            e.base_url.clone(),
            id.clone(),
            0,
            b"autre".to_vec(),
            ca.clone()
        ),
        Err(OnePassError::Conflict)
    );
    assert!(matches!(
        drop_put(e.base_url.clone(), id.clone(), 9, b"x".to_vec(), ca.clone()),
        Err(OnePassError::MailboxUnavailable { .. })
    ));
    assert!(matches!(
        drop_get(e.base_url.clone(), vec![1, 2], 0, ca.clone()),
        Err(OnePassError::InvalidInput { .. })
    ));
    drop_delete(e.base_url.clone(), id.clone(), ca.clone()).unwrap();
    assert_eq!(drop_get(e.base_url, id, 0, ca).unwrap(), None);
}

#[test]
fn zone_round_without_zones_is_empty() {
    let shim = Shim::start();
    let dir = TempDir::new().unwrap();
    let path = db_path(dir.path());
    let created = create_account_with_kdf(path.clone(), PASSWORD.into(), FAST).unwrap();
    let store = open_sync_store(path).unwrap();
    let e = shim.endpoint();
    let zones = ZoneSyncHandle::new(Arc::new(MemSeeds::default()), e.base_url, e.extra_ca_pem);
    let r = zones.run_round(Some(created.session.clone()), store.clone(), now());
    assert!(r.zones.is_empty());
    assert_eq!(r.actions_done, 0);
    assert!(r.refusals.is_empty());
    // Locked: nothing either, and no call fails.
    let r = zones.run_round(None, store, now());
    assert!(r.zones.is_empty());
    assert!(zones.wake_topics().is_empty());
    assert!(matches!(
        zones.set_push_target("00".repeat(16), vec![1; 16], FfiPushKind::Apns, vec![1]),
        Err(OnePassError::MailboxUnavailable { .. })
    ));
    assert!(matches!(
        zones.contact_zone_create(created.session, vec![1, 2, 3], now()),
        Err(OnePassError::InvalidInput { .. })
    ));
}

// ---- Task 2 -----------------------------------------------------------------

/// One account on one device with v2 device keys, and its zone handle on
/// the shim (no account mailbox: the pair's mailboxes hang off an anchor).
struct Person {
    _dir: TempDir,
    session: Arc<Session>,
    keys: Keys,
    seeds: Arc<MemSeeds>,
    zones: Arc<ZoneSyncHandle>,
    store: Arc<SyncStoreHandle>,
}

fn person(shim: &Shim, name: &str) -> Person {
    let dir = TempDir::new().unwrap();
    let path = db_path(dir.path());
    let keys = Keys::new();
    let created = create_account_v2(
        path.clone(),
        PASSWORD.into(),
        Some(FAST),
        keys.classical.clone(),
        keys.half(),
        format!("iPhone de {name}"),
        FfiDeviceKind::Phone,
        FfiDeviceMode::Personal,
    )
    .unwrap();
    let e = shim.endpoint();
    let seeds = Arc::new(MemSeeds::default());
    let zones = ZoneSyncHandle::new(seeds.clone(), e.base_url, e.extra_ca_pem);
    let store = open_sync_store(path).unwrap();
    Person {
        _dir: dir,
        session: created.session,
        keys,
        seeds,
        zones,
        store,
    }
}

/// A PQ half whose signature fails, as a locked Secure Enclave key does.
struct BrokenHalf(SoftwarePqHalf);

impl FfiPqDeviceHalf for BrokenHalf {
    fn mldsa_public(&self) -> Result<Vec<u8>, OnePassError> {
        self.0.mldsa_public().map_err(|_| OnePassError::Crypto)
    }

    fn mlkem_public(&self) -> Result<Vec<u8>, OnePassError> {
        self.0.mlkem_public().map_err(|_| OnePassError::Crypto)
    }

    fn mldsa_sign(&self, _message: Vec<u8>) -> Result<Vec<u8>, OnePassError> {
        Err(OnePassError::Locked)
    }

    fn mlkem_decapsulate(&self, _ciphertext: Vec<u8>) -> Result<Vec<u8>, OnePassError> {
        Err(OnePassError::Locked)
    }
}

fn peer_card(o: FfiContactOutcome) -> Arc<FfiVerifiedPeer> {
    match o {
        FfiContactOutcome::PeerCard { peer } => peer,
        _ => panic!("expected a peer card"),
    }
}

fn zone_offer(o: FfiContactOutcome) -> Vec<u8> {
    match o {
        FfiContactOutcome::PeerZoneOffer { offer } => offer,
        _ => panic!("expected a zone offer"),
    }
}

#[test]
fn face_to_face_pins_both_verified() {
    let shim = Shim::start();
    let alice = person(&shim, "Alice");
    let bob = person(&shim, "Bob");
    let t = now();

    // Alice shows the QR, Bob scans it: one SAS on both screens.
    let start = contact_responder_start(t).unwrap();
    let begin = contact_initiator_begin(start.qr.clone(), start.hello.clone(), t).unwrap();
    let r = start.responder;
    let i = begin.initiator;
    assert_eq!(r.on_key_exchange(begin.key_exchange, t).unwrap(), begin.sas);
    assert!(r.expires_at() > t);

    // Both confirm. Alice's card waits on Bob's side until he confirms.
    let fa = r
        .confirm_and_send_card(
            alice.session.clone(),
            "Alice".into(),
            alice.keys.classical.clone(),
            alice.keys.half(),
            t,
        )
        .unwrap();
    assert!(matches!(
        i.on_frame(fa, t).unwrap(),
        FfiContactOutcome::Waiting
    ));
    assert!(i.verified_peer().is_none());
    let fb = i
        .confirm_and_send_card(
            bob.session.clone(),
            "Bob".into(),
            bob.keys.classical.clone(),
            bob.keys.half(),
            t,
        )
        .unwrap();
    let bob_seen = peer_card(r.on_frame(fb, t).unwrap());
    let alice_seen = i.verified_peer().unwrap();
    assert_eq!(bob_seen.name(), "Bob");
    assert_eq!(alice_seen.name(), "Alice");
    assert_eq!(
        r.verified_peer().unwrap().account_id(),
        bob_seen.account_id()
    );

    // The creator (smaller account id) makes the pair's mailbox on the
    // shim and sends its offer; the other side pins with it.
    let a_creates = alice
        .session
        .creates_contact_zone(bob_seen.clone())
        .unwrap();
    assert_ne!(
        a_creates,
        bob.session
            .creates_contact_zone(alice_seen.clone())
            .unwrap()
    );
    let (on_alice, on_bob) = if a_creates {
        let offer = alice
            .zones
            .contact_zone_create(alice.session.clone(), bob_seen.card(), t)
            .unwrap();
        let got = zone_offer(i.on_frame(r.send_zone_offer(offer, t).unwrap(), t).unwrap());
        (
            alice
                .session
                .finish_contact_session(bob_seen, None, t)
                .unwrap(),
            bob.session
                .finish_contact_session(alice_seen, Some(got), t)
                .unwrap(),
        )
    } else {
        let offer = bob
            .zones
            .contact_zone_create(bob.session.clone(), alice_seen.card(), t)
            .unwrap();
        let got = zone_offer(r.on_frame(i.send_zone_offer(offer, t).unwrap(), t).unwrap());
        (
            alice
                .session
                .finish_contact_session(bob_seen, Some(got), t)
                .unwrap(),
            bob.session
                .finish_contact_session(alice_seen, None, t)
                .unwrap(),
        )
    };
    assert!(matches!(
        i.on_frame(r.confirm_pinned(t).unwrap(), t).unwrap(),
        FfiContactOutcome::Done
    ));
    assert!(matches!(
        r.on_frame(i.end(t).unwrap(), t).unwrap(),
        FfiContactOutcome::Done
    ));

    for c in [&on_alice, &on_bob] {
        assert_eq!(c.level, FfiContactLevel::Verified);
        assert_eq!(c.state, FfiContactState::Active);
        assert_eq!(c.verified_at, t);
        assert_eq!(c.safety_number.len(), 12 * 5 + 11);
    }
    assert_eq!(on_alice.name_local, "Bob");
    assert_eq!(on_bob.name_local, "Alice");
    assert_eq!(on_alice.safety_number, on_bob.safety_number);
    assert_eq!(alice.session.contacts().unwrap(), vec![on_alice.clone()]);
    assert_eq!(bob.session.contacts().unwrap(), vec![on_bob]);

    // Both sides sync the pair's zone over the shim.
    for p in [&alice, &bob] {
        let r = p
            .zones
            .run_round(Some(p.session.clone()), p.store.clone(), t);
        assert_eq!(r.zones.len(), 1, "{:?}", r.zones);
        assert_eq!(r.zones[0].zone.kind, FfiZoneKind::Contact);
        assert_eq!(r.zones[0].status, FfiRoundStatus::Idle, "{:?}", r.zones);
    }

    // Rename stays local; removal ends the contact.
    alice
        .session
        .rename_contact(on_alice.account_id.clone(), "Bob (travail)".into())
        .unwrap();
    assert_eq!(
        alice.session.contacts().unwrap()[0].name_local,
        "Bob (travail)"
    );
    alice
        .session
        .remove_contact(on_alice.account_id.clone(), t + 1)
        .unwrap();
    let removed = &alice.session.contacts().unwrap()[0];
    assert_eq!(removed.state, FfiContactState::Removed { at: t + 1 });
    assert!(removed.safety_number.is_empty());
}

#[test]
fn remote_invite_links_then_safety_number_verifies() {
    let shim = Shim::start();
    let alice = person(&shim, "Alice");
    let bob = person(&shim, "Bob");
    let e = shim.endpoint();
    let ca = e.extra_ca_pem.clone();
    let t = now();

    let invite = alice.session.create_contact_invite(None, t).unwrap();
    assert!(invite.expires_at > t);
    assert_eq!(invite.rdv_id.len(), 16);
    let hosted = alice
        .session
        .create_contact_invite(Some("onepass.example".into()), t)
        .unwrap();
    assert!(hosted.link.contains("onepass.example"));

    // Bob replies through the drop, and keeps his pending side across a
    // restart (Keychain bytes).
    let reply = bob
        .session
        .contact_invite_reply(invite.link.clone(), "Bob".into(), t)
        .unwrap();
    assert_eq!(reply.rdv_id, invite.rdv_id);
    // A sealed reply is larger than one 64 KiB slot.
    assert!(reply.bytes.len() > 64 * 1024);
    assert!(matches!(
        drop_put(
            e.base_url.clone(),
            reply.rdv_id.clone(),
            0,
            reply.bytes.clone(),
            ca.clone()
        ),
        Err(OnePassError::MailboxUnavailable { .. })
    ));
    invite_put(
        e.base_url.clone(),
        reply.rdv_id.clone(),
        FfiInvitePart::Reply,
        reply.bytes.clone(),
        ca.clone(),
    )
    .unwrap();
    // A retry of the same bytes passes; other bytes are a conflict.
    invite_put(
        e.base_url.clone(),
        reply.rdv_id.clone(),
        FfiInvitePart::Reply,
        reply.bytes.clone(),
        ca.clone(),
    )
    .unwrap();
    assert_eq!(
        invite_put(
            e.base_url.clone(),
            reply.rdv_id.clone(),
            FfiInvitePart::Reply,
            vec![1; 10],
            ca.clone(),
        ),
        Err(OnePassError::Conflict)
    );
    assert_eq!(
        invite_get(
            e.base_url.clone(),
            reply.rdv_id.clone(),
            FfiInvitePart::Answer,
            ca.clone()
        )
        .unwrap(),
        None
    );
    let kept = pending_invite_from_bytes(reply.pending.to_bytes()).unwrap();
    assert_eq!(kept.rdv_id(), invite.rdv_id);
    assert!(pending_invite_from_bytes(vec![9, 9]).is_err());

    // Alice reads the reply, makes the pair's mailbox, accepts.
    let got = invite_get(
        e.base_url.clone(),
        invite.rdv_id.clone(),
        FfiInvitePart::Reply,
        ca.clone(),
    )
    .unwrap()
    .unwrap();
    assert_eq!(got, reply.bytes);
    let card = alice
        .session
        .invite_reply_card(invite.invite_id.clone(), got.clone(), t)
        .unwrap();
    let offer = alice
        .zones
        .contact_zone_create(alice.session.clone(), card, t)
        .unwrap();
    let accepted = alice
        .session
        .accept_invite_reply(
            invite.invite_id.clone(),
            got.clone(),
            "Alice".into(),
            offer,
            t,
        )
        .unwrap();
    assert_eq!(accepted.contact.level, FfiContactLevel::Link);
    assert_eq!(accepted.contact.name_local, "Bob");
    // The invitation is used.
    assert!(
        alice
            .session
            .accept_invite_reply(invite.invite_id.clone(), got, "Alice".into(), vec![], t)
            .is_err()
    );
    invite_put(
        e.base_url.clone(),
        invite.rdv_id.clone(),
        FfiInvitePart::Answer,
        accepted.answer,
        ca.clone(),
    )
    .unwrap();

    // Bob finishes from the kept bytes.
    let answer = invite_get(
        e.base_url.clone(),
        invite.rdv_id.clone(),
        FfiInvitePart::Answer,
        ca.clone(),
    )
    .unwrap()
    .unwrap();
    for part in [FfiInvitePart::Reply, FfiInvitePart::Answer] {
        invite_delete(e.base_url.clone(), invite.rdv_id.clone(), part, ca.clone()).unwrap();
    }
    let on_bob = bob.session.finish_invite(kept, answer, t).unwrap();
    assert_eq!(on_bob.level, FfiContactLevel::Link);
    assert_eq!(on_bob.name_local, "Alice");
    assert_eq!(on_bob.safety_number, accepted.contact.safety_number);

    // Compared by voice: a wrong number is refused, the right one verifies.
    let wrong = "00000 ".repeat(12);
    assert!(matches!(
        bob.session
            .confirm_safety_number(on_bob.account_id.clone(), wrong, t + 1),
        Err(OnePassError::Validation { .. })
    ));
    let v = bob
        .session
        .confirm_safety_number(
            on_bob.account_id.clone(),
            on_bob.safety_number.clone(),
            t + 1,
        )
        .unwrap();
    assert_eq!(v.level, FfiContactLevel::Verified);
    assert_eq!(v.verified_at, t + 1);
    let a = alice
        .session
        .confirm_safety_number(
            accepted.contact.account_id.clone(),
            accepted.contact.safety_number.clone(),
            t + 1,
        )
        .unwrap();
    assert_eq!(a.level, FfiContactLevel::Verified);
    // Twice is refused.
    assert!(
        alice
            .session
            .confirm_safety_number(a.account_id, a.safety_number, t + 2)
            .is_err()
    );
}

#[test]
fn failing_pq_half_pins_nothing() {
    let shim = Shim::start();
    let alice = person(&shim, "Alice");
    let t = now();
    let start = contact_responder_start(t).unwrap();
    let begin = contact_initiator_begin(start.qr, start.hello, t).unwrap();
    start
        .responder
        .on_key_exchange(begin.key_exchange, t)
        .unwrap();
    let broken: Arc<dyn FfiPqDeviceHalf> = Arc::new(BrokenHalf(
        SoftwarePqHalf::from_bytes(&alice.keys.pq).unwrap(),
    ));
    assert!(
        start
            .responder
            .confirm_and_send_card(
                alice.session.clone(),
                "Alice".into(),
                alice.keys.classical.clone(),
                broken,
                t,
            )
            .is_err()
    );
    assert!(start.responder.verified_peer().is_none());
    assert!(alice.session.contacts().unwrap().is_empty());
    // A QR that is not one is refused before anything.
    assert!(contact_initiator_begin("pas un QR".into(), vec![1], t).is_err());
}

#[test]
fn contact_zone_create_needs_network() {
    let shim = Shim::start();
    let alice = person(&shim, "Alice");
    let bob = person(&shim, "Bob");
    let t = now();
    let card = {
        // Bob's card, as a reply carries it.
        let invite = alice.session.create_contact_invite(None, t).unwrap();
        let reply = bob
            .session
            .contact_invite_reply(invite.link, "Bob".into(), t)
            .unwrap();
        alice
            .session
            .invite_reply_card(invite.invite_id, reply.bytes, t)
            .unwrap()
    };
    // A server nobody answers: the error says so, nothing is pinned.
    let seeds = Arc::new(MemSeeds::default());
    let offline = ZoneSyncHandle::new(
        seeds,
        "https://localhost:9/functions/v1/mailbox".into(),
        shim.endpoint().extra_ca_pem,
    );
    assert!(matches!(
        offline.contact_zone_create(alice.session.clone(), card, t),
        Err(OnePassError::MailboxUnavailable { .. })
    ));
    assert!(alice.session.contacts().unwrap().is_empty());
}
