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
    secret_key: String,
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
        secret_key: created.secret_key,
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

// ---- Task 3 -----------------------------------------------------------------

/// Alice and Bob verified face to face through the FFI, the pair's
/// mailbox made by the creator and synced on both sides.
fn verified_pair(shim: &Shim) -> (Person, Person) {
    let alice = person(shim, "Alice");
    let bob = person(shim, "Bob");
    let t = now();
    let start = contact_responder_start(t).unwrap();
    let begin = contact_initiator_begin(start.qr, start.hello, t).unwrap();
    let (r, i) = (start.responder, begin.initiator);
    r.on_key_exchange(begin.key_exchange, t).unwrap();
    let fa = r
        .confirm_and_send_card(
            alice.session.clone(),
            "Alice".into(),
            alice.keys.classical.clone(),
            alice.keys.half(),
            t,
        )
        .unwrap();
    i.on_frame(fa, t).unwrap();
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
    if alice
        .session
        .creates_contact_zone(bob_seen.clone())
        .unwrap()
    {
        let offer = alice
            .zones
            .contact_zone_create(alice.session.clone(), bob_seen.card(), t)
            .unwrap();
        let got = zone_offer(i.on_frame(r.send_zone_offer(offer, t).unwrap(), t).unwrap());
        alice
            .session
            .finish_contact_session(bob_seen, None, t)
            .unwrap();
        bob.session
            .finish_contact_session(alice_seen, Some(got), t)
            .unwrap();
    } else {
        let offer = bob
            .zones
            .contact_zone_create(bob.session.clone(), alice_seen.card(), t)
            .unwrap();
        let got = zone_offer(r.on_frame(i.send_zone_offer(offer, t).unwrap(), t).unwrap());
        bob.session
            .finish_contact_session(alice_seen, None, t)
            .unwrap();
        alice
            .session
            .finish_contact_session(bob_seen, Some(got), t)
            .unwrap();
    }
    settle_zones(&[&alice, &bob]);
    (alice, bob)
}

/// Zone rounds on every side until two passes in a row run no action,
/// bring nothing and leave every zone idle (a push of the last side is
/// fetched by the others on the next pass).
fn settle_zones(people: &[&Person]) -> Vec<FfiZoneRoundReport> {
    let mut last = Vec::new();
    let mut quiet_passes = 0;
    for _ in 0..10 {
        last = people
            .iter()
            .map(|p| {
                p.zones
                    .run_round(Some(p.session.clone()), p.store.clone(), now())
            })
            .collect();
        let quiet = last.iter().all(|r| {
            r.actions_done == 0
                && !r.rerun
                && !r.changed
                && r.zones.iter().all(|z| z.status == FfiRoundStatus::Idle)
        });
        quiet_passes = if quiet { quiet_passes + 1 } else { 0 };
        if quiet_passes == 2 {
            return last;
        }
    }
    panic!("zones never settled: {last:?}");
}

fn item_in(session: &Session, vault_id: &str, title: &str) -> FfiItem {
    let mut item = session
        .new_item(vault_id.into(), FfiItemType::Login, title.into())
        .unwrap();
    for f in item.sections.iter_mut().flat_map(|s| s.fields.iter_mut()) {
        if f.id == "username" {
            f.value = FfiFieldValue::Text {
                value: "famille@exemple.fr".into(),
            };
        }
    }
    item
}

fn vault_titles(session: &Session, vault_id: &str) -> Vec<String> {
    let mut t: Vec<String> = session
        .item_summaries()
        .unwrap()
        .into_iter()
        .filter(|s| s.vault_id == vault_id)
        .map(|s| s.title)
        .collect();
    t.sort();
    t
}

#[test]
fn shared_vault_round_trip_through_the_ffi() {
    let shim = Shim::start();
    let (alice, bob) = verified_pair(&shim);
    let t = now();
    let bob_id = bob.session.account_id();

    let v = alice
        .session
        .create_vault(FfiVaultMeta {
            name: "Famille".into(),
            icon: "house".into(),
            color: "blue".into(),
            travel_safe: false,
            mcp_access: false,
        })
        .unwrap();
    alice
        .session
        .save_item(item_in(&alice.session, &v.id, "Banque"))
        .unwrap();
    let shared = alice.session.share_vault(v.id.clone(), t).unwrap();
    assert_eq!(shared.vault_id, v.id);
    assert_eq!((shared.role, shared.owner), (FfiRole::Manage, true));
    // Members are added once the vault's mailbox exists (zone round).
    assert!(
        alice
            .session
            .add_member(v.id.clone(), bob_id.clone(), FfiRole::Write, t)
            .is_err()
    );
    settle_zones(&[&alice]);
    let shared = alice
        .session
        .add_member(v.id.clone(), bob_id.clone(), FfiRole::Write, t)
        .unwrap();
    assert_eq!(shared.members.len(), 2);
    let listed = alice.session.vaults().unwrap();
    let mine = listed.iter().find(|x| x.id == v.id).unwrap();
    assert_eq!(mine.shared.as_ref().unwrap().members.len(), 2);
    assert!(
        listed
            .iter()
            .filter(|x| x.id != v.id)
            .all(|x| x.shared.is_none())
    );
    settle_zones(&[&alice, &bob]);

    // Bob sees the invitation, accepts, reads and writes.
    let invites = bob.session.share_invites().unwrap();
    assert_eq!(invites.len(), 1, "{invites:?}");
    assert_eq!(invites[0].role, FfiRole::Write);
    let joined = bob
        .session
        .accept_share_invite(invites[0].id.clone(), t)
        .unwrap();
    assert_eq!(joined.role, FfiRole::Write);
    settle_zones(&[&alice, &bob]);
    assert_eq!(vault_titles(&bob.session, &v.id), vec!["Banque"]);
    bob.session
        .save_item(item_in(&bob.session, &v.id, "Courses"))
        .unwrap();
    assert_eq!(vault_titles(&bob.session, &v.id), vec!["Banque", "Courses"]);
    settle_zones(&[&alice, &bob]);
    assert_eq!(
        vault_titles(&alice.session, &v.id),
        vec!["Banque", "Courses"]
    );

    // Down to Read: Bob's write is refused with its own kind.
    alice
        .session
        .set_role(v.id.clone(), bob_id.clone(), FfiRole::Read, t)
        .unwrap();
    settle_zones(&[&alice, &bob]);
    let bobs = bob.session.shared_vaults().unwrap();
    assert_eq!(bobs[0].role, FfiRole::Read);
    assert_eq!(
        bob.session
            .save_item(item_in(&bob.session, &v.id, "Interdit"))
            .unwrap_err(),
        OnePassError::ReadOnlyRole
    );

    // Removal: a new key, and every live item counted as seen.
    let removal = alice
        .session
        .remove_member(v.id.clone(), bob_id.clone(), t + 1)
        .unwrap();
    assert_eq!(removal.seen_items, 2);
    assert!(removal.generation > shared.generation);
    let info = &alice.session.shared_vaults().unwrap()[0];
    assert_eq!(info.members.len(), 1);
    assert_eq!(info.generation, removal.generation);
    assert_eq!(alice.session.seen_by_former_members().unwrap().len(), 2);
    settle_zones(&[&alice, &bob]);
    assert!(bob.session.shared_vaults().unwrap().is_empty());
    assert!(vault_titles(&bob.session, &v.id).is_empty());

    // Alone again, the owner makes the vault personal.
    let back = alice.session.stop_sharing(v.id.clone(), t + 2).unwrap();
    assert!(back.shared.is_none());
    assert_eq!(
        vault_titles(&alice.session, &back.id),
        vec!["Banque", "Courses"]
    );
}

/// Alice shares "Famille" with Bob at `role`, Bob accepts, all settled.
fn shared_with_bob(alice: &Person, bob: &Person, role: FfiRole) -> String {
    let t = now();
    let v = alice
        .session
        .create_vault(FfiVaultMeta {
            name: "Famille".into(),
            icon: "house".into(),
            color: "blue".into(),
            travel_safe: false,
            mcp_access: false,
        })
        .unwrap();
    alice
        .session
        .save_item(item_in(&alice.session, &v.id, "Banque"))
        .unwrap();
    alice.session.share_vault(v.id.clone(), t).unwrap();
    settle_zones(&[alice]);
    alice
        .session
        .add_member(v.id.clone(), bob.session.account_id(), role, t)
        .unwrap();
    settle_zones(&[alice, bob]);
    let invite = bob.session.share_invites().unwrap().remove(0);
    bob.session.accept_share_invite(invite.id, t).unwrap();
    settle_zones(&[alice, bob]);
    v.id
}

/// Bob rotates his keys; the 6-digit code he reads out.
fn bob_rotates(bob: &Person) -> u32 {
    let out = bob
        .session
        .rotate_keys(
            FfiRotateRequest {
                revoke: vec![],
                new_password: None,
                password: PASSWORD.into(),
                secret_key: bob.secret_key.clone(),
                new_secret_key: generate_secret_key().unwrap(),
                reason: FfiRotationReason::Rotate,
                keep_tofu: vec![],
            },
            bob.keys.classical.clone(),
            bob.keys.half(),
        )
        .unwrap();
    out.code
        .chars()
        .filter(char::is_ascii_digit)
        .collect::<String>()
        .parse()
        .unwrap()
}

#[test]
fn reader_adopted_by_code_writer_needs_in_person() {
    let shim = Shim::start();
    let (alice, bob) = verified_pair(&shim);
    let vault = shared_with_bob(&alice, &bob, FfiRole::Write);
    let code = bob_rotates(&bob);
    // Alice's vault zone waits on Bob's new identity (Retrying) until she
    // confirms it: a few passes, not a settle.
    for _ in 0..3 {
        for p in [&bob, &alice] {
            p.zones
                .run_round(Some(p.session.clone()), p.store.clone(), now());
        }
    }
    let t = now();
    let changes = alice.session.refresh_member_identities(t).unwrap();
    assert_eq!(changes.len(), 1, "{changes:?}");
    let change = &changes[0];
    assert_eq!(change.account_id, bob.session.account_id());
    assert_eq!(change.vaults, vec![vault.clone()]);
    assert_eq!(change.child.len(), 64);

    // A writer's new identity needs a face-to-face session.
    assert_eq!(
        alice
            .session
            .adopt_member_identity(
                change.account_id.clone(),
                change.child.clone(),
                FfiAdoptionProof::Code { code },
                t,
            )
            .unwrap_err(),
        OnePassError::ContactNotVerified
    );
    assert!(matches!(
        alice.session.adopt_member_identity(
            change.account_id.clone(),
            "zz".into(),
            FfiAdoptionProof::Code { code },
            t,
        ),
        Err(OnePassError::InvalidInput { .. })
    ));

    // Down to Read, the code is enough.
    alice
        .session
        .set_role(vault.clone(), change.account_id.clone(), FfiRole::Read, t)
        .unwrap();
    let adopted = alice
        .session
        .adopt_member_identity(
            change.account_id.clone(),
            change.child.clone(),
            FfiAdoptionProof::Code { code },
            t + 1,
        )
        .unwrap();
    assert_eq!(adopted.len(), 1);
    // Bob takes the renewed credential after the old one is refused, then
    // follows the new body: no refusal reaches the app.
    for _ in 0..4 {
        for p in [&alice, &bob] {
            let r = p
                .zones
                .run_round(Some(p.session.clone()), p.store.clone(), now());
            assert!(r.refusals.is_empty(), "{r:?}");
        }
    }
    let bobs = bob.session.shared_vaults().unwrap();
    assert!(!bobs[0].identity_pending, "{bobs:?}");
    assert_eq!(vault_titles(&bob.session, &vault), vec!["Banque"]);
}
