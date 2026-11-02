//! Face-to-face contact verification (sharing spec 5.3.1, S2, plan ruling
//! A-2): two accounts in memory, the pairing channel under the contact
//! label, no transport. Synthetic data only.

mod common;

use common::*;
use onepass_core::contact::ContactEntry;
use onepass_core::contact::pair_id;
use onepass_core::contact::{
    CONTACT_LABEL, CONTACT_SESSION_SECS, ContactHello, ContactInitiator, ContactLevel,
    ContactMessage, ContactOutcome, ContactResponder, MAX_CONTACT_MESSAGE_BYTES, SignedContactCard,
    VerifiedPeer,
};
use onepass_core::crypto::{Aad, BlobKind, HybridKemSecret, SymmetricKey, open};
use onepass_core::device_keys::{DeviceKeys, DevicePublic, sign_pop};
use onepass_core::devices::{DeviceKind, DeviceMode};
use onepass_core::lineage::{
    GenesisBody, LINEAGE_FORMAT, LineageRecord, RosterEntry, sign_genesis,
};
use onepass_core::pairing::{Approver, Channel, DeviceInfo, Message, Newcomer};
use onepass_core::share::{AccessTarget, ZoneHome};
use onepass_core::store::Zone;
use onepass_core::trust::{LineageHead, TrustLevel, TrustState};

fn entry_of(p: &DevicePublic, name: &str) -> RosterEntry {
    RosterEntry {
        device_id: p.device_id,
        sign_pub: p.sign_pub.clone(),
        kem_pub: p.kem_pub.clone(),
        name: name.into(),
        kind: DeviceKind::Phone,
        mode: DeviceMode::Personal,
        introduced_by: None,
    }
}

/// One account on one device, at its genesis, whose roster is this device:
/// the device, its keys and its own contact card.
struct Person {
    dev: Device,
    keys: DeviceKeys,
    device_id: Id,
    card: SignedContactCard,
}

fn person(name: &str) -> Person {
    let mut server = Server::default();
    let (mut dev, _) = Device::create();
    sync(&mut server, &mut dev).unwrap();
    let keys = DeviceKeys::generate_software().unwrap();
    let device_id = dev.repo().chain().device_id.unwrap();
    let me = keys.public(device_id).unwrap();
    let account = dev.repo().account();
    let account_id = account.params.account_id;
    let identity_pub = account.params.identity_pub.clone();
    let genesis = LineageRecord::Genesis(
        sign_genesis(
            GenesisBody {
                format: LINEAGE_FORMAT,
                account_id,
                identity_pub: identity_pub.clone(),
                creator: entry_of(&me, "iPhone"),
                created_at: T0,
            },
            &keys,
            &account.keyset().identity,
        )
        .unwrap(),
    );
    let mut trust = TrustState::new(
        account_id,
        me.clone(),
        LineageHead {
            generation: 0,
            hash: genesis.hash(),
        },
        identity_pub,
        vec![entry_of(&me, "iPhone")],
        DeviceLineageState::Current,
    );
    trust.levels.insert(me.device_id, TrustLevel::Verified);
    let record = Record {
        id: genesis.record_id(),
        kind: RecordKind::Lineage,
        version: 0,
        data: genesis.encode(),
    };
    dev.repo()
        .store_mut()
        .put_all_if_version_with_trust(vec![(record, None)], vec![], None, &trust)
        .unwrap();
    let card = dev.repo().own_contact_card(name, T0 + 10).unwrap();
    Person {
        dev,
        keys,
        device_id,
        card,
    }
}

const NOW: i64 = T0 + 100;

/// The context a contact proof of possession signs.
fn ctx(transcript: [u8; 32]) -> Vec<u8> {
    [CONTACT_LABEL, &transcript].concat()
}

/// `device`'s card message with a proof over `context`.
fn card_msg(p: &Person, context: &[u8]) -> ContactMessage {
    let device = p.keys.public(p.device_id).unwrap();
    let pop = sign_pop(&p.keys, context, &device).unwrap();
    ContactMessage::Card {
        card: p.card.clone(),
        device,
        pop,
    }
}

fn is_validation<T: std::fmt::Debug>(r: &Result<T>) -> bool {
    matches!(r, Err(Error::Validation(_)))
}

/// Both sides up to the SAS: (responder, initiator, sas_r, sas_i).
fn handshake() -> (ContactResponder, ContactInitiator, String, String) {
    let (mut r, qr, hello) = ContactResponder::new(NOW).unwrap();
    let (i, kx, sas_i) = ContactInitiator::begin(&qr.to_text(), &hello, NOW + 1).unwrap();
    let sas_r = r.on_key_exchange(&kx, NOW + 2).unwrap();
    (r, i, sas_r, sas_i)
}

fn zone_home() -> ZoneHome {
    ZoneHome {
        url: "https://box.example.org".into(),
        mailbox_id: [6; 16],
        extra_ca_pem: None,
    }
}

/// Both sides pin, with the pair's mailbox: the creator (smaller account
/// id) prepares the zone and sends its offer over the session; the other
/// side pins with that offer. Alice is the responder `r`, Bob the
/// initiator `i`.
fn finish_with_zone(
    alice: &mut Person,
    bob: &mut Person,
    r: &mut ContactResponder,
    i: &mut ContactInitiator,
    bob_peer: VerifiedPeer,
    alice_peer: VerifiedPeer,
) -> (ContactEntry, ContactEntry) {
    let a_id = alice.card.card.account_id;
    let b_id = bob.card.card.account_id;
    if a_id < b_id {
        let plan = alice
            .dev
            .repo()
            .prepare_contact_zone(&bob.card, NOW + 5)
            .unwrap();
        let offer = alice
            .dev
            .repo()
            .seal_contact_zone_offer(plan, zone_home())
            .unwrap();
        let f = r.send_zone_offer(&offer, NOW + 5).unwrap();
        let got = match i.on_frame(&f, NOW + 5).unwrap() {
            ContactOutcome::PeerZoneOffer(o) => o,
            other => panic!("{other:?}"),
        };
        let on_alice = alice
            .dev
            .repo()
            .finish_contact_session(bob_peer, None, NOW + 5)
            .unwrap();
        let on_bob = bob
            .dev
            .repo()
            .finish_contact_session(alice_peer, Some(&got), NOW + 5)
            .unwrap();
        (on_alice, on_bob)
    } else {
        let plan = bob
            .dev
            .repo()
            .prepare_contact_zone(&alice.card, NOW + 5)
            .unwrap();
        let offer = bob
            .dev
            .repo()
            .seal_contact_zone_offer(plan, zone_home())
            .unwrap();
        let f = i.send_zone_offer(&offer, NOW + 5).unwrap();
        let got = match r.on_frame(&f, NOW + 5).unwrap() {
            ContactOutcome::PeerZoneOffer(o) => o,
            other => panic!("{other:?}"),
        };
        let on_bob = bob
            .dev
            .repo()
            .finish_contact_session(alice_peer, None, NOW + 5)
            .unwrap();
        let on_alice = alice
            .dev
            .repo()
            .finish_contact_session(bob_peer, Some(&got), NOW + 5)
            .unwrap();
        (on_alice, on_bob)
    }
}

#[test]
fn face_to_face_pins_both_sides() {
    let mut alice = person("Alice");
    let mut bob = person("Bob");
    let (mut r, mut i, sas_r, sas_i) = handshake();
    assert_eq!(sas_r, sas_i);
    assert_eq!(r.transcript_hash(), i.transcript_hash());

    // Bob (initiator) confirms first: his card waits on Alice's side until
    // her own user confirmed.
    let to_alice = i
        .confirm_and_send_card(&bob.card, &bob.keys, bob.device_id, NOW + 3)
        .unwrap();
    assert_eq!(
        r.on_frame(&to_alice, NOW + 3).unwrap(),
        ContactOutcome::Waiting
    );
    assert!(r.verified_peer().is_none());
    let to_bob = r
        .confirm_and_send_card(&alice.card, &alice.keys, alice.device_id, NOW + 4)
        .unwrap();
    let bob_peer = r.verified_peer().expect("verified once confirmed");
    let alice_peer = match i.on_frame(&to_bob, NOW + 4).unwrap() {
        ContactOutcome::PeerCard(c) => c,
        other => panic!("{other:?}"),
    };
    assert_eq!(*bob_peer.card(), bob.card);
    assert_eq!(*alice_peer.card(), alice.card);
    assert_eq!(bob_peer.transcript_hash(), r.transcript_hash());
    assert_eq!(alice_peer.transcript_hash(), i.transcript_hash());
    // A real card is far below the message cap.
    assert!(alice.card.encode().len() < MAX_CONTACT_MESSAGE_BYTES / 20);

    // The smaller account id creates the pair's mailbox and sends its
    // offer once both cards are through.
    let (on_alice, on_bob) =
        finish_with_zone(&mut alice, &mut bob, &mut r, &mut i, bob_peer, alice_peer);
    assert_eq!(on_alice.level, ContactLevel::Verified);
    assert_eq!(on_bob.level, ContactLevel::Verified);
    assert_eq!(on_alice.transcript_hash, on_bob.transcript_hash);
    assert_eq!(on_alice.account_id, bob.card.card.account_id);
    assert_eq!(on_bob.account_id, alice.card.card.account_id);

    // Both say they pinned, then the session is over.
    let f = i.confirm_pinned(NOW + 6).unwrap();
    assert_eq!(r.on_frame(&f, NOW + 6).unwrap(), ContactOutcome::Done);
    let f = r.confirm_pinned(NOW + 6).unwrap();
    assert_eq!(i.on_frame(&f, NOW + 6).unwrap(), ContactOutcome::Done);
    let f = r.end(NOW + 7).unwrap();
    assert_eq!(i.on_frame(&f, NOW + 7).unwrap(), ContactOutcome::Done);
    assert!(i.on_frame(&f, NOW + 7).is_err());
}

#[test]
fn mitm_on_transport_refused() {
    let mallory = person("Mallory");

    // A relay swaps its own ephemeral key into the Hello: the QR's hash
    // does not match.
    let (_, qr, hello) = ContactResponder::new(NOW).unwrap();
    let real = ContactHello::from_bytes(&hello).unwrap();
    let forged = ContactHello {
        session_id: real.session_id,
        ephemeral_public: HybridKemSecret::generate().unwrap().public().unwrap(),
    }
    .to_bytes()
    .unwrap();
    assert!(matches!(
        ContactInitiator::begin(&qr.to_text(), &forged, NOW + 1),
        Err(Error::Integrity(IntegrityError::WrongContext))
    ));

    // A relay swaps the key exchange: it scanned the same QR and answers
    // with its own session key. The codes differ, and Mallory's card never
    // comes out of the responder's session without a confirmation.
    let (mut r, qr, hello) = ContactResponder::new(NOW).unwrap();
    let (honest, _kx_bob, sas_bob) =
        ContactInitiator::begin(&qr.to_text(), &hello, NOW + 1).unwrap();
    let (mut relay, kx_relay, _) = ContactInitiator::begin(&qr.to_text(), &hello, NOW + 1).unwrap();
    let sas_r = r.on_key_exchange(&kx_relay, NOW + 2).unwrap();
    assert_ne!(sas_r, sas_bob);
    let f = relay
        .confirm_and_send_card(&mallory.card, &mallory.keys, mallory.device_id, NOW + 3)
        .unwrap();
    assert_eq!(r.on_frame(&f, NOW + 3).unwrap(), ContactOutcome::Waiting);
    assert!(r.verified_peer().is_none());
    // Bob's side has nothing from the responder: it never confirmed, so
    // no card was sealed for anyone.
    assert!(honest.verified_peer().is_none());
}

#[test]
fn card_before_confirm_refused() {
    let alice = person("Alice");
    let (mut r, _, _) = ContactResponder::new(NOW).unwrap();
    assert!(is_validation(&r.confirm_and_send_card(
        &alice.card,
        &alice.keys,
        alice.device_id,
        NOW + 1
    )));
    // A key exchange the responder never got leaves no channel either.
    assert!(r.on_frame(&[0u8; 64], NOW + 1).is_err());
}

#[test]
fn pop_for_other_transcript_refused() {
    let mut alice = person("Alice");
    let bob = person("Bob");
    let (mut r, mut i, _, _) = handshake();
    r.confirm_and_send_card(&alice.card, &alice.keys, alice.device_id, NOW + 3)
        .unwrap();
    // Bob's card with a proof over another session's transcript.
    let f = i
        .test_seal(&card_msg(&bob, &ctx([0x55; 32])), NOW + 4)
        .unwrap();
    assert!(matches!(
        r.on_frame(&f, NOW + 4),
        Err(Error::Integrity(IntegrityError::Signature))
    ));
    assert!(r.verified_peer().is_none());
    // The session is closed.
    assert!(r.end(NOW + 5).is_err());
    assert!(alice.dev.repo().contacts().unwrap().is_empty());
}

#[test]
fn device_outside_the_roster_refused() {
    let alice = person("Alice");
    let bob = person("Bob");
    let (mut r, mut i, _, _) = handshake();
    r.confirm_and_send_card(&alice.card, &alice.keys, alice.device_id, NOW + 3)
        .unwrap();
    // Bob's card replayed by a device Bob's account does not list, with a
    // valid proof over this transcript.
    let thief = DeviceKeys::generate_software().unwrap();
    let device = thief.public(Id::new()).unwrap();
    let pop = sign_pop(&thief, &ctx(i.transcript_hash()), &device).unwrap();
    let f = i
        .test_seal(
            &ContactMessage::Card {
                card: bob.card.clone(),
                device,
                pop,
            },
            NOW + 4,
        )
        .unwrap();
    assert!(matches!(
        r.on_frame(&f, NOW + 4),
        Err(Error::Integrity(IntegrityError::WrongContext))
    ));
    assert!(r.verified_peer().is_none());
    assert!(r.end(NOW + 5).is_err());
}

#[test]
fn pairing_pop_refused() {
    let bob = person("Bob");
    let (mut r, mut i, _, _) = handshake();
    // A proof of possession over the bare transcript, as the rotation v2
    // pairing proof is made: not a contact proof.
    let f = i
        .test_seal(&card_msg(&bob, &i.transcript_hash()), NOW + 3)
        .unwrap();
    assert!(matches!(
        r.on_frame(&f, NOW + 3),
        Err(Error::Integrity(IntegrityError::Signature))
    ));
    assert!(r.end(NOW + 4).is_err());

    // A second card in one session closes it, even the same good one.
    let (mut r, mut i, _, _) = handshake();
    let msg = card_msg(&bob, &ctx(i.transcript_hash()));
    let f = i.test_seal(&msg, NOW + 3).unwrap();
    assert_eq!(r.on_frame(&f, NOW + 3).unwrap(), ContactOutcome::Waiting);
    let f = i.test_seal(&msg, NOW + 3).unwrap();
    assert!(is_validation(&r.on_frame(&f, NOW + 3)));
    assert!(r.verified_peer().is_none());
    assert!(r.end(NOW + 4).is_err());
}

#[test]
fn state_machine_refusals() {
    // The key exchange is taken once.
    let (mut r, qr, hello) = ContactResponder::new(NOW).unwrap();
    let (_, kx, _) = ContactInitiator::begin(&qr.to_text(), &hello, NOW + 1).unwrap();
    r.on_key_exchange(&kx, NOW + 2).unwrap();
    assert!(is_validation(&r.on_key_exchange(&kx, NOW + 2)));

    // Not after the QR expired, and the failed try uses the session up.
    let (mut r, qr, hello) = ContactResponder::new(NOW).unwrap();
    let (_, kx, _) = ContactInitiator::begin(&qr.to_text(), &hello, NOW + 1).unwrap();
    assert!(r.on_key_exchange(&kx, NOW + 121).is_err());
    assert!(r.on_key_exchange(&kx, NOW + 2).is_err());
    assert!(r.end(NOW + 2).is_err());

    // `Confirmed` before any card: refused, closed.
    let (mut r, mut i, _, _) = handshake();
    let f = i.test_seal(&ContactMessage::Confirmed, NOW + 3).unwrap();
    assert!(is_validation(&r.on_frame(&f, NOW + 3)));
    assert!(r.end(NOW + 4).is_err());
    // `confirm_pinned` before a card was handed over: refused.
    assert!(is_validation(&i.confirm_pinned(NOW + 3)));

    // Nothing after `End`, either side.
    let (mut r, mut i, _, _) = handshake();
    let f = i.end(NOW + 3).unwrap();
    assert!(i.test_seal(&ContactMessage::Confirmed, NOW + 3).is_err());
    assert_eq!(r.on_frame(&f, NOW + 3).unwrap(), ContactOutcome::Done);
    assert!(r.on_frame(&f, NOW + 3).is_err());
    assert!(r.end(NOW + 3).is_err());
}

#[test]
fn session_expires_after_the_sas() {
    // The responder showed its SAS at NOW + 2: no frame after that plus
    // `CONTACT_SESSION_SECS`, and the session stays closed.
    let (mut r, mut i, _, _) = handshake();
    let late = NOW + 2 + CONTACT_SESSION_SECS + 1;
    let f = i.test_seal(&ContactMessage::Confirmed, NOW + 3).unwrap();
    assert!(r.on_frame(&f, late).is_err());
    assert!(r.end(NOW + 4).is_err());
    // The initiator showed its SAS at NOW + 1.
    assert!(i.end(NOW + 1 + CONTACT_SESSION_SECS + 1).is_err());
    assert!(i.end(NOW + 4).is_err());

    // Just in time still passes.
    let (mut r, mut i, _, _) = handshake();
    let f = i.end(NOW + 1 + CONTACT_SESSION_SECS).unwrap();
    assert_eq!(
        r.on_frame(&f, NOW + 2 + CONTACT_SESSION_SECS).unwrap(),
        ContactOutcome::Done
    );
}

#[test]
fn pairing_hello_not_a_contact_hello() {
    let device = DeviceInfo {
        device_id: Id::new(),
        name: "iPad de Camille".into(),
        kind: DeviceKind::Tablet,
    };
    let (_, qr, pairing_hello) = Newcomer::new(device, DeviceMode::Personal, NOW).unwrap();
    assert!(matches!(
        ContactInitiator::begin(&qr.to_text(), &pairing_hello, NOW + 1),
        Err(Error::InvalidFormat(_))
    ));
    let (_, qr, contact_hello) = ContactResponder::new(NOW).unwrap();
    assert!(matches!(
        Approver::begin(&qr.to_text(), &contact_hello, NOW + 1),
        Err(Error::InvalidFormat(_))
    ));
}

#[test]
fn own_card_refused() {
    let mut alice = person("Alice");
    // Alice scans her own QR (her other device, same account).
    let (mut r, mut i, _, _) = handshake();
    let to_r = i
        .confirm_and_send_card(&alice.card, &alice.keys, alice.device_id, NOW + 3)
        .unwrap();
    assert_eq!(r.on_frame(&to_r, NOW + 3).unwrap(), ContactOutcome::Waiting);
    // Confirming reveals the card is this account's own: refused, no card
    // goes out, the session closes.
    assert!(is_validation(&r.confirm_and_send_card(
        &alice.card,
        &alice.keys,
        alice.device_id,
        NOW + 4
    )));
    assert!(r.verified_peer().is_none());
    assert!(r.end(NOW + 5).is_err());

    // The other order: the initiator already confirmed when the card comes.
    let (mut r, mut i2, _, _) = handshake();
    let to_i = r
        .confirm_and_send_card(&alice.card, &alice.keys, alice.device_id, NOW + 3)
        .unwrap();
    i2.confirm_and_send_card(&alice.card, &alice.keys, alice.device_id, NOW + 3)
        .unwrap();
    assert!(is_validation(&i2.on_frame(&to_i, NOW + 4)));
    assert!(i2.verified_peer().is_none());

    // A session never yields one's own card; the repository refuses it
    // anyway.
    let own = VerifiedPeer::test_new(alice.card.clone(), [1; 32]);
    assert!(is_validation(&alice.dev.repo().finish_contact_session(
        own,
        None,
        NOW + 6
    )));
    assert!(alice.dev.repo().contacts().unwrap().is_empty());
}

#[test]
fn pairing_frames_unchanged() {
    // Every byte that enters a pairing frame, checked from outside the
    // channel: the subkey ("n2a" / "a2n" from K), the kind (Pairing), the
    // AAD (session id, last 8 bytes XOR the counter, no vault, schema 1)
    // and the plaintext (postcard of the message, variant index first).
    let k = SymmetricKey::from_bytes([7; 32]);
    let sid = [0x11u8; 16];
    let mut n = Channel::newcomer(&k, sid).unwrap();
    let mut a = Channel::approver(&k, sid).unwrap();
    let aad = |counter: u64| {
        let mut id = sid;
        for (b, c) in id[8..].iter_mut().zip(counter.to_be_bytes()) {
            *b ^= c;
        }
        Aad {
            blob_id: Id(id),
            vault_id: None,
            schema: 1,
        }
    };
    let n2a = k.derive(b"n2a").unwrap();
    let a2n = k.derive(b"a2n").unwrap();
    for (counter, (msg, plain)) in [
        (Message::Confirmed, vec![0u8]),
        (Message::Ack, vec![2u8]),
        (Message::Confirmed, vec![0u8]),
    ]
    .into_iter()
    .enumerate()
    {
        let f = n.seal_at(&msg, NOW).unwrap();
        assert_eq!(&f[..3], b"OPB");
        assert_eq!(f[5], 12);
        let got = open(&n2a, BlobKind::Pairing, &aad(counter as u64), &f).unwrap();
        assert_eq!(*got, plain);
        assert_eq!(a.open_at(&f, NOW).unwrap(), msg);

        let f = a.seal_at(&msg, NOW).unwrap();
        let got = open(&a2n, BlobKind::Pairing, &aad(counter as u64), &f).unwrap();
        assert_eq!(*got, plain);
        assert_eq!(n.open_at(&f, NOW).unwrap(), msg);
    }
    let f = n.seal_at(&Message::End, NOW).unwrap();
    assert_eq!(
        *open(&n2a, BlobKind::Pairing, &aad(3), &f).unwrap(),
        vec![4u8]
    );
    assert!(n.is_closed(NOW));
    assert_eq!(a.open_at(&f, NOW).unwrap(), Message::End);
    assert!(a.is_closed(NOW));
}

#[test]
fn contact_frames_reject_garbage() {
    let (_, _, hello) = ContactResponder::new(NOW).unwrap();
    let h = ContactHello::from_bytes(&hello).unwrap();
    assert_eq!(h.to_bytes().unwrap(), hello);
    let mut trailing = hello.clone();
    trailing.push(0);
    assert!(ContactHello::from_bytes(&trailing).is_err());
    assert!(ContactHello::from_bytes(&hello[..hello.len() - 1]).is_err());
    assert!(ContactHello::from_bytes(&vec![0u8; 5000]).is_err());

    for m in [ContactMessage::Confirmed, ContactMessage::End] {
        let b = m.encode().unwrap();
        assert_eq!(ContactMessage::decode(&b).unwrap(), m);
    }
    assert!(ContactMessage::decode(&[1, 0]).is_err());
    assert!(ContactMessage::decode(&[9]).is_err());
    assert!(ContactMessage::decode(&[]).is_err());
    // Over the cap: refused unread.
    assert!(matches!(
        ContactMessage::decode(&vec![0u8; MAX_CONTACT_MESSAGE_BYTES + 1]),
        Err(Error::InvalidFormat(_))
    ));
}

// ------------------------------------------------- pair mailbox (plan 2, 7b)

/// A completed handshake with both cards through: (responder Alice side,
/// initiator Bob side, Bob's card on Alice's side, Alice's card on Bob's
/// side).
fn cards_through(
    alice: &Person,
    bob: &Person,
) -> (
    ContactResponder,
    ContactInitiator,
    VerifiedPeer,
    VerifiedPeer,
) {
    let (mut r, mut i, _, _) = handshake();
    let to_alice = i
        .confirm_and_send_card(&bob.card, &bob.keys, bob.device_id, NOW + 3)
        .unwrap();
    r.on_frame(&to_alice, NOW + 3).unwrap();
    let to_bob = r
        .confirm_and_send_card(&alice.card, &alice.keys, alice.device_id, NOW + 4)
        .unwrap();
    let bob_peer = r.verified_peer().unwrap();
    let alice_peer = match i.on_frame(&to_bob, NOW + 4).unwrap() {
        ContactOutcome::PeerCard(c) => c,
        other => panic!("{other:?}"),
    };
    (r, i, bob_peer, alice_peer)
}

/// Two people, `creator` with the smaller account id.
fn creator_and_other() -> (Person, Person) {
    let a = person("Alice");
    let b = person("Bob");
    if a.card.card.account_id < b.card.card.account_id {
        (a, b)
    } else {
        (b, a)
    }
}

fn contact_zones(p: &mut Person) -> Vec<(Zone, Option<ZoneHome>)> {
    p.dev
        .repo()
        .zone_accesses()
        .unwrap()
        .into_iter()
        .filter_map(|a| match a.target {
            AccessTarget::Zone(z @ Zone::Contact(_)) => Some((z, a.home)),
            _ => None,
        })
        .collect()
}

#[test]
fn face_to_face_creates_one_zone() {
    let mut alice = person("Alice");
    let mut bob = person("Bob");
    let (mut r, mut i, bob_peer, alice_peer) = cards_through(&alice, &bob);
    finish_with_zone(&mut alice, &mut bob, &mut r, &mut i, bob_peer, alice_peer);
    let za = contact_zones(&mut alice);
    let zb = contact_zones(&mut bob);
    assert_eq!(za.len(), 1);
    assert_eq!(za, zb);
    let pair = pair_id(alice.card.card.account_id, bob.card.card.account_id);
    assert_eq!(za[0], (Zone::Contact(pair), Some(zone_home())));
    // Each side holds its own credential.
    let sa = alice
        .dev
        .repo()
        .zone_access(AccessTarget::Zone(Zone::Contact(pair)))
        .unwrap()
        .unwrap()
        .1;
    let sb = bob
        .dev
        .repo()
        .zone_access(AccessTarget::Zone(Zone::Contact(pair)))
        .unwrap()
        .unwrap()
        .1;
    assert_ne!(sa.public_key(), sb.public_key());
}

#[test]
fn no_offer_no_pin() {
    let (mut c, mut o) = creator_and_other();
    let (_r, _i, peer_on_r, peer_on_i) = cards_through(&c, &o);
    // The responder is `c` here: its peer is `o`'s card.
    let _ = peer_on_r;
    let e = o
        .dev
        .repo()
        .finish_contact_session(peer_on_i, None, NOW + 5)
        .unwrap_err();
    assert!(
        matches!(&e, Error::Validation(v) if v.reason == "no zone"),
        "{e:?}"
    );
    assert!(o.dev.repo().contacts().unwrap().is_empty());
    assert!(contact_zones(&mut o).is_empty());
    // The creator without its mailbox pins nothing either.
    let (_r, _i, peer_on_c, _) = cards_through(&c, &o);
    let e = c
        .dev
        .repo()
        .finish_contact_session(peer_on_c, None, NOW + 5)
        .unwrap_err();
    assert!(
        matches!(&e, Error::Validation(v) if v.reason == "no zone"),
        "{e:?}"
    );
    assert!(c.dev.repo().contacts().unwrap().is_empty());
}

#[test]
fn offer_from_non_creator_refused() {
    let (mut c, mut o) = creator_and_other();
    let (_r, _i, o_peer, _) = cards_through(&c, &o);
    // The other side makes a mailbox and offers it to the creator.
    let plan = o.dev.repo().prepare_contact_zone(&c.card, NOW).unwrap();
    let offer = o
        .dev
        .repo()
        .seal_contact_zone_offer(plan, zone_home())
        .unwrap();
    let r = c
        .dev
        .repo()
        .finish_contact_session(o_peer, Some(&offer), NOW + 5);
    assert!(is_validation(&r), "{r:?}");
    assert!(c.dev.repo().contacts().unwrap().is_empty());
}

#[test]
fn forged_offer_refused() {
    let (mut c, mut o) = creator_and_other();
    let mut mallory = person("Mallory");
    let (_r, _i, _, c_peer) = cards_through(&c, &o);
    // Mallory offers a mailbox to `o` in `c`'s place.
    let plan = mallory
        .dev
        .repo()
        .prepare_contact_zone(&o.card, NOW)
        .unwrap();
    let offer = mallory
        .dev
        .repo()
        .seal_contact_zone_offer(plan, zone_home())
        .unwrap();
    assert!(
        o.dev
            .repo()
            .finish_contact_session(c_peer.clone(), Some(&offer), NOW + 5)
            .is_err()
    );
    assert!(o.dev.repo().contacts().unwrap().is_empty());
    assert!(contact_zones(&mut o).is_empty());
    let _ = &mut c;
}

#[test]
fn offer_seed_for_other_account_refused() {
    let (mut c, mut o) = creator_and_other();
    let mut carol = person("Carol");
    let (_r, _i, _, c_peer) = cards_through(&c, &o);
    // A genuine offer of `c`, made for Carol.
    let plan = c.dev.repo().prepare_contact_zone(&carol.card, NOW).unwrap();
    let offer = c
        .dev
        .repo()
        .seal_contact_zone_offer(plan, zone_home())
        .unwrap();
    assert!(
        o.dev
            .repo()
            .finish_contact_session(c_peer, Some(&offer), NOW + 5)
            .is_err()
    );
    assert!(o.dev.repo().contacts().unwrap().is_empty());
    let _ = &mut carol;
}

#[test]
fn zone_offer_frame_rules() {
    let alice = person("Alice");
    let bob = person("Bob");
    let mut alice_dev = person("Alice2");
    let plan = alice_dev
        .dev
        .repo()
        .prepare_contact_zone(&bob.card, NOW)
        .unwrap();
    let offer = alice_dev
        .dev
        .repo()
        .seal_contact_zone_offer(plan, zone_home())
        .unwrap();
    // Before both cards: refused.
    let (mut r, _i, _, _) = handshake();
    assert!(r.send_zone_offer(&offer, NOW + 3).is_err());
    // Garbage is not an offer.
    let (mut r, mut i, _, _) = cards_through(&alice, &bob);
    assert!(r.send_zone_offer(b"nope", NOW + 5).is_err());
    let f = r.send_zone_offer(&offer, NOW + 5).unwrap();
    assert!(matches!(
        i.on_frame(&f, NOW + 5).unwrap(),
        ContactOutcome::PeerZoneOffer(_)
    ));
    // One offer per session, either way.
    assert!(r.send_zone_offer(&offer, NOW + 5).is_err());
    assert!(i.send_zone_offer(&offer, NOW + 5).is_err());
}
