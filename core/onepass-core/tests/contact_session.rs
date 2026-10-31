//! Face-to-face contact verification (sharing spec 5.3.1, S2, plan ruling
//! A-2): two accounts in memory, the pairing channel under the contact
//! label, no transport. Synthetic data only.

mod common;

use common::*;
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

    let on_alice = alice
        .dev
        .repo()
        .finish_contact_session(bob_peer, NOW + 5)
        .unwrap();
    let on_bob = bob
        .dev
        .repo()
        .finish_contact_session(alice_peer, NOW + 5)
        .unwrap();
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
    assert!(is_validation(
        &alice.dev.repo().finish_contact_session(own, NOW + 6)
    ));
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
