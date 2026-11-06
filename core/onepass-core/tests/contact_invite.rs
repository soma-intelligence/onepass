//! Remote contact invitation through a sealed rendezvous (sharing spec
//! 5.3.2 and 13.4, S27, plan ruling A-5, founder decision 1): accounts in
//! memory, the rendezvous is a byte string handed over. Synthetic data
//! only.

mod common;

use aws_lc_rs::digest::{SHA256, digest};
use common::*;
use onepass_core::account::Account;
use onepass_core::contact::ContactCard;
use onepass_core::contact::{
    CONTACT_INVITE_META_PREFIX, CONTACT_INVITE_TTL_SECS, CONTACT_LINK_PREFIX, ContactEntry,
    ContactInvite, ContactLevel, ContactState, InviteAnswer, InviteReply, SignedContactCard,
    format_safety_number, invite_transcript, open_answer, open_reply, safety_number, seal_answer,
    seal_reply,
};
use onepass_core::contact::{CONTACT_LABEL, pair_id};
use onepass_core::crypto::IdentityKey;
use onepass_core::crypto::kem::wrap_key_labeled;
use onepass_core::crypto::{Aad, BlobKind, SymmetricKey, seal};
use onepass_core::device_keys::{DeviceKeys, DevicePublic};
use onepass_core::devices::{DeviceKind, DeviceMode};
use onepass_core::lineage::{
    GenesisBody, LINEAGE_FORMAT, LineageRecord, RosterEntry, RotationBody, RotationReason,
    sign_genesis, sign_rotation,
};
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

/// One account on one device, at its genesis, with its server, its Secret
/// Key (for a second device) and its own contact card.
struct Person {
    dev: Device,
    server: Server,
    sk: SecretKey,
    card: SignedContactCard,
}

fn person(name: &str) -> Person {
    let mut server = Server::default();
    let (mut dev, sk) = Device::create();
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
        server,
        sk,
        card,
    }
}

const NOW: i64 = T0 + 100;

fn zone_home() -> ZoneHome {
    ZoneHome {
        url: "https://box.example.org".into(),
        mailbox_id: [6; 16],
        extra_ca_pem: None,
    }
}

/// `accept_invite_reply` with the pair's mailbox made first, as the app
/// does: Bob's card, `prepare_contact_zone`, the mailbox (here a fixed
/// home), `seal_contact_zone_offer`.
trait AcceptReply {
    fn accept_reply(
        &mut self,
        invite_id: [u8; 16],
        reply: &[u8],
        name: &str,
        now: i64,
    ) -> Result<(ContactEntry, Vec<u8>)>;
}

impl<S: RecordStore> AcceptReply for Repository<S> {
    fn accept_reply(
        &mut self,
        invite_id: [u8; 16],
        reply: &[u8],
        name: &str,
        now: i64,
    ) -> Result<(ContactEntry, Vec<u8>)> {
        let card = self.invite_reply_card(invite_id, reply, now)?;
        let plan = self.prepare_contact_zone(&card, now)?;
        let offer = self.seal_contact_zone_offer(plan, zone_home())?;
        self.accept_invite_reply(invite_id, reply, name, &offer, now)
    }
}

fn is_validation<T: std::fmt::Debug>(r: &Result<T>) -> bool {
    matches!(r, Err(Error::Validation(_)))
}

fn meta_of(p: &mut Person, invite: &ContactInvite) -> Option<Vec<u8>> {
    let key = format!(
        "{CONTACT_INVITE_META_PREFIX}{}",
        invite
            .invite_id
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    p.dev.repo().store_mut().local_meta(&key).unwrap()
}

fn book(p: &mut Person) -> Vec<ContactEntry> {
    p.dev.repo().contacts().unwrap()
}

/// Alice invites Bob; both end at `Link`: (Alice's entry of Bob, Bob's
/// entry of Alice).
fn link_pair(alice: &mut Person, bob: &mut Person) -> (ContactEntry, ContactEntry) {
    let invite = alice.dev.repo().create_contact_invite(NOW).unwrap();
    let theirs = ContactInvite::parse_link(&invite.link()).unwrap().0;
    let (reply, secret) = seal_reply(&theirs, &bob.card).unwrap();
    let (on_alice, answer) = alice
        .dev
        .repo()
        .accept_reply(invite.invite_id, &reply, "Alice", NOW + 1)
        .unwrap();
    let on_bob = bob
        .dev
        .repo()
        .finish_invite(&secret, &reply, theirs.rdv_id(), &answer, NOW + 2)
        .unwrap();
    (on_alice, on_bob)
}

#[test]
fn remote_invite_pins_link_both_sides() {
    let mut alice = person("Alice");
    let mut bob = person("Bob");
    let invite = alice.dev.repo().create_contact_invite(NOW).unwrap();
    assert_eq!(invite.created_at, NOW);
    assert!(meta_of(&mut alice, &invite).is_some());

    // Bob only has the link.
    let theirs = ContactInvite::parse_link(&invite.link()).unwrap().0;
    assert_eq!(theirs.invite_id, invite.invite_id);
    assert_eq!(theirs.created_at, 0);
    assert_eq!(theirs.rdv_id(), invite.rdv_id());
    let (reply, secret) = seal_reply(&theirs, &bob.card).unwrap();

    // What the rendezvous holds opens under K_inv on Alice's side.
    let opened = open_reply(&invite, &reply).unwrap();
    assert_eq!(opened.card, bob.card);
    assert_eq!(opened.ephemeral_public, secret.public().unwrap());

    let (on_alice, answer) = alice
        .dev
        .repo()
        .accept_reply(invite.invite_id, &reply, "Alice", NOW + 1)
        .unwrap();
    assert_eq!(on_alice.account_id, bob.card.card.account_id);
    assert_eq!(on_alice.level, ContactLevel::Link);
    assert_eq!(on_alice.state, ContactState::Active);
    assert_eq!(on_alice.verified_at, NOW + 1);
    assert_eq!(on_alice.name_local, "Bob");
    assert_eq!(book(&mut alice), vec![on_alice.clone()]);
    // Used: the invitation's record is gone.
    assert!(meta_of(&mut alice, &invite).is_none());

    // The answer carries Alice's card, readable by Bob alone.
    assert_eq!(
        open_answer(&secret, &reply, theirs.rdv_id(), &answer)
            .unwrap()
            .0
            .card
            .account_id,
        alice.card.card.account_id
    );
    let on_bob = bob
        .dev
        .repo()
        .finish_invite(&secret, &reply, theirs.rdv_id(), &answer, NOW + 2)
        .unwrap();
    assert_eq!(on_bob.account_id, alice.card.card.account_id);
    assert_eq!(on_bob.level, ContactLevel::Link);
    assert_eq!(on_bob.name_local, "Alice");
    assert_eq!(book(&mut bob), vec![on_bob.clone()]);

    // One transcript on both sides: SHA-256(rdv || reply).
    let t = invite_transcript(invite.rdv_id(), &reply);
    assert_eq!(on_alice.transcript_hash, t);
    assert_eq!(on_bob.transcript_hash, t);
}

#[test]
fn invite_single_use() {
    let mut alice = person("Alice");
    let bob = person("Bob");
    let carol = person("Carol");
    let invite = alice.dev.repo().create_contact_invite(NOW).unwrap();
    let theirs = ContactInvite::parse_link(&invite.link()).unwrap().0;
    let (reply, _) = seal_reply(&theirs, &bob.card).unwrap();
    alice
        .dev
        .repo()
        .accept_reply(invite.invite_id, &reply, "Alice", NOW + 1)
        .unwrap();
    let before = book(&mut alice);

    // The same link, another card: refused, the book does not change.
    let (second, _) = seal_reply(&theirs, &carol.card).unwrap();
    let r = alice
        .dev
        .repo()
        .accept_reply(invite.invite_id, &second, "Alice", NOW + 2);
    assert!(is_validation(&r), "{r:?}");
    // And the first reply again.
    let r = alice
        .dev
        .repo()
        .accept_reply(invite.invite_id, &reply, "Alice", NOW + 2);
    assert!(is_validation(&r), "{r:?}");
    assert_eq!(book(&mut alice), before);

    // An invitation this device never issued.
    let r = alice
        .dev
        .repo()
        .accept_reply([7; 16], &second, "Alice", NOW + 2);
    assert!(is_validation(&r), "{r:?}");
}

#[test]
fn invite_expired() {
    let mut alice = person("Alice");
    let bob = person("Bob");
    let invite = alice.dev.repo().create_contact_invite(NOW).unwrap();
    let theirs = ContactInvite::parse_link(&invite.link()).unwrap().0;
    let (reply, _) = seal_reply(&theirs, &bob.card).unwrap();
    let r = alice.dev.repo().accept_reply(
        invite.invite_id,
        &reply,
        "Alice",
        invite.created_at + CONTACT_INVITE_TTL_SECS + 1,
    );
    assert!(is_validation(&r), "{r:?}");
    assert!(book(&mut alice).is_empty());
    // Expired: removed, never usable again.
    assert!(meta_of(&mut alice, &invite).is_none());
    let r = alice
        .dev
        .repo()
        .accept_reply(invite.invite_id, &reply, "Alice", NOW + 1);
    assert!(is_validation(&r), "{r:?}");

    // The last second of the window still counts.
    let invite = alice.dev.repo().create_contact_invite(NOW).unwrap();
    let theirs = ContactInvite::parse_link(&invite.link()).unwrap().0;
    let (reply, _) = seal_reply(&theirs, &bob.card).unwrap();
    alice
        .dev
        .repo()
        .accept_reply(
            invite.invite_id,
            &reply,
            "Alice",
            NOW + CONTACT_INVITE_TTL_SECS,
        )
        .unwrap();
}

#[test]
fn expired_invites_pruned_on_create() {
    let mut alice = person("Alice");
    let old = alice.dev.repo().create_contact_invite(NOW).unwrap();
    let kept = alice
        .dev
        .repo()
        .create_contact_invite(NOW + CONTACT_INVITE_TTL_SECS)
        .unwrap();
    alice
        .dev
        .repo()
        .create_contact_invite(NOW + CONTACT_INVITE_TTL_SECS + 1)
        .unwrap();
    assert!(meta_of(&mut alice, &old).is_none());
    assert!(meta_of(&mut alice, &kept).is_some());
}

#[test]
fn server_cannot_forge_reply() {
    let mut alice = person("Alice");
    let bob = person("Bob");
    let invite = alice.dev.repo().create_contact_invite(NOW).unwrap();

    // The server knows the rendezvous id, not K_inv: a well-formed reply
    // sealed under any other key does not open.
    let reply = InviteReply {
        ephemeral_public: onepass_core::crypto::HybridKemSecret::generate()
            .unwrap()
            .public()
            .unwrap(),
        card: bob.card.clone(),
    };
    let forged = seal(
        &SymmetricKey::generate().unwrap(),
        BlobKind::ContactInvite,
        &Aad {
            blob_id: invite.rdv_id(),
            vault_id: None,
            schema: 1,
        },
        &reply.encode().unwrap(),
    )
    .unwrap();
    assert_eq!(
        open_reply(&invite, &forged).unwrap_err(),
        Error::Integrity(IntegrityError::Aead)
    );
    assert_eq!(
        alice
            .dev
            .repo()
            .accept_reply(invite.invite_id, &forged, "Alice", NOW + 1)
            .unwrap_err(),
        Error::Integrity(IntegrityError::Aead)
    );
    // A real reply flipped by one bit: same.
    let theirs = ContactInvite::parse_link(&invite.link()).unwrap().0;
    let (mut real, _) = seal_reply(&theirs, &bob.card).unwrap();
    let last = real.len() - 1;
    real[last] ^= 1;
    assert_eq!(
        open_reply(&invite, &real).unwrap_err(),
        Error::Integrity(IntegrityError::Aead)
    );
    // Junk never burns the invitation.
    assert!(book(&mut alice).is_empty());
    assert!(meta_of(&mut alice, &invite).is_some());
    real[last] ^= 1;
    alice
        .dev
        .repo()
        .accept_reply(invite.invite_id, &real, "Alice", NOW + 2)
        .unwrap();
}

#[test]
fn answer_bound_to_reply() {
    let mut alice = person("Alice");
    let bob = person("Bob");
    let invite = alice.dev.repo().create_contact_invite(NOW).unwrap();
    let theirs = ContactInvite::parse_link(&invite.link()).unwrap().0;
    let rdv = theirs.rdv_id();
    let (reply1, secret1) = seal_reply(&theirs, &bob.card).unwrap();
    let (reply2, secret2) = seal_reply(&theirs, &bob.card).unwrap();
    let (_, answer1) = alice
        .dev
        .repo()
        .accept_reply(invite.invite_id, &reply1, "Alice", NOW + 1)
        .unwrap();
    open_answer(&secret1, &reply1, rdv, &answer1).unwrap();

    // Replayed for another reply of Bob's, under either secret.
    assert!(open_answer(&secret1, &reply2, rdv, &answer1).is_err());
    assert!(open_answer(&secret2, &reply2, rdv, &answer1).is_err());
    // At another rendezvous.
    assert!(open_answer(&secret1, &reply1, Id([9; 16]), &answer1).is_err());

    // The pure functions bind the same way.
    let opened2 = open_reply(&invite, &reply2).unwrap();
    let plan = alice
        .dev
        .repo()
        .prepare_contact_zone(&bob.card, NOW)
        .unwrap();
    let offer = alice
        .dev
        .repo()
        .seal_contact_zone_offer(plan, zone_home())
        .unwrap();
    let answer2 = seal_answer(&reply2, &opened2, &alice.card, rdv, &offer).unwrap();
    assert_eq!(
        open_answer(&secret2, &reply2, rdv, &answer2).unwrap(),
        (alice.card.clone(), offer)
    );
    assert!(open_answer(&secret2, &reply1, rdv, &answer2).is_err());
    assert!(open_answer(&secret1, &reply1, rdv, &answer2).is_err());

    // A malformed answer is InvalidFormat.
    let mut a = InviteAnswer::decode(&answer2).unwrap().encode().unwrap();
    a.push(0);
    assert!(matches!(
        open_answer(&secret2, &reply2, rdv, &a),
        Err(Error::InvalidFormat(_))
    ));
}

#[test]
fn rdv_id_formula() {
    let invite = ContactInvite::new(NOW).unwrap();
    let mut pre = b"onepass/invite-rdv/v1".to_vec();
    pre.extend_from_slice(&invite.invite_id);
    let h = digest(&SHA256, &pre);
    let mut id = [0u8; 16];
    id.copy_from_slice(&h.as_ref()[..16]);
    assert_eq!(invite.rdv_id(), Id(id));
}

#[test]
fn link_round_trip() {
    let invite = ContactInvite::new(NOW).unwrap();
    let link = invite.link();
    let fragment = link.strip_prefix(CONTACT_LINK_PREFIX).unwrap();
    assert_eq!(CONTACT_LINK_PREFIX, "onepass://contact#");
    assert_eq!(fragment.len(), 77);
    assert!(!fragment.contains('?') && !fragment.contains('/'));
    assert!(!fragment.contains('='));
    assert!(
        fragment
            .bytes()
            .all(|c| c.is_ascii_uppercase() || (b'2'..=b'7').contains(&c))
    );

    let parsed = ContactInvite::parse_link(&link).unwrap().0;
    assert_eq!(parsed.invite_id, invite.invite_id);
    assert_eq!(parsed.rdv_id(), invite.rdv_id());
    assert_eq!(parsed.link(), link);
    // Same secret: a reply sealed from the parsed link opens with the
    // original.
    let bob = person("Bob");
    let (reply, _) = seal_reply(&parsed, &bob.card).unwrap();
    open_reply(&invite, &reply).unwrap();

    // Strict parsing.
    for bad in [
        link.to_lowercase(),
        format!("{link}A"),
        link[..link.len() - 1].to_string(),
        link.replace("onepass://contact#", "onepass://contact/#"),
        link.replace("onepass://contact#", "https://contact#"),
        format!("{link}?x=1"),
        String::new(),
    ] {
        assert!(
            matches!(
                ContactInvite::parse_link(&bad),
                Err(Error::InvalidFormat(_))
            ),
            "{bad}"
        );
    }
}

#[test]
fn safety_number_upgrades_to_verified() {
    let mut alice = person("Alice");
    let mut bob = person("Bob");
    let (on_alice, on_bob) = link_pair(&mut alice, &mut bob);
    let bob_id = on_alice.account_id;

    // The same number on both phones.
    let shown = alice.dev.repo().contact_safety_number(bob_id).unwrap();
    assert_eq!(
        bob.dev
            .repo()
            .contact_safety_number(on_bob.account_id)
            .unwrap(),
        shown
    );
    assert_eq!(
        shown,
        safety_number(
            &alice.dev.repo().own_fingerprint().unwrap(),
            &bob.dev.repo().own_fingerprint().unwrap()
        )
    );
    assert_eq!(format_safety_number(&shown).len(), 12 * 5 + 11);

    // Another number (a typo, another pair): refused, nothing written.
    let mut other = shown;
    other[11] = (other[11] + 1) % 100_000;
    assert!(is_validation(&alice.dev.repo().confirm_safety_number(
        bob_id,
        &other,
        NOW + 9
    )));
    assert_eq!(
        alice.dev.repo().contact(bob_id).unwrap().unwrap().level,
        ContactLevel::Link
    );

    let e = alice
        .dev
        .repo()
        .confirm_safety_number(bob_id, &shown, NOW + 10)
        .unwrap();
    assert_eq!(e.level, ContactLevel::Verified);
    assert_eq!(e.verified_at, NOW + 10);
    assert_eq!(Some(e.verified_on), alice.dev.repo().chain().device_id);
    assert_eq!(e.pinned_head, on_alice.pinned_head);
    assert_eq!(e.kem_pub, on_alice.kem_pub);
    assert!(e.usable_for(ContactLevel::Verified));
    assert_eq!(alice.dev.repo().contact(bob_id).unwrap(), Some(e.clone()));

    // Once Verified, nothing more to confirm.
    assert!(is_validation(&alice.dev.repo().confirm_safety_number(
        bob_id,
        &shown,
        NOW + 11
    )));
    // Unknown.
    assert_eq!(
        alice
            .dev
            .repo()
            .confirm_safety_number(Id([3; 16]), &shown, NOW + 11)
            .unwrap_err(),
        Error::NotFound
    );

    // The account's second device sees it Verified after sync.
    sync(&mut alice.server, &mut alice.dev).unwrap();
    let mut second = Device::empty();
    pull(&alice.server, &mut second);
    second.unlock(&alice.sk);
    let there = second.repo().contact(bob_id).unwrap().unwrap();
    assert_eq!(there.level, ContactLevel::Verified);
    assert_eq!(there, e);
}

#[test]
fn safety_number_refuses_removed_contact() {
    let mut alice = person("Alice");
    let mut bob = person("Bob");
    let (on_alice, _) = link_pair(&mut alice, &mut bob);
    let bob_id = on_alice.account_id;
    let shown = alice.dev.repo().contact_safety_number(bob_id).unwrap();
    alice.dev.repo().remove_contact(bob_id, NOW + 5).unwrap();
    assert!(is_validation(&alice.dev.repo().confirm_safety_number(
        bob_id,
        &shown,
        NOW + 6
    )));
    let e = alice.dev.repo().contact(bob_id).unwrap().unwrap();
    assert_eq!(e.level, ContactLevel::Link);
    assert!(matches!(e.state, ContactState::Removed { .. }));

    // A new invitation does not bring a removed contact back either: a
    // re-add takes a face-to-face verification (spec 5.4).
    let invite = alice.dev.repo().create_contact_invite(NOW + 7).unwrap();
    let theirs = ContactInvite::parse_link(&invite.link()).unwrap().0;
    let (reply, _) = seal_reply(&theirs, &bob.card).unwrap();
    let r = alice
        .dev
        .repo()
        .accept_reply(invite.invite_id, &reply, "Alice", NOW + 8);
    assert!(is_validation(&r), "{r:?}");
    // The refusal left the invitation usable.
    assert!(meta_of(&mut alice, &invite).is_some());
}

#[test]
fn own_card_refused() {
    let mut alice = person("Alice");
    let invite = alice.dev.repo().create_contact_invite(NOW).unwrap();
    let theirs = ContactInvite::parse_link(&invite.link()).unwrap().0;
    let (reply, _) = seal_reply(&theirs, &alice.card).unwrap();
    let r = alice
        .dev
        .repo()
        .accept_reply(invite.invite_id, &reply, "Alice", NOW + 1);
    assert!(is_validation(&r), "{r:?}");
    assert!(book(&mut alice).is_empty());

    // Bob's side: an answer carrying his own card.
    let mut bob = person("Bob");
    let (reply, secret) = seal_reply(&theirs, &bob.card).unwrap();
    let opened = open_reply(&invite, &reply).unwrap();
    let plan = alice
        .dev
        .repo()
        .prepare_contact_zone(&bob.card, NOW + 1)
        .unwrap();
    let offer = alice
        .dev
        .repo()
        .seal_contact_zone_offer(plan, zone_home())
        .unwrap();
    let answer = seal_answer(&reply, &opened, &bob.card, theirs.rdv_id(), &offer).unwrap();
    let r = bob
        .dev
        .repo()
        .finish_invite(&secret, &reply, theirs.rdv_id(), &answer, NOW + 2);
    assert!(is_validation(&r), "{r:?}");
    assert!(book(&mut bob).is_empty());
}

#[test]
fn a13_link_level_is_read_only() {
    let mut alice = person("Alice");
    let mut bob = person("Bob");
    let (on_alice, on_bob) = link_pair(&mut alice, &mut bob);
    for e in [on_alice, on_bob] {
        assert_eq!(e.level, ContactLevel::Link);
        assert!(e.usable_for(ContactLevel::Link));
        assert!(!e.usable_for(ContactLevel::Verified));
    }
}

#[test]
fn invite_debug_hides_secret() {
    let invite = ContactInvite::new(NOW).unwrap();
    let link = invite.link();
    let secret_part = &link[link.len() - 40..];
    let dbg = format!("{invite:?}");
    assert!(!dbg.contains(secret_part));
    assert!(!dbg.contains("secret"));
}

#[test]
fn local_meta_taking_is_all_or_nothing() {
    let (dev, _) = Device::create();
    let dir = tempfile::tempdir().unwrap();
    let mut stores: Vec<Box<dyn RecordStore>> = vec![
        Box::new(dev.store()),
        Box::new(onepass_core::store::MemoryStore::new()),
        Box::new(onepass_core::store::SqliteStore::open(&dir.path().join("s.sqlite")).unwrap()),
    ];
    for store in stores.iter_mut() {
        let key = "contact_invite.00";
        // Only the local prefixes: never a key the store keeps itself.
        for bad in ["trust", "chain", "contact_invite.", "x.contact_invite.00"] {
            assert!(matches!(
                store.set_local_meta(bad, Some(b"x")),
                Err(Error::Validation(_))
            ));
            assert!(matches!(store.local_meta(bad), Err(Error::Validation(_))));
        }
        store.set_local_meta(key, Some(b"v1")).unwrap();
        assert_eq!(
            store.local_meta_keys("contact_invite.").unwrap(),
            vec![key.to_string()]
        );
        let rec = |v: u64| Record {
            id: Id([1; 16]),
            kind: RecordKind::Item,
            version: v,
            data: vec![1, 2, 3],
        };
        // A version mismatch: nothing written, the meta stays.
        assert_eq!(
            store
                .put_all_if_version_taking_meta(vec![(rec(1), Some(5))], key, b"v1")
                .unwrap_err(),
            Error::Conflict
        );
        // Another meta value: same.
        assert_eq!(
            store
                .put_all_if_version_taking_meta(vec![(rec(1), None)], key, b"v2")
                .unwrap_err(),
            Error::Conflict
        );
        assert!(store.get(RecordKind::Item, Id([1; 16])).unwrap().is_none());
        assert_eq!(store.local_meta(key).unwrap(), Some(b"v1".to_vec()));
        // Both, then never again.
        store
            .put_all_if_version_taking_meta(vec![(rec(1), None)], key, b"v1")
            .unwrap();
        assert!(store.get(RecordKind::Item, Id([1; 16])).unwrap().is_some());
        assert_eq!(store.local_meta(key).unwrap(), None);
        assert_eq!(
            store
                .put_all_if_version_taking_meta(vec![], key, b"v1")
                .unwrap_err(),
            Error::Conflict
        );
    }
}

/// A synthetic contact: its card at its genesis, and at a valid rotation
/// of it to a new identity.
fn rotating_contact() -> (SignedContactCard, SignedContactCard) {
    let n = Account::create_with_params(PASSWORD, kdf()).unwrap();
    let account_id = n.account.params.account_id;
    let identity = IdentityKey::from_bytes(&n.account.keyset().identity.to_bytes()).unwrap();
    let keys = DeviceKeys::generate_software().unwrap();
    let public = keys.public(Id::new()).unwrap();
    let genesis = LineageRecord::Genesis(
        sign_genesis(
            GenesisBody {
                format: LINEAGE_FORMAT,
                account_id,
                identity_pub: identity.verifying_key(),
                creator: entry_of(&public, "iPhone"),
                created_at: T0,
            },
            &keys,
            &identity,
        )
        .unwrap(),
    );
    let r = n
        .account
        .rotate_keys(
            PASSWORD,
            &SecretKey::generate().unwrap(),
            &n.account.params.kdf,
        )
        .unwrap();
    let next = IdentityKey::from_bytes(&r.account.keyset().identity.to_bytes()).unwrap();
    let mut params_hash = [0u8; 32];
    params_hash.copy_from_slice(digest(&SHA256, &r.params_record).as_ref());
    let rotation = LineageRecord::Rotation(
        sign_rotation(
            RotationBody {
                format: LINEAGE_FORMAT,
                account_id,
                generation: 1,
                parent: genesis.hash(),
                rotator: public.device_id,
                reason: RotationReason::Rotate,
                revoked: vec![],
                roster: vec![entry_of(&public, "iPhone")],
                identity_pub: next.verifying_key(),
                params_hash,
                keyset_hash: [0x4B; 32],
                deliveries: vec![],
                from_heads: BTreeMap::new(),
                issued_at: T0 + 30,
            },
            &keys,
            &next,
        )
        .unwrap(),
    );
    let card = |identity: &IdentityKey, params: &[u8], lineage: Vec<LineageRecord>| {
        let last = lineage.last().unwrap();
        SignedContactCard::sign(
            ContactCard {
                format: 1,
                account_id,
                genesis: lineage[0].hash(),
                head: LineageHead {
                    generation: last.generation(),
                    hash: last.hash(),
                },
                identity_pub: identity.verifying_key(),
                params: params.to_vec(),
                lineage,
                intros: vec![],
                legacy_intros: vec![],
                genesis_params: None,
                name: "Dan".into(),
                issued_at: T0 + 60,
            },
            identity,
        )
        .unwrap()
    };
    (
        card(&identity, &n.params_record, vec![genesis.clone()]),
        card(&next, &r.params_record, vec![genesis, rotation]),
    )
}

#[test]
fn safety_number_refused_after_repin() {
    let (at_genesis, rotated) = rotating_contact();
    let dan = at_genesis.card.account_id;
    let mut alice = person("Alice");
    let mut second = Device::empty();
    pull(&alice.server, &mut second);
    second.unlock(&alice.sk);

    // This device pins Dan at his genesis and shows the number.
    alice
        .dev
        .repo()
        .test_pin_contact(&at_genesis, ContactLevel::Link, [1; 32], NOW)
        .unwrap();
    let shown = alice.dev.repo().contact_safety_number(dan).unwrap();

    // Meanwhile the account's other device pinned his rotated card; the
    // books merge and the newer head wins here.
    second
        .repo()
        .test_pin_contact(&rotated, ContactLevel::Link, [2; 32], NOW + 1)
        .unwrap();
    sync(&mut alice.server, &mut second).unwrap();
    let _ = sync(&mut alice.server, &mut alice.dev);
    alice.dev.repo().rebase().unwrap();
    sync(&mut alice.server, &mut alice.dev).unwrap();
    let moved = alice.dev.repo().contact(dan).unwrap().unwrap();
    assert_eq!(moved.pinned_head, rotated.card.head);
    assert_eq!(moved.level, ContactLevel::Link);

    // The number shown was for the old identity: refused, still Link.
    assert!(is_validation(&alice.dev.repo().confirm_safety_number(
        dan,
        &shown,
        NOW + 5
    )));
    assert_eq!(
        alice.dev.repo().contact(dan).unwrap().unwrap().level,
        ContactLevel::Link
    );
    // The number of the identity now pinned is a new comparison.
    let now_shown = alice.dev.repo().contact_safety_number(dan).unwrap();
    assert_ne!(now_shown, shown);
    let e = alice
        .dev
        .repo()
        .confirm_safety_number(dan, &now_shown, NOW + 6)
        .unwrap();
    assert_eq!(e.level, ContactLevel::Verified);
    assert_eq!(e.pinned_head, rotated.card.head);
}

#[test]
fn invites_pruned_and_prefix_checked() {
    let mut alice = person("Alice");
    let old = alice.dev.repo().create_contact_invite(NOW).unwrap();
    assert_eq!(
        alice
            .dev
            .repo()
            .prune_contact_invites(NOW + CONTACT_INVITE_TTL_SECS)
            .unwrap(),
        0
    );
    assert_eq!(
        alice
            .dev
            .repo()
            .prune_contact_invites(NOW + CONTACT_INVITE_TTL_SECS + 1)
            .unwrap(),
        1
    );
    assert!(meta_of(&mut alice, &old).is_none());
    // Store-internal key names are never listed.
    for bad in ["", "t", "contact_invite"] {
        assert!(matches!(
            alice.dev.repo().store_mut().local_meta_keys(bad),
            Err(Error::Validation(_))
        ));
    }
}

// ------------------------------------------------- pair mailbox (plan 2, 7b)

fn pair_zones(p: &mut Person) -> Vec<(Zone, Option<ZoneHome>)> {
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
fn remote_invite_creates_zone_on_inviter() {
    let mut alice = person("Alice");
    let mut bob = person("Bob");
    // No mailbox, no answer.
    let invite = alice.dev.repo().create_contact_invite(NOW).unwrap();
    let theirs = ContactInvite::parse_link(&invite.link()).unwrap().0;
    let (reply, _) = seal_reply(&theirs, &bob.card).unwrap();
    let r = alice
        .dev
        .repo()
        .prepare_contact_zone(&bob.card, NOW)
        .and_then(|_| {
            let offer = vec![0u8; 8];
            alice
                .dev
                .repo()
                .accept_invite_reply(invite.invite_id, &reply, "Alice", &offer, NOW + 1)
        });
    assert!(is_validation(&r), "{r:?}");
    assert!(book(&mut alice).is_empty());

    let (on_alice, on_bob) = link_pair(&mut alice, &mut bob);
    assert_eq!(on_alice.level, ContactLevel::Link);
    assert_eq!(on_bob.level, ContactLevel::Link);
    let pair = Zone::Contact(pair_id(
        alice.card.card.account_id,
        bob.card.card.account_id,
    ));
    assert_eq!(pair_zones(&mut alice), vec![(pair, Some(zone_home()))]);
    assert_eq!(pair_zones(&mut bob), vec![(pair, Some(zone_home()))]);
}

#[test]
fn answer_v1_refused() {
    let mut alice = person("Alice");
    let bob = person("Bob");
    let invite = alice.dev.repo().create_contact_invite(NOW).unwrap();
    let theirs = ContactInvite::parse_link(&invite.link()).unwrap().0;
    let (reply, secret) = seal_reply(&theirs, &bob.card).unwrap();
    let opened = open_reply(&invite, &reply).unwrap();
    let rdv = theirs.rdv_id();
    // The first version: the card alone under the fresh key.
    let key = SymmetricKey::generate().unwrap();
    let envelope = wrap_key_labeled(
        &opened.ephemeral_public,
        &key,
        CONTACT_LABEL,
        &invite_transcript(rdv, &reply),
    )
    .unwrap();
    let sealed = seal(
        &key,
        BlobKind::ContactInvite,
        &Aad {
            blob_id: rdv,
            vault_id: None,
            schema: 2,
        },
        &alice.card.encode(),
    )
    .unwrap();
    let v1 = InviteAnswer { envelope, sealed }.encode().unwrap();
    assert!(matches!(
        open_answer(&secret, &reply, rdv, &v1),
        Err(Error::InvalidFormat(_))
    ));
}

#[test]
fn link_with_host_round_trip() {
    let invite = ContactInvite::new(NOW).unwrap();
    for host in ["vault.example.org", "box-2.example.org:8443", "localhost"] {
        let link = invite.link_for(Some(host));
        assert!(link.starts_with(&format!("onepass://contact/{host}#")));
        let (back, h) = ContactInvite::parse_link(&link).unwrap();
        assert_eq!(h.as_deref(), Some(host));
        assert_eq!(back.invite_id, invite.invite_id);
        assert_eq!(back.rdv_id(), invite.rdv_id());
    }
    // A host the rules refuse is left out of the link, and refused when
    // parsed.
    for bad in [
        "",
        "Vault.example.org",
        "a..b",
        ".a",
        "a.",
        "a:",
        "a:123456",
        "a/b",
        "a b",
    ] {
        assert_eq!(invite.link_for(Some(bad)), invite.link());
        let forged = invite
            .link()
            .replace("onepass://contact#", &format!("onepass://contact/{bad}#"));
        assert!(ContactInvite::parse_link(&forged).is_err(), "{bad:?}");
    }
    assert!(ContactInvite::parse_link("onepass://contact/#AAAA").is_err());
}

#[test]
fn link_without_host_is_hosted() {
    let invite = ContactInvite::new(NOW).unwrap();
    assert_eq!(invite.link_for(None), invite.link());
    let (back, host) = ContactInvite::parse_link(&invite.link()).unwrap();
    assert_eq!(host, None);
    assert_eq!(back.invite_id, invite.invite_id);
}
