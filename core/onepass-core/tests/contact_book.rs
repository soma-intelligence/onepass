//! The signed contact book (sharing spec 5.4, S6, founder decision 8): one
//! signed, chained, monotone list per identity of the account, synced
//! between its devices, keyed by the contact's account id.
//!
//! Contacts are throwaway accounts whose lineage is built here (genesis,
//! then a rotation for the refresh tests). SLH-DSA signing is slow: each
//! contact is built once per process.

mod common;

use std::collections::BTreeMap;
use std::sync::OnceLock;

use aws_lc_rs::digest::{SHA256, digest};
use common::*;
use onepass_core::account::{Account, NewAccount};
use onepass_core::contact::{
    ContactAlert, ContactCard, ContactEntry, ContactLevel, ContactState, ForeignLineage,
    SignedContactCard,
};
use onepass_core::crypto::{HybridKemPublic, HybridVerifyingKey, IdentityKey};
use onepass_core::device_keys::{DeviceKeys, DevicePublic};
use onepass_core::devices::{DeviceKind, DeviceMode};
use onepass_core::lineage::{
    GenesisBody, LINEAGE_FORMAT, LineageRecord, RosterEntry, RotationBody, RotationReason,
    identity_id, sign_genesis, sign_rotation,
};
use onepass_core::lists::{ListBody, MonotoneEntry, merge};
use onepass_core::repo::RotateRequest;
use onepass_core::trust::{DeviceLineageState, LineageHead, TrustLevel, TrustState};
use proptest::prelude::*;

const TRANSCRIPT: [u8; 32] = [0x7A; 32];

fn sha256(b: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(digest(&SHA256, b).as_ref());
    out
}

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

fn identity_of(n: &NewAccount) -> IdentityKey {
    identity_of_account(&n.account)
}

fn identity_of_account(a: &Account) -> IdentityKey {
    IdentityKey::from_bytes(&a.keyset().identity.to_bytes()).unwrap()
}

fn genesis_by(
    account_id: Id,
    identity: &IdentityKey,
    keys: &DeviceKeys,
    public: &DevicePublic,
    at: i64,
) -> LineageRecord {
    LineageRecord::Genesis(
        sign_genesis(
            GenesisBody {
                format: LINEAGE_FORMAT,
                account_id,
                identity_pub: identity.verifying_key(),
                creator: entry_of(public, "iPhone"),
                created_at: at,
            },
            keys,
            identity,
        )
        .unwrap(),
    )
}

/// A rotation of `parent` (generation 0) by `rotator`, alone in the new
/// roster, to `identity`.
fn rotation_by(
    account_id: Id,
    parent: &LineageRecord,
    keys: &DeviceKeys,
    rotator: &DevicePublic,
    identity: &IdentityKey,
    params: &[u8],
) -> LineageRecord {
    LineageRecord::Rotation(
        sign_rotation(
            RotationBody {
                format: LINEAGE_FORMAT,
                account_id,
                generation: 1,
                parent: parent.hash(),
                rotator: rotator.device_id,
                reason: RotationReason::Rotate,
                revoked: vec![],
                roster: vec![entry_of(rotator, "iPhone")],
                identity_pub: identity.verifying_key(),
                params_hash: sha256(params),
                keyset_hash: [0x4B; 32],
                deliveries: vec![],
                from_heads: BTreeMap::new(),
                issued_at: T0 + 30,
            },
            keys,
            identity,
        )
        .unwrap(),
    )
}

fn card(
    account_id: Id,
    identity: &IdentityKey,
    params: &[u8],
    lineage: Vec<LineageRecord>,
    name: &str,
) -> SignedContactCard {
    let last = lineage.last().unwrap();
    let c = ContactCard {
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
        name: name.into(),
        issued_at: T0 + 60,
    };
    SignedContactCard::sign(c, identity).unwrap()
}

/// Carol at her genesis (her account's identity), with the material to
/// rotate her, and a card of the same account id under another genesis.
struct Carol {
    account_id: Id,
    genesis: LineageRecord,
    /// Her card at the genesis, named "Carol".
    card: SignedContactCard,
    /// The same card, named "Mallory".
    renamed: SignedContactCard,
    /// A valid rotation of the genesis, to a new identity.
    rotation: LineageRecord,
    /// Her card at that rotation.
    rotated: SignedContactCard,
    /// Same account id, params and identity, another genesis.
    other_genesis: SignedContactCard,
}

fn carol() -> &'static Carol {
    static C: OnceLock<Carol> = OnceLock::new();
    C.get_or_init(|| {
        let n = Account::create_with_params(PASSWORD, kdf()).unwrap();
        let account_id = n.account.params.account_id;
        let identity = identity_of(&n);
        let keys = DeviceKeys::generate_software().unwrap();
        let public = keys.public(Id::new()).unwrap();
        let genesis = genesis_by(account_id, &identity, &keys, &public, T0);
        let new_sk = SecretKey::generate().unwrap();
        let r = n
            .account
            .rotate_keys(PASSWORD, &new_sk, &n.account.params.kdf)
            .unwrap();
        let next = identity_of_account(&r.account);
        let rotation = rotation_by(
            account_id,
            &genesis,
            &keys,
            &public,
            &next,
            &r.params_record,
        );
        let rotated = card(
            account_id,
            &next,
            &r.params_record,
            vec![genesis.clone(), rotation.clone()],
            "Carol",
        );
        let other = genesis_by(account_id, &identity, &keys, &public, T0 + 5);
        Carol {
            account_id,
            genesis: genesis.clone(),
            card: card(
                account_id,
                &identity,
                &n.params_record,
                vec![genesis.clone()],
                "Carol",
            ),
            renamed: card(
                account_id,
                &identity,
                &n.params_record,
                vec![genesis],
                "Mallory",
            ),
            rotation,
            rotated,
            other_genesis: card(
                account_id,
                &identity,
                &n.params_record,
                vec![other],
                "Carol",
            ),
        }
    })
}

/// Dave at generation 1: `valid` rotated by his genesis creator, `forged`
/// by a device his genesis never knew.
struct Dave {
    valid: SignedContactCard,
    forged: SignedContactCard,
}

fn dave() -> &'static Dave {
    static D: OnceLock<Dave> = OnceLock::new();
    D.get_or_init(|| {
        let n = Account::create_with_params(PASSWORD, kdf()).unwrap();
        let account_id = n.account.params.account_id;
        let head = identity_of(&n);
        let first = IdentityKey::generate().unwrap();
        let keys = DeviceKeys::generate_software().unwrap();
        let public = keys.public(Id::new()).unwrap();
        let genesis = genesis_by(account_id, &first, &keys, &public, T0);
        let good = rotation_by(
            account_id,
            &genesis,
            &keys,
            &public,
            &head,
            &n.params_record,
        );
        let stranger_keys = DeviceKeys::generate_software().unwrap();
        let stranger = stranger_keys.public(Id::new()).unwrap();
        let bad = rotation_by(
            account_id,
            &genesis,
            &stranger_keys,
            &stranger,
            &head,
            &n.params_record,
        );
        Dave {
            valid: card(
                account_id,
                &head,
                &n.params_record,
                vec![genesis.clone(), good],
                "Dave",
            ),
            forged: card(
                account_id,
                &head,
                &n.params_record,
                vec![genesis, bad],
                "Dave",
            ),
        }
    })
}

fn book(dev: &mut Device) -> Vec<ContactEntry> {
    dev.repo().contacts().unwrap()
}

/// The book record of generation 0 (id = account id).
fn book_record(dev: &mut Device) -> Option<Record> {
    let id = dev.repo().account().params.account_id;
    dev.repo()
        .store_mut()
        .get(RecordKind::ContactBook, id)
        .unwrap()
}

fn pin(dev: &mut Device, c: &SignedContactCard, level: ContactLevel) -> Result<ContactEntry> {
    dev.repo().test_pin_contact(c, level, TRANSCRIPT, T0 + 100)
}

fn is_validation<T: std::fmt::Debug>(r: &Result<T>) -> bool {
    matches!(r, Err(Error::Validation(_)))
}

// ---------------------------------------------------------------- pinning

#[test]
fn pin_then_list() {
    let (mut a, sk) = Device::create();
    assert!(book(&mut a).is_empty());
    let c = carol();
    let e = pin(&mut a, &c.card, ContactLevel::Verified).unwrap();
    let keys = c.card.keys().unwrap();
    assert_eq!(e.account_id, c.account_id);
    assert_eq!(e.genesis, c.genesis.hash());
    assert_eq!(e.pinned_head, c.card.card.head);
    assert_eq!(e.identity_pub, c.card.card.identity_pub);
    assert_eq!(e.sign_pub, keys.sign_pub);
    assert_eq!(e.kem_pub, keys.kem_pub);
    assert_eq!(e.level, ContactLevel::Verified);
    assert_eq!(e.verified_at, T0 + 100);
    assert_eq!(Some(e.verified_on), a.repo().chain().device_id);
    assert_eq!(e.transcript_hash, TRANSCRIPT);
    assert_eq!(e.name_local, "Carol");
    assert_eq!(e.state, ContactState::Active);
    assert_eq!(book(&mut a), vec![e.clone()]);
    assert_eq!(a.repo().contact(c.account_id).unwrap(), Some(e.clone()));
    assert_eq!(a.repo().contact(Id::new()).unwrap(), None);
    assert!(e.usable_for(ContactLevel::Verified));
    assert!(e.usable_for(ContactLevel::Link));
    let p = e.pin();
    assert_eq!(p.head, e.pinned_head);
    assert_eq!(p.genesis, e.genesis);

    // At generation 0 the record id is the account id; seq 1 is pinned.
    let rec = book_record(&mut a).unwrap();
    assert_eq!(rec.id, a.repo().account().params.account_id);
    assert_eq!(rec.version, 1);
    assert_eq!(a.repo().chain().contact_book.unwrap().seq, 1);

    // The other devices of the account read it without verifying again.
    let mut server = Server::default();
    sync(&mut server, &mut a).unwrap();
    let mut b = Device::empty();
    pull(&server, &mut b);
    b.unlock(&sk);
    assert_eq!(book(&mut b), vec![e]);
}

#[test]
fn pin_rotated_card() {
    let (mut a, _) = Device::create();
    let d = dave();
    let e = pin(&mut a, &d.valid, ContactLevel::Link).unwrap();
    assert_eq!(e.pinned_head.generation, 1);
    assert!(e.usable_for(ContactLevel::Link));
    assert!(!e.usable_for(ContactLevel::Verified));
}

#[test]
fn pin_refuses_card_without_valid_lineage() {
    let (mut a, _) = Device::create();
    let d = dave();
    // The card itself is well signed: only its lineage is wrong.
    d.forged.keys().unwrap();
    assert_eq!(
        pin(&mut a, &d.forged, ContactLevel::Verified).unwrap_err(),
        Error::Integrity(IntegrityError::Signature)
    );
    assert!(book_record(&mut a).is_none());
    assert!(book(&mut a).is_empty());
}

#[test]
fn own_card_refused() {
    let (mut a, _) = Device::create();
    let me = a.repo().account().params.account_id;
    // A card of this very account id (the lineage does not matter: the
    // check comes first).
    let mut c = carol().card.clone();
    c.card.account_id = me;
    assert!(is_validation(&pin(&mut a, &c, ContactLevel::Verified)));
    assert!(book_record(&mut a).is_none());
}

#[test]
fn verified_beats_link() {
    let (mut a, _) = Device::create();
    let c = carol();
    let link = a
        .repo()
        .test_pin_contact(&c.card, ContactLevel::Link, [1; 32], T0 + 10)
        .unwrap();
    assert!(!link.usable_for(ContactLevel::Verified));
    let verified = a
        .repo()
        .test_pin_contact(&c.card, ContactLevel::Verified, [2; 32], T0 + 20)
        .unwrap();
    assert_eq!(verified.level, ContactLevel::Verified);
    assert_eq!(verified.verified_at, T0 + 20);
    assert_eq!(verified.transcript_hash, [2; 32]);
    // A later Link pin does not take the level back.
    let again = a
        .repo()
        .test_pin_contact(&c.card, ContactLevel::Link, [3; 32], T0 + 30)
        .unwrap();
    assert_eq!(again, verified);
    assert_eq!(book(&mut a), vec![verified.clone()]);

    // The merge: Verified wins at equal identity, the earliest date of the
    // winning level.
    let mut earlier = verified.clone();
    earlier.verified_at = T0 + 15;
    earlier.transcript_hash = [4; 32];
    assert_eq!(verified.merge(&link), verified);
    assert_eq!(link.merge(&verified), verified);
    assert_eq!(verified.merge(&earlier), earlier);
    assert_eq!(earlier.merge(&verified), earlier);
}

#[test]
fn removed_wins() {
    let (mut a, _) = Device::create();
    let c = carol();
    let e = pin(&mut a, &c.card, ContactLevel::Verified).unwrap();
    a.repo().remove_contact(c.account_id, T0 + 200).unwrap();
    let removed = a.repo().contact(c.account_id).unwrap().unwrap();
    assert_eq!(removed.state, ContactState::Removed { at: T0 + 200 });
    assert!(!removed.usable_for(ContactLevel::Link));
    // Removing again keeps the first date.
    a.repo().remove_contact(c.account_id, T0 + 300).unwrap();
    assert_eq!(a.repo().contact(c.account_id).unwrap().unwrap(), removed);
    // A pin never brings it back.
    assert!(is_validation(&pin(&mut a, &c.card, ContactLevel::Verified)));
    assert_eq!(a.repo().contact(c.account_id).unwrap().unwrap(), removed);
    // Unknown contact.
    assert_eq!(
        a.repo().remove_contact(Id::new(), T0).unwrap_err(),
        Error::NotFound
    );

    // The merge: Removed wins over everything, the earliest date kept.
    let mut later = removed.clone();
    later.state = ContactState::Removed { at: T0 + 900 };
    let mut changed = e.clone();
    changed.state = ContactState::KeysChanged {
        child: [5; 32],
        seen_at: T0,
    };
    for other in [&e, &changed, &later] {
        assert_eq!(removed.merge(other).state, removed.state);
        assert_eq!(other.merge(&removed).state, removed.state);
    }
}

#[test]
fn newer_head_replaces_keys() {
    let (mut a, _) = Device::create();
    let c = carol();
    let old = pin(&mut a, &c.card, ContactLevel::Verified).unwrap();
    // The same contact as another device of the account adopted it at
    // generation 1 (the adoption itself is a later task).
    let keys = c.rotated.keys().unwrap();
    let mut newer = old.clone();
    newer.pinned_head = c.rotated.card.head;
    newer.identity_pub = c.rotated.card.identity_pub.clone();
    newer.sign_pub = keys.sign_pub.clone();
    newer.kem_pub = keys.kem_pub.clone();
    newer.level = ContactLevel::Link;
    newer.verified_at = T0 + 500;
    assert_ne!(newer.sign_pub, old.sign_pub);
    for m in [old.merge(&newer), newer.merge(&old)] {
        assert_eq!(m.pinned_head, newer.pinned_head);
        assert_eq!(m.identity_pub, newer.identity_pub);
        assert_eq!(m.sign_pub, newer.sign_pub);
        assert_eq!(m.kem_pub, newer.kem_pub);
        assert_eq!(m.level, ContactLevel::Link);
        assert_eq!(m.verified_at, T0 + 500);
    }
    // KeysChanged on the old head gives way to the adopted head; at the
    // same head it wins over Active.
    let mut changed = old.clone();
    changed.state = ContactState::KeysChanged {
        child: c.rotation.hash(),
        seen_at: T0 + 400,
    };
    assert_eq!(changed.merge(&newer).state, ContactState::Active);
    assert_eq!(changed.merge(&old).state, changed.state);
    assert_eq!(old.merge(&changed).state, changed.state);

    // A pin at another head than the pinned one is the confirmation
    // path's job, never a silent replacement.
    assert!(is_validation(&pin(
        &mut a,
        &c.rotated,
        ContactLevel::Verified
    )));
    assert_eq!(a.repo().contact(c.account_id).unwrap().unwrap(), old);
    // On a fresh book, the card at generation 1 pins as it is.
    let (mut b, _) = Device::create();
    let e = pin(&mut b, &c.rotated, ContactLevel::Verified).unwrap();
    assert_eq!(e.pinned_head.generation, 1);
    assert_eq!(e.sign_pub, keys.sign_pub);
}

/// Fresh signing and KEM public keys, not the contact's.
struct FreshKeys {
    sign: HybridVerifyingKey,
    kem: HybridKemPublic,
}

impl FreshKeys {
    fn new() -> FreshKeys {
        let keys = DeviceKeys::generate_software().unwrap();
        let p = keys.public(Id::new()).unwrap();
        FreshKeys {
            sign: p.sign_pub,
            kem: p.kem_pub,
        }
    }
}

#[test]
fn other_genesis_alerts_never_replaces() {
    let (mut a, _) = Device::create();
    let c = carol();
    let first = pin(&mut a, &c.card, ContactLevel::Verified).unwrap();
    assert!(a.repo().contact_alerts().is_empty());
    let r = pin(&mut a, &c.other_genesis, ContactLevel::Verified);
    assert!(is_validation(&r));
    assert_eq!(a.repo().contact(c.account_id).unwrap().unwrap(), first);
    assert_eq!(
        a.repo().contact_alerts(),
        &[ContactAlert::ContactBookConflict {
            account_id: c.account_id,
            kept: c.genesis.hash(),
            refused: c.other_genesis.card.genesis,
        }]
    );

    // The merge keeps the older entry, whichever side it is on.
    let mut other = first.clone();
    other.genesis = c.other_genesis.card.genesis;
    other.pinned_head = c.other_genesis.card.head;
    other.verified_at = first.verified_at + 1;
    assert_eq!(first.merge(&other), first);
    assert_eq!(other.merge(&first), first);
}

// ---------------------------------------------------------------- sync

#[test]
fn book_rollback_refused() {
    let (mut a, _) = Device::create();
    pin(&mut a, &carol().card, ContactLevel::Link).unwrap();
    let old = book_record(&mut a).unwrap();
    pin(&mut a, &carol().card, ContactLevel::Verified).unwrap();
    assert_eq!(a.repo().chain().contact_book.unwrap().seq, 2);
    // The store serves seq 1 again.
    a.repo().store_mut().put(old).unwrap();
    assert_eq!(
        a.repo().contacts().unwrap_err(),
        Error::Integrity(IntegrityError::ContactBookRollback)
    );
}

#[test]
fn book_syncs_and_rebases() {
    let mut server = Server::default();
    let (mut a, sk) = Device::create();
    sync(&mut server, &mut a).unwrap();
    let mut b = Device::empty();
    pull(&server, &mut b);
    b.unlock(&sk);
    let c = carol();
    let d = dave();
    // Both devices write their first book before either syncs.
    pin(&mut a, &c.card, ContactLevel::Link).unwrap();
    pin(&mut b, &d.valid, ContactLevel::Link).unwrap();
    b.repo()
        .rename_contact(d.valid.card.account_id, "D.")
        .unwrap();
    sync(&mut server, &mut a).unwrap();
    // B's push loses the race, its book is rebuilt over A's.
    let _ = sync(&mut server, &mut b);
    b.repo().rebase().unwrap();
    sync(&mut server, &mut b).unwrap();
    sync(&mut server, &mut a).unwrap();
    let ids = |dev: &mut Device| -> Vec<Id> { book(dev).iter().map(|e| e.account_id).collect() };
    let mut want = vec![c.account_id, d.valid.card.account_id];
    want.sort();
    assert_eq!(ids(&mut a), want);
    assert_eq!(book(&mut a), book(&mut b));
    assert_eq!(
        a.repo()
            .contact(d.valid.card.account_id)
            .unwrap()
            .unwrap()
            .name_local,
        "D."
    );
}

#[test]
fn book_keyed_by_identity() {
    let mut server = Server::default();
    let (mut a, f) = rotation_fixture(&mut server);
    let c = carol();
    let e = pin(&mut a, &c.card, ContactLevel::Verified).unwrap();
    let account_id = a.repo().account().params.account_id;
    let old = a
        .repo()
        .store_mut()
        .get(RecordKind::ContactBook, account_id)
        .unwrap()
        .unwrap();
    assert_eq!(old.id, account_id);

    let new_sk = SecretKey::generate().unwrap();
    let req = RotateRequest {
        revoke: vec![],
        new_password: None,
        password: PASSWORD,
        secret_key: &f.sk,
        new_secret_key: &new_sk,
        device_keys: &f.me_keys,
        reason: RotationReason::Rotate,
    };
    a.repo().rotate(req).unwrap();
    let rid = identity_id(&a.repo().account().params.identity_pub);
    let rec = a
        .repo()
        .store_mut()
        .get(RecordKind::ContactBook, rid)
        .unwrap()
        .unwrap();
    assert_eq!(rec.version, 1);
    assert_eq!(a.repo().chain().contact_book.unwrap().seq, 1);
    assert_eq!(book(&mut a), vec![e]);

    // The book of the left identity, signed by its key, under the new id:
    // refused (spec 5.4, signatures of the old identity no longer count).
    let mut replay = old.clone();
    replay.id = rid;
    replay.version = 2;
    a.repo().store_mut().put(replay).unwrap();
    assert_eq!(
        a.repo().contacts().unwrap_err(),
        Error::Integrity(IntegrityError::Signature)
    );
}

struct RotFixture {
    sk: SecretKey,
    me_keys: DeviceKeys,
}

/// The rotation fixture of `rotation_v2.rs`, reduced: A pins a genesis
/// whose roster is A alone, `Current`.
fn rotation_fixture(server: &mut Server) -> (Device, RotFixture) {
    let (mut a, sk) = Device::create();
    sync(server, &mut a).unwrap();
    let me_keys = DeviceKeys::generate_software().unwrap();
    let me = me_keys.public(a.repo().chain().device_id.unwrap()).unwrap();
    let account = a.repo().account();
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
            &me_keys,
            &account.keyset().identity,
        )
        .unwrap(),
    );
    let roster = vec![entry_of(&me, "iPhone")];
    let mut trust = TrustState::new(
        account_id,
        me.clone(),
        LineageHead {
            generation: 0,
            hash: genesis.hash(),
        },
        identity_pub,
        roster.clone(),
        DeviceLineageState::Current,
    );
    trust.levels.insert(me.device_id, TrustLevel::Verified);
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
    sync(server, &mut a).unwrap();
    (a, RotFixture { sk, me_keys })
}

// ---------------------------------------------------------------- refresh

#[test]
fn refresh_marks_keys_changed() {
    let (mut a, _) = Device::create();
    let c = carol();
    let before = pin(&mut a, &c.card, ContactLevel::Verified).unwrap();
    // Nothing new: Same, nothing written.
    let seq = a.repo().chain().contact_book.unwrap().seq;
    let r = a
        .repo()
        .refresh_contact(
            c.account_id,
            std::slice::from_ref(&c.genesis),
            &[],
            T0 + 300,
        )
        .unwrap();
    assert_eq!(r, ForeignLineage::Same);
    assert_eq!(a.repo().chain().contact_book.unwrap().seq, seq);

    let records = [c.genesis.clone(), c.rotation.clone()];
    let r = a
        .repo()
        .refresh_contact(c.account_id, &records, &[], T0 + 400)
        .unwrap();
    assert!(matches!(r, ForeignLineage::Advanced { .. }));
    let after = a.repo().contact(c.account_id).unwrap().unwrap();
    assert_eq!(
        after.state,
        ContactState::KeysChanged {
            child: c.rotation.hash(),
            seen_at: T0 + 400
        }
    );
    // S22: adopting is a human decision; keys and head stay.
    assert_eq!(after.pinned_head, before.pinned_head);
    assert_eq!(after.identity_pub, before.identity_pub);
    assert_eq!(after.sign_pub, before.sign_pub);
    assert_eq!(after.kem_pub, before.kem_pub);
    assert!(!after.usable_for(ContactLevel::Link));
    // Seen again later: the first sighting stays.
    a.repo()
        .refresh_contact(c.account_id, &records, &[], T0 + 900)
        .unwrap();
    assert_eq!(a.repo().contact(c.account_id).unwrap().unwrap(), after);
    // A pin never turns it back to Active.
    pin(&mut a, &c.card, ContactLevel::Verified).unwrap();
    assert_eq!(
        a.repo().contact(c.account_id).unwrap().unwrap().state,
        after.state
    );
    // Unknown contact.
    assert_eq!(
        a.repo()
            .refresh_contact(Id::new(), &records, &[], T0)
            .unwrap_err(),
        Error::NotFound
    );
}

#[test]
fn names_never_from_card() {
    let (mut a, _) = Device::create();
    let c = carol();
    pin(&mut a, &c.card, ContactLevel::Link).unwrap();
    // A card under another name, verified in person: the level moves, the
    // local name stays.
    let e = pin(&mut a, &c.renamed, ContactLevel::Verified).unwrap();
    assert_eq!(e.level, ContactLevel::Verified);
    assert_eq!(e.name_local, "Carol");
    a.repo()
        .refresh_contact(c.account_id, &c.renamed.card.lineage, &[], T0 + 300)
        .unwrap();
    assert_eq!(
        a.repo().contact(c.account_id).unwrap().unwrap().name_local,
        "Carol"
    );
    // Only the owner renames.
    a.repo().rename_contact(c.account_id, "Caro").unwrap();
    assert_eq!(
        a.repo().contact(c.account_id).unwrap().unwrap().name_local,
        "Caro"
    );
    assert!(is_validation(&a.repo().rename_contact(c.account_id, "")));
    assert!(is_validation(
        &a.repo().rename_contact(c.account_id, &"x".repeat(65))
    ));
    assert!(is_validation(
        &a.repo().rename_contact(c.account_id, "Caro\u{202E}")
    ));
    assert_eq!(
        a.repo().rename_contact(Id::new(), "X").unwrap_err(),
        Error::NotFound
    );
}

// ---------------------------------------------------------------- merge

/// Key material for random entries: per account, two geneses, two heads
/// each, each head with its own keys.
struct Pool {
    accounts: Vec<Id>,
    geneses: Vec<[u8; 32]>,
    heads: Vec<(
        LineageHead,
        onepass_core::crypto::IdentityVerifyingKey,
        HybridVerifyingKey,
        HybridKemPublic,
    )>,
}

fn pool() -> &'static Pool {
    static P: OnceLock<Pool> = OnceLock::new();
    P.get_or_init(|| {
        let ids: Vec<IdentityKey> = (0..2).map(|_| IdentityKey::generate().unwrap()).collect();
        let heads = (0..4u8)
            .map(|n| {
                let k = FreshKeys::new();
                (
                    LineageHead {
                        generation: u64::from(n % 2),
                        hash: [n + 1; 32],
                    },
                    ids[usize::from(n % 2)].verifying_key(),
                    k.sign,
                    k.kem,
                )
            })
            .collect();
        Pool {
            accounts: (1..=3u8).map(|n| Id([n; 16])).collect(),
            geneses: vec![[0xA0; 32], [0xB0; 32]],
            heads,
        }
    })
}

#[derive(Debug, Clone)]
enum Op {
    Pin {
        account: usize,
        genesis: usize,
        head: usize,
        verified: bool,
        at: i64,
        device: u8,
        transcript: u8,
    },
    Remove {
        account: usize,
        at: i64,
    },
    Rename {
        account: usize,
        name: String,
    },
    KeysChanged {
        account: usize,
        child: u8,
        at: i64,
    },
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        (
            0..3usize,
            0..2usize,
            0..4usize,
            any::<bool>(),
            0..50i64,
            0..3u8,
            0..3u8
        )
            .prop_map(
                |(account, genesis, head, verified, at, device, transcript)| Op::Pin {
                    account,
                    genesis,
                    head,
                    verified,
                    at,
                    device,
                    transcript,
                }
            ),
        (0..3usize, 0..50i64).prop_map(|(account, at)| Op::Remove { account, at }),
        (0..3usize, "[a-c]{1,3}").prop_map(|(account, name)| Op::Rename { account, name }),
        (0..3usize, 0..3u8, 0..50i64).prop_map(|(account, child, at)| Op::KeysChanged {
            account,
            child,
            at
        }),
    ]
}

/// One device's book after `ops`, the way the repository edits it: a new
/// version of an entry is merged into the stored one, the device's own
/// edit preferred.
fn apply(mut book: Vec<ContactEntry>, ops: &[Op]) -> Vec<ContactEntry> {
    let p = pool();
    for op in ops {
        let find = |book: &Vec<ContactEntry>, account: usize| {
            book.iter()
                .position(|e| e.account_id == p.accounts[account])
        };
        let edit = match op {
            Op::Pin {
                account,
                genesis,
                head,
                verified,
                at,
                device,
                transcript,
            } => {
                let (h, identity, sign, kem) = p.heads[*head].clone();
                Some(ContactEntry {
                    account_id: p.accounts[*account],
                    genesis: p.geneses[*genesis],
                    pinned_head: h,
                    identity_pub: identity,
                    sign_pub: sign,
                    kem_pub: kem,
                    level: if *verified {
                        ContactLevel::Verified
                    } else {
                        ContactLevel::Link
                    },
                    verified_at: *at,
                    verified_on: Id([*device; 16]),
                    transcript_hash: [*transcript; 32],
                    name_local: "n".into(),
                    state: ContactState::Active,
                })
            }
            Op::Remove { account, at } => find(&book, *account).map(|i| ContactEntry {
                state: ContactState::Removed { at: *at },
                ..book[i].clone()
            }),
            Op::Rename { account, name } => find(&book, *account).map(|i| ContactEntry {
                name_local: name.clone(),
                ..book[i].clone()
            }),
            Op::KeysChanged { account, child, at } => find(&book, *account).map(|i| ContactEntry {
                state: ContactState::KeysChanged {
                    child: [*child; 32],
                    seen_at: *at,
                },
                ..book[i].clone()
            }),
        };
        if let Some(e) = edit {
            match book.iter().position(|x| x.account_id == e.account_id) {
                Some(i) => book[i] = e.merge_preferring(&book[i]),
                None => {
                    book.push(e);
                    book.sort_by_key(|x| x.account_id);
                }
            }
        }
    }
    book
}

fn removed(book: &[ContactEntry]) -> Vec<Id> {
    book.iter()
        .filter(|e| matches!(e.state, ContactState::Removed { .. }))
        .map(|e| e.account_id)
        .collect()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn book_merge_commutes(
        base in prop::collection::vec(op(), 0..6),
        left in prop::collection::vec(op(), 0..8),
        right in prop::collection::vec(op(), 0..8),
    ) {
        let start = apply(Vec::new(), &base);
        let a = apply(start.clone(), &left);
        let b = apply(start, &right);
        let ab = merge(&a, &b);
        prop_assert_eq!(&ab, &merge(&b, &a));
        prop_assert_eq!(&merge(&ab, &a), &ab);
        prop_assert_eq!(&merge(&ab, &b), &ab);
        prop_assert_eq!(&merge(&ab, &ab), &ab);
        for id in removed(&a).into_iter().chain(removed(&b)) {
            let e = ab.iter().find(|e| e.account_id == id).unwrap();
            let gone = matches!(e.state, ContactState::Removed { .. });
            prop_assert!(gone, "removed entry came back: {:?}", e);
        }
        // A book is a valid list body.
        ListBody::next(None, Id::new(), ab).unwrap();
    }
}
