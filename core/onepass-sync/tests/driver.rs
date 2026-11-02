//! The Rust sync round over an in-memory mailbox: the cases of
//! `SyncCoordinatorTests.swift`, the mailbox's own (lost data, expired
//! cursor, clock, echo, blobs), the phases of a key rotation and the
//! `SyncHome` check.
//!
//! Devices are SQLite files from the core's two-device harness (shared
//! through `#[path]`): the driver runs on a second connection, as the apps
//! run it, with the unlocked session as its hooks.

#[path = "../../onepass-core/tests/common/mod.rs"]
mod common;

mod support;

use common::*;
use onepass_core::synchome::SyncBackend;
use std::cell::RefCell;
use std::rc::Rc;

use onepass_mailbox::testing::{FakeMailbox, FakeMailboxClient};
use onepass_mailbox::{Credential, MailboxApi, MailboxError};
use onepass_sync::policy::CURSOR_KEY;
use onepass_sync::{BatchLimits, Outgoing, RoundStatus, SendResult, Transport, TransportError};
use support::*;

#[test]
fn second_device_restores_through_remote() {
    let (_fake, mut a, mut b, _sk, items) = two_sides(&["alice", "bob"]);
    assert_eq!(users(&b.dev.items()), users(&items));
    assert_eq!(b.dev.items(), a.dev.items());
    assert!(b.round().status == RoundStatus::Idle);
    assert!(a.pending().is_empty());
}

#[test]
fn concurrent_edits_converge_on_both_devices() {
    let (_fake, mut a, mut b, _sk, items) = two_sides(&["alice", "bob"]);
    a.dev.save(&edited(&items[0], "alice2", 1_700_000_100));
    b.dev.save(&edited(&items[1], "bob2", 1_700_000_100));
    a.settle();
    b.settle();
    a.settle();
    assert_eq!(users(&a.dev.items()), ["alice2", "bob2"]);
    assert_eq!(a.dev.items(), b.dev.items());
}

#[test]
fn conflict_on_send_is_restaged_and_resent() {
    let (_fake, a, mut b, _sk, items) = two_sides(&["alice"]);
    let a = Rc::new(RefCell::new(a));
    b.dev.save(&edited(&items[0], "newer", 1_700_000_200));
    // A writes between B's fetch and B's send: B's send meets it, the
    // server's row is staged, the vault rebased, and B's version sent
    // again in the same round.
    let a2 = a.clone();
    let older = edited(&items[0], "older", 1_700_000_100);
    b.t.borrow_mut().before_send = Some(Box::new(move || {
        let mut a = a2.borrow_mut();
        a.dev.save(&older);
        a.settle();
    }));
    let r = b.round();
    // Pushed again; the server echoes it at the next fetch.
    assert!(
        matches!(r.status, RoundStatus::Idle | RoundStatus::WaitingForServer),
        "{r:?}"
    );
    assert!(b.pending().is_empty());
    let t = b.t.borrow();
    assert!(
        t.results
            .iter()
            .any(|rs| rs.iter().any(|r| matches!(r, SendResult::Conflict(_))))
    );
    assert!(!r.rebased.is_empty());
    drop(t);
    b.settle();
    let mut a = a.borrow_mut();
    a.settle();
    assert_eq!(users(&a.dev.items()), ["newer"]);
    assert_eq!(a.dev.items(), b.dev.items());
}

#[test]
fn locked_device_fetches_but_holds_conflicting_vault() {
    let (_fake, mut a, mut b, sk, items) = two_sides(&["alice"]);
    b.dev.save(&edited(&items[0], "by-b", 1_700_000_200));
    b.dev.lock();
    a.dev.save(&edited(&items[0], "by-a", 1_700_000_100));
    a.settle();
    // Locked: the fetch runs, the held vault sends nothing.
    b.t.borrow_mut().batches.clear();
    b.round();
    let v = b.dev.store().vaults_needing_rebase().unwrap();
    assert_eq!(v.len(), 1);
    assert!(
        b.t.borrow()
            .batches
            .iter()
            .flatten()
            .all(|(kind, _, _)| *kind != RecordKind::Manifest)
    );
    b.dev.unlock(&sk);
    assert_eq!(b.settle().status, RoundStatus::Idle);
    a.settle();
    assert_eq!(users(&a.dev.items()), ["by-b"]);
    assert_eq!(a.dev.items(), b.dev.items());
}

#[test]
fn replayed_manifest_is_served_from_the_local_copy() {
    let (_fake, mut a, mut b, _sk, items) = two_sides(&["alice"]);
    let v = b.dev.vault().id;
    let old = b.dev.store().get(RecordKind::Manifest, v).unwrap().unwrap();
    a.dev.save(&edited(&items[0], "alice2", 1_700_000_100));
    a.settle();
    b.settle();
    // The server serves the first manifest again.
    b.t.borrow_mut().inject.push(RemoteChange {
        kind: old.kind,
        id: old.id,
        version: old.version,
        data: Some(old.data),
        server_meta: Some(1u64.to_be_bytes().to_vec()),
    });
    b.round();
    assert_eq!(users(&b.dev.items()), ["alice2"]);
}

#[test]
fn locked_device_ignores_forged_deletions_of_its_account() {
    let (_fake, _a, mut b, _sk, _items) = two_sides(&["alice"]);
    let id = b.dev.repo().account().params.account_id;
    b.dev.lock();
    for kind in [
        RecordKind::AccountParams,
        RecordKind::Keyset,
        RecordKind::DeviceList,
    ] {
        b.t.borrow_mut().inject.push(RemoteChange {
            kind,
            id,
            version: 9,
            data: None,
            server_meta: Some(99u64.to_be_bytes().to_vec()),
        });
    }
    b.round();
    let ignored = b.dev.store().ignored_deletions().unwrap();
    assert!(ignored.iter().any(|d| d.kind == RecordKind::AccountParams));
    assert!(b.dev.store().has_account().unwrap());
}

#[test]
fn empty_zone_on_a_full_fetch_keeps_the_local_copy() {
    let (fake, _a, mut b, _sk, items) = two_sides(&["alice"]);
    // The server loses everything; B fetches from scratch, finds nothing,
    // keeps its copy and sends it all back.
    fake.lose_everything();
    assert_eq!(b.settle().status, RoundStatus::Idle);
    assert_eq!(users(&b.dev.items()), users(&items));
    assert!(b.pending().is_empty());
}

#[test]
fn interrupted_fetch_never_resurrects_a_pushed_deletion() {
    let (_fake, mut a, mut b, _sk, items) = two_sides(&["alice", "bob", "carol"]);
    a.dev.delete(items[1].id);
    a.settle();
    // B fetches from scratch, one record a page, and the fetch is cut
    // after its first page.
    b.driver.transport_mut().inner.set_page_limit(1);
    b.dev.store().delete_meta(CURSOR_KEY).unwrap();
    let n = b.t.borrow().fetches;
    b.t.borrow_mut().fail_on_fetch = Some((n + 2, TransportError::Offline));
    assert_eq!(b.round().status, RoundStatus::Offline);
    // Resumed from the saved cursor: the deletion holds.
    b.settle();
    assert_eq!(users(&b.dev.items()), ["alice", "carol"]);
    a.settle();
    assert_eq!(a.dev.items(), b.dev.items());
}

#[test]
fn unknown_records_are_skipped() {
    let (_fake, mut a, mut b, _sk, _items) = two_sides(&["alice"]);
    a.driver
        .transport_mut()
        .inner
        .api()
        .commit(vec![onepass_mailbox_proto::CommitOp {
            kind: 200,
            id: [7; 16],
            version: 1,
            op: onepass_mailbox_proto::Op::Put {
                expected: None,
                body: onepass_mailbox_proto::Body::Inline(vec![1, 2, 3]),
            },
        }])
        .unwrap();
    let r = b.round();
    assert_eq!(r.status, RoundStatus::Idle, "{r:?}");
    assert!(!r.changed);
}

#[test]
fn cursor_is_not_advanced_past_a_failed_page() {
    let (_fake, mut a, mut b, _sk, items) = two_sides(&["alice"]);
    let cursor = b.dev.store().meta(CURSOR_KEY).unwrap();
    a.dev.save(&edited(&items[0], "alice2", 1_700_000_100));
    a.settle();
    b.t.borrow_mut()
        .fail_fetch
        .push_back(TransportError::RecordUnreadable);
    assert_eq!(b.round().status, RoundStatus::Retrying);
    assert_eq!(b.dev.store().meta(CURSOR_KEY).unwrap(), cursor);
    assert_eq!(users(&b.dev.items()), ["alice"]);
    b.settle();
    assert_eq!(users(&b.dev.items()), ["alice2"]);
}

#[test]
fn large_send_is_split_with_items_before_their_manifest() {
    let (_fake, mut a, mut b, _sk, _items) = two_sides(&[]);
    a.t.borrow_mut().limits = Some(BatchLimits {
        max_records: 3,
        max_bytes: usize::MAX,
    });
    let v = a.dev.vault().id;
    for i in 0..7 {
        a.dev
            .save(&login(v, &format!("user{i}"), 1_700_000_000 + i));
    }
    a.t.borrow_mut().batches.clear();
    assert_eq!(a.settle().status, RoundStatus::Idle);
    let batches = a.t.borrow().batches.clone();
    assert!(batches.len() >= 3);
    assert!(batches.iter().all(|b| b.len() <= 3));
    let flat: Vec<RecordKind> = batches.iter().flatten().map(|(k, _, _)| *k).collect();
    let manifest = flat
        .iter()
        .position(|k| *k == RecordKind::Manifest)
        .unwrap();
    assert!(
        flat[..manifest]
            .iter()
            .filter(|k| **k == RecordKind::Item)
            .count()
            == 7
    );
    b.settle();
    assert_eq!(b.dev.items().len(), 7);
}

#[test]
fn save_without_server_meta_stays_pending() {
    let (_fake, mut a, _b, _sk, items) = two_sides(&["alice"]);
    a.t.borrow_mut().strip_meta = true;
    a.dev.save(&edited(&items[0], "alice2", 1_700_000_100));
    // The send goes through without meta, then the next turn's fetch is
    // cut: the change is still pending.
    let n = a.t.borrow().fetches;
    let sent = a.t.borrow().results.len();
    a.t.borrow_mut().fail_on_fetch = Some((n + 2, TransportError::Offline));
    let r = a.round();
    assert_eq!(r.status, RoundStatus::Offline, "{r:?}");
    assert_eq!(a.t.borrow().results.len(), sent + 1);
    assert!(!a.pending().is_empty());
    a.t.borrow_mut().strip_meta = false;
    a.settle();
    assert!(a.pending().is_empty());
}

#[test]
fn stale_tag_fails_the_whole_batch() {
    let (fake, mut a, mut b, _sk, items) = two_sides(&["alice", "bob"]);
    // Another writer moves item 0 on the server behind B's back.
    a.dev.save(&edited(&items[0], "alice2", 1_700_000_100));
    a.settle();
    // B, without fetching first, sends a batch over the old version.
    b.dev.save(&edited(&items[0], "alice3", 1_700_000_200));
    b.dev.save(&edited(&items[1], "bob3", 1_700_000_200));
    let head_before = fake_head(&fake, &b);
    let store = b.dev.store();
    let pending = store.pending_changes().unwrap();
    let batch: Vec<Outgoing> = pending
        .into_iter()
        .map(|change| Outgoing {
            server_meta: store.server_meta(change.kind, change.id).unwrap(),
            change,
        })
        .collect();
    let results = b.driver.transport_mut().send(&batch).unwrap();
    assert!(results.iter().any(|r| matches!(r, SendResult::Conflict(_))));
    assert!(
        !results
            .iter()
            .any(|r| matches!(r, SendResult::Saved { .. }))
    );
    assert_eq!(fake_head(&fake, &b), head_before);
    // The round then settles both edits.
    b.settle();
    a.settle();
    assert_eq!(users(&a.dev.items()), ["alice3", "bob3"]);
}

fn fake_head(_fake: &FakeMailbox, side: &Side) -> u64 {
    side.driver
        .transport()
        .inner
        .api()
        .changes(0, 1, false)
        .unwrap()
        .head
}

#[test]
fn unreadable_record_is_reported_after_five_rounds() {
    let (_fake, _a, mut b, _sk, _items) = two_sides(&["alice"]);
    for round in 1..=5 {
        b.t.borrow_mut()
            .fail_fetch
            .push_back(TransportError::RecordUnreadable);
        let r = b.round();
        if round < 5 {
            assert_eq!(r.status, RoundStatus::Retrying, "round {round}");
        } else {
            assert_eq!(r.status, RoundStatus::Unreadable);
        }
        assert!(r.retry_after.is_some());
    }
    assert_eq!(b.round().status, RoundStatus::Idle);
}

// ---------------------------------------------------------- mailbox only

#[test]
fn lost_mailbox_is_uploaded_again_and_other_device_converges() {
    let (fake, mut a, mut b, _sk, items) = two_sides(&["alice", "bob"]);
    fake.lose_everything();
    assert_eq!(a.settle().status, RoundStatus::Idle);
    b.dev.save(&edited(&items[1], "bob2", 1_700_000_100));
    assert_eq!(b.settle().status, RoundStatus::Idle);
    a.settle();
    assert_eq!(users(&a.dev.items()), ["alice", "bob2"]);
    assert_eq!(a.dev.items(), b.dev.items());
}

#[test]
fn expired_cursor_refetches_from_scratch() {
    let (fake, mut a, mut b, _sk, items) = two_sides(&["alice", "bob", "carol"]);
    // B goes away with a write of its own.
    b.dev.save(&edited(&items[2], "carol-b", 1_700_000_300));
    // A deletes an item; the tombstone is purged before B comes back.
    a.dev.delete(items[1].id);
    a.settle();
    let head = a
        .driver
        .transport()
        .inner
        .api()
        .changes(0, 1, false)
        .unwrap()
        .head;
    fake.purge_tombstones_before(head + 1);
    let r = b.round();
    assert!(
        matches!(r.status, RoundStatus::Idle | RoundStatus::WaitingForServer),
        "{r:?}"
    );
    b.settle();
    // B's own write left; the purged deletion still holds on B.
    a.settle();
    assert_eq!(users(&b.dev.items()), ["alice", "carol-b"]);
    assert_eq!(a.dev.items(), b.dev.items());
}

#[test]
fn stale_request_reports_clock() {
    let (fake, _a, mut b, _sk, _items) = two_sides(&["alice"]);
    fake.faults().fail_next(MailboxError::Stale);
    let r = b.round();
    assert_eq!(r.status, RoundStatus::ClockSkew);
    assert!(r.retry_after.is_some());
    assert_eq!(b.round().status, RoundStatus::Idle);
}

#[test]
fn echo_of_own_push_is_not_a_change() {
    let (_fake, mut a, _b, _sk, items) = two_sides(&["alice"]);
    a.dev.save(&edited(&items[0], "alice2", 1_700_000_100));
    a.round();
    let r = a.round();
    assert_eq!(r.status, RoundStatus::Idle);
    assert!(!r.changed, "{r:?}");
}

#[test]
fn blob_records_round_trip() {
    let (_fake, mut a, mut b, _sk, items) = two_sides(&["alice"]);
    let mut big = items[0].clone();
    big.notes = "n".repeat(40 * 1024);
    big.updated_at = at(1_700_000_100);
    a.dev.save(&big);
    a.settle();
    b.settle();
    assert_eq!(b.dev.items()[0].notes.len(), 40 * 1024);
}

// ------------------------------------------------------------- sync home

#[test]
fn home_moved_stops_the_round() {
    let (_fake, mut a, _b, _sk, items) = two_sides(&["alice"]);
    let elsewhere = SyncBackend::Mailbox {
        url: "https://other.example.org/functions/v1/mailbox".into(),
        mailbox_id: [9; 16],
    };
    a.dev.repo().set_sync_home(elsewhere.clone(), NOW).unwrap();
    a.dev.save(&edited(&items[0], "alice2", 1_700_000_100));
    a.t.borrow_mut().batches.clear();
    let r = a.round();
    assert_eq!(r.status, RoundStatus::HomeMoved(elsewhere.clone()));
    assert!(a.t.borrow().batches.is_empty());
    assert!(!a.pending().is_empty());
    // Locked, the last home read still stops it.
    let sk_less = a.dev.repo.take();
    let r = a.round();
    assert_eq!(r.status, RoundStatus::HomeMoved(elsewhere));
    a.dev.repo = sk_less;
}

#[test]
fn cloudkit_home_stops_the_round() {
    let (_fake, mut a, _b, _sk, _items) = two_sides(&["alice"]);
    a.dev
        .repo()
        .set_sync_home(SyncBackend::CloudKit, NOW)
        .unwrap();
    assert_eq!(
        a.round().status,
        RoundStatus::HomeMoved(SyncBackend::CloudKit)
    );
}

#[test]
fn own_home_lets_the_round_through() {
    let (_fake, mut a, mut b, _sk, _items) = two_sides(&["alice"]);
    let home = home_of(a.driver.transport().inner.api());
    let set = a.dev.repo().set_sync_home(home, NOW).unwrap();
    assert_eq!(a.settle().status, RoundStatus::Idle);
    assert_eq!(b.settle().status, RoundStatus::Idle);
    assert_eq!(b.dev.repo().sync_home().unwrap(), Some(set));
}

// -------------------------------------------------------------- rotation

mod rotation {
    use super::*;
    use onepass_core::device_keys::{DeviceKeys, DevicePublic};
    use onepass_core::devices::{DeviceKind, DeviceMode};
    use onepass_core::lineage::{
        GenesisBody, LINEAGE_FORMAT, LineageRecord, RosterEntry, RotationReason, sign_genesis,
    };
    use onepass_core::repo::RotateRequest;
    use onepass_core::trust::{DeviceLineageState, LineageHead, TrustLevel, TrustState};

    pub struct Rotator {
        pub side: Side,
        pub sk: SecretKey,
        pub keys: DeviceKeys,
        pub fake: FakeMailbox,
        pub other: FakeMailboxClient,
        /// The roster's other device: its keys and its public part.
        pub other_keys: DeviceKeys,
        pub other_pub: DevicePublic,
    }

    fn entry(p: &DevicePublic, name: &str) -> RosterEntry {
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

    /// A with two items, its trust state pinned to a genesis whose roster
    /// is A and one other device, synced to a mailbox (all of it uploaded
    /// by the first round).
    pub fn rotator() -> Rotator {
        let (fake, ca, cb) = mailbox();
        let (mut a, sk) = Device::create();
        let v = a.vault().id;
        a.save(&login(v, "alice", 1_700_000_000));
        a.save(&login(v, "bob", 1_700_000_001));
        let id = a.repo().chain().device_id.unwrap_or_else(Id::new);
        let keys = DeviceKeys::generate_software().unwrap();
        let me = keys.public(id).unwrap();
        let other_keys = DeviceKeys::generate_software().unwrap();
        let other = other_keys.public(Id::new()).unwrap();
        let other_pub = other.clone();
        let mut roster = vec![entry(&me, "iPhone"), entry(&other, "iPad")];
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
                    creator: entry(&me, "iPhone"),
                    created_at: 1_700_000_000,
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
        let home = home_of(&ca);
        let mut side = Side::new(a, ca, home);
        assert_eq!(side.settle().status, RoundStatus::Idle);
        Rotator {
            side,
            sk,
            keys,
            fake,
            other: cb,
            other_keys,
            other_pub,
        }
    }

    pub fn state(side: &Side) -> DeviceLineageState {
        side.dev.store().trust_state().unwrap().unwrap().state
    }

    pub fn rotate(r: &mut Rotator, new_sk: &SecretKey) -> [u8; 32] {
        let req = RotateRequest {
            revoke: vec![],
            new_password: None,
            password: PASSWORD,
            secret_key: &r.sk,
            new_secret_key: new_sk,
            device_keys: &r.keys,
            reason: RotationReason::Rotate,
            keep_tofu: &[],
        };
        let out = r.side.dev.repo().rotate(req).unwrap();
        assert_eq!(state(&r.side), DeviceLineageState::Rotating { phase: 1 });
        out.head
    }

    const PHASE_ONE: [RecordKind; 7] = [
        RecordKind::KeyDelivery,
        RecordKind::AccountParams,
        RecordKind::Keyset,
        RecordKind::DeviceList,
        RecordKind::VaultList,
        RecordKind::SyncHome,
        RecordKind::Lineage,
    ];

    /// The roster's other device on the mailbox (its client `other`), with
    /// A's trust state as its own: it syncs locked, then is locked again.
    pub fn follower(r: &mut Rotator) -> Side {
        let client =
            std::mem::replace(&mut r.other, r.fake.client(Credential::generate().unwrap()));
        let home = r.side.driver.transport().inner.api().mailbox().unwrap();
        let mut c = Side::new(
            Device::empty(),
            client,
            SyncBackend::Mailbox {
                url: URL.into(),
                mailbox_id: home,
            },
        );
        c.now = r.side.now;
        assert_eq!(c.round().status, RoundStatus::Idle);
        c.dev.unlock(&r.sk);
        let mut trust = r.side.dev.store().trust_state().unwrap().unwrap();
        trust.me = r.other_pub.clone();
        c.dev
            .repo()
            .store_mut()
            .put_all_if_version_with_trust(vec![], vec![], None, &trust)
            .unwrap();
        assert_eq!(c.settle().status, RoundStatus::Idle);
        c.dev.lock();
        c
    }

    /// A on its mailbox home, C following: A rotates and pushes its phases
    /// through the mailbox, C fetches locked and follows.
    fn rotated_across(r: &mut Rotator) -> (Side, SecretKey) {
        let home = home_of(r.side.driver.transport().inner.api());
        r.side.dev.repo().set_sync_home(home, NOW).unwrap();
        assert_eq!(r.side.settle().status, RoundStatus::Idle);
        let mut c = follower(r);
        let new_sk = SecretKey::generate().unwrap();
        let head = rotate(r, &new_sk);
        r.side.round();
        assert_eq!(state(&r.side), DeviceLineageState::Current);
        // Locked, C fetches the rotation; then it follows.
        c.round();
        let (repo, _auk, sk) = onepass_core::repo::follow::follow_rotation(
            c.dev.store(),
            head,
            PASSWORD,
            &r.other_keys,
        )
        .unwrap();
        assert_eq!(sk.to_display(), new_sk.to_display());
        c.dev.repo = Some(repo);
        (c, new_sk)
    }

    #[test]
    fn driver_round_across_rotation() {
        let mut r = rotator();
        let (mut c, new_sk) = rotated_across(&mut r);
        assert_eq!(c.settle().status, RoundStatus::Idle);
        r.side.dev.repo = None;
        r.side.dev.try_unlock(PASSWORD, &new_sk).unwrap();
        assert_eq!(r.side.settle().status, RoundStatus::Idle);
        // Same head, same home, same items.
        let head = |s: &Side| s.dev.store().trust_state().unwrap().unwrap().head;
        assert_eq!(head(&c), head(&r.side));
        let home_a = r.side.dev.repo().sync_home().unwrap().unwrap();
        let home_c = c.dev.repo().sync_home().unwrap().unwrap();
        assert_eq!(home_a, home_c);
        assert_eq!(home_c.seq, 1);
        assert_eq!(c.dev.items(), r.side.dev.items());
    }

    #[test]
    fn rotation_cannot_move_home() {
        // A valid rotation, then the new identity's home names another
        // mailbox (its record reaches this one): the follower stops with
        // `HomeMoved`, a confirmation of its own, never a silent switch.
        let mut r = rotator();
        let (mut c, _new_sk) = rotated_across(&mut r);
        assert_eq!(c.settle().status, RoundStatus::Idle);
        let elsewhere = SyncBackend::Mailbox {
            url: "https://other.example.org/functions/v1/mailbox".into(),
            mailbox_id: [6; 16],
        };
        let params = r.side.dev.repo().account().params.clone();
        let rid =
            onepass_core::store::account_record_id(params.account_id, Some(&params.identity_pub));
        r.side
            .dev
            .repo()
            .set_sync_home(elsewhere.clone(), NOW + 9)
            .unwrap();
        let rec = r
            .side
            .dev
            .store()
            .get(RecordKind::SyncHome, rid)
            .unwrap()
            .unwrap();
        r.fake.faults().inject(onepass_mailbox_proto::ServerRecord {
            seq: 0,
            kind: rec.kind.code(),
            id: rec.id.0,
            version: rec.version,
            body: Some(onepass_mailbox_proto::Body::Inline(rec.data)),
        });
        let v = c.dev.vault().id;
        c.dev.save(&login(v, "carol", 1_700_000_200));
        c.t.borrow_mut().batches.clear();
        let report = c.round();
        assert_eq!(report.status, RoundStatus::HomeMoved(elsewhere));
        assert!(c.t.borrow().batches.is_empty());
        assert!(!c.pending().is_empty());
    }

    #[test]
    fn rotation_phases_pushed_in_order() {
        let mut r = rotator();
        let expected = r.side.dev.items();
        let new_sk = SecretKey::generate().unwrap();
        rotate(&mut r, &new_sk);
        r.side.t.borrow_mut().batches.clear();
        let report = r.side.round();
        assert!(
            matches!(
                report.status,
                RoundStatus::Idle | RoundStatus::WaitingForServer
            ),
            "{report:?}"
        );
        assert_eq!(state(&r.side), DeviceLineageState::Current);
        let batches = r.side.t.borrow().batches.clone();
        assert!(batches.len() >= 3, "{batches:?}");
        // Phase 1: new account records and deliveries, the lineage record
        // last.
        let first = &batches[0];
        assert!(first.iter().all(|(k, _, w)| *w && PHASE_ONE.contains(k)));
        assert_eq!(first.last().unwrap().0, RecordKind::Lineage);
        // Phase 2: the vault records, written, with the rotator's own
        // acknowledgment of the head (O6), which no phase holds back; phase
        // 3: deletions only.
        assert!(
            batches[1].iter().all(|(k, _, w)| *w
                && matches!(
                    k,
                    RecordKind::VaultKey
                        | RecordKind::VaultMeta
                        | RecordKind::Item
                        | RecordKind::Manifest
                        | RecordKind::DeviceAck
                )),
            "{:?}",
            batches[1]
        );
        assert!(batches[2].iter().all(|(_, _, w)| !*w));
        // The new identity opens.
        r.side.dev.repo = None;
        r.side.dev.try_unlock(PASSWORD, &new_sk).unwrap();
        assert_eq!(r.side.dev.items(), expected);
        assert!(r.side.pending().is_empty());
    }

    #[test]
    fn cut_between_phases_resumes() {
        let mut r = rotator();
        let new_sk = SecretKey::generate().unwrap();
        rotate(&mut r, &new_sk);
        // Phase 1 lands, then the transport fails.
        r.side.t.borrow_mut().sends_before_offline = Some(1);
        assert_eq!(r.side.round().status, RoundStatus::Offline);
        assert_eq!(state(&r.side), DeviceLineageState::Rotating { phase: 2 });
        // The next round resumes at phase 2.
        r.side.t.borrow_mut().sends_before_offline = None;
        r.side.t.borrow_mut().batches.clear();
        r.side.round();
        assert_eq!(state(&r.side), DeviceLineageState::Current);
        let batches = r.side.t.borrow().batches.clone();
        assert!(
            batches[0].iter().all(|(k, _, _)| !PHASE_ONE.contains(k)),
            "{batches:?}"
        );
        let _ = (&r.fake, &r.other);
    }
}
