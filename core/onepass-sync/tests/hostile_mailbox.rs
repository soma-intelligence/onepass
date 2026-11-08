//! A hostile mailbox (spec 11, 8; architecture 12, the attack classes of
//! the ETH Zurich and USI studies): replayed, withheld, reordered, injected
//! or rewound records, a lost commit answer, a batch applied in part,
//! another mailbox served in place of this one, an old `SyncHome`. Each
//! class has its expected outcome: nothing the device verified is lost or
//! replaced, and what the server hides ends in an alert or a refusal.
//!
//! Then the two-device scenarios of `onepass-core/tests/sync_two_devices.rs`
//! that go through `SyncStore`, replayed through `SyncDriver`,
//! `MailboxTransport` and `FakeMailbox`.

#[path = "../../onepass-core/tests/common/mod.rs"]
mod common;

mod support;

use common::*;
use onepass_core::sync::{STALE_ALERT_ROUNDS, STALE_ALERT_SECONDS};
use onepass_mailbox::MailboxApi;
use onepass_mailbox::testing::FakeMailbox;
use onepass_mailbox_proto::{Body, ServerRecord};
use onepass_sync::RoundStatus;
use support::*;

/// The vault every item of `two_sides` lives in.
fn vault(side: &mut Side) -> Id {
    side.dev.vault().id
}

/// The ids of the item records `side` is about to send.
fn pending_item_records(side: &Side) -> Vec<Id> {
    side.pending()
        .into_iter()
        .filter(|c| c.kind == RecordKind::Item && c.data.is_some())
        .map(|c| c.id)
        .collect()
}

/// The head of the mailbox `side` syncs with.
fn head(side: &Side) -> u64 {
    side.driver
        .transport()
        .inner
        .api()
        .changes(0, 1, false)
        .unwrap()
        .head
}

fn health_of(side: &mut Side, v: Id) -> VaultSyncHealth {
    health(&mut side.dev, v)
}

#[test]
fn replayed_page_changes_nothing() {
    let (fake, mut a, mut b, _sk, items) = two_sides(&["alice", "bob"]);
    a.dev.save(&edited(&items[0], "alice2", T0 + 10));
    a.settle();
    b.settle();
    let before = b.dev.items();
    let cursor = b
        .dev
        .store()
        .meta(onepass_sync::policy::CURSOR_KEY)
        .unwrap();

    // The server serves the first page again, whatever B asked.
    fake.faults().replay_page(0);
    let r = b.round();
    assert_ne!(r.status, RoundStatus::Idle, "a replayed page is refused");
    assert_eq!(b.dev.items(), before);
    assert_eq!(
        b.dev
            .store()
            .meta(onepass_sync::policy::CURSOR_KEY)
            .unwrap(),
        cursor,
        "the cursor never moves on a refused page"
    );
    // Next round, the honest page: nothing changed.
    assert_eq!(b.settle().status, RoundStatus::Idle);
    assert_eq!(b.dev.items(), before);
    assert_eq!(b.dev.items(), a.dev.items());
}

#[test]
fn withheld_item_alerts_after_threshold() {
    let (fake, mut a, mut b, _sk, items) = two_sides(&["x"]);
    let v = vault(&mut b);
    // B verified the vault once (its copy to serve).
    assert_eq!(users(&b.dev.items()), ["x"]);
    a.dev.save(&edited(&items[0], "x.a", T0 + 10));
    let new_records = pending_item_records(&a);
    assert_eq!(new_records.len(), 1);
    a.settle();
    // The server keeps the new manifest but never serves the new record.
    fake.faults()
        .withhold(RecordKind::Item.code(), new_records[0].0);
    // B serves the copy it verified, never a half state, until the
    // threshold.
    for _ in 0..STALE_ALERT_ROUNDS - 1 {
        b.now += 150;
        let r = b.round();
        assert_eq!(r.status, RoundStatus::WaitingForServer, "{r:?}");
        assert!(is_behind(health_of(&mut b, v)));
        assert_eq!(users(&b.dev.items()), ["x"]);
    }
    b.now += STALE_ALERT_SECONDS;
    b.round();
    assert_eq!(
        health_of(&mut b, v),
        VaultSyncHealth::Alert(IntegrityError::ManifestMissingItem)
    );
    // Never a local deletion.
    assert_eq!(users(&b.dev.items()), ["x"]);
    assert_eq!(users(&a.dev.items()), ["x.a"]);
}

#[test]
fn reordered_pages_converge() {
    let (fake, mut a, mut b, _sk, items) = two_sides(&["alice", "bob", "carol"]);
    b.driver.transport_mut().inner.set_page_limit(2);
    a.dev.save(&edited(&items[0], "alice2", T0 + 10));
    a.dev.delete(items[1].id);
    let v = vault(&mut a);
    a.dev.save(&login(v, "dave", T0 + 11));
    assert_eq!(a.settle().status, RoundStatus::Idle);
    let before = b.dev.items();
    let cursor = b
        .dev
        .store()
        .meta(onepass_sync::policy::CURSOR_KEY)
        .unwrap();

    // Pages in reverse seq order: the strict codec refuses them (a page's
    // seqs rise), nothing is staged, the cursor stays.
    fake.faults().reorder_pages();
    for _ in 0..2 {
        let r = b.round();
        assert_eq!(r.status, RoundStatus::Retrying, "{r:?}");
    }
    assert_eq!(b.dev.items(), before);
    assert_eq!(
        b.dev
            .store()
            .meta(onepass_sync::policy::CURSOR_KEY)
            .unwrap(),
        cursor
    );

    // In order again: B converges.
    fake.faults().honest();
    assert_eq!(b.settle().status, RoundStatus::Idle);
    assert_eq!(users(&b.dev.items()), ["alice2", "carol", "dave"]);
    assert_eq!(b.dev.items(), a.dev.items());
}

#[test]
fn injected_record_refused() {
    let (fake, mut a, mut b, _sk, items) = two_sides(&["alice"]);
    let v = vault(&mut b);
    a.dev.save(&edited(&items[0], "alice2", T0 + 10));
    let id = pending_item_records(&a)[0];
    a.settle();
    b.settle();
    let before = b.dev.items();
    assert_eq!(users(&before), ["alice2"]);

    // A forged item (random bytes) under the id the manifest lists.
    let forged = random_array::<400>().unwrap().to_vec();
    fake.faults().inject(ServerRecord {
        seq: 0,
        kind: RecordKind::Item.code(),
        id: id.0,
        version: 7,
        body: Some(Body::Inline(forged)),
    });
    let r = b.round();
    assert_ne!(r.status, RoundStatus::Idle, "{r:?}");
    // The verified copy is still what B serves.
    assert_eq!(b.dev.items(), before);
    assert_ne!(health_of(&mut b, v), VaultSyncHealth::Ok);
}

#[test]
fn cut_between_commit_and_reply_heals() {
    let (fake, mut a, mut b, _sk, items) = two_sides(&["x"]);
    a.dev.save(&edited(&items[0], "x.a", T0 + 10));
    // The server takes the batch, the device never hears back.
    fake.faults().drop_commit_reply();
    let r = a.round();
    assert_eq!(r.status, RoundStatus::Offline, "{r:?}");
    assert!(!a.pending().is_empty());

    // Next round: A sees its own echo, nothing is left to send.
    assert_eq!(a.settle().status, RoundStatus::Idle);
    assert!(a.pending().is_empty());
    assert!(a.dev.store().vaults_needing_rebase().unwrap().is_empty());
    assert_eq!(users(&a.dev.items()), ["x.a"]);
    b.settle();
    assert_eq!(a.dev.items(), b.dev.items());

    // And the chain goes on from there.
    let x = a.dev.items().remove(0);
    a.dev.save(&edited(&x, "x.a2", T0 + 20));
    a.settle();
    b.settle();
    assert_eq!(users(&b.dev.items()), ["x.a2"]);
}

#[test]
fn partial_batch_detected() {
    let (fake, mut a, mut b, _sk, items) = two_sides(&["x", "y"]);
    let v = vault(&mut b);
    assert_eq!(users(&b.dev.items()), ["x", "y"]);
    a.dev.save(&edited(&items[0], "x.a", T0 + 10));
    let item = pending_item_records(&a)[0];
    // The batch is the new item record, the manifest, the old record's
    // tombstone: the server drops the item and answers `Applied`.
    fake.faults().apply_partially(1);
    assert_eq!(a.round().status, RoundStatus::Idle);
    assert!(a.pending().is_empty(), "A believes it all landed");

    // B sees the manifest without its item: it keeps serving its copy,
    // the vault is behind, then an alert at the threshold.
    for _ in 0..STALE_ALERT_ROUNDS - 1 {
        b.now += 150;
        b.round();
        assert!(
            is_behind(health_of(&mut b, v)),
            "{:?}",
            health_of(&mut b, v)
        );
        assert_eq!(users(&b.dev.items()), ["x", "y"]);
    }
    b.now += STALE_ALERT_SECONDS;
    b.round();
    assert_eq!(
        health_of(&mut b, v),
        VaultSyncHealth::Alert(IntegrityError::ManifestMissingItem)
    );
    assert_eq!(users(&b.dev.items()), ["x", "y"]);
    assert_eq!(users(&a.dev.items()), ["x.a", "y"]);

    // A's next fetch reaches the head without the echo of its item: the
    // server lied. A sends its copy of the item again.
    assert_eq!(a.settle().status, RoundStatus::Idle);
    let on_server = a
        .driver
        .transport()
        .inner
        .api()
        .record(RecordKind::Item.code(), item.0)
        .unwrap();
    assert!(on_server.is_some_and(|r| r.body.is_some()));
    // B reads the whole vault again; its health clears after clean rounds.
    for _ in 0..onepass_core::sync::STALE_CLEAR_ROUNDS + 1 {
        b.round();
    }
    assert_eq!(health_of(&mut b, v), VaultSyncHealth::Ok);
    assert_eq!(b.round().status, RoundStatus::Idle);
    assert_eq!(users(&b.dev.items()), ["x.a", "y"]);
    assert_eq!(b.dev.items(), a.dev.items());
}

#[test]
fn commit_answered_above_head_detected() {
    let (fake, mut a, mut b, _sk, items) = two_sides(&["x"]);
    a.dev.save(&edited(&items[0], "x.a", T0 + 10));
    let item = pending_item_records(&a)[0];
    // The server stores nothing and answers seqs no head will ever reach.
    fake.faults().apply_above_head();
    assert_eq!(a.round().status, RoundStatus::Idle);
    assert!(a.pending().is_empty(), "A believes it all landed");
    let on_server = |a: &Side| {
        a.driver
            .transport()
            .inner
            .api()
            .record(RecordKind::Item.code(), item.0)
            .unwrap()
    };
    assert!(on_server(&a).is_none());

    // A's next fetch reaches the head below the seqs it was answered: the
    // batch is lost, A sends its copy again.
    a.settle();
    assert!(on_server(&a).is_some_and(|r| r.body.is_some()));
    b.settle();
    assert_eq!(users(&b.dev.items()), ["x.a"]);
    assert_eq!(b.dev.items(), a.dev.items());
}

#[test]
fn rewound_mailbox_detected() {
    let (fake, mut a, mut b, _sk, items) = two_sides(&["x"]);
    let v = vault(&mut b);
    let at_v2 = head(&a);
    a.dev.save(&edited(&items[0], "x.a", T0 + 10));
    a.settle();
    b.settle();
    let version = |s: &Side| {
        s.dev
            .store()
            .get(RecordKind::Manifest, v)
            .unwrap()
            .unwrap()
            .version
    };
    let newest = version(&b);
    assert_eq!(users(&b.dev.items()), ["x.a"]);

    // An old backup under the same incarnation.
    fake.faults().rewind_to(at_v2);
    let r = b.round();
    assert_ne!(r.status, RoundStatus::Idle, "{r:?}");
    // The older manifest is never accepted.
    assert_eq!(users(&b.dev.items()), ["x.a"]);
    assert_eq!(version(&b), newest);

    // The devices put their copy back, and a write after it reaches B.
    a.settle();
    b.settle();
    let x = a.dev.items().remove(0);
    a.dev.save(&edited(&x, "x.a2", T0 + 20));
    assert_eq!(a.settle().status, RoundStatus::Idle);
    assert_eq!(b.settle().status, RoundStatus::Idle);
    assert_eq!(users(&b.dev.items()), ["x.a2"]);
    assert_eq!(b.dev.items(), a.dev.items());
}

/// The account's `SyncHome` record as `side` holds it.
fn home_record(side: &Side) -> Record {
    let mut homes = side.dev.store().list(RecordKind::SyncHome).unwrap();
    assert_eq!(homes.len(), 1);
    homes.remove(0)
}

fn server_record(r: &Record) -> ServerRecord {
    ServerRecord {
        seq: 0,
        kind: r.kind.code(),
        id: r.id.0,
        version: r.version,
        body: Some(Body::Inline(r.data.clone())),
    }
}

/// A signs a first home naming another mailbox (kept aside, never sent),
/// then the home naming this one, and both devices pin it. Returns the
/// first home's record.
fn homes(a: &mut Side, b: &mut Side) -> Record {
    let here = home_of(a.driver.transport().inner.api());
    let elsewhere = onepass_core::synchome::SyncBackend::Mailbox {
        url: URL.into(),
        mailbox_id: [7; 16],
    };
    a.dev.repo().set_sync_home(elsewhere, NOW).unwrap();
    let old = home_record(a);
    a.dev.repo().set_sync_home(here, NOW + 1).unwrap();
    assert_eq!(a.settle().status, RoundStatus::Idle);
    assert_eq!(b.settle().status, RoundStatus::Idle);
    assert_eq!(b.dev.repo().sync_home().unwrap().unwrap().seq, 2);
    old
}

#[test]
fn other_mailbox_detected() {
    let (fake, mut a, mut b, _sk, items) = two_sides(&["x"]);
    let old_home = homes(&mut a, &mut b);
    // Another mailbox of the same account: what this one held, with the
    // first home in it.
    let other = FakeMailbox::new();
    let mut oc = other.client(onepass_mailbox::Credential::generate().unwrap());
    oc.create(None, b"other").unwrap();
    other.faults().serve_from(&fake);
    other.faults().inject(server_record(&old_home));

    a.dev.save(&edited(&items[0], "x.a", T0 + 10));
    a.settle();
    let before = b.dev.items();
    let store_before = b.dev.store().list(RecordKind::Manifest).unwrap();
    fake.faults().serve_from(&other);
    let r = b.round();
    assert!(
        matches!(
            r.status,
            RoundStatus::Refused { .. } | RoundStatus::HomeMoved(_)
        ),
        "{r:?}"
    );
    // Nothing written locally.
    assert_eq!(b.dev.items(), before);
    assert_eq!(
        b.dev.store().list(RecordKind::Manifest).unwrap(),
        store_before
    );
    assert_home_still_pinned(&mut b);
}

/// The older home is refused on every read, the pin stays at seq 2.
fn assert_home_still_pinned(b: &mut Side) {
    assert!(matches!(
        b.dev.repo().sync_home(),
        Err(Error::Integrity(IntegrityError::SyncHomeRollback))
    ));
    let pin = RecordStore::chain_state(&b.dev.store()).unwrap().sync_home;
    assert_eq!(pin.map(|s| s.seq), Some(2));
}

#[test]
fn old_sync_home_refused() {
    let (fake, mut a, mut b, _sk, _items) = two_sides(&["x"]);
    let old_home = homes(&mut a, &mut b);
    fake.faults().inject(server_record(&old_home));
    let r = b.round();
    assert_eq!(
        r.status,
        RoundStatus::Refused {
            kind: "sync_home_rollback".into()
        }
    );
    assert_home_still_pinned(&mut b);
}

/// The scenarios of `sync_two_devices.rs` over the mailbox.
mod sync_two_devices_over_mailbox {
    use super::*;

    #[test]
    fn concurrent_edits_of_same_item_newest_wins() {
        let (_fake, mut a, mut b, _sk, items) = two_sides(&["x"]);
        let x = &items[0];
        a.dev.save(&edited(x, "x.a", T0 + 10));
        b.dev.save(&edited(x, "x.b", T0 + 20));
        a.settle();
        b.settle();
        a.settle();
        assert_eq!(users(&a.dev.items()), ["x.b"]);
        assert_eq!(a.dev.items(), b.dev.items());

        // B edits after A again, but pushes first: A's older edit is
        // dropped.
        let x = a.dev.items().remove(0);
        a.dev.save(&edited(&x, "x.a2", T0 + 30));
        b.dev.save(&edited(&x, "x.b2", T0 + 40));
        b.settle();
        a.settle();
        b.settle();
        assert_eq!(users(&a.dev.items()), ["x.b2"]);
        assert_eq!(a.dev.items(), b.dev.items());
    }

    #[test]
    fn remote_password_change_wins_and_keeps_local_usage() {
        use onepass_core::fill_plan::context::FieldRole;
        use onepass_core::fill_plan::intent::Intent;
        use onepass_core::model::usage::{SiteUsage, StepKind, form_shape_hash};

        let (_fake, mut a, mut b, _sk, items) = two_sides(&["x"]);
        let x = &items[0];
        let site = SiteUsage {
            site: "exemple.fr".into(),
            form_shape_hash: form_shape_hash(&[FieldRole::Username, FieldRole::CurrentPassword]),
            intent: Intent::Login,
            step_seq: vec![StepKind::Fill],
            count: 1,
            last_at: at(T0 + 5),
        };
        let v = b.dev.vault();
        assert!(
            b.dev
                .repo()
                .record_usage(&v, x.id, site.clone(), at(T0 + 5), false)
                .unwrap()
        );
        let mut changed = x.clone();
        changed.field_mut("password").unwrap().value =
            FieldValue::Password("n3w".to_owned().into());
        changed.updated_at = at(T0 + 10);
        a.dev.save(&changed);
        a.settle();
        b.settle();
        a.settle();

        let got = b.dev.items().remove(0);
        assert_eq!(got.field("password"), changed.field("password"));
        assert_eq!(got.updated_at, changed.updated_at);
        let on_a = a.dev.items().remove(0);
        assert_eq!(on_a.field("password"), changed.field("password"));
        assert_eq!(a.dev.items(), b.dev.items());
    }

    #[test]
    fn held_vault_sends_nothing_until_rebased() {
        let (_fake, mut a, mut b, sk, items) = two_sides(&["x", "y"]);
        let (x, y) = (&items[0], &items[1]);
        let v = x.vault_id;

        // B edits X, then locks before pushing.
        b.dev.save(&edited(x, "x.b", T0 + 10));
        b.dev.lock();
        assert!(!b.pending().is_empty() || !outbox(&b.dev).is_empty());

        // A pushes a newer manifest; locked B fetches it and sends nothing
        // of the held vault.
        a.dev.save(&edited(y, "y.a", T0 + 10));
        a.settle();
        b.t.borrow_mut().batches.clear();
        b.round();
        assert_eq!(b.dev.store().vaults_needing_rebase().unwrap(), vec![v]);
        assert!(
            b.t.borrow()
                .batches
                .iter()
                .flatten()
                .all(|(k, _, _)| !matches!(k, RecordKind::Item | RecordKind::Manifest)),
            "{:?}",
            b.t.borrow().batches
        );

        // Unlocked, B rebases and both edits survive.
        b.dev.unlock(&sk);
        assert_eq!(b.settle().status, RoundStatus::Idle);
        a.settle();
        assert_eq!(users(&a.dev.items()), ["x.b", "y.a"]);
        assert_eq!(a.dev.items(), b.dev.items());
    }

    #[test]
    fn long_offline_device_with_several_local_writes_converges() {
        let (_fake, mut a, mut b, _sk, items) = two_sides(&["x", "y", "z", "w"]);
        let (x, y, z, w) = (&items[0], &items[1], &items[2], &items[3]);
        let v = x.vault_id;

        // B, offline, writes several times.
        b.dev.save(&edited(x, "x.b", T0 + 30));
        b.dev.delete(y.id);
        let n1 = login(v, "n1", T0 + 31);
        b.dev.save(&n1);
        b.dev.save(&edited(&n1, "n1.b2", T0 + 32));
        let n2 = login(v, "n2", T0 + 33);
        b.dev.save(&n2);
        b.dev.delete(n2.id);
        b.dev.delete(w.id);

        // Meanwhile A advances the server several times.
        a.dev.save(&edited(z, "z.a", T0 + 10));
        a.settle();
        a.dev.save(&login(v, "a1", T0 + 12));
        a.settle();
        a.dev.save(&edited(x, "x.a", T0 + 5));
        a.settle();
        a.dev.save(&edited(w, "w.a", T0 + 14));
        a.settle();

        b.settle();
        a.settle();
        assert_eq!(users(&a.dev.items()), ["a1", "n1.b2", "w.a", "x.b", "z.a"]);
        assert_eq!(a.dev.items(), b.dev.items());
        assert!(a.pending().is_empty());
        assert!(b.pending().is_empty());
    }
}
