//! Two devices over one account, syncing through a fake CloudKit-like
//! server: atomic conditional batches, a change log read with a cursor, and
//! a few ways for the server to misbehave. No network.

mod common;

use common::*;
// ---------------------------------------------------------------- tests

#[test]
fn second_device_restores_from_server() {
    let mut server = Server::default();
    let (mut a, sk) = Device::create();
    let v = personal_vault_of(&mut a);
    let item = login(v, "camille.durand@exemple.fr", T0);
    a.save(&item);
    sync(&mut server, &mut a).unwrap();

    let mut b = Device::empty();
    pull(&server, &mut b);
    assert!(b.store().has_account().unwrap());
    b.unlock(&sk);
    assert_eq!(b.items(), vec![item]);
    assert!(b.store().pending_changes().unwrap().is_empty());
    // Nothing to push from B: a sync is a no-op that changes nothing.
    sync(&mut server, &mut b).unwrap();
    assert_eq!(b.items(), a.items());
}

#[test]
fn sequential_edits_flow_both_ways() {
    let mut server = Server::default();
    let (mut a, mut b, _sk, items) = setup(&mut server, &[("camille", T0)]);
    let x = &items[0];

    a.save(&edited(x, "camille.a", T0 + 10));
    sync(&mut server, &mut a).unwrap();
    sync(&mut server, &mut b).unwrap();
    assert_eq!(users(&b.items()), vec!["camille.a"]);

    b.save(&edited(x, "camille.b", T0 + 20));
    let y = login(x.vault_id, "dominique", T0 + 21);
    b.save(&y);
    sync(&mut server, &mut b).unwrap();
    sync(&mut server, &mut a).unwrap();
    assert_eq!(users(&a.items()), vec!["camille.b", "dominique"]);
    assert_eq!(a.items(), b.items());
    assert!(a.store().vaults_needing_rebase().unwrap().is_empty());
}

#[test]
fn concurrent_edits_of_different_items_both_survive() {
    let mut server = Server::default();
    let (mut a, mut b, _sk, items) = setup(&mut server, &[("x", T0), ("y", T0)]);
    let (x, y) = (&items[0], &items[1]);

    a.save(&edited(x, "x.a", T0 + 10));
    b.save(&edited(y, "y.b", T0 + 10));
    let new_b = login(x.vault_id, "new.b", T0 + 11);
    b.save(&new_b);
    sync(&mut server, &mut a).unwrap();
    // B's manifest conflicts: B pulls, rebases its two writes, pushes.
    sync(&mut server, &mut b).unwrap();
    sync(&mut server, &mut a).unwrap();

    assert_eq!(users(&a.items()), vec!["new.b", "x.a", "y.b"]);
    assert_eq!(a.items(), b.items());
}

#[test]
fn concurrent_edits_of_same_item_newest_wins() {
    // B edits after A, and pushes second.
    let mut server = Server::default();
    let (mut a, mut b, _sk, items) = setup(&mut server, &[("x", T0)]);
    let x = &items[0];
    a.save(&edited(x, "x.a", T0 + 10));
    b.save(&edited(x, "x.b", T0 + 20));
    sync(&mut server, &mut a).unwrap();
    sync(&mut server, &mut b).unwrap();
    sync(&mut server, &mut a).unwrap();
    assert_eq!(users(&a.items()), vec!["x.b"]);
    assert_eq!(a.items(), b.items());

    // B edits after A again, but pushes first: A's older edit is dropped.
    let x = a.items().remove(0);
    a.save(&edited(&x, "x.a2", T0 + 30));
    b.save(&edited(&x, "x.b2", T0 + 40));
    sync(&mut server, &mut b).unwrap();
    sync(&mut server, &mut a).unwrap();
    sync(&mut server, &mut b).unwrap();
    assert_eq!(users(&a.items()), vec!["x.b2"]);
    assert_eq!(a.items(), b.items());
}

#[test]
fn same_timestamp_edits_converge() {
    let mut server = Server::default();
    let (mut a, mut b, _sk, items) = setup(&mut server, &[("x", T0)]);
    let x = &items[0];
    a.save(&edited(x, "x.a", T0 + 10));
    b.save(&edited(x, "x.b", T0 + 10));
    sync(&mut server, &mut a).unwrap();
    sync(&mut server, &mut b).unwrap();
    sync(&mut server, &mut a).unwrap();
    // One of the two, the same on both devices.
    let winner = users(&a.items());
    assert!(winner == ["x.a"] || winner == ["x.b"], "{winner:?}");
    assert_eq!(a.items(), b.items());
}

#[test]
fn local_edit_of_remotely_unchanged_item_wins_despite_an_older_clock() {
    let mut server = Server::default();
    let (mut a, mut b, _sk, items) = setup(&mut server, &[("x", T0 + 100), ("y", T0)]);
    let (x, y) = (&items[0], &items[1]);
    a.save(&edited(y, "y.a", T0 + 10));
    // B's clock is behind: its edit is older than the stored version, but
    // nobody else touched X, so it is not a conflict and must survive.
    b.save(&edited(x, "x.b", T0 + 50));
    sync(&mut server, &mut a).unwrap();
    sync(&mut server, &mut b).unwrap();
    sync(&mut server, &mut a).unwrap();
    assert_eq!(users(&a.items()), vec!["x.b", "y.a"]);
    assert_eq!(a.items(), b.items());
}

#[test]
fn remote_edit_beats_older_local_delete() {
    let mut server = Server::default();
    let (mut a, mut b, _sk, items) = setup(&mut server, &[("x", T0), ("y", T0)]);
    let x = &items[0];
    a.delete(x.id);
    b.save(&edited(x, "x.b", T0 + 20));
    sync(&mut server, &mut b).unwrap();
    // A's deletion was of a version that is no longer the server's: dropped.
    sync(&mut server, &mut a).unwrap();
    sync(&mut server, &mut b).unwrap();
    assert_eq!(users(&a.items()), vec!["x.b", "y"]);
    assert_eq!(a.items(), b.items());
}

#[test]
fn local_delete_applies_when_remote_unchanged() {
    let mut server = Server::default();
    let (mut a, mut b, _sk, items) = setup(&mut server, &[("x", T0), ("y", T0)]);
    let (x, y) = (&items[0], &items[1]);
    a.delete(x.id);
    b.save(&edited(y, "y.b", T0 + 20));
    sync(&mut server, &mut b).unwrap();
    sync(&mut server, &mut a).unwrap();
    sync(&mut server, &mut b).unwrap();
    assert_eq!(users(&a.items()), vec!["y.b"]);
    assert_eq!(a.items(), b.items());
    // The deleted record is gone from the server too.
    let items_on_server = server
        .records
        .iter()
        .filter(|((k, _), e)| *k == RecordKind::Item && e.record.is_some())
        .count();
    assert_eq!(items_on_server, 1);
}

#[test]
fn held_vault_sends_nothing_until_rebased() {
    let mut server = Server::default();
    let (mut a, mut b, sk, items) = setup(&mut server, &[("x", T0), ("y", T0)]);
    let (x, y) = (&items[0], &items[1]);
    let v = x.vault_id;

    // B edits X (a new record, a tombstone for the old one, a manifest),
    // then locks before pushing.
    b.save(&edited(x, "x.b", T0 + 10));
    b.lock();
    assert!(!outbox(&b).is_empty());

    // A pushes a newer manifest; locked B fetches it.
    a.save(&edited(y, "y.a", T0 + 10));
    sync(&mut server, &mut a).unwrap();
    pull(&server, &mut b);
    assert_eq!(b.store().vaults_needing_rebase().unwrap(), vec![v]);
    // Neither the manifest nor any item (record or tombstone) goes out.
    assert_eq!(outbox(&b), vec![]);
    let before = server.clock;
    push(&mut server, &b).unwrap();
    assert_eq!(server.clock, before, "an empty batch writes nothing");

    // Unlocked, B rebases and both edits survive.
    b.unlock(&sk);
    assert_eq!(b.repo().rebase().unwrap(), vec![v]);
    assert!(b.store().vaults_needing_rebase().unwrap().is_empty());
    sync(&mut server, &mut b).unwrap();
    sync(&mut server, &mut a).unwrap();
    assert_eq!(users(&a.items()), vec!["x.b", "y.a"]);
    assert_eq!(a.items(), b.items());
}

#[test]
fn server_replaying_old_manifest_is_never_accepted() {
    let mut server = Server::default();
    let (mut a, sk) = Device::create();
    let v = personal_vault_of(&mut a);
    a.save(&login(v, "x", T0));
    sync(&mut server, &mut a).unwrap();
    let seq2 = server.get(RecordKind::Manifest, v).unwrap();
    assert_eq!(seq2.version, 2);
    a.save(&login(v, "y", T0));
    sync(&mut server, &mut a).unwrap();

    let mut b = Device::empty();
    pull(&server, &mut b);
    b.unlock(&sk);
    assert_eq!(b.items().len(), 2);
    assert_eq!(b.repo().device_state().last_seen[&v].seq, 3);

    // B keeps serving its own copy, the server is behind, and B's copy
    // goes up again (spec 3.1); seq 2 is never what B reads.
    server.replay(seq2);
    pull(&server, &mut b);
    assert_eq!(b.try_items().unwrap().len(), 2);
    assert!(is_behind(health(&mut b, v)));
    // A device state saved and reloaded keeps it.
    b.lock();
    b.unlock(&sk);
    assert_eq!(b.try_items().unwrap().len(), 2);
    sync(&mut server, &mut b).unwrap();
    assert_eq!(server.get(RecordKind::Manifest, v).unwrap().version, 3);
    // Served back: `Ok` after `STALE_CLEAR_ROUNDS` clean rounds, not one.
    pull(&server, &mut b);
    b.repo().note_sync_round(T0).unwrap();
    assert!(is_behind(health(&mut b, v)));
    settle(&mut server, &mut [&mut b], T0 + 60);
    assert_eq!(health(&mut b, v), VaultSyncHealth::Ok);
}

#[test]
fn local_write_over_a_server_gone_back_is_pushed_over_it() {
    let mut server = Server::default();
    let (mut a, sk) = Device::create();
    let v = personal_vault_of(&mut a);
    let x = login(v, "x", T0);
    a.save(&x);
    sync(&mut server, &mut a).unwrap();
    let seq2 = server.get(RecordKind::Manifest, v).unwrap();
    a.save(&login(v, "y", T0));
    sync(&mut server, &mut a).unwrap();

    let mut b = Device::empty();
    pull(&server, &mut b);
    b.unlock(&sk);
    assert_eq!(b.items().len(), 2);
    b.save(&edited(&x, "x.b", T0 + 10));

    // The server goes back to seq 2, older than B's ancestor: B's vault is
    // not held, its write (built on seq 3) goes over the old state.
    server.replay(seq2);
    pull(&server, &mut b);
    assert!(b.store().vaults_needing_rebase().unwrap().is_empty());
    assert_eq!(users(&b.items()), vec!["x.b", "y"]);
    sync(&mut server, &mut b).unwrap();
    sync(&mut server, &mut a).unwrap();
    assert_eq!(users(&a.items()), vec!["x.b", "y"]);
    assert_eq!(a.items(), b.items());
}

#[test]
fn server_withholding_item_alerts_after_threshold() {
    let mut server = Server::default();
    let (mut a, mut b, _sk, items) = setup(&mut server, &[("x", T0)]);
    let x = &items[0];
    let p = x.vault_id;
    a.save(&edited(x, "x.a", T0 + 10));
    sync(&mut server, &mut a).unwrap();
    // The server keeps the new manifest but never serves the new record.
    let blob = server.item_blob(x.id, 2);
    server.withhold(RecordKind::Item, blob);
    // B serves the copy it verified, never a half state, until the
    // threshold.
    for i in 0..STALE_ALERT_ROUNDS - 1 {
        round(&mut server, &mut b, T0 + 150 * i64::from(i)).unwrap();
        assert!(is_behind(health(&mut b, p)));
        assert_eq!(users(&b.items()), vec!["x"]);
    }
    round(&mut server, &mut b, T0 + STALE_ALERT_SECONDS).unwrap();
    assert_eq!(
        health(&mut b, p),
        VaultSyncHealth::Alert(IntegrityError::ManifestMissingItem)
    );
    assert_eq!(users(&b.items()), vec!["x"]);
}

#[test]
fn crash_between_push_and_mark_pushed_heals() {
    let mut server = Server::default();
    let (mut a, mut b, _sk, items) = setup(&mut server, &[("x", T0)]);
    let x = &items[0];
    a.save(&edited(x, "x.a", T0 + 10));
    // The server takes the batch, the device never hears back.
    send(&mut server, &a, outbox(&a), false).unwrap();
    assert!(!outbox(&a).is_empty());

    // Next round: the retry conflicts with A's own records, the pull brings
    // the same versions back, and nothing is left to send.
    sync(&mut server, &mut a).unwrap();
    assert_eq!(outbox(&a), vec![]);
    assert!(a.store().vaults_needing_rebase().unwrap().is_empty());
    assert_eq!(users(&a.items()), vec!["x.a"]);
    sync(&mut server, &mut b).unwrap();
    assert_eq!(a.items(), b.items());

    // And the chain goes on from there.
    a.save(&edited(x, "x.a2", T0 + 20));
    sync(&mut server, &mut a).unwrap();
    sync(&mut server, &mut b).unwrap();
    assert_eq!(users(&b.items()), vec!["x.a2"]);
}

#[test]
fn crash_after_pushing_a_new_vault_heals() {
    let mut server = Server::default();
    let (mut a, mut b, sk, _) = setup(&mut server, &[("x", T0)]);
    let w = a.repo().create_vault(meta("Projet Atlas")).unwrap();
    let item = login(w.id, "atlas", T0);
    a.repo().save_item(&w, item.clone()).unwrap();
    send(&mut server, &a, outbox(&a), false).unwrap();

    // The new vault's pending manifest has no ancestor: it was never in
    // `base`. The pull brings A's own push back, which the rebase adopts.
    sync(&mut server, &mut a).unwrap();
    assert_eq!(outbox(&a), vec![]);
    assert!(a.store().vaults_needing_rebase().unwrap().is_empty());
    let w = a.vault_named("Projet Atlas");
    assert_eq!(a.repo().items(&w).unwrap(), vec![item.clone()]);

    sync(&mut server, &mut b).unwrap();
    b.lock();
    b.unlock(&sk);
    let wb = b.vault_named("Projet Atlas");
    assert_eq!(b.repo().items(&wb).unwrap(), vec![item]);
}

#[test]
fn local_write_during_push_is_rebased() {
    let mut server = Server::default();
    let (mut a, mut b, _sk, items) = setup(&mut server, &[("x", T0), ("y", T0)]);
    let (x, y) = (&items[0], &items[1]);
    a.save(&edited(x, "x.a", T0 + 10));
    let in_flight = outbox(&a);
    // A writes again while the batch is on its way.
    a.save(&edited(y, "y.a", T0 + 11));
    send(&mut server, &a, in_flight, true).unwrap();

    sync(&mut server, &mut a).unwrap();
    assert_eq!(outbox(&a), vec![]);
    assert!(a.store().vaults_needing_rebase().unwrap().is_empty());
    sync(&mut server, &mut b).unwrap();
    assert_eq!(users(&b.items()), vec!["x.a", "y.a"]);
    assert_eq!(a.items(), b.items());
}

#[test]
fn move_against_a_remote_edit_keeps_both_copies() {
    let mut server = Server::default();
    let (mut a, mut b, _sk, items) = setup(&mut server, &[("x", T0)]);
    let x = &items[0];
    let w = b.repo().create_vault(meta("Projet Atlas")).unwrap();
    sync(&mut server, &mut b).unwrap();
    sync(&mut server, &mut a).unwrap();

    // B moves X out while A edits it: nothing is lost, X ends in both.
    let personal = b.vault_named("Personnel");
    let w = b.vault_named(&w.meta.name);
    b.repo().move_item(x.id, &personal, &w).unwrap();
    let pa = a.vault_named("Personnel");
    a.repo().save_item(&pa, edited(x, "x.a", T0 + 10)).unwrap();
    sync(&mut server, &mut a).unwrap();
    sync(&mut server, &mut b).unwrap();
    sync(&mut server, &mut a).unwrap();

    for dev in [&mut a, &mut b] {
        let p = dev.vault_named("Personnel");
        let w = dev.vault_named("Projet Atlas");
        assert_eq!(users(&dev.repo().items(&p).unwrap()), vec!["x.a"]);
        assert_eq!(users(&dev.repo().items(&w).unwrap()), vec!["x"]);
    }
}

#[test]
fn new_vault_with_unconfirmed_push_then_more_writes_converges() {
    let mut server = Server::default();
    let (mut a, mut b, sk, _) = setup(&mut server, &[("x", T0)]);
    let w = a.repo().create_vault(meta("Projet Atlas")).unwrap();
    let first = login(w.id, "atlas", T0);
    a.repo().save_item(&w, first.clone()).unwrap();
    send(&mut server, &a, outbox(&a), false).unwrap();

    // More writes before the next sync: the pending manifest is no longer
    // the one the server holds, and there is still no ancestor.
    let edit = edited(&first, "atlas.v2", T0 + 10);
    a.repo().save_item(&w, edit.clone()).unwrap();
    let second = login(w.id, "atlas.second", T0 + 11);
    a.repo().save_item(&w, second.clone()).unwrap();

    sync(&mut server, &mut a).unwrap();
    assert_eq!(outbox(&a), vec![]);
    assert!(a.store().vaults_needing_rebase().unwrap().is_empty());
    let w = a.vault_named("Projet Atlas");
    assert_eq!(
        users(&a.repo().items(&w).unwrap()),
        vec!["atlas.second", "atlas.v2"]
    );

    sync(&mut server, &mut b).unwrap();
    b.lock();
    b.unlock(&sk);
    let wb = b.vault_named("Projet Atlas");
    assert_eq!(b.repo().items(&wb).unwrap(), a.repo().items(&w).unwrap());
}

#[test]
fn long_offline_device_with_several_local_writes_converges() {
    let mut server = Server::default();
    let (mut a, mut b, _sk, items) =
        setup(&mut server, &[("x", T0), ("y", T0), ("z", T0), ("w", T0)]);
    let (x, y, z, w) = (&items[0], &items[1], &items[2], &items[3]);
    let v = x.vault_id;

    // B, offline, writes several times.
    b.save(&edited(x, "x.b", T0 + 30));
    b.delete(y.id);
    let n1 = login(v, "n1", T0 + 31);
    b.save(&n1);
    b.save(&edited(&n1, "n1.b2", T0 + 32));
    let n2 = login(v, "n2", T0 + 33);
    b.save(&n2);
    b.delete(n2.id);
    b.delete(w.id);

    // Meanwhile A advances the server several times.
    a.save(&edited(z, "z.a", T0 + 10));
    sync(&mut server, &mut a).unwrap();
    let a1 = login(v, "a1", T0 + 12);
    a.save(&a1);
    sync(&mut server, &mut a).unwrap();
    // Older than B's edit of X: B wins it.
    a.save(&edited(x, "x.a", T0 + 5));
    sync(&mut server, &mut a).unwrap();
    // A edits W, which B deleted: the edit wins.
    a.save(&edited(w, "w.a", T0 + 14));
    sync(&mut server, &mut a).unwrap();

    sync(&mut server, &mut b).unwrap();
    sync(&mut server, &mut a).unwrap();
    assert_eq!(users(&a.items()), vec!["a1", "n1.b2", "w.a", "x.b", "z.a"]);
    assert_eq!(a.items(), b.items());
    assert_eq!(outbox(&a), vec![]);
    assert_eq!(outbox(&b), vec![]);
}

#[test]
fn failing_vault_does_not_block_other_vaults() {
    let mut server = Server::default();
    let (mut a, sk) = Device::create();
    let atlas = a.repo().create_vault(meta("Projet Atlas")).unwrap();
    let personal = a.vault_named("Personnel");
    // The vault that fails is the one rebased first (lower id).
    let (bad, good) = if personal.id < atlas.id {
        (personal, atlas)
    } else {
        (atlas, personal)
    };
    let bx = login(bad.id, "bad.x", T0);
    let gx = login(good.id, "good.x", T0);
    a.repo().save_item(&bad, bx.clone()).unwrap();
    a.repo().save_item(&good, gx.clone()).unwrap();
    sync(&mut server, &mut a).unwrap();
    // C reads the bad vault at seq 2 and writes it twice offline: a
    // history that forks from what comes next.
    let mut c = Device::empty();
    pull(&server, &mut c);
    c.unlock(&sk);
    let cb = c.vault_named(&bad.meta.name);
    c.repo().save_item(&cb, login(bad.id, "c1", T0)).unwrap();
    c.repo().save_item(&cb, login(bad.id, "c2", T0)).unwrap();
    let forked: Vec<Record> = outbox(&c).iter().map(|(ch, _)| as_record(ch)).collect();
    for v in [&bad, &good] {
        a.repo().save_item(v, login(v.id, "second", T0)).unwrap();
    }
    sync(&mut server, &mut a).unwrap();

    let mut b = Device::empty();
    pull(&server, &mut b);
    b.unlock(&sk);
    let (bb, bg) = (
        b.vault_named(&bad.meta.name),
        b.vault_named(&good.meta.name),
    );
    b.repo().items(&bb).unwrap();
    b.repo().items(&bg).unwrap();
    b.repo()
        .save_item(&bb, edited(&bx, "bad.b", T0 + 10))
        .unwrap();
    b.repo()
        .save_item(&bg, edited(&gx, "good.b", T0 + 10))
        .unwrap();

    // A advances the good vault; the server serves C's fork of the bad one.
    let ag = a.vault_named(&good.meta.name);
    a.repo()
        .save_item(&ag, login(good.id, "good.a", T0 + 11))
        .unwrap();
    sync(&mut server, &mut a).unwrap();
    for r in forked {
        server.replay(r);
    }
    pull(&server, &mut b);
    let mut both = vec![bad.id, good.id];
    both.sort();
    assert_eq!(b.store().vaults_needing_rebase().unwrap(), both);

    // The first vault fails, the second is still rebased.
    assert_eq!(
        integrity(b.repo().rebase()),
        IntegrityError::ManifestRollback
    );
    assert_eq!(b.store().vaults_needing_rebase().unwrap(), vec![bad.id]);
    assert_eq!(
        users(&b.repo().items(&bb).unwrap()),
        vec!["bad.b", "second"]
    );
    // The good vault goes out; the bad one keeps its edit and waits.
    push(&mut server, &b).unwrap();
    sync(&mut server, &mut a).unwrap();
    let ag = a.vault_named(&good.meta.name);
    assert_eq!(
        users(&a.repo().items(&ag).unwrap()),
        vec!["good.a", "good.b", "second"]
    );
    b.lock();
    b.unlock(&sk);
    let bb = b.vault_named(&bad.meta.name);
    assert_eq!(
        users(&b.repo().items(&bb).unwrap()),
        vec!["bad.b", "second"]
    );
}

#[test]
fn forged_deletions_of_account_and_seen_vault_change_nothing_locally() {
    let mut server = Server::default();
    let (a, mut b, sk, _items) = setup(&mut server, &[("camille", T0)]);
    let before = b.items();
    let v = b.vault().id;
    b.lock();
    let account: Vec<Id> = a
        .store()
        .list(RecordKind::AccountParams)
        .unwrap()
        .into_iter()
        .map(|r| r.id)
        .collect();
    assert_eq!(account.len(), 1);
    for id in &account {
        server.forge_deletion(RecordKind::AccountParams, *id);
        server.forge_deletion(RecordKind::Keyset, *id);
    }
    for kind in [
        RecordKind::VaultKey,
        RecordKind::VaultMeta,
        RecordKind::Manifest,
    ] {
        server.forge_deletion(kind, v);
    }
    pull(&server, &mut b);
    assert_eq!(b.store().account_state().unwrap(), AccountState::Present);
    b.unlock(&sk);
    assert_eq!(b.items(), before);
}

#[test]
fn empty_zone_on_a_full_fetch_keeps_the_local_copy() {
    let mut server = Server::default();
    let (_a, mut b, sk, _items) = setup(&mut server, &[("camille", T0)]);
    let before = b.items();
    b.lock();
    // The token expired and the zone now answers with nothing at all.
    full_fetch(&Server::default(), &mut b);
    assert_eq!(b.store().account_state().unwrap(), AccountState::Present);
    b.unlock(&sk);
    assert_eq!(b.items(), before);
    assert!(b.store().pending_changes().unwrap().is_empty());
}

#[test]
fn full_fetch_hiding_a_seen_vault_keeps_it_readable() {
    let mut server = Server::default();
    let (_a, mut b, sk, _items) = setup(&mut server, &[("camille", T0)]);
    let before = b.items();
    let v = b.vault().id;
    b.lock();
    for kind in [
        RecordKind::VaultKey,
        RecordKind::VaultMeta,
        RecordKind::Manifest,
    ] {
        server.withhold(kind, v);
    }
    full_fetch(&server, &mut b);
    b.unlock(&sk);
    assert_eq!(b.items(), before);
}

#[test]
fn rebase_after_persisted_local_edits_keeps_vault_readable() {
    let mut server = Server::default();
    let (mut a, mut b, _sk, items) = setup(&mut server, &[("x", T0)]);
    let x = items[0].clone();

    // B edits three times, persisting its device state after each edit (as
    // the FFI session does), so a high seq is stored for abandoned manifests.
    for n in 1..=3 {
        b.save(&edited(&x, &format!("x.b{n}"), T0 + 10 + n));
        b.repo().persist_device_state().unwrap();
    }
    // A pushes another edit of the same item: B's push conflicts.
    a.save(&edited(&x, "x.a", T0 + 20));
    sync(&mut server, &mut a).unwrap();
    sync(&mut server, &mut b).unwrap();

    // The rebase renumbered the vault below the abandoned seq; it still loads.
    assert_eq!(b.try_items().unwrap().len(), 1);
    b.lock();
    assert_eq!(b.store().device_state().unwrap().last_seen.len(), 1);
}

// ------------------------------------------- server behind (spec 3.1, 3.2)

/// A and B both read Personnel at seq 3 (`x` then `y`); returns the seq 2
/// manifest record, for the server to go back to.
fn both_at_seq3(server: &mut Server) -> (Device, Device, SecretKey, Id, Record) {
    let (mut a, mut b, sk, items) = setup(server, &[("x", T0)]);
    let p = items[0].vault_id;
    let seq2 = server.get(RecordKind::Manifest, p).unwrap();
    b.save(&login(p, "y", T0 + 1));
    round(server, &mut b, T0).unwrap();
    round(server, &mut a, T0).unwrap();
    assert_eq!(users(&a.items()), vec!["x", "y"]);
    (a, b, sk, p, seq2)
}

/// Every device reads `expected`, sees the vault `Ok` and has nothing left
/// to send.
fn converged(server: &mut Server, devs: &mut [&mut Device], p: Id, expected: &[&str]) {
    settle(server, devs, T0 + 3600);
    for dev in devs.iter_mut() {
        let v = dev.repo().vaults().unwrap();
        let v = v.iter().find(|v| v.id == p).unwrap();
        assert_eq!(users(&dev.repo().items(v).unwrap()), expected);
        assert_eq!(health(dev, p), VaultSyncHealth::Ok);
        assert_eq!(outbox(dev), vec![]);
    }
}

#[test]
fn propagation_delay_no_alert() {
    let mut server = Server::default();
    let (mut a, mut b, _sk, p, seq2) = both_at_seq3(&mut server);

    // A lagging replica serves seq 2 again to A, which read seq 3.
    server.replay(seq2);
    round(&mut server, &mut a, T0 + 30).unwrap();
    assert!(is_behind(health(&mut a, p)));
    assert_eq!(users(&a.items()), vec!["x", "y"]);
    a.save(&login(p, "z", T0 + 31));

    // The next round sends A's copy again: both devices converge.
    round(&mut server, &mut a, T0 + 60).unwrap();
    round(&mut server, &mut b, T0 + 60).unwrap();
    converged(&mut server, &mut [&mut a, &mut b], p, &["x", "y", "z"]);
}

#[test]
fn persistent_rollback_alerts_after_threshold() {
    let mut server = Server::default();
    let (mut a, _b, sk, p, seq2) = both_at_seq3(&mut server);

    // The store takes A's copy back each round, then serves seq 2 again.
    let rewound_round = |server: &mut Server, a: &mut Device, now: i64| {
        push(server, a).unwrap();
        server.replay(seq2.clone());
        pull(server, a);
        a.repo().note_sync_round(now).unwrap();
    };
    for i in 1..=6u32 {
        rewound_round(&mut server, &mut a, T0 + 60 * i64::from(i - 1));
        // More rounds than the threshold, in less time: still only behind.
        assert_eq!(
            health(&mut a, p),
            VaultSyncHealth::ServerBehind {
                since: T0,
                rounds: i
            }
        );
        assert_eq!(users(&a.items()), vec!["x", "y"]);
    }
    rewound_round(&mut server, &mut a, T0 + STALE_ALERT_SECONDS);
    assert_eq!(
        health(&mut a, p),
        VaultSyncHealth::Alert(IntegrityError::ManifestRollback)
    );
    // The device never takes the old state: it still serves its own copy.
    assert_eq!(users(&a.items()), vec!["x", "y"]);
    a.lock();
    a.unlock(&sk);
    assert_eq!(
        health(&mut a, p),
        VaultSyncHealth::Alert(IntegrityError::ManifestRollback)
    );
    assert_eq!(users(&a.items()), vec!["x", "y"]);
}

#[test]
fn swallowed_copy_stays_behind_until_served() {
    let mut server = Server::default();
    let (mut a, mut b, _sk, p, seq2) = both_at_seq3(&mut server);
    server.replay(seq2);
    round(&mut server, &mut a, T0).unwrap();
    assert!(is_behind(health(&mut a, p)));

    // The store acknowledges A's copy but keeps serving seq 2 and never
    // logs the write: the acknowledgment alone does not settle the vault.
    let kept = server.clone();
    push(&mut server, &a).unwrap();
    server = kept;
    for i in 1..STALE_ALERT_ROUNDS {
        round(&mut server, &mut a, T0 + 100 * i64::from(i)).unwrap();
        assert!(is_behind(health(&mut a, p)), "round {i}");
    }
    assert_eq!(
        health(&mut a, p),
        VaultSyncHealth::ServerBehind {
            since: T0,
            rounds: STALE_ALERT_ROUNDS
        }
    );
    round(&mut server, &mut a, T0 + STALE_ALERT_SECONDS).unwrap();
    assert_eq!(
        health(&mut a, p),
        VaultSyncHealth::Alert(IntegrityError::ManifestRollback)
    );
    // Neither device ever reads the old state.
    round(&mut server, &mut b, T0 + STALE_ALERT_SECONDS).unwrap();
    assert_eq!(users(&a.items()), vec!["x", "y"]);
    assert_eq!(users(&b.items()), vec!["x", "y"]);
}

#[test]
fn alternating_store_still_alerts() {
    let mut server = Server::default();
    let (mut a, _b, _sk, p, seq2) = both_at_seq3(&mut server);
    // The store serves the old state one round and A's copy the next: a
    // single clean round never settles the vault, the count keeps running.
    for i in 0..10u32 {
        push(&mut server, &a).unwrap();
        if i % 2 == 0 {
            server.replay(seq2.clone());
        }
        pull(&server, &mut a);
        a.repo().note_sync_round(T0 + 120 * i64::from(i)).unwrap();
        assert_ne!(health(&mut a, p), VaultSyncHealth::Ok, "round {i}");
        assert_eq!(users(&a.items()), vec!["x", "y"]);
    }
    assert_eq!(
        health(&mut a, p),
        VaultSyncHealth::Alert(IntegrityError::ManifestRollback)
    );
}

/// A edits X twice and adds N: its batch is X's record two versions on,
/// N's record, the manifest, then X's old record deleted. Returns the item
/// records and the rest, the two halves of a split batch.
fn a_writes_split_batch(a: &mut Device, x: &Item) -> Vec<(Change, Option<u64>)> {
    a.save(&edited(x, "x.a1", T0 + 10));
    a.save(&edited(x, "x.a2", T0 + 11));
    a.save(&login(x.vault_id, "n", T0 + 12));
    let batch = outbox(a);
    let (records, rest): (Vec<_>, Vec<_>) = batch
        .into_iter()
        .partition(|(c, _)| c.kind == RecordKind::Item && c.data.is_some());
    assert_eq!(records.len(), 2);
    assert_eq!(rest.len(), 2);
    records
}

#[test]
fn partial_send_retry_no_alert() {
    let mut server = Server::default();
    let (mut a, mut b, _sk, items) = setup(&mut server, &[("x", T0), ("y", T0)]);
    let (x, y) = (&items[0], &items[1]);
    let p = x.vault_id;
    // The first request of A's batch goes through, the second fails: A
    // retries at its next round.
    let records = a_writes_split_batch(&mut a, x);
    send(&mut server, &a, records, true).unwrap();

    // B fetches in between: records its manifest does not list.
    round(&mut server, &mut b, T0 + 20).unwrap();
    assert!(is_behind(health(&mut b, p)));
    assert_eq!(users(&b.items()), vec!["x", "y"]);
    // B writes, and its push lands before A's retry.
    b.save(&edited(y, "y.b", T0 + 21));
    round(&mut server, &mut b, T0 + 30).unwrap();
    round(&mut server, &mut a, T0 + 30).unwrap();
    round(&mut server, &mut b, T0 + 60).unwrap();
    round(&mut server, &mut a, T0 + 60).unwrap();
    converged(&mut server, &mut [&mut a, &mut b], p, &["n", "x.a2", "y.b"]);
}

#[test]
fn split_batch_seen_midway_no_alert() {
    let mut server = Server::default();
    let (mut a, mut b, _sk, items) = setup(&mut server, &[("x", T0), ("y", T0)]);
    let x = &items[0];
    let p = x.vault_id;
    // A batch over CloudKit's limits goes in two: the records, then the
    // manifest and the deletions.
    let records = a_writes_split_batch(&mut a, x);
    send(&mut server, &a, records, true).unwrap();

    // B fetches between the two.
    round(&mut server, &mut b, T0 + 20).unwrap();
    assert!(is_behind(health(&mut b, p)));
    assert_eq!(users(&b.items()), vec!["x", "y"]);

    // The second half lands; the next round converges.
    round(&mut server, &mut a, T0 + 30).unwrap();
    round(&mut server, &mut b, T0 + 30).unwrap();
    converged(&mut server, &mut [&mut a, &mut b], p, &["n", "x.a2", "y"]);
}

#[test]
fn partial_fetch_no_alert() {
    let mut server = Server::default();
    let (mut a, mut b, _sk, items) = setup(&mut server, &[("x", T0), ("y", T0)]);
    let (x, y) = (&items[0], &items[1]);
    let p = x.vault_id;
    b.save(&edited(y, "y.b", T0 + 10));
    b.save(&login(p, "n", T0 + 11));
    round(&mut server, &mut b, T0 + 10).unwrap();

    // A's fetch stops after its first page (`moreComing`, no token): the
    // manifest and Y's deletion, not the new records. The round ends there.
    let (changes, _) = server.changes_since(a.cursor);
    let mut store = a.store();
    for c in changes
        .into_iter()
        .filter(|c| c.kind != RecordKind::Item || c.data.is_none())
    {
        store.stage_remote(c).unwrap();
    }
    store.commit_remote().unwrap();
    a.repo().note_sync_round(T0 + 20).unwrap();
    assert!(is_behind(health(&mut a, p)));
    assert_eq!(users(&a.items()), vec!["x", "y"]);
    a.save(&edited(x, "x.a", T0 + 21));

    // The next round fetches the rest and merges A's write.
    round(&mut server, &mut a, T0 + 30).unwrap();
    round(&mut server, &mut a, T0 + 60).unwrap();
    round(&mut server, &mut b, T0 + 60).unwrap();
    converged(&mut server, &mut [&mut a, &mut b], p, &["n", "x.a", "y.b"]);
}

#[test]
fn expired_token_full_fetch_no_alert() {
    let mut server = Server::default();
    let (mut a, mut b, _sk, items) = setup(&mut server, &[("x", T0)]);
    let p = items[0].vault_id;
    let seq2 = server.get(RecordKind::Manifest, p).unwrap();
    let n = login(p, "n", T0 + 1);
    b.save(&n);
    round(&mut server, &mut b, T0).unwrap();
    round(&mut server, &mut a, T0).unwrap();
    assert_eq!(users(&a.items()), vec!["n", "x"]);

    // A's token expired; its fetch from scratch hits the server while it
    // still serves seq 2 and lacks N's record.
    server.replay(seq2);
    let blob = server.item_blob(n.id, 1);
    server.withhold(RecordKind::Item, blob);
    full_fetch(&server, &mut a);
    a.repo().note_sync_round(T0 + 30).unwrap();
    assert!(is_behind(health(&mut a, p)));
    assert_eq!(users(&a.items()), vec!["n", "x"]);
    a.save(&login(p, "z", T0 + 31));

    round(&mut server, &mut a, T0 + 60).unwrap();
    round(&mut server, &mut b, T0 + 60).unwrap();
    converged(&mut server, &mut [&mut a, &mut b], p, &["n", "x", "z"]);
}

#[test]
fn zone_deleted_recreated_no_alert() {
    let mut server = Server::default();
    let (mut a, sk) = Device::create();
    let p = personal_vault_of(&mut a);
    a.save(&login(p, "x", T0));
    round(&mut server, &mut a, T0).unwrap();
    // C reads seq 2, then stays offline.
    let mut c = Device::empty();
    pull(&server, &mut c);
    c.unlock(&sk);
    assert_eq!(users(&c.items()), vec!["x"]);
    c.lock();
    a.save(&login(p, "y", T0 + 1));
    round(&mut server, &mut a, T0).unwrap();
    let mut b = Device::empty();
    pull(&server, &mut b);
    b.unlock(&sk);
    assert_eq!(users(&b.items()), vec!["x", "y"]);

    // The user deletes the zone; it comes back empty. C syncs first and
    // puts its old copy (seq 2) back.
    let mut server = Server::default();
    zone_reset(&server, &mut c);
    push(&mut server, &c).unwrap();

    // A resets onto C's copy: it keeps its own and sends it again.
    zone_reset(&server, &mut a);
    a.repo().note_sync_round(T0 + 30).unwrap();
    assert!(is_behind(health(&mut a, p)));
    assert_eq!(users(&a.items()), vec!["x", "y"]);
    a.save(&login(p, "z", T0 + 31));
    round(&mut server, &mut a, T0 + 60).unwrap();

    zone_reset(&server, &mut b);
    round(&mut server, &mut b, T0 + 60).unwrap();
    c.unlock(&sk);
    round(&mut server, &mut c, T0 + 60).unwrap();
    converged(
        &mut server,
        &mut [&mut a, &mut b, &mut c],
        p,
        &["x", "y", "z"],
    );
}

/// Device C reads Personnel at seq 2, then writes twice offline: the
/// records of its own seq 3 and 4, a history that forks from the server's.
fn offline_fork(server: &Server, sk: &SecretKey, p: Id) -> Vec<Record> {
    let mut c = Device::empty();
    pull(server, &mut c);
    c.unlock(sk);
    c.save(&login(p, "c1", T0 + 1));
    c.save(&login(p, "c2", T0 + 2));
    outbox(&c).iter().map(|(ch, _)| as_record(ch)).collect()
}

#[test]
fn unresolvable_fork_alerts() {
    let mut server = Server::default();
    let (mut a, sk) = Device::create();
    let p = personal_vault_of(&mut a);
    a.save(&login(p, "x", T0));
    round(&mut server, &mut a, T0).unwrap();
    let forked = offline_fork(&server, &sk, p);
    // A moves on to its seq 3; B reads it, then writes offline.
    a.save(&login(p, "y", T0 + 3));
    round(&mut server, &mut a, T0).unwrap();
    let mut b = Device::empty();
    pull(&server, &mut b);
    b.unlock(&sk);
    assert_eq!(users(&b.items()), vec!["x", "y"]);
    b.save(&login(p, "b", T0 + 4));

    // The store serves C's history instead: a seq 4 built on another seq 3.
    for r in forked {
        server.replay(r);
    }
    // B's write cannot be merged onto it: an alert at once, no threshold.
    assert_eq!(
        round(&mut server, &mut b, T0 + 30),
        Err(Error::Integrity(IntegrityError::ManifestRollback))
    );
    assert_eq!(
        health(&mut b, p),
        VaultSyncHealth::Alert(IntegrityError::ManifestRollback)
    );
    // B still reads its own copy, to export it.
    assert_eq!(users(&b.items()), vec!["b", "x", "y"]);

    // A, without a local write, sees the fork too, reads its copy and
    // refuses to write over the fork.
    round(&mut server, &mut a, T0 + 30).unwrap();
    assert_eq!(
        health(&mut a, p),
        VaultSyncHealth::Alert(IntegrityError::ManifestRollback)
    );
    assert_eq!(users(&a.items()), vec!["x", "y"]);
    let v = a.vault();
    assert_eq!(
        a.repo().save_item(&v, login(p, "w", T0 + 5)),
        Err(Error::Integrity(IntegrityError::ManifestRollback))
    );
}

#[test]
fn unreadable_health_never_blocks_reads_or_export() {
    let mut server = Server::default();
    let (mut a, _b, _sk, p, seq2) = both_at_seq3(&mut server);
    // The server goes back, and the health map on disk is damaged.
    server.replay(seq2);
    pull(&server, &mut a);
    a.store().set_meta("sync_health", &[1, 0xff]).unwrap();

    // Reads go on (the copy this device verified), and so does the export.
    assert_eq!(users(&a.items()), vec!["x", "y"]);
    let repo = a.repo();
    let mut vaults = Vec::new();
    for v in repo.vaults().unwrap() {
        let items = repo.items(&v).unwrap();
        vaults.push(onepass_core::archive::ArchivedVault {
            id: v.id,
            meta: v.meta,
            items,
        });
    }
    let archive =
        onepass_core::archive::backup(repo.account(), vaults, Some(("export pass phrase", kdf())))
            .unwrap();
    assert!(!archive.is_empty());

    // The health fails closed: the app shows the safe exits.
    assert!(matches!(a.repo().sync_health(), Err(Error::Store(_))));
    assert!(matches!(
        a.repo().note_sync_round(T0 + 60),
        Err(Error::Store(_))
    ));

    // The exit that discards nothing: forget the health, recount.
    a.repo().reset_sync_health().unwrap();
    assert_eq!(health(&mut a, p), VaultSyncHealth::Ok);
    round(&mut server, &mut a, T0 + 120).unwrap();
    assert!(a.repo().sync_health().is_ok());
    assert_eq!(users(&a.items()), vec!["x", "y"]);
}
