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
fn server_replaying_old_manifest_is_rollback() {
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

    server.replay(seq2);
    pull(&server, &mut b);
    assert_eq!(integrity(b.try_items()), IntegrityError::ManifestRollback);
    // A device state saved and reloaded keeps refusing it.
    b.lock();
    b.unlock(&sk);
    assert_eq!(integrity(b.try_items()), IntegrityError::ManifestRollback);
}

#[test]
fn rebase_onto_a_manifest_older_than_the_ancestor_is_rollback_and_keeps_local_writes() {
    let mut server = Server::default();
    let (mut a, sk) = Device::create();
    let v = personal_vault_of(&mut a);
    let x = login(v, "x", T0);
    a.save(&x);
    sync(&mut server, &mut a).unwrap();
    let seq2 = server.get(RecordKind::Manifest, v).unwrap();
    a.save(&login(v, "y", T0));
    sync(&mut server, &mut a).unwrap();
    let seq3 = server.get(RecordKind::Manifest, v).unwrap();

    let mut b = Device::empty();
    pull(&server, &mut b);
    b.unlock(&sk);
    assert_eq!(b.items().len(), 2);
    b.save(&edited(&x, "x.b", T0 + 10));

    // The server goes back to seq 2: B's vault is held, and the rebase
    // refuses the old manifest without losing B's edit.
    server.replay(seq2);
    pull(&server, &mut b);
    assert_eq!(b.store().vaults_needing_rebase().unwrap(), vec![v]);
    assert_eq!(
        integrity(b.repo().rebase()),
        IntegrityError::ManifestRollback
    );
    assert_eq!(b.store().vaults_needing_rebase().unwrap(), vec![v]);
    assert_eq!(users(&b.items()), vec!["x.b", "y"]);
    b.lock();
    b.unlock(&sk);
    assert_eq!(users(&b.items()), vec!["x.b", "y"]);

    // The server serves seq 3 again: once B fetches it, the vault is no
    // longer held (the ancestor is current) and B's edit goes through.
    server.replay(seq3);
    pull(&server, &mut b);
    assert!(b.store().vaults_needing_rebase().unwrap().is_empty());
    sync(&mut server, &mut b).unwrap();
    sync(&mut server, &mut a).unwrap();
    assert_eq!(users(&a.items()), vec!["x.b", "y"]);
    assert_eq!(a.items(), b.items());
}

#[test]
fn server_withholding_item_is_detected() {
    let mut server = Server::default();
    let (mut a, mut b, _sk, items) = setup(&mut server, &[("x", T0)]);
    let x = &items[0];
    a.save(&edited(x, "x.a", T0 + 10));
    sync(&mut server, &mut a).unwrap();
    // The server keeps the new manifest but never serves the new record.
    let blob = server.item_blob(x.id, 2);
    server.withhold(RecordKind::Item, blob);
    pull(&server, &mut b);
    assert_eq!(
        integrity(b.try_items()),
        IntegrityError::ManifestMissingItem
    );
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
    let bad_seq2 = server.get(RecordKind::Manifest, bad.id).unwrap();
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

    // A advances the good vault; the server rolls the bad one back.
    let ag = a.vault_named(&good.meta.name);
    a.repo()
        .save_item(&ag, login(good.id, "good.a", T0 + 11))
        .unwrap();
    sync(&mut server, &mut a).unwrap();
    server.replay(bad_seq2);
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
