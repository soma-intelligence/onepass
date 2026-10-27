//! Signed restore epochs over the two-device harness: a restore from an old
//! backup (a vault recreated under a new id, a vault written again from an
//! old copy) is accepted by the other devices without an alert, while a
//! store that replays the old state (never read, the device keeps its
//! copy), hides the epoch, serves an older one or forges one is refused.
//! The safe exits after an alert ("keep this device", "take the server's
//! version") go through an epoch too.

mod common;

use common::*;
use onepass_core::epoch::{EpochReason, SignedRestoreEpoch};
use onepass_core::repo::DeviceState;

fn account_id(dev: &mut Device) -> Id {
    dev.repo().account().params.account_id
}

/// Read every vault, as a session does.
fn read_all(dev: &mut Device) -> Result<BTreeMap<String, Vec<String>>> {
    let mut out = BTreeMap::new();
    for v in dev.repo().vaults()? {
        let items = dev.repo().items(&v)?;
        out.insert(v.meta.name.clone(), users(&items));
    }
    Ok(out)
}

/// The world after a restore from an old backup.
struct Restored {
    sk: SecretKey,
    /// The new zone, with the restored account and the epoch.
    server: Server,
    /// The zone as it was just before it was lost.
    old: Server,
    /// A device that read everything before the loss, locked.
    b: Device,
    /// The device that restored, unlocked.
    r: Device,
    personal: Id,
    /// The vault the restore did not know, and the one it recreated.
    atlas: Id,
    atlas_again: Id,
}

/// A writes, R reads the account early then stays offline (its copy is the
/// old backup), A goes on (Personnel moves past R's copy, Projet Atlas is
/// created), B reads everything. The zone is then lost: R pushes its old
/// copy into a new zone, recreates Projet Atlas under a new id, writes an
/// item of the backup into Personnel and issues a `Restore` epoch.
fn restored() -> Restored {
    let mut server = Server::default();
    let (mut a, sk) = Device::create();
    let personal = personal_vault_of(&mut a);
    a.save(&login(personal, "x", T0));
    sync(&mut server, &mut a).unwrap();

    let mut r = Device::empty();
    pull(&server, &mut r);
    r.unlock(&sk);
    assert_eq!(users(&r.items()), vec!["x"]);
    r.lock();

    let atlas = a.repo().create_vault(meta("Projet Atlas")).unwrap();
    a.repo()
        .save_item(&atlas, login(atlas.id, "atlas", T0))
        .unwrap();
    for (i, u) in ["y", "z", "t", "u", "v"].into_iter().enumerate() {
        a.save(&login(personal, u, T0 + i as i64));
    }
    sync(&mut server, &mut a).unwrap();

    let mut b = Device::empty();
    pull(&server, &mut b);
    b.unlock(&sk);
    read_all(&mut b).unwrap();
    assert_eq!(b.repo().device_state().last_seen[&personal].seq, 7);
    assert!(b.repo().device_state().last_seen.contains_key(&atlas.id));
    b.lock();

    // The zone is lost.
    let old = std::mem::take(&mut server);
    r.unlock(&sk);
    zone_reset(&server, &mut r);
    let atlas_again = r.repo().create_vault(meta("Projet Atlas")).unwrap();
    r.repo()
        .save_item(&atlas_again, login(atlas_again.id, "atlas", T0))
        .unwrap();
    let p = r.vault_named("Personnel");
    r.repo()
        .save_item(&p, login(personal, "restored", T0 + 50))
        .unwrap();
    // R's Personnel restarts from its old copy: seq 3, behind B's 7.
    assert_eq!(r.repo().device_state().last_seen[&personal].seq, 3);
    let epoch = r.repo().issue_restore_epoch(EpochReason::Restore).unwrap();
    assert_eq!(epoch.epoch, 1);
    assert_eq!(epoch.reason, EpochReason::Restore);
    assert_eq!(
        epoch.heads.keys().copied().collect::<Vec<_>>(),
        sorted(vec![personal, atlas_again.id])
    );
    assert_eq!(r.repo().restore_epoch(), Some(1));
    sync(&mut server, &mut r).unwrap();

    Restored {
        sk,
        server,
        old,
        b,
        r,
        personal,
        atlas: atlas.id,
        atlas_again: atlas_again.id,
    }
}

fn sorted(mut ids: Vec<Id>) -> Vec<Id> {
    ids.sort();
    ids
}

/// B, whose change token died with the zone, fetches the new zone from
/// scratch and reads it.
fn b_reads_new_zone(w: &mut Restored) -> Result<BTreeMap<String, Vec<String>>> {
    full_fetch(&w.server, &mut w.b);
    w.b.unlock(&w.sk);
    let p = w.b.vault_named("Personnel");
    let items = w.b.repo().items(&p)?;
    let mut out = BTreeMap::new();
    out.insert("Personnel".to_owned(), users(&items));
    let again =
        w.b.repo()
            .vaults()?
            .into_iter()
            .find(|v| v.id == w.atlas_again)
            .expect("recreated vault listed");
    out.insert("Projet Atlas".to_owned(), users(&w.b.repo().items(&again)?));
    Ok(out)
}

#[test]
fn restore_old_backup_no_false_alert() {
    let mut w = restored();
    let seen = b_reads_new_zone(&mut w).unwrap();
    assert_eq!(seen["Personnel"], vec!["restored", "x"]);
    assert_eq!(seen["Projet Atlas"], vec!["atlas"]);
    assert_eq!(w.b.repo().restore_epoch(), Some(1));
    // The epoch heads replaced what B had seen: the vault the restore did
    // not know is forgotten.
    let state = w.b.repo().device_state().clone();
    assert!(!state.last_seen.contains_key(&w.atlas));
    assert_eq!(state.epoch, 1);

    // Life goes on: B writes, R reads it.
    let p = w.b.vault_named("Personnel");
    w.b.repo()
        .save_item(&p, login(w.personal, "after", T0 + 60))
        .unwrap();
    sync(&mut w.server, &mut w.b).unwrap();
    sync(&mut w.server, &mut w.r).unwrap();
    let p = w.r.vault_named("Personnel");
    assert_eq!(
        users(&w.r.repo().items(&p).unwrap()),
        vec!["after", "restored", "x"]
    );
    // Saved and reloaded, B still reads it.
    w.b.lock();
    w.b.unlock(&w.sk);
    assert_eq!(w.b.repo().restore_epoch(), Some(1));
    let p = w.b.vault_named("Personnel");
    assert_eq!(w.b.repo().items(&p).unwrap().len(), 3);
}

#[test]
fn recreated_vault_no_vault_missing() {
    let w = restored();
    // B's local copy is gone too (reinstalled app), its device state kept:
    // the old Projet Atlas is nowhere, the recreated one has a new id.
    let state = w.b.store().device_state().unwrap();
    assert!(state.last_seen.contains_key(&w.atlas));
    let mut b2 = Device::empty();
    pull(&w.server, &mut b2);
    b2.store().set_device_state(&state).unwrap();
    b2.unlock(&w.sk);
    let vaults = b2.repo().vaults().unwrap();
    assert_eq!(
        vaults.iter().map(|v| v.id).collect::<Vec<_>>(),
        sorted(vec![w.personal, w.atlas_again])
    );
    let seen = read_all(&mut b2).unwrap();
    assert_eq!(seen["Personnel"], vec!["restored", "x"]);
    assert_eq!(seen["Projet Atlas"], vec!["atlas"]);
    assert_eq!(b2.repo().restore_epoch(), Some(1));
}

#[test]
fn replayed_old_state_after_epoch_refused() {
    let mut w = restored();
    b_reads_new_zone(&mut w).unwrap();
    // The store serves the abandoned history again: Personnel at seq 7,
    // with its records, more than one step past R's copy before the epoch
    // (a gap `verify_manifest` alone cannot chain).
    let old_manifest = w.old.get(RecordKind::Manifest, w.personal).unwrap();
    assert_eq!(old_manifest.version, 7);
    for ((kind, _), e) in w.old.records.clone() {
        if kind == RecordKind::Item
            && let Some(rec) = e.record
        {
            w.server.replay(rec);
        }
    }
    w.server.replay(old_manifest);
    pull(&w.server, &mut w.b);
    // B never reads the abandoned history: it keeps the epoch's state and
    // reports the server behind (spec 3.1).
    let p = w.b.vault_named("Personnel");
    assert_eq!(users(&w.b.repo().items(&p).unwrap()), vec!["restored", "x"]);
    assert!(is_behind(health(&mut w.b, w.personal)));
    w.b.lock();
    w.b.unlock(&w.sk);
    let p = w.b.vault_named("Personnel");
    assert_eq!(users(&w.b.repo().items(&p).unwrap()), vec!["restored", "x"]);
}

#[test]
fn hidden_epoch_refused() {
    let mut w = restored();
    b_reads_new_zone(&mut w).unwrap();
    let id = account_id(&mut w.b);
    let p = w.b.vault_named("Personnel");
    w.b.lock();

    // A forged deletion of the epoch changes nothing locally.
    w.server.forge_deletion(RecordKind::RestoreEpoch, id);
    pull(&w.server, &mut w.b);
    assert!(
        w.b.store()
            .ignored_deletions()
            .unwrap()
            .iter()
            .any(|d| d.kind == RecordKind::RestoreEpoch && d.id == id)
    );
    w.b.unlock(&w.sk);
    assert_eq!(
        read_all(&mut w.b).unwrap()["Personnel"],
        vec!["restored", "x"]
    );
    w.b.lock();

    // A fresh copy of a store that hides the epoch, under B's device state.
    let state = w.b.store().device_state().unwrap();
    assert_eq!(state.epoch, 1);
    let mut b2 = Device::empty();
    pull(&w.server, &mut b2);
    assert!(
        b2.store()
            .get(RecordKind::RestoreEpoch, id)
            .unwrap()
            .is_none()
    );
    b2.store().set_device_state(&state).unwrap();
    b2.unlock(&w.sk);
    assert_eq!(integrity(b2.repo().vaults()), IntegrityError::EpochRollback);
    assert_eq!(
        integrity(b2.repo().items(&p)),
        IntegrityError::EpochRollback
    );
}

#[test]
fn older_epoch_replayed_refused() {
    let mut server = Server::default();
    let (mut a, mut b, sk, _) = setup(&mut server, &[("x", T0)]);
    let id = account_id(&mut a);
    a.repo().issue_restore_epoch(EpochReason::Restore).unwrap();
    sync(&mut server, &mut a).unwrap();
    let first = server.get(RecordKind::RestoreEpoch, id).unwrap();
    assert_eq!(first.version, 1);
    sync(&mut server, &mut b).unwrap();
    b.items();
    assert_eq!(b.repo().restore_epoch(), Some(1));

    let second = a
        .repo()
        .issue_restore_epoch(EpochReason::TakeServer)
        .unwrap();
    assert_eq!(second.epoch, 2);
    sync(&mut server, &mut a).unwrap();
    sync(&mut server, &mut b).unwrap();
    b.items();
    assert_eq!(b.repo().restore_epoch(), Some(2));

    server.replay(first);
    pull(&server, &mut b);
    assert_eq!(integrity(read_all(&mut b)), IntegrityError::EpochRollback);
    assert_eq!(b.repo().restore_epoch(), Some(2));
    b.lock();
    b.unlock(&sk);
    assert_eq!(integrity(read_all(&mut b)), IntegrityError::EpochRollback);
}

#[test]
fn forged_epoch_signature_refused() {
    let mut server = Server::default();
    let (mut a, mut b, _sk, _) = setup(&mut server, &[("x", T0)]);
    let id = account_id(&mut a);
    a.repo().issue_restore_epoch(EpochReason::Restore).unwrap();
    sync(&mut server, &mut a).unwrap();
    let genuine = server.get(RecordKind::RestoreEpoch, id).unwrap();

    // The store bumps the epoch number of a genuine record.
    let mut forged = SignedRestoreEpoch::decode(&genuine.data).unwrap();
    forged.epoch.epoch = 2;
    server.replay(Record {
        version: 2,
        data: forged.encode(),
        ..genuine.clone()
    });
    pull(&server, &mut b);
    assert_eq!(integrity(read_all(&mut b)), IntegrityError::Signature);
    assert_eq!(b.repo().restore_epoch(), None);

    // A genuine epoch of another account, served under this one.
    let mut other_server = Server::default();
    let (mut other, _) = Device::create();
    other
        .repo()
        .issue_restore_epoch(EpochReason::Restore)
        .unwrap();
    sync(&mut other_server, &mut other).unwrap();
    let other_id = account_id(&mut other);
    let theirs = other_server
        .get(RecordKind::RestoreEpoch, other_id)
        .unwrap();
    server.replay(Record { id, ..theirs });
    pull(&server, &mut b);
    assert_eq!(integrity(read_all(&mut b)), IntegrityError::EpochRollback);

    // Re-signed with another account's key, claiming this account.
    let mut claimed = SignedRestoreEpoch::decode(&genuine.data).unwrap();
    claimed.epoch.epoch = 3;
    let resigned =
        SignedRestoreEpoch::sign(claimed.epoch, &other.repo().account().keyset().signing).unwrap();
    server.replay(Record {
        version: 3,
        data: resigned.encode(),
        ..genuine.clone()
    });
    pull(&server, &mut b);
    assert_eq!(integrity(read_all(&mut b)), IntegrityError::Signature);

    // Trailing bytes after a genuine record: refused, not ignored.
    let mut padded = genuine.data.clone();
    padded.push(0);
    server.replay(Record {
        data: padded,
        ..genuine.clone()
    });
    pull(&server, &mut b);
    assert!(read_all(&mut b).is_err());
    assert_eq!(b.repo().restore_epoch(), None);

    // The genuine one is still accepted.
    server.replay(genuine);
    pull(&server, &mut b);
    b.items();
    assert_eq!(b.repo().restore_epoch(), Some(1));
}

#[test]
fn concurrent_epochs_one_wins() {
    let mut server = Server::default();
    let (mut a, mut b, _sk, _) = setup(&mut server, &[("x", T0)]);
    a.repo().issue_restore_epoch(EpochReason::Restore).unwrap();
    b.repo().issue_restore_epoch(EpochReason::Restore).unwrap();
    sync(&mut server, &mut a).unwrap();
    // B's epoch loses the race: its sync reports the conflict and drops it.
    assert_eq!(sync(&mut server, &mut b), Err(Error::Conflict));
    sync(&mut server, &mut b).unwrap();
    assert_eq!(outbox(&b), vec![]);
    assert_eq!(b.items(), a.items());
    let id = account_id(&mut a);
    let stored = server.get(RecordKind::RestoreEpoch, id).unwrap();
    assert_eq!(stored.version, 1);

    // After the re-sync, B's epoch goes through as the next one.
    let again = b.repo().issue_restore_epoch(EpochReason::Restore).unwrap();
    assert_eq!(again.epoch, 2);
    sync(&mut server, &mut b).unwrap();
    sync(&mut server, &mut a).unwrap();
    assert_eq!(a.items(), b.items());
    assert_eq!(a.repo().restore_epoch(), Some(2));
    assert_eq!(server.get(RecordKind::RestoreEpoch, id).unwrap().version, 2);
}

#[test]
fn offline_writer_rebases_after_epoch() {
    let mut server = Server::default();
    let (mut a, mut b, _sk, items) = setup(&mut server, &[("x", T0), ("y", T0)]);
    let (x, y) = (&items[0], &items[1]);
    // B writes offline while A restores.
    b.save(&edited(x, "x.b", T0 + 10));
    b.save(&login(x.vault_id, "new.b", T0 + 11));
    a.save(&edited(y, "y.a", T0 + 10));
    a.repo().issue_restore_epoch(EpochReason::Restore).unwrap();
    sync(&mut server, &mut a).unwrap();

    // B's manifest no longer chains: it is rebased onto the epoch heads.
    sync(&mut server, &mut b).unwrap();
    assert_eq!(b.repo().restore_epoch(), Some(1));
    sync(&mut server, &mut a).unwrap();
    assert_eq!(users(&a.items()), vec!["new.b", "x.b", "y.a"]);
    assert_eq!(a.items(), b.items());
    assert_eq!(outbox(&a), vec![]);
    assert_eq!(outbox(&b), vec![]);
}

#[test]
fn fresh_device_trusts_stored_epoch() {
    let mut server = Server::default();
    let (mut a, _b, sk, _) = setup(&mut server, &[("x", T0)]);
    let v = personal_vault_of(&mut a);
    let before = server.get(RecordKind::Manifest, v).unwrap();
    let epoch = a.repo().issue_restore_epoch(EpochReason::Restore).unwrap();
    sync(&mut server, &mut a).unwrap();

    // A new device has no history: it takes the stored epoch and its heads.
    let mut c = Device::empty();
    pull(&server, &mut c);
    c.unlock(&sk);
    assert_eq!(c.repo().restore_epoch(), None);
    assert_eq!(c.items(), a.items());
    assert_eq!(c.repo().restore_epoch(), Some(1));
    let state: DeviceState = c.repo().device_state().clone();
    assert_eq!(state.epoch, 1);
    assert_eq!(state.last_seen[&v], epoch.heads[&v]);

    // From then on it never reads the history before the epoch.
    server.replay(before);
    pull(&server, &mut c);
    assert_eq!(c.try_items().unwrap(), a.items());
    assert!(is_behind(health(&mut c, v)));
}

#[test]
fn issuer_behind_on_a_vault_reissues_without_blocking() {
    let mut server = Server::default();
    let (mut a, mut b, _sk, items) = setup(&mut server, &[("x", T0)]);
    let id = account_id(&mut a);
    // B moves Personnel on; A has not pulled it when it issues.
    b.save(&edited(&items[0], "x.b", T0 + 10));
    sync(&mut server, &mut b).unwrap();
    a.repo().issue_restore_epoch(EpochReason::Restore).unwrap();

    // A's head for Personnel cannot reach the server: the epoch is dropped
    // before it ships, and A is told to issue it again.
    assert_eq!(sync(&mut server, &mut a), Err(Error::Conflict));
    assert!(server.get(RecordKind::RestoreEpoch, id).is_none());
    assert_eq!(a.repo().restore_epoch(), None);
    sync(&mut server, &mut a).unwrap();
    assert_eq!(users(&a.items()), vec!["x.b"]);

    // B never saw anything wrong.
    sync(&mut server, &mut b).unwrap();
    assert_eq!(read_all(&mut b).unwrap()["Personnel"], vec!["x.b"]);

    // Re-issued after convergence, the epoch goes through.
    assert_eq!(
        a.repo()
            .issue_restore_epoch(EpochReason::Restore)
            .unwrap()
            .epoch,
        1
    );
    sync(&mut server, &mut a).unwrap();
    sync(&mut server, &mut b).unwrap();
    for dev in [&mut a, &mut b] {
        assert_eq!(read_all(dev).unwrap()["Personnel"], vec!["x.b"]);
        assert_eq!(dev.repo().restore_epoch(), Some(1));
    }
    assert_eq!(outbox(&a), vec![]);
    assert_eq!(outbox(&b), vec![]);
}

#[test]
fn concurrent_epochs_loser_adopts_winner_heads() {
    let mut server = Server::default();
    let (mut a, mut b, sk, _) = setup(&mut server, &[("x", T0)]);
    let id = account_id(&mut a);
    // A vault B has never read: its history reaches B only through the
    // winner's heads.
    let wa = a.repo().create_vault(meta("A seul")).unwrap();
    a.repo().save_item(&wa, login(wa.id, "a", T0)).unwrap();
    sync(&mut server, &mut a).unwrap();
    let wa_seq2 = server.get(RecordKind::Manifest, wa.id).unwrap();
    assert_eq!(wa_seq2.version, 2);
    // A vault only B knows, created offline.
    let wb = b.repo().create_vault(meta("B seul")).unwrap();

    a.repo().issue_restore_epoch(EpochReason::Restore).unwrap();
    b.repo()
        .issue_restore_epoch(EpochReason::KeepThisDevice)
        .unwrap();
    let losing = b
        .store()
        .get(RecordKind::RestoreEpoch, id)
        .unwrap()
        .unwrap();
    sync(&mut server, &mut a).unwrap();
    assert_eq!(sync(&mut server, &mut b), Err(Error::Conflict));

    // B took the winner's epoch and heads: its own vault is forgotten, the
    // winner's vault is known.
    let state = b.repo().device_state().clone();
    assert_eq!(state.epoch, 1);
    assert!(!state.last_seen.contains_key(&wb.id));
    assert!(state.last_seen.contains_key(&wa.id));
    sync(&mut server, &mut b).unwrap();
    sync(&mut server, &mut a).unwrap();
    let names = |m: BTreeMap<String, Vec<String>>| m.into_keys().collect::<Vec<_>>();
    assert_eq!(
        names(read_all(&mut b).unwrap()),
        vec!["A seul", "B seul", "Personnel"]
    );
    assert_eq!(read_all(&mut a).unwrap(), read_all(&mut b).unwrap());

    // The winner's history is checked on B, though B never read that vault
    // before the epoch: its seq 2 is behind the head, never read.
    server.replay(wa_seq2);
    pull(&server, &mut b);
    assert_eq!(users(&b.repo().items(&wa).unwrap()), vec!["a"]);
    assert!(is_behind(health(&mut b, wa.id)));

    // A second, different epoch with the accepted number is a fork, on
    // both devices, even after a reload.
    server.replay(losing);
    pull(&server, &mut a);
    pull(&server, &mut b);
    assert_eq!(integrity(read_all(&mut a)), IntegrityError::EpochRollback);
    assert_eq!(integrity(read_all(&mut b)), IntegrityError::EpochRollback);
    b.lock();
    b.unlock(&sk);
    assert_eq!(integrity(read_all(&mut b)), IntegrityError::EpochRollback);
}

/// A and B read Personnel at seq 3 (`x`, `y`). Device C read seq 2 and
/// wrote `c1`, `c2` offline: its records (its own seq 3 and 4) come back,
/// a history that forks from the server's.
fn fork_world(server: &mut Server) -> (Device, Device, SecretKey, Id, Vec<Record>) {
    let (mut a, sk) = Device::create();
    let p = personal_vault_of(&mut a);
    a.save(&login(p, "x", T0));
    round(server, &mut a, T0).unwrap();
    let mut c = Device::empty();
    pull(server, &mut c);
    c.unlock(&sk);
    c.save(&login(p, "c1", T0 + 1));
    c.save(&login(p, "c2", T0 + 2));
    let forked = outbox(&c).iter().map(|(ch, _)| as_record(ch)).collect();
    a.save(&login(p, "y", T0 + 3));
    round(server, &mut a, T0).unwrap();
    let mut b = Device::empty();
    pull(server, &mut b);
    b.unlock(&sk);
    assert_eq!(users(&b.items()), vec!["x", "y"]);
    (a, b, sk, p, forked)
}

/// Every device reads `expected` in Personnel, at `epoch`, `Ok`, with
/// nothing left to send.
fn settled(server: &mut Server, devs: &mut [&mut Device], p: Id, expected: &[&str], epoch: u64) {
    settle(server, devs, T0 + 3600);
    for dev in devs.iter_mut() {
        assert_eq!(users(&dev.items()), expected);
        assert_eq!(dev.repo().restore_epoch(), Some(epoch));
        assert_eq!(health(dev, p), VaultSyncHealth::Ok);
        assert_eq!(outbox(dev), vec![]);
    }
}

#[test]
fn keep_this_device_after_fork_heals_both_devices() {
    let mut server = Server::default();
    let (mut a, mut b, _sk, p, forked) = fork_world(&mut server);
    // B writes offline; the store serves C's fork.
    b.save(&login(p, "z", T0 + 4));
    for r in forked {
        server.replay(r);
    }
    assert!(round(&mut server, &mut b, T0 + 30).is_err());
    round(&mut server, &mut a, T0 + 30).unwrap();
    for dev in [&mut a, &mut b] {
        assert_eq!(
            health(dev, p),
            VaultSyncHealth::Alert(IntegrityError::ManifestRollback)
        );
    }

    // The owner keeps B's copy: it is re-signed past the epoch floor and
    // overwrites the fork.
    let epoch = b
        .repo()
        .issue_restore_epoch_from_local(EpochReason::KeepThisDevice)
        .unwrap();
    assert_eq!(epoch.epoch, 1);
    assert_eq!(epoch.reason, EpochReason::KeepThisDevice);
    round(&mut server, &mut b, T0 + 60).unwrap();
    round(&mut server, &mut a, T0 + 60).unwrap();
    round(&mut server, &mut b, T0 + 90).unwrap();
    settled(&mut server, &mut [&mut a, &mut b], p, &["x", "y", "z"], 1);
}

#[test]
fn keep_this_device_without_local_writes_heals() {
    let mut server = Server::default();
    let (mut a, mut b, _sk, items) = setup(&mut server, &[("x", T0)]);
    let p = items[0].vault_id;
    let seq2 = server.get(RecordKind::Manifest, p).unwrap();
    a.save(&login(p, "y", T0 + 1));
    round(&mut server, &mut a, T0).unwrap();
    round(&mut server, &mut b, T0).unwrap();
    // The server goes back to seq 2; B has no local write.
    server.replay(seq2);
    round(&mut server, &mut b, T0 + 30).unwrap();
    assert!(is_behind(health(&mut b, p)));

    // Only "keep this device" goes through this path.
    assert_eq!(
        b.repo()
            .issue_restore_epoch_from_local(EpochReason::TakeServer)
            .map(|e| e.epoch),
        Err(Error::InvalidFormat("restore epoch reason"))
    );
    let epoch = b
        .repo()
        .issue_restore_epoch_from_local(EpochReason::KeepThisDevice)
        .unwrap();
    assert_eq!(epoch.epoch, 1);
    round(&mut server, &mut b, T0 + 60).unwrap();
    round(&mut server, &mut a, T0 + 60).unwrap();
    round(&mut server, &mut b, T0 + 90).unwrap();
    settled(&mut server, &mut [&mut a, &mut b], p, &["x", "y"], 1);
}

#[test]
fn take_server_after_alert_converges() {
    let mut server = Server::default();
    let (mut a, mut b, _sk, p, forked) = fork_world(&mut server);
    b.save(&login(p, "z", T0 + 4));
    for r in forked {
        server.replay(r);
    }
    assert!(round(&mut server, &mut b, T0 + 30).is_err());
    assert_eq!(
        health(&mut b, p),
        VaultSyncHealth::Alert(IntegrityError::ManifestRollback)
    );
    // The app exports what B has first: still readable.
    assert_eq!(users(&b.items()), vec!["x", "y", "z"]);

    // The owner takes the server's version: B's unpushed write is dropped.
    let epoch = b.repo().issue_restore_epoch_take_server().unwrap();
    assert_eq!(epoch.epoch, 1);
    assert_eq!(epoch.reason, EpochReason::TakeServer);
    assert_eq!(users(&b.items()), vec!["c1", "c2", "x"]);
    round(&mut server, &mut b, T0 + 60).unwrap();
    // A, which alerted on the fork without a write of its own, takes the
    // epoch's heads.
    round(&mut server, &mut a, T0 + 60).unwrap();
    round(&mut server, &mut b, T0 + 90).unwrap();
    settled(&mut server, &mut [&mut a, &mut b], p, &["c1", "c2", "x"], 1);
}

#[test]
fn concurrent_edit_not_overwritten_by_keep_this_device() {
    let mut server = Server::default();
    let (mut a, mut b, sk, p, forked) = fork_world(&mut server);
    let q = a.repo().create_vault(meta("Projet Atlas")).unwrap();
    let qx = login(q.id, "qx", T0);
    a.repo().save_item(&q, qx.clone()).unwrap();
    round(&mut server, &mut a, T0).unwrap();
    round(&mut server, &mut b, T0).unwrap();
    let bq = b.vault_named("Projet Atlas");
    assert_eq!(users(&b.repo().items(&bq).unwrap()), vec!["qx"]);

    // B writes both vaults offline. Meanwhile A edits Projet Atlas, and the
    // store serves C's fork of Personnel.
    b.save(&login(p, "z", T0 + 4));
    b.repo().save_item(&bq, login(q.id, "q.b", T0 + 5)).unwrap();
    let aq = a.vault_named("Projet Atlas");
    a.repo()
        .save_item(&aq, edited(&qx, "qx.a", T0 + 6))
        .unwrap();
    round(&mut server, &mut a, T0 + 10).unwrap();
    for r in forked {
        server.replay(r);
    }
    // B fetches both: Projet Atlas is held for a rebase, Personnel forks.
    let _ = push(&mut server, &b);
    pull(&server, &mut b);
    let mut both = vec![p, q.id];
    both.sort();
    assert_eq!(b.store().vaults_needing_rebase().unwrap(), both);

    // Keeping B's copy keeps A's edit of Projet Atlas: only Personnel goes
    // over the server's.
    b.repo()
        .issue_restore_epoch_from_local(EpochReason::KeepThisDevice)
        .unwrap();
    round(&mut server, &mut b, T0 + 60).unwrap();
    round(&mut server, &mut a, T0 + 60).unwrap();
    round(&mut server, &mut b, T0 + 90).unwrap();
    for dev in [&mut a, &mut b] {
        assert_eq!(users(&dev.items()), vec!["x", "y", "z"]);
        let vq = dev.vault_named("Projet Atlas");
        assert_eq!(users(&dev.repo().items(&vq).unwrap()), vec!["q.b", "qx.a"]);
        assert_eq!(dev.repo().restore_epoch(), Some(1));
        assert_eq!(outbox(dev), vec![]);
    }
    b.lock();
    b.unlock(&sk);
    assert_eq!(health(&mut b, q.id), VaultSyncHealth::Ok);
}

#[test]
fn rebase_report_lists_vaults_rebased_before_a_conflict() {
    let mut server = Server::default();
    let (mut a, mut b, _sk, items) = setup(&mut server, &[("x", T0)]);
    let p = items[0].vault_id;
    // B moves Personnel on; A issues an epoch without having pulled it.
    b.save(&edited(&items[0], "x.b", T0 + 10));
    sync(&mut server, &mut b).unwrap();
    a.repo().issue_restore_epoch(EpochReason::Restore).unwrap();
    assert!(push(&mut server, &a).is_err());
    pull(&server, &mut a);
    // The epoch cannot ship (`Conflict`), yet Personnel was rebased: the
    // app refreshes it.
    let report = a.repo().rebase_report().unwrap();
    assert_eq!(report.rebased, vec![p]);
    assert_eq!(report.error, Some(Error::Conflict));
    assert_eq!(users(&a.items()), vec!["x.b"]);
}

#[test]
fn keep_this_device_never_erases_newer_incomplete_server_state() {
    let mut server = Server::default();
    let (mut a, mut b, _sk, items) = setup(&mut server, &[("x", T0)]);
    let p = items[0].vault_id;
    // A adds N; the server serves the manifest but not yet N's record.
    let n = login(p, "n", T0 + 1);
    a.save(&n);
    round(&mut server, &mut a, T0).unwrap();
    let blob = server.item_blob(n.id, 1);
    let rec = server.get(RecordKind::Item, blob).unwrap();
    server.withhold(RecordKind::Item, blob);
    round(&mut server, &mut b, T0 + 10).unwrap();
    assert!(is_behind(health(&mut b, p)));

    // "Keep this device" does not push B's older copy over A's write: the
    // vault stays held on B's copy, nothing of it goes out.
    b.repo()
        .issue_restore_epoch_from_local(EpochReason::KeepThisDevice)
        .unwrap();
    assert_eq!(b.store().vaults_needing_rebase().unwrap(), vec![p]);
    assert!(
        outbox(&b)
            .iter()
            .all(|(c, _)| c.kind != RecordKind::Manifest && c.kind != RecordKind::Item)
    );

    // The record arrives: the rebase merges onto A's state and drops the
    // epoch that could not ship (the caller would issue it again).
    server.replay(rec);
    assert_eq!(round(&mut server, &mut b, T0 + 60), Err(Error::Conflict));
    assert_eq!(b.repo().restore_epoch(), None);
    round(&mut server, &mut a, T0 + 60).unwrap();
    settle(&mut server, &mut [&mut a, &mut b], T0 + 120);
    for dev in [&mut a, &mut b] {
        assert_eq!(users(&dev.items()), vec!["n", "x"]);
        assert_eq!(health(dev, p), VaultSyncHealth::Ok);
        assert_eq!(outbox(dev), vec![]);
    }
}

#[test]
fn take_server_refused_keeps_local_writes() {
    let mut server = Server::default();
    let (mut a, mut b, _sk, items) = setup(&mut server, &[("x", T0)]);
    let p = items[0].vault_id;
    let n = login(p, "n", T0 + 1);
    a.save(&n);
    round(&mut server, &mut a, T0).unwrap();
    let blob = server.item_blob(n.id, 1);
    server.withhold(RecordKind::Item, blob);
    b.save(&login(p, "z", T0 + 2));
    pull(&server, &mut b);
    let before = b.repo().device_state().clone();

    // The server's state is incomplete: nothing to take, nothing dropped.
    assert_eq!(
        b.repo().issue_restore_epoch_take_server().map(|e| e.epoch),
        Err(Error::Integrity(IntegrityError::ManifestMissingItem))
    );
    assert_eq!(b.repo().device_state(), &before);
    assert_eq!(b.store().vaults_needing_rebase().unwrap(), vec![p]);
    assert_eq!(users(&b.items()), vec!["x", "z"]);
    assert_eq!(b.repo().restore_epoch(), None);
}

#[test]
fn reissued_keep_never_erases_newer_incomplete_write() {
    let mut server = Server::default();
    let (mut a, mut c, _sk, items) = setup(&mut server, &[("x", T0)]);
    let p = items[0].vault_id;
    let seq2 = server.get(RecordKind::Manifest, p).unwrap();
    a.save(&login(p, "y", T0 + 1));
    round(&mut server, &mut a, T0).unwrap();
    round(&mut server, &mut c, T0).unwrap();

    // The server goes back to seq 2; A sees it and keeps its copy.
    server.replay(seq2);
    pull(&server, &mut a);
    assert_eq!(users(&a.items()), vec!["x", "y"]);
    assert!(a.repo().keep_needed().unwrap());
    a.repo()
        .issue_restore_epoch_from_local(EpochReason::KeepThisDevice)
        .unwrap();

    // Before A pushes, C writes Personnel again (restoring the server's
    // copy and adding its own record), but the server does not serve C's
    // new record yet.
    let z = login(p, "z", T0 + 2);
    c.save(&z);
    round(&mut server, &mut c, T0 + 10).unwrap();
    let blob = server.item_blob(z.id, 1);
    let rec = server.get(RecordKind::Item, blob).unwrap();
    server.withhold(RecordKind::Item, blob);

    // A's epoch cannot ship: withdrawn, Personnel held on A's copy.
    assert_eq!(round(&mut server, &mut a, T0 + 20), Err(Error::Conflict));
    assert_eq!(a.repo().restore_epoch(), None);
    assert_eq!(a.store().vaults_needing_rebase().unwrap(), vec![p]);
    // Nothing for "keep this device" to do: the rebase settles it.
    assert!(!a.repo().keep_needed().unwrap());

    // Re-issued anyway, it still never pushes A's copy over C's write.
    a.repo()
        .issue_restore_epoch_from_local(EpochReason::KeepThisDevice)
        .unwrap();
    assert_eq!(a.store().vaults_needing_rebase().unwrap(), vec![p]);
    assert!(
        outbox(&a)
            .iter()
            .all(|(ch, _)| ch.kind != RecordKind::Manifest && ch.kind != RecordKind::Item)
    );

    // C's record arrives: the rebase merges onto C's state, C's write
    // survives on both devices.
    server.replay(rec);
    let _ = round(&mut server, &mut a, T0 + 60);
    round(&mut server, &mut a, T0 + 70).unwrap();
    round(&mut server, &mut c, T0 + 70).unwrap();
    settle(&mut server, &mut [&mut a, &mut c], T0 + 120);
    for dev in [&mut a, &mut c] {
        assert_eq!(users(&dev.items()), vec!["x", "y", "z"]);
        assert_eq!(health(dev, p), VaultSyncHealth::Ok);
        assert_eq!(outbox(dev), vec![]);
    }
}
