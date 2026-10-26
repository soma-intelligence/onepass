//! Signed restore epochs over the two-device harness: a restore from an old
//! backup (a vault recreated under a new id, a vault written again from an
//! old copy) is accepted by the other devices without an alert, while a
//! store that replays the old state, hides the epoch, serves an older one or
//! forges one is refused.

mod common;

use common::*;
use onepass_core::epoch::{EpochReason, SignedRestoreEpoch};
use onepass_core::repo::DeviceState;

/// Change token key of the harness devices (any name the store does not use).
const TOKEN_KEY: &str = "sync.token";

fn account_id(dev: &mut Device) -> Id {
    dev.repo().account().params.account_id
}

/// The zone was deleted and recreated empty: the device settles a reset
/// fetch that returned nothing, so all its rows go up again.
fn zone_reset(server: &Server, dev: &mut Device) {
    let (changes, cursor) = server.changes_since(0);
    let mut store = dev.store();
    store.begin_zone_reset(TOKEN_KEY).unwrap();
    for c in changes.into_iter().filter(|c| c.data.is_some()) {
        store.stage_remote(c).unwrap();
    }
    store.commit_remote().unwrap();
    store.finish_full_fetch().unwrap();
    dev.cursor = cursor;
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
    let p = w.b.vault_named("Personnel");
    assert_eq!(
        integrity(w.b.repo().items(&p)),
        IntegrityError::ManifestRollback
    );
    w.b.lock();
    w.b.unlock(&w.sk);
    let p = w.b.vault_named("Personnel");
    assert_eq!(
        integrity(w.b.repo().items(&p)),
        IntegrityError::ManifestRollback
    );
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

    // From then on it refuses the history before the epoch.
    server.replay(before);
    pull(&server, &mut c);
    assert_eq!(integrity(c.try_items()), IntegrityError::ManifestRollback);
}
