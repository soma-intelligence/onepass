//! Attack regression suite of key rotation v2 (spec 12, plan Task 19):
//! every reviewer repro of the first design, rewritten against the v2 API,
//! each asserting the "v2 outcome" column of spec 12, plus the race of
//! spec 8.3 in every order.
//!
//! The devices are SyncStore files over the fake server of `common`. A is
//! the rotator ("iPhone"); B ("iPad") is the device the user removes, and
//! the attacker of T1 once removed: it keeps its whole local state (old
//! Secret Key, old keyset, its device keys) and the master password; C
//! ("Mac") is a remaining device; D ("Watch") another one.

mod common;

use std::collections::BTreeSet;

use common::*;
use onepass_core::device_keys::{DeviceKeys, DevicePublic};
use onepass_core::devices::{DeviceKind, DeviceMode};
use onepass_core::epoch::{EpochReason, RestoreEpoch, SignedRestoreEpoch};
use onepass_core::lineage::resolve::PromptKind;
use onepass_core::lineage::{
    GenesisBody, LINEAGE_FORMAT, LineageRecord, RosterEntry, RotationBody, RotationReason,
    delivery_id, identity_id, sign_genesis, sign_rotation,
};
use onepass_core::repo::follow::{
    QuarantineTick, RotationPrompt, follow_rotation, follow_switch, pending_rotation,
    quarantine_tick, reject_rotation, stored_params_epoch,
};
use onepass_core::repo::{RotateRequest, RotationOutcome};
use onepass_core::store::account_record_id;
use onepass_core::trust::{LineageHead, TrustLevel, TrustState};

const NEW_PASSWORD: &str = "Projet Zénith, Camille Durand";

/// Device time, in Unix seconds, for the quarantine clock.
const NOW: u64 = 1_793_100_000;
const YEAR: u64 = 365 * 86_400;

// ---------------------------------------------------------------- fixture

struct Peer {
    keys: DeviceKeys,
    public: DevicePublic,
}

impl Peer {
    fn new(id: Id) -> Peer {
        let keys = DeviceKeys::generate_software().unwrap();
        let public = keys.public(id).unwrap();
        Peer { keys, public }
    }

    fn id(&self) -> Id {
        self.public.device_id
    }

    fn entry(&self, name: &str) -> RosterEntry {
        RosterEntry {
            device_id: self.public.device_id,
            sign_pub: self.public.sign_pub.clone(),
            kem_pub: self.public.kem_pub.clone(),
            name: name.into(),
            kind: DeviceKind::Phone,
            mode: DeviceMode::Personal,
            introduced_by: None,
        }
    }
}

struct Fixture {
    sk: SecretKey,
    /// A, the rotator ("iPhone").
    a: Peer,
    /// B ("iPad"), C ("Mac"), D ("Watch").
    others: Vec<Peer>,
}

const B: usize = 0;
const C: usize = 1;

impl Fixture {
    fn b(&self) -> &Peer {
        &self.others[B]
    }

    fn c(&self) -> &Peer {
        &self.others[C]
    }
}

/// A with three items, synced; A pins a genesis whose roster is A, B, C
/// and D, all verified, state `Current`. The genesis is pushed.
fn fixture(server: &mut Server) -> (Device, Fixture) {
    let (mut a, _b, sk, _items) =
        setup(server, &[("alice", T0), ("bob", T0 + 1), ("carol", T0 + 2)]);
    let me = Peer::new(a.repo().chain().device_id.unwrap_or_else(Id::new));
    let others: Vec<Peer> = (0..3).map(|_| Peer::new(Id::new())).collect();
    let mut roster = vec![me.entry("iPhone")];
    roster.extend(
        others
            .iter()
            .zip(["iPad", "Mac", "Watch"])
            .map(|(p, n)| p.entry(n)),
    );
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
                creator: me.entry("iPhone"),
                created_at: T0,
            },
            &me.keys,
            &account.keyset().identity,
        )
        .unwrap(),
    );
    let mut trust = TrustState::new(
        account_id,
        me.public.clone(),
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
    sync(server, &mut a).unwrap();
    assert!(outbox(&a).is_empty());
    (a, Fixture { sk, a: me, others })
}

/// A device of the account whose trust state is A's genesis state, seen
/// from `others[who]` (its own device public key). Locked.
fn device(server: &mut Server, a: &Device, f: &Fixture, who: usize) -> Device {
    let mut d = Device::empty();
    pull(server, &mut d);
    d.unlock(&f.sk);
    let mut trust = a.store().trust_state().unwrap().unwrap();
    trust.me = f.others[who].public.clone();
    d.repo()
        .store_mut()
        .put_all_if_version_with_trust(vec![], vec![], None, &trust)
        .unwrap();
    d.lock();
    d
}

/// A device holding the account's keys under the identity A leaves, with
/// no trust state (a build before v2, or the attacker's own tool).
/// Unlocked.
fn old_keys_device(server: &Server, f: &Fixture) -> Device {
    let mut d = Device::empty();
    pull(server, &mut d);
    d.unlock(&f.sk);
    d
}

fn reason(revoke: &[Id]) -> RotationReason {
    if revoke.is_empty() {
        RotationReason::Rotate
    } else {
        RotationReason::Revoke
    }
}

/// `dev` (unlocked, holding `keys`) rotates from the head it is on,
/// revoking `revoke`. Nothing is pushed.
fn rotate_on(
    dev: &mut Device,
    f: &Fixture,
    keys: &DeviceKeys,
    revoke: Vec<Id>,
) -> (RotationOutcome, SecretKey) {
    let new_sk = SecretKey::generate().unwrap();
    let req = RotateRequest {
        reason: reason(&revoke),
        revoke,
        new_password: None,
        password: PASSWORD,
        secret_key: &f.sk,
        new_secret_key: &new_sk,
        device_keys: keys,
        keep_tofu: &[],
    };
    let out = dev.repo().rotate(req).unwrap();
    (out, new_sk)
}

fn state(dev: &Device) -> DeviceLineageState {
    dev.store().trust_state().unwrap().unwrap().state
}

fn trust(dev: &Device) -> TrustState {
    dev.store().trust_state().unwrap().unwrap()
}

fn head_of(dev: &Device) -> [u8; 32] {
    trust(dev).head.hash
}

fn prompt_of(dev: &Device) -> Option<RotationPrompt> {
    pending_rotation(&dev.store()).unwrap()
}

fn lineage_id(h: &[u8; 32]) -> Id {
    let mut id = [0u8; 16];
    id.copy_from_slice(&h[..16]);
    Id(id)
}

fn body_of(store: &SyncStore, h: &[u8; 32]) -> RotationBody {
    let rec = store
        .get(RecordKind::Lineage, lineage_id(h))
        .unwrap()
        .expect("lineage record");
    match LineageRecord::decode(&rec.data).unwrap() {
        LineageRecord::Rotation(r) => r.body,
        LineageRecord::Genesis(_) => panic!("a genesis"),
    }
}

/// Push the outbox as it is (one batch) and confirm it, without settling
/// the rotation phase.
fn push_outbox(server: &mut Server, dev: &Device) -> std::result::Result<(), Conflict> {
    send(server, dev, outbox(dev), true)
}

/// Push and settle phases 1 and 2 only (no phase 3): a rotation that looks
/// complete to any follower.
fn push_phases_one_and_two(server: &mut Server, dev: &Device) {
    for phase in [1, 2] {
        push_outbox(server, dev).unwrap();
        assert_eq!(
            dev.store().push_rotation_phase(phase).unwrap(),
            PhaseOutcome::Done,
            "phase {phase}"
        );
    }
}

/// Push and settle phase 1 only: the rotation record, its deliveries,
/// params and keyset, enough for a follower to call it complete.
fn push_phase_one(server: &mut Server, dev: &Device) {
    push_outbox(server, dev).unwrap();
    assert_eq!(
        dev.store().push_rotation_phase(1).unwrap(),
        PhaseOutcome::Done
    );
}

/// Fetch the changes after the cursor, each through `map` (dropped on
/// `None`), stage them and commit at once.
fn pull_mapped(
    server: &Server,
    dev: &mut Device,
    map: impl Fn(RemoteChange) -> Option<RemoteChange>,
) {
    let (changes, cursor) = server.changes_since(dev.cursor);
    let mut store = dev.store();
    for c in changes.into_iter().filter_map(&map) {
        store.stage_remote(c).unwrap();
    }
    store.commit_remote().unwrap();
    dev.cursor = cursor;
}

/// Fetch everything but the lineage records of `hidden`, without moving
/// the cursor past them (a later `pull` brings them).
fn pull_hiding(server: &Server, dev: &mut Device, hidden: &[[u8; 32]]) {
    let ids: Vec<Id> = hidden.iter().map(lineage_id).collect();
    let cursor = dev.cursor;
    pull_mapped(server, dev, |ch| {
        (ch.kind != RecordKind::Lineage || !ids.contains(&ch.id)).then_some(ch)
    });
    dev.cursor = cursor;
}

fn tick(dev: &Device, now: u64) -> QuarantineTick {
    quarantine_tick(&mut dev.store(), now).unwrap()
}

/// Nothing locks `dev` and nothing will erase it, even a year later.
fn assert_never_locked(dev: &Device) {
    assert_eq!(tick(dev, NOW), QuarantineTick::NotQuarantined);
    assert_eq!(tick(dev, NOW + YEAR), QuarantineTick::NotQuarantined);
    assert!(!matches!(
        state(dev),
        DeviceLineageState::Quarantined { .. } | DeviceLineageState::Orphaned { .. }
    ));
}

fn sorted(mut v: Vec<[u8; 32]>) -> Vec<[u8; 32]> {
    v.sort();
    v
}

fn choice_hashes(p: &RotationPrompt) -> Vec<[u8; 32]> {
    sorted(p.choices.iter().map(|c| c.hash).collect())
}

fn names(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

/// The records id of the identity `dev` is on (spec 6.6).
fn records_id(dev: &Device) -> Id {
    let t = trust(dev);
    account_record_id(
        t.account_id,
        (t.head.generation > 0).then_some(&t.identity_pub),
    )
}

/// A restore epoch at `u64::MAX`, validly signed by the identity of `dev`'s
/// session.
fn inflated_epoch(dev: &mut Device) -> Vec<u8> {
    let forged = RestoreEpoch {
        account_id: dev.repo().account_id(),
        epoch: u64::MAX,
        issued_at: T0,
        heads: dev.repo().device_state().last_seen.clone(),
        reason: EpochReason::Restore,
    };
    SignedRestoreEpoch::sign(forged, &dev.repo().account().keyset().signing)
        .unwrap()
        .encode()
}

// ------------------------------------------------------------------ zz1

/// `zz1_concurrent_password_change`: C changes the master password under
/// the old identity while A rotates. Spec 12: the change lives on the old
/// identity's records, never overwrites the rotation's records, and is
/// offered for re-application after following (7.3).
#[test]
fn zz1_concurrent_password_change() {
    let mut server = Server::default();
    let (mut a, f) = fixture(&mut server);
    let mut c = device(&mut server, &a, &f, C);
    let mut d = device(&mut server, &a, &f, 2);
    let old_id = records_id(&c);

    // C changes the password and keeps it pending.
    c.unlock(&f.sk);
    c.repo()
        .change_password(PASSWORD, &f.sk, NEW_PASSWORD)
        .unwrap();
    c.lock();
    // A rotates from the epoch 1 it knew, revoking B, and pushes it all.
    let (ra, a_sk) = rotate_on(&mut a, &f, &f.a.keys, vec![f.b().id()]);
    let body = body_of(&a.store(), &ra.head);
    let new_id = identity_id(&body.identity_pub);
    sync(&mut server, &mut a).unwrap();
    assert_eq!(state(&a), DeviceLineageState::Current);
    pull(&server, &mut c);
    // D, which has not fetched yet, changes the password and pushes it
    // first: old-identity params at epoch 2.
    d.unlock(&f.sk);
    d.repo()
        .change_password(PASSWORD, &f.sk, NEW_PASSWORD)
        .unwrap();
    push(&mut server, &d).unwrap();

    // The two live side by side: neither overwrote the other.
    let old_params = server.get(RecordKind::AccountParams, old_id).unwrap();
    assert_eq!(old_params.version, 2);
    let new_params = server.get(RecordKind::AccountParams, new_id).unwrap();
    assert_eq!(new_params.version, 1);
    assert_eq!(
        aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &new_params.data).as_ref(),
        body.params_hash
    );
    // A ignores the left identity's epoch 2: it reopens with its own keys.
    pull(&server, &mut a);
    a.lock();
    a.try_unlock(PASSWORD, &a_sk).unwrap();
    assert_eq!(a.repo().account().params.epoch, 1);

    // C: the prompt offers to re-apply its pending change.
    let p = prompt_of(&c).expect("a prompt");
    assert_eq!(p.kind, PromptKind::Single);
    assert!(p.choices[0].complete);
    assert!(p.pending_password_change);
    // It follows with the password A knew, never a typed Secret Key.
    let (repo, _, c_sk) = follow_rotation(c.store(), ra.head, PASSWORD, &f.c().keys).unwrap();
    assert_eq!(c_sk.to_display(), a_sk.to_display());
    c.repo = Some(repo);
    // "Oui": epoch 2 of the new identity.
    c.repo()
        .change_password(PASSWORD, &c_sk, NEW_PASSWORD)
        .unwrap();
    sync(&mut server, &mut c).unwrap();
    assert_eq!(
        server
            .get(RecordKind::AccountParams, new_id)
            .unwrap()
            .version,
        2
    );
    // The left identity's records were not touched by C's follow.
    assert_eq!(
        server.get(RecordKind::AccountParams, old_id).unwrap(),
        old_params
    );
    // A takes the new identity's epoch 2 (it verifies under its identity).
    pull(&server, &mut a);
    let pin = a.store().device_state().unwrap().pinned;
    assert_eq!(stored_params_epoch(&a.store(), pin.as_ref()).unwrap(), 2);
    a.lock();
    a.try_unlock(NEW_PASSWORD, &a_sk).unwrap();
    assert_eq!(users(&a.items()), names(&["alice", "bob", "carol"]));
}

// ------------------------------------------------------------------ zz2

/// `zz2_hostile_epoch_inflation`: the server serves restore epochs at
/// `u64::MAX`, validly signed by the identity left (the revoked device
/// holds its keys), under the left identity's id and under the new one's.
/// Spec 12: epochs are per identity; nothing of the left identity is ever
/// compared or obeyed.
#[test]
fn zz2_hostile_epoch_inflation() {
    let mut server = Server::default();
    let (mut a, f) = fixture(&mut server);
    let mut c = device(&mut server, &a, &f, C);
    let old_id = records_id(&a);
    let forged = inflated_epoch(&mut a);
    let (ra, a_sk) = rotate_on(&mut a, &f, &f.a.keys, vec![f.b().id()]);
    sync(&mut server, &mut a).unwrap();
    let new_id = records_id(&a);
    assert_ne!(new_id, old_id);
    let planted = |id| Record {
        id,
        kind: RecordKind::RestoreEpoch,
        version: i64::MAX as u64,
        data: forged.clone(),
    };
    server.replay(planted(old_id));

    // On A: the left identity's epoch is never read.
    pull(&server, &mut a);
    assert_eq!(a.repo().restore_epoch(), None);
    assert_eq!(state(&a), DeviceLineageState::Current);

    // On C: the follow is not blocked, the rotation's `from_heads` sets
    // the vaults' start (R12), not an epoch.
    pull(&server, &mut c);
    let p = prompt_of(&c).expect("a prompt");
    assert!(p.choices[0].complete);
    let body = body_of(&c.store(), &ra.head);
    let (repo, _, _) = follow_rotation(c.store(), ra.head, PASSWORD, &f.c().keys).unwrap();
    assert_eq!(repo.device_state().last_seen, body.from_heads);
    assert_eq!(repo.restore_epoch(), None);
    c.repo = Some(repo);

    // Both go on: the next epoch of the new identity is its first.
    a.lock();
    a.try_unlock(PASSWORD, &a_sk).unwrap();
    let issued = a.repo().issue_restore_epoch(EpochReason::Restore).unwrap();
    assert_eq!(issued.epoch, 1);
    sync(&mut server, &mut a).unwrap();
    assert_eq!(
        server
            .get(RecordKind::RestoreEpoch, new_id)
            .unwrap()
            .version,
        1
    );
    pull(&server, &mut c);
    c.lock();
    c.try_unlock(PASSWORD, &a_sk).unwrap();
    assert_eq!(users(&c.items()), names(&["alice", "bob", "carol"]));
    assert_eq!(c.repo().restore_epoch(), Some(1));
    // The left identity's epoch is still on the server, unread.
    assert_eq!(
        server
            .get(RecordKind::RestoreEpoch, old_id)
            .unwrap()
            .version,
        i64::MAX as u64
    );
    // Planted under the new identity's own id: refused (the signature),
    // never adopted; the epoch stays the identity's own.
    server.replay(planted(new_id));
    pull(&server, &mut c);
    assert_eq!(
        c.repo().vaults().unwrap_err(),
        Error::Integrity(IntegrityError::Signature)
    );
    assert_eq!(c.repo().restore_epoch(), Some(1));
}

/// `zz2_epoch_drop_reopens_pair_drop`: while A rotates, C writes under the
/// old identity; the server then drops (forged deletions) the restore
/// epoch and the params and keyset pair of both identities. Spec 12 and
/// plan Task 10: nothing of the left identity is compared or obeyed, the
/// deletions are refused, and C keeps every one of its writes.
#[test]
fn zz2_epoch_drop_reopens_pair_drop() {
    let mut server = Server::default();
    let (mut a, f) = fixture(&mut server);
    let mut c = device(&mut server, &a, &f, C);
    c.unlock(&f.sk);
    let old_id = records_id(&a);
    let issued = a.repo().issue_restore_epoch(EpochReason::Restore).unwrap();
    assert_eq!(issued.epoch, 1);
    sync(&mut server, &mut a).unwrap();
    pull(&server, &mut c);

    let (ra, a_sk) = rotate_on(&mut a, &f, &f.a.keys, vec![f.b().id()]);
    // C writes during the rotation: one pushed, one kept pending.
    let v = c.vault();
    c.repo()
        .save_item(&v, login(v.id, "pushed", T0 + 50))
        .unwrap();
    sync(&mut server, &mut c).unwrap();
    c.repo()
        .save_item(&v, login(v.id, "pending", T0 + 60))
        .unwrap();
    sync(&mut server, &mut a).unwrap();
    let new_id = records_id(&a);
    pull(&server, &mut c);

    // The server drops the epoch and the account pair, old and new.
    for id in [old_id, new_id] {
        for kind in [
            RecordKind::RestoreEpoch,
            RecordKind::AccountParams,
            RecordKind::Keyset,
        ] {
            if server.get(kind, id).is_some() {
                server.forge_deletion(kind, id);
            }
        }
    }
    pull(&server, &mut a);
    pull(&server, &mut c);
    for dev in [&a, &c] {
        let ignored: BTreeSet<(RecordKind, Id)> = dev
            .store()
            .ignored_deletions()
            .unwrap()
            .iter()
            .map(|e| (e.kind, e.id))
            .collect();
        assert!(ignored.contains(&(RecordKind::AccountParams, new_id)));
        assert!(ignored.contains(&(RecordKind::Keyset, new_id)));
    }
    // A reopens on its records, C still follows with what it holds.
    a.lock();
    a.try_unlock(PASSWORD, &a_sk).unwrap();
    let p = c
        .repo()
        .refresh_pending_rotation()
        .unwrap()
        .expect("prompt");
    assert!(p.choices[0].complete);
    let session = c.repo.take().unwrap();
    drop(session);
    let (repo, _, _) = follow_rotation(c.store(), ra.head, PASSWORD, &f.c().keys).unwrap();
    c.repo = Some(repo);
    sync(&mut server, &mut c).unwrap();
    // C's two writes are there under the new keys, on both devices.
    let all = names(&["alice", "bob", "carol", "pending", "pushed"]);
    assert_eq!(users(&c.items()), all);
    sync(&mut server, &mut a).unwrap();
    assert_eq!(users(&a.items()), all);
    // Nothing goes back to the old identity's account records.
    assert_eq!(trust(&c).head.hash, ra.head);
    assert!(outbox(&c).iter().all(|(ch, _)| ch.id != old_id));
}

// ------------------------------------------------------------------ zz3

/// `zz3_two_concurrent_rotations`: A and C rotate at once. Spec 12 and
/// 8.5: honest siblings, the smaller lineage hash wins; the loser switches
/// once with its writes replayed, the third device follows the winner,
/// the winner never moves; all end on one head.
#[test]
fn zz3_two_concurrent_rotations() {
    let mut server = Server::default();
    let (mut a, f) = fixture(&mut server);
    let mut b = device(&mut server, &a, &f, B);
    let mut c = device(&mut server, &a, &f, C);
    c.unlock(&f.sk);
    let (ra, _) = rotate_on(&mut a, &f, &f.a.keys, vec![]);
    let v = c.vault();
    c.repo()
        .save_item(&v, login(v.id, "before", T0 + 40))
        .unwrap();
    let (rc, _) = rotate_on(&mut c, &f, &f.c().keys, vec![]);
    let v = c.vault();
    c.repo()
        .save_item(&v, login(v.id, "after", T0 + 60))
        .unwrap();
    for d in [&a, &c] {
        push_outbox(&mut server, d).unwrap();
        assert_eq!(
            d.store().push_rotation_phase(1).unwrap(),
            PhaseOutcome::Done
        );
    }
    let a_wins = ra.head < rc.head;
    let (wh, lh) = if a_wins {
        (ra.head, rc.head)
    } else {
        (rc.head, ra.head)
    };
    let (mut w, mut l, l_keys) = if a_wins {
        (a, c, &f.c().keys)
    } else {
        (c, a, &f.a.keys)
    };
    for d in [&mut w, &mut l] {
        pull(&server, d);
        d.repo().refresh_pending_rotation().unwrap();
    }

    // The winner never moves; the loser stops and is asked once.
    assert!(w.repo().pending_prompt().is_none());
    let p = l.repo().pending_prompt().cloned().expect("switch prompt");
    assert_eq!(p.kind, PromptKind::Reapply);
    assert_eq!(choice_hashes(&p), vec![wh]);
    assert!(matches!(state(&l), DeviceLineageState::Candidate { .. }));
    sync(&mut server, &mut w).unwrap();
    assert_eq!(state(&w), DeviceLineageState::Current);
    assert_eq!(head_of(&w), wh);
    let _ = sync(&mut server, &mut l);
    // The loser's phase 2 never went out over the winner.
    assert!(server.get(RecordKind::Lineage, lineage_id(&lh)).is_some());
    assert!(matches!(state(&l), DeviceLineageState::Candidate { .. }));

    pull(&server, &mut l);
    let session = l.repo.take().unwrap();
    let (repo, _, sk) = follow_switch(session, wh, PASSWORD, l_keys).unwrap();
    l.repo = Some(repo);
    assert!(
        l.repo()
            .reapply(PASSWORD, &sk, &SecretKey::generate().unwrap(), l_keys)
            .unwrap()
            .is_none(),
        "nothing to re-apply"
    );
    sync(&mut server, &mut l).unwrap();

    pull(&server, &mut b);
    let pb = prompt_of(&b).expect("b prompts");
    assert_eq!(pb.kind, PromptKind::Single);
    assert_eq!(choice_hashes(&pb), vec![wh]);
    let (repo, _, _) = follow_rotation(b.store(), wh, PASSWORD, &f.b().keys).unwrap();
    b.repo = Some(repo);

    for d in [&mut w, &mut l, &mut b] {
        sync(&mut server, d).unwrap();
    }
    let all = names(&["after", "alice", "before", "bob", "carol"]);
    for d in [&mut w, &mut l, &mut b] {
        pull(&server, d);
        assert_eq!(head_of(d), wh);
        assert_eq!(prompt_of(d), None);
        assert!(d.repo().refresh_pending_rotation().unwrap().is_none());
        assert_eq!(users(&d.items()), all);
    }
}

// ------------------------------------------------------------------ zz4

/// `zz4_revoked_device_fake_complete_rotation_beats_a`: A revokes B; B,
/// offline, makes a rotation revoking A and makes it look complete on the
/// server (phases 1 and 2, before A's). Spec 12: invalid on A (B is
/// revoked there), A never abandons, locks or drops anything; on C it
/// needs the user, who sees "iPad ... a retiré iPhone" and refuses; no
/// Secret Key is ever typed to follow.
#[test]
fn zz4_revoked_device_fake_complete_rotation_beats_a() {
    let mut server = Server::default();
    let (mut a, f) = fixture(&mut server);
    let mut b = device(&mut server, &a, &f, B);
    let mut c = device(&mut server, &a, &f, C);
    let genesis = head_of(&a);
    let (ra, a_sk) = rotate_on(&mut a, &f, &f.a.keys, vec![f.b().id()]);
    let v = a.vault();
    a.save(&login(v.id, "erin", T0 + 70));
    // B gets there first, phases 1 and 2 complete.
    b.unlock(&f.sk);
    let (rb, _) = rotate_on(&mut b, &f, &f.b().keys, vec![f.a.id()]);
    push_phases_one_and_two(&mut server, &b);

    // On A: B's record is nothing; A pushes every phase over B's content.
    sync(&mut server, &mut a).unwrap();
    pull(&server, &mut a);
    assert_eq!(a.repo().refresh_pending_rotation().unwrap(), None);
    assert_eq!(state(&a), DeviceLineageState::Current);
    assert_eq!(head_of(&a), ra.head);
    assert_never_locked(&a);
    let expected = names(&["alice", "bob", "carol", "erin"]);
    assert_eq!(users(&a.items()), expected);
    a.lock();
    a.try_unlock(PASSWORD, &a_sk).unwrap();
    assert_eq!(users(&a.items()), expected);
    let vid = v.id;
    for kind in [RecordKind::VaultKey, RecordKind::Manifest] {
        assert_eq!(
            server.get(kind, vid).map(|r| r.data),
            a.store().get(kind, vid).unwrap().map(|r| r.data),
            "{kind:?}: A's content is what the server serves"
        );
    }

    // On C, A's record withheld: B's looks complete, it still needs the
    // user, and names come from C's own pins.
    pull_hiding(&server, &mut c, &[ra.head]);
    let p = prompt_of(&c).expect("a prompt");
    assert_eq!(p.kind, PromptKind::Single);
    assert_eq!(choice_hashes(&p), vec![rb.head]);
    assert!(p.choices[0].complete);
    assert_eq!(p.choices[0].rotator_name, "iPad");
    assert_eq!(p.choices[0].revoked_names, names(&["iPhone"]));
    assert_never_locked(&c);
    // Read-only meanwhile (R10).
    c.unlock(&f.sk);
    let cv = c.vault();
    assert_eq!(
        c.repo().save_item(&cv, login(cv.id, "x", T0 + 80)).err(),
        Some(Error::ReadOnly)
    );
    c.lock();
    reject_rotation(&mut c.store(), rb.head, true).unwrap();
    assert_eq!(state(&c), DeviceLineageState::Current);
    assert!(trust(&c).excluded.contains(&f.b().id()));
    assert_eq!(head_of(&c), genesis);

    // A's record arrives: that is the one C is asked about now; following
    // it opens the delivery with C's device key and the password only.
    full_fetch(&server, &mut c);
    let p = prompt_of(&c).expect("a prompt");
    assert_eq!(choice_hashes(&p), vec![ra.head]);
    assert_eq!(p.choices[0].rotator_name, "iPhone");
    let (repo, _, sk) = follow_rotation(c.store(), ra.head, PASSWORD, &f.c().keys).unwrap();
    assert_eq!(sk.to_display(), a_sk.to_display());
    c.repo = Some(repo);
    assert_eq!(users(&c.items()), expected);
    // B's record stays invalid there for good.
    assert_eq!(c.repo().refresh_pending_rotation().unwrap(), None);
}

// ------------------------------------------------------------------ zz5

/// `zz5_two_incomplete_rotations_alternate`: A and C rotate at once and the
/// server serves each one incomplete in turn (the deliveries withheld,
/// rounds alternating). Spec 12: no completeness contest, identity-keyed
/// records never overwrite each other, the order of 8.5 settles both in
/// one switch per device; nothing alternates, the revoked device cannot
/// postpone anything.
#[test]
fn zz5_two_incomplete_rotations_alternate() {
    let mut server = Server::default();
    let (mut a, f) = fixture(&mut server);
    let mut b = device(&mut server, &a, &f, B);
    let mut c = device(&mut server, &a, &f, C);
    c.unlock(&f.sk);
    let (ra, _) = rotate_on(&mut a, &f, &f.a.keys, vec![]);
    let (rc, _) = rotate_on(&mut c, &f, &f.c().keys, vec![]);
    // Phase 1 of both, deliveries withheld from every fetch.
    for d in [&a, &c] {
        push_outbox(&mut server, d).unwrap();
        assert_eq!(
            d.store().push_rotation_phase(1).unwrap(),
            PhaseOutcome::Done
        );
    }
    // Identity-keyed: both params records are there, side by side.
    let (ida, idc) = (records_id(&a), records_id(&c));
    assert_ne!(ida, idc);
    assert!(server.get(RecordKind::AccountParams, ida).is_some());
    assert!(server.get(RecordKind::AccountParams, idc).is_some());

    let a_wins = ra.head < rc.head;
    let wh = if a_wins { ra.head } else { rc.head };
    let (mut w, mut l, l_keys) = if a_wins {
        (a, c, &f.c().keys)
    } else {
        (c, a, &f.a.keys)
    };
    // Rounds: the records without any delivery, then with the loser's
    // deliveries only (the loser's rotation looks complete, the winner's
    // does not), then everything for the loser and the winner. The
    // winner never stops nor prompts, the loser always targets the winner
    // and pushes nothing of its phase 2.
    let lh = if a_wins { rc.head } else { ra.head };
    let loser_deliveries: BTreeSet<Id> = [B, C, 2]
        .iter()
        .map(|i| delivery_id(&lh, f.others[*i].id()))
        .chain(std::iter::once(delivery_id(&lh, f.a.id())))
        .collect();
    let mut seen = BTreeSet::new();
    for round in 0..3 {
        for d in [&mut w, &mut l] {
            let cursor = d.cursor;
            pull_only(&server, d, |ch| match round {
                0 => ch.kind != RecordKind::KeyDelivery,
                1 => ch.kind != RecordKind::KeyDelivery || loser_deliveries.contains(&ch.id),
                _ => true,
            });
            d.cursor = cursor;
            d.repo().refresh_pending_rotation().unwrap();
        }
        assert!(w.repo().pending_prompt().is_none(), "round {round}");
        assert!(!matches!(state(&w), DeviceLineageState::Candidate { .. }));
        let p = l.repo().pending_prompt().cloned().expect("loser prompt");
        assert_eq!(p.kind, PromptKind::Reapply);
        seen.insert(choice_hashes(&p));
        let _ = push(&mut server, &l);
        assert!(matches!(state(&l), DeviceLineageState::Candidate { .. }));
        let v = l.vault().id;
        assert_ne!(
            server.get(RecordKind::VaultKey, v).map(|r| r.data),
            l.store()
                .get(RecordKind::VaultKey, v)
                .unwrap()
                .map(|r| r.data),
            "round {round}: the loser's vault key never went out"
        );
    }
    assert_eq!(
        seen,
        BTreeSet::from([vec![wh]]),
        "one target, never another"
    );

    // Everything arrives: one step per device.
    sync(&mut server, &mut w).unwrap();
    pull(&server, &mut l);
    let session = l.repo.take().unwrap();
    let (repo, _, _) = follow_switch(session, wh, PASSWORD, l_keys).unwrap();
    l.repo = Some(repo);
    pull(&server, &mut b);
    let (repo, _, _) = follow_rotation(b.store(), wh, PASSWORD, &f.b().keys).unwrap();
    b.repo = Some(repo);
    for d in [&mut w, &mut l, &mut b] {
        sync(&mut server, d).unwrap();
    }
    for d in [&mut w, &mut l, &mut b] {
        pull(&server, d);
        assert_eq!(head_of(d), wh);
        assert_eq!(prompt_of(d), None);
        assert_eq!(users(&d.items()), names(&["alice", "bob", "carol"]));
    }
}

// ------------------------------------------- zz6 and the biometric device

/// `zz6_updated_device_follows_legit_rotation`: a device updated to v2
/// follows a legitimate rotation. Spec 12: no known-keys memory, it
/// follows through its device key and the password.
#[test]
fn zz6_updated_device_follows_legit_rotation() {
    let mut server = Server::default();
    let (mut a, f) = fixture(&mut server);
    let mut c = device(&mut server, &a, &f, C);
    let (ra, a_sk) = rotate_on(&mut a, &f, &f.a.keys, vec![f.b().id()]);
    sync(&mut server, &mut a).unwrap();
    pull(&server, &mut c);
    let p = prompt_of(&c).expect("a prompt");
    assert_eq!(p.kind, PromptKind::Single);
    assert_eq!(p.choices[0].rotator_name, "iPhone");
    assert_eq!(p.choices[0].revoked_names, names(&["iPad"]));
    assert_eq!(p.code, Some(ra.code));
    // A wrong password changes nothing.
    let genesis = head_of(&c);
    assert!(follow_rotation(c.store(), ra.head, NEW_PASSWORD, &f.c().keys).is_err());
    assert_eq!(head_of(&c), genesis);
    assert_eq!(prompt_of(&c), Some(p.clone()));
    // Another device's keys open nothing.
    assert!(follow_rotation(c.store(), ra.head, PASSWORD, &f.others[2].keys).is_err());
    let (repo, auk, sk) = follow_rotation(c.store(), ra.head, PASSWORD, &f.c().keys).unwrap();
    assert_eq!(sk.to_display(), a_sk.to_display());
    c.repo = Some(repo);
    assert_eq!(head_of(&c), ra.head);
    assert_eq!(state(&c), DeviceLineageState::Current);
    assert_eq!(users(&c.items()), names(&["alice", "bob", "carol"]));
    c.lock();
    // The old keys no longer open it; the new ones and the AUK do.
    assert!(c.try_unlock(PASSWORD, &f.sk).is_err());
    c.try_unlock_with_auk(&auk).unwrap();
}

/// `zz_biometric_device_has_no_known_keys`: a device that only ever
/// unlocked by Face ID (an AUK, no Secret Key typed, no record of known
/// keys). Spec 12: it follows through its device key and the password
/// once, then unlocks by Face ID again; and a rotation forged with the
/// account's old keys but no pinned device key never reaches it.
#[test]
fn zz_biometric_device_has_no_known_keys() {
    let mut server = Server::default();
    let (mut a, f) = fixture(&mut server);
    let mut c = device(&mut server, &a, &f, C);
    let auk = c.try_unlock(PASSWORD, &f.sk).unwrap();
    c.lock();
    c.try_unlock_with_auk(&auk).unwrap();
    c.lock();

    // The attacker holds the old keyset, the password and its own device
    // keys, never pinned by C: its rotation is invisible to C.
    let mut x = old_keys_device(&server, &f);
    let mut forged_trust = trust(&a);
    let stranger = Peer::new(f.c().id());
    forged_trust.me = stranger.public.clone();
    for e in forged_trust.roster.iter_mut() {
        if e.device_id == f.c().id() {
            e.sign_pub = stranger.public.sign_pub.clone();
            e.kem_pub = stranger.public.kem_pub.clone();
        }
    }
    x.repo()
        .store_mut()
        .put_all_if_version_with_trust(vec![], vec![], None, &forged_trust)
        .unwrap();
    let (rx, _) = rotate_on(&mut x, &f, &stranger.keys, vec![f.a.id()]);
    sync(&mut server, &mut x).unwrap();
    pull(&server, &mut c);
    assert!(
        server
            .get(RecordKind::Lineage, lineage_id(&rx.head))
            .is_some()
    );
    assert_eq!(prompt_of(&c), None);
    assert_eq!(state(&c), DeviceLineageState::Current);
    assert_never_locked(&c);
    c.try_unlock_with_auk(&auk).unwrap();
    c.lock();

    // The legitimate rotation: the password once, no Secret Key typed.
    let (ra, a_sk) = rotate_on(&mut a, &f, &f.a.keys, vec![f.b().id()]);
    sync(&mut server, &mut a).unwrap();
    pull(&server, &mut c);
    // A normal Face ID unlock never follows: read-only on the old keys.
    c.try_unlock_with_auk(&auk).unwrap();
    assert!(c.repo().pending_prompt().is_some());
    let cv = c.vault();
    assert_eq!(
        c.repo().save_item(&cv, login(cv.id, "x", T0 + 80)).err(),
        Some(Error::ReadOnly)
    );
    c.repo = None;
    let p = prompt_of(&c).expect("a prompt");
    assert_eq!(choice_hashes(&p), vec![ra.head]);
    let (repo, new_auk, sk) = follow_rotation(c.store(), ra.head, PASSWORD, &f.c().keys).unwrap();
    assert_eq!(sk.to_display(), a_sk.to_display());
    drop(repo);
    // Face ID again, with the AUK the follow handed back.
    c.try_unlock_with_auk(&new_auk).unwrap();
    assert_eq!(users(&c.items()), names(&["alice", "bob", "carol"]));
    c.lock();
    assert!(c.try_unlock_with_auk(&auk).is_err());
}

// ------------------------------------------------------- epoch jump wedge

/// `zz_revoked_device_wedges_rotation_with_epoch_jump`: B, revoked, holds
/// the old keyset: it pushes several password changes under the old
/// identity (params epoch jump) and a restore epoch at `u64::MAX` while A
/// pushes its rotation. Spec 12: params and epochs are per identity; A's
/// rotation goes through, C follows it, nothing of the left identity is
/// compared or obeyed.
#[test]
fn zz_revoked_device_wedges_rotation_with_epoch_jump() {
    let mut server = Server::default();
    let (mut a, f) = fixture(&mut server);
    let mut c = device(&mut server, &a, &f, C);
    let mut b = old_keys_device(&server, &f);
    let old_id = records_id(&a);
    let (ra, a_sk) = rotate_on(&mut a, &f, &f.a.keys, vec![f.b().id()]);
    push_outbox(&mut server, &a).unwrap();

    // B jumps the old identity's epoch, three password changes pushed.
    let mut password = PASSWORD.to_string();
    for i in 0..3 {
        let next = format!("{NEW_PASSWORD} {i}");
        b.repo().change_password(&password, &f.sk, &next).unwrap();
        password = next;
        sync(&mut server, &mut b).unwrap();
    }
    let forged = inflated_epoch(&mut b);
    server.replay(Record {
        id: old_id,
        kind: RecordKind::RestoreEpoch,
        version: i64::MAX as u64,
        data: forged,
    });
    assert_eq!(
        server
            .get(RecordKind::AccountParams, old_id)
            .unwrap()
            .version,
        4
    );

    // A's rotation goes through to the end.
    assert_eq!(
        a.store().push_rotation_phase(1).unwrap(),
        PhaseOutcome::Done
    );
    sync(&mut server, &mut a).unwrap();
    assert_eq!(state(&a), DeviceLineageState::Current);
    a.lock();
    a.try_unlock(PASSWORD, &a_sk).unwrap();
    assert_eq!(a.repo().account().params.epoch, 1);
    assert_eq!(a.repo().restore_epoch(), None);

    // C follows with the password A used, the old epochs unread.
    pull(&server, &mut c);
    let p = prompt_of(&c).expect("a prompt");
    assert!(p.choices[0].complete);
    assert!(!p.pending_password_change);
    let (repo, _, _) = follow_rotation(c.store(), ra.head, PASSWORD, &f.c().keys).unwrap();
    c.repo = Some(repo);
    assert_eq!(c.repo().account().params.epoch, 1);
    assert_eq!(c.repo().restore_epoch(), None);
    assert_eq!(users(&c.items()), names(&["alice", "bob", "carol"]));
    let pin = c.store().device_state().unwrap().pinned;
    assert_eq!(stored_params_epoch(&c.store(), pin.as_ref()).unwrap(), 1);
    // A write under the new keys goes out and reaches A.
    let v = c.vault();
    c.save(&login(v.id, "dave", T0 + 90));
    sync(&mut server, &mut c).unwrap();
    pull(&server, &mut a);
    assert_eq!(users(&a.items()), names(&["alice", "bob", "carol", "dave"]));
}

// ------------------------------------------------ revoker revoked back

/// `revoked_device_can_revoke_its_revoker`: after A removed B, B signs
/// "B revokes A" twice: as a sibling of A's record (from the parent it
/// still holds) and as a child of A's record. Spec 8.3 and R2: on A both
/// are invalid (B is revoked), A is never locked; on C, which followed A,
/// both are invalid too; on D, which has not answered yet, the sibling is
/// a mutual revocation for the user, never a quarantine, and the child is
/// never a child (B is not in A's roster).
#[test]
fn revoked_device_can_revoke_its_revoker() {
    let mut server = Server::default();
    let (mut a, f) = fixture(&mut server);
    let mut b = device(&mut server, &a, &f, B);
    let mut c = device(&mut server, &a, &f, C);
    let mut d = device(&mut server, &a, &f, 2);
    let (ra, _) = rotate_on(&mut a, &f, &f.a.keys, vec![f.b().id()]);
    sync(&mut server, &mut a).unwrap();
    pull(&server, &mut c);
    let (repo, _, _) = follow_rotation(c.store(), ra.head, PASSWORD, &f.c().keys).unwrap();
    c.repo = Some(repo);

    // B's sibling, revoking A (and D, to try a quarantine).
    b.unlock(&f.sk);
    let mut revoke = vec![f.a.id(), f.others[2].id()];
    revoke.sort();
    let (rb, _) = rotate_on(&mut b, &f, &f.b().keys, revoke);
    push_phase_one(&mut server, &b);
    // B's child of A's record, revoking A, signed with B's device key and
    // a fresh identity: generation 1, parent A's head.
    let child = {
        let mut body = body_of(&a.store(), &ra.head);
        body.parent = ra.head;
        body.generation += 1;
        body.rotator = f.b().id();
        body.revoked = vec![f.a.id()];
        body.roster.retain(|e| e.device_id != f.a.id());
        body.roster.push(f.b().entry("iPad"));
        body.roster.sort_by_key(|e| e.device_id);
        body.deliveries.retain(|(id, _)| *id != f.b().id());
        let account = b.repo().account();
        body.identity_pub = account.params.identity_pub.clone();
        LineageRecord::Rotation(
            sign_rotation(body, &f.b().keys, &account.keyset().identity).unwrap(),
        )
    };
    server.replay(Record {
        id: child.record_id(),
        kind: RecordKind::Lineage,
        version: 2,
        data: child.encode(),
    });

    // On A and on C: nothing, never a lock.
    for dev in [&mut a, &mut c] {
        pull(&server, dev);
        assert_eq!(dev.repo().refresh_pending_rotation().unwrap(), None);
        assert_eq!(head_of(dev), ra.head);
        assert_eq!(state(dev), DeviceLineageState::Current);
        assert_never_locked(dev);
        let v = dev.vault();
        let still = login(v.id, "still", T0 + 99);
        dev.save(&still);
        dev.delete(still.id);
    }

    // On D (on the genesis): A's record and B's sibling exclude each other.
    pull(&server, &mut d);
    let p = prompt_of(&d).expect("a prompt");
    assert_eq!(p.kind, PromptKind::Mutual);
    assert_eq!(choice_hashes(&p), sorted(vec![ra.head, rb.head]));
    assert_never_locked(&d);
    // The user keeps A: B excluded, A followed; B's child is never offered.
    let (repo, _, _) = follow_rotation(d.store(), ra.head, PASSWORD, &f.others[2].keys).unwrap();
    d.repo = Some(repo);
    let t = trust(&d);
    assert_eq!(t.head.hash, ra.head);
    assert!(t.excluded.contains(&f.b().id()) && t.revoked.contains(&f.b().id()));
    assert_eq!(d.repo().refresh_pending_rotation().unwrap(), None);
    assert_never_locked(&d);
}

// ------------------------------------------------------- spec 8.3 race

/// A revokes B (R_A), B revokes A (R_B), as spec 8.3. `rb_revokes_c`: B
/// also revokes C (a forged revocation of the device under test).
struct Race83 {
    server: Server,
    f: Fixture,
    a: Device,
    c: Device,
    ra: [u8; 32],
    rb: [u8; 32],
    a_sk: SecretKey,
}

fn race_8_3(rb_revokes_c: bool) -> Race83 {
    let mut server = Server::default();
    let (mut a, f) = fixture(&mut server);
    let mut b = device(&mut server, &a, &f, B);
    let c = device(&mut server, &a, &f, C);
    let (ra, a_sk) = rotate_on(&mut a, &f, &f.a.keys, vec![f.b().id()]);
    sync(&mut server, &mut a).unwrap();
    b.unlock(&f.sk);
    let mut revoke = vec![f.a.id()];
    if rb_revokes_c {
        revoke.push(f.c().id());
    }
    revoke.sort();
    let (rb, _) = rotate_on(&mut b, &f, &f.b().keys, revoke);
    push_phase_one(&mut server, &b);
    Race83 {
        server,
        f,
        a,
        c,
        ra: ra.head,
        rb: rb.head,
        a_sk,
    }
}

/// Spec 8.3 in every order on C, and on A, which never moves:
/// 1. R_A first, confirmed: R_B is invalid from then on;
/// 2. R_A first, unanswered, then R_B: a mutual prompt;
/// 3. R_B first (R_A withheld): "iPad a retiré iPhone", the user refuses,
///    B excluded; then R_A arrives and is followed;
/// 4. both at once: mutual, the choice of A excludes B;
/// 5. both at once, R_B also revoking C: mutual, never a quarantine.
///
/// In no order does C adopt R_B, erase or drop anything.
#[test]
fn race_8_3_all_orders() {
    // On A, whatever the order.
    {
        let mut r = race_8_3(false);
        pull(&r.server, &mut r.a);
        assert_eq!(r.a.repo().refresh_pending_rotation().unwrap(), None);
        assert_eq!(head_of(&r.a), r.ra);
        assert_never_locked(&r.a);
        r.a.lock();
        r.a.try_unlock(PASSWORD, &r.a_sk).unwrap();
    }

    // 1. R_A first, confirmed.
    {
        let mut r = race_8_3(false);
        pull_hiding(&r.server, &mut r.c, &[r.rb]);
        let p = prompt_of(&r.c).expect("prompt");
        assert_eq!(
            (p.kind, choice_hashes(&p)),
            (PromptKind::Single, vec![r.ra])
        );
        assert_eq!(p.choices[0].rotator_name, "iPhone");
        assert_eq!(p.choices[0].revoked_names, names(&["iPad"]));
        let (repo, _, _) = follow_rotation(r.c.store(), r.ra, PASSWORD, &r.f.c().keys).unwrap();
        r.c.repo = Some(repo);
        pull(&r.server, &mut r.c);
        assert_eq!(r.c.repo().refresh_pending_rotation().unwrap(), None);
        assert_eq!(head_of(&r.c), r.ra);
        assert_never_locked(&r.c);
    }

    // 2. R_A first, not answered yet, then R_B: mutual.
    {
        let mut r = race_8_3(false);
        pull_hiding(&r.server, &mut r.c, &[r.rb]);
        assert_eq!(prompt_of(&r.c).unwrap().kind, PromptKind::Single);
        pull(&r.server, &mut r.c);
        let p = prompt_of(&r.c).expect("prompt");
        assert_eq!(p.kind, PromptKind::Mutual);
        assert_eq!(choice_hashes(&p), sorted(vec![r.ra, r.rb]));
        assert_eq!(p.code, None);
        assert_never_locked(&r.c);
        mutual_keeps_a(&mut r);
    }

    // 3. R_B first, R_A withheld: the user refuses, then follows R_A.
    {
        let mut r = race_8_3(false);
        pull_hiding(&r.server, &mut r.c, &[r.ra]);
        let p = prompt_of(&r.c).expect("prompt");
        assert_eq!(
            (p.kind, choice_hashes(&p)),
            (PromptKind::Single, vec![r.rb])
        );
        assert_eq!(p.choices[0].rotator_name, "iPad");
        assert_eq!(p.choices[0].revoked_names, names(&["iPhone"]));
        assert_never_locked(&r.c);
        reject_rotation(&mut r.c.store(), r.rb, true).unwrap();
        assert_eq!(state(&r.c), DeviceLineageState::Current);
        assert!(trust(&r.c).excluded.contains(&r.f.b().id()));
        full_fetch(&r.server, &mut r.c);
        let p = prompt_of(&r.c).expect("prompt");
        assert_eq!(
            (p.kind, choice_hashes(&p)),
            (PromptKind::Single, vec![r.ra])
        );
        let (repo, _, _) = follow_rotation(r.c.store(), r.ra, PASSWORD, &r.f.c().keys).unwrap();
        drop(repo);
        assert_eq!(head_of(&r.c), r.ra);
        assert_eq!(prompt_of(&r.c), None);
    }

    // 4. Both at once.
    {
        let mut r = race_8_3(false);
        pull(&r.server, &mut r.c);
        let p = prompt_of(&r.c).expect("prompt");
        assert_eq!(p.kind, PromptKind::Mutual);
        assert_eq!(choice_hashes(&p), sorted(vec![r.ra, r.rb]));
        let of_b = p.choices.iter().find(|ch| ch.hash == r.rb).unwrap();
        assert_eq!(of_b.rotator_name, "iPad");
        assert_eq!(of_b.revoked_names, names(&["iPhone"]));
        assert_never_locked(&r.c);
        mutual_keeps_a(&mut r);
    }

    // 5. Both at once, R_B revoking C as well: still the user's choice.
    {
        let mut r = race_8_3(true);
        pull(&r.server, &mut r.c);
        let p = prompt_of(&r.c).expect("prompt");
        assert_eq!(p.kind, PromptKind::Mutual);
        assert_eq!(choice_hashes(&p), sorted(vec![r.ra, r.rb]));
        assert_never_locked(&r.c);
        mutual_keeps_a(&mut r);
    }
}

/// C keeps A in a mutual prompt: B excluded, R_B ignored, C on R_A with
/// every item, nothing left to decide.
fn mutual_keeps_a(r: &mut Race83) {
    let (repo, _, sk) = follow_rotation(r.c.store(), r.ra, PASSWORD, &r.f.c().keys).unwrap();
    assert_eq!(sk.to_display(), r.a_sk.to_display());
    r.c.repo = Some(repo);
    let t = trust(&r.c);
    assert_eq!(t.head.hash, r.ra);
    assert!(t.excluded.contains(&r.f.b().id()));
    assert!(t.revoked.contains(&r.f.b().id()));
    assert!(t.ignored.contains(&r.rb));
    assert_eq!(prompt_of(&r.c), None);
    assert_never_locked(&r.c);
    assert_eq!(users(&r.c.items()), names(&["alice", "bob", "carol"]));
}

// ------------------------------------------------- other rows of spec 12

/// Hold-out 4 (unverified params): params served under the new identity's
/// id but signed by another identity, with weaker KDF costs. Spec 12, G8:
/// verified before use, ignored otherwise; the follow and the unlocks use
/// only verified params.
#[test]
fn holdout4_unverified_params_ignored() {
    let mut server = Server::default();
    let (mut a, f) = fixture(&mut server);
    let mut c = device(&mut server, &a, &f, C);
    let genesis = head_of(&c);
    let (ra, a_sk) = rotate_on(&mut a, &f, &f.a.keys, vec![f.b().id()]);
    sync(&mut server, &mut a).unwrap();
    let new_id = records_id(&a);
    // Params of another account's identity, epoch 2, planted under the
    // new identity's id.
    let other = onepass_core::account::Account::create_with_params(PASSWORD, kdf()).unwrap();
    let mut planted = other.account.params.clone();
    planted.account_id = a.repo().account_id();
    let data = planted.encode().unwrap();
    server.replay(Record {
        id: new_id,
        kind: RecordKind::AccountParams,
        version: 2,
        data,
    });
    pull(&server, &mut c);
    let p = prompt_of(&c).expect("a prompt");
    assert!(
        !p.choices[0].complete,
        "unverified params never complete it"
    );
    assert!(follow_rotation(c.store(), ra.head, PASSWORD, &f.c().keys).is_err());
    assert_eq!(head_of(&c), genesis);
    pull(&server, &mut a);
    a.lock();
    // A reopens on the params it verified, never on the planted ones.
    match a.try_unlock(PASSWORD, &a_sk) {
        Ok(_) => {
            let expected = body_of(&a.store(), &ra.head).identity_pub;
            assert_eq!(a.repo().account().params.identity_pub, expected);
        }
        Err(e) => assert!(
            matches!(e, Error::Integrity(_) | Error::InvalidFormat(_)),
            "{e:?}"
        ),
    }
}

type Followed = (Repository<SyncStore>, Auk, SecretKey);
type FollowFn = fn(SyncStore, [u8; 32], &str, &DeviceKeys) -> Result<Followed>;

/// `unlock_after_rotation` argument order (first design): spec 12, the API
/// is gone; following takes no Secret Key and hands the new one back.
#[test]
fn follow_takes_no_secret_key() {
    let mut server = Server::default();
    let (mut a, f) = fixture(&mut server);
    let mut c = device(&mut server, &a, &f, C);
    let (ra, a_sk) = rotate_on(&mut a, &f, &f.a.keys, vec![]);
    sync(&mut server, &mut a).unwrap();
    pull(&server, &mut c);
    // The whole input of a follow: the store, the record chosen, the
    // password and this device's keys. No Secret Key.
    let follow: FollowFn = follow_rotation::<SyncStore>;
    let (_, _, sk) = follow(c.store(), ra.head, PASSWORD, &f.c().keys).unwrap();
    assert_eq!(sk.to_display(), a_sk.to_display());
}

/// Device list signed by a 2b-revoked device marking A revoked (found
/// while designing): spec 12, 8.4 and 10.1, lists no longer erase or lock
/// anything; on a v2 device removing a device is a rotation.
#[test]
fn forged_device_list_revocation_never_erases() {
    let mut server = Server::default();
    let (mut a, f) = fixture(&mut server);
    let mut b = old_keys_device(&server, &f);
    let a_id = a.repo().this_device_id().unwrap();
    let b_id = b
        .repo()
        .register_this_device("iPad", DeviceKind::Tablet, DeviceMode::Personal)
        .unwrap();
    sync(&mut server, &mut b).unwrap();
    pull(&server, &mut a);
    assert!(matches!(
        a.repo().revoke_device(b_id),
        Err(Error::Validation(_))
    ));
    b.repo().revoke_device(a_id).unwrap();
    sync(&mut server, &mut b).unwrap();
    pull(&server, &mut a);
    assert!(!a.repo().is_this_device_revoked().unwrap());
    assert_never_locked(&a);
    a.lock();
    a.unlock(&f.sk);
    let v = a.vault();
    a.save(&login(v.id, "erin", T0 + 70));
    assert_eq!(users(&a.items()), names(&["alice", "bob", "carol", "erin"]));
}
