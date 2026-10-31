//! Key rotation v2, genesis and migration (spec 6.2, 15, R17, O4): a new
//! account writes a genesis; a device of a legacy account writes the
//! legacy genesis or joins it with a legacy intro on its first unlock
//! after the update, trusted on first use; conflicting claims are
//! excluded; a 2b revocation prompts a rotation once; a SAS verification
//! upgrades `Tofu` to `Verified`.

mod common;

use std::collections::BTreeSet;

use common::*;
use onepass_core::device_keys::{DeviceKeys, DevicePublic, sign_pop};
use onepass_core::devices::{DeviceKind, DeviceMode};
use onepass_core::lineage::RotationReason;
use onepass_core::lineage::{
    GenesisBody, LINEAGE_FORMAT, LegacyIntroBody, LineageRecord, RosterEntry, legacy_intro_id,
    sign_genesis, sign_legacy_intro, verify_genesis,
};
use onepass_core::repo::RotateRequest;
use onepass_core::repo::follow::{follow_rotation, pending_rotation};
use onepass_core::repo::migrate::Migration;
use onepass_core::trust::{TrustLevel, TrustState};

// ---------------------------------------------------------------- helpers

/// A device's keys, made by the app at its first unlock after the update.
struct Keys(DeviceKeys);

impl Keys {
    fn new() -> Keys {
        Keys(DeviceKeys::generate_software().unwrap())
    }

    fn public(&self, dev: &mut Device) -> DevicePublic {
        let id = dev.repo().this_device_id().expect("registered");
        self.0.public(id).unwrap()
    }
}

fn trust(dev: &Device) -> TrustState {
    dev.store().trust_state().unwrap().expect("a trust state")
}

fn migrate(dev: &mut Device, keys: &Keys) -> Migration {
    dev.repo().migrate_to_v2(&keys.0).unwrap()
}

fn refresh(dev: &mut Device) {
    dev.repo().refresh_pending_rotation().unwrap();
}

fn roster_ids(t: &TrustState) -> BTreeSet<Id> {
    t.roster.iter().map(|e| e.device_id).collect()
}

fn entry_of(p: &DevicePublic, name: &str) -> RosterEntry {
    RosterEntry {
        device_id: p.device_id,
        sign_pub: p.sign_pub.clone(),
        kem_pub: p.kem_pub.clone(),
        name: name.into(),
        kind: DeviceKind::Mac,
        mode: DeviceMode::Personal,
        introduced_by: None,
    }
}

/// A third legacy device of the account, registered under `name`.
fn third(server: &mut Server, sk: &SecretKey, name: &str) -> Device {
    let mut c = Device::empty();
    pull(server, &mut c);
    c.unlock(sk);
    c.repo()
        .register_this_device(name, DeviceKind::Mac, DeviceMode::Personal)
        .unwrap();
    sync(server, &mut c).unwrap();
    c
}

/// A record pushed by `dev` as is (a forged one: the device holds the
/// account keys).
fn push_record(server: &mut Server, dev: &mut Device, record: Record) {
    dev.repo().store_mut().put_if_version(record, None).unwrap();
    sync(server, dev).unwrap();
}

/// A legacy intro for `public` under `genesis`, signed with the account
/// signing key `dev` holds, the proof of possession by `keys`.
fn legacy_intro(
    dev: &mut Device,
    genesis: [u8; 32],
    keys: &DeviceKeys,
    public: &DevicePublic,
) -> Record {
    let account = dev.repo().account();
    let account_id = account.params.account_id;
    let body = LegacyIntroBody {
        account_id,
        genesis_hash: genesis,
        entry: entry_of(public, "Mac volé"),
        pop: sign_pop(keys, &account_id.0, public).unwrap(),
    };
    let signed = sign_legacy_intro(body, &account.keyset().signing).unwrap();
    Record {
        id: legacy_intro_id(&signed.body),
        kind: RecordKind::DeviceIntro,
        version: 0,
        data: signed.encode(),
    }
}

/// A and B of one legacy account (no trust state), both listed in the
/// device list (a 2b pairing lists the newcomer) and synced.
fn legacy_pair() -> (Server, Device, Device, SecretKey) {
    let mut server = Server::default();
    let (mut a, mut b, sk, _) = setup(&mut server, &[("alice", T0), ("bob", T0 + 1)]);
    sync(&mut server, &mut a).unwrap();
    b.repo()
        .register_this_device("Mac", DeviceKind::Mac, DeviceMode::Personal)
        .unwrap();
    sync(&mut server, &mut b).unwrap();
    sync(&mut server, &mut a).unwrap();
    (server, a, b, sk)
}

/// A and B both migrated (A wrote the genesis, B joined it), synced and
/// looked at again: each pins the other `Tofu`.
fn migrated_pair() -> (Server, Device, Device, SecretKey, Keys, Keys, [u8; 32]) {
    let (mut server, mut a, mut b, sk) = legacy_pair();
    let (ka, kb) = (Keys::new(), Keys::new());
    let Migration::Genesis(g) = migrate(&mut a, &ka) else {
        panic!("A writes the genesis");
    };
    sync(&mut server, &mut a).unwrap();
    sync(&mut server, &mut b).unwrap();
    assert_eq!(migrate(&mut b, &kb), Migration::Joined(g));
    sync(&mut server, &mut b).unwrap();
    sync(&mut server, &mut a).unwrap();
    refresh(&mut a);
    assert_self_pinned(&trust(&a));
    assert_self_pinned(&trust(&b));
    (server, a, b, sk, ka, kb, g)
}

// ---------------------------------------------------------------- genesis

#[test]
fn new_account_writes_genesis() {
    let mut dev = Device::empty();
    let keys = Keys::new();
    let store = SyncStore::open(&dev.path).unwrap();
    let (repo, sk) = Repository::create_account_v2(
        store,
        PASSWORD,
        kdf(),
        &keys.0,
        "iPhone de Camille",
        DeviceKind::Phone,
        DeviceMode::Personal,
    )
    .unwrap();
    dev.repo = Some(repo);
    let me = keys.public(&mut dev);
    assert_self_pinned(&trust(&dev));

    let lineage = dev.store().list(RecordKind::Lineage).unwrap();
    assert_eq!(lineage.len(), 1);
    let LineageRecord::Genesis(g) = LineageRecord::decode(&lineage[0].data).unwrap() else {
        panic!("a genesis");
    };
    verify_genesis(&g).unwrap();
    let account = dev.repo().account();
    assert_eq!(g.body.account_id, account.params.account_id);
    assert_eq!(g.body.identity_pub, account.params.identity_pub);
    assert_eq!(g.body.creator.device_id, me.device_id);
    assert_eq!(g.body.creator.sign_pub, me.sign_pub);
    assert_eq!(g.body.creator.name, "iPhone de Camille");
    assert_eq!(lineage[0].version, 0);
    assert_eq!(lineage[0].id, LineageRecord::Genesis(g.clone()).record_id());

    let t = trust(&dev);
    assert_eq!(t.head.generation, 0);
    assert_eq!(t.head.hash, LineageRecord::Genesis(g).hash());
    assert_eq!(t.me, me);
    assert_eq!(roster_ids(&t), BTreeSet::from([me.device_id]));
    assert_eq!(t.levels.get(&me.device_id), Some(&TrustLevel::Verified));
    assert_eq!(t.state, DeviceLineageState::Current);
    assert!(!t.rotate_now && !t.genesis_alert);
    // The device list names it; the session writes as usual.
    let listed = dev.repo().devices().unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].name, "iPhone de Camille");
    assert_eq!(migrate(&mut dev, &keys), Migration::Already);
    let v = dev.vault();
    dev.save(&login(v.id, "alice", T0));
    dev.lock();
    dev.unlock(&sk);
    assert_eq!(dev.items().len(), 1);
}

// ---------------------------------------------------------------- migration

#[test]
fn two_legacy_devices_migrate_in_both_orders() {
    for a_first in [true, false] {
        let (mut server, mut a, mut b, _sk) = legacy_pair();
        let (ka, kb) = (Keys::new(), Keys::new());
        let ((first, kf), (second, ks)) = if a_first {
            ((&mut a, &ka), (&mut b, &kb))
        } else {
            ((&mut b, &kb), (&mut a, &ka))
        };
        let Migration::Genesis(g) = migrate(first, kf) else {
            panic!("the first device writes the genesis");
        };
        sync(&mut server, first).unwrap();
        sync(&mut server, second).unwrap();
        assert_eq!(migrate(second, ks), Migration::Joined(g));
        sync(&mut server, second).unwrap();
        sync(&mut server, first).unwrap();
        refresh(first);

        let (ta, tb) = (trust(&a), trust(&b));
        assert_eq!(ta.head, tb.head, "same final head");
        assert_eq!(ta.head.hash, g);
        let (ia, ib) = (ka.public(&mut a), kb.public(&mut b));
        let both = BTreeSet::from([ia.device_id, ib.device_id]);
        assert_eq!(roster_ids(&ta), both);
        assert_eq!(roster_ids(&tb), both);
        assert_eq!(ta.levels.get(&ib.device_id), Some(&TrustLevel::Tofu));
        assert_eq!(tb.levels.get(&ia.device_id), Some(&TrustLevel::Tofu));
        assert_eq!(ta.levels.get(&ia.device_id), Some(&TrustLevel::Verified));
        assert_eq!(tb.levels.get(&ib.device_id), Some(&TrustLevel::Verified));
        // The keys pinned are the devices' own.
        let pinned = |t: &TrustState, p: &DevicePublic| {
            t.roster
                .iter()
                .any(|e| e.device_id == p.device_id && e.sign_pub == p.sign_pub)
        };
        assert!(pinned(&ta, &ib) && pinned(&tb, &ia));
        for t in [&ta, &tb] {
            assert!(t.excluded.is_empty());
            assert_eq!(t.state, DeviceLineageState::Current);
            assert!(!t.rotate_now && !t.genesis_alert);
        }
        // Carried item 5: migrated devices are not "pairing incomplete".
        assert_eq!(a.repo().pairing_incomplete().unwrap(), vec![]);
        assert_eq!(b.repo().pairing_incomplete().unwrap(), vec![]);
        // One genesis, one legacy intro on the server.
        let lineage = server
            .records
            .keys()
            .filter(|(k, _)| *k == RecordKind::Lineage)
            .count();
        assert_eq!(lineage, 1);
        // A second migration changes nothing.
        assert_eq!(migrate(&mut a, &ka), Migration::Already);
    }
}

#[test]
fn revoked_2b_device_legacy_intro_refused() {
    let (mut server, mut a, mut b, sk) = legacy_pair();
    let mut r = third(&mut server, &sk, "Vieux Mac");
    let r_id = r.repo().this_device_id().unwrap();
    sync(&mut server, &mut a).unwrap();
    a.repo().revoke_device(r_id).unwrap();
    sync(&mut server, &mut a).unwrap();
    sync(&mut server, &mut r).unwrap();
    let kr = Keys::new();
    let r_pub = kr.public(&mut r);

    // R, revoked, races to write a genesis of its own: never chosen.
    let account = r.repo().account();
    let genesis = LineageRecord::Genesis(
        sign_genesis(
            GenesisBody {
                format: LINEAGE_FORMAT,
                account_id: account.params.account_id,
                identity_pub: account.params.identity_pub.clone(),
                creator: entry_of(&r_pub, "Vieux Mac"),
                created_at: T0,
            },
            &kr.0,
            &account.keyset().identity,
        )
        .unwrap(),
    );
    let forged_genesis = genesis.hash();
    push_record(
        &mut server,
        &mut r,
        Record {
            id: genesis.record_id(),
            kind: RecordKind::Lineage,
            version: 0,
            data: genesis.encode(),
        },
    );
    // R's own migration is refused: the list revokes it.
    let refused = r.repo().migrate_to_v2(&kr.0);
    assert!(matches!(refused, Err(Error::Validation(_))), "{refused:?}");
    assert!(r.store().trust_state().unwrap().is_none());

    sync(&mut server, &mut a).unwrap();
    let ka = Keys::new();
    let Migration::Genesis(g) = migrate(&mut a, &ka) else {
        panic!("A writes its own genesis: R's creator is revoked");
    };
    assert_ne!(g, forged_genesis);
    sync(&mut server, &mut a).unwrap();
    // R's genesis is seen, never followed: an alert.
    let ta = trust(&a);
    assert_eq!(ta.head.hash, g);
    assert_eq!(ta.other_genesis, vec![forged_genesis]);
    assert!(ta.genesis_alert);
    // The 2b-revoked device is excluded on the migrated device.
    assert!(ta.excluded.contains(&r_id));

    // R forges a legacy intro under A's genesis.
    sync(&mut server, &mut r).unwrap();
    let intro = legacy_intro(&mut r, g, &kr.0, &r_pub);
    push_record(&mut server, &mut r, intro);

    sync(&mut server, &mut a).unwrap();
    refresh(&mut a);
    assert!(!roster_ids(&trust(&a)).contains(&r_id));
    sync(&mut server, &mut b).unwrap();
    let kb = Keys::new();
    assert_eq!(migrate(&mut b, &kb), Migration::Joined(g));
    let tb = trust(&b);
    assert!(!roster_ids(&tb).contains(&r_id));
    assert!(tb.excluded.contains(&r_id));
    assert!(!a.repo().pairing_incomplete().unwrap().contains(&r_id));
    // The devices screen shows R revoked (the list's revocation, R is
    // excluded here).
    let shown = a.repo().devices().unwrap();
    assert!(
        shown
            .iter()
            .find(|e| e.device_id == r_id)
            .unwrap()
            .revoked_at
            .is_some()
    );
}

#[test]
fn conflicting_keys_excluded() {
    let (mut server, mut a, mut b, sk, ka, kb, g) = migrated_pair();
    let b_pub = kb.public(&mut b);
    let b_id = b_pub.device_id;
    assert!(roster_ids(&trust(&a)).contains(&b_id));

    // A holder of the account keys claims B's id with another key.
    let other = DeviceKeys::generate_software().unwrap();
    let other_pub = other.public(b_id).unwrap();
    let forged = legacy_intro(&mut a, g, &other, &other_pub);
    push_record(&mut server, &mut a, forged);
    refresh(&mut a);
    let ta = trust(&a);
    assert!(!roster_ids(&ta).contains(&b_id), "B leaves A's roster");
    assert!(ta.excluded.contains(&b_id));
    assert!(ta.conflicted.contains(&b_id));

    // A legacy device migrating now sees both claims: excluded at once.
    let mut c = third(&mut server, &sk, "iPad");
    let kc = Keys::new();
    assert_eq!(migrate(&mut c, &kc), Migration::Joined(g));
    let tc = trust(&c);
    assert!(!roster_ids(&tc).contains(&b_id));
    assert!(tc.excluded.contains(&b_id) && tc.conflicted.contains(&b_id));
    // B keeps its own entry.
    sync(&mut server, &mut b).unwrap();
    refresh(&mut b);
    assert!(roster_ids(&trust(&b)).contains(&b_id));

    // A verification with B's real key lifts the exclusion on A.
    let transcript = [5u8; 32];
    let pop = sign_pop(&kb.0, &transcript, &b_pub).unwrap();
    a.repo().verify_device(&b_pub, &transcript, &pop).unwrap();
    let ta = trust(&a);
    assert!(roster_ids(&ta).contains(&b_id));
    assert!(!ta.excluded.contains(&b_id) && !ta.conflicted.contains(&b_id));
    assert_eq!(ta.levels.get(&b_id), Some(&TrustLevel::Verified));
    let _ = ka;
}

/// A and B listed, then both migrate offline, each before seeing the
/// other's genesis; then both sync. Returns (ga, gb).
fn diverged() -> (
    Server,
    Device,
    Device,
    SecretKey,
    Keys,
    Keys,
    [u8; 32],
    [u8; 32],
) {
    let (server, mut a, mut b, sk) = legacy_pair();
    let (ka, kb) = (Keys::new(), Keys::new());
    let Migration::Genesis(ga) = migrate(&mut a, &ka) else {
        panic!("genesis");
    };
    let Migration::Genesis(gb) = migrate(&mut b, &kb) else {
        panic!("genesis");
    };
    (server, a, b, sk, ka, kb, ga, gb)
}

/// Review I3: two offline migrations converge on one deterministic winner
/// (the smallest valid genesis hash, creator listed and uncontested) at
/// the next unlock-time `migrate_to_v2`, with no user step while no
/// rotation exists and no `Verified` peer; the alert stays.
#[test]
fn second_genesis_alerts_and_converges() {
    let (mut server, mut a, mut b, sk, ka, kb, ga, gb) = diverged();
    sync(&mut server, &mut a).unwrap();
    sync(&mut server, &mut b).unwrap();
    sync(&mut server, &mut a).unwrap();
    refresh(&mut a);
    refresh(&mut b);
    // Seen: the alert, on both sides.
    assert!(trust(&a).genesis_alert && trust(&b).genesis_alert);
    assert_eq!(trust(&a).other_genesis, vec![gb]);

    // The unlock-time call moves the loser to the winner.
    let win = ga.min(gb);
    let (ma, mb) = (migrate(&mut a, &ka), migrate(&mut b, &kb));
    let moved = if win == ga { mb } else { ma };
    assert_eq!(moved, Migration::Joined(win));
    sync(&mut server, &mut a).unwrap();
    sync(&mut server, &mut b).unwrap();
    sync(&mut server, &mut a).unwrap();
    refresh(&mut a);
    refresh(&mut b);
    let (ta, tb) = (trust(&a), trust(&b));
    assert_eq!(ta.head.hash, win);
    assert_eq!(tb.head.hash, win);
    let both = BTreeSet::from([ka.public(&mut a).device_id, kb.public(&mut b).device_id]);
    assert_eq!(roster_ids(&ta), both);
    assert_eq!(roster_ids(&tb), both);
    assert_self_pinned(&ta);
    assert_self_pinned(&tb);
    assert!(ta.genesis_alert && tb.genesis_alert);
    assert_eq!(migrate(&mut a, &ka), Migration::Already);
    assert_eq!(migrate(&mut b, &kb), Migration::Already);

    // Seen: cleared, and it stays cleared.
    a.repo().clear_genesis_alert().unwrap();
    refresh(&mut a);
    assert!(!trust(&a).genesis_alert);
    a.lock();
    a.unlock(&sk);
    assert!(!a.repo().migration_alerts().unwrap().other_genesis);
    assert_eq!(trust(&a).head.hash, win);
}

/// Review I3: once a rotation exists, no automatic switch: the alert,
/// then a re-pair from a device of the other lineage works as an A9
/// follow (local items kept, own writes replayed under the new keys).
#[test]
fn diverged_after_a_rotation_alerts_then_repairs() {
    use onepass_core::pairing::{FullGrant, FullGrantV2, snapshot_from_store};
    use onepass_core::repo::pairing::repair_from_grant;

    let (mut server, mut a, mut b, sk, ka, kb, _ga, gb) = diverged();
    // A pushes its genesis and rotates before B's genesis arrives.
    sync(&mut server, &mut a).unwrap();
    let (head, new_sk) = rotate_a(&mut server, &mut a, &ka, &sk, &[]);
    // B writes offline on its own genesis, then fetches (its push would
    // fail: the server's vaults are sealed under A's new identity).
    let v = b.vault();
    let offline = login(v.id, "offline", T0 + 50);
    b.save(&offline);
    pull(&server, &mut b);
    refresh(&mut b);
    assert_eq!(
        migrate(&mut b, &kb),
        Migration::Already,
        "no automatic switch"
    );
    let tb = trust(&b);
    assert_eq!(tb.head.hash, gb);
    assert!(tb.genesis_alert);
    // Fix round 2: a valid rotation chained to the winning genesis leaves
    // B on a lost lineage: `Orphaned`, no more writes piling up (G4), and
    // the alert stays until B re-pairs.
    assert!(matches!(tb.state, DeviceLineageState::Orphaned { .. }));
    let late = login(v.id, "late", T0 + 60);
    assert_eq!(b.repo().save_item(&v, late), Err(Error::ReadOnly));
    assert!(b.repo().clear_genesis_alert().is_err());
    assert!(trust(&b).genesis_alert);
    assert!(
        b.items().iter().any(|i| i.id == offline.id),
        "still readable"
    );

    // B re-pairs from A (the grant as the SAS session carries it).
    let b_id = kb.public(&mut b).device_id;
    let grant = {
        let repo = a.repo();
        FullGrantV2 {
            full: FullGrant {
                account_id: repo.account().params.account_id,
                secret_key: zeroize::Zeroizing::new(new_sk.to_display()),
                mode: DeviceMode::Personal,
                device_id: b_id,
                snapshot: snapshot_from_store(repo.store()).unwrap(),
            },
            trust: repo.trust_snapshot().unwrap(),
            sync: None,
            enroll: None,
        }
    };
    let session = b.repo.take().unwrap();
    let (repo, _auk, got) = repair_from_grant(session, &grant, PASSWORD, &kb.0).unwrap();
    assert_eq!(got.to_display(), new_sk.to_display());
    b.repo = Some(repo);
    assert_self_pinned(&trust(&b));
    assert_eq!(trust(&b).head.hash, head);
    assert!(b.items().iter().any(|i| i.id == offline.id));
    sync(&mut server, &mut b).unwrap();
    sync(&mut server, &mut a).unwrap();
    assert!(a.items().iter().any(|i| i.id == offline.id));
    // Back on A's lineage: writable, and the alert can be cleared.
    assert_eq!(trust(&b).state, DeviceLineageState::Current);
    let v = b.vault();
    b.save(&login(v.id, "after", T0 + 70));
    b.repo().clear_genesis_alert().unwrap();
}

/// A rotation record that decodes but verifies under nothing.
fn junk_rotation(account_id: Id) -> Record {
    use onepass_core::crypto::IdentityKey;
    use onepass_core::lineage::{RotationBody, sign_rotation};
    let keys = DeviceKeys::generate_software().unwrap();
    let p = keys.public(Id::new()).unwrap();
    let identity = IdentityKey::generate().unwrap();
    let body = RotationBody {
        format: LINEAGE_FORMAT,
        account_id,
        generation: 1,
        parent: [0x42; 32],
        rotator: p.device_id,
        reason: RotationReason::Rotate,
        revoked: vec![],
        roster: vec![entry_of(&p, "junk")],
        identity_pub: identity.verifying_key(),
        params_hash: [0; 32],
        keyset_hash: [0; 32],
        deliveries: vec![],
        from_heads: BTreeMap::new(),
        issued_at: T0,
    };
    let r = LineageRecord::Rotation(sign_rotation(body, &keys, &identity).unwrap());
    Record {
        id: r.record_id(),
        kind: RecordKind::Lineage,
        version: 1,
        data: r.encode(),
    }
}

#[test]
fn rotate_now_prompt_once() {
    let (mut server, mut a, mut b, sk) = legacy_pair();
    let mut r = third(&mut server, &sk, "Vieux Mac");
    let r_id = r.repo().this_device_id().unwrap();
    sync(&mut server, &mut a).unwrap();
    a.repo().revoke_device(r_id).unwrap();
    sync(&mut server, &mut a).unwrap();
    // Review I1: a decodable record nobody signed does not hide the prompt.
    let account_id = r.repo().account().params.account_id;
    push_record(&mut server, &mut r, junk_rotation(account_id));
    sync(&mut server, &mut a).unwrap();

    let ka = Keys::new();
    migrate(&mut a, &ka);
    assert!(trust(&a).rotate_now);
    assert!(a.repo().migration_alerts().unwrap().rotate_now);
    a.repo().clear_rotate_now_prompt().unwrap();
    assert!(!a.repo().migration_alerts().unwrap().rotate_now);
    sync(&mut server, &mut a).unwrap();
    refresh(&mut a);
    a.lock();
    a.unlock(&sk);
    assert!(!a.repo().migration_alerts().unwrap().rotate_now);
    assert!(!trust(&a).rotate_now);

    // Each device shows it once: B migrates with the flag set.
    sync(&mut server, &mut b).unwrap();
    let kb = Keys::new();
    migrate(&mut b, &kb);
    assert!(trust(&b).rotate_now);
}

/// Review I2: a holder of the account keys (here a legacy device's
/// session, as a 2b-revoked one could sign the same) lists a fresh id and
/// posts its legacy intro before the first rotation: it is a `Tofu` roster
/// entry, but the rotation the user runs keeps only the `Tofu` devices the
/// user confirmed: no delivery for it. An id listed after this device
/// migrated never joins.
#[test]
fn unconfirmed_tofu_devices_get_no_delivery() {
    use onepass_core::devices::DeviceEntry;
    use onepass_core::lineage::RotationBody;

    let (mut server, mut a, mut b, sk) = legacy_pair();
    let mut c = third(&mut server, &sk, "iPad");
    let x = DeviceKeys::generate_software().unwrap();
    let x_pub = x.public(Id::new()).unwrap();
    let entry = |id: Id| DeviceEntry {
        device_id: id,
        name: "Mac caché".into(),
        kind: DeviceKind::Mac,
        mode: DeviceMode::Personal,
        added_at: T0,
        added_by: None,
        revoked_at: None,
    };
    c.repo().add_device(entry(x_pub.device_id)).unwrap();
    sync(&mut server, &mut c).unwrap();
    sync(&mut server, &mut a).unwrap();
    let ka = Keys::new();
    let Migration::Genesis(g) = migrate(&mut a, &ka) else {
        panic!("genesis");
    };
    sync(&mut server, &mut a).unwrap();
    sync(&mut server, &mut b).unwrap();
    let kb = Keys::new();
    migrate(&mut b, &kb);
    sync(&mut server, &mut b).unwrap();

    // X's intro under A's genesis, and a fresh Y listed after A migrated.
    sync(&mut server, &mut c).unwrap();
    let intro = legacy_intro(&mut c, g, &x, &x_pub);
    push_record(&mut server, &mut c, intro);
    let y = DeviceKeys::generate_software().unwrap();
    let y_pub = y.public(Id::new()).unwrap();
    c.repo().add_device(entry(y_pub.device_id)).unwrap();
    let intro = legacy_intro(&mut c, g, &y, &y_pub);
    push_record(&mut server, &mut c, intro);
    sync(&mut server, &mut a).unwrap();
    refresh(&mut a);
    let ta = trust(&a);
    let b_id = kb.public(&mut b).device_id;
    assert!(
        roster_ids(&ta).contains(&x_pub.device_id),
        "inside the TOFU window"
    );
    assert!(
        !roster_ids(&ta).contains(&y_pub.device_id),
        "listed after migration"
    );
    assert!(roster_ids(&ta).contains(&b_id));
    // Concern 5: C never migrated: the rotation screen names it.
    let c_id = c.repo().this_device_id().unwrap();
    // Review m1: Y, listed after A migrated and never introduced, too.
    let mut expected = vec![c_id, y_pub.device_id];
    expected.sort();
    assert_eq!(a.repo().unmigrated_devices().unwrap(), expected);

    // A keep of a device that is not `Tofu` in the roster is refused.
    let new_sk = SecretKey::generate().unwrap();
    let r = a.repo().rotate(RotateRequest {
        revoke: vec![],
        new_password: None,
        password: PASSWORD,
        secret_key: &sk,
        new_secret_key: &new_sk,
        device_keys: &ka.0,
        reason: RotationReason::Rotate,
        keep_tofu: &[y_pub.device_id],
    });
    assert!(matches!(r, Err(Error::Validation(_))), "{r:?}");

    // The user confirms B only.
    let (head, _) = rotate_a(&mut server, &mut a, &ka, &sk, &[b_id]);
    let rec = a
        .store()
        .list(RecordKind::Lineage)
        .unwrap()
        .into_iter()
        .filter_map(|r| LineageRecord::decode(&r.data).ok())
        .find(|r| r.hash() == head)
        .unwrap();
    let LineageRecord::Rotation(rot) = rec else {
        panic!("a rotation");
    };
    let body: RotationBody = rot.body;
    let delivered: BTreeSet<Id> = body.deliveries.iter().map(|(id, _)| *id).collect();
    assert_eq!(delivered, BTreeSet::from([b_id]));
    assert!(!body.roster.iter().any(|e| e.device_id == x_pub.device_id));
}

/// Review M1: a 2b revocation written after this device migrated (by a
/// device not updated yet) drops a `Tofu` device and asks for the rotation.
#[test]
fn late_2b_revocation_drops_a_tofu_device() {
    let (mut server, mut a, mut b, sk, _ka, kb, _g) = migrated_pair();
    let b_id = kb.public(&mut b).device_id;
    assert!(!trust(&a).rotate_now);
    let mut old = third(&mut server, &sk, "Vieux iPad");
    old.repo().revoke_device(b_id).unwrap();
    sync(&mut server, &mut old).unwrap();
    sync(&mut server, &mut a).unwrap();
    refresh(&mut a);
    let ta = trust(&a);
    assert!(!roster_ids(&ta).contains(&b_id));
    assert!(ta.excluded.contains(&b_id));
    assert!(a.repo().migration_alerts().unwrap().rotate_now);
}

#[test]
fn verify_ceremony_upgrades_to_verified() {
    let (_server, mut a, mut b, _sk, ka, kb, _g) = migrated_pair();
    let (a_pub, b_pub) = (ka.public(&mut a), kb.public(&mut b));
    let transcript = [7u8; 32];

    // Refused: a proof of possession by another key, another key for B.
    let bad = sign_pop(&ka.0, &transcript, &b_pub).unwrap();
    assert_eq!(
        a.repo().verify_device(&b_pub, &transcript, &bad),
        Err(Error::Integrity(IntegrityError::Signature))
    );
    let other = DeviceKeys::generate_software().unwrap();
    let other_pub = other.public(b_pub.device_id).unwrap();
    let pop = sign_pop(&other, &transcript, &other_pub).unwrap();
    assert_eq!(
        a.repo().verify_device(&other_pub, &transcript, &pop),
        Err(Error::Integrity(IntegrityError::WrongContext))
    );
    assert_eq!(
        trust(&a).levels.get(&b_pub.device_id),
        Some(&TrustLevel::Tofu)
    );

    // Both sides of the SAS session.
    let pop_b = sign_pop(&kb.0, &transcript, &b_pub).unwrap();
    a.repo().verify_device(&b_pub, &transcript, &pop_b).unwrap();
    let pop_a = sign_pop(&ka.0, &transcript, &a_pub).unwrap();
    b.repo().verify_device(&a_pub, &transcript, &pop_a).unwrap();
    assert_eq!(
        trust(&a).levels.get(&b_pub.device_id),
        Some(&TrustLevel::Verified)
    );
    assert_eq!(
        trust(&b).levels.get(&a_pub.device_id),
        Some(&TrustLevel::Verified)
    );
}

// ---------------------------------------------------------------- rotations

fn rotate_a(
    server: &mut Server,
    a: &mut Device,
    ka: &Keys,
    sk: &SecretKey,
    keep_tofu: &[Id],
) -> ([u8; 32], SecretKey) {
    let new_sk = SecretKey::generate().unwrap();
    let out = a
        .repo()
        .rotate(RotateRequest {
            revoke: vec![],
            new_password: None,
            password: PASSWORD,
            secret_key: sk,
            new_secret_key: &new_sk,
            device_keys: &ka.0,
            reason: RotationReason::Rotate,
            keep_tofu,
        })
        .unwrap();
    sync(server, a).unwrap();
    assert_eq!(trust(a).state, DeviceLineageState::Current);
    (out.head, new_sk)
}

/// Task 8 (blocking, carried to Task 14): a legacy device that fetches a
/// rotation before its first unlock after the update still unlocks,
/// migrates and reads its data; the rotation does not list it, so it is
/// `Orphaned` (re-pair to come back), never locked out.
#[test]
fn legacy_device_seeing_rotation_before_migrating_is_not_locked_out() {
    let (mut server, mut a, mut b, sk) = legacy_pair();
    let before = users(&b.items());
    b.lock();
    let ka = Keys::new();
    migrate(&mut a, &ka);
    sync(&mut server, &mut a).unwrap();
    rotate_a(&mut server, &mut a, &ka, &sk, &[]);

    // B fetches everything while locked, then unlocks with its keys.
    pull(&server, &mut b);
    b.try_unlock(PASSWORD, &sk).unwrap();
    let kb = Keys::new();
    assert!(matches!(migrate(&mut b, &kb), Migration::Joined(_)));
    assert!(matches!(
        trust(&b).state,
        DeviceLineageState::Orphaned { .. }
    ));
    assert_eq!(users(&b.items()), before);
    let v = b.vault();
    let r = b.repo().save_item(&v, login(v.id, "eve", T0 + 9));
    assert_eq!(r, Err(Error::ReadOnly));
}

/// A migrated legacy device follows a rotation by a `Tofu` device, with
/// the warning of O7.
#[test]
fn migrated_legacy_device_follows_a_rotation() {
    let (mut server, mut a, mut b, sk, ka, kb, _g) = migrated_pair();
    let b_id = kb.public(&mut b).device_id;
    b.lock();
    let (head, new_sk) = rotate_a(&mut server, &mut a, &ka, &sk, &[b_id]);
    pull(&server, &mut b);
    let prompt = pending_rotation(&b.store()).unwrap().expect("a prompt");
    assert!(prompt.tofu_signer);
    assert_eq!(prompt.choices[0].hash, head);
    let (repo, _auk, got) = follow_rotation(b.store(), head, PASSWORD, &kb.0).unwrap();
    assert_eq!(got.to_display(), new_sk.to_display());
    b.repo = Some(repo);
    assert_eq!(trust(&b).head.hash, head);
    assert_eq!(users(&b.items()), users(&a.items()));
}

/// Task 15 review concern 1: every trust-state constructor except a kit
/// restore leaves the device in its own roster with its own keys (the
/// pin every capability check reads, `repo::kit::check_pinned`).
fn assert_self_pinned(t: &onepass_core::trust::TrustState) {
    assert!(
        t.roster.iter().any(|e| e.device_id == t.me.device_id
            && e.sign_pub == t.me.sign_pub
            && e.kem_pub == t.me.kem_pub),
        "the device is pinned in its own roster"
    );
}
