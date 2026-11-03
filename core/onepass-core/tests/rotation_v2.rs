//! Key rotation v2 on the rotating device (spec 7.1): preconditions that
//! refuse with nothing written, the signed rotation record, the roster and
//! the deliveries, the vault pass, and the single local transaction.
//!
//! Devices come from the two-device harness of `common` (SyncStore files);
//! their device keys and the trust state are seeded here, since the genesis
//! at account creation is a later task.

mod common;

use std::cell::Cell;
use std::collections::BTreeSet;

use common::*;
use onepass_core::chain::ChainState;
use onepass_core::device_keys::{DeviceKeys, DevicePublic};
use onepass_core::devices::{DeviceKind, DeviceMode};
use onepass_core::epoch::{EpochReason, RestoreEpoch, SignedRestoreEpoch};
use onepass_core::lineage::{
    GenesisBody, LINEAGE_FORMAT, LineageRecord, RosterEntry, RotationReason, delivery_id,
    identity_id, rotation_code, sign_genesis, verify_rotation,
};
use onepass_core::lists::{ListBody, VAULT_LIST_DOMAIN, sign};
use onepass_core::manifest::{SeenManifest, SignedManifest, verify_manifest};
use onepass_core::repo::rotate::open_key_delivery;
use onepass_core::repo::travel::TravelState;
use onepass_core::repo::{RotateRequest, RotationOutcome};
use onepass_core::share::ShareState;
use onepass_core::store::{ErasedNotice, RotationPush, VaultEvent, Zone, account_record_id};
use onepass_core::sync::PhaseOutcome;
use onepass_core::trust::{DeviceLineageState, LineageHead, TrustLevel, TrustState};
use onepass_core::vaultlist::VaultListEntry;

const NEW_PASSWORD: &str = "Projet Zénith, Camille Durand";

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
    /// The rotator, A.
    me: Peer,
    /// The other devices of the roster: B, C, D.
    others: Vec<Peer>,
    items: Vec<Item>,
}

/// A with three items (one archived, one trashed), synced with B; A pins a
/// genesis whose roster is A, B, C and D, all verified, state `Current`.
fn fixture() -> (Device, Fixture) {
    fixture_on(&mut Server::default())
}

/// `fixture` on `server`; the genesis is pushed, so the outbox is empty.
fn fixture_on(server: &mut Server) -> (Device, Fixture) {
    let (mut a, _b, sk, items) =
        setup(server, &[("alice", T0), ("bob", T0 + 1), ("carol", T0 + 2)]);
    let v = a.vault();
    a.repo().archive_item(&v, items[1].id).unwrap();
    a.repo().trash_item(&v, items[2].id).unwrap();
    sync(server, &mut a).unwrap();

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
    (
        a,
        Fixture {
            sk,
            me,
            others,
            items,
        },
    )
}

fn request<'a>(
    f: &'a Fixture,
    new_sk: &'a SecretKey,
    revoke: Vec<Id>,
    reason: RotationReason,
) -> RotateRequest<'a> {
    RotateRequest {
        revoke,
        new_password: None,
        password: PASSWORD,
        secret_key: &f.sk,
        new_secret_key: new_sk,
        device_keys: &f.me.keys,
        reason,
        keep_tofu: &[],
    }
}

/// Everything the device file holds that a rotation could change: every
/// record, the trust state, the chain state and the outbox.
#[derive(Debug, PartialEq)]
struct Snapshot {
    records: Vec<Record>,
    trust: Option<Vec<u8>>,
    chain: Vec<u8>,
    outbox: Vec<(RecordKind, Id, u64, Option<Vec<u8>>)>,
}

const KINDS: [RecordKind; 12] = [
    RecordKind::AccountParams,
    RecordKind::Keyset,
    RecordKind::VaultKey,
    RecordKind::VaultMeta,
    RecordKind::Item,
    RecordKind::Manifest,
    RecordKind::RestoreEpoch,
    RecordKind::DeviceList,
    RecordKind::VaultList,
    RecordKind::Lineage,
    RecordKind::DeviceIntro,
    RecordKind::KeyDelivery,
];

fn snapshot(store: &SyncStore) -> Snapshot {
    let mut records = Vec::new();
    for kind in KINDS {
        let mut rs = store.list(kind).unwrap();
        rs.sort_by_key(|r| r.id);
        records.extend(rs);
    }
    Snapshot {
        records,
        trust: store.trust_state().unwrap().map(|t| t.encode()),
        chain: RecordStore::chain_state(store).unwrap().encode(),
        outbox: store
            .pending_changes()
            .unwrap()
            .into_iter()
            .map(|c| (c.kind, c.id, c.version, c.data))
            .collect(),
    }
}

fn is_validation<T: std::fmt::Debug>(r: &Result<T>) -> bool {
    matches!(r, Err(Error::Validation(_)))
}

fn sha256(b: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, b).as_ref());
    out
}

/// The rotation record of `head`, from the store.
fn rotation_of(store: &SyncStore, head: &[u8; 32]) -> onepass_core::lineage::RotationBody {
    let mut id = [0u8; 16];
    id.copy_from_slice(&head[..16]);
    let rec = store
        .get(RecordKind::Lineage, Id(id))
        .unwrap()
        .expect("lineage record");
    match LineageRecord::decode(&rec.data).unwrap() {
        LineageRecord::Rotation(r) => r.body,
        LineageRecord::Genesis(_) => panic!("a genesis"),
    }
}

// ---------------------------------------------------------------- refusals

#[test]
fn rotate_refused_in_travel_mode() {
    let (mut a, f) = fixture();
    let v = a.vault();
    let seen = a.repo().device_state().last_seen[&v.id].clone();
    a.repo().resume_travel(&TravelState {
        parked: BTreeMap::from([(v.id, seen)]),
        entered_at: T0,
        parked_items: Default::default(),
    });
    let before = snapshot(&a.store());
    let new_sk = SecretKey::generate().unwrap();
    let req = request(&f, &new_sk, vec![], RotationReason::Rotate);
    let r = a.repo.as_mut().unwrap().rotate(req);
    assert!(is_validation(&r), "{r:?}");
    assert_eq!(snapshot(&a.store()), before);
}

/// Guard-only travel parks nothing and still counts as travelling.
#[test]
fn rotate_refused_in_travel_mode_with_nothing_parked() {
    let (mut a, f) = fixture();
    a.repo().resume_travel(&TravelState {
        parked: BTreeMap::new(),
        entered_at: T0,
        parked_items: Default::default(),
    });
    assert!(a.repo().travelling());
    let before = snapshot(&a.store());
    let new_sk = SecretKey::generate().unwrap();
    let req = request(&f, &new_sk, vec![], RotationReason::Rotate);
    let r = a.repo.as_mut().unwrap().rotate(req);
    assert!(is_validation(&r), "{r:?}");
    assert_eq!(snapshot(&a.store()), before);
}

#[test]
fn rotate_refused_when_vault_missing() {
    let (mut a, f) = fixture();
    let work = a.repo().create_vault(meta("Travail")).unwrap();
    a.repo()
        .store_mut()
        .delete(RecordKind::VaultKey, work.id)
        .unwrap();
    let before = snapshot(&a.store());
    let new_sk = SecretKey::generate().unwrap();
    let req = request(&f, &new_sk, vec![], RotationReason::Rotate);
    let r = a.repo.as_mut().unwrap().rotate(req);
    assert_eq!(integrity(r), IntegrityError::VaultMissing);
    assert_eq!(snapshot(&a.store()), before);
}

#[test]
fn revoking_self_refused() {
    let (mut a, f) = fixture();
    let before = snapshot(&a.store());
    let new_sk = SecretKey::generate().unwrap();
    let req = request(&f, &new_sk, vec![f.me.id()], RotationReason::Revoke);
    let r = a.repo.as_mut().unwrap().rotate(req);
    assert!(is_validation(&r), "{r:?}");
    assert_eq!(snapshot(&a.store()), before);
}

#[test]
fn revoking_unknown_device_refused() {
    let (mut a, f) = fixture();
    let before = snapshot(&a.store());
    let new_sk = SecretKey::generate().unwrap();
    let req = request(&f, &new_sk, vec![Id::new()], RotationReason::Revoke);
    let r = a.repo.as_mut().unwrap().rotate(req);
    assert!(is_validation(&r), "{r:?}");
    assert_eq!(snapshot(&a.store()), before);
}

#[test]
fn same_secret_key_refused() {
    let (mut a, f) = fixture();
    let before = snapshot(&a.store());
    let same = SecretKey::parse(&f.sk.to_display()).unwrap();
    let req = request(&f, &same, vec![], RotationReason::Rotate);
    let r = a.repo.as_mut().unwrap().rotate(req);
    assert!(is_validation(&r), "{r:?}");
    assert_eq!(snapshot(&a.store()), before);
}

#[test]
fn rotate_refused_with_other_device_keys() {
    let (mut a, f) = fixture();
    let before = snapshot(&a.store());
    let new_sk = SecretKey::generate().unwrap();
    let mut req = request(&f, &new_sk, vec![], RotationReason::Rotate);
    req.device_keys = &f.others[0].keys;
    let r = a.repo.as_mut().unwrap().rotate(req);
    assert!(is_validation(&r), "{r:?}");
    assert_eq!(snapshot(&a.store()), before);
}

#[test]
fn rotate_refused_unless_current() {
    let (mut a, f) = fixture();
    let mut trust = a.store().trust_state().unwrap().unwrap();
    trust.state = DeviceLineageState::Candidate {
        children: vec![[1; 32]],
        resume: None,
    };
    a.repo()
        .store_mut()
        .put_all_if_version_with_trust(vec![], vec![], None, &trust)
        .unwrap();
    let before = snapshot(&a.store());
    let new_sk = SecretKey::generate().unwrap();
    let req = request(&f, &new_sk, vec![], RotationReason::Rotate);
    let r = a.repo.as_mut().unwrap().rotate(req);
    assert!(is_validation(&r), "{r:?}");
    assert_eq!(snapshot(&a.store()), before);
}

/// Controller ruling (Task 6): a session opened with the Account Unlock
/// Key alone does not know the current Secret Key; `rotate` establishes it
/// from the request, so the right key rotates and a wrong one is refused.
#[test]
fn auk_session_rotates_only_with_the_right_secret_key() {
    let (mut a, f) = fixture();
    let auk = a.try_unlock(PASSWORD, &f.sk).unwrap();
    a.try_unlock_with_auk(&auk).unwrap();

    let before = snapshot(&a.store());
    let wrong = SecretKey::generate().unwrap();
    let new_sk = SecretKey::generate().unwrap();
    let mut req = request(&f, &new_sk, vec![], RotationReason::Rotate);
    req.secret_key = &wrong;
    let r = a.repo.as_mut().unwrap().rotate(req);
    assert!(matches!(r, Err(Error::WrongPassword)), "{r:?}");
    assert_eq!(snapshot(&a.store()), before);

    let req = request(&f, &new_sk, vec![], RotationReason::Rotate);
    let out = a.repo.as_mut().unwrap().rotate(req).unwrap();
    let trust = a.store().trust_state().unwrap().unwrap();
    assert_eq!(trust.head.hash, out.head);
}

// ---------------------------------------------------------------- atomicity

/// A store over the device file that fails the trust commit, or breaks
/// every call made after it.
struct Faulty {
    inner: SyncStore,
    fail_commit: bool,
    broken: Cell<bool>,
    /// A trust state another writer saves right before this store's next
    /// conditional trust commit (a lost race).
    race: Option<TrustState>,
}

impl Faulty {
    fn ok(&self) -> Result<()> {
        if self.broken.get() {
            Err(Error::Store("network down".into()))
        } else {
            Ok(())
        }
    }

    fn race(&mut self) -> Result<()> {
        if let Some(t) = self.race.take() {
            self.inner
                .put_all_if_version_with_trust(vec![], vec![], None, &t)?;
        }
        Ok(())
    }
}

impl RecordStore for Faulty {
    fn put(&mut self, r: Record) -> Result<()> {
        self.ok()?;
        self.inner.put(r)
    }
    fn put_if_version(&mut self, r: Record, expected: Option<u64>) -> Result<()> {
        self.ok()?;
        self.inner.put_if_version(r, expected)
    }
    fn get(&self, kind: RecordKind, id: Id) -> Result<Option<Record>> {
        self.ok()?;
        self.inner.get(kind, id)
    }
    fn list(&self, kind: RecordKind) -> Result<Vec<Record>> {
        self.ok()?;
        self.inner.list(kind)
    }
    fn delete(&mut self, kind: RecordKind, id: Id) -> Result<()> {
        self.ok()?;
        self.inner.delete(kind, id)
    }
    fn evict(&mut self, kind: RecordKind, id: Id) -> Result<()> {
        self.ok()?;
        self.inner.evict(kind, id)
    }
    fn evict_all(&mut self, records: &[Record]) -> Result<()> {
        self.ok()?;
        self.inner.evict_all(records)
    }
    fn restore_epoch_mark(&self) -> Result<Option<(u64, [u8; 32])>> {
        self.ok()?;
        self.inner.restore_epoch_mark()
    }
    fn set_restore_epoch_mark(&mut self, epoch: u64, hash: [u8; 32]) -> Result<()> {
        self.ok()?;
        self.inner.set_restore_epoch_mark(epoch, hash)
    }
    fn kept_rows(&self, vault: Id) -> Result<Option<Vec<Record>>> {
        self.ok()?;
        self.inner.kept_rows(vault)
    }
    fn keep_local_copy(
        &mut self,
        vault: Id,
        manifest: &Record,
        restore: &[Record],
        unlisted: &[Id],
        write: bool,
    ) -> Result<()> {
        self.ok()?;
        self.inner
            .keep_local_copy(vault, manifest, restore, unlisted, write)
    }
    fn vault_event(&mut self, vault: Id, event: VaultEvent) -> Result<()> {
        self.ok()?;
        self.inner.vault_event(vault, event)
    }
    fn put_all_if_version(&mut self, writes: Vec<(Record, Option<u64>)>) -> Result<()> {
        self.ok()?;
        self.inner.put_all_if_version(writes)
    }
    fn put_all_if_version_and_delete(
        &mut self,
        writes: Vec<(Record, Option<u64>)>,
        deletes: Vec<(RecordKind, Id)>,
    ) -> Result<()> {
        self.ok()?;
        self.inner.put_all_if_version_and_delete(writes, deletes)
    }
    fn chain_state(&self) -> Result<ChainState> {
        self.ok()?;
        RecordStore::chain_state(&self.inner)
    }
    fn persists_chain(&self) -> bool {
        self.inner.persists_chain()
    }
    fn put_all_if_version_with_chain(
        &mut self,
        writes: Vec<(Record, Option<u64>)>,
        chain: &ChainState,
    ) -> Result<()> {
        self.ok()?;
        self.inner.put_all_if_version_with_chain(writes, chain)
    }
    fn trust_state(&self) -> Result<Option<TrustState>> {
        self.ok()?;
        self.inner.trust_state()
    }
    fn put_all_if_version_with_trust(
        &mut self,
        writes: Vec<(Record, Option<u64>)>,
        deletes: Vec<(RecordKind, Id)>,
        chain: Option<ChainState>,
        trust: &TrustState,
    ) -> Result<()> {
        self.ok()?;
        if self.fail_commit {
            return Err(Error::Store("disk full".into()));
        }
        self.inner
            .put_all_if_version_with_trust(writes, deletes, chain, trust)?;
        // Every call after the commit fails, like a sync that lost the
        // network.
        self.broken.set(true);
        Ok(())
    }
    fn put_with_trust_cas(
        &mut self,
        writes: Vec<(Record, Option<u64>)>,
        deletes: Vec<(RecordKind, Id)>,
        chain: Option<ChainState>,
        expected: &TrustState,
        trust: &TrustState,
    ) -> Result<()> {
        self.ok()?;
        if self.fail_commit {
            return Err(Error::Store("disk full".into()));
        }
        self.race()?;
        self.inner
            .put_with_trust_cas(writes, deletes, chain, expected, trust)?;
        self.broken.set(true);
        Ok(())
    }
    fn put_rotation(
        &mut self,
        writes: Vec<(Record, Option<u64>)>,
        chain: ChainState,
        expected: &TrustState,
        trust: &TrustState,
        rotation: &RotationPush,
        zoned: Vec<(Zone, Record, Option<u64>)>,
        shares: &[ShareState],
    ) -> Result<()> {
        self.ok()?;
        if self.fail_commit {
            return Err(Error::Store("disk full".into()));
        }
        self.race()?;
        self.inner
            .put_rotation(writes, chain, expected, trust, rotation, zoned, shares)?;
        self.broken.set(true);
        Ok(())
    }
    fn is_pending_write(&self, kind: RecordKind, id: Id) -> Result<bool> {
        self.ok()?;
        self.inner.is_pending_write(kind, id)
    }
}

fn faulty_session(a: &Device, f: &Fixture, fail_commit: bool) -> Repository<Faulty> {
    let inner = a.store();
    let state = inner.device_state().unwrap();
    let store = Faulty {
        inner,
        fail_commit,
        broken: Cell::new(false),
        race: None,
    };
    Repository::unlock(store, PASSWORD, &f.sk, state).unwrap()
}

#[test]
fn rotate_writes_one_transaction() {
    let (a, f) = fixture();
    let mut repo = faulty_session(&a, &f, true);
    let before = snapshot(&a.store());
    let new_sk = SecretKey::generate().unwrap();
    let req = request(&f, &new_sk, vec![f.others[0].id()], RotationReason::Revoke);
    let r = repo.rotate(req);
    assert!(matches!(r, Err(Error::Store(_))), "{r:?}");
    assert_eq!(snapshot(&a.store()), before);
    let trust = a.store().trust_state().unwrap().unwrap();
    assert_eq!(trust.state, DeviceLineageState::Current);
    assert_eq!(trust.head.generation, 0);
}

/// K12: once the transaction is committed the call succeeds, whatever
/// fails after it.
#[test]
fn never_fails_after_commit() {
    let (a, f) = fixture();
    let mut repo = faulty_session(&a, &f, false);
    let new_sk = SecretKey::generate().unwrap();
    let req = request(&f, &new_sk, vec![], RotationReason::Rotate);
    let out = repo.rotate(req).unwrap();
    assert!(
        repo.store().broken.get(),
        "the store broke after the commit"
    );
    let trust = a.store().trust_state().unwrap().unwrap();
    assert_eq!(trust.head.hash, out.head);
    assert_eq!(trust.state, DeviceLineageState::Rotating { phase: 1 });
}

/// The approver list follows the rotation, re-signed under the new identity:
/// the devices' approval keys stay enrolled.
#[test]
fn approver_list_survives_rotation() {
    use onepass_core::approvers::ApproverRole;
    use onepass_core::crypto::{HybridKemSecret, HybridSigningKey};
    let (mut a, f) = fixture();
    let sign_pub = HybridSigningKey::generate()
        .unwrap()
        .verifying_key()
        .unwrap();
    let kem_pub = HybridKemSecret::generate().unwrap().public().unwrap();
    a.repo()
        .register_this_approver(sign_pub.clone(), kem_pub, ApproverRole::Phone)
        .unwrap();
    let new_sk = SecretKey::generate().unwrap();
    a.repo()
        .rotate(request(&f, &new_sk, vec![], RotationReason::Rotate))
        .unwrap();
    let listed = a.repo().approvers().unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].sign_pub, sign_pub);
    assert_eq!(listed[0].role, ApproverRole::Phone);
}

// ---------------------------------------------------------------- content

#[test]
fn roster_and_deliveries_exact() {
    let (mut a, f) = fixture();
    let (b, c, d) = (f.others[0].id(), f.others[1].id(), f.others[2].id());
    // D was distrusted on this device ("Ce n'était pas moi").
    let mut trust = a.store().trust_state().unwrap().unwrap();
    trust.excluded.insert(d);
    a.repo()
        .store_mut()
        .put_all_if_version_with_trust(vec![], vec![], None, &trust)
        .unwrap();
    let old = a.store().trust_state().unwrap().unwrap();
    let old_identity = a.repo().account().params.identity_pub.clone();
    let old_signing = a.repo().account().params.signing_pub.clone();
    let vault = a.vault();
    let from = a.repo().device_state().last_seen[&vault.id].clone();

    let new_sk = SecretKey::generate().unwrap();
    let mut req = request(&f, &new_sk, vec![c], RotationReason::Revoke);
    req.new_password = Some(NEW_PASSWORD);
    let RotationOutcome { auk, code, head } = a.repo.as_mut().unwrap().rotate(req).unwrap();
    let store = a.store();

    // The record: decodes strictly, signed by A's pinned key and the new
    // identity, child of the genesis.
    let body = rotation_of(&store, &head);
    let lineage = store
        .get(RecordKind::Lineage, {
            let mut id = [0u8; 16];
            id.copy_from_slice(&head[..16]);
            Id(id)
        })
        .unwrap()
        .unwrap();
    let LineageRecord::Rotation(signed) = LineageRecord::decode(&lineage.data).unwrap() else {
        panic!("rotation")
    };
    assert_eq!(lineage.version, 1);
    assert_eq!(LineageRecord::Rotation(signed.clone()).hash(), head);
    verify_rotation(&signed, &f.me.public.sign_pub).unwrap();
    assert_eq!(code, rotation_code(&head));
    assert_eq!(body.generation, 1);
    assert_eq!(body.parent, old.head.hash);
    assert_eq!(body.rotator, f.me.id());
    assert_eq!(body.reason, RotationReason::Revoke);
    assert_eq!(body.revoked, vec![c]);
    assert_ne!(body.identity_pub, old_identity);

    // Roster = old roster minus revoked minus excluded, keys as pinned.
    let expected: Vec<RosterEntry> = old
        .roster
        .iter()
        .filter(|e| e.device_id != c && e.device_id != d)
        .cloned()
        .collect();
    assert_eq!(body.roster, expected);
    let ids: BTreeSet<Id> = body.roster.iter().map(|e| e.device_id).collect();
    assert_eq!(ids, BTreeSet::from([f.me.id(), b]));

    // One delivery per roster member except the rotator; the envelope
    // hash matches the body, and only that member opens it, to the new
    // Secret Key.
    assert_eq!(body.deliveries.len(), 1);
    let (recipient, hash) = body.deliveries[0];
    assert_eq!(recipient, b);
    let env = store
        .get(RecordKind::KeyDelivery, delivery_id(&head, b))
        .unwrap()
        .expect("B's delivery");
    assert_eq!(sha256(&env.data), hash);
    assert_eq!(store.list(RecordKind::KeyDelivery).unwrap().len(), 1);
    let opened = open_key_delivery(&f.others[0].keys, &body, b, &env.data).unwrap();
    assert_eq!(opened.to_display(), new_sk.to_display());
    assert!(open_key_delivery(&f.others[1].keys, &body, b, &env.data).is_err());
    let mut forged = env.data.clone();
    *forged.last_mut().unwrap() ^= 1;
    assert_eq!(
        integrity(open_key_delivery(&f.others[0].keys, &body, b, &forged)),
        IntegrityError::Signature
    );

    // Identity-keyed params and keyset, hashes in the body; the new pair
    // opens with the new password and Secret Key, to the AUK returned.
    let rid = account_record_id(old.account_id, Some(&body.identity_pub));
    assert_eq!(rid, identity_id(&body.identity_pub));
    let params = store.get(RecordKind::AccountParams, rid).unwrap().unwrap();
    let keyset = store.get(RecordKind::Keyset, rid).unwrap().unwrap();
    assert_eq!(sha256(&params.data), body.params_hash);
    assert_eq!(sha256(&keyset.data), body.keyset_hash);
    let (_, auk2) = onepass_core::account::Account::unlock_exporting_auk(
        NEW_PASSWORD,
        &new_sk,
        &params.data,
        &keyset.data,
        None,
    )
    .unwrap();
    assert_eq!(auk.as_bytes(), auk2.as_bytes());
    // The old pair is still there, under the account id.
    assert!(
        store
            .get(RecordKind::AccountParams, old.account_id)
            .unwrap()
            .is_some()
    );

    // Lists signed again at seq 1 under the identity id.
    for kind in [RecordKind::DeviceList, RecordKind::VaultList] {
        let rec = store.get(kind, rid).unwrap().expect("list");
        assert_eq!(rec.version, 1);
    }

    // from_heads: the manifest the vault was rotated from.
    assert_eq!(body.from_heads.len(), 1);
    assert_eq!(body.from_heads[&vault.id], from);

    // The trust state moved to the new head, in state Rotating.
    let trust = store.trust_state().unwrap().unwrap();
    assert_eq!(
        trust.head,
        LineageHead {
            generation: 1,
            hash: head
        }
    );
    assert_eq!(trust.identity_pub, body.identity_pub);
    assert_eq!(trust.roster, body.roster);
    assert!(trust.revoked.contains(&c));
    assert!(trust.excluded.contains(&d));
    assert_eq!(trust.state, DeviceLineageState::Rotating { phase: 1 });
    let retired = trust.retired.last().expect("old identity retired");
    assert_eq!(retired.identity_pub, old_identity);
    assert_eq!(retired.sign_pub, old_signing);
    assert_eq!(retired.generation, 0);
    assert_eq!(retired.identity_id, identity_id(&old_identity));
}

#[test]
fn old_items_readable_until_phase_three() {
    let (mut a, f) = fixture();
    let before: Vec<Record> = a.store().list(RecordKind::Item).unwrap();
    assert_eq!(before.len(), 3);
    let new_sk = SecretKey::generate().unwrap();
    let req = request(&f, &new_sk, vec![], RotationReason::Rotate);
    a.repo.as_mut().unwrap().rotate(req).unwrap();
    let store = a.store();
    for r in &before {
        assert_eq!(
            store.get(RecordKind::Item, r.id).unwrap().as_ref(),
            Some(r),
            "old item record kept until phase 3"
        );
    }
    // Nothing is deleted locally, not even pending deletions.
    assert!(
        store
            .pending_changes()
            .unwrap()
            .iter()
            .all(|c| c.data.is_some())
    );
}

#[test]
fn items_resealed() {
    let (mut a, f) = fixture();
    let vault = a.vault();
    let old_items = a.repo().items(&vault).unwrap();
    let old_versions: BTreeMap<Id, u64> = {
        let store = a.store();
        store
            .list(RecordKind::Item)
            .unwrap()
            .iter()
            .map(|r| {
                let rec = ItemRecord::decode(split_item_record(&r.data).unwrap().1).unwrap();
                (rec.item_id, rec.version)
            })
            .collect()
    };
    let new_sk = SecretKey::generate().unwrap();
    let req = request(&f, &new_sk, vec![], RotationReason::Rotate);
    let out = a.repo.as_mut().unwrap().rotate(req).unwrap();
    let body = rotation_of(&a.store(), &out.head);

    // The vault under the new account's KEM key, its manifest signed by the
    // new signing key, chained to `from_heads`.
    let account = a.repo.as_ref().unwrap().account();
    assert_eq!(account.params.identity_pub, body.identity_pub);
    let store = a.store();
    let key = store.get(RecordKind::VaultKey, vault.id).unwrap().unwrap();
    let meta_rec = store.get(RecordKind::VaultMeta, vault.id).unwrap().unwrap();
    let fresh = Vault::open(account, vault.id, &key.data, &meta_rec.data).unwrap();
    assert_eq!(fresh.meta, vault.meta);
    assert!(Vault::open(account, vault.id, &key.data, &meta_rec.data).is_ok());
    let man = store.get(RecordKind::Manifest, vault.id).unwrap().unwrap();
    let from: &SeenManifest = &body.from_heads[&vault.id];
    let m = verify_manifest(
        &fresh,
        &account.params.signing_pub,
        &SignedManifest::decode(&man.data).unwrap(),
        Some(from),
    )
    .unwrap();
    assert_eq!(m.seq, from.seq + 1);
    assert_eq!(man.version, m.seq);

    // Every live, archived and trashed item opens under the new vault key
    // at version + 1; the old records do not.
    let mut reopened = Vec::new();
    for r in store.list(RecordKind::Item).unwrap() {
        let rec = ItemRecord::decode(split_item_record(&r.data).unwrap().1).unwrap();
        match fresh.open_item(&rec) {
            Ok(item) => {
                assert_eq!(rec.version, old_versions[&rec.item_id] + 1);
                assert!(
                    m.entries
                        .iter()
                        .any(|e| e.item_id == rec.item_id && e.version == rec.version)
                );
                reopened.push(item);
            }
            Err(_) => assert_eq!(rec.version, old_versions[&rec.item_id]),
        }
    }
    reopened.sort_by_key(|i| i.id);
    let mut expected = old_items.clone();
    expected.sort_by_key(|i| i.id);
    assert_eq!(reopened, expected);
    assert_eq!(m.entries.len(), f.items.len());
    assert!(reopened.iter().any(|i| i.archived));
    assert!(reopened.iter().any(|i| i.trashed_at.is_some()));

    // The session moved to the new keys and remembers the new head.
    assert_eq!(
        a.repo.as_ref().unwrap().device_state().last_seen[&vault.id].seq,
        m.seq
    );
}

// ---------------------------------------------------------------- phases

fn state(dev: &Device) -> DeviceLineageState {
    dev.store().trust_state().unwrap().unwrap().state
}

fn rotating(phase: u8) -> DeviceLineageState {
    DeviceLineageState::Rotating { phase }
}

/// Rotate A (no push), keeping the password.
fn rotate(a: &mut Device, f: &Fixture, new_sk: &SecretKey) -> RotationOutcome {
    let req = request(f, new_sk, vec![], RotationReason::Rotate);
    a.repo.as_mut().unwrap().rotate(req).unwrap()
}

/// Push the outbox as it is (one batch) and confirm it, without settling
/// the phase.
fn push_outbox(server: &mut Server, dev: &Device) -> std::result::Result<(), Conflict> {
    send(server, dev, outbox(dev), true)
}

/// The kinds of the server's writes after `clock`, in write order.
fn write_log(server: &Server, clock: u64) -> Vec<(RecordKind, Id)> {
    let mut log: Vec<(u64, RecordKind, Id)> = server
        .records
        .iter()
        .filter(|(_, e)| e.changed > clock)
        .map(|((k, id), e)| (e.changed, *k, *id))
        .collect();
    log.sort();
    log.into_iter().map(|(_, k, id)| (k, id)).collect()
}

/// The blob ids of the item records of `vault` the store holds.
fn item_blobs(store: &SyncStore, vault: Id) -> BTreeSet<Id> {
    store
        .list(RecordKind::Item)
        .unwrap()
        .into_iter()
        .filter(|r| split_item_record(&r.data).unwrap().0 == vault)
        .map(|r| r.id)
        .collect()
}

fn server_item_blobs(server: &Server, vault: Id) -> BTreeSet<Id> {
    server
        .records
        .iter()
        .filter(|((k, _), e)| {
            *k == RecordKind::Item
                && e.record
                    .as_ref()
                    .is_some_and(|r| split_item_record(&r.data).unwrap().0 == vault)
        })
        .map(|((_, id), _)| *id)
        .collect()
}

#[test]
fn phase_one_writes_new_ids_only_lineage_last() {
    let mut server = Server::default();
    let (mut a, f) = fixture_on(&mut server);
    let new_sk = SecretKey::generate().unwrap();
    let out = rotate(&mut a, &f, &new_sk);
    assert_eq!(state(&a), rotating(1));
    let body = rotation_of(&a.store(), &out.head);
    let rid = identity_id(&body.identity_pub);

    let batch = outbox(&a);
    // All new ids: nothing on the server, nothing expected.
    for (c, tag) in &batch {
        assert!(c.data.is_some(), "{:?} is a deletion", c.kind);
        assert_eq!(*tag, None, "{:?} expects a version", c.kind);
        assert!(server.get(c.kind, c.id).is_none(), "{:?} exists", c.kind);
    }
    let mut lineage = [0u8; 16];
    lineage.copy_from_slice(&out.head[..16]);
    let mut expected: Vec<(RecordKind, Id)> = body
        .deliveries
        .iter()
        .map(|(to, _)| (RecordKind::KeyDelivery, delivery_id(&out.head, *to)))
        .collect();
    expected.sort();
    expected.extend([
        (RecordKind::AccountParams, rid),
        (RecordKind::Keyset, rid),
        (RecordKind::DeviceList, rid),
        (RecordKind::VaultList, rid),
        (RecordKind::Lineage, Id(lineage)),
    ]);
    let ids: Vec<(RecordKind, Id)> = batch.iter().map(|(c, _)| (c.kind, c.id)).collect();
    assert_eq!(ids, expected);
    assert_eq!(body.deliveries.len(), 3);

    // Not confirmed yet: the phase is not over.
    assert_eq!(
        a.store().push_rotation_phase(1).unwrap(),
        PhaseOutcome::Retry
    );
    let clock = server.clock;
    push_outbox(&mut server, &a).unwrap();
    assert_eq!(write_log(&server, clock), expected);
    assert_eq!(state(&a), rotating(1));
    assert_eq!(
        a.store().push_rotation_phase(1).unwrap(),
        PhaseOutcome::Done
    );
    assert_eq!(state(&a), rotating(2));
}

#[test]
fn other_writes_wait_in_phase_one() {
    let mut server = Server::default();
    let (mut a, f) = fixture_on(&mut server);
    let new_sk = SecretKey::generate().unwrap();
    rotate(&mut a, &f, &new_sk);
    let v = a.vault();
    let dora = login(v.id, "dora", T0 + 50);
    a.save(&dora);

    let vault_kinds = [
        RecordKind::VaultKey,
        RecordKind::VaultMeta,
        RecordKind::Item,
        RecordKind::Manifest,
        RecordKind::RestoreEpoch,
    ];
    let phase_one = outbox(&a);
    assert!(
        phase_one
            .iter()
            .all(|(c, _)| !vault_kinds.contains(&c.kind)),
        "{:?}",
        phase_one.iter().map(|(c, _)| c.kind).collect::<Vec<_>>()
    );
    push_outbox(&mut server, &a).unwrap();
    assert_eq!(
        a.store().push_rotation_phase(1).unwrap(),
        PhaseOutcome::Done
    );
    // Phase 2: the vault, the new item with it.
    let phase_two = outbox(&a);
    assert!(
        phase_two
            .iter()
            .any(|(c, _)| c.kind == RecordKind::Manifest)
    );
    assert!(phase_two.iter().all(|(c, _)| c.data.is_some()));
    sync(&mut server, &mut a).unwrap();
    assert_eq!(state(&a), DeviceLineageState::Current);
    assert!(outbox(&a).is_empty());
    assert!(users(&a.items()).contains(&"dora".to_string()));
}

#[test]
fn cut_between_phases_resumes() {
    let mut server = Server::default();
    let (mut a, f) = fixture_on(&mut server);
    let expected = a.items();
    let v = a.vault().id;
    let old_blobs = item_blobs(&a.store(), v);
    let new_sk = SecretKey::generate().unwrap();
    rotate(&mut a, &f, &new_sk);
    a.repo = None;

    // Phase 1 lands, then the app dies before settling it.
    push_outbox(&mut server, &a).unwrap();
    assert_eq!(state(&a), rotating(1));
    assert!(outbox(&a).is_empty());
    assert_eq!(
        a.store().push_rotation_phase(1).unwrap(),
        PhaseOutcome::Done
    );

    // Reopened: phase 2 only, the vault records, nothing deleted; the
    // rotator's acknowledgment of its own head (spec 6.8, O6), which phase 1
    // does not rank, goes with them.
    assert_eq!(state(&a), rotating(2));
    let phase_two = outbox(&a);
    assert!(!phase_two.is_empty());
    assert!(phase_two.iter().all(|(c, _)| c.data.is_some()
        && matches!(
            c.kind,
            RecordKind::VaultKey
                | RecordKind::VaultMeta
                | RecordKind::Item
                | RecordKind::Manifest
                | RecordKind::DeviceAck
        )));
    assert_eq!(
        phase_two
            .iter()
            .filter(|(c, _)| c.kind == RecordKind::DeviceAck)
            .count(),
        1
    );
    push_outbox(&mut server, &a).unwrap();
    assert_eq!(
        a.store().push_rotation_phase(2).unwrap(),
        PhaseOutcome::Done
    );

    // Reopened: phase 3 deletes exactly the records the rotation left.
    assert_eq!(state(&a), rotating(3));
    let phase_three = outbox(&a);
    let deleted: BTreeSet<Id> = phase_three
        .iter()
        .map(|(c, _)| {
            assert!(c.data.is_none() && c.kind == RecordKind::Item);
            c.id
        })
        .collect();
    assert_eq!(deleted, old_blobs);
    push_outbox(&mut server, &a).unwrap();
    // A settle asked for the wrong phase changes nothing.
    assert_eq!(
        a.store().push_rotation_phase(2).unwrap(),
        PhaseOutcome::Retry
    );
    assert_eq!(state(&a), rotating(3));
    assert_eq!(
        a.store().push_rotation_phase(3).unwrap(),
        PhaseOutcome::Done
    );
    assert_eq!(state(&a), DeviceLineageState::Current);
    assert!(outbox(&a).is_empty());
    for blob in &old_blobs {
        assert!(server.get(RecordKind::Item, *blob).is_none());
    }

    // The new identity opens on this device.
    a.try_unlock(PASSWORD, &new_sk).unwrap();
    assert_eq!(a.items(), expected);
}

/// A copy of `a`'s device file (same device keys, same trust state), as a
/// sibling rotation from the same parent would start.
fn sibling_of(a: &mut Device, sk: &SecretKey) -> Device {
    a.lock();
    let s = Device::empty();
    std::fs::copy(&a.path, &s.path).unwrap();
    for ext in ["-wal", "-shm"] {
        let from = PathBuf::from(format!("{}{ext}", a.path.display()));
        if from.exists() {
            std::fs::copy(&from, format!("{}{ext}", s.path.display())).unwrap();
        }
    }
    let mut s = Device {
        cursor: a.cursor,
        ..s
    };
    s.unlock(sk);
    a.unlock(sk);
    s
}

/// A rotates (not pushed); its sibling S, from the same parent, pushes
/// phases 1 and 2 first: the server holds S's records and S's vault key,
/// meta and manifest over the old ones.
fn sibling_race() -> (Server, Device, Device, Fixture, RotationOutcome) {
    let mut server = Server::default();
    let (mut a, f) = fixture_on(&mut server);
    let mut s = sibling_of(&mut a, &f.sk);
    let out = rotate(&mut a, &f, &SecretKey::generate().unwrap());
    rotate(&mut s, &f, &SecretKey::generate().unwrap());
    push_outbox(&mut server, &s).unwrap();
    assert_eq!(
        s.store().push_rotation_phase(1).unwrap(),
        PhaseOutcome::Done
    );
    push_outbox(&mut server, &s).unwrap();
    assert_eq!(
        s.store().push_rotation_phase(2).unwrap(),
        PhaseOutcome::Done
    );
    (server, a, s, f, out)
}

#[test]
fn phase_one_never_conflicts() {
    let (mut server, a, s, _f, out) = sibling_race();
    let batch = outbox(&a);
    assert!(batch.iter().all(|(_, tag)| tag.is_none()));
    send(&mut server, &a, batch, true).expect("phase 1 never conflicts");
    let mut id = [0u8; 16];
    id.copy_from_slice(&out.head[..16]);
    assert!(server.get(RecordKind::Lineage, Id(id)).is_some());
    let theirs = s.store().trust_state().unwrap().unwrap().head.hash;
    id.copy_from_slice(&theirs[..16]);
    assert!(server.get(RecordKind::Lineage, Id(id)).is_some());
    assert_eq!(
        a.store().push_rotation_phase(1).unwrap(),
        PhaseOutcome::Done
    );
}

/// R21: the vault key, meta and manifest hold the sibling's records; the
/// rotator overwrites them conditionally on the version it reads, without
/// reading them.
#[test]
fn phase_two_overwrites_foreign_single_slot() {
    let (mut server, mut a, _s, _f, _out) = sibling_race();
    let expected = a.items();
    let v = a.vault().id;
    push_outbox(&mut server, &a).unwrap();
    assert_eq!(
        a.store().push_rotation_phase(1).unwrap(),
        PhaseOutcome::Done
    );
    // Built on the old records: the sibling's are newer.
    let Err(Conflict(conflicts)) = push_outbox(&mut server, &a) else {
        panic!("phase 2 over the sibling's records")
    };
    assert!(conflicts.contains(&(RecordKind::VaultKey, v)));
    // No phase 3 before phase 2 lands, conflict or not.
    assert_eq!(
        a.store().push_rotation_phase(2).unwrap(),
        PhaseOutcome::Retry
    );
    assert!(outbox(&a).iter().all(|(c, _)| c.data.is_some()));
    pull(&server, &mut a);
    // Not held: nothing to rebase.
    assert!(a.store().vaults_needing_rebase().unwrap().is_empty());
    a.repo().rebase().unwrap();
    let batch = outbox(&a);
    for kind in [
        RecordKind::VaultKey,
        RecordKind::VaultMeta,
        RecordKind::Manifest,
    ] {
        let (c, tag) = batch
            .iter()
            .find(|(c, _)| c.kind == kind && c.id == v)
            .expect("single-slot write");
        assert_eq!(*tag, Some(server.live(kind, v).unwrap().tag));
        assert_ne!(server.get(kind, v).unwrap().data, *c.data.as_ref().unwrap());
    }
    send(&mut server, &a, batch.clone(), true).unwrap();
    for (c, _) in batch.iter().filter(|(c, _)| c.id == v) {
        assert_eq!(server.get(c.kind, v).unwrap(), as_record(c));
    }
    assert_eq!(
        a.store().push_rotation_phase(2).unwrap(),
        PhaseOutcome::Done
    );
    // The sibling's item records are leftovers under another key.
    assert_eq!(a.items(), expected);
}

/// R23: phase 3 deletes the records the `from_heads` manifests list, and
/// nothing else: the sibling's item records stay.
#[test]
fn phase_three_deletes_only_from_heads_items() {
    let (mut server, mut a, _s, _f, _out) = sibling_race();
    let v = a.vault().id;
    // The server holds the old records and the sibling's (it stopped
    // before its phase 3); A holds the old ones and its own.
    let mine = item_blobs(&a.store(), v);
    let served = server_item_blobs(&server, v);
    let old: BTreeSet<Id> = &mine & &served;
    let theirs: BTreeSet<Id> = &served - &mine;
    assert_eq!(old.len(), 3);
    assert_eq!(theirs.len(), 3);
    sync(&mut server, &mut a).unwrap();
    assert_eq!(state(&a), DeviceLineageState::Current);
    let on_server = server_item_blobs(&server, v);
    assert!(on_server.is_disjoint(&old), "old records collected");
    assert!(theirs.is_subset(&on_server), "the sibling's records stay");
}

/// Task 19 carried item 5 (R21): the loser of two sibling rotations pushed
/// its phase 2 before it knew the winner. Its re-sealed item records,
/// which the winner tolerates as a foreign generation, are collected on
/// the server once the loser switched; the winner's stay.
#[test]
fn losers_items_collected_after_its_switch() {
    let mut server = Server::default();
    let (mut a, f) = fixture_on(&mut server);
    let mut c = follower_with(&mut server, &a, &f, C, |_| {});
    c.unlock(&f.sk);
    let v = a.vault().id;
    let old = server_item_blobs(&server, v);
    let ra = rotate(&mut a, &f, &SecretKey::generate().unwrap());
    let c_sk = SecretKey::generate().unwrap();
    let mut req = request(&f, &c_sk, vec![], RotationReason::Rotate);
    req.device_keys = &f.others[C].keys;
    let rc = c.repo.as_mut().unwrap().rotate(req).unwrap();
    let a_wins = ra.head < rc.head;
    let wh = if a_wins { ra.head } else { rc.head };
    let (mut w, mut l, l_keys) = if a_wins {
        (a, c, &f.others[C].keys)
    } else {
        (c, a, &f.me.keys)
    };
    // The loser goes first, phases 1 and 2.
    for phase in [1, 2] {
        push_outbox(&mut server, &l).unwrap();
        assert_eq!(
            l.store().push_rotation_phase(phase).unwrap(),
            PhaseOutcome::Done
        );
    }
    let theirs: BTreeSet<Id> = &server_item_blobs(&server, v) - &old;
    assert_eq!(theirs.len(), 3);
    sync(&mut server, &mut w).unwrap();
    assert_eq!(state(&w), DeviceLineageState::Current);
    let mine: BTreeSet<Id> = &server_item_blobs(&server, v) - &(&old | &theirs);
    assert_eq!(mine.len(), 3);

    pull(&server, &mut l);
    l.repo().refresh_pending_rotation().unwrap();
    let session = l.repo.take().unwrap();
    let (repo, _, _) = follow_switch(session, wh, PASSWORD, l_keys).unwrap();
    l.repo = Some(repo);
    sync(&mut server, &mut l).unwrap();
    let on_server = server_item_blobs(&server, v);
    assert!(
        on_server.is_disjoint(&theirs),
        "the loser's records collected"
    );
    assert_eq!(on_server, mine);
    for d in [&mut w, &mut l] {
        pull(&server, d);
        assert_eq!(head_of(d), wh);
        assert_eq!(
            users(&d.items()),
            ["alice", "bob", "carol"].map(String::from)
        );
    }
}

/// Fix round 1 of Task 19, review C1: the loser switches before the
/// winner's content arrived, so the replay of its own writes (one made
/// before its rotation, which the rotation re-sealed, one after) waits.
/// Nothing of its key generation is collected while it waits; once the
/// replay settled, its writes are under the winner's keys and the server
/// records of its rotation go.
#[test]
fn losers_collection_waits_for_its_replay() {
    let mut server = Server::default();
    let (mut a, f) = fixture_on(&mut server);
    let mut c = follower_with(&mut server, &a, &f, C, |_| {});
    c.unlock(&f.sk);
    let v = a.vault().id;
    let old = server_item_blobs(&server, v);
    let (a_before, c_before) = (login(v, "a-before", T0 + 40), login(v, "c-before", T0 + 41));
    a.save(&a_before);
    c.save(&c_before);
    let ra = rotate(&mut a, &f, &SecretKey::generate().unwrap());
    let c_sk = SecretKey::generate().unwrap();
    let mut req = request(&f, &c_sk, vec![], RotationReason::Rotate);
    req.device_keys = &f.others[C].keys;
    let rc = c.repo.as_mut().unwrap().rotate(req).unwrap();
    let a_wins = ra.head < rc.head;
    let wh = if a_wins { ra.head } else { rc.head };
    let (mut w, mut l, l_keys, mine) = if a_wins {
        (a, c, &f.others[C].keys, "c-before")
    } else {
        (c, a, &f.me.keys, "a-before")
    };
    let theirs = if a_wins { "a-before" } else { "c-before" };
    let mine_id = if a_wins { c_before.id } else { a_before.id };
    l.save(&login(v, "late", T0 + 60));
    for phase in [1, 2] {
        push_outbox(&mut server, &l).unwrap();
        assert_eq!(
            l.store().push_rotation_phase(phase).unwrap(),
            PhaseOutcome::Done
        );
    }
    let loser_records: BTreeSet<Id> = &server_item_blobs(&server, v) - &old;
    assert!(loser_records.len() >= 5, "{}", loser_records.len());
    // The winner's phase 1 only: its record, not its content.
    push_outbox(&mut server, &w).unwrap();
    assert_eq!(
        w.store().push_rotation_phase(1).unwrap(),
        PhaseOutcome::Done
    );
    pull(&server, &mut l);
    l.repo().refresh_pending_rotation().unwrap();
    let session = l.repo.take().unwrap();
    let (repo, _, _) = follow_switch(session, wh, PASSWORD, l_keys).unwrap();
    l.repo = Some(repo);
    assert!(
        !l.store()
            .trust_state()
            .unwrap()
            .unwrap()
            .own_writes
            .replay
            .is_empty()
    );
    sync(&mut server, &mut l).unwrap();
    assert!(
        loser_records.is_subset(&server_item_blobs(&server, v)),
        "nothing collected while the replay waits"
    );
    let t = l.store().trust_state().unwrap().unwrap();
    assert!(!t.own_writes.replay.is_empty());
    assert!(!t.own_writes.alert && t.own_writes.lost.is_empty());

    // The winner's content arrives: the replay settles, then the loser's
    // records go.
    sync(&mut server, &mut w).unwrap();
    pull(&server, &mut l);
    l.repo().replay_own_writes().unwrap();
    let t = l.store().trust_state().unwrap().unwrap();
    assert!(t.own_writes.replay.is_empty(), "{:?}", t.own_writes.replay);
    assert!(!t.own_writes.alert && t.own_writes.lost.is_empty());
    sync(&mut server, &mut l).unwrap();
    // Left: only the loser's own write made before its rotation, under the
    // identity it rotated from (its intent names the re-sealed record):
    // an old-identity late write, which R21 tolerates and no rotation
    // collects (a known limit, Task 19 report).
    let left: BTreeSet<Id> = &server_item_blobs(&server, v) & &loser_records;
    assert_eq!(left.len(), 1, "{left:?}");
    let rec = server
        .get(RecordKind::Item, *left.first().unwrap())
        .unwrap();
    let (_, body) = split_item_record(&rec.data).unwrap();
    let rec = ItemRecord::decode(body).unwrap();
    assert_eq!((rec.item_id, rec.version), (mine_id, 1));
    let expected = {
        let mut u: Vec<String> = ["alice", "bob", "carol", "late", mine, theirs]
            .map(String::from)
            .to_vec();
        u.sort();
        u
    };
    for d in [&mut w, &mut l] {
        sync(&mut server, d).unwrap();
        pull(&server, d);
        assert_eq!(head_of(d), wh);
        assert_eq!(users(&d.items()), expected);
    }
}

/// `zz2_hostile_epoch_inflation` (first design): epochs are per identity.
/// A restore epoch at `u64::MAX`, validly signed by the identity this
/// device left, or under another identity's id, changes nothing.
#[test]
fn hostile_epoch_inflation_is_noop() {
    let mut server = Server::default();
    let (mut a, f) = fixture_on(&mut server);
    let expected = a.items();
    let account_id = a.repo().account_id();
    let forged = RestoreEpoch {
        account_id,
        epoch: u64::MAX,
        issued_at: T0,
        heads: a.repo().device_state().last_seen.clone(),
        reason: EpochReason::Restore,
    };
    let data = SignedRestoreEpoch::sign(forged, &a.repo().account().keyset().signing)
        .unwrap()
        .encode();
    let new_sk = SecretKey::generate().unwrap();
    rotate(&mut a, &f, &new_sk);
    sync(&mut server, &mut a).unwrap();
    assert_eq!(state(&a), DeviceLineageState::Current);

    let other = identity_id(&f_identity(&f));
    for id in [account_id, other] {
        server.replay(Record {
            id,
            kind: RecordKind::RestoreEpoch,
            version: i64::MAX as u64,
            data: data.clone(),
        });
    }
    sync(&mut server, &mut a).unwrap();
    assert_eq!(a.repo().restore_epoch(), None);
    assert_eq!(a.items(), expected);
    let v = a.vault();
    a.save(&login(v.id, "erin", T0 + 60));
    sync(&mut server, &mut a).unwrap();

    // The next epoch of this identity is its first.
    let issued = a.repo().issue_restore_epoch(EpochReason::Restore).unwrap();
    assert_eq!(issued.epoch, 1);
    sync(&mut server, &mut a).unwrap();
    let rid = account_record_id(account_id, Some(&a.repo().account().params.identity_pub));
    assert_eq!(
        server.get(RecordKind::RestoreEpoch, rid).unwrap().version,
        1
    );
    a.lock();
    a.try_unlock(PASSWORD, &new_sk).unwrap();
    assert_eq!(a.repo().restore_epoch(), Some(1));
    assert_eq!(a.items().len(), expected.len() + 1);

    // The left identity's epoch planted under the new identity's own id:
    // refused (its signature), never accepted.
    server.replay(Record {
        id: rid,
        kind: RecordKind::RestoreEpoch,
        version: i64::MAX as u64,
        data,
    });
    sync(&mut server, &mut a).unwrap();
    assert_eq!(
        a.repo().vaults().unwrap_err(),
        Error::Integrity(IntegrityError::Signature)
    );
    assert_eq!(a.repo().restore_epoch(), Some(1));
}

/// Another identity: a peer's device key does not make one, so draw one.
fn f_identity(_f: &Fixture) -> onepass_core::crypto::IdentityVerifyingKey {
    let n = onepass_core::account::Account::create_with_params(PASSWORD, kdf()).unwrap();
    n.account.params.identity_pub.clone()
}

// ---------------------------------------------------------------- reads

/// Controller ruling: right after `rotate`, every read and the next unlock
/// go to the new identity's records.
#[test]
fn reads_and_unlock_follow_the_new_identity() {
    let (mut a, f) = fixture();
    let expected = a.items();
    let new_sk = SecretKey::generate().unwrap();
    let mut req = request(&f, &new_sk, vec![], RotationReason::RotateWithPassword);
    req.new_password = Some(NEW_PASSWORD);
    a.repo.as_mut().unwrap().rotate(req).unwrap();

    assert_eq!(a.repo().vaults().unwrap().len(), 1);
    assert_eq!(a.items(), expected);
    let v = a.vault();
    a.save(&login(v.id, "frank", T0 + 70));
    assert_eq!(a.items().len(), expected.len() + 1);
    a.repo().vault_list().unwrap();

    a.lock();
    assert!(a.try_unlock(PASSWORD, &f.sk).is_err());
    a.try_unlock(NEW_PASSWORD, &new_sk).unwrap();
    assert_eq!(a.repo().vaults().unwrap().len(), 1);
    assert_eq!(a.items().len(), expected.len() + 1);
    let auk = a.try_unlock(NEW_PASSWORD, &new_sk).unwrap();
    a.try_unlock_with_auk(&auk).unwrap();
    assert_eq!(a.items().len(), expected.len() + 1);
    // A password change stays within the new identity (epoch 2).
    a.repo()
        .change_password(NEW_PASSWORD, &new_sk, PASSWORD)
        .unwrap();
    assert_eq!(a.repo().account().params.epoch, 2);
    a.lock();
    a.try_unlock(PASSWORD, &new_sk).unwrap();
    assert_eq!(a.items().len(), expected.len() + 1);
}

/// Controller ruling: the device state is saved after the rotation commit;
/// a crash in between leaves the old pin, epoch and lists. The trust state
/// (and the chain state written with it) wins on reopen.
#[test]
fn crash_before_the_device_state_is_saved() {
    let (mut a, f) = fixture();
    let expected = a.items();
    // A password change (params epoch 2) and a restore epoch (1) under the
    // old identity, saved.
    a.repo()
        .change_password(PASSWORD, &f.sk, NEW_PASSWORD)
        .unwrap();
    a.repo().issue_restore_epoch(EpochReason::Restore).unwrap();
    a.repo().persist_device_state().unwrap();
    let old_identity = a.repo().account().params.identity_pub.clone();
    // A second session of the old identity, as an extension holds.
    let mut stale = {
        let store = a.store();
        let state = store.device_state().unwrap();
        Repository::unlock(store, NEW_PASSWORD, &f.sk, state).unwrap()
    };

    let new_sk = SecretKey::generate().unwrap();
    let mut req = request(&f, &new_sk, vec![], RotationReason::Rotate);
    req.password = NEW_PASSWORD;
    a.repo.as_mut().unwrap().rotate(req).unwrap();
    // Crash: the session never saves its device state.
    a.repo = None;
    let stored = a.store().device_state().unwrap();
    assert_eq!(stored.pinned.unwrap().identity_pub, old_identity);
    assert_eq!(stored.epoch, 1);

    // A session of the left identity cannot save over the new one.
    assert!(matches!(stale.persist_device_state(), Err(Error::Conflict)));
    let chain = RecordStore::chain_state(&a.store()).unwrap();
    assert_eq!(chain.params_epoch, 1);
    drop(stale);

    a.try_unlock(NEW_PASSWORD, &new_sk).unwrap();
    assert_eq!(a.repo().vaults().unwrap().len(), 1);
    assert_eq!(a.items(), expected);
    assert_eq!(a.repo().restore_epoch(), None);
    let new_identity = a.repo().account().params.identity_pub.clone();
    a.lock();
    let stored = a.store().device_state().unwrap();
    assert_eq!(stored.pinned.unwrap().identity_pub, new_identity);
    assert_eq!(stored.epoch, 0);
    a.try_unlock(NEW_PASSWORD, &new_sk).unwrap();
    assert_eq!(a.items(), expected);
}

/// Review I1: in the window after the rotation commits and before the
/// device state is saved (and after a crash there), the saved pin still
/// names the identity this device left. A revoked device holding the old
/// signing key signs an old-identity vault list (seq 5) marking a live
/// vault deleted, and the server deletes the vault's records: the store
/// proves nothing from it. Phase 2 still sends the vault, the deletions
/// are refused and logged, `last_seen` keeps the vault.
#[test]
fn left_identity_vault_list_proves_no_deletion() {
    let mut server = Server::default();
    let (mut a, f) = fixture_on(&mut server);
    let v = a.vault().id;
    let account_id = a.repo().account_id();
    let entries = vec![VaultListEntry {
        vault_id: v,
        created_at: T0,
        deleted_at: Some(T0 + 1),
    }];
    let mut body = ListBody::next(None, account_id, entries.clone()).unwrap();
    for _ in 0..4 {
        body = ListBody::next(Some(&body), account_id, entries.clone()).unwrap();
    }
    let forged = sign(a.repo().account(), VAULT_LIST_DOMAIN, body)
        .unwrap()
        .encode();
    let new_sk = SecretKey::generate().unwrap();
    let req = request(&f, &new_sk, vec![f.others[0].id()], RotationReason::Revoke);
    a.repo.as_mut().unwrap().rotate(req).unwrap();
    // Phase 1 lands; the session has not saved its device state.
    push_outbox(&mut server, &a).unwrap();
    assert_eq!(
        a.store().push_rotation_phase(1).unwrap(),
        PhaseOutcome::Done
    );

    let vault_rows = [
        RecordKind::VaultKey,
        RecordKind::VaultMeta,
        RecordKind::Manifest,
    ];
    let check = |a: &Device, stage: &str| {
        let store = a.store();
        let old_pin = store.device_state().unwrap().pinned.unwrap();
        assert_eq!(old_pin.identity_pub, f_old_identity(&store));
        // A fetch from scratch forgets every server tag first: the base
        // rows are checked after the incremental fetches only.
        for kind in vault_rows.iter().copied().filter(|_| stage != "full fetch") {
            assert!(
                store.server_meta(kind, v).unwrap().is_some(),
                "{stage}: {kind:?} base row"
            );
            assert!(
                store
                    .ignored_deletions()
                    .unwrap()
                    .iter()
                    .any(|d| d.kind == kind && d.id == v),
                "{stage}: {kind:?} deletion logged"
            );
        }
        assert!(store.device_state().unwrap().last_seen.contains_key(&v));
        let out = store.pending_changes().unwrap();
        for kind in vault_rows {
            assert!(
                out.iter()
                    .any(|c| c.kind == kind && c.id == v && c.data.is_some()),
                "{stage}: {kind:?} withheld"
            );
        }
    };

    server.replay(Record {
        id: account_id,
        kind: RecordKind::VaultList,
        version: 5,
        data: forged,
    });
    for kind in vault_rows {
        server.forge_deletion(kind, v);
    }
    // The window: the session is alive, its device state unsaved.
    pull(&server, &mut a);
    check(&a, "window");
    // A crash: the server tries again, then the device fetches from
    // scratch.
    a.repo = None;
    server.replay(server.get(RecordKind::VaultList, account_id).unwrap());
    for kind in vault_rows {
        server.forge_deletion(kind, v);
    }
    pull(&server, &mut a);
    check(&a, "after a crash");
    full_fetch(&server, &mut a);
    check(&a, "full fetch");
}

/// The identity the saved pin names before the session saves again: the
/// one the trust state retired last.
fn f_old_identity(store: &SyncStore) -> onepass_core::crypto::IdentityVerifyingKey {
    store
        .trust_state()
        .unwrap()
        .unwrap()
        .retired
        .last()
        .unwrap()
        .identity_pub
        .clone()
}

/// Review M3: the server took phase 1 but the acknowledgement was lost (no
/// `mark_pushed`). The next fetch brings the rotator's own records back;
/// a rebase and a sync finish the rotation.
#[test]
fn lost_acknowledgement_in_phase_one() {
    let mut server = Server::default();
    let (mut a, f) = fixture_on(&mut server);
    let expected = a.items();
    let new_sk = SecretKey::generate().unwrap();
    rotate(&mut a, &f, &new_sk);
    send(&mut server, &a, outbox(&a), false).unwrap();
    pull(&server, &mut a);
    assert_eq!(state(&a), rotating(1));
    a.repo().rebase().unwrap();
    sync(&mut server, &mut a).unwrap();
    assert_eq!(state(&a), DeviceLineageState::Current);
    assert!(outbox(&a).is_empty());
    assert_eq!(a.items(), expected);
}

// ---------------------------------------------------------------- follow

use onepass_core::lineage::resolve::PromptKind;
use onepass_core::repo::follow::{
    RotationPrompt, follow_rotation, follow_switch, pending_rotation, reject_rotation,
    stored_params_epoch,
};

/// Index of the follower C ("Mac") and of the revoked B ("iPad") in
/// `Fixture::others`.
const C: usize = 1;
const B: usize = 0;

/// A device on the server's account whose trust state is A's (before A
/// rotates), seen from `others[who]`: same genesis head and roster, its
/// own device public key. `edit` changes it before it is saved (local
/// names, levels). Locked, its device state persisted.
fn follower_with(
    server: &mut Server,
    a: &Device,
    f: &Fixture,
    who: usize,
    edit: impl FnOnce(&mut TrustState),
) -> Device {
    let mut c = Device::empty();
    pull(server, &mut c);
    c.unlock(&f.sk);
    let mut trust = a.store().trust_state().unwrap().unwrap();
    trust.me = f.others[who].public.clone();
    edit(&mut trust);
    c.repo()
        .store_mut()
        .put_all_if_version_with_trust(vec![], vec![], None, &trust)
        .unwrap();
    c.lock();
    c
}

/// A and C on one server; A rotates revoking B and pushes every phase; C
/// pulls everything (`keep` filters what reaches it). C stays locked.
fn rotated_with(
    edit: impl FnOnce(&mut TrustState),
    before_rotation: impl FnOnce(&mut Server, &mut Device, &Fixture),
    keep: impl Fn(&RemoteChange, &RotationOutcome, &Fixture) -> bool,
) -> (Server, Device, Device, Fixture, RotationOutcome, SecretKey) {
    let mut server = Server::default();
    let (mut a, f) = fixture_on(&mut server);
    let mut c = follower_with(&mut server, &a, &f, C, edit);
    before_rotation(&mut server, &mut c, &f);
    let new_sk = SecretKey::generate().unwrap();
    let req = request(&f, &new_sk, vec![f.others[B].id()], RotationReason::Revoke);
    let out = a.repo.as_mut().unwrap().rotate(req).unwrap();
    sync(&mut server, &mut a).unwrap();
    assert_eq!(state(&a), DeviceLineageState::Current);
    pull_only(&server, &mut c, |ch| keep(ch, &out, &f));
    (server, a, c, f, out, new_sk)
}

fn rotated() -> (Server, Device, Device, Fixture, RotationOutcome, SecretKey) {
    rotated_with(|_| {}, |_, _, _| {}, |_, _, _| true)
}

fn prompt_of(c: &Device) -> Option<RotationPrompt> {
    pending_rotation(&c.store()).unwrap()
}

#[test]
fn honest_follow() {
    let (_server, mut a, mut c, f, out, new_sk) = rotated();
    let body = rotation_of(&a.store(), &out.head);
    let old_identity = c.store().trust_state().unwrap().unwrap().identity_pub;

    let prompt = prompt_of(&c).expect("a prompt");
    assert_eq!(prompt.kind, PromptKind::Single);
    assert_eq!(prompt.choices.len(), 1);
    let choice = &prompt.choices[0];
    assert_eq!(choice.hash, out.head);
    assert_eq!(choice.rotator_name, "iPhone");
    assert_eq!(choice.revoked_names, vec!["iPad".to_string()]);
    assert_eq!(choice.issued_at, body.issued_at);
    assert_eq!(prompt.code, Some(out.code));
    assert!(!prompt.tofu_signer);
    assert!(!prompt.pending_password_change);

    let (repo, auk, sk) =
        follow_rotation(c.store(), out.head, PASSWORD, &f.others[C].keys).unwrap();
    assert_eq!(sk.to_display(), new_sk.to_display());
    // R12: the vaults start from the manifests the rotation was made from.
    assert_eq!(repo.device_state().last_seen, body.from_heads);
    assert_eq!(repo.account().params.identity_pub, body.identity_pub);
    c.repo = Some(repo);

    let trust = c.store().trust_state().unwrap().unwrap();
    assert_eq!(
        trust.head,
        LineageHead {
            generation: 1,
            hash: out.head
        }
    );
    assert_eq!(trust.state, DeviceLineageState::Current);
    assert_self_pinned(&trust);
    assert_self_pinned(&a.store().trust_state().unwrap().unwrap());
    assert_eq!(trust.identity_pub, body.identity_pub);
    assert_eq!(trust.roster, body.roster);
    assert!(trust.revoked.contains(&f.others[B].id()));
    assert_eq!(trust.retired.last().unwrap().identity_pub, old_identity);
    assert_eq!(
        RecordStore::chain_state(&c.store()).unwrap().params_epoch,
        1
    );
    assert_eq!(prompt_of(&c), None);

    // Every item, under the new identity.
    assert_eq!(c.items(), a.items());
    let v = c.vault();
    c.save(&login(v.id, "dave", T0 + 90));
    c.lock();
    // The new keys open the device again; the old ones do not.
    assert!(c.try_unlock(PASSWORD, &f.sk).is_err());
    c.try_unlock(PASSWORD, &new_sk).unwrap();
    c.try_unlock_with_auk(&auk).unwrap();
    assert_eq!(c.items().len(), a.items().len() + 1);
}

#[test]
fn prompt_names_come_from_local_roster() {
    let (_server, _a, c, f, _out, _sk) = rotated_with(
        |t| {
            for e in &mut t.roster {
                if e.name == "iPhone" {
                    e.name = "Téléphone de Camille".into();
                } else if e.name == "iPad" {
                    e.name = "Tablette du salon".into();
                }
            }
            let a = t.roster.iter().find(|e| e.name.starts_with("Tél")).unwrap();
            t.levels.insert(a.device_id, TrustLevel::Tofu);
        },
        |_, _, _| {},
        |_, _, _| true,
    );
    let _ = &f;
    let prompt = prompt_of(&c).unwrap();
    assert!(prompt.tofu_signer);
    assert!(prompt.choices[0].complete);
    assert_eq!(prompt.choices[0].rotator_name, "Téléphone de Camille");
    assert_eq!(
        prompt.choices[0].revoked_names,
        vec!["Tablette du salon".to_string()]
    );
}

/// Port of `zz6`: a device that only ever unlocked with biometrics (the
/// Account Unlock Key) follows with the master password and its device
/// keys; there is no Secret Key to type.
#[test]
fn biometric_device_follows_with_password_only() {
    let mut auk_kept = None;
    let (_server, a, mut c, f, out, _sk) = rotated_with(
        |_| {},
        |_, c, f| {
            let auk = c.try_unlock(PASSWORD, &f.sk).unwrap();
            c.lock();
            c.try_unlock_with_auk(&auk).unwrap();
            c.lock();
            auk_kept = Some(auk);
        },
        |_, _, _| true,
    );
    let old_auk = auk_kept.unwrap();
    let (repo, auk, _sk) =
        follow_rotation(c.store(), out.head, PASSWORD, &f.others[C].keys).unwrap();
    drop(repo);
    // The old enrollment no longer opens the account; the new one does.
    assert!(c.try_unlock_with_auk(&old_auk).is_err());
    c.try_unlock_with_auk(&auk).unwrap();
    assert_eq!(c.items().len(), f.items.len());
    drop(a);
}

#[test]
fn wrong_password_changes_nothing() {
    let (_server, _a, c, f, out, _sk) = rotated();
    let before = snapshot(&c.store());
    let device = c.store().device_state().unwrap();
    let r = follow_rotation(c.store(), out.head, NEW_PASSWORD, &f.others[C].keys);
    assert!(matches!(r, Err(Error::WrongPassword)), "{:?}", r.err());
    assert_eq!(snapshot(&c.store()), before);
    assert_eq!(c.store().device_state().unwrap(), device);
    assert!(prompt_of(&c).is_some());
}

#[test]
fn follow_waits_for_completeness() {
    let (_server, _a, c, f, out, _sk) = rotated_with(
        |_| {},
        |_, _, _| {},
        |ch, out, f| {
            !(ch.kind == RecordKind::KeyDelivery
                && ch.id == delivery_id(&out.head, f.others[C].id()))
        },
    );
    // Controller ruling (fix round 1): a valid record this device cannot
    // complete is shown, marked incomplete; following it is refused.
    let prompt = prompt_of(&c).expect("a prompt");
    assert_eq!(prompt.kind, PromptKind::Single);
    assert_eq!(prompt.choices[0].hash, out.head);
    assert!(!prompt.choices[0].complete);
    let before = snapshot(&c.store());
    let r = follow_rotation(c.store(), out.head, PASSWORD, &f.others[C].keys);
    assert_eq!(r.err(), Some(Error::NotFound));
    assert_eq!(snapshot(&c.store()), before);
    // The device is read-only at once, and "Ce n'était pas moi" works.
    let mut c = c;
    c.unlock(&f.sk);
    assert!(c.repo().pending_prompt().is_some());
    assert_eq!(
        state(&c),
        DeviceLineageState::Candidate {
            children: vec![out.head],
            resume: None,
        }
    );
    c.lock();
    reject_rotation(&mut c.store(), out.head, true).unwrap();
    assert_eq!(state(&c), DeviceLineageState::Current);
    assert_eq!(prompt_of(&c), None);
}

#[test]
fn substituted_delivery_refused() {
    let mut server = Server::default();
    let (mut a, f) = fixture_on(&mut server);
    let c_dev = follower_with(&mut server, &a, &f, C, |_| {});
    let new_sk = SecretKey::generate().unwrap();
    let req = request(&f, &new_sk, vec![f.others[B].id()], RotationReason::Revoke);
    let out = a.repo.as_mut().unwrap().rotate(req).unwrap();
    sync(&mut server, &mut a).unwrap();
    // The server swaps C's envelope for one of its own making.
    let id = delivery_id(&out.head, f.others[C].id());
    let mut env = server.get(RecordKind::KeyDelivery, id).unwrap();
    *env.data.last_mut().unwrap() ^= 1;
    server.replay(env);
    let mut c = c_dev;
    pull(&server, &mut c);

    let before = snapshot(&c.store());
    let r = follow_rotation(c.store(), out.head, PASSWORD, &f.others[C].keys);
    assert_eq!(integrity(r.map(|_| ())), IntegrityError::Signature);
    assert_eq!(snapshot(&c.store()), before);
}

#[test]
fn cut_during_follow() {
    let (_server, _a, c, f, out, _sk) = rotated();
    let before = snapshot(&c.store());
    let device = c.store().device_state().unwrap();
    let store = Faulty {
        inner: c.store(),
        fail_commit: true,
        broken: Cell::new(false),
        race: None,
    };
    let r = follow_rotation(store, out.head, PASSWORD, &f.others[C].keys);
    assert!(matches!(r, Err(Error::Store(_))), "{:?}", r.err());
    assert_eq!(snapshot(&c.store()), before);
    assert_eq!(c.store().device_state().unwrap(), device);
    let trust = c.store().trust_state().unwrap().unwrap();
    assert_eq!(trust.head.generation, 0);
    assert_eq!(trust.state, DeviceLineageState::Current);
}

/// K9: a normal unlock never follows. It opens the old identity, read
/// only, and reports the pending prompt. C has the rotation's phase 1
/// records, not yet the re-sealed vaults, so its vault still reads.
#[test]
fn normal_unlock_never_follows() {
    let (_server, _a, mut c, f, out, _sk) = rotated_with(
        |_| {},
        |_, _, _| {},
        |ch, _, _| {
            !matches!(
                ch.kind,
                RecordKind::VaultKey
                    | RecordKind::VaultMeta
                    | RecordKind::Manifest
                    | RecordKind::Item
            )
        },
    );
    let old = c.store().trust_state().unwrap().unwrap();
    c.unlock(&f.sk);
    assert_eq!(c.repo().account().params.identity_pub, old.identity_pub);
    let prompt = c.repo().pending_prompt().cloned().expect("pending prompt");
    assert_eq!(prompt.choices[0].hash, out.head);
    let trust = c.store().trust_state().unwrap().unwrap();
    assert_eq!(trust.head, old.head);
    assert_eq!(trust.identity_pub, old.identity_pub);
    assert_eq!(
        trust.state,
        DeviceLineageState::Candidate {
            children: vec![out.head],
            resume: None,
        }
    );
    let before = snapshot(&c.store());
    let v = c.vault();
    assert_eq!(c.repo().items(&v).unwrap().len(), f.items.len());
    let ro = Some(Error::ReadOnly);
    assert_eq!(
        c.repo().save_item(&v, login(v.id, "eve", T0 + 80)).err(),
        ro
    );
    assert_eq!(c.repo().create_vault(meta("Travail")).err(), ro);
    assert_eq!(snapshot(&c.store()), before);
    // Locked and unlocked again: still the old identity, still waiting.
    c.lock();
    c.unlock(&f.sk);
    assert!(c.repo().pending_prompt().is_some());
    assert_eq!(c.repo().account().params.identity_pub, old.identity_pub);
}

/// R10: nothing is written while the device is `Candidate`.
#[test]
fn candidate_is_read_only() {
    // C has A's rotation (phase 1 only, its vault still reads) and waits.
    let (_server, _x, mut a, f, out, _sk) = rotated_with(
        |_| {},
        |_, _, _| {},
        |ch, _, _| {
            !matches!(
                ch.kind,
                RecordKind::VaultKey
                    | RecordKind::VaultMeta
                    | RecordKind::Manifest
                    | RecordKind::Item
            )
        },
    );
    a.unlock(&f.sk);
    assert_eq!(
        state(&a),
        DeviceLineageState::Candidate {
            children: vec![out.head],
            resume: None,
        }
    );
    let before = snapshot(&a.store());
    let v = a.vault();
    let items = a.repo().items(&v).unwrap();
    assert_eq!(items.len(), f.items.len());
    let ro = Some(Error::ReadOnly);
    assert_eq!(
        a.repo().save_item(&v, login(v.id, "eve", T0 + 80)).err(),
        ro
    );
    assert_eq!(a.repo().trash_item(&v, f.items[0].id).err(), ro);
    assert_eq!(a.repo().delete_item(&v, f.items[0].id).err(), ro);
    assert_eq!(a.repo().create_vault(meta("Travail")).err(), ro);
    assert_eq!(a.repo().update_vault_meta(&v, meta("Perso")).err(), ro);
    assert_eq!(
        a.repo()
            .change_password(PASSWORD, &f.sk, NEW_PASSWORD)
            .err(),
        ro
    );
    assert_eq!(a.repo().issue_restore_epoch(EpochReason::Restore).err(), ro);
    assert_eq!(snapshot(&a.store()), before);
}

#[test]
fn reject_excludes_the_signer() {
    let (_server, _a, mut c, f, out, _sk) = rotated();
    let mut store = c.store();
    reject_rotation(&mut store, out.head, true).unwrap();
    let trust = c.store().trust_state().unwrap().unwrap();
    assert_eq!(trust.state, DeviceLineageState::Current);
    assert!(trust.excluded.contains(&f.me.id()));
    assert_eq!(trust.ignored, vec![out.head]);
    assert_eq!(trust.head.generation, 0);
    assert_eq!(prompt_of(&c), None);
    // A choice that is not offered any more is refused.
    let r = reject_rotation(&mut store, out.head, false);
    assert!(is_validation(&r), "{r:?}");
    // The next unlock opens the old identity with nothing pending.
    c.unlock(&f.sk);
    assert!(c.repo().pending_prompt().is_none());
    assert_eq!(state(&c), DeviceLineageState::Current);
}

#[test]
fn pending_password_change_is_reported() {
    let (_server, _a, c, _f, _out, _sk) = rotated_with(
        |_| {},
        |_, c, f| {
            c.unlock(&f.sk);
            c.repo()
                .change_password(PASSWORD, &f.sk, NEW_PASSWORD)
                .unwrap();
            c.lock();
        },
        |_, _, _| true,
    );
    let prompt = prompt_of(&c).unwrap();
    assert!(prompt.pending_password_change);
}

/// Task 6 deferred minor: the "password changed elsewhere" poll reads the
/// params of the trust state's identity, before and after following.
#[test]
fn params_epoch_poll_follows_the_trust_state() {
    let (_server, _a, c, f, out, _sk) = rotated();
    let pin = c.store().device_state().unwrap().pinned;
    assert_eq!(stored_params_epoch(&c.store(), pin.as_ref()).unwrap(), 1);
    let (repo, _, _) = follow_rotation(c.store(), out.head, PASSWORD, &f.others[C].keys).unwrap();
    drop(repo);
    let pin = c.store().device_state().unwrap().pinned;
    assert_eq!(stored_params_epoch(&c.store(), pin.as_ref()).unwrap(), 1);
}

/// Ledger (Task 7): a trust state changed by another writer since follow
/// read it is a conflict, and nothing is written.
#[test]
fn follow_loses_a_trust_race() {
    let (_server, _a, c, f, out, _sk) = rotated();
    let device = c.store().device_state().unwrap();
    let chain = RecordStore::chain_state(&c.store()).unwrap();
    let records = snapshot(&c.store()).records;
    let mut other = c.store().trust_state().unwrap().unwrap();
    other.excluded.insert(Id([0xEE; 16]));
    let store = Faulty {
        inner: c.store(),
        fail_commit: false,
        broken: Cell::new(false),
        race: Some(other.clone()),
    };
    let r = follow_rotation(store, out.head, PASSWORD, &f.others[C].keys);
    assert!(matches!(r, Err(Error::Conflict)), "{:?}", r.err());
    // Only the other writer's trust state landed.
    assert_eq!(c.store().trust_state().unwrap(), Some(other));
    assert_eq!(c.store().device_state().unwrap(), device);
    assert_eq!(RecordStore::chain_state(&c.store()).unwrap(), chain);
    assert_eq!(snapshot(&c.store()).records, records);
}

#[test]
fn rotate_loses_a_trust_race() {
    let (a, f) = fixture();
    let mut other = a.store().trust_state().unwrap().unwrap();
    other.excluded.insert(Id([0xEE; 16]));
    let inner = a.store();
    let state = inner.device_state().unwrap();
    let store = Faulty {
        inner,
        fail_commit: false,
        broken: Cell::new(false),
        race: Some(other.clone()),
    };
    let mut repo = Repository::unlock(store, PASSWORD, &f.sk, state).unwrap();
    let before = snapshot(&a.store());
    let new_sk = SecretKey::generate().unwrap();
    let r = repo.rotate(request(&f, &new_sk, vec![], RotationReason::Rotate));
    assert!(matches!(r, Err(Error::Conflict)), "{r:?}");
    let after = snapshot(&a.store());
    assert_eq!(after.records, before.records);
    assert_eq!(after.outbox, before.outbox);
    assert_eq!(after.trust, Some(other.encode()));
}

/// Spec 8.3: A revokes B, B revokes A. C asks which one the user still
/// holds; keeping A excludes B and ignores B's record.
#[test]
fn mutual_choice_excludes_the_other_signer() {
    let mut server = Server::default();
    let (mut a, f) = fixture_on(&mut server);
    let mut b = follower_with(&mut server, &a, &f, B, |_| {});
    let mut c = follower_with(&mut server, &a, &f, C, |_| {});

    let a_sk = SecretKey::generate().unwrap();
    let req = request(&f, &a_sk, vec![f.others[B].id()], RotationReason::Revoke);
    let ra = a.repo.as_mut().unwrap().rotate(req).unwrap();
    sync(&mut server, &mut a).unwrap();

    b.unlock(&f.sk);
    let b_sk = SecretKey::generate().unwrap();
    let mut req = request(&f, &b_sk, vec![f.me.id()], RotationReason::Revoke);
    req.device_keys = &f.others[B].keys;
    let rb = b.repo.as_mut().unwrap().rotate(req).unwrap();
    // Phase 1 only: B's record, deliveries, params and keyset.
    push_outbox(&mut server, &b).unwrap();

    pull(&server, &mut c);
    let prompt = prompt_of(&c).expect("a prompt");
    assert_eq!(prompt.kind, PromptKind::Mutual);
    assert_eq!(prompt.code, None);
    let mut hashes: Vec<[u8; 32]> = prompt.choices.iter().map(|ch| ch.hash).collect();
    hashes.sort();
    let mut both = vec![ra.head, rb.head];
    both.sort();
    assert_eq!(hashes, both);
    let of_a = prompt.choices.iter().find(|ch| ch.hash == ra.head).unwrap();
    assert_eq!(of_a.rotator_name, "iPhone");
    assert_eq!(of_a.revoked_names, vec!["iPad".to_string()]);
    let of_b = prompt.choices.iter().find(|ch| ch.hash == rb.head).unwrap();
    assert_eq!(of_b.rotator_name, "iPad");
    assert_eq!(of_b.revoked_names, vec!["iPhone".to_string()]);

    let (repo, _, sk) = follow_rotation(c.store(), ra.head, PASSWORD, &f.others[C].keys).unwrap();
    assert_eq!(sk.to_display(), a_sk.to_display());
    drop(repo);
    let trust = c.store().trust_state().unwrap().unwrap();
    assert_eq!(trust.head.hash, ra.head);
    assert!(trust.excluded.contains(&f.others[B].id()));
    assert!(trust.revoked.contains(&f.others[B].id()));
    assert_eq!(trust.ignored, vec![rb.head]);
    assert_eq!(prompt_of(&c), None);
}

/// Review I1: a session unlocked before the rotation arrives becomes
/// read-only as soon as a sync brings it, without an app call.
#[test]
fn session_open_before_rotation_becomes_read_only() {
    let mut server = Server::default();
    let (mut a, f) = fixture_on(&mut server);
    let mut c = follower_with(&mut server, &a, &f, C, |_| {});
    c.unlock(&f.sk);
    let v = c.vault();
    c.repo().save_item(&v, login(v.id, "eve", T0 + 80)).unwrap();
    let new_sk = SecretKey::generate().unwrap();
    let req = request(&f, &new_sk, vec![f.others[B].id()], RotationReason::Revoke);
    let out = a.repo.as_mut().unwrap().rotate(req).unwrap();
    sync(&mut server, &mut a).unwrap();
    pull(&server, &mut c);
    let r = c.repo().save_item(&v, login(v.id, "frank", T0 + 90));
    assert_eq!(r, Err(Error::ReadOnly));
    let prompt = c.repo().pending_prompt().cloned().expect("pending prompt");
    assert_eq!(prompt.choices[0].hash, out.head);
    assert_eq!(
        state(&c),
        DeviceLineageState::Candidate {
            children: vec![out.head],
            resume: None,
        }
    );
}

/// Review I2: following one rotation while the next one is known leaves
/// the new session read-only, prompting for the next.
#[test]
fn follow_then_next_rotation_is_pending() {
    let mut server = Server::default();
    let (mut a, f) = fixture_on(&mut server);
    let mut c = follower_with(&mut server, &a, &f, C, |_| {});
    let sk1 = SecretKey::generate().unwrap();
    let req = request(&f, &sk1, vec![f.others[B].id()], RotationReason::Revoke);
    let r1 = a.repo.as_mut().unwrap().rotate(req).unwrap();
    sync(&mut server, &mut a).unwrap();
    let sk2 = SecretKey::generate().unwrap();
    let mut req = request(&f, &sk2, vec![], RotationReason::Rotate);
    req.secret_key = &sk1;
    let r2 = a.repo.as_mut().unwrap().rotate(req).unwrap();
    sync(&mut server, &mut a).unwrap();
    pull(&server, &mut c);

    let prompt = prompt_of(&c).unwrap();
    assert_eq!(prompt.choices[0].hash, r1.head);
    let (repo, _, _) = follow_rotation(c.store(), r1.head, PASSWORD, &f.others[C].keys).unwrap();
    c.repo = Some(repo);
    let next = c.repo().pending_prompt().cloned().expect("next prompt");
    assert_eq!(next.choices[0].hash, r2.head);
    assert_eq!(
        state(&c),
        DeviceLineageState::Candidate {
            children: vec![r2.head],
            resume: None,
        }
    );
    let r = c.repo().create_vault(meta("Travail"));
    assert_eq!(r.err(), Some(Error::ReadOnly));
}

/// Review M1: following is refused outside `Current` and `Candidate`.
#[test]
fn follow_refused_while_rotating() {
    let (_server, _a, c, f, out, _sk) = rotated();
    let mut trust = c.store().trust_state().unwrap().unwrap();
    trust.state = DeviceLineageState::Rotating { phase: 2 };
    c.store()
        .put_all_if_version_with_trust(vec![], vec![], None, &trust)
        .unwrap();
    let before = snapshot(&c.store());
    let r = follow_rotation(c.store(), out.head, PASSWORD, &f.others[C].keys);
    assert!(is_validation(&r.map(|_| ())));
    assert_eq!(snapshot(&c.store()), before);
}

// ---------------------------------------------------------------- own writes

use onepass_core::repo::replay::ReplayReport;
use onepass_core::trust::{MAX_OWN_WRITES, OWN_WRITE_MAX_AGE_SECS, OwnWrite, OwnWriteLog};

/// A device on the server's account under the identity A leaves, with no
/// trust state: it cannot tell a rotation from anything else (the revoked
/// iPad, a device that never updated). Unlocked.
fn old_device(server: &Server, f: &Fixture) -> Device {
    let mut d = Device::empty();
    pull(server, &mut d);
    d.unlock(&f.sk);
    d
}

/// A commits a rotation revoking B (not pushed yet). Then C, unlocked on
/// the old identity, writes "pushed" and pushes it (so A's content, made
/// from the view A had, lacks it), and writes "pending" without pushing.
/// A pushes every phase; C pulls everything, its session still open.
fn rotation_during_writes() -> (Server, Device, Device, Fixture, RotationOutcome) {
    let mut server = Server::default();
    let (mut a, f) = fixture_on(&mut server);
    let mut c = follower_with(&mut server, &a, &f, C, |_| {});
    c.unlock(&f.sk);
    let new_sk = SecretKey::generate().unwrap();
    let req = request(&f, &new_sk, vec![f.others[B].id()], RotationReason::Revoke);
    let out = a.repo.as_mut().unwrap().rotate(req).unwrap();
    let v = c.vault();
    c.repo()
        .save_item(&v, login(v.id, "pushed", T0 + 50))
        .unwrap();
    sync(&mut server, &mut c).unwrap();
    c.repo()
        .save_item(&v, login(v.id, "pending", T0 + 60))
        .unwrap();
    sync(&mut server, &mut a).unwrap();
    assert_eq!(state(&a), DeviceLineageState::Current);
    pull(&server, &mut c);
    (server, a, c, f, out)
}

fn all_users() -> Vec<String> {
    let mut u: Vec<String> = ["alice", "bob", "carol", "pending", "pushed"]
        .map(String::from)
        .to_vec();
    u.sort();
    u
}

#[test]
fn writes_during_rotation_survive() {
    let (mut server, mut a, mut c, f, out) = rotation_during_writes();
    let v = c.vault().id;
    let trust = c.store().trust_state().unwrap().unwrap();
    let mine: BTreeSet<Id> = trust.own_writes.entries.iter().map(|w| w.item).collect();
    assert_eq!(mine.len(), 2, "both writes logged");
    let old_blobs = item_blobs(&c.store(), v);

    let (repo, _, _) = follow_rotation(c.store(), out.head, PASSWORD, &f.others[C].keys).unwrap();
    c.repo = Some(repo);
    assert_eq!(users(&c.items()), all_users());
    let trust = c.store().trust_state().unwrap().unwrap();
    assert!(trust.own_writes.replay.is_empty());
    assert!(trust.own_writes.replay_heads.is_empty());
    assert!(!trust.own_writes.alert);
    assert!(c.store().retained_rows(v).unwrap().is_empty());
    // Nothing sealed under the old keys goes out.
    let outbox = outbox(&c);
    assert!(!outbox.is_empty());
    assert!(outbox.iter().all(|(ch, _)| ch.kind != RecordKind::Item
        || !old_blobs.contains(&ch.id)
        || ch.data.is_none()));
    // The replay reaches the others under the new identity.
    sync(&mut server, &mut c).unwrap();
    pull(&server, &mut a);
    assert_eq!(users(&a.items()), all_users());
}

/// R11: what another device wrote under the identity left after
/// `from_heads` is not imported; its author replays it.
#[test]
fn other_device_late_write_not_imported() {
    let mut server = Server::default();
    let (mut a, f) = fixture_on(&mut server);
    let mut c = follower_with(&mut server, &a, &f, C, |_| {});
    let mut ipad = old_device(&server, &f);
    let new_sk = SecretKey::generate().unwrap();
    let req = request(&f, &new_sk, vec![f.others[B].id()], RotationReason::Revoke);
    let out = a.repo.as_mut().unwrap().rotate(req).unwrap();
    let v = ipad.vault();
    ipad.repo()
        .save_item(&v, login(v.id, "forged", T0 + 50))
        .unwrap();
    sync(&mut server, &mut ipad).unwrap();
    c.unlock(&f.sk);
    pull(&server, &mut c);
    assert!(users(&c.items()).contains(&"forged".to_string()));
    sync(&mut server, &mut a).unwrap();
    pull(&server, &mut c);

    let (repo, _, _) = follow_rotation(c.store(), out.head, PASSWORD, &f.others[C].keys).unwrap();
    c.repo = Some(repo);
    assert_eq!(
        users(&c.items()),
        ["alice", "bob", "carol"].map(String::from)
    );
    // A, under the new identity, leaves the forged record alone too.
    assert_eq!(
        users(&a.items()),
        ["alice", "bob", "carol"].map(String::from)
    );
}

fn intent(n: u32, at: i64) -> OwnWrite {
    let mut item = [0u8; 16];
    item[..4].copy_from_slice(&n.to_be_bytes());
    OwnWrite {
        vault: Id([1; 16]),
        item: Id(item),
        based_on: SeenManifest {
            seq: 1,
            hash: [0; 32],
        },
        at,
        wrote: None,
    }
}

#[test]
fn log_bounds() {
    let now = T0;
    let mut log = OwnWriteLog::default();
    for n in 0..=MAX_OWN_WRITES as u32 {
        log.record(intent(n, now), false);
    }
    assert_eq!(log.entries.len(), MAX_OWN_WRITES);
    assert_eq!(log.entries[0], intent(1, now), "the oldest went");
    assert!(!log.alert, "no rotation waits: nothing needed was dropped");

    // Waiting for a replay: intents older than 30 days go, with the alert.
    let mut log = OwnWriteLog::default();
    log.record(intent(1, now - OWN_WRITE_MAX_AGE_SECS - 1), false);
    log.record(intent(2, now - OWN_WRITE_MAX_AGE_SECS), false);
    log.adopt(&BTreeMap::new());
    log.prune(now, false);
    assert_eq!(log.replay, vec![intent(2, now - OWN_WRITE_MAX_AGE_SECS)]);
    assert!(log.alert);

    // Candidate: an intent written now drops the expired ones, alert raised.
    let mut log = OwnWriteLog::default();
    log.record(intent(1, now - OWN_WRITE_MAX_AGE_SECS - 1), false);
    log.record(intent(2, now), true);
    assert_eq!(log.entries, vec![intent(2, now)]);
    assert!(log.alert);
    // The trust state holds the bounds.
    let mut trust = TrustState::decode(&{
        let (_server, _a, c, _f, _out, _sk) = rotated();
        c.store().trust_state().unwrap().unwrap().encode()
    })
    .unwrap();
    trust.own_writes = log;
    assert_eq!(TrustState::decode(&trust.encode()).unwrap(), trust);
}

#[test]
fn replay_is_idempotent() {
    let (_server, _a, mut c, f, out) = rotation_during_writes();
    let before = c.store().trust_state().unwrap().unwrap().own_writes;
    let (repo, _, _) = follow_rotation(c.store(), out.head, PASSWORD, &f.others[C].keys).unwrap();
    c.repo = Some(repo);
    assert_eq!(users(&c.items()), all_users());

    // A second follow is refused and changes nothing; a second replay is
    // a no-op.
    let snap = snapshot(&c.store());
    let again = follow_rotation(c.store(), out.head, PASSWORD, &f.others[C].keys);
    assert!(again.is_err());
    assert_eq!(
        c.repo().replay_own_writes().unwrap(),
        ReplayReport::default()
    );
    assert_eq!(snapshot(&c.store()), snap);

    // The rebase path replays nothing a second time.
    c.repo().rebase().unwrap();
    assert_eq!(snapshot(&c.store()), snap);
    assert_eq!(users(&c.items()), all_users());
    assert!(!before.entries.is_empty());
}

/// The rebase a sync runs while the device waits on the prompt writes
/// nothing (R10); after the follow, the replay brings each own write in
/// exactly once.
#[test]
fn rebase_while_candidate_then_replay_once() {
    let (_server, _a, mut c, f, out) = rotation_during_writes();
    let snap = snapshot(&c.store());
    let r = c.repo().rebase();
    assert!(r.is_err() || r == Ok(vec![]), "{r:?}");
    assert_eq!(snapshot(&c.store()).records, snap.records);
    assert_eq!(snapshot(&c.store()).outbox, snap.outbox);
    let (repo, _, _) = follow_rotation(c.store(), out.head, PASSWORD, &f.others[C].keys).unwrap();
    c.repo = Some(repo);
    c.repo().rebase().unwrap();
    let items = c.items();
    let ids: BTreeSet<Id> = items.iter().map(|i| i.id).collect();
    assert_eq!(ids.len(), items.len());
    assert_eq!(users(&items), all_users());
}

/// I4: a device that has not followed reads its own copy of every vault
/// after phase 2 re-sealed it; after the follow that copy is gone.
#[test]
fn candidate_reads_after_phase_two() {
    let (_server, _a, mut c, f, out, _sk) = rotated();
    c.unlock(&f.sk);
    assert_eq!(
        state(&c),
        DeviceLineageState::Candidate {
            children: vec![out.head],
            resume: None,
        }
    );
    let mut vaults = c.repo().vaults().unwrap();
    assert_eq!(vaults.len(), 1);
    let v = vaults.remove(0);
    assert!(!c.store().retained_rows(v.id).unwrap().is_empty());
    let mut items = c.repo().items(&v).unwrap();
    let mut want = f.items.clone();
    items.sort_by_key(|i| i.id);
    want.sort_by_key(|i| i.id);
    assert_eq!(users(&items), users(&want));
    assert_eq!(
        c.repo().save_item(&v, login(v.id, "eve", T0 + 80)).err(),
        Some(Error::ReadOnly)
    );
    c.lock();

    let (repo, _, _) = follow_rotation(c.store(), out.head, PASSWORD, &f.others[C].keys).unwrap();
    c.repo = Some(repo);
    assert!(c.store().retained_rows(v.id).unwrap().is_empty());
    assert_eq!(users(&c.items()), users(&want));
}

/// I5: writes made before the prompt are not pushed under the old keys
/// while the device waits; the replay sends them under the new ones.
#[test]
fn candidate_holds_pending_vault_writes() {
    let (_server, _x, mut c, f, out, _sk) = rotated_with(
        |_| {},
        |server, c, f| {
            c.unlock(&f.sk);
            let v = c.vault();
            c.repo().save_item(&v, login(v.id, "eve", T0 + 80)).unwrap();
            c.lock();
            let _ = server;
        },
        |ch, _, _| {
            !matches!(
                ch.kind,
                RecordKind::VaultKey
                    | RecordKind::VaultMeta
                    | RecordKind::Manifest
                    | RecordKind::Item
            )
        },
    );
    // The stored state is still `Current` (no session looked yet): the
    // prompt found now holds the writes anyway.
    assert_eq!(state(&c), DeviceLineageState::Current);
    assert!(prompt_of(&c).is_some());
    let pending: Vec<_> = outbox(&c);
    assert!(
        pending.iter().all(|(ch, _)| ch.kind.is_immutable()),
        "{pending:?}"
    );
    c.unlock(&f.sk);
    assert!(outbox(&c).iter().all(|(ch, _)| ch.kind.is_immutable()));
    c.lock();

    let (repo, _, _) = follow_rotation(c.store(), out.head, PASSWORD, &f.others[C].keys).unwrap();
    c.repo = Some(repo);
    // Phase 2 is not here: the replay waits, the writes stay held.
    let trust = c.store().trust_state().unwrap().unwrap();
    assert_eq!(trust.own_writes.replay.len(), 1);
    let v = trust.own_writes.replay[0].vault;
    assert!(outbox(&c).iter().all(|(ch, _)| {
        let vault_row = matches!(
            ch.kind,
            RecordKind::Manifest | RecordKind::VaultKey | RecordKind::VaultMeta
        ) && ch.id == v;
        let item_row = ch.kind == RecordKind::Item
            && ch
                .data
                .as_ref()
                .is_some_and(|d| split_item_record(d).unwrap().0 == v);
        !vault_row && !item_row
    }));
}

/// Travel Mode writes are gated like the others (R10).
#[test]
fn travel_refused_while_candidate() {
    let (_server, _a, mut c, f, out, _sk) = rotated();
    c.unlock(&f.sk);
    assert_eq!(
        state(&c),
        DeviceLineageState::Candidate {
            children: vec![out.head],
            resume: None,
        }
    );
    let upstream = c.store();
    let ro = Some(Error::ReadOnly);
    assert_eq!(c.repo().enter_travel(&upstream).err(), ro);
    let parked = TravelState {
        parked: BTreeMap::new(),
        entered_at: T0,
        parked_items: Default::default(),
    };
    assert_eq!(c.repo().exit_travel(&upstream, &parked).err(), ro);
    assert_eq!(c.repo().exit_travel_unpinned(&upstream).err(), ro);
}

// ------------------------------------------------- fix round 1 (review)

/// A commits a rotation (not pushed). C writes X ("mine") and pushes it,
/// then the revoked iPad, still on the old identity, overwrites X
/// ("forged", later) or deletes it (`delete`), and pushes. C pulls that
/// without loading, A pushes every phase, C pulls and follows.
fn overtaken_by_revoked(delete: bool) -> (Server, Device, Device, Id) {
    let mut server = Server::default();
    let (mut a, f) = fixture_on(&mut server);
    let mut c = follower_with(&mut server, &a, &f, C, |_| {});
    let mut ipad = old_device(&server, &f);
    let new_sk = SecretKey::generate().unwrap();
    let req = request(&f, &new_sk, vec![f.others[B].id()], RotationReason::Revoke);
    let out = a.repo.as_mut().unwrap().rotate(req).unwrap();
    c.unlock(&f.sk);
    let v = c.vault();
    let x = login(v.id, "mine", T0 + 50);
    c.repo().save_item(&v, x.clone()).unwrap();
    sync(&mut server, &mut c).unwrap();
    c.lock();
    pull(&server, &mut ipad);
    let iv = ipad.vault();
    if delete {
        ipad.repo().delete_item(&iv, x.id).unwrap();
    } else {
        ipad.repo()
            .save_item(&iv, edited(&x, "forged", T0 + 70))
            .unwrap();
    }
    sync(&mut server, &mut ipad).unwrap();
    // C reads the vault as the iPad left it (a clean load).
    c.unlock(&f.sk);
    pull(&server, &mut c);
    let _ = c.items();
    c.lock();
    sync(&mut server, &mut a).unwrap();
    pull(&server, &mut c);
    let (repo, _, _) = follow_rotation(c.store(), out.head, PASSWORD, &f.others[C].keys).unwrap();
    c.repo = Some(repo);
    sync(&mut server, &mut c).unwrap();
    pull(&server, &mut a);
    (server, a, c, x.id)
}

/// Review C1 (R11): the replay brings back this device's own record of an
/// item, never what the revoked device wrote over it under the old
/// identity.
#[test]
fn replay_never_imports_an_overwrite_by_another_device() {
    let (_server, mut a, mut c, _x) = overtaken_by_revoked(false);
    let alert = c.store().trust_state().unwrap().unwrap().own_writes.alert;
    for dev in [&mut c, &mut a] {
        let u = users(&dev.items());
        assert!(!u.contains(&"forged".to_string()), "{u:?}");
        // Its own record is gone from the device: not replayed, flagged.
        assert!(u.contains(&"mine".to_string()) || alert, "{u:?}");
    }
}

/// Task 17 (carried from Task 10, G4): an intent the replay could not
/// bring back stays named, (vault, item), until the user saw the alert.
#[test]
fn lost_own_writes_are_named_until_seen() {
    let (_server, _a, mut c, x) = overtaken_by_revoked(false);
    let alert = c.repo().own_write_alert().unwrap();
    if alert.alert {
        assert!(alert.lost.iter().any(|(_, item)| *item == x), "{alert:?}");
        c.repo().clear_own_write_alert().unwrap();
        let after = c.repo().own_write_alert().unwrap();
        assert!(!after.alert && after.lost.is_empty());
    } else {
        // Replayed from its own copy: nothing to name.
        assert!(alert.lost.is_empty());
    }
}

/// Review C1, deletion variant: a deletion by the revoked device never
/// removes this device's write.
#[test]
fn replay_never_imports_a_deletion_by_another_device() {
    let (_server, mut a, mut c, _x) = overtaken_by_revoked(true);
    let alert = c.store().trust_state().unwrap().unwrap().own_writes.alert;
    for dev in [&mut c, &mut a] {
        let u = users(&dev.items());
        assert!(u.contains(&"mine".to_string()) || alert, "{u:?}");
    }
}

/// A commits a rotation (not pushed); `during` runs on C, unlocked on the
/// old identity, before A pushes every phase; C pulls and follows.
fn follow_after(during: impl FnOnce(&mut Device)) -> (Server, Device, Device) {
    let mut server = Server::default();
    let (mut a, f) = fixture_on(&mut server);
    let mut c = follower_with(&mut server, &a, &f, C, |_| {});
    let new_sk = SecretKey::generate().unwrap();
    let req = request(&f, &new_sk, vec![f.others[B].id()], RotationReason::Revoke);
    let out = a.repo.as_mut().unwrap().rotate(req).unwrap();
    c.unlock(&f.sk);
    during(&mut c);
    sync(&mut server, &mut a).unwrap();
    pull(&server, &mut c);
    let (repo, _, _) = follow_rotation(c.store(), out.head, PASSWORD, &f.others[C].keys).unwrap();
    c.repo = Some(repo);
    (server, a, c)
}

/// Review I1 of Task 10, carried to Task 11: a vault created under the old
/// identity after `from_heads` is re-created under the new identity (a new
/// vault key, its own items replayed into it); the old one is left alone
/// and nothing of it goes out under the old keys.
#[test]
fn vault_created_under_old_identity_is_recreated() {
    let mut created = None;
    let (mut server, mut a, mut c) = follow_after(|c| {
        let v = c.repo().create_vault(meta("Travail")).unwrap();
        c.repo()
            .save_item(&v, login(v.id, "work", T0 + 80))
            .unwrap();
        created = Some(v.id);
    });
    let old = created.unwrap();
    let t = c.store().trust_state().unwrap().unwrap();
    assert!(t.own_writes.replay.is_empty(), "{:?}", t.own_writes.replay);
    assert!(!t.own_writes.alert);
    let work = c.vault_named("Travail");
    assert_ne!(work.id, old, "a new vault under the new keys");
    assert_eq!(
        users(&c.repo().items(&work).unwrap()),
        vec!["work".to_string()]
    );
    assert_eq!(c.repo().vaults().unwrap().len(), 2);
    assert!(outbox(&c).iter().all(|(ch, _)| {
        ch.id != old
            && !(ch.kind == RecordKind::Item
                && ch
                    .data
                    .as_ref()
                    .is_some_and(|d| split_item_record(d).unwrap().0 == old))
    }));
    sync(&mut server, &mut c).unwrap();
    pull(&server, &mut a);
    let work = a.vault_named("Travail");
    assert_eq!(
        users(&a.repo().items(&work).unwrap()),
        vec!["work".to_string()]
    );
}

/// Task 19 carried item 2: C creates a vault under the old identity after
/// `from_heads` and D writes in it too. Each re-creates it from its own
/// writes under one id derived from the new identity and the old vault:
/// one vault in the end, with C's meta and both items, never two.
#[test]
fn recreated_vault_is_one_across_devices() {
    let mut server = Server::default();
    let (mut a, f) = fixture_on(&mut server);
    let mut c = follower_with(&mut server, &a, &f, C, |_| {});
    let mut d = follower_with(&mut server, &a, &f, 2, |_| {});
    let new_sk = SecretKey::generate().unwrap();
    let req = request(&f, &new_sk, vec![f.others[B].id()], RotationReason::Revoke);
    let out = a.repo.as_mut().unwrap().rotate(req).unwrap();
    c.unlock(&f.sk);
    let old = c.repo().create_vault(meta("Travail")).unwrap();
    c.repo()
        .save_item(&old, login(old.id, "work", T0 + 80))
        .unwrap();
    sync(&mut server, &mut c).unwrap();
    d.unlock(&f.sk);
    pull(&server, &mut d);
    let theirs = d.vault_named("Travail");
    d.repo()
        .save_item(&theirs, login(old.id, "dora", T0 + 81))
        .unwrap();
    sync(&mut server, &mut d).unwrap();
    sync(&mut server, &mut a).unwrap();

    let identity = rotation_of(&a.store(), &out.head).identity_pub;
    let expected = onepass_core::lineage::recreated_vault_id(&identity, old.id);
    for (dev, keys) in [(&mut c, &f.others[C].keys), (&mut d, &f.others[2].keys)] {
        pull(&server, dev);
        dev.repo = None;
        let (repo, _, _) = follow_rotation(dev.store(), out.head, PASSWORD, keys).unwrap();
        dev.repo = Some(repo);
        let t = dev.store().trust_state().unwrap().unwrap();
        assert!(t.own_writes.replay.is_empty(), "{:?}", t.own_writes.replay);
        assert!(!t.own_writes.alert);
        sync(&mut server, dev).unwrap();
    }
    for dev in [&mut a, &mut c, &mut d] {
        pull(&server, dev);
        let vaults = dev.repo().vaults().unwrap();
        assert_eq!(
            vaults.len(),
            2,
            "{:?}",
            vaults.iter().map(|v| &v.meta.name).collect::<Vec<_>>()
        );
        let work = dev.vault_named("Travail");
        assert_eq!(work.id, expected);
        assert_eq!(
            users(&dev.repo().items(&work).unwrap()),
            ["dora", "work"].map(String::from)
        );
    }
}

/// C and D write in a vault C created under the old identity after
/// `from_heads` (a "Travail" vault); A has rotated. Returns the server,
/// the three devices, the old vault id, the head and the derived id.
fn recreate_setup() -> (Server, Device, Device, Device, Fixture, Id, [u8; 32], Id) {
    let mut server = Server::default();
    let (mut a, f) = fixture_on(&mut server);
    let mut c = follower_with(&mut server, &a, &f, C, |_| {});
    let mut d = follower_with(&mut server, &a, &f, 2, |_| {});
    let new_sk = SecretKey::generate().unwrap();
    let req = request(&f, &new_sk, vec![f.others[B].id()], RotationReason::Revoke);
    let out = a.repo.as_mut().unwrap().rotate(req).unwrap();
    c.unlock(&f.sk);
    let old = c.repo().create_vault(meta("Travail")).unwrap();
    c.repo()
        .save_item(&old, login(old.id, "work", T0 + 80))
        .unwrap();
    sync(&mut server, &mut c).unwrap();
    d.unlock(&f.sk);
    pull(&server, &mut d);
    let theirs = d.vault_named("Travail");
    d.repo()
        .save_item(&theirs, login(old.id, "dora", T0 + 81))
        .unwrap();
    sync(&mut server, &mut d).unwrap();
    sync(&mut server, &mut a).unwrap();
    let identity = rotation_of(&a.store(), &out.head).identity_pub;
    let derived = onepass_core::lineage::recreated_vault_id(&identity, old.id);
    (server, a, c, d, f, old.id, out.head, derived)
}

fn follow_and_check(dev: &mut Device, head: [u8; 32], keys: &DeviceKeys) {
    dev.repo = None;
    let (repo, _, _) = follow_rotation(dev.store(), head, PASSWORD, keys).unwrap();
    dev.repo = Some(repo);
    let t = dev.store().trust_state().unwrap().unwrap();
    assert!(t.own_writes.replay.is_empty(), "{:?}", t.own_writes.replay);
    assert!(!t.own_writes.alert);
}

/// Review I3 (fix round 1): the server plants a vault key at the derived
/// id before C replays. C does not join it (it does not verify) and
/// re-creates under a fresh id: the replay completes, nothing waits.
#[test]
fn planted_row_at_the_recreated_id_never_wedges_the_replay() {
    let (mut server, _a, mut c, _d, f, _old, head, derived) = recreate_setup();
    // A vault key and meta of another vault, served at the derived id.
    let any = f_any_vault(&server);
    for kind in [RecordKind::VaultKey, RecordKind::VaultMeta] {
        let mut junk = server.get(kind, any).unwrap();
        junk.id = derived;
        server.replay(junk);
    }
    pull(&server, &mut c);
    follow_and_check(&mut c, head, &f.others[C].keys);
    let work = c.vault_named("Travail");
    assert_ne!(work.id, derived);
    assert_eq!(
        users(&c.repo().items(&work).unwrap()),
        vec!["work".to_string()]
    );
    sync(&mut server, &mut c).unwrap();
}

/// A vault key the server holds, any.
fn f_any_vault(server: &Server) -> Id {
    server
        .records
        .iter()
        .find(|((k, _), e)| *k == RecordKind::VaultKey && e.record.is_some())
        .map(|((_, id), _)| *id)
        .unwrap()
}

/// Review I3 (fix round 1): the honest race, C and D re-create the vault
/// before either one synced. Both derive the same id and the same vault
/// key: the second push conflicts, its rebase joins the first creation
/// (the server's key and meta, its own items merged), and every device
/// ends with one vault holding both writes.
#[test]
fn honest_race_to_recreate_keeps_both_writes() {
    let (mut server, mut a, mut c, mut d, f, _old, head, derived) = recreate_setup();
    pull(&server, &mut c);
    pull(&server, &mut d);
    follow_and_check(&mut c, head, &f.others[C].keys);
    follow_and_check(&mut d, head, &f.others[2].keys);
    sync(&mut server, &mut c).unwrap();
    sync(&mut server, &mut d).unwrap();
    sync(&mut server, &mut c).unwrap();
    for dev in [&mut a, &mut c, &mut d] {
        pull(&server, dev);
        let vaults = dev.repo().vaults().unwrap();
        assert_eq!(vaults.len(), 2);
        let work = dev.vault_named("Travail");
        assert_eq!(work.id, derived);
        assert_eq!(
            users(&dev.repo().items(&work).unwrap()),
            ["dora", "work"].map(String::from)
        );
    }
}

/// Fix round 2: the same race in the other order. D, which wrote no meta
/// of its own, re-creates under the neutral meta and pushes first; C, which
/// created the vault ("Travail"), joins that creation in its rebase. C's
/// own meta replaces the neutral one (spec 10.4, G4): every device ends
/// with "Travail" holding both writes.
#[test]
fn honest_race_to_recreate_keeps_the_creators_meta() {
    let (mut server, mut a, mut c, mut d, f, _old, head, derived) = recreate_setup();
    pull(&server, &mut c);
    pull(&server, &mut d);
    follow_and_check(&mut c, head, &f.others[C].keys);
    follow_and_check(&mut d, head, &f.others[2].keys);
    sync(&mut server, &mut d).unwrap();
    sync(&mut server, &mut c).unwrap();
    sync(&mut server, &mut d).unwrap();
    for dev in [&mut a, &mut c, &mut d] {
        pull(&server, dev);
        let vaults = dev.repo().vaults().unwrap();
        assert_eq!(vaults.len(), 2);
        let names: Vec<_> = vaults.iter().map(|v| v.meta.name.clone()).collect();
        assert!(names.contains(&"Travail".to_string()), "{names:?}");
        let work = dev.vault_named("Travail");
        assert_eq!(work.id, derived);
        assert_eq!(
            users(&dev.repo().items(&work).unwrap()),
            ["dora", "work"].map(String::from)
        );
    }
}

/// Review I2: a rename made under the old identity is replayed under the
/// new keys, not dropped.
#[test]
fn vault_rename_under_old_identity_is_replayed() {
    let (mut server, mut a, mut c) = follow_after(|c| {
        let v = c.vault();
        c.repo().update_vault_meta(&v, meta("Perso")).unwrap();
    });
    assert_eq!(c.vault().meta.name, "Perso");
    let t = c.store().trust_state().unwrap().unwrap();
    assert!(t.own_writes.replay.is_empty());
    assert!(!t.own_writes.alert);
    sync(&mut server, &mut c).unwrap();
    pull(&server, &mut a);
    assert_eq!(a.vault().meta.name, "Perso");
}

/// Review I3: in generation 0, with no rotation anywhere, a vault key the
/// server replaced with garbage is an integrity error as before, never a
/// silent read of the device's own copy.
#[test]
fn generation_zero_broken_vault_key_is_an_alert() {
    let mut server = Server::default();
    let (mut a, _f) = fixture_on(&mut server);
    let v = a.vault().id;
    let live = server.get(RecordKind::VaultKey, v).unwrap();
    let mut data = live.data.clone();
    for b in data.iter_mut().take(64) {
        *b ^= 0x5a;
    }
    server.replay(Record {
        data,
        version: live.version + 1,
        ..live
    });
    pull(&server, &mut a);
    assert!(!a.store().retained_rows(v).unwrap().is_empty());
    assert!(matches!(a.repo().vaults(), Err(Error::Integrity(_))));
}

// ------------------------------------------------- Task 11: siblings

fn head_of(dev: &Device) -> [u8; 32] {
    dev.store().trust_state().unwrap().unwrap().head.hash
}

/// Fetch everything but the Secret Key deliveries, without moving the
/// cursor: the next `pull` brings them (and the rest again).
fn pull_without_deliveries(server: &Server, dev: &mut Device) {
    let cursor = dev.cursor;
    pull_only(server, dev, |ch| ch.kind != RecordKind::KeyDelivery);
    dev.cursor = cursor;
}

/// Ruling I6 (Task 9): the new identity changes its password before the
/// follower follows; the params at epoch 2 no longer match the record's
/// hash but verify under its identity, so the follower follows with the
/// new password.
#[test]
fn follow_after_password_change_on_new_identity() {
    let mut server = Server::default();
    let (mut a, f) = fixture_on(&mut server);
    let mut c = follower_with(&mut server, &a, &f, C, |_| {});
    let new_sk = SecretKey::generate().unwrap();
    let req = request(&f, &new_sk, vec![f.others[B].id()], RotationReason::Revoke);
    let out = a.repo.as_mut().unwrap().rotate(req).unwrap();
    sync(&mut server, &mut a).unwrap();
    a.repo()
        .change_password(PASSWORD, &new_sk, NEW_PASSWORD)
        .unwrap();
    a.repo().persist_device_state().unwrap();
    sync(&mut server, &mut a).unwrap();
    pull(&server, &mut c);

    let prompt = prompt_of(&c).expect("a prompt");
    assert!(prompt.choices[0].complete);
    assert!(follow_rotation(c.store(), out.head, PASSWORD, &f.others[C].keys).is_err());
    let (repo, _, sk) =
        follow_rotation(c.store(), out.head, NEW_PASSWORD, &f.others[C].keys).unwrap();
    assert_eq!(repo.account().params.epoch, 2);
    c.repo = Some(repo);
    assert_eq!(users(&c.items()), users(&a.items()));
    c.lock();
    c.try_unlock(NEW_PASSWORD, &sk).unwrap();
}

/// Params of a later epoch that the new identity did not sign are not
/// taken for the record's (G8): the follow is refused.
#[test]
fn later_epoch_params_must_verify_under_the_record_identity() {
    let (server, _a, c, f, out, _sk) = rotated();
    let body = rotation_of(&c.store(), &out.head);
    let rid = identity_id(&body.identity_pub);
    // The old identity's params (epoch 1, another signer) under the new id.
    let old = server
        .get(RecordKind::AccountParams, f_identity_record_id(&c, &f))
        .unwrap();
    let mut store = c.store();
    store
        .put(Record {
            id: rid,
            kind: RecordKind::AccountParams,
            version: 2,
            data: old.data,
        })
        .unwrap();
    let r = follow_rotation(c.store(), out.head, PASSWORD, &f.others[C].keys);
    assert!(r.is_err());
    assert_eq!(
        head_of(&c),
        c.store().trust_state().unwrap().unwrap().head.hash
    );
    assert_ne!(head_of(&c), out.head);
}

/// The record id of the account params of the identity `c` is on.
fn f_identity_record_id(c: &Device, _f: &Fixture) -> Id {
    let t = c.store().trust_state().unwrap().unwrap();
    account_record_id(
        t.account_id,
        (t.head.generation > 0).then_some(&t.identity_pub),
    )
}

/// Carried item 4 (Task 10): two rotations followed before the first
/// replay finished. The replay opens the device's own copy with the right
/// retired key, brings its own write in, and never the revoked device's
/// late one.
#[test]
fn double_follow_before_replay() {
    let mut server = Server::default();
    let (mut a, f) = fixture_on(&mut server);
    let mut c = follower_with(&mut server, &a, &f, C, |_| {});
    let mut ipad = old_device(&server, &f);
    c.unlock(&f.sk);
    let v = c.vault();
    c.repo()
        .save_item(&v, login(v.id, "mine", T0 + 50))
        .unwrap();
    c.lock();
    let sk1 = SecretKey::generate().unwrap();
    let req = request(&f, &sk1, vec![f.others[B].id()], RotationReason::Revoke);
    let r1 = a.repo.as_mut().unwrap().rotate(req).unwrap();
    let iv = ipad.vault();
    ipad.repo()
        .save_item(&iv, login(iv.id, "forged", T0 + 55))
        .unwrap();
    sync(&mut server, &mut ipad).unwrap();
    sync(&mut server, &mut a).unwrap();

    // C gets r1 without its vault content: the replay waits.
    let cursor = c.cursor;
    pull_only(&server, &mut c, |ch| {
        !matches!(
            ch.kind,
            RecordKind::VaultKey | RecordKind::VaultMeta | RecordKind::Manifest | RecordKind::Item
        )
    });
    c.cursor = cursor;
    let (repo, _, _) = follow_rotation(c.store(), r1.head, PASSWORD, &f.others[C].keys).unwrap();
    drop(repo);
    let t = c.store().trust_state().unwrap().unwrap();
    assert_eq!(t.own_writes.replay.len(), 1);

    // A rotates again; C gets everything and follows r2.
    let sk2 = SecretKey::generate().unwrap();
    let mut req = request(&f, &sk2, vec![], RotationReason::Rotate);
    req.secret_key = &sk1;
    let r2 = a.repo.as_mut().unwrap().rotate(req).unwrap();
    sync(&mut server, &mut a).unwrap();
    pull(&server, &mut c);
    let prompt = prompt_of(&c).expect("r2 prompts");
    assert_eq!(prompt.choices[0].hash, r2.head);
    let (repo, _, _) = follow_rotation(c.store(), r2.head, PASSWORD, &f.others[C].keys).unwrap();
    c.repo = Some(repo);
    let u = users(&c.items());
    assert!(u.contains(&"mine".to_string()), "{u:?}");
    assert!(!u.contains(&"forged".to_string()), "{u:?}");
    let t = c.store().trust_state().unwrap().unwrap();
    assert!(t.own_writes.replay.is_empty());
    assert!(!t.own_writes.alert);
    sync(&mut server, &mut c).unwrap();
    pull(&server, &mut a);
    let u = users(&a.items());
    assert!(u.contains(&"mine".to_string()) && !u.contains(&"forged".to_string()));
}

/// Carried item 5 (Task 10): `ignored` keeps the rejected sibling, but once
/// the device settled on another head the own-copy gate (I3) closes again:
/// a vault key the server replaced with garbage is an integrity error.
#[test]
fn ignored_sibling_no_longer_opens_own_copy() {
    let mut server = Server::default();
    let (mut a, f) = fixture_on(&mut server);
    let mut b = follower_with(&mut server, &a, &f, B, |_| {});
    let mut c = follower_with(&mut server, &a, &f, C, |_| {});
    let a_sk = SecretKey::generate().unwrap();
    let req = request(&f, &a_sk, vec![f.others[B].id()], RotationReason::Revoke);
    let ra = a.repo.as_mut().unwrap().rotate(req).unwrap();
    sync(&mut server, &mut a).unwrap();
    b.unlock(&f.sk);
    let b_sk = SecretKey::generate().unwrap();
    let mut req = request(&f, &b_sk, vec![f.me.id()], RotationReason::Revoke);
    req.device_keys = &f.others[B].keys;
    let rb = b.repo.as_mut().unwrap().rotate(req).unwrap();
    push_outbox(&mut server, &b).unwrap();
    pull(&server, &mut c);
    let (repo, _, _) = follow_rotation(c.store(), ra.head, PASSWORD, &f.others[C].keys).unwrap();
    c.repo = Some(repo);
    assert_eq!(
        c.store().trust_state().unwrap().unwrap().ignored,
        vec![rb.head]
    );
    assert_eq!(c.repo().vaults().unwrap().len(), 1);

    let v = c.vault().id;
    let live = server.get(RecordKind::VaultKey, v).unwrap();
    let mut data = live.data.clone();
    for byte in data.iter_mut().take(64) {
        *byte ^= 0x5a;
    }
    server.replay(Record {
        data,
        version: live.version + 1,
        ..live
    });
    let live = server.get(RecordKind::VaultMeta, v).unwrap();
    let mut data = live.data.clone();
    for byte in data.iter_mut().skip(8).take(32) {
        *byte ^= 0x5a;
    }
    server.replay(Record {
        data,
        version: live.version + 1,
        ..live
    });
    pull(&server, &mut c);
    assert_eq!(c.store().retained_rows(v).unwrap().len(), 2);
    assert!(matches!(c.repo().vaults(), Err(Error::Integrity(_))));
}

/// Review M1 (Task 10): a rename by another device that a session loaded
/// before phase 2 is what that session reads from its own copy while it
/// waits: the meta retained pairs with the manifest kept since that clean
/// load, never the meta from before the rename.
#[test]
fn own_copy_keeps_the_meta_of_its_key() {
    let mut server = Server::default();
    let (mut a, f) = fixture_on(&mut server);
    let mut c = follower_with(&mut server, &a, &f, C, |_| {});
    c.unlock(&f.sk);
    let v = a.vault();
    a.repo().update_vault_meta(&v, meta("Perso")).unwrap();
    sync(&mut server, &mut a).unwrap();
    pull(&server, &mut c);
    assert_eq!(c.vault().meta.name, "Perso");
    let _ = c.items();
    let new_sk = SecretKey::generate().unwrap();
    let req = request(&f, &new_sk, vec![f.others[B].id()], RotationReason::Revoke);
    a.repo.as_mut().unwrap().rotate(req).unwrap();
    sync(&mut server, &mut a).unwrap();
    pull(&server, &mut c);
    assert_eq!(c.vault().meta.name, "Perso");
    assert_eq!(
        users(&c.items()),
        ["alice", "bob", "carol"].map(String::from)
    );
}

/// Two rotations A and C made concurrently from the genesis (`revoke_a`
/// and `revoke_c`), each pushed through phase 1, each rotator then pulling
/// the other's record (and looking at it, as the app does after a fetch).
/// B ("iPad") is a third device on the genesis, locked. C stays unlocked.
struct Race {
    server: Server,
    f: Fixture,
    a: Device,
    b: Device,
    c: Device,
    ra: RotationOutcome,
    rc: RotationOutcome,
}

impl Race {
    /// Spec 8.5: no exclusion between the two, the smaller hash wins.
    fn a_wins(&self) -> bool {
        self.ra.head < self.rc.head
    }
}

fn reason(revoke: &[Id]) -> RotationReason {
    if revoke.is_empty() {
        RotationReason::Rotate
    } else {
        RotationReason::Revoke
    }
}

fn race(
    revoke_a: impl FnOnce(&Fixture) -> Vec<Id>,
    revoke_c: impl FnOnce(&Fixture) -> Vec<Id>,
    before: impl FnOnce(&mut Server, &mut Device, &Fixture),
    after: impl FnOnce(&mut Device),
    pull_round: impl Fn(&Server, &mut Device),
) -> Race {
    let mut server = Server::default();
    let (mut a, f) = fixture_on(&mut server);
    let b = follower_with(&mut server, &a, &f, B, |_| {});
    let mut c = follower_with(&mut server, &a, &f, C, |_| {});
    c.unlock(&f.sk);
    before(&mut server, &mut c, &f);
    let a_sk = SecretKey::generate().unwrap();
    let revoke = revoke_a(&f);
    let req = request(&f, &a_sk, revoke.clone(), reason(&revoke));
    let ra = a.repo.as_mut().unwrap().rotate(req).unwrap();
    let c_sk = SecretKey::generate().unwrap();
    let revoke = revoke_c(&f);
    let mut req = request(&f, &c_sk, revoke.clone(), reason(&revoke));
    req.device_keys = &f.others[C].keys;
    let rc = c.repo.as_mut().unwrap().rotate(req).unwrap();
    after(&mut c);
    // Phase 1: new ids only, never in conflict.
    for d in [&a, &c] {
        push_outbox(&mut server, d).unwrap();
        assert_eq!(
            d.store().push_rotation_phase(1).unwrap(),
            PhaseOutcome::Done
        );
    }
    for d in [&mut a, &mut c] {
        pull_round(&server, d);
        d.repo().refresh_pending_rotation().unwrap();
    }
    Race {
        server,
        f,
        a,
        b,
        c,
        ra,
        rc,
    }
}

/// The device keys of A (`a`) or of C.
fn keys_of(f: &Fixture, a: bool) -> &DeviceKeys {
    if a { &f.me.keys } else { &f.others[C].keys }
}

/// Port of `zz3`: A and C rotate at the same time. The loser switches once
/// (with its own writes replayed, the one made before its rotation and the
/// one after), the third device follows the winner once, the winner never
/// moves; all end on the same head with nothing left to decide.
#[test]
fn two_concurrent_rotations_converge() {
    let r = race(
        |_| vec![],
        |_| vec![],
        |server, c, _| {
            let v = c.vault();
            c.repo()
                .save_item(&v, login(v.id, "carla", T0 + 40))
                .unwrap();
            sync(server, c).unwrap();
        },
        |c| {
            let v = c.vault();
            c.repo()
                .save_item(&v, login(v.id, "late", T0 + 60))
                .unwrap();
        },
        pull,
    );
    let a_wins = r.a_wins();
    let (wh, lh) = if a_wins {
        (r.ra.head, r.rc.head)
    } else {
        (r.rc.head, r.ra.head)
    };
    let Race {
        mut server,
        f,
        a,
        mut b,
        c,
        ..
    } = r;
    let (mut w, mut l) = if a_wins { (a, c) } else { (c, a) };
    let l_keys = keys_of(&f, !a_wins);

    assert!(w.repo().pending_prompt().is_none());
    let p = l.repo().pending_prompt().cloned().expect("switch prompt");
    assert_eq!(p.kind, PromptKind::Reapply);
    assert_eq!(p.choices.len(), 1);
    assert_eq!(p.choices[0].hash, wh);
    assert!(!p.cross_branch_revocation);
    assert!(p.reapply_names.is_empty());
    assert!(matches!(state(&l), DeviceLineageState::Candidate { .. }));

    // The winner pushes its phases; the loser waits.
    sync(&mut server, &mut w).unwrap();
    assert_eq!(state(&w), DeviceLineageState::Current);
    assert_eq!(head_of(&w), wh);

    let mut switches = 0;
    pull(&server, &mut l);
    let session = l.repo.take().unwrap();
    let (repo, _, sk) = follow_switch(session, wh, PASSWORD, l_keys).unwrap();
    switches += 1;
    l.repo = Some(repo);
    assert_eq!(head_of(&l), wh);
    let t = l.store().trust_state().unwrap().unwrap();
    assert_self_pinned(&t);
    assert!(t.own_writes.replay.is_empty(), "{:?}", t.own_writes.replay);
    assert!(!t.own_writes.alert);
    assert!(
        l.repo()
            .reapply(PASSWORD, &sk, &SecretKey::generate().unwrap(), l_keys)
            .unwrap()
            .is_none()
    );
    sync(&mut server, &mut l).unwrap();

    // The third device follows the winner directly.
    pull(&server, &mut b);
    let pb = prompt_of(&b).expect("b prompts");
    assert_eq!(pb.kind, PromptKind::Single);
    assert_eq!(pb.choices.len(), 1);
    assert_eq!(pb.choices[0].hash, wh);
    let (repo, _, _) = follow_rotation(b.store(), wh, PASSWORD, &f.others[B].keys).unwrap();
    b.repo = Some(repo);

    for d in [&mut w, &mut l, &mut b] {
        sync(&mut server, d).unwrap();
    }
    for d in [&mut w, &mut l, &mut b] {
        pull(&server, d);
        assert_eq!(head_of(d), wh);
        assert_eq!(prompt_of(d), None);
        assert!(d.repo().refresh_pending_rotation().unwrap().is_none());
        let u = users(&d.items());
        for name in ["carla", "late", "alice"] {
            assert!(u.contains(&name.to_string()), "{name} missing: {u:?}");
        }
    }
    assert_eq!(switches, 1);
    assert_ne!(lh, wh);
}

/// Port of `zz5`: two rotations seen incomplete first (deliveries
/// withheld). The loser stops pushing at once (a better sibling is known),
/// nothing alternates, and every device converges in at most two user
/// steps (here one: the loser's switch, the third device's follow).
#[test]
fn two_incomplete_rotations_converge() {
    let r = race(
        |_| vec![],
        |_| vec![],
        |_, _, _| {},
        |_| {},
        pull_without_deliveries,
    );
    let a_wins = r.a_wins();
    let wh = if a_wins { r.ra.head } else { r.rc.head };
    let Race {
        mut server,
        f,
        a,
        mut b,
        c,
        ..
    } = r;
    let (mut w, mut l) = if a_wins { (a, c) } else { (c, a) };
    let l_keys = keys_of(&f, !a_wins);
    let mut steps = BTreeMap::new();

    // Incomplete: the loser is read-only, its prompt marked incomplete;
    // following fails and changes nothing.
    let p = l.repo().pending_prompt().cloned().expect("loser prompt");
    assert_eq!(p.kind, PromptKind::Reapply);
    assert!(!p.choices[0].complete);
    assert!(matches!(state(&l), DeviceLineageState::Candidate { .. }));
    assert!(w.repo().pending_prompt().is_none());
    pull_without_deliveries(&server, &mut b);
    let pb = prompt_of(&b).expect("b sees a prompt");
    assert!(!pb.choices[0].complete);
    assert!(follow_rotation(b.store(), wh, PASSWORD, &f.others[B].keys).is_err());

    // The winner goes on; the loser pushes nothing of its phase 2.
    sync(&mut server, &mut w).unwrap();
    assert_eq!(state(&w), DeviceLineageState::Current);
    let _ = sync(&mut server, &mut l);
    assert!(matches!(state(&l), DeviceLineageState::Candidate { .. }));

    // The deliveries arrive.
    pull(&server, &mut l);
    let session = l.repo.take().unwrap();
    let (repo, _, _) = follow_switch(session, wh, PASSWORD, l_keys).unwrap();
    *steps.entry("loser").or_insert(0) += 1;
    l.repo = Some(repo);
    pull(&server, &mut b);
    let (repo, _, _) = follow_rotation(b.store(), wh, PASSWORD, &f.others[B].keys).unwrap();
    *steps.entry("b").or_insert(0) += 1;
    b.repo = Some(repo);
    for d in [&mut w, &mut l, &mut b] {
        sync(&mut server, d).unwrap();
    }
    for d in [&mut w, &mut l, &mut b] {
        pull(&server, d);
        assert_eq!(head_of(d), wh);
        assert_eq!(prompt_of(d), None);
        assert_eq!(
            users(&d.items()),
            ["alice", "bob", "carol"].map(String::from)
        );
    }
    assert!(steps.values().all(|n| *n <= 2), "{steps:?}");
}

/// The winner and the loser of a race whose rotations revoke devices.
struct Settled {
    server: Server,
    f: Fixture,
    w: Device,
    l: Device,
    wh: [u8; 32],
    a_wins: bool,
}

/// `race` with these revocations, the winner pushed through, the loser
/// switched to it.
fn race_and_switch(
    revoke_a: impl FnOnce(&Fixture) -> Vec<Id>,
    revoke_c: impl FnOnce(&Fixture) -> Vec<Id>,
) -> (Settled, SecretKey) {
    let r = race(revoke_a, revoke_c, |_, _, _| {}, |_| {}, pull);
    let a_wins = r.a_wins();
    let wh = if a_wins { r.ra.head } else { r.rc.head };
    let Race {
        mut server,
        f,
        a,
        c,
        ..
    } = r;
    let (mut w, mut l) = if a_wins { (a, c) } else { (c, a) };
    let p = l.repo().pending_prompt().cloned().expect("switch prompt");
    assert_eq!(p.kind, PromptKind::Reapply);
    sync(&mut server, &mut w).unwrap();
    pull(&server, &mut l);
    let session = l.repo.take().unwrap();
    let (repo, _, sk) = follow_switch(session, wh, PASSWORD, keys_of(&f, !a_wins)).unwrap();
    l.repo = Some(repo);
    (
        Settled {
            server,
            f,
            w,
            l,
            wh,
            a_wins,
        },
        sk,
    )
}

/// Spec 8.5 step 5: A revokes B while C revokes D. The loser re-applies
/// its removal, uncovered by the winner, as a `Reapply` child of the
/// winner's tip; the winner follows it, and both end there with both
/// devices removed.
#[test]
fn loser_reapplies_uncovered_removal() {
    let (mut s, sk) = race_and_switch(|f| vec![f.others[B].id()], |f| vec![f.others[2].id()]);
    let (mine, theirs) = if s.a_wins {
        (s.f.others[2].id(), s.f.others[B].id())
    } else {
        (s.f.others[B].id(), s.f.others[2].id())
    };
    assert_eq!(s.l.repo().uncovered_removals().unwrap(), vec![mine]);
    let keys = keys_of(&s.f, !s.a_wins);
    let out =
        s.l.repo()
            .reapply(PASSWORD, &sk, &SecretKey::generate().unwrap(), keys)
            .unwrap()
            .expect("a reapply record");
    let body = rotation_of(&s.l.store(), &out.head);
    assert_eq!(body.reason, RotationReason::Reapply);
    assert_eq!(body.parent, s.wh);
    assert_eq!(body.revoked, vec![mine]);
    assert!(
        !body
            .roster
            .iter()
            .any(|e| e.device_id == mine || e.device_id == theirs)
    );
    sync(&mut s.server, &mut s.l).unwrap();

    pull(&s.server, &mut s.w);
    let p = prompt_of(&s.w).expect("winner prompts for the reapply");
    assert_eq!(p.kind, PromptKind::Single);
    assert_eq!(p.choices[0].hash, out.head);
    let w_keys = keys_of(&s.f, s.a_wins);
    let (repo, _, _) = follow_rotation(s.w.store(), out.head, PASSWORD, w_keys).unwrap();
    s.w.repo = Some(repo);
    for d in [&mut s.w, &mut s.l] {
        sync(&mut s.server, d).unwrap();
        pull(&s.server, d);
        assert_eq!(head_of(d), out.head);
        assert_eq!(prompt_of(d), None);
        let t = d.store().trust_state().unwrap().unwrap();
        assert!(t.revoked.contains(&mine) && t.revoked.contains(&theirs));
        assert_eq!(
            users(&d.items()),
            ["alice", "bob", "carol"].map(String::from)
        );
    }
}

/// The winner already revoked the same device: no `Reapply` record.
#[test]
fn reapply_dropped_when_covered() {
    let (mut s, sk) = race_and_switch(|f| vec![f.others[B].id()], |f| vec![f.others[B].id()]);
    assert!(s.l.repo().uncovered_removals().unwrap().is_empty());
    let keys = keys_of(&s.f, !s.a_wins);
    let lineage_before = s.l.store().list(RecordKind::Lineage).unwrap().len();
    assert!(
        s.l.repo()
            .reapply(PASSWORD, &sk, &SecretKey::generate().unwrap(), keys)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        s.l.store().list(RecordKind::Lineage).unwrap().len(),
        lineage_before
    );
    sync(&mut s.server, &mut s.l).unwrap();
    pull(&s.server, &mut s.w);
    assert_eq!(prompt_of(&s.w), None);
    assert_eq!(head_of(&s.w), s.wh);
    assert_eq!(head_of(&s.l), s.wh);
}

/// Spec 7.3: a password change pending on the identity the device leaves
/// is offered on the follow screen and, on yes, re-applied as epoch 2 of
/// the new identity.
#[test]
fn password_change_reapplied_on_yes() {
    let (mut server, mut a, mut c, f, out, _sk) = rotated_with(
        |_| {},
        |_, c, f| {
            c.unlock(&f.sk);
            c.repo()
                .change_password(PASSWORD, &f.sk, NEW_PASSWORD)
                .unwrap();
            c.lock();
        },
        |_, _, _| true,
    );
    assert!(prompt_of(&c).unwrap().pending_password_change);
    let old_id = f_identity_record_id(&c, &f);
    // The new keys were made under the password A knew.
    let (repo, _, sk) = follow_rotation(c.store(), out.head, PASSWORD, &f.others[C].keys).unwrap();
    c.repo = Some(repo);
    // Review I3: the change made under the identity left never goes out
    // (its keyset is sealed under the old Secret Key the revoked device
    // holds).
    assert!(no_account_pair_out(&c, old_id));
    // "Oui": the change is applied to the new identity.
    c.repo()
        .change_password(PASSWORD, &sk, NEW_PASSWORD)
        .unwrap();
    assert_eq!(c.repo().account().params.epoch, 2);
    c.lock();
    assert!(c.try_unlock(PASSWORD, &sk).is_err());
    c.try_unlock(NEW_PASSWORD, &sk).unwrap();
    assert!(no_account_pair_out(&c, old_id));
    sync(&mut server, &mut c).unwrap();
    assert!(no_account_pair_out(&c, old_id));
    assert_eq!(
        server
            .get(RecordKind::AccountParams, old_id)
            .unwrap()
            .version,
        1
    );
    pull(&server, &mut a);
    let pin = a.store().device_state().unwrap().pinned;
    assert_eq!(stored_params_epoch(&a.store(), pin.as_ref()).unwrap(), 2);
}

/// No account params or keyset of records id `id` in the outbox.
fn no_account_pair_out(dev: &Device, id: Id) -> bool {
    outbox(dev).iter().all(|(ch, _)| {
        !(matches!(ch.kind, RecordKind::AccountParams | RecordKind::Keyset) && ch.id == id)
    })
}

/// Review I3, "Non" path: the pending change of the identity left is not
/// pushed either.
#[test]
fn password_change_of_left_identity_never_pushed() {
    let (mut server, _a, mut c, f, out, _sk) = rotated_with(
        |_| {},
        |_, c, f| {
            c.unlock(&f.sk);
            c.repo()
                .change_password(PASSWORD, &f.sk, NEW_PASSWORD)
                .unwrap();
            c.lock();
        },
        |_, _, _| true,
    );
    let old_id = f_identity_record_id(&c, &f);
    assert!(
        c.store()
            .is_pending_write(RecordKind::AccountParams, old_id)
            .unwrap()
    );
    let (repo, _, _) = follow_rotation(c.store(), out.head, PASSWORD, &f.others[C].keys).unwrap();
    c.repo = Some(repo);
    assert!(no_account_pair_out(&c, old_id));
    // Fix round 2: dropped at the follow, not held forever.
    for kind in [RecordKind::AccountParams, RecordKind::Keyset] {
        assert!(!c.store().is_pending_write(kind, old_id).unwrap());
    }
    sync(&mut server, &mut c).unwrap();
    assert_eq!(
        server
            .get(RecordKind::AccountParams, old_id)
            .unwrap()
            .version,
        1
    );
}

/// Review I1: the loser of a race rejects the winner ("Ce n'était pas
/// moi"): it goes back to its own rotation's phase and pushes it to the
/// end.
#[test]
fn loser_rejecting_the_winner_resumes_its_rotation() {
    let r = race(|_| vec![], |_| vec![], |_, _, _| {}, |_| {}, pull);
    let a_wins = r.a_wins();
    let (wh, lh) = if a_wins {
        (r.ra.head, r.rc.head)
    } else {
        (r.rc.head, r.ra.head)
    };
    let Race {
        mut server, a, c, ..
    } = r;
    let mut l = if a_wins { c } else { a };
    assert!(matches!(state(&l), DeviceLineageState::Candidate { .. }));
    let mut store = l.store();
    reject_rotation(&mut store, wh, true).unwrap();
    assert_eq!(state(&l), rotating(2));
    l.repo().refresh_pending_rotation().unwrap();
    assert!(l.repo().pending_prompt().is_none());
    sync(&mut server, &mut l).unwrap();
    assert_eq!(state(&l), DeviceLineageState::Current);
    assert_eq!(head_of(&l), lh);
    assert_eq!(
        users(&l.items()),
        ["alice", "bob", "carol"].map(String::from)
    );
}

/// Review I2: the loser fetched the winner's records (phase 1 and 2) but
/// no session looked at them: the store itself holds every vault row of
/// the loser and its phase does not advance, so nothing of the winner's
/// vault key, meta or manifest is overwritten.
#[test]
fn loser_never_overwrites_a_known_winner() {
    let r = race(|_| vec![], |_| vec![], |_, _, _| {}, |_| {}, |_, _| {});
    let a_wins = r.a_wins();
    let Race {
        mut server, a, c, ..
    } = r;
    let (mut w, l) = if a_wins { (a, c) } else { (c, a) };
    sync(&mut server, &mut w).unwrap();
    assert_eq!(state(&w), DeviceLineageState::Current);
    let v = w.vault().id;
    let slots: Vec<_> = [
        RecordKind::VaultKey,
        RecordKind::VaultMeta,
        RecordKind::Manifest,
    ]
    .map(|k| server.get(k, v))
    .to_vec();
    let (changes, _) = server.changes_since(l.cursor);
    let mut store = l.store();
    for ch in changes {
        store.stage_remote(ch).unwrap();
    }
    store.commit_remote().unwrap();
    assert!(
        outbox(&l)
            .iter()
            .all(|(ch, _)| ch.kind == RecordKind::Lineage),
        "{:?}",
        outbox(&l).iter().map(|(ch, _)| ch.kind).collect::<Vec<_>>()
    );
    assert_eq!(
        l.store().push_rotation_phase(2).unwrap(),
        PhaseOutcome::Retry
    );
    push_outbox(&mut server, &l).unwrap();
    let after: Vec<_> = [
        RecordKind::VaultKey,
        RecordKind::VaultMeta,
        RecordKind::Manifest,
    ]
    .map(|k| server.get(k, v))
    .to_vec();
    assert_eq!(after, slots);
    pull(&server, &mut w);
    assert_eq!(
        users(&w.items()),
        ["alice", "bob", "carol"].map(String::from)
    );
}

/// Controller ruling (Task 4 review): E followed S1, signed by B; A, on a
/// sibling branch it made without seeing S1, revokes B. E is told (A
/// removed B on another set of keys), never adopts silently and is not
/// quarantined.
#[test]
fn cross_branch_revocation_alerts() {
    let mut server = Server::default();
    let (mut a, f) = fixture_on(&mut server);
    let mut b = follower_with(&mut server, &a, &f, B, |_| {});
    let mut e = follower_with(&mut server, &a, &f, 2, |_| {});
    // A writes nothing while away: it does not see S1 before rotating.
    let before = server.clone();
    b.unlock(&f.sk);
    let b_sk = SecretKey::generate().unwrap();
    let mut req = request(&f, &b_sk, vec![], RotationReason::Rotate);
    req.device_keys = &f.others[B].keys;
    let s1 = b.repo.as_mut().unwrap().rotate(req).unwrap();
    sync(&mut server, &mut b).unwrap();
    pull(&server, &mut e);
    let (repo, _, _) = follow_rotation(e.store(), s1.head, PASSWORD, &f.others[2].keys).unwrap();
    e.repo = Some(repo);
    assert_eq!(head_of(&e), s1.head);

    // A, on the server as it was before S1, revokes B.
    let mut away = before;
    let a_sk = SecretKey::generate().unwrap();
    let req = request(&f, &a_sk, vec![f.others[B].id()], RotationReason::Revoke);
    let ra = a.repo.as_mut().unwrap().rotate(req).unwrap();
    sync(&mut away, &mut a).unwrap();
    // Its records reach E's server (phase 1, then its content).
    for ((kind, id), entry) in &away.records {
        if matches!(
            kind,
            RecordKind::Lineage
                | RecordKind::KeyDelivery
                | RecordKind::AccountParams
                | RecordKind::Keyset
        ) && entry.record.is_some()
            && server.get(*kind, *id).is_none()
        {
            server.replay(entry.record.clone().unwrap());
        }
    }
    pull(&server, &mut e);
    let p = e
        .repo()
        .refresh_pending_rotation()
        .unwrap()
        .expect("an alert");
    assert_eq!(p.kind, PromptKind::Switch);
    assert!(p.cross_branch_revocation);
    assert_eq!(p.choices.len(), 1);
    assert_eq!(p.choices[0].hash, ra.head);
    assert_eq!(p.choices[0].rotator_name, "iPhone");
    assert_eq!(p.choices[0].revoked_names, vec!["iPad".to_string()]);
    // Never a quarantine, never adopted silently, read-only meanwhile.
    let t = e.store().trust_state().unwrap().unwrap();
    assert_eq!(t.head.hash, s1.head);
    assert_eq!(
        t.state,
        DeviceLineageState::Candidate {
            children: vec![ra.head],
            resume: None,
        }
    );
    let v = e.vault();
    assert_eq!(
        e.repo().save_item(&v, login(v.id, "x", T0 + 99)).err(),
        Some(Error::ReadOnly)
    );
    // A plain follow refuses a switch; the session one takes it.
    assert!(is_validation(
        &follow_rotation(e.store(), ra.head, PASSWORD, &f.others[2].keys).map(|_| ())
    ));
    let session = e.repo.take().unwrap();
    let (repo, _, _) = follow_switch(session, ra.head, PASSWORD, &f.others[2].keys).unwrap();
    e.repo = Some(repo);
    let t = e.store().trust_state().unwrap().unwrap();
    assert_eq!(t.head.hash, ra.head);
    assert!(t.revoked.contains(&f.others[B].id()));
}

/// Task 19 carried item 4: the cross-branch flag counts only the records
/// of the device's own chain after the divergence point. B rotates (R1),
/// everyone follows; then A and C both rotate from R1 revoking B. E, on
/// the losing sibling, is asked to switch: the winner revokes B, the
/// rotator of R1, which both branches share, so it is no removal "on
/// another set of keys".
#[test]
fn cross_branch_flag_stops_at_the_divergence() {
    let mut server = Server::default();
    let (mut a, f) = fixture_on(&mut server);
    let mut b = follower_with(&mut server, &a, &f, B, |_| {});
    let mut c = follower_with(&mut server, &a, &f, C, |_| {});
    let mut e = follower_with(&mut server, &a, &f, 2, |_| {});
    b.unlock(&f.sk);
    let b_sk = SecretKey::generate().unwrap();
    let mut req = request(&f, &b_sk, vec![], RotationReason::Rotate);
    req.device_keys = &f.others[B].keys;
    let r1 = b.repo.as_mut().unwrap().rotate(req).unwrap();
    sync(&mut server, &mut b).unwrap();
    a.repo = None;
    for (dev, keys) in [
        (&mut a, &f.me.keys),
        (&mut c, &f.others[C].keys),
        (&mut e, &f.others[2].keys),
    ] {
        pull(&server, dev);
        let (repo, _, _) = follow_rotation(dev.store(), r1.head, PASSWORD, keys).unwrap();
        dev.repo = Some(repo);
    }
    let mut siblings = Vec::new();
    for (dev, keys) in [(&mut a, &f.me.keys), (&mut c, &f.others[C].keys)] {
        let new_sk = SecretKey::generate().unwrap();
        let mut req = request(&f, &new_sk, vec![f.others[B].id()], RotationReason::Revoke);
        req.secret_key = &b_sk;
        req.device_keys = keys;
        let out = dev.repo.as_mut().unwrap().rotate(req).unwrap();
        push_outbox(&mut server, dev).unwrap();
        assert_eq!(
            dev.store().push_rotation_phase(1).unwrap(),
            PhaseOutcome::Done
        );
        siblings.push(out.head);
    }
    siblings.sort();
    let (wh, lh) = (siblings[0], siblings[1]);
    // E sees the loser first and follows it.
    let mut hidden = [0u8; 16];
    hidden.copy_from_slice(&wh[..16]);
    let cursor = e.cursor;
    pull_mapped(&server, &mut e, |ch| {
        (ch.kind != RecordKind::Lineage || ch.id != Id(hidden)).then_some(ch)
    });
    e.cursor = cursor;
    let session = e.repo.take().unwrap();
    drop(session);
    let (repo, _, _) = follow_rotation(e.store(), lh, PASSWORD, &f.others[2].keys).unwrap();
    e.repo = Some(repo);
    // The winner arrives.
    pull(&server, &mut e);
    let p = e
        .repo()
        .refresh_pending_rotation()
        .unwrap()
        .expect("a switch");
    assert_eq!(p.kind, PromptKind::Switch);
    assert_eq!(p.choices[0].hash, wh);
    assert_eq!(p.choices[0].revoked_names.len(), 1);
    assert!(!p.cross_branch_revocation, "B's record is shared");
}

/// Review M1 (fix round 2): the loser switches before its own phase 1 went
/// out. Its lineage record, deliveries, params, keyset and lists are
/// dropped from its outbox and never reach the server.
#[test]
fn switch_drops_the_losers_unsent_phase_one() {
    let mut server = Server::default();
    let (mut a, f) = fixture_on(&mut server);
    let mut c = follower_with(&mut server, &a, &f, C, |_| {});
    c.unlock(&f.sk);
    let a_sk = SecretKey::generate().unwrap();
    let ra = a
        .repo
        .as_mut()
        .unwrap()
        .rotate(request(&f, &a_sk, vec![], RotationReason::Rotate))
        .unwrap();
    let c_sk = SecretKey::generate().unwrap();
    let mut req = request(&f, &c_sk, vec![], RotationReason::Rotate);
    req.device_keys = &f.others[C].keys;
    let rc = c.repo.as_mut().unwrap().rotate(req).unwrap();
    let a_wins = ra.head < rc.head;
    let (wh, lh) = if a_wins {
        (ra.head, rc.head)
    } else {
        (rc.head, ra.head)
    };
    let (mut w, mut l) = if a_wins { (a, c) } else { (c, a) };
    // Only the winner's phase 1 goes out.
    push_outbox(&mut server, &w).unwrap();
    assert_eq!(
        w.store().push_rotation_phase(1).unwrap(),
        PhaseOutcome::Done
    );
    pull(&server, &mut l);
    l.repo().refresh_pending_rotation().unwrap();
    assert_eq!(
        state(&l),
        DeviceLineageState::Candidate {
            children: vec![wh],
            resume: Some(1),
        }
    );
    let body = rotation_of(&l.store(), &lh);
    let left_id = identity_id(&body.identity_pub);
    let mut id = [0u8; 16];
    id.copy_from_slice(&lh[..16]);
    let mut rows = vec![(RecordKind::Lineage, Id(id))];
    rows.extend(
        body.deliveries
            .iter()
            .map(|(r, _)| (RecordKind::KeyDelivery, delivery_id(&lh, *r))),
    );
    for kind in [
        RecordKind::AccountParams,
        RecordKind::Keyset,
        RecordKind::DeviceList,
        RecordKind::VaultList,
    ] {
        rows.push((kind, left_id));
    }
    for (kind, id) in &rows {
        assert!(l.store().is_pending_write(*kind, *id).unwrap(), "{kind:?}");
    }

    sync(&mut server, &mut w).unwrap();
    pull(&server, &mut l);
    let session = l.repo.take().unwrap();
    let (repo, _, _) = follow_switch(session, wh, PASSWORD, keys_of(&f, !a_wins)).unwrap();
    l.repo = Some(repo);
    assert_eq!(head_of(&l), wh);
    for (kind, id) in &rows {
        assert!(!l.store().is_pending_write(*kind, *id).unwrap(), "{kind:?}");
    }
    sync(&mut server, &mut l).unwrap();
    for (kind, id) in &rows {
        assert!(server.get(*kind, *id).is_none(), "{kind:?} on the server");
        assert!(
            outbox(&l)
                .iter()
                .all(|(ch, _)| (ch.kind, ch.id) != (*kind, *id)),
            "{kind:?} in the outbox"
        );
    }
    assert_eq!(
        users(&l.items()),
        ["alice", "bob", "carol"].map(String::from)
    );
}

// ------------------------------------------------- quarantine (Task 12)

use onepass_core::repo::follow::{
    QUARANTINE_ERASE_AFTER_SECS, QuarantineChoice, QuarantineTick, quarantine_resolve,
    quarantine_tick,
};

/// Device time, in Unix seconds, when C first reads its own revocation.
const T: u64 = 1_793_100_000;
const Q: u64 = QUARANTINE_ERASE_AFTER_SECS;

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

/// A and C on one server; C (`edit` applied to its trust state) writes
/// "dave" without pushing it; A rotates revoking C and pushes every phase;
/// C fetches what `map` lets through, locked.
fn c_revoked_with(
    edit: impl FnOnce(&mut TrustState),
    map: impl Fn(RemoteChange) -> Option<RemoteChange>,
) -> (Server, Device, Device, Fixture, RotationOutcome) {
    let mut server = Server::default();
    let (mut a, f) = fixture_on(&mut server);
    let mut c = follower_with(&mut server, &a, &f, C, edit);
    c.unlock(&f.sk);
    let v = c.vault();
    c.save(&login(v.id, "dave", T0 + 50));
    c.lock();
    assert!(!outbox(&c).is_empty());
    let new_sk = SecretKey::generate().unwrap();
    let req = request(&f, &new_sk, vec![f.others[C].id()], RotationReason::Revoke);
    let out = a.repo.as_mut().unwrap().rotate(req).unwrap();
    sync(&mut server, &mut a).unwrap();
    pull_mapped(&server, &mut c, map);
    (server, a, c, f, out)
}

fn c_revoked() -> (Server, Device, Device, Fixture, RotationOutcome) {
    c_revoked_with(|_| {}, Some)
}

fn records(dev: &Device) -> Vec<Record> {
    snapshot(&dev.store()).records
}

/// A pending write nothing else holds back (an intro, a lineage kind that
/// even a `Candidate` device pushes): it goes out unless the device itself
/// is held.
fn stray_write(dev: &Device) {
    let rec = Record {
        id: Id::new(),
        kind: RecordKind::DeviceIntro,
        version: 1,
        data: vec![1, 2, 3],
    };
    dev.store().put(rec).unwrap();
}

fn tick(dev: &Device, now: u64) -> QuarantineTick {
    quarantine_tick(&mut dev.store(), now).unwrap()
}

fn is_quarantine_refusal<T: std::fmt::Debug>(r: &Result<T>) -> bool {
    matches!(r, Err(Error::Validation(v)) if v.reason == "quarantined")
}

fn not_me<'a>(dev: &Device, password: &'a str, sk: &'a SecretKey) -> QuarantineChoice<'a> {
    QuarantineChoice::NotMe {
        password,
        secret_key: sk,
        device: dev.store().device_state().unwrap(),
    }
}

/// The store holds nothing: no record, no trust, chain or device state,
/// nothing to push.
fn assert_erased(dev: &Device) {
    let store = dev.store();
    assert_eq!(
        snapshot(&store),
        Snapshot {
            records: vec![],
            trust: None,
            chain: ChainState::default().encode(),
            outbox: vec![],
        }
    );
    assert_eq!(store.account_state().unwrap(), AccountState::Empty);
    assert_eq!(store.device_state().unwrap(), Default::default());
}

/// Spec 8.4: a valid child revoking C locks C at once (no unlock, nothing
/// pushed), and the clock starts at the first tick, in the same write as
/// the state. Nothing is erased before 7 days.
#[test]
fn self_revocation_locks_then_waits() {
    let (_server, _a, mut c, f, out) = c_revoked();
    stray_write(&c);
    let before = records(&c);
    assert_eq!(prompt_of(&c), None);
    assert!(outbox(&c).is_empty(), "nothing goes out");
    assert!(is_quarantine_refusal(&c.try_unlock(PASSWORD, &f.sk)));
    assert_eq!(state(&c), DeviceLineageState::Current);

    assert_eq!(tick(&c, T), QuarantineTick::Waiting { erase_at: T + Q });
    assert_eq!(
        state(&c),
        DeviceLineageState::Quarantined {
            by: out.head,
            rotator: f.me.id(),
            since: T,
            resume: None,
        }
    );
    assert_eq!(records(&c), before);
    assert_eq!(
        tick(&c, T + Q - 1),
        QuarantineTick::Waiting { erase_at: T + Q }
    );
    assert_eq!(records(&c), before);
    assert!(outbox(&c).is_empty());
    assert!(is_quarantine_refusal(&c.try_unlock(PASSWORD, &f.sk)));
    // Following or rejecting is not offered from a quarantine.
    let mut store = c.store();
    assert!(is_validation(&reject_rotation(&mut store, out.head, true)));
    let r = follow_rotation(c.store(), out.head, PASSWORD, &f.others[C].keys).map(|_| ());
    assert!(is_validation(&r));
    assert_eq!(records(&c), before);
}

#[test]
fn erased_after_seven_days() {
    let (_server, _a, c, _f, _out) = c_revoked();
    assert_eq!(tick(&c, T), QuarantineTick::Waiting { erase_at: T + Q });
    assert_eq!(tick(&c, T + Q), QuarantineTick::Erased);
    assert_erased(&c);
    assert_eq!(tick(&c, T + Q + 1), QuarantineTick::NotQuarantined);
}

/// A clock moved back never erases early: nothing is counted for the move,
/// the erase date shifts to the new reading plus what is left (amended
/// 2026-11-03: the count no longer freezes either).
#[test]
fn clock_moved_back_never_erases_early() {
    let (_server, _a, c, f, out) = c_revoked();
    tick(&c, T);
    let before = records(&c);
    assert_eq!(
        tick(&c, T - 86_400),
        QuarantineTick::Waiting {
            erase_at: T - 86_400 + Q
        }
    );
    assert_eq!(tick(&c, 0), QuarantineTick::Waiting { erase_at: Q });
    assert_eq!(records(&c), before);
    assert_eq!(
        state(&c),
        DeviceLineageState::Quarantined {
            by: out.head,
            rotator: f.me.id(),
            since: T,
            resume: None,
        }
    );
}

/// The erase date never moves: reading the record again, or the server
/// withholding it afterwards, keeps `since`.
#[test]
fn since_is_kept_on_reread() {
    let (mut server, _a, mut c, f, out) = c_revoked();
    tick(&c, T);
    full_fetch(&server, &mut c);
    assert_eq!(
        tick(&c, T + 3 * 86_400),
        QuarantineTick::Waiting { erase_at: T + Q }
    );
    let quarantined = DeviceLineageState::Quarantined {
        by: out.head,
        rotator: f.me.id(),
        since: T,
        resume: None,
    };
    assert_eq!(state(&c), quarantined);
    // A hostile server now withholds the record: still quarantined, same
    // date.
    let mut id = [0u8; 16];
    id.copy_from_slice(&out.head[..16]);
    server.forge_deletion(RecordKind::Lineage, Id(id));
    full_fetch(&server, &mut c);
    assert_eq!(
        tick(&c, T + 4 * 86_400),
        QuarantineTick::Waiting { erase_at: T + Q }
    );
    assert_eq!(state(&c), quarantined);
    assert_eq!(tick(&c, T + Q), QuarantineTick::Erased);
}

#[test]
fn not_me_cancels_erase() {
    let (_server, _a, mut c, f, out) = c_revoked();
    tick(&c, T);
    let before = records(&c);
    let repo = quarantine_resolve(c.store(), not_me(&c, PASSWORD, &f.sk))
        .unwrap()
        .expect("a session");
    c.repo = Some(repo);
    assert_eq!(state(&c), DeviceLineageState::Current);
    assert_eq!(tick(&c, T + 30 * 86_400), QuarantineTick::NotQuarantined);
    assert_eq!(records(&c), before);
    let trust = c.store().trust_state().unwrap().unwrap();
    assert!(trust.ignored.contains(&out.head));
    c.lock();
    c.unlock(&f.sk);
    assert!(c.repo().pending_prompt().is_none());
}

#[test]
fn not_me_excludes_signer() {
    let (_server, _a, c, f, out) = c_revoked();
    tick(&c, T);
    let quarantined = state(&c);
    let r = quarantine_resolve(c.store(), not_me(&c, NEW_PASSWORD, &f.sk));
    assert!(matches!(r, Err(Error::WrongPassword)), "{:?}", r.err());
    assert_eq!(state(&c), quarantined);
    quarantine_resolve(c.store(), not_me(&c, PASSWORD, &f.sk))
        .unwrap()
        .unwrap();
    let trust = c.store().trust_state().unwrap().unwrap();
    assert_eq!(trust.state, DeviceLineageState::Current);
    assert!(trust.excluded.contains(&f.me.id()));
    assert_eq!(trust.ignored, vec![out.head]);
    assert_eq!(trust.head.generation, 0);
}

/// G4: only a valid lineage record locks a device. A record whose identity
/// signature is broken, or signed by a device C never pinned, leaves C
/// `Current`, unlockable, and erases nothing whatever the clock says.
#[test]
fn invalid_record_never_quarantines() {
    let broken = |mut ch: RemoteChange| {
        if ch.kind == RecordKind::Lineage
            && let Some(d) = ch.data.as_mut()
            && matches!(LineageRecord::decode(d), Ok(LineageRecord::Rotation(_)))
        {
            *d.last_mut().unwrap() ^= 1;
        }
        Some(ch)
    };
    let (_s, _a, c1, f1, _o) = c_revoked_with(|_| {}, broken);
    // A is not in C's roster.
    let (_s, _a, c2, f2, _o) = c_revoked_with(
        |t| {
            let a = t
                .roster
                .iter()
                .find(|e| e.name == "iPhone")
                .unwrap()
                .device_id;
            t.roster.retain(|e| e.device_id != a);
            t.levels.remove(&a);
        },
        Some,
    );
    for (mut c, f) in [(c1, f1), (c2, f2)] {
        let before = records(&c);
        assert_eq!(prompt_of(&c), None);
        assert_eq!(tick(&c, T), QuarantineTick::NotQuarantined);
        assert_eq!(tick(&c, T + 365 * 86_400), QuarantineTick::NotQuarantined);
        assert_eq!(state(&c), DeviceLineageState::Current);
        assert_eq!(records(&c), before);
        let r = quarantine_resolve(c.store(), QuarantineChoice::Erase).map(|r| r.is_some());
        assert!(is_validation(&r));
        assert_eq!(records(&c), before);
        c.try_unlock(PASSWORD, &f.sk).unwrap();
    }
}

#[test]
fn erase_now() {
    let (_server, a, c, _f, _out) = c_revoked();
    tick(&c, T);
    assert!(
        quarantine_resolve(c.store(), QuarantineChoice::Erase)
            .unwrap()
            .is_none()
    );
    assert_erased(&c);
    assert_eq!(tick(&c, T + 1), QuarantineTick::NotQuarantined);
    // Never on a device that is not quarantined.
    let before = records(&a);
    let r = quarantine_resolve(a.store(), QuarantineChoice::Erase).map(|r| r.is_some());
    assert!(is_validation(&r));
    assert_eq!(records(&a), before);
}

/// Port of `revoked_device_can_revoke_its_revoker` (spec 8.4, 10.1): B,
/// revoked in the account-signed device list by A, revokes A there too.
/// The list is signed with the account keys B holds, so A ignores it: not
/// revoked, never quarantined, intact and writable.
#[test]
fn forged_device_list_never_erases() {
    let mut server = Server::default();
    let (mut a, f) = fixture_on(&mut server);
    // B: a device holding the account keys, without a trust state (a
    // legacy build, or a thief's tool), that may still sign the list.
    let mut b = Device::empty();
    pull(&server, &mut b);
    b.unlock(&f.sk);
    let a_id = a.repo().this_device_id().unwrap();
    let b_id = b
        .repo()
        .register_this_device("iPad", DeviceKind::Tablet, DeviceMode::Personal)
        .unwrap();
    sync(&mut server, &mut b).unwrap();
    pull(&server, &mut a);
    // Review M1: on a device with a trust state, removing a device is a
    // rotation, never a list edit.
    let before = records(&a);
    let r = a.repo().revoke_device(b_id);
    assert!(is_validation(&r), "{r:?}");
    assert_eq!(records(&a), before);
    // B revokes A in the list.
    b.repo().revoke_device(a_id).unwrap();
    sync(&mut server, &mut b).unwrap();
    pull(&server, &mut a);

    assert!(!a.repo().is_this_device_revoked().unwrap());
    let devices = a.repo().devices().unwrap();
    assert_eq!(
        devices
            .iter()
            .find(|e| e.device_id == a_id)
            .unwrap()
            .revoked_at,
        None
    );
    assert_eq!(tick(&a, T + 365 * 86_400), QuarantineTick::NotQuarantined);
    assert_eq!(state(&a), DeviceLineageState::Current);
    a.lock();
    a.unlock(&f.sk);
    let v = a.vault();
    a.save(&login(v.id, "erin", T0 + 70));
    assert_eq!(
        users(&a.items()),
        ["alice", "bob", "carol", "erin"].map(String::from)
    );
}

/// Port of `zz4_revoked_device_fake_complete_rotation_beats_a`: A revokes
/// B; B, offline, makes a complete rotation revoking A. On A it is signed
/// by a revoked device: ignored, A never moves nor locks. On C, which has
/// not seen A's record, it needs the user, who refuses it.
#[test]
fn zz4_on_a_and_on_c() {
    let mut server = Server::default();
    let (mut a, f) = fixture_on(&mut server);
    let mut b = follower_with(&mut server, &a, &f, B, |_| {});
    let mut c = follower_with(&mut server, &a, &f, C, |_| {});
    let a_sk = SecretKey::generate().unwrap();
    let req = request(&f, &a_sk, vec![f.others[B].id()], RotationReason::Revoke);
    let ra = a.repo.as_mut().unwrap().rotate(req).unwrap();
    sync(&mut server, &mut a).unwrap();
    // B's rotation from the genesis, revoking A, phase 1 complete.
    b.unlock(&f.sk);
    let b_sk = SecretKey::generate().unwrap();
    let mut req = request(&f, &b_sk, vec![f.me.id()], RotationReason::Revoke);
    req.device_keys = &f.others[B].keys;
    let rb = b.repo.as_mut().unwrap().rotate(req).unwrap();
    push_outbox(&mut server, &b).unwrap();

    // On A: nothing.
    pull(&server, &mut a);
    assert_eq!(a.repo().refresh_pending_rotation().unwrap(), None);
    assert_eq!(state(&a), DeviceLineageState::Current);
    assert_eq!(head_of(&a), ra.head);
    assert_eq!(tick(&a, T + 365 * 86_400), QuarantineTick::NotQuarantined);
    let v = a.vault();
    a.save(&login(v.id, "erin", T0 + 70));

    // On C, A's record withheld: a prompt naming B as the rotator.
    let mut ra_id = [0u8; 16];
    ra_id.copy_from_slice(&ra.head[..16]);
    pull_mapped(&server, &mut c, |ch| {
        (ch.kind != RecordKind::Lineage || ch.id != Id(ra_id)).then_some(ch)
    });
    let prompt = prompt_of(&c).expect("a prompt");
    assert_eq!(prompt.kind, PromptKind::Single);
    assert_eq!(prompt.choices[0].hash, rb.head);
    assert_eq!(prompt.choices[0].rotator_name, "iPad");
    assert_eq!(prompt.choices[0].revoked_names, vec!["iPhone".to_string()]);
    assert_eq!(tick(&c, T), QuarantineTick::NotQuarantined);
    let mut store = c.store();
    reject_rotation(&mut store, rb.head, true).unwrap();
    assert_eq!(state(&c), DeviceLineageState::Current);
    assert!(
        c.store()
            .trust_state()
            .unwrap()
            .unwrap()
            .excluded
            .contains(&f.others[B].id())
    );
    // A's record arrives: that is the one C is asked about now.
    full_fetch(&server, &mut c);
    let prompt = prompt_of(&c).expect("a prompt");
    assert_eq!(prompt.choices.len(), 1);
    assert_eq!(prompt.choices[0].hash, ra.head);
}

/// Spec 8.1 and the Task 4 ruling: a valid child that does not list C
/// makes it `Orphaned`: its data reads after unlock, nothing is written or
/// pushed, nothing erases; "Ce n'était pas moi" with the password excludes
/// the signer and returns to `Current`.
#[test]
fn orphaned_reads_only_until_not_me() {
    let mut server = Server::default();
    let (mut a, f) = fixture_on(&mut server);
    let mut c = follower_with(&mut server, &a, &f, C, |_| {});
    c.unlock(&f.sk);
    let v = c.vault();
    c.save(&login(v.id, "dave", T0 + 50));
    c.lock();
    // A never pinned C.
    let mut trust = a.store().trust_state().unwrap().unwrap();
    trust.roster.retain(|e| e.device_id != f.others[C].id());
    trust.levels.remove(&f.others[C].id());
    a.repo()
        .store_mut()
        .put_all_if_version_with_trust(vec![], vec![], None, &trust)
        .unwrap();
    let new_sk = SecretKey::generate().unwrap();
    let out = a
        .repo
        .as_mut()
        .unwrap()
        .rotate(request(&f, &new_sk, vec![], RotationReason::Rotate))
        .unwrap();
    sync(&mut server, &mut a).unwrap();
    pull(&server, &mut c);

    assert_eq!(prompt_of(&c), None);
    assert!(outbox(&c).is_empty(), "nothing goes out");
    c.unlock(&f.sk);
    assert_eq!(
        state(&c),
        DeviceLineageState::Orphaned {
            child: out.head,
            rotator: f.me.id(),
            resume: None,
        }
    );
    assert_eq!(
        users(&c.items()),
        ["alice", "bob", "carol", "dave"].map(String::from)
    );
    let v = c.vault();
    assert_eq!(
        c.repo().save_item(&v, login(v.id, "eve", T0 + 80)).err(),
        Some(Error::ReadOnly)
    );
    c.lock();
    stray_write(&c);
    assert!(outbox(&c).is_empty());
    let before = records(&c);
    assert_eq!(tick(&c, T + 365 * 86_400), QuarantineTick::NotQuarantined);
    assert!(is_validation(
        &quarantine_resolve(c.store(), QuarantineChoice::Erase).map(|r| r.is_some())
    ));
    let r = quarantine_resolve(c.store(), not_me(&c, NEW_PASSWORD, &f.sk));
    assert!(matches!(r, Err(Error::WrongPassword)), "{:?}", r.err());
    assert_eq!(records(&c), before);

    let repo = quarantine_resolve(c.store(), not_me(&c, PASSWORD, &f.sk))
        .unwrap()
        .unwrap();
    c.repo = Some(repo);
    let trust = c.store().trust_state().unwrap().unwrap();
    assert_eq!(trust.state, DeviceLineageState::Current);
    assert!(trust.excluded.contains(&f.me.id()));
    assert!(trust.ignored.contains(&out.head));
    assert!(c.repo().pending_prompt().is_none());
    assert_eq!(
        users(&c.items()),
        ["alice", "bob", "carol", "dave"].map(String::from)
    );
}

/// Review I1: a rotator quarantined by a winning sibling that revokes it
/// (the sibling's signer is the stolen device) answers "Ce n'était pas
/// moi" and goes back to pushing its own rotation where it stopped.
#[test]
fn not_me_resumes_a_quarantined_rotation() {
    let mut server = Server::default();
    let (mut a, f) = fixture_on(&mut server);
    let mut c = follower_with(&mut server, &a, &f, C, |_| {});
    c.unlock(&f.sk);
    let a_sk = SecretKey::generate().unwrap();
    let req = request(&f, &a_sk, vec![f.others[C].id()], RotationReason::Revoke);
    let ra = a.repo.as_mut().unwrap().rotate(req).unwrap();
    let c_sk = SecretKey::generate().unwrap();
    let mut req = request(&f, &c_sk, vec![], RotationReason::Rotate);
    req.device_keys = &f.others[C].keys;
    c.repo.as_mut().unwrap().rotate(req).unwrap();
    for d in [&a, &c] {
        push_outbox(&mut server, d).unwrap();
        assert_eq!(
            d.store().push_rotation_phase(1).unwrap(),
            PhaseOutcome::Done
        );
    }
    c.repo = None;
    pull(&server, &mut c);
    assert_eq!(state(&c), rotating(2));
    assert_eq!(tick(&c, T), QuarantineTick::Waiting { erase_at: T + Q });
    assert_eq!(
        state(&c),
        DeviceLineageState::Quarantined {
            by: ra.head,
            rotator: f.me.id(),
            since: T,
            resume: Some(2),
        }
    );
    assert_eq!(
        c.store().push_rotation_phase(2).unwrap(),
        PhaseOutcome::Retry
    );
    let repo = quarantine_resolve(c.store(), not_me(&c, PASSWORD, &c_sk))
        .unwrap()
        .unwrap();
    drop(repo);
    assert_eq!(state(&c), rotating(2));
    push(&mut server, &c).unwrap();
    assert_eq!(state(&c), DeviceLineageState::Current);
}

/// Review I2: the signer is excluded even when the server deleted the
/// record that quarantined the device; its next record revoking the
/// device does not quarantine it again.
#[test]
fn not_me_excludes_a_withheld_signer() {
    let mut server = Server::default();
    let (mut a, f) = fixture_on(&mut server);
    let mut c = follower_with(&mut server, &a, &f, C, |_| {});
    // S: A's device file before the rotation (same keys, same head).
    let mut s = sibling_of(&mut a, &f.sk);
    let sk1 = SecretKey::generate().unwrap();
    let req = request(&f, &sk1, vec![f.others[C].id()], RotationReason::Revoke);
    let ra = a.repo.as_mut().unwrap().rotate(req).unwrap();
    sync(&mut server, &mut a).unwrap();
    pull(&server, &mut c);
    tick(&c, T);
    let mut id = [0u8; 16];
    id.copy_from_slice(&ra.head[..16]);
    server.forge_deletion(RecordKind::Lineage, Id(id));
    full_fetch(&server, &mut c);
    // The sync store refuses that deletion; the row is gone all the same
    // (a store that lost it): the stored signer is what counts.
    let conn = rusqlite::Connection::open(&c.path).unwrap();
    let gone = conn
        .execute(
            "DELETE FROM base WHERE kind = ?1 AND id = ?2",
            rusqlite::params![RecordKind::Lineage.code(), &id[..]],
        )
        .unwrap();
    assert_eq!(gone, 1);
    drop(conn);
    assert!(
        c.store()
            .get(RecordKind::Lineage, Id(id))
            .unwrap()
            .is_none()
    );
    quarantine_resolve(c.store(), not_me(&c, PASSWORD, &f.sk))
        .unwrap()
        .unwrap();
    let trust = c.store().trust_state().unwrap().unwrap();
    assert!(trust.excluded.contains(&f.me.id()));
    assert_eq!(trust.state, DeviceLineageState::Current);

    let sk2 = SecretKey::generate().unwrap();
    let req = request(&f, &sk2, vec![f.others[C].id()], RotationReason::Revoke);
    s.repo.as_mut().unwrap().rotate(req).unwrap();
    push_outbox(&mut server, &s).unwrap();
    pull(&server, &mut c);
    assert_eq!(tick(&c, T + 86_400), QuarantineTick::NotQuarantined);
    assert_eq!(state(&c), DeviceLineageState::Current);
}

/// Review M4: "Ce n'était pas moi" and "Effacer" before the first tick
/// (the resolver's decision, no clock yet), and an erase whose trust state
/// changed meanwhile erases nothing.
#[test]
fn answers_before_the_first_tick() {
    let (_server, _a, c, f, _out) = c_revoked();
    assert_eq!(state(&c), DeviceLineageState::Current);
    let stale = c.store().trust_state().unwrap().unwrap();
    let mut other = stale.clone();
    other.ignore([0xAB; 32]);
    let before = records(&c);
    assert_eq!(c.store().erase_device(&other, None), Err(Error::Conflict));
    assert_eq!(records(&c), before);
    quarantine_resolve(c.store(), not_me(&c, PASSWORD, &f.sk))
        .unwrap()
        .unwrap();
    assert!(
        c.store()
            .trust_state()
            .unwrap()
            .unwrap()
            .excluded
            .contains(&f.me.id())
    );
    // The stale trust state no longer erases.
    assert_eq!(c.store().erase_device(&stale, None), Err(Error::Conflict));
    assert_eq!(records(&c), before);

    let (_server, _a, c, _f, _out) = c_revoked();
    assert!(
        quarantine_resolve(c.store(), QuarantineChoice::Erase)
            .unwrap()
            .is_none()
    );
    assert_erased(&c);
}

// ------------------------------------------------- Emergency Kit (Task 15)

use onepass_core::lineage::{SignedIntro, verify_intro, verify_intro_identity};
use onepass_core::repo::kit::{KitRestore, UNKNOWN_ROTATOR};

/// The keys the app creates for a device restored with the kit.
fn kit_keys() -> DeviceKeys {
    DeviceKeys::generate_software().unwrap()
}

/// "Restaurer avec mon Emergency Kit" on `dev` (spec 7.5), as the app
/// calls it: the device state it saved, fresh device keys. The session
/// stays open and its device state is saved.
fn restore_kit(dev: &mut Device, sk: &SecretKey, keys: &DeviceKeys) -> Result<()> {
    let store = dev.store();
    let device = store.device_state()?;
    let repo = Repository::restore_from_kit(
        store,
        KitRestore {
            password: PASSWORD,
            secret_key: sk,
            device_keys: keys,
            name: "iPad neuf",
            kind: DeviceKind::Tablet,
            mode: DeviceMode::Personal,
            device,
        },
    )?;
    dev.repo = Some(repo);
    dev.repo().persist_device_state()
}

fn trust_of_dev(dev: &Device) -> Option<TrustState> {
    dev.store().trust_state().unwrap()
}

fn in_roster(t: &TrustState, id: Id) -> bool {
    t.roster.iter().any(|e| e.device_id == id)
}

/// The lineage record id of `h`.
fn lineage_id(h: &[u8; 32]) -> Id {
    let mut id = [0u8; 16];
    id.copy_from_slice(&h[..16]);
    Id(id)
}

/// Spec 7.5 steps 1 to 3, R14 (`rotation.pv`, `restore_new`): the latest
/// kit opens the identity of the head; its signature over the head is
/// what pins the roster; the device is new, outside the roster, and
/// publishes a self-intro signed by its key and by the identity.
#[test]
fn latest_kit_pins_roster_through_identity_sig() {
    let (server, mut a, _c, f, out, new_sk) = rotated();
    let body = rotation_of(&a.store(), &out.head);
    let mut n = Device::empty();
    pull(&server, &mut n);
    let keys = kit_keys();
    restore_kit(&mut n, &new_sk, &keys).unwrap();

    let t = trust_of_dev(&n).expect("a trust state");
    assert_eq!(
        t.head,
        LineageHead {
            generation: 1,
            hash: out.head
        }
    );
    assert_eq!(t.identity_pub, body.identity_pub);
    assert_eq!(t.roster, body.roster);
    assert!(t.revoked.contains(&f.others[B].id()));
    assert_eq!(t.state, DeviceLineageState::Current);
    let me = t.me.device_id;
    assert_eq!(t.me, keys.public(me).unwrap());
    assert!(
        !in_roster(&t, me),
        "a kit-restored device is pinned by others"
    );
    assert!(body.roster.iter().all(|e| e.device_id != me));
    assert_eq!(n.repo().this_device_id(), Some(me));
    assert!(n.repo().awaiting_pin().unwrap());

    // The self-intro, under the head, by its own key and the identity.
    let intro = n
        .store()
        .list(RecordKind::DeviceIntro)
        .unwrap()
        .iter()
        .filter_map(|r| SignedIntro::decode(&r.data).ok())
        .find(|i| i.body.entry.device_id == me)
        .expect("a self-intro");
    assert_eq!(intro.body.head, out.head);
    assert_eq!(intro.body.introducer, me);
    assert_eq!(intro.body.entry.name, "iPad neuf");
    verify_intro(&intro, &t.me.sign_pub).unwrap();
    verify_intro_identity(&intro, &body.identity_pub).unwrap();

    // It reads the account, and unlocks again with the kit.
    assert_eq!(n.items(), a.items());
    n.lock();
    n.try_unlock(PASSWORD, &new_sk).unwrap();
    assert_eq!(n.items(), a.items());
}

/// R14: the roster comes from the identity's signature, never from what
/// the server hands over. A head whose roster was changed (the identity
/// signature no longer verifies) pins nothing, and nothing is written.
#[test]
fn kit_restore_refuses_a_roster_the_identity_did_not_sign() {
    let (mut server, _a, _c, _f, out, new_sk) = rotated();
    let rec = server
        .get(RecordKind::Lineage, lineage_id(&out.head))
        .unwrap();
    let LineageRecord::Rotation(mut forged) = LineageRecord::decode(&rec.data).unwrap() else {
        panic!("a rotation");
    };
    let thief = kit_keys();
    let i = forged
        .body
        .roster
        .iter()
        .position(|e| e.device_id != forged.body.rotator)
        .unwrap();
    forged.body.roster[i].sign_pub = thief.public(Id::new()).unwrap().sign_pub;
    let forged = LineageRecord::Rotation(forged);
    server.replay(Record {
        id: forged.record_id(),
        kind: RecordKind::Lineage,
        version: 1,
        data: forged.encode(),
    });
    let mut n = Device::empty();
    pull_only(&server, &mut n, |c| {
        !(c.kind == RecordKind::Lineage && c.id == lineage_id(&out.head))
    });
    let before = snapshot(&n.store());
    let r = restore_kit(&mut n, &new_sk, &kit_keys());
    assert_eq!(r, Err(Error::Integrity(IntegrityError::Signature)));
    assert_eq!(snapshot(&n.store()), before);
    assert!(trust_of_dev(&n).is_none());
}

/// Spec 7.5 step 4: a kit whose identity has a visible child is outdated,
/// refused with the rotator and the date. On a new device the rotator's
/// name is the neutral label (never the record's text).
#[test]
fn outdated_kit_refused_when_children_visible() {
    let (server, a, _c, f, out, _new_sk) = rotated();
    let body = rotation_of(&a.store(), &out.head);
    let mut n = Device::empty();
    pull(&server, &mut n);
    let before = snapshot(&n.store());
    let r = restore_kit(&mut n, &f.sk, &kit_keys());
    assert_eq!(
        r,
        Err(Error::OutdatedKit {
            rotator: UNKNOWN_ROTATOR.to_string(),
            at: body.issued_at,
        })
    );
    assert_eq!(snapshot(&n.store()), before);
    // A wrong password stays a wrong password.
    let store = n.store();
    let device = store.device_state().unwrap();
    let r = Repository::restore_from_kit(
        store,
        KitRestore {
            password: NEW_PASSWORD,
            secret_key: &f.sk,
            device_keys: &kit_keys(),
            name: "iPad neuf",
            kind: DeviceKind::Tablet,
            mode: DeviceMode::Personal,
            device,
        },
    );
    assert!(matches!(r, Err(Error::WrongPassword)));
}

/// Documented limit (spec 7.5 step 4, 11, `rotation.pv` `restore_old`
/// false by design): a server that hides the child lets an outdated kit
/// restore onto the old identity, which the revoked device also holds.
/// Asserted so that a change of this behaviour is noticed.
#[test]
fn outdated_kit_with_hidden_rotation_lands_on_old_identity() {
    let (server, a, _c, f, out, _new_sk) = rotated();
    let old_identity = f_old_identity(&a.store());
    let mut n = Device::empty();
    pull_only(&server, &mut n, |c| {
        !(c.kind == RecordKind::Lineage && c.id == lineage_id(&out.head))
    });
    restore_kit(&mut n, &f.sk, &kit_keys()).unwrap();
    let t = trust_of_dev(&n).unwrap();
    assert_eq!(t.head.generation, 0);
    assert_eq!(t.identity_pub, old_identity);
    assert_eq!(t.state, DeviceLineageState::Current);
}

/// Spec 7.5 step 5, R14: the self-intro shows on A as a question; A pins
/// the device only on an explicit yes, which writes A's intro and the
/// device list entry; the restored device sees itself pinned, and the
/// other devices take A's intro as any intro.
#[test]
fn kit_restored_device_needs_yes() {
    let (mut server, mut a, mut c, f, out, new_sk) = rotated();
    let (repo, _, _) = follow_rotation(c.store(), out.head, PASSWORD, &f.others[C].keys).unwrap();
    c.repo = Some(repo);
    sync(&mut server, &mut c).unwrap();

    let mut n = Device::empty();
    pull(&server, &mut n);
    let keys = kit_keys();
    restore_kit(&mut n, &new_sk, &keys).unwrap();
    sync(&mut server, &mut n).unwrap();
    let nid = n.repo().this_device_id().unwrap();
    // Nothing but the self-intro went out: no list signed by it.
    assert!(server.live(RecordKind::DeviceList, nid).is_none());

    sync(&mut server, &mut a).unwrap();
    a.repo().refresh_pending_rotation().unwrap();
    sync(&mut server, &mut c).unwrap();
    c.repo().refresh_pending_rotation().unwrap();
    // Seen, not pinned, anywhere.
    let asked = a.repo().kit_restored_devices().unwrap();
    assert_eq!(asked.len(), 1);
    assert_eq!(asked[0].device_id, nid);
    assert_eq!(asked[0].name, "iPad neuf");
    assert_eq!(asked[0].kind, DeviceKind::Tablet);
    assert!(!in_roster(&trust_of_dev(&a).unwrap(), nid));
    assert!(!in_roster(&trust_of_dev(&c).unwrap(), nid));
    assert!(
        !a.repo()
            .devices()
            .unwrap()
            .iter()
            .any(|d| d.device_id == nid)
    );

    // The yes, on A.
    a.repo().accept_kit_restored(nid, &f.me.keys).unwrap();
    let ta = trust_of_dev(&a).unwrap();
    assert!(in_roster(&ta, nid));
    // Fix round 3 (N3): a yes is not a verification.
    assert_eq!(ta.levels.get(&nid), Some(&TrustLevel::Tofu));
    assert!(a.repo().kit_restored_devices().unwrap().is_empty());
    assert!(
        a.repo()
            .devices()
            .unwrap()
            .iter()
            .any(|d| d.device_id == nid && d.revoked_at.is_none())
    );
    sync(&mut server, &mut a).unwrap();

    // N sees itself pinned; C pins it through A's intro.
    sync(&mut server, &mut n).unwrap();
    n.repo().refresh_pending_rotation().unwrap();
    let tn = trust_of_dev(&n).unwrap();
    assert!(in_roster(&tn, nid));
    assert!(!n.repo().awaiting_pin().unwrap());
    n.repo().trust_snapshot().unwrap();
    sync(&mut server, &mut c).unwrap();
    c.repo().refresh_pending_rotation().unwrap();
    assert!(in_roster(&trust_of_dev(&c).unwrap(), nid));
}

/// A "non" on the question excludes the restored device on that device.
#[test]
fn kit_restored_device_refused() {
    let (mut server, mut a, _c, _f, _out, new_sk) = rotated();
    let mut n = Device::empty();
    pull(&server, &mut n);
    restore_kit(&mut n, &new_sk, &kit_keys()).unwrap();
    sync(&mut server, &mut n).unwrap();
    let nid = n.repo().this_device_id().unwrap();
    sync(&mut server, &mut a).unwrap();
    a.repo().reject_kit_restored(nid).unwrap();
    let ta = trust_of_dev(&a).unwrap();
    assert!(ta.excluded.contains(&nid));
    assert!(!in_roster(&ta, nid));
    assert!(a.repo().kit_restored_devices().unwrap().is_empty());
    assert!(is_validation(
        &a.repo().accept_kit_restored(nid, &kit_keys())
    ));
}

/// Spec 7.5 step 5 as ruled (Task 15): before another device pins it, a
/// kit-restored device neither rotates, nor approves a pairing, nor signs
/// a list; its item writes work. Spec 7.5 as amended: when it is the only
/// device left, the user says so ("Je n'ai plus d'autre appareil"), it
/// pins itself, and from then on it rotates.
#[test]
fn restored_device_cannot_rotate_before_pinned() {
    let (mut server, mut a, _c, _f, _out, new_sk) = rotated();
    // A restore over a device that is fine is refused.
    assert!(is_validation(&restore_kit(&mut a, &new_sk, &kit_keys())));

    let mut n = Device::empty();
    pull(&server, &mut n);
    let keys = kit_keys();
    restore_kit(&mut n, &new_sk, &keys).unwrap();
    let sk2 = SecretKey::generate().unwrap();
    let req = RotateRequest {
        revoke: vec![],
        new_password: None,
        password: PASSWORD,
        secret_key: &new_sk,
        new_secret_key: &sk2,
        device_keys: &keys,
        reason: RotationReason::Rotate,
        keep_tofu: &[],
    };
    let before = snapshot(&n.store());
    assert!(is_validation(&n.repo().rotate(req)));
    assert!(is_validation(&n.repo().trust_snapshot()));
    assert!(is_validation(&n.repo().create_vault(meta("Travail"))));
    assert_eq!(snapshot(&n.store()), before);
    // Lists are read, never written (no self-registration).
    n.repo().devices().unwrap();
    assert_eq!(snapshot(&n.store()).outbox, before.outbox);
    // Item writes go on.
    let v = n.vault();
    n.save(&login(v.id, "erin", T0 + 70));

    // The only device left: the user's statement pins it.
    n.repo().claim_only_device().unwrap();
    let t = trust_of_dev(&n).unwrap();
    assert!(in_roster(&t, t.me.device_id));
    assert!(!n.repo().awaiting_pin().unwrap());
    assert!(is_validation(&n.repo().claim_only_device()));
    sync(&mut server, &mut n).unwrap();
    let req = RotateRequest {
        revoke: vec![],
        new_password: None,
        password: PASSWORD,
        secret_key: &new_sk,
        new_secret_key: &sk2,
        device_keys: &keys,
        reason: RotationReason::Rotate,
        keep_tofu: &[],
    };
    let out = n.repo().rotate(req).unwrap();
    assert_eq!(trust_of_dev(&n).unwrap().head.hash, out.head);
}

/// Spec 8.2 (exits of a locked device) as ruled (Task 15): a kit restore
/// over a quarantined device cancels the 7-day erase only when it
/// succeeds, i.e. with the kit of the identity that has no visible child
/// (the latest). The record that locked the device is in its store, so an
/// older kit is always refused there, with the rotator's local name, and
/// the clock keeps running.
#[test]
fn kit_restore_cancels_quarantine_only_with_latest_kit() {
    let mut server = Server::default();
    let (mut a, f) = fixture_on(&mut server);
    let mut b = follower_with(&mut server, &a, &f, B, |_| {});
    let new_sk = SecretKey::generate().unwrap();
    let req = request(&f, &new_sk, vec![f.others[B].id()], RotationReason::Revoke);
    let out = a.repo.as_mut().unwrap().rotate(req).unwrap();
    sync(&mut server, &mut a).unwrap();
    pull(&server, &mut b);
    assert_eq!(tick(&b, T), QuarantineTick::Waiting { erase_at: T + Q });
    let locked = trust_of_dev(&b).unwrap();
    let body = rotation_of(&a.store(), &out.head);

    let r = restore_kit(&mut b, &f.sk, &kit_keys());
    assert_eq!(
        r,
        Err(Error::OutdatedKit {
            rotator: "iPhone".to_string(),
            at: body.issued_at,
        })
    );
    assert_eq!(trust_of_dev(&b).unwrap(), locked);
    assert_eq!(tick(&b, T + 1), QuarantineTick::Waiting { erase_at: T + Q });

    restore_kit(&mut b, &new_sk, &kit_keys()).unwrap();
    let t = trust_of_dev(&b).unwrap();
    assert_eq!(t.state, DeviceLineageState::Current);
    assert_eq!(t.head.hash, out.head);
    assert_ne!(t.me.device_id, f.others[B].id(), "a new device");
    assert!(t.revoked.contains(&f.others[B].id()));
    assert!(!in_roster(&t, t.me.device_id));
    assert_eq!(b.items(), a.items());
    b.lock();
    assert_eq!(tick(&b, T + Q + 1), QuarantineTick::NotQuarantined);
    b.try_unlock(PASSWORD, &new_sk).unwrap();
    assert_eq!(b.items(), a.items());
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

/// Review I1 and concern 2: a kit device that claims to be the only one
/// and rotates (here removing A) is never trusted by A through a late
/// yes: the accept is refused, A is not quarantined, and A raises the
/// alert until the user rejects the device.
#[test]
fn accept_refused_after_kit_device_rotated() {
    let (mut server, mut a, _c, f, _out, new_sk) = rotated();
    let mut n = Device::empty();
    pull(&server, &mut n);
    let keys = kit_keys();
    restore_kit(&mut n, &new_sk, &keys).unwrap();
    sync(&mut server, &mut n).unwrap();
    let nid = n.repo().this_device_id().unwrap();
    n.repo().claim_only_device().unwrap();
    let sk2 = SecretKey::generate().unwrap();
    n.repo()
        .rotate(RotateRequest {
            revoke: vec![f.me.id()],
            new_password: None,
            password: PASSWORD,
            secret_key: &new_sk,
            new_secret_key: &sk2,
            device_keys: &keys,
            reason: RotationReason::Revoke,
            keep_tofu: &[],
        })
        .unwrap();
    sync(&mut server, &mut n).unwrap();

    pull(&server, &mut a);
    a.repo().refresh_pending_rotation().unwrap();
    assert_eq!(state(&a), DeviceLineageState::Current);
    assert_eq!(a.repo().pending_lock(), None);
    let asked = a.repo().kit_restored_devices().unwrap();
    assert_eq!(asked.len(), 1);
    assert!(asked[0].rotated);
    assert!(!asked[0].name_in_use);
    assert_eq!(a.repo().kit_rotation_alerts().unwrap(), asked);

    let r = a.repo().accept_kit_restored(nid, &f.me.keys);
    assert!(matches!(&r, Err(Error::Validation(v)) if v.reason == "already rotated"));
    a.repo().refresh_pending_rotation().unwrap();
    assert!(!in_roster(&trust_of_dev(&a).unwrap(), nid));
    assert_eq!(state(&a), DeviceLineageState::Current);
    assert_eq!(a.repo().pending_lock(), None);
    assert_eq!(tick(&a, T), QuarantineTick::NotQuarantined);

    // "Rejeter" ends the alert.
    a.repo().reject_kit_restored(nid).unwrap();
    assert!(a.repo().kit_rotation_alerts().unwrap().is_empty());
}

/// Review m3: a kit device that takes the name of a known device is shown
/// with that collision flagged.
#[test]
fn kit_device_name_collision_flagged() {
    let (mut server, mut a, _c, _f, _out, new_sk) = rotated();
    let mut n = Device::empty();
    pull(&server, &mut n);
    let store = n.store();
    let device = store.device_state().unwrap();
    let repo = Repository::restore_from_kit(
        store,
        KitRestore {
            password: PASSWORD,
            secret_key: &new_sk,
            device_keys: &kit_keys(),
            name: "Mac",
            kind: DeviceKind::Mac,
            mode: DeviceMode::Personal,
            device,
        },
    )
    .unwrap();
    n.repo = Some(repo);
    sync(&mut server, &mut n).unwrap();
    sync(&mut server, &mut a).unwrap();
    let asked = a.repo().kit_restored_devices().unwrap();
    assert!(asked[0].name_in_use);
    assert!(!asked[0].rotated);
}

/// Review I2 (spec 8.2): a kit device still waiting for a yes that a new
/// rotation leaves `Orphaned` re-pairs from a roster device; it then is
/// in its own roster.
#[test]
fn waiting_kit_device_orphaned_repairs() {
    use onepass_core::pairing::{FullGrant, FullGrantV2, snapshot_from_store};
    use onepass_core::repo::pairing::repair_from_grant;

    let (mut server, mut a, _c, f, _out, new_sk) = rotated();
    let mut n = Device::empty();
    pull(&server, &mut n);
    let keys = kit_keys();
    restore_kit(&mut n, &new_sk, &keys).unwrap();
    sync(&mut server, &mut n).unwrap();
    let nid = n.repo().this_device_id().unwrap();

    // A rotates before answering: N is not in the new roster.
    let sk3 = SecretKey::generate().unwrap();
    let out3 = a
        .repo()
        .rotate(RotateRequest {
            revoke: vec![],
            new_password: None,
            password: PASSWORD,
            secret_key: &new_sk,
            new_secret_key: &sk3,
            device_keys: &f.me.keys,
            reason: RotationReason::Rotate,
            keep_tofu: &[],
        })
        .unwrap();
    sync(&mut server, &mut a).unwrap();
    pull(&server, &mut n);
    n.repo().refresh_pending_rotation().unwrap();
    assert!(matches!(state(&n), DeviceLineageState::Orphaned { .. }));

    let grant = {
        let repo = a.repo();
        FullGrantV2 {
            full: FullGrant {
                account_id: repo.account().params.account_id,
                secret_key: zeroize::Zeroizing::new(sk3.to_display()),
                mode: DeviceMode::Personal,
                device_id: nid,
                snapshot: snapshot_from_store(repo.store()).unwrap(),
            },
            trust: repo.trust_snapshot().unwrap(),
            sync: None,
            enroll: None,
        }
    };
    let session = n.repo.take().unwrap();
    let (repo, _, _) = repair_from_grant(session, &grant, PASSWORD, &keys).unwrap();
    n.repo = Some(repo);
    let t = trust_of_dev(&n).unwrap();
    assert_eq!(t.state, DeviceLineageState::Current);
    assert_eq!(t.head.hash, out3.head);
    assert_self_pinned(&t);
    assert_eq!(n.items(), a.items());
}

/// Review m2: a kit restore over a quarantined device that had a write
/// waiting (made before its revocation, never pushed) keeps it in the
/// own-write log and replays it under the kit's identity (a write that
/// could not be reopened would be counted in `ReplayReport::lost` with
/// the log's alert).
#[test]
fn kit_restore_over_quarantine_keeps_own_writes_accounted() {
    let mut server = Server::default();
    let (mut a, f) = fixture_on(&mut server);
    let mut c = follower_with(&mut server, &a, &f, C, |_| {});
    c.unlock(&f.sk);
    let v = c.vault();
    let dave = login(v.id, "dave", T0 + 50);
    c.save(&dave);
    c.lock();
    let new_sk = SecretKey::generate().unwrap();
    let req = request(&f, &new_sk, vec![f.others[C].id()], RotationReason::Revoke);
    a.repo.as_mut().unwrap().rotate(req).unwrap();
    sync(&mut server, &mut a).unwrap();
    pull(&server, &mut c);
    assert_eq!(tick(&c, T), QuarantineTick::Waiting { erase_at: T + Q });

    restore_kit(&mut c, &new_sk, &kit_keys()).unwrap();
    // The restore replayed it under the kit's identity (the new keyset's
    // retired KEM secret opens the old copy): nothing waits, nothing lost.
    let t = trust_of_dev(&c).unwrap();
    assert!(t.own_writes.replay.is_empty());
    assert!(!t.own_writes.alert);
    assert_eq!(c.repo().replay_own_writes().unwrap().lost, 0);
    assert!(c.items().iter().any(|i| i.id == dave.id));
    sync(&mut server, &mut c).unwrap();
    sync(&mut server, &mut a).unwrap();
    assert!(a.items().iter().any(|i| i.id == dave.id), "A receives it");
}

// ------------------------------------- Task 16: travel, archives, backups

/// The base rows of the device as the Travel Mode upstream.
fn base_upstream(dev: &Device) -> onepass_core::store::MemoryStore {
    let mut up = onepass_core::store::MemoryStore::new();
    for r in dev.store().export_records().unwrap() {
        up.put(r).unwrap();
    }
    up
}

/// The vault of `dev` as an archive entry.
fn archived(dev: &mut Device) -> onepass_core::archive::ArchivedVault {
    let v = dev.vault();
    onepass_core::archive::ArchivedVault {
        id: v.id,
        meta: v.meta.clone(),
        items: dev.items(),
    }
}

/// The records of the kinds that belong to the identity and the lineage.
fn identity_records(store: &SyncStore) -> Vec<Record> {
    let mut out = Vec::new();
    for kind in [
        RecordKind::AccountParams,
        RecordKind::Keyset,
        RecordKind::RestoreEpoch,
        RecordKind::DeviceList,
        RecordKind::VaultList,
        RecordKind::Lineage,
        RecordKind::DeviceIntro,
        RecordKind::KeyDelivery,
    ] {
        out.extend(store.list(kind).unwrap());
    }
    out.sort_by_key(|r| (r.kind.code(), r.id));
    out
}

/// R18, spec 10.7: a backup made before the rotation opens through
/// `retired_kem` and the signature of the retired key, and says so.
#[test]
fn archive_before_rotation_opens_with_warning() {
    use onepass_core::archive::{self, ArchiveKind, Unlock};
    let mut server = Server::default();
    let (mut a, f) = fixture_on(&mut server);
    let av = archived(&mut a);
    let old = archive::backup(a.repo().account(), vec![av.clone()], None).unwrap();
    let fresh = archive::backup(a.repo().account(), vec![av.clone()], None).unwrap();
    // Before any rotation nothing is flagged.
    assert!(!a.repo().open_archive(&old).unwrap().made_before_rotation);

    let new_sk = SecretKey::generate().unwrap();
    let req = request(&f, &new_sk, vec![f.others[B].id()], RotationReason::Revoke);
    a.repo.as_mut().unwrap().rotate(req).unwrap();
    sync(&mut server, &mut a).unwrap();

    // The plain account unlock cannot verify the old signature.
    assert!(archive::open(&old, Unlock::Account(a.repo().account())).is_err());
    // The repository opens it, with the warning.
    let c = a.repo().open_archive(&old).unwrap();
    assert!(c.made_before_rotation);
    assert_eq!(c.kind, ArchiveKind::Backup);
    assert_eq!(c.vaults.len(), 1);
    assert_eq!(c.vaults[0].id, av.id);
    assert_eq!(c.vaults[0].meta, av.meta);
    let ids = |v: &onepass_core::archive::ArchivedVault| {
        v.items.iter().map(|i| i.id).collect::<BTreeSet<_>>()
    };
    assert_eq!(ids(&c.vaults[0]), ids(&av));
    assert!(a.repo().open_archive(&fresh).unwrap().made_before_rotation);

    // A backup made now is not flagged.
    let av2 = archived(&mut a);
    let now = archive::backup(a.repo().account(), vec![av2], None).unwrap();
    assert!(!a.repo().open_archive(&now).unwrap().made_before_rotation);

    // Passphrase archives are unchanged.
    let kdf = kdf();
    let phrase = "quartz lantern oyster meadow 91";
    let both = archive::backup(a.repo().account(), vec![av], Some((phrase, kdf))).unwrap();
    let c = archive::open(&both, Unlock::Passphrase(phrase)).unwrap();
    assert!(!c.made_before_rotation);
}

/// The warning is not forgeable away: an archive signed by nobody the
/// device knows, or made for another account, is still refused.
#[test]
fn archive_signed_by_an_unknown_key_is_refused() {
    use onepass_core::archive;
    let mut server = Server::default();
    let (mut a, f) = fixture_on(&mut server);
    let (mut other, _) = Device::create();
    let av = archived(&mut a);
    let foreign = archive::backup(other.repo().account(), vec![av.clone()], None).unwrap();
    let new_sk = SecretKey::generate().unwrap();
    let req = request(&f, &new_sk, vec![], RotationReason::Rotate);
    a.repo.as_mut().unwrap().rotate(req).unwrap();
    assert!(a.repo().open_archive(&foreign).is_err());
    // Tampered signature bytes under the right account id.
    let own = archive::backup(a.repo().account(), vec![av], None).unwrap();
    let mut bad = own.clone();
    let last = bad.len() - 1;
    bad[last] ^= 1;
    assert!(a.repo().open_archive(&bad).is_err());
}

/// An archive made before the rotation restores as new writes under the
/// current keys: nothing of the old identity comes back (R18, R11).
#[test]
fn restoring_an_old_archive_writes_under_the_current_keys() {
    use onepass_core::archive;
    let mut server = Server::default();
    let (mut a, f) = fixture_on(&mut server);
    let av = archived(&mut a);
    let old = archive::backup(a.repo().account(), vec![av], None).unwrap();
    let new_sk = SecretKey::generate().unwrap();
    let req = request(&f, &new_sk, vec![f.others[B].id()], RotationReason::Revoke);
    a.repo.as_mut().unwrap().rotate(req).unwrap();
    sync(&mut server, &mut a).unwrap();
    let gone = f.items[0].id;
    a.delete(gone);
    let before = a.items().len();

    let contents = a.repo().open_archive(&old).unwrap();
    assert!(contents.made_before_rotation);
    let report = a.repo().restore_archive(&contents).unwrap();
    assert!(report.made_before_rotation);
    assert_eq!(report.vaults_created, 0);
    assert!(report.restored >= 1);
    assert_eq!(a.items().len(), before + report.restored as usize);
    // Everything reads under the new identity after a lock and unlock.
    a.lock();
    a.try_unlock(PASSWORD, &new_sk).unwrap();
    assert!(a.items().iter().any(|i| i.id == gone));
    sync(&mut server, &mut a).unwrap();
}

/// Spec 10.7: `backup restore` imports content only. The lineage, the
/// intros, the deliveries, the account records, the lists and the trust
/// state are the same after it.
#[test]
fn backup_restore_never_touches_lineage() {
    use onepass_core::archive;
    let mut server = Server::default();
    let (mut a, f) = fixture_on(&mut server);
    let av = archived(&mut a);
    let old = archive::backup(a.repo().account(), vec![av], None).unwrap();
    let new_sk = SecretKey::generate().unwrap();
    let req = request(&f, &new_sk, vec![f.others[B].id()], RotationReason::Revoke);
    a.repo.as_mut().unwrap().rotate(req).unwrap();
    sync(&mut server, &mut a).unwrap();
    assert!(
        !identity_records(&a.store()).is_empty(),
        "the fixture has lineage and deliveries"
    );
    a.delete(f.items[0].id);

    let ids = identity_records(&a.store());
    let mut trust = a.store().trust_state().unwrap().unwrap();
    let contents = a.repo().open_archive(&old).unwrap();
    a.repo().restore_archive(&contents).unwrap();
    assert_eq!(identity_records(&a.store()), ids);
    // The restored items are this device's own writes, logged as any
    // write is; nothing else of the trust state moves.
    let mut after = a.store().trust_state().unwrap().unwrap();
    after.own_writes = trust.own_writes.clone();
    trust.own_writes = after.own_writes.clone();
    assert_eq!(after, trust);
}

/// A device that cannot write (a rotation waits for it) restores nothing.
#[test]
fn restore_is_refused_while_candidate() {
    use onepass_core::archive;
    let (_server, _a, mut c, f, _out, _sk) = rotated();
    c.unlock(&f.sk);
    let contents = archive::Contents {
        archive_id: Id::new(),
        kind: archive::ArchiveKind::Backup,
        created_at: T0,
        source_account: None,
        vaults: vec![],
        made_before_rotation: false,
    };
    assert_eq!(
        c.repo().restore_archive(&contents).err(),
        Some(Error::ReadOnly)
    );
}

/// R19, spec 10.6: a follower in Travel Mode adopts the rotation; its
/// state, sealed under the old keys, still opens; `travel off` brings the
/// vault back against the rotation's `from_heads` and never imports what
/// the revoked device wrote late under the old identity (R11).
#[test]
fn travel_follower_adopts_then_travel_off_uses_from_heads() {
    let mut server = Server::default();
    let (mut a, f) = fixture_on(&mut server);
    let mut c = follower_with(&mut server, &a, &f, C, |_| {});
    let mut ipad = old_device(&server, &f);
    c.unlock(&f.sk);
    let vault = c.vault().id;
    let up = base_upstream(&c);
    let state = c.repo().enter_travel(&up).unwrap();
    let sealed = c.repo().seal_travel_state(&state).unwrap();
    c.store()
        .set_travel_hidden(&BTreeSet::from([vault]))
        .unwrap();
    c.lock();

    let new_sk = SecretKey::generate().unwrap();
    let req = request(&f, &new_sk, vec![f.others[B].id()], RotationReason::Revoke);
    let out = a.repo.as_mut().unwrap().rotate(req).unwrap();
    let iv = ipad.vault();
    ipad.repo()
        .save_item(&iv, login(iv.id, "forged", T0 + 50))
        .unwrap();
    sync(&mut server, &mut ipad).unwrap();
    sync(&mut server, &mut a).unwrap();
    let av = a.vault();
    a.repo()
        .save_item(&av, login(av.id, "after", T0 + 80))
        .unwrap();
    sync(&mut server, &mut a).unwrap();
    pull(&server, &mut c);
    assert!(
        c.store()
            .get(RecordKind::VaultKey, vault)
            .unwrap()
            .is_none(),
        "the sync keeps the hidden vault off the device"
    );

    // Adopting works with the vault parked.
    let (repo, _, _) = follow_rotation(c.store(), out.head, PASSWORD, &f.others[C].keys).unwrap();
    let heads = rotation_of(&a.store(), &out.head).from_heads;
    assert!(heads.contains_key(&vault));
    c.repo = Some(repo);

    // The state sealed under the old keys opens under the new ones.
    let reopened = c.repo().open_travel_state(&sealed).unwrap();
    assert_eq!(reopened, state);
    c.repo().resume_travel(&reopened);
    assert!(c.repo().vaults().unwrap().iter().all(|v| v.id != vault));

    // Travel off: the pin is the rotation's, not the parked old one.
    c.store().set_travel_hidden(&BTreeSet::new()).unwrap();
    full_fetch(&server, &mut c);
    c.repo()
        .exit_travel(&onepass_core::store::MemoryStore::new(), &reopened)
        .unwrap();
    let users = users(&c.items());
    assert_eq!(users, ["after", "alice", "bob", "carol"].map(String::from));
    assert!(!users.contains(&"forged".to_string()));
}

/// A state forged with the old signing key (the revoked device holds it)
/// cannot move the pin of a vault the rotation covered: `from_heads` wins
/// over whatever the parked state says.
#[test]
fn old_travel_pin_cannot_override_from_heads() {
    let mut server = Server::default();
    let (mut a, f) = fixture_on(&mut server);
    let mut c = follower_with(&mut server, &a, &f, C, |_| {});
    c.unlock(&f.sk);
    let vault = c.vault().id;
    let up = base_upstream(&c);
    let state = c.repo().enter_travel(&up).unwrap();
    c.store()
        .set_travel_hidden(&BTreeSet::from([vault]))
        .unwrap();
    c.lock();

    let new_sk = SecretKey::generate().unwrap();
    let req = request(&f, &new_sk, vec![f.others[B].id()], RotationReason::Revoke);
    let out = a.repo.as_mut().unwrap().rotate(req).unwrap();
    sync(&mut server, &mut a).unwrap();
    pull(&server, &mut c);
    let (repo, _, _) = follow_rotation(c.store(), out.head, PASSWORD, &f.others[C].keys).unwrap();
    c.repo = Some(repo);

    // The parked pin claims a manifest far ahead of anything real.
    let mut forged = state.clone();
    for seen in forged.parked.values_mut() {
        seen.seq += 1_000;
        seen.hash = [9; 32];
    }
    c.repo().resume_travel(&forged);
    c.store().set_travel_hidden(&BTreeSet::new()).unwrap();
    full_fetch(&server, &mut c);
    c.repo()
        .exit_travel(&onepass_core::store::MemoryStore::new(), &forged)
        .unwrap();
    assert_eq!(
        users(&c.items()),
        ["alice", "bob", "carol"].map(String::from)
    );
}

// ------------------------------------------ Task 16, fix round 1 (review I1)

/// A: rotated (revoking B) and pushed, with a vault "later" created after
/// it. C follows, in Travel Mode for the first vault. The iPad is a device
/// of the old identity (it holds the old signing and KEM keys, as the
/// revoked device does). Returns what the forgery tests need.
struct Travelling {
    server: Server,
    c: Device,
    ipad: Device,
    vault: Id,
    later: Id,
    state: TravelState,
    sealed: Vec<u8>,
}

fn travelling() -> Travelling {
    let mut server = Server::default();
    let (mut a, f) = fixture_on(&mut server);
    let mut c = follower_with(&mut server, &a, &f, C, |_| {});
    let ipad = old_device(&server, &f);
    c.unlock(&f.sk);
    let vault = c.vault().id;
    let up = base_upstream(&c);
    let state = c.repo().enter_travel(&up).unwrap();
    let sealed = c.repo().seal_travel_state(&state).unwrap();
    c.store()
        .set_travel_hidden(&BTreeSet::from([vault]))
        .unwrap();
    c.lock();

    let new_sk = SecretKey::generate().unwrap();
    let req = request(&f, &new_sk, vec![f.others[B].id()], RotationReason::Revoke);
    let out = a.repo.as_mut().unwrap().rotate(req).unwrap();
    sync(&mut server, &mut a).unwrap();
    let later = a.repo().create_vault(meta("Later")).unwrap().id;
    sync(&mut server, &mut a).unwrap();
    pull(&server, &mut c);
    let (repo, _, _) = follow_rotation(c.store(), out.head, PASSWORD, &f.others[C].keys).unwrap();
    c.repo = Some(repo);
    Travelling {
        server,
        c,
        ipad,
        vault,
        later,
        state,
        sealed,
    }
}

/// A state signed with the old key (and sealed to the old KEM key) that
/// lists a vault made after the rotation is refused: it could only be a
/// forgery by the revoked device (rollback, lock-out or hiding of a vault
/// the genuine state cannot know).
#[test]
fn old_key_travel_state_listing_a_later_vault_is_refused() {
    let mut t = travelling();
    let forged = TravelState {
        parked: BTreeMap::from([(
            t.later,
            SeenManifest {
                seq: 1,
                hash: [1; 32],
            },
        )]),
        entered_at: T0,
        parked_items: Default::default(),
    };
    let sealed = t.ipad.repo().seal_travel_state(&forged).unwrap();
    assert!(t.c.repo().open_travel_state(&sealed).is_err());
    // The genuine one still opens.
    assert_eq!(t.c.repo().open_travel_state(&t.sealed).unwrap(), t.state);
}

/// For the vaults the rotation covered, an old-key state keeps no pin of
/// its own: `from_heads` replaces it, so a huge forged seq locks nothing.
#[test]
fn old_key_travel_state_pins_are_replaced_by_from_heads() {
    let mut t = travelling();
    let mut forged = t.state.clone();
    for seen in forged.parked.values_mut() {
        seen.seq += 1_000;
        seen.hash = [9; 32];
    }
    let sealed = t.ipad.repo().seal_travel_state(&forged).unwrap();
    let opened = t.c.repo().open_travel_state(&sealed).unwrap();
    let heads = t.c.repo().device_state().last_seen.clone();
    assert_eq!(opened.parked[&t.vault], heads[&t.vault]);
    t.c.repo().resume_travel(&opened);
    t.c.store().set_travel_hidden(&BTreeSet::new()).unwrap();
    full_fetch(&t.server, &mut t.c);
    t.c.repo()
        .exit_travel(&onepass_core::store::MemoryStore::new(), &opened)
        .unwrap();
    assert_eq!(
        users(&t.c.items()),
        ["alice", "bob", "carol"].map(String::from)
    );
}

/// The follower re-seals its genuine state under the new identity; that
/// one is bound to the current keys and may list a vault made after the
/// rotation (a later Travel Mode), unlike an old-key one.
#[test]
fn travel_state_is_resealed_under_the_new_identity() {
    let mut t = travelling();
    let resealed = t.c.repo().reseal_travel_state(&t.sealed).unwrap();
    assert_ne!(resealed, t.sealed);
    assert_eq!(t.c.repo().open_travel_state(&resealed).unwrap(), t.state);
    // Current-key states are not restricted to `from_heads`.
    let both = TravelState {
        parked: BTreeMap::from([(
            t.later,
            SeenManifest {
                seq: 1,
                hash: [1; 32],
            },
        )]),
        entered_at: T0,
        parked_items: Default::default(),
    };
    let sealed = t.c.repo().seal_travel_state(&both).unwrap();
    assert_eq!(t.c.repo().open_travel_state(&sealed).unwrap(), both);
}

// ------------------------------------------ minor 5: two rotations

/// Two rotations while an archive waits: the oldest archive still opens
/// (retired_kem keeps both KEM secrets, the trust state both signers).
#[test]
fn archive_before_two_rotations_opens_with_warning() {
    use onepass_core::archive;
    let mut server = Server::default();
    let (mut a, f) = fixture_on(&mut server);
    let av = archived(&mut a);
    let old = archive::backup(a.repo().account(), vec![av], None).unwrap();
    let sk1 = SecretKey::generate().unwrap();
    a.repo
        .as_mut()
        .unwrap()
        .rotate(request(&f, &sk1, vec![], RotationReason::Rotate))
        .unwrap();
    sync(&mut server, &mut a).unwrap();
    let sk2 = SecretKey::generate().unwrap();
    let mut second = request(&f, &sk2, vec![], RotationReason::Rotate);
    second.secret_key = &sk1;
    a.repo.as_mut().unwrap().rotate(second).unwrap();
    sync(&mut server, &mut a).unwrap();
    assert_eq!(a.repo().account().keyset().retired_kem.len(), 2);
    assert!(a.repo().open_archive(&old).unwrap().made_before_rotation);
}

/// Task 19 carried item 6: timing of 1000 item writes and a push on a
/// device with a trust state, in `Current`. Run by hand:
/// `cargo test --release --features dev-fast-kdf --test rotation_v2
/// write_loop_timing -- --ignored --nocapture`.
#[test]
#[ignore]
fn write_loop_timing() {
    let mut server = Server::default();
    let (mut a, _f) = fixture_on(&mut server);
    let v = a.vault();
    let t = std::time::Instant::now();
    for i in 0..1000 {
        a.repo()
            .save_item(&v, login(v.id, &format!("u{i}"), T0 + i64::from(i)))
            .unwrap();
    }
    let writes = t.elapsed();
    let t = std::time::Instant::now();
    let changes = a.store().pending_changes().unwrap().len();
    let outbox_time = t.elapsed();
    let t = std::time::Instant::now();
    push(&mut server, &a).unwrap();
    let pushed = t.elapsed();
    eprintln!(
        "TIMING writes(1000)={writes:?} pending_changes({changes})={outbox_time:?} push={pushed:?}"
    );
}

// ---------------------------------------------------------------- acknowledgments (O6)

use onepass_core::lineage::{AckStatus, SignedAck, ack_id, ack_statuses, verify_ack};

fn statuses(dev: &Device) -> Option<Vec<AckStatus>> {
    let store = dev.store();
    let trust = store.trust_state().unwrap().unwrap();
    ack_statuses(&store, &trust)
}

fn acked(dev: &Device, id: Id) -> bool {
    statuses(dev)
        .expect("statuses past generation 0")
        .iter()
        .find(|s| s.device_id == id)
        .expect("in the roster")
        .acknowledged
}

/// Spec 6.8 (O6): nothing to acknowledge before the first rotation.
#[test]
fn generation_zero_shows_no_ack_status() {
    let (a, _f) = fixture();
    assert_eq!(statuses(&a), None);
}

/// The rotator writes its own acknowledgment in the rotation's
/// transaction; the others show "en attente" until they follow, then "à
/// jour" on the rotator once their acknowledgment syncs.
#[test]
fn follow_writes_its_ack_and_the_rotator_shows_it() {
    let (mut server, mut a, mut c, f, out, _new_sk) = rotated();
    let me = f.me.id();
    let cid = f.others[C].id();
    assert!(acked(&a, me));
    assert!(!acked(&a, cid));
    assert!(!acked(&a, f.others[2].id()));
    // B was revoked: not in the roster any more.
    assert!(
        statuses(&a)
            .unwrap()
            .iter()
            .all(|s| s.device_id != f.others[B].id())
    );

    let (repo, _auk, _sk) =
        follow_rotation(c.store(), out.head, PASSWORD, &f.others[C].keys).unwrap();
    c.repo = Some(repo);
    // In C's own store, in the follow's transaction.
    let rec = c
        .store()
        .get(RecordKind::DeviceAck, ack_id(&out.head, cid))
        .unwrap()
        .expect("C's ack");
    assert_eq!(rec.version, 1);
    let ack = SignedAck::decode(&rec.data).unwrap();
    assert_eq!(ack.body.head, out.head);
    assert_eq!(ack.body.device_id, cid);
    verify_ack(&ack, &f.others[C].public.sign_pub).unwrap();
    assert!(acked(&c, cid));

    sync(&mut server, &mut c).unwrap();
    sync(&mut server, &mut a).unwrap();
    assert!(acked(&a, cid));
    assert!(acked(&a, me));
    assert!(!acked(&a, f.others[2].id()));
}

/// Display only: an acknowledgment signed by another key, or naming
/// another head or device, never shows "à jour".
#[test]
fn forged_or_misplaced_acks_show_waiting() {
    use onepass_core::lineage::{AckBody, sign_ack};
    let (_server, mut a, _c, f, out, _new_sk) = rotated();
    let trust = a.store().trust_state().unwrap().unwrap();
    let d = &f.others[2];
    let body = |head: [u8; 32], device: Id| AckBody {
        format: LINEAGE_FORMAT,
        account_id: trust.account_id,
        head,
        device_id: device,
        acked_at: T0,
    };
    let put = |a: &mut Device, id: Id, ack: SignedAck| {
        a.repo()
            .store_mut()
            .put_if_version(
                Record {
                    id,
                    kind: RecordKind::DeviceAck,
                    version: 1,
                    data: ack.encode(),
                },
                None,
            )
            .unwrap();
    };
    // D's ack, signed by A's key.
    put(
        &mut a,
        ack_id(&out.head, d.id()),
        sign_ack(body(out.head, d.id()), &f.me.keys).unwrap(),
    );
    assert!(!acked(&a, d.id()));

    // C's honest signature over another head, stored under the current
    // head's id.
    let c = &f.others[C];
    put(
        &mut a,
        ack_id(&out.head, c.id()),
        sign_ack(body([7; 32], c.id()), &c.keys).unwrap(),
    );
    assert!(!acked(&a, c.id()));
}

// ---------------------------------------------------------------- approver list across a rotation

/// Ruling 2026-11-02 (approver list at rotation): the list survives a
/// rotation, and a locked Mac reads it under the new identity too
/// (`approvers_without_unlock`, agent-ready spec 6.2), on the rotator and on
/// a device that followed. Before the fix the locked read looked under the
/// account id, where only generation 0's records are.
#[test]
fn locked_approver_list_survives_rotation_and_follow() {
    use onepass_core::approvers::{ApproverRole, approvers_without_unlock};
    use onepass_core::crypto::{HybridKemSecret, HybridSigningKey};
    let mut server = Server::default();
    let (mut a, f) = fixture_on(&mut server);
    let sign_pub = HybridSigningKey::generate()
        .unwrap()
        .verifying_key()
        .unwrap();
    let kem_pub = HybridKemSecret::generate().unwrap().public().unwrap();
    a.repo()
        .register_this_approver(sign_pub.clone(), kem_pub, ApproverRole::Phone)
        .unwrap();
    sync(&mut server, &mut a).unwrap();
    let mut c = follower_with(&mut server, &a, &f, C, |_| {});

    let new_sk = SecretKey::generate().unwrap();
    let req = request(&f, &new_sk, vec![], RotationReason::Rotate);
    let out = a.repo.as_mut().unwrap().rotate(req).unwrap();
    sync(&mut server, &mut a).unwrap();
    let locked = |d: &mut Device| {
        let repo = d.repo();
        approvers_without_unlock(repo.store(), repo.device_state(), repo.chain()).unwrap()
    };
    let on_a = locked(&mut a);
    assert_eq!(on_a.entries.len(), 1);
    assert_eq!(on_a.entries[0].sign_pub, sign_pub);
    assert_eq!(on_a.approver_list_seq, 1);

    pull(&server, &mut c);
    let (repo, _auk, _sk) =
        follow_rotation(c.store(), out.head, PASSWORD, &f.others[C].keys).unwrap();
    c.repo = Some(repo);
    assert_eq!(c.repo().approvers().unwrap().len(), 1);
    let on_c = locked(&mut c);
    assert_eq!(on_c.entries.len(), 1);
    assert_eq!(on_c.entries[0].sign_pub, sign_pub);
}

// ------------------------------------------------------------- sync home

/// A on a mailbox (its `SyncHome` pushed), C a follower; A rotates and
/// pushes every phase, C pulls everything.
fn rotated_on_a_mailbox() -> (
    Server,
    Device,
    Device,
    Fixture,
    RotationOutcome,
    onepass_core::synchome::SyncBackend,
) {
    let home = onepass_core::synchome::SyncBackend::Mailbox {
        url: "https://mailbox.example.org/functions/v1/mailbox".into(),
        mailbox_id: [4; 16],
    };
    let mut server = Server::default();
    let (mut a, f) = fixture_on(&mut server);
    a.repo().set_sync_home(home.clone(), T0).unwrap();
    sync(&mut server, &mut a).unwrap();
    let mut c = follower_with(&mut server, &a, &f, C, |_| {});
    let new_sk = SecretKey::generate().unwrap();
    let out = rotate(&mut a, &f, &new_sk);
    sync(&mut server, &mut a).unwrap();
    assert_eq!(state(&a), DeviceLineageState::Current);
    pull(&server, &mut c);
    (server, a, c, f, out, home)
}

#[test]
fn rotation_carries_sync_home() {
    let (server, mut a, _c, _f, _out, home) = rotated_on_a_mailbox();
    let params = a.repo().account().params.clone();
    let rid = account_record_id(params.account_id, Some(&params.identity_pub));
    let got = a.repo().sync_home().unwrap().expect("a home");
    // A new chain under the new identity, same backend, signed by the new
    // key (`sync_home` verifies against it).
    assert_eq!(got.seq, 1);
    assert_eq!(got.prev_hash, [0; 32]);
    assert_eq!(got.backend, home);
    let rec = server.get(RecordKind::SyncHome, rid).expect("pushed");
    assert_eq!(rec.version, 1);
    assert_eq!(
        RecordStore::chain_state(&a.store()).unwrap().sync_home,
        Some(got.seen())
    );
}

#[test]
fn rotation_phase_one_writes_the_home_before_the_lineage_record() {
    let mut server = Server::default();
    let (mut a, f) = fixture_on(&mut server);
    let home = onepass_core::synchome::SyncBackend::CloudKit;
    a.repo().set_sync_home(home, T0).unwrap();
    sync(&mut server, &mut a).unwrap();
    let new_sk = SecretKey::generate().unwrap();
    rotate(&mut a, &f, &new_sk);
    let kinds: Vec<RecordKind> = outbox(&a).iter().map(|(c, _)| c.kind).collect();
    let home_at = kinds
        .iter()
        .position(|k| *k == RecordKind::SyncHome)
        .expect("the home in phase 1");
    let lineage_at = kinds
        .iter()
        .position(|k| *k == RecordKind::Lineage)
        .unwrap();
    assert!(home_at < lineage_at, "{kinds:?}");
}

#[test]
fn rotation_without_a_home_writes_none() {
    let mut server = Server::default();
    let (mut a, f) = fixture_on(&mut server);
    let new_sk = SecretKey::generate().unwrap();
    rotate(&mut a, &f, &new_sk);
    assert!(
        outbox(&a)
            .iter()
            .all(|(c, _)| c.kind != RecordKind::SyncHome)
    );
    assert_eq!(a.repo().sync_home().unwrap(), None);
}

#[test]
fn follower_reads_new_home() {
    let (_server, mut a, c, f, out, home) = rotated_on_a_mailbox();
    let (mut repo, _auk, _sk) =
        follow_rotation(c.store(), out.head, PASSWORD, &f.others[C].keys).unwrap();
    let got = repo.sync_home().unwrap().expect("a home");
    assert_eq!(got.backend, home);
    assert_eq!(got, a.repo().sync_home().unwrap().unwrap());
}

#[test]
fn moved_home_after_rotation_is_read_not_adopted_silently() {
    // A valid rotation, then the new identity names another mailbox: the
    // follower reads the move as signed data (the driver stops on it and
    // the app asks, `HomeMoved`), the pin moves forward only.
    let (mut server, mut a, mut c, f, out, _home) = rotated_on_a_mailbox();
    let elsewhere = onepass_core::synchome::SyncBackend::Mailbox {
        url: "https://other.example.org/functions/v1/mailbox".into(),
        mailbox_id: [5; 16],
    };
    a.repo().set_sync_home(elsewhere.clone(), T0 + 50).unwrap();
    sync(&mut server, &mut a).unwrap();
    pull(&server, &mut c);
    let (mut repo, _auk, _sk) =
        follow_rotation(c.store(), out.head, PASSWORD, &f.others[C].keys).unwrap();
    let got = repo.sync_home().unwrap().unwrap();
    assert_eq!((got.seq, got.backend), (2, elsewhere));
}

#[test]
fn left_identity_home_never_read_after_follow() {
    // The old identity's record stays on the server under its id; the
    // follower reads only the new identity's chain, so an old home served
    // again changes nothing.
    let (server, _a, c, f, out, home) = rotated_on_a_mailbox();
    let (mut repo, _auk, _sk) =
        follow_rotation(c.store(), out.head, PASSWORD, &f.others[C].keys).unwrap();
    let left = server
        .records
        .keys()
        .filter(|(k, _)| *k == RecordKind::SyncHome)
        .count();
    assert_eq!(left, 2, "old and new identity homes");
    assert_eq!(repo.sync_home().unwrap().unwrap().backend, home);
}

// ------------------------------------ Recover rotation (sharing plan 3 Task 3)

use onepass_core::contact::{ForeignLineage, ForeignPin, LegacyIntros, follow_foreign};
use onepass_core::repo::{RecoverRequest, recover_rotate};

const RECOVERED_PASSWORD: &str = "Nouveau départ, Camille Durand";

/// A's account recovered on a new device N (spec 11.5 step 5), from the
/// keyset a recovery slot gives, after A rotated (`rotated`). N synced.
struct Recovered {
    server: Server,
    a: Device,
    n: Device,
    f: Fixture,
    /// A's rotation, the head N recovered from.
    before: RotationOutcome,
    out: RotationOutcome,
    sk: SecretKey,
    keys: DeviceKeys,
    items: Vec<Item>,
    /// A's Secret Key since its own rotation (`before`).
    a_sk: SecretKey,
}

fn recovered() -> Recovered {
    let (mut server, mut a, _c, f, before, a_sk) = rotated();
    let keyset = a.repo().account().recovery_keyset().unwrap();
    let items = a.items();
    let mut n = Device::empty();
    pull(&server, &mut n);
    let keys = kit_keys();
    let sk = SecretKey::generate().unwrap();
    let store = n.store();
    let device = store.device_state().unwrap();
    let (repo, out) = recover_rotate(
        store,
        RecoverRequest {
            keyset_record: &keyset,
            new_password: RECOVERED_PASSWORD,
            new_secret_key: &sk,
            device_keys: &keys,
            device_name: "iPhone de secours",
            kind: DeviceKind::Phone,
            mode: DeviceMode::Personal,
            device,
        },
        T0 + 500,
    )
    .unwrap();
    n.repo = Some(repo);
    n.repo().persist_device_state().unwrap();
    sync(&mut server, &mut n).unwrap();
    Recovered {
        server,
        a,
        n,
        f,
        before,
        out,
        sk,
        keys,
        items,
        a_sk,
    }
}

fn records_of(store: &SyncStore) -> (Vec<LineageRecord>, Vec<SignedIntro>) {
    let records = store
        .list(RecordKind::Lineage)
        .unwrap()
        .iter()
        .map(|r| LineageRecord::decode(&r.data).unwrap())
        .collect();
    let intros = store
        .list(RecordKind::DeviceIntro)
        .unwrap()
        .iter()
        .filter_map(|r| SignedIntro::decode(&r.data).ok())
        .collect();
    (records, intros)
}

/// From the opened keyset: a new identity, Secret Key and password, the
/// roster N alone, every device of A's roster revoked, every item readable
/// under the new identity, a rotation code.
#[test]
fn recover_rotate_end_to_end() {
    let mut r = recovered();
    let t = trust_of_dev(&r.n).unwrap();
    let me = t.me.device_id;
    assert_eq!(t.me, r.keys.public(me).unwrap());
    assert_eq!(
        t.head,
        LineageHead {
            generation: 2,
            hash: r.out.head
        }
    );
    assert_eq!(t.state, DeviceLineageState::Current);
    assert_self_pinned(&t);
    assert_eq!(t.roster.len(), 1);

    let parent = rotation_of(&r.a.store(), &r.before.head);
    let body = rotation_of(&r.n.store(), &r.out.head);
    assert_eq!(body.reason, RotationReason::Recover);
    assert_eq!(body.parent, r.before.head);
    assert_eq!(body.rotator, me);
    assert_eq!(body.roster.len(), 1);
    assert_eq!(body.roster[0].name, "iPhone de secours");
    assert!(body.deliveries.is_empty());
    let mut was: Vec<Id> = parent.roster.iter().map(|e| e.device_id).collect();
    was.sort();
    assert_eq!(body.revoked, was);
    assert_ne!(body.identity_pub, parent.identity_pub);
    assert_eq!(t.identity_pub, body.identity_pub);
    assert_eq!(r.out.code, rotation_code(&r.out.head));
    for id in &was {
        assert!(t.revoked.contains(id));
    }

    // The device list of the new identity names N; A's devices are revoked.
    let devices = r.n.repo().devices().unwrap();
    assert!(
        devices
            .iter()
            .any(|d| d.device_id == me && d.revoked_at.is_none())
    );
    assert!(
        devices
            .iter()
            .filter(|d| was.contains(&d.device_id))
            .all(|d| d.revoked_at.is_some())
    );

    assert_eq!(r.n.items(), r.items);
    r.n.lock();
    r.n.try_unlock(RECOVERED_PASSWORD, &r.sk).unwrap();
    assert_eq!(r.n.items(), r.items);
    assert!(r.n.try_unlock(PASSWORD, &r.sk).is_err());
}

/// Ruling B-4: an old device reads the `Recover` rotation and goes to
/// quarantine (its id is revoked); its exit is to erase and pair again,
/// from the recovered device, as a new device. The rotator is only
/// self-introduced, but the identity this device pinned signed its intro:
/// the erase clock runs (founder decision 2026-11-03, replacing the I1
/// ruling that kept it locked with no date).
#[test]
fn old_devices_quarantined_then_repair() {
    let mut r = recovered();
    pull(&r.server, &mut r.a);
    r.a.repo().refresh_pending_rotation().unwrap();
    assert_eq!(tick(&r.a, T), QuarantineTick::Waiting { erase_at: T + Q });
    assert!(matches!(
        state(&r.a),
        DeviceLineageState::Quarantined { by, .. } if by == r.out.head
    ));
    assert!(
        quarantine_resolve(r.a.store(), QuarantineChoice::Erase)
            .unwrap()
            .is_none()
    );
    assert_erased(&r.a);

    // A new pairing from N.
    use onepass_core::devices::DeviceEntry;
    use onepass_core::pairing::{
        DeviceInfo, FullGrant, FullGrantV2, import_full_v2, snapshot_from_store,
    };
    let p = Peer::new(Id::new());
    let info = DeviceInfo {
        device_id: p.id(),
        name: "iPad".into(),
        kind: DeviceKind::Tablet,
    };
    let entry = DeviceEntry {
        device_id: p.id(),
        name: info.name.clone(),
        kind: info.kind,
        mode: DeviceMode::Personal,
        added_at: T0 + 600,
        added_by: r.n.repo().this_device_id(),
        revoked_at: None,
    };
    let sk = &r.sk;
    let grant =
        r.n.repo()
            .add_device_then(entry, |repo| -> Result<FullGrantV2> {
                Ok(FullGrantV2 {
                    full: FullGrant {
                        account_id: repo.account().params.account_id,
                        secret_key: zeroize::Zeroizing::new(sk.to_display()),
                        mode: DeviceMode::Personal,
                        device_id: p.id(),
                        snapshot: snapshot_from_store(repo.store())?,
                    },
                    trust: repo.trust_snapshot()?,
                    sync: None,
                    enroll: None,
                })
            })
            .unwrap();
    let mut d = Device::empty();
    {
        let mut store = SyncStore::open(&d.path).unwrap();
        import_full_v2(&mut store, &grant, &p.public, &p.keys, &info).unwrap();
    }
    d.try_unlock(RECOVERED_PASSWORD, &r.sk).unwrap();
    let t = trust_of_dev(&d).unwrap();
    assert_eq!(t.head.hash, r.out.head);
    assert_eq!(t.state, DeviceLineageState::Current);
    assert_self_pinned(&t);
    assert_eq!(d.items(), r.items);
}

/// Ruling B-3: without the self-intro signed by the parent identity, the
/// `Recover` rotation is valid neither for an old device (the resolver
/// ignores it) nor for a contact (`follow_foreign`).
#[test]
fn recover_without_identity_intro_invalid() {
    let mut r = recovered();
    pull_only(&r.server, &mut r.a, |ch| ch.kind != RecordKind::DeviceIntro);
    r.a.repo().refresh_pending_rotation().unwrap();
    assert_eq!(state(&r.a), DeviceLineageState::Current);
    assert_eq!(r.a.repo().pending_lock(), None);
    assert_eq!(tick(&r.a, T), QuarantineTick::NotQuarantined);

    let parent = rotation_of(&r.a.store(), &r.before.head);
    let (records, _) = records_of(&r.n.store());
    let pin = foreign_pin(&records, &r.before, &parent);
    assert_eq!(
        follow_foreign(&pin, &records, &[], &LegacyIntros::default()),
        ForeignLineage::Same
    );
    // A self-intro under the head that the identity did not sign counts
    // for nothing either.
    let (_, intros) = records_of(&r.n.store());
    let me = trust_of_dev(&r.n).unwrap().me.device_id;
    let mut forged: Vec<SignedIntro> = intros
        .into_iter()
        .filter(|i| i.body.entry.device_id == me)
        .collect();
    for i in &mut forged {
        i.identity_sig = None;
    }
    assert_eq!(
        follow_foreign(&pin, &records, &forged, &LegacyIntros::default()),
        ForeignLineage::Same
    );
    let _ = &r.f;
}

fn foreign_pin(
    records: &[LineageRecord],
    before: &RotationOutcome,
    parent: &onepass_core::lineage::RotationBody,
) -> ForeignPin {
    let genesis = records
        .iter()
        .find(|r| matches!(r, LineageRecord::Genesis(_)))
        .expect("a genesis");
    ForeignPin {
        account_id: genesis.account_id(),
        genesis: genesis.hash(),
        head: LineageHead {
            generation: 1,
            hash: before.head,
        },
        identity_pub: parent.identity_pub.clone(),
    }
}

/// A contact pinned at A's head sees the recovery as an identity change
/// (spec 12.3 point 1): `Advanced`, the last rotation of reason `Recover`.
#[test]
fn contact_sees_recover_as_identity_change() {
    let r = recovered();
    let parent = rotation_of(&r.a.store(), &r.before.head);
    let (records, intros) = records_of(&r.n.store());
    let pin = foreign_pin(&records, &r.before, &parent);
    match follow_foreign(&pin, &records, &intros, &LegacyIntros::default()) {
        ForeignLineage::Advanced {
            head,
            last_rotation,
            identity_pub,
            ..
        } => {
            assert_eq!(head.hash, r.out.head);
            assert_eq!(last_rotation.reason, RotationReason::Recover);
            assert_ne!(identity_pub, parent.identity_pub);
        }
        other => panic!("expected Advanced, got {other:?}"),
    }
}

// ------------------------- recover wipe and stolen devices (2026-11-03)

use onepass_core::crypto::IdentityKey;
use onepass_core::lineage::wipe::{SignedWipe, WipeBody, sign_wipe, target_key};

const YEAR: u64 = 365 * 86_400;

/// The recovered account with A having read the `Recover` (quarantined
/// at `T`).
fn a_quarantined_by_recover() -> Recovered {
    let mut r = recovered();
    pull(&r.server, &mut r.a);
    assert_eq!(tick(&r.a, T), QuarantineTick::Waiting { erase_at: T + Q });
    r
}

fn a_id(r: &Recovered) -> Id {
    trust_of_dev(&r.a).unwrap().me.device_id
}

/// N marks `device` stolen and pushes; A fetches.
fn n_marks_stolen(r: &mut Recovered, device: Id) {
    r.n.repo().mark_stolen(device, (T + 10) as i64).unwrap();
    sync(&mut r.server, &mut r.n).unwrap();
    pull(&r.server, &mut r.a);
}

/// An order planted in `dev`'s store, as a server would.
fn plant(dev: &Device, w: &SignedWipe) {
    dev.store()
        .put(Record {
            id: w.record_id(),
            kind: RecordKind::Lineage,
            version: 2,
            data: w.encode(),
        })
        .unwrap();
}

/// A valid order for A, signed by N's identity (the recovered head).
fn order_for_a(r: &mut Recovered) -> WipeBody {
    let t = trust_of_dev(&r.a).unwrap();
    let n = trust_of_dev(&r.n).unwrap();
    WipeBody {
        format: LINEAGE_FORMAT,
        account_id: t.account_id,
        target: t.me.device_id,
        target_key: target_key(&t.me),
        removed_by: r.out.head,
        head: r.out.head,
        issuer: n.me.device_id,
        issued_at: (T + 10) as i64,
    }
}

fn n_identity(r: &mut Recovered) -> IdentityKey {
    IdentityKey::from_bytes(&r.n.repo().account().keyset().identity.to_bytes()).unwrap()
}

/// Founder decision 2026-11-03: an old device of a recovered account
/// erases itself 7 days after it read the `Recover`, not before.
#[test]
fn recover_quarantine_erases_after_seven_days() {
    let r = a_quarantined_by_recover();
    assert_eq!(
        tick(&r.a, T + Q - 1),
        QuarantineTick::Waiting { erase_at: T + Q }
    );
    assert!(!matches!(state(&r.a), DeviceLineageState::Legacy));
    assert_eq!(tick(&r.a, T + Q), QuarantineTick::Erased);
    assert_erased(&r.a);
    // The erase says why, for the app's erased screen.
    assert_eq!(
        r.a.store().erased_notice().unwrap(),
        Some(ErasedNotice::Recovered)
    );
    // The recovered device keeps everything.
    assert_eq!(state(&r.n), DeviceLineageState::Current);
}

/// A clock set back neither stops nor reverses the count: the time the
/// clock moves forward from its new reading still counts.
#[test]
fn clock_set_back_does_not_stop_the_erase() {
    let r = a_quarantined_by_recover();
    assert_eq!(
        tick(&r.a, T + 86_400),
        QuarantineTick::Waiting { erase_at: T + Q }
    );
    // Back a year: one day counted, six left from the new reading.
    let back = T - YEAR;
    assert_eq!(
        tick(&r.a, back),
        QuarantineTick::Waiting {
            erase_at: back + Q - 86_400
        }
    );
    // Back again and again, each time after a few real days: they add up.
    assert_eq!(
        tick(&r.a, back + 3 * 86_400),
        QuarantineTick::Waiting {
            erase_at: back + Q - 86_400
        }
    );
    assert!(matches!(tick(&r.a, back), QuarantineTick::Waiting { .. }));
    assert_eq!(tick(&r.a, back + 3 * 86_400), QuarantineTick::Erased);
    assert_erased(&r.a);
}

/// The lock screen's date follows the saved clock, read only.
#[test]
fn erase_date_follows_the_saved_clock() {
    use onepass_core::repo::follow::quarantine_erase_at;
    let r = a_quarantined_by_recover();
    assert_eq!(quarantine_erase_at(&r.a.store()).unwrap(), Some(T + Q));
    tick(&r.a, T - YEAR);
    assert_eq!(
        quarantine_erase_at(&r.a.store()).unwrap(),
        Some(T - YEAR + Q)
    );
}

/// "Ce n'était pas moi" before the 7 days: the countdown is gone, and an
/// order made for that removal no longer erases anything.
#[test]
fn reapproval_cancels_countdown_and_order() {
    let mut r = a_quarantined_by_recover();
    let a = a_id(&r);
    let repo = quarantine_resolve(r.a.store(), not_me(&r.a, PASSWORD, &r.a_sk))
        .unwrap()
        .expect("unlocked");
    drop(repo);
    assert_eq!(state(&r.a), DeviceLineageState::Current);
    n_marks_stolen(&mut r, a);
    assert_eq!(tick(&r.a, T + 1), QuarantineTick::NotQuarantined);
    assert_eq!(tick(&r.a, T + YEAR), QuarantineTick::NotQuarantined);
    assert_eq!(state(&r.a), DeviceLineageState::Current);
    r.a.try_unlock(PASSWORD, &r.a_sk).unwrap();
}

/// Founder decision 2026-11-03: marked stolen right after a `Recover`,
/// the old device erases at its next tick, no countdown.
#[test]
fn stolen_after_recover_erases_at_once() {
    let mut r = a_quarantined_by_recover();
    let a = a_id(&r);
    n_marks_stolen(&mut r, a);
    assert_eq!(r.n.repo().stolen_devices().unwrap(), vec![a]);
    assert_eq!(tick(&r.a, T + 1), QuarantineTick::Erased);
    assert_erased(&r.a);
}

/// The order and the `Recover` arrive in the same fetch: the first tick
/// quarantines, then erases.
#[test]
fn stolen_before_first_tick_erases_at_once() {
    let mut r = recovered();
    let a = trust_of_dev(&r.a).unwrap().me.device_id;
    r.n.repo().mark_stolen(a, T as i64).unwrap();
    sync(&mut r.server, &mut r.n).unwrap();
    pull(&r.server, &mut r.a);
    assert_eq!(tick(&r.a, T), QuarantineTick::Erased);
    assert_erased(&r.a);
}

/// Marking twice writes one order.
#[test]
fn marking_twice_writes_once() {
    let mut r = recovered();
    let a = trust_of_dev(&r.a).unwrap().me.device_id;
    r.n.repo().mark_stolen(a, T as i64).unwrap();
    let count = |r: &Recovered| {
        r.n.store()
            .list(RecordKind::Lineage)
            .unwrap()
            .iter()
            .filter(|x| SignedWipe::decode(&x.data).is_ok())
            .count()
    };
    assert_eq!(count(&r), 1);
    r.n.repo().mark_stolen(a, T as i64 + 5).unwrap();
    assert_eq!(count(&r), 1);
}

/// Attack: an order signed by any identity other than the recovered
/// head's, or naming an issuer outside its roster, or another removal,
/// or other device keys, erases nothing; the countdown goes on.
#[test]
fn forged_orders_erase_nothing() {
    let mut r = a_quarantined_by_recover();
    let good = order_for_a(&mut r);
    let other = IdentityKey::generate().unwrap();
    plant(&r.a, &sign_wipe(good.clone(), &other).unwrap());

    // The old identity (the one A holds itself) is not the head's.
    let old = IdentityKey::from_bytes(&r.a.repo().account().keyset().identity.to_bytes()).unwrap();
    plant(&r.a, &sign_wipe(good.clone(), &old).unwrap());

    let n = n_identity(&mut r);
    let c = r.f.others[C].id();
    for body in [
        WipeBody {
            issuer: c,
            ..good.clone()
        },
        WipeBody {
            target_key: [7; 32],
            ..good.clone()
        },
        WipeBody {
            removed_by: r.before.head,
            ..good.clone()
        },
        WipeBody {
            head: r.before.head,
            ..good.clone()
        },
        WipeBody {
            account_id: Id::new(),
            ..good.clone()
        },
        WipeBody {
            target: c,
            ..good.clone()
        },
    ] {
        plant(&r.a, &sign_wipe(body, &n).unwrap());
    }
    // A signature over another body.
    let mut swapped = sign_wipe(good.clone(), &n).unwrap();
    swapped.body.issued_at += 1;
    plant(&r.a, &swapped);

    assert_eq!(
        tick(&r.a, T + 1),
        QuarantineTick::Waiting { erase_at: T + Q }
    );
    assert!(matches!(
        state(&r.a),
        DeviceLineageState::Quarantined { .. }
    ));

    // The genuine order still works afterwards.
    plant(&r.a, &sign_wipe(good, &n).unwrap());
    assert_eq!(tick(&r.a, T + 2), QuarantineTick::Erased);
}

/// Attack: an order for another device (C, removed by the same
/// `Recover`) replayed to A erases nothing on A.
#[test]
fn order_for_another_device_erases_nothing() {
    let mut r = a_quarantined_by_recover();
    let c = r.f.others[C].id();
    n_marks_stolen(&mut r, c);
    assert_eq!(r.n.repo().stolen_devices().unwrap(), vec![c]);
    assert_eq!(
        tick(&r.a, T + 1),
        QuarantineTick::Waiting { erase_at: T + Q }
    );
}

/// Attack: the order reaches A without the removal it names (the server
/// held the `Recover` back): A is not quarantined and erases nothing.
#[test]
fn order_without_its_removal_erases_nothing() {
    let mut r = recovered();
    let a = trust_of_dev(&r.a).unwrap().me.device_id;
    r.n.repo().mark_stolen(a, T as i64).unwrap();
    sync(&mut r.server, &mut r.n).unwrap();
    let head = r.out.head;
    pull_only(&r.server, &mut r.a, |ch| {
        !(ch.kind == RecordKind::Lineage
            && ch
                .data
                .as_ref()
                .and_then(|d| LineageRecord::decode(d).ok())
                .is_some_and(|l| l.hash() == head))
    });
    assert_eq!(tick(&r.a, T), QuarantineTick::NotQuarantined);
    assert_eq!(state(&r.a), DeviceLineageState::Current);
    r.a.try_unlock(PASSWORD, &r.a_sk).unwrap();
}

/// Without a `Recover`: a device still in the roster cannot be marked (it
/// is removed first, by a rotation); once removed it is, and it erases at
/// its next tick instead of 7 days later. C follows A's first rotation,
/// then A removes C.
#[test]
fn removed_then_marked_stolen_erases_at_once() {
    let (mut server, mut a, c, f, out, sk1) = rotated();
    let (repo, _auk, c_sk) =
        follow_rotation(c.store(), out.head, PASSWORD, &f.others[C].keys).unwrap();
    drop(repo);
    let mut c = c;
    assert_eq!(state(&c), DeviceLineageState::Current);

    let c_id = f.others[C].id();
    let refusal = a.repo().mark_stolen(c_id, T as i64);
    assert!(matches!(&refusal, Err(Error::Validation(v)) if v.reason == "not removed"));
    let me = trust_of_dev(&a).unwrap().me.device_id;
    let refusal = a.repo().mark_stolen(me, T as i64);
    assert!(matches!(&refusal, Err(Error::Validation(v)) if v.reason == "this device"));

    let new_sk = SecretKey::generate().unwrap();
    let mut req = request(&f, &new_sk, vec![c_id], RotationReason::Revoke);
    req.secret_key = &sk1;
    a.repo.as_mut().unwrap().rotate(req).unwrap();
    sync(&mut server, &mut a).unwrap();
    pull(&server, &mut c);
    assert_eq!(tick(&c, T), QuarantineTick::Waiting { erase_at: T + Q });

    a.repo().mark_stolen(c_id, T as i64).unwrap();
    assert_eq!(a.repo().stolen_devices().unwrap(), vec![c_id]);
    sync(&mut server, &mut a).unwrap();
    pull(&server, &mut c);
    assert_eq!(tick(&c, T + 1), QuarantineTick::Erased);
    assert_erased(&c);
    let _ = c_sk;
}

/// The erase touches only the store of the account that was ordered:
/// another account's store on the same device, holding the very same
/// order bytes, stays as it was.
#[test]
fn other_account_store_untouched() {
    let mut r = a_quarantined_by_recover();
    let mut other_server = Server::default();
    let (other, _f) = fixture_on(&mut other_server);
    let a = a_id(&r);
    n_marks_stolen(&mut r, a);
    let order =
        r.a.store()
            .list(RecordKind::Lineage)
            .unwrap()
            .into_iter()
            .find(|x| SignedWipe::decode(&x.data).is_ok())
            .unwrap();
    other.store().put(order).unwrap();
    let before = snapshot(&other.store());
    assert_eq!(tick(&r.a, T + 1), QuarantineTick::Erased);
    assert_eq!(tick(&other, T + 1), QuarantineTick::NotQuarantined);
    assert_eq!(snapshot(&other.store()), before);
}
