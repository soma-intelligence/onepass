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
use onepass_core::store::{RotationPush, VaultEvent, account_record_id};
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
    });
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
    ) -> Result<()> {
        self.ok()?;
        if self.fail_commit {
            return Err(Error::Store("disk full".into()));
        }
        self.race()?;
        self.inner
            .put_rotation(writes, chain, expected, trust, rotation)?;
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

    // Reopened: phase 2 only, the vault records, nothing deleted.
    assert_eq!(state(&a), rotating(2));
    let phase_two = outbox(&a);
    assert!(!phase_two.is_empty());
    assert!(phase_two.iter().all(|(c, _)| c.data.is_some()
        && matches!(
            c.kind,
            RecordKind::VaultKey | RecordKind::VaultMeta | RecordKind::Item | RecordKind::Manifest
        )));
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
    let (repo, _, _) = follow_rotation(c.store(), out.head, PASSWORD, &f.others[C].keys).unwrap();
    c.repo = Some(repo);
    assert!(no_account_pair_out(&c, old_id));
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
