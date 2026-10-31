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
    RotationPrompt, follow_rotation, pending_rotation, reject_rotation, stored_params_epoch,
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
            children: vec![out.head]
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
            children: vec![out.head]
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
            children: vec![out.head]
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
            children: vec![out.head]
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
            children: vec![r2.head]
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
            children: vec![out.head]
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
            children: vec![out.head]
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
