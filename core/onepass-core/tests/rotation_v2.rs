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
use onepass_core::lineage::{
    GenesisBody, LINEAGE_FORMAT, LineageRecord, RosterEntry, RotationReason, delivery_id,
    identity_id, rotation_code, sign_genesis, verify_rotation,
};
use onepass_core::manifest::{SeenManifest, SignedManifest, verify_manifest};
use onepass_core::repo::rotate::open_key_delivery;
use onepass_core::repo::travel::TravelState;
use onepass_core::repo::{RotateRequest, RotationOutcome};
use onepass_core::store::{VaultEvent, account_record_id};
use onepass_core::trust::{DeviceLineageState, LineageHead, TrustLevel, TrustState};

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
    let mut server = Server::default();
    let (mut a, _b, sk, items) = setup(
        &mut server,
        &[("alice", T0), ("bob", T0 + 1), ("carol", T0 + 2)],
    );
    let v = a.vault();
    a.repo().archive_item(&v, items[1].id).unwrap();
    a.repo().trash_item(&v, items[2].id).unwrap();
    sync(&mut server, &mut a).unwrap();

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
}

impl Faulty {
    fn ok(&self) -> Result<()> {
        if self.broken.get() {
            Err(Error::Store("network down".into()))
        } else {
            Ok(())
        }
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
}

fn faulty_session(a: &Device, f: &Fixture, fail_commit: bool) -> Repository<Faulty> {
    let inner = a.store();
    let state = inner.device_state().unwrap();
    let store = Faulty {
        inner,
        fail_commit,
        broken: Cell::new(false),
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
