//! Malicious storage suite: each attack class of the ETH Zurich 2026 study on
//! cloud password managers, played by a store that rewrites what it serves.
//! Every attack must be detected and refused with its exact error.

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::OnceLock;

use onepass_core::account::{Account, AccountParams, NewAccount};
use onepass_core::crypto::{Aad, BlobKind, KdfParams, SymmetricKey, random_array, seal, wrap_key};
use onepass_core::manifest::{
    Manifest, SignedManifest, merkle_root, sign_manifest, verify_manifest,
};
use onepass_core::model::{FieldValue, Item, ItemType, new_item};
use onepass_core::repo::{DeviceState, Repository};
use onepass_core::store::{MemoryStore, Record, RecordKind, RecordStore};
use onepass_core::vault::{ItemRecord, Vault, VaultMeta};
use onepass_core::{Error, Id, IntegrityError, Result};

const PASSWORD: &str = "correct horse";

/// What the store does to the records it serves.
#[derive(Debug, Clone)]
enum Attack {
    /// Serve everything as stored.
    None,
    /// Serve these account params instead of the stored ones.
    DowngradeKdf { params: Vec<u8> },
    /// Serve this manifest record in place of the one with the same id.
    RollbackManifest { manifest: Record },
    /// Hide this item record from `list`.
    DropItem { record: Id },
    /// Add this item record to `list`.
    InjectItem { record: Record },
    /// Serve `old` in place of the record `current`.
    ReplayOldItem { current: Id, old: Record },
    /// Serve the item record under the vault prefix `to`.
    SwapItemsAcrossVaults { record: Id, to: Id },
    /// Exchange the `blob` fields of two item records.
    SwapItemBlobs { a: Id, b: Id },
    /// Serve this key envelope for the vault, and this meta blob if given.
    ReplaceVaultKey {
        vault: Id,
        envelope: Vec<u8>,
        meta: Option<Vec<u8>>,
    },
    /// Hide the key envelope of this vault from `get` and `list`.
    HideVault { vault: Id },
    /// Serve this manifest record, signed by another key.
    ForgeManifest { manifest: Record },
    /// Drop the last byte of the item record's `blob`.
    TruncateBlob { record: Id },
}

/// A store that keeps records honestly and lies when serving them. Every
/// write is logged as `(kind, id)`.
struct EvilStore {
    inner: MemoryStore,
    attack: Attack,
    puts: Rc<RefCell<Vec<(RecordKind, Id)>>>,
}

fn decode_item(data: &[u8]) -> (Id, ItemRecord) {
    let prefix: [u8; 16] = data[..16].try_into().unwrap();
    (Id(prefix), postcard::from_bytes(&data[16..]).unwrap())
}

fn encode_item(vault: Id, rec: &ItemRecord) -> Vec<u8> {
    let mut data = vault.0.to_vec();
    data.extend(postcard::to_allocvec(rec).unwrap());
    data
}

impl EvilStore {
    fn rewrite(&self, mut r: Record) -> Option<Record> {
        use RecordKind as K;
        match (&self.attack, r.kind) {
            (Attack::DowngradeKdf { params }, K::AccountParams) => r.data = params.clone(),
            (
                Attack::RollbackManifest { manifest } | Attack::ForgeManifest { manifest },
                K::Manifest,
            ) if manifest.id == r.id => r = manifest.clone(),
            (Attack::DropItem { record }, K::Item) if *record == r.id => return None,
            (Attack::ReplayOldItem { current, old }, K::Item) if *current == r.id => {
                r = old.clone()
            }
            (Attack::SwapItemsAcrossVaults { record, to }, K::Item) if *record == r.id => {
                r.data[..16].copy_from_slice(&to.0)
            }
            (Attack::SwapItemBlobs { a, b }, K::Item) if *a == r.id || *b == r.id => {
                let other = if *a == r.id { *b } else { *a };
                let other = self.inner.get(K::Item, other).unwrap().unwrap();
                let (vault, mut rec) = decode_item(&r.data);
                rec.blob = decode_item(&other.data).1.blob;
                r.data = encode_item(vault, &rec);
            }
            (
                Attack::ReplaceVaultKey {
                    vault, envelope, ..
                },
                K::VaultKey,
            ) if *vault == r.id => r.data = envelope.clone(),
            (
                Attack::ReplaceVaultKey {
                    vault,
                    meta: Some(meta),
                    ..
                },
                K::VaultMeta,
            ) if *vault == r.id => r.data = meta.clone(),
            (Attack::HideVault { vault }, K::VaultKey) if *vault == r.id => return None,
            (Attack::TruncateBlob { record }, K::Item) if *record == r.id => {
                let (vault, mut rec) = decode_item(&r.data);
                rec.blob.pop();
                r.data = encode_item(vault, &rec);
            }
            _ => {}
        }
        Some(r)
    }
}

impl RecordStore for EvilStore {
    fn put(&mut self, r: Record) -> Result<()> {
        self.puts.borrow_mut().push((r.kind, r.id));
        self.inner.put(r)
    }

    fn put_if_version(&mut self, r: Record, expected: Option<u64>) -> Result<()> {
        self.puts.borrow_mut().push((r.kind, r.id));
        self.inner.put_if_version(r, expected)
    }

    fn get(&self, kind: RecordKind, id: Id) -> Result<Option<Record>> {
        Ok(self.inner.get(kind, id)?.and_then(|r| self.rewrite(r)))
    }

    fn list(&self, kind: RecordKind) -> Result<Vec<Record>> {
        let mut out: Vec<Record> = self
            .inner
            .list(kind)?
            .into_iter()
            .filter_map(|r| self.rewrite(r))
            .collect();
        if let (Attack::InjectItem { record }, RecordKind::Item) = (&self.attack, kind) {
            out.push(record.clone());
        }
        Ok(out)
    }

    fn delete(&mut self, kind: RecordKind, id: Id) -> Result<()> {
        self.inner.delete(kind, id)
    }
}

/// A store shared with the test while the fixture is built, so its records
/// can be read back after the repository wrote them.
struct Shared(Rc<RefCell<MemoryStore>>);

impl RecordStore for Shared {
    fn put(&mut self, r: Record) -> Result<()> {
        self.0.borrow_mut().put(r)
    }

    fn put_if_version(&mut self, r: Record, expected: Option<u64>) -> Result<()> {
        self.0.borrow_mut().put_if_version(r, expected)
    }

    fn get(&self, kind: RecordKind, id: Id) -> Result<Option<Record>> {
        self.0.borrow().get(kind, id)
    }

    fn list(&self, kind: RecordKind) -> Result<Vec<Record>> {
        self.0.borrow().list(kind)
    }

    fn delete(&mut self, kind: RecordKind, id: Id) -> Result<()> {
        self.0.borrow_mut().delete(kind, id)
    }
}

/// The victim's account with two vaults and three items, as an honest store
/// holds it, plus what the store kept from earlier states.
struct Fixture {
    victim: NewAccount,
    /// Another account, for injected and forged records.
    attacker: NewAccount,
    store: MemoryStore,
    device: DeviceState,
    vault_a: Id,
    vault_b: Id,
    /// In vault A, at version 2.
    a1: Id,
    /// In vault A, at version 1.
    a2: Id,
    /// In vault B, at version 1.
    b1: Id,
    /// The version 1 record of `a1`.
    a1_v1: Record,
    /// The manifest of vault A before `a1` went to version 2.
    manifest_a_prev: Record,
}

fn kdf() -> KdfParams {
    KdfParams {
        m_kib: 8192,
        t: 1,
        p: 1,
        salt: random_array().unwrap(),
    }
}

fn meta(name: &str) -> VaultMeta {
    VaultMeta {
        name: name.into(),
        icon: "key".into(),
        color: "blue".into(),
        travel_safe: false,
        mcp_access: false,
    }
}

fn login(vault: Id, user: &str) -> Item {
    let mut item = new_item(ItemType::Login, vault, "Example");
    item.field_mut("username").unwrap().value = FieldValue::Text(user.into());
    item
}

/// The record holding `item_id`, with its blob id.
fn item_record(store: &MemoryStore, item_id: Id) -> Record {
    store
        .list(RecordKind::Item)
        .unwrap()
        .into_iter()
        .find(|r| decode_item(&r.data).1.item_id == item_id)
        .unwrap()
}

fn fixture() -> &'static Fixture {
    static F: OnceLock<Fixture> = OnceLock::new();
    F.get_or_init(|| {
        // The SLH-DSA identity signature is the slow part: both at once.
        let (victim, attacker) = std::thread::scope(|s| {
            let v = s.spawn(|| Account::create_with_params(PASSWORD, kdf()).unwrap());
            let a = s.spawn(|| Account::create_with_params("attacker", kdf()).unwrap());
            (v.join().unwrap(), a.join().unwrap())
        });
        let shared = Rc::new(RefCell::new(MemoryStore::new()));
        let id = victim.account.params.account_id;
        for (kind, data) in [
            (RecordKind::AccountParams, &victim.params_record),
            (RecordKind::Keyset, &victim.keyset_record),
        ] {
            shared
                .borrow_mut()
                .put(Record {
                    id,
                    kind,
                    version: 1,
                    data: data.clone(),
                })
                .unwrap();
        }
        let mut repo = Repository::unlock(
            Shared(shared.clone()),
            PASSWORD,
            &victim.secret_key,
            DeviceState::default(),
        )
        .unwrap();
        let va = repo.create_vault(meta("A")).unwrap();
        let vb = repo.create_vault(meta("B")).unwrap();
        let a1 = login(va.id, "a1");
        let a2 = login(va.id, "a2");
        let b1 = login(vb.id, "b1");
        repo.save_item(&va, a1.clone()).unwrap();
        repo.save_item(&va, a2.clone()).unwrap();
        repo.save_item(&vb, b1.clone()).unwrap();
        let a1_v1 = item_record(&shared.borrow(), a1.id);
        let manifest_a_prev = shared
            .borrow()
            .get(RecordKind::Manifest, va.id)
            .unwrap()
            .unwrap();
        let mut a1_next = a1.clone();
        a1_next.field_mut("username").unwrap().value = FieldValue::Text("a1 v2".into());
        repo.save_item(&va, a1_next).unwrap();
        let device = repo.device_state().clone();
        drop(repo);
        let store = shared.borrow().clone();
        Fixture {
            victim,
            attacker,
            store,
            device,
            vault_a: va.id,
            vault_b: vb.id,
            a1: a1.id,
            a2: a2.id,
            b1: b1.id,
            a1_v1,
            manifest_a_prev,
        }
    })
}

/// Unlock the victim's account on its device, over a store playing `attack`.
fn unlock(attack: Attack, device: DeviceState) -> Result<Repository<EvilStore>> {
    unlock_logged(attack, device, Rc::default())
}

/// `unlock`, logging every write of the store into `puts`.
fn unlock_logged(
    attack: Attack,
    device: DeviceState,
    puts: Rc<RefCell<Vec<(RecordKind, Id)>>>,
) -> Result<Repository<EvilStore>> {
    let f = fixture();
    let store = EvilStore {
        inner: f.store.clone(),
        attack,
        puts,
    };
    Repository::unlock(store, PASSWORD, &f.victim.secret_key, device)
}

fn open(attack: Attack) -> Repository<EvilStore> {
    unlock(attack, fixture().device.clone()).unwrap()
}

fn vault<S: RecordStore>(repo: &Repository<S>, id: Id) -> Vault {
    repo.vaults()
        .unwrap()
        .into_iter()
        .find(|v| v.id == id)
        .unwrap()
}

/// The error of `r`, which must be an integrity refusal.
fn integrity<T: std::fmt::Debug>(r: Result<T>) -> IntegrityError {
    match r {
        Err(Error::Integrity(e)) => e,
        other => panic!("expected an integrity error, got {other:?}"),
    }
}

/// The items of vault `id` served under `attack`.
fn items_under(attack: Attack, id: Id) -> Result<Vec<Item>> {
    let mut repo = open(attack);
    let v = vault(&repo, id);
    repo.items(&v)
}

/// The current manifest of vault A, decoded.
fn current_manifest_a(v: &Vault) -> Manifest {
    let f = fixture();
    let rec = f
        .store
        .get(RecordKind::Manifest, f.vault_a)
        .unwrap()
        .unwrap();
    let sm: SignedManifest = postcard::from_bytes(&rec.data).unwrap();
    verify_manifest(v, &f.victim.account.params.signing_pub, &sm, None).unwrap()
}

fn manifest_record(vault: Id, sm: &SignedManifest, seq: u64) -> Record {
    Record {
        id: vault,
        kind: RecordKind::Manifest,
        version: seq,
        data: postcard::to_allocvec(sm).unwrap(),
    }
}

#[test]
fn honest_store_serves_the_fixture() {
    let f = fixture();
    let mut repo = open(Attack::None);
    let ids: Vec<Id> = repo.vaults().unwrap().iter().map(|v| v.id).collect();
    assert_eq!(ids, vec![f.vault_a, f.vault_b]);
    let va = vault(&repo, f.vault_a);
    let vb = vault(&repo, f.vault_b);
    let a: Vec<Id> = repo.items(&va).unwrap().iter().map(|i| i.id).collect();
    assert_eq!(a, vec![f.a1, f.a2]);
    let b: Vec<Id> = repo.items(&vb).unwrap().iter().map(|i| i.id).collect();
    assert_eq!(b, vec![f.b1]);
}

#[test]
fn downgrade_kdf() {
    let f = fixture();
    let p = &f.victim.account.params;
    let weak = KdfParams {
        m_kib: 8192,
        t: 1,
        p: 1,
        salt: random_array().unwrap(),
    };
    // The signed fields, as `Account` signs v2 params (epoch included),
    // under the attacker's identity, at the victim's epoch.
    let msg = postcard::to_allocvec(&(&p.account_id, &weak, &p.signing_pub, &p.kem_pub, p.epoch))
        .unwrap();
    let identity = &f.attacker.account.keyset().identity;
    let forged = AccountParams {
        account_id: p.account_id,
        kdf: weak,
        identity_pub: identity.verifying_key(),
        signing_pub: p.signing_pub.clone(),
        kem_pub: p.kem_pub.clone(),
        identity_sig: identity.sign(b"account-params/v2", &msg).unwrap(),
        epoch: p.epoch,
    };
    let params = forged.encode().unwrap();
    assert_eq!(
        integrity(
            unlock(
                Attack::DowngradeKdf {
                    params: params.clone()
                },
                f.device.clone()
            )
            .map(drop)
        ),
        IntegrityError::ParamsUnsigned
    );
    // Control: the forged signature itself is valid. A device that pinned
    // nothing gets past every params check and only fails on the keyset,
    // bound to the real parameters (their hash, in its header and sealed
    // context). So the refusal above is the pin.
    let unpinned = unlock(Attack::DowngradeKdf { params }, DeviceState::default());
    assert_eq!(
        unpinned.map(drop),
        Err(Error::Integrity(IntegrityError::WrongContext))
    );
}

#[test]
fn weaker_kdf_same_identity() {
    let mut device = fixture().device.clone();
    device.pinned.as_mut().unwrap().kdf_floor.m_kib = 16384;
    assert_eq!(
        integrity(unlock(Attack::None, device).map(drop)),
        IntegrityError::ParamsDowngrade
    );
}

#[test]
fn rollback_manifest() {
    let f = fixture();
    let mut repo = open(Attack::None);
    let va = vault(&repo, f.vault_a);
    repo.items(&va).unwrap();
    let device = repo.device_state().clone();

    let attack = Attack::RollbackManifest {
        manifest: f.manifest_a_prev.clone(),
    };
    let mut repo = unlock(attack, device).unwrap();
    let va = vault(&repo, f.vault_a);
    assert_eq!(integrity(repo.items(&va)), IntegrityError::ManifestRollback);
}

#[test]
fn rollback_manifest_fork_at_the_same_seq() {
    let f = fixture();
    let mut repo = open(Attack::None);
    let va = vault(&repo, f.vault_a);
    repo.items(&va).unwrap();
    let device = repo.device_state().clone();

    // Another manifest at the seq last seen, validly signed: a fork.
    let mut fork = current_manifest_a(&va);
    fork.entries.retain(|e| e.item_id != f.a2);
    fork.merkle_root = merkle_root(&fork.entries);
    let sm = sign_manifest(&va, &f.victim.account.keyset().signing, &fork).unwrap();
    let attack = Attack::RollbackManifest {
        manifest: manifest_record(f.vault_a, &sm, fork.seq),
    };
    let mut repo = unlock(attack, device).unwrap();
    assert_eq!(integrity(repo.items(&va)), IntegrityError::ManifestRollback);
}

#[test]
fn drop_item() {
    let f = fixture();
    let record = item_record(&f.store, f.a2).id;
    assert_eq!(
        integrity(items_under(Attack::DropItem { record }, f.vault_a)),
        IntegrityError::ManifestMissingItem
    );
}

#[test]
fn inject_item() {
    let f = fixture();
    // An item sealed by the attacker's own account, under its own vault.
    let (theirs, _, _) = Vault::create(&f.attacker.account, meta("X")).unwrap();
    let rec = theirs.seal_item(&login(theirs.id, "evil"), 1).unwrap();
    let record = Record {
        id: Id::new(),
        kind: RecordKind::Item,
        version: 1,
        data: encode_item(f.vault_a, &rec),
    };
    assert_eq!(
        integrity(items_under(Attack::InjectItem { record }, f.vault_a)),
        IntegrityError::ManifestUnexpectedItem
    );
}

#[test]
fn replay_old_item() {
    let f = fixture();
    let attack = Attack::ReplayOldItem {
        current: item_record(&f.store, f.a1).id,
        old: f.a1_v1.clone(),
    };
    assert_eq!(
        integrity(items_under(attack, f.vault_a)),
        IntegrityError::ManifestItemMismatch
    );
}

#[test]
fn swap_items_across_vaults() {
    let f = fixture();
    // a2 is at version 1: the shape of an interrupted first write in B.
    let attack = Attack::SwapItemsAcrossVaults {
        record: item_record(&f.store, f.a2).id,
        to: f.vault_b,
    };
    assert_eq!(
        integrity(items_under(attack, f.vault_b)),
        IntegrityError::ManifestUnexpectedItem
    );
}

#[test]
fn swap_item_blobs() {
    let f = fixture();
    let attack = Attack::SwapItemBlobs {
        a: item_record(&f.store, f.a1).id,
        b: item_record(&f.store, f.a2).id,
    };
    assert_eq!(
        integrity(items_under(attack, f.vault_a)),
        IntegrityError::ManifestItemMismatch
    );
}

fn vault_context(vault: Id) -> Vec<u8> {
    let mut context = b"vault:".to_vec();
    context.extend_from_slice(&vault.0);
    context
}

#[test]
fn replace_vault_key_wrong_recipient() {
    // Wrapped to the attacker's own KEM key: the victim cannot unwrap it.
    let f = fixture();
    let key = SymmetricKey::generate().unwrap();
    let envelope = wrap_key(
        &f.attacker.account.params.kem_pub,
        &key,
        &vault_context(f.vault_a),
    )
    .unwrap();
    let repo = open(Attack::ReplaceVaultKey {
        vault: f.vault_a,
        envelope,
        meta: None,
    });
    assert_eq!(integrity(repo.vaults()), IntegrityError::Commitment);
}

#[test]
fn replace_vault_key_to_victim() {
    // The realistic substitution: the victim's KEM public key is in clear in
    // the account params, so the store wraps its own key to it and seals a
    // matching meta. The envelope and the meta open; only the signed
    // manifest, sealed with the real vault key, gives it away.
    let f = fixture();
    let key = SymmetricKey::generate().unwrap();
    let envelope = wrap_key(
        &f.victim.account.params.kem_pub,
        &key,
        &vault_context(f.vault_a),
    )
    .unwrap();
    let mut evil_meta = meta("A");
    evil_meta.mcp_access = true;
    let aad = Aad {
        blob_id: f.vault_a,
        vault_id: Some(f.vault_a),
        schema: 1,
    };
    let meta_blob = seal(
        &key,
        BlobKind::VaultMeta,
        &aad,
        &postcard::to_allocvec(&evil_meta).unwrap(),
    )
    .unwrap();
    // The substituted vault opens on its own: the envelope is not authenticated.
    let planted = Vault::open(&f.victim.account, f.vault_a, &envelope, &meta_blob).unwrap();
    assert!(planted.meta.mcp_access);

    let attack = Attack::ReplaceVaultKey {
        vault: f.vault_a,
        envelope,
        meta: Some(meta_blob),
    };
    assert_eq!(
        integrity(open(attack.clone()).vaults()),
        IntegrityError::Commitment
    );

    // Even handed the planted vault directly, a write is refused before
    // anything reaches the store, so no secret is sealed under its key.
    let puts = Rc::default();
    let mut repo = unlock_logged(attack, f.device.clone(), Rc::clone(&puts)).unwrap();
    assert_eq!(
        integrity(repo.save_item(&planted, login(f.vault_a, "secret"))),
        IntegrityError::Commitment
    );
    assert!(puts.borrow().is_empty(), "{:?}", puts.borrow());
}

#[test]
fn hide_vault() {
    let f = fixture();
    let attack = Attack::HideVault { vault: f.vault_b };
    // The device read vault B before: hiding it is detected.
    assert_eq!(
        integrity(open(attack.clone()).vaults()),
        IntegrityError::VaultMissing
    );
    // A device that never read it tells too: the signed vault list lists
    // it (milestone 2b).
    let mut device = f.device.clone();
    device.last_seen.remove(&f.vault_b);
    let repo = unlock(attack, device).unwrap();
    assert_eq!(integrity(repo.vaults()), IntegrityError::VaultMissing);
}

#[test]
fn forge_manifest() {
    let f = fixture();
    let repo = open(Attack::None);
    let va = vault(&repo, f.vault_a);
    let m = current_manifest_a(&va);
    let sm = sign_manifest(&va, &f.attacker.account.keyset().signing, &m).unwrap();
    let attack = Attack::ForgeManifest {
        manifest: manifest_record(f.vault_a, &sm, m.seq),
    };
    // Refused as soon as the vault is listed, and again on load.
    assert_eq!(
        integrity(open(attack.clone()).vaults()),
        IntegrityError::Signature
    );
    let mut repo = open(attack);
    assert_eq!(integrity(repo.items(&va)), IntegrityError::Signature);
}

#[test]
fn truncate_blob() {
    let f = fixture();
    let attack = Attack::TruncateBlob {
        record: item_record(&f.store, f.a2).id,
    };
    assert_eq!(
        integrity(items_under(attack, f.vault_a)),
        IntegrityError::ManifestItemMismatch
    );
}
