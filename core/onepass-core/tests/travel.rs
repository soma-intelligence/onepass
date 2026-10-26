//! Travel Mode: vaults without `travel_safe` leave the device only when the
//! upstream holds them byte for byte, and come back only through the core's
//! normal verification (signed manifest, last seen, records).

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::OnceLock;

use onepass_core::account::{Account, NewAccount};
use onepass_core::crypto::{KdfParams, random_array};
use onepass_core::model::{FieldValue, Item, ItemType, new_item};
use onepass_core::repo::travel::{SEALED_TRAVEL_STATE_LEN, TravelState};
use onepass_core::repo::{DeviceState, Repository, split_item_record};
use onepass_core::store::{MemoryStore, Record, RecordKind, RecordStore};
use onepass_core::vault::{Vault, VaultMeta};
use onepass_core::{Error, Id, IntegrityError, Result};

const PASSWORD: &str = "travel pw";

const KINDS: [RecordKind; 6] = [
    RecordKind::AccountParams,
    RecordKind::Keyset,
    RecordKind::VaultKey,
    RecordKind::VaultMeta,
    RecordKind::Item,
    RecordKind::Manifest,
];

fn kdf() -> KdfParams {
    KdfParams {
        m_kib: 8192,
        t: 1,
        p: 1,
        salt: random_array().unwrap(),
    }
}

/// The account of the tests and another one, made once per test binary
/// (SLH-DSA is slow in debug).
fn accounts() -> &'static (NewAccount, NewAccount) {
    static A: OnceLock<(NewAccount, NewAccount)> = OnceLock::new();
    A.get_or_init(|| {
        std::thread::scope(|s| {
            let a = s.spawn(|| Account::create_with_params(PASSWORD, kdf()).unwrap());
            let b = s.spawn(|| Account::create_with_params(PASSWORD, kdf()).unwrap());
            (a.join().unwrap(), b.join().unwrap())
        })
    })
}

/// A store shared with the test, so its records can be read and edited
/// while a repository holds it.
#[derive(Clone, Default)]
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

impl Shared {
    /// Every record, sorted by kind and id.
    fn all(&self) -> Vec<Record> {
        let mut out = Vec::new();
        for kind in KINDS {
            let mut l = self.list(kind).unwrap();
            l.sort_by_key(|r| r.id);
            out.extend(l);
        }
        out
    }

    /// The records of one vault: key, meta, manifest and its items.
    fn vault_records(&self, vault: Id) -> Vec<Record> {
        self.all()
            .into_iter()
            .filter(|r| match r.kind {
                RecordKind::VaultKey | RecordKind::VaultMeta | RecordKind::Manifest => {
                    r.id == vault
                }
                RecordKind::Item => split_item_record(&r.data).unwrap().0 == vault,
                _ => false,
            })
            .collect()
    }

    fn remove_vault(&self, vault: Id) {
        for r in self.vault_records(vault) {
            self.0.borrow_mut().delete(r.kind, r.id).unwrap();
        }
    }

    fn put_all(&self, records: &[Record]) {
        for r in records {
            self.0.borrow_mut().put(r.clone()).unwrap();
        }
    }
}

/// Copy every record of `from` into `to` (a simulated sync).
fn mirror(from: &Shared, to: &Shared) {
    to.put_all(&from.all());
}

fn meta(name: &str, travel_safe: bool) -> VaultMeta {
    VaultMeta {
        name: name.into(),
        icon: "key".into(),
        color: "blue".into(),
        travel_safe,
        mcp_access: false,
    }
}

fn login(vault: Id, user: &str) -> Item {
    let mut item = new_item(ItemType::Login, vault, "Example");
    item.field_mut("username").unwrap().value = FieldValue::Text(user.into());
    item
}

fn write_account(store: &Shared, n: &NewAccount) {
    let id = n.account.params.account_id;
    for (kind, data) in [
        (RecordKind::AccountParams, &n.params_record),
        (RecordKind::Keyset, &n.keyset_record),
    ] {
        store
            .0
            .borrow_mut()
            .put(Record {
                id,
                kind,
                version: 1,
                data: data.clone(),
            })
            .unwrap();
    }
}

struct Fx {
    repo: Repository<Shared>,
    local: Shared,
    upstream: Shared,
    perso: Vault,
    voyage: Vault,
}

/// The account on a local store with "Perso" (not travel safe) and
/// "Voyage" (travel safe), one item in each, and an empty upstream.
fn fx() -> Fx {
    let (n, _) = accounts();
    let local = Shared::default();
    write_account(&local, n);
    let mut repo = Repository::unlock(
        local.clone(),
        PASSWORD,
        &n.secret_key,
        DeviceState::default(),
    )
    .unwrap();
    let perso = repo.create_vault(meta("Perso", false)).unwrap();
    let voyage = repo.create_vault(meta("Voyage", true)).unwrap();
    repo.save_item(&perso, login(perso.id, "perso")).unwrap();
    repo.save_item(&voyage, login(voyage.id, "voyage")).unwrap();
    Fx {
        repo,
        local,
        upstream: Shared::default(),
        perso,
        voyage,
    }
}

fn names(repo: &Repository<Shared>) -> Vec<String> {
    let mut n: Vec<String> = repo
        .vaults()
        .unwrap()
        .into_iter()
        .map(|v| v.meta.name)
        .collect();
    n.sort();
    n
}

fn snapshot(f: &mut Fx) -> Vec<(String, Vec<Item>)> {
    let mut out = Vec::new();
    for v in f.repo.vaults().unwrap() {
        let items = f.repo.items(&v).unwrap();
        out.push((v.meta.name.clone(), items));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

fn integrity<T: std::fmt::Debug>(r: Result<T>) -> IntegrityError {
    match r {
        Err(Error::Integrity(e)) => e,
        other => panic!("expected an integrity error, got {other:?}"),
    }
}

fn vault_by_name(repo: &Repository<Shared>, name: &str) -> Vault {
    repo.vaults()
        .unwrap()
        .into_iter()
        .find(|v| v.meta.name == name)
        .unwrap()
}

#[test]
fn roundtrip_restores_hidden_vaults_intact() {
    let mut f = fx();
    let before = snapshot(&mut f);
    mirror(&f.local, &f.upstream);
    let state = f.repo.enter_travel(&f.upstream).unwrap();
    assert_eq!(names(&f.repo), vec!["Voyage".to_string()]);
    assert!(state.parked.contains_key(&f.perso.id));
    assert!(!state.parked.contains_key(&f.voyage.id));
    assert!(f.local.vault_records(f.perso.id).is_empty());
    assert!(!f.repo.device_state().last_seen.contains_key(&f.perso.id));

    f.repo.exit_travel(&f.upstream, &state).unwrap();
    assert_eq!(snapshot(&mut f), before);
    assert_eq!(
        f.local.vault_records(f.perso.id),
        f.upstream.vault_records(f.perso.id)
    );
}

#[test]
fn enter_refuses_when_upstream_lacks_a_record() {
    let mut f = fx();
    mirror(&f.local, &f.upstream);
    let item = f
        .upstream
        .vault_records(f.perso.id)
        .into_iter()
        .find(|r| r.kind == RecordKind::Item)
        .unwrap();
    f.upstream
        .0
        .borrow_mut()
        .delete(RecordKind::Item, item.id)
        .unwrap();
    let records = f.local.all();
    let device = f.repo.device_state().clone();
    assert!(f.repo.enter_travel(&f.upstream).is_err());
    assert_eq!(f.local.all(), records);
    assert_eq!(f.repo.device_state(), &device);
}

#[test]
fn enter_refuses_when_upstream_record_differs() {
    let mut f = fx();
    mirror(&f.local, &f.upstream);
    let mut m = f
        .upstream
        .get(RecordKind::Manifest, f.perso.id)
        .unwrap()
        .unwrap();
    let last = m.data.len() - 1;
    m.data[last] ^= 0x01;
    f.upstream.put_all(&[m]);
    let records = f.local.all();
    let device = f.repo.device_state().clone();
    assert!(f.repo.enter_travel(&f.upstream).is_err());
    assert_eq!(f.local.all(), records);
    assert_eq!(f.repo.device_state(), &device);
}

#[test]
fn enter_refuses_when_upstream_has_an_extra_item_record() {
    let mut f = fx();
    mirror(&f.local, &f.upstream);
    let mut extra = f
        .upstream
        .vault_records(f.perso.id)
        .into_iter()
        .find(|r| r.kind == RecordKind::Item)
        .unwrap();
    extra.id = Id::new();
    f.upstream.put_all(&[extra]);
    let records = f.local.all();
    assert!(f.repo.enter_travel(&f.upstream).is_err());
    assert_eq!(f.local.all(), records);
}

#[test]
fn exit_with_replayed_manifest_restores_travel_state() {
    let mut f = fx();
    mirror(&f.local, &f.upstream);
    let old_perso = f.upstream.vault_records(f.perso.id);
    f.repo
        .save_item(&f.perso, login(f.perso.id, "perso 2"))
        .unwrap();
    mirror(&f.local, &f.upstream);
    let new_perso = f.upstream.vault_records(f.perso.id);
    let state = f.repo.enter_travel(&f.upstream).unwrap();

    // Life goes on in the travel safe vault.
    f.repo
        .save_item(&f.voyage, login(f.voyage.id, "on the road"))
        .unwrap();
    let travel_records = f.local.all();
    let travel_device = f.repo.device_state().clone();

    // The upstream replays the older state of "Perso".
    f.upstream.remove_vault(f.perso.id);
    f.upstream.put_all(&old_perso);
    assert_eq!(
        integrity(f.repo.exit_travel(&f.upstream, &state)),
        IntegrityError::ManifestRollback
    );
    assert!(f.local.vault_records(f.perso.id).is_empty());
    assert!(!f.repo.device_state().last_seen.contains_key(&f.perso.id));
    assert_eq!(f.local.all(), travel_records);
    assert_eq!(f.repo.device_state(), &travel_device);
    assert_eq!(names(&f.repo), vec!["Voyage".to_string()]);

    // The state stays valid: with the right upstream, exit succeeds.
    f.upstream.remove_vault(f.perso.id);
    f.upstream.put_all(&new_perso);
    f.repo.exit_travel(&f.upstream, &state).unwrap();
    let perso = vault_by_name(&f.repo, "Perso");
    assert_eq!(f.repo.items(&perso).unwrap().len(), 2);
    let voyage = vault_by_name(&f.repo, "Voyage");
    assert_eq!(f.repo.items(&voyage).unwrap().len(), 2);
}

#[test]
fn exit_refuses_item_dropped_by_upstream() {
    let mut f = fx();
    mirror(&f.local, &f.upstream);
    let state = f.repo.enter_travel(&f.upstream).unwrap();
    let travel_records = f.local.all();
    let travel_device = f.repo.device_state().clone();
    let item = f
        .upstream
        .vault_records(f.perso.id)
        .into_iter()
        .find(|r| r.kind == RecordKind::Item)
        .unwrap();
    f.upstream
        .0
        .borrow_mut()
        .delete(RecordKind::Item, item.id)
        .unwrap();
    assert_eq!(
        integrity(f.repo.exit_travel(&f.upstream, &state)),
        IntegrityError::ManifestMissingItem
    );
    assert_eq!(f.local.all(), travel_records);
    assert_eq!(f.repo.device_state(), &travel_device);
}

#[test]
fn exit_refuses_upstream_record_clashing_with_a_local_one() {
    let mut f = fx();
    mirror(&f.local, &f.upstream);
    let state = f.repo.enter_travel(&f.upstream).unwrap();
    let travel_records = f.local.all();
    // The upstream serves a "Perso" item record under the blob id of a
    // local "Voyage" record: copying it would overwrite that record.
    let voyage_item = f
        .local
        .vault_records(f.voyage.id)
        .into_iter()
        .find(|r| r.kind == RecordKind::Item)
        .unwrap();
    let mut clash = f
        .upstream
        .vault_records(f.perso.id)
        .into_iter()
        .find(|r| r.kind == RecordKind::Item)
        .unwrap();
    clash.id = voyage_item.id;
    f.upstream.put_all(&[clash]);
    assert!(f.repo.exit_travel(&f.upstream, &state).is_err());
    assert_eq!(f.local.all(), travel_records);
}

#[test]
fn exit_accepts_newer_upstream_manifest() {
    let mut f = fx();
    mirror(&f.local, &f.upstream);
    let state = f.repo.enter_travel(&f.upstream).unwrap();

    // Another device writes to "Perso" during the trip.
    let (n, _) = accounts();
    let mut other = Repository::unlock(
        f.upstream.clone(),
        PASSWORD,
        &n.secret_key,
        DeviceState::default(),
    )
    .unwrap();
    let perso = vault_by_name(&other, "Perso");
    let added = login(perso.id, "from elsewhere");
    other.save_item(&perso, added.clone()).unwrap();
    drop(other);

    f.repo.exit_travel(&f.upstream, &state).unwrap();
    let perso = vault_by_name(&f.repo, "Perso");
    let items = f.repo.items(&perso).unwrap();
    assert_eq!(items.len(), 2);
    assert!(items.contains(&added));
}

#[test]
fn sealed_state_roundtrip_and_fixed_len() {
    let mut f = fx();
    mirror(&f.local, &f.upstream);
    let state = f.repo.enter_travel(&f.upstream).unwrap();
    let sealed = f.repo.seal_travel_state(&state).unwrap();
    assert_eq!(sealed.len(), SEALED_TRAVEL_STATE_LEN);
    assert_eq!(SEALED_TRAVEL_STATE_LEN, 65536);
    assert_eq!(f.repo.open_travel_state(&sealed).unwrap(), state);

    let empty = TravelState {
        parked: Default::default(),
        entered_at: 0,
    };
    let sealed_empty = f.repo.seal_travel_state(&empty).unwrap();
    assert_eq!(sealed_empty.len(), SEALED_TRAVEL_STATE_LEN);
    assert_eq!(f.repo.open_travel_state(&sealed_empty).unwrap(), empty);
}

#[test]
fn sealed_state_tamper_refused() {
    let mut f = fx();
    mirror(&f.local, &f.upstream);
    let state = f.repo.enter_travel(&f.upstream).unwrap();
    let sealed = f.repo.seal_travel_state(&state).unwrap();

    // A byte of the body.
    let mut b = sealed.clone();
    b[100] ^= 0x01;
    assert!(f.repo.open_travel_state(&b).is_err());

    // Non-zero padding.
    let mut b = sealed.clone();
    *b.last_mut().unwrap() = 1;
    assert!(f.repo.open_travel_state(&b).is_err());

    // Truncated or extended.
    assert!(
        f.repo
            .open_travel_state(&sealed[..sealed.len() - 1])
            .is_err()
    );
    let mut b = sealed.clone();
    b.push(0);
    assert!(f.repo.open_travel_state(&b).is_err());

    // A length prefix pointing past the end.
    let mut b = sealed.clone();
    b[..4].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(f.repo.open_travel_state(&b).is_err());

    // Sealed by another account.
    let (_, n2) = accounts();
    let store = Shared::default();
    write_account(&store, n2);
    let other =
        Repository::unlock(store, PASSWORD, &n2.secret_key, DeviceState::default()).unwrap();
    let foreign = other.seal_travel_state(&state).unwrap();
    assert!(f.repo.open_travel_state(&foreign).is_err());
    assert!(other.open_travel_state(&sealed).is_err());
}

#[test]
fn unpinned_exit_restores_all_missing_vaults() {
    let mut f = fx();
    let before = snapshot(&mut f);
    mirror(&f.local, &f.upstream);
    let _state = f.repo.enter_travel(&f.upstream).unwrap();
    let restored = f.repo.exit_travel_unpinned(&f.upstream).unwrap();
    assert_eq!(restored, vec![f.perso.id]);
    assert_eq!(snapshot(&mut f), before);
    assert!(f.repo.device_state().last_seen.contains_key(&f.perso.id));
    // Nothing missing any more: a second call restores nothing.
    assert_eq!(f.repo.exit_travel_unpinned(&f.upstream).unwrap(), vec![]);
}

#[test]
fn unpinned_exit_still_verifies_records() {
    let mut f = fx();
    mirror(&f.local, &f.upstream);
    let _state = f.repo.enter_travel(&f.upstream).unwrap();
    let travel_records = f.local.all();
    let travel_device = f.repo.device_state().clone();
    let item = f
        .upstream
        .vault_records(f.perso.id)
        .into_iter()
        .find(|r| r.kind == RecordKind::Item)
        .unwrap();
    f.upstream
        .0
        .borrow_mut()
        .delete(RecordKind::Item, item.id)
        .unwrap();
    assert_eq!(
        integrity(f.repo.exit_travel_unpinned(&f.upstream)),
        IntegrityError::ManifestMissingItem
    );
    assert_eq!(f.local.all(), travel_records);
    assert_eq!(f.repo.device_state(), &travel_device);
}

#[test]
fn travel_safe_vaults_and_account_untouched() {
    let mut f = fx();
    mirror(&f.local, &f.upstream);
    let account: Vec<Record> = f
        .local
        .all()
        .into_iter()
        .filter(|r| matches!(r.kind, RecordKind::AccountParams | RecordKind::Keyset))
        .collect();
    assert_eq!(account.len(), 2);
    let voyage = f.local.vault_records(f.voyage.id);
    let voyage_seen = f.repo.device_state().last_seen[&f.voyage.id].clone();
    let upstream = f.upstream.all();

    let _state = f.repo.enter_travel(&f.upstream).unwrap();
    let account_after: Vec<Record> = f
        .local
        .all()
        .into_iter()
        .filter(|r| matches!(r.kind, RecordKind::AccountParams | RecordKind::Keyset))
        .collect();
    assert_eq!(account_after, account);
    assert_eq!(f.local.vault_records(f.voyage.id), voyage);
    assert_eq!(f.repo.device_state().last_seen[&f.voyage.id], voyage_seen);
    // The upstream is only read.
    assert_eq!(f.upstream.all(), upstream);
}

#[test]
fn exit_verifies_a_parked_vault_already_present_locally() {
    let mut f = fx();
    mirror(&f.local, &f.upstream);
    let old_perso = f.upstream.vault_records(f.perso.id);
    f.repo
        .save_item(&f.perso, login(f.perso.id, "perso 2"))
        .unwrap();
    mirror(&f.local, &f.upstream);
    let state = f.repo.enter_travel(&f.upstream).unwrap();

    // The local store gets an old authentic copy of "Perso" (a hostile
    // store, or an exit cut short): exit must not take it as restored.
    f.local.put_all(&old_perso);
    let records = f.local.all();
    let device = f.repo.device_state().clone();
    assert_eq!(
        integrity(f.repo.exit_travel(&f.upstream, &state)),
        IntegrityError::ManifestRollback
    );
    assert_eq!(f.repo.device_state(), &device);
    assert_eq!(f.local.all(), records);
}

#[test]
fn exit_after_an_interrupted_exit_succeeds() {
    let mut f = fx();
    let before = snapshot(&mut f);
    mirror(&f.local, &f.upstream);
    let state = f.repo.enter_travel(&f.upstream).unwrap();
    // A previous exit copied everything, then stopped before verifying.
    f.local.put_all(&f.upstream.vault_records(f.perso.id));
    f.repo.exit_travel(&f.upstream, &state).unwrap();
    assert!(f.repo.device_state().last_seen.contains_key(&f.perso.id));
    assert_eq!(snapshot(&mut f), before);
}

#[test]
fn exit_refuses_item_injected_by_upstream() {
    let mut f = fx();
    mirror(&f.local, &f.upstream);
    let state = f.repo.enter_travel(&f.upstream).unwrap();
    let travel_records = f.local.all();
    let travel_device = f.repo.device_state().clone();
    let mut extra = f
        .upstream
        .vault_records(f.perso.id)
        .into_iter()
        .find(|r| r.kind == RecordKind::Item)
        .unwrap();
    extra.id = Id::new();
    f.upstream.put_all(&[extra]);
    assert_eq!(
        integrity(f.repo.exit_travel(&f.upstream, &state)),
        IntegrityError::ManifestUnexpectedItem
    );
    assert_eq!(f.local.all(), travel_records);
    assert_eq!(f.repo.device_state(), &travel_device);
}

#[test]
fn unpinned_exit_refuses_a_foreign_vault() {
    let mut f = fx();
    mirror(&f.local, &f.upstream);
    let _state = f.repo.enter_travel(&f.upstream).unwrap();
    // A vault of another account, which this account cannot open.
    let (_, n2) = accounts();
    let store = Shared::default();
    write_account(&store, n2);
    let mut other = Repository::unlock(
        store.clone(),
        PASSWORD,
        &n2.secret_key,
        DeviceState::default(),
    )
    .unwrap();
    let foreign = other.create_vault(meta("Foreign", false)).unwrap();
    other
        .save_item(&foreign, login(foreign.id, "foreign"))
        .unwrap();
    f.upstream.put_all(&store.vault_records(foreign.id));

    let travel_records = f.local.all();
    let travel_device = f.repo.device_state().clone();
    assert!(f.repo.exit_travel_unpinned(&f.upstream).is_err());
    assert_eq!(f.local.all(), travel_records);
    assert_eq!(f.repo.device_state(), &travel_device);
    assert!(f.local.vault_records(foreign.id).is_empty());
    assert!(f.local.vault_records(f.perso.id).is_empty());
}

#[test]
fn unpinned_exit_refuses_a_manifest_that_does_not_verify() {
    let mut f = fx();
    mirror(&f.local, &f.upstream);
    let _state = f.repo.enter_travel(&f.upstream).unwrap();
    let mut m = f
        .upstream
        .get(RecordKind::Manifest, f.perso.id)
        .unwrap()
        .unwrap();
    let last = m.data.len() - 1;
    m.data[last] ^= 0x01;
    f.upstream.put_all(&[m]);
    let travel_records = f.local.all();
    let travel_device = f.repo.device_state().clone();
    assert!(f.repo.exit_travel_unpinned(&f.upstream).is_err());
    assert_eq!(f.local.all(), travel_records);
    assert_eq!(f.repo.device_state(), &travel_device);
    assert!(f.local.vault_records(f.perso.id).is_empty());
}
