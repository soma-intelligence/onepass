//! Travel Mode per item (spec 2026-11-02 travel detection and items): an
//! item marked `travel_hidden` in a vault that stays leaves the device like
//! a vault that leaves (its records evicted, its manifest entry kept and
//! pinned) and comes back only through the core's verification.

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::rc::Rc;
use std::sync::OnceLock;

use onepass_core::account::{Account, NewAccount};
use onepass_core::crypto::{KdfParams, random_array};
use onepass_core::model::{
    FieldValue, Item, ItemType, TRAVEL_GUARD_TAG, TRAVEL_HIDDEN_TAG, new_item,
};
use onepass_core::repo::travel::TravelState;
use onepass_core::repo::{DeviceState, Repository, split_item_record};
use onepass_core::store::{MemoryStore, Record, RecordKind, RecordStore};
use onepass_core::vault::{ItemRecord, Vault, VaultMeta};
use onepass_core::{Error, Id, IntegrityError, Result};

const PASSWORD: &str = "travel items pw";

fn kdf() -> KdfParams {
    KdfParams {
        m_kib: 8192,
        t: 1,
        p: 1,
        salt: random_array().unwrap(),
    }
}

fn account() -> &'static NewAccount {
    static A: OnceLock<NewAccount> = OnceLock::new();
    A.get_or_init(|| Account::create_with_params(PASSWORD, kdf()).unwrap())
}

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

const KINDS: [RecordKind; 7] = [
    RecordKind::AccountParams,
    RecordKind::Keyset,
    RecordKind::VaultKey,
    RecordKind::VaultMeta,
    RecordKind::Item,
    RecordKind::Manifest,
    RecordKind::Attachment,
];

impl Shared {
    fn all(&self) -> Vec<Record> {
        let mut out = Vec::new();
        for kind in KINDS {
            let mut l = self.list(kind).unwrap();
            l.sort_by_key(|r| r.id);
            out.extend(l);
        }
        out
    }

    fn put_all(&self, records: &[Record]) {
        for r in records {
            self.0.borrow_mut().put(r.clone()).unwrap();
        }
    }

    /// The item records whose body names `item_id`.
    fn item_records(&self, item_id: Id) -> Vec<Record> {
        self.list(RecordKind::Item)
            .unwrap()
            .into_iter()
            .filter(|r| {
                let (_, body) = split_item_record(&r.data).unwrap();
                ItemRecord::decode(body).unwrap().item_id == item_id
            })
            .collect()
    }

    fn chunks(&self) -> Vec<Record> {
        self.list(RecordKind::Attachment).unwrap()
    }
}

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

fn login(vault: Id, title: &str) -> Item {
    let mut item = new_item(ItemType::Login, vault, title);
    item.field_mut("username").unwrap().value = FieldValue::Text(title.into());
    item
}

struct Fx {
    repo: Repository<Shared>,
    local: Shared,
    upstream: Shared,
    voyage: Vault,
    /// A plain item of the travel safe vault.
    kept: Id,
    /// The item of the travel safe vault marked hidden.
    secret: Id,
}

/// "Voyage" (travel safe) holds "Kept" and "Secret" (hidden in travel);
/// there is no other vault, so only the item leaves.
fn fx() -> Fx {
    let n = account();
    let local = Shared::default();
    let id = n.account.params.account_id;
    for (kind, data) in [
        (RecordKind::AccountParams, &n.params_record),
        (RecordKind::Keyset, &n.keyset_record),
    ] {
        local
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
    let mut repo =
        Repository::unlock(local.clone(), PASSWORD, &n.secret_key, DeviceState::default())
            .unwrap();
    let voyage = repo.create_vault(meta("Voyage", true)).unwrap();
    let kept = login(voyage.id, "Kept");
    let mut secret = login(voyage.id, "Secret");
    secret.set_travel_hidden(true);
    let (kept_id, secret_id) = (kept.id, secret.id);
    repo.save_item(&voyage, kept).unwrap();
    repo.save_item(&voyage, secret).unwrap();
    Fx {
        repo,
        local,
        upstream: Shared::default(),
        voyage,
        kept: kept_id,
        secret: secret_id,
    }
}

fn titles(f: &mut Fx) -> Vec<String> {
    let mut t: Vec<String> = f
        .repo
        .items(&f.voyage)
        .unwrap()
        .into_iter()
        .map(|i| i.title)
        .collect();
    t.sort();
    t
}

fn parked_items(state: &TravelState, vault: Id) -> BTreeSet<Id> {
    state.parked_items.get(&vault).cloned().unwrap_or_default()
}

#[test]
fn tags_read_and_set_once() {
    let mut item = login(Id::new(), "x");
    assert!(!item.travel_hidden() && !item.travel_guarded());
    item.set_travel_hidden(true);
    item.set_travel_hidden(true);
    item.set_travel_guarded(true);
    assert!(item.travel_hidden() && item.travel_guarded());
    assert_eq!(
        item.tags
            .iter()
            .filter(|t| *t == TRAVEL_HIDDEN_TAG || *t == TRAVEL_GUARD_TAG)
            .count(),
        2
    );
    item.set_travel_hidden(false);
    assert!(!item.travel_hidden() && item.travel_guarded());
}

#[test]
fn hidden_item_leaves_local_storage_and_comes_back_intact() {
    let mut f = fx();
    let before = f.repo.items(&f.voyage).unwrap();
    let manifest_before = f.local.get(RecordKind::Manifest, f.voyage.id).unwrap();
    mirror(&f.local, &f.upstream);

    let state = f.repo.enter_travel(&f.upstream).unwrap();
    assert!(state.parked.is_empty());
    assert_eq!(parked_items(&state, f.voyage.id), BTreeSet::from([f.secret]));
    assert!(f.repo.travelling());
    // Really gone from the store, not filtered.
    assert!(f.local.item_records(f.secret).is_empty());
    assert_eq!(f.local.item_records(f.kept).len(), 1);
    // The manifest is untouched and still pinned.
    assert_eq!(
        f.local.get(RecordKind::Manifest, f.voyage.id).unwrap(),
        manifest_before
    );
    assert_eq!(titles(&mut f), vec!["Kept".to_string()]);

    f.repo.exit_travel(&f.upstream, &state).unwrap();
    assert!(!f.repo.travelling());
    assert_eq!(f.repo.items(&f.voyage).unwrap(), before);
}

#[test]
fn entry_refused_without_the_item_upstream_and_nothing_deleted() {
    let mut f = fx();
    mirror(&f.local, &f.upstream);
    for r in f.upstream.item_records(f.secret) {
        f.upstream.0.borrow_mut().delete(r.kind, r.id).unwrap();
    }
    let records = f.local.all();
    let device = f.repo.device_state().clone();
    assert!(f.repo.enter_travel(&f.upstream).is_err());
    assert_eq!(f.local.all(), records);
    assert_eq!(f.repo.device_state(), &device);
    assert!(!f.repo.travelling());
}

#[test]
fn writes_during_travel_keep_the_hidden_entry() {
    let mut f = fx();
    mirror(&f.local, &f.upstream);
    let state = f.repo.enter_travel(&f.upstream).unwrap();

    // Edit and add other items: each new manifest still lists the secret.
    let mut kept = f
        .repo
        .items(&f.voyage)
        .unwrap()
        .into_iter()
        .find(|i| i.id == f.kept)
        .unwrap();
    kept.notes = "edited abroad".into();
    f.repo.save_item(&f.voyage, kept).unwrap();
    f.repo
        .save_item(&f.voyage, login(f.voyage.id, "New"))
        .unwrap();
    assert_eq!(titles(&mut f), vec!["Kept".to_string(), "New".to_string()]);

    // The upstream gets this device's writes (a push), then the item
    // comes back next to them.
    mirror(&f.local, &f.upstream);
    f.repo.exit_travel(&f.upstream, &state).unwrap();
    assert_eq!(
        titles(&mut f),
        vec!["Kept".to_string(), "New".to_string(), "Secret".to_string()]
    );
}

#[test]
fn a_parked_item_cannot_be_written_deleted_or_moved() {
    let mut f = fx();
    let other = f.repo.create_vault(meta("Other", true)).unwrap();
    let secret = f
        .repo
        .items(&f.voyage)
        .unwrap()
        .into_iter()
        .find(|i| i.id == f.secret)
        .unwrap();
    mirror(&f.local, &f.upstream);
    f.repo.enter_travel(&f.upstream).unwrap();
    let records = f.local.all();

    assert_eq!(
        f.repo.save_item(&f.voyage, secret.clone()),
        Err(Error::NotFound)
    );
    assert_eq!(f.repo.delete_item(&f.voyage, f.secret), Err(Error::NotFound));
    assert_eq!(
        f.repo.move_item(f.secret, &f.voyage, &other),
        Err(Error::NotFound)
    );
    assert_eq!(f.local.all(), records);
}

#[test]
fn exit_refuses_an_upstream_item_with_other_content_and_stays_parked() {
    let mut f = fx();
    mirror(&f.local, &f.upstream);
    let state = f.repo.enter_travel(&f.upstream).unwrap();
    let mut r = f.upstream.item_records(f.secret).pop().unwrap();
    let last = r.data.len() - 1;
    r.data[last] ^= 0x01;
    f.upstream.put_all(&[r]);
    let records = f.local.all();

    assert!(matches!(
        f.repo.exit_travel(&f.upstream, &state),
        Err(Error::Integrity(_))
    ));
    assert_eq!(f.local.all(), records);
    assert!(f.repo.travelling());
    // Still usable: the vault reads without the item.
    assert_eq!(titles(&mut f), vec!["Kept".to_string()]);
}

#[test]
fn exit_refuses_when_the_upstream_dropped_the_item() {
    let mut f = fx();
    mirror(&f.local, &f.upstream);
    let state = f.repo.enter_travel(&f.upstream).unwrap();
    for r in f.upstream.item_records(f.secret) {
        f.upstream.0.borrow_mut().delete(r.kind, r.id).unwrap();
    }
    let err = f.repo.exit_travel(&f.upstream, &state).unwrap_err();
    assert_eq!(
        err,
        Error::Integrity(IntegrityError::ManifestMissingItem)
    );
    assert!(f.repo.travelling());
}

#[test]
fn an_item_deleted_by_another_device_is_forgotten_on_exit() {
    let mut f = fx();
    mirror(&f.local, &f.upstream);
    let state = f.repo.enter_travel(&f.upstream).unwrap();

    // Another device (same account, the upstream as its store) deletes it.
    let n = account();
    let mut other = Repository::unlock(
        f.upstream.clone(),
        PASSWORD,
        &n.secret_key,
        DeviceState::default(),
    )
    .unwrap();
    let voyage = other.vaults().unwrap().pop().unwrap();
    other.delete_item(&voyage, f.secret).unwrap();
    drop(other);
    // This device syncs the new manifest (the item records stay dropped).
    let m = f.upstream.get(RecordKind::Manifest, f.voyage.id).unwrap().unwrap();
    f.local.put_all(&[m]);

    f.repo.exit_travel(&f.upstream, &state).unwrap();
    assert_eq!(titles(&mut f), vec!["Kept".to_string()]);
    assert!(!f.repo.travelling());
}

#[test]
fn resumed_session_reads_the_vault_without_the_item() {
    let mut f = fx();
    mirror(&f.local, &f.upstream);
    let state = f.repo.enter_travel(&f.upstream).unwrap();
    let sealed = f.repo.seal_travel_state(&state).unwrap();
    let device = f.repo.device_state().clone();
    let n = account();
    let mut again =
        Repository::unlock(f.local.clone(), PASSWORD, &n.secret_key, device).unwrap();
    let vault = again.vaults().unwrap().pop().unwrap();
    // Without the state, the missing record is an integrity error.
    assert!(again.items(&vault).is_err());
    let opened = again.open_travel_state(&sealed).unwrap();
    assert_eq!(opened, state);
    again.resume_travel(&opened);
    assert!(again.travelling());
    assert_eq!(again.items(&vault).unwrap().len(), 1);
}

#[test]
fn attachments_of_a_hidden_item_leave_and_come_back() {
    let mut f = fx();
    f.repo
        .add_attachment(&f.voyage, f.secret, "scan.pdf", "application/pdf", b"passport scan")
        .unwrap();
    assert_eq!(f.local.chunks().len(), 1);
    mirror(&f.local, &f.upstream);
    let state = f.repo.enter_travel(&f.upstream).unwrap();
    assert!(f.local.chunks().is_empty());

    f.repo.exit_travel(&f.upstream, &state).unwrap();
    let item = f
        .repo
        .items(&f.voyage)
        .unwrap()
        .into_iter()
        .find(|i| i.id == f.secret)
        .unwrap();
    let bytes = f
        .repo
        .read_attachment(&f.voyage, f.secret, item.attachments[0].id)
        .unwrap();
    assert_eq!(&bytes[..], b"passport scan");
}

#[test]
fn entry_refused_when_the_upstream_lacks_a_chunk() {
    let mut f = fx();
    f.repo
        .add_attachment(&f.voyage, f.secret, "scan.pdf", "application/pdf", b"passport scan")
        .unwrap();
    mirror(&f.local, &f.upstream);
    for c in f.upstream.chunks() {
        f.upstream.0.borrow_mut().delete(c.kind, c.id).unwrap();
    }
    let records = f.local.all();
    assert!(f.repo.enter_travel(&f.upstream).is_err());
    assert_eq!(f.local.all(), records);
}

#[test]
fn a_hidden_item_in_a_leaving_vault_leaves_with_its_vault() {
    let mut f = fx();
    let perso = f.repo.create_vault(meta("Perso", false)).unwrap();
    let mut item = login(perso.id, "Bank");
    item.set_travel_hidden(true);
    f.repo.save_item(&perso, item).unwrap();
    mirror(&f.local, &f.upstream);
    let state = f.repo.enter_travel(&f.upstream).unwrap();
    assert!(state.parked.contains_key(&perso.id));
    assert!(!state.parked_items.contains_key(&perso.id));
    f.repo.exit_travel(&f.upstream, &state).unwrap();
    assert_eq!(f.repo.items(&perso).unwrap().len(), 1);
}

#[test]
fn guard_only_entry_is_allowed_and_travelling() {
    let mut f = fx();
    // Nothing hidden any more, one guarded item.
    let mut secret = f
        .repo
        .items(&f.voyage)
        .unwrap()
        .into_iter()
        .find(|i| i.id == f.secret)
        .unwrap();
    secret.set_travel_hidden(false);
    secret.set_travel_guarded(true);
    f.repo.save_item(&f.voyage, secret).unwrap();
    mirror(&f.local, &f.upstream);
    let state = f.repo.enter_travel(&f.upstream).unwrap();
    assert!(state.parked.is_empty() && state.parked_items.is_empty());
    assert!(f.repo.travelling());
    assert_eq!(titles(&mut f).len(), 2);
    f.repo.exit_travel(&f.upstream, &state).unwrap();
    assert!(!f.repo.travelling());
}

#[test]
fn entry_refused_when_nothing_leaves_or_is_guarded() {
    let mut f = fx();
    let mut secret = f
        .repo
        .items(&f.voyage)
        .unwrap()
        .into_iter()
        .find(|i| i.id == f.secret)
        .unwrap();
    secret.set_travel_hidden(false);
    f.repo.save_item(&f.voyage, secret).unwrap();
    mirror(&f.local, &f.upstream);
    assert_eq!(
        f.repo.enter_travel(&f.upstream),
        Err(Error::InvalidFormat("nothing leaves"))
    );
    assert!(!f.repo.travelling());
}

#[test]
fn a_schema_one_state_still_opens() {
    // A state sealed before parked items existed: postcard of
    // `(parked, entered_at)` only. Built through the v1 sealing helper.
    let f = fx();
    let v1 = TravelState {
        parked: Default::default(),
        entered_at: 1_700_000_000,
        parked_items: Default::default(),
    };
    let sealed = f.repo.seal_travel_state_v1_for_tests(&v1).unwrap();
    assert_eq!(f.repo.open_travel_state(&sealed).unwrap(), v1);
}
