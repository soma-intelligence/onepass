//! Travel Mode over the app's `SyncStore`: the hidden vaults leave the
//! device without a single deletion queued for the server, the sync does
//! not bring them back while travelling, and leaving verifies what the
//! server serves against the parked last manifest seen.

mod common;

use std::collections::BTreeSet;

use common::*;
use onepass_core::store::{MemoryStore, RecordKind, RecordStore};
use onepass_core::sync::SyncStore;
use onepass_core::{Id, IntegrityError};

/// The server copy of every `base` row of the device, as the Travel Mode
/// upstream.
fn base_upstream(dev: &Device) -> MemoryStore {
    let mut up = MemoryStore::new();
    for r in dev.store().export_records().unwrap() {
        up.put(r).unwrap();
    }
    up
}

/// Device A with a synced vault "Atlas" (not travel safe) holding one
/// login, and device B pulled and unlocked.
fn travelling_setup(server: &mut Server) -> (Device, Device, Id) {
    let (mut a, sk) = Device::create();
    let atlas = a.repo().create_vault(meta("Atlas")).unwrap();
    a.repo()
        .save_item(&atlas, login(atlas.id, "camille.durand@exemple.fr", T0))
        .unwrap();
    sync(server, &mut a).unwrap();
    let mut b = Device::empty();
    pull(server, &mut b);
    b.unlock(&sk);
    (a, b, atlas.id)
}

fn has_vault(dev: &Device, id: Id) -> bool {
    dev.store().get(RecordKind::VaultKey, id).unwrap().is_some()
}

#[test]
fn entering_queues_no_deletion_and_keeps_the_server_copy() {
    let mut server = Server::default();
    let (mut a, _b, atlas) = travelling_setup(&mut server);
    let up = base_upstream(&a);
    let state = a.repo().enter_travel(&up).unwrap();
    assert!(state.parked.contains_key(&atlas));
    assert!(a.store().pending_changes().unwrap().is_empty());
    assert!(!has_vault(&a, atlas));
    assert!(server.get(RecordKind::VaultKey, atlas).is_some());
    // Nothing to push: a sync leaves the server copy alone.
    a.store()
        .set_travel_hidden(&BTreeSet::from([atlas]))
        .unwrap();
    sync(&mut server, &mut a).unwrap();
    assert!(server.get(RecordKind::Manifest, atlas).is_some());
    assert!(a.repo().vaults().unwrap().iter().all(|v| v.id != atlas));
}

#[test]
fn hidden_vaults_stay_off_the_device_while_others_write() {
    let mut server = Server::default();
    let (mut a, mut b, atlas) = travelling_setup(&mut server);
    let up = base_upstream(&a);
    let state = a.repo().enter_travel(&up).unwrap();
    a.store()
        .set_travel_hidden(&BTreeSet::from([atlas]))
        .unwrap();

    let vault = b.vault_named("Atlas");
    b.repo()
        .save_item(&vault, login(atlas, "b@exemple.fr", T0 + 60))
        .unwrap();
    sync(&mut server, &mut b).unwrap();
    pull(&server, &mut a);
    full_fetch(&server, &mut a);
    assert!(!has_vault(&a, atlas));
    assert!(
        a.store()
            .export_records()
            .unwrap()
            .iter()
            .all(|r| r.id != atlas
                && (r.kind != RecordKind::Item || r.data.get(..16) != Some(&atlas.0[..])))
    );

    // Leaving: the filter goes, a fetch from scratch brings the vault back
    // with B's write, verified against the parked manifest.
    a.store().set_travel_hidden(&BTreeSet::new()).unwrap();
    full_fetch(&server, &mut a);
    a.repo().exit_travel(&MemoryStore::new(), &state).unwrap();
    let vault = a.vault_named("Atlas");
    assert_eq!(a.repo().items(&vault).unwrap().len(), 2);
    assert!(a.store().pending_changes().unwrap().is_empty());
}

#[test]
fn a_replayed_manifest_is_refused_on_exit_and_evicted_again() {
    let mut server = Server::default();
    let (mut a, _b, atlas) = travelling_setup(&mut server);
    let old_manifest = server.get(RecordKind::Manifest, atlas).unwrap();
    // A second write on A moves the manifest past the old one.
    let vault = a.vault_named("Atlas");
    a.repo()
        .save_item(&vault, login(atlas, "deux@exemple.fr", T0 + 120))
        .unwrap();
    sync(&mut server, &mut a).unwrap();
    let up = base_upstream(&a);
    let state = a.repo().enter_travel(&up).unwrap();
    a.store()
        .set_travel_hidden(&BTreeSet::from([atlas]))
        .unwrap();

    server.replay(old_manifest);
    a.store().set_travel_hidden(&BTreeSet::new()).unwrap();
    full_fetch(&server, &mut a);
    let err = integrity(a.repo().exit_travel(&MemoryStore::new(), &state));
    assert_eq!(err, IntegrityError::ManifestRollback);

    // The app takes the refused copy off the device again: nothing queued.
    let rows: Vec<_> = a
        .store()
        .export_records()
        .unwrap()
        .into_iter()
        .filter(|r| {
            r.id == atlas || (r.kind == RecordKind::Item && r.data.get(..16) == Some(&atlas.0[..]))
        })
        .collect();
    let mut store: SyncStore = a.store();
    store.evict_all(&rows).unwrap();
    assert!(!has_vault(&a, atlas));
    assert!(a.store().pending_changes().unwrap().is_empty());
}

#[test]
fn evict_drops_every_layer_and_refuses_lists() {
    let mut server = Server::default();
    let (a, _b, atlas) = travelling_setup(&mut server);
    let mut store = a.store();
    store.evict(RecordKind::VaultMeta, atlas).unwrap();
    assert!(store.get(RecordKind::VaultMeta, atlas).unwrap().is_none());
    assert!(store.pending_changes().unwrap().is_empty());
    assert!(store.evict(RecordKind::VaultList, atlas).is_err());
}

#[test]
fn hidden_set_roundtrips_and_clears() {
    let dev = Device::empty();
    let mut store = dev.store();
    assert!(store.travel_hidden().unwrap().is_empty());
    let set = BTreeSet::from([Id::new(), Id::new()]);
    store.set_travel_hidden(&set).unwrap();
    assert_eq!(store.travel_hidden().unwrap(), set);
    store.set_travel_hidden(&BTreeSet::new()).unwrap();
    assert!(store.travel_hidden().unwrap().is_empty());
}

/// Device A with a synced travel safe vault "Voyage" holding a plain login
/// and one marked hidden in travel, and device B pulled and unlocked.
/// Returns the vault id and the hidden item id.
fn hidden_item_setup(server: &mut Server) -> (Device, Device, Id, Id) {
    let (mut a, sk) = Device::create();
    let mut m = meta("Voyage");
    m.travel_safe = true;
    let voyage = a.repo().create_vault(m).unwrap();
    a.repo()
        .save_item(&voyage, login(voyage.id, "plain@exemple.fr", T0))
        .unwrap();
    let mut secret = login(voyage.id, "secret@exemple.fr", T0);
    secret.set_travel_hidden(true);
    let secret_id = secret.id;
    a.repo().save_item(&voyage, secret).unwrap();
    sync(server, &mut a).unwrap();
    let mut b = Device::empty();
    pull(server, &mut b);
    b.unlock(&sk);
    (a, b, voyage.id, secret_id)
}

fn holds_item(dev: &Device, vault: Id, item: Id) -> bool {
    dev.store()
        .export_records()
        .unwrap()
        .iter()
        .filter(|r| r.kind == RecordKind::Item)
        .any(|r| {
            let (prefix, body) = onepass_core::repo::split_item_record(&r.data).unwrap();
            prefix == vault
                && onepass_core::vault::ItemRecord::decode(body)
                    .unwrap()
                    .item_id
                    == item
        })
}

#[test]
fn hidden_items_set_roundtrips_and_clears() {
    let dev = Device::empty();
    let mut store = dev.store();
    assert!(store.travel_hidden_items().unwrap().is_empty());
    let set = onepass_core::sync::TravelHiddenItems {
        items: BTreeSet::from([Id::new()]),
        chunks: BTreeSet::from([Id::new(), Id::new()]),
    };
    store.set_travel_hidden_items(&set).unwrap();
    assert_eq!(store.travel_hidden_items().unwrap(), set);
    store.set_travel_hidden_items(&Default::default()).unwrap();
    assert!(store.travel_hidden_items().unwrap().is_empty());
}

#[test]
fn a_hidden_item_stays_off_the_device_while_another_device_edits_it() {
    let mut server = Server::default();
    let (mut a, mut b, voyage, secret) = hidden_item_setup(&mut server);
    let up = base_upstream(&a);
    let state = a.repo().enter_travel(&up).unwrap();
    assert!(state.parked_items[&voyage].contains(&secret));
    a.store()
        .set_travel_hidden_items(&onepass_core::sync::TravelHiddenItems {
            items: BTreeSet::from([secret]),
            chunks: BTreeSet::new(),
        })
        .unwrap();
    assert!(!holds_item(&a, voyage, secret));
    assert!(a.store().pending_changes().unwrap().is_empty());

    // B edits the hidden item; A syncs: the new version does not land.
    let vault = b.vault_named("Voyage");
    let item = b
        .repo()
        .items(&vault)
        .unwrap()
        .into_iter()
        .find(|i| i.id == secret)
        .unwrap();
    b.repo()
        .save_item(&vault, edited(&item, "edited@exemple.fr", T0 + 60))
        .unwrap();
    sync(&mut server, &mut b).unwrap();
    pull(&server, &mut a);
    full_fetch(&server, &mut a);
    assert!(!holds_item(&a, voyage, secret));
    let vault = a.vault_named("Voyage");
    assert_eq!(a.repo().items(&vault).unwrap().len(), 1);

    // Leaving: the filter goes, a fetch from scratch brings B's version,
    // verified against the manifest this device pinned.
    a.store()
        .set_travel_hidden_items(&Default::default())
        .unwrap();
    full_fetch(&server, &mut a);
    a.repo().exit_travel(&MemoryStore::new(), &state).unwrap();
    let items = a.repo().items(&vault).unwrap();
    assert_eq!(items.len(), 2);
    let back = items.iter().find(|i| i.id == secret).unwrap();
    assert_eq!(
        back.field("username").unwrap().value,
        onepass_core::model::FieldValue::Text("edited@exemple.fr".into())
    );
    assert!(a.store().pending_changes().unwrap().is_empty());
}
