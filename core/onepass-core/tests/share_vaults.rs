//! Shared vaults on the repository (sharing plan 2, Tasks 6 and 7).

mod common;
mod share_common;

use common::*;
use onepass_core::share::{
    AccessTarget, MemberKey, Role, ShareAction, SignedMembership, ZoneMailboxKind, open_member_key,
};
use onepass_core::store::{MemoryStore, Zone};
use share_common::*;

const NOW: i64 = 1_800_000_000;

/// A device with "Personnel" and "Famille", three items in "Famille" (one
/// archived, one trashed).
fn with_family() -> (Device, SecretKey, Vault, Vec<Item>) {
    let (mut a, sk) = Device::create();
    let fam = a.repo().create_vault(meta("Famille")).unwrap();
    let items: Vec<Item> = ["alice", "bob", "carol"]
        .iter()
        .enumerate()
        .map(|(i, u)| login(fam.id, u, 100 + i as i64))
        .collect();
    for i in &items {
        a.repo().save_item(&fam, i.clone()).unwrap();
    }
    a.repo().archive_item(&fam, items[1].id).unwrap();
    a.repo().trash_item(&fam, items[2].id).unwrap();
    (a, sk, fam, items)
}

/// The shared vault of `zone` opened by hand from the zone's records.
fn open_zone(a: &mut Device, vault_id: Id) -> (Vault, Vec<Item>, Vec<u64>) {
    let zone = Zone::Vault(vault_id);
    let st = a.store();
    let m = st
        .get_in(zone, RecordKind::Membership, vault_id)
        .unwrap()
        .unwrap();
    let body = SignedMembership::decode(&m.data).unwrap().body;
    let mk = st.list_in(zone, RecordKind::MemberKey).unwrap();
    assert_eq!(mk.len(), 1);
    let mk = MemberKey::decode(&mk[0].data).unwrap();
    assert_eq!(mk.generation, 1);
    let key = open_member_key(a.repo().account().keyset(), &mk, &body.key_commit).unwrap();
    let meta_blob = st
        .get_in(zone, RecordKind::VaultMeta, vault_id)
        .unwrap()
        .unwrap()
        .data;
    let v = Vault::from_shared(vault_id, key, &meta_blob).unwrap();
    let mut items = Vec::new();
    let mut versions = Vec::new();
    for r in st.list_in(zone, RecordKind::Item).unwrap() {
        let (prefix, body) = split_item_record(&r.data).unwrap();
        assert_eq!(prefix, vault_id);
        let rec: ItemRecord = postcard::from_bytes(body).unwrap();
        versions.push(rec.version);
        items.push(v.open_item(&rec).unwrap());
    }
    (v, items, versions)
}

#[test]
fn share_keeps_items_and_id() {
    let (mut a, _, fam, items) = with_family();
    let info = a.repo().share_vault(&fam, NOW).unwrap();
    assert_eq!(info.vault_id, fam.id);
    assert_eq!(info.name, "Famille");
    assert_eq!(
        (info.role, info.owner, info.generation),
        (Role::Manage, true, 1)
    );
    assert_eq!(info.members.len(), 1);
    let (v, mut got, versions) = open_zone(&mut a, fam.id);
    assert_eq!(v.id, fam.id);
    got.sort_by_key(|i| i.id);
    let mut want: Vec<Id> = items.iter().map(|i| i.id).collect();
    want.sort();
    assert_eq!(got.iter().map(|i| i.id).collect::<Vec<_>>(), want);
    assert!(got.iter().any(|i| i.archived));
    assert!(got.iter().any(|i| i.trashed_at.is_some()));
    assert!(versions.iter().all(|v| *v >= 2));
    // Nothing of the vault is left in the private zone.
    let st = a.store();
    assert!(st.get(RecordKind::VaultKey, fam.id).unwrap().is_none());
    assert!(st.get(RecordKind::Manifest, fam.id).unwrap().is_none());
    assert!(
        st.list(RecordKind::Item)
            .unwrap()
            .iter()
            .all(|r| split_item_record(&r.data).unwrap().0 != fam.id)
    );
    // The personal vault is still there, the shared one gone from it.
    let names: Vec<String> = a
        .repo()
        .vaults()
        .unwrap()
        .into_iter()
        .filter(|v| !v.zone().is_shared())
        .map(|v| v.meta.name)
        .collect();
    assert_eq!(names, vec!["Personnel".to_string()]);
}

#[test]
fn share_is_one_transaction() {
    let (mut a, _, fam, items) = with_family();
    // A membership row already in the zone: the conditional write fails.
    let mut st = a.store();
    st.put_all_zoned(
        vec![(
            Zone::Vault(fam.id),
            Record {
                kind: RecordKind::Membership,
                id: fam.id,
                version: 1,
                data: vec![1],
            },
            None,
        )],
        vec![],
        None,
        &[],
    )
    .unwrap();
    assert!(a.repo().share_vault(&fam, NOW).is_err());
    let v = a.vault_named("Famille");
    let mut got: Vec<Id> = a.repo().items(&v).unwrap().iter().map(|i| i.id).collect();
    got.sort();
    let mut want: Vec<Id> = items.iter().map(|i| i.id).collect();
    want.sort();
    assert_eq!(got, want);
    assert!(a.store().share_state(fam.id).unwrap().is_none());
    assert!(a.repo().zone_accesses().unwrap().is_empty());
}

#[test]
fn share_queues_create_zone() {
    let (mut a, _, fam, _) = with_family();
    a.repo().share_vault(&fam, NOW).unwrap();
    let zone = Zone::Vault(fam.id);
    let actions = a.repo().pending_share_actions().unwrap();
    let (_, seed) = a
        .repo()
        .zone_access(AccessTarget::Zone(zone))
        .unwrap()
        .unwrap();
    assert_eq!(
        actions,
        vec![ShareAction::CreateZoneMailbox {
            zone,
            kind: ZoneMailboxKind::Shared,
            owner_public_key: seed.public_key(),
        }]
    );
    a.repo().share_action_done(&actions[0]).unwrap();
    assert!(a.repo().pending_share_actions().unwrap().is_empty());
}

#[test]
fn actions_carry_no_seed() {
    let (mut a, _, fam, _) = with_family();
    a.repo().share_vault(&fam, NOW).unwrap();
    let (_, seed) = a
        .repo()
        .zone_access(AccessTarget::Zone(Zone::Vault(fam.id)))
        .unwrap()
        .unwrap();
    for act in a.repo().pending_share_actions().unwrap() {
        let bytes = postcard::to_allocvec(&act).unwrap();
        assert!(!bytes.windows(32).any(|w| w == seed.expose()));
    }
    let state = a.store().share_state(fam.id).unwrap().unwrap();
    assert!(!state.encode().windows(32).any(|w| w == seed.expose()));
}

#[test]
fn share_refused_in_travel_mode() {
    let (mut a, _, fam, _) = with_family();
    let mut up = MemoryStore::new();
    for kind in [
        RecordKind::AccountParams,
        RecordKind::Keyset,
        RecordKind::VaultKey,
        RecordKind::VaultMeta,
        RecordKind::Item,
        RecordKind::Manifest,
        RecordKind::DeviceList,
        RecordKind::VaultList,
    ] {
        for r in a.repo().store().list(kind).unwrap() {
            up.put(r).unwrap();
        }
    }
    let mut voyage = meta("Voyage");
    voyage.travel_safe = true;
    a.repo().create_vault(voyage).unwrap();
    a.repo().enter_travel(&up).unwrap();
    let r = a.repo().share_vault(&fam, NOW);
    assert!(matches!(r, Err(Error::Validation(_))), "{r:?}");
}

#[test]
fn last_personal_vault_cannot_be_shared() {
    let (mut a, _) = Device::create();
    let v = a.vault();
    let r = a.repo().share_vault(&v, NOW);
    assert!(
        matches!(r, Err(Error::InvalidFormat("last vault"))),
        "{r:?}"
    );
}

/// A and B, two devices of one account; "Famille" shared on A, synced.
fn two_devices_shared() -> (Server, Zones, Device, Device, Id, Vec<Item>) {
    let mut server = Server::default();
    let mut zs = Zones::default();
    let (mut a, sk, fam, items) = with_family();
    sync(&mut server, &mut a).unwrap();
    let mut b = Device::empty();
    pull(&server, &mut b);
    b.unlock(&sk);
    a.repo().share_vault(&fam, NOW).unwrap();
    zsettle(&mut server, &mut zs, &mut [&mut a, &mut b]);
    (server, zs, a, b, fam.id, items)
}

fn shared(dev: &mut Device, id: Id) -> Vault {
    dev.repo().shared_vaults().unwrap();
    dev.repo()
        .vaults()
        .unwrap()
        .into_iter()
        .find(|v| v.id == id)
        .expect("shared vault listed")
}

fn ids(items: &[Item]) -> Vec<Id> {
    let mut v: Vec<Id> = items.iter().map(|i| i.id).collect();
    v.sort();
    v
}

#[test]
fn second_device_reads_and_writes_shared() {
    let (mut server, mut zs, mut a, mut b, id, items) = two_devices_shared();
    let infos = b.repo().shared_vaults().unwrap();
    assert_eq!(infos.len(), 1);
    assert_eq!(infos[0].name, "Famille");
    let vb = shared(&mut b, id);
    assert_eq!(vb.zone(), Zone::Vault(id));
    let got = b.repo().items(&vb).unwrap();
    assert_eq!(ids(&got), ids(&items));
    // B writes, A reads.
    let new = login(id, "dave", 500);
    b.repo().save_item(&vb, new.clone()).unwrap();
    zsettle(&mut server, &mut zs, &mut [&mut b, &mut a]);
    let va = shared(&mut a, id);
    let got = a.repo().items(&va).unwrap();
    assert!(got.iter().any(|i| i.id == new.id));
    // A trashes and deletes, B follows.
    a.repo().trash_item(&va, new.id).unwrap();
    a.repo().delete_item(&va, items[0].id).unwrap();
    zsettle(&mut server, &mut zs, &mut [&mut a, &mut b]);
    let got = b.repo().items(&vb).unwrap();
    assert!(got.iter().all(|i| i.id != items[0].id));
    assert!(
        got.iter()
            .find(|i| i.id == new.id)
            .unwrap()
            .trashed_at
            .is_some()
    );
}

#[test]
fn manager_rename_ok() {
    let (mut server, mut zs, mut a, mut b, id, _) = two_devices_shared();
    let va = shared(&mut a, id);
    let mut m = va.meta.clone();
    m.name = "Maison".into();
    a.repo().update_vault_meta(&va, m).unwrap();
    zsettle(&mut server, &mut zs, &mut [&mut a, &mut b]);
    let vb = shared(&mut b, id);
    assert_eq!(vb.meta.name, "Maison");
    b.repo().items(&vb).unwrap();
}

#[test]
fn move_between_personal_and_shared() {
    let (mut server, mut zs, mut a, mut b, id, items) = two_devices_shared();
    let va = shared(&mut a, id);
    let personal = a.vault_named("Personnel");
    a.repo().move_item(items[0].id, &va, &personal).unwrap();
    assert!(
        a.repo()
            .items(&personal)
            .unwrap()
            .iter()
            .any(|i| i.id == items[0].id)
    );
    assert!(
        a.repo()
            .items(&va)
            .unwrap()
            .iter()
            .all(|i| i.id != items[0].id)
    );
    a.repo().move_item(items[0].id, &personal, &va).unwrap();
    zsettle(&mut server, &mut zs, &mut [&mut a, &mut b]);
    let vb = shared(&mut b, id);
    assert!(
        b.repo()
            .items(&vb)
            .unwrap()
            .iter()
            .any(|i| i.id == items[0].id)
    );
}

#[test]
fn mcp_hidden_locally() {
    let (_server, _zs, mut a, _b, id, _) = two_devices_shared();
    let va = shared(&mut a, id);
    let mut m = va.meta.clone();
    m.mcp_access = true;
    let va = a.repo().update_vault_meta(&va, m).unwrap();
    assert!(a.repo().mcp_visible(&va).unwrap());
    a.repo().set_shared_vault_mcp_hidden(id, true).unwrap();
    assert!(!a.repo().mcp_visible(&va).unwrap());
    assert!(a.repo().shared_vaults().unwrap()[0].mcp_hidden);
}

#[test]
fn personal_vaults_exclude_shared() {
    let (_server, _zs, mut a, _b, id, _) = two_devices_shared();
    assert!(
        a.repo()
            .personal_vaults()
            .unwrap()
            .iter()
            .all(|v| v.id != id)
    );
    assert!(a.repo().vaults().unwrap().iter().any(|v| v.id == id));
}
