//! Shared vaults on the repository (sharing plan 2, Tasks 6 to 10).

mod common;
mod share_accts;
mod share_common;

use common::*;
use onepass_core::contact::{ContactLevel, ContactState, pair_id};
use onepass_core::lineage::rotation_code;
use onepass_core::repo::members::AdoptionProof;
use onepass_core::repo::rekey::AccessRefusal;
use onepass_core::share::{
    AccessTarget, InviteRecord, MemberLineageRecord, MemberRef, MembershipReason, RekeyReason,
    RekeyRequest, Role, ShareAction, SignedMembership, ZONE_ACCESS_KIND, ZoneMailboxKind, ZoneRole,
    ZoneSeed, member_key_id, open_zone_credential, server_role, sign_membership,
};
use onepass_core::store::{MemoryStore, RecordStore, Zone};
use onepass_core::sync::PhaseOutcome;
use share_accts::settle;
use share_accts::*;
use share_common::*;

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

// ---- Task 8: members, invites, acceptance ----

#[test]
fn add_then_accept_then_read() {
    let (mut zs, mut a, mut b, id, items) = alice_and_bob(ContactLevel::Verified);
    let bob = account_id(&mut b.dev);
    let info = a
        .dev
        .repo()
        .add_member(id, bob, Role::Write, NOW + 1)
        .unwrap();
    assert_eq!(info.members.len(), 2);
    settle(&mut zs, &mut [&mut a, &mut b]);
    let invites = b.dev.repo().share_invites().unwrap();
    assert_eq!(invites.len(), 1);
    assert_eq!(invites[0].role, Role::Write);
    assert_eq!(invites[0].server_host, "box1.example.org");
    // Alice does not see her own invite as one for her.
    assert!(a.dev.repo().share_invites().unwrap().is_empty());
    let joined = b
        .dev
        .repo()
        .accept_share_invite(invites[0].id, NOW + 2)
        .unwrap();
    assert_eq!(joined.role, Role::Write);
    assert!(b.dev.repo().share_invites().unwrap().is_empty());
    settle(&mut zs, &mut [&mut b, &mut a]);
    let vb = shared(&mut b.dev, id);
    assert_eq!(vb.meta.name, "Famille");
    assert_eq!(ids(&b.dev.repo().items(&vb).unwrap()), ids(&items));
    let new = login(id, "erin", 600);
    b.dev.repo().save_item(&vb, new.clone()).unwrap();
    settle(&mut zs, &mut [&mut b, &mut a]);
    let va = shared(&mut a.dev, id);
    assert!(
        a.dev
            .repo()
            .items(&va)
            .unwrap()
            .iter()
            .any(|i| i.id == new.id)
    );
}

#[test]
fn link_contact_only_read() {
    let (_zs, mut a, mut b, id, _) = alice_and_bob(ContactLevel::Link);
    let bob = account_id(&mut b.dev);
    let e = a
        .dev
        .repo()
        .add_member(id, bob, Role::Write, NOW + 1)
        .unwrap_err();
    assert_eq!(validation(e), ("contact".into(), "not verified"));
    let e = a
        .dev
        .repo()
        .add_member(id, bob, Role::Manage, NOW + 1)
        .unwrap_err();
    assert_eq!(validation(e), ("contact".into(), "not verified"));
    let info = a
        .dev
        .repo()
        .add_member(id, bob, Role::Read, NOW + 1)
        .unwrap();
    let m = info.members.iter().find(|m| m.account_id == bob).unwrap();
    assert_eq!(m.role, Role::Read);
    assert_eq!(m.level, ContactLevel::Link);
}

#[test]
fn invite_from_non_manager_ignored() {
    let (_zs, mut a, mut b, _, _) = alice_and_bob(ContactLevel::Verified);
    let mut carol = Acct::new();
    let zone = Zone::Contact(pair_id(account_id(&mut a.dev), account_id(&mut b.dev)));
    let members = vec![
        member_of(&mut a.dev, Role::Write, ContactLevel::Verified, 1),
        member_of(&mut b.dev, Role::Read, ContactLevel::Verified, 2),
        member_of(&mut carol.dev, Role::Manage, ContactLevel::Verified, 3),
    ];
    let inv = forge_invite(&mut a.dev, &mut b.dev, zone, Id([8; 16]), members);
    assert!(b.dev.repo().share_invites().unwrap().is_empty());
    let e = b.dev.repo().accept_share_invite(inv, NOW).unwrap_err();
    assert_eq!(validation(e), ("membership".into(), "signer not a manager"));
}

#[test]
fn invite_from_unknown_signer_ignored() {
    let (_zs, mut a, mut b, _, _) = alice_and_bob(ContactLevel::Verified);
    let mut carol = Acct::new();
    // Carol is in no book; her invite sits in the zone Bob shares with
    // Alice, then in a zone of her own with Bob.
    let ab = Zone::Contact(pair_id(account_id(&mut a.dev), account_id(&mut b.dev)));
    let members = vec![
        member_of(&mut carol.dev, Role::Manage, ContactLevel::Verified, 1),
        member_of(&mut b.dev, Role::Write, ContactLevel::Verified, 2),
    ];
    let inv = forge_invite(&mut carol.dev, &mut b.dev, ab, Id([8; 16]), members.clone());
    assert!(b.dev.repo().share_invites().unwrap().is_empty());
    assert!(b.dev.repo().accept_share_invite(inv, NOW).is_err());
    let bc = contact_zone(&mut b.dev, &mut carol.dev);
    let inv = forge_invite(&mut carol.dev, &mut b.dev, bc, Id([8; 16]), members);
    assert!(b.dev.repo().share_invites().unwrap().is_empty());
    let e = b.dev.repo().accept_share_invite(inv, NOW).unwrap_err();
    assert_eq!(validation(e), ("invite".into(), "unknown signer"));
}

#[test]
fn invite_listing_other_keys_for_me_refused() {
    let (_zs, mut a, mut b, _, _) = alice_and_bob(ContactLevel::Verified);
    let mut carol = Acct::new();
    let zone = Zone::Contact(pair_id(account_id(&mut a.dev), account_id(&mut b.dev)));
    // Bob's account and identity, Carol's keys.
    let mut fake = member_of(&mut carol.dev, Role::Write, ContactLevel::Verified, 2);
    let real = member_of(&mut b.dev, Role::Write, ContactLevel::Verified, 2);
    fake.account_id = real.account_id;
    fake.identity_id = real.identity_id;
    fake.identity_pub_hash = real.identity_pub_hash;
    let members = vec![
        member_of(&mut a.dev, Role::Manage, ContactLevel::Verified, 1),
        fake,
    ];
    let inv = forge_invite(&mut a.dev, &mut b.dev, zone, Id([8; 16]), members);
    assert!(b.dev.repo().share_invites().unwrap().is_empty());
    let e = b.dev.repo().accept_share_invite(inv, NOW).unwrap_err();
    assert_eq!(validation(e), ("invite".into(), "not for my keys"));
}

#[test]
fn add_member_twice_refused() {
    let (_zs, mut a, mut b, id, _) = alice_and_bob(ContactLevel::Verified);
    let bob = account_id(&mut b.dev);
    a.dev
        .repo()
        .add_member(id, bob, Role::Read, NOW + 1)
        .unwrap();
    let e = a
        .dev
        .repo()
        .add_member(id, bob, Role::Write, NOW + 2)
        .unwrap_err();
    assert_eq!(validation(e), ("member".into(), "already a member"));
}

#[test]
fn invite_credential_opens_only_for_member() {
    let (mut zs, mut a, mut b, id, _) = alice_and_bob(ContactLevel::Verified);
    let bob = account_id(&mut b.dev);
    a.dev
        .repo()
        .add_member(id, bob, Role::Write, NOW + 1)
        .unwrap();
    settle(&mut zs, &mut [&mut a, &mut b]);
    let zone = Zone::Contact(pair_id(account_id(&mut a.dev), bob));
    let recs = b
        .dev
        .store()
        .list_in(zone, RecordKind::ShareInvite)
        .unwrap();
    assert_eq!(recs.len(), 1);
    let InviteRecord::Vault(inv) = InviteRecord::decode(&recs[0].data).unwrap() else {
        panic!("vault invite");
    };
    let bob_ref = me(&mut b.dev);
    let vz = Zone::Vault(id);
    let seed = open_zone_credential(
        b.dev.repo().account().keyset(),
        &inv.credential,
        vz,
        inv.home.mailbox_id,
        &bob_ref,
    )
    .unwrap();
    let mine = inv.membership.body.member(bob).unwrap();
    assert_eq!(seed.credential_id(), mine.credential_id);
    let mut carol = Acct::new();
    let carol_ref = me(&mut carol.dev);
    for who in [&bob_ref, &carol_ref] {
        assert!(
            open_zone_credential(
                carol.dev.repo().account().keyset(),
                &inv.credential,
                vz,
                inv.home.mailbox_id,
                who,
            )
            .is_err()
        );
    }
    // Alice, the manager who drew it, cannot open it either.
    let alice_ref = me(&mut a.dev);
    assert!(
        open_zone_credential(
            a.dev.repo().account().keyset(),
            &inv.credential,
            vz,
            inv.home.mailbox_id,
            &alice_ref,
        )
        .is_err()
    );
}

#[test]
fn add_before_zone_created_refused() {
    let mut zs = Zones::default();
    let (dev, sk, fam, _) = with_family();
    let mut a = Acct::of(dev, sk);
    let mut b = Acct::new();
    pin(&mut a.dev, &mut b.dev, ContactLevel::Verified);
    contact_zone(&mut a.dev, &mut b.dev);
    a.dev.repo().share_vault(&fam, NOW).unwrap();
    a.sync(&mut zs);
    let bob = account_id(&mut b.dev);
    let e = a
        .dev
        .repo()
        .add_member(fam.id, bob, Role::Read, NOW + 1)
        .unwrap_err();
    assert_eq!(validation(e), ("zone".into(), "not created yet"));
    assert!(
        a.dev
            .repo()
            .pending_share_actions()
            .unwrap()
            .iter()
            .all(|x| !matches!(x, ShareAction::GrantCredential { .. }))
    );
}

#[test]
fn grant_action_matches_role() {
    let (_zs, mut a, mut b, id, _) = alice_and_bob(ContactLevel::Verified);
    let mut carol = Acct::new();
    pin(&mut a.dev, &mut carol.dev, ContactLevel::Verified);
    contact_zone(&mut a.dev, &mut carol.dev);
    let bob = account_id(&mut b.dev);
    let carol_id = account_id(&mut carol.dev);
    a.dev
        .repo()
        .add_member(id, bob, Role::Read, NOW + 1)
        .unwrap();
    a.dev
        .repo()
        .add_member(id, carol_id, Role::Manage, NOW + 2)
        .unwrap();
    let grants: Vec<(ZoneRole, Option<[u8; 32]>)> = a
        .dev
        .repo()
        .pending_share_actions()
        .unwrap()
        .into_iter()
        .filter_map(|x| match x {
            ShareAction::GrantCredential {
                role, put_kinds, ..
            } => Some((role, put_kinds)),
            _ => None,
        })
        .collect();
    assert_eq!(grants.len(), 2);
    let (role, kinds) = grants[0];
    assert_eq!(role, ZoneRole::Write);
    let kinds = kinds.expect("a reader writes only its chain records");
    for k in [
        RecordKind::Membership,
        RecordKind::MemberKey,
        RecordKind::MemberLineage,
        RecordKind::RekeyRequest,
    ] {
        let c = k.code() as usize;
        assert_ne!(kinds[c / 8] & (1 << (c % 8)), 0);
    }
    for k in [
        RecordKind::Item,
        RecordKind::Manifest,
        RecordKind::VaultMeta,
    ] {
        let c = k.code() as usize;
        assert_eq!(kinds[c / 8] & (1 << (c % 8)), 0);
    }
    assert_eq!(grants[1], (ZoneRole::Manage, None));
    assert_eq!(server_role(Role::Write), (ZoneRole::Write, None));
}

#[test]
fn second_device_joins_from_head() {
    let (mut zs, mut a, mut b, id, items) = alice_and_bob(ContactLevel::Verified);
    let bob = account_id(&mut b.dev);
    // Bob's second device.
    let mut b2 = Device::empty();
    pull(&b.server, &mut b2);
    b2.unlock(&b.sk);
    a.dev
        .repo()
        .add_member(id, bob, Role::Write, NOW + 1)
        .unwrap();
    settle(&mut zs, &mut [&mut a, &mut b]);
    let inv = b.dev.repo().share_invites().unwrap()[0].id;
    b.dev.repo().accept_share_invite(inv, NOW + 2).unwrap();
    b.sync(&mut zs);
    zsync(&mut b.server, &mut zs, &mut b2);
    zsync(&mut b.server, &mut zs, &mut b2);
    let info = b2.repo().join_from_head(id, NOW + 3).unwrap();
    assert_eq!(info.role, Role::Write);
    let v = shared(&mut b2, id);
    assert_eq!(ids(&b2.repo().items(&v).unwrap()), ids(&items));
}

#[test]
fn contact_zone_requires_offer() {
    let mut a = Acct::new();
    let mut b = Acct::new();
    pin(&mut a.dev, &mut b.dev, ContactLevel::Verified);
    let bob = account_id(&mut b.dev);
    let e = a.dev.repo().contact_zone(bob).unwrap_err();
    assert_eq!(validation(e), ("contact".into(), "no zone"));
    // An access without a home is not enough either.
    let zone = Zone::Contact(pair_id(account_id(&mut a.dev), bob));
    a.dev
        .repo()
        .test_write_zone_access(
            AccessTarget::Zone(zone),
            None,
            &ZoneSeed::generate().unwrap(),
        )
        .unwrap();
    assert!(a.dev.repo().contact_zone(bob).is_err());
    a.dev
        .repo()
        .set_zone_home(AccessTarget::Zone(zone), home(9))
        .unwrap();
    assert_eq!(a.dev.repo().contact_zone(bob).unwrap(), zone);
}

// ---- Task 9: removal with resealing ----

#[test]
fn removal_is_one_transaction() {
    let (_zs, mut a, _b, mut c, id, items) = trio(Role::Read);
    let carol = account_id(&mut c.dev);
    a.dev.repo().remove_member(id, carol, NOW + 3).unwrap();
    let st = a.dev.store();
    let state = st.share_state(id).unwrap().unwrap();
    assert_eq!(state.head.generation, 2);
    assert!(state.head.member(carol).is_none());
    assert_eq!(state.push.as_ref().unwrap().phase, 1);
    let zone = Zone::Vault(id);
    let kinds: Vec<RecordKind> = st
        .zone_pending(zone)
        .unwrap()
        .iter()
        .filter(|r| r.3.is_some())
        .map(|r| r.0)
        .collect();
    for k in [
        RecordKind::Membership,
        RecordKind::MemberKey,
        RecordKind::VaultMeta,
        RecordKind::Manifest,
        RecordKind::Item,
    ] {
        assert!(kinds.contains(&k), "{k:?} pending");
    }
    assert_eq!(
        kinds.iter().filter(|k| **k == RecordKind::Item).count(),
        items.len()
    );
    // A refused removal writes nothing.
    let before = st.zone_pending(zone).unwrap();
    drop(st);
    let alice = account_id(&mut a.dev);
    assert!(a.dev.repo().remove_member(id, alice, NOW + 4).is_err());
    assert_eq!(a.dev.store().zone_pending(zone).unwrap(), before);
}

#[test]
fn removal_cut_between_phases_resumes() {
    let (mut zs, mut a, mut b, mut c, id, items) = trio(Role::Read);
    let carol = account_id(&mut c.dev);
    let zone = Zone::Vault(id);
    a.dev.repo().remove_member(id, carol, NOW + 3).unwrap();
    // Phase 1 only, then a cut.
    zpush_once(&mut zs, &a.dev, zone).unwrap();
    assert!(
        a.dev
            .store()
            .pending_changes_in(zone)
            .unwrap()
            .iter()
            .all(|c| c.data.is_none() || c.kind != RecordKind::Item)
    );
    a.dev.lock();
    a.dev.unlock(&a.sk);
    assert_eq!(push_phase(&a.dev, id), Some(1));
    assert_eq!(
        a.dev.store().push_share_phase(zone).unwrap(),
        PhaseOutcome::Done
    );
    // Phase 2, then a cut.
    zpush_once(&mut zs, &a.dev, zone).unwrap();
    a.dev.lock();
    a.dev.unlock(&a.sk);
    assert_eq!(push_phase(&a.dev, id), Some(2));
    // Old items still on the server until phase 3.
    assert_eq!(item_rows_on_server(&mut zs, id), 2 * items.len());
    assert_eq!(
        a.dev.store().push_share_phase(zone).unwrap(),
        PhaseOutcome::Done
    );
    zpush_once(&mut zs, &a.dev, zone).unwrap();
    assert_eq!(
        a.dev.store().push_share_phase(zone).unwrap(),
        PhaseOutcome::Done
    );
    assert_eq!(push_phase(&a.dev, id), None);
    let va = shared(&mut a.dev, id);
    assert_eq!(item_rows_on_server(&mut zs, id), items.len());
    assert_eq!(opened_on_server(&mut zs, &va).len(), items.len());
    settle(&mut zs, &mut [&mut a, &mut b]);
    let vb = shared(&mut b.dev, id);
    assert_eq!(ids(&b.dev.repo().items(&vb).unwrap()), ids(&items));
}

#[test]
fn concurrent_write_during_removal_survives_at_new_generation() {
    let (mut zs, mut a, mut b, mut c, id, _) = trio(Role::Read);
    let carol_old = shared(&mut c.dev, id);
    let carol = account_id(&mut c.dev);
    // Bob writes while Alice removes Carol; Alice's push goes first.
    let vb = shared(&mut b.dev, id);
    let erin = login(id, "erin", 600);
    b.dev.repo().save_item(&vb, erin.clone()).unwrap();
    a.dev.repo().remove_member(id, carol, NOW + 3).unwrap();
    a.sync(&mut zs);
    b.sync(&mut zs);
    settle(&mut zs, &mut [&mut a, &mut b]);
    let va = shared(&mut a.dev, id);
    assert!(
        a.dev
            .repo()
            .items(&va)
            .unwrap()
            .iter()
            .any(|i| i.id == erin.id)
    );
    let mine = opened_on_server(&mut zs, &va);
    assert!(mine.iter().any(|i| i.id == erin.id));
    assert!(opened_on_server(&mut zs, &carol_old).is_empty());
}

#[test]
fn removal_rebases_over_a_write_between_phases() {
    let (mut zs, mut a, mut b, mut c, id, items) = trio(Role::Read);
    let carol_old = shared(&mut c.dev, id);
    let carol = account_id(&mut c.dev);
    let zone = Zone::Vault(id);
    a.dev.repo().remove_member(id, carol, NOW + 3).unwrap();
    zpush_once(&mut zs, &a.dev, zone).unwrap();
    a.dev.store().push_share_phase(zone).unwrap();
    // Bob writes at generation 1 between Alice's phases.
    let vb = shared(&mut b.dev, id);
    let erin = login(id, "erin", 600);
    b.dev.repo().save_item(&vb, erin.clone()).unwrap();
    b.sync(&mut zs);
    // Alice's manifest loses: she rebases her reseal over Bob's write.
    settle(&mut zs, &mut [&mut a, &mut b]);
    assert_eq!(push_phase(&a.dev, id), None);
    let va = shared(&mut a.dev, id);
    let got = a.dev.repo().items(&va).unwrap();
    assert_eq!(got.len(), items.len() + 1);
    assert!(opened_on_server(&mut zs, &carol_old).is_empty());
    let vb = shared(&mut b.dev, id);
    assert_eq!(b.dev.repo().items(&vb).unwrap().len(), items.len() + 1);
}

#[test]
fn removed_device_erases_local_copy() {
    let (mut zs, mut a, mut b, mut c, id, _) = trio(Role::Read);
    let carol = account_id(&mut c.dev);
    a.dev.repo().remove_member(id, carol, NOW + 3).unwrap();
    settle(&mut zs, &mut [&mut a, &mut b]);
    c.sync(&mut zs);
    assert!(
        c.dev
            .repo()
            .shared_vaults()
            .unwrap()
            .iter()
            .all(|v| v.vault_id != id)
    );
    let st = c.dev.store();
    assert!(st.share_state(id).unwrap().is_none());
    assert!(
        st.list_in(Zone::Vault(id), RecordKind::Item)
            .unwrap()
            .is_empty()
    );
    assert!(
        st.get(
            ZONE_ACCESS_KIND,
            AccessTarget::Zone(Zone::Vault(id)).record_id().unwrap()
        )
        .unwrap()
        .is_none()
    );
}

#[test]
fn removed_offline_device_keeps_pending_as_personal_copy() {
    let (mut zs, mut a, mut b, mut c, id, _) = trio(Role::Read);
    let bob = account_id(&mut b.dev);
    let vb = shared(&mut b.dev, id);
    let erin = login(id, "erin", 600);
    b.dev.repo().save_item(&vb, erin.clone()).unwrap();
    a.dev.repo().remove_member(id, bob, NOW + 3).unwrap();
    settle(&mut zs, &mut [&mut a, &mut c]);
    b.sync(&mut zs);
    assert!(b.dev.store().share_state(id).unwrap().is_none());
    let copy = b.dev.vault_named("Copie de Famille");
    let kept = b.dev.repo().items(&copy).unwrap();
    assert_eq!(kept.len(), 1);
    assert_eq!(users(&kept), vec!["erin".to_string()]);
    // Erin never reached the shared vault.
    let va = shared(&mut a.dev, id);
    assert!(
        a.dev
            .repo()
            .items(&va)
            .unwrap()
            .iter()
            .all(|i| i.id != erin.id)
    );
}

#[test]
fn keys_changed_member_gets_key_pending() {
    let (mut zs, mut a, mut b, mut c, id, _) = trio(Role::Read);
    let bob = account_id(&mut b.dev);
    let bob_ref = me(&mut b.dev);
    let carol = account_id(&mut c.dev);
    a.dev.repo().test_mark_keys_changed(bob, NOW + 3).unwrap();
    a.dev.repo().remove_member(id, carol, NOW + 4).unwrap();
    let state = a.dev.store().share_state(id).unwrap().unwrap();
    assert!(state.head.member(bob).unwrap().key_pending);
    settle(&mut zs, &mut [&mut a]);
    let mk = member_key_id(id, 2, &bob_ref);
    assert!(
        zs.server(Zone::Vault(id))
            .live(RecordKind::MemberKey, mk)
            .is_none()
    );
}

#[test]
fn seen_items_count_matches() {
    let (mut zs, mut a, mut b, mut c, id, items) = trio(Role::Read);
    let carol = account_id(&mut c.dev);
    let out = a.dev.repo().remove_member(id, carol, NOW + 3).unwrap();
    assert_eq!(out.seen_items as usize, items.len());
    settle(&mut zs, &mut [&mut a, &mut b]);
    let seen = a.dev.repo().seen_by_former_members().unwrap();
    assert_eq!(seen.len(), items.len());
    let va = shared(&mut a.dev, id);
    a.dev
        .repo()
        .save_item(&va, edited(&items[0], "alice2", 800))
        .unwrap();
    let seen = a.dev.repo().seen_by_former_members().unwrap();
    assert_eq!(seen.len(), items.len() - 1);
    assert!(seen.iter().all(|(_, i)| *i != items[0].id));
}

#[test]
fn owner_and_last_manager_cannot_be_removed() {
    let (_zs, mut a, mut b, _c, id, _) = trio(Role::Read);
    let alice = account_id(&mut a.dev);
    let bob = account_id(&mut b.dev);
    let e = a.dev.repo().remove_member(id, alice, NOW + 3).unwrap_err();
    assert_eq!(validation(e), ("member".into(), "self"));
    let e = b.dev.repo().remove_member(id, alice, NOW + 3).unwrap_err();
    assert_eq!(validation(e), ("role".into(), "manager only"));
    let e = a
        .dev
        .repo()
        .remove_member(id, Id([7; 16]), NOW + 3)
        .unwrap_err();
    assert_eq!(validation(e), ("member".into(), "not a member"));
    let _ = bob;
}

#[test]
fn revoke_queued_after_phase_b_only() {
    let (mut zs, mut a, _b, mut c, id, _) = trio(Role::Read);
    let carol = account_id(&mut c.dev);
    let zone = Zone::Vault(id);
    let before = revokes(&mut a.dev);
    a.dev.repo().remove_member(id, carol, NOW + 3).unwrap();
    assert_eq!(revokes(&mut a.dev), before);
    zpush_once(&mut zs, &a.dev, zone).unwrap();
    a.dev.store().push_share_phase(zone).unwrap();
    assert_eq!(revokes(&mut a.dev), before);
    zpush_once(&mut zs, &a.dev, zone).unwrap();
    assert_eq!(revokes(&mut a.dev), before);
    a.dev.store().push_share_phase(zone).unwrap();
    assert_eq!(revokes(&mut a.dev), before + 1);
}

#[test]
fn removed_member_reads_its_removal_before_revocation() {
    let (mut zs, mut a, mut b, mut c, id, _) = trio(Role::Read);
    let carol = account_id(&mut c.dev);
    a.dev.repo().remove_member(id, carol, NOW + 3).unwrap();
    settle(&mut zs, &mut [&mut a, &mut b]);
    // Carol's credential is refused: she reads only her contact zone.
    let cz = Zone::Contact(pair_id(account_id(&mut a.dev), carol));
    zpull(&mut zs, &c.dev, cz);
    let got = c
        .dev
        .repo()
        .zone_access_refused(Zone::Vault(id), NOW + 5)
        .unwrap();
    assert_eq!(got, AccessRefusal::Removed);
    assert!(c.dev.store().share_state(id).unwrap().is_none());
}

#[test]
fn unsigned_revocation_never_wipes() {
    let (_zs, _a, mut b, _c, id, items) = trio(Role::Read);
    let zone = Zone::Vault(id);
    let got = b.dev.repo().zone_access_refused(zone, NOW + 5).unwrap();
    assert_eq!(got, AccessRefusal::Unconfirmed);
    let vb = shared(&mut b.dev, id);
    assert_eq!(ids(&b.dev.repo().items(&vb).unwrap()), ids(&items));
    let e = b
        .dev
        .repo()
        .save_item(&vb, login(id, "zed", 900))
        .unwrap_err();
    assert_eq!(validation(e), ("vault".into(), "access refused"));
    assert!(b.dev.store().pending_changes_in(zone).unwrap().is_empty());
}

// ---- Task 10: roles, voluntary leave, rekey requests ----

#[test]
fn demote_writer_to_reader_blocks_writes() {
    let (mut zs, mut a, mut b, mut c, id, _) = trio(Role::Read);
    let bob = account_id(&mut b.dev);
    let info = a.dev.repo().set_role(id, bob, Role::Read, NOW + 3).unwrap();
    assert_eq!(
        info.members
            .iter()
            .find(|m| m.account_id == bob)
            .unwrap()
            .role,
        Role::Read
    );
    assert!(
        a.dev
            .repo()
            .pending_share_actions()
            .unwrap()
            .iter()
            .any(|x| matches!(x, ShareAction::SetCredentialRole { role, .. } if *role == server_role(Role::Read).0))
    );
    settle(&mut zs, &mut [&mut a, &mut b, &mut c]);
    let vb = shared(&mut b.dev, id);
    let e = b
        .dev
        .repo()
        .save_item(&vb, login(id, "zed", 900))
        .unwrap_err();
    assert_eq!(validation(e), ("role".into(), "read only"));
    let alice = account_id(&mut a.dev);
    let e = a.dev.repo().set_role(id, alice, Role::Read, NOW + 4);
    assert_eq!(validation(e.unwrap_err()), ("member".into(), "self"));
}

#[test]
fn promote_link_member_refused() {
    let (mut zs, mut a, mut b, id, _) = alice_and_bob(ContactLevel::Link);
    let bob = account_id(&mut b.dev);
    a.dev
        .repo()
        .add_member(id, bob, Role::Read, NOW + 1)
        .unwrap();
    settle(&mut zs, &mut [&mut a, &mut b]);
    let e = a
        .dev
        .repo()
        .set_role(id, bob, Role::Write, NOW + 2)
        .unwrap_err();
    assert_eq!(validation(e), ("contact".into(), "not verified"));
}

#[test]
fn leave_rotates_on_first_manager_read() {
    let (mut zs, mut a, mut b, mut c, id, items) = trio(Role::Read);
    let bob_ref = me(&mut b.dev);
    b.dev.repo().leave_shared_vault(id, NOW + 3).unwrap();
    // Nothing is revoked before the body and the request are sent.
    assert!(
        b.dev
            .repo()
            .pending_share_actions()
            .unwrap()
            .iter()
            .all(|x| !matches!(x, ShareAction::RevokeCredential { .. }))
    );
    b.sync(&mut zs);
    let revoke = b
        .dev
        .repo()
        .pending_share_actions()
        .unwrap()
        .into_iter()
        .find(|x| matches!(x, ShareAction::RevokeCredential { .. }))
        .expect("revocation queued once sent");
    b.dev.repo().share_action_done(&revoke).unwrap();
    assert!(b.dev.store().share_state(id).unwrap().is_none());
    a.sync(&mut zs);
    let notices = a.dev.repo().process_rekey_requests(NOW + 4).unwrap();
    assert_eq!(notices.len(), 1);
    assert_eq!(notices[0].reason, RekeyReason::Leave);
    assert_eq!(notices[0].generation, 2);
    settle(&mut zs, &mut [&mut a, &mut c]);
    assert_eq!(generation(&a.dev, id), 2);
    let mk = member_key_id(id, 2, &bob_ref);
    assert!(
        zs.server(Zone::Vault(id))
            .live(RecordKind::MemberKey, mk)
            .is_none()
    );
    let vc = shared(&mut c.dev, id);
    assert_eq!(ids(&c.dev.repo().items(&vc).unwrap()), ids(&items));
    // The request is gone: a second pass rotates nothing.
    a.sync(&mut zs);
    assert!(
        a.dev
            .repo()
            .process_rekey_requests(NOW + 5)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn stale_rekey_request_is_noop() {
    let (mut zs, mut a, _b, mut c, id, _) = trio(Role::Read);
    plant_request(&mut c.dev, &mut a.dev, id, 1);
    assert_eq!(
        a.dev.repo().process_rekey_requests(NOW + 3).unwrap().len(),
        1
    );
    assert_eq!(generation(&a.dev, id), 2);
    settle(&mut zs, &mut [&mut a]);
    // The same request about generation 1 again: satisfied, deleted.
    plant_request(&mut c.dev, &mut a.dev, id, 1);
    assert!(
        a.dev
            .repo()
            .process_rekey_requests(NOW + 4)
            .unwrap()
            .is_empty()
    );
    assert_eq!(generation(&a.dev, id), 2);
    assert!(
        a.dev
            .store()
            .list_in(Zone::Vault(id), RecordKind::RekeyRequest)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn forged_rekey_request_from_non_member_ignored() {
    let (_zs, mut a, _b, _c, id, _) = trio(Role::Read);
    let mut dan = Acct::new();
    plant_request(&mut dan.dev, &mut a.dev, id, 1);
    assert!(
        a.dev
            .repo()
            .process_rekey_requests(NOW + 3)
            .unwrap()
            .is_empty()
    );
    assert_eq!(generation(&a.dev, id), 1);
}

#[test]
fn owner_cannot_leave() {
    let (_zs, mut a, _b, _c, id, _) = trio(Role::Read);
    let e = a.dev.repo().leave_shared_vault(id, NOW + 3).unwrap_err();
    assert_eq!(validation(e), ("member".into(), "owner"));
}

// Task 11: concurrent managers (spec 7.4, A20, P6).

#[test]
fn concurrent_role_changes_lowest_wins() {
    for alice_first in [true, false] {
        let (mut zs, mut a, mut b, mut c, _d, id) = two_managers(Role::Manage);
        let carol = account_id(&mut c.dev);
        a.dev
            .repo()
            .set_role(id, carol, Role::Write, NOW + 4)
            .unwrap();
        b.dev
            .repo()
            .set_role(id, carol, Role::Read, NOW + 4)
            .unwrap();
        race(&mut zs, &mut a, &mut b, &mut c, alice_first);
        assert_eq!(head_hash(&mut a.dev, id), head_hash(&mut b.dev, id));
        assert_eq!(head_hash(&mut a.dev, id), head_hash(&mut c.dev, id));
        assert_eq!(
            role_of(&mut a.dev, id, carol),
            Some(Role::Read),
            "alice_first={alice_first}"
        );
    }
}

/// One manager's change in the convergence table.
#[derive(Debug, Clone, Copy)]
enum Op {
    RemoveCarol,
    AddDan,
    CarolRole(Role),
    Rekey,
}

fn apply(x: &mut Acct, id: Id, op: Op, carol: Id, dan: Id) {
    let r = x.dev.repo();
    match op {
        Op::RemoveCarol => {
            r.remove_member(id, carol, NOW + 4).unwrap();
        }
        Op::AddDan => {
            r.add_member(id, dan, Role::Write, NOW + 4).unwrap();
        }
        Op::CarolRole(role) => {
            r.set_role(id, carol, role, NOW + 4).unwrap();
        }
        Op::Rekey => {
            r.test_rekey_vault(id, NOW + 4).unwrap();
        }
    }
}

/// Alice's change and Bob's change (only Bob knows Dan), delivered in
/// both orders: one head, no removal lost, no removed member with an
/// envelope of the final generation, the lowest role kept.
fn converge(op_a: Op, op_b: Op) {
    use Op::*;
    for alice_first in [true, false] {
        let what = format!("{op_a:?} / {op_b:?} alice_first={alice_first}");
        let (mut zs, mut a, mut b, mut c, mut d, id) = two_managers(Role::Manage);
        let carol = account_id(&mut c.dev);
        let carol_ref = me(&mut c.dev);
        let dan = account_id(&mut d.dev);
        let g0 = generation(&a.dev, id);
        apply(&mut a, id, op_a, carol, dan);
        apply(&mut b, id, op_b, carol, dan);
        race(&mut zs, &mut a, &mut b, &mut c, alice_first);
        assert_eq!(
            head_hash(&mut a.dev, id),
            head_hash(&mut b.dev, id),
            "{what}"
        );
        let removed = matches!(op_a, RemoveCarol) || matches!(op_b, RemoveCarol);
        let g = generation(&a.dev, id);
        if removed {
            assert_eq!(role_of(&mut a.dev, id, carol), None, "{what}");
            assert!(g > g0, "{what}");
            assert!(
                zs.server(Zone::Vault(id))
                    .live(RecordKind::MemberKey, member_key_id(id, g, &carol_ref))
                    .is_none(),
                "{what}"
            );
        } else {
            assert_eq!(
                head_hash(&mut a.dev, id),
                head_hash(&mut c.dev, id),
                "{what}"
            );
        }
        if matches!(op_b, AddDan) {
            assert!(role_of(&mut a.dev, id, dan).is_some(), "{what}");
        }
        if matches!(op_a, Rekey) || matches!(op_b, Rekey) {
            assert!(g > g0, "{what}");
        }
        for (x, y) in [(op_a, op_b), (op_b, op_a)] {
            if let (CarolRole(r), CarolRole(s)) = (x, y) {
                assert_eq!(role_of(&mut a.dev, id, carol), Some(r.min(s)), "{what}");
            }
        }
        // Every member left can read the vault at the final generation.
        let va = shared(&mut a.dev, id);
        let vb = shared(&mut b.dev, id);
        assert_eq!(
            ids(&a.dev.repo().items(&va).unwrap()),
            ids(&b.dev.repo().items(&vb).unwrap()),
            "{what}"
        );
    }
}

macro_rules! converge_cases {
    ($($name:ident: $a:expr, $b:expr;)*) => {
        $(
            #[test]
            fn $name() {
                use Op::*;
                converge($a, $b);
            }
        )*
    };
}

converge_cases! {
    converge_remove_vs_add: RemoveCarol, AddDan;
    converge_remove_vs_role: RemoveCarol, CarolRole(Role::Read);
    converge_role_vs_remove: CarolRole(Role::Read), RemoveCarol;
    converge_remove_vs_remove: RemoveCarol, RemoveCarol;
    converge_rekey_vs_add: Rekey, AddDan;
    converge_rekey_vs_rekey: Rekey, Rekey;
    converge_remove_vs_rekey: RemoveCarol, Rekey;
    converge_role_vs_role: CarolRole(Role::Write), CarolRole(Role::Read);
    converge_role_vs_add: CarolRole(Role::Read), AddDan;
}

// Task 12: transfer by copy, stop sharing (spec 9.5, S9, decision 7).

#[test]
fn transfer_keeps_items_and_members() {
    let (mut zs, mut a, mut b, mut c, id, items) = transfer_cast();
    let alice = account_id(&mut a.dev);
    let carol = account_id(&mut c.dev);
    let bob = account_id(&mut b.dev);
    let new_id = transfer(&mut zs, &mut b, id);
    let members = head_members(&mut b.dev, new_id);
    assert!(members.contains(&(bob, Role::Manage)));
    assert!(members.contains(&(alice, Role::Manage)));
    assert!(members.contains(&(carol, Role::Read)));
    let st = b.dev.store().share_state(new_id).unwrap().unwrap();
    assert_eq!(st.head.owner().unwrap().account_id, bob);
    let vb = shared(&mut b.dev, new_id);
    assert_eq!(ids(&b.dev.repo().items(&vb).unwrap()), ids(&items));
    // The old zone ends on a Rekey body pointing at the new home.
    let old = &zs.server(Zone::Vault(id));
    let rec = old.live(RecordKind::Membership, id).unwrap();
    let body = SignedMembership::decode(&rec.record.as_ref().unwrap().data)
        .unwrap()
        .body;
    assert_eq!(body.reason, MembershipReason::Rekey);
    assert_eq!(body.moved_to.unwrap().home, home(2));
    // Bob's copy of the old zone is gone once the last body was sent.
    assert!(b.dev.store().share_state(id).unwrap().is_none());
}

#[test]
fn members_follow_moved_to() {
    let (mut zs, mut a, mut b, mut c, id, items) = transfer_cast();
    let new_id = transfer(&mut zs, &mut b, id);
    settle(&mut zs, &mut [&mut a, &mut b, &mut c]);
    // Carol joined the new vault and dropped the old one.
    assert!(c.dev.store().share_state(id).unwrap().is_none());
    let vc = shared(&mut c.dev, new_id);
    assert_eq!(ids(&c.dev.repo().items(&vc).unwrap()), ids(&items));
    // Alice, the old owner, joined too and deletes the old mailbox first.
    let va = shared(&mut a.dev, new_id);
    assert_eq!(ids(&a.dev.repo().items(&va).unwrap()), ids(&items));
    let delete = ShareAction::DeleteZoneMailbox {
        zone: Zone::Vault(id),
    };
    assert!(
        a.dev
            .repo()
            .pending_share_actions()
            .unwrap()
            .contains(&delete)
    );
    assert!(a.dev.store().share_state(id).unwrap().is_some());
    a.dev.repo().share_action_done(&delete).unwrap();
    assert!(a.dev.store().share_state(id).unwrap().is_none());
    // The vault lists show the new vault only.
    let listed: Vec<Id> = a
        .dev
        .repo()
        .shared_vaults()
        .unwrap()
        .iter()
        .map(|v| v.vault_id)
        .collect();
    assert_eq!(listed, vec![new_id]);
}

#[test]
fn moved_to_from_non_manager_ignored() {
    let (mut zs, mut a, mut b, mut c, id, _) = trio(Role::Read);
    settle(&mut zs, &mut [&mut a, &mut b, &mut c]);
    let carol = me(&mut c.dev);
    let head = c.dev.store().share_state(id).unwrap().unwrap().head;
    let seq_before = a.dev.store().share_state(id).unwrap().unwrap().head.seq;
    assert_eq!(head.seq, seq_before);
    let mut body = head.next(carol, MembershipReason::Rekey, NOW + 4).unwrap();
    body.moved_to = Some(onepass_core::share::MovedTo {
        owner: carol,
        home: home(7),
    });
    let signed = sign_membership(body, &c.dev.repo().account().keyset().signing).unwrap();
    a.dev
        .repo()
        .store_mut()
        .put_all_zoned(
            vec![(
                Zone::Vault(id),
                Record {
                    kind: RecordKind::Membership,
                    id,
                    version: signed.body.seq,
                    data: signed.encode(),
                },
                Some(seq_before),
            )],
            vec![],
            None,
            &[],
        )
        .unwrap();
    a.dev.repo().shared_vaults().unwrap();
    let st = a.dev.store().share_state(id).unwrap().unwrap();
    assert_eq!(st.head.seq, seq_before);
    assert!(st.head.moved_to.is_none());
    assert!(!st.leaving);
}

#[test]
fn stop_sharing_requires_sole_member() {
    let (_zs, mut a, _b, _c, id, _) = trio(Role::Read);
    let e = a.dev.repo().stop_sharing(id, NOW + 4).unwrap_err();
    assert_eq!(validation(e), ("vault".into(), "other members"));
}

#[test]
fn stop_sharing_returns_personal_vault() {
    let (mut zs, mut a, _b, id, items) = alice_and_bob(ContactLevel::Verified);
    a.sync(&mut zs);
    let personal = a.dev.repo().stop_sharing(id, NOW + 4).unwrap();
    assert!(!personal.zone().is_shared());
    assert_eq!(ids(&a.dev.repo().items(&personal).unwrap()), ids(&items));
    assert!(
        a.dev
            .repo()
            .vaults()
            .unwrap()
            .iter()
            .any(|v| v.id == personal.id)
    );
    let delete = ShareAction::DeleteZoneMailbox {
        zone: Zone::Vault(id),
    };
    assert!(
        a.dev
            .repo()
            .pending_share_actions()
            .unwrap()
            .contains(&delete)
    );
    a.dev.repo().share_action_done(&delete).unwrap();
    assert!(a.dev.store().share_state(id).unwrap().is_none());
    assert!(a.dev.repo().shared_vaults().unwrap().is_empty());
}

// Task 13: a rotation carries the member's shared vault keys and lineage
// (spec 12.2 step 3 bis, S3, A12).

#[test]
fn rotator_still_reads_shared_vault() {
    let (_zs, mut a, _b, id, items) = rotating_alice();
    let old = me(&mut a.dev);
    a.rotate(false);
    let new = me(&mut a.dev);
    assert_ne!(old.identity_id, new.identity_id);
    let va = shared(&mut a.dev, id);
    assert_eq!(ids(&a.dev.repo().items(&va).unwrap()), ids(&items));
    let st = a.dev.store().share_state(id).unwrap().unwrap();
    assert_eq!(st.identity_pending.unwrap().new_identity, new);
    // The envelope for the new identity waits in the zone, at the head's
    // generation.
    let g = st.head.generation;
    assert!(
        a.dev
            .store()
            .get_in(
                Zone::Vault(id),
                RecordKind::MemberKey,
                member_key_id(id, g, &new)
            )
            .unwrap()
            .is_some()
    );
}

#[test]
fn lineage_published_to_shared_and_contact_zones() {
    let (_zs, mut a, mut b, id, _) = rotating_alice();
    a.rotate(false);
    let cz = Zone::Contact(pair_id(account_id(&mut a.dev), account_id(&mut b.dev)));
    let head = a.dev.store().trust_state().unwrap().unwrap().head.hash;
    for zone in [Zone::Vault(id), cz] {
        let rows = a
            .dev
            .store()
            .list_in(zone, RecordKind::MemberLineage)
            .unwrap();
        let recs: Vec<MemberLineageRecord> = rows
            .iter()
            .map(|r| {
                let m = MemberLineageRecord::decode(&r.data).unwrap();
                assert_eq!(m.id(), r.id);
                m
            })
            .collect();
        // The genesis, the new rotation and the new identity's params.
        assert_eq!(recs.len(), 3, "{zone:?}");
        assert!(
            recs.iter()
                .any(|m| matches!(m, MemberLineageRecord::Lineage(l) if l.hash() == head))
        );
        assert!(
            recs.iter()
                .any(|m| matches!(m, MemberLineageRecord::Params(_)))
        );
    }
}

#[test]
fn rotate_without_revoke_requests_nothing() {
    let (_zs, mut a, _b, id, _) = rotating_alice();
    a.rotate(false);
    assert!(
        a.dev
            .store()
            .list_in(Zone::Vault(id), RecordKind::RekeyRequest)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn revoke_requests_rekey() {
    let (mut zs, mut a, mut b, id, _) = rotating_alice();
    let old = me(&mut a.dev);
    a.rotate(true);
    let rows = a
        .dev
        .store()
        .list_in(Zone::Vault(id), RecordKind::RekeyRequest)
        .unwrap();
    assert_eq!(rows.len(), 1);
    let req = RekeyRequest::decode(&rows[0].data).unwrap();
    assert_eq!(req.reason, RekeyReason::MemberRotation);
    assert_eq!(req.signer, old);
    assert!(req.lineage_hash.is_some());
    // Bob, a manager? No: Alice is the only manager; the request waits for
    // her own pass after she is confirmed. It reached the zone.
    zsync(&mut a.server, &mut zs, &mut a.dev);
    zsync(&mut b.server, &mut zs, &mut b.dev);
    assert!(
        zs.server(Zone::Vault(id))
            .live(RecordKind::RekeyRequest, req.id())
            .is_some()
    );
}

#[test]
fn zone_access_resigned_on_rotation() {
    let (_zs, mut a, _b, id, _) = rotating_alice();
    let before = a.dev.repo().zone_accesses().unwrap();
    assert!(!before.is_empty());
    a.rotate(false);
    let after = a.dev.repo().zone_accesses().unwrap();
    assert_eq!(after.len(), before.len());
    for access in &after {
        assert!(a.dev.repo().zone_access(access.target).unwrap().is_some());
    }
    assert!(
        after
            .iter()
            .any(|x| x.target == AccessTarget::Zone(Zone::Vault(id)))
    );
}

// Task 14: a member's new identity, retired at once, adopted on a human
// check (spec 12.3, 12.5, S22 to S24, decision 6, A11).

#[test]
fn old_identity_retired_when_rotation_seen() {
    let (_zs, mut a, _b, mut c, id, child) = carol_rotated(Role::Read);
    let carol = account_id(&mut c.dev);
    let old = a
        .dev
        .store()
        .share_state(id)
        .unwrap()
        .unwrap()
        .head
        .member(carol)
        .unwrap()
        .identity_id;
    let changes = a.dev.repo().refresh_member_identities(NOW + 5).unwrap();
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].account_id, carol);
    assert_eq!(changes[0].child, child);
    assert_eq!(changes[0].vaults, vec![id]);
    assert!(!changes[0].forked);
    let st = a.dev.store().share_state(id).unwrap().unwrap();
    assert!(st.retired_signers.contains_key(&MemberRef {
        account_id: carol,
        identity_id: old,
    }));
    let entry = a.dev.repo().contact(carol).unwrap().unwrap();
    assert!(matches!(entry.state, ContactState::KeysChanged { .. }));
    // The vault still reads.
    let va = shared(&mut a.dev, id);
    assert!(!a.dev.repo().items(&va).unwrap().is_empty());
}

#[test]
fn reader_adopted_by_code() {
    let (mut zs, mut a, mut b, mut c, id, child) = carol_rotated(Role::Read);
    let carol = account_id(&mut c.dev);
    let new = me(&mut c.dev);
    let old_credential = a
        .dev
        .store()
        .share_state(id)
        .unwrap()
        .unwrap()
        .head
        .member(carol)
        .unwrap()
        .credential_id;
    a.dev.repo().refresh_member_identities(NOW + 5).unwrap();
    let infos = a
        .dev
        .repo()
        .adopt_member_identity(
            carol,
            child,
            AdoptionProof::Code(rotation_code(&child)),
            NOW + 6,
        )
        .unwrap();
    assert_eq!(infos.len(), 1);
    // The credential is renewed: grant the new one, then revoke the old.
    let actions = a.dev.repo().pending_share_actions().unwrap();
    let grant = actions
        .iter()
        .position(|x| matches!(x, ShareAction::GrantCredential { .. }))
        .expect("grant");
    let revoke = actions
        .iter()
        .position(|x| {
            matches!(x, ShareAction::RevokeCredential { credential_id, .. } if *credential_id == old_credential)
        })
        .expect("revoke");
    assert!(grant < revoke);
    settle(&mut zs, &mut [&mut a, &mut b, &mut c]);
    // Everyone follows the IdentityUpdate body; Carol is no longer
    // pending and holds her new credential.
    for x in [&mut a, &mut b, &mut c] {
        let st = x.dev.store().share_state(id).unwrap().unwrap();
        assert_eq!(st.head.member(carol).unwrap().identity_id, new.identity_id);
        assert_eq!(st.head.reason, MembershipReason::IdentityUpdate);
    }
    let st = c.dev.store().share_state(id).unwrap().unwrap();
    assert!(st.identity_pending.is_none());
    let (_, seed) = c
        .dev
        .repo()
        .zone_access(AccessTarget::Zone(Zone::Vault(id)))
        .unwrap()
        .unwrap();
    assert_eq!(
        seed.credential_id(),
        st.head.member(carol).unwrap().credential_id
    );
    let vc = shared(&mut c.dev, id);
    assert!(!c.dev.repo().items(&vc).unwrap().is_empty());
    // Alice's book pins Carol's new head again.
    let entry = a.dev.repo().contact(carol).unwrap().unwrap();
    assert_eq!(entry.state, ContactState::Active);
    assert_eq!(entry.pinned_head.hash, child);
}

#[test]
fn writer_needs_in_person() {
    let (mut zs, mut a, mut b, _c, id, _) = trio(Role::Read);
    b.rotate(false);
    b.sync(&mut zs);
    a.sync(&mut zs);
    let bob = account_id(&mut b.dev);
    let child = b.dev.store().trust_state().unwrap().unwrap().head.hash;
    a.dev.repo().refresh_member_identities(NOW + 5).unwrap();
    let e = a
        .dev
        .repo()
        .adopt_member_identity(
            bob,
            child,
            AdoptionProof::Code(rotation_code(&child)),
            NOW + 6,
        )
        .unwrap_err();
    assert_eq!(validation(e), ("proof".into(), "in person required"));
    let e = a
        .dev
        .repo()
        .adopt_member_identity(
            bob,
            child,
            AdoptionProof::InPerson {
                transcript_hash: [1; 32],
            },
            NOW + 6,
        )
        .unwrap_err();
    assert_eq!(validation(e), ("proof".into(), "no session"));
    let _ = id;
}

#[test]
fn writes_refused_while_identity_pending() {
    let (_zs, mut b, _, id, _) = {
        let (zs, a, b, id, items) = rotating_alice();
        (zs, b, a, id, items)
    };
    // Bob (a writer) rotates: his writes wait for a manager.
    b.rotate(false);
    let vb = shared(&mut b.dev, id);
    let e = b
        .dev
        .repo()
        .save_item(&vb, login(id, "zed", 900))
        .unwrap_err();
    assert_eq!(validation(e), ("vault".into(), "identity pending"));
}

// Task 15: a sole manager's rotation (spec 12.4, S25, ruling A-13).

#[test]
fn sole_manager_rotation_blocks_membership_changes_until_confirmed() {
    let (mut zs, mut a, mut b, id, _) = rotating_alice();
    let bob = account_id(&mut b.dev);
    let seq = head_of(&b.dev, id).seq;
    a.rotate(false);
    let e = a
        .dev
        .repo()
        .set_role(id, bob, Role::Read, NOW + 5)
        .unwrap_err();
    assert!(matches!(e, Error::Validation(_)));
    a.dev.repo().publish_own_identity(id, NOW + 5).unwrap();
    settle(&mut zs, &mut [&mut a, &mut b]);
    // Bob keeps the last body Alice's old identity signed, and reads.
    b.dev.repo().refresh_member_identities(NOW + 6).unwrap();
    b.sync(&mut zs);
    assert_eq!(head_of(&b.dev, id).seq, seq);
    let vb = shared(&mut b.dev, id);
    assert!(!b.dev.repo().items(&vb).unwrap().is_empty());
}

#[test]
fn member_confirms_locally_then_accepts_new_bodies() {
    let (mut zs, mut a, mut b, id, _) = rotating_alice();
    let alice = account_id(&mut a.dev);
    let bob = account_id(&mut b.dev);
    a.rotate(false);
    let child = a.dev.store().trust_state().unwrap().unwrap().head.hash;
    let new_alice = me(&mut a.dev);
    a.dev.repo().publish_own_identity(id, NOW + 5).unwrap();
    settle(&mut zs, &mut [&mut a, &mut b]);
    b.dev.repo().refresh_member_identities(NOW + 6).unwrap();
    // A code is not enough for a manager.
    let e = b
        .dev
        .repo()
        .adopt_member_identity(
            alice,
            child,
            AdoptionProof::Code(rotation_code(&child)),
            NOW + 6,
        )
        .unwrap_err();
    assert_eq!(validation(e), ("proof".into(), "in person required"));
    repin_in_person(&mut b.dev, &mut a.dev);
    b.dev
        .repo()
        .adopt_member_identity(
            alice,
            child,
            AdoptionProof::InPerson {
                transcript_hash: [1; 32],
            },
            NOW + 7,
        )
        .unwrap();
    let head = head_of(&b.dev, id);
    assert_eq!(head.reason, MembershipReason::IdentityUpdate);
    assert_eq!(
        head.member(alice).unwrap().identity_id,
        new_alice.identity_id
    );
    // Alice manages again, and Bob follows her new bodies.
    a.dev.repo().set_role(id, bob, Role::Read, NOW + 8).unwrap();
    settle(&mut zs, &mut [&mut a, &mut b]);
    assert_eq!(role_of(&mut b.dev, id, bob), Some(Role::Read));
}

#[test]
fn two_managers_one_confirms_the_other() {
    let (mut zs, mut a, mut b, mut c, _d, id) = two_managers(Role::Read);
    let bob = account_id(&mut b.dev);
    b.rotate(false);
    let child = b.dev.store().trust_state().unwrap().unwrap().head.hash;
    let new_bob = me(&mut b.dev);
    b.sync(&mut zs);
    a.sync(&mut zs);
    a.dev.repo().refresh_member_identities(NOW + 6).unwrap();
    repin_in_person(&mut a.dev, &mut b.dev);
    let infos = a
        .dev
        .repo()
        .adopt_member_identity(
            bob,
            child,
            AdoptionProof::InPerson {
                transcript_hash: [1; 32],
            },
            NOW + 7,
        )
        .unwrap();
    assert_eq!(infos.len(), 1);
    settle(&mut zs, &mut [&mut a, &mut b, &mut c]);
    // Carol follows the body Alice signed, without a gesture of her own.
    for x in [&mut a, &mut b, &mut c] {
        let head = head_of(&x.dev, id);
        assert_eq!(head.member(bob).unwrap().identity_id, new_bob.identity_id);
    }
    assert!(
        b.dev
            .store()
            .share_state(id)
            .unwrap()
            .unwrap()
            .identity_pending
            .is_none()
    );
}

#[test]
fn not_confirmed_list_shrinks_when_member_writes() {
    let (mut zs, mut a, mut b, id, _) = rotating_alice();
    let alice = account_id(&mut a.dev);
    let bob = account_id(&mut b.dev);
    // Bob opened the vault once: the manifest Alice's old keys signed is
    // the one he already accepted.
    let vb = shared(&mut b.dev, id);
    b.dev.repo().items(&vb).unwrap();
    a.rotate(false);
    let child = a.dev.store().trust_state().unwrap().unwrap().head.hash;
    a.dev.repo().publish_own_identity(id, NOW + 5).unwrap();
    assert_eq!(a.dev.repo().members_not_confirmed(id).unwrap(), vec![bob]);
    settle(&mut zs, &mut [&mut a, &mut b]);
    b.dev.repo().refresh_member_identities(NOW + 6).unwrap();
    repin_in_person(&mut b.dev, &mut a.dev);
    b.dev
        .repo()
        .adopt_member_identity(
            alice,
            child,
            AdoptionProof::InPerson {
                transcript_hash: [1; 32],
            },
            NOW + 7,
        )
        .unwrap();
    let vb = shared(&mut b.dev, id);
    b.dev.repo().save_item(&vb, login(id, "bob", 800)).unwrap();
    settle(&mut zs, &mut [&mut a, &mut b]);
    let va = shared(&mut a.dev, id);
    assert!(users(&a.dev.repo().items(&va).unwrap()).contains(&"bob".to_string()));
    assert!(a.dev.repo().members_not_confirmed(id).unwrap().is_empty());
}

// ---- Task 7, deferred two-account tests ----

#[test]
fn writer_write_visible_to_reader() {
    let (mut zs, mut a, mut b, mut c, id, _) = trio(Role::Read);
    let vb = shared(&mut b.dev, id);
    b.dev.repo().save_item(&vb, login(id, "bea", 800)).unwrap();
    settle(&mut zs, &mut [&mut a, &mut b, &mut c]);
    let vc = shared(&mut c.dev, id);
    assert!(users(&c.dev.repo().items(&vc).unwrap()).contains(&"bea".to_string()));
}

#[test]
fn reader_cannot_write() {
    let (mut zs, mut a, mut b, mut c, id, _) = trio(Role::Read);
    let vc = shared(&mut c.dev, id);
    let e = c
        .dev
        .repo()
        .save_item(&vc, login(id, "carl", 800))
        .unwrap_err();
    assert_eq!(validation(e), ("role".into(), "read only"));
    assert!(
        c.dev
            .store()
            .zone_pending(Zone::Vault(id))
            .unwrap()
            .is_empty()
    );
    settle(&mut zs, &mut [&mut a, &mut b, &mut c]);
    let va = shared(&mut a.dev, id);
    assert!(!users(&a.dev.repo().items(&va).unwrap()).contains(&"carl".to_string()));
}

// ---- Attachments of shared items ----

fn chunk_rows(zs: &mut Zones, id: Id) -> usize {
    zs.server(Zone::Vault(id))
        .records
        .iter()
        .filter(|((k, _), e)| *k == RecordKind::Attachment && e.record.is_some())
        .count()
}

#[test]
fn shared_attachment_written_in_zone_and_read_by_member() {
    let (mut zs, mut a, mut b, mut c, id, _) = trio(Role::Read);
    let va = shared(&mut a.dev, id);
    let item = login(id, "doc", 800);
    a.dev.repo().save_item(&va, item.clone()).unwrap();
    let r = a
        .dev
        .repo()
        .add_attachment(&va, item.id, "a.txt", "text/plain", b"hello family")
        .unwrap();
    // No chunk in the private zone.
    assert!(
        a.dev
            .store()
            .list(RecordKind::Attachment)
            .unwrap()
            .is_empty()
    );
    settle(&mut zs, &mut [&mut a, &mut b, &mut c]);
    assert!(chunk_rows(&mut zs, id) > 0);
    for x in [&mut b, &mut c] {
        let v = shared(&mut x.dev, id);
        let got = x.dev.repo().read_attachment(&v, item.id, r.id).unwrap();
        assert_eq!(&got[..], b"hello family");
    }
    // Bob (writer) removes it: the chunks leave the zone.
    let vb = shared(&mut b.dev, id);
    b.dev.repo().remove_attachment(&vb, item.id, r.id).unwrap();
    settle(&mut zs, &mut [&mut a, &mut b, &mut c]);
    assert_eq!(chunk_rows(&mut zs, id), 0);
}

#[test]
fn shared_item_delete_and_move_carry_chunks() {
    let (mut zs, mut a, mut b, mut c, id, _) = trio(Role::Read);
    let va = shared(&mut a.dev, id);
    let item = login(id, "doc", 800);
    a.dev.repo().save_item(&va, item.clone()).unwrap();
    a.dev
        .repo()
        .add_attachment(&va, item.id, "a.txt", "text/plain", b"one")
        .unwrap();
    // A personal item with an attachment moves into the shared vault.
    let personal = a.dev.vault_named("Personnel");
    let mine = login(personal.id, "mine", 801);
    a.dev.repo().save_item(&personal, mine.clone()).unwrap();
    let r2 = a
        .dev
        .repo()
        .add_attachment(&personal, mine.id, "b.txt", "text/plain", b"two")
        .unwrap();
    a.dev.repo().move_item(mine.id, &personal, &va).unwrap();
    assert!(
        a.dev
            .store()
            .list(RecordKind::Attachment)
            .unwrap()
            .is_empty()
    );
    settle(&mut zs, &mut [&mut a, &mut b, &mut c]);
    let vc = shared(&mut c.dev, id);
    assert_eq!(
        &c.dev.repo().read_attachment(&vc, mine.id, r2.id).unwrap()[..],
        b"two"
    );
    let before = chunk_rows(&mut zs, id);
    a.dev.repo().delete_item(&va, item.id).unwrap();
    settle(&mut zs, &mut [&mut a, &mut b, &mut c]);
    assert!(chunk_rows(&mut zs, id) < before);
    // And back out to the personal vault.
    let va = shared(&mut a.dev, id);
    a.dev.repo().move_item(mine.id, &va, &personal).unwrap();
    assert_eq!(
        &a.dev
            .repo()
            .read_attachment(&personal, mine.id, r2.id)
            .unwrap()[..],
        b"two"
    );
    settle(&mut zs, &mut [&mut a, &mut b, &mut c]);
    assert_eq!(chunk_rows(&mut zs, id), 0);
}
