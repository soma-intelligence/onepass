//! Shared vaults on the repository (sharing plan 2, Tasks 6 to 8).

mod common;
mod share_common;

use common::*;
use onepass_core::contact::{ContactLevel, pair_id};
use onepass_core::device_keys::{DeviceKeys, DevicePublic};
use onepass_core::devices::{DeviceKind, DeviceMode};
use onepass_core::lineage::{
    GenesisBody, LINEAGE_FORMAT, LineageRecord, RosterEntry, identity_id, sign_genesis,
};
use onepass_core::share::{
    AccessTarget, InviteRecord, MEMBERSHIP_FORMAT, Member, MemberKey, MemberRef, MembershipBody,
    MembershipReason, Role, ShareAction, ShareInvite, SignedMembership, ZoneHome, ZoneMailboxKind,
    ZoneRole, ZoneSeed, identity_pub_hash, member_key_id, open_member_key, open_zone_credential,
    server_role, sign_membership, wrap_zone_credential,
};
use onepass_core::store::{MemoryStore, Zone};
use onepass_core::trust::{LineageHead, TrustLevel, TrustState};
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

// ---- Task 8: members, invites, acceptance ----

fn home(n: u8) -> ZoneHome {
    ZoneHome {
        url: format!("https://box{n}.example.org"),
        mailbox_id: [n; 16],
        extra_ca_pem: None,
    }
}

fn account_id(d: &mut Device) -> Id {
    d.repo().account().params.account_id
}

fn me(d: &mut Device) -> MemberRef {
    d.repo().me()
}

/// `x` pins `y`'s card at `level`.
fn pin(x: &mut Device, y: &mut Device, level: ContactLevel) {
    let card = y.repo().own_contact_card("peer", NOW).unwrap();
    x.repo()
        .test_pin_contact(&card, level, [1; 32], NOW)
        .unwrap();
}

/// The contact zone of `x` and `y`, with a home on both sides (Task 7b
/// stands in).
fn contact_zone(x: &mut Device, y: &mut Device) -> Zone {
    let zone = Zone::Contact(pair_id(account_id(x), account_id(y)));
    for d in [x, y] {
        d.repo()
            .test_write_zone_access(
                AccessTarget::Zone(zone),
                Some(home(9)),
                &ZoneSeed::generate().unwrap(),
            )
            .unwrap();
    }
    zone
}

/// One account and its private server.
struct Acct {
    server: Server,
    dev: Device,
    sk: SecretKey,
}

fn entry_of(p: &DevicePublic) -> RosterEntry {
    RosterEntry {
        device_id: p.device_id,
        sign_pub: p.sign_pub.clone(),
        kem_pub: p.kem_pub.clone(),
        name: "iPhone".into(),
        kind: DeviceKind::Phone,
        mode: DeviceMode::Personal,
        introduced_by: None,
    }
}

impl Acct {
    fn new() -> Acct {
        let (dev, sk) = Device::create();
        Acct::of(dev, sk)
    }

    /// `dev` synced once, then given a lineage genesis and a trust state
    /// (as `contact_invite.rs`), so that it has a contact card.
    fn of(mut dev: Device, sk: SecretKey) -> Acct {
        let mut server = Server::default();
        sync(&mut server, &mut dev).unwrap();
        let keys = DeviceKeys::generate_software().unwrap();
        let me = keys.public(dev.repo().chain().device_id.unwrap()).unwrap();
        let account = dev.repo().account();
        let account_id = account.params.account_id;
        let identity_pub = account.params.identity_pub.clone();
        let genesis = LineageRecord::Genesis(
            sign_genesis(
                GenesisBody {
                    format: LINEAGE_FORMAT,
                    account_id,
                    identity_pub: identity_pub.clone(),
                    creator: entry_of(&me),
                    created_at: NOW - 100,
                },
                &keys,
                &account.keyset().identity,
            )
            .unwrap(),
        );
        let mut trust = TrustState::new(
            account_id,
            me.clone(),
            LineageHead {
                generation: 0,
                hash: genesis.hash(),
            },
            identity_pub,
            vec![entry_of(&me)],
            DeviceLineageState::Current,
        );
        trust.levels.insert(me.device_id, TrustLevel::Verified);
        let record = Record {
            id: genesis.record_id(),
            kind: RecordKind::Lineage,
            version: 0,
            data: genesis.encode(),
        };
        dev.repo()
            .store_mut()
            .put_all_if_version_with_trust(vec![(record, None)], vec![], None, &trust)
            .unwrap();
        sync(&mut server, &mut dev).unwrap();
        Acct { server, dev, sk }
    }

    fn sync(&mut self, zs: &mut Zones) {
        zsync(&mut self.server, zs, &mut self.dev);
    }
}

/// Alice shares "Famille" (its zone has a home) and pins Bob at
/// `level`; Bob pins Alice `Verified`; their contact zone exists.
fn alice_and_bob(level: ContactLevel) -> (Zones, Acct, Acct, Id, Vec<Item>) {
    let mut zs = Zones::default();
    let (dev, sk, fam, items) = with_family();
    let mut a = Acct::of(dev, sk);
    let mut b = Acct::new();
    pin(&mut a.dev, &mut b.dev, level);
    pin(&mut b.dev, &mut a.dev, ContactLevel::Verified);
    contact_zone(&mut a.dev, &mut b.dev);
    a.dev.repo().share_vault(&fam, NOW).unwrap();
    a.dev
        .repo()
        .set_zone_home(AccessTarget::Zone(Zone::Vault(fam.id)), home(1))
        .unwrap();
    a.sync(&mut zs);
    b.sync(&mut zs);
    (zs, a, b, fam.id, items)
}

fn settle(zs: &mut Zones, accts: &mut [&mut Acct]) {
    for _ in 0..2 {
        for a in accts.iter_mut() {
            a.sync(zs);
        }
    }
}

fn validation(e: Error) -> (String, &'static str) {
    match e {
        Error::Validation(v) => (v.field, v.reason),
        other => panic!("expected Validation, got {other:?}"),
    }
}

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
fn a1_server_key_never_used() {
    let (mut zs, mut a, mut b, id, _) = alice_and_bob(ContactLevel::Verified);
    let mut carol = Acct::new();
    let carol_id = account_id(&mut carol.dev);
    // The server drops Carol's card in the contact zone of Alice and Bob.
    let card = carol.dev.repo().own_contact_card("Carol", NOW).unwrap();
    let zone = Zone::Contact(pair_id(account_id(&mut a.dev), account_id(&mut b.dev)));
    a.dev
        .store()
        .put_all_zoned(
            vec![(
                zone,
                Record {
                    kind: RecordKind::ShareInvite,
                    id: Id([3; 16]),
                    version: 1,
                    data: postcard::to_allocvec(&card).unwrap(),
                },
                None,
            )],
            vec![],
            None,
            &[],
        )
        .unwrap();
    let e = a
        .dev
        .repo()
        .add_member(id, carol_id, Role::Read, NOW + 1)
        .unwrap_err();
    assert_eq!(validation(e), ("contact".into(), "unknown"));
    let info = a.dev.repo().shared_vaults().unwrap();
    assert!(info[0].members.iter().all(|m| m.account_id != carol_id));
    let carol_sign = carol.dev.repo().account().params.signing_pub.clone();
    let st = a.dev.store();
    let head = SignedMembership::decode(
        &st.get_in(Zone::Vault(id), RecordKind::Membership, id)
            .unwrap()
            .unwrap()
            .data,
    )
    .unwrap()
    .body;
    assert!(head.members.iter().all(|m| m.sign_pub != carol_sign));
    let _ = &mut zs;
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

/// A member entry for `d` under its current keys.
fn member_of(d: &mut Device, role: Role, level: ContactLevel, credential: u8) -> Member {
    let p = d.repo().account().params.clone();
    Member {
        account_id: p.account_id,
        identity_id: identity_id(&p.identity_pub),
        identity_pub_hash: identity_pub_hash(&p.identity_pub),
        sign_pub: p.signing_pub.clone(),
        kem_pub: p.kem_pub.clone(),
        role,
        owner: role == Role::Manage,
        level,
        added_by: d.repo().me(),
        added_at: NOW,
        key_pending: false,
        credential_id: [credential; 16],
    }
}

/// An invite for `to`, body and invite signed by `signer`, over
/// `members`, dropped in `to`'s store in `zone`. Returns its record id.
fn forge_invite(
    signer: &mut Device,
    to: &mut Device,
    zone: Zone,
    vault_id: Id,
    mut members: Vec<Member>,
) -> Id {
    members.sort_by_key(|m| m.account_id);
    let by = me(signer);
    let body = MembershipBody {
        format: MEMBERSHIP_FORMAT,
        vault_id,
        seq: 1,
        prev_hash: [0; 32],
        generation: 1,
        key_commit: [7; 32],
        members,
        removed: vec![],
        signer: by,
        reason: MembershipReason::Create,
        moved_to: None,
        history: vec![],
        issued_at: NOW,
    };
    let to_ref = me(to);
    let to_kem = to.repo().account().params.kem_pub.clone();
    let seed = ZoneSeed::generate().unwrap();
    let h = home(1);
    let credential =
        wrap_zone_credential(&to_kem, &seed, Zone::Vault(vault_id), h.mailbox_id, &to_ref).unwrap();
    let keys = &signer.repo().account().keyset().signing;
    let signed = sign_membership(body, keys).unwrap();
    let invite =
        InviteRecord::Vault(ShareInvite::sign(vault_id, signed, h, credential, by, keys).unwrap());
    let id = invite.id();
    to.store()
        .put_all_zoned(
            vec![(
                zone,
                Record {
                    kind: RecordKind::ShareInvite,
                    id,
                    version: 1,
                    data: invite.encode(),
                },
                None,
            )],
            vec![],
            None,
            &[],
        )
        .unwrap();
    id
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
fn a17_participant_without_envelope() {
    let (mut zs, mut a, mut b, id, _) = alice_and_bob(ContactLevel::Verified);
    let bob = account_id(&mut b.dev);
    a.dev
        .repo()
        .add_member(id, bob, Role::Write, NOW + 1)
        .unwrap();
    a.sync(&mut zs);
    // Mallory learned the zone's home and holds a credential of the
    // mailbox: she reads every record of the zone.
    let mut mallory = Acct::new();
    let zone = Zone::Vault(id);
    mallory
        .dev
        .repo()
        .test_write_zone_access(
            AccessTarget::Zone(zone),
            Some(home(1)),
            &ZoneSeed::generate().unwrap(),
        )
        .unwrap();
    mallory.sync(&mut zs);
    let st = mallory.dev.store();
    assert!(
        st.get_in(zone, RecordKind::Membership, id)
            .unwrap()
            .is_some()
    );
    let m = me(&mut mallory.dev);
    assert!(
        st.get_in(zone, RecordKind::MemberKey, member_key_id(id, 1, &m))
            .unwrap()
            .is_none()
    );
    for r in st.list_in(zone, RecordKind::MemberKey).unwrap() {
        assert_ne!(MemberKey::decode(&r.data).unwrap().member(), m);
    }
    drop(st);
    assert!(matches!(
        mallory.dev.repo().open_shared(id),
        Err(Error::NotFound)
    ));
    assert!(mallory.dev.repo().join_from_head(id, NOW).is_err());
    assert!(mallory.dev.repo().shared_vaults().unwrap().is_empty());
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
