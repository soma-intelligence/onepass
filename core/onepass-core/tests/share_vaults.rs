//! Shared vaults on the repository (sharing plan 2, Tasks 6 to 10).

mod common;
mod share_common;

use common::*;
use onepass_core::contact::{ContactLevel, pair_id};
use onepass_core::device_keys::{DeviceKeys, DevicePublic};
use onepass_core::devices::{DeviceKind, DeviceMode};
use onepass_core::lineage::{
    GenesisBody, LINEAGE_FORMAT, LineageRecord, RosterEntry, identity_id, sign_genesis,
};
use onepass_core::repo::rekey::AccessRefusal;
use onepass_core::share::{
    AccessTarget, InviteRecord, MEMBERSHIP_FORMAT, Member, MemberKey, MemberRef, MembershipBody,
    MembershipReason, RekeyReason, RekeyRequest, Role, ShareAction, ShareInvite, SignedMembership,
    ZONE_ACCESS_KIND, ZoneHome, ZoneMailboxKind, ZoneRole, ZoneSeed, identity_pub_hash,
    member_key_id, open_member_key, open_zone_credential, server_role, sign_membership,
    wrap_zone_credential,
};
use onepass_core::store::{MemoryStore, RecordStore, Zone};
use onepass_core::sync::PhaseOutcome;
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

    /// One sync, then the shared heads followed, as the app does after
    /// every sync (a device that skips a body signed by a manager raised
    /// in between cannot verify it, spec 7.2 rule 2).
    fn sync(&mut self, zs: &mut Zones) {
        zsync(&mut self.server, zs, &mut self.dev);
        self.dev.repo().shared_vaults().unwrap();
    }
}

/// Alice shares "Famille" (its zone has a home) and pins Bob at
/// `level`; Bob pins Alice `Verified`; their contact zone exists.
fn alice_and_bob(level: ContactLevel) -> (Zones, Acct, Acct, Id, Vec<Item>) {
    alice_and_bob_seen(level, ContactLevel::Verified)
}

/// Alice holds Bob at `level`, Bob holds Alice at `seen`.
fn alice_and_bob_seen(
    level: ContactLevel,
    seen: ContactLevel,
) -> (Zones, Acct, Acct, Id, Vec<Item>) {
    let mut zs = Zones::default();
    let (dev, sk, fam, items) = with_family();
    let mut a = Acct::of(dev, sk);
    let mut b = Acct::new();
    pin(&mut a.dev, &mut b.dev, level);
    pin(&mut b.dev, &mut a.dev, seen);
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

/// A manager Bob holds only at `Link` may give him a `Read` place, on
/// every device, never a place where Bob writes (decision 1, A13).
#[test]
fn a13_unverified_manager_gives_read_only() {
    let (mut zs, mut a, mut b, id, _) =
        alice_and_bob_seen(ContactLevel::Verified, ContactLevel::Link);
    let bob = account_id(&mut b.dev);
    let mut b2 = Device::empty();
    pull(&b.server, &mut b2);
    b2.unlock(&b.sk);
    a.dev
        .repo()
        .add_member(id, bob, Role::Write, NOW + 1)
        .unwrap();
    settle(&mut zs, &mut [&mut a, &mut b]);
    assert!(b.dev.repo().share_invites().unwrap().is_empty());
    // The head names Bob a writer: no device of his joins from it.
    b.sync(&mut zs);
    zsync(&mut b.server, &mut zs, &mut b2);
    assert!(b2.repo().join_from_head(id, NOW + 2).is_err());

    let (mut zs, mut a, mut b, id, items) =
        alice_and_bob_seen(ContactLevel::Verified, ContactLevel::Link);
    let bob = account_id(&mut b.dev);
    let mut b2 = Device::empty();
    pull(&b.server, &mut b2);
    b2.unlock(&b.sk);
    a.dev
        .repo()
        .add_member(id, bob, Role::Read, NOW + 1)
        .unwrap();
    settle(&mut zs, &mut [&mut a, &mut b]);
    let inv = b.dev.repo().share_invites().unwrap()[0].id;
    let joined = b.dev.repo().accept_share_invite(inv, NOW + 2).unwrap();
    assert_eq!(joined.role, Role::Read);
    b.sync(&mut zs);
    zsync(&mut b.server, &mut zs, &mut b2);
    zsync(&mut b.server, &mut zs, &mut b2);
    let info = b2.repo().join_from_head(id, NOW + 3).unwrap();
    assert_eq!(info.role, Role::Read);
    let v = shared(&mut b2, id);
    assert_eq!(ids(&b2.repo().items(&v).unwrap()), ids(&items));
}

// ---- Task 9: removal with resealing ----

/// Alice (owner) shares "Famille" with Bob (`Write`) and Carol (`role`),
/// both accepted and synced.
fn trio(carol_role: Role) -> (Zones, Acct, Acct, Acct, Id, Vec<Item>) {
    let (mut zs, mut a, mut b, id, items) = alice_and_bob(ContactLevel::Verified);
    let mut c = Acct::new();
    pin(&mut a.dev, &mut c.dev, ContactLevel::Verified);
    pin(&mut c.dev, &mut a.dev, ContactLevel::Verified);
    contact_zone(&mut a.dev, &mut c.dev);
    let bob = account_id(&mut b.dev);
    let carol = account_id(&mut c.dev);
    a.dev
        .repo()
        .add_member(id, bob, Role::Write, NOW + 1)
        .unwrap();
    a.dev
        .repo()
        .add_member(id, carol, carol_role, NOW + 1)
        .unwrap();
    settle(&mut zs, &mut [&mut a, &mut b, &mut c]);
    for x in [&mut b, &mut c] {
        let inv = x.dev.repo().share_invites().unwrap()[0].id;
        x.dev.repo().accept_share_invite(inv, NOW + 2).unwrap();
    }
    settle(&mut zs, &mut [&mut a, &mut b, &mut c]);
    (zs, a, b, c, id, items)
}

/// The item rows of the vault zone on its server that `v` opens.
fn opened_on_server(zs: &mut Zones, v: &Vault) -> Vec<Item> {
    let server = zs.server(Zone::Vault(v.id));
    let mut out = Vec::new();
    for ((kind, _), e) in &server.records {
        if *kind != RecordKind::Item {
            continue;
        }
        let Some(r) = &e.record else { continue };
        let (_, body) = split_item_record(&r.data).unwrap();
        let rec = ItemRecord::decode(body).unwrap();
        if let Ok(item) = v.open_item(&rec) {
            out.push(item);
        }
    }
    out
}

fn item_rows_on_server(zs: &mut Zones, id: Id) -> usize {
    zs.server(Zone::Vault(id))
        .records
        .iter()
        .filter(|((k, _), e)| *k == RecordKind::Item && e.record.is_some())
        .count()
}

fn push_phase(d: &Device, id: Id) -> Option<u8> {
    d.store()
        .share_state(id)
        .unwrap()
        .and_then(|s| s.push)
        .map(|p| p.phase)
}

#[test]
fn a4_removed_reads_nothing_new() {
    let (mut zs, mut a, mut b, mut c, id, _) = trio(Role::Read);
    let carol_old = shared(&mut c.dev, id);
    let carol = account_id(&mut c.dev);
    let carol_ref = me(&mut c.dev);
    let out = a.dev.repo().remove_member(id, carol, NOW + 3).unwrap();
    assert_eq!(out.generation, 2);
    settle(&mut zs, &mut [&mut a, &mut b]);
    assert_eq!(push_phase(&a.dev, id), None);
    let va = shared(&mut a.dev, id);
    a.dev.repo().save_item(&va, login(id, "dave", 700)).unwrap();
    settle(&mut zs, &mut [&mut a, &mut b]);
    // No row on the server opens with Carol's old key.
    assert!(item_rows_on_server(&mut zs, id) > 0);
    assert!(opened_on_server(&mut zs, &carol_old).is_empty());
    // No envelope of generation 2 for Carol.
    let mk = member_key_id(id, 2, &carol_ref);
    assert!(
        zs.server(Zone::Vault(id))
            .live(RecordKind::MemberKey, mk)
            .is_none()
    );
    // Bob reads everything at generation 2.
    let vb = shared(&mut b.dev, id);
    assert!(users(&b.dev.repo().items(&vb).unwrap()).contains(&"dave".to_string()));
}

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

fn revokes(d: &mut Device) -> usize {
    d.repo()
        .pending_share_actions()
        .unwrap()
        .iter()
        .filter(|a| matches!(a, ShareAction::RevokeCredential { .. }))
        .count()
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

fn generation(d: &Device, id: Id) -> u32 {
    d.store().share_state(id).unwrap().unwrap().head.generation
}

/// A rekey request signed by `who` about `vault_id` at generation `g`,
/// written straight into `into`'s copy of the zone.
fn plant_request(who: &mut Device, into: &mut Device, vault_id: Id, g: u32) {
    let signer = me(who);
    let req = RekeyRequest::sign(
        vault_id,
        None,
        RekeyReason::MemberRotation,
        g,
        signer,
        &who.repo().account().keyset().signing,
    )
    .unwrap();
    into.repo()
        .store_mut()
        .put_all_zoned(
            vec![(
                Zone::Vault(vault_id),
                Record {
                    kind: RecordKind::RekeyRequest,
                    id: req.id(),
                    version: 1,
                    data: req.encode(),
                },
                None,
            )],
            vec![],
            None,
            &[],
        )
        .unwrap();
}

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

/// `trio(carol_role)` with Bob raised to manager, and Dan, a contact of
/// Bob only.
fn two_managers(carol_role: Role) -> (Zones, Acct, Acct, Acct, Acct, Id) {
    let (mut zs, mut a, mut b, mut c, id, _) = trio(carol_role);
    let bob = account_id(&mut b.dev);
    a.dev
        .repo()
        .set_role(id, bob, Role::Manage, NOW + 3)
        .unwrap();
    settle(&mut zs, &mut [&mut a, &mut b, &mut c]);
    let mut d = Acct::new();
    pin(&mut b.dev, &mut d.dev, ContactLevel::Verified);
    pin(&mut d.dev, &mut b.dev, ContactLevel::Verified);
    contact_zone(&mut b.dev, &mut d.dev);
    (zs, a, b, c, d, id)
}

fn head_hash(d: &mut Device, id: Id) -> [u8; 32] {
    d.repo().shared_vaults().unwrap();
    d.store().share_state(id).unwrap().unwrap().head.hash()
}

fn head_members(d: &mut Device, id: Id) -> Vec<(Id, Role)> {
    d.repo().shared_vaults().unwrap();
    d.store()
        .share_state(id)
        .unwrap()
        .unwrap()
        .head
        .members
        .iter()
        .map(|m| (m.account_id, m.role))
        .collect()
}

fn role_of(d: &mut Device, id: Id, who: Id) -> Option<Role> {
    head_members(d, id)
        .into_iter()
        .find(|(a, _)| *a == who)
        .map(|(_, r)| r)
}

/// Alice and Bob both act on the vault offline, then sync in the given
/// order and settle.
fn race(zs: &mut Zones, a: &mut Acct, b: &mut Acct, c: &mut Acct, alice_first: bool) {
    if alice_first {
        a.sync(zs);
        b.sync(zs);
    } else {
        b.sync(zs);
        a.sync(zs);
    }
    settle(zs, &mut [a, b, c]);
}

#[test]
fn a20_concurrent_managers() {
    for alice_first in [true, false] {
        let (mut zs, mut a, mut b, mut c, mut d, id) = two_managers(Role::Read);
        let carol = account_id(&mut c.dev);
        let carol_ref = me(&mut c.dev);
        let dan = account_id(&mut d.dev);
        a.dev.repo().remove_member(id, carol, NOW + 4).unwrap();
        b.dev
            .repo()
            .add_member(id, dan, Role::Read, NOW + 4)
            .unwrap();
        race(&mut zs, &mut a, &mut b, &mut c, alice_first);
        settle(&mut zs, &mut [&mut a, &mut b, &mut d]);
        let inv = d.dev.repo().share_invites().unwrap();
        assert_eq!(inv.len(), 1, "alice_first={alice_first}");
        d.dev
            .repo()
            .accept_share_invite(inv[0].id, NOW + 5)
            .unwrap();
        settle(&mut zs, &mut [&mut a, &mut b, &mut d]);
        assert_eq!(head_hash(&mut a.dev, id), head_hash(&mut b.dev, id));
        assert_eq!(head_hash(&mut a.dev, id), head_hash(&mut d.dev, id));
        assert_eq!(role_of(&mut a.dev, id, carol), None);
        assert_eq!(role_of(&mut a.dev, id, dan), Some(Role::Read));
        let g = generation(&a.dev, id);
        assert!(g >= 2, "generation {g}");
        let dan_ref = me(&mut d.dev);
        let server = zs.server(Zone::Vault(id));
        assert!(
            server
                .live(RecordKind::MemberKey, member_key_id(id, g, &dan_ref))
                .is_some()
        );
        assert!(
            server
                .live(RecordKind::MemberKey, member_key_id(id, g, &carol_ref))
                .is_none()
        );
        // Dan reads the vault at the final generation.
        let vd = shared(&mut d.dev, id);
        assert!(!d.dev.repo().items(&vd).unwrap().is_empty());
    }
}

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

/// `trio(Role::Read)` with Bob raised to manager and holding Carol in his
/// book (contact zone included).
fn transfer_cast() -> (Zones, Acct, Acct, Acct, Id, Vec<Item>) {
    let (mut zs, mut a, mut b, mut c, id, items) = trio(Role::Read);
    let bob = account_id(&mut b.dev);
    a.dev
        .repo()
        .set_role(id, bob, Role::Manage, NOW + 3)
        .unwrap();
    settle(&mut zs, &mut [&mut a, &mut b, &mut c]);
    pin(&mut b.dev, &mut c.dev, ContactLevel::Verified);
    pin(&mut c.dev, &mut b.dev, ContactLevel::Verified);
    contact_zone(&mut b.dev, &mut c.dev);
    (zs, a, b, c, id, items)
}

/// Bob copies the vault and the transport gives the new zone its home.
fn transfer(zs: &mut Zones, b: &mut Acct, id: Id) -> Id {
    let info = b.dev.repo().transfer_by_copy(id, NOW + 4).unwrap();
    assert_ne!(info.vault_id, id);
    assert!(info.owner);
    b.dev
        .repo()
        .set_zone_home(AccessTarget::Zone(Zone::Vault(info.vault_id)), home(2))
        .unwrap();
    b.sync(zs);
    info.vault_id
}

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
