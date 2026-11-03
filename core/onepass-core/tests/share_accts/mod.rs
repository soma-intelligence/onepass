//! Accounts, contacts and shared vaults for the sharing tests: one
//! private server per account, zones on `share_common`. Used by
//! `share_vaults.rs` and `sharing_attacks.rs`.

#![allow(dead_code, unused_imports)]

use super::common::*;
use super::share_common::*;
use onepass_core::contact::{ContactLevel, ContactState, pair_id};
use onepass_core::device_keys::{DeviceKeys, DevicePublic};
use onepass_core::devices::{DeviceKind, DeviceMode};
use onepass_core::lineage::{
    GenesisBody, LINEAGE_FORMAT, LineageRecord, RosterEntry, identity_id, sign_genesis,
};
use onepass_core::lineage::{RotationReason, rotation_code};
use onepass_core::repo::members::AdoptionProof;
use onepass_core::repo::rekey::AccessRefusal;
use onepass_core::repo::rotate::RotateRequest;
use onepass_core::share::{
    AccessTarget, InviteRecord, MEMBERSHIP_FORMAT, Member, MemberKey, MemberLineageRecord,
    MemberRef, MembershipBody, MembershipReason, RekeyReason, RekeyRequest, Role, ShareAction,
    ShareInvite, SignedMembership, ZONE_ACCESS_KIND, ZoneHome, ZoneMailboxKind, ZoneRole, ZoneSeed,
    identity_pub_hash, member_key_id, open_member_key, open_zone_credential, server_role,
    sign_membership, wrap_zone_credential,
};
use onepass_core::store::{MemoryStore, RecordStore, Zone};
use onepass_core::sync::PhaseOutcome;
use onepass_core::trust::{LineageHead, TrustLevel, TrustState};

pub const NOW: i64 = 1_800_000_000;

/// A device with "Personnel" and "Famille", three items in "Famille" (one
/// archived, one trashed).
pub fn with_family() -> (Device, SecretKey, Vault, Vec<Item>) {
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
pub fn open_zone(a: &mut Device, vault_id: Id) -> (Vault, Vec<Item>, Vec<u64>) {
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

/// A and B, two devices of one account; "Famille" shared on A, synced.
pub fn two_devices_shared() -> (Server, Zones, Device, Device, Id, Vec<Item>) {
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

pub fn shared(dev: &mut Device, id: Id) -> Vault {
    dev.repo().shared_vaults().unwrap();
    dev.repo()
        .vaults()
        .unwrap()
        .into_iter()
        .find(|v| v.id == id)
        .expect("shared vault listed")
}

pub fn ids(items: &[Item]) -> Vec<Id> {
    let mut v: Vec<Id> = items.iter().map(|i| i.id).collect();
    v.sort();
    v
}

pub fn home(n: u8) -> ZoneHome {
    ZoneHome {
        url: format!("https://box{n}.example.org"),
        mailbox_id: [n; 16],
        extra_ca_pem: None,
    }
}

pub fn account_id(d: &mut Device) -> Id {
    d.repo().account().params.account_id
}

pub fn me(d: &mut Device) -> MemberRef {
    d.repo().me()
}

/// `x` pins `y`'s card at `level`.
pub fn pin(x: &mut Device, y: &mut Device, level: ContactLevel) {
    let card = y.repo().own_contact_card("peer", NOW).unwrap();
    x.repo()
        .test_pin_contact(&card, level, [1; 32], NOW)
        .unwrap();
}

/// The contact zone of `x` and `y`, with a home on both sides (Task 7b
/// stands in).
pub fn contact_zone(x: &mut Device, y: &mut Device) -> Zone {
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
pub struct Acct {
    pub server: Server,
    pub dev: Device,
    pub sk: SecretKey,
    /// The device keys the trust state pins (a rotation signs with them).
    pub keys: DeviceKeys,
    /// A second roster device, never paired here: one a rotation can
    /// revoke.
    pub spare: Option<Id>,
}

pub fn entry_of(p: &DevicePublic) -> RosterEntry {
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
    pub fn new() -> Acct {
        let (dev, sk) = Device::create();
        Acct::of(dev, sk)
    }

    /// `dev` synced once, then given a lineage genesis and a trust state
    /// (as `contact_invite.rs`), so that it has a contact card.
    pub fn of(dev: Device, sk: SecretKey) -> Acct {
        Acct::of_with(dev, sk, false)
    }

    /// `of`, with a spare roster device when `spare`.
    pub fn of_with(mut dev: Device, sk: SecretKey, spare: bool) -> Acct {
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
        let spare = spare.then(|| {
            let other = DeviceKeys::generate_software().unwrap();
            let p = other.public(Id::new()).unwrap();
            trust.roster.push(entry_of(&p));
            trust.levels.insert(p.device_id, TrustLevel::Verified);
            p.device_id
        });
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
        Acct {
            server,
            dev,
            sk,
            keys,
            spare,
        }
    }

    /// Rotate this account's keys (`revoke`: the spare device).
    pub fn rotate(&mut self, revoke: bool) -> SecretKey {
        let new_sk = SecretKey::generate().unwrap();
        let revoked: Vec<Id> = if revoke {
            vec![self.spare.expect("a spare device")]
        } else {
            vec![]
        };
        let reason = if revoke {
            RotationReason::Revoke
        } else {
            RotationReason::Rotate
        };
        self.dev
            .repo()
            .rotate(RotateRequest {
                revoke: revoked,
                new_password: None,
                password: PASSWORD,
                secret_key: &self.sk,
                new_secret_key: &new_sk,
                device_keys: &self.keys,
                reason,
                keep_tofu: &[],
            })
            .unwrap();
        new_sk
    }

    /// One sync, then the shared heads followed, as the app does after
    /// every sync (a device that skips a body signed by a manager raised
    /// in between cannot verify it, spec 7.2 rule 2).
    pub fn sync(&mut self, zs: &mut Zones) {
        zsync(&mut self.server, zs, &mut self.dev);
        self.dev.repo().shared_vaults().unwrap();
    }
}

/// Alice shares "Famille" (its zone has a home) and pins Bob at
/// `level`; Bob pins Alice `Verified`; their contact zone exists.
pub fn alice_and_bob(level: ContactLevel) -> (Zones, Acct, Acct, Id, Vec<Item>) {
    alice_and_bob_seen(level, ContactLevel::Verified)
}

/// Alice holds Bob at `level`, Bob holds Alice at `seen`.
pub fn alice_and_bob_seen(
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

pub fn settle(zs: &mut Zones, accts: &mut [&mut Acct]) {
    for _ in 0..2 {
        for a in accts.iter_mut() {
            a.sync(zs);
        }
    }
}

pub fn validation(e: Error) -> (String, &'static str) {
    match e {
        Error::Validation(v) => (v.field, v.reason),
        other => panic!("expected Validation, got {other:?}"),
    }
}

/// A member entry for `d` under its current keys.
pub fn member_of(d: &mut Device, role: Role, level: ContactLevel, credential: u8) -> Member {
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
pub fn forge_invite(
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

/// Alice (owner) shares "Famille" with Bob (`Write`) and Carol (`role`),
/// both accepted and synced.
pub fn trio(carol_role: Role) -> (Zones, Acct, Acct, Acct, Id, Vec<Item>) {
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
pub fn opened_on_server(zs: &mut Zones, v: &Vault) -> Vec<Item> {
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

pub fn item_rows_on_server(zs: &mut Zones, id: Id) -> usize {
    zs.server(Zone::Vault(id))
        .records
        .iter()
        .filter(|((k, _), e)| *k == RecordKind::Item && e.record.is_some())
        .count()
}

pub fn push_phase(d: &Device, id: Id) -> Option<u8> {
    d.store()
        .share_state(id)
        .unwrap()
        .and_then(|s| s.push)
        .map(|p| p.phase)
}

pub fn revokes(d: &mut Device) -> usize {
    d.repo()
        .pending_share_actions()
        .unwrap()
        .iter()
        .filter(|a| matches!(a, ShareAction::RevokeCredential { .. }))
        .count()
}

pub fn generation(d: &Device, id: Id) -> u32 {
    d.store().share_state(id).unwrap().unwrap().head.generation
}

/// A rekey request signed by `who` about `vault_id` at generation `g`,
/// written straight into `into`'s copy of the zone.
pub fn plant_request(who: &mut Device, into: &mut Device, vault_id: Id, g: u32) {
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

/// `trio(carol_role)` with Bob raised to manager, and Dan, a contact of
/// Bob only.
pub fn two_managers(carol_role: Role) -> (Zones, Acct, Acct, Acct, Acct, Id) {
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

pub fn head_hash(d: &mut Device, id: Id) -> [u8; 32] {
    d.repo().shared_vaults().unwrap();
    d.store().share_state(id).unwrap().unwrap().head.hash()
}

pub fn head_members(d: &mut Device, id: Id) -> Vec<(Id, Role)> {
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

pub fn role_of(d: &mut Device, id: Id, who: Id) -> Option<Role> {
    head_members(d, id)
        .into_iter()
        .find(|(a, _)| *a == who)
        .map(|(_, r)| r)
}

/// `trio(Role::Read)` with Bob raised to manager and holding Carol in his
/// book (contact zone included).
pub fn transfer_cast() -> (Zones, Acct, Acct, Acct, Id, Vec<Item>) {
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
pub fn transfer(zs: &mut Zones, b: &mut Acct, id: Id) -> Id {
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

/// Alice (owner, with a spare device) shares "Famille" with Bob (Write).
pub fn rotating_alice() -> (Zones, Acct, Acct, Id, Vec<Item>) {
    let mut zs = Zones::default();
    let (dev, sk, fam, items) = with_family();
    let mut a = Acct::of_with(dev, sk, true);
    let mut b = Acct::new();
    pin(&mut a.dev, &mut b.dev, ContactLevel::Verified);
    pin(&mut b.dev, &mut a.dev, ContactLevel::Verified);
    contact_zone(&mut a.dev, &mut b.dev);
    a.dev.repo().share_vault(&fam, NOW).unwrap();
    a.dev
        .repo()
        .set_zone_home(AccessTarget::Zone(Zone::Vault(fam.id)), home(1))
        .unwrap();
    let bob = account_id(&mut b.dev);
    a.dev
        .repo()
        .add_member(fam.id, bob, Role::Write, NOW + 1)
        .unwrap();
    settle(&mut zs, &mut [&mut a, &mut b]);
    let inv = b.dev.repo().share_invites().unwrap()[0].id;
    b.dev.repo().accept_share_invite(inv, NOW + 2).unwrap();
    settle(&mut zs, &mut [&mut a, &mut b]);
    (zs, a, b, fam.id, items)
}

/// `trio(carol_role)` where Carol rotated her keys and pushed; Alice read
/// the rotation. Returns Carol's new head.
pub fn carol_rotated(carol_role: Role) -> (Zones, Acct, Acct, Acct, Id, [u8; 32]) {
    let (mut zs, mut a, b, mut c, id, _) = trio(carol_role);
    c.rotate(false);
    c.sync(&mut zs);
    a.sync(&mut zs);
    let child = c.dev.store().trust_state().unwrap().unwrap().head.hash;
    (zs, a, b, c, id, child)
}

/// `x` met `y` again face to face: the book pins `y`'s current card
/// `Verified` with transcript `[1; 32]` (removed first: a pin never moves
/// an entry to another head).
pub fn repin_in_person(x: &mut Device, y: &mut Device) {
    let yid = account_id(y);
    x.repo().remove_contact(yid, NOW).unwrap();
    pin(x, y, ContactLevel::Verified);
}

pub fn head_of(d: &Device, id: Id) -> MembershipBody {
    d.store().share_state(id).unwrap().unwrap().head
}

/// Alice and Bob both act on the vault offline, then sync in the given
/// order and settle.
pub fn race(zs: &mut Zones, a: &mut Acct, b: &mut Acct, c: &mut Acct, alice_first: bool) {
    if alice_first {
        a.sync(zs);
        b.sync(zs);
    } else {
        b.sync(zs);
        a.sync(zs);
    }
    settle(zs, &mut [a, b, c]);
}
