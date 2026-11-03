//! Shared zones over an in-memory mailbox (sharing plan 4, Task 1): the
//! share actions run against the server, then each zone syncs through its
//! own driver. Accounts come from the core's sharing harness (`#[path]`);
//! their private zones sync on the core's in-memory server, their shared
//! zones on `FakeMailbox` through `ZoneSync`.

#[path = "../../onepass-core/tests/common/mod.rs"]
mod common;
#[path = "../../onepass-core/tests/share_accts/mod.rs"]
mod share_accts;
#[path = "../../onepass-core/tests/share_common/mod.rs"]
mod share_common;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use common::*;
use onepass_core::contact::{ContactLevel, pair_id};
use onepass_core::repo::rekey::AccessRefusal;
use onepass_core::share::{
    AccessTarget, Role, ShareAction, ZoneSeed, open_zone_credential, verify_contact_zone_offer,
};
use onepass_core::store::{RecordStore, Zone};
use onepass_mailbox::testing::{FAKE_BASE_URL, FakeMailbox, FakeMailboxClient};
use onepass_mailbox::{Credential, Endpoint, MailboxApi, MailboxError};
use onepass_sync::policy::CURSOR_KEY;
use onepass_sync::{
    Connect, MailboxTransport, RoundStatus, SyncDriver, ZoneRoundReport, ZoneSeedStore, ZoneSync,
};
use share_accts::*;
use zeroize::Zeroizing;

const OTHER_URL: &str = "https://other.fake.invalid/functions/v1/mailbox";

// ------------------------------------------------------------ harness

/// Mailbox servers by URL; a server marked down answers `Offline`.
#[derive(Clone, Default)]
struct Net(Arc<Mutex<Vec<(String, FakeMailbox, bool)>>>);

impl Net {
    fn with(fake: &FakeMailbox) -> Net {
        let n = Net::default();
        n.add(FAKE_BASE_URL, fake);
        n
    }

    fn add(&self, url: &str, fake: &FakeMailbox) {
        fake.set_base_url(url);
        self.0
            .lock()
            .unwrap()
            .push((url.to_string(), fake.clone(), true));
    }

    fn set_up(&self, url: &str, up: bool) {
        for s in self.0.lock().unwrap().iter_mut() {
            if s.0 == url {
                s.2 = up;
            }
        }
    }
}

impl Connect for Net {
    type Api = FakeMailboxClient;

    fn connect(
        &self,
        url: &str,
        _extra_ca_pem: Option<&str>,
        seed: &[u8; 32],
    ) -> std::result::Result<FakeMailboxClient, MailboxError> {
        let servers = self.0.lock().unwrap();
        let (_, fake, up) = servers
            .iter()
            .find(|s| s.0 == url)
            .ok_or(MailboxError::Offline)?;
        if !up {
            return Err(MailboxError::Offline);
        }
        Ok(fake.client(Credential::from_seed(seed)?))
    }
}

/// The keychain of one device.
#[derive(Clone, Default)]
struct Seeds(Arc<Mutex<HashMap<[u8; 16], [u8; 32]>>>);

impl ZoneSeedStore for Seeds {
    fn get(&self, mailbox_id: [u8; 16]) -> Option<Zeroizing<[u8; 32]>> {
        self.0
            .lock()
            .unwrap()
            .get(&mailbox_id)
            .copied()
            .map(Zeroizing::new)
    }

    fn put(&self, mailbox_id: [u8; 16], seed: &[u8; 32]) {
        self.0.lock().unwrap().insert(mailbox_id, *seed);
    }

    fn delete(&self, mailbox_id: [u8; 16]) {
        self.0.lock().unwrap().remove(&mailbox_id);
    }
}

/// One account, its keychain and its zone sync.
struct Side {
    acct: Acct,
    seeds: Seeds,
    net: Net,
    zones: ZoneSync<Net>,
}

impl Side {
    fn new(acct: Acct, net: &Net) -> Side {
        let seeds = Seeds::default();
        let zones = zone_sync(&seeds, net);
        Side {
            acct,
            seeds,
            net: net.clone(),
            zones,
        }
    }

    /// The zone sync made again (as after an app restart): drivers and
    /// their clients are new.
    fn restart(&mut self) {
        self.zones = zone_sync(&self.seeds, &self.net);
    }

    /// The private zone, then the zone round unlocked, then the shared
    /// heads followed (as the app does after every round).
    fn round(&mut self) -> ZoneRoundReport {
        sync(&mut self.acct.server, &mut self.acct.dev).unwrap();
        let mut store = self.acct.dev.store();
        let r = self
            .zones
            .run_round(Some(self.acct.dev.repo()), &mut store, NOW);
        self.acct.dev.repo().shared_vaults().unwrap();
        r
    }

    /// The zone round with the session locked.
    fn locked_round(&mut self) -> ZoneRoundReport {
        let mut store = self.acct.dev.store();
        self.zones.run_round(None, &mut store, NOW)
    }

    fn id(&mut self) -> Id {
        account_id(&mut self.acct.dev)
    }
}

fn zone_sync(seeds: &Seeds, net: &Net) -> ZoneSync<Net> {
    ZoneSync::with_connect(
        Box::new(seeds.clone()),
        Endpoint {
            base_url: FAKE_BASE_URL.into(),
            extra_ca_pem: None,
        },
        net.clone(),
    )
}

/// `x` makes the pair's mailbox and offers it; `y` takes its credential
/// from the offer (the verification session stands in).
fn contact_pair(x: &mut Side, y: &mut Side) -> Zone {
    let card = y.acct.dev.repo().own_contact_card("peer", NOW).unwrap();
    let bytes = x
        .zones
        .contact_zone_create(x.acct.dev.repo(), &card, NOW)
        .unwrap();
    let xid = x.id();
    let yid = y.id();
    let zone = Zone::Contact(pair_id(xid, yid));
    let x_sign = x.acct.dev.repo().account().params.signing_pub.clone();
    let me_y = me(&mut y.acct.dev);
    let offer = verify_contact_zone_offer(&bytes, &x_sign, &me_y, pair_id(xid, yid)).unwrap();
    let seed = open_zone_credential(
        y.acct.dev.repo().account().keyset(),
        &offer.credential,
        zone,
        offer.home.mailbox_id,
        &me_y,
    )
    .unwrap();
    y.acct
        .dev
        .repo()
        .test_write_zone_access(AccessTarget::Zone(zone), Some(offer.home), &seed)
        .unwrap();
    zone
}

/// Alice holds "Famille" (not shared yet) and Bob; both pinned
/// `Verified`; their pair's mailbox exists.
fn alice_and_bob(net: &Net) -> (Side, Side, Id, Zone) {
    let (dev, sk, fam, _items) = with_family();
    let mut a = Side::new(Acct::of(dev, sk), net);
    let mut b = Side::new(Acct::new(), net);
    pin(&mut a.acct.dev, &mut b.acct.dev, ContactLevel::Verified);
    pin(&mut b.acct.dev, &mut a.acct.dev, ContactLevel::Verified);
    let pair = contact_pair(&mut a, &mut b);
    (a, b, fam.id, pair)
}

/// Alice shares "Famille" with Bob at `role`; Bob accepts; both synced.
fn shared_pair(net: &Net, role: Role) -> (Side, Side, Id) {
    let (mut a, mut b, fam, _) = alice_and_bob(net);
    let v = a.acct.dev.vault_named("Famille");
    a.acct.dev.repo().share_vault(&v, NOW).unwrap();
    a.round();
    let bob = b.id();
    a.acct
        .dev
        .repo()
        .add_member(fam, bob, role, NOW + 1)
        .unwrap();
    a.round();
    b.round();
    let invites = b.acct.dev.repo().share_invites().unwrap();
    assert_eq!(invites.len(), 1, "Bob sees the invite");
    b.acct
        .dev
        .repo()
        .accept_share_invite(invites[0].id, NOW + 2)
        .unwrap();
    b.round();
    a.round();
    b.round();
    (a, b, fam)
}

fn item_ids(d: &mut Device, vault: Id) -> Vec<Id> {
    let v = shared(d, vault);
    let mut ids: Vec<Id> = d.repo().items(&v).unwrap().iter().map(|i| i.id).collect();
    ids.sort();
    ids
}

fn status_of(r: &ZoneRoundReport, zone: Zone) -> Option<RoundStatus> {
    r.zones
        .iter()
        .find(|(z, _)| *z == zone)
        .map(|(_, s)| s.clone())
}

// ------------------------------------------------------------ tests

#[test]
fn share_actions_run_in_order_then_acknowledged() {
    let fake = FakeMailbox::new();
    let net = Net::with(&fake);
    let (mut a, mut b, fam, _) = alice_and_bob(&net);
    let v = a.acct.dev.vault_named("Famille");
    a.acct.dev.repo().share_vault(&v, NOW).unwrap();
    let queued = a.acct.dev.repo().pending_share_actions().unwrap();
    assert!(matches!(
        queued.as_slice(),
        [ShareAction::CreateZoneMailbox { .. }]
    ));
    let r = a.round();
    assert_eq!(r.actions_done, 1);
    let access = a
        .acct
        .dev
        .repo()
        .zone_access(AccessTarget::Zone(Zone::Vault(fam)))
        .unwrap()
        .unwrap()
        .0;
    let home = access.home.expect("the zone got its home");
    assert_eq!(home.url, FAKE_BASE_URL);
    assert!(a.seeds.get(home.mailbox_id).is_some(), "seed cached");
    // The anchor was made on first use (Alice syncs elsewhere).
    let anchor = a
        .acct
        .dev
        .repo()
        .zone_access(AccessTarget::Anchor)
        .unwrap()
        .unwrap()
        .0;
    assert!(anchor.home.is_some());

    let bob = b.id();
    a.acct
        .dev
        .repo()
        .add_member(fam, bob, Role::Write, NOW + 1)
        .unwrap();
    let r = a.round();
    assert_eq!(r.actions_done, 1, "the grant ran");
    assert!(
        a.acct
            .dev
            .repo()
            .pending_share_actions()
            .unwrap()
            .is_empty()
    );
    assert_eq!(status_of(&r, Zone::Vault(fam)), Some(RoundStatus::Idle));
}

#[test]
fn grant_before_create_waits() {
    let fake = FakeMailbox::new();
    let net = Net::with(&fake);
    let (mut a, _b, fam, _) = alice_and_bob(&net);
    let v = a.acct.dev.vault_named("Famille");
    a.acct.dev.repo().share_vault(&v, NOW).unwrap();
    net.set_up(FAKE_BASE_URL, false);
    let r = a.round();
    assert_eq!(r.actions_done, 0);
    let queued = a.acct.dev.repo().pending_share_actions().unwrap();
    assert!(
        matches!(queued.as_slice(), [ShareAction::CreateZoneMailbox { .. }]),
        "the create stays queued: {queued:?}"
    );
    net.set_up(FAKE_BASE_URL, true);
    a.restart();
    let r = a.round();
    assert_eq!(r.actions_done, 1);
    assert!(
        a.acct
            .dev
            .repo()
            .pending_share_actions()
            .unwrap()
            .is_empty()
    );
    let _ = fam;
}

#[test]
fn zone_round_after_actions() {
    let fake = FakeMailbox::new();
    let net = Net::with(&fake);
    let (mut a, mut b, fam) = shared_pair(&net, Role::Write);
    assert_eq!(
        item_ids(&mut b.acct.dev, fam),
        item_ids(&mut a.acct.dev, fam)
    );
    let v = shared(&mut b.acct.dev, fam);
    let mine = login(fam, "bob-wrote", NOW + 10);
    b.acct.dev.repo().save_item(&v, mine.clone()).unwrap();
    let r = b.round();
    assert_eq!(status_of(&r, Zone::Vault(fam)), Some(RoundStatus::Idle));
    let r = a.round();
    assert!(r.changed);
    assert!(item_ids(&mut a.acct.dev, fam).contains(&mine.id));
}

#[test]
fn locked_round_syncs_zones_from_cached_seeds() {
    let fake = FakeMailbox::new();
    let net = Net::with(&fake);
    let (mut a, mut b, fam) = shared_pair(&net, Role::Write);
    let zone = Zone::Vault(fam);
    let before = b
        .acct
        .dev
        .store()
        .list_in(zone, RecordKind::Item)
        .unwrap()
        .len();
    let v = shared(&mut a.acct.dev, fam);
    a.acct
        .dev
        .repo()
        .save_item(&v, login(fam, "while-bob-sleeps", NOW + 20))
        .unwrap();
    a.round();
    b.acct.dev.lock();
    b.restart();
    let r = b.locked_round();
    assert_eq!(status_of(&r, zone), Some(RoundStatus::Idle));
    assert!(r.changed);
    let after = b
        .acct
        .dev
        .store()
        .list_in(zone, RecordKind::Item)
        .unwrap()
        .len();
    assert_eq!(after, before + 1);
}

#[test]
fn revoked_credential_goes_to_core() {
    let fake = FakeMailbox::new();
    let net = Net::with(&fake);
    let (mut a, mut b, fam) = shared_pair(&net, Role::Read);
    let zone = Zone::Vault(fam);
    let target = AccessTarget::Zone(zone);
    let bob_cred = b
        .acct
        .dev
        .repo()
        .zone_access(target)
        .unwrap()
        .unwrap()
        .0
        .credential_id;
    let (alice_access, alice_seed) = a.acct.dev.repo().zone_access(target).unwrap().unwrap();
    let home = alice_access.home.unwrap();
    // The server drops Bob without any signed removal.
    let mut client = fake.client(Credential::from_seed(alice_seed.expose()).unwrap());
    client.open(home.mailbox_id);
    client.revoke(bob_cred).unwrap();
    let before = item_ids(&mut b.acct.dev, fam);
    let r = b.round();
    assert_eq!(r.refusals, vec![(zone, AccessRefusal::Unconfirmed)]);
    // Nothing erased: the vault stays readable from the local copy.
    assert_eq!(item_ids(&mut b.acct.dev, fam), before);
}

#[test]
fn unreachable_zone_does_not_stop_others() {
    let fake = FakeMailbox::new();
    let other = FakeMailbox::new();
    let net = Net::with(&fake);
    net.add(OTHER_URL, &other);
    let (dev, sk, fam, _items) = with_family();
    let mut a = Side::new(Acct::of(dev, sk), &net);
    let mut b = Side::new(Acct::new(), &net);
    pin(&mut a.acct.dev, &mut b.acct.dev, ContactLevel::Verified);
    pin(&mut b.acct.dev, &mut a.acct.dev, ContactLevel::Verified);
    // The pair lives on the other server (Alice's account mailbox there).
    let parent_seed = ZoneSeed::generate().unwrap();
    let mut parent_client = other.client(Credential::from_seed(parent_seed.expose()).unwrap());
    let parent = parent_client.create(None, b"").unwrap();
    let parent_seed = Zeroizing::new(*parent_seed.expose());
    a.zones.set_parent(Some(onepass_sync::ParentMailbox {
        url: OTHER_URL.into(),
        extra_ca_pem: None,
        mailbox_id: parent.mailbox_id,
        seed: parent_seed,
    }));
    let pair = contact_pair(&mut a, &mut b);
    // The vault zone lives on the default server (the anchor).
    a.zones.set_parent(None);
    let v = a.acct.dev.vault_named("Famille");
    a.acct.dev.repo().share_vault(&v, NOW).unwrap();
    let r = a.round();
    assert_eq!(status_of(&r, Zone::Vault(fam.id)), Some(RoundStatus::Idle));
    assert_eq!(status_of(&r, pair), Some(RoundStatus::Idle));

    net.set_up(FAKE_BASE_URL, false);
    a.restart();
    let r = a.round();
    assert_eq!(
        status_of(&r, Zone::Vault(fam.id)),
        Some(RoundStatus::Offline)
    );
    assert_eq!(status_of(&r, pair), Some(RoundStatus::Idle));
    // Still readable from the local copy.
    assert_eq!(item_ids(&mut a.acct.dev, fam.id).len(), 3);
}

#[test]
fn private_driver_unchanged() {
    // The private driver keeps its keys and its home check; the X1 driver
    // tests (driver.rs, hostile_mailbox.rs, mailbox_e2e.rs) run unchanged.
    let fake = FakeMailbox::new();
    let api = fake.client(Credential::generate().unwrap());
    let d = SyncDriver::new(
        MailboxTransport::new(api),
        onepass_core::synchome::SyncBackend::CloudKit,
    );
    assert_eq!(d.cursor_key(), CURSOR_KEY);
    assert_eq!(d.zone(), Zone::Private);
    let api = fake.client(Credential::generate().unwrap());
    let z = SyncDriver::for_zone(MailboxTransport::new(api), Zone::Vault(Id([7; 16])));
    assert_eq!(z.cursor_key(), format!("zone.01{}.cursor", "07".repeat(16)));
}

#[test]
fn removal_revokes_after_phase_b() {
    let fake = FakeMailbox::new();
    let net = Net::with(&fake);
    let (mut a, mut b, fam) = shared_pair(&net, Role::Write);
    let zone = Zone::Vault(fam);
    let bob = b.id();
    a.acct.dev.repo().remove_member(fam, bob, NOW + 30).unwrap();
    // The revocation is queued only once the new body and manifest are on
    // the server (spec 13.8).
    assert!(
        !a.acct
            .dev
            .repo()
            .pending_share_actions()
            .unwrap()
            .iter()
            .any(|x| matches!(x, ShareAction::RevokeCredential { .. })),
        "no revoke before the push"
    );
    for _ in 0..3 {
        a.round();
    }
    assert!(
        a.acct
            .dev
            .repo()
            .pending_share_actions()
            .unwrap()
            .is_empty()
    );
    let r = b.round();
    assert_eq!(r.refusals, vec![(zone, AccessRefusal::Removed)]);
    assert!(
        !b.acct
            .dev
            .repo()
            .shared_vaults()
            .unwrap()
            .iter()
            .any(|s| s.vault_id == fam),
        "Bob's copy is erased"
    );
}

#[test]
fn transfer_moves_zone_and_deletes_old() {
    let fake = FakeMailbox::new();
    let net = Net::with(&fake);
    let (mut a, mut b, fam) = shared_pair(&net, Role::Manage);
    let (old, old_seed) = a
        .acct
        .dev
        .repo()
        .zone_access(AccessTarget::Zone(Zone::Vault(fam)))
        .unwrap()
        .unwrap();
    let old = old.home.unwrap();
    let info = b.acct.dev.repo().transfer_by_copy(fam, NOW + 40).unwrap();
    for _ in 0..3 {
        b.round();
        a.round();
    }
    let new_home = b
        .acct
        .dev
        .repo()
        .zone_access(AccessTarget::Zone(Zone::Vault(info.vault_id)))
        .unwrap()
        .unwrap()
        .0
        .home
        .expect("the copy got its mailbox");
    assert_ne!(new_home.mailbox_id, old.mailbox_id);
    assert!(
        a.acct
            .dev
            .repo()
            .pending_share_actions()
            .unwrap()
            .is_empty()
    );
    // The old mailbox is gone.
    let mut probe = fake.client(Credential::from_seed(old_seed.expose()).unwrap());
    probe.open(old.mailbox_id);
    assert!(
        probe.info().is_err(),
        "the owner's credential no longer opens it"
    );
    assert!(a.seeds.get(old.mailbox_id).is_none(), "seed forgotten");
}
