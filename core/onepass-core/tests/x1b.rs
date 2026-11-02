//! X1b core (cross-platform spec D.4, D.5): a `SyncHome` signed without
//! being adopted, then adopted; the follower's signed enroll request; the
//! locator and recovery seed derived from the Secret Key.

mod common;

use common::*;
use onepass_core::device_keys::{DEVICE_POP_DOMAIN, DeviceKeys, DevicePublic};
use onepass_core::devices::{DeviceKind, DeviceMode};
use onepass_core::enroll_request::{
    ENROLL_REQUEST_DOMAIN, ENROLL_REQUEST_TTL_SECS, EnrollRequestBody, SignedEnrollRequest,
};
use onepass_core::lineage::RosterEntry;
use onepass_core::mailbox_recovery::{mailbox_locator, mailbox_recovery_seed};
use onepass_core::store::SIDE_KIND_MAILBOX_ENROLL_REQUEST;
use onepass_core::synchome::{SyncBackend, SyncHomeBody};
use onepass_core::trust::{LineageHead, TrustLevel, TrustState};

const T: i64 = 1_790_000_000;
const MBX: [u8; 16] = [9; 16];
const CRED: [u8; 32] = [5; 32];

fn mailbox(n: u8) -> SyncBackend {
    SyncBackend::Mailbox {
        url: format!("https://mailbox{n}.example.org/functions/v1/mailbox"),
        mailbox_id: [n; 16],
    }
}

fn body_of(signed: &[u8]) -> SyncHomeBody {
    onepass_core::synchome::SignedSyncHome::decode(signed)
        .unwrap()
        .body
}

fn two_devices(server: &mut Server) -> (Device, Device) {
    let (mut a, sk) = Device::create();
    sync(server, &mut a).unwrap();
    let mut b = Device::empty();
    pull(server, &mut b);
    b.unlock(&sk);
    (a, b)
}

// ---------------------------------------------------------------- SyncHome

#[test]
fn sign_then_adopt_equals_set() {
    let (mut a, _) = Device::create();
    let (mut b, _) = Device::create();
    let signed = a.repo().sign_sync_home(mailbox(1), T).unwrap();
    let adopted = a.repo().adopt_sync_home(&signed).unwrap();
    let set = b.repo().set_sync_home(mailbox(1), T).unwrap();
    assert_eq!(adopted.seq, set.seq);
    assert_eq!(adopted.prev_hash, set.prev_hash);
    assert_eq!(adopted.backend, set.backend);
    assert_eq!(a.repo().sync_home().unwrap(), Some(adopted.clone()));
    assert_eq!(
        a.store().chain_state().unwrap().sync_home,
        Some(adopted.seen())
    );
    // Adopting the same home again writes nothing new.
    assert_eq!(a.repo().adopt_sync_home(&signed).unwrap(), adopted);
    // The next one chains.
    let next = a.repo().set_sync_home(mailbox(2), T + 1).unwrap();
    assert_eq!((next.seq, next.prev_hash), (2, adopted.hash()));
}

#[test]
fn unadopted_signature_leaves_chain() {
    let (mut a, _) = Device::create();
    let first = a.repo().set_sync_home(mailbox(1), T).unwrap();
    let chain = a.store().chain_state().unwrap();
    let x = a.repo().sign_sync_home(mailbox(2), T + 1).unwrap();
    let y = a.repo().sign_sync_home(mailbox(3), T + 2).unwrap();
    assert_eq!(a.repo().sync_home().unwrap(), Some(first.clone()));
    assert_eq!(a.store().chain_state().unwrap(), chain);
    assert_eq!(body_of(&x).seq, first.seq + 1);
    assert_eq!(body_of(&y).seq, first.seq + 1);
    assert_eq!(body_of(&x).prev_hash, first.hash());
}

#[test]
fn adopt_refuses_fork_after_other_adopted() {
    let (mut a, _) = Device::create();
    let x = a.repo().sign_sync_home(mailbox(1), T).unwrap();
    let y = a.repo().sign_sync_home(mailbox(2), T).unwrap();
    a.repo().adopt_sync_home(&x).unwrap();
    let id = a.repo().account().params.account_id;
    let before = a.repo().store().get(RecordKind::SyncHome, id);
    let err = a.repo().adopt_sync_home(&y).unwrap_err();
    assert_eq!(err, Error::Integrity(IntegrityError::SyncHomeRollback));
    let after = a.repo().store().get(RecordKind::SyncHome, id);
    assert_eq!(before.unwrap(), after.unwrap());
    assert_eq!(a.repo().sync_home().unwrap(), Some(body_of(&x)));
}

#[test]
fn loser_adopts_winner() {
    let mut server = Server::default();
    let (mut a, mut b) = two_devices(&mut server);
    let winner = a.repo().sign_sync_home(mailbox(1), T).unwrap();
    let loser = b.repo().sign_sync_home(mailbox(2), T).unwrap();
    assert_eq!(body_of(&winner).seq, body_of(&loser).seq);
    a.repo().adopt_sync_home(&winner).unwrap();
    // B adopted nothing: the winner's home is the next one for B too.
    assert_eq!(b.repo().adopt_sync_home(&winner).unwrap(), body_of(&winner));
    assert_eq!(b.repo().sync_home().unwrap(), Some(body_of(&winner)));
    // Its own signature is now a fork.
    assert!(b.repo().adopt_sync_home(&loser).is_err());
}

#[test]
fn adopt_foreign_signed_refused() {
    let (mut a, _) = Device::create();
    let (mut other, _) = Device::create();
    let foreign = other.repo().sign_sync_home(mailbox(1), T).unwrap();
    assert!(a.repo().adopt_sync_home(&foreign).is_err());
    assert_eq!(a.repo().sync_home().unwrap(), None);
    assert_eq!(a.store().chain_state().unwrap().sync_home, None);
}

// ---------------------------------------------------------------- locator

fn vector_key() -> SecretKey {
    // `[7u8; 32]` as displayed.
    SecretKey::parse("A4DQ-OBYH-A4DQ-OBYH-A4DQ-OBYH-A4DQ-OBYH-A4DQ-OBYH-A4DQ-OBYH-A4DQ-R").unwrap()
}

#[test]
fn locator_vector() {
    // Computed once with Python's hmac and hashlib (RFC 5869 by hand).
    let locator = mailbox_locator(&vector_key()).unwrap();
    assert_eq!(
        data_encoding::HEXLOWER.encode(&locator),
        "72a1f61d968d558fb42fe4d7b27a2bea"
    );
    let seed = mailbox_recovery_seed(&vector_key(), &[1; 16]).unwrap();
    assert_eq!(
        data_encoding::HEXLOWER.encode(&*seed),
        "f36ed24d5a5455985d88d17a02e28f94e6e75bcd557409a39acd1162bc4eb744"
    );
}

#[test]
fn recovery_seed_depends_on_mailbox() {
    let sk = vector_key();
    let one = mailbox_recovery_seed(&sk, &[1; 16]).unwrap();
    let two = mailbox_recovery_seed(&sk, &[2; 16]).unwrap();
    assert_ne!(*one, *two);
    let other = SecretKey::generate().unwrap();
    assert_ne!(
        mailbox_locator(&sk).unwrap(),
        mailbox_locator(&other).unwrap()
    );
    assert_ne!(*mailbox_recovery_seed(&other, &[1; 16]).unwrap(), *one);
}

// ---------------------------------------------------------------- enroll requests

struct Peer {
    keys: DeviceKeys,
    public: DevicePublic,
}

impl Peer {
    fn new(id: Id) -> Peer {
        let keys = DeviceKeys::generate_software().unwrap();
        let public = keys.public(id).unwrap();
        Peer { keys, public }
    }

    fn entry(&self) -> RosterEntry {
        RosterEntry {
            device_id: self.public.device_id,
            sign_pub: self.public.sign_pub.clone(),
            kem_pub: self.public.kem_pub.clone(),
            name: "device".into(),
            kind: DeviceKind::Phone,
            mode: DeviceMode::Personal,
            introduced_by: None,
        }
    }

    /// A request signed by this peer under `domain`.
    fn request(&self, account_id: Id, mailbox_id: [u8; 16], at: i64, domain: &[u8]) -> Vec<u8> {
        let body = EnrollRequestBody {
            account_id,
            device_id: self.public.device_id,
            credential_pub: CRED,
            mailbox_id,
            issued_at: at,
        };
        let sig = self.keys.sign(domain, &body.encode()).unwrap();
        SignedEnrollRequest { body, sig }.encode()
    }
}

/// `dev` pins a trust state whose roster is `me` and `others`, verified.
fn pin_roster(dev: &mut Device, me: &Peer, others: &[&Peer]) -> TrustState {
    let account = dev.repo().account();
    let mut roster: Vec<RosterEntry> = std::iter::once(me)
        .chain(others.iter().copied())
        .map(Peer::entry)
        .collect();
    roster.sort_by_key(|e| e.device_id);
    let mut trust = TrustState::new(
        account.params.account_id,
        me.public.clone(),
        LineageHead {
            generation: 0,
            hash: [0; 32],
        },
        account.params.identity_pub.clone(),
        roster.clone(),
        DeviceLineageState::Current,
    );
    for e in &roster {
        trust.levels.insert(e.device_id, TrustLevel::Verified);
    }
    write_trust(dev, &trust);
    trust
}

fn write_trust(dev: &mut Device, trust: &TrustState) {
    dev.repo()
        .store_mut()
        .put_all_if_version_with_trust(vec![], vec![], None, trust)
        .unwrap();
}

fn refused<T: std::fmt::Debug>(r: Result<T>, reason: &str) {
    match r {
        Err(Error::Validation(v)) => {
            assert_eq!(v.field, "enroll_request");
            assert_eq!(v.reason, reason);
        }
        other => panic!("expected refusal {reason}: {other:?}"),
    }
}

struct Setup {
    dev: Device,
    me: Peer,
    b: Peer,
    account_id: Id,
}

fn setup() -> Setup {
    let (mut dev, _) = Device::create();
    let me = Peer::new(Id::new());
    let b = Peer::new(Id::new());
    pin_roster(&mut dev, &me, &[&b]);
    let account_id = dev.repo().account().params.account_id;
    Setup {
        dev,
        me,
        b,
        account_id,
    }
}

#[test]
fn enroll_request_round_trip() {
    let mut s = setup();
    let bytes = s
        .dev
        .repo()
        .sign_enroll_request(&s.me.keys, CRED, MBX, T)
        .unwrap();
    let body = s
        .dev
        .repo()
        .verify_enroll_request(&bytes, MBX, T + 10)
        .unwrap();
    assert_eq!(body.device_id, s.me.public.device_id);
    assert_eq!(body.credential_pub, CRED);
    assert_eq!(body.account_id, s.account_id);
    assert_eq!(SignedEnrollRequest::decode(&bytes).unwrap().encode(), bytes);
    // Another device of the roster.
    let other = s.b.request(s.account_id, MBX, T, ENROLL_REQUEST_DOMAIN);
    assert_eq!(
        s.dev
            .repo()
            .verify_enroll_request(&other, MBX, T)
            .unwrap()
            .device_id,
        s.b.public.device_id
    );
    // Signing with keys that are not this device's is refused.
    refused(
        s.dev.repo().sign_enroll_request(&s.b.keys, CRED, MBX, T),
        "not this device's keys",
    );
    // Trailing bytes.
    let mut long = bytes.clone();
    long.push(0);
    refused(
        s.dev.repo().verify_enroll_request(&long, MBX, T),
        "malformed",
    );
}

#[test]
fn enroll_request_from_revoked_device_refused() {
    let mut s = setup();
    let req = s.b.request(s.account_id, MBX, T, ENROLL_REQUEST_DOMAIN);
    let mut trust = s.dev.repo().store().trust_state().unwrap().unwrap();
    trust.add_revoked(&[s.b.public.device_id]);
    write_trust(&mut s.dev, &trust);
    refused(
        s.dev.repo().verify_enroll_request(&req, MBX, T),
        "device revoked",
    );
}

#[test]
fn enroll_request_unknown_device_refused() {
    let mut s = setup();
    let stranger = Peer::new(Id::new());
    let req = stranger.request(s.account_id, MBX, T, ENROLL_REQUEST_DOMAIN);
    refused(
        s.dev.repo().verify_enroll_request(&req, MBX, T),
        "unknown device",
    );
    // A roster device id with a stranger's keys.
    let impostor = Peer {
        keys: DeviceKeys::generate_software().unwrap(),
        public: s.b.public.clone(),
    };
    let req = impostor.request(s.account_id, MBX, T, ENROLL_REQUEST_DOMAIN);
    refused(
        s.dev.repo().verify_enroll_request(&req, MBX, T),
        "signature",
    );
}

#[test]
fn enroll_request_other_account_refused() {
    let mut s = setup();
    let mut other = setup();
    let req = other
        .dev
        .repo()
        .sign_enroll_request(&other.me.keys, CRED, MBX, T)
        .unwrap();
    refused(
        s.dev.repo().verify_enroll_request(&req, MBX, T),
        "other account",
    );
    // Our roster device signing for another account.
    let req = s.b.request(other.account_id, MBX, T, ENROLL_REQUEST_DOMAIN);
    refused(
        s.dev.repo().verify_enroll_request(&req, MBX, T),
        "other account",
    );
}

#[test]
fn enroll_request_stale_refused() {
    let mut s = setup();
    let req = s.b.request(s.account_id, MBX, T, ENROLL_REQUEST_DOMAIN);
    assert!(
        s.dev
            .repo()
            .verify_enroll_request(&req, MBX, T + ENROLL_REQUEST_TTL_SECS)
            .is_ok()
    );
    refused(
        s.dev
            .repo()
            .verify_enroll_request(&req, MBX, T + 8 * 24 * 3600),
        "expired",
    );
}

#[test]
fn enroll_request_from_future_refused() {
    let mut s = setup();
    let ok =
        s.b.request(s.account_id, MBX, T + 300, ENROLL_REQUEST_DOMAIN);
    assert!(s.dev.repo().verify_enroll_request(&ok, MBX, T).is_ok());
    let req =
        s.b.request(s.account_id, MBX, T + 301, ENROLL_REQUEST_DOMAIN);
    refused(
        s.dev.repo().verify_enroll_request(&req, MBX, T),
        "from the future",
    );
}

#[test]
fn enroll_request_other_mailbox_refused() {
    let mut s = setup();
    let req = s.b.request(s.account_id, [8; 16], T, ENROLL_REQUEST_DOMAIN);
    refused(
        s.dev.repo().verify_enroll_request(&req, MBX, T),
        "other mailbox",
    );
}

#[test]
fn enroll_request_other_domain_refused() {
    let mut s = setup();
    let req = s.b.request(s.account_id, MBX, T, DEVICE_POP_DOMAIN);
    refused(
        s.dev.repo().verify_enroll_request(&req, MBX, T),
        "signature",
    );
}

#[test]
fn side_kind_is_not_a_record_kind() {
    assert!(RecordKind::from_code(SIDE_KIND_MAILBOX_ENROLL_REQUEST).is_err());
    assert_eq!(SIDE_KIND_MAILBOX_ENROLL_REQUEST, 28);
    assert_eq!(RecordKind::SyncHome.code(), 27);
}
