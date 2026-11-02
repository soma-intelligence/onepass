//! `SyncHome` (cross-platform spec 4.13, 8): where the account syncs,
//! signed by the account and chained like the signed lists, seen from
//! devices syncing through the fake server of `common`. Also the device
//! kinds appended for the non-Apple apps (spec 5.2).

mod common;

use common::*;
use data_encoding::HEXLOWER;
use onepass_core::chain::ChainState;
use onepass_core::devices::DeviceKind;
use onepass_core::lineage::LineageRecord;
use onepass_core::synchome::{
    SYNC_HOME_DOMAIN, SignedSyncHome, SyncBackend, SyncHomeBody, verify_sync_home,
};

const T: i64 = 1_790_000_000;

fn mailbox(n: u8) -> SyncBackend {
    SyncBackend::Mailbox {
        url: format!("https://mailbox{n}.example.org/functions/v1/mailbox"),
        mailbox_id: [n; 16],
    }
}

fn account_id(dev: &mut Device) -> Id {
    dev.repo().account().params.account_id
}

fn stored(dev: &mut Device) -> Record {
    let id = account_id(dev);
    dev.repo()
        .store()
        .get(RecordKind::SyncHome, id)
        .unwrap()
        .unwrap()
}

/// A record of `body` signed by `dev`'s account key under `domain`.
fn forged(dev: &mut Device, body: SyncHomeBody, domain: &[u8]) -> Record {
    let id = account_id(dev);
    let sig = dev
        .repo()
        .account()
        .keyset()
        .signing
        .sign(domain, &body.encode())
        .unwrap();
    Record {
        id,
        kind: RecordKind::SyncHome,
        version: body.seq,
        data: SignedSyncHome { body, sig }.encode(),
    }
}

/// A creates the account and syncs; B fetches it and unlocks.
fn two_devices(server: &mut Server) -> (Device, Device) {
    let (mut a, sk) = Device::create();
    sync(server, &mut a).unwrap();
    let mut b = Device::empty();
    pull(server, &mut b);
    b.unlock(&sk);
    (a, b)
}

#[test]
fn set_then_read() {
    let (mut a, _sk) = Device::create();
    assert_eq!(a.repo().sync_home().unwrap(), None);
    let set = a.repo().set_sync_home(mailbox(1), T).unwrap();
    assert_eq!(set.seq, 1);
    assert_eq!(set.prev_hash, [0; 32]);
    assert_eq!(set.backend, mailbox(1));
    assert_eq!(set.issued_at, T);
    assert_eq!(set.account_id, account_id(&mut a));
    assert_eq!(a.repo().sync_home().unwrap(), Some(set.clone()));
    // Pinned in the persisted chain state, in the same transaction.
    assert_eq!(a.store().chain_state().unwrap().sync_home, Some(set.seen()));
    // Stored at version = seq under the account records id.
    assert_eq!(stored(&mut a).version, 1);
}

#[test]
fn chain_moves_forward() {
    let (mut a, _sk) = Device::create();
    let first = a.repo().set_sync_home(mailbox(1), T).unwrap();
    let second = a
        .repo()
        .set_sync_home(SyncBackend::CloudKit, T + 1)
        .unwrap();
    assert_eq!(second.seq, 2);
    assert_eq!(second.prev_hash, first.hash());
    assert_eq!(a.repo().sync_home().unwrap(), Some(second));
}

#[test]
fn malformed_backend_refused() {
    let (mut a, _sk) = Device::create();
    for url in [
        "http://mailbox.example.org",
        "https://",
        "https://mailbox.example.org/?x=1",
        "https://mailbox.example.org/#f",
        "https://user@mailbox.example.org",
        "https://mailbox.example.org/a b",
    ] {
        let backend = SyncBackend::Mailbox {
            url: url.into(),
            mailbox_id: [1; 16],
        };
        assert!(a.repo().set_sync_home(backend, T).is_err(), "{url}");
    }
    let long = SyncBackend::Mailbox {
        url: format!("https://{}", "a".repeat(249)),
        mailbox_id: [1; 16],
    };
    assert!(a.repo().set_sync_home(long, T).is_err());
    assert_eq!(a.repo().sync_home().unwrap(), None);
}

#[test]
fn syncs_to_the_other_device() {
    let mut server = Server::default();
    let (mut a, mut b) = two_devices(&mut server);
    let set = a.repo().set_sync_home(mailbox(1), T).unwrap();
    sync(&mut server, &mut a).unwrap();
    pull(&server, &mut b);
    assert_eq!(b.repo().sync_home().unwrap(), Some(set));
}

#[test]
fn rollback_refused() {
    let mut server = Server::default();
    let (mut a, mut b) = two_devices(&mut server);
    a.repo().set_sync_home(mailbox(1), T).unwrap();
    sync(&mut server, &mut a).unwrap();
    let old = stored(&mut a);
    let second = a.repo().set_sync_home(mailbox(2), T + 1).unwrap();
    sync(&mut server, &mut a).unwrap();
    pull(&server, &mut b);
    assert_eq!(b.repo().sync_home().unwrap(), Some(second.clone()));

    server.replay(old);
    pull(&server, &mut b);
    assert_eq!(
        integrity(b.repo().sync_home()),
        IntegrityError::SyncHomeRollback
    );
    // Nothing changed: the pin stays on the second home.
    assert_eq!(b.repo().chain().sync_home, Some(second.seen()));
    // A new device state persist keeps it too.
    b.repo().persist_device_state().unwrap();
    assert_eq!(
        b.store().chain_state().unwrap().sync_home,
        Some(second.seen())
    );
}

#[test]
fn withheld_home_is_a_rollback_once_pinned() {
    let mut server = Server::default();
    let (mut a, mut b) = two_devices(&mut server);
    a.repo().set_sync_home(mailbox(1), T).unwrap();
    sync(&mut server, &mut a).unwrap();
    pull(&server, &mut b);
    assert!(b.repo().sync_home().unwrap().is_some());
    let id = account_id(&mut a);
    server.withhold(RecordKind::SyncHome, id);
    full_fetch(&server, &mut b);
    // A fetch from scratch keeps the record (never deleted by a client).
    assert!(b.repo().sync_home().unwrap().is_some());
}

#[test]
fn fork_refused() {
    let mut server = Server::default();
    let (mut a, mut b) = two_devices(&mut server);
    let first = a.repo().set_sync_home(mailbox(1), T).unwrap();
    a.repo().set_sync_home(mailbox(2), T + 1).unwrap();
    sync(&mut server, &mut a).unwrap();
    pull(&server, &mut b);
    let seen = b.repo().sync_home().unwrap().unwrap();
    // Another body at seq 2, properly signed, chained to the first.
    let other = SyncHomeBody::next(Some(&first), first.account_id, mailbox(3), T + 2).unwrap();
    let rec = forged(&mut a, other, SYNC_HOME_DOMAIN);
    server.replay(rec);
    pull(&server, &mut b);
    assert_eq!(
        integrity(b.repo().sync_home()),
        IntegrityError::SyncHomeRollback
    );
    assert_eq!(b.repo().chain().sync_home, Some(seen.seen()));
}

#[test]
fn next_not_chained_refused() {
    let (mut a, _sk) = Device::create();
    let first = a.repo().set_sync_home(mailbox(1), T).unwrap();
    let mut bad = SyncHomeBody::next(Some(&first), first.account_id, mailbox(2), T).unwrap();
    bad.prev_hash = [9; 32];
    let rec = forged(&mut a, bad, SYNC_HOME_DOMAIN);
    let key = a.repo().account().params.signing_pub.clone();
    assert_eq!(
        integrity(verify_sync_home(
            &rec.data,
            &key,
            first.account_id,
            Some(&first.seen())
        )),
        IntegrityError::SyncHomeRollback
    );
    // Without a pin (first use) it verifies: only the history refuses it.
    assert!(verify_sync_home(&rec.data, &key, first.account_id, None).is_ok());
}

#[test]
fn other_account_refused() {
    let mut server = Server::default();
    let (mut a, mut b) = two_devices(&mut server);
    let body = SyncHomeBody::next(None, Id::new(), mailbox(1), T).unwrap();
    server.replay(forged(&mut a, body, SYNC_HOME_DOMAIN));
    pull(&server, &mut b);
    assert_eq!(
        integrity(b.repo().sync_home()),
        IntegrityError::WrongContext
    );
    assert_eq!(b.repo().chain().sync_home, None);
}

#[test]
fn bad_signature_refused() {
    let mut server = Server::default();
    let (mut a, mut b) = two_devices(&mut server);
    // Signed by another account's key, for this account.
    let (mut other, _sk) = Device::create();
    let body = SyncHomeBody::next(None, account_id(&mut a), mailbox(1), T).unwrap();
    let mut rec = forged(&mut other, body, SYNC_HOME_DOMAIN);
    rec.id = account_id(&mut a);
    server.replay(rec);
    pull(&server, &mut b);
    assert_eq!(integrity(b.repo().sync_home()), IntegrityError::Signature);
    assert_eq!(b.repo().chain().sync_home, None);
}

#[test]
fn other_domain_refused() {
    let mut server = Server::default();
    let (mut a, mut b) = two_devices(&mut server);
    let body = SyncHomeBody::next(None, account_id(&mut a), mailbox(1), T).unwrap();
    server.replay(forged(&mut a, body, b"device-list"));
    pull(&server, &mut b);
    assert_eq!(integrity(b.repo().sync_home()), IntegrityError::Signature);
}

#[test]
fn strict_decode() {
    let (mut a, _sk) = Device::create();
    a.repo().set_sync_home(mailbox(1), T).unwrap();
    let data = stored(&mut a).data;
    assert!(SignedSyncHome::decode(&data).is_ok());
    let mut trailing = data.clone();
    trailing.push(0);
    assert_eq!(
        SignedSyncHome::decode(&trailing),
        Err(Error::InvalidFormat("sync home"))
    );
    assert_eq!(
        SignedSyncHome::decode(&data[..data.len() - 1]),
        Err(Error::InvalidFormat("sync home"))
    );
    // Seq 0 is never signed.
    let mut zero = SyncHomeBody::next(None, account_id(&mut a), mailbox(1), T).unwrap();
    zero.seq = 0;
    let rec = forged(&mut a, zero, SYNC_HOME_DOMAIN);
    assert_eq!(
        SignedSyncHome::decode(&rec.data),
        Err(Error::InvalidFormat("sync home"))
    );
}

#[test]
fn server_deletion_ignored() {
    let mut server = Server::default();
    let (mut a, mut b) = two_devices(&mut server);
    let set = a.repo().set_sync_home(mailbox(1), T).unwrap();
    sync(&mut server, &mut a).unwrap();
    pull(&server, &mut b);
    let id = account_id(&mut a);
    server.forge_deletion(RecordKind::SyncHome, id);
    pull(&server, &mut b);
    let ignored: Vec<RecordKind> = b
        .store()
        .ignored_deletions()
        .unwrap()
        .into_iter()
        .map(|d| d.kind)
        .collect();
    assert!(ignored.contains(&RecordKind::SyncHome));
    assert_eq!(b.repo().sync_home().unwrap(), Some(set));
}

#[test]
fn local_deletion_refused() {
    let (mut a, _sk) = Device::create();
    a.repo().set_sync_home(mailbox(1), T).unwrap();
    let id = account_id(&mut a);
    assert_eq!(
        a.store().delete(RecordKind::SyncHome, id),
        Err(Error::InvalidFormat("list record deletion"))
    );
}

/// A and B both move the account at once: the server keeps A's, B's rebase
/// drops its own and takes A's. Never a silent overwrite of A's choice.
#[test]
fn concurrent_moves_keep_the_first_pushed() {
    let mut server = Server::default();
    let (mut a, mut b) = two_devices(&mut server);
    a.repo().set_sync_home(mailbox(1), T).unwrap();
    sync(&mut server, &mut a).unwrap();
    pull(&server, &mut b);
    b.repo().sync_home().unwrap();

    let by_a = a.repo().set_sync_home(mailbox(2), T + 1).unwrap();
    let by_b = b.repo().set_sync_home(mailbox(3), T + 1).unwrap();
    assert_eq!(by_a.seq, by_b.seq);
    sync(&mut server, &mut a).unwrap();
    sync(&mut server, &mut b).unwrap();
    assert_eq!(b.repo().sync_home().unwrap(), Some(by_a.clone()));
    assert_eq!(
        b.store().chain_state().unwrap().sync_home,
        Some(by_a.seen())
    );
    // B's home never reached the server.
    let id = account_id(&mut a);
    let on_server = server.get(RecordKind::SyncHome, id).unwrap();
    assert_eq!(SignedSyncHome::decode(&on_server.data).unwrap().body, by_a);
    // B can move it again, on top of A's.
    let next = b.repo().set_sync_home(mailbox(3), T + 2).unwrap();
    assert_eq!(next.prev_hash, by_a.hash());
}

#[test]
fn chain_state_v1_still_decodes() {
    // Version 1, frozen: epoch 7, device list (3, [1; 32]), vault list
    // (9, [2; 32]), device id [3; 16].
    let mut v1 = vec![1, 7, 1, 3];
    v1.extend([1u8; 32]);
    v1.extend([1, 9]);
    v1.extend([2u8; 32]);
    v1.push(1);
    v1.extend([3u8; 16]);
    let s = ChainState::decode(&v1).unwrap();
    assert_eq!(s.sync_home, None);
    assert_eq!(s.params_epoch, 7);
    assert_eq!(s.encode()[0], 4);
    assert_eq!(ChainState::decode(&s.encode()).unwrap(), s);
}

#[test]
fn device_kinds_appended() {
    // Frozen before the new kinds: the postcard variant index.
    assert_eq!(postcard::to_allocvec(&DeviceKind::Phone).unwrap(), [0]);
    assert_eq!(postcard::to_allocvec(&DeviceKind::Other).unwrap(), [4]);
    for (kind, code) in [
        (DeviceKind::Android, 5u8),
        (DeviceKind::Windows, 6),
        (DeviceKind::Linux, 7),
    ] {
        let bytes = postcard::to_allocvec(&kind).unwrap();
        assert_eq!(bytes, [code]);
        assert_eq!(postcard::from_bytes::<DeviceKind>(&bytes).unwrap(), kind);
    }
    // A roster entry of the frozen rotation vectors still decodes and
    // re-encodes byte for byte.
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/lineage");
    for name in ["genesis.hex", "rotation.hex"] {
        let text = std::fs::read_to_string(dir.join(name)).unwrap();
        let hex = text
            .lines()
            .find_map(|l| l.strip_prefix("record="))
            .unwrap();
        let bytes = HEXLOWER.decode(hex.as_bytes()).unwrap();
        let rec = LineageRecord::decode(&bytes).unwrap();
        assert_eq!(rec.encode(), bytes, "{name}");
    }
}
