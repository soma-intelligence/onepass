//! Sending a signed copy of an item to a contact (sharing plan 3 Task 7).

mod common;
mod share_accts;
mod share_common;

use common::*;
use onepass_core::Error;
use onepass_core::contact::ContactLevel;
use onepass_core::send::{ItemSend, MAX_SEND_TTL_SECS};
use onepass_core::store::{RecordKind, Zone};
use share_accts::settle;
use share_accts::*;
use share_common::*;

/// Alice and Bob, each `Verified` in the other's book, their contact
/// zone made; Alice has one login with history in "Personnel".
fn pair() -> (Zones, Acct, Acct, Vault, Item) {
    let mut zs = Zones::default();
    let mut a = Acct::new();
    let mut b = Acct::new();
    pin(&mut a.dev, &mut b.dev, ContactLevel::Verified);
    pin(&mut b.dev, &mut a.dev, ContactLevel::Verified);
    contact_zone(&mut a.dev, &mut b.dev);
    let v = a.dev.vault_named("Personnel");
    let item = login(v.id, "wifi", 500);
    a.dev.repo().save_item(&v, item.clone()).unwrap();
    let again = edited(&item, "wifi2", 600);
    a.dev.repo().save_item(&v, again.clone()).unwrap();
    settle(&mut zs, &mut [&mut a, &mut b]);
    (zs, a, b, v, again)
}

fn send(a: &mut Acct, b: &mut Acct, v: &Vault, item: &Item) -> Id {
    let bob = account_id(&mut b.dev);
    a.dev
        .repo()
        .send_item(v, item.id, bob, NOW + 3600, NOW)
        .unwrap()
}

#[test]
fn send_then_accept_into_vault() {
    let (mut zs, mut a, mut b, v, item) = pair();
    let id = send(&mut a, &mut b, &v, &item);
    settle(&mut zs, &mut [&mut a, &mut b]);
    let got = b.dev.repo().received_items(NOW + 1).unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].send_id, id);
    let into = b.dev.vault_named("Personnel");
    let taken = b
        .dev
        .repo()
        .accept_received_item(id, &into, NOW + 2)
        .unwrap();
    assert_ne!(taken.id, item.id);
    assert!(users(&b.dev.repo().items(&into).unwrap()).contains(&"wifi2".to_string()));
    assert!(b.dev.repo().received_items(NOW + 3).unwrap().is_empty());
    settle(&mut zs, &mut [&mut a, &mut b]);
    let zone = b.dev.repo().contact_zone(account_id(&mut a.dev)).unwrap();
    assert!(zs.server(zone).live(RecordKind::ItemSend, id).is_none());
}

#[test]
fn send_strips_history_and_usage() {
    let (mut zs, mut a, mut b, v, item) = pair();
    let id = send(&mut a, &mut b, &v, &item);
    settle(&mut zs, &mut [&mut a, &mut b]);
    let into = b.dev.vault_named("Personnel");
    let taken = b
        .dev
        .repo()
        .accept_received_item(id, &into, NOW + 2)
        .unwrap();
    assert!(taken.password_history.is_empty());
    assert!(taken.usage.is_empty());
    // The only event is Bob's own save, none of Alice's.
    let stored = b.dev.repo().items(&into).unwrap();
    let mine = stored.iter().find(|i| i.id == taken.id).unwrap();
    assert!(mine.events.len() <= 1);
}

#[test]
fn ttl_bounds() {
    let (_zs, mut a, mut b, v, item) = pair();
    let bob = account_id(&mut b.dev);
    for at in [NOW, NOW + MAX_SEND_TTL_SECS + 1] {
        let e = a
            .dev
            .repo()
            .send_item(&v, item.id, bob, at, NOW)
            .unwrap_err();
        assert!(matches!(e, Error::Validation(_)), "{e:?}");
    }
    a.dev
        .repo()
        .send_item(&v, item.id, bob, NOW + MAX_SEND_TTL_SECS, NOW)
        .unwrap();
}

#[test]
fn expired_send_ignored_and_purged() {
    let (mut zs, mut a, mut b, v, item) = pair();
    send(&mut a, &mut b, &v, &item);
    settle(&mut zs, &mut [&mut a, &mut b]);
    assert!(b.dev.repo().received_items(NOW + 3600).unwrap().is_empty());
    assert_eq!(a.dev.repo().purge_expired_sends(NOW + 10).unwrap(), 0);
    assert_eq!(a.dev.repo().purge_expired_sends(NOW + 3600).unwrap(), 1);
    settle(&mut zs, &mut [&mut a, &mut b]);
    assert!(b.dev.repo().received_items(NOW + 1).unwrap().is_empty());
}

#[test]
fn sender_outside_book_refused() {
    let (mut zs, mut a, mut b, v, item) = pair();
    send(&mut a, &mut b, &v, &item);
    settle(&mut zs, &mut [&mut a, &mut b]);
    let alice = account_id(&mut a.dev);
    b.dev.repo().remove_contact(alice, NOW + 1).unwrap();
    assert!(b.dev.repo().received_items(NOW + 2).unwrap().is_empty());
}

#[test]
fn forged_signature_refused() {
    let (mut zs, mut a, mut b, v, item) = pair();
    let id = send(&mut a, &mut b, &v, &item);
    settle(&mut zs, &mut [&mut a, &mut b]);
    let zone = b.dev.repo().contact_zone(account_id(&mut a.dev)).unwrap();
    let rec = zs.server(zone).get(RecordKind::ItemSend, id).unwrap();
    let mut send = ItemSend::decode(&rec.data).unwrap();
    send.expires_at += 1;
    zs.server(zone).replay(Record {
        version: rec.version + 1,
        data: send.encode(),
        ..rec
    });
    settle(&mut zs, &mut [&mut b]);
    assert!(b.dev.repo().received_items(NOW + 1).unwrap().is_empty());
    let _ = Zone::Private;
}

#[test]
fn send_survives_recipient_rotation() {
    let (mut zs, mut a, mut b, v, item) = pair();
    let id = send(&mut a, &mut b, &v, &item);
    settle(&mut zs, &mut [&mut a, &mut b]);
    b.rotate(false);
    let got = b.dev.repo().received_items(NOW + 1).unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].send_id, id);
}

#[test]
fn send_from_rotated_sender_needs_adoption() {
    let (mut zs, mut a, mut b, v, item) = pair();
    a.rotate(false);
    let v = a.dev.vault_named(&v.meta.name);
    let id = send(&mut a, &mut b, &v, &item);
    settle(&mut zs, &mut [&mut a, &mut b]);
    // Bob's book still holds Alice's old identity.
    assert!(b.dev.repo().received_items(NOW + 1).unwrap().is_empty());
    repin_in_person(&mut b.dev, &mut a.dev);
    let got = b.dev.repo().received_items(NOW + 2).unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].send_id, id);
}
