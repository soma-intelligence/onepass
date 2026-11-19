//! The account profile (display name and photo) syncs through the vault as
//! a hidden item: the newest write wins, and no item listing shows it.

mod common;

use common::*;
use onepass_core::error::Error;

fn photo(byte: u8, len: usize) -> Vec<u8> {
    vec![byte; len]
}

#[test]
fn profile_is_absent_until_set() {
    let (mut a, _sk) = Device::create();
    assert_eq!(a.repo().profile().unwrap(), None);
}

#[test]
fn set_profile_reads_back_and_stays_out_of_items() {
    let (mut a, _sk) = Device::create();
    let v = personal_vault_of(&mut a);
    let item = login(v, "camille", T0);
    a.save(&item);

    a.repo()
        .set_profile("Camille Durand", &photo(7, 1000), at(T0 + 5))
        .unwrap();
    let p = a.repo().profile().unwrap().unwrap();
    assert_eq!(p.name, "Camille Durand");
    assert_eq!(p.photo, photo(7, 1000));
    assert_eq!(p.updated_at, at(T0 + 5));
    assert_eq!(a.items(), vec![item]);

    // A second write updates the same record, still hidden.
    a.repo().set_profile("Camille", &[], at(T0 + 6)).unwrap();
    let p = a.repo().profile().unwrap().unwrap();
    assert_eq!((p.name.as_str(), p.photo.len()), ("Camille", 0));
    assert_eq!(a.items().len(), 1);
}

#[test]
fn profile_reaches_the_other_device_both_ways() {
    let mut server = Server::default();
    let (mut a, mut b, _sk, items) = setup(&mut server, &[("camille", T0)]);

    a.repo()
        .set_profile("Camille", &photo(1, 2000), at(T0 + 10))
        .unwrap();
    sync(&mut server, &mut a).unwrap();
    sync(&mut server, &mut b).unwrap();
    let p = b.repo().profile().unwrap().unwrap();
    assert_eq!(
        (p.name.as_str(), p.photo.clone()),
        ("Camille", photo(1, 2000))
    );
    assert_eq!(b.items(), items);

    b.repo()
        .set_profile("Camille D.", &[], at(T0 + 20))
        .unwrap();
    sync(&mut server, &mut b).unwrap();
    sync(&mut server, &mut a).unwrap();
    let p = a.repo().profile().unwrap().unwrap();
    assert_eq!((p.name.as_str(), p.photo.len()), ("Camille D.", 0));
}

#[test]
fn concurrent_first_profiles_converge_to_the_newest() {
    // Both devices publish a profile before seeing the other's: the record
    // id is the same on both, so the rebase keeps the newest write.
    let mut server = Server::default();
    let (mut a, mut b, _sk, _items) = setup(&mut server, &[("camille", T0)]);
    a.repo()
        .set_profile("Old", &photo(1, 10), at(T0 + 10))
        .unwrap();
    b.repo()
        .set_profile("New", &photo(2, 10), at(T0 + 20))
        .unwrap();
    sync(&mut server, &mut a).unwrap();
    sync(&mut server, &mut b).unwrap();
    sync(&mut server, &mut a).unwrap();

    for dev in [&mut a, &mut b] {
        let p = dev.repo().profile().unwrap().unwrap();
        assert_eq!((p.name.as_str(), p.photo.clone()), ("New", photo(2, 10)));
        assert_eq!(dev.items().len(), 1);
    }
}

#[test]
fn older_concurrent_profile_loses_even_when_pushed_last() {
    let mut server = Server::default();
    let (mut a, mut b, _sk, _items) = setup(&mut server, &[("camille", T0)]);
    a.repo().set_profile("Base", &[], at(T0 + 5)).unwrap();
    sync(&mut server, &mut a).unwrap();
    sync(&mut server, &mut b).unwrap();

    b.repo().set_profile("Newer", &[], at(T0 + 30)).unwrap();
    a.repo().set_profile("Older", &[], at(T0 + 20)).unwrap();
    sync(&mut server, &mut b).unwrap();
    sync(&mut server, &mut a).unwrap();
    sync(&mut server, &mut b).unwrap();
    assert_eq!(a.repo().profile().unwrap().unwrap().name, "Newer");
    assert_eq!(b.repo().profile().unwrap().unwrap().name, "Newer");
}

#[test]
fn profile_limits_are_enforced() {
    let (mut a, _sk) = Device::create();
    let long = "x".repeat(65);
    assert!(matches!(
        a.repo().set_profile(&long, &[], at(T0)),
        Err(Error::Validation(_))
    ));
    let big = photo(0, 256 * 1024 + 1);
    assert!(matches!(
        a.repo().set_profile("Camille", &big, at(T0)),
        Err(Error::Validation(_))
    ));
    assert_eq!(a.repo().profile().unwrap(), None);

    // At the limits, accepted; control characters are dropped.
    let name = format!("{}\u{7}", "é".repeat(64));
    let p = a
        .repo()
        .set_profile(&name, &photo(0, 256 * 1024), at(T0))
        .unwrap();
    assert_eq!(p.name, "é".repeat(64));
}

#[test]
fn profile_survives_lock_and_unlock() {
    let (mut a, sk) = Device::create();
    a.repo()
        .set_profile("Camille", &photo(3, 5), at(T0))
        .unwrap();
    a.lock();
    a.unlock(&sk);
    assert_eq!(a.repo().profile().unwrap().unwrap().name, "Camille");
}

#[test]
fn deleting_the_vault_that_holds_the_profile_keeps_it() {
    let (mut a, _sk) = Device::create();
    a.repo().create_vault(meta("Travail")).unwrap();
    a.repo()
        .set_profile("Camille", &photo(4, 8), at(T0))
        .unwrap();
    let personal = a.vault();
    // The profile is invisible: the vault counts as empty.
    a.repo().delete_vault(&personal).unwrap();
    let p = a.repo().profile().unwrap().unwrap();
    assert_eq!((p.name.as_str(), p.photo.clone()), ("Camille", photo(4, 8)));
    let work = a.vault_named("Travail");
    assert_eq!(a.repo().items(&work).unwrap(), vec![]);
}

#[test]
fn seeded_profile_loses_to_any_real_edit() {
    // A device migrating its local profile seeds it at the Unix epoch: a
    // profile another device set for real always wins, pushed first or last.
    let mut server = Server::default();
    let (mut a, mut b, _sk, _items) = setup(&mut server, &[("camille", T0)]);
    a.repo().set_profile("Real", &[], at(T0 + 10)).unwrap();
    assert!(b.repo().seed_profile("Stale", &photo(5, 4)).unwrap());
    sync(&mut server, &mut b).unwrap();
    sync(&mut server, &mut a).unwrap();
    sync(&mut server, &mut b).unwrap();
    assert_eq!(a.repo().profile().unwrap().unwrap().name, "Real");
    assert_eq!(b.repo().profile().unwrap().unwrap().name, "Real");
    // Once a profile exists, a seed changes nothing.
    assert!(!a.repo().seed_profile("Other", &[]).unwrap());
    assert_eq!(a.repo().profile().unwrap().unwrap().name, "Real");
}

fn typed(vault: Id, kind: ItemType, title: &str) -> Item {
    let mut item = new_item(kind, vault, title);
    let required = if kind == ItemType::Identity {
        "first_name"
    } else {
        "cardholder"
    };
    item.field_mut(required).unwrap().value = FieldValue::Text(title.into());
    if kind == ItemType::CreditCard {
        item.field_mut("number").unwrap().value =
            FieldValue::Concealed(String::from("4111111111111111").into());
        item.field_mut("expiry").unwrap().value = FieldValue::MonthYear {
            year: 2030,
            month: 12,
        };
    }
    item.created_at = at(T0);
    item.updated_at = at(T0);
    item
}

#[test]
fn main_identity_and_card_are_set_checked_and_kept_by_name_writes() {
    use onepass_core::repo::profile::ItemRef;
    let mut server = Server::default();
    let (mut a, mut b, _sk, items) = setup(&mut server, &[("camille", T0)]);
    let v = items[0].vault_id;
    let me = typed(v, ItemType::Identity, "Camille");
    let visa = typed(v, ItemType::CreditCard, "Visa");
    a.save(&me);
    a.save(&visa);
    let r = |i: &Item| ItemRef {
        vault_id: i.vault_id,
        item_id: i.id,
    };

    // A profile written without them names none (as one from before them).
    a.repo()
        .set_profile("Camille", &photo(1, 4), at(T0 + 1))
        .unwrap();
    let p = a.repo().profile().unwrap().unwrap();
    assert_eq!((p.main_identity, p.main_card), (None, None));

    // The wrong type, an unknown item: refused, nothing written.
    assert!(matches!(
        a.repo().set_profile_main(Some(r(&visa)), None, at(T0 + 2)),
        Err(Error::Validation(_))
    ));
    assert!(matches!(
        a.repo().set_profile_main(None, Some(r(&me)), at(T0 + 2)),
        Err(Error::Validation(_))
    ));
    let ghost = ItemRef {
        vault_id: v,
        item_id: Id::new(),
    };
    assert!(matches!(
        a.repo().set_profile_main(Some(ghost), None, at(T0 + 2)),
        Err(Error::NotFound)
    ));
    assert_eq!(a.repo().profile().unwrap().unwrap().updated_at, at(T0 + 1));

    // Set: dated now, name and photo untouched.
    let p = a
        .repo()
        .set_profile_main(Some(r(&me)), Some(r(&visa)), at(T0 + 3))
        .unwrap();
    assert_eq!(
        (p.main_identity, p.main_card),
        (Some(r(&me)), Some(r(&visa)))
    );
    assert_eq!((p.name.as_str(), p.photo.clone()), ("Camille", photo(1, 4)));
    assert_eq!(p.updated_at, at(T0 + 3));

    // A name write keeps them, and they reach the other device.
    a.repo().set_profile("Camille D.", &[], at(T0 + 4)).unwrap();
    sync(&mut server, &mut a).unwrap();
    sync(&mut server, &mut b).unwrap();
    let p = b.repo().profile().unwrap().unwrap();
    assert_eq!(p.name, "Camille D.");
    assert_eq!(
        (p.main_identity, p.main_card),
        (Some(r(&me)), Some(r(&visa)))
    );

    // Cleared one at a time.
    let p = b
        .repo()
        .set_profile_main(Some(r(&me)), None, at(T0 + 5))
        .unwrap();
    assert_eq!((p.main_identity, p.main_card), (Some(r(&me)), None));
    assert_eq!(p.name, "Camille D.");
}

#[test]
fn main_card_on_an_account_without_profile_creates_it() {
    use onepass_core::repo::profile::ItemRef;
    let (mut a, _sk) = Device::create();
    let v = personal_vault_of(&mut a);
    let visa = typed(v, ItemType::CreditCard, "Visa");
    a.save(&visa);
    let card = ItemRef {
        vault_id: v,
        item_id: visa.id,
    };
    let p = a.repo().set_profile_main(None, Some(card), at(T0)).unwrap();
    assert_eq!((p.name.as_str(), p.main_card), ("", Some(card)));
    assert_eq!(a.items(), vec![visa]);
}
