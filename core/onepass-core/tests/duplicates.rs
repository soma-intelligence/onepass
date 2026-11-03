//! Possible duplicates on the repository (spec 2026-11-03-duplicates):
//! scan across vaults, merge with files and history kept, archive and trash
//! of the extra copies, durable "not duplicates", sync of the result to a
//! second device, and the Read only role of a shared vault.

mod common;
mod share_accts;
mod share_common;

use common::*;
use onepass_core::duplicates::{Signal, distinct_tag};
use onepass_core::model::{FieldValue, Item, ItemUrl, MatchRule};
use onepass_core::repo::duplicates::{DuplicateScan, ItemKey};
use onepass_core::share::Role;
use share_accts::*;
use zeroize::Zeroizing;

fn site(item: &mut Item, url: &str) {
    item.urls.push(ItemUrl {
        label: String::new(),
        url: url.into(),
        rule: MatchRule::Domain,
        primary: item.urls.is_empty(),
    });
}

fn with_password(mut item: Item, pw: &str) -> Item {
    item.field_mut("password").unwrap().value = FieldValue::Password(Zeroizing::new(pw.into()));
    item
}

fn key(i: &Item) -> ItemKey {
    ItemKey {
        vault_id: i.vault_id,
        item_id: i.id,
    }
}

fn scan(d: &mut Device) -> DuplicateScan {
    d.repo().duplicate_scan(&[]).unwrap()
}

fn find(d: &mut Device, id: onepass_core::Id) -> Item {
    let vaults = d.repo().vaults().unwrap();
    for v in &vaults {
        if let Some(i) = d.repo().items(v).unwrap().into_iter().find(|i| i.id == id) {
            return i;
        }
    }
    panic!("item not found")
}

/// One account, "Personnel" and "Travail", the same GitHub login in each.
fn two_copies() -> (Device, onepass_core::model::Item, onepass_core::model::Item) {
    let (mut a, _sk) = Device::create();
    let perso = a.vault();
    let work = a.repo().create_vault(meta("Travail")).unwrap();
    let mut x = with_password(login(perso.id, "camille@exemple.fr", T0), "old-Pw-1");
    x.title = "GitHub".into();
    site(&mut x, "https://github.com/login");
    x.notes = "perso".into();
    let mut y = with_password(login(work.id, "Camille@Exemple.fr", T0 + 50), "new-Pw-2");
    y.title = "GitHub (travail)".into();
    site(&mut y, "https://www.github.com");
    y.tags = vec!["Travail".into()];
    a.repo().save_item(&perso, x.clone()).unwrap();
    a.repo().save_item(&work, y.clone()).unwrap();
    (a, x, y)
}

#[test]
fn scan_groups_across_vaults_and_names_them() {
    let (mut a, x, y) = two_copies();
    let s = scan(&mut a);
    assert_eq!(s.groups.len(), 1);
    let g = &s.groups[0];
    assert_eq!(g.signals, vec![Signal::SameLogin]);
    assert_eq!(g.domain.as_deref(), Some("github.com"));
    let members: Vec<_> = g.members.iter().map(|&i| &s.items[i]).collect();
    // The most recent copy is the suggested primary.
    assert_eq!(members[0].item.id, y.id);
    assert_eq!(members[0].vault_name, "Travail");
    assert_eq!(members[1].item.id, x.id);
    assert!(members.iter().all(|m| m.writable));
}

#[test]
fn merge_keeps_everything_and_archives_the_copy_intact() {
    let (mut a, x, y) = two_copies();
    let perso = a.vault();
    a.repo()
        .add_attachment(&perso, x.id, "scan.pdf", "application/pdf", b"%PDF-1 fake")
        .unwrap();
    let x_before = find(&mut a, x.id);
    let merged = a
        .repo()
        .merge_duplicates(key(&y), &[key(&x)], "Fusionné dans GitHub (travail)")
        .unwrap();
    assert_eq!(merged.id, y.id);
    let stored = find(&mut a, y.id);
    assert_eq!(stored, merged);
    assert_eq!(stored.urls.len(), 2);
    assert!(stored.notes.contains("--- GitHub ---\nperso"));
    assert!(
        stored
            .password_history
            .iter()
            .any(|h| h.value.as_str() == "old-Pw-1")
    );
    // The file is a copy in the primary's vault, readable there.
    assert_eq!(stored.attachments.len(), 1);
    let work = a.vault_named("Travail");
    let bytes = a
        .repo()
        .read_attachment(&work, y.id, stored.attachments[0].id)
        .unwrap();
    assert_eq!(&bytes[..], b"%PDF-1 fake");
    // The copy is archived, with its note, everything else as it was.
    let archived = find(&mut a, x.id);
    assert!(archived.archived);
    assert_eq!(archived.notes, "perso\n\nFusionné dans GitHub (travail)");
    assert_eq!(archived.sections, x_before.sections);
    assert_eq!(archived.attachments, x_before.attachments);
    assert_eq!(archived.password_history, x_before.password_history);
    let own = a
        .repo()
        .read_attachment(&perso, x.id, archived.attachments[0].id)
        .unwrap();
    assert_eq!(&own[..], b"%PDF-1 fake");
    // Nothing left to review; unarchiving undoes it for that copy.
    assert!(scan(&mut a).groups.is_empty());
    let mut back = archived;
    back.archived = false;
    a.repo().save_item(&perso, back).unwrap();
    assert_eq!(scan(&mut a).groups.len(), 1);
}

#[test]
fn archive_and_trash_the_other_copies() {
    let (mut a, x, y) = two_copies();
    a.repo().archive_duplicates(&[key(&x)]).unwrap();
    assert!(find(&mut a, x.id).archived);
    assert!(scan(&mut a).groups.is_empty());
    let (mut b, x, _) = two_copies();
    b.repo().trash_duplicates(&[key(&x)]).unwrap();
    assert!(find(&mut b, x.id).trashed_at.is_some());
    assert!(scan(&mut b).groups.is_empty());
    // A wrong vault id changes nothing.
    let bad = ItemKey {
        vault_id: y.vault_id,
        item_id: x.id,
    };
    assert!(a.repo().trash_duplicates(&[bad]).is_err());
}

#[test]
fn dismissal_is_durable_and_a_new_copy_brings_the_group_back() {
    let (mut a, x, y) = two_copies();
    let y_before = find(&mut a, y.id);
    a.repo().dismiss_duplicates(&[key(&x), key(&y)]).unwrap();
    assert!(scan(&mut a).groups.is_empty());
    let y_after = find(&mut a, y.id);
    assert!(y_after.tags.contains(&distinct_tag(x.id)));
    assert_eq!(
        y_after.updated_at, y_before.updated_at,
        "never wins over an edit"
    );
    let perso = a.vault();
    let mut z = login(perso.id, "camille@exemple.fr", T0 + 99);
    site(&mut z, "https://github.com");
    a.repo().save_item(&perso, z).unwrap();
    let s = scan(&mut a);
    assert_eq!(s.groups.len(), 1);
    assert_eq!(s.groups[0].members.len(), 3);
}

#[test]
fn merge_and_dismissal_sync_to_the_other_device() {
    let mut server = Server::default();
    let (mut a, mut b, _sk, items) = setup(
        &mut server,
        &[
            ("camille", T0),
            ("camille", T0 + 1),
            ("dominique", T0),
            ("dominique", T0 + 1),
        ],
    );
    // Same title, same username, no website: two pairs.
    assert_eq!(scan(&mut b).groups.len(), 2);
    a.repo()
        .merge_duplicates(key(&items[1]), &[key(&items[0])], "merged")
        .unwrap();
    a.repo()
        .dismiss_duplicates(&[key(&items[2]), key(&items[3])])
        .unwrap();
    sync(&mut server, &mut a).unwrap();
    sync(&mut server, &mut b).unwrap();
    assert!(scan(&mut b).groups.is_empty());
    assert!(find(&mut b, items[0].id).archived);
    assert_eq!(a.items(), b.items());
}

#[test]
fn read_only_copy_is_never_changed() {
    let (mut zs, _a, _b, mut c, id, items) = trio(Role::Read);
    // Carol (Read only in "Famille") keeps her own copy of alice's login.
    let perso = c
        .dev
        .repo()
        .personal_vaults()
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    let mut mine = login(perso.id, "alice", NOW);
    mine.title = items[0].title.clone();
    c.dev.repo().save_item(&perso, mine.clone()).unwrap();
    let s = c.dev.repo().duplicate_scan(&[]).unwrap();
    assert_eq!(s.groups.len(), 1);
    let g = &s.groups[0];
    let primary = &s.items[g.members[0]];
    assert_eq!(primary.item.id, mine.id, "never a read-only primary");
    let shared_copy = &s.items[g.members[1]];
    assert_eq!(shared_copy.vault_id, id);
    assert!(!shared_copy.writable);
    let theirs = key(&shared_copy.item);
    // Nothing that would change the shared copy goes through.
    for e in [
        c.dev
            .repo()
            .merge_duplicates(theirs, &[key(&mine)], "x")
            .unwrap_err(),
        c.dev.repo().archive_duplicates(&[theirs]).unwrap_err(),
        c.dev.repo().trash_duplicates(&[theirs]).unwrap_err(),
    ] {
        assert_eq!(validation(e).1, "read only");
    }
    // Merging into her own copy leaves the shared one as it is and the
    // group does not come back.
    c.dev
        .repo()
        .merge_duplicates(key(&mine), &[theirs], "x")
        .unwrap();
    c.sync(&mut zs);
    let fam = shared(&mut c.dev, id);
    let still = c
        .dev
        .repo()
        .items(&fam)
        .unwrap()
        .into_iter()
        .find(|i| i.id == theirs.item_id)
        .unwrap();
    assert!(!still.archived && still.trashed_at.is_none());
    assert!(c.dev.repo().duplicate_scan(&[]).unwrap().groups.is_empty());
}

#[test]
fn hidden_vaults_are_left_out() {
    let (mut a, _x, y) = two_copies();
    let s = a.repo().duplicate_scan(&[y.vault_id]).unwrap();
    assert!(s.groups.is_empty());
}
