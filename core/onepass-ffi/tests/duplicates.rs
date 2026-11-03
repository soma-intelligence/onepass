//! Possible duplicates through the UniFFI surface: groups with what differs,
//! a preview that writes nothing, merge, and a "not duplicates" marker that
//! the app never sees and an edit from the app keeps. Run with
//! `--features onepass-core/dev-fast-kdf`.

use std::sync::Arc;

use onepass_ffi::*;
use tempfile::TempDir;

const FAST: FfiKdfParams = FfiKdfParams {
    m_kib: 8192,
    t: 1,
    p: 1,
};

fn session() -> (TempDir, Arc<Session>) {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("onepass.db").to_string_lossy().into_owned();
    let created = create_account_with_kdf(path, "Café-étoile".into(), FAST).unwrap();
    (dir, created.session)
}

fn set(item: &mut FfiItem, id: &str, value: FfiFieldValue) {
    for s in &mut item.sections {
        for f in &mut s.fields {
            if f.id == id {
                f.value = value;
                return;
            }
        }
    }
    panic!("no field {id}");
}

fn login(s: &Session, vault: &str, title: &str, user: &str, pw: &str) -> FfiItem {
    let mut item = s
        .new_item(vault.into(), FfiItemType::Login, title.into())
        .unwrap();
    set(
        &mut item,
        "username",
        FfiFieldValue::Text { value: user.into() },
    );
    set(
        &mut item,
        "password",
        FfiFieldValue::Password { value: pw.into() },
    );
    item.urls = vec![FfiUrl {
        label: String::new(),
        url: "https://github.com".into(),
        rule: FfiMatchRule::Domain,
        primary: true,
    }];
    s.save_item(item).unwrap()
}

fn key(i: &FfiItem) -> FfiItemKey {
    FfiItemKey {
        vault_id: i.vault_id.clone(),
        item_id: i.id.clone(),
    }
}

#[test]
fn group_preview_merge_and_dismiss() {
    let (_dir, s) = session();
    let vault = s.vaults().unwrap()[0].id.clone();
    let a = login(&s, &vault, "GitHub", "camille", "Pw-one-11");
    let b = login(&s, &vault, "GitHub perso", "Camille", "Pw-two-22");
    let groups = s.duplicate_groups(vec![]).unwrap();
    assert_eq!(groups.len(), 1);
    let g = &groups[0];
    assert_eq!(g.signals, vec![FfiDuplicateSignal::SameLogin]);
    assert_eq!(g.domain.as_deref(), Some("github.com"));
    assert_eq!(g.copies.len(), 2);
    assert!(g.copies[0].differences.is_empty());
    assert!(
        g.copies[1]
            .differences
            .contains(&FfiDuplicateAspect::Password)
    );
    assert!(
        g.copies
            .iter()
            .all(|c| c.writable && !c.vault_name.is_empty())
    );
    // Hidden vaults are left out.
    assert!(s.duplicate_groups(vec![vault.clone()]).unwrap().is_empty());

    let preview = s.merge_duplicates_preview(key(&a), vec![key(&b)]).unwrap();
    assert_eq!(preview.archived_count, 1);
    assert_eq!(preview.history_added, 1);
    assert_eq!(preview.merged.title, "GitHub");
    // Nothing written.
    assert!(!s.item(vault.clone(), b.id.clone()).unwrap().archived);

    // "Not duplicates", then an edit from the app: the marker survives and
    // never shows among the tags.
    s.dismiss_duplicates(vec![key(&a), key(&b)]).unwrap();
    assert!(s.duplicate_groups(vec![]).unwrap().is_empty());
    let mut edited = s.item(vault.clone(), a.id.clone()).unwrap();
    assert!(edited.tags.is_empty(), "{:?}", edited.tags);
    edited.title = "GitHub (main)".into();
    s.save_item(edited).unwrap();
    assert!(s.duplicate_groups(vec![]).unwrap().is_empty());

    // A third copy brings the group back; merge it.
    let c = login(&s, &vault, "GH", "camille", "Pw-three-33");
    let groups = s.duplicate_groups(vec![]).unwrap();
    assert_eq!(groups.len(), 1);
    let merged = s
        .merge_duplicates(key(&a), vec![key(&b), key(&c)], "Fusionné".into())
        .unwrap();
    assert_eq!(merged.password_history_count, 2);
    assert!(s.item(vault.clone(), b.id.clone()).unwrap().archived);
    assert!(
        s.item(vault.clone(), c.id.clone())
            .unwrap()
            .notes
            .ends_with("Fusionné")
    );
    assert!(s.duplicate_groups(vec![]).unwrap().is_empty());
}

#[test]
fn archive_and_trash_extra_copies() {
    let (_dir, s) = session();
    let vault = s.vaults().unwrap()[0].id.clone();
    let _a = login(&s, &vault, "GitHub", "camille", "Pw-one-11");
    let b = login(&s, &vault, "GitHub", "camille", "Pw-two-22");
    let c = login(&s, &vault, "GitHub", "camille", "Pw-three-33");
    s.archive_duplicates(vec![key(&b)]).unwrap();
    s.trash_duplicates(vec![key(&c)]).unwrap();
    assert!(s.item(vault.clone(), b.id).unwrap().archived);
    assert!(s.item(vault.clone(), c.id).unwrap().trashed_at.is_some());
    assert!(s.duplicate_groups(vec![]).unwrap().is_empty());
}
