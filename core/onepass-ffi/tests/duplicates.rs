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

#[test]
fn review_lines_choices_and_sure_batch() {
    let (_dir, s) = session();
    let vault = s.vaults().unwrap()[0].id.clone();
    let a = login(&s, &vault, "GitHub", "camille", "Pw-one-11");
    let b = login(&s, &vault, "GitHub perso", "camille", "Pw-two-22");
    let g = s.duplicate_groups(vec![]).unwrap().remove(0);
    assert_eq!(g.confidence, FfiDuplicateConfidence::Review);
    let pw = g
        .rows
        .iter()
        .find(|r| r.aspect == FfiDuplicateAspect::Password)
        .unwrap();
    assert_eq!(pw.kind, FfiDuplicateRowKind::Conflict);
    assert!(pw.concealed);
    assert_eq!(pw.values.len(), 2);
    assert_eq!(pw.subject, "password");
    // The sure batch leaves a group with a conflict alone.
    let done = s
        .merge_sure_duplicates(vec![g.id.clone()], vec![], "Fusionné dans {title}".into())
        .unwrap();
    assert!(done.is_empty());
    // Answer: the password of the copy that is not the primary.
    let primary = &g.copies[0];
    let other = &g.copies[1];
    let other_item = if other.summary.id == a.id { &a } else { &b };
    let primary_item = if primary.summary.id == a.id { &a } else { &b };
    let wanted = if other.summary.id == a.id {
        "Pw-one-11"
    } else {
        "Pw-two-22"
    };
    let answers = vec![FfiDuplicateChoice {
        subject: "password".into(),
        from_item_id: Some(other_item.id.clone()),
    }];
    let preview = s
        .merge_duplicates_preview_with(key(primary_item), vec![key(other_item)], answers.clone())
        .unwrap();
    assert_eq!(preview.history_added, 1);
    let merged = s
        .merge_duplicates_with(
            key(primary_item),
            vec![key(other_item)],
            answers,
            "Fusionné".into(),
        )
        .unwrap();
    let got = merged
        .sections
        .iter()
        .flat_map(|s| s.fields.iter())
        .find(|f| f.id == "password")
        .map(|f| f.value.clone());
    assert_eq!(
        got,
        Some(FfiFieldValue::Password {
            value: wanted.into()
        })
    );
    assert!(s.duplicate_groups(vec![]).unwrap().is_empty());
}
