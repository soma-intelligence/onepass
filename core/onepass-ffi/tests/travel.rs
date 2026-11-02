//! Travel Mode through the UniFFI surface, over the app's store and a fake
//! server fed by the sync handle. Run with `--features dev-fast-kdf`.

use std::collections::BTreeMap;
use std::sync::Arc;

use onepass_ffi::*;
use tempfile::TempDir;

const PASSWORD: &str = "Café-étoile";
const FAST: FfiKdfParams = FfiKdfParams {
    m_kib: 8192,
    t: 1,
    p: 1,
};

/// What the server holds: `(kind, id)` to `(version, data)`.
type Server = BTreeMap<(u8, String), (u64, Vec<u8>)>;

struct Device {
    _dir: TempDir,
    path: String,
    session: Arc<Session>,
    secret_key: String,
    sync: Arc<SyncStoreHandle>,
}

fn device() -> Device {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("onepass.db").to_string_lossy().into_owned();
    let created = create_account_with_kdf(path.clone(), PASSWORD.into(), FAST).unwrap();
    let sync = open_sync_store(path.clone()).unwrap();
    Device {
        _dir: dir,
        path,
        session: created.session,
        secret_key: created.secret_key,
        sync,
    }
}

/// Every pending write goes to the server and is confirmed.
fn push(dev: &Device, server: &mut Server) {
    for c in dev.sync.pending_changes().unwrap() {
        match &c.data {
            Some(d) => server.insert((c.kind, c.id.clone()), (c.version, d.clone())),
            None => server.remove(&(c.kind, c.id.clone())),
        };
        dev.sync
            .mark_pushed(c.kind, c.id, c.version, Some(vec![1]))
            .unwrap();
    }
}

/// A fetch from scratch of everything the server holds.
fn full_fetch(dev: &Device, server: &Server) {
    dev.sync.begin_full_fetch().unwrap();
    for ((kind, id), (version, data)) in server {
        dev.sync
            .stage_remote(FfiRemoteRecord {
                kind: *kind,
                id: id.clone(),
                version: *version,
                data: Some(data.clone()),
                server_meta: Some(vec![1]),
            })
            .unwrap();
    }
    dev.sync.commit_remote().unwrap();
    dev.sync.finish_full_fetch().unwrap();
}

/// A device with a vault "Atlas" (not safe for travel) holding one login,
/// everything pushed.
fn atlas(server: &mut Server) -> (Device, String) {
    let dev = device();
    let atlas = dev
        .session
        .create_vault(FfiVaultMeta {
            name: "Atlas".into(),
            icon: "briefcase".into(),
            color: "teal".into(),
            travel_safe: false,
            mcp_access: false,
        })
        .unwrap();
    note(&dev.session, &atlas.id, "Exemple");
    push(&dev, server);
    (dev, atlas.id)
}

/// A secure note in `vault`, saved.
fn note(s: &Session, vault: &str, title: &str) {
    let mut item = s
        .new_item(vault.into(), FfiItemType::SecureNote, title.into())
        .unwrap();
    for f in item.sections.iter_mut().flat_map(|x| x.fields.iter_mut()) {
        if f.id == "content" {
            f.value = FfiFieldValue::Text {
                value: "Projet Atlas".into(),
            };
        }
    }
    s.save_item(item).unwrap();
}

fn vault_names(s: &Session) -> Vec<String> {
    s.vaults()
        .unwrap()
        .into_iter()
        .map(|v| v.meta.name)
        .collect()
}

#[test]
fn round_trip_keeps_the_server_copy_and_survives_a_relaunch() {
    let mut server = Server::new();
    let (dev, atlas) = atlas(&mut server);
    let plan = dev.session.travel_plan().unwrap();
    assert!(plan.iter().any(|e| e.vault_id == atlas && e.leaves));

    let status = dev.session.enter_travel().unwrap();
    assert!(status.active && !status.exiting);
    assert!(status.hidden_count >= 1);
    assert!(dev.sync.pending_changes().unwrap().is_empty());
    assert!(!vault_names(&dev.session).contains(&"Atlas".to_string()));
    assert!(server.keys().any(|(_, id)| *id == atlas));

    // A fetch while travelling does not bring Atlas back.
    full_fetch(&dev, &server);
    assert!(!vault_names(&dev.session).contains(&"Atlas".to_string()));

    // A new session (relaunch, AutoFill extension) resumes the Travel Mode.
    dev.session.lock();
    let unlocked =
        unlock_with_password(dev.path.clone(), PASSWORD.into(), dev.secret_key.clone()).unwrap();
    let session = unlocked.session;
    assert!(session.travel_status().unwrap().active);
    assert!(!vault_names(&session).contains(&"Atlas".to_string()));

    let status = session.begin_travel_exit().unwrap();
    assert!(status.exiting);
    full_fetch(&dev, &server);
    let status = session.finish_travel_exit().unwrap();
    assert!(!status.active);
    assert!(vault_names(&session).contains(&"Atlas".to_string()));
    assert!(dev.sync.pending_changes().unwrap().is_empty());
}

#[test]
fn unsynced_writes_block_entering() {
    let mut server = Server::new();
    let (dev, atlas) = atlas(&mut server);
    note(&dev.session, &atlas, "Pas encore envoyé");
    let err = dev.session.enter_travel().unwrap_err();
    assert_eq!(
        err,
        OnePassError::InvalidInput {
            what: "unsynced changes".into()
        }
    );
    assert!(!dev.session.travel_status().unwrap().active);
}

#[test]
fn a_replayed_server_state_is_refused_and_the_vault_leaves_again() {
    let mut server = Server::new();
    let (dev, atlas) = atlas(&mut server);
    // The old manifest of Atlas, before a second write.
    let old: Vec<_> = server
        .iter()
        .filter(|((_, id), _)| *id == atlas)
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    note(&dev.session, &atlas, "Deux");
    push(&dev, &mut server);
    dev.session.enter_travel().unwrap();

    // The server serves the old key, meta and manifest again.
    for (k, v) in old {
        server.insert(k, v);
    }
    dev.session.begin_travel_exit().unwrap();
    full_fetch(&dev, &server);
    let err = dev.session.finish_travel_exit().unwrap_err();
    assert!(matches!(err, OnePassError::Integrity { .. }), "{err:?}");
    let status = dev.session.travel_status().unwrap();
    assert!(status.active && !status.exiting);
    assert!(!vault_names(&dev.session).contains(&"Atlas".to_string()));
    assert!(dev.sync.pending_changes().unwrap().is_empty());
}

#[test]
fn nothing_to_hide_is_refused() {
    let dev = device();
    for v in dev.session.vaults().unwrap() {
        if !v.meta.travel_safe {
            let mut meta = v.meta.clone();
            meta.travel_safe = true;
            dev.session.update_vault(v.id, meta).unwrap();
        }
    }
    assert!(dev.session.enter_travel().is_err());
}

/// A device whose every vault is safe for travel, with a login "Banque"
/// marked hidden in travel and a login "Mail" behind extra protection, in
/// the first vault, everything pushed. Returns the vault id and both item
/// ids.
fn per_item(server: &mut Server) -> (Device, String, String, String) {
    let dev = device();
    for v in dev.session.vaults().unwrap() {
        if !v.meta.travel_safe {
            let mut meta = v.meta.clone();
            meta.travel_safe = true;
            dev.session.update_vault(v.id, meta).unwrap();
        }
    }
    let vault = dev.session.vaults().unwrap()[0].id.clone();
    let mut bank = dev
        .session
        .new_item(vault.clone(), FfiItemType::Login, "Banque".into())
        .unwrap();
    bank.urls = vec![FfiUrl {
        label: String::new(),
        url: "https://banque.example".into(),
        rule: FfiMatchRule::Domain,
        primary: true,
    }];
    bank.tags = vec!["perso".into()];
    bank.travel_hidden = true;
    let bank = dev.session.save_item(bank).unwrap();
    let mut mail = dev
        .session
        .new_item(vault.clone(), FfiItemType::Login, "Mail".into())
        .unwrap();
    mail.urls = vec![FfiUrl {
        label: String::new(),
        url: "https://mail.example".into(),
        rule: FfiMatchRule::Domain,
        primary: true,
    }];
    mail.travel_guard = true;
    let mail = dev.session.save_item(mail).unwrap();
    push(&dev, server);
    (dev, vault, bank.id, mail.id)
}

fn titles(s: &Session, vault: &str) -> Vec<String> {
    let mut t: Vec<String> = s
        .item_summaries()
        .unwrap()
        .into_iter()
        .filter(|i| i.vault_id == vault)
        .map(|i| i.title)
        .collect();
    t.sort();
    t
}

#[test]
fn item_flags_are_booleans_and_never_tags() {
    let mut server = Server::new();
    let (dev, vault, bank, mail) = per_item(&mut server);
    let bank = dev.session.item(vault.clone(), bank).unwrap();
    assert!(bank.travel_hidden && !bank.travel_guard);
    assert_eq!(bank.tags, vec!["perso".to_string()]);
    let mail = dev.session.item(vault.clone(), mail).unwrap();
    assert!(mail.travel_guard && !mail.travel_hidden);
    assert!(mail.tags.is_empty());
    let summaries: Vec<_> = dev
        .session
        .item_summaries()
        .unwrap()
        .into_iter()
        .filter(|s| s.vault_id == vault)
        .collect();
    assert!(summaries.iter().all(|s| s.tags.iter().all(|t| !t.starts_with("onepass:"))));
    assert!(summaries.iter().any(|s| s.title == "Banque" && s.travel_hidden));
    assert!(summaries.iter().any(|s| s.title == "Mail" && s.travel_guard));
}

#[test]
fn a_hidden_item_leaves_and_comes_back_and_guarded_ones_are_not_offered() {
    let mut server = Server::new();
    let (dev, vault, bank, mail) = per_item(&mut server);
    let plan = dev.session.travel_item_plan().unwrap();
    assert_eq!(plan.hidden.len(), 1);
    assert_eq!(plan.hidden[0].title, "Banque");
    assert_eq!(plan.guarded.len(), 1);
    assert_eq!(
        dev.session
            .autofill_candidates("https://mail.example".into(), false, vec![])
            .unwrap()
            .len(),
        1
    );

    assert!(!dev.session.travelling().unwrap());
    let status = dev.session.enter_travel().unwrap();
    assert!(dev.session.travelling().unwrap());
    assert!(status.active && !status.exiting);
    assert_eq!(status.hidden_count, 0);
    assert_eq!(status.hidden_item_count, 1);
    assert!(dev.sync.pending_changes().unwrap().is_empty());
    assert_eq!(titles(&dev.session, &vault), vec!["Mail".to_string()]);
    assert!(dev.session.item(vault.clone(), bank.clone()).is_err());
    // Extra protection: offered nowhere outside the app while travelling.
    assert!(dev
        .session
        .autofill_candidates("https://mail.example".into(), true, vec![])
        .unwrap()
        .is_empty());
    assert!(dev
        .session
        .autofill_hidden_record_ids()
        .unwrap()
        .iter()
        .any(|r| r.ends_with(&mail)));

    // A fetch while travelling does not bring it back; a relaunch resumes.
    full_fetch(&dev, &server);
    assert_eq!(titles(&dev.session, &vault), vec!["Mail".to_string()]);
    dev.session.lock();
    let session =
        unlock_with_password(dev.path.clone(), PASSWORD.into(), dev.secret_key.clone())
            .unwrap()
            .session;
    assert_eq!(titles(&session, &vault), vec!["Mail".to_string()]);

    let status = session.begin_travel_exit().unwrap();
    assert!(status.exiting);
    full_fetch(&dev, &server);
    let status = session.finish_travel_exit().unwrap();
    assert!(!status.active);
    assert_eq!(
        titles(&session, &vault),
        vec!["Banque".to_string(), "Mail".to_string()]
    );
    assert_eq!(
        session
            .autofill_candidates("https://mail.example".into(), false, vec![])
            .unwrap()
            .len(),
        1
    );
    assert!(dev.sync.pending_changes().unwrap().is_empty());
}

#[test]
fn a_replayed_hidden_item_is_refused_and_it_leaves_again() {
    let mut server = Server::new();
    let (dev, vault, bank, _mail) = per_item(&mut server);
    // A second version of Banque; the server keeps the first one aside.
    let before = server.clone();
    let mut item = dev.session.item(vault.clone(), bank).unwrap();
    item.notes = "deux".into();
    dev.session.save_item(item).unwrap();
    push(&dev, &mut server);
    let added: Vec<_> = server
        .keys()
        .filter(|k| k.0 == 5 && !before.contains_key(k))
        .cloned()
        .collect();
    let removed: Vec<_> = before
        .iter()
        .filter(|(k, _)| k.0 == 5 && !server.contains_key(k))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    assert!(!added.is_empty() && !removed.is_empty());
    let session = &dev.session;
    session.enter_travel().unwrap();

    // The server serves the first version again.
    for k in added {
        server.remove(&k);
    }
    for (k, v) in removed {
        server.insert(k, v);
    }
    session.begin_travel_exit().unwrap();
    full_fetch(&dev, &server);
    let err = session.finish_travel_exit().unwrap_err();
    assert!(matches!(err, OnePassError::Integrity { .. }), "{err:?}");
    let status = session.travel_status().unwrap();
    assert!(status.active && !status.exiting);
    assert_eq!(status.hidden_item_count, 1);
    assert_eq!(titles(session, &vault), vec!["Mail".to_string()]);
    assert!(dev.sync.pending_changes().unwrap().is_empty());
}
