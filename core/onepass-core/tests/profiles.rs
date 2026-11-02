//! The account directory of a device (multi-account spec 2026-11-02,
//! section 4) and the isolation of two accounts on one device (M1).

use std::fs;
use std::path::Path;

use onepass_core::crypto::{KdfParams, random_array};
use onepass_core::profiles::{
    ACCOUNTS_FOLDER, AccountColor, AccountDirectory, AccountKind, DIRECTORY_FILE, MAX_ACCOUNTS,
    STORE_FILE, Slot, normalize_domain, store_path,
};
use onepass_core::repo::Repository;
use onepass_core::sync::SyncStore;
use onepass_core::{Error, Id};

fn folder() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}

fn business(dir: &mut AccountDirectory) -> Slot {
    dir.add(AccountKind::Business, "Soma Labs", AccountColor::Orange, 1)
        .unwrap()
}

fn invalid(e: Error) -> bool {
    matches!(e, Error::InvalidFormat(_))
}

#[test]
fn a_device_without_file_has_the_primary_account_alone_and_writes_nothing() {
    let tmp = folder();
    let dir = AccountDirectory::load(tmp.path()).unwrap();
    assert_eq!(dir, AccountDirectory::implicit());
    assert_eq!(dir.entries.len(), 1);
    assert!(dir.active.is_primary());
    assert!(!dir.unified_search);
    assert!(!tmp.path().join(DIRECTORY_FILE).exists());
}

#[test]
fn add_bind_save_load_round_trip() {
    let tmp = folder();
    let mut dir = AccountDirectory::load(tmp.path()).unwrap();
    let slot = business(&mut dir);
    assert!(!slot.is_primary());
    assert_eq!(slot.as_str().len(), 32);
    let id = Id::new();
    dir.bind(&slot, id).unwrap();
    dir.set_active(&slot).unwrap();
    dir.save(tmp.path()).unwrap();
    let loaded = AccountDirectory::load(tmp.path()).unwrap();
    assert_eq!(loaded, dir);
    let entry = loaded.entry(&slot).unwrap();
    assert_eq!(entry.account_id, Some(id));
    assert_eq!(entry.kind, AccountKind::Business);
    assert_eq!(entry.label, "Soma Labs");
    assert_eq!(loaded.active, slot);
    // No temporary file left behind.
    let names: Vec<String> = fs::read_dir(tmp.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, vec![DIRECTORY_FILE.to_string()]);
}

#[test]
fn the_same_account_is_never_bound_to_two_slots_and_a_binding_never_changes() {
    let mut dir = AccountDirectory::implicit();
    let a = business(&mut dir);
    let b = dir
        .add(AccountKind::Personal, "Famille", AccountColor::Green, 2)
        .unwrap();
    let id = Id::new();
    dir.bind(&a, id).unwrap();
    dir.bind(&a, id).unwrap();
    assert_eq!(dir.bind(&b, id), Err(Error::Conflict));
    assert_eq!(dir.bind(&a, Id::new()), Err(Error::Conflict));
    assert_eq!(dir.bind(&Slot::primary(), id), Err(Error::Conflict));
}

#[test]
fn a_store_of_another_account_is_refused() {
    let mut dir = AccountDirectory::implicit();
    let slot = business(&mut dir);
    let id = Id::new();
    assert_eq!(dir.check_binding(&slot, Some(id)), Ok(()));
    dir.bind(&slot, id).unwrap();
    assert_eq!(dir.check_binding(&slot, Some(id)), Ok(()));
    assert_eq!(dir.check_binding(&slot, None), Ok(()));
    assert_eq!(
        dir.check_binding(&slot, Some(Id::new())),
        Err(Error::Conflict)
    );
}

#[test]
fn the_primary_account_is_never_removed_and_the_active_one_falls_back() {
    let mut dir = AccountDirectory::implicit();
    let slot = business(&mut dir);
    dir.set_active(&slot).unwrap();
    assert!(invalid(dir.remove(&Slot::primary()).unwrap_err()));
    let removed = dir.remove(&slot).unwrap();
    assert_eq!(removed.slot, slot);
    assert!(dir.active.is_primary());
    assert_eq!(dir.remove(&slot), Err(Error::NotFound));
    assert_eq!(dir.set_active(&slot), Err(Error::NotFound));
}

#[test]
fn at_most_eight_accounts() {
    let mut dir = AccountDirectory::implicit();
    for i in 1..MAX_ACCOUNTS {
        dir.add(
            AccountKind::Business,
            &format!("Compte {i}"),
            AccountColor::Teal,
            0,
        )
        .unwrap();
    }
    assert!(invalid(
        dir.add(AccountKind::Business, "Neuf", AccountColor::Teal, 0)
            .unwrap_err()
    ));
}

#[test]
fn labels_are_checked() {
    let mut dir = AccountDirectory::implicit();
    for bad in ["", "   ", "a\u{0}b", "line\nbreak", &"x".repeat(65)] {
        assert!(
            invalid(
                dir.add(AccountKind::Business, bad, AccountColor::Blue, 0)
                    .unwrap_err()
            ),
            "{bad:?}"
        );
    }
    // Trimmed on the way in.
    let slot = dir
        .add(AccountKind::Business, "  Soma  ", AccountColor::Blue, 0)
        .unwrap();
    assert_eq!(dir.entry(&slot).unwrap().label, "Soma");
    // The primary account may keep an empty label.
    dir.update(&Slot::primary(), "", AccountColor::Blue, &[])
        .unwrap();
}

#[test]
fn managed_accounts_need_an_https_server() {
    let mut dir = AccountDirectory::implicit();
    for url in ["http://org.example", "https://", "https://a b", "ftp://x"] {
        let kind = AccountKind::Managed {
            server_url: url.into(),
            org_id: Id::new(),
        };
        assert!(invalid(
            dir.add(kind, "Org", AccountColor::Indigo, 0).unwrap_err()
        ));
    }
    let kind = AccountKind::Managed {
        server_url: "https://onepass.example.org".into(),
        org_id: Id::new(),
    };
    let slot = dir
        .add(kind.clone(), "Org", AccountColor::Indigo, 0)
        .unwrap();
    assert_eq!(dir.entry(&slot).unwrap().kind, kind);
}

#[test]
fn work_domains_are_normalized_and_claimed_once() {
    let mut dir = AccountDirectory::implicit();
    let slot = business(&mut dir);
    dir.update(
        &slot,
        "Soma Labs",
        AccountColor::Orange,
        &[
            "SomaLabs.me.".into(),
            "somalabs.me".into(),
            "xn--bcher-kva.example".into(),
        ],
    )
    .unwrap();
    assert_eq!(
        dir.entry(&slot).unwrap().work_domains,
        vec!["somalabs.me", "xn--bcher-kva.example"]
    );
    assert!(invalid(
        dir.update(
            &Slot::primary(),
            "",
            AccountColor::Blue,
            &["somalabs.me".into()]
        )
        .unwrap_err()
    ));
    for bad in [
        "com",
        "*.somalabs.me",
        "192.168.1.1",
        "-a.com",
        "a..com",
        "bücher.example",
        "a b.com",
        "",
    ] {
        assert!(normalize_domain(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn route_matches_on_label_boundaries_and_prefers_the_longest_domain() {
    let mut dir = AccountDirectory::implicit();
    let work = business(&mut dir);
    let lab = dir
        .add(AccountKind::Business, "Lab", AccountColor::Purple, 0)
        .unwrap();
    dir.update(
        &work,
        "Soma Labs",
        AccountColor::Orange,
        &["somalabs.me".into()],
    )
    .unwrap();
    dir.update(
        &lab,
        "Lab",
        AccountColor::Purple,
        &["lab.somalabs.me".into()],
    )
    .unwrap();
    assert_eq!(dir.route("somalabs.me"), work);
    assert_eq!(dir.route("Mail.SomaLabs.me."), work);
    assert_eq!(dir.route("x.lab.somalabs.me"), lab);
    assert_eq!(dir.route("lab.somalabs.me"), lab);
    assert!(dir.route("evilsomalabs.me").is_primary());
    assert!(dir.route("somalabs.me.evil.com").is_primary());
    assert!(dir.route("github.com").is_primary());
    assert!(dir.route("").is_primary());
    assert!(dir.route("not a host").is_primary());
}

#[test]
fn store_paths_derive_from_the_slot_only() {
    let base = Path::new("/container/OnePass");
    assert_eq!(
        store_path(base, &Slot::primary()),
        base.join(STORE_FILE),
        "the primary store keeps its path"
    );
    let slot = Slot::parse("0123456789abcdef0123456789abcdef").unwrap();
    assert_eq!(
        store_path(base, &slot),
        base.join(ACCOUNTS_FOLDER)
            .join("0123456789abcdef0123456789abcdef")
            .join(STORE_FILE)
    );
    for bad in [
        "../../etc",
        "0123456789ABCDEF0123456789ABCDEF",
        "0123",
        "primary/..",
        "",
    ] {
        assert!(Slot::parse(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn a_tampered_file_is_refused() {
    let tmp = folder();
    let mut dir = AccountDirectory::implicit();
    let slot = business(&mut dir);
    dir.save(tmp.path()).unwrap();
    let path = tmp.path().join(DIRECTORY_FILE);
    let original = fs::read_to_string(&path).unwrap();

    let cases = [
        original.replace(slot.as_str(), "../../../../tmp/evil"),
        original.replace("\"version\": 1", "\"version\": 2"),
        original.replace(slot.as_str(), "primary"),
        original.replace(
            "\"active\": \"primary\"",
            "\"active\": \"ffffffffffffffffffffffffffffffff\"",
        ),
        "{".to_string(),
    ];
    for (i, text) in cases.iter().enumerate() {
        fs::write(&path, text).unwrap();
        assert!(
            matches!(
                AccountDirectory::load(tmp.path()),
                Err(Error::InvalidFormat(_))
            ),
            "case {i}"
        );
    }
}

#[test]
fn duplicate_account_ids_in_a_file_are_refused() {
    let mut dir = AccountDirectory::implicit();
    let a = business(&mut dir);
    let b = dir
        .add(AccountKind::Personal, "Famille", AccountColor::Green, 0)
        .unwrap();
    let id = Id::new();
    dir.entries[1].account_id = Some(id);
    dir.entries[2].account_id = Some(id);
    assert_eq!(dir.validate(), Err(Error::Conflict));
    let _ = (a, b);
}

#[test]
fn reorder_keeps_the_primary_first() {
    let mut dir = AccountDirectory::implicit();
    let a = business(&mut dir);
    let b = dir
        .add(AccountKind::Personal, "Famille", AccountColor::Green, 0)
        .unwrap();
    dir.reorder(&b, 0).unwrap();
    let order: Vec<&Slot> = dir.entries.iter().map(|e| &e.slot).collect();
    assert_eq!(order, vec![&Slot::primary(), &b, &a]);
    assert!(invalid(dir.reorder(&Slot::primary(), 2).unwrap_err()));
    dir.validate().unwrap();
}

fn kdf() -> KdfParams {
    KdfParams {
        m_kib: 8192,
        t: 1,
        p: 1,
        salt: random_array().unwrap(),
    }
}

/// M1: two accounts on one device, one store file each, the same master
/// password: neither Secret Key opens the other store, each store opens
/// with its own.
#[test]
fn two_accounts_in_two_files_share_no_key() {
    const PASSWORD: &str = "le même mot de passe partout";
    let tmp = folder();
    let mut dir = AccountDirectory::implicit();
    let slot = business(&mut dir);
    let personal_path = store_path(tmp.path(), &Slot::primary());
    let business_path = store_path(tmp.path(), &slot);
    fs::create_dir_all(business_path.parent().unwrap()).unwrap();

    let (personal, personal_sk) =
        Repository::create_account(SyncStore::open(&personal_path).unwrap(), PASSWORD, kdf())
            .unwrap();
    let (work, work_sk) =
        Repository::create_account(SyncStore::open(&business_path).unwrap(), PASSWORD, kdf())
            .unwrap();
    let personal_id = personal.account().params.account_id;
    let work_id = work.account().params.account_id;
    assert_ne!(personal_id, work_id);
    assert!(!personal_sk.same_as(&work_sk));
    dir.bind(&Slot::primary(), personal_id).unwrap();
    dir.bind(&slot, work_id).unwrap();
    drop((personal, work));

    let open = |path: &Path, sk| {
        let store = SyncStore::open(path).unwrap();
        let state = store.device_state().unwrap();
        Repository::unlock(store, PASSWORD, sk, state)
    };
    // The other account's Secret Key never opens a store.
    assert!(open(&personal_path, &work_sk).is_err());
    assert!(open(&business_path, &personal_sk).is_err());
    // Each store opens with its own, and holds its own account.
    let mut reopened = open(&business_path, &work_sk).unwrap();
    assert_eq!(reopened.account().params.account_id, work_id);
    reopened.persist_device_state().unwrap();
    let mut reopened = open(&personal_path, &personal_sk).unwrap();
    assert_eq!(reopened.account().params.account_id, personal_id);
    reopened.persist_device_state().unwrap();

    // The stored pin names each store's account, so M4 can tell them apart.
    let pinned = |path: &Path| {
        SyncStore::open(path)
            .unwrap()
            .device_state()
            .unwrap()
            .pinned
            .map(|p| p.account_id)
    };
    assert_eq!(pinned(&business_path), Some(work_id));
    assert_eq!(
        dir.check_binding(&Slot::primary(), pinned(&business_path)),
        Err(Error::Conflict)
    );
    assert_eq!(dir.check_binding(&slot, pinned(&business_path)), Ok(()));
}
