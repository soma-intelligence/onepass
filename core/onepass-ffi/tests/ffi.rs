//! Integration tests of the UniFFI surface, called as plain Rust.
//! Run with `--features dev-fast-kdf`: accounts use fast Argon2id parameters.

use std::path::Path;
use std::sync::Arc;

use onepass_ffi::*;
use tempfile::TempDir;

const PASSWORD: &str = "Café-étoile";
const ABOUT: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const FAST: FfiKdfParams = FfiKdfParams {
    m_kib: 8192,
    t: 1,
    p: 1,
};

struct Fixture {
    _dir: TempDir,
    path: String,
    session: Arc<Session>,
    secret_key: String,
    vault_id: String,
}

fn db_path(dir: &Path) -> String {
    dir.join("onepass.db").to_string_lossy().into_owned()
}

fn fixture() -> Fixture {
    let dir = TempDir::new().unwrap();
    let path = db_path(dir.path());
    let created = create_account_with_kdf(path.clone(), PASSWORD.into(), FAST).unwrap();
    let vault_id = created.session.vaults().unwrap()[0].id.clone();
    Fixture {
        _dir: dir,
        path,
        session: created.session,
        secret_key: created.secret_key,
        vault_id,
    }
}

fn text(value: &str) -> FfiFieldValue {
    FfiFieldValue::Text {
        value: value.into(),
    }
}

/// A valid fictitious value for each kind of field.
fn dummy(item_type: FfiItemType, field: &FfiField) -> FfiFieldValue {
    match (item_type, field.id.as_str()) {
        (FfiItemType::CreditCard, "number") => return text("4111111111111111"),
        (FfiItemType::BankAccount, "iban") => return text("FR7630006000011234567890189"),
        _ => {}
    }
    match field.kind {
        FfiFieldType::Text => text("Projet Atlas"),
        FfiFieldType::Concealed => FfiFieldValue::Concealed {
            value: "secret-42".into(),
        },
        FfiFieldType::Password => FfiFieldValue::Password {
            value: "Mot-de-passe-Atlas-7".into(),
        },
        FfiFieldType::Url => FfiFieldValue::Url {
            value: "https://exemple.fr".into(),
        },
        FfiFieldType::Email => FfiFieldValue::Email {
            value: "camille.durand@exemple.fr".into(),
        },
        FfiFieldType::Phone => FfiFieldValue::Phone {
            value: "+33102030405".into(),
        },
        FfiFieldType::Date => FfiFieldValue::Date {
            value: FfiDate {
                year: 2026,
                month: 1,
                day: 15,
            },
        },
        FfiFieldType::MonthYear => FfiFieldValue::MonthYear {
            year: 2030,
            month: 12,
        },
        FfiFieldType::Number => FfiFieldValue::Number { value: 42 },
        FfiFieldType::Money => FfiFieldValue::Money {
            minor_units: 1250,
            currency: "EUR".into(),
        },
        FfiFieldType::Address => FfiFieldValue::Address {
            value: FfiAddress {
                line1: "12 rue des Lilas".into(),
                line2: String::new(),
                city: "Lyon".into(),
                postal_code: "69001".into(),
                region: "Auvergne-Rhône-Alpes".into(),
                country: "FR".into(),
            },
        },
        FfiFieldType::Menu => FfiFieldValue::Menu {
            value: menu_options(item_type, field.id.clone())
                .first()
                .cloned()
                .unwrap_or_else(|| "oui".into()),
        },
        FfiFieldType::Otp => FfiFieldValue::Otp {
            value: "otpauth://totp/Exemple:camille?secret=GEZDGNBVGY3TQOJQ&issuer=Exemple".into(),
        },
        FfiFieldType::SshKey => FfiFieldValue::SshKey {
            value: FfiSshKey {
                private_pem: "-----BEGIN FAKE KEY-----\nAAAA\n-----END FAKE KEY-----".into(),
                public_openssh: "ssh-ed25519 AAAAexemple camille@exemple.fr".into(),
                fingerprint_sha256: "SHA256:exemple".into(),
            },
        },
        FfiFieldType::Location => FfiFieldValue::Location {
            value: FfiLocation {
                label: "Maison".into(),
                address: Some("12 rue des Lilas".into()),
                lat: 45.75,
                lon: 4.85,
                radius_m: 150,
                suggest_nearby: true,
            },
        },
        FfiFieldType::Mnemonic => FfiFieldValue::Mnemonic {
            value: ABOUT.into(),
        },
        FfiFieldType::Barcode => FfiFieldValue::Barcode {
            value: "123456789012".into(),
            format: FfiBarcodeFormat::Code128,
        },
        FfiFieldType::ItemLink => FfiFieldValue::ItemLink {
            item_id: "0123456789abcdef0123456789abcdef".into(),
        },
        FfiFieldType::File => FfiFieldValue::File {
            value: FfiAttachment {
                id: "fedcba9876543210fedcba9876543210".into(),
                name: "attestation.pdf".into(),
                size: 2048,
                mime: "application/pdf".into(),
            },
        },
        // Passkeys are not creatable from the UI.
        FfiFieldType::Passkey => FfiFieldValue::Empty,
    }
}

fn fill(item: &mut FfiItem) {
    let item_type = item.item_type;
    for section in &mut item.sections {
        for field in &mut section.fields {
            // A national number is checked against its country: leave both empty.
            if item_type == FfiItemType::SocialSecurityNumber && field.id == "country" {
                continue;
            }
            if item_type == FfiItemType::SocialSecurityNumber && field.id == "number" {
                field.value = text("123456");
                continue;
            }
            field.value = dummy(item_type, field);
        }
    }
}

fn set_password(item: &mut FfiItem, value: &str) {
    for f in item.sections.iter_mut().flat_map(|s| s.fields.iter_mut()) {
        if f.id == "password" {
            f.value = FfiFieldValue::Password {
                value: value.into(),
            };
        }
    }
}

fn login(fx: &Fixture, title: &str) -> FfiItem {
    fx.session
        .new_item(fx.vault_id.clone(), FfiItemType::Login, title.into())
        .unwrap()
}

fn saved_login(fx: &Fixture, password: &str) -> FfiItem {
    let mut item = login(fx, "Exemple");
    set_username(&mut item, "camille@exemple.fr");
    set_password(&mut item, password);
    fx.session.save_item(item).unwrap()
}

fn set_username(item: &mut FfiItem, value: &str) {
    for f in item.sections.iter_mut().flat_map(|s| s.fields.iter_mut()) {
        if f.id == "username" {
            f.value = text(value);
        }
    }
}

// ---- accounts -------------------------------------------------------------

#[test]
fn create_then_unlock_with_password_and_auk() {
    let fx = fixture();
    assert!(has_account(fx.path.clone()).unwrap());
    let account_id = fx.session.account_id();
    assert_eq!(account_id.len(), 32);
    fx.session.lock();

    let unlocked =
        unlock_with_password(fx.path.clone(), PASSWORD.into(), fx.secret_key.clone()).unwrap();
    assert_eq!(unlocked.session.account_id(), account_id);
    assert_eq!(unlocked.auk.len(), 32);
    assert_eq!(unlocked.session.vaults().unwrap().len(), 1);
    unlocked.session.lock();

    let session = unlock_with_auk(fx.path.clone(), unlocked.auk).unwrap();
    assert_eq!(session.account_id(), account_id);
    assert_eq!(session.vaults().unwrap()[0].id, fx.vault_id);
    assert!(unlock_with_auk(fx.path.clone(), vec![0; 5]).is_err());
}

#[test]
fn wrong_password_is_wrong_password() {
    let fx = fixture();
    fx.session.lock();
    let err = unlock_with_password(fx.path.clone(), "mauvais".into(), fx.secret_key.clone())
        .err()
        .unwrap();
    assert_eq!(err, OnePassError::WrongPassword);
}

#[test]
fn unlock_accepts_decomposed_accents() {
    let fx = fixture();
    fx.session.lock();
    let nfd = "Cafe\u{301}-e\u{301}toile";
    assert_ne!(nfd, PASSWORD);
    let unlocked =
        unlock_with_password(fx.path.clone(), nfd.into(), fx.secret_key.clone()).unwrap();
    assert_eq!(unlocked.session.vaults().unwrap().len(), 1);
}

#[test]
fn create_refuses_existing_account() {
    let fx = fixture();
    let err = create_account_with_kdf(fx.path.clone(), "autre".into(), FAST)
        .err()
        .unwrap();
    assert_eq!(
        err,
        OnePassError::InvalidInput {
            what: "account exists".into()
        }
    );
    // The first account is untouched.
    assert_eq!(fx.session.vaults().unwrap().len(), 1);
}

#[test]
fn kdf_under_the_floor_is_refused() {
    let dir = TempDir::new().unwrap();
    let weak = FfiKdfParams {
        m_kib: 1024,
        t: 1,
        p: 1,
    };
    let err = create_account_with_kdf(db_path(dir.path()), "x".into(), weak)
        .err()
        .unwrap();
    assert_eq!(
        err,
        OnePassError::InvalidInput {
            what: "kdf params".into()
        }
    );
}

#[test]
fn normalize_secret_key_accepts_lowercase_and_missing_dashes() {
    let fx = fixture();
    let typed = fx.secret_key.replace('-', " ").to_lowercase();
    assert_eq!(normalize_secret_key(typed).unwrap(), fx.secret_key);
    assert_eq!(
        normalize_secret_key(fx.secret_key.replace('-', "").to_lowercase()).unwrap(),
        fx.secret_key
    );
    assert!(matches!(
        normalize_secret_key("pas une clé".into()),
        Err(OnePassError::InvalidInput { .. })
    ));
}

// ---- items ----------------------------------------------------------------

#[test]
fn item_roundtrip_all_26_types() {
    let fx = fixture();
    let types = item_types();
    assert_eq!(types.len(), 26);
    for info in types {
        assert!(!info.label.is_empty());
        let mut item = fx
            .session
            .new_item(fx.vault_id.clone(), info.item_type, "Projet Atlas".into())
            .unwrap();
        assert_eq!(item.sections, template(info.item_type));
        fill(&mut item);
        item.tags = vec!["atlas".into(), "test".into()];
        item.notes = "Note de test".into();
        item.urls = vec![FfiUrl {
            label: "site".into(),
            url: "https://exemple.fr".into(),
            rule: FfiMatchRule::ExactHost,
            primary: true,
        }];
        item.expires = Some(FfiDate {
            year: 2031,
            month: 2,
            day: 28,
        });
        item.rotate_every_days = Some(90);
        let saved = fx
            .session
            .save_item(item.clone())
            .unwrap_or_else(|e| panic!("{:?}: {e:?}", info.item_type));
        let fetched = fx
            .session
            .item(fx.vault_id.clone(), item.id.clone())
            .unwrap();
        assert_eq!(fetched, saved, "{:?}", info.item_type);
        assert_eq!(fetched.sections, item.sections, "{:?}", info.item_type);
        assert_eq!(fetched.title, item.title);
        assert_eq!(fetched.tags, item.tags);
        assert_eq!(fetched.urls, item.urls);
        assert_eq!(fetched.expires, item.expires);
        assert_eq!(fetched.item_type, info.item_type);
    }
    assert_eq!(fx.session.item_summaries().unwrap().len(), 26);
}

#[test]
fn login_methods_and_ids_roundtrip() {
    let fx = fixture();
    let account = saved_login(&fx, "pw-fournisseur-1");
    let mut item = login(&fx, "Site via fournisseur");
    set_username(&mut item, "camille");
    item.login_methods = vec![
        FfiLoginMethod::Password,
        FfiLoginMethod::Passkey,
        FfiLoginMethod::Provider {
            provider: "google".into(),
            account_item_id: account.id.clone(),
            relay_email: None,
        },
        FfiLoginMethod::Provider {
            provider: "oidc:sso.exemple.fr".into(),
            account_item_id: account.id.clone(),
            relay_email: Some("relais@exemple.fr".into()),
        },
    ];
    let saved = fx.session.save_item(item.clone()).unwrap();
    assert_eq!(saved.login_methods, item.login_methods);
    assert_eq!(saved.id.len(), 32);
    assert!(
        saved
            .id
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
    );
    item.login_methods = vec![FfiLoginMethod::Provider {
        provider: "inconnu".into(),
        account_item_id: account.id,
        relay_email: None,
    }];
    assert_eq!(
        fx.session.save_item(item).unwrap_err(),
        OnePassError::InvalidInput {
            what: "provider".into()
        }
    );
}

#[test]
fn repeatable_fields_keep_order() {
    let fx = fixture();
    let mut item = login(&fx, "Codes");
    set_username(&mut item, "camille");
    let section = &mut item.sections[0];
    let pos = section
        .fields
        .iter()
        .position(|f| f.id == "backup_codes")
        .unwrap();
    assert!(section.fields[pos].repeatable);
    let mut proto = section.fields[pos].clone();
    for (i, code) in ["code-c", "code-a", "code-b"].iter().enumerate() {
        proto.value = FfiFieldValue::Concealed {
            value: (*code).into(),
        };
        if i == 0 {
            section.fields[pos] = proto.clone();
        } else {
            section.fields.insert(pos + i, proto.clone());
        }
    }
    let saved = fx.session.save_item(item).unwrap();
    let fetched = fx.session.item(fx.vault_id.clone(), saved.id).unwrap();
    let codes: Vec<String> = fetched.sections[0]
        .fields
        .iter()
        .filter(|f| f.id == "backup_codes")
        .map(|f| match &f.value {
            FfiFieldValue::Concealed { value } => value.clone(),
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(codes, ["code-c", "code-a", "code-b"]);
}

#[test]
fn password_change_goes_to_history() {
    let fx = fixture();
    let saved = saved_login(&fx, "ancien-mdp-1");
    assert_eq!(saved.password_history_count, 0);

    let mut edited = saved.clone();
    set_password(&mut edited, "nouveau-mdp-2");
    let saved = fx.session.save_item(edited).unwrap();
    assert_eq!(saved.password_history_count, 1);
    let history = fx
        .session
        .password_history(fx.vault_id.clone(), saved.id.clone())
        .unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].value, "ancien-mdp-1");

    // Saving without a change adds nothing.
    let again = fx.session.save_item(saved.clone()).unwrap();
    assert_eq!(again.password_history_count, 1);
    // A caller cannot rewrite the history.
    let mut forged = saved;
    forged.password_history_count = 0;
    assert_eq!(
        fx.session.save_item(forged).unwrap().password_history_count,
        1
    );
}

/// Store an item holding a passkey through the core, as the extension will.
fn plant_passkey(fx: &Fixture, item_id: &str) {
    use onepass_core::Id;
    use onepass_core::crypto::SecretKey;
    use onepass_core::model::{FieldValue, PasskeyCredential};
    use onepass_core::repo::Repository;
    use onepass_core::sync::SyncStore;
    use time::OffsetDateTime;

    fx.session.lock();
    let store = SyncStore::open(Path::new(&fx.path)).unwrap();
    let device = store.device_state().unwrap();
    let sk = SecretKey::parse(&fx.secret_key).unwrap();
    let mut repo = Repository::unlock(store, PASSWORD, &sk, device).unwrap();
    let vault = repo.vaults().unwrap().remove(0);
    let mut items = repo.items(&vault).unwrap();
    let mut item = items
        .drain(..)
        .find(|i| {
            i.id.0
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
                == item_id
        })
        .unwrap();
    let _: Id = item.id;
    item.field_mut("passkeys").unwrap().value = FieldValue::Passkey(PasskeyCredential {
        rp_id: "exemple.fr".into(),
        user_name: "camille".into(),
        user_handle: vec![7; 8],
        credential_id: vec![0xab, 0xcd, 0xef],
        private_key: zeroize::Zeroizing::new(vec![0x5a; 32]),
        created_at: OffsetDateTime::now_utc(),
    });
    repo.save_item(&vault, item).unwrap();
    repo.persist_device_state().unwrap();
}

/// The private key and user handle of the stored passkey, read by the core.
fn stored_passkey(fx: &Fixture, session_unlock: bool) -> (Vec<u8>, Vec<u8>) {
    use onepass_core::crypto::SecretKey;
    use onepass_core::model::FieldValue;
    use onepass_core::repo::Repository;
    use onepass_core::sync::SyncStore;

    if session_unlock {
        fx.session.lock();
    }
    let store = SyncStore::open(Path::new(&fx.path)).unwrap();
    let device = store.device_state().unwrap();
    let sk = SecretKey::parse(&fx.secret_key).unwrap();
    let mut repo = Repository::unlock(store, PASSWORD, &sk, device).unwrap();
    let vault = repo.vaults().unwrap().remove(0);
    for item in repo.items(&vault).unwrap() {
        if let Some(f) = item.field("passkeys")
            && let FieldValue::Passkey(p) = &f.value
        {
            return (p.private_key.to_vec(), p.user_handle.clone());
        }
    }
    panic!("no passkey");
}

#[test]
fn passkey_private_key_never_crosses_and_is_kept() {
    let fx = fixture();
    let saved = saved_login(&fx, "pw-passkey-1");
    plant_passkey(&fx, &saved.id);
    let unlocked =
        unlock_with_password(fx.path.clone(), PASSWORD.into(), fx.secret_key.clone()).unwrap();
    let session = unlocked.session;

    let item = session.item(fx.vault_id.clone(), saved.id.clone()).unwrap();
    let passkey = item
        .sections
        .iter()
        .flat_map(|s| s.fields.iter())
        .find_map(|f| match &f.value {
            FfiFieldValue::Passkey { value } => Some(value.clone()),
            _ => None,
        })
        .expect("passkey is listed");
    assert_eq!(passkey.credential_id_hex, "abcdef");
    // Nothing the UI receives carries the key bytes (0x5a, "5a5a...").
    assert!(!format!("{item:?}").contains("5a5a"));
    assert!(!format!("{item:?}").contains("90, 90"));

    // Edit the title and the passkey's display name, save, lock.
    let mut edited = item.clone();
    edited.title = "Exemple renommé".into();
    for f in edited.sections.iter_mut().flat_map(|s| s.fields.iter_mut()) {
        if let FfiFieldValue::Passkey { value } = &mut f.value {
            value.user_name = "camille.d".into();
        }
    }
    session.save_item(edited).unwrap();
    session.lock();
    let (key, handle) = stored_passkey(&fx, false);
    assert_eq!(key, vec![0x5a; 32]);
    assert_eq!(handle, vec![7; 8]);

    // A passkey the item never held cannot be invented from the UI.
    let session = unlock_with_password(fx.path.clone(), PASSWORD.into(), fx.secret_key.clone())
        .unwrap()
        .session;
    let mut forged = session.item(fx.vault_id.clone(), saved.id).unwrap();
    for f in forged.sections.iter_mut().flat_map(|s| s.fields.iter_mut()) {
        if let FfiFieldValue::Passkey { value } = &mut f.value {
            value.credential_id_hex = "010203".into();
        }
    }
    assert_eq!(
        session.save_item(forged).unwrap_err(),
        OnePassError::InvalidInput {
            what: "passkey".into()
        }
    );
}

#[test]
fn validation_error_names_field_not_value() {
    let fx = fixture();
    let mut item = fx
        .session
        .new_item(
            fx.vault_id.clone(),
            FfiItemType::CreditCard,
            "Carte Atlas".into(),
        )
        .unwrap();
    fill(&mut item);
    for f in item.sections.iter_mut().flat_map(|s| s.fields.iter_mut()) {
        if f.id == "number" {
            f.value = text("4111111111111112");
        }
    }
    let err = fx.session.save_item(item.clone()).unwrap_err();
    assert!(
        matches!(&err, OnePassError::Validation { field, .. } if field == "number"),
        "{err:?}"
    );
    let shown = format!("{err:?} {err}");
    assert!(!shown.contains("4111111111111112"));
    // The same verdict without a session, and nothing was stored.
    assert_eq!(validate_item(item).unwrap(), err);
    assert!(fx.session.item_summaries().unwrap().is_empty());

    let mut ok = fx
        .session
        .new_item(fx.vault_id.clone(), FfiItemType::SecureNote, "Note".into())
        .unwrap();
    assert!(validate_item(ok.clone()).is_some(), "required content");
    fill(&mut ok);
    assert_eq!(validate_item(ok), None);
}

#[test]
fn trash_restore_archive_move_delete() {
    let fx = fixture();
    let other = fx
        .session
        .create_vault(FfiVaultMeta {
            name: "Projet Atlas".into(),
            icon: "folder".into(),
            color: "#336699".into(),
            travel_safe: true,
            mcp_access: false,
        })
        .unwrap();
    assert_eq!(fx.session.vaults().unwrap().len(), 2);
    let item = saved_login(&fx, "pw-cycle-1");
    let find = |s: &Session| {
        s.item_summaries()
            .unwrap()
            .into_iter()
            .find(|i| i.id == item.id)
            .unwrap()
    };

    fx.session
        .trash_item(fx.vault_id.clone(), item.id.clone())
        .unwrap();
    assert!(find(&fx.session).trashed_at.is_some());
    fx.session
        .restore_item(fx.vault_id.clone(), item.id.clone())
        .unwrap();
    assert!(find(&fx.session).trashed_at.is_none());

    fx.session
        .archive_item(fx.vault_id.clone(), item.id.clone())
        .unwrap();
    assert!(find(&fx.session).archived);
    fx.session
        .unarchive_item(fx.vault_id.clone(), item.id.clone())
        .unwrap();
    assert!(!find(&fx.session).archived);

    fx.session
        .set_favorite(fx.vault_id.clone(), item.id.clone(), true)
        .unwrap();
    assert!(find(&fx.session).favorite);

    fx.session
        .move_item(item.id.clone(), fx.vault_id.clone(), other.id.clone())
        .unwrap();
    assert_eq!(find(&fx.session).vault_id, other.id);
    assert_eq!(
        fx.session
            .item(fx.vault_id.clone(), item.id.clone())
            .unwrap_err(),
        OnePassError::NotFound
    );
    let counts: Vec<u32> = fx
        .session
        .vaults()
        .unwrap()
        .iter()
        .map(|v| v.item_count)
        .collect();
    assert_eq!(counts.iter().sum::<u32>(), 1);

    fx.session
        .delete_item(other.id.clone(), item.id.clone())
        .unwrap();
    assert!(fx.session.item_summaries().unwrap().is_empty());
    assert_eq!(
        fx.session.item(other.id, item.id).unwrap_err(),
        OnePassError::NotFound
    );
}

#[test]
fn update_vault_renames() {
    let fx = fixture();
    let mut meta = fx.session.vaults().unwrap()[0].meta.clone();
    meta.name = "Famille".into();
    let v = fx.session.update_vault(fx.vault_id.clone(), meta).unwrap();
    assert_eq!(v.meta.name, "Famille");
    assert_eq!(fx.session.vaults().unwrap()[0].meta.name, "Famille");
}

#[test]
fn purge_trash_respects_age() {
    let fx = fixture();
    let kept = saved_login(&fx, "pw-garde-1");
    let doomed = saved_login(&fx, "pw-corbeille-1");
    fx.session
        .trash_item(fx.vault_id.clone(), doomed.id.clone())
        .unwrap();
    // Trashed just now: not old enough for 30 days, nor for 1.
    assert_eq!(fx.session.purge_trash(30).unwrap(), 0);
    assert_eq!(fx.session.purge_trash(1).unwrap(), 0);
    assert_eq!(fx.session.item_summaries().unwrap().len(), 2);
    assert_eq!(fx.session.purge_trash(0).unwrap(), 1);
    let left = fx.session.item_summaries().unwrap();
    assert_eq!(left.len(), 1);
    assert_eq!(left[0].id, kept.id);
}

#[test]
fn lock_makes_every_call_locked() {
    let fx = fixture();
    let item = saved_login(&fx, "pw-verrou-1");
    let (v, i) = (fx.vault_id.clone(), item.id.clone());
    fx.session.lock();
    let s = &fx.session;
    let meta = FfiVaultMeta {
        name: "x".into(),
        icon: "x".into(),
        color: "x".into(),
        travel_safe: false,
        mcp_access: false,
    };
    let locked = OnePassError::Locked;
    assert_eq!(s.vaults().unwrap_err(), locked);
    assert_eq!(s.create_vault(meta.clone()).unwrap_err(), locked);
    assert_eq!(s.update_vault(v.clone(), meta).unwrap_err(), locked);
    assert_eq!(s.item_summaries().unwrap_err(), locked);
    assert_eq!(s.item(v.clone(), i.clone()).unwrap_err(), locked);
    assert_eq!(
        s.new_item(v.clone(), FfiItemType::Login, "x".into())
            .unwrap_err(),
        locked
    );
    assert_eq!(s.save_item(item).unwrap_err(), locked);
    assert_eq!(s.trash_item(v.clone(), i.clone()).unwrap_err(), locked);
    assert_eq!(s.restore_item(v.clone(), i.clone()).unwrap_err(), locked);
    assert_eq!(s.archive_item(v.clone(), i.clone()).unwrap_err(), locked);
    assert_eq!(s.unarchive_item(v.clone(), i.clone()).unwrap_err(), locked);
    assert_eq!(s.delete_item(v.clone(), i.clone()).unwrap_err(), locked);
    assert_eq!(
        s.set_favorite(v.clone(), i.clone(), true).unwrap_err(),
        locked
    );
    assert_eq!(
        s.move_item(i.clone(), v.clone(), v.clone()).unwrap_err(),
        locked
    );
    assert_eq!(s.purge_trash(0).unwrap_err(), locked);
    assert_eq!(s.password_history(v, i).unwrap_err(), locked);
    assert_eq!(s.rebase_all().unwrap_err(), locked);
    // Locking twice is harmless, and account_id needs no key.
    s.lock();
    assert_eq!(s.account_id().len(), 32);
}

#[test]
fn summaries_have_no_secret_values() {
    let fx = fixture();
    let password = "S3cr3t-Atlas-Pw-91";
    let mut item = login(&fx, "Banque");
    set_username(&mut item, "camille@exemple.fr");
    set_password(&mut item, password);
    item.notes = "note privée".into();
    let saved = fx.session.save_item(item).unwrap();
    let summaries = fx.session.item_summaries().unwrap();
    assert_eq!(summaries.len(), 1);
    let shown = format!("{summaries:?}");
    assert!(!shown.contains(password));
    assert!(!shown.contains("note privée"));
    assert_eq!(summaries[0].subtitle, "camille@exemple.fr");
    assert_eq!(summaries[0].id, saved.id);
    // The debug output of a full item masks secrets too.
    assert!(!format!("{saved:?}").contains(password));
}

// ---- sync -----------------------------------------------------------------

#[test]
fn sync_handle_sees_pending_after_save() {
    let fx = fixture();
    let handle = open_sync_store(fx.path.clone()).unwrap();
    assert!(handle.has_account().unwrap());
    let count_items = |h: &SyncStoreHandle| {
        h.pending_changes()
            .unwrap()
            .iter()
            .filter(|c| c.kind == 5)
            .count()
    };
    let before = count_items(&handle);

    saved_login(&fx, "pw-sync-1");
    assert_eq!(count_items(&handle), before + 1);

    // Pushing everything empties the queue; a new save fills it again.
    for c in handle.pending_changes().unwrap() {
        handle
            .mark_pushed(c.kind, c.id, c.version, Some(vec![1, 2, 3]))
            .unwrap();
    }
    assert!(handle.pending_changes().unwrap().is_empty());
    saved_login(&fx, "pw-sync-2");
    assert_eq!(count_items(&handle), 1);

    handle.set_meta("zone-token".into(), vec![9, 9]).unwrap();
    assert_eq!(handle.meta("zone-token".into()).unwrap(), Some(vec![9, 9]));
    assert_eq!(handle.meta("absent".into()).unwrap(), None);
    assert!(handle.commit_remote().unwrap().is_empty());
    assert!(fx.session.rebase_all().unwrap().is_empty());
    assert_eq!(
        handle.mark_pushed(99, "0".repeat(32), 1, None).unwrap_err(),
        OnePassError::InvalidInput {
            what: "record kind".into()
        }
    );
}

#[test]
fn locked_handle_stages_and_commits_a_remote_change() {
    let fx = fixture();
    fx.session.lock();
    let handle = open_sync_store(fx.path.clone()).unwrap();
    let id = "00112233445566778899aabbccddeeff".to_string();
    handle
        .stage_remote(FfiRemoteRecord {
            kind: 4,
            id: id.clone(),
            version: 3,
            data: Some(vec![1, 2, 3]),
            server_meta: Some(vec![7]),
        })
        .unwrap();
    handle.commit_remote().unwrap();
    assert_eq!(handle.server_meta(4, id).unwrap(), Some(vec![7]));
}

// ---- free functions -------------------------------------------------------

#[test]
fn totp_now_from_uri_and_base32() {
    let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    let code = totp_now(secret.into(), 59).unwrap();
    assert_eq!(code.code, "287082");
    assert_eq!(code.period, 30);
    assert_eq!(code.remaining, 1);
    let uri = format!("otpauth://totp/Exemple:camille?secret={secret}&issuer=Exemple&digits=8");
    assert_eq!(totp_now(uri, 59).unwrap().code, "94287082");
    assert!(totp_now("pas base32 !!".into(), 59).is_err());
}

#[test]
fn generator_and_catalog_helpers() {
    let pw = generate_password(FfiPasswordRecipe::Characters {
        length: 24,
        digits: true,
        symbols: false,
        avoid_ambiguous: true,
    })
    .unwrap();
    assert_eq!(pw.chars().count(), 24);
    let words = generate_password(FfiPasswordRecipe::Words {
        count: 4,
        separator: "-".into(),
        french: true,
        capitalize: false,
    })
    .unwrap();
    assert_eq!(words.split('-').count(), 4);
    let pin = generate_password(FfiPasswordRecipe::Pin { length: 6 }).unwrap();
    assert!(pin.len() == 6 && pin.chars().all(|c| c.is_ascii_digit()));
    assert!(
        generate_password(FfiPasswordRecipe::Pin { length: 300 }).is_err(),
        "length over u8"
    );
    assert!(
        password_entropy_bits(FfiPasswordRecipe::Pin { length: 6 })
            < password_entropy_bits(FfiPasswordRecipe::Pin { length: 8 })
    );
    assert_eq!(
        password_entropy_bits(FfiPasswordRecipe::Pin { length: 300 }),
        0.0
    );

    assert_eq!(card_brand("4111111111111111".into()), "visa");
    assert_eq!(card_brand("n'importe quoi".into()), "unknown");
    assert!(
        menu_options(FfiItemType::Database, "engine".into()).contains(&"PostgreSQL".to_string())
    );
    assert!(menu_options(FfiItemType::Login, "username".into()).is_empty());
    assert_eq!(item_types()[0].item_type, FfiItemType::Login);
}

#[test]
fn unknown_ids_are_invalid_input_not_a_panic() {
    let fx = fixture();
    assert_eq!(
        fx.session.item("zz".into(), "zz".into()).unwrap_err(),
        OnePassError::InvalidInput { what: "id".into() }
    );
    assert_eq!(
        fx.session.item("0".repeat(32), "0".repeat(32)).unwrap_err(),
        OnePassError::NotFound
    );
}
