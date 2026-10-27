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
fn provider_login_saves_without_username_and_shows_provider() {
    let fx = fixture();
    let account = saved_login(&fx, "pw-fournisseur-2");
    let mut item = login(&fx, "Atlas via GitHub");
    assert!(matches!(
        fx.session.save_item(item.clone()).unwrap_err(),
        OnePassError::Validation { field, .. } if field == "username"
    ));
    item.login_methods = vec![
        FfiLoginMethod::Passkey,
        FfiLoginMethod::Provider {
            provider: "github".into(),
            account_item_id: account.id.clone(),
            relay_email: None,
        },
        FfiLoginMethod::Provider {
            provider: "oidc:sso.exemple.fr".into(),
            account_item_id: account.id.clone(),
            relay_email: None,
        },
    ];
    let saved = fx.session.save_item(item).unwrap();
    let summaries = fx.session.item_summaries().unwrap();
    let row = summaries.iter().find(|s| s.id == saved.id).unwrap();
    assert_eq!(row.subtitle, "");
    assert_eq!(row.sign_in_provider.as_deref(), Some("github"));
    let plain = summaries.iter().find(|s| s.id == account.id).unwrap();
    assert_eq!(plain.sign_in_provider, None);
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
fn document_without_file_validates_and_saves() {
    // Attachments come in milestone 5: until then a required file field counts as filled.
    let fx = fixture();
    let item = fx
        .session
        .new_item(
            fx.vault_id.clone(),
            FfiItemType::Document,
            "Attestation".into(),
        )
        .unwrap();
    assert_eq!(validate_item(item.clone()), None);
    let saved = fx.session.save_item(item).unwrap();
    let files = saved
        .sections
        .iter()
        .flat_map(|s| s.fields.iter())
        .find(|f| f.id == "files")
        .unwrap();
    // Stored without a file, marked not required until attachments exist.
    assert!(!files.required);
    assert_eq!(files.value, FfiFieldValue::Empty);
    // The template itself still requires files.
    assert!(
        template(FfiItemType::Document)
            .iter()
            .flat_map(|s| s.fields.iter())
            .any(|f| f.id == "files" && f.required)
    );
    // The title is still checked.
    let mut untitled = saved.clone();
    untitled.title = "  ".into();
    assert!(
        matches!(validate_item(untitled), Some(OnePassError::Validation { field, .. }) if field == "title")
    );
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
fn zone_reset_requeues_missing_records_after_a_full_fetch() {
    let fx = fixture();
    let handle = open_sync_store(fx.path.clone()).unwrap();
    saved_login(&fx, "pw-requeue");
    let first = handle.pending_changes().unwrap();
    for c in &first {
        handle
            .mark_pushed(c.kind, c.id.clone(), c.version, Some(vec![5]))
            .unwrap();
    }
    handle.set_meta("remote.token".into(), vec![1]).unwrap();
    assert!(handle.pending_changes().unwrap().is_empty());
    let some = &first[0];

    handle.begin_zone_reset("remote.token".into()).unwrap();
    assert_eq!(handle.meta("remote.token".into()).unwrap(), None);
    assert_eq!(
        handle.server_meta(some.kind, some.id.clone()).unwrap(),
        None
    );
    assert!(handle.pending_changes().unwrap().is_empty());

    assert!(!handle.finish_full_fetch().unwrap());
    assert_eq!(handle.pending_changes().unwrap().len(), first.len());
    assert!(!handle.finish_full_fetch().unwrap());
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

// ---- fix round 1 ----------------------------------------------------------

#[test]
fn purge_trash_huge_age_is_zero() {
    let fx = fixture();
    let item = saved_login(&fx, "pw-age-1");
    fx.session.trash_item(fx.vault_id.clone(), item.id).unwrap();
    assert_eq!(fx.session.purge_trash(u32::MAX).unwrap(), 0);
    assert_eq!(fx.session.item_summaries().unwrap().len(), 1);
}

#[test]
fn sync_handle_cannot_touch_device_state() {
    let fx = fixture();
    let handle = open_sync_store(fx.path.clone()).unwrap();
    // The core stores the anti-rollback state under this key.
    assert_eq!(handle.meta("device_state".into()).unwrap(), None);
    handle
        .set_meta("device_state".into(), vec![0xff; 4])
        .unwrap();
    assert_eq!(
        handle.meta("device_state".into()).unwrap(),
        Some(vec![0xff; 4])
    );
    // The session still unlocks and keeps working: its state was not replaced.
    fx.session.lock();
    let unlocked =
        unlock_with_password(fx.path.clone(), PASSWORD.into(), fx.secret_key.clone()).unwrap();
    assert_eq!(unlocked.session.vaults().unwrap().len(), 1);
    // Reading the raw key through a plain connection shows a namespaced row.
    let conn = rusqlite_free_keys(&fx.path);
    assert!(conn.contains(&"sync.device_state".to_string()));
    assert_eq!(
        conn.iter().filter(|k| k.as_str() == "device_state").count(),
        1,
        "only the core's own row"
    );
}

/// Keys of the `meta` table, read with the sqlite3 CLI-free core API: the
/// handle cannot list keys, so ask SQLite through a second core store.
fn rusqlite_free_keys(path: &str) -> Vec<String> {
    let mut keys = Vec::new();
    for k in ["device_state", "sync.device_state"] {
        let store = onepass_core::sync::SyncStore::open(Path::new(path)).unwrap();
        if store.meta(k).unwrap().is_some() {
            keys.push(k.to_string());
        }
    }
    keys
}

#[test]
fn save_item_with_stale_vault_is_conflict() {
    let fx = fixture();
    let other = fx
        .session
        .create_vault(FfiVaultMeta {
            name: "Projet Atlas".into(),
            icon: "folder".into(),
            color: "#336699".into(),
            travel_safe: false,
            mcp_access: false,
        })
        .unwrap();
    let item = saved_login(&fx, "pw-stale-1");
    fx.session
        .move_item(item.id.clone(), fx.vault_id.clone(), other.id.clone())
        .unwrap();
    // A stale editor still holds the old vault id.
    assert_eq!(
        fx.session.save_item(item).unwrap_err(),
        OnePassError::Conflict
    );
    assert_eq!(fx.session.item_summaries().unwrap().len(), 1);
}

#[test]
fn passkey_metadata_is_not_editable_and_duplicates_are_refused() {
    let fx = fixture();
    let saved = saved_login(&fx, "pw-passkey-2");
    plant_passkey(&fx, &saved.id);
    let session = unlock_with_password(fx.path.clone(), PASSWORD.into(), fx.secret_key.clone())
        .unwrap()
        .session;
    let item = session.item(fx.vault_id.clone(), saved.id.clone()).unwrap();
    let passkey_of = |i: &FfiItem| {
        i.sections
            .iter()
            .flat_map(|s| s.fields.iter())
            .find_map(|f| match &f.value {
                FfiFieldValue::Passkey { value } => Some(value.clone()),
                _ => None,
            })
            .unwrap()
    };
    let original = passkey_of(&item);

    let mut edited = item.clone();
    for f in edited.sections.iter_mut().flat_map(|s| s.fields.iter_mut()) {
        if let FfiFieldValue::Passkey { value } = &mut f.value {
            value.rp_id = "autre.exemple.fr".into();
            value.created_at = 0;
            value.user_name = "nouveau".into();
        }
    }
    let saved = session.save_item(edited).unwrap();
    let after = passkey_of(&saved);
    assert_eq!(after.rp_id, original.rp_id);
    assert_eq!(after.created_at, original.created_at);
    assert_eq!(after.user_name, "nouveau");

    // The same credential twice in one item.
    let mut dup = saved;
    let field = dup.sections[0]
        .fields
        .iter()
        .find(|f| matches!(f.value, FfiFieldValue::Passkey { .. }))
        .unwrap()
        .clone();
    dup.sections[0].fields.push(field);
    assert_eq!(
        session.save_item(dup).unwrap_err(),
        OnePassError::InvalidInput {
            what: "passkey".into()
        }
    );
}

#[test]
fn month_year_month_must_be_1_to_12() {
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
    for bad in [0u8, 13, 255] {
        for f in item.sections.iter_mut().flat_map(|s| s.fields.iter_mut()) {
            if let FfiFieldValue::MonthYear { month, .. } = &mut f.value {
                *month = bad;
            }
        }
        assert_eq!(
            fx.session.save_item(item.clone()).unwrap_err(),
            OnePassError::InvalidInput {
                what: "month".into()
            }
        );
    }
}

#[test]
fn totp_debug_masks_the_code_and_entropy_matches_generate() {
    let code = totp_now("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".into(), 59).unwrap();
    assert!(!format!("{code:?}").contains("287082"));
    // Out-of-range recipes: refused by generate, zero entropy.
    for r in [
        FfiPasswordRecipe::Characters {
            length: 3,
            digits: true,
            symbols: true,
            avoid_ambiguous: false,
        },
        FfiPasswordRecipe::Words {
            count: 0,
            separator: "-".into(),
            french: false,
            capitalize: false,
        },
        FfiPasswordRecipe::Pin { length: 2 },
    ] {
        assert!(generate_password(r.clone()).is_err());
        assert_eq!(password_entropy_bits(r), 0.0);
    }
}

#[test]
fn verify_password_returns_the_auk_and_never_writes_the_device_state() {
    let fx = fixture();
    let unlocked =
        unlock_with_password(fx.path.clone(), PASSWORD.into(), fx.secret_key.clone()).unwrap();
    unlocked.session.lock();
    // A device state that an unlock would change (it pins the account).
    {
        let mut store = onepass_core::sync::SyncStore::open(Path::new(&fx.path)).unwrap();
        store
            .set_device_state(&onepass_core::repo::DeviceState::default())
            .unwrap();
    }
    let read_state = || {
        onepass_core::sync::SyncStore::open(Path::new(&fx.path))
            .unwrap()
            .device_state()
            .unwrap()
    };
    let auk = verify_password(fx.path.clone(), PASSWORD.into(), fx.secret_key.clone()).unwrap();
    assert_eq!(auk, unlocked.auk);
    assert_eq!(read_state(), onepass_core::repo::DeviceState::default());
    assert_eq!(
        verify_password(fx.path.clone(), "mauvais".into(), fx.secret_key.clone()),
        Err(OnePassError::WrongPassword)
    );
    // A real unlock does persist.
    let again =
        unlock_with_password(fx.path.clone(), PASSWORD.into(), fx.secret_key.clone()).unwrap();
    again.session.lock();
    assert!(read_state().pinned.is_some());
}

#[test]
fn store_state_and_create_refuse_a_pinned_account_that_disappeared() {
    let fx = fixture();
    assert_eq!(
        store_state(fx.path.clone()).unwrap(),
        FfiStoreState::Account
    );
    let handle = open_sync_store(fx.path.clone()).unwrap();
    assert_eq!(handle.store_state().unwrap(), FfiStoreState::Account);
    fx.session.lock();
    // Push the local rows to base, then a "server" deletes the account
    // records: commit_remote ignores those deletions.
    for c in handle.pending_changes().unwrap() {
        handle
            .mark_pushed(c.kind, c.id, c.version, Some(vec![1]))
            .unwrap();
    }
    assert!(handle.pending_changes().unwrap().is_empty());
    let account_id = fx.session.account_id();
    for kind in [1u8, 2] {
        handle
            .stage_remote(FfiRemoteRecord {
                kind,
                id: account_id.clone(),
                version: 1,
                data: None,
                server_meta: None,
            })
            .unwrap();
    }
    handle.commit_remote().unwrap();
    assert_eq!(
        store_state(fx.path.clone()).unwrap(),
        FfiStoreState::Account
    );

    // The params record disappears anyway (a damaged file, here a local
    // tombstone hiding it): pinned but missing.
    {
        use onepass_core::store::{RecordKind, RecordStore};
        let mut store = onepass_core::sync::SyncStore::open(Path::new(&fx.path)).unwrap();
        let id = store.list(RecordKind::AccountParams).unwrap()[0].id;
        store.delete(RecordKind::AccountParams, id).unwrap();
    }
    assert_eq!(
        store_state(fx.path.clone()).unwrap(),
        FfiStoreState::PinnedButMissing
    );
    assert!(!has_account(fx.path.clone()).unwrap());
    let err = create_account_with_kdf(fx.path.clone(), "autre".into(), FAST)
        .err()
        .unwrap();
    assert_eq!(
        err,
        OnePassError::Integrity {
            kind: "account_missing".into()
        }
    );
}

#[test]
fn reset_store_empties_the_file_while_a_handle_stays_open() {
    let fx = fixture();
    let handle = open_sync_store(fx.path.clone()).unwrap();
    handle.set_meta("token".into(), vec![1, 2]).unwrap();
    assert!(!handle.pending_changes().unwrap().is_empty());
    fx.session.lock();
    reset_store(fx.path.clone()).unwrap();
    assert_eq!(store_state(fx.path.clone()).unwrap(), FfiStoreState::Empty);
    // The open handle sees the emptied file, not a stale unlinked copy.
    assert_eq!(handle.store_state().unwrap(), FfiStoreState::Empty);
    assert!(handle.pending_changes().unwrap().is_empty());
    assert_eq!(handle.meta("token".into()).unwrap(), None);
    // A new account in the same file is what the handle then syncs.
    let created = create_account_with_kdf(fx.path.clone(), PASSWORD.into(), FAST).unwrap();
    assert_eq!(handle.store_state().unwrap(), FfiStoreState::Account);
    assert!(!handle.pending_changes().unwrap().is_empty());
    created.session.lock();
}

#[test]
fn reset_store_for_recovery_drops_the_pin_and_lets_an_account_be_created() {
    let fx = fixture();
    let handle = open_sync_store(fx.path.clone()).unwrap();
    // A readable account is never wiped by the recovery path.
    assert!(matches!(
        reset_store_for_recovery(fx.path.clone()),
        Err(OnePassError::InvalidInput { .. })
    ));
    fx.session.lock();
    {
        use onepass_core::store::{RecordKind, RecordStore};
        let mut store = onepass_core::sync::SyncStore::open(Path::new(&fx.path)).unwrap();
        let id = store.list(RecordKind::AccountParams).unwrap()[0].id;
        store.delete(RecordKind::AccountParams, id).unwrap();
    }
    assert_eq!(
        store_state(fx.path.clone()).unwrap(),
        FfiStoreState::PinnedButMissing
    );
    handle.set_meta("remote.token".into(), vec![1]).unwrap();
    reset_store_for_recovery(fx.path.clone()).unwrap();
    // The pin is gone with everything else: the store is empty again.
    assert_eq!(store_state(fx.path.clone()).unwrap(), FfiStoreState::Empty);
    assert_eq!(handle.store_state().unwrap(), FfiStoreState::Empty);
    assert_eq!(handle.meta("remote.token".into()).unwrap(), None);
    assert_eq!(handle.account_id().unwrap(), None);
    let created = create_account_with_kdf(fx.path.clone(), PASSWORD.into(), FAST).unwrap();
    assert_eq!(handle.store_state().unwrap(), FfiStoreState::Account);
    assert_eq!(
        handle.account_id().unwrap(),
        Some(created.account_id.clone())
    );
    created.session.lock();
}

#[test]
fn ignored_deletions_are_listed_and_cleared() {
    let fx = fixture();
    let handle = open_sync_store(fx.path.clone()).unwrap();
    let account_id = fx.session.account_id();
    // Push everything so the account rows are in `base`.
    for change in handle.pending_changes().unwrap() {
        handle
            .mark_pushed(change.kind, change.id, change.version, Some(vec![1]))
            .unwrap();
    }
    assert!(handle.ignored_deletions().unwrap().is_empty());
    for kind in [1u8, 2] {
        handle
            .stage_remote(FfiRemoteRecord {
                kind,
                id: account_id.clone(),
                version: 1,
                data: None,
                server_meta: None,
            })
            .unwrap();
    }
    handle.commit_remote().unwrap();
    let log = handle.ignored_deletions().unwrap();
    assert_eq!(log.len(), 2);
    assert_eq!((log[0].kind, log[1].kind), (1, 2));
    assert!(log.iter().all(|e| e.id == account_id && e.at > 0));
    handle.clear_ignored_deletions().unwrap();
    assert!(handle.ignored_deletions().unwrap().is_empty());
    // The log is out of reach of the handle's own meta keys.
    handle
        .set_meta("ignored_deletions".into(), vec![0])
        .unwrap();
    assert!(handle.ignored_deletions().unwrap().is_empty());
    fx.session.lock();
}

// ---- security hardening: epochs, sync health, export, byte secrets ------

const BACKUP_PASSPHRASE: &str = "orbite-velours-cascade-lanterne-92";

/// A server as the app's sync coordinator sees it: the last pushed version
/// of every record (`None`: deleted).
type Server = std::collections::BTreeMap<(u8, String), (u64, Option<Vec<u8>>)>;

fn push(handle: &SyncStoreHandle, server: &mut Server) {
    for c in handle.pending_changes().unwrap() {
        server.insert((c.kind, c.id.clone()), (c.version, c.data.clone()));
        handle.mark_pushed(c.kind, c.id, c.version, None).unwrap();
    }
}

fn pull(handle: &SyncStoreHandle, server: &Server) {
    for ((kind, id), (version, data)) in server {
        handle
            .stage_remote(FfiRemoteRecord {
                kind: *kind,
                id: id.clone(),
                version: *version,
                data: data.clone(),
                server_meta: None,
            })
            .unwrap();
    }
    handle.commit_remote().unwrap();
}

/// A device in sync with its server, then a login saved and pushed, then
/// the server gone back to the state before the login (its manifest
/// rewound, the login's record deleted). Returns the server before the
/// rollback, the rolled back one, and the handle.
fn rolled_back_server(fx: &Fixture) -> (Server, Server, Arc<SyncStoreHandle>) {
    let handle = open_sync_store(fx.path.clone()).unwrap();
    let mut server = Server::new();
    push(&handle, &mut server);
    pull(&handle, &server);
    let old = server.clone();
    saved_login(fx, "pw-rollback");
    push(&handle, &mut server);
    pull(&handle, &server);
    let mut rolled = old.clone();
    for ((kind, id), (version, _)) in &server {
        if !old.contains_key(&(*kind, id.clone())) {
            rolled.insert((*kind, id.clone()), (version + 1, None));
        }
    }
    pull(&handle, &rolled);
    (server, rolled, handle)
}

fn health_of(fx: &Fixture) -> FfiHealthState {
    let health = fx.session.sync_health().unwrap();
    assert_eq!(health.len(), 1);
    assert_eq!(health[0].vault_id, fx.vault_id);
    health[0].state.clone()
}

fn titles(fx: &Fixture) -> Vec<String> {
    fx.session
        .item_summaries()
        .unwrap()
        .into_iter()
        .map(|s| s.title)
        .collect()
}

/// Full sync rounds (push, fetch, end of round) against an honest server
/// until the vault is `Ok`; fails on an alert or after 10 rounds.
fn sync_rounds_until_ok(fx: &Fixture, handle: &SyncStoreHandle, server: &mut Server) {
    for round in 0..10 {
        push(handle, server);
        pull(handle, server);
        fx.session.rebase_all().unwrap();
        fx.session.note_sync_round(1_700_000_000 + round).unwrap();
        match health_of(fx) {
            FfiHealthState::Ok => return,
            FfiHealthState::Alert { kind } => panic!("alert {kind}"),
            FfiHealthState::ServerBehind { .. } => {}
        }
    }
    panic!("still behind after 10 rounds");
}

#[test]
fn issue_restore_epoch_counts_up_and_is_remembered() {
    let fx = fixture();
    assert_eq!(fx.session.restore_epoch(), None);
    assert_eq!(
        fx.session
            .issue_restore_epoch(FfiEpochReason::Restore)
            .unwrap(),
        1
    );
    assert_eq!(fx.session.restore_epoch(), Some(1));
    assert_eq!(
        fx.session
            .issue_restore_epoch(FfiEpochReason::Restore)
            .unwrap(),
        2
    );
    // The epoch record waits for the push, with the vault's manifest.
    let handle = open_sync_store(fx.path.clone()).unwrap();
    assert!(
        handle
            .pending_changes()
            .unwrap()
            .iter()
            .any(|c| c.kind == 7)
    );
    fx.session.lock();
    let again =
        unlock_with_password(fx.path.clone(), PASSWORD.into(), fx.secret_key.clone()).unwrap();
    assert_eq!(again.session.restore_epoch(), Some(2));
    assert_eq!(again.session.restore_epoch(), Some(2));
    again.session.lock();
    assert_eq!(again.session.restore_epoch(), None);
    assert_eq!(
        again
            .session
            .issue_restore_epoch(FfiEpochReason::Restore)
            .unwrap_err(),
        OnePassError::Locked
    );
}

#[test]
fn sync_health_lists_every_vault_ok_and_note_sync_round_keeps_it() {
    let fx = fixture();
    assert_eq!(health_of(&fx), FfiHealthState::Ok);
    let second = fx
        .session
        .create_vault(FfiVaultMeta {
            name: "Famille".into(),
            icon: "folder".into(),
            color: "#336699".into(),
            travel_safe: true,
            mcp_access: false,
        })
        .unwrap();
    let health = fx.session.sync_health().unwrap();
    assert_eq!(health.len(), 2);
    assert!(health.iter().all(|h| h.state == FfiHealthState::Ok));
    assert!(health.iter().any(|h| h.vault_id == second.id));
    let mut ids: Vec<String> = health.iter().map(|h| h.vault_id.clone()).collect();
    ids.sort();
    assert_eq!(
        ids,
        health
            .iter()
            .map(|h| h.vault_id.clone())
            .collect::<Vec<_>>()
    );
    fx.session.note_sync_round(1_700_000_000).unwrap();
    assert!(
        fx.session
            .sync_health()
            .unwrap()
            .iter()
            .all(|h| h.state == FfiHealthState::Ok)
    );
}

#[test]
fn server_rollback_is_server_behind_then_counted_by_rounds() {
    let fx = fixture();
    let (_, _, _handle) = rolled_back_server(&fx);
    // The device serves its own copy: the login is still there.
    assert!(titles(&fx).contains(&"Exemple".to_string()));
    assert!(matches!(
        health_of(&fx),
        FfiHealthState::ServerBehind { .. }
    ));
    fx.session.note_sync_round(1_700_000_000).unwrap();
    assert_eq!(
        health_of(&fx),
        FfiHealthState::ServerBehind {
            since: 1_700_000_000,
            rounds: 1
        }
    );
}

#[test]
fn keep_this_device_after_a_server_rollback_issues_an_epoch_and_heals() {
    let fx = fixture();
    let (_, mut rolled, handle) = rolled_back_server(&fx);
    assert!(titles(&fx).contains(&"Exemple".to_string()));
    assert!(matches!(
        health_of(&fx),
        FfiHealthState::ServerBehind { .. }
    ));
    let epoch = fx.session.keep_this_device().unwrap();
    assert_eq!(epoch, 1);
    assert_eq!(fx.session.restore_epoch(), Some(1));
    // The copy goes to the server, which serves it back: the vault is `Ok`
    // again after a few clean rounds (never an alert on the way).
    sync_rounds_until_ok(&fx, &handle, &mut rolled);
    assert!(titles(&fx).contains(&"Exemple".to_string()));
    assert!(handle.pending_changes().unwrap().is_empty());
}

#[test]
fn take_server_after_a_server_rollback_drops_the_local_copy() {
    let fx = fixture();
    let (_, mut rolled, handle) = rolled_back_server(&fx);
    assert!(titles(&fx).contains(&"Exemple".to_string()));
    assert!(matches!(
        health_of(&fx),
        FfiHealthState::ServerBehind { .. }
    ));
    let epoch = fx.session.take_server().unwrap();
    assert_eq!(epoch, 1);
    assert_eq!(fx.session.restore_epoch(), Some(1));
    assert!(!titles(&fx).contains(&"Exemple".to_string()));
    sync_rounds_until_ok(&fx, &handle, &mut rolled);
    assert!(!titles(&fx).contains(&"Exemple".to_string()));
}

#[test]
fn rebase_with_report_reports_nothing_on_a_clean_store() {
    let fx = fixture();
    saved_login(&fx, "pw-report");
    let report = fx.session.rebase_with_report().unwrap();
    assert_eq!(
        report,
        FfiRebaseReport {
            rebased: Vec::new(),
            conflict: false,
            error: None,
        }
    );
    assert!(fx.session.rebase_all().unwrap().is_empty());
}

#[test]
fn rebase_with_report_lists_a_rebased_vault() {
    // Device A and its server.
    let fx = fixture();
    let a = open_sync_store(fx.path.clone()).unwrap();
    let mut server = Server::new();
    push(&a, &mut server);
    pull(&a, &server);
    // Device B: a second store filled from the server, then unlocked.
    let dir_b = TempDir::new().unwrap();
    let path_b = db_path(dir_b.path());
    let b = open_sync_store(path_b.clone()).unwrap();
    pull(&b, &server);
    let device_b = unlock_with_password(path_b, PASSWORD.into(), fx.secret_key.clone()).unwrap();
    // B writes and pushes; A writes offline, then fetches B's write.
    let mut item = device_b
        .session
        .new_item(fx.vault_id.clone(), FfiItemType::Login, "Depuis B".into())
        .unwrap();
    set_username(&mut item, "camille@exemple.fr");
    set_password(&mut item, "pw-device-b");
    device_b.session.save_item(item).unwrap();
    push(&b, &mut server);
    saved_login(&fx, "pw-device-a");
    pull(&a, &server);

    let report = fx.session.rebase_with_report().unwrap();
    assert_eq!(
        report,
        FfiRebaseReport {
            rebased: vec![fx.vault_id.clone()],
            conflict: false,
            error: None,
        }
    );
    let mut seen = titles(&fx);
    seen.sort();
    assert_eq!(seen, vec!["Depuis B".to_string(), "Exemple".to_string()]);
}

fn export_fast(fx: &Fixture, passphrase: &str) -> Result<Vec<u8>, OnePassError> {
    fx.session
        .export_encrypted_backup_with_kdf(passphrase.as_bytes().to_vec(), FAST)
}

#[test]
fn export_encrypted_backup_opens_with_the_passphrase_and_the_account() {
    use onepass_core::archive::{self, ArchiveKind, Unlock};
    let fx = fixture();
    let saved = saved_login(&fx, "pw-export");
    let bytes = export_fast(&fx, BACKUP_PASSPHRASE).unwrap();

    let info = archive::inspect(&bytes).unwrap();
    assert_eq!(info.kind, ArchiveKind::Backup);
    assert!(info.passphrase && info.signed);
    assert_eq!(
        info.account.map(|a| a.to_string().replace('-', "")),
        Some(fx.session.account_id())
    );

    let check = |contents: archive::Contents| {
        assert_eq!(contents.kind, ArchiveKind::Backup);
        assert_eq!(contents.vaults.len(), 1);
        let items = &contents.vaults[0].items;
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].title, saved.title);
    };
    check(archive::open(&bytes, Unlock::Passphrase(BACKUP_PASSPHRASE)).unwrap());
    assert!(archive::open(&bytes, Unlock::Passphrase("mauvaise-phrase")).is_err());

    let store = onepass_core::sync::SyncStore::open(Path::new(&fx.path)).unwrap();
    let device = store.device_state().unwrap();
    let secret_key = onepass_core::crypto::SecretKey::parse(&fx.secret_key).unwrap();
    let repo =
        onepass_core::repo::Repository::unlock(store, PASSWORD, &secret_key, device).unwrap();
    check(archive::open(&bytes, Unlock::Account(repo.account())).unwrap());
}

#[test]
fn export_encrypted_backup_refuses_weak_or_invalid_passphrases() {
    let fx = fixture();
    let weak = OnePassError::Validation {
        field: "passphrase".into(),
        reason: "too weak".into(),
    };
    // At the production floor: refused before Argon2id runs.
    assert_eq!(
        fx.session
            .export_encrypted_backup(b"azerty".to_vec())
            .unwrap_err(),
        weak
    );
    assert_eq!(
        fx.session
            .export_encrypted_backup(vec![0xff, 0xfe, 0x41])
            .unwrap_err(),
        OnePassError::InvalidInput {
            what: "passphrase".into()
        }
    );
    assert_eq!(export_fast(&fx, "azerty").unwrap_err(), weak);
    let weak_kdf = FfiKdfParams {
        m_kib: 1024,
        t: 1,
        p: 1,
    };
    assert_eq!(
        fx.session
            .export_encrypted_backup_with_kdf(BACKUP_PASSPHRASE.as_bytes().to_vec(), weak_kdf)
            .unwrap_err(),
        OnePassError::InvalidInput {
            what: "kdf params".into()
        }
    );
    fx.session.lock();
    assert_eq!(
        export_fast(&fx, BACKUP_PASSPHRASE).unwrap_err(),
        OnePassError::Locked
    );
}

#[test]
fn byte_variants_match_the_string_versions() {
    let dir = TempDir::new().unwrap();
    let path = db_path(dir.path());
    let created =
        create_account_with_kdf_bytes(path.clone(), PASSWORD.as_bytes().to_vec(), FAST).unwrap();
    let account_id = created.account_id.clone();
    created.session.lock();

    let by_string =
        unlock_with_password(path.clone(), PASSWORD.into(), created.secret_key.clone()).unwrap();
    by_string.session.lock();
    let by_bytes = unlock_with_password_bytes(
        path.clone(),
        PASSWORD.as_bytes().to_vec(),
        created.secret_key.as_bytes().to_vec(),
    )
    .unwrap();
    assert_eq!(by_bytes.auk, by_string.auk);
    assert_eq!(by_bytes.session.account_id(), account_id);
    by_bytes.session.lock();

    let verified = verify_password_bytes(
        path.clone(),
        PASSWORD.as_bytes().to_vec(),
        created.secret_key.as_bytes().to_vec(),
    )
    .unwrap();
    assert_eq!(
        verified,
        verify_password(path.clone(), PASSWORD.into(), created.secret_key.clone()).unwrap()
    );

    // Same errors as the String versions.
    assert_eq!(
        unlock_with_password_bytes(
            path.clone(),
            b"mauvais".to_vec(),
            created.secret_key.as_bytes().to_vec()
        )
        .err(),
        Some(OnePassError::WrongPassword)
    );
    assert_eq!(
        verify_password_bytes(
            path.clone(),
            b"mauvais".to_vec(),
            created.secret_key.as_bytes().to_vec()
        ),
        Err(OnePassError::WrongPassword)
    );
    assert_eq!(
        create_account_with_kdf_bytes(path.clone(), b"autre".to_vec(), FAST)
            .err()
            .unwrap(),
        OnePassError::InvalidInput {
            what: "account exists".into()
        }
    );
    assert_eq!(
        create_account_bytes(path.clone(), b"autre".to_vec())
            .err()
            .unwrap(),
        OnePassError::InvalidInput {
            what: "account exists".into()
        }
    );
}

#[test]
fn byte_variants_refuse_invalid_utf8() {
    let fx = fixture();
    fx.session.lock();
    let bad = vec![0xc3, 0x28];
    let password = OnePassError::InvalidInput {
        what: "password".into(),
    };
    // A non-ASCII typed Secret Key gets the same error.
    let key_err = normalize_secret_key("é".into()).unwrap_err();
    assert_eq!(
        key_err,
        OnePassError::InvalidInput {
            what: "secret key checksum".into()
        }
    );
    assert_eq!(
        unlock_with_password_bytes(
            fx.path.clone(),
            bad.clone(),
            fx.secret_key.clone().into_bytes()
        )
        .err(),
        Some(password.clone())
    );
    assert_eq!(
        unlock_with_password_bytes(fx.path.clone(), PASSWORD.as_bytes().to_vec(), bad.clone())
            .err(),
        Some(key_err.clone())
    );
    assert_eq!(
        verify_password_bytes(
            fx.path.clone(),
            bad.clone(),
            fx.secret_key.clone().into_bytes()
        ),
        Err(password.clone())
    );
    assert_eq!(
        verify_password_bytes(fx.path.clone(), PASSWORD.as_bytes().to_vec(), bad.clone()),
        Err(key_err)
    );
    let dir = TempDir::new().unwrap();
    assert_eq!(
        create_account_bytes(db_path(dir.path()), bad.clone()).err(),
        Some(password.clone())
    );
    assert_eq!(
        create_account_with_kdf_bytes(db_path(dir.path()), bad, FAST).err(),
        Some(password)
    );
    assert!(!has_account(db_path(dir.path())).unwrap());
}

#[test]
fn keep_needed_and_reset_sync_health() {
    let fx = fixture();
    assert!(!fx.session.keep_needed().unwrap());
    // The server went back: keeping this device's copy is useful.
    let (_, _, _handle) = rolled_back_server(&fx);
    assert!(titles(&fx).contains(&"Exemple".to_string()));
    assert!(matches!(
        health_of(&fx),
        FfiHealthState::ServerBehind { .. }
    ));
    assert!(fx.session.keep_needed().unwrap());
    // Forgetting the health discards nothing: the copy is still served
    // (and queued again for the server), the next rounds recount.
    fx.session.reset_sync_health().unwrap();
    assert_eq!(health_of(&fx), FfiHealthState::Ok);
    assert!(titles(&fx).contains(&"Exemple".to_string()));
    fx.session.lock();
    assert_eq!(fx.session.keep_needed(), Err(OnePassError::Locked));
    assert_eq!(fx.session.reset_sync_health(), Err(OnePassError::Locked));
}

#[test]
fn import_items_into_vault_with_new_ids_and_folder_tags() {
    let fx = fixture();
    let csv = b"folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n\
        Personal,1,login,Mail,,,0,https://mail.example.com,alice,Pw-Invented-1,\n\
        ,0,note,Memo,Invented body,,0,,,,\n"
        .to_vec();
    let format = detect_import_format("export.csv".into(), csv.clone()).unwrap();
    assert_eq!(format, "bitwarden-csv");
    let preview = preview_import(format.clone(), csv.clone()).unwrap();
    assert_eq!(preview.items, 2);

    let done = fx
        .session
        .import_items(format.clone(), csv.clone(), fx.vault_id.clone())
        .unwrap();
    assert_eq!(done.items, 2);
    let again = fx
        .session
        .import_items(format, csv, fx.vault_id.clone())
        .unwrap();
    assert_eq!(again.items, 2);

    let all = fx.session.item_summaries().unwrap();
    assert_eq!(all.len(), 4, "a second import adds, never overwrites");
    let mail: Vec<_> = all.iter().filter(|s| s.title == "Mail").collect();
    assert_eq!(mail.len(), 2);
    assert_ne!(mail[0].id, mail[1].id);
    assert!(mail.iter().all(|s| s.vault_id == fx.vault_id));
    assert_eq!(mail[0].tags, vec!["Personal".to_owned()]);
    assert!(mail[0].favorite);
}

#[test]
fn import_into_unknown_vault_writes_nothing() {
    let fx = fixture();
    let csv = b"name,url,username,password\nA,https://a.example.com,u,p\n".to_vec();
    let other = "0".repeat(32);
    assert_eq!(
        fx.session.import_items("chrome-csv".into(), csv, other),
        Err(OnePassError::NotFound)
    );
    assert!(fx.session.item_summaries().unwrap().is_empty());
}
