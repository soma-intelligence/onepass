//! Restore and plaintext export over the UniFFI surface (milestone 5, apps
//! side). Run with `--features dev-fast-kdf`.

use std::sync::Arc;

use onepass_core::archive::format::{decode_container, encode_container};
use onepass_ffi::*;
use tempfile::TempDir;

const PASSWORD: &str = "Café-étoile";
const PASSPHRASE: &str = "orbite-velours-cascade-lanterne-92";
const FAST: FfiKdfParams = FfiKdfParams {
    m_kib: 8192,
    t: 1,
    p: 1,
};

struct Fixture {
    _dir: TempDir,
    session: Arc<Session>,
    vault_id: String,
}

fn fixture() -> Fixture {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("onepass.db").to_string_lossy().into_owned();
    let created = create_account_with_kdf(path, PASSWORD.into(), FAST).unwrap();
    let vault_id = created.session.vaults().unwrap()[0].id.clone();
    Fixture {
        _dir: dir,
        session: created.session,
        vault_id,
    }
}

fn saved_login(fx: &Fixture, title: &str, password: &str) -> FfiItem {
    let mut item = fx
        .session
        .new_item(fx.vault_id.clone(), FfiItemType::Login, title.into())
        .unwrap();
    for f in item.sections.iter_mut().flat_map(|s| s.fields.iter_mut()) {
        match f.id.as_str() {
            "username" => {
                f.value = FfiFieldValue::Text {
                    value: "camille@exemple.fr".into(),
                }
            }
            "password" => {
                f.value = FfiFieldValue::Password {
                    value: password.into(),
                }
            }
            _ => {}
        }
    }
    fx.session.save_item(item).unwrap()
}

fn backup(fx: &Fixture) -> Vec<u8> {
    fx.session
        .export_encrypted_backup_with_kdf(PASSPHRASE.as_bytes().to_vec(), FAST)
        .unwrap()
}

fn titles(fx: &Fixture) -> Vec<String> {
    let mut t: Vec<String> = fx
        .session
        .item_summaries()
        .unwrap()
        .into_iter()
        .map(|s| s.title)
        .collect();
    t.sort();
    t
}

#[test]
fn inspect_reads_the_header_only() {
    let fx = fixture();
    saved_login(&fx, "Atlas", "pw-atlas-1");
    let bytes = backup(&fx);
    let info = inspect_archive(bytes.clone()).unwrap();
    assert_eq!(info.kind, FfiArchiveKind::Backup);
    assert!(info.has_passphrase && info.signed && !info.newer_version);
    assert!(!info.for_this_account, "no session, no account");
    assert!(fx.session.archive_info(bytes).unwrap().for_this_account);
    assert!(matches!(
        inspect_archive(b"not an archive".to_vec()),
        Err(OnePassError::InvalidInput { .. })
    ));
}

#[test]
fn own_backup_restores_by_account_without_overwriting() {
    let fx = fixture();
    let kept = saved_login(&fx, "Atlas", "pw-atlas-1");
    let gone = saved_login(&fx, "Borée", "pw-boree-2");
    let bytes = backup(&fx);
    fx.session
        .delete_item(gone.vault_id.clone(), gone.id.clone())
        .unwrap();
    // The kept item changes after the backup: the restore must not touch it.
    let mut edited = fx
        .session
        .item(kept.vault_id.clone(), kept.id.clone())
        .unwrap();
    edited.title = "Atlas modifié".into();
    fx.session.save_item(edited).unwrap();

    let preview = fx.session.preview_restore(bytes.clone(), None).unwrap();
    assert!(preview.signature_verified);
    assert_eq!(
        (preview.items, preview.skipped, preview.vaults_created),
        (1, 1, 0)
    );
    assert_eq!(preview.epoch, None);
    assert_eq!(
        titles(&fx),
        vec!["Atlas modifié"],
        "a preview writes nothing"
    );

    let done = fx.session.restore_archive(bytes.clone(), None).unwrap();
    assert_eq!((done.items, done.skipped), (1, 1));
    assert!(done.epoch.is_some());
    assert_eq!(titles(&fx), vec!["Atlas modifié", "Borée"]);
    let back = fx.session.item(gone.vault_id, gone.id).unwrap();
    assert_eq!(back.title, "Borée");

    // Again: everything is already there.
    let again = fx.session.restore_archive(bytes, None).unwrap();
    assert_eq!((again.items, again.skipped), (0, 2));
}

#[test]
fn another_accounts_backup_needs_its_passphrase_and_creates_its_vaults() {
    let source = fixture();
    saved_login(&source, "Atlas", "pw-atlas-1");
    let bytes = backup(&source);
    let target = fixture();

    let info = target.session.archive_info(bytes.clone()).unwrap();
    assert!(!info.for_this_account && info.has_passphrase);
    assert_eq!(
        target.session.preview_restore(bytes.clone(), None),
        Err(OnePassError::InvalidInput {
            what: "archive passphrase".into()
        })
    );
    assert_eq!(
        target
            .session
            .preview_restore(bytes.clone(), Some(b"mauvaise-phrase-de-passe".to_vec())),
        Err(OnePassError::WrongPassword)
    );
    let done = target
        .session
        .restore_archive(bytes, Some(PASSPHRASE.as_bytes().to_vec()))
        .unwrap();
    assert!(!done.signature_verified);
    assert_eq!((done.items, done.vaults_created), (1, 1));
    assert_eq!(
        done.by_type,
        vec![FfiImportTypeCount {
            item_type: FfiItemType::Login,
            count: 1
        }]
    );
    assert_eq!(target.session.vaults().unwrap().len(), 2);
    assert_eq!(titles(&target), vec!["Atlas"]);
}

#[test]
fn tampered_backup_is_refused_with_a_signature_error() {
    let fx = fixture();
    saved_login(&fx, "Atlas", "pw-atlas-1");
    let bytes = backup(&fx);

    // Signature stripped: the header still names this account.
    let (mut header, sealed) = decode_container(&bytes).unwrap();
    header.signature = None;
    let stripped = encode_container(&header, sealed).unwrap();
    assert_eq!(
        fx.session.preview_restore(stripped.clone(), None),
        Err(OnePassError::Integrity {
            kind: "signature".into()
        })
    );
    // Even with the passphrase: an archive for this account opens by the account only.
    assert_eq!(
        fx.session
            .restore_archive(stripped, Some(PASSPHRASE.as_bytes().to_vec())),
        Err(OnePassError::Integrity {
            kind: "signature".into()
        })
    );

    // One bit of the payload flipped.
    let mut flipped = bytes.clone();
    let last = flipped.len() - 1;
    flipped[last] ^= 1;
    assert!(matches!(
        fx.session.restore_archive(flipped, None),
        Err(OnePassError::Integrity { .. })
    ));
    assert_eq!(titles(&fx), vec!["Atlas"], "nothing written");
}

#[test]
fn plaintext_csv_leaves_trash_out_and_reimports() {
    let fx = fixture();
    saved_login(&fx, "Atlas", "pw-atlas-1");
    let trashed = saved_login(&fx, "Corbeille", "pw-corbeille-3");
    fx.session.trash_item(trashed.vault_id, trashed.id).unwrap();
    let csv = fx.session.export_plaintext_csv(vec![]).unwrap();
    let text = String::from_utf8(csv.clone()).unwrap();
    assert!(text.starts_with("title,type,vault,url,username,password,otpauth,notes,tags,extra"));
    assert!(text.contains("pw-atlas-1"));
    assert!(!text.contains("Corbeille"));
    assert_eq!(
        detect_import_format("x.csv".into(), csv.clone()).as_deref(),
        Some("onepass-csv")
    );
    assert_eq!(preview_import("onepass-csv".into(), csv).unwrap().items, 1);

    assert_eq!(
        fx.session
            .export_plaintext_csv(vec![fx.vault_id.clone()])
            .unwrap(),
        fx.session.export_plaintext_csv(vec![]).unwrap()
    );
    assert_eq!(
        fx.session
            .export_plaintext_csv(vec!["00000000000000000000000000000001".into()]),
        Err(OnePassError::NotFound)
    );
}
