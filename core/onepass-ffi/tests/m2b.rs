//! Milestone 2b over the UniFFI surface, called as plain Rust: QR pairing
//! (full and public), the signed device list, vault deletion and master
//! password change. Two temp stores stand for two devices; a "sync" moves
//! pending rows of one into the base of the other, as the server would.
//! Synthetic data only. Run with `--features dev-fast-kdf`.

use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use onepass_ffi::*;
use tempfile::TempDir;

const PASSWORD: &str = "Café-étoile";
const NEW_PASSWORD: &str = "Nouveau-mot-de-passe-Atlas";
const FAST: FfiKdfParams = FfiKdfParams {
    m_kib: 8192,
    t: 1,
    p: 1,
};
const ITEM_KIND: u8 = 5;

fn now() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
}

fn db_path(dir: &Path) -> String {
    dir.join("onepass.db").to_string_lossy().into_owned()
}

struct Device {
    _dir: TempDir,
    path: String,
    session: Arc<Session>,
    secret_key: String,
    vault_id: String,
}

/// An account on its own device, registered in the device list, with one
/// login, everything pushed.
fn approver_device() -> Device {
    let dir = TempDir::new().unwrap();
    let path = db_path(dir.path());
    let created = create_account_with_kdf(path.clone(), PASSWORD.into(), FAST).unwrap();
    let vault_id = created.session.vaults().unwrap()[0].id.clone();
    created
        .session
        .register_this_device(
            "Mac de Camille".into(),
            FfiDeviceKind::Mac,
            FfiDeviceMode::Personal,
        )
        .unwrap();
    let d = Device {
        _dir: dir,
        path,
        session: created.session,
        secret_key: created.secret_key,
        vault_id,
    };
    save_login(&d, &d.vault_id, "Messagerie exemple.fr", "pw-atlas-1");
    push(&d.path);
    d
}

fn save_login(d: &Device, vault_id: &str, title: &str, password: &str) -> FfiItem {
    let mut item = d
        .session
        .new_item(vault_id.into(), FfiItemType::Login, title.into())
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
    d.session.save_item(item).unwrap()
}

/// The server accepts every pending row of `path`; returns them.
fn push(path: &str) -> Vec<FfiRecordChange> {
    let h = open_sync_store(path.into()).unwrap();
    let changes = h.pending_changes().unwrap();
    for c in &changes {
        h.mark_pushed(c.kind, c.id.clone(), c.version, Some(b"tag".to_vec()))
            .unwrap();
    }
    changes
}

/// Push `from`, then fetch those rows into `to`.
fn sync(from: &str, to: &str) {
    let changes = push(from);
    let h = open_sync_store(to.into()).unwrap();
    for c in changes {
        h.stage_remote(FfiRemoteRecord {
            kind: c.kind,
            id: c.id,
            version: c.version,
            data: c.data,
            server_meta: Some(b"tag".to_vec()),
        })
        .unwrap();
    }
    h.commit_remote().unwrap();
}

/// Both sides through the SAS and the newcomer's confirmation.
fn confirmed(mode: FfiDeviceMode) -> (Arc<PairingNewcomer>, Arc<PairingApprover>) {
    let n =
        PairingNewcomer::new("iPad de Camille".into(), FfiDeviceKind::Tablet, mode, now()).unwrap();
    let qr = n.qr_text();
    assert!(qr.starts_with("OPPAIR1:"));
    assert_eq!(pairing_service_name(qr.clone()).unwrap(), n.service_name());
    assert_eq!(n.service_name().len(), 32);
    let a = PairingApprover::begin(qr, n.hello(), now()).unwrap();
    assert_eq!(a.requested_mode(), mode);
    let peer = a.peer();
    assert_eq!(peer.name, "iPad de Camille");
    assert_eq!(peer.kind, FfiDeviceKind::Tablet);
    assert_eq!(peer.id, n.device_id());
    assert_eq!(a.service_name(), n.service_name());
    let sas = n.on_key_exchange(a.key_exchange(), now()).unwrap();
    assert_eq!(sas, a.sas());
    assert_eq!(sas.len(), 6);
    let f = n.confirm().unwrap();
    assert_eq!(a.on_frame(f).unwrap(), FfiPairingMessage::Confirmed);
    (n, a)
}

struct Newcomer {
    _dir: TempDir,
    path: String,
}

fn empty_device() -> Newcomer {
    let dir = TempDir::new().unwrap();
    let path = db_path(dir.path());
    Newcomer { _dir: dir, path }
}

#[test]
fn ffi_full_pairing_end_to_end() {
    let a = approver_device();
    let (n, ap) = confirmed(FfiDeviceMode::Personal);

    // Nothing is granted before the user's approval on the approver.
    let frame = ap
        .seal_full_grant(
            a.session.clone(),
            a.secret_key.clone(),
            FfiDeviceMode::Personal,
            false,
        )
        .unwrap();
    // A second grant is refused.
    assert!(
        ap.seal_full_grant(
            a.session.clone(),
            a.secret_key.clone(),
            FfiDeviceMode::Personal,
            false
        )
        .is_err()
    );
    let FfiPairingMessage::FullGrant {
        account_id,
        mode,
        device_id,
        snapshot_records,
    } = n.open(frame).unwrap()
    else {
        panic!("expected a full grant");
    };
    assert_eq!(account_id, a.session.account_id());
    assert_eq!(mode, FfiDeviceMode::Personal);
    assert_eq!(device_id, n.device_id());
    assert!(snapshot_records >= 6);
    // The Secret Key stays in the core until the import succeeds.
    assert_eq!(n.take_secret_key(), None);

    let ack = n.seal_ack().unwrap();
    assert_eq!(ap.on_frame(ack).unwrap(), FfiPairingMessage::Ack);

    let dev = empty_device();
    let unlocked = n
        .import_snapshot(dev.path.clone(), PASSWORD.into())
        .unwrap();
    assert_eq!(unlocked.auk.len(), 32);
    let sk = n.take_secret_key().unwrap();
    assert_eq!(sk, a.secret_key);
    assert_eq!(n.take_secret_key(), None, "taken once");
    // A second import is refused.
    assert!(
        n.import_snapshot(dev.path.clone(), PASSWORD.into())
            .is_err()
    );

    // Same vaults and items.
    let mine = unlocked.session.vaults().unwrap();
    let theirs = a.session.vaults().unwrap();
    assert_eq!(
        mine.iter().map(|v| v.id.clone()).collect::<Vec<_>>(),
        theirs.iter().map(|v| v.id.clone()).collect::<Vec<_>>()
    );
    assert_eq!(unlocked.session.item_summaries().unwrap().len(), 1);
    unlocked.session.lock();

    // The same password and the received Secret Key open it again.
    let again = unlock_with_password(dev.path.clone(), PASSWORD.into(), sk).unwrap();
    assert_eq!(again.session.this_device_id(), Some(n.device_id()));

    // The approver listed the newcomer; after a sync both see two devices.
    let listed = a.session.devices().unwrap();
    assert_eq!(listed.len(), 2);
    let me = a.session.this_device_id().unwrap();
    let added = listed.iter().find(|d| d.id == n.device_id()).unwrap();
    assert_eq!(added.added_by.as_deref(), Some(me.as_str()));
    assert_eq!(added.name, "iPad de Camille");
    assert_eq!(added.kind, FfiDeviceKind::Tablet);
    assert_eq!(added.mode, FfiDeviceMode::Personal);
    assert!(!added.is_this_device);
    assert!(listed.iter().any(|d| d.id == me && d.is_this_device));

    sync(&a.path, &dev.path);
    let seen = again.session.devices().unwrap();
    assert_eq!(seen.len(), 2);
    let self_entry = seen.iter().find(|d| d.is_this_device).unwrap();
    assert_eq!(self_entry.id, n.device_id());
    assert_eq!(self_entry.added_by.as_deref(), Some(me.as_str()));
    assert!(!again.session.is_this_device_revoked().unwrap());

    // Either side ends the session.
    let end = ap.seal_end().unwrap();
    assert_eq!(n.open(end).unwrap(), FfiPairingMessage::End);
}

#[test]
fn ffi_public_pairing_items_only() {
    let a = approver_device();
    let second = save_login(&a, &a.vault_id, "Code du portail", "pw-portail");
    let (n, ap) = confirmed(FfiDeviceMode::Public);

    // A public request never gets the account.
    assert!(
        ap.seal_full_grant(
            a.session.clone(),
            a.secret_key.clone(),
            FfiDeviceMode::Public,
            false
        )
        .is_err()
    );
    let refs = vec![FfiItemRef {
        vault_id: a.vault_id.clone(),
        item_id: second.id.clone(),
    }];
    for minutes in [0, 61] {
        assert!(
            ap.seal_public_grant(a.session.clone(), refs.clone(), minutes)
                .is_err()
        );
    }
    assert!(ap.seal_public_grant(a.session.clone(), vec![], 15).is_err());
    let before = now();
    let frame = ap.seal_public_grant(a.session.clone(), refs, 15).unwrap();
    let FfiPairingMessage::PublicGrant { expires_at, items } = n.open(frame).unwrap() else {
        panic!("expected a public grant");
    };
    assert!(expires_at >= before + 15 * 60 && expires_at <= now() + 15 * 60);
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].id, second.id);
    assert_eq!(items[0].title, "Code du portail");

    // Nothing of the account: no Secret Key, no import, nothing written.
    assert_eq!(n.take_secret_key(), None);
    let dev = empty_device();
    assert!(
        n.import_snapshot(dev.path.clone(), PASSWORD.into())
            .is_err()
    );
    assert_eq!(store_state(dev.path.clone()).unwrap(), FfiStoreState::Empty);
    // The public device is not listed.
    assert_eq!(a.session.devices().unwrap().len(), 1);

    let ack = n.seal_ack().unwrap();
    assert_eq!(ap.on_frame(ack).unwrap(), FfiPairingMessage::Ack);
    let at = now();
    let opened = n
        .seal_audit(second.id.clone(), FfiAuditAction::Opened, at)
        .unwrap();
    assert_eq!(
        ap.on_frame(opened).unwrap(),
        FfiPairingMessage::Audit {
            at,
            item_id: second.id.clone(),
            action: FfiAuditAction::Opened,
        }
    );
    let copied = n
        .seal_audit(
            second.id.clone(),
            FfiAuditAction::Copied {
                label: "Mot de passe".into(),
            },
            at + 1,
        )
        .unwrap();
    assert!(matches!(
        ap.on_frame(copied).unwrap(),
        FfiPairingMessage::Audit {
            action: FfiAuditAction::Copied { .. },
            ..
        }
    ));
    let end = n.seal_end().unwrap();
    assert_eq!(ap.on_frame(end).unwrap(), FfiPairingMessage::End);
    // Nothing passes after End.
    assert!(
        n.seal_audit(second.id, FfiAuditAction::Opened, at + 2)
            .is_err()
    );
}

#[test]
fn tampered_snapshot_rejected() {
    let a = approver_device();
    // A hostile server altered an item row the approver now holds in base.
    let h = open_sync_store(a.path.clone()).unwrap();
    let item = a.session.item_summaries().unwrap()[0].id.clone();
    let changes = {
        save_login(&a, &a.vault_id, "Autre", "pw-autre");
        push(&a.path)
    };
    let row = changes
        .iter()
        .find(|c| c.kind == ITEM_KIND && c.id != item)
        .unwrap()
        .clone();
    let mut data = row.data.clone().unwrap();
    let last = data.len() - 1;
    data[last] ^= 1;
    h.stage_remote(FfiRemoteRecord {
        kind: row.kind,
        id: row.id,
        version: row.version,
        data: Some(data),
        server_meta: Some(b"tag".to_vec()),
    })
    .unwrap();
    h.commit_remote().unwrap();

    let (n, ap) = confirmed(FfiDeviceMode::Shared);
    let frame = ap
        .seal_full_grant(
            a.session.clone(),
            a.secret_key.clone(),
            FfiDeviceMode::Shared,
            false,
        )
        .unwrap();
    assert!(matches!(
        n.open(frame).unwrap(),
        FfiPairingMessage::FullGrant { .. }
    ));
    let dev = empty_device();
    let err = n
        .import_snapshot(dev.path.clone(), PASSWORD.into())
        .err()
        .unwrap();
    assert!(matches!(err, OnePassError::Integrity { .. }), "{err:?}");
    // Nothing stays: an empty store and no Secret Key.
    assert_eq!(store_state(dev.path.clone()).unwrap(), FfiStoreState::Empty);
    assert_eq!(n.take_secret_key(), None);
}

#[test]
fn import_refuses_non_empty_store() {
    let a = approver_device();
    let (n, ap) = confirmed(FfiDeviceMode::Personal);
    let frame = ap
        .seal_full_grant(
            a.session.clone(),
            a.secret_key.clone(),
            FfiDeviceMode::Personal,
            false,
        )
        .unwrap();
    n.open(frame).unwrap();

    // The newcomer's store already holds another account: refused, and that
    // account is left alone.
    let dev = empty_device();
    let other = create_account_with_kdf(dev.path.clone(), "Autre-compte-1".into(), FAST).unwrap();
    let other_id = other.session.account_id();
    other.session.lock();
    assert!(
        n.import_snapshot(dev.path.clone(), PASSWORD.into())
            .is_err()
    );
    assert_eq!(n.take_secret_key(), None);
    let still =
        unlock_with_password(dev.path.clone(), "Autre-compte-1".into(), other.secret_key).unwrap();
    assert_eq!(still.session.account_id(), other_id);
}

#[test]
fn secret_key_withheld_after_failed_import() {
    let a = approver_device();
    let (n, ap) = confirmed(FfiDeviceMode::Personal);
    assert!(
        n.import_snapshot(empty_device().path, PASSWORD.into())
            .is_err(),
        "no grant yet"
    );
    let frame = ap
        .seal_full_grant(
            a.session.clone(),
            a.secret_key.clone(),
            FfiDeviceMode::Personal,
            false,
        )
        .unwrap();
    n.open(frame).unwrap();

    let dev = empty_device();
    assert_eq!(
        n.import_snapshot(dev.path.clone(), "mauvais-mot-de-passe".into())
            .err(),
        Some(OnePassError::WrongPassword)
    );
    assert_eq!(n.take_secret_key(), None);
    assert_eq!(store_state(dev.path.clone()).unwrap(), FfiStoreState::Empty);

    // The right password then works on the same, emptied store.
    n.import_snapshot(dev.path.clone(), PASSWORD.into())
        .unwrap();
    assert_eq!(n.take_secret_key(), Some(a.secret_key.clone()));
}

#[test]
fn ffi_change_password() {
    let a = approver_device();
    assert_eq!(a.session.params_epoch().unwrap(), 1);
    assert_eq!(store_params_epoch(a.path.clone()).unwrap(), 1);
    assert_eq!(pinned_params_epoch(a.path.clone()).unwrap(), 1);

    assert_eq!(
        a.session
            .change_password("faux".into(), a.secret_key.clone(), NEW_PASSWORD.into())
            .err(),
        Some(OnePassError::WrongPassword)
    );
    let auk = a
        .session
        .change_password(PASSWORD.into(), a.secret_key.clone(), NEW_PASSWORD.into())
        .unwrap();
    assert_eq!(auk.len(), 32);
    assert_eq!(a.session.params_epoch().unwrap(), 2);
    assert_eq!(store_params_epoch(a.path.clone()).unwrap(), 2);
    assert_eq!(pinned_params_epoch(a.path.clone()).unwrap(), 2);
    // The session goes on.
    assert_eq!(a.session.item_summaries().unwrap().len(), 1);
    a.session.lock();

    assert_eq!(
        unlock_with_password(a.path.clone(), PASSWORD.into(), a.secret_key.clone())
            .err()
            .map(|e| e.to_string()),
        Some(OnePassError::WrongPassword.to_string())
    );
    unlock_with_password(a.path.clone(), NEW_PASSWORD.into(), a.secret_key.clone()).unwrap();
    let s = unlock_with_auk(a.path.clone(), auk).unwrap();
    assert_eq!(s.params_epoch().unwrap(), 2);

    // Another device that has not unlocked since sees the change coming.
    let other = empty_device();
    let (n, ap) = confirmed(FfiDeviceMode::Personal);
    // The approver pushes the change, then pairs a device.
    push(&a.path);
    let frame = ap
        .seal_full_grant(
            s.clone(),
            a.secret_key.clone(),
            FfiDeviceMode::Personal,
            false,
        )
        .unwrap();
    n.open(frame).unwrap();
    let u = n
        .import_snapshot(other.path.clone(), NEW_PASSWORD.into())
        .unwrap();
    assert_eq!(pinned_params_epoch(other.path.clone()).unwrap(), 2);
    u.session.lock();
    assert!(store_params_epoch("/nonexistent/dir/onepass.db".into()).is_err());
}

#[test]
fn ffi_revoke_and_detect() {
    let a = approver_device();
    let (n, ap) = confirmed(FfiDeviceMode::Personal);
    let frame = ap
        .seal_full_grant(
            a.session.clone(),
            a.secret_key.clone(),
            FfiDeviceMode::Personal,
            false,
        )
        .unwrap();
    n.open(frame).unwrap();
    let dev = empty_device();
    let u = n
        .import_snapshot(dev.path.clone(), PASSWORD.into())
        .unwrap();
    sync(&a.path, &dev.path);
    assert!(!u.session.is_this_device_revoked().unwrap());

    // This device cannot revoke itself from the list.
    let me = a.session.this_device_id().unwrap();
    assert!(a.session.revoke_device(me).is_err());
    assert!(a.session.revoke_device("00".repeat(16)).is_err());

    a.session
        .rename_device(n.device_id(), "iPad du salon".into())
        .unwrap();
    a.session.revoke_device(n.device_id()).unwrap();
    // Revoking again changes nothing.
    a.session.revoke_device(n.device_id()).unwrap();
    let entry = a
        .session
        .devices()
        .unwrap()
        .into_iter()
        .find(|d| d.id == n.device_id())
        .unwrap();
    assert_eq!(entry.name, "iPad du salon");
    assert!(entry.revoked_at.is_some());
    assert!(a.session.rename_device(n.device_id(), "x".into()).is_err());

    sync(&a.path, &dev.path);
    assert!(u.session.is_this_device_revoked().unwrap());
    // A revoked device cannot register again.
    assert!(
        u.session
            .register_this_device(
                "iPad".into(),
                FfiDeviceKind::Tablet,
                FfiDeviceMode::Personal
            )
            .is_err()
    );
}

#[test]
fn ffi_delete_vault() {
    let a = approver_device();
    // The last vault cannot go.
    assert!(a.session.delete_vault(a.vault_id.clone()).is_err());
    let made = a
        .session
        .create_vault(FfiVaultMeta {
            name: "Projets".into(),
            icon: "folder".into(),
            color: "blue".into(),
            travel_safe: false,
            mcp_access: false,
        })
        .unwrap();
    assert_eq!(a.session.vaults().unwrap().len(), 2);
    // A vault with a live item cannot go.
    let item = save_login(&a, &made.id, "Projet Atlas", "pw-projet");
    assert!(a.session.delete_vault(made.id.clone()).is_err());
    a.session
        .trash_item(made.id.clone(), item.id.clone())
        .unwrap();
    a.session.delete_vault(made.id.clone()).unwrap();
    let left = a.session.vaults().unwrap();
    assert_eq!(left.len(), 1);
    assert_eq!(left[0].id, a.vault_id);
    assert_eq!(
        a.session.delete_vault(made.id).err(),
        Some(OnePassError::NotFound)
    );
}

#[test]
fn full_grant_without_sync_includes_local_state() {
    // An approver that never synced: everything it holds is pending.
    let dir = TempDir::new().unwrap();
    let path = db_path(dir.path());
    let created = create_account_with_kdf(path.clone(), PASSWORD.into(), FAST).unwrap();
    let vault_id = created.session.vaults().unwrap()[0].id.clone();
    created
        .session
        .register_this_device(
            "Mac de Camille".into(),
            FfiDeviceKind::Mac,
            FfiDeviceMode::Personal,
        )
        .unwrap();
    let a = Device {
        _dir: dir,
        path,
        session: created.session,
        secret_key: created.secret_key,
        vault_id,
    };
    save_login(&a, &a.vault_id, "Messagerie exemple.fr", "pw-atlas-1");
    let (n, ap) = confirmed(FfiDeviceMode::Personal);

    // The server view is empty: refused, and nothing is listed.
    assert!(
        ap.seal_full_grant(
            a.session.clone(),
            a.secret_key.clone(),
            FfiDeviceMode::Personal,
            false
        )
        .is_err()
    );
    assert_eq!(a.session.devices().unwrap().len(), 1);

    // The local view carries everything, the new device list included.
    let frame = ap
        .seal_full_grant(
            a.session.clone(),
            a.secret_key.clone(),
            FfiDeviceMode::Personal,
            true,
        )
        .unwrap();
    assert!(matches!(
        n.open(frame).unwrap(),
        FfiPairingMessage::FullGrant { .. }
    ));
    let dev = empty_device();
    let unlocked = n
        .import_snapshot(dev.path.clone(), PASSWORD.into())
        .unwrap();
    assert_eq!(n.take_secret_key(), Some(a.secret_key.clone()));
    let items = unlocked.session.item_summaries().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].title, "Messagerie exemple.fr");
    let seen = unlocked.session.devices().unwrap();
    assert_eq!(seen.len(), 2);
    assert!(
        seen.iter()
            .any(|d| d.id == n.device_id() && d.is_this_device)
    );
    assert!(!unlocked.session.is_this_device_revoked().unwrap());
}

#[test]
fn public_grant_strips_history_and_passkeys() {
    let a = approver_device();
    let item = save_login(&a, &a.vault_id, "Banque exemple.fr", "pw-ancien-1");
    // A second password leaves the first one in the history.
    let mut changed = a.session.item(a.vault_id.clone(), item.id.clone()).unwrap();
    for f in changed
        .sections
        .iter_mut()
        .flat_map(|s| s.fields.iter_mut())
    {
        if f.id == "password" {
            f.value = FfiFieldValue::Password {
                value: "pw-nouveau-2".into(),
            };
        }
    }
    let changed = a.session.save_item(changed).unwrap();
    assert_eq!(changed.password_history_count, 1);
    a.session
        .create_passkey(FfiPasskeyCreation {
            vault_id: a.vault_id.clone(),
            item_id: Some(item.id.clone()),
            rp_id: "exemple.fr".into(),
            user_name: "camille".into(),
            user_handle: vec![1, 2, 3, 4],
            client_data_hash: vec![9; 32],
            excluded_credential_ids: Vec::new(),
        })
        .unwrap();
    let has_passkey = |i: &FfiItem| {
        i.sections
            .iter()
            .flat_map(|s| &s.fields)
            .any(|f| matches!(f.value, FfiFieldValue::Passkey { .. }))
    };
    let stored = a.session.item(a.vault_id.clone(), item.id.clone()).unwrap();
    assert!(has_passkey(&stored));
    assert_eq!(stored.password_history_count, 1);

    let (n, ap) = confirmed(FfiDeviceMode::Public);
    let refs = vec![FfiItemRef {
        vault_id: a.vault_id.clone(),
        item_id: item.id.clone(),
    }];
    let frame = ap.seal_public_grant(a.session.clone(), refs, 15).unwrap();
    let FfiPairingMessage::PublicGrant { items, .. } = n.open(frame).unwrap() else {
        panic!("expected a public grant");
    };
    assert_eq!(items.len(), 1);
    let lent = &items[0];
    assert_eq!(lent.password_history_count, 0);
    assert!(!has_passkey(lent), "no passkey crosses to a public device");
    // The current password still does.
    assert!(lent.sections.iter().flat_map(|s| &s.fields).any(|f| f.value
        == FfiFieldValue::Password {
            value: "pw-nouveau-2".into()
        }));
    // The approver's item keeps both.
    let kept = a.session.item(a.vault_id.clone(), item.id.clone()).unwrap();
    assert!(has_passkey(&kept));
    assert_eq!(kept.password_history_count, 1);
}

#[test]
fn oversized_full_grant_lists_nothing() {
    // An approver without sync whose local view is above the 50 MiB cap: the
    // grant is refused and the device list stays as it was (L2: the device
    // is listed only once the grant is sealed).
    let a = approver_device();
    let note = "n".repeat(850 * 1024);
    let mut big = Vec::new();
    for i in 0..64 {
        let mut item = a
            .session
            .new_item(
                a.vault_id.clone(),
                FfiItemType::SecureNote,
                format!("Note {i}"),
            )
            .unwrap();
        for f in item.sections.iter_mut().flat_map(|s| s.fields.iter_mut()) {
            if f.id == "content" {
                f.value = FfiFieldValue::Text {
                    value: note.clone(),
                };
            }
        }
        big.push(a.session.save_item(item).unwrap().id);
    }
    let (n, ap) = confirmed(FfiDeviceMode::Personal);
    let err = ap
        .seal_full_grant(
            a.session.clone(),
            a.secret_key.clone(),
            FfiDeviceMode::Personal,
            true,
        )
        .unwrap_err();
    assert!(
        matches!(&err, OnePassError::InvalidInput { .. } if format!("{err:?}").contains("too large")),
        "{err:?}"
    );
    assert_eq!(a.session.devices().unwrap().len(), 1, "nothing listed");

    // Smaller now: the same pairing goes through and lists the device once.
    for id in big {
        a.session.delete_item(a.vault_id.clone(), id).unwrap();
    }
    let frame = ap
        .seal_full_grant(
            a.session.clone(),
            a.secret_key.clone(),
            FfiDeviceMode::Personal,
            true,
        )
        .unwrap();
    assert!(matches!(
        n.open(frame).unwrap(),
        FfiPairingMessage::FullGrant { .. }
    ));
    let listed = a.session.devices().unwrap();
    assert_eq!(listed.len(), 2);
    assert!(listed.iter().any(|d| d.id == n.device_id()));
}

#[test]
fn discarded_grant_cannot_be_imported() {
    // Too many wrong passwords, inactivity or leaving the screen drop the
    // received grant (M3): the Secret Key and the snapshot are gone.
    let a = approver_device();
    let (n, ap) = confirmed(FfiDeviceMode::Personal);
    let frame = ap
        .seal_full_grant(
            a.session.clone(),
            a.secret_key.clone(),
            FfiDeviceMode::Personal,
            false,
        )
        .unwrap();
    n.open(frame).unwrap();
    let dev = empty_device();
    assert_eq!(
        n.import_snapshot(dev.path.clone(), "mauvais-mot-de-passe".into())
            .err(),
        Some(OnePassError::WrongPassword)
    );
    n.discard_grant();
    assert!(
        n.import_snapshot(dev.path.clone(), PASSWORD.into())
            .is_err()
    );
    assert_eq!(n.take_secret_key(), None);
    assert_eq!(store_state(dev.path.clone()).unwrap(), FfiStoreState::Empty);
}
