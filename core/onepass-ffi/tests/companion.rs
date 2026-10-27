//! Companion surface tests. Run with `--features dev-fast-kdf`.

use onepass_ffi::*;
use tempfile::TempDir;

const SEED: &str = "JBSWY3DPEHPK3PXP";
const FAST: FfiKdfParams = FfiKdfParams {
    m_kib: 8192,
    t: 1,
    p: 1,
};

struct Fx {
    _dir: TempDir,
    session: std::sync::Arc<Session>,
    vault_id: String,
}

fn fx() -> Fx {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("onepass.db").to_string_lossy().into_owned();
    let created = create_account_with_kdf(path, "Café-étoile".into(), FAST).unwrap();
    let vault_id = created.session.vaults().unwrap()[0].id.clone();
    Fx {
        _dir: dir,
        session: created.session,
        vault_id,
    }
}

/// A Login with username and TOTP, `on_watch` and `favorite` as given.
fn save_login(fx: &Fx, on_watch: bool, favorite: bool) -> FfiItem {
    let mut item = fx
        .session
        .new_item(fx.vault_id.clone(), FfiItemType::Login, "Exemple".into())
        .unwrap();
    item.on_watch = on_watch;
    item.favorite = favorite;
    for f in item.sections.iter_mut().flat_map(|s| s.fields.iter_mut()) {
        match f.id.as_str() {
            "username" => {
                f.value = FfiFieldValue::Text {
                    value: "camille@exemple.fr".into(),
                }
            }
            "totp" | "otp" => f.value = FfiFieldValue::Otp { value: SEED.into() },
            _ => {}
        }
    }
    fx.session.save_item(item).unwrap()
}

#[test]
fn payload_round_trip_through_ffi() {
    let fx = fx();
    let item = save_login(&fx, true, false);
    let key = companion_generate_key().unwrap();
    let sealed = fx
        .session
        .companion_payload(key.public.clone(), 7, 1_000, vec![])
        .unwrap();
    let vault = CompanionVault::open(key.secret, sealed).unwrap();
    assert_eq!(vault.generation(), 7);
    assert_eq!(vault.generated_at(), 1_000);
    let entries = vault.entries();
    assert_eq!(entries.len(), 1);
    let e = &entries[0];
    assert_eq!(e.item_id, item.id);
    assert!(e.has_totp);
    assert!(e.fields.iter().any(|f| f.value == "camille@exemple.fr"));
    let got = vault.totp(item.id.clone(), 59).unwrap();
    assert_eq!(got.code, totp_now(SEED.into(), 59).unwrap().code);
    assert!(vault.totp("0".repeat(32), 59).is_none());
}

#[test]
fn entries_never_carry_seed() {
    let fx = fx();
    save_login(&fx, true, false);
    let key = companion_generate_key().unwrap();
    let sealed = fx
        .session
        .companion_payload(key.public, 1, 1_000, vec![])
        .unwrap();
    let vault = CompanionVault::open(key.secret, sealed).unwrap();
    for e in vault.entries() {
        assert!(e.fields.iter().all(|f| f.value != SEED));
    }
}

#[test]
fn open_rejects_bad_key_bytes() {
    let fx = fx();
    let key = companion_generate_key().unwrap();
    assert!(matches!(
        fx.session
            .companion_payload(vec![1, 2, 3], 1, 1_000, vec![]),
        Err(OnePassError::InvalidInput { .. })
    ));
    assert!(matches!(
        CompanionVault::open(vec![1, 2, 3], vec![0; 64]),
        Err(OnePassError::InvalidInput { .. })
    ));
    drop(key);
}

#[test]
fn hidden_vault_excluded() {
    let fx = fx();
    save_login(&fx, true, false);
    let key = companion_generate_key().unwrap();
    let sealed = fx
        .session
        .companion_payload(key.public, 1, 1_000, vec![fx.vault_id.clone()])
        .unwrap();
    let vault = CompanionVault::open(key.secret, sealed).unwrap();
    assert!(vault.entries().is_empty());
}

#[test]
fn glance_through_ffi() {
    let fx = fx();
    let item = save_login(&fx, false, true);
    let snap = fx.session.glance_snapshot(1_000, 3_600, vec![]).unwrap();
    assert_eq!(snap.favorites.len(), 1);
    assert_eq!(snap.favorites[0].item_id, item.id);
    assert_eq!(snap.codes.len(), 1);
    assert_eq!(snap.codes[0].period, 30);
    let n = snap.codes[0].codes.len();
    assert!(n == 120 || n == 121, "codes: {n}");
}

#[test]
fn locked_session_errors() {
    let fx = fx();
    let key = companion_generate_key().unwrap();
    fx.session.lock();
    assert!(matches!(
        fx.session.companion_payload(key.public, 1, 1_000, vec![]),
        Err(OnePassError::Locked)
    ));
    assert!(matches!(
        fx.session.glance_snapshot(1_000, 3_600, vec![]),
        Err(OnePassError::Locked)
    ));
}
