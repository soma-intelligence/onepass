//! Guarded Kit over the UniFFI surface, called as plain Rust: the settings
//! flow (on, renew, off), the unlock with a kept guard or the realms, the
//! password change and the owner poll, against `FfiTestRealmNet` (three
//! realms in this process). Synthetic data only. Run with
//! `--features dev-fast-kdf`.
#![cfg(feature = "dev-fast-kdf")]

use std::path::Path;

use onepass_ffi::*;
use tempfile::TempDir;

const FAST: FfiKdfParams = FfiKdfParams {
    m_kib: 8192,
    t: 1,
    p: 1,
};

fn db_path(dir: &Path) -> String {
    dir.join("onepass.sqlite").to_string_lossy().into_owned()
}

/// One test at a time: the test network is process-wide.
fn net() -> (
    std::sync::MutexGuard<'static, ()>,
    std::sync::Arc<FfiTestRealmNet>,
) {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    (g, FfiTestRealmNet::new().unwrap())
}

#[test]
fn guard_flow_over_ffi() {
    let (_l, net) = net();
    let dir = TempDir::new().unwrap();
    let path = db_path(dir.path());
    let created = create_account_with_kdf(path.clone(), "pw".into(), FAST).unwrap();
    let sk = created.secret_key.clone();
    let session = created.session;

    let s = session.guard_state().unwrap();
    assert!(s.available && !s.on);
    let on = session
        .enable_guard("pw".into(), sk.clone(), net.transport())
        .unwrap();
    assert_eq!(on.guard.len(), 32);
    assert_eq!(on.auk.len(), 32);
    let s = session.guard_state().unwrap();
    assert!(s.on && s.version == 1 && s.threshold == 2 && s.realm_set_current);
    assert_eq!(session.guard_secret().unwrap(), Some(on.guard.clone()));
    session.lock();

    // The plain unlock refuses; the kept guard and the realms open it.
    assert!(matches!(
        unlock_with_password(path.clone(), "pw".into(), sk.clone()).err(),
        Some(OnePassError::GuardRequired)
    ));
    let u = unlock_with_password_guarded(
        path.clone(),
        "pw".into(),
        sk.clone(),
        Some(on.guard.clone()),
        None,
    )
    .unwrap();
    assert_eq!(u.guard, Some(on.guard.clone()));
    u.session.lock();
    let u = unlock_with_password_guarded(
        path.clone(),
        "pw".into(),
        sk.clone(),
        None,
        Some(net.transport()),
    )
    .unwrap();
    u.session.lock();
    // The version tells the app its kept guard is current; a local check
    // with it needs no realm, and a wrong password stays local.
    assert_eq!(guard_version(path.clone()).unwrap(), Some(1));
    net.set_down(0, true).unwrap();
    net.set_down(1, true).unwrap();
    net.set_down(2, true).unwrap();
    assert_eq!(
        verify_password_guarded(path.clone(), "pw".into(), sk.clone(), on.guard.clone())
            .unwrap()
            .len(),
        32
    );
    assert!(matches!(
        verify_password_guarded(path.clone(), "nope".into(), sk.clone(), on.guard.clone()).err(),
        Some(OnePassError::WrongPassword)
    ));
    for i in 0..3 {
        net.set_down(i, false).unwrap();
    }
    // The biometric key still opens it.
    unlock_with_auk(path.clone(), on.auk.clone())
        .unwrap()
        .lock();

    // Wrong password at the realms: attempts left, and the poll sees it.
    match unlock_with_password_guarded(
        path.clone(),
        "nope".into(),
        sk.clone(),
        None,
        Some(net.transport()),
    )
    .err()
    {
        Some(OnePassError::GuardWrongPassword { remaining }) => assert_eq!(remaining, 9),
        other => panic!("expected GuardWrongPassword, got {other:?}"),
    }
    let session = unlock_with_auk(path.clone(), on.auk.clone()).unwrap();
    let h = session.guard_health(net.transport()).unwrap();
    assert_eq!(h.failures.len(), 1);
    assert_eq!((h.realms_answered, h.realms_total), (3, 3));
    assert!(!h.needs_renewal);

    // Two realms down: unavailable, not a wrong password.
    net.set_down(0, true).unwrap();
    net.set_down(1, true).unwrap();
    assert!(matches!(
        unlock_with_password_guarded(
            path.clone(),
            "pw".into(),
            sk.clone(),
            None,
            Some(net.transport())
        )
        .err(),
        Some(OnePassError::GuardUnavailable { .. })
    ));
    net.set_down(0, false).unwrap();
    net.set_down(1, false).unwrap();

    // Renew with a new G: the old one no longer opens.
    let renewed = session
        .renew_guard("pw".into(), sk.clone(), net.transport(), true)
        .unwrap();
    assert_ne!(renewed.guard, on.guard);
    assert_eq!(session.guard_state().unwrap().version, 2);

    // Password change on a guarded account.
    assert!(matches!(
        session
            .change_password("pw".into(), sk.clone(), "new".into())
            .err(),
        Some(OnePassError::GuardRequired)
    ));
    session
        .change_password_guarded("pw".into(), sk.clone(), "new".into(), net.transport())
        .unwrap();

    // Off: back to the password and the Secret Key alone.
    let auk = session
        .disable_guard("new".into(), sk.clone(), net.transport())
        .unwrap();
    assert_eq!(auk.len(), 32);
    assert!(!session.guard_state().unwrap().on);
    assert_eq!(session.guard_secret().unwrap(), None);
    session.lock();
    unlock_with_password(path, "new".into(), sk)
        .unwrap()
        .session
        .lock();
}
