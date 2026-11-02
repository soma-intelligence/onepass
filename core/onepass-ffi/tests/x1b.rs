//! X1b over the UniFFI surface (cross-platform spec D.4, D.5, D.7): the
//! Secret Key locator and recovery credential against the mailbox, grants
//! and their refusal, the abandon of a fresh mailbox, a `SyncHome` signed
//! then adopted, and a follower's enroll request verified by another device
//! of the account. Same loopback shim as `mailbox.rs`. Synthetic data only.
//! Run with `--features dev-fast-kdf`.

#![allow(dead_code, unused_imports)]

include!("support/mailbox_shim.rs");

fn backend_of(home: &FfiMailboxHome, base_url: &str) -> FfiSyncBackend {
    FfiSyncBackend::Mailbox {
        base_url: base_url.into(),
        mailbox_id: home.mailbox_id.clone(),
    }
}

#[test]
fn locator_registered_then_located() {
    let shim = Shim::start();
    let a = legacy_first(&shim);
    let locator = mailbox_locator(a.secret_key.clone()).unwrap();
    assert_eq!(locator.len(), 16);
    assert_eq!(
        mailbox_locate(shim.endpoint(), locator.clone()).unwrap(),
        Vec::<String>::new()
    );
    a.sync.set_locator(locator.clone()).unwrap();
    assert_eq!(
        mailbox_locate(shim.endpoint(), locator).unwrap(),
        vec![a.home.mailbox_id.clone()]
    );
    // A malformed locator never leaves the device.
    assert!(matches!(
        mailbox_locate(shim.endpoint(), vec![0; 15]),
        Err(OnePassError::InvalidInput { .. })
    ));
}

#[test]
fn recovery_credential_reads_after_grant() {
    let shim = Shim::start();
    let a = legacy_first(&shim);
    let rc = mailbox_recovery_credential(a.secret_key.clone(), a.home.mailbox_id.clone()).unwrap();
    // Derived, so the same twice; bound to the mailbox.
    let again =
        mailbox_recovery_credential(a.secret_key.clone(), a.home.mailbox_id.clone()).unwrap();
    assert_eq!(rc.seed, again.seed);
    let elsewhere = mailbox_recovery_credential(a.secret_key.clone(), "00".repeat(16)).unwrap();
    assert_ne!(rc.public_key, elsewhere.public_key);

    let id = a
        .sync
        .grant(rc.public_key.clone(), FfiCredentialRole::Manage, vec![])
        .unwrap();
    assert_eq!(id, rc.id);
    shim.register(&rc);

    // A restoring device, with nothing but the recovery credential.
    let dir = TempDir::new().unwrap();
    let path = db_path(dir.path());
    let sync = MailboxSync::open(
        path,
        shim.endpoint(),
        a.home.mailbox_id.clone(),
        rc.seed.clone(),
    )
    .unwrap();
    let report = settle(&sync, None);
    assert!(report.changed, "the restoring device fetched the account");
}

#[test]
fn a_reader_cannot_grant() {
    let shim = Shim::start();
    let a = legacy_first(&shim);
    let reader = shim.credential();
    a.sync
        .grant(reader.public_key.clone(), FfiCredentialRole::Read, vec![])
        .unwrap();
    let dir = TempDir::new().unwrap();
    let sync = MailboxSync::open(
        db_path(dir.path()),
        shim.endpoint(),
        a.home.mailbox_id.clone(),
        reader.seed,
    )
    .unwrap();
    let other = mailbox_generate_credential().unwrap();
    assert_eq!(
        sync.grant(other.public_key, FfiCredentialRole::Read, vec![]),
        Err(OnePassError::Forbidden)
    );
    assert_eq!(sync.set_locator(vec![1; 16]), Err(OnePassError::Forbidden));
    assert!(matches!(
        a.sync.grant(vec![1; 31], FfiCredentialRole::Read, vec![]),
        Err(OnePassError::InvalidInput { .. })
    ));
}

#[test]
fn abandon_then_locate_finds_nothing() {
    let shim = Shim::start();
    let cred = shim.credential();
    let home = mailbox_create(shim.endpoint(), cred.seed.clone(), None).unwrap();
    let dir = TempDir::new().unwrap();
    let sync = MailboxSync::open(
        db_path(dir.path()),
        shim.endpoint(),
        home.mailbox_id.clone(),
        cred.seed,
    )
    .unwrap();
    let locator = vec![7; 16];
    sync.set_locator(locator.clone()).unwrap();
    assert_eq!(
        mailbox_locate(shim.endpoint(), locator.clone()).unwrap(),
        vec![home.mailbox_id.clone()]
    );
    sync.abandon().unwrap();
    assert_eq!(
        mailbox_locate(shim.endpoint(), locator).unwrap(),
        Vec::<String>::new()
    );
}

#[test]
fn sign_adopt_through_ffi() {
    let shim = Shim::start();
    let a = legacy_first(&shim);
    let before = a.session.sync_home().unwrap().unwrap();
    let base = shim.endpoint().base_url;
    let other = mailbox_create(shim.endpoint(), shim.credential().seed, None).unwrap();
    let third = mailbox_create(shim.endpoint(), shim.credential().seed, None).unwrap();
    let x = a.session.sign_sync_home(backend_of(&other, &base)).unwrap();
    let y = a.session.sign_sync_home(backend_of(&third, &base)).unwrap();
    // Nothing adopted yet.
    assert_eq!(a.session.sync_home().unwrap(), Some(before.clone()));
    let adopted = a.session.adopt_sync_home(x.clone()).unwrap();
    assert_eq!(adopted.seq, before.seq + 1);
    assert_eq!(adopted.backend, backend_of(&other, &base));
    assert_eq!(a.session.adopt_sync_home(x).unwrap(), adopted);
    assert!(a.session.adopt_sync_home(y).is_err());
    assert_eq!(a.session.sync_home().unwrap(), Some(adopted));
    // A plain http home is never signed.
    assert!(
        a.session
            .sign_sync_home(FfiSyncBackend::Mailbox {
                base_url: "http://localhost/functions/v1/mailbox".into(),
                mailbox_id: other.mailbox_id,
            })
            .is_err()
    );
}

#[test]
fn enroll_request_through_ffi() {
    // A creates a v2 account; B pairs (no mailbox in the grant).
    let dir = TempDir::new().unwrap();
    let keys_a = Keys::new();
    let created = create_account_v2(
        db_path(dir.path()),
        PASSWORD.into(),
        Some(FAST),
        keys_a.classical.clone(),
        keys_a.half(),
        "Mac de Camille".into(),
        FfiDeviceKind::Mac,
        FfiDeviceMode::Personal,
    )
    .unwrap();
    let a = created.session;
    let keys_b = Keys::new();
    let n = PairingNewcomer::new(
        "iPad de Camille".into(),
        FfiDeviceKind::Tablet,
        FfiDeviceMode::Personal,
        now(),
        None,
    )
    .unwrap();
    let ap = PairingApprover::begin(n.qr_text(), n.hello(), now()).unwrap();
    n.on_key_exchange(ap.key_exchange(), now()).unwrap();
    let f = n
        .confirm_with_key(keys_b.classical.clone(), keys_b.half())
        .unwrap();
    assert_eq!(ap.on_frame(f).unwrap(), FfiPairingMessage::Confirmed);
    let frame = ap
        .seal_full_grant(
            a.clone(),
            created.secret_key.clone(),
            FfiDeviceMode::Personal,
            true,
            None,
        )
        .unwrap();
    assert!(matches!(
        n.open(frame).unwrap(),
        FfiPairingMessage::FullGrant { .. }
    ));
    let dir_b = TempDir::new().unwrap();
    let b = n
        .import_snapshot_v2(
            db_path(dir_b.path()),
            PASSWORD.into(),
            keys_b.classical.clone(),
            keys_b.half(),
        )
        .unwrap()
        .session;
    let ack = n
        .seal_key_ack(keys_b.classical.clone(), keys_b.half())
        .unwrap();
    assert_eq!(ap.on_frame(ack).unwrap(), FfiPairingMessage::Ack);
    ap.introduce(a.clone(), keys_a.classical.clone(), keys_a.half())
        .unwrap();

    // B asks for a credential on the mailbox A migrated to; A verifies.
    let mbx = "ab".repeat(16);
    let cred = mailbox_generate_credential().unwrap();
    let request = b
        .sign_enroll_request(
            keys_b.classical.clone(),
            keys_b.half(),
            cred.public_key.clone(),
            mbx.clone(),
        )
        .unwrap();
    let verified = a
        .verify_enroll_request(request.clone(), mbx.clone())
        .unwrap();
    assert_eq!(verified.credential_pub, cred.public_key);
    assert!((verified.issued_at - now()).abs() < 60);
    assert_ne!(verified.device_id, String::new());
    // Another mailbox, or a request signed with another device's keys.
    assert!(a.verify_enroll_request(request, "cd".repeat(16)).is_err());
    assert!(
        b.sign_enroll_request(
            keys_a.classical.clone(),
            keys_a.half(),
            cred.public_key,
            mbx
        )
        .is_err()
    );
}

#[test]
fn server_check_reads_config() {
    let shim = Shim::start();
    let info = mailbox_server_check(shim.endpoint()).unwrap();
    assert!(info.open_signup);
    // Nothing listens there: unavailable, never a panic.
    let dead = FfiMailboxEndpoint {
        base_url: "http://127.0.0.1:9".into(),
        extra_ca_pem: None,
    };
    assert!(matches!(
        mailbox_server_check(dead),
        Err(OnePassError::MailboxUnavailable { .. })
    ));
}

#[test]
fn sync_home_record_id_is_hex_and_stable() {
    let shim = Shim::start();
    let a = legacy_first(&shim);
    let id = a.session.sync_home_record_id().unwrap();
    assert_eq!(id.len(), 32);
    assert!(id.bytes().all(|b| b.is_ascii_hexdigit()));
    assert_eq!(a.session.sync_home_record_id().unwrap(), id);
}

#[test]
fn known_kinds() {
    for code in [1u8, 5, 10, 13, 24, 25, 27] {
        assert!(is_known_record_kind(code), "{code}");
    }
    for code in [0u8, 28, 200, 255] {
        assert!(!is_known_record_kind(code), "{code}");
    }
    assert_eq!(side_kind_mailbox_enroll_request(), 28);
}
