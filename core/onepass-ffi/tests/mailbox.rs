//! The mailbox over the UniFFI surface, called as plain Rust (Task 18): the
//! credential, the creation and enrollment of a mailbox, two devices syncing
//! through `MailboxSync`, a locked round, the clock skew, a pairing that
//! hands over the mailbox, and the wake listener's thread.
//!
//! No network: `Shim` serves the in-memory `FakeMailbox` over loopback TLS
//! (the test CA of `onepass-mailbox`), so the real client signs and checks
//! every request and answer. The shim checks each signature as the edge
//! function does. Synthetic data only. Run with `--features dev-fast-kdf`.

include!("support/mailbox_shim.rs");

// ---- tests ------------------------------------------------------------------

#[test]
fn credential_is_fresh_and_named_by_its_key() {
    let a = mailbox_generate_credential().unwrap();
    let b = mailbox_generate_credential().unwrap();
    assert_ne!(a.seed, b.seed);
    assert_eq!(a.public_key.len(), 32);
    assert_eq!(a.id.len(), 32);
    let c = Credential::from_seed(&a.seed).unwrap();
    assert_eq!(
        c.public_key().as_bytes().as_slice(),
        a.public_key.as_slice()
    );
}

#[test]
fn two_devices_sync_through_the_mailbox() {
    let shim = Shim::start();
    let a = legacy_first(&shim);

    // B joins the mailbox with a ticket A issues for its credential.
    let cred_b = shim.credential();
    let ticket = a
        .sync
        .issue_enroll_ticket(cred_b.public_key.clone(), now())
        .unwrap();
    let home_b = mailbox_enroll(cred_b.seed.clone(), ticket, Some(CA_PEM.into())).unwrap();
    assert_eq!(home_b, a.home);

    // Locked, B fetches the account: no rebase, nothing refused.
    let dir_b = TempDir::new().unwrap();
    let path_b = db_path(dir_b.path());
    let sync_b = MailboxSync::open(
        path_b.clone(),
        shim.endpoint(),
        home_b.mailbox_id.clone(),
        cred_b.seed,
    )
    .unwrap();
    let locked = settle(&sync_b, None);
    assert!(locked.changed);
    assert!(locked.rebased.is_empty());
    let b = unlock_with_password(path_b, PASSWORD.into(), a.secret_key.clone())
        .unwrap()
        .session;
    settle(&sync_b, Some(b.clone()));
    assert_eq!(titles(&b), ["Messagerie"]);
    assert_eq!(b.sync_home().unwrap(), a.session.sync_home().unwrap());

    // An edit on A reaches B.
    a.session.save_item(login(&a.session, "Banque")).unwrap();
    settle(&a.sync, Some(a.session.clone()));
    let r = settle(&sync_b, Some(b.clone()));
    assert!(r.changed);
    assert_eq!(titles(&b), ["Banque", "Messagerie"]);

    // A locked session is the same as none.
    b.lock();
    assert_eq!(settle(&sync_b, Some(b)).status, FfiRoundStatus::Idle);
    let _ = &a.path;
}

#[test]
fn clock_skew_reaches_the_app() {
    let shim = Shim::start();
    let a = legacy_first(&shim);
    shim.fake.faults().fail_next(MailboxError::Stale);
    let r = a.sync.run_round(Some(a.session.clone()), now());
    assert_eq!(r.status, FfiRoundStatus::ClockSkew);
    assert!(r.retry_after_seconds.is_some());
    shim.fake.faults().fail_next(MailboxError::Stale);
    assert_eq!(a.sync.wake_info(), Err(OnePassError::ClockSkew));
    let info = a.sync.wake_info().unwrap();
    assert_eq!(info.topic.len(), 32);
    assert_eq!(info.publishable_key, "pk-test");
    assert_eq!(
        settle(&a.sync, Some(a.session.clone())).status,
        FfiRoundStatus::Idle
    );
}

#[test]
fn an_unknown_server_is_unavailable_not_a_crash() {
    let cred = mailbox_generate_credential().unwrap();
    let closed = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = closed.local_addr().unwrap().port();
    drop(closed);
    let endpoint = FfiMailboxEndpoint {
        base_url: format!("https://localhost:{port}{PREFIX}"),
        extra_ca_pem: Some(CA_PEM.into()),
    };
    assert!(matches!(
        mailbox_create(endpoint, cred.seed, None),
        Err(OnePassError::MailboxUnavailable { .. })
    ));
    assert!(matches!(
        mailbox_enroll(vec![1; 32], vec![1, 2, 3], None),
        Err(OnePassError::InvalidInput { .. })
    ));
}

#[test]
fn sync_home_refuses_a_plain_http_mailbox() {
    let dir = TempDir::new().unwrap();
    let created = create_account_with_kdf(db_path(dir.path()), PASSWORD.into(), FAST).unwrap();
    assert_eq!(created.session.sync_home().unwrap(), None);
    let bad = FfiSyncBackend::Mailbox {
        base_url: "http://localhost/functions/v1/mailbox".into(),
        mailbox_id: "00".repeat(16),
    };
    assert!(created.session.set_sync_home(bad).is_err());
    let cloud = created
        .session
        .set_sync_home(FfiSyncBackend::CloudKit)
        .unwrap();
    assert_eq!(cloud.backend, FfiSyncBackend::CloudKit);
}

#[test]
fn pairing_hands_over_the_mailbox_with_a_ticket() {
    let shim = Shim::start();
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
    let a = first_device(&shim, (created.session, created.secret_key), dir);

    // The newcomer sends its credential key inside the SAS channel.
    let cred_b = shim.credential();
    let keys_b = Keys::new();
    let n = PairingNewcomer::new(
        "Pixel de Camille".into(),
        FfiDeviceKind::Phone,
        FfiDeviceMode::Personal,
        now(),
        Some(cred_b.public_key.clone()),
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
            a.session.clone(),
            a.secret_key.clone(),
            FfiDeviceMode::Personal,
            false,
            Some(a.sync.clone()),
        )
        .unwrap();
    assert!(matches!(
        n.open(frame).unwrap(),
        FfiPairingMessage::FullGrant { .. }
    ));

    // The grant names the account's home and a ticket for this credential.
    let enrollment = n.mailbox_enrollment().unwrap().expect("a mailbox to join");
    assert_eq!(enrollment.home, a.session.sync_home().unwrap().unwrap());
    assert_eq!(n.grant_sync_home(), Some(enrollment.home.clone()));
    let home_b =
        mailbox_enroll(cred_b.seed.clone(), enrollment.ticket, Some(CA_PEM.into())).unwrap();
    assert_eq!(mailbox_backend(&home_b), enrollment.home.backend);

    // B imports the snapshot and syncs through the mailbox.
    let dir_b = TempDir::new().unwrap();
    let path_b = db_path(dir_b.path());
    let b = n
        .import_snapshot_v2(
            path_b.clone(),
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
    ap.introduce(a.session.clone(), keys_a.classical.clone(), keys_a.half())
        .unwrap();
    let sync_b =
        MailboxSync::open(path_b, shim.endpoint(), home_b.mailbox_id, cred_b.seed).unwrap();
    settle(&a.sync, Some(a.session.clone()));
    settle(&sync_b, Some(b.clone()));
    assert_eq!(titles(&b), ["Messagerie"]);
    b.save_item(login(&b, "Train")).unwrap();
    settle(&sync_b, Some(b.clone()));
    settle(&a.sync, Some(a.session.clone()));
    assert_eq!(titles(&a.session), ["Messagerie", "Train"]);
}

#[test]
fn approver_without_a_mailbox_grants_no_ticket() {
    let shim = Shim::start();
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
    let a = first_device(&shim, (created.session, created.secret_key), dir);
    let keys_b = Keys::new();
    let n = PairingNewcomer::new(
        "Pixel de Camille".into(),
        FfiDeviceKind::Phone,
        FfiDeviceMode::Personal,
        now(),
        Some(vec![7; 32]),
    )
    .unwrap();
    let ap = PairingApprover::begin(n.qr_text(), n.hello(), now()).unwrap();
    n.on_key_exchange(ap.key_exchange(), now()).unwrap();
    let f = n
        .confirm_with_key(keys_b.classical.clone(), keys_b.half())
        .unwrap();
    ap.on_frame(f).unwrap();
    let frame = ap
        .seal_full_grant(
            a.session.clone(),
            a.secret_key.clone(),
            FfiDeviceMode::Personal,
            false,
            None,
        )
        .unwrap();
    n.open(frame).unwrap();
    assert_eq!(n.mailbox_enrollment().unwrap(), None);
    assert_eq!(n.grant_sync_home(), a.session.sync_home().unwrap());
    assert!(
        PairingNewcomer::new(
            "x".into(),
            FfiDeviceKind::Phone,
            FfiDeviceMode::Personal,
            now(),
            Some(vec![7; 31]),
        )
        .is_err()
    );
}

// ---- the wake listener ------------------------------------------------------

/// Counts wakes; `dropped` is set once the listener let go of it (its
/// thread ended).
struct Observer {
    wakes: AtomicUsize,
    dropped: Arc<AtomicBool>,
}

impl FfiWakeObserver for Observer {
    fn wake(&self) {
        self.wakes.fetch_add(1, Ordering::SeqCst);
    }
}

impl Drop for Observer {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::SeqCst);
    }
}

#[test]
fn wake_listener_stop_ends_its_thread() {
    let closed = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = closed.local_addr().unwrap().port();
    drop(closed);
    let dropped = Arc::new(AtomicBool::new(false));
    let observer: Arc<dyn FfiWakeObserver> = Arc::new(Observer {
        wakes: AtomicUsize::new(0),
        dropped: dropped.clone(),
    });
    let info = FfiWakeInfo {
        realtime_url: format!("wss://localhost:{port}/realtime/v1"),
        publishable_key: "pk-test".into(),
        topic: "ab".repeat(16),
    };
    let handle = start_wake_listener(info.clone(), observer).unwrap();
    std::thread::sleep(Duration::from_millis(300));
    assert!(!dropped.load(Ordering::SeqCst), "listener runs until stop");
    handle.stop();
    let deadline = Instant::now() + Duration::from_secs(10);
    while !dropped.load(Ordering::SeqCst) {
        assert!(Instant::now() < deadline, "the listener thread never ended");
        std::thread::sleep(Duration::from_millis(50));
    }
    handle.stop();

    let bad = FfiWakeInfo {
        topic: "zz".into(),
        ..info
    };
    let o: Arc<dyn FfiWakeObserver> = Arc::new(Observer {
        wakes: AtomicUsize::new(0),
        dropped: Arc::new(AtomicBool::new(false)),
    });
    assert!(start_wake_listener(bad, o).is_err());
}

#[test]
fn rendezvous_checks_its_session_and_url() {
    let base = "https://localhost:1/functions/v1/mailbox".to_string();
    assert!(
        RendezvousTransport::new(base.clone(), "ab".into(), FfiRdvRole::Newcomer, None).is_err()
    );
    assert!(
        RendezvousTransport::new(
            "ftp://x".into(),
            "ab".repeat(16),
            FfiRdvRole::Approver,
            None
        )
        .is_err()
    );
    let t = RendezvousTransport::new(base, "ab".repeat(16), FfiRdvRole::Newcomer, None).unwrap();
    t.close();
    assert!(t.send(vec![1]).is_err());
}
