//! The family, organizer-assisted recovery and item sends over the UniFFI
//! surface, called as plain Rust (sharing plan 4, Task 4).
//!
//! No network: `Shim` serves the in-memory `FakeMailbox` over loopback TLS.
//! Synthetic data only. Run with `--features dev-fast-kdf`.

#![allow(dead_code, unused_imports)]

include!("support/mailbox_shim.rs");
include!("support/people.rs");

const DAY: i64 = 24 * 3600;

/// Alice creates the family and Bob, her verified contact, joins it.
fn family_of_two(shim: &Shim) -> (Person, Person) {
    let (alice, bob) = verified_pair(shim);
    let t = now();
    let f = alice.session.create_family("Famille".into(), t).unwrap();
    assert!(f.i_am_organizer);
    assert_eq!(f.members.len(), 1);
    assert_eq!(f.vaults.len(), 1);
    settle_zones(&[&alice]);
    let f = alice
        .session
        .invite_to_family(bob.session.account_id(), FfiFamilyRole::Member, t)
        .unwrap();
    assert!(f.needs_second_organizer);
    settle_zones(&[&alice, &bob]);
    let invites = bob.session.family_invites().unwrap();
    assert_eq!(invites.len(), 1);
    assert_eq!(invites[0].from_name_local, "Alice");
    assert_eq!(invites[0].role, FfiFamilyRole::Member);
    let joined = bob
        .session
        .accept_family_invite(invites[0].id.clone(), t)
        .unwrap();
    assert!(!joined.i_am_organizer);
    settle_zones(&[&alice, &bob]);
    (alice, bob)
}

#[test]
fn family_created_and_member_joins() {
    let shim = Shim::start();
    let (alice, bob) = family_of_two(&shim);
    let a = alice.session.family().unwrap().unwrap();
    let b = bob.session.family().unwrap().unwrap();
    assert_eq!(a.family_id, b.family_id);
    let mut names: Vec<_> = a.members.iter().map(|m| m.role).collect();
    names.sort_by_key(|r| *r == FfiFamilyRole::Organizer);
    assert_eq!(names, vec![FfiFamilyRole::Member, FfiFamilyRole::Organizer]);
    // The family vault reached Bob.
    let vault = a.vaults[0].clone();
    assert!(bob.session.vaults().unwrap().iter().any(|v| v.id == vault));
    // A member cannot invite.
    assert!(
        bob.session
            .invite_to_family(alice.session.account_id(), FfiFamilyRole::Member, now())
            .is_err()
    );
    assert!(bob.session.family_invites().unwrap().is_empty());
}

/// Every pending row of Bob's private base, fetched into an empty store:
/// his new device, nothing unlocked.
fn new_device_of(p: &Person, dir: &TempDir, at: i64) -> String {
    let path = db_path(dir.path());
    let rows = p.store.pending_changes().unwrap();
    assert!(!rows.is_empty());
    let n = open_sync_store(path.clone()).unwrap();
    for c in rows {
        n.stage_remote(FfiRemoteRecord {
            kind: c.kind,
            id: c.id,
            version: c.version,
            data: c.data,
            server_meta: Some(b"tag".to_vec()),
        })
        .unwrap();
    }
    n.commit_remote_checked(u64::try_from(at).unwrap()).unwrap();
    path
}

#[test]
fn recovery_goes_end_to_end_through_the_ffi() {
    let shim = Shim::start();
    let (alice, bob) = family_of_two(&shim);
    let t = now();
    let vault = bob.session.vaults().unwrap()[0].id.clone();
    bob.session
        .save_item(item_in(&bob.session, &vault, "Banque"))
        .unwrap();

    // Bob enrolls with Alice, 24 hours.
    let alice_id = alice.session.account_id();
    let bob_id = bob.session.account_id();
    assert!(matches!(
        bob.session.enroll_recovery(
            alice_id.clone(),
            60,
            PASSWORD.into(),
            bob.secret_key.clone(),
            t
        ),
        Err(OnePassError::Validation { field, .. }) if field == "delay"
    ));
    let e = bob
        .session
        .enroll_recovery(
            alice_id,
            DAY as u32,
            PASSWORD.into(),
            bob.secret_key.clone(),
            t,
        )
        .unwrap();
    assert_eq!(e.organizer_name_local, "Alice");
    assert!(e.valid);
    assert_eq!(bob.session.recovery_enrollment().unwrap(), Some(e.clone()));
    settle_zones(&[&alice, &bob]);
    let helpers = alice.session.recovery_enrollments_for_me().unwrap();
    assert_eq!(helpers.len(), 1);
    assert_eq!(helpers[0].member, bob_id);
    assert_eq!(helpers[0].enrollment_id, e.enrollment_id);

    // Alice asks; the delay runs on her clock.
    let status = alice
        .session
        .request_recovery(bob_id.clone(), PASSWORD.into(), alice.secret_key.clone(), t)
        .unwrap();
    let release_after = t + DAY;
    assert_eq!(status, FfiRecoveryStatus::Waiting { release_after });
    settle_zones(&[&alice, &bob]);
    let alerts = recovery_alerts(bob.path.clone()).unwrap();
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].enrollment_id, e.enrollment_id);
    assert_eq!(alerts[0].release_after, release_after);
    assert_eq!(
        alice
            .session
            .recovery_status(bob_id.clone(), release_after - 1)
            .unwrap(),
        FfiRecoveryStatus::Waiting { release_after }
    );
    assert_eq!(
        alice
            .session
            .recovery_status(bob_id.clone(), release_after)
            .unwrap(),
        FfiRecoveryStatus::Ready
    );

    // Face to face with Bob's new device, after the delay.
    let at = release_after + 5;
    let dir = TempDir::new().unwrap();
    let path = new_device_of(&bob, &dir, at);
    let start = recovery_responder_start(at).unwrap();
    let begin = contact_initiator_begin(start.qr, start.hello, at).unwrap();
    assert_eq!(
        start
            .responder
            .on_key_exchange(begin.key_exchange, at)
            .unwrap(),
        begin.sas
    );
    begin.initiator.confirm_sas_for_recovery().unwrap();
    let frame = alice
        .session
        .release_recovery_share(bob_id.clone(), begin.initiator.clone(), at)
        .unwrap();
    let k = Keys::new();
    let new_sk = generate_secret_key().unwrap();
    let recovered = start
        .responder
        .recover(
            path,
            frame,
            None,
            "un tout nouveau mot de passe".into(),
            new_sk,
            k.classical.clone(),
            k.half(),
            "iPhone de secours".into(),
            FfiDeviceKind::Phone,
            FfiDeviceMode::Personal,
            at + 5,
        )
        .unwrap();
    assert!(vault_titles(&recovered, &vault).contains(&"Banque".to_string()));
}

#[test]
fn locked_device_cancels_the_request() {
    let shim = Shim::start();
    let (alice, bob) = family_of_two(&shim);
    let t = now();
    let bob_id = bob.session.account_id();
    let e = bob
        .session
        .enroll_recovery(
            alice.session.account_id(),
            DAY as u32,
            PASSWORD.into(),
            bob.secret_key.clone(),
            t,
        )
        .unwrap();
    settle_zones(&[&alice, &bob]);
    alice
        .session
        .request_recovery(bob_id.clone(), PASSWORD.into(), alice.secret_key.clone(), t)
        .unwrap();
    settle_zones(&[&alice, &bob]);

    // Bob's device is locked: no session, only its store and its keys.
    bob.session.lock();
    let alerts = recovery_alerts(bob.path.clone()).unwrap();
    assert_eq!(alerts.len(), 1);
    assert!(matches!(
        cancel_recovery(
            bob.path.clone(),
            "00".repeat(16),
            bob.keys.classical.clone(),
            bob.keys.half(),
            t + 60,
        ),
        Err(OnePassError::Validation { field, .. }) if field == "enrollment"
    ));
    cancel_recovery(
        bob.path.clone(),
        e.enrollment_id,
        bob.keys.classical.clone(),
        bob.keys.half(),
        t + 60,
    )
    .unwrap();
    // The cancel travels in the zone round of a locked device too.
    for _ in 0..4 {
        bob.zones.run_round(None, bob.store.clone(), now());
        alice
            .zones
            .run_round(Some(alice.session.clone()), alice.store.clone(), now());
    }
    assert_eq!(
        alice.session.recovery_status(bob_id, t + 2 * DAY).unwrap(),
        FfiRecoveryStatus::Cancelled { at: t + 60 }
    );
}

#[test]
fn sent_item_accepted_into_a_vault() {
    let shim = Shim::start();
    let (alice, bob) = verified_pair(&shim);
    let t = now();
    let av = alice.session.vaults().unwrap()[0].id.clone();
    let item = alice
        .session
        .save_item(item_in(&alice.session, &av, "Wi-Fi maison"))
        .unwrap();
    assert!(matches!(
        alice.session.send_item(
            av.clone(),
            item.id.clone(),
            bob.session.account_id(),
            t + 31 * DAY,
            t
        ),
        Err(OnePassError::Validation { field, .. }) if field == "expires_at"
    ));
    alice
        .session
        .send_item(av, item.id, bob.session.account_id(), t + DAY, t)
        .unwrap();
    settle_zones(&[&alice, &bob]);
    let got = bob.session.received_items(t).unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].from_name_local, "Alice");
    assert_eq!(got[0].title, "Wi-Fi maison");
    assert_eq!(got[0].kind, FfiItemType::Login);
    let bv = bob.session.vaults().unwrap()[0].id.clone();
    let kept = bob
        .session
        .accept_received_item(got[0].send_id.clone(), bv.clone(), t)
        .unwrap();
    assert_eq!(kept.title, "Wi-Fi maison");
    assert!(vault_titles(&bob.session, &bv).contains(&"Wi-Fi maison".to_string()));
    assert!(bob.session.received_items(t).unwrap().is_empty());
    settle_zones(&[&alice, &bob]);
    assert_eq!(alice.session.purge_expired_sends(t + 2 * DAY).unwrap(), 0);
}
