//! Organizer-assisted recovery (sharing plan 3 Tasks 4 to 6, spec 11.3 to
//! 11.7).

mod common;
mod share_accts;
mod share_common;

use common::*;
use onepass_core::contact::ContactLevel;
use onepass_core::crypto::kem::unwrap_key_labeled;
use onepass_core::family::FamilyRole;
use onepass_core::recovery::{
    RECOVERY_DELAY_DEFAULT_SECS, RecoveryHalf, RecoveryMessage, SHARE_LABEL, derive_rk,
    share_context,
};
use onepass_core::share::AccessTarget;
use onepass_core::store::{Record, RecordKind, Zone};
use share_accts::settle;
use share_accts::*;
use share_common::*;

/// Alice organizes a family; Bob joins as a member, each `Verified` in
/// the other's book, their contact zone made.
fn family() -> (Zones, Acct, Acct) {
    let mut zs = Zones::default();
    let mut a = Acct::new();
    let info = a.dev.repo().create_family("Famille", NOW).unwrap();
    a.dev
        .repo()
        .set_zone_home(AccessTarget::Zone(Zone::Family(info.family_id)), home(7))
        .unwrap();
    a.dev
        .repo()
        .set_zone_home(AccessTarget::Zone(Zone::Vault(info.vaults[0])), home(8))
        .unwrap();
    a.sync(&mut zs);
    let mut b = Acct::new();
    pin(&mut a.dev, &mut b.dev, ContactLevel::Verified);
    pin(&mut b.dev, &mut a.dev, ContactLevel::Verified);
    contact_zone(&mut a.dev, &mut b.dev);
    let bob = account_id(&mut b.dev);
    a.dev
        .repo()
        .invite_to_family(bob, FamilyRole::Member, NOW + 1)
        .unwrap();
    settle(&mut zs, &mut [&mut a, &mut b]);
    let inv = b.dev.repo().family_invites().unwrap()[0].id;
    b.dev.repo().accept_family_invite(inv, NOW + 2).unwrap();
    settle(&mut zs, &mut [&mut a, &mut b]);
    (zs, a, b)
}

/// Bob enrolls with Alice as his helper.
fn enroll(zs: &mut Zones, a: &mut Acct, b: &mut Acct, delay: u32) -> Id {
    let alice = account_id(&mut a.dev);
    let e = b
        .dev
        .repo()
        .enroll_recovery(alice, delay, PASSWORD, &b.sk, NOW + 10)
        .unwrap();
    settle(zs, &mut [&mut *a, &mut *b]);
    e.enrollment_id
}

fn validation<T: std::fmt::Debug>(r: onepass_core::Result<T>) -> (String, &'static str) {
    match r {
        Err(Error::Validation(v)) => (v.field, v.reason),
        other => panic!("expected a validation error, got {other:?}"),
    }
}

fn messages(d: &mut Device, zone: Zone) -> Vec<RecoveryMessage> {
    d.store()
        .list_in(zone, RecordKind::RecoveryMessage)
        .unwrap()
        .iter()
        .map(|r| RecoveryMessage::decode(&r.data).unwrap())
        .collect()
}

#[test]
fn enroll_writes_slot_half_and_message() {
    let (mut zs, mut a, mut b) = family();
    let eid = enroll(&mut zs, &mut a, &mut b, RECOVERY_DELAY_DEFAULT_SECS);
    let bob = me(&mut b.dev);
    let store = b.dev.store();
    let slot = store
        .get(RecordKind::RecoverySlot, bob.identity_id)
        .unwrap();
    assert!(slot.is_some());
    let half = store
        .get(RecordKind::RecoveryHalf, bob.identity_id)
        .unwrap()
        .expect("a half");
    match RecoveryHalf::decode(&half.data).unwrap() {
        RecoveryHalf::Clear { enrollment_id, .. } => assert_eq!(enrollment_id, eid),
        other => panic!("an iCloud account keeps its half in clear: {other:?}"),
    }
    let view = b
        .dev
        .repo()
        .recovery_enrollment()
        .unwrap()
        .expect("enrolled");
    assert_eq!(view.enrollment_id, eid);
    assert_eq!(view.delay_secs, RECOVERY_DELAY_DEFAULT_SECS);
    assert!(view.valid);
    assert_eq!(view.organizer_name_local, "peer");

    // Alice sees Bob, and her KEM key opens S_org.
    let helped = a.dev.repo().recovery_enrollments_for_me().unwrap();
    assert_eq!(helped.len(), 1);
    assert_eq!(helped[0].member, bob.account_id);
    assert_eq!(helped[0].enrollment_id, eid);
    let zone = a.dev.repo().contact_zone(bob.account_id).unwrap();
    let alice = me(&mut a.dev);
    let msgs = messages(&mut a.dev, zone);
    let Some(RecoveryMessage::Enroll { envelope, .. }) = msgs.first() else {
        panic!("an enrollment");
    };
    let kem = &a.dev.repo().account().keyset().kem;
    unwrap_key_labeled(
        kem,
        envelope,
        SHARE_LABEL,
        &share_context(&bob, &alice, eid),
    )
    .unwrap();
}

#[test]
fn mailbox_account_half_is_sealed() {
    let (mut zs, mut a, mut b) = family();
    b.dev
        .repo()
        .set_sync_home(
            onepass_core::synchome::SyncBackend::Mailbox {
                url: "https://box.example.org".into(),
                mailbox_id: [3; 16],
            },
            NOW + 5,
        )
        .unwrap();
    let eid = enroll(&mut zs, &mut a, &mut b, RECOVERY_DELAY_DEFAULT_SECS);
    let bob = me(&mut b.dev);
    let half = b
        .dev
        .store()
        .get(RecordKind::RecoveryHalf, bob.identity_id)
        .unwrap()
        .unwrap();
    match RecoveryHalf::decode(&half.data).unwrap() {
        RecoveryHalf::Sealed { enrollment_id, .. } => assert_eq!(enrollment_id, eid),
        other => panic!("a mailbox account seals its half: {other:?}"),
    }
}

/// A9: nothing writes a slot without the member's password, and an
/// `Enroll` the server planted (not signed by the member) is ignored.
#[test]
fn a9_no_auto_enrollment() {
    let (mut zs, mut a, mut b) = family();
    let alice = account_id(&mut a.dev);
    assert!(matches!(
        b.dev
            .repo()
            .enroll_recovery(alice, RECOVERY_DELAY_DEFAULT_SECS, "wrong", &b.sk, NOW),
        Err(Error::WrongPassword)
    ));
    let bob = me(&mut b.dev);
    assert!(
        b.dev
            .store()
            .get(RecordKind::RecoverySlot, bob.identity_id)
            .unwrap()
            .is_none()
    );

    // The server plants an enrollment of Bob signed by another key.
    let alice_ref = me(&mut a.dev);
    let zone = a.dev.repo().contact_zone(bob.account_id).unwrap();
    let forger = onepass_core::crypto::HybridSigningKey::generate().unwrap();
    let forged = RecoveryMessage::Enroll {
        enrollment: onepass_core::recovery::RecoveryEnrollment {
            member: bob,
            organizer: alice_ref,
            enrollment_id: Id::new(),
            delay_secs: RECOVERY_DELAY_DEFAULT_SECS,
            created_at: NOW,
        },
        envelope: vec![1; 64],
        sig: onepass_core::recovery::messages::unsigned(),
    }
    .sign_with(|d, m| forger.sign(d, m))
    .unwrap();
    a.dev
        .store()
        .put_all_zoned(
            vec![(
                zone,
                Record {
                    kind: RecordKind::RecoveryMessage,
                    id: forged.record_id(),
                    version: 1,
                    data: forged.encode(),
                },
                None,
            )],
            vec![],
            None,
            &[],
        )
        .unwrap();
    assert!(
        a.dev
            .repo()
            .recovery_enrollments_for_me()
            .unwrap()
            .is_empty()
    );
    settle(&mut zs, &mut [&mut a, &mut b]);
    assert!(b.dev.repo().recovery_enrollment().unwrap().is_none());
}

/// A10: the envelope is made for the organizer's key as pinned in the
/// member's book; an organizer held at `Link` is refused.
#[test]
fn a10_enrollment_to_pinned_key() {
    let (mut zs, mut a, mut b) = family();
    let eid = enroll(&mut zs, &mut a, &mut b, RECOVERY_DELAY_DEFAULT_SECS);
    let bob = me(&mut b.dev);
    let alice = account_id(&mut a.dev);
    let pinned = b.dev.repo().contact(alice).unwrap().unwrap();
    let zone = b.dev.repo().contact_zone(alice).unwrap();
    let msgs = messages(&mut b.dev, zone);
    let Some(RecoveryMessage::Enroll {
        envelope,
        enrollment,
        ..
    }) = msgs.iter().find(|m| m.enrollment_id() == eid)
    else {
        panic!("an enrollment");
    };
    assert_eq!(
        enrollment.organizer.identity_id,
        onepass_core::lineage::identity_id(&pinned.identity_pub)
    );
    // Another KEM key (what a hostile server would present) opens nothing.
    let other = onepass_core::crypto::HybridKemSecret::generate().unwrap();
    let ctx = share_context(&bob, &enrollment.organizer, eid);
    assert!(unwrap_key_labeled(&other, envelope, SHARE_LABEL, &ctx).is_err());

    // Carol, held at Link by Dan, cannot be Dan's helper.
    let mut c = Acct::new();
    let mut d = Acct::new();
    c.dev.repo().create_family("Famille", NOW).unwrap();
    let carol = account_id(&mut c.dev);
    pin(&mut d.dev, &mut c.dev, ContactLevel::Link);
    let (field, reason) = validation(d.dev.repo().enroll_recovery(
        carol,
        RECOVERY_DELAY_DEFAULT_SECS,
        PASSWORD,
        &d.sk,
        NOW,
    ));
    assert_eq!((field.as_str(), reason), ("organizer", "not verified"));
}

#[test]
fn delay_bounds() {
    let (mut zs, mut a, mut b) = family();
    let alice = account_id(&mut a.dev);
    for delay in [23 * 3600, 8 * 86_400] {
        let (field, _) = validation(
            b.dev
                .repo()
                .enroll_recovery(alice, delay, PASSWORD, &b.sk, NOW),
        );
        assert_eq!(field, "delay");
    }
    assert_eq!(RECOVERY_DELAY_DEFAULT_SECS, 72 * 3600);
    enroll(&mut zs, &mut a, &mut b, RECOVERY_DELAY_DEFAULT_SECS);
}

/// Review focus 3: the organizer rotates its keys; the enrollment is no
/// longer valid on the member's side (the envelope names the old key).
#[test]
fn organizer_rotation_cancels_enrollment() {
    let (mut zs, mut a, mut b) = family();
    enroll(&mut zs, &mut a, &mut b, RECOVERY_DELAY_DEFAULT_SECS);
    a.rotate(false);
    settle(&mut zs, &mut [&mut a, &mut b]);
    b.dev.repo().refresh_member_identities(NOW + 20).unwrap();
    let view = b.dev.repo().recovery_enrollment().unwrap().unwrap();
    assert!(!view.valid);
}

#[test]
fn member_rotation_cancels_enrollment() {
    let (mut zs, mut a, mut b) = family();
    enroll(&mut zs, &mut a, &mut b, RECOVERY_DELAY_DEFAULT_SECS);
    b.rotate(false);
    settle(&mut zs, &mut [&mut a, &mut b]);
    a.dev.repo().refresh_member_identities(NOW + 20).unwrap();
    let view = b.dev.repo().recovery_enrollment().unwrap().unwrap();
    assert!(!view.valid);
    // The organizer no longer lists it: the member's book identity moved.
    assert!(
        a.dev
            .repo()
            .recovery_enrollments_for_me()
            .unwrap()
            .is_empty()
    );
}

/// B-1: RK = HKDF-SHA256(S_org || S_store, "onepass/recovery/rk/v1" ||
/// postcard((account, identity, enrollment))), frozen.
#[test]
fn rk_formula() {
    let rk = derive_rk(&[1; 32], &[2; 32], Id([3; 16]), Id([4; 16]), Id([5; 16])).unwrap();
    // An independent HKDF over the same inputs.
    use aws_lc_rs::hkdf::{HKDF_SHA256, KeyType, Salt};
    struct L32;
    impl KeyType for L32 {
        fn len(&self) -> usize {
            32
        }
    }
    let mut ikm = [1u8; 64];
    ikm[32..].fill(2);
    let bound = postcard::to_allocvec(&(Id([3; 16]), Id([4; 16]), Id([5; 16]))).unwrap();
    let prk = Salt::new(HKDF_SHA256, &[]).extract(&ikm);
    let info = [b"onepass/recovery/rk/v1".as_slice(), &bound];
    let okm = prk.expand(&info, L32).unwrap();
    let mut want = [0u8; 32];
    okm.fill(&mut want).unwrap();
    assert_eq!(rk.expose(), &want);
    assert_eq!(
        data_encoding::HEXLOWER.encode(rk.expose()),
        FROZEN_RK,
        "the RK formula moved"
    );
}

const FROZEN_RK: &str = "32ce1d0690f4301fa52c0db10422a19b0c369985d10ffe4018c773d6fff82f52";

// ------------------------------------------------ request, delay, cancel

use onepass_core::repo::recovery::{RecoveryStatus, cancel_recovery, recovery_alerts};

const DAY: i64 = 86_400;

/// Bob enrolled with Alice; Alice asks at `NOW + 100`.
fn requested() -> (Zones, Acct, Acct, Id, i64) {
    let (mut zs, mut a, mut b) = family();
    let eid = enroll(&mut zs, &mut a, &mut b, RECOVERY_DELAY_DEFAULT_SECS);
    let bob = account_id(&mut b.dev);
    let status = a
        .dev
        .repo()
        .request_recovery(bob, PASSWORD, &a.sk, NOW + 100)
        .unwrap();
    let release_after = NOW + 100 + i64::from(RECOVERY_DELAY_DEFAULT_SECS);
    assert_eq!(status, RecoveryStatus::Waiting { release_after });
    settle(&mut zs, &mut [&mut a, &mut b]);
    (zs, a, b, eid, release_after)
}

#[test]
fn request_shows_on_member_devices() {
    let (_zs, _a, mut b, eid, release_after) = requested();
    b.dev.lock();
    let alerts = recovery_alerts(&b.dev.store()).unwrap();
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].enrollment_id, eid);
    assert_eq!(alerts[0].organizer_name_local, "peer");
    assert_eq!(alerts[0].release_after, release_after);
}

#[test]
fn ready_after_delay_only() {
    let (_zs, mut a, mut b, _eid, release_after) = requested();
    let bob = account_id(&mut b.dev);
    assert_eq!(
        a.dev
            .repo()
            .recovery_status(bob, release_after - 1)
            .unwrap(),
        RecoveryStatus::Waiting { release_after }
    );
    assert_eq!(
        a.dev.repo().recovery_status(bob, release_after).unwrap(),
        RecoveryStatus::Ready
    );
}

#[test]
fn cancel_from_member_device_seen() {
    let (mut zs, mut a, mut b, eid, release_after) = requested();
    let bob = account_id(&mut b.dev);
    b.dev.lock();
    cancel_recovery(&mut b.dev.store(), eid, &b.keys, NOW + 200).unwrap();
    b.dev.unlock(&b.sk);
    settle(&mut zs, &mut [&mut a, &mut b]);
    assert_eq!(
        a.dev
            .repo()
            .recovery_status(bob, release_after + DAY)
            .unwrap(),
        RecoveryStatus::Cancelled { at: NOW + 200 }
    );
}

#[test]
fn cancel_from_unknown_device_ignored() {
    let (mut zs, mut a, mut b, eid, release_after) = requested();
    let bob = account_id(&mut b.dev);
    // A device key outside Bob's roster signs a cancellation.
    let stranger = onepass_core::device_keys::DeviceKeys::generate_software().unwrap();
    cancel_recovery(&mut b.dev.store(), eid, &stranger, NOW + 200).unwrap();
    settle(&mut zs, &mut [&mut a, &mut b]);
    assert_eq!(
        a.dev.repo().recovery_status(bob, release_after).unwrap(),
        RecoveryStatus::Ready
    );
}

#[test]
fn request_from_non_organizer_ignored() {
    let (mut zs, mut a, mut b) = family();
    let eid = enroll(&mut zs, &mut a, &mut b, RECOVERY_DELAY_DEFAULT_SECS);
    // Carol, a contact of Bob's who is not his helper, writes a request.
    let mut c = Acct::new();
    pin(&mut b.dev, &mut c.dev, ContactLevel::Verified);
    pin(&mut c.dev, &mut b.dev, ContactLevel::Verified);
    let zone = contact_zone(&mut b.dev, &mut c.dev);
    let bob = account_id(&mut b.dev);
    assert!(matches!(
        c.dev
            .repo()
            .request_recovery(bob, PASSWORD, &c.sk, NOW + 100),
        Err(Error::Validation(_))
    ));
    let carol = me(&mut c.dev);
    let forged = RecoveryMessage::Request {
        enrollment_id: eid,
        requested_at: NOW + 100,
        release_after: NOW + 101,
        organizer: carol,
        sig: onepass_core::recovery::messages::unsigned(),
    }
    .sign_with(|d, m| c.dev.repo().account().keyset().signing.sign(d, m))
    .unwrap();
    b.dev
        .store()
        .put_all_zoned(
            vec![(
                zone,
                Record {
                    kind: RecordKind::RecoveryMessage,
                    id: forged.record_id(),
                    version: 1,
                    data: forged.encode(),
                },
                None,
            )],
            vec![],
            None,
            &[],
        )
        .unwrap();
    assert!(recovery_alerts(&b.dev.store()).unwrap().is_empty());
}

/// Review focus 2: a new enrollment while a request waits voids it.
#[test]
fn reenroll_voids_pending_request() {
    let (mut zs, mut a, mut b, _eid, release_after) = requested();
    let bob = account_id(&mut b.dev);
    enroll(&mut zs, &mut a, &mut b, RECOVERY_DELAY_DEFAULT_SECS);
    assert_eq!(
        a.dev.repo().recovery_status(bob, release_after).unwrap(),
        RecoveryStatus::Replaced
    );
}

/// A22, a documented limit: a server that withholds the cancellation lets
/// the delay run out. Asserted so that a change shows.
#[test]
fn a22_withheld_cancel_is_a_limit() {
    let (_zs, mut a, mut b, eid, release_after) = requested();
    let bob = account_id(&mut b.dev);
    cancel_recovery(&mut b.dev.store(), eid, &b.keys, NOW + 200).unwrap();
    // Never synced: Alice never reads it.
    assert_eq!(
        a.dev.repo().recovery_status(bob, release_after).unwrap(),
        RecoveryStatus::Ready
    );
}

// Task 6: the release face to face and the recovery.

use onepass_core::contact::{
    ContactInitiator, ContactMessage, ContactResponder, ForeignLineage, LegacyIntros,
    follow_foreign,
};
use onepass_core::crypto::{Aad, BlobKind, open};
use onepass_core::device_keys::DeviceKeys;
use onepass_core::devices::{DeviceKind, DeviceMode};
use onepass_core::lineage::{LineageRecord, RotationReason};
use onepass_core::recovery::{half_aad, slot_aad, store_seal_key};
use onepass_core::repo::recovery::recover_with_share;
use onepass_core::repo::{RecoverRequest, RotationOutcome};
use onepass_core::sync::SyncStore;

const RECOVERED_PASSWORD: &str = "un tout nouveau mot de passe";

/// Bob's new device shows the recovery QR, Alice scans it; both read the
/// same SAS.
fn face_to_face(now: i64) -> (ContactInitiator, ContactResponder) {
    let (mut resp, qr, hello) = ContactResponder::new_for_recovery(now).unwrap();
    let (init, kx, code) = ContactInitiator::begin(&qr.to_text(), &hello, now).unwrap();
    assert_eq!(resp.on_key_exchange(&kx, now).unwrap(), code);
    (init, resp)
}

/// Alice confirms the SAS and releases her half.
fn release(a: &mut Acct, bob: Id, now: i64) -> (ContactResponder, Vec<u8>) {
    let (mut init, resp) = face_to_face(now);
    init.confirm_sas_for_recovery().unwrap();
    let frame = a
        .dev
        .repo()
        .release_recovery_share(bob, &mut init, now)
        .unwrap();
    (resp, frame)
}

/// A new device of Bob's, its private base pulled, nothing unlocked.
fn new_device(b: &Acct) -> Device {
    let mut n = Device::empty();
    pull(&b.server, &mut n);
    n
}

fn recover(
    n: &mut Device,
    resp: &mut ContactResponder,
    frame: &[u8],
    kit: Option<&SecretKey>,
    now: i64,
) -> onepass_core::Result<(
    onepass_core::repo::Repository<SyncStore>,
    RotationOutcome,
    SecretKey,
)> {
    let sk = SecretKey::generate().unwrap();
    let keys = DeviceKeys::generate_software().unwrap();
    let store = n.store();
    let device = store.device_state().unwrap();
    let (repo, out) = recover_with_share(
        store,
        resp,
        frame,
        kit,
        RecoverRequest {
            keyset_record: &[],
            new_password: RECOVERED_PASSWORD,
            new_secret_key: &sk,
            device_keys: &keys,
            device_name: "iPhone de secours",
            kind: DeviceKind::Phone,
            mode: DeviceMode::Personal,
            device,
        },
        now,
    )?;
    Ok((repo, out, sk))
}

/// Bob with one login, enrolled and requested: `(zs, a, b, eid,
/// release_after)`.
fn requested_with_item() -> (Zones, Acct, Acct, Id, i64) {
    let (mut zs, a, mut b, eid, release_after) = requested();
    let v = personal_vault_of(&mut b.dev);
    b.dev.save(&login(v, "bob", NOW + 300));
    b.sync(&mut zs);
    (zs, a, b, eid, release_after)
}

#[test]
fn recovery_goes_end_to_end() {
    let (mut zs, mut a, mut b, _eid, release_after) = requested_with_item();
    let bob = account_id(&mut b.dev);
    let before = users(&b.dev.items());
    assert!(before.contains(&"bob".to_string()));
    let (mut resp, frame) = release(&mut a, bob, release_after);
    let mut n = new_device(&b);
    let (repo, out, sk) = recover(&mut n, &mut resp, &frame, None, release_after + 10).unwrap();
    n.repo = Some(repo);
    n.repo().persist_device_state().unwrap();
    sync(&mut b.server, &mut n).unwrap();
    // Bob reads every item under his new identity.
    assert_eq!(users(&n.items()), before);
    assert_ne!(me(&mut n).identity_id, me(&mut b.dev).identity_id);
    n.lock();
    n.try_unlock(RECOVERED_PASSWORD, &sk).unwrap();
    // Slot and half are gone.
    for kind in [RecordKind::RecoverySlot, RecordKind::RecoveryHalf] {
        assert!(n.store().list(kind).unwrap().is_empty(), "{kind:?} left");
    }
    // Alice, pinned at Bob's old head, sees a `Recover` rotation.
    let pin = a.dev.repo().contact(bob).unwrap().unwrap().pin();
    let store = n.store();
    let records: Vec<LineageRecord> = store
        .list(RecordKind::Lineage)
        .unwrap()
        .iter()
        .map(|r| LineageRecord::decode(&r.data).unwrap())
        .collect();
    let intros: Vec<_> = store
        .list(RecordKind::DeviceIntro)
        .unwrap()
        .iter()
        .map(|r| onepass_core::lineage::SignedIntro::decode(&r.data).unwrap())
        .collect();
    match follow_foreign(&pin, &records, &intros, &LegacyIntros::default()) {
        ForeignLineage::Advanced {
            head,
            last_rotation,
            ..
        } => {
            assert_eq!(head.hash, out.head);
            assert_eq!(last_rotation.reason, RotationReason::Recover);
        }
        other => panic!("expected Advanced, got {other:?}"),
    }
    let _ = &mut zs;
}

#[test]
fn release_refused_before_delay() {
    let (_zs, mut a, mut b, _eid, release_after) = requested();
    let bob = account_id(&mut b.dev);
    let (mut init, _resp) = face_to_face(release_after - 1);
    init.confirm_sas_for_recovery().unwrap();
    let r = a
        .dev
        .repo()
        .release_recovery_share(bob, &mut init, release_after - 1);
    assert_eq!(validation(r), ("recovery".into(), "not ready"));
}

#[test]
fn release_refused_after_cancel() {
    let (mut zs, mut a, mut b, eid, release_after) = requested();
    let bob = account_id(&mut b.dev);
    cancel_recovery(&mut b.dev.store(), eid, &b.keys, NOW + 200).unwrap();
    settle(&mut zs, &mut [&mut a, &mut b]);
    let (mut init, _resp) = face_to_face(release_after);
    init.confirm_sas_for_recovery().unwrap();
    let r = a
        .dev
        .repo()
        .release_recovery_share(bob, &mut init, release_after);
    assert_eq!(validation(r), ("recovery".into(), "not ready"));
}

#[test]
fn release_refused_without_sas_confirmed() {
    let (_zs, mut a, mut b, _eid, release_after) = requested();
    let bob = account_id(&mut b.dev);
    let (mut init, _resp) = face_to_face(release_after);
    assert!(matches!(
        a.dev
            .repo()
            .release_recovery_share(bob, &mut init, release_after),
        Err(Error::Validation(_))
    ));
    // Nothing written: a confirmed session still releases.
    init.confirm_sas_for_recovery().unwrap();
    a.dev
        .repo()
        .release_recovery_share(bob, &mut init, release_after)
        .unwrap();
}

#[test]
fn second_release_refused() {
    let (_zs, mut a, mut b, _eid, release_after) = requested();
    let bob = account_id(&mut b.dev);
    release(&mut a, bob, release_after);
    let (mut init, _resp) = face_to_face(release_after + 1);
    init.confirm_sas_for_recovery().unwrap();
    let r = a
        .dev
        .repo()
        .release_recovery_share(bob, &mut init, release_after + 1);
    assert_eq!(validation(r), ("recovery".into(), "already released"));
}

/// S_org, the envelope Alice holds.
fn s_org_of(a: &mut Acct, b: &mut Acct, eid: Id) -> [u8; 32] {
    let bob = me(&mut b.dev);
    let alice = me(&mut a.dev);
    let zone = a.dev.repo().contact_zone(bob.account_id).unwrap();
    let envelope = messages(&mut a.dev, zone)
        .into_iter()
        .find_map(|m| match m {
            RecoveryMessage::Enroll {
                enrollment,
                envelope,
                ..
            } if enrollment.enrollment_id == eid => Some(envelope),
            _ => None,
        })
        .unwrap();
    let kem = &a.dev.repo().account().keyset().kem;
    *unwrap_key_labeled(
        kem,
        &envelope,
        SHARE_LABEL,
        &share_context(&bob, &alice, eid),
    )
    .unwrap()
    .expose()
}

/// Every 32-byte window (step 8) of `data`.
fn windows(data: &[u8]) -> impl Iterator<Item = [u8; 32]> + '_ {
    (0..data.len().saturating_sub(31))
        .step_by(8)
        .map(|i| data[i..i + 32].try_into().unwrap())
}

fn opens(
    slot: &[u8],
    s_org: &[u8; 32],
    s_store: &[u8; 32],
    bob: &onepass_core::share::MemberRef,
    eid: Id,
) -> bool {
    let rk = derive_rk(s_org, s_store, bob.account_id, bob.identity_id, eid).unwrap();
    open(
        &rk,
        BlobKind::RecoverySlot,
        &slot_aad(bob.identity_id),
        slot,
    )
    .is_ok()
}

/// A18: the organizer, with S_org and everything its base holds, does not
/// open the member's keyset (S_store is missing). The slot is handed to
/// her here, as if the server leaked it.
#[test]
fn a18_organizer_alone() {
    let (_zs, mut a, mut b, eid, _release_after) = requested();
    let bob = me(&mut b.dev);
    let s_org = s_org_of(&mut a, &mut b, eid);
    let slot = b
        .dev
        .store()
        .get(RecordKind::RecoverySlot, bob.identity_id)
        .unwrap()
        .unwrap()
        .data;
    let store = a.dev.store();
    assert!(store.list(RecordKind::RecoveryHalf).unwrap().is_empty());
    assert!(store.list(RecordKind::RecoverySlot).unwrap().is_empty());
    let zone = a.dev.repo().contact_zone(bob.account_id).unwrap();
    let mut candidates: Vec<[u8; 32]> = vec![[0; 32], s_org];
    for kind in [
        RecordKind::RecoveryMessage,
        RecordKind::MemberLineage,
        RecordKind::ContactBook,
    ] {
        for r in store
            .list_in(zone, kind)
            .unwrap()
            .iter()
            .chain(store.list(kind).unwrap().iter())
        {
            candidates.extend(windows(&r.data));
        }
    }
    for c in &candidates {
        assert!(!opens(&slot, &s_org, c, &bob, eid));
    }
}

/// The server holds the slot and the half (in clear on iCloud), never
/// S_org: nothing opens.
#[test]
fn server_alone_cannot_recover() {
    let (_zs, _a, mut b, eid, _release_after) = requested();
    let bob = me(&mut b.dev);
    let store = b.dev.store();
    let slot = store
        .get(RecordKind::RecoverySlot, bob.identity_id)
        .unwrap()
        .unwrap()
        .data;
    let half = store
        .get(RecordKind::RecoveryHalf, bob.identity_id)
        .unwrap()
        .unwrap();
    let RecoveryHalf::Clear { s_store, .. } = RecoveryHalf::decode(&half.data).unwrap() else {
        panic!("clear half");
    };
    let mut candidates: Vec<[u8; 32]> = vec![[0; 32], s_store];
    candidates.extend(windows(&slot));
    for c in &candidates {
        assert!(!opens(&slot, c, &s_store, &bob, eid));
    }
}

/// Bob on the mailbox, enrolled, Alice asked.
fn mailbox_requested() -> (Zones, Acct, Acct, Id, i64) {
    let (mut zs, mut a, mut b) = family();
    b.dev
        .repo()
        .set_sync_home(
            onepass_core::synchome::SyncBackend::Mailbox {
                url: "https://box.example.org".into(),
                mailbox_id: [3; 16],
            },
            NOW + 5,
        )
        .unwrap();
    b.sync(&mut zs);
    let v = personal_vault_of(&mut b.dev);
    b.dev.save(&login(v, "bob", NOW + 6));
    b.sync(&mut zs);
    let eid = enroll(&mut zs, &mut a, &mut b, RECOVERY_DELAY_DEFAULT_SECS);
    let bob = account_id(&mut b.dev);
    a.dev
        .repo()
        .request_recovery(bob, PASSWORD, &a.sk, NOW + 100)
        .unwrap();
    settle(&mut zs, &mut [&mut a, &mut b]);
    (
        zs,
        a,
        b,
        eid,
        NOW + 100 + i64::from(RECOVERY_DELAY_DEFAULT_SECS),
    )
}

/// Spec 11.7: the mailbox operator and the organizer together (S_org and
/// every row of the member's mailbox) without the Secret Key open nothing.
#[test]
fn mailbox_operator_and_organizer_cannot_recover() {
    let (_zs, mut a, mut b, eid, release_after) = mailbox_requested();
    let bob = me(&mut b.dev);
    let s_org = s_org_of(&mut a, &mut b, eid);
    let store = b.dev.store();
    let slot = store
        .get(RecordKind::RecoverySlot, bob.identity_id)
        .unwrap()
        .unwrap()
        .data;
    let half = store
        .get(RecordKind::RecoveryHalf, bob.identity_id)
        .unwrap()
        .unwrap();
    let decoded = RecoveryHalf::decode(&half.data).unwrap();
    let RecoveryHalf::Sealed { sealed, .. } = &decoded else {
        panic!("sealed half");
    };
    let sealed = sealed.clone();
    let mut candidates: Vec<[u8; 32]> = vec![[0; 32], s_org];
    candidates.extend(windows(&sealed));
    candidates.extend(windows(&slot));
    for c in &candidates {
        assert!(!opens(&slot, &s_org, c, &bob, eid));
        let k = store_seal_key(c, eid).unwrap();
        assert!(
            open(
                &k,
                BlobKind::RecoverySlot,
                &half_aad(bob.identity_id, eid),
                &sealed
            )
            .is_err()
        );
    }
    // And the app refuses without the kit.
    let (mut resp, frame) = release(&mut a, bob.account_id, release_after);
    let mut n = new_device(&b);
    let r = recover(&mut n, &mut resp, &frame, None, release_after + 10).map(|_| ());
    assert_eq!(validation(r), ("recovery".into(), "emergency kit needed"));
    let _: Aad = slot_aad(bob.identity_id);
}

/// A mailbox account that forgot its password but kept its kit recovers.
#[test]
fn mailbox_recovery_with_kit() {
    let (_zs, mut a, mut b, _eid, release_after) = mailbox_requested();
    let bob = account_id(&mut b.dev);
    let before = users(&b.dev.items());
    let (mut resp, frame) = release(&mut a, bob, release_after);
    let mut n = new_device(&b);
    let (repo, _out, _sk) =
        recover(&mut n, &mut resp, &frame, Some(&b.sk), release_after + 10).unwrap();
    n.repo = Some(repo);
    assert_eq!(users(&n.items()), before);
}

#[test]
fn wrong_enrollment_share_refused() {
    let (_zs, mut a, mut b, eid, release_after) = requested();
    let s_org = s_org_of(&mut a, &mut b, eid);
    let (mut init, mut resp) = face_to_face(release_after);
    let frame = init
        .test_seal(
            &ContactMessage::RecoveryShare {
                enrollment_id: Id::new(),
                s_org: zeroize::Zeroizing::new(s_org),
            },
            release_after,
        )
        .unwrap();
    let mut n = new_device(&b);
    let r = recover(&mut n, &mut resp, &frame, None, release_after).map(|_| ());
    assert_eq!(validation(r), ("recovery".into(), "wrong enrollment"));
}

/// Once the half is handed over, a late cancellation changes nothing.
#[test]
fn cancel_after_release_changes_nothing() {
    let (mut zs, mut a, mut b, eid, release_after) = requested_with_item();
    let bob = account_id(&mut b.dev);
    let before = users(&b.dev.items());
    let (mut resp, frame) = release(&mut a, bob, release_after);
    cancel_recovery(&mut b.dev.store(), eid, &b.keys, release_after + 1).unwrap();
    settle(&mut zs, &mut [&mut a, &mut b]);
    let mut n = new_device(&b);
    let (repo, _out, _sk) = recover(&mut n, &mut resp, &frame, None, release_after + 10).unwrap();
    n.repo = Some(repo);
    assert_eq!(users(&n.items()), before);
}
