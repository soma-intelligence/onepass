//! Attacks on the family and its recovery (sharing plan 3 Task 8, spec 16
//! and 20), end to end against the public API, several accounts on a
//! multi-zone server. A9, A10, A18 and A22 run in `tests/recovery.rs`,
//! next to the fixtures they share with the recovery flow; A14 is a
//! documented limit (`docs/security/README.md`, section 19).

mod common;
mod share_accts;
mod share_common;

use common::*;
use onepass_core::contact::{ContactInitiator, ContactLevel, ContactResponder};
use onepass_core::family::FamilyRole;
use onepass_core::recovery::RECOVERY_DELAY_DEFAULT_SECS;
use onepass_core::repo::recovery::RecoveryStatus;
use onepass_core::share::{AccessTarget, member_key_id};
use onepass_core::store::{RecordKind, Zone};
use share_accts::settle;
use share_accts::*;
use share_common::*;

/// Alice organizes "Famille"; Bob joins as a member, both `Verified`.
fn family() -> (Zones, Acct, Acct, Id) {
    let mut zs = Zones::default();
    let mut a = Acct::new();
    let info = a.dev.repo().create_family("Famille", NOW).unwrap();
    let vault = info.vaults[0];
    a.dev
        .repo()
        .set_zone_home(AccessTarget::Zone(Zone::Family(info.family_id)), home(7))
        .unwrap();
    a.dev
        .repo()
        .set_zone_home(AccessTarget::Zone(Zone::Vault(vault)), home(8))
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
    (zs, a, b, vault)
}

/// The organizer rotates her keys between the request and the release:
/// the enrollment named her old identity, so nothing is released and the
/// member is asked to enroll again.
#[test]
fn organizer_rotates_during_enrollment() {
    let (mut zs, mut a, mut b, _) = family();
    let alice = account_id(&mut a.dev);
    let bob = account_id(&mut b.dev);
    b.dev
        .repo()
        .enroll_recovery(
            alice,
            RECOVERY_DELAY_DEFAULT_SECS,
            PASSWORD,
            &b.sk,
            NOW + 10,
        )
        .unwrap();
    settle(&mut zs, &mut [&mut a, &mut b]);
    a.dev
        .repo()
        .request_recovery(bob, PASSWORD, &a.sk, NOW + 100)
        .unwrap();
    a.sk = a.rotate(false);
    settle(&mut zs, &mut [&mut a, &mut b]);
    b.dev.repo().refresh_member_identities(NOW + 101).unwrap();
    let later = NOW + 100 + i64::from(RECOVERY_DELAY_DEFAULT_SECS);
    assert_eq!(
        a.dev.repo().recovery_status(bob, later).unwrap(),
        RecoveryStatus::NotEnrolled
    );
    let (_resp, qr, hello) = ContactResponder::new_for_recovery(later).unwrap();
    let (mut init, _kx, _code) = ContactInitiator::begin(&qr.to_text(), &hello, later).unwrap();
    init.confirm_sas_for_recovery().unwrap();
    assert!(matches!(
        a.dev.repo().release_recovery_share(bob, &mut init, later),
        Err(Error::Validation(_))
    ));
    assert!(!b.dev.repo().recovery_enrollment().unwrap().unwrap().valid);
}

/// Removing a member from the family rotates every family vault: no
/// envelope of the next generation names them, and their device stops
/// listing the vault.
#[test]
fn family_removal_cuts_every_vault() {
    let (mut zs, mut a, mut b, vault) = family();
    let bob = account_id(&mut b.dev);
    let bob_ref = me(&mut b.dev);
    assert!(
        b.dev
            .repo()
            .shared_vaults()
            .unwrap()
            .iter()
            .any(|v| v.vault_id == vault)
    );
    let info = a.dev.repo().family().unwrap().unwrap();
    let gens: Vec<(Id, u32)> = info
        .vaults
        .iter()
        .map(|v| (*v, generation(&a.dev, *v)))
        .collect();
    a.dev.repo().remove_from_family(bob, NOW + 3).unwrap();
    settle(&mut zs, &mut [&mut a, &mut b]);
    for (v, g) in gens {
        assert_eq!(generation(&a.dev, v), g + 1);
        assert!(
            zs.server(Zone::Vault(v))
                .live(RecordKind::MemberKey, member_key_id(v, g + 1, &bob_ref))
                .is_none()
        );
    }
    assert!(b.dev.repo().family().unwrap().is_none());
    assert!(
        !b.dev
            .repo()
            .shared_vaults()
            .unwrap()
            .iter()
            .any(|v| v.vault_id == vault)
    );
}
