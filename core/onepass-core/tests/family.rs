//! The family (sharing plan 3, Tasks 1 and 2): the signed body and its
//! rules, then the repository operations.

mod common;
mod share_accts;
mod share_common;

use common::*;
use onepass_core::contact::ContactLevel;
use onepass_core::crypto::{HybridKemSecret, HybridSigningKey};
use onepass_core::family::{
    FamilyBody, FamilyInvite, FamilyMember, FamilyReason, FamilyRole, MAX_FAMILY, SignedFamily,
    accept_first_family, accept_next_family, sign_family,
};
use onepass_core::share::AccessTarget;
use onepass_core::share::{
    InviteRecord, MemberRef, Removed, Role, ZoneHome, ZoneSeed, member_key_id,
};
use onepass_core::store::Zone;
use onepass_core::{Error, IntegrityError};
use share_accts::settle;
use share_accts::*;
use share_common::*;

struct Person {
    key: HybridSigningKey,
    member: FamilyMember,
}

fn person(role: FamilyRole, level: ContactLevel) -> Person {
    let key = HybridSigningKey::generate().unwrap();
    let member = FamilyMember {
        account_id: Id::new(),
        identity_id: Id::new(),
        sign_pub: key.verifying_key().unwrap(),
        kem_pub: HybridKemSecret::generate().unwrap().public().unwrap(),
        role,
        level,
        added_at: 100,
    };
    Person { key, member }
}

fn sorted(mut members: Vec<FamilyMember>) -> Vec<FamilyMember> {
    members.sort_by_key(|m| m.account_id);
    members
}

fn first(org: &Person, others: &[&Person]) -> FamilyBody {
    let mut members = vec![org.member.clone()];
    members.extend(others.iter().map(|p| p.member.clone()));
    FamilyBody {
        format: 1,
        family_id: Id([5; 16]),
        seq: 1,
        prev_hash: [0; 32],
        members: sorted(members),
        removed: vec![],
        vaults: vec![Id([6; 16])],
        signer: org.member.member_ref(),
        reason: FamilyReason::Create,
        history: vec![],
        issued_at: 100,
    }
}

fn validation<T: std::fmt::Debug>(r: onepass_core::Result<T>) {
    assert!(matches!(r, Err(Error::Validation(_))), "{r:?}");
}

fn invalid<T: std::fmt::Debug>(r: onepass_core::Result<T>) {
    assert!(matches!(r, Err(Error::InvalidFormat(_))), "{r:?}");
}

#[test]
fn family_round_trip_and_strict() {
    let org = person(FamilyRole::Organizer, ContactLevel::Verified);
    let kid = person(FamilyRole::Member, ContactLevel::Link);
    let signed = sign_family(first(&org, &[&kid]), &org.key).unwrap();
    let bytes = signed.encode();
    assert_eq!(SignedFamily::decode(&bytes).unwrap(), signed);
    let mut longer = bytes.clone();
    longer.push(0);
    assert!(SignedFamily::decode(&longer).is_err());
    assert_eq!(
        accept_first_family(&signed, &org.member.sign_pub).unwrap(),
        signed.body
    );
    // Another key than the organizer's in the body: refused.
    let other = HybridSigningKey::generate().unwrap();
    assert!(accept_first_family(&signed, &other.verifying_key().unwrap()).is_err());
}

#[test]
fn seventh_member_refused() {
    let org = person(FamilyRole::Organizer, ContactLevel::Verified);
    let five: Vec<Person> = (0..5)
        .map(|_| person(FamilyRole::Member, ContactLevel::Verified))
        .collect();
    let refs: Vec<&Person> = five.iter().collect();
    let body = first(&org, &refs);
    assert_eq!(body.members.len(), MAX_FAMILY);
    let head = sign_family(body.clone(), &org.key).unwrap().body;
    let seventh = person(FamilyRole::Member, ContactLevel::Verified);
    let mut next = head
        .next(org.member.member_ref(), FamilyReason::Add, 200)
        .unwrap();
    next.members.push(seventh.member.clone());
    next.members = sorted(next.members);
    invalid(sign_family(next, &org.key));
}

#[test]
fn non_organizer_body_refused() {
    let org = person(FamilyRole::Organizer, ContactLevel::Verified);
    let kid = person(FamilyRole::Member, ContactLevel::Verified);
    let head = first(&org, &[&kid]);
    let newcomer = person(FamilyRole::Member, ContactLevel::Verified);
    let mut next = head
        .next(kid.member.member_ref(), FamilyReason::Add, 200)
        .unwrap();
    next.members.push(newcomer.member.clone());
    next.members = sorted(next.members);
    let signed = sign_family(next, &kid.key).unwrap();
    validation(accept_next_family(&head, &signed));
    // The same body signed by the organizer goes through.
    let mut next = head
        .next(org.member.member_ref(), FamilyReason::Add, 200)
        .unwrap();
    next.members.push(newcomer.member.clone());
    next.members = sorted(next.members);
    let signed = sign_family(next, &org.key).unwrap();
    accept_next_family(&head, &signed).unwrap();
}

#[test]
fn link_organizer_refused() {
    let org = person(FamilyRole::Organizer, ContactLevel::Verified);
    let weak = person(FamilyRole::Organizer, ContactLevel::Link);
    invalid(sign_family(first(&org, &[&weak]), &org.key));
}

#[test]
fn last_organizer_cannot_leave() {
    let org = person(FamilyRole::Organizer, ContactLevel::Verified);
    let kid = person(FamilyRole::Member, ContactLevel::Verified);
    let head = first(&org, &[&kid]);
    let mut next = head
        .next(org.member.member_ref(), FamilyReason::Leave, 200)
        .unwrap();
    next.members
        .retain(|m| m.account_id != org.member.account_id);
    next.removed.push(Removed {
        account_id: org.member.account_id,
        identity_id: org.member.identity_id,
        removed_at: 200,
        by: org.member.member_ref(),
    });
    invalid(sign_family(next, &org.key));
}

#[test]
fn leave_only_removes_self() {
    let org = person(FamilyRole::Organizer, ContactLevel::Verified);
    let kid = person(FamilyRole::Member, ContactLevel::Verified);
    let other = person(FamilyRole::Member, ContactLevel::Verified);
    let head = first(&org, &[&kid, &other]);
    let leave = |extra: bool| {
        let mut next = head
            .next(kid.member.member_ref(), FamilyReason::Leave, 200)
            .unwrap();
        next.members
            .retain(|m| m.account_id != kid.member.account_id);
        next.removed.push(Removed {
            account_id: kid.member.account_id,
            identity_id: kid.member.identity_id,
            removed_at: 200,
            by: kid.member.member_ref(),
        });
        if extra {
            next.members
                .retain(|m| m.account_id != other.member.account_id);
            next.removed.push(Removed {
                account_id: other.member.account_id,
                identity_id: other.member.identity_id,
                removed_at: 200,
                by: kid.member.member_ref(),
            });
        }
        next.removed.sort_by_key(|r| (r.account_id, r.identity_id));
        sign_family(next, &kid.key).unwrap()
    };
    accept_next_family(&head, &leave(false)).unwrap();
    validation(accept_next_family(&head, &leave(true)));
}

#[test]
fn family_rollback_and_fork() {
    let org = person(FamilyRole::Organizer, ContactLevel::Verified);
    let kid = person(FamilyRole::Member, ContactLevel::Verified);
    let h1 = first(&org, &[&kid]);
    let s1 = sign_family(h1.clone(), &org.key).unwrap();
    let mut b2 = h1
        .next(org.member.member_ref(), FamilyReason::Vaults, 200)
        .unwrap();
    b2.vaults.push(Id([7; 16]));
    let h2 = accept_next_family(&h1, &sign_family(b2, &org.key).unwrap()).unwrap();
    // The old body replayed.
    let r = accept_next_family(&h2, &s1);
    assert!(
        matches!(r, Err(Error::Integrity(IntegrityError::FamilyRollback))),
        "{r:?}"
    );
    // Another body at the same seq.
    let mut fork = h1
        .next(org.member.member_ref(), FamilyReason::Vaults, 201)
        .unwrap();
    fork.vaults.push(Id([8; 16]));
    let r = accept_next_family(&h2, &sign_family(fork, &org.key).unwrap());
    assert!(
        matches!(r, Err(Error::Integrity(IntegrityError::FamilyRollback))),
        "{r:?}"
    );
    // A member dropped without being listed as removed.
    let mut drop = h2
        .next(org.member.member_ref(), FamilyReason::Remove, 202)
        .unwrap();
    drop.members
        .retain(|m| m.account_id != kid.member.account_id);
    validation(accept_next_family(
        &h2,
        &sign_family(drop, &org.key).unwrap(),
    ));
}

#[test]
fn vault_invite_bytes_unchanged() {
    // The family variant comes last: the earlier variants keep their tags.
    let org = person(FamilyRole::Organizer, ContactLevel::Verified);
    let signed = sign_family(first(&org, &[]), &org.key).unwrap();
    let home = ZoneHome {
        url: "https://box.example".into(),
        mailbox_id: [9; 16],
        extra_ca_pem: None,
    };
    let _ = ZoneSeed::generate().unwrap();
    let invite =
        FamilyInvite::sign(signed, home, vec![1; 32], org.member.member_ref(), &org.key).unwrap();
    invite.verify(&org.member.sign_pub).unwrap();
    let rec = InviteRecord::Family(invite);
    let bytes = rec.encode();
    assert_eq!(bytes[0], 3);
    assert_eq!(InviteRecord::decode(&bytes).unwrap(), rec);
    let _ = MemberRef {
        account_id: Id::new(),
        identity_id: Id::new(),
    };
}

#[test]
fn skipped_body_followed_through_history() {
    let org = person(FamilyRole::Organizer, ContactLevel::Verified);
    let kid = person(FamilyRole::Member, ContactLevel::Verified);
    let h1 = first(&org, &[&kid]);
    let mut b2 = h1
        .next(org.member.member_ref(), FamilyReason::Vaults, 200)
        .unwrap();
    b2.vaults.push(Id([7; 16]));
    let mut b3 = b2
        .next(org.member.member_ref(), FamilyReason::Vaults, 201)
        .unwrap();
    b3.vaults.push(Id([8; 16]));
    let s3 = sign_family(b3.clone(), &org.key).unwrap();
    assert_eq!(accept_next_family(&h1, &s3).unwrap(), b3);
    // A body whose history does not hold the pinned head: refused.
    let mut lone = b3.clone();
    lone.history.clear();
    let r = accept_next_family(&h1, &sign_family(lone, &org.key).unwrap());
    assert!(
        matches!(r, Err(Error::Integrity(IntegrityError::FamilyRollback))),
        "{r:?}"
    );
}

// ---- Task 2: the family on the repository ----

/// Alice creates her family; its zone and its vault's zone get homes.
fn alice_family() -> (Zones, Acct, Id, Id) {
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
    (zs, a, info.family_id, vault)
}

/// `who` joins Alice's family, held by her at `level`.
fn join(zs: &mut Zones, a: &mut Acct, who: &mut Acct, level: ContactLevel, role: FamilyRole) {
    pin(&mut a.dev, &mut who.dev, level);
    pin(&mut who.dev, &mut a.dev, ContactLevel::Verified);
    contact_zone(&mut a.dev, &mut who.dev);
    let id = account_id(&mut who.dev);
    a.dev.repo().invite_to_family(id, role, NOW + 1).unwrap();
    settle(zs, &mut [&mut *a, &mut *who]);
    let inv = who.dev.repo().family_invites().unwrap()[0].id;
    who.dev.repo().accept_family_invite(inv, NOW + 2).unwrap();
    settle(zs, &mut [&mut *a, &mut *who]);
}

#[test]
fn create_family_has_family_vault() {
    let (_zs, mut a, family_id, vault) = alice_family();
    let info = a.dev.repo().family().unwrap().unwrap();
    assert_eq!(info.family_id, family_id);
    assert_eq!(info.vaults, vec![vault]);
    assert!(info.i_am_organizer);
    assert_eq!(info.members.len(), 1);
    assert_eq!(shared(&mut a.dev, vault).meta.name, "Famille");
}

#[test]
fn invite_then_accept_joins_vaults() {
    let (mut zs, mut a, _, vault) = alice_family();
    let mut b = Acct::new();
    let mut c = Acct::new();
    join(
        &mut zs,
        &mut a,
        &mut b,
        ContactLevel::Verified,
        FamilyRole::Member,
    );
    join(
        &mut zs,
        &mut a,
        &mut c,
        ContactLevel::Link,
        FamilyRole::Member,
    );
    settle(&mut zs, &mut [&mut a, &mut b, &mut c]);
    let bob = account_id(&mut b.dev);
    let carol = account_id(&mut c.dev);
    assert_eq!(role_of(&mut a.dev, vault, bob), Some(Role::Write));
    assert_eq!(role_of(&mut a.dev, vault, carol), Some(Role::Read));
    for x in [&mut b, &mut c] {
        let info = x.dev.repo().family().unwrap().unwrap();
        assert_eq!(info.members.len(), 3);
        assert!(!info.i_am_organizer);
        let v = shared(&mut x.dev, vault);
        x.dev.repo().items(&v).unwrap();
    }
}

#[test]
fn organizer_reads_no_private_vault() {
    let (mut zs, mut a, _, vault) = alice_family();
    let mut b = Acct::new();
    join(
        &mut zs,
        &mut a,
        &mut b,
        ContactLevel::Verified,
        FamilyRole::Member,
    );
    let bobs: Vec<Id> = b
        .dev
        .repo()
        .vaults()
        .unwrap()
        .iter()
        .filter(|v| v.id != vault)
        .map(|v| v.id)
        .collect();
    assert!(!bobs.is_empty());
    let alices: Vec<Id> = a
        .dev
        .repo()
        .vaults()
        .unwrap()
        .iter()
        .map(|v| v.id)
        .collect();
    assert!(bobs.iter().all(|v| !alices.contains(v)));
    let info = a.dev.repo().family().unwrap().unwrap();
    assert!(info.vaults.iter().all(|v| !bobs.contains(v)));
}

#[test]
fn remove_from_family_rotates_each_vault() {
    let (mut zs, mut a, _, vault) = alice_family();
    let mut b = Acct::new();
    join(
        &mut zs,
        &mut a,
        &mut b,
        ContactLevel::Verified,
        FamilyRole::Member,
    );
    let bob = account_id(&mut b.dev);
    let bob_ref = me(&mut b.dev);
    let g = generation(&a.dev, vault);
    let info = a.dev.repo().remove_from_family(bob, NOW + 3).unwrap();
    assert_eq!(info.members.len(), 1);
    settle(&mut zs, &mut [&mut a, &mut b]);
    assert_eq!(generation(&a.dev, vault), g + 1);
    assert!(
        zs.server(Zone::Vault(vault))
            .live(
                onepass_core::store::RecordKind::MemberKey,
                member_key_id(vault, g + 1, &bob_ref)
            )
            .is_none()
    );
    assert!(b.dev.repo().family().unwrap().is_none());
}

#[test]
fn needs_second_organizer_until_two() {
    let (mut zs, mut a, _, _) = alice_family();
    assert!(
        a.dev
            .repo()
            .family()
            .unwrap()
            .unwrap()
            .needs_second_organizer
    );
    let mut b = Acct::new();
    join(
        &mut zs,
        &mut a,
        &mut b,
        ContactLevel::Verified,
        FamilyRole::Member,
    );
    let bob = account_id(&mut b.dev);
    assert!(
        a.dev
            .repo()
            .family()
            .unwrap()
            .unwrap()
            .needs_second_organizer
    );
    let info = a
        .dev
        .repo()
        .set_family_role(bob, FamilyRole::Organizer, NOW + 3)
        .unwrap();
    assert!(!info.needs_second_organizer);
}

#[test]
fn one_family_per_account() {
    let (_zs, mut a, _, _) = alice_family();
    let e = a.dev.repo().create_family("Autre", NOW + 1).unwrap_err();
    assert!(matches!(e, Error::Validation(_)), "{e:?}");
}
