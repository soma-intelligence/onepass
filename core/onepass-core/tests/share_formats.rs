//! Formats of shared vaults (sharing plan 2, Tasks 2 to 5).

use aws_lc_rs::digest::{SHA256, digest};
use onepass_core::account::Keyset;
use onepass_core::crypto::kem::wrap_key_labeled;
use onepass_core::crypto::{
    HybridKemSecret, HybridSigningKey, IdentityKey, SymmetricKey, wrap_key,
};
use onepass_core::share::{
    MemberKey, MemberRef, VAULT_KEY_LABEL, key_commit, key_context, member_key_id, open_member_key,
    wrap_member_key,
};
use onepass_core::{Error, Id, IntegrityError};

fn keyset() -> Keyset {
    Keyset {
        kem: HybridKemSecret::generate().unwrap(),
        signing: HybridSigningKey::generate().unwrap(),
        identity: IdentityKey::generate().unwrap(),
        retired_kem: Vec::new(),
    }
}

fn member() -> MemberRef {
    MemberRef {
        account_id: Id::new(),
        identity_id: Id::new(),
    }
}

#[test]
fn member_key_round_trip_and_strict() {
    let ks = keyset();
    let m = member();
    let v = Id::new();
    let key = SymmetricKey::generate().unwrap();
    let mk = wrap_member_key(&ks.kem.public().unwrap(), &key, v, 3, &m).unwrap();
    let bytes = mk.encode();
    assert_eq!(MemberKey::decode(&bytes).unwrap(), mk);
    let mut longer = bytes.clone();
    longer.push(0);
    assert!(matches!(
        MemberKey::decode(&longer),
        Err(Error::InvalidFormat(_))
    ));
    assert!(matches!(
        MemberKey::decode(&bytes[..bytes.len() - 1]),
        Err(Error::InvalidFormat(_))
    ));
    let zero = MemberKey {
        generation: 0,
        ..mk.clone()
    };
    assert!(matches!(
        MemberKey::decode(&zero.encode()),
        Err(Error::InvalidFormat(_))
    ));
    let empty = MemberKey {
        envelope: Vec::new(),
        ..mk.clone()
    };
    assert!(matches!(
        MemberKey::decode(&empty.encode()),
        Err(Error::InvalidFormat(_))
    ));
    let commit = key_commit(&key, v, 3);
    let opened = open_member_key(&ks, &mk, &commit).unwrap();
    assert_eq!(opened.expose(), key.expose());
}

#[test]
fn member_key_id_formula() {
    let m = member();
    let v = Id::new();
    let mut pre = b"onepass/member-key-id/v1".to_vec();
    pre.extend_from_slice(&v.0);
    pre.extend_from_slice(&7u32.to_be_bytes());
    pre.extend_from_slice(&m.account_id.0);
    pre.extend_from_slice(&m.identity_id.0);
    let h = digest(&SHA256, &pre);
    assert_eq!(member_key_id(v, 7, &m).0[..], h.as_ref()[..16]);
}

#[test]
fn key_commit_formula() {
    let key = SymmetricKey::from_bytes([9; 32]);
    let v = Id([1; 16]);
    let k = aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA256, &[9; 32]);
    let mut msg = b"onepass/vault-key-commit/v1".to_vec();
    msg.extend_from_slice(&[1; 16]);
    msg.extend_from_slice(&2u32.to_be_bytes());
    assert_eq!(
        key_commit(&key, v, 2)[..],
        aws_lc_rs::hmac::sign(&k, &msg).as_ref()[..]
    );
    assert_ne!(key_commit(&key, v, 2), key_commit(&key, v, 3));
}

#[test]
fn a15_substituted_envelope() {
    let ks = keyset();
    let m = member();
    let v = Id::new();
    let real = SymmetricKey::generate().unwrap();
    let other = SymmetricKey::generate().unwrap();
    // A valid envelope of another key, under the right context.
    let mk = wrap_member_key(&ks.kem.public().unwrap(), &other, v, 1, &m).unwrap();
    let r = open_member_key(&ks, &mk, &key_commit(&real, v, 1));
    assert!(matches!(
        r,
        Err(Error::Integrity(IntegrityError::Commitment))
    ));
}

#[test]
fn a16_envelope_context() {
    let ks = keyset();
    let m = member();
    let v = Id::new();
    let key = SymmetricKey::generate().unwrap();
    let mk = wrap_member_key(&ks.kem.public().unwrap(), &key, v, 1, &m).unwrap();
    let other_vault = Id::new();
    let variants = [
        MemberKey {
            vault_id: other_vault,
            ..mk.clone()
        },
        MemberKey {
            generation: 2,
            ..mk.clone()
        },
        MemberKey {
            account_id: Id::new(),
            ..mk.clone()
        },
        MemberKey {
            identity_id: Id::new(),
            ..mk.clone()
        },
    ];
    for bad in variants {
        // The envelope's AEAD fails (its own key commitment, or the tag):
        // never a key, never a panic.
        let commit = key_commit(&key, bad.vault_id, bad.generation);
        let r = open_member_key(&ks, &bad, &commit);
        assert!(
            matches!(
                r,
                Err(Error::Crypto)
                    | Err(Error::Integrity(IntegrityError::Aead))
                    | Err(Error::Integrity(IntegrityError::Commitment))
            ),
            "{r:?}"
        );
    }
}

#[test]
fn retired_kem_opens_old_envelope() {
    let old = keyset();
    let m = member();
    let v = Id::new();
    let key = SymmetricKey::generate().unwrap();
    let mk = wrap_member_key(&old.kem.public().unwrap(), &key, v, 1, &m).unwrap();
    // After a rotation: a new KEM key, the old one retired.
    let rotated = Keyset {
        kem: HybridKemSecret::generate().unwrap(),
        signing: HybridSigningKey::generate().unwrap(),
        identity: IdentityKey::generate().unwrap(),
        retired_kem: vec![HybridKemSecret::from_bytes(&old.kem.to_bytes()).unwrap()],
    };
    let opened = open_member_key(&rotated, &mk, &key_commit(&key, v, 1)).unwrap();
    assert_eq!(opened.expose(), key.expose());
    // Without the retired key it does not open.
    let fresh = keyset();
    assert!(open_member_key(&fresh, &mk, &key_commit(&key, v, 1)).is_err());
}

#[test]
fn label_separated_from_pairing_and_vault() {
    let ks = keyset();
    let m = member();
    let v = Id::new();
    let key = SymmetricKey::generate().unwrap();
    let commit = key_commit(&key, v, 1);
    let pub_ = ks.kem.public().unwrap();
    let ctx = key_context(v, 1, &m);
    let pairing = wrap_key_labeled(&pub_, &key, b"onepass/pairing/v1", &ctx).unwrap();
    let mut vault_ctx = b"vault:".to_vec();
    vault_ctx.extend_from_slice(&v.0);
    let personal = wrap_key(&pub_, &key, &vault_ctx).unwrap();
    let personal_same_ctx = wrap_key(&pub_, &key, &ctx).unwrap();
    for envelope in [pairing, personal, personal_same_ctx] {
        let mk = MemberKey {
            vault_id: v,
            generation: 1,
            account_id: m.account_id,
            identity_id: m.identity_id,
            envelope,
        };
        assert!(open_member_key(&ks, &mk, &commit).is_err());
    }
    // The right label opens.
    let good = wrap_key_labeled(&pub_, &key, VAULT_KEY_LABEL, &ctx).unwrap();
    let mk = MemberKey {
        vault_id: v,
        generation: 1,
        account_id: m.account_id,
        identity_id: m.identity_id,
        envelope: good,
    };
    assert!(open_member_key(&ks, &mk, &commit).is_ok());
}

// ------------------------------------------------------------ membership

use onepass_core::contact::ContactLevel;
use onepass_core::share::{
    MAX_MEMBERS, Member, MembershipBody, MembershipReason, MovedTo, Removed, Role,
    SignedMembership, ZoneHome, accept_first, accept_next, merge_concurrent, merge_removed,
    sign_membership,
};

struct Person {
    key: HybridSigningKey,
    member: Member,
}

fn person(role: Role, level: ContactLevel, owner: bool) -> Person {
    let key = HybridSigningKey::generate().unwrap();
    let account_id = Id::new();
    let member = Member {
        account_id,
        identity_id: Id::new(),
        identity_pub_hash: [1; 32],
        sign_pub: key.verifying_key().unwrap(),
        kem_pub: HybridKemSecret::generate().unwrap().public().unwrap(),
        role,
        owner,
        level,
        added_by: MemberRef {
            account_id,
            identity_id: Id::new(),
        },
        added_at: 100,
        key_pending: false,
        credential_id: *Id::new().0.first_chunk::<16>().unwrap(),
    };
    Person { key, member }
}

fn sorted(mut members: Vec<Member>) -> Vec<Member> {
    members.sort_by_key(|m| m.account_id);
    members
}

fn first_body(vault: Id, owner: &Person, others: &[&Person]) -> MembershipBody {
    let mut members = vec![owner.member.clone()];
    members.extend(others.iter().map(|p| p.member.clone()));
    MembershipBody {
        format: 1,
        vault_id: vault,
        seq: 1,
        prev_hash: [0; 32],
        generation: 1,
        key_commit: [7; 32],
        members: sorted(members),
        removed: Vec::new(),
        signer: owner.member.member_ref(),
        reason: MembershipReason::Create,
        moved_to: None,
        history: Vec::new(),
        issued_at: 1000,
    }
}

struct Cast {
    alice: Person,
    bob: Person,
    carol: Person,
    head: MembershipBody,
}

/// Alice owner and manager, Bob writer, Carol reader (Link).
fn cast() -> Cast {
    let alice = person(Role::Manage, ContactLevel::Verified, true);
    let bob = person(Role::Write, ContactLevel::Verified, false);
    let carol = person(Role::Read, ContactLevel::Link, false);
    let head = first_body(Id::new(), &alice, &[&bob, &carol]);
    Cast {
        alice,
        bob,
        carol,
        head,
    }
}

fn signed(body: MembershipBody, by: &Person) -> SignedMembership {
    sign_membership(body, &by.key).unwrap()
}

fn next_by(c: &MembershipBody, by: &Person, reason: MembershipReason) -> MembershipBody {
    c.next(by.member.member_ref(), reason, 2000).unwrap()
}

fn remove(body: &mut MembershipBody, who: &Person, by: &Person) {
    body.members
        .retain(|m| m.account_id != who.member.account_id);
    body.removed.push(Removed {
        account_id: who.member.account_id,
        identity_id: who.member.identity_id,
        removed_at: 2000,
        by: by.member.member_ref(),
    });
    body.removed.sort_by_key(|r| (r.account_id, r.identity_id));
}

fn validation<T: std::fmt::Debug>(r: onepass_core::Result<T>) {
    assert!(matches!(r, Err(Error::Validation(_))), "{r:?}");
}

#[test]
fn membership_round_trip() {
    let c = cast();
    let s = signed(c.head.clone(), &c.alice);
    let bytes = s.encode();
    assert_eq!(SignedMembership::decode(&bytes).unwrap(), s);
    let mut longer = bytes.clone();
    longer.push(0);
    assert!(SignedMembership::decode(&longer).is_err());
    assert_eq!(accept_first(&s, &c.alice.member.sign_pub).unwrap(), c.head);
    // The signer key must be the caller's.
    assert!(accept_first(&s, &c.bob.member.sign_pub).is_err());
}

#[test]
fn rule1_strict_decode() {
    let c = cast();
    let mut unsorted = c.head.clone();
    unsorted.members.reverse();
    let mut dup = c.head.clone();
    dup.members.push(dup.members[0].clone());
    dup.members = sorted(dup.members);
    let mut zero = c.head.clone();
    zero.seq = 0;
    let mut first_with_prev = c.head.clone();
    first_with_prev.prev_hash = [1; 32];
    for bad in [unsorted, dup, zero, first_with_prev] {
        assert!(sign_membership(bad.clone(), &c.alice.key).is_err());
        let forged = SignedMembership {
            body: bad,
            sig: signed(c.head.clone(), &c.alice).sig,
        };
        assert!(matches!(
            SignedMembership::decode(&forged.encode()),
            Err(Error::InvalidFormat(_))
        ));
    }
    // A broken chain at seq + 1.
    let mut n = next_by(&c.head, &c.alice, MembershipReason::Meta);
    n.prev_hash = [9; 32];
    assert!(matches!(
        accept_next(&c.head, &signed(n, &c.alice)),
        Err(Error::Integrity(IntegrityError::MembershipRollback))
    ));
}

#[test]
fn sixty_fifth_member_refused() {
    let c = cast();
    let mut body = c.head.clone();
    while body.members.len() < MAX_MEMBERS + 1 {
        let mut m = c.bob.member.clone();
        m.account_id = Id::new();
        m.credential_id = *Id::new().0.first_chunk::<16>().unwrap();
        body.members.push(m);
    }
    body.members = sorted(body.members);
    assert!(matches!(
        sign_membership(body.clone(), &c.alice.key),
        Err(Error::InvalidFormat(_))
    ));
    // Drop one non-owner: back at the cap, accepted.
    let owner = c.alice.member.account_id;
    let i = body
        .members
        .iter()
        .position(|m| m.account_id != owner)
        .unwrap();
    body.members.remove(i);
    assert_eq!(body.members.len(), MAX_MEMBERS);
    sign_membership(body, &c.alice.key).unwrap();
}

#[test]
fn a2_injected_member_refused() {
    let c = cast();
    let outsider = person(Role::Manage, ContactLevel::Verified, false);
    // Signed by a non-member.
    let mut n = c
        .head
        .next(outsider.member.member_ref(), MembershipReason::Add, 2000)
        .unwrap();
    n.members.push(outsider.member.clone());
    n.members = sorted(n.members);
    validation(accept_next(&c.head, &signed(n, &outsider)));
    // Signed by a writer.
    let mut n = next_by(&c.head, &c.bob, MembershipReason::Add);
    n.members.push(outsider.member.clone());
    n.members = sorted(n.members);
    validation(accept_next(&c.head, &signed(n, &c.bob)));
    // The received body swaps Alice's signing key for the attacker's.
    let mut n = next_by(&c.head, &c.alice, MembershipReason::Add);
    for m in &mut n.members {
        if m.account_id == c.alice.member.account_id {
            m.sign_pub = outsider.member.sign_pub.clone();
        }
    }
    n.members.push({
        let mut m = outsider.member.clone();
        m.role = Role::Read;
        m
    });
    n.members = sorted(n.members);
    let r = accept_next(&c.head, &signed(n, &outsider));
    assert!(
        matches!(r, Err(Error::Integrity(IntegrityError::Signature))),
        "{r:?}"
    );
    // The honest add passes.
    let mut n = next_by(&c.head, &c.alice, MembershipReason::Add);
    n.members.push(outsider.member.clone());
    n.members = sorted(n.members);
    accept_next(&c.head, &signed(n, &c.alice)).unwrap();
}

#[test]
fn leave_only_removes_self() {
    let c = cast();
    let mut n = next_by(&c.head, &c.bob, MembershipReason::Leave);
    remove(&mut n, &c.bob, &c.bob);
    accept_next(&c.head, &signed(n.clone(), &c.bob)).unwrap();
    // Also removes Carol.
    let mut more = n.clone();
    remove(&mut more, &c.carol, &c.bob);
    validation(accept_next(&c.head, &signed(more, &c.bob)));
    // Also changes a role.
    let mut role = n.clone();
    for m in &mut role.members {
        if m.account_id == c.carol.member.account_id {
            m.role = Role::Read;
            m.added_at = 1;
        }
    }
    validation(accept_next(&c.head, &signed(role, &c.bob)));
    // The owner cannot leave.
    let mut owner = next_by(&c.head, &c.alice, MembershipReason::Leave);
    remove(&mut owner, &c.alice, &c.alice);
    let bob_mgr = owner
        .members
        .iter_mut()
        .find(|m| m.account_id == c.bob.member.account_id)
        .unwrap();
    bob_mgr.role = Role::Manage;
    validation(accept_next(&c.head, &signed(owner, &c.alice)));
}

#[test]
fn removed_is_monotone() {
    let c = cast();
    let mut n = next_by(&c.head, &c.alice, MembershipReason::Remove);
    remove(&mut n, &c.carol, &c.alice);
    n.generation = 2;
    n.key_commit = [8; 32];
    let h2 = accept_next(&c.head, &signed(n, &c.alice)).unwrap();
    // A removed entry that disappears.
    let mut n3 = next_by(&h2, &c.alice, MembershipReason::Meta);
    n3.removed.clear();
    validation(accept_next(&h2, &signed(n3, &c.alice)));
    // A removed member still listed under the same identity.
    let mut n3 = next_by(&h2, &c.alice, MembershipReason::Add);
    n3.members.push(c.carol.member.clone());
    n3.members = sorted(n3.members);
    assert!(sign_membership(n3, &c.alice.key).is_err());
    // A member dropped without being listed as removed.
    let mut n3 = next_by(&h2, &c.alice, MembershipReason::Meta);
    n3.members
        .retain(|m| m.account_id != c.bob.member.account_id);
    validation(accept_next(&h2, &signed(n3, &c.alice)));
}

#[test]
fn owner_protected() {
    let c = cast();
    // Dave, a second manager who is not the owner.
    let dave = person(Role::Manage, ContactLevel::Verified, false);
    let mut n = next_by(&c.head, &c.alice, MembershipReason::Add);
    n.members.push(dave.member.clone());
    n.members = sorted(n.members);
    let h2 = accept_next(&c.head, &signed(n, &c.alice)).unwrap();
    // Dave removes the owner.
    let mut n = next_by(&h2, &dave, MembershipReason::Remove);
    remove(&mut n, &c.alice, &dave);
    n.generation = 2;
    n.key_commit = [8; 32];
    validation(accept_next(&h2, &signed(n, &dave)));
    // Dave demotes the owner.
    let mut n = next_by(&h2, &dave, MembershipReason::Role);
    for m in &mut n.members {
        if m.owner {
            m.role = Role::Write;
        }
    }
    validation(accept_next(&h2, &signed(n, &dave)));
    // Dave makes himself owner.
    let mut n = next_by(&h2, &dave, MembershipReason::Role);
    for m in &mut n.members {
        m.owner = m.account_id == dave.member.account_id;
    }
    validation(accept_next(&h2, &signed(n, &dave)));
    // The owner demotes itself, Dave still manages: accepted.
    let mut n = next_by(&h2, &c.alice, MembershipReason::Role);
    for m in &mut n.members {
        if m.owner {
            m.role = Role::Write;
        }
    }
    accept_next(&h2, &signed(n, &c.alice)).unwrap();
    // The last manager demoted: refused (shape).
    let mut n = next_by(&c.head, &c.alice, MembershipReason::Role);
    for m in &mut n.members {
        if m.owner {
            m.role = Role::Write;
        }
    }
    assert!(sign_membership(n, &c.alice.key).is_err());
}

#[test]
fn generation_bump_rules() {
    let c = cast();
    // Bump without a new commitment.
    let mut n = next_by(&c.head, &c.alice, MembershipReason::Rekey);
    n.generation = 2;
    validation(accept_next(&c.head, &signed(n, &c.alice)));
    // Bump with Add.
    let mut n = next_by(&c.head, &c.alice, MembershipReason::Add);
    n.generation = 2;
    n.key_commit = [8; 32];
    validation(accept_next(&c.head, &signed(n, &c.alice)));
    // New commitment without a bump.
    let mut n = next_by(&c.head, &c.alice, MembershipReason::Rekey);
    n.key_commit = [8; 32];
    validation(accept_next(&c.head, &signed(n, &c.alice)));
    for reason in [
        MembershipReason::Remove,
        MembershipReason::Rekey,
        MembershipReason::IdentityUpdate,
    ] {
        let mut n = next_by(&c.head, &c.alice, reason);
        n.generation = 2;
        n.key_commit = [8; 32];
        if reason == MembershipReason::Remove {
            remove(&mut n, &c.carol, &c.alice);
        }
        accept_next(&c.head, &signed(n, &c.alice)).unwrap();
    }
}

#[test]
fn link_member_read_only() {
    let c = cast();
    for role in [Role::Write, Role::Manage] {
        let mut n = next_by(&c.head, &c.alice, MembershipReason::Role);
        for m in &mut n.members {
            if m.account_id == c.carol.member.account_id {
                m.role = role;
            }
        }
        assert!(matches!(
            sign_membership(n, &c.alice.key),
            Err(Error::InvalidFormat(_))
        ));
    }
}

#[test]
fn moved_to_only_with_rekey() {
    let c = cast();
    let home = ZoneHome {
        url: "https://mailbox.example".into(),
        mailbox_id: [3; 16],
        extra_ca_pem: None,
    };
    let mut n = next_by(&c.head, &c.alice, MembershipReason::Meta);
    n.moved_to = Some(MovedTo {
        owner: c.alice.member.member_ref(),
        home: home.clone(),
    });
    assert!(sign_membership(n, &c.alice.key).is_err());
    let mut n = next_by(&c.head, &c.alice, MembershipReason::Rekey);
    n.generation = 2;
    n.key_commit = [8; 32];
    n.moved_to = Some(MovedTo {
        owner: c.alice.member.member_ref(),
        home,
    });
    accept_next(&c.head, &signed(n, &c.alice)).unwrap();
}

#[test]
fn credential_ids_unique() {
    let c = cast();
    let mut n = next_by(&c.head, &c.alice, MembershipReason::Meta);
    let id = n.members[0].credential_id;
    n.members[1].credential_id = id;
    assert!(matches!(
        sign_membership(n, &c.alice.key),
        Err(Error::InvalidFormat(_))
    ));
}

#[test]
fn a3_membership_rollback() {
    let c = cast();
    let mut n = next_by(&c.head, &c.alice, MembershipReason::Remove);
    remove(&mut n, &c.carol, &c.alice);
    n.generation = 2;
    n.key_commit = [8; 32];
    let s2 = signed(n, &c.alice);
    let h2 = accept_next(&c.head, &s2).unwrap();
    let h3 = accept_next(
        &h2,
        &signed(next_by(&h2, &c.alice, MembershipReason::Meta), &c.alice),
    )
    .unwrap();
    // The body from before Carol's removal, replayed.
    let r = accept_next(&h3, &signed(c.head.clone(), &c.alice));
    assert!(matches!(
        r,
        Err(Error::Integrity(IntegrityError::MembershipRollback))
    ));
    let r = accept_next(&h3, &s2);
    assert!(matches!(
        r,
        Err(Error::Integrity(IntegrityError::MembershipRollback))
    ));
    // A skip ahead is accepted when the history chains it.
    let h4 = h3
        .next(c.alice.member.member_ref(), MembershipReason::Meta, 3000)
        .unwrap();
    let h5 = h4
        .next(c.alice.member.member_ref(), MembershipReason::Meta, 3001)
        .unwrap();
    accept_next(&h3, &signed(h5, &c.alice)).unwrap();
}

#[test]
fn same_seq_other_hash_is_fork() {
    let c = cast();
    let a = next_by(&c.head, &c.alice, MembershipReason::Meta);
    let mut b = a.clone();
    b.issued_at += 1;
    let h2 = accept_next(&c.head, &signed(a.clone(), &c.alice)).unwrap();
    assert_eq!(accept_next(&h2, &signed(a, &c.alice)).unwrap(), h2);
    assert!(matches!(
        accept_next(&h2, &signed(b, &c.alice)),
        Err(Error::Integrity(IntegrityError::MembershipFork))
    ));
}

#[test]
fn merge_removal_wins() {
    let c = cast();
    // Mine removes Carol; theirs promotes her to... a role change on her.
    let mut mine = next_by(&c.head, &c.alice, MembershipReason::Remove);
    remove(&mut mine, &c.carol, &c.alice);
    let mut theirs = next_by(&c.head, &c.alice, MembershipReason::Role);
    for m in &mut theirs.members {
        if m.account_id == c.bob.member.account_id {
            m.role = Role::Read;
        }
    }
    let merged = merge_concurrent(&c.head, &mine, &theirs).unwrap();
    assert!(
        merged
            .iter()
            .all(|m| m.account_id != c.carol.member.account_id)
    );
    assert_eq!(
        merged
            .iter()
            .find(|m| m.account_id == c.bob.member.account_id)
            .unwrap()
            .role,
        Role::Read
    );
    assert_eq!(merge_removed(&c.head, &mine, &theirs).len(), 1);
}

#[test]
fn merge_lowest_role_wins() {
    let c = cast();
    let set = |role| {
        let mut n = next_by(&c.head, &c.alice, MembershipReason::Role);
        for m in &mut n.members {
            if m.account_id == c.bob.member.account_id {
                m.role = role;
            }
        }
        n
    };
    let mine = set(Role::Manage);
    let theirs = set(Role::Read);
    for merged in [
        merge_concurrent(&c.head, &mine, &theirs).unwrap(),
        merge_concurrent(&c.head, &theirs, &mine).unwrap(),
    ] {
        let bob = merged
            .iter()
            .find(|m| m.account_id == c.bob.member.account_id)
            .unwrap();
        assert_eq!(bob.role, Role::Read);
    }
}

mod merge_props {
    use super::*;
    use proptest::prelude::*;

    /// One concurrent change: remove member i, set member i's role, or add
    /// a new member with a given role.
    #[derive(Debug, Clone)]
    enum Op {
        Remove(usize),
        Role(usize, u8),
        Add(u8, i64),
    }

    fn ops() -> impl Strategy<Value = Vec<Op>> {
        prop::collection::vec(
            prop_oneof![
                (0usize..4).prop_map(Op::Remove),
                (0usize..4, 0u8..3).prop_map(|(i, r)| Op::Role(i, r)),
                (0u8..3, 0i64..10).prop_map(|(r, t)| Op::Add(r, t)),
            ],
            0..4,
        )
    }

    fn role(r: u8) -> Role {
        [Role::Read, Role::Write, Role::Manage][r as usize]
    }

    fn apply(base: &MembershipBody, ops: &[Op], pool: &[Member]) -> MembershipBody {
        let mut b = base.clone();
        for (k, op) in ops.iter().enumerate() {
            match op {
                Op::Remove(i) => {
                    if let Some(m) = base.members.get(*i) {
                        let m = m.clone();
                        if b.members.iter().any(|x| x.account_id == m.account_id) {
                            b.members.retain(|x| x.account_id != m.account_id);
                            b.removed.push(Removed {
                                account_id: m.account_id,
                                identity_id: m.identity_id,
                                removed_at: 50 + k as i64,
                                by: m.added_by,
                            });
                        }
                    }
                }
                Op::Role(i, r) => {
                    if let Some(m) = base.members.get(*i) {
                        for x in &mut b.members {
                            if x.account_id == m.account_id {
                                x.role = role(*r);
                            }
                        }
                    }
                }
                Op::Add(r, t) => {
                    let mut m = pool[(*r as usize + *t as usize) % pool.len()].clone();
                    m.role = role(*r);
                    m.added_at = *t;
                    if !b.members.iter().any(|x| x.account_id == m.account_id) {
                        b.members.push(m);
                    }
                }
            }
        }
        b.members.sort_by_key(|m| m.account_id);
        b.removed.sort_by_key(|r| (r.account_id, r.identity_id));
        b
    }

    fn fixture() -> &'static (MembershipBody, Vec<Member>) {
        static F: std::sync::OnceLock<(MembershipBody, Vec<Member>)> = std::sync::OnceLock::new();
        F.get_or_init(|| {
            let c = cast();
            let d = person(Role::Write, ContactLevel::Verified, false);
            let mut head = c.head.clone();
            head.members.push(d.member);
            head.members = sorted(head.members);
            let pool = (0..3)
                .map(|_| person(Role::Read, ContactLevel::Verified, false).member)
                .collect();
            (head, pool)
        })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]
        #[test]
        fn merge_commutes(a in ops(), b in ops()) {
            let (base, pool) = fixture();
            let mine = apply(base, &a, pool);
            let theirs = apply(base, &b, pool);
            let x = merge_concurrent(base, &mine, &theirs).unwrap();
            let y = merge_concurrent(base, &theirs, &mine).unwrap();
            prop_assert_eq!(&x, &y);
            prop_assert_eq!(merge_removed(base, &mine, &theirs), merge_removed(base, &theirs, &mine));
            // Removal wins: nobody removed on either side is in the merge.
            for r in mine.removed.iter().chain(&theirs.removed) {
                prop_assert!(!x.iter().any(|m| m.account_id == r.account_id && m.identity_id == r.identity_id));
            }
        }
    }
}

// ------------------------------------------------------------ shared manifests

mod manifests {
    use super::*;
    use onepass_core::manifest::{
        Manifest, ManifestEntry, SeenManifest, manifest_hash, sign_manifest, verify_manifest,
    };
    use onepass_core::share::{
        MembershipView, SharedSignedManifest, sign_shared_manifest, verify_shared_manifest,
    };
    use onepass_core::vault::{Vault, VaultMeta};

    fn meta(name: &str) -> VaultMeta {
        VaultMeta {
            name: name.into(),
            icon: "folder".into(),
            color: "blue".into(),
            travel_safe: false,
            mcp_access: false,
        }
    }

    struct World {
        c: Cast,
        vault: Vault,
    }

    fn world() -> World {
        let c = cast();
        let (vault, _, _) = Vault::new_shared(c.head.vault_id, meta("Family")).unwrap();
        World { c, vault }
    }

    fn manifest(w: &World, body: &MembershipBody) -> Manifest {
        Manifest::next(None, w.vault.id, Vec::new())
            .unwrap()
            .with_meta(&w.vault.meta)
            .with_membership(body.seen(), body.generation)
    }

    fn sign(w: &World, by: &Person, m: &Manifest) -> SharedSignedManifest {
        sign_shared_manifest(&w.vault, &by.key, by.member.member_ref(), m).unwrap()
    }

    fn view<'a>(head: &'a MembershipBody, ancestors: &'a [MembershipBody]) -> MembershipView<'a> {
        MembershipView { head, ancestors }
    }

    #[test]
    fn shared_manifest_round_trip() {
        let w = world();
        let m = manifest(&w, &w.c.head);
        let sm = sign(&w, &w.c.bob, &m);
        assert_eq!(SharedSignedManifest::decode(&sm.encode()).unwrap(), sm);
        let mut longer = sm.encode();
        longer.push(0);
        assert!(SharedSignedManifest::decode(&longer).is_err());
        let got = verify_shared_manifest(&w.vault, &view(&w.c.head, &[]), &sm, None, None).unwrap();
        assert_eq!(got, m);
        // Without the shared fields, nothing is signed.
        let plain = Manifest::next(None, w.vault.id, Vec::new()).unwrap();
        assert!(
            sign_shared_manifest(&w.vault, &w.c.bob.key, w.c.bob.member.member_ref(), &plain)
                .is_err()
        );
    }

    #[test]
    fn personal_manifest_bytes_unchanged() {
        // A personal manifest keeps its EXT_V1 encoding: the hash below is
        // the one `manifest_hash` gave before the shared extension existed.
        let m = Manifest {
            vault_id: Id([1; 16]),
            seq: 2,
            prev_hash: [3; 32],
            entries: vec![ManifestEntry {
                item_id: Id([4; 16]),
                version: 5,
                record_hash: [6; 32],
            }],
            merkle_root: [7; 32],
            ext: Some(onepass_core::manifest::ManifestExt {
                meta_hash: Some([8; 32]),
                history: vec![(1, [9; 32])],
                membership: None,
                generation: None,
            }),
        };
        let mut plain = postcard::to_allocvec(&m).unwrap();
        plain.push(1);
        plain.extend(postcard::to_allocvec(&(Some([8u8; 32]), vec![(1u64, [9u8; 32])])).unwrap());
        assert_eq!(manifest_hash(&m), digest(&SHA256, &plain).as_ref());
    }

    #[test]
    fn a21_domain_separation() {
        let w = world();
        // A personal manifest, signed by Alice, served as a shared one.
        let personal = Manifest::next(None, w.vault.id, Vec::new()).unwrap();
        let sm = sign_manifest(&w.vault, &w.c.alice.key, &personal).unwrap();
        let replay = SharedSignedManifest {
            blob: sm.blob.clone(),
            signer: w.c.alice.member.member_ref(),
            sig: sm.sig.clone(),
        };
        let r = verify_shared_manifest(&w.vault, &view(&w.c.head, &[]), &replay, None, None);
        assert!(
            matches!(r, Err(Error::Integrity(IntegrityError::Signature))),
            "{r:?}"
        );
        // And the other way.
        let shared = sign(&w, &w.c.alice, &manifest(&w, &w.c.head));
        let back = onepass_core::manifest::SignedManifest {
            blob: shared.blob,
            sig: shared.sig,
        };
        let r = verify_manifest(&w.vault, &w.c.alice.member.sign_pub, &back, None);
        assert!(
            matches!(r, Err(Error::Integrity(IntegrityError::Signature))),
            "{r:?}"
        );
    }

    #[test]
    fn a6_reader_manifest_refused() {
        let w = world();
        let sm = sign(&w, &w.c.carol, &manifest(&w, &w.c.head));
        validation(verify_shared_manifest(
            &w.vault,
            &view(&w.c.head, &[]),
            &sm,
            None,
            None,
        ));
    }

    #[test]
    fn a7_writer_meta_refused() {
        let w = world();
        let m = manifest(&w, &w.c.head);
        let other_meta = Some([0xaa; 32]);
        let by_bob = sign(&w, &w.c.bob, &m);
        validation(verify_shared_manifest(
            &w.vault,
            &view(&w.c.head, &[]),
            &by_bob,
            None,
            other_meta,
        ));
        let by_alice = sign(&w, &w.c.alice, &m);
        verify_shared_manifest(&w.vault, &view(&w.c.head, &[]), &by_alice, None, other_meta)
            .unwrap();
        // Same meta: a writer is fine.
        let same = Some(onepass_core::manifest::meta_hash(&w.vault.meta));
        verify_shared_manifest(&w.vault, &view(&w.c.head, &[]), &by_bob, None, same).unwrap();
    }

    #[test]
    fn pointer_to_ancestor_ok_unless_role_or_generation_changed() {
        let w = world();
        let h1 = w.c.head.clone();
        let old = sign(&w, &w.c.bob, &manifest(&w, &h1));
        // A meta body: nothing changes for Bob.
        let h2 = next_by(&h1, &w.c.alice, MembershipReason::Meta);
        let anc = [h1.clone()];
        verify_shared_manifest(&w.vault, &view(&h2, &anc), &old, None, None).unwrap();
        // Bob demoted to reader since.
        let mut demoted = next_by(&h1, &w.c.alice, MembershipReason::Role);
        for m in &mut demoted.members {
            if m.account_id == w.c.bob.member.account_id {
                m.role = Role::Read;
            }
        }
        validation(verify_shared_manifest(
            &w.vault,
            &view(&demoted, &anc),
            &old,
            None,
            None,
        ));
        // A rekey since.
        let mut rekey = next_by(&h1, &w.c.alice, MembershipReason::Rekey);
        rekey.generation = 2;
        rekey.key_commit = [8; 32];
        validation(verify_shared_manifest(
            &w.vault,
            &view(&rekey, &anc),
            &old,
            None,
            None,
        ));
    }

    #[test]
    fn a5_removed_write_refused() {
        let w = world();
        // Carol made writer, then removed; she signs under the old body.
        let mut h1 = w.c.head.clone();
        let mut carol = person(Role::Write, ContactLevel::Verified, false);
        carol.member = {
            let mut m = w.c.carol.member.clone();
            m.role = Role::Write;
            m.level = ContactLevel::Verified;
            m
        };
        carol.key = HybridSigningKey::generate().unwrap();
        carol.member.sign_pub = carol.key.verifying_key().unwrap();
        for m in &mut h1.members {
            if m.account_id == carol.member.account_id {
                *m = carol.member.clone();
            }
        }
        let sm = sign(&w, &carol, &manifest(&w, &h1));
        let mut h2 = next_by(&h1, &w.c.alice, MembershipReason::Remove);
        remove(&mut h2, &carol, &w.c.alice);
        h2.generation = 2;
        h2.key_commit = [8; 32];
        let anc = [h1.clone()];
        validation(verify_shared_manifest(
            &w.vault,
            &view(&h2, &anc),
            &sm,
            None,
            None,
        ));
        // Pointing at the head that removed her: not a member.
        let sm = sign(&w, &carol, &manifest(&w, &h2));
        validation(verify_shared_manifest(
            &w.vault,
            &view(&h2, &anc),
            &sm,
            None,
            None,
        ));
    }

    #[test]
    fn generation_must_match_pointer() {
        let w = world();
        let m = Manifest::next(None, w.vault.id, Vec::new())
            .unwrap()
            .with_membership(w.c.head.seen(), w.c.head.generation + 1);
        let sm = sign(&w, &w.c.bob, &m);
        let r = verify_shared_manifest(&w.vault, &view(&w.c.head, &[]), &sm, None, None);
        assert!(
            matches!(r, Err(Error::Integrity(IntegrityError::WrongContext))),
            "{r:?}"
        );
    }

    #[test]
    fn unknown_pointer_set_aside() {
        let w = world();
        let ahead = next_by(&w.c.head, &w.c.alice, MembershipReason::Meta);
        let sm = sign(&w, &w.c.bob, &manifest(&w, &ahead));
        let r = verify_shared_manifest(&w.vault, &view(&w.c.head, &[]), &sm, None, None);
        assert!(matches!(r, Err(Error::NotFound)), "{r:?}");
    }

    #[test]
    fn a8_membership_fork_detected() {
        let w = world();
        let mut other = w.c.head.clone();
        other.issued_at += 1;
        let sm = sign(&w, &w.c.bob, &manifest(&w, &other));
        let r = verify_shared_manifest(&w.vault, &view(&w.c.head, &[]), &sm, None, None);
        assert!(
            matches!(r, Err(Error::Integrity(IntegrityError::MembershipFork))),
            "{r:?}"
        );
    }

    #[test]
    fn shared_manifest_rollback_refused() {
        let w = world();
        let m1 = manifest(&w, &w.c.head);
        let m2 = Manifest::next(Some(&m1), w.vault.id, Vec::new())
            .unwrap()
            .with_membership(w.c.head.seen(), w.c.head.generation);
        let s1 = sign(&w, &w.c.bob, &m1);
        let seen = SeenManifest {
            seq: m2.seq,
            hash: manifest_hash(&m2),
        };
        let r = verify_shared_manifest(&w.vault, &view(&w.c.head, &[]), &s1, Some(&seen), None);
        assert!(
            matches!(r, Err(Error::Integrity(IntegrityError::ManifestRollback))),
            "{r:?}"
        );
    }
}

// ------------------------------------------------------------ local share state

mod state {
    use super::*;
    use onepass_core::share::{MEMBERSHIP_HISTORY, PendingIdentity, ShareState};
    use onepass_core::store::{MemoryStore, Record, RecordKind, RecordStore, Zone};
    use onepass_core::sync::SyncStore;

    fn state() -> ShareState {
        let c = cast();
        let mut s = ShareState::new(Zone::Vault(c.head.vault_id), c.head.clone());
        s.retired_signers.insert(c.bob.member.member_ref(), 3);
        s.identity_pending = Some(PendingIdentity {
            new_identity: c.alice.member.member_ref(),
            since: 9,
        });
        s
    }

    #[test]
    fn share_state_strict_decode() {
        let s = state();
        let b = s.encode();
        assert_eq!(ShareState::decode(&b).unwrap(), s);
        let mut longer = b.clone();
        longer.push(0);
        assert!(ShareState::decode(&longer).is_err());
        let mut v = s.clone();
        v.version = 2;
        assert!(ShareState::decode(&v.encode()).is_err());
        let mut private = s.clone();
        private.zone = Zone::Private;
        assert!(ShareState::decode(&private.encode()).is_err());
        let mut other = s.clone();
        other.vault_id = Id::new();
        assert!(ShareState::decode(&other.encode()).is_err());
        // An ancestor newer than the head.
        let mut bad = s.clone();
        let mut newer = s.head.clone();
        newer.seq = 5;
        bad.ancestors.push(newer);
        assert!(ShareState::decode(&bad.encode()).is_err());
    }

    #[test]
    fn ancestors_capped_at_64() {
        let mut s = state();
        let alice = MemberRef {
            account_id: s.head.members[0].account_id,
            identity_id: s.head.members[0].identity_id,
        };
        for i in 0..(MEMBERSHIP_HISTORY + 10) {
            let next = s
                .head
                .next(alice, MembershipReason::Meta, 2000 + i as i64)
                .unwrap();
            s.advance(next);
        }
        assert_eq!(s.ancestors.len(), MEMBERSHIP_HISTORY);
        assert_eq!(s.ancestors[0].seq, s.head.seq - 1);
        assert_eq!(ShareState::decode(&s.encode()).unwrap(), s);
        let mut over = s.clone();
        over.ancestors.push({
            let mut b = s.head.clone();
            b.seq = 0;
            b
        });
        assert!(ShareState::decode(&over.encode()).is_err());
    }

    fn stores() -> Vec<Box<dyn RecordStore>> {
        vec![
            Box::new(MemoryStore::new()),
            Box::new(SyncStore::open_in_memory().unwrap()),
        ]
    }

    #[test]
    fn share_state_written_with_records() {
        let s = state();
        let zone = s.zone;
        let id = Id::new();
        for mut st in stores() {
            let rec = |v: u64, d: &[u8]| Record {
                kind: RecordKind::Item,
                id,
                version: v,
                data: d.to_vec(),
            };
            st.put_all_zoned(vec![(zone, rec(1, b"a"), None)], vec![], None, &[])
                .unwrap();
            // A conditional write that fails: neither record nor state.
            let r = st.put_all_zoned(
                vec![(zone, rec(2, b"b"), Some(7))],
                vec![],
                None,
                std::slice::from_ref(&s),
            );
            assert!(matches!(r, Err(Error::Conflict)));
            assert_eq!(st.share_state(s.vault_id).unwrap(), None);
            st.put_all_zoned(
                vec![(zone, rec(2, b"b"), Some(1))],
                vec![],
                None,
                std::slice::from_ref(&s),
            )
            .unwrap();
            assert_eq!(st.share_state(s.vault_id).unwrap(), Some(s.clone()));
            assert_eq!(st.share_states().unwrap(), vec![s.clone()]);
            // Dropping the zone forgets the state too.
            st.drop_zone(zone).unwrap();
            assert_eq!(st.share_state(s.vault_id).unwrap(), None);
        }
    }

    #[test]
    fn share_state_never_pushed() {
        let s = state();
        let mut st = SyncStore::open_in_memory().unwrap();
        st.put_all_zoned(vec![], vec![], None, std::slice::from_ref(&s))
            .unwrap();
        assert!(st.pending_changes().unwrap().is_empty());
        assert!(st.pending_changes_in(s.zone).unwrap().is_empty());
        assert!(st.zones().unwrap().is_empty());
    }
}
