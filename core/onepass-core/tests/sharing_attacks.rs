//! Sharing attack regressions (sharing spec 16, plan 2 Task 16): one test
//! per covered line of the catalogue, end to end through the public API,
//! with two to four accounts and one fake server per zone. A9, A10, A18
//! and A22 belong to plan 3; A14 is documented only.

mod common;
mod share_accts;
mod share_common;

use common::*;
use onepass_core::contact::{ContactLevel, pair_id};
use onepass_core::crypto::SymmetricKey;
use onepass_core::lineage::rotation_code;
use onepass_core::repo::members::AdoptionProof;
use onepass_core::share::{
    AccessTarget, MemberKey, MembershipReason, Role, SignedMembership, ZoneSeed, member_key_id,
    sign_membership, wrap_member_key,
};
use onepass_core::store::{RecordStore, Zone};
use onepass_core::{Error, IntegrityError};
use share_accts::settle;
use share_accts::*;
use share_common::*;

/// The server takes `dev`'s unsent rows of `zone` as they are, without
/// the conditional write (a server helping a stale or hostile member).
fn replay_pending(zs: &mut Zones, dev: &Device, zone: Zone) -> usize {
    let changes = dev.store().pending_changes_in(zone).unwrap();
    let n = changes.len();
    for c in changes {
        match c.data {
            Some(data) => zs.server(zone).replay(Record {
                kind: c.kind,
                id: c.id,
                version: c.version,
                data,
            }),
            None => zs.server(zone).forge_deletion(c.kind, c.id),
        }
    }
    n
}

/// What `dev` reads of shared vault `id`: the user names, or the refusal.
fn read_users(dev: &mut Device, id: Id) -> Result<Vec<String>> {
    dev.repo().shared_vaults()?;
    let v = dev
        .repo()
        .vaults()?
        .into_iter()
        .find(|v| v.id == id)
        .ok_or(Error::NotFound)?;
    Ok(users(&dev.repo().items(&v)?))
}

#[test]
fn a1_server_key_never_used() {
    let (mut zs, mut a, mut b, id, _) = alice_and_bob(ContactLevel::Verified);
    let mut carol = Acct::new();
    let carol_id = account_id(&mut carol.dev);
    // The server drops Carol's card in the contact zone of Alice and Bob.
    let card = carol.dev.repo().own_contact_card("Carol", NOW).unwrap();
    let zone = Zone::Contact(pair_id(account_id(&mut a.dev), account_id(&mut b.dev)));
    a.dev
        .store()
        .put_all_zoned(
            vec![(
                zone,
                Record {
                    kind: RecordKind::ShareInvite,
                    id: Id([3; 16]),
                    version: 1,
                    data: postcard::to_allocvec(&card).unwrap(),
                },
                None,
            )],
            vec![],
            None,
            &[],
        )
        .unwrap();
    let e = a
        .dev
        .repo()
        .add_member(id, carol_id, Role::Read, NOW + 1)
        .unwrap_err();
    assert_eq!(validation(e), ("contact".into(), "unknown"));
    let info = a.dev.repo().shared_vaults().unwrap();
    assert!(info[0].members.iter().all(|m| m.account_id != carol_id));
    let carol_sign = carol.dev.repo().account().params.signing_pub.clone();
    let st = a.dev.store();
    let head = SignedMembership::decode(
        &st.get_in(Zone::Vault(id), RecordKind::Membership, id)
            .unwrap()
            .unwrap()
            .data,
    )
    .unwrap()
    .body;
    assert!(head.members.iter().all(|m| m.sign_pub != carol_sign));
    let _ = &mut zs;
}

#[test]
fn a4_removed_reads_nothing_new() {
    let (mut zs, mut a, mut b, mut c, id, _) = trio(Role::Read);
    let carol_old = shared(&mut c.dev, id);
    let carol = account_id(&mut c.dev);
    let carol_ref = me(&mut c.dev);
    let out = a.dev.repo().remove_member(id, carol, NOW + 3).unwrap();
    assert_eq!(out.generation, 2);
    settle(&mut zs, &mut [&mut a, &mut b]);
    assert_eq!(push_phase(&a.dev, id), None);
    let va = shared(&mut a.dev, id);
    a.dev.repo().save_item(&va, login(id, "dave", 700)).unwrap();
    settle(&mut zs, &mut [&mut a, &mut b]);
    // No row on the server opens with Carol's old key.
    assert!(item_rows_on_server(&mut zs, id) > 0);
    assert!(opened_on_server(&mut zs, &carol_old).is_empty());
    // No envelope of generation 2 for Carol.
    let mk = member_key_id(id, 2, &carol_ref);
    assert!(
        zs.server(Zone::Vault(id))
            .live(RecordKind::MemberKey, mk)
            .is_none()
    );
    // Bob reads everything at generation 2.
    let vb = shared(&mut b.dev, id);
    assert!(users(&b.dev.repo().items(&vb).unwrap()).contains(&"dave".to_string()));
}

#[test]
fn a11_forged_member_rotation_not_adopted() {
    let (mut zs, mut a, _b, mut c, id, child) = carol_rotated(Role::Read);
    let carol = account_id(&mut c.dev);
    a.dev.repo().refresh_member_identities(NOW + 5).unwrap();
    let code = rotation_code(&child);
    let e = a
        .dev
        .repo()
        .adopt_member_identity(
            carol,
            child,
            AdoptionProof::Code((code + 1) % 1_000_000),
            NOW + 6,
        )
        .unwrap_err();
    assert_eq!(validation(e), ("code".into(), "wrong code"));
    // A head the records do not lead to is refused too.
    let e = a
        .dev
        .repo()
        .adopt_member_identity(carol, [9; 32], AdoptionProof::Code(code), NOW + 6)
        .unwrap_err();
    assert!(matches!(e, Error::NotFound | Error::Validation(_)));
    a.sync(&mut zs);
    let new = me(&mut c.dev);
    let g = generation(&a.dev, id);
    assert!(
        zs.server(Zone::Vault(id))
            .live(RecordKind::MemberKey, member_key_id(id, g, &new))
            .map(|e| e.record.is_some())
            .unwrap_or(false),
        "Carol's own envelope for her new identity is on the server"
    );
    assert_ne!(
        a.dev
            .store()
            .share_state(id)
            .unwrap()
            .unwrap()
            .head
            .member(carol)
            .unwrap()
            .identity_id,
        new.identity_id
    );
}

/// A manager Bob holds only at `Link` may give him a `Read` place, on
/// every device, never a place where Bob writes (decision 1, A13).
#[test]
fn a13_link_level_cannot_manage() {
    let (mut zs, mut a, mut b, id, _) =
        alice_and_bob_seen(ContactLevel::Verified, ContactLevel::Link);
    let bob = account_id(&mut b.dev);
    let mut b2 = Device::empty();
    pull(&b.server, &mut b2);
    b2.unlock(&b.sk);
    a.dev
        .repo()
        .add_member(id, bob, Role::Write, NOW + 1)
        .unwrap();
    settle(&mut zs, &mut [&mut a, &mut b]);
    assert!(b.dev.repo().share_invites().unwrap().is_empty());
    // The head names Bob a writer: no device of his joins from it.
    b.sync(&mut zs);
    zsync(&mut b.server, &mut zs, &mut b2);
    assert!(b2.repo().join_from_head(id, NOW + 2).is_err());

    let (mut zs, mut a, mut b, id, items) =
        alice_and_bob_seen(ContactLevel::Verified, ContactLevel::Link);
    let bob = account_id(&mut b.dev);
    let mut b2 = Device::empty();
    pull(&b.server, &mut b2);
    b2.unlock(&b.sk);
    a.dev
        .repo()
        .add_member(id, bob, Role::Read, NOW + 1)
        .unwrap();
    settle(&mut zs, &mut [&mut a, &mut b]);
    let inv = b.dev.repo().share_invites().unwrap()[0].id;
    let joined = b.dev.repo().accept_share_invite(inv, NOW + 2).unwrap();
    assert_eq!(joined.role, Role::Read);
    b.sync(&mut zs);
    zsync(&mut b.server, &mut zs, &mut b2);
    zsync(&mut b.server, &mut zs, &mut b2);
    let info = b2.repo().join_from_head(id, NOW + 3).unwrap();
    assert_eq!(info.role, Role::Read);
    let v = shared(&mut b2, id);
    assert_eq!(ids(&b2.repo().items(&v).unwrap()), ids(&items));
}

#[test]
fn a17_participant_without_envelope() {
    let (mut zs, mut a, mut b, id, _) = alice_and_bob(ContactLevel::Verified);
    let bob = account_id(&mut b.dev);
    a.dev
        .repo()
        .add_member(id, bob, Role::Write, NOW + 1)
        .unwrap();
    a.sync(&mut zs);
    // Mallory learned the zone's home and holds a credential of the
    // mailbox: she reads every record of the zone.
    let mut mallory = Acct::new();
    let zone = Zone::Vault(id);
    mallory
        .dev
        .repo()
        .test_write_zone_access(
            AccessTarget::Zone(zone),
            Some(home(1)),
            &ZoneSeed::generate().unwrap(),
        )
        .unwrap();
    mallory.sync(&mut zs);
    let st = mallory.dev.store();
    assert!(
        st.get_in(zone, RecordKind::Membership, id)
            .unwrap()
            .is_some()
    );
    let m = me(&mut mallory.dev);
    assert!(
        st.get_in(zone, RecordKind::MemberKey, member_key_id(id, 1, &m))
            .unwrap()
            .is_none()
    );
    for r in st.list_in(zone, RecordKind::MemberKey).unwrap() {
        assert_ne!(MemberKey::decode(&r.data).unwrap().member(), m);
    }
    drop(st);
    assert!(matches!(
        mallory.dev.repo().open_shared(id),
        Err(Error::NotFound)
    ));
    assert!(mallory.dev.repo().join_from_head(id, NOW).is_err());
    assert!(mallory.dev.repo().shared_vaults().unwrap().is_empty());
}

#[test]
fn a20_concurrent_managers() {
    for alice_first in [true, false] {
        let (mut zs, mut a, mut b, mut c, mut d, id) = two_managers(Role::Read);
        let carol = account_id(&mut c.dev);
        let carol_ref = me(&mut c.dev);
        let dan = account_id(&mut d.dev);
        a.dev.repo().remove_member(id, carol, NOW + 4).unwrap();
        b.dev
            .repo()
            .add_member(id, dan, Role::Read, NOW + 4)
            .unwrap();
        race(&mut zs, &mut a, &mut b, &mut c, alice_first);
        settle(&mut zs, &mut [&mut a, &mut b, &mut d]);
        let inv = d.dev.repo().share_invites().unwrap();
        assert_eq!(inv.len(), 1, "alice_first={alice_first}");
        d.dev
            .repo()
            .accept_share_invite(inv[0].id, NOW + 5)
            .unwrap();
        settle(&mut zs, &mut [&mut a, &mut b, &mut d]);
        assert_eq!(head_hash(&mut a.dev, id), head_hash(&mut b.dev, id));
        assert_eq!(head_hash(&mut a.dev, id), head_hash(&mut d.dev, id));
        assert_eq!(role_of(&mut a.dev, id, carol), None);
        assert_eq!(role_of(&mut a.dev, id, dan), Some(Role::Read));
        let g = generation(&a.dev, id);
        assert!(g >= 2, "generation {g}");
        let dan_ref = me(&mut d.dev);
        let server = zs.server(Zone::Vault(id));
        assert!(
            server
                .live(RecordKind::MemberKey, member_key_id(id, g, &dan_ref))
                .is_some()
        );
        assert!(
            server
                .live(RecordKind::MemberKey, member_key_id(id, g, &carol_ref))
                .is_none()
        );
        // Dan reads the vault at the final generation.
        let vd = shared(&mut d.dev, id);
        assert!(!d.dev.repo().items(&vd).unwrap().is_empty());
    }
}

#[test]
fn a2_injected_member_refused() {
    let (mut zs, mut a, mut b, mut c, id, _) = trio(Role::Read);
    let mut m = Acct::new();
    let mallory = account_id(&mut m.dev);
    let head = head_of(&a.dev, id);
    let mut intruder = member_of(&mut m.dev, Role::Write, ContactLevel::Verified, 9);
    // Signed by an outsider, then by Bob (a writer, not a manager).
    for by_bob in [false, true] {
        let signer = if by_bob { &mut b.dev } else { &mut m.dev };
        let mut body = head
            .next(me(signer), MembershipReason::Add, NOW + 5)
            .unwrap();
        intruder.added_by = body.signer;
        body.members.push(intruder.clone());
        body.members.sort_by_key(|x| x.account_id);
        let signed = sign_membership(body, &signer.repo().account().keyset().signing).unwrap();
        zs.server(Zone::Vault(id)).replay(Record {
            kind: RecordKind::Membership,
            id,
            version: head.seq + 1,
            data: signed.encode(),
        });
        settle(&mut zs, &mut [&mut a, &mut b, &mut c]);
        for x in [&mut a, &mut b, &mut c] {
            let h = head_of(&x.dev, id);
            assert_eq!(h.seq, head.seq);
            assert!(h.member(mallory).is_none());
        }
    }
    // Nothing was wrapped for Mallory.
    let mk = member_key_id(id, head.generation, &me(&mut m.dev));
    assert!(
        zs.server(Zone::Vault(id))
            .live(RecordKind::MemberKey, mk)
            .is_none()
    );
}

#[test]
fn a3_membership_rollback() {
    let (mut zs, mut a, mut b, mut c, id, _) = trio(Role::Read);
    let carol = account_id(&mut c.dev);
    let carol_ref = me(&mut c.dev);
    let zone = Zone::Vault(id);
    let before = zs.server(zone).get(RecordKind::Membership, id).unwrap();
    a.dev.repo().remove_member(id, carol, NOW + 3).unwrap();
    settle(&mut zs, &mut [&mut a, &mut b]);
    let after = head_of(&a.dev, id);
    assert_eq!(after.generation, 2);
    // The server serves the list from before the removal, as it was, then
    // with a version above the head.
    for version in [before.version, after.seq + 1] {
        zs.server(zone).replay(Record {
            version,
            ..before.clone()
        });
        settle(&mut zs, &mut [&mut a, &mut b]);
        for x in [&mut a, &mut b] {
            let h = head_of(&x.dev, id);
            assert_eq!(h.seq, after.seq);
            assert!(h.member(carol).is_none());
        }
        // A manager's next change wraps nothing for Carol.
        let va = shared(&mut a.dev, id);
        a.dev
            .repo()
            .save_item(&va, login(id, "dave", 700 + version as i64))
            .unwrap();
        settle(&mut zs, &mut [&mut a, &mut b]);
        for g in 2..=head_of(&a.dev, id).generation {
            assert!(
                zs.server(zone)
                    .live(RecordKind::MemberKey, member_key_id(id, g, &carol_ref))
                    .is_none()
            );
        }
    }
}

#[test]
fn a5_removed_write_refused() {
    let (mut zs, mut a, mut b, mut c, id, _) = trio(Role::Write);
    let carol = account_id(&mut c.dev);
    let zone = Zone::Vault(id);
    a.dev.repo().remove_member(id, carol, NOW + 3).unwrap();
    settle(&mut zs, &mut [&mut a, &mut b]);
    // Carol's device has not seen her removal: it writes, and the server
    // takes the rows as they are.
    let vc = shared(&mut c.dev, id);
    c.dev
        .repo()
        .save_item(&vc, login(id, "mallet", 900))
        .unwrap();
    assert!(replay_pending(&mut zs, &c.dev, zone) > 0);
    settle(&mut zs, &mut [&mut a, &mut b]);
    for x in [&mut a, &mut b] {
        // The manifest Carol signed is refused: nothing of hers is read.
        let e = read_users(&mut x.dev, id).unwrap_err();
        assert!(
            matches!(e, Error::Validation(_) | Error::Integrity(_)),
            "{e:?}"
        );
    }
}

#[test]
fn a6_reader_manifest_refused() {
    let (mut zs, mut a, mut b, mut c, id, _) = trio(Role::Write);
    let carol = account_id(&mut c.dev);
    let zone = Zone::Vault(id);
    // A reader cannot write through the API.
    a.dev
        .repo()
        .set_role(id, carol, Role::Read, NOW + 3)
        .unwrap();
    settle(&mut zs, &mut [&mut a, &mut b]);
    let vc = shared(&mut c.dev, id);
    // Carol's device still holds her as a writer: it writes, the server
    // takes the rows.
    c.dev
        .repo()
        .save_item(&vc, login(id, "mallet", 900))
        .unwrap();
    assert!(replay_pending(&mut zs, &c.dev, zone) > 0);
    settle(&mut zs, &mut [&mut a, &mut b]);
    for x in [&mut a, &mut b] {
        let e = read_users(&mut x.dev, id).unwrap_err();
        assert_eq!(
            validation(e),
            ("signer".into(), "role changed since the named body")
        );
    }
    // Once she follows the head, her unsent write goes to a personal copy
    // and her own device refuses to write.
    settle(&mut zs, &mut [&mut c]);
    let copy = c
        .dev
        .repo()
        .vaults()
        .unwrap()
        .into_iter()
        .find(|v| v.meta.name == "Copie de Famille")
        .expect("personal copy");
    assert_eq!(users(&c.dev.repo().items(&copy).unwrap()), vec!["mallet"]);
    let vc = shared(&mut c.dev, id);
    assert!(
        c.dev
            .repo()
            .save_item(&vc, login(id, "again", 901))
            .is_err()
    );
}

#[test]
fn a7_writer_meta_refused() {
    let (mut zs, mut a, mut b, mut c, id, _) = trio(Role::Write);
    let vb = shared(&mut b.dev, id);
    let mut meta = vb.meta.clone();
    meta.name = "Mallory".into();
    let e = b.dev.repo().update_vault_meta(&vb, meta).unwrap_err();
    assert!(matches!(e, Error::Validation(_)), "{e:?}");
    settle(&mut zs, &mut [&mut a, &mut b, &mut c]);
    for x in [&mut a, &mut b, &mut c] {
        assert_eq!(shared(&mut x.dev, id).meta.name, "Famille");
    }
    // A manager may.
    let va = shared(&mut a.dev, id);
    let mut meta = va.meta.clone();
    meta.name = "Maison".into();
    a.dev.repo().update_vault_meta(&va, meta).unwrap();
    settle(&mut zs, &mut [&mut a, &mut b, &mut c]);
    assert_eq!(shared(&mut c.dev, id).meta.name, "Maison");
}

#[test]
fn a8_membership_fork_detected() {
    let (zs, mut a, mut b, mut c, mut d, id) = two_managers(Role::Read);
    let dan = account_id(&mut d.dev);
    let carol = account_id(&mut c.dev);
    let zone = Zone::Vault(id);
    // The server splits the zone in two: Alice and Carol on one side, Bob
    // on the other. Each manager signs the next body.
    let mut left = zs.clone();
    let mut right = zs;
    a.dev
        .repo()
        .set_role(id, carol, Role::Write, NOW + 4)
        .unwrap();
    settle(&mut left, &mut [&mut a, &mut c]);
    b.dev
        .repo()
        .add_member(id, dan, Role::Write, NOW + 4)
        .unwrap();
    settle(&mut right, &mut [&mut b]);
    // Bob writes under his branch; the server shows his manifest and item
    // rows to Carol, next to Alice's branch.
    let vb = shared(&mut b.dev, id);
    b.dev.repo().save_item(&vb, login(id, "fork", 950)).unwrap();
    assert!(replay_pending(&mut right, &b.dev, zone) > 0);
    right
        .server(zone)
        .records
        .retain(|(k, _), _| *k != RecordKind::Membership);
    for ((k, i), e) in right.server(zone).records.clone() {
        if let Some(r) = e.record
            && k != RecordKind::Membership
        {
            left.server(zone).replay(Record {
                kind: k,
                id: i,
                ..r
            });
        }
    }
    settle(&mut left, &mut [&mut c]);
    let e = read_users(&mut c.dev, id).unwrap_err();
    assert!(
        matches!(e, Error::Integrity(IntegrityError::MembershipFork)),
        "{e:?}"
    );
}

#[test]
fn a12_revoked_device_after_rekey() {
    let (mut zs, mut a, mut b, mut c, id, _) = trio_spare(Role::Write);
    let carol_old = shared(&mut c.dev, id);
    let g = head_of(&a.dev, id).generation;
    // Carol rotates and revokes her other device; that device keeps the
    // vault key of generation g.
    c.rotate(true);
    settle(&mut zs, &mut [&mut a, &mut b, &mut c]);
    a.dev.repo().process_rekey_requests(NOW + 6).unwrap();
    settle(&mut zs, &mut [&mut a, &mut b, &mut c]);
    assert!(head_of(&a.dev, id).generation > g);
    let va = shared(&mut a.dev, id);
    a.dev.repo().save_item(&va, login(id, "dave", 700)).unwrap();
    settle(&mut zs, &mut [&mut a, &mut b]);
    assert!(item_rows_on_server(&mut zs, id) > 0);
    assert!(!users(&opened_on_server(&mut zs, &carol_old)).contains(&"dave".to_string()));
    assert!(
        read_users(&mut b.dev, id)
            .unwrap()
            .contains(&"dave".to_string())
    );
}

#[test]
fn a15_substituted_envelope() {
    let (mut zs, mut a, mut b, id, _) = alice_and_bob(ContactLevel::Verified);
    let bob = account_id(&mut b.dev);
    let bob_ref = me(&mut b.dev);
    a.dev
        .repo()
        .add_member(id, bob, Role::Write, NOW + 1)
        .unwrap();
    settle(&mut zs, &mut [&mut a, &mut b]);
    // The server wraps a key of its own for Bob, in the right context.
    let kem = b.dev.repo().account().params.kem_pub.clone();
    let g = head_of(&a.dev, id).generation;
    let fake = wrap_member_key(&kem, &SymmetricKey::generate().unwrap(), id, g, &bob_ref).unwrap();
    zs.server(Zone::Vault(id)).replay(Record {
        kind: RecordKind::MemberKey,
        id: fake.id(),
        version: 1,
        data: fake.encode(),
    });
    settle(&mut zs, &mut [&mut b]);
    let inv = b.dev.repo().share_invites().unwrap()[0].id;
    let joined = b.dev.repo().accept_share_invite(inv, NOW + 2);
    if let Err(e) = &joined {
        assert!(
            matches!(e, Error::Integrity(IntegrityError::Commitment)),
            "{e:?}"
        );
    }
    // Bob never opens the vault with the server's key.
    let e = read_users(&mut b.dev, id).unwrap_err();
    assert!(matches!(e, Error::NotFound), "{e:?}");
}

#[test]
fn a16_envelope_context() {
    let (mut zs, mut a, mut b, mut c, id, _) = trio(Role::Read);
    let carol = account_id(&mut c.dev);
    let bob_ref = me(&mut b.dev);
    let zone = Zone::Vault(id);
    let g1 = zs
        .server(zone)
        .get(RecordKind::MemberKey, member_key_id(id, 1, &bob_ref))
        .unwrap();
    a.dev.repo().remove_member(id, carol, NOW + 3).unwrap();
    settle(&mut zs, &mut [&mut a]);
    let va = shared(&mut a.dev, id);
    a.dev.repo().save_item(&va, login(id, "dave", 700)).unwrap();
    settle(&mut zs, &mut [&mut a]);
    // The server serves Bob's envelope of generation 1 under the id of
    // his generation 2 envelope.
    let g2 = member_key_id(id, 2, &bob_ref);
    assert!(zs.server(zone).live(RecordKind::MemberKey, g2).is_some());
    zs.server(zone).replay(Record {
        id: g2,
        version: 2,
        ..g1.clone()
    });
    assert_eq!(MemberKey::decode(&g1.data).unwrap().generation, 1);
    settle(&mut zs, &mut [&mut b]);
    // The envelope does not open at generation 2: the vault is not
    // offered to Bob, nothing of generation 2 is read.
    let e = read_users(&mut b.dev, id).unwrap_err();
    assert!(matches!(e, Error::NotFound), "{e:?}");
}

#[test]
fn a19_record_deletion_detected() {
    let (mut zs, mut a, mut b, mut c, id, _) = trio(Role::Write);
    let zone = Zone::Vault(id);
    // Bob, a writer, deletes an item row of the zone without the manifest.
    let row = zs
        .server(zone)
        .records
        .iter()
        .find(|((k, _), e)| *k == RecordKind::Item && e.record.is_some())
        .map(|((_, i), _)| *i)
        .unwrap();
    zs.server(zone).forge_deletion(RecordKind::Item, row);
    settle(&mut zs, &mut [&mut a, &mut b, &mut c]);
    let e = read_users(&mut c.dev, id).unwrap_err();
    assert!(
        matches!(e, Error::Integrity(IntegrityError::ManifestMissingItem)),
        "{e:?}"
    );
}

#[test]
fn a21_domain_separation() {
    // Alice's "Famille" while personal: its manifest on her own server.
    let mut zs = Zones::default();
    let (dev, sk, fam, _) = with_family();
    let mut a = Acct::of(dev, sk);
    let personal = a.server.get(RecordKind::Manifest, fam.id).unwrap();
    let mut b = Acct::new();
    pin(&mut a.dev, &mut b.dev, ContactLevel::Verified);
    pin(&mut b.dev, &mut a.dev, ContactLevel::Verified);
    contact_zone(&mut a.dev, &mut b.dev);
    a.dev.repo().share_vault(&fam, NOW).unwrap();
    a.dev
        .repo()
        .set_zone_home(AccessTarget::Zone(Zone::Vault(fam.id)), home(1))
        .unwrap();
    let bob = account_id(&mut b.dev);
    a.dev
        .repo()
        .add_member(fam.id, bob, Role::Write, NOW + 1)
        .unwrap();
    settle(&mut zs, &mut [&mut a, &mut b]);
    let inv = b.dev.repo().share_invites().unwrap()[0].id;
    b.dev.repo().accept_share_invite(inv, NOW + 2).unwrap();
    settle(&mut zs, &mut [&mut a, &mut b]);
    // The server serves that personal manifest as the shared one.
    let zone = Zone::Vault(fam.id);
    let shared_row = zs.server(zone).get(RecordKind::Manifest, fam.id).unwrap();
    zs.server(zone).replay(Record {
        version: shared_row.version + 1,
        ..personal
    });
    settle(&mut zs, &mut [&mut b]);
    let e = read_users(&mut b.dev, fam.id).unwrap_err();
    assert!(
        matches!(e, Error::Integrity(_) | Error::InvalidFormat(_)),
        "{e:?}"
    );
}

#[test]
fn rotation_during_removal() {
    let (mut zs, mut a, mut b, mut c, _d, id) = two_managers(Role::Read);
    let alice = account_id(&mut a.dev);
    let carol = account_id(&mut c.dev);
    let carol_ref = me(&mut c.dev);
    let carol_old = shared(&mut c.dev, id);
    let g = head_of(&b.dev, id).generation;
    // Alice rotates while Bob removes Carol, neither seeing the other.
    a.rotate(false);
    let child = a.dev.store().trust_state().unwrap().unwrap().head.hash;
    b.dev.repo().remove_member(id, carol, NOW + 4).unwrap();
    settle(&mut zs, &mut [&mut a, &mut b, &mut c]);
    let head = head_of(&b.dev, id);
    assert!(head.member(carol).is_none());
    assert!(head.generation > g);
    // Bob confirms Alice's new keys face to face.
    b.dev.repo().refresh_member_identities(NOW + 6).unwrap();
    repin_in_person(&mut b.dev, &mut a.dev);
    b.dev
        .repo()
        .adopt_member_identity(
            alice,
            child,
            AdoptionProof::InPerson {
                transcript_hash: [1; 32],
            },
            NOW + 7,
        )
        .unwrap();
    settle(&mut zs, &mut [&mut a, &mut b]);
    let vb = shared(&mut b.dev, id);
    b.dev.repo().save_item(&vb, login(id, "dave", 700)).unwrap();
    settle(&mut zs, &mut [&mut a, &mut b]);
    // Alice reads the new generation under her new identity.
    assert!(
        read_users(&mut a.dev, id)
            .unwrap()
            .contains(&"dave".to_string())
    );
    // Carol has nothing of it.
    let last = head_of(&b.dev, id).generation;
    for gen_ in (g + 1)..=last {
        assert!(
            zs.server(Zone::Vault(id))
                .live(RecordKind::MemberKey, member_key_id(id, gen_, &carol_ref))
                .is_none()
        );
    }
    assert!(!users(&opened_on_server(&mut zs, &carol_old)).contains(&"dave".to_string()));
}

/// `trio`, Carol with a spare roster device a rotation can revoke.
fn trio_spare(carol_role: Role) -> (Zones, Acct, Acct, Acct, Id, Vec<Item>) {
    let (mut zs, mut a, mut b, id, items) = alice_and_bob(ContactLevel::Verified);
    let (dev, sk) = Device::create();
    let mut c = Acct::of_with(dev, sk, true);
    pin(&mut a.dev, &mut c.dev, ContactLevel::Verified);
    pin(&mut c.dev, &mut a.dev, ContactLevel::Verified);
    contact_zone(&mut a.dev, &mut c.dev);
    let bob = account_id(&mut b.dev);
    let carol = account_id(&mut c.dev);
    a.dev
        .repo()
        .add_member(id, bob, Role::Write, NOW + 1)
        .unwrap();
    a.dev
        .repo()
        .add_member(id, carol, carol_role, NOW + 1)
        .unwrap();
    settle(&mut zs, &mut [&mut a, &mut b, &mut c]);
    for x in [&mut b, &mut c] {
        let inv = x.dev.repo().share_invites().unwrap()[0].id;
        x.dev.repo().accept_share_invite(inv, NOW + 2).unwrap();
    }
    settle(&mut zs, &mut [&mut a, &mut b, &mut c]);
    (zs, a, b, c, id, items)
}
