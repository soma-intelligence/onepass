//! Zone mailboxes, zone accesses and member credentials (sharing plan 2,
//! Task 5b).

mod common;

use common::*;
use onepass_core::account::Keyset;
use onepass_core::crypto::{HybridKemSecret, HybridSigningKey, IdentityKey};
use onepass_core::repo::share::list_zone_accesses;
use onepass_core::share::{
    AccessTarget, ContactZoneOffer, MemberRef, Role, SignedContactZoneOffer, SignedZoneAccess,
    ZONE_ACCESS_KIND, ZoneHome, ZoneRole, ZoneSeed, open_zone_credential, server_role,
    verify_contact_zone_offer, wrap_zone_credential,
};
use onepass_core::store::Zone;

fn home(url: &str) -> ZoneHome {
    ZoneHome {
        url: url.into(),
        mailbox_id: [5; 16],
        extra_ca_pem: None,
    }
}

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
fn zone_home_strict() {
    let ok = home("https://mailbox.example/x");
    assert_eq!(ZoneHome::decode(&ok.encode()).unwrap(), ok);
    assert_eq!(ok.host(), "mailbox.example");
    let long = format!("https://{}", "a".repeat(257 - 8));
    assert_eq!(long.len(), 257);
    let mut pem = home("https://m.example");
    pem.extra_ca_pem = Some("p".repeat(8 * 1024 + 1));
    for bad in [home("http://m.example"), home(&long), pem] {
        assert!(matches!(
            ZoneHome::decode(&bad.encode()),
            Err(Error::InvalidFormat(_))
        ));
    }
    let max = format!("https://{}", "a".repeat(256 - 8));
    ZoneHome::decode(&home(&max).encode()).unwrap();
    let mut longer = ok.encode();
    longer.push(0);
    assert!(ZoneHome::decode(&longer).is_err());
}

#[test]
fn server_role_table() {
    let (r, kinds) = server_role(Role::Read);
    assert_eq!(r, ZoneRole::Write);
    let kinds = kinds.unwrap();
    let codes = [
        RecordKind::Membership.code(),
        RecordKind::MemberKey.code(),
        RecordKind::MemberLineage.code(),
        RecordKind::RekeyRequest.code(),
    ];
    assert_eq!(codes, [15, 16, 17, 18]);
    assert_eq!(kinds, onepass_mailbox_proto::put_kinds_of(&codes));
    for k in 0..=255u8 {
        assert_eq!(
            onepass_mailbox_proto::put_kinds_allow(&kinds, k),
            codes.contains(&k)
        );
    }
    assert_eq!(server_role(Role::Write), (ZoneRole::Write, None));
    assert_eq!(server_role(Role::Manage), (ZoneRole::Manage, None));
}

#[test]
fn credential_id_matches_mailbox_formula() {
    let seed = ZoneSeed::from_bytes([0x42; 32]);
    let pk = seed.public_key();
    assert_eq!(
        seed.credential_id(),
        onepass_mailbox_proto::credential_id(&pk)
    );
    // Frozen: the Ed25519 public key of 0x42 * 32 and its id.
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    assert_eq!(hex(&seed.credential_id()).len(), 32);
    let again = ZoneSeed::from_bytes([0x42; 32]);
    assert_eq!(again.public_key(), pk);
}

#[test]
fn zone_credential_round_trip() {
    let ks = keyset();
    let me = member();
    let zone = Zone::Vault(Id::new());
    let seed = ZoneSeed::generate().unwrap();
    let env = wrap_zone_credential(&ks.kem.public().unwrap(), &seed, zone, [1; 16], &me).unwrap();
    let got = open_zone_credential(&ks, &env, zone, [1; 16], &me).unwrap();
    assert_eq!(got.expose(), seed.expose());
}

#[test]
fn zone_credential_context_bound() {
    let ks = keyset();
    let me = member();
    let zone = Zone::Vault(Id::new());
    let seed = ZoneSeed::generate().unwrap();
    let env = wrap_zone_credential(&ks.kem.public().unwrap(), &seed, zone, [1; 16], &me).unwrap();
    assert!(open_zone_credential(&ks, &env, Zone::Vault(Id::new()), [1; 16], &me).is_err());
    assert!(open_zone_credential(&ks, &env, Zone::Contact(Id::new()), [1; 16], &me).is_err());
    assert!(open_zone_credential(&ks, &env, zone, [2; 16], &me).is_err());
    assert!(open_zone_credential(&ks, &env, zone, [1; 16], &member()).is_err());
    assert!(open_zone_credential(&keyset(), &env, zone, [1; 16], &me).is_err());
}

#[test]
fn zone_credential_opens_with_retired_kem() {
    let old = keyset();
    let me = member();
    let zone = Zone::Family(Id::new());
    let seed = ZoneSeed::generate().unwrap();
    let env = wrap_zone_credential(&old.kem.public().unwrap(), &seed, zone, [1; 16], &me).unwrap();
    let mut new = keyset();
    new.retired_kem.push(old.kem);
    let got = open_zone_credential(&new, &env, zone, [1; 16], &me).unwrap();
    assert_eq!(got.expose(), seed.expose());
}

fn vault_target() -> AccessTarget {
    AccessTarget::Zone(Zone::Vault(Id::new()))
}

#[test]
fn zone_access_signed_and_synced() {
    let mut server = Server::default();
    let (mut a, mut b, _, _) = setup(&mut server, &[]);
    let t = vault_target();
    let seed = ZoneSeed::generate().unwrap();
    // Written by A (through anchor and a zone access), read on B.
    let (_, anchor_seed) = a.repo().anchor().unwrap();
    a.repo()
        .test_write_zone_access(t, Some(home("https://m.example")), &seed)
        .unwrap();
    settle(&mut server, &mut [&mut a, &mut b], 10);
    let (acc, got) = b.repo().zone_access(t).unwrap().unwrap();
    assert_eq!(got.expose(), seed.expose());
    assert_eq!(acc.credential_id, seed.credential_id());
    assert_eq!(acc.home, Some(home("https://m.example")));
    let (h, again) = b.repo().anchor().unwrap();
    assert_eq!(h, None);
    assert_eq!(again.expose(), anchor_seed.expose());
    assert_eq!(b.repo().zone_accesses().unwrap().len(), 2);
}

#[test]
fn zone_access_forged_refused() {
    let (mut a, _) = Device::create();
    let me = a.repo().me();
    let t = vault_target();
    let seed = ZoneSeed::generate().unwrap();
    // Signed by another account's key, for my account id and KEM key.
    let other = keyset();
    let params = a.repo().account().params.clone();
    let forged = SignedZoneAccess::seal(
        me.account_id,
        &params.kem_pub,
        &other.signing,
        t,
        None,
        &seed,
    )
    .unwrap();
    let mut st = a.store();
    let put = |st: &mut SyncStore, data: Vec<u8>, v: Option<u64>| {
        st.put_all_zoned(
            vec![(
                Zone::Private,
                Record {
                    kind: ZONE_ACCESS_KIND,
                    id: t.record_id().unwrap(),
                    version: v.map_or(1, |v| v + 1),
                    data,
                },
                v,
            )],
            vec![],
            None,
            &[],
        )
        .unwrap()
    };
    put(&mut st, forged.encode(), None);
    assert!(matches!(
        a.repo().zone_access(t),
        Err(Error::Integrity(IntegrityError::Signature))
    ));
    assert!(a.repo().zone_accesses().unwrap().is_empty());
    // Signed by me, but the seed wrapped for another KEM key.
    let wrong_kem = SignedZoneAccess::seal(
        me.account_id,
        &other.kem.public().unwrap(),
        &a.repo().account().keyset().signing,
        t,
        None,
        &seed,
    )
    .unwrap();
    put(&mut st, wrong_kem.encode(), Some(1));
    assert!(a.repo().zone_access(t).is_err());
}

#[test]
fn zone_access_locked_lists_without_seed() {
    let (mut a, sk) = Device::create();
    let t = vault_target();
    let seed = ZoneSeed::generate().unwrap();
    a.repo()
        .test_write_zone_access(t, Some(home("https://m.example")), &seed)
        .unwrap();
    a.lock();
    let listed = list_zone_accesses(&a.store()).unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].target, t);
    assert_eq!(listed[0].credential_id, seed.credential_id());
    a.unlock(&sk);
    assert!(a.repo().zone_access(t).unwrap().is_some());
}

#[test]
fn home_set_once() {
    let (mut a, _) = Device::create();
    let t = vault_target();
    let seed = ZoneSeed::generate().unwrap();
    assert!(matches!(
        a.repo().set_zone_home(t, home("https://m.example")),
        Err(Error::NotFound)
    ));
    a.repo().test_write_zone_access(t, None, &seed).unwrap();
    assert!(a.repo().set_zone_home(t, home("http://m.example")).is_err());
    a.repo()
        .set_zone_home(t, home("https://m.example"))
        .unwrap();
    a.repo()
        .set_zone_home(t, home("https://m.example"))
        .unwrap();
    let r = a.repo().set_zone_home(t, home("https://other.example"));
    assert!(matches!(r, Err(Error::Validation(_))), "{r:?}");
    let (acc, s) = a.repo().zone_access(t).unwrap().unwrap();
    assert_eq!(acc.home, Some(home("https://m.example")));
    assert_eq!(s.expose(), seed.expose());
}

#[test]
fn anchor_created_once() {
    let (mut a, _) = Device::create();
    let (h, s1) = a.repo().anchor().unwrap();
    assert_eq!(h, None);
    let (_, s2) = a.repo().anchor().unwrap();
    assert_eq!(s1.expose(), s2.expose());
    assert_eq!(a.repo().zone_accesses().unwrap().len(), 1);
}

fn offer(creator: MemberRef, pair: Id) -> ContactZoneOffer {
    ContactZoneOffer {
        pair_id: pair,
        home: home("https://m.example"),
        creator,
        credential: vec![1, 2, 3],
    }
}

#[test]
fn contact_zone_offer_round_trip() {
    let ks = keyset();
    let creator = member();
    let me = member();
    let pair = Id::new();
    let s = SignedContactZoneOffer::sign(offer(creator, pair), &ks.signing).unwrap();
    let got =
        verify_contact_zone_offer(&s.encode(), &ks.signing.verifying_key().unwrap(), &me, pair)
            .unwrap();
    assert_eq!(got, offer(creator, pair));
    let mut longer = s.encode();
    longer.push(0);
    assert!(SignedContactZoneOffer::decode(&longer).is_err());
}

#[test]
fn contact_zone_offer_other_signer_refused() {
    let ks = keyset();
    let pair = Id::new();
    let s = SignedContactZoneOffer::sign(offer(member(), pair), &ks.signing).unwrap();
    let r = verify_contact_zone_offer(
        &s.encode(),
        &keyset().signing.verifying_key().unwrap(),
        &member(),
        pair,
    );
    assert!(
        matches!(r, Err(Error::Integrity(IntegrityError::Signature))),
        "{r:?}"
    );
}

#[test]
fn contact_zone_offer_other_pair_refused() {
    let ks = keyset();
    let pair = Id::new();
    let s = SignedContactZoneOffer::sign(offer(member(), pair), &ks.signing).unwrap();
    let vk = ks.signing.verifying_key().unwrap();
    let r = verify_contact_zone_offer(&s.encode(), &vk, &member(), Id::new());
    assert!(
        matches!(r, Err(Error::Integrity(IntegrityError::WrongContext))),
        "{r:?}"
    );
}

/// Every row of every table of the store file, as raw bytes.
fn all_store_bytes(dev: &Device) -> Vec<u8> {
    let conn = rusqlite::Connection::open(&dev.path).unwrap();
    let mut out = Vec::new();
    let tables: Vec<String> = conn
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table'")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    for t in tables {
        let mut stmt = conn.prepare(&format!("SELECT * FROM {t}")).unwrap();
        let n = stmt.column_count();
        let mut rows = stmt.query([]).unwrap();
        while let Some(row) = rows.next().unwrap() {
            for i in 0..n {
                match row.get_ref(i).unwrap() {
                    rusqlite::types::ValueRef::Blob(b) => out.extend_from_slice(b),
                    rusqlite::types::ValueRef::Text(b) => out.extend_from_slice(b),
                    _ => {}
                }
            }
        }
    }
    out
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn seed_never_in_store_plaintext() {
    let (mut a, _) = Device::create();
    let t = vault_target();
    let seed = ZoneSeed::generate().unwrap();
    a.repo().test_write_zone_access(t, None, &seed).unwrap();
    assert!(!contains(&all_store_bytes(&a), seed.expose()));
    a.repo()
        .set_zone_home(t, home("https://m.example"))
        .unwrap();
    assert!(!contains(&all_store_bytes(&a), seed.expose()));
    let (_, anchor) = a.repo().anchor().unwrap();
    a.repo().persist_device_state().unwrap();
    let bytes = all_store_bytes(&a);
    assert!(!contains(&bytes, seed.expose()));
    assert!(!contains(&bytes, anchor.expose()));
}

#[test]
fn zone_access_server_deletion_refused() {
    let mut server = Server::default();
    let (mut a, mut b, _, _) = setup(&mut server, &[]);
    a.repo().anchor().unwrap();
    settle(&mut server, &mut [&mut a, &mut b], 10);
    let id = AccessTarget::Anchor.record_id().unwrap();
    server.forge_deletion(ZONE_ACCESS_KIND, id);
    pull(&server, &mut b);
    assert!(b.store().get(ZONE_ACCESS_KIND, id).unwrap().is_some());
}
