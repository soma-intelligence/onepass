//! Sharing over the UniFFI surface, called as plain Rust (plan 4): zones,
//! invite drops and the zone round (Task 1), contacts (Task 2), shared
//! vaults (Task 3).
//!
//! No network: `Shim` serves the in-memory `FakeMailbox` over loopback TLS,
//! so the real client signs and checks every request. Synthetic data only.
//! Run with `--features dev-fast-kdf`.

#![allow(dead_code, unused_imports)]

include!("support/mailbox_shim.rs");

use std::collections::HashMap as SeedMap;

/// The keychain of one device, in memory.
#[derive(Default)]
struct MemSeeds(Mutex<SeedMap<Vec<u8>, Vec<u8>>>);

impl FfiZoneSeedStore for MemSeeds {
    fn get(&self, mailbox_id: Vec<u8>) -> Option<Vec<u8>> {
        self.0.lock().unwrap().get(&mailbox_id).cloned()
    }

    fn put(&self, mailbox_id: Vec<u8>, seed: Vec<u8>) {
        self.0.lock().unwrap().insert(mailbox_id, seed);
    }

    fn delete(&self, mailbox_id: Vec<u8>) {
        self.0.lock().unwrap().remove(&mailbox_id);
    }
}

// ---- Task 1 -----------------------------------------------------------------

#[test]
fn zone_in_invalid_hex_is_invalid_input() {
    let bad = |kind, id: Option<&str>| {
        zone_normalized(FfiZone {
            kind,
            id: id.map(str::to_string),
        })
    };
    assert!(matches!(
        bad(FfiZoneKind::Vault, Some("not hex")),
        Err(OnePassError::InvalidInput { .. })
    ));
    assert!(matches!(
        bad(FfiZoneKind::Contact, None),
        Err(OnePassError::InvalidInput { .. })
    ));
    assert!(matches!(
        bad(FfiZoneKind::Private, Some(&"00".repeat(16))),
        Err(OnePassError::InvalidInput { .. })
    ));
    let ok = bad(FfiZoneKind::Family, Some(&"AB".repeat(16))).unwrap();
    assert_eq!(ok.id.as_deref(), Some("ab".repeat(16).as_str()));
    assert_eq!(
        bad(FfiZoneKind::Private, None).unwrap().kind,
        FfiZoneKind::Private
    );
}

#[test]
fn drop_round_trip() {
    let shim = Shim::start();
    let e = shim.endpoint();
    let id = vec![7u8; 16];
    let ca = e.extra_ca_pem.clone();
    assert_eq!(
        drop_get(e.base_url.clone(), id.clone(), 0, ca.clone()).unwrap(),
        None
    );
    drop_put(
        e.base_url.clone(),
        id.clone(),
        0,
        b"offre".to_vec(),
        ca.clone(),
    )
    .unwrap();
    assert_eq!(
        drop_get(e.base_url.clone(), id.clone(), 0, ca.clone()).unwrap(),
        Some(b"offre".to_vec())
    );
    // Write once: the first write stands.
    assert_eq!(
        drop_put(
            e.base_url.clone(),
            id.clone(),
            0,
            b"autre".to_vec(),
            ca.clone()
        ),
        Err(OnePassError::Conflict)
    );
    assert!(matches!(
        drop_put(e.base_url.clone(), id.clone(), 9, b"x".to_vec(), ca.clone()),
        Err(OnePassError::MailboxUnavailable { .. })
    ));
    assert!(matches!(
        drop_get(e.base_url.clone(), vec![1, 2], 0, ca.clone()),
        Err(OnePassError::InvalidInput { .. })
    ));
    drop_delete(e.base_url.clone(), id.clone(), ca.clone()).unwrap();
    assert_eq!(drop_get(e.base_url, id, 0, ca).unwrap(), None);
}

#[test]
fn zone_round_without_zones_is_empty() {
    let shim = Shim::start();
    let dir = TempDir::new().unwrap();
    let path = db_path(dir.path());
    let created = create_account_with_kdf(path.clone(), PASSWORD.into(), FAST).unwrap();
    let store = open_sync_store(path).unwrap();
    let e = shim.endpoint();
    let zones = ZoneSyncHandle::new(Arc::new(MemSeeds::default()), e.base_url, e.extra_ca_pem);
    let r = zones.run_round(Some(created.session.clone()), store.clone(), now());
    assert!(r.zones.is_empty());
    assert_eq!(r.actions_done, 0);
    assert!(r.refusals.is_empty());
    // Locked: nothing either, and no call fails.
    let r = zones.run_round(None, store, now());
    assert!(r.zones.is_empty());
    assert!(zones.wake_topics().is_empty());
    assert!(matches!(
        zones.set_push_target("00".repeat(16), vec![1; 16], FfiPushKind::Apns, vec![1]),
        Err(OnePassError::MailboxUnavailable { .. })
    ));
    assert!(matches!(
        zones.contact_zone_create(created.session, vec![1, 2, 3], now()),
        Err(OnePassError::InvalidInput { .. })
    ));
}
