// Shared people helpers for the sharing FFI tests (sharing.rs, family.rs):
// included after support/mailbox_shim.rs.

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

/// One account on one device with v2 device keys, and its zone handle on
/// the shim (no account mailbox: the pair's mailboxes hang off an anchor).
struct Person {
    _dir: TempDir,
    path: String,
    session: Arc<Session>,
    secret_key: String,
    keys: Keys,
    seeds: Arc<MemSeeds>,
    zones: Arc<ZoneSyncHandle>,
    store: Arc<SyncStoreHandle>,
}

fn person(shim: &Shim, name: &str) -> Person {
    let dir = TempDir::new().unwrap();
    let path = db_path(dir.path());
    let keys = Keys::new();
    let created = create_account_v2(
        path.clone(),
        PASSWORD.into(),
        Some(FAST),
        keys.classical.clone(),
        keys.half(),
        format!("iPhone de {name}"),
        FfiDeviceKind::Phone,
        FfiDeviceMode::Personal,
    )
    .unwrap();
    let e = shim.endpoint();
    let seeds = Arc::new(MemSeeds::default());
    let zones = ZoneSyncHandle::new(seeds.clone(), e.base_url, e.extra_ca_pem);
    let store = open_sync_store(path.clone()).unwrap();
    Person {
        _dir: dir,
        path,
        secret_key: created.secret_key,
        session: created.session,
        keys,
        seeds,
        zones,
        store,
    }
}

/// A PQ half whose signature fails, as a locked Secure Enclave key does.
struct BrokenHalf(SoftwarePqHalf);

impl FfiPqDeviceHalf for BrokenHalf {
    fn mldsa_public(&self) -> Result<Vec<u8>, OnePassError> {
        self.0.mldsa_public().map_err(|_| OnePassError::Crypto)
    }

    fn mlkem_public(&self) -> Result<Vec<u8>, OnePassError> {
        self.0.mlkem_public().map_err(|_| OnePassError::Crypto)
    }

    fn mldsa_sign(&self, _message: Vec<u8>) -> Result<Vec<u8>, OnePassError> {
        Err(OnePassError::Locked)
    }

    fn mlkem_decapsulate(&self, _ciphertext: Vec<u8>) -> Result<Vec<u8>, OnePassError> {
        Err(OnePassError::Locked)
    }
}

fn peer_card(o: FfiContactOutcome) -> Arc<FfiVerifiedPeer> {
    match o {
        FfiContactOutcome::PeerCard { peer } => peer,
        _ => panic!("expected a peer card"),
    }
}

fn zone_offer(o: FfiContactOutcome) -> Vec<u8> {
    match o {
        FfiContactOutcome::PeerZoneOffer { offer } => offer,
        _ => panic!("expected a zone offer"),
    }
}


/// Alice and Bob verified face to face through the FFI, the pair's
/// mailbox made by the creator and synced on both sides.
fn verified_pair(shim: &Shim) -> (Person, Person) {
    let alice = person(shim, "Alice");
    let bob = person(shim, "Bob");
    let t = now();
    let start = contact_responder_start(t).unwrap();
    let begin = contact_initiator_begin(start.qr, start.hello, t).unwrap();
    let (r, i) = (start.responder, begin.initiator);
    r.on_key_exchange(begin.key_exchange, t).unwrap();
    let fa = r
        .confirm_and_send_card(
            alice.session.clone(),
            "Alice".into(),
            alice.keys.classical.clone(),
            alice.keys.half(),
            t,
        )
        .unwrap();
    i.on_frame(fa, t).unwrap();
    let fb = i
        .confirm_and_send_card(
            bob.session.clone(),
            "Bob".into(),
            bob.keys.classical.clone(),
            bob.keys.half(),
            t,
        )
        .unwrap();
    let bob_seen = peer_card(r.on_frame(fb, t).unwrap());
    let alice_seen = i.verified_peer().unwrap();
    if alice
        .session
        .creates_contact_zone(bob_seen.clone())
        .unwrap()
    {
        let offer = alice
            .zones
            .contact_zone_create(alice.session.clone(), bob_seen.card(), t)
            .unwrap();
        let got = zone_offer(i.on_frame(r.send_zone_offer(offer, t).unwrap(), t).unwrap());
        alice
            .session
            .finish_contact_session(bob_seen, None, t)
            .unwrap();
        bob.session
            .finish_contact_session(alice_seen, Some(got), t)
            .unwrap();
    } else {
        let offer = bob
            .zones
            .contact_zone_create(bob.session.clone(), alice_seen.card(), t)
            .unwrap();
        let got = zone_offer(r.on_frame(i.send_zone_offer(offer, t).unwrap(), t).unwrap());
        bob.session
            .finish_contact_session(alice_seen, None, t)
            .unwrap();
        alice
            .session
            .finish_contact_session(bob_seen, Some(got), t)
            .unwrap();
    }
    settle_zones(&[&alice, &bob]);
    (alice, bob)
}

/// Zone rounds on every side until two passes in a row run no action,
/// bring nothing and leave every zone idle (a push of the last side is
/// fetched by the others on the next pass).
fn settle_zones(people: &[&Person]) -> Vec<FfiZoneRoundReport> {
    let mut last = Vec::new();
    let mut quiet_passes = 0;
    for _ in 0..10 {
        last = people
            .iter()
            .map(|p| {
                p.zones
                    .run_round(Some(p.session.clone()), p.store.clone(), now())
            })
            .collect();
        let quiet = last.iter().all(|r| {
            r.actions_done == 0
                && !r.rerun
                && !r.changed
                && r.zones.iter().all(|z| z.status == FfiRoundStatus::Idle)
        });
        quiet_passes = if quiet { quiet_passes + 1 } else { 0 };
        if quiet_passes == 2 {
            return last;
        }
    }
    panic!("zones never settled: {last:?}");
}

fn item_in(session: &Session, vault_id: &str, title: &str) -> FfiItem {
    let mut item = session
        .new_item(vault_id.into(), FfiItemType::Login, title.into())
        .unwrap();
    for f in item.sections.iter_mut().flat_map(|s| s.fields.iter_mut()) {
        if f.id == "username" {
            f.value = FfiFieldValue::Text {
                value: "famille@exemple.fr".into(),
            };
        }
    }
    item
}

fn vault_titles(session: &Session, vault_id: &str) -> Vec<String> {
    let mut t: Vec<String> = session
        .item_summaries()
        .unwrap()
        .into_iter()
        .filter(|s| s.vault_id == vault_id)
        .map(|s| s.title)
        .collect();
    t.sort();
    t
}
