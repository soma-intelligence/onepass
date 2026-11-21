//! Guarded Kit (spec 2026-11-20): registration and restore against three
//! in-process realms, and the attacks of spec sections 5 to 8.

use std::cell::{Cell, RefCell};

use onepass_core::Id;
use onepass_core::crypto::{
    KdfParams, SecretKey, derive_auk, derive_auk_v2, guard_input, stretch_password,
};
use onepass_core::guarded_kit::client::tag_of;
use onepass_core::guarded_kit::oprf;
use onepass_core::guarded_kit::realm::RealmStore;
use onepass_core::guarded_kit::realm::{DEFAULT_LIMIT, MemoryRealmStore, Realm};
use onepass_core::guarded_kit::wire::{
    Request, ResponseBody, SignedResponse, encode_request, encode_response, open_response,
    request_hash, response_message,
};
use onepass_core::guarded_kit::{
    GuardDescriptor, GuardError, GuardSecret, GuardStatus, Locator, RealmInfo, RealmTransport,
    delete, register, restore, status,
};

const NOW: u64 = 1_800_000_000;

struct Net {
    realms: Vec<RefCell<Realm<MemoryRealmStore>>>,
    infos: Vec<RealmInfo>,
    /// Realms that do not answer.
    down: RefCell<Vec<usize>>,
    calls: Cell<usize>,
}

impl Net {
    fn new() -> Net {
        let mut realms = Vec::new();
        let mut infos = Vec::new();
        for i in 0..3u8 {
            let r = Realm::new([i + 1; 32], DEFAULT_LIMIT, MemoryRealmStore::default());
            infos.push(RealmInfo {
                id: [i + 10; 16],
                url: format!("https://realm-{i}.test"),
                response_key: r.response_key().unwrap(),
            });
            realms.push(RefCell::new(r));
        }
        Net {
            realms,
            infos,
            down: RefCell::new(Vec::new()),
            calls: Cell::new(0),
        }
    }

    fn index(&self, realm: &RealmInfo) -> Option<usize> {
        self.infos.iter().position(|r| r.id == realm.id)
    }
}

impl RealmTransport for Net {
    fn call(&self, realm: &RealmInfo, request: &[u8]) -> Result<Vec<u8>, GuardError> {
        self.calls.set(self.calls.get() + 1);
        let i = self
            .index(realm)
            .ok_or(GuardError::Transport("unknown".into()))?;
        if self.down.borrow().contains(&i) {
            return Err(GuardError::Transport("down".into()));
        }
        self.realms[i].borrow_mut().handle(request, NOW)
    }
}

fn params() -> KdfParams {
    let (m_kib, t, p) = onepass_core::crypto::DEV_KDF_FLOOR;
    KdfParams {
        m_kib,
        t,
        p,
        salt: [3; 32],
    }
}

fn x_of(password: &str) -> [u8; 32] {
    let s = stretch_password(password, &params()).unwrap();
    *guard_input(&s, &params()).unwrap()
}

fn setup(net: &Net, password: &str) -> (GuardSecret, Locator) {
    let g = GuardSecret::generate().unwrap();
    let loc = register(net, &net.infos, 2, &x_of(password), &g, 1).unwrap();
    (g, loc)
}

#[test]
fn restore_with_kit_and_realms() {
    let net = Net::new();
    let (g, loc) = setup(&net, "correct horse");
    let back = restore(&net, &net.infos, &loc, &x_of("correct horse")).unwrap();
    assert_eq!(back.expose(), g.expose());
}

#[test]
fn one_realm_down_still_restores() {
    let net = Net::new();
    let (g, loc) = setup(&net, "pw");
    net.down.borrow_mut().push(0);
    let back = restore(&net, &net.infos, &loc, &x_of("pw")).unwrap();
    assert_eq!(back.expose(), g.expose());
}

#[test]
fn t_minus_one_realms_cannot_restore() {
    let net = Net::new();
    let (_g, loc) = setup(&net, "pw");
    net.down.borrow_mut().extend([0, 1]);
    assert_eq!(
        restore(&net, &net.infos, &loc, &x_of("pw")).unwrap_err(),
        GuardError::Unavailable {
            reached: 1,
            needed: 2
        }
    );
}

#[test]
fn wrong_password_counts_once_and_stops() {
    let net = Net::new();
    let (_g, loc) = setup(&net, "pw");
    let before = net.calls.get();
    let e = restore(&net, &net.infos, &loc, &x_of("nope")).unwrap_err();
    assert_eq!(
        e,
        GuardError::WrongPassword {
            remaining: DEFAULT_LIMIT - 1
        }
    );
    // Two evaluations (the threshold) and one unlock.
    assert_eq!(net.calls.get() - before, 3);
}

#[test]
fn success_resets_the_counter() {
    let net = Net::new();
    let (g, loc) = setup(&net, "pw");
    for _ in 0..(DEFAULT_LIMIT - 1) {
        assert!(restore(&net, &net.infos, &loc, &x_of("nope")).is_err());
    }
    let back = restore(&net, &net.infos, &loc, &x_of("pw")).unwrap();
    assert_eq!(back.expose(), g.expose());
    match status(&net, &net.infos[0], &loc.placements[0].guard_id, &g).unwrap() {
        GuardStatus::Active {
            attempts, failures, ..
        } => {
            assert_eq!(attempts, 0);
            assert!(failures.is_empty());
        }
        GuardStatus::Gone => panic!("guard gone"),
    }
}

#[test]
fn limit_erases_share_for_good() {
    let net = Net::new();
    let (g, loc) = setup(&net, "pw");
    // Each wrong guess costs an attempt at the two realms asked (0 and 1)
    // and fails the tag at realm 0.
    for _ in 0..DEFAULT_LIMIT {
        assert!(matches!(
            restore(&net, &net.infos, &loc, &x_of("guess")),
            Err(GuardError::WrongPassword { .. })
        ));
    }
    assert_eq!(
        status(&net, &net.infos[0], &loc.placements[0].guard_id, &g).unwrap(),
        GuardStatus::Gone
    );
    // Realm 1 is at its limit: its next evaluation erases it, and the
    // right password finds one realm left.
    assert!(matches!(
        restore(&net, &net.infos, &loc, &x_of("pw")),
        Err(GuardError::Unavailable { reached: 1, .. })
    ));
    assert_eq!(
        status(&net, &net.infos[1], &loc.placements[1].guard_id, &g).unwrap(),
        GuardStatus::Gone
    );
}

#[test]
fn one_compromised_realm_cannot_test_passwords() {
    let net = Net::new();
    let (_g, loc) = setup(&net, "pw");
    // An insider of realm 0 reads its record: key share, tag, sealed share.
    let p = &loc.placements[0];
    let rec = net.realms[0].borrow().store().get(&p.guard_id).unwrap();
    // Even with the right password, the share alone gives a wrong OPRF
    // output, so no tag matches: no offline test, for any guess.
    for guess in ["pw", "guess", ""] {
        let y = oprf::evaluate_full(&rec.key_share, &x_of(guess)).unwrap();
        let t = tag_of(y.as_slice(), &net.infos[0].id, p.index, loc.version).unwrap();
        assert_ne!(t, rec.tag, "{guess}");
    }
}

#[test]
fn two_compromised_realms_can_test_passwords() {
    // Negative witness: with T key shares the insiders rebuild the OPRF
    // and test guesses offline (spec 13: today's level, never below).
    let net = Net::new();
    let (_g, loc) = setup(&net, "pw");
    let p0 = &loc.placements[0];
    let p1 = &loc.placements[1];
    let r0 = net.realms[0].borrow().store().get(&p0.guard_id).unwrap();
    let r1 = net.realms[1].borrow().store().get(&p1.guard_id).unwrap();
    let test = |guess: &str| {
        let b = oprf::blind(&x_of(guess)).unwrap();
        let e0 = oprf::evaluate(&r0.key_share, &b.message).unwrap();
        let e1 = oprf::evaluate(&r1.key_share, &b.message).unwrap();
        let e = oprf::combine_evaluations(&[(p0.index, e0), (p1.index, e1)]).unwrap();
        let y = b.finalize(&x_of(guess), &e).unwrap();
        tag_of(y.as_slice(), &net.infos[0].id, p0.index, loc.version).unwrap() == r0.tag
    };
    assert!(!test("guess"));
    assert!(test("pw"));
}

#[test]
fn total_guesses_bounded_by_realms_times_limit() {
    let net = Net::new();
    let (g, loc) = setup(&net, "pw");
    let mut guesses = 0;
    for i in 0..1000 {
        match restore(&net, &net.infos, &loc, &x_of(&format!("g{i}"))) {
            Err(GuardError::WrongPassword { .. }) => guesses += 1,
            Err(GuardError::Unavailable { .. }) => break,
            other => panic!("{other:?}"),
        }
    }
    // Each guess costs an attempt at T = 2 realms: at most N x limit / T.
    assert!(guesses <= 3 * usize::from(DEFAULT_LIMIT) / 2, "{guesses}");
    // Fewer than T realms hold a share now: the guard is dead for anyone.
    let alive = loc
        .placements
        .iter()
        .enumerate()
        .filter(|(i, p)| {
            status(&net, &net.infos[*i], &p.guard_id, &g).unwrap() != GuardStatus::Gone
        })
        .count();
    assert!(alive < 2, "{alive}");
}

#[test]
fn fake_realm_rejected_by_pinning() {
    let net = Net::new();
    let (_g, mut loc) = setup(&net, "pw");
    // Storage swaps a placement for a realm that is not pinned.
    loc.placements[0].realm_id = [99; 16];
    let before = net.calls.get();
    let back = restore(&net, &net.infos, &loc, &x_of("pw"));
    assert!(back.is_ok(), "the two pinned realms still answer");
    // The unpinned realm was never called.
    assert_eq!(net.calls.get() - before, 4);
}

#[test]
fn forged_response_refused() {
    let net = Net::new();
    let (_g, loc) = setup(&net, "pw");
    let req = encode_request(&Request::Unlock {
        guard_id: loc.placements[0].guard_id,
        tag: [0; 32],
    })
    .unwrap();
    // A network attacker signs with its own key.
    let body = ResponseBody::Unlocked {
        share_ct: vec![1, 2, 3],
    };
    let h = request_hash(&req);
    let forged = encode_response(&SignedResponse {
        request_hash: h,
        body: body.clone(),
        sig: vec![0; 64],
    })
    .unwrap();
    assert_eq!(
        open_response(&forged, &req, &net.infos[0].response_key).unwrap_err(),
        GuardError::RealmSignature
    );
    // A genuine response replayed for another request.
    let other = encode_request(&Request::Unlock {
        guard_id: loc.placements[0].guard_id,
        tag: [1; 32],
    })
    .unwrap();
    let genuine = net.call(&net.infos[0], &req).unwrap();
    assert_eq!(
        open_response(&genuine, &other, &net.infos[0].response_key).unwrap_err(),
        GuardError::RealmSignature
    );
    let _ = response_message(&h, &body).unwrap();
}

#[test]
fn only_the_owner_manages_the_guard() {
    let net = Net::new();
    let (g, loc) = setup(&net, "pw");
    let thief = GuardSecret::generate().unwrap();
    assert!(status(&net, &net.infos[0], &loc.placements[0].guard_id, &thief).is_err());
    assert_eq!(delete(&net, &net.infos, &loc, &thief).unwrap(), 0);
    assert!(restore(&net, &net.infos, &loc, &x_of("pw")).is_ok());
    assert_eq!(delete(&net, &net.infos, &loc, &g).unwrap(), 3);
    assert!(restore(&net, &net.infos, &loc, &x_of("pw")).is_err());
}

#[test]
fn status_reports_failures() {
    let net = Net::new();
    let (g, loc) = setup(&net, "pw");
    let _ = restore(&net, &net.infos, &loc, &x_of("thief"));
    match status(&net, &net.infos[0], &loc.placements[0].guard_id, &g).unwrap() {
        GuardStatus::Active {
            attempts,
            failures,
            limit,
            version,
        } => {
            assert_eq!((attempts, limit, version), (1, DEFAULT_LIMIT, 1));
            assert_eq!(failures, vec![NOW]);
        }
        GuardStatus::Gone => panic!(),
    }
}

#[test]
fn register_refuses_a_bad_key_share() {
    let net = Net::new();
    for key_share in [[0u8; 32], [0xff; 32]] {
        let req = encode_request(&Request::Register {
            owner: [1; 32],
            version: 1,
            key_share,
            tag: [0; 32],
            share_ct: vec![0; 10],
        })
        .unwrap();
        let resp = net.call(&net.infos[0], &req).unwrap();
        assert!(matches!(
            open_response(&resp, &req, &net.infos[0].response_key).unwrap(),
            ResponseBody::Refused(_)
        ));
    }
}

#[test]
fn version_is_bound() {
    let net = Net::new();
    let (_g, mut loc) = setup(&net, "pw");
    loc.version = 2;
    assert!(matches!(
        restore(&net, &net.infos, &loc, &x_of("pw")),
        Err(GuardError::WrongPassword { .. })
    ));
}

#[test]
fn descriptor_round_trip_and_locator_needs_secret_key() {
    let net = Net::new();
    let (_g, loc) = setup(&net, "pw");
    let sk = SecretKey::generate().unwrap();
    let account = Id([5; 16]);
    let d = GuardDescriptor::seal(&sk, account, &net.infos, &loc).unwrap();
    let d2 = GuardDescriptor::decode(&d.encode().unwrap()).unwrap();
    assert_eq!(d, d2);
    assert_eq!(d2.open_locator(&sk).unwrap(), loc);

    // Storage alone (no Secret Key) cannot find the guard.
    let other = SecretKey::generate().unwrap();
    assert_eq!(
        d2.open_locator(&other).unwrap_err(),
        GuardError::LocatorRefused
    );
    // A header that lies about the version is refused.
    let mut lying = d2.clone();
    lying.version = 7;
    assert!(lying.open_locator(&sk).is_err());
    assert_ne!(d.hash().unwrap(), lying.hash().unwrap());
}

#[test]
fn v1_auk_never_equals_v2() {
    let p = params();
    let sk = SecretKey::generate().unwrap();
    let s = stretch_password("pw", &p).unwrap();
    let v1 = derive_auk("pw", &sk, &p).unwrap();
    let g = GuardSecret::generate().unwrap();
    let v2 = derive_auk_v2(&s, &sk, g.expose(), &p).unwrap();
    assert_ne!(v1.expose(), v2.expose());
    // The guard input is not the AUK, and depends on the password.
    assert_ne!(guard_input(&s, &p).unwrap().as_slice(), v1.expose());
    assert_ne!(x_of("pw"), x_of("pw2"));
    // A different guard gives a different AUK.
    let g2 = GuardSecret::generate().unwrap();
    assert_ne!(
        v2.expose(),
        derive_auk_v2(&s, &sk, g2.expose(), &p).unwrap().expose()
    );
}

#[test]
fn registration_needs_every_realm() {
    let net = Net::new();
    net.down.borrow_mut().push(2);
    let g = GuardSecret::generate().unwrap();
    assert!(register(&net, &net.infos, 2, &x_of("pw"), &g, 1).is_err());
}

#[test]
fn malformed_request_gets_signed_refusal() {
    let net = Net::new();
    let req = b"garbage".to_vec();
    let resp = net.call(&net.infos[0], &req).unwrap();
    assert!(matches!(
        open_response(&resp, &req, &net.infos[0].response_key).unwrap(),
        ResponseBody::Refused(_)
    ));
}
