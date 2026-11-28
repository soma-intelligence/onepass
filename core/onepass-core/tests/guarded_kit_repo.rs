//! Guarded Kit on the repository (spec 2026-11-20, sections 7.1, 7.2, 8):
//! signed guard params, keyset under AUK v2, unlock with a kept guard or
//! the realms, turn off, renew, password change, owner poll.

use std::cell::RefCell;

use onepass_core::account::AccountParams;
use onepass_core::crypto::{DEV_KDF_FLOOR, KdfParams, random_array};
use onepass_core::guarded_kit::realm::{DEFAULT_LIMIT, MemoryRealmStore, Realm};
use onepass_core::guarded_kit::{
    GuardAccess, GuardError, GuardSecret, GuardState, RealmInfo, RealmTransport,
};
use onepass_core::repo::{DeviceState, Repository};
use onepass_core::store::{MemoryStore, RecordKind, RecordStore};
use onepass_core::{Error, IntegrityError};

const NOW: u64 = 1_800_000_000;

struct Net {
    realms: Vec<RefCell<Realm<MemoryRealmStore>>>,
    infos: Vec<RealmInfo>,
    down: RefCell<Vec<usize>>,
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
        }
    }

    /// Records held at realm `i`.
    fn held(&self, i: usize) -> usize {
        self.realms[i].borrow().store().len()
    }
}

impl RealmTransport for Net {
    fn call(&self, realm: &RealmInfo, request: &[u8]) -> Result<Vec<u8>, GuardError> {
        let i = self
            .infos
            .iter()
            .position(|r| r.id == realm.id)
            .ok_or(GuardError::Transport("unknown".into()))?;
        if self.down.borrow().contains(&i) {
            return Err(GuardError::Transport("down".into()));
        }
        self.realms[i].borrow_mut().handle(request, NOW)
    }
}

fn kdf() -> KdfParams {
    let (m_kib, t, p) = DEV_KDF_FLOOR;
    KdfParams {
        m_kib,
        t,
        p,
        salt: random_array().unwrap(),
    }
}

fn guarded(
    net: &Net,
) -> (
    Repository<MemoryStore>,
    onepass_core::crypto::SecretKey,
    GuardSecret,
) {
    let (mut repo, sk) = Repository::create_account(MemoryStore::new(), "pw", kdf()).unwrap();
    let (_, g) = repo.enable_guard("pw", &sk, net, &net.infos).unwrap();
    (repo, sk, g)
}

fn params_of(store: &MemoryStore) -> AccountParams {
    let r = &store.list(RecordKind::AccountParams).unwrap()[0];
    AccountParams::decode(&r.data).unwrap()
}

#[test]
fn enable_signs_the_guard_and_reseals_under_v2() {
    let net = Net::new();
    let (repo, sk, g) = guarded(&net);
    assert!(matches!(
        repo.guard_state(&net.infos),
        GuardState::On {
            version: 1,
            threshold: 2,
            realm_set_current: true,
            ..
        }
    ));
    assert_eq!(repo.guard_secret().unwrap().unwrap().expose(), g.expose());
    let stored = params_of(repo.store());
    assert!(stored.guard.is_some());
    assert_eq!(stored.epoch, 2);
    for i in 0..3 {
        assert_eq!(net.held(i), 1);
    }

    // The password and Secret Key alone no longer open it.
    let store = repo.store().clone();
    let e = Repository::unlock(store.clone(), "pw", &sk, DeviceState::default())
        .err()
        .unwrap();
    assert_eq!(e, Error::Guard(GuardError::Required));
    // With the guard kept by the device.
    let (_, _, back) = Repository::unlock_guarded(
        store.clone(),
        "pw",
        &sk,
        DeviceState::default(),
        GuardAccess::Secret(&g),
    )
    .unwrap();
    assert_eq!(back.unwrap().expose(), g.expose());
}

#[test]
fn new_device_restores_through_the_realms() {
    let net = Net::new();
    let (repo, sk, g) = guarded(&net);
    let store = repo.store().clone();
    let access = GuardAccess::Realms {
        transport: &net,
        pinned: &net.infos,
    };
    let (other, _, back) =
        Repository::unlock_guarded(store.clone(), "pw", &sk, DeviceState::default(), access)
            .unwrap();
    assert_eq!(back.unwrap().expose(), g.expose());
    assert_eq!(other.guard_secret().unwrap().unwrap().expose(), g.expose());

    // A wrong password costs one attempt at two realms and says so.
    let e = Repository::unlock_guarded(store.clone(), "nope", &sk, DeviceState::default(), access)
        .err()
        .unwrap();
    assert_eq!(
        e,
        Error::Guard(GuardError::WrongPassword {
            remaining: DEFAULT_LIMIT - 1
        })
    );
    // One realm down: still restores.
    net.down.borrow_mut().push(0);
    assert!(
        Repository::unlock_guarded(store.clone(), "pw", &sk, DeviceState::default(), access)
            .is_ok()
    );
    // Two down: refused, nothing guessed offline.
    net.down.borrow_mut().push(1);
    assert!(matches!(
        Repository::unlock_guarded(store, "pw", &sk, DeviceState::default(), access)
            .err()
            .unwrap(),
        Error::Guard(GuardError::Unavailable { .. })
    ));
}

#[test]
fn a_stolen_kit_cannot_turn_the_realms_off_by_editing_params() {
    let net = Net::new();
    let (repo, sk, _g) = guarded(&net);
    let mut store = repo.store().clone();
    let mut rec = store.list(RecordKind::AccountParams).unwrap()[0].clone();
    let mut p = AccountParams::decode(&rec.data).unwrap();
    p.guard = None;
    rec.data = p.encode().unwrap();
    rec.version += 1;
    store.put(rec).unwrap();
    assert_eq!(
        Repository::unlock(store, "pw", &sk, DeviceState::default())
            .err()
            .unwrap(),
        Error::Integrity(IntegrityError::ParamsUnsigned)
    );
}

#[test]
fn disable_goes_back_to_v1_and_deletes_at_the_realms() {
    let net = Net::new();
    let (mut repo, sk, _g) = guarded(&net);
    repo.disable_guard("pw", &sk, &net, &net.infos).unwrap();
    assert_eq!(repo.guard_state(&net.infos), GuardState::Off);
    assert!(params_of(repo.store()).guard.is_none());
    for i in 0..3 {
        assert_eq!(net.held(i), 0);
    }
    assert!(Repository::unlock(repo.store().clone(), "pw", &sk, DeviceState::default()).is_ok());
}

#[test]
fn disable_needs_the_password() {
    let net = Net::new();
    let (mut repo, sk, _g) = guarded(&net);
    assert_eq!(
        repo.disable_guard("nope", &sk, &net, &net.infos)
            .unwrap_err(),
        Error::WrongPassword
    );
    assert!(params_of(repo.store()).guard.is_some());
}

#[test]
fn renew_keeps_or_replaces_g_and_drops_the_old_version() {
    let net = Net::new();
    let (mut repo, sk, g) = guarded(&net);
    let (_, same) = repo
        .renew_guard("pw", &sk, &net, &net.infos, false)
        .unwrap();
    assert_eq!(same.expose(), g.expose());
    assert!(matches!(
        repo.guard_state(&net.infos),
        GuardState::On { version: 2, .. }
    ));
    for i in 0..3 {
        assert_eq!(net.held(i), 1, "old version deleted");
    }
    let (_, fresh) = repo.renew_guard("pw", &sk, &net, &net.infos, true).unwrap();
    assert_ne!(fresh.expose(), g.expose());
    let store = repo.store().clone();
    assert!(
        Repository::unlock_guarded(
            store.clone(),
            "pw",
            &sk,
            DeviceState::default(),
            GuardAccess::Secret(&g)
        )
        .is_err()
    );
    assert!(
        Repository::unlock_guarded(
            store,
            "pw",
            &sk,
            DeviceState::default(),
            GuardAccess::Realms {
                transport: &net,
                pinned: &net.infos
            }
        )
        .is_ok()
    );
}

#[test]
fn enable_twice_refused_and_failed_registration_writes_nothing() {
    let net = Net::new();
    let (mut repo, sk) = Repository::create_account(MemoryStore::new(), "pw", kdf()).unwrap();
    net.down.borrow_mut().push(2);
    assert!(repo.enable_guard("pw", &sk, &net, &net.infos).is_err());
    assert!(params_of(repo.store()).guard.is_none());
    net.down.borrow_mut().clear();
    repo.enable_guard("pw", &sk, &net, &net.infos).unwrap();
    assert!(matches!(
        repo.enable_guard("pw", &sk, &net, &net.infos).unwrap_err(),
        Error::Validation(_)
    ));
}

#[test]
fn password_change_registers_again() {
    let net = Net::new();
    let (mut repo, sk, g) = guarded(&net);
    assert_eq!(
        repo.change_password("pw", &sk, "new").unwrap_err(),
        Error::Guard(GuardError::Required)
    );
    repo.change_password_guarded("pw", &sk, "new", &net, &net.infos)
        .unwrap();
    for i in 0..3 {
        assert_eq!(net.held(i), 1);
    }
    let store = repo.store().clone();
    let access = GuardAccess::Realms {
        transport: &net,
        pinned: &net.infos,
    };
    let (_, _, back) =
        Repository::unlock_guarded(store.clone(), "new", &sk, DeviceState::default(), access)
            .unwrap();
    assert_eq!(back.unwrap().expose(), g.expose());
    assert!(Repository::unlock_guarded(store, "pw", &sk, DeviceState::default(), access).is_err());
}

#[test]
fn health_reports_failures_and_lost_realms() {
    let net = Net::new();
    let (repo, sk, _g) = guarded(&net);
    let store = repo.store().clone();
    let access = GuardAccess::Realms {
        transport: &net,
        pinned: &net.infos,
    };
    let _ = Repository::unlock_guarded(store, "nope", &sk, DeviceState::default(), access);
    let h = repo.guard_health(&net, &net.infos).unwrap();
    assert_eq!(h.failures, vec![NOW]);
    assert!(!h.needs_renewal);

    // A realm forgets the guard: renew from this device.
    net.realms[2].borrow_mut().store_mut().clear();
    assert!(repo.guard_health(&net, &net.infos).unwrap().needs_renewal);
}

#[test]
fn realm_list_change_shows_as_not_current() {
    let net = Net::new();
    let (repo, _sk, _g) = guarded(&net);
    let mut other = net.infos.clone();
    other[2].id = [99; 16];
    assert!(matches!(
        repo.guard_state(&other),
        GuardState::On {
            realm_set_current: false,
            ..
        }
    ));
}
