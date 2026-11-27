//! Guarded Kit over the UniFFI surface (spec
//! `docs/superpowers/specs/2026-11-20-guarded-kit-design.md`, sections 7 to
//! 9): turn the guard on and off, renew it, change the master password of a
//! guarded account, poll the realms, unlock and restore with the guard.
//!
//! Rust holds no network code: the app implements `FfiRealmTransport`
//! (one HTTPS POST of opaque bytes to the realm's URL) and every response
//! is checked here against the realm keys pinned in this build. The realm
//! list never comes from the app or from storage.
//!
//! `G` (32 bytes) is handed back once after each change and each unlock
//! with the password: the app keeps it in its secure storage (Keychain,
//! Android Keystore) and passes it to `unlock_with_password_guarded` next
//! time; without it, the unlock goes to the realms. Any unlocked session
//! also gives it back (`guard_secret`).

use std::sync::Arc;

use onepass_core::account::AccountParams;
use onepass_core::crypto::SecretKey;
use onepass_core::guarded_kit::{
    GuardAccess, GuardError, GuardSecret, GuardState, RealmInfo, RealmTransport, pinned_realms,
};
use onepass_core::repo::Repository;
use onepass_core::repo::kit::KitRestore;
use onepass_core::store::{RecordKind, RecordStore};
use zeroize::Zeroizing;

use crate::devices::{FfiDeviceKind, FfiDeviceMode};
use crate::error::{OnePassError, invalid};
use crate::open_store;
use crate::rotation::{FfiPqDeviceHalf, device_keys};
use crate::session::Session;

/// One HTTPS POST to a realm, implemented by the app: send `request` as
/// the body to `url`, return the response body. Any transport failure
/// (offline, timeout, TLS, non-200) is an error; the core then tries the
/// next realm or reports `GuardUnavailable`. Called on the thread of the
/// FFI call, sometimes while that call holds its `Session`: never call
/// back into the FFI from here.
#[uniffi::export(with_foreign)]
pub trait FfiRealmTransport: Send + Sync {
    fn call(&self, url: String, request: Vec<u8>) -> Result<Vec<u8>, OnePassError>;
}

struct Transport(Arc<dyn FfiRealmTransport>);

impl RealmTransport for Transport {
    fn call(&self, realm: &RealmInfo, request: &[u8]) -> Result<Vec<u8>, GuardError> {
        self.0
            .call(realm.url.clone(), request.to_vec())
            .map_err(|_| GuardError::Transport("realm unreachable".into()))
    }
}

/// The settings screen (spec 9): "Protection du kit d'urgence".
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiGuardState {
    /// This build pins realms: the feature can be turned on.
    pub available: bool,
    pub on: bool,
    pub version: u32,
    pub threshold: u8,
    pub realms: u8,
    /// False after a realm list change in a release: renew (same `G`, no
    /// new kit).
    pub realm_set_current: bool,
}

/// After turning the guard on or renewing it: the new Account Unlock Key
/// (biometrics enroll again) and `G` for the device's secure storage.
#[derive(uniffi::Record)]
pub struct FfiGuardChange {
    pub auk: Vec<u8>,
    pub guard: Vec<u8>,
}

/// An unlock with the password on an account that may be guarded: `guard`
/// is `G` when the account is guarded (keep it), `None` otherwise.
#[derive(uniffi::Record)]
pub struct FfiGuardUnlocked {
    pub session: Arc<Session>,
    pub auk: Vec<u8>,
    pub guard: Option<Vec<u8>>,
}

/// The owner poll of spec 8.4.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiGuardHealth {
    /// Failed restore attempts the realms logged, Unix seconds, newest
    /// first: "Quelqu'un a essayé de restaurer ton compte avec ton kit
    /// d'urgence."
    pub failures: Vec<u64>,
    /// A realm lost the guard: renew it (`renew_guard`, same `G`).
    pub needs_renewal: bool,
    pub realms_answered: u8,
    pub realms_total: u8,
}

/// The realms of this build (tests may set others, `dev-fast-kdf` only).
pub(crate) fn realms() -> Vec<RealmInfo> {
    #[cfg(feature = "dev-fast-kdf")]
    if let Some(r) = test_net::realms() {
        return r;
    }
    pinned_realms()
}

fn guard_of(bytes: &[u8]) -> Result<GuardSecret, OnePassError> {
    let b: [u8; 32] = bytes.try_into().map_err(|_| invalid("guard"))?;
    Ok(GuardSecret::from_bytes(b))
}

fn state_of(s: GuardState, realms: &[RealmInfo]) -> FfiGuardState {
    let available = !realms.is_empty();
    match s {
        GuardState::Off => FfiGuardState {
            available,
            on: false,
            version: 0,
            threshold: 0,
            realms: 0,
            realm_set_current: true,
        },
        GuardState::On {
            version,
            threshold,
            realms,
            realm_set_current,
        } => FfiGuardState {
            available,
            on: true,
            version,
            threshold,
            realms,
            realm_set_current,
        },
    }
}

/// `unlock_with_password` on an account that may be guarded (spec 7.2):
/// with `guard` (kept by the device) when given, else through the realms
/// when `transport` is given. A guarded account with neither is
/// `GuardRequired`; a wrong password at the realms `GuardWrongPassword`
/// with the attempts left.
///
/// Keep `G` with its version (`guard_version`, or `FfiGuardState.version`
/// after the unlock) and pass it only while `guard_version` still gives
/// that version. Then a wrong password is a plain `WrongPassword`, found
/// on the device, and never spends an attempt at the realms. Go to the
/// realms only without a kept `G` or after a version change (guard
/// renewed or password changed on another device): retrying a typo there
/// would burn the realm counters, which erase the guard for good at the
/// limit.
#[uniffi::export]
pub fn unlock_with_password_guarded(
    db_path: String,
    password: String,
    secret_key: String,
    guard: Option<Vec<u8>>,
    transport: Option<Arc<dyn FfiRealmTransport>>,
) -> Result<FfiGuardUnlocked, OnePassError> {
    let password = Zeroizing::new(password);
    let secret_key = SecretKey::parse(&Zeroizing::new(secret_key))?;
    let guard = guard.map(Zeroizing::new);
    let kept = guard.as_deref().map(|g| guard_of(g)).transpose()?;
    let realms = realms();
    let transport = transport.map(Transport);
    let access = access_of(kept.as_ref(), transport.as_ref(), &realms);
    let store = open_store(&db_path)?;
    let device = store.device_state()?;
    let (mut repo, auk, g) =
        Repository::unlock_guarded(store, &password, &secret_key, device, access)?;
    repo.persist_device_state()?;
    Ok(FfiGuardUnlocked {
        session: Session::new(repo)?,
        auk: auk.as_bytes().to_vec(),
        guard: g.map(|g| g.expose().to_vec()),
    })
}

/// The guard version in the store's newest account parameters, read
/// without any key: `None` when the account is not guarded. Unverified
/// (the unlock checks the signature): it only tells the app whether its
/// kept `G` is still current, so that a wrong password is never sent to
/// the realms.
#[uniffi::export]
pub fn guard_version(db_path: String) -> Result<Option<u32>, OnePassError> {
    let store = open_store(&db_path)?;
    let records = store.list(RecordKind::AccountParams)?;
    let Some(newest) = records.iter().max_by_key(|r| r.version) else {
        return Ok(None);
    };
    let params = AccountParams::decode(&newest.data)?;
    Ok(params.guard.map(|g| g.descriptor.version))
}

/// `verify_password` on a guarded account, with the `G` this device kept:
/// the Account Unlock Key, no session, no device state written, and never
/// a call to the realms (a local check must not spend their attempts).
/// An unguarded account ignores `guard`.
#[uniffi::export]
pub fn verify_password_guarded(
    db_path: String,
    password: String,
    secret_key: String,
    guard: Vec<u8>,
) -> Result<Vec<u8>, OnePassError> {
    let password = Zeroizing::new(password);
    let secret_key = SecretKey::parse(&Zeroizing::new(secret_key))?;
    let guard = guard_of(&Zeroizing::new(guard))?;
    let store = open_store(&db_path)?;
    let device = store.device_state()?;
    let (repo, auk, _) = Repository::unlock_guarded(
        store,
        &password,
        &secret_key,
        device,
        GuardAccess::Secret(&guard),
    )?;
    drop(repo);
    Ok(auk.as_bytes().to_vec())
}

/// `restore_from_kit` on an account that may be guarded (spec 7.2): `G`
/// from the realms. A wrong password costs one attempt and is
/// `GuardWrongPassword { remaining }`.
#[uniffi::export]
#[allow(clippy::too_many_arguments)]
pub fn restore_from_kit_guarded(
    db_path: String,
    password: String,
    secret_key: String,
    classical: Vec<u8>,
    pq: Arc<dyn FfiPqDeviceHalf>,
    name: String,
    kind: FfiDeviceKind,
    mode: FfiDeviceMode,
    transport: Arc<dyn FfiRealmTransport>,
) -> Result<Arc<Session>, OnePassError> {
    let password = Zeroizing::new(password);
    let classical = Zeroizing::new(classical);
    let secret_key = SecretKey::parse(&Zeroizing::new(secret_key))?;
    let keys = device_keys(&classical, pq)?;
    let realms = realms();
    let transport = Transport(transport);
    let store = open_store(&db_path)?;
    let device = store.device_state()?;
    let mut repo = Repository::restore_from_kit_guarded(
        store,
        KitRestore {
            password: &password,
            secret_key: &secret_key,
            device_keys: &keys,
            name: &name,
            kind: kind.into(),
            mode: mode.into(),
            device,
        },
        GuardAccess::Realms {
            transport: &transport,
            pinned: &realms,
        },
    )?;
    repo.persist_device_state()?;
    Session::new(repo)
}

fn access_of<'a>(
    kept: Option<&'a GuardSecret>,
    transport: Option<&'a Transport>,
    realms: &'a [RealmInfo],
) -> GuardAccess<'a> {
    match (kept, transport) {
        (Some(g), _) => GuardAccess::Secret(g),
        (None, Some(t)) => GuardAccess::Realms {
            transport: t,
            pinned: realms,
        },
        (None, None) => GuardAccess::None,
    }
}

#[uniffi::export]
impl Session {
    /// Off or on, and whether this build can turn it on (spec 9).
    pub fn guard_state(&self) -> Result<FfiGuardState, OnePassError> {
        let realms = realms();
        self.with(|repo| Ok(state_of(repo.guard_state(&realms), &realms)))
    }

    /// `G` of a guarded account (for the device's secure storage), `None`
    /// when the guard is off.
    pub fn guard_secret(&self) -> Result<Option<Vec<u8>>, OnePassError> {
        self.with(|repo| Ok(repo.guard_secret()?.map(|g| g.expose().to_vec())))
    }

    /// Turn the guard on (spec 8.1), after the password and the Secret Key.
    /// Registers at every realm (all must answer), then writes. The app
    /// then offers a new Emergency Kit (spec 9 copy).
    pub fn enable_guard(
        &self,
        password: String,
        secret_key: String,
        transport: Arc<dyn FfiRealmTransport>,
    ) -> Result<FfiGuardChange, OnePassError> {
        let password = Zeroizing::new(password);
        let secret_key = SecretKey::parse(&Zeroizing::new(secret_key))?;
        let realms = realms();
        let transport = Transport(transport);
        self.with(|repo| {
            let (auk, g) = repo.enable_guard(&password, &secret_key, &transport, &realms)?;
            Ok(FfiGuardChange {
                auk: auk.as_bytes().to_vec(),
                guard: g.expose().to_vec(),
            })
        })
    }

    /// Register again (spec 8.3, 8.4): `new_guard` false keeps `G` (realm
    /// list change, a realm that lost it), true draws a new one (CLI
    /// `guard rotate`). The old version is deleted at the realms.
    pub fn renew_guard(
        &self,
        password: String,
        secret_key: String,
        transport: Arc<dyn FfiRealmTransport>,
        new_guard: bool,
    ) -> Result<FfiGuardChange, OnePassError> {
        let password = Zeroizing::new(password);
        let secret_key = SecretKey::parse(&Zeroizing::new(secret_key))?;
        let realms = realms();
        let transport = Transport(transport);
        self.with(|repo| {
            let (auk, g) =
                repo.renew_guard(&password, &secret_key, &transport, &realms, new_guard)?;
            Ok(FfiGuardChange {
                auk: auk.as_bytes().to_vec(),
                guard: g.expose().to_vec(),
            })
        })
    }

    /// Turn the guard off (spec 9): the keyset back under the password and
    /// the Secret Key alone, the guard deleted at the realms. Returns the
    /// new Account Unlock Key; the app erases its kept `G`.
    pub fn disable_guard(
        &self,
        password: String,
        secret_key: String,
        transport: Arc<dyn FfiRealmTransport>,
    ) -> Result<Vec<u8>, OnePassError> {
        let password = Zeroizing::new(password);
        let secret_key = SecretKey::parse(&Zeroizing::new(secret_key))?;
        let realms = realms();
        let transport = Transport(transport);
        self.with(|repo| {
            let auk = repo.disable_guard(&password, &secret_key, &transport, &realms)?;
            Ok(auk.as_bytes().to_vec())
        })
    }

    /// `change_password` on an account that may be guarded (spec 8.2): a
    /// guarded one registers `G` again for the new password. Returns the
    /// new Account Unlock Key.
    pub fn change_password_guarded(
        &self,
        current: String,
        secret_key: String,
        new: String,
        transport: Arc<dyn FfiRealmTransport>,
    ) -> Result<Vec<u8>, OnePassError> {
        let (current, new) = (Zeroizing::new(current), Zeroizing::new(new));
        let secret_key = SecretKey::parse(&Zeroizing::new(secret_key))?;
        let realms = realms();
        let transport = Transport(transport);
        self.with(|repo| {
            let auk =
                repo.change_password_guarded(&current, &secret_key, &new, &transport, &realms)?;
            Ok(auk.as_bytes().to_vec())
        })
    }

    /// Poll the realms with the owner key (spec 8.4), at most once a day
    /// and after each sync. Off: an empty report.
    pub fn guard_health(
        &self,
        transport: Arc<dyn FfiRealmTransport>,
    ) -> Result<FfiGuardHealth, OnePassError> {
        let realms = realms();
        let transport = Transport(transport);
        self.with(|repo| {
            let h = repo.guard_health(&transport, &realms)?;
            Ok(FfiGuardHealth {
                failures: h.failures.clone(),
                needs_renewal: h.needs_renewal,
                realms_answered: u8::try_from(
                    h.realms.iter().filter(|r| r.status.is_some()).count(),
                )
                .unwrap_or(u8::MAX),
                realms_total: u8::try_from(h.realms.len()).unwrap_or(u8::MAX),
            })
        })
    }
}

#[cfg(feature = "dev-fast-kdf")]
pub use test_net::FfiTestRealmNet;

/// Tests only (`dev-fast-kdf`): three realms in this process, pinned in
/// place of the build's list while the network lives, for the Swift and
/// Kotlin tests of the guard screens. Never in a shipped build.
#[cfg(feature = "dev-fast-kdf")]
pub(crate) mod test_net {
    use std::sync::{Arc, Mutex};

    use onepass_core::guarded_kit::RealmInfo;
    use onepass_core::guarded_kit::realm::{DEFAULT_LIMIT, MemoryRealmStore, Realm};

    use super::FfiRealmTransport;
    use crate::error::OnePassError;

    static REALMS: Mutex<Option<Vec<RealmInfo>>> = Mutex::new(None);

    pub(crate) fn realms() -> Option<Vec<RealmInfo>> {
        REALMS.lock().ok()?.clone()
    }

    pub(crate) struct TestNet {
        realms: Vec<(String, Mutex<Realm<MemoryRealmStore>>)>,
        down: Mutex<Vec<u8>>,
    }

    impl FfiRealmTransport for TestNet {
        fn call(&self, url: String, request: Vec<u8>) -> Result<Vec<u8>, OnePassError> {
            let i = self
                .realms
                .iter()
                .position(|(u, _)| *u == url)
                .ok_or(OnePassError::NotFound)?;
            if self
                .down
                .lock()
                .map_err(|_| OnePassError::Store)?
                .contains(&(i as u8))
            {
                return Err(OnePassError::NotFound);
            }
            let mut r = self.realms[i].1.lock().map_err(|_| OnePassError::Store)?;
            r.handle(&request, 1_800_000_000)
                .map_err(|_| OnePassError::Crypto)
        }
    }

    /// The test network as the app sees it, with a switch to take realms
    /// down.
    #[derive(uniffi::Object)]
    pub struct FfiTestRealmNet {
        net: Arc<TestNet>,
    }

    #[uniffi::export]
    impl FfiTestRealmNet {
        /// Three fresh realms, pinned for this process from now on.
        #[uniffi::constructor]
        pub fn new() -> Result<Arc<FfiTestRealmNet>, OnePassError> {
            let mut realms = Vec::new();
            let mut infos = Vec::new();
            for i in 0..3u8 {
                let r = Realm::new([i + 1; 32], DEFAULT_LIMIT, MemoryRealmStore::default());
                let url = format!("https://realm-{i}.test");
                infos.push(RealmInfo {
                    id: [i + 10; 16],
                    url: url.clone(),
                    response_key: r.response_key().map_err(|_| OnePassError::Crypto)?,
                });
                realms.push((url, Mutex::new(r)));
            }
            *REALMS.lock().map_err(|_| OnePassError::Store)? = Some(infos);
            Ok(Arc::new(FfiTestRealmNet {
                net: Arc::new(TestNet {
                    realms,
                    down: Mutex::new(Vec::new()),
                }),
            }))
        }

        /// The transport to hand to the guard calls.
        pub fn transport(&self) -> Arc<dyn FfiRealmTransport> {
            self.net.clone()
        }

        /// Realm `index` (0 to 2) stops answering, or answers again.
        pub fn set_down(&self, index: u8, down: bool) -> Result<(), OnePassError> {
            let mut d = self.net.down.lock().map_err(|_| OnePassError::Store)?;
            d.retain(|i| *i != index);
            if down {
                d.push(index);
            }
            Ok(())
        }
    }
}
