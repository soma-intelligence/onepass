//! Guarded Kit on the repository (spec `2026-11-20-guarded-kit-design.md`,
//! sections 7.1, 8 and 9): turn the guard on or off, renew it, change the
//! master password of a guarded account, poll the realms.
//!
//! Every change follows the same order:
//! 1. the current password and Secret Key are checked by opening the stored
//!    records with every unlock check (pin, pinned epoch, floors), `G`
//!    coming from the params themselves (`Account::guard`);
//! 2. the new guard, if any, is registered at every realm;
//! 3. the params (with the guard) and the keyset (under `AUK_v2`, or
//!    `AUK_v1` when the guard goes off) are written together, conditional
//!    on the versions read (`commit_rekeyed`): a lost race is `Conflict`
//!    and the previous pair stays;
//! 4. the guard replaced, if any, is deleted at the realms with its owner
//!    key, best effort: a realm out of reach keeps a record no one can
//!    locate without the old Secret Key and password, and the counts the
//!    old record reports.
//!
//! A registration that fails (a realm down, a refusal) writes nothing: the
//! records already made at the other realms are left, unlocatable.
//!
//! The realms are the ones this build pins (`guarded_kit::pinned_realms`);
//! the functions take them as an argument so tests run in-process realms.

use super::Repository;
use crate::account::Account;
use crate::account::Auk;
use crate::crypto::{SecretKey, guard_input, stretch_password};
use crate::guarded_kit::{
    DEFAULT_THRESHOLD, GuardAccess, GuardDescriptor, GuardError, GuardSecret, GuardState,
    GuardStatus, Locator, RealmInfo, RealmTransport, delete, register, status,
};
use crate::store::{Record, RecordKind, RecordStore};
use crate::{Error, Result};

/// One realm's answer to the owner poll (spec 8.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealmGuardStatus {
    pub realm_id: [u8; 16],
    /// `None`: the realm did not answer (or not with its pinned key).
    pub status: Option<GuardStatus>,
}

impl RealmGuardStatus {
    /// Failed restore attempts this realm logged (Unix seconds), the alert
    /// of spec 8.4.
    pub fn failures(&self) -> &[u64] {
        match &self.status {
            Some(GuardStatus::Active { failures, .. }) => failures,
            _ => &[],
        }
    }
}

/// What the settings screen shows of the polls: the alert, and whether a
/// realm lost the guard (spec 8.4: re-register from this device).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardHealth {
    pub realms: Vec<RealmGuardStatus>,
    /// Every failure logged, newest first.
    pub failures: Vec<u64>,
    /// A realm says the guard is gone (burnt, or lost): renew it.
    pub needs_renewal: bool,
}

/// The guard a change registers: `G` and its locator.
type Registered = (GuardDescriptor, Locator);

impl<S: RecordStore> Repository<S> {
    /// Off, or on with its version and threshold (spec 9).
    pub fn guard_state(&self, pinned: &[RealmInfo]) -> GuardState {
        match &self.account.params.guard {
            None => GuardState::Off,
            Some(g) => g.state(pinned),
        }
    }

    /// The guard `G`, for the device to keep in its secure storage (then
    /// `GuardAccess::Secret` at the next unlock with the password). `None`
    /// when the guard is off.
    pub fn guard_secret(&self) -> Result<Option<GuardSecret>> {
        Ok(self.account.guard()?.map(|(g, _)| g))
    }

    /// Turn the guard on (spec 8.1): a new `G`, registered at every realm
    /// of `realms`, then params v3 and the keyset under `AUK_v2`. Returns
    /// the new Account Unlock Key (biometrics enroll again) and `G` (the
    /// device keeps it). Refused when the guard is already on
    /// (`Validation("guard")`: renew it instead).
    pub fn enable_guard(
        &mut self,
        password: &str,
        secret_key: &SecretKey,
        transport: &dyn RealmTransport,
        realms: &[RealmInfo],
    ) -> Result<(Auk, GuardSecret)> {
        if self.account.params.guard.is_some() {
            return Err(refused("already on"));
        }
        self.put_guard(
            password,
            secret_key,
            transport,
            realms,
            GuardSecret::generate()?,
        )
    }

    /// Register the guard again (spec 8.3, 8.4; CLI `guard rotate`):
    /// - `new_guard = false`: the same `G` under a new version, after a
    ///   realm list change or a realm that lost it; no new kit needed;
    /// - `new_guard = true`: a new `G`, so a device that kept the old one
    ///   (or anyone who saw it) loses the owner rights.
    ///
    /// The old version is deleted at the realms afterwards. Refused when
    /// the guard is off.
    pub fn renew_guard(
        &mut self,
        password: &str,
        secret_key: &SecretKey,
        transport: &dyn RealmTransport,
        realms: &[RealmInfo],
        new_guard: bool,
    ) -> Result<(Auk, GuardSecret)> {
        let Some((g, _)) = self.account.guard()? else {
            return Err(refused("off"));
        };
        let g = if new_guard {
            GuardSecret::generate()?
        } else {
            g
        };
        self.put_guard(password, secret_key, transport, realms, g)
    }

    /// Turn the guard off (spec 9, CLI `guard disable`): params without it,
    /// the keyset back under `AUK_v1`, then the guard deleted at the realms
    /// of `pinned`. Returns the new Account Unlock Key. Refused when the
    /// guard is off.
    pub fn disable_guard(
        &mut self,
        password: &str,
        secret_key: &SecretKey,
        transport: &dyn RealmTransport,
        pinned: &[RealmInfo],
    ) -> Result<Auk> {
        self.writable()?;
        let Some(old) = self.account.guard()? else {
            return Err(refused("off"));
        };
        let (params, keyset, stored, stretched) = self.open_stored(password, secret_key, &old.0)?;
        let rekeyed = stored.reguard(&stretched, secret_key, None)?;
        let auk = self.commit_rekeyed(&params, &keyset, rekeyed)?;
        let _ = delete(transport, pinned, &old.1, &old.0);
        Ok(auk)
    }

    /// Change the master password of a guarded account (spec 8.2): the new
    /// password gives a new guard input, so `G` is registered again for it
    /// (new version) before the params and keyset are written; the old
    /// version is deleted afterwards. An unguarded account takes
    /// `change_password`.
    pub fn change_password_guarded(
        &mut self,
        current: &str,
        secret_key: &SecretKey,
        new: &str,
        transport: &dyn RealmTransport,
        realms: &[RealmInfo],
    ) -> Result<Auk> {
        let Some((g, old_locator)) = self.account.guard()? else {
            return self.change_password(current, secret_key, new);
        };
        self.writable()?;
        let (params, keyset, stored, _) = self.open_stored(current, secret_key, &g)?;
        let version = next_version(&old_locator)?;
        let account_id = stored.params.account_id;
        let mut reg = |x: &[u8; 32]| -> Result<Registered> {
            register_guard(transport, realms, x, &g, version, secret_key, account_id)
        };
        let rekeyed = stored.rekey_with(secret_key, new, Some((&g, &mut reg)))?;
        let auk = self.commit_rekeyed(&params, &keyset, rekeyed)?;
        let _ = delete(transport, realms, &old_locator, &g);
        Ok(auk)
    }

    /// Poll every realm of the guard with the owner key (spec 8.4): the
    /// failures logged, and whether a realm lost the guard. Off: an empty
    /// report.
    pub fn guard_health(
        &self,
        transport: &dyn RealmTransport,
        pinned: &[RealmInfo],
    ) -> Result<GuardHealth> {
        let Some((g, locator)) = self.account.guard()? else {
            return Ok(GuardHealth {
                realms: Vec::new(),
                failures: Vec::new(),
                needs_renewal: false,
            });
        };
        let mut realms = Vec::new();
        for p in &locator.placements {
            let Some(realm) = pinned.iter().find(|r| r.id == p.realm_id) else {
                continue;
            };
            realms.push(RealmGuardStatus {
                realm_id: p.realm_id,
                status: status(transport, realm, &p.guard_id, &g).ok(),
            });
        }
        let mut failures: Vec<u64> = realms
            .iter()
            .flat_map(|r| r.failures().iter().copied())
            .collect();
        failures.sort_unstable_by(|a, b| b.cmp(a));
        failures.dedup();
        let needs_renewal = realms.iter().any(|r| r.status == Some(GuardStatus::Gone))
            || locator.placements.len() > realms.len();
        Ok(GuardHealth {
            realms,
            failures,
            needs_renewal,
        })
    }

    /// Register `g` at `realms` for the current password and write params
    /// and keyset; delete the version it replaces, if any.
    fn put_guard(
        &mut self,
        password: &str,
        secret_key: &SecretKey,
        transport: &dyn RealmTransport,
        realms: &[RealmInfo],
        g: GuardSecret,
    ) -> Result<(Auk, GuardSecret)> {
        self.writable()?;
        let old = self.account.guard()?;
        let (params, keyset, stored, stretched) = match &old {
            Some((old_g, _)) => self.open_stored(password, secret_key, old_g)?,
            None => self.open_stored_unguarded(password, secret_key)?,
        };
        let version = match &old {
            Some((_, l)) => next_version(l)?,
            None => 1,
        };
        let x = guard_input(&stretched, &stored.params.kdf)?;
        let account_id = stored.params.account_id;
        let (descriptor, locator) =
            register_guard(transport, realms, &x, &g, version, secret_key, account_id)?;
        let rekeyed = stored.reguard(&stretched, secret_key, Some((&g, descriptor, &locator)))?;
        let auk = self.commit_rekeyed(&params, &keyset, rekeyed)?;
        if let Some((old_g, old_locator)) = &old {
            let _ = delete(transport, realms, old_locator, old_g);
        }
        Ok((auk, g))
    }

    /// The session identity's records, opened with the password, the
    /// Secret Key and `g` (unlock checks included), and the stretched
    /// password under the stored params.
    fn open_stored(
        &self,
        password: &str,
        secret_key: &SecretKey,
        g: &GuardSecret,
    ) -> Result<(Record, Record, Account, zeroize::Zeroizing<[u8; 32]>)> {
        let (params, keyset) = self.session_records()?;
        let (stored, _, _) = Account::unlock_guarded_at(
            password,
            secret_key,
            &params.data,
            &keyset.data,
            self.device.pinned.as_ref(),
            self.chain.params_epoch,
            GuardAccess::Secret(g),
        )?;
        let stretched = stretch_password(password, &stored.params.kdf)?;
        Ok((params, keyset, stored, stretched))
    }

    fn open_stored_unguarded(
        &self,
        password: &str,
        secret_key: &SecretKey,
    ) -> Result<(Record, Record, Account, zeroize::Zeroizing<[u8; 32]>)> {
        let (params, keyset) = self.session_records()?;
        let (stored, _, _) = Account::unlock_guarded_at(
            password,
            secret_key,
            &params.data,
            &keyset.data,
            self.device.pinned.as_ref(),
            self.chain.params_epoch,
            GuardAccess::None,
        )?;
        let stretched = stretch_password(password, &stored.params.kdf)?;
        Ok((params, keyset, stored, stretched))
    }

    fn session_records(&self) -> Result<(Record, Record)> {
        let params = self
            .store
            .get(RecordKind::AccountParams, self.records_id)?
            .ok_or(Error::NotFound)?;
        let keyset = self
            .store
            .get(RecordKind::Keyset, self.records_id)?
            .ok_or(Error::NotFound)?;
        Ok((params, keyset))
    }
}

fn register_guard(
    transport: &dyn RealmTransport,
    realms: &[RealmInfo],
    x: &[u8; 32],
    g: &GuardSecret,
    version: u32,
    secret_key: &SecretKey,
    account_id: crate::Id,
) -> Result<Registered> {
    if realms.is_empty() {
        return Err(GuardError::Config("no realm pinned").into());
    }
    let locator = register(transport, realms, DEFAULT_THRESHOLD, x, g, version)?;
    let descriptor = GuardDescriptor::seal(secret_key, account_id, realms, &locator)?;
    Ok((descriptor, locator))
}

fn next_version(locator: &Locator) -> Result<u32> {
    locator
        .version
        .checked_add(1)
        .ok_or(Error::InvalidFormat("guard version"))
}

fn refused(reason: &'static str) -> Error {
    crate::ValidationError {
        field: "guard".into(),
        reason,
    }
    .into()
}
