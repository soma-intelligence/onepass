//! Security hardening surface (additive): restore epochs and their safe
//! exits, per-vault sync health, the encrypted export of the local state,
//! and byte variants of the calls that take the master password, so Swift
//! can hand over a buffer it wipes instead of an immutable `String`.

use onepass_core::archive::{self, ArchivedVault};
use onepass_core::crypto::KdfParams;
use onepass_core::epoch::EpochReason;
use onepass_core::sync::VaultSyncHealth;
use zeroize::Zeroizing;

use crate::convert::id_hex;
use crate::error::{OnePassError, integrity_kind, invalid};
use crate::session::Session;
use crate::types::{FfiCreatedAccount, FfiKdfParams, FfiUnlocked};
use crate::{create, kdf_params, unlock_password, verify};

/// Why a restore epoch is issued.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiEpochReason {
    /// A backup was restored.
    Restore,
    /// Safe exit after an alert: this device's copies win.
    KeepThisDevice,
    /// Safe exit after an alert: the server's state wins.
    TakeServer,
}

impl From<FfiEpochReason> for EpochReason {
    fn from(r: FfiEpochReason) -> Self {
        match r {
            FfiEpochReason::Restore => EpochReason::Restore,
            FfiEpochReason::KeepThisDevice => EpochReason::KeepThisDevice,
            FfiEpochReason::TakeServer => EpochReason::TakeServer,
        }
    }
}

/// The sync state of one vault.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum FfiHealthState {
    /// The server serves a state at least as new as this device's.
    Ok,
    /// The server serves an older or incomplete state; this device serves
    /// its own verified copy and sends it again. `since`: Unix seconds of
    /// the first sync round that counted it (0 until one did); `rounds`:
    /// rounds counted since.
    ServerBehind { since: i64, rounds: u32 },
    /// An integrity alert (`kind` as in `OnePassError::Integrity`): the
    /// server stayed behind past the thresholds, or forked. The app offers
    /// the safe exits (`keep_this_device`, `take_server`).
    Alert { kind: String },
}

impl From<VaultSyncHealth> for FfiHealthState {
    fn from(h: VaultSyncHealth) -> Self {
        match h {
            VaultSyncHealth::Ok => Self::Ok,
            VaultSyncHealth::ServerBehind { since, rounds } => Self::ServerBehind { since, rounds },
            VaultSyncHealth::Alert(e) => Self::Alert {
                kind: integrity_kind(e).to_owned(),
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiVaultHealth {
    pub vault_id: String,
    pub state: FfiHealthState,
}

/// What `Session::rebase_with_report` did: the vaults rebased (refresh
/// them) even when an error follows; `conflict` is true when this device's
/// restore epoch lost a race and was dropped (sync, then issue it again).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiRebaseReport {
    pub rebased: Vec<String>,
    pub conflict: bool,
    pub error: Option<OnePassError>,
}

/// A secret handed over as bytes, wiped on drop, read as UTF-8 in place.
/// Invalid UTF-8 is `InvalidInput { what }`.
fn utf8<'a>(bytes: &'a Zeroizing<Vec<u8>>, what: &str) -> Result<&'a str, OnePassError> {
    std::str::from_utf8(bytes).map_err(|_| invalid(what))
}

#[uniffi::export]
impl Session {
    /// Issue a restore epoch over the current state (strict: every vault
    /// and the stored epoch must pass their checks). Returns its number.
    /// For the safe exits after an alert, see `keep_this_device` and
    /// `take_server`.
    pub fn issue_restore_epoch(&self, reason: FfiEpochReason) -> Result<u64, OnePassError> {
        self.with(|repo| Ok(repo.issue_restore_epoch(reason.into())?.epoch))
    }

    /// Safe exit "keep this device": an epoch whose heads are the copies
    /// this device serves, pushed over the server's where it is behind or
    /// forked. Returns the epoch number.
    pub fn keep_this_device(&self) -> Result<u64, OnePassError> {
        self.with(|repo| {
            Ok(repo
                .issue_restore_epoch_from_local(EpochReason::KeepThisDevice)?
                .epoch)
        })
    }

    /// Safe exit "take the server's version". Destructive: every local
    /// write not pushed yet is dropped. Export first
    /// (`export_encrypted_backup`). Returns the epoch number.
    pub fn take_server(&self) -> Result<u64, OnePassError> {
        self.with(|repo| Ok(repo.issue_restore_epoch_take_server()?.epoch))
    }

    /// The restore epoch this device accepted last, `None` before any (or
    /// while locked). A plain read of the device state under the lock: it
    /// writes nothing, so no store error can turn into a silent `None`.
    pub fn restore_epoch(&self) -> Option<u64> {
        self.guard().as_ref().and_then(|repo| repo.restore_epoch())
    }

    /// The sync health of every vault, in vault id order.
    pub fn sync_health(&self) -> Result<Vec<FfiVaultHealth>, OnePassError> {
        self.with(|repo| {
            Ok(repo
                .sync_health()?
                .into_iter()
                .map(|(id, h)| FfiVaultHealth {
                    vault_id: id_hex(id),
                    state: h.into(),
                })
                .collect())
        })
    }

    /// Whether "keep this device" has anything to push over the server's
    /// (a fork, a vault in alert, or one the server went back on): offer or
    /// re-issue the exit only then. False while another device's newer
    /// write is not fully served yet. A read: nothing is written.
    pub fn keep_needed(&self) -> Result<bool, OnePassError> {
        let guard = self.guard();
        let repo = guard.as_ref().ok_or(OnePassError::Locked)?;
        Ok(repo.keep_needed()?)
    }

    /// Forget the sync health of every vault, after the owner chose to:
    /// the way out of an unreadable health map (`sync_health` failing) that
    /// discards no data. The next rounds recount.
    pub fn reset_sync_health(&self) -> Result<(), OnePassError> {
        self.with(|repo| Ok(repo.reset_sync_health()?))
    }

    /// The end of a sync round (after fetch, rebase and push) at `now`,
    /// Unix seconds: counts one round for every vault still behind.
    pub fn note_sync_round(&self, now: i64) -> Result<(), OnePassError> {
        self.with(|repo| Ok(repo.note_sync_round(now)?))
    }

    /// `rebase_all`, reporting the vaults rebased along with the error
    /// instead of either one. `Err` only for what stops the rebase before
    /// any vault.
    pub fn rebase_with_report(&self) -> Result<FfiRebaseReport, OnePassError> {
        self.with(|repo| {
            let report = repo.rebase_report()?;
            let error = report.error.map(OnePassError::from);
            Ok(FfiRebaseReport {
                rebased: report.rebased.into_iter().map(id_hex).collect(),
                conflict: error == Some(OnePassError::Conflict),
                error,
            })
        })
    }

    /// An encrypted OnePass backup of the local state this device serves
    /// (every vault, trashed and archived items included): signed by the
    /// account, readable with the account or with `passphrase` (UTF-8,
    /// zxcvbn score at least 3, wiped here). Argon2id at the floor.
    pub fn export_encrypted_backup(&self, passphrase: Vec<u8>) -> Result<Vec<u8>, OnePassError> {
        let passphrase = Zeroizing::new(passphrase);
        self.backup(&passphrase, KdfParams::new_default()?)
    }

    /// `export_encrypted_backup` with explicit Argon2id parameters for the
    /// passphrase. The core refuses parameters under its floor, except in
    /// debug builds with the `dev-fast-kdf` feature (tests).
    pub fn export_encrypted_backup_with_kdf(
        &self,
        passphrase: Vec<u8>,
        kdf: FfiKdfParams,
    ) -> Result<Vec<u8>, OnePassError> {
        let passphrase = Zeroizing::new(passphrase);
        self.backup(&passphrase, kdf_params(kdf)?)
    }
}

impl Session {
    fn backup(
        &self,
        passphrase: &Zeroizing<Vec<u8>>,
        kdf: KdfParams,
    ) -> Result<Vec<u8>, OnePassError> {
        let passphrase = utf8(passphrase, "passphrase")?;
        self.with(|repo| {
            let mut vaults = Vec::new();
            for v in repo.vaults()? {
                let items = repo.items(&v)?;
                vaults.push(ArchivedVault {
                    id: v.id,
                    meta: v.meta,
                    items,
                });
            }
            Ok(archive::backup(
                repo.account(),
                vaults,
                Some((passphrase, kdf.clone())),
            )?)
        })
    }
}

/// `create_account` with the password as UTF-8 bytes, wiped here.
#[uniffi::export]
pub fn create_account_bytes(
    db_path: String,
    password: Vec<u8>,
) -> Result<FfiCreatedAccount, OnePassError> {
    let password = Zeroizing::new(password);
    let password = utf8(&password, "password")?;
    create(&db_path, password, KdfParams::new_default()?)
}

/// `create_account_with_kdf` with the password as UTF-8 bytes, wiped here.
#[uniffi::export]
pub fn create_account_with_kdf_bytes(
    db_path: String,
    password: Vec<u8>,
    kdf: FfiKdfParams,
) -> Result<FfiCreatedAccount, OnePassError> {
    let password = Zeroizing::new(password);
    let password = utf8(&password, "password")?;
    create(&db_path, password, kdf_params(kdf)?)
}

/// `unlock_with_password` with the password and Secret Key as UTF-8 bytes,
/// wiped here.
#[uniffi::export]
pub fn unlock_with_password_bytes(
    db_path: String,
    password: Vec<u8>,
    secret_key: Vec<u8>,
) -> Result<FfiUnlocked, OnePassError> {
    let (password, secret_key) = (Zeroizing::new(password), Zeroizing::new(secret_key));
    unlock_password(
        &db_path,
        utf8(&password, "password")?,
        utf8(&secret_key, "secret key checksum")?,
    )
}

/// `verify_password` with the password and Secret Key as UTF-8 bytes,
/// wiped here.
#[uniffi::export]
pub fn verify_password_bytes(
    db_path: String,
    password: Vec<u8>,
    secret_key: Vec<u8>,
) -> Result<Vec<u8>, OnePassError> {
    let (password, secret_key) = (Zeroizing::new(password), Zeroizing::new(secret_key));
    verify(
        &db_path,
        utf8(&password, "password")?,
        utf8(&secret_key, "secret key checksum")?,
    )
}
