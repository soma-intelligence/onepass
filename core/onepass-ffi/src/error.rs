//! The error type crossing the FFI. Never carries a field value.

use std::fmt;

use onepass_core::{Error, IntegrityError};

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Error)]
pub enum OnePassError {
    WrongPassword,
    NotFound,
    Conflict,
    Locked,
    Validation {
        field: String,
        reason: String,
    },
    Integrity {
        kind: String,
    },
    InvalidInput {
        what: String,
    },
    Store,
    Crypto,
    PasskeyExcluded,
    /// Key rotation v2 (spec 8.1, R10): a rotation waits for the user's
    /// answer ("C'est moi" or "Ce n'était pas moi"): the device reads, it
    /// writes nothing. The app shows the confirmation screen
    /// (`pending_rotation`) and the banner "Lecture seule jusqu'à ta
    /// réponse".
    ReadOnly,
    /// An Emergency Kit made before a rotation (spec 7.5 step 4, R14): the
    /// keys changed on `rotator` (this device's local name for it, or "un
    /// autre appareil", never a name read from the server) at `at` (Unix
    /// seconds). Nothing was restored.
    OutdatedKit {
        rotator: String,
        at: i64,
    },
    /// The operation needs this device `Current` and a rotation is under
    /// way: a rotation waits for the user's answer (answer it first), this
    /// device still pushes its own rotation, or replays its own writes
    /// under the new keys (sync first, then retry).
    RotationPending,
    /// A valid lineage record revokes this device (spec 8.4): locked, it is
    /// erased 7 days after it first read it unless the user answers "Ce
    /// n'était pas moi" (`quarantine_tick`, `quarantine_resolve`).
    Quarantined,
    /// A valid lineage record does not list this device (spec 8.1): it
    /// reads, it writes nothing; its exits are "Ce n'était pas moi", a
    /// re-pair or the Emergency Kit.
    Orphaned,
    /// This session is open on an identity the device left (it followed a
    /// rotation in another session or process): lock and unlock again,
    /// never retry the call (Task 8).
    IdentityLeft,
    /// The remote unlock envelope `C` no longer opens the account (master
    /// password changed elsewhere): erase it and enroll again.
    RemoteUnlockStale,
}

impl fmt::Display for OnePassError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongPassword => f.write_str("wrong password or secret key"),
            Self::NotFound => f.write_str("not found"),
            Self::Conflict => f.write_str("concurrent write, retry"),
            Self::Locked => f.write_str("locked"),
            Self::Validation { field, reason } => write!(f, "invalid {field}: {reason}"),
            Self::Integrity { kind } => write!(f, "integrity check failed: {kind}"),
            Self::InvalidInput { what } => write!(f, "invalid input: {what}"),
            Self::Store => f.write_str("store error"),
            Self::Crypto => f.write_str("cryptographic operation failed"),
            Self::PasskeyExcluded => {
                f.write_str("a passkey the relying party excluded already exists")
            }
            Self::ReadOnly => f.write_str("read only until the key rotation is answered"),
            Self::OutdatedKit { .. } => {
                f.write_str("emergency kit outdated: the keys changed since")
            }
            Self::RotationPending => f.write_str("a key rotation is under way"),
            Self::Quarantined => f.write_str("this device was removed from the account"),
            Self::Orphaned => f.write_str("this device is not in the account's keys"),
            Self::IdentityLeft => f.write_str("the account keys changed: lock and unlock"),
            Self::RemoteUnlockStale => f.write_str("remote unlock must be enrolled again"),
        }
    }
}

impl std::error::Error for OnePassError {}

pub(crate) fn integrity_kind(e: IntegrityError) -> &'static str {
    match e {
        IntegrityError::Commitment => "commitment",
        IntegrityError::Aead => "aead",
        IntegrityError::Signature => "signature",
        IntegrityError::ManifestRollback => "manifest_rollback",
        IntegrityError::ManifestMissingItem => "manifest_missing_item",
        IntegrityError::ManifestUnexpectedItem => "manifest_unexpected_item",
        IntegrityError::ManifestItemMismatch => "manifest_item_mismatch",
        IntegrityError::ParamsUnsigned => "params_unsigned",
        IntegrityError::ParamsDowngrade => "params_downgrade",
        IntegrityError::WrongKind => "wrong_kind",
        IntegrityError::WrongContext => "wrong_context",
        IntegrityError::VaultMissing => "vault_missing",
        IntegrityError::EpochRollback => "epoch_rollback",
        IntegrityError::ParamsRollback => "params_rollback",
        IntegrityError::DeviceListRollback => "device_list_rollback",
        IntegrityError::VaultListRollback => "vault_list_rollback",
        IntegrityError::RemoteSignature => "remote_signature",
        IntegrityError::RemoteExpired => "remote_expired",
        IntegrityError::RemoteReplay => "remote_replay",
        IntegrityError::RemoteUnknownDevice => "remote_unknown_device",
        IntegrityError::RemoteWrongRecipient => "remote_wrong_recipient",
        IntegrityError::RemoteUnknownRequest => "remote_unknown_request",
        IntegrityError::ContactBookRollback => "contact_book_rollback",
        IntegrityError::MembershipRollback => "membership_rollback",
        IntegrityError::MembershipFork => "membership_fork",
        IntegrityError::FamilyRollback => "family_rollback",
        IntegrityError::SyncHomeRollback => "sync_home_rollback",
    }
}

impl From<Error> for OnePassError {
    fn from(e: Error) -> Self {
        match e {
            Error::Crypto => Self::Crypto,
            Error::WrongPassword => Self::WrongPassword,
            Error::Integrity(i) => Self::Integrity {
                kind: integrity_kind(i).to_owned(),
            },
            Error::InvalidFormat(what) => Self::InvalidInput {
                what: what.to_owned(),
            },
            Error::NotFound => Self::NotFound,
            Error::Conflict => Self::Conflict,
            Error::Store(_) => Self::Store,
            // Refined by the session to `Orphaned` or `Quarantined` when
            // a lock makes it read-only (`Session::with`).
            Error::ReadOnly => Self::ReadOnly,
            Error::OutdatedKit { rotator, at } => Self::OutdatedKit { rotator, at },
            // The core's refusal of a quarantined device (spec 8.4).
            Error::Validation(v) if v.field == "device" && v.reason == "quarantined" => {
                Self::Quarantined
            }
            Error::Validation(v) => Self::Validation {
                field: v.field,
                reason: v.reason.to_owned(),
            },
        }
    }
}

/// A foreign `FfiPqDeviceHalf` that panicked or threw something other than
/// a `OnePassError`: a failed cryptographic operation, nothing written.
impl From<uniffi::UnexpectedUniFFICallbackError> for OnePassError {
    fn from(_: uniffi::UnexpectedUniFFICallbackError) -> Self {
        Self::Crypto
    }
}

pub(crate) fn invalid(what: &str) -> OnePassError {
    OnePassError::InvalidInput {
        what: what.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_detail_is_dropped() {
        let e: OnePassError = Error::Store("secret".into()).into();
        assert_eq!(e, OnePassError::Store);
        assert!(!format!("{e:?}{e}").contains("secret"));
    }

    /// Task 17: each new state of key rotation v2 has its own kind.
    #[test]
    fn rotation_errors_have_their_own_kinds() {
        assert_eq!(OnePassError::from(Error::ReadOnly), OnePassError::ReadOnly);
        assert_eq!(
            OnePassError::from(Error::OutdatedKit {
                rotator: "iPhone de Camille".into(),
                at: 42,
            }),
            OnePassError::OutdatedKit {
                rotator: "iPhone de Camille".into(),
                at: 42,
            }
        );
        let quarantined = onepass_core::ValidationError {
            field: "device".into(),
            reason: "quarantined",
        };
        assert_eq!(
            OnePassError::from(Error::Validation(quarantined)),
            OnePassError::Quarantined
        );
        let other = onepass_core::ValidationError {
            field: "device".into(),
            reason: "not current",
        };
        assert!(matches!(
            OnePassError::from(Error::Validation(other)),
            OnePassError::Validation { .. }
        ));
    }

    #[test]
    fn integrity_kinds_are_snake_case() {
        let e: OnePassError = Error::Integrity(IntegrityError::ManifestRollback).into();
        assert_eq!(
            e,
            OnePassError::Integrity {
                kind: "manifest_rollback".into()
            }
        );
        let e: OnePassError = Error::Integrity(IntegrityError::EpochRollback).into();
        assert_eq!(
            e,
            OnePassError::Integrity {
                kind: "epoch_rollback".into()
            }
        );
    }
}
