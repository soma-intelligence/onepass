//! The error type crossing the FFI. Never carries a field value.

use std::fmt;

use onepass_core::{Error, IntegrityError};

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Error)]
pub enum OnePassError {
    WrongPassword,
    NotFound,
    Conflict,
    Locked,
    Validation { field: String, reason: String },
    Integrity { kind: String },
    InvalidInput { what: String },
    Store,
    Crypto,
    PasskeyExcluded,
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
            Error::Validation(v) => Self::Validation {
                field: v.field,
                reason: v.reason.to_owned(),
            },
            Error::NotFound => Self::NotFound,
            Error::Conflict => Self::Conflict,
            Error::Store(_) => Self::Store,
        }
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
