use std::fmt;

/// Which integrity check failed. Never carries data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegrityError {
    Commitment,
    Aead,
    Signature,
    ManifestRollback,
    ManifestMissingItem,
    ManifestUnexpectedItem,
    ManifestItemMismatch,
    ParamsUnsigned,
    ParamsDowngrade,
    WrongKind,
    WrongContext,
}

impl fmt::Display for IntegrityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Commitment => "key commitment mismatch",
            Self::Aead => "authenticated decryption failed",
            Self::Signature => "signature verification failed",
            Self::ManifestRollback => "manifest rollback detected",
            Self::ManifestMissingItem => "manifest lists an item that is missing",
            Self::ManifestUnexpectedItem => "item is not listed in the manifest",
            Self::ManifestItemMismatch => "item does not match the manifest",
            Self::ParamsUnsigned => "parameters are not signed",
            Self::ParamsDowngrade => "parameters downgrade detected",
            Self::WrongKind => "record has an unexpected kind",
            Self::WrongContext => "record is bound to a different context",
        };
        f.write_str(s)
    }
}

/// A rejected input. `field` names the field, never its value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationError {
    pub field: String,
    pub reason: &'static str,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid {}: {}", self.field, self.reason)
    }
}

impl std::error::Error for ValidationError {}

/// Library error. Messages never contain secrets or item content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Crypto,
    WrongPassword,
    Integrity(IntegrityError),
    InvalidFormat(&'static str),
    Validation(ValidationError),
    NotFound,
    /// Storage layer failure. The string must be non-sensitive and produced
    /// by the store layer. It is available through `Debug` only; `Display`
    /// never prints it.
    Store(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Crypto => f.write_str("cryptographic operation failed"),
            Self::WrongPassword => f.write_str("wrong password or secret key"),
            Self::Integrity(e) => write!(f, "integrity check failed: {e}"),
            Self::InvalidFormat(what) => write!(f, "invalid format: {what}"),
            Self::Validation(e) => e.fmt(f),
            Self::NotFound => f.write_str("not found"),
            Self::Store(_) => f.write_str("store error"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Validation(e) => Some(e),
            _ => None,
        }
    }
}

impl From<IntegrityError> for Error {
    fn from(e: IntegrityError) -> Self {
        Self::Integrity(e)
    }
}

impl From<ValidationError> for Error {
    fn from(e: ValidationError) -> Self {
        Self::Validation(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_display_hides_the_detail() {
        let e = Error::Store("secret".into());
        assert!(!e.to_string().contains("secret"));
        assert_eq!(e.to_string(), "store error");
        assert!(format!("{e:?}").contains("secret"));
    }
}
