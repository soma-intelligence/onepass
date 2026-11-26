//! Guarded Kit: a rate-limited third secret for Emergency Kit restores
//! (spec `docs/superpowers/specs/2026-11-20-guarded-kit-design.md`).
//!
//! The guard `G` (256 bits) joins the AUK (`crypto::kdf::derive_auk_v2`).
//! It is split T-of-N ([`shamir`]) across realms, each of which releases
//! its share only after an OPRF proof of the guard input `x` ([`oprf`],
//! [`client`]) and erases it after [`realm::DEFAULT_LIMIT`] attempts
//! ([`realm`]). Devices keep `G` locally; only a restore asks the realms.
//!
//! This module keeps its own error type so that the guard never changes
//! the crate's `Error` that the FFI maps exhaustively.

pub mod client;
pub mod descriptor;
pub mod oprf;
pub mod params;
pub mod realm;
pub mod shamir;
pub mod wire;

use std::fmt;

use zeroize::Zeroizing;

pub use client::{GuardStatus, RealmTransport, delete, register, restore, status};
pub use descriptor::{GuardDescriptor, Locator, Placement, realm_set_hash};
pub use params::{GuardAccess, GuardParams, GuardState};

use crate::crypto::fill_random;

/// Default threshold and realm count (spec 5).
pub const DEFAULT_THRESHOLD: u8 = 2;
pub const DEFAULT_REALMS: usize = 3;

/// One realm as pinned in a release (spec 5): never read from storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealmInfo {
    pub id: [u8; 16],
    pub url: String,
    /// Ed25519 key the realm signs its responses with.
    pub response_key: [u8; 32],
}

/// The realms pinned in this build. Empty until the three Soma realms are
/// deployed (decision Q2); restore and registration refuse an empty list.
pub fn pinned_realms() -> Vec<RealmInfo> {
    Vec::new()
}

/// The guard `G`, wiped on drop.
pub struct GuardSecret(Zeroizing<[u8; 32]>);

impl GuardSecret {
    pub fn generate() -> Result<GuardSecret, GuardError> {
        let mut g = Zeroizing::new([0u8; 32]);
        fill_random(g.as_mut_slice()).map_err(|_| GuardError::Crypto)?;
        Ok(GuardSecret(g))
    }

    pub fn from_bytes(b: [u8; 32]) -> GuardSecret {
        GuardSecret(Zeroizing::new(b))
    }

    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for GuardSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GuardSecret(..)")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardError {
    Crypto,
    /// Bad parameters from the caller.
    Config(&'static str),
    Malformed(&'static str),
    /// A response not signed by the pinned key, or not for our request.
    RealmSignature,
    /// A realm answered something the protocol does not allow here.
    Unexpected,
    /// The tag check failed: wrong password. `remaining` is the fewest
    /// attempts left at the realms asked (0: that realm erased its share).
    WrongPassword {
        remaining: u8,
    },
    /// Fewer than the threshold of realms gave their share.
    Unavailable {
        reached: u8,
        needed: u8,
    },
    /// A released share did not open: a realm bug or a forged share.
    ShareRefused,
    /// The locator did not open with this Secret Key.
    LocatorRefused,
    /// Transport failure, set by the app's transport. Never sensitive.
    Transport(String),
    /// The account is guarded and no guard (`G`) nor realm access was
    /// given.
    Required,
}

impl fmt::Display for GuardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Crypto => f.write_str("cryptographic operation failed"),
            Self::Config(w) => write!(f, "invalid guard configuration: {w}"),
            Self::Malformed(w) => write!(f, "malformed guard message: {w}"),
            Self::RealmSignature => f.write_str("realm response not signed by the pinned key"),
            Self::Unexpected => f.write_str("unexpected realm response"),
            Self::WrongPassword { remaining } => {
                write!(f, "wrong password, {remaining} attempts left")
            }
            Self::Unavailable { reached, needed } => {
                write!(f, "only {reached} of {needed} realms answered")
            }
            Self::ShareRefused => f.write_str("a realm share did not open"),
            Self::LocatorRefused => f.write_str("guard locator did not open"),
            Self::Transport(_) => f.write_str("realm unreachable"),
            Self::Required => f.write_str("the account needs its guard"),
        }
    }
}

impl std::error::Error for GuardError {}
