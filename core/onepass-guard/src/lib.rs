//! Shared guard rails for the MCP server and the SSH agent: user approvals,
//! terminal-safe display text, locally signed configuration and a hash-chained
//! audit log.
//!
//! This crate does not depend on `onepass-core`: signatures are opaque bytes
//! produced and checked through the [`LocalSigner`] trait.
//!
//! `unsafe` is denied except in the terminal handling of `approval` (libc
//! calls on `/dev/tty`) and in `strong_macos` (LocalAuthentication).
#![deny(unsafe_code)]

mod approval;
mod audit;
mod clients;
mod clock;
mod control;
mod display;
mod grants;
mod limits;
mod signed;
mod strong;
#[cfg(target_os = "macos")]
mod strong_macos;

pub use approval::{
    ApprovalRequest, Approver, CHALLENGE_ALPHABET, Decision, DevAutoApprover, GRANT_CHOICES,
    Surface, Target, TtyApprover, challenge_code, decision_label, dev_auto_approver_from_env,
    parse_answer, render_prompt,
};
pub use audit::{
    AuditEntry, AuditLog, AuditRecord, AuditSink, AuditVerification, OUTCOME_CLIENT_COOLING_DOWN,
    OUTCOME_GRANT_EXPIRED, OUTCOME_GRANT_REVOKED, OUTCOME_HOST_NOT_BOUND, OUTCOME_NOT_PAIRED,
    OUTCOME_RATE_LIMITED, OUTCOME_REGISTRY_UNUSABLE, OUTCOME_STRONG_AUTH_FAILED, SignedAuditSink,
    head_path, verify_log,
};
pub use clients::{
    CLIENTS_DOMAIN, ClientRecord, ClientRegistry, ClientRegistryLoader, Unpaired, load_clients,
    save_clients,
};
pub use clock::{Clock, SystemClock};
pub use control::{
    ACK_DOMAIN, ControlChange, ControlServer, DEFAULT_NOTIFY_DEADLINE, LostFn, MAX_CONTROL_SOCKETS,
    NOTIFY_DOMAIN, NotifyFn, NotifyOutcome, PING_DOMAIN, SharedSigner, notify_servers,
};
pub use display::sanitize_for_display;
pub use grants::{
    DEFAULT_GRANT_TTL, GRANTS_DOMAIN, Grant, GrantCheck, GrantRequest, GrantStore, MAX_GRANT_TTL,
    Revoke, RevokeOutcome, RevokedGrant,
};
pub use limits::{Admit, Gated, Kind, LIMIT_ENV_VARS, Limits, PromptGate, Throttle};
pub use signed::{open_config, seal_config};
pub use strong::{
    ChainStrong, DevStrong, FallbackStrong, LOCAL_AUTH_TIMEOUT, LocalAuthStrong, StrongAuth,
    StrongOutcome, dev_strong_from_env,
};

use std::fmt;

/// Test doubles: a scripted approver, a hand-driven clock and a fixed
/// strong-authentication answer.
pub mod testing {
    pub use crate::approval::testing::*;
    pub use crate::clock::testing::FakeClock;
    pub use crate::strong::testing::dev_strong;
}

/// Signs and verifies local data with a key owned by the caller (for example
/// the account's local signature key). `domain` separates uses of the key.
///
/// Implementations MUST bind `domain` into what they sign (for example sign
/// `domain || 0x00 || msg`): `seal_config` passes the domain and the payload
/// separately and relies on this for domain separation.
pub trait LocalSigner {
    /// Signs `msg` under `domain`.
    fn sign(&self, domain: &[u8], msg: &[u8]) -> Result<Vec<u8>, GuardError>;
    /// Verifies `sig` over `msg` under `domain`.
    fn verify(&self, domain: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), GuardError>;
}

/// Errors of this crate. Messages never carry data from the files involved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardError {
    /// An I/O failure (only the kind is kept).
    Io(std::io::ErrorKind),
    /// A file or envelope is not in the expected format.
    Format(&'static str),
    /// A signature does not verify.
    Signature,
    /// The audit log was edited, truncated or is inconsistent with its head.
    Tampered(&'static str),
    /// A local setup problem, described by a fixed message.
    Config(&'static str),
}

impl fmt::Display for GuardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GuardError::Io(kind) => write!(f, "i/o error: {kind}"),
            GuardError::Format(what) => write!(f, "invalid format: {what}"),
            GuardError::Signature => write!(f, "signature verification failed"),
            GuardError::Tampered(what) => write!(f, "tampering detected: {what}"),
            GuardError::Config(what) => f.write_str(what),
        }
    }
}

impl std::error::Error for GuardError {}

impl From<std::io::Error> for GuardError {
    fn from(e: std::io::Error) -> Self {
        GuardError::Io(e.kind())
    }
}

#[cfg(test)]
pub(crate) mod testutil {
    use super::{GuardError, LocalSigner};
    use aws_lc_rs::hmac;

    /// HMAC-SHA256 test signer with a fixed key.
    pub struct TestSigner(pub [u8; 32]);

    impl TestSigner {
        pub fn new() -> Self {
            TestSigner([7u8; 32])
        }
        fn input(domain: &[u8], msg: &[u8]) -> Vec<u8> {
            let mut v = domain.to_vec();
            v.push(0);
            v.extend_from_slice(msg);
            v
        }
    }

    impl LocalSigner for TestSigner {
        fn sign(&self, domain: &[u8], msg: &[u8]) -> Result<Vec<u8>, GuardError> {
            let key = hmac::Key::new(hmac::HMAC_SHA256, &self.0);
            Ok(hmac::sign(&key, &Self::input(domain, msg))
                .as_ref()
                .to_vec())
        }
        fn verify(&self, domain: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), GuardError> {
            let key = hmac::Key::new(hmac::HMAC_SHA256, &self.0);
            hmac::verify(&key, &Self::input(domain, msg), sig).map_err(|_| GuardError::Signature)
        }
    }
}
