//! Shared guard rails for the MCP server and the SSH agent: user approvals,
//! terminal-safe display text, locally signed configuration and a hash-chained
//! audit log.
//!
//! This crate does not depend on `onepass-core`: signatures are opaque bytes
//! produced and checked through the [`LocalSigner`] trait.

mod approval;
mod audit;
mod display;
mod signed;

pub use approval::{
    ApprovalRequest, Approver, Decision, DevAutoApprover, Surface, Target, TtyApprover,
    dev_auto_approver_from_env, parse_answer, parse_dev_auto_approve, render_prompt, testing,
};
pub use audit::{AuditEntry, AuditLog, AuditRecord, AuditSink, SignedAuditSink, verify_log};
pub use display::sanitize_for_display;
pub use signed::{open_config, seal_config};

use std::fmt;

/// Signs and verifies local data with a key owned by the caller (for example
/// the account's local signature key). `domain` separates uses of the key.
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
}

impl fmt::Display for GuardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GuardError::Io(kind) => write!(f, "i/o error: {kind}"),
            GuardError::Format(what) => write!(f, "invalid format: {what}"),
            GuardError::Signature => write!(f, "signature verification failed"),
            GuardError::Tampered(what) => write!(f, "tampering detected: {what}"),
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
