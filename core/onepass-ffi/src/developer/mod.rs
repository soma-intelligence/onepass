//! Milestone 7 in the apps (spec 2026-10-27-m7-app): the SSH agent and the
//! MCP server served by the unlocked app, over its session, with the
//! hardened guards of `onepass-guard`.
//!
//! The app gives a data folder (inside its container) that holds the
//! signed audit log, the client registry, the grants, the MCP policy and
//! the two sockets. Approvals, presence checks (Touch ID) and pairing
//! prompts are asked of the app through [`FfiDeveloperUi`]; every call
//! comes from a server thread, never from the app's main thread, and may
//! block until the user answers.
//!
//! The exports exist on every platform (one set of Swift bindings); the
//! servers are only started by the Mac app.

mod admin;
mod mcp;
mod ssh;

pub use admin::*;
pub use mcp::*;
pub use ssh::*;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use onepass_core::crypto::HybridSignature;
use onepass_guard::{
    ApprovalRequest, Approver, Decision, GuardError, LocalSigner, MAX_GRANT_TTL, StrongAuth,
    StrongOutcome, Surface, sanitize_for_display,
};

use crate::error::{OnePassError, invalid};
use crate::session::Session;

/// Files of the data folder.
pub(crate) const AUDIT_FILE: &str = "audit.log";
pub(crate) const CLIENTS_FILE: &str = "clients.json";
pub(crate) const GRANTS_FILE: &str = "grants.json";
pub(crate) const POLICY_FILE: &str = "mcp-policy.json";

/// Stack of the server threads: the core's signature checks keep big
/// arrays on the stack (the app's `CoreThread` uses the same size).
pub(crate) const SERVER_STACK: usize = 16 << 20;

/// Longest socket path `sun_path` holds on macOS, terminator included.
const MAX_SOCKET_PATH: usize = 104;

/// The app's side of the servers: approvals, presence and pairing.
#[uniffi::export(with_foreign)]
pub trait FfiDeveloperUi: Send + Sync {
    /// Ask the user about one request. Blocks until answered.
    fn approve(&self, request: FfiApprovalRequest) -> FfiDecision;
    /// Ask the device owner to authenticate (Touch ID, Apple Watch or the
    /// session password). `reason` names the client and the target.
    fn verify_presence(&self, reason: String) -> bool;
    /// A signed MCP client that is not paired asks to be. The app shows its
    /// verified identity, then checks presence. True pairs it.
    fn pair_request(&self, client: FfiMcpClient) -> bool;
}

/// What a server asks the user to approve. Every text is display-safe
/// (control characters replaced, length bounded).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiApprovalRequest {
    /// `ssh` or `mcp`.
    pub surface: String,
    /// Who asks: the program, as verified (`client_verified`) or declared.
    pub client: String,
    pub client_verified: bool,
    /// What is asked (`sign`, `run_with_secrets`, `reveal_secret`...).
    pub action: String,
    /// Label and value lines, no secret.
    pub details: Vec<FfiDetail>,
    /// Vault, item and field names the request touches.
    pub targets: Vec<FfiTarget>,
    /// The user may allow it for a few minutes (otherwise once only).
    pub remember_allowed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiDetail {
    pub label: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiTarget {
    pub vault: String,
    pub item: String,
    pub field: Option<String>,
}

/// The user's answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiDecision {
    Deny,
    AllowOnce,
    /// A grant of this many minutes (5, 15 or 60; capped at 60).
    AllowForMinutes {
        minutes: u32,
    },
}

fn safe(s: &str) -> String {
    sanitize_for_display(s)
}

fn to_ffi(req: &ApprovalRequest) -> FfiApprovalRequest {
    FfiApprovalRequest {
        surface: match req.surface {
            Surface::Mcp => "mcp",
            Surface::Ssh => "ssh",
        }
        .into(),
        client: safe(&req.client),
        client_verified: req.client_verified,
        action: safe(&req.action),
        details: req
            .details
            .iter()
            .map(|(l, v)| FfiDetail {
                label: safe(l),
                value: safe(v),
            })
            .collect(),
        targets: req
            .targets
            .iter()
            .map(|t| FfiTarget {
                vault: safe(&t.vault),
                item: safe(&t.item),
                field: t.field.as_deref().map(safe),
            })
            .collect(),
        remember_allowed: req.remember_allowed,
    }
}

/// The decision a guard sees. A grant is only given where the request
/// allows one, and never longer than the guard's ceiling.
pub(crate) fn decision_of(d: FfiDecision, remember_allowed: bool) -> Decision {
    match d {
        FfiDecision::Deny => Decision::Deny,
        FfiDecision::AllowOnce => Decision::AllowOnce,
        FfiDecision::AllowForMinutes { .. } if !remember_allowed => Decision::AllowOnce,
        FfiDecision::AllowForMinutes { minutes: 0 } => Decision::AllowOnce,
        FfiDecision::AllowForMinutes { minutes } => {
            Decision::AllowFor(Duration::from_secs(u64::from(minutes) * 60).min(MAX_GRANT_TTL))
        }
    }
}

/// [`Approver`] over the app. With `presence`, an allowed request also
/// needs the device owner (Touch ID): a failed check is a refusal.
pub(crate) struct UiApprover {
    pub ui: Arc<dyn FfiDeveloperUi>,
    pub presence: bool,
}

impl Approver for UiApprover {
    fn approve(&self, req: &ApprovalRequest) -> Decision {
        let shown = to_ffi(req);
        let decision = decision_of(self.ui.approve(shown.clone()), req.remember_allowed);
        if decision == Decision::Deny || !self.presence {
            return decision;
        }
        let reason = format!("{} : {}", shown.client, shown.action);
        if self.ui.verify_presence(reason) {
            decision
        } else {
            Decision::Deny
        }
    }
}

/// [`StrongAuth`] over the app's presence check.
pub(crate) struct UiStrong(pub Arc<dyn FfiDeveloperUi>);

impl StrongAuth for UiStrong {
    fn verify(&self, reason: &str) -> StrongOutcome {
        if self.0.verify_presence(safe(reason)) {
            StrongOutcome::Verified
        } else {
            StrongOutcome::Denied
        }
    }
}

/// [`LocalSigner`] over the session: the account's local signature key
/// (`Repository::sign_local`, which binds the domain). A signature is the
/// postcard encoding of the core's `HybridSignature`, as in the CLI, so
/// both read the same files. Fails while the session is locked.
#[derive(Clone)]
pub(crate) struct SessionSigner(pub Arc<Session>);

impl LocalSigner for SessionSigner {
    fn sign(&self, domain: &[u8], msg: &[u8]) -> Result<Vec<u8>, GuardError> {
        let guard = self.0.guard();
        let repo = guard.as_ref().ok_or(GuardError::Config("locked"))?;
        let sig = repo
            .sign_local(domain, msg)
            .map_err(|_| GuardError::Format("local signature"))?;
        postcard::to_allocvec(&sig).map_err(|_| GuardError::Format("local signature"))
    }

    fn verify(&self, domain: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), GuardError> {
        let (sig, rest): (HybridSignature, &[u8]) =
            postcard::take_from_bytes(sig).map_err(|_| GuardError::Signature)?;
        if !rest.is_empty() {
            return Err(GuardError::Signature);
        }
        let guard = self.0.guard();
        let repo = guard.as_ref().ok_or(GuardError::Config("locked"))?;
        repo.verify_local(domain, msg, &sig)
            .map_err(|_| GuardError::Signature)
    }
}

/// The account id as the guard files name it (hyphenated, like the CLI).
pub(crate) fn guard_account_id(session: &Session) -> Result<String, OnePassError> {
    let guard = session.guard();
    let repo = guard.as_ref().ok_or(OnePassError::Locked)?;
    Ok(repo.account_id().to_string())
}

/// The data folder, created `0700` when missing.
pub(crate) fn data_dir(dir: &str) -> Result<PathBuf, OnePassError> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    let path = PathBuf::from(dir);
    if !path.is_absolute() {
        return Err(invalid("data folder must be absolute"));
    }
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&path)
        .map_err(|_| invalid("data folder"))?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
        .map_err(|_| invalid("data folder"))?;
    Ok(path)
}

/// A socket path that fits `sun_path`.
pub(crate) fn socket_path(path: &str) -> Result<PathBuf, OnePassError> {
    if path.len() + 1 > MAX_SOCKET_PATH {
        return Err(invalid("socket path too long"));
    }
    let p = Path::new(path);
    if !p.is_absolute() {
        return Err(invalid("socket path must be absolute"));
    }
    Ok(p.to_path_buf())
}

/// Device and inode of the socket at `path`, right after binding it.
pub(crate) fn socket_identity(path: &Path) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    std::fs::symlink_metadata(path)
        .ok()
        .map(|m| (m.dev(), m.ino()))
}

/// Removes the socket at `path` only if it is still the one this host
/// bound (`id`): a newer host's socket at the same path stays.
pub(crate) fn remove_socket(path: &Path, id: Option<(u64, u64)>) {
    if id.is_some() && socket_identity(path) == id {
        let _ = std::fs::remove_file(path);
    }
}

pub(crate) fn guard_error(e: GuardError) -> OnePassError {
    match e {
        GuardError::Signature | GuardError::Tampered(_) => OnePassError::Integrity {
            kind: "signature".into(),
        },
        GuardError::Config("locked") => OnePassError::Locked,
        other => invalid(&other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grants_are_capped_and_only_where_allowed() {
        assert_eq!(
            decision_of(FfiDecision::AllowForMinutes { minutes: 15 }, true),
            Decision::AllowFor(Duration::from_secs(900))
        );
        assert_eq!(
            decision_of(FfiDecision::AllowForMinutes { minutes: 600 }, true),
            Decision::AllowFor(MAX_GRANT_TTL)
        );
        assert_eq!(
            decision_of(FfiDecision::AllowForMinutes { minutes: 15 }, false),
            Decision::AllowOnce
        );
        assert_eq!(
            decision_of(FfiDecision::AllowForMinutes { minutes: 0 }, true),
            Decision::AllowOnce
        );
        assert_eq!(decision_of(FfiDecision::Deny, true), Decision::Deny);
    }

    #[test]
    fn long_socket_paths_are_refused() {
        assert!(socket_path("/tmp/a.sock").is_ok());
        assert!(socket_path(&format!("/{}", "a".repeat(110))).is_err());
        assert!(socket_path("relative.sock").is_err());
    }
}
