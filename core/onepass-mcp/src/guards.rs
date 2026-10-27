//! What the hardened server needs beyond the policy (spec sections 3.3 and
//! 4): who the client is, how to read the paired clients, the revocable
//! grants, the rate limits, strong authentication, a clock, and the
//! liveness of the control channel.
//!
//! The CLI builds a [`McpGuards`] once per server. The client registry is
//! read again at every call through [`McpGuards::registry`] (see
//! [`file_registry`]), so an unpairing applies to the next call. The grant
//! store is shared behind a mutex with the control channel callback, which
//! pushes revocations into it.

use crate::policy::{ClientScopes, client_scopes};
use onepass_guard::{
    ClientRecord, ClientRegistry, ClientRegistryLoader, Clock, GrantStore, GuardError, Limits,
    LocalSigner, StrongAuth, Surface, Throttle,
};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// The verified identity of the client that launched the server.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientContext {
    /// Code identity (`platform:...`, `team:...:...`, `adhoc:...`,
    /// `unsigned:...`): the key of the registry and of the grants.
    pub client_id: String,
    /// Label shown to the user and written to the audit log.
    pub label: String,
    /// True for a `Platform` or `Team` identity.
    pub signed: bool,
    /// Ad hoc code only: whether it runs with the hardened runtime.
    pub hardened: Option<bool>,
}

/// Reads the client registry, verified (called at every tool call).
pub type RegistryFn = Box<dyn FnMut() -> Result<ClientRegistry, GuardError>>;

/// Liveness of the control channel: false once the server can no longer
/// be told about revocations (it must stop serving).
pub type LivenessFn = Arc<dyn Fn() -> bool + Send + Sync>;

/// How long a request waits for an identical pending prompt by default
/// (the terminal approver's answer timeout).
pub const DEFAULT_PROMPT_WAIT: Duration = Duration::from_secs(60);

/// The hardening state of one MCP server.
pub struct McpGuards {
    /// Who the client is.
    pub client: ClientContext,
    /// Reads the paired clients, at every call.
    pub registry: RegistryFn,
    /// The grants file, shared with the control channel callback.
    pub grants: Arc<Mutex<GrantStore>>,
    /// Signs and verifies the grants file (the account's local key).
    pub grants_signer: Box<dyn LocalSigner>,
    /// Rate limits and the approval fatigue guard.
    pub throttle: Throttle,
    /// Strong authentication for `reveal_secret` and `totp_code`.
    pub strong: Arc<dyn StrongAuth>,
    /// Wall and monotonic time.
    pub clock: Arc<dyn Clock>,
    /// The control channel's liveness, when one is running: every call is
    /// refused once it reports false.
    pub liveness: Option<LivenessFn>,
    /// How long a request waits for an identical pending prompt.
    pub prompt_wait: Duration,
}

impl McpGuards {
    /// Guards with the MCP limits ([`Limits::mcp`]), no control channel and
    /// the default prompt wait. Set the public fields to change them.
    pub fn new(
        client: ClientContext,
        registry: RegistryFn,
        grants: Arc<Mutex<GrantStore>>,
        grants_signer: Box<dyn LocalSigner>,
        strong: Arc<dyn StrongAuth>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        McpGuards {
            client,
            registry,
            grants,
            grants_signer,
            throttle: Throttle::new(Limits::mcp()),
            strong,
            clock,
            liveness: None,
            prompt_wait: DEFAULT_PROMPT_WAIT,
        }
    }

    /// The scopes the registry grants `client` on the MCP surface, or
    /// `None` when it is not paired for MCP.
    pub(crate) fn paired_scopes(
        reg: &ClientRegistry,
        client: &ClientContext,
    ) -> Option<ClientScopes> {
        reg.find(Surface::Mcp, &client.client_id).map(client_scopes)
    }
}

/// A registry reader over `<path>` (normally `<data-dir>/clients.json`):
/// each call verifies the signed file through `loader`, which refuses a
/// registry older than one already seen and drops the clients unpaired by
/// control notifications (share `loader` with the control channel
/// callback, which calls `apply_unpairs` on it).
pub fn file_registry<S: LocalSigner + 'static>(
    path: PathBuf,
    signer: S,
    account_id: String,
    loader: Arc<Mutex<ClientRegistryLoader>>,
) -> RegistryFn {
    Box::new(move || {
        let mut loader = loader.lock().unwrap_or_else(|e| e.into_inner());
        loader.load(&path, &signer, &account_id)
    })
}

/// A client record paired for MCP with `scopes` (vault id to scope names).
/// Used by pairing code and tests; `code` is the verified code identity as
/// JSON.
pub fn mcp_client_record(
    client: &ClientContext,
    code: serde_json::Value,
    scopes: &ClientScopes,
    paired_at: i64,
) -> ClientRecord {
    ClientRecord {
        id: client.client_id.clone(),
        surface: Surface::Mcp,
        label: client.label.clone(),
        code,
        paired_at,
        mcp_scopes: Some(
            scopes
                .iter()
                .map(|(v, s)| (v.clone(), s.iter().map(|x| x.as_str().to_owned()).collect()))
                .collect(),
        ),
        ssh_keys: None,
    }
}
