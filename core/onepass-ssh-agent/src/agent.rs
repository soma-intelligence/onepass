//! Agent logic: which request gets which response, behind user approval
//! (milestone 7 spec 6.2 to 6.4, hardening spec 2026-10-26 section 6).
//!
//! The keys live in the vault: a [`KeySource`] lists them on every request
//! and loads a private key only to sign, after approval. Nothing is added to
//! or removed from the agent by clients.
//!
//! The agent runs in one of two modes, chosen by its [`AgentGuards`]:
//!
//! - Paired ([`AgentGuards::new`], `onepass ssh-agent`): only paired clients
//!   are served. The server identifies each connection once (code identity
//!   through `onepass-peer`) and the agent reads the client registry at
//!   every request. A sign request goes through, in this order: uid,
//!   control channel, identity, pairing, lock, key known and allowed for the
//!   client, RSA SHA-1 refusal, bound session (on a bound connection, a
//!   userauth request for the bound session id and host only, except the
//!   `git` exception), forwarding (an unbound userauth signature from `ssh`
//!   counts as forwarded), host binding (with the `git`
//!   exception), audit log ready, signature rate limit, grant (signed
//!   grants file), prompt rate limit, prompt (identical requests
//!   coalesced), strong authentication (`--strong`), then the signature.
//! - Open ([`AgentGuards::open`], the app's agent until it pairs SSH
//!   clients): every client of this user is asked, no rate limit, grants in
//!   memory, and a key whose bookmarks the destination does not match is
//!   asked about with a warning instead of refused.
//!
//! In both modes a wrong `SSH_AGENTC_UNLOCK` passphrase holds the next
//! attempt back for a delay that doubles at each failure (up to 60 s).
//!
//! In both modes a grant is keyed by the client's code identity (never the
//! path of a pid), the key and the destination the connection is bound to,
//! and a client whose code cannot be read is never remembered.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use data_encoding::{BASE64, HEXLOWER};
use onepass_core::Id;
use onepass_core::model::{FieldValue, Item, ItemType};
use onepass_core::repo::Repository;
use onepass_core::store::RecordStore;
use onepass_guard::{
    Admit, Answer, ApprovalRequest, Approver, AuditEntry, AuditSink, ClientRecord, ClientRegistry,
    ClientRegistryLoader, Clock, Decision, Gated, GrantCheck, GrantRequest, GrantStore, GuardError,
    Kind, Limits, LocalSigner, MAX_GRANT_TTL, OUTCOME_CLIENT_COOLING_DOWN, OUTCOME_GRANT_EXPIRED,
    OUTCOME_GRANT_REVOKED, OUTCOME_HOST_NOT_BOUND, OUTCOME_NOT_PAIRED, OUTCOME_RATE_LIMITED,
    OUTCOME_REGISTRY_UNUSABLE, OUTCOME_STRONG_AUTH_FAILED, PromptGate, StrongAuth, StrongOutcome,
    Surface, SystemClock, Target, Throttle, challenge_code, decision_label, sanitize_for_display,
};
use onepass_peer::{ClientIdentity, CodeIdentity, effective_uid};
use zeroize::Zeroizing;

use crate::keys::{AgentKey, fingerprint_of_blob, verify_signature};
use crate::knownhosts::matching_hosts;
use crate::sshsig::sshsig_namespace;
use crate::wire::{Request, Response, SSH_AGENT_RSA_SHA2_256, SSH_AGENT_RSA_SHA2_512, SshReader};

/// Audit and approval action of a signature. A refused
/// `session-bind@openssh.com` is audited under it too, with a `bind_*`
/// outcome and no item.
const ACTION_SIGN: &str = "ssh_sign";
/// Field that holds the private key of an SSH Key item.
const KEY_FIELD: &str = "private_key";
/// Audit action of a key listing refused before pairing.
const ACTION_LIST: &str = "ssh_list";
/// Audit action of a lock or unlock refused before pairing.
const ACTION_LOCK: &str = "ssh_lock";
/// Client name when the peer's executable is unknown.
const UNKNOWN_PROCESS: &str = "unknown process";
const SESSION_BIND: &str = "session-bind@openssh.com";
/// Audit outcome of a sign request on a bound connection whose data is not
/// a userauth request for the bound session and host.
const OUTCOME_SESSION_MISMATCH: &str = "session_mismatch";
/// `SSH_MSG_USERAUTH_REQUEST` (RFC 4252).
const SSH_MSG_USERAUTH_REQUEST: u8 = 50;
/// The OpenSSH method that names the server's host key in the request.
const HOSTBOUND_METHOD: &[u8] = b"publickey-hostbound-v00@openssh.com";
/// Longest wait after wrong unlock passphrases.
const MAX_UNLOCK_DELAY: Duration = Duration::from_secs(60);
/// SSHSIG namespace that may sign without a host binding (commit signing),
/// for keys whose `git_signing` is yes.
const GIT_NAMESPACE: &str = "git";
/// Most audit entries per minute for refusals before pairing: a client
/// looping on requests must not flood the log (it is still refused).
pub const MAX_UNPAIRED_AUDIT_PER_MIN: usize = 6;

/// What the kernel says about a connected client (spec 6.3). Each part is
/// `None` when the platform or the kernel cannot tell.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PeerInfo {
    /// Effective uid of the peer.
    pub uid: Option<u32>,
    /// Pid of the peer (at connection time).
    pub pid: Option<i32>,
    /// Executable path of that pid. Informative: a pid can be reused, and
    /// the process can exec another program after connecting.
    pub exe: Option<String>,
    /// Code-signing client id of the process that connected, read through
    /// its audit token (`onepass_peer::identify_peer`): the identity open
    /// mode keys grants by. `None` when it cannot be read; such a peer is
    /// never remembered.
    pub code: Option<String>,
    /// Code identity of the peer, read once when the connection was
    /// accepted; `None` when the system could not tell (never served in
    /// paired mode).
    pub identity: Option<ClientIdentity>,
}

/// A key the agent offers: public data and settings of one SSH Key item.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyInfo {
    /// Item id.
    pub item_id: String,
    /// Vault id.
    pub vault_id: String,
    /// Vault name, shown in the approval prompt.
    pub vault_name: String,
    /// Item title: the identity comment and the key name in prompts.
    pub title: String,
    /// SSH public key blob.
    pub public_blob: Vec<u8>,
    /// `SHA256:` fingerprint of `public_blob`.
    pub fingerprint: String,
    /// Ask at every signature, never remember.
    pub confirm_each_use: bool,
    /// Host bookmarks (names or OpenSSH `Host` patterns). When not empty,
    /// the key only signs for a bound connection to one of them.
    pub hosts: Vec<String>,
    /// May sign SSHSIG requests of the `git` namespace without a host
    /// binding (commit signing).
    pub git_signing: bool,
}

/// Where the agent's keys come from. Errors are plain messages without
/// secrets.
pub trait KeySource: Send {
    /// The keys to offer, read again at each call.
    fn list(&mut self) -> Result<Vec<KeyInfo>, String>;
    /// The private key of an item, loaded only to sign.
    fn load(&mut self, item_id: &str) -> Result<AgentKey, String>;
}

/// [`KeySource`] over an unlocked repository.
pub struct RepoKeySource<S: RecordStore> {
    repo: Repository<S>,
}

impl<S: RecordStore> RepoKeySource<S> {
    /// Serves the keys of `repo`.
    pub fn new(repo: Repository<S>) -> Self {
        RepoKeySource { repo }
    }
}

impl<S: RecordStore + Send> KeySource for RepoKeySource<S> {
    fn list(&mut self) -> Result<Vec<KeyInfo>, String> {
        ssh_keys_of(&mut self.repo).map_err(|e| e.to_string())
    }

    fn load(&mut self, item_id: &str) -> Result<AgentKey, String> {
        load_key_of(&mut self.repo, item_id)
    }
}

/// Whether a yes/no field value says yes: a `Menu` or `Text` equal to
/// `yes`, `oui`, `true` or `1`, ignoring case and surrounding spaces.
pub fn menu_truthy(v: &FieldValue) -> bool {
    match v {
        FieldValue::Menu(s) | FieldValue::Text(s) => {
            let s = s.trim();
            ["yes", "oui", "true", "1"]
                .iter()
                .any(|y| s.eq_ignore_ascii_case(y))
        }
        _ => false,
    }
}

fn field_truthy(item: &Item, id: &str) -> bool {
    item.field(id).is_some_and(|f| menu_truthy(&f.value))
}

/// An SSH Key item the agent may use: not trashed, not archived, and
/// `use_in_agent` set.
fn agent_eligible(item: &Item) -> bool {
    item.item_type == ItemType::SshKey
        && item.trashed_at.is_none()
        && !item.archived
        && field_truthy(item, "use_in_agent")
}

/// Public key blob from an OpenSSH public key line (`type base64 [comment]`).
fn blob_of_public_line(line: &str) -> Option<Vec<u8>> {
    let mut parts = line.split_ascii_whitespace();
    let key_type = parts.next()?;
    let blob = BASE64.decode(parts.next()?.as_bytes()).ok()?;
    // The blob starts with its own type name: both must agree.
    let mut r = SshReader::new(&blob);
    (r.utf8().ok()? == key_type).then_some(blob)
}

/// The agent keys of every vault of `repo` (spec 6.2): SSH Key items not
/// trashed nor archived whose `use_in_agent` is yes. The fingerprint is
/// computed from the public key, not read from the item. An item whose
/// public key does not parse is skipped.
pub fn ssh_keys_of<S: RecordStore>(
    repo: &mut Repository<S>,
) -> Result<Vec<KeyInfo>, onepass_core::Error> {
    let mut out = Vec::new();
    for vault in repo.vaults()? {
        for item in repo.items(&vault)? {
            if !agent_eligible(&item) {
                continue;
            }
            let Some(FieldValue::SshKey(v)) = item.field(KEY_FIELD).map(|f| &f.value) else {
                continue;
            };
            let Some(public_blob) = blob_of_public_line(&v.public_openssh) else {
                continue;
            };
            let hosts = item
                .sections
                .iter()
                .flat_map(|s| s.fields.iter())
                .filter(|f| f.id == "hosts")
                .filter_map(|f| match &f.value {
                    FieldValue::Text(h) if !h.trim().is_empty() => Some(h.trim().to_owned()),
                    _ => None,
                })
                .collect();
            out.push(KeyInfo {
                item_id: item.id.to_string(),
                vault_id: vault.id.to_string(),
                vault_name: vault.meta.name.clone(),
                title: item.title.clone(),
                fingerprint: fingerprint_of_blob(&public_blob),
                public_blob,
                confirm_each_use: field_truthy(&item, "confirm_each_use"),
                hosts,
                git_signing: field_truthy(&item, "git_signing"),
            });
        }
    }
    Ok(out)
}

/// The private key of an agent key item, read from the vault now. The item
/// must still be eligible (see [`ssh_keys_of`]).
pub fn load_key_of<S: RecordStore>(
    repo: &mut Repository<S>,
    item_id: &str,
) -> Result<AgentKey, String> {
    let id: Id = item_id.parse().map_err(|_| "invalid item id".to_owned())?;
    let vaults = repo.vaults().map_err(|e| e.to_string())?;
    for vault in &vaults {
        let items = repo.items(vault).map_err(|e| e.to_string())?;
        let Some(item) = items.iter().find(|i| i.id == id) else {
            continue;
        };
        if !agent_eligible(item) {
            return Err("item is not an agent key".into());
        }
        let Some(FieldValue::SshKey(v)) = item.field(KEY_FIELD).map(|f| &f.value) else {
            return Err("item has no SSH private key".into());
        };
        return AgentKey::from_private_text(&v.private_pem, None).map_err(|e| e.to_string());
    }
    Err("item not found".into())
}

/// Per-connection state.
#[derive(Clone, Debug, Default)]
pub struct ConnState {
    /// Destination learned from `session-bind@openssh.com`.
    pub bound: Option<BoundHost>,
}

/// A verified `session-bind@openssh.com` (the latest one of a forwarded
/// chain).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoundHost {
    /// Host key blob of the destination.
    pub host_key: Vec<u8>,
    /// The SSH session id the host key signed. A sign request on this
    /// connection must be a userauth request for this very session.
    pub session_id: Vec<u8>,
    /// Whether the connection is a forwarded agent.
    pub forwarded: bool,
}

/// When the user is asked (`onepass ssh-agent --confirm`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Confirm {
    /// A prompt may grant the client the key for a few minutes.
    #[default]
    Session,
    /// Every signature is asked: no grant is ever given or used.
    Always,
}

/// Agent settings.
#[derive(Clone, Debug)]
pub struct AgentConfig {
    /// Sign on forwarded connections (always with approval).
    pub allow_forwarded: bool,
    /// `known_hosts` files read to name a bound destination.
    pub known_hosts: Vec<PathBuf>,
    /// Ceiling of a grant: an "allow for N minutes" answer lasts N minutes,
    /// at most this long (and never more than [`MAX_GRANT_TTL`]).
    pub remember_for: Duration,
    /// Session (grants allowed) or always ask.
    pub confirm: Confirm,
    /// Strong authentication (Touch ID or master password) at every
    /// signature, grant or not.
    pub strong: bool,
}

impl Default for AgentConfig {
    fn default() -> Self {
        AgentConfig {
            allow_forwarded: false,
            known_hosts: Vec::new(),
            remember_for: Duration::from_secs(3600),
            confirm: Confirm::Session,
            strong: false,
        }
    }
}

/// Reads the client registry, verified (called at every request). `Send`:
/// the agent serves connections from several threads.
pub type RegistryFn = Box<dyn FnMut() -> Result<ClientRegistry, GuardError> + Send>;

/// Liveness of the control channel: false once the agent can no longer be
/// told about revocations (it must stop serving).
pub type LivenessFn = Arc<dyn Fn() -> bool + Send + Sync>;

/// How long a request waits for an identical pending prompt by default
/// (the terminal approver's answer timeout).
pub const DEFAULT_PROMPT_WAIT: Duration = Duration::from_secs(60);

/// The pairing state of a paired agent.
struct Pairing {
    /// Reads the paired clients, at every request.
    registry: RegistryFn,
    /// The grants file, shared with the control channel callback.
    grants: Arc<Mutex<GrantStore>>,
    /// Signs and verifies the grants file (the account's local key).
    grants_signer: Box<dyn LocalSigner + Send>,
}

/// Strong authentication that never succeeds: `strong` asked of an open
/// agent refuses every signature.
struct NoStrong;

impl StrongAuth for NoStrong {
    fn verify(&self, _reason: &str) -> StrongOutcome {
        StrongOutcome::Unavailable
    }
}

/// The hardening state of the agent (mirrors the MCP server's guards).
pub struct AgentGuards {
    /// Registry and grants file of a paired agent; `None` for an open one.
    pairing: Option<Pairing>,
    /// Rate limits and the approval fatigue guard (paired agent only).
    pub throttle: Throttle,
    /// Strong authentication for `--strong`.
    pub strong: Arc<dyn StrongAuth>,
    /// Wall and monotonic time.
    pub clock: Arc<dyn Clock>,
    /// The control channel's liveness, when one is running: every request
    /// is refused (and the server stops) once it reports false.
    pub liveness: Option<LivenessFn>,
    /// How long a request waits for an identical pending prompt.
    pub prompt_wait: Duration,
}

impl AgentGuards {
    /// Guards with the SSH limits ([`Limits::ssh`]), no control channel and
    /// the default prompt wait. Set the public fields to change them.
    pub fn new(
        registry: RegistryFn,
        grants: Arc<Mutex<GrantStore>>,
        grants_signer: Box<dyn LocalSigner + Send>,
        strong: Arc<dyn StrongAuth>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        AgentGuards {
            pairing: Some(Pairing {
                registry,
                grants,
                grants_signer,
            }),
            throttle: Throttle::new(Limits::ssh()),
            strong,
            clock,
            liveness: None,
            prompt_wait: DEFAULT_PROMPT_WAIT,
        }
    }

    /// Guards of an open agent (the app's, until it pairs SSH clients):
    /// every client of this user is asked, without rate limits, and grants
    /// live in memory until they expire, the agent stops or LOCK. A
    /// bookmarked key is asked about with a warning on another destination
    /// instead of refused. Strong authentication is not available
    /// (`AgentConfig::strong` then refuses every signature).
    pub fn open() -> Self {
        AgentGuards {
            pairing: None,
            throttle: Throttle::new(Limits::ssh()),
            strong: Arc::new(NoStrong),
            clock: Arc::new(SystemClock),
            liveness: None,
            prompt_wait: DEFAULT_PROMPT_WAIT,
        }
    }
}

/// A registry reader over `<path>` (normally `<data-dir>/clients.json`):
/// each call verifies the signed file through `loader`, which refuses a
/// registry older than one already seen and drops the clients unpaired by
/// control notifications (share `loader` with the control channel
/// callback, which calls `apply_unpairs` on it).
pub fn file_registry<S: LocalSigner + Send + 'static>(
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

/// The verified code identity as stored in a client record (`code`).
pub fn code_json(code: &CodeIdentity) -> serde_json::Value {
    match code {
        CodeIdentity::Platform { identifier } => {
            serde_json::json!({ "kind": "platform", "identifier": identifier })
        }
        CodeIdentity::Team {
            team_id,
            identifier,
        } => serde_json::json!({ "kind": "team", "team_id": team_id, "identifier": identifier }),
        CodeIdentity::AdHoc {
            path,
            cdhash,
            hardened,
        } => serde_json::json!({
            "kind": "adhoc", "path": path.to_string_lossy(), "cdhash": cdhash, "hardened": hardened
        }),
        CodeIdentity::Unsigned { path, sha256 } => serde_json::json!({
            "kind": "unsigned", "path": path.to_string_lossy(), "sha256": sha256
        }),
    }
}

/// A client record paired for SSH: `ssh_keys` lists the fingerprints the
/// client may see and use (`None` = every key). Used by pairing code and
/// tests.
pub fn ssh_client_record(
    code: &CodeIdentity,
    label: &str,
    ssh_keys: Option<BTreeSet<String>>,
    paired_at: i64,
) -> ClientRecord {
    ClientRecord {
        id: code.client_id(),
        surface: Surface::Ssh,
        label: label.to_owned(),
        code: code_json(code),
        paired_at,
        mcp_scopes: None,
        ssh_keys,
    }
}

/// The grant key of a signature: a digest of the client id, the key
/// fingerprint and the fingerprint of the host key the connection is bound
/// to (`None` when unbound), so the grants file names none of them. A grant
/// given for one destination does not sign for another.
pub fn grant_key(client_id: &str, fingerprint: &str, destination: Option<&str>) -> String {
    let canonical = serde_json::json!([client_id, fingerprint, destination]).to_string();
    let d = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, canonical.as_bytes());
    HEXLOWER.encode(d.as_ref())
}

/// The response to a request, and whether to close the connection after it.
#[derive(Debug, PartialEq, Eq)]
pub struct Reply {
    /// Response to send.
    pub response: Response,
    /// Close the connection once the response is sent.
    pub close: bool,
}

impl Reply {
    fn send(response: Response) -> Reply {
        Reply {
            response,
            close: false,
        }
    }

    fn failure() -> Reply {
        Reply::send(Response::Failure)
    }

    fn close() -> Reply {
        Reply {
            response: Response::Failure,
            close: true,
        }
    }
}

/// An approver shared behind an `Arc`, for [`PromptGate`].
struct SharedApprover(Arc<dyn Approver>);

impl Approver for SharedApprover {
    fn approve(&self, req: &ApprovalRequest) -> Answer {
        self.0.approve(req)
    }

    fn code_is_public(&self) -> bool {
        self.0.code_is_public()
    }
}

/// The client behind a request: a paired client as the registry describes
/// it, or (open agent) the peer as the kernel describes it.
struct Client {
    /// Client id (code identity). Always set for a paired client; `None`
    /// for an open agent's peer whose code cannot be read (never
    /// remembered).
    id: Option<String>,
    /// Pairing label, or the executable path for an open agent.
    label: String,
    /// Admitted through the registry (paired agent).
    paired: bool,
    /// Platform or team identity (the system vouches for the code).
    verified: bool,
    /// Ad hoc code only: whether it runs with the hardened runtime.
    hardened: Option<bool>,
    /// Fingerprints the client may use, `None` = all.
    ssh_keys: Option<BTreeSet<String>>,
}

impl Client {
    fn allows(&self, key: &KeyInfo) -> bool {
        self.ssh_keys
            .as_ref()
            .is_none_or(|k| k.contains(&key.fingerprint))
    }
}

/// Who an audit entry names.
#[derive(Clone)]
struct Who {
    exe: String,
    client_id: Option<String>,
    label: Option<String>,
}

impl Who {
    fn of(peer: &PeerInfo) -> Who {
        let exe = peer
            .exe
            .clone()
            .or_else(|| {
                peer.identity
                    .as_ref()
                    .and_then(|i| i.exe.as_ref())
                    .map(|p| p.to_string_lossy().into_owned())
            })
            .unwrap_or_else(|| UNKNOWN_PROCESS.to_owned());
        Who {
            exe,
            client_id: peer
                .identity
                .as_ref()
                .map(|i| i.code.client_id())
                .or_else(|| peer.code.clone()),
            label: None,
        }
    }

    fn paired(mut self, client: &Client) -> Who {
        if client.paired {
            self.label = Some(client.label.clone());
        }
        self
    }
}

/// Destination, namespace and approval origin of a sign request, for the
/// audit log.
#[derive(Clone, Default)]
struct SignCtx {
    destination: Option<String>,
    namespace: Option<String>,
    /// Where the prompt was answered (`mac`, `phone:<id>`), once known.
    approved_on: Option<String>,
}

/// The mutable state of the agent, behind one mutex never held during a
/// prompt or a strong authentication.
struct Inner<K: KeySource> {
    source: K,
    audit: Box<dyn AuditSink + Send>,
    /// SHA-256 of the lock passphrase while locked.
    locked: Option<Zeroizing<Vec<u8>>>,
    /// Wrong unlock passphrases since the last lock or unlock, and the
    /// instant before which no attempt is checked.
    unlock_failures: u32,
    unlock_not_before: Option<Instant>,
    /// Wall time of the last LOCK: grants created at or before it are not
    /// used (a grant lasts at most until LOCK).
    lock_floor: Option<i64>,
    /// Registry and grants file of a paired agent.
    pairing: Option<Pairing>,
    /// Grants of an open agent: grant key to expiry (monotonic).
    memory_grants: HashMap<String, Instant>,
    throttle: Throttle,
    /// When the last refusals before pairing were audited, within the last
    /// minute.
    unpaired_audited: VecDeque<Instant>,
}

/// The SSH agent: paired clients, approvals, grants, lock state and audit.
/// Shared between the connection threads (`&self` everywhere); prompts and
/// strong authentication run without holding the agent's state, so other
/// clients are served meanwhile and identical requests share one prompt.
pub struct Agent<K: KeySource> {
    inner: Mutex<Inner<K>>,
    /// Paired agent (see the module documentation).
    paired: bool,
    gate: PromptGate<SharedApprover>,
    strong: Arc<dyn StrongAuth>,
    clock: Arc<dyn Clock>,
    liveness: Option<LivenessFn>,
    config: AgentConfig,
}

/// The outcome of the checks before a prompt.
struct Prepared {
    who: Who,
    client: Client,
    key: KeyInfo,
    ctx: SignCtx,
    /// The grant key when the request may be remembered.
    grant_key: Option<String>,
    /// Set when a live grant covers the request (no prompt).
    remembered: bool,
    req: ApprovalRequest,
}

impl<K: KeySource> Agent<K> {
    /// An unlocked agent, paired or open as `guards` say.
    pub fn new(
        source: K,
        approver: Arc<dyn Approver>,
        audit: Box<dyn AuditSink + Send>,
        config: AgentConfig,
        guards: AgentGuards,
    ) -> Self {
        Agent {
            paired: guards.pairing.is_some(),
            inner: Mutex::new(Inner {
                source,
                audit,
                locked: None,
                unlock_failures: 0,
                unlock_not_before: None,
                lock_floor: None,
                pairing: guards.pairing,
                memory_grants: HashMap::new(),
                throttle: guards.throttle,
                unpaired_audited: VecDeque::new(),
            }),
            gate: PromptGate::new(SharedApprover(approver), guards.prompt_wait),
            strong: guards.strong,
            clock: guards.clock,
            liveness: guards.liveness,
            config,
        }
    }

    /// False once the control channel is lost: the agent refuses every
    /// request and [`crate::serve`] stops.
    pub fn control_alive(&self) -> bool {
        self.liveness.as_ref().is_none_or(|alive| alive())
    }

    /// Requests of `client_id` for the key `fingerprint`, on a connection
    /// not bound to a destination, waiting for an identical pending prompt
    /// (diagnostics and tests).
    pub fn waiting_for_prompt(&self, client_id: &str, fingerprint: &str) -> usize {
        self.gate
            .waiting(client_id, &grant_key(client_id, fingerprint, None))
    }

    fn state(&self) -> MutexGuard<'_, Inner<K>> {
        // A panic under the lock leaves counters behind at worst; every
        // decision is taken again from the files and the registry.
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Handles one request from a peer on a connection.
    pub fn handle(&self, conn: &mut ConnState, peer: &PeerInfo, req: Request) -> Reply {
        // A peer of another uid, or whose uid the system cannot tell, is
        // refused and disconnected.
        if peer.uid != Some(effective_uid()) {
            return Reply::close();
        }
        if !self.control_alive() {
            let mut st = self.state();
            st.refuse_unpaired(&*self.clock, &Who::of(peer), ACTION_SIGN, "refused");
            return Reply::close();
        }
        match req {
            Request::RequestIdentities => self.identities(peer),
            Request::Sign {
                key_blob,
                data,
                flags,
            } => self.sign(conn, peer, &key_blob, &data, flags),
            Request::Lock(pass) => self.lock(peer, &pass),
            Request::Unlock(pass) => self.unlock(peer, &pass),
            Request::Extension { name, contents } if name == SESSION_BIND => {
                self.session_bind(conn, peer, &contents)
            }
            Request::Extension { .. } | Request::Unsupported(_) => Reply::failure(),
        }
    }

    /// The paired client behind `peer`, or the refusal already audited
    /// (at most [`MAX_UNPAIRED_AUDIT_PER_MIN`] entries a minute).
    fn admit(&self, st: &mut Inner<K>, peer: &PeerInfo, action: &str) -> Result<Client, ()> {
        st.admit(peer).map_err(|outcome| {
            st.refuse_unpaired(&*self.clock, &Who::of(peer), action, outcome);
        })
    }

    fn identities(&self, peer: &PeerInfo) -> Reply {
        let mut st = self.state();
        let Ok(client) = self.admit(&mut st, peer, ACTION_LIST) else {
            return Reply::send(Response::Identities(Vec::new()));
        };
        if st.locked.is_some() {
            return Reply::send(Response::Identities(Vec::new()));
        }
        match st.source.list() {
            Ok(keys) => Reply::send(Response::Identities(
                keys.into_iter()
                    .filter(|k| client.allows(k))
                    .map(|k| (k.public_blob, k.title))
                    .collect(),
            )),
            Err(_) => Reply::failure(),
        }
    }

    fn lock(&self, peer: &PeerInfo, pass: &[u8]) -> Reply {
        let mut st = self.state();
        if self.admit(&mut st, peer, ACTION_LOCK).is_err() || st.locked.is_some() {
            return Reply::failure();
        }
        st.locked = Some(digest(pass));
        st.unlock_failures = 0;
        st.unlock_not_before = None;
        // Spec 6.3: a grant lasts at most until LOCK.
        st.lock_floor = Some(self.clock.now_unix());
        st.memory_grants.clear();
        Reply::send(Response::Success)
    }

    fn unlock(&self, peer: &PeerInfo, pass: &[u8]) -> Reply {
        let mut st = self.state();
        if self.admit(&mut st, peer, ACTION_LOCK).is_err() {
            return Reply::failure();
        }
        let Some(expected) = &st.locked else {
            return Reply::failure();
        };
        // After a wrong passphrase, attempts are refused unchecked for a
        // delay that doubles at each failure (1 s, 2 s, 4 s, up to 60 s):
        // a client cannot guess a short passphrase at full speed. A refused
        // attempt does not count, so it cannot push the delay out.
        let now = self.clock.monotonic();
        if st.unlock_not_before.is_some_and(|t| now < t) {
            return Reply::failure();
        }
        let given = digest(pass);
        if aws_lc_rs::constant_time::verify_slices_are_equal(expected, &given).is_err() {
            st.unlock_failures = st.unlock_failures.saturating_add(1);
            let delay = Duration::from_secs(1u64 << st.unlock_failures.min(7).saturating_sub(1))
                .min(MAX_UNLOCK_DELAY);
            st.unlock_not_before = Some(now + delay);
            return Reply::failure();
        }
        st.locked = None;
        st.unlock_failures = 0;
        st.unlock_not_before = None;
        Reply::send(Response::Success)
    }

    fn session_bind(&self, conn: &mut ConnState, peer: &PeerInfo, contents: &[u8]) -> Reply {
        let mut st = self.state();
        let Ok(client) = self.admit(&mut st, peer, ACTION_SIGN) else {
            return Reply::failure();
        };
        let who = Who::of(peer).paired(&client);
        let parsed = (|| {
            let mut r = SshReader::new(contents);
            let host_key = r.string()?.to_vec();
            let session_id = r.string()?.to_vec();
            let signature = r.string()?.to_vec();
            let forwarding = r.u8()?;
            r.finish()?;
            Ok::<_, crate::wire::WireError>((host_key, session_id, signature, forwarding))
        })();
        let Ok((host_key, session_id, signature, forwarding)) = parsed else {
            st.record_bind(&who, "bind_malformed");
            return Reply::close();
        };
        if verify_signature(&host_key, &session_id, &signature).is_err() {
            st.record_bind(&who, "bind_bad_signature");
            return Reply::close();
        }
        let forwarded = forwarding != 0;
        match &conn.bound {
            // As OpenSSH: a connection bound for direct use cannot be bound
            // again (only forwarded hops add binds).
            Some(prev) if !prev.forwarded => {
                st.record_bind(&who, "bind_refused");
                Reply::failure()
            }
            // Once forwarded, always forwarded: a later hop cannot clear it.
            Some(_) => {
                conn.bound = Some(BoundHost {
                    host_key,
                    session_id,
                    forwarded: true,
                });
                Reply::send(Response::Success)
            }
            None => {
                conn.bound = Some(BoundHost {
                    host_key,
                    session_id,
                    forwarded,
                });
                Reply::send(Response::Success)
            }
        }
    }

    /// Counts a request of `kind` for the client, or refuses it (audited;
    /// a cooling down period is told once on the terminal). An open agent
    /// has no rate limit.
    fn throttle(&self, st: &mut Inner<K>, p: &Prepared, kind: Kind) -> Result<(), ()> {
        let Some(id) = p.client.id.as_deref().filter(|_| self.paired) else {
            return Ok(());
        };
        let outcome = match st.throttle.admit(&*self.clock, id, kind) {
            Admit::Ok => return Ok(()),
            Admit::RateLimited => OUTCOME_RATE_LIMITED,
            Admit::CoolingDown {
                until,
                first_notice,
            } => {
                if first_notice {
                    let left = until.saturating_duration_since(self.clock.monotonic());
                    eprintln!(
                        "onepass ssh-agent: {} refused for {} min after repeated denials",
                        sanitize_for_display(&p.client.label),
                        left.as_secs().div_ceil(60)
                    );
                }
                OUTCOME_CLIENT_COOLING_DOWN
            }
        };
        st.record(&p.who, Some(&p.key), &p.ctx, "policy", outcome);
        Err(())
    }

    /// Counts a user decision for the approval fatigue guard (paired agent
    /// only).
    fn record_decision(&self, st: &mut Inner<K>, client: &Client, denied: bool) {
        if let Some(id) = client.id.as_deref().filter(|_| self.paired) {
            st.throttle.record_decision(&*self.clock, id, denied);
        }
    }

    /// Every check up to the prompt, under the state lock. `Err` carries the
    /// reply of a refusal, already audited.
    fn prepare(
        &self,
        st: &mut Inner<K>,
        conn: &ConnState,
        peer: &PeerInfo,
        key_blob: &[u8],
        data: &[u8],
        flags: u32,
    ) -> Result<Prepared, Reply> {
        let client = self
            .admit(st, peer, ACTION_SIGN)
            .map_err(|()| Reply::failure())?;
        let who = Who::of(peer).paired(&client);
        let mut ctx = SignCtx {
            destination: None,
            namespace: sshsig_namespace(data),
            approved_on: None,
        };
        let refuse = |st: &mut Inner<K>, key: Option<&KeyInfo>, ctx: &SignCtx, outcome: &str| {
            st.record(&who, key, ctx, "policy", outcome);
            Reply::failure()
        };
        if st.locked.is_some() {
            return Err(refuse(st, None, &ctx, "refused"));
        }
        let key = match st.source.list() {
            Ok(keys) => keys.into_iter().find(|k| k.public_blob == key_blob),
            Err(_) => return Err(refuse(st, None, &ctx, "error")),
        };
        let Some(key) = key else {
            return Err(refuse(st, None, &ctx, "refused"));
        };
        // A key outside the client's list is unknown to it.
        if !client.allows(&key) {
            return Err(refuse(st, None, &ctx, "refused"));
        }
        // RSA with SHA-1 (no SHA-2 flag) is refused before asking anyone.
        if is_rsa(&key.public_blob)
            && flags & (SSH_AGENT_RSA_SHA2_256 | SSH_AGENT_RSA_SHA2_512) == 0
        {
            return Err(refuse(st, Some(&key), &ctx, "refused"));
        }
        let userauth = parse_userauth(data, &key.public_blob);
        // `ssh` (OpenSSH 8.9 and later) binds a connection before it signs
        // to authenticate. A userauth signature from `ssh` on an unbound
        // connection is either a local `ssh` older than 8.9 or an agent
        // forwarded by a client that sent no bind: the agent cannot tell.
        // It is not refused (older Linux distributions still ship such an
        // `ssh`), but it never counts as local: asked every time, shown as
        // forwarded, never remembered.
        let unbound_ssh_auth = conn.bound.is_none() && userauth.is_some() && peer_is_ssh(peer);
        let forwarded = conn.bound.as_ref().is_some_and(|b| b.forwarded);
        let git_exception = key.git_signing && ctx.namespace.as_deref() == Some(GIT_NAMESPACE);
        // A bound connection signs a userauth request for the bound session
        // only, and for a host-bound request only the bound host (as
        // OpenSSH's agent): the bind must not lend its destination to data
        // meant for another server. The git exception stays.
        if let Some(b) = &conn.bound {
            let same_session = userauth.as_ref().is_some_and(|u| {
                u.session_id == b.session_id.as_slice()
                    && u.host_key.is_none_or(|h| h == b.host_key.as_slice())
            });
            if !same_session && !git_exception {
                return Err(refuse(st, Some(&key), &ctx, OUTCOME_SESSION_MISMATCH));
            }
        }
        let matched = conn.bound.as_ref().map(|b| {
            let hosts = self.bookmarked_hosts(&b.host_key, &key.hosts);
            let fp = fingerprint_of_blob(&b.host_key);
            ctx.destination = Some(if hosts.is_empty() {
                fp
            } else {
                format!("{fp} ({})", hosts.join(", "))
            });
            !hosts.is_empty()
        });
        if forwarded && !self.config.allow_forwarded {
            return Err(refuse(st, Some(&key), &ctx, "refused"));
        }
        // Host binding (spec 6), paired agent: a key with bookmarks signs
        // only for a connection bound to one of them, except a commit
        // signature by a `git_signing` key. An open agent asks with a
        // warning instead.
        if self.paired && !key.hosts.is_empty() && matched != Some(true) && !git_exception {
            return Err(refuse(st, Some(&key), &ctx, OUTCOME_HOST_NOT_BOUND));
        }
        // Fail closed: no signature unless it can be logged.
        if st.audit.ready().is_err() {
            return Err(refuse(st, Some(&key), &ctx, "audit_unusable"));
        }

        // A grant is only possible for identified code: one id shared by
        // every unidentified peer would share its grants. It is keyed by
        // the code the kernel vouches for, never by the path of a pid (a
        // client can fork, exec `ssh` and keep the connection), and by the
        // destination the session is bound to.
        let rememberable = self.config.confirm == Confirm::Session
            && !key.confirm_each_use
            && !forwarded
            && !unbound_ssh_auth
            && client.id.is_some();
        let destination = conn
            .bound
            .as_ref()
            .map(|b| fingerprint_of_blob(&b.host_key));
        let mut p = Prepared {
            grant_key: client
                .id
                .as_deref()
                .filter(|_| rememberable)
                .map(|id| grant_key(id, &key.fingerprint, destination.as_deref())),
            req: self.approval_request(
                conn,
                &client,
                peer,
                &key,
                &ctx,
                forwarded || unbound_ssh_auth,
                rememberable,
            ),
            who,
            client,
            key,
            ctx,
            remembered: false,
        };
        self.throttle(st, &p, Kind::Secret)
            .map_err(|()| Reply::failure())?;
        if let Some(gk) = &p.grant_key {
            p.remembered = self.grant_live(st, &p, gk);
        }
        if !p.remembered {
            self.throttle(st, &p, Kind::Prompt)
                .map_err(|()| Reply::failure())?;
        }
        Ok(p)
    }

    /// Whether a live grant covers the request: the signed grants file of a
    /// paired agent (an expired or revoked grant is audited), the memory of
    /// an open one. A grant from before the last LOCK is not used.
    fn grant_live(&self, st: &mut Inner<K>, p: &Prepared, gk: &str) -> bool {
        let Some(id) = p.client.id.as_deref() else {
            return false;
        };
        let Some(pairing) = &st.pairing else {
            let now = self.clock.monotonic();
            st.memory_grants.retain(|_, until| *until > now);
            return st.memory_grants.contains_key(gk);
        };
        let check = pairing
            .grants
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .check(
                &*pairing.grants_signer,
                &*self.clock,
                id,
                Surface::Ssh,
                ACTION_SIGN,
                gk,
            );
        match check {
            GrantCheck::Valid(g) => st.lock_floor.is_none_or(|floor| g.created_at > floor),
            GrantCheck::Expired => {
                st.record(
                    &p.who,
                    Some(&p.key),
                    &p.ctx,
                    "policy",
                    OUTCOME_GRANT_EXPIRED,
                );
                false
            }
            GrantCheck::Revoked => {
                st.record(
                    &p.who,
                    Some(&p.key),
                    &p.ctx,
                    "policy",
                    OUTCOME_GRANT_REVOKED,
                );
                false
            }
            GrantCheck::None => false,
        }
    }

    /// Stores a grant of `d` for the request: in the signed grants file of
    /// a paired agent, in memory for an open one.
    fn add_grant(&self, st: &mut Inner<K>, p: &Prepared, gk: &str, d: Duration) {
        let Some(id) = p.client.id.as_deref() else {
            return;
        };
        let Some(pairing) = &st.pairing else {
            st.memory_grants
                .insert(gk.to_owned(), self.clock.monotonic() + d);
            return;
        };
        let req = GrantRequest {
            client_id: id.to_owned(),
            surface: Surface::Ssh,
            action: ACTION_SIGN.to_owned(),
            key: gk.to_owned(),
            vault_id: Some(p.key.vault_id.clone()),
        };
        let added = pairing
            .grants
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .add(&*pairing.grants_signer, &*self.clock, req, d);
        // The user allowed this signature: it goes ahead even if the grant
        // could not be stored (the next one asks again).
        if let Err(err) = added {
            eprintln!("onepass ssh-agent: grant not recorded: {err}");
        }
    }

    fn sign(
        &self,
        conn: &ConnState,
        peer: &PeerInfo,
        key_blob: &[u8],
        data: &[u8],
        flags: u32,
    ) -> Reply {
        let mut p = match self.prepare(&mut self.state(), conn, peer, key_blob, data, flags) {
            Ok(p) => p,
            Err(reply) => return reply,
        };

        // The prompt, without the state lock. Only a request that may be
        // remembered is coalesced with an identical pending one: a joined
        // request gets a deny or a grant, never someone else's "once". The
        // guard draws the code the user confirms; no code, no prompt.
        let gated = if p.remembered {
            None
        } else if let (Some(gk), Some(id)) = (&p.grant_key, &p.client.id) {
            Some(self.gate.approve(id, gk, &p.req))
        } else {
            let Some(code) = challenge_code() else {
                self.state()
                    .record(&p.who, Some(&p.key), &p.ctx, "denied", "refused");
                return Reply::failure();
            };
            let mut req = p.req.clone();
            req.confirm_code = code;
            let answer = self.gate.inner().approve(&req);
            Some(Gated {
                decision: answer.decision,
                approved_on: answer.approved_on,
                joined: false,
            })
        };
        let mut decision = "remembered";
        let mut allow_for = None;
        if let Some(gated) = gated {
            p.ctx.approved_on = gated.approved_on.clone();
            let label = |l: &'static str| if gated.joined { "joined" } else { l };
            let mut st = self.state();
            // With strong authentication to come, an allowed prompt does not
            // end a run of denials by itself (see below).
            let strong_follows = self.config.strong && gated.decision != Decision::Deny;
            if !gated.joined && !strong_follows {
                self.record_decision(&mut st, &p.client, gated.decision == Decision::Deny);
            }
            match gated.decision {
                Decision::Deny => {
                    st.record(&p.who, Some(&p.key), &p.ctx, label("denied"), "refused");
                    return Reply::failure();
                }
                Decision::AllowFor(d) if p.grant_key.is_some() => {
                    let d = d.min(MAX_GRANT_TTL).min(self.config.remember_for);
                    allow_for = Some(d);
                    decision = label(decision_label(&Decision::AllowFor(d)));
                }
                Decision::AllowOnce | Decision::AllowFor(_) => decision = label("once"),
            }
        }

        // Strong authentication proves who answered: a failure counts as a
        // denial, an unavailable method refuses without counting.
        if self.config.strong {
            let reason = sanitize_for_display(&format!(
                "{ACTION_SIGN} for {}: {} / {}",
                p.client.label, p.key.vault_name, p.key.title
            ));
            let outcome = self.strong.verify(&reason);
            let mut st = self.state();
            match outcome {
                StrongOutcome::Verified => self.record_decision(&mut st, &p.client, false),
                StrongOutcome::Denied | StrongOutcome::Unavailable => {
                    if outcome == StrongOutcome::Denied {
                        self.record_decision(&mut st, &p.client, true);
                    }
                    st.record(
                        &p.who,
                        Some(&p.key),
                        &p.ctx,
                        decision,
                        OUTCOME_STRONG_AUTH_FAILED,
                    );
                    return Reply::failure();
                }
            }
        }

        let mut st = self.state();
        // Locked while the user was asked: nothing is signed.
        if st.locked.is_some() {
            st.record(&p.who, Some(&p.key), &p.ctx, decision, "refused");
            return Reply::failure();
        }
        if let (Some(d), Some(gk)) = (allow_for, &p.grant_key) {
            self.add_grant(&mut st, &p, gk, d);
        }
        let signature = st
            .source
            .load(&p.key.item_id)
            .ok()
            // The loaded key must be the one that was listed and approved.
            .filter(|k| k.public_blob() == p.key.public_blob)
            .and_then(|k| k.sign(data, flags).ok());
        match signature {
            Some(sig) => {
                st.record(&p.who, Some(&p.key), &p.ctx, decision, "ok");
                Reply::send(Response::Signature(sig))
            }
            None => {
                st.record(&p.who, Some(&p.key), &p.ctx, decision, "error");
                Reply::failure()
            }
        }
    }

    /// The approval request of a signature: paired clients by label and
    /// client id, an open agent's peers by executable and code identity.
    #[allow(clippy::too_many_arguments)]
    fn approval_request(
        &self,
        conn: &ConnState,
        client: &Client,
        peer: &PeerInfo,
        key: &KeyInfo,
        ctx: &SignCtx,
        forwarded: bool,
        remember_allowed: bool,
    ) -> ApprovalRequest {
        let pid = peer
            .pid
            .map_or_else(|| "unknown pid".to_owned(), |p| p.to_string());
        let exe = peer.exe.as_deref().unwrap_or(UNKNOWN_PROCESS);
        let mut details = vec![
            ("key".to_owned(), key.title.clone()),
            ("fingerprint".to_owned(), key.fingerprint.clone()),
        ];
        if client.paired {
            details.push((
                "client id".to_owned(),
                client.id.clone().unwrap_or_default(),
            ));
            if let Some(h) = client.hardened {
                details.push((
                    "hardened runtime".to_owned(),
                    if h { "yes" } else { "no" }.to_owned(),
                ));
            }
            details.push(("process".to_owned(), format!("{exe} ({pid})")));
        } else {
            details.push(("process".to_owned(), format!("{exe} ({pid})")));
            details.push((
                "code".to_owned(),
                client
                    .id
                    .clone()
                    .unwrap_or_else(|| "unidentified".to_owned()),
            ));
        }
        if let (Some(_), Some(destination)) = (&conn.bound, &ctx.destination) {
            details.push(("destination".to_owned(), destination.clone()));
        }
        let unmatched = |b: &BoundHost| self.bookmarked_hosts(&b.host_key, &key.hosts).is_empty();
        if !key.hosts.is_empty() {
            if self.paired {
                // Only the git exception reaches a prompt with a key whose
                // bookmarks the destination does not match.
                if conn.bound.as_ref().is_none_or(unmatched) {
                    details.push((
                        "warning".to_owned(),
                        "not bound to one of this key's hosts: allowed for git commit signing only"
                            .to_owned(),
                    ));
                }
            } else if conn.bound.as_ref().is_some_and(unmatched) {
                details.push((
                    "warning".to_owned(),
                    "the destination matches none of this key's host bookmarks".to_owned(),
                ));
            }
        }
        details.push((
            "forwarded".to_owned(),
            if forwarded { "yes" } else { "no" }.to_owned(),
        ));
        if let Some(ns) = &ctx.namespace {
            details.push(("namespace".to_owned(), ns.clone()));
        }
        ApprovalRequest {
            surface: Surface::Ssh,
            client: client.label.clone(),
            client_verified: client.verified,
            action: ACTION_SIGN.to_owned(),
            details,
            targets: vec![Target {
                vault: key.vault_name.clone(),
                item: key.title.clone(),
                field: Some(KEY_FIELD.to_owned()),
            }],
            remember_allowed,
            // `--strong` runs its own check after the prompt.
            strong_required: false,
            // Drawn right before the prompt.
            confirm_code: String::new(),
        }
    }

    /// Bookmarks of a key that the configured `known_hosts` files list with
    /// `host_key`. Unreadable files are skipped.
    fn bookmarked_hosts(&self, host_key: &[u8], bookmarks: &[String]) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        if bookmarks.is_empty() {
            return out;
        }
        for path in &self.config.known_hosts {
            let Ok(text) = std::fs::read_to_string(path) else {
                continue;
            };
            for h in matching_hosts(&text, host_key, bookmarks) {
                if !out.iter().any(|o| o.eq_ignore_ascii_case(&h)) {
                    out.push(h);
                }
            }
        }
        out
    }
}

impl<K: KeySource> Inner<K> {
    /// The paired client behind `peer`, or the audit outcome of the refusal
    /// (`not_paired`, `registry_unusable`). An open agent admits every peer
    /// (the uid was checked before), unverified, by its executable.
    fn admit(&mut self, peer: &PeerInfo) -> Result<Client, &'static str> {
        let Some(pairing) = &mut self.pairing else {
            return Ok(Client {
                id: peer
                    .code
                    .clone()
                    .or_else(|| peer.identity.as_ref().map(|i| i.code.client_id())),
                label: peer
                    .exe
                    .clone()
                    .unwrap_or_else(|| UNKNOWN_PROCESS.to_owned()),
                paired: false,
                verified: false,
                hardened: None,
                ssh_keys: None,
            });
        };
        let identity = peer.identity.as_ref().ok_or(OUTCOME_NOT_PAIRED)?;
        let id = identity.code.client_id();
        let reg = (pairing.registry)().map_err(|_| OUTCOME_REGISTRY_UNUSABLE)?;
        let rec = reg.find(Surface::Ssh, &id).ok_or(OUTCOME_NOT_PAIRED)?;
        Ok(Client {
            label: rec.label.clone(),
            paired: true,
            verified: identity.code.is_signed(),
            hardened: match &identity.code {
                CodeIdentity::AdHoc { hardened, .. } => Some(*hardened),
                _ => None,
            },
            ssh_keys: rec.ssh_keys.clone(),
            id: Some(id),
        })
    }

    /// Audits a refusal before pairing, at most
    /// [`MAX_UNPAIRED_AUDIT_PER_MIN`] a minute over every client.
    fn refuse_unpaired(&mut self, clock: &dyn Clock, who: &Who, action: &str, outcome: &str) {
        let now = clock.monotonic();
        let minute = Duration::from_secs(60);
        while self
            .unpaired_audited
            .front()
            .is_some_and(|&t| now.saturating_duration_since(t) >= minute)
        {
            self.unpaired_audited.pop_front();
        }
        if self.unpaired_audited.len() >= MAX_UNPAIRED_AUDIT_PER_MIN {
            return;
        }
        self.unpaired_audited.push_back(now);
        self.write(AuditEntry {
            surface: Surface::Ssh,
            client: who.exe.clone(),
            client_id: who.client_id.clone(),
            client_label: None,
            action: action.to_owned(),
            vault_id: None,
            item_id: None,
            field: None,
            decision: "policy".to_owned(),
            outcome: outcome.to_owned(),
            approved_on: None,
            destination: None,
            namespace: None,
        });
    }

    /// Records a sign attempt. A failed write cannot undo a signature
    /// already returned: it goes to stderr. Signing itself checked the log
    /// with [`AuditSink::ready`] first.
    fn record(
        &mut self,
        who: &Who,
        key: Option<&KeyInfo>,
        ctx: &SignCtx,
        decision: &str,
        outcome: &str,
    ) {
        self.write(AuditEntry {
            surface: Surface::Ssh,
            client: who.exe.clone(),
            client_id: who.client_id.clone(),
            client_label: who.label.clone(),
            action: ACTION_SIGN.to_owned(),
            vault_id: key.map(|k| k.vault_id.clone()),
            item_id: key.map(|k| k.item_id.clone()),
            field: key.map(|_| KEY_FIELD.to_owned()),
            decision: decision.to_owned(),
            outcome: outcome.to_owned(),
            approved_on: ctx.approved_on.clone(),
            destination: ctx.destination.clone(),
            namespace: ctx.namespace.clone(),
        });
    }

    fn record_bind(&mut self, who: &Who, outcome: &str) {
        self.record(who, None, &SignCtx::default(), "policy", outcome);
    }

    fn write(&mut self, e: AuditEntry) {
        if let Err(err) = self.audit.record(&e) {
            eprintln!("onepass: audit log write failed: {err}");
        }
    }
}

fn digest(pass: &[u8]) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(
        aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, pass)
            .as_ref()
            .to_vec(),
    )
}

/// What a userauth request to sign names (RFC 4252 section 7).
struct Userauth<'a> {
    session_id: &'a [u8],
    /// The server host key of a `publickey-hostbound-v00@openssh.com`
    /// request.
    host_key: Option<&'a [u8]>,
}

/// `data` as a public key userauth request for `key_blob`: `string
/// session_id, byte 50, string user, string service, string method,
/// boolean TRUE, string algorithm, string key` and, for the host-bound
/// method, `string host_key`, nothing after. `None` for anything else.
fn parse_userauth<'a>(data: &'a [u8], key_blob: &[u8]) -> Option<Userauth<'a>> {
    let mut r = SshReader::new(data);
    let session_id = r.string().ok()?;
    if session_id.is_empty() || r.u8().ok()? != SSH_MSG_USERAUTH_REQUEST {
        return None;
    }
    r.string().ok()?;
    r.string().ok()?;
    let method = r.string().ok()?;
    let hostbound = match method {
        b"publickey" => false,
        HOSTBOUND_METHOD => true,
        _ => return None,
    };
    if r.u8().ok()? != 1 {
        return None;
    }
    r.string().ok()?;
    if r.string().ok()? != key_blob {
        return None;
    }
    let host_key = if hostbound {
        Some(r.string().ok()?)
    } else {
        None
    };
    r.finish().ok()?;
    Some(Userauth {
        session_id,
        host_key,
    })
}

/// Whether the peer runs OpenSSH's `ssh` client (by executable name).
fn peer_is_ssh(peer: &PeerInfo) -> bool {
    peer.exe
        .as_deref()
        .and_then(|e| std::path::Path::new(e).file_name())
        .is_some_and(|n| n == "ssh")
}

fn is_rsa(public_blob: &[u8]) -> bool {
    SshReader::new(public_blob).string().ok() == Some(b"ssh-rsa".as_slice())
}
