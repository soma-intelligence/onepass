//! Agent logic: which request gets which response, behind user approval
//! (spec 6.2 to 6.4).
//!
//! The keys live in the vault: a [`KeySource`] lists them on every request
//! and loads a private key only to sign, after approval. Nothing is added to
//! or removed from the agent by clients.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use data_encoding::BASE64;
use onepass_core::Id;
use onepass_core::model::{FieldValue, Item, ItemType};
use onepass_core::repo::Repository;
use onepass_core::store::RecordStore;
use onepass_guard::{
    ApprovalRequest, Approver, AuditEntry, AuditSink, Decision, Surface, Target, decision_label,
};
use onepass_peer::effective_uid;
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
/// Client name when the peer's executable is unknown.
const UNKNOWN_PROCESS: &str = "unknown process";
const SESSION_BIND: &str = "session-bind@openssh.com";

/// What the kernel says about a connected client (spec 6.3). Each part is
/// `None` when the platform or the kernel cannot tell.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PeerInfo {
    /// Effective uid of the peer.
    pub uid: Option<u32>,
    /// Pid of the peer (at connection time).
    pub pid: Option<i32>,
    /// Executable path of that pid. Informative: a pid can be reused.
    pub exe: Option<String>,
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
    /// Host bookmarks (names or OpenSSH `Host` patterns).
    pub hosts: Vec<String>,
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

/// A verified `session-bind@openssh.com`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoundHost {
    /// Host key blob of the destination.
    pub host_key: Vec<u8>,
    /// Whether the connection is a forwarded agent.
    pub forwarded: bool,
}

/// Agent settings.
#[derive(Clone, Debug)]
pub struct AgentConfig {
    /// Sign on forwarded connections (always with approval).
    pub allow_forwarded: bool,
    /// `known_hosts` files read to name a bound destination.
    pub known_hosts: Vec<PathBuf>,
    /// Ceiling of a grant: an "allow for N minutes" answer lasts N minutes,
    /// at most this long.
    pub remember_for: Duration,
}

impl Default for AgentConfig {
    fn default() -> Self {
        AgentConfig {
            allow_forwarded: false,
            known_hosts: Vec::new(),
            remember_for: Duration::from_secs(3600),
        }
    }
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
}

/// The SSH agent: approvals, session grants, lock state and audit.
pub struct Agent<K: KeySource> {
    source: K,
    approver: Arc<dyn Approver>,
    audit: Box<dyn AuditSink + Send>,
    config: AgentConfig,
    /// SHA-256 of the lock passphrase while locked.
    locked: Option<Zeroizing<Vec<u8>>>,
    /// "Allow for the session" grants: (key fingerprint, executable) to
    /// expiry.
    grants: HashMap<(String, String), Instant>,
}

impl<K: KeySource> Agent<K> {
    /// An unlocked agent with no grant.
    pub fn new(
        source: K,
        approver: Arc<dyn Approver>,
        audit: Box<dyn AuditSink + Send>,
        config: AgentConfig,
    ) -> Self {
        Agent {
            source,
            approver,
            audit,
            config,
            locked: None,
            grants: HashMap::new(),
        }
    }

    /// Handles one request from a peer on a connection.
    pub fn handle(&mut self, conn: &mut ConnState, peer: &PeerInfo, req: Request) -> Reply {
        // A peer of another uid, or whose uid the system cannot tell, is
        // refused and disconnected.
        if peer.uid != Some(effective_uid()) {
            return Reply {
                response: Response::Failure,
                close: true,
            };
        }
        match req {
            Request::RequestIdentities => self.identities(),
            Request::Sign {
                key_blob,
                data,
                flags,
            } => self.sign(conn, peer, &key_blob, &data, flags),
            Request::Lock(pass) => self.lock(&pass),
            Request::Unlock(pass) => self.unlock(&pass),
            Request::Extension { name, contents } if name == SESSION_BIND => {
                self.session_bind(conn, peer, &contents)
            }
            Request::Extension { .. } | Request::Unsupported(_) => Reply::failure(),
        }
    }

    fn identities(&mut self) -> Reply {
        if self.locked.is_some() {
            return Reply::send(Response::Identities(Vec::new()));
        }
        match self.source.list() {
            Ok(keys) => Reply::send(Response::Identities(
                keys.into_iter().map(|k| (k.public_blob, k.title)).collect(),
            )),
            Err(_) => Reply::failure(),
        }
    }

    fn lock(&mut self, pass: &[u8]) -> Reply {
        if self.locked.is_some() {
            return Reply::failure();
        }
        self.locked = Some(digest(pass));
        // Spec 6.3: a session grant lasts at most until LOCK.
        self.grants.clear();
        Reply::send(Response::Success)
    }

    fn unlock(&mut self, pass: &[u8]) -> Reply {
        let Some(expected) = &self.locked else {
            return Reply::failure();
        };
        let given = digest(pass);
        if aws_lc_rs::constant_time::verify_slices_are_equal(expected, &given).is_err() {
            return Reply::failure();
        }
        self.locked = None;
        Reply::send(Response::Success)
    }

    fn session_bind(&mut self, conn: &mut ConnState, peer: &PeerInfo, contents: &[u8]) -> Reply {
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
            self.record_bind(peer, "bind_malformed");
            return Reply {
                response: Response::Failure,
                close: true,
            };
        };
        if verify_signature(&host_key, &session_id, &signature).is_err() {
            self.record_bind(peer, "bind_bad_signature");
            return Reply {
                response: Response::Failure,
                close: true,
            };
        }
        let forwarded = forwarding != 0;
        match &conn.bound {
            // As OpenSSH: a connection bound for direct use cannot be bound
            // again (only forwarded hops add binds).
            Some(prev) if !prev.forwarded => {
                self.record_bind(peer, "bind_refused");
                Reply::failure()
            }
            // Once forwarded, always forwarded: a later hop cannot clear it.
            Some(_) => {
                conn.bound = Some(BoundHost {
                    host_key,
                    forwarded: true,
                });
                Reply::send(Response::Success)
            }
            None => {
                conn.bound = Some(BoundHost {
                    host_key,
                    forwarded,
                });
                Reply::send(Response::Success)
            }
        }
    }

    fn sign(
        &mut self,
        conn: &ConnState,
        peer: &PeerInfo,
        key_blob: &[u8],
        data: &[u8],
        flags: u32,
    ) -> Reply {
        let exe = peer
            .exe
            .clone()
            .unwrap_or_else(|| UNKNOWN_PROCESS.to_owned());
        if self.locked.is_some() {
            self.record_sign(&exe, None, "policy", "refused");
            return Reply::failure();
        }
        let key = match self.source.list() {
            Ok(keys) => keys.into_iter().find(|k| k.public_blob == key_blob),
            Err(_) => {
                self.record_sign(&exe, None, "policy", "error");
                return Reply::failure();
            }
        };
        let Some(key) = key else {
            self.record_sign(&exe, None, "policy", "refused");
            return Reply::failure();
        };
        // RSA with SHA-1 (no SHA-2 flag) is refused before asking anyone.
        if is_rsa(&key.public_blob)
            && flags & (SSH_AGENT_RSA_SHA2_256 | SSH_AGENT_RSA_SHA2_512) == 0
        {
            self.record_sign(&exe, Some(&key), "policy", "refused");
            return Reply::failure();
        }
        let forwarded = conn.bound.as_ref().is_some_and(|b| b.forwarded);
        if forwarded && !self.config.allow_forwarded {
            self.record_sign(&exe, Some(&key), "policy", "refused");
            return Reply::failure();
        }

        // A grant is only possible for an identified executable: "unknown
        // process" would share one grant between every unidentified peer.
        let rememberable = !key.confirm_each_use && !forwarded && peer.exe.is_some();
        let grant_key = (key.fingerprint.clone(), exe.clone());
        // Fail closed: no signature unless it can be logged.
        if self.audit.ready().is_err() {
            self.record_sign(&exe, Some(&key), "policy", "audit_unusable");
            return Reply::failure();
        }
        let now = Instant::now();
        self.grants.retain(|_, until| *until > now);
        let decision = if rememberable && self.grants.contains_key(&grant_key) {
            "remembered"
        } else {
            let req = self.approval_request(conn, peer, &key, &exe, data, forwarded, rememberable);
            match self.approver.approve(&req) {
                Decision::Deny => {
                    self.record_sign(&exe, Some(&key), "denied", "refused");
                    return Reply::failure();
                }
                Decision::AllowOnce => "once",
                Decision::AllowFor(d) if rememberable => {
                    let d = d.min(self.config.remember_for);
                    self.grants.insert(grant_key, Instant::now() + d);
                    decision_label(&Decision::AllowFor(d))
                }
                Decision::AllowFor(_) => "once",
            }
        };

        let signature = self
            .source
            .load(&key.item_id)
            .ok()
            // The loaded key must be the one that was listed and approved.
            .filter(|k| k.public_blob() == key.public_blob)
            .and_then(|k| k.sign(data, flags).ok());
        match signature {
            Some(sig) => {
                self.record_sign(&exe, Some(&key), decision, "ok");
                Reply::send(Response::Signature(sig))
            }
            None => {
                self.record_sign(&exe, Some(&key), decision, "error");
                Reply::failure()
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn approval_request(
        &self,
        conn: &ConnState,
        peer: &PeerInfo,
        key: &KeyInfo,
        exe: &str,
        data: &[u8],
        forwarded: bool,
        remember_allowed: bool,
    ) -> ApprovalRequest {
        let pid = peer
            .pid
            .map_or_else(|| "unknown pid".to_owned(), |p| p.to_string());
        let mut details = vec![
            ("key".to_owned(), key.title.clone()),
            ("fingerprint".to_owned(), key.fingerprint.clone()),
            ("process".to_owned(), format!("{exe} ({pid})")),
        ];
        if let Some(bound) = &conn.bound {
            let hosts = self.bookmarked_hosts(&bound.host_key, &key.hosts);
            let host_fp = fingerprint_of_blob(&bound.host_key);
            let destination = if hosts.is_empty() {
                host_fp
            } else {
                format!("{host_fp} ({})", hosts.join(", "))
            };
            details.push(("destination".to_owned(), destination));
            if hosts.is_empty() && !key.hosts.is_empty() {
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
        if let Some(ns) = sshsig_namespace(data) {
            details.push(("namespace".to_owned(), ns));
        }
        ApprovalRequest {
            surface: Surface::Ssh,
            client_verified: false,
            client: exe.to_owned(),
            action: ACTION_SIGN.to_owned(),
            details,
            targets: vec![Target {
                vault: key.vault_name.clone(),
                item: key.title.clone(),
                field: Some(KEY_FIELD.to_owned()),
            }],
            remember_allowed,
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

    /// Records a sign attempt. A failed write cannot undo a signature
    /// already returned: it goes to stderr. Signing itself checked the log
    /// with [`AuditSink::ready`] first.
    fn record_sign(&mut self, exe: &str, key: Option<&KeyInfo>, decision: &str, outcome: &str) {
        let written = self.audit.record(&AuditEntry {
            surface: Surface::Ssh,
            client: exe.to_owned(),
            client_id: None,
            client_label: None,
            action: ACTION_SIGN.to_owned(),
            vault_id: key.map(|k| k.vault_id.clone()),
            item_id: key.map(|k| k.item_id.clone()),
            field: key.map(|_| KEY_FIELD.to_owned()),
            decision: decision.to_owned(),
            outcome: outcome.to_owned(),
        });
        report_audit_failure(written);
    }

    fn record_bind(&mut self, peer: &PeerInfo, outcome: &str) {
        let exe = peer
            .exe
            .clone()
            .unwrap_or_else(|| UNKNOWN_PROCESS.to_owned());
        let written = self.audit.record(&AuditEntry {
            surface: Surface::Ssh,
            client: exe,
            client_id: None,
            client_label: None,
            action: ACTION_SIGN.to_owned(),
            vault_id: None,
            item_id: None,
            field: None,
            decision: "policy".to_owned(),
            outcome: outcome.to_owned(),
        });
        report_audit_failure(written);
    }
}

fn report_audit_failure(written: Result<(), onepass_guard::GuardError>) {
    if let Err(err) = written {
        eprintln!("onepass: audit log write failed: {err}");
    }
}

fn digest(pass: &[u8]) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(
        aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, pass)
            .as_ref()
            .to_vec(),
    )
}

fn is_rsa(public_blob: &[u8]) -> bool {
    SshReader::new(public_blob).string().ok() == Some(b"ssh-rsa".as_slice())
}
