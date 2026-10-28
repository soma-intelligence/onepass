//! What the app's settings show and change: the signed MCP policy, the
//! paired clients, the live grants and the audit log.
//!
//! The grant store and the client registry loader of a data folder are one
//! object per process ([`guard_state`]), shared with the running MCP
//! server: a revocation or an unpairing made here applies to the server's
//! memory at once, even if a file is later restored (spec section 4.3).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use onepass_guard::{
    AuditEntry, AuditLog, AuditRecord, AuditSink, ClientRegistry, ClientRegistryLoader, GrantStore,
    Revoke, SignedAuditSink, Surface, SystemClock, head_path, verify_log,
};
use onepass_mcp::{Policy, PolicyError, Scope, load_policy, save_policy};
use onepass_peer::{CodeIdentity, identity_of_file};

use super::{
    AUDIT_FILE, CLIENTS_FILE, GRANTS_FILE, POLICY_FILE, SessionSigner, data_dir, guard_account_id,
    guard_error,
};
use crate::error::{OnePassError, invalid};
use crate::session::Session;

/// The guard objects of one data folder, shared by the settings and the
/// running servers of this process.
pub(crate) struct GuardState {
    pub grants: Arc<Mutex<GrantStore>>,
    pub loader: Arc<Mutex<ClientRegistryLoader>>,
    /// Pairing questions by client id: one at a time, and a pause after a
    /// refusal.
    pub pairing: Mutex<HashMap<String, PairingState>>,
}

/// Where the pairing of one client stands.
pub(crate) enum PairingState {
    /// The user is being asked.
    Asking,
    /// The user refused at this time.
    RefusedAt(std::time::Instant),
}

/// The [`GuardState`] of `dir` for `account_id`, made on first use. A new
/// account in the same folder gets fresh state.
pub(crate) fn guard_state(dir: &Path, account_id: &str) -> Arc<GuardState> {
    /// One state per (data folder, account).
    type States = HashMap<(PathBuf, String), Arc<GuardState>>;
    static STATES: OnceLock<Mutex<States>> = OnceLock::new();
    let mut states = STATES
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    states
        .entry((dir.to_path_buf(), account_id.to_owned()))
        .or_insert_with(|| {
            Arc::new(GuardState {
                grants: Arc::new(Mutex::new(GrantStore::open(
                    dir.join(GRANTS_FILE),
                    account_id,
                ))),
                loader: Arc::new(Mutex::new(ClientRegistryLoader::new())),
                pairing: Mutex::new(HashMap::new()),
            })
        })
        .clone()
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// One vault in the MCP policy.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiMcpVault {
    pub vault_id: String,
    pub name: String,
    /// The vault's own flag (meta). The app exposes a vault only when the
    /// flag is on and the signed policy lists it.
    pub mcp_access: bool,
    /// Scopes the signed policy grants: `metadata`, `use`, `write`,
    /// `totp`, `reveal`. Empty: not exposed.
    pub scopes: Vec<String>,
}

/// The signed policy as the settings show it.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiMcpPolicy {
    pub vaults: Vec<FfiMcpVault>,
    pub allow_generate: bool,
}

fn scopes_of(names: &[String]) -> Result<BTreeSet<Scope>, OnePassError> {
    names
        .iter()
        .map(|n| n.parse::<Scope>().map_err(|_| invalid("scope")))
        .collect()
}

fn names_of(scopes: &BTreeSet<Scope>) -> Vec<String> {
    scopes.iter().map(|s| s.as_str().to_owned()).collect()
}

fn policy_error(e: PolicyError) -> OnePassError {
    match e {
        PolicyError::Io(_) => invalid("MCP policy unreadable"),
        _ => OnePassError::Integrity {
            kind: "signature".into(),
        },
    }
}

/// The app's policy: the signed file, or none at all (nothing exposed)
/// when it is missing. Unlike the CLI, a vault the file does not list gets
/// no scope (spec 4.4).
pub(crate) fn app_policy(session: &Arc<Session>, dir: &Path) -> Result<Policy, OnePassError> {
    let account = guard_account_id(session)?;
    let path = dir.join(POLICY_FILE);
    if !path.exists() {
        return Ok(Policy {
            account_id: account,
            vaults: BTreeMap::new(),
            allow_generate: true,
        });
    }
    load_policy(&path, &SessionSigner(session.clone()), &account).map_err(policy_error)
}

/// The vault ids the app exposes: listed by the policy with a scope.
pub(crate) fn exposed_vaults(policy: &Policy) -> BTreeSet<String> {
    policy
        .vaults
        .iter()
        .filter(|(_, s)| !s.is_empty())
        .map(|(v, _)| v.clone())
        .collect()
}

/// A paired client.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiPairedClient {
    pub id: String,
    /// `mcp` or `ssh`.
    pub surface: String,
    pub label: String,
    pub signed: bool,
    pub paired_at: i64,
    /// MCP scopes per vault id.
    pub scopes: Vec<FfiClientScopes>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiClientScopes {
    pub vault_id: String,
    pub scopes: Vec<String>,
}

/// A live grant.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiGrant {
    pub id: String,
    pub client_id: String,
    pub surface: String,
    pub action: String,
    pub vault_id: Option<String>,
    pub created_at: i64,
    pub expires_at: i64,
}

/// One verified audit entry, ids translated to names where the session
/// knows them.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiAuditEntry {
    pub seq: u64,
    /// UTC time, RFC 3339.
    pub time: String,
    pub surface: String,
    pub client: String,
    pub action: String,
    pub vault: Option<String>,
    pub item: Option<String>,
    pub field: Option<String>,
    pub decision: String,
    pub outcome: String,
}

/// The audit log after verification. `problem` set: the chain or its head
/// failed verification (nothing is shown then, the log must be rotated).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiAuditReport {
    pub entries: Vec<FfiAuditEntry>,
    /// The last lines are not covered by the signed head yet (a crash
    /// between a line and its head).
    pub unsealed_tail: bool,
    pub problem: Option<String>,
}

fn surface_name(s: Surface) -> String {
    match s {
        Surface::Mcp => "mcp",
        Surface::Ssh => "ssh",
    }
    .into()
}

/// Lowercase hex without hyphens: ids as the app and the CLI write them
/// compare equal.
fn norm(id: &str) -> String {
    id.chars()
        .filter(|c| *c != '-')
        .flat_map(char::to_lowercase)
        .collect()
}

/// Whether a client id names code the system vouches for (platform or
/// team identity).
fn signed_id(id: &str) -> bool {
    id.starts_with("platform:") || id.starts_with("team:")
}

/// The code identity as stored in a client record (informative: the id is
/// what the guards compare).
pub(crate) fn code_json(code: &CodeIdentity) -> serde_json::Value {
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
            "kind": "adhoc", "path": path.display().to_string(), "cdhash": cdhash,
            "hardened": hardened,
        }),
        CodeIdentity::Unsigned { path, sha256 } => serde_json::json!({
            "kind": "unsigned", "path": path.display().to_string(), "sha256": sha256,
        }),
    }
}

#[uniffi::export]
impl Session {
    /// Every vault with its MCP flag and the scopes of the signed policy.
    pub fn mcp_policy(
        self: Arc<Self>,
        data_dir_path: String,
    ) -> Result<FfiMcpPolicy, OnePassError> {
        let me = self.clone();
        let dir = data_dir(&data_dir_path)?;
        let policy = app_policy(&me, &dir)?;
        let vaults = self.with(|repo| Ok(repo.vaults()?))?;
        Ok(FfiMcpPolicy {
            vaults: vaults
                .into_iter()
                .map(|v| {
                    let id = v.id.to_string();
                    FfiMcpVault {
                        vault_id: crate::convert::id_hex(v.id),
                        name: v.meta.name.clone(),
                        mcp_access: v.meta.mcp_access,
                        scopes: policy.vaults.get(&id).map(names_of).unwrap_or_default(),
                    }
                })
                .collect(),
            allow_generate: policy.allow_generate,
        })
    }

    /// Signs and writes the policy: each vault's scopes (empty: not
    /// exposed) and `allow_generate`. The app checks presence first.
    pub fn set_mcp_policy(
        self: Arc<Self>,
        data_dir_path: String,
        vaults: Vec<FfiClientScopes>,
        allow_generate: bool,
    ) -> Result<(), OnePassError> {
        let me = self.clone();
        let dir = data_dir(&data_dir_path)?;
        let account = guard_account_id(&me)?;
        let mut map = BTreeMap::new();
        for v in vaults {
            let id = crate::convert::parse_id(&v.vault_id)?;
            let scopes = scopes_of(&v.scopes)?;
            if !scopes.is_empty() {
                map.insert(id.to_string(), scopes);
            }
        }
        let policy = Policy {
            account_id: account,
            vaults: map,
            allow_generate,
        };
        save_policy(&dir.join(POLICY_FILE), &SessionSigner(me.clone()), &policy)
            .map_err(policy_error)?;
        audit_admin(&me, &dir, "mcp_policy_set", None, None);
        Ok(())
    }

    /// The paired clients of the registry, verified.
    pub fn paired_clients(
        self: Arc<Self>,
        data_dir_path: String,
    ) -> Result<Vec<FfiPairedClient>, OnePassError> {
        let me = self.clone();
        let dir = data_dir(&data_dir_path)?;
        let account = guard_account_id(&me)?;
        let state = guard_state(&dir, &account);
        let reg = lock(&state.loader)
            .load(&dir.join(CLIENTS_FILE), &SessionSigner(me), &account)
            .map_err(guard_error)?;
        Ok(reg
            .clients
            .iter()
            .map(|c| FfiPairedClient {
                id: c.id.clone(),
                surface: surface_name(c.surface),
                label: onepass_guard::sanitize_for_display(&c.label),
                signed: signed_id(&c.id),
                paired_at: c.paired_at,
                scopes: c
                    .mcp_scopes
                    .iter()
                    .flatten()
                    .map(|(v, s)| FfiClientScopes {
                        vault_id: norm(v),
                        scopes: s.iter().cloned().collect(),
                    })
                    .collect(),
            })
            .collect())
    }

    /// Changes a paired MCP client's scopes on one vault (empty: none).
    pub fn set_client_scopes(
        self: Arc<Self>,
        data_dir_path: String,
        client_id: String,
        vault_id: String,
        scopes: Vec<String>,
    ) -> Result<(), OnePassError> {
        let scopes = scopes_of(&scopes)?;
        let vault = crate::convert::parse_id(&vault_id)?.to_string();
        edit_registry(&self, &data_dir_path, |reg| {
            let c = reg
                .clients
                .iter_mut()
                .find(|c| c.surface == Surface::Mcp && c.id == client_id)
                .ok_or(OnePassError::NotFound)?;
            let map = c.mcp_scopes.get_or_insert_with(BTreeMap::new);
            if scopes.is_empty() {
                map.remove(&vault);
            } else {
                map.insert(vault.clone(), names_of(&scopes).into_iter().collect());
            }
            Ok(())
        })?;
        let dir = data_dir(&data_dir_path)?;
        audit_admin(
            &self,
            &dir,
            "client_scopes_set",
            Some(&client_id),
            Some(vault),
        );
        Ok(())
    }

    /// Unpairs a client, and revokes its grants, in the files and in the
    /// memory of this process's servers.
    pub fn unpair_client(
        self: Arc<Self>,
        data_dir_path: String,
        client_id: String,
    ) -> Result<(), OnePassError> {
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let mut unpaired = None;
        edit_registry(&self, &data_dir_path, |reg| {
            unpaired = Some(reg.unpair(&client_id, now));
            Ok(())
        })?;
        let me = self.clone();
        let dir = data_dir(&data_dir_path)?;
        let account = guard_account_id(&me)?;
        let state = guard_state(&dir, &account);
        if let Some(u) = unpaired {
            let mut loader = lock(&state.loader);
            let generation = loader.generation_seen;
            loader.apply_unpairs(generation, &[u]);
        }
        revoke(&self, &dir, &account, Revoke::Client(client_id.clone()))?;
        audit_admin(&self, &dir, "client_unpaired", Some(&client_id), None);
        Ok(())
    }

    /// Pairs the program at `path` for MCP (ad hoc or unsigned code, which
    /// is never paired from a prompt), with `metadata` and `use` on every
    /// exposed vault. The app shows the identity and checks presence
    /// first. Returns the client id.
    pub fn pair_program(
        self: Arc<Self>,
        data_dir_path: String,
        path: String,
    ) -> Result<String, OnePassError> {
        let code = identity_of_file(Path::new(&path)).map_err(|_| invalid("program identity"))?;
        let me = self.clone();
        let dir = data_dir(&data_dir_path)?;
        let policy = app_policy(&me, &dir)?;
        let label = Path::new(&path)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.clone());
        let client = onepass_mcp::ClientContext {
            client_id: code.client_id(),
            label,
            signed: code.is_signed(),
            hardened: match &code {
                CodeIdentity::AdHoc { hardened, .. } => Some(*hardened),
                _ => None,
            },
        };
        let id = client.client_id.clone();
        pair(&me, &dir, &client, code_json(&code), &policy)?;
        audit_admin(&me, &dir, "client_paired", Some(&id), None);
        Ok(id)
    }

    /// The live grants, verified.
    pub fn live_grants(
        self: Arc<Self>,
        data_dir_path: String,
    ) -> Result<Vec<FfiGrant>, OnePassError> {
        let me = self.clone();
        let dir = data_dir(&data_dir_path)?;
        let account = guard_account_id(&me)?;
        let state = guard_state(&dir, &account);
        let list = lock(&state.grants)
            .list(&SessionSigner(me), &SystemClock)
            .map_err(guard_error)?;
        Ok(list
            .into_iter()
            .map(|g| FfiGrant {
                id: g.id,
                client_id: g.client_id,
                surface: surface_name(g.surface),
                action: g.action,
                vault_id: g.vault_id.as_deref().map(norm),
                created_at: g.created_at,
                expires_at: g.expires_at,
            })
            .collect())
    }

    /// Revokes one grant, or all of them when `grant_id` is absent.
    pub fn revoke_grants(
        self: Arc<Self>,
        data_dir_path: String,
        grant_id: Option<String>,
    ) -> Result<(), OnePassError> {
        let me = self.clone();
        let dir = data_dir(&data_dir_path)?;
        let account = guard_account_id(&me)?;
        revoke(
            &self,
            &dir,
            &account,
            grant_id.map_or(Revoke::All, Revoke::Id),
        )?;
        audit_admin(&self, &dir, "grants_revoked", None, None);
        Ok(())
    }

    /// The audit log, verified; vault and item ids become names where the
    /// session knows them.
    pub fn audit_report(
        self: Arc<Self>,
        data_dir_path: String,
    ) -> Result<FfiAuditReport, OnePassError> {
        let me = self.clone();
        let dir = data_dir(&data_dir_path)?;
        let path = dir.join(AUDIT_FILE);
        if !path.exists() {
            return Ok(FfiAuditReport {
                entries: Vec::new(),
                unsealed_tail: false,
                problem: None,
            });
        }
        let verified = match verify_log(&path, &SessionSigner(me)) {
            Ok(v) => v,
            Err(e) => {
                return Ok(FfiAuditReport {
                    entries: Vec::new(),
                    unsealed_tail: false,
                    problem: Some(e.to_string()),
                });
            }
        };
        let (vaults, items) = self.with(|repo| {
            let mut vaults = HashMap::new();
            let mut items = HashMap::new();
            for v in repo.vaults()? {
                for i in repo.items(&v)? {
                    items.insert(norm(&i.id.to_string()), i.title.clone());
                }
                vaults.insert(norm(&v.id.to_string()), v.meta.name.clone());
            }
            Ok((vaults, items))
        })?;
        let name = |map: &HashMap<String, String>, id: &Option<String>| {
            id.as_ref()
                .map(|i| map.get(&norm(i)).cloned().unwrap_or_else(|| i.clone()))
        };
        let entries = verified
            .records
            .into_iter()
            .rev()
            .map(|AuditRecord { seq, ts, entry: e }| FfiAuditEntry {
                seq,
                time: ts,
                surface: surface_name(e.surface),
                client: onepass_guard::sanitize_for_display(
                    e.client_label.as_deref().unwrap_or(&e.client),
                ),
                action: e.action,
                vault: name(&vaults, &e.vault_id),
                item: name(&items, &e.item_id),
                field: e.field,
                decision: e.decision,
                outcome: e.outcome,
            })
            .collect();
        Ok(FfiAuditReport {
            entries,
            unsealed_tail: verified.unsealed_tail,
            problem: None,
        })
    }

    /// Archives the log and its head as `audit.log.<UTC time>.bad` (and
    /// `.bad.head`) and starts an empty one: the way out of a log that no
    /// longer verifies. Servers reopen the log path at their next entry.
    pub fn rotate_audit_log(self: Arc<Self>, data_dir_path: String) -> Result<(), OnePassError> {
        // Only from an unlocked app: the new log starts with a signed entry.
        guard_account_id(&self)?;
        let dir = data_dir(&data_dir_path)?;
        let path = dir.join(AUDIT_FILE);
        let stamp = time::OffsetDateTime::now_utc().unix_timestamp();
        let bad = dir.join(format!("{AUDIT_FILE}.{stamp}.bad"));
        let rename = |from: &Path, to: &Path| match std::fs::rename(from, to) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(invalid("audit log")),
            _ => Ok(()),
        };
        rename(&path, &bad)?;
        rename(
            &head_path(&path),
            &dir.join(format!("{AUDIT_FILE}.{stamp}.bad.head")),
        )?;
        audit_admin(&self, &dir, "audit_log_rotated", None, None);
        Ok(())
    }
}

/// Who changes the settings, in the audit log.
const SETTINGS_CLIENT: &str = "OnePass settings";

/// One signed audit entry for a change of the guards made from the app
/// (pairing, unpairing, scopes, policy, revocation, log rotation): the log
/// tells who could do what, and when that changed. A failure to write it
/// is not reported (the change itself is already made and verified).
pub(crate) fn audit_admin(
    session: &Arc<Session>,
    dir: &Path,
    action: &str,
    client: Option<&str>,
    vault: Option<String>,
) {
    let Ok(log) = AuditLog::open(&dir.join(AUDIT_FILE)) else {
        return;
    };
    let mut sink = SignedAuditSink {
        log,
        signer: SessionSigner(session.clone()),
    };
    let _ = sink.record(&AuditEntry {
        surface: Surface::Mcp,
        client: SETTINGS_CLIENT.into(),
        client_id: None,
        client_label: client.map(onepass_guard::sanitize_for_display),
        action: action.into(),
        vault_id: vault,
        item_id: None,
        field: None,
        decision: "allowed".into(),
        outcome: "ok".into(),
    });
}

fn edit_registry(
    session: &Arc<Session>,
    data_dir_path: &str,
    f: impl FnOnce(&mut ClientRegistry) -> Result<(), OnePassError>,
) -> Result<(), OnePassError> {
    let dir = data_dir(data_dir_path)?;
    let account = guard_account_id(session)?;
    let state = guard_state(&dir, &account);
    let signer = SessionSigner(session.clone());
    let mut loader = lock(&state.loader);
    let path = dir.join(CLIENTS_FILE);
    let mut reg = loader.load(&path, &signer, &account).map_err(guard_error)?;
    f(&mut reg)?;
    loader.save(&path, &signer, &mut reg).map_err(guard_error)
}

fn revoke(
    session: &Arc<Session>,
    dir: &Path,
    account: &str,
    which: Revoke,
) -> Result<(), OnePassError> {
    let state = guard_state(dir, account);
    let mut grants = lock(&state.grants);
    let out = grants
        .revoke(&SessionSigner(session.clone()), &SystemClock, which)
        .map_err(guard_error)?;
    grants.apply_revocations(
        &SystemClock,
        out.generation,
        &out.revoked,
        std::slice::from_ref(&out.selector),
    );
    Ok(())
}

/// Adds `client` to the registry for MCP with `metadata` and `use` on every
/// vault the policy exposes (replacing an older pairing of the same id).
pub(crate) fn pair(
    session: &Arc<Session>,
    dir: &Path,
    client: &onepass_mcp::ClientContext,
    code: serde_json::Value,
    policy: &Policy,
) -> Result<(), OnePassError> {
    let account = guard_account_id(session)?;
    let state = guard_state(dir, &account);
    let signer = SessionSigner(session.clone());
    let mut loader = lock(&state.loader);
    let path = dir.join(CLIENTS_FILE);
    let mut reg = loader.load(&path, &signer, &account).map_err(guard_error)?;
    // Already paired (two connections asked at once, or a pairing from the
    // settings): its scopes stay as the user set them.
    if reg.find(Surface::Mcp, &client.client_id).is_some() {
        return Ok(());
    }
    let scopes = onepass_mcp::default_client_scopes(exposed_vaults(policy));
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    reg.clients
        .push(onepass_mcp::mcp_client_record(client, code, &scopes, now));
    loader.save(&path, &signer, &mut reg).map_err(guard_error)
}
