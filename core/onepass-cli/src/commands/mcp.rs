//! `onepass mcp`: the MCP server over stdio, its signed policy and its
//! audit log (spec sections 4 and 7).
//!
//! The server unlocks once (password on `/dev/tty`, since stdin and stdout
//! carry the protocol), then every vault access is its own lock cycle
//! through [`LongSession::with_repo`]. Files: `<data-dir>/mcp-policy.json`,
//! `<data-dir>/audit.log` and `<data-dir>/audit.log.head`.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Arc;

use clap::{Args, Subcommand};
use onepass_core::Id;
use onepass_core::model::Item;
use onepass_core::reference::SecretRef;
use onepass_core::repo::Repository;
use onepass_core::store::SqliteStore;
use onepass_core::vault::Vault;
use onepass_guard::{
    Approver, AuditLog, AuditVerification, SignedAuditSink, TtyApprover,
    dev_auto_approver_from_env, sanitize_for_display, verify_log,
};
use onepass_mcp::{
    McpTools, Narrowing, Policy, PolicyError, PortError, RepoPort, Scope, VaultInfo, VaultPort,
    load_policy, save_policy, serve,
};
use zeroize::Zeroizing;

use super::vault::find_vault;
use crate::session::{CliError, Ctx, LongSession, stdout_error, stored, with_session};
use crate::signer::{RepoSigner, SharedSigner};

const POLICY_FILE: &str = "mcp-policy.json";
const AUDIT_FILE: &str = "audit.log";

/// `onepass mcp`: serve by default, or manage the policy and the audit log.
#[derive(Args)]
#[command(args_conflicts_with_subcommands = true)]
pub struct McpCmd {
    #[command(subcommand)]
    command: Option<McpSub>,
    /// Only expose this MCP vault (name or id), repeatable.
    #[arg(long = "vault")]
    vaults: Vec<String>,
    /// Only keep these scopes: comma list of metadata,use,write,totp,reveal.
    #[arg(long, value_parser = parse_scopes)]
    scopes: Option<BTreeSet<Scope>>,
}

#[derive(Subcommand)]
enum McpSub {
    /// Show or change the signed policy.
    #[command(subcommand)]
    Policy(PolicyCmd),
    /// Show the audit log, verified.
    Audit {
        /// Only verify the log and print the verdict.
        #[arg(long)]
        verify: bool,
    },
}

#[derive(Subcommand)]
enum PolicyCmd {
    /// The scopes in force on each MCP vault.
    Show,
    /// Set the scopes of an MCP vault (re-signs the policy).
    Set {
        /// MCP vault name or id.
        #[arg(long)]
        vault: String,
        /// Comma list of metadata,use,write,totp,reveal (may be empty).
        #[arg(long, value_parser = parse_scopes)]
        scopes: BTreeSet<Scope>,
        /// Whether `generate_password` is offered.
        #[arg(long, action = clap::ArgAction::Set)]
        allow_generate: Option<bool>,
    },
}

/// A comma list of scopes; an empty list is no scope at all.
fn parse_scopes(s: &str) -> Result<BTreeSet<Scope>, String> {
    s.split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(|p| {
            p.parse::<Scope>().map_err(|_| {
                format!("unknown scope '{p}' (expected metadata, use, write, totp or reveal)")
            })
        })
        .collect()
}

fn scope_list(scopes: &BTreeSet<Scope>) -> String {
    scopes
        .iter()
        .map(|s| s.as_str())
        .collect::<Vec<_>>()
        .join(",")
}

pub fn run(ctx: &Ctx, cmd: McpCmd) -> Result<(), CliError> {
    match cmd.command {
        None => serve_stdio(ctx, &cmd.vaults, cmd.scopes),
        Some(McpSub::Policy(PolicyCmd::Show)) => policy_show(ctx),
        Some(McpSub::Policy(PolicyCmd::Set {
            vault,
            scopes,
            allow_generate,
        })) => policy_set(ctx, &vault, scopes, allow_generate),
        Some(McpSub::Audit { verify }) => audit(ctx, verify),
    }
}

fn policy_path(ctx: &Ctx) -> PathBuf {
    ctx.data_dir.join(POLICY_FILE)
}

fn audit_path(ctx: &Ctx) -> PathBuf {
    ctx.data_dir.join(AUDIT_FILE)
}

/// A refused policy file: tampered, of another account or garbled all
/// exit 3 with the same message.
fn policy_error(e: PolicyError) -> CliError {
    match e {
        PolicyError::Io(kind) => CliError::usage(format!("i/o error: {kind}")),
        PolicyError::Tampered | PolicyError::WrongAccount | PolicyError::Format => CliError {
            code: 3,
            msg: "mcp policy failed verification".into(),
        },
    }
}

fn load(repo: &Repository<SqliteStore>, ctx: &Ctx) -> Result<Policy, CliError> {
    load_policy(
        &policy_path(ctx),
        &RepoSigner(repo),
        &repo.account_id().to_string(),
    )
    .map_err(policy_error)
}

/// The MCP vault whose id, or else name, is `key`; any other vault is
/// reported as missing.
fn find_mcp_vault<'a>(mcp: &'a [Vault], key: &str) -> Result<&'a Vault, CliError> {
    match find_vault(mcp, key) {
        Ok(i) => Ok(&mcp[i]),
        Err(e) if e.code == 4 => Err(CliError::not_found(format!("no MCP vault named '{key}'"))),
        Err(e) => Err(e),
    }
}

fn mcp_vaults(repo: &Repository<SqliteStore>) -> Result<Vec<Vault>, CliError> {
    Ok(stored(repo.vaults())?
        .into_iter()
        .filter(|v| v.meta.mcp_access)
        .collect())
}

fn policy_show(ctx: &Ctx) -> Result<(), CliError> {
    with_session(ctx, |repo| {
        let policy = load(repo, ctx)?;
        let vaults = mcp_vaults(repo)?;
        if ctx.json {
            let rows: Vec<_> = vaults
                .iter()
                .map(|v| {
                    let id = v.id.to_string();
                    serde_json::json!({
                        "id": id,
                        "name": v.meta.name,
                        "scopes": policy.scopes_for(&id),
                    })
                })
                .collect();
            crate::out!(
                "{}",
                serde_json::json!({ "vaults": rows, "allow_generate": policy.allow_generate })
            );
        } else {
            for v in &vaults {
                let id = v.id.to_string();
                crate::out!(
                    "{}  {}  {}",
                    sanitize_for_display(&v.meta.name),
                    id,
                    scope_list(&policy.scopes_for(&id))
                );
            }
            crate::out!("allow_generate: {}", policy.allow_generate);
        }
        Ok(())
    })
}

fn policy_set(
    ctx: &Ctx,
    vault: &str,
    scopes: BTreeSet<Scope>,
    allow_generate: Option<bool>,
) -> Result<(), CliError> {
    with_session(ctx, |repo| {
        let mut policy = load(repo, ctx)?;
        let vaults = mcp_vaults(repo)?;
        let v = find_mcp_vault(&vaults, vault)?;
        let id = v.id.to_string();
        policy.vaults.insert(id.clone(), scopes);
        if let Some(g) = allow_generate {
            policy.allow_generate = g;
        }
        save_policy(&policy_path(ctx), &RepoSigner(&*repo), &policy).map_err(policy_error)?;
        crate::out!(
            "policy of {} set: {}",
            id,
            scope_list(&policy.scopes_for(&id))
        );
        Ok(())
    })
}

/// The audit log, verified first: nothing is printed from a log that does
/// not verify. Without `verify_only`, every entry with vault names and item
/// titles resolved (sanitized for the terminal), then the verdict.
fn audit(ctx: &Ctx, verify_only: bool) -> Result<(), CliError> {
    with_session(ctx, |repo| {
        let path = audit_path(ctx);
        let failed = || CliError {
            code: 3,
            msg: "audit log failed verification".into(),
        };
        let verification = if path.exists() {
            verify_log(&path, &RepoSigner(&*repo)).map_err(|_| failed())?
        } else {
            let mut head = path.clone().into_os_string();
            head.push(".head");
            if PathBuf::from(head).exists() {
                return Err(failed());
            }
            AuditVerification {
                records: Vec::new(),
                unsealed_tail: false,
            }
        };
        if !verify_only {
            let (vault_names, titles) = names(repo)?;
            let show = |id: &Option<String>, names: &BTreeMap<String, String>| match id {
                None => "-".to_owned(),
                Some(i) => names
                    .get(i)
                    .map(|n| sanitize_for_display(n))
                    .unwrap_or_else(|| sanitize_for_display(i)),
            };
            for r in &verification.records {
                let e = &r.entry;
                crate::out!(
                    "{} {} {} client={} action={} vault={} item={} field={} decision={} outcome={}",
                    r.seq,
                    sanitize_for_display(&r.ts),
                    match e.surface {
                        onepass_guard::Surface::Mcp => "mcp",
                        onepass_guard::Surface::Ssh => "ssh",
                    },
                    sanitize_for_display(&e.client),
                    sanitize_for_display(&e.action),
                    show(&e.vault_id, &vault_names),
                    show(&e.item_id, &titles),
                    e.field
                        .as_deref()
                        .map(sanitize_for_display)
                        .unwrap_or_else(|| "-".into()),
                    sanitize_for_display(&e.decision),
                    sanitize_for_display(&e.outcome),
                );
            }
        }
        let n = verification.records.len();
        if verification.unsealed_tail {
            crate::out!("audit log verified ({n} entries, last entry not yet sealed)");
        } else {
            crate::out!("audit log verified ({n} entries)");
        }
        Ok(())
    })
}

/// Vault names and item titles by id, every vault and item included.
type Names = (BTreeMap<String, String>, BTreeMap<String, String>);

fn names(repo: &mut Repository<SqliteStore>) -> Result<Names, CliError> {
    let mut vault_names = BTreeMap::new();
    let mut titles = BTreeMap::new();
    for v in stored(repo.vaults())? {
        for item in stored(repo.items(&v))? {
            titles.insert(item.id.to_string(), item.title.clone());
        }
        vault_names.insert(v.id.to_string(), v.meta.name.clone());
    }
    Ok((vault_names, titles))
}

/// The CLI error of a request, as the tools see it. Messages never carry
/// a value.
fn port_error(e: CliError) -> PortError {
    match e.code {
        3 => PortError::Integrity,
        4 => PortError::NotFound,
        _ => PortError::Other(e.msg),
    }
}

/// [`VaultPort`] of the server: every call is its own lock cycle through
/// [`LongSession::with_repo`], over a [`RepoPort`].
pub struct LockedPort(pub Rc<RefCell<LongSession>>);

impl LockedPort {
    fn call<T>(
        &mut self,
        f: impl FnOnce(&mut RepoPort<'_, SqliteStore>) -> Result<T, PortError>,
    ) -> Result<T, PortError> {
        self.0
            .borrow_mut()
            .with_repo(|repo| Ok(f(&mut RepoPort(repo))))
            .map_err(port_error)?
    }
}

impl VaultPort for LockedPort {
    fn vaults(&mut self) -> Result<Vec<VaultInfo>, PortError> {
        self.call(|p| p.vaults())
    }

    fn items(&mut self, vault_id: Id) -> Result<Vec<Item>, PortError> {
        self.call(|p| p.items(vault_id))
    }

    fn resolve(&mut self, r: &SecretRef) -> Result<Zeroizing<String>, PortError> {
        self.call(|p| p.resolve(r))
    }

    fn save_item(&mut self, vault_id: Id, item: Item) -> Result<(), PortError> {
        self.call(|p| p.save_item(vault_id, item))
    }
}

fn serve_stdio(
    ctx: &Ctx,
    vault_keys: &[String],
    scopes: Option<BTreeSet<Scope>>,
) -> Result<(), CliError> {
    // Checked before prompting: a bad dev switch must not cost a password.
    let approver: Arc<dyn Approver> = match dev_auto_approver_from_env().map_err(CliError::usage)? {
        Some(a) => Arc::new(a),
        None => Arc::new(TtyApprover::new()),
    };
    let session = Rc::new(RefCell::new(LongSession::open(ctx)?));
    let policy = load(session.borrow().repo(), ctx)?;
    let mcp = session.borrow_mut().with_repo(|repo| mcp_vaults(repo))?;
    let narrowed = if vault_keys.is_empty() {
        None
    } else {
        let mut ids = BTreeSet::new();
        for key in vault_keys {
            ids.insert(find_mcp_vault(&mcp, key)?.id.to_string());
        }
        Some(ids)
    };
    let narrowing = Narrowing {
        vaults: narrowed,
        scopes,
    };
    let visible = mcp
        .iter()
        .filter(|v| {
            narrowing
                .vaults
                .as_ref()
                .is_none_or(|o| o.contains(&v.id.to_string()))
        })
        .count();
    let log = AuditLog::open(&audit_path(ctx))
        .map_err(|e| CliError::usage(format!("cannot open the audit log: {e}")))?;
    let sink = SignedAuditSink {
        log,
        signer: SharedSigner(session.clone()),
    };
    let mut tools = McpTools::new(
        LockedPort(session.clone()),
        policy,
        narrowing,
        approver,
        Box::new(sink),
        Some(session.borrow().ctx().data_dir.clone()),
    );
    eprintln!("onepass mcp: ready ({visible} vaults)");
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    serve(&mut tools, stdin.lock(), stdout.lock()).map_err(stdout_error)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_lists() {
        assert_eq!(
            parse_scopes("metadata, reveal").unwrap(),
            BTreeSet::from([Scope::Metadata, Scope::Reveal])
        );
        assert_eq!(parse_scopes("").unwrap(), BTreeSet::new());
        assert!(parse_scopes("use,admin").unwrap_err().contains("admin"));
        assert!(parse_scopes("Use").is_err());
        assert_eq!(
            scope_list(&BTreeSet::from([Scope::Use, Scope::Metadata])),
            "metadata,use"
        );
    }

    #[test]
    fn errors_map_to_exit_codes_and_port_errors() {
        for e in [
            PolicyError::Tampered,
            PolicyError::WrongAccount,
            PolicyError::Format,
        ] {
            let c = policy_error(e);
            assert_eq!(c.code, 3);
            assert_eq!(c.msg, "mcp policy failed verification");
        }
        assert_eq!(
            policy_error(PolicyError::Io(std::io::ErrorKind::Other)).code,
            1
        );
        let integrity = CliError {
            code: 3,
            msg: "x".into(),
        };
        assert_eq!(port_error(integrity), PortError::Integrity);
        assert_eq!(port_error(CliError::not_found("gone")), PortError::NotFound);
        assert_eq!(
            port_error(CliError::usage("i/o error: busy")),
            PortError::Other("i/o error: busy".into())
        );
    }
}
