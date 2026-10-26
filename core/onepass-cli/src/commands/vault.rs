use clap::Subcommand;
use onepass_core::repo::Repository;
use onepass_core::store::SqliteStore;
use onepass_core::vault::{Vault, VaultMeta};

use crate::session::{CliError, Ctx, stored, with_session};

#[derive(Subcommand)]
pub enum VaultCmd {
    /// List the vaults.
    List,
    /// Create a vault. Its flags are fixed at creation.
    Create {
        name: String,
        /// Expose the vault to the MCP server.
        #[arg(long)]
        mcp_access: bool,
        /// Keep the vault on the device in Travel Mode.
        #[arg(long)]
        travel_safe: bool,
    },
}

pub fn run(ctx: &Ctx, cmd: VaultCmd) -> Result<(), CliError> {
    match cmd {
        VaultCmd::List => with_session(ctx, |repo| {
            let vaults = stored(repo.vaults())?;
            if ctx.json {
                let rows: Vec<_> = vaults
                    .iter()
                    .map(|v| serde_json::json!({ "id": v.id.to_string(), "name": v.meta.name }))
                    .collect();
                crate::out!("{}", serde_json::Value::Array(rows));
            } else {
                for v in &vaults {
                    crate::out!("{}  {}", v.id, v.meta.name);
                }
            }
            Ok(())
        }),
        VaultCmd::Create {
            name,
            mcp_access,
            travel_safe,
        } => with_session(ctx, |repo| {
            if name.trim().is_empty() {
                return Err(CliError::usage("the vault name must not be empty"));
            }
            let vault = stored(repo.create_vault(VaultMeta {
                name,
                icon: "folder".into(),
                color: "blue".into(),
                travel_safe,
                mcp_access,
            }))?;
            if ctx.json {
                crate::out!("{}", serde_json::json!({ "id": vault.id.to_string() }));
            } else {
                crate::out!("created {}", vault.id);
            }
            Ok(())
        }),
    }
}

/// The vault whose id, or else whose name (ignoring case), is `key`.
/// Returns its index in `vaults`.
pub fn find_vault(vaults: &[Vault], key: &str) -> Result<usize, CliError> {
    if let Some(i) = vaults
        .iter()
        .position(|v| v.id.to_string().eq_ignore_ascii_case(key))
    {
        return Ok(i);
    }
    let named: Vec<usize> = vaults
        .iter()
        .enumerate()
        .filter(|(_, v)| v.meta.name.to_lowercase() == key.to_lowercase())
        .map(|(i, _)| i)
        .collect();
    match named.as_slice() {
        [i] => Ok(*i),
        [] => Err(CliError::not_found(format!("no vault named '{key}'"))),
        _ => Err(CliError::usage(format!(
            "ambiguous vault '{key}', use the vault id"
        ))),
    }
}

/// Every vault of the repository.
pub fn all(repo: &Repository<SqliteStore>) -> Result<Vec<Vault>, CliError> {
    stored(repo.vaults())
}
