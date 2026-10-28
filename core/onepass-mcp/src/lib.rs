//! OnePass MCP server: JSON-RPC 2.0 over stdio. The protocol layer lives in
//! [`protocol`]; tools plug in behind the [`ToolHost`] trait. [`tools`]
//! holds the OnePass tools, which reach the vaults only through a
//! [`VaultPort`] and under a signed [`Policy`]. [`runner`], [`mask`] and
//! [`template`] serve the secret tools, whose side effects go through a
//! [`Workspace`].

pub mod guards;
pub mod mask;
pub mod policy;
pub mod port;
pub mod protocol;
pub mod runner;
pub mod template;
pub mod tools;
pub mod workspace;

pub use guards::{
    ClientContext, DEFAULT_PROMPT_WAIT, LivenessFn, McpGuards, RegistryFn, file_registry,
    mcp_client_record,
};
pub use policy::{
    ClientScopes, Narrowing, Policy, PolicyError, Scope, client_scopes, default_client_scopes,
    effective, effective_for_client, load_policy, save_policy,
};
pub use port::{PortError, RepoPort, VaultInfo, VaultPort};
pub use protocol::{
    ClientInfo, MAX_LINE, PROTOCOL_VERSIONS, Session, ToolHost, ToolOutcome, ToolSpec, handle_line,
    serve,
};
pub use tools::{McpTools, PolicySource};
pub use workspace::{LocalWorkspace, MAX_TEMPLATE, Workspace, WorkspaceRefusal};
