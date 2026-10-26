//! OnePass MCP server: JSON-RPC 2.0 over stdio. The protocol layer lives in
//! [`protocol`]; tools plug in behind the [`ToolHost`] trait.

pub mod protocol;

pub use protocol::{
    ClientInfo, MAX_LINE, PROTOCOL_VERSIONS, Session, ToolHost, ToolOutcome, ToolSpec, handle_line,
    serve,
};
