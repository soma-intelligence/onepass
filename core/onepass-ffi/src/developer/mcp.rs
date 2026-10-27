//! The MCP server served by the app (spec section 4).

/// An MCP client as its relay identified it (spec 3.2).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiMcpClient {
    /// Stable client id (`team:<team>:<identifier>`, `adhoc:<cdhash>`...).
    pub id: String,
    /// Display label (sanitized).
    pub label: String,
    /// The system vouches for its code (platform or team identity).
    pub signed: bool,
    /// The client ids walked from the relay's parent up to the client.
    pub chain: Vec<String>,
}
