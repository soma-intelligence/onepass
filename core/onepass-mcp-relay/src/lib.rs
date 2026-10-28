//! The relay between an MCP client and the OnePass Mac app (app design
//! spec sections 4.1 and 4.2).
//!
//! An MCP client launches the `onepass-mcp` binary of this crate and talks
//! JSON-RPC to it on stdio. The relay identifies the client, connects to
//! the app's Unix socket, relays the lines both ways without reading them,
//! and runs for the app, outside its sandbox, the commands of
//! `run_with_secrets` and the file reads and writes of `fill_template`.
//! [`wire`] holds the messages of the socket, shared with the app side.
#![deny(unsafe_code)]

pub mod wire;
