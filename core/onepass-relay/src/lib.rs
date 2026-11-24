//! Rendezvous of the production bridge (spec
//! `docs/superpowers/specs/2026-10-27-release-bridge-design.md`).
//!
//! The Mac app listens on `bridge.sock` at the root of its App Group
//! container. Three kinds of clients connect: the Safari Web Extension
//! (`me.somalabs.onepass.safari`), `onepass-relay`, the binary Chrome and
//! Firefox launch (`me.somalabs.onepass.relay`), and the Mac fill helper
//! (`me.somalabs.onepass.fill`). Each side checks the
//! other's code signature through the kernel audit token (`onepass-peer`):
//! same team, exact identifier. The group container is not a boundary
//! against an unsandboxed process of the same user; the signature is.
//!
//! On the socket: one opening frame from the client (`{"onepass_relay":1}`,
//! plus `"extension"` from the relay; Safari and the helper name none), then bridge envelopes byte for byte,
//! with the native messaging framing (1 MiB cap).

pub mod launcher;
pub mod open_app;
pub mod preamble;
pub mod rendezvous;
pub mod server;

pub use preamble::Preamble;
pub use rendezvous::{
    APP_ID, Client, FILL_EXTENSION_ID, FILL_ID, FILL_SUFFIX, GROUP_SUFFIX, RELAY_ID, RELAY_SUFFIX,
    SAFARI_EXTENSION_ID, SAFARI_ID, SOCKET_NAME, classify_client, is_app, socket_path,
};
