//! Rendezvous of the production bridge (spec
//! `docs/specs/2026-10-27-release-bridge-design.md`).
//!
//! The Mac app listens on `bridge.sock` at the root of its App Group
//! container. Two kinds of clients connect: the Safari Web Extension
//! (`me.somalabs.onepass.safari`) and `onepass-relay`, the binary Chrome and
//! Firefox launch (`me.somalabs.onepass.relay`). Each side checks the
//! other's code signature through the kernel audit token (`onepass-peer`):
//! same team, exact identifier. The group container is not a boundary
//! against an unsandboxed process of the same user; the signature is.
//!
//! On the socket: one opening frame from the client (`{"onepass_relay":1}`,
//! plus `"extension"` from the relay), then bridge envelopes byte for byte,
//! with the native messaging framing (1 MiB cap).

pub mod preamble;
pub mod rendezvous;
pub mod server;

pub use preamble::Preamble;
pub use rendezvous::{
    APP_ID, Client, GROUP_SUFFIX, RELAY_ID, SAFARI_EXTENSION_ID, SAFARI_ID, SOCKET_NAME,
    classify_client, is_app, socket_path,
};
