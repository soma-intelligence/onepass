//! OnePass SSH agent: the ssh-agent wire protocol and SSH keys over
//! aws-lc-rs, the approval-gated agent and its Unix socket server.
//!
//! - [`wire`]: message framing and the request and response codec
//!   (draft-miller-ssh-agent).
//! - [`keys`]: key generation, import (OpenSSH, PEM), OpenSSH export,
//!   signing and verification.
//! - [`agent`]: request handling behind approvals, session grants, lock,
//!   session binding, and the vault key source.
//! - [`knownhosts`]: host bookmarks against `known_hosts`.
//! - [`sshsig`]: namespace of SSHSIG signature requests.
//! - [`server`]: the Unix socket, its accept loop and the credentials of
//!   its clients (through `onepass-peer`).
#![deny(unsafe_code)]

pub mod agent;
mod der;
pub mod keys;
pub mod knownhosts;
mod openssh;
pub mod server;
pub mod sshsig;
pub mod wire;

pub use agent::PeerInfo;
pub use agent::{
    Agent, AgentConfig, BoundHost, ConnState, KeyInfo, KeySource, Reply, RepoKeySource,
    load_key_of, menu_truthy, ssh_keys_of,
};
pub use knownhosts::{matching_hosts, pattern_matches};
pub use server::peer_info;
pub use server::{bind_socket, serve, serve_with_stack};
pub use sshsig::sshsig_namespace;
