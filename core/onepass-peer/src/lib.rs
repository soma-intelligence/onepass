//! What the kernel and the code-signing system say about a local client
//! (hardening spec 3.1 and 3.2).
//!
//! - [`cred`]: kernel credentials of a Unix socket peer (uid, pid, audit
//!   token), parent pids, executable paths and the effective uid.
//! - [`code`]: the code-signing identity of a process ([`CodeIdentity`]),
//!   its stable client id, and the MCP client found by skipping launchers.
//!
//! This crate holds the `unsafe` code of the MCP server and the SSH agent:
//! libc calls in `cred` and Security.framework calls in `macos`, each block
//! with a SAFETY comment. Everything else is safe Rust.
#![deny(unsafe_code)]

pub mod code;
pub mod cred;
#[cfg(target_os = "macos")]
mod macos;

pub use code::{
    ClientIdentity, CodeIdentity, LAUNCHERS, LINUX_LAUNCHER_PATHS, MAX_LAUNCHERS, PeerError,
    file_sha256, identify_mcp_parent, identify_peer, identify_pid, identity_of_file,
};
pub use cred::{PeerCred, effective_uid, exe_path, parent_of, parent_pid, peer_cred, pid_exists};
