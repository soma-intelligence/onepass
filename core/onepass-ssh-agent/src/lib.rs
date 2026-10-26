//! OnePass SSH agent: the ssh-agent wire protocol and SSH keys over
//! aws-lc-rs.
//!
//! - [`wire`]: message framing and the request and response codec
//!   (draft-miller-ssh-agent).
//! - [`keys`]: key generation, import (OpenSSH, PEM), OpenSSH export,
//!   signing and verification.

mod der;
pub mod keys;
mod openssh;
pub mod wire;
