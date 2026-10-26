//! Browser extension bridge protocol of OnePass: native messaging framing,
//! hybrid KEM, transcript and key derivation.

pub mod error;
pub mod framing;

pub use error::{AppErrorCode, BridgeError};

pub type Result<T> = std::result::Result<T, BridgeError>;
