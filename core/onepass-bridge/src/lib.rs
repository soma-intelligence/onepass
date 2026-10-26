//! Browser extension bridge protocol of OnePass: native messaging framing,
//! hybrid KEM, transcript and key derivation.

pub mod error;
pub mod framing;
pub mod kdf;
pub mod kem;
pub mod transcript;

pub use error::{AppErrorCode, BridgeError};

pub type Result<T> = std::result::Result<T, BridgeError>;
