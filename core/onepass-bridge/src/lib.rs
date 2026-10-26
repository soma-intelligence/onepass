//! Browser extension bridge protocol of OnePass: native messaging framing,
//! hybrid KEM, transcript and key derivation,
//! envelopes and pairing.

pub mod error;
pub mod framing;
pub mod kdf;
pub mod kem;
pub mod pairing;
pub mod transcript;
pub mod wire;

pub use error::{AppErrorCode, BridgeError};

pub type Result<T> = std::result::Result<T, BridgeError>;
