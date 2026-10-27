//! Browser extension bridge protocol of OnePass: native messaging framing,
//! hybrid KEM, transcript and key derivation, envelopes, pairing, session
//! handshake and encrypted channel, origin matching, provider domains and
//! application messages.

pub mod api;
pub mod audit;
pub mod channel;
pub mod error;
pub mod framing;
pub mod kdf;
pub mod kem;
pub mod origin;
pub mod pairing;
pub mod policy;
pub mod provider;
pub mod service;
pub mod session;
pub mod transcript;
pub mod wire;

pub use error::{AppErrorCode, BridgeError};

pub type Result<T> = std::result::Result<T, BridgeError>;
