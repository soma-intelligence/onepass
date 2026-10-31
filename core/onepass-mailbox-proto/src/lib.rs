//! Wire format of the OnePass mailbox (cross-platform spec, section 4).
//!
//! Every body is `PROTO_VERSION` followed by its postcard encoding. Decoding
//! is strict: the whole buffer is consumed, re-encoding gives the input back
//! byte for byte (so no non-canonical varint), list lengths are capped before
//! anything is deserialized, and each message checks its own invariants.
//! The server is hostile, so a decode error is a typed value, never a panic.
#![deny(unsafe_code)]

pub mod messages;

pub use messages::*;

use sha2::{Digest, Sha256 as Sha256Hasher};

/// SHA-256 of a blob body, as announced and referenced by commits.
pub fn blob_sha256(data: &[u8]) -> Sha256 {
    Sha256Hasher::digest(data).into()
}

/// Lowercase hex, as used in Storage object names.
pub fn hex(bytes: &[u8]) -> String {
    data_encoding::HEXLOWER.encode(bytes)
}
