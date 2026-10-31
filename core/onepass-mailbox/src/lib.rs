//! Blocking client of the OnePass mailbox (cross-platform spec, section 4).
//!
//! One `ureq` agent per client, TLS 1.3 only through `rustls` and
//! `aws-lc-rs`, every mailbox request signed with the device's mailbox
//! credential (spec 4.7), bodies in the strict postcard of
//! `onepass-mailbox-proto`. Nothing here is async: the app calls it from a
//! thread of its own.
//!
//! The server is hostile (spec 4.15): every answer is decoded strictly and
//! checked against what was asked, and every blob read back is checked
//! against its SHA-256 before the bytes leave this crate.
#![deny(unsafe_code)]

// `testing` lets the client talk plain http to loopback. Tests turn it on
// through a dev-dependency; a release build must never carry it.
#[cfg(all(feature = "testing", not(debug_assertions)))]
compile_error!("onepass-mailbox: feature `testing` is for debug test builds only");

mod blobs;
mod client;
mod credential;
mod http;

use std::fmt;

/// Longest `Retry { after }` the client hands on, seconds.
pub const RETRY_AFTER_MAX: u32 = 3600;

pub use client::{ChangeFeed, FeedPage, MailboxClient};
pub use credential::{Credential, CredentialKey};
pub use http::{Endpoint, tls_client_config};
pub use onepass_mailbox_proto::ErrorCode;

/// What a mailbox call can end with, besides its answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MailboxError {
    /// The server could not be reached (refused, unresolved, timed out).
    Offline,
    /// Try again later: `429 rate_limited`, `503 retry`, or a gateway that
    /// gave up. `after` is the server's hint in seconds, when it gave one,
    /// at most `RETRY_AFTER_MAX` (a hostile server cannot park the client).
    Retry { after: Option<u32> },
    /// `401 stale_request`: this device's clock is more than 300 s off.
    Stale,
    /// `410 cursor_expired`: start a full fetch again (spec 4.5).
    CursorExpired,
    /// Any other error code the server answered with.
    Server(ErrorCode),
    /// The server's answer (or the caller's input) is not what the protocol
    /// allows. The string says which check failed.
    Malformed(&'static str),
    /// The TLS configuration could not be built, or the handshake failed
    /// (untrusted certificate, no TLS 1.3, no shared group): retrying the
    /// same network will not help.
    Tls(String),
    /// A blob read back does not have the size or SHA-256 it was named by.
    Integrity(&'static str),
    /// A record body above 900 KiB, a request body above 4 MiB, or a
    /// `413 too_large` from the server.
    TooLarge,
    /// A create without invite was refused: the server takes invites only
    /// (its `/v1/config` may still say `open_signup`, spec 4.9), or this key
    /// already belongs to a mailbox.
    InviteRequired,
    /// The system random source failed.
    Rng,
}

impl fmt::Display for MailboxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Offline => f.write_str("mailbox unreachable"),
            Self::Retry { after: Some(s) } => write!(f, "mailbox busy, retry in {s} s"),
            Self::Retry { after: None } => f.write_str("mailbox busy, retry later"),
            Self::Stale => f.write_str("device clock is too far off"),
            Self::CursorExpired => f.write_str("change cursor expired, full fetch needed"),
            Self::Server(c) => write!(f, "mailbox refused the request: {c:?}"),
            Self::Malformed(w) => write!(f, "malformed mailbox exchange: {w}"),
            Self::Tls(w) => write!(f, "TLS configuration: {w}"),
            Self::Integrity(w) => write!(f, "integrity check failed: {w}"),
            Self::TooLarge => f.write_str("too large for the mailbox"),
            Self::InviteRequired => f.write_str("this mailbox server needs an invite"),
            Self::Rng => f.write_str("system random source failed"),
        }
    }
}

impl std::error::Error for MailboxError {}
