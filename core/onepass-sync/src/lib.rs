//! The sync round in Rust (cross-platform spec 4.14), for the apps that do
//! not run `SyncCoordinator.swift`: a `SyncDriver` over any `Transport`,
//! and `MailboxTransport`, the transport of a OnePass mailbox.
//!
//! Nothing here is async or threaded: the app calls `run_round` from a
//! thread of its own and schedules the next round from its report.
#![deny(unsafe_code)]

pub mod driver;
pub mod mailbox;
pub mod policy;
pub mod transport;
pub mod zones;

pub use driver::{RoundHooks, RoundReport, RoundStatus, SyncDriver, integrity_kind};
pub use mailbox::{MailboxTransport, transport_error};
pub use transport::{BatchLimits, Outgoing, Page, SendResult, Transport, TransportError};
pub use zones::{
    Connect, HttpConnect, ParentMailbox, ZoneError, ZoneHooks, ZoneRoundReport, ZoneSeedStore,
    ZoneSync, ZoneWake,
};
