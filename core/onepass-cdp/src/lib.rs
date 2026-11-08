//! Local Chrome DevTools filler (spec 2026-11-07-agent-browser-fill-design
//! section 6): fills a login or card form in a Chrome an agent drives with
//! `--remote-debugging-port`.
//!
//! Rules this crate holds:
//! - only `ws://127.0.0.1` and `ws://[::1]` are reached, checked on the text
//!   of the address before any socket is opened (no DNS, `localhost` refused
//!   by name, no userinfo);
//! - the page is read with `Page.getFrameTree`, `Target.getTargetInfo` and
//!   `DOMSnapshot.captureSnapshot`; a value is typed with `DOM.focus` then
//!   `Input.insertText` only, never through any `Runtime.*` command;
//! - only the top frame's fields and buttons are filled or clicked;
//! - the origin of the top frame is pinned on first read and read again
//!   before every field: a change stops the fill with [`CdpError::OriginChanged`];
//! - 5 s per command, 30 s for a whole [`CdpPage::fill`].
//!
//! The page context goes to `onepass_core::fill_plan::plan` as it is. Its
//! `field_ref` and `button_ref` are the DevTools `backendNodeId` of the
//! element in decimal; [`backend_node_id`] reads one back.

use std::fmt;

mod classify;
mod fill;
mod page;
mod socket;

#[cfg(feature = "testing")]
pub mod fake;

pub use fill::FillStep;
pub use page::CdpPage;
pub use zeroize::Zeroizing;

/// Why a DevTools call failed. Never carries data from the page, an
/// address or a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CdpError {
    /// The address is not `127.0.0.1` or `::1` (MCP `cdp_not_local`).
    NotLocal,
    /// The address is malformed, or the socket or handshake failed.
    Connect,
    /// Chrome answered with an error or something this crate cannot read.
    Protocol,
    /// The top frame's origin is not the one read first (MCP `origin_mismatch`).
    OriginChanged,
    /// The top frame holds no field to fill (MCP `no_fields`).
    NoFields,
    /// A command took more than 5 s, or a fill more than 30 s (MCP `timeout`).
    Timeout,
}

impl fmt::Display for CdpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotLocal => "the DevTools address is not on this machine",
            Self::Connect => "could not connect to the DevTools address",
            Self::Protocol => "the browser gave an answer that cannot be used",
            Self::OriginChanged => "the page moved to another origin",
            Self::NoFields => "no field to fill in the top frame",
            Self::Timeout => "the browser did not answer in time",
        })
    }
}

impl std::error::Error for CdpError {}

/// Entry point.
pub struct CdpFiller;

impl CdpFiller {
    /// Connects to a page target, `ws://127.0.0.1:<port>/devtools/page/<id>`
    /// or `ws://[::1]:<port>/...`. [`CdpError::NotLocal`] for any other host,
    /// before any socket is opened.
    pub fn connect(ws_url: &str) -> Result<CdpPage, CdpError> {
        Self::connect_with(ws_url, socket::COMMAND_TIMEOUT, fill::FILL_TIMEOUT)
    }

    /// [`CdpFiller::connect`] with other time limits (tests).
    #[doc(hidden)]
    pub fn connect_with(
        ws_url: &str,
        command: std::time::Duration,
        whole_fill: std::time::Duration,
    ) -> Result<CdpPage, CdpError> {
        let sock = socket::Socket::connect(ws_url, command)?;
        Ok(CdpPage::new(sock, whole_fill))
    }
}

/// The `backendNodeId` a `field_ref` or `button_ref` of this crate's page
/// context names.
pub fn backend_node_id(element_ref: &str) -> Option<i64> {
    if element_ref.is_empty() || !element_ref.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    element_ref.parse().ok()
}
