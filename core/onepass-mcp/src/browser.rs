//! The browser behind `fill_in_browser` (spec 2026-11-07 sections 3 to 6).
//!
//! The MCP crate never talks to a browser itself: it asks a [`BrowserFill`]
//! to look at the page the agent is on ([`BrowserFill::probe`]), checks the
//! policy and asks the user, then has it fill the approved item
//! ([`BrowserFill::fill`]) or drop the probe ([`BrowserFill::cancel`]). The
//! app implements it over its bridge to the Chrome extension, and over a
//! local CDP client for browsers an agent drives. No value ever comes back
//! through this trait: only field names and whether a form was submitted.

use onepass_core::Id;
use onepass_core::model::Item;

/// The browser a fill goes to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BrowserTarget {
    /// Chrome with the OnePass extension (phase 1).
    Chrome,
    /// A page reached over the Chrome DevTools Protocol, by its `ws://`
    /// address (phase 2). Whether it is local is the implementation's check.
    Cdp(String),
}

/// What is filled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FillKind {
    /// Username and password of a Login item.
    Login,
    /// Number, holder, expiry and code of a credit card.
    Card,
}

impl FillKind {
    /// The audit and approval action of this kind.
    pub fn action(self) -> &'static str {
        match self {
            FillKind::Login => "fill_login",
            FillKind::Card => "fill_card",
        }
    }
}

/// The page the agent is on, as the browser saw it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PageProbe {
    /// Title of the tab, shown to the user only (never logged).
    pub tab_title: String,
    /// Origin of the page (`https://host[:port]`).
    pub origin: String,
    /// The page handle the fill must land on: the document id for Chrome,
    /// the target id for CDP.
    pub handle: String,
    /// The bridge request this probe opened (0 for CDP). Never returned to
    /// the agent nor logged.
    pub request_id: u64,
}

/// What a fill did: the names of the fields filled, and whether the form
/// was submitted. Never a value.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FillOutcome {
    pub filled: Vec<String>,
    pub submitted: bool,
}

/// Why the browser could not probe or fill.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BrowserError {
    /// No browser is connected.
    NoBrowser,
    /// The browser did not answer in time.
    Timeout,
    /// The active tab is not the page the agent named, or it changed.
    TabMismatch,
    /// The page's origin is not the approved one.
    OriginMismatch,
    /// The fields are in a frame of another site.
    CrossSiteFrame,
    /// No field to fill on the page.
    NoFields,
    /// The CDP address is not on this machine.
    CdpNotLocal,
}

impl BrowserError {
    /// The error name the tool returns.
    pub fn code(self) -> &'static str {
        match self {
            BrowserError::NoBrowser => "no_browser",
            BrowserError::Timeout => "timeout",
            BrowserError::TabMismatch => "tab_mismatch",
            BrowserError::OriginMismatch => "origin_mismatch",
            BrowserError::CrossSiteFrame => "cross_site_frame",
            BrowserError::NoFields => "no_fields",
            BrowserError::CdpNotLocal => "cdp_not_local",
        }
    }

    /// A short explanation, free of page or vault data.
    pub fn text(self) -> &'static str {
        match self {
            BrowserError::NoBrowser => "no browser connected to OnePass",
            BrowserError::Timeout => "the browser did not answer in time",
            BrowserError::TabMismatch => "the active tab is not on this site",
            BrowserError::OriginMismatch => "the page is not on the item's site",
            BrowserError::CrossSiteFrame => "the fields are in a frame of another site",
            BrowserError::NoFields => "no field to fill on the page",
            BrowserError::CdpNotLocal => "the CDP address is not on this machine",
        }
    }
}

/// A browser OnePass can fill into for an agent.
pub trait BrowserFill: Send {
    /// Looks at the page `client_id` says it is on (`url`), in `target`.
    fn probe(
        &self,
        client_id: &str,
        target: &BrowserTarget,
        url: &str,
    ) -> Result<PageProbe, BrowserError>;

    /// Fills `item` (of `vault_id`) into the probed page, once, after the
    /// user approved. `submit` presses the sign-in button (logins only).
    #[allow(clippy::too_many_arguments)]
    fn fill(
        &self,
        client_id: &str,
        target: &BrowserTarget,
        probe: &PageProbe,
        item: &Item,
        vault_id: Id,
        kind: FillKind,
        submit: bool,
    ) -> Result<FillOutcome, BrowserError>;

    /// Drops a probe that will not be filled (refused, denied, failed).
    fn cancel(&self, _probe: &PageProbe) {}
}
