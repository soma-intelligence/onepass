//! The browser behind the MCP tool `fill_in_browser` in the app (spec
//! 2026-11-07 sections 3 to 6): [`HubBrowser`] carries the tool's probe
//! and fill to the Chrome extension through the agent hub the bridge
//! serves (`agent_wait`), and answers with field names only.
//!
//! The hub is one per process ([`agent_hub`]): the bridge server and the
//! MCP host are separate objects the app creates on its own, so neither
//! owns the other, and both must see the same queue.

use std::sync::{Arc, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use onepass_bridge::agent::{
    AgentError, AgentHub, AgentKind, FILL_TIMEOUT, PROBE_TIMEOUT, ProbeResult,
};
use onepass_core::Id;
use onepass_core::model::Item;
use onepass_mcp::browser::{
    BrowserError, BrowserFill, BrowserTarget, FillKind, FillOutcome, PageProbe,
};

/// The agent hub of this process, made on first use, clocked in Unix
/// seconds. One per process is safe: the bridge and the agent servers
/// both stay on the primary account (AppModel.swift, ruling P7).
pub(crate) fn agent_hub() -> Arc<AgentHub> {
    static HUB: OnceLock<Arc<AgentHub>> = OnceLock::new();
    HUB.get_or_init(|| {
        AgentHub::new(Arc::new(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        }))
    })
    .clone()
}

/// Spec 3 names for the hub's errors. The tool reports a refusal by the
/// extension as no browser (controller ruling): `denied` is kept for the
/// user's answer.
fn browser_error(e: AgentError) -> BrowserError {
    match e {
        AgentError::NoBrowser | AgentError::Denied => BrowserError::NoBrowser,
        AgentError::Timeout => BrowserError::Timeout,
        AgentError::TabMismatch => BrowserError::TabMismatch,
        AgentError::OriginMismatch => BrowserError::OriginMismatch,
        AgentError::CrossSiteFrame => BrowserError::CrossSiteFrame,
        AgentError::NoFields => BrowserError::NoFields,
    }
}

fn agent_kind(kind: FillKind) -> AgentKind {
    match kind {
        FillKind::Login => AgentKind::Login,
        FillKind::Card => AgentKind::Card,
    }
}

/// [`BrowserFill`] over the agent hub. `Chrome` goes to the extension;
/// `Cdp` answers `no_browser` until the local CDP client (plan task 10)
/// takes that arm.
pub(crate) struct HubBrowser {
    pub(crate) hub: Arc<AgentHub>,
}

impl BrowserFill for HubBrowser {
    fn probe(
        &self,
        client_id: &str,
        target: &BrowserTarget,
        url: &str,
    ) -> Result<PageProbe, BrowserError> {
        match target {
            BrowserTarget::Chrome => {
                let (
                    request_id,
                    ProbeResult {
                        tab_title,
                        origin,
                        document_id,
                    },
                ) = self
                    .hub
                    .probe(client_id, url, PROBE_TIMEOUT)
                    .map_err(browser_error)?;
                Ok(PageProbe {
                    tab_title,
                    origin,
                    handle: document_id,
                    request_id,
                })
            }
            BrowserTarget::Cdp(_) => Err(BrowserError::NoBrowser),
        }
    }

    fn fill(
        &self,
        _client_id: &str,
        target: &BrowserTarget,
        probe: &PageProbe,
        item: &Item,
        _vault_id: Id,
        kind: FillKind,
        submit: bool,
    ) -> Result<FillOutcome, BrowserError> {
        match target {
            BrowserTarget::Chrome => {
                // The ticket's origin is the probed one, byte for byte: the
                // host redeems it against the origin the extension reports.
                let done = self
                    .hub
                    .fill(
                        probe.request_id,
                        &item.id.to_string(),
                        &probe.origin,
                        agent_kind(kind),
                        submit,
                        &probe.handle,
                        FILL_TIMEOUT,
                    )
                    .map_err(browser_error)?;
                Ok(FillOutcome {
                    filled: done.filled,
                    submitted: done.submitted,
                })
            }
            BrowserTarget::Cdp(_) => Err(BrowserError::NoBrowser),
        }
    }

    fn cancel(&self, probe: &PageProbe) {
        // CDP probes carry request 0, which the hub never issues.
        self.hub.cancel(probe.request_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hub_errors_keep_their_names() {
        let pairs = [
            (AgentError::NoBrowser, "no_browser"),
            (AgentError::Denied, "no_browser"),
            (AgentError::Timeout, "timeout"),
            (AgentError::TabMismatch, "tab_mismatch"),
            (AgentError::OriginMismatch, "origin_mismatch"),
            (AgentError::CrossSiteFrame, "cross_site_frame"),
            (AgentError::NoFields, "no_fields"),
        ];
        for (e, code) in pairs {
            assert_eq!(browser_error(e).code(), code);
        }
    }

    #[test]
    fn one_hub_per_process() {
        assert!(Arc::ptr_eq(&agent_hub(), &agent_hub()));
    }

    #[test]
    fn cdp_has_no_browser_yet() {
        let b = HubBrowser { hub: agent_hub() };
        let cdp = BrowserTarget::Cdp("ws://127.0.0.1:9222/devtools/page/x".into());
        assert_eq!(
            b.probe("c", &cdp, "https://example.com").unwrap_err(),
            BrowserError::NoBrowser
        );
    }
}
