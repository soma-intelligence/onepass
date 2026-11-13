//! The browser behind the MCP tool `fill_in_browser` in the app (spec
//! 2026-11-07 sections 3 to 6): [`HubBrowser`] carries the tool's probe
//! and fill to the Chrome extension through the agent hub the bridge
//! serves (`agent_wait`), or to a local Chrome an agent drives over the
//! DevTools protocol (`onepass-cdp`), and answers with field names only.
//!
//! The CDP connection is made by this process (the app, or the test
//! binary), never by the relay or the agent: the address is checked to be
//! loopback before any socket opens, and the values go from the item the
//! tool read through the vault port straight into `Input.insertText`.
//!
//! The hub is one per process ([`agent_hub`]): the bridge server and the
//! MCP host are separate objects the app creates on its own, so neither
//! owns the other, and both must see the same queue.
// The servers that use this code listen on Unix sockets; their Windows
// named pipes come with milestone X3 (spec 2026-10-30).
#![cfg_attr(not(unix), allow(dead_code))]

use std::sync::{Arc, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use onepass_bridge::agent::{
    AgentError, AgentHub, AgentKind, FILL_TIMEOUT, PROBE_TIMEOUT, ProbeResult,
};
use onepass_bridge::api::{FillField, Response};
use onepass_bridge::origin::Origin;
use onepass_bridge::policy::{card_values, login_secrets, to_candidate};
use onepass_cdp::{CdpError, CdpFiller, CdpPage, FillStep, Zeroizing, backend_node_id};
use onepass_core::Id;
use onepass_core::fill_plan::context::{ButtonClass, FieldRole};
use onepass_core::fill_plan::intent::Intent;
use onepass_core::fill_plan::score::MatchQuality as PlanQuality;
use onepass_core::fill_plan::{FillPlan, GroupKind, Pool, ReasonCode, plan};
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

/// Spec 3 names for the DevTools errors. A socket or protocol failure is
/// no browser to fill; a select or checkbox in the plan is no field.
fn cdp_error(e: CdpError) -> BrowserError {
    match e {
        CdpError::NotLocal => BrowserError::CdpNotLocal,
        CdpError::OriginChanged => BrowserError::OriginMismatch,
        CdpError::NoFields | CdpError::Unsupported => BrowserError::NoFields,
        CdpError::Timeout => BrowserError::Timeout,
        CdpError::Connect | CdpError::Protocol => BrowserError::NoBrowser,
    }
}

/// The exact `https` origin of a URL, or none.
fn https_origin(url: &str) -> Option<String> {
    Origin::parse(url).ok().map(|o| o.origin_string())
}

/// The item field a written role came from (what the agent is told, as the
/// extension's `ITEM_FIELD`), for the roles a fill of `kind` writes.
fn item_field(kind: FillKind, role: FieldRole) -> Option<&'static str> {
    use FieldRole as R;
    match (kind, role) {
        (FillKind::Login, R::Username | R::Email) => Some("username"),
        (FillKind::Login, R::CurrentPassword) => Some("password"),
        (FillKind::Login, R::Otp) => Some("totp"),
        (FillKind::Card, R::CcName) => Some("cardholder"),
        (FillKind::Card, R::CcNumber) => Some("number"),
        (FillKind::Card, R::CcExp | R::CcExpMonth | R::CcExpYear) => Some("expiry"),
        (FillKind::Card, R::CcCsc) => Some("cvv"),
        _ => None,
    }
}

/// A login plan whose submit an agent may ask for: a sign-in or code page
/// with no pay or create button (the extension's `submittable`).
fn submittable(p: &FillPlan) -> bool {
    matches!(p.intent, Intent::Login | Intent::Otp)
        && !p.reasons.contains(&ReasonCode::PayButton)
        && !p.reasons.contains(&ReasonCode::CreateButton)
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The value of each role a fill of `item` writes, read from the item as
/// the bridge does for the extension (`login_secrets`, `card_values`):
/// autofill fields only, the code of the moment. Empty values are left out.
fn role_values(
    item: &Item,
    kind: FillKind,
    roles: &[FieldRole],
) -> Vec<(FieldRole, Zeroizing<String>)> {
    use FieldRole as R;
    let mut out = Vec::new();
    let mut put = |role: FieldRole, v: Zeroizing<String>| {
        if roles.contains(&role) && !v.is_empty() {
            out.push((role, v));
        }
    };
    match kind {
        FillKind::Login => {
            let mut fields = Vec::new();
            if roles.iter().any(|r| matches!(r, R::Username | R::Email)) {
                fields.push(FillField::Username);
            }
            if roles.contains(&R::CurrentPassword) {
                fields.push(FillField::Password);
            }
            if roles.contains(&R::Otp) {
                fields.push(FillField::Totp);
            }
            if let Response::Login {
                username,
                password,
                totp,
            } = login_secrets(item, &fields, now_secs())
            {
                if let Some(u) = username {
                    let u = Zeroizing::new(u);
                    put(R::Username, u.clone());
                    put(R::Email, u);
                }
                if let Some(p) = password {
                    put(R::CurrentPassword, p.0);
                }
                if let Some(t) = totp {
                    put(R::Otp, t.0);
                }
            }
        }
        FillKind::Card => {
            if let Response::Card {
                cardholder,
                number,
                exp_month,
                exp_year,
                cvv,
            } = card_values(item)
            {
                put(R::CcName, Zeroizing::new(cardholder));
                put(R::CcNumber, number.0);
                if !exp_month.is_empty() && !exp_year.is_empty() {
                    // The last two characters (the extension's `slice(-2)`),
                    // never a byte slice.
                    let n = exp_year.chars().count();
                    let yy: String = exp_year.chars().skip(n.saturating_sub(2)).collect();
                    put(R::CcExp, Zeroizing::new(format!("{exp_month}/{yy}")));
                }
                put(R::CcExpMonth, Zeroizing::new(exp_month));
                put(R::CcExpYear, Zeroizing::new(exp_year));
                if let Some(c) = cvv {
                    put(R::CcCsc, c.0);
                }
            }
        }
    }
    out
}

/// Probe over CDP: the real origin of the top frame, which must be
/// `https` (else `tab_mismatch`), and the page title. The URL the agent gave
/// is not compared here: the tool checks the page's site and the item's rule
/// on this origin (`tab_mismatch`), as for Chrome.
fn cdp_probe(ws_url: &str) -> Result<PageProbe, BrowserError> {
    let mut page = CdpFiller::connect(ws_url).map_err(cdp_error)?;
    let origin = https_origin(&page.main_frame_url().map_err(cdp_error)?)
        .ok_or(BrowserError::TabMismatch)?;
    let tab_title = page.title().map_err(cdp_error)?;
    Ok(PageProbe {
        tab_title,
        origin,
        handle: ws_url.to_owned(),
        request_id: 0,
    })
}

/// Fill over CDP, on a new connection: the top frame must still be at the
/// approved origin (`origin_mismatch` if the page moved after approval;
/// pinned for every later step), then the page context
/// is planned for this item alone, each planned field typed, and for a
/// login with `submit` on a sign-in page the form's submit button clicked.
fn cdp_fill(
    ws_url: &str,
    probe: &PageProbe,
    item: &Item,
    kind: FillKind,
    submit: bool,
    with_totp: bool,
) -> Result<FillOutcome, BrowserError> {
    let mut page = CdpFiller::connect(ws_url).map_err(cdp_error)?;
    let origin = https_origin(&page.main_frame_url().map_err(cdp_error)?);
    if origin.as_deref() != Some(probe.origin.as_str()) {
        return Err(BrowserError::OriginMismatch);
    }
    let ctx = page.page_context().map_err(cdp_error)?;
    let (group_kind, candidate) = match kind {
        FillKind::Login => (GroupKind::Login, to_candidate(item, PlanQuality::Exact)),
        FillKind::Card => (GroupKind::Card, to_candidate(item, PlanQuality::Other)),
    };
    // The plan only says which form and which fields: the item is the
    // approved one, the only candidate.
    let mut pool = Pool {
        logins: vec![],
        cards: vec![],
        identities: vec![],
        identity_country: Default::default(),
        default_card: None,
        now: i64::try_from(now_secs()).unwrap_or(i64::MAX),
    };
    match kind {
        FillKind::Login => pool.logins.push(candidate),
        FillKind::Card => pool.cards.push(candidate),
    }
    let p = plan(&ctx, pool).map_err(|_| BrowserError::NoFields)?;
    let group = p
        .groups
        .iter()
        .find(|g| g.kind == group_kind && !g.fields.is_empty())
        .ok_or(BrowserError::NoFields)?;
    let mut roles: Vec<FieldRole> = Vec::new();
    for (_, r) in &group.fields {
        // The one-time code only when the tool allowed it (`with_totp`).
        if item_field(kind, *r).is_some()
            && !roles.contains(r)
            && (with_totp || *r != FieldRole::Otp)
        {
            roles.push(*r);
        }
    }
    let values = role_values(item, kind, &roles);
    let mut steps = Vec::new();
    let mut filled: Vec<String> = Vec::new();
    for (field_ref, role) in &group.fields {
        let (Some(id), Some(name)) = (backend_node_id(field_ref), item_field(kind, *role)) else {
            continue;
        };
        let Some((_, v)) = values.iter().find(|(r, _)| r == role) else {
            continue;
        };
        steps.push(FillStep::new(id, v.clone()));
        if !filled.iter().any(|f| f == name) {
            filled.push(name.to_owned());
        }
    }
    drop(values);
    if steps.is_empty() {
        return Err(BrowserError::NoFields);
    }
    // A card is never submitted, nor a page that pays or creates an account.
    let button = (kind == FillKind::Login && submit && submittable(&p))
        .then(|| submit_button(&ctx, &group.form_ref))
        .flatten();
    page.fill(steps, None).map_err(cdp_error)?;
    let submitted = button.is_some_and(|b| click(&mut page, b));
    Ok(FillOutcome { filled, submitted })
}

/// The first submit button of the planned form.
fn submit_button(
    ctx: &onepass_core::fill_plan::context::PageContext,
    form_ref: &str,
) -> Option<i64> {
    ctx.forms
        .iter()
        .find(|f| f.form_ref == form_ref)?
        .buttons
        .iter()
        .find(|b| b.class == ButtonClass::Submit)
        .and_then(|b| backend_node_id(&b.button_ref))
}

/// Clicks the submit button. A page that moved after the fill keeps its
/// fields written, and nothing is clicked.
fn click(page: &mut CdpPage, button: i64) -> bool {
    page.click(button).is_ok()
}

/// Whether the session serves agents only (the Mac is locked).
pub(crate) type AgentOnly = Box<dyn Fn() -> bool + Send>;

/// [`BrowserFill`] over the agent hub (`Chrome`, to the extension) or over
/// a local DevTools socket (`Cdp`).
pub(crate) struct HubBrowser {
    pub(crate) hub: Arc<AgentHub>,
    /// True while the session was opened from the phone for agents only:
    /// no browser fill then, whatever the target (spec 4 and 9).
    pub(crate) agent_only: AgentOnly,
}

impl BrowserFill for HubBrowser {
    fn ready(&self) -> Result<(), BrowserError> {
        if (self.agent_only)() {
            return Err(BrowserError::MacLocked);
        }
        Ok(())
    }

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
            BrowserTarget::Cdp(ws_url) => cdp_probe(ws_url),
        }
    }

    fn fill(
        &self,
        client_id: &str,
        target: &BrowserTarget,
        probe: &PageProbe,
        item: &Item,
        _vault_id: Id,
        kind: FillKind,
        submit: bool,
        with_totp: bool,
    ) -> Result<FillOutcome, BrowserError> {
        match target {
            BrowserTarget::Chrome => {
                // The ticket's origin is the probed one, byte for byte: the
                // host redeems it against the origin the extension reports.
                let done = self
                    .hub
                    .fill(
                        client_id,
                        probe.request_id,
                        &item.id.to_string(),
                        &probe.origin,
                        agent_kind(kind),
                        submit,
                        with_totp,
                        &probe.handle,
                        FILL_TIMEOUT,
                    )
                    .map_err(browser_error)?;
                Ok(FillOutcome {
                    filled: done.filled,
                    submitted: done.submitted,
                })
            }
            BrowserTarget::Cdp(ws_url) => cdp_fill(ws_url, probe, item, kind, submit, with_totp),
        }
    }

    fn cancel(&self, probe: &PageProbe) {
        // CDP probes carry request 0, which the hub never issues, and hold
        // no connection: nothing to drop.
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
    fn cdp_errors_keep_their_names() {
        let pairs = [
            (CdpError::NotLocal, "cdp_not_local"),
            (CdpError::OriginChanged, "origin_mismatch"),
            (CdpError::NoFields, "no_fields"),
            (CdpError::Unsupported, "no_fields"),
            (CdpError::Timeout, "timeout"),
            (CdpError::Connect, "no_browser"),
            (CdpError::Protocol, "no_browser"),
        ];
        for (e, code) in pairs {
            assert_eq!(cdp_error(e).code(), code);
        }
    }

    #[test]
    fn cdp_probe_refuses_a_remote_address_before_any_socket() {
        let b = HubBrowser {
            hub: agent_hub(),
            agent_only: Box::new(|| false),
        };
        let cdp = BrowserTarget::Cdp("ws://192.0.2.1:9222/devtools/page/x".into());
        assert_eq!(
            b.probe("c", &cdp, "https://example.com").unwrap_err(),
            BrowserError::CdpNotLocal
        );
    }

    #[test]
    fn agent_only_session_is_not_ready() {
        let b = HubBrowser {
            hub: agent_hub(),
            agent_only: Box::new(|| true),
        };
        let e = b.ready().unwrap_err();
        assert_eq!(e.code(), "no_browser");
        assert!(e.text().contains("unlock the Mac"), "{}", e.text());
        let b = HubBrowser {
            hub: agent_hub(),
            agent_only: Box::new(|| false),
        };
        assert!(b.ready().is_ok());
    }
}
