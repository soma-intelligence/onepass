//! `fill_in_browser` (spec 2026-11-07 sections 3, 4 and 7): fills a login
//! or a card into the page the agent is on, through a [`BrowserFill`],
//! after the user's approval. Never returns a value.

use super::secrets::{push_detail, str_arg};
use super::{Call, CallResult, McpTools, Refusal, kind_name, untrusted};
use crate::browser::{BrowserError, BrowserTarget, FillKind, PageProbe};
use crate::policy::Scope;
use crate::port::{VaultInfo, VaultPort};
use crate::protocol::ClientInfo;
use onepass_core::model::checks::{CardBrand, card_brand};
use onepass_core::model::{FieldValue, Item, ItemType, MatchRule};
use onepass_guard::Target;
use serde_json::{Map, Value, json};
use zeroize::Zeroizing;

/// Longest tab title shown for approval, in characters.
const MAX_TAB_TITLE: usize = 150;

/// The field names `filled` may report to the agent; any other name a
/// browser gives is dropped.
const FILLED_NAMES: [&str; 7] = [
    "username",
    "password",
    "totp",
    "cardholder",
    "number",
    "expiry",
    "cvv",
];

fn named(code: &'static str, text: &str) -> Refusal {
    Refusal::Named {
        code,
        text: text.to_owned(),
    }
}

fn browser_refusal(e: BrowserError) -> Refusal {
    named(e.code(), e.text())
}

/// A URL's host (lowercase ASCII) and its port when not the default one.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Host {
    scheme: String,
    host: String,
    port: Option<u16>,
    ip: bool,
}

impl Host {
    /// Registrable domain (eTLD+1), or the whole host for an address or a
    /// bare public suffix.
    fn site(&self) -> String {
        if self.ip {
            return self.host.clone();
        }
        psl::domain_str(&self.host).unwrap_or(&self.host).to_owned()
    }

    /// `scheme://host[:port]`: what the audit log keeps of a page.
    fn origin(&self) -> String {
        match self.port {
            Some(p) => format!("{}://{}:{p}", self.scheme, self.host),
            None => format!("{}://{}", self.scheme, self.host),
        }
    }
}

/// Parses `scheme://host[:port][/...]`. Without `://`, `bare_is_https`
/// reads it as `https` (items may store a bare host), else it is refused.
/// User info, non ASCII hosts (give the punycode form) and malformed ports
/// are refused.
fn parse_url(s: &str, bare_is_https: bool) -> Option<Host> {
    let s = s.trim();
    let (scheme, rest) = match s.split_once("://") {
        Some((scheme, rest)) => (scheme.to_ascii_lowercase(), rest),
        None if bare_is_https => ("https".to_owned(), s),
        None => return None,
    };
    if scheme != "https" && scheme != "http" {
        return None;
    }
    let end = rest.find(['/', '?', '#', '\\']).unwrap_or(rest.len());
    let authority = &rest[..end];
    if authority.contains('@') {
        return None;
    }
    let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
        let (addr, after) = v6.split_once(']')?;
        if addr.is_empty()
            || !addr
                .chars()
                .all(|c| c.is_ascii_hexdigit() || c == ':' || c == '.')
        {
            return None;
        }
        (format!("[{}]", addr.to_ascii_lowercase()), after)
    } else {
        let i = authority.find(':').unwrap_or(authority.len());
        (authority[..i].to_owned(), &authority[i..])
    };
    let port = match port.strip_prefix(':') {
        None if port.is_empty() => None,
        None => return None,
        Some("") => None,
        Some(p) => Some(p.parse::<u16>().ok()?),
    };
    let default = if scheme == "https" { 443 } else { 80 };
    let port = port.filter(|&p| p != default);
    let ip = host.starts_with('[');
    let host = if ip {
        host
    } else {
        let h = host.trim_end_matches('.').to_ascii_lowercase();
        if h.is_empty()
            || !h
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_')
        {
            return None;
        }
        h
    };
    let ip = ip || host.bytes().all(|b| b.is_ascii_digit() || b == b'.');
    Some(Host {
        scheme,
        host,
        port,
        ip,
    })
}

/// An `https` URL, or `not_https`; one without a usable host is invalid.
fn https_page(url: &str) -> Result<Host, Refusal> {
    let https = url
        .trim()
        .get(..8)
        .is_some_and(|h| h.eq_ignore_ascii_case("https://"));
    if !https {
        return Err(named("not_https", "the page must be served over HTTPS"));
    }
    parse_url(url, false).ok_or_else(|| Refusal::Invalid("invalid url".into()))
}

/// Whether a CDP address is a plain `ws://` one (any case): the only kind
/// a local DevTools socket has. Whether its host is local is the browser's
/// check.
fn is_ws(addr: &str) -> bool {
    addr.get(..5)
        .is_some_and(|h| h.eq_ignore_ascii_case("ws://"))
}

/// What one of the item's URLs matched on `page`, under its own rule:
/// `Domain` the registrable domain (`site:<etld1>`), `ExactHost` the exact
/// host (`host:<host>`), `ExactUrl` the exact origin (`origin:<origin>`;
/// the path cannot be checked against an origin), `Never` nothing. A port
/// written in the item URL must equal the page's. When several URLs match,
/// the narrowest wins, so a grant keyed on it never widens the item's rule.
fn item_match(item: &Item, page: &Host) -> Option<String> {
    item.urls
        .iter()
        .filter_map(|u| {
            let h = parse_url(&u.url, true)?;
            if h.port.is_some() && h.port != page.port {
                return None;
            }
            match u.rule {
                MatchRule::Never => None,
                MatchRule::Domain => {
                    (h.site() == page.site()).then(|| (1, format!("site:{}", page.site())))
                }
                MatchRule::ExactHost => {
                    (h.host == page.host).then(|| (2, format!("host:{}", page.host)))
                }
                MatchRule::ExactUrl => {
                    (h.scheme == "https" && h.host == page.host && h.port == page.port)
                        .then(|| (3, format!("origin:{}", page.origin())))
                }
            }
        })
        .max_by_key(|(rank, _)| *rank)
        .map(|(_, m)| m)
}

/// Whether an item may be filled at all: not archived, not hidden from
/// autofill (trashed items are never listed).
fn fill_eligible(item: &Item, wanted: ItemType) -> bool {
    item.item_type == wanted && !item.archived && !item.hide_from_autofill
}

fn brand_name(b: CardBrand) -> Option<&'static str> {
    Some(match b {
        CardBrand::Visa => "Visa",
        CardBrand::Mastercard => "Mastercard",
        CardBrand::Amex => "American Express",
        CardBrand::Discover => "Discover",
        CardBrand::Jcb => "JCB",
        CardBrand::DinersClub => "Diners Club",
        CardBrand::UnionPay => "UnionPay",
        CardBrand::Maestro => "Maestro",
        CardBrand::CartesBancaires => "Cartes Bancaires",
        CardBrand::Unknown => return None,
    })
}

/// `<brand> ···· <last 4>` for the approval panel only (never the agent
/// nor the log); the item title when the number is missing.
fn card_shown(item: &Item) -> String {
    let number = match item.field("number").map(|f| &f.value) {
        Some(FieldValue::Concealed(n) | FieldValue::Password(n)) => Some(n.as_str()),
        Some(FieldValue::Text(n)) => Some(n.as_str()),
        _ => None,
    };
    let digits = Zeroizing::new(
        number
            .unwrap_or_default()
            .chars()
            .filter(char::is_ascii_digit)
            .collect::<String>(),
    );
    if digits.len() < 4 {
        return item.title.clone();
    }
    let brand = number
        .and_then(|n| brand_name(card_brand(n)))
        .unwrap_or("Card");
    format!(
        "{brand} \u{b7}\u{b7}\u{b7}\u{b7} {}",
        &digits[digits.len() - 4..]
    )
}

/// The metadata of a candidate item, for `ambiguous_item`.
fn candidate(v: &VaultInfo, item: &Item) -> Value {
    let urls: Vec<&str> = item.urls.iter().map(|u| u.url.as_str()).collect();
    json!({
        "id": item.id.to_string(),
        "vault_id": v.id.to_string(),
        "vault": v.name,
        "title": item.title,
        "type": kind_name(&item.item_type),
        "urls": urls,
    })
}

impl<P: VaultPort> McpTools<P> {
    /// The live item `id` of type `wanted` in a visible vault, else
    /// `no_item` (a missing item, one out of reach, archived or hidden
    /// from autofill answer the same).
    fn fill_item_by_id(
        &mut self,
        id: &str,
        wanted: ItemType,
    ) -> Result<(VaultInfo, Item), Refusal> {
        for v in self.visible_vaults()? {
            let Ok(items) = self.live_items(v.id) else {
                continue;
            };
            if let Some(i) = items
                .into_iter()
                .find(|i| i.id.to_string().eq_ignore_ascii_case(id))
            {
                if !fill_eligible(&i, wanted) {
                    break;
                }
                return Ok((v, i));
            }
        }
        Err(named("no_item", "no such item"))
    }

    /// The only item of type `wanted` in the vaults with the `fill` scope
    /// whose title (or, for a login, a URL) contains `query` ignoring case,
    /// and, for a login, with a URL matching `page` under its rule. Several give
    /// `ambiguous_item` with their metadata, none `no_item`.
    fn fill_item_by_query(
        &mut self,
        query: &str,
        wanted: ItemType,
        page: &Host,
    ) -> Result<(VaultInfo, Item), Refusal> {
        let q = query.to_lowercase();
        let mut found = Vec::new();
        for v in self.visible_vaults()? {
            if !self.scopes(&v).contains(&Scope::Fill) {
                continue;
            }
            let Ok(items) = self.live_items(v.id) else {
                continue;
            };
            for i in items {
                if !fill_eligible(&i, wanted) {
                    continue;
                }
                let hit = match wanted {
                    ItemType::Login => {
                        (i.title.to_lowercase().contains(&q)
                            || i.urls.iter().any(|u| u.url.to_lowercase().contains(&q)))
                            && item_match(&i, page).is_some()
                    }
                    _ => i.title.to_lowercase().contains(&q),
                };
                if hit {
                    found.push((v.clone(), i));
                }
            }
        }
        if found.len() > 1 {
            let list: Vec<Value> = found.iter().map(|(v, i)| candidate(v, i)).collect();
            let text = format!(
                "several items match, use item_id: {}",
                untrusted(Value::Array(list))
            );
            return Err(Refusal::Named {
                code: "ambiguous_item",
                text,
            });
        }
        found
            .pop()
            .ok_or_else(|| named("no_item", "no item matches"))
    }

    /// `fill_in_browser {item_id | query, url, kind, submit?, target}`.
    ///
    /// Order: arguments, HTTPS, `submit` for a card, a `cdp` address that is
    /// not `ws://` (`cdp_not_local`), a locked Mac (`no_browser`), the item,
    /// the `fill` scope, the item's site (login), the audit log and the
    /// secret rate limit, the probe, the tab's site, then the approval
    /// (prompt rate limit, grant, prompt), strong
    /// authentication unless a grant covered it, the fill, the log. Every
    /// exit after a probe that does not reach the fill cancels the probe.
    pub(super) fn fill_in_browser(
        &mut self,
        client: &ClientInfo,
        args: &Map<String, Value>,
        call: &mut Call<'_>,
    ) -> CallResult {
        let kind = match str_arg(args, "kind") {
            Some("card") => FillKind::Card,
            _ => FillKind::Login,
        };
        call.action = Some(kind.action());
        let url = str_arg(args, "url").unwrap_or_default();
        let page = https_page(url)?;
        call.destination = Some(page.origin());
        let site = page.site();
        let submit = args.get("submit").and_then(Value::as_bool).unwrap_or(false);
        if kind == FillKind::Card && submit {
            return Err(named("submit_not_allowed", "a card is never submitted").into());
        }
        let target = match args.get("target") {
            Some(t) if t.get("cdp").is_some() => {
                BrowserTarget::Cdp(t["cdp"].as_str().unwrap_or_default().to_owned())
            }
            _ => BrowserTarget::Chrome,
        };
        // Only a DevTools socket can be local: any other scheme (http, a
        // bare host, nothing) is refused before the item is even looked up.
        if let BrowserTarget::Cdp(addr) = &target
            && !is_ws(addr)
        {
            return Err(browser_refusal(BrowserError::CdpNotLocal).into());
        }
        // A locked Mac (agents-only session) fills nothing, in Chrome or
        // over CDP: refused before the item is looked up or anyone asked.
        if let Some(b) = self.browser.as_ref() {
            b.ready().map_err(browser_refusal)?;
        }
        let wanted = match kind {
            FillKind::Login => ItemType::Login,
            FillKind::Card => ItemType::CreditCard,
        };
        let (vault, item) = match str_arg(args, "item_id") {
            Some(id) => self.fill_item_by_id(id, wanted)?,
            None => {
                self.fill_item_by_query(str_arg(args, "query").unwrap_or_default(), wanted, &page)?
            }
        };
        call.target(vault.id, item.id, None);
        if self.require(&vault, Scope::Fill).is_err() {
            return Err(named("scope_denied", "scope 'fill' not granted for this vault").into());
        }
        if kind == FillKind::Login && item_match(&item, &page).is_none() {
            return Err(named("origin_mismatch", "the item is not for this site").into());
        }

        let client_id = self.client.client_id.clone();
        if self.browser.is_none() {
            return Err(browser_refusal(BrowserError::NoBrowser).into());
        }
        // Audit log usable and the secret rate limit, before the browser is
        // asked anything: a throttled agent cannot drive probes.
        self.admit_secret()?;
        let browser = self
            .browser
            .as_ref()
            .ok_or_else(|| browser_refusal(BrowserError::NoBrowser))?;
        let probe = browser
            .probe(&client_id, &target, url)
            .map_err(browser_refusal)?;
        let cdp = matches!(target, BrowserTarget::Cdp(_));
        if let Err(r) = self.fill_gate(client, kind, cdp, &site, &vault, &item, &probe, call) {
            if let Some(b) = self.browser.as_ref() {
                b.cancel(&probe);
            }
            return Err(r.into());
        }
        let browser = self
            .browser
            .as_ref()
            .ok_or_else(|| browser_refusal(BrowserError::NoBrowser))?;
        // The one-time code goes only where `totp_code` would give it: the
        // `totp` scope on the vault, and a prompt with its strong gesture
        // answered for this very call (`fill_gate` ran both unless a grant
        // covered the call). `fill` alone, or a remembered window, fills
        // the login and password only.
        let with_totp = kind == FillKind::Login
            && call.decision != "remembered"
            && self.require(&vault, Scope::Totp).is_ok();
        let out = browser
            .fill(
                &client_id, &target, &probe, &item, vault.id, kind, submit, with_totp,
            )
            .map_err(browser_refusal)?;
        call.field = Some(if out.submitted { "submitted" } else { "filled" }.to_owned());
        // Only the item field names of spec 3 reach the agent, once each.
        let mut filled: Vec<&str> = Vec::new();
        for name in &out.filled {
            if let Some(n) = FILLED_NAMES.iter().find(|n| **n == name.as_str())
                && !filled.contains(n)
            {
                filled.push(n);
            }
        }
        Ok(json!({"filled": filled, "submitted": out.submitted}))
    }

    /// Everything between the probe and the fill: the tab's site, the
    /// approval and strong authentication.
    #[allow(clippy::too_many_arguments)]
    fn fill_gate(
        &mut self,
        client: &ClientInfo,
        kind: FillKind,
        cdp: bool,
        site: &str,
        vault: &VaultInfo,
        item: &Item,
        probe: &PageProbe,
        call: &mut Call<'_>,
    ) -> Result<(), Refusal> {
        let tab = parse_url(&probe.origin, false)
            .filter(|h| h.scheme == "https" && h.site() == site)
            .ok_or_else(|| browser_refusal(BrowserError::TabMismatch))?;
        // A login's tab must satisfy the item's own rule too; the grant is
        // keyed on what it matched, never wider than that rule.
        let matched = match kind {
            FillKind::Login => Some(
                item_match(item, &tab).ok_or_else(|| browser_refusal(BrowserError::TabMismatch))?,
            ),
            FillKind::Card => None,
        };
        call.destination = Some(tab.origin());
        let action = kind.action();
        let mut details = Vec::new();
        push_detail(&mut details, "site", site);
        // Spec 6.4: a page reached over CDP says so first, its title second.
        if cdp {
            push_detail(&mut details, "browser", "cdp");
        }
        match kind {
            FillKind::Login => {
                let title: String = probe.tab_title.chars().take(MAX_TAB_TITLE).collect();
                push_detail(&mut details, "tab", &title);
            }
            FillKind::Card => push_detail(&mut details, "card", &card_shown(item)),
        }
        let targets = vec![Target {
            vault: vault.name.clone(),
            item: item.title.clone(),
            field: None,
        }];
        let remember = kind == FillKind::Login && !item.reprompt;
        // The grant also names the browser: a window opened for the
        // extension never covers a page driven over CDP, nor the reverse.
        let browser = if cdp { "cdp" } else { "chrome" };
        let key = json!([item.id.to_string(), matched, browser]).to_string();
        self.approve_admitted(
            client,
            action,
            details,
            targets,
            remember,
            Some(key),
            Some(vault.id),
            call,
        )
        .map_err(|r| match r {
            Refusal::Denied => named("denied", "denied by the user"),
            other => other,
        })?;
        if call.decision != "remembered" {
            let shown = format!("{} / {} on {site}", vault.name, item.title);
            let on = call.approved_on.clone();
            // Spec 3: a result or a named error. A failed or cancelled
            // strong gesture is the user not approving.
            self.strong_auth_for(action, &shown, on.as_deref())
                .map_err(|r| match r {
                    Refusal::StrongAuthFailed => named("denied", "strong authentication failed"),
                    other => other,
                })?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::{McpTools, Refusal};
    use super::{https_page, parse_url};
    use crate::browser::{
        BrowserError, BrowserFill, BrowserTarget, FillKind, FillOutcome, PageProbe,
    };
    use crate::guards::{ClientContext, McpGuards, mcp_client_record};
    use crate::policy::{ClientScopes, Narrowing, Policy, Scope};
    use crate::port::{PortError, VaultInfo, VaultPort};
    use crate::protocol::{ClientInfo, ToolHost, ToolOutcome};
    use onepass_core::Id;
    use onepass_core::model::{FieldValue, Item, ItemType, ItemUrl, MatchRule, new_item};
    use onepass_core::reference::SecretRef;
    use onepass_guard::testing::{FakeClock, ScriptedApprover, dev_strong};
    use onepass_guard::{
        AuditEntry, AuditSink, ClientRegistry, Decision, GrantStore, GuardError, Limits,
        LocalSigner, Throttle,
    };
    use serde_json::{Value, json};
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use zeroize::Zeroizing;

    const PASSWORD: &str = "hunter2-correct-horse";
    const CARD_NUMBER: &str = "4111111111111111";
    const REQUEST_ID: u64 = 9_876_543_210;

    struct TestSigner;

    impl LocalSigner for TestSigner {
        fn sign(&self, domain: &[u8], msg: &[u8]) -> Result<Vec<u8>, GuardError> {
            let key = aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA256, &[7; 32]);
            let input = [domain, b"\0", msg].concat();
            Ok(aws_lc_rs::hmac::sign(&key, &input).as_ref().to_vec())
        }
        fn verify(&self, domain: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), GuardError> {
            let key = aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA256, &[7; 32]);
            let input = [domain, b"\0", msg].concat();
            aws_lc_rs::hmac::verify(&key, &input, sig).map_err(|_| GuardError::Signature)
        }
    }

    #[derive(Default)]
    struct FakePort {
        vaults: Vec<VaultInfo>,
        items: BTreeMap<Id, Vec<Item>>,
    }

    impl VaultPort for FakePort {
        fn vaults(&mut self) -> Result<Vec<VaultInfo>, PortError> {
            Ok(self.vaults.clone())
        }
        fn items(&mut self, vault_id: Id) -> Result<Vec<Item>, PortError> {
            self.items
                .get(&vault_id)
                .cloned()
                .ok_or(PortError::NotFound)
        }
        fn resolve(&mut self, _r: &SecretRef) -> Result<Zeroizing<String>, PortError> {
            Err(PortError::Other("fill never resolves".into()))
        }
        fn save_item(&mut self, _vault_id: Id, _item: Item) -> Result<(), PortError> {
            Err(PortError::Other("read only".into()))
        }
    }

    /// What the fake browser saw.
    #[derive(Default)]
    struct BrowserLog {
        probes: Vec<String>,
        fills: Vec<(Id, FillKind, bool, String)>,
        /// `with_totp` of each fill, in order.
        totp: Vec<bool>,
        cancels: Vec<u64>,
    }

    /// A browser whose active tab is on `origin`, titled `title`.
    struct FakeBrowser {
        origin: String,
        title: String,
        probe_error: Option<BrowserError>,
        fill_error: Option<BrowserError>,
        log: Arc<Mutex<BrowserLog>>,
        /// What the fill reports instead of the kind's default names.
        filled: Option<Vec<String>>,
        locked: bool,
    }

    impl BrowserFill for FakeBrowser {
        fn ready(&self) -> Result<(), BrowserError> {
            if self.locked {
                return Err(BrowserError::MacLocked);
            }
            Ok(())
        }

        fn probe(
            &self,
            _client_id: &str,
            _target: &BrowserTarget,
            url: &str,
        ) -> Result<PageProbe, BrowserError> {
            self.log.lock().unwrap().probes.push(url.to_owned());
            if let Some(e) = self.probe_error {
                return Err(e);
            }
            Ok(PageProbe {
                tab_title: self.title.clone(),
                origin: self.origin.clone(),
                handle: "doc-1".into(),
                request_id: REQUEST_ID,
            })
        }

        fn fill(
            &self,
            _client_id: &str,
            _target: &BrowserTarget,
            probe: &PageProbe,
            item: &Item,
            _vault_id: Id,
            kind: FillKind,
            submit: bool,
            with_totp: bool,
        ) -> Result<FillOutcome, BrowserError> {
            let mut log = self.log.lock().unwrap();
            log.fills
                .push((item.id, kind, submit, probe.handle.clone()));
            log.totp.push(with_totp);
            drop(log);
            if let Some(e) = self.fill_error {
                return Err(e);
            }
            let filled = self.filled.clone().unwrap_or_else(|| match kind {
                FillKind::Login => vec!["username".into(), "password".into()],
                FillKind::Card => vec!["number".into(), "expiry".into(), "cvv".into()],
            });
            Ok(FillOutcome {
                filled,
                submitted: submit,
            })
        }

        fn cancel(&self, probe: &PageProbe) {
            self.log.lock().unwrap().cancels.push(probe.request_id);
        }
    }

    #[derive(Clone, Default)]
    struct Sink(Arc<Mutex<Vec<AuditEntry>>>);

    impl AuditSink for Sink {
        fn record(&mut self, e: &AuditEntry) -> Result<(), GuardError> {
            self.0.lock().unwrap().push(e.clone());
            Ok(())
        }
    }

    struct Fx {
        tools: McpTools<FakePort>,
        agents: VaultInfo,
        other: VaultInfo,
        github: Item,
        card: Item,
        approver: Arc<ScriptedApprover>,
        audit: Sink,
        log: Arc<Mutex<BrowserLog>>,
        clock: Arc<FakeClock>,
        _dir: tempfile::TempDir,
    }

    fn client() -> ClientInfo {
        ClientInfo {
            name: "agent".into(),
            version: "1".into(),
        }
    }

    fn login(vault: Id, title: &str, url: &str) -> Item {
        let mut i = new_item(ItemType::Login, vault, title);
        if let Some(f) = i.field_mut("username") {
            f.value = FieldValue::Text("octocat".into());
        }
        if let Some(f) = i.field_mut("password") {
            f.value = FieldValue::Password(Zeroizing::new(PASSWORD.into()));
        }
        i.urls.push(ItemUrl {
            label: "website".into(),
            url: url.into(),
            rule: MatchRule::Domain,
            primary: true,
        });
        i
    }

    /// Vault `Agents` with the fill scope (a GitHub login, a Visa card) and
    /// vault `Other` without it (a second GitHub login). The browser's tab
    /// is on `https://github.com`, the approver answers with `answers`.
    fn fx(answers: Vec<Decision>) -> Fx {
        let vault = |name: &str| VaultInfo {
            id: Id::new(),
            name: name.into(),
            mcp_access: true,
        };
        let agents = vault("Agents");
        let other = vault("Other");
        let github = login(agents.id, "GitHub", "https://github.com/login");
        let mut card = new_item(ItemType::CreditCard, agents.id, "Visa perso");
        if let Some(f) = card.field_mut("number") {
            f.value = FieldValue::Concealed(Zeroizing::new(CARD_NUMBER.into()));
        }
        let other_github = login(other.id, "GitHub work", "https://github.com");
        let mut items = BTreeMap::new();
        items.insert(agents.id, vec![github.clone(), card.clone()]);
        items.insert(other.id, vec![other_github]);
        let vaults = vec![agents.clone(), other.clone()];

        let ctx = ClientContext {
            client_id: "team:T:agent".into(),
            label: "Agent".into(),
            signed: true,
            hardened: None,
        };
        let scopes: ClientScopes = vaults
            .iter()
            .map(|v| (v.id.to_string(), Scope::ALL.into_iter().collect()))
            .collect();
        let mut reg = ClientRegistry::empty("acct");
        reg.clients
            .push(mcp_client_record(&ctx, Value::Null, &scopes, 1));
        let dir = tempfile::tempdir().unwrap();
        let clock = Arc::new(FakeClock::new(1_000_000));
        let mut g = McpGuards::new(
            ctx,
            Box::new(move || Ok(reg.clone())),
            Arc::new(Mutex::new(GrantStore::open(
                dir.path().join("grants.json"),
                "acct",
            ))),
            Box::new(TestSigner),
            Arc::new(dev_strong(true)),
            clock.clone(),
        );
        g.throttle = Throttle::new(Limits {
            prompts_per_min: 1000,
            secret_per_min: 1000,
            denials_before_cooldown: 1000,
            cooldown: Duration::from_secs(1),
        });
        g.prompt_wait = Duration::from_secs(1);
        let mut policy = Policy::default_for("acct");
        policy
            .vaults
            .insert(agents.id.to_string(), Scope::ALL.into_iter().collect());
        policy.vaults.insert(
            other.id.to_string(),
            BTreeSet::from([Scope::Metadata, Scope::Use]),
        );
        let approver = Arc::new(ScriptedApprover::new(answers));
        let audit = Sink::default();
        let log = Arc::new(Mutex::new(BrowserLog::default()));
        let tools = McpTools::new(
            FakePort { vaults, items },
            policy,
            Narrowing::default(),
            approver.clone(),
            Box::new(audit.clone()),
            None,
            g,
        )
        .with_browser(Box::new(FakeBrowser {
            origin: "https://github.com".into(),
            title: "Sign in to GitHub".into(),
            probe_error: None,
            fill_error: None,
            log: log.clone(),
            filled: None,
            locked: false,
        }));
        Fx {
            tools,
            agents,
            other,
            github,
            card,
            approver,
            audit,
            log,
            clock,
            _dir: dir,
        }
    }

    impl Fx {
        fn call(&mut self, args: Value) -> ToolOutcome {
            self.tools
                .call(&client(), "fill_in_browser", args.as_object().unwrap())
        }

        fn set_browser(&mut self, origin: &str, probe_error: Option<BrowserError>) {
            self.set_browser_full(origin, probe_error, None);
        }

        fn set_browser_full(
            &mut self,
            origin: &str,
            probe_error: Option<BrowserError>,
            fill_error: Option<BrowserError>,
        ) {
            self.tools.browser = Some(Box::new(FakeBrowser {
                origin: origin.into(),
                title: "Sign in to GitHub".into(),
                probe_error,
                fill_error,
                log: self.log.clone(),
                filled: None,
                locked: false,
            }));
        }

        fn entries(&self) -> Vec<AuditEntry> {
            self.audit.0.lock().unwrap().clone()
        }
    }

    fn chrome() -> Value {
        json!({"browser": "chrome"})
    }

    fn login_args(item: &Item) -> Value {
        json!({"item_id": item.id.to_string(), "url": "https://github.com/login", "kind": "login", "target": chrome()})
    }

    fn card_args(item: &Item, url: &str) -> Value {
        json!({"item_id": item.id.to_string(), "url": url, "kind": "card", "target": chrome()})
    }

    /// The refusal text, which starts with the error name.
    fn refused(out: ToolOutcome) -> String {
        match out {
            ToolOutcome::Refused(m) => m,
            ToolOutcome::Ok(v) => panic!("not refused: {v}"),
            ToolOutcome::InvalidParams(m) => panic!("invalid params: {m}"),
        }
    }

    fn code(out: ToolOutcome) -> String {
        let m = refused(out);
        m.split(':').next().unwrap_or_default().to_owned()
    }

    fn ok(out: ToolOutcome) -> Value {
        match out {
            ToolOutcome::Ok(v) => v,
            ToolOutcome::Refused(m) => panic!("refused: {m}"),
            ToolOutcome::InvalidParams(m) => panic!("invalid params: {m}"),
        }
    }

    #[test]
    fn urls_give_their_site_and_origin() {
        let h = parse_url("https://Accounts.Example.co.uk:443/x?y#z", false).unwrap();
        assert_eq!(h.site(), "example.co.uk");
        assert_eq!(h.origin(), "https://accounts.example.co.uk");
        let h = parse_url("https://app.example.com.:8443", false).unwrap();
        assert_eq!(h.origin(), "https://app.example.com:8443");
        assert_eq!(
            parse_url("github.com/login", true).unwrap().site(),
            "github.com"
        );
        assert!(parse_url("github.com/login", false).is_none());
        assert_eq!(
            parse_url("https://10.0.0.1/a", false).unwrap().site(),
            "10.0.0.1"
        );
        assert_eq!(
            parse_url("https://[::1]:9/", false).unwrap().origin(),
            "https://[::1]:9"
        );
        for bad in [
            "https://user@github.com",
            "https://github.com:99999",
            "https://github.com:x",
            "https://",
            "https://exämple.com",
            "ftp://github.com",
            "https://[::1]x",
        ] {
            assert!(parse_url(bad, false).is_none(), "{bad}");
        }
        assert!(https_page("HTTPS://github.com").is_ok());
        assert!(matches!(https_page("https://"), Err(Refusal::Invalid(_))));
    }

    #[test]
    fn http_url_is_not_https() {
        let mut f = fx(vec![Decision::AllowOnce]);
        let mut args = login_args(&f.github.clone());
        args["url"] = json!("http://github.com/login");
        assert_eq!(code(f.call(args)), "not_https");
        assert!(f.approver.calls().is_empty());
        assert!(f.log.lock().unwrap().probes.is_empty());
    }

    #[test]
    fn card_with_submit_is_refused_before_any_prompt() {
        let mut f = fx(vec![Decision::AllowOnce]);
        let mut args = card_args(&f.card.clone(), "https://github.com/checkout");
        args["submit"] = json!(true);
        assert_eq!(code(f.call(args)), "submit_not_allowed");
        assert!(f.approver.calls().is_empty());
        assert!(f.log.lock().unwrap().probes.is_empty());
    }

    #[test]
    fn vault_without_fill_scope_is_scope_denied() {
        let mut f = fx(vec![Decision::AllowOnce]);
        let other = f.tools.port.items[&f.other.id][0].clone();
        assert_eq!(code(f.call(login_args(&other))), "scope_denied");
        assert!(f.approver.calls().is_empty());
        assert!(f.log.lock().unwrap().probes.is_empty());
        // A query never sees items of vaults without the fill scope: only
        // the Agents login matches.
        let out = f.call(json!({"query": "github", "url": "https://github.com/login", "kind": "login", "target": chrome()}));
        ok(out);
        let fills = &f.log.lock().unwrap().fills;
        assert_eq!(fills[0].0, f.github.id);
    }

    #[test]
    fn item_for_other_site_is_origin_mismatch_without_prompt() {
        let mut f = fx(vec![Decision::AllowOnce]);
        let mut args = login_args(&f.github.clone());
        args["url"] = json!("https://github.com.evil.test/login");
        assert_eq!(code(f.call(args)), "origin_mismatch");
        assert!(f.approver.calls().is_empty());
        assert!(f.log.lock().unwrap().probes.is_empty());
    }

    #[test]
    fn ambiguous_query_lists_candidates_and_fills_nothing() {
        let mut f = fx(vec![Decision::AllowOnce]);
        let second = login(f.agents.id, "GitHub bot", "https://gist.github.com");
        f.tools
            .port
            .items
            .get_mut(&f.agents.id)
            .unwrap()
            .push(second.clone());
        let out = f.call(json!({"query": "github", "url": "https://github.com/login", "kind": "login", "target": chrome()}));
        let m = refused(out);
        assert!(m.starts_with("ambiguous_item: "), "{m}");
        assert!(m.contains(&f.github.id.to_string()), "{m}");
        assert!(m.contains(&second.id.to_string()), "{m}");
        assert!(!m.contains(PASSWORD) && !m.contains("octocat"), "{m}");
        assert!(f.approver.calls().is_empty());
        assert!(f.log.lock().unwrap().probes.is_empty());
        // No match at all.
        let out = f.call(json!({"query": "gitlab", "url": "https://github.com/login", "kind": "login", "target": chrome()}));
        assert_eq!(code(out), "no_item");
        // A card query: by title, exactly one.
        let out = f.call(json!({"query": "visa", "url": "https://shop.test/pay", "kind": "card", "target": chrome()}));
        assert_eq!(code(out), "tab_mismatch");
    }

    #[test]
    fn tab_on_other_site_is_tab_mismatch_without_prompt() {
        let mut f = fx(vec![Decision::AllowOnce]);
        f.set_browser("https://evil.test", None);
        assert_eq!(code(f.call(login_args(&f.github.clone()))), "tab_mismatch");
        assert!(f.approver.calls().is_empty());
        let log = f.log.lock().unwrap();
        assert_eq!(log.probes.len(), 1);
        assert!(log.fills.is_empty());
        assert_eq!(log.cancels, vec![REQUEST_ID]);
    }

    #[test]
    fn denied_fill_cancels_the_probe() {
        let mut f = fx(vec![Decision::Deny]);
        assert_eq!(code(f.call(login_args(&f.github.clone()))), "denied");
        let log = f.log.lock().unwrap();
        assert!(log.fills.is_empty());
        assert_eq!(log.cancels, vec![REQUEST_ID]);
    }

    #[test]
    fn login_fill_prompts_then_remembers_for_the_chosen_window() {
        let mut f = fx(vec![
            Decision::AllowFor(Duration::from_secs(300)),
            Decision::AllowOnce,
        ]);
        let args = login_args(&f.github.clone());
        let out = ok(f.call(args.clone()));
        assert_eq!(
            out,
            json!({"filled": ["username", "password"], "submitted": false})
        );
        let calls = f.approver.calls();
        assert_eq!(calls.len(), 1);
        let req = &calls[0];
        assert_eq!(req.action, "fill_login");
        assert!(req.remember_allowed);
        assert!(req.strong_required);
        assert_eq!(
            req.details,
            vec![
                ("site".to_owned(), "github.com".to_owned()),
                ("tab".to_owned(), "Sign in to GitHub".to_owned()),
            ]
        );
        // Within the window: no prompt.
        ok(f.call(args.clone()));
        assert_eq!(f.approver.calls().len(), 1);
        assert_eq!(f.entries()[1].decision, "remembered");
        // After it: asked again.
        f.clock.advance(Duration::from_secs(301));
        ok(f.call(args));
        assert_eq!(f.approver.calls().len(), 2);
        assert_eq!(f.log.lock().unwrap().fills.len(), 3);
        assert!(f.log.lock().unwrap().cancels.is_empty());
    }

    /// A login fill writes the one-time code under the rules of
    /// `totp_code`: the `totp` scope on the vault, and an approval with its
    /// strong gesture on this very call. A remembered window, or `fill`
    /// alone, fills the login and password only.
    #[test]
    fn login_fill_writes_the_code_only_with_totp_scope_and_a_fresh_gesture() {
        let mut f = fx(vec![
            Decision::AllowFor(Duration::from_secs(300)),
            Decision::AllowOnce,
        ]);
        let args = login_args(&f.github.clone());
        ok(f.call(args.clone()));
        // Within the window: no prompt, so no code.
        ok(f.call(args.clone()));
        assert_eq!(f.entries()[1].decision, "remembered");
        // Asked again, but the vault no longer grants `totp`.
        let no_totp: BTreeSet<Scope> = Scope::ALL
            .into_iter()
            .filter(|s| *s != Scope::Totp)
            .collect();
        f.tools
            .policy
            .vaults
            .insert(f.agents.id.to_string(), no_totp);
        f.clock.advance(Duration::from_secs(301));
        ok(f.call(args));
        assert_eq!(f.approver.calls().len(), 2);
        assert_eq!(f.log.lock().unwrap().totp, vec![true, false, false]);
    }

    /// A card never carries a one-time code.
    #[test]
    fn card_fill_never_asks_for_a_code() {
        let mut f = fx(vec![Decision::AllowOnce]);
        f.set_browser("https://shop.test", None);
        ok(f.call(card_args(&f.card.clone(), "https://shop.test/pay")));
        assert_eq!(f.log.lock().unwrap().totp, vec![false]);
    }

    #[test]
    fn card_fill_prompts_every_time() {
        let mut f = fx(vec![
            Decision::AllowFor(Duration::from_secs(300)),
            Decision::AllowFor(Duration::from_secs(300)),
        ]);
        f.set_browser("https://shop.test", None);
        let args = card_args(&f.card.clone(), "https://shop.test/pay");
        ok(f.call(args.clone()));
        ok(f.call(args));
        let calls = f.approver.calls();
        assert_eq!(calls.len(), 2);
        for req in &calls {
            assert_eq!(req.action, "fill_card");
            assert!(!req.remember_allowed);
            assert!(req.strong_required);
            assert_eq!(
                req.details,
                vec![
                    ("site".to_owned(), "shop.test".to_owned()),
                    (
                        "card".to_owned(),
                        "Visa \u{b7}\u{b7}\u{b7}\u{b7} 1111".to_owned()
                    ),
                ]
            );
        }
        let fills = &f.log.lock().unwrap().fills;
        assert_eq!(fills.len(), 2);
        assert_eq!(fills[0].1, FillKind::Card);
        assert!(!fills[0].2);
    }

    #[test]
    fn response_never_contains_a_value() {
        let mut f = fx(vec![Decision::AllowOnce, Decision::AllowOnce]);
        let mut args = login_args(&f.github.clone());
        args["submit"] = json!(true);
        let out = ok(f.call(args)).to_string();
        assert!(!out.contains(PASSWORD) && !out.contains("octocat"), "{out}");
        assert!(
            !out.contains(&REQUEST_ID.to_string()) && !out.contains("doc-1"),
            "{out}"
        );
        assert_eq!(
            out,
            json!({"filled": ["username", "password"], "submitted": true}).to_string()
        );
        f.set_browser("https://shop.test", None);
        let out = ok(f.call(card_args(&f.card.clone(), "https://shop.test/pay"))).to_string();
        assert!(!out.contains(CARD_NUMBER) && !out.contains("1111"), "{out}");
        for e in f.entries() {
            let s = serde_json::to_string(&e).unwrap();
            assert!(!s.contains(PASSWORD) && !s.contains(CARD_NUMBER), "{s}");
        }
    }

    #[test]
    fn each_fill_writes_one_audit_entry_with_origin_only() {
        let mut f = fx(vec![Decision::AllowOnce]);
        ok(f.call(login_args(&f.github.clone())));
        let entries = f.entries();
        assert_eq!(entries.len(), 1);
        let e = &entries[0];
        assert_eq!(e.action, "fill_login");
        assert_eq!(e.outcome, "ok");
        assert_eq!(e.decision, "once");
        assert_eq!(e.vault_id, Some(f.agents.id.to_string()));
        assert_eq!(e.item_id, Some(f.github.id.to_string()));
        assert_eq!(e.destination.as_deref(), Some("https://github.com"));
        let s = serde_json::to_string(e).unwrap();
        assert!(
            !s.contains("Sign in") && !s.contains("/login") && !s.contains(&REQUEST_ID.to_string()),
            "{s}"
        );
        // A refusal writes one entry too, with the origin of the url.
        let mut args = login_args(&f.github.clone());
        args["url"] = json!("https://evil.test/a/b?c=d");
        assert_eq!(code(f.call(args)), "origin_mismatch");
        let entries = f.entries();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1].outcome, "origin_mismatch");
        assert_eq!(entries[1].destination.as_deref(), Some("https://evil.test"));
    }

    #[test]
    fn browser_timeout_is_reported_as_timeout() {
        let mut f = fx(vec![Decision::AllowOnce]);
        f.set_browser("https://github.com", Some(BrowserError::Timeout));
        assert_eq!(code(f.call(login_args(&f.github.clone()))), "timeout");
        assert!(f.approver.calls().is_empty());
        // A timeout while filling, after approval: no cancel, the fill
        // consumed the probe.
        let mut f = fx(vec![Decision::AllowOnce]);
        f.set_browser_full("https://github.com", None, Some(BrowserError::Timeout));
        assert_eq!(code(f.call(login_args(&f.github.clone()))), "timeout");
        assert!(f.log.lock().unwrap().cancels.is_empty());
    }

    #[test]
    fn browser_errors_have_their_names() {
        for (e, name) in [
            (BrowserError::NoBrowser, "no_browser"),
            (BrowserError::Timeout, "timeout"),
            (BrowserError::TabMismatch, "tab_mismatch"),
            (BrowserError::OriginMismatch, "origin_mismatch"),
            (BrowserError::CrossSiteFrame, "cross_site_frame"),
            (BrowserError::NoFields, "no_fields"),
            (BrowserError::CdpNotLocal, "cdp_not_local"),
        ] {
            let mut f = fx(vec![Decision::AllowOnce]);
            f.set_browser("https://github.com", Some(e));
            assert_eq!(code(f.call(login_args(&f.github.clone()))), name);
        }
        let mut f = fx(vec![]);
        f.tools.browser = None;
        assert_eq!(code(f.call(login_args(&f.github.clone()))), "no_browser");
        assert_eq!(
            Refusal::Named {
                code: "denied",
                text: "x".into()
            }
            .outcome(),
            "denied"
        );
    }

    /// A login for `https://app.example.com` only (rule `ExactHost`), and
    /// one with two exact hosts.
    fn exact_host_fx(answers: Vec<Decision>) -> (Fx, Item) {
        let mut f = fx(answers);
        let mut item = login(f.agents.id, "Example app", "https://app.example.com");
        item.urls[0].rule = MatchRule::ExactHost;
        item.urls.push(ItemUrl {
            label: "sso".into(),
            url: "https://sso.example.com".into(),
            rule: MatchRule::ExactHost,
            primary: false,
        });
        f.tools
            .port
            .items
            .get_mut(&f.agents.id)
            .unwrap()
            .push(item.clone());
        (f, item)
    }

    fn exact_args(item: &Item, url: &str) -> Value {
        json!({"item_id": item.id.to_string(), "url": url, "kind": "login", "target": chrome()})
    }

    #[test]
    fn exact_host_item_refuses_sibling_subdomain() {
        let (mut f, item) = exact_host_fx(vec![Decision::AllowOnce, Decision::AllowOnce]);
        // The agent names a sibling host: refused before any probe.
        f.set_browser("https://www.example.com", None);
        assert_eq!(
            code(f.call(exact_args(&item, "https://www.example.com/login"))),
            "origin_mismatch"
        );
        assert!(f.log.lock().unwrap().probes.is_empty());
        // The agent names the right host but the tab is on a sibling.
        assert_eq!(
            code(f.call(exact_args(&item, "https://app.example.com/login"))),
            "tab_mismatch"
        );
        assert!(f.approver.calls().is_empty());
        assert_eq!(f.log.lock().unwrap().cancels, vec![REQUEST_ID]);
        // The exact host fills.
        f.set_browser("https://app.example.com", None);
        ok(f.call(exact_args(&item, "https://app.example.com/login")));
        // An ExactUrl item is held to its origin, port included.
        let mut f = fx(vec![Decision::AllowOnce]);
        let mut pinned = login(f.agents.id, "Pinned", "https://app.example.com:8443/login");
        pinned.urls[0].rule = MatchRule::ExactUrl;
        f.tools
            .port
            .items
            .get_mut(&f.agents.id)
            .unwrap()
            .push(pinned.clone());
        assert_eq!(
            code(f.call(exact_args(&pinned, "https://app.example.com/login"))),
            "origin_mismatch"
        );
    }

    #[test]
    fn exact_host_grant_does_not_cover_sibling() {
        let (mut f, item) = exact_host_fx(vec![
            Decision::AllowFor(Duration::from_secs(300)),
            Decision::AllowOnce,
        ]);
        f.set_browser("https://app.example.com", None);
        ok(f.call(exact_args(&item, "https://app.example.com/login")));
        ok(f.call(exact_args(&item, "https://app.example.com/login")));
        assert_eq!(f.approver.calls().len(), 1);
        // Same item and registrable domain, other exact host: asked again.
        f.set_browser("https://sso.example.com", None);
        ok(f.call(exact_args(&item, "https://sso.example.com/")));
        assert_eq!(f.approver.calls().len(), 2);
    }

    #[test]
    fn hidden_item_by_id_is_no_item() {
        let mut f = fx(vec![Decision::AllowOnce, Decision::AllowOnce]);
        let mut hidden = login(f.agents.id, "Hidden", "https://github.com");
        hidden.hide_from_autofill = true;
        let mut archived = login(f.agents.id, "Archived", "https://github.com");
        archived.archived = true;
        let mut trashed = login(f.agents.id, "Trashed", "https://github.com");
        trashed.trashed_at = Some(trashed.created_at);
        let items = f.tools.port.items.get_mut(&f.agents.id).unwrap();
        items.extend([hidden.clone(), archived.clone(), trashed.clone()]);
        for i in [&hidden, &archived, &trashed] {
            assert_eq!(code(f.call(login_args(i))), "no_item", "{}", i.title);
        }
        assert!(f.approver.calls().is_empty());
        assert!(f.log.lock().unwrap().probes.is_empty());
    }

    #[test]
    fn unknown_brand_shows_card() {
        let mut card = new_item(ItemType::CreditCard, Id::new(), "Prepaid");
        card.field_mut("number").unwrap().value =
            FieldValue::Concealed(Zeroizing::new("9999000011112222".into()));
        card.field_mut("card_type").unwrap().value = FieldValue::Menu("Débit".into());
        assert_eq!(
            super::card_shown(&card),
            "Card \u{b7}\u{b7}\u{b7}\u{b7} 2222"
        );
        card.field_mut("number").unwrap().value = FieldValue::Empty;
        assert_eq!(super::card_shown(&card), "Prepaid");
    }

    #[test]
    fn cdp_address_without_ws_scheme_is_cdp_not_local() {
        for addr in [
            "http://127.0.0.1:9222/devtools/page/x",
            "https://127.0.0.1:9222/json",
            "wss://127.0.0.1:9222/devtools/page/x",
            "127.0.0.1:9222",
            " ws://127.0.0.1:9222/devtools/page/x",
        ] {
            let mut f = fx(vec![Decision::AllowOnce]);
            let mut args = login_args(&f.github.clone());
            args["target"] = json!({"cdp": addr});
            assert_eq!(code(f.call(args)), "cdp_not_local", "{addr}");
            assert!(f.approver.calls().is_empty());
            assert!(f.log.lock().unwrap().probes.is_empty());
            assert_eq!(f.entries()[0].outcome, "cdp_not_local");
        }
        assert!(super::is_ws("WS://127.0.0.1:1/x") && super::is_ws("ws://[::1]:1/x"));
    }

    #[test]
    fn cdp_target_says_so_in_the_panel() {
        let mut f = fx(vec![Decision::AllowOnce, Decision::AllowOnce]);
        let cdp = json!({"cdp": "ws://127.0.0.1:9222/devtools/page/x"});
        let mut args = login_args(&f.github.clone());
        args["target"] = cdp.clone();
        ok(f.call(args));
        f.set_browser("https://shop.test", None);
        let mut args = card_args(&f.card.clone(), "https://shop.test/pay");
        args["target"] = cdp;
        ok(f.call(args));
        let calls = f.approver.calls();
        assert_eq!(
            calls[0].details,
            vec![
                ("site".to_owned(), "github.com".to_owned()),
                ("browser".to_owned(), "cdp".to_owned()),
                ("tab".to_owned(), "Sign in to GitHub".to_owned()),
            ]
        );
        assert_eq!(
            calls[1].details[1],
            ("browser".to_owned(), "cdp".to_owned())
        );
        assert_eq!(calls[1].details[2].0, "card");
        // The Chrome target never shows it.
        let mut f = fx(vec![Decision::AllowOnce]);
        ok(f.call(login_args(&f.github.clone())));
        assert!(
            f.approver.calls()[0]
                .details
                .iter()
                .all(|(l, _)| l != "browser")
        );
    }

    #[test]
    fn login_grant_window_is_per_browser_target() {
        let window = Decision::AllowFor(Duration::from_secs(900));
        let cdp = json!({"cdp": "ws://127.0.0.1:9222/devtools/page/x"});
        for (first, second) in [(chrome(), cdp.clone()), (cdp.clone(), chrome())] {
            let mut f = fx(vec![window, window, Decision::AllowOnce]);
            let mut args = login_args(&f.github.clone());
            args["target"] = first.clone();
            ok(f.call(args.clone()));
            // Same target within the window: no prompt.
            ok(f.call(args.clone()));
            assert_eq!(f.approver.calls().len(), 1);
            assert_eq!(f.entries()[1].decision, "remembered");
            // The other target, same item and site: asked again.
            args["target"] = second.clone();
            ok(f.call(args.clone()));
            assert_eq!(f.approver.calls().len(), 2, "{first} then {second}");
            assert_ne!(f.entries()[2].decision, "remembered");
        }
    }

    #[test]
    fn failed_strong_auth_cancels_the_probe() {
        let mut f = fx(vec![Decision::AllowOnce]);
        f.tools.strong = Arc::new(dev_strong(false));
        assert_eq!(code(f.call(login_args(&f.github.clone()))), "denied");
        let log = f.log.lock().unwrap();
        assert!(log.fills.is_empty());
        assert_eq!(log.cancels, vec![REQUEST_ID]);
    }

    #[test]
    fn filled_reports_only_the_known_field_names() {
        let mut f = fx(vec![Decision::AllowOnce]);
        f.tools.browser = Some(Box::new(FakeBrowser {
            origin: "https://github.com".into(),
            title: "Sign in to GitHub".into(),
            probe_error: None,
            fill_error: None,
            log: f.log.clone(),
            filled: Some(vec![
                "password".into(),
                "hunter2".into(),
                "username".into(),
                "password".into(),
                "current_password".into(),
                "cvv".into(),
            ]),
            locked: false,
        }));
        let out = ok(f.call(login_args(&f.github.clone())));
        assert_eq!(
            out,
            json!({"filled": ["password", "username", "cvv"], "submitted": false})
        );
    }

    #[test]
    fn locked_mac_is_no_browser_before_item_lookup_and_prompt() {
        for target in [
            chrome(),
            json!({"cdp": "ws://127.0.0.1:9222/devtools/page/x"}),
        ] {
            let mut f = fx(vec![Decision::AllowOnce]);
            f.tools.browser = Some(Box::new(FakeBrowser {
                origin: "https://github.com".into(),
                title: "Sign in to GitHub".into(),
                probe_error: None,
                fill_error: None,
                log: f.log.clone(),
                filled: None,
                locked: true,
            }));
            // An unknown item: the refusal comes first all the same.
            let out = f.call(
                json!({"query": "nothing", "url": "https://github.com/login",
                "kind": "login", "target": target}),
            );
            let m = refused(out);
            assert!(m.starts_with("no_browser"), "{m}");
            assert!(m.contains("unlock the Mac"), "{m}");
            assert!(f.approver.calls().is_empty());
            assert!(f.log.lock().unwrap().probes.is_empty());
        }
    }

    #[test]
    fn secret_rate_limit_runs_before_the_probe() {
        let mut f = fx(vec![Decision::AllowOnce, Decision::AllowOnce]);
        f.tools.throttle = Throttle::new(Limits {
            prompts_per_min: 1000,
            secret_per_min: 1,
            denials_before_cooldown: 1000,
            cooldown: Duration::from_secs(1),
        });
        ok(f.call(login_args(&f.github.clone())));
        let m = refused(f.call(login_args(&f.github.clone())));
        assert!(m.contains("rate"), "{m}");
        // The second call never reached the browser.
        assert_eq!(f.log.lock().unwrap().probes.len(), 1);
        assert_eq!(f.approver.calls().len(), 1);
    }
}
