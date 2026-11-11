//! The one URL matcher (spec 6.1): the bridge, the system AutoFill and the
//! MCP all decide through [`matches`], whatever parser gave them the parts.
//!
//! Hosts are compared in their lowercase ASCII (punycode) form, so an IDN
//! lookalike never equals the original. The registrable domain (eTLD+1)
//! comes from the Public Suffix List through the `psl` crate.
//!
//! The associated domains are Apple's `quirks/shared-credentials.json` from
//! `apple/password-manager-resources` (MIT), vendored next to the password
//! rules in `onepass-bridge/data` at commit
//! `316412ba01dba1d84dc52d51267f503964638e20`. It is embedded here, not in
//! the bridge, because the MCP does not depend on the bridge. No network
//! call happens at run time.

use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

use crate::model::{Item, ItemUrl, MatchRule};

const SHARED_CREDENTIALS: &str =
    include_str!("../../../onepass-bridge/data/shared-credentials.json");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Https,
    Http,
}

impl Scheme {
    /// `https` or `http`, any case; nothing else is ever matched.
    pub fn parse(s: &str) -> Option<Scheme> {
        if s.eq_ignore_ascii_case("https") {
            Some(Scheme::Https)
        } else if s.eq_ignore_ascii_case("http") {
            Some(Scheme::Http)
        } else {
            None
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Scheme::Https => "https",
            Scheme::Http => "http",
        }
    }

    pub fn default_port(self) -> u16 {
        match self {
            Scheme::Https => 443,
            Scheme::Http => 80,
        }
    }
}

/// A page or an item URL, parsed and normalized by the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UrlParts {
    pub scheme: Scheme,
    /// Lowercase ASCII (punycode), no trailing dot; an IPv6 address in
    /// brackets.
    pub host: String,
    /// `None` for the default port of the scheme.
    pub port: Option<u16>,
    /// `/` at least, without query or fragment. Empty when the parser
    /// cannot vouch for it: such a path equals no `ExactUrl` item.
    pub path: String,
    /// The host is an address.
    pub ip: bool,
}

impl UrlParts {
    /// Registrable domain (eTLD+1), or the whole host when the PSL gives
    /// none (an address, a bare public suffix).
    pub fn site(&self) -> String {
        site_of(&self.host, self.ip)
    }

    /// `scheme://host[:port]`.
    pub fn origin(&self) -> String {
        match self.port {
            Some(p) => format!("{}://{}:{p}", self.scheme.as_str(), self.host),
            None => format!("{}://{}", self.scheme.as_str(), self.host),
        }
    }

    /// The port the page is served on.
    pub fn effective_port(&self) -> u16 {
        self.port.unwrap_or(self.scheme.default_port())
    }

    /// Same scheme, host and port.
    pub fn same_origin(&self, other: &UrlParts) -> bool {
        self.scheme == other.scheme && self.host == other.host && self.port == other.port
    }

    /// May a page at this URL be filled at all: `https`, or `http` on a
    /// loopback host (spec 6.1). Every other `http` page is refused.
    pub fn fillable_page(&self) -> bool {
        self.scheme == Scheme::Https || is_loopback(&self.host)
    }
}

/// Registrable domain of a host, the host itself for an address or when
/// the PSL gives none.
pub fn site_of(host: &str, ip: bool) -> String {
    if ip {
        return host.to_owned();
    }
    psl::domain_str(host).unwrap_or(host).to_owned()
}

/// The loopback hosts, where plain `http` may be filled: `localhost`,
/// `127.0.0.1` and `[::1]`, nothing else (the strict reading of "local
/// hosts" in spec 6.1: no `*.localhost`, no `*.local`, no private range).
pub fn is_loopback(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "[::1]")
}

/// How well an item URL matches a page, best first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum UrlMatch {
    ExactHost,
    Domain,
    /// Another registrable domain known to share its credentials with the
    /// page's. Offered, never chosen for the user.
    Associated,
}

/// Match of an item URL under its rule against a page (spec 6.1, 7.3).
///
/// - `Domain`: same registrable domain (`ExactHost` when the hosts are
///   equal), else an associated domain (`https` on both sides only).
/// - `ExactHost`: same host.
/// - `ExactUrl`: same origin (scheme, host, port) and same path; query and
///   fragment are ignored by the parsers.
/// - `Never`: never.
///
/// A port written in the item URL must equal the page's. On a loopback
/// page the ports are always compared, the scheme's own when none is
/// written: each loopback port is another program, and an item saved for
/// `localhost` is not every one of them. A page that is not `fillable_page`
/// matches nothing.
pub fn matches(item: &UrlParts, rule: MatchRule, page: &UrlParts) -> Option<UrlMatch> {
    if rule == MatchRule::Never || !page.fillable_page() {
        return None;
    }
    let item_port = match item.port {
        None if is_loopback(&page.host) => Some(item.effective_port()),
        written => written,
    };
    if let Some(p) = item_port
        && p != page.effective_port()
    {
        return None;
    }
    let same_host = item.host == page.host;
    match rule {
        MatchRule::Never => None,
        MatchRule::ExactHost => same_host.then_some(UrlMatch::ExactHost),
        MatchRule::ExactUrl => {
            (item.same_origin(page) && !page.path.is_empty() && item.path == page.path)
                .then_some(UrlMatch::ExactHost)
        }
        MatchRule::Domain => {
            if same_host {
                Some(UrlMatch::ExactHost)
            } else if item.site() == page.site() {
                Some(UrlMatch::Domain)
            } else if associated(item, page) {
                Some(UrlMatch::Associated)
            } else {
                None
            }
        }
    }
}

/// Best match of an item's URLs on a page, with the URL that gave it (the
/// first of the best tier). `parse` reads an item URL (a bare host is
/// `https`).
///
/// The associated tier is the weakest and the most guarded:
/// - an item holding any URL on the page's own site, whatever its rule and
///   whether it matches, never gets it there: that URL rules alone, and a
///   URL of another site never widens it (`has_url_on_site`);
/// - it becomes a `Domain` match only on a host where the user picked the
///   item while it was offered as associated (`Item::
///   picked_as_associated_on`): any other memory of the site proves
///   nothing, and a pick on one host says nothing of the site's other hosts.
pub fn item_match<'a>(
    item: &'a Item,
    page: &UrlParts,
    parse: impl Fn(&str) -> Option<UrlParts>,
) -> Option<(UrlMatch, &'a ItemUrl)> {
    let (q, url) = item
        .urls
        .iter()
        .filter_map(|u| matches(&parse(&u.url)?, u.rule, page).map(|q| (q, u)))
        .min_by_key(|(q, _)| *q)?;
    if q != UrlMatch::Associated {
        return Some((q, url));
    }
    if has_url_on_site(item, page, parse) {
        return None;
    }
    if item.picked_as_associated_on(&page.host) {
        return Some((UrlMatch::Domain, url));
    }
    Some((UrlMatch::Associated, url))
}

/// Does the item hold a URL on the page's registrable domain, whatever its
/// rule? Such an item is never an associated match on that site.
pub fn has_url_on_site(
    item: &Item,
    page: &UrlParts,
    parse: impl Fn(&str) -> Option<UrlParts>,
) -> bool {
    let site = page.site();
    item.urls
        .iter()
        .filter_map(|u| parse(&u.url))
        .any(|u| u.ip == page.ip && u.site() == site)
}

fn associated(item: &UrlParts, page: &UrlParts) -> bool {
    item.scheme == Scheme::Https
        && page.scheme == Scheme::Https
        && !item.ip
        && !page.ip
        && associations().allows(&item.site(), &page.site())
}

/// Which registrable domains share their credentials (Apple's
/// `shared-credentials.json`).
#[derive(Debug, Default)]
pub struct Associations {
    /// Site an item was saved on, to the other sites it may be offered on.
    offers: HashMap<String, HashSet<String>>,
}

/// A domain of the list we can map safely: lowercase ASCII and its own
/// registrable domain. A subdomain is dropped, never widened to its site.
fn usable(domain: &str) -> bool {
    !domain.is_empty()
        && domain
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
        && psl::domain_str(domain) == Some(domain)
}

fn domains(v: Option<&serde_json::Value>) -> Vec<&str> {
    v.and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|d| d.as_str())
                .filter(|d| usable(d))
                .collect()
        })
        .unwrap_or_default()
}

impl Associations {
    /// Reads the list. A `shared` group works in both directions; a
    /// `from`/`to` entry offers a credential saved on a `from` domain on
    /// the `to` domains only. An entry of another shape, and a domain that
    /// is not `usable`, are ignored. A malformed file gives an empty table.
    pub fn parse(json: &str) -> Associations {
        let mut offers: HashMap<String, HashSet<String>> = HashMap::new();
        let entries: Vec<serde_json::Map<String, serde_json::Value>> =
            serde_json::from_str(json).unwrap_or_default();
        let mut add = |from: &str, to: &str| {
            if from != to {
                offers
                    .entry(from.to_owned())
                    .or_default()
                    .insert(to.to_owned());
            }
        };
        for e in &entries {
            let keys: Vec<&str> = e.keys().map(String::as_str).collect();
            let one_way = e.contains_key("from")
                && e.contains_key("to")
                && keys
                    .iter()
                    .all(|k| matches!(*k, "from" | "to" | "fromDomainsAreObsoleted"));
            if keys == ["shared"] {
                let group = domains(e.get("shared"));
                for a in &group {
                    for b in &group {
                        add(a, b);
                    }
                }
            } else if one_way {
                for a in domains(e.get("from")) {
                    for b in domains(e.get("to")) {
                        add(a, b);
                    }
                }
            }
        }
        Associations { offers }
    }

    /// May a credential saved on `saved_on` be offered on `page`? Both are
    /// registrable domains. Never true for the same site, never transitive.
    pub fn allows(&self, saved_on: &str, page: &str) -> bool {
        self.offers
            .get(saved_on)
            .is_some_and(|to| to.contains(page))
    }

    /// Sites with at least one associated site.
    pub fn len(&self) -> usize {
        self.offers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.offers.is_empty()
    }
}

/// The embedded list, parsed once.
pub fn associations() -> &'static Associations {
    static TABLE: OnceLock<Associations> = OnceLock::new();
    TABLE.get_or_init(|| Associations::parse(SHARED_CREDENTIALS))
}

/// Splits an explicit scheme off: `http` in `http://x`. A `://` inside a
/// path or a query is not a scheme separator.
pub fn split_scheme(s: &str) -> Option<(&str, &str)> {
    let i = s.find("://")?;
    let scheme = s.get(..i)?;
    if scheme.contains(['/', '?', '#']) {
        return None;
    }
    Some((scheme, s.get(i + 3..)?))
}

/// A strict parser for callers without a URL library: `scheme://host[:port]
/// [/path]`. Without a scheme, `bare_is_https` reads the value as `https`
/// (items may store a bare host), else it is refused. User info, non ASCII
/// hosts (give the punycode form) and malformed ports are refused. Nothing
/// is normalized beyond case and the default port, so a path with a
/// backslash is left empty.
pub fn parse_ascii(s: &str, bare_is_https: bool) -> Option<UrlParts> {
    let s = s.trim();
    let (scheme, rest) = match split_scheme(s) {
        Some((scheme, rest)) => (Scheme::parse(scheme)?, rest),
        None if bare_is_https => (Scheme::Https, s),
        None => return None,
    };
    let end = rest.find(['/', '?', '#', '\\']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at_checked(end)?;
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
        let (h, p) = authority.split_at_checked(i)?;
        (h.to_owned(), p)
    };
    let port = match port.strip_prefix(':') {
        None if port.is_empty() => None,
        None => return None,
        Some("") => None,
        Some(p) => Some(p.parse::<u16>().ok()?),
    };
    let port = port.filter(|&p| p != scheme.default_port());
    let v6 = host.starts_with('[');
    let host = if v6 {
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
    let ip = v6 || host.bytes().all(|b| b.is_ascii_digit() || b == b'.');
    let path_end = tail.find(['?', '#']).unwrap_or(tail.len());
    let path = match tail.get(..path_end)? {
        "" => "/".to_owned(),
        p if p.contains('\\') => String::new(),
        p => p.to_owned(),
    };
    Some(UrlParts {
        scheme,
        host,
        port,
        path,
        ip,
    })
}

/// Are two origins as the browser reports them (`scheme://host[:port]`)
/// the same origin? False when either does not parse.
pub fn same_origin(a: &str, b: &str) -> bool {
    match (parse_ascii(a, false), parse_ascii(b, false)) {
        (Some(a), Some(b)) => a.same_origin(&b),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> UrlParts {
        parse_ascii(s, true).unwrap()
    }

    fn m(item: &str, rule: MatchRule, page: &str) -> Option<UrlMatch> {
        matches(&p(item), rule, &p(page))
    }

    #[test]
    fn domain_host_and_never() {
        let page = "https://app.atlas-cloud.test/login";
        assert_eq!(
            m("atlas-cloud.test", MatchRule::Domain, page),
            Some(UrlMatch::Domain)
        );
        assert_eq!(
            m("https://app.atlas-cloud.test", MatchRule::Domain, page),
            Some(UrlMatch::ExactHost)
        );
        assert_eq!(m("atlas-cloud.test", MatchRule::ExactHost, page), None);
        assert_eq!(
            m("app.atlas-cloud.test", MatchRule::ExactHost, page),
            Some(UrlMatch::ExactHost)
        );
        assert_eq!(m("app.atlas-cloud.test", MatchRule::Never, page), None);
        assert_eq!(
            m(
                "atlas-cloud.test",
                MatchRule::Domain,
                "https://atlas-cloud.test.evil.test"
            ),
            None
        );
        assert_eq!(
            m("x.github.io", MatchRule::Domain, "https://y.github.io"),
            None
        );
    }

    #[test]
    fn a_written_port_must_be_the_pages() {
        let item = "https://atlas-cloud.test:8443";
        for rule in [MatchRule::Domain, MatchRule::ExactHost] {
            assert_eq!(
                m(item, rule, "https://atlas-cloud.test:8443/x"),
                Some(UrlMatch::ExactHost)
            );
            assert_eq!(m(item, rule, "https://atlas-cloud.test/x"), None);
            assert_eq!(m(item, rule, "https://atlas-cloud.test:9443/x"), None);
        }
        // No port in the item: any page port.
        assert_eq!(
            m(
                "atlas-cloud.test",
                MatchRule::ExactHost,
                "https://atlas-cloud.test:8443"
            ),
            Some(UrlMatch::ExactHost)
        );
        // The default port of each scheme is no written port.
        assert_eq!(
            m(
                "https://atlas-cloud.test:443",
                MatchRule::Domain,
                "https://atlas-cloud.test"
            ),
            Some(UrlMatch::ExactHost)
        );
    }

    #[test]
    fn exact_url_is_origin_and_path() {
        let item = "https://atlas-cloud.test/login?a=1";
        let rule = MatchRule::ExactUrl;
        assert_eq!(
            m(item, rule, "https://atlas-cloud.test/login?next=/x#top"),
            Some(UrlMatch::ExactHost)
        );
        assert_eq!(m(item, rule, "https://atlas-cloud.test/other"), None);
        assert_eq!(m(item, rule, "https://atlas-cloud.test"), None);
        assert_eq!(m(item, rule, "https://atlas-cloud.test:8443/login"), None);
        assert_eq!(m(item, rule, "https://app.atlas-cloud.test/login"), None);
        // An http item is another origin than the https page.
        assert_eq!(
            m(
                "http://atlas-cloud.test/login",
                rule,
                "https://atlas-cloud.test/login"
            ),
            None
        );
        // A path the parser could not vouch for equals none.
        let mut page = p("https://atlas-cloud.test/login");
        page.path = String::new();
        let mut blank = p(item);
        blank.path = String::new();
        assert_eq!(matches(&blank, rule, &page), None);
    }

    #[test]
    fn http_pages_only_on_loopback() {
        for page in [
            "http://localhost:3000/login",
            "http://127.0.0.1:3000/login",
            "http://[::1]:3000/login",
        ] {
            let host = p(page).host;
            assert_eq!(
                m(&format!("http://{host}:3000"), MatchRule::Domain, page),
                Some(UrlMatch::ExactHost),
                "{page}"
            );
            // The item's scheme is not compared outside `ExactUrl`.
            assert_eq!(
                m(&format!("{host}:3000"), MatchRule::ExactHost, page),
                Some(UrlMatch::ExactHost),
                "{page}"
            );
            // Another port is another program.
            assert_eq!(
                m(&format!("http://{host}:8080"), MatchRule::Domain, page),
                None,
                "{page}"
            );
            assert_eq!(
                m(
                    &format!("http://{host}:3000/login"),
                    MatchRule::ExactUrl,
                    page
                ),
                Some(UrlMatch::ExactHost),
                "{page}"
            );
            assert_eq!(
                m(&format!("{host}:3000/login"), MatchRule::ExactUrl, page),
                None,
                "{page}"
            );
        }
        for page in [
            "http://atlas-cloud.test/login",
            "http://app.localhost:3000",
            "http://nas.local",
            "http://127.0.0.2",
            "http://192.168.1.10",
            "http://localhost.evil.test",
        ] {
            let host = p(page).host;
            assert!(!p(page).fillable_page(), "{page}");
            for item in [format!("http://{host}"), host.clone()] {
                assert_eq!(m(&item, MatchRule::Domain, page), None, "{page}");
                assert_eq!(m(&item, MatchRule::ExactHost, page), None, "{page}");
            }
        }
        // An http item still matches the https page of its host.
        assert_eq!(
            m(
                "http://atlas-cloud.test",
                MatchRule::Domain,
                "https://atlas-cloud.test"
            ),
            Some(UrlMatch::ExactHost)
        );
    }

    const LIST: &str = r#"[
        {"shared": ["alpha.test", "beta.test", "gamma.co.uk"]},
        {"from": ["old.test"], "to": ["new.test"], "fromDomainsAreObsoleted": true},
        {"from": ["one.test"], "to": ["two.test", "three.test"]},
        {"shared": ["login.sub.test", "solo.test"]},
        {"shared": ["x.test", "y.test"], "to": ["z.test"]},
        {"from": ["q.test"], "to": ["r.test"], "surprise": 1},
        {"from": ["UPPER.test", "bücher.test", "co.uk"], "to": ["new.test"]}
    ]"#;

    #[test]
    fn shared_groups_work_both_ways() {
        let t = Associations::parse(LIST);
        assert!(t.allows("alpha.test", "beta.test"));
        assert!(t.allows("beta.test", "alpha.test"));
        assert!(t.allows("gamma.co.uk", "alpha.test"));
        assert!(!t.allows("alpha.test", "alpha.test"));
        assert!(!t.allows("alpha.test", "new.test"));
    }

    #[test]
    fn from_to_is_one_way() {
        let t = Associations::parse(LIST);
        assert!(t.allows("old.test", "new.test"));
        assert!(!t.allows("new.test", "old.test"));
        assert!(t.allows("one.test", "two.test"));
        assert!(t.allows("one.test", "three.test"));
        // The `to` domains of one entry are not associated with each other.
        assert!(!t.allows("two.test", "three.test"));
        assert!(!t.allows("two.test", "one.test"));
    }

    #[test]
    fn what_cannot_be_mapped_is_ignored() {
        let t = Associations::parse(LIST);
        // A subdomain is dropped, never widened to its registrable domain.
        assert!(!t.allows("solo.test", "sub.test"));
        assert!(!t.allows("sub.test", "solo.test"));
        assert!(!t.allows("solo.test", "login.sub.test"));
        // An entry of an unknown shape.
        assert!(!t.allows("x.test", "y.test"));
        assert!(!t.allows("x.test", "z.test"));
        assert!(!t.allows("q.test", "r.test"));
        // Upper case, non ASCII, a public suffix.
        assert!(!t.allows("upper.test", "new.test"));
        assert!(!t.allows("co.uk", "new.test"));
        assert!(Associations::parse("not json").is_empty());
        assert!(Associations::parse("{}").is_empty());
    }

    #[test]
    fn embedded_list_parses() {
        let t = associations();
        assert!(t.len() > 100, "{}", t.len());
        // One-way: a2hosting.com became hosting.com.
        assert!(t.allows("a2hosting.com", "hosting.com"));
        assert!(!t.allows("hosting.com", "a2hosting.com"));
        // Shared, on a multi-label suffix too.
        assert!(t.allows("ad.nl", "dpgmedia.nl"));
        assert!(t.allows("dpgmedia.nl", "ad.nl"));
        assert!(t.allows("airbnb.com.ar", "airbnb.co.cr"));
    }

    #[test]
    fn associated_tier_is_for_domain_rule_and_https_only() {
        let page = "https://my.hosting.com/login";
        assert_eq!(
            m("https://www.a2hosting.com", MatchRule::Domain, page),
            Some(UrlMatch::Associated)
        );
        assert_eq!(
            m("a2hosting.com", MatchRule::Domain, page),
            Some(UrlMatch::Associated)
        );
        // One way only.
        assert_eq!(
            m("hosting.com", MatchRule::Domain, "https://a2hosting.com"),
            None
        );
        // Never for a narrower rule, nor over http, nor past a written port.
        assert_eq!(m("a2hosting.com", MatchRule::ExactHost, page), None);
        assert_eq!(m("a2hosting.com/login", MatchRule::ExactUrl, page), None);
        assert_eq!(m("a2hosting.com", MatchRule::Never, page), None);
        assert_eq!(m("http://a2hosting.com", MatchRule::Domain, page), None);
        assert_eq!(m("a2hosting.com:8443", MatchRule::Domain, page), None);
        // Both directions of a shared group.
        assert_eq!(
            m("ad.nl", MatchRule::Domain, "https://login.dpgmedia.nl"),
            Some(UrlMatch::Associated)
        );
        assert_eq!(
            m("dpgmedia.nl", MatchRule::Domain, "https://www.ad.nl"),
            Some(UrlMatch::Associated)
        );
    }

    fn login(urls: &[(&str, MatchRule)]) -> Item {
        let mut i = crate::model::new_item(crate::model::ItemType::Login, crate::Id::new(), "L");
        for (url, rule) in urls {
            i.urls.push(ItemUrl {
                label: String::new(),
                url: (*url).into(),
                rule: *rule,
                primary: false,
            });
        }
        i
    }

    fn used(item: &mut Item, key: &str) {
        let now = time::OffsetDateTime::UNIX_EPOCH + time::Duration::days(20_000);
        item.note_usage(
            crate::model::usage::SiteUsage {
                site: key.into(),
                form_shape_hash: [0; 16],
                intent: crate::fill_plan::intent::Intent::Login,
                step_seq: vec![],
                count: 1,
                last_at: now,
            },
            now,
        );
    }

    fn im(item: &Item, page: &str) -> Option<UrlMatch> {
        item_match(item, &p(page), |u| parse_ascii(u, true)).map(|(q, _)| q)
    }

    #[test]
    fn a_url_on_the_pages_own_site_rules_alone() {
        // The review's case: an exact host URL on hosting.com and a domain
        // URL on a2hosting.com (which the list offers on hosting.com). The
        // second never widens the first to the rest of hosting.com.
        let mut item = login(&[
            ("https://login.hosting.com", MatchRule::ExactHost),
            ("https://www.a2hosting.com", MatchRule::Domain),
        ]);
        assert_eq!(
            im(&item, "https://login.hosting.com"),
            Some(UrlMatch::ExactHost)
        );
        assert_eq!(im(&item, "https://x.hosting.com"), None);
        // Used on its own host: the site's memory changes nothing elsewhere.
        used(&mut item, "hosting.com");
        assert_eq!(im(&item, "https://x.hosting.com"), None);
        // Even a `never` URL of the site says the user ruled on it.
        let never = login(&[
            ("https://hosting.com", MatchRule::Never),
            ("https://www.a2hosting.com", MatchRule::Domain),
        ]);
        assert_eq!(im(&never, "https://my.hosting.com"), None);
        // Without a URL of its own there, the associated tier stands.
        let plain = login(&[("https://www.a2hosting.com", MatchRule::Domain)]);
        assert_eq!(
            im(&plain, "https://my.hosting.com"),
            Some(UrlMatch::Associated)
        );
    }

    #[test]
    fn only_a_pick_through_the_associated_tier_promotes() {
        use crate::model::usage::associated_pick_key;
        let mut item = login(&[("https://www.a2hosting.com", MatchRule::Domain)]);
        let page = "https://my.hosting.com/login";
        assert_eq!(im(&item, page), Some(UrlMatch::Associated));
        // Any memory of the site is not a pick: the item could have earned
        // it through another URL it no longer has.
        used(&mut item, "hosting.com");
        assert_eq!(im(&item, page), Some(UrlMatch::Associated));
        // The pick, on this host: a domain match from now on, here.
        used(&mut item, &associated_pick_key("my.hosting.com"));
        assert!(item.picked_as_associated_on("my.hosting.com"));
        assert_eq!(im(&item, page), Some(UrlMatch::Domain));
        // Forgetting the site forgets the pick.
        let now = time::OffsetDateTime::UNIX_EPOCH + time::Duration::days(20_001);
        assert!(item.forget_site_usage("hosting.com", now));
        assert!(!item.picked_as_associated_on("my.hosting.com"));
        assert!(item.usage.is_empty(), "{:?}", item.usage);
        assert_eq!(im(&item, page), Some(UrlMatch::Associated));
    }

    #[test]
    fn a_pick_on_one_host_of_a_shared_suffix_promotes_no_other_host() {
        // `to` domains that host third parties under their subdomains
        // (fandom.com wikis, mwn.de members): the list cannot tell them
        // apart, so a pick counts for the host it was made on only.
        let mut wiki = login(&[("https://www.wikia.com", MatchRule::Domain)]);
        used(
            &mut wiki,
            &crate::model::usage::associated_pick_key("cats.fandom.com"),
        );
        used(&mut wiki, "fandom.com");
        assert_eq!(im(&wiki, "https://cats.fandom.com"), Some(UrlMatch::Domain));
        assert_eq!(
            im(&wiki, "https://evil.fandom.com"),
            Some(UrlMatch::Associated)
        );
        assert_eq!(im(&wiki, "https://fandom.com"), Some(UrlMatch::Associated));
        let mut tum = login(&[("https://campus.tum.de", MatchRule::Domain)]);
        used(
            &mut tum,
            &crate::model::usage::associated_pick_key("idp.mwn.de"),
        );
        assert_eq!(im(&tum, "https://idp.mwn.de"), Some(UrlMatch::Domain));
        assert_eq!(
            im(&tum, "https://someone.mwn.de"),
            Some(UrlMatch::Associated)
        );
    }

    #[test]
    fn a_loopback_page_is_matched_on_its_port_always() {
        // No port written is the scheme's own port, never "any port": each
        // loopback port is another program.
        for host in ["localhost", "127.0.0.1", "[::1]"] {
            let page = format!("http://{host}:3000/login");
            for item in [format!("http://{host}"), host.to_owned()] {
                for rule in [MatchRule::Domain, MatchRule::ExactHost] {
                    assert_eq!(m(&item, rule, &page), None, "{item} on {page}");
                }
            }
            // `http://host` is port 80, a bare host (https) port 443.
            assert_eq!(
                m(
                    &format!("http://{host}"),
                    MatchRule::Domain,
                    &format!("http://{host}/")
                ),
                Some(UrlMatch::ExactHost)
            );
            assert_eq!(
                m(host, MatchRule::Domain, &format!("https://{host}/")),
                Some(UrlMatch::ExactHost)
            );
            assert_eq!(m(host, MatchRule::Domain, &format!("http://{host}/")), None);
            assert_eq!(
                m(&format!("http://{host}:3000"), MatchRule::Domain, &page),
                Some(UrlMatch::ExactHost)
            );
        }
        // Elsewhere an item without a port still matches any port.
        assert_eq!(
            m(
                "atlas-cloud.test",
                MatchRule::Domain,
                "https://atlas-cloud.test:8443"
            ),
            Some(UrlMatch::ExactHost)
        );
    }

    #[test]
    fn strict_parser_refuses_what_it_cannot_read() {
        let h = parse_ascii("https://Accounts.Example.co.uk:443/x?y#z", false).unwrap();
        assert_eq!(h.site(), "example.co.uk");
        assert_eq!(h.origin(), "https://accounts.example.co.uk");
        assert_eq!(h.path, "/x");
        assert_eq!(p("example.com").path, "/");
        assert_eq!(p("example.com?q").path, "/");
        assert_eq!(p("example.com\\x").path, "");
        assert_eq!(p("http://localhost:80/").port, None);
        assert_eq!(p("http://localhost:443/").port, Some(443));
        // A `://` in a query is not a scheme separator.
        let q = p("example.com/p?next=https://evil.test");
        assert_eq!((q.host.as_str(), q.path.as_str()), ("example.com", "/p"));
        assert!(parse_ascii("example.com", false).is_none());
        for bad in [
            "https://user@example.com",
            "https://example.com:99999",
            "https://",
            "https://ex\u{e4}mple.com",
            "ftp://example.com",
            "https://[::1]x",
        ] {
            assert!(parse_ascii(bad, true).is_none(), "{bad}");
        }
    }

    #[test]
    fn same_origin_is_scheme_host_port() {
        assert!(same_origin("https://a.test", "https://a.test"));
        assert!(same_origin("https://a.test:443", "https://A.test/"));
        assert!(same_origin(
            "http://localhost:3000",
            "http://localhost:3000"
        ));
        assert!(!same_origin("https://a.test", "https://b.a.test"));
        assert!(!same_origin("https://a.test", "https://a.test:8443"));
        assert!(!same_origin("https://a.test", "http://a.test"));
        assert!(!same_origin("https://a.test", "null"));
        assert!(!same_origin("", ""));
        assert!(!same_origin("a.test", "a.test"));
    }
}
