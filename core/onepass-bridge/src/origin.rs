//! Page origins and item URL matching (spec 7.3).
//!
//! The rules live in `onepass_core::fill_plan::origin`, shared with the
//! system AutoFill and the MCP; this module reads pages and item URLs with
//! the `url` crate (WHATWG parsing, punycode hosts) and hands them over.
//! Hosts are compared in their ASCII (punycode) form, so an IDN lookalike
//! never equals the original. The registrable domain (eTLD+1) comes from
//! the Public Suffix List through the `psl` crate.

use onepass_core::fill_plan::origin as rules;
use onepass_core::fill_plan::origin::{Scheme, UrlMatch, UrlParts};
use onepass_core::model::{Item, MatchRule};
use url::{Host, Url};

use crate::{AppErrorCode, BridgeError, Result};

/// How well an item URL matches a page, best first.
///
/// On the wire (`Summary::match`) an associated match is sent as `domain`:
/// the extension's parsers refuse an unknown value and would drop the whole
/// list. The plan says it with the reason `associated_domain`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchQuality {
    ExactHost,
    Domain,
    /// A domain known to share its credentials with the page's, where the
    /// item was never used: offered in the menu, never filled unasked.
    #[serde(rename(serialize = "domain"), skip_deserializing)]
    Associated,
}

impl From<UrlMatch> for MatchQuality {
    fn from(m: UrlMatch) -> Self {
        match m {
            UrlMatch::ExactHost => MatchQuality::ExactHost,
            UrlMatch::Domain => MatchQuality::Domain,
            UrlMatch::Associated => MatchQuality::Associated,
        }
    }
}

/// A page origin given by the browser: `https`, or `http` on a loopback
/// host for `parse_page`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin {
    parts: UrlParts,
}

fn invalid() -> BridgeError {
    BridgeError::App(AppErrorCode::Invalid)
}

fn insecure() -> BridgeError {
    BridgeError::App(AppErrorCode::InsecureOrigin)
}

/// Host of a parsed URL in lowercase ASCII, and whether it is an address.
fn host_of(url: &Url) -> Option<(String, bool)> {
    match url.host()? {
        Host::Domain(d) => {
            let d = d.trim_end_matches('.').to_ascii_lowercase();
            (!d.is_empty()).then_some((d, false))
        }
        Host::Ipv4(a) => Some((a.to_string(), true)),
        Host::Ipv6(a) => Some((format!("[{a}]"), true)),
    }
}

/// The parts of a parsed `https` or `http` URL with a host.
fn parts_of(url: &Url) -> Option<UrlParts> {
    let scheme = Scheme::parse(url.scheme())?;
    let (host, ip) = host_of(url)?;
    Some(UrlParts {
        scheme,
        host,
        port: url.port(),
        path: url.path().to_owned(),
        ip,
    })
}

/// Reads an item URL, or what the system names a site by: a URL, or a bare
/// host read as `https`. Only `https` and `http` give parts.
pub fn parse_parts(s: &str) -> Option<UrlParts> {
    let s = s.trim();
    let url = if rules::split_scheme(s).is_some() {
        Url::parse(s).ok()?
    } else {
        Url::parse(&format!("https://{s}")).ok()?
    };
    parts_of(&url)
}

impl Origin {
    /// Parse a page origin or URL. Anything but `https` is
    /// `insecure_origin`; an unparsable value or one without a host is
    /// `invalid`. Query and fragment are dropped.
    pub fn parse(s: &str) -> Result<Origin> {
        let page = Origin::parse_page(s)?;
        if page.parts.scheme != Scheme::Https {
            return Err(insecure());
        }
        Ok(page)
    }

    /// `parse` for a page to list, plan or fill (spec 6.1): also `http` on
    /// a loopback host (`localhost`, `127.0.0.1`, `[::1]`). Every other
    /// `http` origin stays `insecure_origin`.
    pub fn parse_page(s: &str) -> Result<Origin> {
        let url = Url::parse(s.trim()).map_err(|_| invalid())?;
        let Some(scheme) = Scheme::parse(url.scheme()) else {
            return Err(insecure());
        };
        let parts = match parts_of(&url) {
            Some(p) => p,
            None if scheme == Scheme::Https => return Err(invalid()),
            None => return Err(insecure()),
        };
        if !parts.fillable_page() {
            return Err(insecure());
        }
        Ok(Origin { parts })
    }

    /// What the shared matcher compares.
    pub fn parts(&self) -> &UrlParts {
        &self.parts
    }

    /// Lowercase ASCII host, without port.
    pub fn host(&self) -> &str {
        &self.parts.host
    }

    /// Whether the host is an IP address.
    pub fn is_ip(&self) -> bool {
        self.parts.ip
    }

    /// Explicit non default port, if any.
    pub fn port(&self) -> Option<u16> {
        self.parts.port
    }

    /// Path, `/` at least.
    pub fn path(&self) -> &str {
        &self.parts.path
    }

    /// Registrable domain (eTLD+1), or the whole host when the PSL gives
    /// none (an address, a bare public suffix).
    pub fn site(&self) -> String {
        self.parts.site()
    }

    /// `scheme://host[:port]`.
    pub fn origin_string(&self) -> String {
        self.parts.origin()
    }

    /// `scheme://host[:port]/path`, without query or fragment.
    pub fn url_string(&self) -> String {
        format!("{}{}", self.origin_string(), self.parts.path)
    }
}

/// Match of an item URL under its rule against a page (spec 7.3), by the
/// shared `fill_plan::origin::matches`.
///
/// - `Domain`: same registrable domain (`ExactHost` quality when the hosts
///   are equal), else an associated domain (`Associated`).
/// - `ExactHost`: same host.
/// - `ExactUrl`: same origin (an `http` item never matches an `https`
///   page) and same path; query and fragment are ignored.
/// - `Never`: never.
///
/// A port written in the item URL must equal the page port; on a loopback
/// page the ports are always compared (the scheme's own when none is
/// written). An item URL may be a bare host: it is read as `https`.
pub fn matches(item_url: &str, rule: MatchRule, page: &Origin) -> Option<MatchQuality> {
    let item = parse_parts(item_url)?;
    rules::matches(&item, rule, &page.parts).map(MatchQuality::from)
}

/// Best match of any of the item URLs against the page
/// (`fill_plan::origin::item_match`): an item with a URL on the page's own
/// site is never an associated match there, and an associated match is a
/// `Domain` match only on a host where the user picked the item.
pub fn item_match(item: &Item, page: &Origin) -> Option<MatchQuality> {
    rules::item_match(item, &page.parts, parse_parts).map(|(q, _)| q.into())
}

/// Host of an item URL in lowercase ASCII, if it parses.
pub fn item_host(item_url: &str) -> Option<String> {
    parse_parts(item_url).map(|u| u.host)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page(s: &str) -> Origin {
        Origin::parse(s).unwrap()
    }

    #[test]
    fn domain_rule_matches_subdomain() {
        let p = page("https://app.atlas-cloud.test/login");
        assert_eq!(
            matches("https://atlas-cloud.test", MatchRule::Domain, &p),
            Some(MatchQuality::Domain)
        );
        let same = page("https://atlas-cloud.test/");
        assert_eq!(
            matches("https://atlas-cloud.test", MatchRule::Domain, &same),
            Some(MatchQuality::ExactHost)
        );
    }

    #[test]
    fn exact_host_rejects_subdomain() {
        let p = page("https://app.atlas-cloud.test");
        assert_eq!(
            matches("https://atlas-cloud.test", MatchRule::ExactHost, &p),
            None
        );
        let admin = page("https://admin.atlas-cloud.test/x");
        assert_eq!(
            matches(
                "https://admin.atlas-cloud.test",
                MatchRule::ExactHost,
                &admin
            ),
            Some(MatchQuality::ExactHost)
        );
    }

    #[test]
    fn exact_url_ignores_query_fragment() {
        let p = page("https://atlas-cloud.test/login?next=/home#top");
        assert_eq!(
            matches(
                "https://atlas-cloud.test/login?a=1",
                MatchRule::ExactUrl,
                &p
            ),
            Some(MatchQuality::ExactHost)
        );
        assert_eq!(
            matches("https://atlas-cloud.test/other", MatchRule::ExactUrl, &p),
            None
        );
        assert_eq!(
            matches("http://atlas-cloud.test/login", MatchRule::ExactUrl, &p),
            None
        );
    }

    #[test]
    fn never_never() {
        let p = page("https://atlas-cloud.test");
        assert_eq!(
            matches("https://atlas-cloud.test", MatchRule::Never, &p),
            None
        );
    }

    #[test]
    fn explicit_port_must_match() {
        let p = page("https://atlas-cloud.test:8443/");
        assert_eq!(
            matches("https://atlas-cloud.test:8443", MatchRule::Domain, &p),
            Some(MatchQuality::ExactHost)
        );
        let default = page("https://atlas-cloud.test/");
        assert_eq!(
            matches("https://atlas-cloud.test:8443", MatchRule::Domain, &default),
            None
        );
        // No port in the item: any page port.
        assert_eq!(
            matches("https://atlas-cloud.test", MatchRule::ExactHost, &p),
            Some(MatchQuality::ExactHost)
        );
    }

    #[test]
    fn http_page_rejected() {
        assert_eq!(
            Origin::parse("http://atlas-cloud.test"),
            Err(BridgeError::App(AppErrorCode::InsecureOrigin))
        );
        assert_eq!(
            Origin::parse("javascript:alert(1)"),
            Err(BridgeError::App(AppErrorCode::InsecureOrigin))
        );
        assert_eq!(
            Origin::parse("not a url"),
            Err(BridgeError::App(AppErrorCode::Invalid))
        );
    }

    #[test]
    fn lookalike_suffix_rejected() {
        let p = page("https://atlas-cloud.test.evil.test/login");
        assert_eq!(
            matches("https://atlas-cloud.test", MatchRule::Domain, &p),
            None
        );
        let typo = page("https://atlass-cloud.test/login");
        assert_eq!(
            matches("https://atlas-cloud.test", MatchRule::Domain, &typo),
            None
        );
    }

    #[test]
    fn idn_homograph_rejected() {
        // Cyrillic "а" (U+0430) in place of the Latin "a".
        let p = page("https://\u{430}tlas-cloud.test/");
        assert!(p.host().starts_with("xn--"), "{}", p.host());
        assert_eq!(
            matches("https://atlas-cloud.test", MatchRule::Domain, &p),
            None
        );
        assert_eq!(
            matches("https://atlas-cloud.test", MatchRule::ExactHost, &p),
            None
        );
    }

    #[test]
    fn psl_multi_label_suffix() {
        assert_eq!(page("https://a.example.co.uk").site(), "example.co.uk");
        assert_eq!(
            page("https://a.example.co.uk").site(),
            page("https://b.example.co.uk").site()
        );
        assert_ne!(
            page("https://x.github.io").site(),
            page("https://y.github.io").site()
        );
        assert_eq!(
            matches(
                "https://x.github.io",
                MatchRule::Domain,
                &page("https://y.github.io")
            ),
            None
        );
    }

    #[test]
    fn host_is_lowercase_and_origin_strings_are_canonical() {
        let p = page("HTTPS://App.Atlas-Cloud.TEST:443/Path?q#f");
        assert_eq!(p.host(), "app.atlas-cloud.test");
        assert_eq!(p.port(), None);
        assert_eq!(p.origin_string(), "https://app.atlas-cloud.test");
        assert_eq!(p.url_string(), "https://app.atlas-cloud.test/Path");
    }

    #[test]
    fn bare_host_item_url_is_https() {
        let p = page("https://atlas-cloud.test/");
        assert_eq!(
            matches("atlas-cloud.test", MatchRule::Domain, &p),
            Some(MatchQuality::ExactHost)
        );
    }

    #[test]
    fn loopback_http_is_a_page_and_nothing_else_is() {
        for (s, origin) in [
            ("http://localhost:3000/login?x", "http://localhost:3000"),
            ("http://LOCALHOST./", "http://localhost"),
            ("http://127.0.0.1:8080", "http://127.0.0.1:8080"),
            ("http://127.1", "http://127.0.0.1"),
            ("http://[::1]:5173/app", "http://[::1]:5173"),
            ("http://[0:0:0:0:0:0:0:1]", "http://[::1]"),
            ("http://localhost:80", "http://localhost"),
        ] {
            let p = Origin::parse_page(s).unwrap_or_else(|e| panic!("{s}: {e:?}"));
            assert_eq!(p.origin_string(), origin, "{s}");
            // Passkeys, password rules and the rest stay https only.
            assert_eq!(
                Origin::parse(s),
                Err(BridgeError::App(AppErrorCode::InsecureOrigin)),
                "{s}"
            );
        }
        for s in [
            "http://atlas-cloud.test",
            "http://app.localhost:3000",
            "http://localhost.evil.test",
            "http://nas.local",
            "http://127.0.0.2",
            "http://192.168.1.10",
            "http://10.0.0.1",
            "http://[::2]",
            "http://0.0.0.0",
            "ws://localhost:3000",
            "file:///etc/passwd",
            "javascript:alert(1)",
        ] {
            assert_eq!(
                Origin::parse_page(s),
                Err(BridgeError::App(AppErrorCode::InsecureOrigin)),
                "{s}"
            );
        }
        for s in ["not a url", "http://", "https://"] {
            assert_eq!(
                Origin::parse_page(s),
                Err(BridgeError::App(AppErrorCode::Invalid)),
                "{s}"
            );
        }
        assert_eq!(
            Origin::parse_page("https://atlas-cloud.test/x").map(|p| p.url_string()),
            Ok("https://atlas-cloud.test/x".to_owned())
        );
    }

    #[test]
    fn loopback_item_matches_its_port_only() {
        let p = Origin::parse_page("http://localhost:3000/login").unwrap();
        for item in ["http://localhost:3000", "localhost:3000"] {
            assert_eq!(
                matches(item, MatchRule::Domain, &p),
                Some(MatchQuality::ExactHost),
                "{item}"
            );
        }
        // No port written is the scheme's own, never every loopback port.
        for item in ["localhost", "http://localhost", "https://localhost"] {
            assert_eq!(matches(item, MatchRule::Domain, &p), None, "{item}");
        }
        assert_eq!(
            matches("http://localhost:8080", MatchRule::Domain, &p),
            None
        );
        assert_eq!(
            matches("http://localhost:3000/login", MatchRule::ExactUrl, &p),
            Some(MatchQuality::ExactHost)
        );
        // `ExactUrl` is an origin: the https item is not this http page.
        assert_eq!(
            matches("https://localhost:3000/login", MatchRule::ExactUrl, &p),
            None
        );
        assert_eq!(
            matches("http://127.0.0.1:3000", MatchRule::Domain, &p),
            None
        );
    }

    #[test]
    fn scheme_in_a_query_is_not_the_item_scheme() {
        let p = page("https://atlas-cloud.test/");
        assert_eq!(
            matches(
                "atlas-cloud.test/login?next=https://evil.test",
                MatchRule::Domain,
                &p
            ),
            Some(MatchQuality::ExactHost)
        );
        assert_eq!(
            item_host("atlas-cloud.test/p?next=https://evil.test").as_deref(),
            Some("atlas-cloud.test")
        );
    }

    #[test]
    fn associated_domain_is_its_own_tier() {
        // From Apple's list: a2hosting.com became hosting.com, one way.
        let p = page("https://my.hosting.com/login");
        assert_eq!(
            matches("https://www.a2hosting.com", MatchRule::Domain, &p),
            Some(MatchQuality::Associated)
        );
        assert_eq!(
            matches("https://www.a2hosting.com", MatchRule::ExactHost, &p),
            None
        );
        assert_eq!(
            matches(
                "https://hosting.com",
                MatchRule::Domain,
                &page("https://a2hosting.com")
            ),
            None
        );
        // Older extensions refuse an unknown `match`: sent as `domain`.
        assert_eq!(
            serde_json::to_string(&MatchQuality::Associated).unwrap(),
            "\"domain\""
        );
        assert_eq!(
            serde_json::from_str::<MatchQuality>("\"domain\"").unwrap(),
            MatchQuality::Domain
        );
        assert!(serde_json::from_str::<MatchQuality>("\"associated\"").is_err());
    }
}
