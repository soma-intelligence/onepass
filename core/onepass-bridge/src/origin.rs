//! Page origins and item URL matching (spec 7.3).
//!
//! Hosts are compared in their ASCII (punycode) form, so an IDN lookalike
//! never equals the original. The registrable domain (eTLD+1) comes from
//! the Public Suffix List through the `psl` crate.

use onepass_core::model::MatchRule;
use url::{Host, Url};

use crate::{AppErrorCode, BridgeError, Result};

/// How well an item URL matches a page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchQuality {
    ExactHost,
    Domain,
}

/// A page origin given by the browser: `https` only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin {
    host: String,
    port: Option<u16>,
    path: String,
    ip: bool,
}

const HTTPS_PORT: u16 = 443;

fn invalid() -> BridgeError {
    BridgeError::App(AppErrorCode::Invalid)
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

impl Origin {
    /// Parse a page origin or URL. Anything but `https` is
    /// `insecure_origin`; an unparsable value or one without a host is
    /// `invalid`. Query and fragment are dropped.
    pub fn parse(s: &str) -> Result<Origin> {
        let url = Url::parse(s.trim()).map_err(|_| invalid())?;
        if url.scheme() != "https" {
            return Err(BridgeError::App(AppErrorCode::InsecureOrigin));
        }
        let (host, ip) = host_of(&url).ok_or_else(invalid)?;
        Ok(Origin {
            host,
            port: url.port(),
            path: url.path().to_owned(),
            ip,
        })
    }

    /// Lowercase ASCII host, without port.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Explicit non default port, if any.
    pub fn port(&self) -> Option<u16> {
        self.port
    }

    /// Path, `/` at least.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Registrable domain (eTLD+1), or the whole host when the PSL gives
    /// none (an address, a bare public suffix).
    pub fn site(&self) -> String {
        site_of(&self.host, self.ip)
    }

    /// `https://host[:port]`.
    pub fn origin_string(&self) -> String {
        match self.port {
            Some(p) => format!("https://{}:{p}", self.host),
            None => format!("https://{}", self.host),
        }
    }

    /// `https://host[:port]/path`, without query or fragment.
    pub fn url_string(&self) -> String {
        format!("{}{}", self.origin_string(), self.path)
    }
}

fn site_of(host: &str, ip: bool) -> String {
    if ip {
        return host.to_owned();
    }
    psl::domain_str(host).unwrap_or(host).to_owned()
}

/// An item URL. Items may store a bare host: it is read as `https`.
struct ItemUrl {
    scheme: String,
    host: String,
    port: Option<u16>,
    path: String,
    ip: bool,
}

fn parse_item_url(s: &str) -> Option<ItemUrl> {
    let s = s.trim();
    let url = if s.contains("://") {
        Url::parse(s).ok()?
    } else {
        Url::parse(&format!("https://{s}")).ok()?
    };
    if url.scheme() != "https" && url.scheme() != "http" {
        return None;
    }
    let (host, ip) = host_of(&url)?;
    Some(ItemUrl {
        scheme: url.scheme().to_owned(),
        host,
        port: url.port(),
        path: url.path().to_owned(),
        ip,
    })
}

/// Match of an item URL under its rule against a page (spec 7.3).
///
/// - `Domain`: same registrable domain (`ExactHost` quality when the hosts
///   are equal).
/// - `ExactHost`: same host.
/// - `ExactUrl`: same origin (an `http` item never matches) and same path;
///   query and fragment are ignored.
/// - `Never`: never.
///
/// A port written in the item URL must equal the page port.
pub fn matches(item_url: &str, rule: MatchRule, page: &Origin) -> Option<MatchQuality> {
    if rule == MatchRule::Never {
        return None;
    }
    let item = parse_item_url(item_url)?;
    if let Some(p) = item.port
        && p != page.port.unwrap_or(HTTPS_PORT)
    {
        return None;
    }
    let same_host = item.host == page.host;
    match rule {
        MatchRule::Never => None,
        MatchRule::ExactHost => same_host.then_some(MatchQuality::ExactHost),
        MatchRule::ExactUrl => (item.scheme == "https"
            && same_host
            && item.port == page.port
            && item.path == page.path)
            .then_some(MatchQuality::ExactHost),
        MatchRule::Domain => {
            if same_host {
                Some(MatchQuality::ExactHost)
            } else if site_of(&item.host, item.ip) == page.site() {
                Some(MatchQuality::Domain)
            } else {
                None
            }
        }
    }
}

/// Host of an item URL in lowercase ASCII, if it parses.
pub fn item_host(item_url: &str) -> Option<String> {
    parse_item_url(item_url).map(|u| u.host)
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
}
