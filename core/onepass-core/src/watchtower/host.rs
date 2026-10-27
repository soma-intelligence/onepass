//! Host of a URL, shared by Watchtower and the importers.

use std::net::{Ipv4Addr, Ipv6Addr};

/// Longest host name kept (DNS limit), the domain cap shared with import.
pub const MAX_HOST_LEN: usize = crate::import::limits::MAX_DOMAIN_LEN;

/// Scheme of `url` when it has an explicit, well-formed one (`http` in
/// `http://x`). A `://` inside a path or a query is not a scheme.
pub(crate) fn scheme_of(url: &str) -> Option<&str> {
    let (scheme, _) = url.trim().split_once("://")?;
    let mut chars = scheme.chars();
    let first_ok = chars.next().is_some_and(|c| c.is_ascii_alphabetic());
    let rest_ok = chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'));
    (first_ok && rest_ok).then_some(scheme)
}

/// Lower-cased host of a URL, without scheme, credentials or port. A
/// missing scheme is allowed. IPv6 literals keep their brackets; IDN hosts
/// are left as written. `None` when no host remains or it is longer than
/// [`MAX_HOST_LEN`].
pub fn host_of(url: &str) -> Option<String> {
    let s = url.trim();
    let rest = match scheme_of(s) {
        Some(scheme) => s.get(scheme.len() + 3..)?,
        None => s,
    };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = rest.get(..end)?;
    let host_port = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host = if host_port.starts_with('[') {
        host_port.get(..=host_port.find(']')?)?
    } else {
        host_port.split(':').next()?
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    (!host.is_empty() && host.len() <= MAX_HOST_LEN).then_some(host)
}

/// True for loopback and local network names, where plain `http` is not a
/// finding: `localhost`, `127.0.0.1`, `[::1]`, `*.local`, `*.localhost`.
pub fn is_local_host(h: &str) -> bool {
    let h = h.to_ascii_lowercase();
    matches!(h.as_str(), "localhost" | "127.0.0.1" | "[::1]")
        || h.ends_with(".local")
        || h.ends_with(".localhost")
}

/// Suffixes of names that only resolve on a private network.
const PRIVATE_SUFFIXES: [&str; 6] = [
    ".lan",
    ".home",
    ".internal",
    ".local",
    ".localhost",
    ".home.arpa",
];

fn is_private_v4(ip: Ipv4Addr) -> bool {
    let [a, b, ..] = ip.octets();
    a == 0
        || a == 10
        || a == 127
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 168)
        || (a == 169 && b == 254)
        || (a == 100 && (64..=127).contains(&b))
}

fn is_private_v6(ip: Ipv6Addr) -> bool {
    let first = ip.segments().first().copied().unwrap_or(0);
    ip.is_loopback()
        || ip.is_unspecified()
        || first & 0xffc0 == 0xfe80
        || first & 0xfe00 == 0xfc00
        || ip.to_ipv4_mapped().is_some_and(is_private_v4)
}

/// True for a host (as returned by [`host_of`]) that names a machine on a
/// private network, where no request may be sent: RFC 1918, shared
/// (100.64/10), link-local, loopback and `0.0.0.0/8` IPv4; bracketed IPv6
/// loopback, link-local (`fe80::/10`) and unique local (`fc00::/7`);
/// single-label names; names under `.lan`, `.home`, `.internal`, `.local`,
/// `.localhost`, `.home.arpa`. A dotted name whose last label is numeric
/// but is not a plain IPv4 address (`127.1`) is treated as private too.
pub(crate) fn is_private_host(h: &str) -> bool {
    let h = h.trim_end_matches('.').to_ascii_lowercase();
    if let Some(inner) = h.strip_prefix('[') {
        return inner
            .strip_suffix(']')
            .and_then(|i| i.parse::<Ipv6Addr>().ok())
            .is_none_or(is_private_v6);
    }
    if h == "localhost" || !h.contains('.') {
        return true;
    }
    if PRIVATE_SUFFIXES.iter().any(|s| h.ends_with(s)) {
        return true;
    }
    let last = h.rsplit('.').next().unwrap_or("");
    if !last.is_empty() && last.chars().all(|c| c.is_ascii_digit()) {
        return h.parse::<Ipv4Addr>().map_or(true, is_private_v4);
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_of_cases() {
        assert_eq!(
            host_of("https://User:pw@Example.COM:8443/x").as_deref(),
            Some("example.com")
        );
        assert_eq!(host_of("example.com/path").as_deref(), Some("example.com"));
        assert_eq!(host_of("http://[::1]:80").as_deref(), Some("[::1]"));
        assert_eq!(
            host_of("https://example.net?q#f").as_deref(),
            Some("example.net")
        );
        assert_eq!(host_of(""), None);
        assert_eq!(host_of("https://"), None);
        assert_eq!(host_of("Example.org.").as_deref(), Some("example.org"));
        // A `://` in the query is not a scheme separator.
        assert_eq!(
            host_of("example.com/a?next=https://example.org").as_deref(),
            Some("example.com")
        );
        let long = format!("https://{}.com", "a".repeat(MAX_HOST_LEN));
        assert_eq!(host_of(&long), None);
    }

    #[test]
    fn scheme_cases() {
        assert_eq!(scheme_of("HTTP://example.com"), Some("HTTP"));
        assert_eq!(scheme_of("example.com"), None);
        assert_eq!(scheme_of("example.com/a?u=http://x"), None);
        assert_eq!(scheme_of("://x"), None);
    }

    #[test]
    fn local_hosts() {
        for h in [
            "localhost",
            "127.0.0.1",
            "[::1]",
            "nas.local",
            "app.localhost",
            "LocalHost",
        ] {
            assert!(is_local_host(h), "{h}");
        }
        for h in ["example.com", "local", "notlocalhost", "127.0.0.2", "[::2]"] {
            assert!(!is_local_host(h), "{h}");
        }
    }

    #[test]
    fn private_hosts() {
        for h in [
            "10.0.0.1",
            "172.16.5.4",
            "172.31.255.255",
            "192.168.1.1",
            "100.64.0.1",
            "100.127.255.254",
            "169.254.10.10",
            "127.0.0.1",
            "0.0.0.0",
            "127.1",
            "[::1]",
            "[::]",
            "[fe80::1]",
            "[febf::1]",
            "[fc00::1]",
            "[fd12:3456::1]",
            "[::ffff:192.168.0.1]",
            "[not-an-ip]",
            "router",
            "localhost",
            "nas.lan",
            "box.home",
            "svc.internal",
            "printer.local",
            "app.localhost",
            "nas.home.arpa",
            "NAS.LAN",
        ] {
            assert!(is_private_host(h), "{h}");
        }
        for h in [
            "example.com",
            "8.8.8.8",
            "172.32.0.1",
            "172.15.0.1",
            "100.128.0.1",
            "192.169.0.1",
            "[2001:db8::1]",
            "[fec0::1]",
            "[::ffff:8.8.8.8]",
            "lan.example.com",
            "home.example.org",
        ] {
            assert!(!is_private_host(h), "{h}");
        }
    }
}
