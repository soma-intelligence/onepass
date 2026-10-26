//! Host of a URL, shared by Watchtower and the importers.

/// Longest host name kept (DNS limit).
pub const MAX_HOST_LEN: usize = 253;

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
}
