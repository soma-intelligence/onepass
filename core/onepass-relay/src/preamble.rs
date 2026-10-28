//! The opening frame a client sends on the socket before any envelope.

use serde::{Deserialize, Serialize};

/// Longest extension id accepted (a Chrome id is 32 letters, a Firefox id
/// an email-like or braced GUID string).
pub const MAX_EXTENSION_ID: usize = 128;

/// `{"onepass_relay":1}` from Safari, `{"onepass_relay":1,"extension":"<id>"}`
/// from the relay, where the id is the one the browser passed on the
/// command line. Informative only: a local process can lie about it; the
/// pairing is the guard.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Preamble {
    pub onepass_relay: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extension: Option<String>,
}

impl Preamble {
    pub const VERSION: u8 = 1;

    pub fn new(extension: Option<String>) -> Preamble {
        Preamble {
            onepass_relay: Self::VERSION,
            extension,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    /// Strict parse: version 1, no unknown key, an extension id that is
    /// short, printable ASCII and not empty.
    pub fn parse(bytes: &[u8]) -> Option<Preamble> {
        let p: Preamble = serde_json::from_slice(bytes).ok()?;
        if p.onepass_relay != Self::VERSION {
            return None;
        }
        if let Some(id) = &p.extension
            && (id.is_empty()
                || id.len() > MAX_EXTENSION_ID
                || !id.bytes().all(|b| b.is_ascii_graphic()))
        {
            return None;
        }
        Some(p)
    }
}

/// The calling extension's id from the browser's launch arguments. Chrome
/// passes its origin `chrome-extension://<id>/`; Firefox passes the
/// manifest path then the add-on id. Browser flags (`--parent-window=...`)
/// are skipped. Anything else gives `None`.
pub fn extension_from_args(args: &[String]) -> Option<String> {
    let positional: Vec<&String> = args.iter().filter(|a| !a.starts_with("--")).collect();
    let first = positional.first()?;
    if let Some(rest) = first.strip_prefix("chrome-extension://") {
        let id = rest.trim_end_matches('/');
        return (!id.is_empty() && !id.contains('/')).then(|| id.to_owned());
    }
    positional
        .get(1)
        .filter(|s| !s.is_empty())
        .map(|s| (*s).clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn round_trip_and_safari_form() {
        let p = Preamble::new(Some("abcdefghijklmnopabcdefghijklmnop".into()));
        assert_eq!(Preamble::parse(&p.to_bytes()), Some(p));
        let s = Preamble::new(None);
        assert_eq!(s.to_bytes(), br#"{"onepass_relay":1}"#);
        assert_eq!(Preamble::parse(br#"{"onepass_relay":1}"#), Some(s));
    }

    #[test]
    fn strict_parse() {
        for bad in [
            &br#"{"onepass_relay":2}"#[..],
            br#"{"onepass_relay":1,"x":1}"#,
            br#"{"onepass_relay":1,"extension":""}"#,
            br#"{"onepass_relay":1,"extension":"a b"}"#,
            br#"{"onepass_relay":1,"extension":7}"#,
            br#"{"v":1,"t":"hello"}"#,
            b"not json",
        ] {
            assert_eq!(
                Preamble::parse(bad),
                None,
                "{}",
                String::from_utf8_lossy(bad)
            );
        }
        let long = format!(r#"{{"onepass_relay":1,"extension":"{}"}}"#, "a".repeat(129));
        assert_eq!(Preamble::parse(long.as_bytes()), None);
    }

    #[test]
    fn extension_ids_from_browser_arguments() {
        assert_eq!(
            extension_from_args(&args(&[
                "chrome-extension://abcdefgh/",
                "--parent-window=0"
            ]))
            .as_deref(),
            Some("abcdefgh")
        );
        assert_eq!(
            extension_from_args(&args(&[
                "/x/me.somalabs.onepass.json",
                "onepass@somalabs.me"
            ]))
            .as_deref(),
            Some("onepass@somalabs.me")
        );
        assert_eq!(extension_from_args(&args(&["chrome-extension:///"])), None);
        assert_eq!(
            extension_from_args(&args(&["chrome-extension://a/b/"])),
            None
        );
        assert_eq!(extension_from_args(&args(&["/x/manifest.json"])), None);
        assert_eq!(extension_from_args(&[]), None);
    }
}
