//! The opening frame a client sends on the socket before any envelope.

use serde::{Deserialize, Serialize};

use crate::launcher::MAX_LAUNCHER;

/// Longest extension id accepted (a Chrome id is 32 letters, a Firefox id
/// an email-like or braced GUID string).
pub const MAX_EXTENSION_ID: usize = 128;

/// `{"onepass_relay":1}` from Safari, `{"onepass_relay":1,"extension":"<id>"}`
/// from the relay, where the id is the one the browser passed on the
/// command line. The id alone is informative: any local process can launch
/// the relay with a false one. `launcher` is the code-signing client id of
/// the relay's parent process, verified by the relay
/// (`team:<team>:<identifier>`), present only when the parent is signed by a
/// team: the app pairs without a code only when it names a known browser
/// (`launcher::vouch`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Preamble {
    pub onepass_relay: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extension: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub launcher: Option<String>,
}

impl Preamble {
    pub const VERSION: u8 = 1;

    pub fn new(extension: Option<String>) -> Preamble {
        Preamble {
            onepass_relay: Self::VERSION,
            extension,
            launcher: None,
        }
    }

    /// The relay's opening frame, with its verified launcher if any.
    pub fn with_launcher(extension: String, launcher: Option<String>) -> Preamble {
        Preamble {
            onepass_relay: Self::VERSION,
            extension: Some(extension),
            launcher,
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
        let fits = |s: &str, max: usize| {
            !s.is_empty() && s.len() <= max && s.bytes().all(|b| b.is_ascii_graphic())
        };
        if p.extension
            .as_deref()
            .is_some_and(|id| !fits(id, MAX_EXTENSION_ID))
        {
            return None;
        }
        if p.launcher
            .as_deref()
            .is_some_and(|l| !fits(l, MAX_LAUNCHER))
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
    fn launcher_round_trip_and_strict() {
        let p = Preamble::with_launcher(
            "abc".into(),
            Some("team:EQHXZ8M8AV:com.google.Chrome".into()),
        );
        assert_eq!(
            p.to_bytes(),
            br#"{"onepass_relay":1,"extension":"abc","launcher":"team:EQHXZ8M8AV:com.google.Chrome"}"#
        );
        assert_eq!(Preamble::parse(&p.to_bytes()), Some(p));
        assert_eq!(
            Preamble::with_launcher("abc".into(), None).to_bytes(),
            br#"{"onepass_relay":1,"extension":"abc"}"#
        );
        for bad in [
            &br#"{"onepass_relay":1,"extension":"a","launcher":""}"#[..],
            br#"{"onepass_relay":1,"extension":"a","launcher":"a b"}"#,
            br#"{"onepass_relay":1,"extension":"a","launcher":1}"#,
        ] {
            assert_eq!(Preamble::parse(bad), None);
        }
        let long = format!(
            r#"{{"onepass_relay":1,"extension":"a","launcher":"{}"}}"#,
            "a".repeat(257)
        );
        assert_eq!(Preamble::parse(long.as_bytes()), None);
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
