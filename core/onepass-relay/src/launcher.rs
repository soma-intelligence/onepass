//! Which browser launched the relay, and when the app may pair a browser
//! extension without a code (spec
//! `docs/superpowers/specs/2026-11-02-browser-auto-pairing-design.md`).
//!
//! The relay identifies its parent process by its code signature and sends
//! the verified identity in the opening frame (`launcher`). The app trusts
//! that statement because it checked the relay's own signature: the relay is
//! our hardened binary, it reports, it never decides. The app pairs without
//! a code only for Safari (its extension lives in the app's own signed
//! bundle) or for a known browser, signed by its publisher, that launched
//! the relay for an extension id the app serves.

use crate::rendezvous::{Client, SAFARI_EXTENSION_ID};

/// The two kinds of browser extension ids.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    /// Chrome, Edge, Brave: 32 letters `a` to `p`.
    Chromium,
    /// Firefox: an add-on id (`name@domain` or a braced GUID).
    Gecko,
}

/// A browser the relay may vouch for: its publisher's team, the exact
/// code-signing identifier of its main process, and the name the app shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Browser {
    pub team: &'static str,
    pub identifier: &'static str,
    pub name: &'static str,
    pub family: Family,
}

const fn b(
    team: &'static str,
    identifier: &'static str,
    name: &'static str,
    family: Family,
) -> Browser {
    Browser {
        team,
        identifier,
        name,
        family,
    }
}

const GOOGLE: &str = "EQHXZ8M8AV";
const MICROSOFT: &str = "UBF8T346G9";
const BRAVE: &str = "KL8N8XSYF4";
const MOZILLA: &str = "43AQ936H96";

/// Browsers whose publisher team is known for certain (ruling A2). Any
/// other browser, an unsigned Chromium among them, pairs with a code.
pub const BROWSERS: [Browser; 14] = [
    b(
        GOOGLE,
        "com.google.Chrome",
        "Google Chrome",
        Family::Chromium,
    ),
    b(
        GOOGLE,
        "com.google.Chrome.beta",
        "Google Chrome Beta",
        Family::Chromium,
    ),
    b(
        GOOGLE,
        "com.google.Chrome.dev",
        "Google Chrome Dev",
        Family::Chromium,
    ),
    b(
        GOOGLE,
        "com.google.Chrome.canary",
        "Google Chrome Canary",
        Family::Chromium,
    ),
    b(
        MICROSOFT,
        "com.microsoft.edgemac",
        "Microsoft Edge",
        Family::Chromium,
    ),
    b(
        MICROSOFT,
        "com.microsoft.edgemac.Beta",
        "Microsoft Edge Beta",
        Family::Chromium,
    ),
    b(
        MICROSOFT,
        "com.microsoft.edgemac.Dev",
        "Microsoft Edge Dev",
        Family::Chromium,
    ),
    b(
        MICROSOFT,
        "com.microsoft.edgemac.Canary",
        "Microsoft Edge Canary",
        Family::Chromium,
    ),
    b(BRAVE, "com.brave.Browser", "Brave", Family::Chromium),
    b(
        BRAVE,
        "com.brave.Browser.beta",
        "Brave Beta",
        Family::Chromium,
    ),
    b(
        BRAVE,
        "com.brave.Browser.nightly",
        "Brave Nightly",
        Family::Chromium,
    ),
    b(MOZILLA, "org.mozilla.firefox", "Firefox", Family::Gecko),
    b(
        MOZILLA,
        "org.mozilla.firefoxdeveloperedition",
        "Firefox Developer Edition",
        Family::Gecko,
    ),
    b(
        MOZILLA,
        "org.mozilla.nightly",
        "Firefox Nightly",
        Family::Gecko,
    ),
];

/// Name shown for a Safari pairing.
pub const SAFARI_NAME: &str = "Safari";
/// Longest `launcher` accepted in the opening frame.
pub const MAX_LAUNCHER: usize = 256;

/// The known browser whose client id (`team:<team>:<identifier>`, as
/// `onepass_peer::CodeIdentity::client_id` writes it) is `launcher`.
pub fn known_browser(launcher: &str) -> Option<&'static Browser> {
    let rest = launcher.strip_prefix("team:")?;
    let (team, identifier) = rest.split_once(':')?;
    BROWSERS
        .iter()
        .find(|b| b.team == team && b.identifier == identifier)
}

/// The family an extension id belongs to by its shape.
pub fn extension_family(id: &str) -> Family {
    if id.len() == 32 && id.bytes().all(|c| (b'a'..=b'p').contains(&c)) {
        Family::Chromium
    } else {
        Family::Gecko
    }
}

/// Whether the app pairs this connection without a code, and the browser
/// name it then records (verified, never the extension's own claim).
///
/// Safari: always, unless blocked. Relay: the launcher is a known browser,
/// the extension id is one the app serves, its shape fits the browser's
/// family, and the user did not revoke it. Anything else gives `None`: the
/// pairing needs the code and Touch ID, as before.
pub fn vouch(
    client: Client,
    extension_id: &str,
    launcher: Option<&str>,
    allowed: &[String],
    blocked: &[String],
) -> Option<&'static str> {
    if blocked.iter().any(|b| b == extension_id) {
        return None;
    }
    match client {
        Client::Safari => (extension_id == SAFARI_EXTENSION_ID).then_some(SAFARI_NAME),
        Client::Relay => {
            let browser = known_browser(launcher?)?;
            let served = allowed.iter().any(|a| a == extension_id);
            (served && extension_family(extension_id) == browser.family).then_some(browser.name)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHROME_EXT: &str = "abcdefghijklmnopabcdefghijklmnop";
    const FIREFOX_EXT: &str = "onepass@somalabs.me";

    fn allowed() -> Vec<String> {
        vec![CHROME_EXT.into(), FIREFOX_EXT.into()]
    }

    #[test]
    fn known_browsers_by_exact_team_and_identifier() {
        assert_eq!(
            known_browser("team:EQHXZ8M8AV:com.google.Chrome").map(|b| b.name),
            Some("Google Chrome")
        );
        assert_eq!(
            known_browser("team:43AQ936H96:org.mozilla.firefox").map(|b| b.family),
            Some(Family::Gecko)
        );
        for unknown in [
            // Right identifier, wrong team: someone else's "Chrome".
            "team:AAAAAAAAAA:com.google.Chrome",
            // Right team, another binary of the publisher.
            "team:EQHXZ8M8AV:com.google.Chrome.helper",
            "team:EQHXZ8M8AV:com.google.Chrome.extra",
            "platform:com.apple.Safari",
            "adhoc:0011",
            "team:EQHXZ8M8AV",
            "",
        ] {
            assert!(known_browser(unknown).is_none(), "{unknown}");
        }
    }

    #[test]
    fn every_browser_has_a_well_formed_team() {
        for b in BROWSERS {
            assert!(crate::rendezvous::is_team_id(b.team), "{}", b.identifier);
        }
    }

    #[test]
    fn extension_families_by_shape() {
        assert_eq!(extension_family(CHROME_EXT), Family::Chromium);
        assert_eq!(extension_family(FIREFOX_EXT), Family::Gecko);
        assert_eq!(extension_family("{8f2c-11}"), Family::Gecko);
        // 32 characters but outside a..p: not a Chrome id.
        assert_eq!(extension_family(&"z".repeat(32)), Family::Gecko);
    }

    #[test]
    fn safari_is_vouched_by_its_own_signature() {
        assert_eq!(
            vouch(Client::Safari, SAFARI_EXTENSION_ID, None, &[], &[]),
            Some("Safari")
        );
        assert_eq!(
            vouch(
                Client::Safari,
                SAFARI_EXTENSION_ID,
                None,
                &[],
                &["safari".into()]
            ),
            None
        );
    }

    #[test]
    fn relay_is_vouched_only_for_a_known_browser_and_a_served_id() {
        let chrome = Some("team:EQHXZ8M8AV:com.google.Chrome");
        let brave = Some("team:KL8N8XSYF4:com.brave.Browser");
        let firefox = Some("team:43AQ936H96:org.mozilla.firefox");
        assert_eq!(
            vouch(Client::Relay, CHROME_EXT, chrome, &allowed(), &[]),
            Some("Google Chrome")
        );
        assert_eq!(
            vouch(Client::Relay, CHROME_EXT, brave, &allowed(), &[]),
            Some("Brave")
        );
        assert_eq!(
            vouch(Client::Relay, FIREFOX_EXT, firefox, &allowed(), &[]),
            Some("Firefox")
        );
        // No verified launcher (an unknown parent, an unsigned Chromium).
        assert_eq!(
            vouch(Client::Relay, CHROME_EXT, None, &allowed(), &[]),
            None
        );
        assert_eq!(
            vouch(
                Client::Relay,
                CHROME_EXT,
                Some("adhoc:00ff"),
                &allowed(),
                &[]
            ),
            None
        );
        // An id the app does not serve.
        let other = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        assert_eq!(vouch(Client::Relay, other, chrome, &allowed(), &[]), None);
        // Crossed families: Firefox never passes a Chrome origin, nor Chrome
        // an add-on id.
        assert_eq!(
            vouch(Client::Relay, CHROME_EXT, firefox, &allowed(), &[]),
            None
        );
        assert_eq!(
            vouch(Client::Relay, FIREFOX_EXT, chrome, &allowed(), &[]),
            None
        );
        // Revoked by the user.
        assert_eq!(
            vouch(
                Client::Relay,
                CHROME_EXT,
                chrome,
                &allowed(),
                &[CHROME_EXT.into()]
            ),
            None
        );
        // The relay never speaks for Safari's id.
        assert_eq!(
            vouch(
                Client::Relay,
                SAFARI_EXTENSION_ID,
                chrome,
                &["safari".into()],
                &[]
            ),
            None
        );
    }
}
