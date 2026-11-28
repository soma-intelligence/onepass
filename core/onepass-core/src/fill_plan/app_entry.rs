//! App entries: a login item can name Mac apps by bundle ID. They are plain
//! `ItemUrl` values with the url `macapp://<bundle-id>`, so no schema change.

use crate::model::{Item, ItemUrl, MatchRule};

pub const APP_SCHEME: &str = "macapp";

/// The Mac browsers, by bundle id. A browser is never remembered as an
/// app: a `macapp://` entry for one would match every page it shows. Must
/// match FillKit's list (`apple/FillKit/Sources/FillKit/KnownBrowsers.swift`).
pub const KNOWN_BROWSERS: [&str; 25] = [
    "com.apple.Safari",
    "com.apple.SafariTechnologyPreview",
    "com.google.Chrome",
    "com.google.Chrome.beta",
    "com.google.Chrome.dev",
    "com.google.Chrome.canary",
    "org.chromium.Chromium",
    "com.microsoft.edgemac",
    "com.microsoft.edgemac.Beta",
    "com.microsoft.edgemac.Dev",
    "com.microsoft.edgemac.Canary",
    "com.brave.Browser",
    "com.brave.Browser.beta",
    "com.brave.Browser.nightly",
    "com.vivaldi.Vivaldi",
    "com.operasoftware.Opera",
    "com.operasoftware.OperaGX",
    "company.thebrowser.Browser",
    "com.kagi.kagimacOS",
    "org.mozilla.firefox",
    "org.mozilla.firefoxdeveloperedition",
    "org.mozilla.nightly",
    "org.torproject.torbrowser",
    "com.duckduckgo.macos.browser",
    "app.zen-browser.zen",
];

/// True for a bundle id of [`KNOWN_BROWSERS`], compared case-insensitively.
pub fn is_known_browser(bundle_id: &str) -> bool {
    KNOWN_BROWSERS
        .iter()
        .any(|b| b.eq_ignore_ascii_case(bundle_id))
}

/// 2 to 255 ASCII chars, at least two dot separated segments of
/// `[A-Za-z0-9-]`, no empty segment.
pub fn valid_bundle_id(id: &str) -> bool {
    if id.len() < 2 || id.len() > 255 {
        return false;
    }
    let mut segments = 0;
    for seg in id.split('.') {
        if seg.is_empty() || !seg.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
            return false;
        }
        segments += 1;
    }
    segments >= 2
}

pub fn app_entry_url(bundle_id: &str) -> Option<String> {
    valid_bundle_id(bundle_id).then(|| format!("{APP_SCHEME}://{bundle_id}"))
}

fn entry_bundle_id(url: &str) -> Option<&str> {
    url.strip_prefix(APP_SCHEME)?.strip_prefix("://")
}

/// True when the item has a usable app entry for this bundle ID (compared
/// case-insensitively). Entries with the `Never` rule do not count.
pub fn matches_app(item: &Item, bundle_id: &str) -> bool {
    valid_bundle_id(bundle_id)
        && item.urls.iter().any(|u| {
            u.rule != MatchRule::Never
                && entry_bundle_id(&u.url).is_some_and(|b| b.eq_ignore_ascii_case(bundle_id))
        })
}

/// Appends an app entry. False when the bundle ID is invalid or the item
/// already has an entry for it (any rule).
pub fn add_app_entry(item: &mut Item, bundle_id: &str, label: &str) -> bool {
    let Some(url) = app_entry_url(bundle_id) else {
        return false;
    };
    let present = item
        .urls
        .iter()
        .any(|u| entry_bundle_id(&u.url).is_some_and(|b| b.eq_ignore_ascii_case(bundle_id)));
    if present {
        return false;
    }
    item.urls.push(ItemUrl {
        label: label.to_string(),
        url,
        rule: MatchRule::ExactHost,
        primary: false,
    });
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Id;
    use crate::model::{ItemType, new_item};

    fn login_with_urls(urls: &[&str]) -> Item {
        let mut it = new_item(ItemType::Login, Id::new(), "Test");
        it.urls = urls
            .iter()
            .map(|u| ItemUrl {
                label: String::new(),
                url: (*u).into(),
                rule: MatchRule::Domain,
                primary: false,
            })
            .collect();
        it
    }

    #[test]
    fn valid_ids() {
        assert!(valid_bundle_id("com.tinyspeck.slackmacgap"));
        assert!(valid_bundle_id("org.mozilla.firefox"));
        for bad in [
            "",
            "com",
            "com.evil/../x",
            "https://a.b",
            "a..b",
            "com.x y",
            &"a.".repeat(100),
        ] {
            assert!(!valid_bundle_id(bad), "{bad}");
        }
    }

    #[test]
    fn url_round_trip() {
        assert_eq!(
            app_entry_url("com.discord").as_deref(),
            Some("macapp://com.discord")
        );
        assert_eq!(app_entry_url("bad/id"), None);
    }

    #[test]
    fn matches_case_insensitively_and_never_web_urls() {
        let mut item = login_with_urls(&["https://slack.com"]);
        assert!(!matches_app(&item, "com.tinyspeck.slackmacgap"));
        assert!(add_app_entry(
            &mut item,
            "com.tinyspeck.slackmacgap",
            "Slack"
        ));
        assert!(!add_app_entry(
            &mut item,
            "COM.tinyspeck.slackmacgap",
            "Slack"
        ));
        assert!(matches_app(&item, "com.TinySpeck.slackmacgap"));
        assert!(!matches_app(&item, "com.tinyspeck"));
    }

    #[test]
    fn browsers_are_known_without_case() {
        assert!(is_known_browser("com.apple.Safari"));
        assert!(is_known_browser("COM.GOOGLE.CHROME"));
        assert!(!is_known_browser("com.tinyspeck.slackmacgap"));
        assert!(KNOWN_BROWSERS.iter().all(|b| valid_bundle_id(b)));
    }

    #[test]
    fn never_rule_does_not_match() {
        let mut item = login_with_urls(&[]);
        add_app_entry(&mut item, "com.discord", "Discord");
        item.urls[0].rule = MatchRule::Never;
        assert!(!matches_app(&item, "com.discord"));
    }
}
