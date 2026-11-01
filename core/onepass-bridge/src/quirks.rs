//! Known site password rules (spec G7, 6.4).
//!
//! The table is Apple's `quirks/password-rules.json` from
//! `apple/password-manager-resources` (MIT), embedded at a pinned commit by
//! `scripts/update-password-quirks.sh`. It maps a domain to a rule string in
//! the Password Rules language. No network call happens at run time.

use std::collections::HashMap;
use std::sync::OnceLock;

use crate::origin::Origin;

const RAW: &str = include_str!("../data/password-rules.json");

#[derive(serde::Deserialize)]
struct Entry {
    #[serde(rename = "password-rules")]
    rules: String,
}

/// Parsed once at first use. Strings are owned (JSON escapes cannot be
/// borrowed) and leaked once so lookups hand out `&'static str`. A malformed
/// embedded file yields an empty table (a unit test pins that it parses).
fn table() -> &'static HashMap<String, &'static str> {
    static TABLE: OnceLock<HashMap<String, &'static str>> = OnceLock::new();
    TABLE.get_or_init(|| {
        serde_json::from_str::<HashMap<String, Entry>>(RAW)
            .map(|m| {
                m.into_iter()
                    .map(|(k, v)| (k, &*Box::leak(v.rules.into_boxed_str())))
                    .collect()
            })
            .unwrap_or_default()
    })
}

/// Rule string for a page, if the site is known.
///
/// Tries the exact host, then each parent domain down to and including the
/// registrable domain (`Origin::site`). A bare public suffix is never looked
/// up.
pub fn quirk_rules(origin: &Origin) -> Option<&'static str> {
    let table = table();
    let host = origin.host();
    let site = origin.site();
    if !host.ends_with(site.as_str()) {
        return table.get(host).copied();
    }
    let mut candidate = host;
    loop {
        if let Some(rules) = table.get(candidate) {
            return Some(rules);
        }
        if candidate.len() <= site.len() {
            return None;
        }
        // Strip one label; the dot before `site` guarantees we stay at or
        // above the registrable domain.
        candidate = &candidate[candidate.find('.')? + 1..];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn origin(s: &str) -> Origin {
        Origin::parse(s).unwrap()
    }

    #[test]
    fn table_parses_and_is_not_empty() {
        assert!(table().len() > 100);
    }

    #[test]
    fn known_host_found() {
        let rules = quirk_rules(&origin("https://apple.com/")).unwrap();
        assert!(rules.contains("minlength") || rules.contains("required"));
    }

    #[test]
    fn subdomain_uses_site() {
        assert_eq!(
            quirk_rules(&origin("https://www.apple.com/login")),
            quirk_rules(&origin("https://apple.com/"))
        );
        assert!(quirk_rules(&origin("https://deep.sub.google.com/")).is_some());
    }

    #[test]
    fn exact_host_beats_site() {
        // `account.xiaomi.com` has its own entry, distinct from the bare site.
        let exact = quirk_rules(&origin("https://account.xiaomi.com/")).unwrap();
        assert_eq!(table().get("account.xiaomi.com").copied(), Some(exact));
        assert_eq!(
            quirk_rules(&origin("https://x.account.xiaomi.com/")),
            Some(exact)
        );
    }

    #[test]
    fn unknown_none() {
        assert_eq!(quirk_rules(&origin("https://no-such-site.example/")), None);
        assert_eq!(quirk_rules(&origin("https://203.0.113.9/")), None);
    }

    #[test]
    fn public_suffix_not_looked_up() {
        // `co.uk` is a suffix: never a match for a host under it that is unknown.
        assert_eq!(quirk_rules(&origin("https://unknown-shop.co.uk/")), None);
    }
}
