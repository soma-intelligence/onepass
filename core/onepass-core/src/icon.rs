//! Item icon helpers (milestone 5).

#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

use crate::model::checks::{CardBrand, card_brand};
use crate::model::field::FieldValue;
use crate::model::item::Item;
use crate::model::templates::ItemType;
use crate::watchtower::host::{host_of, is_private_host};

/// What a client needs to draw an item icon, without any network access.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IconHint {
    /// Host of the primary URL (else the first one).
    pub host: Option<String>,
    /// Icon URLs a client may try, always `https`, empty for private hosts
    /// (private addresses, single-label and local network names): the
    /// client then draws the letter.
    pub candidates: Vec<String>,
    /// Brand of the card number of a credit card.
    pub card_brand: Option<CardBrand>,
    /// First alphanumeric character of the title, upper-cased, else `#`.
    pub letter: char,
}

/// Icon hint of an item.
pub fn hint(item: &Item) -> IconHint {
    let url = item
        .urls
        .iter()
        .find(|u| u.primary)
        .or_else(|| item.urls.first());
    let host = url.and_then(|u| host_of(&u.url));
    let candidates = match &host {
        Some(h) if !is_private_host(h) => vec![
            format!("https://{h}/apple-touch-icon.png"),
            format!("https://{h}/favicon.ico"),
        ],
        _ => Vec::new(),
    };
    let brand = (item.item_type == ItemType::CreditCard)
        .then(|| match item.field("number").map(|f| &f.value) {
            Some(FieldValue::Concealed(n) | FieldValue::Password(n)) => Some(card_brand(n)),
            Some(FieldValue::Text(n)) => Some(card_brand(n)),
            _ => None,
        })
        .flatten();
    let letter = item
        .title
        .chars()
        .find(|c| c.is_alphanumeric())
        .and_then(|c| c.to_uppercase().next())
        .unwrap_or('#');
    IconHint {
        host,
        candidates,
        card_brand: brand,
        letter,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::Id;
    use crate::model::field::FieldValue;
    use crate::model::item::ItemUrl;
    use crate::model::item::MatchRule;
    use crate::model::templates::new_item;
    use zeroize::Zeroizing;

    fn url(u: &str, primary: bool) -> ItemUrl {
        ItemUrl {
            label: String::new(),
            url: u.into(),
            rule: MatchRule::Domain,
            primary,
        }
    }

    #[test]
    fn icon_for_login() {
        let mut it = new_item(ItemType::Login, Id::new(), "Example");
        it.urls = vec![
            url("https://other.org", false),
            url("https://www.Example.com/login", true),
        ];
        let h = hint(&it);
        assert_eq!(h.host.as_deref(), Some("www.example.com"));
        assert_eq!(
            h.candidates,
            vec![
                "https://www.example.com/apple-touch-icon.png",
                "https://www.example.com/favicon.ico"
            ]
        );
        assert_eq!(h.card_brand, None);
        assert_eq!(h.letter, 'E');
        it.urls = vec![url("https://first.org", false)];
        assert_eq!(hint(&it).host.as_deref(), Some("first.org"));
        it.urls = vec![url("http://localhost:8080", true)];
        let h = hint(&it);
        assert_eq!(h.host.as_deref(), Some("localhost"));
        assert!(h.candidates.is_empty());
    }

    #[test]
    fn icon_never_http() {
        let mut it = new_item(ItemType::Login, Id::new(), "x");
        it.urls = vec![url("http://example.com", true)];
        let h = hint(&it);
        assert!(!h.candidates.is_empty());
        assert!(h.candidates.iter().all(|c| c.starts_with("https://")));
    }

    #[test]
    fn icon_card_brand() {
        let mut it = new_item(ItemType::CreditCard, Id::new(), "Carte");
        if let Some(f) = it.field_mut("number") {
            f.value = FieldValue::Concealed(Zeroizing::new("4111 1111 1111 1111".into()));
        }
        assert_eq!(hint(&it).card_brand, Some(CardBrand::Visa));
        let login = new_item(ItemType::Login, Id::new(), "L");
        assert_eq!(hint(&login).card_brand, None);
    }

    #[test]
    fn icon_letter_fallback() {
        let l = |t: &str| hint(&new_item(ItemType::Login, Id::new(), t)).letter;
        assert_eq!(l("  - bank"), 'B');
        assert_eq!(l("\u{e9}cole"), '\u{c9}');
        assert_eq!(l("\u{df}x"), 'S');
        assert_eq!(l("***"), '#');
        assert_eq!(l(""), '#');
    }

    #[test]
    fn icon_no_candidates_for_private_hosts() {
        let mut it = new_item(ItemType::Login, Id::new(), "Router");
        for u in [
            "http://192.168.1.1/admin",
            "https://10.0.0.2",
            "http://[fe80::1]:8080",
            "https://nas.home.arpa",
            "https://intranet/",
            "https://svc.internal",
        ] {
            it.urls = vec![url(u, true)];
            let h = hint(&it);
            assert!(h.candidates.is_empty(), "{u}");
            assert_eq!(h.letter, 'R');
        }
    }
}
