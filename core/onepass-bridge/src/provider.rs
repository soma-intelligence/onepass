//! Sign-in providers and their official hosts (spec 8.7).
//!
//! Hosts are compared exactly, never by registrable domain: a lookalike
//! such as `accounts.google.com.evil.test` is never the provider.

use onepass_core::model::Provider;
use serde::{Deserialize, Serialize};

/// A provider the extension knows, lowercase on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProviderId {
    Google,
    Apple,
    Microsoft,
    Github,
    Facebook,
    X,
    Linkedin,
    Discord,
    Slack,
}

impl ProviderId {
    pub const ALL: [ProviderId; 9] = [
        ProviderId::Google,
        ProviderId::Apple,
        ProviderId::Microsoft,
        ProviderId::Github,
        ProviderId::Facebook,
        ProviderId::X,
        ProviderId::Linkedin,
        ProviderId::Discord,
        ProviderId::Slack,
    ];

    /// The wire spelling.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Google => "google",
            Self::Apple => "apple",
            Self::Microsoft => "microsoft",
            Self::Github => "github",
            Self::Facebook => "facebook",
            Self::X => "x",
            Self::Linkedin => "linkedin",
            Self::Discord => "discord",
            Self::Slack => "slack",
        }
    }

    /// The model provider of the `core`.
    pub fn to_core(self) -> Provider {
        match self {
            Self::Google => Provider::Google,
            Self::Apple => Provider::Apple,
            Self::Microsoft => Provider::Microsoft,
            Self::Github => Provider::GitHub,
            Self::Facebook => Provider::Facebook,
            Self::X => Provider::X,
            Self::Linkedin => Provider::LinkedIn,
            Self::Discord => Provider::Discord,
            Self::Slack => Provider::Slack,
        }
    }
}

/// Official hosts of a provider, exact hosts (spec 8.7).
pub fn official_hosts(p: ProviderId) -> &'static [&'static str] {
    match p {
        ProviderId::Google => &["accounts.google.com"],
        ProviderId::Apple => &["appleid.apple.com", "idmsa.apple.com"],
        ProviderId::Microsoft => &[
            "login.microsoftonline.com",
            "login.live.com",
            "account.live.com",
        ],
        ProviderId::Github => &["github.com"],
        ProviderId::Facebook => &["www.facebook.com", "m.facebook.com"],
        ProviderId::X => &["x.com", "twitter.com", "api.x.com"],
        ProviderId::Linkedin => &["www.linkedin.com"],
        ProviderId::Discord => &["discord.com"],
        ProviderId::Slack => &["slack.com"],
    }
}

/// The provider whose official host list holds exactly `host` (lowercase
/// ASCII, as `Origin::host` gives it).
pub fn from_host(host: &str) -> Option<ProviderId> {
    ProviderId::ALL
        .into_iter()
        .find(|p| official_hosts(*p).contains(&host))
}

/// The bridge provider of a `core` provider; `None` for enterprise and
/// custom providers, which have no fixed official host.
pub fn from_core(p: &Provider) -> Option<ProviderId> {
    Some(match p {
        Provider::Google => ProviderId::Google,
        Provider::Apple => ProviderId::Apple,
        Provider::Microsoft => ProviderId::Microsoft,
        Provider::GitHub => ProviderId::Github,
        Provider::Facebook => ProviderId::Facebook,
        Provider::X => ProviderId::X,
        Provider::LinkedIn => ProviderId::Linkedin,
        Provider::Discord => ProviderId::Discord,
        Provider::Slack => ProviderId::Slack,
        Provider::Okta | Provider::EntraId | Provider::CustomOidc(_) | Provider::CustomSaml(_) => {
            return None;
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::origin::Origin;

    #[test]
    fn official_google_host() {
        assert_eq!(from_host("accounts.google.com"), Some(ProviderId::Google));
        let o = Origin::parse("https://Accounts.Google.com/signin").unwrap();
        assert_eq!(from_host(o.host()), Some(ProviderId::Google));
        assert_eq!(from_host("twitter.com"), Some(ProviderId::X));
    }

    #[test]
    fn lookalike_google_is_none() {
        assert_eq!(from_host("accounts.google.com.evil.test"), None);
        assert_eq!(from_host("accounts-google.com"), None);
        assert_eq!(from_host("google.com"), None);
        assert_eq!(from_host("evil.accounts.google.com"), None);
    }

    #[test]
    fn wire_names_round_trip_with_core() {
        for p in ProviderId::ALL {
            assert_eq!(
                serde_json::to_string(&p).unwrap(),
                format!("\"{}\"", p.as_str())
            );
            assert_eq!(from_core(&p.to_core()), Some(p));
        }
        assert_eq!(from_core(&Provider::Okta), None);
    }
}
