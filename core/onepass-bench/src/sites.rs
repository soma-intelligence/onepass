//! The bench's site list (`bench/sites.json`): public pages with a hand-written truth.

use std::collections::HashSet;
use std::fmt;
use std::path::Path;

use serde::{Deserialize, Serialize};

pub const LIST_VERSION: u32 = 1;

/// Truth roles: the model label set (`ml/onepass_ml/labels.py`) plus two extension roles the
/// models fold elsewhere (`full_name`, `region`).
pub const ROLES: &[&str] = &[
    "username",
    "email",
    "password",
    "new_password",
    "otp",
    "cc_name",
    "cc_number",
    "cc_exp",
    "cc_exp_month",
    "cc_exp_year",
    "cc_csc",
    "given_name",
    "family_name",
    "tel",
    "birth_date",
    "organization",
    "address_line1",
    "address_line2",
    "postal_code",
    "city",
    "country",
    "full_name",
    "region",
    "none",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Login,
    Signup,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TruthField {
    pub selector: String,
    pub role: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accept: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Site {
    pub id: String,
    pub url: String,
    pub kind: Kind,
    pub lang: String,
    pub fields: Vec<TruthField>,
}

impl Site {
    pub fn host(&self) -> &str {
        let rest = self.url.strip_prefix("https://").unwrap_or(&self.url);
        rest.split(['/', '?', '#']).next().unwrap_or(rest)
    }

    /// Path plus query, as `robots.txt` rules see it.
    pub fn path(&self) -> &str {
        let rest = self.url.strip_prefix("https://").unwrap_or(&self.url);
        match rest.find('/') {
            Some(i) => &rest[i..],
            None => "/",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SiteList {
    pub version: u32,
    pub sites: Vec<Site>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListError(pub String);

impl fmt::Display for ListError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ListError {}

impl SiteList {
    pub fn load(path: &Path) -> Result<SiteList, ListError> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| ListError(format!("{}: {e}", path.display())))?;
        SiteList::parse(&text)
    }

    pub fn parse(text: &str) -> Result<SiteList, ListError> {
        let list: SiteList =
            serde_json::from_str(text).map_err(|e| ListError(format!("site list: {e}")))?;
        list.validate()?;
        Ok(list)
    }

    pub fn validate(&self) -> Result<(), ListError> {
        if self.version != LIST_VERSION {
            return Err(ListError(format!(
                "site list version {} (expected {LIST_VERSION})",
                self.version
            )));
        }
        let mut ids = HashSet::new();
        for s in &self.sites {
            let bad = |m: &str| Err(ListError(format!("site {}: {m}", s.id)));
            if s.id.is_empty()
                || !s
                    .id
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
            {
                return bad("id must be lowercase letters, digits and dashes");
            }
            if !ids.insert(s.id.as_str()) {
                return bad("duplicate id");
            }
            if !s.url.starts_with("https://") || s.host().is_empty() {
                return bad("url must be https");
            }
            if s.fields.is_empty() {
                return bad("no truth field");
            }
            let mut selectors = HashSet::new();
            for f in &s.fields {
                if f.selector.trim().is_empty() || !selectors.insert(f.selector.as_str()) {
                    return bad("empty or duplicate selector");
                }
                for r in std::iter::once(&f.role).chain(f.accept.iter()) {
                    if !ROLES.contains(&r.as_str()) {
                        return bad(&format!("unknown role {r}"));
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OK: &str = r##"{"version":1,"sites":[{"id":"ex-login","url":"https://ex.example/login?x=1","kind":"login","lang":"en",
      "fields":[{"selector":"#u","role":"username","accept":["email"]},{"selector":"#p","role":"password"}]}]}"##;

    #[test]
    fn parses_and_reads_host_and_path() {
        let l = SiteList::parse(OK).unwrap();
        assert_eq!(l.sites[0].host(), "ex.example");
        assert_eq!(l.sites[0].path(), "/login?x=1");
        assert_eq!(l.sites[0].kind, Kind::Login);
    }

    #[test]
    fn rejects_bad_lists() {
        let cases = [
            OK.replace("\"version\":1", "\"version\":2"),
            OK.replace("https://ex", "http://ex"),
            OK.replace("\"role\":\"password\"", "\"role\":\"secret\""),
            OK.replace("ex-login", "Ex Login"),
            OK.replace("\"#p\"", "\"#u\""),
            OK.replace("\"lang\":\"en\"", "\"lang\":\"en\",\"extra\":1"),
            r#"{"version":1,"sites":[{"id":"a","url":"https://a.example","kind":"login","lang":"en","fields":[]}]}"#.to_string(),
        ];
        for c in cases {
            assert!(SiteList::parse(&c).is_err(), "accepted: {c}");
        }
        let dup = OK.replace("]}]}", "]},{\"id\":\"ex-login\",\"url\":\"https://b.example\",\"kind\":\"signup\",\"lang\":\"en\",\"fields\":[{\"selector\":\"#a\",\"role\":\"new_password\"}]}]}");
        assert!(SiteList::parse(&dup).is_err());
    }
}
