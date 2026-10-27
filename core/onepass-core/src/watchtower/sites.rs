//! Site catalogs: 2FA and passkey support, breached sites (spec 3.4), and
//! the checks that use them: `missing_2fa`, `passkey_available`,
//! `breached_site`, plus `provider_exposed` (spec 3.2).
//!
//! Catalogs are parsed from bytes supplied by the caller; no I/O here. A
//! malformed entry is skipped; only a wrong top-level type, invalid JSON or
//! a cap overrun rejects the document.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde_json::{Map, Value};
use time::{Date, Month};

use crate::id::Id;
use crate::model::{FieldValue, Item, ItemType, LoginMethod};
use crate::{Error, Result};

use super::checks::{Check, Detail, Finding, excluded, password_changed_on, passwords, push};
use super::host::{MAX_HOST_LEN, host_of};

/// Largest catalog document (spec 3.4).
const MAX_DOC_BYTES: usize = 16 * 1024 * 1024;
/// Most entries in one catalog document.
const MAX_DOC_ENTRIES: usize = 100_000;

/// 2FA and passkey support of one domain.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SiteInfo {
    /// TOTP codes accepted.
    pub totp: bool,
    /// Hardware security keys accepted.
    pub u2f: bool,
    /// Passkeys accepted, for passwordless sign-in or as a second factor.
    pub passkey: bool,
    /// Where the site documents its setup. The 2FA directory wins over the
    /// passkeys directory.
    pub documentation: Option<String>,
}

/// Sites offering 2FA or passkeys, keyed by lower-case domain.
#[derive(Debug, Default, Clone)]
pub struct SiteDirectory {
    sites: HashMap<String, SiteInfo>,
}

impl SiteDirectory {
    /// Loads a 2fa.directory v4 document:
    /// `{ "<domain>": { "methods": [..], "documentation": ".." } }`.
    pub fn from_2fa_directory(json: &[u8]) -> Result<SiteDirectory> {
        let entries = object_doc(json, "2fa directory")?;
        let mut dir = SiteDirectory::default();
        for (domain, entry) in &entries {
            let (Some(domain), Value::Object(entry)) = (normalize_domain(domain), entry) else {
                continue;
            };
            let methods = match entry.get("methods") {
                None => &[][..],
                Some(Value::Array(m)) => m.as_slice(),
                Some(_) => continue,
            };
            let has = |name: &str| methods.iter().any(|m| m.as_str() == Some(name));
            let info = SiteInfo {
                totp: has("totp"),
                u2f: has("u2f"),
                passkey: false,
                documentation: documentation(entry),
            };
            dir.merge(domain, info);
        }
        Ok(dir)
    }

    /// Adds a passkeys-api v1 document:
    /// `{ "<domain>": { "passwordless": "allowed", "mfa": "allowed" } }`.
    /// Flags are merged with the existing entry of the domain.
    pub fn add_passkeys_directory(&mut self, json: &[u8]) -> Result<()> {
        let entries = object_doc(json, "passkeys directory")?;
        for (domain, entry) in &entries {
            let (Some(domain), Value::Object(entry)) = (normalize_domain(domain), entry) else {
                continue;
            };
            let allowed = |k: &str| entry.get(k).and_then(Value::as_str) == Some("allowed");
            let info = SiteInfo {
                totp: false,
                u2f: false,
                passkey: allowed("passwordless") || allowed("mfa"),
                documentation: documentation(entry),
            };
            self.merge(domain, info);
        }
        Ok(())
    }

    /// Entry of the host, or of its closest parent domain. Labels are
    /// removed from the left down to two labels; no public suffix list.
    pub fn lookup(&self, host: &str) -> Option<&SiteInfo> {
        let host = normalize_domain(host)?;
        candidates(&host).find_map(|d| self.sites.get(d))
    }

    /// Number of domains.
    pub fn len(&self) -> usize {
        self.sites.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sites.is_empty()
    }

    /// Ors the flags; the first documentation found is kept.
    fn merge(&mut self, domain: String, info: SiteInfo) {
        let slot = self.sites.entry(domain).or_default();
        slot.totp |= info.totp;
        slot.u2f |= info.u2f;
        slot.passkey |= info.passkey;
        if slot.documentation.is_none() {
            slot.documentation = info.documentation;
        }
    }
}

/// One verified breach.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Breach {
    pub name: String,
    /// Lower-case domain.
    pub domain: String,
    pub date: Date,
}

/// Verified breaches by domain.
#[derive(Debug, Default, Clone)]
pub struct BreachCatalog {
    by_domain: HashMap<String, Vec<Breach>>,
}

impl BreachCatalog {
    /// Loads an HIBP `breaches` document: an array of objects with `Name`,
    /// `Domain`, `BreachDate` (`YYYY-MM-DD`) and `IsVerified`. Unverified
    /// breaches and those without a domain are skipped.
    pub fn from_hibp(json: &[u8]) -> Result<BreachCatalog> {
        const BAD: Error = Error::InvalidFormat("breach catalog");
        let Value::Array(entries) = parse_doc(json, BAD)? else {
            return Err(BAD);
        };
        if entries.len() > MAX_DOC_ENTRIES {
            return Err(BAD);
        }
        let mut catalog = BreachCatalog::default();
        for entry in &entries {
            let Value::Object(e) = entry else {
                continue;
            };
            if e.get("IsVerified").and_then(Value::as_bool) != Some(true) {
                continue;
            }
            let name = e.get("Name").and_then(Value::as_str).unwrap_or("");
            let domain = e
                .get("Domain")
                .and_then(Value::as_str)
                .and_then(normalize_domain);
            let date = e
                .get("BreachDate")
                .and_then(Value::as_str)
                .and_then(parse_date);
            let (Some(domain), Some(date)) = (domain, date) else {
                continue;
            };
            if name.is_empty() {
                continue;
            }
            catalog
                .by_domain
                .entry(domain.clone())
                .or_default()
                .push(Breach {
                    name: name.to_owned(),
                    domain,
                    date,
                });
        }
        Ok(catalog)
    }

    /// Breaches of the host and of its parent domains, oldest first.
    pub fn lookup(&self, host: &str) -> Vec<&Breach> {
        let Some(host) = normalize_domain(host) else {
            return Vec::new();
        };
        let mut found: Vec<&Breach> = candidates(&host)
            .filter_map(|d| self.by_domain.get(d))
            .flatten()
            .collect();
        found.sort_by(|a, b| (a.date, &a.name).cmp(&(b.date, &b.name)));
        found
    }
}

/// Parses a document under the byte cap.
fn parse_doc(json: &[u8], bad: Error) -> Result<Value> {
    if json.len() > MAX_DOC_BYTES {
        return Err(bad);
    }
    serde_json::from_slice(json).map_err(|_| bad)
}

/// A document whose top level is an object, under the entry cap.
fn object_doc(json: &[u8], what: &'static str) -> Result<Map<String, Value>> {
    match parse_doc(json, Error::InvalidFormat(what))? {
        Value::Object(m) if m.len() <= MAX_DOC_ENTRIES => Ok(m),
        _ => Err(Error::InvalidFormat(what)),
    }
}

/// Longest documentation link kept.
const MAX_DOC_URL: usize = 2048;

/// The documentation link of an entry, kept only when it is an `https://`
/// URL of printable ASCII without spaces, at most [`MAX_DOC_URL`] bytes:
/// the value comes from a downloaded document and may be shown in a
/// terminal.
fn documentation(entry: &Map<String, Value>) -> Option<String> {
    entry
        .get("documentation")
        .and_then(Value::as_str)
        .filter(|s| is_safe_doc_url(s))
        .map(str::to_owned)
}

fn is_safe_doc_url(s: &str) -> bool {
    s.len() <= MAX_DOC_URL
        && s.len() > "https://".len()
        && s.starts_with("https://")
        && s.bytes().all(|b| b.is_ascii_graphic())
}

/// Lower-cased domain without a trailing dot; `None` when empty or longer
/// than [`MAX_HOST_LEN`].
fn normalize_domain(d: &str) -> Option<String> {
    let d = d.trim().trim_end_matches('.');
    (!d.is_empty() && d.len() <= MAX_HOST_LEN).then(|| d.to_ascii_lowercase())
}

/// The host, then each parent domain, down to two labels.
fn candidates(host: &str) -> impl Iterator<Item = &str> {
    std::iter::successors(Some(host), |h| h.split_once('.').map(|(_, rest)| rest))
        .take_while(|h| h.contains('.'))
}

/// `YYYY-MM-DD`.
fn parse_date(s: &str) -> Option<Date> {
    let mut parts = s.split('-');
    let (y, m, d) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some()
        || [y, m, d]
            .iter()
            .any(|p| !p.bytes().all(|b| b.is_ascii_digit()))
    {
        return None;
    }
    if y.len() != 4 || m.len() != 2 || d.len() != 2 {
        return None;
    }
    let month = Month::try_from(m.parse::<u8>().ok()?).ok()?;
    Date::from_calendar_date(y.parse().ok()?, month, d.parse().ok()?).ok()
}

/// Distinct hosts of the item URLs, primary first.
fn item_hosts(item: &Item) -> Vec<String> {
    let mut hosts: Vec<String> = Vec::new();
    let primary = item.urls.iter().filter(|u| u.primary);
    let others = item.urls.iter().filter(|u| !u.primary);
    for host in primary.chain(others).filter_map(|u| host_of(&u.url)) {
        if !hosts.contains(&host) {
            hosts.push(host);
        }
    }
    hosts
}

fn fields(item: &Item) -> impl Iterator<Item = &FieldValue> {
    item.sections
        .iter()
        .flat_map(|s| s.fields.iter())
        .map(|f| &f.value)
}

/// A non-empty `Otp` field anywhere in the item.
fn has_totp(item: &Item) -> bool {
    fields(item).any(|v| matches!(v, FieldValue::Otp(s) if !s.trim().is_empty()))
}

/// A `Passkey` value anywhere in the item.
fn has_passkey(item: &Item) -> bool {
    fields(item).any(|v| matches!(v, FieldValue::Passkey(_)))
}

/// `missing_2fa` and `passkey_available` on Logins: one finding per item
/// and check, from the first host (primary first) that qualifies.
pub(crate) fn site_findings(items: &[&Item], dir: &SiteDirectory, out: &mut Vec<Finding>) {
    for item in items {
        if item.item_type != ItemType::Login {
            continue;
        }
        let hosts = item_hosts(item);
        let infos: Vec<&SiteInfo> = hosts.iter().filter_map(|h| dir.lookup(h)).collect();
        if !has_totp(item)
            && let Some(info) = infos.iter().find(|i| i.totp || i.u2f)
        {
            let detail = Detail::Site {
                documentation: info.documentation.clone(),
            };
            push(out, item, Check::Missing2fa, None, detail);
        }
        if !has_passkey(item)
            && let Some(info) = infos.iter().find(|i| i.passkey)
        {
            let detail = Detail::Site {
                documentation: info.documentation.clone(),
            };
            push(out, item, Check::PasskeyAvailable, None, detail);
        }
    }
}

/// `breached_site` on Logins and Passwords: the most recent breach of any
/// host dated after the last password change, one finding per item.
pub(crate) fn breach_findings(items: &[&Item], catalog: &BreachCatalog, out: &mut Vec<Finding>) {
    for item in items {
        if !matches!(item.item_type, ItemType::Login | ItemType::Password)
            || excluded(item, Check::BreachedSite)
        {
            continue;
        }
        let Some((field_id, _)) = passwords(item).next() else {
            continue;
        };
        let changed = password_changed_on(item);
        let latest = item_hosts(item)
            .iter()
            .flat_map(|h| catalog.lookup(h))
            .filter(|b| b.date > changed)
            .max_by(|a, b| (a.date, &a.name).cmp(&(b.date, &b.name)));
        if let Some(b) = latest {
            let detail = Detail::Breach {
                name: b.name.clone(),
                date: b.date,
            };
            push(out, item, Check::BreachedSite, Some(field_id), detail);
        }
    }
}

/// `provider_exposed`: a provider account (target of a
/// `LoginMethod::Provider` of a Login) with a `compromised`, `reused` or
/// `weak` finding in `findings`, or without TOTP nor passkey. One finding
/// per account, listing the sorted ids of the dependent Logins.
pub(crate) fn provider_findings(items: &[&Item], findings: &[Finding]) -> Vec<Finding> {
    let mut dependents: BTreeMap<Id, BTreeSet<Id>> = BTreeMap::new();
    for item in items {
        if item.item_type != ItemType::Login {
            continue;
        }
        for m in &item.login_methods {
            if let LoginMethod::Provider { account, .. } = m
                && *account != item.id
            {
                dependents.entry(*account).or_default().insert(item.id);
            }
        }
    }
    if dependents.is_empty() {
        return Vec::new();
    }
    let by_id: HashMap<Id, &Item> = items.iter().map(|i| (i.id, *i)).collect();
    let exposed: BTreeSet<Id> = findings
        .iter()
        .filter(|f| matches!(f.check, Check::Compromised | Check::Reused | Check::Weak))
        .map(|f| f.item_id)
        .collect();
    let mut out = Vec::new();
    for (account, deps) in dependents {
        let Some(provider) = by_id.get(&account) else {
            continue;
        };
        let unprotected = !has_totp(provider) && !has_passkey(provider);
        if exposed.contains(&account) || unprotected {
            let detail = Detail::Dependents {
                items: deps.into_iter().collect(),
            };
            push(&mut out, provider, Check::ProviderExposed, None, detail);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidates_stop_at_two_labels() {
        let c: Vec<_> = candidates("a.b.example.com").collect();
        assert_eq!(c, ["a.b.example.com", "b.example.com", "example.com"]);
        assert_eq!(candidates("localhost").count(), 0);
        assert_eq!(candidates("[::1]").count(), 0);
    }

    #[test]
    fn date_format_is_strict() {
        assert_eq!(
            parse_date("2025-06-15"),
            Date::from_calendar_date(2025, Month::June, 15).ok()
        );
        for bad in [
            "2025-6-15",
            "2025-06-31",
            "2025-06-15-1",
            "+025-06-15",
            "",
            "x",
        ] {
            assert_eq!(parse_date(bad), None, "{bad}");
        }
    }

    #[test]
    fn domains_normalized() {
        assert_eq!(
            normalize_domain(" Example.COM. ").as_deref(),
            Some("example.com")
        );
        assert_eq!(normalize_domain("."), None);
        assert_eq!(normalize_domain(&"a".repeat(MAX_HOST_LEN + 1)), None);
    }

    #[test]
    fn documentation_only_safe_https() {
        let doc = |v: Value| {
            let mut m = Map::new();
            m.insert("documentation".into(), v);
            documentation(&m)
        };
        assert_eq!(
            doc(Value::from("https://example.com/2fa")).as_deref(),
            Some("https://example.com/2fa")
        );
        for bad in [
            "http://example.com/2fa",
            "https://",
            "javascript:alert(1)",
            "https://example.com/\x1b[31m",
            "https://example.com/a b",
            "https://example.com/\u{e9}",
            "",
        ] {
            assert_eq!(doc(Value::from(bad)), None, "{bad:?}");
        }
        let long = format!("https://example.com/{}", "a".repeat(MAX_DOC_URL));
        assert_eq!(doc(Value::from(long)), None);
        assert_eq!(doc(Value::from(7)), None);
    }
}
