//! Watchtower over the UniFFI surface (milestone 5, apps side).
//!
//! The analysis runs on a copy of the items taken under the session lock,
//! then outside of it: a slow report never blocks the other calls.
//!
//! Breach lookups make no network call here. The caller passes the range
//! responses it already holds (`FfiWatchtowerOptions::ranges`); every prefix
//! the core asked for and did not get comes back in `missing_prefixes`. The
//! app runs once with no response (offline report plus the prefixes to
//! fetch), downloads those ranges, then runs again with them. Only the
//! 5 hex character prefix of a SHA-1 ever leaves the core (spec 3.3).
//!
//! The report carries ids, counts and a score, never a secret.

#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

use std::collections::{BTreeMap, BTreeSet, HashMap};

use onepass_core::generator;
use onepass_core::model::{FieldValue, Item};
use onepass_core::site_pack;
use onepass_core::watchtower::{
    BreachCatalog, Check, Detail, Options, PwnedStatus, RangeSource, SiteDirectory, Sources,
    analyze,
};
use onepass_core::{Error, Id, IntegrityError};
use time::OffsetDateTime;

use crate::convert::{id_hex, parse_id};
use crate::error::OnePassError;
use crate::session::Session;

/// Strength levels of the app's meter (`StrengthMeter`): thresholds in bits.
const STRENGTH_THRESHOLDS: [f64; 4] = [40.0, 60.0, 80.0, 100.0];

/// One HIBP `range` response held by the caller.
#[derive(uniffi::Record, Debug, Clone)]
pub struct FfiRangeResponse {
    /// 5 upper-case hex characters.
    pub prefix: String,
    pub body: Vec<u8>,
}

/// What an analysis may use besides the items.
#[derive(uniffi::Record, Debug, Clone)]
pub struct FfiWatchtowerOptions {
    /// Days before a deadline when an expiration is reported.
    pub expiry_warning_days: u16,
    /// Age in days from which a password is old.
    pub old_password_days: u16,
    /// `None`: breach lookups off (status `disabled`). `Some`: the responses
    /// at hand; a prefix without one is reported in `missing_prefixes`.
    pub ranges: Option<Vec<FfiRangeResponse>>,
    /// Vaults left out of the analysis (hidden on this device).
    pub excluded_vault_ids: Vec<String>,
    /// Have I Been Pwned `/api/v3/breaches` (the whole public catalog).
    /// Without it, or when it does not parse, `breached_site` does not run.
    pub breach_catalog: Option<Vec<u8>>,
    /// A site pack (`site_pack::parse` format), already verified by the
    /// caller: the only source of `missing_2fa` and `passkey_available`.
    /// Without it, or when it does not parse, no site check runs.
    #[uniffi(default = None)]
    pub site_pack: Option<Vec<u8>>,
}

/// Breach lookup outcome.
#[derive(uniffi::Enum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum FfiPwnedStatus {
    Checked,
    Partial { failed_prefixes: u32 },
    Unavailable,
    Disabled,
}

/// Results of one check.
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct FfiWatchtowerCheck {
    /// Stable id of the check (`reused`, `weak`, `compromised`...).
    pub check: String,
    /// Findings (one per field when the check concerns a field).
    pub findings: u32,
    /// Distinct items concerned, without hyphens, sorted.
    pub item_ids: Vec<String>,
    /// Where each item of `missing_2fa` and `passkey_available` can set the
    /// feature up, one per item, sorted by item id. Empty for other checks.
    #[uniffi(default = [])]
    pub site_links: Vec<FfiSiteLink>,
}

/// The site facts behind one `missing_2fa` or `passkey_available` finding.
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct FfiSiteLink {
    /// Item id, without hyphens.
    pub item_id: String,
    /// The item host that matched the pack.
    pub host: String,
    pub settings_url: Option<String>,
    pub help_url: Option<String>,
    /// The pack carries a non-empty recipe for this check.
    pub has_recipe: bool,
}

#[derive(uniffi::Record, Debug, Clone)]
pub struct FfiWatchtowerReport {
    /// Global health score, 0 to 100 (spec 3.5).
    pub score: u8,
    /// Active items analyzed (trashed and archived ones are skipped).
    pub items_analyzed: u32,
    /// Every check of the core, in its order, even when nothing was found.
    pub checks: Vec<FfiWatchtowerCheck>,
    /// Password fields of the analyzed items by strength level, 0 (too
    /// short) to 4 (excellent), on the scale of `password_strength_bits`.
    pub strength: Vec<u32>,
    pub pwned: FfiPwnedStatus,
    /// Prefixes the core asked for and found no response for, sorted.
    pub missing_prefixes: Vec<String>,
    /// `missing_2fa` and `passkey_available` ran.
    pub sites_checked: bool,
}

/// Serves the caller's responses and records what is missing.
struct HeldRanges {
    bodies: HashMap<String, Vec<u8>>,
    missing: BTreeSet<String>,
}

impl RangeSource for HeldRanges {
    fn range(&mut self, prefix: &str) -> onepass_core::Result<Vec<u8>> {
        match self.bodies.get(prefix) {
            Some(body) => Ok(body.clone()),
            None => {
                self.missing.insert(prefix.to_owned());
                Err(Error::NotFound)
            }
        }
    }
}

fn sites(options: &FfiWatchtowerOptions) -> Option<SiteDirectory> {
    // A pack that does not parse means no site checks, never an error.
    let bytes = options.site_pack.as_deref()?;
    site_pack::parse(bytes)
        .ok()
        .map(|pack| SiteDirectory::from_site_pack(&pack))
        .filter(|d| !d.is_empty())
}

fn strength_levels(items: &[Item]) -> Vec<u32> {
    let mut levels = vec![0u32; STRENGTH_THRESHOLDS.len() + 1];
    let fields = items
        .iter()
        .filter(|i| i.trashed_at.is_none() && !i.archived)
        .flat_map(|i| i.sections.iter().flat_map(|s| s.fields.iter()));
    for field in fields {
        let FieldValue::Password(p) = &field.value else {
            continue;
        };
        if p.is_empty() {
            continue;
        }
        let bits = generator::strength_bits(p);
        let level = STRENGTH_THRESHOLDS.iter().filter(|t| bits >= **t).count();
        if let Some(slot) = levels.get_mut(level) {
            *slot = slot.saturating_add(1);
        }
    }
    levels
}

fn pwned_to_ffi(status: &PwnedStatus) -> FfiPwnedStatus {
    match status {
        PwnedStatus::Checked => FfiPwnedStatus::Checked,
        PwnedStatus::Partial { failed_prefixes } => FfiPwnedStatus::Partial {
            failed_prefixes: *failed_prefixes,
        },
        PwnedStatus::Unavailable => FfiPwnedStatus::Unavailable,
        PwnedStatus::Disabled => FfiPwnedStatus::Disabled,
    }
}

/// Runs the analysis on items already copied out of the session.
pub(crate) fn report(
    items: &[Item],
    options: &FfiWatchtowerOptions,
    key_use_since: Option<OffsetDateTime>,
) -> FfiWatchtowerReport {
    let now = OffsetDateTime::now_utc();
    let mut opts = Options::new(now.date()).with_key_use(now, key_use_since);
    opts.expiry_warning_days = options.expiry_warning_days;
    opts.old_password_days = options.old_password_days;
    let directory = sites(options);
    let breaches = options
        .breach_catalog
        .as_deref()
        .and_then(|json| BreachCatalog::from_hibp(json).ok());
    let mut held = options.ranges.as_ref().map(|ranges| HeldRanges {
        bodies: ranges
            .iter()
            .map(|r| (r.prefix.to_ascii_uppercase(), r.body.clone()))
            .collect(),
        missing: BTreeSet::new(),
    });
    let core = analyze(
        items,
        &opts,
        Sources {
            pwned: held.as_mut().map(|h| h as &mut dyn RangeSource),
            sites: directory.as_ref(),
            breaches: breaches.as_ref(),
        },
    );
    let mut by_check: BTreeMap<Check, (u32, BTreeSet<Id>)> = BTreeMap::new();
    let mut links: BTreeMap<Check, BTreeMap<Id, FfiSiteLink>> = BTreeMap::new();
    for f in &core.findings {
        let entry = by_check.entry(f.check).or_default();
        entry.0 = entry.0.saturating_add(1);
        entry.1.insert(f.item_id);
        if let Detail::Site {
            documentation,
            host,
            settings_url,
            recipe,
        } = &f.detail
        {
            links
                .entry(f.check)
                .or_default()
                .entry(f.item_id)
                .or_insert_with(|| FfiSiteLink {
                    item_id: id_hex(f.item_id),
                    host: host.clone(),
                    settings_url: settings_url.clone(),
                    help_url: documentation.clone(),
                    has_recipe: *recipe,
                });
        }
    }
    let checks = Check::ALL
        .iter()
        .map(|check| {
            let (findings, ids) = by_check.remove(check).unwrap_or_default();
            let mut site_links: Vec<FfiSiteLink> = links
                .remove(check)
                .map(|m| m.into_values().collect())
                .unwrap_or_default();
            site_links.sort_by(|a, b| a.item_id.cmp(&b.item_id));
            FfiWatchtowerCheck {
                check: check.id().to_owned(),
                findings,
                item_ids: ids.into_iter().map(id_hex).collect(),
                site_links,
            }
        })
        .collect();
    let items_analyzed = items
        .iter()
        .filter(|i| i.trashed_at.is_none() && !i.archived)
        .count();
    FfiWatchtowerReport {
        score: core.score,
        items_analyzed: u32::try_from(items_analyzed).unwrap_or(u32::MAX),
        checks,
        strength: strength_levels(items),
        pwned: pwned_to_ffi(&core.pwned),
        missing_prefixes: held
            .map(|h| h.missing.into_iter().collect())
            .unwrap_or_default(),
        sites_checked: core.sites_checked,
    }
}

#[uniffi::export]
impl Session {
    /// Watchtower report of every vault but `excluded_vault_ids`. Local
    /// checks always run; breach lookups use `options.ranges` only (no
    /// network in the core). Never returns a field value.
    pub fn watchtower_report(
        &self,
        options: FfiWatchtowerOptions,
    ) -> Result<FfiWatchtowerReport, OnePassError> {
        let excluded = options
            .excluded_vault_ids
            .iter()
            .map(|id| parse_id(id))
            .collect::<Result<BTreeSet<Id>, _>>()?;
        // Copied under the lock, analyzed outside of it.
        let (items, key_use_since) = self.with(|repo| {
            let mut out = Vec::new();
            for vault in repo.vaults()? {
                if excluded.contains(&vault.id) {
                    continue;
                }
                out.extend(repo.items(&vault)?);
            }
            // A failed read means the warm-up is not established: no key is
            // reported dormant.
            let since = repo.key_use_since().ok().flatten();
            Ok((out, since))
        })?;
        Ok(report(&items, &options, key_use_since))
    }
}

/// Verifies a downloaded site pack against the manifest, its signature and
/// the 32-byte Ed25519 `public_key`, and returns its version. A bad
/// signature, size or hash is `Integrity { kind: "site_pack" }`; a pack that
/// is signed but malformed is `InvalidInput { what: "site_pack" }`.
#[uniffi::export]
pub fn verify_site_pack(
    manifest: Vec<u8>,
    signature: Vec<u8>,
    pack: Vec<u8>,
    public_key: Vec<u8>,
) -> Result<u64, OnePassError> {
    match site_pack::verify_signed(&manifest, &signature, &pack, &public_key) {
        Ok(parsed) => Ok(parsed.version),
        Err(Error::Integrity(IntegrityError::Signature | IntegrityError::ManifestItemMismatch)) => {
            Err(OnePassError::Integrity {
                kind: "site_pack".to_owned(),
            })
        }
        Err(_) => Err(OnePassError::InvalidInput {
            what: "site_pack".to_owned(),
        }),
    }
}

/// Version of an already verified pack (the bundled copy or the cache).
#[uniffi::export]
pub fn site_pack_version(pack: Vec<u8>) -> Result<u64, OnePassError> {
    site_pack::parse(&pack)
        .map(|p| p.version)
        .map_err(|_| OnePassError::InvalidInput {
            what: "site_pack".to_owned(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn held_ranges_record_missing_prefixes_once() {
        let mut held = HeldRanges {
            bodies: HashMap::from([("ABCDE".to_owned(), b"X:1".to_vec())]),
            missing: BTreeSet::new(),
        };
        assert!(held.range("ABCDE").is_ok());
        assert!(held.range("12345").is_err());
        assert!(held.range("12345").is_err());
        assert_eq!(held.missing.len(), 1);
    }

    #[test]
    fn dormant_check_is_listed_and_waits_for_the_warm_up() {
        use onepass_core::model::{ItemType, new_item};
        let mut key = new_item(ItemType::ApiCredential, Id([1; 16]), "Key");
        key.created_at = OffsetDateTime::now_utc() - time::Duration::days(200);
        let options = FfiWatchtowerOptions {
            expiry_warning_days: 30,
            old_password_days: 365,
            ranges: None,
            excluded_vault_ids: vec![],
            breach_catalog: None,
            site_pack: None,
        };
        let count = |since| {
            let r = report(std::slice::from_ref(&key), &options, since);
            r.checks
                .iter()
                .find(|c| c.check == "dormant")
                .map(|c| c.findings)
        };
        assert_eq!(count(None), Some(0));
        let old = OffsetDateTime::now_utc() - time::Duration::days(100);
        assert_eq!(count(Some(old)), Some(1));
    }
}
