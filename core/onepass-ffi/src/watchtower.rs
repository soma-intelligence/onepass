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
use onepass_core::watchtower::{
    Check, Options, PwnedStatus, RangeSource, SiteDirectory, Sources, analyze,
};
use onepass_core::{Error, Id};
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
    /// 2fa.directory v4 `all.json`. Without it, `missing_2fa` does not run.
    pub twofa_directory: Option<Vec<u8>>,
    /// passkeys-api v1 `all.json`, merged into the 2FA directory (or alone).
    pub passkeys_directory: Option<Vec<u8>>,
    /// Vaults left out of the analysis (hidden on this device).
    pub excluded_vault_ids: Vec<String>,
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
    let mut dir = match options.twofa_directory.as_deref() {
        Some(json) => SiteDirectory::from_2fa_directory(json).ok(),
        None => None,
    };
    if let Some(json) = options.passkeys_directory.as_deref() {
        let mut target = dir.take().unwrap_or_default();
        // A bad passkey document leaves the 2FA one usable.
        if target.add_passkeys_directory(json).is_ok() || !target.is_empty() {
            dir = Some(target);
        }
    }
    dir.filter(|d| !d.is_empty())
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
pub(crate) fn report(items: &[Item], options: &FfiWatchtowerOptions) -> FfiWatchtowerReport {
    let today = OffsetDateTime::now_utc().date();
    let mut opts = Options::new(today);
    opts.expiry_warning_days = options.expiry_warning_days;
    opts.old_password_days = options.old_password_days;
    let directory = sites(options);
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
            breaches: None,
        },
    );
    let mut by_check: BTreeMap<Check, (u32, BTreeSet<Id>)> = BTreeMap::new();
    for f in &core.findings {
        let entry = by_check.entry(f.check).or_default();
        entry.0 = entry.0.saturating_add(1);
        entry.1.insert(f.item_id);
    }
    let checks = Check::ALL
        .iter()
        .map(|check| {
            let (findings, ids) = by_check.remove(check).unwrap_or_default();
            FfiWatchtowerCheck {
                check: check.id().to_owned(),
                findings,
                item_ids: ids.into_iter().map(id_hex).collect(),
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
        let items = self.with(|repo| {
            let mut out = Vec::new();
            for vault in repo.vaults()? {
                if excluded.contains(&vault.id) {
                    continue;
                }
                out.extend(repo.items(&vault)?);
            }
            Ok(out)
        })?;
        Ok(report(&items, &options))
    }
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
    fn bad_passkeys_document_keeps_the_2fa_directory() {
        let options = FfiWatchtowerOptions {
            expiry_warning_days: 30,
            old_password_days: 365,
            ranges: None,
            twofa_directory: Some(br#"{"exemple.fr":{"methods":["totp"]}}"#.to_vec()),
            passkeys_directory: Some(b"not json".to_vec()),
            excluded_vault_ids: vec![],
        };
        let dir = sites(&options).unwrap();
        assert!(dir.lookup("exemple.fr").unwrap().totp);
    }
}
