//! Watchtower: local password and site checks (milestone 5).
//!
//! [`analyze`] performs no I/O: breach lookups go through a
//! [`RangeSource`] and the site catalogs are loaded by the caller. Trashed
//! and archived items are skipped. A report names a field by its id, never
//! by its value.

#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

pub mod checks;
pub mod host;
pub mod pwned;
pub mod score;
pub mod sites;

use std::collections::BTreeMap;

use serde::Serialize;
use time::Date;

use crate::model::Item;

pub use checks::{Check, Detail, Finding, Severity};
pub use pwned::{DirRangeSource, RangeSource, parse_range};
pub use score::VaultScore;
pub use sites::{Breach, BreachCatalog, SiteDirectory, SiteInfo};

/// Thresholds of an analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Options {
    pub today: Date,
    /// Days before a deadline when an expiration becomes a warning.
    pub expiry_warning_days: u16,
    /// Age (days) from which a password is "old".
    pub old_password_days: u16,
}

impl Options {
    /// Defaults: warn 30 days before an expiration, passwords old at 365 days.
    pub fn new(today: Date) -> Options {
        Options {
            today,
            expiry_warning_days: 30,
            old_password_days: 365,
        }
    }
}

/// External data for the checks that need it.
pub struct Sources<'a> {
    /// `None`: breach lookups disabled (strict offline mode).
    pub pwned: Option<&'a mut dyn RangeSource>,
    /// 2FA and passkey support.
    pub sites: Option<&'a SiteDirectory>,
    /// Breached sites.
    pub breaches: Option<&'a BreachCatalog>,
}

impl Sources<'_> {
    /// No external data: local checks only.
    pub fn none() -> Sources<'static> {
        Sources {
            pwned: None,
            sites: None,
            breaches: None,
        }
    }
}

/// Outcome of the breach lookups.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum PwnedStatus {
    Checked,
    Partial { failed_prefixes: u32 },
    Unavailable,
    Disabled,
}

/// Result of [`analyze`]. Carries ids, dates and counts, never a secret.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Report {
    /// Global score, 0 to 100.
    pub score: u8,
    pub vaults: Vec<VaultScore>,
    /// Sorted by vault, item, check, then field id.
    pub findings: Vec<Finding>,
    pub counts: BTreeMap<Check, u32>,
    pub pwned: PwnedStatus,
    /// `missing_2fa` and `passkey_available` ran.
    pub sites_checked: bool,
    /// `breached_site` ran.
    pub breaches_checked: bool,
}

/// Runs every check on `items` (spec 3.2) and scores the result (spec 3.5).
pub fn analyze(items: &[Item], opts: &Options, sources: Sources<'_>) -> Report {
    let Sources {
        pwned,
        sites,
        breaches,
    } = sources;
    let analyzed: Vec<&Item> = items
        .iter()
        .filter(|i| i.trashed_at.is_none() && !i.archived)
        .collect();
    let mut findings = checks::local_findings(&analyzed, opts);
    let pwned_status = match pwned {
        Some(source) => {
            let (found, status) = pwned::pwned_findings(&analyzed, source);
            findings.extend(found);
            status
        }
        None => PwnedStatus::Disabled,
    };
    if let Some(dir) = sites {
        sites::site_findings(&analyzed, dir, &mut findings);
    }
    if let Some(catalog) = breaches {
        sites::breach_findings(&analyzed, catalog, &mut findings);
    }
    // Last: it reads the compromised, reused and weak findings.
    let exposed = sites::provider_findings(&analyzed, &findings);
    findings.extend(exposed);
    findings.sort_by(|a, b| {
        (a.vault_id, a.item_id, a.check, &a.field_id).cmp(&(
            b.vault_id,
            b.item_id,
            b.check,
            &b.field_id,
        ))
    });
    let mut counts = BTreeMap::new();
    for f in &findings {
        *counts.entry(f.check).or_insert(0u32) += 1;
    }
    let (score, vaults) = score::scores(&analyzed, &findings);
    Report {
        score,
        vaults,
        findings,
        counts,
        pwned: pwned_status,
        sites_checked: sites.is_some(),
        breaches_checked: breaches.is_some(),
    }
}
