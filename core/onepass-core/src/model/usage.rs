//! Per-site fill memory of an item: which form shape a site showed, what
//! the fill did there, how often.
//!
//! Wire format: `Item` skips `usage` in its own serde form, so the MCP and
//! the CLI never list it. `vault::encode_item` writes it as a second sealed
//! trailer, a `UsageTrailer` after the `ItemTrailer` of `model::events`
//! (written even empty, so the usage always sits second). An item without
//! usage is written exactly as before. A trailer a build cannot read opens
//! the item without usage, never fails it. A usage write leaves
//! `updated_at` alone, so any real edit from another device wins the sync
//! rebase, which then carries the local usage over (`merge_usage`).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};

use crate::fill_plan::context::FieldRole;
use crate::fill_plan::intent::Intent;
use crate::model::item::Item;

/// Most sites remembered per item: the least recently used go first.
pub const MAX_SITES: usize = 20;
/// An entry unused this long is dropped at the next write.
pub const USAGE_TTL_DAYS: i64 = 365;
/// A known site with the same shape and intent is rewritten only once its
/// last use is this old: repeated fills do not churn the sealed record.
pub const REWRITE_AFTER_SECS: i64 = 3600;

/// One step of a fill. Postcard encodes variants by index: new variants
/// must only ever be appended (pinned by `model::wire_tests`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StepKind {
    Fill,
    Otp,
    ProviderClick,
    Account,
}

/// What a site looked like the last time this item filled it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SiteUsage {
    /// Registrable domain (eTLD+1).
    pub site: String,
    /// `form_shape_hash` of the field roles, in page order. No page text.
    pub form_shape_hash: [u8; 16],
    pub intent: Intent,
    pub step_seq: Vec<StepKind>,
    pub count: u32,
    pub last_at: OffsetDateTime,
}

/// The second trailer of a sealed item, after `ItemTrailer`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageTrailer {
    pub sites: Vec<SiteUsage>,
}

/// First 16 bytes of the SHA-256 of the role names (their serde names)
/// joined by `,`.
pub fn form_shape_hash(roles: &[FieldRole]) -> [u8; 16] {
    let names: Vec<String> = roles
        .iter()
        .map(|r| match serde_json::to_value(r) {
            Ok(serde_json::Value::String(s)) => s,
            _ => String::new(),
        })
        .collect();
    let d = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, names.join(",").as_bytes());
    let mut out = [0u8; 16];
    out.copy_from_slice(&d.as_ref()[..16]);
    out
}

/// Of two entries for one site, the one whose shape, intent and steps are
/// kept: the later `last_at`, a tie to the larger encoding of the shape,
/// intent and steps. A total order on what is kept, so the merge gives the
/// same answer whatever the order of its inputs.
fn newer<'a>(a: &'a SiteUsage, b: &'a SiteUsage) -> &'a SiteUsage {
    let key = |u: &SiteUsage| {
        let shape = postcard::to_allocvec(&(&u.form_shape_hash, u.intent, &u.step_seq));
        (u.last_at, shape.unwrap_or_default())
    };
    if key(a) >= key(b) { a } else { b }
}

/// Most recent first, then by site: the stored order, and the order the
/// cap keeps.
fn settle(sites: &mut Vec<SiteUsage>) {
    sites.sort_by(|a, b| b.last_at.cmp(&a.last_at).then_with(|| a.site.cmp(&b.site)));
    sites.truncate(MAX_SITES);
}

/// Union by site: the larger `last_at` and `count`, the shape, intent and
/// steps of the more recent entry. Commutative, at most `MAX_SITES`.
pub fn merge_usage(a: &[SiteUsage], b: &[SiteUsage]) -> Vec<SiteUsage> {
    let mut by_site: BTreeMap<&str, SiteUsage> = BTreeMap::new();
    for u in a.iter().chain(b) {
        let merged = match by_site.get(u.site.as_str()) {
            None => u.clone(),
            Some(prev) => SiteUsage {
                count: prev.count.max(u.count),
                last_at: prev.last_at.max(u.last_at),
                ..newer(prev, u).clone()
            },
        };
        by_site.insert(&u.site, merged);
    }
    let mut out: Vec<SiteUsage> = by_site.into_values().collect();
    settle(&mut out);
    out
}

impl Item {
    /// Remember a fill of `u.site` at `now`. `true` when the item must be
    /// saved: the site is new for it, or its shape or intent changed, or its
    /// last use is older than `REWRITE_AFTER_SECS`. Otherwise nothing is
    /// written. Entries older than `USAGE_TTL_DAYS` are dropped, at most
    /// `MAX_SITES` kept (the most recent). Never touches `updated_at`.
    pub fn note_usage(&mut self, u: SiteUsage, now: OffsetDateTime) -> bool {
        let cutoff = now - Duration::days(USAGE_TTL_DAYS);
        self.usage.retain(|e| e.last_at >= cutoff);
        let write = match self.usage.iter_mut().find(|e| e.site == u.site) {
            None => {
                self.usage.push(SiteUsage {
                    count: u.count.max(1),
                    last_at: now,
                    ..u
                });
                true
            }
            Some(e) => {
                let changed = e.form_shape_hash != u.form_shape_hash || e.intent != u.intent;
                let stale = now - e.last_at >= Duration::seconds(REWRITE_AFTER_SECS);
                if changed || stale {
                    *e = SiteUsage {
                        count: e.count.saturating_add(1),
                        last_at: now.max(e.last_at),
                        ..u
                    };
                }
                changed || stale
            }
        };
        settle(&mut self.usage);
        write
    }

    /// Drop what this item remembers of `site`. `true` if it had any.
    pub fn forget_site_usage(&mut self, site: &str) -> bool {
        let before = self.usage.len();
        self.usage.retain(|e| e.site != site);
        self.usage.len() != before
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use time::macros::datetime;

    use super::*;
    use crate::Id;
    use crate::model::{ItemType, new_item};

    const T0: OffsetDateTime = datetime!(2026-10-28 12:00 UTC);

    fn item() -> Item {
        new_item(ItemType::Login, Id::new(), "Example")
    }

    fn usage(site: &str, roles: &[FieldRole], at: OffsetDateTime) -> SiteUsage {
        SiteUsage {
            site: site.into(),
            form_shape_hash: form_shape_hash(roles),
            intent: Intent::Login,
            step_seq: vec![StepKind::Fill],
            count: 1,
            last_at: at,
        }
    }

    const LOGIN: &[FieldRole] = &[FieldRole::Username, FieldRole::CurrentPassword];

    #[test]
    fn form_shape_hash_is_sha256_of_role_names() {
        let d = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, b"username,current_password");
        assert_eq!(form_shape_hash(LOGIN), d.as_ref()[..16]);
        // Order counts.
        assert_ne!(
            form_shape_hash(&[FieldRole::CurrentPassword, FieldRole::Username]),
            form_shape_hash(LOGIN)
        );
    }

    #[test]
    fn first_use_writes() {
        let mut it = item();
        assert!(it.note_usage(usage("example.com", LOGIN, T0), T0));
        assert_eq!(it.usage.len(), 1);
        assert_eq!(it.usage[0].count, 1);
        assert_eq!(it.usage[0].last_at, T0);
    }

    #[test]
    fn forget_site_usage_removes_only_that_site() {
        let mut it = item();
        it.note_usage(usage("a.com", LOGIN, T0), T0);
        it.note_usage(usage("b.com", LOGIN, T0), T0);
        assert!(it.forget_site_usage("a.com"));
        assert_eq!(it.usage.len(), 1);
        assert_eq!(it.usage[0].site, "b.com");
        assert!(!it.forget_site_usage("a.com"));
    }

    #[test]
    fn same_site_within_hour_does_not_write() {
        let mut it = item();
        it.note_usage(usage("example.com", LOGIN, T0), T0);
        let later = T0 + Duration::minutes(59);
        assert!(!it.note_usage(usage("example.com", LOGIN, later), later));
        assert_eq!(it.usage[0].count, 1);
        assert_eq!(it.usage[0].last_at, T0);
    }

    #[test]
    fn shape_change_writes() {
        let mut it = item();
        it.note_usage(usage("example.com", LOGIN, T0), T0);
        let later = T0 + Duration::minutes(5);
        let otp = usage("example.com", &[FieldRole::Otp], later);
        assert!(it.note_usage(otp.clone(), later));
        assert_eq!(it.usage[0].form_shape_hash, otp.form_shape_hash);
        // An intent change alone writes too.
        let mut signup = otp;
        signup.intent = Intent::Signup;
        assert!(it.note_usage(signup, later));
        assert_eq!(it.usage[0].intent, Intent::Signup);
    }

    #[test]
    fn after_an_hour_writes_and_counts() {
        let mut it = item();
        it.note_usage(usage("example.com", LOGIN, T0), T0);
        let later = T0 + Duration::seconds(REWRITE_AFTER_SECS);
        assert!(it.note_usage(usage("example.com", LOGIN, later), later));
        assert_eq!(it.usage.len(), 1);
        assert_eq!(it.usage[0].count, 2);
        assert_eq!(it.usage[0].last_at, later);
    }

    #[test]
    fn never_touches_updated_at() {
        let mut it = item();
        let before = it.updated_at;
        it.note_usage(usage("example.com", LOGIN, T0), T0);
        it.forget_site_usage("example.com");
        assert_eq!(it.updated_at, before);
    }

    #[test]
    fn keeps_twenty_most_recent_sites() {
        let mut it = item();
        for i in 0..25 {
            let at = T0 + Duration::minutes(i);
            assert!(it.note_usage(usage(&format!("s{i}.com"), LOGIN, at), at));
        }
        assert_eq!(it.usage.len(), MAX_SITES);
        assert!(
            it.usage
                .iter()
                .all(|u| u.last_at >= T0 + Duration::minutes(5))
        );
        assert_eq!(it.usage[0].site, "s24.com");
    }

    #[test]
    fn drops_entries_older_than_a_year() {
        let mut it = item();
        it.note_usage(usage("old.com", LOGIN, T0), T0);
        it.note_usage(
            usage("kept.com", LOGIN, T0 + Duration::days(10)),
            T0 + Duration::days(10),
        );
        let now = T0 + Duration::days(USAGE_TTL_DAYS + 1);
        assert!(it.note_usage(usage("new.com", LOGIN, now), now));
        let sites: Vec<&str> = it.usage.iter().map(|u| u.site.as_str()).collect();
        assert_eq!(sites, ["new.com", "kept.com"]);
    }

    #[test]
    fn merge_keeps_max_count_and_latest_shape() {
        let mut a = usage("example.com", LOGIN, T0 + Duration::hours(2));
        a.count = 3;
        let mut b = usage("example.com", &[FieldRole::Otp], T0 + Duration::hours(5));
        b.count = 2;
        b.intent = Intent::Otp;
        let only_a = usage("a.com", LOGIN, T0);
        let m = merge_usage(&[a.clone(), only_a.clone()], &[b.clone()]);
        assert_eq!(m.len(), 2);
        let e = m.iter().find(|u| u.site == "example.com").unwrap();
        assert_eq!(e.count, 3);
        assert_eq!(e.last_at, b.last_at);
        assert_eq!(e.form_shape_hash, b.form_shape_hash);
        assert_eq!(e.intent, Intent::Otp);
        assert!(m.contains(&only_a));
        // Capped like a write.
        let many: Vec<SiteUsage> = (0..30)
            .map(|i| usage(&format!("s{i}.com"), LOGIN, T0 + Duration::minutes(i)))
            .collect();
        assert_eq!(merge_usage(&many, &[]).len(), MAX_SITES);
    }

    fn arb_usage() -> impl Strategy<Value = SiteUsage> {
        (
            0u8..6,
            any::<[u8; 16]>(),
            0usize..3,
            prop::collection::vec(0u8..4, 0..4),
            0u32..10,
            0i64..5,
        )
            .prop_map(|(site, hash, intent, steps, count, hours)| SiteUsage {
                site: format!("s{site}.com"),
                form_shape_hash: hash,
                intent: [Intent::Login, Intent::Otp, Intent::Signup][intent],
                step_seq: steps
                    .into_iter()
                    .map(|s| {
                        [
                            StepKind::Fill,
                            StepKind::Otp,
                            StepKind::ProviderClick,
                            StepKind::Account,
                        ][usize::from(s)]
                    })
                    .collect(),
                count,
                last_at: T0 + Duration::hours(hours),
            })
    }

    proptest! {
        #[test]
        fn merge_is_commutative(
            a in prop::collection::vec(arb_usage(), 0..8),
            b in prop::collection::vec(arb_usage(), 0..8),
        ) {
            prop_assert_eq!(merge_usage(&a, &b), merge_usage(&b, &a));
        }
    }
}
