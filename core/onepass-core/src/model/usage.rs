//! Per-site fill memory of an item: which form shape a site showed, what
//! the fill did there, how often.
//!
//! Wire format: `Item` skips `usage` in its own serde form, so the MCP and
//! the CLI never list it. `vault::encode_item` writes it as a second sealed
//! trailer, a `UsageTrailer` after the `ItemTrailer` of `model::events`
//! (written even empty, so the usage always sits second). An item without
//! usage is written exactly as before. A trailer a build cannot read opens
//! the item without usage, never fails it. A usage write leaves
//! `updated_at` alone, and the sync rebase always lets a remote edit win
//! over a local change that touched only the usage, then carries the local
//! usage over (`merge_trailers`). Forgetting a site leaves a tombstone in
//! the trailer, so the union of that merge does not bring the site back.

use std::cmp::Reverse;
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};

use crate::fill_plan::context::FieldRole;
use crate::fill_plan::intent::Intent;
use crate::fill_plan::score::UsageSignal;
use crate::id::Id;
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

/// A site forgotten on purpose, and when: an entry for it no newer than
/// this is dropped wherever it comes from, so a forget survives the union
/// of a sync merge.
pub type Forgotten = (String, OffsetDateTime);

/// The second trailer of a sealed item, after `ItemTrailer`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageTrailer {
    pub sites: Vec<SiteUsage>,
    pub forgotten: Vec<Forgotten>,
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

/// The newest tombstone per site, newest first then by site, at most
/// `MAX_SITES`.
fn settle_forgotten(forgotten: &mut Vec<Forgotten>) {
    let mut by_site: BTreeMap<String, OffsetDateTime> = BTreeMap::new();
    for (site, at) in forgotten.drain(..) {
        let e = by_site.entry(site).or_insert(at);
        *e = (*e).max(at);
    }
    forgotten.extend(by_site);
    forgotten.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    forgotten.truncate(MAX_SITES);
}

/// Drop every entry at or before its site's tombstone.
fn bury(sites: &mut Vec<SiteUsage>, forgotten: &[Forgotten]) {
    sites.retain(|u| {
        !forgotten
            .iter()
            .any(|(site, at)| *site == u.site && u.last_at <= *at)
    });
}

/// Union by site, uncapped (see `merge_usage`).
fn union(a: &[SiteUsage], b: &[SiteUsage]) -> Vec<SiteUsage> {
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
    by_site.into_values().collect()
}

/// Union by site: the larger `last_at` and `count`, the shape, intent and
/// steps of the more recent entry. Commutative, at most `MAX_SITES`.
/// Tombstones are not looked at: the sync merge uses `merge_trailers`.
pub fn merge_usage(a: &[SiteUsage], b: &[SiteUsage]) -> Vec<SiteUsage> {
    let mut out = union(a, b);
    settle(&mut out);
    out
}

/// Merge of two whole trailers: `merge_usage` of the sites, the newest
/// tombstone per site (at most `MAX_SITES`, the newest), and no site whose
/// `last_at` is at or before its tombstone. Commutative.
pub fn merge_trailers(a: &UsageTrailer, b: &UsageTrailer) -> UsageTrailer {
    let mut forgotten: Vec<Forgotten> = a.forgotten.iter().chain(&b.forgotten).cloned().collect();
    settle_forgotten(&mut forgotten);
    let mut sites = union(&a.sites, &b.sites);
    bury(&mut sites, &forgotten);
    settle(&mut sites);
    UsageTrailer { sites, forgotten }
}

/// The one item among `items` used last on `site`: the latest `last_at`, a
/// tie to the higher count, then the lowest item id. The caller passes the
/// candidates of one kind, so there is exactly one `last_on_site` per kind.
pub fn last_used_on<'a>(items: impl IntoIterator<Item = &'a Item>, site: &str) -> Option<Id> {
    items
        .into_iter()
        .filter_map(|i| {
            i.usage_on(site)
                .map(|u| (u.last_at, u.count, Reverse(i.id), i.id))
        })
        .max()
        .map(|(.., id)| id)
}

impl Item {
    /// Remember a fill of `u.site` at `now`. `true` when the item must be
    /// saved: the site is new for it, or its shape or intent changed, or its
    /// last use is older than `REWRITE_AFTER_SECS`, and the entry is still
    /// there after the cap. Otherwise nothing is written. Entries and
    /// tombstones older than `USAGE_TTL_DAYS` are dropped, at most
    /// `MAX_SITES` of each kept (the most recent). Never touches
    /// `updated_at`.
    pub fn note_usage(&mut self, u: SiteUsage, now: OffsetDateTime) -> bool {
        self.note_usage_with(u, now, false)
    }

    /// `note_usage`, with `force` rewriting a known entry within
    /// `REWRITE_AFTER_SECS` too: another item used the site after this one,
    /// so this entry must become the newest again (`Repository::record_usage`).
    pub fn note_usage_with(&mut self, u: SiteUsage, now: OffsetDateTime, force: bool) -> bool {
        let cutoff = now - Duration::days(USAGE_TTL_DAYS);
        self.usage.retain(|e| e.last_at >= cutoff);
        self.usage_forgotten.retain(|(_, at)| *at >= cutoff);
        let site = u.site.clone();
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
                let write = changed || stale || force;
                if write {
                    *e = SiteUsage {
                        count: e.count.saturating_add(1),
                        last_at: now.max(e.last_at),
                        ..u
                    };
                }
                write
            }
        };
        bury(&mut self.usage, &self.usage_forgotten);
        settle(&mut self.usage);
        write && self.usage.iter().any(|e| e.site == site)
    }

    /// What this item remembers of `site`.
    pub fn usage_on(&self, site: &str) -> Option<&SiteUsage> {
        self.usage.iter().find(|e| e.site == site)
    }

    /// The ranking signal of this item's memory of `site`, for
    /// `fill_plan::score`: `last` is `last_used_on` of the candidates,
    /// `shape` the form shape of the page if known.
    pub fn usage_signal(
        &self,
        site: &str,
        last: Option<Id>,
        shape: Option<[u8; 16]>,
    ) -> Option<UsageSignal> {
        self.usage_on(site).map(|u| UsageSignal {
            last_on_site: Some(self.id) == last,
            same_shape: Some(u.form_shape_hash) == shape,
            count: u.count,
            last_at: u.last_at.unix_timestamp(),
        })
    }

    /// Another of `others` (the caller keeps the eligible items of this
    /// item's kind) used `site` after this item did: a new use of this item
    /// must then be written even within `REWRITE_AFTER_SECS`, or the other
    /// stays the last used there (A, B, then A within the hour).
    pub fn used_later_by_another<'a>(
        &self,
        site: &str,
        others: impl IntoIterator<Item = &'a Item>,
    ) -> bool {
        self.site_last_at(site).is_some_and(|own| {
            others
                .into_iter()
                .filter(|o| o.id != self.id)
                .filter_map(|o| o.site_last_at(site))
                .any(|at| at > own)
        })
    }

    /// When this item last filled `site`, if it remembers it.
    pub fn site_last_at(&self, site: &str) -> Option<OffsetDateTime> {
        self.usage
            .iter()
            .find(|e| e.site == site)
            .map(|e| e.last_at)
    }

    /// Drop what this item remembers of `site` and leave a tombstone at
    /// `now` (or the entry's own `last_at` if a clock ran ahead), so
    /// another device's copy of the entry does not come back with the next
    /// sync. `true` if it had any (the item must be saved).
    pub fn forget_site_usage(&mut self, site: &str, now: OffsetDateTime) -> bool {
        let Some(at) = self
            .usage
            .iter()
            .filter(|e| e.site == site)
            .map(|e| e.last_at.max(now))
            .max()
        else {
            return false;
        };
        self.usage.retain(|e| e.site != site);
        let cutoff = now - Duration::days(USAGE_TTL_DAYS);
        self.usage_forgotten.retain(|(_, t)| *t >= cutoff);
        self.usage_forgotten.push((site.to_owned(), at));
        settle_forgotten(&mut self.usage_forgotten);
        true
    }

    /// The usage and its tombstones, as sealed.
    pub fn usage_trailer(&self) -> UsageTrailer {
        UsageTrailer {
            sites: self.usage.clone(),
            forgotten: self.usage_forgotten.clone(),
        }
    }

    pub fn set_usage_trailer(&mut self, t: UsageTrailer) {
        self.usage = t.sites;
        self.usage_forgotten = t.forgotten;
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
    fn last_used_on_breaks_ties_by_count_then_lowest_id() {
        let t1 = T0 + Duration::minutes(1);
        let (mut a, mut b, c) = (item(), item(), item());
        a.id = Id([2; 16]);
        b.id = Id([1; 16]);
        assert_eq!(last_used_on([&a, &b, &c], "example.com"), None);
        a.note_usage(usage("example.com", LOGIN, T0), T0);
        b.note_usage(usage("example.com", LOGIN, T0), T0);
        assert_eq!(last_used_on([&a, &b], "example.com"), Some(b.id));
        a.note_usage_with(usage("example.com", LOGIN, T0), T0, true);
        assert_eq!(last_used_on([&a, &b], "example.com"), Some(a.id));
        b.note_usage_with(usage("example.com", LOGIN, t1), t1, true);
        assert_eq!(last_used_on([&a, &b, &c], "example.com"), Some(b.id));
        let signal = |i: &Item| i.usage_signal("example.com", Some(b.id), None);
        assert!(signal(&b).is_some_and(|u| u.last_on_site && !u.same_shape));
        assert!(signal(&a).is_some_and(|u| !u.last_on_site && u.count == 2));
        assert_eq!(signal(&c), None);
    }

    #[test]
    fn used_later_by_another_needs_an_own_entry_and_a_later_other() {
        let t1 = T0 + Duration::minutes(1);
        let (mut a, mut b) = (item(), item());
        assert!(!a.used_later_by_another("example.com", [&b]));
        b.note_usage(usage("example.com", LOGIN, T0), T0);
        assert!(!a.used_later_by_another("example.com", [&b]));
        a.note_usage(usage("example.com", LOGIN, t1), t1);
        assert!(!a.used_later_by_another("example.com", [&a, &b]));
        assert!(b.used_later_by_another("example.com", [&a, &b]));
        assert!(!b.used_later_by_another("other.com", [&a, &b]));
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
        assert!(it.forget_site_usage("a.com", T0));
        assert_eq!(it.usage.len(), 1);
        assert_eq!(it.usage[0].site, "b.com");
        assert!(!it.forget_site_usage("a.com", T0));
    }

    #[test]
    fn forget_leaves_a_tombstone_and_refreshes_it() {
        let mut it = item();
        it.note_usage(usage("a.com", LOGIN, T0), T0);
        let t1 = T0 + Duration::hours(1);
        assert!(it.forget_site_usage("a.com", t1));
        assert_eq!(it.usage_forgotten, vec![("a.com".to_owned(), t1)]);
        // Used again later: allowed, and survives its own tombstone.
        let t2 = t1 + Duration::hours(1);
        assert!(it.note_usage(usage("a.com", LOGIN, t2), t2));
        assert_eq!(it.usage.len(), 1);
        let t3 = t2 + Duration::hours(1);
        assert!(it.forget_site_usage("a.com", t3));
        assert_eq!(it.usage_forgotten, vec![("a.com".to_owned(), t3)]);
    }

    #[test]
    fn merge_drops_sites_forgotten_since() {
        let mine = UsageTrailer {
            sites: vec![usage("b.com", LOGIN, T0)],
            forgotten: vec![("a.com".into(), T0 + Duration::hours(2))],
        };
        let theirs = UsageTrailer {
            sites: vec![
                usage("a.com", LOGIN, T0 + Duration::hours(1)),
                usage("c.com", LOGIN, T0),
            ],
            forgotten: vec![
                ("a.com".into(), T0),
                ("b.com".into(), T0 - Duration::hours(1)),
            ],
        };
        let m = merge_trailers(&mine, &theirs);
        let sites: Vec<&str> = m.sites.iter().map(|u| u.site.as_str()).collect();
        assert_eq!(sites, ["b.com", "c.com"]);
        assert!(
            m.forgotten
                .contains(&("a.com".into(), T0 + Duration::hours(2)))
        );
        assert!(!m.forgotten.contains(&("a.com".into(), T0)));
        // A use after the forget comes back.
        let again = UsageTrailer {
            sites: vec![usage("a.com", LOGIN, T0 + Duration::hours(3))],
            forgotten: vec![],
        };
        assert_eq!(merge_trailers(&mine, &again).sites.len(), 2);
    }

    #[test]
    fn tombstones_expire_and_are_capped() {
        let mut it = item();
        for i in 0..25 {
            let at = T0 + Duration::minutes(i);
            let site = format!("s{i}.com");
            it.note_usage(usage(&site, LOGIN, at), at);
            it.forget_site_usage(&site, at);
        }
        assert_eq!(it.usage_forgotten.len(), MAX_SITES);
        assert_eq!(it.usage_forgotten[0].0, "s24.com");
        let later = T0 + Duration::days(USAGE_TTL_DAYS + 1);
        it.note_usage(usage("new.com", LOGIN, later), later);
        assert!(it.usage_forgotten.is_empty());
    }

    #[test]
    fn note_usage_is_false_when_the_entry_is_capped_away() {
        let mut it = item();
        // Twenty sites stamped by a clock ahead of this one.
        for i in 0..20 {
            let at = T0 + Duration::days(1) + Duration::minutes(i);
            it.note_usage(usage(&format!("s{i}.com"), LOGIN, at), at);
        }
        assert!(!it.note_usage(usage("late.com", LOGIN, T0), T0));
        assert!(it.usage.iter().all(|u| u.site != "late.com"));
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
    fn forced_write_within_hour_moves_last_at() {
        let mut it = item();
        it.note_usage(usage("example.com", LOGIN, T0), T0);
        let later = T0 + Duration::minutes(20);
        assert!(it.note_usage_with(usage("example.com", LOGIN, later), later, true));
        assert_eq!(it.usage[0].count, 2);
        assert_eq!(it.usage[0].last_at, later);
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
        it.forget_site_usage("example.com", T0);
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

        #[test]
        fn trailer_merge_is_commutative_and_honours_tombstones(
            a in arb_trailer(),
            b in arb_trailer(),
        ) {
            let m = merge_trailers(&a, &b);
            prop_assert_eq!(&m, &merge_trailers(&b, &a));
            prop_assert!(m.forgotten.len() <= MAX_SITES);
            for u in &m.sites {
                prop_assert!(!m.forgotten.iter().any(|(s, at)| *s == u.site && u.last_at <= *at));
            }
        }
    }

    fn arb_trailer() -> impl Strategy<Value = UsageTrailer> {
        (
            prop::collection::vec(arb_usage(), 0..8),
            prop::collection::vec((0u8..6, 0i64..5), 0..4),
        )
            .prop_map(|(sites, gone)| UsageTrailer {
                sites,
                forgotten: gone
                    .into_iter()
                    .map(|(s, h)| (format!("s{s}.com"), T0 + Duration::hours(h)))
                    .collect(),
            })
    }
}
