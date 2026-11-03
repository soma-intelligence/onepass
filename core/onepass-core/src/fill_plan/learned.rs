//! Learned account preference: a score bonus per item from the autofill
//! history of a site (`crate::autofill_history`), added to the candidate
//! score of `fill_plan::score`.
//!
//! Version 1 is a deterministic scorer, not a trained model: decayed
//! frecency of the user's choices, in the same browser profile first and on
//! the site as a whole second, with a penalty for an item offered first and
//! passed over. Its inputs are exactly the features a trained ranker would
//! use (per site and per context choice counts, rank shown, the lists
//! shown, the age of each event), so a model trained later on the device
//! from the same history (pairwise logistic or LambdaMART over the `Shown`
//! lists and the choices that followed) replaces `affinity` behind the same
//! signature, with this scorer as its baseline and fallback.
//!
//! Scale: `CONTEXT_MAX` is above `LAST_ON_SITE`, so two choices of an
//! account in one browser profile put it first there even when another
//! profile used another account on the site last; a typed username
//! (`TYPED_USERNAME`) still wins over everything.

use std::collections::BTreeMap;

use time::OffsetDateTime;

use crate::autofill_history::{AutofillAction, AutofillEvent, ClientContext, expired};
use crate::id::Id;

/// Most bonus from the choices made in the same browser and profile.
pub const CONTEXT_MAX: f64 = 160.0;
/// Most bonus from the choices made on the site in any context.
pub const SITE_MAX: f64 = 40.0;
/// Most penalty for an item offered first and passed over (or dismissed).
pub const PENALTY_MAX: f64 = 40.0;
/// Weight of a choice halves every this many days.
pub const HALF_LIFE_DAYS: f64 = 30.0;
/// A dismissal weighs this much of a passed-over first offer.
const DISMISS_WEIGHT: f64 = 0.5;
/// A first candidate with at least this bonus counts as remembered for the
/// confidence of a plan.
pub const TRUST: i64 = 80;

fn decay(now: OffsetDateTime, at: OffsetDateTime) -> f64 {
    let days = ((now - at).as_seconds_f64() / 86_400.0).max(0.0);
    (0.5f64).powf(days / HALF_LIFE_DAYS)
}

#[derive(Default)]
struct Tally {
    by_item: BTreeMap<Id, f64>,
    total: f64,
}

impl Tally {
    fn add(&mut self, item: Id, w: f64) {
        *self.by_item.entry(item).or_default() += w;
        self.total += w;
    }

    /// The item's share of the choices, times the confidence in that
    /// share (`n / (n + 1)` over the decayed count `n`).
    fn part(&self, item: &Id) -> f64 {
        if self.total <= 0.0 {
            return 0.0;
        }
        let share = self.by_item.get(item).copied().unwrap_or(0.0) / self.total;
        share * self.total / (self.total + 1.0)
    }
}

/// The bonus of each item that has one, from the events of one site, for
/// a plan made in `client` at `now`. Expired events are ignored. Pure and
/// deterministic: the same events give the same bonuses.
pub fn affinity(
    events: &[AutofillEvent],
    client: &ClientContext,
    now: OffsetDateTime,
) -> BTreeMap<Id, i64> {
    let mut ctx = Tally::default();
    let mut site = Tally::default();
    let mut passed: BTreeMap<Id, f64> = BTreeMap::new();
    for e in events.iter().filter(|e| !expired(e, now)) {
        let Some(item) = e.item_id else { continue };
        let w = decay(now, e.at);
        let same = e.client.same_context(client);
        if e.is_choice() {
            site.add(item, w);
            if same {
                ctx.add(item, w);
            }
        } else if same {
            match e.action {
                AutofillAction::PickedOther => *passed.entry(item).or_default() += w,
                AutofillAction::Dismissed => {
                    *passed.entry(item).or_default() += w * DISMISS_WEIGHT;
                }
                _ => {}
            }
        }
    }
    let mut items: Vec<Id> = site.by_item.keys().chain(passed.keys()).copied().collect();
    items.sort();
    items.dedup();
    let mut out = BTreeMap::new();
    for item in items {
        let chosen = ctx.by_item.get(&item).copied().unwrap_or(0.0);
        let neg = passed.get(&item).copied().unwrap_or(0.0);
        let penalty = PENALTY_MAX * neg / (neg + chosen + 1.0);
        let bonus = CONTEXT_MAX * ctx.part(&item) + SITE_MAX * site.part(&item) - penalty;
        let b = bonus.round() as i64;
        if b != 0 {
            out.insert(item, b);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::autofill_history::{BrowserKind, EventSource};

    const NOW: i64 = 1_800_000_000;

    fn at(days_ago: i64) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(NOW - days_ago * 86_400).unwrap()
    }

    fn client(b: BrowserKind, profile: &str) -> ClientContext {
        ClientContext {
            browser: b,
            profile_id: Some(profile.into()),
            profile_name: None,
        }
    }

    fn ev(item: u8, action: AutofillAction, c: &ClientContext, days_ago: i64) -> AutofillEvent {
        AutofillEvent {
            at: at(days_ago),
            action,
            source: EventSource::Extension,
            site: "example.com".into(),
            item_id: Some(Id([item; 16])),
            rank: None,
            shown: vec![],
            client: c.clone(),
            device_id: None,
        }
    }

    #[test]
    fn no_history_no_bonus() {
        let c = client(BrowserKind::Chrome, "a");
        assert!(affinity(&[], &c, at(0)).is_empty());
    }

    #[test]
    fn choices_in_the_profile_lead_there_only() {
        let work = client(BrowserKind::Chrome, "work");
        let home = client(BrowserKind::Chrome, "home");
        let evs = vec![
            ev(1, AutofillAction::Picked, &work, 3),
            ev(1, AutofillAction::Picked, &work, 2),
            ev(2, AutofillAction::Picked, &home, 1),
            ev(2, AutofillAction::Picked, &home, 0),
        ];
        let w = affinity(&evs, &work, at(0));
        let h = affinity(&evs, &home, at(0));
        assert!(w[&Id([1; 16])] > w[&Id([2; 16])]);
        assert!(h[&Id([2; 16])] > h[&Id([1; 16])]);
        // Two choices in the profile beat `LAST_ON_SITE` (80).
        assert!(w[&Id([1; 16])] > crate::fill_plan::weights::LAST_ON_SITE);
    }

    #[test]
    fn exact_values_are_deterministic() {
        let c = client(BrowserKind::Safari, "s");
        let evs = vec![ev(1, AutofillAction::Picked, &c, 0)];
        // One fresh choice: ctx part = 1 * 1/2, site part = 1/2.
        assert_eq!(affinity(&evs, &c, at(0))[&Id([1; 16])], 100);
        // A month later the weight is halved: n = 0.5, part = 1/3.
        let later = OffsetDateTime::from_unix_timestamp(NOW + 30 * 86_400).unwrap();
        assert_eq!(affinity(&evs, &c, later)[&Id([1; 16])], 67);
    }

    #[test]
    fn other_browser_counts_for_the_site_only() {
        let chrome = client(BrowserKind::Chrome, "a");
        let safari = client(BrowserKind::Safari, "a");
        let evs = vec![ev(1, AutofillAction::Picked, &chrome, 0)];
        assert_eq!(affinity(&evs, &safari, at(0))[&Id([1; 16])], 20);
    }

    #[test]
    fn passed_over_first_offer_is_penalized() {
        let c = client(BrowserKind::Chrome, "a");
        let evs = vec![
            ev(1, AutofillAction::PickedOther, &c, 0),
            ev(1, AutofillAction::PickedOther, &c, 0),
            ev(2, AutofillAction::Picked, &c, 0),
            ev(2, AutofillAction::Picked, &c, 0),
        ];
        let a = affinity(&evs, &c, at(0));
        assert!(a[&Id([1; 16])] < 0);
        assert!(a[&Id([2; 16])] > 0);
    }

    #[test]
    fn expired_events_are_ignored() {
        let c = client(BrowserKind::Chrome, "a");
        let evs = vec![ev(1, AutofillAction::Picked, &c, 200)];
        assert!(affinity(&evs, &c, at(0)).is_empty());
    }

    #[test]
    fn shown_alone_is_no_choice() {
        let c = client(BrowserKind::Chrome, "a");
        let mut e = ev(1, AutofillAction::Shown, &c, 0);
        e.shown = vec![Id([1; 16])];
        assert!(affinity(&[e], &c, at(0)).is_empty());
    }
}
