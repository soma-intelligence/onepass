//! Candidate score, order and confidence (spec R4).
//!
//! Without usage memory and without a typed username the score is the match
//! quality alone: favorite, recency and frequency then only break ties in
//! `order`, which keeps the historic order of the two existing rankers.
//! The learned bonus of the autofill history (`fill_plan::learned`) is
//! added as it is: zero without history, so the order above is unchanged.

use super::weights::{
    ASSOCIATED, DOMAIN, EXACT, FAVORITE, FREQUENCY_MAX, LAST_ON_SITE, MARGIN, RECENCY_MAX,
    SAME_SHAPE, TYPED_USERNAME,
};
use serde::Serialize;

use crate::id::Id;

const DAY: i64 = 86_400;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MatchQuality {
    Exact,
    Domain,
    /// A domain known to share its credentials with the page's, never used
    /// there yet (`origin::item_match` makes it `Domain` once the item
    /// remembers the site). Offered in the menu, never chosen: a first
    /// candidate of this tier is `Low` confidence.
    Associated,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateKind {
    Login,
    Card,
    Identity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UsageSignal {
    pub last_on_site: bool,
    pub same_shape: bool,
    pub count: u32,
    /// Unix seconds.
    pub last_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub item_id: Id,
    pub kind: CandidateKind,
    pub quality: MatchQuality,
    pub favorite: bool,
    pub updated_at: i64,
    pub title: String,
    pub username_hash: Option<[u8; 32]>,
    pub usage: Option<UsageSignal>,
    /// A Login holding a one-time code secret (only these fill an Otp form).
    pub has_totp: bool,
    /// Learned bonus of the autofill history (`fill_plan::learned::affinity`)
    /// for the browser profile the plan is made in; 0 without history.
    pub affinity: i64,
    /// The item lives in a vault nobody else can write to (a personal
    /// vault). False for a shared vault, and whenever the caller does not
    /// know: only an item of the user's own gets the `sole_exact` trust,
    /// never one a member of a shared vault could have planted.
    pub private_vault: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tiebreak {
    /// Lowercase title (the bridge order).
    Title,
    /// Favorite first, then most recently updated (the FFI order).
    FavoriteThenRecent,
}

/// Ordered: `Low < Medium < High`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

fn recency(now: i64, last_at: i64) -> i64 {
    let age = now - last_at;
    let r = if age < DAY {
        5
    } else if age < 30 * DAY {
        3
    } else if age < 365 * DAY {
        1
    } else {
        0
    };
    r.min(RECENCY_MAX)
}

fn typed_match(c: &Candidate, typed: Option<&[u8; 32]>) -> bool {
    matches!((typed, c.username_hash.as_ref()), (Some(t), Some(h)) if t == h)
}

pub fn score(c: &Candidate, typed: Option<&[u8; 32]>, now: i64) -> i64 {
    let mut s = match c.quality {
        MatchQuality::Exact => EXACT,
        MatchQuality::Domain => DOMAIN,
        MatchQuality::Associated => ASSOCIATED,
        MatchQuality::Other => 0,
    };
    let typed_hit = typed_match(c, typed);
    if typed_hit {
        s += TYPED_USERNAME;
    }
    if c.usage.is_some() || typed_hit {
        if c.favorite {
            s += FAVORITE;
        }
        if let Some(u) = &c.usage {
            if u.last_on_site {
                s += LAST_ON_SITE;
            }
            if u.same_shape {
                s += SAME_SHAPE;
            }
            s += recency(now, u.last_at);
            s += i64::from(u.count).min(FREQUENCY_MAX);
        }
    }
    s + c.affinity
}

/// Score descending, then quality, then the tiebreak. Stable.
pub fn order(cands: &mut [Candidate], typed: Option<&[u8; 32]>, now: i64, tiebreak: Tiebreak) {
    cands.sort_by(|a, b| {
        let by_score = score(b, typed, now).cmp(&score(a, typed, now));
        by_score
            .then(a.quality.cmp(&b.quality))
            .then_with(|| match tiebreak {
                Tiebreak::Title => a.title.to_lowercase().cmp(&b.title.to_lowercase()),
                Tiebreak::FavoriteThenRecent => b
                    .favorite
                    .cmp(&a.favorite)
                    .then(b.updated_at.cmp(&a.updated_at)),
            })
    });
}

/// The best candidate is the only one matching the page's exact host, every
/// other one matches its registrable domain (or an associated one) only,
/// and nothing remembers this site: no other candidate was used here or
/// learned, and the first one was not passed over. `confidence` trusts it
/// like a single candidate.
///
/// Only for an item of the user's own (`Candidate::private_vault`): in a
/// shared vault another member can save a login on the exact host of a
/// site, and the user would be signed in to that member's account without
/// a click.
pub fn sole_exact(ranked: &[Candidate]) -> bool {
    let Some((first, rest)) = ranked.split_first() else {
        return false;
    };
    first.quality == MatchQuality::Exact
        && first.private_vault
        && first.affinity >= 0
        && !rest.is_empty()
        && rest.iter().all(|c| {
            matches!(c.quality, MatchQuality::Domain | MatchQuality::Associated)
                && c.usage.is_none()
                && c.affinity <= 0
        })
}

/// `ranked` is ordered and `scores[i]` is the score of `ranked[i]`. A typed
/// username shows as a first score of at least `TYPED_USERNAME`.
///
/// An `Associated` candidate is a menu entry only: first, it makes the
/// plan `Low` (even with a typed username); behind, it is not a rival and
/// never lowers the confidence in the direct matches.
pub fn confidence(ranked: &[Candidate], scores: &[i64], role_min_ok: bool) -> Confidence {
    let Some(first) = ranked.first() else {
        return Confidence::Low;
    };
    if first.quality == MatchQuality::Associated {
        return Confidence::Low;
    }
    let top = scores.first().copied().unwrap_or(0);
    let remembered = first.usage.is_some_and(|u| u.last_on_site)
        || first.affinity >= super::learned::TRUST
        || top >= TYPED_USERNAME;
    let rival = ranked
        .iter()
        .zip(scores)
        .skip(1)
        .find(|(c, _)| c.quality != MatchQuality::Associated)
        .map(|(_, s)| *s);
    let Some(second) = rival else {
        return if role_min_ok {
            Confidence::High
        } else {
            Confidence::Medium
        };
    };
    if top == second && !remembered {
        return Confidence::Low;
    }
    if top - second >= MARGIN && remembered && role_min_ok {
        return Confidence::High;
    }
    if role_min_ok && sole_exact(ranked) {
        return Confidence::High;
    }
    Confidence::Medium
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const NOW: i64 = 1_800_000_000;

    fn cand(n: u8, quality: MatchQuality) -> Candidate {
        Candidate {
            item_id: Id([n; 16]),
            kind: CandidateKind::Login,
            quality,
            favorite: false,
            updated_at: 0,
            title: format!("t{n}"),
            username_hash: None,
            usage: None,
            has_totp: false,
            affinity: 0,
            private_vault: true,
        }
    }

    fn usage(
        last_on_site: bool,
        same_shape: bool,
        count: u32,
        last_at: i64,
    ) -> Option<UsageSignal> {
        Some(UsageSignal {
            last_on_site,
            same_shape,
            count,
            last_at,
        })
    }

    fn sc(c: &Candidate) -> i64 {
        score(c, None, NOW)
    }

    #[test]
    fn exact_beats_domain() {
        assert!(sc(&cand(1, MatchQuality::Exact)) > sc(&cand(2, MatchQuality::Domain)));
    }

    #[test]
    fn last_on_site_beats_exact_without_memory() {
        let mut d = cand(1, MatchQuality::Domain);
        d.usage = usage(true, false, 0, 0);
        assert_eq!(sc(&d), 140);
        assert!(sc(&d) > sc(&cand(2, MatchQuality::Exact)));
    }

    #[test]
    fn same_shape_adds_twenty() {
        let mut a = cand(1, MatchQuality::Exact);
        a.usage = usage(false, false, 0, 0);
        let mut b = a.clone();
        b.usage = usage(false, true, 0, 0);
        assert_eq!(sc(&b) - sc(&a), 20);
    }

    #[test]
    fn typed_username_is_decisive() {
        let hash = [7u8; 32];
        let mut d = cand(1, MatchQuality::Domain);
        d.username_hash = Some(hash);
        let mut e = cand(2, MatchQuality::Exact);
        e.usage = usage(true, true, 99, NOW);
        e.favorite = true;
        assert!(score(&d, Some(&hash), NOW) > score(&e, Some(&hash), NOW));
    }

    #[test]
    fn favorite_only_breaks_ties() {
        let a = cand(1, MatchQuality::Exact);
        let mut b = cand(2, MatchQuality::Exact);
        b.favorite = true;
        assert_eq!(sc(&a), sc(&b));
        let mut v = vec![a, b];
        order(&mut v, None, NOW, Tiebreak::FavoriteThenRecent);
        assert_eq!(v[0].item_id, Id([2; 16]));
    }

    #[test]
    fn recency_capped_at_five() {
        let mut a = cand(1, MatchQuality::Exact);
        a.usage = usage(false, false, 0, NOW);
        assert_eq!(sc(&a) - 100, 5);
        a.usage = usage(false, false, 0, NOW - 2 * DAY);
        assert_eq!(sc(&a) - 100, 3);
        a.usage = usage(false, false, 0, NOW - 100 * DAY);
        assert_eq!(sc(&a) - 100, 1);
        a.usage = usage(false, false, 0, NOW - 400 * DAY);
        assert_eq!(sc(&a) - 100, 0);
    }

    #[test]
    fn frequency_capped_at_five() {
        let mut a = cand(1, MatchQuality::Exact);
        a.usage = usage(false, false, 3, 0);
        assert_eq!(sc(&a), 103);
        a.usage = usage(false, false, 1000, 0);
        assert_eq!(sc(&a), 105);
    }

    fn scores(v: &[Candidate]) -> Vec<i64> {
        v.iter().map(sc).collect()
    }

    #[test]
    fn single_candidate_is_high() {
        let v = vec![cand(1, MatchQuality::Exact)];
        assert_eq!(confidence(&v, &scores(&v), true), Confidence::High);
    }

    #[test]
    fn tie_without_memory_is_low() {
        let v = vec![cand(1, MatchQuality::Exact), cand(2, MatchQuality::Exact)];
        assert_eq!(confidence(&v, &scores(&v), true), Confidence::Low);
    }

    #[test]
    fn margin_with_memory_is_high() {
        let mut a = cand(1, MatchQuality::Exact);
        a.usage = usage(true, false, 0, 0);
        let v = vec![a, cand(2, MatchQuality::Exact)];
        assert_eq!(confidence(&v, &scores(&v), true), Confidence::High);
    }

    #[test]
    fn margin_without_memory_or_typed_is_medium() {
        let v = vec![cand(1, MatchQuality::Exact), cand(2, MatchQuality::Other)];
        assert_eq!(confidence(&v, &scores(&v), true), Confidence::Medium);
    }

    #[test]
    fn below_margin_is_medium() {
        let mut a = cand(1, MatchQuality::Exact);
        a.usage = usage(true, false, 0, 0);
        let b = cand(2, MatchQuality::Exact);
        let v = vec![a, b];
        // 180 against 100 is a lead of 80; shrink it under the margin.
        let s = [130, 100];
        assert_eq!(confidence(&v, &s, true), Confidence::Medium);
    }

    #[test]
    fn weak_roles_cap_at_medium() {
        let v = vec![cand(1, MatchQuality::Exact)];
        assert_eq!(confidence(&v, &scores(&v), false), Confidence::Medium);
    }

    #[test]
    fn typed_match_gives_high() {
        let hash = [7u8; 32];
        let mut d = cand(1, MatchQuality::Domain);
        d.username_hash = Some(hash);
        let v = vec![d, cand(2, MatchQuality::Other)];
        let s: Vec<i64> = v.iter().map(|c| score(c, Some(&hash), NOW)).collect();
        assert_eq!(confidence(&v, &s, true), Confidence::High);
    }

    #[test]
    fn two_typed_matches_tied_is_medium() {
        let hash = [7u8; 32];
        let mut a = cand(1, MatchQuality::Domain);
        a.username_hash = Some(hash);
        let mut b = cand(2, MatchQuality::Domain);
        b.username_hash = Some(hash);
        let v = vec![a, b];
        let s: Vec<i64> = v.iter().map(|c| score(c, Some(&hash), NOW)).collect();
        assert_eq!(s[0], s[1]);
        assert_eq!(confidence(&v, &s, true), Confidence::Medium);
    }

    #[test]
    fn learned_affinity_lifts_and_trusts() {
        let mut a = cand(1, MatchQuality::Domain);
        a.affinity = 120;
        let mut b = cand(2, MatchQuality::Exact);
        b.usage = usage(true, false, 0, 0);
        // 60 + 120 against 100 + 80.
        assert_eq!(sc(&a), 180);
        assert_eq!(sc(&b), 180);
        a.affinity = 121;
        let mut v = vec![b, a];
        order(&mut v, None, NOW, Tiebreak::Title);
        assert_eq!(v[0].item_id, Id([1; 16]));
        let s = scores(&v);
        // Remembered through the history, with a lead under the margin.
        assert_eq!(confidence(&v, &s, true), Confidence::Medium);
        let v = vec![v[0].clone(), cand(3, MatchQuality::Other)];
        assert_eq!(confidence(&v, &scores(&v), true), Confidence::High);
    }

    #[test]
    fn sole_exact_among_domain_matches_is_high() {
        let v = vec![
            cand(1, MatchQuality::Exact),
            cand(2, MatchQuality::Domain),
            cand(3, MatchQuality::Domain),
        ];
        assert!(sole_exact(&v));
        assert_eq!(confidence(&v, &scores(&v), true), Confidence::High);
        // Weak roles still cap it.
        assert_eq!(confidence(&v, &scores(&v), false), Confidence::Medium);
    }

    #[test]
    fn sole_exact_is_for_an_item_of_a_private_vault_only() {
        // A member of a shared vault saved the exact host: no such trust.
        // As before the rule, the better match is never `High` (nothing is
        // submitted for the user).
        let planted = Candidate {
            private_vault: false,
            ..cand(1, MatchQuality::Exact)
        };
        let v = vec![planted.clone(), cand(2, MatchQuality::Domain)];
        assert!(!sole_exact(&v));
        assert_eq!(confidence(&v, &scores(&v), true), Confidence::Medium);
        // The user's own exact host beside a shared domain match: trusted.
        let shared_domain = Candidate {
            private_vault: false,
            ..cand(2, MatchQuality::Domain)
        };
        let v = vec![cand(1, MatchQuality::Exact), shared_domain];
        assert!(sole_exact(&v));
        // Alone, the shared item is a single candidate as before.
        let v = vec![planted];
        assert_eq!(confidence(&v, &scores(&v), true), Confidence::High);
    }

    #[test]
    fn two_exact_without_memory_stay_a_menu() {
        let v = vec![
            cand(1, MatchQuality::Exact),
            cand(2, MatchQuality::Exact),
            cand(3, MatchQuality::Domain),
        ];
        assert!(!sole_exact(&v));
        assert_eq!(confidence(&v, &scores(&v), true), Confidence::Low);
    }

    #[test]
    fn sole_exact_needs_no_memory_elsewhere() {
        // A domain match used here before (not last): the site has memory.
        let mut d = cand(2, MatchQuality::Domain);
        d.usage = usage(false, false, 1, 0);
        let v = vec![cand(1, MatchQuality::Exact), d];
        assert!(!sole_exact(&v));
        assert_eq!(confidence(&v, &scores(&v), true), Confidence::Medium);
        // A domain match the history prefers.
        let mut d = cand(2, MatchQuality::Domain);
        d.affinity = 10;
        let v = vec![cand(1, MatchQuality::Exact), d];
        assert!(!sole_exact(&v));
        assert_eq!(confidence(&v, &scores(&v), true), Confidence::Medium);
        // The exact one was offered first and passed over.
        let mut e = cand(1, MatchQuality::Exact);
        e.affinity = -5;
        let v = vec![e, cand(2, MatchQuality::Domain)];
        assert!(!sole_exact(&v));
        assert_eq!(confidence(&v, &scores(&v), true), Confidence::Medium);
        // An unmatched candidate (a manual choice) is no domain match.
        let v = vec![cand(1, MatchQuality::Exact), cand(2, MatchQuality::Other)];
        assert!(!sole_exact(&v));
        // One candidate is not "several".
        assert!(!sole_exact(&[cand(1, MatchQuality::Exact)]));
    }

    #[test]
    fn typed_username_still_wins_over_the_sole_exact() {
        let hash = [7u8; 32];
        let mut d = cand(2, MatchQuality::Domain);
        d.username_hash = Some(hash);
        let mut v = vec![cand(1, MatchQuality::Exact), d];
        order(&mut v, Some(&hash), NOW, Tiebreak::Title);
        assert_eq!(v[0].item_id, Id([2; 16]));
        let s: Vec<i64> = v.iter().map(|c| score(c, Some(&hash), NOW)).collect();
        assert!(!sole_exact(&v));
        assert_eq!(confidence(&v, &s, true), Confidence::High);
    }

    #[test]
    fn associated_ranks_below_domain_and_above_other() {
        let a = sc(&cand(1, MatchQuality::Associated));
        assert!(sc(&cand(2, MatchQuality::Domain)) > a);
        assert!(a > sc(&cand(3, MatchQuality::Other)));
        let mut v = vec![
            cand(1, MatchQuality::Other),
            cand(2, MatchQuality::Associated),
            cand(3, MatchQuality::Domain),
            cand(4, MatchQuality::Exact),
        ];
        order(&mut v, None, NOW, Tiebreak::Title);
        let ids: Vec<u8> = v.iter().map(|c| c.item_id.0[0]).collect();
        assert_eq!(ids, [4, 3, 2, 1]);
    }

    #[test]
    fn associated_first_is_always_low() {
        let v = vec![cand(1, MatchQuality::Associated)];
        assert_eq!(confidence(&v, &scores(&v), true), Confidence::Low);
        // Even with the typed username of that account.
        let hash = [7u8; 32];
        let mut a = cand(1, MatchQuality::Associated);
        a.username_hash = Some(hash);
        let mut v = vec![cand(2, MatchQuality::Domain), a];
        order(&mut v, Some(&hash), NOW, Tiebreak::Title);
        assert_eq!(v[0].item_id, Id([1; 16]));
        let s: Vec<i64> = v.iter().map(|c| score(c, Some(&hash), NOW)).collect();
        assert_eq!(confidence(&v, &s, true), Confidence::Low);
    }

    #[test]
    fn associated_behind_is_no_rival() {
        // One direct match stays a single candidate.
        let v = vec![
            cand(1, MatchQuality::Domain),
            cand(2, MatchQuality::Associated),
        ];
        assert_eq!(confidence(&v, &scores(&v), true), Confidence::High);
        // Two tied direct matches stay a menu.
        let v = vec![
            cand(1, MatchQuality::Domain),
            cand(2, MatchQuality::Domain),
            cand(3, MatchQuality::Associated),
        ];
        assert_eq!(confidence(&v, &scores(&v), true), Confidence::Low);
        // One exact, the rest associated: the sole exact host.
        let v = vec![
            cand(1, MatchQuality::Exact),
            cand(2, MatchQuality::Associated),
        ];
        assert_eq!(confidence(&v, &scores(&v), true), Confidence::High);
    }

    #[test]
    fn no_candidate_is_low() {
        assert_eq!(confidence(&[], &[], true), Confidence::Low);
    }

    #[test]
    fn title_tiebreak_matches_bridge_sort() {
        let mut v = vec![
            cand(1, MatchQuality::Domain),
            cand(2, MatchQuality::Exact),
            cand(3, MatchQuality::Exact),
        ];
        v[0].title = "alpha".into();
        v[1].title = "Zed".into();
        v[2].title = "bob".into();
        order(&mut v, None, NOW, Tiebreak::Title);
        let titles: Vec<_> = v.iter().map(|c| c.title.as_str()).collect();
        assert_eq!(titles, ["bob", "Zed", "alpha"]);
    }

    fn quality_strategy() -> impl Strategy<Value = MatchQuality> {
        prop_oneof![
            Just(MatchQuality::Exact),
            Just(MatchQuality::Domain),
            Just(MatchQuality::Associated),
            Just(MatchQuality::Other)
        ]
    }

    fn list_strategy() -> impl Strategy<Value = Vec<Candidate>> {
        prop::collection::vec(
            (quality_strategy(), any::<bool>(), 0i64..5, "[a-zA-Z]{0,3}"),
            0..12,
        )
        .prop_map(|rows| {
            rows.into_iter()
                .enumerate()
                .map(|(i, (q, fav, upd, title))| {
                    let mut c = cand(i as u8, q);
                    c.favorite = fav;
                    c.updated_at = upd;
                    c.title = title;
                    c
                })
                .collect()
        })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(200))]

        // The bridge comparator, verbatim: quality then lowercase title.
        #[test]
        fn title_order_equals_bridge_oracle(v in list_strategy()) {
            let mut oracle = v.clone();
            oracle.sort_by(|a, b| {
                a.quality
                    .cmp(&b.quality)
                    .then_with(|| a.title.to_lowercase().cmp(&b.title.to_lowercase()))
            });
            let mut got = v;
            order(&mut got, None, NOW, Tiebreak::Title);
            prop_assert_eq!(got, oracle);
        }

        // The FFI comparator, verbatim: quality, favorite first, newest first.
        #[test]
        fn favorite_recent_order_equals_ffi_oracle(v in list_strategy()) {
            let mut oracle = v.clone();
            oracle.sort_by(|a, b| {
                a.quality
                    .cmp(&b.quality)
                    .then(b.favorite.cmp(&a.favorite))
                    .then(b.updated_at.cmp(&a.updated_at))
            });
            let mut got = v;
            order(&mut got, None, NOW, Tiebreak::FavoriteThenRecent);
            prop_assert_eq!(got, oracle);
        }
    }
}
