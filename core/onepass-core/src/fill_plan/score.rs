//! Candidate score, order and confidence (spec R4).
//!
//! Without usage memory and without a typed username the score is the match
//! quality alone: favorite, recency and frequency then only break ties in
//! `order`, which keeps the historic order of the two existing rankers.

use super::weights::{
    DOMAIN, EXACT, FAVORITE, FREQUENCY_MAX, LAST_ON_SITE, MARGIN, RECENCY_MAX, SAME_SHAPE,
    TYPED_USERNAME,
};
use serde::Serialize;

use crate::id::Id;

const DAY: i64 = 86_400;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MatchQuality {
    Exact,
    Domain,
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
    s
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

/// `ranked` is ordered and `scores[i]` is the score of `ranked[i]`. A typed
/// username shows as a first score of at least `TYPED_USERNAME`.
pub fn confidence(ranked: &[Candidate], scores: &[i64], role_min_ok: bool) -> Confidence {
    let Some(first) = ranked.first() else {
        return Confidence::Low;
    };
    let top = scores.first().copied().unwrap_or(0);
    let remembered = first.usage.is_some_and(|u| u.last_on_site) || top >= TYPED_USERNAME;
    let Some(&second) = scores.get(1).filter(|_| ranked.len() > 1) else {
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
