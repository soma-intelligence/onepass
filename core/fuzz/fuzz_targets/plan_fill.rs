#![no_main]

//! A page context as the content script sends it (hostile: it lives in the
//! page), then the plan over a fixed pool of three candidates. `plan`
//! validates the context itself; it must never panic.

use std::collections::HashMap;

use libfuzzer_sys::fuzz_target;
use onepass_core::Id;
use onepass_core::fill_plan::context::PageContext;
use onepass_core::fill_plan::score::{Candidate, CandidateKind, MatchQuality, UsageSignal};
use onepass_core::fill_plan::{Pool, plan};

const NOW: i64 = 1_800_000_000;

fn candidate(n: u8, kind: CandidateKind, quality: MatchQuality) -> Candidate {
    Candidate {
        item_id: Id([n; 16]),
        kind,
        quality,
        favorite: n == 2,
        // Nanoseconds.
        updated_at: (NOW - i64::from(n) * 60) * 1_000_000_000,
        title: format!("item {n}"),
        username_hash: None,
        usage: None,
        has_totp: n == 1,
    }
}

fn pool() -> Pool {
    let mut remembered = candidate(1, CandidateKind::Login, MatchQuality::Exact);
    // The typed hash a context can name: 32 bytes of 1.
    remembered.username_hash = Some([1u8; 32]);
    remembered.usage = Some(UsageSignal {
        last_on_site: true,
        same_shape: true,
        count: 3,
        last_at: NOW - 3600,
    });
    let card = candidate(3, CandidateKind::Card, MatchQuality::Other);
    Pool {
        logins: vec![
            remembered,
            candidate(2, CandidateKind::Login, MatchQuality::Domain),
        ],
        default_card: Some(card.item_id),
        cards: vec![card],
        identities: vec![],
        identity_country: HashMap::new(),
        now: NOW,
    }
}

fuzz_target!(|data: &[u8]| {
    if let Ok(ctx) = serde_json::from_slice::<PageContext>(data) {
        let _ = plan(&ctx, pool());
    }
});
