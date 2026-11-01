//! Behavior of `site_password::generate_for`: profiles, source trust, the
//! `narrow` ladder, the report, and a property test over random rules.

use onepass_core::site_password::{
    CharSet, GenerationReport, PasswordContext, Profile, Source, generate_for,
};
use proptest::prelude::*;

/// The generator's default symbols (`generator.rs`).
const SYMBOLS: &str = "-_.!?#@$%&*+=";
const CLASSES: [&str; 4] = ["lower", "upper", "digit", "special"];

fn run(ctx: &PasswordContext, profile: &Profile, narrow: u8) -> (String, GenerationReport) {
    let (password, report) = generate_for(ctx, profile, narrow).expect("generation");
    (password.to_string(), report)
}

fn rules(rules: &[&str]) -> PasswordContext {
    PasswordContext {
        rules: rules.iter().map(|r| (*r).to_owned()).collect(),
        ..PasswordContext::default()
    }
}

fn has(p: &str, f: fn(&char) -> bool) -> bool {
    p.chars().any(|c| f(&c))
}

fn is_special(c: &char) -> bool {
    !c.is_ascii_alphanumeric()
}

#[test]
fn strong_without_rules_is_24_all_classes() {
    let (p, r) = run(&PasswordContext::default(), &Profile::Strong, 0);
    assert_eq!(p.chars().count(), 24);
    assert_eq!(r.length, 24);
    assert!(has(&p, char::is_ascii_lowercase));
    assert!(has(&p, char::is_ascii_uppercase));
    assert!(has(&p, char::is_ascii_digit));
    assert!(p.chars().filter(is_special).all(|c| SYMBOLS.contains(c)));
    assert!(has(&p, is_special));
    assert!(r.lower && r.upper && r.digit && r.special);
    assert!(r.sources.is_empty() && r.dropped.is_empty());
    assert!(!r.fallback && !r.weak_by_site);
    assert!(r.entropy_bits > 140.0);
}

#[test]
fn strong_with_maxlength_40_is_32() {
    let ctx = PasswordContext {
        max_length: Some(40),
        ..PasswordContext::default()
    };
    let (p, r) = run(&ctx, &Profile::Strong, 0);
    assert_eq!(p.chars().count(), 32);
    assert_eq!(r.sources, vec![Source::Attributes]);
}

#[test]
fn strong_with_maxlength_12_is_12() {
    let ctx = PasswordContext {
        max_length: Some(12),
        ..PasswordContext::default()
    };
    let (p, _) = run(&ctx, &Profile::Strong, 0);
    assert_eq!(p.chars().count(), 12);
}

#[test]
fn maxlength_below_4_is_ignored() {
    let ctx = PasswordContext {
        max_length: Some(3),
        ..PasswordContext::default()
    };
    let (p, r) = run(&ctx, &Profile::Strong, 0);
    assert_eq!(p.chars().count(), 24);
    assert!(r.sources.is_empty());
}

#[test]
fn length_capped_at_64() {
    let (p, _) = run(
        &rules(&["minlength: 60; maxlength: 200;"]),
        &Profile::Strong,
        0,
    );
    assert_eq!(p.chars().count(), 60);
    let custom = Profile::Custom {
        length: 100,
        digits: true,
        symbols: true,
    };
    let (p, _) = run(&PasswordContext::default(), &custom, 0);
    assert_eq!(p.chars().count(), 64);
}

#[test]
fn attribute_beats_hint() {
    let ctx = PasswordContext {
        max_length: Some(12),
        hint_text: Some("8 à 20 caractères".to_owned()),
        ..PasswordContext::default()
    };
    let (p, r) = run(&ctx, &Profile::Strong, 0);
    assert_eq!(p.chars().count(), 12);
    assert_eq!(r.length, 12);
    assert_eq!(r.dropped, vec![Source::Hints]);
    assert_eq!(r.sources, vec![Source::Attributes]);
    assert!(!r.fallback);
}

#[test]
fn agreeing_hint_is_kept() {
    let ctx = PasswordContext {
        max_length: Some(20),
        hint_text: Some("au moins 12 caractères, un chiffre".to_owned()),
        ..PasswordContext::default()
    };
    let (p, r) = run(&ctx, &Profile::Strong, 0);
    assert_eq!(p.chars().count(), 20);
    assert_eq!(r.sources, vec![Source::Attributes, Source::Hints]);
    assert!(r.dropped.is_empty());
}

#[test]
fn quirk_dropped_before_attributes() {
    let ctx = PasswordContext {
        min_length: Some(16),
        quirk_rules: Some("minlength: 8; maxlength: 12;".to_owned()),
        ..PasswordContext::default()
    };
    let (p, r) = run(&ctx, &Profile::Strong, 0);
    assert_eq!(r.dropped, vec![Source::Quirks]);
    assert_eq!(r.sources, vec![Source::Attributes]);
    assert_eq!(p.chars().count(), 24);
    assert!(!r.fallback);
}

#[test]
fn rules_and_attributes_contradicting_fall_back() {
    let ctx = PasswordContext {
        rules: vec!["minlength: 20;".to_owned()],
        max_length: Some(10),
        ..PasswordContext::default()
    };
    let (p, r) = run(&ctx, &Profile::Strong, 0);
    assert!(r.fallback);
    assert!(r.sources.is_empty());
    assert_eq!(r.dropped, vec![Source::PasswordRules, Source::Attributes]);
    assert_eq!(p.chars().count(), 24);
}

#[test]
fn readable_with_max_16_falls_back() {
    let ctx = PasswordContext {
        max_length: Some(16),
        ..PasswordContext::default()
    };
    for _ in 0..50 {
        let (p, r) = run(&ctx, &Profile::Readable, 0);
        assert!(r.fallback);
        assert_eq!(p.chars().count(), 16);
        assert_eq!(r.length, 16);
        // Strong instead: every class, not words.
        assert!(r.lower && r.upper && r.digit && r.special);
        assert!(
            !p.split('-')
                .all(|w| w.len() >= 4 && w.chars().all(|c| c.is_ascii_alphabetic()))
        );
    }
}

#[test]
fn readable_default_has_capital_and_digit() {
    for _ in 0..50 {
        let (p, r) = run(&PasswordContext::default(), &Profile::Readable, 0);
        let words: Vec<&str> = p.split('-').collect();
        assert_eq!(words.len(), 5, "{}", words.len());
        assert_eq!(p.chars().filter(char::is_ascii_uppercase).count(), 1);
        assert!(p.ends_with(|c: char| c.is_ascii_digit()));
        assert!(!r.fallback);
        assert!(r.entropy_bits > 60.0 && !r.weak_by_site);
        assert!(r.lower && r.upper && r.digit && r.special);
    }
}

#[test]
fn readable_grows_for_a_long_minimum() {
    let ctx = rules(&["minlength: 30;"]);
    for _ in 0..50 {
        let (p, r) = run(&ctx, &Profile::Readable, 0);
        assert!(!r.fallback);
        assert!(p.chars().count() >= 30 && p.chars().count() <= 64);
        assert!(p.split('-').count() >= 6);
    }
}

#[test]
fn readable_without_dash_uses_another_special_or_none() {
    let ctx = rules(&["allowed: lower, upper, digit, [_];"]);
    let (p, r) = run(&ctx, &Profile::Readable, 0);
    assert!(!r.fallback);
    assert_eq!(p.split('_').count(), 5);
    let ctx = rules(&["allowed: lower, upper, digit;"]);
    let (p, r) = run(&ctx, &Profile::Readable, 0);
    assert!(!r.fallback);
    assert!(p.chars().all(|c| c.is_ascii_alphanumeric()));
}

#[test]
fn required_tilde_present() {
    for _ in 0..20 {
        let (p, r) = run(&rules(&["required: [~];"]), &Profile::Strong, 0);
        assert!(p.contains('~'));
        assert!(!r.fallback);
        assert_eq!(r.sources, vec![Source::PasswordRules]);
    }
    let ctx = rules(&["required: lower; required: upper; required: digit; required: [~];"]);
    for _ in 0..20 {
        let (p, r) = run(&ctx, &Profile::Strong, 0);
        assert!(p.contains('~'));
        assert!(!r.fallback);
        // `allowed` comes from the required classes alone: no other symbol.
        assert!(p.chars().all(|c| c.is_ascii_alphanumeric() || c == '~'));
    }
}

#[test]
fn ascii_printable_draws_default_symbols() {
    let ctx = rules(&["allowed: ascii-printable;"]);
    for _ in 0..20 {
        let (p, _) = run(&ctx, &Profile::Strong, 0);
        assert!(p.chars().filter(is_special).all(|c| SYMBOLS.contains(c)));
    }
}

#[test]
fn narrow_1_has_no_symbols() {
    for _ in 0..20 {
        let (p, r) = run(&PasswordContext::default(), &Profile::Strong, 1);
        assert_eq!(p.chars().count(), 24);
        assert!(p.chars().all(|c| c.is_ascii_alphanumeric()));
        assert!(!r.special);
    }
    // A required symbol stays.
    let (p, _) = run(
        &rules(&["required: lower, upper; required: [!];"]),
        &Profile::Strong,
        1,
    );
    assert!(p.contains('!'));
}

#[test]
fn narrow_2_lower_and_digits_only() {
    let ctx = PasswordContext {
        max_length: Some(20),
        ..PasswordContext::default()
    };
    for _ in 0..20 {
        let (p, r) = run(&ctx, &Profile::Strong, 2);
        assert_eq!(p.chars().count(), 20);
        assert!(
            p.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        );
        assert!(r.lower && r.digit && !r.upper && !r.special);
    }
}

#[test]
fn narrow_above_2_is_rejected() {
    let err = generate_for(&PasswordContext::default(), &Profile::Strong, 3).unwrap_err();
    match err {
        onepass_core::Error::Validation(v) => assert_eq!(v.field, "narrow"),
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn custom_respects_choice_and_site() {
    let custom = Profile::Custom {
        length: 16,
        digits: false,
        symbols: false,
    };
    let (p, _) = run(&PasswordContext::default(), &custom, 0);
    assert_eq!(p.chars().count(), 16);
    assert!(p.chars().all(|c| c.is_ascii_alphabetic()));
    // The site maximum wins over the user length.
    let ctx = PasswordContext {
        max_length: Some(10),
        ..PasswordContext::default()
    };
    let (p, _) = run(&ctx, &custom, 0);
    assert_eq!(p.chars().count(), 10);
}

#[test]
fn six_digits_site_is_weak_by_site() {
    let ctx = rules(&["allowed: digit; minlength: 6; maxlength: 6;"]);
    let (p, r) = run(&ctx, &Profile::Strong, 0);
    assert_eq!(p.chars().count(), 6);
    assert!(p.chars().all(|c| c.is_ascii_digit()));
    assert!(r.weak_by_site);
    assert!(r.entropy_bits < 60.0);
    assert!(!r.fallback);
}

#[test]
fn report_has_no_password_char() {
    for profile in [Profile::Strong, Profile::Readable] {
        let (p, r) = run(&PasswordContext::default(), &profile, 0);
        let json = serde_json::to_string(&r).unwrap();
        assert!(!json.contains(&p));
        assert!(json.contains("\"weak_by_site\""));
    }
    let ctx = PasswordContext {
        max_length: Some(12),
        hint_text: Some("8 à 20 caractères".to_owned()),
        ..PasswordContext::default()
    };
    let (_, r) = run(&ctx, &Profile::Strong, 0);
    let json = serde_json::to_string(&r).unwrap();
    assert!(json.contains("\"dropped\":[\"hints\"]"), "{json}");
    assert!(json.contains("\"sources\":[\"attributes\"]"), "{json}");
}

#[cfg(not(debug_assertions))]
#[test]
fn generation_under_5ms() {
    use std::time::Instant;
    let ctx = PasswordContext {
        rules: vec!["minlength: 12; required: lower; required: upper; required: digit; required: [-().&@?'#,/\"+]; max-consecutive: 2;".to_owned()],
        quirk_rules: Some("minlength: 10; maxlength: 30;".to_owned()),
        min_length: Some(8),
        max_length: Some(32),
        hint_text: Some("Entre 8 et 32 caractères, au moins une majuscule et un chiffre.".to_owned()),
    };
    for profile in [Profile::Strong, Profile::Readable] {
        let mut times: Vec<u128> = (0..200)
            .map(|_| {
                let start = Instant::now();
                generate_for(&ctx, &profile, 0).unwrap();
                start.elapsed().as_micros()
            })
            .collect();
        times.sort_unstable();
        let median = times[times.len() / 2];
        assert!(median < 5_000, "median {median} us for {profile:?}");
    }
}

/// Every constraint of the generated rule string is met.
fn meets(p: &str, min: u32, max: Option<u32>, required: &[CharSet], allowed: &CharSet) -> bool {
    let len = p.chars().count() as u32;
    len >= min
        && max.is_none_or(|m| len <= m)
        && len <= 64
        && p.chars().all(|c| allowed.contains(c))
        && required
            .iter()
            .all(|set| p.chars().any(|c| set.contains(c)))
}

fn class(name: &str) -> CharSet {
    CharSet::ascii_class(name).unwrap()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    #[test]
    fn any_satisfiable_constraints_are_met(
        (min, max) in (1u32..=40).prop_flat_map(|min| (Just(min), prop::option::of(min..=80u32))),
        required_mask in 0u8..16,
        allowed_mask in 0u8..16,
        profile_pick in 0u8..3,
        via_attributes in any::<bool>(),
        narrow in 0u8..=2,
    ) {
        let pick = |mask: u8| -> Vec<&str> {
            CLASSES.iter().enumerate().filter(|(i, _)| mask & (1 << i) != 0).map(|(_, n)| *n).collect()
        };
        let required_names = pick(required_mask);
        let allowed_names = pick(allowed_mask);
        let mut parts = Vec::new();
        if !via_attributes {
            parts.push(format!("minlength: {min};"));
            if let Some(m) = max {
                parts.push(format!("maxlength: {m};"));
            }
        }
        for name in &required_names {
            parts.push(format!("required: {name};"));
        }
        if !allowed_names.is_empty() {
            parts.push(format!("allowed: {};", allowed_names.join(", ")));
        }
        let ctx = PasswordContext {
            rules: vec![parts.join(" ")],
            min_length: via_attributes.then_some(min),
            max_length: if via_attributes { max } else { None },
            ..PasswordContext::default()
        };
        let profile = match profile_pick {
            0 => Profile::Strong,
            1 => Profile::Readable,
            _ => Profile::Custom { length: 20, digits: true, symbols: true },
        };

        let (p, r) = run(&ctx, &profile, narrow);
        prop_assert!(p.chars().count() <= 64);
        prop_assert_eq!(r.length as usize, p.chars().count());

        // An attribute maxlength below 4 is ignored.
        let max = if via_attributes { max.filter(|m| *m >= 4) } else { max };
        let required: Vec<CharSet> = required_names.iter().map(|n| class(n)).collect();
        let allowed = if required_names.is_empty() && allowed_names.is_empty() {
            CLASSES.iter().fold(CharSet::default(), |acc, n| acc.union(&class(n)))
        } else {
            required_names.iter().chain(&allowed_names).fold(CharSet::default(), |acc, n| acc.union(&class(n)))
        };
        let satisfiable = max.is_none_or(|m| required.len() as u32 <= m);
        if satisfiable {
            prop_assert!(meets(&p, min, max, &required, &allowed), "{:?} {:?} {:?}", ctx, profile, r);
            prop_assert!(!(r.fallback && r.sources.is_empty()));
        } else {
            prop_assert!(r.fallback && r.sources.is_empty());
        }
    }
}
