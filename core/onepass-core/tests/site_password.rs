//! Behavior of `site_password::generate_for`: profiles, source trust, the
//! `narrow` ladder, the report, and a property test over random rules.

use onepass_core::site_password::{
    CharSet, Constraints, GenerationReport, PasswordContext, Profile, Source, generate_for,
    parse_hints, parse_passwordrules,
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
        assert!(r.readable_fell_back);
        assert!(!r.fallback);
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
fn readable_meets_a_minimum_of_30() {
    let ctx = rules(&["minlength: 30;"]);
    for _ in 0..50 {
        let (p, r) = run(&ctx, &Profile::Readable, 0);
        assert!(!r.fallback && !r.readable_fell_back);
        assert!(p.chars().count() >= 30 && p.chars().count() <= 64);
    }
}

#[test]
fn readable_max_40_gets_5_words() {
    let ctx = PasswordContext {
        max_length: Some(40),
        ..PasswordContext::default()
    };
    for _ in 0..100 {
        let (p, r) = run(&ctx, &Profile::Readable, 0);
        assert!(!r.readable_fell_back && !r.fallback);
        assert_eq!(p.split('-').count(), 5);
        assert!(p.chars().count() <= 40);
    }
}

#[test]
fn readable_high_min_uses_more_words() {
    let ctx = rules(&["minlength: 45;"]);
    for _ in 0..100 {
        let (p, r) = run(&ctx, &Profile::Readable, 0);
        assert!(!r.readable_fell_back && !r.fallback);
        assert!(p.split('-').count() >= 6);
        assert!(p.chars().count() >= 45 && p.chars().count() <= 64);
    }
}

#[test]
fn hint_class_ban_survives_length_conflict() {
    let ctx = PasswordContext {
        max_length: Some(12),
        hint_text: Some("8 à 20 caractères, sans caractère spécial".to_owned()),
        ..PasswordContext::default()
    };
    for _ in 0..20 {
        let (p, r) = run(&ctx, &Profile::Strong, 0);
        assert_eq!(p.chars().count(), 12);
        assert!(p.chars().all(|c| c.is_ascii_alphanumeric()));
        assert_eq!(r.sources, vec![Source::Attributes, Source::Hints]);
        assert!(r.dropped.is_empty());
    }
}

#[test]
fn quirk_classes_survive_length_conflict() {
    let ctx = PasswordContext {
        max_length: Some(12),
        quirk_rules: Some(
            "minlength: 8; maxlength: 30; required: lower; required: digit; allowed: lower, digit;"
                .to_owned(),
        ),
        ..PasswordContext::default()
    };
    for _ in 0..20 {
        let (p, r) = run(&ctx, &Profile::Strong, 0);
        assert_eq!(p.chars().count(), 12);
        assert!(
            p.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        );
        assert!(has(&p, char::is_ascii_lowercase) && has(&p, char::is_ascii_digit));
        assert_eq!(r.sources, vec![Source::Attributes, Source::Quirks]);
        assert!(r.dropped.is_empty());
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
fn short_custom_is_not_weak_by_site() {
    // 8 chars of letters: under 60 bits, but the user's choice, not the site's.
    let custom = Profile::Custom {
        length: 8,
        digits: false,
        symbols: false,
    };
    let (_, r) = run(&PasswordContext::default(), &custom, 0);
    assert!(r.entropy_bits < 60.0);
    assert!(!r.weak_by_site);
    // A site maximum that keeps it as short: still the user's length.
    let ctx = PasswordContext {
        max_length: Some(12),
        ..PasswordContext::default()
    };
    let (_, r) = run(&ctx, &custom, 0);
    assert!(!r.weak_by_site);
}

#[test]
fn custom_cut_by_site_is_weak_by_site() {
    // The user asked for 20 letters (over 100 bits); the site allows 8.
    let custom = Profile::Custom {
        length: 20,
        digits: false,
        symbols: false,
    };
    let ctx = PasswordContext {
        max_length: Some(8),
        ..PasswordContext::default()
    };
    let (p, r) = run(&ctx, &custom, 0);
    assert_eq!(p.chars().count(), 8);
    assert!(r.weak_by_site);
}

#[test]
fn repeated_rule_strings_require_each_class_once() {
    let rule = "required: lower; required: upper; required: digit; maxlength: 8;";
    let once = parse_passwordrules(rule).unwrap();
    let mut thrice = Constraints::default();
    for _ in 0..3 {
        thrice.merge(&parse_passwordrules(rule).unwrap());
    }
    thrice.merge(&parse_passwordrules("maxlength: 8;").unwrap());
    let mut once_with_max = Constraints::default();
    once_with_max.merge(&once);
    once_with_max.merge(&parse_passwordrules("maxlength: 8;").unwrap());
    assert_eq!(thrice, once_with_max);
    assert_eq!(thrice.required.len(), 3);
    // Field, confirmation and quirk give the same string: the max still holds.
    let ctx = PasswordContext {
        rules: vec![rule.to_owned(), rule.to_owned()],
        quirk_rules: Some(rule.to_owned()),
        max_length: Some(8),
        ..PasswordContext::default()
    };
    let (p, r) = run(&ctx, &Profile::Strong, 0);
    assert!(!r.fallback);
    assert_eq!(p.chars().count(), 8);
}

#[test]
fn required_digit_alone_gives_digits_only() {
    // Apple semantics (ruled kept): `allowed` is the union of the named
    // classes, so `required: digit` alone means digits only (PIN quirks).
    let (p, r) = run(&rules(&["required: digit; minlength: 4; maxlength: 8;"]), &Profile::Strong, 0);
    assert!(!r.fallback);
    assert!(p.chars().all(|c| c.is_ascii_digit()), "{p}");
}

#[test]
fn report_has_no_password_char() {
    for profile in [Profile::Strong, Profile::Readable] {
        let (p, r) = run(&PasswordContext::default(), &profile, 0);
        let json = serde_json::to_string(&r).unwrap();
        assert!(!json.contains(&p));
        assert!(json.contains("\"weak_by_site\""));
        assert!(json.contains("\"readable_fell_back\":false"));
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
            prop_assert!(!r.fallback);
        } else {
            prop_assert!(r.fallback && r.sources.is_empty());
        }
    }
}

/// Real-world check of the hint reader. `password_hints.jsonl` holds the
/// distinct texts found next to password fields in the passive top 1000 corpus
/// (`extension/lab/corpus/hints.ts`), each labelled by hand with what the text
/// means. One JSON object per line:
/// - `min`, `max`: length bounds, `null` when absent;
/// - `required`: class names (`upper`, `lower`, `digit`, `special`), any order;
/// - `allowed`: `null` (no restriction), `"alnum"` (letters and digits),
///   `"alnum+<chars>"` (letters, digits and those chars) or an explicit char set;
/// - `forbidden`: the chars never allowed (a string, empty when none).
///
/// A line passes when `parse_hints` gives exactly those constraints.
#[test]
fn hints_corpus_accuracy() {
    let raw = include_str!("fixtures/password_hints.jsonl");
    let class = |n: &str| CharSet::ascii_class(n).unwrap();
    let alnum = class("lower").union(&class("upper")).union(&class("digit"));
    let (mut total, mut misses) = (0usize, 0usize);
    for line in raw.lines().filter(|l| !l.trim().is_empty()) {
        let v: serde_json::Value = serde_json::from_str(line).expect("fixture line");
        let text = v["text"].as_str().unwrap();
        let num = |k: &str| v[k].as_u64().map(|n| n as u32);
        let names = |c: &Constraints| -> Vec<String> {
            let mut names: Vec<String> = c
                .required
                .iter()
                .map(|s| {
                    ["upper", "lower", "digit", "special"]
                        .into_iter()
                        .find(|n| class(n) == *s)
                        .map_or_else(
                            || format!("set:{}", s.iter().collect::<String>()),
                            String::from,
                        )
                })
                .collect();
            names.sort();
            names
        };
        let chars = |s: &str| -> CharSet { s.chars().collect() };
        let expected_allowed = match v["allowed"].as_str() {
            None => None,
            Some("alnum") => Some(alnum.clone()),
            Some(s) => Some(match s.strip_prefix("alnum+") {
                Some(extra) => alnum.union(&chars(extra)),
                None => chars(s),
            }),
        };
        let mut expected_required: Vec<String> = v["required"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| n.as_str().unwrap().to_string())
            .collect();
        expected_required.sort();
        let want_forbidden = chars(v["forbidden"].as_str().unwrap());

        let got = parse_hints(text);
        total += 1;
        let ok = got.min_length == num("min").unwrap_or(0)
            && got.max_length == num("max")
            && names(&got) == expected_required
            && got.allowed == expected_allowed
            && got.forbidden == want_forbidden;
        if !ok {
            misses += 1;
            println!(
                "MISS {text:?}\n  expected {line}\n  got min={} max={:?} required={:?} allowed={:?} forbidden={:?}",
                got.min_length,
                got.max_length,
                names(&got),
                got.allowed.as_ref().map(|s| s.iter().collect::<String>()),
                got.forbidden.iter().collect::<String>(),
            );
        }
    }
    println!("hints corpus: {}/{total} exact", total - misses);
    assert!(total >= 100, "fixture too small: {total}");
    assert!(
        (total - misses) * 100 >= total * 95,
        "hint accuracy {}/{total} is below 95 %",
        total - misses
    );
}
