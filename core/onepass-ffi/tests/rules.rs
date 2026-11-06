//! Integration tests of `password_from_rules`: Apple `passwordrules`
//! parsing, merging and generation, with the fallback recipe on any
//! unreadable or contradictory input.

use onepass_ffi::*;

fn fallback() -> FfiPasswordRecipe {
    FfiPasswordRecipe::Characters {
        length: 20,
        digits: true,
        symbols: true,
        avoid_ambiguous: false,
    }
}

fn gen_one(rules: &[&str]) -> String {
    password_from_rules(rules.iter().map(|s| (*s).to_owned()).collect(), fallback()).unwrap()
}

const SPECIAL: &str = "-~!@#$%^&*_+=`|(){}[:;\"'<>,.? ";

#[test]
fn empty_rules_use_fallback() {
    let p = password_from_rules(vec![], fallback()).unwrap();
    assert_eq!(p.chars().count(), 20);
    let pin = password_from_rules(vec![], FfiPasswordRecipe::Pin { length: 6 }).unwrap();
    assert_eq!(pin.len(), 6);
    assert!(pin.chars().all(|c| c.is_ascii_digit()));
}

#[test]
fn minlength_maxlength() {
    for _ in 0..50 {
        let p = gen_one(&["minlength: 8; maxlength: 12;"]);
        assert_eq!(p.chars().count(), 12);
    }
    // Without a maximum the target is 20, raised to the minimum.
    assert_eq!(gen_one(&["minlength: 8;"]).chars().count(), 20);
    assert_eq!(gen_one(&["minlength: 30;"]).chars().count(), 30);
    assert_eq!(gen_one(&["maxlength: 10;"]).chars().count(), 10);
}

#[test]
fn required_classes() {
    let rules = "required: lower; required: upper; required: digit; required: [-_];";
    for _ in 0..200 {
        let p = gen_one(&[rules]);
        assert_eq!(p.chars().count(), 20);
        assert!(p.chars().any(|c| c.is_ascii_lowercase()));
        assert!(p.chars().any(|c| c.is_ascii_uppercase()));
        assert!(p.chars().any(|c| c.is_ascii_digit()));
        assert!(p.chars().any(|c| c == '-' || c == '_'));
        assert!(
            p.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        );
    }
}

#[test]
fn allowed_only() {
    for _ in 0..50 {
        let p = gen_one(&["allowed: digit; minlength: 6; maxlength: 6;"]);
        assert_eq!(p.len(), 6);
        assert!(p.chars().all(|c| c.is_ascii_digit()));
    }
}

#[test]
fn max_consecutive() {
    for _ in 0..300 {
        let p: Vec<char> = gen_one(&["max-consecutive: 2; allowed: [ab];"])
            .chars()
            .collect();
        assert!(p.iter().all(|c| *c == 'a' || *c == 'b'));
        assert!(p.windows(3).all(|w| !(w[0] == w[1] && w[1] == w[2])));
    }
}

#[test]
fn merged_rules() {
    for _ in 0..50 {
        let p = gen_one(&["minlength: 10;", "maxlength: 14; required: digit;"]);
        let n = p.chars().count();
        assert!((10..=14).contains(&n));
        assert!(p.chars().any(|c| c.is_ascii_digit()));
    }
    // The strictest bound of each kind wins.
    let p = gen_one(&[
        "minlength: 8; maxlength: 16;",
        "minlength: 10; maxlength: 12;",
    ]);
    assert_eq!(p.chars().count(), 12);
}

#[test]
fn unreadable_or_contradictory_fall_back() {
    for rules in [
        "minlength: 30; maxlength: 10;",
        "garbage",
        "minlength: abc;",
        "required: nonsense;",
        "allowed: [a-]b];",
        "required: digit; required: upper; required: lower; maxlength: 2;",
        "allowed: digit; required: upper;minlength: 4; maxlength: 4;; max-consecutive: 0;",
        "allowed: [a]; max-consecutive: 1; minlength: 5; maxlength: 5;",
    ] {
        let p = gen_one(&[rules]);
        assert_eq!(p.chars().count(), 20, "{rules}");
    }
    // Two rule sets whose allowed sets do not intersect.
    assert_eq!(
        gen_one(&["allowed: digit;", "allowed: upper;"])
            .chars()
            .count(),
        20
    );
}

#[test]
fn syntax_details() {
    // Unknown properties are ignored, names and classes are case-insensitive.
    let p = gen_one(&["Frobnicate: 3; ALLOWED: DIGIT; MinLength: 7; maxlength: 7"]);
    assert_eq!(p.len(), 7);
    assert!(p.chars().all(|c| c.is_ascii_digit()));
    // Several classes in one value; "]" first and "-" last in a set.
    for _ in 0..100 {
        let p = gen_one(&["allowed: upper, []-]; required: [-]; minlength: 12; maxlength: 12;"]);
        assert!(p.contains('-'));
        assert!(
            p.chars()
                .all(|c| c.is_ascii_uppercase() || c == ']' || c == '-')
        );
    }
    // Special never starts or ends with a space; ascii-printable stays ASCII.
    for _ in 0..200 {
        let p = gen_one(&["allowed: special; minlength: 8; maxlength: 8;"]);
        assert!(p.chars().all(|c| SPECIAL.contains(c)));
        assert!(!p.starts_with(' ') && !p.ends_with(' '));
        let q = gen_one(&["allowed: unicode; minlength: 8; maxlength: 8;"]);
        assert!(q.chars().all(|c| (' '..='~').contains(&c)));
    }
}

#[test]
fn length_is_capped() {
    for rules in [
        "minlength: 4294967295; maxlength: 4294967295;",
        "minlength: 65;",
        "minlength: 65; maxlength: 100;",
    ] {
        assert_eq!(gen_one(&[rules]).chars().count(), 20, "{rules}");
    }
    assert_eq!(
        gen_one(&["minlength: 64; maxlength: 4294967295;"]).len(),
        64
    );
    assert_eq!(gen_one(&["maxlength: 4294967295;"]).len(), 20);
}

#[test]
fn lenient_lists_and_printable_sets() {
    let p = gen_one(&["required: upper,; allowed: upper; minlength: 8; maxlength: 8;"]);
    assert!(p.chars().all(|c| c.is_ascii_uppercase()));
    // Control and non-ASCII characters in a set are unreadable: fallback.
    for rules in ["allowed: [a\u{7}b];", "allowed: [aé];", "allowed: ,;"] {
        assert_eq!(gen_one(&[rules]).chars().count(), 20, "{rules}");
    }
}

fn context(rules: &[&str]) -> FfiPasswordContext {
    FfiPasswordContext {
        rules: rules.iter().map(|s| (*s).to_owned()).collect(),
        ..FfiPasswordContext::default()
    }
}

#[test]
fn password_for_context_follows_rules() {
    let rules = "required: lower; required: digit; allowed: [-]; maxlength: 16;";
    for _ in 0..100 {
        let g = password_for_context(context(&[rules, ""]), FfiPasswordProfile::Strong).unwrap();
        // Strong takes the largest allowed length up to 32.
        assert_eq!(g.password.chars().count(), 16);
        assert!(g.password.chars().any(|c| c.is_ascii_lowercase()));
        assert!(g.password.chars().any(|c| c.is_ascii_digit()));
        assert!(
            g.password
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        );
        assert!(!g.fallback);
        assert!(!g.readable_fell_back);
    }
    // No constraint: Strong stops at 24.
    let g =
        password_for_context(FfiPasswordContext::default(), FfiPasswordProfile::Strong).unwrap();
    assert_eq!(g.password.chars().count(), 24);
    assert!(!g.weak_by_site);
    // Attributes count too.
    let ctx = FfiPasswordContext {
        max_length: Some(12),
        ..FfiPasswordContext::default()
    };
    let g = password_for_context(ctx, FfiPasswordProfile::Strong).unwrap();
    assert_eq!(g.password.chars().count(), 12);
}

#[test]
fn readable_profile_from_ffi() {
    let g =
        password_for_context(FfiPasswordContext::default(), FfiPasswordProfile::Readable).unwrap();
    let words: Vec<&str> = g.password.split('-').collect();
    assert_eq!(words.len(), 5, "{}", g.password.len());
    assert!(g.password.chars().any(|c| c.is_ascii_uppercase()));
    assert!(g.password.chars().any(|c| c.is_ascii_digit()));
    assert!(!g.readable_fell_back);
    // Too short for words: Strong instead, and the report says so.
    let g =
        password_for_context(context(&["maxlength: 8;"]), FfiPasswordProfile::Readable).unwrap();
    assert!(g.readable_fell_back);
    assert_eq!(g.password.chars().count(), 8);
}

#[test]
fn custom_profile_from_ffi() {
    let custom = |length| FfiPasswordProfile::Custom {
        length,
        digits: false,
        symbols: false,
    };
    let g = password_for_context(FfiPasswordContext::default(), custom(10)).unwrap();
    assert_eq!(g.password.chars().count(), 10);
    assert!(g.password.chars().all(|c| c.is_ascii_alphabetic()));
    for bad in [0, 7, 65, 300] {
        assert!(matches!(
            password_for_context(FfiPasswordContext::default(), custom(bad)),
            Err(OnePassError::Validation { ref field, .. }) if field == "length"
        ));
    }
}

#[test]
fn contradictory_context_falls_back() {
    let g = password_for_context(
        context(&["minlength: 20; maxlength: 10;"]),
        FfiPasswordProfile::Strong,
    )
    .unwrap();
    assert!(g.fallback);
    assert_eq!(g.password.chars().count(), 24);
}

#[test]
fn oversized_rule_string_is_dropped_not_fatal() {
    let oversized = format!("minlength: 8;{}", " ".repeat(1025 - 13));
    assert_eq!(oversized.len(), 1025);
    let g = password_for_context(
        context(&[oversized.as_str(), "minlength: 30;"]),
        FfiPasswordProfile::Strong,
    )
    .unwrap();
    assert!(g.password.chars().count() >= 30);
    // Alone, the oversized string leaves the profile alone.
    let g =
        password_for_context(context(&[oversized.as_str()]), FfiPasswordProfile::Strong).unwrap();
    assert_eq!(g.password.chars().count(), 24);
}

#[test]
fn ninth_rule_string_ignored() {
    // Eight distinct strings (identical ones are read once).
    let distinct: Vec<String> = (0..8).map(|i| format!("minlength: {};", 8 + i)).collect();
    let mut rules: Vec<&str> = distinct.iter().map(String::as_str).collect();
    rules.push("maxlength: 10;");
    let g = password_for_context(context(&rules), FfiPasswordProfile::Strong).unwrap();
    // The ninth string's maximum is never read: Strong stays at 24.
    assert_eq!(g.password.chars().count(), 24);
    // Blank strings do not count toward the 8.
    let mut rules = vec![" "; 8];
    rules.push("maxlength: 10;");
    let g = password_for_context(context(&rules), FfiPasswordProfile::Strong).unwrap();
    assert_eq!(g.password.chars().count(), 10);
}

#[test]
fn repeated_rule_strings_keep_the_maximum() {
    // Field, confirmation and quirk carry one string: each class counts
    // once, so four required classes still fit in 4 to 7 chars.
    let rule =
        "required: lower; required: upper; required: digit; required: special; maxlength: 7;";
    let ctx = FfiPasswordContext {
        rules: vec![rule.to_owned(), rule.to_owned()],
        quirk_rules: Some(rule.to_owned()),
        max_length: Some(7),
        ..FfiPasswordContext::default()
    };
    let g = password_for_context(ctx, FfiPasswordProfile::Strong).unwrap();
    assert!(!g.fallback);
    assert_eq!(g.password.chars().count(), 7);
}

#[test]
fn quirk_rules_are_the_quirk_tier() {
    // A quirk contradicting the field's rules is dropped, the field's kept.
    let ctx = FfiPasswordContext {
        rules: vec!["minlength: 20;".to_owned()],
        quirk_rules: Some("maxlength: 12;".to_owned()),
        ..FfiPasswordContext::default()
    };
    let g = password_for_context(ctx, FfiPasswordProfile::Strong).unwrap();
    assert!(!g.fallback);
    assert!(g.password.chars().count() >= 20);
    // Alone, the quirk applies.
    let ctx = FfiPasswordContext {
        quirk_rules: Some("maxlength: 12;".to_owned()),
        ..FfiPasswordContext::default()
    };
    let g = password_for_context(ctx, FfiPasswordProfile::Strong).unwrap();
    assert_eq!(g.password.chars().count(), 12);
}
