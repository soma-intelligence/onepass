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
