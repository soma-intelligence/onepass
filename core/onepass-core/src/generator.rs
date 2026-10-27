//! Generator of random passwords, passphrases and PINs.
//!
//! Every random choice is made by rejection sampling on CSPRNG bytes
//! (`crypto::fill_random`), never by a plain modulo, so each choice is
//! exactly uniform.

use crate::crypto::fill_random;
use crate::{Error, Result, ValidationError};
use std::sync::OnceLock;
use zeroize::{Zeroize, Zeroizing};

/// Symbols offered by the random generator. Chosen because most sites
/// accept them: none is a quote, backslash, space, bracket, slash or pipe.
const SYMBOLS: &str = "-_.!?#@$%&*+=";
const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";
/// Characters that are easy to confuse. Removed from every class when
/// `avoid_ambiguous` is set.
const AMBIGUOUS: &str = "0Oo1lI|`'\"";

const EFF_LIST: &str = include_str!("../data/eff_large_wordlist.txt");
const FR_LIST: &str = include_str!("../data/fr_diceware_wordlist.txt");

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CharsetOptions {
    /// 8..=100
    pub length: u8,
    pub lower: bool,
    pub upper: bool,
    pub digits: bool,
    pub symbols: bool,
    pub avoid_ambiguous: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wordlist {
    EffEnglish,
    FrenchDiceware,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PassphraseOptions {
    /// 3..=20
    pub words: u8,
    pub separator: String,
    pub capitalize: bool,
    pub include_digit: bool,
    pub list: Wordlist,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recipe {
    Random(CharsetOptions),
    Passphrase(PassphraseOptions),
    /// `digits` in 4..=12
    Pin {
        digits: u8,
    },
}

fn out_of_range(field: &str) -> Error {
    Error::Validation(ValidationError {
        field: field.to_owned(),
        reason: "out of range",
    })
}

/// Uniform integer in `0..n`, by rejection on 32 random bits: draws at or
/// above the largest multiple of `n` that fits in 2^32 are discarded, so
/// there is no modulo bias. `n` must be in `1..=2^32`.
fn uniform_below(n: usize) -> Result<usize> {
    debug_assert!(n >= 1 && n as u64 <= 1 << 32);
    let n = n as u64;
    let limit = (1u64 << 32) - ((1u64 << 32) % n);
    let mut buf = Zeroizing::new([0u8; 4]);
    loop {
        fill_random(&mut *buf)?;
        let r = u64::from(u32::from_be_bytes(*buf));
        if r < limit {
            return Ok((r % n) as usize);
        }
    }
}

fn words_of(list: Wordlist) -> &'static [&'static str] {
    static EFF: OnceLock<Vec<&'static str>> = OnceLock::new();
    static FR: OnceLock<Vec<&'static str>> = OnceLock::new();
    let (cell, text) = match list {
        Wordlist::EffEnglish => (&EFF, EFF_LIST),
        Wordlist::FrenchDiceware => (&FR, FR_LIST),
    };
    cell.get_or_init(|| text.lines().filter(|l| !l.is_empty()).collect())
}

fn keep(c: &char, avoid_ambiguous: bool) -> bool {
    !(avoid_ambiguous && AMBIGUOUS.contains(*c))
}

/// Enabled classes, each already stripped of ambiguous characters.
fn classes(o: &CharsetOptions) -> Vec<Vec<char>> {
    [
        (o.lower, LOWER),
        (o.upper, UPPER),
        (o.digits, DIGITS),
        (o.symbols, SYMBOLS),
    ]
    .into_iter()
    .filter(|(on, _)| *on)
    .map(|(_, set)| set.chars().filter(|c| keep(c, o.avoid_ambiguous)).collect())
    .collect()
}

fn random_password(o: &CharsetOptions) -> Result<Zeroizing<String>> {
    if !(8..=100).contains(&o.length) {
        return Err(out_of_range("length"));
    }
    let classes = classes(o);
    if classes.is_empty() {
        return Err(out_of_range("classes"));
    }
    let alphabet: Vec<char> = classes.iter().flatten().copied().collect();
    // Draw the whole password uniformly, then reject it and draw again if an
    // enabled class is missing. The result is uniform over the passwords that
    // contain every class, with no position bias (unlike forcing one
    // character per class into fixed or shuffled slots).
    let mut candidate = Zeroizing::new(String::with_capacity(usize::from(o.length)));
    loop {
        for _ in 0..o.length {
            candidate.push(alphabet[uniform_below(alphabet.len())?]);
        }
        if classes
            .iter()
            .all(|class| candidate.chars().any(|c| class.contains(&c)))
        {
            return Ok(candidate);
        }
        candidate.zeroize();
    }
}

fn passphrase(o: &PassphraseOptions) -> Result<Zeroizing<String>> {
    if !(3..=20).contains(&o.words) {
        return Err(out_of_range("words"));
    }
    let list = words_of(o.list);
    let mut chosen: Vec<&'static str> = Vec::with_capacity(usize::from(o.words));
    for _ in 0..o.words {
        chosen.push(list[uniform_below(list.len())?]);
    }
    let capacity =
        chosen.iter().map(|w| w.len()).sum::<usize>() + o.separator.len() * (chosen.len() - 1) + 1;
    let mut out = Zeroizing::new(String::with_capacity(capacity));
    for (i, word) in chosen.iter().enumerate() {
        if i > 0 {
            out.push_str(&o.separator);
        }
        if o.capitalize {
            // Word lists are lowercase ASCII.
            let mut chars = word.chars();
            if let Some(first) = chars.next() {
                out.push(first.to_ascii_uppercase());
                out.push_str(chars.as_str());
            }
        } else {
            out.push_str(word);
        }
    }
    if o.include_digit {
        let d = uniform_below(10)? as u8;
        out.push(char::from(b'0' + d));
    }
    Ok(out)
}

fn pin(digits: u8) -> Result<Zeroizing<String>> {
    if !(4..=12).contains(&digits) {
        return Err(out_of_range("digits"));
    }
    let mut out = Zeroizing::new(String::with_capacity(usize::from(digits)));
    for _ in 0..digits {
        out.push(char::from(b'0' + uniform_below(10)? as u8));
    }
    Ok(out)
}

/// Generate a secret from a recipe. Out-of-range parameters give
/// `Error::Validation` naming the field (`length`, `words`, `digits`, or
/// `classes` when no character class is enabled).
pub fn generate(recipe: &Recipe) -> Result<Zeroizing<String>> {
    match recipe {
        Recipe::Random(o) => random_password(o),
        Recipe::Passphrase(o) => passphrase(o),
        Recipe::Pin { digits } => pin(*digits),
    }
}

/// Entropy of the recipe in bits, assuming the parameters are in range.
///
/// - Random: `length * log2(alphabet size)`. The "one of each class" rule
///   removes a small share of the space and is ignored, so this is a slight
///   overestimate.
/// - Passphrase: `words * log2(7776)`, plus `log2(10)` when `include_digit`
///   (the digit is always appended at the end). The separator and
///   capitalization are fixed choices and add nothing.
/// - Pin: `digits * log2(10)`.
pub fn entropy_bits(recipe: &Recipe) -> f64 {
    match recipe {
        Recipe::Random(o) => {
            let size = classes(o).iter().map(Vec::len).sum::<usize>();
            if size == 0 {
                0.0
            } else {
                f64::from(o.length) * (size as f64).log2()
            }
        }
        Recipe::Passphrase(o) => {
            let list = words_of(o.list).len() as f64;
            f64::from(o.words) * list.log2() + if o.include_digit { 10f64.log2() } else { 0.0 }
        }
        Recipe::Pin { digits } => f64::from(*digits) * 10f64.log2(),
    }
}

/// Strength estimate of a typed or stored password, in bits, on the same
/// scale as `entropy_bits` so a meter shows the same level for a generated
/// password and for the same password once saved:
///
/// - only ASCII digits: a PIN, `digits * log2(10)`;
/// - at least 3 words of one of the generator's lists (any case) joined by
///   one repeated separator: `words * log2(list size)`, as `Recipe::Passphrase`;
/// - otherwise `length * log2(pool)`, the pool summing the classes present
///   with the generator's sizes (lower 26, upper 26, digits 10, its 13
///   symbols), 33 for any other printable ASCII character instead of the 13
///   symbols, and 100 for anything outside ASCII. A generated random password
///   holds every enabled class, so this equals `entropy_bits` for its recipe
///   (without `avoid_ambiguous`, which it slightly overestimates).
///
/// A hint for a meter, not a guarantee: patterns and dictionary words that
/// are not a generator passphrase are not detected.
pub fn strength_bits(password: &str) -> f64 {
    if password.is_empty() {
        return 0.0;
    }
    let length = password.chars().count() as f64;
    if password.bytes().all(|b| b.is_ascii_digit()) {
        return length * 10f64.log2();
    }
    let (mut lower, mut upper, mut digit, mut symbol, mut other_ascii, mut non_ascii) =
        (false, false, false, false, false, false);
    for c in password.chars() {
        match c {
            'a'..='z' => lower = true,
            'A'..='Z' => upper = true,
            '0'..='9' => digit = true,
            c if SYMBOLS.contains(c) => symbol = true,
            c if c.is_ascii() => other_ascii = true,
            _ => non_ascii = true,
        }
    }
    let pool = [
        (lower, 26),
        (upper, 26),
        (digit, 10),
        (symbol && !other_ascii, 13),
        (other_ascii, 33),
        (non_ascii, 100),
    ]
    .iter()
    .filter(|(on, _)| *on)
    .map(|(_, n)| *n)
    .sum::<u32>();
    let pool_bits = length * f64::from(pool).log2();
    match passphrase_words(password) {
        Some((words, list)) => (words as f64 * (list as f64).log2()).min(pool_bits),
        None => pool_bits,
    }
}

/// `(word count, list size)` when `password` is at least 3 words of one
/// generator list joined by a single repeated separator (a word of the list
/// may itself hold a hyphen, like `t-shirt`, whatever the separator).
fn passphrase_words(password: &str) -> Option<(usize, usize)> {
    let lower = Zeroizing::new(password.to_lowercase());
    let mut separators: Vec<char> = lower.chars().filter(|c| !c.is_ascii_lowercase()).collect();
    separators.sort_unstable();
    separators.dedup();
    if separators.is_empty() || separators.len() > 2 {
        return None;
    }
    let mut best: Option<(usize, usize)> = None;
    for &sep in &separators {
        let parts: Vec<&str> = lower.split(sep).collect();
        for list in [Wordlist::FrenchDiceware, Wordlist::EffEnglish] {
            let words = words_of(list);
            if let Some(n) = count_words(&parts, sep, words).filter(|n| *n >= 3)
                && best.is_none_or(|(b, _)| n < b)
            {
                best = Some((n, words.len()));
            }
        }
    }
    best
}

/// Fewest list words covering `parts` in order (a word spans one part, or two
/// parts joined by the separator), or None.
fn count_words(parts: &[&str], sep: char, words: &[&str]) -> Option<usize> {
    let known = |w: &str| words.contains(&w);
    let mut best: Vec<Option<usize>> = vec![None; parts.len() + 1];
    best[0] = Some(0);
    for i in 0..parts.len() {
        let Some(so_far) = best[i] else { continue };
        if known(parts[i]) {
            best[i + 1] = Some(best[i + 1].map_or(so_far + 1, |b| b.min(so_far + 1)));
        }
        if i + 1 < parts.len() {
            let joined = Zeroizing::new(format!("{}{sep}{}", parts[i], parts[i + 1]));
            if known(&joined) {
                best[i + 2] = Some(best[i + 2].map_or(so_far + 1, |b| b.min(so_far + 1)));
            }
        }
    }
    best[parts.len()]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_classes(length: u8) -> Recipe {
        Recipe::Random(CharsetOptions {
            length,
            lower: true,
            upper: true,
            digits: true,
            symbols: true,
            avoid_ambiguous: true,
        })
    }

    fn validation_field(r: &Recipe) -> String {
        match generate(r) {
            Err(Error::Validation(v)) => {
                assert_eq!(v.reason, "out of range");
                v.field
            }
            other => panic!("expected validation error, got {other:?}"),
        }
    }

    #[test]
    fn random_respects_length_and_classes() {
        let r = all_classes(20);
        for _ in 0..200 {
            let p = generate(&r).unwrap();
            assert_eq!(p.chars().count(), 20);
            assert!(
                p.chars().any(|c| c.is_ascii_lowercase())
                    && p.chars().any(|c| c.is_ascii_uppercase())
                    && p.chars().any(|c| c.is_ascii_digit())
                    && p.chars().any(|c| !c.is_ascii_alphanumeric())
            );
            assert!(!p.contains(['0', 'O', 'o', '1', 'l', 'I']));
        }
    }

    #[test]
    fn random_minimum_length_still_has_every_class() {
        let r = all_classes(8);
        for _ in 0..500 {
            let p = generate(&r).unwrap();
            assert_eq!(p.chars().count(), 8);
            assert!(
                p.chars().any(|c| c.is_ascii_lowercase())
                    && p.chars().any(|c| c.is_ascii_uppercase())
                    && p.chars().any(|c| c.is_ascii_digit())
                    && p.chars().any(|c| SYMBOLS.contains(c))
            );
        }
    }

    #[test]
    fn random_uses_only_the_enabled_classes_and_symbol_set() {
        let r = Recipe::Random(CharsetOptions {
            length: 100,
            lower: false,
            upper: false,
            digits: true,
            symbols: true,
            avoid_ambiguous: false,
        });
        for _ in 0..50 {
            let p = generate(&r).unwrap();
            assert!(p.chars().all(|c| c.is_ascii_digit() || SYMBOLS.contains(c)));
            assert!(p.chars().any(|c| c.is_ascii_digit()));
            assert!(p.chars().any(|c| SYMBOLS.contains(c)));
        }
    }

    #[test]
    fn random_ambiguous_set_is_excluded_from_every_class() {
        let r = all_classes(100);
        for _ in 0..50 {
            let p = generate(&r).unwrap();
            assert!(!p.contains(|c| AMBIGUOUS.contains(c)));
        }
    }

    #[test]
    fn random_without_any_class_is_rejected() {
        let r = Recipe::Random(CharsetOptions {
            length: 20,
            lower: false,
            upper: false,
            digits: false,
            symbols: false,
            avoid_ambiguous: false,
        });
        assert_eq!(validation_field(&r), "classes");
    }

    #[test]
    fn wordlists_have_7776_unique_words() {
        for list in [Wordlist::EffEnglish, Wordlist::FrenchDiceware] {
            let words = words_of(list);
            assert_eq!(words.len(), 7776);
            let unique: std::collections::HashSet<&str> = words.iter().copied().collect();
            assert_eq!(unique.len(), 7776);
            assert!(
                words
                    .iter()
                    .all(|w| !w.is_empty() && !w.contains(char::is_whitespace))
            );
        }
    }

    #[test]
    fn wordlists_are_lowercase_and_nfc() {
        use unicode_normalization::UnicodeNormalization;
        for list in [Wordlist::EffEnglish, Wordlist::FrenchDiceware] {
            for &w in words_of(list).iter() {
                assert_eq!(w, w.to_lowercase(), "{list:?}: {w:?}");
                assert_eq!(w, w.nfc().collect::<String>(), "{list:?}: {w:?}");
            }
        }
    }

    fn passphrase(words: u8, capitalize: bool, include_digit: bool, list: Wordlist) -> Recipe {
        Recipe::Passphrase(PassphraseOptions {
            words,
            separator: "-".into(),
            capitalize,
            include_digit,
            list,
        })
    }

    #[test]
    fn passphrase_entropy() {
        let r = passphrase(6, false, false, Wordlist::EffEnglish);
        assert!((entropy_bits(&r) - 77.5).abs() < 0.1);
        let r = passphrase(6, true, true, Wordlist::FrenchDiceware);
        assert!((entropy_bits(&r) - (77.5 + 10f64.log2())).abs() < 0.1);
    }

    #[test]
    fn random_and_pin_entropy() {
        // 20 characters over 26 + 26 + 10 + 13 = 75 symbols.
        let r = Recipe::Random(CharsetOptions {
            length: 20,
            lower: true,
            upper: true,
            digits: true,
            symbols: true,
            avoid_ambiguous: false,
        });
        assert!((entropy_bits(&r) - 20.0 * 75f64.log2()).abs() < 1e-9);
        assert!((entropy_bits(&Recipe::Pin { digits: 6 }) - 6.0 * 10f64.log2()).abs() < 1e-9);
    }

    #[test]
    fn passphrase_has_the_requested_shape() {
        for list in [Wordlist::EffEnglish, Wordlist::FrenchDiceware] {
            let words = words_of(list);
            let r = Recipe::Passphrase(PassphraseOptions {
                words: 5,
                separator: " + ".into(),
                capitalize: true,
                include_digit: true,
                list,
            });
            for _ in 0..50 {
                let p = generate(&r).unwrap();
                let parts: Vec<&str> = p.split(" + ").collect();
                assert_eq!(parts.len(), 5);
                let (last, rest) = parts.split_last().unwrap();
                let digit = last.chars().last().unwrap();
                assert!(digit.is_ascii_digit());
                let last_word = &last[..last.len() - 1];
                for part in rest.iter().copied().chain([last_word]) {
                    let first = part.chars().next().unwrap();
                    assert!(first.is_uppercase());
                    let lower = part.to_lowercase();
                    assert!(words.contains(&lower.as_str()), "{lower} not in the list");
                }
            }
        }
    }

    #[test]
    fn passphrase_plain_has_no_digit_and_no_capital() {
        let r = passphrase(4, false, false, Wordlist::EffEnglish);
        let words = words_of(Wordlist::EffEnglish);
        let p = generate(&r).unwrap();
        let parts: Vec<&str> = p.split('-').collect();
        // EFF contains a few hyphenated words, so only check the lower bound.
        assert!(parts.len() >= 4);
        assert!(
            !p.chars()
                .any(|c| c.is_ascii_digit() || c.is_ascii_uppercase())
        );
        assert!(words.iter().any(|w| p.starts_with(w)));
    }

    #[test]
    fn pin_digits_only() {
        for n in 4..=12u8 {
            let p = generate(&Recipe::Pin { digits: n }).unwrap();
            assert_eq!(p.len(), n as usize);
            assert!(p.chars().all(|c| c.is_ascii_digit()));
        }
    }

    #[test]
    fn out_of_range_is_rejected() {
        assert_eq!(validation_field(&all_classes(7)), "length");
        assert_eq!(validation_field(&all_classes(101)), "length");
        assert_eq!(
            validation_field(&passphrase(2, false, false, Wordlist::EffEnglish)),
            "words"
        );
        assert_eq!(
            validation_field(&passphrase(21, false, false, Wordlist::EffEnglish)),
            "words"
        );
        assert_eq!(validation_field(&Recipe::Pin { digits: 3 }), "digits");
        assert_eq!(validation_field(&Recipe::Pin { digits: 13 }), "digits");
    }

    #[test]
    fn range_bounds_are_accepted() {
        assert!(generate(&all_classes(8)).is_ok());
        assert!(generate(&all_classes(100)).is_ok());
        assert!(generate(&passphrase(3, false, false, Wordlist::EffEnglish)).is_ok());
        assert!(generate(&passphrase(20, false, false, Wordlist::EffEnglish)).is_ok());
        assert!(generate(&Recipe::Pin { digits: 4 }).is_ok());
        assert!(generate(&Recipe::Pin { digits: 12 }).is_ok());
    }

    #[test]
    fn two_draws_differ() {
        let r = all_classes(32);
        assert_ne!(*generate(&r).unwrap(), *generate(&r).unwrap());
    }

    #[test]
    fn uniform_below_is_flat_over_ten_values() {
        let mut counts = [0u32; 10];
        for _ in 0..100_000 {
            counts[uniform_below(10).unwrap()] += 1;
        }
        for (v, c) in counts.iter().enumerate() {
            assert!((9_600..=10_400).contains(c), "value {v} drawn {c} times");
        }
    }

    #[test]
    fn uniform_below_stays_in_range_for_awkward_bounds() {
        for n in [1usize, 2, 3, 7, 75, 255, 256, 257, 7776, 65_535, 65_537] {
            for _ in 0..200 {
                assert!(uniform_below(n).unwrap() < n);
            }
        }
    }

    #[test]
    fn strength_of_a_generated_password_matches_its_recipe() {
        let recipes = [
            Recipe::Pin { digits: 6 },
            Recipe::Passphrase(PassphraseOptions {
                words: 5,
                separator: "-".into(),
                capitalize: false,
                include_digit: false,
                list: Wordlist::FrenchDiceware,
            }),
            Recipe::Passphrase(PassphraseOptions {
                words: 4,
                separator: " ".into(),
                capitalize: true,
                include_digit: false,
                list: Wordlist::EffEnglish,
            }),
            Recipe::Passphrase(PassphraseOptions {
                words: 6,
                separator: ".".into(),
                capitalize: false,
                include_digit: false,
                list: Wordlist::EffEnglish,
            }),
        ];
        for recipe in recipes.iter().chain(
            [8u8, 13, 16, 20, 40]
                .iter()
                .flat_map(|&length| {
                    [(true, true), (true, false), (false, true), (false, false)].map(
                        |(digits, symbols)| {
                            Recipe::Random(CharsetOptions {
                                length,
                                lower: true,
                                upper: true,
                                digits,
                                symbols,
                                avoid_ambiguous: false,
                            })
                        },
                    )
                })
                .collect::<Vec<_>>()
                .iter(),
        ) {
            for _ in 0..200 {
                let generated = generate(recipe).unwrap();
                let expected = entropy_bits(recipe);
                let got = strength_bits(&generated);
                assert!(
                    (got - expected).abs() < 1e-9,
                    "{recipe:?}: {got} != {expected}"
                );
            }
        }
    }

    #[test]
    fn strength_of_typed_passwords() {
        assert_eq!(strength_bits(""), 0.0);
        assert!((strength_bits("abcd") - 4.0 * 26f64.log2()).abs() < 1e-9);
        // `~` is not one of the generator's symbols: the 33 printable ones count.
        assert!((strength_bits("ab~d") - 4.0 * 59f64.log2()).abs() < 1e-9);
        assert!(strength_bits("tj7N-qe4L-wPz9-Kc2m!") >= 100.0);
        // Two list words are not a passphrase; a hyphenated list word is one word.
        let two = strength_bits("abacus-abdomen");
        assert!((two - 14.0 * 39f64.log2()).abs() < 1e-9);
        let hyphenated = strength_bits("t-shirt-abacus-abdomen");
        assert!((hyphenated - 3.0 * 7776f64.log2()).abs() < 1e-9);
        let spaced = strength_bits("Abacus T-shirt Abdomen Drop-down");
        assert!((spaced - 4.0 * 7776f64.log2()).abs() < 1e-9);
    }
}
