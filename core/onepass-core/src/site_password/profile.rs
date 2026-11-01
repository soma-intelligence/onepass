//! Generator profiles over resolved site constraints, and `generate_for`,
//! the entry point: context in, password and secret-free report out.

use zeroize::Zeroizing;

use super::constraints::{CharSet, Constraints, draw};
use super::resolve::{MAX_LENGTH, PasswordContext, Source, resolve};
use crate::generator::{SYMBOLS, Wordlist, uniform_below, words_of};
use crate::{Error, Result, ValidationError};

/// Strong length when no source states a length.
const STRONG_DEFAULT: u32 = 24;
/// Strong stops here when a maximum allows more.
const STRONG_MAX: u32 = 32;
/// Readable word counts tried in turn: the default, shorter to fit a
/// maximum, then longer to meet a minimum.
const WORD_COUNTS: [usize; 6] = [5, 4, 3, 8, 7, 6];
/// Draws of a passphrase before falling back to Strong.
const READABLE_ATTEMPTS: usize = 100;
/// Below this, the report warns that the site forced a weak password.
const WEAK_BITS: f64 = 60.0;

/// How the password is built.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Profile {
    /// Random chars of every class allowed: 24, or the largest allowed up
    /// to 32 when the site states a maximum.
    Strong,
    /// French diceware words joined by `-`, one capital and one digit.
    Readable,
    /// The user's length (8..=64) and classes; lower and upper always on.
    Custom {
        length: u8,
        digits: bool,
        symbols: bool,
    },
}

/// What was generated, without any char of the password.
#[derive(Clone, Debug, PartialEq, serde::Serialize)]
pub struct GenerationReport {
    pub length: u32,
    pub lower: bool,
    pub upper: bool,
    pub digit: bool,
    pub special: bool,
    /// Sources whose constraints were applied.
    pub sources: Vec<Source>,
    /// Sources removed because they contradicted a more trusted one.
    pub dropped: Vec<Source>,
    /// The site constraints could not be met: the profile ran alone.
    pub fallback: bool,
    /// Readable did not fit the site and Strong was used instead.
    pub readable_fell_back: bool,
    /// `entropy_bits` is below 60.
    pub weak_by_site: bool,
    pub entropy_bits: f64,
}

/// Classes the profile draws from, before the site narrows them.
#[derive(Clone, Copy)]
struct Classes {
    lower: bool,
    upper: bool,
    digit: bool,
    special: bool,
}

impl Classes {
    /// `narrow = 1` drops symbols, `narrow = 2` keeps lower and digits.
    fn of(profile: &Profile, narrow: u8) -> Classes {
        let mut c = match profile {
            Profile::Strong | Profile::Readable => Classes {
                lower: true,
                upper: true,
                digit: true,
                special: true,
            },
            Profile::Custom {
                digits, symbols, ..
            } => Classes {
                lower: true,
                upper: true,
                digit: *digits,
                special: *symbols,
            },
        };
        if narrow >= 1 {
            c.special = false;
        }
        if narrow >= 2 {
            c = Classes {
                lower: true,
                upper: false,
                digit: true,
                special: false,
            };
        }
        c
    }
}

/// The chars a profile may use on a site.
struct Alphabet {
    all: CharSet,
    /// Profile classes present in `all`, each wanted at least once.
    groups: Vec<CharSet>,
    /// Symbols drawn freely (not only because the site requires them), in
    /// preference order.
    specials: Vec<char>,
}

fn class(name: &str) -> CharSet {
    CharSet::ascii_class(name).unwrap_or_default()
}

/// What the site accepts. With no class named, letters, digits and the
/// generator's symbols, plus whatever a required class names.
fn site_allowed(c: &Constraints) -> CharSet {
    let required: CharSet = c.required.iter().flat_map(CharSet::iter).collect();
    let base = match &c.allowed {
        Some(a) => a.clone(),
        None => ["lower", "upper", "digit"]
            .iter()
            .fold(SYMBOLS.chars().collect(), |acc: CharSet, n| {
                acc.union(&class(n))
            })
            .union(&required),
    };
    base.difference(&c.forbidden)
}

/// The profile classes met by the site. Symbols are the generator's when
/// the site takes any of them, else the site's own (never the space). Chars
/// of the required classes are always in, so a required `~` stays usable
/// whatever the profile or `narrow`.
fn alphabet(c: &Constraints, classes: Classes) -> Alphabet {
    let site = site_allowed(c);
    let mut groups = Vec::new();
    for (on, name) in [
        (classes.lower, "lower"),
        (classes.upper, "upper"),
        (classes.digit, "digit"),
    ] {
        let set = site.intersection(&class(name));
        if on && !set.is_empty() {
            groups.push(set);
        }
    }
    let mut specials: Vec<char> = Vec::new();
    if classes.special {
        specials = SYMBOLS.chars().filter(|ch| site.contains(*ch)).collect();
        if specials.is_empty() {
            specials = site
                .iter()
                .filter(|ch| !ch.is_ascii_alphanumeric() && *ch != ' ')
                .collect();
        }
        if !specials.is_empty() {
            groups.push(specials.iter().copied().collect());
        }
    }
    let required: CharSet = c.required.iter().flat_map(CharSet::iter).collect();
    let mut all = groups
        .iter()
        .fold(required.intersection(&site), |acc, g| acc.union(g));
    if all.is_empty() {
        // The profile wants nothing the site takes: use the site.
        let no_space: CharSet = site.iter().filter(|ch| *ch != ' ').collect();
        all = if no_space.is_empty() { site } else { no_space };
    }
    Alphabet {
        all,
        groups,
        specials,
    }
}

/// Bounds of the length, the 64 cap included.
fn bounds(c: &Constraints) -> (u32, u32) {
    (
        c.min_length,
        c.max_length.unwrap_or(MAX_LENGTH).min(MAX_LENGTH),
    )
}

fn strong_length(c: &Constraints) -> u32 {
    let (min, max) = bounds(c);
    let target = if c.max_length.is_some() {
        max.min(STRONG_MAX)
    } else {
        STRONG_DEFAULT
    };
    target.max(min).min(max)
}

fn custom_length(c: &Constraints, length: u8) -> u32 {
    let (min, max) = bounds(c);
    u32::from(length).clamp(8, MAX_LENGTH).max(min).min(max)
}

/// Random chars from the profile alphabet: every profile class and every
/// required class at least once, or only the required classes when the
/// length is too short for both.
fn random(c: &Constraints, classes: Classes, length: u32) -> Option<(Zeroizing<String>, f64)> {
    let a = alphabet(c, classes);
    let mut target = Constraints {
        allowed: Some(a.all.clone()),
        required: a.groups.iter().chain(&c.required).cloned().collect(),
        max_consecutive: c.max_consecutive,
        recognized: true,
        ..Constraints::default()
    };
    let length = length as usize;
    let password = draw(&target, length).or_else(|| {
        target.required = c.required.clone();
        draw(&target, length)
    })?;
    let bits = length as f64 * (a.all.len() as f64).log2();
    Some((password, bits))
}

fn holds_all(set: &CharSet, chars: &str) -> bool {
    chars.chars().all(|ch| set.contains(ch))
}

const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";

/// One run of `ch` longer than `max`.
fn too_long_run(p: &[char], max: Option<u32>) -> bool {
    let Some(max) = max else { return false };
    let mut run = 0;
    p.iter().enumerate().any(|(i, ch)| {
        run = if i > 0 && p[i - 1] == *ch { run + 1 } else { 1 };
        run > max
    })
}

/// A French passphrase that fits the site, or `None` (the caller falls back
/// to Strong). Word counts are tried in `WORD_COUNTS` order when their
/// expected length (average word of the list, separators, digit) is inside
/// the bounds; draws whose actual length is outside are rejected, so the
/// bounds always hold.
fn readable(c: &Constraints, classes: Classes) -> Option<(Zeroizing<String>, f64)> {
    let a = alphabet(c, classes);
    if !holds_all(&a.all, LOWER) {
        return None;
    }
    let capital = holds_all(&a.all, UPPER);
    let digit = holds_all(&a.all, DIGITS);
    let separator = if a.specials.contains(&'-') {
        Some('-')
    } else {
        a.specials.first().copied()
    };
    let list = words_of(Wordlist::FrenchDiceware);
    let longest = list.iter().map(|w| w.len()).max().unwrap_or(0);
    let average = list.iter().map(|w| w.len()).sum::<usize>() as f64 / list.len().max(1) as f64;
    let seps = |n: usize| if separator.is_some() { n - 1 } else { 0 };
    let (min, max) = bounds(c);
    let (min, max) = (min as usize, max as usize);
    let expected = |n: usize| n as f64 * average + (seps(n) + usize::from(digit)) as f64;
    WORD_COUNTS
        .into_iter()
        .filter(|&n| (min as f64..=max as f64).contains(&expected(n)))
        .find_map(|n| {
            let parts = Parts {
                words: n,
                separator,
                capital,
                digit,
                capacity: n * longest + seps(n) + 1 + c.required.len(),
            };
            (0..READABLE_ATTEMPTS).find_map(|_| passphrase(c, &a, list, &parts, min..=max))
        })
}

/// Shape of a passphrase draw.
struct Parts {
    words: usize,
    separator: Option<char>,
    capital: bool,
    digit: bool,
    /// Longest the draw can get, so the buffer never reallocates.
    capacity: usize,
}

/// One passphrase draw, `None` when it misses a constraint.
fn passphrase(
    c: &Constraints,
    a: &Alphabet,
    list: &[&str],
    p: &Parts,
    lengths: std::ops::RangeInclusive<usize>,
) -> Option<(Zeroizing<String>, f64)> {
    let (words, separator, capital, digit) = (p.words, p.separator, p.capital, p.digit);
    let mut out: Zeroizing<Vec<char>> = Zeroizing::new(Vec::with_capacity(p.capacity));
    let cap_at = uniform_below(words).ok()?;
    for i in 0..words {
        if i > 0
            && let Some(s) = separator
        {
            out.push(s);
        }
        let word = list[uniform_below(list.len()).ok()?];
        for (j, ch) in word.chars().enumerate() {
            out.push(if capital && i == cap_at && j == 0 {
                ch.to_ascii_uppercase()
            } else {
                ch
            });
        }
    }
    if digit {
        out.push(char::from(b'0' + uniform_below(10).ok()? as u8));
    }
    let mut bits = words as f64 * (list.len() as f64).log2();
    if capital {
        bits += (words as f64).log2();
    }
    if digit {
        bits += 10f64.log2();
    }
    // Required classes the words did not give: one char of each, added
    // at the end.
    for set in &c.required {
        if out.iter().any(|ch| set.contains(*ch)) {
            continue;
        }
        let pool: Vec<char> = set.intersection(&a.all).iter().collect();
        if pool.is_empty() {
            return None;
        }
        out.push(pool[uniform_below(pool.len()).ok()?]);
        bits += (pool.len() as f64).log2();
    }
    let edge_space = out.first() == Some(&' ') || out.last() == Some(&' ');
    if edge_space
        || too_long_run(&out, c.max_consecutive)
        || !out.iter().all(|ch| a.all.contains(*ch))
        || !lengths.contains(&out.len())
    {
        return None;
    }
    let mut password = Zeroizing::new(String::with_capacity(out.len() * 4));
    password.extend(out.iter());
    Some((password, bits))
}

/// The password of `profile` under `c`, and whether Readable gave way to
/// Strong.
fn run(
    c: &Constraints,
    profile: &Profile,
    classes: Classes,
) -> Option<(Zeroizing<String>, f64, bool)> {
    match profile {
        Profile::Strong => random(c, classes, strong_length(c)).map(|(p, b)| (p, b, false)),
        Profile::Custom { length, .. } => {
            random(c, classes, custom_length(c, *length)).map(|(p, b)| (p, b, false))
        }
        Profile::Readable => match readable(c, classes) {
            Some((p, b)) => Some((p, b, false)),
            None => random(c, classes, strong_length(c)).map(|(p, b)| (p, b, true)),
        },
    }
}

/// Generate a password for a signup field. `narrow` (0 to 2) is the
/// fallback level after the page refused a candidate: 1 drops symbols, 2
/// keeps lowercase and digits; classes the site requires are kept.
///
/// Errors: `Validation` on field `narrow` above 2; `Crypto` when the system
/// random source fails.
pub fn generate_for(
    ctx: &PasswordContext,
    profile: &Profile,
    narrow: u8,
) -> Result<(Zeroizing<String>, GenerationReport)> {
    if narrow > 2 {
        return Err(Error::Validation(ValidationError {
            field: "narrow".to_owned(),
            reason: "out of range",
        }));
    }
    let classes = Classes::of(profile, narrow);
    let mut resolved = resolve(ctx);
    let mut fallback = resolved.fallback;
    let generated = match run(&resolved.constraints, profile, classes) {
        Some(g) => g,
        None => {
            // Satisfiable on paper but no draw met it: the profile runs
            // alone, as for contradicting sources.
            fallback = true;
            resolved.dropped.append(&mut resolved.sources);
            run(&Constraints::default(), profile, classes).ok_or(Error::Crypto)?
        }
    };
    let (password, entropy_bits, gave_way) = generated;
    let has = |f: fn(&char) -> bool| password.chars().any(|ch| f(&ch));
    let report = GenerationReport {
        length: password.chars().count() as u32,
        lower: has(char::is_ascii_lowercase),
        upper: has(char::is_ascii_uppercase),
        digit: has(char::is_ascii_digit),
        special: has(|ch| !ch.is_ascii_alphanumeric()),
        sources: resolved.sources,
        dropped: resolved.dropped,
        fallback,
        readable_fell_back: gave_way,
        weak_by_site: entropy_bits < WEAK_BITS,
        entropy_bits,
    };
    Ok((password, report))
}
