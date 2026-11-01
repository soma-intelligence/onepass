//! Reader of written password instructions shown near a signup field
//! ("8 à 20 caractères", "at least 12", "une majuscule"...). Deterministic:
//! the text is folded to lowercase ASCII, split into words, numbers and
//! symbols, then matched against fixed French and English phrase tables.
//! Linear time, no regex.

use super::constraints::{CharSet, Constraints};

/// The reader looks at this many chars of the text, no more.
const MAX_CHARS: usize = 600;
/// Lengths outside this range are ignored as noise.
const LENGTHS: std::ops::RangeInclusive<u32> = 1..=128;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tok<'a> {
    Word(&'a str),
    Num(u32),
    Sym(char),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Class {
    Upper,
    Lower,
    Digit,
    Special,
    Space,
}

/// Read `text` into constraints. Never fails: an empty `Constraints` comes
/// back when nothing is recognized.
pub fn parse_hints(text: &str) -> Constraints {
    let folded: String = text
        .chars()
        .take(MAX_CHARS)
        .flat_map(char::to_lowercase)
        .map(fold)
        .collect();
    let toks = tokenize(&folded);
    let mut out = Constraints::default();
    read_lengths(&toks, &mut out);
    read_classes(&toks, &mut out);
    out
}

/// Latin-1 and French accents to ASCII.
fn fold(c: char) -> char {
    match c {
        'é' | 'è' | 'ê' | 'ë' => 'e',
        'à' | 'â' | 'ä' => 'a',
        'î' | 'ï' => 'i',
        'ô' | 'ö' => 'o',
        'ù' | 'û' | 'ü' => 'u',
        'ç' => 'c',
        c => c,
    }
}

/// Punctuation that only separates words; any other ASCII punctuation is a
/// symbol token.
fn is_separator(c: char) -> bool {
    !c.is_ascii_graphic()
        || matches!(
            c,
            ',' | ';' | ':' | '.' | '\'' | '"' | '(' | ')' | '[' | ']'
        )
}

fn tokenize(s: &str) -> Vec<Tok<'_>> {
    let mut toks = Vec::new();
    let mut chars = s.char_indices().peekable();
    while let Some((start, c)) = chars.next() {
        if c.is_ascii_lowercase() {
            let mut end = start + 1;
            while let Some(&(i, n)) = chars.peek() {
                if !n.is_ascii_lowercase() {
                    break;
                }
                end = i + 1;
                chars.next();
            }
            toks.push(Tok::Word(&s[start..end]));
        } else if let Some(d) = c.to_digit(10).filter(|_| c.is_ascii_digit()) {
            let mut n = d;
            while let Some(&(_, next)) = chars.peek() {
                let Some(d) = next.to_digit(10).filter(|_| next.is_ascii_digit()) else {
                    break;
                };
                n = n.saturating_mul(10).saturating_add(d);
                chars.next();
            }
            toks.push(Tok::Num(n));
        } else if !is_separator(c) {
            toks.push(Tok::Sym(c));
        }
    }
    toks
}

fn word<'a>(toks: &[Tok<'a>], i: usize) -> Option<&'a str> {
    match toks.get(i) {
        Some(Tok::Word(w)) => Some(w),
        _ => None,
    }
}

fn num(toks: &[Tok<'_>], i: usize) -> Option<u32> {
    match toks.get(i) {
        Some(Tok::Num(n)) if LENGTHS.contains(n) => Some(*n),
        _ => None,
    }
}

fn is_unit(toks: &[Tok<'_>], i: usize) -> bool {
    matches!(
        word(toks, i),
        Some(
            "caractere"
                | "caracteres"
                | "character"
                | "characters"
                | "char"
                | "chars"
                | "car"
                | "signes"
        )
    )
}

fn set_min(out: &mut Constraints, n: u32) {
    out.min_length = out.min_length.max(n);
    out.recognized = true;
}

fn set_max(out: &mut Constraints, n: u32) {
    out.max_length = Some(out.max_length.map_or(n, |m| m.min(n)));
    out.recognized = true;
}

/// `n` is at `i`: does a minimum or maximum phrase come right before it?
fn prefix_kind(toks: &[Tok<'_>], i: usize) -> Option<bool> {
    let prev = |k: usize| i.checked_sub(k).and_then(|j| word(toks, j));
    match (prev(2), prev(1)) {
        (Some("au"), Some("moins")) | (_, Some("least" | "minimum" | "min" | "mini")) => Some(true),
        (Some("au"), Some("plus"))
        | (Some("up"), Some("to"))
        | (Some("jusqu"), Some("a"))
        | (Some("plus"), Some("de"))
        | (Some("more"), Some("than"))
        | (_, Some("most" | "maximum" | "max" | "maxi")) => Some(false),
        _ => None,
    }
}

fn read_lengths(toks: &[Tok<'_>], out: &mut Constraints) {
    let mut i = 0;
    while i < toks.len() {
        let Some(n) = num(toks, i) else {
            i += 1;
            continue;
        };
        // Range: "entre 8 et 20 caracteres", "8 a 20 caracteres", "8-20 characters".
        let sep = word(toks, i + 1);
        let is_sep = match (toks.get(i + 1), sep) {
            (Some(Tok::Sym('-')), _) | (_, Some("a" | "to")) => true,
            (_, Some("et" | "and")) => {
                matches!(
                    i.checked_sub(1).and_then(|j| word(toks, j)),
                    Some("entre" | "between")
                )
            }
            _ => false,
        };
        if is_sep
            && let Some(m) = num(toks, i + 2)
            && is_unit(toks, i + 3)
            && n <= m
        {
            set_min(out, n);
            set_max(out, m);
            i += 3;
            continue;
        }
        // "8+ characters"
        if toks.get(i + 1) == Some(&Tok::Sym('+')) && is_unit(toks, i + 2) {
            set_min(out, n);
        } else if is_unit(toks, i + 1) {
            // "au moins 12 caracteres", "20 caracteres maximum".
            match (prefix_kind(toks, i), word(toks, i + 2)) {
                (Some(true), _) | (None, Some("minimum" | "min" | "mini")) => set_min(out, n),
                (Some(false), _) | (None, Some("maximum" | "max" | "maxi")) => set_max(out, n),
                _ => {}
            }
        }
        i += 1;
    }
}

fn class_of(w: &str) -> Option<Class> {
    Some(match w {
        "majuscule" | "majuscules" | "uppercase" | "upper" | "capital" | "capitale"
        | "capitales" | "capitals" => Class::Upper,
        "minuscule" | "minuscules" | "lowercase" | "lower" => Class::Lower,
        "chiffre" | "chiffres" | "digit" | "digits" | "number" | "numbers" | "nombre"
        | "nombres" => Class::Digit,
        "special" | "speciale" | "speciaux" | "speciales" | "specials" | "symbole" | "symboles"
        | "symbol" | "symbols" => Class::Special,
        "espace" | "espaces" | "space" | "spaces" | "whitespace" | "blanc" | "blancs" => {
            Class::Space
        }
        _ => return None,
    })
}

fn is_negation(w: &str) -> bool {
    matches!(
        w,
        "sans" | "no" | "without" | "pas" | "aucun" | "aucune" | "non" | "not" | "ni"
    )
}

/// A negation sits up to 3 tokens before `i`, or "interdit"/"not allowed"
/// follows it.
fn negated(toks: &[Tok<'_>], i: usize) -> bool {
    let before = (1..=3)
        .filter_map(|k| i.checked_sub(k))
        .map_while(|j| match toks[j] {
            Tok::Word(w) => Some(w),
            _ => None,
        })
        .any(is_negation);
    #[allow(clippy::match_like_matches_macro)]
    let after = match (word(toks, i + 1), word(toks, i + 2)) {
        (
            Some(
                "interdit" | "interdits" | "interdite" | "interdites" | "forbidden" | "prohibited",
            ),
            _,
        ) => true,
        (Some("not"), Some("allowed" | "permitted" | "accepted")) => true,
        _ => false,
    };
    before || after
}

/// A "one / un / au moins" style quantity sits right before the class word,
/// possibly with a noun in between ("un caractere special").
fn quantified(toks: &[Tok<'_>], i: usize) -> bool {
    for k in 1..=3 {
        let Some(j) = i.checked_sub(k) else {
            return false;
        };
        match toks[j] {
            Tok::Word(w) if is_negation(w) => return false,
            Tok::Word("a") => {
                // "a" is also the French "à" of a range ("8 à 20").
                if !matches!(toks.get(j.wrapping_sub(1)), Some(Tok::Num(_))) {
                    return true;
                }
            }
            Tok::Word("un" | "une" | "one" | "an" | "moins" | "least") => return true,
            Tok::Num(n) if k == 1 && n >= 1 => return true,
            _ => {}
        }
    }
    false
}

fn listed_symbols(toks: &[Tok<'_>]) -> CharSet {
    let mut set = CharSet::default();
    for (i, t) in toks.iter().enumerate() {
        if matches!(t, Tok::Word("parmi" | "among" | "from" | "comme" | "like")) {
            set.extend(toks[i + 1..].iter().map_while(|t| match t {
                Tok::Sym(c) => Some(*c),
                _ => None,
            }));
        }
    }
    set
}

fn read_classes(toks: &[Tok<'_>], out: &mut Constraints) {
    let (mut upper, mut lower, mut digit, mut special) = (false, false, false, false);
    let (mut no_special, mut alnum_only) = (false, false);
    for (i, t) in toks.iter().enumerate() {
        let Tok::Word(w) = t else { continue };
        if matches!(
            *w,
            "alphanumeric" | "alphanumerique" | "alphanumeriques" | "alphanumerics"
        ) {
            let near = |k: usize| {
                word(toks, k).is_some_and(|x| matches!(x, "only" | "uniquement" | "seulement"))
            };
            alnum_only |= near(i + 1) || near(i + 2) || i.checked_sub(1).is_some_and(near);
            continue;
        }
        let Some(class) = class_of(w) else { continue };
        if matches!(class, Class::Digit) && matches!(word(toks, i + 1), Some("of" | "de")) {
            continue; // "number of characters"
        }
        if negated(toks, i) {
            match class {
                Class::Special => no_special = true,
                Class::Space => {
                    out.forbidden.extend([' ']);
                    out.recognized = true;
                }
                _ => {}
            }
        } else if quantified(toks, i) {
            match class {
                Class::Upper => upper = true,
                Class::Lower => lower = true,
                Class::Digit => digit = true,
                Class::Special => special = true,
                Class::Space => {}
            }
        }
    }
    let class = |n| CharSet::ascii_class(n).unwrap_or_default();
    let alnum = class("lower").union(&class("upper")).union(&class("digit"));
    if no_special || alnum_only {
        out.allowed = Some(alnum.clone());
        out.recognized = true;
    }
    for (on, name) in [(upper, "upper"), (lower, "lower"), (digit, "digit")] {
        if on {
            out.required.push(class(name));
            out.recognized = true;
        }
    }
    if special {
        let listed = listed_symbols(toks);
        if listed.is_empty() {
            out.required.push(class("special"));
        } else {
            out.allowed = Some(alnum.union(&listed));
            out.required.push(listed);
        }
        out.recognized = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(names: &[&str]) -> CharSet {
        names
            .iter()
            .map(|n| CharSet::ascii_class(n).unwrap())
            .fold(CharSet::default(), |a, s| a.union(&s))
    }

    fn lens(text: &str) -> (u32, Option<u32>) {
        let c = parse_hints(text);
        (c.min_length, c.max_length)
    }

    #[test]
    fn fr_range() {
        assert_eq!(lens("Entre 8 et 20 caractères"), (8, Some(20)));
    }

    #[test]
    fn fr_a_range() {
        assert_eq!(lens("8 à 20 caractères"), (8, Some(20)));
    }

    #[test]
    fn fr_min() {
        assert_eq!(lens("Au moins 12 caractères"), (12, None));
    }

    #[test]
    fn fr_max() {
        assert_eq!(lens("20 caractères maximum"), (0, Some(20)));
    }

    #[test]
    fn en_between() {
        assert_eq!(lens("between 8 and 64 characters"), (8, Some(64)));
    }

    #[test]
    fn en_plus() {
        assert_eq!(lens("8+ characters"), (8, None));
    }

    #[test]
    fn en_up_to() {
        assert_eq!(lens("up to 16 characters"), (0, Some(16)));
    }

    #[test]
    fn required_classes_fr() {
        let c = parse_hints("une majuscule, un chiffre et un caractère spécial");
        assert_eq!(
            c.required,
            vec![set(&["upper"]), set(&["digit"]), set(&["special"])]
        );
        assert!(c.recognized());
    }

    #[test]
    fn required_classes_en() {
        let c = parse_hints("one uppercase letter and a number");
        assert_eq!(c.required, vec![set(&["upper"]), set(&["digit"])]);
    }

    #[test]
    fn forbidden_specials() {
        let c = parse_hints("sans caractères spéciaux");
        assert_eq!(c.allowed, Some(set(&["lower", "upper", "digit"])));
        assert!(c.required.is_empty());
    }

    #[test]
    fn alnum_only_en() {
        let c = parse_hints("alphanumeric only");
        assert_eq!(c.allowed, Some(set(&["lower", "upper", "digit"])));
    }

    #[test]
    fn no_spaces() {
        let c = parse_hints("no spaces");
        assert!(c.forbidden.contains(' '));
        assert!(c.recognized());
    }

    #[test]
    fn listed_symbols() {
        let c = parse_hints("un symbole parmi !@#$%");
        let listed: CharSet = "!@#$%".chars().collect();
        assert_eq!(c.required, vec![listed.clone()]);
        assert_eq!(
            c.allowed,
            Some(set(&["lower", "upper", "digit"]).union(&listed))
        );
    }

    #[test]
    fn accents_and_case() {
        assert_eq!(lens("AU MOINS 10 CARACTERES"), (10, None));
    }

    #[test]
    fn out_of_range_number() {
        let c = parse_hints("au moins 500 caractères");
        assert_eq!(c.min_length, 0);
        assert!(!c.recognized());
    }

    #[test]
    fn huge_input() {
        let text = format!("{}au moins 12", "a".repeat(1 << 20));
        let start = std::time::Instant::now();
        let c = parse_hints(&text);
        assert!(start.elapsed() < std::time::Duration::from_millis(50));
        assert_eq!(c, Constraints::default());
    }

    #[test]
    fn no_false_positives() {
        assert_eq!(parse_hints(""), Constraints::default());
        let c = parse_hints("au moins 1 majuscule");
        assert_eq!(c.min_length, 0);
        assert_eq!(c.required, vec![set(&["upper"])]);
        // "à" of a range must not read as a quantity for "spéciaux".
        assert!(
            parse_hints("8 à 20 caractères spéciaux")
                .required
                .is_empty()
        );
        assert!(parse_hints("number of characters").required.is_empty());
    }
}
