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
    /// End of a clause: `,` `;` or `.` followed by a space or the end.
    Clause,
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
        } else if matches!(c, ',' | ';' | '.')
            && chars.peek().is_none_or(|&(_, n)| n.is_whitespace())
        {
            toks.push(Tok::Clause);
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
/// Returns `(is_min, bound)`. Bare "more than N" / "plus de N" is a minimum
/// of N + 1, "less than N" / "moins de N" a maximum of N - 1; the negated
/// forms ("no more than", "pas plus de", "pas moins de") keep N.
fn prefix_kind(toks: &[Tok<'_>], i: usize, n: u32) -> Option<(bool, u32)> {
    let prev = |k: usize| i.checked_sub(k).and_then(|j| word(toks, j));
    // "no more than", "pas plus de", "must not be more than", "cannot be more than".
    let is_not = |w: Option<&str>| matches!(w, Some("no" | "not" | "pas" | "cannot"));
    let negated = is_not(prev(3))
        || (matches!(prev(3), Some("be" | "etre" | "exceed" | "contain" | "have"))
            && is_not(prev(4)));
    // "minimum length 7": a noun sits between the phrase and the number.
    let (p2, p1) = if matches!(prev(1), Some("length" | "longueur" | "size" | "taille")) {
        (None, prev(2))
    } else {
        (prev(2), prev(1))
    };
    match (p2, p1) {
        (Some("au"), Some("moins")) | (_, Some("least" | "minimum" | "min" | "mini")) => {
            Some((true, n))
        }
        (Some("au"), Some("plus"))
        | (Some("up"), Some("to"))
        | (Some("jusqu"), Some("a"))
        | (_, Some("most" | "maximum" | "max" | "maxi")) => Some((false, n)),
        (Some("more"), Some("than")) | (Some("plus"), Some("de")) => {
            // "more than 128" would need 129: out of range, ignored.
            Some(if negated { (false, n) } else { (true, n + 1) })
                .filter(|&(_, m)| negated || LENGTHS.contains(&m))
        }
        (Some("less" | "fewer"), Some("than")) | (Some("moins"), Some("de")) => {
            if negated {
                Some((true, n))
            } else {
                Some((false, n - 1)).filter(|&(_, m)| m > 0)
            }
        }
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
            match (prefix_kind(toks, i, n), word(toks, i + 2)) {
                (Some((true, m)), _) => set_min(out, m),
                (Some((false, m)), _) => set_max(out, m),
                (None, Some("minimum" | "min" | "mini")) => set_min(out, n),
                (None, Some("maximum" | "max" | "maxi")) => set_max(out, n),
                _ => {}
            }
        } else if matches!(toks.get(i + 1), None | Some(Tok::Clause | Tok::Sym(_)))
            && let Some((is_min, m)) = prefix_kind(toks, i, n).filter(|_| explicit_bound(toks, i))
        {
            // Unit-less bound at the end of a clause: "at least 8", "min 8, max 20".
            if is_min {
                set_min(out, m);
            } else {
                set_max(out, m);
            }
        }
        i += 1;
    }
}

/// The phrase before the number at `i` names a bound outright ("at least",
/// "minimum", "max", "up to"...), not a comparison like "more than" that a
/// bare number could belong to something else.
fn explicit_bound(toks: &[Tok<'_>], i: usize) -> bool {
    matches!(
        (
            i.checked_sub(1).and_then(|j| word(toks, j)),
            i.checked_sub(2).and_then(|j| word(toks, j))
        ),
        (
            Some("least" | "minimum" | "min" | "mini" | "most" | "maximum" | "max" | "maxi"),
            _
        ) | (Some("moins" | "plus"), Some("au"))
            | (Some("to"), Some("up"))
    )
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
        "sans" | "no" | "without" | "pas" | "aucun" | "aucune" | "non" | "not" | "ni" | "cannot"
    )
}

/// A negation sits up to 3 tokens before `i` (not across a clause end or a
/// quantity word), or "interdit"/"not allowed" follows it.
fn negated(toks: &[Tok<'_>], i: usize) -> bool {
    let mut before = false;
    for k in 1..=3 {
        let Some(j) = i.checked_sub(k) else { break };
        match toks[j] {
            Tok::Word(w) if is_negation(w) => {
                before = true;
                break;
            }
            Tok::Word("un" | "une" | "one" | "an" | "moins" | "least") | Tok::Clause => break,
            _ => {}
        }
    }
    // "spaces are not allowed", "les espaces sont interdits".
    let skip = usize::from(matches!(
        word(toks, i + 1),
        Some("are" | "is" | "sont" | "est")
    ));
    let after = matches!(
        (word(toks, i + 1 + skip), word(toks, i + 2 + skip)),
        (
            Some(
                "interdit" | "interdits" | "interdite" | "interdites" | "forbidden" | "prohibited"
            ),
            _
        ) | (Some("not"), Some("allowed" | "permitted" | "accepted"))
    );
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
            Tok::Clause => return false,
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
            // Symbols may be comma separated: "like !, @, #".
            let rest = &toks[i + 1..];
            set.extend(
                rest.iter()
                    .enumerate()
                    .map_while(|(k, t)| match t {
                        Tok::Sym(c) => Some(Some(*c)),
                        Tok::Clause if matches!(rest.get(k + 1), Some(Tok::Sym(_))) => Some(None),
                        _ => None,
                    })
                    .flatten(),
            );
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
        if matches!(*w, "lettres" | "letters")
            && matches!(word(toks, i + 1), Some("et" | "and"))
            && matches!(
                word(toks, i + 2),
                Some("chiffres" | "nombres" | "numbers" | "digits")
            )
        {
            let only = |k: Option<usize>| {
                k.and_then(|k| word(toks, k))
                    .is_some_and(|x| matches!(x, "only" | "uniquement" | "seulement"))
            };
            alnum_only |= only(Some(i + 3)) || only(i.checked_sub(1)) || only(i.checked_sub(2));
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
    fn fr_letters_digits_only() {
        let c = parse_hints("lettres et chiffres uniquement");
        assert_eq!(c.allowed, Some(set(&["lower", "upper", "digit"])));
        assert!(c.required.is_empty());
    }

    #[test]
    fn en_letters_numbers_only() {
        for t in [
            "letters and numbers only",
            "letters and digits only",
            "only letters and numbers",
        ] {
            assert_eq!(
                parse_hints(t).allowed,
                Some(set(&["lower", "upper", "digit"])),
                "{t}"
            );
        }
    }

    #[test]
    fn en_more_than_is_min() {
        assert_eq!(lens("more than 12 characters"), (13, None));
        assert_eq!(lens("less than 20 characters"), (0, Some(19)));
    }

    #[test]
    fn fr_plus_de_is_min() {
        assert_eq!(lens("plus de 12 caractères"), (13, None));
        assert_eq!(lens("moins de 20 caractères"), (0, Some(19)));
    }

    #[test]
    fn en_no_more_than_is_max() {
        assert_eq!(lens("no more than 12 characters"), (0, Some(12)));
        assert_eq!(lens("pas plus de 12 caractères"), (0, Some(12)));
    }

    #[test]
    fn no_spaces_then_special() {
        let c = parse_hints("no spaces, a special character");
        assert!(c.forbidden.contains(' '));
        assert_eq!(c.required, vec![set(&["special"])]);
        assert_eq!(c.allowed, None);
    }

    #[test]
    fn sans_espace_puis_chiffre() {
        let c = parse_hints("sans espace, un chiffre");
        assert!(c.forbidden.contains(' '));
        assert_eq!(c.required, vec![set(&["digit"])]);
    }

    #[test]
    fn minimum_length_noun() {
        assert_eq!(lens("minimum length 7 characters must contain"), (7, None));
        assert_eq!(lens("maximum length 20 characters"), (0, Some(20)));
    }

    #[test]
    fn must_not_be_more_than_is_max() {
        assert_eq!(lens("must not be more than 12 characters"), (0, Some(12)));
        assert_eq!(lens("cannot be more than 12 characters"), (0, Some(12)));
        assert_eq!(lens("must not be less than 8 characters"), (8, None));
    }

    #[test]
    fn more_than_128_is_ignored() {
        let c = parse_hints("more than 128 characters");
        assert_eq!(c.min_length, 0);
        assert!(!c.recognized());
    }

    #[test]
    fn comma_separated_symbols() {
        let c = parse_hints("a symbol like !, @, #");
        let listed: CharSet = "!@#".chars().collect();
        assert_eq!(c.required, vec![listed]);
    }

    #[test]
    fn spaces_not_allowed_forms() {
        for t in [
            "spaces are not allowed",
            "cannot contain spaces",
            "les espaces sont interdits",
        ] {
            assert!(parse_hints(t).forbidden.contains(' '), "{t}");
        }
    }

    #[test]
    fn unitless_bounds() {
        assert_eq!(lens("at least 8"), (8, None));
        assert_eq!(lens("min 8, max 20 characters"), (8, Some(20)));
        assert_eq!(lens("Au moins 10."), (10, None));
        // A class quantity is not a length.
        assert_eq!(lens("at least 1 uppercase"), (0, None));
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
