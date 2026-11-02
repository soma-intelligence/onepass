//! Password constraints and the drawing loop that satisfies them.

use std::collections::BTreeSet;

use zeroize::Zeroizing;

use crate::generator::uniform_below;

/// Draws of a whole password before giving up on the constraints.
const ATTEMPTS: usize = 100;
/// Apple `special` class: ASCII punctuation they list, and the space.
const SPECIAL: &str = "-~!@#$%^&*_+=`|(){}[:;\"'<>,.? ";

/// A set of characters.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CharSet(BTreeSet<char>);

impl CharSet {
    /// One of the Apple class names: `upper`, `lower`, `digit`, `special`,
    /// `ascii-printable`, `unicode` (treated as `ascii-printable`).
    pub fn ascii_class(name: &str) -> Option<CharSet> {
        let ascii = |f: fn(&char) -> bool| ('\u{20}'..='\u{7e}').filter(&f).collect();
        Some(match name {
            "upper" => ascii(char::is_ascii_uppercase),
            "lower" => ascii(char::is_ascii_lowercase),
            "digit" => ascii(char::is_ascii_digit),
            "special" => SPECIAL.chars().collect(),
            "ascii-printable" | "unicode" => ascii(|_| true),
            _ => return None,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn contains(&self, c: char) -> bool {
        self.0.contains(&c)
    }

    pub fn iter(&self) -> impl Iterator<Item = char> + '_ {
        self.0.iter().copied()
    }

    pub fn intersection(&self, other: &CharSet) -> CharSet {
        CharSet(self.0.intersection(&other.0).copied().collect())
    }

    pub fn union(&self, other: &CharSet) -> CharSet {
        CharSet(self.0.union(&other.0).copied().collect())
    }

    pub fn difference(&self, other: &CharSet) -> CharSet {
        CharSet(self.0.difference(&other.0).copied().collect())
    }
}

impl FromIterator<char> for CharSet {
    fn from_iter<I: IntoIterator<Item = char>>(iter: I) -> Self {
        CharSet(iter.into_iter().collect())
    }
}

impl Extend<char> for CharSet {
    fn extend<I: IntoIterator<Item = char>>(&mut self, iter: I) {
        self.0.extend(iter);
    }
}

/// What a site accepts. Merging two sets keeps the strictest of each.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Constraints {
    pub min_length: u32,
    pub max_length: Option<u32>,
    /// Union of the `allowed` and `required` classes read. `None` while no
    /// class was named (everything allowed).
    pub allowed: Option<CharSet>,
    /// One set per `required` entry: the password holds one char of each.
    pub required: Vec<CharSet>,
    /// Chars never drawn, subtracted from `allowed`.
    pub forbidden: CharSet,
    pub max_consecutive: Option<u32>,
    /// At least one known property was read.
    pub(crate) recognized: bool,
}

impl Constraints {
    /// True when at least one known property was read, so the constraints
    /// are more than an empty rule set.
    pub fn recognized(&self) -> bool {
        self.recognized
    }

    /// Fold `other` in: max of `min_length`, min of `max_length` and
    /// `max_consecutive`, intersection of `allowed` (`None` is everything),
    /// `required` sets not already present appended, union of `forbidden`.
    /// The grammar has no counts: a rule string read twice (field and
    /// confirmation, or page and quirk) requires each class once.
    pub fn merge(&mut self, other: &Constraints) {
        self.recognized |= other.recognized;
        self.min_length = self.min_length.max(other.min_length);
        self.max_length = min_opt(self.max_length, other.max_length);
        self.max_consecutive = min_opt(self.max_consecutive, other.max_consecutive);
        self.allowed = match (self.allowed.take(), &other.allowed) {
            (Some(a), Some(b)) => Some(a.intersection(b)),
            (Some(a), None) => Some(a),
            (None, b) => b.clone(),
        };
        for set in &other.required {
            if !self.required.contains(set) {
                self.required.push(set.clone());
            }
        }
        self.forbidden = self.forbidden.union(&other.forbidden);
    }

    /// Whether some password can meet these constraints, length aside from
    /// the bounds themselves.
    pub fn satisfiable(&self) -> bool {
        if self.max_consecutive == Some(0) {
            return false;
        }
        if self
            .max_length
            .is_some_and(|max| max < self.min_length || max == 0)
        {
            return false;
        }
        let alphabet = self.alphabet();
        if alphabet.is_empty() {
            return false;
        }
        let fits = |set: &CharSet| !set.intersection(&alphabet).is_empty();
        self.required.iter().all(fits)
            && self
                .max_length
                .is_none_or(|max| self.required.len() <= max as usize)
    }

    /// Chars that may be drawn: `allowed` (all four classes when none was
    /// named) minus `forbidden`.
    fn alphabet(&self) -> CharSet {
        let allowed = self.allowed.clone().unwrap_or_else(|| {
            ["lower", "upper", "digit", "special"]
                .iter()
                .filter_map(|n| CharSet::ascii_class(n))
                .fold(CharSet::default(), |acc, s| acc.union(&s))
        });
        allowed.difference(&self.forbidden)
    }
}

fn min_opt(a: Option<u32>, b: Option<u32>) -> Option<u32> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

fn pick(set: &[char]) -> Option<char> {
    Some(set[uniform_below(set.len()).ok()?])
}

/// Length of the run of `c` ending at the end of `out`.
fn run_at_end(out: &[char], c: char) -> u32 {
    out.iter().rev().take_while(|x| **x == c).count() as u32
}

fn valid(out: &[char], max_consecutive: Option<u32>) -> bool {
    let edge_space = out.first() == Some(&' ') || out.last() == Some(&' ');
    let run_ok = max_consecutive.is_none_or(|max| {
        let mut run = 0;
        out.iter().enumerate().all(|(i, c)| {
            run = if i > 0 && out[i - 1] == *c {
                run + 1
            } else {
                1
            };
            run <= max
        })
    });
    !edge_space && run_ok
}

/// One attempt: a char of each required set at distinct random positions,
/// the rest drawn from the alphabet left to right, never extending a run
/// past `max-consecutive`. `None` when this attempt fails.
fn attempt(
    length: usize,
    alphabet: &[char],
    required: &[Vec<char>],
    max_consecutive: Option<u32>,
) -> Option<Zeroizing<Vec<char>>> {
    let mut fixed: Zeroizing<Vec<Option<char>>> = Zeroizing::new(vec![None; length]);
    let mut free: Vec<usize> = (0..length).collect();
    for group in required {
        let slot = free.swap_remove(uniform_below(free.len()).ok()?);
        fixed[slot] = Some(pick(group)?);
    }
    let mut out = Zeroizing::new(Vec::with_capacity(length));
    for (i, slot) in fixed.iter().enumerate() {
        let c = match slot {
            Some(c) => *c,
            None => {
                let candidates: Vec<char> = alphabet
                    .iter()
                    .copied()
                    .filter(|c| max_consecutive.is_none_or(|m| run_at_end(&out, *c) < m))
                    .filter(|c| *c != ' ' || (i != 0 && i != length - 1))
                    .collect();
                if candidates.is_empty() {
                    return None;
                }
                pick(&candidates)?
            }
        };
        out.push(c);
    }
    valid(&out, max_consecutive).then_some(out)
}

/// A password of `length` chars meeting `c`, or `None` when the constraints
/// cannot be met within 100 attempts. The caller picks `length` inside the
/// bounds of `c`.
pub fn draw(c: &Constraints, length: usize) -> Option<Zeroizing<String>> {
    if length == 0 || c.max_consecutive == Some(0) {
        return None;
    }
    let alphabet_set = c.alphabet();
    let alphabet: Vec<char> = alphabet_set.iter().collect();
    if alphabet.is_empty() {
        return None;
    }
    // Each required class is restricted to what is allowed.
    let required: Vec<Vec<char>> = c
        .required
        .iter()
        .map(|set| set.intersection(&alphabet_set).iter().collect::<Vec<_>>())
        .collect();
    if required.len() > length || required.iter().any(Vec::is_empty) {
        return None;
    }
    for _ in 0..ATTEMPTS {
        if let Some(chars) = attempt(length, &alphabet, &required, c.max_consecutive) {
            let mut password = Zeroizing::new(String::with_capacity(length * 4));
            password.extend(chars.iter());
            return Some(password);
        }
    }
    None
}
