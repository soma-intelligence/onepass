//! Passwords that follow Apple `passwordrules` strings.
//!
//! The AutoFill extension receives the rules of the site (field, confirmation
//! field, system fixes) and must generate a password that satisfies them.
//! Parsing is tolerant: unknown properties are ignored and names are case
//! insensitive, but a known property with a malformed value makes the whole
//! rule set unreadable. Unreadable and contradictory rule sets, like an empty
//! one, are answered with the fallback recipe through `generate_password`.

use std::collections::BTreeSet;

use onepass_core::crypto::fill_random;
use zeroize::Zeroizing;

use crate::{FfiPasswordRecipe, OnePassError, generate_password};

/// Target length when the rules leave room.
const TARGET_LENGTH: u32 = 20;
/// Longest password generated, whatever the rules say.
const MAX_LENGTH: u32 = 64;
/// Draws of a whole password before giving up on the rules.
const ATTEMPTS: usize = 100;
/// Apple `special` class: ASCII punctuation they list, and the space.
const SPECIAL: &str = "-~!@#$%^&*_+=`|(){}[:;\"'<>,.? ";

type CharSet = BTreeSet<char>;

/// Constraints accumulated over every rule string. The strictest wins.
#[derive(Default)]
struct Rules {
    /// Union of the `allowed` and `required` classes of the rule string(s)
    /// read so far. `None` while none was named.
    allowed: Option<CharSet>,
    /// One set per `required` entry: the password holds one char of each.
    required: Vec<CharSet>,
    min_length: u32,
    max_length: Option<u32>,
    max_consecutive: Option<u32>,
    /// At least one known property was read.
    recognized: bool,
}

fn class_set(name: &str) -> Option<CharSet> {
    let ascii = |f: fn(&char) -> bool| ('\u{20}'..='\u{7e}').filter(&f).collect();
    Some(match name {
        "upper" => ascii(char::is_ascii_uppercase),
        "lower" => ascii(char::is_ascii_lowercase),
        "digit" => ascii(char::is_ascii_digit),
        "special" => SPECIAL.chars().collect(),
        // `unicode` is treated as `ascii-printable`.
        "ascii-printable" | "unicode" => ascii(|_| true),
        _ => return None,
    })
}

/// Split at `delim` outside `[...]` sets. A `]` right after `[` is a literal.
fn split_outside_sets(s: &str, delim: char) -> Vec<&str> {
    let mut parts = Vec::new();
    let (mut start, mut in_set, mut set_start) = (0, false, 0);
    for (i, c) in s.char_indices() {
        if in_set {
            if c == ']' && i > set_start + 1 {
                in_set = false;
            }
        } else if c == '[' {
            in_set = true;
            set_start = i;
        } else if c == delim {
            parts.push(&s[start..i]);
            start = i + c.len_utf8();
        }
    }
    parts.push(&s[start..]);
    parts
}

/// One class name or `[...]` set. In a set `]` may only come first and `-`
/// only first or last. `None` when unreadable.
fn parse_class(token: &str) -> Option<CharSet> {
    let token = token.trim();
    if let Some(inner) = token.strip_prefix('[') {
        let inner = inner.strip_suffix(']')?;
        let chars: Vec<char> = inner.chars().collect();
        if chars.is_empty() {
            return None;
        }
        for (i, c) in chars.iter().enumerate() {
            if !(' '..='~').contains(c) {
                return None;
            }
            let edge_dash = *c == '-' && (i == 0 || i == chars.len() - 1);
            if (*c == '-' && !edge_dash) || (*c == ']' && i != 0) {
                return None;
            }
        }
        return Some(chars.into_iter().collect());
    }
    class_set(&token.to_ascii_lowercase())
}

fn parse_classes(value: &str) -> Option<Vec<CharSet>> {
    // Empty tokens (a trailing comma) are skipped; no token at all is
    // unreadable.
    let sets: Option<Vec<CharSet>> = split_outside_sets(value, ',')
        .into_iter()
        .filter(|t| !t.trim().is_empty())
        .map(parse_class)
        .collect();
    sets.filter(|s| !s.is_empty())
}

fn parse_number(value: &str) -> Option<u32> {
    value.trim().parse().ok()
}

impl Rules {
    /// Fold one rule string in. `None` when a known property is malformed.
    fn absorb(&mut self, text: &str) -> Option<()> {
        for property in split_outside_sets(text, ';') {
            let Some((name, value)) = property.split_once(':') else {
                continue;
            };
            let name = name.trim().to_ascii_lowercase();
            match name.as_str() {
                "minlength" => {
                    self.min_length = self.min_length.max(parse_number(value)?);
                }
                "maxlength" => {
                    let n = parse_number(value)?;
                    self.max_length = Some(self.max_length.map_or(n, |m| m.min(n)));
                }
                "max-consecutive" => {
                    let n = parse_number(value)?;
                    self.max_consecutive = Some(self.max_consecutive.map_or(n, |m| m.min(n)));
                }
                "allowed" | "required" => {
                    let sets = parse_classes(value)?;
                    // Required classes count as allowed too.
                    let named = self.allowed.get_or_insert_with(CharSet::new);
                    named.extend(sets.iter().flatten().copied());
                    if name == "required" {
                        self.required.extend(sets);
                    }
                }
                _ => continue,
            }
            self.recognized = true;
        }
        Some(())
    }
}

/// Parse every rule string. Each string builds its own allowed set (union of
/// its `allowed` and `required` classes); the sets of different strings are
/// intersected, so the strictest wins. `None` when unreadable.
fn parse(rules: &[String]) -> Option<Rules> {
    let mut merged = Rules::default();
    let mut allowed: Option<CharSet> = None;
    for text in rules {
        let mut one = Rules::default();
        one.absorb(text)?;
        merged.recognized |= one.recognized;
        merged.min_length = merged.min_length.max(one.min_length);
        merged.max_length = match (merged.max_length, one.max_length) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        merged.max_consecutive = match (merged.max_consecutive, one.max_consecutive) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        merged.required.append(&mut one.required);
        if let Some(set) = one.allowed {
            allowed = Some(match allowed {
                Some(prev) => prev.intersection(&set).copied().collect(),
                None => set,
            });
        }
    }
    merged.allowed = allowed;
    Some(merged)
}

/// Uniform integer in `0..n` (`n >= 1`), by rejection on 32 random bits so
/// there is no modulo bias.
fn uniform_below(n: usize) -> Option<usize> {
    let n = n as u64;
    let limit = (1u64 << 32) - ((1u64 << 32) % n);
    let mut buf = Zeroizing::new([0u8; 4]);
    loop {
        fill_random(&mut *buf).ok()?;
        let r = u64::from(u32::from_be_bytes(*buf));
        if r < limit {
            return Some((r % n) as usize);
        }
    }
}

fn pick(set: &[char]) -> Option<char> {
    Some(set[uniform_below(set.len())?])
}

/// Length chosen from the bounds: the target, clamped into them.
fn choose_length(r: &Rules) -> Option<usize> {
    // Hard cap: the rules come from web pages and the extension is memory
    // limited. A minimum above the cap cannot be met.
    if r.min_length > MAX_LENGTH {
        return None;
    }
    let target = r.min_length.max(TARGET_LENGTH);
    let length = r
        .max_length
        .map_or(target, |max| max.min(target))
        .min(MAX_LENGTH);
    (length >= r.min_length && length >= 1).then_some(length as usize)
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
/// the rest drawn from the allowed set left to right, never extending a run
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
        let slot = free.swap_remove(uniform_below(free.len())?);
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

fn from_rules(rules: &[String]) -> Option<Zeroizing<String>> {
    let parsed = parse(rules)?;
    if !parsed.recognized || parsed.max_consecutive == Some(0) {
        return None;
    }
    let length = choose_length(&parsed)?;
    let allowed = parsed.allowed.unwrap_or_else(|| {
        ["lower", "upper", "digit", "special"]
            .iter()
            .filter_map(|n| class_set(n))
            .flatten()
            .collect()
    });
    let alphabet: Vec<char> = allowed.iter().copied().collect();
    if alphabet.is_empty() {
        return None;
    }
    // Each required class is restricted to what the rules allow.
    let required: Vec<Vec<char>> = parsed
        .required
        .iter()
        .map(|set| set.intersection(&allowed).copied().collect::<Vec<_>>())
        .collect();
    if required.len() > length || required.iter().any(Vec::is_empty) {
        return None;
    }
    for _ in 0..ATTEMPTS {
        if let Some(chars) = attempt(length, &alphabet, &required, parsed.max_consecutive) {
            let mut password = Zeroizing::new(String::with_capacity(length * 4));
            password.extend(chars.iter());
            return Some(password);
        }
    }
    None
}

/// A password that follows the Apple `passwordrules` strings received for a
/// field (field, confirmation, system fixes). Without a readable and
/// satisfiable rule set, the `fallback` recipe generates it.
#[uniffi::export]
pub fn password_from_rules(
    rules: Vec<String>,
    fallback: FfiPasswordRecipe,
) -> Result<String, OnePassError> {
    let rules: Vec<String> = rules.into_iter().filter(|r| !r.trim().is_empty()).collect();
    if let Some(password) = from_rules(&rules) {
        return Ok(password.to_string());
    }
    generate_password(fallback)
}
