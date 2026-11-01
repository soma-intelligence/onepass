//! Reader for Apple `passwordrules` strings.
//!
//! Parsing is tolerant: unknown properties are ignored and names are case
//! insensitive, but a known property with a malformed value makes the whole
//! rule string unreadable.

use super::constraints::{CharSet, Constraints};

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
    CharSet::ascii_class(&token.to_ascii_lowercase())
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

/// Parse one `passwordrules` string. `None` when a known property is
/// malformed. A string with no known property gives default constraints
/// that are not `recognized`.
pub fn parse_passwordrules(s: &str) -> Option<Constraints> {
    let mut c = Constraints::default();
    for property in split_outside_sets(s, ';') {
        let Some((name, value)) = property.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        match name.as_str() {
            "minlength" => c.min_length = c.min_length.max(parse_number(value)?),
            "maxlength" => {
                let n = parse_number(value)?;
                c.max_length = Some(c.max_length.map_or(n, |m| m.min(n)));
            }
            "max-consecutive" => {
                let n = parse_number(value)?;
                c.max_consecutive = Some(c.max_consecutive.map_or(n, |m| m.min(n)));
            }
            "allowed" | "required" => {
                let sets = parse_classes(value)?;
                // Required classes count as allowed too.
                let named = c.allowed.get_or_insert_with(CharSet::default);
                named.extend(sets.iter().flat_map(CharSet::iter));
                if name == "required" {
                    c.required.extend(sets);
                }
            }
            _ => continue,
        }
        c.recognized = true;
    }
    Some(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minlength_maxlength() {
        let c = parse_passwordrules("minlength: 8; maxlength: 16").unwrap();
        assert_eq!(c.min_length, 8);
        assert_eq!(c.max_length, Some(16));
        assert!(c.recognized());
    }

    #[test]
    fn unknown_property_ignored() {
        let c = parse_passwordrules("flavor: sweet; MinLength: 6").unwrap();
        assert_eq!(c.min_length, 6);
        let empty = parse_passwordrules("flavor: sweet").unwrap();
        assert!(!empty.recognized());
        assert_eq!(empty, Constraints::default());
    }

    #[test]
    fn malformed_value_unreadable() {
        assert!(parse_passwordrules("minlength: abc").is_none());
        assert!(parse_passwordrules("required: nonsense").is_none());
        assert!(parse_passwordrules("allowed: [a-b]").is_none());
    }

    #[test]
    fn bracket_set_with_literal_close() {
        let c = parse_passwordrules("required: [];a]; max-consecutive: 2").unwrap();
        // `[];a]` is split at the first `;` outside the set only after `]`
        // closes: here the set is `];a`, one literal close, a semicolon, a.
        assert_eq!(c.required.len(), 1);
        let set = &c.required[0];
        assert!(set.contains(']') && set.contains(';') && set.contains('a'));
        assert_eq!(c.max_consecutive, Some(2));
    }

    #[test]
    fn merge_keeps_strictest_max() {
        let mut a =
            parse_passwordrules("minlength: 8; maxlength: 20; allowed: lower, digit").unwrap();
        let b = parse_passwordrules("minlength: 10; maxlength: 12; allowed: lower, upper").unwrap();
        a.merge(&b);
        assert_eq!(a.min_length, 10);
        assert_eq!(a.max_length, Some(12));
        let allowed = a.allowed.unwrap();
        assert!(allowed.contains('a') && !allowed.contains('A') && !allowed.contains('1'));
    }
}
