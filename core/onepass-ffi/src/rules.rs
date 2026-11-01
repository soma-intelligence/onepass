//! Passwords that follow Apple `passwordrules` strings.
//!
//! The AutoFill extension receives the rules of the site (field, confirmation
//! field, system fixes) and must generate a password that satisfies them.
//! Parsing is tolerant: unknown properties are ignored and names are case
//! insensitive, but a known property with a malformed value makes the whole
//! rule set unreadable. Unreadable and contradictory rule sets, like an empty
//! one, are answered with the fallback recipe through `generate_password`.

use onepass_core::site_password::{Constraints, parse_passwordrules};
use zeroize::Zeroizing;

use crate::{FfiPasswordRecipe, OnePassError, generate_password};

/// Target length when the rules leave room.
const TARGET_LENGTH: u32 = 20;
/// Longest password generated, whatever the rules say.
const MAX_LENGTH: u32 = 64;

/// Parse every rule string and merge them. The strictest wins. `None` when
/// one is unreadable.
fn parse(rules: &[String]) -> Option<Constraints> {
    let mut merged = Constraints::default();
    for text in rules {
        merged.merge(&parse_passwordrules(text)?);
    }
    Some(merged)
}

/// Length chosen from the bounds: the target, clamped into them.
fn choose_length(c: &Constraints) -> Option<usize> {
    // Hard cap: the rules come from web pages and the extension is memory
    // limited. A minimum above the cap cannot be met.
    if c.min_length > MAX_LENGTH {
        return None;
    }
    let target = c.min_length.max(TARGET_LENGTH);
    let length = c
        .max_length
        .map_or(target, |max| max.min(target))
        .min(MAX_LENGTH);
    (length >= c.min_length && length >= 1).then_some(length as usize)
}

fn from_rules(rules: &[String]) -> Option<Zeroizing<String>> {
    let parsed = parse(rules)?;
    if !parsed.recognized() || !parsed.satisfiable() {
        return None;
    }
    let length = choose_length(&parsed)?;
    onepass_core::site_password::draw(&parsed, length)
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
