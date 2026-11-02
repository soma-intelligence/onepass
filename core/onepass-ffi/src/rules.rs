//! Passwords that follow Apple `passwordrules` strings.
//!
//! The AutoFill extension receives the rules of the site (field, confirmation
//! field, system fixes) and must generate a password that satisfies them.
//! Parsing is tolerant: unknown properties are ignored and names are case
//! insensitive, but a known property with a malformed value makes the whole
//! rule set unreadable. Unreadable and contradictory rule sets, like an empty
//! one, are answered with the fallback recipe through `generate_password`.

use onepass_core::site_password::{
    Constraints, PasswordContext, Profile, generate_for, parse_passwordrules,
};
use zeroize::Zeroizing;

use crate::error::invalid;
use crate::{
    FfiGenerated, FfiPasswordContext, FfiPasswordProfile, FfiPasswordRecipe, OnePassError,
    generate_password,
};

/// Target length when the rules leave room.
const TARGET_LENGTH: u32 = 20;
/// Longest password generated, whatever the rules say.
const MAX_LENGTH: u32 = 64;
/// Most rule strings `password_for_context` reads (field, confirmation,
/// quirk, with room to spare); later ones are ignored.
const MAX_RULE_STRINGS: usize = 8;
/// Longest rule string `password_for_context` reads; longer ones are dropped.
const MAX_RULE_LEN: usize = 1024;
/// Custom profile length bounds.
const CUSTOM_LENGTHS: std::ops::RangeInclusive<u32> = 8..=64;

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

fn profile_to_core(p: FfiPasswordProfile) -> Result<Profile, OnePassError> {
    Ok(match p {
        FfiPasswordProfile::Strong => Profile::Strong,
        FfiPasswordProfile::Readable => Profile::Readable,
        FfiPasswordProfile::Custom {
            length,
            digits,
            symbols,
        } => {
            if !CUSTOM_LENGTHS.contains(&length) {
                return Err(OnePassError::Validation {
                    field: "length".to_owned(),
                    reason: "out of range".to_owned(),
                });
            }
            Profile::Custom {
                length: u8::try_from(length).map_err(|_| invalid("length"))?,
                digits,
                symbols,
            }
        }
    })
}

/// A password for a signup field, built by `profile` within what the field
/// says (`passwordrules` strings, length attributes, written hints). Same
/// engine as the browser extension: contradicting or unreadable sources are
/// dropped, least trusted first, and the profile runs alone when nothing
/// usable is left (`fallback`).
///
/// Rule strings over 1024 bytes are dropped, identical ones are read once
/// and only the first 8 left are read: the page writes them, so they never
/// fail the request. `quirk_rules` is read in the quirk tier, as in the
/// bridge.
///
/// Errors: `Validation` on field `length` for a `Custom` length outside 8 to
/// 64; `Crypto` when the system random source fails.
#[uniffi::export]
pub fn password_for_context(
    context: FfiPasswordContext,
    profile: FfiPasswordProfile,
) -> Result<FfiGenerated, OnePassError> {
    let profile = profile_to_core(profile)?;
    // The field's and the confirmation's rules come from the page: limits
    // drop what is over them, never fail the request.
    // Identical strings (field and confirmation) are read once.
    let mut rules: Vec<String> = Vec::new();
    for r in context.rules {
        if !r.trim().is_empty() && r.len() <= MAX_RULE_LEN && !rules.contains(&r) {
            rules.push(r);
        }
        if rules.len() == MAX_RULE_STRINGS {
            break;
        }
    }
    let quirk_rules = context
        .quirk_rules
        .filter(|r| !r.trim().is_empty() && r.len() <= MAX_RULE_LEN);
    let ctx = PasswordContext {
        rules,
        quirk_rules,
        min_length: context.min_length,
        max_length: context.max_length,
        hint_text: context.hint_text,
    };
    let (password, report) = generate_for(&ctx, &profile, 0)?;
    Ok(FfiGenerated {
        password: password.to_string(),
        weak_by_site: report.weak_by_site,
        fallback: report.fallback,
        readable_fell_back: report.readable_fell_back,
    })
}
