//! Reading the sources of a signup field and settling their contradictions
//! by trust.

use super::constraints::Constraints;
use super::hints::parse_hints;
use super::passwordrules::parse_passwordrules;

/// No password is longer than this, whatever the site says.
pub(crate) const MAX_LENGTH: u32 = 64;
/// An attribute `maxlength` below this is a broken field and is ignored.
const MIN_ATTRIBUTE_MAX: u32 = 4;

/// What the page (or the system) says about a new password field. Holds no
/// typed value.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PasswordContext {
    /// `passwordrules` of the field and of its confirmation.
    pub rules: Vec<String>,
    /// Known rule of the site, filled by the bridge.
    pub quirk_rules: Option<String>,
    /// `minlength` attribute.
    pub min_length: Option<u32>,
    /// `maxlength` attribute (the smaller of the two fields).
    pub max_length: Option<u32>,
    /// Written instructions near the field.
    pub hint_text: Option<String>,
}

/// Where a constraint came from, most trusted first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    PasswordRules,
    Attributes,
    Quirks,
    Hints,
}

/// The constraints kept, and which sources were kept or dropped.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Resolved {
    pub constraints: Constraints,
    pub sources: Vec<Source>,
    pub dropped: Vec<Source>,
    /// The two trusted sources contradict each other: nothing is kept.
    pub fallback: bool,
}

/// Each source that gave at least one recognized constraint, in trust
/// order. A `passwordrules` string with a malformed value is skipped.
fn read(ctx: &PasswordContext) -> Vec<(Source, Constraints)> {
    let mut out = Vec::new();
    let mut rules = Constraints::default();
    for r in &ctx.rules {
        if let Some(c) = parse_passwordrules(r) {
            rules.merge(&c);
        }
    }
    if rules.recognized() {
        out.push((Source::PasswordRules, rules));
    }
    let attributes = Constraints {
        min_length: ctx.min_length.unwrap_or(0),
        max_length: ctx.max_length.filter(|m| *m >= MIN_ATTRIBUTE_MAX),
        recognized: true,
        ..Constraints::default()
    };
    if attributes.min_length > 0 || attributes.max_length.is_some() {
        out.push((Source::Attributes, attributes));
    }
    if let Some(c) = ctx
        .quirk_rules
        .as_deref()
        .and_then(parse_passwordrules)
        .filter(Constraints::recognized)
    {
        out.push((Source::Quirks, c));
    }
    if let Some(text) = &ctx.hint_text {
        let c = parse_hints(text);
        if c.recognized() {
            out.push((Source::Hints, c));
        }
    }
    out
}

/// Satisfiable within the 64 char cap.
pub(crate) fn usable(c: &Constraints) -> bool {
    c.satisfiable() && c.min_length <= MAX_LENGTH && c.required.len() <= MAX_LENGTH as usize
}

/// The length claim of a less trusted `other` is wrong when one of its
/// stated bounds falls outside the range `base` allows ("8 to 20" written
/// next to a `maxlength` of 12). Its other constraints may still be right.
fn length_conflict(base: &Constraints, other: &Constraints) -> bool {
    let outside = |n: u32| n < base.min_length || base.max_length.is_some_and(|m| n > m);
    other.max_length.is_some_and(outside) || (other.min_length > 0 && outside(other.min_length))
}

/// True when `c` says nothing beyond the defaults.
fn is_empty(c: &Constraints) -> bool {
    c.min_length == 0
        && c.max_length.is_none()
        && c.allowed.is_none()
        && c.required.is_empty()
        && c.forbidden.is_empty()
        && c.max_consecutive.is_none()
}

/// What is kept of a less trusted `other` next to `base`: `None` when it
/// must be dropped. A wrong length claim is stripped as a whole (both
/// bounds: the stated range is one statement) and the rest is kept; the
/// source is dropped when nothing is left, or when what is left leaves
/// nothing satisfiable.
fn keep(base: &Constraints, other: &Constraints) -> Option<Constraints> {
    let mut kept = other.clone();
    if length_conflict(base, other) {
        kept.min_length = 0;
        kept.max_length = None;
        if is_empty(&kept) {
            return None;
        }
    }
    let mut merged = base.clone();
    merged.merge(&kept);
    usable(&merged).then_some(kept)
}

/// Merge the sources in trust order. `PasswordRules` and `Attributes` are
/// never dropped against each other: if they alone contradict, nothing is
/// kept and `fallback` is set. `Quirks` then `Hints` are added one by one,
/// each stripped of a wrong length claim and dropped when it still
/// contradicts what is kept so far, so a sound hint survives a dropped
/// quirk.
pub(crate) fn resolve(ctx: &PasswordContext) -> Resolved {
    let present = read(ctx);
    let mut out = Resolved::default();
    let (trusted, lesser): (Vec<_>, Vec<_>) = present
        .iter()
        .partition(|(s, _)| matches!(s, Source::PasswordRules | Source::Attributes));
    for (source, c) in trusted {
        out.constraints.merge(c);
        out.sources.push(*source);
    }
    if !usable(&out.constraints) {
        return Resolved {
            dropped: present.iter().map(|(s, _)| *s).collect(),
            fallback: true,
            ..Resolved::default()
        };
    }
    for (source, c) in lesser {
        match keep(&out.constraints, c) {
            Some(kept) => {
                out.constraints.merge(&kept);
                out.sources.push(*source);
            }
            None => out.dropped.push(*source),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hint_inside_trusted_bounds_kept() {
        let ctx = PasswordContext {
            min_length: Some(8),
            max_length: Some(20),
            hint_text: Some("au moins 10 caracteres".to_owned()),
            ..PasswordContext::default()
        };
        let r = resolve(&ctx);
        assert_eq!(r.sources, vec![Source::Attributes, Source::Hints]);
        assert_eq!(r.constraints.min_length, 10);
    }

    #[test]
    fn hint_with_lower_minimum_dropped() {
        let ctx = PasswordContext {
            rules: vec!["minlength: 12;".to_owned()],
            hint_text: Some("au moins 8 caracteres".to_owned()),
            ..PasswordContext::default()
        };
        let r = resolve(&ctx);
        assert_eq!(r.dropped, vec![Source::Hints]);
        assert_eq!(r.constraints.min_length, 12);
    }

    #[test]
    fn bad_quirk_does_not_take_a_sound_hint_with_it() {
        let ctx = PasswordContext {
            max_length: Some(16),
            quirk_rules: Some("minlength: 20;".to_owned()),
            hint_text: Some("au moins 10 caracteres".to_owned()),
            ..PasswordContext::default()
        };
        let r = resolve(&ctx);
        assert_eq!(r.sources, vec![Source::Attributes, Source::Hints]);
        assert_eq!(r.dropped, vec![Source::Quirks]);
    }

    #[test]
    fn quirk_length_stripped_classes_kept() {
        let ctx = PasswordContext {
            max_length: Some(12),
            quirk_rules: Some("minlength: 14; required: digit; allowed: lower, digit;".to_owned()),
            ..PasswordContext::default()
        };
        let r = resolve(&ctx);
        assert_eq!(r.sources, vec![Source::Attributes, Source::Quirks]);
        assert!(r.dropped.is_empty());
        assert_eq!(r.constraints.min_length, 0);
        assert_eq!(r.constraints.max_length, Some(12));
        assert_eq!(r.constraints.required.len(), 1);
    }

    #[test]
    fn malformed_rule_skipped_and_unrecognized_not_a_source() {
        let ctx = PasswordContext {
            rules: vec!["minlength: abc;".to_owned(), "flavor: sweet".to_owned()],
            hint_text: Some("bienvenue".to_owned()),
            ..PasswordContext::default()
        };
        let r = resolve(&ctx);
        assert!(r.sources.is_empty() && r.dropped.is_empty() && !r.fallback);
    }

    #[test]
    fn minimum_above_cap_falls_back() {
        let r = resolve(&PasswordContext {
            min_length: Some(65),
            ..PasswordContext::default()
        });
        assert!(r.fallback);
        assert_eq!(r.dropped, vec![Source::Attributes]);
    }
}
