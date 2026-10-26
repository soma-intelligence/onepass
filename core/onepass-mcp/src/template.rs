//! `{{ onepass://... }}` placeholders of `fill_template` (spec section 4.3).
//!
//! A placeholder is `{{`, optional spaces or tabs, a reference that starts
//! with `onepass://` (scheme in any case) and runs until whitespace or `}`,
//! optional spaces or tabs, then `}}`. Anything else between braces is left
//! as it is.

use std::ops::Range;
use zeroize::Zeroizing;

const SCHEME: &str = "onepass://";

fn skip_blanks(t: &str, mut i: usize) -> usize {
    while matches!(t.as_bytes().get(i), Some(b' ' | b'\t')) {
        i += 1;
    }
    i
}

/// The placeholders of `t`, in order: the byte range of each one (braces
/// included) and the reference inside.
pub fn template_refs(t: &str) -> Vec<(Range<usize>, String)> {
    let mut found = Vec::new();
    let mut from = 0;
    while let Some(off) = t[from..].find("{{") {
        let start = from + off;
        match placeholder_at(t, start) {
            Some((end, reference)) => {
                found.push((start..end, reference.to_owned()));
                from = end;
            }
            None => from = start + 1,
        }
    }
    found
}

/// The placeholder starting at `start` (which holds `{{`): its end and its
/// reference.
fn placeholder_at(t: &str, start: usize) -> Option<(usize, &str)> {
    let ref_start = skip_blanks(t, start + 2);
    let head = t.get(ref_start..ref_start + SCHEME.len())?;
    if !head.eq_ignore_ascii_case(SCHEME) {
        return None;
    }
    let body = &t[ref_start..];
    let len = body
        .find(|c: char| c.is_whitespace() || c == '}')
        .unwrap_or(body.len());
    if len == SCHEME.len() {
        return None;
    }
    let close = skip_blanks(t, ref_start + len);
    t[close..]
        .starts_with("}}")
        .then(|| (close + 2, &body[..len]))
}

/// `t` with its placeholders replaced, in order, by `values`. Placeholders
/// beyond the values given are left as they are.
pub fn render_template(t: &str, values: &[Zeroizing<String>]) -> Zeroizing<String> {
    let extra: usize = values.iter().map(|v| v.len()).sum();
    let mut out = Zeroizing::new(String::with_capacity(t.len() + extra));
    let mut last = 0;
    for ((range, _), value) in template_refs(t).into_iter().zip(values) {
        out.push_str(&t[last..range.start]);
        out.push_str(value);
        last = range.end;
    }
    out.push_str(&t[last..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_refs_found() {
        let t = "a={{ onepass://V/I/f }} b={{onepass://V/I/s/g}}\tc={{\tONEPASS://x/y/z  }}";
        let refs = template_refs(t);
        let names: Vec<&str> = refs.iter().map(|(_, r)| r.as_str()).collect();
        assert_eq!(
            names,
            ["onepass://V/I/f", "onepass://V/I/s/g", "ONEPASS://x/y/z"]
        );
        assert_eq!(&t[refs[0].0.clone()], "{{ onepass://V/I/f }}");
        assert_eq!(&t[refs[1].0.clone()], "{{onepass://V/I/s/g}}");
    }

    #[test]
    fn template_refs_ignores_other_braces() {
        for t in [
            "{{ name }}",
            "{{ onepass:// }}",
            "{{ onepass://a/b/c",
            "{{ onepass://a/b/c d }}",
            "{ onepass://a/b/c }",
            "{{ https://a/b/c }}",
            "",
            "{{",
            "{{{{",
        ] {
            assert!(template_refs(t).is_empty(), "{t:?}");
        }
        // A brace run before the real placeholder.
        let refs = template_refs("{{{ onepass://a/b/c }}");
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].0, 1..22);
    }

    #[test]
    fn render_replaces_in_order() {
        let t = "x={{ onepass://a/b/c }}, y={{onepass://a/b/d}}, z={{ other }}";
        let values = [Zeroizing::new("one".into()), Zeroizing::new("two".into())];
        assert_eq!(*render_template(t, &values), "x=one, y=two, z={{ other }}");
        // Fewer values: the rest is kept.
        assert_eq!(
            *render_template(t, &values[..1]),
            "x=one, y={{onepass://a/b/d}}, z={{ other }}"
        );
        assert_eq!(*render_template("plain é", &[]), "plain é");
    }
}
