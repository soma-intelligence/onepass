//! Terminal-safe display text.

/// Maximum number of characters kept by [`sanitize_for_display`].
const MAX_DISPLAY_CHARS: usize = 200;

/// Makes untrusted text safe to print on a terminal: every Unicode control
/// character (category Cc: ESC, CR, LF, BEL, DEL and the C1 controls) becomes
/// `?`, then the text is cut to 200 characters, with `…` (U+2026) appended when
/// something was cut.
pub fn sanitize_for_display(s: &str) -> String {
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i == MAX_DISPLAY_CHARS {
            out.push('\u{2026}');
            break;
        }
        out.push(if c.is_control() { '?' } else { c });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_strips_terminal_escapes() {
        assert_eq!(sanitize_for_display("a\x1b[2Jb\rc\u{9b}d"), "a?[2Jb?c?d");
        let long = "x".repeat(300);
        let out = sanitize_for_display(&long);
        assert_eq!(out, format!("{}\u{2026}", "x".repeat(200)));
        assert_eq!(sanitize_for_display(&"y".repeat(200)), "y".repeat(200));
    }
}
