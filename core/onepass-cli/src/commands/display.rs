//! Text output of untrusted strings (titles, vault and folder names,
//! catalog names): control characters never reach the terminal.

/// `s` with every control character (`char::is_control`: C0, DEL, C1)
/// replaced by U+FFFD, so an escape sequence hidden in imported or
/// downloaded data is shown, not interpreted. JSON output does not need
/// this: serde escapes control characters.
pub fn clean(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { '\u{FFFD}' } else { c })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_characters_are_replaced() {
        assert_eq!(clean("plain \u{e9}t\u{e9}"), "plain \u{e9}t\u{e9}");
        assert_eq!(clean("a\x1b[31mb"), "a\u{FFFD}[31mb");
        assert_eq!(
            clean("x\ny\r\t\u{7f}\u{9b}"),
            "x\u{FFFD}y\u{FFFD}\u{FFFD}\u{FFFD}\u{FFFD}"
        );
    }
}
