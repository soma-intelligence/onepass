//! Masking of secret values in command output (spec section 4.3).
//!
//! Each value of 4 characters or more is replaced by `<concealed:NAME>`,
//! and so are its standard base64, URL-safe base64 without padding, and
//! lowercase and uppercase hexadecimal forms. This is a risk reduction,
//! not a guarantee: an approved command can always transform a secret
//! (`rev`, a different encoding) or send it elsewhere. The real barrier
//! is the approval, which shows the exact command.

use data_encoding::{BASE64, BASE64URL_NOPAD, HEXLOWER, HEXUPPER};

/// Values shorter than this many characters are left alone: masking them
/// would garble ordinary text and hide little.
pub const MIN_MASKED_CHARS: usize = 4;

/// Replaces in `text` every value of `secrets` (`(name, value)` pairs), and
/// its common encodings, by `<concealed:NAME>`. Longer needles win where
/// several match at the same place; masked text is never scanned again.
pub fn mask(text: &str, secrets: &[(&str, &str)]) -> String {
    let mut needles: Vec<(String, &str)> = Vec::new();
    for (name, value) in secrets {
        if value.chars().count() < MIN_MASKED_CHARS {
            continue;
        }
        let bytes = value.as_bytes();
        for form in [
            (*value).to_owned(),
            BASE64.encode(bytes),
            BASE64URL_NOPAD.encode(bytes),
            HEXLOWER.encode(bytes),
            HEXUPPER.encode(bytes),
        ] {
            needles.push((form, name));
        }
    }
    if needles.is_empty() {
        return text.to_owned();
    }
    needles.sort_by(|a, b| b.0.len().cmp(&a.0.len()).then_with(|| a.0.cmp(&b.0)));
    needles.dedup_by(|a, b| a.0 == b.0);

    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(c) = rest.chars().next() {
        match needles.iter().find(|(n, _)| rest.starts_with(n.as_str())) {
            Some((n, name)) => {
                out.push_str("<concealed:");
                out.push_str(name);
                out.push('>');
                rest = &rest[n.len()..];
            }
            None => {
                out.push(c);
                rest = &rest[c.len_utf8()..];
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_plain_base64_hex() {
        let v = "hunter2-secret";
        let text = format!(
            "plain {v} b64 {} hex {} HEX {}.",
            BASE64.encode(v.as_bytes()),
            HEXLOWER.encode(v.as_bytes()),
            HEXUPPER.encode(v.as_bytes()),
        );
        let out = mask(&text, &[("PW", v)]);
        assert_eq!(
            out,
            "plain <concealed:PW> b64 <concealed:PW> hex <concealed:PW> HEX <concealed:PW>."
        );
        // URL-safe base64 without padding differs from the standard form
        // when the encoding has `+` or `/`.
        let raw = "\u{3fe}\u{3ff}\u{3ff}?";
        let url = BASE64URL_NOPAD.encode(raw.as_bytes());
        assert_ne!(url, BASE64.encode(raw.as_bytes()));
        assert!(url.contains('-') || url.contains('_'), "{url}");
        assert_eq!(mask(&format!("[{url}]"), &[("K", raw)]), "[<concealed:K>]");
    }

    #[test]
    fn mask_ignores_short_values() {
        assert_eq!(mask("abc and abc", &[("S", "abc")]), "abc and abc");
        assert_eq!(mask("text", &[]), "text");
        assert_eq!(mask("abcd", &[("S", "abcd")]), "<concealed:S>");
    }

    #[test]
    fn mask_longest_first() {
        let out = mask("x abcdef y abcd", &[("A", "abcd"), ("B", "abcdef")]);
        assert_eq!(out, "x <concealed:B> y <concealed:A>");
    }

    #[test]
    fn mask_keeps_multibyte_text() {
        let out = mask("é café secret é", &[("S", "secret")]);
        assert_eq!(out, "é café <concealed:S> é");
    }

    #[test]
    fn masked_text_is_not_rescanned() {
        // The placeholder of A contains the value of B.
        let out = mask("value-one", &[("CONCEALED", "value-one"), ("B", "conc")]);
        assert_eq!(out, "<concealed:CONCEALED>");
    }
}
