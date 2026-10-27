//! Length-prefixed transcript hashing (spec 6.3).

use aws_lc_rs::digest;

/// Domain label hashed ahead of every transcript.
pub const TRANSCRIPT_LABEL: &str = "onepass/bridge/transcript/v1";

/// Accumulates fields as `u32 big-endian length || bytes`, the label first.
pub struct Transcript {
    buf: Vec<u8>,
}

impl Transcript {
    pub fn new(label: &str) -> Transcript {
        let mut t = Transcript { buf: Vec::new() };
        t.push(label.as_bytes());
        t
    }

    /// Append one field. Strings are passed as their UTF-8 bytes.
    pub fn push(&mut self, field: &[u8]) {
        // Fields are bounded by the 1 MiB frame ceiling, far below u32::MAX.
        let len = u32::try_from(field.len()).unwrap_or(u32::MAX);
        self.buf.extend_from_slice(&len.to_be_bytes());
        self.buf.extend_from_slice(field);
    }

    /// SHA-256 of everything pushed so far, label included.
    pub fn hash(&self) -> [u8; 32] {
        let d = digest::digest(&digest::SHA256, &self.buf);
        let mut out = [0u8; 32];
        out.copy_from_slice(d.as_ref());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(fields: &[&[u8]]) -> [u8; 32] {
        let mut t = Transcript::new(TRANSCRIPT_LABEL);
        for f in fields {
            t.push(f);
        }
        t.hash()
    }

    #[test]
    fn transcript_length_prefix_is_unambiguous() {
        assert_ne!(t(&[b"ab", b"c"]), t(&[b"a", b"bc"]));
        assert_ne!(t(&[b"abc"]), t(&[b"abc", b""]));
    }

    #[test]
    fn transcript_is_deterministic_and_label_bound() {
        assert_eq!(t(&[b"x", b"y"]), t(&[b"x", b"y"]));
        let mut other = Transcript::new("onepass/bridge/other/v1");
        other.push(b"x");
        other.push(b"y");
        assert_ne!(other.hash(), t(&[b"x", b"y"]));
    }

    #[test]
    fn transcript_known_answer() {
        // SHA-256 over: 00 00 00 1c "onepass/bridge/transcript/v1" 00 00 00 01 "a".
        let mut raw = 28u32.to_be_bytes().to_vec();
        raw.extend_from_slice(b"onepass/bridge/transcript/v1");
        raw.extend_from_slice(&1u32.to_be_bytes());
        raw.push(b'a');
        let want = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &raw);
        assert_eq!(t(&[b"a"]).as_slice(), want.as_ref());
    }
}
