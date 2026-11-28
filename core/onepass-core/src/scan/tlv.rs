//! BER-TLV as an eMRTD speaks it: tags of 1 to 3 bytes, lengths in the
//! short form or `81`, `82`, `83` followed by 1 to 3 length bytes.

use std::fmt;

/// One parsed element: its tag and a view of its value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tlv<'a> {
    pub tag: u32,
    pub value: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlvError {
    /// The bytes end before the element does.
    Truncated,
    /// A tag longer than 3 bytes, or a length form this reader does not take.
    Malformed,
}

impl fmt::Display for TlvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TlvError::Truncated => f.write_str("TLV is truncated"),
            TlvError::Malformed => f.write_str("TLV is malformed"),
        }
    }
}

impl std::error::Error for TlvError {}

/// Tag at the start of `b`: (tag, bytes used).
fn parse_tag(b: &[u8]) -> Result<(u32, usize), TlvError> {
    let first = *b.first().ok_or(TlvError::Truncated)?;
    let mut tag = u32::from(first);
    let mut used = 1;
    if first & 0x1F == 0x1F {
        loop {
            let next = *b.get(used).ok_or(TlvError::Truncated)?;
            used += 1;
            if used > 3 {
                return Err(TlvError::Malformed);
            }
            tag = (tag << 8) | u32::from(next);
            if next & 0x80 == 0 {
                break;
            }
        }
    }
    Ok((tag, used))
}

/// Length at the start of `b`: (length, bytes used).
fn parse_length(b: &[u8]) -> Result<(usize, usize), TlvError> {
    let first = *b.first().ok_or(TlvError::Truncated)?;
    match first {
        0x00..=0x7F => Ok((usize::from(first), 1)),
        0x81..=0x83 => {
            let n = usize::from(first & 0x0F);
            let bytes = b.get(1..=n).ok_or(TlvError::Truncated)?;
            let len = bytes.iter().fold(0usize, |a, &x| (a << 8) | usize::from(x));
            Ok((len, 1 + n))
        }
        _ => Err(TlvError::Malformed),
    }
}

/// Reads the first element of `b`; returns it and the bytes after it.
pub fn parse_one(b: &[u8]) -> Result<(Tlv<'_>, &[u8]), TlvError> {
    let (tag, t) = parse_tag(b)?;
    let (len, l) = parse_length(&b[t..])?;
    let start = t + l;
    let end = start.checked_add(len).ok_or(TlvError::Malformed)?;
    let value = b.get(start..end).ok_or(TlvError::Truncated)?;
    Ok((Tlv { tag, value }, &b[end..]))
}

/// Whether the tag marks a constructed element (its value is more TLVs).
fn constructed(tag: u32) -> bool {
    let first = if tag > 0xFFFF {
        (tag >> 16) as u8
    } else if tag > 0xFF {
        (tag >> 8) as u8
    } else {
        tag as u8
    };
    first & 0x20 != 0
}

/// The value at `path`, descending through constructed tags. The first
/// element with a matching tag at each level wins.
pub fn find<'a>(b: &'a [u8], path: &[u32]) -> Option<&'a [u8]> {
    let (&want, rest) = path.split_first()?;
    let mut cur = b;
    while !cur.is_empty() {
        let (tlv, after) = parse_one(cur).ok()?;
        if tlv.tag == want {
            if rest.is_empty() {
                return Some(tlv.value);
            }
            if constructed(tlv.tag) {
                return find(tlv.value, rest);
            }
            return None;
        }
        cur = after;
    }
    None
}

/// Encodes one element, the shortest length form.
pub fn encode(tag: u32, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.len() + 6);
    let tag_bytes = tag.to_be_bytes();
    let skip = tag_bytes.iter().take(3).take_while(|&&x| x == 0).count();
    out.extend_from_slice(&tag_bytes[skip..]);
    let n = value.len();
    if n < 0x80 {
        out.push(n as u8);
    } else if n <= 0xFF {
        out.extend_from_slice(&[0x81, n as u8]);
    } else if n <= 0xFFFF {
        out.extend_from_slice(&[0x82, (n >> 8) as u8, n as u8]);
    } else {
        out.extend_from_slice(&[0x83, (n >> 16) as u8, (n >> 8) as u8, n as u8]);
    }
    out.extend_from_slice(value);
    out
}

/// Total length of a file (header plus value) from its first bytes: enough
/// of them to hold the tag and the length. `None` if they do not.
pub fn file_length(header: &[u8]) -> Option<usize> {
    let (_, t) = parse_tag(header).ok()?;
    let (len, l) = parse_length(&header[t..]).ok()?;
    t.checked_add(l)?.checked_add(len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tlv_two_byte_tag_and_long_length() {
        let mut b = vec![0x5F, 0x1F, 0x82, 0x01, 0x00];
        b.extend(std::iter::repeat_n(0xAB, 256));
        b.push(0x99); // trailing byte stays in the rest
        let (t, rest) = parse_one(&b).unwrap();
        assert_eq!(t.tag, 0x5F1F);
        assert_eq!(t.value.len(), 256);
        assert_eq!(rest, &[0x99]);
        assert_eq!(
            &encode(0x5F1F, t.value)[..5],
            &[0x5F, 0x1F, 0x82, 0x01, 0x00]
        );
    }

    #[test]
    fn tlv_find_nested() {
        // DG1: 61 { 5F1F <mrz> }
        let inner = encode(0x5F1F, b"P<UTO");
        let dg1 = encode(0x61, &inner);
        assert_eq!(find(&dg1, &[0x61, 0x5F1F]), Some(&b"P<UTO"[..]));
        assert_eq!(find(&dg1, &[0x61]), Some(&inner[..]));
        assert_eq!(find(&dg1, &[0x61, 0x5F20]), None);
        assert_eq!(find(&dg1, &[0x62]), None);
        // Cannot descend into a primitive tag.
        assert_eq!(find(&inner, &[0x5F1F, 0x01]), None);
    }

    #[test]
    fn tlv_rejects_truncated() {
        assert_eq!(parse_one(&[]), Err(TlvError::Truncated));
        assert_eq!(parse_one(&[0x61, 0x05, 0x01]), Err(TlvError::Truncated));
        assert_eq!(parse_one(&[0x61, 0x82, 0x01]), Err(TlvError::Truncated));
        assert_eq!(parse_one(&[0x5F]), Err(TlvError::Truncated));
        assert_eq!(
            parse_one(&[0x61, 0x84, 1, 2, 3, 4]),
            Err(TlvError::Malformed)
        );
        assert_eq!(find(&[0x61, 0x05, 0x01], &[0x61]), None);
    }

    #[test]
    fn file_length_from_first_four_bytes() {
        assert_eq!(file_length(&[0x75, 0x82, 0x5A, 0x3C]), Some(0x5A3C + 4));
        assert_eq!(file_length(&[0x61, 0x5B]), Some(0x5B + 2));
        assert_eq!(file_length(&[0x75, 0x82, 0x5A]), None);
        assert_eq!(file_length(&[]), None);
    }

    #[test]
    fn encode_length_forms() {
        assert_eq!(encode(0x04, &[1, 2]), vec![0x04, 0x02, 1, 2]);
        assert_eq!(&encode(0x04, &[0; 128])[..3], &[0x04, 0x81, 0x80]);
        assert_eq!(
            &encode(0x04, &[0; 0x1_0000])[..5],
            &[0x04, 0x83, 0x01, 0x00, 0x00]
        );
    }
}
