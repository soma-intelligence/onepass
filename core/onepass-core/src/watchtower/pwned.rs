//! Password breach lookups by k-anonymity (spec 3.3).
//!
//! Only the 5-character prefix of a SHA-1 digest leaves this module, through
//! a [`RangeSource`]. The 35-character suffix is compared locally.

use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::hint::black_box;
use std::io::{ErrorKind, Read};
use std::path::PathBuf;

use aws_lc_rs::digest::{SHA1_FOR_LEGACY_USE_ONLY, digest};
use zeroize::Zeroizing;

use crate::model::{FieldValue, Item};
use crate::{Error, Result};

use super::PwnedStatus;
use super::checks::{Check, Detail, Finding};

/// Largest accepted range response (spec 3.3).
const MAX_RANGE_BYTES: u64 = 4 * 1024 * 1024;
const PREFIX_LEN: usize = 5;
const SUFFIX_LEN: usize = 35;

/// Source of HIBP `range` responses.
pub trait RangeSource {
    /// Response body for a prefix of 5 upper-case hex characters.
    fn range(&mut self, prefix: &str) -> crate::Result<Vec<u8>>;
}

/// Offline source: a directory of `<PREFIX>.txt` files in the
/// PwnedPasswordsDownloader format.
#[derive(Debug, Clone)]
pub struct DirRangeSource {
    dir: PathBuf,
}

impl DirRangeSource {
    pub fn new(dir: impl Into<PathBuf>) -> DirRangeSource {
        DirRangeSource { dir: dir.into() }
    }

    fn read_file(&self, name: &str) -> Result<Vec<u8>> {
        let path = self.dir.join(name);
        let mut file = File::open(&path).map_err(map_io)?;
        let meta = file.metadata().map_err(map_io)?;
        if !meta.is_file() || meta.len() > MAX_RANGE_BYTES {
            return Err(Error::InvalidFormat("range file"));
        }
        let mut buf = Vec::new();
        file.by_ref()
            .take(MAX_RANGE_BYTES + 1)
            .read_to_end(&mut buf)
            .map_err(map_io)?;
        if buf.len() as u64 > MAX_RANGE_BYTES {
            return Err(Error::InvalidFormat("range file"));
        }
        Ok(buf)
    }
}

fn map_io(e: std::io::Error) -> Error {
    if e.kind() == ErrorKind::NotFound {
        Error::NotFound
    } else {
        Error::Store("range file read failed".into())
    }
}

fn is_upper_hex(b: u8) -> bool {
    b.is_ascii_digit() || (b'A'..=b'F').contains(&b)
}

impl RangeSource for DirRangeSource {
    fn range(&mut self, prefix: &str) -> Result<Vec<u8>> {
        let b = prefix.as_bytes();
        if b.len() != PREFIX_LEN || !b.iter().all(|&c| is_upper_hex(c)) {
            return Err(Error::InvalidFormat("range prefix"));
        }
        match self.read_file(&format!("{prefix}.txt")) {
            Err(Error::NotFound) => self.read_file(&format!("{}.txt", prefix.to_ascii_lowercase())),
            other => other,
        }
    }
}

/// Parses a range body: lines `SUFFIX:COUNT`, LF or CRLF. Suffixes come back
/// upper-case. Empty lines and zero counts (padding) are skipped.
pub fn parse_range(body: &[u8]) -> Result<Vec<([u8; 35], u64)>> {
    const BAD: Error = Error::InvalidFormat("range response");
    if body.len() as u64 > MAX_RANGE_BYTES {
        return Err(BAD);
    }
    let mut out = Vec::new();
    for raw in body.split(|&c| c == b'\n') {
        let line = raw.strip_suffix(b"\r").unwrap_or(raw);
        if line.is_empty() {
            continue;
        }
        let mut parts = line.splitn(2, |&c| c == b':');
        let (Some(sfx), Some(cnt)) = (parts.next(), parts.next()) else {
            return Err(BAD);
        };
        if sfx.len() != SUFFIX_LEN
            || !sfx.iter().all(u8::is_ascii_hexdigit)
            || cnt.is_empty()
            || !cnt.iter().all(u8::is_ascii_digit)
        {
            return Err(BAD);
        }
        let count: u64 = std::str::from_utf8(cnt)
            .map_err(|_| BAD)?
            .parse()
            .map_err(|_| BAD)?;
        if count == 0 {
            continue;
        }
        let mut suffix = [0u8; SUFFIX_LEN];
        for (d, s) in suffix.iter_mut().zip(sfx) {
            *d = s.to_ascii_uppercase();
        }
        out.push((suffix, count));
    }
    Ok(out)
}

/// SHA-1 of a password as 40 upper-case hex characters.
///
/// An unsalted SHA-1 of a password is as sensitive as its hex, so the raw
/// digest is copied into a wiped buffer and aws-lc's `Digest` (no `Zeroize`)
/// is overwritten in place with the digest of a constant. Best effort: the
/// type is `Copy`, so copies the compiler makes are outside our control.
pub(crate) fn sha1_hex(pw: &str) -> Zeroizing<[u8; 40]> {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut raw = Zeroizing::new([0u8; 20]);
    let mut d = digest(&SHA1_FOR_LEGACY_USE_ONLY, pw.as_bytes());
    for (slot, byte) in raw.iter_mut().zip(d.as_ref()) {
        *slot = *byte;
    }
    d = digest(&SHA1_FOR_LEGACY_USE_ONLY, b"");
    black_box(&d);
    let mut out = Zeroizing::new([0u8; 40]);
    for (pair, byte) in out
        .as_mut_slice()
        .as_chunks_mut::<2>()
        .0
        .iter_mut()
        .zip(raw.iter())
    {
        for (slot, nibble) in pair.iter_mut().zip([byte >> 4, byte & 0x0F]) {
            *slot = HEX.get(usize::from(nibble)).copied().unwrap_or(b'0');
        }
    }
    out
}

/// One password field to look up.
struct Target<'a> {
    item: &'a Item,
    field_id: &'a str,
    /// Index into the distinct hashes.
    hash: usize,
}

/// Looks every analyzed password up and returns the `compromised` findings
/// with the outcome. A prefix is requested once, whatever the number of
/// passwords sharing it.
pub(crate) fn pwned_findings(
    items: &[&Item],
    source: &mut dyn RangeSource,
) -> (Vec<Finding>, PwnedStatus) {
    let mut hashes: Vec<Zeroizing<[u8; 40]>> = Vec::new();
    let mut seen: HashMap<&str, usize> = HashMap::new();
    let mut targets: Vec<Target<'_>> = Vec::new();
    for item in items {
        if item
            .watchtower_exclusions
            .iter()
            .any(|e| e == Check::Compromised.id())
        {
            continue;
        }
        for f in item.sections.iter().flat_map(|s| s.fields.iter()) {
            let FieldValue::Password(p) = &f.value else {
                continue;
            };
            if p.is_empty() {
                continue;
            }
            let hash = *seen.entry(p.as_str()).or_insert_with(|| {
                hashes.push(sha1_hex(p));
                hashes.len() - 1
            });
            targets.push(Target {
                item,
                field_id: f.id.as_str(),
                hash,
            });
        }
    }

    // Distinct prefixes, sorted. Each maps to the hashes sharing it.
    let mut by_prefix: BTreeMap<[u8; PREFIX_LEN], Vec<usize>> = BTreeMap::new();
    for (idx, h) in hashes.iter().enumerate() {
        if let Some(p) = h.first_chunk::<PREFIX_LEN>() {
            by_prefix.entry(*p).or_default().push(idx);
        }
    }

    let requested = by_prefix.len();
    let mut failed = 0u32;
    let mut counts: HashMap<usize, u64> = HashMap::new();
    for (prefix, members) in &by_prefix {
        let Ok(prefix_str) = std::str::from_utf8(prefix) else {
            failed = failed.saturating_add(1);
            continue;
        };
        let parsed = source.range(prefix_str).and_then(|body| parse_range(&body));
        let Ok(entries) = parsed else {
            failed = failed.saturating_add(1);
            continue;
        };
        for &idx in members {
            let suffix = hashes.get(idx).and_then(|h| h.get(PREFIX_LEN..));
            let hit = entries
                .iter()
                .find(|(s, _)| Some(s.as_slice()) == suffix)
                .map(|(_, c)| *c);
            if let Some(c) = hit {
                counts.insert(idx, c);
            }
        }
    }

    let findings = targets
        .iter()
        .filter_map(|t| {
            let count = *counts.get(&t.hash)?;
            Some(Finding {
                item_id: t.item.id,
                vault_id: t.item.vault_id,
                check: Check::Compromised,
                severity: Check::Compromised.severity(),
                field_id: Some(t.field_id.to_owned()),
                detail: Detail::Pwned { count },
            })
        })
        .collect();

    let status = if failed == 0 {
        PwnedStatus::Checked
    } else if usize::try_from(failed).is_ok_and(|f| f >= requested) {
        PwnedStatus::Unavailable
    } else {
        PwnedStatus::Partial {
            failed_prefixes: failed,
        }
    };
    (findings, status)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha1_hex_known_vector() {
        let h = sha1_hex("password");
        assert_eq!(&h[..], b"5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8");
    }

    #[test]
    fn sha1_hex_fips_180_vectors() {
        // The empty input is also the constant the raw digest is overwritten
        // with: the wipe must not leak into the result.
        assert_eq!(
            &sha1_hex("")[..],
            b"DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"
        );
        assert_eq!(
            &sha1_hex("abc")[..],
            b"A9993E364706816ABA3E25717850C26C9CD0D89D"
        );
    }

    #[test]
    fn parse_range_padding_ignored() {
        let body = b"00000000000000000000000000000000000:0\r\n\
                     0123456789abcdef0123456789abcdef012:7\r\n\r\n";
        let r = parse_range(body).unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(&r[0].0, b"0123456789ABCDEF0123456789ABCDEF012");
        assert_eq!(r[0].1, 7);
    }

    #[test]
    fn parse_range_rejects_garbage() {
        for bad in [
            &b"nonsense"[..],
            b"0123456789ABCDEF0123456789ABCDEF012",
            b"0123456789ABCDEF0123456789ABCDEF012:x",
            b"0123456789ABCDEF0123456789ABCDEF012:",
            b"0123456789ABCDEF0123456789ABCDEF01:3",
            b"0123456789ABCDEF0123456789ABCDEF01G:3",
            b"0123456789ABCDEF0123456789ABCDEF012:-1",
        ] {
            assert!(
                matches!(
                    parse_range(bad),
                    Err(Error::InvalidFormat("range response"))
                ),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn dir_source_reads_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("ABCDE.txt"), b"body").unwrap();
        std::fs::write(dir.path().join("0abcd.txt"), b"low").unwrap();
        let mut s = DirRangeSource::new(dir.path());
        assert_eq!(s.range("ABCDE").unwrap(), b"body");
        assert_eq!(s.range("0ABCD").unwrap(), b"low");
        std::fs::write(
            dir.path().join("BBBBB.txt"),
            vec![b'x'; 4 * 1024 * 1024 + 1],
        )
        .unwrap();
        assert!(matches!(s.range("BBBBB"), Err(Error::InvalidFormat(_))));
        assert!(matches!(s.range("FFFFF"), Err(Error::NotFound)));
        assert!(matches!(s.range("abcde"), Err(Error::InvalidFormat(_))));
        assert!(matches!(s.range("../AB"), Err(Error::InvalidFormat(_))));
    }
}
