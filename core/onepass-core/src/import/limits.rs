//! Caps on hostile import input (spec 4.4) and the bounded readers for the
//! two container formats: CSV and zip. Every violation is
//! `Error::InvalidFormat` with a static reason.

// The format parsers (tasks 2 to 9) and the CSV export are the callers;
// until they land, only the tests use these readers.
use std::io::{Cursor, Read};

use zeroize::Zeroizing;
use zip::CompressionMethod;

use crate::{Error, Result};

const MIB: usize = 1 << 20;

/// Largest import file.
pub(crate) const MAX_INPUT: usize = 256 * MIB;
/// Most entries in a zip (1PUX, Dashlane).
pub(crate) const ZIP_MAX_ENTRIES: usize = 10_000;
/// Most decompressed bytes over all entries of a zip.
pub(crate) const ZIP_MAX_TOTAL: u64 = 512 * MIB as u64;
/// Most decompressed bytes in one zip entry.
pub(crate) const ZIP_MAX_ENTRY: u64 = 64 * MIB as u64;
/// Largest CSV cell.
pub(crate) const CSV_MAX_CELL: usize = MIB;
/// Most CSV rows, XML entries, or items in one import.
pub(crate) const MAX_RECORDS: usize = 1_000_000;
/// Deepest XML element nesting (KeePass).
pub(crate) const XML_MAX_DEPTH: usize = 256;
/// Longest host name.
pub(crate) const MAX_DOMAIN_LEN: usize = 253;

fn check_input(bytes: &[u8]) -> Result<()> {
    if bytes.len() > MAX_INPUT {
        return Err(Error::InvalidFormat("import file too large"));
    }
    Ok(())
}

/// Header and rows of a CSV file. The UTF-8 BOM is dropped and the rest
/// must be strict UTF-8. Header names are trimmed and lower-cased; rows
/// may have any length (`flexible`). Caps: cell size and row count.
pub(crate) fn csv_records(bytes: &[u8]) -> Result<(Vec<String>, Vec<Vec<String>>)> {
    let mut rows = csv_rows(bytes)?.into_iter();
    let header = match rows.next() {
        None => return Ok((Vec::new(), Vec::new())),
        Some(first) => first.iter().map(|h| h.trim().to_lowercase()).collect(),
    };
    Ok((header, rows.collect()))
}

/// Every record of a header-less CSV file (Keeper), cells as written.
/// Same rules and caps as [`csv_records`], whose header is the first
/// record here (so one more record is allowed).
pub(crate) fn csv_rows(bytes: &[u8]) -> Result<Vec<Vec<String>>> {
    const BAD: Error = Error::InvalidFormat("csv syntax");
    check_input(bytes)?;
    let bytes = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes);
    let text = std::str::from_utf8(bytes).map_err(|_| Error::InvalidFormat("csv is not utf-8"))?;
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .from_reader(text.as_bytes());
    let mut rows: Vec<Vec<String>> = Vec::new();
    for record in reader.records() {
        if rows.len() > MAX_RECORDS {
            return Err(Error::InvalidFormat("too many csv rows"));
        }
        let record = record.map_err(|_| BAD)?;
        if record.iter().any(|c| c.len() > CSV_MAX_CELL) {
            return Err(Error::InvalidFormat("csv cell too large"));
        }
        rows.push(record.iter().map(str::to_owned).collect());
    }
    Ok(rows)
}

/// Name and content of every file entry of a zip, in archive order.
/// Directory entries are skipped. Names are never used as paths. Only
/// stored and deflated entries are accepted. Decompressed sizes are
/// enforced while reading (`Read::take`), not trusted from the headers.
pub(crate) fn zip_entries(bytes: &[u8]) -> Result<Vec<(String, Zeroizing<Vec<u8>>)>> {
    const BAD: Error = Error::InvalidFormat("zip archive");
    check_input(bytes)?;
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).map_err(|_| BAD)?;
    if archive.len() > ZIP_MAX_ENTRIES {
        return Err(Error::InvalidFormat("too many zip entries"));
    }
    let mut total: u64 = 0;
    let mut reserved: u64 = 0;
    let mut out = Vec::new();
    for i in 0..archive.len() {
        let file = archive.by_index(i).map_err(|_| BAD)?;
        if file.is_dir() {
            continue;
        }
        if !matches!(
            file.compression(),
            CompressionMethod::Stored | CompressionMethod::Deflated
        ) {
            return Err(Error::InvalidFormat("zip compression method"));
        }
        let name = file.name().map_err(|_| BAD)?.into_owned();
        let cap = ZIP_MAX_ENTRY.min(ZIP_MAX_TOTAL.saturating_sub(total));
        // Reserve up front so the secret is not left behind by reallocation,
        // but never more than the caps allow over the whole archive: the
        // declared size is attacker controlled.
        let reserve = file
            .size()
            .min(cap)
            .min(ZIP_MAX_TOTAL.saturating_sub(reserved));
        reserved = reserved.saturating_add(reserve);
        let mut buf = Zeroizing::new(Vec::with_capacity(usize::try_from(reserve).unwrap_or(0)));
        file.take(cap.saturating_add(1))
            .read_to_end(&mut buf)
            .map_err(|_| BAD)?;
        let n = buf.len() as u64;
        if n > ZIP_MAX_ENTRY {
            return Err(Error::InvalidFormat("zip entry too large"));
        }
        if n > cap {
            return Err(Error::InvalidFormat("zip content too large"));
        }
        total = total.saturating_add(n);
        out.push((name, buf));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Write};

    use zip::CompressionMethod;
    use zip::write::{SimpleFileOptions, ZipWriter};

    use super::*;
    use crate::Error;

    fn zip_of(entries: &[(&str, &[u8])], method: CompressionMethod) -> Vec<u8> {
        let mut w = ZipWriter::new(Cursor::new(Vec::new()));
        let opts = SimpleFileOptions::default().compression_method(method);
        for (name, data) in entries {
            w.start_file(*name, opts).unwrap();
            w.write_all(data).unwrap();
        }
        w.finish().unwrap().into_inner()
    }

    #[test]
    fn zip_caps() {
        let zeros = vec![0u8; 65 << 20];
        let bomb = zip_of(&[("export.data", &zeros)], CompressionMethod::Deflated);
        assert!(bomb.len() < 1 << 20, "deflated zeros stay small");
        assert!(matches!(zip_entries(&bomb), Err(Error::InvalidFormat(_))));

        let ok = zip_of(
            &[("a.csv", b"one"), ("dir/b.csv", b"two")],
            CompressionMethod::Deflated,
        );
        let entries = zip_entries(&ok).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].0, "a.csv");
        assert_eq!(entries[0].1.as_slice(), b"one");
        assert_eq!(entries[1].0, "dir/b.csv");
        assert_eq!(entries[1].1.as_slice(), b"two");
    }

    #[test]
    fn zip_entry_count_cap() {
        let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
        let build = |n: usize| {
            let mut w = ZipWriter::new(Cursor::new(Vec::new()));
            for i in 0..n {
                w.start_file(format!("e{i}"), opts).unwrap();
            }
            w.finish().unwrap().into_inner()
        };
        assert_eq!(
            zip_entries(&build(ZIP_MAX_ENTRIES)).unwrap().len(),
            ZIP_MAX_ENTRIES
        );
        assert_eq!(
            zip_entries(&build(ZIP_MAX_ENTRIES + 1)),
            Err(Error::InvalidFormat("too many zip entries"))
        );
    }

    #[test]
    fn zip_skips_directories_and_keeps_stored() {
        let mut w = ZipWriter::new(Cursor::new(Vec::new()));
        let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
        w.add_directory("dir/", opts).unwrap();
        w.start_file("dir/x", opts).unwrap();
        w.write_all(b"x").unwrap();
        let bytes = w.finish().unwrap().into_inner();
        let entries = zip_entries(&bytes).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, "dir/x");
    }

    #[test]
    fn zip_rejects_garbage() {
        assert!(matches!(
            zip_entries(b"not a zip"),
            Err(Error::InvalidFormat(_))
        ));
    }

    #[test]
    fn csv_bom_crlf_multiline() {
        let input = "\u{feff}Name,URL\r\n\"a\r\nb\",https://example.com\r\n";
        let (header, rows) = csv_records(input.as_bytes()).unwrap();
        assert_eq!(header, vec!["name", "url"]);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0][0], "a\r\nb");
        assert_eq!(rows[0][1], "https://example.com");
    }

    #[test]
    fn csv_header_is_trimmed_and_lowercased() {
        let (header, rows) = csv_records(b" Title , Login_URI\nx\n").unwrap();
        assert_eq!(header, vec!["title", "login_uri"]);
        // Flexible: a short row is accepted.
        assert_eq!(rows, vec![vec!["x".to_owned()]]);
    }

    #[test]
    fn csv_rejects_non_utf8() {
        assert!(matches!(
            csv_records(&[b'a', b',', 0xff, b'\n']),
            Err(Error::InvalidFormat(_))
        ));
    }

    #[test]
    fn csv_rejects_huge_cell() {
        let mut input = b"name\n".to_vec();
        input.extend(std::iter::repeat_n(b'a', CSV_MAX_CELL + 1));
        input.push(b'\n');
        assert!(matches!(csv_records(&input), Err(Error::InvalidFormat(_))));
    }
}
