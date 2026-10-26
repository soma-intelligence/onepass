//! Import of other password managers' exports (milestone 5).

#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

pub(crate) mod bitwarden;
pub(crate) mod build;
pub(crate) mod csv_logins;
pub(crate) mod cxf;
pub(crate) mod dashlane;
pub(crate) mod keepass;
pub(crate) mod lastpass;
pub(crate) mod limits;
pub(crate) mod onepux;
pub mod text;

use std::io::Cursor;

use serde::Serialize;
use serde::de::IgnoredAny;

use crate::error::{Error, Result};
use crate::model::Item;

/// Source format of an import file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Format {
    OnePasswordPux,
    OnePasswordCsv,
    BitwardenJson,
    BitwardenCsv,
    ChromeCsv,
    SafariCsv,
    FirefoxCsv,
    LastPassCsv,
    DashlaneCsv,
    DashlaneZip,
    ProtonPassCsv,
    KeePassXml,
    CredentialExchange,
    OtpAuthUris,
    WifiQr,
    /// Encrypted OnePass archive: opened by the `archive` module, which
    /// needs a passphrase.
    OnePassArchive,
}

impl Format {
    /// Every format, in declaration order.
    pub const ALL: [Format; 16] = [
        Format::OnePasswordPux,
        Format::OnePasswordCsv,
        Format::BitwardenJson,
        Format::BitwardenCsv,
        Format::ChromeCsv,
        Format::SafariCsv,
        Format::FirefoxCsv,
        Format::LastPassCsv,
        Format::DashlaneCsv,
        Format::DashlaneZip,
        Format::ProtonPassCsv,
        Format::KeePassXml,
        Format::CredentialExchange,
        Format::OtpAuthUris,
        Format::WifiQr,
        Format::OnePassArchive,
    ];

    /// Stable kebab-case name (CLI flag value).
    pub fn name(self) -> &'static str {
        match self {
            Format::OnePasswordPux => "1pux",
            Format::OnePasswordCsv => "1password-csv",
            Format::BitwardenJson => "bitwarden-json",
            Format::BitwardenCsv => "bitwarden-csv",
            Format::ChromeCsv => "chrome-csv",
            Format::SafariCsv => "safari-csv",
            Format::FirefoxCsv => "firefox-csv",
            Format::LastPassCsv => "lastpass-csv",
            Format::DashlaneCsv => "dashlane-csv",
            Format::DashlaneZip => "dashlane-zip",
            Format::ProtonPassCsv => "protonpass-csv",
            Format::KeePassXml => "keepass-xml",
            Format::CredentialExchange => "cxf",
            Format::OtpAuthUris => "otpauth",
            Format::WifiQr => "wifi-qr",
            Format::OnePassArchive => "onepass",
        }
    }

    /// Inverse of [`Format::name`]. Exact, case-sensitive match.
    pub fn from_name(s: &str) -> Option<Format> {
        Format::ALL.into_iter().find(|f| f.name() == s)
    }
}

/// Result of parsing one import file.
#[derive(Debug, Default)]
pub struct Import {
    pub items: Vec<ImportedItem>,
    /// Entry index and static code: never a value.
    pub warnings: Vec<Warning>,
    /// Empty rows and unsupported entries.
    pub skipped: u32,
}

#[derive(Debug, Clone)]
pub struct ImportedItem {
    /// `vault_id` is `Id([0; 16])` until the target vault is chosen.
    pub item: Item,
    /// Vault, folder or group of the source.
    pub folder: Option<String>,
}

/// A fallback applied to one source entry. Codes: `field_moved`,
/// `login_to_password`, `to_secure_note`, `totp_moved`,
/// `attachment_skipped`, `unsupported_entry`, `bad_date`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Warning {
    /// Zero-based index of the entry in the source.
    pub entry: u32,
    pub code: &'static str,
}

/// Longest prefix examined for a CSV header line.
const HEADER_PROBE: usize = 64 * 1024;

/// Guess the format of an import file from its content (the name is never
/// trusted). Reads only a zip central directory, a first CSV line or the
/// top-level keys of a JSON object: nothing is fully parsed.
pub fn detect(_file_name: &str, bytes: &[u8]) -> Option<Format> {
    if bytes.starts_with(b"OPARCH") {
        return Some(Format::OnePassArchive);
    }
    if bytes.starts_with(b"PK\x03\x04") {
        return detect_zip(bytes);
    }
    let bytes = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes);
    let start = bytes.iter().position(|b| !b.is_ascii_whitespace())?;
    let body = bytes.get(start..)?;
    if body.starts_with(b"<?xml") || body.starts_with(b"<KeePassFile") {
        return Some(Format::KeePassXml);
    }
    if body.starts_with(b"{") {
        return detect_json(body);
    }
    if body.starts_with(b"otpauth") {
        return Some(Format::OtpAuthUris);
    }
    if body.starts_with(b"WIFI:") {
        return Some(Format::WifiQr);
    }
    detect_csv(bytes)
}

fn detect_zip(bytes: &[u8]) -> Option<Format> {
    let archive = zip::ZipArchive::new(Cursor::new(bytes)).ok()?;
    let mut dashlane = false;
    for name in archive.file_names() {
        let Ok(name) = name else { continue };
        if name.as_ref() == "export.data" {
            return Some(Format::OnePasswordPux);
        }
        dashlane |= dashlane::is_dashlane_entry(&name);
    }
    dashlane.then_some(Format::DashlaneZip)
}

fn detect_json(body: &[u8]) -> Option<Format> {
    let keys: std::collections::BTreeMap<String, IgnoredAny> = serde_json::from_slice(body).ok()?;
    if keys.contains_key("items") && keys.contains_key("encrypted") {
        Some(Format::BitwardenJson)
    } else if keys.contains_key("accounts") {
        Some(Format::CredentialExchange)
    } else {
        None
    }
}

fn detect_csv(bytes: &[u8]) -> Option<Format> {
    let probe = bytes.get(..bytes.len().min(HEADER_PROBE))?;
    let line = probe.split(|b| *b == b'\n').next()?;
    let record = csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .from_reader(line)
        .byte_records()
        .next()?
        .ok()?;
    let header: Vec<String> = record
        .iter()
        .map(|c| String::from_utf8_lossy(c).trim().to_lowercase())
        .collect();
    if let Some(f) = csv_logins::sniff(&header) {
        return Some(f);
    }
    if lastpass::is_lastpass_header(&header) {
        return Some(Format::LastPassCsv);
    }
    dashlane::is_dashlane_header(&header).then_some(Format::DashlaneCsv)
}

/// Parse an import file of a known format. Input over 256 MiB and results
/// over one million items are refused.
pub fn parse(format: Format, bytes: &[u8]) -> Result<Import> {
    if bytes.len() > limits::MAX_INPUT {
        return Err(Error::InvalidFormat("import file too large"));
    }
    let import = match format {
        Format::OnePasswordPux => onepux::parse_1pux(bytes),
        Format::OnePasswordCsv => csv_logins::parse_onepassword_csv(bytes),
        Format::BitwardenJson => bitwarden::parse_bitwarden_json(bytes),
        Format::BitwardenCsv => csv_logins::parse_bitwarden_csv(bytes),
        Format::ChromeCsv => csv_logins::parse_chrome(bytes),
        Format::SafariCsv => csv_logins::parse_safari(bytes),
        Format::FirefoxCsv => csv_logins::parse_firefox(bytes),
        Format::LastPassCsv => lastpass::parse_lastpass(bytes),
        Format::DashlaneCsv => dashlane::parse_dashlane_csv(bytes),
        Format::DashlaneZip => dashlane::parse_dashlane_zip(bytes),
        Format::ProtonPassCsv => csv_logins::parse_protonpass_csv(bytes),
        Format::KeePassXml => keepass::parse_keepass_xml(bytes),
        Format::CredentialExchange => cxf::parse_cxf(bytes),
        Format::OtpAuthUris => text::parse_otpauth_lines(bytes),
        Format::WifiQr => text::parse_wifi_qr_lines(bytes),
        Format::OnePassArchive => Err(Error::InvalidFormat("OnePass archive: use archive::open")),
    }?;
    if import.items.len() > limits::MAX_RECORDS {
        return Err(Error::InvalidFormat("too many items"));
    }
    Ok(import)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_names_roundtrip() {
        assert_eq!(Format::ALL.len(), 16);
        for f in Format::ALL {
            assert_eq!(Format::from_name(f.name()), Some(f));
        }
        assert_eq!(Format::OnePasswordPux.name(), "1pux");
        assert_eq!(Format::CredentialExchange.name(), "cxf");
        assert_eq!(Format::OnePassArchive.name(), "onepass");
        assert_eq!(Format::from_name("nope"), None);
        assert_eq!(Format::from_name("1PUX"), None);
    }
}
