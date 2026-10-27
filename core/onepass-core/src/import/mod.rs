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
pub(crate) mod enpass;
pub(crate) mod json;
pub(crate) mod keepass;
pub(crate) mod keeper;
pub(crate) mod lastpass;
pub(crate) mod limits;
pub(crate) mod nordpass;
pub(crate) mod onepux;
pub(crate) mod roboform;
pub mod text;

use std::io::Cursor;

use serde::de::{DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer as _, Serialize};

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
    /// OnePass plaintext CSV export (`export::csv_plaintext`).
    OnePassCsv,
    NordPassCsv,
    /// Header-less: detected only when it starts with a header row.
    KeeperCsv,
    EnpassJson,
    RoboFormCsv,
}

impl Format {
    /// Every format, in declaration order.
    pub const ALL: [Format; 21] = [
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
        Format::OnePassCsv,
        Format::NordPassCsv,
        Format::KeeperCsv,
        Format::EnpassJson,
        Format::RoboFormCsv,
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
            Format::OnePassCsv => "onepass-csv",
            Format::NordPassCsv => "nordpass-csv",
            Format::KeeperCsv => "keeper-csv",
            Format::EnpassJson => "enpass-json",
            Format::RoboFormCsv => "roboform-csv",
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
/// trusted). Reads a zip central directory (entry names only), the first
/// CSV line, or, for JSON, makes one syntax-only streaming pass over the
/// object that keeps no value and no key (memory stays constant). No
/// record is ever built.
pub fn detect(_file_name: &str, bytes: &[u8]) -> Option<Format> {
    if bytes.starts_with(b"OPARCH") {
        return Some(Format::OnePassArchive);
    }
    if bytes.starts_with(b"PK\x03\x04") {
        return detect_zip(bytes);
    }
    // KDBX is not supported, but reported as KeePass so that `parse` gives
    // the explicit refusal.
    if bytes.starts_with(&keepass::KDBX_MAGIC) {
        return Some(Format::KeePassXml);
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
    detect_csv(body)
}

fn detect_zip(bytes: &[u8]) -> Option<Format> {
    let archive = zip::ZipArchive::new(Cursor::new(bytes)).ok()?;
    let (mut dashlane, mut safari) = (false, false);
    for name in archive.file_names() {
        let Ok(name) = name else { continue };
        if name.as_ref() == "export.data" {
            return Some(Format::OnePasswordPux);
        }
        dashlane |= dashlane::is_dashlane_entry(&name);
        safari |= csv_logins::is_safari_passwords_entry(&name);
    }
    if dashlane {
        Some(Format::DashlaneZip)
    } else {
        safari.then_some(Format::SafariCsv)
    }
}

/// Top-level JSON keys that matter for detection.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
enum Key {
    Items,
    Encrypted,
    Data,
    Accounts,
    #[serde(other)]
    Other,
}

/// Visits a JSON object recording which interesting keys it holds. Keys
/// deserialize into a unit enum and values into `IgnoredAny`: nothing owned.
#[derive(Default)]
struct Keys {
    items: bool,
    encrypted: bool,
    data: bool,
    accounts: bool,
    /// The first element of `items` has Enpass keys.
    enpass: bool,
}

/// Keys of an item that only Enpass writes.
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum ItemKey {
    TemplateType,
    Category,
    Fields,
    #[serde(other)]
    Other,
}

/// Seed for the `items` value: looks at the keys of its first element
/// only, skips the rest. A value that is not an array of objects fails
/// detection, as it fits no known format.
struct FirstItem<'a>(&'a mut bool);

impl<'de> DeserializeSeed<'de> for FirstItem<'_> {
    type Value = ();

    fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> std::result::Result<(), D::Error> {
        d.deserialize_seq(self)
    }
}

impl<'de> Visitor<'de> for FirstItem<'_> {
    type Value = ();

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("an array")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> std::result::Result<(), A::Error> {
        seq.next_element_seed(EnpassItem(self.0))?;
        while seq.next_element::<IgnoredAny>()?.is_some() {}
        Ok(())
    }
}

/// Sets the flag when an object has `template_type`, or both `category`
/// and `fields` (Enpass); never keeps a value.
struct EnpassItem<'a>(&'a mut bool);

impl<'de> DeserializeSeed<'de> for EnpassItem<'_> {
    type Value = ();

    fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> std::result::Result<(), D::Error> {
        d.deserialize_map(self)
    }
}

impl<'de> Visitor<'de> for EnpassItem<'_> {
    type Value = ();

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a JSON object")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> std::result::Result<(), A::Error> {
        let (mut template, mut category, mut fields) = (false, false, false);
        while let Some(key) = map.next_key::<ItemKey>()? {
            match key {
                ItemKey::TemplateType => template = true,
                ItemKey::Category => category = true,
                ItemKey::Fields => fields = true,
                ItemKey::Other => {}
            }
            map.next_value::<IgnoredAny>()?;
        }
        *self.0 = template || (category && fields);
        Ok(())
    }
}

impl<'de> Visitor<'de> for &mut Keys {
    type Value = ();

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a JSON object")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> std::result::Result<(), A::Error> {
        while let Some(key) = map.next_key::<Key>()? {
            match key {
                Key::Items => {
                    self.items = true;
                    map.next_value_seed(FirstItem(&mut self.enpass))?;
                    continue;
                }
                Key::Encrypted => self.encrypted = true,
                Key::Data => self.data = true,
                Key::Accounts => self.accounts = true,
                Key::Other => {}
            }
            map.next_value::<IgnoredAny>()?;
        }
        Ok(())
    }
}

fn detect_json(body: &[u8]) -> Option<Format> {
    let mut keys = Keys::default();
    let mut de = serde_json::Deserializer::from_slice(body);
    de.deserialize_map(&mut keys).ok()?;
    de.end().ok()?;
    // An encrypted export has `encrypted` and `data` but no `items`: still
    // Bitwarden, so that `parse` reports the explicit encrypted-export error.
    if keys.encrypted && (keys.items || keys.data) {
        Some(Format::BitwardenJson)
    } else if keys.items && keys.enpass {
        Some(Format::EnpassJson)
    } else if keys.accounts {
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
    if nordpass::is_nordpass_header(&header) {
        return Some(Format::NordPassCsv);
    }
    if roboform::is_roboform_header(&header) {
        return Some(Format::RoboFormCsv);
    }
    if keeper::is_keeper_header(&header) {
        return Some(Format::KeeperCsv);
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
        Format::OnePassCsv => csv_logins::parse_onepass_csv(bytes),
        Format::NordPassCsv => nordpass::parse_nordpass_csv(bytes),
        Format::KeeperCsv => keeper::parse_keeper_csv(bytes),
        Format::EnpassJson => enpass::parse_enpass_json(bytes),
        Format::RoboFormCsv => roboform::parse_roboform_csv(bytes),
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
        assert_eq!(Format::ALL.len(), 21);
        for f in Format::ALL {
            assert_eq!(Format::from_name(f.name()), Some(f));
        }
        assert_eq!(Format::OnePasswordPux.name(), "1pux");
        assert_eq!(Format::CredentialExchange.name(), "cxf");
        assert_eq!(Format::OnePassArchive.name(), "onepass");
        assert_eq!(Format::OnePassCsv.name(), "onepass-csv");
        assert_eq!(Format::from_name("nope"), None);
        assert_eq!(Format::from_name("1PUX"), None);
    }

    #[test]
    fn kdbx_detected_and_refused_with_message() {
        let mut kdbx = keepass::KDBX_MAGIC.to_vec();
        kdbx.extend_from_slice(&[0x01, 0x00, 0x04, 0x00, 0xFF, 0xFE]);
        assert_eq!(detect("db.kdbx", &kdbx), Some(Format::KeePassXml));
        assert_eq!(
            parse(Format::KeePassXml, &kdbx).unwrap_err(),
            Error::InvalidFormat("KeePass KDBX is not supported: export as KeePass 2 XML")
        );
    }
}
