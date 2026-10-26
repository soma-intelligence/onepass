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

pub(crate) mod build;
pub(crate) mod csv_logins;
pub(crate) mod dashlane;
pub(crate) mod lastpass;
pub(crate) mod limits;

use serde::Serialize;

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
