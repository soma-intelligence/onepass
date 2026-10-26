//! Format detection and the import entry point, through the public API.

use std::io::Write;

use onepass_core::import::{Format, detect, parse};
use onepass_core::model::validate;
use proptest::prelude::*;
use zip::write::SimpleFileOptions;

macro_rules! fixture {
    ($name:literal) => {
        include_bytes!(concat!("fixtures/import/", $name)) as &[u8]
    };
}

fn zip_of(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    for (name, data) in files {
        w.start_file(*name, SimpleFileOptions::default()).unwrap();
        w.write_all(data).unwrap();
    }
    w.finish().unwrap().into_inner()
}

fn dashlane_zip() -> Vec<u8> {
    zip_of(&[
        ("credentials.csv", fixture!("dashlane/credentials.csv")),
        ("securenotes.csv", fixture!("dashlane/securenotes.csv")),
        ("payments.csv", fixture!("dashlane/payments.csv")),
        ("ids.csv", fixture!("dashlane/ids.csv")),
        ("personalInfo.csv", fixture!("dashlane/personalInfo.csv")),
    ])
}

fn pux() -> Vec<u8> {
    zip_of(&[
        ("export.attributes", b"{}"),
        ("export.data", fixture!("1pux-export.data.json")),
    ])
}

/// Every fixture with the format it must be detected as.
fn cases() -> Vec<(&'static str, Vec<u8>, Format)> {
    let v = |b: &[u8]| b.to_vec();
    vec![
        ("export.1pux", pux(), Format::OnePasswordPux),
        (
            "1password.csv",
            v(fixture!("1password.csv")),
            Format::OnePasswordCsv,
        ),
        (
            "bitwarden.json",
            v(fixture!("bitwarden.json")),
            Format::BitwardenJson,
        ),
        (
            "bitwarden.csv",
            v(fixture!("bitwarden.csv")),
            Format::BitwardenCsv,
        ),
        ("chrome.csv", v(fixture!("chrome.csv")), Format::ChromeCsv),
        ("safari.csv", v(fixture!("safari.csv")), Format::SafariCsv),
        (
            "firefox.csv",
            v(fixture!("firefox.csv")),
            Format::FirefoxCsv,
        ),
        (
            "lastpass.csv",
            v(fixture!("lastpass.csv")),
            Format::LastPassCsv,
        ),
        (
            "credentials.csv",
            v(fixture!("dashlane/credentials.csv")),
            Format::DashlaneCsv,
        ),
        (
            "securenotes.csv",
            v(fixture!("dashlane/securenotes.csv")),
            Format::DashlaneCsv,
        ),
        (
            "payments.csv",
            v(fixture!("dashlane/payments.csv")),
            Format::DashlaneCsv,
        ),
        (
            "ids.csv",
            v(fixture!("dashlane/ids.csv")),
            Format::DashlaneCsv,
        ),
        (
            "personalInfo.csv",
            v(fixture!("dashlane/personalInfo.csv")),
            Format::DashlaneCsv,
        ),
        ("dashlane.zip", dashlane_zip(), Format::DashlaneZip),
        (
            "protonpass.csv",
            v(fixture!("protonpass.csv")),
            Format::ProtonPassCsv,
        ),
        (
            "keepass.xml",
            v(fixture!("keepass.xml")),
            Format::KeePassXml,
        ),
        (
            "cxf.json",
            v(fixture!("cxf.json")),
            Format::CredentialExchange,
        ),
        (
            "otpauth.txt",
            v(fixture!("otpauth.txt")),
            Format::OtpAuthUris,
        ),
        ("wifi-qr.txt", v(fixture!("wifi-qr.txt")), Format::WifiQr),
    ]
}

#[test]
fn detects_every_fixture() {
    for (name, bytes, want) in cases() {
        assert_eq!(detect(name, &bytes), Some(want), "{name}");
    }
}

#[test]
fn detect_ignores_file_name_and_rejects_unknown() {
    assert_eq!(detect("data.1pux", b"hello"), None);
    assert_eq!(detect("x.csv", b""), None);
    assert_eq!(detect("x", b"a,b,c\n1,2,3\n"), None);
    assert_eq!(detect("x", b"{\"a\": 1}"), None);
    assert_eq!(detect("x", b"PK\x03\x04garbage"), None);
    assert_eq!(detect("x", &zip_of(&[("other.txt", b"x")])), None);
    assert_eq!(detect("x", b"OPARCH\x01rest"), Some(Format::OnePassArchive));
}

#[test]
fn detects_lastpass_without_totp_and_bom() {
    let old = b"url,username,password,extra,name,grouping,fav\nhttp://a,b,c,,d,e,0\n";
    assert_eq!(detect("x", old), Some(Format::LastPassCsv));
    let mut bom = b"\xEF\xBB\xBF".to_vec();
    bom.extend_from_slice(fixture!("lastpass.csv"));
    assert_eq!(detect("x", &bom), Some(Format::LastPassCsv));
}

#[test]
fn parse_every_fixture_validates() {
    for (name, bytes, format) in cases() {
        let import = parse(format, &bytes).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert!(!import.items.is_empty(), "{name}");
        for it in &import.items {
            validate(&it.item).unwrap_or_else(|e| panic!("{name}: {e}"));
        }
    }
}

#[test]
fn oversized_input_rejected() {
    let big = vec![b'a'; 256 * 1024 * 1024 + 1];
    for f in Format::ALL {
        if f != Format::OnePassArchive {
            assert!(parse(f, &big).is_err(), "{}", f.name());
        }
    }
}

#[test]
fn archive_is_refused() {
    assert!(parse(Format::OnePassArchive, b"OPARCH").is_err());
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn no_panic_on_arbitrary_bytes(bytes in proptest::collection::vec(any::<u8>(), 0..4096)) {
        for f in Format::ALL {
            if f != Format::OnePassArchive {
                let _ = parse(f, &bytes);
            }
        }
        let _ = detect("x", &bytes);
    }
}
