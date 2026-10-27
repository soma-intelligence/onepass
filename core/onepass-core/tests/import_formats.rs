//! Format detection and the import entry point, through the public API.

use std::io::Write;

use onepass_core::Id;
use onepass_core::archive::ArchivedVault;
use onepass_core::export::csv_plaintext;
use onepass_core::import::{Format, detect, parse};
use onepass_core::model::{FieldValue, Item, ItemType, ItemUrl, MatchRule, new_item, validate};
use onepass_core::vault::VaultMeta;
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
        (
            "onepass.csv",
            v(fixture!("onepass.csv")),
            Format::OnePassCsv,
        ),
        (
            "Passwords.csv",
            v(fixture!("apple-passwords.csv")),
            Format::SafariCsv,
        ),
        (
            "nordpass.csv",
            v(fixture!("nordpass.csv")),
            Format::NordPassCsv,
        ),
        (
            "enpass.json",
            v(fixture!("enpass.json")),
            Format::EnpassJson,
        ),
        (
            "roboform.csv",
            v(fixture!("roboform.csv")),
            Format::RoboFormCsv,
        ),
    ]
}

#[test]
fn detects_every_fixture() {
    for (name, bytes, want) in cases() {
        assert_eq!(detect(name, &bytes), Some(want), "{name}");
    }
}

#[test]
fn apple_passwords_export_keeps_multiline_notes_and_otp() {
    let imp = parse(Format::SafariCsv, fixture!("apple-passwords.csv")).unwrap();
    assert_eq!(imp.items.len(), 2);
    let it = &imp.items[0].item;
    assert_eq!(it.title, "mail.example.com (alice@example.com)");
    assert_eq!(text(it, "username"), "alice@example.com");
    assert_eq!(text(it, "password"), "Apple-Invented-1");
    assert_eq!(it.notes, "Recovery, by phone\nsecond line");
    assert!(matches!(
        it.field("totp").map(|f| &f.value),
        Some(FieldValue::Otp(uri)) if uri.starts_with("otpauth://totp/")
    ));
}

#[test]
fn safari_browsing_data_zip_reads_passwords_csv() {
    let z = zip_of(&[
        ("Bookmarks.html", b"<html></html>"),
        ("Passwords.csv", fixture!("apple-passwords.csv")),
        ("History.json", b"{}"),
    ]);
    assert_eq!(detect("Safari Export.zip", &z), Some(Format::SafariCsv));
    let imp = parse(Format::SafariCsv, &z).unwrap();
    assert_eq!(imp.items.len(), 2);
    let without = zip_of(&[("Bookmarks.html", b"<html></html>")]);
    assert!(parse(Format::SafariCsv, &without).is_err());
}

#[test]
fn chromium_browsers_share_the_chrome_csv() {
    // Edge, Brave, Opera, Arc and Vivaldi write Chrome's export, with or
    // without the `note` column.
    for csv in [
        &b"name,url,username,password\nA,https://a.example.com,u,p\n"[..],
        &b"name,url,username,password,note\nA,https://a.example.com,u,p,n\n"[..],
    ] {
        assert_eq!(
            detect("Microsoft Edge Passwords.csv", csv),
            Some(Format::ChromeCsv)
        );
        assert_eq!(parse(Format::ChromeCsv, csv).unwrap().items.len(), 1);
    }
}

#[test]
fn keeper_without_header_needs_the_format_chosen() {
    let csv = fixture!("keeper.csv");
    assert_eq!(detect("keeper.csv", csv), None);
    let imp = parse(Format::KeeperCsv, csv).unwrap();
    assert_eq!(imp.items.len(), 3);
    for it in &imp.items {
        validate(&it.item).unwrap();
    }
    let with_header =
        b"Folder,Title,Login,Password,Website Address,Notes,Shared Folder,Custom Fields\n\
        ,Shop,bob,Pw-Invented-2,https://shop.example.org,,,\n";
    assert_eq!(detect("x", with_header), Some(Format::KeeperCsv));
}

#[test]
fn bitwarden_unencrypted_json_is_not_enpass() {
    let b = br#"{"encrypted":false,"folders":[],"items":[{"type":1,"name":"A","login":{"username":"u","password":"p"}}]}"#;
    assert_eq!(detect("x", b), Some(Format::BitwardenJson));
    assert_eq!(detect("x", br#"{"items":[{"name":"A"}]}"#), None);
    assert_eq!(detect("x", br#"{"items":7}"#), None);
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

#[test]
fn json_with_many_keys_is_detected_in_constant_memory() {
    let mut s = String::from("{");
    for i in 0..200_000 {
        s.push_str(&format!("\"k{i}\":0,"));
    }
    s.push_str("\"accounts\":[]}");
    assert_eq!(detect("x", s.as_bytes()), Some(Format::CredentialExchange));
}

#[test]
fn header_after_blank_lines_is_detected() {
    let mut b = b"\n\r\n  \n".to_vec();
    b.extend_from_slice(fixture!("chrome.csv"));
    assert_eq!(detect("x", &b), Some(Format::ChromeCsv));
}

#[test]
fn enpass_like_csv_is_not_dashlane() {
    assert_eq!(detect("x", b"title,password,url\na,b,c\n"), None);
    assert_eq!(detect("x", b"title,note,url,password\na,b,c,d\n"), None);
    assert_eq!(detect("x", b"type,name,number\na,b,c\n"), None);
}

#[test]
fn dashlane_secure_notes_with_category() {
    assert_eq!(
        detect("x", b"title,note,category\na,b,c\n"),
        Some(Format::DashlaneCsv)
    );
}

#[test]
fn encrypted_bitwarden_json_is_detected_and_refused() {
    let b = br#"{"encrypted":true,"passwordProtected":true,"data":"2.xxx"}"#;
    assert_eq!(detect("x", b), Some(Format::BitwardenJson));
    assert!(parse(Format::BitwardenJson, b).is_err());
}

#[test]
fn damaged_zips_do_not_panic() {
    let z = dashlane_zip();
    for cut in [4, 30, z.len() / 2, z.len() - 10, z.len() - 1] {
        let t = &z[..cut];
        let _ = detect("x", t);
        let _ = parse(Format::DashlaneZip, t);
    }
    // Corrupt the central directory (last 100 bytes).
    let mut c = z.clone();
    let n = c.len();
    for b in &mut c[n - 100..] {
        *b ^= 0xA5;
    }
    let _ = detect("x", &c);
    let _ = parse(Format::DashlaneZip, &c);
    let _ = parse(Format::OnePasswordPux, &c);
}

#[test]
fn zip_entries_in_subdirectories() {
    // 1PUX needs `export.data` at the root; a nested one is not detected.
    let nested = zip_of(&[("dir/export.data", fixture!("1pux-export.data.json"))]);
    assert_eq!(detect("x", &nested), None);
    // Dashlane entries are matched by base name.
    let nested = zip_of(&[("dir/credentials.csv", fixture!("dashlane/credentials.csv"))]);
    assert_eq!(detect("x", &nested), Some(Format::DashlaneZip));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn no_panic_on_mutated_fixtures(
        which in 0usize..64,
        cut in any::<prop::sample::Index>(),
        flips in proptest::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 0..8),
    ) {
        let all = cases();
        let (_, bytes, format) = &all[which % all.len()];
        let mut m = bytes.clone();
        for (i, v) in &flips {
            let n = m.len();
            m[i.index(n)] ^= v | 1;
        }
        let truncated = &m[..cut.index(m.len() + 1)];
        for data in [&m[..], truncated] {
            let _ = parse(*format, data);
            let _ = detect("x", data);
            for f in Format::ALL {
                if f != Format::OnePassArchive {
                    let _ = parse(f, data);
                }
            }
        }
    }

    #[test]
    fn no_panic_on_arbitrary_bytes(bytes in proptest::collection::vec(any::<u8>(), 0..4096)) {
        for f in Format::ALL {
            if f != Format::OnePassArchive {
                let _ = parse(f, &bytes);
            }
        }
        let _ = detect("x", &bytes);
    }

    /// Spec 10: the plaintext CSV export reads back through the OnePass
    /// CSV importer with titles, usernames, passwords and URLs intact.
    #[test]
    fn onepass_csv_export_roundtrip(
        logins in proptest::collection::vec(
            ("[A-Za-z0-9][A-Za-z0-9 ,\"']{0,20}[A-Za-z0-9]", "[a-z0-9._@-]{1,20}", "[!-~]{1,32}", "[a-z0-9]{1,12}"),
            1..12,
        ),
    ) {
        let items: Vec<Item> = logins
            .iter()
            .map(|(title, user, pw, host)| login(title, user, pw, &format!("https://{host}.example.com")))
            .collect();
        let vault = ArchivedVault {
            id: Id::new(),
            meta: VaultMeta {
                name: "Perso".into(),
                icon: String::new(),
                color: String::new(),
                travel_safe: false,
                mcp_access: false,
            },
            items: items.clone(),
        };
        let csv = csv_plaintext(&[vault]).unwrap();
        prop_assert_eq!(detect("x", &csv), Some(Format::OnePassCsv));
        let back = parse(Format::OnePassCsv, &csv).unwrap();
        prop_assert_eq!(back.items.len(), items.len());
        for (a, b) in items.iter().zip(&back.items) {
            let b = &b.item;
            prop_assert_eq!(&a.title, &b.title);
            prop_assert_eq!(b.item_type, ItemType::Login);
            prop_assert_eq!(text(a, "username"), text(b, "username"));
            prop_assert_eq!(text(a, "password"), text(b, "password"));
            let urls = |i: &Item| i.urls.iter().map(|u| u.url.clone()).collect::<Vec<_>>();
            prop_assert_eq!(urls(a), urls(b));
        }
    }
}

fn login(title: &str, user: &str, pw: &str, url: &str) -> Item {
    let mut it = new_item(ItemType::Login, Id::new(), title);
    it.urls = vec![ItemUrl {
        label: String::new(),
        url: url.into(),
        rule: MatchRule::Domain,
        primary: true,
    }];
    if let Some(f) = it.field_mut("username") {
        f.value = FieldValue::Text(user.into());
    }
    if let Some(f) = it.field_mut("password") {
        f.value = FieldValue::Password(pw.to_owned().into());
    }
    it
}

fn text(item: &Item, id: &str) -> String {
    match item.field(id).map(|f| &f.value) {
        Some(FieldValue::Text(s)) => s.clone(),
        Some(FieldValue::Password(s)) => s.to_string(),
        _ => String::new(),
    }
}
