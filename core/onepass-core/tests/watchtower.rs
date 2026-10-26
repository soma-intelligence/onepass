//! Breach check by k-anonymity through the public API (spec 3.3).

use std::collections::HashMap;

use onepass_core::Id;
use onepass_core::model::{FieldValue, Item, ItemType, new_item};
use onepass_core::watchtower::{
    Check, DirRangeSource, Options, PwnedStatus, RangeSource, Sources, analyze, parse_range,
};
use time::{Date, Month};
use zeroize::Zeroizing;

const PASSWORD_HASH: &str = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8";
const OTHER_HASH: &str = "7C4A8D09CA3762AF61E59520943DC26494F8941B"; // "123456"

fn login(title: &str, pw: &str) -> Item {
    let mut it = new_item(ItemType::Login, Id([0; 16]), title);
    if let Some(f) = it.field_mut("password") {
        f.value = FieldValue::Password(Zeroizing::new(pw.to_owned()));
    }
    it
}

fn opts() -> Options {
    Options::new(Date::from_calendar_date(2026, Month::October, 25).unwrap())
}

/// Answers from a table and records every prefix received.
struct RecordingSource {
    table: HashMap<String, Result<Vec<u8>, ()>>,
    seen: Vec<String>,
}

impl RecordingSource {
    fn new() -> Self {
        Self {
            table: HashMap::new(),
            seen: Vec::new(),
        }
    }
    fn answer(&mut self, hash: &str, count: u64) {
        let (p, s) = hash.split_at(5);
        self.table
            .insert(p.to_owned(), Ok(format!("{s}:{count}\r\n").into_bytes()));
    }
}

impl RangeSource for RecordingSource {
    fn range(&mut self, prefix: &str) -> onepass_core::Result<Vec<u8>> {
        self.seen.push(prefix.to_owned());
        match self.table.get(prefix) {
            Some(Ok(b)) => Ok(b.clone()),
            _ => Err(onepass_core::Error::NotFound),
        }
    }
}

fn run(items: &[Item], src: &mut RecordingSource) -> onepass_core::watchtower::Report {
    analyze(
        items,
        &opts(),
        Sources {
            pwned: Some(src),
            sites: None,
            breaches: None,
        },
    )
}

#[test]
fn only_prefixes_leave_core() {
    let mut src = RecordingSource::new();
    src.answer(PASSWORD_HASH, 3);
    let items = [login("a", "password"), login("b", "123456")];
    let _ = run(&items, &mut src);
    assert_eq!(src.seen.len(), 2);
    for p in &src.seen {
        assert_eq!(p.len(), 5);
        assert!(
            p.bytes()
                .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b))
        );
        assert!(!p.contains("password"));
        assert!(!PASSWORD_HASH.get(5..).unwrap().contains(p.as_str()));
    }
}

#[test]
fn compromised_found_with_count() {
    let mut src = RecordingSource::new();
    src.answer(PASSWORD_HASH, 9_545_824);
    src.answer(OTHER_HASH, 0);
    let items = [login("a", "password"), login("b", "123456")];
    let r = run(&items, &mut src);
    assert_eq!(r.pwned, PwnedStatus::Checked);
    let found: Vec<_> = r
        .findings
        .iter()
        .filter(|f| f.check == Check::Compromised)
        .collect();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].item_id, items[0].id);
    assert_eq!(found[0].field_id.as_deref(), Some("password"));
    assert_eq!(
        serde_json::to_value(&found[0].detail).unwrap()["count"],
        9_545_824
    );
    assert_eq!(r.counts.get(&Check::Compromised), Some(&1));
}

#[test]
fn one_request_per_prefix() {
    let mut src = RecordingSource::new();
    src.answer(PASSWORD_HASH, 5);
    let items = [login("a", "password"), login("b", "password")];
    let r = run(&items, &mut src);
    assert_eq!(src.seen.len(), 1);
    let n = r
        .findings
        .iter()
        .filter(|f| f.check == Check::Compromised)
        .count();
    assert_eq!(n, 2);
}

#[test]
fn failing_source_gives_partial() {
    let mut src = RecordingSource::new();
    src.answer(PASSWORD_HASH, 5);
    let items = [login("a", "password"), login("b", "123456")];
    let r = run(&items, &mut src);
    assert_eq!(r.pwned, PwnedStatus::Partial { failed_prefixes: 1 });
    assert_eq!(
        r.findings
            .iter()
            .filter(|f| f.check == Check::Compromised)
            .count(),
        1
    );
}

#[test]
fn invalid_body_counts_as_failed_prefix() {
    let mut src = RecordingSource::new();
    src.answer(PASSWORD_HASH, 5);
    src.table
        .insert(OTHER_HASH[..5].to_owned(), Ok(b"garbage".to_vec()));
    let items = [login("a", "password"), login("b", "123456")];
    let r = run(&items, &mut src);
    assert_eq!(r.pwned, PwnedStatus::Partial { failed_prefixes: 1 });
}

#[test]
fn all_failing_gives_unavailable() {
    let mut src = RecordingSource::new();
    let items = [login("a", "password"), login("b", "123456")];
    let r = run(&items, &mut src);
    assert_eq!(r.pwned, PwnedStatus::Unavailable);
    assert!(r.findings.iter().all(|f| f.check != Check::Compromised));
}

#[test]
fn disabled_without_source() {
    let r = analyze(&[login("a", "password")], &opts(), Sources::none());
    assert_eq!(r.pwned, PwnedStatus::Disabled);
}

#[test]
fn no_password_with_source_is_checked() {
    let mut src = RecordingSource::new();
    let r = run(&[], &mut src);
    assert_eq!(r.pwned, PwnedStatus::Checked);
    assert!(src.seen.is_empty());
}

#[test]
fn trashed_and_excluded_items_are_not_sent() {
    let mut src = RecordingSource::new();
    src.answer(PASSWORD_HASH, 5);
    let mut trashed = login("a", "password");
    trashed.trashed_at = Some(time::OffsetDateTime::now_utc());
    let mut excluded = login("b", "123456");
    excluded.watchtower_exclusions.push("compromised".into());
    let r = run(&[trashed, excluded], &mut src);
    assert!(src.seen.is_empty());
    assert_eq!(r.pwned, PwnedStatus::Checked);
}

#[test]
fn dir_source_through_analyze() {
    let dir = tempfile::tempdir().unwrap();
    let (p, s) = PASSWORD_HASH.split_at(5);
    std::fs::write(dir.path().join(format!("{p}.txt")), format!("{s}:42\n")).unwrap();
    let mut src = DirRangeSource::new(dir.path());
    let r = analyze(
        &[login("a", "password")],
        &opts(),
        Sources {
            pwned: Some(&mut src),
            sites: None,
            breaches: None,
        },
    );
    assert_eq!(r.pwned, PwnedStatus::Checked);
    assert_eq!(r.counts.get(&Check::Compromised), Some(&1));
    assert_eq!(parse_range(b"").unwrap().len(), 0);
}

// ---- Site catalogs (spec 3.4) and the checks that use them (spec 3.2) ----

mod sites {
    use onepass_core::Id;
    use onepass_core::model::{
        FieldValue, Item, ItemType, ItemUrl, LoginMethod, MatchRule, PasskeyCredential,
        PasswordHistoryEntry, Provider, new_item,
    };
    use onepass_core::watchtower::{
        BreachCatalog, Check, Detail, Report, Severity, SiteDirectory, Sources, analyze,
    };
    use time::macros::{date, datetime};
    use zeroize::Zeroizing;

    const STRONG: &str = "x7#Qm!vP2$wL9@zR4kT-hN6";

    const TWO_FA: &[u8] = br#"{
        "example.com": { "methods": ["totp", "sms"], "documentation": "https://example.com/help/2fa" },
        "example.org": {},
        "Keys.Example.NET": { "methods": ["u2f"] },
        "bad.example.net": "not an object",
        "worse.example.net": { "methods": "totp" }
    }"#;

    const PASSKEYS: &[u8] = br#"{
        "example.com": { "passwordless": "allowed", "documentation": "https://example.com/help/passkeys" },
        "example.org": { "mfa": "allowed", "documentation": "https://example.org/passkeys" },
        "example.net": { "passwordless": "not-allowed" }
    }"#;

    const HIBP: &[u8] = br#"[
        { "Name": "ExampleOld", "Domain": "example.com", "BreachDate": "2020-03-01", "IsVerified": true },
        { "Name": "ExampleNew", "Domain": "example.com", "BreachDate": "2025-06-15", "IsVerified": true },
        { "Name": "OrgLeak", "Domain": "example.org", "BreachDate": "2025-01-10", "IsVerified": false },
        { "Name": "NoDomain", "Domain": "", "BreachDate": "2025-01-10", "IsVerified": true },
        { "Name": "BadDate", "Domain": "example.net", "BreachDate": "someday", "IsVerified": true },
        "not an object"
    ]"#;

    fn opts() -> onepass_core::watchtower::Options {
        onepass_core::watchtower::Options::new(date!(2026 - 10 - 25))
    }

    fn login(title: &str, pw: &str, site: &str) -> Item {
        let mut it = new_item(ItemType::Login, Id([0; 16]), title);
        it.created_at = datetime!(2026-10-01 0:00 UTC);
        it.updated_at = it.created_at;
        if let Some(f) = it.field_mut("password") {
            f.value = FieldValue::Password(Zeroizing::new(pw.to_owned()));
        }
        if !site.is_empty() {
            it.urls.push(ItemUrl {
                label: String::new(),
                url: site.to_owned(),
                rule: MatchRule::Domain,
                primary: true,
            });
        }
        it
    }

    fn with_totp(mut it: Item) -> Item {
        it.field_mut("totp").unwrap().value = FieldValue::Otp(Zeroizing::new(
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP".into(),
        ));
        it
    }

    fn with_passkey(mut it: Item) -> Item {
        it.field_mut("passkeys").unwrap().value = FieldValue::Passkey(PasskeyCredential {
            rp_id: "example.com".into(),
            user_name: "alice".into(),
            user_handle: vec![1, 2, 3],
            credential_id: vec![4, 5, 6],
            private_key: Zeroizing::new(vec![7; 32]),
            created_at: datetime!(2026-01-01 0:00 UTC),
        });
        it
    }

    fn directory() -> SiteDirectory {
        let mut d = SiteDirectory::from_2fa_directory(TWO_FA).unwrap();
        d.add_passkeys_directory(PASSKEYS).unwrap();
        d
    }

    fn run(items: &[Item], sites: Option<&SiteDirectory>, br: Option<&BreachCatalog>) -> Report {
        analyze(
            items,
            &opts(),
            Sources {
                pwned: None,
                sites,
                breaches: br,
            },
        )
    }

    fn of(r: &Report, c: Check) -> Vec<&onepass_core::watchtower::Finding> {
        r.findings.iter().filter(|f| f.check == c).collect()
    }

    #[test]
    fn two_fa_directory_parse() {
        let d = SiteDirectory::from_2fa_directory(TWO_FA).unwrap();
        // Wrong-typed entries are skipped, not fatal.
        assert_eq!(d.len(), 3);
        assert!(!d.is_empty());
        let com = d.lookup("example.com").unwrap();
        assert!(com.totp && !com.u2f && !com.passkey);
        assert_eq!(
            com.documentation.as_deref(),
            Some("https://example.com/help/2fa")
        );
        let org = d.lookup("example.org").unwrap();
        assert!(!org.totp && !org.u2f && !org.passkey);
        assert_eq!(org.documentation, None);
        // Domains are lower-cased.
        assert!(d.lookup("keys.example.net").unwrap().u2f);
        assert!(d.lookup("bad.example.net").is_none());
        assert!(d.lookup("worse.example.net").is_none());
        assert!(d.lookup("example.invalid").is_none());
        assert!(SiteDirectory::default().is_empty());
        for bad in [&b"[]"[..], b"\"x\"", b"not json", b"42"] {
            assert!(matches!(
                SiteDirectory::from_2fa_directory(bad),
                Err(onepass_core::Error::InvalidFormat(_))
            ));
        }
    }

    #[test]
    fn subdomain_matches_parent() {
        let d = directory();
        assert!(d.lookup("login.example.com").unwrap().totp);
        assert!(d.lookup("a.b.example.com").unwrap().totp);
        assert!(d.lookup("LOGIN.Example.Com").unwrap().totp);
        // The most specific entry wins.
        assert!(d.lookup("x.keys.example.net").unwrap().u2f);
        // Suffix on a label boundary only.
        assert!(d.lookup("notexample.com").is_none());
        assert!(d.lookup("com").is_none());
        let b = BreachCatalog::from_hibp(HIBP).unwrap();
        let found = b.lookup("www.example.com");
        let names: Vec<_> = found.iter().map(|x| x.name.as_str()).collect();
        assert_eq!(names, ["ExampleOld", "ExampleNew"]);
        assert!(b.lookup("evilexample.com").is_empty());
    }

    #[test]
    fn passkeys_merge() {
        let d = directory();
        let com = d.lookup("example.com").unwrap();
        assert!(com.totp && com.passkey);
        // The 2FA documentation wins over the passkeys one.
        assert_eq!(
            com.documentation.as_deref(),
            Some("https://example.com/help/2fa")
        );
        let org = d.lookup("example.org").unwrap();
        assert!(!org.totp && org.passkey);
        assert_eq!(
            org.documentation.as_deref(),
            Some("https://example.org/passkeys")
        );
        let net = d.lookup("example.net").unwrap();
        assert!(!net.passkey && !net.totp);
        assert_eq!(d.len(), 4);
    }

    #[test]
    fn missing_2fa_and_passkey_findings() {
        let d = directory();
        let bare = login("Bare", STRONG, "https://www.example.com/login");
        let secured = with_passkey(with_totp(login("Secured", STRONG, "https://example.com")));
        let org = login("Org", STRONG, "https://example.org");
        let unknown = login("Unknown", STRONG, "https://example.invalid");
        // A non-primary URL host still counts.
        let mut second = login("Second", STRONG, "https://example.invalid");
        second.urls.push(ItemUrl {
            label: String::new(),
            url: "https://app.example.com".into(),
            rule: MatchRule::Domain,
            primary: false,
        });
        let mut excluded = login("Excluded", STRONG, "https://example.com");
        excluded.watchtower_exclusions.push("missing_2fa".into());
        let items = [
            bare.clone(),
            secured,
            org.clone(),
            unknown,
            second.clone(),
            excluded.clone(),
        ];

        let r = run(&items, Some(&d), None);
        assert!(r.sites_checked);
        assert!(!r.breaches_checked);
        let m: Vec<_> = of(&r, Check::Missing2fa);
        let mut ids: Vec<Id> = m.iter().map(|f| f.item_id).collect();
        ids.sort();
        let mut want = vec![bare.id, second.id];
        want.sort();
        assert_eq!(ids, want);
        assert!(m.iter().all(|f| f.severity == Severity::Low));
        assert!(m.iter().all(|f| f.detail
            == Detail::Site {
                documentation: Some("https://example.com/help/2fa".into())
            }));

        let p = of(&r, Check::PasskeyAvailable);
        let mut ids: Vec<Id> = p.iter().map(|f| f.item_id).collect();
        ids.sort();
        let mut want = vec![bare.id, org.id, second.id, excluded.id];
        want.sort();
        assert_eq!(ids, want);
        assert!(p.iter().all(|f| f.severity == Severity::Info));

        // Without the directory the checks do not run.
        let r = run(&items, None, None);
        assert!(!r.sites_checked);
        assert!(of(&r, Check::Missing2fa).is_empty());
        assert!(of(&r, Check::PasskeyAvailable).is_empty());
    }

    #[test]
    fn breach_after_last_change_flagged_before_not() {
        let b = BreachCatalog::from_hibp(HIBP).unwrap();
        // Created 2026-10-01: after both breaches.
        let fresh = login("Fresh", STRONG, "https://example.com");
        // Changed 2024-01-01: after ExampleOld, before ExampleNew.
        let mut stale = login("Stale", STRONG, "https://shop.example.com");
        stale.created_at = datetime!(2019-01-01 0:00 UTC);
        stale.password_history.push(PasswordHistoryEntry {
            value: Zeroizing::new("old one".into()),
            replaced_at: datetime!(2024-01-01 12:00 UTC),
        });
        // Created 2019: before both, the latest breach is reported.
        let mut ancient = login("Ancient", STRONG, "https://example.com");
        ancient.created_at = datetime!(2019-01-01 0:00 UTC);
        // A Password item with a URL is checked too.
        let mut pw_item = new_item(ItemType::Password, Id([0; 16]), "Pw");
        pw_item.created_at = datetime!(2019-01-01 0:00 UTC);
        pw_item.field_mut("password").unwrap().value =
            FieldValue::Password(Zeroizing::new(STRONG.into()));
        pw_item.urls.push(ItemUrl {
            label: String::new(),
            url: "example.com".into(),
            rule: MatchRule::Domain,
            primary: true,
        });
        let items = [
            fresh.clone(),
            stale.clone(),
            ancient.clone(),
            pw_item.clone(),
        ];
        let r = run(&items, None, Some(&b));
        assert!(r.breaches_checked);
        let found = of(&r, Check::BreachedSite);
        assert_eq!(found.len(), 3);
        assert!(found.iter().all(|f| f.item_id != fresh.id));
        for f in &found {
            assert_eq!(f.severity, Severity::High);
            assert_eq!(f.field_id.as_deref(), Some("password"));
            assert_eq!(
                f.detail,
                Detail::Breach {
                    name: "ExampleNew".into(),
                    date: date!(2025 - 06 - 15)
                }
            );
        }
        let json = serde_json::to_value(found[0]).unwrap();
        assert_eq!(json["detail"]["date"], "2025-06-15");
    }

    #[test]
    fn unverified_breach_ignored() {
        let b = BreachCatalog::from_hibp(HIBP).unwrap();
        assert!(b.lookup("example.org").is_empty());
        assert!(b.lookup("example.net").is_empty());
        let mut it = login("Org", STRONG, "https://example.org");
        it.created_at = datetime!(2019-01-01 0:00 UTC);
        let r = run(&[it], None, Some(&b));
        assert!(of(&r, Check::BreachedSite).is_empty());
        for bad in [&b"{}"[..], b"null", b"[", b"7"] {
            assert!(matches!(
                BreachCatalog::from_hibp(bad),
                Err(onepass_core::Error::InvalidFormat(_))
            ));
        }
    }

    #[test]
    fn provider_without_2fa_lists_dependents() {
        let mut google = login("Google", STRONG, "https://accounts.example.com");
        google.field_mut("username").unwrap().value =
            FieldValue::Text("account@example.com".into());
        let mut a = login("App A", "", "https://a.example.org");
        let mut b = login("App B", "", "https://b.example.org");
        for it in [&mut a, &mut b] {
            it.login_methods.push(LoginMethod::Provider {
                provider: Provider::Google,
                account: google.id,
                relay_email: None,
            });
        }
        // A provider account with TOTP and a strong, unique password is fine.
        let safe = with_totp(login(
            "Safe",
            "k9$Lp2@wQ7!zX4#mR8-vN3",
            "https://example.net",
        ));
        let mut c = login("App C", "", "https://c.example.org");
        c.login_methods.push(LoginMethod::Provider {
            provider: Provider::Apple,
            account: safe.id,
            relay_email: Some("relay@example.net".into()),
        });
        let items = [google.clone(), a.clone(), b.clone(), safe.clone(), c];
        let r = run(&items, None, None);
        let p = of(&r, Check::ProviderExposed);
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].item_id, google.id);
        assert_eq!(p[0].severity, Severity::Critical);
        let mut want = vec![a.id, b.id];
        want.sort();
        assert_eq!(
            p[0].detail,
            Detail::Dependents {
                items: want.clone()
            }
        );
        let json = serde_json::to_value(p[0]).unwrap();
        assert_eq!(json["detail"]["items"][0], want[0].to_string());

        // A provider with TOTP but a weak password is still exposed.
        let weak = with_totp(login("Weak provider", "password", "https://example.net"));
        let mut d = login("App D", "", "https://d.example.org");
        d.login_methods.push(LoginMethod::Provider {
            provider: Provider::GitHub,
            account: weak.id,
            relay_email: None,
        });
        let r = run(&[weak.clone(), d.clone()], None, None);
        let p = of(&r, Check::ProviderExposed);
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].detail, Detail::Dependents { items: vec![d.id] });
    }

    #[test]
    fn oversized_directory_rejected() {
        let big = vec![b' '; 16 * 1024 * 1024 + 1];
        assert!(matches!(
            SiteDirectory::from_2fa_directory(&big),
            Err(onepass_core::Error::InvalidFormat(_))
        ));
        let mut d = SiteDirectory::default();
        assert!(matches!(
            d.add_passkeys_directory(&big),
            Err(onepass_core::Error::InvalidFormat(_))
        ));
        assert!(matches!(
            BreachCatalog::from_hibp(&big),
            Err(onepass_core::Error::InvalidFormat(_))
        ));
        // 100 001 entries, well under the byte cap.
        let mut many = String::from("{");
        for i in 0..100_001 {
            if i > 0 {
                many.push(',');
            }
            many.push_str(&format!("\"d{i}.example.com\":{{}}"));
        }
        many.push('}');
        assert!(many.len() < 16 * 1024 * 1024);
        assert!(matches!(
            SiteDirectory::from_2fa_directory(many.as_bytes()),
            Err(onepass_core::Error::InvalidFormat(_))
        ));
        let mut arr = String::from("[");
        for i in 0..100_001 {
            if i > 0 {
                arr.push(',');
            }
            arr.push_str("{}");
        }
        arr.push(']');
        assert!(matches!(
            BreachCatalog::from_hibp(arr.as_bytes()),
            Err(onepass_core::Error::InvalidFormat(_))
        ));
        // Over-long domains are skipped.
        let long = format!("{{\"{}.com\":{{\"methods\":[\"totp\"]}}}}", "a".repeat(250));
        assert!(
            SiteDirectory::from_2fa_directory(long.as_bytes())
                .unwrap()
                .is_empty()
        );
    }
}
