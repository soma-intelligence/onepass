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
