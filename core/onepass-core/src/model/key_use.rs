//! Key usage log of an item: which channel touched a secret of it, how,
//! from which device and client, and how often.
//!
//! Privacy: an entry never holds a secret value, a command line, an
//! argument or a file path. `client` is a short application name and
//! `field` a field label, both cut to `MAX_LABEL_CHARS` and stripped of
//! control and bidi-override characters (`sanitize_label`), so a hostile
//! client name cannot spoof the display of the log.
//!
//! Uses coalesce on `(channel, action, device_id, client, field)`: one
//! entry counts the repeats, `first_at` to `last_at`, so a busy agent does
//! not churn the sealed record. The model reads no clock: every function
//! takes `now` (the merge uses the latest `last_at` it sees).
//!
//! Merge: union by coalescing key with the larger `count`, the earlier
//! `first_at` and the later `last_at`. "Clear log" leaves `cleared_at`, a
//! tombstone: an entry no newer than it is dropped wherever it comes from,
//! so a clear survives the union of a sync merge. The merge is
//! commutative and idempotent, its output sorted most recent first.

use std::cmp::Reverse;
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};

use crate::id::Id;
use crate::model::usage::REWRITE_AFTER_SECS;

/// Most entries kept per item: the oldest `last_at` go first.
pub const MAX_KEY_USES: usize = 200;
/// An entry whose `last_at` is older than this is dropped at the next write.
pub const KEY_USE_TTL_DAYS: i64 = 365;
/// Longest device name, client or field label, in characters.
pub const MAX_LABEL_CHARS: usize = 64;

/// Where a use came from. Postcard encodes variants by index: new variants
/// must only ever be appended (pinned by `model::wire_tests`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KeyUseChannel {
    App,
    AutoFill,
    Cli,
    Mcp,
    SshAgent,
}

/// What was done with the secret. Only append, as `KeyUseChannel`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KeyUseAction {
    Revealed,
    Copied,
    Injected,
    Totp,
    Signed,
    Filled,
}

/// One coalesced entry of the log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyUse {
    pub channel: KeyUseChannel,
    pub action: KeyUseAction,
    pub device_id: Id,
    pub device_name: String,
    /// Application name, may be empty.
    pub client: String,
    /// Label of the field touched, empty when the action covers the item.
    pub field: String,
    pub first_at: OffsetDateTime,
    pub last_at: OffsetDateTime,
    /// Saturating.
    pub count: u32,
}

/// A use to record, before it is coalesced into the log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyUseInput {
    pub channel: KeyUseChannel,
    pub action: KeyUseAction,
    pub device_id: Id,
    pub device_name: String,
    pub client: String,
    pub field: String,
}

/// The third trailer of a sealed item, after `UsageTrailer`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyUseTrailer {
    pub entries: Vec<KeyUse>,
    /// Set by "Clear log": an entry with `last_at <= cleared_at` is dropped.
    pub cleared_at: Option<OffsetDateTime>,
}

/// Coalescing key of an entry. Its order is only used to make ties
/// deterministic.
type Key = (u8, u8, Id, String, String);

fn key_of(u: &KeyUse) -> Key {
    (
        u.channel as u8,
        u.action as u8,
        u.device_id,
        u.client.clone(),
        u.field.clone(),
    )
}

fn input_key(u: &KeyUseInput) -> Key {
    (
        u.channel as u8,
        u.action as u8,
        u.device_id,
        sanitize_label(&u.client),
        sanitize_label(&u.field),
    )
}

/// Drop control characters and bidi overrides, trim, keep at most
/// `MAX_LABEL_CHARS` characters (never cutting inside one).
pub fn sanitize_label(s: &str) -> String {
    let kept: String = s
        .chars()
        .filter(|c| {
            !c.is_control()
                && !matches!(
                    c,
                    '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
                )
        })
        .collect();
    kept.trim().chars().take(MAX_LABEL_CHARS).collect()
}

impl KeyUseTrailer {
    /// No entries and no tombstone: nothing to write.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty() && self.cleared_at.is_none()
    }

    /// Record `count` uses of `u`, the latest at `at`. Coalesces into the
    /// entry with the same key (labels sanitized first), clamps `at` and any
    /// stored `last_at` in the future to `now`, then prunes.
    pub fn note(&mut self, u: &KeyUseInput, count: u32, at: OffsetDateTime, now: OffsetDateTime) {
        let at = at.min(now);
        self.clamp(now);
        let k = input_key(u);
        match self.entries.iter_mut().find(|e| key_of(e) == k) {
            Some(e) => {
                e.count = e.count.saturating_add(count);
                e.last_at = e.last_at.max(at);
                e.first_at = e.first_at.min(at);
            }
            None => self.entries.push(KeyUse {
                channel: u.channel,
                action: u.action,
                device_id: u.device_id,
                device_name: sanitize_label(&u.device_name),
                client: k.3,
                field: k.4,
                first_at: at,
                last_at: at,
                count,
            }),
        }
        self.prune(now);
    }

    /// Whether `u` is worth a write: no entry has its key, or the entry's
    /// last use is an hour old (a future `last_at` counts as `now`), so
    /// repeated uses do not churn the sealed record.
    pub fn due(&self, u: &KeyUseInput, now: OffsetDateTime) -> bool {
        let k = input_key(u);
        match self.entries.iter().find(|e| key_of(e) == k) {
            None => true,
            Some(e) => now - e.last_at.min(now) >= Duration::seconds(REWRITE_AFTER_SECS),
        }
    }

    /// Drop entries older than the TTL or at or before `cleared_at`, then
    /// the entries with the oldest `last_at` while over `MAX_KEY_USES`.
    pub fn prune(&mut self, now: OffsetDateTime) {
        let oldest = now - Duration::days(KEY_USE_TTL_DAYS);
        let cleared = self.cleared_at;
        self.entries
            .retain(|e| e.last_at >= oldest && cleared.is_none_or(|c| e.last_at > c));
        if self.entries.len() > MAX_KEY_USES {
            self.entries
                .sort_by_cached_key(|e| Reverse((e.last_at, key_of(e))));
            self.entries.truncate(MAX_KEY_USES);
        }
    }

    /// "Clear log": no entries, a tombstone at `now`.
    pub fn clear(&mut self, now: OffsetDateTime) {
        self.entries.clear();
        self.cleared_at = Some(now);
    }

    /// A clock that ran ahead must not freeze an entry as "recent".
    fn clamp(&mut self, now: OffsetDateTime) {
        for e in &mut self.entries {
            e.last_at = e.last_at.min(now);
            e.first_at = e.first_at.min(e.last_at);
        }
    }
}

/// Merge of two trailers: union by coalescing key (larger `count`, earlier
/// `first_at`, later `last_at`), the later `cleared_at`, then `prune` with
/// the latest `last_at` seen as the clock. Labels are sanitized first: a
/// trailer decoded from another device is untrusted. Commutative and
/// idempotent; the entries come out most recent first.
pub fn merge_key_uses(a: &KeyUseTrailer, b: &KeyUseTrailer) -> KeyUseTrailer {
    let mut by_key: BTreeMap<Key, KeyUse> = BTreeMap::new();
    for u in a.entries.iter().chain(&b.entries) {
        let mut u = u.clone();
        u.client = sanitize_label(&u.client);
        u.field = sanitize_label(&u.field);
        u.device_name = sanitize_label(&u.device_name);
        let u = &u;
        match by_key.get_mut(&key_of(u)) {
            None => {
                by_key.insert(key_of(u), u.clone());
            }
            Some(m) => {
                m.count = m.count.max(u.count);
                m.first_at = m.first_at.min(u.first_at);
                // The name of the later entry, a tie to the larger name.
                if (u.last_at, &u.device_name) > (m.last_at, &m.device_name) {
                    m.device_name = u.device_name.clone();
                }
                m.last_at = m.last_at.max(u.last_at);
            }
        }
    }
    let now = by_key.values().map(|e| e.last_at).max();
    let mut out = KeyUseTrailer {
        entries: by_key.into_values().collect(),
        cleared_at: a.cleared_at.max(b.cleared_at),
    };
    if let Some(now) = now {
        out.prune(now);
    }
    out.entries
        .sort_by_cached_key(|e| (Reverse(e.last_at), key_of(e)));
    out
}

#[cfg(test)]
mod tests {
    use time::macros::datetime;

    use super::*;

    const T: OffsetDateTime = datetime!(2026-11-14 12:00 UTC);

    fn input(field: &str) -> KeyUseInput {
        KeyUseInput {
            channel: KeyUseChannel::Mcp,
            action: KeyUseAction::Revealed,
            device_id: Id([1; 16]),
            device_name: "Mac".into(),
            client: "Claude Code".into(),
            field: field.into(),
        }
    }

    fn secs(n: i64) -> Duration {
        Duration::seconds(n)
    }

    fn entry(field: &str, count: u32, first: OffsetDateTime, last: OffsetDateTime) -> KeyUse {
        KeyUse {
            channel: KeyUseChannel::Mcp,
            action: KeyUseAction::Revealed,
            device_id: Id([1; 16]),
            device_name: "Mac".into(),
            client: "Claude Code".into(),
            field: field.into(),
            first_at: first,
            last_at: last,
            count,
        }
    }

    fn trailer(entries: Vec<KeyUse>) -> KeyUseTrailer {
        KeyUseTrailer {
            entries,
            cleared_at: None,
        }
    }

    #[test]
    fn note_inserts_then_coalesces() {
        let mut t = KeyUseTrailer::default();
        t.note(&input("k"), 1, T, T);
        t.note(&input("k"), 1, T + secs(10), T + secs(10));
        assert_eq!(t.entries.len(), 1);
        assert_eq!(t.entries[0].count, 2);
        assert_eq!(t.entries[0].first_at, T);
        assert_eq!(t.entries[0].last_at, T + secs(10));
    }

    #[test]
    fn note_clamps_a_future_at_to_now() {
        let mut t = KeyUseTrailer::default();
        t.note(&input("k"), 1, T + Duration::days(1), T);
        assert_eq!(t.entries[0].last_at, T);
        assert_eq!(t.entries[0].first_at, T);
        // A bump with a future time clamps too.
        t.note(&input("k"), 1, T + Duration::days(1), T + secs(5));
        assert_eq!(t.entries[0].last_at, T + secs(5));
        assert!(t.due(&input("k"), T + secs(5) + secs(3600)));
    }

    #[test]
    fn different_field_is_another_entry() {
        let mut t = KeyUseTrailer::default();
        t.note(&input("a"), 1, T, T);
        t.note(&input("b"), 1, T, T);
        assert_eq!(t.entries.len(), 2);
    }

    #[test]
    fn due_only_after_an_hour() {
        let mut t = KeyUseTrailer::default();
        let u = input("k");
        t.note(&u, 1, T, T);
        assert!(!t.due(&u, T + secs(3599)));
        assert!(t.due(&u, T + secs(3600)));
        assert!(t.due(&input("other"), T));
    }

    #[test]
    fn future_last_at_is_clamped() {
        let mut t = trailer(vec![entry("k", 1, T, T + Duration::days(1))]);
        let u = input("k");
        assert!(!t.due(&u, T));
        t.note(&u, 1, T, T);
        assert!(t.entries[0].last_at <= T);
        assert!(t.due(&u, T + secs(3600)));
    }

    #[test]
    fn cap_drops_oldest_but_not_the_bumped() {
        let mut t = KeyUseTrailer::default();
        for i in 0..MAX_KEY_USES {
            let at = T + secs(i as i64);
            t.note(&input(&format!("f{i}")), 1, at, at);
        }
        assert_eq!(t.entries.len(), MAX_KEY_USES);
        let now = T + secs(1000);
        t.note(&input("f0"), 1, now, now);
        t.note(&input("new"), 1, now, now);
        assert_eq!(t.entries.len(), MAX_KEY_USES);
        assert!(t.entries.iter().any(|e| e.field == "f0"));
        assert!(t.entries.iter().any(|e| e.field == "new"));
        assert!(!t.entries.iter().any(|e| e.field == "f1"));
    }

    #[test]
    fn ttl_drops_year_old() {
        let mut t = trailer(vec![
            entry("old", 1, T - Duration::days(400), T - Duration::days(366)),
            entry("fresh", 1, T, T),
        ]);
        t.prune(T);
        assert_eq!(t.entries.len(), 1);
        assert_eq!(t.entries[0].field, "fresh");
    }

    #[test]
    fn count_saturates() {
        let mut t = trailer(vec![entry("k", u32::MAX - 1, T, T)]);
        t.note(&input("k"), 5, T, T);
        assert_eq!(t.entries[0].count, u32::MAX);
    }

    #[test]
    fn sanitize_label_strips_and_truncates() {
        assert_eq!(sanitize_label("Cla\u{202E}ude\n"), "Claude");
        assert_eq!(sanitize_label(&"a".repeat(10_000)).chars().count(), 64);
        let e = sanitize_label(&"é".repeat(70));
        assert_eq!(e.chars().count(), 64);
        assert!(std::str::from_utf8(e.as_bytes()).is_ok());
    }

    #[test]
    fn merge_is_union_max_min() {
        let t1 = T;
        let t2 = T + secs(100);
        let a = trailer(vec![entry("k", 3, t2, t2)]);
        let b = trailer(vec![entry("k", 5, t1, t1), entry("l", 1, t1, t1)]);
        let m = merge_key_uses(&a, &b);
        assert_eq!(m.entries.len(), 2);
        let k = m.entries.iter().find(|e| e.field == "k").unwrap();
        assert_eq!((k.count, k.first_at, k.last_at), (5, t1, t2));
        assert!(m.entries.iter().any(|e| e.field == "l"));
    }

    #[test]
    fn merge_sanitizes_untrusted_labels_before_keying() {
        let mut dirty = entry("k", 2, T, T + secs(5));
        dirty.client = "Cla\u{202E}ude".into();
        let mut clean = entry("k", 1, T, T);
        clean.client = "Claude".into();
        for merged in [
            merge_key_uses(&trailer(vec![clean.clone()]), &trailer(vec![dirty.clone()])),
            merge_key_uses(&trailer(vec![dirty]), &trailer(vec![clean])),
        ] {
            assert_eq!(merged.entries.len(), 1);
            assert_eq!(merged.entries[0].client, "Claude");
            assert_eq!(merged.entries[0].count, 2);
        }
    }

    #[test]
    fn merge_is_idempotent_and_commutative() {
        let a = trailer(vec![entry("k", 3, T, T + secs(5)), entry("x", 1, T, T)]);
        let mut b = trailer(vec![entry("k", 5, T - secs(9), T), entry("l", 2, T, T)]);
        b.cleared_at = Some(T - secs(100));
        let ab = merge_key_uses(&a, &b);
        assert_eq!(ab, merge_key_uses(&b, &a));
        assert_eq!(ab, merge_key_uses(&ab, &b));
        assert_eq!(ab, merge_key_uses(&ab, &ab));
    }

    #[test]
    fn clear_is_a_tombstone() {
        let t = T;
        let mut a = KeyUseTrailer::default();
        a.entries.push(entry("early", 1, t, t));
        a.clear(t);
        let b = trailer(vec![
            entry("before", 1, t - secs(50), t - secs(10)),
            entry("after", 1, t + secs(10), t + secs(20)),
        ]);
        let m = merge_key_uses(&a, &b);
        assert_eq!(m.entries.len(), 1);
        assert_eq!(m.entries[0].field, "after");
        assert_eq!(m.cleared_at, Some(t));
    }
}
