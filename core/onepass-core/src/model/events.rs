//! Timeline of an item: what happened to it, never a value.
//!
//! Events live inside the sealed item record, so they sync and stay
//! encrypted with the item. They name a field by its label, a website by its
//! host, a vault by its name, a passkey by its relying party: never a secret,
//! never a field value.
//!
//! Wire format: `Item` skips `events` in its own serde form (an older record
//! decodes unchanged). `vault::encode_item` writes them after `(version,
//! item)` as an `ItemTrailer` when there is at least one, and
//! `vault::open_item` reads that trailer when bytes remain. A later
//! extension appends a second trailer after this one, never a field here.
//! A trailer a build cannot read opens the item without events: history
//! never locks an item out. An older build that then saves the item drops
//! the history it could not read.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::model::field::{FieldType, FieldValue, Section};
use crate::model::item::Item;
use crate::watchtower::host::host_of;

/// Most events kept per item: older ones are dropped first.
pub const MAX_EVENTS: usize = 200;

/// What happened. Postcard encodes variants by index: new variants must only
/// ever be appended at the end, never inserted or reordered (pinned by
/// `model::wire_tests`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventKind {
    Created,
    FieldAdded { label: String },
    FieldRemoved { label: String },
    FieldChanged { label: String },
    PasswordChanged,
    TitleChanged,
    WebsiteAdded { host: String },
    WebsiteRemoved { host: String },
    Moved { from: String, to: String },
    Favorited,
    Unfavorited,
    Archived,
    Unarchived,
    Trashed,
    Restored,
    Imported { format: String },
    PasskeyAdded { rp_id: String },
    PasskeyRemoved { rp_id: String },
    AttachmentAdded { name: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemEvent {
    pub at: OffsetDateTime,
    pub kind: EventKind,
}

/// The bytes after `(version, item)` in a sealed item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemTrailer {
    pub events: Vec<ItemEvent>,
}

impl Item {
    /// Append an event, dropping the oldest beyond `MAX_EVENTS`.
    pub fn record(&mut self, at: OffsetDateTime, kind: EventKind) {
        self.events.push(ItemEvent { at, kind });
        if self.events.len() > MAX_EVENTS {
            let extra = self.events.len() - MAX_EVENTS;
            self.events.drain(..extra);
        }
    }
}

fn is_blank(v: &FieldValue) -> bool {
    match v {
        FieldValue::Empty => true,
        FieldValue::Text(s)
        | FieldValue::Url(s)
        | FieldValue::Email(s)
        | FieldValue::Phone(s)
        | FieldValue::Menu(s) => s.trim().is_empty(),
        FieldValue::Concealed(s)
        | FieldValue::Password(s)
        | FieldValue::Otp(s)
        | FieldValue::Mnemonic(s) => s.is_empty(),
        FieldValue::Barcode { value, .. } => value.is_empty(),
        _ => false,
    }
}

/// Every non-blank field, keyed by section id and field id, in order.
fn filled(sections: &[Section]) -> Vec<(&str, &str, &str, FieldType, &FieldValue)> {
    sections
        .iter()
        .flat_map(|s| {
            s.fields
                .iter()
                .filter(|f| !is_blank(&f.value))
                .map(move |f| {
                    (
                        s.id.as_str(),
                        f.id.as_str(),
                        f.label.as_str(),
                        f.kind,
                        &f.value,
                    )
                })
        })
        .collect()
}

/// Host of a website, `None` when the URL has none (the raw text could hold
/// credentials, so it is never recorded).
fn site(url: &str) -> Option<String> {
    host_of(url)
}

/// Record on `new` what an edit changed since `old` (`None`: a new item,
/// recorded as `Created`). Compares fields by section and field id; a
/// password field change is `PasswordChanged`, a passkey or file field adds
/// or removes a passkey or an attachment. Values are compared, never copied.
pub fn record_edit(old: Option<&Item>, new: &mut Item, now: OffsetDateTime) {
    let Some(old) = old else {
        new.record(now, EventKind::Created);
        return;
    };
    let mut out = Vec::new();
    if old.title != new.title {
        out.push(EventKind::TitleChanged);
    }
    let (before, after) = (filled(&old.sections), filled(&new.sections));
    let find = |list: &[(&str, &str, &str, FieldType, &FieldValue)], s: &str, f: &str| {
        list.iter().position(|x| x.0 == s && x.1 == f)
    };
    for &(s, f, label, kind, value) in &after {
        let label = label.to_owned();
        match find(&before, s, f).map(|i| before[i].4) {
            Some(prev) if prev == value => {}
            Some(prev) => out.push(match (kind, prev, value) {
                (FieldType::Password, ..) => EventKind::PasswordChanged,
                (_, FieldValue::Passkey(a), FieldValue::Passkey(b))
                    if a.credential_id != b.credential_id =>
                {
                    EventKind::PasskeyAdded {
                        rp_id: b.rp_id.clone(),
                    }
                }
                _ => EventKind::FieldChanged { label },
            }),
            None => out.push(match value {
                FieldValue::Passkey(p) => EventKind::PasskeyAdded {
                    rp_id: p.rp_id.clone(),
                },
                FieldValue::File(a) => EventKind::AttachmentAdded {
                    name: a.name.clone(),
                },
                FieldValue::Password(_) if old.item_type == new.item_type => {
                    EventKind::PasswordChanged
                }
                _ => EventKind::FieldAdded { label },
            }),
        }
    }
    for &(s, f, label, _, value) in &before {
        if find(&after, s, f).is_none() {
            out.push(match value {
                FieldValue::Passkey(p) => EventKind::PasskeyRemoved {
                    rp_id: p.rp_id.clone(),
                },
                _ => EventKind::FieldRemoved {
                    label: label.to_owned(),
                },
            });
        }
    }
    let hosts = |i: &Item| {
        i.urls
            .iter()
            .filter_map(|u| site(&u.url))
            .collect::<Vec<_>>()
    };
    let (old_hosts, new_hosts) = (hosts(old), hosts(new));
    for h in new_hosts.iter().filter(|h| !old_hosts.contains(h)) {
        out.push(EventKind::WebsiteAdded { host: h.clone() });
    }
    for h in old_hosts.iter().filter(|h| !new_hosts.contains(h)) {
        out.push(EventKind::WebsiteRemoved { host: h.clone() });
    }
    if old.notes != new.notes {
        out.push(EventKind::FieldChanged {
            label: "notes".to_owned(),
        });
    }
    if old.tags != new.tags {
        out.push(EventKind::FieldChanged {
            label: "tags".to_owned(),
        });
    }
    for a in new
        .attachments
        .iter()
        .filter(|a| !old.attachments.iter().any(|o| o.id == a.id))
    {
        out.push(EventKind::AttachmentAdded {
            name: a.name.clone(),
        });
    }
    match (old.favorite, new.favorite) {
        (false, true) => out.push(EventKind::Favorited),
        (true, false) => out.push(EventKind::Unfavorited),
        _ => {}
    }
    match (old.archived, new.archived) {
        (false, true) => out.push(EventKind::Archived),
        (true, false) => out.push(EventKind::Unarchived),
        _ => {}
    }
    match (old.trashed_at.is_some(), new.trashed_at.is_some()) {
        (false, true) => out.push(EventKind::Trashed),
        (true, false) => out.push(EventKind::Restored),
        _ => {}
    }
    for kind in out {
        new.record(now, kind);
    }
}

/// Kind of a timeline row, including the ones synthesized for items saved
/// before events existed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimelineKind {
    Event(EventKind),
    /// Synthesized from `updated_at` when nothing else explains it.
    Modified,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimelineEntry {
    pub at: OffsetDateTime,
    pub kind: TimelineKind,
}

/// The item's timeline, newest first. Stored events, plus for an item
/// older than its events: `Created` at `created_at` when no creation or
/// import is recorded, a `PasswordChanged` per previous password replaced
/// before the first recorded event, and `Modified` at `updated_at` when the
/// item has no event at all and was changed after its creation.
pub fn timeline(item: &Item) -> Vec<TimelineEntry> {
    let mut out: Vec<TimelineEntry> = item
        .events
        .iter()
        .map(|e| TimelineEntry {
            at: e.at,
            kind: TimelineKind::Event(e.kind.clone()),
        })
        .collect();
    let first = item.events.iter().map(|e| e.at).min();
    let born = item
        .events
        .iter()
        .any(|e| matches!(e.kind, EventKind::Created | EventKind::Imported { .. }));
    if !born {
        out.push(TimelineEntry {
            at: item.created_at,
            kind: TimelineKind::Event(EventKind::Created),
        });
    }
    for h in &item.password_history {
        if first.is_none_or(|f| h.replaced_at < f) {
            out.push(TimelineEntry {
                at: h.replaced_at,
                kind: TimelineKind::Event(EventKind::PasswordChanged),
            });
        }
    }
    if item.events.is_empty()
        && item.updated_at > item.created_at + time::Duration::seconds(1)
        && !item
            .password_history
            .iter()
            .any(|h| h.replaced_at == item.updated_at)
    {
        out.push(TimelineEntry {
            at: item.updated_at,
            kind: TimelineKind::Modified,
        });
    }
    // Newest first; equal times keep the recording order reversed.
    out.reverse();
    out.sort_by_key(|e| std::cmp::Reverse(e.at));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Id;
    use crate::model::{ItemType, ItemUrl, MatchRule, PasswordHistoryEntry, new_item};
    use time::macros::datetime;
    use zeroize::Zeroizing;

    const T0: OffsetDateTime = datetime!(2026-10-01 08:00 UTC);
    const T1: OffsetDateTime = datetime!(2026-10-02 08:00 UTC);

    fn login() -> Item {
        let mut i = new_item(ItemType::Login, Id::new(), "GitHub");
        i.created_at = T0;
        i.updated_at = T0;
        i
    }

    fn set(item: &mut Item, id: &str, v: FieldValue) {
        item.field_mut(id).unwrap().value = v;
    }

    fn kinds(item: &Item) -> Vec<EventKind> {
        item.events.iter().map(|e| e.kind.clone()).collect()
    }

    #[test]
    fn new_item_is_created() {
        let mut i = login();
        record_edit(None, &mut i, T0);
        assert_eq!(kinds(&i), [EventKind::Created]);
    }

    #[test]
    fn edit_records_labels_never_values() {
        let mut old = login();
        set(&mut old, "username", FieldValue::Text("alice".into()));
        set(
            &mut old,
            "password",
            FieldValue::Password(Zeroizing::new("hunter2".into())),
        );
        let mut new = old.clone();
        new.title = "GitHub perso".into();
        set(&mut new, "username", FieldValue::Text("bob".into()));
        set(
            &mut new,
            "password",
            FieldValue::Password(Zeroizing::new("s3cret-new".into())),
        );
        set(
            &mut new,
            "email",
            FieldValue::Email("bob@example.com".into()),
        );
        new.urls.push(ItemUrl {
            label: String::new(),
            url: "https://github.com/login".into(),
            rule: MatchRule::Domain,
            primary: true,
        });
        new.favorite = true;
        record_edit(Some(&old), &mut new, T1);
        assert_eq!(
            kinds(&new),
            [
                EventKind::TitleChanged,
                EventKind::FieldChanged {
                    label: "Identifiant".into()
                },
                EventKind::PasswordChanged,
                EventKind::FieldAdded {
                    label: "Email".into()
                },
                EventKind::WebsiteAdded {
                    host: "github.com".into()
                },
                EventKind::Favorited,
            ]
        );
        let dump = format!("{:?}", new.events);
        for secret in ["hunter2", "s3cret-new", "alice", "bob@example.com"] {
            assert!(!dump.contains(secret), "{secret}");
        }
    }

    #[test]
    fn removed_field_and_website() {
        let mut old = login();
        set(&mut old, "username", FieldValue::Text("alice".into()));
        old.urls.push(ItemUrl {
            label: String::new(),
            url: "https://example.com".into(),
            rule: MatchRule::Domain,
            primary: true,
        });
        let mut new = old.clone();
        set(&mut new, "username", FieldValue::Empty);
        new.urls.clear();
        record_edit(Some(&old), &mut new, T1);
        assert_eq!(
            kinds(&new),
            [
                EventKind::FieldRemoved {
                    label: "Identifiant".into()
                },
                EventKind::WebsiteRemoved {
                    host: "example.com".into()
                },
            ]
        );
    }

    #[test]
    fn unchanged_edit_records_nothing() {
        let old = login();
        let mut new = old.clone();
        record_edit(Some(&old), &mut new, T1);
        assert!(new.events.is_empty());
    }

    #[test]
    fn events_are_capped() {
        let mut i = login();
        for _ in 0..MAX_EVENTS + 5 {
            i.record(T1, EventKind::Favorited);
        }
        i.record(T1, EventKind::Archived);
        assert_eq!(i.events.len(), MAX_EVENTS);
        assert_eq!(i.events.last().unwrap().kind, EventKind::Archived);
    }

    #[test]
    fn timeline_of_an_item_without_events_is_synthesized() {
        let mut i = login();
        i.password_history.push(PasswordHistoryEntry {
            value: Zeroizing::new("old".into()),
            replaced_at: datetime!(2026-10-05 08:00 UTC),
        });
        i.updated_at = datetime!(2026-10-09 08:00 UTC);
        let t = timeline(&i);
        assert_eq!(
            t.iter().map(|e| (e.at, e.kind.clone())).collect::<Vec<_>>(),
            [
                (i.updated_at, TimelineKind::Modified),
                (
                    datetime!(2026-10-05 08:00 UTC),
                    TimelineKind::Event(EventKind::PasswordChanged)
                ),
                (T0, TimelineKind::Event(EventKind::Created)),
            ]
        );
    }

    #[test]
    fn timeline_uses_recorded_events_newest_first() {
        let mut i = login();
        record_edit(None, &mut i, T0);
        i.record(T1, EventKind::Archived);
        i.updated_at = T1;
        let t = timeline(&i);
        assert_eq!(t.len(), 2);
        assert_eq!(t[0].kind, TimelineKind::Event(EventKind::Archived));
        assert_eq!(t[1].kind, TimelineKind::Event(EventKind::Created));
    }
}

/// Golden encodings of the stored event kinds (see `model::wire_tests`).
#[cfg(test)]
mod wire_tests {
    use super::*;

    #[test]
    fn event_kind_indexes() {
        let s = String::new;
        let kinds = [
            EventKind::Created,
            EventKind::FieldAdded { label: s() },
            EventKind::FieldRemoved { label: s() },
            EventKind::FieldChanged { label: s() },
            EventKind::PasswordChanged,
            EventKind::TitleChanged,
            EventKind::WebsiteAdded { host: s() },
            EventKind::WebsiteRemoved { host: s() },
            EventKind::Moved { from: s(), to: s() },
            EventKind::Favorited,
            EventKind::Unfavorited,
            EventKind::Archived,
            EventKind::Unarchived,
            EventKind::Trashed,
            EventKind::Restored,
            EventKind::Imported { format: s() },
            EventKind::PasskeyAdded { rp_id: s() },
            EventKind::PasskeyRemoved { rp_id: s() },
            EventKind::AttachmentAdded { name: s() },
        ];
        for (i, k) in kinds.iter().enumerate() {
            assert_eq!(
                usize::from(postcard::to_allocvec(k).unwrap()[0]),
                i,
                "{k:?}"
            );
        }
    }

    #[test]
    fn trailer_golden_bytes() {
        let t = ItemTrailer {
            events: vec![ItemEvent {
                at: OffsetDateTime::UNIX_EPOCH,
                kind: EventKind::Favorited,
            }],
        };
        let bytes = postcard::to_allocvec(&t).unwrap();
        // One event, then the time as written by `time`'s serde form, then
        // the variant index of `Favorited`.
        assert_eq!(bytes[0], 1);
        assert_eq!(*bytes.last().unwrap(), 9);
        assert_eq!(postcard::from_bytes::<ItemTrailer>(&bytes).unwrap(), t);
    }
}
