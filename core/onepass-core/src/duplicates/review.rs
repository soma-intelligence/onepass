//! What differs between the copies of a group, line by line, and how sure
//! the merge can be (spec 2026-11-08-duplicates-review).
//!
//! A line is shown only when the copies differ. Each line is one of:
//!
//! - `Added`: one copy brings something the others lack (a field filled on
//!   one side only, a website, a tag, a file, a passkey), or one note holds
//!   the others. The merge keeps it, nothing to ask.
//! - `Kept`: the copies differ but one value wins without a question: the
//!   title of the primary, or the only password that no copy keeps in its
//!   history (the others are older passwords saved again).
//! - `Conflict`: two copies hold different values for the same thing (a
//!   password, a username, a TOTP secret, a number, two different notes).
//!   The user answers which one is right.
//!
//! A group without any conflict is `Sure`: it can be merged in a batch with
//! the default choices. Otherwise it is `Review`.

use std::collections::BTreeSet;

use super::{Aspect, is_blank, password_of, same_value, visible_tags};
use crate::id::Id;
use crate::model::{Field, FieldValue, Item};
use crate::watchtower::host::host_of;

/// Subject of the title line.
pub const TITLE: &str = "title";
/// Subject of the notes line.
pub const NOTES: &str = "notes";
/// Subject of the password line (the `password` field).
pub const PASSWORD: &str = "password";

/// How sure the merge of a group can be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
    /// Same item, the copies only add to one another: merge in a batch.
    Sure,
    /// At least one conflict to answer.
    Review,
}

/// What a line of the review is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RowKind {
    Added,
    Kept,
    Conflict,
}

/// One line where the copies differ.
#[derive(Debug, Clone, PartialEq)]
pub struct Row {
    pub aspect: Aspect,
    /// What a choice names: `title`, `notes`, `password` or a field id.
    /// Empty for a list (websites, passkeys, files, tags): a list is always
    /// the union, nothing to choose.
    pub subject: String,
    /// The field's label (template label or the user's), empty otherwise.
    pub label: String,
    pub kind: RowKind,
    /// One per copy, in the order given to `review`; `None` when that copy
    /// has nothing for this line. A list is one text, one entry per line.
    pub values: Vec<Option<FieldValue>>,
    /// The value is a secret (password, concealed, TOTP, recovery phrase):
    /// shown masked.
    pub concealed: bool,
    /// Index of the copy whose value the merge keeps by default; `None` for
    /// a list and for two different notes (both kept by default).
    pub winner: Option<usize>,
}

/// The review of one group.
#[derive(Debug, Clone, PartialEq)]
pub struct Review {
    pub confidence: Confidence,
    pub rows: Vec<Row>,
}

/// One answer for `merge_with`: the value of `subject` comes from the copy
/// `from`. `from: None` on `notes` keeps every note (the default merge).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Choice {
    pub subject: String,
    pub from: Option<Id>,
}

impl Review {
    /// The default answers of every line that has a winner, for `copies`
    /// as given to `review`.
    pub fn choices(&self, copies: &[&Item]) -> Vec<Choice> {
        self.rows
            .iter()
            .filter(|r| !r.subject.is_empty())
            .filter_map(|r| {
                let i = r.winner?;
                Some(Choice {
                    subject: r.subject.clone(),
                    from: Some(copies.get(i)?.id),
                })
            })
            .collect()
    }
}

fn concealed(v: &FieldValue) -> bool {
    matches!(
        v,
        FieldValue::Concealed(_)
            | FieldValue::Password(_)
            | FieldValue::Otp(_)
            | FieldValue::Mnemonic(_)
    )
}

/// Index of the most recently edited copy among `holders`.
fn most_recent(copies: &[&Item], holders: impl IntoIterator<Item = usize>) -> Option<usize> {
    holders
        .into_iter()
        .filter_map(|i| copies.get(i).map(|c| (c.updated_at, i)))
        .max_by(|a, b| a.0.cmp(&b.0).then_with(|| b.1.cmp(&a.1)))
        .map(|(_, i)| i)
}

/// Two values of one field are the same: usernames ignore case and spaces.
fn same_field_value(id: &str, a: &FieldValue, b: &FieldValue) -> bool {
    match (id, a, b) {
        ("username" | "email" | "address", FieldValue::Text(x), FieldValue::Text(y))
        | ("username" | "email" | "address", FieldValue::Email(x), FieldValue::Email(y))
        | ("username" | "email" | "address", FieldValue::Text(x), FieldValue::Email(y))
        | ("username" | "email" | "address", FieldValue::Email(x), FieldValue::Text(y)) => {
            x.trim().to_lowercase() == y.trim().to_lowercase()
        }
        _ => same_value(a, b),
    }
}

/// The distinct values among `vals` (first spelling kept).
fn distinct<'a>(id: &str, vals: &[Option<&'a FieldValue>]) -> Vec<&'a FieldValue> {
    let mut out: Vec<&FieldValue> = Vec::new();
    for v in vals.iter().flatten() {
        if !out.iter().any(|o| same_field_value(id, o, v)) {
            out.push(v);
        }
    }
    out
}

/// A value line: `Added` when only some copies have it, `Conflict` when
/// they disagree, nothing when they all hold the same.
fn value_row(
    copies: &[&Item],
    aspect: Aspect,
    subject: &str,
    label: &str,
    vals: &[Option<&FieldValue>],
) -> Option<Row> {
    let d = distinct(subject, vals);
    let holders = || vals.iter().enumerate().filter(|(_, v)| v.is_some()).map(|(i, _)| i);
    let (kind, winner) = match d.len() {
        0 => return None,
        1 if vals.iter().all(Option::is_some) => return None,
        1 => (RowKind::Added, holders().next()),
        _ => (RowKind::Conflict, most_recent(copies, holders())),
    };
    Some(Row {
        aspect,
        subject: subject.to_owned(),
        label: label.to_owned(),
        kind,
        values: vals.iter().map(|v| v.cloned()).collect(),
        concealed: d.iter().any(|v| concealed(v)),
        winner,
    })
}

/// The password line. A password that some copy keeps in its history is
/// an older one: when only one password is in no history, it wins.
fn password_row(copies: &[&Item]) -> Option<Row> {
    let fields: Vec<Option<&FieldValue>> = copies
        .iter()
        .map(|c| {
            c.sections
                .iter()
                .flat_map(|s| s.fields.iter())
                .find(|f| f.id == PASSWORD && matches!(&f.value, FieldValue::Password(p) if !p.is_empty()))
                .map(|f| &f.value)
        })
        .collect();
    let mut row = value_row(copies, Aspect::Password, PASSWORD, "", &fields)?;
    if row.kind == RowKind::Conflict {
        let old = |v: &str| {
            copies
                .iter()
                .any(|c| c.password_history.iter().any(|h| h.value.as_str() == v))
        };
        let current: BTreeSet<&str> = copies
            .iter()
            .filter_map(|c| password_of(c))
            .filter(|v| !old(v))
            .collect();
        if current.len() == 1 {
            let holders = copies
                .iter()
                .enumerate()
                .filter(|(_, c)| password_of(c).is_some_and(|p| current.contains(p)))
                .map(|(i, _)| i);
            row.kind = RowKind::Kept;
            row.winner = most_recent(copies, holders);
        }
    }
    Some(row)
}

fn field_aspect(f: &Field) -> Aspect {
    match (&f.value, f.id.as_str()) {
        (FieldValue::Otp(_), _) => Aspect::Totp,
        (_, "username" | "email" | "address") => Aspect::Username,
        _ => Aspect::Fields,
    }
}

/// The filled fields of `item` with that id.
fn fields_of<'a>(item: &'a Item, id: &str) -> Vec<&'a Field> {
    item.sections
        .iter()
        .flat_map(|s| s.fields.iter())
        .filter(|f| f.id == id && !is_blank(&f.value))
        .collect()
}

/// The distinct values of `fields`.
fn value_set<'a>(fields: &[&'a Field]) -> Vec<&'a FieldValue> {
    let mut out: Vec<&FieldValue> = Vec::new();
    for f in fields {
        if !out.iter().any(|o| same_value(o, &f.value)) {
            out.push(&f.value);
        }
    }
    out
}

/// Every field line but the password, passkeys and files, in the order the
/// fields first appear (the primary's first).
fn field_rows(copies: &[&Item], rows: &mut Vec<Row>) {
    let mut ids: Vec<&str> = Vec::new();
    for c in copies {
        for f in c.sections.iter().flat_map(|s| s.fields.iter()) {
            let skip = f.id == PASSWORD
                || is_blank(&f.value)
                || matches!(f.value, FieldValue::Passkey(_) | FieldValue::File(_));
            if !skip && !ids.contains(&f.id.as_str()) {
                ids.push(&f.id);
            }
        }
    }
    for id in ids {
        let per: Vec<Vec<&Field>> = copies.iter().map(|c| fields_of(c, id)).collect();
        let Some(first) = per.iter().flatten().next().copied() else {
            continue;
        };
        if per.iter().flatten().any(|f| f.repeatable) {
            // A repeatable field (backup codes): the merge keeps every value.
            let sets: Vec<Vec<&FieldValue>> = per.iter().map(|fs| value_set(fs)).collect();
            let all: Vec<&FieldValue> = sets.iter().flatten().copied().collect();
            let same = sets
                .iter()
                .all(|s| s.len() == sets.first().map_or(0, Vec::len) && all.iter().all(|v| s.iter().any(|x| same_value(x, v))));
            if !same {
                rows.push(Row {
                    aspect: field_aspect(first),
                    subject: String::new(),
                    label: first.label.clone(),
                    kind: RowKind::Added,
                    values: sets.iter().map(|s| s.first().map(|v| (*v).clone())).collect(),
                    concealed: concealed(&first.value),
                    winner: None,
                });
            }
            continue;
        }
        let vals: Vec<Option<&FieldValue>> = per.iter().map(|fs| fs.first().map(|f| &f.value)).collect();
        if let Some(row) = value_row(copies, field_aspect(first), id, &first.label, &vals) {
            rows.push(row);
        }
    }
}

/// A list line (websites, passkeys, files, tags): the union is kept, so a
/// difference is only ever an addition.
fn list_row(copies: &[&Item], aspect: Aspect, of: impl Fn(&Item) -> BTreeSet<String>) -> Option<Row> {
    let sets: Vec<BTreeSet<String>> = copies.iter().map(|c| of(c)).collect();
    let first = sets.first()?;
    if sets.iter().all(|s| s == first) {
        return None;
    }
    Some(Row {
        aspect,
        subject: String::new(),
        label: String::new(),
        kind: RowKind::Added,
        values: sets
            .iter()
            .map(|s| {
                (!s.is_empty()).then(|| FieldValue::Text(s.iter().cloned().collect::<Vec<_>>().join("\n")))
            })
            .collect(),
        concealed: false,
        winner: None,
    })
}

/// The notes line: one note, or one that holds all the others, is an
/// addition; two notes that each say something else are a conflict, both
/// kept by default.
fn notes_row(copies: &[&Item]) -> Option<Row> {
    let notes: Vec<Option<&str>> = copies
        .iter()
        .map(|c| Some(c.notes.trim()).filter(|n| !n.is_empty()))
        .collect();
    let mut d: Vec<&str> = Vec::new();
    for n in notes.iter().flatten() {
        if !d.contains(n) {
            d.push(n);
        }
    }
    let values = notes
        .iter()
        .map(|n| n.map(|n| FieldValue::Text(n.to_owned())))
        .collect();
    let row = |kind, winner| Row {
        aspect: Aspect::Notes,
        subject: NOTES.to_owned(),
        label: String::new(),
        kind,
        values,
        concealed: false,
        winner,
    };
    if d.is_empty() || (d.len() == 1 && notes.iter().all(Option::is_some)) {
        return None;
    }
    let holder = |n: &str| notes.iter().position(|x| *x == Some(n));
    if d.len() == 1 {
        return Some(row(RowKind::Added, d.first().and_then(|n| holder(n))));
    }
    let whole = d.iter().find(|n| d.iter().all(|o| n.contains(o)));
    match whole {
        Some(n) => Some(row(RowKind::Added, holder(n))),
        None => Some(row(RowKind::Conflict, None)),
    }
}

fn hosts(item: &Item) -> BTreeSet<String> {
    item.urls
        .iter()
        .filter_map(|u| {
            let u = u.url.trim();
            (!u.is_empty()).then(|| host_of(u).unwrap_or_else(|| u.to_owned()))
        })
        .collect()
}

/// What differs between `copies` (the primary first), and how sure a merge
/// of them can be.
pub fn review(copies: &[&Item]) -> Review {
    let mut rows = Vec::new();
    if let Some(primary) = copies.first() {
        let t = primary.title.trim().to_lowercase();
        if copies.iter().any(|c| c.title.trim().to_lowercase() != t) {
            rows.push(Row {
                aspect: Aspect::Title,
                subject: TITLE.to_owned(),
                label: String::new(),
                kind: RowKind::Kept,
                values: copies
                    .iter()
                    .map(|c| Some(FieldValue::Text(c.title.trim().to_owned())))
                    .collect(),
                concealed: false,
                winner: Some(0),
            });
        }
    }
    rows.extend(password_row(copies));
    field_rows(copies, &mut rows);
    // The password sits right after the username, as in the item.
    if let (Some(pw), Some(user)) = (
        rows.iter().position(|r| r.aspect == Aspect::Password),
        rows.iter().position(|r| r.aspect == Aspect::Username),
    ) && user > pw
    {
        let r = rows.remove(user);
        rows.insert(pw, r);
    }
    rows.extend(list_row(copies, Aspect::Websites, hosts));
    rows.extend(list_row(copies, Aspect::Passkeys, |i| {
        i.sections
            .iter()
            .flat_map(|s| s.fields.iter())
            .filter_map(|f| match &f.value {
                FieldValue::Passkey(p) => Some(format!("{} ({})", p.rp_id, p.user_name)),
                _ => None,
            })
            .collect()
    }));
    rows.extend(notes_row(copies));
    rows.extend(list_row(copies, Aspect::Attachments, |i| {
        i.attachments.iter().map(|a| a.name.clone()).collect()
    }));
    rows.extend(list_row(copies, Aspect::Tags, |i| {
        visible_tags(i).into_iter().map(str::to_owned).collect()
    }));
    let confidence = if rows.iter().any(|r| r.kind == RowKind::Conflict) {
        Confidence::Review
    } else {
        Confidence::Sure
    };
    Review { confidence, rows }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::duplicates::{MERGED_SECTION_ID, merge_with};
    use crate::model::{ItemType, ItemUrl, MatchRule, PasswordHistoryEntry, new_item};
    use time::macros::datetime;
    use zeroize::Zeroizing;

    fn login(title: &str, user: &str, pw: &str, site: &str) -> Item {
        let mut i = new_item(ItemType::Login, Id([1; 16]), title);
        i.id = Id::new();
        set(&mut i, "username", FieldValue::Text(user.into()));
        set(&mut i, PASSWORD, FieldValue::Password(Zeroizing::new(pw.into())));
        if !site.is_empty() {
            i.urls.push(ItemUrl {
                label: String::new(),
                url: site.into(),
                rule: MatchRule::Domain,
                primary: true,
            });
        }
        i.updated_at = datetime!(2026-01-01 0:00 UTC);
        i
    }

    fn set(item: &mut Item, id: &str, v: FieldValue) {
        item.field_mut(id).unwrap().value = v;
    }

    fn otp(s: &str) -> FieldValue {
        FieldValue::Otp(Zeroizing::new(s.into()))
    }

    fn row(r: &Review, a: Aspect) -> &Row {
        r.rows.iter().find(|x| x.aspect == a).unwrap()
    }

    fn pw(item: &Item) -> &str {
        password_of(item).unwrap()
    }

    #[test]
    fn identical_copies_have_no_line() {
        let a = login("GitHub", "alice", "pw", "https://github.com");
        let mut b = a.clone();
        b.id = Id::new();
        let r = review(&[&a, &b]);
        assert!(r.rows.is_empty());
        assert_eq!(r.confidence, Confidence::Sure);
    }

    #[test]
    fn a_website_and_a_title_are_sure() {
        let a = login("Compte Google", "c@gmail.com", "pw", "https://accounts.google.com");
        let b = login("Gmail", "c@gmail.com", "pw", "https://mail.google.com");
        let r = review(&[&a, &b]);
        assert_eq!(r.confidence, Confidence::Sure);
        assert_eq!(row(&r, Aspect::Title).kind, RowKind::Kept);
        assert_eq!(row(&r, Aspect::Title).winner, Some(0));
        let w = row(&r, Aspect::Websites);
        assert_eq!(w.kind, RowKind::Added);
        assert_eq!(w.values[1], Some(FieldValue::Text("mail.google.com".into())));
    }

    #[test]
    fn username_case_is_not_a_conflict() {
        let a = login("A", "Camille.Durand@exemple.fr", "pw", "https://github.com");
        let b = login("A", " camille.durand@exemple.fr", "pw", "https://github.com");
        let r = review(&[&a, &b]);
        assert!(r.rows.is_empty(), "{:?}", r.rows);
    }

    #[test]
    fn two_usernames_are_a_conflict() {
        let a = login("A", "alice", "pw", "https://a.example");
        let b = login("A", "bob", "pw", "https://a.example");
        let r = review(&[&a, &b]);
        assert_eq!(r.confidence, Confidence::Review);
        assert_eq!(row(&r, Aspect::Username).kind, RowKind::Conflict);
        assert_eq!(row(&r, Aspect::Username).subject, "username");
    }

    #[test]
    fn a_password_on_one_side_only_is_added() {
        let a = login("A", "alice", "", "https://a.example");
        let b = login("A", "alice", "Secret-1", "https://a.example");
        let r = review(&[&a, &b]);
        assert_eq!(r.confidence, Confidence::Sure);
        let p = row(&r, Aspect::Password);
        assert_eq!(p.kind, RowKind::Added);
        assert_eq!(p.winner, Some(1));
        assert!(p.concealed);
    }

    #[test]
    fn two_passwords_ask_and_default_to_the_newest() {
        let a = login("A", "alice", "Old-One", "https://a.example");
        let mut b = login("A", "alice", "New-One", "https://a.example");
        b.updated_at = datetime!(2026-06-01 0:00 UTC);
        let r = review(&[&a, &b]);
        assert_eq!(r.confidence, Confidence::Review);
        let p = row(&r, Aspect::Password);
        assert_eq!(p.kind, RowKind::Conflict);
        assert_eq!(p.winner, Some(1));
    }

    #[test]
    fn an_older_password_found_in_a_history_is_sure() {
        let mut a = login("A", "alice", "Current", "https://a.example");
        a.password_history.push(PasswordHistoryEntry {
            value: Zeroizing::new("Saved-Again".into()),
            replaced_at: datetime!(2025-01-01 0:00 UTC),
        });
        let mut b = login("A", "alice", "Saved-Again", "https://a.example");
        // Edited later, yet its password is the old one.
        b.updated_at = datetime!(2026-06-01 0:00 UTC);
        let r = review(&[&a, &b]);
        assert_eq!(r.confidence, Confidence::Sure);
        let p = row(&r, Aspect::Password);
        assert_eq!(p.kind, RowKind::Kept);
        assert_eq!(p.winner, Some(0));
    }

    #[test]
    fn the_primary_password_in_the_other_history_lets_the_other_win() {
        let a = login("A", "alice", "Old", "https://a.example");
        let mut b = login("A", "alice", "Newer", "https://a.example");
        b.password_history.push(PasswordHistoryEntry {
            value: Zeroizing::new("Old".into()),
            replaced_at: datetime!(2025-01-01 0:00 UTC),
        });
        let r = review(&[&a, &b]);
        assert_eq!(r.confidence, Confidence::Sure);
        assert_eq!(row(&r, Aspect::Password).winner, Some(1));
        let m = merge_with(&a, &[&b], &r.choices(&[&a, &b]), "", datetime!(2026-07-01 0:00 UTC));
        assert_eq!(pw(&m.merged), "Newer");
        assert!(m.merged.password_history.iter().any(|h| h.value.as_str() == "Old"));
    }

    #[test]
    fn totp_on_one_side_is_added_two_secrets_conflict() {
        let a = login("A", "alice", "pw", "https://a.example");
        let mut b = login("A", "alice", "pw", "https://a.example");
        set(&mut b, "totp", otp("JBSWY3DPEHPK3PXP"));
        let r = review(&[&a, &b]);
        assert_eq!(r.confidence, Confidence::Sure);
        assert_eq!(row(&r, Aspect::Totp).kind, RowKind::Added);
        assert!(row(&r, Aspect::Totp).concealed);

        let mut c = a.clone();
        c.id = Id::new();
        set(&mut c, "totp", otp("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP"));
        // The same secret spelled as a URI is not a difference.
        assert!(review(&[&b, &c]).rows.is_empty());
        set(&mut c, "totp", otp("GEZDGNBVGY3TQOJQ"));
        let r = review(&[&b, &c]);
        assert_eq!(r.confidence, Confidence::Review);
        assert_eq!(row(&r, Aspect::Totp).kind, RowKind::Conflict);
    }

    #[test]
    fn notes_held_by_another_are_added_two_notes_conflict() {
        let mut a = login("A", "alice", "pw", "https://a.example");
        let mut b = login("A", "alice", "pw", "https://a.example");
        a.notes = "Compte principal.".into();
        b.notes = "Compte principal.\nCode PIN au dos.".into();
        let r = review(&[&a, &b]);
        assert_eq!(r.confidence, Confidence::Sure);
        assert_eq!(row(&r, Aspect::Notes).winner, Some(1));
        b.notes = "Enregistré depuis Safari.".into();
        let r = review(&[&a, &b]);
        assert_eq!(r.confidence, Confidence::Review);
        let n = row(&r, Aspect::Notes);
        assert_eq!(n.kind, RowKind::Conflict);
        assert_eq!(n.winner, None);
    }

    #[test]
    fn choosing_the_other_password_keeps_the_primary_one_in_history() {
        let a = login("A", "alice", "Mine", "https://a.example");
        let b = login("A", "alice", "Theirs", "https://a.example");
        let choice = Choice {
            subject: PASSWORD.into(),
            from: Some(b.id),
        };
        let m = merge_with(&a, &[&b], &[choice], "", datetime!(2026-07-01 0:00 UTC));
        assert_eq!(pw(&m.merged), "Theirs");
        let hist: Vec<&str> = m.merged.password_history.iter().map(|h| h.value.as_str()).collect();
        assert_eq!(hist, vec!["Mine"]);
    }

    #[test]
    fn choosing_the_other_username_keeps_the_primary_one_as_extra() {
        let a = login("Primary", "alice", "pw", "https://a.example");
        let b = login("Other", "bob", "pw", "https://a.example");
        let choice = Choice {
            subject: "username".into(),
            from: Some(b.id),
        };
        let m = merge_with(&a, &[&b], &[choice], "", datetime!(2026-07-01 0:00 UTC));
        assert_eq!(m.merged.field("username").unwrap().value, FieldValue::Text("bob".into()));
        let extra = m.merged.sections.iter().find(|s| s.id == MERGED_SECTION_ID).unwrap();
        assert_eq!(extra.fields.len(), 1);
        assert_eq!(extra.fields[0].value, FieldValue::Text("alice".into()));
        assert!(extra.fields[0].label.ends_with("(Primary)"));
    }

    #[test]
    fn choosing_one_note_drops_the_other_from_the_merged_item() {
        let mut a = login("A", "alice", "pw", "https://a.example");
        let mut b = login("B", "alice", "pw", "https://a.example");
        a.notes = "Mine".into();
        b.notes = "Theirs".into();
        let now = datetime!(2026-07-01 0:00 UTC);
        let keep_b = Choice {
            subject: NOTES.into(),
            from: Some(b.id),
        };
        let m = merge_with(&a, &[&b], &[keep_b], "Fusionné", now);
        assert_eq!(m.merged.notes, "Theirs");
        // The archived copy keeps its own note, so nothing is lost.
        assert!(m.archived[0].notes.starts_with("Theirs"));
        let keep_a = Choice {
            subject: NOTES.into(),
            from: Some(a.id),
        };
        assert_eq!(merge_with(&a, &[&b], &[keep_a], "", now).merged.notes, "Mine");
        let both = Choice {
            subject: NOTES.into(),
            from: None,
        };
        let m = merge_with(&a, &[&b], &[both], "", now);
        assert!(m.merged.notes.contains("Mine") && m.merged.notes.contains("Theirs"));
    }

    #[test]
    fn a_sure_merge_with_default_choices_loses_nothing() {
        let mut a = login("Compte Google", "c@gmail.com", "pw", "https://accounts.google.com");
        let mut b = login("Gmail", "c@gmail.com", "pw", "https://mail.google.com");
        set(&mut b, "totp", otp("JBSWY3DPEHPK3PXP"));
        b.tags.push("Famille".into());
        a.notes = String::new();
        b.notes = "Note".into();
        let copies = [&a, &b];
        let r = review(&copies);
        assert_eq!(r.confidence, Confidence::Sure);
        let m = merge_with(&a, &[&b], &r.choices(&copies), "", datetime!(2026-07-01 0:00 UTC));
        assert_eq!(m.merged.title, "Compte Google");
        assert_eq!(m.merged.urls.len(), 2);
        assert!(matches!(m.merged.field("totp").unwrap().value, FieldValue::Otp(_)));
        assert!(m.merged.tags.contains(&"Famille".to_owned()));
        assert_eq!(m.merged.notes, "Note");
        // Nothing went to an extra field: no conflict was folded.
        assert!(!m.merged.sections.iter().any(|s| s.id == MERGED_SECTION_ID));
    }

    #[test]
    fn three_copies_line_up_one_value_each() {
        let a = login("A", "alice", "pw", "https://a.example");
        let b = login("A", "alice", "pw", "https://b.example");
        let c = login("A", "alice", "pw", "");
        let r = review(&[&a, &b, &c]);
        let w = row(&r, Aspect::Websites);
        assert_eq!(w.values.len(), 3);
        assert_eq!(w.values[2], None);
    }
}
