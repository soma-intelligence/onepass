//! Possible duplicates: items of one account that are likely the same
//! account or the same document, and how two or more of them fold into one
//! (spec 2026-11-03-duplicates).
//!
//! Detection is pure: it reads decrypted items and returns groups, never a
//! value. A group is made of strong signals only:
//!
//! - same type, a shared registrable domain (eTLD+1 of a website, an app
//!   link or a host field) and the same username (or email), normalized;
//! - the same TOTP secret (compared decoded, through a hash);
//! - the same card number (cards) or document number (ID card, passport,
//!   driver license, social security number), same type;
//! - the same title and username, same type, both without any website.
//!
//! The same password on the same domain with other usernames is password
//! reuse, which Watchtower reports: it never makes a group here. Archived,
//! trashed, pending and profile items never take part. Two copies of one
//! item id (a move cut short) are not duplicates. A pair the user called
//! "not duplicates" is remembered on the items themselves, as a hidden tag
//! `onepass:distinct:<other id>` on at least one side: encrypted with the
//! item, synced with it. A group comes back only through a new pair.
//!
//! Merging (`merge`) keeps a primary item and folds the others into it
//! without losing anything: the others are archived, intact, with a note.

use std::collections::{BTreeSet, HashMap};

use data_encoding::HEXLOWER;
use time::OffsetDateTime;

use crate::id::Id;
use crate::model::{
    AttachmentRef, Field, FieldValue, Item, ItemType, PasswordHistoryEntry, Section,
};
use crate::watchtower::host::host_of;

/// Prefix of the hidden tag that says "not a duplicate of" another item.
pub const DISTINCT_TAG_PREFIX: &str = "onepass:distinct:";

/// Section that receives the conflicting values of the merged-away items.
pub const MERGED_SECTION_ID: &str = "merged";

/// Why items were grouped. Ordered from the strongest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Signal {
    SameTotp,
    SameCardNumber,
    SameDocumentNumber,
    SameLogin,
    SameTitleAndUsername,
}

/// One item as detection sees it: `writable` is false in a shared vault
/// where this account is Read only.
#[derive(Debug, Clone, Copy)]
pub struct Candidate<'a> {
    pub item: &'a Item,
    pub writable: bool,
}

/// A group of possible duplicates. `members` index the candidates given to
/// `find`, the suggested primary first (always a writable one).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    /// Stable for the same set of items: hex of a hash of their ids.
    pub id: String,
    pub signals: Vec<Signal>,
    /// The registrable domain shared, for a `SameLogin` group.
    pub domain: Option<String>,
    pub members: Vec<usize>,
}

/// What differs in a copy from the suggested primary. Never a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Aspect {
    Title,
    Username,
    Password,
    Websites,
    Totp,
    Passkeys,
    Notes,
    Fields,
    Attachments,
    Tags,
}

/// The hidden tag that says `self` is not a duplicate of `other`.
pub fn distinct_tag(other: Id) -> String {
    format!("{DISTINCT_TAG_PREFIX}{}", HEXLOWER.encode(&other.0))
}

/// The tag is a "not a duplicate of" marker.
pub fn is_distinct_tag(tag: &str) -> bool {
    tag.starts_with(DISTINCT_TAG_PREFIX)
}

/// The user said `a` and `b` are not duplicates (either side remembers it).
pub fn dismissed(a: &Item, b: &Item) -> bool {
    let (ta, tb) = (distinct_tag(b.id), distinct_tag(a.id));
    a.tags.contains(&ta) || b.tags.contains(&tb)
}

/// Add the "not a duplicate of" tags of `others` to `item`. True when the
/// item changed.
pub fn mark_distinct(item: &mut Item, others: impl IntoIterator<Item = Id>) -> bool {
    let mut changed = false;
    for other in others {
        if other == item.id {
            continue;
        }
        let tag = distinct_tag(other);
        if !item.tags.contains(&tag) {
            item.tags.push(tag);
            changed = true;
        }
    }
    changed
}

/// Takes part in detection: live, not pending, not the account profile.
fn eligible(item: &Item) -> bool {
    !item.archived && item.trashed_at.is_none() && !item.is_pending() && !item.is_profile()
}

fn text<'a>(item: &'a Item, id: &str) -> Option<&'a str> {
    item.sections
        .iter()
        .flat_map(|s| s.fields.iter())
        .filter(|f| f.id == id)
        .find_map(|f| match &f.value {
            FieldValue::Text(s) | FieldValue::Email(s) | FieldValue::Url(s) => Some(s.as_str()),
            FieldValue::Concealed(s) | FieldValue::Password(s) => Some(s.as_str()),
            _ => None,
        })
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

/// Username of an item, normalized (trimmed, lower case): the `username`
/// field, else `email`, else the address of an Email item.
pub(crate) fn username(item: &Item) -> Option<String> {
    ["username", "email", "address"]
        .iter()
        .find_map(|id| text(item, id))
        .map(str::to_lowercase)
}

/// Registrable domain (eTLD+1) of a host; the host itself for an address,
/// a single label or a bare public suffix.
fn registrable(host: &str) -> String {
    let h = host.trim_end_matches('.');
    if h.starts_with('[') || h.parse::<std::net::IpAddr>().is_ok() || !h.contains('.') {
        return h.to_owned();
    }
    psl::domain_str(h).unwrap_or(h).to_owned()
}

/// Every registrable domain the item names: websites, app links, URL
/// fields and a `host` field. An app id that is not a URL counts as
/// `app:<id>`.
pub(crate) fn domains(item: &Item) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for u in &item.urls {
        if let Some(h) = host_of(&u.url) {
            out.insert(registrable(&h));
        }
    }
    for app in &item.apps {
        let a = app.trim();
        if a.is_empty() {
            continue;
        }
        match a.contains("://").then(|| host_of(a)).flatten() {
            Some(h) => out.insert(registrable(&h)),
            None => out.insert(format!("app:{}", a.to_lowercase())),
        };
    }
    for f in item.sections.iter().flat_map(|s| s.fields.iter()) {
        let host = match (&f.value, f.id.as_str()) {
            (FieldValue::Url(u), _) => host_of(u),
            (FieldValue::Text(t), "host") => host_of(t),
            _ => None,
        };
        if let Some(h) = host {
            out.insert(registrable(&h));
        }
    }
    out
}

fn has_website(item: &Item) -> bool {
    item.urls.iter().any(|u| !u.url.trim().is_empty())
        || item.apps.iter().any(|a| !a.trim().is_empty())
}

/// Hash of a decoded TOTP secret (an `otpauth://` URI or a bare base32
/// secret), `None` when it does not decode.
fn otp_key(v: &str) -> Option<[u8; 32]> {
    let v = v.trim();
    if v.is_empty() {
        return None;
    }
    let cfg = if v.to_ascii_lowercase().starts_with("otpauth://") {
        crate::totp::parse_otpauth(v)
    } else {
        crate::totp::totp_from_secret(v)
    };
    cfg.ok()
        .filter(|c| !c.secret.is_empty())
        .map(|c| crate::share::sha256(&[b"onepass/dup-totp", &c.secret]))
}

/// Hash of each decoded TOTP secret of the item (`Otp` fields only, a
/// replaced seed kept as `previous_otp_*` is not one).
fn totp_keys(item: &Item) -> Vec<[u8; 32]> {
    item.sections
        .iter()
        .flat_map(|s| s.fields.iter())
        .filter_map(|f| match &f.value {
            FieldValue::Otp(v) => otp_key(v),
            _ => None,
        })
        .collect()
}

fn is_document(t: ItemType) -> bool {
    matches!(
        t,
        ItemType::IdCard
            | ItemType::Passport
            | ItemType::DriverLicense
            | ItemType::SocialSecurityNumber
    )
}

/// Card number (digits, at least 12) or document number (letters and
/// digits upper case, at least 4), for those types.
fn number_key(item: &Item) -> Option<(Signal, String)> {
    let raw = text(item, "number")?;
    if item.item_type == ItemType::CreditCard {
        let d: String = raw.chars().filter(char::is_ascii_digit).collect();
        return (d.len() >= 12).then_some((Signal::SameCardNumber, d));
    }
    if is_document(item.item_type) {
        let d: String = raw
            .chars()
            .filter(char::is_ascii_alphanumeric)
            .map(|c| c.to_ascii_uppercase())
            .collect();
        return (d.len() >= 4).then_some((Signal::SameDocumentNumber, d));
    }
    None
}

/// The keys an item is bucketed under: a pair of items sharing one key is
/// a candidate pair for that signal.
fn keys(item: &Item) -> Vec<(Signal, String)> {
    let mut out = Vec::new();
    let ty = format!("{:?}", item.item_type);
    let user = username(item);
    if let Some(u) = &user {
        for d in domains(item) {
            out.push((Signal::SameLogin, format!("{ty}\u{0}{d}\u{0}{u}")));
        }
        if !has_website(item) {
            let title = item.title.trim().to_lowercase();
            if !title.is_empty() {
                out.push((
                    Signal::SameTitleAndUsername,
                    format!("{ty}\u{0}{title}\u{0}{u}"),
                ));
            }
        }
    }
    for k in totp_keys(item) {
        out.push((Signal::SameTotp, HEXLOWER.encode(&k)));
    }
    if let Some((s, n)) = number_key(item) {
        let h = crate::share::sha256(&[b"onepass/dup-number", ty.as_bytes(), n.as_bytes()]);
        out.push((s, HEXLOWER.encode(&h)));
    }
    out
}

fn root(parent: &mut [usize], mut i: usize) -> usize {
    while let Some(&p) = parent.get(i) {
        if p == i {
            break;
        }
        let gp = parent.get(p).copied().unwrap_or(p);
        if let Some(slot) = parent.get_mut(i) {
            *slot = gp;
        }
        i = p;
    }
    i
}

/// How rich an item is, to pick the primary: passkeys and TOTP first, then
/// the most recent edit, then the number of filled fields.
fn richness(item: &Item) -> (u8, OffsetDateTime, usize) {
    let fields = filled_fields(item);
    let has_passkey = fields
        .iter()
        .any(|f| matches!(f.value, FieldValue::Passkey(_)));
    let has_totp = fields.iter().any(|f| matches!(f.value, FieldValue::Otp(_)));
    (
        u8::from(has_passkey) + u8::from(has_totp),
        item.updated_at,
        fields.len() + item.urls.len() + item.attachments.len(),
    )
}

/// Index (into `cands`) of the suggested primary among `members`: the
/// richest writable one (`richness`). `None` when none is writable.
pub fn suggested_primary(cands: &[Candidate<'_>], members: &[usize]) -> Option<usize> {
    members
        .iter()
        .copied()
        .filter(|&i| cands.get(i).is_some_and(|c| c.writable))
        .max_by(|&a, &b| {
            let (ia, ib) = (&cands[a], &cands[b]);
            richness(ia.item)
                .cmp(&richness(ib.item))
                // Equal: the smaller id, so the choice is stable.
                .then_with(|| ib.item.id.cmp(&ia.item.id))
        })
}

/// The groups of possible duplicates among `cands`, sorted by the title of
/// their primary. A group always has two members or more and at least one
/// writable one (nothing to do otherwise).
pub fn find(cands: &[Candidate<'_>]) -> Vec<Group> {
    let mut buckets: HashMap<(Signal, String), Vec<usize>> = HashMap::new();
    for (i, c) in cands.iter().enumerate() {
        if !eligible(c.item) {
            continue;
        }
        for k in keys(c.item) {
            let list = buckets.entry(k).or_default();
            if !list.contains(&i) {
                list.push(i);
            }
        }
    }
    let mut parent: Vec<usize> = (0..cands.len()).collect();
    let mut edges: Vec<(usize, usize, Signal, Option<String>)> = Vec::new();
    for ((signal, key), list) in &buckets {
        for (n, &a) in list.iter().enumerate() {
            for &b in list.iter().skip(n + 1) {
                let (ia, ib) = (cands[a].item, cands[b].item);
                if ia.id == ib.id || dismissed(ia, ib) {
                    continue;
                }
                let domain = (*signal == Signal::SameLogin)
                    .then(|| key.split('\u{0}').nth(1).map(str::to_owned))
                    .flatten();
                edges.push((a, b, *signal, domain));
                let (ra, rb) = (root(&mut parent, a), root(&mut parent, b));
                if ra != rb {
                    parent[rb] = ra;
                }
            }
        }
    }
    // Per root: members, signals, shared domains.
    type Acc = (BTreeSet<usize>, BTreeSet<Signal>, BTreeSet<String>);
    let mut groups: HashMap<usize, Acc> = HashMap::new();
    for (a, b, signal, domain) in edges {
        let r = root(&mut parent, a);
        let g = groups.entry(r).or_default();
        g.0.insert(a);
        g.0.insert(b);
        g.1.insert(signal);
        if let Some(d) = domain {
            g.2.insert(d);
        }
    }
    let mut out: Vec<Group> = groups
        .into_values()
        .filter_map(|(members, signals, domains)| {
            let members: Vec<usize> = members.into_iter().collect();
            let primary = suggested_primary(cands, &members)?;
            let mut ordered = vec![primary];
            let mut rest: Vec<usize> = members.into_iter().filter(|&m| m != primary).collect();
            rest.sort_by(|&a, &b| cands[b].item.updated_at.cmp(&cands[a].item.updated_at));
            ordered.extend(rest);
            let mut ids: Vec<Id> = ordered.iter().map(|&i| cands[i].item.id).collect();
            ids.sort();
            let parts: Vec<&[u8]> = ids.iter().map(|id| id.0.as_slice()).collect();
            let mut all: Vec<&[u8]> = vec![b"onepass/dup-group"];
            all.extend(parts);
            let id = HEXLOWER.encode(&crate::share::sha256(&all)[..16]);
            Some(Group {
                id,
                signals: signals.into_iter().collect(),
                domain: domains.into_iter().next(),
                members: ordered,
            })
        })
        .collect();
    out.sort_by(|a, b| {
        let t = |g: &Group| cands[g.members[0]].item.title.to_lowercase();
        t(a).cmp(&t(b)).then_with(|| a.id.cmp(&b.id))
    });
    out
}

/// Items bucketed by the detection keys of `find`, to match an item that
/// is not among them (an item an import brings) with the same rules.
pub struct Index {
    buckets: HashMap<(Signal, String), Vec<usize>>,
    ids: Vec<Id>,
}

impl Index {
    /// Index of `items`; the ones that never take part (archived, trashed,
    /// pending, profile) are left out.
    pub fn new<'a>(items: impl IntoIterator<Item = &'a Item>) -> Self {
        let mut buckets: HashMap<(Signal, String), Vec<usize>> = HashMap::new();
        let mut ids = Vec::new();
        for (i, item) in items.into_iter().enumerate() {
            ids.push(item.id);
            if !eligible(item) {
                continue;
            }
            for k in keys(item) {
                let list = buckets.entry(k).or_default();
                if !list.contains(&i) {
                    list.push(i);
                }
            }
        }
        Self { buckets, ids }
    }

    /// The indexed items `item` is a possible duplicate of, with the
    /// signals, best match first: the strongest signal, then the most
    /// signals, then the lowest index. Empty when `item` would not take
    /// part in detection, and never the same id.
    pub fn matches(&self, item: &Item) -> Vec<(usize, Vec<Signal>)> {
        if !eligible(item) {
            return Vec::new();
        }
        let mut found: std::collections::BTreeMap<usize, BTreeSet<Signal>> =
            std::collections::BTreeMap::new();
        for k in keys(item) {
            let signal = k.0;
            for &i in self.buckets.get(&k).into_iter().flatten() {
                if self.ids.get(i) == Some(&item.id) {
                    continue;
                }
                found.entry(i).or_default().insert(signal);
            }
        }
        let mut out: Vec<(usize, Vec<Signal>)> = found
            .into_iter()
            .map(|(i, s)| (i, s.into_iter().collect()))
            .collect();
        out.sort_by(|a, b| {
            a.1.first()
                .cmp(&b.1.first())
                .then_with(|| b.1.len().cmp(&a.1.len()))
                .then_with(|| a.0.cmp(&b.0))
        });
        out
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
        | FieldValue::Mnemonic(s) => s.trim().is_empty(),
        FieldValue::Barcode { value, .. } => value.trim().is_empty(),
        _ => false,
    }
}

fn filled_fields(item: &Item) -> Vec<&Field> {
    item.sections
        .iter()
        .flat_map(|s| s.fields.iter())
        .filter(|f| !is_blank(&f.value))
        .collect()
}

fn password_of(item: &Item) -> Option<&str> {
    item.sections
        .iter()
        .flat_map(|s| s.fields.iter())
        .find_map(|f| match &f.value {
            FieldValue::Password(p) if f.id == "password" && !p.is_empty() => Some(p.as_str()),
            _ => None,
        })
}

fn website_set(item: &Item) -> BTreeSet<String> {
    item.urls
        .iter()
        .map(|u| u.url.trim().trim_end_matches('/').to_lowercase())
        .filter(|u| !u.is_empty())
        .collect()
}

fn passkey_ids(item: &Item) -> BTreeSet<Vec<u8>> {
    item.sections
        .iter()
        .flat_map(|s| s.fields.iter())
        .filter_map(|f| match &f.value {
            FieldValue::Passkey(p) => Some(p.credential_id.clone()),
            _ => None,
        })
        .collect()
}

fn visible_tags(item: &Item) -> BTreeSet<&str> {
    item.tags
        .iter()
        .map(String::as_str)
        .filter(|t| !t.starts_with("onepass:"))
        .collect()
}

/// What differs in `other` from `primary`, in `Aspect` order. Never a value.
pub fn differences(primary: &Item, other: &Item) -> Vec<Aspect> {
    let mut out = Vec::new();
    if primary.title.trim() != other.title.trim() {
        out.push(Aspect::Title);
    }
    if username(primary) != username(other) {
        out.push(Aspect::Username);
    }
    if password_of(primary) != password_of(other) {
        out.push(Aspect::Password);
    }
    if website_set(primary) != website_set(other) {
        out.push(Aspect::Websites);
    }
    if totp_keys(primary) != totp_keys(other) {
        out.push(Aspect::Totp);
    }
    if passkey_ids(primary) != passkey_ids(other) {
        out.push(Aspect::Passkeys);
    }
    if primary.notes.trim() != other.notes.trim() {
        out.push(Aspect::Notes);
    }
    let rest = |i: &Item| -> Vec<(String, FieldValue)> {
        filled_fields(i)
            .into_iter()
            .filter(|f| {
                !matches!(f.id.as_str(), "username" | "email" | "address" | "password")
                    && !matches!(f.value, FieldValue::Otp(_) | FieldValue::Passkey(_))
            })
            .map(|f| (f.id.clone(), f.value.clone()))
            .collect()
    };
    if rest(primary) != rest(other) {
        out.push(Aspect::Fields);
    }
    let files = |i: &Item| -> BTreeSet<(String, u64)> {
        i.attachments
            .iter()
            .map(|a| (a.name.clone(), a.size))
            .collect()
    };
    if files(primary) != files(other) {
        out.push(Aspect::Attachments);
    }
    if visible_tags(primary) != visible_tags(other) {
        out.push(Aspect::Tags);
    }
    out
}

/// The result of `merge`: the primary as it will be saved, the others as
/// they will be archived, and the attachments of the others to copy into
/// the primary (the copies keep theirs).
#[derive(Debug, Clone, PartialEq)]
pub struct Merge {
    pub merged: Item,
    pub archived: Vec<Item>,
    /// (item the file comes from, its reference there).
    pub attachments: Vec<(Id, AttachmentRef)>,
}

fn same_value(a: &FieldValue, b: &FieldValue) -> bool {
    match (a, b) {
        (FieldValue::Passkey(x), FieldValue::Passkey(y)) => x.credential_id == y.credential_id,
        (FieldValue::Otp(x), FieldValue::Otp(y)) => match (otp_key(x), otp_key(y)) {
            (Some(kx), Some(ky)) => kx == ky,
            _ => x.trim() == y.trim(),
        },
        (FieldValue::Text(x), FieldValue::Text(y))
        | (FieldValue::Email(x), FieldValue::Email(y))
        | (FieldValue::Url(x), FieldValue::Url(y)) => x.trim() == y.trim(),
        _ => a == b,
    }
}

/// Where `field_id` sits in `item`: (section index, field index) of its
/// last occurrence.
fn locate(item: &Item, field_id: &str) -> Option<(usize, usize)> {
    let mut found = None;
    for (si, s) in item.sections.iter().enumerate() {
        for (fi, f) in s.fields.iter().enumerate() {
            if f.id == field_id {
                found = Some((si, fi));
            }
        }
    }
    found
}

fn has_value(item: &Item, field_id: &str, v: &FieldValue) -> bool {
    item.sections
        .iter()
        .flat_map(|s| s.fields.iter())
        .any(|f| f.id == field_id && same_value(&f.value, v))
}

fn any_value(item: &Item, v: &FieldValue) -> bool {
    item.sections
        .iter()
        .flat_map(|s| s.fields.iter())
        .any(|f| same_value(&f.value, v))
}

/// Push a conflicting value of `from` into the primary's merged section, as
/// an extra field labeled with the source title. Never filled automatically.
fn push_extra(merged: &mut Item, field: &Field, from_title: &str) {
    let section = match merged
        .sections
        .iter()
        .position(|s| s.id == MERGED_SECTION_ID)
    {
        Some(i) => i,
        None => {
            merged.sections.push(Section {
                id: MERGED_SECTION_ID.to_owned(),
                label: String::new(),
                fields: Vec::new(),
            });
            merged.sections.len() - 1
        }
    };
    let n = merged
        .sections
        .iter()
        .flat_map(|s| s.fields.iter())
        .filter(|f| f.id.starts_with("merged_"))
        .count()
        + 1;
    if let Some(s) = merged.sections.get_mut(section) {
        s.fields.push(Field {
            id: format!("merged_{n}_{}", field.id),
            label: format!("{} ({})", field.label, from_title.trim()),
            kind: field.kind,
            value: field.value.clone(),
            required: false,
            repeatable: false,
            autofill: false,
        });
    }
}

fn push_history(merged: &mut Item, value: &str, at: OffsetDateTime) {
    if value.is_empty()
        || password_of(merged) == Some(value)
        || merged
            .password_history
            .iter()
            .any(|h| h.value.as_str() == value)
    {
        return;
    }
    merged.password_history.push(PasswordHistoryEntry {
        value: zeroize::Zeroizing::new(value.to_owned()),
        replaced_at: at,
    });
}

/// Fold `other`'s fields into `merged`.
fn fold_fields(merged: &mut Item, other: &Item) {
    for section in &other.sections {
        for field in &section.fields {
            if is_blank(&field.value) {
                continue;
            }
            // The other's password: history, never a second password field.
            if let (FieldValue::Password(p), "password") = (&field.value, field.id.as_str()) {
                push_history(merged, p, other.updated_at);
                continue;
            }
            if has_value(merged, &field.id, &field.value) {
                continue;
            }
            match locate(merged, &field.id) {
                Some((si, fi)) => {
                    let blank = merged
                        .sections
                        .get(si)
                        .and_then(|s| s.fields.get(fi))
                        .is_some_and(|f| is_blank(&f.value));
                    let repeatable = merged
                        .sections
                        .get(si)
                        .and_then(|s| s.fields.get(fi))
                        .is_some_and(|f| f.repeatable);
                    if blank {
                        if let Some(f) = merged
                            .sections
                            .get_mut(si)
                            .and_then(|s| s.fields.get_mut(fi))
                        {
                            f.value = field.value.clone();
                        }
                    } else if repeatable {
                        if let Some(s) = merged.sections.get_mut(si) {
                            let mut copy = field.clone();
                            copy.required = false;
                            s.fields.insert(fi + 1, copy);
                        }
                    } else if !any_value(merged, &field.value) {
                        push_extra(merged, field, &other.title);
                    }
                }
                None => {
                    // A custom field the primary lacks: same section when it
                    // has one by that id, else the other's section is added.
                    let mut copy = field.clone();
                    copy.required = false;
                    match merged.sections.iter_mut().find(|s| s.id == section.id) {
                        Some(s) => s.fields.push(copy),
                        None => merged.sections.push(Section {
                            id: section.id.clone(),
                            label: section.label.clone(),
                            fields: vec![copy],
                        }),
                    }
                }
            }
        }
    }
}

/// Notes of `other` appended under a separator line naming it, unless the
/// primary's notes already hold them.
fn fold_notes(merged: &mut Item, other: &Item) {
    let theirs = other.notes.trim();
    if theirs.is_empty() || merged.notes.contains(theirs) {
        return;
    }
    if !merged.notes.trim().is_empty() {
        merged.notes.push_str("\n\n");
    }
    merged
        .notes
        .push_str(&format!("--- {} ---\n{theirs}", other.title.trim()));
}

/// Fold `others` into `primary` (spec 2026-11-03-duplicates, section 3):
///
/// - websites, app links, places, sign-in methods and visible tags: union;
///   favorite, re-prompt and watch: kept when any copy has them;
/// - notes: the others' appended, each under a `--- <title> ---` line;
/// - fields: a blank field of the primary takes the other's value; a
///   repeatable one (passkeys, backup codes) gets the other's values too; a
///   custom field the primary lacks is added; a conflicting value goes to an
///   extra field "<label> (<other title>)" in a `merged` section, never
///   autofilled. TOTP and passkeys are thereby always kept;
/// - password: the primary's; every other password and password history
///   entry goes to the primary's history, so nothing is lost;
/// - attachments: listed in `Merge::attachments`, for the repository to
///   copy (the archived copies keep their own files).
///
/// The others come back archived, with `note` appended to their notes on
/// a line of its own (the app passes "Merged into <title>" in its
/// language). Their ids, fields and files are untouched: unarchiving one
/// undoes the merge for it. `updated_at` is `now` everywhere; the events
/// are the caller's (`record_edit`, `EventKind::Archived`).
pub fn merge(primary: &Item, others: &[&Item], note: &str, now: OffsetDateTime) -> Merge {
    let mut merged = primary.clone();
    let mut attachments = Vec::new();
    let mut archived = Vec::with_capacity(others.len());
    for other in others {
        if other.id == primary.id {
            continue;
        }
        for u in &other.urls {
            let key = u.url.trim().trim_end_matches('/').to_lowercase();
            if !key.is_empty() && !website_set(&merged).contains(&key) {
                let mut u = u.clone();
                u.primary = false;
                merged.urls.push(u);
            }
        }
        for a in &other.apps {
            if !merged.apps.contains(a) {
                merged.apps.push(a.clone());
            }
        }
        for l in &other.locations {
            if !merged.locations.contains(l) {
                merged.locations.push(l.clone());
            }
        }
        for m in &other.login_methods {
            if !merged.login_methods.contains(m) {
                merged.login_methods.push(m.clone());
            }
        }
        for t in &other.tags {
            if !t.starts_with("onepass:") && !merged.tags.contains(t) {
                merged.tags.push(t.clone());
            }
        }
        merged.favorite |= other.favorite;
        merged.reprompt |= other.reprompt;
        merged.on_watch |= other.on_watch;
        if merged.expires.is_none() {
            merged.expires = other.expires;
        }
        if merged.rotate_every_days.is_none() {
            merged.rotate_every_days = other.rotate_every_days;
        }
        if merged.custom_icon.is_none() {
            merged.custom_icon.clone_from(&other.custom_icon);
        }
        if merged.color.is_none() {
            merged.color.clone_from(&other.color);
        }
        fold_notes(&mut merged, other);
        fold_fields(&mut merged, other);
        for h in &other.password_history {
            push_history(&mut merged, &h.value, h.replaced_at);
        }
        for a in &other.attachments {
            if !merged.attachments.iter().any(|m| m.id == a.id)
                && !attachments
                    .iter()
                    .any(|(_, r): &(Id, AttachmentRef)| r.id == a.id)
            {
                attachments.push((other.id, a.clone()));
            }
        }
        let mut copy = (*other).clone();
        copy.archived = true;
        let note = note.trim();
        if !note.is_empty() {
            if !copy.notes.trim().is_empty() {
                copy.notes.push_str("\n\n");
            }
            copy.notes.push_str(note);
        }
        copy.updated_at = now;
        archived.push(copy);
    }
    merged.password_history.sort_by_key(|h| h.replaced_at);
    merged.updated_at = now;
    Merge {
        merged,
        archived,
        attachments,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{FieldType, ItemUrl, MatchRule, PasskeyCredential, new_item};
    use time::macros::datetime;
    use zeroize::Zeroizing;

    fn url(u: &str) -> ItemUrl {
        ItemUrl {
            label: String::new(),
            url: u.into(),
            rule: MatchRule::Domain,
            primary: true,
        }
    }

    fn set(item: &mut Item, id: &str, v: FieldValue) {
        item.field_mut(id).unwrap().value = v;
    }

    fn login(title: &str, user: &str, pw: &str, site: &str) -> Item {
        let mut i = new_item(ItemType::Login, Id([1; 16]), title);
        i.id = Id::new();
        set(&mut i, "username", FieldValue::Text(user.into()));
        set(
            &mut i,
            "password",
            FieldValue::Password(Zeroizing::new(pw.into())),
        );
        if !site.is_empty() {
            i.urls.push(url(site));
        }
        i
    }

    fn all(items: &[Item]) -> Vec<Candidate<'_>> {
        items
            .iter()
            .map(|item| Candidate {
                item,
                writable: true,
            })
            .collect()
    }

    fn groups(items: &[Item]) -> Vec<Group> {
        find(&all(items))
    }

    #[test]
    fn same_registrable_domain_and_username_group() {
        let a = login(
            "GitHub",
            "Alice@Example.com ",
            "one",
            "https://github.com/login",
        );
        let b = login("GH", "alice@example.com", "two", "https://www.github.com");
        let c = login("Other", "bob", "one", "https://github.com");
        let g = groups(&[a, b, c]);
        assert_eq!(g.len(), 1);
        assert_eq!(g[0].members.len(), 2);
        assert_eq!(g[0].signals, vec![Signal::SameLogin]);
        assert_eq!(g[0].domain.as_deref(), Some("github.com"));
    }

    #[test]
    fn public_suffix_aware_domains() {
        // Two sites under one public suffix are different registrable domains.
        let a = login("A", "alice", "x", "https://alice.github.io");
        let b = login("B", "alice", "x", "https://bob.github.io");
        assert!(groups(&[a, b]).is_empty());
        let a = login("A", "alice", "x", "https://shop.example.co.uk");
        let b = login("B", "alice", "y", "https://example.co.uk");
        assert_eq!(groups(&[a, b]).len(), 1);
    }

    #[test]
    fn any_url_or_app_link_counts() {
        let mut a = login("A", "alice", "x", "https://example.org");
        a.urls.push(url("https://accounts.example.com"));
        let b = login("B", "alice", "y", "https://example.com");
        assert_eq!(groups(&[a, b]).len(), 1);
        let mut c = login("C", "carol", "x", "");
        c.apps.push("com.example.app".into());
        let mut d = login("D", "carol", "y", "");
        d.apps.push("com.example.app".into());
        assert_eq!(groups(&[c, d]).len(), 1);
    }

    #[test]
    fn password_reuse_is_not_a_duplicate() {
        let a = login("A", "alice", "Same-Pw-1", "https://example.com");
        let b = login("B", "bob", "Same-Pw-1", "https://example.com");
        assert!(groups(&[a, b]).is_empty());
    }

    #[test]
    fn different_types_never_group_on_login() {
        let a = login("A", "alice", "x", "https://example.com");
        let mut b = new_item(ItemType::Server, Id([1; 16]), "B");
        set(&mut b, "username", FieldValue::Text("alice".into()));
        b.urls.push(url("https://example.com"));
        assert!(groups(&[a, b]).is_empty());
    }

    #[test]
    fn same_totp_secret_groups_any_spelling() {
        let mut a = login("A", "alice", "x", "https://a.example");
        set(
            &mut a,
            "totp",
            FieldValue::Otp(Zeroizing::new("JBSWY3DPEHPK3PXP".into())),
        );
        let mut b = login("B", "other", "y", "https://b.example");
        set(
            &mut b,
            "totp",
            FieldValue::Otp(Zeroizing::new(
                "otpauth://totp/X:alice?secret=jbsw y3dp ehpk 3pxp&issuer=X".replace(' ', ""),
            )),
        );
        let g = groups(&[a, b]);
        assert_eq!(g.len(), 1);
        assert_eq!(g[0].signals, vec![Signal::SameTotp]);
    }

    #[test]
    fn index_matches_an_item_from_outside_with_the_same_rules() {
        let vault = vec![
            login("Shop", "Bob", "a", "https://shop.example.com"),
            login("Mail", "bob", "b", "https://mail-invented.org"),
            login("Shop", "alice", "c", "https://shop.example.com"),
        ];
        let mut archived = login("Shop old", "bob", "d", "https://shop.example.com");
        archived.archived = true;
        let mut items = vault.clone();
        items.push(archived);
        let index = Index::new(&items);
        let incoming = login(
            "Shop again",
            " BOB ",
            "z",
            "https://www.shop.example.com/login",
        );
        let found = index.matches(&incoming);
        assert_eq!(
            found,
            vec![(0, vec![Signal::SameLogin])],
            "archived never matches"
        );
        // The same id is a move, never a duplicate.
        let mut same = incoming.clone();
        same.id = items[0].id;
        assert!(index.matches(&same).is_empty());
        // Strongest signal first.
        let mut a = login("A", "x", "p", "");
        set(
            &mut a,
            "totp",
            FieldValue::Otp(Zeroizing::new("JBSWY3DPEHPK3PXP".to_owned())),
        );
        let b = login("B", "y", "p", "");
        let c = login("Other", "x", "p", "");
        let index = Index::new(&[c.clone(), b, a.clone()]);
        let mut inc = login("A", "x", "q", "");
        set(
            &mut inc,
            "totp",
            FieldValue::Otp(Zeroizing::new("JBSWY3DPEHPK3PXP".to_owned())),
        );
        let found = index.matches(&inc);
        assert_eq!(found.first().map(|f| f.0), Some(2));
        assert_eq!(
            found[0].1,
            vec![Signal::SameTotp, Signal::SameTitleAndUsername]
        );
        assert!(found.iter().all(|f| f.0 != 0), "another title, no website");
    }

    #[test]
    fn card_and_document_numbers() {
        let card = |n: &str| {
            let mut c = new_item(ItemType::CreditCard, Id([1; 16]), "Visa");
            c.id = Id::new();
            set(
                &mut c,
                "number",
                FieldValue::Concealed(Zeroizing::new(n.into())),
            );
            c
        };
        let g = groups(&[
            card("4111 1111 1111 1111"),
            card("4111-1111-1111-1111"),
            card("5500 0000 0000 0004"),
        ]);
        assert_eq!(g.len(), 1);
        assert_eq!(g[0].signals, vec![Signal::SameCardNumber]);
        let doc = |t: ItemType, n: &str| {
            let mut d = new_item(t, Id([1; 16]), "Doc");
            d.id = Id::new();
            set(
                &mut d,
                "number",
                FieldValue::Concealed(Zeroizing::new(n.into())),
            );
            d
        };
        let g = groups(&[
            doc(ItemType::Passport, "22ab 12345"),
            doc(ItemType::Passport, "22AB12345"),
            // Same number, other type: not the same document.
            doc(ItemType::IdCard, "22AB12345"),
        ]);
        assert_eq!(g.len(), 1);
        assert_eq!(g[0].members.len(), 2);
        assert_eq!(g[0].signals, vec![Signal::SameDocumentNumber]);
    }

    #[test]
    fn same_title_and_username_without_websites() {
        let a = login("Wi-Fi box", "admin", "x", "");
        let b = login(" wi-fi BOX", "Admin", "y", "");
        assert_eq!(groups(&[a.clone(), b]).len(), 1);
        // With a website on one side, the title is not enough.
        let c = login("Wi-Fi box", "admin", "x", "https://box.example");
        assert!(groups(&[a, c]).is_empty());
    }

    #[test]
    fn archived_trashed_pending_and_profile_never_take_part() {
        let a = login("A", "alice", "x", "https://example.com");
        let mut b = a.clone();
        b.id = Id::new();
        b.archived = true;
        let mut c = a.clone();
        c.id = Id::new();
        c.trashed_at = Some(datetime!(2026-11-01 0:00 UTC));
        let mut d = a.clone();
        d.id = Id::new();
        d.tags.push(crate::model::PENDING_TAG.into());
        let mut e = a.clone();
        e.id = Id::new();
        e.tags.push(crate::model::PROFILE_TAG.into());
        assert!(groups(&[a, b, c, d, e]).is_empty());
    }

    #[test]
    fn same_item_id_in_two_vaults_is_not_a_duplicate() {
        let a = login("A", "alice", "x", "https://example.com");
        let mut b = a.clone();
        b.vault_id = Id([2; 16]);
        assert!(groups(&[a, b]).is_empty());
    }

    #[test]
    fn across_vaults_is_allowed() {
        let a = login("A", "alice", "x", "https://example.com");
        let mut b = login("B", "alice", "y", "https://example.com");
        b.vault_id = Id([9; 16]);
        assert_eq!(groups(&[a, b]).len(), 1);
    }

    #[test]
    fn dismissal_hides_the_pair_until_a_new_one_appears() {
        let mut a = login("A", "alice", "x", "https://example.com");
        let b = login("B", "alice", "y", "https://example.com");
        assert!(mark_distinct(&mut a, [b.id]));
        let own = a.id;
        assert!(
            !mark_distinct(&mut a, [b.id, own]),
            "idempotent, never itself"
        );
        assert!(dismissed(&a, &b) && dismissed(&b, &a));
        assert!(groups(&[a.clone(), b.clone()]).is_empty());
        let c = login("C", "alice", "z", "https://example.com");
        let g = groups(&[a, b, c]);
        assert_eq!(g.len(), 1);
        assert_eq!(g[0].members.len(), 3, "the new copy links all three");
    }

    #[test]
    fn group_id_is_stable_and_order_free() {
        let a = login("A", "alice", "x", "https://example.com");
        let b = login("B", "alice", "y", "https://example.com");
        let g1 = groups(&[a.clone(), b.clone()]);
        let g2 = groups(&[b, a]);
        assert_eq!(g1[0].id, g2[0].id);
    }

    #[test]
    fn read_only_copies_are_never_primary_and_all_read_only_is_no_group() {
        let mut a = login("A", "alice", "x", "https://example.com");
        set(
            &mut a,
            "totp",
            FieldValue::Otp(Zeroizing::new("JBSWY3DPEHPK3PXP".into())),
        );
        let b = login("B", "alice", "y", "https://example.com");
        let items = [a, b];
        let cands = vec![
            Candidate {
                item: &items[0],
                writable: false,
            },
            Candidate {
                item: &items[1],
                writable: true,
            },
        ];
        let g = find(&cands);
        assert_eq!(g[0].members[0], 1, "the richer copy is read only");
        let none: Vec<_> = items
            .iter()
            .map(|item| Candidate {
                item,
                writable: false,
            })
            .collect();
        assert!(find(&none).is_empty());
    }

    #[test]
    fn primary_prefers_totp_then_recent_edit() {
        let mut a = login("A", "alice", "x", "https://example.com");
        a.updated_at = datetime!(2026-01-01 0:00 UTC);
        let mut b = login("B", "alice", "y", "https://example.com");
        b.updated_at = datetime!(2026-06-01 0:00 UTC);
        let items = [a.clone(), b.clone()];
        assert_eq!(groups(&items)[0].members[0], 1, "most recent");
        set(
            &mut a,
            "totp",
            FieldValue::Otp(Zeroizing::new("JBSWY3DPEHPK3PXP".into())),
        );
        let items = [a, b];
        assert_eq!(groups(&items)[0].members[0], 0, "TOTP wins over recency");
    }

    #[test]
    fn differences_name_aspects_never_values() {
        let a = login("GitHub", "alice", "one", "https://github.com");
        let mut b = login("GitHub perso", "alice", "two", "https://github.com");
        b.notes = "note".into();
        assert_eq!(
            differences(&a, &b),
            vec![Aspect::Title, Aspect::Password, Aspect::Notes]
        );
        assert!(differences(&a, &a).is_empty());
    }

    fn passkey(id: u8) -> FieldValue {
        FieldValue::Passkey(PasskeyCredential {
            rp_id: "github.com".into(),
            user_name: "alice".into(),
            user_handle: vec![id],
            credential_id: vec![id; 4],
            private_key: Zeroizing::new(vec![id; 8]),
            created_at: datetime!(2026-01-01 0:00 UTC),
        })
    }

    #[test]
    fn merge_loses_nothing() {
        let now = datetime!(2026-11-03 12:00 UTC);
        let mut p = login("GitHub", "alice", "primary-pw", "https://github.com");
        p.tags = vec!["dev".into()];
        p.notes = "mine".into();
        set(&mut p, "passkeys", passkey(1));
        let mut o = login(
            "GitHub old",
            "alice",
            "older-pw",
            "https://github.com/login",
        );
        o.updated_at = datetime!(2025-01-01 0:00 UTC);
        o.tags = vec!["dev".into(), "work".into(), distinct_tag(Id::new())];
        o.notes = "theirs".into();
        o.favorite = true;
        set(
            &mut o,
            "totp",
            FieldValue::Otp(Zeroizing::new("JBSWY3DPEHPK3PXP".into())),
        );
        set(&mut o, "passkeys", passkey(2));
        set(
            &mut o,
            "pin",
            FieldValue::Concealed(Zeroizing::new("1234".into())),
        );
        o.password_history.push(PasswordHistoryEntry {
            value: Zeroizing::new("ancient-pw".into()),
            replaced_at: datetime!(2024-01-01 0:00 UTC),
        });
        o.attachments.push(AttachmentRef {
            id: Id::new(),
            name: "scan.pdf".into(),
            size: 10,
            mime: "application/pdf".into(),
        });
        o.sections[0].fields.push(Field {
            id: "custom_1".into(),
            label: "Recovery email".into(),
            kind: FieldType::Email,
            value: FieldValue::Email("r@example.com".into()),
            required: false,
            repeatable: false,
            autofill: false,
        });
        let m = merge(&p, &[&o], "Merged into GitHub", now);
        let r = &m.merged;
        assert_eq!(r.id, p.id);
        assert_eq!(r.title, "GitHub");
        assert_eq!(password_of(r), Some("primary-pw"));
        let hist: Vec<&str> = r
            .password_history
            .iter()
            .map(|h| h.value.as_str())
            .collect();
        assert_eq!(hist, vec!["ancient-pw", "older-pw"]);
        assert_eq!(r.urls.len(), 2);
        assert_eq!(r.urls.iter().filter(|u| u.primary).count(), 1);
        assert_eq!(r.tags, vec!["dev".to_string(), "work".to_string()]);
        assert!(r.favorite);
        assert_eq!(r.notes, "mine\n\n--- GitHub old ---\ntheirs");
        assert!(matches!(
            &r.field("totp").unwrap().value,
            FieldValue::Otp(_)
        ));
        assert_eq!(passkey_ids(r).len(), 2, "both passkeys kept");
        assert!(
            matches!(&r.field("pin").unwrap().value, FieldValue::Concealed(v) if v.as_str() == "1234")
        );
        assert!(r.field("custom_1").is_some());
        assert_eq!(m.attachments.len(), 1);
        assert_eq!(m.attachments[0].0, o.id);
        assert_eq!(r.updated_at, now);
        // The other comes back archived and otherwise intact.
        let a = &m.archived[0];
        assert!(a.archived);
        assert_eq!(a.notes, "theirs\n\nMerged into GitHub");
        assert_eq!(password_of(a), Some("older-pw"));
        assert_eq!(a.attachments, o.attachments);
        assert_eq!(a.sections, o.sections);
        assert_eq!(a.id, o.id);
        assert_eq!(a.vault_id, o.vault_id);
    }

    #[test]
    fn merge_conflicts_become_labeled_extra_fields() {
        let now = datetime!(2026-11-03 12:00 UTC);
        let mut p = login("Bank", "alice", "pw", "https://bank.example");
        set(
            &mut p,
            "pin",
            FieldValue::Concealed(Zeroizing::new("1111".into())),
        );
        set(
            &mut p,
            "totp",
            FieldValue::Otp(Zeroizing::new("JBSWY3DPEHPK3PXP".into())),
        );
        let mut o = login("Bank 2", "alice", "pw", "https://bank.example");
        set(
            &mut o,
            "pin",
            FieldValue::Concealed(Zeroizing::new("2222".into())),
        );
        set(
            &mut o,
            "totp",
            FieldValue::Otp(Zeroizing::new("GEZDGNBVGY3TQOJQ".into())),
        );
        let m = merge(&p, &[&o], "", now);
        let extra = m
            .merged
            .sections
            .iter()
            .find(|s| s.id == MERGED_SECTION_ID)
            .unwrap();
        assert_eq!(extra.fields.len(), 2);
        assert!(extra.fields.iter().all(|f| !f.autofill && !f.required));
        let labels: Vec<&str> = extra.fields.iter().map(|f| f.label.as_str()).collect();
        assert_eq!(labels, vec!["TOTP (Bank 2)", "PIN (Bank 2)"]);
        assert!(
            extra
                .fields
                .iter()
                .any(|f| matches!(f.value, FieldValue::Otp(_)))
        );
        // The primary's own values are untouched; same password: no history.
        assert!(
            matches!(&m.merged.field("pin").unwrap().value, FieldValue::Concealed(v) if v.as_str() == "1111")
        );
        assert!(m.merged.password_history.is_empty());
        assert_eq!(m.archived[0].notes, "", "an empty note adds nothing");
        // Merging twice the same way adds nothing more.
        let again = merge(&m.merged, &[&o], "", now);
        assert_eq!(again.merged.sections, m.merged.sections);
    }

    #[test]
    fn same_totp_in_other_spelling_is_not_a_conflict() {
        let now = datetime!(2026-11-03 12:00 UTC);
        let mut p = login("A", "alice", "pw", "https://a.example");
        set(
            &mut p,
            "totp",
            FieldValue::Otp(Zeroizing::new("JBSWY3DPEHPK3PXP".into())),
        );
        let mut o = login("A", "alice", "pw", "https://a.example");
        set(
            &mut o,
            "totp",
            FieldValue::Otp(Zeroizing::new(
                "otpauth://totp/A?secret=JBSWY3DPEHPK3PXP".into(),
            )),
        );
        let m = merge(&p, &[&o], "", now);
        assert!(m.merged.sections.iter().all(|s| s.id != MERGED_SECTION_ID));
    }

    #[test]
    fn merge_of_three_keeps_every_password() {
        let now = datetime!(2026-11-03 12:00 UTC);
        let p = login("A", "alice", "p0", "https://a.example");
        let o1 = login("A", "alice", "p1", "https://a.example");
        let o2 = login("A", "alice", "p2", "https://a.example");
        let m = merge(&p, &[&o1, &o2, &p], "x", now);
        assert_eq!(m.archived.len(), 2, "the primary is never archived");
        let hist: BTreeSet<&str> = m
            .merged
            .password_history
            .iter()
            .map(|h| h.value.as_str())
            .collect();
        assert_eq!(hist, BTreeSet::from(["p1", "p2"]));
    }
}
