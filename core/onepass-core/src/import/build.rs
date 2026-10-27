//! Common builder of imported items (spec 4.2).
//!
//! A parser fills a [`Draft`] by template field id; [`Draft::finish`] turns
//! it into an item that always passes `model::validate`. Data with no
//! template slot lands in an `imported` section, never dropped. When the
//! item does not validate, the fallbacks run in order: move the offending
//! field to `imported`, turn a Login without username into a Password, and
//! finally turn the item into a SecureNote. Each fallback adds a warning
//! that carries a static code, never a value.

// The format parsers (tasks 2 to 9) are the callers; until they land, only
// the tests use the builder.
use time::{Date, Month, OffsetDateTime};
use zeroize::Zeroizing;

use crate::error::{Error, ValidationError};
use crate::id::Id;
use crate::model::checks::base32_secret_valid;
use crate::model::{
    Field, FieldType, FieldValue, Item, ItemType, ItemUrl, MatchRule, PasswordHistoryEntry,
    Section, new_item, template, validate,
};
use crate::totp::parse_otpauth;
pub(crate) use crate::watchtower::host::host_of;

use super::{Import, ImportedItem, Warning};

const IMPORTED_ID: &str = "imported";
const IMPORTED_LABEL: &str = "Importé";
const UNTITLED: &str = "Sans titre";
/// A custom field whose lower-cased label contains one of these is masked.
const SECRET_HINTS: [&str; 7] = ["pass", "secret", "pin", "code", "key", "cvv", "token"];

/// A value waiting for `finish`. A bare TOTP secret becomes an `otpauth`
/// URI there, once the title is known.
#[derive(Clone)]
enum Pending {
    Value(FieldValue),
    /// Normalized secret, and the source text kept for `imported` should
    /// the URI be refused.
    Base32 {
        secret: Zeroizing<String>,
        raw: Zeroizing<String>,
    },
}

/// An item under construction. Holds secrets: no `Debug`.
#[derive(Clone)]
pub(crate) struct Draft {
    kind: ItemType,
    title: String,
    notes: String,
    urls: Vec<String>,
    tags: Vec<String>,
    favorite: bool,
    archived: bool,
    folder: Option<String>,
    created: Option<OffsetDateTime>,
    updated: Option<OffsetDateTime>,
    expires: Option<Date>,
    history: Vec<PasswordHistoryEntry>,
    /// Template field id and value, in call order.
    values: Vec<(String, Pending)>,
    /// Label and value of custom fields for the `imported` section.
    extras: Vec<(String, FieldValue)>,
    /// Warnings raised while filling (`bad_date`, `totp_moved`).
    codes: Vec<&'static str>,
}

impl Draft {
    pub(crate) fn new(t: ItemType) -> Draft {
        Draft {
            kind: t,
            title: String::new(),
            notes: String::new(),
            urls: Vec::new(),
            tags: Vec::new(),
            favorite: false,
            archived: false,
            folder: None,
            created: None,
            updated: None,
            expires: None,
            history: Vec::new(),
            values: Vec::new(),
            extras: Vec::new(),
            codes: Vec::new(),
        }
    }

    pub(crate) fn title(&mut self, s: &str) {
        s.trim().clone_into(&mut self.title);
    }

    /// Appends, separated from earlier notes by a blank line.
    pub(crate) fn notes(&mut self, s: &str) {
        if s.trim().is_empty() {
            return;
        }
        if !self.notes.is_empty() {
            self.notes.push_str("\n\n");
        }
        self.notes.push_str(s);
    }

    /// The first URL is the primary one. Blank URLs are ignored.
    pub(crate) fn url(&mut self, s: &str) {
        let s = s.trim();
        if !s.is_empty() {
            self.urls.push(s.to_owned());
        }
    }

    pub(crate) fn tag(&mut self, s: &str) {
        let s = s.trim();
        if !s.is_empty() && !self.tags.iter().any(|t| t == s) {
            self.tags.push(s.to_owned());
        }
    }

    pub(crate) fn favorite(&mut self, b: bool) {
        self.favorite = b;
    }

    pub(crate) fn archived(&mut self, b: bool) {
        self.archived = b;
    }

    pub(crate) fn folder(&mut self, s: &str) {
        let s = s.trim();
        self.folder = (!s.is_empty()).then(|| s.to_owned());
    }

    pub(crate) fn created(&mut self, t: OffsetDateTime) {
        self.created = Some(t);
    }

    pub(crate) fn updated(&mut self, t: OffsetDateTime) {
        self.updated = Some(t);
    }

    pub(crate) fn expires(&mut self, d: Date) {
        self.expires = Some(d);
    }

    pub(crate) fn history(&mut self, pw: &str, at: OffsetDateTime) {
        if !pw.is_empty() {
            self.history.push(PasswordHistoryEntry {
                value: Zeroizing::new(pw.to_owned()),
                replaced_at: at,
            });
        }
    }

    /// Sets template field `id` from source text, converted to the field's
    /// kind. A blank value is ignored. A value that does not convert, or an
    /// id the template lacks, goes to `imported` (dates add `bad_date`, OTP
    /// values `totp_moved`).
    pub(crate) fn set(&mut self, id: &str, raw: &str) {
        if raw.trim().is_empty() {
            return;
        }
        let Some((kind, label)) = slot(self.kind, id) else {
            self.extra(id, raw, false);
            return;
        };
        match convert(kind, raw) {
            Some(p) => self.values.push((id.to_owned(), p)),
            None if kind == FieldType::Otp => {
                self.extra("TOTP", raw, true);
                self.codes.push("totp_moved");
            }
            None => {
                if matches!(kind, FieldType::Date | FieldType::MonthYear) {
                    self.codes.push("bad_date");
                }
                self.extra(&label, raw, is_secret_kind(kind));
            }
        }
    }

    /// Sets template field `id` to an already built value (passkey,
    /// location, barcode, SSH key, address). A value whose kind does not
    /// match the template field, or an unknown id, goes to `imported`.
    pub(crate) fn set_value(&mut self, id: &str, v: FieldValue) {
        if kind_of(&v).is_none() {
            return;
        }
        match slot(self.kind, id) {
            Some(_) => self.values.push((id.to_owned(), Pending::Value(v))),
            None => self.extras.push((id.to_owned(), v)),
        }
    }

    /// A source date or timestamp that does not parse: kept as text in
    /// `imported` under `label`, with a `bad_date` warning. Blank is ignored.
    pub(crate) fn bad_value(&mut self, label: &str, raw: &str) {
        if raw.trim().is_empty() {
            return;
        }
        self.extras
            .push((label.to_owned(), FieldValue::Text(raw.to_owned())));
        self.codes.push("bad_date");
    }

    /// Custom field for the `imported` section, masked when `secret` or
    /// when the label looks like a secret. A blank value is ignored.
    pub(crate) fn extra(&mut self, label: &str, raw: &str, secret: bool) {
        if raw.trim().is_empty() {
            return;
        }
        let lower = label.to_lowercase();
        let value = if secret || SECRET_HINTS.iter().any(|h| lower.contains(h)) {
            FieldValue::Concealed(Zeroizing::new(raw.to_owned()))
        } else {
            FieldValue::Text(raw.to_owned())
        };
        self.extras.push((label.to_owned(), value));
    }

    /// Builds the item, applies the fallbacks, and appends it with its
    /// warnings (tagged `entry`) to `out`.
    pub(crate) fn finish(self, entry: u32, out: &mut Import) {
        let folder = self.folder.clone();
        let mut codes = Vec::new();
        let item = self.built(&mut codes);
        out.warnings
            .extend(codes.into_iter().map(|code| Warning { entry, code }));
        out.items.push(ImportedItem { item, folder });
    }

    /// The final, valid item; warning codes are appended to `codes`.
    fn built(self, codes: &mut Vec<&'static str>) -> Item {
        let Draft {
            kind,
            title,
            notes,
            urls,
            tags,
            favorite,
            archived,
            folder: _,
            created,
            updated,
            expires,
            history,
            values,
            extras,
            codes: fill_codes,
        } = self;
        codes.extend(fill_codes);
        let title = if title.is_empty() {
            urls.first()
                .and_then(|u| host_of(u))
                .unwrap_or_else(|| UNTITLED.to_owned())
        } else {
            title
        };
        let mut item = new_item(kind, Id([0; 16]), &title);
        item.notes = notes;
        item.urls = urls
            .into_iter()
            .enumerate()
            .map(|(i, url)| ItemUrl {
                label: String::new(),
                url,
                rule: MatchRule::Domain,
                primary: i == 0,
            })
            .collect();
        item.tags = tags;
        item.favorite = favorite;
        item.archived = archived;
        if let Some(t) = created {
            item.created_at = t;
            item.updated_at = t;
        }
        if let Some(t) = updated {
            item.updated_at = t;
        }
        item.expires = expires;
        item.password_history = history;
        for (label, value) in extras {
            push_imported(&mut item, label, value);
        }
        for (id, pending) in values {
            let value = match pending {
                Pending::Value(v) => v,
                Pending::Base32 { secret, raw } => {
                    let uri = Zeroizing::new(otpauth_from_parts(
                        &secret,
                        None,
                        Some(&item.title),
                        "SHA1",
                        6,
                        30,
                    ));
                    if parse_otpauth(&uri).is_err() {
                        codes.push("totp_moved");
                        push_imported(&mut item, "TOTP".to_owned(), FieldValue::Concealed(raw));
                        continue;
                    }
                    FieldValue::Otp(uri)
                }
            };
            place(&mut item, &id, value);
        }
        settle(&mut item, codes);
        item
    }
}

/// Kind and label of template field `id`.
fn slot(t: ItemType, id: &str) -> Option<(FieldType, String)> {
    template(t)
        .into_iter()
        .flat_map(|s| s.fields)
        .find(|f| f.id == id)
        .map(|f| (f.kind, f.label))
}

fn is_secret_kind(k: FieldType) -> bool {
    matches!(
        k,
        FieldType::Concealed | FieldType::Password | FieldType::Mnemonic | FieldType::Otp
    )
}

fn kind_of(v: &FieldValue) -> Option<FieldType> {
    Some(match v {
        FieldValue::Text(_) => FieldType::Text,
        FieldValue::Concealed(_) => FieldType::Concealed,
        FieldValue::Password(_) => FieldType::Password,
        FieldValue::Url(_) => FieldType::Url,
        FieldValue::Email(_) => FieldType::Email,
        FieldValue::Phone(_) => FieldType::Phone,
        FieldValue::Date(_) => FieldType::Date,
        FieldValue::MonthYear { .. } => FieldType::MonthYear,
        FieldValue::Number(_) => FieldType::Number,
        FieldValue::Money { .. } => FieldType::Money,
        FieldValue::Address(_) => FieldType::Address,
        FieldValue::Menu(_) => FieldType::Menu,
        FieldValue::Otp(_) => FieldType::Otp,
        FieldValue::Passkey(_) => FieldType::Passkey,
        FieldValue::SshKey(_) => FieldType::SshKey,
        FieldValue::File(_) => FieldType::File,
        FieldValue::Location(_) => FieldType::Location,
        FieldValue::Mnemonic(_) => FieldType::Mnemonic,
        FieldValue::Barcode { .. } => FieldType::Barcode,
        FieldValue::ItemLink(_) => FieldType::ItemLink,
        FieldValue::Empty => return None,
    })
}

/// Source text converted to a value of kind `k`, `None` when it does not
/// convert or the kind has no text form.
fn convert(k: FieldType, raw: &str) -> Option<Pending> {
    let t = raw.trim();
    let secret = || Zeroizing::new(raw.to_owned());
    let v = match k {
        FieldType::Text => FieldValue::Text(raw.to_owned()),
        FieldType::Menu => FieldValue::Menu(t.to_owned()),
        FieldType::Concealed => FieldValue::Concealed(secret()),
        FieldType::Password => FieldValue::Password(secret()),
        FieldType::Mnemonic => FieldValue::Mnemonic(secret()),
        FieldType::Url => FieldValue::Url(t.to_owned()),
        FieldType::Email => FieldValue::Email(t.to_owned()),
        FieldType::Phone => FieldValue::Phone(t.to_owned()),
        FieldType::Date => FieldValue::Date(parse_date(t)?),
        FieldType::MonthYear => {
            let (year, month) = parse_month_year(t)?;
            FieldValue::MonthYear { year, month }
        }
        FieldType::Number => FieldValue::Number(t.parse().ok()?),
        FieldType::Otp => return totp(raw),
        _ => return None,
    };
    Some(Pending::Value(v))
}

/// An `otpauth://` URI that parses is kept; a bare base32 secret waits for
/// the title (spaces and dashes dropped, upper case, padding removed).
fn totp(raw: &str) -> Option<Pending> {
    let t = raw.trim();
    if t.get(..10)
        .is_some_and(|p| p.eq_ignore_ascii_case("otpauth://"))
    {
        return parse_otpauth(t)
            .is_ok()
            .then(|| Pending::Value(FieldValue::Otp(Zeroizing::new(t.to_owned()))));
    }
    if !base32_secret_valid(t) {
        return None;
    }
    let mut s = Zeroizing::new(String::with_capacity(t.len()));
    s.extend(
        t.chars()
            .filter(|c| !c.is_whitespace() && *c != '-' && *c != '=')
            .map(|c| c.to_ascii_uppercase()),
    );
    Some(Pending::Base32 {
        secret: s,
        raw: Zeroizing::new(raw.to_owned()),
    })
}

/// All-digit text of `len` characters (any length when `len` is empty).
fn digits<T: std::str::FromStr>(s: &str, len: std::ops::RangeInclusive<usize>) -> Option<T> {
    (len.contains(&s.len()) && s.bytes().all(|b| b.is_ascii_digit()))
        .then(|| s.parse().ok())
        .flatten()
}

/// `YYYY-MM-DD`, `DD/MM/YYYY`, `YYYYMMDD`, or Unix seconds (9 to 12
/// digits). Any other digit string is refused rather than guessed.
fn parse_date(s: &str) -> Option<Date> {
    let ymd = |y: &str, m: &str, d: &str| -> Option<Date> {
        let month = Month::try_from(digits::<u8>(m, 1..=2)?).ok()?;
        Date::from_calendar_date(digits(y, 4..=4)?, month, digits(d, 1..=2)?).ok()
    };
    if s.len() == 8 && s.bytes().all(|b| b.is_ascii_digit()) {
        return ymd(s.get(..4)?, s.get(4..6)?, s.get(6..)?);
    }
    if let Some(secs) = digits::<i64>(s, 9..=12) {
        return OffsetDateTime::from_unix_timestamp(secs)
            .ok()
            .map(|t| t.date());
    }
    let parts: Vec<&str> = s.split('-').collect();
    if let [y, m, d] = parts.as_slice() {
        return ymd(y, m, d);
    }
    let parts: Vec<&str> = s.split('/').collect();
    if let [d, m, y] = parts.as_slice() {
        return ymd(y, m, d);
    }
    None
}

/// `MM/YYYY`, `MM/YY` (20YY), `YYYY-MM`, or `YYYYMM`.
fn parse_month_year(s: &str) -> Option<(u16, u8)> {
    let (year, month): (u16, u8) = if let Some((m, y)) = s.split_once('/') {
        let year = match y.len() {
            2 => 2000 + digits::<u16>(y, 2..=2)?,
            _ => digits(y, 4..=4)?,
        };
        (year, digits(m, 1..=2)?)
    } else if let Some((y, m)) = s.split_once('-') {
        (digits(y, 4..=4)?, digits(m, 1..=2)?)
    } else {
        let y = s.get(..4)?;
        let m = s.get(4..)?;
        (digits(y, 4..=4)?, digits(m, 2..=2)?)
    };
    ((1..=12).contains(&month) && year >= 1000).then_some((year, month))
}

fn unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
}

/// Length of `s` once percent-encoded.
fn encoded_len(s: &str) -> usize {
    s.bytes().map(|b| if unreserved(b) { 1 } else { 3 }).sum()
}

/// Percent-encodes `s` into `out`, keeping RFC 3986 unreserved characters.
/// Writes in place: no temporary copy of the input.
fn encode_into(out: &mut String, s: &str) {
    for b in s.bytes() {
        if unreserved(b) {
            out.push(char::from(b));
        } else {
            let hex = |n: u8| {
                char::from_digit(u32::from(n), 16)
                    .unwrap_or('0')
                    .to_ascii_uppercase()
            };
            out.push('%');
            out.push(hex(b >> 4));
            out.push(hex(b & 0x0f));
        }
    }
}

/// `otpauth://totp/<issuer>:<account>?secret=...&issuer=...&algorithm=...
/// &digits=...&period=...`. Blank issuer or account parts are left out.
/// The URI is written into one buffer sized up front, so the secret is
/// never left behind in a reallocated or temporary string.
pub(crate) fn otpauth_from_parts(
    secret_b32: &str,
    issuer: Option<&str>,
    account: Option<&str>,
    algorithm: &str,
    digits: u8,
    period: u32,
) -> String {
    use std::fmt::Write;

    let issuer = issuer.map(str::trim).filter(|s| !s.is_empty());
    let account = account.map(str::trim).filter(|s| !s.is_empty());
    let issuer_len = issuer.map_or(0, encoded_len);
    // Fixed text, the variable parts, and room for the two numbers.
    let capacity = "otpauth://totp/:?secret=&issuer=&algorithm=&digits=&period=".len()
        + 2 * issuer_len
        + account.map_or(0, encoded_len)
        + encoded_len(secret_b32)
        + encoded_len(algorithm)
        + 3
        + 10;
    let mut uri = Zeroizing::new(String::with_capacity(capacity));
    uri.push_str("otpauth://totp/");
    if let Some(i) = issuer {
        encode_into(&mut uri, i);
        if account.is_some() {
            uri.push(':');
        }
    }
    if let Some(a) = account {
        encode_into(&mut uri, a);
    }
    uri.push_str("?secret=");
    encode_into(&mut uri, secret_b32);
    if let Some(i) = issuer {
        uri.push_str("&issuer=");
        encode_into(&mut uri, i);
    }
    uri.push_str("&algorithm=");
    encode_into(&mut uri, algorithm);
    // Integers are formatted on the stack, straight into the buffer.
    let _ = write!(uri, "&digits={digits}&period={period}");
    // Moves the allocation out; the emptied wrapper has nothing to wipe.
    std::mem::take(&mut *uri)
}

fn is_filled(v: &FieldValue) -> bool {
    match v {
        FieldValue::Empty => false,
        FieldValue::Text(s)
        | FieldValue::Url(s)
        | FieldValue::Email(s)
        | FieldValue::Phone(s)
        | FieldValue::Menu(s) => !s.trim().is_empty(),
        FieldValue::Concealed(s)
        | FieldValue::Password(s)
        | FieldValue::Mnemonic(s)
        | FieldValue::Otp(s) => !s.trim().is_empty(),
        _ => true,
    }
}

/// Appends a custom field to the `imported` section, created on first use.
/// Ids are `imported_<n>`, numbered from 1 and never reused.
fn push_imported(item: &mut Item, label: String, value: FieldValue) {
    let Some(kind) = kind_of(&value) else {
        return;
    };
    let pos = match item.sections.iter().position(|s| s.id == IMPORTED_ID) {
        Some(p) => p,
        None => {
            item.sections.push(Section {
                id: IMPORTED_ID.to_owned(),
                label: IMPORTED_LABEL.to_owned(),
                fields: Vec::new(),
            });
            item.sections.len() - 1
        }
    };
    let Some(section) = item.sections.get_mut(pos) else {
        return;
    };
    let id = format!("{IMPORTED_ID}_{}", section.fields.len() + 1);
    section.fields.push(Field {
        id,
        label,
        kind,
        value,
        required: false,
        repeatable: false,
        autofill: false,
    });
}

/// Fills template field `id`. A repeatable field already filled gets a
/// copy right after its last occurrence; any other clash, a kind mismatch
/// or an unknown id goes to `imported`.
fn place(item: &mut Item, id: &str, value: FieldValue) {
    let mut target = None;
    for (si, s) in item.sections.iter().enumerate() {
        if s.id == IMPORTED_ID {
            continue;
        }
        for (fi, f) in s.fields.iter().enumerate() {
            if f.id == id {
                target = Some((si, fi));
            }
        }
    }
    let Some((si, fi)) = target else {
        push_imported(item, id.to_owned(), value);
        return;
    };
    let Some(section) = item.sections.get_mut(si) else {
        return;
    };
    let Some(field) = section.fields.get_mut(fi) else {
        return;
    };
    if kind_of(&value) != Some(field.kind) {
        let label = field.label.clone();
        push_imported(item, label, value);
    } else if !is_filled(&field.value) {
        field.value = value;
    } else if field.repeatable {
        let mut copy = field.clone();
        copy.value = value;
        section.fields.insert(fi + 1, copy);
    } else {
        let label = field.label.clone();
        push_imported(item, label, value);
    }
}

/// Positions (section, field) of the filled occurrences of template
/// field `id`, outside `imported`.
fn filled_occurrences(item: &Item, id: &str) -> Vec<(usize, usize)> {
    let mut found = Vec::new();
    for (si, s) in item.sections.iter().enumerate() {
        if s.id == IMPORTED_ID {
            continue;
        }
        for (fi, f) in s.fields.iter().enumerate() {
            if f.id == id && is_filled(&f.value) {
                found.push((si, fi));
            }
        }
    }
    found
}

/// Whether the occurrence at `at` alone makes `validate` fail on `id` with
/// `reason`: probed on a copy where it is the only occurrence of `id`,
/// moved into the template slot.
fn occurrence_fails(item: &Item, id: &str, reason: &str, at: (usize, usize)) -> bool {
    let Some(value) = item
        .sections
        .get(at.0)
        .and_then(|s| s.fields.get(at.1))
        .map(|f| f.value.clone())
    else {
        return false;
    };
    let mut probe = item.clone();
    let mut first = true;
    for s in probe.sections.iter_mut().filter(|s| s.id != IMPORTED_ID) {
        s.fields.retain_mut(|f| {
            if f.id != id {
                return true;
            }
            if first {
                first = false;
                f.value = value.clone();
                return true;
            }
            false
        });
    }
    matches!(
        validate(&probe),
        Err(Error::Validation(ValidationError { field, reason: r })) if field == id && r == reason
    )
}

/// Moves the occurrence of template field `id` that fails validation with
/// `reason` to `imported` (the first filled one when none can be singled
/// out): the template field is emptied, a repeatable copy is removed.
/// False when no occurrence holds a value.
fn move_field(item: &mut Item, id: &str, reason: &str) -> bool {
    let filled = filled_occurrences(item, id);
    let target = match filled.as_slice() {
        [] => return false,
        [only] => *only,
        [first, ..] => filled
            .iter()
            .copied()
            .find(|at| occurrence_fails(item, id, reason, *at))
            .unwrap_or(*first),
    };
    let (si, fi) = target;
    let Some(section) = item.sections.get_mut(si) else {
        return false;
    };
    let is_copy = section.fields.iter().take(fi).any(|g| g.id == id);
    let field = if is_copy {
        if fi >= section.fields.len() {
            return false;
        }
        section.fields.remove(fi)
    } else {
        let Some(f) = section.fields.get_mut(fi) else {
            return false;
        };
        let mut moved = f.clone();
        moved.value = std::mem::replace(&mut f.value, FieldValue::Empty);
        moved
    };
    push_imported(item, field.label, field.value);
    true
}

/// Changes the item type. Filled fields whose id is in `keep` go to the
/// same id in the new template; every other filled field goes to
/// `imported`, which is kept.
fn retype(item: &mut Item, t: ItemType, keep: &[&str]) {
    let old = std::mem::take(&mut item.sections);
    let mut imported = None;
    let mut moved = Vec::new();
    for s in old {
        if s.id == IMPORTED_ID {
            imported = Some(s);
        } else {
            moved.extend(s.fields.into_iter().filter(|f| is_filled(&f.value)));
        }
    }
    item.item_type = t;
    item.sections = template(t);
    item.sections.extend(imported);
    for f in moved {
        let slot = keep
            .contains(&f.id.as_str())
            .then(|| item.field_mut(&f.id))
            .flatten()
            .filter(|g| g.kind == f.kind && !is_filled(&g.value));
        match slot {
            Some(g) => g.value = f.value,
            None => push_imported(item, f.label, f.value),
        }
    }
}

/// SecureNote fallback: content is the notes (moved out of `notes`), or
/// the title when there are none.
fn to_secure_note(item: &mut Item) {
    retype(item, ItemType::SecureNote, &[]);
    let content = if item.notes.trim().is_empty() {
        item.title.clone()
    } else {
        std::mem::take(&mut item.notes)
    };
    if let Some(f) = item.field_mut("content") {
        f.value = FieldValue::Text(content);
    }
}

fn has_value(item: &Item, id: &str) -> bool {
    item.sections
        .iter()
        .filter(|s| s.id != IMPORTED_ID)
        .flat_map(|s| s.fields.iter())
        .any(|f| f.id == id && is_filled(&f.value))
}

/// Applies the spec 4.2 fallbacks until the item validates. Bounded: one
/// round per field plus three; a SecureNote with a non-blank title and
/// content always validates, which is the last resort.
fn settle(item: &mut Item, codes: &mut Vec<&'static str>) {
    if item.title.trim().is_empty() {
        item.title = UNTITLED.to_owned();
    }
    let rounds = item.sections.iter().map(|s| s.fields.len()).sum::<usize>() + 3;
    for _ in 0..rounds {
        let failing = match validate(item) {
            Ok(()) => return,
            Err(Error::Validation(ValidationError { field, reason })) => Some((field, reason)),
            Err(_) => None,
        };
        if failing.is_some_and(|(f, r)| move_field(item, &f, r)) {
            codes.push("field_moved");
            continue;
        }
        if item.item_type == ItemType::Login
            && !has_value(item, "username")
            && has_value(item, "password")
        {
            retype(item, ItemType::Password, &["password"]);
            codes.push("login_to_password");
            continue;
        }
        to_secure_note(item);
        codes.push("to_secure_note");
    }
    if validate(item).is_err() {
        to_secure_note(item);
        codes.push("to_secure_note");
    }
}

#[cfg(test)]
mod tests {
    use time::macros::{date, datetime};
    use zeroize::Zeroizing;

    use super::*;
    use crate::model::{FieldType, FieldValue, ItemType, validate};
    use crate::totp::parse_otpauth;

    fn one(d: Draft) -> (Item, Vec<&'static str>) {
        let mut out = Import::default();
        d.finish(7, &mut out);
        assert_eq!(out.items.len(), 1);
        assert!(out.warnings.iter().all(|w| w.entry == 7));
        let codes = out.warnings.iter().map(|w| w.code).collect();
        let item = out.items.pop().unwrap().item;
        validate(&item).unwrap();
        (item, codes)
    }

    fn imported(item: &Item) -> Vec<&Field> {
        item.sections
            .iter()
            .filter(|s| s.id == "imported")
            .flat_map(|s| s.fields.iter())
            .collect()
    }

    fn secret(s: &str) -> Zeroizing<String> {
        Zeroizing::new(s.into())
    }

    #[test]
    fn login_full() {
        let mut d = Draft::new(ItemType::Login);
        d.title("Example");
        d.set("username", "alice@example.com");
        d.set("password", "Pw-1");
        d.url("https://example.com/login");
        d.set("totp", "JBSWY3DPEHPK3PXP");
        let (item, codes) = one(d);
        assert_eq!(item.item_type, ItemType::Login);
        assert_eq!(item.vault_id, Id([0; 16]));
        assert_eq!(item.title, "Example");
        assert_eq!(
            item.field("password").unwrap().value,
            FieldValue::Password(secret("Pw-1"))
        );
        let FieldValue::Otp(uri) = &item.field("totp").unwrap().value else {
            panic!("totp is not an otp value");
        };
        assert!(uri.starts_with("otpauth://totp/"));
        let cfg = parse_otpauth(uri).unwrap();
        assert_eq!(cfg.account.as_deref(), Some("Example"));
        assert_eq!(item.urls.len(), 1);
        assert!(item.urls[0].primary);
        assert_eq!(item.urls[0].rule, MatchRule::Domain);
        assert!(codes.is_empty(), "{codes:?}");
        assert!(imported(&item).is_empty());
    }

    #[test]
    fn otpauth_value_is_kept() {
        let uri = "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example";
        let mut d = Draft::new(ItemType::Login);
        d.title("t");
        d.set("username", "alice");
        d.set("totp", uri);
        let (item, codes) = one(d);
        assert_eq!(
            item.field("totp").unwrap().value,
            FieldValue::Otp(secret(uri))
        );
        assert!(codes.is_empty());
    }

    #[test]
    fn bad_totp_moves_to_imported() {
        let mut d = Draft::new(ItemType::Login);
        d.title("t");
        d.set("username", "alice");
        d.set("totp", "not base32 !");
        let (item, codes) = one(d);
        assert_eq!(item.field("totp").unwrap().value, FieldValue::Empty);
        let extra = imported(&item);
        assert_eq!(extra.len(), 1);
        assert_eq!(extra[0].label, "TOTP");
        assert_eq!(extra[0].kind, FieldType::Concealed);
        assert_eq!(codes, vec!["totp_moved"]);
    }

    #[test]
    fn login_without_username_becomes_password() {
        let mut d = Draft::new(ItemType::Login);
        d.title("Example");
        d.set("password", "Pw-1");
        d.url("https://example.com");
        let (item, codes) = one(d);
        assert_eq!(item.item_type, ItemType::Password);
        assert_eq!(
            item.field("password").unwrap().value,
            FieldValue::Password(secret("Pw-1"))
        );
        assert_eq!(item.urls[0].url, "https://example.com");
        assert_eq!(codes, vec!["login_to_password"]);
    }

    #[test]
    fn nothing_required_becomes_secure_note() {
        let mut d = Draft::new(ItemType::Login);
        d.title("Example");
        d.notes("n");
        let (item, codes) = one(d);
        assert_eq!(item.item_type, ItemType::SecureNote);
        assert_eq!(
            item.field("content").unwrap().value,
            FieldValue::Text("n".into())
        );
        assert_eq!(codes, vec!["to_secure_note"]);
    }

    #[test]
    fn secure_note_without_notes_uses_title() {
        let mut d = Draft::new(ItemType::Login);
        d.title("Only a title");
        d.set("email", "alice@example.com");
        let (item, _) = one(d);
        assert_eq!(item.item_type, ItemType::SecureNote);
        assert_eq!(
            item.field("content").unwrap().value,
            FieldValue::Text("Only a title".into())
        );
        // The email has no slot in a note: it is kept in `imported`.
        let extra = imported(&item);
        assert_eq!(extra.len(), 1);
        assert_eq!(
            extra[0].value,
            FieldValue::Email("alice@example.com".into())
        );
    }

    #[test]
    fn bad_card_number_moves_to_imported() {
        let mut d = Draft::new(ItemType::CreditCard);
        d.title("Card");
        d.set("cardholder", "Q Caron");
        d.set("number", "1234");
        d.set("expiry", "12/2030");
        let (item, codes) = one(d);
        assert_eq!(item.item_type, ItemType::SecureNote);
        let extra = imported(&item);
        let number = extra
            .iter()
            .find(|f| f.value == FieldValue::Concealed(secret("1234")))
            .expect("number kept in imported");
        assert_eq!(number.kind, FieldType::Concealed);
        assert!(
            extra
                .iter()
                .any(|f| f.value == FieldValue::Text("Q Caron".into()))
        );
        assert!(extra.iter().any(|f| f.value
            == FieldValue::MonthYear {
                year: 2030,
                month: 12
            }));
        assert_eq!(codes, vec!["field_moved", "to_secure_note"]);
        let mut ids: Vec<&str> = extra.iter().map(|f| f.id.as_str()).collect();
        ids.dedup();
        assert_eq!(ids.len(), extra.len(), "imported ids are unique");
    }

    #[test]
    fn valid_card_stays_a_card() {
        let mut d = Draft::new(ItemType::CreditCard);
        d.title("Card");
        d.set("cardholder", "Q Caron");
        d.set("number", "4111 1111 1111 1111");
        d.set("expiry", "2030-12");
        let (item, codes) = one(d);
        assert_eq!(item.item_type, ItemType::CreditCard);
        assert!(codes.is_empty());
    }

    #[test]
    fn unknown_field_goes_to_extra() {
        let mut d = Draft::new(ItemType::Login);
        d.title("t");
        d.set("username", "alice");
        d.set("favourite_colour", "blue");
        d.set("password", "");
        let (item, codes) = one(d);
        let extra = imported(&item);
        assert_eq!(extra.len(), 1);
        assert_eq!(extra[0].id, "imported_1");
        assert_eq!(extra[0].label, "favourite_colour");
        assert_eq!(extra[0].kind, FieldType::Text);
        assert_eq!(extra[0].value, FieldValue::Text("blue".into()));
        assert_eq!(item.field("password").unwrap().value, FieldValue::Empty);
        assert!(codes.is_empty());
        let section = item.sections.iter().find(|s| s.id == "imported").unwrap();
        assert_eq!(section.label, "Importé");
    }

    #[test]
    fn secret_like_label_is_concealed() {
        let mut d = Draft::new(ItemType::Login);
        d.title("t");
        d.set("username", "alice");
        d.extra("API token", "x", false);
        d.extra("Comment", "y", false);
        d.extra("Comment", "z", true);
        d.extra("Empty", "  ", true);
        let (item, _) = one(d);
        let extra = imported(&item);
        let kinds: Vec<FieldType> = extra.iter().map(|f| f.kind).collect();
        assert_eq!(
            kinds,
            vec![FieldType::Concealed, FieldType::Text, FieldType::Concealed]
        );
        assert_eq!(extra[0].value, FieldValue::Concealed(secret("x")));
        let ids: Vec<&str> = extra.iter().map(|f| f.id.as_str()).collect();
        assert_eq!(ids, vec!["imported_1", "imported_2", "imported_3"]);
    }

    /// A valid card except for what the test sets.
    fn card() -> Draft {
        let mut d = Draft::new(ItemType::CreditCard);
        d.title("Card");
        d.set("cardholder", "Q Caron");
        d.set("number", "4111111111111111");
        d
    }

    #[test]
    fn month_year_formats() {
        for raw in ["03/2031", "03/31", "2031-03", "203103", "3/2031"] {
            let mut d = card();
            d.set("expiry", raw);
            let (item, codes) = one(d);
            assert_eq!(item.item_type, ItemType::CreditCard, "{raw}");
            assert_eq!(
                item.field("expiry").unwrap().value,
                FieldValue::MonthYear {
                    year: 2031,
                    month: 3
                },
                "{raw}"
            );
            assert!(codes.is_empty(), "{raw}");
        }
        for raw in ["13/2031", "00/2031", "2031-13", "march", "03/2031/1"] {
            let mut d = card();
            d.set("expiry", raw);
            let (item, codes) = one(d);
            // `expiry` is required: without it the card becomes a note.
            assert_eq!(item.item_type, ItemType::SecureNote, "{raw}");
            let extra = imported(&item);
            let kept = extra.iter().find(|f| f.label == "Expiration").unwrap();
            assert_eq!(kept.value, FieldValue::Text(raw.into()), "{raw}");
            assert_eq!(codes, vec!["bad_date", "to_secure_note"], "{raw}");
        }
    }

    #[test]
    fn date_formats() {
        for raw in ["2030-01-31", "31/01/2030", "1896048000"] {
            let mut d = card();
            d.set("expiry", "01/2031");
            d.set("issued_on", raw);
            let (item, codes) = one(d);
            assert_eq!(
                item.field("issued_on").unwrap().value,
                FieldValue::Date(date!(2030 - 01 - 31)),
                "{raw}"
            );
            assert!(codes.is_empty(), "{raw}");
        }
        let mut d = card();
        d.set("expiry", "01/2031");
        d.set("issued_on", "2030-02-30");
        let (item, codes) = one(d);
        assert_eq!(item.field("issued_on").unwrap().value, FieldValue::Empty);
        assert_eq!(imported(&item).len(), 1);
        assert_eq!(codes, vec!["bad_date"]);
    }

    #[test]
    fn ambiguous_digit_dates() {
        let cases = [
            ("20300131", Some(date!(2030 - 01 - 31))),
            ("1700000000", Some(date!(2023 - 11 - 14))),
            ("2030", None),
            ("123", None),
            ("1234567890123", None),
            ("20301331", None),
        ];
        for (raw, want) in cases {
            let mut d = card();
            d.set("expiry", "01/2031");
            d.set("issued_on", raw);
            let (item, codes) = one(d);
            match want {
                Some(day) => {
                    assert_eq!(
                        item.field("issued_on").unwrap().value,
                        FieldValue::Date(day),
                        "{raw}"
                    );
                    assert!(codes.is_empty(), "{raw}");
                }
                None => {
                    assert_eq!(item.field("issued_on").unwrap().value, FieldValue::Empty);
                    let extra = imported(&item);
                    assert_eq!(extra.len(), 1, "{raw}");
                    assert_eq!(extra[0].value, FieldValue::Text(raw.into()), "{raw}");
                    assert_eq!(codes, vec!["bad_date"], "{raw}");
                }
            }
        }
    }

    #[test]
    fn bad_value_keeps_text_and_warns() {
        let mut d = Draft::new(ItemType::Login);
        d.title("t");
        d.set("username", "alice");
        d.bad_value("timeCreated", "yesterday");
        d.bad_value("timeCreated", " ");
        let (item, codes) = one(d);
        let extra = imported(&item);
        assert_eq!(extra.len(), 1);
        assert_eq!(extra[0].label, "timeCreated");
        assert_eq!(extra[0].value, FieldValue::Text("yesterday".into()));
        assert_eq!(codes, vec!["bad_date"]);
    }

    #[test]
    fn move_field_takes_the_failing_occurrence() {
        let mut item = crate::model::new_item(ItemType::CreditCard, Id([0; 16]), "Card");
        item.field_mut("cardholder").unwrap().value = FieldValue::Text("Q Caron".into());
        item.field_mut("expiry").unwrap().value = FieldValue::MonthYear {
            year: 2031,
            month: 1,
        };
        let number = item.field_mut("number").unwrap();
        number.value = FieldValue::Concealed(secret("4111111111111111"));
        number.repeatable = true;
        let mut copy = number.clone();
        copy.value = FieldValue::Concealed(secret("1234"));
        let at = item.sections[0]
            .fields
            .iter()
            .position(|f| f.id == "number")
            .unwrap();
        item.sections[0].fields.insert(at + 1, copy);
        let mut codes = Vec::new();
        settle(&mut item, &mut codes);
        assert_eq!(codes, vec!["field_moved"]);
        assert_eq!(item.item_type, ItemType::CreditCard);
        assert_eq!(
            item.field("number").unwrap().value,
            FieldValue::Concealed(secret("4111111111111111"))
        );
        let extra = imported(&item);
        assert_eq!(extra.len(), 1);
        assert_eq!(extra[0].value, FieldValue::Concealed(secret("1234")));
    }

    #[test]
    fn otpauth_buffer_is_not_reallocated() {
        let uri = otpauth_from_parts(
            "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
            Some("Exämple & Co"),
            Some("alice@example.com"),
            "SHA1",
            6,
            30,
        );
        // Sized up front: only the slack reserved for the two numbers is
        // left, a reallocation would at least double the capacity.
        assert!(uri.capacity() >= uri.len());
        assert!(uri.capacity() - uri.len() <= 13, "{}", uri.capacity());
        let cfg = parse_otpauth(&uri).unwrap();
        assert_eq!(cfg.issuer.as_deref(), Some("Exämple & Co"));
    }

    #[test]
    fn number_and_text_kinds() {
        let mut d = Draft::new(ItemType::Server);
        d.title("db");
        d.set("host", "db.example.net");
        d.set("port", "5432");
        d.set("protocol", "ssh");
        let (item, codes) = one(d);
        assert_eq!(item.field("port").unwrap().value, FieldValue::Number(5432));
        assert_eq!(
            item.field("protocol").unwrap().value,
            FieldValue::Menu("ssh".into())
        );
        assert!(codes.is_empty());
        let mut d2 = Draft::new(ItemType::Server);
        d2.title("db");
        d2.set("host", "db.example.net");
        d2.set("port", "not a port");
        let (item, codes) = one(d2);
        assert_eq!(item.field("port").unwrap().value, FieldValue::Empty);
        assert_eq!(imported(&item).len(), 1);
        assert!(codes.is_empty());
    }

    #[test]
    fn repeatable_values_follow_the_first() {
        let mut d = Draft::new(ItemType::Login);
        d.title("t");
        d.set("username", "alice");
        d.set("backup_codes", "c1");
        d.set("backup_codes", "c2");
        d.set("backup_codes", "c3");
        d.set("pin", "1111");
        d.set("pin", "2222");
        let (item, _) = one(d);
        let fields = &item.sections[0].fields;
        let at = fields.iter().position(|f| f.id == "backup_codes").unwrap();
        let values: Vec<&FieldValue> = fields[at..at + 3].iter().map(|f| &f.value).collect();
        assert_eq!(
            values,
            vec![
                &FieldValue::Concealed(secret("c1")),
                &FieldValue::Concealed(secret("c2")),
                &FieldValue::Concealed(secret("c3")),
            ]
        );
        assert!(fields[at..at + 3].iter().all(|f| f.id == "backup_codes"));
        // `pin` is not repeatable: the second value is kept in `imported`.
        assert_eq!(
            item.field("pin").unwrap().value,
            FieldValue::Concealed(secret("1111"))
        );
        let extra = imported(&item);
        assert_eq!(extra.len(), 1);
        assert_eq!(extra[0].value, FieldValue::Concealed(secret("2222")));
    }

    #[test]
    fn metadata_is_copied() {
        let created = datetime!(2020-01-02 03:04:05 UTC);
        let updated = datetime!(2021-01-02 03:04:05 UTC);
        let mut d = Draft::new(ItemType::Login);
        d.title("t");
        d.set("username", "alice");
        d.notes("a");
        d.notes("");
        d.notes("b");
        d.url("");
        d.url("https://example.com");
        d.url("https://example.org");
        d.tag("work");
        d.tag("");
        d.favorite(true);
        d.archived(true);
        d.folder("Perso");
        d.created(created);
        d.updated(updated);
        d.expires(date!(2031 - 03 - 01));
        d.history("old", created);
        let mut out = Import::default();
        d.finish(0, &mut out);
        let ImportedItem { item, folder } = out.items.pop().unwrap();
        assert_eq!(folder.as_deref(), Some("Perso"));
        assert_eq!(item.notes, "a\n\nb");
        assert_eq!(item.urls.len(), 2);
        assert!(item.urls[0].primary && !item.urls[1].primary);
        assert_eq!(item.tags, vec!["work"]);
        assert!(item.favorite && item.archived);
        assert_eq!(item.created_at, created);
        assert_eq!(item.updated_at, updated);
        assert_eq!(item.expires, Some(date!(2031 - 03 - 01)));
        assert_eq!(item.password_history.len(), 1);
        assert_eq!(item.password_history[0].replaced_at, created);
    }

    #[test]
    fn set_value_fills_or_imports() {
        let mut d = Draft::new(ItemType::Identity);
        d.title("me");
        let address = crate::model::Address {
            line1: "1 Main St".into(),
            line2: String::new(),
            city: "Springfield".into(),
            postal_code: "00000".into(),
            region: String::new(),
            country: "US".into(),
        };
        d.set_value("unknown_slot", FieldValue::Address(address.clone()));
        let (item, _) = one(d);
        let extra = imported(&item);
        assert_eq!(extra.len(), 1);
        assert_eq!(extra[0].kind, FieldType::Address);
        assert_eq!(extra[0].value, FieldValue::Address(address));
    }

    #[test]
    fn untitled_uses_host() {
        let mut d = Draft::new(ItemType::Login);
        d.set("username", "alice");
        d.url("https://www.example.org/x");
        let (item, _) = one(d);
        assert_eq!(item.title, "www.example.org");

        let mut d = Draft::new(ItemType::Login);
        d.set("username", "alice");
        let (item, _) = one(d);
        assert_eq!(item.title, "Sans titre");
    }

    #[test]
    fn fresh_ids_each_parse() {
        let mut d = Draft::new(ItemType::Login);
        d.title("t");
        d.set("username", "alice");
        let mut out = Import::default();
        d.clone().finish(0, &mut out);
        d.finish(1, &mut out);
        assert_eq!(out.items.len(), 2);
        assert_ne!(out.items[0].item.id, out.items[1].item.id);
    }

    #[test]
    fn otpauth_from_parts_roundtrips() {
        let uri = otpauth_from_parts(
            "JBSWY3DPEHPK3PXP",
            Some("Example Co"),
            Some("alice@example.com"),
            "SHA256",
            8,
            60,
        );
        let cfg = parse_otpauth(&uri).unwrap();
        assert_eq!(cfg.issuer.as_deref(), Some("Example Co"));
        assert_eq!(cfg.account.as_deref(), Some("alice@example.com"));
        assert_eq!(cfg.algorithm, crate::totp::TotpAlgorithm::Sha256);
        assert_eq!(cfg.digits, 8);
        assert_eq!(cfg.period, 60);
        assert!(
            parse_otpauth(&otpauth_from_parts(
                "JBSWY3DPEHPK3PXP",
                None,
                None,
                "SHA1",
                6,
                30
            ))
            .is_ok()
        );
    }

    #[test]
    fn warnings_carry_no_values() {
        let w = Warning {
            entry: 3,
            code: "field_moved",
        };
        assert_eq!(
            serde_json::to_string(&w).unwrap(),
            r#"{"entry":3,"code":"field_moved"}"#
        );
    }
}
