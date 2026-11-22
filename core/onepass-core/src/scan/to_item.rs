//! Turning a chip read into a vault item, and merging a later read into an
//! item that already exists.
//!
//! Nothing here logs or prints identity data.

use time::{Date, Month, OffsetDateTime};
use zeroize::Zeroizing;

use crate::error::{Error, ValidationError};
use crate::id::Id;
use crate::model::field::{Field, FieldType, FieldValue};
use crate::model::item::Item;
use crate::model::{ItemType, new_item, template};
use crate::scan::icao::{ChipRead, ChipStatus};
use crate::scan::mrz::{Mrz, parse_td3};

/// A value that differs between the stored item and the scanned chip.
/// `Debug` omits the values: they are identity data.
#[derive(Clone, PartialEq, Eq)]
pub struct FieldConflict {
    pub field_id: String,
    pub stored: String,
    pub scanned: String,
}

impl std::fmt::Debug for FieldConflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FieldConflict")
            .field("field_id", &self.field_id)
            .finish_non_exhaustive()
    }
}

/// "ANNA MARIA" -> "Anna Maria", "DUPONT-MARTIN" -> "Dupont-Martin".
fn readable_case(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut start = true;
    for c in s.trim().chars() {
        if start {
            out.extend(c.to_uppercase());
        } else {
            out.extend(c.to_lowercase());
        }
        start = matches!(c, ' ' | '-' | '\'');
    }
    out
}

/// YYMMDD to a date; `None` when it is not a real date.
fn parse_yymmdd(s: &str, century_of: impl Fn(i32) -> i32) -> Option<Date> {
    let b = s.as_bytes();
    if b.len() != 6 || !b.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let n = |i: usize| i32::from(b[i] - b'0') * 10 + i32::from(b[i + 1] - b'0');
    let month = Month::try_from(u8::try_from(n(2)).ok()?).ok()?;
    Date::from_calendar_date(century_of(n(0)), month, u8::try_from(n(4)).ok()?).ok()
}

fn text(s: &str) -> FieldValue {
    if s.is_empty() {
        FieldValue::Empty
    } else {
        FieldValue::Text(s.into())
    }
}

fn concealed(s: &str) -> FieldValue {
    if s.is_empty() {
        FieldValue::Empty
    } else {
        FieldValue::Concealed(Zeroizing::new(s.into()))
    }
}

fn status_label(s: ChipStatus) -> &'static str {
    match s {
        ChipStatus::Verified => "Authentifié par la puce",
        ChipStatus::Unverifiable => "Lu sur la puce, signature non vérifiable",
        ChipStatus::Invalid => "Signature invalide",
    }
}

fn passport_type(code: &str) -> &'static str {
    match code {
        "P" => "Ordinaire",
        "PD" => "Diplomatique",
        "PS" => "Service",
        _ => "Autre",
    }
}

/// Fields filled from the identity data of the chip (the MRZ of DG1): user
/// data, so a merge never overwrites them. The chip badge vouches for them.
fn identity_values(m: &Mrz, today: Date) -> Vec<(&'static str, FieldValue)> {
    let mut v = vec![
        ("issuing_country", text(&m.issuing_state)),
        ("number", concealed(&m.document_number)),
        ("last_name", text(&readable_case(&m.surname))),
        ("first_names", text(&readable_case(&m.given_names))),
        ("nationality", text(&m.nationality)),
        ("mrz", concealed(&m.raw)),
        (
            "passport_type",
            FieldValue::Menu(passport_type(&m.document_code).into()),
        ),
    ];
    // Expiry is always this century. A birth year after the current year
    // can only be the last one.
    if let Some(d) = parse_yymmdd(&m.expiry_date, |yy| 2000 + yy) {
        v.push(("expiry", FieldValue::Date(d)));
    }
    let cur = today.year() % 100;
    if let Some(d) = parse_yymmdd(
        &m.birth_date,
        |yy| if yy <= cur { 2000 + yy } else { 1900 + yy },
    ) {
        v.push(("birth_date", FieldValue::Date(d)));
    }
    let sex = match m.sex {
        'F' => Some("Féminin"),
        'M' => Some("Masculin"),
        'X' => Some("Autre"),
        _ => None,
    };
    if let Some(s) = sex {
        v.push(("sex", FieldValue::Menu(s.into())));
    }
    v
}

/// Machine data of the read itself: refreshed by every read.
fn chip_values(read: &ChipRead, today: Date) -> Vec<(&'static str, FieldValue)> {
    vec![
        (
            "chip_status",
            FieldValue::Menu(status_label(read.status).into()),
        ),
        ("chip_read_on", FieldValue::Date(today)),
        ("document_code", text(&read.mrz.document_code)),
    ]
}

fn field_mut<'a>(item: &'a mut Item, id: &str) -> Option<&'a mut Field> {
    item.sections
        .iter_mut()
        .flat_map(|s| s.fields.iter_mut())
        .find(|f| f.id == id)
}

/// A new passport item from a chip read, titled "Passeport" and the ICAO
/// issuing state code. The portrait is not stored here: the app attaches it.
pub fn chip_read_to_item(read: &ChipRead, vault_id: Id, today: Date) -> Item {
    let title = format!("Passeport {}", read.mrz.issuing_state.trim())
        .trim()
        .to_string();
    let mut item = new_item(ItemType::Passport, vault_id, &title);
    for (id, v) in identity_values(&read.mrz, today)
        .into_iter()
        .chain(chip_values(read, today))
    {
        if let Some(f) = field_mut(&mut item, id) {
            f.value = v;
        }
    }
    item
}

/// Empty, or text-like and blank (as `validate` counts it).
fn is_blank(v: &FieldValue) -> bool {
    match v {
        FieldValue::Empty => true,
        FieldValue::Text(s) | FieldValue::Menu(s) => s.trim().is_empty(),
        FieldValue::Concealed(s) => s.trim().is_empty(),
        _ => false,
    }
}

/// Display form of a value, for comparison and conflict reports.
fn shown(v: &FieldValue) -> String {
    match v {
        FieldValue::Text(s) | FieldValue::Menu(s) => s.clone(),
        FieldValue::Concealed(s) => s.to_string(),
        FieldValue::Date(d) => d.to_string(),
        _ => String::new(),
    }
}

/// Merges a later chip read into an existing passport item (spec 6.1). Fails
/// with a validation error when `existing` is not a passport.
///
/// Rule: identity fields that are empty or blank are filled; a non-empty stored value
/// is a user edit and is kept, and when it differs from the scanned one (ignoring
/// case, Unicode-aware, and surrounding spaces) a `FieldConflict` is reported. A
/// conflict whose field id is in `take_scanned` takes the scanned value instead (the
/// user picked the chip's side). The chip section (`chip_status`, `chip_read_on`,
/// `document_code`) is machine data and is refreshed from the read, except that
/// `chip_status` is cleared while a conflict keeps a stored value: the badge would
/// vouch for data the chip did not give. Every conflict is reported, taken or not.
/// Items created before the chip fields existed get the missing sections and fields
/// added first. Title and everything else are kept.
pub fn merge_chip_read(
    existing: &Item,
    read: &ChipRead,
    today: Date,
    take_scanned: &[String],
) -> Result<(Item, Vec<FieldConflict>), Error> {
    if existing.item_type != ItemType::Passport {
        return Err(Error::Validation(ValidationError {
            field: "item_type".into(),
            reason: "not a passport",
        }));
    }
    let mut item = existing.clone();
    for ts in template(ItemType::Passport) {
        match item.sections.iter_mut().find(|s| s.id == ts.id) {
            None => item.sections.push(ts),
            Some(s) => {
                for f in ts.fields {
                    match s.fields.iter_mut().find(|g| g.id == f.id) {
                        None => s.fields.push(f),
                        // The MRZ of items made before it was concealed.
                        Some(g) if g.id == "mrz" && g.kind == FieldType::Text => {
                            g.kind = FieldType::Concealed;
                            if let FieldValue::Text(t) = &mut g.value {
                                g.value = FieldValue::Concealed(Zeroizing::new(std::mem::take(t)));
                            }
                        }
                        Some(_) => {}
                    }
                }
            }
        }
    }
    let mut conflicts = Vec::new();
    let mut kept_stored = false;
    for (id, scanned) in identity_values(&read.mrz, today) {
        if scanned == FieldValue::Empty {
            continue;
        }
        let Some(f) = field_mut(&mut item, id) else {
            continue;
        };
        if is_blank(&f.value) {
            f.value = scanned;
            continue;
        }
        if same(&f.value, &scanned) {
            continue;
        }
        conflicts.push(FieldConflict {
            field_id: id.into(),
            stored: shown(&f.value),
            scanned: shown(&scanned),
        });
        if take_scanned.iter().any(|t| t == id) {
            f.value = scanned;
        } else {
            kept_stored = true;
        }
    }
    for (id, v) in chip_values(read, today) {
        if let Some(f) = field_mut(&mut item, id) {
            f.value = v;
        }
    }
    if kept_stored && let Some(f) = field_mut(&mut item, "chip_status") {
        f.value = FieldValue::Empty;
    }
    item.updated_at = OffsetDateTime::now_utc();
    Ok((item, conflicts))
}

/// Equal as the merge compares them: shown form, surrounding spaces and case
/// (Unicode-aware) ignored.
fn same(a: &FieldValue, b: &FieldValue) -> bool {
    shown(a).trim().to_lowercase() == shown(b).trim().to_lowercase()
}

fn value<'a>(item: &'a Item, id: &str) -> Option<&'a FieldValue> {
    item.sections
        .iter()
        .flat_map(|s| &s.fields)
        .find(|f| f.id == id)
        .map(|f| &f.value)
}

/// Clears the chip badge (`chip_status`) of a passport about to be saved when
/// its identity fields no longer say what the chip said. Call it on every
/// edit, with the item as stored before the edit (`None` for a new item).
///
/// The badge holds while:
/// - the `mrz` field (the chip's DG1 MRZ, set by the read) parses and passes
///   its check digits;
/// - every non-blank identity field equals the value that MRZ gives (as the
///   merge compares, the read date standing for "today" in the birth century
///   rule); a field the user cleared claims nothing and is let through;
/// - the MRZ did not change unless the read date changed with it (a new read):
///   an MRZ edited by hand, even one consistent with the other fields, drops
///   the badge.
///
/// So a chip read (new item or merge) keeps its badge, and an edit of a field
/// the chip vouches for (names, number, nationality, dates, sex, MRZ, issuing
/// country, type) drops it. `chip_read_on` and `document_code` are kept: they
/// say when the chip was read and what it held, which stays true; without the
/// status, no badge is shown. Other item types are left alone.
pub fn guard_chip_status(stored: Option<&Item>, item: &mut Item) {
    if item.item_type != ItemType::Passport {
        return;
    }
    match value(item, "chip_status") {
        Some(v) if !is_blank(v) => {}
        _ => return,
    }
    if chip_fields_hold(stored, item) {
        return;
    }
    if let Some(f) = field_mut(item, "chip_status") {
        f.value = FieldValue::Empty;
    }
}

fn chip_fields_hold(stored: Option<&Item>, item: &Item) -> bool {
    let Some(mrz) = value(item, "mrz") else {
        return false;
    };
    let raw = Zeroizing::new(shown(mrz));
    let lines: Vec<&str> = raw.lines().map(str::trim).collect();
    let Ok(m) = parse_td3(&lines) else {
        return false;
    };
    let Some(FieldValue::Date(read_on)) = value(item, "chip_read_on") else {
        return false;
    };
    if let Some(old) = stored.filter(|s| s.item_type == ItemType::Passport) {
        let mrz_changed = !matches!(value(old, "mrz"), Some(v) if same(v, mrz));
        if mrz_changed && value(old, "chip_read_on") == value(item, "chip_read_on") {
            return false;
        }
    }
    identity_values(&m, *read_on)
        .iter()
        .all(|(id, want)| match value(item, id) {
            None => true,
            Some(have) => is_blank(have) || same(have, want),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::icao::ChipStatus;
    use crate::scan::mrz::parse_td3;
    use time::macros::date;

    const L1: &str = "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<";
    const L2: &str = "L898902C36UTO7408122F1204159ZE184226B<<<<<10";

    fn specimen(status: ChipStatus) -> ChipRead {
        ChipRead {
            mrz: parse_td3(&[L1, L2]).unwrap(),
            portrait: None,
            status,
            progress_files: Vec::new(),
        }
    }

    fn get(item: &Item, id: &str) -> FieldValue {
        item.sections
            .iter()
            .flat_map(|s| &s.fields)
            .find(|f| f.id == id)
            .unwrap_or_else(|| panic!("missing field {id}"))
            .value
            .clone()
    }

    fn text(item: &Item, id: &str) -> String {
        match get(item, id) {
            FieldValue::Text(s) | FieldValue::Menu(s) => s,
            FieldValue::Concealed(s) => s.to_string(),
            other => panic!("{id}: {other:?}"),
        }
    }

    fn set(item: &mut Item, id: &str, v: FieldValue) {
        item.sections
            .iter_mut()
            .flat_map(|s| &mut s.fields)
            .find(|f| f.id == id)
            .unwrap()
            .value = v;
    }

    #[test]
    fn chip_read_to_item_fills_specimen() {
        let today = date!(2026 - 11 - 21);
        let item = chip_read_to_item(&specimen(ChipStatus::Verified), Id::new(), today);
        assert_eq!(item.item_type, ItemType::Passport);
        assert_eq!(item.title, "Passeport UTO");
        assert_eq!(text(&item, "issuing_country"), "UTO");
        assert_eq!(text(&item, "number"), "L898902C3");
        assert_eq!(
            get(&item, "expiry"),
            FieldValue::Date(date!(2012 - 04 - 15))
        );
        assert_eq!(text(&item, "last_name"), "Eriksson");
        assert_eq!(text(&item, "first_names"), "Anna Maria");
        assert_eq!(text(&item, "nationality"), "UTO");
        assert_eq!(
            get(&item, "birth_date"),
            FieldValue::Date(date!(1974 - 08 - 12))
        );
        assert_eq!(text(&item, "sex"), "Féminin");
        assert_eq!(
            get(&item, "mrz"),
            FieldValue::Concealed(Zeroizing::new(format!("{L1}\n{L2}")))
        );
        assert_eq!(text(&item, "passport_type"), "Ordinaire");
        assert_eq!(text(&item, "document_code"), "P");
        assert_eq!(text(&item, "chip_status"), "Authentifié par la puce");
        assert_eq!(get(&item, "chip_read_on"), FieldValue::Date(today));
        assert_eq!(get(&item, "portrait"), FieldValue::Empty);
    }

    #[test]
    fn chip_status_labels() {
        let today = date!(2026 - 11 - 21);
        let s = |st| {
            text(
                &chip_read_to_item(&specimen(st), Id::new(), today),
                "chip_status",
            )
        };
        assert_eq!(
            s(ChipStatus::Unverifiable),
            "Lu sur la puce, signature non vérifiable"
        );
        assert_eq!(s(ChipStatus::Invalid), "Signature invalide");
    }

    #[test]
    fn passport_type_from_document_code() {
        let today = date!(2026 - 11 - 21);
        for (code, want) in [
            ("P", "Ordinaire"),
            ("PD", "Diplomatique"),
            ("PS", "Service"),
            ("PX", "Autre"),
        ] {
            let mut r = specimen(ChipStatus::Verified);
            r.mrz.document_code = code.into();
            let item = chip_read_to_item(&r, Id::new(), today);
            assert_eq!(text(&item, "passport_type"), want);
        }
    }

    #[test]
    fn birth_century_rule() {
        let mut r = specimen(ChipStatus::Verified);
        r.mrz.birth_date = "260101".into();
        let it = chip_read_to_item(&r, Id::new(), date!(2026 - 11 - 21));
        assert_eq!(
            get(&it, "birth_date"),
            FieldValue::Date(date!(2026 - 01 - 01))
        );
        r.mrz.birth_date = "270101".into();
        let it = chip_read_to_item(&r, Id::new(), date!(2026 - 11 - 21));
        assert_eq!(
            get(&it, "birth_date"),
            FieldValue::Date(date!(1927 - 01 - 01))
        );
    }

    #[test]
    fn hyphenated_names_keep_readable_case() {
        let mut r = specimen(ChipStatus::Verified);
        r.mrz.surname = "DUPONT-MARTIN".into();
        let it = chip_read_to_item(&r, Id::new(), date!(2026 - 11 - 21));
        assert_eq!(text(&it, "last_name"), "Dupont-Martin");
    }

    #[test]
    fn merge_keeps_user_edits_and_reports_conflict() {
        let today = date!(2026 - 11 - 21);
        let read = specimen(ChipStatus::Verified);
        let mut item = new_item(ItemType::Passport, Id::new(), "Mon passeport");
        set(&mut item, "last_name", FieldValue::Text("Erikson".into()));
        set(
            &mut item,
            "first_names",
            FieldValue::Text("anna maria".into()),
        );
        set(
            &mut item,
            "chip_status",
            FieldValue::Menu("Signature invalide".into()),
        );
        let (merged, conflicts) = merge_chip_read(&item, &read, today, &[]).unwrap();
        // Same id, user title kept.
        assert_eq!(merged.id, item.id);
        assert_eq!(merged.title, "Mon passeport");
        // Conflict reported, stored value kept.
        assert_eq!(text(&merged, "last_name"), "Erikson");
        assert_eq!(
            conflicts,
            vec![FieldConflict {
                field_id: "last_name".into(),
                stored: "Erikson".into(),
                scanned: "Eriksson".into()
            }]
        );
        // Equal ignoring case: no conflict. Empty fields filled.
        assert_eq!(text(&merged, "first_names"), "anna maria");
        assert_eq!(text(&merged, "number"), "L898902C3");
        // Chip section refreshed, but the badge is dropped: the stored
        // surname the user kept is not the chip's.
        assert_eq!(get(&merged, "chip_status"), FieldValue::Empty);
        assert_eq!(get(&merged, "chip_read_on"), FieldValue::Date(today));
        assert_eq!(text(&merged, "document_code"), "P");
    }

    #[test]
    fn merge_takes_picked_chip_values_and_keeps_the_badge() {
        let today = date!(2026 - 11 - 21);
        let read = specimen(ChipStatus::Verified);
        let mut item = new_item(ItemType::Passport, Id::new(), "Mon passeport");
        set(&mut item, "last_name", FieldValue::Text("Erikson".into()));
        let (merged, conflicts) =
            merge_chip_read(&item, &read, today, &["last_name".into()]).unwrap();
        // Still reported (the reveal lists it), but settled for the chip.
        assert_eq!(conflicts.len(), 1);
        assert_eq!(text(&merged, "last_name"), "Eriksson");
        assert_eq!(text(&merged, "chip_status"), "Authentifié par la puce");
        // A pick for a field without conflict changes nothing.
        let (same_read, c) = merge_chip_read(&merged, &read, today, &["sex".into()]).unwrap();
        assert!(c.is_empty());
        assert_eq!(text(&same_read, "sex"), "Féminin");
    }

    /// Check digit (ICAO 9303-3, weights 7 3 1).
    fn cd(s: &str) -> char {
        let v = |c: u8| match c {
            b'0'..=b'9' => u32::from(c - b'0'),
            b'A'..=b'Z' => u32::from(c - b'A') + 10,
            _ => 0,
        };
        let sum: u32 = s
            .bytes()
            .zip([7, 3, 1].iter().cycle())
            .map(|(c, w)| v(c) * w)
            .sum();
        char::from_digit(sum % 10, 10).unwrap()
    }

    /// The specimen's second line with another document number.
    fn line2(number: &str) -> String {
        let (birth, expiry, opt) = ("740812", "120415", "ZE184226B<<<<<");
        let n = format!("{number}{}", cd(number));
        let b = format!("{birth}{}", cd(birth));
        let e = format!("{expiry}{}", cd(expiry));
        let o = format!("{opt}{}", cd(opt));
        let composite = cd(&format!("{n}{b}{e}{o}"));
        format!("{n}UTO{b}F{e}{o}{composite}")
    }

    fn chip_item(read_on: Date) -> Item {
        chip_read_to_item(&specimen(ChipStatus::Verified), Id::new(), read_on)
    }

    fn badge(item: &Item) -> FieldValue {
        get(item, "chip_status")
    }

    #[test]
    fn guard_keeps_the_badge_of_a_chip_read() {
        let today = date!(2026 - 11 - 21);
        let mut item = chip_item(today);
        guard_chip_status(None, &mut item);
        assert_eq!(text(&item, "chip_status"), "Authentifié par la puce");
        // An edit outside the identity fields keeps it.
        let stored = item.clone();
        item.notes = "Renouveler en 2030".into();
        set(&mut item, "birth_place", FieldValue::Text("Zenith".into()));
        guard_chip_status(Some(&stored), &mut item);
        assert_eq!(text(&item, "chip_status"), "Authentifié par la puce");
        // So does a case change or clearing a field (it claims nothing).
        set(&mut item, "last_name", FieldValue::Text("ERIKSSON ".into()));
        set(&mut item, "nationality", FieldValue::Empty);
        guard_chip_status(Some(&stored), &mut item);
        assert_eq!(text(&item, "chip_status"), "Authentifié par la puce");
    }

    #[test]
    fn guard_drops_the_badge_when_an_identity_field_is_edited() {
        let today = date!(2026 - 11 - 21);
        for (id, v) in [
            ("last_name", FieldValue::Text("Erikson".into())),
            ("first_names", FieldValue::Text("Anna".into())),
            (
                "number",
                FieldValue::Concealed(Zeroizing::new("X1234567".into())),
            ),
            ("nationality", FieldValue::Text("FRA".into())),
            ("birth_date", FieldValue::Date(date!(1975 - 08 - 12))),
            ("expiry", FieldValue::Date(date!(2032 - 04 - 15))),
            ("sex", FieldValue::Menu("Masculin".into())),
            ("issuing_country", FieldValue::Text("FRA".into())),
            ("passport_type", FieldValue::Menu("Service".into())),
            ("mrz", FieldValue::Concealed(Zeroizing::new("P<UTO".into()))),
        ] {
            let stored = chip_item(today);
            let mut item = stored.clone();
            set(&mut item, id, v);
            guard_chip_status(Some(&stored), &mut item);
            assert_eq!(badge(&item), FieldValue::Empty, "{id}");
            // The read date and document code stay: they are still true.
            assert_eq!(get(&item, "chip_read_on"), FieldValue::Date(today), "{id}");
            assert_eq!(text(&item, "document_code"), "P", "{id}");
        }
    }

    #[test]
    fn guard_drops_the_badge_of_a_consistent_mrz_typed_by_hand() {
        // Another valid MRZ, and a number matching it: consistent, but the
        // MRZ changed without a new read.
        let today = date!(2026 - 11 - 21);
        let stored = chip_item(today);
        let mut item = stored.clone();
        let l2 = line2("X12345678");
        assert!(parse_td3(&[L1, &l2]).is_ok());
        set(
            &mut item,
            "mrz",
            FieldValue::Concealed(Zeroizing::new(format!("{L1}\n{l2}"))),
        );
        set(
            &mut item,
            "number",
            FieldValue::Concealed(Zeroizing::new("X12345678".into())),
        );
        guard_chip_status(Some(&stored), &mut item);
        assert_eq!(badge(&item), FieldValue::Empty);
    }

    #[test]
    fn guard_keeps_the_badge_of_a_merged_later_read() {
        // Read in 2025, the user cleared the given names; read again today
        // from a renewed passport: the merge fills the names and takes the
        // new MRZ and number the user picked.
        let stored = {
            let mut i = chip_item(date!(2025 - 01 - 10));
            let l2 = line2("X12345678");
            set(
                &mut i,
                "mrz",
                FieldValue::Concealed(Zeroizing::new(format!("{L1}\n{l2}"))),
            );
            set(
                &mut i,
                "number",
                FieldValue::Concealed(Zeroizing::new("X12345678".into())),
            );
            set(&mut i, "first_names", FieldValue::Empty);
            i
        };
        let today = date!(2026 - 11 - 21);
        let picks = ["mrz".to_string(), "number".to_string()];
        let (mut merged, conflicts) =
            merge_chip_read(&stored, &specimen(ChipStatus::Verified), today, &picks).unwrap();
        assert_eq!(conflicts.len(), 2);
        guard_chip_status(Some(&stored), &mut merged);
        assert_eq!(text(&merged, "chip_status"), "Authentifié par la puce");
        assert_eq!(text(&merged, "first_names"), "Anna Maria");
    }

    #[test]
    fn guard_leaves_unbadged_and_other_items_alone() {
        let mut login = new_item(ItemType::Login, Id::new(), "Site");
        let before = login.clone();
        guard_chip_status(None, &mut login);
        assert_eq!(login.sections, before.sections);
        // A passport typed by hand: no badge to drop, nothing changes.
        let mut manual = new_item(ItemType::Passport, Id::new(), "P");
        set(&mut manual, "last_name", FieldValue::Text("Durand".into()));
        let before = manual.clone();
        guard_chip_status(Some(&before), &mut manual);
        assert_eq!(manual.sections, before.sections);
    }

    #[test]
    fn merge_adds_missing_chip_section_to_old_items() {
        let today = date!(2026 - 11 - 21);
        let mut item = new_item(ItemType::Passport, Id::new(), "Ancien");
        item.sections.retain(|s| s.id != "chip");
        item.sections[0].fields.retain(|f| f.id != "portrait");
        let (merged, conflicts) =
            merge_chip_read(&item, &specimen(ChipStatus::Verified), today, &[]).unwrap();
        assert!(conflicts.is_empty());
        assert_eq!(text(&merged, "document_code"), "P");
        assert_eq!(get(&merged, "portrait"), FieldValue::Empty);
    }

    #[test]
    fn merge_conceals_the_mrz_of_old_items() {
        let today = date!(2026 - 11 - 21);
        let read = specimen(ChipStatus::Verified);
        let mut item = chip_read_to_item(&read, Id::new(), today);
        let f = item
            .sections
            .iter_mut()
            .flat_map(|s| &mut s.fields)
            .find(|f| f.id == "mrz")
            .unwrap();
        f.kind = FieldType::Text;
        f.value = FieldValue::Text(format!("{L1}\n{L2}"));
        let (merged, conflicts) = merge_chip_read(&item, &read, today, &[]).unwrap();
        assert!(conflicts.is_empty());
        let f = merged
            .sections
            .iter()
            .flat_map(|s| &s.fields)
            .find(|f| f.id == "mrz")
            .unwrap();
        assert_eq!(f.kind, FieldType::Concealed);
        assert_eq!(
            f.value,
            FieldValue::Concealed(Zeroizing::new(format!("{L1}\n{L2}")))
        );
    }

    #[test]
    fn merge_rejects_non_passport() {
        let item = new_item(ItemType::Login, Id::new(), "Site");
        let r = merge_chip_read(
            &item,
            &specimen(ChipStatus::Verified),
            date!(2026 - 11 - 21),
            &[],
        );
        assert!(matches!(r, Err(Error::Validation(_))));
    }

    #[test]
    fn apostrophe_name_and_sex_x() {
        let mut r = specimen(ChipStatus::Verified);
        r.mrz.surname = "O'BRIEN".into();
        r.mrz.sex = 'X';
        let it = chip_read_to_item(&r, Id::new(), date!(2026 - 11 - 21));
        assert_eq!(text(&it, "last_name"), "O'Brien");
        assert_eq!(text(&it, "sex"), "Autre");
    }

    #[test]
    fn empty_issuing_state_gives_trimmed_title() {
        let mut r = specimen(ChipStatus::Verified);
        r.mrz.issuing_state = String::new();
        let it = chip_read_to_item(&r, Id::new(), date!(2026 - 11 - 21));
        assert_eq!(it.title, "Passeport");
    }

    #[test]
    fn merge_of_same_read_has_no_conflicts() {
        let today = date!(2026 - 11 - 21);
        let read = specimen(ChipStatus::Verified);
        let item = chip_read_to_item(&read, Id::new(), today);
        let (merged, conflicts) = merge_chip_read(&item, &read, today, &[]).unwrap();
        assert!(conflicts.is_empty());
        assert_eq!(merged.sections, item.sections);
    }

    #[test]
    fn merge_fills_empty_dates_and_blank_text_and_compares_unicode_case() {
        let today = date!(2026 - 11 - 21);
        let mut read = specimen(ChipStatus::Verified);
        read.mrz.given_names = "ÉRIC".into();
        let mut item = new_item(ItemType::Passport, Id::new(), "P");
        set(&mut item, "last_name", FieldValue::Text("  ".into()));
        set(&mut item, "first_names", FieldValue::Text("éric".into()));
        let (m, c) = merge_chip_read(&item, &read, today, &[]).unwrap();
        assert!(c.is_empty());
        assert_eq!(text(&m, "last_name"), "Eriksson");
        assert_eq!(text(&m, "first_names"), "éric");
        assert_eq!(
            get(&m, "birth_date"),
            FieldValue::Date(date!(1974 - 08 - 12))
        );
        assert_eq!(get(&m, "expiry"), FieldValue::Date(date!(2012 - 04 - 15)));
    }
}
