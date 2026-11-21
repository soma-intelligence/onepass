//! Turning a chip read into a vault item, and merging a later read into an
//! item that already exists.
//!
//! Nothing here logs or prints identity data.

use time::{Date, Month, OffsetDateTime};
use zeroize::Zeroizing;

use crate::error::{Error, ValidationError};
use crate::id::Id;
use crate::model::field::{Field, FieldValue};
use crate::model::item::Item;
use crate::model::{ItemType, new_item, template};
use crate::scan::icao::{ChipRead, ChipStatus};

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

/// Fields filled from the identity data of the chip: user data, so a merge
/// never overwrites them.
fn identity_values(read: &ChipRead, today: Date) -> Vec<(&'static str, FieldValue)> {
    let m = &read.mrz;
    let mut v = vec![
        ("issuing_country", text(&m.issuing_state)),
        (
            "number",
            if m.document_number.is_empty() {
                FieldValue::Empty
            } else {
                FieldValue::Concealed(Zeroizing::new(m.document_number.clone()))
            },
        ),
        ("last_name", text(&readable_case(&m.surname))),
        ("first_names", text(&readable_case(&m.given_names))),
        ("nationality", text(&m.nationality)),
        ("mrz", text(&m.raw)),
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
    for (id, v) in identity_values(read, today)
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
/// case, Unicode-aware, and surrounding spaces) a `FieldConflict` is reported. The chip section
/// (`chip_status`, `chip_read_on`, `document_code`) is machine data and is always
/// refreshed from the read. Items created before the chip fields existed get the
/// missing sections and fields added first. Title and everything else are kept.
pub fn merge_chip_read(
    existing: &Item,
    read: &ChipRead,
    today: Date,
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
                    if !s.fields.iter().any(|g| g.id == f.id) {
                        s.fields.push(f);
                    }
                }
            }
        }
    }
    let mut conflicts = Vec::new();
    for (id, scanned) in identity_values(read, today) {
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
        let (a, b) = (shown(&f.value), shown(&scanned));
        if a.trim().to_lowercase() != b.trim().to_lowercase() {
            conflicts.push(FieldConflict {
                field_id: id.into(),
                stored: a,
                scanned: b,
            });
        }
    }
    for (id, v) in chip_values(read, today) {
        if let Some(f) = field_mut(&mut item, id) {
            f.value = v;
        }
    }
    item.updated_at = OffsetDateTime::now_utc();
    Ok((item, conflicts))
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
        assert_eq!(text(&item, "mrz"), format!("{L1}\n{L2}"));
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
        let (merged, conflicts) = merge_chip_read(&item, &read, today).unwrap();
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
        // Chip section refreshed.
        assert_eq!(text(&merged, "chip_status"), "Authentifié par la puce");
        assert_eq!(get(&merged, "chip_read_on"), FieldValue::Date(today));
    }

    #[test]
    fn merge_adds_missing_chip_section_to_old_items() {
        let today = date!(2026 - 11 - 21);
        let mut item = new_item(ItemType::Passport, Id::new(), "Ancien");
        item.sections.retain(|s| s.id != "chip");
        item.sections[0].fields.retain(|f| f.id != "portrait");
        let (merged, conflicts) =
            merge_chip_read(&item, &specimen(ChipStatus::Verified), today).unwrap();
        assert!(conflicts.is_empty());
        assert_eq!(text(&merged, "document_code"), "P");
        assert_eq!(get(&merged, "portrait"), FieldValue::Empty);
    }

    #[test]
    fn merge_rejects_non_passport() {
        let item = new_item(ItemType::Login, Id::new(), "Site");
        let r = merge_chip_read(
            &item,
            &specimen(ChipStatus::Verified),
            date!(2026 - 11 - 21),
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
        let (merged, conflicts) = merge_chip_read(&item, &read, today).unwrap();
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
        let (m, c) = merge_chip_read(&item, &read, today).unwrap();
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
