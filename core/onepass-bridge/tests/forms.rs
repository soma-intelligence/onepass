//! `fill_identity` for the forms flows (spec 2026-11-06 sections 4, 9 and
//! 10.2): the identity's person and company values, and on request its
//! passport, driver license and the site's loyalty number, each audited.

mod common;

use common::*;
use onepass_bridge::audit::MemoryAudit;
use onepass_bridge::service::Service;
use onepass_core::Id;
use onepass_core::model::{FieldValue, Item, ItemType, ItemUrl, MatchRule, new_item};
use serde_json::{Value, json};
use time::{Date, Duration, Month, OffsetDateTime};
use zeroize::Zeroizing;

/// 2026-09-20, Unix seconds.
const NOW: u64 = 1_790_000_000;
const ATLAS: &str = "https://atlas-cloud.test";

struct H {
    svc: Service<FakeVault>,
    ids: Ids,
    audit: MemoryAudit,
    next: u64,
}

impl H {
    fn new() -> H {
        H::with(|_, _| {})
    }

    /// The fixture vault, changed by `f` before the service owns it.
    fn with(f: impl FnOnce(&mut FakeVault, &Ids)) -> H {
        let (mut vault, ids) = FakeVault::new();
        f(&mut vault, &ids);
        let audit = MemoryAudit::new();
        H {
            svc: Service::new(vault, Box::new(audit.clone())),
            ids,
            audit,
            next: 0,
        }
    }

    fn call(&mut self, mut req: Value) -> Value {
        self.next += 1;
        req["id"] = json!(self.next);
        let out = self.svc.handle(req.to_string().as_bytes(), NOW);
        serde_json::from_slice(&out).unwrap()
    }

    fn fill(&mut self, extras: &[&str], origin: &str) -> Value {
        let ident = self.ids.identity.to_string();
        self.call(json!({"op":"fill_identity","ctx":"menu","item_id":ident,
                         "origin":origin,"extras":extras}))
    }

    fn ops(&self) -> Vec<(&'static str, Option<String>, Option<String>)> {
        self.audit
            .events()
            .into_iter()
            .map(|e| (e.op, e.item_id, e.origin))
            .collect()
    }
}

fn ok(v: &Value) -> &Value {
    assert!(v.get("err").is_none(), "unexpected error: {v}");
    &v["ok"]
}

fn err(v: &Value) -> &str {
    assert!(v.get("ok").is_none(), "unexpected success: {v}");
    v["err"]["code"].as_str().unwrap()
}

fn set(item: &mut Item, field: &str, value: FieldValue) {
    item.field_mut(field).expect(field).value = value;
}

fn text(s: &str) -> FieldValue {
    FieldValue::Text(s.into())
}

fn concealed(s: &str) -> FieldValue {
    FieldValue::Concealed(Zeroizing::new(s.into()))
}

fn day(y: i32, m: Month, d: u8) -> FieldValue {
    FieldValue::Date(Date::from_calendar_date(y, m, d).unwrap())
}

fn vault_of(v: &FakeVault) -> Id {
    v.vaults[0].id
}

/// A passport of `first_names last_name`, valid until `expiry_year`,
/// saved `age_days` before now.
fn passport(
    v: &FakeVault,
    first_names: &str,
    last: &str,
    number: &str,
    expiry_year: i32,
    age_days: i64,
) -> Item {
    let mut p = new_item(
        ItemType::Passport,
        vault_of(v),
        &format!("Passeport {last}"),
    );
    set(&mut p, "issuing_country", text("FR"));
    set(&mut p, "number", concealed(number));
    set(&mut p, "expiry", day(expiry_year, Month::March, 1));
    set(&mut p, "last_name", text(last));
    set(&mut p, "first_names", text(first_names));
    set(&mut p, "nationality", text("FR"));
    set(&mut p, "birth_date", day(1990, Month::May, 17));
    set(&mut p, "birth_place", text("Lyon"));
    set(&mut p, "sex", FieldValue::Menu("Masculin".into()));
    set(&mut p, "issued_on", day(2021, Month::March, 2));
    p.updated_at =
        OffsetDateTime::from_unix_timestamp(NOW as i64).unwrap() - Duration::days(age_days);
    p
}

fn license(v: &FakeVault, full_name: &str, number: &str) -> Item {
    let mut l = new_item(
        ItemType::DriverLicense,
        vault_of(v),
        &format!("Permis {full_name}"),
    );
    set(&mut l, "full_name", text(full_name));
    set(&mut l, "number", concealed(number));
    set(&mut l, "country", text("FR"));
    set(&mut l, "issued_on", day(2015, Month::June, 3));
    set(&mut l, "expiry", day(2030, Month::June, 3));
    l
}

fn program(v: &FakeVault, t: ItemType, name: &str, number: &str, url: &str) -> Item {
    let mut r = new_item(t, vault_of(v), name);
    let name_field = if t == ItemType::RewardProgram {
        "company"
    } else {
        "organization"
    };
    set(&mut r, name_field, text(name));
    set(&mut r, "member_number", concealed(number));
    r.urls.push(ItemUrl {
        label: "site web".into(),
        url: url.into(),
        rule: MatchRule::Domain,
        primary: true,
    });
    r
}

fn identity_mut<'a>(v: &'a mut FakeVault, ids: &Ids) -> &'a mut Item {
    v.items.iter_mut().find(|i| i.id == ids.identity).unwrap()
}

#[test]
fn identity_gives_person_and_company_values() {
    let mut h = H::with(|v, ids| {
        let i = identity_mut(v, ids);
        set(i, "honorific", text("M."));
        set(i, "middle_name", text("Jean"));
        set(i, "birth_name", text("Durand"));
        set(i, "sex", FieldValue::Menu("Masculin".into()));
        set(i, "birth_place", text("Lyon"));
        set(i, "nationality", text("FR"));
        set(
            i,
            "work_phone",
            FieldValue::Phone("+33 1 00 00 00 00".into()),
        );
        set(i, "job_title", text("Directeur"));
        set(i, "department", text("Achats"));
        set(
            i,
            "website",
            FieldValue::Url("https://atlas.example".into()),
        );
        set(i, "vat_number", text("FR40303265045"));
        set(i, "company_registration", text("30326504500017"));
    });
    let v = h.fill(&[], ATLAS);
    let o = ok(&v);
    for (k, want) in [
        ("honorific", "M."),
        ("middle_name", "Jean"),
        ("birth_name", "Durand"),
        ("sex", "m"),
        ("birth_place", "Lyon"),
        ("nationality", "FR"),
        ("work_tel", "+33 1 00 00 00 00"),
        ("job_title", "Directeur"),
        ("department", "Achats"),
        ("website", "https://atlas.example"),
        ("vat_number", "FR40303265045"),
        ("company_registration", "30326504500017"),
        ("given_name", "Alex"),
        ("tel", "+33 6 00 00 00 00"),
    ] {
        assert_eq!(o[k], want, "{k}");
    }
}

#[test]
fn sex_is_canonical() {
    for (stored, want) in [
        ("Féminin", Some("f")),
        ("Masculin", Some("m")),
        ("Autre", Some("x")),
        ("female", Some("f")),
        ("Homme", Some("m")),
        ("??", None),
    ] {
        let mut h = H::with(|v, ids| {
            set(identity_mut(v, ids), "sex", FieldValue::Menu(stored.into()));
        });
        let v = h.fill(&[], ATLAS);
        assert_eq!(ok(&v).get("sex").and_then(Value::as_str), want, "{stored}");
    }
}

#[test]
fn no_extras_no_document() {
    let mut h = H::with(|v, _| {
        let p = passport(v, "Alex", "Martin", "18AB12345", 2031, 10);
        let l = license(v, "Alex Martin", "120375201234");
        let r = program(v, ItemType::RewardProgram, "Atlas Miles", "AM123", ATLAS);
        v.items.extend([p, l, r]);
    });
    // An old request, without the `extras` key at all.
    let ident = h.ids.identity.to_string();
    let v = h.call(json!({"op":"fill_identity","ctx":"menu","item_id":ident,"origin":ATLAS}));
    let o = ok(&v);
    for k in ["passport", "driver_license", "loyalty"] {
        assert!(o.get(k).is_none(), "{k}: {o}");
    }
    let v = h.fill(&[], ATLAS);
    assert!(ok(&v).get("passport").is_none());
    let ops: Vec<&str> = h.ops().iter().map(|(op, _, _)| *op).collect();
    assert_eq!(ops, ["fill_identity", "fill_identity"]);
}

#[test]
fn passport_of_the_holder_is_given_and_audited() {
    let mut pid = Id::new();
    let mut h = H::with(|v, _| {
        let other = passport(v, "Camille", "Durand", "11CD00001", 2031, 1);
        let mine = passport(v, "Alex Pierre", "Martin", "18AB12345", 2031, 10);
        pid = mine.id;
        v.items.extend([other, mine]);
    });
    let v = h.fill(&["passport"], ATLAS);
    assert_eq!(
        ok(&v)["passport"],
        json!({"first_names":"Alex Pierre","last_name":"Martin","number":"18AB12345",
               "issuing_country":"FR","issued_on":"2021-03-02","expiry":"2031-03-01",
               "nationality":"FR","sex":"m","birth_date":"1990-05-17","birth_place":"Lyon"})
    );
    assert!(ok(&v).get("driver_license").is_none());
    let ident = h.ids.identity.to_string();
    assert_eq!(
        h.ops(),
        [
            ("fill_identity", Some(ident), Some(ATLAS.to_owned())),
            (
                "fill_document",
                Some(pid.to_string()),
                Some(ATLAS.to_owned())
            ),
        ]
    );
}

#[test]
fn holder_names_fold_case_accents_and_hyphens() {
    let mut h = H::with(|v, ids| {
        set(identity_mut(v, ids), "first_name", text("Jean-Éric"));
        set(identity_mut(v, ids), "last_name", text("Le Gall"));
        let other = passport(v, "Camille", "Durand", "11CD00001", 2031, 1);
        let mine = passport(v, "JEAN ERIC Paul", "LE-GALL", "18AB12345", 2031, 10);
        v.items.extend([other, mine]);
    });
    let v = h.fill(&["passport"], ATLAS);
    assert_eq!(ok(&v)["passport"]["number"], "18AB12345");
}

#[test]
fn two_passports_of_the_holder_give_the_latest_valid_one() {
    // The newest is expired: the older valid one.
    let mut h = H::with(|v, _| {
        let old = passport(v, "Alex", "Martin", "OLD000001", 2031, 400);
        let expired = passport(v, "Alex", "Martin", "EXP000001", 2025, 1);
        v.items.extend([old, expired]);
    });
    assert_eq!(
        ok(&h.fill(&["passport"], ATLAS))["passport"]["number"],
        "OLD000001"
    );
    // Both valid: the most recent.
    let mut h = H::with(|v, _| {
        let old = passport(v, "Alex", "Martin", "OLD000001", 2031, 400);
        let new = passport(v, "Alex", "Martin", "NEW000001", 2034, 3);
        v.items.extend([old, new]);
    });
    assert_eq!(
        ok(&h.fill(&["passport"], ATLAS))["passport"]["number"],
        "NEW000001"
    );
    // Both expired: none.
    let mut h = H::with(|v, _| {
        let a = passport(v, "Alex", "Martin", "EXP000001", 2024, 400);
        let b = passport(v, "Alex", "Martin", "EXP000002", 2025, 3);
        v.items.extend([a, b]);
    });
    let v = h.fill(&["passport"], ATLAS);
    assert!(ok(&v).get("passport").is_none());
    assert_eq!(h.ops().len(), 1);
}

#[test]
fn single_identity_and_single_passport_go_together() {
    // No holder match, but the vault has one identity and one passport.
    let mut h = H::with(|v, _| {
        let p = passport(v, "Sacha", "Bernard", "18AB12345", 2031, 10);
        v.items.push(p);
    });
    assert_eq!(
        ok(&h.fill(&["passport"], ATLAS))["passport"]["number"],
        "18AB12345"
    );
    // Two passports of other people: none.
    let mut h = H::with(|v, _| {
        let a = passport(v, "Sacha", "Bernard", "18AB12345", 2031, 10);
        let b = passport(v, "Camille", "Durand", "11CD00001", 2031, 1);
        v.items.extend([a, b]);
    });
    assert!(ok(&h.fill(&["passport"], ATLAS)).get("passport").is_none());
    // Two identities: none either.
    let mut h = H::with(|v, _| {
        let p = passport(v, "Sacha", "Bernard", "18AB12345", 2031, 10);
        let mut other = new_item(ItemType::Identity, vault_of(v), "Sacha Bernard");
        set(&mut other, "first_name", text("Sacha"));
        v.items.extend([p, other]);
    });
    assert!(ok(&h.fill(&["passport"], ATLAS)).get("passport").is_none());
}

#[test]
fn archived_trashed_or_hidden_documents_never_leave() {
    for how in ["archived", "trashed", "hidden"] {
        let mut h = H::with(|v, _| {
            let mut p = passport(v, "Alex", "Martin", "18AB12345", 2031, 10);
            let mut l = license(v, "Alex Martin", "120375201234");
            let mut r = program(v, ItemType::RewardProgram, "Atlas Miles", "AM123", ATLAS);
            for i in [&mut p, &mut l, &mut r] {
                match how {
                    "archived" => i.archived = true,
                    "trashed" => i.trashed_at = Some(OffsetDateTime::UNIX_EPOCH),
                    _ => i.hide_from_autofill = true,
                }
            }
            v.items.extend([p, l, r]);
        });
        let v = h.fill(&["passport", "driver_license", "loyalty"], ATLAS);
        let o = ok(&v);
        for k in ["passport", "driver_license", "loyalty"] {
            assert!(o.get(k).is_none(), "{how} {k}");
        }
        assert!(!v.to_string().contains("18AB12345"), "{how}");
    }
}

#[test]
fn driver_license_of_the_holder() {
    let mut lid = Id::new();
    let mut h = H::with(|v, _| {
        let other = license(v, "Camille Durand", "990000000001");
        let mine = license(v, "MARTIN Alex", "120375201234");
        lid = mine.id;
        v.items.extend([other, mine]);
    });
    let v = h.fill(&["driver_license"], ATLAS);
    assert_eq!(
        ok(&v)["driver_license"],
        json!({"number":"120375201234","country":"FR","issued_on":"2015-06-03",
               "expiry":"2030-06-03"})
    );
    assert!(ok(&v).get("passport").is_none());
    assert_eq!(h.ops()[1].0, "fill_document");
    assert_eq!(h.ops()[1].1, Some(lid.to_string()));
    // A first name inside another word is not the holder.
    let mut h = H::with(|v, _| {
        let a = license(v, "Alexandra Martin", "990000000001");
        let b = license(v, "Camille Durand", "990000000002");
        v.items.extend([a, b]);
    });
    assert!(
        ok(&h.fill(&["driver_license"], ATLAS))
            .get("driver_license")
            .is_none()
    );
}

#[test]
fn loyalty_only_for_the_one_program_of_the_site() {
    let mut rid = Id::new();
    let mut h = H::with(|v, _| {
        let r = program(v, ItemType::RewardProgram, "Atlas Miles", "AM123", ATLAS);
        rid = r.id;
        let elsewhere = program(
            v,
            ItemType::RewardProgram,
            "Volair",
            "VO999",
            "https://volair.test",
        );
        v.items.extend([r, elsewhere]);
    });
    let v = h.fill(&["loyalty"], "https://www.atlas-cloud.test/book");
    assert_eq!(
        ok(&v)["loyalty"],
        json!({"number":"AM123","program":"Atlas Miles"})
    );
    assert_eq!(
        h.ops()[1],
        (
            "fill_loyalty",
            Some(rid.to_string()),
            Some("https://www.atlas-cloud.test/book".to_owned())
        )
    );
    // Another domain, a lookalike: nothing.
    for o in ["https://example.test", "https://atlas-cloud.test.evil.test"] {
        let v = h.fill(&["loyalty"], o);
        assert!(ok(&v).get("loyalty").is_none(), "{o}");
        assert!(!v.to_string().contains("AM123"), "{o}");
    }
    // A membership counts the same; two eligible programs: none.
    let mut h = H::with(|v, _| {
        let m = program(v, ItemType::Membership, "Atlas Club", "CL77", ATLAS);
        v.items.push(m);
    });
    assert_eq!(
        ok(&h.fill(&["loyalty"], ATLAS))["loyalty"]["number"],
        "CL77"
    );
    let mut h = H::with(|v, _| {
        let a = program(v, ItemType::RewardProgram, "Atlas Miles", "AM123", ATLAS);
        let b = program(v, ItemType::Membership, "Atlas Club", "CL77", ATLAS);
        v.items.extend([a, b]);
    });
    assert!(ok(&h.fill(&["loyalty"], ATLAS)).get("loyalty").is_none());
}

#[test]
fn document_with_reprompt_asks_for_it() {
    let build = |approve: bool| {
        H::with(move |v, _| {
            let mut p = passport(v, "Alex", "Martin", "18AB12345", 2031, 10);
            p.reprompt = true;
            v.items.push(p);
            v.approve_reprompt = approve;
        })
    };
    let mut h = build(false);
    let v = h.fill(&["passport"], ATLAS);
    assert_eq!(err(&v), "reprompt_required");
    assert!(!v.to_string().contains("18AB12345"));
    assert!(h.ops().iter().all(|(op, _, _)| *op != "fill_document"));
    // Without the extra, the passport is not looked at.
    assert!(ok(&h.fill(&[], ATLAS)).get("passport").is_none());
    let mut h = build(true);
    assert_eq!(
        ok(&h.fill(&["passport"], ATLAS))["passport"]["number"],
        "18AB12345"
    );
}

#[test]
fn unknown_extra_is_invalid() {
    let mut h = H::new();
    let v = h.fill(&["id_card"], ATLAS);
    assert_eq!(err(&v), "invalid");
}

/// Task 13 (document number security, spec section 9 rule 6): the audit names the documents
/// given, never their numbers; another origin's request gets the passport (no domain on it) but
/// never the loyalty number of a program bound to this site.
#[test]
fn audit_holds_no_document_number() {
    let mut h = H::with(|v, _| {
        let p = passport(v, "Alex", "Martin", "18AB12345", 2031, 10);
        let l = license(v, "Alex Martin", "120375201234");
        let r = program(v, ItemType::RewardProgram, "Atlas Miles", "AM123", ATLAS);
        v.items.extend([p, l, r]);
    });
    let v = h.fill(&["passport", "driver_license", "loyalty"], ATLAS);
    assert_eq!(ok(&v)["loyalty"]["number"], "AM123");
    let seen = format!("{:?}", h.audit.events());
    for n in ["18AB12345", "120375201234", "AM123"] {
        assert!(!seen.contains(n), "{n} in the audit: {seen}");
    }
    let v = h.fill(
        &["passport", "loyalty"],
        "https://atlas-cloud.test.evil.test",
    );
    assert!(ok(&v).get("loyalty").is_none());
}

#[test]
fn a_document_of_another_account_is_never_attached() {
    // Two accounts on the host: the identity is the primary account's, the
    // only passport of its person is the other account's.
    let mut h = H::with(|v, _| {
        v.two_accounts();
        let mut p = passport(v, "Alex", "Martin", "19XX00042", 2031, 10);
        p.vault_id = v.vaults[1].id;
        v.items.push(p);
    });
    let v = h.fill(&["passport"], ATLAS);
    assert!(ok(&v).get("passport").is_none(), "{v}");
    let ops: Vec<&str> = h.ops().iter().map(|o| o.0).collect();
    assert_eq!(ops, ["fill_identity"]);
}
