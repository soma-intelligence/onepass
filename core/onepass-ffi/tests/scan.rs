//! Passport chip reading over the UniFFI surface: MRZ parsing, the ICAO
//! session object, and the chip read turned into (or merged with) an item.
//!
//! Synthetic data only: the ICAO specimen (ERIKSSON ANNA MARIA, L898902C3)
//! and the replay fixture of onepass-core (tests/fixtures/icao). The replay
//! test needs `--features scan-test-rng`.

use std::sync::Arc;

use onepass_ffi::*;
use tempfile::TempDir;

const L1: &str = "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<";
const L2: &str = "L898902C36UTO7408122F1204159ZE184226B<<<<<10";

const FAST: FfiKdfParams = FfiKdfParams {
    m_kib: 8192,
    t: 1,
    p: 1,
};

fn specimen() -> Vec<String> {
    vec![L1.into(), L2.into()]
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

fn fixture() -> serde_json::Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../onepass-core/tests/fixtures/icao/session_pace.json"
    );
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn fixture_master_list() -> Vec<u8> {
    unhex(fixture()["master_list"].as_str().unwrap())
}

fn session() -> (TempDir, Arc<Session>, String) {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("onepass.db").to_string_lossy().into_owned();
    let created = create_account_with_kdf(path, "Café-étoile".into(), FAST).unwrap();
    let vault_id = created.session.vaults().unwrap()[0].id.clone();
    (dir, created.session, vault_id)
}

fn read(status: FfiChipStatus) -> FfiChipRead {
    FfiChipRead {
        mrz: mrz_parse(specimen()).unwrap(),
        portrait: Some(vec![0xFF, 0xD8, 0xFF, 0xE0]),
        portrait_format: Some(FfiImageFormat::Jpeg),
        status,
    }
}

/// A text-like field's value.
fn field(item: &FfiItem, id: &str) -> String {
    let f = item
        .sections
        .iter()
        .flat_map(|s| s.fields.iter())
        .find(|f| f.id == id)
        .unwrap_or_else(|| panic!("no field {id}"));
    match &f.value {
        FfiFieldValue::Text { value } | FfiFieldValue::Concealed { value } => value.clone(),
        other => panic!("{id}: {other:?}"),
    }
}

#[test]
fn mrz_parse_reads_the_specimen() {
    let m = mrz_parse(specimen()).unwrap();
    assert_eq!(m.document_code, "P");
    assert_eq!(m.issuing_state, "UTO");
    assert_eq!(m.surname, "ERIKSSON");
    assert_eq!(m.given_names, "ANNA MARIA");
    assert_eq!(m.document_number, "L898902C3");
    assert_eq!(m.nationality, "UTO");
    assert_eq!(m.birth_date, "740812");
    assert_eq!(m.sex, "F");
    assert_eq!(m.expiry_date, "120415");
    assert_eq!(m.lines, specimen());
    // Debug never shows identity data.
    assert!(!format!("{m:?}").contains("ERIKSSON"));
}

#[test]
fn mrz_parse_refuses_a_bad_check_digit() {
    let bad = vec![L1.into(), L2.replacen("C36", "C35", 1)];
    assert!(matches!(
        mrz_parse(bad),
        Err(OnePassError::Validation { field, .. }) if field == "mrz"
    ));
    assert!(mrz_parse(vec![L1.into()]).is_err());
}

#[test]
fn session_refuses_a_bad_master_list_or_mrz() {
    assert!(FfiIcaoSession::new(specimen(), vec![0x30, 0x00]).is_err());
    assert!(FfiIcaoSession::new(vec!["P<".into()], fixture_master_list()).is_err());
}

#[test]
fn session_starts_by_selecting_the_master_file_then_ef_card_access() {
    let s = FfiIcaoSession::new(specimen(), fixture_master_list()).unwrap();
    assert_eq!(
        s.start(),
        FfiIcaoStep::Send {
            apdu: unhex("00A4000C023F00")
        }
    );
    // Whatever the chip answers to SELECT MF, EF.CardAccess comes next.
    assert_eq!(
        s.on_response(unhex("6A82")),
        FfiIcaoStep::Send {
            apdu: unhex("00A4020C02011C")
        }
    );
    assert_eq!(s.progress(), 0.0);
}

/// No EF.CardAccess: BAC. The chip refuses EXTERNAL AUTHENTICATE (6300):
/// wrong MRZ data, `AccessDenied`.
#[test]
fn refused_bac_is_access_denied() {
    let s = FfiIcaoSession::new(specimen(), fixture_master_list()).unwrap();
    let mut step = s.start();
    for _ in 0..8 {
        let FfiIcaoStep::Send { apdu } = step else {
            break;
        };
        let answer = match apdu[1] {
            0xA4 if apdu[2] != 0x02 => unhex("9000"),
            0xA4 => unhex("6A82"),
            0x84 => unhex("01020304050607089000"),
            0x82 => unhex("6300"),
            ins => panic!("unexpected INS {ins:02X}"),
        };
        step = s.on_response(answer);
    }
    assert_eq!(
        step,
        FfiIcaoStep::Failed {
            reason: FfiIcaoFailure::AccessDenied
        }
    );
}

#[test]
fn garbage_answer_is_other() {
    let s = FfiIcaoSession::new(specimen(), fixture_master_list()).unwrap();
    s.start();
    // SELECT MF, then SELECT EF.CardAccess refused: BAC, SELECT applet
    // refused with 6A82.
    let FfiIcaoStep::Send { .. } = s.on_response(unhex("9000")) else {
        panic!("SELECT EF.CardAccess expected");
    };
    let FfiIcaoStep::Send { .. } = s.on_response(unhex("6A82")) else {
        panic!("BAC expected");
    };
    assert_eq!(
        s.on_response(unhex("6A82")),
        FfiIcaoStep::Failed {
            reason: FfiIcaoFailure::Other
        }
    );
}

#[cfg(feature = "scan-test-rng")]
#[test]
fn replays_the_fixture_read() {
    let v = fixture();
    let r = &v["random"];
    let s = FfiIcaoSession::new_replayable(
        specimen(),
        fixture_master_list(),
        v["today"].as_str().unwrap().into(),
        FfiIcaoTestRandom {
            bac_rnd_ifd: unhex(r["bac_rnd_ifd"].as_str().unwrap()),
            bac_k_ifd: unhex(r["bac_k_ifd"].as_str().unwrap()),
            pace_map_sk: unhex(r["pace_map_sk"].as_str().unwrap()),
            pace_eph_sk: unhex(r["pace_eph_sk"].as_str().unwrap()),
        },
    )
    .unwrap();
    let mut step = s.start();
    for e in v["exchange"].as_array().unwrap() {
        let FfiIcaoStep::Send { apdu } = step else {
            panic!("session ended early");
        };
        assert_eq!(apdu, unhex(e["command"].as_str().unwrap()));
        step = s.on_response(unhex(e["response"].as_str().unwrap()));
    }
    let FfiIcaoStep::Done { read } = step else {
        panic!("read expected, got {step:?}");
    };
    assert_eq!(read.status, FfiChipStatus::Verified);
    assert_eq!(read.portrait_format, Some(FfiImageFormat::Jpeg));
    assert_eq!(read.mrz.document_number, "L898902C3");
    assert_eq!(s.progress(), 1.0);
}

#[test]
fn item_from_chip_makes_an_unsaved_passport() {
    let (_dir, s, vault) = session();
    let item = s
        .item_from_chip(vault.clone(), read(FfiChipStatus::Verified))
        .unwrap();
    assert_eq!(item.item_type, FfiItemType::Passport);
    assert_eq!(item.title, "Passeport UTO");
    assert_eq!(item.vault_id, vault);
    assert!(s.item_summaries().unwrap().is_empty());
    assert_eq!(field(&item, "number"), "L898902C3");
    assert_eq!(field(&item, "last_name"), "Eriksson");
    assert!(
        s.item_from_chip(
            "00000000000000000000000000000000".into(),
            read(FfiChipStatus::Verified)
        )
        .is_err()
    );
}

#[test]
fn merge_chip_keeps_user_edits_and_reports_conflicts() {
    let (_dir, s, vault) = session();
    let mut item = s
        .item_from_chip(vault.clone(), read(FfiChipStatus::Unverifiable))
        .unwrap();
    for f in item.sections.iter_mut().flat_map(|s| s.fields.iter_mut()) {
        if f.id == "number" {
            f.value = FfiFieldValue::Concealed {
                value: "X1234567".into(),
            };
        }
    }
    let saved = s.save_item(item).unwrap();
    let merged = s
        .merge_chip(saved.clone(), read(FfiChipStatus::Verified))
        .unwrap();
    assert_eq!(merged.item.id, saved.id);
    assert_eq!(field(&merged.item, "number"), "X1234567");
    assert_eq!(merged.conflicts.len(), 1);
    assert_eq!(merged.conflicts[0].field_id, "number");
    assert_eq!(merged.conflicts[0].scanned, "L898902C3");

    let login = s
        .new_item(vault, FfiItemType::Login, "Not a passport".into())
        .unwrap();
    assert!(s.merge_chip(login, read(FfiChipStatus::Verified)).is_err());
}

/// The app's path: the shipped BSI list (its signer is not verifiable by
/// the core), pinned by its SHA-256.
#[test]
fn pinned_session_takes_the_shipped_master_list() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../apple/App/Resources/csca-masterlist.ml"
    );
    let ml = std::fs::read(path).unwrap();
    let pin = unhex("2bc0f28b35d83f2fc2d1495b1c715add358dfb9ba343e9788bc27a19ced13a9f");
    // The strict constructor refuses it.
    assert!(FfiIcaoSession::new(specimen(), ml.clone()).is_err());
    let s = FfiIcaoSession::new_pinned(specimen(), ml.clone(), pin.clone()).unwrap();
    assert_eq!(
        s.start(),
        FfiIcaoStep::Send {
            apdu: unhex("00A4000C023F00")
        }
    );
    let mut wrong = pin.clone();
    wrong[31] ^= 1;
    assert!(matches!(
        FfiIcaoSession::new_pinned(specimen(), ml.clone(), wrong),
        Err(OnePassError::InvalidInput { what }) if what == "master list"
    ));
    assert!(FfiIcaoSession::new_pinned(specimen(), ml, pin[..31].to_vec()).is_err());
}
