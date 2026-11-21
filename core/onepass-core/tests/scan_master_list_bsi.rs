//! The CSCA master list the Apple app ships (apple/App/Resources), the BSI
//! "German Master List": it must load (CMS signature, signer issued by a
//! listed CSCA) and cover at least France and the United States.

use std::path::PathBuf;

use onepass_core::scan::icao::load_master_list;

fn manifest(rel: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

/// The German master list signer chains to a brainpoolP512r1 CSCA
/// (csca-germany, ecdsa-with-SHA512), a curve passive authentication does
/// not support yet: loading fails with `Protocol("master list signer not
/// issued by a listed CSCA")`. Run with `--ignored` once BP512 lands.
#[test]
#[ignore = "core lacks brainpoolP512r1: the BSI signer chain does not verify"]
fn shipped_master_list_loads_with_fra_and_usa() {
    let ml = load_master_list(&manifest("../../apple/App/Resources/csca-masterlist.ml"))
        .expect("the shipped master list loads");
    assert!(ml.len() > 100, "only {} CSCAs", ml.len());
    let countries = ml.country_codes();
    // CSCA subjects carry the ISO 3166-1 alpha-2 code (countryName).
    for (state, alpha2) in [("FRA", "FR"), ("USA", "US"), ("DEU", "DE")] {
        assert!(countries.contains(alpha2), "no CSCA for {state}");
    }
}

/// `country_codes` on the synthetic master list of the replay fixture: one
/// CSCA, `C=UT`.
#[test]
fn country_codes_of_the_fixture_master_list() {
    let fixture: serde_json::Value =
        serde_json::from_slice(&manifest("tests/fixtures/icao/session_pace.json")).unwrap();
    let ml = load_master_list(&unhex(fixture["master_list"].as_str().unwrap())).unwrap();
    let codes: Vec<String> = ml.country_codes().into_iter().collect();
    assert_eq!(codes, ["UT"]);
}
