//! The CSCA master list the Apple app ships (apple/App/Resources), the BSI
//! "German Master List".
//!
//! Its signer chains to a brainpoolP512r1 CSCA (csca-germany,
//! ecdsa-with-SHA512), a curve passive authentication does not verify, so
//! the strict `load_master_list` refuses it. The app loads it with
//! `load_master_list_pinned` and the SHA-256 recorded next to the file.

use std::path::PathBuf;

use onepass_core::scan::icao::{IcaoError, load_master_list, load_master_list_pinned};
use sha2::{Digest, Sha256};

/// SHA-256 of apple/App/Resources/csca-masterlist.ml (the app pins the same
/// value in apple/App/Resources/CSCAMasterList.swift).
const SHIPPED_SHA256: &str = "2bc0f28b35d83f2fc2d1495b1c715add358dfb9ba343e9788bc27a19ced13a9f";

fn manifest(rel: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn shipped() -> Vec<u8> {
    manifest("../../apple/App/Resources/csca-masterlist.ml")
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

fn digest(s: &str) -> [u8; 32] {
    unhex(s).try_into().unwrap()
}

#[test]
fn shipped_file_matches_the_pinned_digest() {
    let have: [u8; 32] = Sha256::digest(shipped()).into();
    assert_eq!(have, digest(SHIPPED_SHA256));
}

#[test]
fn pinned_load_of_the_shipped_list_finds_fra_and_usa() {
    let ml = load_master_list_pinned(&shipped(), &digest(SHIPPED_SHA256))
        .expect("the shipped master list loads pinned");
    // The page announces 609 certificates: the brainpoolP512r1 CSCAs are
    // kept (unusable for a signature check, not a reason to fail the load).
    assert!(ml.len() >= 600, "only {} CSCAs", ml.len());
    let countries = ml.country_codes();
    // CSCA subjects carry the ISO 3166-1 alpha-2 code (countryName); DE
    // CSCAs are brainpoolP384r1 and brainpoolP512r1.
    for (state, alpha2) in [("FRA", "FR"), ("USA", "US"), ("DEU", "DE")] {
        assert!(countries.contains(alpha2), "no CSCA for {state}");
    }
}

#[test]
fn pinned_load_refuses_a_digest_mismatch() {
    let mut wrong = digest(SHIPPED_SHA256);
    wrong[0] ^= 1;
    assert_eq!(
        load_master_list_pinned(&shipped(), &wrong).unwrap_err(),
        IcaoError::Protocol("master list digest mismatch")
    );
    // One byte changed in the file: same refusal.
    let mut bytes = shipped();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    assert_eq!(
        load_master_list_pinned(&bytes, &digest(SHIPPED_SHA256)).unwrap_err(),
        IcaoError::Protocol("master list digest mismatch")
    );
}

#[test]
fn pinned_load_still_requires_a_csca_master_list() {
    let junk = b"not a master list".to_vec();
    let pin: [u8; 32] = Sha256::digest(&junk).into();
    assert_eq!(
        load_master_list_pinned(&junk, &pin).unwrap_err(),
        IcaoError::Protocol("master list is not CMS SignedData")
    );
}

/// The strict loader is unchanged: it refuses the BSI list.
#[test]
fn strict_load_refuses_the_shipped_list() {
    assert_eq!(
        load_master_list(&shipped()).unwrap_err(),
        IcaoError::Protocol("master list signer not issued by a listed CSCA")
    );
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
