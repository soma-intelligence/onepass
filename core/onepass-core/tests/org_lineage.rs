//! Org identity, fingerprint and fingerprint words (Business E1).
//!
//! The words vector in `tests/vectors/org/words.hex` was written once by
//! `generate_org_vectors` (ignored) and is frozen: the tests read it back.

mod org_common;

use std::collections::BTreeMap;
use std::path::PathBuf;

use data_encoding::HEXLOWER;
use onepass_core::generator::Wordlist;
use onepass_core::org::{OrgId, fingerprint_words, org_fingerprint};
use org_common::*;
use sha3::Shake256;
use sha3::digest::{ExtendableOutput, Update, XofReader};

const EFF_TEXT: &str = include_str!("../data/eff_large_wordlist.txt");

/// The word derivation, written from the plan independently of the crate:
/// SHAKE256("onepass/org-words/v1" || fpr), 2-byte big-endian draws, a draw
/// below 62208 picks word `v % 7776`, others are skipped, 20 words in 4
/// groups of 5. Also returns how many draws were rejected.
fn reference_words_counted(fpr: &[u8; 32]) -> ([[String; 5]; 4], usize) {
    let words: Vec<&str> = EFF_TEXT.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(words.len(), 7776);
    let mut xof = Shake256::default();
    xof.update(b"onepass/org-words/v1");
    xof.update(fpr);
    let mut reader = xof.finalize_xof();
    let mut out: Vec<String> = Vec::new();
    let mut rejected = 0;
    while out.len() < 20 {
        let mut b = [0u8; 2];
        reader.read(&mut b);
        let v = u32::from(u16::from_be_bytes(b));
        if v < 62208 {
            out.push(words[(v % 7776) as usize].to_string());
        } else {
            rejected += 1;
        }
    }
    let groups: [[String; 5]; 4] =
        std::array::from_fn(|g| std::array::from_fn(|i| out[g * 5 + i].clone()));
    (groups, rejected)
}

fn reference_words(fpr: &[u8; 32]) -> [[String; 5]; 4] {
    reference_words_counted(fpr).0
}

fn vectors_dir() -> PathBuf {
    std::env::var_os("ONEPASS_CORE_VECTORS")
        .map_or_else(
            || PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors"),
            PathBuf::from,
        )
        .join("org")
}

fn read_vector(name: &str) -> BTreeMap<String, String> {
    let text = std::fs::read_to_string(vectors_dir().join(name)).unwrap();
    text.lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| {
            let (k, v) = l.split_once('=').unwrap();
            (k.to_string(), v.to_string())
        })
        .collect()
}

fn ascending_fpr() -> [u8; 32] {
    std::array::from_fn(|i| i as u8)
}

fn joined(words: &[[String; 5]; 4]) -> String {
    words
        .iter()
        .flatten()
        .cloned()
        .collect::<Vec<_>>()
        .join(" ")
}

#[test]
fn fingerprint_is_prefixed_hash() {
    let p = org_secrets().public(OrgId([1; 16])).unwrap();
    assert_eq!(
        org_fingerprint(&p),
        sha256(&[b"onepass/org-fpr/v1", &postcard::to_allocvec(&p).unwrap()])
    );
    assert_ne!(
        org_fingerprint(&p),
        org_fingerprint(&org_secrets().public(OrgId([2; 16])).unwrap())
    );
}

#[test]
fn public_carries_the_secret_halves() {
    let s = org_secrets();
    let p = s.public(OrgId([3; 16])).unwrap();
    assert_eq!(p.org_id, OrgId([3; 16]));
    assert_eq!(p.identity_pub, s.identity.verifying_key());
    assert_eq!(p.audit_kem_pub, s.audit.public().unwrap());
}

#[test]
fn words_follow_the_reference_algorithm() {
    for seed in 0u8..32 {
        let fpr = [seed; 32];
        assert_eq!(
            fingerprint_words(&fpr, Wordlist::EffEnglish),
            reference_words(&fpr)
        );
    }
}

#[test]
fn words_work_on_the_french_list() {
    let w = fingerprint_words(&ascending_fpr(), Wordlist::FrenchDiceware);
    assert_eq!(w.iter().flatten().count(), 20);
    assert_ne!(
        joined(&w),
        joined(&fingerprint_words(&ascending_fpr(), Wordlist::EffEnglish))
    );
}

#[test]
fn words_frozen_vector() {
    let v = read_vector("words.hex");
    let fpr = ascending_fpr();
    assert_eq!(v["fpr"], HEXLOWER.encode(&fpr));
    let words = fingerprint_words(&fpr, Wordlist::EffEnglish);
    assert_eq!(joined(&words), v["words"]);
    assert_eq!(v["words"].split(' ').count(), 20);
}

#[test]
fn words_reject_high_draws() {
    let seed = (0u8..=255)
        .find(|s| reference_words_counted(&[*s; 32]).1 > 0)
        .expect("a seed whose stream has a draw >= 62208");
    let fpr = [seed; 32];
    assert_eq!(
        fingerprint_words(&fpr, Wordlist::EffEnglish),
        reference_words(&fpr)
    );
}

/// Run once to (re)create the frozen file: `cargo test -p onepass-core
/// --features dev-fast-kdf --test org_lineage -- --ignored
/// generate_org_vectors`. The file is committed; the tests only read it.
#[test]
#[ignore]
fn generate_org_vectors() {
    let fpr = ascending_fpr();
    let words = fingerprint_words(&fpr, Wordlist::EffEnglish);
    let s = format!(
        "# frozen org words vector, do not regenerate\nfpr={}\nwords={}\n",
        HEXLOWER.encode(&fpr),
        joined(&words)
    );
    std::fs::create_dir_all(vectors_dir()).unwrap();
    std::fs::write(vectors_dir().join("words.hex"), s).unwrap();
}
