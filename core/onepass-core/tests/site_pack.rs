//! Site pack parser, recipe rules and signed vector. The recipe fixtures are shared with
//! `scripts/test_site_pack.py`, so the Python and Rust rules cannot drift apart.

use std::fs;
use std::path::{Path, PathBuf};

use aws_lc_rs::digest::{SHA256, digest};
use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
use data_encoding::{BASE64, HEXLOWER};
use onepass_core::site_pack::{
    PasskeyLevel, SetupKind, Step, parse, validate_recipe, verify_signed,
};
use onepass_core::{Error, IntegrityError};
use serde_json::{Value, json};

const SEED: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const PUBLIC: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

/// `ONEPASS_CORE_FIXTURES` points at a copy of `tests/fixtures` when the test
/// runs away from the source tree (the Android emulator run).
fn fixtures() -> PathBuf {
    std::env::var_os("ONEPASS_CORE_FIXTURES")
        .map_or_else(
            || Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures"),
            PathBuf::from,
        )
        .join("site-pack")
}

fn recipe_files(kind: &str) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = fs::read_dir(fixtures().join("recipes").join(kind))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect();
    files.sort();
    assert!(!files.is_empty());
    files
}

fn run_recipe(path: &Path) -> Result<usize, &'static str> {
    let v: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    let kind = match v["kind"].as_str().unwrap() {
        "totp" | "setup_totp" => SetupKind::Totp,
        "passkey" | "setup_passkey" => SetupKind::Passkey,
        other => panic!("unknown kind {other}"),
    };
    let domains: Vec<&str> = v["domains"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d.as_str().unwrap())
        .collect();
    validate_recipe(kind, v["steps"].as_array().unwrap(), &domains).map(|s| s.len())
}

#[test]
fn valid_recipe_fixtures_pass() {
    for path in recipe_files("valid") {
        run_recipe(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    }
}

#[test]
fn invalid_recipe_fixtures_fail() {
    for path in recipe_files("invalid") {
        assert!(
            run_recipe(&path).is_err(),
            "{} was accepted",
            path.display()
        );
    }
}

#[test]
fn url_only_recipe_is_empty() {
    assert_eq!(
        run_recipe(&fixtures().join("recipes/valid/url-only.json")),
        Ok(0)
    );
}

fn recipe(kind: SetupKind, steps: Value) -> Result<usize, &'static str> {
    validate_recipe(kind, steps.as_array().unwrap(), &["example.com"]).map(|s| s.len())
}

#[test]
fn whole_word_and_exact_matching() {
    let click =
        |name: &str| json!([{"do":"click","role":"button","name":[name]},{"do":"expect_qr"}]);
    // A destructive word inside a longer word is fine; as a word it is refused.
    assert!(recipe(SetupKind::Totp, click("Payment methods")).is_ok());
    assert!(recipe(SetupKind::Totp, click("Pay now")).is_err());
    assert!(recipe(SetupKind::Totp, click("Supprimer-le")).is_err());
    assert!(recipe(SetupKind::Totp, click("ne pas désactiver")).is_err());
    assert!(recipe(SetupKind::Totp, click("Désactiver")).is_err());
    assert!(recipe(SetupKind::Totp, click("Pagaré")).is_ok());
    // Final names match by equality only.
    assert!(recipe(SetupKind::Totp, click("  VERIFY ")).is_err());
    assert!(recipe(SetupKind::Totp, click("Verify your phone")).is_ok());
    assert!(recipe(SetupKind::Totp, click("Activer la double")).is_ok());
    // wait_for may name a destructive word: it never acts.
    let wait = json!([{"do":"wait_for","role":"button","name":["Delete"]},{"do":"expect_qr"}]);
    assert!(recipe(SetupKind::Totp, wait).is_ok());
}

#[test]
fn goto_host_rules() {
    let goto = |url: &str| json!([{"do":"goto","url":url},{"do":"expect_qr"}]);
    assert!(recipe(SetupKind::Totp, goto("https://example.com/a")).is_ok());
    assert!(recipe(SetupKind::Totp, goto("https://accounts.example.com/a")).is_ok());
    assert!(recipe(SetupKind::Totp, goto("https://EXAMPLE.com./a")).is_ok());
    assert!(recipe(SetupKind::Totp, goto("https://example.com.evil.io/a")).is_err());
    assert!(recipe(SetupKind::Totp, goto("https://notexample.com/a")).is_err());
    assert!(recipe(SetupKind::Totp, goto("https://example.com:8443/a")).is_err());
    assert!(recipe(SetupKind::Totp, goto("https://user@example.com/a")).is_err());
    assert!(recipe(SetupKind::Totp, goto("https://evil.io\\@example.com/")).is_err());
    assert!(recipe(SetupKind::Totp, goto("http://example.com/a")).is_err());
    assert!(recipe(SetupKind::Totp, goto("https://evil.io%2f.example.com/a")).is_err());
    let long = format!("https://example.com/{}", "a".repeat(2040));
    assert!(recipe(SetupKind::Totp, goto(&long)).is_err());
}

#[test]
fn step_shapes() {
    let ok = recipe(
        SetupKind::Passkey,
        json!([{"do":"reauth","timeout_s":5},{"do":"expect_passkey_prompt"}]),
    );
    assert_eq!(ok, Ok(2));
    let steps = validate_recipe(
        SetupKind::Passkey,
        json!([{"do":"reauth","timeout_s":5},{"do":"expect_passkey_prompt"}])
            .as_array()
            .unwrap(),
        &["example.com"],
    )
    .unwrap();
    assert_eq!((steps[0].timeout_s, steps[1].timeout_s), (5, 60));
    assert_eq!(steps[1].step, Step::ExpectPasskeyPrompt);
    assert!(recipe(SetupKind::Totp, json!([{"do":"expect_qr","timeout_s":0}])).is_err());
    assert!(recipe(SetupKind::Totp, json!([{"do":"expect_qr","timeout_s":1.5}])).is_err());
    assert!(
        recipe(
            SetupKind::Totp,
            json!([{"do":"expect_qr","timeout_s":true}])
        )
        .is_err()
    );
    assert!(
        recipe(
            SetupKind::Totp,
            json!([{"do":"click","role":"div","name":["x"]},{"do":"expect_qr"}])
        )
        .is_err()
    );
    assert!(
        recipe(
            SetupKind::Totp,
            json!([{"do":"click","role":"button","name":[]},{"do":"expect_qr"}])
        )
        .is_err()
    );
    let long = "n".repeat(81);
    assert!(
        recipe(
            SetupKind::Totp,
            json!([{"do":"click","role":"button","name":[long]},{"do":"expect_qr"}])
        )
        .is_err()
    );
    let css = "c".repeat(201);
    assert!(
        recipe(
            SetupKind::Totp,
            json!([{"do":"wait_for","role":"tab","name":["x"],"css":css},{"do":"expect_qr"}])
        )
        .is_err()
    );
    assert!(recipe(SetupKind::Passkey, json!([{"do":"expect_qr"}])).is_err());
    assert!(recipe(SetupKind::Totp, json!([{"do":"done"}])).is_err());
}

fn read_pack() -> Vec<u8> {
    fs::read(fixtures().join("signed/onepass-sites-2026112001.json")).unwrap()
}

#[test]
fn expected_pack_parses() {
    let pack = parse(&fs::read(fixtures().join("expected-pack.json")).unwrap()).unwrap();
    assert_eq!(pack.version, 2026112001);
    assert_eq!(pack.sites.len(), 4);
    let amazon = &pack.sites["amazon.com"];
    assert_eq!(amazon.passkey, Some(PasskeyLevel::Mfa));
    assert_eq!(amazon.twofa, ["sms", "totp"]);
    assert_eq!(amazon.additional_domains, ["amazon.de", "amazon.fr"]);
    assert_eq!(
        amazon.help.as_deref(),
        Some("https://www.amazon.com/passkeys")
    );
    assert_eq!(
        pack.sites["dropbox.com"].passkey,
        Some(PasskeyLevel::Signin)
    );
    assert!(pack.sites["ovh.com"].passkey.is_none());
    let github = &pack.sites["github.com"];
    assert_eq!(
        github.setup_totp.as_ref().unwrap().url,
        "https://github.com/settings/security"
    );
    let steps = github.setup_totp.as_ref().unwrap().recipe.as_ref().unwrap();
    assert_eq!(steps.len(), 5);
    assert_eq!(steps[4].step, Step::ExpectQr);
    let passkey = github.setup_passkey.as_ref().unwrap();
    assert_eq!(passkey.url, "https://github.com/settings/security");
    assert!(passkey.recipe.is_none());
}

#[test]
fn bad_recipe_drops_only_that_recipe() {
    let bad: Value = serde_json::from_slice(
        &fs::read(fixtures().join("recipes/invalid/goto-other-domain.json")).unwrap(),
    )
    .unwrap();
    let pack = json!({"format":1,"version":7,"sites":{
        "example.com": {
            "twofa": ["totp"],
            "setup_totp": {
                "url": "https://example.com/settings/security",
                "verified": {"date":"2026-11-20","browser":"firefox"},
                "steps": bad["steps"]
            }
        },
        "other.org": {"twofa":["sms"], "passkey":"signin"}
    }});
    let pack = parse(&serde_json::to_vec(&pack).unwrap()).unwrap();
    let site = &pack.sites["example.com"];
    let setup = site.setup_totp.as_ref().unwrap();
    assert_eq!(setup.url, "https://example.com/settings/security");
    assert!(setup.recipe.is_none());
    assert_eq!(site.twofa, ["totp"]);
    assert_eq!(pack.sites["other.org"].passkey, Some(PasskeyLevel::Signin));
}

#[test]
fn bad_entries_are_skipped_not_fatal() {
    let pack = json!({"format":1,"version":7,"sites":{
        "good.com": {"twofa":["totp"]},
        "BAD.com": {"twofa":["totp"]},
        "worse.com": {"twofa":"totp"},
        "odd.com": {"passkey":"maybe"},
        "unverified.com": {"setup_totp": {"url":"https://unverified.com/s","steps":[]}},
        "offsite.com": {"setup_totp": {"url":"https://elsewhere.net/s",
            "verified":{"date":"2026-11-20","browser":"safari"},"steps":[]}}
    }});
    let pack = parse(&serde_json::to_vec(&pack).unwrap()).unwrap();
    let names: Vec<_> = pack.sites.keys().map(String::as_str).collect();
    assert_eq!(names, ["good.com", "offsite.com", "unverified.com"]);
    assert!(pack.sites["unverified.com"].setup_totp.is_none());
    assert!(pack.sites["offsite.com"].setup_totp.is_none());
}

#[test]
fn wrong_format_or_oversize_refused() {
    let refused = |bytes: &[u8]| matches!(parse(bytes), Err(Error::InvalidFormat(_)));
    assert!(refused(br#"{"format":2,"version":1,"sites":{}}"#));
    assert!(refused(br#"{"version":1,"sites":{}}"#));
    assert!(refused(br#"{"format":1,"sites":{}}"#));
    assert!(refused(b"not json"));
    assert!(refused(b"[]"));
    let mut big = br#"{"format":1,"version":1,"sites":{}}"#.to_vec();
    big.resize(16 * 1024 * 1024 + 1, b' ');
    assert!(refused(&big));
    let mut sites = String::from(r#"{"format":1,"version":1,"sites":{"#);
    for i in 0..100_001 {
        if i > 0 {
            sites.push(',');
        }
        sites.push_str(&format!("\"s{i}.com\":{{}}"));
    }
    sites.push_str("}}");
    assert!(refused(sites.as_bytes()));
    let at_cap = sites.replacen(",\"s100000.com\":{}", "", 1);
    assert_eq!(parse(at_cap.as_bytes()).unwrap().sites.len(), 100_000);
}

fn public_key() -> Vec<u8> {
    HEXLOWER.decode(PUBLIC.as_bytes()).unwrap()
}

fn sign(manifest: &[u8]) -> Vec<u8> {
    let seed = HEXLOWER.decode(SEED.as_bytes()).unwrap();
    let key = Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
    assert_eq!(key.public_key().as_ref(), public_key().as_slice());
    format!("{}\n", BASE64.encode(key.sign(manifest).as_ref())).into_bytes()
}

fn signed() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let dir = fixtures().join("signed");
    (
        fs::read(dir.join("site-pack-manifest.json")).unwrap(),
        fs::read(dir.join("site-pack-manifest.json.sig")).unwrap(),
        read_pack(),
    )
}

fn manifest_for(pack: &[u8], edit: impl FnOnce(&mut Value)) -> Vec<u8> {
    let mut m = json!({"format":1,"version":2026112001,"sites":4,"sources":{},
        "pack":{"file":"onepass-sites-2026112001.json","size":pack.len(),
        "sha256":HEXLOWER.encode(digest(&SHA256, pack).as_ref())}});
    edit(&mut m);
    serde_json::to_vec(&m).unwrap()
}

fn integrity(r: onepass_core::Result<onepass_core::site_pack::SitePack>) -> Option<IntegrityError> {
    match r {
        Err(Error::Integrity(e)) => Some(e),
        _ => None,
    }
}

#[test]
fn signed_vector_verifies() {
    let (manifest, sig, pack) = signed();
    let parsed = verify_signed(&manifest, &sig, &pack, &public_key()).unwrap();
    assert_eq!(parsed.version, 2026112001);
    assert_eq!(parsed.sites.len(), 4);
    assert!(
        parsed.sites["github.com"]
            .setup_totp
            .as_ref()
            .unwrap()
            .recipe
            .is_some()
    );
    // Our own signing helper agrees with the Python signature byte for byte.
    assert_eq!(sign(&manifest), sig);
}

#[test]
fn tampered_pack_refused() {
    let (manifest, sig, mut pack) = signed();
    let at = pack.iter().position(|b| *b == b'z').unwrap_or(10);
    pack[at] ^= 1;
    assert_eq!(
        integrity(verify_signed(&manifest, &sig, &pack, &public_key())),
        Some(IntegrityError::ManifestItemMismatch)
    );
    let (mut manifest, sig, pack) = signed();
    let at = manifest.iter().position(|b| *b == b'4').unwrap();
    manifest[at] = b'5';
    assert_eq!(
        integrity(verify_signed(&manifest, &sig, &pack, &public_key())),
        Some(IntegrityError::Signature)
    );
}

#[test]
fn manifest_size_or_sha_mismatch_refused() {
    let (_, _, pack) = signed();
    let wrong_size = manifest_for(&pack, |m| m["pack"]["size"] = json!(pack.len() + 1));
    let wrong_sha = manifest_for(&pack, |m| m["pack"]["sha256"] = json!("0".repeat(64)));
    for manifest in [wrong_size, wrong_sha] {
        let sig = sign(&manifest);
        assert_eq!(
            integrity(verify_signed(&manifest, &sig, &pack, &public_key())),
            Some(IntegrityError::ManifestItemMismatch)
        );
    }
    let good = manifest_for(&pack, |_| {});
    verify_signed(&good, &sign(&good), &pack, &public_key()).unwrap();
}

#[test]
fn manifest_version_differs_from_pack_refused() {
    let (_, _, pack) = signed();
    let manifest = manifest_for(&pack, |m| m["version"] = json!(2026112002u64));
    let r = verify_signed(&manifest, &sign(&manifest), &pack, &public_key());
    assert!(matches!(r, Err(Error::InvalidFormat(_))));
}

#[test]
fn wrong_key_refused() {
    let (manifest, sig, pack) = signed();
    let mut other = public_key();
    other[0] ^= 1;
    assert_eq!(
        integrity(verify_signed(&manifest, &sig, &pack, &other)),
        Some(IntegrityError::Signature)
    );
    assert_eq!(
        integrity(verify_signed(&manifest, &sig, &pack, &[1, 2, 3])),
        Some(IntegrityError::Signature)
    );
    assert_eq!(
        integrity(verify_signed(
            &manifest,
            b"!!not base64!!\n",
            &pack,
            &public_key()
        )),
        Some(IntegrityError::Signature)
    );
}

#[test]
fn bad_file_name_refused() {
    let (_, _, pack) = signed();
    for name in [
        "../onepass-sites-2026112001.json",
        "onepass-sites-.json",
        "onepass-sites-1234567890123.json",
        "onepass-sites-12a.json",
        "sites-2026112001.json",
        "onepass-sites-2026112001.json.exe",
    ] {
        let manifest = manifest_for(&pack, |m| m["pack"]["file"] = json!(name));
        let r = verify_signed(&manifest, &sign(&manifest), &pack, &public_key());
        assert!(matches!(r, Err(Error::InvalidFormat(_))), "{name}");
    }
}

#[test]
fn invalid_fixtures_fail_for_their_own_reason() {
    let expected = [
        ("click-delete-fr", "destructive"),
        ("click-pay", "destructive"),
        ("click-verify-final", "final verify"),
        ("empty-name", "name is not"),
        ("goto-backslash-host", "goto url"),
        ("goto-http", "goto url"),
        ("goto-lookalike", "goto url"),
        ("goto-other-domain", "goto url"),
        ("goto-percent-host", "goto url"),
        ("text-entry", "unknown step"),
        ("thirteen-steps", "more than 12"),
        ("timeout-61", "timeout_s"),
        ("totp-ends-without-expect-qr", "does not end"),
        ("totp-with-passkey-prompt", "other kind"),
        ("unknown-do", "unknown step"),
        ("unknown-key", "unknown key"),
    ];
    let files = recipe_files("invalid");
    assert_eq!(files.len(), expected.len());
    for (name, part) in expected {
        let reason =
            run_recipe(&fixtures().join(format!("recipes/invalid/{name}.json"))).unwrap_err();
        assert!(reason.contains(part), "{name}: {reason}");
    }
}

fn pack_with_additional(key: &str, extra: &str) -> onepass_core::site_pack::SitePack {
    let pack = json!({"format":1,"version":7,"sites":{
        key: {
            "additional_domains": [extra],
            "setup_totp": {
                "url": "https://example.com/s",
                "verified": {"date":"2026-11-20","browser":"firefox"},
                "steps": [{"do":"goto","url":"https://evil.example.org/x"},{"do":"expect_qr"}]
            }
        },
        "safe.net": {"twofa": ["totp"]}
    }});
    parse(&serde_json::to_vec(&pack).unwrap()).unwrap()
}

#[test]
fn public_suffix_additional_domains_do_not_widen_the_allow_list() {
    for extra in [
        "com",
        "co.uk",
        "github.io",
        "org",
        "a..b",
        "1.2.3.4",
        "-a.com",
        "a-.com",
    ] {
        let pack = pack_with_additional("example.com", extra);
        let site = &pack.sites["example.com"];
        assert!(site.additional_domains.is_empty(), "{extra} was accepted");
        // The recipe goes to evil.example.org: only a widened allow-list could pass it.
        assert!(
            site.setup_totp.as_ref().unwrap().recipe.is_none(),
            "{extra} widened it"
        );
        assert!(pack.sites.contains_key("safe.net"));
    }
    // A fine additional domain still works, and a recipe goto to it passes.
    let pack = pack_with_additional("example.com", "example.org");
    let setup = pack.sites["example.com"].setup_totp.as_ref().unwrap();
    assert!(setup.recipe.is_some());
}

#[test]
fn public_suffix_site_key_is_skipped() {
    for key in ["co.uk", "com", "github.io", "localhost", "1.2.3.4"] {
        let pack = json!({"format":1,"version":7,"sites":{key: {"twofa":["totp"]}, "ok.com": {}}});
        let pack = parse(&serde_json::to_vec(&pack).unwrap()).unwrap();
        assert_eq!(pack.sites.keys().collect::<Vec<_>>(), ["ok.com"], "{key}");
    }
}
