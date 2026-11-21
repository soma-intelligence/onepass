//! Watchtower over the UniFFI surface. Run with `--features dev-fast-kdf`.

use std::sync::Arc;

use onepass_ffi::watchtower::{
    FfiPwnedStatus, FfiRangeResponse, FfiWatchtowerOptions, site_pack_version, verify_site_pack,
};
use onepass_ffi::*;
use tempfile::TempDir;

const FAST: FfiKdfParams = FfiKdfParams {
    m_kib: 8192,
    t: 1,
    p: 1,
};

struct Fixture {
    _dir: TempDir,
    session: Arc<Session>,
    vault_id: String,
}

fn fixture() -> Fixture {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("onepass.db").to_string_lossy().into_owned();
    let created = create_account_with_kdf(path, "Café-étoile".into(), FAST).unwrap();
    let vault_id = created.session.vaults().unwrap()[0].id.clone();
    Fixture {
        _dir: dir,
        session: created.session,
        vault_id,
    }
}

fn login(fx: &Fixture, title: &str, password: &str, url: &str) -> FfiItem {
    let mut item = fx
        .session
        .new_item(fx.vault_id.clone(), FfiItemType::Login, title.into())
        .unwrap();
    for f in item.sections.iter_mut().flat_map(|s| s.fields.iter_mut()) {
        match f.id.as_str() {
            "username" => {
                f.value = FfiFieldValue::Text {
                    value: "camille@exemple.fr".into(),
                }
            }
            "password" => {
                f.value = FfiFieldValue::Password {
                    value: password.into(),
                }
            }
            _ => {}
        }
    }
    item.urls = vec![FfiUrl {
        label: String::new(),
        url: url.into(),
        rule: FfiMatchRule::Domain,
        primary: true,
    }];
    fx.session.save_item(item).unwrap()
}

fn options(ranges: Option<Vec<FfiRangeResponse>>) -> FfiWatchtowerOptions {
    FfiWatchtowerOptions {
        expiry_warning_days: 30,
        old_password_days: 365,
        ranges,
        excluded_vault_ids: vec![],
        breach_catalog: None,
        site_pack: None,
    }
}

fn ids<'a>(report: &'a watchtower::FfiWatchtowerReport, check: &str) -> &'a [String] {
    &report
        .checks
        .iter()
        .find(|c| c.check == check)
        .unwrap()
        .item_ids
}

#[test]
fn offline_report_flags_reuse_weak_and_http() {
    let fx = fixture();
    let a = login(&fx, "A", "azerty", "http://exemple.fr");
    let b = login(&fx, "B", "azerty", "https://autre.fr");
    let c = login(&fx, "C", "Tq7#vLr9-pXw2!mZ8kEa-Hs4", "https://troisieme.fr");
    let report = fx.session.watchtower_report(options(None)).unwrap();
    assert_eq!(report.items_analyzed, 3);
    assert_eq!(report.pwned, FfiPwnedStatus::Disabled);
    assert!(report.missing_prefixes.is_empty());
    let mut reused = vec![a.id.clone(), b.id.clone()];
    reused.sort();
    assert_eq!(ids(&report, "reused"), reused.as_slice());
    assert!(ids(&report, "weak").contains(&a.id));
    assert!(!ids(&report, "weak").contains(&c.id));
    assert_eq!(ids(&report, "insecure_url"), std::slice::from_ref(&a.id));
    assert_eq!(report.strength.len(), 5);
    assert_eq!(report.strength.iter().sum::<u32>(), 3);
    assert!(report.score < 100);
    assert!(!report.sites_checked);
}

#[test]
fn breach_lookup_runs_in_two_passes_with_prefixes_only() {
    let fx = fixture();
    // SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8.
    let item = login(&fx, "A", "password", "https://exemple.fr");
    let first = fx.session.watchtower_report(options(Some(vec![]))).unwrap();
    assert_eq!(first.missing_prefixes, ["5BAA6".to_owned()]);
    assert_eq!(first.pwned, FfiPwnedStatus::Unavailable);
    assert!(ids(&first, "compromised").is_empty());

    let body =
        b"1E4C9B93F3F0682250B6CF8331B7EE68FD8:3861493\r\n0000000000000000000000000000000000A:0\r\n";
    let second = fx
        .session
        .watchtower_report(options(Some(vec![FfiRangeResponse {
            prefix: "5BAA6".into(),
            body: body.to_vec(),
        }])))
        .unwrap();
    assert!(second.missing_prefixes.is_empty());
    assert_eq!(second.pwned, FfiPwnedStatus::Checked);
    assert_eq!(ids(&second, "compromised"), std::slice::from_ref(&item.id));
    assert!(second.score < first.score);
}

/// The core's signed site-pack vector. `ONEPASS_CORE_FIXTURES` points at a
/// copy of the core's `tests/fixtures` when the test runs away from the
/// source tree (the Android emulator run).
fn signed(name: &str) -> Vec<u8> {
    let root = std::env::var_os("ONEPASS_CORE_FIXTURES").map_or_else(
        || {
            std::path::PathBuf::from(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../onepass-core/tests/fixtures"
            ))
        },
        std::path::PathBuf::from,
    );
    std::fs::read(root.join("site-pack/signed").join(name)).unwrap()
}

fn signed_key() -> Vec<u8> {
    let text = String::from_utf8(signed("public-key.b64")).unwrap();
    data_encoding::BASE64
        .decode(text.trim().as_bytes())
        .unwrap()
}

fn signed_pack() -> Vec<u8> {
    signed("onepass-sites-2026112001.json")
}

fn link<'a>(
    report: &'a watchtower::FfiWatchtowerReport,
    check: &str,
) -> &'a [watchtower::FfiSiteLink] {
    &report
        .checks
        .iter()
        .find(|c| c.check == check)
        .unwrap()
        .site_links
}

#[test]
fn site_pack_enables_2fa_and_passkey_checks() {
    let fx = fixture();
    let item = login(&fx, "A", "Tq7#vLr9-pXw2!mZ8kEa-Hs4", "https://dropbox.com");
    let mut opts = options(None);
    opts.site_pack = Some(signed_pack());
    let report = fx.session.watchtower_report(opts).unwrap();
    assert!(report.sites_checked);
    assert_eq!(
        ids(&report, "passkey_available"),
        std::slice::from_ref(&item.id)
    );
    // dropbox.com lists no 2FA method in the pack.
    assert!(ids(&report, "missing_2fa").is_empty());

    let other = login(&fx, "B", "Tq7#vLr9-pXw2!mZ8kEa-Hs4", "https://ovh.com");
    let mut opts = options(None);
    opts.site_pack = Some(signed_pack());
    let report = fx.session.watchtower_report(opts).unwrap();
    assert_eq!(ids(&report, "missing_2fa"), std::slice::from_ref(&other.id));
}

#[test]
fn site_links_carry_host_urls_and_recipe() {
    let fx = fixture();
    let gh = login(
        &fx,
        "G",
        "Tq7#vLr9-pXw2!mZ8kEa-Hs4",
        "https://github.com/login",
    );
    let ovh = login(&fx, "O", "Tq7#vLr9-pXw2!mZ8kEa-Hs4", "https://ovh.com");
    let mut opts = options(None);
    opts.site_pack = Some(signed_pack());
    let report = fx.session.watchtower_report(opts).unwrap();

    let twofa = link(&report, "missing_2fa");
    let mut want = vec![gh.id.clone(), ovh.id.clone()];
    want.sort();
    assert_eq!(
        twofa.iter().map(|l| l.item_id.clone()).collect::<Vec<_>>(),
        want
    );
    let gh_link = twofa.iter().find(|l| l.item_id == gh.id).unwrap();
    assert_eq!(gh_link.host, "github.com");
    assert_eq!(
        gh_link.settings_url.as_deref(),
        Some("https://github.com/settings/security")
    );
    assert!(
        gh_link
            .help_url
            .as_deref()
            .unwrap()
            .starts_with("https://docs.github.com/")
    );
    assert!(gh_link.has_recipe);
    let ovh_link = twofa.iter().find(|l| l.item_id == ovh.id).unwrap();
    assert_eq!(ovh_link.settings_url, None);
    assert_eq!(ovh_link.help_url, None);
    assert!(!ovh_link.has_recipe);

    // The passkey setup block of github.com has a URL and no steps.
    let keys = link(&report, "passkey_available");
    assert_eq!(keys.len(), 1);
    let k = keys.first().unwrap();
    assert_eq!(k.item_id, gh.id);
    assert_eq!(
        k.settings_url.as_deref(),
        Some("https://github.com/settings/security")
    );
    assert!(!k.has_recipe);
    // Other checks carry no links.
    assert!(link(&report, "weak").is_empty());
}

#[test]
fn bad_site_pack_means_no_site_checks() {
    let fx = fixture();
    login(&fx, "A", "Tq7#vLr9-pXw2!mZ8kEa-Hs4", "https://github.com");
    let mut opts = options(None);
    opts.site_pack = Some(b"not json".to_vec());
    let report = fx.session.watchtower_report(opts).unwrap();
    assert!(!report.sites_checked);
    assert!(ids(&report, "missing_2fa").is_empty());
    assert!(link(&report, "missing_2fa").is_empty());
}

#[test]
fn verify_site_pack_accepts_the_signed_vector() {
    let version = verify_site_pack(
        signed("site-pack-manifest.json"),
        signed("site-pack-manifest.json.sig"),
        signed_pack(),
        signed_key(),
    )
    .unwrap();
    assert_eq!(version, 2026112001);
    assert_eq!(site_pack_version(signed_pack()).unwrap(), 2026112001);
}

#[test]
fn verify_site_pack_refuses_tampering() {
    let manifest = signed("site-pack-manifest.json");
    let sig = signed("site-pack-manifest.json.sig");
    let key = signed_key();
    let integrity = |r: Result<u64, OnePassError>| matches!(r, Err(OnePassError::Integrity { kind }) if kind == "site_pack");

    // One byte of the pack changed: size kept, hash differs.
    let mut pack = signed_pack();
    let at = pack.iter().position(|b| *b == b'g').unwrap();
    pack[at] = b'h';
    assert!(integrity(verify_site_pack(
        manifest.clone(),
        sig.clone(),
        pack,
        key.clone()
    )));
    // A pack of another size.
    let mut longer = signed_pack();
    longer.push(b' ');
    assert!(integrity(verify_site_pack(
        manifest.clone(),
        sig.clone(),
        longer,
        key.clone()
    )));
    // A manifest that was not signed.
    let mut forged = manifest.clone();
    forged.push(b' ');
    assert!(integrity(verify_site_pack(
        forged,
        sig.clone(),
        signed_pack(),
        key.clone()
    )));
    // Another key.
    assert!(integrity(verify_site_pack(
        manifest,
        sig,
        signed_pack(),
        vec![7u8; 32]
    )));
    // A bundled pack that is not a pack.
    assert!(matches!(
        site_pack_version(b"nope".to_vec()),
        Err(OnePassError::InvalidInput { what }) if what == "site_pack"
    ));
}

#[test]
fn excluded_vaults_are_not_analyzed_and_report_has_no_secret() {
    let fx = fixture();
    login(&fx, "A", "azerty-secret-unique", "https://exemple.fr");
    let mut opts = options(None);
    opts.excluded_vault_ids = vec![fx.vault_id.clone()];
    let report = fx.session.watchtower_report(opts).unwrap();
    assert_eq!(report.items_analyzed, 0);
    assert_eq!(report.score, 100);
    let all = fx.session.watchtower_report(options(None)).unwrap();
    assert!(!format!("{all:?}").contains("azerty-secret-unique"));
}

#[test]
fn locked_session_refuses() {
    let fx = fixture();
    fx.session.lock();
    assert!(matches!(
        fx.session.watchtower_report(options(None)),
        Err(OnePassError::Locked)
    ));
}

#[test]
fn breach_catalog_feeds_breached_site() {
    let fx = fixture();
    let item = login(
        &fx,
        "A",
        "Tq7#vLr9-pXw2!mZ8kEa-Hs4",
        "https://compte.exemple.fr",
    );
    let without = fx.session.watchtower_report(options(None)).unwrap();
    assert!(ids(&without, "breached_site").is_empty());
    // A breach dated after the password was set: the password predates it.
    let catalog = br#"[{"Name":"Exemple","Domain":"exemple.fr","BreachDate":"2099-01-01","IsVerified":true}]"#;
    let mut opts = options(None);
    opts.breach_catalog = Some(catalog.to_vec());
    let with = fx.session.watchtower_report(opts.clone()).unwrap();
    assert_eq!(ids(&with, "breached_site"), std::slice::from_ref(&item.id));
    // A catalog that does not parse turns the check off, nothing else.
    opts.breach_catalog = Some(b"not json".to_vec());
    let bad = fx.session.watchtower_report(opts).unwrap();
    assert!(ids(&bad, "breached_site").is_empty());
    assert_eq!(bad.items_analyzed, 1);
}
