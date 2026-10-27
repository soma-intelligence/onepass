//! Watchtower over the UniFFI surface. Run with `--features dev-fast-kdf`.

use std::sync::Arc;

use onepass_ffi::watchtower::{FfiPwnedStatus, FfiRangeResponse, FfiWatchtowerOptions};
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
        twofa_directory: None,
        passkeys_directory: None,
        excluded_vault_ids: vec![],
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

#[test]
fn sites_directory_enables_2fa_and_passkey_checks() {
    let fx = fixture();
    let item = login(&fx, "A", "Tq7#vLr9-pXw2!mZ8kEa-Hs4", "https://exemple.fr");
    let mut opts = options(None);
    opts.twofa_directory = Some(br#"{"exemple.fr":{"methods":["totp"]}}"#.to_vec());
    opts.passkeys_directory = Some(br#"{"exemple.fr":{"passwordless":"allowed"}}"#.to_vec());
    let report = fx.session.watchtower_report(opts).unwrap();
    assert!(report.sites_checked);
    assert_eq!(ids(&report, "missing_2fa"), std::slice::from_ref(&item.id));
    assert_eq!(
        ids(&report, "passkey_available"),
        std::slice::from_ref(&item.id)
    );
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
