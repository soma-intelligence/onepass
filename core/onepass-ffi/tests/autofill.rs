//! Integration tests of the AutoFill surface: identities for the system
//! store, candidates for a site, passkey creation and assertion.

use std::sync::Arc;

use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1, UnparsedPublicKey};
use onepass_ffi::*;
use tempfile::TempDir;

const PASSWORD: &str = "Café-étoile";
const ABOUT: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const FAST: FfiKdfParams = FfiKdfParams {
    m_kib: 8192,
    t: 1,
    p: 1,
};
const LOGIN_PASSWORD: &str = "Mot-de-passe-Atlas-7";
const TOTP_SECRET: &str = "GEZDGNBVGY3TQOJQ";

struct Fixture {
    _dir: TempDir,
    session: Arc<Session>,
    vault_id: String,
}

fn fixture() -> Fixture {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("onepass.db").to_string_lossy().into_owned();
    let created = create_account_with_kdf(path, PASSWORD.into(), FAST).unwrap();
    let vault_id = created.session.vaults().unwrap()[0].id.clone();
    Fixture {
        _dir: dir,
        session: created.session,
        vault_id,
    }
}

fn second_vault(fx: &Fixture) -> String {
    fx.session
        .create_vault(FfiVaultMeta {
            name: "Famille".into(),
            icon: "folder".into(),
            color: "#336699".into(),
            travel_safe: false,
            mcp_access: false,
        })
        .unwrap()
        .id
}

fn set(item: &mut FfiItem, id: &str, value: FfiFieldValue) {
    for f in item.sections.iter_mut().flat_map(|s| s.fields.iter_mut()) {
        if f.id == id {
            f.value = value.clone();
        }
    }
}

fn text(value: &str) -> FfiFieldValue {
    FfiFieldValue::Text {
        value: value.into(),
    }
}

fn url(u: &str, rule: FfiMatchRule) -> FfiUrl {
    FfiUrl {
        label: String::new(),
        url: u.into(),
        rule,
        primary: false,
    }
}

/// A saved Login of `vault` with these URLs (rule `Domain`).
fn login_in(
    fx: &Fixture,
    vault: &str,
    title: &str,
    urls: &[&str],
    user: &str,
    totp: bool,
) -> FfiItem {
    let mut item = fx
        .session
        .new_item(vault.into(), FfiItemType::Login, title.into())
        .unwrap();
    set(&mut item, "username", text(user));
    set(
        &mut item,
        "password",
        FfiFieldValue::Password {
            value: LOGIN_PASSWORD.into(),
        },
    );
    if totp {
        set(
            &mut item,
            "totp",
            FfiFieldValue::Otp {
                value: TOTP_SECRET.into(),
            },
        );
    }
    item.urls = urls.iter().map(|u| url(u, FfiMatchRule::Domain)).collect();
    fx.session.save_item(item).unwrap()
}

fn login(fx: &Fixture, title: &str, urls: &[&str]) -> FfiItem {
    login_in(fx, &fx.vault_id, title, urls, "camille@exemple.fr", false)
}

/// A saved item of another type, its required fields filled, with a URL
/// and Login-like fields where the template has them.
fn other_item(fx: &Fixture, item_type: FfiItemType, u: &str) -> FfiItem {
    let mut item = fx
        .session
        .new_item(fx.vault_id.clone(), item_type, "Autre".into())
        .unwrap();
    for f in item.sections.iter_mut().flat_map(|s| s.fields.iter_mut()) {
        f.value = match (f.kind, f.required) {
            (FfiFieldType::Mnemonic, true) => FfiFieldValue::Mnemonic {
                value: ABOUT.into(),
            },
            (FfiFieldType::Text, true) => text("camille"),
            (FfiFieldType::Email, true) => FfiFieldValue::Email {
                value: "camille@exemple.fr".into(),
            },
            (FfiFieldType::Password, _) => FfiFieldValue::Password {
                value: LOGIN_PASSWORD.into(),
            },
            (FfiFieldType::Otp, _) => FfiFieldValue::Otp {
                value: TOTP_SECRET.into(),
            },
            (FfiFieldType::Menu, true) => FfiFieldValue::Menu {
                value: menu_options(item_type, f.id.clone())
                    .first()
                    .cloned()
                    .unwrap_or_default(),
            },
            _ => f.value.clone(),
        };
    }
    item.urls = vec![url(u, FfiMatchRule::Domain)];
    fx.session.save_item(item).unwrap()
}

fn creation(vault: &str, item_id: Option<String>, rp_id: &str, user: &str) -> FfiPasskeyCreation {
    FfiPasskeyCreation {
        vault_id: vault.into(),
        item_id,
        rp_id: rp_id.into(),
        user_name: user.into(),
        user_handle: vec![1, 2, 3, 4],
        client_data_hash: vec![9; 32],
        excluded_credential_ids: Vec::new(),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn record_id(vault: &str, item: &str) -> String {
    format!("{vault}:{item}")
}

fn passkey_fields(item: &FfiItem) -> Vec<FfiPasskey> {
    item.sections
        .iter()
        .flat_map(|s| &s.fields)
        .filter_map(|f| match &f.value {
            FfiFieldValue::Passkey { value } => Some(value.clone()),
            _ => None,
        })
        .collect()
}

fn count(ids: &[FfiAutofillIdentity], kind: FfiAutofillKind) -> usize {
    ids.iter().filter(|i| i.kind == kind).count()
}

fn titles(c: &[FfiAutofillCandidate]) -> Vec<(String, FfiMatchQuality)> {
    c.iter().map(|c| (c.title.clone(), c.quality)).collect()
}

// ---- identities -----------------------------------------------------------

#[test]
fn identities_cover_logins_only() {
    let fx = fixture();
    let main = login_in(
        &fx,
        &fx.vault_id,
        "Principal",
        &[
            "https://login.example.com/session",
            "https://www.exemple.fr",
        ],
        "camille",
        true,
    );
    let reg = fx
        .session
        .create_passkey(creation(
            &fx.vault_id,
            Some(main.id.clone()),
            "example.com",
            "camille",
        ))
        .unwrap();

    let trashed = login(&fx, "Corbeille", &["https://trash.example.net"]);
    fx.session
        .trash_item(fx.vault_id.clone(), trashed.id)
        .unwrap();
    let archived = login(&fx, "Archive", &["https://archive.example.net"]);
    fx.session
        .archive_item(fx.vault_id.clone(), archived.id)
        .unwrap();
    let mut hidden = login(&fx, "Masque", &["https://hidden.example.net"]);
    hidden.hide_from_autofill = true;
    fx.session.save_item(hidden).unwrap();
    other_item(&fx, FfiItemType::CryptoWallet, "https://wallet.example.net");
    other_item(&fx, FfiItemType::Email, "https://mail.example.net");

    let ids = fx.session.autofill_identities(Vec::new()).unwrap();
    assert_eq!(count(&ids, FfiAutofillKind::Password), 2, "{ids:?}");
    assert_eq!(count(&ids, FfiAutofillKind::OneTimeCode), 2, "{ids:?}");
    assert_eq!(count(&ids, FfiAutofillKind::Passkey), 1, "{ids:?}");
    assert_eq!(ids.len(), 5);
    let rid = record_id(&fx.vault_id, &main.id);
    assert!(ids.iter().all(|i| i.record_id == rid));
    assert!(ids.iter().all(|i| i.user == "camille"));

    let mut services: Vec<_> = ids
        .iter()
        .filter(|i| i.kind == FfiAutofillKind::Password)
        .map(|i| i.service.clone())
        .collect();
    services.sort();
    assert_eq!(services, ["login.example.com", "www.exemple.fr"]);
    for i in ids.iter().filter(|i| i.kind != FfiAutofillKind::Passkey) {
        assert!(i.credential_id.is_empty() && i.user_handle.is_empty());
    }
    let pk = ids
        .iter()
        .find(|i| i.kind == FfiAutofillKind::Passkey)
        .unwrap();
    assert_eq!(pk.service, "example.com");
    assert_eq!(pk.credential_id, reg.credential_id);
    assert_eq!(pk.user_handle, vec![1, 2, 3, 4]);

    let dump = format!("{ids:?}");
    assert!(!dump.contains(LOGIN_PASSWORD) && !dump.contains(TOTP_SECRET));
}

#[test]
fn identities_mark_favorites() {
    let fx = fixture();
    let item = login(&fx, "Favori", &["https://example.com"]);
    fx.session
        .set_favorite(fx.vault_id.clone(), item.id, true)
        .unwrap();
    let ids = fx.session.autofill_identities(Vec::new()).unwrap();
    assert_eq!(ids.len(), 1);
    assert!(ids[0].favorite);
}

#[test]
fn identities_skip_excluded_vaults() {
    let fx = fixture();
    let other = second_vault(&fx);
    login(&fx, "Perso", &["https://example.com"]);
    let shared = login_in(
        &fx,
        &other,
        "Perso",
        &["https://example.com"],
        "camille@exemple.fr",
        false,
    );

    let all = fx.session.autofill_identities(Vec::new()).unwrap();
    assert_eq!(all.len(), 2);
    let kept = fx.session.autofill_identities(vec![other.clone()]).unwrap();
    assert_eq!(kept.len(), 1);
    assert_ne!(kept[0].record_id, record_id(&other, &shared.id));
    assert!(kept[0].record_id.starts_with(&fx.vault_id));

    let candidates = fx
        .session
        .autofill_candidates("example.com".into(), true, vec![other.clone()])
        .unwrap();
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].vault_id, fx.vault_id);

    assert!(matches!(
        fx.session.autofill_identities(vec!["zz".into()]),
        Err(OnePassError::InvalidInput { .. })
    ));
}

// ---- candidates -----------------------------------------------------------

#[test]
fn candidates_rank_and_reject_lookalikes() {
    let fx = fixture();
    for (title, u) in [
        ("login", "https://login.example.com"),
        ("apex", "https://example.com"),
        ("uk", "https://example.co.uk"),
        ("digit", "https://examp1e.com"),
        ("evil", "https://example.com.evil.net"),
        ("plain", "http://example.com"),
        ("ip", "https://192.168.1.10"),
    ] {
        login(&fx, title, &[u]);
    }
    other_item(&fx, FfiItemType::CryptoWallet, "https://example.com");

    let c = fx
        .session
        .autofill_candidates("www.example.com".into(), false, Vec::new())
        .unwrap();
    let mut got = titles(&c);
    got.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(
        got,
        [
            ("apex".to_owned(), FfiMatchQuality::Domain),
            ("login".to_owned(), FfiMatchQuality::Domain)
        ]
    );

    let c = fx
        .session
        .autofill_candidates(
            "https://login.example.com/path?q=1".into(),
            false,
            Vec::new(),
        )
        .unwrap();
    assert_eq!(
        titles(&c),
        [
            ("login".to_owned(), FfiMatchQuality::ExactHost),
            ("apex".to_owned(), FfiMatchQuality::Domain)
        ]
    );
    assert_eq!(c[0].url.as_deref(), Some("https://login.example.com"));
    assert_eq!(c[0].user, "camille@exemple.fr");
    assert!(c[0].has_password && !c[0].has_totp && c[0].passkeys.is_empty());

    let c = fx
        .session
        .autofill_candidates("example.co.uk".into(), false, Vec::new())
        .unwrap();
    assert_eq!(titles(&c), [("uk".to_owned(), FfiMatchQuality::ExactHost)]);

    let c = fx
        .session
        .autofill_candidates("192.168.1.10".into(), false, Vec::new())
        .unwrap();
    assert_eq!(titles(&c), [("ip".to_owned(), FfiMatchQuality::ExactHost)]);

    // A plain http page of a public domain gets nothing.
    let c = fx
        .session
        .autofill_candidates("http://example.com".into(), false, Vec::new())
        .unwrap();
    assert!(c.is_empty(), "{c:?}");

    let c = fx
        .session
        .autofill_candidates("www.example.com".into(), true, Vec::new())
        .unwrap();
    assert_eq!(c.len(), 7, "every Login, never the wallet");
    assert!(c[..2].iter().all(|c| c.quality == FfiMatchQuality::Domain));
    assert!(c[2..].iter().all(|c| c.quality == FfiMatchQuality::Other));

    let c = fx
        .session
        .autofill_candidates(String::new(), true, Vec::new())
        .unwrap();
    assert_eq!(c.len(), 7);
    assert!(c.iter().all(|c| c.quality == FfiMatchQuality::Other));
    assert!(
        fx.session
            .autofill_candidates(String::new(), false, Vec::new())
            .unwrap()
            .is_empty()
    );
}

#[test]
fn candidates_never_offer_hidden_logins() {
    let fx = fixture();
    login(&fx, "visible", &["https://example.com"]);
    let mut hidden = login(&fx, "hidden", &["https://example.com"]);
    hidden.hide_from_autofill = true;
    fx.session.save_item(hidden).unwrap();
    for include_all in [false, true] {
        for service in ["example.com", ""] {
            let c = fx
                .session
                .autofill_candidates(service.into(), include_all, Vec::new())
                .unwrap();
            assert!(c.iter().all(|c| c.title != "hidden"), "{c:?}");
        }
    }
    let c = fx
        .session
        .autofill_candidates("example.com".into(), true, Vec::new())
        .unwrap();
    assert_eq!(
        titles(&c),
        [("visible".to_owned(), FfiMatchQuality::ExactHost)]
    );
}

#[test]
fn candidates_include_passkeys_by_rp_id() {
    let fx = fixture();
    let bare = login(&fx, "sans URL", &[]);
    fx.session
        .create_passkey(creation(
            &fx.vault_id,
            Some(bare.id.clone()),
            "example.com",
            "camille",
        ))
        .unwrap();
    let mut hidden = login(&fx, "cachée", &[]);
    hidden = fx
        .session
        .item(
            fx.vault_id.clone(),
            fx.session
                .create_passkey(creation(
                    &fx.vault_id,
                    Some(hidden.id.clone()),
                    "example.com",
                    "dominique",
                ))
                .unwrap()
                .item_id,
        )
        .unwrap();
    hidden.hide_from_autofill = true;
    fx.session.save_item(hidden).unwrap();
    // A Login whose URL only shares the registrable domain is upgraded by its passkey.
    let near = login(&fx, "domaine", &["https://www.example.com"]);
    fx.session
        .create_passkey(creation(
            &fx.vault_id,
            Some(near.id.clone()),
            "example.com",
            "alex",
        ))
        .unwrap();

    for service in ["example.com", "https://EXAMPLE.com/login", "Example.COM."] {
        let c = fx
            .session
            .autofill_candidates(service.into(), false, Vec::new())
            .unwrap();
        let mut got = titles(&c);
        got.sort();
        assert_eq!(
            got,
            [
                ("domaine".to_owned(), FfiMatchQuality::ExactHost),
                ("sans URL".to_owned(), FfiMatchQuality::ExactHost),
            ],
            "{service}"
        );
        let bare_c = c.iter().find(|c| c.title == "sans URL").unwrap();
        assert_eq!(bare_c.url, None);
        assert_eq!(bare_c.passkeys.len(), 1);
    }
    for service in ["other.com", "a.example.com", "example.com.evil.net"] {
        let c = fx
            .session
            .autofill_candidates(service.into(), false, Vec::new())
            .unwrap();
        assert!(c.iter().all(|c| c.title != "sans URL"), "{service}: {c:?}");
    }
}

#[test]
fn hidden_record_ids_cover_every_item_type() {
    let fx = fixture();
    let visible = login(&fx, "visible", &["https://example.com"]);
    let mut hidden = login(&fx, "cachée", &["https://example.com"]);
    hidden.hide_from_autofill = true;
    let hidden = fx.session.save_item(hidden).unwrap();
    let mut note = other_item(&fx, FfiItemType::SecureNote, "https://example.com");
    note.hide_from_autofill = true;
    let note = fx.session.save_item(note).unwrap();
    let mut ids = fx.session.autofill_hidden_record_ids().unwrap();
    ids.sort();
    let mut expected = vec![
        record_id(&fx.vault_id, &hidden.id),
        record_id(&fx.vault_id, &note.id),
    ];
    expected.sort();
    assert_eq!(ids, expected);
    assert!(!ids.contains(&record_id(&fx.vault_id, &visible.id)));
}

#[test]
fn candidates_allow_http_on_local_hosts() {
    let fx = fixture();
    login(&fx, "dev", &["http://localhost:8080/login"]);
    let c = fx
        .session
        .autofill_candidates("localhost".into(), false, Vec::new())
        .unwrap();
    assert_eq!(titles(&c), [("dev".to_owned(), FfiMatchQuality::ExactHost)]);
}

#[test]
fn candidates_order_favorites_then_recent() {
    let fx = fixture();
    let a = login(&fx, "a", &["https://a.example.com"]);
    login(&fx, "b", &["https://b.example.com"]);
    let c = fx
        .session
        .autofill_candidates("example.com".into(), false, Vec::new())
        .unwrap();
    assert_eq!(c.len(), 2);
    fx.session
        .set_favorite(fx.vault_id.clone(), a.id, true)
        .unwrap();
    let c = fx
        .session
        .autofill_candidates("example.com".into(), false, Vec::new())
        .unwrap();
    assert_eq!(c[0].title, "a");
}

/// Twelve Logins, three qualities, some favorites: best match first, then
/// favorites, then most recently updated. Frozen from the ranker before it
/// went through `fill_plan::order`.
#[test]
fn candidates_order_is_frozen() {
    let fx = fixture();
    let mut ids = std::collections::HashMap::new();
    for t in ["e1", "e2", "e3", "e4"] {
        ids.insert(t, login(&fx, t, &["https://shop.example.com"]).id);
    }
    for t in ["d1", "d2", "d3", "d4"] {
        ids.insert(t, login(&fx, t, &["https://www.example.com"]).id);
    }
    for t in ["o1", "o2", "o3", "o4"] {
        ids.insert(t, login(&fx, t, &["https://other.test"]).id);
    }
    for t in ["e2", "d3", "d1", "o4", "e4"] {
        fx.session
            .set_favorite(fx.vault_id.clone(), ids[t].clone(), true)
            .unwrap();
    }
    let c = fx
        .session
        .autofill_candidates("shop.example.com".into(), true, Vec::new())
        .unwrap();
    let got: Vec<&str> = c.iter().map(|c| c.title.as_str()).collect();
    assert_eq!(
        got,
        [
            "e4", "e2", "e3", "e1", "d1", "d3", "d4", "d2", "o4", "o3", "o2", "o1"
        ]
    );
}

#[test]
fn candidates_respect_match_rule() {
    let fx = fixture();
    let mut exact = login(&fx, "exact", &[]);
    exact.urls = vec![url("https://example.com", FfiMatchRule::ExactHost)];
    fx.session.save_item(exact).unwrap();
    let mut never = login(&fx, "never", &[]);
    never.urls = vec![url("https://example.com", FfiMatchRule::Never)];
    fx.session.save_item(never).unwrap();
    let mut exact_url = login(&fx, "exact_url", &[]);
    exact_url.urls = vec![url("https://example.com/login", FfiMatchRule::ExactUrl)];
    fx.session.save_item(exact_url).unwrap();

    let c = fx
        .session
        .autofill_candidates("login.example.com".into(), false, Vec::new())
        .unwrap();
    assert!(c.is_empty(), "{c:?}");

    let c = fx
        .session
        .autofill_candidates("example.com".into(), false, Vec::new())
        .unwrap();
    let mut got = titles(&c);
    got.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(
        got,
        [
            ("exact".to_owned(), FfiMatchQuality::ExactHost),
            ("exact_url".to_owned(), FfiMatchQuality::ExactHost)
        ]
    );

    let c = fx
        .session
        .autofill_candidates("example.com".into(), true, Vec::new())
        .unwrap();
    assert_eq!(
        c.last().map(|c| (c.title.as_str(), c.quality)),
        Some(("never", FfiMatchQuality::Other))
    );
}

// ---- passkeys -------------------------------------------------------------

fn has_aaguid(attestation: &[u8]) -> bool {
    attestation
        .windows(16)
        .any(|w| w == onepass_core::webauthn::AAGUID)
}

#[test]
fn create_passkey_new_login() {
    let fx = fixture();
    let reg = fx
        .session
        .create_passkey(creation(&fx.vault_id, None, "example.com", "camille"))
        .unwrap();
    assert_eq!(reg.vault_id, fx.vault_id);
    assert_eq!(reg.credential_id.len(), 16);
    assert!(has_aaguid(&reg.attestation_object));

    let item = fx.session.item(fx.vault_id.clone(), reg.item_id).unwrap();
    assert_eq!(item.item_type, FfiItemType::Login);
    assert_eq!(item.title, "example.com");
    assert_eq!(item.urls.len(), 1);
    assert_eq!(item.urls[0].url, "https://example.com");
    assert_eq!(item.login_methods, [FfiLoginMethod::Passkey]);
    let user = item
        .sections
        .iter()
        .flat_map(|s| &s.fields)
        .find(|f| f.id == "username")
        .unwrap();
    assert_eq!(user.value, text("camille"));
    let pks = passkey_fields(&item);
    assert_eq!(pks.len(), 1);
    assert_eq!(pks[0].rp_id, "example.com");
    assert_eq!(pks[0].user_name, "camille");
    assert_eq!(pks[0].credential_id_hex, hex(&reg.credential_id));

    let c = fx
        .session
        .autofill_candidates("example.com".into(), false, Vec::new())
        .unwrap();
    assert_eq!(c.len(), 1);
    assert!(!c[0].has_password);
    assert_eq!(
        c[0].passkeys,
        [FfiPasskeyRef {
            rp_id: "example.com".into(),
            user_name: "camille".into(),
            credential_id: reg.credential_id,
        }]
    );
}

#[test]
fn create_passkey_existing_login() {
    let fx = fixture();
    let item = login(&fx, "Exemple", &["https://example.com"]);
    for _ in 0..2 {
        fx.session
            .create_passkey(creation(
                &fx.vault_id,
                Some(item.id.clone()),
                "example.com",
                "camille",
            ))
            .unwrap();
    }
    let stored = fx.session.item(fx.vault_id.clone(), item.id).unwrap();
    assert_eq!(passkey_fields(&stored).len(), 2);
    let methods = stored
        .login_methods
        .iter()
        .filter(|m| **m == FfiLoginMethod::Passkey)
        .count();
    assert_eq!(methods, 1);
    let pw = stored
        .sections
        .iter()
        .flat_map(|s| &s.fields)
        .find(|f| f.id == "password")
        .unwrap();
    assert_eq!(
        pw.value,
        FfiFieldValue::Password {
            value: LOGIN_PASSWORD.into()
        }
    );
    assert_eq!(fx.session.item_summaries().unwrap().len(), 1);

    let wallet = other_item(&fx, FfiItemType::CryptoWallet, "https://example.com");
    assert!(
        fx.session
            .create_passkey(creation(&fx.vault_id, Some(wallet.id), "example.com", "c"))
            .is_err()
    );
}

#[test]
fn create_passkey_refuses_archived_or_trashed_login() {
    let fx = fixture();
    let archived = login(&fx, "Archive", &["https://example.com"]);
    fx.session
        .archive_item(fx.vault_id.clone(), archived.id.clone())
        .unwrap();
    let trashed = login(&fx, "Corbeille", &["https://example.com"]);
    fx.session
        .trash_item(fx.vault_id.clone(), trashed.id.clone())
        .unwrap();
    for id in [archived.id, trashed.id] {
        assert_eq!(
            fx.session
                .create_passkey(creation(
                    &fx.vault_id,
                    Some(id.clone()),
                    "example.com",
                    "camille"
                ))
                .unwrap_err(),
            OnePassError::NotFound
        );
        let item = fx.session.item(fx.vault_id.clone(), id).unwrap();
        assert!(passkey_fields(&item).is_empty());
    }
}

#[test]
fn create_passkey_excluded() {
    let fx = fixture();
    let first = fx
        .session
        .create_passkey(creation(&fx.vault_id, None, "example.com", "camille"))
        .unwrap();
    let mut again = creation(&fx.vault_id, None, "example.com", "camille");
    again.excluded_credential_ids = vec![vec![0; 16], first.credential_id.clone()];
    assert_eq!(
        fx.session.create_passkey(again).unwrap_err(),
        OnePassError::PasskeyExcluded
    );
    let mut on_item = creation(
        &fx.vault_id,
        Some(first.item_id.clone()),
        "example.com",
        "camille",
    );
    on_item.excluded_credential_ids = vec![first.credential_id.clone()];
    assert_eq!(
        fx.session.create_passkey(on_item).unwrap_err(),
        OnePassError::PasskeyExcluded
    );
    assert_eq!(fx.session.item_summaries().unwrap().len(), 1);
    let item = fx.session.item(fx.vault_id.clone(), first.item_id).unwrap();
    assert_eq!(passkey_fields(&item).len(), 1);
    assert!(!OnePassError::PasskeyExcluded.to_string().is_empty());

    // The same id for another relying party does not block.
    let mut other_rp = creation(&fx.vault_id, None, "exemple.fr", "camille");
    other_rp.excluded_credential_ids = vec![first.credential_id];
    assert!(fx.session.create_passkey(other_rp).is_ok());
}

/// The P-256 public key in the attested credential data of an attestation
/// object, as an uncompressed point.
fn public_key(attestation: &[u8], credential_id: &[u8]) -> Vec<u8> {
    let at = attestation
        .windows(16)
        .position(|w| w == onepass_core::webauthn::AAGUID)
        .unwrap();
    let cose = &attestation[at + 16 + 2 + credential_id.len()..];
    assert_eq!(
        &cose[..10],
        &[0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]
    );
    let mut point = vec![0x04];
    point.extend_from_slice(&cose[10..42]);
    point.extend_from_slice(&cose[45..77]);
    point
}

#[test]
fn assertion_verifies_and_hides_key() {
    let fx = fixture();
    let reg = fx
        .session
        .create_passkey(creation(&fx.vault_id, None, "example.com", "camille"))
        .unwrap();
    let hash = vec![0x42; 32];
    let a = fx
        .session
        .passkey_assertion(
            fx.vault_id.clone(),
            reg.item_id.clone(),
            reg.credential_id.clone(),
            hash.clone(),
        )
        .unwrap();
    assert_eq!(a.user_handle, vec![1, 2, 3, 4]);
    assert_eq!(a.credential_id, reg.credential_id);
    let mut msg = a.authenticator_data.clone();
    msg.extend_from_slice(&hash);
    UnparsedPublicKey::new(
        &ECDSA_P256_SHA256_ASN1,
        public_key(&reg.attestation_object, &reg.credential_id),
    )
    .verify(&msg, &a.signature)
    .unwrap();

    assert_eq!(
        fx.session
            .passkey_assertion(
                fx.vault_id.clone(),
                reg.item_id.clone(),
                vec![7; 16],
                hash.clone()
            )
            .unwrap_err(),
        OnePassError::NotFound
    );
    fx.session
        .trash_item(fx.vault_id.clone(), reg.item_id.clone())
        .unwrap();
    assert_eq!(
        fx.session
            .passkey_assertion(fx.vault_id.clone(), reg.item_id, reg.credential_id, hash)
            .unwrap_err(),
        OnePassError::NotFound
    );
}

#[test]
fn locked_session_refuses() {
    let fx = fixture();
    let item = login(&fx, "Exemple", &["https://example.com"]);
    fx.session.lock();
    let s = &fx.session;
    let locked = OnePassError::Locked;
    assert_eq!(s.autofill_identities(Vec::new()).unwrap_err(), locked);
    assert_eq!(
        s.autofill_candidates("example.com".into(), true, Vec::new())
            .unwrap_err(),
        locked
    );
    assert_eq!(
        s.create_passkey(creation(&fx.vault_id, None, "example.com", "c"))
            .unwrap_err(),
        locked
    );
    assert_eq!(
        s.passkey_assertion(fx.vault_id.clone(), item.id, vec![1; 16], vec![0; 32])
            .unwrap_err(),
        locked
    );
}

// ---- site memory (smart fill, task 7) ---------------------------------------

fn rank_of(ids: &[FfiAutofillIdentity], rid: &str, kind: FfiAutofillKind) -> u32 {
    ids.iter()
        .find(|i| i.record_id == rid && i.kind == kind)
        .unwrap_or_else(|| panic!("no {kind:?} identity for {rid}: {ids:?}"))
        .rank
}

fn note(fx: &Fixture, item: &FfiItem, service: &str) -> Result<bool, OnePassError> {
    fx.session.note_autofill_use(
        record_id(&item.vault_id, &item.id),
        service.into(),
        Vec::new(),
    )
}

fn plan(fx: &Fixture, service: &str, request: FfiAutofillRequest) -> FfiAutofillPlan {
    fx.session
        .autofill_plan(service.into(), request, Vec::new())
        .unwrap()
}

#[test]
fn identity_rank_prefers_last_used_on_host() {
    let fx = fixture();
    let fav = login(&fx, "Favori", &["https://example.com"]);
    fx.session
        .set_favorite(fx.vault_id.clone(), fav.id.clone(), true)
        .unwrap();
    let used = login(&fx, "Utilise", &["https://example.com"]);
    let plain = login(&fx, "Simple", &["https://example.com"]);
    let elsewhere = login(&fx, "Ailleurs", &["https://ailleurs.org"]);
    let rid = |i: &FfiItem| record_id(&i.vault_id, &i.id);

    // No memory yet: the favorite rule alone.
    let ids = fx.session.autofill_identities(Vec::new()).unwrap();
    assert_eq!(rank_of(&ids, &rid(&fav), FfiAutofillKind::Password), 50);
    assert_eq!(rank_of(&ids, &rid(&used), FfiAutofillKind::Password), 0);
    assert_eq!(rank_of(&ids, &rid(&plain), FfiAutofillKind::Password), 0);

    // Last used beats favorite, on that host only.
    note(&fx, &used, "https://example.com/login").unwrap();
    note(&fx, &elsewhere, "ailleurs.org").unwrap();
    let ids = fx.session.autofill_identities(Vec::new()).unwrap();
    assert_eq!(rank_of(&ids, &rid(&used), FfiAutofillKind::Password), 100);
    assert_eq!(rank_of(&ids, &rid(&fav), FfiAutofillKind::Password), 50);
    assert_eq!(rank_of(&ids, &rid(&plain), FfiAutofillKind::Password), 0);
    assert_eq!(
        rank_of(&ids, &rid(&elsewhere), FfiAutofillKind::Password),
        100
    );

    // A, B, then A within the hour: A is the last used again.
    note(&fx, &plain, "example.com").unwrap();
    note(&fx, &used, "example.com").unwrap();
    let ids = fx.session.autofill_identities(Vec::new()).unwrap();
    assert_eq!(rank_of(&ids, &rid(&used), FfiAutofillKind::Password), 100);
    assert_eq!(rank_of(&ids, &rid(&plain), FfiAutofillKind::Password), 0);

    // Forgetting the site leaves the favorite rule alone.
    assert_eq!(
        fx.session.known_usage_sites(Vec::new()).unwrap(),
        ["ailleurs.org", "example.com"]
    );
    assert_eq!(
        fx.session
            .forget_site_usage("https://www.example.com".into(), Vec::new())
            .unwrap(),
        2
    );
    let ids = fx.session.autofill_identities(Vec::new()).unwrap();
    assert_eq!(rank_of(&ids, &rid(&used), FfiAutofillKind::Password), 0);
    assert_eq!(rank_of(&ids, &rid(&fav), FfiAutofillKind::Password), 50);
    assert_eq!(
        fx.session.known_usage_sites(Vec::new()).unwrap(),
        ["ailleurs.org"]
    );
}

#[test]
fn plan_partial_context_orders_by_memory() {
    let fx = fixture();
    let other = second_vault(&fx);
    let old = login(&fx, "Ancien", &["https://example.com"]);
    let new = login(&fx, "Recent", &["https://example.com"]);
    let shared = login_in(
        &fx,
        &other,
        "Famille",
        &["https://example.com"],
        "famille@exemple.fr",
        false,
    );
    for i in 0..5 {
        login(&fx, &format!("Domaine {i}"), &["https://www.example.com"]);
    }
    login(&fx, "Ailleurs", &["https://ailleurs.org"]);

    // No memory: the candidates' order, capped at six, two equal tops.
    let before = plan(&fx, "example.com", FfiAutofillRequest::Password);
    let candidates: Vec<String> = fx
        .session
        .autofill_candidates("example.com".into(), false, Vec::new())
        .unwrap()
        .into_iter()
        .map(|c| c.item_id)
        .take(6)
        .collect();
    assert_eq!(before.item_ids, candidates);
    assert_eq!(before.item_ids.len(), 6);
    assert_eq!(before.confidence, FfiConfidence::Low);

    // The older Login was used here: first, with a clear margin.
    note(&fx, &old, "example.com").unwrap();
    let after = plan(&fx, "example.com", FfiAutofillRequest::Password);
    assert_eq!(after.item_ids[0], old.id);
    assert_eq!(after.confidence, FfiConfidence::High);
    assert_eq!(after.item_ids.len(), 6);

    // Across vaults: A, B, then A again within the hour ends on A.
    note(&fx, &shared, "example.com").unwrap();
    assert_eq!(
        plan(&fx, "example.com", FfiAutofillRequest::Password).item_ids[0],
        shared.id
    );
    note(&fx, &old, "example.com").unwrap();
    assert_eq!(
        plan(&fx, "example.com", FfiAutofillRequest::Password).item_ids[0],
        old.id
    );

    // A vault left out is never planned nor written.
    let kept = fx
        .session
        .autofill_plan(
            "example.com".into(),
            FfiAutofillRequest::Password,
            vec![other.clone()],
        )
        .unwrap();
    assert!(!kept.item_ids.contains(&shared.id));
    assert_eq!(
        fx.session
            .note_autofill_use(
                record_id(&other, &shared.id),
                "example.com".into(),
                vec![other.clone()]
            )
            .unwrap_err(),
        OnePassError::NotFound
    );

    // No site, no plan.
    let none = plan(&fx, "", FfiAutofillRequest::Password);
    assert!(none.item_ids.is_empty());
    assert_eq!(none.confidence, FfiConfidence::Low);
    let _ = new;
}

#[test]
fn plan_one_time_code_only_items_with_totp() {
    let fx = fixture();
    let with_a = login_in(
        &fx,
        &fx.vault_id,
        "Code A",
        &["https://example.com"],
        "a",
        true,
    );
    let with_b = login_in(
        &fx,
        &fx.vault_id,
        "Code B",
        &["https://example.com"],
        "b",
        true,
    );
    let without = login(&fx, "Sans code", &["https://example.com"]);

    let p = plan(&fx, "example.com", FfiAutofillRequest::OneTimeCode);
    let mut got = p.item_ids.clone();
    got.sort();
    let mut want = vec![with_a.id.clone(), with_b.id.clone()];
    want.sort();
    assert_eq!(got, want);
    assert!(!p.item_ids.contains(&without.id));

    // A Login without a code used last does not take the code's place.
    note(&fx, &without, "example.com").unwrap();
    note(&fx, &with_a, "example.com").unwrap();
    let p = plan(&fx, "example.com", FfiAutofillRequest::OneTimeCode);
    assert_eq!(p.item_ids, [with_a.id.clone(), with_b.id.clone()]);
    assert_eq!(p.confidence, FfiConfidence::High);
    let pw = plan(&fx, "example.com", FfiAutofillRequest::Password);
    assert_eq!(pw.item_ids[0], with_a.id);
    assert_eq!(pw.item_ids.len(), 3);
}

#[test]
fn note_autofill_use_rejects_other_site() {
    let fx = fixture();
    let item = login(&fx, "Exemple", &["https://example.com"]);

    assert!(matches!(
        note(&fx, &item, "https://other.org"),
        Err(OnePassError::InvalidInput { .. })
    ));
    assert!(matches!(
        note(&fx, &item, ""),
        Err(OnePassError::InvalidInput { .. })
    ));
    assert!(matches!(
        fx.session
            .note_autofill_use("pas un record".into(), "example.com".into(), Vec::new()),
        Err(OnePassError::InvalidInput { .. })
    ));
    assert!(fx.session.known_usage_sites(Vec::new()).unwrap().is_empty());
    let ids = fx.session.autofill_identities(Vec::new()).unwrap();
    assert_eq!(ids[0].rank, 0);

    // Archived, trashed and hidden Logins are not eligible.
    let archived = login(&fx, "Archive", &["https://example.com"]);
    fx.session
        .archive_item(fx.vault_id.clone(), archived.id.clone())
        .unwrap();
    let trashed = login(&fx, "Corbeille", &["https://example.com"]);
    fx.session
        .trash_item(fx.vault_id.clone(), trashed.id.clone())
        .unwrap();
    let mut hidden = login(&fx, "Masque", &["https://example.com"]);
    hidden.hide_from_autofill = true;
    let hidden = fx.session.save_item(hidden).unwrap();
    for i in [&archived, &trashed, &hidden] {
        assert_eq!(
            note(&fx, i, "example.com").unwrap_err(),
            OnePassError::NotFound
        );
    }
    assert!(fx.session.known_usage_sites(Vec::new()).unwrap().is_empty());

    // The matching site is written, and leaves `updated_at` alone.
    let before = fx
        .session
        .item(fx.vault_id.clone(), item.id.clone())
        .unwrap();
    note(&fx, &item, "https://login.example.com").unwrap();
    let after = fx
        .session
        .item(fx.vault_id.clone(), item.id.clone())
        .unwrap();
    assert_eq!(before.updated_at, after.updated_at);
    assert_eq!(
        fx.session.known_usage_sites(Vec::new()).unwrap(),
        ["example.com"]
    );

    fx.session.lock();
    assert_eq!(
        note(&fx, &item, "example.com").unwrap_err(),
        OnePassError::Locked
    );
}

#[test]
fn otp_identity_rank_counts_logins_with_a_code_only() {
    let fx = fixture();
    let coded = login_in(
        &fx,
        &fx.vault_id,
        "Code",
        &["https://example.com"],
        "a",
        true,
    );
    let plain = login(&fx, "Sans code", &["https://example.com"]);
    let rid = |i: &FfiItem| record_id(&i.vault_id, &i.id);
    assert!(note(&fx, &coded, "example.com").is_ok());
    assert!(note(&fx, &plain, "example.com").is_ok());

    let ids = fx.session.autofill_identities(Vec::new()).unwrap();
    assert_eq!(rank_of(&ids, &rid(&plain), FfiAutofillKind::Password), 100);
    assert_eq!(rank_of(&ids, &rid(&coded), FfiAutofillKind::Password), 0);
    // The last Login used with a code is the code's first choice.
    assert_eq!(
        rank_of(&ids, &rid(&coded), FfiAutofillKind::OneTimeCode),
        100
    );
}
