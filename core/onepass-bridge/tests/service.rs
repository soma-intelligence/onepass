//! Request service and disclosure policy (spec 7.2 to 7.5).

mod common;

use common::*;
use onepass_bridge::audit::MemoryAudit;
use onepass_bridge::service::Service;
use onepass_core::Id;
use onepass_core::model::{FieldValue, LoginMethod, MatchRule, Provider};
use onepass_core::totp::{code_at, totp_from_secret};
use serde_json::{Value, json};

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
        let (vault, ids) = FakeVault::new();
        let audit = MemoryAudit::new();
        H {
            svc: Service::new(vault, Box::new(audit.clone())),
            ids,
            audit,
            next: 0,
        }
    }

    fn call_at(&mut self, mut req: Value, now: u64) -> Value {
        self.next += 1;
        req["id"] = json!(self.next);
        let out = self.svc.handle(req.to_string().as_bytes(), now);
        let v: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["id"], json!(self.next), "{v}");
        v
    }

    fn call(&mut self, req: Value) -> Value {
        self.call_at(req, NOW)
    }

    fn raw(&mut self, bytes: &[u8]) -> Value {
        serde_json::from_slice(&self.svc.handle(bytes, NOW)).unwrap()
    }

    fn vault(&self) -> &FakeVault {
        self.svc.vault()
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

fn titles(v: &Value) -> Vec<String> {
    ok(v)["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["title"].as_str().unwrap().to_owned())
        .collect()
}

fn id(i: Id) -> String {
    i.to_string()
}

fn list(origin: &str) -> Value {
    json!({"op":"list_for_origin","ctx":"menu","origin":origin})
}

fn fill(item: Id, origin: &str) -> Value {
    json!({"op":"fill_login","ctx":"menu","item_id":id(item),"origin":origin,
           "fields":["username","password","totp"]})
}

fn expected_totp(now: u64) -> String {
    code_at(&totp_from_secret(TOTP_SECRET).unwrap(), now).unwrap()
}

#[test]
fn list_for_origin_returns_matching_only() {
    let mut h = H::new();
    let v = h.call(list(ATLAS));
    assert_eq!(titles(&v), ["Atlas Cloud"]);
    assert_eq!(ok(&v)["items"][0]["match"], "exact_host");

    let v = h.call(list("https://admin.atlas-cloud.test/login"));
    assert_eq!(titles(&v), ["Atlas admin", "Atlas Cloud"]);
    assert_eq!(ok(&v)["items"][0]["match"], "exact_host");
    assert_eq!(ok(&v)["items"][1]["match"], "domain");
    assert_eq!(ok(&v)["items"][1]["has_totp"], true);
    assert_eq!(ok(&v)["items"][1]["subtitle"], "alex@atlas.dev");
    assert_eq!(ok(&v)["items"][1]["vault_name"], "Personnel");

    for lookalike in [
        "https://atlas-cloud.test.evil.test",
        "https://atlass-cloud.test",
        "https://\u{430}tlas-cloud.test",
    ] {
        assert!(titles(&h.call(list(lookalike))).is_empty(), "{lookalike}");
    }
}

#[test]
fn summaries_contain_no_secret() {
    let mut h = H::new();
    let mut all = String::new();
    for req in [
        list(ATLAS),
        list("https://admin.atlas-cloud.test"),
        list("https://accounts.google.com"),
        list("https://noauto.atlas-cloud.test"),
        json!({"op":"search","ctx":"popup","query":""}),
        json!({"op":"list_fillable","ctx":"menu","origin":ATLAS,"kind":"card"}),
        json!({"op":"list_fillable","ctx":"menu","origin":ATLAS,"kind":"identity"}),
        json!({"op":"provider_accounts","ctx":"menu","provider":"google",
               "origin":"https://docs.atlas-cloud.test"}),
        json!({"op":"vaults"}),
        json!({"op":"status"}),
    ] {
        let v = h.call(req);
        ok(&v);
        all.push_str(&v.to_string());
    }
    for s in SECRETS {
        assert!(!all.contains(s), "leaked {s}");
    }
    assert!(!all.contains(&format!("\"{CARD_CVV}\"")));
    assert!(!all.contains("otpauth"));
    assert!(!all.contains(&expected_totp(NOW)));
    assert!(all.contains("\u{2022}\u{2022}\u{2022}\u{2022} 4242"));
}

#[test]
fn fill_login_mismatch_origin() {
    let mut h = H::new();
    let (atlas, admin) = (h.ids.atlas, h.ids.admin);
    assert_eq!(
        err(&h.call(fill(atlas, "https://evil.test"))),
        "origin_mismatch"
    );
    assert_eq!(
        err(&h.call(fill(atlas, "https://atlas-cloud.test.evil.test"))),
        "origin_mismatch"
    );
    assert_eq!(err(&h.call(fill(admin, ATLAS))), "origin_mismatch");
    assert!(h.audit.events().is_empty());
}

#[test]
fn fill_login_http_rejected() {
    let mut h = H::new();
    let atlas = h.ids.atlas;
    assert_eq!(
        err(&h.call(fill(atlas, "http://atlas-cloud.test"))),
        "insecure_origin"
    );
}

#[test]
fn fill_login_returns_totp_code_not_secret() {
    let mut h = H::new();
    let atlas = h.ids.atlas;
    let v = h.call(fill(atlas, "https://app.atlas-cloud.test/login"));
    let o = ok(&v);
    assert_eq!(o["username"], "alex@atlas.dev");
    assert_eq!(o["password"], ATLAS_PASSWORD);
    assert_eq!(o["totp"], expected_totp(NOW));
    assert!(!v.to_string().contains(TOTP_SECRET));

    let v = h.call(json!({"op":"fill_login","ctx":"menu","item_id":id(atlas),
                          "origin":ATLAS,"fields":["username"]}));
    assert_eq!(ok(&v), &json!({"username":"alex@atlas.dev"}));

    let v = h.call(json!({"op":"totp","ctx":"chain","item_id":id(atlas),"origin":ATLAS}));
    assert_eq!(ok(&v)["code"], expected_totp(NOW));
    assert!(ok(&v)["remaining"].as_u64().unwrap() <= 30);
    let v = h.call(json!({"op":"totp","ctx":"popup","item_id":id(atlas)}));
    assert_eq!(ok(&v)["code"], expected_totp(NOW));
    let v =
        h.call(json!({"op":"totp","ctx":"menu","item_id":id(atlas),"origin":"https://evil.test"}));
    assert_eq!(err(&v), "origin_mismatch");
    let v = h.call(json!({"op":"totp","ctx":"menu","item_id":id(atlas)}));
    assert_eq!(err(&v), "not_allowed");
}

#[test]
fn archived_hidden_wallet_excluded() {
    let mut h = H::new();
    let (archived, hidden, wallet) = (h.ids.archived, h.ids.hidden, h.ids.wallet);
    assert_eq!(err(&h.call(fill(archived, ATLAS))), "not_found");
    assert_eq!(err(&h.call(fill(hidden, ATLAS))), "not_found");
    let v = h.call(json!({"op":"reveal","ctx":"popup","item_id":id(wallet),"field":"seed"}));
    assert_eq!(err(&v), "not_found");
    let names = titles(&h.call(json!({"op":"search","ctx":"popup","query":"atlas"})));
    for t in ["Atlas ancien", "Atlas cache", "Atlas wallet"] {
        assert!(!names.contains(&t.to_owned()), "{t} listed");
    }
    assert!(names.contains(&"Atlas Cloud".to_owned()));
    assert!(names.contains(&"Carte Atlas".to_owned()));
}

#[test]
fn field_autofill_false_excluded() {
    let mut h = H::new();
    let noauto = h.ids.noauto;
    let v = h.call(fill(noauto, "https://noauto.atlas-cloud.test"));
    assert_eq!(ok(&v), &json!({"username":"alex@atlas.dev"}));
    let v = h.call(json!({"op":"reveal","ctx":"popup","item_id":id(noauto),"field":"password"}));
    assert_eq!(err(&v), "not_allowed");
    let v = h.call(list("https://noauto.atlas-cloud.test"));
    assert_eq!(titles(&v), ["Atlas sans autofill", "Atlas Cloud"]);
    assert_eq!(ok(&v)["items"][0]["has_password"], false);
    assert_eq!(ok(&v)["items"][1]["has_password"], true);
}

#[test]
fn reveal_only_from_popup() {
    let mut h = H::new();
    let atlas = h.ids.atlas;
    for ctx in ["menu", "overlay", "save_prompt", "chain"] {
        let v = h.call(json!({"op":"reveal","ctx":ctx,"item_id":id(atlas),"field":"password"}));
        assert_eq!(err(&v), "not_allowed", "{ctx}");
    }
    let v = h.call(json!({"op":"reveal","ctx":"popup","item_id":id(atlas),"field":"password"}));
    assert_eq!(ok(&v)["value"], ATLAS_PASSWORD);
    let v = h.call(json!({"op":"reveal","ctx":"popup","item_id":id(atlas),"field":"totp"}));
    assert_eq!(err(&v), "not_allowed");
    let v = h.call(json!({"op":"reveal","ctx":"popup","item_id":id(atlas),"field":"missing"}));
    assert_eq!(err(&v), "not_found");
}

#[test]
fn search_only_from_popup() {
    let mut h = H::new();
    for ctx in ["menu", "overlay", "save_prompt", "chain"] {
        let v = h.call(json!({"op":"search","ctx":ctx,"query":"atlas"}));
        assert_eq!(err(&v), "not_allowed", "{ctx}");
    }
    let v = h.call(json!({"op":"search","ctx":"popup","query":"alex.pro"}));
    assert_eq!(titles(&v), ["Google pro"]);
}

#[test]
fn reprompt_required() {
    let mut h = H::new();
    let r = h.ids.reprompt;
    let origin = "https://vault.atlas-cloud.test";
    assert_eq!(err(&h.call(fill(r, origin))), "reprompt_required");
    let v = h.call(json!({"op":"reveal","ctx":"popup","item_id":id(r),"field":"password"}));
    assert_eq!(err(&v), "reprompt_required");
    h.svc.vault_mut().approve_reprompt = true;
    let v = h.call(fill(r, origin));
    assert_eq!(ok(&v)["password"], REPROMPT_PASSWORD);
}

#[test]
fn rate_limited_after_60() {
    let mut h = H::new();
    let atlas = h.ids.atlas;
    for i in 0..60 {
        let v = h.call_at(fill(atlas, ATLAS), NOW + i / 2);
        ok(&v);
    }
    assert_eq!(
        err(&h.call_at(fill(atlas, ATLAS), NOW + 30)),
        "rate_limited"
    );
    let v = h.call_at(
        json!({"op":"reveal","ctx":"popup","item_id":id(atlas),"field":"password"}),
        NOW + 59,
    );
    assert_eq!(err(&v), "rate_limited");
    // Non secret requests are not limited.
    ok(&h.call_at(list(ATLAS), NOW + 59));
    // The two requests of second NOW leave the window at NOW + 60.
    ok(&h.call_at(fill(atlas, ATLAS), NOW + 60));
    ok(&h.call_at(fill(atlas, ATLAS), NOW + 60));
    assert_eq!(
        err(&h.call_at(fill(atlas, ATLAS), NOW + 60)),
        "rate_limited"
    );
}

#[test]
fn replayed_request_id_invalid() {
    let mut h = H::new();
    let req = br#"{"id":42,"op":"status"}"#;
    let first = h.raw(req);
    assert_eq!(first["id"], 42);
    ok(&first);
    let second = h.raw(req);
    assert_eq!(second["id"], 42);
    assert_eq!(err(&second), "invalid");
    // An id used by a malformed request is spent too.
    assert_eq!(err(&h.raw(br#"{"id":43,"op":"nope"}"#)), "invalid");
    assert_eq!(err(&h.raw(br#"{"id":43,"op":"status"}"#)), "invalid");
}

#[test]
fn check_credentials_new_same_update() {
    let mut h = H::new();
    let atlas = h.ids.atlas;
    let check = |user: &str, pass: &str| {
        json!({"op":"check_credentials","ctx":"save_prompt","origin":"https://app.atlas-cloud.test",
               "username":user,"password":pass})
    };
    let v = h.call(check("alex@atlas.dev", ATLAS_PASSWORD));
    assert_eq!(
        ok(&v),
        &json!({"status":"same","item_id":id(atlas),"title":"Atlas Cloud"})
    );
    let v = h.call(check("Alex@Atlas.dev", "Changed-Pass-0010"));
    assert_eq!(
        ok(&v),
        &json!({"status":"update","item_id":id(atlas),"title":"Atlas Cloud"})
    );
    let v = h.call(check("someone@atlas.dev", ATLAS_PASSWORD));
    assert_eq!(ok(&v), &json!({"status":"new"}));
    // The archived login with the same identifier never answers.
    let v = h.call(check("alex@atlas.dev", ARCHIVED_PASSWORD));
    assert_eq!(ok(&v)["status"], "update");
    let v = h.call(
        json!({"op":"check_credentials","ctx":"save_prompt","origin":"https://evil.test",
                          "username":"alex@atlas.dev","password":ATLAS_PASSWORD}),
    );
    assert_eq!(ok(&v), &json!({"status":"new"}));
}

#[test]
fn save_then_list() {
    let mut h = H::new();
    let perso = h.ids.perso;
    let v = h.call(json!({"op":"save_login","ctx":"save_prompt",
        "origin":"https://shop.atlas-cloud.test/account/login?x=1","title":"Atlas Shop",
        "username":"alex@atlas.dev","password":"Shop-Pass-0011","vault_id":id(perso),
        "rule":"exact_host","tags":["achats"]}));
    let new_id = ok(&v)["item_id"].as_str().unwrap().to_owned();
    let saved = h
        .vault()
        .items
        .iter()
        .find(|i| i.id.to_string() == new_id)
        .unwrap();
    assert_eq!(saved.vault_id, perso);
    assert_eq!(saved.tags, ["achats"]);
    assert_eq!(saved.urls.len(), 1);
    assert_eq!(saved.urls[0].label, "site web");
    assert_eq!(saved.urls[0].url, "https://shop.atlas-cloud.test");
    assert_eq!(saved.urls[0].rule, MatchRule::ExactHost);
    assert!(saved.urls[0].primary);

    let v = h.call(list("https://shop.atlas-cloud.test"));
    assert_eq!(titles(&v), ["Atlas Shop", "Atlas Cloud"]);
    let v = h.call(json!({"op":"fill_login","ctx":"menu","item_id":new_id,
                          "origin":"https://shop.atlas-cloud.test","fields":["password"]}));
    assert_eq!(ok(&v)["password"], "Shop-Pass-0011");

    let unknown = json!({"op":"save_login","ctx":"save_prompt","origin":ATLAS,"title":"x",
        "username":"u","password":"p","vault_id":id(Id::new()),"rule":"domain","tags":[]});
    assert_eq!(err(&h.call(unknown)), "not_found");
    let http = json!({"op":"save_login","ctx":"save_prompt","origin":"http://atlas-cloud.test",
        "title":"x","username":"u","password":"p","vault_id":id(perso),"rule":"domain","tags":[]});
    assert_eq!(err(&h.call(http)), "insecure_origin");
}

#[test]
fn save_login_refuses_empty_password() {
    let mut h = H::new();
    let perso = h.ids.perso;
    let before = h.vault().items.len();
    let empty = json!({"op":"save_login","ctx":"save_prompt","origin":ATLAS,"title":"Atlas",
        "username":"alex@atlas.dev","password":"","vault_id":id(perso),"rule":"domain","tags":[]});
    assert_eq!(err(&h.call(empty)), "invalid");
    assert_eq!(h.vault().items.len(), before);
}

#[test]
fn update_password_keeps_history() {
    let mut h = H::new();
    let atlas = h.ids.atlas;
    let v = h.call(
        json!({"op":"update_password","ctx":"save_prompt","item_id":id(atlas),
                          "origin":ATLAS,"password":"New-Pass-0012"}),
    );
    assert_eq!(ok(&v), &json!({}));
    let item = h.vault().item(atlas);
    match &item.field("password").unwrap().value {
        FieldValue::Password(p) => assert_eq!(p.as_str(), "New-Pass-0012"),
        _ => panic!("password field"),
    }
    assert_eq!(item.password_history.len(), 1);
    assert_eq!(item.password_history[0].value.as_str(), ATLAS_PASSWORD);
    assert_eq!(
        item.password_history[0].replaced_at.unix_timestamp(),
        NOW as i64
    );
    let v = h.call(
        json!({"op":"update_password","ctx":"save_prompt","item_id":id(atlas),
                          "origin":"https://evil.test","password":"x"}),
    );
    assert_eq!(err(&v), "origin_mismatch");
}

#[test]
fn provider_accounts_marks_linked() {
    let mut h = H::new();
    let (perso, pro) = (h.ids.google_perso, h.ids.google_pro);
    let v = h.call(
        json!({"op":"provider_accounts","ctx":"menu","provider":"google",
                          "origin":"https://docs.atlas-cloud.test"}),
    );
    let o = ok(&v);
    let accounts: Vec<&str> = o["accounts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["item_id"].as_str().unwrap())
        .collect();
    assert_eq!(accounts.len(), 2);
    assert!(accounts.contains(&id(perso).as_str()));
    assert!(accounts.contains(&id(pro).as_str()));
    assert_eq!(o["linked_item_id"], id(perso));

    let v =
        h.call(json!({"op":"provider_accounts","ctx":"menu","provider":"google","origin":ATLAS}));
    assert!(ok(&v).get("linked_item_id").is_none());
    let v =
        h.call(json!({"op":"provider_accounts","ctx":"menu","provider":"apple","origin":ATLAS}));
    assert_eq!(ok(&v)["accounts"], json!([]));

    // The site summary names the linked account.
    let v = h.call(list("https://docs.atlas-cloud.test"));
    assert_eq!(
        ok(&v)["items"][0]["methods"],
        json!([{"provider":"google","account_email":"alex.perso@example.com"}])
    );
}

#[test]
fn fill_provider_requires_official_host() {
    let mut h = H::new();
    let (perso, atlas) = (h.ids.google_perso, h.ids.atlas);
    let req = |account: Id, provider_origin: &str| {
        json!({"op":"fill_provider","ctx":"chain","account_item_id":id(account),
               "provider":"google","provider_origin":provider_origin,
               "site_origin":"https://docs.atlas-cloud.test","fields":["username","password"]})
    };
    for fake in [
        "https://accounts.google.com.evil.test",
        "https://accounts-google.com",
        "https://evil.test",
    ] {
        assert_eq!(err(&h.call(req(perso, fake))), "origin_mismatch", "{fake}");
    }
    assert_eq!(
        err(&h.call(req(perso, "http://accounts.google.com"))),
        "insecure_origin"
    );
    assert_eq!(
        err(&h.call(req(atlas, "https://accounts.google.com"))),
        "not_found"
    );
    let v = h.call(req(perso, "https://accounts.google.com/signin/v2"));
    assert_eq!(
        ok(&v),
        &json!({"username":"alex.perso@example.com","password":GOOGLE_PERSO_PASSWORD})
    );
}

#[test]
fn link_provider_adds_method() {
    let mut h = H::new();
    let (atlas, pro) = (h.ids.atlas, h.ids.google_pro);
    let v = h.call(
        json!({"op":"link_provider","ctx":"save_prompt","site_origin":ATLAS,
                          "provider":"google","account_item_id":id(pro)}),
    );
    assert_eq!(ok(&v)["item_id"], id(atlas));
    let expected = LoginMethod::Provider {
        provider: Provider::Google,
        account: pro,
        relay_email: None,
    };
    assert_eq!(
        h.vault()
            .item(atlas)
            .login_methods
            .iter()
            .filter(|m| **m == expected)
            .count(),
        1
    );
    // Linking again adds nothing.
    h.call(
        json!({"op":"link_provider","ctx":"save_prompt","site_origin":ATLAS,
                  "provider":"google","account_item_id":id(pro)}),
    );
    assert_eq!(h.vault().item(atlas).login_methods.len(), 1);

    // No login for the site: one is created, titled by the domain.
    let v = h.call(json!({"op":"link_provider","ctx":"save_prompt",
                          "site_origin":"https://www.evil.test/start",
                          "provider":"google","account_item_id":id(pro)}));
    let new_id: Id = ok(&v)["item_id"].as_str().unwrap().parse().unwrap();
    let item = h.vault().item(new_id);
    assert_eq!(item.title, "evil.test");
    assert_eq!(item.login_methods, [expected]);
    assert_eq!(item.urls[0].url, "https://www.evil.test");

    // The account must be a login of that provider.
    let v = h.call(
        json!({"op":"link_provider","ctx":"save_prompt","site_origin":ATLAS,
                          "provider":"google","account_item_id":id(atlas)}),
    );
    assert_eq!(err(&v), "not_found");
}

#[test]
fn locked_vault_returns_locked() {
    let mut h = H::new();
    let atlas = h.ids.atlas;
    h.svc.vault_mut().locked = true;
    let v = h.call(json!({"op":"status"}));
    assert_eq!(
        ok(&v),
        &json!({"locked":true,"account":"alex@atlas.dev","vaults":2})
    );
    assert_eq!(err(&h.call(list(ATLAS))), "locked");
    assert_eq!(err(&h.call(fill(atlas, ATLAS))), "locked");
    assert_eq!(err(&h.call(json!({"op":"vaults"}))), "locked");
    let v = h.call(json!({"op":"unlock"}));
    assert_eq!(ok(&v), &json!({"locked":false}));
    assert_eq!(titles(&h.call(list(ATLAS))), ["Atlas Cloud"]);
}

#[test]
fn audit_records_secret_ops_without_values() {
    let mut h = H::new();
    let (atlas, card) = (h.ids.atlas, h.ids.card);
    ok(&h.call(fill(atlas, ATLAS)));
    ok(&h.call(json!({"op":"totp","ctx":"popup","item_id":id(atlas)})));
    ok(&h.call(json!({"op":"reveal","ctx":"popup","item_id":id(atlas),"field":"password"})));
    ok(&h.call(json!({"op":"fill_card","ctx":"menu","item_id":id(card),"origin":ATLAS})));
    ok(&h.call(list(ATLAS)));
    let events = h.audit.events();
    let ops: Vec<&str> = events.iter().map(|e| e.op).collect();
    assert_eq!(ops, ["fill_login", "totp", "reveal", "fill_card"]);
    assert_eq!(events[0].item_id, Some(id(atlas)));
    assert_eq!(events[0].origin.as_deref(), Some(ATLAS));
    assert_eq!(events[0].at, NOW);
    assert_eq!(events[3].item_id, Some(id(card)));
    let dump = format!("{events:?}");
    for s in SECRETS {
        assert!(!dump.contains(s), "leaked {s}");
    }
    assert!(!dump.contains(&expected_totp(NOW)));
}

#[test]
fn malformed_json_is_invalid_not_panic() {
    let mut h = H::new();
    for bad in [
        &b""[..],
        b"{",
        b"null",
        b"[]",
        b"42",
        b"\xff\xfe",
        br#"{"id":"7","op":"status"}"#,
        br#"{"id":-1,"op":"status"}"#,
        br#"{"id":1e3,"op":"status"}"#,
        br#"{"id":18446744073709551616,"op":"status"}"#,
    ] {
        let v = h.raw(bad);
        assert_eq!(v["id"], Value::Null, "{bad:?}");
        assert_eq!(err(&v), "invalid");
    }
    for (bad, want) in [
        (&br#"{"id":5}"#[..], 5),
        (br#"{"id":6,"op":"nope"}"#, 6),
        (br#"{"id":7,"op":"status","x":1}"#, 7),
        (br#"{"id":8,"op":"fill_login","ctx":"menu"}"#, 8),
        (br#"{"id":9,"op":"fill_login","ctx":"menu","item_id":"zz","origin":"https://atlas-cloud.test","fields":[]}"#, 9),
    ] {
        let v = h.raw(bad);
        assert_eq!(v["id"], want);
        assert_eq!(err(&v), "invalid");
        assert_eq!(v["err"]["msg"], "invalid request");
    }
}

#[test]
fn fill_card_and_identity_values() {
    let mut h = H::new();
    let (card, ident, atlas) = (h.ids.card, h.ids.identity, h.ids.atlas);
    let v = h.call(json!({"op":"fill_card","ctx":"menu","item_id":id(card),"origin":ATLAS}));
    assert_eq!(
        ok(&v),
        &json!({"cardholder":"Alex Martin","number":CARD_NUMBER,"exp_month":"04",
                "exp_year":"2029","cvv":CARD_CVV})
    );
    let v = h.call(json!({"op":"fill_identity","ctx":"menu","item_id":id(ident),"origin":ATLAS}));
    assert_eq!(
        ok(&v),
        &json!({"given_name":"Alex","family_name":"Martin","email":"alex@atlas.dev",
                "tel":"+33 6 00 00 00 00","organization":"Atlas","birthday":"1990-05-17",
                "address":{"line1":"1 rue de l'Exemple","line2":"","city":"Lyon",
                           "postal_code":"69000","region":"Rhone","country":"FR"}})
    );
    let v = h.call(json!({"op":"fill_card","ctx":"menu","item_id":id(card),
                          "origin":"http://atlas-cloud.test"}));
    assert_eq!(err(&v), "insecure_origin");
    let v = h.call(json!({"op":"fill_card","ctx":"menu","item_id":id(atlas),"origin":ATLAS}));
    assert_eq!(err(&v), "not_found");
    let v = h.call(json!({"op":"list_fillable","ctx":"menu","origin":ATLAS,"kind":"identity"}));
    assert_eq!(titles(&v), ["Alex Martin"]);
    assert_eq!(ok(&v)["items"][0]["subtitle"], "Alex Martin");
}

fn smart(h: &mut H, recipe: Value, origin: Option<&str>) -> Value {
    let mut req = json!({"op":"generate","ctx":"menu","recipe":recipe});
    if let Some(o) = origin {
        req["origin"] = json!(o);
    }
    h.call(req)
}

#[test]
fn smart_with_context_follows_maxlength() {
    let mut h = H::new();
    let v = smart(
        &mut h,
        json!({"kind":"smart","context":{"max_length":14}}),
        None,
    );
    assert_eq!(ok(&v)["password"].as_str().unwrap().chars().count(), 14);
    assert_eq!(ok(&v)["report"]["length"], 14);
    let v = smart(
        &mut h,
        json!({"kind":"smart","context":{"rules":["minlength: 10; maxlength: 12; required: digit;"]}}),
        None,
    );
    let pw = ok(&v)["password"].as_str().unwrap().to_owned();
    assert!((10..=12).contains(&pw.chars().count()));
    assert!(pw.chars().any(|c| c.is_ascii_digit()));
}

#[test]
fn smart_quirks_applied_from_origin() {
    // accor.com: minlength 10, maxlength 20, one of each class.
    let mut h = H::new();
    let v = smart(
        &mut h,
        json!({"kind":"smart"}),
        Some("https://www.accor.com/login"),
    );
    let pw = ok(&v)["password"].as_str().unwrap().to_owned();
    assert!((10..=20).contains(&pw.chars().count()), "{}", pw.len());
    assert!(pw.chars().any(|c| c.is_ascii_lowercase()));
    assert!(pw.chars().any(|c| c.is_ascii_uppercase()));
    assert!(pw.chars().any(|c| c.is_ascii_digit()));
    assert_eq!(ok(&v)["report"]["sources"], json!(["quirks"]));
    let v = smart(&mut h, json!({"kind":"smart"}), Some("not an origin"));
    assert_eq!(err(&v), "invalid");
    let v = smart(&mut h, json!({"kind":"smart"}), Some("http://accor.com/"));
    assert_eq!(err(&v), "insecure_origin");
}

#[test]
fn smart_profiles_and_bounds() {
    let mut h = H::new();
    let v = smart(&mut h, json!({"kind":"smart","profile":"readable"}), None);
    assert_eq!(ok(&v)["password"].as_str().unwrap().split('-').count(), 5);
    let v = smart(
        &mut h,
        json!({"kind":"smart","profile":"custom","length":12,"symbols":false}),
        None,
    );
    let pw = ok(&v)["password"].as_str().unwrap().to_owned();
    assert_eq!(pw.chars().count(), 12);
    assert!(pw.chars().all(|c| c.is_ascii_alphanumeric()));
    for len in [7, 65] {
        let v = smart(
            &mut h,
            json!({"kind":"smart","profile":"custom","length":len}),
            None,
        );
        assert_eq!(err(&v), "invalid");
    }
    let rules: Vec<_> = (0..9).map(|_| "minlength: 8;").collect();
    let v = smart(
        &mut h,
        json!({"kind":"smart","context":{"rules":rules}}),
        None,
    );
    assert_eq!(err(&v), "invalid");
    let long = "a".repeat(1025);
    let v = smart(
        &mut h,
        json!({"kind":"smart","context":{"rules":[long]}}),
        None,
    );
    assert_eq!(err(&v), "invalid");
}

#[test]
fn narrow_above_2_invalid() {
    let mut h = H::new();
    let v = smart(&mut h, json!({"kind":"smart","narrow":3}), None);
    assert_eq!(err(&v), "invalid");
    let v = smart(&mut h, json!({"kind":"smart","narrow":2}), None);
    assert!(
        ok(&v)["password"]
            .as_str()
            .unwrap()
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
    );
}

#[test]
fn context_hint_over_600_truncated_not_rejected() {
    let mut h = H::new();
    let hint = format!("{} at most 12 characters", "x".repeat(700));
    let v = smart(
        &mut h,
        json!({"kind":"smart","context":{"hint_text":hint}}),
        None,
    );
    // The limit sits past the cut: the hint is ignored, not an error.
    assert_eq!(ok(&v)["password"].as_str().unwrap().chars().count(), 24);
}

#[test]
fn generate_recipes() {
    let mut h = H::new();
    let gen_ = |kind: &str, extra: Value| {
        let mut r = json!({"kind":kind});
        if let Value::Object(m) = extra {
            r.as_object_mut().unwrap().extend(m);
        }
        json!({"op":"generate","ctx":"menu","recipe":r})
    };
    let v = h.call(gen_("random", json!({})));
    assert_eq!(ok(&v)["password"].as_str().unwrap().chars().count(), 20);
    let v = h.call(gen_("random", json!({"length":32,"symbols":true})));
    assert_eq!(ok(&v)["password"].as_str().unwrap().chars().count(), 32);
    let v = h.call(gen_("pin", json!({})));
    let pin = ok(&v)["password"].as_str().unwrap().to_owned();
    assert_eq!(pin.len(), 6);
    assert!(pin.chars().all(|c| c.is_ascii_digit()));
    let v = h.call(gen_("memorable", json!({})));
    assert_eq!(ok(&v)["password"].as_str().unwrap().split('-').count(), 5);
    let v = h.call(gen_("smart", json!({})));
    let smart = ok(&v)["password"].as_str().unwrap().to_owned();
    assert_eq!(smart.chars().count(), 24);
    assert!(smart.chars().any(|c| !c.is_ascii_alphanumeric()));
    assert!(ok(&v)["entropy_bits"].as_f64().unwrap() > 100.0);
    assert!(ok(&v)["report"]["length"].as_u64() == Some(24));
    let v = h.call(gen_("random", json!({})));
    assert!(ok(&v).get("report").is_none());
    for len in [3, 101] {
        let v = h.call(gen_("random", json!({ "length": len })));
        assert_eq!(err(&v), "invalid");
    }
}

#[test]
fn provider_account_with_never_rule_is_not_a_provider_account() {
    let mut h = H::new();
    let perso = h.ids.google_perso;
    for u in h
        .svc
        .vault_mut()
        .items
        .iter_mut()
        .find(|i| i.id == perso)
        .unwrap()
        .urls
        .iter_mut()
    {
        u.rule = MatchRule::Never;
    }
    let v = h.call(
        json!({"op":"provider_accounts","ctx":"menu","provider":"google",
                          "origin":"https://docs.atlas-cloud.test"}),
    );
    let o = ok(&v);
    assert!(!o.to_string().contains(&id(perso)), "{o}");
    assert!(o.get("linked_item_id").is_none());
    let v = h.call(
        json!({"op":"fill_provider","ctx":"chain","account_item_id":id(perso),
        "provider":"google","provider_origin":"https://accounts.google.com",
        "site_origin":"https://docs.atlas-cloud.test","fields":["password"]}),
    );
    assert_eq!(err(&v), "not_found");
}

#[test]
fn fill_provider_honors_exact_url_and_port() {
    let mut h = H::new();
    let perso = h.ids.google_perso;
    {
        let item = h
            .svc
            .vault_mut()
            .items
            .iter_mut()
            .find(|i| i.id == perso)
            .unwrap();
        item.urls[0].url = "https://accounts.google.com:8443/signin".into();
        item.urls[0].rule = MatchRule::ExactUrl;
    }
    let req = |provider_origin: &str| {
        json!({"op":"fill_provider","ctx":"chain","account_item_id":id(perso),
            "provider":"google","provider_origin":provider_origin,
            "site_origin":"https://docs.atlas-cloud.test","fields":["password"]})
    };
    assert_eq!(
        err(&h.call(req("https://accounts.google.com/signin"))),
        "origin_mismatch"
    );
    assert_eq!(
        err(&h.call(req("https://accounts.google.com:8443/other"))),
        "origin_mismatch"
    );
    let v = h.call(req("https://accounts.google.com:8443/signin?x=1"));
    assert_eq!(ok(&v)["password"], GOOGLE_PERSO_PASSWORD);
}

#[test]
fn reveal_and_totp_limited_to_displayable_types() {
    let mut h = H::new();
    let perso = h.ids.perso;
    let mut ssh =
        onepass_core::model::new_item(onepass_core::model::ItemType::SshKey, perso, "Atlas SSH");
    ssh.field_mut("passphrase").unwrap().value =
        FieldValue::Concealed(zeroize::Zeroizing::new("Ssh-Pass-0013".into()));
    ssh.sections[0].fields.push(onepass_core::model::Field {
        id: "totp".into(),
        label: "TOTP".into(),
        kind: onepass_core::model::FieldType::Otp,
        value: FieldValue::Otp(zeroize::Zeroizing::new(TOTP_SECRET.into())),
        required: false,
        repeatable: false,
        autofill: true,
    });
    ssh.urls.push(onepass_core::model::ItemUrl {
        label: "site web".into(),
        url: ATLAS.into(),
        rule: MatchRule::Domain,
        primary: true,
    });
    let ssh_id = ssh.id;
    h.svc.vault_mut().items.push(ssh);
    let v = h.call(json!({"op":"reveal","ctx":"popup","item_id":id(ssh_id),"field":"passphrase"}));
    assert_eq!(err(&v), "not_found");
    let v = h.call(json!({"op":"totp","ctx":"popup","item_id":id(ssh_id)}));
    assert_eq!(err(&v), "not_found");
    let v = h.call(json!({"op":"totp","ctx":"menu","item_id":id(ssh_id),"origin":ATLAS}));
    assert_eq!(err(&v), "not_found");
}

#[test]
fn account_email_ignores_ineligible_accounts() {
    let mut h = H::new();
    let perso = h.ids.google_perso;
    h.svc
        .vault_mut()
        .items
        .iter_mut()
        .find(|i| i.id == perso)
        .unwrap()
        .archived = true;
    let v = h.call(list("https://docs.atlas-cloud.test"));
    let s = v.to_string();
    assert!(!s.contains("alex.perso@example.com"), "{s}");
}

#[test]
fn writes_to_reprompt_items_need_approval() {
    let mut h = H::new();
    let (r, pro) = (h.ids.reprompt, h.ids.google_pro);
    let origin = "https://vault.atlas-cloud.test";
    let v = h.call(
        json!({"op":"update_password","ctx":"save_prompt","item_id":id(r),
                          "origin":origin,"password":"New-Pass-0014"}),
    );
    assert_eq!(err(&v), "reprompt_required");
    let v = h.call(
        json!({"op":"link_provider","ctx":"save_prompt","site_origin":origin,
                          "provider":"google","account_item_id":id(pro)}),
    );
    assert_eq!(err(&v), "reprompt_required");
    let item = h.vault().item(r);
    assert!(item.password_history.is_empty());
    assert!(item.login_methods.is_empty());
    h.svc.vault_mut().approve_reprompt = true;
    let v = h.call(
        json!({"op":"update_password","ctx":"save_prompt","item_id":id(r),
                          "origin":origin,"password":"New-Pass-0014"}),
    );
    assert_eq!(ok(&v), &json!({}));
}

#[test]
fn writes_count_in_the_rate_limit() {
    let mut h = H::new();
    let (atlas, pro) = (h.ids.atlas, h.ids.google_pro);
    for i in 0..30 {
        let pw = format!("Rot-Pass-{i:04}");
        ok(&h.call(
            json!({"op":"update_password","ctx":"save_prompt","item_id":id(atlas),
                          "origin":ATLAS,"password":pw}),
        ));
        ok(&h.call(
            json!({"op":"link_provider","ctx":"save_prompt","site_origin":ATLAS,
                          "provider":"google","account_item_id":id(pro)}),
        ));
    }
    let v = h.call(
        json!({"op":"update_password","ctx":"save_prompt","item_id":id(atlas),
                          "origin":ATLAS,"password":"x"}),
    );
    assert_eq!(err(&v), "rate_limited");
    let v = h.call(
        json!({"op":"link_provider","ctx":"save_prompt","site_origin":ATLAS,
                          "provider":"google","account_item_id":id(pro)}),
    );
    assert_eq!(err(&v), "rate_limited");
}

/// Twelve Logins of mixed quality, title case, favorite and date: the order of
/// `list_for_origin` is best match first, then lowercase title. Frozen from the
/// ranker before it went through `fill_plan::order`.
#[test]
fn list_for_origin_order_is_frozen() {
    use onepass_core::model::{ItemType, ItemUrl, new_item};

    let (mut vault, _) = FakeVault::new();
    let v = vault.vaults[0].id;
    vault.items.clear();
    let rows = [
        (
            "zeta",
            "https://shop.example.test",
            MatchRule::ExactHost,
            true,
        ),
        (
            "Yankee",
            "https://www.example.test",
            MatchRule::Domain,
            false,
        ),
        (
            "Alpha",
            "https://shop.example.test",
            MatchRule::ExactHost,
            false,
        ),
        (
            "apple",
            "https://blog.example.test",
            MatchRule::Domain,
            true,
        ),
        ("Nope1", "https://elsewhere.test", MatchRule::Domain, true),
        (
            "Beta",
            "https://shop.example.test",
            MatchRule::ExactHost,
            true,
        ),
        ("Zulu", "https://www.example.test", MatchRule::Domain, false),
        (
            "alpha2",
            "https://shop.example.test",
            MatchRule::ExactHost,
            false,
        ),
        (
            "Cherry",
            "https://www.example.test",
            MatchRule::Domain,
            true,
        ),
        (
            "Nope2",
            "https://elsewhere.test",
            MatchRule::ExactHost,
            false,
        ),
        (
            "mango",
            "https://shop.example.test",
            MatchRule::ExactHost,
            false,
        ),
        (
            "banana",
            "https://docs.example.test",
            MatchRule::Domain,
            false,
        ),
    ];
    for (title, u, rule, favorite) in rows {
        let mut i = new_item(ItemType::Login, v, title);
        i.favorite = favorite;
        i.urls.push(ItemUrl {
            label: String::new(),
            url: u.into(),
            rule,
            primary: true,
        });
        vault.items.push(i);
    }
    let mut svc = Service::new(vault, Box::new(MemoryAudit::new()));
    let out = svc.handle(
        json!({"id":1,"op":"list_for_origin","ctx":"menu","origin":"https://shop.example.test"})
            .to_string()
            .as_bytes(),
        NOW,
    );
    let v: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(
        titles(&v),
        [
            "Alpha", "alpha2", "Beta", "mango", "zeta", "apple", "banana", "Cherry", "Yankee",
            "Zulu"
        ]
    );
}

// Smart fill: fill_salt, plan_fill, note_fill, forget_site.

const TWIN: &str = "https://twin.test";
const FORM_REF: &str = "form-login-7";
const USER_REF: &str = "ref-user-7";
const PASS_REF: &str = "ref-pass-7";

/// One login form: username then current password, a submit button.
fn login_form() -> Value {
    json!({"form_ref":FORM_REF,
           "intent_hints":{"kind":"login","signup_words":false,"reset_words":false,
                           "checkout_words":false,"ignore":false},
           "step_index":null,
           "fields":[
               {"field_ref":USER_REF,"role":"username","confidence":0.9,"visible":true,
                "prefilled":"empty"},
               {"field_ref":PASS_REF,"role":"current_password","confidence":0.9,
                "visible":true,"prefilled":"empty"}],
           "buttons":[{"button_ref":"ref-submit-7","class":"submit"}]})
}

fn page(origin: &str, typed: Option<Vec<u8>>) -> Value {
    json!({"origin":origin,"top_origin":origin,"frame_kind":"top","forms":[login_form()],
           "typed_username_hash":typed})
}

fn plan_req(origin: &str, context: Value) -> Value {
    json!({"op":"plan_fill","ctx":"menu","origin":origin,"context":context})
}

fn note(item: Id, origin: &str) -> Value {
    json!({"op":"note_fill","ctx":"chain","item_id":id(item),"origin":origin,
           "roles":["username","current_password"],"intent":"login","steps":["fill"]})
}

/// Two equal logins on `TWIN`: `(a, b)`, b's username is `tom@example.com`.
fn twins(h: &mut H) -> (Id, Id) {
    let v = h.svc.vault_mut();
    let a = v.add_login("Twin A", "alex@twin.test", TWIN, MatchRule::Domain);
    let b = v.add_login("Twin B", "tom@example.com", TWIN, MatchRule::Domain);
    (a, b)
}

fn salt(h: &mut H) -> Vec<u8> {
    let v = h.call(json!({"op":"fill_salt","ctx":"menu"}));
    let hex = ok(&v)["salt"].as_str().unwrap().to_owned();
    assert_eq!(hex.len(), 64, "{hex}");
    data_encoding::HEXLOWER.decode(hex.as_bytes()).unwrap()
}

fn sha256(parts: &[&[u8]]) -> Vec<u8> {
    let mut ctx = aws_lc_rs::digest::Context::new(&aws_lc_rs::digest::SHA256);
    for p in parts {
        ctx.update(p);
    }
    ctx.finish().as_ref().to_vec()
}

#[test]
fn plan_fill_rejects_foreign_origin() {
    let mut h = H::new();
    for foreign in [
        "https://evil.test",
        "https://atlas-cloud.test.evil.test",
        "https://admin.atlas-cloud.test",
    ] {
        let v = h.call(plan_req(ATLAS, page(foreign, None)));
        assert_eq!(err(&v), "origin_mismatch", "{foreign}");
    }
    let v = h.call(plan_req(ATLAS, page("http://atlas-cloud.test", None)));
    assert_eq!(err(&v), "insecure_origin");
    assert!(h.audit.events().is_empty());
}

#[test]
fn plan_fill_returns_open_chain_for_single_login() {
    let mut h = H::new();
    let atlas = h.ids.atlas;
    let v = h.call(plan_req(ATLAS, page(ATLAS, None)));
    let plan = &ok(&v)["plan"];
    assert_eq!(plan["intent"], "login", "{plan}");
    assert_eq!(plan["action"], "open_chain");
    assert_eq!(plan["confidence"], "high");
    assert_eq!(
        plan["groups"],
        json!([{"form_ref":FORM_REF,"kind":"login","item_id":id(atlas),
                "fields":[{"field_ref":USER_REF,"role":"username"},
                          {"field_ref":PASS_REF,"role":"current_password"}]}])
    );
    assert_eq!(plan["alternatives"], json!([]));
    assert!(
        plan["reasons"]
            .as_array()
            .unwrap()
            .contains(&json!("single_candidate"))
    );
    for s in SECRETS {
        assert!(!v.to_string().contains(s), "leaked {s}");
    }
}

#[test]
fn plan_fill_uses_typed_username_hash() {
    let mut h = H::new();
    let (a, b) = twins(&mut h);
    let v = h.call(plan_req(TWIN, page(TWIN, None)));
    assert_eq!(ok(&v)["plan"]["confidence"], "low", "{v}");

    let salt = salt(&mut h);
    let typed = sha256(&[&salt, b"tom@example.com"]);
    let v = h.call(plan_req(TWIN, page(TWIN, Some(typed))));
    let plan = &ok(&v)["plan"];
    assert_eq!(plan["confidence"], "high", "{plan}");
    assert_eq!(plan["groups"][0]["item_id"], id(b));
    assert_eq!(plan["alternatives"], json!([id(a)]));
    assert!(
        plan["reasons"]
            .as_array()
            .unwrap()
            .contains(&json!("typed_username"))
    );

    // A hash with another salt matches nothing.
    let stale = sha256(&[&[0u8; 32], b"tom@example.com"]);
    let v = h.call(plan_req(TWIN, page(TWIN, Some(stale))));
    assert_eq!(ok(&v)["plan"]["confidence"], "low", "{v}");
}

#[test]
fn plan_fill_rejects_oversized_context() {
    let mut h = H::new();
    let forms: Vec<Value> = (0..33)
        .map(|n| {
            let mut f = login_form();
            f["form_ref"] = json!(format!("f{n}"));
            f["fields"] = json!([]);
            f
        })
        .collect();
    let mut ctx = page(ATLAS, None);
    ctx["forms"] = json!(forms);
    assert_eq!(err(&h.call(plan_req(ATLAS, ctx))), "invalid");

    let fields: Vec<Value> = (0..65)
        .map(|n| {
            json!({"field_ref":format!("x{n}"),"role":"unknown","confidence":0.5,
                        "visible":true,"prefilled":"empty"})
        })
        .collect();
    let mut ctx = page(ATLAS, None);
    ctx["forms"][0]["fields"] = json!(fields);
    assert_eq!(err(&h.call(plan_req(ATLAS, ctx))), "invalid");

    let mut ctx = page(ATLAS, None);
    ctx["forms"][0]["fields"][1]["field_ref"] = json!(USER_REF);
    assert_eq!(err(&h.call(plan_req(ATLAS, ctx))), "invalid");

    let mut ctx = page(ATLAS, None);
    ctx["forms"][0]["extra"] = json!(true);
    assert_eq!(err(&h.call(plan_req(ATLAS, ctx))), "invalid");
}

#[test]
fn note_fill_then_plan_prefers_last_used() {
    let mut h = H::new();
    let (a, b) = twins(&mut h);
    let v = h.call(plan_req(TWIN, page(TWIN, None)));
    assert_eq!(ok(&v)["plan"]["confidence"], "low", "{v}");

    assert_eq!(ok(&h.call(note(b, TWIN))), &json!({}));
    let usage = &h.vault().item(b).usage;
    assert_eq!(usage.len(), 1);
    assert_eq!(usage[0].site, "twin.test");
    assert!(h.vault().item(a).usage.is_empty());

    let v = h.call(plan_req(TWIN, page(TWIN, None)));
    let plan = &ok(&v)["plan"];
    assert_eq!(plan["confidence"], "high", "{plan}");
    assert_eq!(plan["groups"][0]["item_id"], id(b));
    assert_eq!(plan["action"], "open_chain");
    let reasons = plan["reasons"].as_array().unwrap();
    assert!(reasons.contains(&json!("last_on_site")), "{plan}");
    assert!(reasons.contains(&json!("same_shape")), "{plan}");
}

// Autofill history: client_info, note_autofill, the learned order.

fn client(profile: &str) -> Value {
    json!({"op":"client_info","browser":"chrome","profile_id":profile,"profile_name":"Work"})
}

fn note_ev(action: &str, item: Option<Id>, rank: Option<u8>, shown: &[Id]) -> Value {
    let mut v = json!({"op":"note_autofill","ctx":"menu","origin":TWIN,"action":action,
                       "shown": shown.iter().map(|i| id(*i)).collect::<Vec<_>>()});
    if let Some(i) = item {
        v["item_id"] = json!(id(i));
    }
    if let Some(r) = rank {
        v["rank"] = json!(r);
    }
    v
}

#[test]
fn picks_in_a_profile_lead_its_plans_and_carry_no_value() {
    let mut h = H::new();
    let (a, b) = twins(&mut h);
    let lead = |h: &mut H| -> Value {
        let v = h.call_at(plan_req(TWIN, page(TWIN, None)), NOW + 120);
        ok(&v)["plan"]["groups"][0]["item_id"].clone()
    };
    // Work profile: the user picks a (b listed first), and signs in with it.
    assert_eq!(ok(&h.call(client("work-1"))), &json!({}));
    for _ in 0..2 {
        assert_eq!(
            ok(&h.call(note_ev("shown", None, None, &[b, a]))),
            &json!({})
        );
        assert_eq!(
            ok(&h.call(note_ev("picked", Some(a), Some(1), &[]))),
            &json!({})
        );
        assert_eq!(
            ok(&h.call(note_ev("picked_other", Some(b), Some(0), &[]))),
            &json!({})
        );
    }
    assert_eq!(ok(&h.call(note(a, TWIN))), &json!({}));
    // Home profile: b signs in last, so the synced memory has b last here.
    assert_eq!(ok(&h.call(client("home-2"))), &json!({}));
    assert_eq!(ok(&h.call_at(note(b, TWIN), NOW + 60)), &json!({}));
    assert!(
        h.vault().item(b).site_last_at("twin.test") > h.vault().item(a).site_last_at("twin.test")
    );
    assert_eq!(lead(&mut h), json!(id(b)));
    // Back in the work profile, a leads; at home, b.
    ok(&h.call(client("work-1")));
    assert_eq!(lead(&mut h), json!(id(a)));
    ok(&h.call(client("home-2")));
    assert_eq!(lead(&mut h), json!(id(b)));
    // Events name the session's profile, the site and item ids; never a value.
    let hist = &h.vault().history;
    assert_eq!(hist.len(), 8);
    assert!(hist.iter().all(|e| e.site == "twin.test"));
    assert_eq!(hist[0].shown, vec![b, a]);
    assert_eq!(hist[1].client.profile_id.as_deref(), Some("work-1"));
    assert_eq!(hist[1].client.profile_name.as_deref(), Some("Work"));
    assert_eq!(hist[6].item_id, Some(a));
    assert_eq!(hist[7].client.profile_id.as_deref(), Some("home-2"));
    let dump = format!("{hist:?}");
    assert!(!dump.contains("tom@example.com") && !dump.contains("alex@twin.test"));
}

#[test]
fn note_autofill_checks_items_ctx_and_client() {
    let mut h = H::new();
    let (a, _) = twins(&mut h);
    let atlas = h.ids.atlas;
    // A login of another site: not this page's.
    assert_eq!(
        err(&h.call(note_ev("picked", Some(atlas), Some(0), &[]))),
        "not_found"
    );
    // A pick names its item.
    assert_eq!(
        err(&h.call(note_ev("picked", None, Some(0), &[]))),
        "invalid"
    );
    // A shown list keeps only this page's items.
    assert_eq!(
        ok(&h.call(note_ev("shown", None, None, &[atlas, a]))),
        &json!({})
    );
    assert_eq!(h.vault().history[0].shown, vec![a]);
    // Too many shown, or a context the history does not take.
    let many: Vec<Id> = (0..9).map(|_| a).collect();
    assert_eq!(err(&h.call(note_ev("shown", None, None, &many))), "invalid");
    let mut v = note_ev("picked", Some(a), Some(0), &[]);
    v["ctx"] = json!("save_prompt");
    assert_eq!(err(&h.call(v)), "not_allowed");
    // An http page, a profile id that is not opaque, the system's own kind.
    let mut v = note_ev("picked", Some(a), Some(0), &[]);
    v["origin"] = json!("http://twin.test");
    assert_eq!(err(&h.call(v)), "insecure_origin");
    assert_eq!(err(&h.call(client("has space"))), "invalid");
    assert_eq!(
        err(&h.call(json!({"op":"client_info","browser":"system_auto_fill"}))),
        "invalid"
    );
    // Unknown fields are refused, as for every op.
    assert_eq!(
        err(&h.call(json!({"op":"client_info","browser":"chrome","email":"x@y.z"}))),
        "invalid"
    );
    assert_eq!(h.vault().history.len(), 1);
}

#[test]
fn note_fill_rejects_item_of_other_site() {
    let mut h = H::new();
    let (_, b) = twins(&mut h);
    let (atlas, google) = (h.ids.atlas, h.ids.google_perso);
    assert_eq!(err(&h.call(note(atlas, TWIN))), "origin_mismatch");
    assert_eq!(err(&h.call(note(google, ATLAS))), "origin_mismatch");
    assert_eq!(
        err(&h.call(note(b, "https://twin.test.evil.test"))),
        "origin_mismatch"
    );
    assert_eq!(err(&h.call(note(h.ids.archived, ATLAS))), "not_found");
    assert!(h.vault().items.iter().all(|i| i.usage.is_empty()));
    assert!(h.audit.events().is_empty());
}

#[test]
fn salt_changes_between_sessions() {
    let mut h1 = H::new();
    let mut h2 = H::new();
    let s1 = salt(&mut h1);
    assert_eq!(salt(&mut h1), s1, "one salt per session");
    let s2 = salt(&mut h2);
    assert_ne!(s1, s2);
    assert_ne!(s1, vec![0u8; 32]);
}

#[test]
fn plan_fill_audit_has_no_refs() {
    let mut h = H::new();
    let (_, b) = twins(&mut h);
    ok(&h.call(json!({"op":"fill_salt","ctx":"menu"})));
    ok(&h.call(plan_req(TWIN, page(TWIN, None))));
    ok(&h.call(note(b, TWIN)));
    let events = h.audit.events();
    let ops: Vec<&str> = events.iter().map(|e| e.op).collect();
    assert_eq!(ops, ["plan_fill", "note_fill"]);
    assert_eq!(events[0].item_id, None);
    assert_eq!(events[0].origin.as_deref(), Some("twin.test"));
    let p = events[0].plan.expect("plan summary");
    assert_eq!(
        serde_json::to_value(p).unwrap(),
        json!({"intent":"login","action":"show_menu","confidence":"low"})
    );
    assert_eq!(events[1].item_id.as_deref(), Some(id(b).as_str()));
    assert_eq!(events[1].origin.as_deref(), Some("twin.test"));
    assert!(events[1].plan.is_none());
    let dump = format!("{events:?}");
    for s in [
        FORM_REF,
        USER_REF,
        PASS_REF,
        "ref-submit-7",
        "username",
        "current_password",
        "CurrentPassword",
        "tom@example.com",
    ] {
        assert!(!dump.contains(s), "audit holds {s}: {dump}");
    }
}

#[test]
fn plan_fill_otp_page_uses_the_login_holding_a_code() {
    let mut h = H::new();
    let (a, b) = twins(&mut h);
    let item = h
        .svc
        .vault_mut()
        .items
        .iter_mut()
        .find(|i| i.id == b)
        .unwrap();
    item.field_mut("totp").unwrap().value =
        FieldValue::Otp(format!("otpauth://totp/Twin:tom?secret={TOTP_SECRET}&issuer=Twin").into());
    // B (with a code) signed in here, then A (without one), last.
    ok(&h.call(note(b, TWIN)));
    ok(&h.call_at(note(a, TWIN), NOW + 60));
    let code_page = json!({"origin":TWIN,"top_origin":TWIN,"frame_kind":"top",
        "typed_username_hash":null,
        "forms":[{"form_ref":"form-otp","intent_hints":{"kind":"otp","signup_words":false,
            "reset_words":false,"checkout_words":false,"ignore":false},"step_index":null,
            "fields":[{"field_ref":"ref-otp","role":"otp","confidence":0.9,"visible":true,
                       "prefilled":"empty"}],
            "buttons":[{"button_ref":"ref-go","class":"submit"}]}]});
    let v = h.call_at(plan_req(TWIN, code_page), NOW + 120);
    let plan = &ok(&v)["plan"];
    assert_eq!(plan["intent"], "otp", "{plan}");
    assert_eq!(plan["groups"][0]["item_id"], id(b), "{plan}");
    assert_eq!(plan["action"], "fill_and_submit", "{plan}");
    assert_eq!(plan["alternatives"], json!([]), "{plan}");
}

#[test]
fn forget_site_only_from_popup() {
    let mut h = H::new();
    let (_, b) = twins(&mut h);
    ok(&h.call(note(b, TWIN)));
    for ctx in ["menu", "overlay", "chain", "save_prompt"] {
        let v = h.call(json!({"op":"forget_site","ctx":ctx,"site":"twin.test"}));
        assert_eq!(err(&v), "not_allowed", "{ctx}");
    }
    assert_eq!(h.vault().item(b).usage.len(), 1);
    let v = h.call(json!({"op":"forget_site","ctx":"popup","site":" Twin.Test "}));
    assert_eq!(ok(&v), &json!({"items":1}));
    assert!(h.vault().item(b).usage.is_empty());
    let v = h.call(json!({"op":"forget_site","ctx":"popup","site":"   "}));
    assert_eq!(err(&v), "invalid");
    let v = h.call(plan_req(TWIN, page(TWIN, None)));
    assert_eq!(ok(&v)["plan"]["confidence"], "low", "{v}");
}

#[test]
fn username_hash_vector() {
    // Same vector as `hash_matches_rust_vector` in the extension.
    let h = onepass_bridge::policy::username_hash(&[0u8; 32], "Tom@Example.com ");
    assert_eq!(
        data_encoding::HEXLOWER.encode(&h),
        "a2d55ed8b5a8ec8839231c0db36ebe5fd98d0bc6e8268b889a44f408e72c0d35"
    );
}

// Review round 1.

#[test]
fn note_fill_a_b_a_within_hour_prefers_a() {
    let mut h = H::new();
    let (a, b) = twins(&mut h);
    ok(&h.call_at(note(a, TWIN), NOW));
    ok(&h.call_at(note(b, TWIN), NOW + 600));
    ok(&h.call_at(note(a, TWIN), NOW + 1200));
    let v = h.call_at(plan_req(TWIN, page(TWIN, None)), NOW + 1300);
    let plan = &ok(&v)["plan"];
    assert_eq!(plan["groups"][0]["item_id"], id(a), "{plan}");
    assert_eq!(plan["confidence"], "high", "{plan}");
}

/// One checkout form: number, expiry, security code, a pay button.
fn checkout_page(origin: &str) -> Value {
    let field = |r: &str, role: &str| json!({"field_ref":r,"role":role,"confidence":0.9,"visible":true,"prefilled":"empty"});
    json!({"origin":origin,"top_origin":origin,"frame_kind":"top","typed_username_hash":null,
           "forms":[{"form_ref":"pay-form",
               "intent_hints":{"kind":"card","signup_words":false,"reset_words":false,
                               "checkout_words":true,"ignore":false},
               "step_index":null,
               "fields":[field("cc-n","cc_number"),field("cc-e","cc_exp"),field("cc-c","cc_csc")],
               "buttons":[{"button_ref":"pay","class":"pay"}]}]})
}

#[test]
fn note_fill_card_then_checkout_prefers_it() {
    use onepass_core::model::{ItemType, new_item};
    let mut h = H::new();
    let perso = h.ids.perso;
    let second = new_item(ItemType::CreditCard, perso, "Carte Twin");
    let second_id = second.id;
    h.svc.vault_mut().items.push(second);
    let cards = [h.ids.card, second_id];

    let v = h.call(plan_req(ATLAS, checkout_page(ATLAS)));
    let first = ok(&v)["plan"]["groups"][0]["item_id"].clone();
    assert_eq!(ok(&v)["plan"]["intent"], "checkout", "{v}");
    let other = cards.into_iter().find(|c| json!(id(*c)) != first).unwrap();

    let noted = json!({"op":"note_fill","ctx":"menu","item_id":id(other),"origin":ATLAS,
                       "roles":["cc_number","cc_exp","cc_csc"],"intent":"checkout",
                       "steps":["fill"]});
    assert_eq!(ok(&h.call(noted)), &json!({}));
    assert_eq!(h.vault().item(other).usage[0].site, "atlas-cloud.test");

    let v = h.call(plan_req(ATLAS, checkout_page(ATLAS)));
    let plan = &ok(&v)["plan"];
    assert_eq!(plan["groups"][0]["item_id"], id(other), "{plan}");
    assert_ne!(plan["action"], "fill_and_submit");
    // An http origin is still refused, even with no URL to match.
    let mut bad = json!({"op":"note_fill","ctx":"menu","item_id":id(other),
                         "origin":"http://atlas-cloud.test","roles":[],"intent":"checkout",
                         "steps":[]});
    assert_eq!(err(&h.call(bad.clone())), "insecure_origin");
    // An identity is noted the same way.
    bad["origin"] = json!(ATLAS);
    bad["item_id"] = json!(id(h.ids.identity));
    bad["intent"] = json!("address");
    assert_eq!(ok(&h.call(bad)), &json!({}));
}

#[test]
fn last_on_site_tie_marks_one() {
    let mut h = H::new();
    let (a, b) = twins(&mut h);
    ok(&h.call(note(a, TWIN)));
    ok(&h.call(note(b, TWIN)));
    let v = h.call(plan_req(TWIN, page(TWIN, None)));
    let plan = &ok(&v)["plan"];
    assert_eq!(plan["groups"][0]["item_id"], id(a.min(b)), "{plan}");
    assert!(
        plan["reasons"]
            .as_array()
            .unwrap()
            .contains(&json!("last_on_site")),
        "{plan}"
    );
}

#[test]
fn plan_fill_rejects_top_frame_with_other_top_origin() {
    let mut h = H::new();
    let mut ctx = page(ATLAS, None);
    ctx["top_origin"] = json!("https://evil.test");
    assert_eq!(err(&h.call(plan_req(ATLAS, ctx.clone()))), "invalid");
    // A same-origin child frame may sit under another top origin.
    ctx["frame_kind"] = json!("same_origin_child");
    ok(&h.call(plan_req(ATLAS, ctx)));
}

#[test]
fn forget_site_normalizes_unicode_host() {
    let mut h = H::new();
    let shop = "https://b\u{fc}cher.test";
    let item = h
        .svc
        .vault_mut()
        .add_login("Buecher", "alex@b.test", shop, MatchRule::Domain);
    ok(&h.call(note(item, shop)));
    assert_eq!(h.vault().item(item).usage[0].site, "xn--bcher-kva.test");
    let v = h.call(json!({"op":"forget_site","ctx":"popup","site":"login.B\u{dc}CHER.test"}));
    assert_eq!(ok(&v), &json!({"items":1}));
    assert!(h.vault().item(item).usage.is_empty());
}

// Review round 2.

#[test]
fn note_fill_a_b_a_across_vaults_prefers_a() {
    let mut h = H::new();
    let (perso, pro) = (h.ids.perso, h.ids.pro);
    let v = h.svc.vault_mut();
    let a = v.add_login_in(perso, "Twin A", "alex@twin.test", TWIN, MatchRule::Domain);
    let b = v.add_login_in(pro, "Twin B", "tom@example.com", TWIN, MatchRule::Domain);
    ok(&h.call_at(note(a, TWIN), NOW));
    ok(&h.call_at(note(b, TWIN), NOW + 600));
    ok(&h.call_at(note(a, TWIN), NOW + 1200));
    assert_eq!(
        h.vault().item(a).usage[0].last_at.unix_timestamp(),
        (NOW + 1200) as i64
    );
    let v = h.call_at(plan_req(TWIN, page(TWIN, None)), NOW + 1300);
    let plan = &ok(&v)["plan"];
    assert_eq!(plan["groups"][0]["item_id"], id(a), "{plan}");
    assert_eq!(plan["confidence"], "high", "{plan}");
}

// ---- Passkeys (spec 3.1 of the extension lab fixes) ----

mod passkeys {
    use super::*;
    use aws_lc_rs::digest::{SHA256, digest};
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1, UnparsedPublicKey};
    use data_encoding::BASE64URL_NOPAD as B64U;
    use onepass_core::model::PasskeyCredential;

    const RP: &str = "atlas-cloud.test";
    const LOGIN: &str = "https://login.atlas-cloud.test";
    const HANDLE: &[u8] = &[0x75, 0x73, 0x65, 0x72, 0x2d, 0x31];
    const CHALLENGE: &[u8] = &[0xfb, 0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

    fn b64(b: &[u8]) -> String {
        B64U.encode(b)
    }

    fn unb64(v: &Value) -> Vec<u8> {
        B64U.decode(v.as_str().expect("string").as_bytes())
            .expect("b64url")
    }

    /// The Atlas Cloud login with one passkey for `atlas-cloud.test`.
    fn with_passkey() -> (H, PasskeyCredential) {
        let mut h = H::new();
        let atlas = h.ids.atlas;
        let cred = h
            .svc
            .vault_mut()
            .add_passkey(atlas, RP, "alex@atlas.dev", HANDLE);
        (h, cred)
    }

    fn list_req(ctx: &str, origin: &str, rp_id: &str) -> Value {
        json!({"op":"passkey_list","ctx":ctx,"origin":origin,"rp_id":rp_id})
    }

    fn get_req(ctx: &str, origin: &str, rp_id: &str, item: Id, cred: &[u8]) -> Value {
        json!({"op":"passkey_get","ctx":ctx,"origin":origin,"top_origin":origin,"rp_id":rp_id,
               "item_id":id(item),"credential_id":b64(cred),"challenge":b64(CHALLENGE)})
    }

    fn create_req(origin: &str, user: &str, exclude: &[&[u8]]) -> Value {
        json!({"op":"passkey_create","ctx":"passkey","origin":origin,"top_origin":origin,"rp_id":RP,
               "user_name":user,"user_handle":b64(HANDLE),"challenge":b64(CHALLENGE),
               "exclude":exclude.iter().map(|c| b64(c)).collect::<Vec<_>>()})
    }

    /// Checks an assertion reply against a public key point.
    fn verify(reply: &Value, point: &[u8], rp_id: &str) {
        let auth = unb64(&reply["authenticator_data"]);
        assert_eq!(auth[..32], *digest(&SHA256, rp_id.as_bytes()).as_ref());
        let cdj = unb64(&reply["client_data_json"]);
        let mut msg = auth.clone();
        msg.extend_from_slice(digest(&SHA256, &cdj).as_ref());
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, point)
            .verify(&msg, &unb64(&reply["signature"]))
            .expect("signature verifies");
    }

    /// Uncompressed point of a credential's public key, from its COSE key.
    fn point_of(cred: &PasskeyCredential) -> Vec<u8> {
        let cose = onepass_core::webauthn::public_key_cose(cred).unwrap();
        let mut p = vec![0x04];
        p.extend_from_slice(&cose[10..42]);
        p.extend_from_slice(&cose[45..77]);
        p
    }

    #[test]
    fn passkey_list_has_no_secret() {
        let (mut h, cred) = with_passkey();
        let (hidden, archived) = (h.ids.hidden, h.ids.archived);
        h.svc.vault_mut().add_passkey(hidden, RP, "hidden", &[1]);
        h.svc
            .vault_mut()
            .add_passkey(archived, RP, "archived", &[2]);
        h.svc
            .vault_mut()
            .add_passkey(h.ids.admin, "other.test", "admin", &[3]);
        let v = h.call(list_req("passkey", LOGIN, RP));
        assert_eq!(
            ok(&v),
            &json!({"passkeys":[{
                "item_id": id(h.ids.atlas),
                "vault_id": id(h.ids.perso),
                "vault_name": "Personnel",
                "title": "Atlas Cloud",
                "user_name": "alex@atlas.dev",
                "credential_id": b64(&cred.credential_id),
            }]})
        );
        let dump = v.to_string();
        assert!(!dump.contains(&b64(&cred.private_key)));
        assert!(!dump.contains(&b64(HANDLE)));
        for s in SECRETS {
            assert!(!dump.contains(s), "leaked {s}");
        }
        // Chain context too; same rp id in upper case; nothing for another
        // rp id of the site; no audit and no rate limit slot.
        let v = h.call(list_req("chain", ATLAS, "ATLAS-cloud.test"));
        assert_eq!(ok(&v)["passkeys"].as_array().unwrap().len(), 1);
        h.svc
            .vault_mut()
            .add_passkey(h.ids.atlas, "login.atlas-cloud.test", "x", &[4]);
        let v = h.call(list_req("passkey", ATLAS, RP));
        assert_eq!(ok(&v)["passkeys"].as_array().unwrap().len(), 1);
        assert!(h.audit.events().is_empty());
    }

    #[test]
    fn passkey_list_checks_rp_id_and_origin() {
        let (mut h, _) = with_passkey();
        assert_eq!(
            err(&h.call(list_req("passkey", ATLAS, "evil.test"))),
            "origin_mismatch"
        );
        assert_eq!(
            err(&h.call(list_req("passkey", ATLAS, "test"))),
            "origin_mismatch"
        );
        assert_eq!(
            err(&h.call(list_req("passkey", "http://atlas-cloud.test", RP))),
            "insecure_origin"
        );
        assert_eq!(err(&h.call(list_req("menu", ATLAS, RP))), "not_allowed");
        h.svc.vault_mut().locked = true;
        assert_eq!(err(&h.call(list_req("passkey", ATLAS, RP))), "locked");
    }

    #[test]
    fn passkey_get_builds_client_data_from_origin() {
        let (mut h, cred) = with_passkey();
        let v = h.call(get_req(
            "passkey",
            LOGIN,
            RP,
            h.ids.atlas,
            &cred.credential_id,
        ));
        let r = ok(&v);
        assert_eq!(
            String::from_utf8(unb64(&r["client_data_json"])).unwrap(),
            format!(
                r#"{{"type":"webauthn.get","challenge":"{}","origin":"{LOGIN}","crossOrigin":false}}"#,
                b64(CHALLENGE)
            )
        );
        assert_eq!(unb64(&r["credential_id"]), cred.credential_id);
        assert_eq!(unb64(&r["user_handle"]), HANDLE);
        // The page cannot hand its own client data, nor a hash of it.
        for extra in [
            json!({"client_data_json": b64(b"{}")}),
            json!({"client_data_hash": b64(&[0u8; 32])}),
            json!({"cross_origin": true}),
        ] {
            let mut req = get_req("passkey", LOGIN, RP, h.ids.atlas, &cred.credential_id);
            for (k, x) in extra.as_object().unwrap() {
                req[k] = x.clone();
            }
            assert_eq!(err(&h.call(req)), "invalid");
        }
    }

    #[test]
    fn passkey_get_signature_verifies() {
        let (mut h, cred) = with_passkey();
        let v = h.call(get_req(
            "chain",
            ATLAS,
            RP,
            h.ids.atlas,
            &cred.credential_id,
        ));
        let r = ok(&v);
        verify(r, &point_of(&cred), RP);
        let auth = unb64(&r["authenticator_data"]);
        assert_eq!(auth.len(), 37);
        assert_eq!(auth[32] & 0x01, 0x01, "user present");
        assert_eq!(
            auth[32] & 0x04,
            0,
            "the bridge never claims user verification"
        );
        assert_eq!(r.as_object().unwrap().len(), 5);
        assert!(!v.to_string().contains(&b64(&cred.private_key)));
    }

    #[test]
    fn passkey_get_refused_outside_passkey_or_chain_ctx() {
        let (mut h, cred) = with_passkey();
        for ctx in ["popup", "menu", "overlay", "save_prompt"] {
            let v = h.call(get_req(ctx, ATLAS, RP, h.ids.atlas, &cred.credential_id));
            assert_eq!(err(&v), "not_allowed", "{ctx}");
        }
        assert!(h.audit.events().is_empty());
    }

    #[test]
    fn passkey_get_http_refused() {
        let (mut h, cred) = with_passkey();
        for o in [
            "http://atlas-cloud.test",
            "http://login.atlas-cloud.test:8080",
        ] {
            let v = h.call(get_req("passkey", o, RP, h.ids.atlas, &cred.credential_id));
            assert_eq!(err(&v), "insecure_origin", "{o}");
        }
        assert!(h.audit.events().is_empty());
    }

    #[test]
    fn passkey_get_refuses_other_site_and_unknown_credential() {
        let (mut h, cred) = with_passkey();
        let atlas = h.ids.atlas;
        let evil = h
            .svc
            .vault_mut()
            .add_login("Evil", "e", "https://evil.test", MatchRule::Domain);
        let evil_cred = h.svc.vault_mut().add_passkey(evil, "evil.test", "e", &[9]);
        // The rp id of another site, even with a credential that exists.
        let v = h.call(get_req(
            "passkey",
            ATLAS,
            "evil.test",
            evil,
            &evil_cred.credential_id,
        ));
        assert_eq!(err(&v), "origin_mismatch");
        // A credential of another rp id under this site's rp id.
        let v = h.call(get_req(
            "passkey",
            ATLAS,
            RP,
            evil,
            &evil_cred.credential_id,
        ));
        assert_eq!(err(&v), "not_found");
        // Another item's id with this credential.
        let v = h.call(get_req(
            "passkey",
            ATLAS,
            RP,
            h.ids.admin,
            &cred.credential_id,
        ));
        assert_eq!(err(&v), "not_found");
        let v = h.call(get_req("passkey", ATLAS, RP, atlas, &[1, 2, 3]));
        assert_eq!(err(&v), "not_found");
        // Bad shapes.
        let mut bad = get_req("passkey", ATLAS, RP, atlas, &cred.credential_id);
        bad["challenge"] = json!("");
        assert_eq!(err(&h.call(bad.clone())), "invalid");
        bad["challenge"] = json!(b64(&[0u8; 1025]));
        assert_eq!(err(&h.call(bad)), "invalid");
        let mut bad = get_req("passkey", ATLAS, RP, atlas, &cred.credential_id);
        bad["credential_id"] = json!("not base64url!");
        assert_eq!(err(&h.call(bad)), "invalid");
        assert!(h.audit.events().is_empty());
    }

    #[test]
    fn passkey_get_follows_reprompt() {
        let mut h = H::new();
        let r = h.ids.reprompt;
        let cred = h.svc.vault_mut().add_passkey(r, RP, "alex", HANDLE);
        let v = h.call(get_req("passkey", ATLAS, RP, r, &cred.credential_id));
        assert_eq!(err(&v), "reprompt_required");
        h.svc.vault_mut().approve_reprompt = true;
        ok(&h.call(get_req("passkey", ATLAS, RP, r, &cred.credential_id)));
    }

    #[test]
    fn passkey_create_then_get() {
        let mut h = H::new();
        let atlas = h.ids.atlas;
        // Stored in the site's login with this user name.
        let v = h.call(create_req(LOGIN, "Alex@Atlas.dev", &[]));
        let r = ok(&v).clone();
        assert_eq!(r["item_id"], id(atlas));
        assert_eq!(r["public_key_algorithm"], -7);
        let cdj: Value = serde_json::from_slice(&unb64(&r["client_data_json"])).unwrap();
        assert_eq!(
            cdj,
            json!({"type":"webauthn.create","challenge":b64(CHALLENGE),"origin":LOGIN,"crossOrigin":false})
        );
        let stored = h.vault().passkeys(atlas);
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].rp_id, RP);
        assert_eq!(stored[0].user_name, "Alex@Atlas.dev");
        assert_eq!(stored[0].user_handle, HANDLE);
        let cred_id = unb64(&r["credential_id"]);
        assert_eq!(stored[0].credential_id, cred_id);
        let auth = unb64(&r["authenticator_data"]);
        assert_eq!(auth[..32], *digest(&SHA256, RP.as_bytes()).as_ref());
        assert_eq!(auth[32] & 0x05, 0x01, "UP=1, UV=0");
        assert!(
            unb64(&r["attestation_object"])
                .windows(auth.len())
                .any(|w| w == auth.as_slice())
        );
        // SPKI DER of the new key: header then the point of the COSE key.
        let spki = unb64(&r["public_key"]);
        assert_eq!(spki.len(), 91);
        assert_eq!(spki[26..], point_of(&stored[0])[..]);
        assert!(
            h.vault()
                .item(atlas)
                .login_methods
                .contains(&LoginMethod::Passkey)
        );
        assert!(!v.to_string().contains(&b64(&stored[0].private_key)));

        // Then it signs, verified with the public key the creation gave.
        let v = h.call(get_req("passkey", ATLAS, RP, atlas, &cred_id));
        verify(ok(&v), &spki[26..], RP);
        let v = h.call(list_req("passkey", ATLAS, RP));
        assert_eq!(ok(&v)["passkeys"][0]["credential_id"], b64(&cred_id));

        // Another user name: a new login of the site in the first vault.
        let v = h.call(create_req(ATLAS, "new.user@atlas.dev", &[]));
        let new_id = ok(&v)["item_id"].as_str().unwrap().to_owned();
        assert_ne!(new_id, id(atlas));
        let item = h
            .vault()
            .items
            .iter()
            .find(|i| i.id.to_string() == new_id)
            .unwrap()
            .clone();
        assert_eq!(item.vault_id, h.ids.perso);
        assert_eq!(item.title, RP);
        assert_eq!(item.subtitle(), "new.user@atlas.dev");
        assert_eq!(item.urls[0].url, format!("https://{RP}"));
        let v = h.call(list_req("passkey", LOGIN, RP));
        assert_eq!(ok(&v)["passkeys"].as_array().unwrap().len(), 2);
        let ops: Vec<&str> = h.audit.events().iter().map(|e| e.op).collect();
        assert_eq!(ops, ["passkey_create", "passkey_get", "passkey_create"]);
    }

    #[test]
    fn passkey_create_checks_context_and_shapes() {
        let mut h = H::new();
        let mut req = create_req(ATLAS, "alex@atlas.dev", &[]);
        for ctx in ["chain", "menu", "popup", "overlay", "save_prompt"] {
            req["ctx"] = json!(ctx);
            assert_eq!(err(&h.call(req.clone())), "not_allowed", "{ctx}");
        }
        let mut req = create_req("http://atlas-cloud.test", "alex@atlas.dev", &[]);
        assert_eq!(err(&h.call(req.clone())), "insecure_origin");
        req["origin"] = json!(ATLAS);
        req["top_origin"] = json!(ATLAS);
        req["rp_id"] = json!("evil.test");
        assert_eq!(err(&h.call(req.clone())), "origin_mismatch");
        req["rp_id"] = json!(RP);
        req["user_handle"] = json!(b64(&[0u8; 65]));
        assert_eq!(err(&h.call(req.clone())), "invalid");
        req["user_handle"] = json!(b64(HANDLE));
        req["vault_id"] = json!(id(Id::new()));
        assert_eq!(err(&h.call(req.clone())), "not_found");
        req["vault_id"] = json!(id(h.ids.pro));
        let v = h.call(req);
        // The site's login of that user name wins over the vault asked for.
        assert_eq!(ok(&v)["item_id"], id(h.ids.atlas));
        assert_eq!(err(&h.call(create_req(ATLAS, " ", &[]))), "invalid");
        assert!(h.vault().passkeys(h.ids.admin).is_empty());
    }

    #[test]
    fn passkey_create_excluded() {
        let (mut h, cred) = with_passkey();
        let before = h.vault().items.len();
        let v = h.call(create_req(
            ATLAS,
            "someone@atlas.dev",
            &[&[7, 7], &cred.credential_id],
        ));
        assert_eq!(err(&v), "excluded");
        assert_eq!(h.vault().items.len(), before);
        assert_eq!(h.vault().passkeys(h.ids.atlas).len(), 1);
        // An excluded id of another rp id does not block.
        let other = h
            .svc
            .vault_mut()
            .add_passkey(h.ids.admin, "other.test", "a", &[1]);
        ok(&h.call(create_req(
            ATLAS,
            "someone@atlas.dev",
            &[&other.credential_id],
        )));
        assert!(h.audit.events().iter().all(|e| e.op == "passkey_create"));
        assert_eq!(h.audit.events().len(), 1);
    }

    #[test]
    fn passkey_ops_are_audited_and_rate_limited() {
        let (mut h, cred) = with_passkey();
        let atlas = h.ids.atlas;
        ok(&h.call(get_req("passkey", LOGIN, RP, atlas, &cred.credential_id)));
        ok(&h.call(create_req(ATLAS, "other@atlas.dev", &[])));
        let events = h.audit.events();
        assert_eq!(events[0].op, "passkey_get");
        assert_eq!(events[0].item_id, Some(id(atlas)));
        assert_eq!(events[0].origin.as_deref(), Some(LOGIN));
        assert_eq!(events[0].at, NOW);
        assert_eq!(events[1].op, "passkey_create");
        assert_eq!(events[1].origin.as_deref(), Some(ATLAS));
        let dump = format!("{events:?}");
        assert!(!dump.contains(&b64(&cred.private_key)));
        assert!(!dump.contains(&b64(CHALLENGE)));
        for _ in 2..60 {
            ok(&h.call(get_req("chain", ATLAS, RP, atlas, &cred.credential_id)));
        }
        let v = h.call(get_req("passkey", ATLAS, RP, atlas, &cred.credential_id));
        assert_eq!(err(&v), "rate_limited");
        assert_eq!(
            err(&h.call(create_req(ATLAS, "x@atlas.dev", &[]))),
            "rate_limited"
        );
        // The list has no secret: never limited.
        ok(&h.call(list_req("passkey", ATLAS, RP)));
        // Other secret requests share the window.
        assert_eq!(err(&h.call(fill(atlas, ATLAS))), "rate_limited");
        ok(&h.call_at(
            get_req("passkey", ATLAS, RP, atlas, &cred.credential_id),
            NOW + 60,
        ));
    }

    #[test]
    fn passkey_top_origin_must_be_the_frame_origin() {
        let (mut h, cred) = with_passkey();
        let atlas = h.ids.atlas;
        // A same-origin frame (top equals frame, path and port normalized).
        let mut req = get_req("passkey", ATLAS, RP, atlas, &cred.credential_id);
        req["top_origin"] = json!("https://atlas-cloud.test:443/home");
        ok(&h.call(req));
        for top in [
            "https://evil.test",
            "https://login.atlas-cloud.test",
            "https://atlas-cloud.test:8443",
            "http://atlas-cloud.test",
            "not an origin",
        ] {
            let mut req = get_req("passkey", ATLAS, RP, atlas, &cred.credential_id);
            req["top_origin"] = json!(top);
            assert_eq!(err(&h.call(req)), "not_allowed", "get {top}");
            let mut req = create_req(ATLAS, "alex@atlas.dev", &[]);
            req["top_origin"] = json!(top);
            assert_eq!(err(&h.call(req)), "not_allowed", "create {top}");
        }
        // Required.
        let mut req = get_req("passkey", ATLAS, RP, atlas, &cred.credential_id);
        req.as_object_mut().unwrap().remove("top_origin");
        assert_eq!(err(&h.call(req)), "invalid");
        let mut req = create_req(ATLAS, "alex@atlas.dev", &[]);
        req.as_object_mut().unwrap().remove("top_origin");
        assert_eq!(err(&h.call(req)), "invalid");
        // Still crossOrigin false on the accepted call.
        let v = h.call(get_req("passkey", ATLAS, RP, atlas, &cred.credential_id));
        let cd: Value = serde_json::from_slice(&unb64(&ok(&v)["client_data_json"])).unwrap();
        assert_eq!(cd["crossOrigin"], false);
        assert_eq!(h.audit.events().len(), 2);
    }

    #[test]
    fn passkey_origin_with_trailing_dot_refused() {
        let (mut h, cred) = with_passkey();
        let atlas = h.ids.atlas;
        let dotted = "https://atlas-cloud.test.";
        let v = h.call(get_req("passkey", dotted, RP, atlas, &cred.credential_id));
        assert_eq!(err(&v), "invalid");
        assert_eq!(
            err(&h.call(create_req(dotted, "alex@atlas.dev", &[]))),
            "invalid"
        );
        assert_eq!(err(&h.call(list_req("passkey", dotted, RP))), "invalid");
        assert!(h.audit.events().is_empty());
    }

    #[test]
    fn passkey_create_refuses_control_characters_in_user_name() {
        let mut h = H::new();
        for user in [
            "alex\u{202e}gro.live",
            "alex\u{200b}",
            "alex\nroot",
            "alex\u{2066}",
        ] {
            assert_eq!(
                err(&h.call(create_req(ATLAS, user, &[]))),
                "invalid",
                "{user:?}"
            );
        }
        assert!(h.audit.events().is_empty());
        assert!(h.vault().passkeys(h.ids.atlas).is_empty());
    }
}

fn save_pending(h: &mut H, origin: &str, username: &str) -> Id {
    let perso = h.ids.perso;
    let v = h.call(
        json!({"op":"save_login","ctx":"save_prompt","origin":origin,"title":"",
        "username":username,"password":"Gen-Pass-0042","vault_id":id(perso),
        "rule":"domain","tags":["onepass:pending","onepass:weak-by-site"]}),
    );
    ok(&v)["item_id"].as_str().unwrap().parse().unwrap()
}

fn username_of(h: &H, item: Id) -> String {
    match &h.vault().item(item).field("username").unwrap().value {
        FieldValue::Text(s) => s.clone(),
        _ => panic!("username field"),
    }
}

#[test]
fn confirm_pending_drops_tag_sets_username() {
    let mut h = H::new();
    let item = save_pending(&mut h, "https://signup.atlas-cloud.test/join", "");
    let v = h.call(
        json!({"op":"confirm_pending","ctx":"save_prompt","item_id":id(item),
        "origin":"https://signup.atlas-cloud.test","username":"  alex@atlas.dev "}),
    );
    assert_eq!(ok(&v), &json!({}));
    assert_eq!(h.vault().item(item).tags, ["onepass:weak-by-site"]);
    assert_eq!(username_of(&h, item), "alex@atlas.dev");
    match &h.vault().item(item).field("password").unwrap().value {
        FieldValue::Password(p) => assert_eq!(p.as_str(), "Gen-Pass-0042"),
        _ => panic!("password field"),
    }
    // Confirmed once: a second confirm finds no pending tag.
    let v = h.call(
        json!({"op":"confirm_pending","ctx":"save_prompt","item_id":id(item),
        "origin":"https://signup.atlas-cloud.test","username":"other@atlas.dev"}),
    );
    assert_eq!(err(&v), "invalid");
    assert_eq!(username_of(&h, item), "alex@atlas.dev");

    // An empty submitted username keeps the one already known.
    let known = save_pending(&mut h, ATLAS, "known@atlas.dev");
    let v = h.call(
        json!({"op":"confirm_pending","ctx":"save_prompt","item_id":id(known),
        "origin":ATLAS,"username":""}),
    );
    assert_eq!(ok(&v), &json!({}));
    assert_eq!(username_of(&h, known), "known@atlas.dev");
    assert!(
        h.vault()
            .item(known)
            .tags
            .iter()
            .all(|t| t != "onepass:pending")
    );
}

#[test]
fn update_password_sets_and_clears_weak_tag_on_pending() {
    let mut h = H::new();
    let item = save_pending(&mut h, ATLAS, "");
    let update = |h: &mut H, weak: Option<bool>| {
        let mut req = json!({"op":"update_password","ctx":"save_prompt","item_id":id(item),
            "origin":ATLAS,"password":"Gen-Pass-0043"});
        if let Some(w) = weak {
            req["weak_by_site"] = json!(w);
        }
        let v = h.call(req);
        assert_eq!(ok(&v), &json!({}));
    };
    // A strong regeneration clears the tag.
    update(&mut h, Some(false));
    assert_eq!(h.vault().item(item).tags, ["onepass:pending"]);
    // A weak one sets it, once.
    update(&mut h, Some(true));
    update(&mut h, Some(true));
    assert_eq!(
        h.vault().item(item).tags,
        ["onepass:pending", "onepass:weak-by-site"]
    );
    // No flag: tags untouched.
    update(&mut h, None);
    assert_eq!(
        h.vault().item(item).tags,
        ["onepass:pending", "onepass:weak-by-site"]
    );
}

#[test]
fn update_password_weak_flag_ignored_off_pending() {
    let mut h = H::new();
    let item = save_pending(&mut h, ATLAS, "known@atlas.dev");
    let v = h.call(
        json!({"op":"confirm_pending","ctx":"save_prompt","item_id":id(item),
        "origin":ATLAS,"username":""}),
    );
    assert_eq!(ok(&v), &json!({}));
    let v = h.call(
        json!({"op":"update_password","ctx":"save_prompt","item_id":id(item),
        "origin":ATLAS,"password":"Gen-Pass-0044","weak_by_site":false}),
    );
    assert_eq!(ok(&v), &json!({}));
    assert_eq!(h.vault().item(item).tags, ["onepass:weak-by-site"]);
}

#[test]
fn confirm_pending_refuses_untagged() {
    let mut h = H::new();
    let atlas = h.ids.atlas;
    let before = h.vault().item(atlas).clone();
    let v = h.call(
        json!({"op":"confirm_pending","ctx":"save_prompt","item_id":id(atlas),
        "origin":ATLAS,"username":"mallory@evil.test"}),
    );
    assert_eq!(err(&v), "invalid");
    let after = h.vault().item(atlas);
    assert_eq!(after.tags, before.tags);
    assert_eq!(
        after.field("username").unwrap().value,
        before.field("username").unwrap().value
    );
    let v = h.call(
        json!({"op":"confirm_pending","ctx":"save_prompt","item_id":id(Id::new()),
        "origin":ATLAS,"username":"x"}),
    );
    assert_eq!(err(&v), "not_found");
}

#[test]
fn confirm_pending_checks_origin() {
    let mut h = H::new();
    let item = save_pending(&mut h, ATLAS, "");
    let v = h.call(
        json!({"op":"confirm_pending","ctx":"save_prompt","item_id":id(item),
        "origin":"https://evil.test","username":"alex@atlas.dev"}),
    );
    assert_eq!(err(&v), "origin_mismatch");
    let v = h.call(
        json!({"op":"confirm_pending","ctx":"save_prompt","item_id":id(item),
        "origin":"http://atlas-cloud.test","username":"alex@atlas.dev"}),
    );
    assert_eq!(err(&v), "insecure_origin");
    assert!(
        h.vault()
            .item(item)
            .tags
            .iter()
            .any(|t| t == "onepass:pending")
    );
    assert_eq!(
        h.vault().item(item).field("username").unwrap().value,
        FieldValue::Empty
    );
    // Unknown fields are refused like every request.
    let v = h.call(
        json!({"op":"confirm_pending","ctx":"save_prompt","item_id":id(item),
        "origin":ATLAS,"username":"a","password":"x"}),
    );
    assert_eq!(err(&v), "invalid");
    // No username known nor submitted: confirming would leave a Login without one.
    let v = h.call(
        json!({"op":"confirm_pending","ctx":"save_prompt","item_id":id(item),
        "origin":ATLAS,"username":"  "}),
    );
    assert_eq!(err(&v), "invalid");
    assert!(h.vault().item(item).is_pending());
}

fn check(origin: &str, user: &str, pass: &str) -> Value {
    json!({"op":"check_credentials","ctx":"save_prompt","origin":origin,
           "username":user,"password":pass})
}

#[test]
fn check_credentials_finds_pending_any_username() {
    let mut h = H::new();
    let item = save_pending(&mut h, "https://signup.atlas-cloud.test/join", "");
    for user in ["alex@atlas.dev", "", "someone@else.test"] {
        let v = h.call(check("https://app.atlas-cloud.test", user, "Gen-Pass-0042"));
        assert_eq!(
            ok(&v),
            &json!({"status":"pending","item_id":id(item),"title":"atlas-cloud.test"}),
            "{user}"
        );
    }
    // A pending item with a known username: still `pending`, never `same`.
    let known = save_pending(&mut h, ATLAS, "alex@atlas.dev");
    h.call(
        json!({"op":"confirm_pending","ctx":"save_prompt","item_id":id(item),
        "origin":ATLAS,"username":"first@atlas.dev"}),
    );
    let v = h.call(check(ATLAS, "alex@atlas.dev", "Gen-Pass-0042"));
    assert_eq!(ok(&v)["status"], "pending");
    assert_eq!(ok(&v)["item_id"], id(known));
    // Confirmed items answer as before.
    ok(&h.call(
        json!({"op":"confirm_pending","ctx":"save_prompt","item_id":id(known),
        "origin":ATLAS,"username":""}),
    ));
    let v = h.call(check(ATLAS, "first@atlas.dev", "Gen-Pass-0042"));
    assert_eq!(ok(&v)["status"], "same");
    assert_eq!(ok(&v)["item_id"], id(item));
    // Non-pending items keep their verdicts.
    let v = h.call(check(ATLAS, "alex@atlas.dev", ATLAS_PASSWORD));
    assert_eq!(ok(&v)["status"], "same");
    assert_eq!(ok(&v)["item_id"], id(h.ids.atlas));
}

#[test]
fn check_credentials_pending_wrong_password_is_new() {
    let mut h = H::new();
    save_pending(&mut h, ATLAS, "");
    let v = h.call(check(ATLAS, "nobody@atlas.dev", "Typed-Pass-0099"));
    assert_eq!(ok(&v), &json!({"status":"new"}));
    // The pending item is no update candidate either: the known login is.
    let v = h.call(check(ATLAS, "alex@atlas.dev", "Typed-Pass-0099"));
    assert_eq!(ok(&v)["status"], "update");
    assert_eq!(ok(&v)["item_id"], id(h.ids.atlas));
}

#[test]
fn check_credentials_pending_other_site_ignored() {
    let mut h = H::new();
    save_pending(&mut h, ATLAS, "");
    let v = h.call(check(
        "https://evil.test",
        "alex@atlas.dev",
        "Gen-Pass-0042",
    ));
    assert_eq!(ok(&v), &json!({"status":"new"}));
}

// Cards and identities typed by hand in a page form (MS-04).

const SHOP: &str = "https://shop.atlas-cloud.test";
const NEW_CARD: &str = "5555 5555 5555 4444";

fn check_card(number: &str, month: &str, year: &str) -> Value {
    json!({"op":"check_card","ctx":"save_prompt","origin":SHOP,
           "number":number,"exp_month":month,"exp_year":year})
}

fn save_card(vault: Id, number: &str, month: &str, year: &str, item_id: Option<Id>) -> Value {
    let mut v = json!({"op":"save_card","ctx":"save_prompt","origin":SHOP,"vault_id":id(vault),
        "title":"","cardholder":"  Alex Martin ","number":number,
        "exp_month":month,"exp_year":year});
    if let Some(i) = item_id {
        v["item_id"] = json!(id(i));
    }
    v
}

fn saved<'a>(h: &'a H, v: &Value) -> &'a onepass_core::model::Item {
    let new_id = ok(v)["item_id"].as_str().unwrap().to_owned();
    h.vault()
        .items
        .iter()
        .find(|i| i.id.to_string() == new_id)
        .unwrap()
}

#[test]
fn check_card_new_same_update() {
    let mut h = H::new();
    let card = h.ids.card;
    let same = json!({"status":"same","item_id":id(card),"title":"Carte Atlas"});
    assert_eq!(
        ok(&h.call(check_card("4242424242424242", "04", "2029"))),
        &same
    );
    assert_eq!(
        ok(&h.call(check_card("4242-4242-4242-4242", "4", "29"))),
        &same
    );
    // No typed expiry: the number alone answers.
    assert_eq!(
        ok(&h.call(check_card("4242 4242 4242 4242", "", ""))),
        &same
    );
    let v = h.call(check_card("4242424242424242", "05", "2031"));
    assert_eq!(
        ok(&v),
        &json!({"status":"update","item_id":id(card),"title":"Carte Atlas"})
    );
    assert_eq!(
        ok(&h.call(check_card(NEW_CARD, "01", "30"))),
        &json!({"status":"new"})
    );
    // An archived card never answers.
    h.svc
        .vault_mut()
        .items
        .iter_mut()
        .find(|i| i.id == card)
        .unwrap()
        .archived = true;
    assert_eq!(
        ok(&h.call(check_card("4242424242424242", "04", "2029"))),
        &json!({"status":"new"})
    );
}

#[test]
fn check_card_refuses_bad_input() {
    let mut h = H::new();
    for bad in ["4242", "4242 4242 4242 4241", "4242x4242x4242x4242", ""] {
        assert_eq!(err(&h.call(check_card(bad, "", ""))), "invalid", "{bad}");
    }
    assert_eq!(err(&h.call(check_card(NEW_CARD, "13", "2030"))), "invalid");
    assert_eq!(err(&h.call(check_card(NEW_CARD, "01", "203"))), "invalid");
    for ctx in ["menu", "popup", "overlay", "chain"] {
        let v = h.call(json!({"op":"check_card","ctx":ctx,"origin":SHOP,
            "number":NEW_CARD,"exp_month":"","exp_year":""}));
        assert_eq!(err(&v), "not_allowed", "{ctx}");
    }
    let http = json!({"op":"check_card","ctx":"save_prompt","origin":"http://shop.test",
        "number":NEW_CARD,"exp_month":"","exp_year":""});
    assert_eq!(err(&h.call(http)), "insecure_origin");
}

#[test]
fn save_card_new_stores_fields_without_cvv() {
    let mut h = H::new();
    let perso = h.ids.perso;
    let v = h.call(save_card(perso, NEW_CARD, "3", "31", None));
    let item = saved(&h, &v);
    assert_eq!(item.vault_id, perso);
    assert_eq!(item.item_type, onepass_core::model::ItemType::CreditCard);
    assert_eq!(item.title, "Carte \u{2022}\u{2022}\u{2022}\u{2022} 4444");
    assert_eq!(
        item.field("cardholder").unwrap().value,
        FieldValue::Text("Alex Martin".into())
    );
    assert!(matches!(
        &item.field("number").unwrap().value,
        FieldValue::Concealed(n) if n.as_str() == "5555555555554444"
    ));
    assert_eq!(
        item.field("expiry").unwrap().value,
        FieldValue::MonthYear {
            year: 2031,
            month: 3
        }
    );
    assert_eq!(item.field("cvv").unwrap().value, FieldValue::Empty);
    let new_id = item.id;
    let events = h.audit.events();
    let last = events.last().unwrap();
    assert_eq!(last.op, "save_card");
    assert_eq!(last.item_id, Some(id(new_id)));
    assert_eq!(last.origin.as_deref(), Some(SHOP));
    assert!(!format!("{events:?}").contains("4444"));
    // Now known.
    let v = h.call(check_card(NEW_CARD, "03", "2031"));
    assert_eq!(ok(&v)["status"], "same");
    assert_eq!(ok(&v)["item_id"], id(new_id));
}

#[test]
fn save_card_without_expiry_or_holder() {
    let mut h = H::new();
    let perso = h.ids.perso;
    let v = h.call(json!({"op":"save_card","ctx":"save_prompt","origin":SHOP,
        "vault_id":id(perso),"title":"Ma carte","cardholder":"","number":NEW_CARD,
        "exp_month":"","exp_year":""}));
    let item = saved(&h, &v);
    assert_eq!(item.title, "Ma carte");
    assert_eq!(item.field("expiry").unwrap().value, FieldValue::Empty);
    assert_eq!(item.field("cardholder").unwrap().value, FieldValue::Empty);
    let before = h.vault().items.len();
    // Both parts given, one wrong.
    assert_eq!(
        err(&h.call(save_card(perso, NEW_CARD, "0", "31", None))),
        "invalid"
    );
    assert_eq!(
        err(&h.call(save_card(perso, "1234", "", "", None))),
        "invalid"
    );
    assert_eq!(
        err(&h.call(save_card(Id::new(), NEW_CARD, "", "", None))),
        "not_found"
    );
    assert_eq!(h.vault().items.len(), before);
}

#[test]
fn save_card_updates_expiry_of_the_same_number() {
    let mut h = H::new();
    let (perso, card) = (h.ids.perso, h.ids.card);
    let before = h.vault().items.len();
    let v = h.call(save_card(
        perso,
        "4242424242424242",
        "09",
        "2032",
        Some(card),
    ));
    assert_eq!(ok(&v), &json!({"item_id":id(card)}));
    assert_eq!(h.vault().items.len(), before);
    let item = h.vault().item(card);
    assert_eq!(
        item.field("expiry").unwrap().value,
        FieldValue::MonthYear {
            year: 2032,
            month: 9
        }
    );
    // Everything else stays: holder, number as stored, CVV, title.
    assert_eq!(item.title, "Carte Atlas");
    assert_eq!(
        item.field("cardholder").unwrap().value,
        FieldValue::Text("Alex Martin".into())
    );
    assert!(matches!(
        &item.field("number").unwrap().value,
        FieldValue::Concealed(n) if n.as_str() == CARD_NUMBER
    ));
    assert!(matches!(
        &item.field("cvv").unwrap().value,
        FieldValue::Concealed(n) if n.as_str() == CARD_CVV
    ));
    assert_eq!(h.audit.events().last().unwrap().op, "save_card");
}

#[test]
fn save_card_refuses_another_number_for_an_item() {
    let mut h = H::new();
    let (perso, card, identity) = (h.ids.perso, h.ids.card, h.ids.identity);
    let v = h.call(save_card(perso, NEW_CARD, "09", "2032", Some(card)));
    assert_eq!(err(&v), "invalid");
    assert_eq!(
        h.vault().item(card).field("expiry").unwrap().value,
        FieldValue::MonthYear {
            year: 2029,
            month: 4
        }
    );
    let v = h.call(save_card(perso, NEW_CARD, "09", "2032", Some(identity)));
    assert_eq!(err(&v), "not_found");
    let v = h.call(save_card(perso, NEW_CARD, "09", "2032", Some(Id::new())));
    assert_eq!(err(&v), "not_found");
}

#[test]
fn save_card_and_identity_need_save_prompt() {
    let mut h = H::new();
    let perso = h.ids.perso;
    let before = h.vault().items.len();
    for ctx in ["menu", "popup", "overlay", "chain", "passkey"] {
        let mut v = save_card(perso, NEW_CARD, "", "", None);
        v["ctx"] = json!(ctx);
        assert_eq!(err(&h.call(v)), "not_allowed", "{ctx}");
        let v = json!({"op":"save_identity","ctx":ctx,"origin":SHOP,"vault_id":id(perso),
            "title":"","given_name":"Sam"});
        assert_eq!(err(&h.call(v)), "not_allowed", "{ctx}");
        let v = json!({"op":"check_identity","ctx":ctx,"origin":SHOP,"given_name":"Sam"});
        assert_eq!(err(&h.call(v)), "not_allowed", "{ctx}");
    }
    assert_eq!(h.vault().items.len(), before);
}

fn check_identity(extra: Value) -> Value {
    let mut v = json!({"op":"check_identity","ctx":"save_prompt","origin":SHOP});
    for (k, val) in extra.as_object().unwrap() {
        v[k] = val.clone();
    }
    v
}

#[test]
fn check_identity_same_and_new() {
    let mut h = H::new();
    let identity = h.ids.identity;
    let same = json!({"status":"same","item_id":id(identity),"title":"Alex Martin"});
    let v = h.call(check_identity(json!({
        "given_name":" alex ","family_name":"MARTIN","email":"Alex@Atlas.dev",
        "tel":"+33 (6) 00-00-00-00","organization":"atlas",
        "address":{"line1":"1  rue de l'exemple","city":"LYON","postal_code":"69000","country":"fr"}
    })));
    assert_eq!(ok(&v), &same);
    // A subset is held too.
    assert_eq!(
        ok(&h.call(check_identity(json!({"email":"alex@atlas.dev"})))),
        &same
    );
    for differs in [
        json!({"given_name":"Sam"}),
        json!({"given_name":"Alex","email":"sam@atlas.dev"}),
        json!({"tel":"+33 6 11 11 11 11"}),
        json!({"address":{"city":"Paris"}}),
    ] {
        let v = h.call(check_identity(differs.clone()));
        assert_eq!(ok(&v), &json!({"status":"new"}), "{differs}");
    }
}

#[test]
fn check_identity_refuses_nothing_typed() {
    let mut h = H::new();
    for empty in [
        json!({}),
        json!({"given_name":"  ","email":"","tel":"-"}),
        json!({"address":{"line1":" ","city":""}}),
    ] {
        assert_eq!(
            err(&h.call(check_identity(empty.clone()))),
            "invalid",
            "{empty}"
        );
    }
}

#[test]
fn save_identity_with_address() {
    let mut h = H::new();
    let perso = h.ids.perso;
    let v = h.call(
        json!({"op":"save_identity","ctx":"save_prompt","origin":SHOP,
        "vault_id":id(perso),"title":"","given_name":" Sam ","family_name":"Durand",
        "email":"sam@example.test","tel":"+33 6 11 11 11 11","organization":"Atlas",
        "address":{"line1":"2 avenue du Test ","line2":"","city":"Paris","postal_code":"75001",
                   "region":"","country":"FR"}}),
    );
    let item = saved(&h, &v);
    assert_eq!(item.item_type, onepass_core::model::ItemType::Identity);
    assert_eq!(item.title, "Sam Durand");
    assert_eq!(
        item.field("first_name").unwrap().value,
        FieldValue::Text("Sam".into())
    );
    assert_eq!(
        item.field("last_name").unwrap().value,
        FieldValue::Text("Durand".into())
    );
    assert_eq!(
        item.field("email").unwrap().value,
        FieldValue::Email("sam@example.test".into())
    );
    assert_eq!(
        item.field("mobile_phone").unwrap().value,
        FieldValue::Phone("+33 6 11 11 11 11".into())
    );
    assert_eq!(
        item.field("company").unwrap().value,
        FieldValue::Text("Atlas".into())
    );
    let FieldValue::Address(a) = &item.field("address").unwrap().value else {
        panic!("no address")
    };
    assert_eq!(a.line1, "2 avenue du Test");
    assert_eq!(a.city, "Paris");
    assert_eq!(a.country, "FR");
    let new_id = item.id;
    let last = h.audit.events().last().cloned().unwrap();
    assert_eq!(last.op, "save_identity");
    assert_eq!(last.item_id, Some(id(new_id)));
    // Now known.
    let v = h.call(check_identity(
        json!({"email":"sam@example.test","tel":"0033611111111"}),
    ));
    assert_eq!(ok(&v)["status"], "new");
    let v = h.call(check_identity(
        json!({"email":"sam@example.test","tel":"+33611111111"}),
    ));
    assert_eq!(ok(&v)["item_id"], id(new_id));
}

#[test]
fn save_identity_titles_and_no_address() {
    let mut h = H::new();
    let perso = h.ids.perso;
    let v = h.call(
        json!({"op":"save_identity","ctx":"save_prompt","origin":SHOP,
        "vault_id":id(perso),"title":"","email":"sam@example.test",
        "address":{"line1":" ","city":""}}),
    );
    let item = saved(&h, &v);
    assert_eq!(item.title, "sam@example.test");
    assert_eq!(item.field("address").unwrap().value, FieldValue::Empty);
    let v = h.call(
        json!({"op":"save_identity","ctx":"save_prompt","origin":SHOP,
        "vault_id":id(perso),"title":"","organization":"Atlas"}),
    );
    assert_eq!(saved(&h, &v).title, "atlas-cloud.test");
    let v = h.call(
        json!({"op":"save_identity","ctx":"save_prompt","origin":SHOP,
        "vault_id":id(perso),"title":" Livraison ","given_name":"Sam"}),
    );
    assert_eq!(saved(&h, &v).title, "Livraison");
}

#[test]
fn save_identity_refuses_empty_and_unknown_vault() {
    let mut h = H::new();
    let perso = h.ids.perso;
    let before = h.vault().items.len();
    let empty = json!({"op":"save_identity","ctx":"save_prompt","origin":SHOP,
        "vault_id":id(perso),"title":"Vide","given_name":" ","address":{}});
    assert_eq!(err(&h.call(empty)), "invalid");
    let unknown = json!({"op":"save_identity","ctx":"save_prompt","origin":SHOP,
        "vault_id":id(Id::new()),"title":"","given_name":"Sam"});
    assert_eq!(err(&h.call(unknown)), "not_found");
    assert_eq!(h.vault().items.len(), before);
}

#[test]
fn card_and_identity_ops_locked() {
    let mut h = H::new();
    let (perso, card) = (h.ids.perso, h.ids.card);
    h.svc.vault_mut().locked = true;
    let before = h.vault().items.len();
    assert_eq!(err(&h.call(check_card(NEW_CARD, "", ""))), "locked");
    assert_eq!(
        err(&h.call(save_card(perso, NEW_CARD, "", "", None))),
        "locked"
    );
    assert_eq!(
        err(&h.call(save_card(perso, "4242424242424242", "01", "33", Some(card)))),
        "locked"
    );
    assert_eq!(
        err(&h.call(check_identity(json!({"given_name":"Sam"})))),
        "locked"
    );
    let v = json!({"op":"save_identity","ctx":"save_prompt","origin":SHOP,
        "vault_id":id(perso),"title":"","given_name":"Sam"});
    assert_eq!(err(&h.call(v)), "locked");
    assert_eq!(h.vault().items.len(), before);
    assert!(h.audit.events().is_empty());
}

// ---- Agent fill (spec 2026-11-07-agent-browser-fill 5): ctx `agent`,
// `agent_wait` and the result requests.

mod agent {
    use super::*;
    use onepass_bridge::agent::{
        AgentError, AgentHub, AgentKind, FillResult, ProbeResult, WAIT_TIMEOUT,
    };
    use onepass_bridge::api::Ctx;
    use std::sync::Arc;
    use std::thread::{self, JoinHandle};
    use std::time::{Duration, Instant};

    const LONG: Duration = Duration::from_secs(5);

    type Filler = JoinHandle<Result<FillResult, AgentError>>;

    fn with_hub() -> (H, Arc<AgentHub>) {
        let (vault, ids) = FakeVault::new();
        let audit = MemoryAudit::new();
        let hub = AgentHub::new(Arc::new(|| NOW));
        let h = H {
            svc: Service::new(vault, Box::new(audit.clone())).with_agent_hub(Arc::clone(&hub)),
            ids,
            audit,
            next: 0,
        };
        (h, hub)
    }

    fn wait() -> Value {
        json!({"op":"agent_wait"})
    }

    fn agent_fill(item: Id, origin: &str, request: Option<u64>) -> Value {
        let mut v = json!({"op":"fill_login","ctx":"agent","item_id":id(item),"origin":origin,
                           "fields":["username","password"]});
        if let Some(r) = request {
            v["agent_request"] = json!(r);
        }
        v
    }

    fn agent_card(item: Id, origin: &str, request: u64) -> Value {
        json!({"op":"fill_card","ctx":"agent","agent_request":request,"item_id":id(item),
               "origin":origin})
    }

    /// The tool probes `origin` and fills `item`, the service plays the
    /// extension (`agent_wait`, `agent_probe_result`): the ticket is issued
    /// once the fill job is in the extension's hands.
    fn ticket(
        h: &mut H,
        hub: &Arc<AgentHub>,
        item: Id,
        origin: &str,
        kind: AgentKind,
    ) -> (u64, Filler) {
        ticket_with(h, hub, item, origin, kind, false)
    }

    /// `ticket`, the tool allowing the one-time code or not.
    fn ticket_with(
        h: &mut H,
        hub: &Arc<AgentHub>,
        item: Id,
        origin: &str,
        kind: AgentKind,
        totp: bool,
    ) -> (u64, Filler) {
        // Another browser listens too, idle: the service polls first.
        assert!(hub.wait_job(hub.register(), Duration::ZERO).is_none());
        let tool = Arc::clone(hub);
        let url = format!("{origin}/login");
        let prober = thread::spawn(move || tool.probe("claude", &url, LONG));
        let v = h.call(wait());
        let job = &ok(&v)["job"];
        assert_eq!(job["job"], "probe", "{v}");
        assert_eq!(job["url"], format!("{origin}/login"));
        let request_id = job["request_id"].as_u64().unwrap();
        let v = h.call(json!({"op":"agent_probe_result","request_id":request_id,
            "result":{"ok":{"tab_title":"Atlas Cloud","origin":origin,"document_id":"doc-1"}}}));
        assert_eq!(ok(&v), &json!({}));
        let (id_back, page) = prober.join().unwrap().unwrap();
        assert_eq!(id_back, request_id);
        assert_eq!(
            page,
            ProbeResult {
                tab_title: "Atlas Cloud".into(),
                origin: origin.into(),
                document_id: "doc-1".into(),
            }
        );
        let tool = Arc::clone(hub);
        let item_id = id(item);
        let o = origin.to_owned();
        let filler = thread::spawn(move || {
            tool.fill(
                "claude", request_id, &item_id, &o, kind, true, totp, "doc-1", LONG,
            )
        });
        let v = h.call(wait());
        let want_kind = match kind {
            AgentKind::Login => "login",
            AgentKind::Card => "card",
        };
        assert_eq!(
            ok(&v)["job"],
            json!({"job":"fill","request_id":request_id,"item_id":id(item),"kind":want_kind,
                   "submit":true,"document_id":"doc-1"})
        );
        (request_id, filler)
    }

    fn finish(h: &mut H, request_id: u64, filler: Filler) -> Result<FillResult, AgentError> {
        let v = h.call(json!({"op":"agent_fill_result","request_id":request_id,
            "result":{"ok":{"filled":["username","password"],"submitted":true}}}));
        assert_eq!(ok(&v), &json!({}));
        filler.join().unwrap()
    }

    #[test]
    fn agent_ctx_fill_without_ticket_is_not_allowed() {
        let (mut h, _hub) = with_hub();
        let atlas = h.ids.atlas;
        assert_eq!(err(&h.call(agent_fill(atlas, ATLAS, None))), "not_allowed");
        assert_eq!(
            err(&h.call(agent_fill(atlas, ATLAS, Some(1)))),
            "not_allowed"
        );
        let card = h.ids.card;
        assert_eq!(err(&h.call(agent_card(card, ATLAS, 1))), "not_allowed");
        assert!(h.audit.events().is_empty());
        // Without a hub, never.
        let mut plain = H::new();
        let atlas = plain.ids.atlas;
        assert_eq!(
            err(&plain.call(agent_fill(atlas, ATLAS, Some(1)))),
            "not_allowed"
        );
    }

    #[test]
    fn agent_ctx_fill_with_ticket_returns_values_once() {
        let (mut h, hub) = with_hub();
        let atlas = h.ids.atlas;
        let (rid, filler) = ticket(&mut h, &hub, atlas, ATLAS, AgentKind::Login);
        let v = h.call(agent_fill(atlas, ATLAS, Some(rid)));
        assert_eq!(ok(&v)["username"], "alex@atlas.dev", "{v}");
        assert!(ok(&v)["password"].is_string());
        assert_eq!(
            err(&h.call(agent_fill(atlas, ATLAS, Some(rid)))),
            "not_allowed"
        );
        let events = h.audit.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].op, "fill_login");
        assert_eq!(events[0].ctx, Ctx::Agent);
        assert_eq!(events[0].item_id, Some(id(atlas)));
        let out = finish(&mut h, rid, filler).unwrap();
        assert_eq!(out.filled, vec!["username", "password"]);
        assert!(out.submitted);
    }

    /// The extension asks for the code too: an agent gets it only when the
    /// tool's ticket allows it (the `totp` scope and a fresh gesture).
    #[test]
    fn agent_ctx_fill_gives_the_code_only_when_the_ticket_allows_it() {
        let ask = |item: Id, rid: u64| {
            json!({"op":"fill_login","ctx":"agent","item_id":id(item),"origin":ATLAS,
                   "fields":["username","password","totp"],"agent_request":rid})
        };
        for allowed in [false, true] {
            let (mut h, hub) = with_hub();
            let atlas = h.ids.atlas;
            let (rid, filler) = ticket_with(&mut h, &hub, atlas, ATLAS, AgentKind::Login, allowed);
            let v = h.call(ask(atlas, rid));
            assert!(ok(&v)["password"].is_string(), "{v}");
            if allowed {
                assert_eq!(ok(&v)["totp"], expected_totp(NOW), "{v}");
            } else {
                assert!(ok(&v)["totp"].is_null(), "{v}");
            }
            finish(&mut h, rid, filler).unwrap();
        }
    }

    #[test]
    fn agent_ctx_card_ticket_is_for_a_card_only() {
        let (mut h, hub) = with_hub();
        let (atlas, card) = (h.ids.atlas, h.ids.card);
        let (rid, filler) = ticket(&mut h, &hub, card, ATLAS, AgentKind::Card);
        // Another item, or the login path for the card's ticket: refused,
        // and the ticket holds.
        assert_eq!(
            err(&h.call(agent_fill(atlas, ATLAS, Some(rid)))),
            "not_allowed"
        );
        assert_eq!(
            err(&h.call(agent_card(card, "https://evil.test", rid))),
            "not_allowed"
        );
        let v = h.call(agent_card(card, ATLAS, rid));
        assert_eq!(ok(&v)["cardholder"], "Alex Martin", "{v}");
        assert_eq!(err(&h.call(agent_card(card, ATLAS, rid))), "not_allowed");
        finish(&mut h, rid, filler).unwrap();
    }

    #[test]
    fn agent_ctx_fill_for_other_origin_is_origin_mismatch() {
        let (mut h, hub) = with_hub();
        let atlas = h.ids.atlas;
        let (rid, filler) = ticket(&mut h, &hub, atlas, ATLAS, AgentKind::Login);
        assert_eq!(
            err(&h.call(agent_fill(atlas, "https://evil.test", Some(rid)))),
            "origin_mismatch"
        );
        assert_eq!(
            err(&h.call(agent_fill(atlas, "http://atlas-cloud.test", Some(rid)))),
            "insecure_origin"
        );
        // The checks ran before the ticket: it still serves its own origin.
        ok(&h.call(agent_fill(atlas, ATLAS, Some(rid))));
        finish(&mut h, rid, filler).unwrap();
    }

    #[test]
    fn agent_ctx_is_refused_outside_fills_and_plans() {
        let (mut h, _hub) = with_hub();
        let atlas = h.ids.atlas;
        for req in [
            json!({"op":"list_for_origin","ctx":"agent","origin":ATLAS}),
            json!({"op":"totp","ctx":"agent","item_id":id(atlas),"origin":ATLAS}),
            json!({"op":"reveal","ctx":"agent","item_id":id(atlas),"field":"password"}),
            json!({"op":"search","ctx":"agent","query":""}),
            json!({"op":"fill_salt","ctx":"agent"}),
            json!({"op":"fill_identity","ctx":"agent","item_id":id(h.ids.identity),"origin":ATLAS}),
        ] {
            assert_eq!(err(&h.call(req.clone())), "not_allowed", "{req}");
        }
        // `agent_request` belongs to the agent context only.
        let mut v = fill(atlas, ATLAS);
        v["agent_request"] = json!(1);
        assert_eq!(err(&h.call(v)), "invalid");
        assert!(h.audit.events().is_empty());
    }

    #[test]
    fn agent_plan_needs_a_live_ticket_and_leaves_it() {
        let (mut h, hub) = with_hub();
        let atlas = h.ids.atlas;
        let plan = |r: Option<u64>| {
            let mut v = plan_req(ATLAS, page(ATLAS, None));
            v["ctx"] = json!("agent");
            if let Some(r) = r {
                v["agent_request"] = json!(r);
            }
            v
        };
        assert_eq!(err(&h.call(plan(None))), "not_allowed");
        assert_eq!(err(&h.call(plan(Some(1)))), "not_allowed");
        let (rid, filler) = ticket(&mut h, &hub, atlas, ATLAS, AgentKind::Login);
        let v = h.call(plan(Some(rid)));
        assert_eq!(ok(&v)["plan"]["intent"], "login", "{v}");
        // Planning did not spend the ticket.
        ok(&h.call(agent_fill(atlas, ATLAS, Some(rid))));
        assert_eq!(err(&h.call(plan(Some(rid)))), "not_allowed");
        finish(&mut h, rid, filler).unwrap();
    }

    #[test]
    fn agent_wait_on_agent_only_session_is_refused() {
        // The app bridge reads an agents-only session as locked
        // (onepass-ffi `Shared::session`): the service answers `locked` at
        // once, and the extension does not count as listening.
        let (mut h, hub) = with_hub();
        h.svc.vault_mut().locked = true;
        let start = Instant::now();
        assert_eq!(err(&h.call(wait())), "locked");
        assert!(start.elapsed() < Duration::from_secs(1));
        assert!(!hub.has_listener());
        let r = json!({"op":"agent_probe_result","request_id":1,"result":{"err":"denied"}});
        assert_eq!(err(&h.call(r)), "locked");
        let r = json!({"op":"agent_fill_result","request_id":1,"result":{"err":"denied"}});
        assert_eq!(err(&h.call(r)), "locked");
    }

    #[test]
    fn agent_ops_without_hub_are_not_allowed() {
        let mut h = H::new();
        assert_eq!(err(&h.call(wait())), "not_allowed");
        let r = json!({"op":"agent_probe_result","request_id":1,"result":{"err":"denied"}});
        assert_eq!(err(&h.call(r)), "not_allowed");
        let r = json!({"op":"agent_fill_result","request_id":1,
                       "result":{"ok":{"filled":[],"submitted":false}}});
        assert_eq!(err(&h.call(r)), "not_allowed");
    }

    #[test]
    fn agent_wait_returns_none_after_25s() {
        let (mut h, hub) = with_hub();
        let start = Instant::now();
        let v = h.call(wait());
        let waited = start.elapsed();
        assert_eq!(ok(&v), &json!({"job": null}));
        assert!(waited >= WAIT_TIMEOUT, "{waited:?}");
        assert!(waited < WAIT_TIMEOUT + Duration::from_secs(3), "{waited:?}");
        assert!(hub.has_listener());
    }

    #[test]
    fn extension_errors_reach_the_tool_as_codes() {
        let (mut h, hub) = with_hub();
        assert!(hub.wait_job(hub.register(), Duration::ZERO).is_none());
        let tool = Arc::clone(&hub);
        let prober = thread::spawn(move || tool.probe("claude", "https://atlas-cloud.test/", LONG));
        let v = h.call(wait());
        let rid = ok(&v)["job"]["request_id"].as_u64().unwrap();
        let v = h.call(json!({"op":"agent_probe_result","request_id":rid,
                              "result":{"err":"cross_site_frame"}}));
        ok(&v);
        assert_eq!(
            prober.join().unwrap().unwrap_err(),
            AgentError::CrossSiteFrame
        );

        let atlas = h.ids.atlas;
        let (rid, filler) = ticket(&mut h, &hub, atlas, ATLAS, AgentKind::Login);
        let v = h.call(json!({"op":"agent_fill_result","request_id":rid,
                              "result":{"err":"made_up_code"}}));
        ok(&v);
        assert_eq!(filler.join().unwrap().unwrap_err(), AgentError::Denied);
        // A late or unknown answer is dropped, still acknowledged.
        let v = h.call(json!({"op":"agent_fill_result","request_id":rid,
                              "result":{"ok":{"filled":["password"],"submitted":false}}}));
        ok(&v);
    }

    /// A second bridge session (another browser profile) on the same hub.
    fn second_session(hub: &Arc<AgentHub>) -> H {
        let (vault, ids) = FakeVault::new();
        let audit = MemoryAudit::new();
        H {
            svc: Service::new(vault, Box::new(audit.clone())).with_agent_hub(Arc::clone(hub)),
            ids,
            audit,
            next: 1_000,
        }
    }

    #[test]
    fn only_the_session_that_probed_gets_the_fill_and_its_ticket() {
        let (mut h, hub) = with_hub();
        let mut other = second_session(&hub);
        let atlas = h.ids.atlas;
        let (rid, filler) = ticket(&mut h, &hub, atlas, ATLAS, AgentKind::Login);
        // The other profile cannot plan, open the values, nor answer.
        let mut plan = plan_req(ATLAS, page(ATLAS, None));
        plan["ctx"] = json!("agent");
        plan["agent_request"] = json!(rid);
        assert_eq!(err(&other.call(plan.clone())), "not_allowed");
        let other_atlas = other.ids.atlas;
        assert_eq!(
            err(&other.call(agent_fill(other_atlas, ATLAS, Some(rid)))),
            "not_allowed"
        );
        let v = other.call(json!({"op":"agent_fill_result","request_id":rid,
            "result":{"ok":{"filled":["password"],"submitted":false}}}));
        ok(&v);
        assert!(other.audit.events().is_empty());
        // The owner still holds a live ticket and a waiting fill.
        ok(&h.call(plan));
        ok(&h.call(agent_fill(atlas, ATLAS, Some(rid))));
        let out = finish(&mut h, rid, filler).unwrap();
        assert_eq!(out.filled, vec!["username", "password"]);
    }

    #[test]
    fn a_session_that_declines_passes_the_probe_on() {
        let (mut h, hub) = with_hub();
        let mut other = second_session(&hub);
        // An idle listener makes the hub count as listening before the
        // sessions poll (a session that never polled is not waited for).
        let ghost = hub.listener();
        assert!(ghost.wait_job(Duration::ZERO).is_none());
        let tool = Arc::clone(&hub);
        let prober = thread::spawn(move || tool.probe("claude", "https://atlas-cloud.test/", LONG));
        // The first profile is not on the page: it declines.
        let v = h.call(wait());
        let rid = ok(&v)["job"]["request_id"].as_u64().unwrap();
        ok(&h.call(json!({"op":"agent_probe_result","request_id":rid,
                          "result":{"err":"tab_mismatch"}})));
        // The second profile gets the same probe and finds the page.
        let v = other.call(wait());
        assert_eq!(ok(&v)["job"]["request_id"].as_u64(), Some(rid), "{v}");
        drop(ghost);
        ok(
            &other.call(json!({"op":"agent_probe_result","request_id":rid,
            "result":{"ok":{"tab_title":"Atlas Cloud","origin":ATLAS,"document_id":"doc-2"}}})),
        );
        let (got, page) = prober.join().unwrap().unwrap();
        assert_eq!((got, page.document_id.as_str()), (rid, "doc-2"));
        // The fill goes to the second profile only, with its ticket.
        let tool = Arc::clone(&hub);
        let item = id(other.ids.atlas);
        let filler = thread::spawn(move || {
            tool.fill(
                "claude",
                rid,
                &item,
                ATLAS,
                AgentKind::Login,
                false,
                false,
                "doc-2",
                LONG,
            )
        });
        let v = other.call(wait());
        assert_eq!(ok(&v)["job"]["job"], "fill", "{v}");
        let atlas = other.ids.atlas;
        assert_eq!(
            err(&h.call(agent_fill(h.ids.atlas, ATLAS, Some(rid)))),
            "not_allowed"
        );
        ok(&other.call(agent_fill(atlas, ATLAS, Some(rid))));
        let v = other.call(json!({"op":"agent_fill_result","request_id":rid,
            "result":{"ok":{"filled":["username","password"],"submitted":false}}}));
        ok(&v);
        assert!(filler.join().unwrap().is_ok());
    }
}

// One gesture, one engine (2026-11-10): loopback http, child frames at the
// top origin, the sole exact host and the associated domains.

mod one_engine {
    use super::*;

    const LOCAL: &str = "http://localhost:3000";
    /// Apple's list: a2hosting.com became hosting.com (one way).
    const OLD_HOST: &str = "https://www.a2hosting.com";
    const NEW_HOST: &str = "https://my.hosting.com";
    /// Apple's list: ad.nl and dpgmedia.nl share their accounts.
    const AD: &str = "https://www.ad.nl";
    const DPG: &str = "https://login.dpgmedia.nl";

    fn reasons(plan: &Value) -> Vec<String> {
        plan["reasons"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r.as_str().unwrap().to_owned())
            .collect()
    }

    fn plan_of(h: &mut H, origin: &str) -> Value {
        ok(&h.call(plan_req(origin, page(origin, None))))["plan"].clone()
    }

    #[test]
    fn loopback_http_lists_plans_and_fills() {
        let mut h = H::new();
        let dev = h
            .svc
            .vault_mut()
            .add_login("Dev", "dev@local.test", LOCAL, MatchRule::Domain);
        // Another program on another port never gets it.
        h.svc.vault_mut().add_login(
            "Other port",
            "dev@local.test",
            "http://localhost:8080",
            MatchRule::Domain,
        );
        assert_eq!(titles(&h.call(list(LOCAL))), ["Dev"]);
        let plan = plan_of(&mut h, LOCAL);
        assert_eq!(plan["action"], "open_chain", "{plan}");
        assert_eq!(plan["groups"][0]["item_id"], id(dev), "{plan}");
        let v = h.call(fill(dev, LOCAL));
        assert_eq!(ok(&v)["username"], "dev@local.test", "{v}");
        ok(&h.call(note(dev, LOCAL)));
        assert_eq!(h.vault().item(dev).usage[0].site, "localhost");
        for (o, title) in [
            ("http://127.0.0.1:3000", "IPv4"),
            ("http://[::1]:3000", "IPv6"),
        ] {
            h.svc
                .vault_mut()
                .add_login(title, "dev@local.test", o, MatchRule::Domain);
            assert_eq!(titles(&h.call(list(o))), [title], "{o}");
        }
    }

    #[test]
    fn every_other_http_origin_stays_refused() {
        let mut h = H::new();
        let atlas = h.ids.atlas;
        for o in [
            "http://atlas-cloud.test",
            "http://app.localhost:3000",
            "http://nas.local",
            "http://192.168.1.10",
            "http://127.0.0.2",
            "http://localhost.atlas-cloud.test",
        ] {
            assert_eq!(err(&h.call(list(o))), "insecure_origin", "{o}");
            assert_eq!(err(&h.call(fill(atlas, o))), "insecure_origin", "{o}");
            assert_eq!(
                err(&h.call(plan_req(o, page(o, None)))),
                "insecure_origin",
                "{o}"
            );
        }
        // Passkeys stay https only, loopback included.
        let v =
            h.call(json!({"op":"passkey_list","ctx":"passkey","origin":LOCAL,"rp_id":"localhost"}));
        assert_eq!(err(&v), "insecure_origin");
    }

    #[test]
    fn child_frame_at_the_top_origin_plans_like_the_top() {
        let mut h = H::new();
        let mut ctx = page(ATLAS, None);
        ctx["frame_kind"] = json!("same_origin_child");
        let plan = ok(&h.call(plan_req(ATLAS, ctx.clone())))["plan"].clone();
        assert_eq!(plan["action"], "open_chain", "{plan}");
        assert!(
            !reasons(&plan).contains(&"child_frame".to_owned()),
            "{plan}"
        );
        // Under any other top document the frame is held as before.
        for top in [
            "https://evil.test",
            "https://app.atlas-cloud.test",
            "https://atlas-cloud.test:8443",
        ] {
            ctx["top_origin"] = json!(top);
            let plan = ok(&h.call(plan_req(ATLAS, ctx.clone())))["plan"].clone();
            assert_eq!(plan["action"], "fill", "{top}: {plan}");
            assert!(reasons(&plan).contains(&"child_frame".to_owned()), "{plan}");
        }
    }

    #[test]
    fn sole_exact_host_opens_the_chain_without_memory() {
        let mut h = H::new();
        let v = h.svc.vault_mut();
        let exact = v.add_login(
            "Exact",
            "a@twin.test",
            "https://app.twin.test",
            MatchRule::Domain,
        );
        let wide = v.add_login("Wide", "b@twin.test", TWIN, MatchRule::Domain);
        let plan = plan_of(&mut h, "https://app.twin.test");
        assert_eq!(plan["action"], "open_chain", "{plan}");
        assert_eq!(plan["confidence"], "high", "{plan}");
        assert_eq!(plan["groups"][0]["item_id"], id(exact), "{plan}");
        assert_eq!(plan["alternatives"], json!([id(wide)]), "{plan}");
        assert!(
            reasons(&plan).contains(&"sole_exact_host".to_owned()),
            "{plan}"
        );
        // Two exact hosts and no memory: the menu.
        h.svc.vault_mut().add_login(
            "Exact 2",
            "c@twin.test",
            "https://app.twin.test",
            MatchRule::Domain,
        );
        let plan = plan_of(&mut h, "https://app.twin.test");
        assert_eq!(plan["action"], "show_menu", "{plan}");
        assert!(
            !reasons(&plan).contains(&"sole_exact_host".to_owned()),
            "{plan}"
        );
    }

    #[test]
    fn the_tier_is_the_host_of_the_url_not_the_rule_of_the_item() {
        // The lab's account profile p3 as its fixture builds it today: two
        // logins saved on the very same URL, the page's, one with the rule
        // `exact_host` and one with `domain`. On that host a `domain` rule
        // is an exact host match too: two exact hosts, the menu.
        const APEX: &str = "https://amber-falcon-3.test";
        let mut h = H::new();
        let v = h.svc.vault_mut();
        let own = v.add_login("Amber", "a@amber.test", APEX, MatchRule::ExactHost);
        let second = v.add_login("Amber (domaine)", "b@amber.test", APEX, MatchRule::Domain);
        let listed = h.call(list(APEX));
        assert_eq!(ok(&listed)["items"][0]["match"], "exact_host", "{listed}");
        assert_eq!(ok(&listed)["items"][1]["match"], "exact_host", "{listed}");
        let plan = plan_of(&mut h, APEX);
        assert_eq!(plan["action"], "show_menu", "{plan}");
        assert!(
            !reasons(&plan).contains(&"sole_exact_host".to_owned()),
            "{plan}"
        );
        // The domain-wide login saved on another host of the domain: the
        // page's own login is the sole exact host, filled without asking.
        h.svc
            .vault_mut()
            .items
            .iter_mut()
            .find(|i| i.id == second)
            .unwrap()
            .urls[0]
            .url = "https://www.amber-falcon-3.test".into();
        let listed = h.call(list(APEX));
        assert_eq!(ok(&listed)["items"][0]["match"], "exact_host", "{listed}");
        assert_eq!(ok(&listed)["items"][1]["match"], "domain", "{listed}");
        let plan = plan_of(&mut h, APEX);
        assert_eq!(plan["action"], "open_chain", "{plan}");
        assert_eq!(plan["confidence"], "high", "{plan}");
        assert_eq!(plan["groups"][0]["item_id"], id(own), "{plan}");
        assert_eq!(plan["alternatives"], json!([id(second)]), "{plan}");
        assert!(
            reasons(&plan).contains(&"sole_exact_host".to_owned()),
            "{plan}"
        );
    }

    #[test]
    fn associated_domain_first_use_is_menu_only_then_normal() {
        let mut h = H::new();
        let old =
            h.svc
                .vault_mut()
                .add_login("Old host", "a@host.test", OLD_HOST, MatchRule::Domain);
        // Listed, as a domain match on the wire (older extensions refuse
        // an unknown `match`).
        let v = h.call(list(NEW_HOST));
        assert_eq!(titles(&v), ["Old host"]);
        assert_eq!(ok(&v)["items"][0]["match"], "domain", "{v}");
        // Next to it, for a UI that says so; a direct match has no such key.
        assert_eq!(ok(&v)["items"][0]["associated"], true, "{v}");
        let direct = h.call(list(OLD_HOST));
        assert_eq!(ok(&direct)["items"][0]["match"], "exact_host", "{direct}");
        assert!(ok(&direct)["items"][0].get("associated").is_none());
        // First use: the menu, never a fill, never a submit.
        let plan = plan_of(&mut h, NEW_HOST);
        assert_eq!(plan["action"], "show_menu", "{plan}");
        assert_eq!(plan["confidence"], "low", "{plan}");
        assert_eq!(plan["groups"][0]["item_id"], id(old), "{plan}");
        assert!(
            reasons(&plan).contains(&"associated_domain".to_owned()),
            "{plan}"
        );
        // The user picks it in the menu: the fill is served, and noted.
        let v = h.call(fill(old, NEW_HOST));
        assert_eq!(ok(&v)["username"], "a@host.test", "{v}");
        ok(&h.call(note(old, NEW_HOST)));
        // The site's memory, and the pick on this very host.
        let mut keys: Vec<&str> = h
            .vault()
            .item(old)
            .usage
            .iter()
            .map(|u| u.site.as_str())
            .collect();
        keys.sort();
        assert_eq!(keys, ["assoc:my.hosting.com", "hosting.com"]);
        // Second use: a normal match.
        let plan = plan_of(&mut h, NEW_HOST);
        assert_eq!(plan["action"], "open_chain", "{plan}");
        assert_eq!(plan["confidence"], "high", "{plan}");
        assert!(
            !reasons(&plan).contains(&"associated_domain".to_owned()),
            "{plan}"
        );
        // Forgetting the site brings the menu back.
        ok(&h.call(json!({"op":"forget_site","ctx":"popup","site":"hosting.com"})));
        assert_eq!(plan_of(&mut h, NEW_HOST)["action"], "show_menu");
    }

    #[test]
    fn the_bridge_itself_keeps_an_associated_login_behind_the_users_pick() {
        // An extension from before the associated tier reads such a row as
        // a plain domain match: nothing it does on its own gets the secret,
        // changes the item or promotes the match.
        let mut h = H::new();
        let old =
            h.svc
                .vault_mut()
                .add_login("Old host", "a@host.test", OLD_HOST, MatchRule::Domain);
        let with_ctx = |ctx: &str| {
            json!({"op":"fill_login","ctx":ctx,"item_id":id(old),"origin":NEW_HOST,
                   "fields":["username","password"]})
        };
        for ctx in ["chain", "overlay", "save_prompt"] {
            assert_eq!(err(&h.call(with_ctx(ctx))), "not_allowed", "{ctx}");
        }
        let totp = json!({"op":"totp","ctx":"chain","item_id":id(old),"origin":NEW_HOST});
        assert_eq!(err(&h.call(totp)), "not_allowed");
        let update = json!({"op":"update_password","ctx":"save_prompt","item_id":id(old),
                            "origin":NEW_HOST,"password":"Planted-Pass-0101"});
        assert_eq!(err(&h.call(update.clone())), "not_allowed");
        // A note without a served fill writes nothing and promotes nothing.
        assert_eq!(err(&h.call(note(old, NEW_HOST))), "not_allowed");
        assert!(h.vault().item(old).usage.is_empty());
        assert_eq!(plan_of(&mut h, NEW_HOST)["action"], "show_menu");
        assert!(h.audit.events().iter().all(|e| e.op == "plan_fill"));

        // The user's pick in the menu: served, and what follows it in this
        // session goes through (the next step of the chain, the save).
        ok(&h.call(with_ctx("menu")));
        ok(&h.call(with_ctx("chain")));
        ok(&h.call(update));
        // On another host of the same site the pick does not count.
        let elsewhere = json!({"op":"fill_login","ctx":"chain","item_id":id(old),
                               "origin":"https://other.hosting.com","fields":["password"]});
        assert_eq!(err(&h.call(elsewhere)), "not_allowed");
        assert_eq!(
            err(&h.call(note(old, "https://other.hosting.com"))),
            "not_allowed"
        );
        // Noted: promoted on the host of the pick only.
        ok(&h.call(note(old, NEW_HOST)));
        let v = h.call(list(NEW_HOST));
        assert!(ok(&v)["items"][0].get("associated").is_none(), "{v}");
        let v = h.call(list("https://other.hosting.com"));
        assert_eq!(ok(&v)["items"][0]["associated"], true, "{v}");
        assert_eq!(
            plan_of(&mut h, "https://other.hosting.com")["action"],
            "show_menu"
        );
    }

    #[test]
    fn a_site_memory_from_another_url_promotes_nothing() {
        // The review's case, through the bridge: an exact host URL on
        // hosting.com used there, and a domain URL on a2hosting.com.
        let mut h = H::new();
        let item = h.svc.vault_mut().add_login(
            "Two homes",
            "a@host.test",
            "https://login.hosting.com",
            MatchRule::ExactHost,
        );
        let stored = h
            .svc
            .vault_mut()
            .items
            .iter_mut()
            .find(|i| i.id == item)
            .unwrap();
        let mut second = stored.urls[0].clone();
        second.url = OLD_HOST.into();
        second.rule = MatchRule::Domain;
        second.primary = false;
        stored.urls.push(second);
        ok(&h.call(fill(item, "https://login.hosting.com")));
        ok(&h.call(note(item, "https://login.hosting.com")));
        // Elsewhere on hosting.com: not offered at all, nothing to chain.
        assert!(titles(&h.call(list("https://x.hosting.com"))).is_empty());
        assert_eq!(
            err(&h.call(fill(item, "https://x.hosting.com"))),
            "origin_mismatch"
        );
        let plan = plan_of(&mut h, "https://x.hosting.com");
        assert_eq!(plan["action"], "show_menu", "{plan}");
        assert_eq!(plan["groups"], json!([]), "{plan}");
    }

    #[test]
    fn the_sole_exact_host_of_a_shared_vault_is_not_trusted() {
        let mut h = H::new();
        // The second fixture vault is shared with other people.
        h.svc.vault_mut().vaults[1].personal = false;
        let shared = h.ids.pro;
        let v = h.svc.vault_mut();
        let planted = v.add_login_in(
            shared,
            "Planted",
            "attacker@bank.test",
            "https://login.bank.test",
            MatchRule::Domain,
        );
        let mine = v.add_login(
            "Bank",
            "me@bank.test",
            "https://bank.test",
            MatchRule::Domain,
        );
        let plan = plan_of(&mut h, "https://login.bank.test");
        // As before the sole exact host rule: the better match is put in
        // the form, nothing is sent, no sign-in starts without the user.
        assert_eq!(plan["action"], "fill", "{plan}");
        assert_eq!(plan["confidence"], "medium", "{plan}");
        assert!(
            !reasons(&plan).contains(&"sole_exact_host".to_owned()),
            "{plan}"
        );
        assert_eq!(plan["groups"][0]["item_id"], id(planted), "{plan}");
        assert_eq!(plan["alternatives"], json!([id(mine)]), "{plan}");
        // The other way round (the user's own exact host, a shared domain
        // match) keeps the rule.
        let v = h.svc.vault_mut();
        let own = v.add_login(
            "Own",
            "me@own.test",
            "https://app.own.test",
            MatchRule::Domain,
        );
        v.add_login_in(
            shared,
            "Team",
            "team@own.test",
            "https://own.test",
            MatchRule::Domain,
        );
        let plan = plan_of(&mut h, "https://app.own.test");
        assert_eq!(plan["action"], "open_chain", "{plan}");
        assert_eq!(plan["groups"][0]["item_id"], id(own), "{plan}");
        assert!(
            reasons(&plan).contains(&"sole_exact_host".to_owned()),
            "{plan}"
        );
    }

    #[test]
    fn associated_domains_keep_their_direction_and_the_item_rule() {
        let mut h = H::new();
        let v = h.svc.vault_mut();
        let new = v.add_login("New host", "a@host.test", NEW_HOST, MatchRule::Domain);
        let pinned = v.add_login("Pinned", "b@host.test", OLD_HOST, MatchRule::ExactHost);
        let ad = v.add_login("AD", "a@ad.test", AD, MatchRule::Domain);
        let dpg = v.add_login("DPG", "a@dpg.test", DPG, MatchRule::Domain);
        // `from` to `to` only: the new host's login never goes back.
        assert!(
            titles(&h.call(list(OLD_HOST)))
                .iter()
                .all(|t| t != "New host")
        );
        assert_eq!(err(&h.call(fill(new, OLD_HOST))), "origin_mismatch");
        // An exact host rule is never widened.
        assert_eq!(titles(&h.call(list(NEW_HOST))), ["New host"]);
        assert_eq!(err(&h.call(fill(pinned, NEW_HOST))), "origin_mismatch");
        assert_eq!(err(&h.call(note(pinned, NEW_HOST))), "origin_mismatch");
        // A shared group works both ways, after the direct match.
        assert_eq!(titles(&h.call(list(AD))), ["AD", "DPG"]);
        assert_eq!(titles(&h.call(list(DPG))), ["DPG", "AD"]);
        ok(&h.call(fill(ad, DPG)));
        ok(&h.call(fill(dpg, AD)));
        // The direct match stays as good as alone, the other is an
        // alternative of the menu.
        let plan = plan_of(&mut h, AD);
        assert_eq!(plan["action"], "open_chain", "{plan}");
        assert_eq!(plan["groups"][0]["item_id"], id(ad), "{plan}");
        assert_eq!(plan["alternatives"], json!([id(dpg)]), "{plan}");
        // Never over http, never to an unrelated site.
        assert_eq!(
            err(&h.call(fill(ad, "https://dpgmedia.nl.evil.test"))),
            "origin_mismatch"
        );
    }

    #[test]
    fn associated_login_is_no_owner_for_a_provider_link() {
        let mut h = H::new();
        let old =
            h.svc
                .vault_mut()
                .add_login("Old host", "a@host.test", OLD_HOST, MatchRule::Domain);
        let google = h.ids.google_perso;
        let v = h.call(
            json!({"op":"link_provider","ctx":"save_prompt","site_origin":NEW_HOST,
            "provider":"google","account_item_id":id(google)}),
        );
        // A new login of the page's site is made: the old host's is untouched.
        assert_ne!(ok(&v)["item_id"], id(old), "{v}");
        assert!(h.vault().item(old).login_methods.is_empty());
    }
}

// Several accounts on one host (the Mac app with added accounts): the
// personal vault is the primary account's, the `pro` vault another one's.
mod accounts {
    use super::*;

    const ADMIN: &str = "https://admin.atlas-cloud.test";

    fn two() -> H {
        let mut h = H::new();
        h.svc.vault_mut().two_accounts();
        h
    }

    fn accounts_of(v: &Value) -> Vec<String> {
        ok(v)["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s["account"].as_str().unwrap_or("-").to_owned())
            .collect()
    }

    fn plan_of(h: &mut H, origin: &str) -> Value {
        ok(&h.call(plan_req(origin, page(origin, None))))["plan"].clone()
    }

    fn save(vault: Id, origin: &str) -> Value {
        json!({"op":"save_login","ctx":"save_prompt","origin":origin,"title":"",
               "username":"new@atlas.dev","password":"New-Pass-0099",
               "vault_id":id(vault),"rule":"domain","tags":[]})
    }

    #[test]
    fn one_account_adds_nothing_to_the_wire() {
        let mut h = H::new();
        let v = h.call(list(ADMIN));
        for s in ok(&v)["items"].as_array().unwrap() {
            let o = s.as_object().unwrap();
            assert_eq!(o.len(), 12, "{s}");
            assert!(!o.contains_key("account") && !o.contains_key("associated"));
        }
        let v = h.call(json!({"op":"vaults"}));
        for e in ok(&v)["vaults"].as_array().unwrap() {
            assert_eq!(e.as_object().unwrap().len(), 3, "{e}");
        }
        let admin = h.ids.admin;
        ok(&h.call(fill(admin, ADMIN)));
        assert_eq!(h.audit.events().last().unwrap().account, None);
    }

    #[test]
    fn candidates_of_two_accounts_carry_their_account() {
        let mut h = two();
        // Every host routes to the primary account here: its items come
        // first, even behind a better match of the other account.
        let v = h.call(list(ADMIN));
        assert_eq!(titles(&v), ["Atlas Cloud", "Atlas admin"]);
        assert_eq!(accounts_of(&v), [PRIMARY_LABEL, WORK_LABEL]);
        assert_eq!(ok(&v)["items"][1]["match"], "exact_host");
        let v = h.call(json!({"op":"vaults"}));
        let labels: Vec<&str> = ok(&v)["vaults"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["account"].as_str().unwrap())
            .collect();
        assert_eq!(labels, [PRIMARY_LABEL, WORK_LABEL]);
        // A search has no page: no routing, both accounts labelled.
        let v = h.call(json!({"op":"search","ctx":"popup","query":"atlas admin"}));
        assert_eq!(accounts_of(&v), [WORK_LABEL]);
    }

    #[test]
    fn the_account_the_host_routes_to_ranks_first() {
        let mut h = two();
        h.svc.vault_mut().routed = WORK_KEY.to_owned();
        let v = h.call(list(ADMIN));
        assert_eq!(titles(&v), ["Atlas admin", "Atlas Cloud"]);
        assert_eq!(accounts_of(&v), [WORK_LABEL, PRIMARY_LABEL]);
        // Cards live in the primary account only: still offered.
        let v = h.call(json!({"op":"list_fillable","ctx":"menu","origin":ADMIN,"kind":"card"}));
        assert_eq!(accounts_of(&v), [PRIMARY_LABEL]);
    }

    #[test]
    fn a_plan_is_made_from_the_account_the_host_routes_to() {
        let mut h = two();
        let (atlas, admin) = (h.ids.atlas, h.ids.admin);
        // Primary: its domain match alone, as if the other account's exact
        // host login were not there (no leak from one account's choice to
        // the other's).
        let plan = plan_of(&mut h, ADMIN);
        assert_eq!(plan["groups"][0]["item_id"], id(atlas), "{plan}");
        assert_eq!(plan["alternatives"], json!([]), "{plan}");
        h.svc.vault_mut().routed = WORK_KEY.to_owned();
        let plan = plan_of(&mut h, ADMIN);
        assert_eq!(plan["groups"][0]["item_id"], id(admin), "{plan}");
        assert_eq!(plan["alternatives"], json!([]), "{plan}");
        // The routed account has nothing for the page: the other one's
        // login is planned rather than nothing.
        h.svc.vault_mut().routed = PRIMARY_KEY.to_owned();
        let pro = h.ids.pro;
        let only = h.svc.vault_mut().add_login_in(
            pro,
            "Work only",
            "alex@work.test",
            "https://work-only.test",
            MatchRule::Domain,
        );
        let plan = plan_of(&mut h, "https://work-only.test");
        assert_eq!(plan["groups"][0]["item_id"], id(only), "{plan}");
    }

    #[test]
    fn the_journal_names_the_account_of_the_item() {
        let mut h = two();
        let (atlas, admin, perso, pro) = (h.ids.atlas, h.ids.admin, h.ids.perso, h.ids.pro);
        let last = |h: &H| {
            let e = h.audit.events().last().unwrap().clone();
            (e.op, e.account)
        };
        ok(&h.call(fill(admin, ADMIN)));
        assert_eq!(last(&h), ("fill_login", Some(WORK_KEY.to_owned())));
        ok(&h.call(fill(atlas, ATLAS)));
        assert_eq!(last(&h), ("fill_login", Some(PRIMARY_KEY.to_owned())));
        // A new login is journaled under the account of its vault.
        ok(&h.call(save(pro, "https://new-work.test")));
        assert_eq!(last(&h), ("save_login", Some(WORK_KEY.to_owned())));
        ok(&h.call(save(perso, "https://new-home.test")));
        assert_eq!(last(&h), ("save_login", Some(PRIMARY_KEY.to_owned())));
        // A plan spans the accounts: no account.
        plan_of(&mut h, ATLAS);
        assert_eq!(last(&h), ("plan_fill", None));
        // A passkey made in a vault that holds nothing yet: its account.
        let empty = Id::new();
        let mut info = h.vault().vaults[1].clone();
        info.id = empty;
        h.svc.vault_mut().vaults.push(info);
        let v = h.call(
            json!({"op":"passkey_create","ctx":"passkey","origin":"https://pk.test",
            "top_origin":"https://pk.test","rp_id":"pk.test","user_name":"alex",
            "user_handle":"dXNlcg","challenge":"Y2hhbGxlbmdl","exclude":[],
            "vault_id":id(empty)}),
        );
        ok(&v);
        assert_eq!(last(&h), ("passkey_create", Some(WORK_KEY.to_owned())));
        // One account again (the other locked): the journal names none.
        for v in &mut h.svc.vault_mut().vaults {
            v.account = None;
        }
        ok(&h.call(fill(atlas, ATLAS)));
        assert_eq!(last(&h), ("fill_login", None));
    }

    #[test]
    fn a_provider_link_stays_in_the_account_of_the_provider_login() {
        let mut h = two();
        let (atlas, google_pro, pro) = (h.ids.atlas, h.ids.google_pro, h.ids.pro);
        // The site's login is the primary account's, the Google login the
        // other one's: the first is left alone, a login is made beside the
        // second.
        let v = h.call(
            json!({"op":"link_provider","ctx":"save_prompt","site_origin":ATLAS,
                              "provider":"google","account_item_id":id(google_pro)}),
        );
        let made: Id = ok(&v)["item_id"].as_str().unwrap().parse().unwrap();
        assert_ne!(made, atlas);
        assert!(h.vault().item(atlas).login_methods.is_empty());
        assert_eq!(h.vault().item(made).vault_id, pro);
        assert_eq!(
            h.audit.events().last().unwrap().account.as_deref(),
            Some(WORK_KEY)
        );
    }

    #[test]
    fn a_new_item_defaults_to_the_account_the_page_routes_to() {
        let mut h = two();
        let (perso, pro) = (h.ids.perso, h.ids.pro);
        let vault_of = |h: &H, v: &Value| {
            let made: Id = ok(v)["item_id"].as_str().unwrap().parse().unwrap();
            h.vault().item(made).vault_id
        };
        let unnamed = |origin: &str| {
            json!({"op":"save_login","ctx":"save_prompt","origin":origin,"title":"",
                   "username":"new@atlas.dev","password":"New-Pass-0099",
                   "vault_id":"","rule":"domain","tags":[]})
        };
        let passkey = |origin: &str, rp: &str| {
            json!({"op":"passkey_create","ctx":"passkey","origin":origin,"top_origin":origin,
                   "rp_id":rp,"user_name":"alex","user_handle":"dXNlcg",
                   "challenge":"Y2hhbGxlbmdl","exclude":[]})
        };
        let first_vault = |h: &mut H, origin: Option<&str>| {
            let mut req = json!({"op":"vaults"});
            if let Some(o) = origin {
                req["origin"] = json!(o);
            }
            ok(&h.call(req))["vaults"][0]["id"].clone()
        };
        // The primary account claims every host here.
        let v = h.call(unnamed("https://home-a.test"));
        assert_eq!(vault_of(&h, &v), perso);
        let v = h.call(passkey("https://home-b.test", "home-b.test"));
        assert_eq!(vault_of(&h, &v), perso);
        assert_eq!(first_vault(&mut h, Some("https://home-a.test")), id(perso));
        // The added account claims the host: new logins and passkeys land
        // there, and the vault list of that page starts with its vault.
        h.svc.vault_mut().routed = WORK_KEY.to_owned();
        let v = h.call(unnamed("https://work-a.test"));
        assert_eq!(vault_of(&h, &v), pro);
        assert_eq!(
            h.audit.events().last().unwrap().account.as_deref(),
            Some(WORK_KEY)
        );
        let v = h.call(passkey("https://work-b.test", "work-b.test"));
        assert_eq!(vault_of(&h, &v), pro);
        assert_eq!(first_vault(&mut h, Some("https://work-a.test")), id(pro));
        // Without a page the list is the plain one, and a vault the user
        // names is the user's choice.
        assert_eq!(first_vault(&mut h, None), id(perso));
        let v = h.call(save(perso, "https://work-c.test"));
        assert_eq!(vault_of(&h, &v), perso);
        assert_eq!(
            err(&h.call(json!({"op":"vaults","origin":"http://x.test"}))),
            "insecure_origin"
        );
    }

    #[test]
    fn an_update_stays_in_the_account_of_its_item() {
        let mut h = two();
        let (admin, pro) = (h.ids.admin, h.ids.pro);
        let v = h.call(
            json!({"op":"update_password","ctx":"save_prompt","item_id":id(admin),
                              "origin":ADMIN,"password":"Rotated-Pass-0100"}),
        );
        ok(&v);
        assert_eq!(h.vault().item(admin).vault_id, pro);
        assert_eq!(
            h.audit.events().last().unwrap().account.as_deref(),
            Some(WORK_KEY)
        );
    }
}

// What the host is told beside the journal: who asks to unlock and for
// which page, which page a confirmation is for, and each secret served.
mod host_signals {
    use super::*;

    #[test]
    fn unlock_carries_the_checked_origin_host() {
        let mut h = H::new();
        h.svc.vault_mut().locked = true;
        // An older extension: no origin.
        ok(&h.call(json!({"op":"unlock"})));
        h.svc.vault_mut().locked = true;
        ok(&h.call(json!({"op":"unlock","origin":"https://App.Atlas-Cloud.test/login?x=1"})));
        h.svc.vault_mut().locked = true;
        ok(&h.call(json!({"op":"unlock","origin":"http://localhost:3000"})));
        assert_eq!(
            h.vault().unlocks,
            [
                None,
                Some("app.atlas-cloud.test".to_owned()),
                Some("localhost".to_owned())
            ]
        );
        // An origin that is no page of ours asks nothing of the user.
        for bad in [
            "http://atlas-cloud.test",
            "javascript:alert(1)",
            "atlas-cloud.test",
            "",
        ] {
            let v = h.call(json!({"op":"unlock","origin":bad}));
            assert!(v.get("err").is_some(), "{bad}: {v}");
        }
        assert_eq!(h.vault().unlocks.len(), 3);
    }

    #[test]
    fn a_confirmation_names_the_page_of_the_request() {
        let mut h = H::new();
        let r = h.ids.reprompt;
        let origin = "https://vault.atlas-cloud.test";
        assert_eq!(err(&h.call(fill(r, origin))), "reprompt_required");
        let v = h.call(json!({"op":"reveal","ctx":"popup","item_id":id(r),"field":"password"}));
        assert_eq!(err(&v), "reprompt_required");
        let v = h.call(json!({"op":"totp","ctx":"popup","item_id":id(r)}));
        assert_eq!(err(&v), "reprompt_required");
        assert_eq!(
            h.vault().reprompts,
            [
                (r, Some("vault.atlas-cloud.test".to_owned())),
                (r, None),
                (r, None)
            ]
        );
    }

    #[test]
    fn each_served_secret_is_told_once_and_nothing_else_is() {
        let mut h = H::new();
        let (atlas, card, identity) = (h.ids.atlas, h.ids.card, h.ids.identity);
        let r = h.ids.reprompt;
        // Nothing here serves a secret: lists, plans, notes, saves, a
        // refused fill, a status.
        ok(&h.call(list(ATLAS)));
        ok(&h.call(plan_req(ATLAS, page(ATLAS, None))));
        ok(&h.call(json!({"op":"status"})));
        assert_eq!(
            err(&h.call(fill(atlas, "https://evil.test"))),
            "origin_mismatch"
        );
        assert_eq!(
            err(&h.call(fill(r, "https://vault.atlas-cloud.test"))),
            "reprompt_required"
        );
        let perso = h.ids.perso;
        ok(&h.call(
            json!({"op":"save_login","ctx":"save_prompt","origin":"https://new.test",
            "title":"","username":"a@new.test","password":"New-Pass-0102",
            "vault_id":id(perso),"rule":"domain","tags":[]}),
        ));
        assert!(h.vault().served.is_empty(), "{:?}", h.vault().served);

        ok(&h.call(fill(atlas, ATLAS)));
        ok(&h.call(note(atlas, ATLAS)));
        ok(&h.call(json!({"op":"totp","ctx":"popup","item_id":id(atlas)})));
        ok(&h.call(json!({"op":"reveal","ctx":"popup","item_id":id(atlas),"field":"password"})));
        ok(&h.call(json!({"op":"fill_card","ctx":"menu","item_id":id(card),"origin":ATLAS})));
        ok(&h.call(
            json!({"op":"fill_identity","ctx":"menu","item_id":id(identity),
                          "origin":ATLAS}),
        ));
        assert_eq!(
            h.vault().served,
            [
                ("fill_login", atlas, None),
                ("totp", atlas, None),
                ("reveal", atlas, None),
                ("fill_card", card, None),
                ("fill_identity", identity, None)
            ]
        );
        // As many as the journal's lines for a served secret.
        let journal: Vec<&str> = h
            .audit
            .events()
            .iter()
            .map(|e| e.op)
            .filter(|op| op.starts_with("fill_") || matches!(*op, "totp" | "reveal"))
            .collect();
        assert_eq!(journal.len(), h.vault().served.len());
    }

    #[test]
    fn a_served_secret_names_the_account_of_its_item() {
        let mut h = H::new();
        h.svc.vault_mut().two_accounts();
        let admin = h.ids.admin;
        ok(&h.call(fill(admin, "https://admin.atlas-cloud.test")));
        assert_eq!(
            h.vault().served,
            [("fill_login", admin, Some(WORK_KEY.to_owned()))]
        );
    }
}

// ---- undo_save (spec 2026-11-11 4.1) ----

fn save_fresh(h: &mut H, now: u64) -> String {
    let perso = h.ids.perso;
    let v = h.call_at(
        json!({"op":"save_login","ctx":"save_prompt","origin":"https://newsite.atlas-cloud.test",
            "title":"","username":"fresh@atlas.dev","password":"Fresh-Pass-0042",
            "vault_id":id(perso),"rule":"domain","tags":[]}),
        now,
    );
    ok(&v)["item_id"].as_str().unwrap().to_owned()
}

fn undo(item: &str, origin: &str) -> Value {
    json!({"op":"undo_save","ctx":"save_prompt","item_id":item,"origin":origin})
}

const NEWSITE: &str = "https://newsite.atlas-cloud.test";

#[test]
fn undo_save_deletes_a_fresh_save() {
    let mut h = H::new();
    let item = save_fresh(&mut h, NOW);
    let v = h.call_at(undo(&item, NEWSITE), NOW + 60);
    assert_eq!(ok(&v), &json!({}));
    assert!(h.vault().items.iter().all(|i| i.id.to_string() != item));
    let v = h.call(list(NEWSITE));
    assert!(titles(&v).iter().all(|t| !t.contains("newsite")), "{v}");
    // Used once: a second undo finds nothing.
    assert_eq!(err(&h.call_at(undo(&item, NEWSITE), NOW + 61)), "not_found");
}

#[test]
fn undo_save_refuses_after_60_s() {
    let mut h = H::new();
    let item = save_fresh(&mut h, NOW);
    assert_eq!(err(&h.call_at(undo(&item, NEWSITE), NOW + 61)), "not_found");
    assert!(h.vault().items.iter().any(|i| i.id.to_string() == item));
}

#[test]
fn undo_save_refuses_other_site() {
    let mut h = H::new();
    let item = save_fresh(&mut h, NOW);
    assert_eq!(
        err(&h.call_at(undo(&item, "https://evil.test"), NOW + 5)),
        "not_found"
    );
    assert!(h.vault().items.iter().any(|i| i.id.to_string() == item));
    // Another subdomain of the same registrable domain is the same site.
    let v = h.call_at(undo(&item, "https://login.atlas-cloud.test"), NOW + 5);
    assert_eq!(ok(&v), &json!({}));
}

#[test]
fn undo_refuses_an_edited_item() {
    let mut h = H::new();
    let item = save_fresh(&mut h, NOW);
    let v = h.call_at(
        json!({"op":"update_password","ctx":"save_prompt","item_id":item,"origin":NEWSITE,
               "password":"Changed-Pass-7788"}),
        NOW + 10,
    );
    assert!(v.get("error").is_none(), "{v}");
    assert_eq!(err(&h.call_at(undo(&item, NEWSITE), NOW + 20)), "not_found");
    assert!(h.vault().items.iter().any(|i| i.id.to_string() == item));
}

#[test]
fn undo_save_refuses_an_item_it_did_not_save() {
    let mut h = H::new();
    let other = h.svc.vault_mut().add_login(
        "Direct",
        "d@atlas.dev",
        "https://direct.atlas-cloud.test",
        MatchRule::Domain,
    );
    let v = h.call(undo(&id(other), "https://direct.atlas-cloud.test"));
    assert_eq!(err(&v), "not_found");
    assert!(h.vault().items.iter().any(|i| i.id == other));
}

#[test]
fn vaults_marks_shared() {
    let mut h = H::new();
    let pro = h.ids.pro;
    for v in &mut h.svc.vault_mut().vaults {
        v.shared = v.id == pro;
    }
    let v = h.call(json!({"op":"vaults"}));
    for e in ok(&v)["vaults"].as_array().unwrap() {
        if e["id"] == id(pro) {
            assert_eq!(e["shared"], json!(true), "{e}");
        } else {
            assert!(e.get("shared").is_none(), "{e}");
        }
    }
}
