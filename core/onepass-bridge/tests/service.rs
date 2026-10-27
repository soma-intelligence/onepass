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
    assert_eq!(events[0].item_id, id(atlas));
    assert_eq!(events[0].origin.as_deref(), Some(ATLAS));
    assert_eq!(events[0].at, NOW);
    assert_eq!(events[3].item_id, id(card));
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
    assert_eq!(smart.chars().count(), 20);
    assert!(smart.chars().any(|c| !c.is_ascii_alphanumeric()));
    assert!(ok(&v)["entropy_bits"].as_f64().unwrap() > 100.0);
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
