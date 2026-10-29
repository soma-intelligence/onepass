//! Reference plans, one per intent of spec 8.1, plus the review focus cases.

use std::collections::HashMap;
use std::time::Instant;

use onepass_core::Id;
use onepass_core::fill_plan::context::{
    ButtonClass, ButtonContext, ContextError, FieldContext, FieldRole, FormContext, FrameKind,
    IntentHints, PageContext, Prefilled,
};
use onepass_core::fill_plan::intent::Intent;
use onepass_core::fill_plan::score::{
    Candidate, CandidateKind, Confidence, MatchQuality, UsageSignal,
};
use onepass_core::fill_plan::{
    Action, FillPlan, GroupItem, GroupKind, PlanGroup, Pool, ReasonCode, plan,
};

const NOW: i64 = 1_800_000_000;

fn id(n: u8) -> Id {
    Id([n; 16])
}

fn hints() -> IntentHints {
    IntentHints {
        kind: None,
        signup_words: false,
        reset_words: false,
        checkout_words: false,
        ignore: false,
    }
}

fn field(r: &str, role: FieldRole) -> FieldContext {
    FieldContext {
        field_ref: r.into(),
        role: Some(role),
        confidence: 0.9,
        visible: true,
        prefilled: Prefilled::Empty,
    }
}

fn button(r: &str, class: ButtonClass) -> ButtonContext {
    ButtonContext {
        button_ref: r.into(),
        class,
    }
}

fn form(r: &str, fields: Vec<FieldContext>, buttons: Vec<ButtonContext>) -> FormContext {
    FormContext {
        form_ref: r.into(),
        intent_hints: hints(),
        step_index: None,
        fields,
        buttons,
    }
}

fn page_at(top: &str, forms: Vec<FormContext>) -> PageContext {
    PageContext {
        origin: top.into(),
        top_origin: top.into(),
        frame_kind: FrameKind::Top,
        forms,
        typed_username_hash: None,
    }
}

fn page(forms: Vec<FormContext>) -> PageContext {
    page_at("https://example.com", forms)
}

fn cand(n: u8, kind: CandidateKind, quality: MatchQuality) -> Candidate {
    Candidate {
        item_id: id(n),
        kind,
        quality,
        favorite: false,
        updated_at: 0,
        title: format!("t{n}"),
        username_hash: None,
        usage: None,
    }
}

fn login(n: u8) -> Candidate {
    cand(n, CandidateKind::Login, MatchQuality::Exact)
}

fn card(n: u8) -> Candidate {
    cand(n, CandidateKind::Card, MatchQuality::Other)
}

fn identity(n: u8) -> Candidate {
    cand(n, CandidateKind::Identity, MatchQuality::Other)
}

fn last_here() -> Option<UsageSignal> {
    Some(UsageSignal {
        last_on_site: true,
        same_shape: false,
        count: 1,
        last_at: NOW,
    })
}

fn pool() -> Pool {
    Pool {
        logins: vec![],
        cards: vec![],
        identities: vec![],
        identity_country: HashMap::new(),
        default_card: None,
        now: NOW,
    }
}

fn logins(v: Vec<Candidate>) -> Pool {
    Pool {
        logins: v,
        ..pool()
    }
}

fn login_form() -> FormContext {
    form(
        "login",
        vec![
            field("user", FieldRole::Username),
            field("pass", FieldRole::CurrentPassword),
        ],
        vec![button("go", ButtonClass::Submit)],
    )
}

fn group(p: &FillPlan, kind: GroupKind) -> &PlanGroup {
    p.groups
        .iter()
        .find(|g| g.kind == kind)
        .unwrap_or_else(|| panic!("no {kind:?} group in {p:?}"))
}

fn refs(g: &PlanGroup) -> Vec<&str> {
    g.fields.iter().map(|(r, _)| r.as_str()).collect()
}

// Spec 8.1, Login.

#[test]
fn login_single_account_opens_chain() {
    let p = plan(&page(vec![login_form()]), logins(vec![login(1)])).unwrap();
    assert_eq!(p.intent, Intent::Login);
    assert_eq!(p.action, Action::OpenChain);
    assert_eq!(p.confidence, Confidence::High);
    assert_eq!(p.groups.len(), 1);
    let g = &p.groups[0];
    assert_eq!(g.form_ref, "login");
    assert_eq!(g.item, GroupItem::Item(id(1)));
    assert_eq!(g.kind, GroupKind::Login);
    assert_eq!(
        g.fields,
        vec![
            ("user".to_string(), FieldRole::Username),
            ("pass".to_string(), FieldRole::CurrentPassword),
        ]
    );
    assert!(p.alternatives.is_empty());
    assert!(p.reasons.contains(&ReasonCode::SingleCandidate));
}

#[test]
fn login_tie_shows_menu() {
    let p = plan(
        &page(vec![login_form()]),
        logins(vec![login(1), login(2), login(3)]),
    )
    .unwrap();
    assert_eq!(p.action, Action::ShowMenu);
    assert_eq!(p.confidence, Confidence::Low);
    assert_eq!(p.alternatives.len(), 2);
    assert!(p.reasons.contains(&ReasonCode::Tie));
}

#[test]
fn login_medium_fills_without_submit() {
    // Exact beats Domain by 40 points but without memory: Medium.
    let p = plan(
        &page(vec![login_form()]),
        logins(vec![
            cand(2, CandidateKind::Login, MatchQuality::Domain),
            login(1),
        ]),
    )
    .unwrap();
    assert_eq!(p.confidence, Confidence::Medium);
    assert_eq!(p.action, Action::Fill);
    assert_eq!(p.groups[0].item, GroupItem::Item(id(1)));
    assert_eq!(p.alternatives, vec![id(2)]);
}

#[test]
fn login_remembered_account_opens_chain_among_several() {
    let mut a = login(1);
    let mut b = login(2);
    b.usage = last_here();
    a.favorite = true;
    let p = plan(&page(vec![login_form()]), logins(vec![a, b])).unwrap();
    assert_eq!(p.confidence, Confidence::High);
    assert_eq!(p.action, Action::OpenChain);
    assert_eq!(p.groups[0].item, GroupItem::Item(id(2)));
    assert!(p.reasons.contains(&ReasonCode::LastOnSite));
}

#[test]
fn login_typed_username_picks_its_account() {
    let hash = [9u8; 32];
    let mut ctx = page(vec![login_form()]);
    ctx.typed_username_hash = Some(hash);
    let mut b = login(2);
    b.username_hash = Some(hash);
    let p = plan(&ctx, logins(vec![login(1), b])).unwrap();
    assert_eq!(p.groups[0].item, GroupItem::Item(id(2)));
    assert_eq!(p.confidence, Confidence::High);
    assert!(p.reasons.contains(&ReasonCode::TypedUsername));
}

#[test]
fn login_in_child_frame_never_submits() {
    let mut ctx = page(vec![login_form()]);
    ctx.frame_kind = FrameKind::SameOriginChild;
    let p = plan(&ctx, logins(vec![login(1)])).unwrap();
    assert_eq!(p.confidence, Confidence::High);
    assert_eq!(p.action, Action::Fill);
    assert!(p.reasons.contains(&ReasonCode::ChildFrame));
}

#[test]
fn login_form_with_pay_button_never_submits() {
    let mut f = login_form();
    f.buttons.push(button("pay", ButtonClass::Pay));
    let p = plan(&page(vec![f]), logins(vec![login(1)])).unwrap();
    assert_eq!(p.confidence, Confidence::High);
    assert_eq!(p.action, Action::Fill);
    assert!(p.reasons.contains(&ReasonCode::PayButton));
}

#[test]
fn login_form_with_create_button_never_submits() {
    let mut f = login_form();
    f.buttons.push(button("new", ButtonClass::Create));
    let p = plan(&page(vec![f]), logins(vec![login(1)])).unwrap();
    assert_eq!(p.action, Action::Fill);
    assert!(p.reasons.contains(&ReasonCode::CreateButton));
}

#[test]
fn login_weak_roles_fill_without_submit() {
    let mut f = login_form();
    f.fields[1].confidence = 0.5;
    let p = plan(&page(vec![f]), logins(vec![login(1)])).unwrap();
    assert_eq!(p.confidence, Confidence::Medium);
    assert_eq!(p.action, Action::Fill);
    assert!(p.reasons.contains(&ReasonCode::WeakRoles));
}

#[test]
fn login_skips_hidden_and_typed_fields() {
    let mut f = login_form();
    f.fields[0].prefilled = Prefilled::Typed;
    let mut hidden = field("trap", FieldRole::CurrentPassword);
    hidden.visible = false;
    f.fields.push(hidden);
    let p = plan(&page(vec![f]), logins(vec![login(1)])).unwrap();
    assert_eq!(refs(&p.groups[0]), ["pass"]);
}

#[test]
fn login_with_empty_vault_shows_menu() {
    let p = plan(&page(vec![login_form()]), pool()).unwrap();
    assert_eq!(p.action, Action::ShowMenu);
    assert!(p.groups.is_empty());
    assert!(p.reasons.contains(&ReasonCode::NoCandidate));
}

// Spec 8.1, Otp alone.

#[test]
fn otp_alone_uses_last_on_site_item() {
    let mut b = login(2);
    b.usage = last_here();
    let ctx = page(vec![form(
        "code",
        vec![field("otp", FieldRole::Otp)],
        vec![button("go", ButtonClass::Submit)],
    )]);
    let p = plan(&ctx, logins(vec![login(1), b])).unwrap();
    assert_eq!(p.intent, Intent::Otp);
    assert_eq!(p.action, Action::FillAndSubmit);
    assert_eq!(p.confidence, Confidence::High);
    assert_eq!(p.groups.len(), 1);
    assert_eq!(p.groups[0].item, GroupItem::Item(id(2)));
    assert_eq!(p.groups[0].kind, GroupKind::Login);
    assert_eq!(refs(&p.groups[0]), ["otp"]);
    assert!(p.reasons.contains(&ReasonCode::LastOnSite));
}

#[test]
fn otp_without_site_memory_only_fills() {
    let ctx = page(vec![form(
        "code",
        vec![field("otp", FieldRole::Otp)],
        vec![button("go", ButtonClass::Submit)],
    )]);
    let p = plan(&ctx, logins(vec![login(1)])).unwrap();
    assert_eq!(p.confidence, Confidence::High);
    assert_eq!(p.action, Action::Fill);
}

#[test]
fn two_login_forms_never_submit() {
    let mut second = login_form();
    second.form_ref = "login2".into();
    second.fields[0].field_ref = "user2".into();
    second.fields[1].field_ref = "pass2".into();
    let p = plan(&page(vec![login_form(), second]), logins(vec![login(1)])).unwrap();
    assert_eq!(p.confidence, Confidence::High);
    assert_eq!(p.groups.len(), 2);
    assert_eq!(p.action, Action::Fill);
    assert!(p.reasons.contains(&ReasonCode::MultipleForms));
}

#[test]
fn otp_in_child_frame_fills_without_submit() {
    let mut ctx = page(vec![form(
        "code",
        vec![field("otp", FieldRole::Otp)],
        vec![],
    )]);
    ctx.frame_kind = FrameKind::SameOriginChild;
    let p = plan(&ctx, logins(vec![login(1)])).unwrap();
    assert_eq!(p.action, Action::Fill);
    assert!(p.reasons.contains(&ReasonCode::ChildFrame));
}

// Spec 8.1, Signup.

#[test]
fn signup_fills_identity_and_generated_never_submits() {
    let f = form(
        "signup",
        vec![
            field("first", FieldRole::GivenName),
            field("mail", FieldRole::Email),
            field("pw", FieldRole::NewPassword),
            field("pw2", FieldRole::ConfirmPassword),
        ],
        vec![button("create", ButtonClass::Create)],
    );
    let pl = Pool {
        identities: vec![identity(5)],
        ..pool()
    };
    let p = plan(&page(vec![f]), pl).unwrap();
    assert_eq!(p.intent, Intent::Signup);
    assert_eq!(p.action, Action::Fill);
    let ident = group(&p, GroupKind::Identity);
    assert_eq!(ident.item, GroupItem::Item(id(5)));
    assert_eq!(refs(ident), ["first", "mail"]);
    let gen_group = group(&p, GroupKind::GeneratedPassword);
    assert_eq!(gen_group.item, GroupItem::GeneratedPassword);
    assert_eq!(refs(gen_group), ["pw", "pw2"]);
}

// Spec 8.1, Reset.

#[test]
fn reset_fills_current_and_generated() {
    let f = form(
        "reset",
        vec![
            field("old", FieldRole::CurrentPassword),
            field("new", FieldRole::NewPassword),
            field("new2", FieldRole::NewPassword),
        ],
        vec![button("save", ButtonClass::Submit)],
    );
    let p = plan(&page(vec![f]), logins(vec![login(1)])).unwrap();
    assert_eq!(p.intent, Intent::Reset);
    assert_eq!(p.action, Action::Fill);
    let lg = group(&p, GroupKind::Login);
    assert_eq!(lg.item, GroupItem::Item(id(1)));
    assert_eq!(refs(lg), ["old"]);
    let gen_group = group(&p, GroupKind::GeneratedPassword);
    assert_eq!(gen_group.item, GroupItem::GeneratedPassword);
    assert_eq!(refs(gen_group), ["new", "new2"]);
}

// Spec 8.1, Checkout.

fn checkout_form() -> FormContext {
    form(
        "pay",
        vec![
            field("num", FieldRole::CcNumber),
            field("exp", FieldRole::CcExp),
            field("csc", FieldRole::CcCsc),
            field("name", FieldRole::FullName),
            field("mail", FieldRole::Email),
            field("zip", FieldRole::PostalCode),
        ],
        vec![button("buy", ButtonClass::Pay)],
    )
}

fn checkout_pool() -> Pool {
    let mut identity_country = HashMap::new();
    identity_country.insert(id(20), "US".to_string());
    identity_country.insert(id(21), "FR".to_string());
    Pool {
        cards: vec![card(10), card(11), card(12)],
        identities: vec![identity(20), identity(21)],
        identity_country,
        default_card: Some(id(11)),
        ..pool()
    }
}

#[test]
fn checkout_mixes_card_identity_email() {
    // No memory: default card, identity whose country is the TLD.
    let ctx = page_at("https://boutique.fr", vec![checkout_form()]);
    let p = plan(&ctx, checkout_pool()).unwrap();
    assert_eq!(p.intent, Intent::Checkout);
    assert_eq!(p.action, Action::Fill);
    let c = group(&p, GroupKind::Card);
    assert_eq!(c.item, GroupItem::Item(id(11)));
    assert_eq!(refs(c), ["num", "exp", "csc"]);
    let i = group(&p, GroupKind::Identity);
    assert_eq!(i.item, GroupItem::Item(id(21)));
    assert_eq!(refs(i), ["name", "mail", "zip"]);
    assert!(!p.alternatives.contains(&id(11)));

    // The card used here last time wins over the default one.
    let mut pl = checkout_pool();
    pl.cards[2].usage = last_here();
    let p = plan(&ctx, pl).unwrap();
    assert_eq!(group(&p, GroupKind::Card).item, GroupItem::Item(id(12)));

    // No country match: first identity.
    let ctx = page_at("https://shop.de", vec![checkout_form()]);
    let p = plan(&ctx, checkout_pool()).unwrap();
    assert_eq!(group(&p, GroupKind::Identity).item, GroupItem::Item(id(20)));
}

#[test]
fn checkout_never_submits_even_with_one_card() {
    let pl = Pool {
        cards: vec![card(10)],
        identities: vec![identity(20)],
        ..pool()
    };
    let p = plan(&page(vec![checkout_form()]), pl).unwrap();
    assert_eq!(p.confidence, Confidence::High);
    assert_eq!(p.action, Action::Fill);
}

// Spec 8.1, Address.

#[test]
fn address_fills_identity_only() {
    let f = form(
        "ship",
        vec![
            field("name", FieldRole::FullName),
            field("street", FieldRole::AddressLine1),
            field("city", FieldRole::City),
        ],
        vec![button("go", ButtonClass::Submit)],
    );
    let pl = Pool {
        identities: vec![identity(20)],
        cards: vec![card(10)],
        logins: vec![login(1)],
        ..pool()
    };
    let p = plan(&page(vec![f]), pl).unwrap();
    assert_eq!(p.intent, Intent::Address);
    assert_eq!(p.action, Action::Fill);
    assert_eq!(p.groups.len(), 1);
    assert_eq!(p.groups[0].kind, GroupKind::Identity);
    assert_eq!(p.groups[0].item, GroupItem::Item(id(20)));
    assert_eq!(refs(&p.groups[0]), ["name", "street", "city"]);
}

// Spec 8.1, Ignore.

#[test]
fn ignore_form_is_nothing() {
    let mut f = login_form();
    f.intent_hints.ignore = true;
    let p = plan(&page(vec![f]), logins(vec![login(1)])).unwrap();
    assert_eq!(p.intent, Intent::Ignore);
    assert_eq!(p.action, Action::Nothing);
    assert!(p.groups.is_empty());
    assert!(p.reasons.contains(&ReasonCode::IgnoredForm));
}

// Review focus.

#[test]
fn only_login_form_is_planned_beside_search_form() {
    let mut search = form("search", vec![field("q", FieldRole::Username)], vec![]);
    search.intent_hints.ignore = true;
    let p = plan(&page(vec![search, login_form()]), logins(vec![login(1)])).unwrap();
    assert_eq!(p.intent, Intent::Login);
    assert!(!p.groups.is_empty());
    assert!(p.groups.iter().all(|g| g.form_ref != "search"));
}

#[test]
fn login_outranks_address_on_one_page() {
    let addr = form("news", vec![field("city", FieldRole::City)], vec![]);
    let p = plan(
        &page(vec![addr, login_form()]),
        Pool {
            logins: vec![login(1)],
            identities: vec![identity(20)],
            ..pool()
        },
    )
    .unwrap();
    assert_eq!(p.intent, Intent::Login);
    assert!(p.groups.iter().all(|g| g.form_ref == "login"));
}

#[test]
fn checkout_with_empty_vault_shows_menu_without_groups() {
    let p = plan(&page(vec![checkout_form()]), pool()).unwrap();
    assert_eq!(p.intent, Intent::Checkout);
    assert_eq!(p.action, Action::ShowMenu);
    assert!(p.groups.is_empty());
}

#[test]
fn hostile_context_is_invalid() {
    let f = form(
        "f",
        vec![
            field("a", FieldRole::Username),
            field("a", FieldRole::CurrentPassword),
        ],
        vec![],
    );
    assert_eq!(
        plan(&page(vec![f]), logins(vec![login(1)])).unwrap_err(),
        ContextError::DuplicateRef
    );
}

#[test]
fn plan_serializes_as_snake_case_without_values() {
    let p = plan(&page(vec![login_form()]), logins(vec![login(1)])).unwrap();
    let json = serde_json::to_string(&p).unwrap();
    assert!(json.contains("\"action\":\"open_chain\""), "{json}");
    assert!(json.contains("\"intent\":\"login\""), "{json}");
    assert!(json.contains("\"current_password\""), "{json}");
    assert!(!json.contains("t1"), "titles must not leak: {json}");
}

// Performance.

#[test]
#[ignore]
fn plan_500_items_under_20ms() {
    let pl = || Pool {
        logins: (0..500u16)
            .map(|i| {
                let mut c = login((i % 250) as u8);
                c.item_id = Id([
                    (i >> 8) as u8,
                    i as u8,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    1,
                ]);
                c.updated_at = i64::from(i);
                c.favorite = i % 7 == 0;
                c
            })
            .collect(),
        cards: (0..20).map(card).collect(),
        identities: (30..40).map(identity).collect(),
        default_card: Some(id(3)),
        ..pool()
    };
    let roles = [
        FieldRole::CcName,
        FieldRole::CcNumber,
        FieldRole::CcExpMonth,
        FieldRole::CcExpYear,
        FieldRole::CcCsc,
        FieldRole::GivenName,
        FieldRole::FamilyName,
        FieldRole::Email,
        FieldRole::AddressLine1,
        FieldRole::City,
        FieldRole::PostalCode,
        FieldRole::Country,
    ];
    let fields = roles
        .iter()
        .enumerate()
        .map(|(i, r)| field(&format!("f{i}"), *r))
        .collect();
    let pay = page(vec![form(
        "pay",
        fields,
        vec![button("b", ButtonClass::Pay)],
    )]);
    // The login page ranks all 500 Logins, the heavier case.
    for (ctx, intent) in [
        (pay, Intent::Checkout),
        (page(vec![login_form()]), Intent::Login),
    ] {
        let mut times: Vec<u128> = (0..50)
            .map(|_| {
                let input = pl();
                let t = Instant::now();
                let p = plan(&ctx, input).unwrap();
                let elapsed = t.elapsed().as_micros();
                assert_eq!(p.intent, intent);
                elapsed
            })
            .collect();
        times.sort_unstable();
        let median = times[times.len() / 2];
        println!("plan {intent:?} median: {median} us");
        assert!(median < 20_000, "median {median} us");
    }
}
