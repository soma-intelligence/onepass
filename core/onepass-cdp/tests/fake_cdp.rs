//! The filler against a fake DevTools page server on 127.0.0.1.

use std::io::ErrorKind;
use std::net::TcpListener;
use std::time::{Duration, Instant};

use onepass_cdp::fake::{FakeCdp, card_page, card_page_with_select, login_page, set_value};
use onepass_cdp::{CdpError, CdpFiller, FillStep, Zeroizing, backend_node_id};
use onepass_core::fill_plan::context::{
    ButtonClass, ButtonContext, FieldContext, FieldRole, FormContext, FrameKind, IntentHints,
    PageContext, Prefilled,
};
use onepass_core::fill_plan::intent::{Intent, intent_of};

const URL: &str = "https://example.com/login";

fn fake() -> FakeCdp {
    FakeCdp::start(URL, "Example sign in", login_page(URL))
}

#[test]
fn remote_host_is_not_local() {
    // A loopback listener that must never see a connection: every refusal
    // happens on the text of the address.
    let probe = TcpListener::bind("127.0.0.1:0").unwrap();
    probe.set_nonblocking(true).unwrap();
    let port = probe.local_addr().unwrap().port();
    let refused = [
        "ws://10.0.0.2:9222/devtools/page/x".to_owned(),
        "ws://example.com:9222/devtools/page/x".to_owned(),
        "ws://example.com/devtools/page/x".to_owned(),
        format!("ws://localhost:{port}/devtools/page/x"),
        format!("ws://LOCALHOST:{port}/devtools/page/x"),
        format!("ws://user@127.0.0.1:{port}/devtools/page/x"),
        format!("ws://user:pw@127.0.0.1:{port}/devtools/page/x"),
        format!("ws://127.0.0.1:{port}@example.com/devtools/page/x"),
        format!("ws://127.0.0.1.nip.io:{port}/devtools/page/x"),
        format!("ws://127.0.0.2:{port}/devtools/page/x"),
        format!("ws://0.0.0.0:{port}/devtools/page/x"),
        format!("ws://2130706433:{port}/devtools/page/x"),
        format!("ws://[::ffff:127.0.0.1]:{port}/devtools/page/x"),
        "wss://example.com/devtools/page/x".to_owned(),
        "wss://10.0.0.2:9222/devtools/page/x".to_owned(),
    ];
    for url in &refused {
        let t = Instant::now();
        let err = CdpFiller::connect(url).err();
        assert_eq!(err, Some(CdpError::NotLocal), "{url}");
        assert!(
            t.elapsed() < Duration::from_millis(200),
            "{url} took a lookup"
        );
    }
    match probe.accept() {
        Err(e) if e.kind() == ErrorKind::WouldBlock => {}
        other => panic!("a refused address reached the socket: {other:?}"),
    }
    // Malformed is not "not local".
    assert_eq!(
        CdpFiller::connect("http://127.0.0.1:9222/json").err(),
        Some(CdpError::Connect)
    );
    // The two loopback forms are accepted (and here reach the fake).
    let f = fake();
    assert!(CdpFiller::connect(&f.ws_url()).is_ok());
    let v6 = format!("ws://[::1]:{}/devtools/page/FAKE", f.port());
    // ::1 may be unbound on this machine: only NotLocal would be wrong.
    assert_ne!(CdpFiller::connect(&v6).err(), Some(CdpError::NotLocal));
}

#[test]
fn reads_main_frame_url_and_title() {
    let f = fake();
    let mut page = CdpFiller::connect(&f.ws_url()).unwrap();
    assert_eq!(page.main_frame_url().unwrap(), URL);
    assert_eq!(page.title().unwrap(), "Example sign in");
    let m = f.methods();
    assert!(m.contains(&"Page.getFrameTree".to_owned()), "{m:?}");
    assert!(m.contains(&"Target.getTargetInfo".to_owned()), "{m:?}");
    assert!(m.iter().all(|m| !m.starts_with("Runtime.")), "{m:?}");
}

#[test]
fn fill_uses_insert_text_never_runtime_evaluate() {
    let f = fake();
    let mut page = CdpFiller::connect(&f.ws_url()).unwrap();
    assert_eq!(page.main_frame_url().unwrap(), URL);
    let ctx = page.page_context().unwrap();
    let fields = &ctx.forms[0].fields;
    let user = backend_node_id(&fields[0].field_ref).unwrap();
    let pass = backend_node_id(&fields[1].field_ref).unwrap();
    let button = backend_node_id(&ctx.forms[0].buttons[0].button_ref).unwrap();
    page.fill(
        vec![
            FillStep::new(user, Zeroizing::new("alice@example.com".to_owned())),
            FillStep::new(pass, Zeroizing::new("s3cr3t-Pa55".to_owned())),
        ],
        Some(button),
    )
    .unwrap();

    assert_eq!(f.inserted(), ["alice@example.com", "s3cr3t-Pa55"]);
    let cmds = f.commands();
    for c in &cmds {
        let method = c["method"].as_str().unwrap();
        assert!(!method.starts_with("Runtime."), "{method}");
        if method != "Input.insertText" {
            let s = c.to_string();
            assert!(!s.contains("s3cr3t-Pa55") && !s.contains("alice@"), "{s}");
        }
    }
    // Each value goes right after a focus on its own node.
    let seq: Vec<(String, Option<i64>)> = cmds
        .iter()
        .map(|c| {
            (
                c["method"].as_str().unwrap().to_owned(),
                c["params"]["backendNodeId"].as_i64(),
            )
        })
        .filter(|(m, _)| m == "DOM.focus" || m == "Input.insertText")
        .collect();
    assert_eq!(
        seq,
        [
            ("DOM.focus".to_owned(), Some(user)),
            ("Input.insertText".to_owned(), None),
            ("DOM.focus".to_owned(), Some(pass)),
            ("Input.insertText".to_owned(), None),
        ]
    );
    // The submit: a press and a release at the button's centre (10,120 80x30).
    let presses: Vec<&serde_json::Value> = cmds
        .iter()
        .filter(|c| c["method"] == "Input.dispatchMouseEvent")
        .collect();
    assert!(
        presses
            .iter()
            .any(|c| c["params"]["type"] == "mousePressed")
    );
    let rel = presses
        .iter()
        .find(|c| c["params"]["type"] == "mouseReleased")
        .unwrap();
    assert_eq!(rel["params"]["x"].as_f64(), Some(50.0));
    assert_eq!(rel["params"]["y"].as_f64(), Some(135.0));

    // A node of another frame (the ad's password field) is never typed into.
    assert_eq!(page.type_into(21, "x"), Err(CdpError::Protocol));
    assert_eq!(f.inserted().len(), 2);
}

#[test]
fn navigation_between_fields_stops_the_fill() {
    let f = fake();
    let mut page = CdpFiller::connect(&f.ws_url()).unwrap();
    page.main_frame_url().unwrap();
    let ctx = page.page_context().unwrap();
    let user = backend_node_id(&ctx.forms[0].fields[0].field_ref).unwrap();
    let pass = backend_node_id(&ctx.forms[0].fields[1].field_ref).unwrap();
    // The page leaves for another site once the first value is in.
    f.navigate_after_inserts(1, "https://evil.example/login");
    let err = page
        .fill(
            vec![
                FillStep::new(user, Zeroizing::new("alice".to_owned())),
                FillStep::new(pass, Zeroizing::new("hunter2".to_owned())),
            ],
            None,
        )
        .unwrap_err();
    assert_eq!(err, CdpError::OriginChanged);
    assert_eq!(f.inserted(), ["alice"]);
    // A path change on the same origin does not stop a fill.
    let g = fake();
    let mut page = CdpFiller::connect(&g.ws_url()).unwrap();
    page.main_frame_url().unwrap();
    page.page_context().unwrap();
    g.navigate_after_inserts(1, "https://example.com/login?step=2");
    page.fill(
        vec![
            FillStep::new(user, Zeroizing::new("alice".to_owned())),
            FillStep::new(pass, Zeroizing::new("hunter2".to_owned())),
        ],
        None,
    )
    .unwrap();
    assert_eq!(g.inserted(), ["alice", "hunter2"]);
    // A standalone type_into checks too.
    g.navigate("https://evil.example/");
    assert_eq!(page.type_into(user, "x"), Err(CdpError::OriginChanged));
    assert_eq!(g.inserted().len(), 2);
}

#[test]
fn page_context_matches_a_login_form_fixture() {
    let f = fake();
    let mut page = CdpFiller::connect(&f.ws_url()).unwrap();
    let ctx = page.page_context().unwrap();
    let expected = PageContext {
        origin: "https://example.com".into(),
        top_origin: "https://example.com".into(),
        frame_kind: FrameKind::Top,
        forms: vec![FormContext {
            form_ref: ctx.forms[0].form_ref.clone(),
            intent_hints: IntentHints {
                kind: None,
                signup_words: false,
                reset_words: false,
                checkout_words: false,
                ignore: false,
            },
            step_index: None,
            fields: vec![
                FieldContext {
                    field_ref: "11".into(),
                    role: Some(FieldRole::Username),
                    confidence: 1.0,
                    visible: true,
                    prefilled: Prefilled::Empty,
                },
                FieldContext {
                    field_ref: "12".into(),
                    role: Some(FieldRole::CurrentPassword),
                    // "password" in name and label plus the type: 3 + 4.5 + 3.
                    confidence: 1.0,
                    visible: true,
                    prefilled: Prefilled::Empty,
                },
                FieldContext {
                    field_ref: "14".into(),
                    role: Some(FieldRole::Unknown),
                    confidence: 0.0,
                    visible: false,
                    prefilled: Prefilled::Empty,
                },
            ],
            buttons: vec![ButtonContext {
                button_ref: "13".into(),
                class: ButtonClass::Submit,
            }],
        }],
        typed_username_hash: None,
    };
    assert_eq!(ctx, expected);
    assert_eq!(ctx.validate(), Ok(()));
    assert_eq!(intent_of(&ctx.forms[0]), Intent::Login);
    assert!(
        f.methods()
            .contains(&"DOMSnapshot.captureSnapshot".to_owned())
    );
}

#[test]
fn a_silent_browser_times_out() {
    let f = fake();
    f.never_answer("Page.getFrameTree");
    let mut page = CdpFiller::connect_with(
        &f.ws_url(),
        Duration::from_millis(300),
        Duration::from_secs(1),
    )
    .unwrap();
    let t = Instant::now();
    assert_eq!(page.main_frame_url(), Err(CdpError::Timeout));
    assert!(t.elapsed() < Duration::from_secs(2));
}

#[test]
fn card_form_roles_from_labels() {
    let url = "https://shop.example/checkout";
    let f = FakeCdp::start(url, "Checkout", card_page(url));
    let mut page = CdpFiller::connect(&f.ws_url()).unwrap();
    let ctx = page.page_context().unwrap();
    let roles: Vec<(String, Option<FieldRole>)> = ctx.forms[0]
        .fields
        .iter()
        .map(|f| (f.field_ref.clone(), f.role))
        .collect();
    assert_eq!(
        roles,
        [
            ("31".to_owned(), Some(FieldRole::CcNumber)),
            ("32".to_owned(), Some(FieldRole::CcName)),
            ("33".to_owned(), Some(FieldRole::CcExp)),
            ("34".to_owned(), Some(FieldRole::CcCsc)),
        ]
    );
    assert_eq!(ctx.forms[0].buttons[0].class, ButtonClass::Pay);
    assert!(ctx.forms[0].intent_hints.checkout_words);
    assert_eq!(intent_of(&ctx.forms[0]), Intent::Checkout);
}

#[test]
fn a_page_without_fields_is_no_fields() {
    use onepass_cdp::fake::{FakeDocument, el, text};
    let doc = FakeDocument {
        url: URL.into(),
        title: "t".into(),
        frame_id: "MAIN".into(),
        root: el(
            "html",
            &[],
            vec![el("body", &[], vec![el("p", &[], vec![text("hi")])])],
        ),
    };
    let f = FakeCdp::start(URL, "t", vec![doc]);
    let mut page = CdpFiller::connect(&f.ws_url()).unwrap();
    assert_eq!(page.page_context(), Err(CdpError::NoFields));
}

#[test]
fn a_select_in_the_fill_fails_it_with_nothing_typed_or_clicked() {
    let url = "https://shop.example/checkout";
    let f = FakeCdp::start(url, "Checkout", card_page_with_select(url));
    let mut page = CdpFiller::connect(&f.ws_url()).unwrap();
    let ctx = page.page_context().unwrap();
    // The select is still in the context for the planner.
    assert!(ctx.forms[0].fields.iter().any(|f| f.field_ref == "33"));
    assert_eq!(page.check_typable(33), Err(CdpError::Unsupported));
    let before = f.commands().len();
    let err = page
        .fill(
            vec![
                FillStep::new(31, Zeroizing::new("4111111111111111".to_owned())),
                FillStep::new(33, Zeroizing::new("02".to_owned())),
            ],
            Some(35),
        )
        .unwrap_err();
    assert_eq!(err, CdpError::Unsupported);
    // Refused before any command: nothing focused, typed or clicked.
    assert_eq!(f.commands().len(), before);
    assert!(f.inserted().is_empty());
    assert_eq!(page.type_into(33, "02"), Err(CdpError::Unsupported));
    assert_eq!(f.commands().len(), before);
}

#[test]
fn a_field_holding_text_is_cleared_before_typing() {
    let mut docs = login_page(URL);
    set_value(&mut docs, 11, "old-user");
    let f = FakeCdp::start(URL, "Example sign in", docs);
    let mut page = CdpFiller::connect(&f.ws_url()).unwrap();
    let ctx = page.page_context().unwrap();
    assert_eq!(ctx.forms[0].fields[0].prefilled, Prefilled::Typed);
    page.fill(
        vec![FillStep::new(11, Zeroizing::new("alice".to_owned()))],
        None,
    )
    .unwrap();
    assert_eq!(f.field_text(11).as_deref(), Some("alice"));
    let cmds = f.commands();
    let pos = |pred: &dyn Fn(&serde_json::Value) -> bool| cmds.iter().position(pred).unwrap();
    let focus = pos(&|c| c["method"] == "DOM.focus");
    let select_all = pos(&|c| {
        c["method"] == "Input.dispatchKeyEvent"
            && c["params"]["type"] == "keyDown"
            && c["params"]["commands"][0] == "selectAll"
    });
    let insert = pos(&|c| c["method"] == "Input.insertText");
    assert!(focus < select_all && select_all < insert, "{cmds:?}");
    // Meta+A then Control+A.
    let mods: Vec<i64> = cmds
        .iter()
        .filter(|c| c["method"] == "Input.dispatchKeyEvent" && c["params"]["type"] == "keyDown")
        .map(|c| c["params"]["modifiers"].as_i64().unwrap())
        .collect();
    assert_eq!(mods, [4, 2]);
    assert!(f.methods().iter().all(|m| !m.starts_with("Runtime.")));
}

#[test]
fn navigation_on_focus_sends_no_text() {
    let f = fake();
    let mut page = CdpFiller::connect(&f.ws_url()).unwrap();
    page.main_frame_url().unwrap();
    page.page_context().unwrap();
    f.navigate_on_focus("https://evil.example/");
    assert_eq!(page.type_into(11, "alice"), Err(CdpError::OriginChanged));
    assert!(f.methods().contains(&"DOM.focus".to_owned()));
    assert!(f.inserted().is_empty());
}
