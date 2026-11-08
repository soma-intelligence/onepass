//! A manual check against a real Chrome (ignored by default): the select-all
//! key events with the `selectAll` command, then `Input.insertText`, replace
//! the text a field already holds.
//!
//! Start a throwaway Chrome (never your own profile) on a local page whose
//! script copies both fields into `document.title` on every `input` event:
//!
//! ```text
//! chrome --headless=new --remote-debugging-port=9222 \
//!   --user-data-dir="$(mktemp -d)" http://127.0.0.1:8765/login.html
//! ONEPASS_CDP_WS=<webSocketDebuggerUrl of the page from :9222/json> \
//!   cargo test -p onepass-cdp --test real_chrome -- --ignored
//! ```
//!
//! The page holds `old-user@test.invalid` and `old-pass` (fake values) in an
//! email field and a password field, and a "Sign in" submit button whose
//! submit handler appends `|sent` to the title.

use onepass_cdp::{CdpFiller, backend_node_id};
use onepass_core::fill_plan::context::{ButtonClass, FieldRole};

#[test]
#[ignore = "needs a real Chrome with --remote-debugging-port, see the file header"]
fn real_chrome_replaces_prefilled_text() {
    let ws = std::env::var("ONEPASS_CDP_WS").expect("ONEPASS_CDP_WS");
    let mut page = CdpFiller::connect(&ws).unwrap();
    let url = page.main_frame_url().unwrap();
    assert!(url.starts_with("http://127.0.0.1:"), "{url}");
    let ctx = page.page_context().unwrap();
    let form = &ctx.forms[0];
    let id_of = |role: FieldRole| {
        form.fields
            .iter()
            .find(|f| f.role == Some(role))
            .and_then(|f| backend_node_id(&f.field_ref))
            .unwrap_or_else(|| panic!("no {role:?} field in {form:?}"))
    };
    let user = id_of(FieldRole::Username);
    let pw = id_of(FieldRole::CurrentPassword);
    page.type_into(user, "alice@test.invalid").unwrap();
    page.type_into(pw, "Fake-Pass-1").unwrap();
    assert_eq!(page.title().unwrap(), "U:alice@test.invalid|P:Fake-Pass-1");
    let button = form
        .buttons
        .iter()
        .find(|b| b.class == ButtonClass::Submit)
        .and_then(|b| backend_node_id(&b.button_ref))
        .expect("a submit button");
    page.click(button).unwrap();
    assert_eq!(
        page.title().unwrap(),
        "U:alice@test.invalid|P:Fake-Pass-1|sent"
    );
}
