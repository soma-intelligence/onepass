//! The core planner on the probe's page context, with a fake one-item vault.

use onepass_core::Id;
use onepass_core::fill_plan::context::{FieldRole, PageContext};
use onepass_core::fill_plan::score::{Candidate, CandidateKind, MatchQuality, UsageSignal};
use onepass_core::fill_plan::{FillPlan, GroupItem, Pool, plan};
use serde::Serialize;

use crate::score::PlanSummary;
use crate::sites::Kind;

/// The one Login of the fake vault.
pub const FAKE_LOGIN: Id = Id([0xb0; 16]);
/// Fixed clock: plans do not depend on the day of the run.
pub const NOW: i64 = 1_800_000_000;

pub fn fake_pool(kind: Kind) -> Pool {
    let logins = match kind {
        Kind::Login => vec![Candidate {
            item_id: FAKE_LOGIN,
            kind: CandidateKind::Login,
            quality: MatchQuality::Exact,
            favorite: false,
            updated_at: NOW - 86_400,
            title: "bench".into(),
            username_hash: None,
            usage: Some(UsageSignal {
                last_on_site: true,
                same_shape: true,
                count: 3,
                last_at: NOW - 86_400,
            }),
            has_totp: false,
        }],
        Kind::Signup => Vec::new(),
    };
    Pool {
        logins,
        cards: Vec::new(),
        identities: Vec::new(),
        identity_country: Default::default(),
        default_card: None,
        now: NOW,
    }
}

/// One form to fill: its ref and each field ref with the role the plan gives it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FillGroup {
    pub form_ref: String,
    pub generated: bool,
    pub fields: Vec<(String, FieldRole)>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Planned {
    pub summary: PlanSummary,
    pub groups: Vec<FillGroup>,
}

fn snake<T: Serialize>(v: &T) -> String {
    serde_json::to_value(v)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}

/// Plans the page. The context is the probe's JSON (`buildPageContext`); a context the core
/// refuses is an error, never a panic.
pub fn plan_for(ctx_json: &serde_json::Value, kind: Kind) -> Result<Planned, String> {
    let ctx: PageContext =
        serde_json::from_value(ctx_json.clone()).map_err(|e| format!("page context: {e}"))?;
    let p: FillPlan = plan(&ctx, fake_pool(kind)).map_err(|e| format!("plan: {e}"))?;
    let groups: Vec<FillGroup> = p
        .groups
        .iter()
        .filter(|g| match g.item {
            GroupItem::Item(id) => id == FAKE_LOGIN,
            GroupItem::GeneratedPassword => true,
        })
        .map(|g| FillGroup {
            form_ref: g.form_ref.clone(),
            generated: g.item == GroupItem::GeneratedPassword,
            fields: g.fields.clone(),
        })
        .collect();
    Ok(Planned {
        summary: PlanSummary {
            intent: snake(&p.intent),
            action: snake(&p.action),
            groups: groups.len(),
        },
        groups,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ctx(fields: serde_json::Value, kind: &str, signup_words: bool) -> serde_json::Value {
        json!({
            "origin": "https://s.example", "top_origin": "https://s.example", "frame_kind": "top",
            "typed_username_hash": null,
            "forms": [{
                "form_ref": "f1",
                "intent_hints": {"kind": kind, "signup_words": signup_words, "reset_words": false, "checkout_words": false, "ignore": false},
                "step_index": null,
                "fields": fields,
                "buttons": [{"button_ref": "b1", "class": if signup_words { "create" } else { "submit" }}]
            }]
        })
    }

    fn field(r: &str, role: &str) -> serde_json::Value {
        json!({"field_ref": r, "role": role, "confidence": 0.9, "visible": true, "prefilled": "empty"})
    }

    #[test]
    fn login_plans_one_group_on_both_fields() {
        let c = ctx(
            json!([field("u", "username"), field("p", "current_password")]),
            "login",
            false,
        );
        let p = plan_for(&c, Kind::Login).unwrap();
        assert_eq!(p.summary.intent, "login");
        assert_eq!(p.groups.len(), 1);
        assert!(!p.groups[0].generated);
        let refs: Vec<&str> = p.groups[0].fields.iter().map(|(r, _)| r.as_str()).collect();
        assert_eq!(refs, ["u", "p"]);
    }

    #[test]
    fn signup_plans_the_generated_password() {
        let c = ctx(
            json!([
                field("e", "email"),
                field("n", "new_password"),
                field("c", "confirm_password")
            ]),
            "signup",
            true,
        );
        let p = plan_for(&c, Kind::Signup).unwrap();
        assert_eq!(p.summary.intent, "signup");
        assert!(p.groups.iter().any(|g| g.generated));
    }

    #[test]
    fn bad_context_is_an_error() {
        assert!(plan_for(&json!({"forms": 1}), Kind::Login).is_err());
        let c = ctx(
            json!([field("u", "username"), field("u", "current_password")]),
            "login",
            false,
        );
        assert!(plan_for(&c, Kind::Login).is_err());
    }
}
