//! One fill plan for the whole page (spec 4.2, 6.4, 8.1, 9).

use std::collections::HashMap;

use serde::Serialize;

use super::context::{
    ButtonClass, ContextError, FieldRole, FormContext, FrameKind, PageContext, Prefilled,
};
use super::intent::{Intent, intent_of};
use super::score::{Candidate, Confidence, Tiebreak, confidence, order, score};
use super::weights::{ROLE_MIN, TYPED_USERNAME};
use crate::id::Id;

const MAX_ALTERNATIVES: usize = 5;

/// Main intent of a page: the first of these found among its forms.
pub const PRIORITY: [Intent; 6] = [
    Intent::Login,
    Intent::Otp,
    Intent::Reset,
    Intent::Signup,
    Intent::Checkout,
    Intent::Address,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Fill,
    FillAndSubmit,
    OpenChain,
    ShowMenu,
    Nothing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupItem {
    Item(Id),
    GeneratedPassword,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupKind {
    Login,
    Card,
    Identity,
    GeneratedPassword,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct PlanGroup {
    pub form_ref: String,
    pub item: GroupItem,
    pub kind: GroupKind,
    pub fields: Vec<(String, FieldRole)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasonCode {
    SingleCandidate,
    LastOnSite,
    SameShape,
    TypedUsername,
    Tie,
    WeakRoles,
    NoCandidate,
    IgnoredForm,
    PayButton,
    CreateButton,
    ChildFrame,
    MultipleForms,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct FillPlan {
    pub intent: Intent,
    pub groups: Vec<PlanGroup>,
    pub action: Action,
    pub confidence: Confidence,
    pub alternatives: Vec<Id>,
    pub reasons: Vec<ReasonCode>,
}

/// Candidates already through the hard filter (spec 6.1), one list per kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pool {
    pub logins: Vec<Candidate>,
    pub cards: Vec<Candidate>,
    pub identities: Vec<Candidate>,
    /// Two-letter country code of each identity that has one.
    pub identity_country: HashMap<Id, String>,
    pub default_card: Option<Id>,
    /// Unix seconds.
    pub now: i64,
}

/// The page's main intent: the first of `PRIORITY` among its forms,
/// `Ignore` when none.
pub fn page_intent(ctx: &PageContext) -> Intent {
    let intents: Vec<Intent> = ctx.forms.iter().map(intent_of).collect();
    PRIORITY
        .into_iter()
        .find(|i| intents.contains(i))
        .unwrap_or(Intent::Ignore)
}

/// Which roles of a form of `intent` a group of `kind` fills.
fn wants(intent: Intent, kind: GroupKind, role: FieldRole) -> bool {
    use FieldRole as R;
    let identity = role.is_identity_or_address() || role == R::Email;
    let generated = matches!(role, R::NewPassword | R::ConfirmPassword);
    match (intent, kind) {
        (Intent::Login, GroupKind::Login) => {
            matches!(role, R::Username | R::Email | R::CurrentPassword | R::Otp)
        }
        (Intent::Otp, GroupKind::Login) => role == R::Otp,
        (Intent::Reset, GroupKind::Login) => {
            matches!(role, R::Username | R::Email | R::CurrentPassword)
        }
        (Intent::Reset | Intent::Signup, GroupKind::GeneratedPassword) => generated,
        // A signup's identifier is the identity's e-mail, also in a field
        // marked `username`.
        (Intent::Signup, GroupKind::Identity) => identity || role == R::Username,
        (Intent::Checkout | Intent::Address, GroupKind::Identity) => identity,
        (Intent::Checkout, GroupKind::Card) => role.is_card(),
        _ => false,
    }
}

/// Visible fields with a role the group fills, never one the user typed in.
fn targets(form: &FormContext, intent: Intent, kind: GroupKind) -> Vec<(String, FieldRole)> {
    form.fields
        .iter()
        .filter(|f| f.visible && f.prefilled != Prefilled::Typed)
        .filter_map(|f| f.role.map(|r| (f, r)))
        .filter(|(_, r)| wants(intent, kind, *r))
        .map(|(f, r)| (f.field_ref.clone(), r))
        .collect()
}

/// Two-letter country of the top-level origin's TLD, `.uk` as `GB`.
fn origin_country(top_origin: &str) -> Option<String> {
    let rest = top_origin.split_once("://").map_or(top_origin, |(_, r)| r);
    let host = rest.split(['/', '?', '#']).next()?;
    if host.starts_with('[') {
        return None;
    }
    let host = host.split(':').next()?.trim_end_matches('.');
    let tld = host.rsplit_once('.')?.1;
    if tld.len() != 2 || !tld.bytes().all(|b| b.is_ascii_alphabetic()) {
        return None;
    }
    let tld = tld.to_ascii_uppercase();
    Some(if tld == "UK" { "GB".into() } else { tld })
}

/// How a slot falls back when no candidate was used on this site.
enum Fallback {
    /// Ranking only.
    None,
    /// The default card, else the ranking.
    DefaultCard(Option<Id>),
    /// The identity of the origin's country, else the ranking (a tie
    /// among identities is a menu, never the first one by rule).
    Country(Option<String>),
}

/// One kind of item the plan needs, ranked, with its pick first.
struct Slot {
    kind: GroupKind,
    ranked: Vec<Candidate>,
    scores: Vec<i64>,
    /// Picked by a rule (default card, identity of the country), not ranking.
    by_rule: bool,
}

impl Slot {
    fn new(
        kind: GroupKind,
        mut ranked: Vec<Candidate>,
        typed: Option<&[u8; 32]>,
        now: i64,
        fallback: Fallback,
        countries: &HashMap<Id, String>,
    ) -> Slot {
        order(&mut ranked, typed, now, Tiebreak::FavoriteThenRecent);
        let mut scores: Vec<i64> = ranked.iter().map(|c| score(c, typed, now)).collect();
        let remembered = ranked
            .first()
            .is_some_and(|c| c.usage.is_some_and(|u| u.last_on_site));
        let mut by_rule = false;
        if !remembered && !ranked.is_empty() {
            let found = match &fallback {
                Fallback::None => None,
                Fallback::DefaultCard(card) => {
                    card.and_then(|d| ranked.iter().position(|c| c.item_id == d))
                }
                Fallback::Country(country) => country.as_ref().and_then(|cc| {
                    ranked.iter().position(|c| {
                        countries
                            .get(&c.item_id)
                            .is_some_and(|v| v.eq_ignore_ascii_case(cc))
                    })
                }),
            };
            if let Some(i) = found {
                by_rule = true;
                ranked[..=i].rotate_right(1);
                scores[..=i].rotate_right(1);
            }
        }
        Slot {
            kind,
            ranked,
            scores,
            by_rule,
        }
    }

    fn chosen(&self) -> Option<Id> {
        self.ranked.first().map(|c| c.item_id)
    }

    fn confidence(&self, role_min_ok: bool) -> Confidence {
        let c = confidence(&self.ranked, &self.scores, role_min_ok);
        // A rule pick is a valid fill even among tied candidates.
        if self.by_rule && !self.ranked.is_empty() {
            c.max(Confidence::Medium)
        } else {
            c
        }
    }
}

fn push(reasons: &mut Vec<ReasonCode>, r: ReasonCode) {
    if !reasons.contains(&r) {
        reasons.push(r);
    }
}

fn ignored() -> FillPlan {
    FillPlan {
        intent: Intent::Ignore,
        groups: vec![],
        action: Action::Nothing,
        confidence: Confidence::Low,
        alternatives: vec![],
        reasons: vec![ReasonCode::IgnoredForm],
    }
}

/// The plan for the whole page. Carries ids, refs and roles, never a value.
///
/// Auto-submit is decided here and only here: `OpenChain` (Login) or
/// `FillAndSubmit` (Otp) need High confidence, the top frame, exactly one
/// planned form, and no `Pay` or `Create` button in it; Otp also needs the
/// item used on this site last time.
pub fn plan(ctx: &PageContext, pool: Pool) -> Result<FillPlan, ContextError> {
    ctx.validate()?;
    let intents: Vec<Intent> = ctx.forms.iter().map(intent_of).collect();
    let Some(intent) = PRIORITY.into_iter().find(|i| intents.contains(i)) else {
        return Ok(ignored());
    };
    let forms: Vec<&FormContext> = ctx
        .forms
        .iter()
        .zip(&intents)
        .filter(|(_, i)| **i == intent)
        .map(|(f, _)| f)
        .collect();
    let needs = |kind: GroupKind| forms.iter().any(|f| !targets(f, intent, kind).is_empty());

    // The slots this page needs; the first one is the primary.
    let typed = ctx.typed_username_hash.as_ref();
    let now = pool.now;
    let countries = &pool.identity_country;
    let mut slots: Vec<Slot> = Vec::new();
    let mut logins = pool.logins;
    if intent == Intent::Otp {
        // Only a Login holding a one-time code secret can fill a code.
        logins.retain(|c| c.has_totp);
    }
    if needs(GroupKind::Login) {
        slots.push(Slot::new(
            GroupKind::Login,
            logins,
            typed,
            now,
            Fallback::None,
            countries,
        ));
    }
    if needs(GroupKind::Card) {
        slots.push(Slot::new(
            GroupKind::Card,
            pool.cards,
            None,
            now,
            Fallback::DefaultCard(pool.default_card),
            countries,
        ));
    }
    if needs(GroupKind::Identity) {
        slots.push(Slot::new(
            GroupKind::Identity,
            pool.identities,
            None,
            now,
            Fallback::Country(origin_country(&ctx.top_origin)),
            countries,
        ));
    }

    // A signup without an identity to choose (none in the vault, or a tie
    // with no rule to break it) still gets its generated password: the
    // identity is left out of the plan, not guessed, and does not lower its
    // confidence.
    let mut reasons = Vec::new();
    if intent == Intent::Signup {
        slots.retain(|s| {
            let keep = s.kind != GroupKind::Identity || s.confidence(true) > Confidence::Low;
            if !keep {
                push(&mut reasons, ReasonCode::NoCandidate);
            }
            keep
        });
    }

    let mut groups = Vec::new();
    for form in &forms {
        for slot in &slots {
            if let Some(item) = slot.chosen() {
                let fields = targets(form, intent, slot.kind);
                if !fields.is_empty() {
                    groups.push(PlanGroup {
                        form_ref: form.form_ref.clone(),
                        item: GroupItem::Item(item),
                        kind: slot.kind,
                        fields,
                    });
                }
            }
        }
        let fields = targets(form, intent, GroupKind::GeneratedPassword);
        if !fields.is_empty() {
            groups.push(PlanGroup {
                form_ref: form.form_ref.clone(),
                item: GroupItem::GeneratedPassword,
                kind: GroupKind::GeneratedPassword,
                fields,
            });
        }
    }

    let refs: Vec<&str> = groups
        .iter()
        .flat_map(|g| g.fields.iter().map(|(r, _)| r.as_str()))
        .collect();
    let role_min_ok = forms
        .iter()
        .flat_map(|f| &f.fields)
        .filter(|f| refs.contains(&f.field_ref.as_str()))
        .all(|f| f.confidence >= ROLE_MIN);

    // The weakest slot sets the plan's confidence.
    let confidence = slots
        .iter()
        .map(|s| s.confidence(role_min_ok))
        .min()
        .unwrap_or(if role_min_ok {
            Confidence::High
        } else {
            Confidence::Medium
        });
    if slots.iter().any(|s| s.ranked.is_empty()) {
        push(&mut reasons, ReasonCode::NoCandidate);
    }
    if !role_min_ok {
        push(&mut reasons, ReasonCode::WeakRoles);
    }
    let mut alternatives = Vec::new();
    if let Some(primary) = slots.first() {
        if let Some(first) = primary.ranked.first() {
            if primary.ranked.len() == 1 {
                push(&mut reasons, ReasonCode::SingleCandidate);
            }
            if let Some(u) = first.usage {
                if u.last_on_site {
                    push(&mut reasons, ReasonCode::LastOnSite);
                }
                if u.same_shape {
                    push(&mut reasons, ReasonCode::SameShape);
                }
            }
            if primary.kind == GroupKind::Login && primary.scores[0] >= TYPED_USERNAME {
                push(&mut reasons, ReasonCode::TypedUsername);
            }
            if primary.scores.get(1) == Some(&primary.scores[0]) {
                push(&mut reasons, ReasonCode::Tie);
            }
        }
        alternatives = primary
            .ranked
            .iter()
            .skip(1)
            .take(MAX_ALTERNATIVES)
            .map(|c| c.item_id)
            .collect();
    }

    let action = if groups.is_empty() || confidence == Confidence::Low {
        Action::ShowMenu
    } else if confidence == Confidence::High && matches!(intent, Intent::Login | Intent::Otp) {
        let mut held = false;
        if ctx.frame_kind != FrameKind::Top {
            push(&mut reasons, ReasonCode::ChildFrame);
            held = true;
        }
        let buttons = || forms.iter().flat_map(|f| &f.buttons);
        if buttons().any(|b| b.class == ButtonClass::Pay) {
            push(&mut reasons, ReasonCode::PayButton);
            held = true;
        }
        if buttons().any(|b| b.class == ButtonClass::Create) {
            push(&mut reasons, ReasonCode::CreateButton);
            held = true;
        }
        // Which form to send is ambiguous with more than one planned.
        let mut planned: Vec<&str> = groups.iter().map(|g| g.form_ref.as_str()).collect();
        planned.dedup();
        if planned.len() > 1 {
            push(&mut reasons, ReasonCode::MultipleForms);
            held = true;
        }
        // A value the user typed in a field the chosen item would fill
        // (the chain refills by its own analysis and could overwrite it):
        // only a typed username that matched the chosen account is let by.
        let typed_matched = slots.first().is_some_and(|s| {
            s.kind == GroupKind::Login && s.scores.first().is_some_and(|t| *t >= TYPED_USERNAME)
        });
        let typed_in_target = forms.iter().flat_map(|f| &f.fields).any(|f| {
            f.visible
                && f.prefilled == Prefilled::Typed
                && f.role.is_some_and(|r| {
                    wants(intent, GroupKind::Login, r) && !(typed_matched && r.is_identifier())
                })
        });
        if typed_in_target {
            held = true;
        }
        // A code is sent only for the item used on this site last time.
        let remembered = slots
            .first()
            .and_then(|s| s.ranked.first())
            .is_some_and(|c| c.usage.is_some_and(|u| u.last_on_site));
        if intent == Intent::Otp && !remembered {
            held = true;
        }
        match (held, intent) {
            (true, _) => Action::Fill,
            (false, Intent::Login) => Action::OpenChain,
            (false, _) => Action::FillAndSubmit,
        }
    } else {
        Action::Fill
    };

    Ok(FillPlan {
        intent,
        groups,
        action,
        confidence,
        alternatives,
        reasons,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn country_from_top_origin_tld() {
        assert_eq!(origin_country("https://boutique.fr").as_deref(), Some("FR"));
        assert_eq!(
            origin_country("https://a.b.de:8443/x").as_deref(),
            Some("DE")
        );
        assert_eq!(origin_country("https://shop.co.uk").as_deref(), Some("GB"));
        assert_eq!(origin_country("https://example.com"), None);
        assert_eq!(origin_country("http://localhost:3000"), None);
        assert_eq!(origin_country("http://[::1]:8080"), None);
        assert_eq!(origin_country("http://10.0.0.1"), None);
    }
}
