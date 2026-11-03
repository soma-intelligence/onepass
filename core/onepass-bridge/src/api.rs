//! Application messages carried in the clear text of a `msg` frame
//! (spec 6.7 and 7.2).
//!
//! A request is `{"id": n, "op": "...", ...}`. A reply is
//! `{"id": n, "ok": {...}}` or `{"id": n, "err": {"code", "msg"}}`.
//! Requests reject unknown fields. Secret strings, in requests and in
//! replies, are `SecretString`: wiped on drop, masked in `Debug`.

use std::fmt;

use onepass_core::autofill_history::{AutofillAction, BrowserKind};
use onepass_core::fill_plan::context::{FieldRole, PageContext};
use onepass_core::fill_plan::intent::Intent;
use onepass_core::fill_plan::score::Confidence;
use onepass_core::fill_plan::{Action, FillPlan, GroupItem, GroupKind, PasskeyOffer, ReasonCode};
use onepass_core::model::MatchRule;
use onepass_core::model::usage::StepKind;
use onepass_core::site_password::GenerationReport;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::AppErrorCode;
use crate::origin::MatchQuality;
use crate::provider::ProviderId;

/// A secret string: wiped on drop, `**` in `Debug`, a plain JSON string
/// on the wire.
#[derive(Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecretString(pub Zeroizing<String>);

impl SecretString {
    pub fn new(s: Zeroizing<String>) -> Self {
        Self(s)
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl From<&str> for SecretString {
    fn from(s: &str) -> Self {
        Self(Zeroizing::new(s.to_owned()))
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("**")
    }
}

/// Where the action comes from in the extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ctx {
    Popup,
    Menu,
    Overlay,
    SavePrompt,
    Chain,
    /// The extension's passkey choice window.
    Passkey,
}

impl Ctx {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Popup => "popup",
            Self::Menu => "menu",
            Self::Overlay => "overlay",
            Self::SavePrompt => "save_prompt",
            Self::Chain => "chain",
            Self::Passkey => "passkey",
        }
    }
}

/// A login field the extension may ask to fill.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FillField {
    Username,
    Password,
    Totp,
}

/// Kind of `list_fillable`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FillKind {
    Card,
    Identity,
}

/// Match rule of a saved login, as on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Rule {
    Domain,
    ExactHost,
    ExactUrl,
    Never,
}

impl From<Rule> for MatchRule {
    fn from(r: Rule) -> MatchRule {
        match r {
            Rule::Domain => MatchRule::Domain,
            Rule::ExactHost => MatchRule::ExactHost,
            Rule::ExactUrl => MatchRule::ExactUrl,
            Rule::Never => MatchRule::Never,
        }
    }
}

/// One step of a fill, as `note_fill` reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Step {
    Fill,
    Otp,
    ProviderClick,
    Account,
}

impl From<Step> for StepKind {
    fn from(s: Step) -> StepKind {
        match s {
            Step::Fill => StepKind::Fill,
            Step::Otp => StepKind::Otp,
            Step::ProviderClick => StepKind::ProviderClick,
            Step::Account => StepKind::Account,
        }
    }
}

/// Generator recipe kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecipeKind {
    Random,
    Memorable,
    Pin,
    Smart,
}

/// Generator profile of the `smart` kind.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecipeProfile {
    #[default]
    Strong,
    Readable,
    Custom,
}

/// What the page says about its password field (`smart` only).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecipeContext {
    /// `passwordrules` attribute values, at most 8 of at most 1024 chars.
    #[serde(default)]
    pub rules: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_length: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_length: Option<u32>,
    /// Written instructions near the field; cut to 600 chars.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hint_text: Option<String>,
}

/// Generator request. Every field but `kind` may be left out: each kind
/// has its defaults. `profile`, `context` and `narrow` apply to `smart`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Recipe {
    pub kind: RecipeKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub length: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub symbols: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<RecipeProfile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<RecipeContext>,
    /// Retry ladder step, 0..=2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub narrow: Option<u8>,
}

/// An application request. Every operation carries the request `id`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Status {
        id: u64,
    },
    Unlock {
        id: u64,
    },
    Vaults {
        id: u64,
    },
    ListForOrigin {
        id: u64,
        ctx: Ctx,
        origin: String,
    },
    Search {
        id: u64,
        ctx: Ctx,
        query: String,
    },
    ListFillable {
        id: u64,
        ctx: Ctx,
        origin: String,
        kind: FillKind,
    },
    FillLogin {
        id: u64,
        ctx: Ctx,
        item_id: String,
        origin: String,
        fields: Vec<FillField>,
    },
    FillCard {
        id: u64,
        ctx: Ctx,
        item_id: String,
        origin: String,
    },
    FillIdentity {
        id: u64,
        ctx: Ctx,
        item_id: String,
        origin: String,
    },
    Totp {
        id: u64,
        ctx: Ctx,
        item_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        origin: Option<String>,
    },
    Reveal {
        id: u64,
        ctx: Ctx,
        item_id: String,
        field: String,
    },
    CheckCredentials {
        id: u64,
        ctx: Ctx,
        origin: String,
        username: String,
        password: SecretString,
    },
    SaveLogin {
        id: u64,
        ctx: Ctx,
        origin: String,
        title: String,
        username: String,
        password: SecretString,
        vault_id: String,
        rule: Rule,
        tags: Vec<String>,
    },
    UpdatePassword {
        id: u64,
        ctx: Ctx,
        item_id: String,
        origin: String,
        password: SecretString,
        /// A pending Login regenerated: set (true) or clear (false) its
        /// `onepass:weak-by-site` tag. Ignored on any other item.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        weak_by_site: Option<bool>,
    },
    /// A pending Login (tag `onepass:pending`) whose form was sent: the tag
    /// drops, `username` (when not blank) replaces the stored one.
    ConfirmPending {
        id: u64,
        ctx: Ctx,
        item_id: String,
        origin: String,
        username: String,
    },
    Generate {
        id: u64,
        ctx: Ctx,
        recipe: Recipe,
        /// Page origin, to look up the site's known rules (`smart` only).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        origin: Option<String>,
    },
    ProviderAccounts {
        id: u64,
        ctx: Ctx,
        provider: ProviderId,
        origin: String,
    },
    FillProvider {
        id: u64,
        ctx: Ctx,
        account_item_id: String,
        provider: ProviderId,
        provider_origin: String,
        site_origin: String,
        fields: Vec<FillField>,
    },
    LinkProvider {
        id: u64,
        ctx: Ctx,
        site_origin: String,
        provider: ProviderId,
        account_item_id: String,
    },
    FillSalt {
        id: u64,
        ctx: Ctx,
    },
    /// `origin` is the browser's origin of the frame; `context.origin` must
    /// be the same.
    PlanFill {
        id: u64,
        ctx: Ctx,
        origin: String,
        context: PageContext,
    },
    /// `roles`: the planned form's roles, in page order, as `plan_fill`
    /// hashes them for `same_shape`.
    NoteFill {
        id: u64,
        ctx: Ctx,
        item_id: String,
        origin: String,
        roles: Vec<FieldRole>,
        intent: Intent,
        steps: Vec<Step>,
    },
    ForgetSite {
        id: u64,
        ctx: Ctx,
        site: String,
    },
    /// The browser and browser profile of this session, for the device's
    /// autofill history (`onepass_core::autofill_history`). `profile_id`:
    /// an opaque id the extension drew and keeps in its own storage;
    /// `profile_name` only when the browser exposes one.
    ClientInfo {
        id: u64,
        browser: BrowserKind,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        profile_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        profile_name: Option<String>,
    },
    /// One autofill history event of the frame `origin`: a list shown
    /// (`shown`, best first), a pick of `item_id` at `rank`, a dismissal
    /// (`item_id`: the first entry), a first offer passed over, a fill.
    /// Never a value.
    NoteAutofill {
        id: u64,
        ctx: Ctx,
        origin: String,
        action: AutofillAction,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        item_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        rank: Option<u8>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        shown: Vec<String>,
    },
    /// Passkeys of `rp_id` for a page, without a secret. `origin` is the
    /// browser's origin of the frame.
    PasskeyList {
        id: u64,
        ctx: Ctx,
        origin: String,
        rp_id: String,
    },
    /// An assertion by a stored passkey. `credential_id` and `challenge`
    /// are base64url; the host builds `clientDataJSON` from `origin`.
    /// `top_origin`: the browser's origin of the top frame, which must be
    /// `origin` (same-origin frames only).
    PasskeyGet {
        id: u64,
        ctx: Ctx,
        origin: String,
        top_origin: String,
        rp_id: String,
        item_id: String,
        credential_id: String,
        challenge: String,
    },
    /// A new passkey. `user_handle`, `challenge` and each `exclude` id are
    /// base64url. `vault_id`: where a new Login goes when the site has
    /// none of `user_name` (the first vault when left out).
    PasskeyCreate {
        id: u64,
        ctx: Ctx,
        origin: String,
        top_origin: String,
        rp_id: String,
        user_name: String,
        user_handle: String,
        challenge: String,
        #[serde(default)]
        exclude: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        vault_id: Option<String>,
    },
}

impl Request {
    /// The request id.
    pub fn id(&self) -> u64 {
        match self {
            Self::Status { id }
            | Self::Unlock { id }
            | Self::Vaults { id }
            | Self::ListForOrigin { id, .. }
            | Self::Search { id, .. }
            | Self::ListFillable { id, .. }
            | Self::FillLogin { id, .. }
            | Self::FillCard { id, .. }
            | Self::FillIdentity { id, .. }
            | Self::Totp { id, .. }
            | Self::Reveal { id, .. }
            | Self::CheckCredentials { id, .. }
            | Self::SaveLogin { id, .. }
            | Self::UpdatePassword { id, .. }
            | Self::ConfirmPending { id, .. }
            | Self::Generate { id, .. }
            | Self::ProviderAccounts { id, .. }
            | Self::FillProvider { id, .. }
            | Self::LinkProvider { id, .. }
            | Self::FillSalt { id, .. }
            | Self::PlanFill { id, .. }
            | Self::NoteFill { id, .. }
            | Self::ForgetSite { id, .. }
            | Self::ClientInfo { id, .. }
            | Self::NoteAutofill { id, .. }
            | Self::PasskeyList { id, .. }
            | Self::PasskeyGet { id, .. }
            | Self::PasskeyCreate { id, .. } => *id,
        }
    }

    /// The wire name of the operation.
    pub fn op(&self) -> &'static str {
        match self {
            Self::Status { .. } => "status",
            Self::Unlock { .. } => "unlock",
            Self::Vaults { .. } => "vaults",
            Self::ListForOrigin { .. } => "list_for_origin",
            Self::Search { .. } => "search",
            Self::ListFillable { .. } => "list_fillable",
            Self::FillLogin { .. } => "fill_login",
            Self::FillCard { .. } => "fill_card",
            Self::FillIdentity { .. } => "fill_identity",
            Self::Totp { .. } => "totp",
            Self::Reveal { .. } => "reveal",
            Self::CheckCredentials { .. } => "check_credentials",
            Self::SaveLogin { .. } => "save_login",
            Self::UpdatePassword { .. } => "update_password",
            Self::ConfirmPending { .. } => "confirm_pending",
            Self::Generate { .. } => "generate",
            Self::ProviderAccounts { .. } => "provider_accounts",
            Self::FillProvider { .. } => "fill_provider",
            Self::LinkProvider { .. } => "link_provider",
            Self::FillSalt { .. } => "fill_salt",
            Self::PlanFill { .. } => "plan_fill",
            Self::NoteFill { .. } => "note_fill",
            Self::ForgetSite { .. } => "forget_site",
            Self::ClientInfo { .. } => "client_info",
            Self::NoteAutofill { .. } => "note_autofill",
            Self::PasskeyList { .. } => "passkey_list",
            Self::PasskeyGet { .. } => "passkey_get",
            Self::PasskeyCreate { .. } => "passkey_create",
        }
    }
}

/// Kind of a summarized item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SummaryKind {
    Login,
    Card,
    Identity,
}

/// A sign-in method of a summarized login.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Method {
    pub provider: ProviderId,
    pub account_email: String,
}

/// What the extension may see of an item without a secret (spec 7.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Summary {
    pub item_id: String,
    pub vault_id: String,
    pub vault_name: String,
    pub title: String,
    pub subtitle: String,
    pub kind: SummaryKind,
    pub icon_letter: String,
    pub icon_color: String,
    pub has_password: bool,
    pub has_totp: bool,
    pub methods: Vec<Method>,
    #[serde(rename = "match")]
    pub match_quality: Option<MatchQuality>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VaultEntry {
    pub id: String,
    pub name: String,
    pub color: Option<String>,
}

/// Address of `fill_identity`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AddressOut {
    pub line1: String,
    pub line2: String,
    pub city: String,
    pub postal_code: String,
    pub region: String,
    pub country: String,
}

/// `check_credentials` verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialStatus {
    New,
    Same,
    Update,
    /// A pending Login of the site (tag `onepass:pending`) holds this very
    /// password, whatever its username: confirm it, never save a second one.
    Pending,
}

/// A field of a plan group.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PlanField {
    pub field_ref: String,
    pub role: FieldRole,
}

/// A group of `plan_fill`: the item as a hyphenated id, `null` for a
/// generated password.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PlanGroupOut {
    pub form_ref: String,
    pub kind: GroupKind,
    pub item_id: Option<String>,
    pub fields: Vec<PlanField>,
}

/// `FillPlan` on the wire: ids as the hyphenated strings of every other
/// reply, fields as objects.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PlanOut {
    pub intent: Intent,
    pub groups: Vec<PlanGroupOut>,
    pub action: Action,
    pub confidence: Confidence,
    pub alternatives: Vec<String>,
    pub reasons: Vec<ReasonCode>,
    /// Signup only: the form's passkey button (`null` when none).
    pub passkey: Option<PasskeyOffer>,
}

impl From<FillPlan> for PlanOut {
    fn from(p: FillPlan) -> PlanOut {
        let groups = p
            .groups
            .into_iter()
            .map(|g| PlanGroupOut {
                form_ref: g.form_ref,
                kind: g.kind,
                item_id: match g.item {
                    GroupItem::Item(id) => Some(id.to_string()),
                    GroupItem::GeneratedPassword => None,
                },
                fields: g
                    .fields
                    .into_iter()
                    .map(|(field_ref, role)| PlanField { field_ref, role })
                    .collect(),
            })
            .collect();
        PlanOut {
            intent: p.intent,
            groups,
            action: p.action,
            confidence: p.confidence,
            alternatives: p.alternatives.iter().map(|id| id.to_string()).collect(),
            reasons: p.reasons,
            passkey: p.passkey,
        }
    }
}

/// A passkey as `passkey_list` shows it: never a key, never a user handle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PasskeySummary {
    pub item_id: String,
    pub vault_id: String,
    pub vault_name: String,
    pub title: String,
    pub user_name: String,
    /// Base64url.
    pub credential_id: String,
}

/// The `ok` payload of a reply, one shape per operation.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
pub enum Response {
    Status {
        locked: bool,
        account: String,
        vaults: usize,
    },
    Unlock {
        locked: bool,
    },
    Vaults {
        vaults: Vec<VaultEntry>,
    },
    Items {
        items: Vec<Summary>,
    },
    /// `fill_login` and `fill_provider`.
    Login {
        #[serde(skip_serializing_if = "Option::is_none")]
        username: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        password: Option<SecretString>,
        #[serde(skip_serializing_if = "Option::is_none")]
        totp: Option<SecretString>,
    },
    /// Month `MM` and year `YYYY`, empty when unknown.
    Card {
        cardholder: String,
        number: SecretString,
        exp_month: String,
        exp_year: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        cvv: Option<SecretString>,
    },
    Identity {
        #[serde(skip_serializing_if = "Option::is_none")]
        given_name: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        family_name: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        email: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        tel: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        organization: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        birthday: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        address: Option<AddressOut>,
    },
    Totp {
        code: SecretString,
        remaining: u32,
    },
    Reveal {
        value: SecretString,
    },
    CheckCredentials {
        status: CredentialStatus,
        #[serde(skip_serializing_if = "Option::is_none")]
        item_id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        title: Option<String>,
    },
    ItemId {
        item_id: String,
    },
    Generate {
        password: SecretString,
        entropy_bits: f64,
        /// Present for `smart`.
        #[serde(skip_serializing_if = "Option::is_none")]
        report: Option<GenerationReport>,
    },
    ProviderAccounts {
        accounts: Vec<Summary>,
        #[serde(skip_serializing_if = "Option::is_none")]
        linked_item_id: Option<String>,
    },
    /// `fill_salt`: 32 bytes, lower-case hex.
    Salt {
        salt: String,
    },
    Plan {
        plan: PlanOut,
    },
    /// `forget_site`: how many items forgot the site.
    Forgotten {
        items: usize,
    },
    Passkeys {
        passkeys: Vec<PasskeySummary>,
    },
    /// `passkey_get`, every value base64url.
    PasskeyAssertion {
        credential_id: String,
        client_data_json: String,
        authenticator_data: String,
        signature: String,
        user_handle: String,
    },
    /// `passkey_create`, every value but the ids and the algorithm
    /// base64url. `public_key`: DER `SubjectPublicKeyInfo`.
    PasskeyRegistration {
        item_id: String,
        credential_id: String,
        client_data_json: String,
        attestation_object: String,
        authenticator_data: String,
        public_key: String,
        public_key_algorithm: i64,
    },
    /// `{}`.
    Empty {},
}

/// Body of an error reply. `msg` never holds a secret nor user data
/// beyond an item id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ErrorBody {
    pub code: &'static str,
    pub msg: String,
}

impl ErrorBody {
    pub fn new(code: AppErrorCode, msg: impl Into<String>) -> Self {
        Self {
            code: code.as_str(),
            msg: msg.into(),
        }
    }
}

/// A reply envelope.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
pub enum Reply {
    Ok { id: u64, ok: Box<Response> },
    Err { id: Option<u64>, err: ErrorBody },
}

#[cfg(test)]
mod tests {
    use super::*;
    use onepass_core::site_password::Source;
    use serde_json::{Value, json};

    /// Parses the wire string, checks the id and op, and checks that
    /// serializing gives back the same JSON value.
    fn round_trip(wire: &str, id: u64, op: &str) -> Request {
        let req: Request = serde_json::from_str(wire).unwrap();
        assert_eq!(req.id(), id);
        assert_eq!(req.op(), op);
        let back: Value = serde_json::to_value(&req).unwrap();
        let orig: Value = serde_json::from_str(wire).unwrap();
        assert_eq!(back, orig);
        req
    }

    #[test]
    fn request_json_round_trip_status() {
        round_trip(r#"{"id":1,"op":"status"}"#, 1, "status");
    }

    #[test]
    fn request_json_round_trip_unlock() {
        round_trip(r#"{"id":2,"op":"unlock"}"#, 2, "unlock");
    }

    #[test]
    fn request_json_round_trip_vaults() {
        round_trip(r#"{"op":"vaults","id":3}"#, 3, "vaults");
    }

    #[test]
    fn request_json_round_trip_list_for_origin() {
        let r = round_trip(
            r#"{"id":4,"op":"list_for_origin","ctx":"menu","origin":"https://atlas-cloud.test"}"#,
            4,
            "list_for_origin",
        );
        assert!(matches!(r, Request::ListForOrigin { ctx: Ctx::Menu, .. }));
    }

    #[test]
    fn request_json_round_trip_search() {
        round_trip(
            r#"{"id":5,"op":"search","ctx":"popup","query":"atlas"}"#,
            5,
            "search",
        );
    }

    #[test]
    fn request_json_round_trip_list_fillable() {
        let r = round_trip(
            r#"{"id":6,"op":"list_fillable","ctx":"menu","origin":"https://atlas-cloud.test","kind":"card"}"#,
            6,
            "list_fillable",
        );
        assert!(matches!(
            r,
            Request::ListFillable {
                kind: FillKind::Card,
                ..
            }
        ));
    }

    #[test]
    fn request_json_round_trip_fill_login() {
        let r = round_trip(
            r#"{"id":7,"op":"fill_login","ctx":"overlay","item_id":"x","origin":"https://atlas-cloud.test","fields":["username","password","totp"]}"#,
            7,
            "fill_login",
        );
        let Request::FillLogin { fields, .. } = r else {
            panic!()
        };
        assert_eq!(
            fields,
            vec![FillField::Username, FillField::Password, FillField::Totp]
        );
    }

    #[test]
    fn request_json_round_trip_fill_card() {
        round_trip(
            r#"{"id":8,"op":"fill_card","ctx":"menu","item_id":"x","origin":"https://atlas-cloud.test"}"#,
            8,
            "fill_card",
        );
    }

    #[test]
    fn request_json_round_trip_fill_identity() {
        round_trip(
            r#"{"id":9,"op":"fill_identity","ctx":"menu","item_id":"x","origin":"https://atlas-cloud.test"}"#,
            9,
            "fill_identity",
        );
    }

    #[test]
    fn request_json_round_trip_totp() {
        round_trip(
            r#"{"id":10,"op":"totp","ctx":"popup","item_id":"x"}"#,
            10,
            "totp",
        );
        round_trip(
            r#"{"id":11,"op":"totp","ctx":"chain","item_id":"x","origin":"https://atlas-cloud.test"}"#,
            11,
            "totp",
        );
    }

    #[test]
    fn request_json_round_trip_reveal() {
        round_trip(
            r#"{"id":12,"op":"reveal","ctx":"popup","item_id":"x","field":"password"}"#,
            12,
            "reveal",
        );
    }

    #[test]
    fn request_json_round_trip_check_credentials() {
        let r = round_trip(
            r#"{"id":13,"op":"check_credentials","ctx":"save_prompt","origin":"https://atlas-cloud.test","username":"alex@atlas.dev","password":"pw-x"}"#,
            13,
            "check_credentials",
        );
        assert!(!format!("{r:?}").contains("pw-x"));
    }

    #[test]
    fn request_json_round_trip_save_login() {
        let r = round_trip(
            r#"{"id":14,"op":"save_login","ctx":"save_prompt","origin":"https://atlas-cloud.test","title":"Atlas","username":"alex@atlas.dev","password":"pw-y","vault_id":"v","rule":"exact_host","tags":["work"]}"#,
            14,
            "save_login",
        );
        assert!(matches!(
            r,
            Request::SaveLogin {
                rule: Rule::ExactHost,
                ..
            }
        ));
    }

    #[test]
    fn request_json_round_trip_update_password() {
        round_trip(
            r#"{"id":15,"op":"update_password","ctx":"save_prompt","item_id":"x","origin":"https://atlas-cloud.test","password":"pw-z"}"#,
            15,
            "update_password",
        );
        round_trip(
            r#"{"id":15,"op":"update_password","ctx":"save_prompt","item_id":"x","origin":"https://atlas-cloud.test","password":"pw-z","weak_by_site":true}"#,
            15,
            "update_password",
        );
        assert!(
            serde_json::from_str::<Request>(
                r#"{"id":15,"op":"update_password","ctx":"save_prompt","item_id":"x","origin":"https://atlas-cloud.test","password":"pw-z","weak":true}"#,
            )
            .is_err()
        );
    }

    #[test]
    fn request_json_round_trip_confirm_pending() {
        round_trip(
            r#"{"id":16,"op":"confirm_pending","ctx":"save_prompt","item_id":"x","origin":"https://atlas-cloud.test","username":"alex@atlas.dev"}"#,
            16,
            "confirm_pending",
        );
    }

    #[test]
    fn report_round_trips() {
        let report = GenerationReport {
            length: 14,
            lower: true,
            upper: true,
            digit: true,
            special: false,
            sources: vec![Source::PasswordRules, Source::Quirks],
            dropped: vec![Source::Hints],
            fallback: false,
            readable_fell_back: false,
            weak_by_site: false,
            entropy_bits: 80.5,
        };
        let reply = Reply::Ok {
            id: 1,
            ok: Box::new(Response::Generate {
                password: "pw".into(),
                entropy_bits: 80.5,
                report: Some(report.clone()),
            }),
        };
        let v = serde_json::to_value(&reply).unwrap();
        assert_eq!(
            v["ok"]["report"]["sources"],
            json!(["password_rules", "quirks"])
        );
        let back: GenerationReport = serde_json::from_value(v["ok"]["report"].clone()).unwrap();
        assert_eq!(back, report);
        let none = Response::Generate {
            password: "pw".into(),
            entropy_bits: 1.0,
            report: None,
        };
        assert!(serde_json::to_value(&none).unwrap().get("report").is_none());
    }

    #[test]
    fn request_json_round_trip_generate_smart() {
        let r = round_trip(
            r#"{"id":18,"op":"generate","ctx":"menu","recipe":{"kind":"smart","profile":"custom","length":16,"narrow":1,"context":{"rules":["minlength: 8;"],"max_length":20,"hint_text":"x"}},"origin":"https://a.test"}"#,
            18,
            "generate",
        );
        let Request::Generate { recipe, origin, .. } = r else {
            panic!()
        };
        assert_eq!(recipe.profile, Some(RecipeProfile::Custom));
        assert_eq!(recipe.narrow, Some(1));
        assert_eq!(recipe.context.unwrap().max_length, Some(20));
        assert_eq!(origin.as_deref(), Some("https://a.test"));
        assert!(
            serde_json::from_str::<Request>(
                r#"{"id":1,"op":"generate","ctx":"menu","recipe":{"kind":"smart","context":{"x":1}}}"#
            )
            .is_err()
        );
    }

    #[test]
    fn request_json_round_trip_generate() {
        let r = round_trip(
            r#"{"id":16,"op":"generate","ctx":"menu","recipe":{"kind":"random","length":24,"symbols":true}}"#,
            16,
            "generate",
        );
        let Request::Generate { recipe, .. } = r else {
            panic!()
        };
        assert_eq!(recipe.kind, RecipeKind::Random);
        assert_eq!(recipe.length, Some(24));
        round_trip(
            r#"{"id":17,"op":"generate","ctx":"popup","recipe":{"kind":"memorable"}}"#,
            17,
            "generate",
        );
    }

    #[test]
    fn request_json_round_trip_provider_accounts() {
        let r = round_trip(
            r#"{"id":18,"op":"provider_accounts","ctx":"menu","provider":"google","origin":"https://accounts.google.com"}"#,
            18,
            "provider_accounts",
        );
        assert!(matches!(
            r,
            Request::ProviderAccounts {
                provider: ProviderId::Google,
                ..
            }
        ));
    }

    #[test]
    fn request_json_round_trip_fill_provider() {
        round_trip(
            r#"{"id":19,"op":"fill_provider","ctx":"chain","account_item_id":"a","provider":"google","provider_origin":"https://accounts.google.com","site_origin":"https://atlas-cloud.test","fields":["username"]}"#,
            19,
            "fill_provider",
        );
    }

    #[test]
    fn request_json_round_trip_link_provider() {
        round_trip(
            r#"{"id":20,"op":"link_provider","ctx":"save_prompt","site_origin":"https://atlas-cloud.test","provider":"google","account_item_id":"a"}"#,
            20,
            "link_provider",
        );
    }

    #[test]
    fn request_json_round_trip_fill_salt() {
        round_trip(
            r#"{"id":21,"op":"fill_salt","ctx":"menu"}"#,
            21,
            "fill_salt",
        );
    }

    #[test]
    fn request_json_round_trip_plan_fill() {
        let r = round_trip(
            r#"{"id":22,"op":"plan_fill","ctx":"menu","origin":"https://atlas-cloud.test","context":{"origin":"https://atlas-cloud.test","top_origin":"https://atlas-cloud.test","frame_kind":"top","forms":[{"form_ref":"f","intent_hints":{"kind":"login","signup_words":false,"reset_words":false,"checkout_words":false,"ignore":false},"step_index":null,"fields":[{"field_ref":"u","role":"username","confidence":0.5,"visible":true,"prefilled":"empty"}],"buttons":[]}],"typed_username_hash":null}}"#,
            22,
            "plan_fill",
        );
        let Request::PlanFill { context, .. } = r else {
            panic!()
        };
        assert_eq!(context.forms[0].fields[0].role, Some(FieldRole::Username));
    }

    #[test]
    fn request_json_round_trip_note_fill() {
        let r = round_trip(
            r#"{"id":23,"op":"note_fill","ctx":"chain","item_id":"x","origin":"https://atlas-cloud.test","roles":["username","current_password"],"intent":"login","steps":["fill","provider_click"]}"#,
            23,
            "note_fill",
        );
        let Request::NoteFill { steps, .. } = r else {
            panic!()
        };
        assert_eq!(StepKind::from(steps[1]), StepKind::ProviderClick);
    }

    #[test]
    fn request_json_round_trip_forget_site() {
        round_trip(
            r#"{"id":24,"op":"forget_site","ctx":"popup","site":"atlas-cloud.test"}"#,
            24,
            "forget_site",
        );
    }

    #[test]
    fn request_json_round_trip_passkey_list() {
        let r = round_trip(
            r#"{"id":25,"op":"passkey_list","ctx":"passkey","origin":"https://atlas-cloud.test","rp_id":"atlas-cloud.test"}"#,
            25,
            "passkey_list",
        );
        assert!(matches!(
            r,
            Request::PasskeyList {
                ctx: Ctx::Passkey,
                ..
            }
        ));
    }

    #[test]
    fn request_json_round_trip_passkey_get() {
        round_trip(
            r#"{"id":26,"op":"passkey_get","ctx":"chain","origin":"https://atlas-cloud.test","top_origin":"https://atlas-cloud.test","rp_id":"atlas-cloud.test","item_id":"x","credential_id":"AQID","challenge":"BAUG"}"#,
            26,
            "passkey_get",
        );
    }

    #[test]
    fn request_json_round_trip_passkey_create() {
        round_trip(
            r#"{"id":27,"op":"passkey_create","ctx":"passkey","origin":"https://atlas-cloud.test","top_origin":"https://atlas-cloud.test","rp_id":"atlas-cloud.test","user_name":"alex","user_handle":"AQ","challenge":"BAUG","exclude":["AQID"]}"#,
            27,
            "passkey_create",
        );
        round_trip(
            r#"{"id":28,"op":"passkey_create","ctx":"passkey","origin":"https://atlas-cloud.test","top_origin":"https://atlas-cloud.test","rp_id":"atlas-cloud.test","user_name":"alex","user_handle":"AQ","challenge":"BAUG","exclude":[],"vault_id":"v"}"#,
            28,
            "passkey_create",
        );
    }

    #[test]
    fn passkey_replies_have_the_wire_shape() {
        let a = Response::PasskeyAssertion {
            credential_id: "c".into(),
            client_data_json: "j".into(),
            authenticator_data: "a".into(),
            signature: "s".into(),
            user_handle: "u".into(),
        };
        assert_eq!(
            serde_json::to_value(&a).unwrap(),
            json!({"credential_id":"c","client_data_json":"j","authenticator_data":"a",
                   "signature":"s","user_handle":"u"})
        );
        let l = Response::Passkeys {
            passkeys: vec![PasskeySummary {
                item_id: "i".into(),
                vault_id: "v".into(),
                vault_name: "Perso".into(),
                title: "Atlas".into(),
                user_name: "alex".into(),
                credential_id: "c".into(),
            }],
        };
        assert_eq!(
            serde_json::to_value(&l).unwrap(),
            json!({"passkeys":[{"item_id":"i","vault_id":"v","vault_name":"Perso",
                   "title":"Atlas","user_name":"alex","credential_id":"c"}]})
        );
    }

    #[test]
    fn plan_has_the_wire_shape() {
        let item = onepass_core::Id([7u8; 16]);
        let plan = FillPlan {
            intent: Intent::Signup,
            groups: vec![
                onepass_core::fill_plan::PlanGroup {
                    form_ref: "f".into(),
                    item: GroupItem::Item(item),
                    kind: GroupKind::Login,
                    fields: vec![("u".into(), FieldRole::Email)],
                },
                onepass_core::fill_plan::PlanGroup {
                    form_ref: "f".into(),
                    item: GroupItem::GeneratedPassword,
                    kind: GroupKind::GeneratedPassword,
                    fields: vec![("p".into(), FieldRole::NewPassword)],
                },
            ],
            action: Action::Fill,
            confidence: Confidence::Medium,
            alternatives: vec![item],
            reasons: vec![ReasonCode::Tie, ReasonCode::PasskeyOffered],
            passkey: Some(PasskeyOffer {
                form_ref: "f".into(),
                button_ref: "b".into(),
            }),
        };
        let reply = Response::Plan { plan: plan.into() };
        let id = "07070707-0707-0707-0707-070707070707";
        assert_eq!(
            serde_json::to_value(&reply).unwrap(),
            json!({"plan":{"intent":"signup","action":"fill","confidence":"medium",
                "alternatives":[id],"reasons":["tie","passkey_offered"],
                "passkey":{"form_ref":"f","button_ref":"b"},
                "groups":[
                    {"form_ref":"f","kind":"login","item_id":id,
                     "fields":[{"field_ref":"u","role":"email"}]},
                    {"form_ref":"f","kind":"generated_password","item_id":null,
                     "fields":[{"field_ref":"p","role":"new_password"}]}]}})
        );
    }

    #[test]
    fn unknown_field_rejected() {
        for wire in [
            r#"{"id":1,"op":"status","extra":1}"#,
            r#"{"id":1,"op":"search","ctx":"popup","query":"a","x":true}"#,
            r#"{"id":1,"op":"generate","ctx":"menu","recipe":{"kind":"pin","digits":4}}"#,
            r#"{"id":1,"op":"nope"}"#,
            r#"{"id":1,"op":"search","ctx":"page","query":"a"}"#,
            r#"{"id":1,"op":"provider_accounts","ctx":"menu","provider":"Google","origin":"https://a.test"}"#,
            r#"{"id":1,"op":"fill_salt","ctx":"menu","x":1}"#,
            r#"{"id":1,"op":"note_fill","ctx":"chain","item_id":"x","origin":"https://a.test","roles":[],"intent":"login","steps":["Fill"]}"#,
            r#"{"id":1,"op":"forget_site","ctx":"popup"}"#,
            r#"{"id":1,"op":"passkey_get","ctx":"passkey","origin":"https://a.test","top_origin":"https://a.test","rp_id":"a.test","item_id":"x","credential_id":"AQ","challenge":"AQ","client_data_json":"e30"}"#,
            r#"{"id":1,"op":"passkey_list","ctx":"page","origin":"https://a.test","rp_id":"a.test"}"#,
            r#"{"id":1,"op":"passkey_create","ctx":"passkey","origin":"https://a.test","rp_id":"a.test","user_name":"a","challenge":"AQ"}"#,
        ] {
            assert!(serde_json::from_str::<Request>(wire).is_err(), "{wire}");
        }
    }

    #[test]
    fn replies_have_the_wire_shape() {
        let ok = Reply::Ok {
            id: 3,
            ok: Box::new(Response::Totp {
                code: "123456".into(),
                remaining: 12,
            }),
        };
        assert_eq!(
            serde_json::to_value(&ok).unwrap(),
            json!({"id":3,"ok":{"code":"123456","remaining":12}})
        );
        let empty = Reply::Ok {
            id: 4,
            ok: Box::new(Response::Empty {}),
        };
        assert_eq!(
            serde_json::to_value(&empty).unwrap(),
            json!({"id":4,"ok":{}})
        );
        let err = Reply::Err {
            id: None,
            err: ErrorBody::new(AppErrorCode::Invalid, "malformed request"),
        };
        assert_eq!(
            serde_json::to_value(&err).unwrap(),
            json!({"id":null,"err":{"code":"invalid","msg":"malformed request"}})
        );
        assert!(!format!("{ok:?}").contains("123456"));
    }

    #[test]
    fn summary_has_the_wire_shape() {
        let s = Summary {
            item_id: "i".into(),
            vault_id: "v".into(),
            vault_name: "Perso".into(),
            title: "Atlas Cloud".into(),
            subtitle: "alex@atlas.dev".into(),
            kind: SummaryKind::Login,
            icon_letter: "A".into(),
            icon_color: "#000000".into(),
            has_password: true,
            has_totp: false,
            methods: vec![Method {
                provider: ProviderId::Google,
                account_email: "alex.perso@example.com".into(),
            }],
            match_quality: None,
        };
        let v = serde_json::to_value(&s).unwrap();
        assert_eq!(v["match"], Value::Null);
        assert_eq!(v["kind"], "login");
        assert_eq!(v["methods"][0]["provider"], "google");
        assert_eq!(v.as_object().unwrap().len(), 12);
    }
}
