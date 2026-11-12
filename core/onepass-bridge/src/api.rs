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
use crate::agent::{AgentError, AgentJob, AgentKind, FillResult, ProbeResult};
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
    /// A fill an MCP agent asked for and the holder approved (spec
    /// 2026-11-07-agent-browser-fill 5). Accepted for `plan_fill`,
    /// `fill_login` and `fill_card` only, each with `agent_request`.
    Agent,
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
            Self::Agent => "agent",
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

/// Address typed in a page form (`check_identity`, `save_identity`).
/// Every part may be left out or empty.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AddressIn {
    pub line1: String,
    pub line2: String,
    pub city: String,
    pub postal_code: String,
    pub region: String,
    pub country: String,
}

/// An application request. Every operation carries the request `id`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Status {
        id: u64,
    },
    /// `origin`: the page the user's gesture was on (https, or http on a
    /// loopback host), for the app to bind its unlock to it. Optional: an
    /// older extension sends none.
    Unlock {
        id: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        origin: Option<String>,
    },
    /// `origin`: the page a new item would be saved for; the vaults of the
    /// account it routes to come first. Optional.
    Vaults {
        id: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        origin: Option<String>,
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
    /// `agent_request`: with `ctx` `agent` only, the agent request whose
    /// ticket this fill spends.
    FillLogin {
        id: u64,
        ctx: Ctx,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        agent_request: Option<u64>,
        item_id: String,
        origin: String,
        fields: Vec<FillField>,
    },
    FillCard {
        id: u64,
        ctx: Ctx,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        agent_request: Option<u64>,
        item_id: String,
        origin: String,
    },
    FillIdentity {
        id: u64,
        ctx: Ctx,
        item_id: String,
        origin: String,
        /// Documents of the identity to add, only those the form asks for.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        extras: Vec<Extra>,
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
    /// A card typed by hand in a checkout form: is it stored already?
    /// `exp_month` and `exp_year` (2 or 4 digits) may be empty. Same reply
    /// as `check_credentials`. Context `save_prompt` only.
    CheckCard {
        id: u64,
        ctx: Ctx,
        origin: String,
        number: SecretString,
        #[serde(default)]
        exp_month: String,
        #[serde(default)]
        exp_year: String,
    },
    /// Saves a typed card: a new CreditCard in `vault_id`, or, with
    /// `item_id`, the expiry (and a missing cardholder) of the stored card
    /// holding this number. Never a CVV. Context `save_prompt` only.
    SaveCard {
        id: u64,
        ctx: Ctx,
        origin: String,
        vault_id: String,
        #[serde(default)]
        title: String,
        #[serde(default)]
        cardholder: String,
        number: SecretString,
        #[serde(default)]
        exp_month: String,
        #[serde(default)]
        exp_year: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        item_id: Option<String>,
    },
    /// An identity typed in a shipping or contact form: does a stored
    /// Identity hold every non-empty value already? Context `save_prompt`
    /// only.
    CheckIdentity {
        id: u64,
        ctx: Ctx,
        origin: String,
        #[serde(default)]
        given_name: String,
        #[serde(default)]
        family_name: String,
        #[serde(default)]
        email: String,
        #[serde(default)]
        tel: String,
        #[serde(default)]
        organization: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        address: Option<AddressIn>,
    },
    /// Saves a typed identity as a new Identity in `vault_id`. Context
    /// `save_prompt` only.
    SaveIdentity {
        id: u64,
        ctx: Ctx,
        origin: String,
        vault_id: String,
        #[serde(default)]
        title: String,
        #[serde(default)]
        given_name: String,
        #[serde(default)]
        family_name: String,
        #[serde(default)]
        email: String,
        #[serde(default)]
        tel: String,
        #[serde(default)]
        organization: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        address: Option<AddressIn>,
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
        /// A generated password written to an existing Login from a
        /// change-password form (spec 5.2): the item gets `onepass:pending`
        /// in the same write, and the form's submission confirms it
        /// (`confirm_pending`).
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        pending: bool,
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
    /// Delete for good a Login this session saved through `save_login`
    /// in the last 60 s, for the same site and not edited since (the
    /// toast's Undo). Anything else is `not_found`.
    UndoSave {
        id: u64,
        ctx: Ctx,
        item_id: String,
        origin: String,
    },
    /// Delete for good the pending Login `item_id` (tag `onepass:pending`):
    /// a generated password the save card moved into another login (spec
    /// 5.2). Only one this session wrote through `save_login` as pending,
    /// for the same site, still pending and untouched since; anything else
    /// is `not_found`.
    DiscardPending {
        id: u64,
        ctx: Ctx,
        item_id: String,
        origin: String,
    },
    /// Rename, change the username of, or move to another vault a Login
    /// this session saved through `save_login` in the last 600 s, for the
    /// same site and not edited since (the toast's Edit). Anything else is
    /// `not_found`. A move saves the login in `vault_id` first, then deletes
    /// the old item: `item_id` in the answer names the login as it is now.
    AmendSave {
        id: u64,
        ctx: Ctx,
        item_id: String,
        origin: String,
        title: String,
        username: String,
        vault_id: String,
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
    /// be the same. `agent_request`: with `ctx` `agent` only, a request
    /// holding a live ticket (not spent by the plan).
    PlanFill {
        id: u64,
        ctx: Ctx,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        agent_request: Option<u64>,
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
    /// Long poll of the extension's agent session: the next agent job, or
    /// none after `agent::WAIT_TIMEOUT`.
    AgentWait {
        id: u64,
    },
    /// The extension's answer to a probe job.
    AgentProbeResult {
        id: u64,
        request_id: u64,
        #[serde(with = "agent_result")]
        result: std::result::Result<ProbeWire, String>,
    },
    /// The extension's answer to a fill job.
    AgentFillResult {
        id: u64,
        request_id: u64,
        #[serde(with = "agent_result")]
        result: std::result::Result<FillWire, String>,
    },
}

impl Request {
    /// The request id.
    pub fn id(&self) -> u64 {
        match self {
            Self::Status { id }
            | Self::Unlock { id, .. }
            | Self::Vaults { id, .. }
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
            | Self::CheckCard { id, .. }
            | Self::SaveCard { id, .. }
            | Self::CheckIdentity { id, .. }
            | Self::SaveIdentity { id, .. }
            | Self::UpdatePassword { id, .. }
            | Self::ConfirmPending { id, .. }
            | Self::UndoSave { id, .. }
            | Self::DiscardPending { id, .. }
            | Self::AmendSave { id, .. }
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
            | Self::PasskeyCreate { id, .. }
            | Self::AgentWait { id }
            | Self::AgentProbeResult { id, .. }
            | Self::AgentFillResult { id, .. } => *id,
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
            Self::CheckCard { .. } => "check_card",
            Self::SaveCard { .. } => "save_card",
            Self::CheckIdentity { .. } => "check_identity",
            Self::SaveIdentity { .. } => "save_identity",
            Self::UpdatePassword { .. } => "update_password",
            Self::ConfirmPending { .. } => "confirm_pending",
            Self::UndoSave { .. } => "undo_save",
            Self::DiscardPending { .. } => "discard_pending",
            Self::AmendSave { .. } => "amend_save",
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
            Self::AgentWait { .. } => "agent_wait",
            Self::AgentProbeResult { .. } => "agent_probe_result",
            Self::AgentFillResult { .. } => "agent_fill_result",
        }
    }

    /// The context of the request, for those that carry one.
    pub fn ctx(&self) -> Option<Ctx> {
        match self {
            Self::ListForOrigin { ctx, .. }
            | Self::Search { ctx, .. }
            | Self::ListFillable { ctx, .. }
            | Self::FillLogin { ctx, .. }
            | Self::FillCard { ctx, .. }
            | Self::FillIdentity { ctx, .. }
            | Self::Totp { ctx, .. }
            | Self::Reveal { ctx, .. }
            | Self::CheckCredentials { ctx, .. }
            | Self::SaveLogin { ctx, .. }
            | Self::CheckCard { ctx, .. }
            | Self::SaveCard { ctx, .. }
            | Self::CheckIdentity { ctx, .. }
            | Self::SaveIdentity { ctx, .. }
            | Self::UpdatePassword { ctx, .. }
            | Self::ConfirmPending { ctx, .. }
            | Self::UndoSave { ctx, .. }
            | Self::DiscardPending { ctx, .. }
            | Self::AmendSave { ctx, .. }
            | Self::Generate { ctx, .. }
            | Self::ProviderAccounts { ctx, .. }
            | Self::FillProvider { ctx, .. }
            | Self::LinkProvider { ctx, .. }
            | Self::FillSalt { ctx, .. }
            | Self::PlanFill { ctx, .. }
            | Self::NoteFill { ctx, .. }
            | Self::ForgetSite { ctx, .. }
            | Self::NoteAutofill { ctx, .. }
            | Self::PasskeyList { ctx, .. }
            | Self::PasskeyGet { ctx, .. }
            | Self::PasskeyCreate { ctx, .. } => Some(*ctx),
            Self::Status { .. }
            | Self::Unlock { .. }
            | Self::Vaults { .. }
            | Self::ClientInfo { .. }
            | Self::AgentWait { .. }
            | Self::AgentProbeResult { .. }
            | Self::AgentFillResult { .. } => None,
        }
    }

    /// `agent_request` of the requests that carry one.
    pub fn agent_request(&self) -> Option<u64> {
        match self {
            Self::FillLogin { agent_request, .. }
            | Self::FillCard { agent_request, .. }
            | Self::PlanFill { agent_request, .. } => *agent_request,
            _ => None,
        }
    }
}

/// The tab an extension found for a probe job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeWire {
    pub tab_title: String,
    pub origin: String,
    pub document_id: String,
}

impl From<ProbeWire> for ProbeResult {
    fn from(p: ProbeWire) -> ProbeResult {
        ProbeResult {
            tab_title: p.tab_title,
            origin: p.origin,
            document_id: p.document_id,
        }
    }
}

/// What a fill job wrote: field names, never values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FillWire {
    pub filled: Vec<String>,
    pub submitted: bool,
}

impl From<FillWire> for FillResult {
    fn from(f: FillWire) -> FillResult {
        FillResult {
            filled: f.filled,
            submitted: f.submitted,
        }
    }
}

/// The error code of a probe or fill job, as the extension names it. An
/// unknown code is a refusal. `timeout`: the host refused the values
/// because the ticket expired or was spent (`not_allowed`).
pub fn agent_error(code: &str) -> AgentError {
    match code {
        "tab_mismatch" => AgentError::TabMismatch,
        "timeout" => AgentError::Timeout,
        "origin_mismatch" => AgentError::OriginMismatch,
        "cross_site_frame" => AgentError::CrossSiteFrame,
        "no_fields" => AgentError::NoFields,
        _ => AgentError::Denied,
    }
}

/// A job result on the wire: `{"ok": {...}}` or `{"err": "<code>"}`.
mod agent_result {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    #[derive(Serialize)]
    #[serde(rename_all = "snake_case")]
    enum Out<'a, T> {
        Ok(&'a T),
        Err(&'a str),
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "snake_case")]
    enum In<T> {
        Ok(T),
        Err(String),
    }

    pub fn serialize<S: Serializer, T: Serialize>(
        r: &Result<T, String>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        match r {
            Ok(v) => Out::Ok(v),
            Err(e) => Out::Err(e.as_str()),
        }
        .serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
        d: D,
    ) -> Result<Result<T, String>, D::Error> {
        Ok(match In::deserialize(d)? {
            In::Ok(v) => Ok(v),
            In::Err(e) => Err(e),
        })
    }
}

/// What an agent fill writes, on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentKindWire {
    Login,
    Card,
}

/// A job for the extension: `{"job":"probe","request_id","url"}` or
/// `{"job":"fill","request_id","item_id","kind","submit","document_id"}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "job", rename_all = "snake_case")]
pub enum AgentJobWire {
    Probe {
        request_id: u64,
        url: String,
    },
    Fill {
        request_id: u64,
        item_id: String,
        kind: AgentKindWire,
        submit: bool,
        document_id: String,
    },
}

impl From<AgentJob> for AgentJobWire {
    fn from(job: AgentJob) -> AgentJobWire {
        match job {
            AgentJob::Probe { request_id, url } => AgentJobWire::Probe { request_id, url },
            AgentJob::Fill {
                request_id,
                item_id,
                kind,
                submit,
                document_id,
            } => AgentJobWire::Fill {
                request_id,
                item_id,
                kind: match kind {
                    AgentKind::Login => AgentKindWire::Login,
                    AgentKind::Card => AgentKindWire::Card,
                },
                submit,
                document_id,
            },
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
    /// The match is an associated domain (sent as `domain` in `match`, the
    /// only values an extension accepts there): a UI may say so. Left out
    /// when false.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub associated: bool,
    /// Label of the item's account when the host offers items of several
    /// accounts; left out otherwise. An older extension ignores it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VaultEntry {
    pub id: String,
    pub name: String,
    pub color: Option<String>,
    /// As `Summary::account`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    /// A shared vault, left out when false: the extension never saves
    /// into it without a card.
    #[serde(skip_serializing_if = "std::ops::Not::not", default)]
    pub shared: bool,
}

/// What `fill_identity` may add to the identity's own values, on request
/// only: the holder's passport, driver license, the site's loyalty number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Extra {
    Passport,
    DriverLicense,
    Loyalty,
}

/// The passport associated with the identity of a `fill_identity`. Dates
/// `YYYY-MM-DD`, sex `f`, `m` or `x`; a value left out is unknown.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct PassportOut {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_names: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub number: Option<SecretString>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuing_country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issued_on: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiry: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nationality: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub birth_date: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub birth_place: Option<String>,
}

/// The driver license associated with the identity of a `fill_identity`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct LicenseOut {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub number: Option<SecretString>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issued_on: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiry: Option<String>,
}

/// The site's loyalty program of a `fill_identity`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LoyaltyOut {
    pub number: SecretString,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub program: Option<String>,
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

/// The `ok` payload of a reply, one shape per operation. One value lives
/// for one reply and is serialized at once: the size of the identity
/// variant costs nothing worth a box.
#[allow(clippy::large_enum_variant)]
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
        #[serde(skip_serializing_if = "Option::is_none")]
        honorific: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        middle_name: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        birth_name: Option<String>,
        /// `f`, `m` or `x`.
        #[serde(skip_serializing_if = "Option::is_none")]
        sex: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        birth_place: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        nationality: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        job_title: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        department: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        website: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        work_tel: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        vat_number: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        company_registration: Option<String>,
        /// `extras` only.
        #[serde(skip_serializing_if = "Option::is_none")]
        passport: Option<PassportOut>,
        #[serde(skip_serializing_if = "Option::is_none")]
        driver_license: Option<LicenseOut>,
        #[serde(skip_serializing_if = "Option::is_none")]
        loyalty: Option<LoyaltyOut>,
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
    /// `agent_wait`: the next job, `null` when none came in time.
    AgentJob {
        job: Option<AgentJobWire>,
    },
    /// `agent_probe_result` and `agent_fill_result`: `{}`.
    Ack {},
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
    fn request_json_round_trip_fill_identity_with_extras() {
        let r = round_trip(
            r#"{"id":9,"op":"fill_identity","ctx":"menu","item_id":"x","origin":"https://atlas-cloud.test","extras":["passport","driver_license","loyalty"]}"#,
            9,
            "fill_identity",
        );
        let Request::FillIdentity { extras, .. } = r else {
            panic!()
        };
        assert_eq!(
            extras,
            [Extra::Passport, Extra::DriverLicense, Extra::Loyalty]
        );
        let bad = r#"{"id":9,"op":"fill_identity","ctx":"menu","item_id":"x","origin":"https://atlas-cloud.test","extras":["id_card"]}"#;
        assert!(serde_json::from_str::<Request>(bad).is_err());
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
    fn request_json_round_trip_check_card() {
        let r = round_trip(
            r#"{"id":31,"op":"check_card","ctx":"save_prompt","origin":"https://shop.test","number":"4242 4242 4242 4242","exp_month":"04","exp_year":"29"}"#,
            31,
            "check_card",
        );
        assert!(!format!("{r:?}").contains("4242"));
        // The expiry may be left out.
        let r: Request = serde_json::from_str(
            r#"{"id":32,"op":"check_card","ctx":"save_prompt","origin":"https://shop.test","number":"4242424242424242"}"#,
        )
        .unwrap();
        assert!(matches!(r, Request::CheckCard { ref exp_month, .. } if exp_month.is_empty()));
        // A CVV is never taken.
        assert!(
            serde_json::from_str::<Request>(
                r#"{"id":33,"op":"check_card","ctx":"save_prompt","origin":"https://shop.test","number":"4242424242424242","cvv":"737"}"#,
            )
            .is_err()
        );
    }

    #[test]
    fn request_json_round_trip_save_card() {
        let r = round_trip(
            r#"{"id":34,"op":"save_card","ctx":"save_prompt","origin":"https://shop.test","vault_id":"v","title":"","cardholder":"Alex Martin","number":"4242424242424242","exp_month":"4","exp_year":"2029"}"#,
            34,
            "save_card",
        );
        assert!(!format!("{r:?}").contains("4242"));
        let r = round_trip(
            r#"{"id":35,"op":"save_card","ctx":"save_prompt","origin":"https://shop.test","vault_id":"v","title":"Visa","cardholder":"","number":"4242424242424242","exp_month":"","exp_year":"","item_id":"x"}"#,
            35,
            "save_card",
        );
        assert!(matches!(
            r,
            Request::SaveCard {
                item_id: Some(_),
                ..
            }
        ));
        assert!(
            serde_json::from_str::<Request>(
                r#"{"id":36,"op":"save_card","ctx":"save_prompt","origin":"https://shop.test","vault_id":"v","title":"","cardholder":"","number":"4242424242424242","exp_month":"","exp_year":"","cvv":"737"}"#,
            )
            .is_err()
        );
    }

    #[test]
    fn request_json_round_trip_check_identity() {
        let r = round_trip(
            r#"{"id":37,"op":"check_identity","ctx":"save_prompt","origin":"https://shop.test","given_name":"Alex","family_name":"Martin","email":"alex@atlas.dev","tel":"+33 6 00 00 00 00","organization":"","address":{"line1":"1 rue de l'Exemple","line2":"","city":"Lyon","postal_code":"69000","region":"","country":"FR"}}"#,
            37,
            "check_identity",
        );
        let Request::CheckIdentity { address, .. } = r else {
            panic!()
        };
        assert_eq!(address.unwrap().city, "Lyon");
        round_trip(
            r#"{"id":38,"op":"check_identity","ctx":"save_prompt","origin":"https://shop.test","given_name":"","family_name":"","email":"alex@atlas.dev","tel":"","organization":""}"#,
            38,
            "check_identity",
        );
        // Address parts may be left out; unknown parts are refused.
        let r: Request = serde_json::from_str(
            r#"{"id":39,"op":"check_identity","ctx":"save_prompt","origin":"https://shop.test","address":{"city":"Lyon"}}"#,
        )
        .unwrap();
        assert!(
            matches!(r, Request::CheckIdentity { address: Some(ref a), .. } if a.line1.is_empty())
        );
        assert!(
            serde_json::from_str::<Request>(
                r#"{"id":40,"op":"check_identity","ctx":"save_prompt","origin":"https://shop.test","address":{"street":"x"}}"#,
            )
            .is_err()
        );
    }

    #[test]
    fn request_json_round_trip_save_identity() {
        round_trip(
            r#"{"id":41,"op":"save_identity","ctx":"save_prompt","origin":"https://shop.test","vault_id":"v","title":"","given_name":"Alex","family_name":"Martin","email":"","tel":"","organization":"Atlas","address":{"line1":"1 rue","line2":"","city":"Lyon","postal_code":"69000","region":"","country":"FR"}}"#,
            41,
            "save_identity",
        );
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
        // Spec 5.2: the change-password form's update, tagged pending.
        round_trip(
            r#"{"id":15,"op":"update_password","ctx":"save_prompt","item_id":"x","origin":"https://atlas-cloud.test","password":"pw-z","pending":true}"#,
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
    fn request_json_round_trip_amend_save() {
        round_trip(
            r#"{"id":32,"op":"amend_save","ctx":"save_prompt","item_id":"i","origin":"https://atlas-cloud.test","title":"Atlas","username":"alex@atlas.dev","vault_id":"v"}"#,
            32,
            "amend_save",
        );
    }

    #[test]
    fn request_json_round_trip_discard_pending() {
        round_trip(
            r#"{"id":33,"op":"discard_pending","ctx":"save_prompt","item_id":"i","origin":"https://atlas-cloud.test"}"#,
            33,
            "discard_pending",
        );
    }

    #[test]
    fn request_json_round_trip_undo_save() {
        round_trip(
            r#"{"id":31,"op":"undo_save","ctx":"save_prompt","item_id":"i","origin":"https://atlas-cloud.test"}"#,
            31,
            "undo_save",
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
    fn request_json_round_trip_plan_fill_with_forms_roles() {
        let r = round_trip(
            r#"{"id":22,"op":"plan_fill","ctx":"menu","origin":"https://volair.test","context":{"origin":"https://volair.test","top_origin":"https://volair.test","frame_kind":"top","forms":[{"form_ref":"f","intent_hints":{"kind":null,"signup_words":false,"reset_words":false,"checkout_words":false,"ignore":false},"step_index":null,"fields":[{"field_ref":"a","role":"honorific_prefix","confidence":0.5,"visible":true,"prefilled":"empty"},{"field_ref":"b","role":"passport_number","confidence":0.5,"visible":true,"prefilled":"empty"},{"field_ref":"c","role":"vat_number","confidence":0.5,"visible":true,"prefilled":"empty"}],"buttons":[]}],"typed_username_hash":null}}"#,
            22,
            "plan_fill",
        );
        let Request::PlanFill { context, .. } = r else {
            panic!()
        };
        let roles: Vec<_> = context.forms[0].fields.iter().map(|f| f.role).collect();
        assert_eq!(
            roles,
            [
                Some(FieldRole::HonorificPrefix),
                Some(FieldRole::PassportNumber),
                Some(FieldRole::VatNumber)
            ]
        );
        let r = round_trip(
            r#"{"id":23,"op":"note_fill","ctx":"menu","item_id":"x","origin":"https://volair.test","roles":["email","given_name","license_number","loyalty_number"],"intent":"address","steps":["fill"]}"#,
            23,
            "note_fill",
        );
        let Request::NoteFill { roles, .. } = r else {
            panic!()
        };
        assert_eq!(roles[2], FieldRole::LicenseNumber);
        assert_eq!(roles[3], FieldRole::LoyaltyNumber);
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
    fn old_requests_without_agent_request_still_decode() {
        for (wire, op) in [
            (
                r#"{"id":7,"op":"fill_login","ctx":"overlay","item_id":"x","origin":"https://atlas-cloud.test","fields":["password"]}"#,
                "fill_login",
            ),
            (
                r#"{"id":7,"op":"fill_card","ctx":"menu","item_id":"x","origin":"https://atlas-cloud.test"}"#,
                "fill_card",
            ),
        ] {
            let r = round_trip(wire, 7, op);
            let (Request::FillLogin { agent_request, .. }
            | Request::FillCard { agent_request, .. }) = r
            else {
                panic!()
            };
            assert_eq!(agent_request, None);
        }
        let r = round_trip(
            r#"{"id":9,"op":"fill_login","ctx":"agent","agent_request":7,"item_id":"x","origin":"https://atlas-cloud.test","fields":["username","password"]}"#,
            9,
            "fill_login",
        );
        assert!(matches!(
            r,
            Request::FillLogin {
                ctx: Ctx::Agent,
                agent_request: Some(7),
                ..
            }
        ));
        let r = round_trip(
            r#"{"id":10,"op":"plan_fill","ctx":"agent","agent_request":7,"origin":"https://atlas-cloud.test","context":{"origin":"https://atlas-cloud.test","top_origin":"https://atlas-cloud.test","frame_kind":"top","forms":[],"typed_username_hash":null}}"#,
            10,
            "plan_fill",
        );
        assert!(matches!(
            r,
            Request::PlanFill {
                agent_request: Some(7),
                ..
            }
        ));
        assert_eq!(Ctx::Agent.as_str(), "agent");
    }

    #[test]
    fn agent_requests_round_trip() {
        round_trip(r#"{"id":1,"op":"agent_wait"}"#, 1, "agent_wait");
        let r = round_trip(
            r#"{"id":2,"op":"agent_probe_result","request_id":7,"result":{"ok":{"tab_title":"Atlas","origin":"https://atlas-cloud.test","document_id":"d1"}}}"#,
            2,
            "agent_probe_result",
        );
        let Request::AgentProbeResult {
            request_id, result, ..
        } = r
        else {
            panic!()
        };
        assert_eq!(request_id, 7);
        assert_eq!(result.unwrap().document_id, "d1");
        let r = round_trip(
            r#"{"id":3,"op":"agent_probe_result","request_id":7,"result":{"err":"tab_mismatch"}}"#,
            3,
            "agent_probe_result",
        );
        let Request::AgentProbeResult { result, .. } = r else {
            panic!()
        };
        assert_eq!(result.unwrap_err(), "tab_mismatch");
        let r = round_trip(
            r#"{"id":4,"op":"agent_fill_result","request_id":7,"result":{"ok":{"filled":["username","password"],"submitted":true}}}"#,
            4,
            "agent_fill_result",
        );
        let Request::AgentFillResult { result, .. } = r else {
            panic!()
        };
        let out = result.unwrap();
        assert_eq!(out.filled, vec!["username", "password"]);
        assert!(out.submitted);
        round_trip(
            r#"{"id":5,"op":"agent_fill_result","request_id":7,"result":{"err":"no_fields"}}"#,
            5,
            "agent_fill_result",
        );
        for wire in [
            r#"{"id":1,"op":"agent_wait","x":1}"#,
            r#"{"id":1,"op":"agent_probe_result","request_id":7,"result":{"Ok":{"tab_title":"a","origin":"b","document_id":"c"}}}"#,
            r#"{"id":1,"op":"agent_probe_result","request_id":7,"result":{"ok":{"tab_title":"a","origin":"b","document_id":"c","x":1}}}"#,
            r#"{"id":1,"op":"agent_fill_result","request_id":7,"result":{"ok":{"filled":[],"submitted":false,"value":"s"}}}"#,
            r#"{"id":1,"op":"agent_fill_result","request_id":7}"#,
        ] {
            assert!(serde_json::from_str::<Request>(wire).is_err(), "{wire}");
        }
    }

    #[test]
    fn agent_jobs_have_the_wire_shape() {
        let probe = Response::AgentJob {
            job: Some(AgentJobWire::from(AgentJob::Probe {
                request_id: 7,
                url: "https://github.com/login".into(),
            })),
        };
        assert_eq!(
            serde_json::to_value(&probe).unwrap(),
            json!({"job":{"job":"probe","request_id":7,"url":"https://github.com/login"}})
        );
        let fill = Response::AgentJob {
            job: Some(AgentJobWire::from(AgentJob::Fill {
                request_id: 7,
                item_id: "i".into(),
                kind: AgentKind::Login,
                submit: true,
                document_id: "d".into(),
            })),
        };
        assert_eq!(
            serde_json::to_value(&fill).unwrap(),
            json!({"job":{"job":"fill","request_id":7,"item_id":"i","kind":"login","submit":true,"document_id":"d"}})
        );
        let card = AgentJobWire::from(AgentJob::Fill {
            request_id: 8,
            item_id: "c".into(),
            kind: AgentKind::Card,
            submit: false,
            document_id: "d".into(),
        });
        assert_eq!(serde_json::to_value(&card).unwrap()["kind"], "card");
        assert_eq!(
            serde_json::to_value(Response::AgentJob { job: None }).unwrap(),
            json!({"job": null})
        );
        assert_eq!(serde_json::to_value(Response::Ack {}).unwrap(), json!({}));
    }

    #[test]
    fn agent_error_codes_map_to_the_hub() {
        for (code, want) in [
            ("tab_mismatch", AgentError::TabMismatch),
            ("origin_mismatch", AgentError::OriginMismatch),
            ("cross_site_frame", AgentError::CrossSiteFrame),
            ("no_fields", AgentError::NoFields),
            ("denied", AgentError::Denied),
            ("timeout", AgentError::Timeout),
            ("no_browser", AgentError::Denied),
            ("anything", AgentError::Denied),
        ] {
            assert_eq!(agent_error(code), want, "{code}");
        }
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
            associated: false,
            account: None,
        };
        let v = serde_json::to_value(&s).unwrap();
        assert_eq!(v["match"], Value::Null);
        assert_eq!(v["kind"], "login");
        assert_eq!(v["methods"][0]["provider"], "google");
        // The optional fields are left out: the shape an extension from
        // before them reads.
        assert_eq!(v.as_object().unwrap().len(), 12);

        let tagged = Summary {
            match_quality: Some(MatchQuality::Associated),
            associated: true,
            account: Some("Soma Labs".into()),
            ..s
        };
        let v = serde_json::to_value(&tagged).unwrap();
        assert_eq!(v["match"], "domain");
        assert_eq!(v["associated"], true);
        assert_eq!(v["account"], "Soma Labs");
        assert_eq!(v.as_object().unwrap().len(), 14);
    }
}
