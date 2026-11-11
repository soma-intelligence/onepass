//! Request service: decodes an application request, applies the rules of
//! spec 7.2 to 7.5 and encodes the reply.
//!
//! Every origin decision is made here again: the extension only forwards
//! the origin the browser gave it. A reply holding a secret is built in a
//! `Zeroizing` buffer and journaled without its value.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::str::FromStr;
use std::sync::Arc;

use onepass_core::Id;
use onepass_core::autofill_history::{
    AutofillAction, AutofillEvent, BrowserKind, ClientContext, EventSource, MAX_SHOWN,
};
use onepass_core::fill_plan::compose::PRIORITY;
use onepass_core::fill_plan::context::{FieldRole, FrameKind, MAX_FIELDS, PageContext};
use onepass_core::fill_plan::intent::{Intent, intent_of};
use onepass_core::fill_plan::score::{Candidate, MatchQuality as PlanQuality, Tiebreak, order};
use onepass_core::fill_plan::{Pool, page_intent, plan};
use onepass_core::generator::{self, CharsetOptions, PassphraseOptions, Wordlist};
use onepass_core::model::checks::luhn_valid;
use onepass_core::model::usage::{SiteUsage, associated_pick_key, form_shape_hash};
use onepass_core::model::{
    Address, EventKind, FieldValue, Item, ItemType, ItemUrl, LoginMethod, MatchRule, PENDING_TAG,
    PasswordHistoryEntry, WEAK_BY_SITE_TAG, new_item, validate,
};
use onepass_core::site_password::{GenerationReport, PasswordContext, Profile, generate_for};
use onepass_core::webauthn;
use serde::Deserialize;
use time::OffsetDateTime;
use zeroize::Zeroizing;

use crate::agent::{AgentHub, AgentKind, AgentListener, WAIT_TIMEOUT};
use crate::api::{
    AddressIn, AgentJobWire, CredentialStatus, Ctx, ErrorBody, Extra, FillField, FillKind,
    PasskeySummary, Recipe, RecipeKind, RecipeProfile, Reply, Request, Response, SecretString,
    Step, Summary, SummaryKind, VaultEntry, agent_error,
};
use crate::audit::{AuditEvent, AuditSink, PlanAudit};
use crate::origin::{MatchQuality, Origin};
use crate::policy::{
    add_passkey, associated_document, card_values, direct_match, eligible, identity_values,
    is_provider_account, item_match, license_values, login_identifier, login_secrets,
    loyalty_values, otp_field, passkeys, passport_values, plan_candidates, plan_quality,
    provider_url_matches, reveal_value, site_loyalty, stored_password, summarize, summary_kind,
    to_candidate, totp_now,
};
use crate::provider::{ProviderId, from_host};
use crate::quirks::quirk_rules;
use crate::session::UsernameSalt;
use crate::webauthn_rp::{
    Ceremony, ES256, MAX_CHALLENGE, MAX_CREDENTIAL_ID, MAX_EXCLUDE, MAX_USER_HANDLE, b64url,
    check_user_name, client_data_hash, client_data_json, from_b64url, p256_spki, passkey_origin,
    rp_id_for,
};
use crate::{AppErrorCode, BridgeError, Result};

/// Secret requests allowed per sliding window (spec 7.5).
pub const SECRET_LIMIT: usize = 60;
/// Length of the sliding window, in seconds.
pub const SECRET_WINDOW: u64 = 60;
/// Label of the URL of a login saved from the extension.
const SAVED_URL_LABEL: &str = "site web";
/// Most steps `note_fill` takes for one fill.
const MAX_STEPS: usize = 16;
/// Longest site `forget_site` takes (a DNS name).
const MAX_SITE_LEN: usize = 253;
/// The journal operations that record a secret served to the client.
const SERVED: [&str; 9] = [
    "fill_login",
    "fill_card",
    "fill_identity",
    "fill_document",
    "fill_loyalty",
    "fill_provider",
    "totp",
    "reveal",
    "passkey_get",
];
/// Initial capacity of a reply buffer. Replies with a secret are far
/// smaller, so the buffer never reallocates (which would leave an
/// unwiped copy behind).
const REPLY_CAPACITY: usize = 16 * 1024;

/// Lock state of the vault as the extension may see it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultStatus {
    pub locked: bool,
    /// Account name (an email).
    pub account: String,
    /// Number of vaults.
    pub vaults: usize,
}

/// The account of a vault, on a host that serves several at once (the Mac
/// app with added accounts).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountTag {
    /// Stable name of the account on this device (the directory's slot):
    /// what the journal keeps, never shown.
    pub key: String,
    /// The account's label, shown on a candidate.
    pub label: String,
    /// `items_for` routes the page's host to another account: this one's
    /// items rank behind, and join a plan only when that account has none.
    pub behind: bool,
}

/// A vault's metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultInfo {
    pub id: Id,
    pub name: String,
    pub color: Option<String>,
    /// None on a host with one account (or one unlocked account).
    pub account: Option<AccountTag>,
    /// A personal vault: nobody but the user can write to it. False for a
    /// shared vault, and for a host that cannot tell (no `sole_exact`
    /// trust for its items, `fill_plan::score`).
    pub personal: bool,
}

impl VaultInfo {
    fn account_key(&self) -> Option<&str> {
        self.account.as_ref().map(|a| a.key.as_str())
    }

    fn behind(&self) -> bool {
        self.account.as_ref().is_some_and(|a| a.behind)
    }
}

/// What the service needs from the vault. The macOS app and the
/// development host each implement it.
pub trait VaultAccess {
    fn status(&self) -> VaultStatus;
    /// Ask the user to unlock. `true` when the vault is unlocked after the
    /// call. `origin_host`: the host of the page the user's gesture was on,
    /// when the extension said (an older one does not).
    fn unlock(&mut self, origin_host: Option<&str>) -> Result<bool>;
    fn vaults(&self) -> Result<Vec<VaultInfo>>;
    /// `vaults` for a page on `host`, routed as `items_for`: the vaults of
    /// the account `host` routes to first (a new item defaults to the
    /// first), the others tagged `behind`. One account: `vaults`.
    fn vaults_for(&self, host: &str) -> Result<Vec<VaultInfo>> {
        let _ = host;
        self.vaults()
    }
    /// The pairing of the client this vault serves, told once by the
    /// connection loop before any request. A host with one client ignores
    /// it.
    fn bind_client(&mut self, pairing_id: &[u8; 16]) {
        let _ = pairing_id;
    }
    /// A secret was served to the client, after every check: `kind` is the
    /// journal's operation (`fill_login`, `fill_card`, `fill_identity`,
    /// `fill_document`, `fill_loyalty`, `fill_provider`, `totp`, `reveal`,
    /// `passkey_get`), `account` the item's account key when the host
    /// serves several. Never for a plan, a note, a save, a refusal or an
    /// agent fill.
    fn secret_served(&mut self, kind: &'static str, item_id: Id, account: Option<&str>) {
        let _ = (kind, item_id, account);
    }
    /// Every item with its vault.
    fn items(&mut self) -> Result<Vec<(VaultInfo, Item)>>;
    /// `items` for a page on `host`. A host with several accounts routes
    /// `host` as the system AutoFill does (the account claiming the domain,
    /// else the primary one): that account's items come first, the others
    /// are tagged `behind`. One account: `items`.
    fn items_for(&mut self, host: &str) -> Result<Vec<(VaultInfo, Item)>> {
        let _ = host;
        self.items()
    }
    /// Create or replace an item.
    fn save(&mut self, vault_id: Id, item: Item) -> Result<()>;
    /// Ask the user to confirm access to an item marked `reprompt`.
    /// `origin_host`: the host of the page the request is for, none for a
    /// request without a page (the extension's window).
    fn approve_reprompt(&mut self, item_id: Id, origin_host: Option<&str>) -> bool;
    /// Remember a fill of `u.site` by an item (`Repository::record_usage`):
    /// `true` when the item was rewritten. `force`: another item, in any
    /// vault, used the site after this one, so the entry is rewritten even
    /// within the hour.
    fn record_usage(
        &mut self,
        vault_id: Id,
        item_id: Id,
        u: SiteUsage,
        now: OffsetDateTime,
        force: bool,
    ) -> Result<bool>;
    /// Forget `site` in every item (`Repository::forget_site_usage`): how
    /// many items were rewritten.
    fn forget_site_usage(&mut self, site: &str) -> Result<usize>;
    /// Keep one event in the device's autofill history
    /// (`Repository::record_autofill_event`): `false` when the history is
    /// off or not kept. A host without a history keeps nothing.
    fn record_autofill_event(&mut self, ev: AutofillEvent) -> Result<bool> {
        let _ = ev;
        Ok(false)
    }
    /// The learned bonus of each item on `site` for a plan made in
    /// `client` (`Repository::autofill_affinity`). None without a history.
    fn autofill_affinity(
        &mut self,
        site: &str,
        client: &ClientContext,
        now: OffsetDateTime,
    ) -> Result<BTreeMap<Id, i64>> {
        let _ = (site, client, now);
        Ok(BTreeMap::new())
    }
}

type OpResult<T> = std::result::Result<T, AppErrorCode>;

fn message(code: AppErrorCode) -> &'static str {
    match code {
        AppErrorCode::Locked => "vault is locked",
        AppErrorCode::NotFound => "item not found",
        AppErrorCode::OriginMismatch => "origin does not match the item",
        AppErrorCode::InsecureOrigin => "origin is not https",
        AppErrorCode::NotAllowed => "operation not allowed in this context",
        AppErrorCode::RepromptRequired => "item needs confirmation",
        AppErrorCode::RateLimited => "too many secret requests",
        AppErrorCode::Invalid => "invalid request",
        AppErrorCode::Excluded => "a credential of the exclude list is stored",
        _ => "internal error",
    }
}

fn app_code(e: BridgeError) -> AppErrorCode {
    match e {
        BridgeError::App(code) => code,
        _ => AppErrorCode::Internal,
    }
}

/// Only the id of a request, for replying to one that does not decode.
#[derive(Deserialize)]
struct IdProbe {
    id: u64,
}

fn parse_id(s: &str) -> OpResult<Id> {
    Id::from_str(s.trim()).map_err(|_| AppErrorCode::Invalid)
}

/// The page of a request: `https`, or `http` on a loopback host (spec 6.1).
/// Passkeys keep `passkey_origin`, `https` only.
fn origin(s: &str) -> OpResult<Origin> {
    Origin::parse_page(s).map_err(app_code)
}

fn unix(now: u64) -> OffsetDateTime {
    i64::try_from(now)
        .ok()
        .and_then(|t| OffsetDateTime::from_unix_timestamp(t).ok())
        .unwrap_or(OffsetDateTime::UNIX_EPOCH)
}

fn rank(q: Option<MatchQuality>) -> u8 {
    match q {
        Some(MatchQuality::ExactHost) => 0,
        Some(MatchQuality::Domain) => 1,
        Some(MatchQuality::Associated) => 2,
        None => 3,
    }
}

/// Sorts summaries through `fill_plan::order`: best match first, then by
/// title. No usage and no typed username, so `now` never enters a score.
fn sort(pairs: Vec<(Summary, Candidate)>) -> Vec<Summary> {
    let mut by_id: HashMap<Id, VecDeque<Summary>> = HashMap::new();
    let mut cands = Vec::with_capacity(pairs.len());
    for (s, c) in pairs {
        by_id.entry(c.item_id).or_default().push_back(s);
        cands.push(c);
    }
    order(&mut cands, None, 0, Tiebreak::Title);
    cands
        .iter()
        .filter_map(|c| by_id.get_mut(&c.item_id)?.pop_front())
        .collect()
}

/// Roles of the page's main form (the first form of the main intent, as
/// `fill_plan::plan` picks it): its visible fields with a role, in page
/// order. `note_fill` sends the same list.
fn main_roles(ctx: &PageContext) -> Option<Vec<FieldRole>> {
    let intents: Vec<Intent> = ctx.forms.iter().map(intent_of).collect();
    let main = PRIORITY.into_iter().find(|i| intents.contains(i))?;
    let (form, _) = ctx.forms.iter().zip(&intents).find(|(_, i)| **i == main)?;
    Some(
        form.fields
            .iter()
            .filter(|f| f.visible)
            .filter_map(|f| f.role)
            .collect(),
    )
}

/// Two-letter country of an identity's address, if it has one.
fn identity_country(item: &Item) -> Option<String> {
    match item.field("address").map(|f| &f.value) {
        Some(FieldValue::Address(a)) if !a.country.trim().is_empty() => {
            Some(a.country.trim().to_ascii_uppercase())
        }
        _ => None,
    }
}

/// Equality of two secrets in constant time.
fn same_secret(a: &str, b: &str) -> bool {
    aws_lc_rs::constant_time::verify_slices_are_equal(a.as_bytes(), b.as_bytes()).is_ok()
}

/// Rule strings a request may carry, and the longest of them.
const MAX_RULE_STRINGS: usize = 8;
const MAX_RULE_LEN: usize = 1024;
/// Longest `hint_text` kept; a longer one is cut, not refused.
const MAX_HINT_CHARS: usize = 600;

/// The `smart` kind: constraints from the request and the site's known
/// rules, then the chosen profile.
fn smart_password(
    r: &Recipe,
    page: Option<&Origin>,
) -> OpResult<(Zeroizing<String>, GenerationReport)> {
    let profile = match r.profile.unwrap_or_default() {
        RecipeProfile::Strong => Profile::Strong,
        RecipeProfile::Readable => Profile::Readable,
        RecipeProfile::Custom => {
            let length = r.length.unwrap_or(24);
            if !(8..=64).contains(&length) {
                return Err(AppErrorCode::Invalid);
            }
            Profile::Custom {
                length: length as u8,
                digits: true,
                symbols: r.symbols.unwrap_or(true),
            }
        }
    };
    let mut ctx = PasswordContext {
        quirk_rules: page.and_then(quirk_rules).map(str::to_owned),
        ..PasswordContext::default()
    };
    if let Some(c) = &r.context {
        if c.rules.len() > MAX_RULE_STRINGS || c.rules.iter().any(|s| s.len() > MAX_RULE_LEN) {
            return Err(AppErrorCode::Invalid);
        }
        ctx.rules = c.rules.clone();
        ctx.min_length = c.min_length;
        ctx.max_length = c.max_length;
        ctx.hint_text = c
            .hint_text
            .as_ref()
            .map(|h| h.chars().take(MAX_HINT_CHARS).collect());
    }
    generate_for(&ctx, &profile, r.narrow.unwrap_or(0)).map_err(|_| AppErrorCode::Invalid)
}

fn generator_recipe(r: &Recipe) -> OpResult<generator::Recipe> {
    if let Some(len) = r.length
        && !(4..=100).contains(&len)
    {
        return Err(AppErrorCode::Invalid);
    }
    let length = |default: u8| r.length.map_or(default, |l| l as u8);
    let charset = |len: u8, symbols: bool| {
        generator::Recipe::Random(CharsetOptions {
            length: len,
            lower: true,
            upper: true,
            digits: true,
            symbols,
            avoid_ambiguous: false,
        })
    };
    Ok(match r.kind {
        RecipeKind::Random => charset(length(20), r.symbols.unwrap_or(false)),
        // Handled by `smart_password` before this is reached.
        RecipeKind::Smart => return Err(AppErrorCode::Invalid),
        RecipeKind::Memorable => generator::Recipe::Passphrase(PassphraseOptions {
            words: 5,
            separator: "-".to_owned(),
            capitalize: false,
            include_digit: false,
            list: Wordlist::FrenchDiceware,
        }),
        RecipeKind::Pin => generator::Recipe::Pin { digits: length(6) },
    })
}

/// The request service of one session.
pub struct Service<V: VaultAccess> {
    vault: V,
    audit: Box<dyn AuditSink>,
    seen: HashSet<u64>,
    secret_times: VecDeque<u64>,
    /// Drawn at the first `fill_salt` or `plan_fill`, gone with the
    /// session.
    salt: Option<UsernameSalt>,
    /// The browser and profile of the session (`client_info`); unknown
    /// until the extension says.
    client: ClientContext,
    /// This session as a listener of the app's agent hub, shared by every
    /// session (spec 2026-11-07-agent-browser-fill 5): the jobs, answers
    /// and tickets it sees are its own. None: no agent fill here.
    agent: Option<AgentListener>,
    /// Account key of each vault and item last read, for the journal.
    /// Empty on a host with one account.
    owners: HashMap<Id, String>,
    /// Logins the user picked in the menu or the popup on a host where
    /// they are an associated match only, and were served (item, host):
    /// what follows that pick in this session (the next steps of its
    /// sign-in, its `note_fill`) is let through. Nothing else acts on an
    /// associated match.
    picked: HashSet<(Id, String)>,
}

impl<V: VaultAccess> Service<V> {
    pub fn new(vault: V, audit: Box<dyn AuditSink>) -> Self {
        Self {
            vault,
            audit,
            seen: HashSet::new(),
            secret_times: VecDeque::new(),
            salt: None,
            client: ClientContext::unknown(),
            agent: None,
            owners: HashMap::new(),
            picked: HashSet::new(),
        }
    }

    /// Serves agent fills through `hub`: `agent_wait`, the result requests
    /// and the `agent` context.
    pub fn with_agent_hub(mut self, hub: Arc<AgentHub>) -> Self {
        self.agent = Some(hub.listener());
        self
    }

    pub fn vault(&self) -> &V {
        &self.vault
    }

    pub fn vault_mut(&mut self) -> &mut V {
        &mut self.vault
    }

    /// Handles one request and gives the JSON reply. Never panics: a
    /// request that does not decode gets `invalid` (with its id when one
    /// can be read), a replayed id gets `invalid`.
    pub fn handle(&mut self, req_json: &[u8], now: u64) -> Zeroizing<Vec<u8>> {
        let reply = match serde_json::from_slice::<Request>(req_json) {
            Ok(req) => {
                let id = req.id();
                if !self.seen.insert(id) {
                    Self::error(Some(id), AppErrorCode::Invalid)
                } else {
                    match self.dispatch(&req, now) {
                        Ok(ok) => Reply::Ok {
                            id,
                            ok: Box::new(ok),
                        },
                        Err(code) => Self::error(Some(id), code),
                    }
                }
            }
            Err(_) => {
                let id = serde_json::from_slice::<IdProbe>(req_json)
                    .ok()
                    .map(|p| p.id);
                if let Some(id) = id {
                    self.seen.insert(id);
                }
                Self::error(id, AppErrorCode::Invalid)
            }
        };
        encode(&reply)
    }

    fn error(id: Option<u64>, code: AppErrorCode) -> Reply {
        Reply::Err {
            id,
            err: ErrorBody::new(code, message(code)),
        }
    }

    fn record(&mut self, op: &'static str, item_id: Id, origin: Option<&str>, ctx: Ctx, at: u64) {
        self.audit.record(AuditEvent {
            op,
            item_id: Some(item_id.to_string()),
            origin: origin.map(str::to_owned),
            ctx,
            at,
            plan: None,
            account: self.owners.get(&item_id).cloned(),
        });
        // The same point tells the host a secret left, for what it keeps
        // of the user's activity. An agent fill is not the user at work.
        if SERVED.contains(&op) && ctx != Ctx::Agent {
            let account = self.owners.get(&item_id).cloned();
            self.vault.secret_served(op, item_id, account.as_deref());
        }
    }

    /// The session's username salt, drawn on first use.
    fn salt(&mut self) -> OpResult<&UsernameSalt> {
        if self.salt.is_none() {
            self.salt = Some(UsernameSalt::generate().map_err(app_code)?);
        }
        self.salt.as_ref().ok_or(AppErrorCode::Internal)
    }

    /// Takes a slot in the secret request window, or `rate_limited`.
    fn take_secret_slot(&mut self, now: u64) -> OpResult<()> {
        while self
            .secret_times
            .front()
            .is_some_and(|t| now.saturating_sub(*t) >= SECRET_WINDOW)
        {
            self.secret_times.pop_front();
        }
        if self.secret_times.len() >= SECRET_LIMIT {
            return Err(AppErrorCode::RateLimited);
        }
        self.secret_times.push_back(now);
        Ok(())
    }

    fn reprompt(&mut self, item: &Item, page: Option<&Origin>) -> OpResult<()> {
        if item.reprompt && !self.vault.approve_reprompt(item.id, page.map(Origin::host)) {
            return Err(AppErrorCode::RepromptRequired);
        }
        Ok(())
    }

    /// The match of a login a request may act on, or `origin_mismatch`.
    ///
    /// An associated match (a domain sharing its credentials with the
    /// page's, where the user never picked this login) is the user's to
    /// start: from the menu or the popup (`ctx`), or for an agent fill the
    /// holder approved (its ticket is checked by the caller). Anything else
    /// (a chain, the overlay, a save) gets it only after such a pick was
    /// served in this session: `not_allowed` otherwise, whatever the
    /// extension knows of the tier.
    fn login_match(&self, item: &Item, page: &Origin, ctx: Ctx) -> OpResult<MatchQuality> {
        if matches!(ctx, Ctx::Menu | Ctx::Popup | Ctx::Agent) {
            return item_match(item, page).ok_or(AppErrorCode::OriginMismatch);
        }
        self.followed_match(item, page)
    }

    /// `login_match` for what only follows a pick (a write, a note, a step
    /// of a chain): an associated match needs the pick served before, in
    /// this session.
    fn followed_match(&self, item: &Item, page: &Origin) -> OpResult<MatchQuality> {
        let q = item_match(item, page).ok_or(AppErrorCode::OriginMismatch)?;
        if q == MatchQuality::Associated
            && !self.picked.contains(&(item.id, page.host().to_owned()))
        {
            return Err(AppErrorCode::NotAllowed);
        }
        Ok(q)
    }

    /// A login was served on the user's pick while it was an associated
    /// match: remembered for the rest of the session (`picked`).
    fn note_pick(&mut self, item: &Item, page: &Origin, q: MatchQuality, ctx: Ctx) {
        if q == MatchQuality::Associated && matches!(ctx, Ctx::Menu | Ctx::Popup) {
            self.picked.insert((item.id, page.host().to_owned()));
        }
    }

    fn items(&mut self) -> OpResult<Vec<(VaultInfo, Item)>> {
        let all = self.vault.items().map_err(app_code)?;
        self.note_owners(&all);
        Ok(all)
    }

    /// `items` for a page: routed by its host (`VaultAccess::items_for`).
    fn items_on(&mut self, page: &Origin) -> OpResult<Vec<(VaultInfo, Item)>> {
        let all = self.vault.items_for(page.host()).map_err(app_code)?;
        self.note_owners(&all);
        Ok(all)
    }

    /// The vaults, their accounts remembered for the journal. With a page,
    /// routed by its host (`VaultAccess::vaults_for`).
    fn vault_list(&mut self, page: Option<&Origin>) -> OpResult<Vec<VaultInfo>> {
        let vaults = match page {
            Some(p) => self.vault.vaults_for(p.host()),
            None => self.vault.vaults(),
        }
        .map_err(app_code)?;
        if !vaults.is_empty() && vaults.iter().all(|v| v.account.is_none()) {
            self.owners.clear();
        }
        for v in &vaults {
            if let Some(key) = v.account_key() {
                self.owners.insert(v.id, key.to_owned());
            }
        }
        Ok(vaults)
    }

    /// Remember the account of what was just read. A read that names no
    /// account (one account answers) forgets them all: its journal lines
    /// name none.
    fn note_owners(&mut self, all: &[(VaultInfo, Item)]) {
        if !all.is_empty() && all.iter().all(|(v, _)| v.account.is_none()) {
            self.owners.clear();
        }
        for (v, i) in all {
            if let Some(key) = v.account_key() {
                self.owners.insert(v.id, key.to_owned());
                self.owners.insert(i.id, key.to_owned());
            }
        }
    }

    /// Create or replace `item` in its vault; the journal then names the
    /// account of that vault for it.
    fn save(&mut self, vault_id: Id, item: Item) -> OpResult<()> {
        let id = item.id;
        self.vault.save(vault_id, item).map_err(app_code)?;
        if let Some(key) = self.owners.get(&vault_id).cloned() {
            self.owners.insert(id, key);
        }
        Ok(())
    }

    /// An eligible item by id, or `not_found` (an archived or hidden item
    /// is not told apart from a missing one).
    fn eligible_item(&mut self, item_id: &str) -> OpResult<(VaultInfo, Item)> {
        let id = parse_id(item_id)?;
        self.items()?
            .into_iter()
            .find(|(_, i)| i.id == id && eligible(i))
            .ok_or(AppErrorCode::NotFound)
    }

    /// An eligible item of a type the extension can display (login, card,
    /// identity), or `not_found`: other types (SSH keys, servers, ID
    /// documents) never leave the host.
    fn displayable_item(&mut self, item_id: &str) -> OpResult<Item> {
        let (_, item) = self.eligible_item(item_id)?;
        if summary_kind(item.item_type).is_none() {
            return Err(AppErrorCode::NotFound);
        }
        Ok(item)
    }

    fn dispatch(&mut self, req: &Request, now: u64) -> OpResult<Response> {
        // The agent context opens fills and plans only, each for a named
        // agent request; `agent_request` means nothing elsewhere.
        match (req.ctx(), req.agent_request()) {
            (Some(Ctx::Agent), Some(_))
                if matches!(
                    req,
                    Request::FillLogin { .. } | Request::FillCard { .. } | Request::PlanFill { .. }
                ) => {}
            (Some(Ctx::Agent), _) => return Err(AppErrorCode::NotAllowed),
            (_, Some(_)) => return Err(AppErrorCode::Invalid),
            _ => {}
        }
        match req {
            Request::Status { .. } => {
                let s = self.vault.status();
                return Ok(Response::Status {
                    locked: s.locked,
                    account: s.account,
                    vaults: s.vaults,
                });
            }
            Request::Unlock { origin: o, .. } => {
                // Checked like every origin; an older extension sends none.
                let page = o.as_deref().map(origin).transpose()?;
                let unlocked = self
                    .vault
                    .unlock(page.as_ref().map(Origin::host))
                    .map_err(app_code)?;
                return Ok(Response::Unlock { locked: !unlocked });
            }
            // Not a vault value: served locked too.
            Request::FillSalt { .. } => {
                return Ok(Response::Salt {
                    salt: self.salt()?.hex(),
                });
            }
            _ => {}
        }
        if self.vault.status().locked {
            return Err(AppErrorCode::Locked);
        }
        // The hub's own lock only: the vault is not held while the long
        // poll waits (each session has its own service).
        match req {
            Request::AgentWait { .. } => {
                let job = self.hub()?.wait_job(WAIT_TIMEOUT);
                return Ok(Response::AgentJob {
                    job: job.map(AgentJobWire::from),
                });
            }
            Request::AgentProbeResult {
                request_id, result, ..
            } => {
                let result = result
                    .clone()
                    .map(Into::into)
                    .map_err(|code| agent_error(&code));
                self.hub()?.probe_done(*request_id, result);
                return Ok(Response::Ack {});
            }
            Request::AgentFillResult {
                request_id, result, ..
            } => {
                let result = result
                    .clone()
                    .map(Into::into)
                    .map_err(|code| agent_error(&code));
                self.hub()?.fill_done(*request_id, result);
                return Ok(Response::Ack {});
            }
            _ => {}
        }
        if matches!(
            req,
            Request::FillLogin { .. }
                | Request::FillCard { .. }
                | Request::FillIdentity { .. }
                | Request::FillProvider { .. }
                | Request::Totp { .. }
                | Request::Reveal { .. }
                | Request::CheckCredentials { .. }
                | Request::CheckCard { .. }
                | Request::SaveCard { .. }
                | Request::CheckIdentity { .. }
                | Request::UpdatePassword { .. }
                | Request::ConfirmPending { .. }
                | Request::LinkProvider { .. }
                | Request::PasskeyGet { .. }
                | Request::PasskeyCreate { .. }
        ) {
            self.take_secret_slot(now)?;
        }
        match req {
            Request::Status { .. }
            | Request::Unlock { .. }
            | Request::FillSalt { .. }
            | Request::AgentWait { .. }
            | Request::AgentProbeResult { .. }
            | Request::AgentFillResult { .. } => Err(AppErrorCode::Internal),
            Request::Vaults { origin: o, .. } => self.vaults(o.as_deref()),
            Request::ListForOrigin { origin: o, .. } => self.list_for_origin(o),
            Request::Search { ctx, query, .. } => self.search(*ctx, query),
            Request::ListFillable {
                origin: o, kind, ..
            } => self.list_fillable(o, *kind),
            Request::FillLogin {
                ctx,
                agent_request,
                item_id,
                origin: o,
                fields,
                ..
            } => self.fill_login(*ctx, *agent_request, item_id, o, fields, now),
            Request::FillCard {
                ctx,
                agent_request,
                item_id,
                origin: o,
                ..
            } => self.fill_other(*ctx, *agent_request, item_id, o, ItemType::CreditCard, now),
            Request::FillIdentity {
                ctx,
                item_id,
                origin: o,
                extras,
                ..
            } => self.fill_identity(*ctx, item_id, o, extras, now),
            Request::Totp {
                ctx,
                item_id,
                origin: o,
                ..
            } => self.totp(*ctx, item_id, o.as_deref(), now),
            Request::Reveal {
                ctx,
                item_id,
                field,
                ..
            } => self.reveal(*ctx, item_id, field, now),
            Request::CheckCredentials {
                origin: o,
                username,
                password,
                ..
            } => self.check_credentials(o, username, password),
            Request::SaveLogin {
                ctx,
                origin: o,
                title,
                username,
                password,
                vault_id,
                rule,
                tags,
                ..
            } => {
                let new = NewLogin {
                    title,
                    username,
                    password,
                    vault_id,
                    rule: (*rule).into(),
                    tags,
                };
                self.save_login(*ctx, o, new, now)
            }
            Request::CheckCard {
                ctx,
                origin: o,
                number,
                exp_month,
                exp_year,
                ..
            } => self.check_card(*ctx, o, number, exp_month, exp_year),
            Request::SaveCard {
                ctx,
                origin: o,
                vault_id,
                title,
                cardholder,
                number,
                exp_month,
                exp_year,
                item_id,
                ..
            } => {
                let card = NewCard {
                    vault_id,
                    title,
                    cardholder,
                    number,
                    exp_month,
                    exp_year,
                    item_id: item_id.as_deref(),
                };
                self.save_card(*ctx, o, card, now)
            }
            Request::CheckIdentity {
                ctx,
                origin: o,
                given_name,
                family_name,
                email,
                tel,
                organization,
                address,
                ..
            } => {
                let typed = TypedIdentity {
                    given_name,
                    family_name,
                    email,
                    tel,
                    organization,
                    address: address.as_ref(),
                };
                self.check_identity(*ctx, o, &typed)
            }
            Request::SaveIdentity {
                ctx,
                origin: o,
                vault_id,
                title,
                given_name,
                family_name,
                email,
                tel,
                organization,
                address,
                ..
            } => {
                let typed = TypedIdentity {
                    given_name,
                    family_name,
                    email,
                    tel,
                    organization,
                    address: address.as_ref(),
                };
                self.save_identity(*ctx, o, vault_id, title, &typed, now)
            }
            Request::UpdatePassword {
                ctx,
                item_id,
                origin: o,
                password,
                weak_by_site,
                ..
            } => self.update_password(*ctx, item_id, o, password, *weak_by_site, now),
            Request::ConfirmPending {
                ctx,
                item_id,
                origin: o,
                username,
                ..
            } => self.confirm_pending(*ctx, item_id, o, username, now),
            Request::Generate {
                recipe, origin: o, ..
            } => {
                let page = o.as_deref().map(origin).transpose()?;
                if recipe.kind == RecipeKind::Smart {
                    let (password, report) = smart_password(recipe, page.as_ref())?;
                    return Ok(Response::Generate {
                        password: SecretString(password),
                        entropy_bits: report.entropy_bits,
                        report: Some(report),
                    });
                }
                let r = generator_recipe(recipe)?;
                let password = generator::generate(&r).map_err(|_| AppErrorCode::Invalid)?;
                Ok(Response::Generate {
                    password: SecretString(password),
                    entropy_bits: generator::entropy_bits(&r),
                    report: None,
                })
            }
            Request::ProviderAccounts {
                provider,
                origin: o,
                ..
            } => self.provider_accounts(*provider, o),
            Request::FillProvider {
                ctx,
                account_item_id,
                provider,
                provider_origin,
                site_origin,
                fields,
                ..
            } => self.fill_provider(
                *ctx,
                account_item_id,
                *provider,
                provider_origin,
                site_origin,
                fields,
                now,
            ),
            Request::LinkProvider {
                ctx,
                site_origin,
                provider,
                account_item_id,
                ..
            } => self.link_provider(*ctx, site_origin, *provider, account_item_id, now),
            Request::PlanFill {
                ctx,
                agent_request,
                origin: o,
                context,
                ..
            } => {
                if *ctx == Ctx::Agent {
                    let live =
                        agent_request.is_some_and(|r| self.hub().is_ok_and(|h| h.ticket_live(r)));
                    if !live {
                        return Err(AppErrorCode::NotAllowed);
                    }
                }
                self.plan_fill(*ctx, o, context, now)
            }
            Request::NoteFill {
                ctx,
                item_id,
                origin: o,
                roles,
                intent,
                steps,
                ..
            } => {
                let fill = Noted {
                    roles,
                    intent: *intent,
                    steps,
                };
                self.note_fill(*ctx, item_id, o, fill, now)
            }
            Request::ForgetSite { ctx, site, .. } => self.forget_site(*ctx, site, now),
            Request::ClientInfo {
                browser,
                profile_id,
                profile_name,
                ..
            } => self.client_info(*browser, profile_id, profile_name),
            Request::NoteAutofill {
                ctx,
                origin: o,
                action,
                item_id,
                rank,
                shown,
                ..
            } => {
                let note = AutofillNote {
                    action: *action,
                    item_id: item_id.as_deref(),
                    rank: *rank,
                    shown,
                };
                self.note_autofill(*ctx, o, note, now)
            }
            Request::PasskeyList {
                ctx,
                origin: o,
                rp_id,
                ..
            } => self.passkey_list(*ctx, o, rp_id),
            Request::PasskeyGet {
                ctx,
                origin: o,
                top_origin,
                rp_id,
                item_id,
                credential_id,
                challenge,
                ..
            } => {
                let get = PasskeyAsk {
                    top_origin,
                    rp_id,
                    item_id,
                    credential_id,
                    challenge,
                };
                self.passkey_get(*ctx, o, get, now)
            }
            Request::PasskeyCreate {
                ctx,
                origin: o,
                top_origin,
                rp_id,
                user_name,
                user_handle,
                challenge,
                exclude,
                vault_id,
                ..
            } => {
                let new = NewPasskey {
                    top_origin,
                    rp_id,
                    user_name,
                    user_handle,
                    challenge,
                    exclude,
                    vault_id: vault_id.as_deref(),
                };
                self.passkey_create(*ctx, o, new, now)
            }
        }
    }

    /// The vaults; with the page's origin, those of the account it routes
    /// to first (the extension saves a new item in the first by default).
    fn vaults(&mut self, o: Option<&str>) -> OpResult<Response> {
        let page = o.map(origin).transpose()?;
        let vaults = self
            .vault_list(page.as_ref())?
            .into_iter()
            .map(|v| VaultEntry {
                id: v.id.to_string(),
                name: v.name,
                color: v.color,
                account: v.account.map(|a| a.label),
            })
            .collect();
        Ok(Response::Vaults { vaults })
    }

    /// Summaries of `pick`ed items, with the provider account emails
    /// resolved against the whole vault.
    fn summaries(
        all: &[(VaultInfo, Item)],
        pick: impl Fn(&Item) -> Option<Option<MatchQuality>>,
    ) -> Vec<Summary> {
        let email = |id: Id| {
            all.iter()
                .find(|(_, i)| i.id == id && eligible(i))
                .and_then(|(_, i)| login_identifier(i))
                .map(str::to_owned)
        };
        let pairs = all
            .iter()
            .filter(|(_, i)| eligible(i) && summary_kind(i.item_type).is_some())
            .filter_map(|(v, i)| {
                pick(i).map(|q| (summarize(v, i, q, &email), to_candidate(i, plan_quality(q))))
            })
            .collect();
        let mut out = sort(pairs);
        // The account the page routes to first (`items_for`). Stable, and
        // nothing moves on a host with one account.
        let behind: HashSet<String> = all
            .iter()
            .filter(|(v, _)| v.behind())
            .map(|(_, i)| i.id.to_string())
            .collect();
        if !behind.is_empty() {
            out.sort_by_key(|s| behind.contains(&s.item_id));
        }
        out
    }

    fn list_for_origin(&mut self, o: &str) -> OpResult<Response> {
        let page = origin(o)?;
        let all = self.items_on(&page)?;
        let items = Self::summaries(&all, |i| {
            if i.item_type != ItemType::Login {
                return None;
            }
            item_match(i, &page).map(Some)
        });
        Ok(Response::Items { items })
    }

    fn search(&mut self, ctx: Ctx, query: &str) -> OpResult<Response> {
        if ctx != Ctx::Popup {
            return Err(AppErrorCode::NotAllowed);
        }
        let q = query.trim().to_lowercase();
        let all = self.items()?;
        let items = Self::summaries(&all, |i| {
            let hit = q.is_empty()
                || i.title.to_lowercase().contains(&q)
                || (i.item_type == ItemType::Login
                    && login_identifier(i).is_some_and(|u| u.to_lowercase().contains(&q)))
                || i.urls.iter().any(|u| u.url.to_lowercase().contains(&q));
            hit.then_some(None)
        });
        Ok(Response::Items { items })
    }

    fn list_fillable(&mut self, o: &str, kind: FillKind) -> OpResult<Response> {
        let page = origin(o)?;
        let want = match kind {
            FillKind::Card => SummaryKind::Card,
            FillKind::Identity => SummaryKind::Identity,
        };
        let all = self.items_on(&page)?;
        let items = Self::summaries(&all, |i| {
            (summary_kind(i.item_type) == Some(want)).then_some(None)
        });
        Ok(Response::Items { items })
    }

    /// This session's listener of the hub, or `not_allowed` when this
    /// service has none.
    fn hub(&self) -> OpResult<&AgentListener> {
        self.agent.as_ref().ok_or(AppErrorCode::NotAllowed)
    }

    /// For the agent context: spends the ticket of `request` for this
    /// item, origin and kind, or `not_allowed`. Called once the origin
    /// checks of the request passed. Other contexts pass. `true` when the
    /// fill may give the one-time code: always outside the agent context,
    /// for an agent only when its ticket says so.
    fn agent_ticket(
        &self,
        ctx: Ctx,
        request: Option<u64>,
        item_id: &str,
        o: &str,
        kind: AgentKind,
    ) -> OpResult<bool> {
        if ctx != Ctx::Agent {
            return Ok(true);
        }
        let request = request.ok_or(AppErrorCode::NotAllowed)?;
        let ticket = self
            .hub()?
            .redeem_ticket(request, item_id, o, kind)
            .ok_or(AppErrorCode::NotAllowed)?;
        Ok(ticket.totp)
    }

    fn fill_login(
        &mut self,
        ctx: Ctx,
        agent_request: Option<u64>,
        item_id: &str,
        o: &str,
        fields: &[FillField],
        now: u64,
    ) -> OpResult<Response> {
        let page = origin(o)?;
        let (_, item) = self.eligible_item(item_id)?;
        if item.item_type != ItemType::Login {
            return Err(AppErrorCode::NotFound);
        }
        let q = self.login_match(&item, &page, ctx)?;
        let with_totp = self.agent_ticket(ctx, agent_request, item_id, o, AgentKind::Login)?;
        self.reprompt(&item, Some(&page))?;
        // An agent without the right to the code fills login and password
        // only, whatever fields the page asked for.
        let fields: Vec<FillField> = fields
            .iter()
            .copied()
            .filter(|f| with_totp || *f != FillField::Totp)
            .collect();
        let out = login_secrets(&item, &fields, now);
        self.note_pick(&item, &page, q, ctx);
        self.record("fill_login", item.id, Some(o), ctx, now);
        Ok(out)
    }

    fn fill_other(
        &mut self,
        ctx: Ctx,
        agent_request: Option<u64>,
        item_id: &str,
        o: &str,
        kind: ItemType,
        now: u64,
    ) -> OpResult<Response> {
        let page = origin(o)?;
        let (_, item) = self.eligible_item(item_id)?;
        if item.item_type != kind {
            return Err(AppErrorCode::NotFound);
        }
        self.agent_ticket(ctx, agent_request, item_id, o, AgentKind::Card)?;
        self.reprompt(&item, Some(&page))?;
        self.record("fill_card", item.id, Some(o), ctx, now);
        Ok(card_values(&item))
    }

    /// An identity, and on request (`extras`) the passport and driver
    /// license of its person and the page's loyalty number (spec 2026-11-06
    /// sections 4 and 9). A document asks for its own reprompt and has its
    /// own audit record, `fill_document` or `fill_loyalty`.
    fn fill_identity(
        &mut self,
        ctx: Ctx,
        item_id: &str,
        o: &str,
        extras: &[Extra],
        now: u64,
    ) -> OpResult<Response> {
        let page = origin(o)?;
        let (home, item) = self.eligible_item(item_id)?;
        if item.item_type != ItemType::Identity {
            return Err(AppErrorCode::NotFound);
        }
        self.reprompt(&item, Some(&page))?;
        let mut out = identity_values(&item);
        let mut given: Vec<(&'static str, Id)> = Vec::new();
        if !extras.is_empty() {
            // The documents of the identity's own account only.
            let all: Vec<Item> = self
                .items()?
                .into_iter()
                .filter(|(v, _)| v.account_key() == home.account_key())
                .map(|(_, i)| i)
                .collect();
            let today = OffsetDateTime::from_unix_timestamp(i64::try_from(now).unwrap_or(i64::MAX))
                .map_err(|_| AppErrorCode::Internal)?
                .date();
            let Response::Identity {
                passport,
                driver_license,
                loyalty,
                ..
            } = &mut out
            else {
                return Err(AppErrorCode::Internal);
            };
            if extras.contains(&Extra::Passport)
                && let Some(doc) = associated_document(&item, &all, ItemType::Passport, today)
            {
                self.reprompt(doc, Some(&page))?;
                *passport = Some(passport_values(doc));
                given.push(("fill_document", doc.id));
            }
            if extras.contains(&Extra::DriverLicense)
                && let Some(doc) = associated_document(&item, &all, ItemType::DriverLicense, today)
            {
                self.reprompt(doc, Some(&page))?;
                *driver_license = Some(license_values(doc));
                given.push(("fill_document", doc.id));
            }
            if extras.contains(&Extra::Loyalty)
                && let Some(program) = site_loyalty(&all, &page)
                && let Some(values) = loyalty_values(program)
            {
                self.reprompt(program, Some(&page))?;
                *loyalty = Some(values);
                given.push(("fill_loyalty", program.id));
            }
        }
        self.record("fill_identity", item.id, Some(o), ctx, now);
        for (op, id) in given {
            self.record(op, id, Some(o), ctx, now);
        }
        Ok(out)
    }

    fn totp(&mut self, ctx: Ctx, item_id: &str, o: Option<&str>, now: u64) -> OpResult<Response> {
        let page = match (ctx, o) {
            (Ctx::Popup, _) => None,
            (_, Some(o)) => Some(origin(o)?),
            (_, None) => return Err(AppErrorCode::NotAllowed),
        };
        let item = self.displayable_item(item_id)?;
        let q = match &page {
            Some(page) => Some(self.login_match(&item, page, ctx)?),
            None => None,
        };
        self.reprompt(&item, page.as_ref())?;
        let (code, remaining) = totp_now(&item, now)?.ok_or(AppErrorCode::NotFound)?;
        if let (Some(page), Some(q)) = (&page, q) {
            self.note_pick(&item, page, q, ctx);
        }
        self.record("totp", item.id, o, ctx, now);
        Ok(Response::Totp { code, remaining })
    }

    fn reveal(&mut self, ctx: Ctx, item_id: &str, field: &str, now: u64) -> OpResult<Response> {
        if ctx != Ctx::Popup {
            return Err(AppErrorCode::NotAllowed);
        }
        let item = self.displayable_item(item_id)?;
        self.reprompt(&item, None)?;
        let value = reveal_value(&item, field)?;
        self.record("reveal", item.id, None, ctx, now);
        Ok(Response::Reveal { value })
    }

    fn check_credentials(
        &mut self,
        o: &str,
        username: &str,
        password: &SecretString,
    ) -> OpResult<Response> {
        let page = origin(o)?;
        let user = username.trim();
        // The routed account's logins first: among equal matches, the
        // verdict names one of them.
        let all = self.items_on(&page)?;
        let mut site: Vec<(Option<MatchQuality>, &Item)> = all
            .iter()
            .map(|(_, i)| i)
            .filter(|i| eligible(i) && i.item_type == ItemType::Login)
            .filter_map(|i| item_match(i, &page).map(|q| (Some(q), i)))
            .collect();
        site.sort_by_key(|(q, _)| rank(*q));
        // A pending login (saved before its form was sent, often without a
        // username) holding this password answers first, whatever the
        // username: the submission confirms it (spec 7.2).
        if let Some((_, i)) = site.iter().find(|(_, i)| {
            i.is_pending() && stored_password(i).is_some_and(|p| same_secret(p, password.expose()))
        }) {
            return Ok(verdict(CredentialStatus::Pending, Some(i)));
        }
        let mut candidates: Vec<(Option<MatchQuality>, &Item)> = site
            .into_iter()
            .filter(|(_, i)| !i.is_pending())
            .filter(|(_, i)| login_identifier(i).is_some_and(|u| u.eq_ignore_ascii_case(user)))
            .collect();
        candidates.sort_by_key(|(q, _)| rank(*q));
        if let Some((_, i)) = candidates
            .iter()
            .find(|(_, i)| stored_password(i).is_some_and(|p| same_secret(p, password.expose())))
        {
            return Ok(verdict(CredentialStatus::Same, Some(i)));
        }
        Ok(match candidates.first() {
            Some((_, i)) => verdict(CredentialStatus::Update, Some(i)),
            None => verdict(CredentialStatus::New, None),
        })
    }

    fn save_login(&mut self, ctx: Ctx, o: &str, new: NewLogin<'_>, now: u64) -> OpResult<Response> {
        let page = origin(o)?;
        // A login is never saved without a password (defense in depth: the
        // extension refuses it too).
        if new.password.0.is_empty() {
            return Err(AppErrorCode::Invalid);
        }
        let vault_id = self.known_vault(new.vault_id, &page)?;
        let title = match new.title.trim() {
            "" => page.site(),
            t => t.to_owned(),
        };
        let mut item = new_item(ItemType::Login, vault_id, &title);
        let username = new.username.trim();
        if !username.is_empty() {
            set_value(&mut item, "username", FieldValue::Text(username.to_owned()))?;
        }
        set_value(
            &mut item,
            "password",
            FieldValue::Password(new.password.0.clone()),
        )?;
        let url = if new.rule == MatchRule::ExactUrl {
            page.url_string()
        } else {
            page.origin_string()
        };
        item.urls.push(ItemUrl {
            label: SAVED_URL_LABEL.to_owned(),
            url,
            rule: new.rule,
            primary: true,
        });
        item.tags = new
            .tags
            .iter()
            .map(|t| t.trim().to_owned())
            .filter(|t| !t.is_empty())
            .collect();
        validate(&item).map_err(|_| AppErrorCode::Invalid)?;
        let id = item.id;
        self.save(vault_id, item)?;
        self.record("save_login", id, Some(o), ctx, now);
        Ok(Response::ItemId {
            item_id: id.to_string(),
        })
    }

    /// The vault of a new item made on `page`: `vault_id` when it names a
    /// vault of the host (`not_found` otherwise), and when it is empty the
    /// first vault of the account the page routes to (`vaults_for`), so a
    /// site an added account claims is saved there, not in the primary
    /// account.
    fn known_vault(&mut self, vault_id: &str, page: &Origin) -> OpResult<Id> {
        let vaults = self.vault_list(Some(page))?;
        if vault_id.trim().is_empty() {
            return vaults.first().map(|v| v.id).ok_or(AppErrorCode::NotFound);
        }
        let vault_id = parse_id(vault_id)?;
        if !vaults.iter().any(|v| v.id == vault_id) {
            return Err(AppErrorCode::NotFound);
        }
        Ok(vault_id)
    }

    /// `same`: an eligible card holds this number and its expiry (or one
    /// of the two expiries is unknown); `update`: it holds the number with
    /// another expiry; `new` otherwise. Cards are not bound to a site:
    /// the origin is only checked.
    fn check_card(
        &mut self,
        ctx: Ctx,
        o: &str,
        number: &SecretString,
        exp_month: &str,
        exp_year: &str,
    ) -> OpResult<Response> {
        save_ctx(ctx)?;
        origin(o)?;
        let digits = card_digits(number)?;
        let expiry = parse_expiry(exp_month, exp_year)?;
        let all = self.items()?;
        let cards: Vec<&Item> = all
            .iter()
            .map(|(_, i)| i)
            .filter(|i| eligible(i) && i.item_type == ItemType::CreditCard)
            .filter(|i| stored_card_digits(i).is_some_and(|d| same_secret(&d, &digits)))
            .collect();
        let same = cards.iter().find(|i| match (expiry, stored_expiry(i)) {
            (Some(e), Some(s)) => e == s,
            _ => true,
        });
        Ok(match (same, cards.first()) {
            (Some(i), _) => verdict(CredentialStatus::Same, Some(i)),
            (None, Some(i)) => verdict(CredentialStatus::Update, Some(i)),
            (None, None) => verdict(CredentialStatus::New, None),
        })
    }

    fn save_card(&mut self, ctx: Ctx, o: &str, card: NewCard<'_>, now: u64) -> OpResult<Response> {
        save_ctx(ctx)?;
        let page = origin(o)?;
        let digits = card_digits(card.number)?;
        let expiry = parse_expiry(card.exp_month, card.exp_year)?;
        let cardholder = card.cardholder.trim();
        let item = match card.item_id {
            Some(item_id) => {
                let (_, mut item) = self.eligible_item(item_id)?;
                if item.item_type != ItemType::CreditCard {
                    return Err(AppErrorCode::NotFound);
                }
                // The item must hold the very number typed: an item id
                // alone never rewrites another card.
                if !stored_card_digits(&item).is_some_and(|d| same_secret(&d, &digits)) {
                    return Err(AppErrorCode::Invalid);
                }
                self.reprompt(&item, Some(&page))?;
                if let Some((year, month)) = expiry {
                    set_value(&mut item, "expiry", FieldValue::MonthYear { year, month })?;
                }
                if !cardholder.is_empty() && field_text(&item, "cardholder").is_none() {
                    set_value(
                        &mut item,
                        "cardholder",
                        FieldValue::Text(cardholder.to_owned()),
                    )?;
                }
                item.updated_at = unix(now);
                item
            }
            None => {
                let vault_id = self.known_vault(card.vault_id, &page)?;
                let title = match card.title.trim() {
                    "" => format!("Carte \u{2022}\u{2022}\u{2022}\u{2022} {}", last4(&digits)),
                    t => t.to_owned(),
                };
                let mut item = new_item(ItemType::CreditCard, vault_id, &title);
                if !cardholder.is_empty() {
                    set_value(
                        &mut item,
                        "cardholder",
                        FieldValue::Text(cardholder.to_owned()),
                    )?;
                }
                set_value(&mut item, "number", FieldValue::Concealed(digits.clone()))?;
                if let Some((year, month)) = expiry {
                    set_value(&mut item, "expiry", FieldValue::MonthYear { year, month })?;
                }
                item
            }
        };
        validate_typed(&item, &["cardholder", "expiry"])?;
        let (id, vault_id) = (item.id, item.vault_id);
        self.save(vault_id, item)?;
        self.record("save_card", id, Some(o), ctx, now);
        Ok(Response::ItemId {
            item_id: id.to_string(),
        })
    }

    /// `same` when an eligible Identity holds every non-empty typed value,
    /// `new` otherwise.
    fn check_identity(
        &mut self,
        ctx: Ctx,
        o: &str,
        typed: &TypedIdentity<'_>,
    ) -> OpResult<Response> {
        save_ctx(ctx)?;
        origin(o)?;
        if typed.is_empty() {
            return Err(AppErrorCode::Invalid);
        }
        let all = self.items()?;
        let found = all
            .iter()
            .map(|(_, i)| i)
            .filter(|i| eligible(i) && i.item_type == ItemType::Identity)
            .find(|i| typed.held_by(i));
        Ok(match found {
            Some(i) => verdict(CredentialStatus::Same, Some(i)),
            None => verdict(CredentialStatus::New, None),
        })
    }

    fn save_identity(
        &mut self,
        ctx: Ctx,
        o: &str,
        vault_id: &str,
        title: &str,
        typed: &TypedIdentity<'_>,
        now: u64,
    ) -> OpResult<Response> {
        save_ctx(ctx)?;
        let page = origin(o)?;
        if typed.is_empty() {
            return Err(AppErrorCode::Invalid);
        }
        let vault_id = self.known_vault(vault_id, &page)?;
        let (given, family, email) = (
            typed.given_name.trim(),
            typed.family_name.trim(),
            typed.email.trim(),
        );
        let name = format!("{given} {family}").trim().to_owned();
        let title = match title.trim() {
            "" if !name.is_empty() => name,
            "" if !email.is_empty() => email.to_owned(),
            "" => page.site(),
            t => t.to_owned(),
        };
        let mut item = new_item(ItemType::Identity, vault_id, &title);
        let texts = [
            (
                "first_name",
                given,
                FieldValue::Text as fn(String) -> FieldValue,
            ),
            ("last_name", family, FieldValue::Text),
            ("email", email, FieldValue::Email),
            ("mobile_phone", typed.tel.trim(), FieldValue::Phone),
            ("company", typed.organization.trim(), FieldValue::Text),
        ];
        for (field, value, kind) in texts {
            if !value.is_empty() {
                set_value(&mut item, field, kind(value.to_owned()))?;
            }
        }
        if let Some(a) = typed.address.filter(|a| !address_is_empty(a)) {
            set_value(
                &mut item,
                "address",
                FieldValue::Address(Address {
                    line1: a.line1.trim().to_owned(),
                    line2: a.line2.trim().to_owned(),
                    city: a.city.trim().to_owned(),
                    postal_code: a.postal_code.trim().to_owned(),
                    region: a.region.trim().to_owned(),
                    country: a.country.trim().to_owned(),
                }),
            )?;
        }
        validate_typed(&item, &["first_name"])?;
        let id = item.id;
        self.save(vault_id, item)?;
        self.record("save_identity", id, Some(o), ctx, now);
        Ok(Response::ItemId {
            item_id: id.to_string(),
        })
    }

    fn update_password(
        &mut self,
        ctx: Ctx,
        item_id: &str,
        o: &str,
        password: &SecretString,
        weak_by_site: Option<bool>,
        now: u64,
    ) -> OpResult<Response> {
        let page = origin(o)?;
        let (_, mut item) = self.eligible_item(item_id)?;
        if item.item_type != ItemType::Login {
            return Err(AppErrorCode::NotFound);
        }
        self.followed_match(&item, &page)?;
        self.reprompt(&item, Some(&page))?;
        let at = unix(now);
        if let Some(old) = stored_password(&item).filter(|p| !p.is_empty()).cloned() {
            item.password_history.push(PasswordHistoryEntry {
                value: old,
                replaced_at: at,
            });
        }
        set_value(
            &mut item,
            "password",
            FieldValue::Password(password.0.clone()),
        )?;
        // A regenerated pending password: its weak flag follows the new draw.
        if let Some(weak) = weak_by_site
            && item.is_pending()
        {
            item.tags.retain(|t| t != WEAK_BY_SITE_TAG);
            if weak {
                item.tags.push(WEAK_BY_SITE_TAG.to_owned());
            }
        }
        item.updated_at = at;
        let (id, vault_id) = (item.id, item.vault_id);
        self.save(vault_id, item)?;
        self.record("update_password", id, Some(o), ctx, now);
        Ok(Response::Empty {})
    }

    /// The form of a pending Login was sent: drop `PENDING_TAG` (other tags,
    /// `WEAK_BY_SITE_TAG` among them, stay) and complete the username. A
    /// blank `username` keeps the stored one. Same origin check as
    /// `update_password`; an item without the tag is refused.
    fn confirm_pending(
        &mut self,
        ctx: Ctx,
        item_id: &str,
        o: &str,
        username: &str,
        now: u64,
    ) -> OpResult<Response> {
        let page = origin(o)?;
        let (_, mut item) = self.eligible_item(item_id)?;
        if item.item_type != ItemType::Login {
            return Err(AppErrorCode::NotFound);
        }
        self.followed_match(&item, &page)?;
        if !item.is_pending() {
            return Err(AppErrorCode::Invalid);
        }
        self.reprompt(&item, Some(&page))?;
        let username = username.trim();
        if !username.is_empty() {
            set_value(&mut item, "username", FieldValue::Text(username.to_owned()))?;
        }
        item.tags.retain(|t| t != PENDING_TAG);
        // Still no username: the item would not be a valid Login.
        validate(&item).map_err(|_| AppErrorCode::Invalid)?;
        item.updated_at = unix(now);
        let (id, vault_id) = (item.id, item.vault_id);
        self.save(vault_id, item)?;
        self.record("confirm_pending", id, Some(o), ctx, now);
        Ok(Response::Empty {})
    }

    fn provider_accounts(&mut self, p: ProviderId, o: &str) -> OpResult<Response> {
        let site = origin(o)?;
        let all = self.items()?;
        let accounts = Self::summaries(&all, |i| is_provider_account(i, p).then_some(None));
        let core = p.to_core();
        let linked_item_id = all
            .iter()
            .map(|(_, i)| i)
            .filter(|i| eligible(i) && i.item_type == ItemType::Login)
            .filter(|i| direct_match(i, &site).is_some())
            .flat_map(|i| i.login_methods.iter())
            .find_map(|m| match m {
                LoginMethod::Provider {
                    provider, account, ..
                } if *provider == core => {
                    let id = account.to_string();
                    accounts.iter().any(|a| a.item_id == id).then_some(id)
                }
                _ => None,
            });
        Ok(Response::ProviderAccounts {
            accounts,
            linked_item_id,
        })
    }

    /// An eligible login of provider `p`: `not_found` if missing or not a
    /// login of `p`.
    fn provider_account(
        &mut self,
        account_item_id: &str,
        p: ProviderId,
    ) -> OpResult<(VaultInfo, Item)> {
        let (vault, item) = self.eligible_item(account_item_id)?;
        if !is_provider_account(&item, p) {
            return Err(AppErrorCode::NotFound);
        }
        Ok((vault, item))
    }

    #[allow(clippy::too_many_arguments)]
    fn fill_provider(
        &mut self,
        ctx: Ctx,
        account_item_id: &str,
        p: ProviderId,
        provider_origin: &str,
        site_origin: &str,
        fields: &[FillField],
        now: u64,
    ) -> OpResult<Response> {
        let prov = origin(provider_origin)?;
        origin(site_origin)?;
        if from_host(prov.host()) != Some(p) {
            return Err(AppErrorCode::OriginMismatch);
        }
        let (_, item) = self.provider_account(account_item_id, p)?;
        if !provider_url_matches(&item, p, &prov) {
            return Err(AppErrorCode::OriginMismatch);
        }
        self.reprompt(&item, Some(&prov))?;
        let out = login_secrets(&item, fields, now);
        self.record("fill_provider", item.id, Some(provider_origin), ctx, now);
        Ok(out)
    }

    fn link_provider(
        &mut self,
        ctx: Ctx,
        site_origin: &str,
        p: ProviderId,
        account_item_id: &str,
        now: u64,
    ) -> OpResult<Response> {
        let site = origin(site_origin)?;
        let (home, account) = self.provider_account(account_item_id, p)?;
        let method = LoginMethod::Provider {
            provider: p.to_core(),
            account: account.id,
            relay_email: None,
        };
        // A login of the provider login's own account only: no item of one
        // account ever points into another.
        let mut logins: Vec<(MatchQuality, Item)> = self
            .items()?
            .into_iter()
            .filter(|(v, _)| v.account_key() == home.account_key())
            .map(|(_, i)| i)
            .filter(|i| eligible(i) && i.item_type == ItemType::Login && i.id != account.id)
            .filter_map(|i| direct_match(&i, &site).map(|q| (q, i)))
            .collect();
        logins.sort_by_key(|(q, _)| rank(Some(*q)));
        let item = match logins.into_iter().next() {
            Some((_, mut item)) => {
                self.reprompt(&item, Some(&site))?;
                if !item.login_methods.contains(&method) {
                    item.login_methods.push(method);
                    item.updated_at = unix(now);
                }
                item
            }
            None => {
                let mut item = new_item(ItemType::Login, account.vault_id, &site.site());
                item.urls.push(ItemUrl {
                    label: SAVED_URL_LABEL.to_owned(),
                    url: site.origin_string(),
                    rule: MatchRule::Domain,
                    primary: true,
                });
                item.login_methods.push(method);
                item
            }
        };
        let (id, vault_id) = (item.id, item.vault_id);
        self.save(vault_id, item)?;
        self.record("link_provider", id, Some(site_origin), ctx, now);
        Ok(Response::ItemId {
            item_id: id.to_string(),
        })
    }

    /// The plan for a page (spec 4.3). The page context must come from the
    /// frame of `o`; the pool is what `list_for_origin` lists for logins,
    /// and every card and identity.
    fn plan_fill(
        &mut self,
        ctx: Ctx,
        o: &str,
        context: &PageContext,
        now: u64,
    ) -> OpResult<Response> {
        let page = origin(o)?;
        if origin(&context.origin)?.origin_string() != page.origin_string() {
            return Err(AppErrorCode::OriginMismatch);
        }
        context.validate().map_err(|_| AppErrorCode::Invalid)?;
        // A top frame is its own top: anything else is a forged context.
        if context.frame_kind == FrameKind::Top
            && Origin::parse_page(&context.top_origin)
                .ok()
                .map(|t| t.origin_string())
                != Some(page.origin_string())
        {
            return Err(AppErrorCode::Invalid);
        }
        let site = page.site();
        let shape = main_roles(context).map(|roles| form_shape_hash(&roles));
        let all = self.items_on(&page)?;
        let usable = || all.iter().map(|(_, i)| i).filter(|i| eligible(i));
        // Several accounts: a plan is made from the account the page routes
        // to, as the system AutoFill answers from one account; another
        // account's items join a kind only when that account has none (the
        // menu still lists them all).
        let behind: HashSet<Id> = all
            .iter()
            .filter(|(v, _)| v.behind())
            .map(|(_, i)| i.id)
            .collect();
        fn routed<'a>(
            mut v: Vec<(&'a Item, PlanQuality)>,
            behind: &HashSet<Id>,
        ) -> Vec<(&'a Item, PlanQuality)> {
            if v.iter().any(|(i, _)| !behind.contains(&i.id)) {
                v.retain(|(i, _)| !behind.contains(&i.id));
            }
            v
        }
        // A code page is filled from a Login holding a code only, and the
        // one used here last is found among those (as the system AutoFill
        // does for a one-time code).
        let otp = page_intent(context) == Intent::Otp;
        let logins: Vec<(&Item, PlanQuality)> = usable()
            .filter(|i| i.item_type == ItemType::Login)
            .filter(|i| !otp || otp_field(i).is_some())
            .filter_map(|i| item_match(i, &page).map(|q| (i, plan_quality(Some(q)))))
            .collect();
        let logins = routed(logins, &behind);
        let of_kind = |k: SummaryKind| -> Vec<(&Item, PlanQuality)> {
            routed(
                usable()
                    .filter(|i| summary_kind(i.item_type) == Some(k))
                    .map(|i| (i, plan_quality(None)))
                    .collect(),
                &behind,
            )
        };
        let (cards, identities) = (of_kind(SummaryKind::Card), of_kind(SummaryKind::Identity));
        let identity_country = identities
            .iter()
            .filter_map(|(i, _)| identity_country(i).map(|c| (i.id, c)))
            .collect();
        // The learned preference of this browser profile on the site; a
        // failing history never fails the plan.
        let learned = self
            .vault
            .autofill_affinity(&site, &self.client, unix(now))
            .unwrap_or_default();
        let salt = self.salt()?.bytes();
        // The items of the user's own vaults: the only ones the sole exact
        // host rule trusts.
        let personal: HashSet<Id> = all
            .iter()
            .filter(|(v, _)| v.personal)
            .map(|(_, i)| i.id)
            .collect();
        let with_learned = |mut v: Vec<Candidate>| {
            for c in &mut v {
                c.affinity = learned.get(&c.item_id).copied().unwrap_or(0);
                c.private_vault = personal.contains(&c.item_id);
            }
            v
        };
        let pool = Pool {
            logins: with_learned(plan_candidates(&logins, &site, shape, salt)),
            cards: with_learned(plan_candidates(&cards, &site, shape, salt)),
            identities: with_learned(plan_candidates(&identities, &site, shape, salt)),
            identity_country,
            default_card: None,
            now: i64::try_from(now).unwrap_or(i64::MAX),
        };
        let fill = plan(context, pool).map_err(|_| AppErrorCode::Invalid)?;
        self.audit.record(AuditEvent {
            op: "plan_fill",
            item_id: None,
            origin: Some(page.host().to_owned()),
            ctx,
            at: now,
            plan: Some(PlanAudit::from(&fill)),
            account: None,
        });
        Ok(Response::Plan { plan: fill.into() })
    }

    /// Remember that an item filled this site, for the next plans. A login
    /// must match the origin; a card or an identity has no URL, so the
    /// origin is only the site key.
    fn note_fill(
        &mut self,
        ctx: Ctx,
        item_id: &str,
        o: &str,
        fill: Noted<'_>,
        now: u64,
    ) -> OpResult<Response> {
        let page = origin(o)?;
        if fill.roles.len() > MAX_FIELDS || fill.steps.len() > MAX_STEPS {
            return Err(AppErrorCode::Invalid);
        }
        let id = parse_id(item_id)?;
        let all = self.items()?;
        let (vault, item) = all
            .iter()
            .find(|(_, i)| i.id == id && eligible(i))
            .ok_or(AppErrorCode::NotFound)?;
        let kind = summary_kind(item.item_type).ok_or(AppErrorCode::NotFound)?;
        // A login offered here as an associated match only: its fill is
        // noted, and the match promoted, only when that fill was served on
        // the user's pick in this session.
        let promoted = kind == SummaryKind::Login
            && self.followed_match(item, &page)? == MatchQuality::Associated;
        let site = page.site();
        // Another eligible item of this kind, in any vault, used the site
        // after this one: rewrite, or it stays `last_on_site` (spec 6.2).
        let force = item.used_later_by_another(
            &site,
            all.iter()
                .map(|(_, i)| i)
                .filter(|i| eligible(i) && summary_kind(i.item_type) == Some(kind)),
        );
        let (vault_id, item_id) = (vault.id, item.id);
        let at = unix(now);
        let usage = SiteUsage {
            site: site.clone(),
            form_shape_hash: form_shape_hash(fill.roles),
            intent: fill.intent,
            step_seq: fill.steps.iter().map(|s| (*s).into()).collect(),
            count: 1,
            last_at: at,
        };
        if promoted {
            // The pick, kept for this very host (`fill_plan::origin`): from
            // now on the login is a domain match there.
            let pick = SiteUsage {
                site: associated_pick_key(page.host()),
                ..usage.clone()
            };
            self.vault
                .record_usage(vault_id, item_id, pick, at, true)
                .map_err(app_code)?;
            self.picked.remove(&(item_id, page.host().to_owned()));
        }
        self.vault
            .record_usage(vault_id, item_id, usage, at, force)
            .map_err(app_code)?;
        // A fill that worked (the page moved on, a chain ended, a save
        // confirmed it): a choice for the history. Best effort.
        let _ = self.vault.record_autofill_event(AutofillEvent {
            at,
            action: AutofillAction::Submitted,
            source: EventSource::Extension,
            site,
            item_id: Some(item_id),
            rank: None,
            shown: Vec::new(),
            client: self.client.clone(),
            device_id: None,
        });
        self.record("note_fill", item_id, Some(page.host()), ctx, now);
        Ok(Response::Empty {})
    }

    /// The browser and profile of the session, checked
    /// (`ClientContext::validated`). The extension says it once per
    /// session; an older app refuses the op and ranks without it.
    fn client_info(
        &mut self,
        browser: BrowserKind,
        profile_id: &Option<String>,
        profile_name: &Option<String>,
    ) -> OpResult<Response> {
        // Only the AutoFill extension of the system speaks for itself.
        if browser == BrowserKind::SystemAutoFill {
            return Err(AppErrorCode::Invalid);
        }
        self.client = ClientContext {
            browser,
            profile_id: profile_id.clone(),
            profile_name: profile_name.clone(),
        }
        .validated()
        .map_err(|_| AppErrorCode::Invalid)?;
        Ok(Response::Empty {})
    }

    /// One event of the autofill history for the frame `o`. Items are
    /// checked as `note_fill` checks them: eligible, a login matching the
    /// origin. A shown id that is not such an item is left out. Kept only
    /// on this device, with this session's browser and profile.
    fn note_autofill(
        &mut self,
        ctx: Ctx,
        o: &str,
        note: AutofillNote<'_>,
        now: u64,
    ) -> OpResult<Response> {
        if !matches!(ctx, Ctx::Menu | Ctx::Popup | Ctx::Overlay | Ctx::Chain) {
            return Err(AppErrorCode::NotAllowed);
        }
        let page = origin(o)?;
        if note.shown.len() > MAX_SHOWN {
            return Err(AppErrorCode::Invalid);
        }
        let all = self.items()?;
        let usable = |id: Id| {
            all.iter().map(|(_, i)| i).find(|i| {
                i.id == id
                    && eligible(i)
                    && match summary_kind(i.item_type) {
                        Some(SummaryKind::Login) => item_match(i, &page).is_some(),
                        Some(_) => true,
                        None => false,
                    }
            })
        };
        let item_id = match note.item_id {
            Some(s) => Some(usable(parse_id(s)?).ok_or(AppErrorCode::NotFound)?.id),
            None if note.action == AutofillAction::Shown => None,
            None => return Err(AppErrorCode::Invalid),
        };
        let mut shown = Vec::new();
        for s in note.shown {
            if let Some(i) = usable(parse_id(s)?) {
                shown.push(i.id);
            }
        }
        let ev = AutofillEvent {
            at: unix(now),
            action: note.action,
            source: EventSource::Extension,
            site: page.site(),
            item_id,
            rank: note.rank,
            shown,
            client: self.client.clone(),
            device_id: None,
        };
        self.vault.record_autofill_event(ev).map_err(app_code)?;
        self.audit.record(AuditEvent {
            op: "note_autofill",
            item_id: item_id.map(|i| i.to_string()),
            origin: Some(page.host().to_owned()),
            ctx,
            at: now,
            plan: None,
            account: item_id.and_then(|i| self.owners.get(&i).cloned()),
        });
        Ok(Response::Empty {})
    }

    /// Forget a site in every item. From the extension window only. `site`
    /// is a host or an https origin, reduced as `Origin::site` does (IDN to
    /// punycode, lower case, registrable domain).
    fn forget_site(&mut self, ctx: Ctx, site: &str, now: u64) -> OpResult<Response> {
        if ctx != Ctx::Popup {
            return Err(AppErrorCode::NotAllowed);
        }
        let site = match site.trim() {
            "" => return Err(AppErrorCode::Invalid),
            s if s.contains("://") => origin(s)?.site(),
            s => origin(&format!("https://{s}"))?.site(),
        };
        if site.len() > MAX_SITE_LEN {
            return Err(AppErrorCode::Invalid);
        }
        let items = self.vault.forget_site_usage(&site).map_err(app_code)?;
        // A forgotten site is asked again from the menu.
        self.picked.clear();
        self.audit.record(AuditEvent {
            op: "forget_site",
            item_id: None,
            origin: Some(site),
            ctx,
            at: now,
            plan: None,
            account: None,
        });
        Ok(Response::Forgotten { items })
    }
}

/// The passkey operations run from the passkey choice window, and from a
/// sign-in chain the user started (`passkey_create` from the window only).
fn passkey_ctx(ctx: Ctx, create: bool) -> OpResult<()> {
    match ctx {
        Ctx::Passkey => Ok(()),
        Ctx::Chain if !create => Ok(()),
        _ => Err(AppErrorCode::NotAllowed),
    }
}

/// The frame origin of a passkey request whose top frame, as the browser
/// gave it, is `top`: `not_allowed` unless both are the same origin (no
/// passkey in a cross-origin frame, so `crossOrigin` is always false).
fn framed_origin(o: &str, top: &str) -> OpResult<Origin> {
    let page = passkey_origin(o)?;
    let same = passkey_origin(top)
        .ok()
        .is_some_and(|t| t.origin_string() == page.origin_string());
    if !same {
        return Err(AppErrorCode::NotAllowed);
    }
    Ok(page)
}

impl<V: VaultAccess> Service<V> {
    /// Passkeys of `rp_id` in the eligible logins, once the `rp_id` is
    /// checked against the browser's origin. No secret, no user handle.
    fn passkey_list(&mut self, ctx: Ctx, o: &str, rp_id: &str) -> OpResult<Response> {
        passkey_ctx(ctx, false)?;
        let page = passkey_origin(o)?;
        let rp = rp_id_for(&page, rp_id)?;
        let all = self.items()?;
        let mut out: Vec<PasskeySummary> = all
            .iter()
            .filter(|(_, i)| eligible(i) && i.item_type == ItemType::Login)
            .flat_map(|(v, i)| {
                passkeys(i)
                    .filter(|p| p.rp_id.eq_ignore_ascii_case(&rp))
                    .map(move |p| PasskeySummary {
                        item_id: i.id.to_string(),
                        vault_id: v.id.to_string(),
                        vault_name: v.name.clone(),
                        title: i.title.clone(),
                        user_name: p.user_name.clone(),
                        credential_id: b64url(&p.credential_id),
                    })
            })
            .collect();
        out.sort_by(|a, b| {
            (a.title.to_lowercase(), &a.user_name).cmp(&(b.title.to_lowercase(), &b.user_name))
        });
        Ok(Response::Passkeys { passkeys: out })
    }

    /// An assertion by the passkey `credential_id` of the login `item_id`.
    /// The host builds `clientDataJSON` from the browser's origin; the
    /// private key never leaves.
    fn passkey_get(
        &mut self,
        ctx: Ctx,
        o: &str,
        get: PasskeyAsk<'_>,
        now: u64,
    ) -> OpResult<Response> {
        passkey_ctx(ctx, false)?;
        let page = framed_origin(o, get.top_origin)?;
        let rp = rp_id_for(&page, get.rp_id)?;
        let cred_id = from_b64url(get.credential_id, MAX_CREDENTIAL_ID)?;
        let challenge = from_b64url(get.challenge, MAX_CHALLENGE)?;
        let (_, item) = self.eligible_item(get.item_id)?;
        if item.item_type != ItemType::Login {
            return Err(AppErrorCode::NotFound);
        }
        let Some(cred) = passkeys(&item)
            .find(|p| p.credential_id == cred_id && p.rp_id.eq_ignore_ascii_case(&rp))
            .cloned()
        else {
            return Err(AppErrorCode::NotFound);
        };
        self.reprompt(&item, Some(&page))?;
        // Signed over the checked rp id, in lower case, as the relying
        // party hashes it.
        let signer = onepass_core::model::PasskeyCredential { rp_id: rp, ..cred };
        let client_data = client_data_json(Ceremony::Get, &challenge, &page)?;
        // The bridge never verified the user itself: UV stays 0.
        let a = webauthn::assertion_with_uv(&signer, &client_data_hash(&client_data), false)
            .map_err(|_| AppErrorCode::Internal)?;
        self.record("passkey_get", item.id, Some(o), ctx, now);
        Ok(Response::PasskeyAssertion {
            credential_id: b64url(&signer.credential_id),
            client_data_json: b64url(&client_data),
            authenticator_data: b64url(&a.authenticator_data),
            signature: b64url(&a.signature),
            user_handle: b64url(&signer.user_handle),
        })
    }

    /// A new ES256 passkey, stored in the site's login of `user_name`, else
    /// in a new login. `excluded` when a live item already holds one of
    /// `exclude` for this `rp_id`.
    fn passkey_create(
        &mut self,
        ctx: Ctx,
        o: &str,
        new: NewPasskey<'_>,
        now: u64,
    ) -> OpResult<Response> {
        passkey_ctx(ctx, true)?;
        let page = framed_origin(o, new.top_origin)?;
        let rp = rp_id_for(&page, new.rp_id)?;
        let user_handle = from_b64url(new.user_handle, MAX_USER_HANDLE)?;
        let challenge = from_b64url(new.challenge, MAX_CHALLENGE)?;
        let user_name = check_user_name(new.user_name)?;
        if new.exclude.len() > MAX_EXCLUDE {
            return Err(AppErrorCode::Invalid);
        }
        let exclude = new
            .exclude
            .iter()
            .map(|c| from_b64url(c, MAX_CREDENTIAL_ID))
            .collect::<OpResult<Vec<_>>>()?;
        // Routed by the page: a new login goes to the account that claims
        // the domain, a login to complete is looked for there first.
        let vaults = self.vault_list(Some(&page))?;
        let asked_vault = match new.vault_id {
            Some(v) => {
                let id = parse_id(v)?;
                if !vaults.iter().any(|x| x.id == id) {
                    return Err(AppErrorCode::NotFound);
                }
                Some(id)
            }
            None => None,
        };
        let all = self.items_on(&page)?;
        // Any item not in the trash counts, eligible or not: the relying
        // party asked not to register twice on this authenticator.
        let excluded = all
            .iter()
            .filter(|(_, i)| i.trashed_at.is_none())
            .flat_map(|(_, i)| passkeys(i))
            .any(|p| p.rp_id.eq_ignore_ascii_case(&rp) && exclude.contains(&p.credential_id));
        if excluded {
            return Err(AppErrorCode::Excluded);
        }
        let mut owners: Vec<(MatchQuality, Item)> = all
            .into_iter()
            .map(|(_, i)| i)
            .filter(|i| eligible(i) && i.item_type == ItemType::Login)
            .filter(|i| {
                login_identifier(i).is_some_and(|u| u.trim().eq_ignore_ascii_case(user_name))
            })
            .filter_map(|i| direct_match(&i, &page).map(|q| (q, i)))
            .collect();
        owners.sort_by_key(|(q, _)| rank(Some(*q)));
        let at = unix(now);
        let (mut item, created) = match owners.into_iter().next() {
            Some((_, item)) => {
                self.reprompt(&item, Some(&page))?;
                (item, false)
            }
            None => {
                let vault_id = asked_vault
                    .or_else(|| vaults.first().map(|v| v.id))
                    .ok_or(AppErrorCode::NotFound)?;
                (new_passkey_login(vault_id, &rp, user_name), true)
            }
        };
        let cred = webauthn::new_credential(&rp, user_name, &user_handle, at)
            .map_err(|_| AppErrorCode::Invalid)?;
        let client_data = client_data_json(Ceremony::Create, &challenge, &page)?;
        let reg = webauthn::registration_with_uv(&cred, &client_data_hash(&client_data), false)
            .map_err(|_| AppErrorCode::Internal)?;
        let public_key = p256_spki(&public_point(&cred)?)?;
        if created {
            item.record(at, EventKind::Created);
        }
        item.record(at, EventKind::PasskeyAdded { rp_id: rp.clone() });
        add_passkey(&mut item, cred);
        if !item.login_methods.contains(&LoginMethod::Passkey) {
            item.login_methods.push(LoginMethod::Passkey);
        }
        item.updated_at = at;
        validate(&item).map_err(|_| AppErrorCode::Invalid)?;
        let (id, vault_id) = (item.id, item.vault_id);
        self.save(vault_id, item)?;
        self.record("passkey_create", id, Some(o), ctx, now);
        Ok(Response::PasskeyRegistration {
            item_id: id.to_string(),
            credential_id: b64url(&reg.credential_id),
            client_data_json: b64url(&client_data),
            attestation_object: b64url(&reg.attestation_object),
            authenticator_data: b64url(&reg.authenticator_data),
            public_key: b64url(&public_key),
            public_key_algorithm: ES256,
        })
    }
}

/// Uncompressed public point of a passkey's P-256 key.
fn public_point(cred: &onepass_core::model::PasskeyCredential) -> OpResult<Vec<u8>> {
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
    let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &cred.private_key)
        .map_err(|_| AppErrorCode::Internal)?;
    Ok(pair.public_key().as_ref().to_vec())
}

/// A new login for a passkey: titled by the relying party, its URL (rule
/// `domain`), the user name as identifier. As the macOS AutoFill does.
fn new_passkey_login(vault_id: Id, rp_id: &str, user_name: &str) -> Item {
    let mut item = new_item(ItemType::Login, vault_id, rp_id);
    item.urls.push(ItemUrl {
        label: SAVED_URL_LABEL.to_owned(),
        url: format!("https://{rp_id}"),
        rule: MatchRule::Domain,
        primary: true,
    });
    if let Some(f) = item.field_mut("username") {
        f.value = FieldValue::Text(user_name.to_owned());
    }
    item
}

/// Input of `passkey_get`.
struct PasskeyAsk<'a> {
    top_origin: &'a str,
    rp_id: &'a str,
    item_id: &'a str,
    credential_id: &'a str,
    challenge: &'a str,
}

/// Input of `passkey_create`.
struct NewPasskey<'a> {
    top_origin: &'a str,
    rp_id: &'a str,
    user_name: &'a str,
    user_handle: &'a str,
    challenge: &'a str,
    exclude: &'a [String],
    vault_id: Option<&'a str>,
}

/// What `note_autofill` carries, borrowed from the request.
struct AutofillNote<'a> {
    action: AutofillAction,
    item_id: Option<&'a str>,
    rank: Option<u8>,
    shown: &'a [String],
}

/// Input of `note_fill`.
struct Noted<'a> {
    roles: &'a [FieldRole],
    intent: Intent,
    steps: &'a [Step],
}

/// Input of `save_login`.
struct NewLogin<'a> {
    title: &'a str,
    username: &'a str,
    password: &'a SecretString,
    vault_id: &'a str,
    rule: MatchRule,
    tags: &'a [String],
}

/// A card typed in a page, for `save_card`.
struct NewCard<'a> {
    vault_id: &'a str,
    title: &'a str,
    cardholder: &'a str,
    number: &'a SecretString,
    exp_month: &'a str,
    exp_year: &'a str,
    item_id: Option<&'a str>,
}

/// An identity typed in a page, for `check_identity` and `save_identity`.
struct TypedIdentity<'a> {
    given_name: &'a str,
    family_name: &'a str,
    email: &'a str,
    tel: &'a str,
    organization: &'a str,
    address: Option<&'a AddressIn>,
}

impl TypedIdentity<'_> {
    /// No value worth saving or comparing.
    fn is_empty(&self) -> bool {
        [
            self.given_name,
            self.family_name,
            self.email,
            self.organization,
        ]
        .iter()
        .all(|v| norm(v).is_empty())
            && phone_digits(self.tel).is_empty()
            && self.address.is_none_or(address_is_empty)
    }

    /// Does `item` hold every non-empty value typed?
    fn held_by(&self, item: &Item) -> bool {
        let text = |field: &str, typed: &str| {
            let t = norm(typed);
            t.is_empty() || field_text(item, field).is_some_and(|s| norm(s) == t)
        };
        let tel = phone_digits(self.tel);
        let tel_ok = tel.is_empty()
            || ["mobile_phone", "home_phone", "work_phone"]
                .iter()
                .any(|f| field_text(item, f).is_some_and(|s| phone_digits(s) == tel));
        let address_ok = match self.address.filter(|a| !address_is_empty(a)) {
            None => true,
            Some(a) => match item.field("address").map(|f| &f.value) {
                Some(FieldValue::Address(s)) => [
                    (&a.line1, &s.line1),
                    (&a.line2, &s.line2),
                    (&a.city, &s.city),
                    (&a.postal_code, &s.postal_code),
                    (&a.region, &s.region),
                    (&a.country, &s.country),
                ]
                .iter()
                .all(|(t, s)| norm(t).is_empty() || norm(t) == norm(s)),
                _ => false,
            },
        };
        text("first_name", self.given_name)
            && text("last_name", self.family_name)
            && text("email", self.email)
            && text("company", self.organization)
            && tel_ok
            && address_ok
    }
}

/// Lower case, trimmed, inner whitespace collapsed to one space.
fn norm(s: &str) -> String {
    s.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

fn phone_digits(s: &str) -> String {
    s.chars().filter(char::is_ascii_digit).collect()
}

fn address_is_empty(a: &AddressIn) -> bool {
    [
        &a.line1,
        &a.line2,
        &a.city,
        &a.postal_code,
        &a.region,
        &a.country,
    ]
    .iter()
    .all(|p| p.trim().is_empty())
}

/// Non-blank text of a text-like field, whatever its autofill flag.
fn field_text<'a>(item: &'a Item, id: &str) -> Option<&'a str> {
    match item.field(id).map(|f| &f.value) {
        Some(
            FieldValue::Text(s)
            | FieldValue::Email(s)
            | FieldValue::Phone(s)
            | FieldValue::Url(s)
            | FieldValue::Menu(s),
        ) => {
            let t = s.trim();
            (!t.is_empty()).then_some(t)
        }
        _ => None,
    }
}

/// Only `save_prompt` saves or compares what a page form held.
fn save_ctx(ctx: Ctx) -> OpResult<()> {
    if ctx != Ctx::SavePrompt {
        return Err(AppErrorCode::NotAllowed);
    }
    Ok(())
}

/// Digits of a typed card number (spaces and dashes dropped): 12 to 19
/// digits with a valid check digit, or `invalid`.
fn card_digits(number: &SecretString) -> OpResult<Zeroizing<String>> {
    let raw = number.expose();
    if raw
        .chars()
        .any(|c| !(c.is_ascii_digit() || c == ' ' || c == '-'))
    {
        return Err(AppErrorCode::Invalid);
    }
    let digits: Zeroizing<String> =
        Zeroizing::new(raw.chars().filter(char::is_ascii_digit).collect());
    if !(12..=19).contains(&digits.len()) || !luhn_valid(&digits) {
        return Err(AppErrorCode::Invalid);
    }
    Ok(digits)
}

/// Digits of the number a stored card holds.
fn stored_card_digits(item: &Item) -> Option<Zeroizing<String>> {
    let s = match item.field("number").map(|f| &f.value) {
        Some(FieldValue::Concealed(n)) => n.as_str(),
        Some(FieldValue::Text(n)) => n.as_str(),
        _ => return None,
    };
    let d: Zeroizing<String> = Zeroizing::new(s.chars().filter(char::is_ascii_digit).collect());
    (!d.is_empty()).then_some(d)
}

/// `(year, month)` of a stored card, `None` when unknown.
fn stored_expiry(item: &Item) -> Option<(u16, u8)> {
    match item.field("expiry").map(|f| &f.value) {
        Some(FieldValue::MonthYear { year, month }) if (1..=12).contains(month) && *year > 0 => {
            Some((*year, *month))
        }
        _ => None,
    }
}

/// A typed expiry: month 1 to 12, year of 2 (20YY) or 4 digits. `None`
/// when either part is empty; `invalid` when both are given and one is
/// wrong.
fn parse_expiry(month: &str, year: &str) -> OpResult<Option<(u16, u8)>> {
    let (month, year) = (month.trim(), year.trim());
    if month.is_empty() || year.is_empty() {
        return Ok(None);
    }
    let digits = |s: &str| !s.is_empty() && s.len() <= 4 && s.bytes().all(|b| b.is_ascii_digit());
    if !digits(month) || !digits(year) {
        return Err(AppErrorCode::Invalid);
    }
    let m: u8 = month.parse().map_err(|_| AppErrorCode::Invalid)?;
    let y: u16 = year.parse().map_err(|_| AppErrorCode::Invalid)?;
    let y = match year.len() {
        2 => 2000 + y,
        4 => y,
        _ => return Err(AppErrorCode::Invalid),
    };
    if !(1..=12).contains(&m) {
        return Err(AppErrorCode::Invalid);
    }
    Ok(Some((y, m)))
}

fn last4(digits: &str) -> &str {
    &digits[digits.len().saturating_sub(4)..]
}

/// `validate`, with `waived` required fields allowed blank: a page form
/// may lack them (a checkout without a cardholder, a shipping form
/// without a first name), the user completes them in the app.
fn validate_typed(item: &Item, waived: &[&str]) -> OpResult<()> {
    let mut probe = item.clone();
    for f in probe.sections.iter_mut().flat_map(|s| s.fields.iter_mut()) {
        if waived.contains(&f.id.as_str()) {
            f.required = false;
        }
    }
    validate(&probe).map_err(|_| AppErrorCode::Invalid)
}

fn verdict(status: CredentialStatus, item: Option<&Item>) -> Response {
    Response::CheckCredentials {
        status,
        item_id: item.map(|i| i.id.to_string()),
        title: item.map(|i| i.title.clone()),
    }
}

fn set_value(item: &mut Item, field: &str, value: FieldValue) -> OpResult<()> {
    item.field_mut(field)
        .map(|f| f.value = value)
        .ok_or(AppErrorCode::Internal)
}

fn encode(reply: &Reply) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(REPLY_CAPACITY));
    if serde_json::to_writer(&mut *out, reply).is_err() {
        out.clear();
        out.extend_from_slice(br#"{"id":null,"err":{"code":"internal","msg":"internal error"}}"#);
    }
    out
}
