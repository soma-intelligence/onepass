//! Request service: decodes an application request, applies the rules of
//! spec 7.2 to 7.5 and encodes the reply.
//!
//! Every origin decision is made here again: the extension only forwards
//! the origin the browser gave it. A reply holding a secret is built in a
//! `Zeroizing` buffer and journaled without its value.

use std::collections::{HashSet, VecDeque};
use std::str::FromStr;

use onepass_core::Id;
use onepass_core::generator::{self, CharsetOptions, PassphraseOptions, Wordlist};
use onepass_core::model::{
    FieldValue, Item, ItemType, ItemUrl, LoginMethod, MatchRule, PasswordHistoryEntry, new_item,
    validate,
};
use serde::Deserialize;
use time::OffsetDateTime;
use zeroize::Zeroizing;

use crate::api::{
    CredentialStatus, Ctx, ErrorBody, FillField, FillKind, Recipe, RecipeKind, Reply, Request,
    Response, SecretString, Summary, SummaryKind, VaultEntry,
};
use crate::audit::{AuditEvent, AuditSink};
use crate::origin::{MatchQuality, Origin};
use crate::policy::{
    card_values, eligible, identity_values, is_provider_account, item_match, login_identifier,
    login_secrets, provider_url_matches, reveal_value, stored_password, summarize, summary_kind,
    totp_now,
};
use crate::provider::{ProviderId, from_host};
use crate::{AppErrorCode, BridgeError, Result};

/// Secret requests allowed per sliding window (spec 7.5).
pub const SECRET_LIMIT: usize = 60;
/// Length of the sliding window, in seconds.
pub const SECRET_WINDOW: u64 = 60;
/// Label of the URL of a login saved from the extension.
const SAVED_URL_LABEL: &str = "site web";
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

/// A vault's metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultInfo {
    pub id: Id,
    pub name: String,
    pub color: Option<String>,
}

/// What the service needs from the vault. The macOS app and the
/// development host each implement it.
pub trait VaultAccess {
    fn status(&self) -> VaultStatus;
    /// Ask the user to unlock. `true` when the vault is unlocked after the
    /// call.
    fn unlock(&mut self) -> Result<bool>;
    fn vaults(&self) -> Result<Vec<VaultInfo>>;
    /// Every item with its vault.
    fn items(&mut self) -> Result<Vec<(VaultInfo, Item)>>;
    /// Create or replace an item.
    fn save(&mut self, vault_id: Id, item: Item) -> Result<()>;
    /// Ask the user to confirm access to an item marked `reprompt`.
    fn approve_reprompt(&mut self, item_id: Id) -> bool;
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

fn origin(s: &str) -> OpResult<Origin> {
    Origin::parse(s).map_err(app_code)
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
        None => 2,
    }
}

/// Sorts summaries: best match first, then by title.
fn sort(items: &mut [Summary]) {
    items.sort_by(|a, b| {
        rank(a.match_quality)
            .cmp(&rank(b.match_quality))
            .then_with(|| a.title.to_lowercase().cmp(&b.title.to_lowercase()))
    });
}

/// Equality of two secrets in constant time.
fn same_secret(a: &str, b: &str) -> bool {
    aws_lc_rs::constant_time::verify_slices_are_equal(a.as_bytes(), b.as_bytes()).is_ok()
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
        RecipeKind::Smart => charset(length(20), r.symbols.unwrap_or(true)),
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
}

impl<V: VaultAccess> Service<V> {
    pub fn new(vault: V, audit: Box<dyn AuditSink>) -> Self {
        Self {
            vault,
            audit,
            seen: HashSet::new(),
            secret_times: VecDeque::new(),
        }
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
            item_id: item_id.to_string(),
            origin: origin.map(str::to_owned),
            ctx,
            at,
        });
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

    fn reprompt(&mut self, item: &Item) -> OpResult<()> {
        if item.reprompt && !self.vault.approve_reprompt(item.id) {
            return Err(AppErrorCode::RepromptRequired);
        }
        Ok(())
    }

    fn items(&mut self) -> OpResult<Vec<(VaultInfo, Item)>> {
        self.vault.items().map_err(app_code)
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
        match req {
            Request::Status { .. } => {
                let s = self.vault.status();
                return Ok(Response::Status {
                    locked: s.locked,
                    account: s.account,
                    vaults: s.vaults,
                });
            }
            Request::Unlock { .. } => {
                let unlocked = self.vault.unlock().map_err(app_code)?;
                return Ok(Response::Unlock { locked: !unlocked });
            }
            _ => {}
        }
        if self.vault.status().locked {
            return Err(AppErrorCode::Locked);
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
                | Request::UpdatePassword { .. }
                | Request::LinkProvider { .. }
        ) {
            self.take_secret_slot(now)?;
        }
        match req {
            Request::Status { .. } | Request::Unlock { .. } => Err(AppErrorCode::Internal),
            Request::Vaults { .. } => self.vaults(),
            Request::ListForOrigin { origin: o, .. } => self.list_for_origin(o),
            Request::Search { ctx, query, .. } => self.search(*ctx, query),
            Request::ListFillable {
                origin: o, kind, ..
            } => self.list_fillable(o, *kind),
            Request::FillLogin {
                ctx,
                item_id,
                origin: o,
                fields,
                ..
            } => self.fill_login(*ctx, item_id, o, fields, now),
            Request::FillCard {
                ctx,
                item_id,
                origin: o,
                ..
            } => self.fill_other(*ctx, item_id, o, ItemType::CreditCard, now),
            Request::FillIdentity {
                ctx,
                item_id,
                origin: o,
                ..
            } => self.fill_other(*ctx, item_id, o, ItemType::Identity, now),
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
            Request::UpdatePassword {
                ctx,
                item_id,
                origin: o,
                password,
                ..
            } => self.update_password(*ctx, item_id, o, password, now),
            Request::Generate { recipe, .. } => {
                let r = generator_recipe(recipe)?;
                let password = generator::generate(&r).map_err(|_| AppErrorCode::Invalid)?;
                Ok(Response::Generate {
                    password: SecretString(password),
                    entropy_bits: generator::entropy_bits(&r),
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
        }
    }

    fn vaults(&mut self) -> OpResult<Response> {
        let vaults = self
            .vault
            .vaults()
            .map_err(app_code)?
            .into_iter()
            .map(|v| VaultEntry {
                id: v.id.to_string(),
                name: v.name,
                color: v.color,
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
        let mut out: Vec<Summary> = all
            .iter()
            .filter(|(_, i)| eligible(i) && summary_kind(i.item_type).is_some())
            .filter_map(|(v, i)| pick(i).map(|q| summarize(v, i, q, &email)))
            .collect();
        sort(&mut out);
        out
    }

    fn list_for_origin(&mut self, o: &str) -> OpResult<Response> {
        let page = origin(o)?;
        let all = self.items()?;
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
        origin(o)?;
        let want = match kind {
            FillKind::Card => SummaryKind::Card,
            FillKind::Identity => SummaryKind::Identity,
        };
        let all = self.items()?;
        let items = Self::summaries(&all, |i| {
            (summary_kind(i.item_type) == Some(want)).then_some(None)
        });
        Ok(Response::Items { items })
    }

    fn fill_login(
        &mut self,
        ctx: Ctx,
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
        if item_match(&item, &page).is_none() {
            return Err(AppErrorCode::OriginMismatch);
        }
        self.reprompt(&item)?;
        let out = login_secrets(&item, fields, now);
        self.record("fill_login", item.id, Some(o), ctx, now);
        Ok(out)
    }

    fn fill_other(
        &mut self,
        ctx: Ctx,
        item_id: &str,
        o: &str,
        kind: ItemType,
        now: u64,
    ) -> OpResult<Response> {
        origin(o)?;
        let (_, item) = self.eligible_item(item_id)?;
        if item.item_type != kind {
            return Err(AppErrorCode::NotFound);
        }
        self.reprompt(&item)?;
        let (op, out) = if kind == ItemType::CreditCard {
            ("fill_card", card_values(&item))
        } else {
            ("fill_identity", identity_values(&item))
        };
        self.record(op, item.id, Some(o), ctx, now);
        Ok(out)
    }

    fn totp(&mut self, ctx: Ctx, item_id: &str, o: Option<&str>, now: u64) -> OpResult<Response> {
        let page = match (ctx, o) {
            (Ctx::Popup, _) => None,
            (_, Some(o)) => Some(origin(o)?),
            (_, None) => return Err(AppErrorCode::NotAllowed),
        };
        let item = self.displayable_item(item_id)?;
        if let Some(page) = &page
            && item_match(&item, page).is_none()
        {
            return Err(AppErrorCode::OriginMismatch);
        }
        self.reprompt(&item)?;
        let (code, remaining) = totp_now(&item, now)?.ok_or(AppErrorCode::NotFound)?;
        self.record("totp", item.id, o, ctx, now);
        Ok(Response::Totp { code, remaining })
    }

    fn reveal(&mut self, ctx: Ctx, item_id: &str, field: &str, now: u64) -> OpResult<Response> {
        if ctx != Ctx::Popup {
            return Err(AppErrorCode::NotAllowed);
        }
        let item = self.displayable_item(item_id)?;
        self.reprompt(&item)?;
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
        let all = self.items()?;
        let mut candidates: Vec<(Option<MatchQuality>, &Item)> = all
            .iter()
            .map(|(_, i)| i)
            .filter(|i| eligible(i) && i.item_type == ItemType::Login)
            .filter_map(|i| item_match(i, &page).map(|q| (Some(q), i)))
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
        let vault_id = parse_id(new.vault_id)?;
        if !self
            .vault
            .vaults()
            .map_err(app_code)?
            .iter()
            .any(|v| v.id == vault_id)
        {
            return Err(AppErrorCode::NotFound);
        }
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
        self.vault.save(vault_id, item).map_err(app_code)?;
        self.record("save_login", id, Some(o), ctx, now);
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
        now: u64,
    ) -> OpResult<Response> {
        let page = origin(o)?;
        let (_, mut item) = self.eligible_item(item_id)?;
        if item.item_type != ItemType::Login {
            return Err(AppErrorCode::NotFound);
        }
        if item_match(&item, &page).is_none() {
            return Err(AppErrorCode::OriginMismatch);
        }
        self.reprompt(&item)?;
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
        item.updated_at = at;
        let (id, vault_id) = (item.id, item.vault_id);
        self.vault.save(vault_id, item).map_err(app_code)?;
        self.record("update_password", id, Some(o), ctx, now);
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
            .filter(|i| item_match(i, &site).is_some())
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
    fn provider_account(&mut self, account_item_id: &str, p: ProviderId) -> OpResult<Item> {
        let (_, item) = self.eligible_item(account_item_id)?;
        if !is_provider_account(&item, p) {
            return Err(AppErrorCode::NotFound);
        }
        Ok(item)
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
        let item = self.provider_account(account_item_id, p)?;
        if !provider_url_matches(&item, p, &prov) {
            return Err(AppErrorCode::OriginMismatch);
        }
        self.reprompt(&item)?;
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
        let account = self.provider_account(account_item_id, p)?;
        let method = LoginMethod::Provider {
            provider: p.to_core(),
            account: account.id,
            relay_email: None,
        };
        let mut logins: Vec<(MatchQuality, Item)> = self
            .items()?
            .into_iter()
            .map(|(_, i)| i)
            .filter(|i| eligible(i) && i.item_type == ItemType::Login && i.id != account.id)
            .filter_map(|i| item_match(&i, &site).map(|q| (q, i)))
            .collect();
        logins.sort_by_key(|(q, _)| rank(Some(*q)));
        let item = match logins.into_iter().next() {
            Some((_, mut item)) => {
                self.reprompt(&item)?;
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
        self.vault.save(vault_id, item).map_err(app_code)?;
        self.record("link_provider", id, Some(site_origin), ctx, now);
        Ok(Response::ItemId {
            item_id: id.to_string(),
        })
    }
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
