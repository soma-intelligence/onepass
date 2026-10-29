//! AutoFill: identities for the system store, Logins matching a site, and
//! passkey registration and assertion. No secret value crosses here, and the
//! passkey private key never leaves the Rust.

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};

use onepass_core::Id;
use onepass_core::fill_plan::intent::Intent;
use onepass_core::fill_plan::score::{
    Candidate, CandidateKind, Confidence, MatchQuality as PlanQuality, Tiebreak, confidence, order,
    score,
};
use onepass_core::model::usage::{SiteUsage, StepKind, form_shape_hash, last_used_on};
use onepass_core::model::{
    self, Field, FieldType, FieldValue, Item, ItemType, ItemUrl, LoginMethod, MatchRule,
    PasskeyCredential,
};
use onepass_core::watchtower::host::is_local_host;
use onepass_core::webauthn;
use time::OffsetDateTime;
use url::{Host, Url};

use crate::convert::{id_hex, parse_id};
use crate::error::{OnePassError, invalid};
use crate::session::{Repo, Session, find_item, find_vault};
use crate::types::*;

const PASSKEYS: &str = "passkeys";
/// `FfiAutofillIdentity::rank` of the Login used last on the site.
const RANK_LAST_USED: u32 = 100;
/// `FfiAutofillIdentity::rank` of a favorite.
const RANK_FAVORITE: u32 = 50;
/// Most items in an `FfiAutofillPlan`.
const PLAN_MAX: usize = 6;

/// Host of a site as compared for AutoFill: lower-case ASCII (punycode), an
/// IP address marked as such.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Site {
    host: String,
    ip: bool,
}

/// The site of a URL or a bare domain (`https://` assumed when no scheme is
/// given). Only `https`, and `http` on a local host, give a site: a plain
/// `http` page of a public domain is never filled.
fn site(raw: &str) -> Option<Site> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    let has_scheme = raw
        .find("://")
        .is_some_and(|i| !raw[..i].contains(['/', '?', '#']));
    let parsed = if has_scheme {
        Url::parse(raw)
    } else {
        Url::parse(&format!("https://{raw}"))
    }
    .ok()?;
    let secure = match parsed.scheme() {
        "https" => true,
        "http" => false,
        _ => return None,
    };
    let (host, ip) = match parsed.host()? {
        Host::Domain(d) => (d.trim_end_matches('.').to_owned(), false),
        Host::Ipv4(a) => (a.to_string(), true),
        Host::Ipv6(a) => (format!("[{a}]"), true),
    };
    if host.is_empty() || (!secure && !is_local_host(&host)) {
        return None;
    }
    Some(Site { host, ip })
}

/// The key of a site in the usage memory, as the bridge writes it: the
/// registrable domain (eTLD+1), the address itself for an IP.
fn usage_site(s: &Site) -> String {
    if s.ip {
        return s.host.clone();
    }
    psl::domain_str(&s.host).unwrap_or(&s.host).to_owned()
}

/// How the URL of a Login matches the requested site under its rule.
/// `ExactUrl` compares hosts, like `ExactHost`.
fn url_quality(service: &Site, url: &ItemUrl) -> Option<FfiMatchQuality> {
    if url.rule == MatchRule::Never {
        return None;
    }
    let s = site(&url.url)?;
    if s.host == service.host {
        return Some(FfiMatchQuality::ExactHost);
    }
    if url.rule != MatchRule::Domain || s.ip || service.ip {
        return None;
    }
    let ours = psl::domain_str(&s.host)?;
    let theirs = psl::domain_str(&service.host)?;
    (ours == theirs).then_some(FfiMatchQuality::Domain)
}

/// Best match of a Login and the URL that gave it. A passkey whose relying
/// party is the requested host makes the Login an `ExactHost` match even
/// without such a URL: the system has already verified the rp id (the URL
/// returned is then the best matching one, else the first).
fn item_quality<'a>(service: &Site, item: &'a Item) -> Option<(FfiMatchQuality, Option<&'a str>)> {
    let by_url = item
        .urls
        .iter()
        .filter_map(|u| url_quality(service, u).map(|q| (q, u.url.as_str())))
        .min_by_key(|(q, _)| *q);
    let by_rp = passkeys(item).any(|p| site(&p.rp_id).is_some_and(|s| s.host == service.host));
    match by_url {
        Some((q, url)) if !by_rp || q <= FfiMatchQuality::ExactHost => Some((q, Some(url))),
        Some((_, url)) => Some((FfiMatchQuality::ExactHost, Some(url))),
        None if by_rp => Some((
            FfiMatchQuality::ExactHost,
            item.urls.first().map(|u| u.url.as_str()),
        )),
        None => None,
    }
}

fn filled(item: &Item, id: &str) -> bool {
    match item.field(id).map(|f| &f.value) {
        Some(FieldValue::Password(v) | FieldValue::Otp(v) | FieldValue::Concealed(v)) => {
            !v.trim().is_empty()
        }
        Some(FieldValue::Text(v) | FieldValue::Email(v)) => !v.trim().is_empty(),
        _ => false,
    }
}

fn passkeys(item: &Item) -> impl Iterator<Item = &PasskeyCredential> {
    item.sections
        .iter()
        .flat_map(|s| &s.fields)
        .filter(|f| f.id == PASSKEYS)
        .filter_map(|f| match &f.value {
            FieldValue::Passkey(p) => Some(p),
            _ => None,
        })
}

/// A Login neither trashed nor archived. Other types never fill.
fn live_login(item: &Item) -> bool {
    item.item_type == ItemType::Login && item.trashed_at.is_none() && !item.archived
}

fn record_id(item: &Item) -> String {
    format!("{}:{}", id_hex(item.vault_id), id_hex(item.id))
}

/// `"<vault id>:<item id>"` back to its two ids.
fn parse_record_id(record: &str) -> Result<(Id, Id), OnePassError> {
    let (vault, item) = record.split_once(':').ok_or_else(|| invalid("record id"))?;
    Ok((parse_id(vault)?, parse_id(item)?))
}

/// A Login the system AutoFill may offer: live and not hidden from AutoFill.
fn offerable(item: &Item) -> bool {
    live_login(item) && !item.hide_from_autofill
}

fn ffi_confidence(c: Confidence) -> FfiConfidence {
    match c {
        Confidence::Low => FfiConfidence::Low,
        Confidence::Medium => FfiConfidence::Medium,
        Confidence::High => FfiConfidence::High,
    }
}

/// Unix seconds, the clock of `UsageSignal::last_at`.
fn unix_now() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}

/// Every item of every vault but the excluded ones.
fn visible_items(repo: &mut Repo, excluded: &HashSet<Id>) -> Result<Vec<Item>, OnePassError> {
    let mut out = Vec::new();
    for v in repo.vaults()? {
        if !excluded.contains(&v.id) {
            out.extend(repo.items(&v)?);
        }
    }
    Ok(out)
}

fn parse_ids(ids: &[String]) -> Result<HashSet<Id>, OnePassError> {
    ids.iter().map(|s| parse_id(s)).collect()
}

/// The Login used last on each usage site, among the Logins with a code
/// for the one-time code identities and among all of them for the others.
struct LastUsed {
    any: HashMap<String, Id>,
    with_code: HashMap<String, Id>,
}

impl LastUsed {
    fn of(items: &[Item]) -> Self {
        let sites: BTreeSet<&str> = items
            .iter()
            .flat_map(|i| i.usage.iter().map(|u| u.site.as_str()))
            .collect();
        let by_site = |pool: &[&Item]| -> HashMap<String, Id> {
            sites
                .iter()
                .filter_map(|s| {
                    last_used_on(pool.iter().copied(), s).map(|id| ((*s).to_owned(), id))
                })
                .collect()
        };
        let all: Vec<&Item> = items.iter().collect();
        let coded: Vec<&Item> = items.iter().filter(|i| filled(i, "totp")).collect();
        LastUsed {
            any: by_site(&all),
            with_code: by_site(&coded),
        }
    }

    fn get(&self, kind: FfiAutofillKind, site: &str) -> Option<Id> {
        match kind {
            FfiAutofillKind::OneTimeCode => self.with_code.get(site),
            _ => self.any.get(site),
        }
        .copied()
    }
}

/// The identities of one Login. `last_used`: the Login used last on each
/// usage site, which gets `RANK_LAST_USED` on that site's identities of
/// its kind.
fn identities_of(item: &Item, last_used: &LastUsed, out: &mut Vec<FfiAutofillIdentity>) {
    let user = item.subtitle();
    let rank = |kind: FfiAutofillKind, service: &str| {
        let last = site(service)
            .map(|s| usage_site(&s))
            .and_then(|s| last_used.get(kind, &s));
        if last == Some(item.id) {
            RANK_LAST_USED
        } else if item.favorite {
            RANK_FAVORITE
        } else {
            0
        }
    };
    let entry =
        |kind, service: String, credential_id, user_handle, user: &str| FfiAutofillIdentity {
            kind,
            rank: rank(kind, &service),
            service,
            user: user.to_owned(),
            record_id: record_id(item),
            favorite: item.favorite,
            credential_id,
            user_handle,
        };
    let hosts: Vec<String> = item
        .urls
        .iter()
        .filter(|u| u.rule != MatchRule::Never)
        .filter_map(|u| site(&u.url))
        .map(|s| s.host)
        .collect();
    if !user.trim().is_empty() || filled(item, "password") {
        for h in &hosts {
            out.push(entry(
                FfiAutofillKind::Password,
                h.clone(),
                Vec::new(),
                Vec::new(),
                &user,
            ));
        }
    }
    if filled(item, "totp") {
        for h in &hosts {
            out.push(entry(
                FfiAutofillKind::OneTimeCode,
                h.clone(),
                Vec::new(),
                Vec::new(),
                &user,
            ));
        }
    }
    for p in passkeys(item) {
        out.push(entry(
            FfiAutofillKind::Passkey,
            p.rp_id.clone(),
            p.credential_id.clone(),
            p.user_handle.clone(),
            &p.user_name,
        ));
    }
}

fn candidate(item: &Item, quality: FfiMatchQuality, url: Option<&str>) -> FfiAutofillCandidate {
    FfiAutofillCandidate {
        vault_id: id_hex(item.vault_id),
        item_id: id_hex(item.id),
        title: item.title.clone(),
        user: item.subtitle(),
        url: url.map(str::to_owned),
        quality,
        has_password: filled(item, "password"),
        has_totp: filled(item, "totp"),
        passkeys: passkeys(item)
            .map(|p| FfiPasskeyRef {
                rp_id: p.rp_id.clone(),
                user_name: p.user_name.clone(),
                credential_id: p.credential_id.clone(),
            })
            .collect(),
    }
}

/// The ranking envelope of a Login for `fill_plan::score::order`. No usage and
/// no typed username yet: the score is the match quality alone.
pub(crate) fn to_candidate(item: &Item, q: FfiMatchQuality) -> Candidate {
    Candidate {
        item_id: item.id,
        kind: CandidateKind::Login,
        quality: match q {
            FfiMatchQuality::ExactHost => PlanQuality::Exact,
            FfiMatchQuality::Domain => PlanQuality::Domain,
            FfiMatchQuality::Other => PlanQuality::Other,
        },
        favorite: item.favorite,
        // Nanoseconds, so two saves in one second keep their order.
        updated_at: i64::try_from(item.updated_at.unix_timestamp_nanos()).unwrap_or(i64::MAX),
        title: item.title.clone(),
        username_hash: None,
        usage: None,
        has_totp: filled(item, "totp"),
    }
}

/// Puts the passkey in the first empty `passkeys` field, or in a copy right
/// after the last one (the field is repeatable); a Login without the field
/// gets one at the end of its first section.
fn add_passkey(item: &mut Item, cred: PasskeyCredential) {
    let mut last = None;
    for (si, s) in item.sections.iter_mut().enumerate() {
        for (fi, f) in s.fields.iter_mut().enumerate() {
            if f.id == PASSKEYS && f.kind == FieldType::Passkey {
                if f.value == FieldValue::Empty {
                    f.value = FieldValue::Passkey(cred);
                    return;
                }
                last = Some((si, fi));
            }
        }
    }
    let value = FieldValue::Passkey(cred);
    if let Some((si, fi)) = last
        && let Some(section) = item.sections.get_mut(si)
        && let Some(field) = section.fields.get(fi)
    {
        let mut copy = field.clone();
        copy.value = value;
        section.fields.insert(fi + 1, copy);
        return;
    }
    let field = Field {
        id: PASSKEYS.to_owned(),
        label: "Passkeys".to_owned(),
        kind: FieldType::Passkey,
        value,
        required: false,
        repeatable: true,
        autofill: true,
    };
    match item.sections.first_mut() {
        Some(section) => section.fields.push(field),
        None => item.sections.push(model::Section {
            id: "main".to_owned(),
            label: "Connexion".to_owned(),
            fields: vec![field],
        }),
    }
}

/// A new Login for a passkey: titled by the relying party, its URL, the
/// user name as identifier.
fn new_passkey_login(vault_id: Id, request: &FfiPasskeyCreation, now: OffsetDateTime) -> Item {
    let mut item = model::new_item(ItemType::Login, vault_id, &request.rp_id);
    item.urls = vec![ItemUrl {
        label: String::new(),
        url: format!("https://{}", request.rp_id),
        rule: MatchRule::Domain,
        primary: true,
    }];
    if let Some(f) = item.field_mut("username") {
        f.value = FieldValue::Text(request.user_name.clone());
    }
    item.created_at = now;
    item
}

/// True when a live item of any vault holds one of `excluded` for `rp_id`.
fn has_excluded(repo: &mut Repo, rp_id: &str, excluded: &[Vec<u8>]) -> Result<bool, OnePassError> {
    if excluded.is_empty() {
        return Ok(false);
    }
    for item in visible_items(repo, &HashSet::new())? {
        if item.trashed_at.is_some() {
            continue;
        }
        let hit = passkeys(&item)
            .any(|p| p.rp_id.eq_ignore_ascii_case(rp_id) && excluded.contains(&p.credential_id));
        if hit {
            return Ok(true);
        }
    }
    Ok(false)
}

#[uniffi::export]
impl Session {
    /// The identities to publish in the system store: for each live Login
    /// not hidden from AutoFill, a password identity per URL host, a one-time
    /// code identity per URL host when the TOTP is filled, and a passkey
    /// identity per passkey. Items of `excluded_vault_ids` are skipped.
    /// `rank`: the Login used last on the identity's site (of those
    /// published) first, then favorites.
    pub fn autofill_identities(
        &self,
        excluded_vault_ids: Vec<String>,
    ) -> Result<Vec<FfiAutofillIdentity>, OnePassError> {
        let excluded = parse_ids(&excluded_vault_ids)?;
        self.with(|repo| {
            let items: Vec<Item> = visible_items(repo, &excluded)?
                .into_iter()
                .filter(offerable)
                .collect();
            let last_used = LastUsed::of(&items);
            let mut out = Vec::new();
            for item in &items {
                identities_of(item, &last_used, &mut out);
            }
            let mut seen = HashSet::new();
            out.retain(|i| {
                seen.insert((
                    i.kind,
                    i.service.clone(),
                    i.user.clone(),
                    i.record_id.clone(),
                    i.credential_id.clone(),
                ))
            });
            Ok(out)
        })
    }

    /// The items of any type hidden from AutoFill, as record ids
    /// `"<vault id>:<item id>"` (trashed and archived ones included). Text
    /// insertion lists every item but these (ruling X3: never offered).
    pub fn autofill_hidden_record_ids(&self) -> Result<Vec<String>, OnePassError> {
        self.with(|repo| {
            Ok(visible_items(repo, &HashSet::new())?
                .iter()
                .filter(|i| i.hide_from_autofill)
                .map(record_id)
                .collect())
        })
    }

    /// The Logins matching `service` (a domain or a URL from the system;
    /// empty for none), same host first (a URL of that host, or a passkey
    /// whose rp id is that host), then same registrable domain, then
    /// favorites, then most recently updated. `include_all` appends every
    /// other live Login as `Other` (manual choice). Logins hidden from
    /// AutoFill are never returned.
    pub fn autofill_candidates(
        &self,
        service: String,
        include_all: bool,
        excluded_vault_ids: Vec<String>,
    ) -> Result<Vec<FfiAutofillCandidate>, OnePassError> {
        let excluded = parse_ids(&excluded_vault_ids)?;
        let target = site(&service);
        self.with(|repo| {
            let mut by_id: HashMap<Id, VecDeque<FfiAutofillCandidate>> = HashMap::new();
            let mut cands = Vec::new();
            for item in visible_items(repo, &excluded)? {
                if !live_login(&item) || item.hide_from_autofill {
                    continue;
                }
                let best = target.as_ref().and_then(|t| item_quality(t, &item));
                let (q, url) = match best {
                    Some((q, url)) => (q, url),
                    None if include_all => (
                        FfiMatchQuality::Other,
                        item.urls.first().map(|u| u.url.as_str()),
                    ),
                    None => continue,
                };
                by_id
                    .entry(item.id)
                    .or_default()
                    .push_back(candidate(&item, q, url));
                cands.push(to_candidate(&item, q));
            }
            // No usage and no typed username, so `now` never enters a score.
            order(&mut cands, None, 0, Tiebreak::FavoriteThenRecent);
            Ok(cands
                .iter()
                .filter_map(|c| by_id.get_mut(&c.item_id)?.pop_front())
                .collect())
        })
    }

    /// The Logins to offer first for `service` (a domain or a URL from the
    /// system), as item ids, at most six: the candidates of
    /// `autofill_candidates` (without `include_all`), with a TOTP for a
    /// `OneTimeCode` request, ranked by `fill_plan::score::order` with their
    /// memory of the site. The system never shows the page, so there is no
    /// form context: no typed username, no form shape, and the field asked
    /// for counts as recognized for the confidence. Without memory the order
    /// is that of `autofill_candidates`. No site gives an empty `Low` plan.
    pub fn autofill_plan(
        &self,
        service: String,
        request: FfiAutofillRequest,
        excluded_vault_ids: Vec<String>,
    ) -> Result<FfiAutofillPlan, OnePassError> {
        let excluded = parse_ids(&excluded_vault_ids)?;
        let Some(target) = site(&service) else {
            return Ok(FfiAutofillPlan {
                item_ids: Vec::new(),
                confidence: FfiConfidence::Low,
            });
        };
        let key = usage_site(&target);
        self.with(|repo| {
            let items = visible_items(repo, &excluded)?;
            let matched: Vec<(&Item, FfiMatchQuality)> = items
                .iter()
                .filter(|i| offerable(i))
                .filter(|i| request == FfiAutofillRequest::Password || filled(i, "totp"))
                .filter_map(|i| item_quality(&target, i).map(|(q, _)| (i, q)))
                .collect();
            let last = last_used_on(matched.iter().map(|(i, _)| *i), &key);
            let mut cands: Vec<Candidate> = matched
                .iter()
                .map(|(i, q)| {
                    let mut c = to_candidate(i, *q);
                    c.usage = i.usage_signal(&key, last, None);
                    c
                })
                .collect();
            let now = unix_now();
            order(&mut cands, None, now, Tiebreak::FavoriteThenRecent);
            let scores: Vec<i64> = cands.iter().map(|c| score(c, None, now)).collect();
            Ok(FfiAutofillPlan {
                confidence: ffi_confidence(confidence(&cands, &scores, true)),
                item_ids: cands
                    .iter()
                    .take(PLAN_MAX)
                    .map(|c| id_hex(c.item_id))
                    .collect(),
            })
        })
    }

    /// Remember that the system AutoFill filled `service` with the Login
    /// `record_id` (`"<vault id>:<item id>"`), for the next plans and
    /// identity ranks. The Login must be offerable (live, not hidden from
    /// AutoFill, outside `excluded_vault_ids`: `NotFound` otherwise) and
    /// match `service` as `autofill_candidates` matches it (`InvalidInput`
    /// otherwise, nothing written). The page is never seen: a site the Login
    /// already remembers keeps its shape, intent and steps (only the use
    /// moves); a new one gets no field roles, intent `Login`, one `Fill`
    /// step. Written with the force rule of the bridge's `note_fill` across
    /// the vaults not excluded. `true` when the item was rewritten (`false`:
    /// throttled within the hour, nothing changed).
    pub fn note_autofill_use(
        &self,
        record_id: String,
        service: String,
        excluded_vault_ids: Vec<String>,
    ) -> Result<bool, OnePassError> {
        let (vault_id, item_id) = parse_record_id(&record_id)?;
        let excluded = parse_ids(&excluded_vault_ids)?;
        if excluded.contains(&vault_id) {
            return Err(OnePassError::NotFound);
        }
        let target = site(&service).ok_or_else(|| invalid("service"))?;
        let key = usage_site(&target);
        self.with(|repo| {
            let items = visible_items(repo, &excluded)?;
            let item = items
                .iter()
                .find(|i| i.id == item_id && i.vault_id == vault_id && offerable(i))
                .ok_or(OnePassError::NotFound)?;
            if item_quality(&target, item).is_none() {
                return Err(invalid("service"));
            }
            let force = item.used_later_by_another(&key, items.iter().filter(|i| offerable(i)));
            let now = OffsetDateTime::now_utc();
            // A known entry (maybe the extension's) keeps its shape, intent
            // and steps: only the use moves, and the hourly throttle holds.
            let usage = match item.usage_on(&key) {
                Some(known) => SiteUsage {
                    count: 1,
                    last_at: now,
                    ..known.clone()
                },
                None => SiteUsage {
                    site: key.clone(),
                    form_shape_hash: form_shape_hash(&[]),
                    intent: Intent::Login,
                    step_seq: vec![StepKind::Fill],
                    count: 1,
                    last_at: now,
                },
            };
            let vault = find_vault(repo, vault_id)?;
            Ok(repo.record_usage(&vault, item_id, usage, now, force)?)
        })
    }

    /// The sites the items of the vaults not excluded remember (registrable
    /// domains, sorted), for "forget the choices for a site".
    pub fn known_usage_sites(
        &self,
        excluded_vault_ids: Vec<String>,
    ) -> Result<Vec<String>, OnePassError> {
        let excluded = parse_ids(&excluded_vault_ids)?;
        self.with(|repo| {
            let sites: BTreeSet<String> = visible_items(repo, &excluded)?
                .into_iter()
                .flat_map(|i| i.usage.into_iter().map(|u| u.site))
                .collect();
            Ok(sites.into_iter().collect())
        })
    }

    /// Forget `site` (a domain or a URL, reduced to its registrable domain)
    /// in every item of the vaults not excluded, as the bridge's
    /// `forget_site` does (`Repository::forget_site_usage_in`, best effort).
    /// Returns how many items were rewritten; an error when any vault could
    /// not be read or written (the others were still rewritten).
    pub fn forget_site_usage(
        &self,
        site: String,
        excluded_vault_ids: Vec<String>,
    ) -> Result<u32, OnePassError> {
        let excluded = parse_ids(&excluded_vault_ids)?;
        let key = self::site(&site)
            .map(|s| usage_site(&s))
            .ok_or_else(|| invalid("site"))?;
        self.with(|repo| {
            let n = repo.forget_site_usage_in(&key, |v| !excluded.contains(&v.id))?;
            Ok(u32::try_from(n).unwrap_or(u32::MAX))
        })
    }

    /// Create a passkey and store it: in the `passkeys` field of the Login
    /// `item_id` (adding the passkey login method if missing), or in a new
    /// Login of `vault_id` (`NotFound` for a trashed or archived Login).
    /// `PasskeyExcluded` when a live item already holds
    /// one of `excluded_credential_ids` for this relying party.
    pub fn create_passkey(
        &self,
        request: FfiPasskeyCreation,
    ) -> Result<FfiPasskeyRegistration, OnePassError> {
        let vault_id = parse_id(&request.vault_id)?;
        let item_id = request.item_id.as_deref().map(parse_id).transpose()?;
        self.with(|repo| {
            let vault = find_vault(repo, vault_id)?;
            if has_excluded(repo, &request.rp_id, &request.excluded_credential_ids)? {
                return Err(OnePassError::PasskeyExcluded);
            }
            let now = OffsetDateTime::now_utc();
            let mut item = match item_id {
                Some(id) => {
                    let item = find_item(repo, &vault, id)?;
                    // A trashed or archived item could not sign later.
                    if item.trashed_at.is_some() || item.archived {
                        return Err(OnePassError::NotFound);
                    }
                    if item.item_type != ItemType::Login {
                        return Err(invalid("passkey item"));
                    }
                    item
                }
                None => new_passkey_login(vault_id, &request, now),
            };
            let cred = webauthn::new_credential(
                &request.rp_id,
                &request.user_name,
                &request.user_handle,
                now,
            )?;
            let reg = webauthn::registration(&cred, &request.client_data_hash)?;
            if item_id.is_none() {
                item.record(now, onepass_core::model::EventKind::Created);
            }
            item.record(
                now,
                onepass_core::model::EventKind::PasskeyAdded {
                    rp_id: request.rp_id.clone(),
                },
            );
            add_passkey(&mut item, cred);
            if !item.login_methods.contains(&LoginMethod::Passkey) {
                item.login_methods.push(LoginMethod::Passkey);
            }
            item.updated_at = now;
            let item = crate::validate_for_save(item)?;
            let item_id = item.id;
            repo.save_item(&vault, item)?;
            Ok(FfiPasskeyRegistration {
                vault_id: id_hex(vault_id),
                item_id: id_hex(item_id),
                credential_id: reg.credential_id,
                attestation_object: reg.attestation_object,
            })
        })
    }

    /// Sign a passkey assertion with the passkey `credential_id` of a live
    /// Login. `NotFound` for an unknown credential or a trashed or archived
    /// item.
    pub fn passkey_assertion(
        &self,
        vault_id: String,
        item_id: String,
        credential_id: Vec<u8>,
        client_data_hash: Vec<u8>,
    ) -> Result<FfiPasskeyAssertion, OnePassError> {
        let (vault_id, item_id) = (parse_id(&vault_id)?, parse_id(&item_id)?);
        self.with(|repo| {
            let vault = find_vault(repo, vault_id)?;
            let item = find_item(repo, &vault, item_id)?;
            if !live_login(&item) {
                return Err(OnePassError::NotFound);
            }
            let cred = passkeys(&item)
                .find(|p| p.credential_id == credential_id)
                .ok_or(OnePassError::NotFound)?;
            let a = webauthn::assertion(cred, &client_data_hash)?;
            Ok(FfiPasskeyAssertion {
                user_handle: cred.user_handle.clone(),
                authenticator_data: a.authenticator_data,
                signature: a.signature,
                credential_id: cred.credential_id.clone(),
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(host: &str) -> Site {
        site(host).unwrap()
    }

    fn u(url: &str, rule: MatchRule) -> ItemUrl {
        ItemUrl {
            label: String::new(),
            url: url.into(),
            rule,
            primary: false,
        }
    }

    /// A fresh account with two Logins of `https://example.com`.
    fn two_logins() -> (tempfile::TempDir, std::sync::Arc<Session>, Id, Id, Id) {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("onepass.db").to_string_lossy().into_owned();
        let kdf = FfiKdfParams {
            m_kib: 8192,
            t: 1,
            p: 1,
        };
        let session = crate::create_account_with_kdf(path, "Cafe-etoile".into(), kdf)
            .unwrap()
            .session;
        let vault = session.vaults().unwrap()[0].id.clone();
        let mut ids = Vec::new();
        for title in ["A", "B"] {
            let mut item = session
                .new_item(vault.clone(), FfiItemType::Login, title.into())
                .unwrap();
            item.urls = vec![FfiUrl {
                label: String::new(),
                url: "https://example.com".into(),
                rule: FfiMatchRule::Domain,
                primary: true,
            }];
            for f in item.sections.iter_mut().flat_map(|s| s.fields.iter_mut()) {
                if f.id == "username" {
                    f.value = FfiFieldValue::Text {
                        value: title.to_lowercase(),
                    };
                }
            }
            ids.push(parse_id(&session.save_item(item).unwrap().id).unwrap());
        }
        (dir, session, parse_id(&vault).unwrap(), ids[0], ids[1])
    }

    fn usage_of(session: &Session, vault_id: Id, item_id: Id) -> SiteUsage {
        session
            .with(|repo| {
                let vault = find_vault(repo, vault_id)?;
                find_item(repo, &vault, item_id)
            })
            .unwrap()
            .usage_on("example.com")
            .cloned()
            .unwrap()
    }

    /// The extension remembered a shape, an intent and steps; a system
    /// AutoFill use only moves `last_at` and `count`, and stays throttled
    /// within the hour unless another Login used the site since.
    #[test]
    fn note_autofill_use_keeps_the_extension_entry() {
        use onepass_core::fill_plan::context::FieldRole;
        let (_dir, session, vault_id, a, b) = two_logins();
        let now = OffsetDateTime::now_utc();
        let shape = form_shape_hash(&[FieldRole::Username, FieldRole::CurrentPassword]);
        let steps = vec![StepKind::Fill, StepKind::ProviderClick];
        let bridge = |at: OffsetDateTime| SiteUsage {
            site: "example.com".into(),
            form_shape_hash: shape,
            intent: Intent::Signup,
            step_seq: steps.clone(),
            count: 1,
            last_at: at,
        };
        session
            .with(|repo| {
                let vault = find_vault(repo, vault_id)?;
                let t0 = now - time::Duration::minutes(10);
                let t1 = now - time::Duration::minutes(5);
                repo.record_usage(&vault, a, bridge(t0), t0, false)?;
                repo.record_usage(&vault, b, bridge(t1), t1, false)?;
                Ok(())
            })
            .unwrap();
        let record = |id: Id| format!("{}:{}", id_hex(vault_id), id_hex(id));
        let note = |id: Id| {
            session
                .note_autofill_use(record(id), "example.com".into(), Vec::new())
                .unwrap()
        };

        // B used the site after A: forced, and only the use moves.
        assert!(note(a));
        let u = usage_of(&session, vault_id, a);
        assert_eq!(u.form_shape_hash, shape);
        assert_eq!(u.intent, Intent::Signup);
        assert_eq!(u.step_seq, steps);
        assert_eq!(u.count, 2);
        assert!(u.last_at > now - time::Duration::minutes(1));

        // Within the hour, nothing else used the site: nothing written.
        assert!(!note(a));
        assert_eq!(usage_of(&session, vault_id, a).count, 2);
        // B is not the last any more: forced again, its entry kept too.
        assert!(note(b));
        let u = usage_of(&session, vault_id, b);
        assert_eq!((u.form_shape_hash, u.count), (shape, 2));
    }

    #[test]
    fn sites_are_normalized() {
        assert_eq!(s("WWW.Example.COM.").host, "www.example.com");
        assert_eq!(
            s("https://user@login.example.com:8443/x").host,
            "login.example.com"
        );
        assert_eq!(s("bücher.example").host, "xn--bcher-kva.example");
        assert!(s("192.168.1.10").ip);
        assert_eq!(s("[::1]:3000").host, "[::1]");
        assert!(site("http://example.com").is_none());
        assert!(site("http://localhost:8080").is_some());
        assert!(site("ftp://example.com").is_none());
        assert!(site("").is_none());
        assert_eq!(s("example.com/p?next=https://evil.net").host, "example.com");
    }

    #[test]
    fn domain_rule_uses_the_public_suffix_list() {
        let q = |svc: &str, url: &str| url_quality(&s(svc), &u(url, MatchRule::Domain));
        assert_eq!(
            q("a.example.com", "https://b.example.com"),
            Some(FfiMatchQuality::Domain)
        );
        assert_eq!(
            q("example.co.uk", "https://example.co.uk"),
            Some(FfiMatchQuality::ExactHost)
        );
        assert_eq!(q("a.example.co.uk", "https://co.uk"), None);
        assert_eq!(q("alice.github.io", "https://bob.github.io"), None);
        assert_eq!(q("10.0.0.1", "https://10.0.0.2"), None);
    }
}
