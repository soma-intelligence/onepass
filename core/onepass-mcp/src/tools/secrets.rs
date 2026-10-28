//! Secret tools (spec sections 4.2 and 4.3): `run_with_secrets` and
//! `fill_template` (`use`), `create_login` (`write`), `totp_code`
//! (`totp`), `reveal_secret` (`reveal`), and `generate_password`
//! (`allow_generate`).
//!
//! Order of the checks, always: arguments, pairing, visibility, scope,
//! then [`McpTools::approve`] (audit log usable, rate limits, grants,
//! prompt), strong authentication for `reveal_secret` and `totp_code`,
//! action. Every reference is located (vault, live item, field) before
//! anyone is asked, and no value is read before the user approves: a
//! request the policy refuses never reaches the approver.

use super::{Call, CallResult, McpTools, Refusal};
use crate::mask::mask;
use crate::policy::Scope;
use crate::port::{PortError, VaultInfo, VaultPort};
use crate::protocol::ClientInfo;
use crate::runner::RunRequest;
use crate::template::{render_template, template_refs};
use data_encoding::HEXLOWER;
use onepass_core::Id;
use onepass_core::generator::{
    CharsetOptions, PassphraseOptions, Recipe, Wordlist, entropy_bits, generate,
};
use onepass_core::model::{
    Field, FieldType, FieldValue, Item, ItemType, ItemUrl, MatchRule, new_item, validate,
};
use onepass_core::reference::{SecretRef, otp_field_of};
use onepass_core::totp::{TotpConfig, parse_otpauth, seconds_remaining, totp_from_secret};
use onepass_guard::{
    Admit, ApprovalRequest, Decision, GrantCheck, GrantRequest, Kind, MAX_GRANT_TTL,
    OUTCOME_GRANT_EXPIRED, OUTCOME_GRANT_REVOKED, StrongOutcome, Surface, Target, decision_label,
    sanitize_for_display,
};
use serde_json::{Map, Value, json};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

/// `run_with_secrets` timeout when none is given.
const DEFAULT_TIMEOUT_SECS: u64 = 60;
/// Password length of `create_login` and `generate_password` by default.
const DEFAULT_LENGTH: u8 = 24;
/// Longest command shown for approval, in characters. A longer one is
/// refused: the user must be able to read all of what they approve.
const MAX_SHOWN: usize = 8192;
/// Characters per detail line of an approval prompt (the prompt cuts each
/// line at 200, so long values are split instead of cut).
const DETAIL_CHUNK: usize = 150;
/// Most placeholders in one template.
const MAX_PLACEHOLDERS: usize = 256;

/// A reference located within reach: its vault, its live item, the field
/// it designates, and the reference rewritten with ids.
struct Located {
    vault: VaultInfo,
    item: Item,
    field_id: String,
    r: SecretRef,
}

impl Located {
    fn target(&self) -> Target {
        Target {
            vault: self.vault.name.clone(),
            item: self.item.title.clone(),
            field: Some(self.field_id.clone()),
        }
    }

    /// What a session grant is bound to: the resolved vault, item and field.
    fn key_material(&self) -> Value {
        json!([
            self.vault.id.to_string(),
            self.item.id.to_string(),
            self.field_id
        ])
    }

    /// One approval detail line: `vault / item / field`.
    fn shown(&self) -> String {
        format!(
            "{} / {} / {}",
            self.vault.name, self.item.title, self.field_id
        )
    }

    /// The located field (it exists: `locate` found it).
    fn field(&self) -> Result<&Field, Refusal> {
        field_of(&self.item, &self.r)
    }
}

/// Tools whose prompt is followed by strong authentication.
fn needs_strong(action: &str) -> bool {
    matches!(action, "reveal_secret" | "totp_code")
}

fn invalid(m: &str) -> Refusal {
    Refusal::Invalid(m.to_owned())
}

fn label_is(label: &str, seg: &str) -> bool {
    label.to_lowercase() == seg.to_lowercase()
}

/// The field `r` designates in `item`, by the core's rule: `totp` without
/// a section is the item's one filled OTP field; otherwise by id, then by
/// label (ignoring case); without a section, several matches are
/// ambiguous; within a section, the first match wins.
fn field_of<'a>(item: &'a Item, r: &SecretRef) -> Result<&'a Field, Refusal> {
    let found = match &r.section {
        None if r.field.eq_ignore_ascii_case("totp") => {
            Some(otp_field_of(item).map_err(|e| Refusal::from(PortError::from(e)))?)
        }
        None => {
            let all = || item.sections.iter().flat_map(|s| s.fields.iter());
            let by_id: Vec<&Field> = all().filter(|f| f.id == r.field).collect();
            let hits = if by_id.is_empty() {
                all().filter(|f| label_is(&f.label, &r.field)).collect()
            } else {
                by_id
            };
            match hits.as_slice() {
                [] => None,
                [f] => Some(*f),
                _ => {
                    return Err(invalid(
                        "invalid reference: ambiguous field, add the section",
                    ));
                }
            }
        }
        Some(sec) => {
            let by_id: Vec<_> = item.sections.iter().filter(|s| s.id == *sec).collect();
            let chosen = if by_id.is_empty() {
                item.sections
                    .iter()
                    .filter(|s| label_is(&s.label, sec))
                    .collect()
            } else {
                by_id
            };
            let all = || chosen.iter().flat_map(|s| s.fields.iter());
            all()
                .find(|f| f.id == r.field)
                .or_else(|| all().find(|f| label_is(&f.label, &r.field)))
        }
    };
    found.ok_or(Refusal::NotFound)
}

/// Adds `(label, value)` to `details`, split into lines the prompt shows
/// in full.
fn push_detail(details: &mut Vec<(String, String)>, label: &str, value: &str) {
    let chars: Vec<char> = sanitize_chars(value);
    if chars.is_empty() {
        details.push((label.to_owned(), String::new()));
    }
    for (i, chunk) in chars.chunks(DETAIL_CHUNK).enumerate() {
        let l = if i == 0 {
            label.to_owned()
        } else {
            format!("{label} (continued)")
        };
        details.push((l, chunk.iter().collect()));
    }
}

/// `value` with control and invisible format characters replaced, uncut.
fn sanitize_chars(value: &str) -> Vec<char> {
    value
        .chars()
        .map(|c| {
            let mut buf = [0u8; 4];
            let shown = sanitize_for_display(c.encode_utf8(&mut buf));
            shown.chars().next().unwrap_or('?')
        })
        .collect()
}

fn str_arg<'a>(args: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    args.get(key).and_then(Value::as_str)
}

/// `(name, reference)` pairs of an `env` or `files` argument.
fn names(args: &Map<String, Value>, key: &str) -> Vec<(String, String)> {
    args.get(key)
        .and_then(Value::as_object)
        .map(|o| {
            o.iter()
                .map(|(k, v)| (k.clone(), v.as_str().unwrap_or_default().to_owned()))
                .collect()
        })
        .unwrap_or_default()
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The TOTP configuration of an OTP field value, by the core's rules: an
/// `otpauth://` URI is parsed as one, anything else is a bare base32
/// secret. `None` for anything the core could not turn into a code (an
/// HOTP URI, bad base32, an empty value).
fn otp_config(value: &FieldValue) -> Option<TotpConfig> {
    let FieldValue::Otp(s) = value else {
        return None;
    };
    let s = s.trim();
    let cfg = if s
        .get(..10)
        .is_some_and(|h| h.eq_ignore_ascii_case("otpauth://"))
    {
        parse_otpauth(s)
    } else {
        totp_from_secret(s)
    };
    cfg.ok()
}

impl<P: VaultPort> McpTools<P> {
    /// Locates `reference` (vault, live item, field) without reading the
    /// value, and records it as a target of `call`.
    fn locate(&mut self, reference: &str, call: &mut Call) -> Result<Located, Refusal> {
        let (vault, item, r) = self.locate_restricted(reference)?;
        let field_id = match field_of(&item, &r) {
            Ok(f) => f.id.clone(),
            Err(e) => {
                call.target(vault.id, item.id, None);
                return Err(e);
            }
        };
        call.target(vault.id, item.id, Some(field_id.clone()));
        Ok(Located {
            vault,
            item,
            field_id,
            r,
        })
    }

    /// The vault every located reference is in, when there is only one.
    fn single_vault(located: &[Located]) -> Option<Id> {
        let first = located.first()?.vault.id;
        located.iter().all(|l| l.vault.id == first).then_some(first)
    }

    /// The grant key of a request: a digest of the client id and the
    /// canonical request (`material`), so the grants file holds no request
    /// data and a grant never covers another client.
    fn grant_key(&self, material: &str) -> String {
        let canonical = json!([self.client.client_id, material]).to_string();
        let d = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, canonical.as_bytes());
        HEXLOWER.encode(d.as_ref())
    }

    /// Counts a request of `kind` for the client, or refuses it (rate limit,
    /// cooling down after repeated denials, told once on the terminal).
    fn admit(&mut self, kind: Kind) -> Result<(), Refusal> {
        match self
            .throttle
            .admit(&*self.clock, &self.client.client_id, kind)
        {
            Admit::Ok => Ok(()),
            Admit::RateLimited => Err(Refusal::RateLimited),
            Admit::CoolingDown {
                until,
                first_notice,
            } => {
                if first_notice {
                    let left = until.saturating_duration_since(self.clock.monotonic());
                    eprintln!(
                        "onepass mcp: {} refused for {} min after repeated denials",
                        sanitize_for_display(&self.client.label),
                        left.as_secs().div_ceil(60)
                    );
                }
                Err(Refusal::CoolingDown)
            }
        }
    }

    /// Approves a secret request, in this order: the audit log must be
    /// appendable (a secret action is never performed when it could not be
    /// logged), the secret rate limit, then a live grant for exactly this
    /// request and client (only when `remember_allowed`), else the prompt
    /// rate limit and the prompt (identical pending prompts are coalesced).
    /// An expired or revoked grant is logged, then the user is asked again.
    /// `AllowFor` records a grant in the signed grants file. Sets the
    /// decision label.
    #[allow(clippy::too_many_arguments)]
    fn approve(
        &mut self,
        client: &ClientInfo,
        action: &str,
        details: Vec<(String, String)>,
        targets: Vec<Target>,
        remember_allowed: bool,
        key: Option<String>,
        vault_id: Option<Id>,
        call: &mut Call,
    ) -> Result<(), Refusal> {
        if self.audit.ready().is_err() {
            return Err(Refusal::AuditUnusable);
        }
        self.admit(Kind::Secret)?;
        let key = key.filter(|_| remember_allowed).map(|k| self.grant_key(&k));
        if let Some(k) = &key {
            let check = self.grants.lock().unwrap_or_else(|e| e.into_inner()).check(
                &*self.grants_signer,
                &*self.clock,
                &self.client.client_id,
                Surface::Mcp,
                action,
                k,
            );
            match check {
                GrantCheck::Valid(_) => {
                    call.decision = "remembered";
                    return Ok(());
                }
                GrantCheck::Expired => self.record(client, action, call, OUTCOME_GRANT_EXPIRED),
                GrantCheck::Revoked => self.record(client, action, call, OUTCOME_GRANT_REVOKED),
                GrantCheck::None => {}
            }
        }
        self.admit(Kind::Prompt)?;
        // Coalescing key: the grant key, else the request as shown.
        let gate_key = match &key {
            Some(k) => k.clone(),
            None => {
                let shown: Vec<Value> = targets
                    .iter()
                    .map(|t| json!([t.vault, t.item, t.field]))
                    .collect();
                self.grant_key(&json!([action, details, shown]).to_string())
            }
        };
        let declared = &client.name;
        let who = if self.client.signed {
            format!("{} (declared: {declared})", self.client.label)
        } else {
            format!("{} (unsigned, declared: {declared})", self.client.label)
        };
        let req = ApprovalRequest {
            surface: Surface::Mcp,
            client: who,
            // Only a paired client reaches a prompt: its label is verified.
            client_verified: true,
            action: action.to_owned(),
            details,
            targets,
            remember_allowed,
        };
        let gated = self.gate.approve(&self.client.client_id, &gate_key, &req);
        // A prompt allowed for a tool that also needs strong authentication
        // ends the run of denials only once strong authentication succeeds
        // (see `strong_auth`): a client cannot reset it by having the user
        // approve a prompt and then fail Touch ID.
        let strong_follows = needs_strong(action) && gated.decision != Decision::Deny;
        if !gated.joined && !strong_follows {
            self.throttle.record_decision(
                &*self.clock,
                &self.client.client_id,
                gated.decision == Decision::Deny,
            );
        }
        let label = |l: &'static str| if gated.joined { "joined" } else { l };
        match gated.decision {
            Decision::Deny => {
                call.decision = label("denied");
                Err(Refusal::Denied)
            }
            Decision::AllowFor(d) if key.is_some() => {
                let d = d.min(MAX_GRANT_TTL);
                call.decision = label(decision_label(&Decision::AllowFor(d)));
                let req = GrantRequest {
                    client_id: self.client.client_id.clone(),
                    surface: Surface::Mcp,
                    action: action.to_owned(),
                    key: key.unwrap_or_default(),
                    vault_id: vault_id.map(|v| v.to_string()),
                };
                let added = self.grants.lock().unwrap_or_else(|e| e.into_inner()).add(
                    &*self.grants_signer,
                    &*self.clock,
                    req,
                    d,
                );
                // The user allowed this request: it goes ahead even if the
                // grant could not be stored (the next one asks again).
                if let Err(err) = added {
                    eprintln!("onepass mcp: grant not recorded: {err}");
                }
                Ok(())
            }
            Decision::AllowOnce | Decision::AllowFor(_) => {
                call.decision = label("once");
                Ok(())
            }
        }
    }

    /// Strong authentication (spec 4.4) after the prompt, for the tools
    /// that return a value. The reason names the client and the target. A
    /// failed authentication counts as a user denial (toward the cooling
    /// down period), a success ends the run of denials; `Unavailable` (no
    /// method could run) counts as neither.
    fn strong_auth(&mut self, action: &str, l: &Located) -> Result<(), Refusal> {
        let reason = sanitize_for_display(&format!(
            "{action} for {}: {}",
            self.client.label,
            l.shown()
        ));
        let outcome = self.strong.verify(&reason);
        let (clock, id) = (&*self.clock, &self.client.client_id);
        match outcome {
            StrongOutcome::Verified => {
                self.throttle.record_decision(clock, id, false);
                Ok(())
            }
            StrongOutcome::Denied => {
                self.throttle.record_decision(clock, id, true);
                Err(Refusal::StrongAuthFailed)
            }
            StrongOutcome::Unavailable => Err(Refusal::StrongAuthFailed),
        }
    }

    /// Locates every reference, then checks the `use` scope on each vault.
    fn locate_for_use<'n>(
        &mut self,
        refs: impl IntoIterator<Item = &'n str>,
        call: &mut Call,
    ) -> Result<Vec<Located>, Refusal> {
        let mut located = Vec::new();
        for r in refs {
            located.push(self.locate(r, call)?);
        }
        for l in &located {
            self.require(&l.vault, Scope::Use)?;
        }
        Ok(located)
    }

    /// `run_with_secrets {command, env?, files?, cwd?, timeout_secs?}`.
    pub(super) fn run_with_secrets(
        &mut self,
        client: &ClientInfo,
        args: &Map<String, Value>,
        call: &mut Call,
    ) -> CallResult {
        let argv: Vec<String> = args
            .get("command")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        let env = names(args, "env");
        let files = names(args, "files");
        let cwd = str_arg(args, "cwd");
        let timeout = args
            .get("timeout_secs")
            .and_then(Value::as_u64)
            .unwrap_or(DEFAULT_TIMEOUT_SECS);
        let shown = argv.join(" ");
        if shown.chars().count() > MAX_SHOWN {
            return Err(invalid("command is too long to show for approval").into());
        }

        let refs = env.iter().chain(&files).map(|(_, r)| r.as_str());
        let located = self.locate_for_use(refs, call)?;

        let mut details = Vec::new();
        push_detail(&mut details, "command", &shown);
        push_detail(
            &mut details,
            "cwd",
            cwd.unwrap_or("(the server's working directory)"),
        );
        // `located` follows `env` then `files`, in the same order.
        let named = env
            .iter()
            .map(|(n, _)| ("env", n))
            .chain(files.iter().map(|(n, _)| ("file", n)));
        for ((kind, name), l) in named.zip(&located) {
            push_detail(&mut details, kind, &format!("{name} = {}", l.shown()));
        }
        let remember = !located.iter().any(|l| l.item.reprompt);
        // Session grants cover exactly this request: argv, both maps (keys
        // sorted by serde_json), the working directory, and what each
        // reference resolved to.
        let resolved: Vec<Value> = located.iter().map(Located::key_material).collect();
        let key = json!([
            "run_with_secrets",
            argv,
            args.get("env"),
            args.get("files"),
            cwd,
            resolved
        ]);
        self.approve(
            client,
            "run_with_secrets",
            details,
            located.iter().map(Located::target).collect(),
            remember,
            Some(key.to_string()),
            Self::single_vault(&located),
            call,
        )?;

        let mut values = Vec::with_capacity(located.len());
        for l in &located {
            values.push(self.read_value(&l.vault, &l.r)?);
        }
        let mut values = values.into_iter();
        let mut take = |list: &[(String, String)]| -> Vec<(String, Zeroizing<String>)> {
            list.iter()
                .map(|(n, _)| (n.clone(), values.next().unwrap_or_default()))
                .collect()
        };
        let req = RunRequest {
            argv,
            env: take(&env),
            files: take(&files),
            cwd: cwd.map(PathBuf::from),
            timeout: Duration::from_secs(timeout),
        };
        let out = self.workspace.run(&req)?;
        let secrets: Vec<(&str, &str)> = req
            .env
            .iter()
            .chain(&req.files)
            .map(|(n, v)| (n.as_str(), v.as_str()))
            .collect();
        Ok(json!({
            "exit_code": out.code,
            "stdout": mask(&out.stdout, &secrets),
            "stderr": mask(&out.stderr, &secrets),
            "timed_out": out.timed_out,
            "truncated": out.truncated,
        }))
    }

    /// `fill_template {template_path, output_path, overwrite?}`.
    pub(super) fn fill_template(
        &mut self,
        client: &ClientInfo,
        args: &Map<String, Value>,
        call: &mut Call,
    ) -> CallResult {
        let template_path = str_arg(args, "template_path").unwrap_or_default();
        let output_path = str_arg(args, "output_path").unwrap_or_default();
        let overwrite = args
            .get("overwrite")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        self.workspace
            .check_output(Path::new(output_path), overwrite, self.forbidden_dir())?;
        let template = self
            .workspace
            .read_template(Path::new(template_path), self.forbidden_dir())?;
        let refs = template_refs(&template);
        if refs.is_empty() {
            return Err(invalid("template has no {{ onepass://... }} placeholder").into());
        }
        if refs.len() > MAX_PLACEHOLDERS {
            return Err(invalid("template has too many placeholders").into());
        }

        let located = self.locate_for_use(refs.iter().map(|(_, r)| r.as_str()), call)?;

        let mut details = Vec::new();
        push_detail(&mut details, "template", template_path);
        push_detail(&mut details, "output", output_path);
        push_detail(
            &mut details,
            "overwrite",
            if overwrite { "yes" } else { "no" },
        );
        for l in &located {
            push_detail(&mut details, "reference", &l.shown());
        }
        let remember = !located.iter().any(|l| l.item.reprompt);
        // The references are part of the key: an edited template asks again.
        let placeholders: Vec<&str> = refs.iter().map(|(_, r)| r.as_str()).collect();
        let resolved: Vec<Value> = located.iter().map(Located::key_material).collect();
        let key = json!([
            "fill_template",
            template_path,
            output_path,
            overwrite,
            placeholders,
            resolved
        ]);
        self.approve(
            client,
            "fill_template",
            details,
            located.iter().map(Located::target).collect(),
            remember,
            Some(key.to_string()),
            Self::single_vault(&located),
            call,
        )?;

        let mut values = Vec::with_capacity(located.len());
        for l in &located {
            values.push(self.read_value(&l.vault, &l.r)?);
        }
        let rendered = render_template(&template, &values);
        // Checked again: the path may have changed while the user decided.
        self.workspace.write_output(
            Path::new(output_path),
            &rendered,
            overwrite,
            self.forbidden_dir(),
        )?;
        Ok(json!({"replaced": refs.len(), "output_path": output_path}))
    }

    /// `create_login {vault, title, url?, username?, length?}`.
    pub(super) fn create_login(
        &mut self,
        client: &ClientInfo,
        args: &Map<String, Value>,
        call: &mut Call,
    ) -> CallResult {
        let title = str_arg(args, "title").unwrap_or_default();
        let url = str_arg(args, "url");
        let username = str_arg(args, "username");
        let length = args
            .get("length")
            .and_then(Value::as_u64)
            .and_then(|n| u8::try_from(n).ok())
            .unwrap_or(DEFAULT_LENGTH);

        let vault = self.find_vault(str_arg(args, "vault").unwrap_or_default())?;
        call.vault_id = Some(vault.id);
        self.require(&vault, Scope::Write)?;

        let mut item = new_item(ItemType::Login, vault.id, title);
        if let Some(u) = username
            && let Some(f) = item.field_mut("username")
        {
            f.value = FieldValue::Text(u.to_owned());
        }
        if let Some(url) = url {
            item.urls.push(ItemUrl {
                label: "website".into(),
                url: url.to_owned(),
                rule: MatchRule::Domain,
                primary: true,
            });
        }
        // Refused before asking: the user never approves a doomed request.
        validate(&item).map_err(|e| Refusal::from(PortError::from(e)))?;

        let mut details = Vec::new();
        push_detail(&mut details, "title", title);
        push_detail(&mut details, "username", username.unwrap_or(""));
        push_detail(&mut details, "url", url.unwrap_or(""));
        push_detail(
            &mut details,
            "password",
            &format!("random, {length} characters"),
        );
        let target = Target {
            vault: vault.name.clone(),
            item: title.to_owned(),
            field: None,
        };
        self.approve(
            client,
            "create_login",
            details,
            vec![target],
            false,
            None,
            Some(vault.id),
            call,
        )?;

        let recipe = Recipe::Random(CharsetOptions {
            length,
            lower: true,
            upper: true,
            digits: true,
            symbols: true,
            avoid_ambiguous: false,
        });
        let password = generate(&recipe).map_err(|e| Refusal::from(PortError::from(e)))?;
        if let Some(f) = item.field_mut("password") {
            f.value = FieldValue::Password(password);
        }
        let item_id = item.id;
        call.item_id = Some(item_id);
        call.field = Some("password".into());
        self.store_item(&vault, item)?;
        Ok(json!({
            "item_id": item_id.to_string(),
            "reference": format!("onepass://{}/{item_id}/password", vault.id),
        }))
    }

    /// `generate_password {length?, symbols?, words?, pin_digits?}`.
    pub(super) fn generate_password(&mut self, args: &Map<String, Value>) -> CallResult {
        if !self.policy.allow_generate {
            return Err(invalid("password generation is disabled by policy").into());
        }
        let small = |key: &str| {
            args.get(key)
                .and_then(Value::as_u64)
                .and_then(|n| u8::try_from(n).ok())
        };
        let recipe = if let Some(words) = small("words") {
            Recipe::Passphrase(PassphraseOptions {
                words,
                separator: "-".into(),
                capitalize: false,
                include_digit: false,
                list: Wordlist::EffEnglish,
            })
        } else if let Some(digits) = small("pin_digits") {
            Recipe::Pin { digits }
        } else {
            Recipe::Random(CharsetOptions {
                length: small("length").unwrap_or(DEFAULT_LENGTH),
                lower: true,
                upper: true,
                digits: true,
                symbols: args.get("symbols").and_then(Value::as_bool).unwrap_or(true),
                avoid_ambiguous: false,
            })
        };
        let password = generate(&recipe).map_err(|e| Refusal::from(PortError::from(e)))?;
        let bits = (entropy_bits(&recipe) * 10.0).round() / 10.0;
        Ok(json!({"password": password.as_str(), "entropy_bits": bits}))
    }

    /// `totp_code {reference}`: approved on every call, never remembered,
    /// then strong authentication.
    pub(super) fn totp_code(
        &mut self,
        client: &ClientInfo,
        args: &Map<String, Value>,
        call: &mut Call,
    ) -> CallResult {
        let l = self.locate(str_arg(args, "reference").unwrap_or_default(), call)?;
        self.require(&l.vault, Scope::Totp)?;
        let field = l.field()?;
        if field.kind != FieldType::Otp {
            return Err(invalid("reference is not a one-time password field").into());
        }
        if !matches!(&field.value, FieldValue::Otp(s) if !s.trim().is_empty()) {
            return Err(invalid("invalid reference: field is empty").into());
        }
        // Parsed before asking: a value the core cannot use (HOTP, bad
        // base32) is refused here, never after the user said yes.
        let cfg =
            otp_config(&field.value).ok_or_else(|| invalid("unsupported one-time password"))?;
        self.approve(
            client,
            "totp_code",
            Vec::new(),
            vec![l.target()],
            false,
            None,
            Some(l.vault.id),
            call,
        )?;
        self.strong_auth("totp_code", &l)?;
        let code = self.read_value(&l.vault, &l.r)?;
        Ok(json!({
            "code": code.as_str(),
            "seconds_remaining": seconds_remaining(&cfg, now()),
        }))
    }

    /// `reveal_secret {reference}`: approved on every call, never
    /// remembered, then strong authentication. The value comes back as
    /// untrusted vault data.
    pub(super) fn reveal_secret(
        &mut self,
        client: &ClientInfo,
        args: &Map<String, Value>,
        call: &mut Call,
    ) -> CallResult {
        let l = self.locate(str_arg(args, "reference").unwrap_or_default(), call)?;
        self.require(&l.vault, Scope::Reveal)?;
        self.approve(
            client,
            "reveal_secret",
            Vec::new(),
            vec![l.target()],
            false,
            None,
            Some(l.vault.id),
            call,
        )?;
        self.strong_auth("reveal_secret", &l)?;
        let value = self.read_value(&l.vault, &l.r)?;
        Ok(super::untrusted(json!({"value": value.as_str()})))
    }
}
