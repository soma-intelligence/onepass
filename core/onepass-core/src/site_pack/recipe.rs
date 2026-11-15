//! Setup recipes of the site pack: a closed vocabulary of steps, checked again at every load.
//! The rules mirror `scripts/site_pack.py` (`validate_recipe`); the shared fixtures under
//! `tests/fixtures/site-pack/recipes` keep the two in step. No recipe runs in this wave.

use serde_json::{Map, Value};

pub const MAX_STEPS: usize = 12;
pub const MAX_TIMEOUT_S: u64 = 60;
pub const DEFAULT_TIMEOUT_S: u8 = 60;
pub const MAX_URL_BYTES: usize = 2048;

const DESTRUCTIVE_WORDS: [&str; 16] = [
    "delete",
    "disable",
    "remove",
    "pay",
    "supprimer",
    "désactiver",
    "retirer",
    "payer",
    "eliminar",
    "desactivar",
    "quitar",
    "pagar",
    "elimina",
    "disattiva",
    "rimuovi",
    "paga",
];
const FINAL_NAMES: [&str; 14] = [
    "verify",
    "activate",
    "confirm",
    "submit",
    "vérifier",
    "activer",
    "confirmer",
    "valider",
    "verificar",
    "activar",
    "confirmar",
    "verifica",
    "attiva",
    "conferma",
];

/// Which setup block a recipe belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetupKind {
    Totp,
    Passkey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Button,
    Link,
    Radio,
    Checkbox,
    Tab,
    MenuItem,
    Option,
}

impl Role {
    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "button" => Self::Button,
            "link" => Self::Link,
            "radio" => Self::Radio,
            "checkbox" => Self::Checkbox,
            "tab" => Self::Tab,
            "menuitem" => Self::MenuItem,
            "option" => Self::Option,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub role: Role,
    pub names: Vec<String>,
    pub css: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    Goto { url: String },
    Click(Target),
    WaitFor(Target),
    Reauth,
    ExpectQr,
    ExpectPasskeyPrompt,
    Done,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipeStep {
    pub step: Step,
    pub timeout_s: u8,
}

fn is_word_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// True when `word` occurs in `text` with no word character on either side.
fn has_whole_word(text: &str, word: &str) -> bool {
    text.match_indices(word).any(|(at, _)| {
        let before = text[..at].chars().next_back();
        let after = text[at + word.len()..].chars().next();
        !before.is_some_and(is_word_char) && !after.is_some_and(is_word_char)
    })
}

/// `url` is https, printable ASCII, at most 2048 bytes, with no userinfo or port, and its host
/// is one of `domains` or a subdomain of one.
pub fn url_allowed(url: &str, domains: &[&str]) -> bool {
    if url.is_empty()
        || url.len() > MAX_URL_BYTES
        || !url.bytes().all(|b| (0x21..=0x7e).contains(&b))
    {
        return false;
    }
    let Some((scheme, rest)) = url.split_once("://") else {
        return false;
    };
    if !scheme.eq_ignore_ascii_case("https") {
        return false;
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.contains(['@', ':', '\\', '[', ']']) {
        return false;
    }
    let host = authority.to_ascii_lowercase();
    let host = host.trim_end_matches('.');
    !host.is_empty()
        && domains.iter().any(|d| {
            let d = d.to_ascii_lowercase();
            host == d || host.ends_with(&format!(".{d}"))
        })
}

fn timeout(step: &Map<String, Value>) -> Result<u8, &'static str> {
    match step.get("timeout_s") {
        None => Ok(DEFAULT_TIMEOUT_S),
        Some(v) => match v.as_u64() {
            Some(t @ 1..=MAX_TIMEOUT_S) => Ok(t as u8),
            _ => Err("timeout_s is not an integer from 1 to 60"),
        },
    }
}

fn target(step: &Map<String, Value>, click: bool) -> Result<Target, &'static str> {
    let role = step
        .get("role")
        .and_then(Value::as_str)
        .and_then(Role::parse)
        .ok_or("role is not in the vocabulary")?;
    let list = step
        .get("name")
        .and_then(Value::as_array)
        .filter(|l| !l.is_empty())
        .ok_or("name is not a non-empty list")?;
    let mut names = Vec::with_capacity(list.len());
    for n in list {
        let n = n.as_str().ok_or("a name is not a string")?;
        if !(1..=80).contains(&n.trim().chars().count()) || n.chars().count() > 80 {
            return Err("a name is not a string of 1 to 80 characters");
        }
        if click {
            let folded = n.trim().to_lowercase();
            if DESTRUCTIVE_WORDS.iter().any(|w| has_whole_word(&folded, w)) {
                return Err("click name contains a destructive word");
            }
            if FINAL_NAMES.contains(&folded.as_str()) {
                return Err("click name is a final verify or activate click");
            }
        }
        names.push(n.to_owned());
    }
    let css = match step.get("css") {
        None => None,
        Some(Value::String(s)) if s.chars().count() <= 200 => Some(s.clone()),
        Some(_) => return Err("css is not a string of at most 200 characters"),
    };
    Ok(Target { role, names, css })
}

fn no_extra_keys(step: &Map<String, Value>, allowed: &[&str]) -> Result<(), &'static str> {
    if step
        .keys()
        .all(|k| k == "do" || k == "timeout_s" || allowed.contains(&k.as_str()))
    {
        Ok(())
    } else {
        Err("unknown key for this step")
    }
}

fn parse_step(value: &Value, domains: &[&str]) -> Result<(Step, u8), &'static str> {
    let step = value.as_object().ok_or("step is not an object")?;
    let name = step.get("do").and_then(Value::as_str).unwrap_or("");
    let parsed = match name {
        "goto" => {
            no_extra_keys(step, &["url"])?;
            let url = step.get("url").and_then(Value::as_str).unwrap_or("");
            if !url_allowed(url, domains) {
                return Err("goto url is not https on the site's domains");
            }
            Step::Goto {
                url: url.to_owned(),
            }
        }
        "click" => {
            no_extra_keys(step, &["role", "name", "css"])?;
            Step::Click(target(step, true)?)
        }
        "wait_for" => {
            no_extra_keys(step, &["role", "name", "css"])?;
            Step::WaitFor(target(step, false)?)
        }
        "reauth" => {
            no_extra_keys(step, &[])?;
            Step::Reauth
        }
        "expect_qr" => {
            no_extra_keys(step, &[])?;
            Step::ExpectQr
        }
        "expect_passkey_prompt" => {
            no_extra_keys(step, &[])?;
            Step::ExpectPasskeyPrompt
        }
        "done" => {
            no_extra_keys(step, &[])?;
            Step::Done
        }
        _ => return Err("unknown step"),
    };
    Ok((parsed, timeout(step)?))
}

/// Checks a recipe against the rules and returns its typed steps, or the first reason it is
/// refused. An empty list is valid (a setup block that only carries a URL). `domains` are the
/// site's domain and its additional domains.
pub fn validate_recipe(
    kind: SetupKind,
    steps: &[Value],
    domains: &[&str],
) -> core::result::Result<Vec<RecipeStep>, &'static str> {
    if steps.len() > MAX_STEPS {
        return Err("more than 12 steps");
    }
    let mut out = Vec::with_capacity(steps.len());
    for value in steps {
        let (step, timeout_s) = parse_step(value, domains)?;
        out.push(RecipeStep { step, timeout_s });
    }
    let (own, other) = match kind {
        SetupKind::Totp => (Step::ExpectQr, Step::ExpectPasskeyPrompt),
        SetupKind::Passkey => (Step::ExpectPasskeyPrompt, Step::ExpectQr),
    };
    if out.iter().any(|s| s.step == other) {
        return Err("recipe contains the other kind's expect step");
    }
    if out.last().is_some_and(|s| s.step != own) {
        return Err("recipe does not end with its expect step");
    }
    Ok(out)
}
