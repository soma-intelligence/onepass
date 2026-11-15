//! The site pack: which sites offer 2FA and passkeys, where their settings pages are, and the
//! setup recipes checked by hand (`scripts/site_pack.py` builds and signs it).
//!
//! Pack format 1 is compact JSON, at most 16 MiB and 100,000 sites. A site entry that fails its
//! own checks is skipped; a setup block with a refused recipe keeps its URL and loses the
//! recipe; the whole pack is refused only for bad JSON, a wrong `format` or a cap overrun.
//! A downloaded pack is used only after [`verify_signed`] accepts it, at download and at every
//! load. No recipe runs in this wave.

pub mod recipe;

use std::collections::BTreeMap;

use aws_lc_rs::digest::{SHA256, digest};
use aws_lc_rs::signature::{ED25519, UnparsedPublicKey};
use data_encoding::{BASE64, HEXLOWER};
use serde_json::{Map, Value};

use crate::{Error, IntegrityError, Result};
pub use recipe::{RecipeStep, Role, SetupKind, Step, Target, url_allowed, validate_recipe};

pub const FORMAT: u64 = 1;
pub const MAX_PACK_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_SITES: usize = 100_000;
const MAX_MANIFEST_BYTES: usize = 64 * 1024;
const MAX_SIGNATURE_BYTES: usize = 256;
const MAX_DOMAIN_LEN: usize = 253;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SitePack {
    pub version: u64,
    pub sites: BTreeMap<String, PackSite>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackSite {
    pub twofa: Vec<String>,
    pub passkey: Option<PasskeyLevel>,
    pub help: Option<String>,
    pub additional_domains: Vec<String>,
    pub setup_totp: Option<SiteSetup>,
    pub setup_passkey: Option<SiteSetup>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasskeyLevel {
    Signin,
    Mfa,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SiteSetup {
    pub url: String,
    /// `None` when the block carries no steps or its recipe was refused.
    pub recipe: Option<Vec<RecipeStep>>,
}

fn bad(what: &'static str) -> Error {
    Error::InvalidFormat(what)
}

fn domain_ok(d: &str) -> bool {
    !d.is_empty()
        && d.len() <= MAX_DOMAIN_LEN
        && d.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
}

fn verified_ok(v: Option<&Value>) -> bool {
    let Some(v) = v.and_then(Value::as_object) else {
        return false;
    };
    let (Some(date), Some(browser)) = (
        v.get("date").and_then(Value::as_str),
        v.get("browser").and_then(Value::as_str),
    ) else {
        return false;
    };
    v.len() == 2 && date_ok(date) && matches!(browser, "chromium" | "firefox" | "safari")
}

fn date_ok(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
        return false;
    }
    let num = |r: std::ops::Range<usize>| -> Option<u32> {
        s.get(r)
            .filter(|t| t.bytes().all(|c| c.is_ascii_digit()))?
            .parse()
            .ok()
    };
    let (Some(y), Some(m), Some(d)) = (num(0..4), num(5..7), num(8..10)) else {
        return false;
    };
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let days = match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    y >= 1 && (1..=days).contains(&d)
}

/// A setup block: `None` when it is not a verified block with a safe URL.
fn parse_setup(block: &Value, kind: SetupKind, domains: &[&str]) -> Option<SiteSetup> {
    let block = block.as_object()?;
    if !verified_ok(block.get("verified")) {
        return None;
    }
    let url = block.get("url")?.as_str()?;
    if !url_allowed(url, domains) {
        return None;
    }
    let recipe = match block.get("steps") {
        Some(Value::Array(steps)) if !steps.is_empty() => {
            validate_recipe(kind, steps, domains).ok()
        }
        _ => None,
    };
    Some(SiteSetup {
        url: url.to_owned(),
        recipe,
    })
}

fn string_list(v: Option<&Value>) -> Option<Vec<String>> {
    match v {
        None => Some(Vec::new()),
        Some(Value::Array(items)) => items
            .iter()
            .map(|i| i.as_str().map(str::to_owned))
            .collect(),
        Some(_) => None,
    }
}

fn parse_site(site: &Map<String, Value>, domain: &str) -> Option<PackSite> {
    let twofa = string_list(site.get("twofa"))?;
    let additional_domains = string_list(site.get("additional_domains"))?;
    if !additional_domains.iter().all(|d| domain_ok(d)) {
        return None;
    }
    let passkey = match site.get("passkey") {
        None => None,
        Some(Value::String(s)) if s == "signin" => Some(PasskeyLevel::Signin),
        Some(Value::String(s)) if s == "mfa" => Some(PasskeyLevel::Mfa),
        Some(_) => return None,
    };
    let help = site
        .get("help")
        .and_then(Value::as_str)
        .filter(|h| h.len() > "https://".len() && url_text_ok(h))
        .map(str::to_owned);
    let mut domains = vec![domain];
    domains.extend(additional_domains.iter().map(String::as_str));
    let setup_totp = site
        .get("setup_totp")
        .and_then(|b| parse_setup(b, SetupKind::Totp, &domains));
    let setup_passkey = site
        .get("setup_passkey")
        .and_then(|b| parse_setup(b, SetupKind::Passkey, &domains));
    Some(PackSite {
        twofa,
        passkey,
        help,
        additional_domains,
        setup_totp,
        setup_passkey,
    })
}

fn url_text_ok(s: &str) -> bool {
    s.len() <= recipe::MAX_URL_BYTES
        && s.starts_with("https://")
        && s.bytes().all(|b| b.is_ascii_graphic())
}

/// Parses a pack (format 1). Refuses bad JSON, a wrong `format`, a missing `version`, more than
/// 16 MiB or 100,000 sites; skips site entries and drops recipes that fail their own checks.
pub fn parse(pack: &[u8]) -> Result<SitePack> {
    if pack.len() > MAX_PACK_BYTES {
        return Err(bad("site pack too large"));
    }
    let root: Value = serde_json::from_slice(pack).map_err(|_| bad("site pack is not JSON"))?;
    let root = root.as_object().ok_or(bad("site pack is not an object"))?;
    if root.get("format").and_then(Value::as_u64) != Some(FORMAT) {
        return Err(bad("site pack format is not 1"));
    }
    let version = root
        .get("version")
        .and_then(Value::as_u64)
        .ok_or(bad("site pack has no version"))?;
    let sites = root
        .get("sites")
        .and_then(Value::as_object)
        .ok_or(bad("site pack has no sites"))?;
    if sites.len() > MAX_SITES {
        return Err(bad("site pack has too many sites"));
    }
    let mut out = BTreeMap::new();
    for (domain, site) in sites {
        if !domain_ok(domain) {
            continue;
        }
        if let Some(site) = site.as_object().and_then(|s| parse_site(s, domain)) {
            out.insert(domain.clone(), site);
        }
    }
    Ok(SitePack {
        version,
        sites: out,
    })
}

fn manifest_pack_name_ok(name: &str) -> bool {
    let Some(digits) = name
        .strip_prefix("onepass-sites-")
        .and_then(|n| n.strip_suffix(".json"))
    else {
        return false;
    };
    (1..=12).contains(&digits.len()) && digits.bytes().all(|b| b.is_ascii_digit())
}

/// Verifies a signed pack and returns it. `signature` is the `.sig` file (base64 of the 64-byte
/// Ed25519 signature over the exact manifest bytes, then a newline); `public_key` is the raw
/// 32-byte key. Checks the signature, the manifest's file name, the pack's size and SHA-256, and
/// that the pack's version is the manifest's.
pub fn verify_signed(
    manifest: &[u8],
    signature: &[u8],
    pack: &[u8],
    public_key: &[u8],
) -> Result<SitePack> {
    let sig_error = Error::Integrity(IntegrityError::Signature);
    if signature.len() > MAX_SIGNATURE_BYTES || manifest.len() > MAX_MANIFEST_BYTES {
        return Err(sig_error);
    }
    let text =
        std::str::from_utf8(signature).map_err(|_| Error::Integrity(IntegrityError::Signature))?;
    let sig = BASE64
        .decode(text.trim().as_bytes())
        .map_err(|_| Error::Integrity(IntegrityError::Signature))?;
    UnparsedPublicKey::new(&ED25519, public_key)
        .verify(manifest, &sig)
        .map_err(|_| sig_error)?;

    let manifest: Value =
        serde_json::from_slice(manifest).map_err(|_| bad("site pack manifest is not JSON"))?;
    if manifest.get("format").and_then(Value::as_u64) != Some(FORMAT) {
        return Err(bad("site pack manifest format is not 1"));
    }
    let version = manifest
        .get("version")
        .and_then(Value::as_u64)
        .ok_or(bad("site pack manifest has no version"))?;
    let entry = manifest
        .get("pack")
        .and_then(Value::as_object)
        .ok_or(bad("site pack manifest has no pack entry"))?;
    let file = entry.get("file").and_then(Value::as_str).unwrap_or("");
    if !manifest_pack_name_ok(file) {
        return Err(bad("site pack manifest names an unexpected file"));
    }
    let size = entry.get("size").and_then(Value::as_u64);
    let sha = entry.get("sha256").and_then(Value::as_str);
    let mismatch = Error::Integrity(IntegrityError::ManifestItemMismatch);
    let (Some(size), Some(sha)) = (size, sha) else {
        return Err(bad("site pack manifest pack entry is incomplete"));
    };
    if pack.len() as u64 != size || HEXLOWER.encode(digest(&SHA256, pack).as_ref()) != sha {
        return Err(mismatch);
    }
    let parsed = parse(pack)?;
    if parsed.version != version {
        return Err(bad("site pack version differs from its manifest"));
    }
    Ok(parsed)
}
