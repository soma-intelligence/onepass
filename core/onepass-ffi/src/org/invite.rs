//! The join link: `onepass://org/join?v=1&s=<url>&m=<mailbox>&o=<org>&a=<account>
//! &f=<fingerprint>&n=<nonce>&c=<credential seed>&t=<member token>[&d=<domain>]`.
//! Every key once (all required but `d`), lowercase hex, at most 2048 bytes.

use onepass_core::org::fingerprint_base32;
use onepass_core::synchome::mailbox_url_ok;
use url::Url;

use super::{FfiOrgInvite, parse_fingerprint};
use crate::convert::{bytes_hex, hex_bytes};
use crate::error::{OnePassError, invalid};

const LINK_MAX: usize = 2048;
/// The only plain-http server a link may name, for the local test stack.
pub(super) const LOOPBACK_URL: &str = "http://127.0.0.1:54321/functions/v1/mailbox";
const KEYS: [&str; 10] = ["v", "s", "m", "o", "a", "f", "n", "c", "t", "d"];

fn bad(what: &str) -> OnePassError {
    invalid(what)
}

/// Lowercase hex of exactly `bytes` bytes.
fn hex_exact(s: &str, bytes: usize, what: &str) -> Result<Vec<u8>, OnePassError> {
    if s.len() != bytes * 2 || s.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(bad(what));
    }
    hex_bytes(s).ok_or_else(|| bad(what))
}

fn server_ok(url: &str, allow_loopback: bool) -> bool {
    mailbox_url_ok(url) || (allow_loopback && url == LOOPBACK_URL)
}

/// Lowercase LDH hostname, at least one dot, at most 253 characters, labels
/// of 1 to 63 characters not starting or ending with a hyphen.
fn domain_ok(d: &str) -> bool {
    d.len() <= 253
        && d.contains('.')
        && d.split('.').all(|l| {
            (1..=63).contains(&l.len())
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

fn check(i: &FfiOrgInvite, allow_loopback: bool) -> Result<(), OnePassError> {
    if !server_ok(&i.server_url, allow_loopback) {
        return Err(bad("server url"));
    }
    hex_exact(&i.mailbox_id, 16, "mailbox id")?;
    hex_exact(&i.org_id, 16, "org id")?;
    hex_exact(&i.account_id, 16, "account id")?;
    if i.fingerprint.len() != 32 {
        return Err(bad("fingerprint"));
    }
    if i.nonce.len() != 32 {
        return Err(bad("nonce"));
    }
    if i.credential_seed.len() != 32 {
        return Err(bad("credential"));
    }
    if i.member_token.len() != 32 {
        return Err(bad("member token"));
    }
    if i.domain.as_deref().is_some_and(|d| !domain_ok(d)) {
        return Err(bad("domain"));
    }
    Ok(())
}

/// The link of an invite.
#[uniffi::export]
pub fn org_invite_encode(invite: FfiOrgInvite) -> Result<String, OnePassError> {
    check(&invite, true)?;
    let mut url = Url::parse("onepass://org/join").map_err(|_| bad("link"))?;
    {
        let mut q = url.query_pairs_mut();
        q.append_pair("v", "1")
            .append_pair("s", &invite.server_url)
            .append_pair("m", &invite.mailbox_id)
            .append_pair("o", &invite.org_id)
            .append_pair("a", &invite.account_id)
            .append_pair(
                "f",
                &fingerprint_base32(
                    invite
                        .fingerprint
                        .as_slice()
                        .try_into()
                        .map_err(|_| bad("fingerprint"))?,
                ),
            )
            .append_pair("n", &bytes_hex(&invite.nonce))
            .append_pair("c", &bytes_hex(&invite.credential_seed))
            .append_pair("t", &bytes_hex(&invite.member_token));
        if let Some(d) = &invite.domain {
            q.append_pair("d", d);
        }
    }
    let link: String = url.into();
    if link.len() > LINK_MAX {
        return Err(bad("link size"));
    }
    Ok(link)
}

/// Reads a join link. Any refusal is `InvalidInput`.
#[uniffi::export]
pub fn org_invite_parse(
    link: String,
    allow_loopback_http: bool,
) -> Result<FfiOrgInvite, OnePassError> {
    if link.len() > LINK_MAX {
        return Err(bad("link size"));
    }
    let url = Url::parse(&link).map_err(|_| bad("link"))?;
    if url.scheme() != "onepass"
        || url.host_str() != Some("org")
        || url.path() != "/join"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some()
        || url.fragment().is_some()
    {
        return Err(bad("link"));
    }
    let mut vals: [Option<String>; 10] = Default::default();
    for (k, v) in url.query_pairs() {
        let idx = KEYS
            .iter()
            .position(|key| *key == k)
            .ok_or_else(|| bad("link key"))?;
        if vals[idx].replace(v.into_owned()).is_some() {
            return Err(bad("link key repeated"));
        }
    }
    let get = |k: &str| -> Result<&String, OnePassError> {
        let idx = KEYS.iter().position(|key| *key == k).unwrap_or(0);
        vals[idx].as_ref().ok_or_else(|| bad("link key missing"))
    };
    if get("v")? != "1" {
        return Err(bad("link version"));
    }
    let invite = FfiOrgInvite {
        server_url: get("s")?.clone(),
        mailbox_id: get("m")?.clone(),
        org_id: get("o")?.clone(),
        account_id: get("a")?.clone(),
        fingerprint: parse_fingerprint(get("f")?)?.to_vec(),
        nonce: hex_exact(get("n")?, 32, "nonce")?,
        credential_seed: hex_exact(get("c")?, 32, "credential")?,
        member_token: hex_exact(get("t")?, 32, "member token")?,
        domain: vals[9].clone(),
    };
    check(&invite, allow_loopback_http)?;
    Ok(invite)
}
