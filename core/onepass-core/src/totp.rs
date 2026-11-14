//! TOTP (RFC 6238), `otpauth://` URIs, Google Authenticator migration
//! payloads and Steam Guard codes.
//!
//! Design choices:
//! - The `otpauth://` URI is parsed by hand (scheme, label, query, percent
//!   decoding). The `url` crate would pull in the IDNA and Unicode tables for
//!   a format that has no host, so the small parser is the smaller attack
//!   surface. No input makes it panic.
//! - Issuer: the `issuer` parameter wins when present, otherwise the label
//!   prefix (`Issuer:account`) is used. The account is always the part of the
//!   label after the first colon, or the whole label when there is no colon.
//! - Steam Guard is selected with the `encoder=steam` parameter (the
//!   convention of Aegis and Bitwarden). Its `digits` field is kept but
//!   ignored: a Steam code always has 5 characters.
//! - Migration: entries that are HOTP, MD5, or use an unknown digit count are
//!   skipped. The call fails with `InvalidFormat` when no entry is supported.

use crate::model::{Field, FieldType, FieldValue, Item, ItemType, Section};
use crate::{Error, Result};
use aws_lc_rs::hmac;
use data_encoding::{BASE32_NOPAD, BASE64_NOPAD};
use prost::Message;
use std::fmt;
use zeroize::Zeroizing;

const STEAM_ALPHABET: &[u8; 26] = b"23456789BCDFGHJKMNPQRTVWXY";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TotpAlgorithm {
    Sha1,
    Sha256,
    Sha512,
}

#[derive(Clone)]
pub struct TotpConfig {
    pub secret: Zeroizing<Vec<u8>>,
    pub algorithm: TotpAlgorithm,
    /// 6..=8. Ignored when `steam` is set.
    pub digits: u8,
    pub period: u32,
    pub issuer: Option<String>,
    pub account: Option<String>,
    pub steam: bool,
}

impl fmt::Debug for TotpConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TotpConfig")
            .field("secret", &"[redacted]")
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("period", &self.period)
            .field("issuer", &self.issuer)
            .field("account", &self.account)
            .field("steam", &self.steam)
            .finish()
    }
}

/// Id prefix of a field that keeps a replaced one-time password seed
/// (`previous_otp_<n>`, a concealed custom field shown as "Ancien code").
/// The label is in the language of the device that wrote it: only this
/// prefix tells the field apart, and it carries a seed like a `totp` field.
pub const PREVIOUS_OTP_FIELD_PREFIX: &str = "previous_otp_";

/// The field id is one of a replaced one-time password seed.
pub fn is_previous_otp_field(id: &str) -> bool {
    id.starts_with(PREVIOUS_OTP_FIELD_PREFIX)
}

/// Code for the time step containing `unix_seconds`.
pub fn code_at(cfg: &TotpConfig, unix_seconds: u64) -> Result<String> {
    if cfg.period == 0 {
        return Err(Error::InvalidFormat("otp period"));
    }
    if !cfg.steam && !(6..=8).contains(&cfg.digits) {
        return Err(Error::InvalidFormat("otp digits"));
    }
    let counter = unix_seconds / u64::from(cfg.period);
    let alg = match cfg.algorithm {
        TotpAlgorithm::Sha1 => hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
        TotpAlgorithm::Sha256 => hmac::HMAC_SHA256,
        TotpAlgorithm::Sha512 => hmac::HMAC_SHA512,
    };
    let tag = hmac::sign(&hmac::Key::new(alg, &cfg.secret), &counter.to_be_bytes());
    let mac = tag.as_ref();
    let off = usize::from(mac[mac.len() - 1] & 0x0f);
    let mut code = u32::from_be_bytes([mac[off] & 0x7f, mac[off + 1], mac[off + 2], mac[off + 3]]);
    if cfg.steam {
        let mut out = String::with_capacity(5);
        for _ in 0..5 {
            out.push(char::from(STEAM_ALPHABET[(code % 26) as usize]));
            code /= 26;
        }
        return Ok(out);
    }
    let modulus = 10u32.pow(u32::from(cfg.digits));
    Ok(format!(
        "{:0width$}",
        code % modulus,
        width = usize::from(cfg.digits)
    ))
}

/// Seconds until the current code changes (1..=period). 0 for a zero period.
/// Reserved: no caller in M1, kept for the app's countdown (milestone 2).
pub fn seconds_remaining(cfg: &TotpConfig, unix_seconds: u64) -> u32 {
    if cfg.period == 0 {
        return 0;
    }
    let p = u64::from(cfg.period);
    (p - unix_seconds % p) as u32
}

fn percent_decode(s: &str, plus_is_space: bool) -> Result<Zeroizing<String>> {
    const BAD: Error = Error::InvalidFormat("otpauth uri");
    let b = s.as_bytes();
    let mut out: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(b.len()));
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' => {
                let hex = b.get(i + 1..i + 3).ok_or(BAD)?;
                let hex = std::str::from_utf8(hex).map_err(|_| BAD)?;
                out.push(u8::from_str_radix(hex, 16).map_err(|_| BAD)?);
                i += 3;
            }
            b'+' if plus_is_space => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    // Validate in place, then copy: the buffer `out` is wiped on drop.
    let text = std::str::from_utf8(&out).map_err(|_| BAD)?;
    Ok(Zeroizing::new(text.to_owned()))
}

fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    let head = s.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix)
        .then(|| &s[prefix.len()..])
}

fn decode_base32_secret(raw: &str) -> Result<Zeroizing<Vec<u8>>> {
    const BAD: Error = Error::InvalidFormat("otp secret");
    // One pass into a single wiped buffer: no plain intermediate String.
    // Padding is only valid at the end, so any `=` is dropped when it is
    // followed solely by padding or spaces; an inner `=` fails the decode.
    let mut cleaned: Zeroizing<String> = Zeroizing::new(String::with_capacity(raw.len()));
    for c in raw.chars() {
        if !c.is_whitespace() && c != '-' {
            cleaned.push(c.to_ascii_uppercase());
        }
    }
    while cleaned.ends_with('=') {
        cleaned.pop();
    }
    if cleaned.is_empty() {
        return Err(BAD);
    }
    let bytes = BASE32_NOPAD.decode(cleaned.as_bytes()).map_err(|_| BAD)?;
    if bytes.is_empty() {
        return Err(BAD);
    }
    Ok(Zeroizing::new(bytes))
}

fn clean(s: &str) -> Option<String> {
    let t = s.trim();
    (!t.is_empty()).then(|| t.to_owned())
}

/// A bare base32 secret (spaces, dashes and lower case allowed, trailing
/// `=` padding dropped) with the defaults: SHA1, 6 digits, 30 s. Nothing
/// in it is read as a parameter: a bad character is
/// `InvalidFormat("otp secret")`.
pub fn totp_from_secret(secret: &str) -> Result<TotpConfig> {
    Ok(TotpConfig {
        secret: decode_base32_secret(secret)?,
        algorithm: TotpAlgorithm::Sha1,
        digits: 6,
        period: 30,
        issuer: None,
        account: None,
        steam: false,
    })
}

/// Parses `otpauth://totp/Label?secret=...`. Defaults: SHA1, 6 digits, 30 s.
pub fn parse_otpauth(uri: &str) -> Result<TotpConfig> {
    const BAD: Error = Error::InvalidFormat("otpauth uri");
    let rest = strip_prefix_ci(uri.trim(), "otpauth://").ok_or(BAD)?;
    let rest = rest.split('#').next().unwrap_or("");
    let (path, query) = rest.split_once('?').unwrap_or((rest, ""));
    let (kind, label) = path.split_once('/').unwrap_or((path, ""));
    if kind.eq_ignore_ascii_case("hotp") {
        return Err(Error::InvalidFormat("hotp unsupported"));
    }
    if !kind.eq_ignore_ascii_case("totp") {
        return Err(Error::InvalidFormat("otpauth type"));
    }
    let label = percent_decode(label, false)?;
    let (label_issuer, account) = match label.split_once(':') {
        Some((i, a)) => (clean(i), clean(a)),
        None => (None, clean(&label)),
    };

    let mut secret = None;
    let mut issuer_param = None;
    let mut algorithm = TotpAlgorithm::Sha1;
    let mut digits = 6u8;
    let mut period = 30u32;
    let mut steam = false;
    let mut seen: Vec<String> = Vec::new();
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let k = percent_decode(k, true)?.to_ascii_lowercase();
        if seen.contains(&k) {
            continue; // first occurrence wins
        }
        let v = percent_decode(v, true)?;
        match k.as_str() {
            "secret" => secret = Some(decode_base32_secret(&v)?),
            "issuer" => issuer_param = clean(&v),
            "algorithm" => {
                algorithm = match v.to_ascii_uppercase().as_str() {
                    "SHA1" => TotpAlgorithm::Sha1,
                    "SHA256" => TotpAlgorithm::Sha256,
                    "SHA512" => TotpAlgorithm::Sha512,
                    _ => return Err(Error::InvalidFormat("otp algorithm")),
                }
            }
            "digits" => {
                digits = v
                    .parse::<u8>()
                    .ok()
                    .filter(|d| (6..=8).contains(d))
                    .ok_or(Error::InvalidFormat("otp digits"))?;
            }
            "period" => {
                period = v
                    .parse::<u32>()
                    .ok()
                    .filter(|p| *p > 0)
                    .ok_or(Error::InvalidFormat("otp period"))?;
            }
            "encoder" => steam = v.eq_ignore_ascii_case("steam"),
            _ => {}
        }
        seen.push(k);
    }
    Ok(TotpConfig {
        secret: secret.ok_or(Error::InvalidFormat("otp secret"))?,
        algorithm,
        digits,
        period,
        issuer: issuer_param.or(label_issuer),
        account,
        steam,
    })
}

#[derive(Clone, PartialEq, Message)]
struct MigrationPayload {
    #[prost(message, repeated, tag = "1")]
    otp_parameters: Vec<OtpParameters>,
}

#[derive(Clone, PartialEq, Message)]
struct OtpParameters {
    #[prost(bytes = "vec", tag = "1")]
    secret: Vec<u8>,
    #[prost(string, tag = "2")]
    name: String,
    #[prost(string, tag = "3")]
    issuer: String,
    #[prost(int32, tag = "4")]
    algorithm: i32,
    #[prost(int32, tag = "5")]
    digits: i32,
    #[prost(int32, tag = "6")]
    otp_type: i32,
    #[prost(int64, tag = "7")]
    counter: i64,
}

/// Parses `otpauth-migration://offline?data=<base64>` (Google Authenticator
/// export). HOTP, MD5 and unknown-digit entries are skipped; fails with
/// `InvalidFormat` when nothing supported remains.
/// Reserved: no caller in M1, kept for the import flow (fuzzed and tested
/// already, since it reads untrusted input).
pub fn parse_migration(uri: &str) -> Result<Vec<TotpConfig>> {
    const BAD: Error = Error::InvalidFormat("migration uri");
    let rest = strip_prefix_ci(uri.trim(), "otpauth-migration://").ok_or(BAD)?;
    let query = rest.split_once('?').ok_or(BAD)?.1;
    let query = query.split('#').next().unwrap_or("");
    let mut data = None;
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=')
            && k == "data"
        {
            let mut d = percent_decode(v, true)?;
            // Form decoding turned a literal `+` into a space: restore it.
            if d.contains(' ') {
                let fixed = Zeroizing::new(d.replace(' ', "+"));
                d = fixed;
            }
            data = Some(d);
            break;
        }
    }
    let data = data.ok_or(BAD)?;
    let data = data.trim_end_matches('=');
    let raw = Zeroizing::new(BASE64_NOPAD.decode(data.as_bytes()).map_err(|_| BAD)?);
    let mut payload = MigrationPayload::decode(&raw[..]).map_err(|_| BAD)?;

    let mut out = Vec::new();
    for p in &mut payload.otp_parameters {
        // Taken first, so a skipped entry's secret is wiped when `secret`
        // drops on `continue`.
        let secret = Zeroizing::new(std::mem::take(&mut p.secret));
        let algorithm = match p.algorithm {
            0 | 1 => TotpAlgorithm::Sha1,
            2 => TotpAlgorithm::Sha256,
            3 => TotpAlgorithm::Sha512,
            _ => continue,
        };
        let digits = match p.digits {
            0 | 1 => 6,
            2 => 8,
            _ => continue,
        };
        if p.otp_type == 1 || secret.is_empty() {
            continue; // HOTP or empty secret
        }
        let (name_issuer, account) = match p.name.split_once(':') {
            Some((i, a)) => (clean(i), clean(a)),
            None => (None, clean(&p.name)),
        };
        out.push(TotpConfig {
            secret,
            algorithm,
            digits,
            period: 30,
            issuer: clean(&p.issuer).or(name_issuer),
            account,
            steam: false,
        });
    }
    if out.is_empty() {
        return Err(Error::InvalidFormat("migration has no totp entry"));
    }
    Ok(out)
}

/// What `attach_otp` did to the item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtpAttach {
    /// The item had no code: the new one is stored.
    Added,
    /// The item already holds this very code: nothing was written.
    Same,
    /// The item holds a different code and `replace` was false: untouched.
    Conflict,
    /// The old code moved to a `previous_otp_<n>` field, the new one is stored.
    Replaced,
}

/// An `otpauth://` URI or a bare base32 secret, parsed as `otp_code` does:
/// a bare secret is never read as a URI.
fn parse_otp_value(value: &str) -> Result<TotpConfig> {
    const OTPAUTH: &str = "otpauth://";
    let value = value.trim();
    if value
        .get(..OTPAUTH.len())
        .is_some_and(|h| h.eq_ignore_ascii_case(OTPAUTH))
    {
        parse_otpauth(value)
    } else {
        totp_from_secret(value)
    }
}

/// Same generator: secret, algorithm, digits, period (and Steam encoding).
fn same_generator(a: &TotpConfig, b: &TotpConfig) -> bool {
    *a.secret == *b.secret
        && a.algorithm == b.algorithm
        && a.digits == b.digits
        && a.period == b.period
        && a.steam == b.steam
}

/// Writes a one-time password seed on a Login and keeps the replaced one.
/// `value` is an `otpauth://totp/` URI or a bare base32 secret. The item must
/// be a Login with at most one non-empty OTP field, else `InvalidFormat`.
/// A different stored code is only replaced when `replace` is set: the old
/// value then moves to a concealed `previous_otp_<n>` field (smallest unused
/// `n`, in the `custom` section) labelled `previous_label`. Without
/// `replace`, a conflict leaves the item untouched.
pub fn attach_otp(
    item: &mut Item,
    value: &str,
    replace: bool,
    previous_label: &str,
) -> Result<OtpAttach> {
    if item.item_type != ItemType::Login {
        return Err(Error::InvalidFormat("not a login"));
    }
    let new_cfg = parse_otp_value(value)?;
    let mut filled = Vec::new();
    for (s, sec) in item.sections.iter().enumerate() {
        for (f, field) in sec.fields.iter().enumerate() {
            if matches!(&field.value, FieldValue::Otp(v) if !v.trim().is_empty()) {
                filled.push((s, f));
            }
        }
    }
    if filled.len() > 1 {
        return Err(Error::InvalidFormat("ambiguous one-time password"));
    }
    let new_value = Zeroizing::new(value.trim().to_owned());

    let Some(&(s, f)) = filled.first() else {
        set_otp(item, new_value);
        return Ok(OtpAttach::Added);
    };
    let FieldValue::Otp(old) = &item.sections[s].fields[f].value else {
        return Err(Error::InvalidFormat("one-time password"));
    };
    let old = old.clone();
    // An unreadable stored value counts as different, never as an error.
    if parse_otp_value(&old).is_ok_and(|c| same_generator(&c, &new_cfg)) {
        return Ok(OtpAttach::Same);
    }
    if !replace {
        return Ok(OtpAttach::Conflict);
    }
    let n = (1..)
        .find(|n| {
            let id = format!("{PREVIOUS_OTP_FIELD_PREFIX}{n}");
            item.field(&id).is_none()
        })
        .unwrap_or(1);
    let keep = Field {
        id: format!("{PREVIOUS_OTP_FIELD_PREFIX}{n}"),
        label: previous_label.to_owned(),
        kind: FieldType::Concealed,
        value: FieldValue::Concealed(Zeroizing::new(old.trim().to_owned())),
        required: false,
        repeatable: false,
        autofill: false,
    };
    match item.sections.iter_mut().find(|s| s.id == CUSTOM_SECTION_ID) {
        Some(sec) => sec.fields.push(keep),
        None => item.sections.push(Section {
            id: CUSTOM_SECTION_ID.to_owned(),
            label: CUSTOM_SECTION_LABEL.to_owned(),
            fields: vec![keep],
        }),
    }
    item.sections[s].fields[f].value = FieldValue::Otp(new_value);
    Ok(OtpAttach::Replaced)
}

/// Stores `value` in the Login's `totp` field, or in the first (empty) OTP field,
/// adding a `totp` field to the first section when there is none.
fn set_otp(item: &mut Item, value: Zeroizing<String>) {
    let target = item
        .sections
        .iter_mut()
        .flat_map(|s| s.fields.iter_mut())
        .find(|f| f.id == "totp" && f.kind == FieldType::Otp);
    let target = match target {
        Some(f) => Some(f),
        None => item
            .sections
            .iter_mut()
            .flat_map(|s| s.fields.iter_mut())
            .find(|f| f.kind == FieldType::Otp),
    };
    if let Some(f) = target {
        f.value = FieldValue::Otp(value);
        return;
    }
    let field = Field {
        id: "totp".to_owned(),
        label: "TOTP".to_owned(),
        kind: FieldType::Otp,
        value: FieldValue::Otp(value),
        required: false,
        repeatable: false,
        autofill: false,
    };
    match item.sections.first_mut() {
        Some(sec) => sec.fields.push(field),
        None => item.sections.push(Section {
            id: "main".to_owned(),
            label: "Connexion".to_owned(),
            fields: vec![field],
        }),
    }
}

const CUSTOM_SECTION_ID: &str = "custom";
const CUSTOM_SECTION_LABEL: &str = "Champs perso";

#[cfg(test)]
mod tests {
    #[test]
    fn previous_otp_field_is_told_by_its_id_only() {
        assert!(super::is_previous_otp_field("previous_otp_1"));
        assert!(!super::is_previous_otp_field("totp"));
        assert!(!super::is_previous_otp_field("custom_1"));
    }

    use super::*;

    fn cfg(alg: TotpAlgorithm, len: usize) -> TotpConfig {
        let secret: Vec<u8> = b"1234567890".iter().cycle().take(len).copied().collect();
        TotpConfig {
            secret: Zeroizing::new(secret),
            algorithm: alg,
            digits: 8,
            period: 30,
            issuer: None,
            account: None,
            steam: false,
        }
    }

    const TIMES: [u64; 6] = [
        59,
        1111111109,
        1111111111,
        1234567890,
        2000000000,
        20000000000,
    ];

    fn check(alg: TotpAlgorithm, len: usize, expected: [&str; 6]) {
        let c = cfg(alg, len);
        for (t, e) in TIMES.iter().zip(expected) {
            assert_eq!(code_at(&c, *t).unwrap(), e, "t={t}");
        }
    }

    #[test]
    fn rfc6238_sha1() {
        check(
            TotpAlgorithm::Sha1,
            20,
            [
                "94287082", "07081804", "14050471", "89005924", "69279037", "65353130",
            ],
        );
    }

    #[test]
    fn rfc6238_sha256() {
        check(
            TotpAlgorithm::Sha256,
            32,
            [
                "46119246", "68084774", "67062674", "91819424", "90698825", "77737706",
            ],
        );
    }

    #[test]
    fn rfc6238_sha512() {
        check(
            TotpAlgorithm::Sha512,
            64,
            [
                "90693936", "25091201", "99943326", "93441116", "38618901", "47863826",
            ],
        );
    }

    #[test]
    fn six_digit_code_is_zero_padded_tail() {
        let mut c = cfg(TotpAlgorithm::Sha1, 20);
        c.digits = 6;
        assert_eq!(code_at(&c, 59).unwrap(), "287082");
        assert_eq!(code_at(&c, 1111111109).unwrap(), "081804");
    }

    #[test]
    fn code_at_rejects_bad_config() {
        let mut c = cfg(TotpAlgorithm::Sha1, 20);
        c.period = 0;
        assert!(matches!(code_at(&c, 1), Err(Error::InvalidFormat(_))));
        assert_eq!(seconds_remaining(&c, 1), 0);
        c.period = 30;
        c.digits = 9;
        assert!(matches!(code_at(&c, 1), Err(Error::InvalidFormat(_))));
    }

    #[test]
    fn seconds_remaining_counts_down() {
        let c = cfg(TotpAlgorithm::Sha1, 20);
        assert_eq!(seconds_remaining(&c, 0), 30);
        assert_eq!(seconds_remaining(&c, 29), 1);
        assert_eq!(seconds_remaining(&c, 59), 1);
        assert_eq!(seconds_remaining(&c, 60), 30);
    }

    #[test]
    fn steam_code_uses_the_steam_alphabet() {
        let mut c = cfg(TotpAlgorithm::Sha1, 20);
        c.steam = true;
        c.digits = 6;
        let code = code_at(&c, 59).unwrap();
        assert_eq!(code.len(), 5);
        assert!(code.bytes().all(|b| STEAM_ALPHABET.contains(&b)));
        // Independent derivation: the RFC 6238 SHA1 vector at t=59 has the
        // 31-bit truncated value 1094287082 (its 8 digit code is the value
        // mod 10^8). Steam takes the same value in base 26, low digit first.
        let mut v = 1094287082u32;
        let mut expected = String::new();
        for _ in 0..5 {
            expected.push(char::from(STEAM_ALPHABET[(v % 26) as usize]));
            v /= 26;
        }
        assert_eq!(code, expected);
        assert_ne!(code_at(&c, 59).unwrap(), code_at(&c, 89).unwrap());
    }

    #[test]
    fn otpauth_defaults_and_label() {
        let c =
            parse_otpauth("otpauth://totp/GitHub:quentin?secret=JBSWY3DPEHPK3PXP&issuer=GitHub")
                .unwrap();
        assert_eq!(
            (
                c.digits,
                c.period,
                c.issuer.as_deref(),
                c.account.as_deref()
            ),
            (6, 30, Some("GitHub"), Some("quentin"))
        );
        assert_eq!(c.algorithm, TotpAlgorithm::Sha1);
        assert_eq!(&c.secret[..], b"Hello!\xDE\xAD\xBE\xEF");
    }

    #[test]
    fn otpauth_percent_decoding_and_issuer_precedence() {
        let c = parse_otpauth(
            "otpauth://totp/Old%20Co%3Aa%40b.c?secret=jbsw%20y3dp-ehpk3pxp%3D%3D&issuer=New+Co&algorithm=sha256&digits=8&period=60",
        )
        .unwrap();
        assert_eq!(c.issuer.as_deref(), Some("New Co"));
        assert_eq!(c.account.as_deref(), Some("a@b.c"));
        assert_eq!(c.algorithm, TotpAlgorithm::Sha256);
        assert_eq!((c.digits, c.period), (8, 60));
        assert_eq!(c.secret.len(), 10);
        // No issuer param: label prefix is used; no colon: account only.
        let c = parse_otpauth("otpauth://totp/Acme:bob?secret=JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(c.issuer.as_deref(), Some("Acme"));
        let c = parse_otpauth("otpauth://totp/bob?secret=JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!((c.issuer, c.account.as_deref()), (None, Some("bob")));
    }

    #[test]
    fn otpauth_steam_encoder() {
        let c =
            parse_otpauth("otpauth://totp/Steam:me?secret=JBSWY3DPEHPK3PXP&encoder=steam").unwrap();
        assert!(c.steam);
    }

    #[test]
    fn otpauth_rejects_hotp_and_bad_input() {
        let bad = |u: &str| matches!(parse_otpauth(u), Err(Error::InvalidFormat(_)));
        assert_eq!(
            parse_otpauth("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=1").unwrap_err(),
            Error::InvalidFormat("hotp unsupported")
        );
        assert!(bad("otpauth://totp/x?secret=!!"));
        assert!(bad("otpauth://totp/x?secret="));
        assert!(bad("otpauth://totp/x?secret=%20"));
        assert!(bad("otpauth://totp/x"));
        assert!(bad("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=5"));
        assert!(bad("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=9"));
        assert!(bad("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=abc"));
        assert!(bad("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=0"));
        assert!(bad(
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=MD5"
        ));
        assert!(bad("otpauth://foo/x?secret=JBSWY3DPEHPK3PXP"));
        assert!(bad("https://example.com"));
        assert!(bad("otpauth://totp/%zz?secret=JBSWY3DPEHPK3PXP"));
        assert!(bad("otpauth://totp/%ff?secret=JBSWY3DPEHPK3PXP"));
        assert!(bad("otpauth://totp/%"));
        assert!(bad(""));
    }

    #[test]
    fn otpauth_never_panics_on_odd_bytes() {
        for u in [
            "otpauth:/",
            "otpauth://",
            "otpauth://totp",
            "é",
            "otpauth://tot\u{e9}/x",
            "OTPAUTH://TOTP/x?SECRET=JBSWY3DPEHPK3PXP",
        ] {
            let _ = parse_otpauth(u);
        }
        assert!(parse_otpauth("OTPAUTH://TOTP/x?SECRET=JBSWY3DPEHPK3PXP").is_ok());
    }

    #[test]
    fn debug_redacts_the_secret() {
        let c = parse_otpauth("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP").unwrap();
        let d = format!("{c:?}");
        assert!(d.contains("[redacted]"));
        assert!(!d.contains("72, 101"));
    }

    use data_encoding::BASE64;

    fn migration_uri(entries: Vec<OtpParameters>) -> String {
        let bytes = MigrationPayload {
            otp_parameters: entries,
        }
        .encode_to_vec();
        let b64 = BASE64.encode(&bytes);
        let enc: String = b64
            .chars()
            .map(|c| match c {
                '+' => "%2B".to_owned(),
                '/' => "%2F".to_owned(),
                '=' => "%3D".to_owned(),
                c => c.to_string(),
            })
            .collect();
        format!("otpauth-migration://offline?data={enc}")
    }

    fn entry(
        secret: &[u8],
        name: &str,
        issuer: &str,
        alg: i32,
        digits: i32,
        ty: i32,
    ) -> OtpParameters {
        OtpParameters {
            secret: secret.to_vec(),
            name: name.into(),
            issuer: issuer.into(),
            algorithm: alg,
            digits,
            otp_type: ty,
            counter: 0,
        }
    }

    #[test]
    fn migration_payload_decodes() {
        let uri = migration_uri(vec![
            entry(b"12345678901234567890", "GitHub:quentin", "GitHub", 1, 1, 2),
            entry(b"abcdefghij", "bob@example.com", "Acme", 3, 2, 2),
        ]);
        let v = parse_migration(&uri).unwrap();
        assert_eq!(v.len(), 2);
        assert_eq!(&v[0].secret[..], b"12345678901234567890");
        assert_eq!(v[0].issuer.as_deref(), Some("GitHub"));
        assert_eq!(v[0].account.as_deref(), Some("quentin"));
        assert_eq!(
            (v[0].algorithm, v[0].digits, v[0].period),
            (TotpAlgorithm::Sha1, 6, 30)
        );
        assert_eq!(v[1].account.as_deref(), Some("bob@example.com"));
        assert_eq!((v[1].algorithm, v[1].digits), (TotpAlgorithm::Sha512, 8));
    }

    #[test]
    fn migration_skips_unsupported_and_fails_when_none_left() {
        let uri = migration_uri(vec![
            entry(b"hotpsecret", "h", "", 1, 1, 1),
            entry(b"md5secret!", "m", "", 4, 1, 2),
            entry(b"goodsecret", "g", "", 0, 0, 0),
        ]);
        let v = parse_migration(&uri).unwrap();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].account.as_deref(), Some("g"));

        let none = migration_uri(vec![entry(b"hotpsecret", "h", "", 1, 1, 1)]);
        assert!(matches!(
            parse_migration(&none),
            Err(Error::InvalidFormat(_))
        ));
    }

    #[test]
    fn migration_rejects_garbage() {
        for u in [
            "",
            "otpauth-migration://offline",
            "otpauth-migration://offline?data=",
            "otpauth-migration://offline?data=!!!",
            "otpauth-migration://offline?data=/////w",
            "https://x",
        ] {
            assert!(
                matches!(parse_migration(u), Err(Error::InvalidFormat(_))),
                "{u}"
            );
        }
    }

    // attach_otp

    use crate::id::Id;
    use crate::model::new_item;

    const SEED: &str = "JBSWY3DPEHPK3PXP";
    const OTHER: &str = "GEZDGNBVGY3TQOJQ";

    fn login() -> Item {
        new_item(ItemType::Login, Id::new(), "Mail")
    }

    fn totp_of(item: &Item) -> String {
        match &item.field("totp").unwrap().value {
            FieldValue::Otp(v) => v.to_string(),
            _ => panic!("totp is not an otp field"),
        }
    }

    #[test]
    fn attach_adds_to_login_without_code() {
        let mut item = login();
        let r = attach_otp(&mut item, SEED, false, "Old code").unwrap();
        assert_eq!(r, OtpAttach::Added);
        assert_eq!(totp_of(&item), SEED);
    }

    #[test]
    fn attach_same_secret_is_same_and_writes_nothing() {
        let mut item = login();
        attach_otp(&mut item, SEED, false, "Old code").unwrap();
        let before = item.clone();
        let uri = format!("otpauth://totp/Mail:me?secret={SEED}&issuer=Mail");
        assert_eq!(
            attach_otp(&mut item, &uri, true, "Old code").unwrap(),
            OtpAttach::Same
        );
        assert_eq!(item, before);
    }

    #[test]
    fn attach_conflict_leaves_item_untouched() {
        let mut item = login();
        attach_otp(&mut item, SEED, false, "Old code").unwrap();
        let before = item.clone();
        assert_eq!(
            attach_otp(&mut item, OTHER, false, "Old code").unwrap(),
            OtpAttach::Conflict
        );
        assert_eq!(item, before);
    }

    #[test]
    fn attach_replace_keeps_old_seed() {
        let mut item = login();
        attach_otp(&mut item, SEED, false, "Old code").unwrap();
        assert_eq!(
            attach_otp(&mut item, OTHER, true, "Old code").unwrap(),
            OtpAttach::Replaced
        );
        assert_eq!(totp_of(&item), OTHER);
        let kept = item.field("previous_otp_1").unwrap();
        assert_eq!(kept.label, "Old code");
        assert_eq!(kept.kind, FieldType::Concealed);
        assert!(matches!(&kept.value, FieldValue::Concealed(v) if v.as_str() == SEED));
    }

    #[test]
    fn attach_second_replace_uses_next_index() {
        let mut item = login();
        attach_otp(&mut item, SEED, false, "Old code").unwrap();
        attach_otp(&mut item, OTHER, true, "Old code").unwrap();
        attach_otp(&mut item, "MFRGGZDFMZTWQ2LK", true, "Old code").unwrap();
        assert!(matches!(
            &item.field("previous_otp_2").unwrap().value,
            FieldValue::Concealed(v) if v.as_str() == OTHER
        ));
        assert!(item.field("previous_otp_1").is_some());
    }

    #[test]
    fn attach_refuses_non_login_hotp_and_garbage() {
        let mut note = new_item(ItemType::SecureNote, Id::new(), "Note");
        assert!(attach_otp(&mut note, SEED, false, "Old code").is_err());
        let mut item = login();
        let before = item.clone();
        let hotp = format!("otpauth://hotp/Mail?secret={SEED}&counter=1");
        assert!(attach_otp(&mut item, &hotp, false, "Old code").is_err());
        assert!(attach_otp(&mut item, "not base32!", false, "Old code").is_err());
        assert_eq!(item, before);
    }

    #[test]
    fn attach_refuses_ambiguous_item() {
        let mut item = login();
        item.field_mut("totp").unwrap().value = FieldValue::Otp(Zeroizing::new(SEED.into()));
        item.sections[0].fields.push(Field {
            id: "totp_2".into(),
            label: "TOTP 2".into(),
            kind: FieldType::Otp,
            value: FieldValue::Otp(Zeroizing::new(OTHER.into())),
            required: false,
            repeatable: false,
            autofill: false,
        });
        assert!(attach_otp(&mut item, OTHER, true, "Old code").is_err());
    }

    #[test]
    fn attach_replace_writes_the_filled_field_not_a_second_one() {
        let mut item = login();
        item.field_mut("totp").unwrap().id = "mfa".into();
        item.field_mut("mfa").unwrap().value = FieldValue::Otp(Zeroizing::new(SEED.into()));
        attach_otp(&mut item, OTHER, true, "Old code").unwrap();
        let filled = item
            .sections
            .iter()
            .flat_map(|s| &s.fields)
            .filter(|f| matches!(&f.value, FieldValue::Otp(v) if !v.is_empty()))
            .count();
        assert_eq!(filled, 1);
        assert!(item.field("previous_otp_1").is_some());
    }
}
