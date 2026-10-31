//! Signed requests (spec 4.7): one fixed form of RFC 9421 HTTP Message
//! Signatures with an RFC 9530 `Content-Digest`.
//!
//! The same code builds the signature base for the Rust client and, through
//! the WebAssembly build, for the edge function: one canonicalization for
//! both sides. Ed25519 itself is the caller's (aws-lc-rs on the client,
//! WebCrypto in the edge function).

use data_encoding::{BASE64, BASE64URL_NOPAD, HEXLOWER};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256 as Sha256Hasher};

use crate::messages::{CredentialId, ProtoError};

pub const SIG_TAG: &str = "onepass-mailbox/v1";
/// Largest accepted `|now - created|`, in seconds.
pub const SKEW_SECS: i64 = 300;
/// How long the server keeps a nonce (twice the skew window).
pub const NONCE_TTL_SECS: i64 = 600;
pub const CREDENTIAL_ID_PREFIX: &[u8] = b"onepass/mailbox-credential-id/v1";
/// Longest `@onepass-target`. Not fixed by the spec: a bound on a field the
/// server copies into the signature base.
pub const TARGET_MAX: usize = 2048;

/// The mailbox credential key type. It is a per-device Ed25519 key, separate
/// from the rotation v2 device keys (spec 4.7, "Écart avec la décision 1").
/// Every use goes through these two aliases and `CREDENTIAL_ALG`, so a later
/// switch of key type stays local to this file.
pub type CredentialPublicKey = [u8; 32];
pub type CredentialSignature = [u8; 64];
pub const CREDENTIAL_ALG: &str = "ed25519";

const LABEL: &str = "sig1";
const COMPONENTS: &str = r#"("@method" "@onepass-target" "content-digest")"#;
const DIGEST_PREFIX: &str = "sha-256=:";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureParams {
    pub created: i64,
    #[serde(with = "crate::bytes::fixed")]
    pub nonce: [u8; 16],
    #[serde(with = "crate::bytes::fixed")]
    pub keyid: CredentialId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParsedSignature {
    pub params: SignatureParams,
    #[serde(with = "crate::bytes::fixed")]
    pub sig: CredentialSignature,
}

/// `sha-256=:<base64 of SHA-256(body)>:`, empty body included.
pub fn content_digest(body: &[u8]) -> String {
    let d: [u8; 32] = Sha256Hasher::digest(body).into();
    format!("{DIGEST_PREFIX}{}:", BASE64.encode(&d))
}

/// Mailbox credential id: the first 16 bytes of
/// `SHA-256(CREDENTIAL_ID_PREFIX || public_key)`.
pub fn credential_id(public_key: &CredentialPublicKey) -> CredentialId {
    let mut h = Sha256Hasher::new();
    h.update(CREDENTIAL_ID_PREFIX);
    h.update(public_key);
    let d: [u8; 32] = h.finalize().into();
    let mut id = [0u8; 16];
    id.copy_from_slice(&d[..16]);
    id
}

/// The `@signature-params` value, also the `Signature-Input` value after `sig1=`.
fn params_value(p: &SignatureParams) -> String {
    format!(
        r#"{COMPONENTS};created={};nonce="{}";keyid="{}";alg="{CREDENTIAL_ALG}";tag="{SIG_TAG}""#,
        p.created,
        BASE64URL_NOPAD.encode(&p.nonce),
        HEXLOWER.encode(&p.keyid),
    )
}

pub fn signature_input_header(p: &SignatureParams) -> String {
    format!("{LABEL}={}", params_value(p))
}

pub fn signature_header(sig: &CredentialSignature) -> String {
    format!("{LABEL}=:{}:", BASE64.encode(sig))
}

fn check_method(method: &str) -> Result<(), ProtoError> {
    match method {
        "GET" | "POST" | "PUT" | "DELETE" => Ok(()),
        _ => Err(ProtoError::Signature("method")),
    }
}

fn check_target(target: &str) -> Result<(), ProtoError> {
    if target.len() > TARGET_MAX {
        return Err(ProtoError::Signature("target length"));
    }
    if !target.starts_with("/v1/") {
        return Err(ProtoError::Signature("target prefix"));
    }
    if !target.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(ProtoError::Signature("target character"));
    }
    Ok(())
}

fn check_digest(digest: &str) -> Result<(), ProtoError> {
    let b64 = digest
        .strip_prefix(DIGEST_PREFIX)
        .and_then(|r| r.strip_suffix(':'))
        .ok_or(ProtoError::Signature("content-digest"))?;
    let d = BASE64
        .decode(b64.as_bytes())
        .map_err(|_| ProtoError::Signature("content-digest"))?;
    if d.len() != 32 || BASE64.encode(&d) != b64 {
        return Err(ProtoError::Signature("content-digest"));
    }
    Ok(())
}

/// The signed bytes (RFC 9421 section 2.5): four lines joined by `\n`, no
/// final newline.
pub fn signature_base(
    method: &str,
    target: &str,
    content_digest: &str,
    p: &SignatureParams,
) -> Result<Vec<u8>, ProtoError> {
    check_method(method)?;
    check_target(target)?;
    check_digest(content_digest)?;
    if p.created < 0 {
        return Err(ProtoError::Signature("created"));
    }
    Ok(format!(
        "\"@method\": {method}\n\"@onepass-target\": {target}\n\"content-digest\": {content_digest}\n\"@signature-params\": {}",
        params_value(p)
    )
    .into_bytes())
}

fn quoted(v: &str) -> Result<&str, ProtoError> {
    v.strip_prefix('"')
        .and_then(|r| r.strip_suffix('"'))
        .ok_or(ProtoError::Signature("parameter quoting"))
}

fn set<T>(slot: &mut Option<T>, v: T) -> Result<(), ProtoError> {
    if slot.replace(v).is_some() {
        return Err(ProtoError::Signature("duplicate parameter"));
    }
    Ok(())
}

/// Strict parse of `Signature-Input` and `Signature`. The values read are
/// turned back into headers, and both must equal the input byte for byte:
/// any other spelling, order or extra item is refused.
pub fn parse_signature_headers(
    signature_input: &str,
    signature: &str,
) -> Result<ParsedSignature, ProtoError> {
    let rest = signature_input
        .strip_prefix(LABEL)
        .and_then(|r| r.strip_prefix('='))
        .ok_or(ProtoError::Signature("label"))?;
    let rest = rest
        .strip_prefix(COMPONENTS)
        .ok_or(ProtoError::Signature("components"))?;
    let rest = rest
        .strip_prefix(';')
        .ok_or(ProtoError::Signature("missing parameter"))?;

    let (mut created, mut nonce, mut keyid, mut alg, mut tag) = (None, None, None, None, None);
    for item in rest.split(';') {
        let (name, value) = item
            .split_once('=')
            .ok_or(ProtoError::Signature("parameter"))?;
        match name {
            "created" => {
                if value.is_empty()
                    || value.len() > 19
                    || !value.bytes().all(|b| b.is_ascii_digit())
                {
                    return Err(ProtoError::Signature("created"));
                }
                let v = value
                    .parse::<i64>()
                    .map_err(|_| ProtoError::Signature("created"))?;
                set(&mut created, v)?;
            }
            "nonce" => {
                let raw = BASE64URL_NOPAD
                    .decode(quoted(value)?.as_bytes())
                    .map_err(|_| ProtoError::Signature("nonce"))?;
                let n: [u8; 16] = raw.try_into().map_err(|_| ProtoError::Signature("nonce"))?;
                set(&mut nonce, n)?;
            }
            "keyid" => {
                let raw = HEXLOWER
                    .decode(quoted(value)?.as_bytes())
                    .map_err(|_| ProtoError::Signature("keyid"))?;
                let k: CredentialId = raw.try_into().map_err(|_| ProtoError::Signature("keyid"))?;
                set(&mut keyid, k)?;
            }
            "alg" => {
                if quoted(value)? != CREDENTIAL_ALG {
                    return Err(ProtoError::Signature("alg"));
                }
                set(&mut alg, ())?;
            }
            "tag" => {
                if quoted(value)? != SIG_TAG {
                    return Err(ProtoError::Signature("tag"));
                }
                set(&mut tag, ())?;
            }
            _ => return Err(ProtoError::Signature("unknown parameter")),
        }
    }
    let missing = ProtoError::Signature("missing parameter");
    alg.ok_or(missing.clone())?;
    tag.ok_or(missing.clone())?;
    let params = SignatureParams {
        created: created.ok_or(missing.clone())?,
        nonce: nonce.ok_or(missing.clone())?,
        keyid: keyid.ok_or(missing)?,
    };
    if signature_input_header(&params) != signature_input {
        return Err(ProtoError::Signature("not canonical"));
    }

    let b64 = signature
        .strip_prefix(LABEL)
        .and_then(|r| r.strip_prefix("=:"))
        .and_then(|r| r.strip_suffix(':'))
        .ok_or(ProtoError::Signature("signature label"))?;
    let raw = BASE64
        .decode(b64.as_bytes())
        .map_err(|_| ProtoError::Signature("signature encoding"))?;
    let sig: CredentialSignature = raw
        .try_into()
        .map_err(|_| ProtoError::Signature("signature length"))?;
    if signature_header(&sig) != signature {
        return Err(ProtoError::Signature("signature not canonical"));
    }
    Ok(ParsedSignature { params, sig })
}

/// `|now - created| <= SKEW_SECS`, computed without overflow.
pub fn check_skew(created: i64, now: i64) -> Result<(), ProtoError> {
    if (i128::from(now) - i128::from(created)).abs() <= i128::from(SKEW_SECS) {
        Ok(())
    } else {
        Err(ProtoError::Skew)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_793_404_800;

    fn params() -> SignatureParams {
        SignatureParams {
            created: NOW,
            nonce: [7; 16],
            keyid: [0xab; 16],
        }
    }

    fn base() -> String {
        let b = signature_base(
            "POST",
            "/v1/mailboxes/00/commit?after=12",
            &content_digest(b"body"),
            &params(),
        )
        .unwrap();
        String::from_utf8(b).unwrap()
    }

    #[test]
    fn base_has_no_trailing_newline() {
        let b = base();
        assert!(!b.ends_with('\n'));
        assert_eq!(b.matches('\n').count(), 3);
    }

    #[test]
    fn components_in_fixed_order() {
        let b = base();
        let names: Vec<&str> = b.lines().map(|l| l.split_once(": ").unwrap().0).collect();
        assert_eq!(
            names,
            [
                "\"@method\"",
                "\"@onepass-target\"",
                "\"content-digest\"",
                "\"@signature-params\""
            ]
        );
        assert!(b.ends_with(&signature_input_header(&params())["sig1=".len()..]));
    }

    #[test]
    fn base_refuses_bad_inputs() {
        let d = content_digest(b"");
        let p = params();
        for m in ["get", "PATCH", "HEAD", ""] {
            assert!(signature_base(m, "/v1/x", &d, &p).is_err(), "{m}");
        }
        for t in ["/v2/x", "v1/x", "/v1/a b", "/v1/\u{e9}", "/v1/a\nb"] {
            assert!(signature_base("GET", t, &d, &p).is_err(), "{t}");
        }
        let long = format!("/v1/{}", "a".repeat(TARGET_MAX));
        assert!(signature_base("GET", &long, &d, &p).is_err());
        for bad in ["sha-256=:AAAA:", "sha-512=:x:", "", &d[..d.len() - 1]] {
            assert!(signature_base("GET", "/v1/x", bad, &p).is_err(), "{bad}");
        }
        let neg = SignatureParams { created: -1, ..p };
        assert!(signature_base("GET", "/v1/x", &d, &neg).is_err());
    }

    #[test]
    fn parse_round_trip() {
        let p = params();
        let sig = [9u8; 64];
        let parsed =
            parse_signature_headers(&signature_input_header(&p), &signature_header(&sig)).unwrap();
        assert_eq!(parsed, ParsedSignature { params: p, sig });
    }

    #[test]
    fn skew() {
        let now = NOW;
        assert_eq!(check_skew(now - 300, now), Ok(()));
        assert_eq!(check_skew(now + 300, now), Ok(()));
        assert_eq!(check_skew(now, now), Ok(()));
        assert_eq!(check_skew(now - 301, now), Err(ProtoError::Skew));
        assert_eq!(check_skew(now + 301, now), Err(ProtoError::Skew));
        assert_eq!(check_skew(i64::MIN, now), Err(ProtoError::Skew));
        assert_eq!(check_skew(i64::MAX, i64::MIN), Err(ProtoError::Skew));
        assert_eq!(check_skew(i64::MIN, i64::MIN), Ok(()));
    }

    #[test]
    fn credential_id_is_domain_separated() {
        let pk = [42u8; 32];
        let mut h = Sha256Hasher::new();
        h.update(CREDENTIAL_ID_PREFIX);
        h.update(pk);
        let full: [u8; 32] = h.finalize().into();
        assert_eq!(credential_id(&pk)[..], full[..16]);
        let bare: [u8; 32] = Sha256Hasher::digest(pk).into();
        assert_ne!(credential_id(&pk)[..], bare[..16]);
    }

    /// One test per refused shape of the headers.
    mod parse_refuses {
        use super::*;

        fn input() -> String {
            signature_input_header(&params())
        }

        fn sig() -> String {
            signature_header(&[9u8; 64])
        }

        fn refused(input: &str, sig: &str) {
            assert!(
                matches!(
                    parse_signature_headers(input, sig),
                    Err(ProtoError::Signature(_))
                ),
                "accepted: {input} / {sig}"
            );
        }

        fn replaced(from: &str, to: &str) -> String {
            let i = input();
            assert!(i.contains(from), "{from}");
            i.replacen(from, to, 1)
        }

        #[test]
        fn two_labels() {
            let i = input();
            let two = format!("{i}, sig2={}", &i["sig1=".len()..]);
            refused(&two, &sig());
            let s = sig();
            refused(&i, &format!("{s}, sig2={}", &s["sig1=".len()..]));
        }

        #[test]
        fn other_label() {
            refused(&input().replacen("sig1=", "sig2=", 1), &sig());
            refused(&input(), &sig().replacen("sig1=", "sig2=", 1));
        }

        #[test]
        fn missing_component() {
            refused(&replaced(r#" "content-digest""#, ""), &sig());
        }

        #[test]
        fn extra_component() {
            refused(
                &replaced(r#""content-digest")"#, r#""content-digest" "@authority")"#),
                &sig(),
            );
        }

        #[test]
        fn reordered_components() {
            refused(
                &replaced(
                    r#""@method" "@onepass-target""#,
                    r#""@onepass-target" "@method""#,
                ),
                &sig(),
            );
        }

        #[test]
        fn reordered_parameters() {
            refused(
                &replaced(
                    r#";alg="ed25519";tag="onepass-mailbox/v1""#,
                    r#";tag="onepass-mailbox/v1";alg="ed25519""#,
                ),
                &sig(),
            );
        }

        #[test]
        fn missing_parameter() {
            refused(&replaced(r#";alg="ed25519""#, ""), &sig());
            refused(&replaced(";created=1793404800", ""), &sig());
        }

        #[test]
        fn duplicate_parameter() {
            refused(
                &replaced(r#";alg="ed25519""#, r#";alg="ed25519";alg="ed25519""#),
                &sig(),
            );
            refused(
                &replaced(
                    ";created=1793404800",
                    ";created=1793404800;created=1793404800",
                ),
                &sig(),
            );
        }

        #[test]
        fn unknown_parameter() {
            refused(&format!("{};expires=1793405000", input()), &sig());
        }

        #[test]
        fn other_alg() {
            refused(
                &replaced(r#"alg="ed25519""#, r#"alg="ecdsa-p256-sha256""#),
                &sig(),
            );
        }

        #[test]
        fn other_tag() {
            refused(
                &replaced(r#"tag="onepass-mailbox/v1""#, r#"tag="onepass-mailbox/v2""#),
                &sig(),
            );
        }

        #[test]
        fn nonce_of_15_or_17_bytes() {
            let enc = BASE64URL_NOPAD.encode(&[7u8; 16]);
            refused(&replaced(&enc, &BASE64URL_NOPAD.encode(&[7u8; 15])), &sig());
            refused(&replaced(&enc, &BASE64URL_NOPAD.encode(&[7u8; 17])), &sig());
            // Padded or standard alphabet spellings of the same nonce.
            refused(&replaced(&enc, &format!("{enc}==")), &sig());
            let p = SignatureParams {
                nonce: [0xfb; 16],
                ..params()
            };
            let i = signature_input_header(&p);
            let url = BASE64URL_NOPAD.encode(&[0xfb; 16]);
            refused(
                &i.replacen(&url, &url.replace('-', "+").replace('_', "/"), 1),
                &sig(),
            );
        }

        #[test]
        fn keyid_not_hex_or_31_chars() {
            let hex = "ab".repeat(16);
            refused(&replaced(&hex, &format!("zz{}", &hex[2..])), &sig());
            refused(&replaced(&hex, &hex[1..]), &sig());
            refused(&replaced(&hex, &hex.to_uppercase()), &sig());
        }

        #[test]
        fn created_not_canonical() {
            refused(
                &replaced("created=1793404800", "created=01793404800"),
                &sig(),
            );
            refused(&replaced("created=1793404800", "created=-1"), &sig());
            refused(
                &replaced("created=1793404800", "created=+1793404800"),
                &sig(),
            );
            refused(
                &replaced("created=1793404800", r#"created="1793404800""#),
                &sig(),
            );
        }

        #[test]
        fn signature_of_63_bytes() {
            refused(&input(), &format!("sig1=:{}:", BASE64.encode(&[9u8; 63])));
            refused(&input(), &format!("sig1=:{}:", BASE64.encode(&[9u8; 65])));
        }

        #[test]
        fn non_canonical_base64() {
            let s = sig();
            // Last character carries unused bits: flip one of them.
            let b64 = &s["sig1=:".len()..s.len() - 1];
            let last = b64.as_bytes()[b64.len() - 3];
            let alt = (last + 1) as char;
            let mut bad = b64.to_string();
            bad.replace_range(b64.len() - 3..b64.len() - 2, &alt.to_string());
            refused(&input(), &format!("sig1=:{bad}:"));
            // Missing padding, URL alphabet, whitespace.
            refused(&input(), &format!("sig1=:{}:", b64.trim_end_matches('=')));
            let url = BASE64.encode(&[0xfb; 64]);
            refused(
                &input(),
                &format!("sig1=:{}:", url.replace('+', "-").replace('/', "_")),
            );
            refused(&input(), &format!(" {s}"));
            refused(&format!("{} ", input()), &s);
        }
    }
}
