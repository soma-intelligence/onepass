//! Relying party checks of the passkey operations: the `rp_id` a page asks
//! for against the origin the browser gave, and the `clientDataJSON` the
//! host builds itself (the page never writes it).
//!
//! An `rp_id` is valid for an origin when it is the origin's host, or a
//! registrable domain suffix of it, and is never a public suffix (Public
//! Suffix List, private section included, through the `psl` crate).

use aws_lc_rs::digest::{SHA256, digest};
use data_encoding::BASE64URL_NOPAD;
use url::Host;

use crate::AppErrorCode;
use crate::origin::Origin;

/// Longest DNS name.
const MAX_RP_ID: usize = 253;
/// Longest challenge accepted, in bytes.
pub const MAX_CHALLENGE: usize = 1024;
/// Longest user handle (WebAuthn: 1 to 64 bytes).
pub const MAX_USER_HANDLE: usize = 64;
/// Longest credential id accepted from the extension.
pub const MAX_CREDENTIAL_ID: usize = 1023;
/// Most credential ids `passkey_create` takes in `exclude`.
pub const MAX_EXCLUDE: usize = 64;
/// COSE algorithm of every OnePass passkey: ES256.
pub const ES256: i64 = -7;
/// DER header of a P-256 `SubjectPublicKeyInfo`, before the 65 bytes of
/// the uncompressed point.
const P256_SPKI_HEADER: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

type OpResult<T> = std::result::Result<T, AppErrorCode>;

/// The WebAuthn ceremony a `clientDataJSON` is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ceremony {
    Get,
    Create,
}

impl Ceremony {
    fn as_str(self) -> &'static str {
        match self {
            Self::Get => "webauthn.get",
            Self::Create => "webauthn.create",
        }
    }
}

/// The `rp_id` of a request, in lower-case ASCII, once checked against
/// the page origin. `invalid` when it is not a domain name;
/// `origin_mismatch` when the origin is an address, when the `rp_id` is a
/// public suffix, or when it is neither the host nor a parent domain of it
/// within the same registrable domain.
pub fn rp_id_for(page: &Origin, rp_id: &str) -> OpResult<String> {
    let rp = normalize(rp_id)?;
    if page.is_ip() {
        return Err(AppErrorCode::OriginMismatch);
    }
    let host = page.host();
    // A public suffix (or a bare TLD) is never a relying party, even for
    // a page served on it.
    let Some(rp_site) = psl::domain_str(&rp) else {
        return Err(AppErrorCode::OriginMismatch);
    };
    let same = host == rp;
    let parent = host
        .strip_suffix(rp.as_str())
        .is_some_and(|head| head.len() > 1 && head.ends_with('.'));
    if !(same || parent) || psl::domain_str(host) != Some(rp_site) {
        return Err(AppErrorCode::OriginMismatch);
    }
    Ok(rp)
}

/// Lower-case ASCII (punycode) form of a domain name, or `invalid`.
fn normalize(rp_id: &str) -> OpResult<String> {
    let s = rp_id.trim();
    if s.is_empty() || s.len() > MAX_RP_ID || s.ends_with('.') {
        return Err(AppErrorCode::Invalid);
    }
    let rp = match Host::parse(s) {
        Ok(Host::Domain(d)) => d.to_ascii_lowercase(),
        _ => return Err(AppErrorCode::Invalid),
    };
    let label_ok = |l: &str| {
        !l.is_empty() && l.len() <= 63 && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    };
    if rp.len() > MAX_RP_ID || !rp.split('.').all(label_ok) {
        return Err(AppErrorCode::Invalid);
    }
    Ok(rp)
}

/// The `clientDataJSON` of a ceremony, built from the browser's origin:
/// `{"type":...,"challenge":<base64url>,"origin":<origin>,"crossOrigin":false}`.
/// The extension only lets the top frame or a same-origin frame ask, so
/// `crossOrigin` is always false.
pub fn client_data_json(ceremony: Ceremony, challenge: &[u8], page: &Origin) -> Vec<u8> {
    // Every value is ASCII without a quote or a backslash (a fixed type,
    // base64url, an origin of a punycode host), so no escaping is needed.
    format!(
        r#"{{"type":"{}","challenge":"{}","origin":"{}","crossOrigin":false}}"#,
        ceremony.as_str(),
        b64url(challenge),
        page.origin_string(),
    )
    .into_bytes()
}

/// SHA-256 of a `clientDataJSON`.
pub fn client_data_hash(client_data_json: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(digest(&SHA256, client_data_json).as_ref());
    out
}

/// Unpadded base64url.
pub fn b64url(bytes: &[u8]) -> String {
    BASE64URL_NOPAD.encode(bytes)
}

/// Bytes of an unpadded base64url string of 1 to `max` bytes, or
/// `invalid`.
pub fn from_b64url(s: &str, max: usize) -> OpResult<Vec<u8>> {
    let bytes = BASE64URL_NOPAD
        .decode(s.trim().as_bytes())
        .map_err(|_| AppErrorCode::Invalid)?;
    if bytes.is_empty() || bytes.len() > max {
        return Err(AppErrorCode::Invalid);
    }
    Ok(bytes)
}

/// DER `SubjectPublicKeyInfo` of an uncompressed P-256 point, as
/// `AuthenticatorAttestationResponse.getPublicKey()` gives it.
pub fn p256_spki(point: &[u8]) -> OpResult<Vec<u8>> {
    if point.len() != 65 || point[0] != 0x04 {
        return Err(AppErrorCode::Internal);
    }
    let mut out = P256_SPKI_HEADER.to_vec();
    out.extend_from_slice(point);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page(s: &str) -> Origin {
        Origin::parse(s).unwrap()
    }

    #[test]
    fn rp_id_equal_host_ok() {
        assert_eq!(
            rp_id_for(&page("https://atlas-cloud.test/login"), "atlas-cloud.test").unwrap(),
            "atlas-cloud.test"
        );
        assert_eq!(
            rp_id_for(
                &page("https://login.example.co.uk:8443"),
                "Login.Example.co.uk"
            )
            .unwrap(),
            "login.example.co.uk"
        );
    }

    #[test]
    fn rp_id_registrable_suffix_ok() {
        assert_eq!(
            rp_id_for(&page("https://login.atlas-cloud.test"), "atlas-cloud.test").unwrap(),
            "atlas-cloud.test"
        );
        assert_eq!(
            rp_id_for(&page("https://a.b.example.co.uk"), "b.example.co.uk").unwrap(),
            "b.example.co.uk"
        );
        assert_eq!(
            rp_id_for(&page("https://a.b.example.co.uk"), "example.co.uk").unwrap(),
            "example.co.uk"
        );
    }

    #[test]
    fn rp_id_public_suffix_refused() {
        for (o, rp) in [
            ("https://login.example.co.uk", "co.uk"),
            ("https://login.example.co.uk", "uk"),
            ("https://atlas-cloud.test", "test"),
            ("https://alice.github.io", "github.io"),
            ("https://github.io", "github.io"),
            ("https://example.com", "com"),
        ] {
            assert_eq!(
                rp_id_for(&page(o), rp),
                Err(AppErrorCode::OriginMismatch),
                "{o} {rp}"
            );
        }
    }

    #[test]
    fn rp_id_other_site_refused() {
        for (o, rp) in [
            ("https://atlas-cloud.test", "evil.test"),
            ("https://atlas-cloud.test", "login.atlas-cloud.test"),
            ("https://atlas-cloud.test", "atlas-cloud.test.evil.test"),
            ("https://evilatlas-cloud.test", "atlas-cloud.test"),
            ("https://alice.github.io", "bob.github.io"),
            ("https://\u{430}tlas-cloud.test", "atlas-cloud.test"),
            ("https://atlas-cloud.test", "\u{430}tlas-cloud.test"),
            ("https://127.0.0.1", "127.0.0.1"),
        ] {
            assert!(rp_id_for(&page(o), rp).is_err(), "{o} {rp}");
        }
        for rp in [
            "",
            " ",
            "atlas-cloud.test.",
            ".atlas-cloud.test",
            "a..test",
            "atlas-cloud.test:443",
            "https://atlas-cloud.test",
            "atlas cloud.test",
            "[::1]",
        ] {
            assert_eq!(
                rp_id_for(&page("https://atlas-cloud.test"), rp),
                Err(AppErrorCode::Invalid),
                "{rp:?}"
            );
        }
    }

    #[test]
    fn client_data_json_has_the_webauthn_layout() {
        let cdj = client_data_json(
            Ceremony::Get,
            &[0xfb, 0xff, 0x01],
            &page("https://login.atlas-cloud.test:8443/x?y#z"),
        );
        assert_eq!(
            String::from_utf8(cdj.clone()).unwrap(),
            r#"{"type":"webauthn.get","challenge":"-_8B","origin":"https://login.atlas-cloud.test:8443","crossOrigin":false}"#
        );
        let create = client_data_json(Ceremony::Create, &[1], &page("https://atlas-cloud.test"));
        let v: serde_json::Value = serde_json::from_slice(&create).unwrap();
        assert_eq!(v["type"], "webauthn.create");
        assert_eq!(v["origin"], "https://atlas-cloud.test");
        assert_eq!(client_data_hash(&cdj).len(), 32);
    }

    #[test]
    fn b64url_round_trip_and_bounds() {
        assert_eq!(from_b64url(&b64url(&[1, 2, 3]), 3).unwrap(), [1, 2, 3]);
        assert_eq!(from_b64url("AQID", 2), Err(AppErrorCode::Invalid));
        assert_eq!(from_b64url("", 8), Err(AppErrorCode::Invalid));
        assert_eq!(from_b64url("AQ==", 8), Err(AppErrorCode::Invalid));
        assert_eq!(from_b64url("+/8", 8), Err(AppErrorCode::Invalid));
    }
}
