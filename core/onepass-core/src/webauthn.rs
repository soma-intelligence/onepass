//! WebAuthn passkey cryptography: credential creation, registration and
//! assertion data for ES256 (ECDSA P-256 with SHA-256).
//!
//! The private key never leaves this module as anything but the PKCS#8 DER
//! stored in `PasskeyCredential`. CBOR is written by hand: the structures are
//! few and fixed.

use crate::crypto::random::random_array;
use crate::model::PasskeyCredential;
use crate::{Error, Result};
use aws_lc_rs::digest::{SHA256, digest};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
use time::OffsetDateTime;
use zeroize::Zeroizing;

/// OnePass authenticator AAGUID, drawn once at random and fixed.
pub const AAGUID: [u8; 16] = [
    0x0e, 0x0f, 0xd0, 0x5b, 0xa7, 0xc9, 0x85, 0x8d, 0xa5, 0xba, 0x7e, 0x69, 0x5e, 0x91, 0xc3, 0x6c,
];

const MAX_RP_ID: usize = 253;
const MAX_USER_HANDLE: usize = 64;
const MAX_USER_NAME: usize = 1024;
const CREDENTIAL_ID_LEN: usize = 16;

// Authenticator data flags: UP, UV, BE, BS, AT.
const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;
const FLAG_BE: u8 = 0x08;
const FLAG_BS: u8 = 0x10;
const FLAG_AT: u8 = 0x40;

/// Result of a registration: what the system needs to complete it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registration {
    pub credential_id: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub attestation_object: Vec<u8>,
}

/// Result of an assertion (sign-in).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assertion {
    pub authenticator_data: Vec<u8>,
    /// ECDSA P-256 SHA-256 signature, DER encoded.
    pub signature: Vec<u8>,
}

/// Create a fresh ES256 passkey for `rp_id`. The private key is PKCS#8 DER,
/// the same format the CXF import stores.
pub fn new_credential(
    rp_id: &str,
    user_name: &str,
    user_handle: &[u8],
    now: OffsetDateTime,
) -> Result<PasskeyCredential> {
    check_rp_id(rp_id)?;
    if user_handle.len() > MAX_USER_HANDLE {
        return Err(Error::InvalidFormat("passkey user handle"));
    }
    if user_name.len() > MAX_USER_NAME {
        return Err(Error::InvalidFormat("passkey user name"));
    }
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &SystemRandom::new())
        .map_err(|_| Error::Crypto)?;
    Ok(PasskeyCredential {
        rp_id: rp_id.to_owned(),
        user_name: user_name.to_owned(),
        user_handle: user_handle.to_vec(),
        credential_id: random_array::<CREDENTIAL_ID_LEN>()?.to_vec(),
        private_key: Zeroizing::new(pkcs8.as_ref().to_vec()),
        created_at: now,
    })
}

/// COSE_Key (ES256) of the credential, in canonical CBOR (77 bytes):
/// `{1: 2, 3: -7, -1: 1, -2: x, -3: y}`.
pub fn public_key_cose(cred: &PasskeyCredential) -> Result<Vec<u8>> {
    let pair = key_pair(cred)?;
    let point = pair.public_key().as_ref();
    if point.len() != 65 || point[0] != 0x04 {
        return Err(Error::InvalidFormat("passkey key"));
    }
    let mut out = vec![0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21];
    cbor_bytes(&mut out, &point[1..33]);
    out.push(0x22);
    cbor_bytes(&mut out, &point[33..65]);
    Ok(out)
}

/// Registration data: authenticator data with the attested credential and a
/// `none` attestation object.
pub fn registration(cred: &PasskeyCredential, client_data_hash: &[u8]) -> Result<Registration> {
    check_hash(client_data_hash)?;
    check_rp_id(&cred.rp_id)?;
    if cred.credential_id.is_empty() || cred.credential_id.len() > u16::MAX as usize {
        return Err(Error::InvalidFormat("passkey credential id"));
    }
    let cose = public_key_cose(cred)?;
    let mut auth = auth_data_header(&cred.rp_id, FLAG_UP | FLAG_UV | FLAG_BE | FLAG_BS | FLAG_AT);
    auth.extend_from_slice(&AAGUID);
    auth.extend_from_slice(&(cred.credential_id.len() as u16).to_be_bytes());
    auth.extend_from_slice(&cred.credential_id);
    auth.extend_from_slice(&cose);

    // {"fmt": "none", "attStmt": {}, "authData": h'...'} in CTAP2 canonical order.
    let mut obj = vec![0xa3];
    cbor_text(&mut obj, "fmt");
    cbor_text(&mut obj, "none");
    cbor_text(&mut obj, "attStmt");
    obj.push(0xa0);
    cbor_text(&mut obj, "authData");
    cbor_bytes(&mut obj, &auth);
    Ok(Registration {
        credential_id: cred.credential_id.clone(),
        authenticator_data: auth,
        attestation_object: obj,
    })
}

/// Assertion data: authenticator data and the signature over
/// `authenticator_data || client_data_hash`.
pub fn assertion(cred: &PasskeyCredential, client_data_hash: &[u8]) -> Result<Assertion> {
    check_hash(client_data_hash)?;
    check_rp_id(&cred.rp_id)?;
    let pair = key_pair(cred)?;
    let auth = auth_data_header(&cred.rp_id, FLAG_UP | FLAG_UV | FLAG_BE | FLAG_BS);
    let mut msg = auth.clone();
    msg.extend_from_slice(client_data_hash);
    let sig = pair
        .sign(&SystemRandom::new(), &msg)
        .map_err(|_| Error::Crypto)?;
    Ok(Assertion {
        authenticator_data: auth,
        signature: sig.as_ref().to_vec(),
    })
}

fn check_rp_id(rp_id: &str) -> Result<()> {
    if rp_id.is_empty() || rp_id.len() > MAX_RP_ID {
        return Err(Error::InvalidFormat("passkey rp id"));
    }
    Ok(())
}

fn check_hash(hash: &[u8]) -> Result<()> {
    if hash.len() != 32 {
        return Err(Error::InvalidFormat("client data hash"));
    }
    Ok(())
}

/// A key that does not parse as PKCS#8 P-256 (for instance a passkey imported
/// with another algorithm) is rejected.
fn key_pair(cred: &PasskeyCredential) -> Result<EcdsaKeyPair> {
    EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &cred.private_key)
        .map_err(|_| Error::InvalidFormat("passkey key"))
}

/// SHA-256(rp_id) || flags || signature counter (always 0).
fn auth_data_header(rp_id: &str, flags: u8) -> Vec<u8> {
    let mut v = digest(&SHA256, rp_id.as_bytes()).as_ref().to_vec();
    v.push(flags);
    v.extend_from_slice(&[0u8; 4]);
    v
}

fn cbor_head(out: &mut Vec<u8>, major: u8, len: usize) {
    let m = major << 5;
    if len < 24 {
        out.push(m | len as u8);
    } else if len < 256 {
        out.extend_from_slice(&[m | 24, len as u8]);
    } else {
        out.push(m | 25);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    }
}

fn cbor_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    cbor_head(out, 2, bytes.len());
    out.extend_from_slice(bytes);
}

fn cbor_text(out: &mut Vec<u8>, text: &str) {
    cbor_head(out, 3, text.len());
    out.extend_from_slice(text.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;
    use aws_lc_rs::digest::{SHA256, digest};
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1, UnparsedPublicKey};
    use time::macros::datetime;
    use zeroize::Zeroizing;

    fn cred() -> PasskeyCredential {
        new_credential(
            "example.com",
            "alice",
            &[1, 2, 3],
            datetime!(2026-10-26 12:00 UTC),
        )
        .unwrap()
    }

    #[test]
    fn cose_key_layout() {
        let c = cred();
        let k = public_key_cose(&c).unwrap();
        assert_eq!(k.len(), 77);
        assert_eq!(
            k[..10],
            [0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]
        );
        assert_eq!(k[42..45], [0x22, 0x58, 0x20]);
    }

    #[test]
    fn registration_auth_data_layout() {
        let c = cred();
        let r = registration(&c, &[7u8; 32]).unwrap();
        let a = &r.authenticator_data;
        assert_eq!(a[..32], *digest(&SHA256, b"example.com").as_ref());
        assert_eq!(a[32], 0x5D);
        assert_eq!(a[33..37], [0, 0, 0, 0]);
        assert_eq!(a[37..53], AAGUID);
        assert_eq!(a[53..55], 16u16.to_be_bytes());
        assert_eq!(a[55..71], c.credential_id[..]);
        assert_eq!(a[71..], public_key_cose(&c).unwrap()[..]);
        assert_eq!(r.credential_id, c.credential_id);
    }

    #[test]
    fn attestation_object_is_canonical_none() {
        let c = cred();
        let r = registration(&c, &[7u8; 32]).unwrap();
        let mut want = vec![0xa3, 0x63];
        want.extend_from_slice(b"fmt");
        want.extend_from_slice(&[0x64]);
        want.extend_from_slice(b"none");
        want.extend_from_slice(&[0x67]);
        want.extend_from_slice(b"attStmt");
        want.extend_from_slice(&[0xa0, 0x68]);
        want.extend_from_slice(b"authData");
        assert_eq!(r.authenticator_data.len(), 148);
        want.extend_from_slice(&[0x58, 148]);
        want.extend_from_slice(&r.authenticator_data);
        assert_eq!(r.attestation_object, want);
    }

    #[test]
    fn cbor_byte_string_headers() {
        let mut v = Vec::new();
        cbor_bytes(&mut v, &[0u8; 23]);
        assert_eq!(v[..1], [0x57]);
        let mut v = Vec::new();
        cbor_bytes(&mut v, &[0u8; 300]);
        assert_eq!(v[..3], [0x59, 0x01, 0x2c]);
    }

    #[test]
    fn assertion_verifies() {
        let c = cred();
        let cdh = [9u8; 32];
        let a = assertion(&c, &cdh).unwrap();
        assert_eq!(a.authenticator_data.len(), 37);
        assert_eq!(a.authenticator_data[32], 0x1D);
        assert_eq!(a.authenticator_data[33..], [0, 0, 0, 0]);
        let cose = public_key_cose(&c).unwrap();
        let mut point = vec![0x04];
        point.extend_from_slice(&cose[10..42]);
        point.extend_from_slice(&cose[45..77]);
        let mut msg = a.authenticator_data.clone();
        msg.extend_from_slice(&cdh);
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, point)
            .verify(&msg, &a.signature)
            .unwrap();
    }

    #[test]
    fn two_credentials_differ() {
        let (a, b) = (cred(), cred());
        assert_eq!(a.credential_id.len(), 16);
        assert_ne!(a.credential_id, b.credential_id);
        assert_ne!(*a.private_key, *b.private_key);
    }

    #[test]
    fn rejects_bad_inputs() {
        let now = datetime!(2026-10-26 12:00 UTC);
        let bad = |r: crate::Result<PasskeyCredential>| {
            assert!(matches!(r, Err(Error::InvalidFormat(_))))
        };
        bad(new_credential("", "a", &[], now));
        bad(new_credential(&"a".repeat(254), "a", &[], now));
        assert!(new_credential(&"a".repeat(253), "a", &[], now).is_ok());
        bad(new_credential("x.com", "a", &[0; 65], now));
        bad(new_credential("x.com", &"a".repeat(1025), &[], now));
        let c = cred();
        assert!(matches!(
            registration(&c, &[0; 31]),
            Err(Error::InvalidFormat(_))
        ));
        assert!(matches!(
            assertion(&c, &[0; 31]),
            Err(Error::InvalidFormat(_))
        ));
    }

    #[test]
    fn rejects_foreign_key() {
        let mut c = cred();
        c.private_key = Zeroizing::new(vec![5u8; 32]);
        assert_eq!(
            assertion(&c, &[0; 32]).unwrap_err(),
            Error::InvalidFormat("passkey key")
        );
        assert_eq!(
            public_key_cose(&c).unwrap_err(),
            Error::InvalidFormat("passkey key")
        );
    }
}
