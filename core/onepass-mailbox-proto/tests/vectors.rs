//! Frozen request signature vectors (spec 4.7), written from the spec form
//! with an independent tool and fixed seeds. A failure here is a wire break.

use aws_lc_rs::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use data_encoding::HEXLOWER;
use onepass_mailbox_proto::*;
use serde::Deserialize;

#[derive(Deserialize)]
struct File {
    vectors: Vec<Vector>,
}

#[derive(Deserialize)]
struct Vector {
    name: String,
    seed: String,
    public_key: String,
    method: String,
    target: String,
    body: String,
    created: i64,
    nonce: String,
    keyid: String,
    content_digest: String,
    signature_input: String,
    signature_base: String,
    signature_bytes: String,
    signature: String,
}

fn hex<const N: usize>(s: &str) -> [u8; N] {
    HEXLOWER.decode(s.as_bytes()).unwrap().try_into().unwrap()
}

#[test]
fn signature_vectors() {
    let file: File =
        serde_json::from_str(include_str!("vectors/signature.json")).expect("vector file");
    assert!(file.vectors.len() >= 4);
    let methods: Vec<&str> = file.vectors.iter().map(|v| v.method.as_str()).collect();
    for m in ["GET", "POST", "PUT", "DELETE"] {
        assert!(methods.contains(&m), "no {m} vector");
    }
    assert!(file.vectors.iter().any(|v| v.target.contains('?')));

    for v in &file.vectors {
        let name = &v.name;
        let seed: [u8; 32] = hex(&v.seed);
        let key = Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
        let pk: CredentialPublicKey = hex(&v.public_key);
        assert_eq!(key.public_key().as_ref(), pk, "{name}: public key");
        assert_eq!(credential_id(&pk), hex::<16>(&v.keyid), "{name}: keyid");

        let body = HEXLOWER.decode(v.body.as_bytes()).unwrap();
        assert_eq!(content_digest(&body), v.content_digest, "{name}: digest");

        let params = SignatureParams {
            created: v.created,
            nonce: hex(&v.nonce),
            keyid: hex(&v.keyid),
        };
        assert_eq!(
            signature_input_header(&params),
            v.signature_input,
            "{name}: Signature-Input"
        );
        let base = signature_base(&v.method, &v.target, &v.content_digest, &params).unwrap();
        assert_eq!(base, v.signature_base.as_bytes(), "{name}: base");

        // Ed25519 is deterministic: the frozen signature is the one we make.
        let sig: CredentialSignature = hex(&v.signature_bytes);
        assert_eq!(key.sign(&base).as_ref(), sig, "{name}: signature");
        UnparsedPublicKey::new(&ED25519, pk)
            .verify(&base, &sig)
            .unwrap_or_else(|_| panic!("{name}: verify"));
        assert_eq!(signature_header(&sig), v.signature, "{name}: Signature");

        let parsed = parse_signature_headers(&v.signature_input, &v.signature).unwrap();
        assert_eq!(parsed, ParsedSignature { params, sig }, "{name}: parse");
        check_skew(v.created, v.created + SKEW_SECS).unwrap();
    }
}
