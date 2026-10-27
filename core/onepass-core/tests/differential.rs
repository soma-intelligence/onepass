//! NIST ACVP vectors and differential tests between aws-lc-rs (the library the
//! crate uses) and libcrux (an independent, formally verified implementation).

use aws_lc_rs::kem::{Ciphertext, DecapsulationKey, EncapsulationKey, ML_KEM_1024};
use aws_lc_rs::signature::{
    KeyPair, ML_DSA_87, ML_DSA_87_SIGNING, PqdsaKeyPair, UnparsedPublicKey,
};
use data_encoding::HEXUPPER;
use serde_json::Value;
use slh_dsa::{Sha2_256s, Signature as SlhSignature, VerifyingKey as SlhVerifyingKey};

use libcrux_ml_dsa::ml_dsa_87 as lx_dsa;
use libcrux_ml_kem::mlkem1024 as lx_kem;

const MLKEM_VECTORS: &str = include_str!("vectors/mlkem1024.json");
const MLDSA_VECTORS: &str = include_str!("vectors/mldsa87.json");
const MLDSA_SIGGEN_VECTORS: &str = include_str!("vectors/mldsa87_siggen.json");
const SLHDSA_VECTORS: &str = include_str!("vectors/slhdsa_sha2_256s.json");

fn groups(json: &str) -> Vec<Value> {
    let v: Value = serde_json::from_str(json).unwrap();
    v["groups"].as_array().unwrap().clone()
}

fn hex(t: &Value, field: &str) -> Vec<u8> {
    HEXUPPER
        .decode(t[field].as_str().unwrap().as_bytes())
        .unwrap()
}

fn flag(t: &Value) -> bool {
    t["testPassed"].as_bool().unwrap()
}

fn aws_decapsulate(dk: &[u8], ct: &[u8]) -> Vec<u8> {
    let dk = DecapsulationKey::new(&ML_KEM_1024, dk).unwrap();
    dk.decapsulate(Ciphertext::from(ct))
        .unwrap()
        .as_ref()
        .to_vec()
}

fn libcrux_decapsulate(dk: &[u8], ct: &[u8]) -> Vec<u8> {
    let dk = lx_kem::MlKem1024PrivateKey::try_from(dk).unwrap();
    let ct = lx_kem::MlKem1024Ciphertext::try_from(ct).unwrap();
    lx_kem::decapsulate(&dk, &ct).to_vec()
}

#[test]
fn mlkem1024_acvp_decapsulation_vectors() {
    let mut decapsulations = 0;
    let mut encapsulations = 0;
    for g in groups(MLKEM_VECTORS) {
        for t in g["tests"].as_array().unwrap() {
            let (dk, c, k) = (hex(t, "dk"), hex(t, "c"), hex(t, "k"));
            let id = t["tcId"].as_u64().unwrap();
            assert_eq!(
                aws_decapsulate(&dk, &c),
                k,
                "aws-lc decapsulation tcId {id}"
            );
            assert_eq!(
                libcrux_decapsulate(&dk, &c),
                k,
                "libcrux decapsulation tcId {id}"
            );
            decapsulations += 1;
            if g["function"] == "encapsulation" {
                // Deterministic encapsulation from the vector's message m.
                let ek = lx_kem::MlKem1024PublicKey::try_from(&hex(t, "ek")[..]).unwrap();
                let m: [u8; 32] = hex(t, "m").try_into().unwrap();
                let (ct, ss) = lx_kem::encapsulate(&ek, m);
                assert_eq!(ct.as_slice()[..], c[..], "libcrux ciphertext tcId {id}");
                assert_eq!(ss.to_vec(), k, "libcrux encapsulation tcId {id}");
                encapsulations += 1;
            }
        }
    }
    assert_eq!((decapsulations, encapsulations), (35, 25));
}

#[test]
fn mldsa87_acvp_verification_vectors() {
    let mut aws_cases = 0;
    let mut libcrux_cases = 0;
    for g in groups(MLDSA_VECTORS) {
        for t in g["tests"].as_array().unwrap() {
            let (pk, msg, ctx, sig) = (
                hex(t, "pk"),
                hex(t, "message"),
                hex(t, "context"),
                hex(t, "signature"),
            );
            let id = t["tcId"].as_u64().unwrap();
            // aws-lc only offers pure ML-DSA with an empty context.
            if ctx.is_empty() {
                let ok = UnparsedPublicKey::new(&ML_DSA_87, &pk)
                    .verify(&msg, &sig)
                    .is_ok();
                assert_eq!(ok, flag(t), "aws-lc tcId {id}");
                aws_cases += 1;
            }
            // libcrux takes a context: run every pure case.
            let ok = match (
                <[u8; 2592]>::try_from(&pk[..]),
                <[u8; 4627]>::try_from(&sig[..]),
            ) {
                (Ok(pk), Ok(sig)) => lx_dsa::verify(
                    &lx_dsa::MLDSA87VerificationKey::new(pk),
                    &msg,
                    &ctx,
                    &lx_dsa::MLDSA87Signature::new(sig),
                )
                .is_ok(),
                _ => false,
            };
            assert_eq!(ok, flag(t), "libcrux tcId {id}");
            libcrux_cases += 1;
        }
    }
    assert_eq!((aws_cases, libcrux_cases), (1, 15));
}

#[test]
fn mldsa87_acvp_signature_generation_vectors_verify() {
    // ACVP sigGen output (pure, empty context): every expected signature must
    // verify under its public key, on aws-lc and on libcrux.
    let mut cases = 0;
    for g in groups(MLDSA_SIGGEN_VECTORS) {
        for t in g["tests"].as_array().unwrap() {
            let (pk, msg, sig) = (hex(t, "pk"), hex(t, "message"), hex(t, "signature"));
            let id = t["tcId"].as_u64().unwrap();
            assert!(
                UnparsedPublicKey::new(&ML_DSA_87, &pk)
                    .verify(&msg, &sig)
                    .is_ok(),
                "aws-lc tcId {id}"
            );
            let lx_pk =
                lx_dsa::MLDSA87VerificationKey::new(<[u8; 2592]>::try_from(&pk[..]).unwrap());
            let lx_sig = lx_dsa::MLDSA87Signature::new(<[u8; 4627]>::try_from(&sig[..]).unwrap());
            assert!(
                lx_dsa::verify(&lx_pk, &msg, &[], &lx_sig).is_ok(),
                "libcrux tcId {id}"
            );
            cases += 1;
        }
    }
    assert_eq!(cases, 3);
}

#[test]
fn slhdsa_sha2_256s_acvp_verification_vectors() {
    let mut external = 0;
    let mut internal = 0;
    for g in groups(SLHDSA_VECTORS) {
        let is_external = g["signatureInterface"] == "external";
        for t in g["tests"].as_array().unwrap() {
            let id = t["tcId"].as_u64().unwrap();
            let vk = SlhVerifyingKey::<Sha2_256s>::try_from(&hex(t, "pk")[..]).unwrap();
            let msg = hex(t, "message");
            let ok = match SlhSignature::<Sha2_256s>::try_from(&hex(t, "signature")[..]) {
                Ok(sig) if is_external => vk
                    .try_verify_with_context(&msg, &hex(t, "context"), &sig)
                    .is_ok(),
                Ok(sig) => vk.slh_verify_internal(&msg, &sig).is_ok(),
                Err(_) => false,
            };
            assert_eq!(ok, flag(t), "tcId {id}");
            if is_external {
                external += 1;
            } else {
                internal += 1;
            }
        }
    }
    assert_eq!((external, internal), (14, 14));
}

#[test]
fn mlkem1024_awslc_and_libcrux_interoperate() {
    for i in 0..100 {
        // aws-lc key, libcrux encapsulates, aws-lc decapsulates.
        let dk = DecapsulationKey::generate(&ML_KEM_1024).unwrap();
        let ek = dk.encapsulation_key().unwrap().key_bytes().unwrap();
        let lx_ek = lx_kem::MlKem1024PublicKey::try_from(ek.as_ref()).unwrap();
        assert!(lx_kem::validate_public_key(&lx_ek), "iteration {i}");
        let mut m = [0u8; 32];
        aws_lc_rs::rand::fill(&mut m).unwrap();
        let (ct, ss) = lx_kem::encapsulate(&lx_ek, m);
        let aws_ss = dk
            .decapsulate(Ciphertext::from(&ct.as_slice()[..]))
            .unwrap();
        assert_eq!(aws_ss.as_ref(), &ss[..], "libcrux to aws-lc, iteration {i}");

        // libcrux key, aws-lc encapsulates, libcrux decapsulates.
        let mut seed = [0u8; 64];
        aws_lc_rs::rand::fill(&mut seed).unwrap();
        let pair = lx_kem::generate_key_pair(seed);
        let aws_ek = EncapsulationKey::new(&ML_KEM_1024, pair.pk()).unwrap();
        let (aws_ct, aws_ss) = aws_ek.encapsulate().unwrap();
        let lx_ct = lx_kem::MlKem1024Ciphertext::try_from(aws_ct.as_ref()).unwrap();
        let lx_ss = lx_kem::decapsulate(pair.private_key(), &lx_ct);
        assert_eq!(
            aws_ss.as_ref(),
            &lx_ss[..],
            "aws-lc to libcrux, iteration {i}"
        );
    }
}

#[test]
fn mldsa87_awslc_and_libcrux_interoperate() {
    for i in 0..50 {
        let msg = format!("onepass interop message {i}").into_bytes();

        // aws-lc signature verified by libcrux (pure, empty context).
        let aws_key = PqdsaKeyPair::generate(&ML_DSA_87_SIGNING).unwrap();
        let mut sig = vec![0u8; 4627];
        let n = aws_key.sign(&msg, &mut sig).unwrap();
        assert_eq!(n, 4627);
        let lx_pk = lx_dsa::MLDSA87VerificationKey::new(
            <[u8; 2592]>::try_from(aws_key.public_key().as_ref()).unwrap(),
        );
        let lx_sig = lx_dsa::MLDSA87Signature::new(<[u8; 4627]>::try_from(&sig[..]).unwrap());
        assert!(
            lx_dsa::verify(&lx_pk, &msg, &[], &lx_sig).is_ok(),
            "aws-lc to libcrux, iteration {i}"
        );

        // libcrux signature verified by aws-lc.
        let mut keygen = [0u8; 32];
        let mut rand = [0u8; 32];
        aws_lc_rs::rand::fill(&mut keygen).unwrap();
        aws_lc_rs::rand::fill(&mut rand).unwrap();
        let pair = lx_dsa::generate_key_pair(keygen);
        let lx_sig = lx_dsa::sign(&pair.signing_key, &msg, &[], rand).unwrap();
        assert!(
            UnparsedPublicKey::new(&ML_DSA_87, pair.verification_key.as_ref())
                .verify(&msg, lx_sig.as_ref())
                .is_ok(),
            "libcrux to aws-lc, iteration {i}"
        );
        // A tampered message must fail on both sides.
        let mut bad = msg.clone();
        bad[0] ^= 1;
        assert!(lx_dsa::verify(&lx_pk, &bad, &[], &lx_sig).is_err());
        assert!(
            UnparsedPublicKey::new(&ML_DSA_87, pair.verification_key.as_ref())
                .verify(&bad, lx_sig.as_ref())
                .is_err()
        );
    }
}
