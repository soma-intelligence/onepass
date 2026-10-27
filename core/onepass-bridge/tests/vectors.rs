//! Cross-language test vectors of the bridge protocol.
//!
//! Every value is produced by the production state machines
//! (`HostPairing`, `ExtPairing`, `host_accept`, `ext_hello`, `Channel`)
//! through their deterministic constructors, with seeds derived from
//! SHA-256 of fixed ASCII labels. The seeds are public and carry no secret.
//! The TypeScript client replays these files.
//!
//! Run (the test needs feature `vectors`, so a plain `cargo test
//! --workspace` skips it):
//!
//! ```text
//! cargo test -p onepass-bridge --features vectors --test vectors
//! ```
//!
//! Regenerate the files after an intended protocol change:
//!
//! ```text
//! ONEPASS_WRITE_VECTORS=1 cargo test -p onepass-bridge --features vectors --test vectors
//! ```
//!
//! `vectors_are_up_to_date` regenerates everything in memory and compares
//! the JSON values (whitespace is irrelevant).

use std::path::PathBuf;

use aws_lc_rs::digest::{SHA256, digest};
use data_encoding::BASE64;
use onepass_bridge::api::{Ctx, Method, Reply, Request, Response, Summary, SummaryKind};
use onepass_bridge::kdf;
use onepass_bridge::kem::{self, KemSecret};
use onepass_bridge::origin::MatchQuality;
use onepass_bridge::pairing::{ExtPairing, HostPairing};
use onepass_bridge::provider::ProviderId;
use onepass_bridge::session::{ext_hello_deterministic, host_accept_deterministic};
use onepass_bridge::wire::{self, Envelope, Msg, PairConfirm, PairHello, PairOffer, PairReveal};
use serde_json::{Map, Value, json};
use zeroize::Zeroizing;

const EXT_NAME: &str = "OnePass";
const BROWSER: &str = "Chromium";

fn b64(b: &[u8]) -> Value {
    Value::String(BASE64.encode(b))
}

/// `N` bytes derived from SHA-256 of `"onepass vectors <name>"`, extended
/// block by block with a counter suffix when more than 32 bytes are needed.
fn seed<const N: usize>(name: &str) -> [u8; N] {
    let mut out = [0u8; N];
    for (i, chunk) in out.chunks_mut(32).enumerate() {
        let label = if i == 0 {
            format!("onepass vectors {name}")
        } else {
            format!("onepass vectors {name} {i}")
        };
        let d = digest(&SHA256, label.as_bytes());
        chunk.copy_from_slice(&d.as_ref()[..chunk.len()]);
    }
    out
}

/// The exact JSON object that goes on the wire for an envelope.
fn wire_json(env: &Envelope) -> Value {
    serde_json::from_slice(&wire::to_bytes(env)).expect("envelope is JSON")
}

fn obj(fields: Vec<(&str, Value)>) -> Value {
    let mut m = Map::new();
    for (k, v) in fields {
        m.insert(k.to_owned(), v);
    }
    Value::Object(m)
}

fn kem_vectors() -> Value {
    let mlkem_seed = seed::<64>("mlkem seed kem");
    let x25519_secret = seed::<32>("x25519 secret kem");
    let encaps_mlkem_seed = seed::<32>("encaps mlkem seed kem");
    let encaps_x25519_eph = seed::<32>("encaps x25519 eph kem");
    let sk = KemSecret::from_seeds(&mlkem_seed, &x25519_secret).unwrap();
    let public = sk.public();
    let (ct, ss) =
        kem::encapsulate_deterministic(&public, &encaps_mlkem_seed, &encaps_x25519_eph).unwrap();
    assert_eq!(*sk.decapsulate(&ct).unwrap(), *ss);
    obj(vec![
        ("mlkem_seed", b64(&mlkem_seed)),
        ("x25519_secret", b64(&x25519_secret)),
        ("public", b64(&public.to_bytes())),
        ("encaps_mlkem_seed", b64(&encaps_mlkem_seed)),
        ("encaps_x25519_eph", b64(&encaps_x25519_eph)),
        ("ct", b64(&ct)),
        ("ss", b64(&*ss)),
    ])
}

/// Code keys and the code `kdf::sas` shows for them, including values under
/// 100 000 that need zero padding ("%03d %03d").
fn sas_cases() -> Value {
    let cases: Vec<Value> = [0u32, 5, 12_345, 99_999, 100_000, 999_999, 1_000_000 + 7]
        .iter()
        .map(|n| {
            let mut key = [0xA5u8; 32];
            key[..4].copy_from_slice(&n.to_be_bytes());
            json!({"code_key": b64(&key), "sas": kdf::sas(&key)})
        })
        .collect();
    assert_eq!(cases[2]["sas"], "012 345");
    Value::Array(cases)
}

/// Pairing vectors plus the record both sides stored, reused by the session.
fn pairing_vectors() -> (Value, onepass_bridge::pairing::PairingRecord) {
    let ext_mlkem_seed = seed::<64>("mlkem seed ext");
    let ext_x25519_secret = seed::<32>("x25519 secret ext");
    let ext_nonce = seed::<32>("nonce ext");
    let host_mlkem_seed = seed::<64>("mlkem seed host");
    let host_x25519_secret = seed::<32>("x25519 secret host");
    let host_nonce = seed::<32>("nonce host");
    let pairing_id = seed::<16>("pairing id");
    let encaps_mlkem_seed = seed::<32>("encaps mlkem seed pairing");
    let encaps_x25519_eph = seed::<32>("encaps x25519 eph pairing");

    let sk_e = KemSecret::from_seeds(&ext_mlkem_seed, &ext_x25519_secret).unwrap();
    let sk_h = KemSecret::from_seeds(&host_mlkem_seed, &host_x25519_secret).unwrap();

    let (mut ext, hello): (ExtPairing, PairHello) =
        ExtPairing::start_deterministic(EXT_NAME, BROWSER, 0, sk_e, ext_nonce).unwrap();
    let commit = hello.commit.0;
    let (mut host, offer): (HostPairing, PairOffer) =
        HostPairing::start_deterministic(hello.clone(), 0, pairing_id, sk_h, host_nonce).unwrap();
    let (reveal, sas_ext): (PairReveal, _) = ext
        .on_offer_deterministic(offer.clone(), &encaps_mlkem_seed, &encaps_x25519_eph)
        .unwrap();
    let sas_host = host.on_reveal(reveal.clone(), 0).unwrap();
    assert_eq!(sas_ext, sas_host);
    let done = host.approve(0).unwrap();
    ext.on_done(done.clone(), 0).unwrap();
    let keys_host = host.vector_keys().expect("host keys");
    assert_eq!(Some(keys_host.clone()), ext.vector_keys());
    let (confirm, record): (PairConfirm, _) = ext.confirm(0).unwrap();
    let host_record = host.on_confirm(confirm.clone(), 0).unwrap();
    assert_eq!(*host_record.key, *record.key);
    assert_eq!(*record.key, keys_host.pairing_key);

    let v = obj(vec![
        ("ext_name", json!(EXT_NAME)),
        ("browser", json!(BROWSER)),
        ("ext_mlkem_seed", b64(&ext_mlkem_seed)),
        ("ext_x25519_secret", b64(&ext_x25519_secret)),
        ("ext_nonce", b64(&ext_nonce)),
        ("host_mlkem_seed", b64(&host_mlkem_seed)),
        ("host_x25519_secret", b64(&host_x25519_secret)),
        ("host_nonce", b64(&host_nonce)),
        ("pairing_id", b64(&pairing_id)),
        ("encaps_mlkem_seed", b64(&encaps_mlkem_seed)),
        ("encaps_x25519_eph", b64(&encaps_x25519_eph)),
        ("commit", b64(&commit)),
        ("transcript_hash", b64(&keys_host.transcript_hash)),
        ("sas", json!(sas_host.0)),
        ("sas_cases", sas_cases()),
        ("pairing_key", b64(&keys_host.pairing_key)),
        ("confirm_key", b64(&keys_host.confirm_key)),
        ("mac_host", b64(&done.mac.0)),
        ("mac_ext", b64(&confirm.mac.0)),
        ("pair_hello", wire_json(&Envelope::PairHello(hello))),
        ("pair_offer", wire_json(&Envelope::PairOffer(offer))),
        ("pair_reveal", wire_json(&Envelope::PairReveal(reveal))),
        ("pair_sas", wire_json(&Envelope::PairSas)),
        ("pair_done", wire_json(&Envelope::PairDone(done))),
        ("pair_confirm", wire_json(&Envelope::PairConfirm(confirm))),
        ("pair_ok", wire_json(&Envelope::PairOk)),
    ]);
    (v, record)
}

fn frame(
    plain: &str,
    ch_send: &mut onepass_bridge::channel::Channel,
    ch_recv: &mut onepass_bridge::channel::Channel,
) -> Value {
    let env = ch_send.seal(plain.as_bytes()).unwrap();
    let Envelope::Msg(m) = &env else {
        panic!("seal gives a msg")
    };
    let m: Msg = m.clone();
    assert_eq!(&*ch_recv.open(&m).unwrap(), plain.as_bytes());
    json!({"counter": m.c, "plaintext": plain, "msg": wire_json(&env)})
}

fn session_vectors(record: &onepass_bridge::pairing::PairingRecord) -> Value {
    let ext_mlkem_seed = seed::<64>("mlkem seed session ext");
    let ext_x25519_secret = seed::<32>("x25519 secret session ext");
    let ext_nonce = seed::<32>("nonce session ext");
    let encaps_mlkem_seed = seed::<32>("encaps mlkem seed session");
    let encaps_x25519_eph = seed::<32>("encaps x25519 eph session");
    let host_nonce = seed::<32>("nonce session host");
    let session_id = seed::<16>("session id");

    let sk = KemSecret::from_seeds(&ext_mlkem_seed, &ext_x25519_secret).unwrap();
    let (pending_ext, hello) = ext_hello_deterministic(record, sk, ext_nonce).unwrap();
    let key = record.key.clone();
    let (pending_host, welcome) = host_accept_deterministic(
        hello.clone(),
        |id| (*id == record.pairing_id).then(|| Zeroizing::new(*key)),
        &encaps_mlkem_seed,
        &encaps_x25519_eph,
        host_nonce,
        session_id,
    )
    .unwrap();
    let keys = pending_host.vector_keys();
    let (mut ext_ch, finish) = pending_ext.on_welcome(welcome.clone(), 0).unwrap();
    let mut host_ch = pending_host.on_finish(finish.clone(), 0).unwrap();

    let e2h = [
        Request::Status { id: 1 },
        Request::ListForOrigin {
            id: 2,
            ctx: Ctx::Popup,
            origin: "https://atlas-cloud.test".into(),
        },
    ];
    let h2e = [
        Reply::Ok {
            id: 1,
            ok: Box::new(Response::Status {
                locked: false,
                account: "alex@atlas.dev".into(),
                vaults: 2,
            }),
        },
        Reply::Ok {
            id: 2,
            ok: Box::new(Response::Items {
                items: vec![Summary {
                    item_id: "it_01".into(),
                    vault_id: "vt_01".into(),
                    vault_name: "Personal".into(),
                    title: "Atlas Cloud".into(),
                    subtitle: "alex@atlas.dev".into(),
                    kind: SummaryKind::Login,
                    icon_letter: "A".into(),
                    icon_color: "#4F46E5".into(),
                    has_password: true,
                    has_totp: false,
                    methods: vec![Method {
                        provider: ProviderId::Google,
                        account_email: "alex.perso@example.com".into(),
                    }],
                    match_quality: Some(MatchQuality::ExactHost),
                }],
            }),
        },
    ];
    // Plaintexts are the compact serialization of the real API types.
    let e2h: Vec<String> = e2h
        .iter()
        .map(|r| serde_json::to_string(r).unwrap())
        .collect();
    let h2e: Vec<String> = h2e
        .iter()
        .map(|r| serde_json::to_string(r).unwrap())
        .collect();
    for p in &e2h {
        serde_json::from_str::<Request>(p).expect("e2h plaintext is a valid request");
    }
    let e2h_frames: Vec<Value> = e2h
        .iter()
        .map(|p| frame(p, &mut ext_ch, &mut host_ch))
        .collect();
    let h2e_frames: Vec<Value> = h2e
        .iter()
        .map(|p| frame(p, &mut host_ch, &mut ext_ch))
        .collect();

    obj(vec![
        ("pairing_id", b64(&record.pairing_id)),
        ("pairing_key", b64(&*record.key)),
        ("ext_mlkem_seed", b64(&ext_mlkem_seed)),
        ("ext_x25519_secret", b64(&ext_x25519_secret)),
        ("ext_nonce", b64(&ext_nonce)),
        ("host_encaps_mlkem_seed", b64(&encaps_mlkem_seed)),
        ("host_encaps_x25519_eph", b64(&encaps_x25519_eph)),
        ("host_nonce", b64(&host_nonce)),
        ("session_id", b64(&session_id)),
        ("transcript_hash", b64(&keys.transcript_hash)),
        ("key_e2h", b64(&keys.key_e2h)),
        ("key_h2e", b64(&keys.key_h2e)),
        ("key_confirm", b64(&keys.key_confirm)),
        ("hello", wire_json(&Envelope::Hello(hello))),
        ("welcome", wire_json(&Envelope::Welcome(welcome))),
        ("finish", wire_json(&Envelope::Finish(finish))),
        ("frames_e2h", Value::Array(e2h_frames)),
        ("frames_h2e", Value::Array(h2e_frames)),
    ])
}

fn generate() -> Vec<(&'static str, Value)> {
    let (pairing, record) = pairing_vectors();
    let session = session_vectors(&record);
    vec![
        ("kem.json", kem_vectors()),
        ("pairing.json", pairing),
        ("session.json", session),
    ]
}

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors")
}

#[test]
fn vectors_are_up_to_date() {
    let files = generate();
    if std::env::var_os("ONEPASS_WRITE_VECTORS").is_some_and(|v| v == "1") {
        std::fs::create_dir_all(dir()).unwrap();
        for (name, value) in &files {
            let mut text = serde_json::to_string_pretty(value).unwrap();
            text.push('\n');
            std::fs::write(dir().join(name), text).unwrap();
        }
        return;
    }
    for (name, want) in &files {
        let path = dir().join(name);
        let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
            panic!(
                "{}: {e}; run with ONEPASS_WRITE_VECTORS=1 to create it",
                path.display()
            )
        });
        let have: Value = serde_json::from_str(&text).unwrap();
        assert!(
            have == *want,
            "{name} is stale; regenerate with ONEPASS_WRITE_VECTORS=1"
        );
    }
}
