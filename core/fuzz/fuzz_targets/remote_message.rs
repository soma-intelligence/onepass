#![no_main]

//! A remote approval message as a hostile transport serves it, opened on
//! both sides with fixed keys. Random bytes never pass the signature, so the
//! parse, size and sender-lookup paths are what this reaches.

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use onepass_core::Id;
use onepass_core::approvers::{ApproverEntry, ApproverRole};
use onepass_core::crypto::kem::HybridKemSecret;
use onepass_core::crypto::HybridSigningKey;
use onepass_core::remote::{ApproverIdentity, PendingRequests, ReplayGuard, open_request, open_response};

struct Fixture {
    me: ApproverIdentity,
    approvers: Vec<ApproverEntry>,
}

fn fixture() -> &'static Fixture {
    static F: OnceLock<Fixture> = OnceLock::new();
    F.get_or_init(|| {
        let signing = HybridSigningKey::generate().unwrap();
        let kem = HybridKemSecret::generate().unwrap();
        let entry = |id: u8, role| ApproverEntry {
            device_id: Id([id; 16]),
            sign_pub: signing.verifying_key().unwrap(),
            kem_pub: kem.public().unwrap(),
            role,
            added_at: 0,
            retired_at: None,
        };
        Fixture {
            approvers: vec![entry(1, ApproverRole::Mac), entry(2, ApproverRole::Phone)],
            me: ApproverIdentity {
                device_id: Id([2; 16]),
                signing,
                kem,
            },
        }
    })
}

fuzz_target!(|data: &[u8]| {
    let f = fixture();
    let mut seen = ReplayGuard::new();
    let _ = open_request(data, &f.me, &f.approvers, 1_000, &mut seen);
    let mut pending = PendingRequests::new();
    pending.insert([7; 16], Id([2; 16]), 2_000);
    let _ = open_response(data, &f.me, &f.approvers, &mut pending, 1_000);
    let _ = ReplayGuard::from_bytes(data);
});
