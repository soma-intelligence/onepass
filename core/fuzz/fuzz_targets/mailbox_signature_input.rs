#![no_main]

//! Hostile `Signature-Input` and `Signature` headers and signature base
//! inputs: no panic, and whatever parses spells back to exactly the input.

use libfuzzer_sys::fuzz_target;
use onepass_mailbox_proto::*;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let mut parts = text.splitn(3, '\n');
    let input = parts.next().unwrap_or("");
    let signature = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");
    if let Ok(p) = parse_signature_headers(input, signature) {
        assert_eq!(signature_input_header(&p.params), input);
        assert_eq!(signature_header(&p.sig), signature);
        for method in ["GET", "POST", "PUT", "DELETE"] {
            if let Ok(base) = signature_base(method, target, &content_digest(data), &p.params) {
                assert!(!base.ends_with(b"\n"));
                assert_eq!(base.iter().filter(|&&b| b == b'\n').count(), 3);
            }
        }
        let _ = check_skew(p.params.created, 1_793_404_800);
    }
    let params = SignatureParams {
        created: 0,
        nonce: [0; 16],
        keyid: [0; 16],
    };
    let _ = signature_base(input, target, signature, &params);
});
