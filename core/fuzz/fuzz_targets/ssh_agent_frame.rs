#![no_main]

use libfuzzer_sys::fuzz_target;
use onepass_ssh_agent::keys::verify_signature;
use onepass_ssh_agent::wire::decode_request;

// The first byte picks how the rest is split into a public key blob, a signed
// message and a signature blob (verify_signature), so the length-prefixed
// parsers see every kind of truncation. The whole input also goes to the agent
// request decoder. Neither may panic.
fuzz_target!(|data: &[u8]| {
    let _ = decode_request(data);

    let Some((&split, rest)) = data.split_first() else {
        return;
    };
    let a = (split as usize) % (rest.len() + 1);
    let (blob, tail) = rest.split_at(a);
    let b = (split as usize / 2) % (tail.len() + 1);
    let (msg, sig) = tail.split_at(b);
    let _ = verify_signature(blob, msg, sig);
});
