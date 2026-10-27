#![no_main]

use libfuzzer_sys::fuzz_target;
use onepass_core::Id;
use onepass_core::crypto::{Aad, BlobKind, SymmetricKey, open, seal};

const KINDS: [BlobKind; 8] = [
    BlobKind::Keyset,
    BlobKind::VaultKey,
    BlobKind::VaultMeta,
    BlobKind::ItemKey,
    BlobKind::Item,
    BlobKind::Manifest,
    BlobKind::Attachment,
    BlobKind::DeviceState,
];

fuzz_target!(|data: &[u8]| {
    let key = SymmetricKey::from_bytes([0x42; 32]);
    let aad = Aad {
        blob_id: Id([1; 16]),
        vault_id: Some(Id([2; 16])),
        schema: 1,
    };
    let Some((&sel, rest)) = data.split_first() else {
        return;
    };
    let kind = KINDS[usize::from(sel) % KINDS.len()];
    // Raw bytes: exercises the length and magic checks only; with a fixed
    // key random bytes never pass the key commitment.
    let _ = open(&key, kind, &aad, rest);
    // Same bytes behind a well-formed prefix (magic, format, algorithm,
    // kind): reaches the key commitment check.
    let mut framed = vec![b'O', b'P', b'B', 1, 1, kind as u8];
    framed.extend_from_slice(rest);
    let _ = open(&key, kind, &aad, &framed);
    // A valid sealed blob mutated by the input (XOR over its bytes, then a
    // truncation): reaches the commitment, AEAD and padding checks with
    // inputs close to valid ones.
    if let Ok(mut blob) = seal(&key, kind, &aad, b"fixed plaintext") {
        for (i, b) in rest.iter().enumerate() {
            let at = i % blob.len();
            blob[at] ^= b;
        }
        let _ = open(&key, kind, &aad, &blob);
        if let Some(&cut) = rest.first() {
            blob.truncate(usize::from(cut) % (blob.len() + 1));
            let _ = open(&key, kind, &aad, &blob);
        }
    }
});
