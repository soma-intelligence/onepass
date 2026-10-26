#![no_main]

use libfuzzer_sys::fuzz_target;
use onepass_core::Id;
use onepass_core::crypto::{Aad, BlobKind, SymmetricKey, open};

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
    // Raw bytes: exercises the length and magic checks.
    let _ = open(&key, kind, &aad, rest);
    // Same bytes behind a well-formed prefix (magic, format, algorithm,
    // kind): reaches the commitment and AEAD checks.
    let mut framed = vec![b'O', b'P', b'B', 1, 1, kind as u8];
    framed.extend_from_slice(rest);
    let _ = open(&key, kind, &aad, &framed);
});
