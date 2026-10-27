#![no_main]

//! An OnePass archive as a hostile file: header inspection, then opening by
//! passphrase and by account. The account is fixed and made once, at the dev
//! KDF floor (the fuzz crate enables `dev-fast-kdf`, and cargo-fuzz builds
//! with debug assertions, which that floor needs). Besides the raw bytes, the
//! input also mutates a valid backup, so parsing gets past the container
//! framing into the signature and key commitment checks.

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use onepass_core::Id;
use onepass_core::account::{Account, NewAccount};
use onepass_core::archive::{ArchivedVault, Unlock, backup, inspect, open};
use onepass_core::crypto::{KdfParams, random_array};
use onepass_core::model::{ItemType, new_item};
use onepass_core::vault::VaultMeta;

const PASSPHRASE: &str = "quartz lantern oyster meadow 91";

fn kdf() -> KdfParams {
    KdfParams {
        m_kib: 8192,
        t: 1,
        p: 1,
        salt: random_array().unwrap(),
    }
}

fn account() -> &'static NewAccount {
    static A: OnceLock<NewAccount> = OnceLock::new();
    A.get_or_init(|| Account::create_with_params("fuzz account pw", kdf()).unwrap())
}

fn valid_archive() -> &'static [u8] {
    static B: OnceLock<Vec<u8>> = OnceLock::new();
    B.get_or_init(|| {
        let vault = Id::new();
        let vaults = vec![ArchivedVault {
            id: vault,
            meta: VaultMeta {
                name: "Fuzz".into(),
                icon: "key".into(),
                color: "blue".into(),
                travel_safe: false,
                mcp_access: false,
            },
            items: vec![new_item(ItemType::Login, vault, "Example")],
        }];
        backup(&account().account, vaults, Some((PASSPHRASE, kdf()))).unwrap()
    })
}

fn exercise(bytes: &[u8]) {
    let _ = inspect(bytes);
    let _ = open(bytes, Unlock::Passphrase(PASSPHRASE));
    let _ = open(bytes, Unlock::Account(&account().account));
}

fuzz_target!(|data: &[u8]| {
    exercise(data);

    // Mutations of a valid archive: (position, xor) byte pairs.
    let mut bytes = valid_archive().to_vec();
    for pair in data.chunks_exact(3) {
        let pos = usize::from(u16::from_le_bytes([pair[0], pair[1]])) % bytes.len();
        bytes[pos] ^= pair[2];
    }
    exercise(&bytes);
});
