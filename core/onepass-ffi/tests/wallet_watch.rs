//! Watch-only crypto data over the UniFFI surface. Run with `--features dev-fast-kdf`.

use std::sync::Arc;

use onepass_ffi::*;
use tempfile::TempDir;

const FAST: FfiKdfParams = FfiKdfParams {
    m_kib: 8192,
    t: 1,
    p: 1,
};
const ABANDON: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn session() -> (TempDir, Arc<Session>, String) {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("onepass.db").to_string_lossy().into_owned();
    let created = create_account_with_kdf(path, "Café-étoile".into(), FAST).unwrap();
    let vault_id = created.session.vaults().unwrap()[0].id.clone();
    (dir, created.session, vault_id)
}

#[test]
fn derives_public_data_from_the_stored_phrase_only() {
    let (_dir, s, vault) = session();
    let mut item = s
        .new_item(vault.clone(), FfiItemType::CryptoWallet, "Test".into())
        .unwrap();
    for f in item.sections.iter_mut().flat_map(|s| s.fields.iter_mut()) {
        match f.id.as_str() {
            "name" => {
                f.value = FfiFieldValue::Text {
                    value: "Test".into(),
                }
            }
            "recovery_phrase" => {
                f.value = FfiFieldValue::Mnemonic {
                    value: ABANDON.into(),
                }
            }
            _ => {}
        }
    }
    let saved = s.save_item(item).unwrap();
    let public = s
        .watch_derive_public(vault.clone(), saved.id.clone())
        .unwrap();
    assert_eq!(
        public.ethereum_address,
        "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"
    );
    assert_eq!(
        public.solana_address,
        "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk"
    );
    assert_eq!(
        watch_xpub_addresses(public.bitcoin_zpub.clone(), false, 0, 1).unwrap(),
        vec!["bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"]
    );
    // Nothing was written to the item.
    let again = s.item(vault, saved.id).unwrap();
    assert_eq!(again.sections, saved.sections);
}

#[test]
fn refuses_other_types_and_an_empty_phrase() {
    let (_dir, s, vault) = session();
    let mut wallet = s
        .new_item(vault.clone(), FfiItemType::CryptoWallet, "Vide".into())
        .unwrap();
    for f in wallet.sections.iter_mut().flat_map(|s| s.fields.iter_mut()) {
        if f.id == "name" {
            f.value = FfiFieldValue::Text {
                value: "Vide".into(),
            };
        }
        if f.id == "recovery_phrase" {
            f.value = FfiFieldValue::Mnemonic {
                value: ABANDON.into(),
            };
        }
    }
    let saved = s.save_item(wallet).unwrap();
    assert!(
        s.watch_derive_public(vault.clone(), "00".repeat(16))
            .is_err()
    );
    assert!(s.watch_derive_public(vault, saved.id).is_ok());
}

#[test]
fn entries_and_xpubs() {
    let a = watch_parse_entry("eth: 0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed".into()).unwrap();
    assert_eq!(a.chain, FfiWatchChain::Ethereum);
    assert_eq!(
        a.entry,
        "Ethereum, 0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
    );
    assert!(matches!(
        watch_parse_entry("Ethereum, 0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD".into()),
        Err(OnePassError::InvalidInput { what }) if what == "address checksum"
    ));
    assert!(matches!(
        watch_xpub_kind("xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi".into()),
        Err(OnePassError::InvalidInput { what }) if what == "extended private key"
    ));
    assert_eq!(watch_gap_limit(), 20);
}
