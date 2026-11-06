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
    let (a, b) = (watch_cache_key().unwrap(), watch_cache_key().unwrap());
    assert_eq!(a.len(), 32);
    assert_ne!(a, b);
}

#[test]
fn unprotected_wallets_are_the_funded_ones_with_a_phrase() {
    let (_dir, s, vault) = session();
    let mut item = s
        .new_item(vault.clone(), FfiItemType::CryptoWallet, "Chaud".into())
        .unwrap();
    for f in item.sections.iter_mut().flat_map(|s| s.fields.iter_mut()) {
        match f.id.as_str() {
            "name" => {
                f.value = FfiFieldValue::Text {
                    value: "Chaud".into(),
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
    let key = FfiItemKey {
        vault_id: vault.clone(),
        item_id: saved.id.clone(),
    };
    let bogus = FfiItemKey {
        vault_id: vault,
        item_id: "zz".into(),
    };
    assert_eq!(
        s.watch_unprotected_wallets(vec![key.clone(), bogus])
            .unwrap(),
        vec![key]
    );
}

#[test]
fn watch_wallets_reads_public_fields_only() {
    let (_dir, s, vault) = session();
    let mut item = s
        .new_item(vault.clone(), FfiItemType::CryptoWallet, "Froid".into())
        .unwrap();
    let main = &mut item.sections[0];
    let at = main
        .fields
        .iter()
        .position(|f| f.id == "public_addresses")
        .unwrap();
    let mut copy = main.fields[at].clone();
    for f in main.fields.iter_mut() {
        match f.id.as_str() {
            "name" => f.value = FfiFieldValue::Text { value: "Froid".into() },
            "recovery_phrase" => f.value = FfiFieldValue::Mnemonic { value: ABANDON.into() },
            "public_addresses" => {
                f.value = FfiFieldValue::Text {
                    value: "eth, 0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed".into(),
                }
            }
            "xpub" => {
                f.value = FfiFieldValue::Text {
                    value: "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs".into(),
                }
            }
            _ => {}
        }
    }
    copy.value = FfiFieldValue::Text {
        value: "Bitcoin, pas une adresse".into(),
    };
    main.fields.insert(at + 1, copy);
    s.save_item(item).unwrap();
    let wallets = s.watch_wallets().unwrap();
    assert_eq!(wallets.len(), 1);
    let w = &wallets[0];
    assert_eq!(w.addresses.len(), 1);
    assert_eq!(
        w.addresses[0].address,
        "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
    );
    assert_eq!(w.invalid_entries, vec!["Bitcoin, pas une adresse"]);
    assert!(w.xpub.is_some() && !w.xpub_invalid);
    assert!(w.has_phrase && w.phrase_unprotected);
}
