use onepass_core::crypto::SymmetricKey;
use onepass_core::crypto::aead::{Aad, BlobKind, HEADER_LEN, open, padded_len, seal};
use onepass_core::{Error, Id, IntegrityError};
use proptest::prelude::*;

fn aad() -> Aad {
    Aad {
        blob_id: Id::new(),
        vault_id: Some(Id::new()),
        schema: 1,
    }
}

#[test]
fn roundtrip_at_padding_edges() {
    let k = SymmetricKey::generate().unwrap();
    let a = aad();
    for len in [
        0, 1, 251, 252, 253, 255, 256, 257, 65531, 65532, 65536, 65537, 200_000,
    ] {
        let pt = vec![0x5A; len];
        let blob = seal(&k, BlobKind::Item, &a, &pt).unwrap();
        assert_eq!(blob.len(), HEADER_LEN + padded_len(len + 4) + 16);
        assert_eq!(&open(&k, BlobKind::Item, &a, &blob).unwrap()[..], &pt[..]);
    }
}

#[test]
fn padded_len_buckets() {
    assert_eq!(padded_len(1), 256);
    assert_eq!(padded_len(256), 256);
    assert_eq!(padded_len(257), 512);
    assert_eq!(padded_len(65536), 65536);
    assert_eq!(padded_len(65537), 131072);
    assert_eq!(padded_len(131073), 196608);
}

#[test]
fn wrong_kind_vault_blobid_or_schema_is_rejected() {
    let k = SymmetricKey::generate().unwrap();
    let a = aad();
    let blob = seal(&k, BlobKind::Item, &a, b"x").unwrap();
    assert!(matches!(
        open(&k, BlobKind::Keyset, &a, &blob),
        Err(Error::Integrity(IntegrityError::WrongKind))
    ));
    for other in [
        Aad {
            blob_id: Id::new(),
            ..a.clone()
        },
        Aad {
            vault_id: Some(Id::new()),
            ..a.clone()
        },
        Aad {
            schema: 2,
            ..a.clone()
        },
    ] {
        assert!(matches!(
            open(&k, BlobKind::Item, &other, &blob),
            Err(Error::Integrity(IntegrityError::Commitment))
        ));
    }
}

#[test]
fn wrong_key_fails_on_commitment_before_aead() {
    let a = aad();
    let blob = seal(&SymmetricKey::generate().unwrap(), BlobKind::Item, &a, b"x").unwrap();
    assert!(matches!(
        open(
            &SymmetricKey::generate().unwrap(),
            BlobKind::Item,
            &a,
            &blob
        ),
        Err(Error::Integrity(IntegrityError::Commitment))
    ));
}

proptest! {
    #[test]
    fn any_single_bitflip_is_rejected(pt in proptest::collection::vec(any::<u8>(), 0..2000), pos in any::<usize>(), bit in 0u8..8) {
        let k = SymmetricKey::generate().unwrap();
        let a = aad();
        let mut blob = seal(&k, BlobKind::Item, &a, &pt).unwrap();
        let i = pos % blob.len();
        blob[i] ^= 1 << bit;
        prop_assert!(open(&k, BlobKind::Item, &a, &blob).is_err());
    }
}
