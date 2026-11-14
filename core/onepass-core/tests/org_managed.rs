//! OnePass Business E1 (Task 2): a managed account's genesis names its
//! organisation (format 2) and takes the account id the inviter chose; a
//! personal account's genesis stays format 1.

use onepass_core::crypto::{KdfParams, random_array};
use onepass_core::device_keys::DeviceKeys;
use onepass_core::devices::{DeviceKind, DeviceMode};
use onepass_core::lineage::{GenesisBody, LineageRecord, verify_genesis};
use onepass_core::org::OrgId;
use onepass_core::repo::{ManagedGenesis, Repository};
use onepass_core::store::{RecordKind, RecordStore, SqliteStore};
use onepass_core::{Id, Result};

const PASSWORD: &str = "Projet Atlas, Camille Durand";

fn kdf() -> KdfParams {
    KdfParams {
        m_kib: 8192,
        t: 1,
        p: 1,
        salt: random_array().unwrap(),
    }
}

fn create(
    dir: &tempfile::TempDir,
    org: Option<Option<ManagedGenesis>>,
) -> Result<Repository<SqliteStore>> {
    let store = SqliteStore::open(&dir.path().join("vault.db"))?;
    let keys = DeviceKeys::generate_software()?;
    let (repo, _sk) = match org {
        None => Repository::create_account_v2(
            store,
            PASSWORD,
            kdf(),
            &keys,
            "iPhone de Camille",
            DeviceKind::Phone,
            DeviceMode::Personal,
        )?,
        Some(org) => Repository::create_account_v2_with_org(
            store,
            PASSWORD,
            kdf(),
            &keys,
            "iPhone de Camille",
            DeviceKind::Phone,
            DeviceMode::Personal,
            org,
        )?,
    };
    Ok(repo)
}

fn genesis(repo: &Repository<SqliteStore>) -> GenesisBody {
    let lineage = repo.store().list(RecordKind::Lineage).unwrap();
    assert_eq!(lineage.len(), 1);
    let rec = LineageRecord::decode(&lineage[0].data).unwrap();
    assert_eq!(lineage[0].id, rec.record_id());
    let LineageRecord::Genesis(g) = rec else {
        panic!("a genesis")
    };
    verify_genesis(&g).unwrap();
    g.body
}

#[test]
fn managed_account_writes_format_2_genesis() {
    let dir = tempfile::tempdir().unwrap();
    let repo = create(
        &dir,
        Some(Some(ManagedGenesis {
            org_id: OrgId([7; 16]),
            account_id: Id([9; 16]),
        })),
    )
    .unwrap();
    let g = genesis(&repo);
    assert_eq!(g.format, 2);
    assert_eq!(g.org, Some([7; 16]));
    assert_eq!(g.account_id, Id([9; 16]));
    assert_eq!(repo.account().params.account_id, Id([9; 16]));
    assert_eq!(repo.genesis_org(), Ok(Some(OrgId([7; 16]))));
}

#[test]
fn personal_account_still_writes_format_1() {
    for org in [None, Some(None)] {
        let dir = tempfile::tempdir().unwrap();
        let repo = create(&dir, org).unwrap();
        let g = genesis(&repo);
        assert_eq!(g.format, 1);
        assert_eq!(g.org, None);
        assert_eq!(g.account_id, repo.account().params.account_id);
        assert_ne!(g.account_id, Id([9; 16]));
        assert_eq!(repo.genesis_org(), Ok(None));
    }
}

/// A pre-v2 account has no genesis: no org either.
#[test]
fn legacy_account_has_no_org() {
    let dir = tempfile::tempdir().unwrap();
    let store = SqliteStore::open(&dir.path().join("vault.db")).unwrap();
    let (repo, _) = Repository::create_account(store, PASSWORD, kdf()).unwrap();
    assert_eq!(repo.genesis_org(), Ok(None));
}
