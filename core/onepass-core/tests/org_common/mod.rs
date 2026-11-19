//! Shared fixtures for the org tests (Business E1). SLH-DSA keygen is slow,
//! so every key here is generated once per test binary behind a `OnceLock`.
//! Each binary uses a subset, hence the `dead_code` allowance. Also the
//! managed account a join request needs (`create`) and the standard org
//! the attack and property tests share (`std_org`).

#![allow(dead_code)]

use std::sync::OnceLock;

use onepass_core::Id;
use onepass_core::crypto::{
    HybridKemPublic, HybridKemSecret, IdentityKey, IdentityVerifyingKey, KdfParams, random_array,
};
use onepass_core::device_keys::{DeviceKeys, DevicePublic};
use onepass_core::devices::{DeviceKind, DeviceMode};
use onepass_core::lineage::{LineageRecord, verify_genesis};
use onepass_core::org::{
    MemberRef, MemberState, OrgGenesisBody, OrgId, OrgLineage, OrgMember, OrgSecrets, Role,
    RoleSet, RosterBody, SignedOrgRecord, SignedRoster, accept_first_roster, founding_roster,
    invite_commit, member_kem_hash, sign_org_genesis, sign_roster, verify_org_genesis,
};
use onepass_core::repo::{ManagedGenesis, Repository};
use onepass_core::store::{RecordKind, RecordStore, SqliteStore};

/// The org secrets of the test organization.
pub fn org_secrets() -> &'static OrgSecrets {
    static CELL: OnceLock<OrgSecrets> = OnceLock::new();
    CELL.get_or_init(|| OrgSecrets::generate().unwrap())
}

/// Identity key `i` of a pool of 3 (one per test account, `i < 3`).
pub fn identity_pool(i: usize) -> &'static (IdentityKey, IdentityVerifyingKey) {
    static POOL: OnceLock<Vec<(IdentityKey, IdentityVerifyingKey)>> = OnceLock::new();
    &POOL.get_or_init(|| {
        (0..3)
            .map(|_| {
                let k = IdentityKey::generate().unwrap();
                let vk = k.verifying_key();
                (k, vk)
            })
            .collect()
    })[i]
}

/// KEM key pair `i` of a pool of 3 (member KEM keys, `i < 3`).
pub fn kem_pool(i: usize) -> &'static (HybridKemSecret, HybridKemPublic) {
    static POOL: OnceLock<Vec<(HybridKemSecret, HybridKemPublic)>> = OnceLock::new();
    &POOL.get_or_init(|| {
        (0..3)
            .map(|_| {
                let s = HybridKemSecret::generate().unwrap();
                let p = s.public().unwrap();
                (s, p)
            })
            .collect()
    })[i]
}

/// A software device and its public half.
pub struct TestDevice {
    pub keys: DeviceKeys,
    pub public: DevicePublic,
}

/// A fresh software device with id `Id([tag; 16])`.
pub fn device(tag: u8) -> TestDevice {
    let keys = DeviceKeys::generate_software().unwrap();
    let public = keys.public(Id([tag; 16])).unwrap();
    TestDevice { keys, public }
}

/// The owner reference of test account `account`: `Id([account; 16])`,
/// identity and KEM keys from the pools (`account % 3`, so accounts may
/// share keys; only account ids must be unique), the devices' fingerprints
/// sorted.
pub fn member_ref(account: u8, devices: &[&TestDevice]) -> MemberRef {
    let i = usize::from(account % 3);
    let mut fprs: Vec<[u8; 32]> = devices.iter().map(|d| d.public.fingerprint()).collect();
    fprs.sort_unstable();
    MemberRef {
        account_id: Id([account; 16]),
        account_identity_pub: identity_pool(i).1.clone(),
        account_kem_pub: kem_pool(i).1.clone(),
        devices: fprs,
    }
}

/// SHA-256 over the concatenation of `parts` (the crate's helper is private).
pub fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut ctx = aws_lc_rs::digest::Context::new(&aws_lc_rs::digest::SHA256);
    for p in parts {
        ctx.update(p);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(ctx.finish().as_ref());
    out
}

pub const PASSWORD: &str = "Projet Atlas, Camille Durand";

/// A managed (or personal) account as the join request needs it: the
/// creator device's keys and public half, the genesis record bytes, the
/// account KEM key and identity.
pub struct Joiner {
    pub keys: DeviceKeys,
    pub device: DevicePublic,
    pub genesis: Vec<u8>,
    pub kem: HybridKemPublic,
    pub identity: IdentityVerifyingKey,
}

/// A fresh v2 account (dev KDF) on a temporary store: managed for `org`,
/// personal for `None`.
pub fn create(org: Option<ManagedGenesis>) -> Joiner {
    let dir = tempfile::tempdir().unwrap();
    let store = SqliteStore::open(&dir.path().join("vault.db")).unwrap();
    let keys = DeviceKeys::generate_software().unwrap();
    let kdf = KdfParams {
        m_kib: 8192,
        t: 1,
        p: 1,
        salt: random_array().unwrap(),
    };
    let (repo, _sk) = Repository::create_account_v2_with_org(
        store,
        PASSWORD,
        kdf,
        &keys,
        "iPhone de Camille",
        DeviceKind::Phone,
        DeviceMode::Personal,
        org,
    )
    .unwrap();
    let lineage = repo.store().list(RecordKind::Lineage).unwrap();
    assert_eq!(lineage.len(), 1);
    let genesis = lineage[0].data.clone();
    let LineageRecord::Genesis(g) = LineageRecord::decode(&genesis).unwrap() else {
        panic!("a genesis")
    };
    verify_genesis(&g).unwrap();
    let c = &g.body.creator;
    let device = DevicePublic {
        device_id: c.device_id,
        sign_pub: c.sign_pub.clone(),
        kem_pub: c.kem_pub.clone(),
    };
    assert_eq!(keys.public(c.device_id).unwrap(), device);
    Joiner {
        keys,
        device,
        genesis,
        kem: repo.account().params.kem_pub.clone(),
        identity: g.body.identity_pub.clone(),
    }
}

/// The standard org's id and accounts: owner O, admins A and B, user
/// manager U, provisioner P, plain member M.
pub const STD_ORG: OrgId = OrgId([7; 16]);
pub const ACC_O: u8 = 1;
pub const ACC_A: u8 = 2;
pub const ACC_U: u8 = 3;
pub const ACC_P: u8 = 4;
pub const ACC_M: u8 = 5;
pub const ACC_B: u8 = 6;

pub fn acct(a: u8) -> Id {
    Id([a; 16])
}

/// The standard org: one owner O (lineage at generation 0) and rosters
/// r1..r3 (`chain[i]` is seq `i + 1`): r1 founding by O, r2 O invites A
/// and B with {Admin}, U with {UserManager}, P with {Provisioner}, M with
/// no role, r3 O activates them (identity and KEM keys from the pools, one
/// device each).
pub struct StdOrg {
    pub o: TestDevice,
    pub a: TestDevice,
    pub b: TestDevice,
    pub u: TestDevice,
    pub p: TestDevice,
    pub m: TestDevice,
    pub genesis: SignedOrgRecord,
    pub lineage: OrgLineage,
    pub chain: Vec<SignedRoster>,
}

impl StdOrg {
    /// The device of account `a` (one of the `ACC_*`).
    pub fn dev(&self, a: u8) -> &TestDevice {
        match a {
            ACC_O => &self.o,
            ACC_A => &self.a,
            ACC_B => &self.b,
            ACC_U => &self.u,
            ACC_P => &self.p,
            ACC_M => &self.m,
            _ => panic!("no device for account {a}"),
        }
    }

    /// Roster `seq` of the chain.
    pub fn roster(&self, seq: usize) -> &RosterBody {
        &self.chain[seq - 1].body
    }
}

/// An Invited entry for account `a` (invitation nonce `[a; 32]`).
pub fn invited_member(org: OrgId, a: u8, roles: RoleSet) -> OrgMember {
    OrgMember {
        account_id: acct(a),
        account_identity_pub: None,
        scim_id_hash: [0; 32],
        invite_commit: invite_commit(org, acct(a), &[a; 32]),
        account_kem_hash: [0; 32],
        roles,
        state: MemberState::Invited,
        devices: vec![],
    }
}

/// `m` Active with the identity, KEM hash and devices of `r`.
pub fn activate_as(m: &mut OrgMember, r: &MemberRef) {
    m.state = MemberState::Active;
    m.account_identity_pub = Some(r.account_identity_pub.clone());
    m.account_kem_hash = member_kem_hash(&r.account_kem_pub);
    m.devices = r.devices.clone();
}

/// Inserts `m` in account order, or replaces the entry of its account.
pub fn upsert_member(body: &mut RosterBody, m: OrgMember) {
    match body
        .members
        .binary_search_by(|x| x.account_id.cmp(&m.account_id))
    {
        Ok(i) => body.members[i] = m,
        Err(i) => body.members.insert(i, m),
    }
}

/// `body` signed by `d`.
pub fn signed_by(body: RosterBody, d: &TestDevice) -> SignedRoster {
    sign_roster(body, &d.public, &d.keys).unwrap()
}

pub fn std_org() -> &'static StdOrg {
    static CELL: OnceLock<StdOrg> = OnceLock::new();
    CELL.get_or_init(|| {
        let (o, a, b, u, p, m) = (
            device(0x10),
            device(0x20),
            device(0x60),
            device(0x30),
            device(0x40),
            device(0x50),
        );
        let secrets = org_secrets();
        let genesis = sign_org_genesis(
            OrgGenesisBody {
                format: 1,
                org_id: STD_ORG,
                name: "Acme".to_string(),
                org_identity_pub: secrets.identity.verifying_key(),
                audit_kem_pub: secrets.audit.public().unwrap(),
                owners: vec![member_ref(ACC_O, &[&o])],
                created_at: 1_700_000_000,
            },
            &secrets.identity,
            &[(&o.public, &o.keys)],
        )
        .unwrap();
        let lineage = verify_org_genesis(&genesis).unwrap();
        let r1 = founding_roster(&lineage).unwrap();
        let mut r2 = r1.next().unwrap();
        let invites = [
            (ACC_A, Role::Admin),
            (ACC_B, Role::Admin),
            (ACC_U, Role::UserManager),
            (ACC_P, Role::Provisioner),
        ];
        for (acc, role) in invites {
            upsert_member(&mut r2, invited_member(STD_ORG, acc, RoleSet::of(&[role])));
        }
        upsert_member(&mut r2, invited_member(STD_ORG, ACC_M, RoleSet::EMPTY));
        let mut r3 = r2.next().unwrap();
        for (acc, d) in [
            (ACC_A, &a),
            (ACC_B, &b),
            (ACC_U, &u),
            (ACC_P, &p),
            (ACC_M, &m),
        ] {
            let e = r3
                .members
                .iter_mut()
                .find(|x| x.account_id == acct(acc))
                .unwrap();
            activate_as(e, &member_ref(acc, &[d]));
        }
        let chain = vec![signed_by(r1, &o), signed_by(r2, &o), signed_by(r3, &o)];
        accept_first_roster(&lineage, &chain).unwrap();
        StdOrg {
            o,
            a,
            b,
            u,
            p,
            m,
            genesis,
            lineage,
            chain,
        }
    })
}
