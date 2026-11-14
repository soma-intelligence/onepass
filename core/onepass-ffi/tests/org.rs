//! Organization types, fingerprint words and the join link format; create,
//! open, pin and verify an organisation over `FakeMailbox` (no TLS), and the
//! managed account genesis.

use onepass_ffi::{
    FfiOrgInvite, OnePassError, org_fingerprint_words, org_invite_encode, org_invite_parse,
    org_parse_dns_txt, org_parse_fingerprint,
};

const SERVER: &str = "https://mailbox.example.com/functions/v1/mailbox";
const LOOPBACK: &str = "http://127.0.0.1:54321/functions/v1/mailbox";

fn sample_invite() -> FfiOrgInvite {
    FfiOrgInvite {
        server_url: SERVER.into(),
        mailbox_id: "0a".repeat(16),
        org_id: "0b".repeat(16),
        account_id: "0c".repeat(16),
        fingerprint: vec![9u8; 32],
        nonce: vec![0xd1; 32],
        credential_seed: vec![0xe2; 32],
        member_token: vec![0xf3; 32],
        domain: Some("example.com".into()),
    }
}

/// The valid link with one query pair replaced (`None` drops it); a value
/// is spliced verbatim, so callers pass it already percent-encoded.
fn link_with(key: &str, value: Option<&str>) -> String {
    let link = org_invite_encode(sample_invite()).unwrap();
    let (base, query) = link.split_once('?').unwrap();
    let mut pairs: Vec<String> = query
        .split('&')
        .filter(|p| !p.starts_with(&format!("{key}=")))
        .map(str::to_owned)
        .collect();
    if let Some(v) = value {
        pairs.push(format!("{key}={v}"));
    }
    format!("{base}?{}", pairs.join("&"))
}

fn parse_with(key: &str, value: &str) -> Result<FfiOrgInvite, OnePassError> {
    org_invite_parse(link_with(key, Some(value)), false)
}

fn refused(r: Result<FfiOrgInvite, OnePassError>) -> bool {
    matches!(r, Err(OnePassError::InvalidInput { .. }))
}

#[test]
fn fingerprint_words_are_four_groups_of_five() {
    let w = org_fingerprint_words(vec![7u8; 32]).unwrap();
    assert_eq!(w.len(), 4);
    assert!(w.iter().all(|g| g.len() == 5));
}

#[test]
fn fingerprint_words_ignore_locale() {
    let w = org_fingerprint_words(vec![7u8; 32]).unwrap();
    assert_eq!(w, org_fingerprint_words(vec![7u8; 32]).unwrap());
    assert!(w.concat().iter().all(|w| w.is_ascii()));
    assert_ne!(w, org_fingerprint_words(vec![8u8; 32]).unwrap());
}

#[test]
fn fingerprint_words_refuse_wrong_length() {
    assert!(org_fingerprint_words(vec![0; 31]).is_err());
    assert!(org_fingerprint_words(vec![0; 33]).is_err());
}

#[test]
fn dns_and_mdm_texts_parse_to_the_same_fingerprint() {
    let fpr = [9u8; 32];
    let text = onepass_core::org::fingerprint_base32(&fpr);
    assert_eq!(
        org_parse_dns_txt(format!("v=op1; org={text}")).unwrap(),
        fpr
    );
    assert_eq!(org_parse_fingerprint(text.clone()).unwrap(), fpr);
    assert_eq!(org_parse_fingerprint(text.to_lowercase()).unwrap(), fpr);
    assert!(org_parse_fingerprint(text[1..].into()).is_err());
    assert!(org_parse_fingerprint(format!("{}1", &text[1..])).is_err());
}

#[test]
fn invite_round_trips() {
    let i = sample_invite();
    assert_eq!(
        org_invite_parse(org_invite_encode(i.clone()).unwrap(), false).unwrap(),
        i
    );
    let no_domain = FfiOrgInvite { domain: None, ..i };
    assert_eq!(
        org_invite_parse(org_invite_encode(no_domain.clone()).unwrap(), false).unwrap(),
        no_domain
    );
}

#[test]
fn invite_parse_refuses_http_server() {
    assert!(matches!(
        parse_with("s", "http%3A%2F%2Fa.example"),
        Err(OnePassError::InvalidInput { .. })
    ));
}

#[test]
fn invite_parse_refuses_missing_duplicate_and_unknown_keys() {
    for k in ["s", "m", "o", "a", "f", "n", "c", "t", "v"] {
        assert!(
            refused(org_invite_parse(link_with(k, None), false)),
            "missing {k}"
        );
    }
    let link = org_invite_encode(sample_invite()).unwrap();
    for k in ["m", "n", "t", "a", "d"] {
        let dup = format!("{link}&{k}=00");
        assert!(refused(org_invite_parse(dup, false)), "repeated {k}");
    }
    assert!(refused(org_invite_parse(format!("{link}&x=1"), false)));
}

#[test]
fn invite_parse_refuses_bad_lengths() {
    assert!(refused(parse_with("m", &"0a".repeat(15))));
    assert!(refused(parse_with("o", &"0b".repeat(17))));
    assert!(refused(parse_with("a", &"0c".repeat(15))));
    assert!(refused(parse_with("n", &"d1".repeat(16))));
    assert!(refused(parse_with("n", &"d1".repeat(33))));
    assert!(refused(parse_with("c", &"e2".repeat(31))));
    assert!(refused(parse_with("t", &"f3".repeat(31))));
    assert!(refused(parse_with("f", "NOTBASE32")));
    // Uppercase hex is refused: one spelling per link.
    assert!(refused(parse_with("m", &"0A".repeat(16))));
}

#[test]
fn invite_parse_refuses_other_scheme_host_or_version() {
    let link = org_invite_encode(sample_invite()).unwrap();
    let query = link.split_once('?').unwrap().1;
    for base in [
        "https://org/join",
        "onepass://item/join",
        "onepass://org/other",
        "onepass://org/join/",
        "onepass://org:1/join",
        "onepass://u@org/join",
    ] {
        assert!(refused(org_invite_parse(format!("{base}?{query}"), false)));
    }
    assert!(refused(org_invite_parse(format!("{link}#x"), false)));
    assert!(refused(parse_with("v", "2")));
}

#[test]
fn invite_parse_refuses_oversized_link() {
    let link = org_invite_encode(sample_invite()).unwrap();
    let big = format!("{link}&x={}", "a".repeat(2049 - link.len() - 3));
    assert_eq!(big.len(), 2049);
    assert!(refused(org_invite_parse(big, false)));
}

#[test]
fn invite_parse_refuses_bad_domain() {
    for d in [
        "Example.com",
        "example.com.",
        "a..b",
        "nodot",
        "-a.example.com",
        "a_b.example.com",
        &format!("{}.com", "a".repeat(64)),
        &format!("{}.com", vec!["a".repeat(60); 5].join(".")),
    ] {
        assert!(refused(parse_with("d", d)), "{d}");
    }
    assert!(parse_with("d", "sub.example-1.co").is_ok());
}

#[test]
fn loopback_http_only_when_allowed() {
    let enc = LOOPBACK.replace(':', "%3A").replace('/', "%2F");
    let link = link_with("s", Some(&enc));
    let got = org_invite_parse(link.clone(), true).unwrap();
    assert_eq!(got.server_url, LOOPBACK);
    assert!(refused(org_invite_parse(link, false)));
    // Only that exact URL.
    let other = "http%3A%2F%2F127.0.0.1%3A54322%2Ffunctions%2Fv1%2Fmailbox";
    assert!(refused(org_invite_parse(link_with("s", Some(other)), true)));
}

// ---- create, pin and verify (Task 2) -----------------------------------------------
// The test-only entry points (`publish_with_client`, `with_store`) exist
// with the `dev-fast-kdf` feature, as the test command enables.

#[cfg(feature = "dev-fast-kdf")]
mod lifecycle {
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    use onepass_core::device_keys::{DeviceKeys, DevicePublic, PqDeviceHalf, SoftwarePqHalf};
    use onepass_core::org::{Role, RoleSet, SignedRoster, invite_member, sign_roster};
    use onepass_ffi::{
        FfiDeviceKind, FfiDeviceMode, FfiKdfParams, FfiMemberState, FfiOrgCreated, FfiOrgRole,
        FfiPinSource, FfiPqDeviceHalf, OnePassError, OrgClient, OrgDraft, Session,
        create_account_v2, create_account_with_kdf, create_managed_account, device_public,
        generate_classical_device_keys, mailbox_generate_credential, managed_account_org,
        org_fingerprint_words,
    };
    use onepass_mailbox::testing::hostile_org::HostileOrgStore;
    use onepass_mailbox::testing::{FakeMailbox, FakeMailboxClient};
    use onepass_mailbox::{Credential, MailboxApi, OrgStore, OrgStoreApi};
    use tempfile::TempDir;

    const PASSWORD: &str = "Café-étoile";
    const FAST: FfiKdfParams = FfiKdfParams {
        m_kib: 8192,
        t: 1,
        p: 1,
    };
    const NOW: i64 = 1_800_000_000;
    const ORG_NAME: &str = "Soma Labs";

    struct Half(SoftwarePqHalf);

    impl FfiPqDeviceHalf for Half {
        fn mldsa_public(&self) -> Result<Vec<u8>, OnePassError> {
            self.0.mldsa_public().map_err(|_| OnePassError::Crypto)
        }

        fn mlkem_public(&self) -> Result<Vec<u8>, OnePassError> {
            self.0.mlkem_public().map_err(|_| OnePassError::Crypto)
        }

        fn mldsa_sign(&self, message: Vec<u8>) -> Result<Vec<u8>, OnePassError> {
            self.0
                .mldsa_sign(&message)
                .map_err(|_| OnePassError::Crypto)
        }

        fn mlkem_decapsulate(&self, ciphertext: Vec<u8>) -> Result<Vec<u8>, OnePassError> {
            Ok(self
                .0
                .mlkem_decapsulate(&ciphertext)
                .map_err(|_| OnePassError::Crypto)?
                .to_vec())
        }
    }

    struct Keys {
        classical: Vec<u8>,
        pq: Vec<u8>,
    }

    impl Keys {
        fn new() -> Keys {
            Keys {
                classical: generate_classical_device_keys().unwrap(),
                pq: SoftwarePqHalf::generate().unwrap().to_bytes().to_vec(),
            }
        }

        fn half(&self) -> Arc<dyn FfiPqDeviceHalf> {
            Arc::new(Half(SoftwarePqHalf::from_bytes(&self.pq).unwrap()))
        }

        /// The core's view of the same keys, to sign by hand what Task 3 will
        /// sign through the FFI.
        fn core(&self) -> DeviceKeys {
            DeviceKeys::new(
                &self.classical,
                Box::new(SoftwarePqHalf::from_bytes(&self.pq).unwrap()),
            )
            .unwrap()
        }
    }

    fn db_path(dir: &Path) -> String {
        dir.join("onepass.db").to_string_lossy().into_owned()
    }

    fn unhex<const N: usize>(s: &str) -> [u8; N] {
        let v: Vec<u8> = (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect();
        v.try_into().unwrap()
    }

    struct Owner {
        _dir: TempDir,
        session: Arc<Session>,
        keys: Keys,
    }

    impl Owner {
        /// A managed account of `org_id` with a fresh account id (the creator).
        fn new(org_id: &str) -> Owner {
            let dir = TempDir::new().unwrap();
            let keys = Keys::new();
            let created = create_managed_account(
                db_path(dir.path()),
                PASSWORD.as_bytes().to_vec(),
                Some(FAST),
                keys.classical.clone(),
                keys.half(),
                "Mac".into(),
                FfiDeviceKind::Mac,
                FfiDeviceMode::Personal,
                org_id.into(),
                None,
            )
            .unwrap();
            Owner {
                _dir: dir,
                session: created.session,
                keys,
            }
        }

        fn device(&self) -> DevicePublic {
            let id = self.session.this_device_id().unwrap();
            let bytes = device_public(self.keys.classical.clone(), self.keys.half(), id).unwrap();
            DevicePublic::decode(&bytes).unwrap()
        }
    }

    /// An org published on `fake` by a fresh owner; its creator's pin lives in
    /// `creator_dir`.
    struct Org {
        fake: FakeMailbox,
        owner: Owner,
        created: FfiOrgCreated,
        org_id: [u8; 16],
        _dirs: TempDir,
        creator_dir: PathBuf,
    }

    fn publish_draft(
        draft: &OrgDraft,
        fake: &FakeMailbox,
        owner: &Owner,
        state_dir: &Path,
    ) -> Result<FfiOrgCreated, OnePassError> {
        let cred = mailbox_generate_credential().unwrap();
        let client = fake.client(Credential::from_seed(&cred.seed).unwrap());
        draft.publish_with_client(
            Box::new(client),
            cred.seed,
            "org-invite".into(),
            owner.session.clone(),
            owner.keys.classical.clone(),
            owner.keys.half(),
            ORG_NAME.into(),
            state_dir.to_string_lossy().into_owned(),
            NOW,
        )
    }

    fn publish(fake: &FakeMailbox) -> Org {
        let draft = OrgDraft::new().unwrap();
        let owner = Owner::new(&draft.org_id());
        let dirs = TempDir::new().unwrap();
        let creator_dir = dirs.path().join("creator");
        let created = publish_draft(&draft, fake, &owner, &creator_dir).unwrap();
        Org {
            fake: fake.clone(),
            org_id: unhex(&draft.org_id()),
            owner,
            created,
            _dirs: dirs,
            creator_dir,
        }
    }

    impl Org {
        /// A client of the org mailbox with the creator's credential.
        fn client(&self) -> FakeMailboxClient {
            let mut c = self
                .fake
                .client(Credential::from_seed(&self.created.credential_seed).unwrap());
            c.open(unhex(&self.created.mailbox_id));
            c
        }

        fn store(&self) -> OrgStore<FakeMailboxClient> {
            OrgStore::new(self.client(), self.org_id)
        }

        fn hostile(&self) -> HostileOrgStore<OrgStore<FakeMailboxClient>> {
            HostileOrgStore::new(self.store())
        }

        fn open(&self, store: Box<dyn OrgStoreApi + Send>, dir: &Path) -> Arc<OrgClient> {
            OrgClient::with_store(store, self.org_id, dir.to_path_buf())
        }

        /// A second device of the org (fresh state dir) pinned TOFU from the
        /// link fingerprint.
        fn second_device(&self) -> (PathBuf, Arc<OrgClient>) {
            let dir = self._dirs.path().join("second");
            let client = self.open(Box::new(self.store()), &dir);
            client
                .pin(
                    FfiPinSource::Tofu { verified: false },
                    Some(self.created.state.fingerprint.clone()),
                    NOW,
                )
                .unwrap();
            (dir, client)
        }

        /// Roster seq 2 (an Invited member), signed by the owner's device.
        fn write_roster_2(&self) {
            let mut store = self.store();
            let one = SignedRoster::decode(&store.roster(1).unwrap().unwrap()).unwrap();
            let (next, _) = invite_member(&one.body, [0; 32], RoleSet::EMPTY).unwrap();
            let signed = sign_roster(next, &self.owner.device(), &self.owner.keys.core()).unwrap();
            store.put_roster(2, signed.encode()).unwrap();
        }
    }

    fn pin_bytes(dir: &Path) -> Vec<u8> {
        std::fs::read(dir.join("pin.bin")).unwrap()
    }

    fn integrity(kind: &str) -> OnePassError {
        OnePassError::Integrity { kind: kind.into() }
    }

    #[test]
    fn managed_account_names_its_org() {
        let org_id = "ab".repeat(16);
        let dir = TempDir::new().unwrap();
        let keys = Keys::new();
        let account_id = "cd".repeat(16);
        let created = create_managed_account(
            db_path(dir.path()),
            PASSWORD.as_bytes().to_vec(),
            Some(FAST),
            keys.classical.clone(),
            keys.half(),
            "Mac".into(),
            FfiDeviceKind::Mac,
            FfiDeviceMode::Personal,
            org_id.clone(),
            Some(account_id.clone()),
        )
        .unwrap();
        assert_eq!(created.account_id, account_id);
        assert_eq!(
            managed_account_org(db_path(dir.path())).unwrap(),
            Some(org_id.clone())
        );
        // Locked: still readable (the launch screen reads it before unlock).
        created.session.lock();
        assert_eq!(
            managed_account_org(db_path(dir.path())).unwrap(),
            Some(org_id)
        );
    }

    #[test]
    fn managed_account_refuses_bad_ids() {
        let dir = TempDir::new().unwrap();
        let keys = Keys::new();
        let make = |org: &str, account: Option<&str>| {
            create_managed_account(
                db_path(dir.path()),
                PASSWORD.as_bytes().to_vec(),
                Some(FAST),
                keys.classical.clone(),
                keys.half(),
                "Mac".into(),
                FfiDeviceKind::Mac,
                FfiDeviceMode::Personal,
                org.into(),
                account.map(str::to_owned),
            )
        };
        assert!(make("ab", None).is_err());
        assert!(make(&"ab".repeat(16), Some("cd")).is_err());
        assert_eq!(managed_account_org(db_path(dir.path())).unwrap(), None);
    }

    #[test]
    fn personal_account_has_no_org() {
        let dir = TempDir::new().unwrap();
        let keys = Keys::new();
        create_account_v2(
            db_path(dir.path()),
            PASSWORD.into(),
            Some(FAST),
            keys.classical.clone(),
            keys.half(),
            "Mac".into(),
            FfiDeviceKind::Mac,
            FfiDeviceMode::Personal,
        )
        .unwrap();
        assert_eq!(managed_account_org(db_path(dir.path())).unwrap(), None);

        let legacy = TempDir::new().unwrap();
        create_account_with_kdf(db_path(legacy.path()), PASSWORD.into(), FAST).unwrap();
        assert_eq!(managed_account_org(db_path(legacy.path())).unwrap(), None);
    }

    #[test]
    fn creator_holds_a_verified_pin_and_the_founding_roster() {
        let org = publish(&FakeMailbox::org());
        let s = &org.created.state;
        assert_eq!(s.name, ORG_NAME);
        assert_eq!(s.source, FfiPinSource::Tofu { verified: true });
        assert_eq!(s.roster_seq, 1);
        assert_eq!(s.lineage_generation, 0);
        assert_eq!(s.owners, vec![org.owner.session.account_id()]);
        assert_eq!(s.members.len(), 1);
        let m = &s.members[0];
        assert_eq!(m.account_id, org.owner.session.account_id());
        assert_eq!(m.roles, vec![FfiOrgRole::Owner]);
        assert_eq!(m.state, FfiMemberState::Active);
        assert_eq!(m.display_name, None);
        assert!(!m.former_owner);
        assert_eq!(m.devices.len(), 1);
        assert_eq!(m.devices[0].fingerprint.len(), 64);
        assert_eq!(org.created.credential_seed.len(), 32);
        // The pin on disk says the same.
        let reopened = org.open(Box::new(org.store()), &org.creator_dir);
        assert_eq!(reopened.state().unwrap().as_ref(), Some(s));
        // The owner keyset is stored for the creator.
        let mut store = org.store();
        let owner_id: [u8; 16] = unhex(&org.owner.session.account_id());
        assert!(store.owner_keyset(owner_id).unwrap().is_some());
    }

    #[test]
    fn create_then_second_device_pins_tofu() {
        let org = publish(&FakeMailbox::org());
        let (_, second) = org.second_device();
        let s = second.state().unwrap().unwrap();
        assert_eq!(s.name, ORG_NAME);
        assert_eq!(s.source, FfiPinSource::Tofu { verified: false });
        assert_eq!(s.roster_seq, 1);
        assert_eq!(s.members.len(), 1);
        assert_eq!(s.members[0].roles, vec![FfiOrgRole::Owner]);
        assert_eq!(s.fingerprint, org.created.state.fingerprint);
        assert_eq!(
            s.fingerprint_words,
            org_fingerprint_words(org.created.state.fingerprint.clone()).unwrap()
        );
        assert_eq!(s.dns_value, org.created.state.dns_value);
        assert!(s.dns_value.starts_with("v=op1; org="));
    }

    #[test]
    fn dns_and_mdm_pins_take_the_expected_fingerprint() {
        let org = publish(&FakeMailbox::org());
        let fpr = org.created.state.fingerprint.clone();
        for (name, source) in [("dns", FfiPinSource::Dns), ("mdm", FfiPinSource::Mdm)] {
            let dir = org._dirs.path().join(name);
            let client = org.open(Box::new(org.store()), &dir);
            assert_eq!(client.pin(source, None, NOW), Err(validation_expected()));
            assert_eq!(
                client.pin(source, Some(vec![1; 32]), NOW),
                Err(OnePassError::OrgPinMismatch)
            );
            assert_eq!(
                client.pin(source, Some(fpr.clone()), NOW).unwrap().source,
                source
            );
        }
    }

    fn validation_expected() -> OnePassError {
        OnePassError::Validation {
            field: "expected_fpr".into(),
            reason: "MDM and DNS pins need a fingerprint".into(),
        }
    }

    #[test]
    fn pin_refuses_an_unexpected_fingerprint() {
        let org = publish(&FakeMailbox::org());
        let dir = org._dirs.path().join("second");
        let client = org.open(Box::new(org.store()), &dir);
        assert_eq!(
            client.pin(
                FfiPinSource::Tofu { verified: false },
                Some(vec![1; 32]),
                NOW
            ),
            Err(OnePassError::OrgPinMismatch)
        );
        assert_eq!(client.state().unwrap(), None);
        assert!(!dir.join("pin.bin").exists());
    }

    #[test]
    fn pin_refuses_another_org_in_the_mailbox() {
        let org = publish(&FakeMailbox::org());
        let dir = org._dirs.path().join("second");
        // The client expects org id [7; 16]; the mailbox holds another org.
        let client = OrgClient::with_store(Box::new(org.store()), [7; 16], dir.clone());
        assert_eq!(
            client.pin(FfiPinSource::Tofu { verified: false }, None, NOW),
            Err(integrity("wrong_context"))
        );
        assert!(!dir.join("pin.bin").exists());
    }

    #[test]
    fn pinned_identity_never_follows_a_new_genesis() {
        let fake = FakeMailbox::org();
        let org = publish(&fake);
        let (dir, second) = org.second_device();
        let before = second.state().unwrap();
        // Another validly signed genesis (another org, its own identity key):
        // what a server holding no org secret can serve at generation 0.
        let other = publish(&fake);
        let other_genesis = other.store().lineage_from(0).unwrap().remove(0).1;
        let mut hostile = org.hostile();
        hostile.fork_lineage(0, other_genesis);
        let client = org.open(Box::new(hostile), &dir);
        assert_eq!(client.refresh(), Err(OnePassError::OrgPinMismatch));
        assert_eq!(client.state().unwrap(), before);
        // A server withholding the pinned generation: a rollback.
        let mut hostile = org.hostile();
        hostile.withhold_lineage_from(0);
        let client = org.open(Box::new(hostile), &dir);
        assert_eq!(client.refresh(), Err(integrity("org_lineage_rollback")));
        assert_eq!(client.state().unwrap(), before);
    }

    #[test]
    fn refresh_follows_a_new_roster() {
        let org = publish(&FakeMailbox::org());
        let (_, second) = org.second_device();
        org.write_roster_2();
        let s = second.refresh().unwrap();
        assert_eq!(s.roster_seq, 2);
        assert_eq!(s.members.len(), 2);
        assert!(
            s.members
                .iter()
                .any(|m| m.state == FfiMemberState::Invited && m.roles.is_empty())
        );
        assert_eq!(second.state().unwrap(), Some(s));
    }

    #[test]
    fn withheld_or_replayed_roster_never_rolls_back() {
        let org = publish(&FakeMailbox::org());
        let (dir, second) = org.second_device();
        org.write_roster_2();
        assert_eq!(second.refresh().unwrap().roster_seq, 2);

        let mut hostile = org.hostile();
        hostile.replay_roster(1);
        let client = org.open(Box::new(hostile), &dir);
        assert_eq!(client.refresh(), Err(integrity("org_roster_rollback")));
        assert_eq!(client.state().unwrap().unwrap().roster_seq, 2);

        let mut hostile = org.hostile();
        hostile.withhold_newest_roster();
        let client = org.open(Box::new(hostile), &dir);
        assert_eq!(client.refresh(), Err(integrity("org_roster_rollback")));
        assert_eq!(client.state().unwrap().unwrap().roster_seq, 2);
    }

    #[test]
    fn forked_roster_is_refused() {
        let org = publish(&FakeMailbox::org());
        let (dir, _) = org.second_device();
        // Another seq 1, signed by the owner's device: the owner made Admin too.
        let one = SignedRoster::decode(&org.store().roster(1).unwrap().unwrap()).unwrap();
        let mut body = one.body.clone();
        body.members[0].roles = RoleSet::of(&[Role::Owner, Role::Admin]);
        let fork = sign_roster(body, &org.owner.device(), &org.owner.keys.core()).unwrap();
        let mut hostile = org.hostile();
        hostile.fork_roster(1, fork.encode());
        let client = org.open(Box::new(hostile), &dir);
        assert_eq!(client.refresh(), Err(integrity("org_roster_fork")));
        assert_eq!(
            client.state().unwrap().unwrap().members[0].roles,
            vec![FfiOrgRole::Owner]
        );
    }

    #[test]
    fn mark_verified_turns_tofu_into_verified_and_persists() {
        let org = publish(&FakeMailbox::org());
        let (dir, second) = org.second_device();
        let s = second.mark_verified().unwrap();
        assert_eq!(s.source, FfiPinSource::Tofu { verified: true });
        let reopened = org.open(Box::new(org.store()), &dir);
        assert_eq!(
            reopened.state().unwrap().unwrap().source,
            FfiPinSource::Tofu { verified: true }
        );
        // Refresh keeps the verification.
        assert_eq!(
            reopened.refresh().unwrap().source,
            FfiPinSource::Tofu { verified: true }
        );
    }

    #[test]
    fn mark_verified_and_refresh_need_a_pin() {
        let org = publish(&FakeMailbox::org());
        let client = org.open(Box::new(org.store()), &org._dirs.path().join("none"));
        assert_eq!(client.state().unwrap(), None);
        assert_eq!(client.refresh(), Err(OnePassError::NotFound));
        assert_eq!(client.mark_verified(), Err(OnePassError::NotFound));
    }

    #[test]
    fn draft_publishes_once() {
        let fake = FakeMailbox::org();
        let draft = OrgDraft::new().unwrap();
        let owner = Owner::new(&draft.org_id());
        let dirs = TempDir::new().unwrap();
        publish_draft(&draft, &fake, &owner, &dirs.path().join("a")).unwrap();
        assert!(matches!(
            publish_draft(&draft, &fake, &owner, &dirs.path().join("b")),
            Err(OnePassError::InvalidInput { .. })
        ));
    }

    #[test]
    fn publish_needs_a_managed_account_of_this_org() {
        let fake = FakeMailbox::org();
        let draft = OrgDraft::new().unwrap();
        let stranger = Owner::new(&"ab".repeat(16));
        let dirs = TempDir::new().unwrap();
        assert!(matches!(
            publish_draft(&draft, &fake, &stranger, dirs.path()),
            Err(OnePassError::Validation { .. })
        ));
        assert!(!dirs.path().join("pin.bin").exists());
    }

    #[test]
    fn pin_file_unchanged_after_a_refused_refresh() {
        let org = publish(&FakeMailbox::org());
        let (dir, second) = org.second_device();
        org.write_roster_2();
        second.refresh().unwrap();
        let before = pin_bytes(&dir);
        let mut hostile = org.hostile();
        hostile.replay_roster(1);
        let client = org.open(Box::new(hostile), &dir);
        assert!(client.refresh().is_err());
        assert_eq!(pin_bytes(&dir), before);
    }

    #[cfg(unix)]
    #[test]
    fn pin_folder_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let org = publish(&FakeMailbox::org());
        let mode = std::fs::metadata(&org.creator_dir)
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700);
    }
}
