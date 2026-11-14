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
    use std::sync::atomic::{AtomicBool, Ordering};

    use onepass_mailbox::org::{JoinFeedDelta, JoinRequest, ORG_ROSTER_KIND};
    use onepass_mailbox::{
        ChangeFeed, Credential, CredentialKey, FeedPage, MailboxApi, MailboxError, OrgStore,
        OrgStoreApi, OrgStoreError,
    };
    use onepass_mailbox_proto::{
        Body, ChangesPage, ChildKind, CommitOp, CommitResponse, CredentialId, CredentialRole,
        MailboxCreated, MailboxId, MailboxInfo, PushKind, ServerConfig, ServerRecord,
        SignedEnrollTicket,
    };
    use tempfile::TempDir;

    const PASSWORD: &str = "Café-étoile";
    const FAST: FfiKdfParams = FfiKdfParams {
        m_kib: 8192,
        t: 1,
        p: 1,
    };
    const NOW: i64 = 1_800_000_000;
    const ORG_NAME: &str = "Soma Labs";
    /// The org mailbox server the clients name in their join links.
    use super::SERVER as SERVER_URL;

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
            OrgClient::with_store(store, self.org_id, dir.to_path_buf(), SERVER_URL.into())
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

        /// Roster `seq` (one more Invited member), signed by the owner's device.
        fn write_roster(&self, seq: u64) {
            let mut store = self.store();
            let prev = SignedRoster::decode(&store.roster(seq - 1).unwrap().unwrap()).unwrap();
            let (next, _) = invite_member(&prev.body, [0; 32], RoleSet::EMPTY).unwrap();
            let signed = sign_roster(next, &self.owner.device(), &self.owner.keys.core()).unwrap();
            store.put_roster(seq, signed.encode()).unwrap();
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
        let client = OrgClient::with_store(
            Box::new(org.store()),
            [7; 16],
            dir.clone(),
            SERVER_URL.into(),
        );
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
        org.write_roster(2);
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
        org.write_roster(2);
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
        org.write_roster(2);
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

    // ---- fix round 1: resumed publish, pin races, withheld rosters -----------------

    /// A mailbox client that fails the first commit writing a roster.
    struct FailRoster {
        inner: FakeMailboxClient,
        armed: AtomicBool,
    }

    impl FailRoster {
        fn fault(&self, ops: &[CommitOp]) -> Result<(), MailboxError> {
            if ops.iter().any(|o| o.kind == ORG_ROSTER_KIND)
                && self.armed.swap(false, Ordering::SeqCst)
            {
                return Err(MailboxError::Malformed("test fault"));
            }
            Ok(())
        }
    }

    impl MailboxApi for FailRoster {
        fn server_config(&self) -> Result<ServerConfig, MailboxError> {
            self.inner.server_config()
        }

        fn create(
            &mut self,
            invite: Option<&[u8]>,
            label: &[u8],
        ) -> Result<MailboxCreated, MailboxError> {
            self.inner.create(invite, label)
        }

        fn open(&mut self, mailbox: MailboxId) {
            self.inner.open(mailbox)
        }

        fn mailbox(&self) -> Option<MailboxId> {
            self.inner.mailbox()
        }

        fn credential_key(&self) -> CredentialKey {
            self.inner.credential_key()
        }

        fn info(&self) -> Result<MailboxInfo, MailboxError> {
            self.inner.info()
        }

        fn changes(&self, after: u64, limit: u32, full: bool) -> Result<ChangesPage, MailboxError> {
            self.inner.changes(after, limit, full)
        }

        fn next_changes(
            &self,
            feed: &mut ChangeFeed,
            limit: u32,
        ) -> Result<FeedPage, MailboxError> {
            self.inner.next_changes(feed, limit)
        }

        fn commit(&self, ops: Vec<CommitOp>) -> Result<CommitResponse, MailboxError> {
            self.fault(&ops)?;
            self.inner.commit(ops)
        }

        fn record(&self, kind: u8, id: [u8; 16]) -> Result<Option<ServerRecord>, MailboxError> {
            self.inner.record(kind, id)
        }

        fn enroll(
            &mut self,
            ticket: &SignedEnrollTicket,
            label: &[u8],
        ) -> Result<(), MailboxError> {
            self.inner.enroll(ticket, label)
        }

        fn revoke(&self, credential: CredentialId) -> Result<(), MailboxError> {
            self.inner.revoke(credential)
        }

        fn grant(
            &self,
            public_key: [u8; 32],
            role: CredentialRole,
            put_kinds: Option<[u8; 32]>,
            label: &[u8],
        ) -> Result<CredentialId, MailboxError> {
            self.inner.grant(public_key, role, put_kinds, label)
        }

        fn set_role(
            &self,
            credential: CredentialId,
            role: CredentialRole,
            put_kinds: Option<[u8; 32]>,
        ) -> Result<(), MailboxError> {
            self.inner.set_role(credential, role, put_kinds)
        }

        fn set_push(&self, kind: PushKind, token: &[u8]) -> Result<(), MailboxError> {
            self.inner.set_push(kind, token)
        }

        fn set_push_target(
            &self,
            tag: [u8; 16],
            kind: PushKind,
            token: &[u8],
        ) -> Result<(), MailboxError> {
            self.inner.set_push_target(tag, kind, token)
        }

        fn set_locator(&self, locator: [u8; 16]) -> Result<(), MailboxError> {
            self.inner.set_locator(locator)
        }

        fn abandon(&self) -> Result<(), MailboxError> {
            self.inner.abandon()
        }

        fn create_child(
            &self,
            kind: ChildKind,
            owner_public_key: [u8; 32],
            label: &[u8],
        ) -> Result<MailboxCreated, MailboxError> {
            self.inner.create_child(kind, owner_public_key, label)
        }

        fn create_org_invite(&self, uses: u16, ttl_hours: u16) -> Result<Vec<u8>, MailboxError> {
            self.inner.create_org_invite(uses, ttl_hours)
        }

        fn issue_ticket(
            &self,
            new_credential_pub: CredentialKey,
            now: i64,
        ) -> Result<SignedEnrollTicket, MailboxError> {
            self.inner.issue_ticket(new_credential_pub, now)
        }

        fn upload_blobs(&self, blobs: &[&[u8]]) -> Result<(), MailboxError> {
            self.inner.upload_blobs(blobs)
        }

        fn fetch_body(&self, body: &Body) -> Result<Vec<u8>, MailboxError> {
            self.inner.fetch_body(body)
        }

        fn commit_with_blobs(
            &self,
            ops: Vec<CommitOp>,
            blobs: &[&[u8]],
        ) -> Result<CommitResponse, MailboxError> {
            self.fault(&ops)?;
            self.inner.commit_with_blobs(ops, blobs)
        }
    }

    type Hook = Box<dyn FnOnce() + Send>;

    /// An org store that hides one roster seq and runs `hook` once when
    /// `latest_roster` is asked (another client acting meanwhile).
    struct Tweaked {
        inner: OrgStore<FakeMailboxClient>,
        hide: Option<u64>,
        hook: Option<Hook>,
        /// One entry per `join_requests_since` call: did it start from a
        /// full feed. A `join_requests` call (the whole feed) logs `None`.
        feeds: Arc<std::sync::Mutex<Vec<Option<bool>>>>,
        /// `create_member_invite` fails.
        fail_mint: bool,
        /// Runs once when `create_member_invite` is asked.
        on_mint: Option<Hook>,
        /// The next `taken` roster puts answer `Taken` (nothing written).
        taken: u32,
    }

    impl OrgStoreApi for Tweaked {
        fn put_lineage(&mut self, generation: u64, bytes: Vec<u8>) -> Result<(), OrgStoreError> {
            self.inner.put_lineage(generation, bytes)
        }

        fn lineage_from(&mut self, generation: u64) -> Result<Vec<(u64, Vec<u8>)>, OrgStoreError> {
            self.inner.lineage_from(generation)
        }

        fn put_roster(&mut self, seq: u64, bytes: Vec<u8>) -> Result<(), OrgStoreError> {
            if self.taken > 0 {
                self.taken -= 1;
                return Err(OrgStoreError::Taken);
            }
            self.inner.put_roster(seq, bytes)
        }

        fn roster(&mut self, seq: u64) -> Result<Option<Vec<u8>>, OrgStoreError> {
            if self.hide == Some(seq) {
                return Ok(None);
            }
            self.inner.roster(seq)
        }

        fn latest_roster(&mut self) -> Result<Option<(u64, Vec<u8>)>, OrgStoreError> {
            if let Some(hook) = self.hook.take() {
                hook();
            }
            self.inner.latest_roster()
        }

        fn put_owner_keyset(
            &mut self,
            account_id: [u8; 16],
            bytes: Vec<u8>,
        ) -> Result<(), OrgStoreError> {
            self.inner.put_owner_keyset(account_id, bytes)
        }

        fn owner_keyset(&mut self, account_id: [u8; 16]) -> Result<Option<Vec<u8>>, OrgStoreError> {
            self.inner.owner_keyset(account_id)
        }

        fn put_join_request(
            &mut self,
            account_id: [u8; 16],
            bytes: Vec<u8>,
        ) -> Result<(), OrgStoreError> {
            self.inner.put_join_request(account_id, bytes)
        }

        fn join_requests(&mut self) -> Result<Vec<JoinRequest>, OrgStoreError> {
            self.feeds.lock().unwrap().push(None);
            self.inner.join_requests()
        }

        fn join_requests_since(
            &mut self,
            feed: &mut ChangeFeed,
        ) -> Result<JoinFeedDelta, OrgStoreError> {
            self.feeds.lock().unwrap().push(Some(feed.is_full()));
            self.inner.join_requests_since(feed)
        }

        fn delete_join_request(&mut self, account_id: [u8; 16]) -> Result<(), OrgStoreError> {
            self.inner.delete_join_request(account_id)
        }

        fn mailbox(&self) -> &dyn MailboxApi {
            self.inner.mailbox()
        }

        fn create_member_invite(&mut self, ttl_hours: u16) -> Result<Vec<u8>, OrgStoreError> {
            if let Some(hook) = self.on_mint.take() {
                hook();
            }
            if self.fail_mint {
                return Err(MailboxError::Malformed("test mint fault").into());
            }
            self.inner.create_member_invite(ttl_hours)
        }
    }

    impl Org {
        fn tweaked(&self, hide: Option<u64>, hook: Option<Hook>) -> Box<dyn OrgStoreApi + Send> {
            Box::new(Tweaked {
                inner: self.store(),
                hide,
                hook,
                feeds: Default::default(),
                fail_mint: false,
                on_mint: None,
                taken: 0,
            })
        }
    }

    #[test]
    fn publish_resumes_after_a_failed_write() {
        let fake = FakeMailbox::org();
        let draft = OrgDraft::new().unwrap();
        let owner = Owner::new(&draft.org_id());
        let dirs = TempDir::new().unwrap();
        let state_dir = dirs.path().join("creator");
        let cred = mailbox_generate_credential().unwrap();
        let client = FailRoster {
            inner: fake.client(Credential::from_seed(&cred.seed).unwrap()),
            armed: AtomicBool::new(true),
        };
        let first = draft.publish_with_client(
            Box::new(client),
            cred.seed.clone(),
            "org-invite".into(),
            owner.session.clone(),
            owner.keys.classical.clone(),
            owner.keys.half(),
            ORG_NAME.into(),
            state_dir.to_string_lossy().into_owned(),
            NOW,
        );
        assert!(
            matches!(first, Err(OnePassError::MailboxUnavailable { .. })),
            "{first:?}"
        );
        assert!(!state_dir.join("pin.bin").exists());
        // Resumed: the client passed now is never used (no second mailbox).
        let created = publish_draft(&draft, &fake, &owner, &state_dir).unwrap();
        assert_eq!(created.credential_seed, cred.seed);
        assert_eq!(created.state.roster_seq, 1);
        assert_eq!(created.state.source, FfiPinSource::Tofu { verified: true });
        let org = Org {
            fake: fake.clone(),
            org_id: unhex(&draft.org_id()),
            owner,
            created,
            _dirs: dirs,
            creator_dir: state_dir,
        };
        let mut store = org.store();
        assert!(store.roster(1).unwrap().is_some());
        let owner_id: [u8; 16] = unhex(&org.owner.session.account_id());
        assert!(store.owner_keyset(owner_id).unwrap().is_some());
        let (_, second) = org.second_device();
        assert_eq!(
            second.state().unwrap().unwrap().fingerprint,
            org.created.state.fingerprint
        );
        // Finished: used.
        assert!(matches!(
            publish_draft(&draft, &fake, &org.owner, &org._dirs.path().join("again")),
            Err(OnePassError::InvalidInput { .. })
        ));
    }

    #[test]
    fn refresh_never_writes_over_a_newer_pin() {
        let org = publish(&FakeMailbox::org());
        let (dir, _) = org.second_device();
        org.write_roster(2);
        let other = org.open(Box::new(org.store()), &dir);
        // While this client fetches, another one on the same folder marks the
        // pin verified: the unverified result must not land over it.
        let hook: Hook = Box::new(move || {
            other.mark_verified().unwrap();
        });
        let client = org.open(org.tweaked(None, Some(hook)), &dir);
        assert_eq!(client.refresh(), Err(OnePassError::Conflict));
        let s = client.state().unwrap().unwrap();
        assert_eq!(s.source, FfiPinSource::Tofu { verified: true });
        assert_eq!(s.roster_seq, 1);
        // Again, from what is stored now.
        let s = client.refresh().unwrap();
        assert_eq!(s.roster_seq, 2);
        assert_eq!(s.source, FfiPinSource::Tofu { verified: true });
    }

    #[test]
    fn withheld_middle_roster_is_a_rollback() {
        let org = publish(&FakeMailbox::org());
        let (dir, _) = org.second_device();
        org.write_roster(2);
        org.write_roster(3);
        let before = pin_bytes(&dir);
        let client = org.open(org.tweaked(Some(2), None), &dir);
        assert_eq!(client.refresh(), Err(integrity("org_roster_rollback")));
        assert_eq!(pin_bytes(&dir), before);
    }

    // ---- invitations and join requests (Task 3) ------------------------------------

    use onepass_core::org::{
        JoinRequestBody, SignedJoinRequest, activate_member, sign_join_request, verify_join_request,
    };
    use onepass_ffi::{
        FfiInviteLink, FfiJoinPosted, FfiJoinRequest, FfiOrgInvite, org_invite_parse,
    };

    const DOMAIN: &str = "somalabs.me";
    const MARIE: &str = "Marie Dupont";

    impl Org {
        /// The creator's own client (its pin is in `creator_dir`).
        fn creator(&self) -> Arc<OrgClient> {
            self.open(Box::new(self.store()), &self.creator_dir)
        }

        /// An invitation by the owner's device, with its parsed link.
        fn invite(&self, label: &str, roles: Vec<FfiOrgRole>) -> (FfiInviteLink, FfiOrgInvite) {
            let link = self
                .creator()
                .create_invite(
                    self.owner.session.clone(),
                    self.owner.keys.classical.clone(),
                    self.owner.keys.half(),
                    label.into(),
                    Some(DOMAIN.into()),
                    roles,
                    NOW,
                )
                .unwrap();
            let invite = org_invite_parse(link.link.clone(), false).unwrap();
            (link, invite)
        }

        /// A client of the org mailbox holding the invite credential.
        fn invite_store(&self, invite: &FfiOrgInvite) -> OrgStore<FakeMailboxClient> {
            let mut c = self
                .fake
                .client(Credential::from_seed(&invite.credential_seed).unwrap());
            c.open(unhex(&invite.mailbox_id));
            OrgStore::new(c, self.org_id)
        }

        /// The device that follows an invite: an org client with the invite
        /// credential, pinned TOFU against the link's fingerprint, and the
        /// managed account of the invited account id.
        fn joiner(&self, invite: &FfiOrgInvite) -> Joiner {
            let dir = TempDir::new().unwrap();
            let client = OrgClient::with_store(
                Box::new(self.invite_store(invite)),
                self.org_id,
                dir.path().join("org"),
                SERVER_URL.into(),
            );
            client
                .pin(
                    FfiPinSource::Tofu { verified: false },
                    Some(invite.fingerprint.clone()),
                    NOW,
                )
                .unwrap();
            let keys = Keys::new();
            let created = create_managed_account(
                db_path(dir.path()),
                PASSWORD.as_bytes().to_vec(),
                Some(FAST),
                keys.classical.clone(),
                keys.half(),
                "iPhone".into(),
                FfiDeviceKind::Phone,
                FfiDeviceMode::Personal,
                invite.org_id.clone(),
                Some(invite.account_id.clone()),
            )
            .unwrap();
            Joiner {
                _dir: dir,
                session: created.session,
                keys,
                client,
            }
        }

        /// The raw join requests in the mailbox.
        fn raw_requests(&self) -> Vec<([u8; 16], Vec<u8>)> {
            self.store().join_requests().unwrap()
        }
    }

    struct Joiner {
        _dir: TempDir,
        session: Arc<Session>,
        keys: Keys,
        client: Arc<OrgClient>,
    }

    impl Joiner {
        fn post(&self, invite: &FfiOrgInvite, name: &str) -> Result<FfiJoinPosted, OnePassError> {
            self.client.post_join_request(
                self.session.clone(),
                self.keys.classical.clone(),
                self.keys.half(),
                invite.clone(),
                name.into(),
                NOW,
            )
        }
    }

    #[test]
    fn invite_link_parses_to_this_org() {
        let org = publish(&FakeMailbox::org());
        let (link, invite) = org.invite("Marie", vec![]);
        assert_eq!(invite.server_url, SERVER_URL);
        assert_eq!(invite.org_id, hex(&org.org_id));
        assert_eq!(invite.mailbox_id, org.created.mailbox_id);
        assert_eq!(invite.fingerprint, org.created.state.fingerprint);
        assert_eq!(invite.domain.as_deref(), Some(DOMAIN));
        assert_eq!(invite.account_id, link.account_id);
        assert_eq!(invite.nonce.len(), 32);
        assert_eq!(invite.member_token.len(), 32);
        assert_ne!(invite.credential_seed, org.created.credential_seed);
        // The roster moved to seq 2 with the Invited member, no role.
        let s = org.creator().state().unwrap().unwrap();
        assert_eq!(s.roster_seq, 2);
        let m = s
            .members
            .iter()
            .find(|m| m.account_id == link.account_id)
            .unwrap();
        assert_eq!(m.state, FfiMemberState::Invited);
        assert!(m.roles.is_empty());
        // Roles given at invitation sit in the roster.
        let (admin, _) = org.invite("Paul", vec![FfiOrgRole::Admin]);
        let s = org.creator().state().unwrap().unwrap();
        assert_eq!(s.roster_seq, 3);
        let m = s
            .members
            .iter()
            .find(|m| m.account_id == admin.account_id)
            .unwrap();
        assert_eq!(m.roles, vec![FfiOrgRole::Admin]);
        // The invite file keeps neither the credential seed nor the token.
        let local = std::fs::read(org.creator_dir.join("invites.bin")).unwrap();
        let holds = |needle: &[u8]| local.windows(needle.len()).any(|w| w == needle);
        assert!(holds(&unhex::<16>(&link.account_id)));
        assert!(!holds(&invite.credential_seed));
        assert!(!holds(&invite.member_token));
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn joiner_reads_with_the_invite_credential_and_posts_once() {
        let org = publish(&FakeMailbox::org());
        let (_, invite) = org.invite("Marie", vec![]);
        let joiner = org.joiner(&invite);
        // The joiner pinned the org and sees itself Invited.
        let s = joiner.client.state().unwrap().unwrap();
        assert_eq!(s.fingerprint, invite.fingerprint);
        assert!(
            s.members
                .iter()
                .any(|m| m.account_id == invite.account_id && m.state == FfiMemberState::Invited)
        );
        let posted = joiner.post(&invite, MARIE).unwrap();
        let words = posted.code_words.clone();
        assert_eq!(words.len(), 5);
        // R27: the request names the member's own credential, not the link's.
        let req = SignedJoinRequest::decode(&org.raw_requests()[0].1).unwrap();
        let link_key = Credential::from_seed(&invite.credential_seed)
            .unwrap()
            .public_key();
        let own_key = Credential::from_seed(&posted.credential_seed)
            .unwrap()
            .public_key();
        assert_ne!(req.body.mailbox_credential, link_key.to_bytes());
        assert_eq!(req.body.mailbox_credential, own_key.to_bytes());
        let got = org.creator().join_requests().unwrap();
        assert_eq!(
            got,
            vec![FfiJoinRequest {
                account_id: invite.account_id.clone(),
                display_name: MARIE.into(),
                devices: got[0].devices.clone(),
                code_words: words.clone(),
                issued_here: true,
                invite_label: Some("Marie".into()),
                in_roster: false,
            }]
        );
        assert_eq!(got[0].devices.len(), 1);
        assert_eq!(got[0].devices[0].fingerprint.len(), 64);
        // Posting again rewrites the one request.
        joiner.post(&invite, MARIE).unwrap();
        assert_eq!(org.raw_requests().len(), 1);
        assert_eq!(org.creator().join_requests().unwrap().len(), 1);
        // Another device of the org did not issue it.
        let (_, second) = org.second_device();
        second.refresh().unwrap();
        let other = second.join_requests().unwrap();
        assert_eq!(other.len(), 1);
        assert!(!other[0].issued_here);
        assert_eq!(other[0].invite_label, None);
        // Names come from the verified request, read by refresh itself (R28).
        let state_named = org.creator().refresh().unwrap();
        assert_eq!(
            state_named
                .members
                .iter()
                .find(|m| m.account_id == invite.account_id)
                .unwrap()
                .display_name
                .as_deref(),
            Some(MARIE)
        );
        // The member drops the link's credential: that client is done.
        joiner.client.revoke_own_credential().unwrap();
        assert!(joiner.client.refresh().is_err());
        assert!(org.invite_store(&invite).roster(1).is_err());
    }

    #[test]
    fn display_name_is_checked() {
        let org = publish(&FakeMailbox::org());
        let (_, invite) = org.invite("Marie", vec![]);
        let joiner = org.joiner(&invite);
        let long = "é".repeat(33); // 66 bytes, 33 characters
        for name in ["", long.as_str(), "Marie\u{200B}", "Ma\nrie"] {
            assert!(
                matches!(
                    joiner.post(&invite, name),
                    Err(OnePassError::Validation { ref field, .. }) if field == "display_name"
                ),
                "{name:?}"
            );
        }
        assert!(org.raw_requests().is_empty());
        joiner.post(&invite, &"é".repeat(32)).unwrap();
    }

    #[test]
    fn invite_credential_cannot_write_the_roster() {
        let org = publish(&FakeMailbox::org());
        let (_, invite) = org.invite("Marie", vec![]);
        let mut store = org.invite_store(&invite);
        let two = store.roster(2).unwrap().unwrap();
        let err = store.put_roster(3, two).unwrap_err();
        assert_eq!(OnePassError::from(err), OnePassError::Forbidden);
        assert_eq!(org.store().latest_roster().unwrap().unwrap().0, 2);
    }

    #[test]
    fn request_for_another_accounts_invitation_is_dropped() {
        let org = publish(&FakeMailbox::org());
        let (_, a) = org.invite("Marie", vec![]);
        let (_, b) = org.invite("Paul", vec![]);
        let marie = org.joiner(&a);
        let paul = org.joiner(&b);
        // Paul's session is not the account of Marie's invitation.
        assert!(matches!(
            paul.post(&a, "Paul"),
            Err(OnePassError::Validation { .. })
        ));
        // Paul's own account with Marie's nonce: posted, then dropped.
        let stolen = FfiOrgInvite {
            nonce: a.nonce.clone(),
            ..b.clone()
        };
        paul.post(&stolen, "Paul").unwrap();
        marie.post(&a, MARIE).unwrap();
        assert_eq!(org.raw_requests().len(), 2);
        let got = org.creator().join_requests().unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].account_id, a.account_id);
    }

    #[test]
    fn forged_join_request_is_dropped() {
        let org = publish(&FakeMailbox::org());
        let (_, invite) = org.invite("Marie", vec![]);
        let joiner = org.joiner(&invite);
        joiner.post(&invite, MARIE).unwrap();
        let creator = org.creator();
        assert_eq!(creator.join_requests().unwrap().len(), 1);
        let account: [u8; 16] = unhex(&invite.account_id);
        let honest = SignedJoinRequest::decode(&org.raw_requests()[0].1).unwrap();

        // Another display name under the old signature.
        let mut forged = honest.clone();
        forged.body.display_name = "Admin".into();
        org.store()
            .put_join_request(account, forged.encode())
            .unwrap();
        assert_eq!(creator.join_requests().unwrap(), vec![]);

        // Validly signed, but the mailbox credential is no Ed25519 point.
        let mut point = [0u8; 32];
        point[0] = 2; // y = 2 is not on the curve
        let body = JoinRequestBody {
            mailbox_credential: point,
            ..honest.body.clone()
        };
        let signed = sign_join_request(body, &joiner.keys.core()).unwrap();
        org.store()
            .put_join_request(account, signed.encode())
            .unwrap();
        assert_eq!(creator.join_requests().unwrap(), vec![]);

        // The honest one again is shown again.
        org.store()
            .put_join_request(account, honest.encode())
            .unwrap();
        assert_eq!(creator.join_requests().unwrap().len(), 1);
    }

    #[test]
    fn decline_removes_the_request() {
        let org = publish(&FakeMailbox::org());
        let (_, invite) = org.invite("Marie", vec![]);
        org.joiner(&invite).post(&invite, MARIE).unwrap();
        let creator = org.creator();
        assert_eq!(creator.join_requests().unwrap().len(), 1);
        assert!(org.invite_store(&invite).roster(1).is_ok());
        creator
            .decline_join_request(invite.account_id.clone())
            .unwrap();
        assert_eq!(creator.join_requests().unwrap(), vec![]);
        assert!(org.raw_requests().is_empty());
        // The issuing device revoked the link's credential (R27).
        assert!(org.invite_store(&invite).roster(1).is_err());
        // The invitation itself stands (withdrawing it is a roster edit).
        let s = creator.refresh().unwrap();
        assert_eq!(s.roster_seq, 2);
        assert!(
            s.members
                .iter()
                .any(|m| m.account_id == invite.account_id && m.state == FfiMemberState::Invited)
        );
    }

    #[test]
    fn join_feed_is_incremental() {
        let org = publish(&FakeMailbox::org());
        let (_, invite) = org.invite("Marie", vec![]);
        let feeds: Arc<std::sync::Mutex<Vec<Option<bool>>>> = Default::default();
        let client = org.open(
            Box::new(Tweaked {
                inner: org.store(),
                hide: None,
                hook: None,
                feeds: feeds.clone(),
                fail_mint: false,
                on_mint: None,
                taken: 0,
            }),
            &org.creator_dir,
        );
        assert_eq!(client.join_requests().unwrap(), vec![]);
        org.joiner(&invite).post(&invite, MARIE).unwrap();
        assert_eq!(client.join_requests().unwrap().len(), 1);
        assert_eq!(client.join_requests().unwrap().len(), 1);
        // One full read, then only changes since the cursor.
        assert_eq!(
            *feeds.lock().unwrap(),
            vec![Some(true), Some(false), Some(false)]
        );
    }

    #[test]
    fn a_member_without_manage_rights_cannot_create_an_invite() {
        let org = publish(&FakeMailbox::org());
        let (_, invite) = org.invite("Marie", vec![]);
        let joiner = org.joiner(&invite);
        joiner.post(&invite, MARIE).unwrap();
        // Still Invited: its device is in no roster entry.
        let invite_by = |j: &Joiner| {
            j.client.create_invite(
                j.session.clone(),
                j.keys.classical.clone(),
                j.keys.half(),
                "Paul".into(),
                None,
                vec![],
                NOW,
            )
        };
        assert_eq!(invite_by(&joiner), Err(integrity("org_role_denied")));
        // Activated by the owner (by hand: acceptance is Task 4), no role.
        let mut store = org.store();
        let two = SignedRoster::decode(&store.roster(2).unwrap().unwrap()).unwrap();
        let req = SignedJoinRequest::decode(&org.raw_requests()[0].1).unwrap();
        let fpr: [u8; 32] = org.created.state.fingerprint.clone().try_into().unwrap();
        let joined = verify_join_request(&req, &two.body, &fpr).unwrap();
        let three = activate_member(&two.body, &joined).unwrap();
        let three = sign_roster(three, &org.owner.device(), &org.owner.keys.core()).unwrap();
        store.put_roster(3, three.encode()).unwrap();
        let s = joiner.client.refresh().unwrap();
        assert!(
            s.members
                .iter()
                .any(|m| m.account_id == invite.account_id && m.state == FfiMemberState::Active)
        );
        assert_eq!(invite_by(&joiner), Err(integrity("org_role_denied")));
        assert_eq!(org.store().latest_roster().unwrap().unwrap().0, 3);
        assert_eq!(joiner.client.state().unwrap().unwrap().roster_seq, 3);
    }

    // ---- fix round 1: side-effect order of create_invite (R28) -----------------------

    impl Org {
        fn credential_count(&self) -> u16 {
            self.client().info().unwrap().usage.credentials
        }

        fn invite_through(&self, client: &OrgClient) -> Result<FfiInviteLink, OnePassError> {
            client.create_invite(
                self.owner.session.clone(),
                self.owner.keys.classical.clone(),
                self.owner.keys.half(),
                "Marie".into(),
                None,
                vec![],
                NOW,
            )
        }
    }

    #[test]
    fn broken_invites_file_fails_before_any_write() {
        let org = publish(&FakeMailbox::org());
        std::fs::write(org.creator_dir.join("invites.bin"), b"\x01garbage").unwrap();
        let credentials = org.credential_count();
        assert!(matches!(
            org.invite_through(&org.creator()),
            Err(OnePassError::InvalidInput { .. })
        ));
        assert_eq!(org.store().latest_roster().unwrap().unwrap().0, 1);
        assert_eq!(org.credential_count(), credentials);
    }

    #[test]
    fn failed_token_mint_revokes_the_credential() {
        let org = publish(&FakeMailbox::org());
        let credentials = org.credential_count();
        let client = org.open(
            Box::new(Tweaked {
                inner: org.store(),
                hide: None,
                hook: None,
                feeds: Default::default(),
                fail_mint: true,
                on_mint: None,
                taken: 0,
            }),
            &org.creator_dir,
        );
        assert!(org.invite_through(&client).is_err());
        // The roster write stands; the granted credential does not.
        assert_eq!(org.store().latest_roster().unwrap().unwrap().0, 2);
        assert_eq!(org.credential_count(), credentials);
        assert!(!org.creator_dir.join("invites.bin").exists());
    }

    #[test]
    fn unsaved_invites_file_still_returns_the_link() {
        let org = publish(&FakeMailbox::org());
        // After the server writes, a folder takes the place of invites.bin:
        // the local save fails.
        let path = org.creator_dir.join("invites.bin");
        let hook: Hook = Box::new(move || std::fs::create_dir(&path).unwrap());
        let client = org.open(
            Box::new(Tweaked {
                inner: org.store(),
                hide: None,
                hook: None,
                feeds: Default::default(),
                fail_mint: false,
                on_mint: Some(hook),
                taken: 0,
            }),
            &org.creator_dir,
        );
        let link = org.invite_through(&client).unwrap();
        let invite = org_invite_parse(link.link, false).unwrap();
        assert_eq!(invite.account_id, link.account_id);
        assert_eq!(org.store().latest_roster().unwrap().unwrap().0, 2);
    }

    // ---- roster edits, owners and the owner keyset (Task 4) --------------------------

    use onepass_ffi::{FfiEditOutcome, FfiOrgMember, FfiOrgState, FfiRosterEdit, TestOrgServer};

    /// An invited member that posted its join request.
    struct Member {
        invite: FfiOrgInvite,
        joiner: Joiner,
        posted: FfiJoinPosted,
    }

    impl Member {
        fn account(&self) -> String {
            self.invite.account_id.clone()
        }

        /// The org mailbox store with the member's own credential (R27).
        fn own_store(&self, org: &Org) -> OrgStore<FakeMailboxClient> {
            let mut c = org
                .fake
                .client(Credential::from_seed(&self.posted.credential_seed).unwrap());
            c.open(unhex(&self.invite.mailbox_id));
            OrgStore::new(c, org.org_id)
        }

        /// The member's org client reopened with its own credential, on the
        /// pin the link's client made.
        fn own_client(&self, org: &Org) -> Arc<OrgClient> {
            self.own_client_over(org, Box::new(self.own_store(org)))
        }

        fn own_client_over(&self, org: &Org, store: Box<dyn OrgStoreApi + Send>) -> Arc<OrgClient> {
            org.open(store, &self.joiner._dir.path().join("org"))
        }

        fn edit(
            &self,
            client: &OrgClient,
            edit: FfiRosterEdit,
        ) -> Result<FfiEditOutcome, OnePassError> {
            let j = &self.joiner;
            client.edit_roster(
                j.session.clone(),
                j.keys.classical.clone(),
                j.keys.half(),
                edit,
                NOW,
            )
        }

        fn summarize(&self, client: &OrgClient, edit: FfiRosterEdit) -> FfiEditSummary {
            let j = &self.joiner;
            client
                .summarize(
                    j.session.clone(),
                    j.keys.classical.clone(),
                    j.keys.half(),
                    edit,
                )
                .unwrap()
        }

        fn keyset_available(&self, client: &OrgClient) -> bool {
            let j = &self.joiner;
            client
                .owner_keyset_available(j.session.clone(), j.keys.classical.clone(), j.keys.half())
                .unwrap()
        }
    }

    use onepass_ffi::FfiEditSummary;

    impl Org {
        /// Invited by the owner's device with `roles`, joined and posted
        /// as `name`.
        fn member(&self, name: &str, roles: Vec<FfiOrgRole>) -> Member {
            let (_, invite) = self.invite(name, roles);
            let joiner = self.joiner(&invite);
            let posted = joiner.post(&invite, name).unwrap();
            Member {
                invite,
                joiner,
                posted,
            }
        }

        /// A member accepted by the owner with `roles`.
        fn accepted(&self, name: &str, roles: Vec<FfiOrgRole>) -> Member {
            let m = self.member(name, vec![]);
            self.accept(&m, roles).unwrap();
            m
        }

        fn accept(
            &self,
            m: &Member,
            roles: Vec<FfiOrgRole>,
        ) -> Result<FfiEditOutcome, OnePassError> {
            self.edit(FfiRosterEdit::Accept {
                account_id: m.account(),
                roles,
            })
        }

        /// An edit by the owner's device through its own client.
        fn edit(&self, edit: FfiRosterEdit) -> Result<FfiEditOutcome, OnePassError> {
            self.edit_by(&self.creator(), edit)
        }

        fn edit_by(
            &self,
            client: &OrgClient,
            edit: FfiRosterEdit,
        ) -> Result<FfiEditOutcome, OnePassError> {
            client.edit_roster(
                self.owner.session.clone(),
                self.owner.keys.classical.clone(),
                self.owner.keys.half(),
                edit,
                NOW,
            )
        }

        fn summarize(&self, edit: FfiRosterEdit) -> Result<FfiEditSummary, OnePassError> {
            self.creator().summarize(
                self.owner.session.clone(),
                self.owner.keys.classical.clone(),
                self.owner.keys.half(),
                edit,
            )
        }

        fn set_owners(&self, owners: Vec<String>) -> Result<FfiOrgState, OnePassError> {
            self.creator().set_owners(
                self.owner.session.clone(),
                self.owner.keys.classical.clone(),
                self.owner.keys.half(),
                owners,
                NOW,
            )
        }

        fn latest_seq(&self) -> u64 {
            self.store().latest_roster().unwrap().unwrap().0
        }

        fn account(&self) -> String {
            self.owner.session.account_id()
        }
    }

    fn member_of<'a>(s: &'a FfiOrgState, account: &str) -> &'a FfiOrgMember {
        s.members.iter().find(|m| m.account_id == account).unwrap()
    }

    fn roles_error(reason: &str) -> OnePassError {
        OnePassError::Validation {
            field: "roles".into(),
            reason: reason.into(),
        }
    }

    #[test]
    fn admin_accepts_a_join_request() {
        let org = publish(&FakeMailbox::org());
        let m = org.member(MARIE, vec![FfiOrgRole::Auditor]);
        let out = org.accept(&m, vec![]).unwrap();
        assert!(out.server_access_updated);
        assert_eq!(out.state.roster_seq, 3);
        let e = member_of(&out.state, &m.account());
        assert_eq!(e.state, FfiMemberState::Active);
        // The roles of the edit, not the invitation's.
        assert!(e.roles.is_empty());
        assert_eq!(e.devices.len(), 1);
        assert_eq!(e.display_name.as_deref(), Some(MARIE));
        // No longer waiting.
        assert_eq!(org.creator().join_requests().unwrap(), vec![]);
        // The inviting device revoked the link's credential; the member reads
        // with its own and sees itself Active.
        assert!(org.invite_store(&m.invite).roster(1).is_err());
        let s = m.own_client(&org).refresh().unwrap();
        assert_eq!(member_of(&s, &m.account()).state, FfiMemberState::Active);
        assert_eq!(s.roster_seq, 3);
    }

    #[test]
    fn accept_needs_a_verified_join_request() {
        let org = publish(&FakeMailbox::org());
        let (link, _) = org.invite("Marie", vec![]);
        let accept = FfiRosterEdit::Accept {
            account_id: link.account_id.clone(),
            roles: vec![],
        };
        assert_eq!(org.summarize(accept.clone()), Err(OnePassError::NotFound));
        assert_eq!(org.edit(accept), Err(OnePassError::NotFound));
        assert_eq!(org.latest_seq(), 2);
    }

    #[test]
    fn member_names_come_from_join_requests() {
        let org = publish(&FakeMailbox::org());
        let m = org.accepted(MARIE, vec![]);
        // A device that never listed the requests: a plain refresh names her.
        let (_, second) = org.second_device();
        let s = second.refresh().unwrap();
        assert_eq!(
            member_of(&s, &m.account()).display_name.as_deref(),
            Some(MARIE)
        );
        assert_eq!(member_of(&s, &org.account()).display_name, None);
    }

    #[test]
    fn accepted_member_moves_to_its_own_credential() {
        let org = publish(&FakeMailbox::org());
        let m = org.member(MARIE, vec![]);
        // Accepted by a device that did not issue the invitation: the link's
        // credential stays for the member to drop.
        let (_, second) = org.second_device();
        let out = org
            .edit_by(
                &second,
                FfiRosterEdit::Accept {
                    account_id: m.account(),
                    roles: vec![],
                },
            )
            .unwrap();
        assert!(out.server_access_updated);
        let s = m.joiner.client.refresh().unwrap();
        assert_eq!(member_of(&s, &m.account()).state, FfiMemberState::Active);
        let own = m.own_client(&org);
        assert_eq!(own.refresh().unwrap().roster_seq, 3);
        m.joiner.client.revoke_own_credential().unwrap();
        assert!(m.joiner.client.refresh().is_err());
        assert!(own.refresh().is_ok());
    }

    #[test]
    fn summary_comes_from_the_pinned_roster() {
        let org = publish(&FakeMailbox::org());
        let m = org.accepted(MARIE, vec![]);
        let (dir, second) = org.second_device();
        assert_eq!(second.refresh().unwrap().roster_seq, 3);
        let before = pin_bytes(&dir);
        // The server now holds a newer roster with the member Removed.
        org.edit(FfiRosterEdit::Remove {
            account_id: m.account(),
        })
        .unwrap();
        assert_eq!(org.latest_seq(), 4);
        let summary = second
            .summarize(
                org.owner.session.clone(),
                org.owner.keys.classical.clone(),
                org.owner.keys.half(),
                FfiRosterEdit::Suspend {
                    account_id: m.account(),
                },
            )
            .unwrap();
        assert_eq!(
            summary,
            FfiEditSummary {
                member_name: MARIE.into(),
                device_count: 1,
                roles_before: vec![],
                roles_after: vec![],
                state_before: Some(FfiMemberState::Active),
                state_after: FfiMemberState::Suspended,
                allowed: true,
            }
        );
        // Nothing read, nothing written.
        assert_eq!(pin_bytes(&dir), before);
        assert_eq!(org.latest_seq(), 4);
    }

    #[test]
    fn user_manager_cannot_grant_admin() {
        let org = publish(&FakeMailbox::org());
        let b = org.accepted("Bea", vec![FfiOrgRole::UserManager]);
        let c = org.accepted("Carl", vec![]);
        let client = b.own_client(&org);
        client.refresh().unwrap();
        let seq = org.latest_seq();
        let admin = FfiRosterEdit::SetRoles {
            account_id: c.account(),
            roles: vec![FfiOrgRole::Admin],
        };
        let summary = b.summarize(&client, admin.clone());
        assert!(!summary.allowed);
        assert_eq!(summary.roles_after, vec![FfiOrgRole::Admin]);
        assert_eq!(b.edit(&client, admin), Err(integrity("org_role_denied")));
        assert_eq!(org.latest_seq(), seq);
        // A role it holds itself it may grant.
        let um = FfiRosterEdit::SetRoles {
            account_id: c.account(),
            roles: vec![FfiOrgRole::UserManager],
        };
        assert!(b.summarize(&client, um.clone()).allowed);
        assert!(b.edit(&client, um).unwrap().server_access_updated);
        assert_eq!(org.latest_seq(), seq + 1);
    }

    #[test]
    fn owner_changes_only_through_the_lineage() {
        let org = publish(&FakeMailbox::org());
        let m = org.accepted(MARIE, vec![]);
        let seq = org.latest_seq();
        let owner_via_lineage = roles_error("owner via lineage");
        for edit in [
            FfiRosterEdit::SetRoles {
                account_id: m.account(),
                roles: vec![FfiOrgRole::Owner],
            },
            // Touching the Owner bit of an owner.
            FfiRosterEdit::SetRoles {
                account_id: org.account(),
                roles: vec![FfiOrgRole::Admin],
            },
        ] {
            assert_eq!(org.summarize(edit.clone()), Err(owner_via_lineage.clone()));
            assert_eq!(org.edit(edit), Err(owner_via_lineage.clone()));
        }
        let officer = FfiRosterEdit::SetRoles {
            account_id: m.account(),
            roles: vec![FfiOrgRole::RecoveryOfficer],
        };
        assert_eq!(
            org.edit(officer),
            Err(roles_error("recovery officer via lineage"))
        );
        let (link, _) = org.invite("Paul", vec![]);
        assert_eq!(
            org.edit(FfiRosterEdit::Accept {
                account_id: link.account_id,
                roles: vec![FfiOrgRole::Owner],
            }),
            Err(owner_via_lineage)
        );
        assert_eq!(org.latest_seq(), seq + 1);
    }

    #[test]
    fn concurrent_edit_rebases_once() {
        let org = publish(&FakeMailbox::org());
        let b = org.accepted("Bea", vec![FfiOrgRole::Admin]);
        let x = org.accepted("Xavier", vec![]);
        let (y, _) = org.invite("Yann", vec![]);
        // A (the owner) and B both pinned at the same seq.
        let client_b = b.own_client(&org);
        let seq = client_b.refresh().unwrap().roster_seq;
        assert_eq!(org.creator().refresh().unwrap().roster_seq, seq);
        org.edit(FfiRosterEdit::Suspend {
            account_id: x.account(),
        })
        .unwrap();
        // B removes Y from its stale pin: its seq is taken, it rebases.
        let out = b
            .edit(
                &client_b,
                FfiRosterEdit::Remove {
                    account_id: y.account_id.clone(),
                },
            )
            .unwrap();
        assert_eq!(out.state.roster_seq, seq + 2);
        assert_eq!(
            member_of(&out.state, &x.account()).state,
            FfiMemberState::Suspended
        );
        assert_eq!(
            member_of(&out.state, &y.account_id).state,
            FfiMemberState::Removed {
                at: NOW,
                by: b.account()
            }
        );
        // A store answering Taken twice: Conflict, the pin as it was.
        let dir = b.joiner._dir.path().join("org");
        let before = pin_bytes(&dir);
        let taken = b.own_client_over(
            &org,
            Box::new(Tweaked {
                inner: b.own_store(&org),
                hide: None,
                hook: None,
                feeds: Default::default(),
                fail_mint: false,
                on_mint: None,
                taken: 2,
            }),
        );
        assert_eq!(
            b.edit(
                &taken,
                FfiRosterEdit::Reactivate {
                    account_id: x.account(),
                }
            )
            .map(|o| o.state.roster_seq),
            Err(OnePassError::Conflict)
        );
        assert_eq!(pin_bytes(&dir), before);
        assert_eq!(org.latest_seq(), seq + 2);
    }

    #[test]
    fn suspend_reactivate_remove_keep_the_member_listed() {
        let org = publish(&FakeMailbox::org());
        let m = org.accepted(MARIE, vec![FfiOrgRole::Auditor]);
        let count = org.creator().state().unwrap().unwrap().members.len();
        let account: [u8; 16] = unhex(&m.account());
        let request = org.raw_requests()[0].1.clone();
        let account_id = m.account();

        let out = org
            .edit(FfiRosterEdit::Suspend {
                account_id: account_id.clone(),
            })
            .unwrap();
        assert!(out.server_access_updated);
        let e = member_of(&out.state, &account_id);
        assert_eq!(e.state, FfiMemberState::Suspended);
        assert_eq!(e.roles, vec![FfiOrgRole::Auditor]);
        assert_eq!(out.state.members.len(), count);
        // Suspended: reads only.
        assert!(m.own_client(&org).refresh().is_ok());
        let put = m.own_store(&org).put_join_request(account, request.clone());
        assert_eq!(
            put.map_err(OnePassError::from),
            Err(OnePassError::Forbidden)
        );

        let out = org
            .edit(FfiRosterEdit::Reactivate {
                account_id: account_id.clone(),
            })
            .unwrap();
        assert!(out.server_access_updated);
        assert_eq!(
            member_of(&out.state, &account_id).state,
            FfiMemberState::Active
        );
        m.own_store(&org)
            .put_join_request(account, request)
            .unwrap();

        let out = org
            .edit(FfiRosterEdit::Remove {
                account_id: account_id.clone(),
            })
            .unwrap();
        let e = member_of(&out.state, &account_id);
        assert_eq!(
            e.state,
            FfiMemberState::Removed {
                at: NOW,
                by: org.account()
            }
        );
        assert!(e.roles.is_empty());
        assert!(e.devices.is_empty());
        assert_eq!(out.state.members.len(), count);
        // Removed is for good.
        assert_eq!(
            org.edit(FfiRosterEdit::Reactivate { account_id }),
            Err(integrity("org_role_denied"))
        );
        assert_eq!(org.creator().refresh().unwrap().members.len(), count);
    }

    #[test]
    fn removal_revokes_mailbox_access() {
        let org = publish(&FakeMailbox::org());
        let m = org.accepted(MARIE, vec![FfiOrgRole::UserManager]);
        let own = m.own_client(&org);
        own.refresh().unwrap();
        let out = org
            .edit(FfiRosterEdit::Remove {
                account_id: m.account(),
            })
            .unwrap();
        assert!(out.server_access_updated);
        assert!(matches!(
            own.refresh(),
            Err(OnePassError::MailboxUnavailable { .. } | OnePassError::Forbidden)
        ));
    }

    #[test]
    fn removing_an_invited_member_withdraws_the_invitation() {
        let org = publish(&FakeMailbox::org());
        let (link, invite) = org.invite("Marie", vec![]);
        assert!(org.invite_store(&invite).roster(1).is_ok());
        let out = org
            .edit(FfiRosterEdit::Remove {
                account_id: link.account_id.clone(),
            })
            .unwrap();
        assert!(out.server_access_updated);
        assert!(matches!(
            member_of(&out.state, &link.account_id).state,
            FfiMemberState::Removed { .. }
        ));
        assert!(org.invite_store(&invite).roster(1).is_err());
    }

    #[test]
    fn promoted_admin_gets_manage_and_can_write_the_roster() {
        let org = publish(&FakeMailbox::org());
        let m = org.accepted(MARIE, vec![]);
        let own = m.own_client(&org);
        own.refresh().unwrap();
        let invite = |c: &OrgClient| {
            let j = &m.joiner;
            c.create_invite(
                j.session.clone(),
                j.keys.classical.clone(),
                j.keys.half(),
                "Paul".into(),
                None,
                vec![],
                NOW,
            )
        };
        assert_eq!(invite(&own), Err(integrity("org_role_denied")));
        let out = org
            .edit(FfiRosterEdit::SetRoles {
                account_id: m.account(),
                roles: vec![FfiOrgRole::Admin],
            })
            .unwrap();
        assert!(out.server_access_updated);
        assert_eq!(
            member_of(&out.state, &m.account()).roles,
            vec![FfiOrgRole::Admin]
        );
        let seq = org.latest_seq();
        own.refresh().unwrap();
        // A roster write and a credential grant: Manage.
        invite(&own).unwrap();
        assert_eq!(org.latest_seq(), seq + 1);
    }

    #[test]
    fn single_owner_adds_a_second_owner() {
        let org = publish(&FakeMailbox::org());
        let b = org.accepted("Bea", vec![]);
        let mut owners = vec![org.account(), b.account()];
        owners.sort();
        let seq = org.latest_seq();
        let s = org.set_owners(owners.clone()).unwrap();
        assert_eq!(s.lineage_generation, 1);
        assert_eq!(s.owners, owners);
        assert_eq!(s.roster_seq, seq + 1);
        assert_eq!(member_of(&s, &b.account()).roles, vec![FfiOrgRole::Owner]);
        let own = b.own_client(&org);
        let seen = own.refresh().unwrap();
        assert_eq!(seen.lineage_generation, 1);
        assert_eq!(seen.owners, owners);
        assert!(b.keyset_available(&own));
        assert!(
            org.creator()
                .owner_keyset_available(
                    org.owner.session.clone(),
                    org.owner.keys.classical.clone(),
                    org.owner.keys.half(),
                )
                .unwrap()
        );
        // The new owner holds Manage: it writes the roster.
        let carl = org.accepted("Carl", vec![]);
        own.refresh().unwrap();
        b.edit(
            &own,
            FfiRosterEdit::Suspend {
                account_id: carl.account(),
            },
        )
        .unwrap();
    }

    #[test]
    fn third_owner_needs_quorum() {
        let org = publish(&FakeMailbox::org());
        let b = org.accepted("Bea", vec![]);
        org.set_owners(vec![org.account(), b.account()]).unwrap();
        let c = org.accepted("Carl", vec![]);
        let seq = org.latest_seq();
        assert_eq!(
            org.set_owners(vec![org.account(), b.account(), c.account()]),
            Err(OnePassError::Validation {
                field: "owners".into(),
                reason: "quorum".into(),
            })
        );
        assert_eq!(org.store().lineage_from(0).unwrap().len(), 2);
        assert_eq!(org.latest_seq(), seq);
        let mut store = org.store();
        assert!(store.owner_keyset(unhex(&c.account())).unwrap().is_none());
    }

    #[test]
    fn member_cannot_open_the_owner_keyset() {
        let org = publish(&FakeMailbox::org());
        let m = org.accepted(MARIE, vec![FfiOrgRole::Admin]);
        let own = m.own_client(&org);
        own.refresh().unwrap();
        assert!(!m.keyset_available(&own));
        // Even with the creator's sealed keyset served under its own id.
        let creator: [u8; 16] = unhex(&org.account());
        let sealed = org.store().owner_keyset(creator).unwrap().unwrap();
        org.store()
            .put_owner_keyset(unhex(&m.account()), sealed)
            .unwrap();
        assert!(!m.keyset_available(&own));
    }

    #[test]
    fn test_org_server_runs_a_join() {
        let server = TestOrgServer::new();
        let draft = OrgDraft::new().unwrap();
        let owner = Owner::new(&draft.org_id());
        let dirs = TempDir::new().unwrap();
        let path = |name: &str| dirs.path().join(name).to_string_lossy().into_owned();
        let created = server
            .draft_publish(
                draft.clone(),
                owner.session.clone(),
                owner.keys.classical.clone(),
                owner.keys.half(),
                ORG_NAME.into(),
                path("admin"),
                NOW,
            )
            .unwrap();
        let admin = server
            .client(
                created.mailbox_id.clone(),
                created.credential_seed.clone(),
                draft.org_id(),
                path("admin"),
            )
            .unwrap();
        let link = admin
            .create_invite(
                owner.session.clone(),
                owner.keys.classical.clone(),
                owner.keys.half(),
                "Marie".into(),
                None,
                vec![],
                NOW,
            )
            .unwrap();
        // The loopback test server: only with the test switch.
        assert!(org_invite_parse(link.link.clone(), false).is_err());
        let invite = org_invite_parse(link.link, true).unwrap();
        let joiner = server
            .client(
                invite.mailbox_id.clone(),
                invite.credential_seed.clone(),
                invite.org_id.clone(),
                path("joiner"),
            )
            .unwrap();
        joiner
            .pin(
                FfiPinSource::Tofu { verified: false },
                Some(invite.fingerprint.clone()),
                NOW,
            )
            .unwrap();
        let keys = Keys::new();
        let account = create_managed_account(
            db_path(&dirs.path().join("joiner")),
            PASSWORD.as_bytes().to_vec(),
            Some(FAST),
            keys.classical.clone(),
            keys.half(),
            "iPhone".into(),
            FfiDeviceKind::Phone,
            FfiDeviceMode::Personal,
            invite.org_id.clone(),
            Some(invite.account_id.clone()),
        )
        .unwrap();
        let posted = joiner
            .post_join_request(
                account.session.clone(),
                keys.classical.clone(),
                keys.half(),
                invite.clone(),
                MARIE.into(),
                NOW,
            )
            .unwrap();
        assert_eq!(
            admin.join_requests().unwrap()[0].code_words,
            posted.code_words
        );
        admin
            .edit_roster(
                owner.session.clone(),
                owner.keys.classical.clone(),
                owner.keys.half(),
                FfiRosterEdit::Accept {
                    account_id: invite.account_id.clone(),
                    roles: vec![],
                },
                NOW,
            )
            .unwrap();
        let own = server
            .client(
                invite.mailbox_id.clone(),
                posted.credential_seed,
                invite.org_id.clone(),
                path("joiner"),
            )
            .unwrap();
        let s = own.refresh().unwrap();
        assert_eq!(
            member_of(&s, &invite.account_id).state,
            FfiMemberState::Active
        );
    }
}
