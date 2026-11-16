//! The organisation flow of the apps, through the FFI, against a real
//! mailbox on a LOCAL Supabase stack (the setup of
//! `onepass-mailbox/tests/conformance_e2e.rs`: `supabase start`, the
//! functions served, `mailbox/scripts/local-env.sh` and
//! `mailbox/scripts/e2e-admin.sh setup` run):
//!
//!   ONEPASS_MAILBOX_E2E_URL     base URL of the function, for example
//!                               http://127.0.0.1:57421/functions/v1/mailbox
//!   ONEPASS_MAILBOX_E2E_ADMIN   path of mailbox/scripts/e2e-admin.sh
//!                               (default: found from this crate)
//!
//! The test mints its own `org` plan invite (`e2e-admin.sh org-invite`).
//! Without ONEPASS_MAILBOX_E2E_URL it prints why and passes.
//!
//! The owner publishes an org (genesis, founding roster, sealed keyset),
//! mints a token for its own managed mailbox, invites a member; the member
//! follows the link (TOFU pin, its managed mailbox, its managed account)
//! and posts its join request; the owner reads it with the same 5 words,
//! accepts, changes the member's roles, suspends and removes it, and the
//! member's own client sees each step. Hostile cases run against the same
//! server: a second genesis, a roster overwrite, writes by limited
//! credentials, a tampered fingerprint and a forged roster.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use onepass_core::device_keys::{PqDeviceHalf, SoftwarePqHalf};
use onepass_ffi::{
    FfiDeviceKind, FfiDeviceMode, FfiKdfParams, FfiMailboxEndpoint, FfiMemberState, FfiOrgMember,
    FfiOrgRole, FfiOrgState, FfiPinSource, FfiPqDeviceHalf, FfiRosterEdit, OnePassError, OrgClient,
    OrgDraft, Session, create_managed_account, generate_classical_device_keys,
    mailbox_check_managed, mailbox_create_managed, mailbox_generate_credential, org_invite_parse,
};
use onepass_mailbox::testing::{managed_plan, org_plan};
use onepass_mailbox::{Credential, Endpoint, MailboxClient, OrgStore};
use tempfile::TempDir;

const PASSWORD: &str = "Café-étoile";
const FAST: FfiKdfParams = FfiKdfParams {
    m_kib: 8192,
    t: 1,
    p: 1,
};
const ORG_NAME: &str = "Soma Labs e2e";
const MARIE: &str = "Marie Dupont";

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

/// A device: its classical keys and its software post-quantum half.
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
}

/// A managed account of an org on one device.
struct Account {
    session: Arc<Session>,
    keys: Keys,
}

impl Account {
    fn new(dir: &Path, name: &str, org_id: &str, account_id: Option<String>) -> Account {
        std::fs::create_dir_all(dir).unwrap();
        let keys = Keys::new();
        let created = create_managed_account(
            dir.join("onepass.db").to_string_lossy().into_owned(),
            PASSWORD.as_bytes().to_vec(),
            Some(FAST),
            keys.classical.clone(),
            keys.half(),
            name.into(),
            FfiDeviceKind::Mac,
            FfiDeviceMode::Personal,
            org_id.into(),
            account_id,
        )
        .unwrap();
        Account {
            session: created.session,
            keys,
        }
    }

    fn edit(&self, client: &OrgClient, edit: FfiRosterEdit, now: i64) -> FfiOrgState {
        let out = client
            .edit_roster(
                self.session.clone(),
                self.keys.classical.clone(),
                self.keys.half(),
                edit,
                now,
            )
            .unwrap();
        assert!(
            out.server_access_updated,
            "the server access follows the edit"
        );
        out.state
    }

    fn keyset_available(&self, client: &OrgClient) -> bool {
        client
            .owner_keyset_available(
                self.session.clone(),
                self.keys.classical.clone(),
                self.keys.half(),
            )
            .unwrap()
    }
}

struct E2e {
    url: String,
    admin: PathBuf,
    dirs: TempDir,
}

impl E2e {
    fn admin(&self, args: &[&str]) -> String {
        let out = Command::new(&self.admin)
            .args(args)
            .output()
            .unwrap_or_else(|e| panic!("{}: {e}", self.admin.display()));
        assert!(
            out.status.success(),
            "e2e-admin.sh {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap().trim().to_owned()
    }

    fn endpoint(&self) -> FfiMailboxEndpoint {
        FfiMailboxEndpoint {
            base_url: self.url.clone(),
            extra_ca_pem: None,
        }
    }

    fn dir(&self, name: &str) -> PathBuf {
        self.dirs.path().join(name)
    }

    fn state_dir(&self, name: &str) -> String {
        self.dir(name).join("org").to_string_lossy().into_owned()
    }

    /// An org client of `mailbox_id` with the credential of `seed`, its pin
    /// in `name`'s state folder.
    fn client(&self, mailbox_id: &str, seed: &[u8], org_id: &str, name: &str) -> Arc<OrgClient> {
        OrgClient::open(
            self.endpoint(),
            mailbox_id.into(),
            seed.to_vec(),
            org_id.into(),
            self.state_dir(name),
        )
        .unwrap()
    }

    /// The raw org store of `mailbox_id` with the credential of `seed`, as a
    /// hostile client holding that credential would use it.
    fn raw(&self, mailbox_id: &str, seed: &[u8], org_id: &str) -> OrgStore<MailboxClient> {
        let endpoint = Endpoint {
            base_url: self.url.clone(),
            extra_ca_pem: None,
        };
        let mut c = MailboxClient::new(endpoint, Credential::from_seed(seed).unwrap()).unwrap();
        c.open(unhex(mailbox_id));
        OrgStore::new(c, unhex(org_id))
    }
}

fn unhex<const N: usize>(s: &str) -> [u8; N] {
    let v: Vec<u8> = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect();
    v.try_into().unwrap()
}

fn member_of<'a>(s: &'a FfiOrgState, account: &str) -> &'a FfiOrgMember {
    s.members
        .iter()
        .find(|m| m.account_id == account)
        .unwrap_or_else(|| panic!("{account} not in the roster"))
}

fn flipped(bytes: &[u8]) -> Vec<u8> {
    let mut b = bytes.to_vec();
    let last = b.len() - 1;
    b[last] ^= 1;
    b
}

fn wall() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

#[test]
fn org_flow_e2e() {
    let Ok(url) = std::env::var("ONEPASS_MAILBOX_E2E_URL") else {
        println!("skipped: ONEPASS_MAILBOX_E2E_URL unset");
        return;
    };
    let admin = std::env::var_os("ONEPASS_MAILBOX_E2E_ADMIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../mailbox/scripts/e2e-admin.sh")
        });
    let t = E2e {
        url,
        admin,
        dirs: TempDir::new().unwrap(),
    };
    // Four mailboxes are created from this address below.
    t.admin(&["reset-rate"]);
    let now = wall();

    // ---- the owner publishes the org ---------------------------------------
    let server_invite = t.admin(&["org-invite"]);
    let draft = OrgDraft::new().unwrap();
    let org_id = draft.org_id();
    let owner = Account::new(&t.dir("owner"), "Mac", &org_id, None);
    let owner_account = owner.session.account_id();
    let seed = mailbox_generate_credential().unwrap().seed;
    let created = draft
        .publish(
            t.endpoint(),
            server_invite.clone(),
            seed.clone(),
            owner.session.clone(),
            owner.keys.classical.clone(),
            owner.keys.half(),
            ORG_NAME.into(),
            t.state_dir("owner"),
            now,
        )
        .expect("publish on the real server");
    let mailbox_id = created.mailbox_id.clone();
    assert_eq!(created.state.name, ORG_NAME);
    assert_eq!(created.state.lineage_generation, 0);
    assert_eq!(created.state.roster_seq, 1);
    assert_eq!(created.state.owners, vec![owner_account.clone()]);
    assert_eq!(created.state.source, FfiPinSource::Tofu { verified: true });
    let founder = member_of(&created.state, &owner_account);
    assert_eq!(founder.state, FfiMemberState::Active);
    assert_eq!(founder.roles, vec![FfiOrgRole::Owner]);
    // The server holds exactly what was signed, on plan `org`.
    {
        let mut raw = t.raw(&mailbox_id, &seed, &org_id);
        assert_eq!(raw.api().info().unwrap().limits, org_plan());
        assert_eq!(raw.lineage_from(0).unwrap().len(), 1);
        assert_eq!(raw.latest_roster().unwrap().unwrap().0, 1);
        assert!(
            raw.owner_keyset(unhex(&owner_account)).unwrap().is_some(),
            "the owner keyset is on the server"
        );
    }
    // The server invite was for one use.
    let again = OrgDraft::new().unwrap();
    let other = Account::new(&t.dir("other"), "Mac", &again.org_id(), None);
    assert!(
        again
            .publish(
                t.endpoint(),
                server_invite,
                mailbox_generate_credential().unwrap().seed,
                other.session.clone(),
                other.keys.classical.clone(),
                other.keys.half(),
                ORG_NAME.into(),
                t.state_dir("other"),
                now,
            )
            .is_err(),
        "a spent org invite creates no second org mailbox"
    );
    eprintln!("publish: ok");

    let admin = t.client(&mailbox_id, &seed, &org_id, "owner");
    assert_eq!(admin.refresh().unwrap().roster_seq, 1);
    assert!(owner.keyset_available(&admin), "the owner opens its keyset");

    // ---- the creator's own managed mailbox ---------------------------------
    let token = admin.mint_member_token().unwrap();
    let home_seed = mailbox_generate_credential().unwrap().seed;
    let home = mailbox_create_managed(t.endpoint(), home_seed.clone(), token.clone())
        .expect("managed mailbox from a minted token");
    mailbox_check_managed(t.endpoint(), home_seed, home.mailbox_id.clone()).unwrap();
    assert!(
        mailbox_create_managed(
            t.endpoint(),
            mailbox_generate_credential().unwrap().seed,
            token
        )
        .is_err(),
        "a member token is for one use"
    );
    eprintln!("creator managed mailbox: ok");

    // ---- invite, follow the link, post the join request --------------------
    let link = admin
        .create_invite(
            owner.session.clone(),
            owner.keys.classical.clone(),
            owner.keys.half(),
            "Marie".into(),
            None,
            vec![],
            now,
        )
        .expect("invite on the real server");
    let invite = org_invite_parse(link.link, true).expect("the link parses");
    assert_eq!(invite.server_url, t.url);
    assert_eq!(invite.mailbox_id, mailbox_id);
    assert_eq!(invite.org_id, org_id);
    assert_eq!(invite.account_id, link.account_id);
    assert_eq!(admin.state().unwrap().unwrap().roster_seq, 2);
    let account = invite.account_id.clone();
    assert_eq!(
        member_of(&admin.state().unwrap().unwrap(), &account).state,
        FfiMemberState::Invited
    );

    // A device given a tampered fingerprint refuses the org.
    let tampered = t.client(
        &invite.mailbox_id,
        &invite.credential_seed,
        &org_id,
        "tampered",
    );
    assert!(
        tampered
            .pin(
                FfiPinSource::Tofu { verified: false },
                Some(flipped(&invite.fingerprint)),
                now,
            )
            .is_err(),
        "a pin against another fingerprint is refused"
    );
    assert_eq!(tampered.state().unwrap(), None);

    let joiner = t.client(
        &invite.mailbox_id,
        &invite.credential_seed,
        &org_id,
        "member",
    );
    let pinned = joiner
        .pin(
            FfiPinSource::Tofu { verified: false },
            Some(invite.fingerprint.clone()),
            now,
        )
        .expect("TOFU pin from the link");
    assert_eq!(pinned.fingerprint, created.state.fingerprint);
    assert_eq!(pinned.roster_seq, 2);

    // The member's own account mailbox, from the link's token.
    let member_home_seed = mailbox_generate_credential().unwrap().seed;
    let member_home = mailbox_create_managed(
        t.endpoint(),
        member_home_seed.clone(),
        invite.member_token.clone(),
    )
    .expect("the member's managed mailbox");
    {
        let endpoint = Endpoint {
            base_url: t.url.clone(),
            extra_ca_pem: None,
        };
        let mut c = MailboxClient::new(endpoint, Credential::from_seed(&member_home_seed).unwrap())
            .unwrap();
        c.open(unhex(&member_home.mailbox_id));
        assert_eq!(c.info().unwrap().limits, managed_plan());
    }

    let member = Account::new(&t.dir("member"), "iPhone", &org_id, Some(account.clone()));
    let own_seed = mailbox_generate_credential().unwrap().seed;
    let posted = joiner
        .post_join_request(
            member.session.clone(),
            member.keys.classical.clone(),
            member.keys.half(),
            invite.clone(),
            MARIE.into(),
            own_seed.clone(),
            now,
        )
        .expect("join request on the real server");
    assert_eq!(posted.code_words.len(), 5);

    // The link's credential writes join requests only.
    {
        let mut raw = t.raw(&invite.mailbox_id, &invite.credential_seed, &org_id);
        let roster2 = raw.roster(2).unwrap().unwrap();
        assert_eq!(
            raw.put_roster(3, roster2).map_err(OnePassError::from),
            Err(OnePassError::Forbidden),
            "the invite credential cannot write a roster"
        );
        let genesis = raw.lineage_from(0).unwrap()[0].1.clone();
        assert_eq!(
            raw.put_lineage(1, genesis).map_err(OnePassError::from),
            Err(OnePassError::Forbidden),
            "the invite credential cannot write the lineage"
        );
        // Reads are not limited by kind (any credential of the mailbox
        // reads every record): the owner keyset stays sealed to the owners'
        // account keys, which `keyset_available` checks below.
    }
    eprintln!("invite and join request: ok");

    // ---- the owner reads the request and accepts it ------------------------
    let requests = admin.join_requests().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].account_id, account);
    assert_eq!(requests[0].display_name, MARIE);
    assert_eq!(requests[0].code_words, posted.code_words, "same 5 words");
    assert!(requests[0].issued_here);

    let state = owner.edit(
        &admin,
        FfiRosterEdit::Accept {
            account_id: account.clone(),
            roles: vec![],
        },
        now,
    );
    let m = member_of(&state, &account);
    assert_eq!(m.state, FfiMemberState::Active);
    assert_eq!(m.display_name.as_deref(), Some(MARIE));
    assert_eq!(state.roster_seq, 3);

    // The member reopens with its own credential and reads the org mailbox.
    let own = t.client(&invite.mailbox_id, &own_seed, &org_id, "member");
    let s = own.refresh().expect("the member reads the org mailbox");
    assert_eq!(s.roster_seq, 3);
    assert_eq!(member_of(&s, &account).state, FfiMemberState::Active);
    assert!(
        !member.keyset_available(&own),
        "a member never opens the owner keyset"
    );
    // The owner's device issued the invitation: the accept revoked the
    // link's credential on the server (R38 (d)).
    assert!(
        matches!(
            joiner.refresh(),
            Err(OnePassError::MailboxUnavailable { .. } | OnePassError::Forbidden)
        ),
        "the link's credential is gone"
    );
    assert!(own.refresh().is_ok());
    eprintln!("accept: ok");

    // ---- role change, suspension, removal ----------------------------------
    let state = owner.edit(
        &admin,
        FfiRosterEdit::SetRoles {
            account_id: account.clone(),
            roles: vec![FfiOrgRole::Auditor],
        },
        now,
    );
    assert_eq!(member_of(&state, &account).roles, vec![FfiOrgRole::Auditor]);
    let s = own.refresh().unwrap();
    assert_eq!(s.roster_seq, 4);
    assert_eq!(member_of(&s, &account).roles, vec![FfiOrgRole::Auditor]);
    eprintln!("set roles: ok");

    let request = t
        .raw(&mailbox_id, &seed, &org_id)
        .join_requests()
        .unwrap()
        .into_iter()
        .find(|(a, _)| *a == unhex::<16>(&account))
        .expect("the member's join request")
        .1;
    let state = owner.edit(
        &admin,
        FfiRosterEdit::Suspend {
            account_id: account.clone(),
        },
        now,
    );
    assert_eq!(member_of(&state, &account).state, FfiMemberState::Suspended);
    let s = own.refresh().expect("a suspended member still reads");
    assert_eq!(member_of(&s, &account).state, FfiMemberState::Suspended);
    assert_eq!(
        t.raw(&invite.mailbox_id, &own_seed, &org_id)
            .put_join_request([0x99; 16], request.clone())
            .map_err(OnePassError::from),
        Err(OnePassError::Forbidden),
        "a suspended member writes nothing"
    );
    eprintln!("suspend: ok");

    let state = owner.edit(
        &admin,
        FfiRosterEdit::Remove {
            account_id: account.clone(),
        },
        now,
    );
    assert_eq!(
        member_of(&state, &account).state,
        FfiMemberState::Removed {
            at: now,
            by: owner_account.clone()
        }
    );
    assert!(
        matches!(
            own.refresh(),
            Err(OnePassError::MailboxUnavailable { .. } | OnePassError::Forbidden)
        ),
        "a removed member's credential is revoked on the server"
    );
    assert_eq!(
        own.state().unwrap().map(|s| s.roster_seq),
        Some(5),
        "the member's device kept the last roster it verified"
    );
    eprintln!("remove: ok");

    // ---- hostile writes by the manager credential --------------------------
    let mut raw = t.raw(&mailbox_id, &seed, &org_id);
    let genesis = raw.lineage_from(0).unwrap()[0].1.clone();
    raw.put_lineage(0, genesis.clone())
        .expect("the same genesis again is accepted");
    assert_eq!(
        raw.put_lineage(0, flipped(&genesis))
            .map_err(OnePassError::from),
        Err(OnePassError::Conflict),
        "a second genesis for the org is refused"
    );
    let roster1 = raw.roster(1).unwrap().unwrap();
    assert_eq!(
        raw.put_roster(1, flipped(&roster1))
            .map_err(OnePassError::from),
        Err(OnePassError::Conflict),
        "a roster overwrite is refused"
    );
    assert_eq!(
        raw.roster(1).unwrap().unwrap(),
        roster1,
        "the first write stands"
    );
    // A forged next roster (the server cannot tell): every client refuses
    // it and keeps its pin.
    let (head, last) = raw.latest_roster().unwrap().unwrap();
    eprintln!(
        "roster head before the forgery: {head} (owner pin {})",
        admin.state().unwrap().unwrap().roster_seq
    );
    assert_eq!(admin.refresh().unwrap().roster_seq, head);
    raw.put_roster(head + 1, flipped(&last)).unwrap();
    let pin = std::fs::read(t.dir("owner").join("org").join("pin.bin")).unwrap();
    assert!(admin.refresh().is_err(), "a forged roster is refused");
    assert_eq!(
        std::fs::read(t.dir("owner").join("org").join("pin.bin")).unwrap(),
        pin,
        "the pin is untouched"
    );
    assert_eq!(admin.state().unwrap().unwrap().roster_seq, head);
    eprintln!("hostile cases: ok");
}
