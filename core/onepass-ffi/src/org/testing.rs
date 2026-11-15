//! Tests only (`dev-fast-kdf`, never in a shipped framework): an org
//! mailbox server in process for the Swift tests (R15). One `FakeMailbox`
//! on the org plan, shared by every client made here; no HTTP, no TLS.
//!
//! A join, as the app does it: the admin `draft_publish`es, opens
//! `client(created.mailbox_id, created.credential_seed, ..)` and calls
//! `create_invite`; the link names `LOOPBACK_URL`, so it parses with
//! `org_invite_parse(link, true)`. The joiner opens `client(invite.mailbox_id,
//! invite.credential_seed, invite.org_id, ..)`, pins `Tofu { verified:
//! false }` with the link's fingerprint, makes its account with
//! `create_managed_account(.., invite.org_id, Some(invite.account_id))` and
//! posts with `post_join_request`. Once accepted it reopens with the seed
//! `post_join_request` returned.

use std::path::PathBuf;
use std::sync::Arc;

use onepass_mailbox::testing::FakeMailbox;
use onepass_mailbox::{Credential, MailboxApi, OrgStore};
use zeroize::Zeroizing;

use super::invite::LOOPBACK_URL;
use super::{FfiOrgCreated, OrgClient, OrgDraft, org_id_of};
use crate::convert::bytes_hex;
use crate::error::OnePassError;
use crate::mailbox::{
    FfiMailboxHome, check_managed_mailbox, create_managed_mailbox, fresh_credential,
};
use crate::rotation::FfiPqDeviceHalf;
use crate::session::Session;

/// The org mailbox server of the Swift tests.
#[derive(uniffi::Object)]
pub struct TestOrgServer {
    fake: FakeMailbox,
}

/// The fake gives the org plan to any mailbox created without one of its
/// own minted tokens, whatever invite it carries.
const SERVER_INVITE: &str = "test-org-invite";

#[uniffi::export]
impl TestOrgServer {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(TestOrgServer {
            fake: FakeMailbox::org(),
        })
    }

    /// A server invite for `draft_publish` (any value works on this server).
    pub fn server_invite(&self) -> String {
        SERVER_INVITE.into()
    }

    /// `OrgDraft::publish` on this server, with a fresh org mailbox
    /// credential (its seed comes back in `FfiOrgCreated`).
    #[allow(clippy::too_many_arguments)]
    pub fn draft_publish(
        &self,
        draft: Arc<OrgDraft>,
        session: Arc<Session>,
        classical: Vec<u8>,
        pq: Arc<dyn FfiPqDeviceHalf>,
        name: String,
        state_dir: String,
        now: i64,
    ) -> Result<FfiOrgCreated, OnePassError> {
        let classical = Zeroizing::new(classical);
        let credential = fresh_credential()?;
        let seed = credential.seed();
        let client = self.fake.client(credential);
        draft.publish_with_client(
            Box::new(client),
            seed.to_vec(),
            SERVER_INVITE.into(),
            session,
            classical.to_vec(),
            pq,
            name,
            state_dir,
            now,
        )
    }

    /// `mailbox_create_managed` on this server: the account mailbox of the
    /// credential of `credential_seed`, created with the `managed` token
    /// `token`. Its home names `LOOPBACK_URL`.
    pub fn create_member_mailbox(
        &self,
        credential_seed: Vec<u8>,
        token: Vec<u8>,
    ) -> Result<FfiMailboxHome, OnePassError> {
        let seed = Zeroizing::new(credential_seed);
        let token = Zeroizing::new(token);
        let mut client = self.fake.client(Credential::from_seed(&seed)?);
        let (mailbox_id, incarnation) = create_managed_mailbox(&mut client, &token)?;
        Ok(FfiMailboxHome {
            base_url: LOOPBACK_URL.into(),
            mailbox_id: bytes_hex(&mailbox_id),
            incarnation,
        })
    }

    /// `mailbox_check_managed` on this server.
    pub fn check_member_mailbox(
        &self,
        credential_seed: Vec<u8>,
        mailbox_id: String,
    ) -> Result<(), OnePassError> {
        let seed = Zeroizing::new(credential_seed);
        let mut client = self.fake.client(Credential::from_seed(&seed)?);
        client.open(crate::mailbox::mailbox_id(&mailbox_id)?);
        check_managed_mailbox(&client)
    }

    /// An org client of mailbox `mailbox_id` (32 hex) holding the
    /// credential of `credential_seed`, for org `org_id` (32 hex), its pin
    /// in `state_dir`. Its join links name `LOOPBACK_URL`.
    pub fn client(
        &self,
        mailbox_id: String,
        credential_seed: Vec<u8>,
        org_id: String,
        state_dir: String,
    ) -> Result<Arc<OrgClient>, OnePassError> {
        let seed = Zeroizing::new(credential_seed);
        let credential = Credential::from_seed(&seed)?;
        let org_id = org_id_of(&org_id)?;
        let mut client = self.fake.client(credential);
        client.open(crate::mailbox::mailbox_id(&mailbox_id)?);
        Ok(OrgClient::with_store(
            Box::new(OrgStore::new(client, org_id)),
            org_id,
            PathBuf::from(state_dir),
            LOOPBACK_URL.into(),
        ))
    }
}
