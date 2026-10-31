//! What a mailbox offers its client, as a trait: `MailboxClient` talks to a
//! real server, `testing::FakeMailboxClient` (feature `testing`) to the
//! in-memory model. The sync engine and the conformance suite take either.

use onepass_mailbox_proto::{
    Body, ChangesPage, CommitOp, CommitResponse, CredentialId, MailboxCreated, MailboxId,
    MailboxInfo, PushKind, ServerConfig, ServerRecord, SignedEnrollTicket,
};

use crate::client::{ChangeFeed, FeedPage, MailboxClient};
use crate::credential::CredentialKey;
use crate::{MailboxError, blobs};

/// The client side of the mailbox API (spec 4.6). Every answer has passed
/// the client's checks before it is returned, whichever implementation
/// produced it.
pub trait MailboxApi: Send {
    /// `GET /v1/config`.
    fn server_config(&self) -> Result<ServerConfig, MailboxError>;

    /// Creates a mailbox owned by this credential and opens it.
    fn create(
        &mut self,
        invite: Option<&[u8]>,
        label: &[u8],
    ) -> Result<MailboxCreated, MailboxError>;

    fn open(&mut self, mailbox: MailboxId);

    fn mailbox(&self) -> Option<MailboxId>;

    fn credential_key(&self) -> CredentialKey;

    fn info(&self) -> Result<MailboxInfo, MailboxError>;

    /// One page of changes after `after` (spec 4.5).
    fn changes(&self, after: u64, limit: u32, full: bool) -> Result<ChangesPage, MailboxError>;

    /// The next page of a feed; the feed moves only on a page that passed.
    fn next_changes(&self, feed: &mut ChangeFeed, limit: u32) -> Result<FeedPage, MailboxError> {
        let page = self.changes(feed.after(), limit, feed.is_full())?;
        feed.advance(page)
    }

    /// One atomic batch (spec 4.6).
    fn commit(&self, ops: Vec<CommitOp>) -> Result<CommitResponse, MailboxError>;

    /// `None` when the key was never written (a tombstone is `Some`).
    fn record(&self, kind: u8, id: [u8; 16]) -> Result<Option<ServerRecord>, MailboxError>;

    /// Joins the mailbox a ticket names, then opens it.
    fn enroll(&mut self, ticket: &SignedEnrollTicket, label: &[u8]) -> Result<(), MailboxError>;

    fn revoke(&self, credential: CredentialId) -> Result<(), MailboxError>;

    fn set_push(&self, kind: PushKind, token: &[u8]) -> Result<(), MailboxError>;

    /// A ticket for `new_credential_pub`, valid 300 s from `now`. No request.
    fn issue_ticket(
        &self,
        new_credential_pub: CredentialKey,
        now: i64,
    ) -> Result<SignedEnrollTicket, MailboxError>;

    /// Announces the blobs and uploads those the mailbox does not hold.
    fn upload_blobs(&self, blobs: &[&[u8]]) -> Result<(), MailboxError>;

    /// The bytes of a body, a blob checked against its size and SHA-256.
    fn fetch_body(&self, body: &Body) -> Result<Vec<u8>, MailboxError>;

    /// `commit` for a batch naming blobs, re-announcing once if a blob was
    /// collected in between (spec 4.11).
    fn commit_with_blobs(
        &self,
        ops: Vec<CommitOp>,
        blobs: &[&[u8]],
    ) -> Result<CommitResponse, MailboxError> {
        blobs::commit_with_blobs(self, ops, blobs)
    }
}

impl MailboxApi for MailboxClient {
    fn server_config(&self) -> Result<ServerConfig, MailboxError> {
        MailboxClient::server_config(self)
    }

    fn create(
        &mut self,
        invite: Option<&[u8]>,
        label: &[u8],
    ) -> Result<MailboxCreated, MailboxError> {
        MailboxClient::create(self, invite, label)
    }

    fn open(&mut self, mailbox: MailboxId) {
        MailboxClient::open(self, mailbox);
    }

    fn mailbox(&self) -> Option<MailboxId> {
        MailboxClient::mailbox(self)
    }

    fn credential_key(&self) -> CredentialKey {
        MailboxClient::credential_key(self)
    }

    fn info(&self) -> Result<MailboxInfo, MailboxError> {
        MailboxClient::info(self)
    }

    fn changes(&self, after: u64, limit: u32, full: bool) -> Result<ChangesPage, MailboxError> {
        MailboxClient::changes(self, after, limit, full)
    }

    fn commit(&self, ops: Vec<CommitOp>) -> Result<CommitResponse, MailboxError> {
        MailboxClient::commit(self, ops)
    }

    fn record(&self, kind: u8, id: [u8; 16]) -> Result<Option<ServerRecord>, MailboxError> {
        MailboxClient::record(self, kind, id)
    }

    fn enroll(&mut self, ticket: &SignedEnrollTicket, label: &[u8]) -> Result<(), MailboxError> {
        MailboxClient::enroll(self, ticket, label)
    }

    fn revoke(&self, credential: CredentialId) -> Result<(), MailboxError> {
        MailboxClient::revoke(self, credential)
    }

    fn set_push(&self, kind: PushKind, token: &[u8]) -> Result<(), MailboxError> {
        MailboxClient::set_push(self, kind, token)
    }

    fn issue_ticket(
        &self,
        new_credential_pub: CredentialKey,
        now: i64,
    ) -> Result<SignedEnrollTicket, MailboxError> {
        MailboxClient::issue_ticket(self, new_credential_pub, now)
    }

    fn upload_blobs(&self, blobs: &[&[u8]]) -> Result<(), MailboxError> {
        MailboxClient::upload_blobs(self, blobs)
    }

    fn fetch_body(&self, body: &Body) -> Result<Vec<u8>, MailboxError> {
        MailboxClient::fetch_body(self, body)
    }
}
