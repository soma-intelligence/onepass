//! Signed requests (spec 4.7), the routes of spec 4.6 and the checks the
//! client makes on every answer.

use std::collections::HashMap;

use onepass_mailbox_proto::{
    COMMIT_BODY_MAX, COMMIT_OPS_MAX, CONTENT_TYPE, ChangesPage, ChangesQuery, CommitOp,
    CommitRequest, CommitResponse, CreateMailbox, CredentialId, CredentialRole, Enroll,
    EnrollTicket, ErrorBody, ErrorCode, GrantCredential, Located, MailboxCreated, MailboxId,
    MailboxInfo, Message, Op, PAGE_MAX_RECORDS, ProtoError, PushKind, ServerConfig, ServerRecord,
    SetCredentialRole, SetLocator, SetPush, SignatureParams, SignedEnrollTicket, TICKET_VERSION,
    content_digest, credential_id, decode, encode, hex, signature_base, signature_header,
    signature_input_header, ticket_signed_bytes,
};

use crate::credential::{Credential, CredentialKey};
use crate::http::{self, Endpoint, Http, Method, RESPONSE_MAX, Response};
use crate::{MailboxError, RETRY_AFTER_MAX};

/// Lifetime of the enroll tickets this device issues, seconds.
const TICKET_SECS: i64 = 300;

type Clock = Box<dyn Fn() -> i64 + Send + Sync>;

fn system_clock() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

fn random16() -> Result<[u8; 16], MailboxError> {
    let mut n = [0u8; 16];
    aws_lc_rs::rand::fill(&mut n).map_err(|_| MailboxError::Rng)?;
    Ok(n)
}

/// A local check of a message about to be sent.
pub(crate) fn local(e: ProtoError) -> MailboxError {
    match e {
        ProtoError::TooLarge(_) => MailboxError::TooLarge,
        _ => MailboxError::Malformed("request"),
    }
}

/// A blocking mailbox client: one endpoint, one credential, at most one
/// open mailbox.
pub struct MailboxClient {
    http: Http,
    base: String,
    credential: Credential,
    mailbox: Option<MailboxId>,
    clock: Clock,
}

impl MailboxClient {
    pub fn new(endpoint: Endpoint, credential: Credential) -> Result<Self, MailboxError> {
        let base = http::base_url(&endpoint)?;
        Ok(MailboxClient {
            http: Http::new(&endpoint)?,
            base,
            credential,
            mailbox: None,
            clock: Box::new(system_clock),
        })
    }

    /// Replaces the clock that dates signatures (Unix seconds).
    pub fn with_clock(mut self, now: Box<dyn Fn() -> i64 + Send + Sync>) -> Self {
        self.clock = now;
        self
    }

    pub fn open(&mut self, mailbox: MailboxId) {
        self.mailbox = Some(mailbox);
    }

    pub fn mailbox(&self) -> Option<MailboxId> {
        self.mailbox
    }

    pub fn credential_key(&self) -> CredentialKey {
        self.credential.public_key()
    }

    pub(crate) fn http(&self) -> &Http {
        &self.http
    }

    pub(crate) fn mailbox_path(&self) -> Result<String, MailboxError> {
        let m = self
            .mailbox
            .ok_or(MailboxError::Malformed("no mailbox open"))?;
        Ok(format!("/v1/mailboxes/{}", hex(&m)))
    }

    // --------------------------------------------------------- transport

    /// A request signed by this client's credential (spec 4.7). `target` is
    /// relative to the base URL; the body is checked against
    /// `COMMIT_BODY_MAX` before anything is signed or sent.
    pub(crate) fn signed(
        &self,
        method: Method,
        target: &str,
        body: &[u8],
    ) -> Result<Response, MailboxError> {
        if body.len() > COMMIT_BODY_MAX {
            return Err(MailboxError::TooLarge);
        }
        let digest = content_digest(body);
        let params = SignatureParams {
            created: (self.clock)(),
            nonce: random16()?,
            keyid: self.credential.id(),
        };
        let base = signature_base(method.as_str(), target, &digest, &params)
            .map_err(|_| MailboxError::Malformed("signature base"))?;
        let sig = self.credential.sign(&base);
        let mut headers = vec![
            ("content-digest", digest),
            ("signature-input", signature_input_header(&params)),
            ("signature", signature_header(&sig)),
        ];
        if matches!(method, Method::Post | Method::Put) {
            headers.push(("content-type", CONTENT_TYPE.to_string()));
        }
        let url = format!("{}{target}", self.base);
        self.http.send(method, &url, &headers, body, RESPONSE_MAX)
    }

    // -------------------------------------------------------------- routes

    /// `GET /v1/config`, the only route nobody signs.
    pub fn server_config(&self) -> Result<ServerConfig, MailboxError> {
        let url = format!("{}/v1/config", self.base);
        let r = self.http.send(Method::Get, &url, &[], &[], RESPONSE_MAX)?;
        read(expect(r, &[200])?)
    }

    /// `POST /v1/mailboxes`, signed by this credential (proof of
    /// possession). Opens the new mailbox on success.
    pub fn create(
        &mut self,
        invite: Option<&[u8]>,
        label: &[u8],
    ) -> Result<MailboxCreated, MailboxError> {
        let req = CreateMailbox {
            public_key: self.credential.public_key().to_bytes(),
            invite: invite.map(<[u8]>::to_vec),
            label: label.to_vec(),
        };
        req.check().map_err(local)?;
        let r = self
            .signed(Method::Post, "/v1/mailboxes", &encode(&req))
            .and_then(|r| expect(r, &[200]));
        let r = create_refusal(r, invite.is_none())?;
        let created: MailboxCreated = read(r)?;
        self.mailbox = Some(created.mailbox_id);
        Ok(created)
    }

    /// `POST /v1/mailboxes/{m}/credentials` with a ticket an enrolled
    /// device issued for this credential (spec 4.12). Opens the mailbox.
    pub fn enroll(
        &mut self,
        ticket: &SignedEnrollTicket,
        label: &[u8],
    ) -> Result<(), MailboxError> {
        let t = &ticket.ticket;
        let req = enroll_request(ticket, label, self.credential.public_key(), &self.base)?;
        let target = format!("/v1/mailboxes/{}/credentials", hex(&t.mailbox_id));
        let r = self.signed(Method::Post, &target, &encode(&req))?;
        expect_empty(r)?;
        self.mailbox = Some(t.mailbox_id);
        Ok(())
    }

    /// `GET /v1/mailboxes/{m}`.
    pub fn info(&self) -> Result<MailboxInfo, MailboxError> {
        let r = self.signed(Method::Get, &self.mailbox_path()?, &[])?;
        read(expect(r, &[200])?)
    }

    /// One page of `GET /v1/mailboxes/{m}/changes` (spec 4.5). `full` asks
    /// for live rows only; `ChangeFeed` chains pages the way the spec says.
    /// Checked here: a full page has no tombstone, records come after
    /// `after`, and an empty page echoes `after` and says nothing is left.
    pub fn changes(&self, after: u64, limit: u32, full: bool) -> Result<ChangesPage, MailboxError> {
        check_changes_query(after, limit)?;
        let q = ChangesQuery { after, limit, full };
        let target = format!("{}/changes?{}", self.mailbox_path()?, q.to_query());
        let r = self.signed(Method::Get, &target, &[])?;
        let page: ChangesPage = read(expect(r, &[200])?)?;
        check_page(after, limit, full, &page)?;
        Ok(page)
    }

    /// The next page of a feed, which moves on only when the page passed
    /// every check.
    pub fn next_changes(
        &self,
        feed: &mut ChangeFeed,
        limit: u32,
    ) -> Result<FeedPage, MailboxError> {
        let page = self.changes(feed.after(), limit, feed.is_full())?;
        feed.advance(page)
    }

    /// `POST /v1/mailboxes/{m}/commit`. A batch is all or nothing. A
    /// conflict answer lists only a capped prefix of the conflicting keys, in
    /// batch order (spec 4.6): store those, resubmit, and the rest come next.
    /// A batch naming a blob the collector took in the meantime is answered
    /// `Server(Malformed)`: announce and upload it again, or use
    /// `commit_with_blobs`, which does.
    pub fn commit(&self, ops: Vec<CommitOp>) -> Result<CommitResponse, MailboxError> {
        let target = format!("{}/commit", self.mailbox_path()?);
        let (req, body) = commit_request(ops)?;
        let r = expect(self.signed(Method::Post, &target, &body)?, &[200, 409])?;
        let status = r.status;
        let answer: CommitResponse = read(r)?;
        check_commit(&req.ops, &answer, status)?;
        Ok(answer)
    }

    /// `GET /v1/mailboxes/{m}/records/{kind}/{id}`; `None` when absent
    /// (`not_found`). A path the server does not serve answers `no_route`
    /// and comes back as `Server(NoRoute)`, never as `None`.
    pub fn record(&self, kind: u8, id: [u8; 16]) -> Result<Option<ServerRecord>, MailboxError> {
        if kind == 0 {
            return Err(MailboxError::Malformed("kind zero"));
        }
        let target = format!("{}/records/{kind}/{}", self.mailbox_path()?, hex(&id));
        let r = match self
            .signed(Method::Get, &target, &[])
            .and_then(|r| expect(r, &[200]))
        {
            Err(MailboxError::Server(ErrorCode::NotFound)) => return Ok(None),
            r => r?,
        };
        let rec: ServerRecord = read(r)?;
        check_record(kind, id, &rec)?;
        Ok(Some(rec))
    }

    /// `DELETE /v1/mailboxes/{m}/credentials/{c}`.
    pub fn revoke(&self, credential: CredentialId) -> Result<(), MailboxError> {
        let target = format!("{}/credentials/{}", self.mailbox_path()?, hex(&credential));
        expect_empty(self.signed(Method::Delete, &target, &[])?)
    }

    /// `POST /v1/mailboxes/{m}/grants`: a manager lets `public_key` in with
    /// `role`, without a ticket (spec D.7). Returns the new credential's id,
    /// computed here from the key (the answer carries none).
    pub fn grant(
        &self,
        public_key: [u8; 32],
        role: CredentialRole,
        put_kinds: Option<[u8; 32]>,
        label: &[u8],
    ) -> Result<CredentialId, MailboxError> {
        let target = format!("{}/grants", self.mailbox_path()?);
        let req = grant_request(public_key, role, put_kinds, label)?;
        expect_empty(self.signed(Method::Post, &target, &encode(&req))?)?;
        Ok(credential_id(&public_key))
    }

    /// `PUT /v1/mailboxes/{m}/credentials/{c}/role` (manager only).
    pub fn set_role(
        &self,
        credential: CredentialId,
        role: CredentialRole,
        put_kinds: Option<[u8; 32]>,
    ) -> Result<(), MailboxError> {
        let target = format!(
            "{}/credentials/{}/role",
            self.mailbox_path()?,
            hex(&credential)
        );
        let req = role_request(role, put_kinds)?;
        expect_empty(self.signed(Method::Put, &target, &encode(&req))?)
    }

    /// `PUT /v1/mailboxes/{m}/locator` (manager only, spec D.4).
    pub fn set_locator(&self, locator: [u8; 16]) -> Result<(), MailboxError> {
        let target = format!("{}/locator", self.mailbox_path()?);
        let req = SetLocator { locator };
        expect_empty(self.signed(Method::Put, &target, &encode(&req))?)
    }

    /// `DELETE /v1/mailboxes/{m}`: the creator abandons the mailbox within
    /// 24 hours of its creation (spec D.5).
    pub fn abandon(&self) -> Result<(), MailboxError> {
        expect_empty(self.signed(Method::Delete, &self.mailbox_path()?, &[])?)
    }

    /// `PUT /v1/mailboxes/{m}/push`.
    pub fn set_push(&self, kind: PushKind, token: &[u8]) -> Result<(), MailboxError> {
        let target = format!("{}/push", self.mailbox_path()?);
        let req = push_request(kind, token)?;
        expect_empty(self.signed(Method::Put, &target, &encode(&req))?)
    }

    /// An enroll ticket for `new_credential_pub`, valid 300 s from `now`,
    /// signed by this credential (spec 4.12). No request is made.
    pub fn issue_ticket(
        &self,
        new_credential_pub: CredentialKey,
        now: i64,
    ) -> Result<SignedEnrollTicket, MailboxError> {
        issue_ticket(
            &self.credential,
            &self.base,
            self.mailbox,
            new_credential_pub,
            now,
        )
    }
}

// ------------------------------------------------------- shared checks
//
// The request building and answer checks below are the client's whole
// judgement of the server. `FakeMailboxClient` (feature `testing`) runs the
// very same functions, so a test against the in-memory model checks what
// the real client checks.

/// `limit` 1 to 1000, `after` a Postgres bigint.
pub(crate) fn check_changes_query(after: u64, limit: u32) -> Result<(), MailboxError> {
    if limit == 0 || limit > PAGE_MAX_RECORDS || after > i64::MAX as u64 {
        return Err(MailboxError::Malformed("changes query"));
    }
    Ok(())
}

/// A page answers the query it was read for: no more records than asked,
/// records after `after`, an empty page echoes `after` and says nothing is
/// left, and a full page has no tombstone.
pub(crate) fn check_page(
    after: u64,
    limit: u32,
    full: bool,
    page: &ChangesPage,
) -> Result<(), MailboxError> {
    if page.records.len() > limit as usize {
        return Err(MailboxError::Malformed("page longer than asked"));
    }
    match page.records.first() {
        Some(first) if first.seq <= after => {
            return Err(MailboxError::Malformed("record before cursor"));
        }
        None if page.next_after != after || page.more => {
            return Err(MailboxError::Malformed("empty page"));
        }
        _ => {}
    }
    if full && page.records.iter().any(|r| r.body.is_none()) {
        return Err(MailboxError::Malformed("tombstone in a full fetch"));
    }
    Ok(())
}

/// The batch as sent: not empty, at most `COMMIT_OPS_MAX` operations, each
/// key once, and its encoding at most `COMMIT_BODY_MAX`.
pub(crate) fn commit_request(ops: Vec<CommitOp>) -> Result<(CommitRequest, Vec<u8>), MailboxError> {
    if ops.is_empty() {
        return Err(MailboxError::Malformed("empty commit"));
    }
    if ops.len() > COMMIT_OPS_MAX {
        return Err(MailboxError::TooLarge);
    }
    let req = CommitRequest { ops };
    req.check().map_err(local)?;
    let body = encode(&req);
    if body.len() > COMMIT_BODY_MAX {
        return Err(MailboxError::TooLarge);
    }
    Ok((req, body))
}

/// A commit answer, checked against the batch.
pub(crate) fn check_commit(
    ops: &[CommitOp],
    answer: &CommitResponse,
    status: u16,
) -> Result<(), MailboxError> {
    match (answer, status) {
        (CommitResponse::Applied { seqs }, 200) => check_applied(ops, seqs),
        (CommitResponse::Conflict { current }, 409) => check_conflicts(ops, current),
        _ => Err(MailboxError::Malformed("commit status")),
    }
}

/// `/v1/config` may advertise open signup while the database switch is off
/// (spec 4.9): a create without invite answered malformed says so plainly.
pub(crate) fn create_refusal<T>(
    r: Result<T, MailboxError>,
    without_invite: bool,
) -> Result<T, MailboxError> {
    match r {
        Err(MailboxError::Server(ErrorCode::Malformed)) if without_invite => {
            Err(MailboxError::InviteRequired)
        }
        r => r,
    }
}

/// An enroll body for this key and this server only.
pub(crate) fn enroll_request(
    ticket: &SignedEnrollTicket,
    label: &[u8],
    own: CredentialKey,
    base: &str,
) -> Result<Enroll, MailboxError> {
    let t = &ticket.ticket;
    if t.new_credential_pub != own.to_bytes() {
        return Err(MailboxError::Malformed("ticket for another key"));
    }
    if t.mailbox_url != base {
        return Err(MailboxError::Malformed("ticket for another server"));
    }
    let req = Enroll {
        ticket: ticket.clone(),
        label: label.to_vec(),
    };
    req.check().map_err(local)?;
    Ok(req)
}

pub(crate) fn grant_request(
    public_key: [u8; 32],
    role: CredentialRole,
    put_kinds: Option<[u8; 32]>,
    label: &[u8],
) -> Result<GrantCredential, MailboxError> {
    let req = GrantCredential {
        public_key,
        role,
        put_kinds,
        label: label.to_vec(),
    };
    req.check().map_err(local)?;
    Ok(req)
}

pub(crate) fn role_request(
    role: CredentialRole,
    put_kinds: Option<[u8; 32]>,
) -> Result<SetCredentialRole, MailboxError> {
    let req = SetCredentialRole { role, put_kinds };
    req.check().map_err(local)?;
    Ok(req)
}

pub(crate) fn push_request(kind: PushKind, token: &[u8]) -> Result<SetPush, MailboxError> {
    let req = SetPush {
        kind,
        token: token.to_vec(),
    };
    req.check().map_err(local)?;
    if kind != PushKind::None && token.is_empty() {
        return Err(MailboxError::Malformed("push kind without token"));
    }
    Ok(req)
}

/// An enroll ticket for `new_credential_pub`, valid `TICKET_SECS` from
/// `now`, signed by `credential` for the mailbox at `base`.
pub(crate) fn issue_ticket(
    credential: &Credential,
    base: &str,
    mailbox: Option<MailboxId>,
    new_credential_pub: CredentialKey,
    now: i64,
) -> Result<SignedEnrollTicket, MailboxError> {
    let mailbox_id = mailbox.ok_or(MailboxError::Malformed("no mailbox open"))?;
    let ticket = EnrollTicket {
        version: TICKET_VERSION,
        mailbox_url: base.to_string(),
        mailbox_id,
        new_credential_pub: new_credential_pub.to_bytes(),
        expires_at: now
            .checked_add(TICKET_SECS)
            .ok_or(MailboxError::Malformed("ticket time"))?,
        nonce: random16()?,
    };
    ticket.check().map_err(local)?;
    let sig = credential.sign(&ticket_signed_bytes(&ticket));
    Ok(SignedEnrollTicket {
        ticket,
        approver_credential: credential.id(),
        sig,
    })
}

/// `GET /v1/locate/{locator}` (spec D.4): the mailbox a locator names, or
/// `None` (`not_found`: unknown, or the mailbox was abandoned). Unsigned:
/// a device restoring from its Emergency Kit holds no credential yet. The
/// id is only where to look: the recovery credential signs there next, and
/// what it reads is checked by the core.
pub fn locate(endpoint: &Endpoint, locator: [u8; 16]) -> Result<Option<MailboxId>, MailboxError> {
    let http = Http::new(endpoint)?;
    let url = format!("{}/v1/locate/{}", http::base_url(endpoint)?, hex(&locator));
    match http
        .send(Method::Get, &url, &[], &[], RESPONSE_MAX)
        .and_then(|r| expect(r, &[200]))
    {
        Err(MailboxError::Server(ErrorCode::NotFound)) => Ok(None),
        r => Ok(Some(read::<Located>(r?)?.mailbox_id)),
    }
}

/// A record answer is for the key asked.
pub(crate) fn check_record(kind: u8, id: [u8; 16], rec: &ServerRecord) -> Result<(), MailboxError> {
    if rec.kind != kind || rec.id != id {
        return Err(MailboxError::Malformed("record for another key"));
    }
    Ok(())
}

/// What an error code becomes for the caller (the status was checked).
pub(crate) fn error_of(code: ErrorCode, retry_after: Option<u32>) -> MailboxError {
    match code {
        ErrorCode::StaleRequest => MailboxError::Stale,
        ErrorCode::CursorExpired => MailboxError::CursorExpired,
        ErrorCode::TooLarge => MailboxError::TooLarge,
        ErrorCode::Forbidden => MailboxError::Forbidden,
        ErrorCode::RateLimited | ErrorCode::Retry => MailboxError::Retry {
            after: cap(retry_after),
        },
        code => MailboxError::Server(code),
    }
}

/// Applied: one entry per operation, a seq for every put (a delete that
/// changed nothing has none), seqs strictly increasing in batch order.
fn check_applied(ops: &[CommitOp], seqs: &[Option<u64>]) -> Result<(), MailboxError> {
    let bad = MailboxError::Malformed("commit seqs");
    if seqs.len() != ops.len() {
        return Err(bad);
    }
    let mut last = 0u64;
    for (op, seq) in ops.iter().zip(seqs) {
        match (seq, &op.op) {
            (None, Op::Delete) => {}
            (None, Op::Put { .. }) => return Err(bad),
            (Some(s), _) => {
                if *s <= last {
                    return Err(bad);
                }
                last = *s;
            }
        }
    }
    Ok(())
}

/// Conflict: a non-empty list of puts of the batch, in batch order, each
/// at most once, a server row (if any) for that very key.
fn check_conflicts(
    ops: &[CommitOp],
    current: &[onepass_mailbox_proto::ConflictEntry],
) -> Result<(), MailboxError> {
    let bad = MailboxError::Malformed("commit conflicts");
    if current.is_empty() {
        return Err(bad);
    }
    let index: HashMap<(u8, [u8; 16]), usize> = ops
        .iter()
        .enumerate()
        .map(|(i, o)| ((o.kind, o.id), i))
        .collect();
    let mut prev: Option<usize> = None;
    for c in current {
        let i = *index.get(&(c.kind, c.id)).ok_or(bad.clone())?;
        if prev.is_some_and(|p| i <= p) || matches!(ops[i].op, Op::Delete) {
            return Err(bad);
        }
        if c.server
            .as_ref()
            .is_some_and(|s| s.kind != c.kind || s.id != c.id)
        {
            return Err(bad);
        }
        prev = Some(i);
    }
    Ok(())
}

/// The answer's status is one of `ok`, or it becomes the error it carries.
pub(crate) fn expect(r: Response, ok: &[u16]) -> Result<Response, MailboxError> {
    if ok.contains(&r.status) {
        return Ok(r);
    }
    match r.status {
        300..=399 => return Err(MailboxError::Malformed("redirect")),
        200..=299 => return Err(MailboxError::Malformed("status")),
        _ => {}
    }
    let body = is_postcard(&r)
        .then(|| decode::<ErrorBody>(&r.body).ok())
        .flatten();
    let Some(body) = body else {
        // A gateway in front of the function, or nothing we understand.
        return Err(match r.status {
            429 => MailboxError::Retry {
                after: cap(r.retry_after),
            },
            413 => MailboxError::TooLarge,
            502..=504 => MailboxError::Retry { after: None },
            _ => MailboxError::Malformed("error body"),
        });
    };
    // The code must come with its own status (spec 4.6): a 500 that says
    // cursor_expired would otherwise start a full fetch.
    if status_of(body.code) != r.status {
        return Err(MailboxError::Malformed("error status"));
    }
    Err(error_of(body.code, body.retry_after.or(r.retry_after)))
}

fn cap(after: Option<u32>) -> Option<u32> {
    after.map(|s| s.min(RETRY_AFTER_MAX))
}

/// HTTP status of each error code (spec 4.6).
fn status_of(code: ErrorCode) -> u16 {
    match code {
        ErrorCode::Malformed => 400,
        ErrorCode::BadSignature | ErrorCode::StaleRequest | ErrorCode::Replay => 401,
        ErrorCode::UnknownCredential
        | ErrorCode::RevokedCredential
        | ErrorCode::Frozen
        | ErrorCode::Forbidden => 403,
        ErrorCode::NotFound | ErrorCode::NoRoute => 404,
        ErrorCode::CursorExpired => 410,
        ErrorCode::TooLarge => 413,
        ErrorCode::Quota => 422,
        ErrorCode::RateLimited => 429,
        ErrorCode::Retry => 503,
    }
}

fn expect_empty(r: Response) -> Result<(), MailboxError> {
    let r = expect(r, &[204])?;
    if !r.body.is_empty() {
        return Err(MailboxError::Malformed("body on 204"));
    }
    Ok(())
}

fn is_postcard(r: &Response) -> bool {
    r.content_type.as_deref().is_some_and(|t| {
        let t = t.trim();
        t.eq_ignore_ascii_case(CONTENT_TYPE)
            || t.get(..CONTENT_TYPE.len())
                .is_some_and(|p| p.eq_ignore_ascii_case(CONTENT_TYPE))
                && t[CONTENT_TYPE.len()..].trim_start().starts_with(';')
    })
}

/// Strict decode of a postcard answer.
pub(crate) fn read<M: Message>(r: Response) -> Result<M, MailboxError> {
    if !is_postcard(&r) {
        return Err(MailboxError::Malformed("content type"));
    }
    decode(&r.body).map_err(|_| MailboxError::Malformed("response"))
}

// ------------------------------------------------------------------- feed

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// `first`: head and incarnation of the first page, once read.
    /// `stored`: the incarnation the local zone holds, if any.
    Full {
        after: u64,
        first: Option<(u64, u64)>,
        stored: Option<u64>,
    },
    Incremental {
        after: u64,
        incarnation: u64,
    },
}

/// Where a change feed stands (spec 4.5). A full fetch keeps `full=1` on
/// every page, remembers the head of its first page, and once done goes
/// on incrementally from that head. Store `after()` and `incarnation()` of
/// an incremental feed to resume it later.
///
/// Every page is checked against the incarnation the feed holds: a page
/// of another one, between pages or against the stored value, is
/// `MailboxError::IncarnationChanged` and the feed does not move. The
/// feed never restarts on its own: the caller resets its zone first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChangeFeed(Mode);

impl ChangeFeed {
    /// A full fetch for a zone that holds nothing yet: a first sync, or
    /// after a reset for a changed incarnation. Its first page fixes the
    /// incarnation.
    pub fn full() -> ChangeFeed {
        ChangeFeed(Mode::Full {
            after: 0,
            first: None,
            stored: None,
        })
    }

    /// A full fetch for a zone that holds `incarnation` (after a
    /// `CursorExpired`): a page of another incarnation is refused.
    pub fn full_for(incarnation: u64) -> ChangeFeed {
        ChangeFeed(Mode::Full {
            after: 0,
            first: None,
            stored: Some(incarnation),
        })
    }

    /// Resumes an incremental feed at `after` of `incarnation`.
    pub fn incremental(after: u64, incarnation: u64) -> ChangeFeed {
        ChangeFeed(Mode::Incremental { after, incarnation })
    }

    pub fn is_full(&self) -> bool {
        matches!(self.0, Mode::Full { .. })
    }

    pub fn after(&self) -> u64 {
        match self.0 {
            Mode::Full { after, .. } | Mode::Incremental { after, .. } => after,
        }
    }

    /// The incarnation every page must carry; `None` only for `full()`
    /// before its first page.
    pub fn incarnation(&self) -> Option<u64> {
        match self.0 {
            Mode::Full { first, stored, .. } => first.map(|f| f.1).or(stored),
            Mode::Incremental { incarnation, .. } => Some(incarnation),
        }
    }

    /// Moves the feed past a page read at `after()` (already checked by
    /// `check_page`); the feed does not move when the page fails a check.
    pub(crate) fn advance(&mut self, page: ChangesPage) -> Result<FeedPage, MailboxError> {
        if let Some(expected) = self.incarnation()
            && page.incarnation != expected
        {
            return Err(MailboxError::IncarnationChanged {
                expected,
                found: page.incarnation,
            });
        }
        let (next, more, full_done) = match self.0 {
            Mode::Full { first, stored, .. } => {
                let (head, incarnation) = match first {
                    None => (page.head, page.incarnation),
                    Some(f) => {
                        if page.head < f.0 {
                            return Err(MailboxError::Malformed("head went back"));
                        }
                        f
                    }
                };
                if page.more {
                    let next = Mode::Full {
                        after: page.next_after,
                        first: Some((head, incarnation)),
                        stored,
                    };
                    (next, true, false)
                } else {
                    // Everything written since the first page has a seq above
                    // its head: go on incrementally from there (spec 4.5).
                    let next = Mode::Incremental {
                        after: head,
                        incarnation,
                    };
                    (next, page.head != head, true)
                }
            }
            Mode::Incremental { incarnation, .. } => (
                Mode::Incremental {
                    after: page.next_after,
                    incarnation,
                },
                page.more,
                false,
            ),
        };
        let full = self.is_full();
        self.0 = next;
        Ok(FeedPage {
            incarnation: page.incarnation,
            min_cursor: page.min_cursor,
            records: page.records,
            full,
            full_done,
            more,
        })
    }
}

/// A page read through a `ChangeFeed`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedPage {
    /// The incarnation of the page, already checked against the feed's.
    pub incarnation: u64,
    pub min_cursor: u64,
    pub records: Vec<ServerRecord>,
    /// The page came from a full fetch.
    pub full: bool,
    /// The last page of a full fetch: the feed is incremental from here.
    pub full_done: bool,
    /// Call `next_changes` again: there is more to read now.
    pub more: bool,
}
