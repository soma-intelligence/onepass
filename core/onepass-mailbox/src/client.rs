//! Signed requests (spec 4.7), the routes of spec 4.6 and the checks the
//! client makes on every answer.

use std::collections::HashMap;

use onepass_mailbox_proto::{
    COMMIT_BODY_MAX, COMMIT_OPS_MAX, CONTENT_TYPE, ChangesPage, ChangesQuery, CommitOp,
    CommitRequest, CommitResponse, CreateMailbox, CredentialId, Enroll, EnrollTicket, ErrorBody,
    ErrorCode, MailboxCreated, MailboxId, MailboxInfo, Message, Op, PAGE_MAX_RECORDS, ProtoError,
    PushKind, ServerConfig, ServerRecord, SetPush, SignatureParams, SignedEnrollTicket,
    TICKET_VERSION, content_digest, decode, encode, hex, signature_base, signature_header,
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
        let r = match r {
            // `/v1/config` may advertise open signup while the database
            // switch is off (spec 4.9): without an invite, say so plainly.
            Err(MailboxError::Server(ErrorCode::Malformed)) if invite.is_none() => {
                return Err(MailboxError::InviteRequired);
            }
            r => r?,
        };
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
        if t.new_credential_pub != self.credential.public_key().to_bytes() {
            return Err(MailboxError::Malformed("ticket for another key"));
        }
        if t.mailbox_url != self.base {
            return Err(MailboxError::Malformed("ticket for another server"));
        }
        let req = Enroll {
            ticket: ticket.clone(),
            label: label.to_vec(),
        };
        req.check().map_err(local)?;
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
        if limit == 0 || limit > PAGE_MAX_RECORDS || after > i64::MAX as u64 {
            return Err(MailboxError::Malformed("changes query"));
        }
        let q = ChangesQuery { after, limit, full };
        let target = format!("{}/changes?{}", self.mailbox_path()?, q.to_query());
        let r = self.signed(Method::Get, &target, &[])?;
        let page: ChangesPage = read(expect(r, &[200])?)?;
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
        let (next, more, full_done) = match feed.0 {
            Mode::Full { first, .. } => {
                let (head, incarnation) = match first {
                    None => (page.head, page.incarnation),
                    Some(f) => {
                        if page.incarnation != f.1 {
                            return Err(MailboxError::Malformed(
                                "incarnation changed in a full fetch",
                            ));
                        }
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
                    };
                    (next, true, false)
                } else {
                    // Everything written since the first page has a seq above
                    // its head: go on incrementally from there (spec 4.5).
                    (Mode::Incremental { after: head }, page.head != head, true)
                }
            }
            Mode::Incremental { .. } => (
                Mode::Incremental {
                    after: page.next_after,
                },
                page.more,
                false,
            ),
        };
        let full = feed.is_full();
        feed.0 = next;
        Ok(FeedPage {
            incarnation: page.incarnation,
            min_cursor: page.min_cursor,
            records: page.records,
            full,
            full_done,
            more,
        })
    }

    /// `POST /v1/mailboxes/{m}/commit`. A batch is all or nothing. A
    /// conflict answer lists only a capped prefix of the conflicting keys, in
    /// batch order (spec 4.6): store those, resubmit, and the rest come next.
    /// A batch naming a blob the collector took in the meantime is answered
    /// `Server(Malformed)`: announce and upload it again, or use
    /// `commit_with_blobs`, which does.
    pub fn commit(&self, ops: Vec<CommitOp>) -> Result<CommitResponse, MailboxError> {
        let target = format!("{}/commit", self.mailbox_path()?);
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
        let r = expect(self.signed(Method::Post, &target, &body)?, &[200, 409])?;
        let status = r.status;
        let answer: CommitResponse = read(r)?;
        match (&answer, status) {
            (CommitResponse::Applied { seqs }, 200) => check_applied(&req.ops, seqs)?,
            (CommitResponse::Conflict { current }, 409) => check_conflicts(&req.ops, current)?,
            _ => return Err(MailboxError::Malformed("commit status")),
        }
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
        if rec.kind != kind || rec.id != id {
            return Err(MailboxError::Malformed("record for another key"));
        }
        Ok(Some(rec))
    }

    /// `DELETE /v1/mailboxes/{m}/credentials/{c}`.
    pub fn revoke(&self, credential: CredentialId) -> Result<(), MailboxError> {
        let target = format!("{}/credentials/{}", self.mailbox_path()?, hex(&credential));
        expect_empty(self.signed(Method::Delete, &target, &[])?)
    }

    /// `PUT /v1/mailboxes/{m}/push`.
    pub fn set_push(&self, kind: PushKind, token: &[u8]) -> Result<(), MailboxError> {
        let target = format!("{}/push", self.mailbox_path()?);
        let req = SetPush {
            kind,
            token: token.to_vec(),
        };
        req.check().map_err(local)?;
        if kind != PushKind::None && token.is_empty() {
            return Err(MailboxError::Malformed("push kind without token"));
        }
        expect_empty(self.signed(Method::Put, &target, &encode(&req))?)
    }

    /// An enroll ticket for `new_credential_pub`, valid 300 s from `now`,
    /// signed by this credential (spec 4.12). No request is made.
    pub fn issue_ticket(
        &self,
        new_credential_pub: CredentialKey,
        now: i64,
    ) -> Result<SignedEnrollTicket, MailboxError> {
        let mailbox_id = self
            .mailbox
            .ok_or(MailboxError::Malformed("no mailbox open"))?;
        let ticket = EnrollTicket {
            version: TICKET_VERSION,
            mailbox_url: self.base.clone(),
            mailbox_id,
            new_credential_pub: new_credential_pub.to_bytes(),
            expires_at: now
                .checked_add(TICKET_SECS)
                .ok_or(MailboxError::Malformed("ticket time"))?,
            nonce: random16()?,
        };
        ticket.check().map_err(local)?;
        let sig = self.credential.sign(&ticket_signed_bytes(&ticket));
        Ok(SignedEnrollTicket {
            ticket,
            approver_credential: self.credential.id(),
            sig,
        })
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
    Err(match body.code {
        ErrorCode::StaleRequest => MailboxError::Stale,
        ErrorCode::CursorExpired => MailboxError::CursorExpired,
        ErrorCode::TooLarge => MailboxError::TooLarge,
        ErrorCode::RateLimited | ErrorCode::Retry => MailboxError::Retry {
            after: cap(body.retry_after.or(r.retry_after)),
        },
        code => MailboxError::Server(code),
    })
}

fn cap(after: Option<u32>) -> Option<u32> {
    after.map(|s| s.min(RETRY_AFTER_MAX))
}

/// HTTP status of each error code (spec 4.6).
fn status_of(code: ErrorCode) -> u16 {
    match code {
        ErrorCode::Malformed => 400,
        ErrorCode::BadSignature | ErrorCode::StaleRequest | ErrorCode::Replay => 401,
        ErrorCode::UnknownCredential | ErrorCode::RevokedCredential | ErrorCode::Frozen => 403,
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
    Full {
        after: u64,
        first: Option<(u64, u64)>,
    },
    Incremental {
        after: u64,
    },
}

/// Where a change feed stands (spec 4.5). A full fetch keeps `full=1` on
/// every page, remembers the head of its first page, and once done goes
/// on incrementally from that head. Store `after()` of an incremental feed
/// to resume it later.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChangeFeed(Mode);

impl ChangeFeed {
    /// A full fetch from the start: after a first sync, a
    /// `CursorExpired`, or a changed incarnation.
    pub fn full() -> ChangeFeed {
        ChangeFeed(Mode::Full {
            after: 0,
            first: None,
        })
    }

    pub fn incremental(after: u64) -> ChangeFeed {
        ChangeFeed(Mode::Incremental { after })
    }

    pub fn is_full(&self) -> bool {
        matches!(self.0, Mode::Full { .. })
    }

    pub fn after(&self) -> u64 {
        match self.0 {
            Mode::Full { after, .. } | Mode::Incremental { after } => after,
        }
    }
}

/// A page read through a `ChangeFeed`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedPage {
    /// Compare with the stored incarnation before applying anything: a
    /// different one means the server lost data (spec 4.5).
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
