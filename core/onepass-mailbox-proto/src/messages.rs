//! Message types and the strict postcard codec.

use std::collections::BTreeSet;
use std::fmt;

use serde::Deserialize;
use serde::Serialize;
use serde::de::DeserializeOwned;

pub const PROTO_VERSION: u8 = 1;
pub const CONTENT_TYPE: &str = "application/vnd.onepass.mailbox.v1+postcard";
pub const INLINE_MAX: usize = 16 * 1024;
pub const RECORD_MAX: usize = 900 * 1024;
pub const COMMIT_BODY_MAX: usize = 4 << 20;
pub const COMMIT_OPS_MAX: usize = 20_000;
pub const PAGE_MAX_RECORDS: u32 = 1_000;
pub const PAGE_MAX_BYTES: usize = 4 << 20;
pub const LABEL_MAX: usize = 64;
pub const URL_MAX: usize = 256;
/// Push token, at most 4096 bytes (spec 4.6).
pub const PUSH_TOKEN_MAX: usize = 4096;
/// Invite code carried by `CreateMailbox`. Not fixed by the spec: a bound so
/// the field cannot be used to inflate a request.
pub const INVITE_MAX: usize = 256;
/// Publishable key in `ServerConfig`. Not fixed by the spec, same reason.
pub const KEY_MAX: usize = 1024;
/// A signed Storage URL carries a token and is longer than `URL_MAX`. Not
/// fixed by the spec, same reason.
pub const SIGNED_URL_MAX: usize = 2048;

pub type MailboxId = [u8; 16];
pub type CredentialId = [u8; 16];
pub type Sha256 = [u8; 32];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtoError {
    /// First byte is not `PROTO_VERSION`.
    Version,
    /// Truncated, trailing bytes, non canonical encoding or bad field.
    Format(&'static str),
    /// A cap was exceeded.
    TooLarge(&'static str),
    /// A list that must be sorted or unique is not.
    Unsorted(&'static str),
    /// Signature problems (used by the layers above this crate).
    Signature(&'static str),
    /// Clock skew (used by the layers above this crate).
    Skew,
    /// Enroll ticket expired, or valid for longer than allowed.
    Ticket(&'static str),
}

impl fmt::Display for ProtoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Version => f.write_str("unknown protocol version"),
            Self::Format(w) => write!(f, "malformed message: {w}"),
            Self::TooLarge(w) => write!(f, "too large: {w}"),
            Self::Unsorted(w) => write!(f, "not sorted or not unique: {w}"),
            Self::Signature(w) => write!(f, "bad signature: {w}"),
            Self::Skew => f.write_str("clock skew"),
            Self::Ticket(w) => write!(f, "bad enroll ticket: {w}"),
        }
    }
}

impl std::error::Error for ProtoError {}

/// A wire body. `check` enforces the invariants that the type system does not.
pub trait Message: Serialize + DeserializeOwned {
    fn check(&self) -> Result<(), ProtoError>;

    /// When the postcard encoding starts with the length of a list, its name
    /// and cap: read and compared before anything is deserialized.
    fn leading_list_cap() -> Option<(&'static str, usize)> {
        None
    }
}

/// `PROTO_VERSION`, then the postcard encoding of `m`.
pub fn encode<M: Message>(m: &M) -> Vec<u8> {
    let mut out = vec![PROTO_VERSION];
    out.extend(postcard::to_allocvec(m).expect("postcard to a Vec cannot fail"));
    out
}

/// Strict decode: version, list cap, whole buffer, canonical form, `check`.
pub fn decode<M: Message>(bytes: &[u8]) -> Result<M, ProtoError> {
    let (&version, body) = bytes.split_first().ok_or(ProtoError::Format("empty"))?;
    if version != PROTO_VERSION {
        return Err(ProtoError::Version);
    }
    if let Some((name, cap)) = M::leading_list_cap() {
        let len = leading_varint(body).ok_or(ProtoError::Format("length"))?;
        if len > cap as u64 {
            return Err(ProtoError::TooLarge(name));
        }
    }
    let (m, rest) =
        postcard::take_from_bytes::<M>(body).map_err(|_| ProtoError::Format("postcard"))?;
    if !rest.is_empty() {
        return Err(ProtoError::Format("trailing"));
    }
    let again = postcard::to_allocvec(&m).map_err(|_| ProtoError::Format("re-encode"))?;
    if again != body {
        return Err(ProtoError::Format("not canonical"));
    }
    m.check()?;
    Ok(m)
}

/// The varint at the start of `b`, or `None` if it is cut short or too long.
fn leading_varint(b: &[u8]) -> Option<u64> {
    let mut v: u64 = 0;
    for (i, &byte) in b.iter().take(10).enumerate() {
        let part = u64::from(byte & 0x7f);
        if i == 9 && part > 1 {
            return None;
        }
        v |= part << (7 * i);
        if byte & 0x80 == 0 {
            return Some(v);
        }
    }
    None
}

fn kind_ok(kind: u8) -> Result<(), ProtoError> {
    if kind == 0 {
        Err(ProtoError::Format("kind zero"))
    } else {
        Ok(())
    }
}

// ---------------------------------------------------------------- records

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Body {
    Inline(#[serde(with = "crate::bytes::vec")] Vec<u8>),
    Blob {
        #[serde(with = "crate::bytes::fixed")]
        sha256: Sha256,
        size: u32,
    },
}

impl Message for Body {
    fn check(&self) -> Result<(), ProtoError> {
        match self {
            Self::Inline(d) if d.len() > INLINE_MAX => Err(ProtoError::TooLarge("inline")),
            Self::Blob { size, .. } if *size as usize > RECORD_MAX => {
                Err(ProtoError::TooLarge("blob"))
            }
            _ => Ok(()),
        }
    }
}

/// `body: None` is a tombstone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerRecord {
    pub seq: u64,
    pub kind: u8,
    #[serde(with = "crate::bytes::fixed")]
    pub id: [u8; 16],
    pub version: u64,
    pub body: Option<Body>,
}

impl Message for ServerRecord {
    fn check(&self) -> Result<(), ProtoError> {
        kind_ok(self.kind)?;
        self.body.as_ref().map_or(Ok(()), Message::check)
    }
}

/// One page of `GET /v1/mailboxes/{m}/changes` (spec 4.5, 4.6). `head` is the
/// mailbox's last written seq when the page was read: in a full fetch the
/// client keeps the head of its first page and goes on incrementally from it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangesPage {
    pub incarnation: u64,
    pub min_cursor: u64,
    pub head: u64,
    pub records: Vec<ServerRecord>,
    pub next_after: u64,
    pub more: bool,
}

impl Message for ChangesPage {
    fn check(&self) -> Result<(), ProtoError> {
        if self.records.len() > PAGE_MAX_RECORDS as usize {
            return Err(ProtoError::TooLarge("page records"));
        }
        let mut prev: Option<u64> = None;
        for r in &self.records {
            r.check()?;
            if prev.is_some_and(|p| r.seq <= p) {
                return Err(ProtoError::Unsorted("page"));
            }
            if r.seq > self.head {
                return Err(ProtoError::Format("head"));
            }
            prev = Some(r.seq);
        }
        // An empty page echoes the requested `after`: the client checks that.
        if let Some(last) = self.records.last()
            && self.next_after != last.seq
        {
            return Err(ProtoError::Format("next_after"));
        }
        let size = postcard::to_allocvec(self)
            .map_err(|_| ProtoError::Format("re-encode"))?
            .len();
        if size > PAGE_MAX_BYTES {
            return Err(ProtoError::TooLarge("page bytes"));
        }
        Ok(())
    }
}

/// Query string of `GET /v1/mailboxes/{m}/changes`, in its only accepted
/// spelling: `after=<seq>&limit=<1..=1000>&full=<0|1>`, decimal without sign
/// or leading zero, `after` at most `i64::MAX`. `full` asks for a full fetch (live rows only, tombstones
/// skipped, `min_cursor` ignored), otherwise the fetch is incremental.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangesQuery {
    pub after: u64,
    pub limit: u32,
    pub full: bool,
}

impl ChangesQuery {
    pub fn to_query(&self) -> String {
        format!(
            "after={}&limit={}&full={}",
            self.after,
            self.limit,
            u8::from(self.full)
        )
    }

    /// Strict parse of the query string, without the leading `?`. The value
    /// read is written back and must equal the input byte for byte.
    pub fn parse(query: &str) -> Result<Self, ProtoError> {
        fn field<'a>(item: Option<&'a str>, name: &str) -> Result<&'a str, ProtoError> {
            item.and_then(|i| i.strip_prefix(name))
                .and_then(|i| i.strip_prefix('='))
                .ok_or(ProtoError::Format("changes query"))
        }
        let bad = || ProtoError::Format("changes query");
        let mut items = query.split('&');
        let after = field(items.next(), "after")?;
        let limit = field(items.next(), "limit")?;
        let full = field(items.next(), "full")?;
        if items.next().is_some() {
            return Err(bad());
        }
        let digits =
            |v: &str| !v.is_empty() && v.len() <= 20 && v.bytes().all(|b| b.is_ascii_digit());
        if !digits(after) || !digits(limit) {
            return Err(bad());
        }
        let q = ChangesQuery {
            after: after.parse().map_err(|_| bad())?,
            limit: limit.parse().map_err(|_| bad())?,
            full: match full {
                "0" => false,
                "1" => true,
                _ => return Err(bad()),
            },
        };
        // Seqs are Postgres bigint: an after above i64::MAX names no seq.
        if q.limit == 0
            || q.limit > PAGE_MAX_RECORDS
            || q.after > i64::MAX as u64
            || q.to_query() != query
        {
            return Err(bad());
        }
        Ok(q)
    }
}

// ----------------------------------------------------------------- commit

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Op {
    Put { expected: Option<u64>, body: Body },
    Delete,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitOp {
    pub kind: u8,
    #[serde(with = "crate::bytes::fixed")]
    pub id: [u8; 16],
    pub version: u64,
    pub op: Op,
}

impl Message for Op {
    fn check(&self) -> Result<(), ProtoError> {
        match self {
            Self::Put { body, .. } => body.check(),
            Self::Delete => Ok(()),
        }
    }
}

impl Message for CommitOp {
    fn check(&self) -> Result<(), ProtoError> {
        kind_ok(self.kind)?;
        self.op.check()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitRequest {
    pub ops: Vec<CommitOp>,
}

impl Message for CommitRequest {
    fn leading_list_cap() -> Option<(&'static str, usize)> {
        Some(("ops", COMMIT_OPS_MAX))
    }

    fn check(&self) -> Result<(), ProtoError> {
        if self.ops.is_empty() {
            return Err(ProtoError::Format("empty commit"));
        }
        let mut seen = BTreeSet::new();
        for o in &self.ops {
            o.check()?;
            if !seen.insert((o.kind, o.id)) {
                return Err(ProtoError::Unsorted("commit"));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConflictEntry {
    pub kind: u8,
    #[serde(with = "crate::bytes::fixed")]
    pub id: [u8; 16],
    pub server: Option<ServerRecord>,
}

impl Message for ConflictEntry {
    fn check(&self) -> Result<(), ProtoError> {
        kind_ok(self.kind)?;
        self.server.as_ref().map_or(Ok(()), Message::check)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CommitResponse {
    /// One entry per operation, in the order sent: the seq it took, or `None`
    /// for a delete that changed nothing (absent key or tombstone already).
    /// The client stores no `server_meta` for `None`.
    Applied {
        seqs: Vec<Option<u64>>,
    },
    Conflict {
        current: Vec<ConflictEntry>,
    },
}

impl Message for CommitResponse {
    fn check(&self) -> Result<(), ProtoError> {
        match self {
            Self::Applied { seqs } => {
                if seqs.len() > COMMIT_OPS_MAX {
                    return Err(ProtoError::TooLarge("seqs"));
                }
            }
            Self::Conflict { current } => {
                if current.len() > COMMIT_OPS_MAX {
                    return Err(ProtoError::TooLarge("conflicts"));
                }
                for c in current {
                    c.check()?;
                }
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------- mailbox

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateMailbox {
    #[serde(with = "crate::bytes::fixed")]
    pub public_key: [u8; 32],
    #[serde(with = "crate::bytes::opt_vec")]
    pub invite: Option<Vec<u8>>,
    #[serde(with = "crate::bytes::vec")]
    pub label: Vec<u8>,
}

impl Message for CreateMailbox {
    fn check(&self) -> Result<(), ProtoError> {
        if self.label.len() > LABEL_MAX {
            return Err(ProtoError::TooLarge("label"));
        }
        if self.invite.as_ref().is_some_and(|i| i.len() > INVITE_MAX) {
            return Err(ProtoError::TooLarge("invite"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MailboxCreated {
    #[serde(with = "crate::bytes::fixed")]
    pub mailbox_id: MailboxId,
    pub incarnation: u64,
    #[serde(with = "crate::bytes::fixed")]
    pub wake_topic: [u8; 16],
}

impl Message for MailboxCreated {
    fn check(&self) -> Result<(), ProtoError> {
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Limits {
    pub max_bytes: u64,
    pub max_records: u32,
    pub max_credentials: u16,
    pub req_per_min: u16,
    pub max_commit_ops: u32,
}

impl Message for Limits {
    fn check(&self) -> Result<(), ProtoError> {
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Usage {
    pub bytes: u64,
    pub records: u32,
    pub credentials: u16,
}

impl Message for Usage {
    fn check(&self) -> Result<(), ProtoError> {
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MailboxInfo {
    pub incarnation: u64,
    #[serde(with = "crate::bytes::fixed")]
    pub wake_topic: [u8; 16],
    pub min_cursor: u64,
    pub limits: Limits,
    pub usage: Usage,
}

impl Message for MailboxInfo {
    fn check(&self) -> Result<(), ProtoError> {
        Ok(())
    }
}

/// `GET /v1/config`. `realtime_url` and `publishable_key` open the public
/// wake channel `mbx:<wake_topic>` (spec 4.10). A wake message only means
/// "fetch now": the client ignores its payload, whatever it holds (the
/// server's `realtime.send` adds an `id`), and never trusts it for anything.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerConfig {
    pub realtime_url: String,
    pub publishable_key: String,
    pub open_signup: bool,
}

impl Message for ServerConfig {
    fn check(&self) -> Result<(), ProtoError> {
        if self.realtime_url.len() > URL_MAX {
            return Err(ProtoError::TooLarge("url"));
        }
        if self.publishable_key.len() > KEY_MAX {
            return Err(ProtoError::TooLarge("key"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PushKind {
    None,
    Fcm,
    Apns,
    UnifiedPush,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetPush {
    pub kind: PushKind,
    #[serde(with = "crate::bytes::vec")]
    pub token: Vec<u8>,
}

impl Message for SetPush {
    fn check(&self) -> Result<(), ProtoError> {
        if self.token.len() > PUSH_TOKEN_MAX {
            return Err(ProtoError::TooLarge("token"));
        }
        if self.kind == PushKind::None && !self.token.is_empty() {
            return Err(ProtoError::Format("token without kind"));
        }
        Ok(())
    }
}

// ------------------------------------------------------------------ blobs

fn sorted_unique<T, K: Ord>(
    list: &[T],
    key: impl Fn(&T) -> K,
    name: &'static str,
) -> Result<(), ProtoError> {
    if list.len() > PAGE_MAX_RECORDS as usize {
        return Err(ProtoError::TooLarge(name));
    }
    if list.windows(2).any(|w| key(&w[0]) >= key(&w[1])) {
        return Err(ProtoError::Unsorted(name));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobAnnounce {
    #[serde(with = "crate::bytes::fixed_pairs")]
    pub blobs: Vec<(Sha256, u32)>,
}

impl Message for BlobAnnounce {
    fn leading_list_cap() -> Option<(&'static str, usize)> {
        Some(("blobs", PAGE_MAX_RECORDS as usize))
    }

    fn check(&self) -> Result<(), ProtoError> {
        sorted_unique(&self.blobs, |b| b.0, "blobs")?;
        if self.blobs.iter().any(|b| b.1 as usize > RECORD_MAX) {
            return Err(ProtoError::TooLarge("blob"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobUrls {
    #[serde(with = "crate::bytes::fixed_pairs")]
    pub urls: Vec<(Sha256, Option<String>)>,
}

impl Message for BlobUrls {
    fn leading_list_cap() -> Option<(&'static str, usize)> {
        Some(("urls", PAGE_MAX_RECORDS as usize))
    }

    fn check(&self) -> Result<(), ProtoError> {
        sorted_unique(&self.urls, |u| u.0, "urls")?;
        if self
            .urls
            .iter()
            .any(|u| u.1.as_ref().is_some_and(|s| s.len() > SIGNED_URL_MAX))
        {
            return Err(ProtoError::TooLarge("url"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobLookup {
    #[serde(with = "crate::bytes::fixed_list")]
    pub blobs: Vec<Sha256>,
}

impl Message for BlobLookup {
    fn leading_list_cap() -> Option<(&'static str, usize)> {
        Some(("blobs", PAGE_MAX_RECORDS as usize))
    }

    fn check(&self) -> Result<(), ProtoError> {
        sorted_unique(&self.blobs, |b| *b, "blobs")
    }
}

// ----------------------------------------------------------------- errors

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorCode {
    Malformed,
    BadSignature,
    StaleRequest,
    Replay,
    UnknownCredential,
    RevokedCredential,
    Frozen,
    NotFound,
    CursorExpired,
    TooLarge,
    Quota,
    RateLimited,
    Retry,
    /// 404 for a method and path the mailbox does not serve, so a client can
    /// tell a wrong base URL from a record that is absent (`NotFound`).
    NoRoute,
    /// 403: the credential's role does not allow the request (a reader
    /// that commits, a limited writer outside its kinds, a non-manager that
    /// grants, changes a role or revokes another credential, the last
    /// manager or an owner that would lose its place). Appended after
    /// `NoRoute`: the codes before it keep their bytes.
    Forbidden,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorBody {
    pub code: ErrorCode,
    pub retry_after: Option<u32>,
}

impl Message for ErrorBody {
    fn check(&self) -> Result<(), ProtoError> {
        Ok(())
    }
}

// ------------------------------------------------------------------ roles

/// What a credential may do in its mailbox (spec D.7). The server enforces
/// it as defence in depth; a client never reads it to decide a right.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CredentialRole {
    /// Reads only.
    Read,
    /// Reads and writes; with `put_kinds`, puts only those kinds and
    /// deletes nothing.
    Write,
    /// Writes, grants, changes roles, revokes other credentials.
    Manage,
}

/// The 256 bit kind set of `put_kinds`: bit k (byte k / 8, bit k % 8 from
/// the least significant, as Postgres `get_bit` numbers them) is kind k.
pub fn put_kinds_of(kinds: &[u8]) -> [u8; 32] {
    let mut set = [0u8; 32];
    for &k in kinds {
        set[usize::from(k / 8)] |= 1 << (k % 8);
    }
    set
}

/// Kind `kind` is in the set.
pub fn put_kinds_allow(set: &[u8; 32], kind: u8) -> bool {
    set[usize::from(kind / 8)] & (1 << (kind % 8)) != 0
}

fn role_check(role: CredentialRole, put_kinds: &Option<[u8; 32]>) -> Result<(), ProtoError> {
    if put_kinds.is_some() && role != CredentialRole::Write {
        return Err(ProtoError::Format("put_kinds without write role"));
    }
    Ok(())
}

/// `POST /v1/mailboxes/{m}/grants`: a manager adds a credential, no ticket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantCredential {
    #[serde(with = "crate::bytes::fixed")]
    pub public_key: [u8; 32],
    pub role: CredentialRole,
    #[serde(with = "crate::bytes::opt_fixed")]
    pub put_kinds: Option<[u8; 32]>,
    #[serde(with = "crate::bytes::vec")]
    pub label: Vec<u8>,
}

impl Message for GrantCredential {
    fn check(&self) -> Result<(), ProtoError> {
        if self.label.len() > LABEL_MAX {
            return Err(ProtoError::TooLarge("label"));
        }
        role_check(self.role, &self.put_kinds)
    }
}

/// `PUT /v1/mailboxes/{m}/credentials/{c}/role`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetCredentialRole {
    pub role: CredentialRole,
    #[serde(with = "crate::bytes::opt_fixed")]
    pub put_kinds: Option<[u8; 32]>,
}

impl Message for SetCredentialRole {
    fn check(&self) -> Result<(), ProtoError> {
        role_check(self.role, &self.put_kinds)
    }
}

impl Message for CredentialRole {
    fn check(&self) -> Result<(), ProtoError> {
        Ok(())
    }
}

// ---------------------------------------------------------------- locator

/// `PUT /v1/mailboxes/{m}/locator` (manager only, spec D.4): the 16 bytes
/// the client derives from the Secret Key. A mailbox keeps its two latest
/// locators (old and new until phase 3 of a rotation); a third drops the
/// oldest. Another mailbox may hold the same locator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetLocator {
    #[serde(with = "crate::bytes::fixed")]
    pub locator: [u8; 16],
}

impl Message for SetLocator {
    fn check(&self) -> Result<(), ProtoError> {
        Ok(())
    }
}

/// Most mailboxes one lookup answers (spec D.4).
pub const LOCATED_MAX: usize = 8;

/// `POST /v1/locate` (unsigned, spec D.4): the locator goes in the body, so
/// it never reaches a URL log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocateRequest {
    #[serde(with = "crate::bytes::fixed")]
    pub locator: [u8; 16],
}

impl Message for LocateRequest {
    fn check(&self) -> Result<(), ProtoError> {
        Ok(())
    }
}

/// `200` of `POST /v1/locate`: the live mailboxes that registered the
/// locator, oldest registration first, 1 to `LOCATED_MAX`, each once (none
/// is `404 not_found`). Several mailboxes may share a locator (two devices
/// that raced a migration, D.5; a squatter who holds the Secret Key): the
/// client tries each with its recovery credential and keeps the one the
/// core verifies as its account. An id is only where to look.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Located {
    #[serde(with = "crate::bytes::fixed_list")]
    pub mailbox_ids: Vec<MailboxId>,
}

impl Message for Located {
    fn leading_list_cap() -> Option<(&'static str, usize)> {
        Some(("mailbox_ids", LOCATED_MAX))
    }

    fn check(&self) -> Result<(), ProtoError> {
        if self.mailbox_ids.is_empty() {
            return Err(ProtoError::Format("no mailbox located"));
        }
        if self.mailbox_ids.len() > LOCATED_MAX {
            return Err(ProtoError::TooLarge("mailbox_ids"));
        }
        let unique: BTreeSet<&MailboxId> = self.mailbox_ids.iter().collect();
        if unique.len() != self.mailbox_ids.len() {
            return Err(ProtoError::Format("mailbox located twice"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{blob_sha256, hex};

    fn inline(n: usize) -> Body {
        Body::Inline(vec![7; n])
    }

    fn put(kind: u8, id: u8, body: Body) -> CommitOp {
        CommitOp {
            kind,
            id: [id; 16],
            version: 3,
            op: Op::Put {
                expected: Some(2),
                body,
            },
        }
    }

    fn rec(seq: u64) -> ServerRecord {
        ServerRecord {
            seq,
            kind: 5,
            id: [seq as u8; 16],
            version: 1,
            body: Some(inline(3)),
        }
    }

    fn rt<M: Message + PartialEq + fmt::Debug>(m: M) {
        let bytes = encode(&m);
        assert_eq!(bytes[0], PROTO_VERSION);
        assert_eq!(decode::<M>(&bytes).unwrap(), m);
    }

    #[test]
    fn round_trip_every_message() {
        rt(inline(5));
        rt(Body::Blob {
            sha256: [9; 32],
            size: 20_000,
        });
        rt(rec(1));
        rt(ServerRecord {
            body: None,
            ..rec(2)
        });
        rt(ChangesPage {
            incarnation: 4,
            min_cursor: 1,
            head: 2_000,
            records: vec![rec(3), rec(9)],
            next_after: 9,
            more: true,
        });
        rt(ChangesPage {
            incarnation: 4,
            min_cursor: 1,
            head: 2_000,
            records: vec![],
            next_after: 12,
            more: false,
        });
        rt(Op::Delete);
        rt(put(5, 1, inline(2)));
        rt(CommitOp {
            kind: 5,
            id: [1; 16],
            version: 4,
            op: Op::Delete,
        });
        rt(CommitRequest {
            ops: vec![put(5, 1, inline(2)), put(6, 1, inline(0))],
        });
        rt(CommitResponse::Applied {
            seqs: vec![Some(1), None, Some(300)],
        });
        let entry = ConflictEntry {
            kind: 5,
            id: [1; 16],
            server: Some(rec(7)),
        };
        rt(entry.clone());
        rt(CommitResponse::Conflict {
            current: vec![
                entry,
                ConflictEntry {
                    kind: 6,
                    id: [2; 16],
                    server: None,
                },
            ],
        });
        rt(CreateMailbox {
            public_key: [3; 32],
            invite: Some(vec![1, 2]),
            label: b"phone".to_vec(),
        });
        rt(MailboxCreated {
            mailbox_id: [1; 16],
            incarnation: 2,
            wake_topic: [4; 16],
        });
        let limits = Limits {
            max_bytes: 1 << 30,
            max_records: 100_000,
            max_credentials: 8,
            req_per_min: 600,
            max_commit_ops: 20_000,
        };
        let usage = Usage {
            bytes: 5,
            records: 6,
            credentials: 1,
        };
        rt(limits.clone());
        rt(usage.clone());
        rt(MailboxInfo {
            incarnation: 1,
            wake_topic: [5; 16],
            min_cursor: 0,
            limits,
            usage,
        });
        rt(ServerConfig {
            realtime_url: "wss://x.example/realtime".into(),
            publishable_key: "pk".into(),
            open_signup: true,
        });
        for kind in [
            PushKind::None,
            PushKind::Fcm,
            PushKind::Apns,
            PushKind::UnifiedPush,
        ] {
            rt(SetPush {
                kind,
                token: if kind == PushKind::None {
                    vec![]
                } else {
                    vec![1; 40]
                },
            });
        }
        rt(BlobAnnounce {
            blobs: vec![([1; 32], 20_000), ([2; 32], 30_000)],
        });
        rt(BlobUrls {
            urls: vec![([1; 32], Some("https://u".into())), ([2; 32], None)],
        });
        rt(BlobLookup {
            blobs: vec![[1; 32], [2; 32]],
        });
        for code in [
            ErrorCode::Malformed,
            ErrorCode::BadSignature,
            ErrorCode::StaleRequest,
            ErrorCode::Replay,
            ErrorCode::UnknownCredential,
            ErrorCode::RevokedCredential,
            ErrorCode::Frozen,
            ErrorCode::NotFound,
            ErrorCode::CursorExpired,
            ErrorCode::TooLarge,
            ErrorCode::Quota,
            ErrorCode::RateLimited,
            ErrorCode::Retry,
            ErrorCode::NoRoute,
            ErrorCode::Forbidden,
        ] {
            rt(ErrorBody {
                code,
                retry_after: Some(30),
            });
        }
        for role in [
            CredentialRole::Read,
            CredentialRole::Write,
            CredentialRole::Manage,
        ] {
            rt(role);
            rt(SetCredentialRole {
                role,
                put_kinds: None,
            });
            rt(GrantCredential {
                public_key: [6; 32],
                role,
                put_kinds: None,
                label: b"follower".to_vec(),
            });
        }
        let mut kinds = [0u8; 32];
        kinds[1] = 0b1100_0000;
        kinds[2] = 0b0000_0011;
        rt(GrantCredential {
            public_key: [7; 32],
            role: CredentialRole::Write,
            put_kinds: Some(kinds),
            label: vec![],
        });
        rt(SetCredentialRole {
            role: CredentialRole::Write,
            put_kinds: Some(kinds),
        });
    }

    /// The codes before `Forbidden` keep their bytes: it was appended.
    #[test]
    fn error_code_forbidden_appended() {
        let body = |code| {
            encode(&ErrorBody {
                code,
                retry_after: None,
            })
        };
        // Frozen before the change: version, variant index 13, no retry_after.
        assert_eq!(body(ErrorCode::NoRoute), [PROTO_VERSION, 13, 0]);
        assert_eq!(body(ErrorCode::Retry), [PROTO_VERSION, 12, 0]);
        assert_eq!(body(ErrorCode::Malformed), [PROTO_VERSION, 0, 0]);
        assert_eq!(body(ErrorCode::Forbidden), [PROTO_VERSION, 14, 0]);
    }

    #[test]
    fn put_kinds_only_with_write_role() {
        let kinds = Some([0xffu8; 32]);
        for role in [CredentialRole::Read, CredentialRole::Manage] {
            let g = GrantCredential {
                public_key: [1; 32],
                role,
                put_kinds: kinds,
                label: vec![],
            };
            assert_eq!(
                decode::<GrantCredential>(&encode(&g)),
                Err(ProtoError::Format("put_kinds without write role"))
            );
            let s = SetCredentialRole {
                role,
                put_kinds: kinds,
            };
            assert_eq!(
                decode::<SetCredentialRole>(&encode(&s)),
                Err(ProtoError::Format("put_kinds without write role"))
            );
        }
        let long = GrantCredential {
            public_key: [1; 32],
            role: CredentialRole::Read,
            put_kinds: None,
            label: vec![b'a'; LABEL_MAX + 1],
        };
        assert_eq!(
            decode::<GrantCredential>(&encode(&long)),
            Err(ProtoError::TooLarge("label"))
        );
    }

    /// A locator is 16 raw bytes; a lookup answers 1 to 8 distinct mailbox
    /// ids, in the server's order (oldest first), nothing else.
    #[test]
    fn locator_messages() {
        rt(SetLocator { locator: [3; 16] });
        rt(LocateRequest { locator: [3; 16] });
        let mut want = vec![PROTO_VERSION];
        want.extend([3u8; 16]);
        assert_eq!(encode(&SetLocator { locator: [3; 16] }), want);
        assert_eq!(encode(&LocateRequest { locator: [3; 16] }), want);
        let ids: Vec<MailboxId> = (0..LOCATED_MAX as u8).map(|i| [9 - i; 16]).collect();
        rt(Located {
            mailbox_ids: ids.clone(),
        });
        rt(Located {
            mailbox_ids: vec![[4; 16]],
        });
        let bad = |ids: Vec<MailboxId>| decode::<Located>(&encode(&Located { mailbox_ids: ids }));
        assert_eq!(bad(vec![]), Err(ProtoError::Format("no mailbox located")));
        assert_eq!(
            bad(vec![[1; 16], [2; 16], [1; 16]]),
            Err(ProtoError::Format("mailbox located twice"))
        );
        let mut nine = ids;
        nine.push([0x77; 16]);
        assert!(matches!(bad(nine), Err(ProtoError::TooLarge(_))));
        let mut short = vec![PROTO_VERSION];
        short.extend([3u8; 15]);
        assert!(decode::<LocateRequest>(&short).is_err());
    }

    /// Bit k of `put_kinds` is kind k: byte k / 8, bit k % 8 from the least
    /// significant (Postgres `get_bit`).
    #[test]
    fn put_kinds_bits() {
        let set = put_kinds_of(&[14, 15, 16, 17]);
        assert_eq!(set[1], 0b1100_0000);
        assert_eq!(set[2], 0b0000_0011);
        assert!(
            set.iter()
                .enumerate()
                .all(|(i, b)| i == 1 || i == 2 || *b == 0)
        );
        assert!(put_kinds_allow(&set, 14) && put_kinds_allow(&set, 17));
        assert!(!put_kinds_allow(&set, 13) && !put_kinds_allow(&set, 18));
        assert!(put_kinds_allow(&put_kinds_of(&[255]), 255));
    }

    #[test]
    fn unknown_version_refused() {
        let mut bytes = encode(&CommitRequest {
            ops: vec![put(5, 1, inline(1))],
        });
        bytes[0] = 2;
        assert_eq!(decode::<CommitRequest>(&bytes), Err(ProtoError::Version));
        assert_eq!(
            decode::<CommitRequest>(&[]),
            Err(ProtoError::Format("empty"))
        );
    }

    #[test]
    fn trailing_byte_refused() {
        let mut bytes = encode(&CommitResponse::Applied {
            seqs: vec![Some(1)],
        });
        bytes.push(0);
        assert!(matches!(
            decode::<CommitResponse>(&bytes),
            Err(ProtoError::Format(_))
        ));
    }

    #[test]
    fn truncated_refused() {
        let bytes = encode(&rec(1));
        for n in 1..bytes.len() {
            assert!(
                matches!(
                    decode::<ServerRecord>(&bytes[..n]),
                    Err(ProtoError::Format(_))
                ),
                "cut at {n}"
            );
        }
    }

    #[test]
    fn non_canonical_varint_refused() {
        // version, variant Applied, one seq, Some, then seq 1 written as 0x81 0x00.
        let bytes = [PROTO_VERSION, 0, 1, 1, 0x81, 0x00];
        assert!(matches!(
            decode::<CommitResponse>(&bytes),
            Err(ProtoError::Format(_))
        ));
        assert_eq!(
            decode::<CommitResponse>(&[PROTO_VERSION, 0, 1, 1, 1]).unwrap(),
            CommitResponse::Applied {
                seqs: vec![Some(1)]
            }
        );
    }

    #[test]
    fn inline_above_limit_refused() {
        let over = CommitRequest {
            ops: vec![put(5, 1, inline(INLINE_MAX + 1))],
        };
        assert_eq!(
            decode::<CommitRequest>(&encode(&over)),
            Err(ProtoError::TooLarge("inline"))
        );
        let exact = CommitRequest {
            ops: vec![put(5, 1, inline(INLINE_MAX))],
        };
        assert!(decode::<CommitRequest>(&encode(&exact)).is_ok());
    }

    #[test]
    fn blob_above_record_max_refused() {
        let blob = |size| CommitRequest {
            ops: vec![put(
                5,
                1,
                Body::Blob {
                    sha256: [1; 32],
                    size,
                },
            )],
        };
        assert!(decode::<CommitRequest>(&encode(&blob(RECORD_MAX as u32))).is_ok());
        assert_eq!(
            decode::<CommitRequest>(&encode(&blob(RECORD_MAX as u32 + 1))),
            Err(ProtoError::TooLarge("blob"))
        );
    }

    #[test]
    fn commit_ops_cap() {
        // Only the length prefix is present: the cap fires before the rest is read.
        let mut bytes = vec![PROTO_VERSION];
        bytes.extend(postcard::to_allocvec(&(COMMIT_OPS_MAX as u64 + 1)).unwrap());
        assert_eq!(
            decode::<CommitRequest>(&bytes),
            Err(ProtoError::TooLarge("ops"))
        );
        let mut bytes = vec![PROTO_VERSION];
        bytes.extend(postcard::to_allocvec(&(u64::MAX)).unwrap());
        assert_eq!(
            decode::<CommitRequest>(&bytes),
            Err(ProtoError::TooLarge("ops"))
        );
        // At the cap the prefix passes and the missing operations are a format error.
        let mut bytes = vec![PROTO_VERSION];
        bytes.extend(postcard::to_allocvec(&(COMMIT_OPS_MAX as u64)).unwrap());
        assert!(matches!(
            decode::<CommitRequest>(&bytes),
            Err(ProtoError::Format(_))
        ));
    }

    #[test]
    fn commit_duplicate_key_refused() {
        let dup = CommitRequest {
            ops: vec![
                put(5, 1, inline(1)),
                put(5, 2, inline(1)),
                put(5, 1, inline(2)),
            ],
        };
        assert_eq!(
            decode::<CommitRequest>(&encode(&dup)),
            Err(ProtoError::Unsorted("commit"))
        );
    }

    #[test]
    fn kind_zero_refused() {
        assert!(decode::<ServerRecord>(&encode(&ServerRecord { kind: 0, ..rec(1) })).is_err());
        assert!(
            decode::<CommitRequest>(&encode(&CommitRequest {
                ops: vec![put(0, 1, inline(1))]
            }))
            .is_err()
        );
        assert!(
            decode::<ConflictEntry>(&encode(&ConflictEntry {
                kind: 0,
                id: [1; 16],
                server: None
            }))
            .is_err()
        );
        let page = ChangesPage {
            incarnation: 1,
            min_cursor: 0,
            head: 2_000,
            records: vec![ServerRecord { kind: 0, ..rec(1) }],
            next_after: 1,
            more: false,
        };
        assert!(decode::<ChangesPage>(&encode(&page)).is_err());
        let conflict = CommitResponse::Conflict {
            current: vec![ConflictEntry {
                kind: 0,
                id: [1; 16],
                server: None,
            }],
        };
        assert!(decode::<CommitResponse>(&encode(&conflict)).is_err());
    }

    #[test]
    fn page_sorted_by_seq() {
        let page = |seqs: &[u64], next_after| ChangesPage {
            incarnation: 1,
            min_cursor: 0,
            head: 2_000,
            records: seqs.iter().map(|&s| rec(s)).collect(),
            next_after,
            more: false,
        };
        assert!(decode::<ChangesPage>(&encode(&page(&[1, 2, 5], 5))).is_ok());
        assert_eq!(
            decode::<ChangesPage>(&encode(&page(&[1, 1], 1))),
            Err(ProtoError::Unsorted("page"))
        );
        assert_eq!(
            decode::<ChangesPage>(&encode(&page(&[3, 2], 2))),
            Err(ProtoError::Unsorted("page"))
        );
        assert!(decode::<ChangesPage>(&encode(&page(&[1, 2], 1))).is_err());
        assert!(decode::<ChangesPage>(&encode(&page(&[], 77))).is_ok());
    }

    #[test]
    fn page_caps() {
        let too_many = ChangesPage {
            incarnation: 1,
            min_cursor: 0,
            head: 2_000,
            records: (1..=u64::from(PAGE_MAX_RECORDS) + 1).map(rec).collect(),
            next_after: u64::from(PAGE_MAX_RECORDS) + 1,
            more: false,
        };
        assert_eq!(
            decode::<ChangesPage>(&encode(&too_many)),
            Err(ProtoError::TooLarge("page records"))
        );
        // 400 records of 16 KiB each exceed 4 MiB.
        let heavy = ChangesPage {
            incarnation: 1,
            min_cursor: 0,
            head: 2_000,
            records: (1..=300u64)
                .map(|s| ServerRecord {
                    body: Some(inline(INLINE_MAX)),
                    ..rec(s)
                })
                .collect(),
            next_after: 300,
            more: false,
        };
        assert_eq!(
            decode::<ChangesPage>(&encode(&heavy)),
            Err(ProtoError::TooLarge("page bytes"))
        );
    }

    #[test]
    fn blob_lists_sorted_unique() {
        let a = BlobAnnounce {
            blobs: vec![([2; 32], 1), ([1; 32], 1)],
        };
        assert_eq!(
            decode::<BlobAnnounce>(&encode(&a)),
            Err(ProtoError::Unsorted("blobs"))
        );
        let a = BlobAnnounce {
            blobs: vec![([1; 32], 1), ([1; 32], 2)],
        };
        assert!(decode::<BlobAnnounce>(&encode(&a)).is_err());
        let l = BlobLookup {
            blobs: vec![[2; 32], [1; 32]],
        };
        assert_eq!(
            decode::<BlobLookup>(&encode(&l)),
            Err(ProtoError::Unsorted("blobs"))
        );
        let l = BlobLookup {
            blobs: vec![[1; 32], [1; 32]],
        };
        assert!(decode::<BlobLookup>(&encode(&l)).is_err());
        let sorted = |n: u32| BlobLookup {
            blobs: (0..n)
                .map(|i| {
                    let mut h = [0u8; 32];
                    h[..4].copy_from_slice(&i.to_be_bytes());
                    h
                })
                .collect(),
        };
        assert!(decode::<BlobLookup>(&encode(&sorted(PAGE_MAX_RECORDS))).is_ok());
        assert_eq!(
            decode::<BlobLookup>(&encode(&sorted(PAGE_MAX_RECORDS + 1))),
            Err(ProtoError::TooLarge("blobs"))
        );
        let big = BlobAnnounce {
            blobs: vec![([1; 32], RECORD_MAX as u32 + 1)],
        };
        assert!(decode::<BlobAnnounce>(&encode(&big)).is_err());
        let u = BlobUrls {
            urls: vec![([2; 32], None), ([1; 32], None)],
        };
        assert!(decode::<BlobUrls>(&encode(&u)).is_err());
    }

    #[test]
    fn label_and_url_caps() {
        let mk = |n| CreateMailbox {
            public_key: [0; 32],
            invite: None,
            label: vec![b'a'; n],
        };
        assert!(decode::<CreateMailbox>(&encode(&mk(LABEL_MAX))).is_ok());
        assert_eq!(
            decode::<CreateMailbox>(&encode(&mk(LABEL_MAX + 1))),
            Err(ProtoError::TooLarge("label"))
        );
        let cfg = |n| ServerConfig {
            realtime_url: "u".repeat(n),
            publishable_key: "k".into(),
            open_signup: false,
        };
        assert!(decode::<ServerConfig>(&encode(&cfg(URL_MAX))).is_ok());
        assert_eq!(
            decode::<ServerConfig>(&encode(&cfg(URL_MAX + 1))),
            Err(ProtoError::TooLarge("url"))
        );
    }

    #[test]
    fn push_token_caps() {
        let p = |kind, n| SetPush {
            kind,
            token: vec![1; n],
        };
        assert!(decode::<SetPush>(&encode(&p(PushKind::Fcm, PUSH_TOKEN_MAX))).is_ok());
        assert_eq!(
            decode::<SetPush>(&encode(&p(PushKind::Fcm, PUSH_TOKEN_MAX + 1))),
            Err(ProtoError::TooLarge("token"))
        );
        assert!(decode::<SetPush>(&encode(&p(PushKind::None, 1))).is_err());
    }

    #[test]
    fn unknown_enum_tag_refused() {
        let bytes = [PROTO_VERSION, 200, 0];
        assert!(matches!(
            decode::<ErrorBody>(&bytes),
            Err(ProtoError::Format(_))
        ));
    }

    #[test]
    fn empty_commit_refused() {
        assert_eq!(
            decode::<CommitRequest>(&encode(&CommitRequest { ops: vec![] })),
            Err(ProtoError::Format("empty commit"))
        );
        assert_eq!(
            decode::<CommitRequest>(&[PROTO_VERSION, 0]),
            Err(ProtoError::Format("empty commit"))
        );
    }

    #[test]
    fn page_seqs_not_above_head() {
        let page = |head| ChangesPage {
            incarnation: 1,
            min_cursor: 0,
            head,
            records: vec![rec(3), rec(9)],
            next_after: 9,
            more: false,
        };
        assert!(decode::<ChangesPage>(&encode(&page(9))).is_ok());
        assert!(decode::<ChangesPage>(&encode(&page(12))).is_ok());
        assert_eq!(
            decode::<ChangesPage>(&encode(&page(8))),
            Err(ProtoError::Format("head"))
        );
    }

    #[test]
    fn changes_query_round_trip() {
        for q in [
            ChangesQuery {
                after: 0,
                limit: 1,
                full: false,
            },
            ChangesQuery {
                after: i64::MAX as u64,
                limit: PAGE_MAX_RECORDS,
                full: true,
            },
            ChangesQuery {
                after: 12,
                limit: 500,
                full: true,
            },
        ] {
            assert_eq!(ChangesQuery::parse(&q.to_query()), Ok(q.clone()));
        }
        assert_eq!(
            ChangesQuery {
                after: 12,
                limit: 500,
                full: true
            }
            .to_query(),
            "after=12&limit=500&full=1"
        );
    }

    #[test]
    fn changes_query_refused() {
        for bad in [
            "",
            "after=1&limit=1",
            "after=1&limit=1&full=1&x=1",
            "limit=1&after=1&full=1",
            "after=01&limit=1&full=0",
            "after=+1&limit=1&full=0",
            "after=-1&limit=1&full=0",
            "after=18446744073709551616&limit=1&full=0",
            "after=18446744073709551615&limit=1&full=0",
            "after=9223372036854775808&limit=1&full=0",
            "after=1&limit=0&full=0",
            "after=1&limit=1001&full=0",
            "after=1&limit=1&full=2",
            "after=1&limit=1&full=true",
            "after=1&after=1&limit=1&full=0",
            "after=&limit=1&full=0",
            "after=1&limit=1&full=0&",
        ] {
            assert!(
                matches!(ChangesQuery::parse(bad), Err(ProtoError::Format(_))),
                "accepted {bad}"
            );
        }
    }

    #[test]
    fn helpers() {
        assert_eq!(
            hex(&blob_sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
