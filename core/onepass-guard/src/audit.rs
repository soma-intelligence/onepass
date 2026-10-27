//! Hash-chained audit log with a signed head.
//!
//! One JSON object per line. The hash of an entry is the SHA-256 of its line
//! bytes without the newline; `prev` holds the previous entry's hash (64 zeros
//! for the first). The file `<log>.head` holds `{"seq":n,"hash":"<hex>"}` of
//! the last entry, sealed with [`seal_config`], so edits, insertions,
//! deletions and tail truncation are all detected.
//!
//! Several processes (the MCP server and the SSH agent) may append to the same
//! log: every append takes an exclusive lock and derives the chain state from
//! the disk, never from memory, and refuses to extend a log that does not
//! match its signed head.
//!
//! Accepted cost: a crash between writing a line and rewriting the head leaves
//! one line beyond the head. That single trailing line is accepted (and
//! resealed by the next append) if it links to the head hash, so an attacker
//! who can write the log can append one forged trailing entry that looks like
//! such a crash. Truncation, edits and insertions are still detected. Replaying
//! an old log together with its old authentic head is not detected.

use crate::approval::Surface;
use crate::{GuardError, LocalSigner, open_config, seal_config};
use aws_lc_rs::digest;
use data_encoding::HEXLOWER;
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{FileExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

const HEAD_DOMAIN: &[u8] = b"audit-head";
const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Outcome: the client is not paired (refused without a prompt).
pub const OUTCOME_NOT_PAIRED: &str = "not_paired";
/// Outcome: over the per-minute prompt or secret limit.
pub const OUTCOME_RATE_LIMITED: &str = "rate_limited";
/// Outcome: the client is cooling down after repeated denials.
pub const OUTCOME_CLIENT_COOLING_DOWN: &str = "client_cooling_down";
/// Outcome: a grant matched but had expired (the user is asked again).
pub const OUTCOME_GRANT_EXPIRED: &str = "grant_expired";
/// Outcome: a grant matched but had been revoked (the user is asked again).
pub const OUTCOME_GRANT_REVOKED: &str = "grant_revoked";
/// Outcome: strong authentication (Touch ID or master password) failed.
pub const OUTCOME_STRONG_AUTH_FAILED: &str = "strong_auth_failed";
/// Outcome: an SSH signature for a host the connection is not bound to.
pub const OUTCOME_HOST_NOT_BOUND: &str = "host_not_bound";
/// Outcome: the client registry could not be trusted (bad signature,
/// replayed, unreadable): refused without a prompt.
pub const OUTCOME_REGISTRY_UNUSABLE: &str = "registry_unusable";

/// What happened, with opaque ids only: no secret values and no titles.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AuditEntry {
    /// Surface that handled the request.
    pub surface: Surface,
    /// Client name as declared (untrusted).
    pub client: String,
    /// Code identity of the paired client (`platform:`, `team:` or
    /// `unsigned:` form). Absent in entries written before it existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// Label of the paired client, as shown to the user.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_label: Option<String>,
    /// Action name.
    pub action: String,
    /// Opaque vault id.
    pub vault_id: Option<String>,
    /// Opaque item id.
    pub item_id: Option<String>,
    /// Field name or id.
    pub field: Option<String>,
    /// Approval decision (free-form label).
    pub decision: String,
    /// Result of the action (free-form label).
    pub outcome: String,
}

/// An entry as stored, with its position and time.
#[derive(Clone, Debug, PartialEq)]
pub struct AuditRecord {
    /// Position in the chain, from 1.
    pub seq: u64,
    /// RFC 3339 UTC timestamp.
    pub ts: String,
    /// The logged entry.
    pub entry: AuditEntry,
}

/// Result of [`verify_log`].
#[derive(Clone, Debug, PartialEq)]
pub struct AuditVerification {
    /// All records, in order.
    pub records: Vec<AuditRecord>,
    /// True when the last line is not yet sealed by the head (a previous
    /// crash between the line and the head, see the module documentation).
    pub unsealed_tail: bool,
}

/// The on-disk line.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Line {
    seq: u64,
    ts: String,
    surface: Surface,
    client: String,
    // Optional so that lines written before these fields keep verifying,
    // and omitted when absent so that such lines are byte-identical.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    client_label: Option<String>,
    action: String,
    vault_id: Option<String>,
    item_id: Option<String>,
    field: Option<String>,
    decision: String,
    outcome: String,
    prev: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Head {
    seq: u64,
    hash: String,
}

fn hash_line(line: &str) -> String {
    HEXLOWER.encode(digest::digest(&digest::SHA256, line.as_bytes()).as_ref())
}

/// Path of the signed head file of the log at `log` (`<log>.head`).
pub fn head_path(log: &Path) -> PathBuf {
    let mut s = log.as_os_str().to_owned();
    s.push(".head");
    PathBuf::from(s)
}

fn seal_head(signer: &dyn LocalSigner, seq: u64, hash: &str) -> Result<String, GuardError> {
    let payload = serde_json::to_string(&Head {
        seq,
        hash: hash.to_owned(),
    })
    .map_err(|_| GuardError::Format("audit head"))?;
    seal_config(signer, HEAD_DOMAIN, &payload)
}

/// Reads and verifies the head; `None` when the file does not exist.
fn read_head(log: &Path, signer: &dyn LocalSigner) -> Result<Option<Head>, GuardError> {
    let text = match fs::read_to_string(head_path(log)) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let payload = open_config(signer, HEAD_DOMAIN, &text)?;
    serde_json::from_str(&payload)
        .map(Some)
        .map_err(|_| GuardError::Format("audit head"))
}

/// Chain state derived from the disk: last sequence number, last line hash,
/// and whether that last line is still unsealed.
struct State {
    seq: u64,
    hash: String,
    unsealed: bool,
}

/// Checks the last line against the verified head. `last` is the last line
/// with its parsed form, `lines` the total number of lines.
fn reconcile(
    head: Option<&Head>,
    last: Option<(&Line, String)>,
    lines: usize,
) -> Result<State, GuardError> {
    match (head, last) {
        (None, None) => Ok(State {
            seq: 0,
            hash: ZERO_HASH.to_owned(),
            unsealed: false,
        }),
        (None, Some((l, h))) => {
            if lines == 1 && l.seq == 1 && l.prev == ZERO_HASH {
                Ok(State {
                    seq: 1,
                    hash: h,
                    unsealed: true,
                })
            } else {
                Err(GuardError::Tampered("head file missing"))
            }
        }
        (Some(_), None) => Err(GuardError::Tampered("log missing or empty but head exists")),
        (Some(head), Some((l, h))) => {
            if l.seq == head.seq && h == head.hash {
                Ok(State {
                    seq: l.seq,
                    hash: h,
                    unsealed: false,
                })
            } else if l.seq == head.seq + 1 && l.prev == head.hash {
                Ok(State {
                    seq: l.seq,
                    hash: h,
                    unsealed: true,
                })
            } else {
                Err(GuardError::Tampered("log does not match signed head"))
            }
        }
    }
}

/// Appender for the audit log. Holds only the path: all chain state is read
/// from disk under an exclusive lock on every append.
pub struct AuditLog {
    path: PathBuf,
}

impl AuditLog {
    /// Creates the log (mode 0600) if missing and enforces 0600 on an
    /// existing one. The chain is not verified here: use [`verify_log`].
    pub fn open(path: &Path) -> Result<AuditLog, GuardError> {
        let f = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(path)?;
        f.set_permissions(fs::Permissions::from_mode(0o600))?;
        Ok(AuditLog {
            path: path.to_owned(),
        })
    }

    /// Checks, without writing anything, that the log can be appended to:
    /// under the exclusive lock it reads the last line and the head and
    /// verifies they agree (an unsealed trailing line left by a crash is
    /// accepted, as in [`AuditLog::append`]).
    pub fn ready(&self, signer: &dyn LocalSigner) -> Result<(), GuardError> {
        let f = OpenOptions::new().read(true).open(&self.path)?;
        f.lock()?;
        load_state(&f, &self.path, signer).map(|_| ())
    }

    /// Appends `e` and rewrites the signed head atomically.
    ///
    /// Under an exclusive lock it reads the last line (only the tail of the
    /// file) and the head, verifies the head signature and refuses with
    /// [`GuardError::Tampered`] (writing nothing) if they disagree, except for
    /// one unsealed trailing line left by a crash, which is resealed first.
    pub fn append(&mut self, signer: &dyn LocalSigner, e: &AuditEntry) -> Result<(), GuardError> {
        let mut f = OpenOptions::new()
            .read(true)
            .append(true)
            .mode(0o600)
            .open(&self.path)?;
        f.lock()?;
        let state = load_state(&f, &self.path, signer)?;

        // Never leave two lines beyond the head: reseal the tail first.
        if state.unsealed {
            let sealed = seal_head(signer, state.seq, &state.hash)?;
            write_atomic(&head_path(&self.path), sealed.as_bytes())?;
        }

        let ts = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .map_err(|_| GuardError::Format("timestamp"))?;
        let line = Line {
            seq: state.seq + 1,
            ts,
            surface: e.surface,
            client: e.client.clone(),
            client_id: e.client_id.clone(),
            client_label: e.client_label.clone(),
            action: e.action.clone(),
            vault_id: e.vault_id.clone(),
            item_id: e.item_id.clone(),
            field: e.field.clone(),
            decision: e.decision.clone(),
            outcome: e.outcome.clone(),
            prev: state.hash.clone(),
        };
        let json = serde_json::to_string(&line).map_err(|_| GuardError::Format("audit line"))?;
        let sealed = seal_head(signer, line.seq, &hash_line(&json))?;

        f.write_all(format!("{json}\n").as_bytes())?;
        f.sync_all()?;
        write_atomic(&head_path(&self.path), sealed.as_bytes())?;
        // The lock is released when `f` is dropped.
        Ok(())
    }
}

/// Size of one backward read when looking for the last line.
const TAIL_CHUNK: u64 = 4096;
/// Longest last line accepted (a longer one is treated as a format error).
const MAX_TAIL: usize = 1 << 20;

/// Reads the last non-empty line of `f` by reading backwards from the end.
/// Returns the line and whether it is the only content of the file.
fn read_last_line(f: &File) -> Result<Option<(String, bool)>, GuardError> {
    let len = f.metadata()?.len();
    let mut pos = len;
    let mut buf: Vec<u8> = Vec::new();
    loop {
        let end = buf.len() - buf.iter().rev().take_while(|&&b| b == b'\n').count();
        if let Some(i) = buf[..end].iter().rposition(|&b| b == b'\n') {
            let line = String::from_utf8(buf[i + 1..end].to_vec())
                .map_err(|_| GuardError::Format("audit line"))?;
            return Ok(Some((line, false)));
        }
        if pos == 0 {
            if end == 0 {
                return Ok(None);
            }
            let line = String::from_utf8(buf[..end].to_vec())
                .map_err(|_| GuardError::Format("audit line"))?;
            return Ok(Some((line, true)));
        }
        if buf.len() > MAX_TAIL {
            return Err(GuardError::Format("audit line too long"));
        }
        let n = TAIL_CHUNK.min(pos);
        pos -= n;
        let mut chunk = vec![0u8; n as usize];
        f.read_exact_at(&mut chunk, pos)?;
        chunk.extend_from_slice(&buf);
        buf = chunk;
    }
}

/// Derives the chain state from the tail of the locked log `f` and its head.
fn load_state(f: &File, path: &Path, signer: &dyn LocalSigner) -> Result<State, GuardError> {
    let head = read_head(path, signer)?;
    let parsed = match read_last_line(f)? {
        None => None,
        Some((raw, only)) => Some((
            serde_json::from_str::<Line>(&raw).map_err(|_| GuardError::Format("audit line"))?,
            hash_line(&raw),
            only,
        )),
    };
    // `reconcile` only needs the line count to tell a lone first line apart.
    let count = match &parsed {
        None => 0,
        Some((_, _, true)) => 1,
        Some(_) => 2,
    };
    reconcile(
        head.as_ref(),
        parsed.as_ref().map(|(l, h, _)| (l, h.clone())),
        count,
    )
}

/// Writes `data` to `path` through a temporary file, a rename and an fsync of
/// the parent directory.
fn write_atomic(path: &Path, data: &[u8]) -> Result<(), GuardError> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    let mut f: File = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;
    f.write_all(data)?;
    f.sync_all()?;
    fs::rename(&tmp, path)?;
    if let Some(dir) = path.parent() {
        let dir = if dir.as_os_str().is_empty() {
            Path::new(".")
        } else {
            dir
        };
        File::open(dir)?.sync_all()?;
    }
    Ok(())
}

/// Checks the whole chain and the signed head; returns the records in order.
///
/// An edited, inserted or deleted line breaks the `seq`/`prev` chain; a
/// truncated or extended tail no longer matches the head; a head signed with
/// another key gives [`GuardError::Signature`]. One trailing line that links
/// to the head hash is accepted and reported through `unsealed_tail`.
///
/// The log is read and the head checked under a shared lock on the log, so a
/// concurrent append (which holds the exclusive lock while it writes the line
/// and the head) is never seen half done.
pub fn verify_log(path: &Path, signer: &dyn LocalSigner) -> Result<AuditVerification, GuardError> {
    let mut f = File::open(path)?;
    f.lock_shared()?;
    let mut text = String::new();
    f.read_to_string(&mut text)?;
    let mut records = Vec::new();
    let mut prev = ZERO_HASH.to_owned();
    let mut last: Option<Line> = None;
    for raw in text.lines() {
        let l: Line = serde_json::from_str(raw).map_err(|_| GuardError::Format("audit line"))?;
        if l.seq != records.len() as u64 + 1 {
            return Err(GuardError::Tampered("sequence gap or reorder"));
        }
        if l.prev != prev {
            return Err(GuardError::Tampered("broken hash chain"));
        }
        prev = hash_line(raw);
        records.push(AuditRecord {
            seq: l.seq,
            ts: l.ts.clone(),
            entry: AuditEntry {
                surface: l.surface,
                client: l.client.clone(),
                client_id: l.client_id.clone(),
                client_label: l.client_label.clone(),
                action: l.action.clone(),
                vault_id: l.vault_id.clone(),
                item_id: l.item_id.clone(),
                field: l.field.clone(),
                decision: l.decision.clone(),
                outcome: l.outcome.clone(),
            },
        });
        last = Some(l);
    }

    let head = read_head(path, signer)?;
    let state = reconcile(
        head.as_ref(),
        last.as_ref().map(|l| (l, prev.clone())),
        records.len(),
    )?;
    Ok(AuditVerification {
        records,
        unsealed_tail: state.unsealed,
    })
}

/// Receives audit entries from the front ends.
pub trait AuditSink {
    /// Records `e`. Must not panic. An error means the entry was not written;
    /// the caller decides whether that blocks anything.
    fn record(&mut self, e: &AuditEntry) -> Result<(), GuardError>;

    /// Checks, writing nothing, that an entry can be recorded now. Front ends
    /// call it before a secret action and refuse the action on error, so the
    /// log fails closed for secrets.
    fn ready(&mut self) -> Result<(), GuardError> {
        Ok(())
    }
}

impl AuditSink for Vec<AuditEntry> {
    fn record(&mut self, e: &AuditEntry) -> Result<(), GuardError> {
        self.push(e.clone());
        Ok(())
    }
}

/// Sink writing to an [`AuditLog`] signed by `signer`.
pub struct SignedAuditSink<G: LocalSigner> {
    /// The log appended to.
    pub log: AuditLog,
    /// Signs the head after each entry.
    pub signer: G,
}

impl<G: LocalSigner> AuditSink for SignedAuditSink<G> {
    fn record(&mut self, e: &AuditEntry) -> Result<(), GuardError> {
        self.log.append(&self.signer, e)
    }

    fn ready(&mut self) -> Result<(), GuardError> {
        self.log.ready(&self.signer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TestSigner;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    fn entry(n: u32) -> AuditEntry {
        AuditEntry {
            surface: if n.is_multiple_of(2) {
                Surface::Ssh
            } else {
                Surface::Mcp
            },
            client: format!("client{n}"),
            client_id: None,
            client_label: None,
            action: "reveal_secret".into(),
            vault_id: Some(format!("v{n}")),
            item_id: Some(format!("i{n}")),
            field: None,
            decision: "allow_once".into(),
            outcome: "ok".into(),
        }
    }

    fn make(dir: &std::path::Path, n: u32) -> (std::path::PathBuf, TestSigner) {
        let path = dir.join("audit.log");
        let signer = TestSigner::new();
        let mut log = AuditLog::open(&path).unwrap();
        for i in 1..=n {
            log.append(&signer, &entry(i)).unwrap();
        }
        (path, signer)
    }

    fn lines(path: &std::path::Path) -> Vec<String> {
        fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(String::from)
            .collect()
    }

    fn write_lines(path: &std::path::Path, l: &[String]) {
        fs::write(path, format!("{}\n", l.join("\n"))).unwrap();
    }

    #[test]
    fn audit_chain_verifies() {
        let dir = tempfile::tempdir().unwrap();
        let (path, signer) = make(dir.path(), 3);
        let recs = verify_log(&path, &signer).unwrap().records;
        assert_eq!(recs.len(), 3);
        for (i, r) in recs.iter().enumerate() {
            assert_eq!(r.seq, i as u64 + 1);
            assert_eq!(r.entry, entry(i as u32 + 1));
            assert!(r.ts.ends_with('Z'));
        }
        let first: serde_json::Value = serde_json::from_str(&lines(&path)[0]).unwrap();
        assert_eq!(first["prev"], "0".repeat(64));
        assert_eq!(first["surface"], "mcp");
    }

    #[test]
    fn audit_detects_edit() {
        let dir = tempfile::tempdir().unwrap();
        let (path, signer) = make(dir.path(), 3);
        let mut l = lines(&path);
        l[1] = l[1].replace("client2", "client9");
        write_lines(&path, &l);
        assert!(matches!(
            verify_log(&path, &signer),
            Err(GuardError::Tampered(_))
        ));
        // Editing the last line is caught by the head.
        let dir2 = tempfile::tempdir().unwrap();
        let (path, signer) = make(dir2.path(), 3);
        let mut l = lines(&path);
        l[2] = l[2].replace("client3", "client9");
        write_lines(&path, &l);
        assert!(matches!(
            verify_log(&path, &signer),
            Err(GuardError::Tampered(_))
        ));
    }

    #[test]
    fn audit_detects_insertion() {
        let dir = tempfile::tempdir().unwrap();
        let (path, signer) = make(dir.path(), 3);
        let mut l = lines(&path);
        let dup = l[0].clone();
        l.insert(1, dup);
        write_lines(&path, &l);
        assert!(matches!(
            verify_log(&path, &signer),
            Err(GuardError::Tampered(_))
        ));
    }

    #[test]
    fn audit_detects_deletion() {
        let dir = tempfile::tempdir().unwrap();
        let (path, signer) = make(dir.path(), 3);
        let mut l = lines(&path);
        l.remove(1);
        write_lines(&path, &l);
        assert!(matches!(
            verify_log(&path, &signer),
            Err(GuardError::Tampered(_))
        ));
    }

    #[test]
    fn audit_detects_truncation() {
        let dir = tempfile::tempdir().unwrap();
        let (path, signer) = make(dir.path(), 3);
        let mut l = lines(&path);
        l.pop();
        write_lines(&path, &l);
        assert!(matches!(
            verify_log(&path, &signer),
            Err(GuardError::Tampered(_))
        ));
        // Removing everything is caught too.
        fs::write(&path, "").unwrap();
        assert!(matches!(
            verify_log(&path, &signer),
            Err(GuardError::Tampered(_))
        ));
    }

    #[test]
    fn audit_detects_forged_head() {
        let dir = tempfile::tempdir().unwrap();
        let (path, signer) = make(dir.path(), 3);
        let other = TestSigner([9u8; 32]);
        let head = head_path(&path);
        let forged =
            crate::seal_config(&other, b"audit-head", "{\"seq\":3,\"hash\":\"00\"}").unwrap();
        fs::write(&head, forged).unwrap();
        assert_eq!(verify_log(&path, &signer), Err(GuardError::Signature));
        fs::remove_file(&head).unwrap();
        assert!(matches!(
            verify_log(&path, &signer),
            Err(GuardError::Tampered(_))
        ));
    }

    #[test]
    fn audit_reopen_continues_chain() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let signer = TestSigner::new();
        {
            let mut log = AuditLog::open(&path).unwrap();
            log.append(&signer, &entry(1)).unwrap();
            log.append(&signer, &entry(2)).unwrap();
        }
        let mut log = AuditLog::open(&path).unwrap();
        log.append(&signer, &entry(3)).unwrap();
        let recs = verify_log(&path, &signer).unwrap().records;
        assert_eq!(
            recs.iter().map(|r| r.seq).collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
    }

    #[test]
    fn audit_file_mode_is_0600() {
        let dir = tempfile::tempdir().unwrap();
        let (path, _s) = make(dir.path(), 1);
        let mode = |p: &std::path::Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(&head_path(&path)), 0o600);
    }

    #[test]
    fn signed_sink_records_and_vec_sink_collects() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let mut sink = SignedAuditSink {
            log: AuditLog::open(&path).unwrap(),
            signer: TestSigner::new(),
        };
        sink.record(&entry(1)).unwrap();
        assert_eq!(
            verify_log(&path, &TestSigner::new()).unwrap().records.len(),
            1
        );
        let mut v: Vec<AuditEntry> = Vec::new();
        v.record(&entry(2)).unwrap();
        assert_eq!(v, vec![entry(2)]);
    }

    #[test]
    fn audit_head_write_failure_recovers() {
        let dir = tempfile::tempdir().unwrap();
        let (path, signer) = make(dir.path(), 1);
        let tmp = dir.path().join("audit.log.head.tmp");
        fs::create_dir(&tmp).unwrap();
        let mut log = AuditLog::open(&path).unwrap();
        assert!(log.append(&signer, &entry(2)).is_err());
        let v = verify_log(&path, &signer).unwrap();
        assert!(v.unsealed_tail);
        assert_eq!(v.records.len(), 2);
        fs::remove_dir(&tmp).unwrap();
        log.append(&signer, &entry(3)).unwrap();
        let v = verify_log(&path, &signer).unwrap();
        assert!(!v.unsealed_tail);
        assert_eq!(
            v.records.iter().map(|r| r.seq).collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
    }

    #[test]
    fn audit_truncation_then_append_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (path, signer) = make(dir.path(), 3);
        let mut l = lines(&path);
        l.pop();
        write_lines(&path, &l);
        let before = fs::read(&path).unwrap();
        let head_before = fs::read(head_path(&path)).unwrap();
        let mut log = AuditLog::open(&path).unwrap();
        assert!(matches!(
            log.append(&signer, &entry(9)),
            Err(GuardError::Tampered(_))
        ));
        assert_eq!(fs::read(&path).unwrap(), before);
        assert_eq!(fs::read(head_path(&path)).unwrap(), head_before);
    }

    #[test]
    fn audit_two_handles_share_one_chain() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let signer = TestSigner::new();
        let mut a = AuditLog::open(&path).unwrap();
        let mut b = AuditLog::open(&path).unwrap();
        for i in 0..3 {
            a.append(&signer, &entry(i)).unwrap();
            b.append(&signer, &entry(i)).unwrap();
        }
        let v = verify_log(&path, &signer).unwrap();
        assert_eq!(v.records.len(), 6);
        assert!(!v.unsealed_tail);
    }

    #[test]
    fn audit_single_unsealed_tail_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let (path, signer) = make(dir.path(), 2);
        let old_head = fs::read(head_path(&path)).unwrap();
        let mut log = AuditLog::open(&path).unwrap();
        log.append(&signer, &entry(3)).unwrap();
        fs::write(head_path(&path), old_head).unwrap();
        let v = verify_log(&path, &signer).unwrap();
        assert!(v.unsealed_tail);
        assert_eq!(v.records.len(), 3);
        // The next append reseals the head over the tail.
        let mut log = AuditLog::open(&path).unwrap();
        log.append(&signer, &entry(4)).unwrap();
        assert!(!verify_log(&path, &signer).unwrap().unsealed_tail);
    }

    #[test]
    fn audit_head_ahead_of_log_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (path, signer) = make(dir.path(), 3);
        let l = lines(&path);
        write_lines(&path, &l[..1]);
        assert!(matches!(
            verify_log(&path, &signer),
            Err(GuardError::Tampered(_))
        ));
        fs::remove_file(&path).unwrap();
        assert!(verify_log(&path, &signer).is_err());
    }

    #[test]
    fn signed_sink_ready_and_record_report_tampering() {
        let dir = tempfile::tempdir().unwrap();
        let (path, signer) = make(dir.path(), 3);
        let mut sink = SignedAuditSink {
            log: AuditLog::open(&path).unwrap(),
            signer,
        };
        assert_eq!(sink.ready(), Ok(()));
        let mut l = lines(&path);
        l[2] = l[2].replace("client3", "client9");
        write_lines(&path, &l);
        let before = fs::read(&path).unwrap();
        assert!(matches!(sink.ready(), Err(GuardError::Tampered(_))));
        assert!(matches!(
            sink.record(&entry(4)),
            Err(GuardError::Tampered(_))
        ));
        assert_eq!(fs::read(&path).unwrap(), before);
        let mut v: Vec<AuditEntry> = Vec::new();
        assert_eq!(v.ready(), Ok(()));
    }

    #[test]
    fn audit_ready_writes_nothing_and_accepts_fresh_log() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let signer = TestSigner::new();
        let log = AuditLog::open(&path).unwrap();
        log.ready(&signer).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"");
        assert!(!head_path(&path).exists());
        let (path, signer) = make(dir.path(), 2);
        let before = fs::read(&path).unwrap();
        let head_before = fs::read(head_path(&path)).unwrap();
        AuditLog::open(&path).unwrap().ready(&signer).unwrap();
        assert_eq!(fs::read(&path).unwrap(), before);
        assert_eq!(fs::read(head_path(&path)).unwrap(), head_before);
    }

    #[test]
    fn audit_torn_trailing_line_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (path, signer) = make(dir.path(), 2);
        let mut f = OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(b"{\"seq\":3,\"ts").unwrap();
        let log = AuditLog::open(&path).unwrap();
        assert!(log.ready(&signer).is_err());
    }

    #[test]
    fn audit_append_reads_only_the_tail() {
        // A corrupted early line is not looked at by append (only verify_log
        // reads everything), which proves append reads the tail only.
        let dir = tempfile::tempdir().unwrap();
        let (path, signer) = make(dir.path(), 3);
        let mut l = lines(&path);
        l[0] = "garbage that is not json".into();
        write_lines(&path, &l);
        let mut log = AuditLog::open(&path).unwrap();
        log.ready(&signer).unwrap();
        log.append(&signer, &entry(4)).unwrap();
        assert!(verify_log(&path, &signer).is_err());
        // A long log keeps working: the tail spans more than one read chunk.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let mut log = AuditLog::open(&path).unwrap();
        let mut big = entry(1);
        big.client = "c".repeat(10_000);
        for _ in 0..3 {
            log.append(&signer, &big).unwrap();
        }
        let v = verify_log(&path, &signer).unwrap();
        assert_eq!(v.records.len(), 3);
    }

    #[test]
    fn verify_log_never_fails_during_concurrent_appends() {
        let dir = tempfile::tempdir().unwrap();
        let (path, signer) = make(dir.path(), 1);
        let p2 = path.clone();
        let writer = std::thread::spawn(move || {
            let signer = TestSigner::new();
            let mut log = AuditLog::open(&p2).unwrap();
            for i in 0..200 {
                log.append(&signer, &entry(i)).unwrap();
            }
        });
        let mut checks = 0;
        while !writer.is_finished() {
            let v = verify_log(&path, &signer).expect("no spurious failure");
            assert!(!v.unsealed_tail);
            checks += 1;
        }
        writer.join().unwrap();
        assert!(checks > 0);
        assert_eq!(verify_log(&path, &signer).unwrap().records.len(), 201);
    }

    #[test]
    fn head_path_is_next_to_the_log() {
        assert_eq!(
            head_path(Path::new("/data/audit.log")),
            PathBuf::from("/data/audit.log.head")
        );
    }

    /// A line exactly as written before `client_id` and `client_label`
    /// existed (milestone 7 format).
    const OLD_LINE: &str = r#"{"seq":1,"ts":"2026-10-25T10:00:00Z","surface":"mcp","client":"claude","action":"run_with_secrets","vault_id":"v1","item_id":"i1","field":"password","decision":"once","outcome":"ok","prev":"0000000000000000000000000000000000000000000000000000000000000000"}"#;

    #[test]
    fn audit_old_format_line_still_verifies() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let signer = TestSigner::new();
        fs::write(&path, format!("{OLD_LINE}\n")).unwrap();
        let head = seal_head(&signer, 1, &hash_line(OLD_LINE)).unwrap();
        fs::write(head_path(&path), head).unwrap();

        let v = verify_log(&path, &signer).unwrap();
        assert_eq!(v.records.len(), 1);
        assert!(!v.unsealed_tail);
        let e = &v.records[0].entry;
        assert_eq!(e.client, "claude");
        assert_eq!(e.client_id, None);
        assert_eq!(e.client_label, None);

        // The chain goes on with new-format entries after the old line.
        let mut log = AuditLog::open(&path).unwrap();
        let mut new = entry(2);
        new.client_id = Some("team:ABCDE12345:com.example.agent".into());
        new.client_label = Some("Example agent".into());
        new.outcome = OUTCOME_RATE_LIMITED.into();
        log.append(&signer, &new).unwrap();
        let recs = verify_log(&path, &signer).unwrap().records;
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[1].entry, new);
        // The old line is untouched on disk.
        assert_eq!(lines(&path)[0], OLD_LINE);
    }

    #[test]
    fn audit_client_fields_roundtrip_and_are_omitted_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let signer = TestSigner::new();
        let mut log = AuditLog::open(&path).unwrap();
        let mut with = entry(1);
        with.client_id = Some("platform:com.apple.Terminal".into());
        with.client_label = Some("Terminal \u{1b}[2J".into());
        let without = entry(2);
        log.append(&signer, &with).unwrap();
        log.append(&signer, &without).unwrap();

        let recs = verify_log(&path, &signer).unwrap().records;
        assert_eq!(recs[0].entry, with);
        assert_eq!(recs[1].entry, without);
        let l = lines(&path);
        let first: serde_json::Value = serde_json::from_str(&l[0]).unwrap();
        assert_eq!(first["client_id"], "platform:com.apple.Terminal");
        assert!(!l[1].contains("client_id"));
        assert!(!l[1].contains("client_label"));

        // AuditEntry itself (de)serializes the same way.
        let json = serde_json::to_string(&without).unwrap();
        assert!(!json.contains("client_id"));
        let back: AuditEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back, without);
    }

    #[test]
    fn audit_outcomes_are_the_spec_strings() {
        assert_eq!(OUTCOME_NOT_PAIRED, "not_paired");
        assert_eq!(OUTCOME_RATE_LIMITED, "rate_limited");
        assert_eq!(OUTCOME_CLIENT_COOLING_DOWN, "client_cooling_down");
        assert_eq!(OUTCOME_GRANT_EXPIRED, "grant_expired");
        assert_eq!(OUTCOME_GRANT_REVOKED, "grant_revoked");
        assert_eq!(OUTCOME_STRONG_AUTH_FAILED, "strong_auth_failed");
        assert_eq!(OUTCOME_HOST_NOT_BOUND, "host_not_bound");
        assert_eq!(OUTCOME_REGISTRY_UNUSABLE, "registry_unusable");
    }
}
