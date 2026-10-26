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
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

const HEAD_DOMAIN: &[u8] = b"audit-head";
const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// What happened, with opaque ids only: no secret values and no titles.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AuditEntry {
    /// Surface that handled the request.
    pub surface: Surface,
    /// Client name as declared (untrusted).
    pub client: String,
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

/// Path of the signed head file for a log.
fn head_path(log: &Path) -> PathBuf {
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

    /// Appends `e` and rewrites the signed head atomically.
    ///
    /// Under an exclusive lock it reads the last line and the head, verifies
    /// the head signature and refuses with [`GuardError::Tampered`] (writing
    /// nothing) if they disagree, except for one unsealed trailing line left
    /// by a crash, which is resealed first.
    pub fn append(&mut self, signer: &dyn LocalSigner, e: &AuditEntry) -> Result<(), GuardError> {
        let mut f = OpenOptions::new()
            .read(true)
            .append(true)
            .mode(0o600)
            .open(&self.path)?;
        f.lock()?;
        let mut text = String::new();
        f.read_to_string(&mut text)
            .map_err(|_| GuardError::Format("audit log"))?;

        let head = read_head(&self.path, signer)?;
        let last_raw = text.lines().rfind(|l| !l.is_empty());
        let parsed = match last_raw {
            None => None,
            Some(raw) => Some((
                serde_json::from_str::<Line>(raw).map_err(|_| GuardError::Format("audit line"))?,
                hash_line(raw),
            )),
        };
        let count = text.lines().filter(|l| !l.is_empty()).count();
        let state = reconcile(
            head.as_ref(),
            parsed.as_ref().map(|(l, h)| (l, h.clone())),
            count,
        )?;

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
pub fn verify_log(path: &Path, signer: &dyn LocalSigner) -> Result<AuditVerification, GuardError> {
    let text = fs::read_to_string(path)?;
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
    /// Records `e`. Must not panic; failures are reported, not propagated.
    fn record(&mut self, e: &AuditEntry);
}

impl AuditSink for Vec<AuditEntry> {
    fn record(&mut self, e: &AuditEntry) {
        self.push(e.clone());
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
    fn record(&mut self, e: &AuditEntry) {
        if let Err(err) = self.log.append(&self.signer, e) {
            eprintln!("onepass: audit log write failed: {err}");
        }
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
        sink.record(&entry(1));
        assert_eq!(
            verify_log(&path, &TestSigner::new()).unwrap().records.len(),
            1
        );
        let mut v: Vec<AuditEntry> = Vec::new();
        v.record(&entry(2));
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
}
