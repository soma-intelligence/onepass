//! Hash-chained audit log with a signed head.
//!
//! One JSON object per line. The hash of an entry is the SHA-256 of its line
//! bytes without the newline; `prev` holds the previous entry's hash (64 zeros
//! for the first). The file `<log>.head` holds `{"seq":n,"hash":"<hex>"}` of
//! the last entry, sealed with [`seal_config`], so edits, insertions,
//! deletions and tail truncation are all detected. Known limit: replaying an
//! old log together with its old authentic head is not detected.

use crate::approval::Surface;
use crate::{GuardError, LocalSigner, open_config, seal_config};
use aws_lc_rs::digest;
use data_encoding::HEXLOWER;
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
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

/// Appender for the audit log.
pub struct AuditLog {
    path: PathBuf,
    seq: u64,
    last_hash: String,
}

impl AuditLog {
    /// Opens (creating with mode 0600 if needed) the log and resumes its
    /// sequence number and last hash. The chain is not verified here: use
    /// [`verify_log`].
    pub fn open(path: &Path) -> Result<AuditLog, GuardError> {
        OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(path)?;
        let text = fs::read_to_string(path).map_err(|_| GuardError::Format("audit log"))?;
        let (seq, last_hash) = match text.lines().rfind(|l| !l.is_empty()) {
            None => (0, ZERO_HASH.to_owned()),
            Some(last) => {
                let l: Line =
                    serde_json::from_str(last).map_err(|_| GuardError::Format("audit line"))?;
                (l.seq, hash_line(last))
            }
        };
        Ok(AuditLog {
            path: path.to_owned(),
            seq,
            last_hash,
        })
    }

    /// Appends `e`, then rewrites the signed head atomically.
    pub fn append(&mut self, signer: &dyn LocalSigner, e: &AuditEntry) -> Result<(), GuardError> {
        let ts = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .map_err(|_| GuardError::Format("timestamp"))?;
        let line = Line {
            seq: self.seq + 1,
            ts,
            surface: e.surface,
            client: e.client.clone(),
            action: e.action.clone(),
            vault_id: e.vault_id.clone(),
            item_id: e.item_id.clone(),
            field: e.field.clone(),
            decision: e.decision.clone(),
            outcome: e.outcome.clone(),
            prev: self.last_hash.clone(),
        };
        let text = serde_json::to_string(&line).map_err(|_| GuardError::Format("audit line"))?;
        let hash = hash_line(&text);
        let head = seal_config(
            signer,
            HEAD_DOMAIN,
            &serde_json::to_string(&Head {
                seq: line.seq,
                hash: hash.clone(),
            })
            .map_err(|_| GuardError::Format("audit head"))?,
        )?;

        let mut f = OpenOptions::new()
            .append(true)
            .mode(0o600)
            .open(&self.path)?;
        f.write_all(format!("{text}\n").as_bytes())?;
        f.sync_all()?;
        write_atomic(&head_path(&self.path), head.as_bytes())?;

        self.seq = line.seq;
        self.last_hash = hash;
        Ok(())
    }
}

/// Writes `data` to `path` through a temporary file and a rename.
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
    Ok(())
}

/// Checks the whole chain and the signed head; returns the records in order.
///
/// An edited, inserted or deleted line breaks the `seq`/`prev` chain; a
/// truncated or extended tail no longer matches the head; a head signed with
/// another key gives [`GuardError::Signature`].
pub fn verify_log(path: &Path, signer: &dyn LocalSigner) -> Result<Vec<AuditRecord>, GuardError> {
    let text = fs::read_to_string(path)?;
    let mut records = Vec::new();
    let mut prev = ZERO_HASH.to_owned();
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
            ts: l.ts,
            entry: AuditEntry {
                surface: l.surface,
                client: l.client,
                action: l.action,
                vault_id: l.vault_id,
                item_id: l.item_id,
                field: l.field,
                decision: l.decision,
                outcome: l.outcome,
            },
        });
    }

    let head_text = match fs::read_to_string(head_path(path)) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return if records.is_empty() {
                Ok(records)
            } else {
                Err(GuardError::Tampered("head file missing"))
            };
        }
        Err(e) => return Err(e.into()),
    };
    let payload = open_config(signer, HEAD_DOMAIN, &head_text)?;
    let head: Head =
        serde_json::from_str(&payload).map_err(|_| GuardError::Format("audit head"))?;
    if head.seq != records.len() as u64 || (head.seq > 0 && head.hash != prev) {
        return Err(GuardError::Tampered("log does not match signed head"));
    }
    Ok(records)
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
        let recs = verify_log(&path, &signer).unwrap();
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
        let recs = verify_log(&path, &signer).unwrap();
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
        assert_eq!(verify_log(&path, &TestSigner::new()).unwrap().len(), 1);
        let mut v: Vec<AuditEntry> = Vec::new();
        v.record(&entry(2));
        assert_eq!(v, vec![entry(2)]);
    }
}
