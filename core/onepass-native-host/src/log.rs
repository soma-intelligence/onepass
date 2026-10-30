//! Host journal `<data_dir>/native-host.log` (0600), mirrored on stderr
//! (Chrome ignores it). Lines are fixed host messages: never a secret, and
//! never a value received from the extension. Also the audit sink: JSON
//! lines in `<data_dir>/audit.log` (0600), without any value.

use std::fs::{self, DirBuilder, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use onepass_bridge::audit::{AuditEvent, AuditSink};

pub const LOG_FILE: &str = "native-host.log";
pub const AUDIT_FILE: &str = "audit.log";

/// Unix seconds.
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Create `dir` (and parents) with mode 0700.
pub fn ensure_dir(dir: &Path) -> std::io::Result<()> {
    DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
}

/// Append to `path`, creating it with mode 0600.
fn append(path: &Path, line: &str) -> std::io::Result<()> {
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(line.as_bytes())?;
    f.write_all(b"\n")
}

#[derive(Debug, Clone)]
pub struct Log {
    path: Option<PathBuf>,
}

impl Log {
    /// Journal in `data_dir`, created if needed.
    pub fn open(data_dir: &Path) -> Log {
        let path = ensure_dir(data_dir).ok().map(|()| data_dir.join(LOG_FILE));
        Log { path }
    }

    /// Stderr only.
    #[cfg(test)]
    pub fn stderr() -> Log {
        Log { path: None }
    }

    /// One line, prefixed with the time and the process id. Write failures
    /// are ignored: the journal never stops the host.
    pub fn line(&self, msg: &str) {
        let line = format!("{} [{}] {msg}", now(), std::process::id());
        // Never `eprintln!`: it panics when stderr is closed.
        let _ = writeln!(std::io::stderr(), "{line}");
        if let Some(p) = &self.path {
            let _ = append(p, &line);
        }
    }
}

/// Audit journal: one JSON object per line, no value.
pub struct FileAudit {
    path: PathBuf,
}

impl FileAudit {
    pub fn new(data_dir: &Path) -> FileAudit {
        FileAudit {
            path: data_dir.join(AUDIT_FILE),
        }
    }
}

impl AuditSink for FileAudit {
    fn record(&mut self, e: AuditEvent) {
        let mut line = serde_json::json!({
            "at": e.at,
            "op": e.op,
            "item_id": e.item_id,
            "origin": e.origin,
            "ctx": e.ctx.as_str(),
        });
        if let (Some(p), Some(obj)) = (e.plan, line.as_object_mut()) {
            obj.insert("intent".into(), serde_json::json!(p.intent));
            obj.insert("action".into(), serde_json::json!(p.action));
            obj.insert("confidence".into(), serde_json::json!(p.confidence));
        }
        let _ = append(&self.path, &line.to_string());
    }
}
