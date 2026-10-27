//! Stored pairings: `<data_dir>/pairings.json`, mode 0600 in a 0700
//! directory, rewritten atomically (temporary file, then rename).
//!
//! Several host processes share the file (one per browser connection):
//! every change re-reads it under the exclusive lock `pairings.lock`, so a
//! process never writes back a stale copy over another one's pairing.

use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use data_encoding::BASE64;
use onepass_bridge::pairing::PairingRecord;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::config::HostError;
use crate::log::ensure_dir;
use crate::vault::lock_file;

pub const PAIRINGS_FILE: &str = "pairings.json";
pub const PAIRINGS_LOCK: &str = "pairings.lock";

/// Write `bytes` to `path` through a temporary file in the same directory
/// (0600, synced), then rename it over `path` and sync the directory.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let mut name = path
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    name.push(format!(".{}.tmp", std::process::id()));
    let tmp = dir.join(name);
    let _ = fs::remove_file(&tmp);
    let written = (|| {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        fs::rename(&tmp, path)
    })();
    if written.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    written?;
    fs::File::open(&dir)?.sync_all()
}

/// One stored pairing. The key is base64 in a wiped buffer.
#[derive(Serialize, Deserialize)]
struct Stored {
    pairing_id: String,
    key: Zeroizing<String>,
    ext_name: String,
    browser: String,
    extension_id: String,
    created_at: u64,
    last_used: u64,
}

#[derive(Serialize, Deserialize, Default)]
struct File {
    pairings: Vec<Stored>,
}

/// The pairings of the data directory.
pub struct Pairings {
    dir: PathBuf,
    file: File,
}

fn io(e: std::io::Error) -> HostError {
    HostError::new(format!("pairings.json: {}", e.kind()))
}

fn read(path: &Path) -> Result<File, HostError> {
    match fs::read(path) {
        Ok(b) => {
            let b = Zeroizing::new(b);
            serde_json::from_slice(&b).map_err(|_| HostError::new("pairings.json is invalid"))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(File::default()),
        Err(e) => Err(io(e)),
    }
}

fn decode_key(s: &Stored) -> Option<Zeroizing<[u8; 32]>> {
    let raw = Zeroizing::new(BASE64.decode(s.key.as_bytes()).ok()?);
    let mut key = Zeroizing::new([0u8; 32]);
    if raw.len() != key.len() {
        return None;
    }
    key.copy_from_slice(&raw);
    Some(key)
}

impl Pairings {
    /// Read `<data_dir>/pairings.json` (none yet is an empty list).
    pub fn load(data_dir: &Path) -> Result<Pairings, HostError> {
        ensure_dir(data_dir).map_err(io)?;
        let file = read(&data_dir.join(PAIRINGS_FILE))?;
        Ok(Pairings {
            dir: data_dir.to_path_buf(),
            file,
        })
    }

    fn path(&self) -> PathBuf {
        self.dir.join(PAIRINGS_FILE)
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.file.pairings.len()
    }

    /// The pairing key of `id`, if paired. Read from the file as it is now
    /// (another process may have paired since this one started); the copy
    /// loaded at start only serves when the file cannot be read.
    pub fn key(&self, id: &[u8; 16]) -> Option<Zeroizing<[u8; 32]>> {
        let want = BASE64.encode(id);
        let fresh = read(&self.path()).ok();
        let file = fresh.as_ref().unwrap_or(&self.file);
        let s = file.pairings.iter().find(|p| p.pairing_id == want)?;
        decode_key(s)
    }

    /// Read-modify-write under the exclusive lock: re-read the file, apply
    /// `change`, write it back atomically when `change` returns true.
    fn modify(&mut self, change: impl FnOnce(&mut File) -> bool) -> Result<(), HostError> {
        let _lock = lock_file(&self.dir.join(PAIRINGS_LOCK)).map_err(io)?;
        let mut file = read(&self.path())?;
        if change(&mut file) {
            let bytes = Zeroizing::new(
                serde_json::to_vec_pretty(&file)
                    .map_err(|_| HostError::new("cannot encode pairings.json"))?,
            );
            write_atomic(&self.path(), &bytes).map_err(io)?;
        }
        self.file = file;
        Ok(())
    }

    /// Store a completed pairing (replacing one with the same id).
    pub fn add(&mut self, rec: &PairingRecord, extension_id: &str) -> Result<(), HostError> {
        let pairing_id = BASE64.encode(&rec.pairing_id);
        let stored = Stored {
            pairing_id: pairing_id.clone(),
            key: Zeroizing::new(BASE64.encode(&*rec.key)),
            ext_name: rec.ext_name.clone(),
            browser: rec.browser.clone(),
            extension_id: extension_id.to_owned(),
            created_at: rec.created_at,
            last_used: rec.created_at,
        };
        self.modify(move |f| {
            f.pairings.retain(|p| p.pairing_id != pairing_id);
            f.pairings.push(stored);
            true
        })
    }

    /// Record a session opened with `id` at `now`.
    pub fn touch(&mut self, id: &[u8; 16], now: u64) -> Result<(), HostError> {
        let want = BASE64.encode(id);
        self.modify(
            |f| match f.pairings.iter_mut().find(|p| p.pairing_id == want) {
                Some(p) => {
                    p.last_used = now;
                    true
                }
                None => false,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn record(id: u8) -> PairingRecord {
        PairingRecord {
            pairing_id: [id; 16],
            key: Zeroizing::new([id + 1; 32]),
            ext_name: "OnePass".into(),
            browser: "Chromium".into(),
            created_at: 5,
        }
    }

    #[test]
    fn add_reload_lookup() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("data");
        let mut p = Pairings::load(&data).unwrap();
        assert_eq!(p.len(), 0);
        p.add(&record(1), "ext").unwrap();
        p.add(&record(2), "ext").unwrap();
        p.add(&record(1), "ext").unwrap();
        p.touch(&[2; 16], 9).unwrap();
        let p = Pairings::load(&data).unwrap();
        assert_eq!(p.len(), 2);
        assert_eq!(*p.key(&[1; 16]).unwrap(), [2u8; 32]);
        assert!(p.key(&[3; 16]).is_none());
        let mode = |q: &Path| fs::metadata(q).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&data.join(PAIRINGS_FILE)), 0o600);
        assert_eq!(mode(&data), 0o700);
        // No temporary file left behind: the file and its lock only.
        assert_eq!(fs::read_dir(&data).unwrap().count(), 2);
        assert_eq!(mode(&data.join(PAIRINGS_LOCK)), 0o600);
    }

    #[test]
    fn two_processes_never_lose_a_pairing() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("data");
        // Both handles load before either writes, like two host processes.
        let mut a = Pairings::load(&data).unwrap();
        let mut b = Pairings::load(&data).unwrap();
        a.add(&record(1), "ext").unwrap();
        b.add(&record(2), "ext").unwrap();
        // A's copy predates B's pairing: B's is still found, and A's touch
        // does not erase it.
        assert!(a.key(&[2; 16]).is_some());
        a.touch(&[1; 16], 9).unwrap();
        let p = Pairings::load(&data).unwrap();
        assert_eq!(p.len(), 2);
        assert!(p.key(&[1; 16]).is_some());
        assert!(p.key(&[2; 16]).is_some());
    }
}
