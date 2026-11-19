//! Open and sign in (spec 2026-11-04-open-and-sign-in): a single-use
//! pending sign-in the app records when the user taps a login's website,
//! read by the bridge host when the browser loads a page of that site.
//!
//! The entry holds the item id, the site (registrable domain) and host of
//! the item URL, and two times. Never a secret, never a username: the
//! extension still fetches the values through `fill_login`, which redoes
//! the item's own match rule. The entry lives in one file of a directory
//! only this device's apps can reach (the App Group container, or the
//! development host's `data_dir`), never leaves the device, lives
//! `PENDING_TTL` seconds and is taken at most once.
//!
//! Rules of `take`: the page and its top frame must be the same `https`
//! origin (no frame, no `http`), of the entry's site, within its life. A
//! page of another site leaves the entry in place (the user may still be on
//! the way); an expired or unreadable entry is removed.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};

use onepass_core::Id;
use serde::{Deserialize, Serialize};

use crate::origin::Origin;
use crate::{AppErrorCode, BridgeError, Result};

/// File name of the entry in its directory.
pub const PENDING_FILE: &str = "pending-sign-in.json";
/// Life of an entry, in seconds.
pub const PENDING_TTL: u64 = 60;
/// Clock skew tolerated between the app writing and the host reading.
const SKEW: u64 = 5;
/// Largest entry file read (a few hundred bytes in practice).
const MAX_FILE: u64 = 4096;

/// One pending sign-in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingSignIn {
    pub v: u8,
    /// Hyphenated item id.
    pub item_id: String,
    /// Registrable domain of the item URL.
    pub site: String,
    /// Host of the item URL (shown in logs and tests, not matched).
    pub host: String,
    /// Unix seconds.
    pub created: u64,
    pub expires: u64,
}

fn invalid() -> BridgeError {
    BridgeError::App(AppErrorCode::Invalid)
}

/// The item URL as the page it opens: a bare host is read as `https`, an
/// `http` URL is refused (`insecure_origin`).
fn item_origin(url: &str) -> Result<Origin> {
    let url = url.trim();
    if url.is_empty() {
        return Err(invalid());
    }
    if url.contains("://") {
        Origin::parse(url)
    } else {
        Origin::parse(&format!("https://{url}"))
    }
}

impl PendingSignIn {
    /// The entry for `item_id` opening `item_url` at `now`.
    pub fn new(item_id: Id, item_url: &str, now: u64) -> Result<Self> {
        let o = item_origin(item_url)?;
        Ok(Self {
            v: 1,
            item_id: item_id.to_string(),
            site: o.site(),
            host: o.host().to_owned(),
            created: now,
            expires: now + PENDING_TTL,
        })
    }

    /// Well formed and alive at `now`: an entry from the future (beyond the
    /// skew) or living longer than `PENDING_TTL` is not trusted.
    pub fn alive(&self, now: u64) -> bool {
        self.v == 1
            && self.expires > self.created
            && self.expires - self.created <= PENDING_TTL
            && now + SKEW >= self.created
            && now < self.expires
            && Id::from_str(&self.item_id).is_ok()
    }

    /// The page `origin`, in a top frame of `top_origin`, may take it at
    /// `now`.
    pub fn matches(&self, origin: &str, top_origin: &str, now: u64) -> bool {
        let (Ok(page), Ok(top)) = (Origin::parse(origin), Origin::parse(top_origin)) else {
            return false;
        };
        self.alive(now) && page.origin_string() == top.origin_string() && page.site() == self.site
    }
}

/// The directory holding the entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingStore {
    dir: PathBuf,
}

static CLAIMS: AtomicU64 = AtomicU64::new(0);

impl PendingStore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    pub fn path(&self) -> PathBuf {
        self.dir.join(PENDING_FILE)
    }

    /// Record a sign-in of `item_id` on `item_url`, replacing any other.
    pub fn record(&self, item_id: Id, item_url: &str, now: u64) -> Result<PendingSignIn> {
        let entry = PendingSignIn::new(item_id, item_url, now)?;
        let text = serde_json::to_vec(&entry).map_err(|_| invalid())?;
        write_private(&self.dir, &self.path(), &text).map_err(|e| BridgeError::Io(e.kind()))?;
        Ok(entry)
    }

    /// Remove the entry, if any.
    pub fn clear(&self) {
        let _ = fs::remove_file(self.path());
    }

    fn read(path: &Path) -> Option<PendingSignIn> {
        let meta = fs::metadata(path).ok()?;
        if !meta.is_file() || meta.len() > MAX_FILE {
            return None;
        }
        serde_json::from_slice(&fs::read(path).ok()?).ok()
    }

    /// The entry, untouched, when one is there and alive at `now`. An
    /// expired or unreadable entry is removed.
    pub fn peek(&self, now: u64) -> Option<PendingSignIn> {
        let path = self.path();
        if !path.exists() {
            return None;
        }
        match Self::read(&path) {
            Some(e) if e.alive(now) => Some(e),
            _ => {
                let _ = fs::remove_file(&path);
                None
            }
        }
    }

    /// Take the entry for page `origin` (top frame `top_origin`) at `now`:
    /// the item id, once. Anything else gives `None`.
    pub fn take(&self, origin: &str, top_origin: &str, now: u64) -> Option<Id> {
        let entry = self.peek(now)?;
        if !entry.matches(origin, top_origin, now) {
            return None;
        }
        // Claim by rename: of two hosts taking at once, one wins.
        let path = self.path();
        let n = CLAIMS.fetch_add(1, Ordering::Relaxed);
        let claimed = self
            .dir
            .join(format!(".{PENDING_FILE}.{}.{n}", std::process::id()));
        fs::rename(&path, &claimed).ok()?;
        let again = Self::read(&claimed);
        let _ = fs::remove_file(&claimed);
        // Replaced between the read and the claim: the new one is gone too,
        // which is the safe side (the user taps again).
        let again = again.filter(|e| *e == entry)?;
        Id::from_str(&again.item_id).ok()
    }
}

/// Write `bytes` to `path` (0600 on Unix) through a temporary file and a
/// rename, so a reader never sees half an entry.
fn write_private(dir: &Path, path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    fs::create_dir_all(dir)?;
    let n = CLAIMS.fetch_add(1, Ordering::Relaxed);
    let tmp = dir.join(format!(".{PENDING_FILE}.tmp.{}.{n}", std::process::id()));
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let result = (|| {
        let mut f = opts.open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> PendingStore {
        let n = CLAIMS.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "onepass-pending-{}-{n}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        PendingStore::new(dir)
    }

    fn id() -> Id {
        Id::from_str("0192f1a0-0000-7000-8000-000000000001").unwrap()
    }

    const T: u64 = 1_800_000_000;

    #[test]
    fn taken_once_on_the_site() {
        let s = store();
        s.record(id(), "https://google.com", T).unwrap();
        let page = "https://accounts.google.com";
        assert_eq!(s.take(page, page, T + 1), Some(id()));
        assert_eq!(s.take(page, page, T + 2), None);
        assert!(!s.path().exists());
    }

    #[test]
    fn bare_host_reads_as_https() {
        let s = store();
        let e = s.record(id(), "atlas-cloud.test/login", T).unwrap();
        assert_eq!(e.site, "atlas-cloud.test");
        assert_eq!(e.host, "atlas-cloud.test");
        assert_eq!(e.expires, T + PENDING_TTL);
    }

    #[test]
    fn expired_gives_nothing_and_is_removed() {
        let s = store();
        s.record(id(), "https://atlas-cloud.test", T).unwrap();
        let page = "https://atlas-cloud.test";
        assert_eq!(s.take(page, page, T + PENDING_TTL), None);
        assert!(!s.path().exists());
    }

    #[test]
    fn other_site_gives_nothing_and_keeps_it() {
        let s = store();
        s.record(id(), "https://atlas-cloud.test", T).unwrap();
        let evil = "https://atlas-cloud.test.evil.test";
        assert_eq!(s.take(evil, evil, T + 1), None);
        assert!(s.path().exists());
        let page = "https://www.atlas-cloud.test";
        assert_eq!(s.take(page, page, T + 2), Some(id()));
    }

    #[test]
    fn http_is_refused() {
        let s = store();
        assert_eq!(
            s.record(id(), "http://atlas-cloud.test", T).unwrap_err(),
            BridgeError::App(AppErrorCode::InsecureOrigin)
        );
        s.record(id(), "https://atlas-cloud.test", T).unwrap();
        let page = "http://atlas-cloud.test";
        assert_eq!(s.take(page, page, T + 1), None);
        assert!(s.path().exists());
    }

    #[test]
    fn cross_site_frame_is_refused() {
        let s = store();
        s.record(id(), "https://atlas-cloud.test", T).unwrap();
        // The login page framed by another site, and a frame of another
        // origin of the same site: both refused.
        assert_eq!(
            s.take("https://atlas-cloud.test", "https://evil.test", T + 1),
            None
        );
        assert_eq!(
            s.take(
                "https://login.atlas-cloud.test",
                "https://atlas-cloud.test",
                T + 1
            ),
            None
        );
        assert!(s.path().exists());
    }

    #[test]
    fn a_new_record_replaces_the_old() {
        let s = store();
        let other = Id::from_str("0192f1a0-0000-7000-8000-000000000002").unwrap();
        s.record(id(), "https://atlas-cloud.test", T).unwrap();
        s.record(other, "https://google.com", T + 1).unwrap();
        let page = "https://atlas-cloud.test";
        assert_eq!(s.take(page, page, T + 2), None);
        let g = "https://accounts.google.com";
        assert_eq!(s.take(g, g, T + 2), Some(other));
    }

    #[test]
    fn forged_entries_are_not_trusted() {
        let s = store();
        let mut e = PendingSignIn::new(id(), "https://atlas-cloud.test", T).unwrap();
        e.expires = T + 3600;
        fs::create_dir_all(&s.dir).unwrap();
        fs::write(s.path(), serde_json::to_vec(&e).unwrap()).unwrap();
        let page = "https://atlas-cloud.test";
        assert_eq!(s.take(page, page, T + 1), None);
        assert!(!s.path().exists());
        // From the future.
        let e = PendingSignIn::new(id(), "https://atlas-cloud.test", T + 600).unwrap();
        fs::write(s.path(), serde_json::to_vec(&e).unwrap()).unwrap();
        assert_eq!(s.take(page, page, T), None);
        fs::write(s.path(), b"not json").unwrap();
        assert_eq!(s.take(page, page, T), None);
        assert!(!s.path().exists());
    }

    #[cfg(unix)]
    #[test]
    fn file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let s = store();
        s.record(id(), "https://atlas-cloud.test", T).unwrap();
        let mode = fs::metadata(s.path()).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
