//! What Watchtower downloads when "Vérifier les fuites" is on, as the Apple
//! apps' `WatchtowerFetcher` does:
//!
//! - Have I Been Pwned ranges (k-anonymity): only the 5 hex character
//!   prefixes of SHA-1 hashes the core asks for (`missing_prefixes`), with
//!   `Add-Padding`, kept in memory for an hour and dropped at lock;
//! - the HIBP list of breached sites, downloaded whole and kept a week on
//!   disk. Two-factor and passkey support come from the site pack the app
//!   ships (`SITE_PACK`), as on iPhone and Android: nothing is downloaded
//!   from 2fa.directory.
//!
//! No password, hash or item ever leaves: the core compares the rest here.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

const RANGE_URL: &str = "https://api.pwnedpasswords.com/range/";
const BREACHES_URL: &str = "https://haveibeenpwned.com/api/v3/breaches";
const RANGE_LIMIT: u64 = 4 * 1024 * 1024;
const CATALOG_LIMIT: u64 = 16 * 1024 * 1024;
const RANGE_LIFETIME: Duration = Duration::from_secs(3600);
const CATALOG_LIFETIME: Duration = Duration::from_secs(7 * 86_400);
const PARALLEL: usize = 6;

/// Ranges already fetched this session.
#[derive(Default)]
pub struct RangeCache(Mutex<HashMap<String, (Instant, Vec<u8>)>>);

impl RangeCache {
    pub fn clear(&self) {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
    }

    /// The fresh ranges held, as the core takes them.
    pub fn held(&self) -> Vec<onepass_ffi::watchtower::FfiRangeResponse> {
        let map = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        map.iter()
            .filter(|(_, (at, _))| at.elapsed() < RANGE_LIFETIME)
            .map(
                |(prefix, (_, body))| onepass_ffi::watchtower::FfiRangeResponse {
                    prefix: prefix.clone(),
                    body: body.clone(),
                },
            )
            .collect()
    }

    /// Downloads the prefixes not held yet, 6 at a time. A prefix that fails
    /// is left out: the core then reports a partial check.
    pub fn fetch(&self, prefixes: &[String]) {
        let wanted: Vec<&String> = {
            let map = self.0.lock().unwrap_or_else(PoisonError::into_inner);
            prefixes
                .iter()
                .filter(|p| is_prefix(p))
                .filter(|p| {
                    map.get(*p)
                        .is_none_or(|(at, _)| at.elapsed() >= RANGE_LIFETIME)
                })
                .collect()
        };
        if wanted.is_empty() {
            return;
        }
        let agent = agent();
        for chunk in wanted.chunks(PARALLEL) {
            let got: Vec<(String, Vec<u8>)> = std::thread::scope(|scope| {
                let handles: Vec<_> = chunk
                    .iter()
                    .map(|p| {
                        let agent = agent.clone();
                        scope.spawn(move || {
                            get(&agent, &format!("{RANGE_URL}{p}"), true, RANGE_LIMIT)
                                .map(|b| ((*p).clone(), b))
                        })
                    })
                    .collect();
                handles
                    .into_iter()
                    .filter_map(|h| h.join().ok().flatten())
                    .collect()
            });
            let mut map = self.0.lock().unwrap_or_else(PoisonError::into_inner);
            for (p, body) in got {
                map.insert(p, (Instant::now(), body));
            }
        }
    }
}

/// Exactly 5 characters of 0-9 A-F, or no request is made.
fn is_prefix(p: &str) -> bool {
    p.len() == 5
        && p.bytes()
            .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b))
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_connect(Some(Duration::from_secs(15)))
        .timeout_recv_response(Some(Duration::from_secs(15)))
        .timeout_global(Some(Duration::from_secs(60)))
        .user_agent("OnePass-Watchtower")
        .http_status_as_error(true)
        .build()
        .into()
}

/// One GET, HTTP 200 only, abandoned past `limit` bytes.
fn get(agent: &ureq::Agent, url: &str, padding: bool, limit: u64) -> Option<Vec<u8>> {
    let mut req = agent.get(url);
    if padding {
        req = req.header("Add-Padding", "true");
    }
    let mut resp = req.call().ok()?;
    if resp.status() != 200 {
        return None;
    }
    resp.body_mut()
        .with_config()
        .limit(limit)
        .read_to_vec()
        .ok()
}

/// The signed site pack of the Apple apps (docs/site-pack.md), one copy in the repository: the
/// source of `missing_2fa` and `passkey_available`. No newer pack is fetched until the app carries
/// the pack's public key, as on iPhone and Android.
pub const SITE_PACK: &[u8] = include_bytes!("../../../apple/SitePack/onepass-sites.json");

/// The catalogs at hand.
#[derive(Default)]
pub struct Catalogs {
    pub breaches: Option<Vec<u8>>,
}

fn cache_dir(data: &Path) -> PathBuf {
    data.join("watchtower")
}

/// The catalogs: from the disk copy when it is less than a week old (or
/// when `network` is false), downloaded otherwise; a failed download falls
/// back on the stale copy.
pub fn catalogs(data: &Path, network: bool) -> Catalogs {
    let dir = cache_dir(data);
    let agent = network.then(agent);
    let one = |name: &str, url: &str| -> Option<Vec<u8>> {
        let path = dir.join(name);
        let fresh = std::fs::metadata(&path)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.elapsed().ok())
            .is_some_and(|age| age < CATALOG_LIFETIME);
        let cached = || std::fs::read(&path).ok();
        if fresh || agent.is_none() {
            return cached();
        }
        match agent
            .as_ref()
            .and_then(|a| get(a, url, false, CATALOG_LIMIT))
        {
            Some(body) => {
                let _ = std::fs::create_dir_all(&dir);
                let _ = std::fs::write(&path, &body);
                Some(body)
            }
            None => cached(),
        }
    };
    Catalogs {
        breaches: one("hibp-breaches.json", BREACHES_URL),
    }
}

#[cfg(test)]
mod tests {
    use super::is_prefix;

    #[test]
    fn only_five_upper_hex_characters_are_sent() {
        assert!(is_prefix("21BD1"));
        assert!(!is_prefix("21bd1"));
        assert!(!is_prefix("21BD"));
        assert!(!is_prefix("21BD12"));
        assert!(!is_prefix("21BDG"));
        assert!(!is_prefix("../x/"));
    }
}
