//! Short-lived, revocable grants persisted in a signed file (`grants.json`,
//! domain `grants`), reread at every check so a revocation from another
//! terminal acts on a running server.
//!
//! File payload:
//! `{ "account_id", "generation", "grants": [Grant...], "revoked": [{ "id", "expires_at" }] }`.
//!
//! - Every write increments `generation`; a [`GrantStore`] remembers the
//!   highest generation it has read or written and refuses an older file
//!   (an authentic file restored after a revocation), treating it as holding
//!   no grants.
//! - A revoked grant stays in `grants` and its id is listed in `revoked`
//!   until it expires, so [`GrantStore::check`] can answer
//!   [`GrantCheck::Revoked`] instead of [`GrantCheck::None`].
//! - Expiry: `expires_at` must be in the future on the wall clock, and for a
//!   grant issued by this process the monotonic deadline (`issued + ttl`)
//!   must not have passed either, so rolling the wall clock back does not
//!   revive it. A grant this process did not issue relies on wall time only
//!   (plus `created_at <= now`, which catches a rollback before its creation).
//! - Expired grants and tombstones are pruned at every write.
//! - Read-modify-write runs under an exclusive lock on `<path>.lock`, reads
//!   under a shared lock.

use crate::approval::Surface;
use crate::clock::Clock;
use crate::signed::{lock_sibling, write_private_atomic};
use crate::{GuardError, LocalSigner, open_config, seal_config};
use data_encoding::HEXLOWER;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::ErrorKind;
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// Signature domain of the grants file.
pub const GRANTS_DOMAIN: &[u8] = b"grants";
/// Default lifetime of a grant.
pub const DEFAULT_GRANT_TTL: Duration = Duration::from_secs(5 * 60);
/// Longest lifetime of a grant; longer requests are clamped.
pub const MAX_GRANT_TTL: Duration = Duration::from_secs(60 * 60);

/// One grant. Never contains secrets.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    /// Random id, 16 lowercase hex characters.
    pub id: String,
    /// Code identity of the client the grant is bound to.
    pub client_id: String,
    /// The surface that issued the grant.
    pub surface: Surface,
    /// The approved action.
    pub action: String,
    /// The exact request key the grant covers.
    pub key: String,
    /// The vault involved, if any.
    pub vault_id: Option<String>,
    /// Creation time, seconds since the Unix epoch.
    pub created_at: i64,
    /// Expiry time, seconds since the Unix epoch.
    pub expires_at: i64,
}

/// What a new grant covers; the store sets the id and the times.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantRequest {
    /// Code identity of the client.
    pub client_id: String,
    /// The surface.
    pub surface: Surface,
    /// The approved action.
    pub action: String,
    /// The exact request key.
    pub key: String,
    /// The vault involved, if any.
    pub vault_id: Option<String>,
}

/// Result of [`GrantStore::check`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GrantCheck {
    /// A live grant covers the request.
    Valid(Grant),
    /// A grant covered the request but has expired.
    Expired,
    /// A grant covered the request but was revoked.
    Revoked,
    /// No grant covers the request (or the file could not be trusted).
    None,
}

/// What [`GrantStore::revoke`] revokes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Revoke {
    /// One grant by id.
    Id(String),
    /// Every grant of one client id.
    Client(String),
    /// Every grant.
    All,
}

/// A revoked grant id, kept until the grant would have expired: in the file
/// (`revoked`), in control notifications, and in the memory of servers.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct RevokedGrant {
    /// The grant id.
    pub id: String,
    /// When the grant would have expired (seconds since the Unix epoch).
    pub expires_at: i64,
}

/// What a revocation covers, pushed to running servers as such, so it also
/// covers grants the revoking command did not see (its file may have been
/// restored). `created_at` comes from the signed grant.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(untagged)]
pub enum RevokeSelector {
    /// One grant by id.
    Id {
        /// The grant id.
        id: String,
    },
    /// Every grant of `client_id` created at or before the revocation.
    Client {
        /// Code identity of the client.
        client_id: String,
        /// Wall time of the revocation.
        created_at_or_before: i64,
    },
    /// Every grant created at or before the revocation.
    All {
        /// Wall time of the revocation.
        all_created_at_or_before: i64,
    },
}

impl RevokeSelector {
    /// True if `g` is covered.
    pub fn matches(&self, g: &Grant) -> bool {
        match self {
            RevokeSelector::Id { id } => &g.id == id,
            RevokeSelector::Client {
                client_id,
                created_at_or_before,
            } => &g.client_id == client_id && g.created_at <= *created_at_or_before,
            RevokeSelector::All {
                all_created_at_or_before,
            } => g.created_at <= *all_created_at_or_before,
        }
    }

    /// The selector for `which`, revoked at wall time `now`.
    pub fn for_revoke(which: &Revoke, now: i64) -> Self {
        match which {
            Revoke::Id(id) => RevokeSelector::Id { id: id.clone() },
            Revoke::Client(c) => RevokeSelector::Client {
                client_id: c.clone(),
                created_at_or_before: now,
            },
            Revoke::All => RevokeSelector::All {
                all_created_at_or_before: now,
            },
        }
    }
}

/// Result of [`GrantStore::revoke`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevokeOutcome {
    /// The selector of this revocation, pushed to running servers.
    pub selector: RevokeSelector,
    /// Grants revoked by this call (not revoked before).
    pub newly: usize,
    /// Every unexpired grant matching the request, revoked before or now:
    /// what the command pushes to running servers.
    pub revoked: Vec<RevokedGrant>,
    /// The generation of the file after the call.
    pub generation: u64,
}

/// The signed payload of `grants.json`.
#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct GrantsFile {
    account_id: String,
    generation: u64,
    grants: Vec<Grant>,
    revoked: Vec<RevokedGrant>,
}

impl GrantsFile {
    fn empty(account_id: &str, generation: u64) -> Self {
        GrantsFile {
            account_id: account_id.to_owned(),
            generation,
            grants: Vec::new(),
            revoked: Vec::new(),
        }
    }

    fn revoked_ids(&self) -> HashSet<&str> {
        self.revoked.iter().map(|t| t.id.as_str()).collect()
    }

    /// Drops grants and tombstones whose wall-clock expiry has passed.
    fn prune(&mut self, now: i64) {
        self.grants.retain(|g| g.expires_at > now);
        self.revoked.retain(|t| t.expires_at > now);
    }
}

/// The state of one grant at one instant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Live,
    Expired,
    Revoked,
}

/// The grants file of one account, with the replay memory of this process.
#[derive(Debug)]
pub struct GrantStore {
    path: PathBuf,
    account_id: String,
    generation_seen: u64,
    /// Grant id to monotonic deadline, for grants issued by this process.
    issued: HashMap<String, Instant>,
    /// Revocations pushed by control notifications: grant id to expiry. They
    /// hold whatever the file says, until the grant would have expired.
    pushed_revoked: HashMap<String, i64>,
    /// Revocation selectors pushed by control notifications, each with the
    /// wall time until which it is kept (every grant it can match has
    /// expired by then).
    pushed_selectors: Vec<(RevokeSelector, i64)>,
}

impl GrantStore {
    /// A store for the grants file at `path`, belonging to `account_id`.
    /// Nothing is read until the first operation.
    pub fn open(path: impl Into<PathBuf>, account_id: &str) -> Self {
        GrantStore {
            path: path.into(),
            account_id: account_id.to_owned(),
            generation_seen: 0,
            issued: HashMap::new(),
            pushed_revoked: HashMap::new(),
            pushed_selectors: Vec::new(),
        }
    }

    /// Highest generation read or written so far.
    pub fn generation_seen(&self) -> u64 {
        self.generation_seen
    }

    /// Raises the replay floor to `generation` (never lowers it). Called when
    /// a signed control notification announces a newer file written by
    /// another process, so restoring an older file afterwards is refused.
    pub fn raise_floor(&mut self, generation: u64) {
        self.generation_seen = self.generation_seen.max(generation);
    }

    /// Applies a verified control notification: raises the floor, remembers
    /// each enumerated revoked grant until its expiry and each selector for
    /// the longest grant life, so a restored or laundered file (even one at
    /// a higher generation, even one holding grants the revoking command
    /// never saw) cannot revive a covered grant in this process.
    pub fn apply_revocations(
        &mut self,
        clock: &dyn Clock,
        generation: u64,
        revoked: &[RevokedGrant],
        selectors: &[RevokeSelector],
    ) {
        self.raise_floor(generation);
        let now = clock.now_unix();
        // `MAX_GRANT_TTL` is 3600 s: the cast cannot truncate.
        let life = MAX_GRANT_TTL.as_secs() as i64;
        for sel in selectors {
            let since = match sel {
                RevokeSelector::Id { .. } => now,
                RevokeSelector::Client {
                    created_at_or_before,
                    ..
                } => now.max(*created_at_or_before),
                RevokeSelector::All {
                    all_created_at_or_before,
                } => now.max(*all_created_at_or_before),
            };
            self.pushed_selectors
                .push((sel.clone(), since.saturating_add(life)));
        }
        for r in revoked {
            let e = self
                .pushed_revoked
                .entry(r.id.clone())
                .or_insert(r.expires_at);
            *e = (*e).max(r.expires_at);
        }
    }

    /// Selectors pushed to this store and still remembered.
    pub fn pushed_selectors(&self) -> Vec<RevokeSelector> {
        self.pushed_selectors
            .iter()
            .map(|(s, _)| s.clone())
            .collect()
    }

    /// Forgets pushed revocations that can no longer match a live grant.
    fn prune_pushed(&mut self, now: i64) {
        self.pushed_revoked.retain(|_, e| *e > now);
        self.pushed_selectors.retain(|(_, until)| *until > now);
    }

    /// True if a pushed revocation covers `g`.
    fn pushed_covers(&self, g: &Grant) -> bool {
        self.pushed_revoked.contains_key(&g.id)
            || self.pushed_selectors.iter().any(|(s, _)| s.matches(g))
    }

    /// Ids of the revocations pushed to this store and still remembered.
    pub fn pushed_revocations(&self) -> Vec<RevokedGrant> {
        let mut v: Vec<RevokedGrant> = self
            .pushed_revoked
            .iter()
            .map(|(id, e)| RevokedGrant {
                id: id.clone(),
                expires_at: *e,
            })
            .collect();
        v.sort();
        v
    }

    /// Records a grant for `req` valid for `ttl` (clamped to
    /// [`MAX_GRANT_TTL`]) and returns it.
    pub fn add(
        &mut self,
        signer: &dyn LocalSigner,
        clock: &dyn Clock,
        req: GrantRequest,
        ttl: Duration,
    ) -> Result<Grant, GuardError> {
        let secs = ttl.min(MAX_GRANT_TTL).as_secs();
        let _lock = self.lock(true)?;
        let (mut file, _) = self.load_for_write(signer)?;
        let now = clock.now_unix();
        let mono = clock.monotonic();
        file.prune(now);
        let id = loop {
            let id = random_id()?;
            if !file.grants.iter().any(|g| g.id == id) && !file.revoked.iter().any(|t| t.id == id) {
                break id;
            }
        };
        let grant = Grant {
            id,
            client_id: req.client_id,
            surface: req.surface,
            action: req.action,
            key: req.key,
            vault_id: req.vault_id,
            created_at: now,
            // `secs` is at most 3600: the cast cannot truncate.
            expires_at: now.saturating_add(secs as i64),
        };
        file.grants.push(grant.clone());
        self.write(signer, file)?;
        self.issued
            .insert(grant.id.clone(), mono + Duration::from_secs(secs));
        Ok(grant)
    }

    /// Looks for a grant covering exactly (`client_id`, `surface`, `action`,
    /// `key`). Any failure to read or trust the file gives
    /// [`GrantCheck::None`].
    pub fn check(
        &mut self,
        signer: &dyn LocalSigner,
        clock: &dyn Clock,
        client_id: &str,
        surface: Surface,
        action: &str,
        key: &str,
    ) -> GrantCheck {
        let file = match self.lock(false).and_then(|_lock| self.read_checked(signer)) {
            Ok(f) => f,
            Err(_) => return GrantCheck::None,
        };
        self.generation_seen = self.generation_seen.max(file.generation);
        let now = clock.now_unix();
        self.prune_pushed(now);
        let revoked = file.revoked_ids();
        let mut result = GrantCheck::None;
        for g in file.grants.iter().filter(|g| {
            g.client_id == client_id && g.surface == surface && g.action == action && g.key == key
        }) {
            match self.state(g, &revoked, clock) {
                State::Live => return GrantCheck::Valid(g.clone()),
                State::Revoked => result = GrantCheck::Revoked,
                State::Expired => {
                    if result == GrantCheck::None {
                        result = GrantCheck::Expired;
                    }
                }
            }
        }
        result
    }

    /// Revokes the matching live grants. The file is rewritten (higher
    /// generation) only if at least one grant was newly revoked (or a
    /// replayed file had to be replaced). The outcome lists every unexpired
    /// matching grant, newly or already revoked, and the selector of the
    /// revocation (`Revoke::Id` gives an id selector even when the id is not
    /// in the file read), for the control push.
    pub fn revoke(
        &mut self,
        signer: &dyn LocalSigner,
        clock: &dyn Clock,
        which: Revoke,
    ) -> Result<RevokeOutcome, GuardError> {
        let _lock = self.lock(true)?;
        let (mut file, healed) = self.load_for_write(signer)?;
        if !healed {
            self.generation_seen = self.generation_seen.max(file.generation);
        }
        let now = clock.now_unix();
        let selector = RevokeSelector::for_revoke(&which, now);
        let already: HashSet<String> = file.revoked.iter().map(|t| t.id.clone()).collect();
        let mut matching: Vec<RevokedGrant> = file
            .grants
            .iter()
            .filter(|g| selector.matches(g) && g.expires_at > now)
            .map(|g| RevokedGrant {
                id: g.id.clone(),
                expires_at: g.expires_at,
            })
            .collect();
        matching.sort();
        let newly: Vec<RevokedGrant> = matching
            .iter()
            .filter(|r| !already.contains(&r.id))
            .cloned()
            .collect();
        let count = newly.len();
        if count > 0 || healed {
            file.revoked.extend(newly);
            file.prune(now);
            self.write(signer, file)?;
        }
        Ok(RevokeOutcome {
            selector,
            newly: count,
            revoked: matching,
            generation: self.generation_seen,
        })
    }

    /// The live (unexpired, unrevoked) grants.
    pub fn list(
        &mut self,
        signer: &dyn LocalSigner,
        clock: &dyn Clock,
    ) -> Result<Vec<Grant>, GuardError> {
        let file = {
            let _lock = self.lock(false)?;
            self.read_checked(signer)?
        };
        self.generation_seen = self.generation_seen.max(file.generation);
        let now = clock.now_unix();
        self.prune_pushed(now);
        let revoked = file.revoked_ids();
        Ok(file
            .grants
            .iter()
            .filter(|g| self.state(g, &revoked, clock) == State::Live)
            .cloned()
            .collect())
    }

    fn state(&self, g: &Grant, revoked: &HashSet<&str>, clock: &dyn Clock) -> State {
        if revoked.contains(g.id.as_str()) || self.pushed_covers(g) {
            return State::Revoked;
        }
        let now = clock.now_unix();
        let lifetime = g.expires_at.saturating_sub(g.created_at);
        // `MAX_GRANT_TTL` is 3600 s: the cast cannot truncate.
        if g.created_at > now || now >= g.expires_at || lifetime > MAX_GRANT_TTL.as_secs() as i64 {
            return State::Expired;
        }
        match self.issued.get(&g.id) {
            Some(deadline) if clock.monotonic() >= *deadline => State::Expired,
            _ => State::Live,
        }
    }

    /// Locks `<path>.lock` (bounded wait, see `lock_sibling`).
    fn lock(&self, exclusive: bool) -> Result<File, GuardError> {
        lock_sibling(&self.path, exclusive)
    }

    /// Reads and verifies the file, without the replay check. A missing file
    /// is empty at generation 0.
    fn read_raw(&self, signer: &dyn LocalSigner) -> Result<GrantsFile, GuardError> {
        let text = match fs::read_to_string(&self.path) {
            Ok(t) => t,
            Err(e) if e.kind() == ErrorKind::NotFound => {
                return Ok(GrantsFile::empty(&self.account_id, 0));
            }
            Err(e) => return Err(e.into()),
        };
        let payload = open_config(signer, GRANTS_DOMAIN, &text)?;
        let file: GrantsFile =
            serde_json::from_str(&payload).map_err(|_| GuardError::Format("grants file"))?;
        if file.account_id != self.account_id {
            return Err(GuardError::Tampered("grants file of another account"));
        }
        Ok(file)
    }

    /// Like `read_raw`, refusing a file older than one already seen.
    fn read_checked(&self, signer: &dyn LocalSigner) -> Result<GrantsFile, GuardError> {
        let file = self.read_raw(signer)?;
        if file.generation < self.generation_seen {
            return Err(GuardError::Tampered(
                "grants file older than one already seen",
            ));
        }
        Ok(file)
    }

    /// The file to modify. A replayed (older) file is replaced by an empty
    /// one, so nothing it holds comes back; the flag says so.
    fn load_for_write(&self, signer: &dyn LocalSigner) -> Result<(GrantsFile, bool), GuardError> {
        let file = self.read_raw(signer)?;
        if file.generation < self.generation_seen {
            return Ok((
                GrantsFile::empty(&self.account_id, self.generation_seen),
                true,
            ));
        }
        Ok((file, false))
    }

    /// Writes `file` signed with a generation above everything seen.
    fn write(&mut self, signer: &dyn LocalSigner, mut file: GrantsFile) -> Result<(), GuardError> {
        // Pushed revocations go back into the file, so a laundered file is
        // repaired by the next write of this process.
        let listed: HashSet<String> = file.revoked.iter().map(|t| t.id.clone()).collect();
        let repaired: Vec<RevokedGrant> = file
            .grants
            .iter()
            .filter(|g| !listed.contains(&g.id) && self.pushed_covers(g))
            .map(|g| RevokedGrant {
                id: g.id.clone(),
                expires_at: g.expires_at,
            })
            .collect();
        file.revoked.extend(repaired);
        file.generation = file
            .generation
            .max(self.generation_seen)
            .checked_add(1)
            .ok_or(GuardError::Format("grants generation"))?;
        let payload =
            serde_json::to_string(&file).map_err(|_| GuardError::Format("grants file"))?;
        let sealed = seal_config(signer, GRANTS_DOMAIN, &payload)?;
        write_private_atomic(&self.path, sealed.as_bytes())?;
        self.generation_seen = file.generation;
        // `issued` pruning: an entry is kept as long as its grant is still in
        // the file, even after its monotonic deadline, because dropping it
        // would let a wall clock rolled back (but still after `created_at`)
        // make the grant look live again to this process. Grants leave the
        // file once expired on the wall clock (pruned on write), which bounds
        // the map by the size of the file.
        let ids: HashSet<&str> = file.grants.iter().map(|g| g.id.as_str()).collect();
        self.issued.retain(|id, _| ids.contains(id.as_str()));
        Ok(())
    }
}

/// A random grant id: 8 bytes as 16 lowercase hex characters.
fn random_id() -> Result<String, GuardError> {
    let mut b = [0u8; 8];
    aws_lc_rs::rand::fill(&mut b).map_err(|_| GuardError::Format("random source"))?;
    Ok(HEXLOWER.encode(&b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::testing::FakeClock;
    use crate::testutil::TestSigner;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    const T0: i64 = 1_800_000_000;
    const MIN: Duration = Duration::from_secs(60);

    fn req(client: &str, key: &str) -> GrantRequest {
        GrantRequest {
            client_id: client.to_owned(),
            surface: Surface::Mcp,
            action: "use".to_owned(),
            key: key.to_owned(),
            vault_id: Some("vault-1".to_owned()),
        }
    }

    fn check(
        st: &mut GrantStore,
        s: &TestSigner,
        c: &FakeClock,
        client: &str,
        key: &str,
    ) -> GrantCheck {
        st.check(s, c, client, Surface::Mcp, "use", key)
    }

    fn setup() -> (tempfile::TempDir, PathBuf, TestSigner, FakeClock) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("grants.json");
        (dir, path, TestSigner::new(), FakeClock::new(T0))
    }

    /// The decoded payload of the grants file.
    fn payload(path: &std::path::Path, s: &TestSigner) -> serde_json::Value {
        let text = fs::read_to_string(path).unwrap();
        serde_json::from_str(&open_config(s, GRANTS_DOMAIN, &text).unwrap()).unwrap()
    }

    #[test]
    fn add_then_check_valid() {
        let (_d, path, s, c) = setup();
        let mut st = GrantStore::open(&path, "acc");
        let g = st
            .add(&s, &c, req("platform:a", "k1"), DEFAULT_GRANT_TTL)
            .unwrap();
        assert_eq!(g.id.len(), 16);
        assert!(
            g.id.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );
        assert_eq!(g.created_at, T0);
        assert_eq!(g.expires_at, T0 + 300);
        assert_eq!(
            check(&mut st, &s, &c, "platform:a", "k1"),
            GrantCheck::Valid(g.clone())
        );
        // Another key, action or surface is not covered.
        assert_eq!(check(&mut st, &s, &c, "platform:a", "k2"), GrantCheck::None);
        assert_eq!(
            st.check(&s, &c, "platform:a", Surface::Mcp, "reveal", "k1"),
            GrantCheck::None
        );
        assert_eq!(
            st.check(&s, &c, "platform:a", Surface::Ssh, "use", "k1"),
            GrantCheck::None
        );
        // Another process (another store) sees it too.
        let mut other = GrantStore::open(&path, "acc");
        assert_eq!(
            check(&mut other, &s, &c, "platform:a", "k1"),
            GrantCheck::Valid(g.clone())
        );
        assert_eq!(st.list(&s, &c).unwrap(), vec![g]);
    }

    #[test]
    fn grants_file_mode_0600() {
        let (_d, path, s, c) = setup();
        let mut st = GrantStore::open(&path, "acc");
        st.add(&s, &c, req("platform:a", "k1"), DEFAULT_GRANT_TTL)
            .unwrap();
        let mode = |p: &std::path::Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600);
        let mut lock = path.as_os_str().to_owned();
        lock.push(".lock");
        assert_eq!(mode(std::path::Path::new(&lock)), 0o600);
    }

    #[test]
    fn missing_file_has_no_grants() {
        let (_d, path, s, c) = setup();
        let mut st = GrantStore::open(&path, "acc");
        assert_eq!(check(&mut st, &s, &c, "platform:a", "k1"), GrantCheck::None);
        assert!(st.list(&s, &c).unwrap().is_empty());
    }

    #[test]
    fn expired_grant_is_refused_and_reported() {
        let (_d, path, s, c) = setup();
        let mut st = GrantStore::open(&path, "acc");
        st.add(&s, &c, req("platform:a", "k1"), DEFAULT_GRANT_TTL)
            .unwrap();
        c.advance(DEFAULT_GRANT_TTL - Duration::from_secs(1));
        assert!(matches!(
            check(&mut st, &s, &c, "platform:a", "k1"),
            GrantCheck::Valid(_)
        ));
        c.advance(Duration::from_secs(1));
        assert_eq!(
            check(&mut st, &s, &c, "platform:a", "k1"),
            GrantCheck::Expired
        );
        let mut other = GrantStore::open(&path, "acc");
        assert_eq!(
            check(&mut other, &s, &c, "platform:a", "k1"),
            GrantCheck::Expired
        );
        assert!(st.list(&s, &c).unwrap().is_empty());
    }

    #[test]
    fn wall_clock_rollback_does_not_revive_grant() {
        let (_d, path, s, c) = setup();
        let mut st = GrantStore::open(&path, "acc");
        st.add(&s, &c, req("platform:a", "k1"), DEFAULT_GRANT_TTL)
            .unwrap();
        c.advance(10 * MIN);
        assert_eq!(
            check(&mut st, &s, &c, "platform:a", "k1"),
            GrantCheck::Expired
        );
        // The wall clock is set back to just after the creation.
        c.set_now_unix(T0 + 10);
        assert_eq!(
            check(&mut st, &s, &c, "platform:a", "k1"),
            GrantCheck::Expired
        );
        assert!(st.list(&s, &c).unwrap().is_empty());
        // Back before the creation: refused even by a store that did not issue it.
        c.set_now_unix(T0 - 10);
        let mut other = GrantStore::open(&path, "acc");
        assert_eq!(
            check(&mut other, &s, &c, "platform:a", "k1"),
            GrantCheck::Expired
        );
    }

    #[test]
    fn revoked_grant_reported_revoked() {
        let (_d, path, s, c) = setup();
        let mut st = GrantStore::open(&path, "acc");
        let g = st
            .add(&s, &c, req("platform:a", "k1"), DEFAULT_GRANT_TTL)
            .unwrap();
        st.add(&s, &c, req("platform:a", "k2"), DEFAULT_GRANT_TTL)
            .unwrap();
        // Revoked from another terminal (another store).
        let mut cli = GrantStore::open(&path, "acc");
        let out = cli.revoke(&s, &c, Revoke::Id(g.id.clone())).unwrap();
        assert_eq!(out.newly, 1);
        assert_eq!(
            out.revoked,
            vec![RevokedGrant {
                id: g.id.clone(),
                expires_at: g.expires_at
            }]
        );
        assert_eq!(out.generation, cli.generation_seen());
        assert_eq!(
            check(&mut st, &s, &c, "platform:a", "k1"),
            GrantCheck::Revoked
        );
        assert!(matches!(
            check(&mut st, &s, &c, "platform:a", "k2"),
            GrantCheck::Valid(_)
        ));
        // Revoking it again changes nothing and does not rewrite the file.
        let gen_before = payload(&path, &s)["generation"].as_u64().unwrap();
        let again = cli.revoke(&s, &c, Revoke::Id(g.id.clone())).unwrap();
        assert_eq!(again.newly, 0);
        // Still listed for the push, so a command can re-push it.
        assert_eq!(again.revoked.len(), 1);
        assert_eq!(
            payload(&path, &s)["generation"].as_u64().unwrap(),
            gen_before
        );
        assert_eq!(st.list(&s, &c).unwrap().len(), 1);
        // A new grant for the same request is valid again.
        st.add(&s, &c, req("platform:a", "k1"), DEFAULT_GRANT_TTL)
            .unwrap();
        assert!(matches!(
            check(&mut st, &s, &c, "platform:a", "k1"),
            GrantCheck::Valid(_)
        ));
    }

    #[test]
    fn revoke_by_client_and_all() {
        let (_d, path, s, c) = setup();
        let mut st = GrantStore::open(&path, "acc");
        st.add(&s, &c, req("platform:a", "k1"), DEFAULT_GRANT_TTL)
            .unwrap();
        st.add(&s, &c, req("platform:a", "k2"), DEFAULT_GRANT_TTL)
            .unwrap();
        st.add(&s, &c, req("platform:b", "k1"), DEFAULT_GRANT_TTL)
            .unwrap();
        st.add(&s, &c, req("platform:c", "k1"), DEFAULT_GRANT_TTL)
            .unwrap();
        assert_eq!(
            st.revoke(&s, &c, Revoke::Client("platform:a".into()))
                .unwrap()
                .newly,
            2
        );
        assert_eq!(
            check(&mut st, &s, &c, "platform:a", "k2"),
            GrantCheck::Revoked
        );
        assert!(matches!(
            check(&mut st, &s, &c, "platform:b", "k1"),
            GrantCheck::Valid(_)
        ));
        let all = st.revoke(&s, &c, Revoke::All).unwrap();
        assert_eq!(all.newly, 2);
        assert_eq!(all.revoked.len(), 4);
        assert_eq!(
            check(&mut st, &s, &c, "platform:b", "k1"),
            GrantCheck::Revoked
        );
        assert!(st.list(&s, &c).unwrap().is_empty());
    }

    #[test]
    fn restored_file_after_revoke_refused() {
        let (_d, path, s, c) = setup();
        let mut st = GrantStore::open(&path, "acc");
        let g = st
            .add(&s, &c, req("platform:a", "k1"), DEFAULT_GRANT_TTL)
            .unwrap();
        let saved = fs::read(&path).unwrap();
        assert_eq!(st.revoke(&s, &c, Revoke::Id(g.id)).unwrap().newly, 1);
        fs::write(&path, &saved).unwrap();
        assert!(!matches!(
            check(&mut st, &s, &c, "platform:a", "k1"),
            GrantCheck::Valid(_)
        ));
        assert!(matches!(st.list(&s, &c), Err(GuardError::Tampered(_))));
        // A server that read the newer file refuses the restored one as well.
        let mut server = GrantStore::open(&path, "acc");
        fs::remove_file(&path).unwrap();
        st.add(&s, &c, req("platform:z", "kz"), DEFAULT_GRANT_TTL)
            .unwrap();
        let _ = check(&mut server, &s, &c, "platform:z", "kz");
        let seen = server.generation_seen();
        assert!(seen >= 1);
        fs::write(&path, &saved).unwrap();
        assert!(!matches!(
            check(&mut server, &s, &c, "platform:a", "k1"),
            GrantCheck::Valid(_)
        ));
        // Writing after a replay goes above everything seen.
        st.add(&s, &c, req("platform:y", "ky"), DEFAULT_GRANT_TTL)
            .unwrap();
        let written = payload(&path, &s)["generation"].as_u64().unwrap();
        assert_eq!(written, st.generation_seen());
        assert!(written > seen);
        assert!(matches!(
            check(&mut server, &s, &c, "platform:y", "ky"),
            GrantCheck::Valid(_)
        ));
        assert!(!matches!(
            check(&mut server, &s, &c, "platform:a", "k1"),
            GrantCheck::Valid(_)
        ));
    }

    #[test]
    fn grant_bound_to_client() {
        let (_d, path, s, c) = setup();
        let mut st = GrantStore::open(&path, "acc");
        st.add(
            &s,
            &c,
            req("team:ABCDE12345:com.example.agent", "k1"),
            DEFAULT_GRANT_TTL,
        )
        .unwrap();
        assert_eq!(
            check(&mut st, &s, &c, "adhoc:0123abcd", "k1"),
            GrantCheck::None
        );
        assert!(matches!(
            check(&mut st, &s, &c, "team:ABCDE12345:com.example.agent", "k1"),
            GrantCheck::Valid(_)
        ));
    }

    #[test]
    fn ttl_clamped_to_60_minutes() {
        let (_d, path, s, c) = setup();
        let mut st = GrantStore::open(&path, "acc");
        let g = st
            .add(&s, &c, req("platform:a", "k1"), 3 * MAX_GRANT_TTL)
            .unwrap();
        assert_eq!(g.expires_at - g.created_at, 3600);
        c.advance(59 * MIN);
        assert!(matches!(
            check(&mut st, &s, &c, "platform:a", "k1"),
            GrantCheck::Valid(_)
        ));
        c.advance(MIN);
        assert_eq!(
            check(&mut st, &s, &c, "platform:a", "k1"),
            GrantCheck::Expired
        );
    }

    #[test]
    fn prune_expired_on_write() {
        let (_d, path, s, c) = setup();
        let mut st = GrantStore::open(&path, "acc");
        let short = st.add(&s, &c, req("platform:a", "k1"), MIN).unwrap();
        let revoked = st.add(&s, &c, req("platform:a", "k2"), 2 * MIN).unwrap();
        let long = st.add(&s, &c, req("platform:a", "k3"), 30 * MIN).unwrap();
        st.revoke(&s, &c, Revoke::Id(revoked.id.clone())).unwrap();
        let p = payload(&path, &s);
        assert_eq!(p["grants"].as_array().unwrap().len(), 3);
        assert_eq!(p["revoked"].as_array().unwrap().len(), 1);
        assert_eq!(p["revoked"][0]["id"], revoked.id.as_str());

        c.advance(3 * MIN);
        let fresh = st.add(&s, &c, req("platform:a", "k4"), MIN).unwrap();
        let p = payload(&path, &s);
        let ids: Vec<&str> = p["grants"]
            .as_array()
            .unwrap()
            .iter()
            .map(|g| g["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, vec![long.id.as_str(), fresh.id.as_str()]);
        assert!(!ids.contains(&short.id.as_str()));
        assert!(p["revoked"].as_array().unwrap().is_empty());
        assert_eq!(p["account_id"], "acc");
    }

    #[test]
    fn tampered_or_foreign_file_gives_no_grant() {
        let (_d, path, s, c) = setup();
        let mut st = GrantStore::open(&path, "acc");
        st.add(&s, &c, req("platform:a", "k1"), DEFAULT_GRANT_TTL)
            .unwrap();
        let text = fs::read_to_string(&path).unwrap();
        fs::write(&path, text.replace("platform:a", "platform:b")).unwrap();
        let mut other = GrantStore::open(&path, "acc");
        assert_eq!(
            check(&mut other, &s, &c, "platform:b", "k1"),
            GrantCheck::None
        );
        assert_eq!(other.list(&s, &c), Err(GuardError::Signature));
        assert_eq!(
            other.add(&s, &c, req("platform:b", "k1"), DEFAULT_GRANT_TTL),
            Err(GuardError::Signature)
        );

        // A valid file of another account.
        fs::remove_file(&path).unwrap();
        GrantStore::open(&path, "other")
            .add(&s, &c, req("platform:a", "k1"), DEFAULT_GRANT_TTL)
            .unwrap();
        let mut mine = GrantStore::open(&path, "acc");
        assert_eq!(
            check(&mut mine, &s, &c, "platform:a", "k1"),
            GrantCheck::None
        );
        assert!(matches!(mine.list(&s, &c), Err(GuardError::Tampered(_))));
    }

    #[test]
    fn rollback_after_a_later_write_does_not_revive_grant() {
        let (_d, path, s, c) = setup();
        let mut st = GrantStore::open(&path, "acc");
        st.add(&s, &c, req("platform:a", "k1"), DEFAULT_GRANT_TTL)
            .unwrap();
        // The wall clock is rolled back while the monotonic clock passes the
        // deadline; a later write must not forget that the grant is expired.
        c.advance_monotonic(10 * MIN);
        c.set_now_unix(T0 + 60);
        st.add(&s, &c, req("platform:a", "k2"), DEFAULT_GRANT_TTL)
            .unwrap();
        assert_eq!(
            check(&mut st, &s, &c, "platform:a", "k1"),
            GrantCheck::Expired
        );
    }

    #[test]
    fn raise_floor_and_list_raise_generation_seen() {
        let (_d, path, s, c) = setup();
        let mut writer = GrantStore::open(&path, "acc");
        writer
            .add(&s, &c, req("platform:a", "k1"), DEFAULT_GRANT_TTL)
            .unwrap();
        let mut reader = GrantStore::open(&path, "acc");
        assert_eq!(reader.list(&s, &c).unwrap().len(), 1);
        assert_eq!(reader.generation_seen(), 1);
        reader.raise_floor(5);
        assert_eq!(reader.generation_seen(), 5);
        reader.raise_floor(2);
        assert_eq!(reader.generation_seen(), 5);
        assert!(matches!(reader.list(&s, &c), Err(GuardError::Tampered(_))));
        assert_eq!(
            check(&mut reader, &s, &c, "platform:a", "k1"),
            GrantCheck::None
        );
    }

    #[test]
    fn held_lock_bounds_the_wait() {
        let (_d, path, s, c) = setup();
        let mut st = GrantStore::open(&path, "acc");
        st.add(&s, &c, req("platform:a", "k1"), DEFAULT_GRANT_TTL)
            .unwrap();
        let holder = crate::signed::lock_sibling(&path, true).unwrap();
        let t = Instant::now();
        assert_eq!(check(&mut st, &s, &c, "platform:a", "k1"), GrantCheck::None);
        assert_eq!(
            st.add(&s, &c, req("platform:a", "k2"), DEFAULT_GRANT_TTL),
            Err(GuardError::Io(std::io::ErrorKind::TimedOut))
        );
        let waited = t.elapsed();
        assert!(waited >= 2 * crate::signed::LOCK_WAIT, "{waited:?}");
        assert!(waited < 4 * crate::signed::LOCK_WAIT, "{waited:?}");
        drop(holder);
        assert!(matches!(
            check(&mut st, &s, &c, "platform:a", "k1"),
            GrantCheck::Valid(_)
        ));
    }

    #[test]
    fn concurrent_stores_keep_one_consistent_file() {
        let (_d, path, s, c) = setup();
        const N: usize = 15;
        let run = |client: &'static str| {
            let path = path.clone();
            std::thread::spawn(move || {
                let s = TestSigner::new();
                let c = FakeClock::new(T0);
                let mut st = GrantStore::open(&path, "acc");
                let mut ids = Vec::new();
                for i in 0..N {
                    let g = st
                        .add(&s, &c, req(client, &format!("k{i}")), DEFAULT_GRANT_TTL)
                        .unwrap();
                    ids.push(g.id);
                }
                // Revoke every third grant of this client.
                for id in ids.iter().step_by(3) {
                    assert_eq!(st.revoke(&s, &c, Revoke::Id(id.clone())).unwrap().newly, 1);
                }
                ids
            })
        };
        let a = run("platform:a");
        let b = run("platform:b");
        let (ids_a, ids_b) = (a.join().unwrap(), b.join().unwrap());
        let revoked_per_client = N.div_ceil(3);
        let mut st = GrantStore::open(&path, "acc");
        let live = st.list(&s, &c).unwrap();
        assert_eq!(live.len(), 2 * (N - revoked_per_client));
        let p = payload(&path, &s);
        assert_eq!(p["grants"].as_array().unwrap().len(), 2 * N);
        assert_eq!(
            p["revoked"].as_array().unwrap().len(),
            2 * revoked_per_client
        );
        // One write per add and per revoke, none lost.
        assert_eq!(
            p["generation"].as_u64().unwrap() as usize,
            2 * (N + revoked_per_client)
        );
        for (i, id) in ids_a.iter().chain(ids_b.iter()).enumerate() {
            let expected = !(i % N).is_multiple_of(3);
            assert_eq!(live.iter().any(|g| &g.id == id), expected);
        }
    }

    #[test]
    fn pushed_revocation_holds_against_a_laundered_file() {
        let (_d, path, s, c) = setup();
        let mut server = GrantStore::open(&path, "acc");
        let g = server
            .add(&s, &c, req("platform:a", "k1"), DEFAULT_GRANT_TTL)
            .unwrap();
        let before = fs::read(&path).unwrap();
        let mut cli = GrantStore::open(&path, "acc");
        let out = cli.revoke(&s, &c, Revoke::Id(g.id.clone())).unwrap();
        server.apply_revocations(&c, out.generation, &out.revoked, &[]);
        // Restore, then a fresh process writes N + 1 with G live.
        fs::write(&path, &before).unwrap();
        GrantStore::open(&path, "acc")
            .add(&s, &c, req("platform:z", "kz"), DEFAULT_GRANT_TTL)
            .unwrap();
        assert_eq!(
            payload(&path, &s)["generation"].as_u64().unwrap(),
            out.generation
        );
        assert_eq!(
            check(&mut server, &s, &c, "platform:a", "k1"),
            GrantCheck::Revoked
        );
        assert!(server.list(&s, &c).unwrap().iter().all(|x| x.id != g.id));
        // The next write of the server puts the revocation back in the file.
        server
            .add(&s, &c, req("platform:y", "ky"), DEFAULT_GRANT_TTL)
            .unwrap();
        let mut fresh = GrantStore::open(&path, "acc");
        assert_eq!(
            check(&mut fresh, &s, &c, "platform:a", "k1"),
            GrantCheck::Revoked
        );
        // Forgotten once the grant would have expired.
        c.advance(DEFAULT_GRANT_TTL);
        let _ = check(&mut server, &s, &c, "platform:a", "k1");
        assert!(server.pushed_revocations().is_empty());
    }

    /// F0 has no G; the server then issues G (F1). F0 is restored before the
    /// revocation, so the revoking command never sees G; F1 is restored
    /// after: the pushed selector still refuses G.
    fn revoke_unseen_grant(which: impl Fn(&Grant) -> Revoke) {
        let (_d, path, s, c) = setup();
        let mut server = GrantStore::open(&path, "acc");
        server
            .add(&s, &c, req("platform:o", "ko"), DEFAULT_GRANT_TTL)
            .unwrap();
        let f0 = fs::read(&path).unwrap();
        c.advance(Duration::from_secs(10));
        let g = server
            .add(&s, &c, req("platform:a", "k1"), DEFAULT_GRANT_TTL)
            .unwrap();
        let f1 = fs::read(&path).unwrap();
        fs::write(&path, &f0).unwrap();
        c.advance(Duration::from_secs(10));
        let mut cli = GrantStore::open(&path, "acc");
        let out = cli.revoke(&s, &c, which(&g)).unwrap();
        assert!(out.revoked.iter().all(|r| r.id != g.id));
        server.apply_revocations(
            &c,
            out.generation,
            &out.revoked,
            std::slice::from_ref(&out.selector),
        );
        fs::write(&path, &f1).unwrap();
        assert_eq!(
            check(&mut server, &s, &c, "platform:a", "k1"),
            GrantCheck::Revoked
        );
        assert!(server.list(&s, &c).unwrap().iter().all(|x| x.id != g.id));
        // A grant created after the revocation is not covered (except by id).
        c.advance(Duration::from_secs(10));
        server
            .add(&s, &c, req("platform:a", "k2"), DEFAULT_GRANT_TTL)
            .unwrap();
        assert!(matches!(
            check(&mut server, &s, &c, "platform:a", "k2"),
            GrantCheck::Valid(_)
        ));
        // Selectors are forgotten after the longest grant life.
        c.advance(MAX_GRANT_TTL + Duration::from_secs(60));
        let _ = check(&mut server, &s, &c, "platform:a", "k2");
        assert!(server.pushed_selectors().is_empty());
    }

    #[test]
    fn selector_all_refuses_grant_unseen_by_revoke() {
        revoke_unseen_grant(|_| Revoke::All);
    }

    #[test]
    fn selector_client_refuses_grant_unseen_by_revoke() {
        revoke_unseen_grant(|_| Revoke::Client("platform:a".into()));
    }

    #[test]
    fn selector_absent_id_refuses_grant_unseen_by_revoke() {
        revoke_unseen_grant(|g| Revoke::Id(g.id.clone()));
    }

    #[test]
    fn selectors_match_on_signed_fields() {
        let g = Grant {
            id: "00aa".into(),
            client_id: "platform:a".into(),
            surface: Surface::Mcp,
            action: "use".into(),
            key: "k".into(),
            vault_id: None,
            created_at: 100,
            expires_at: 400,
        };
        assert!(RevokeSelector::for_revoke(&Revoke::Id("00aa".into()), 0).matches(&g));
        assert!(!RevokeSelector::for_revoke(&Revoke::Id("00bb".into()), 0).matches(&g));
        assert!(RevokeSelector::for_revoke(&Revoke::Client("platform:a".into()), 100).matches(&g));
        assert!(!RevokeSelector::for_revoke(&Revoke::Client("platform:a".into()), 99).matches(&g));
        assert!(!RevokeSelector::for_revoke(&Revoke::Client("platform:b".into()), 500).matches(&g));
        assert!(RevokeSelector::for_revoke(&Revoke::All, 100).matches(&g));
        assert!(!RevokeSelector::for_revoke(&Revoke::All, 99).matches(&g));
        // Wire form.
        let j = |s: &RevokeSelector| serde_json::to_string(s).unwrap();
        assert_eq!(j(&RevokeSelector::Id { id: "x".into() }), r#"{"id":"x"}"#);
        assert_eq!(
            j(&RevokeSelector::Client {
                client_id: "c".into(),
                created_at_or_before: 5
            }),
            r#"{"client_id":"c","created_at_or_before":5}"#
        );
        assert_eq!(
            j(&RevokeSelector::All {
                all_created_at_or_before: 5
            }),
            r#"{"all_created_at_or_before":5}"#
        );
        for sel in [
            RevokeSelector::Id { id: "x".into() },
            RevokeSelector::Client {
                client_id: "c".into(),
                created_at_or_before: 5,
            },
            RevokeSelector::All {
                all_created_at_or_before: 5,
            },
        ] {
            assert_eq!(
                serde_json::from_str::<RevokeSelector>(&j(&sel)).unwrap(),
                sel
            );
        }
    }
}
