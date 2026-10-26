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
use crate::signed::write_private_atomic;
use crate::{GuardError, LocalSigner, open_config, seal_config};
use data_encoding::HEXLOWER;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::ErrorKind;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
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

/// A revoked grant id, kept until the grant would have expired.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Tombstone {
    id: String,
    expires_at: i64,
}

/// The signed payload of `grants.json`.
#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct GrantsFile {
    account_id: String,
    generation: u64,
    grants: Vec<Grant>,
    revoked: Vec<Tombstone>,
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
        }
    }

    /// Highest generation read or written so far.
    pub fn generation_seen(&self) -> u64 {
        self.generation_seen
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
        self.issued.retain(|_, deadline| *deadline > mono);
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

    /// Revokes the matching live grants and returns how many were revoked.
    /// The file is rewritten (higher generation) only if at least one was.
    pub fn revoke(
        &mut self,
        signer: &dyn LocalSigner,
        clock: &dyn Clock,
        which: Revoke,
    ) -> Result<usize, GuardError> {
        let _lock = self.lock(true)?;
        let (mut file, healed) = self.load_for_write(signer)?;
        let now = clock.now_unix();
        let already: HashSet<String> = file.revoked.iter().map(|t| t.id.clone()).collect();
        let newly: Vec<Tombstone> = file
            .grants
            .iter()
            .filter(|g| match &which {
                Revoke::Id(id) => &g.id == id,
                Revoke::Client(c) => &g.client_id == c,
                Revoke::All => true,
            })
            .filter(|g| g.expires_at > now && !already.contains(&g.id))
            .map(|g| Tombstone {
                id: g.id.clone(),
                expires_at: g.expires_at,
            })
            .collect();
        let count = newly.len();
        if count > 0 || healed {
            file.revoked.extend(newly);
            file.prune(now);
            self.write(signer, file)?;
        }
        Ok(count)
    }

    /// The live (unexpired, unrevoked) grants.
    pub fn list(
        &self,
        signer: &dyn LocalSigner,
        clock: &dyn Clock,
    ) -> Result<Vec<Grant>, GuardError> {
        let file = {
            let _lock = self.lock(false)?;
            self.read_checked(signer)?
        };
        let revoked = file.revoked_ids();
        Ok(file
            .grants
            .iter()
            .filter(|g| self.state(g, &revoked, clock) == State::Live)
            .cloned()
            .collect())
    }

    fn state(&self, g: &Grant, revoked: &HashSet<&str>, clock: &dyn Clock) -> State {
        if revoked.contains(g.id.as_str()) {
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

    fn lock_path(&self) -> PathBuf {
        let mut p = self.path.as_os_str().to_owned();
        p.push(".lock");
        PathBuf::from(p)
    }

    /// Opens (creating it 0600) the sibling lock file and locks it. The lock
    /// is released when the returned file is dropped.
    fn lock(&self, exclusive: bool) -> Result<File, GuardError> {
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(self.lock_path())?;
        f.set_permissions(fs::Permissions::from_mode(0o600))?;
        if exclusive {
            f.lock()?;
        } else {
            f.lock_shared()?;
        }
        Ok(f)
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
        assert_eq!(cli.revoke(&s, &c, Revoke::Id(g.id.clone())).unwrap(), 1);
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
        assert_eq!(cli.revoke(&s, &c, Revoke::Id(g.id.clone())).unwrap(), 0);
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
                .unwrap(),
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
        assert_eq!(st.revoke(&s, &c, Revoke::All).unwrap(), 2);
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
        assert_eq!(st.revoke(&s, &c, Revoke::Id(g.id)).unwrap(), 1);
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
}
