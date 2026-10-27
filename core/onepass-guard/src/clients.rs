//! Signed registry of paired clients (`clients.json`, domain `clients`).
//!
//! The registry carries a `generation` counter. Each save increments it, and a
//! [`ClientRegistryLoader`] remembers the highest generation it has accepted,
//! so a long-running server refuses an older (authentic) registry replayed
//! while it runs. After a restart that memory is gone: replaying an older
//! registry then is out of scope (same limit as the MCP policy).

use crate::approval::Surface;
use crate::signed::{lock_sibling, write_private_atomic};
use crate::{GuardError, LocalSigner, open_config, seal_config};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::io::ErrorKind;
use std::path::Path;

/// Signature domain of the client registry.
pub const CLIENTS_DOMAIN: &[u8] = b"clients";

/// One paired client. Never contains secrets.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ClientRecord {
    /// Code identity string (`platform:...`, `team:...:...`, `adhoc:...`,
    /// `unsigned:...`).
    pub id: String,
    /// The surface the client is paired for.
    pub surface: Surface,
    /// Human label chosen at pairing.
    pub label: String,
    /// The verified code identity, as JSON (opaque to this crate).
    pub code: serde_json::Value,
    /// Pairing time, seconds since the Unix epoch.
    pub paired_at: i64,
    /// MCP only: vault id to allowed scopes.
    #[serde(default)]
    pub mcp_scopes: Option<BTreeMap<String, BTreeSet<String>>>,
    /// SSH only: allowed key fingerprints, `None` = all keys.
    #[serde(default)]
    pub ssh_keys: Option<BTreeSet<String>>,
}

/// An unpairing pushed to running servers: records of `client_id` paired at
/// or before `at` are ignored by a server that was told.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct Unpaired {
    /// Code identity of the unpaired client.
    pub client_id: String,
    /// Unpairing time, seconds since the Unix epoch.
    pub at: i64,
}

/// The registry of paired clients of one account.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ClientRegistry {
    /// The account the registry belongs to.
    pub account_id: String,
    /// Incremented by every save.
    pub generation: u64,
    /// Paired clients.
    pub clients: Vec<ClientRecord>,
}

impl ClientRegistry {
    /// An empty registry at generation 0.
    pub fn empty(account_id: &str) -> Self {
        ClientRegistry {
            account_id: account_id.to_owned(),
            generation: 0,
            clients: Vec::new(),
        }
    }

    /// Removes every record of `id` (all surfaces) and returns what to push
    /// to running servers, even when the registry read had no record of `id`
    /// (it may have been restored to hide one). `at` is the later of `now`
    /// and the newest `paired_at` removed, so every removed record is
    /// covered.
    pub fn unpair(&mut self, id: &str, now: i64) -> Unpaired {
        let newest = self
            .clients
            .iter()
            .filter(|c| c.id == id)
            .map(|c| c.paired_at)
            .max();
        self.clients.retain(|c| c.id != id);
        Unpaired {
            client_id: id.to_owned(),
            at: newest.map_or(now, |p| p.max(now)),
        }
    }

    /// The client paired for `surface` with code identity `id`.
    pub fn find(&self, surface: Surface, id: &str) -> Option<&ClientRecord> {
        self.clients
            .iter()
            .find(|c| c.surface == surface && c.id == id)
    }
}

/// Reads and verifies the registry at `path`. A missing file gives an empty
/// registry at generation 0. A registry of another account is refused.
pub fn load_clients(
    path: &Path,
    signer: &dyn LocalSigner,
    account_id: &str,
) -> Result<ClientRegistry, GuardError> {
    let text = match fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(ClientRegistry::empty(account_id)),
        Err(e) => return Err(e.into()),
    };
    let payload = open_config(signer, CLIENTS_DOMAIN, &text)?;
    let reg: ClientRegistry =
        serde_json::from_str(&payload).map_err(|_| GuardError::Format("client registry"))?;
    if reg.account_id != account_id {
        return Err(GuardError::Tampered("client registry of another account"));
    }
    Ok(reg)
}

/// Writes `reg` signed, atomically, with mode 0600, under an exclusive lock
/// on `<path>.lock`. Inside the lock the file on disk is read again and the
/// new generation is one above the highest of the disk, `reg` and `floor`,
/// so two writers never produce two registries with the same generation. An
/// untrusted file on disk is overwritten (it counts as generation 0).
pub fn save_clients(
    path: &Path,
    signer: &dyn LocalSigner,
    reg: &mut ClientRegistry,
) -> Result<(), GuardError> {
    save_above(path, signer, reg, 0)
}

fn save_above(
    path: &Path,
    signer: &dyn LocalSigner,
    reg: &mut ClientRegistry,
    floor: u64,
) -> Result<(), GuardError> {
    let _lock = lock_sibling(path, true)?;
    // A file that cannot be trusted (bad signature, format, other account)
    // carries no generation worth keeping: it is replaced, from the floors
    // known here. A running server whose floor is higher refuses the result
    // until notified, which fails closed.
    let disk = match load_clients(path, signer, &reg.account_id) {
        Ok(r) => r.generation,
        Err(GuardError::Io(kind)) => return Err(GuardError::Io(kind)),
        Err(_) => 0,
    };
    let generation = disk
        .max(reg.generation)
        .max(floor)
        .checked_add(1)
        .ok_or(GuardError::Format("client registry generation"))?;
    let mut next = reg.clone();
    next.generation = generation;
    let payload =
        serde_json::to_string(&next).map_err(|_| GuardError::Format("client registry"))?;
    let sealed = seal_config(signer, CLIENTS_DOMAIN, &payload)?;
    write_private_atomic(path, sealed.as_bytes())?;
    reg.generation = generation;
    Ok(())
}

/// Loads the registry and refuses one older than the highest generation this
/// loader has accepted (replay while the process runs).
#[derive(Debug, Default)]
pub struct ClientRegistryLoader {
    /// Highest generation accepted so far.
    pub generation_seen: u64,
    /// Unpairings pushed by control notifications: client id to the latest
    /// unpairing time.
    unpaired: HashMap<String, i64>,
}

impl ClientRegistryLoader {
    /// A loader that has seen nothing yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Like [`load_clients`], plus the replay check.
    pub fn load(
        &mut self,
        path: &Path,
        signer: &dyn LocalSigner,
        account_id: &str,
    ) -> Result<ClientRegistry, GuardError> {
        let reg = load_clients(path, signer, account_id)?;
        if reg.generation < self.generation_seen {
            return Err(GuardError::Tampered(
                "client registry older than one already seen",
            ));
        }
        self.generation_seen = reg.generation;
        let mut reg = reg;
        reg.clients.retain(|c| match self.unpaired.get(&c.id) {
            Some(at) => c.paired_at > *at,
            None => true,
        });
        Ok(reg)
    }

    /// Like [`save_clients`], also above the highest generation this loader
    /// has seen; the floor then follows the written generation.
    pub fn save(
        &mut self,
        path: &Path,
        signer: &dyn LocalSigner,
        reg: &mut ClientRegistry,
    ) -> Result<(), GuardError> {
        save_above(path, signer, reg, self.generation_seen)?;
        self.generation_seen = self.generation_seen.max(reg.generation);
        Ok(())
    }

    /// Raises the replay floor to `generation` (never lowers it). Called when
    /// a signed control notification announces a newer registry.
    pub fn raise_floor(&mut self, generation: u64) {
        self.generation_seen = self.generation_seen.max(generation);
    }

    /// Applies a verified control notification: raises the floor and
    /// remembers each unpairing, so a restored or laundered registry cannot
    /// bring the client back; only a record paired later than the unpairing
    /// (a genuine re-pairing) is accepted again.
    pub fn apply_unpairs(&mut self, generation: u64, unpaired: &[Unpaired]) {
        self.raise_floor(generation);
        for u in unpaired {
            let e = self.unpaired.entry(u.client_id.clone()).or_insert(u.at);
            *e = (*e).max(u.at);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TestSigner;
    use std::os::unix::fs::PermissionsExt;

    fn record(id: &str, surface: Surface) -> ClientRecord {
        ClientRecord {
            id: id.to_owned(),
            surface,
            label: "test client".to_owned(),
            code: serde_json::json!({"kind": "platform", "identifier": "com.example.tool"}),
            paired_at: 1_800_000_000,
            mcp_scopes: Some(BTreeMap::from([(
                "vault-1".to_owned(),
                BTreeSet::from(["metadata".to_owned(), "use".to_owned()]),
            )])),
            ssh_keys: None,
        }
    }

    #[test]
    fn missing_registry_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let reg =
            load_clients(&dir.path().join("clients.json"), &TestSigner::new(), "acc").unwrap();
        assert_eq!(reg, ClientRegistry::empty("acc"));
    }

    #[test]
    fn registry_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("clients.json");
        let s = TestSigner::new();
        let mut reg = ClientRegistry::empty("acc");
        reg.clients
            .push(record("platform:com.example.tool", Surface::Mcp));
        save_clients(&path, &s, &mut reg).unwrap();
        let back = load_clients(&path, &s, "acc").unwrap();
        assert_eq!(back, reg);
        assert!(
            back.find(Surface::Mcp, "platform:com.example.tool")
                .is_some()
        );
        assert!(
            back.find(Surface::Ssh, "platform:com.example.tool")
                .is_none()
        );
        assert!(
            back.find(Surface::Mcp, "platform:com.example.other")
                .is_none()
        );
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn registry_tamper_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("clients.json");
        let s = TestSigner::new();
        let mut reg = ClientRegistry::empty("acc");
        reg.clients
            .push(record("platform:com.example.tool", Surface::Mcp));
        save_clients(&path, &s, &mut reg).unwrap();
        let text = fs::read_to_string(&path).unwrap();
        let edited = text.replace("com.example.tool", "com.example.evil");
        assert_ne!(edited, text);
        fs::write(&path, edited).unwrap();
        assert_eq!(load_clients(&path, &s, "acc"), Err(GuardError::Signature));
        // A registry signed by another key is refused too.
        save_clients(&path, &s, &mut reg).unwrap();
        assert_eq!(
            load_clients(&path, &TestSigner([9u8; 32]), "acc"),
            Err(GuardError::Signature)
        );
    }

    #[test]
    fn registry_of_other_account_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("clients.json");
        let s = TestSigner::new();
        save_clients(&path, &s, &mut ClientRegistry::empty("other")).unwrap();
        assert!(matches!(
            load_clients(&path, &s, "acc"),
            Err(GuardError::Tampered(_))
        ));
    }

    #[test]
    fn registry_generation_increments() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("clients.json");
        let s = TestSigner::new();
        let mut reg = ClientRegistry::empty("acc");
        save_clients(&path, &s, &mut reg).unwrap();
        assert_eq!(reg.generation, 1);
        let mut back = load_clients(&path, &s, "acc").unwrap();
        assert_eq!(back.generation, 1);
        save_clients(&path, &s, &mut back).unwrap();
        assert_eq!(load_clients(&path, &s, "acc").unwrap().generation, 2);
    }

    #[test]
    fn older_registry_replay_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("clients.json");
        let s = TestSigner::new();
        let mut reg = ClientRegistry::empty("acc");
        reg.clients
            .push(record("platform:com.example.tool", Surface::Mcp));
        save_clients(&path, &s, &mut reg).unwrap();
        let old = fs::read(&path).unwrap();

        // Unpair: generation 2, no clients.
        reg.clients.clear();
        save_clients(&path, &s, &mut reg).unwrap();

        let mut loader = ClientRegistryLoader::new();
        assert!(loader.load(&path, &s, "acc").unwrap().clients.is_empty());
        assert_eq!(loader.generation_seen, 2);

        // The older, authentic registry is put back: refused.
        fs::write(&path, &old).unwrap();
        assert!(matches!(
            loader.load(&path, &s, "acc"),
            Err(GuardError::Tampered(_))
        ));
        // Deleting the file is a replay of generation 0: refused as well.
        fs::remove_file(&path).unwrap();
        assert!(matches!(
            loader.load(&path, &s, "acc"),
            Err(GuardError::Tampered(_))
        ));
        // A fresh loader (process restart) accepts the old one (documented).
        fs::write(&path, &old).unwrap();
        assert_eq!(
            ClientRegistryLoader::new()
                .load(&path, &s, "acc")
                .unwrap()
                .generation,
            1
        );
    }

    #[test]
    fn two_loaders_saving_in_turn_never_fork() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("clients.json");
        let s = TestSigner::new();
        let mut l1 = ClientRegistryLoader::new();
        let mut l2 = ClientRegistryLoader::new();
        let mut r1 = l1.load(&path, &s, "acc").unwrap();
        let mut r2 = l2.load(&path, &s, "acc").unwrap();
        r1.clients.push(record("platform:one", Surface::Mcp));
        r2.clients.push(record("platform:two", Surface::Ssh));
        l1.save(&path, &s, &mut r1).unwrap();
        assert_eq!(r1.generation, 1);
        // r2 still says generation 0: the save goes above the disk.
        l2.save(&path, &s, &mut r2).unwrap();
        assert_eq!(r2.generation, 2);
        assert_eq!(l2.generation_seen, 2);
        let back = l1.load(&path, &s, "acc").unwrap();
        assert_eq!(back.generation, 2);
        assert!(back.find(Surface::Ssh, "platform:two").is_some());
        // The free function also goes above the disk.
        let mut stale = ClientRegistry::empty("acc");
        save_clients(&path, &s, &mut stale).unwrap();
        assert_eq!(stale.generation, 3);
        // A loader with a raised floor writes above it.
        let mut l3 = ClientRegistryLoader::new();
        l3.raise_floor(10);
        l3.raise_floor(4);
        assert_eq!(l3.generation_seen, 10);
        assert!(matches!(
            l3.load(&path, &s, "acc"),
            Err(GuardError::Tampered(_))
        ));
        l3.save(&path, &s, &mut stale).unwrap();
        assert_eq!(stale.generation, 11);
        assert_eq!(l3.load(&path, &s, "acc").unwrap().generation, 11);
    }

    #[test]
    fn pushed_unpair_holds_against_laundering_and_allows_repair() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("clients.json");
        let s = TestSigner::new();
        let mut reg = ClientRegistry::empty("acc");
        let mut rec = record("platform:a", Surface::Mcp);
        rec.paired_at = 1_000;
        reg.clients.push(rec.clone());
        save_clients(&path, &s, &mut reg).unwrap();
        let paired = fs::read(&path).unwrap();
        let mut server = ClientRegistryLoader::new();
        assert!(
            server
                .load(&path, &s, "acc")
                .unwrap()
                .find(Surface::Mcp, "platform:a")
                .is_some()
        );

        let u = reg.unpair("platform:a", 2_000);
        assert_eq!(u.at, 2_000);
        // Absent: still pushed. A record paired later than `now` sets `at`.
        assert_eq!(reg.unpair("platform:a", 2_000).at, 2_000);
        let mut future = ClientRegistry::empty("acc");
        let mut r = record("platform:f", Surface::Ssh);
        r.paired_at = 5_000;
        future.clients.push(r);
        assert_eq!(future.unpair("platform:f", 2_000).at, 5_000);
        assert!(future.clients.is_empty());
        save_clients(&path, &s, &mut reg).unwrap();
        server.apply_unpairs(reg.generation, std::slice::from_ref(&u));

        // Restored, then laundered by a fresh save at the same generation.
        fs::write(&path, &paired).unwrap();
        let mut laundered = load_clients(&path, &s, "acc").unwrap();
        save_clients(&path, &s, &mut laundered).unwrap();
        assert_eq!(laundered.generation, reg.generation);
        assert!(
            server
                .load(&path, &s, "acc")
                .unwrap()
                .find(Surface::Mcp, "platform:a")
                .is_none()
        );

        // A genuine re-pairing, later than the unpairing, is accepted.
        let mut again = load_clients(&path, &s, "acc").unwrap();
        again.clients.clear();
        rec.paired_at = 2_001;
        again.clients.push(rec);
        save_clients(&path, &s, &mut again).unwrap();
        assert!(
            server
                .load(&path, &s, "acc")
                .unwrap()
                .find(Surface::Mcp, "platform:a")
                .is_some()
        );
    }

    #[test]
    fn unpair_pushed_even_when_the_registry_read_hid_the_client() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("clients.json");
        let s = TestSigner::new();
        // F0: without C. F1: with C.
        let mut reg = ClientRegistry::empty("acc");
        reg.clients.push(record("platform:other", Surface::Mcp));
        save_clients(&path, &s, &mut reg).unwrap();
        let f0 = fs::read(&path).unwrap();
        let mut rec = record("platform:c", Surface::Mcp);
        rec.paired_at = 1_000;
        reg.clients.push(rec);
        save_clients(&path, &s, &mut reg).unwrap();
        let f1 = fs::read(&path).unwrap();
        let mut server = ClientRegistryLoader::new();
        assert!(
            server
                .load(&path, &s, "acc")
                .unwrap()
                .find(Surface::Mcp, "platform:c")
                .is_some()
        );

        // F0 restored before the unpairing: the command does not see C.
        fs::write(&path, &f0).unwrap();
        let mut seen = load_clients(&path, &s, "acc").unwrap();
        assert!(seen.find(Surface::Mcp, "platform:c").is_none());
        let u = seen.unpair("platform:c", 2_000);
        save_clients(&path, &s, &mut seen).unwrap();
        server.apply_unpairs(seen.generation, std::slice::from_ref(&u));

        // F1 restored after (same generation as the command's write).
        fs::write(&path, &f1).unwrap();
        let back = server.load(&path, &s, "acc").unwrap();
        assert!(back.find(Surface::Mcp, "platform:c").is_none());
        assert!(back.find(Surface::Mcp, "platform:other").is_some());
    }
}
