//! Signed registry of paired clients (`clients.json`, domain `clients`).
//!
//! The registry carries a `generation` counter. Each save increments it, and a
//! [`ClientRegistryLoader`] remembers the highest generation it has accepted,
//! so a long-running server refuses an older (authentic) registry replayed
//! while it runs. After a restart that memory is gone: replaying an older
//! registry then is out of scope (same limit as the MCP policy).

use crate::approval::Surface;
use crate::signed::write_private_atomic;
use crate::{GuardError, LocalSigner, open_config, seal_config};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
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

/// Increments the generation of `reg` and writes it signed, atomically, with
/// mode 0600.
pub fn save_clients(
    path: &Path,
    signer: &dyn LocalSigner,
    reg: &mut ClientRegistry,
) -> Result<(), GuardError> {
    reg.generation = reg
        .generation
        .checked_add(1)
        .ok_or(GuardError::Format("client registry generation"))?;
    let payload = serde_json::to_string(reg).map_err(|_| GuardError::Format("client registry"))?;
    let sealed = seal_config(signer, CLIENTS_DOMAIN, &payload)?;
    write_private_atomic(path, sealed.as_bytes())
}

/// Loads the registry and refuses one older than the highest generation this
/// loader has accepted (replay while the process runs).
#[derive(Debug, Default)]
pub struct ClientRegistryLoader {
    /// Highest generation accepted so far.
    pub generation_seen: u64,
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
        Ok(reg)
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
}
