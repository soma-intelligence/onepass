//! Shared fixtures of the agent tests: keys generated once per test binary,
//! an in-memory key source, a readable audit sink and a raw agent client.
#![allow(dead_code)]

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex, OnceLock};

use onepass_guard::{AuditEntry, AuditSink};
use onepass_ssh_agent::keys::{AgentKey, KeyType};
use onepass_ssh_agent::wire::{
    SSH_AGENTC_REQUEST_IDENTITIES, SSH_AGENTC_SIGN_REQUEST, SshReader, SshWriter,
};
use onepass_ssh_agent::{KeyInfo, KeySource, PeerInfo, peer_info};
use zeroize::Zeroizing;

pub const VAULT_ID: &str = "vault-1";
pub const VAULT_NAME: &str = "Perso";

/// The key types of the fixture (RSA 4096 is left out: slow to generate).
pub const TYPES: [KeyType; 5] = [
    KeyType::Ed25519,
    KeyType::EcdsaP256,
    KeyType::EcdsaP384,
    KeyType::EcdsaP521,
    KeyType::Rsa3072,
];

/// One private key per type, as OpenSSH text, generated once.
fn private_texts() -> &'static Vec<(KeyType, Zeroizing<String>)> {
    static K: OnceLock<Vec<(KeyType, Zeroizing<String>)>> = OnceLock::new();
    K.get_or_init(|| {
        TYPES
            .iter()
            .map(|&t| {
                let k = AgentKey::generate(t).unwrap();
                (t, k.to_openssh_private("test").unwrap())
            })
            .collect()
    })
}

pub fn title_of(t: KeyType) -> String {
    format!("key-{t:?}").to_lowercase()
}

pub fn item_id_of(t: KeyType) -> String {
    format!("item-{t:?}").to_lowercase()
}

/// The fixture key of type `t`.
pub fn key(t: KeyType) -> AgentKey {
    let (_, text) = private_texts().iter().find(|(k, _)| *k == t).unwrap();
    AgentKey::from_private_text(text, None).unwrap()
}

/// Listed key and its private OpenSSH text.
pub type Entry = (KeyInfo, Zeroizing<String>);

/// An in-memory key source. Settings can be changed through the shared
/// handle while the agent owns the source.
#[derive(Clone)]
pub struct FakeSource {
    pub keys: Arc<Mutex<Vec<Entry>>>,
}

impl FakeSource {
    /// Every fixture key, `confirm_each_use` off, no bookmark.
    pub fn all() -> Self {
        Self::with(&TYPES)
    }

    pub fn with(types: &[KeyType]) -> Self {
        let keys = types
            .iter()
            .map(|&t| {
                let k = key(t);
                let info = KeyInfo {
                    item_id: item_id_of(t),
                    vault_id: VAULT_ID.into(),
                    vault_name: VAULT_NAME.into(),
                    title: title_of(t),
                    public_blob: k.public_blob(),
                    fingerprint: k.fingerprint(),
                    confirm_each_use: false,
                    hosts: Vec::new(),
                };
                let (_, text) = private_texts().iter().find(|(x, _)| *x == t).unwrap();
                (info, text.clone())
            })
            .collect();
        FakeSource {
            keys: Arc::new(Mutex::new(keys)),
        }
    }

    pub fn edit(&self, t: KeyType, f: impl FnOnce(&mut KeyInfo)) {
        let mut keys = self.keys.lock().unwrap();
        let (info, _) = keys
            .iter_mut()
            .find(|(i, _)| i.item_id == item_id_of(t))
            .unwrap();
        f(info);
    }
}

impl KeySource for FakeSource {
    fn list(&mut self) -> Result<Vec<KeyInfo>, String> {
        Ok(self
            .keys
            .lock()
            .unwrap()
            .iter()
            .map(|(i, _)| i.clone())
            .collect())
    }

    fn load(&mut self, item_id: &str) -> Result<AgentKey, String> {
        let keys = self.keys.lock().unwrap();
        let (_, text) = keys
            .iter()
            .find(|(i, _)| i.item_id == item_id)
            .ok_or("not found")?;
        AgentKey::from_private_text(text, None).map_err(|e| e.to_string())
    }
}

/// An audit sink the test reads while the agent owns it.
#[derive(Clone, Default)]
pub struct SharedAudit(pub Arc<Mutex<Vec<AuditEntry>>>);

impl AuditSink for SharedAudit {
    fn record(&mut self, e: &AuditEntry) -> Result<(), onepass_guard::GuardError> {
        self.0.lock().unwrap().push(e.clone());
        Ok(())
    }
}

impl SharedAudit {
    pub fn entries(&self) -> Vec<AuditEntry> {
        self.0.lock().unwrap().clone()
    }
}

/// Uid of this process, as the kernel reports it for a socket pair.
pub fn own_uid() -> u32 {
    let (a, _b) = UnixStream::pair().unwrap();
    peer_info(&a).uid.expect("peer uid")
}

/// A peer of this user running `exe`.
pub fn peer(exe: &str) -> PeerInfo {
    PeerInfo {
        uid: Some(own_uid()),
        pid: Some(4242),
        exe: Some(exe.into()),
    }
}

/// Writes one framed message.
pub fn send(s: &mut UnixStream, body: &[u8]) {
    let mut w = SshWriter::new();
    w.string(body);
    s.write_all(w.as_slice()).unwrap();
}

/// Reads one framed message body.
pub fn recv(s: &mut UnixStream) -> Vec<u8> {
    let mut len = [0u8; 4];
    s.read_exact(&mut len).unwrap();
    let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
    s.read_exact(&mut body).unwrap();
    body
}

pub fn identities_request() -> Vec<u8> {
    vec![SSH_AGENTC_REQUEST_IDENTITIES]
}

pub fn sign_request(blob: &[u8], data: &[u8], flags: u32) -> Vec<u8> {
    let mut w = SshWriter::new();
    w.u8(SSH_AGENTC_SIGN_REQUEST)
        .string(blob)
        .string(data)
        .u32(flags);
    w.into_vec()
}

/// `(blob, comment)` pairs of an identities answer.
pub fn parse_identities(body: &[u8]) -> Vec<(Vec<u8>, String)> {
    let mut r = SshReader::new(body);
    assert_eq!(r.u8().unwrap(), 12);
    let n = r.u32().unwrap();
    let mut out = Vec::new();
    for _ in 0..n {
        let blob = r.string().unwrap().to_vec();
        let comment = r.utf8().unwrap().to_owned();
        out.push((blob, comment));
    }
    r.finish().unwrap();
    out
}

/// The signature blob of a sign response.
pub fn parse_signature(body: &[u8]) -> Vec<u8> {
    let mut r = SshReader::new(body);
    assert_eq!(r.u8().unwrap(), 14, "expected a sign response");
    let sig = r.string().unwrap().to_vec();
    r.finish().unwrap();
    sig
}
