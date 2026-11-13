//! Shared fixtures of the agent tests: keys generated once per test binary,
//! an in-memory key source, a readable audit sink and a raw agent client.
#![allow(dead_code)]

use std::collections::BTreeSet;
#[cfg(unix)]
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use onepass_guard::testing::FakeClock;
use onepass_guard::{
    AuditEntry, AuditSink, ClientRegistry, GrantStore, GuardError, Limits, LocalSigner, StrongAuth,
    StrongOutcome, Throttle,
};
use onepass_peer::{ClientIdentity, CodeIdentity};
use onepass_ssh_agent::keys::{AgentKey, KeyType};
use onepass_ssh_agent::wire::{
    SSH_AGENTC_REQUEST_IDENTITIES, SSH_AGENTC_SIGN_REQUEST, SshReader, SshWriter,
};
#[cfg(unix)]
use onepass_ssh_agent::peer_info;
use onepass_ssh_agent::{AgentGuards, KeyInfo, KeySource, PeerInfo, ssh_client_record};
use tempfile::TempDir;
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
                    git_signing: false,
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
#[cfg(not(unix))]
pub fn own_uid() -> u32 {
    // No uid on Windows: the agent compares with `effective_uid`, 0 there.
    onepass_peer::effective_uid()
}

/// Uid of this process, as the kernel reports it for a socket pair.
#[cfg(unix)]
pub fn own_uid() -> u32 {
    let (a, _b) = UnixStream::pair().unwrap();
    peer_info(&a).uid.expect("peer uid")
}

/// The platform identity of `exe`: `com.apple.<file name>`.
pub fn platform_identity(exe: &str) -> ClientIdentity {
    let name = exe.rsplit('/').next().unwrap_or(exe);
    ClientIdentity {
        code: CodeIdentity::Platform {
            identifier: format!("com.apple.{name}"),
        },
        pid: 4242,
        exe: Some(PathBuf::from(exe)),
        chain: Vec::new(),
    }
}

/// A peer of this user running `exe`, identified as a platform binary.
pub fn peer(exe: &str) -> PeerInfo {
    peer_with(exe, Some(platform_identity(exe)))
}

/// A peer of this user running `exe` with the given code identity.
pub fn peer_with(exe: &str, identity: Option<ClientIdentity>) -> PeerInfo {
    PeerInfo {
        uid: Some(own_uid()),
        pid: Some(4242),
        exe: Some(exe.into()),
        code: identity.as_ref().map(|i| i.code.client_id()),
        identity,
    }
}

/// The executables the default fixtures pair (platform identities).
pub const PAIRED_EXES: [&str; 4] = [
    "/usr/bin/ssh",
    "/usr/bin/ssh-add",
    "/usr/bin/ssh-keygen",
    "/usr/bin/git",
];

/// HMAC-SHA256 signer binding the domain, for the grants file.
pub struct TestSigner(pub [u8; 32]);

impl TestSigner {
    fn input(domain: &[u8], msg: &[u8]) -> Vec<u8> {
        let mut v = domain.to_vec();
        v.push(0);
        v.extend_from_slice(msg);
        v
    }
}

impl LocalSigner for TestSigner {
    fn sign(&self, domain: &[u8], msg: &[u8]) -> Result<Vec<u8>, GuardError> {
        let key = aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA256, &self.0);
        Ok(aws_lc_rs::hmac::sign(&key, &Self::input(domain, msg))
            .as_ref()
            .to_vec())
    }
    fn verify(&self, domain: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), GuardError> {
        let key = aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA256, &self.0);
        aws_lc_rs::hmac::verify(&key, &Self::input(domain, msg), sig)
            .map_err(|_| GuardError::Signature)
    }
}

pub fn signer() -> TestSigner {
    TestSigner([11; 32])
}

pub const ACCOUNT_ID: &str = "test-account";

/// Strong authentication whose answer the test sets; counts the calls and
/// keeps the reasons shown.
pub struct SwitchStrong {
    pub outcome: Mutex<StrongOutcome>,
    pub calls: AtomicUsize,
    pub reasons: Mutex<Vec<String>>,
}

impl SwitchStrong {
    pub fn set(&self, o: StrongOutcome) {
        *self.outcome.lock().unwrap() = o;
    }
    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl StrongAuth for SwitchStrong {
    fn verify(&self, reason: &str) -> StrongOutcome {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.reasons.lock().unwrap().push(reason.to_owned());
        *self.outcome.lock().unwrap()
    }
}

/// Limits that never get in the way.
pub fn loose_limits() -> Limits {
    Limits {
        prompts_per_min: 100_000,
        secret_per_min: 100_000,
        denials_before_cooldown: 100_000,
        cooldown: std::time::Duration::from_secs(600),
    }
}

/// The test's handles on the agent's guards: the paired clients, the
/// clock, strong authentication and the grants directory.
pub struct GuardEnv {
    pub registry: Arc<Mutex<ClientRegistry>>,
    pub registry_broken: Arc<AtomicBool>,
    pub clock: Arc<FakeClock>,
    pub strong: Arc<SwitchStrong>,
    pub dir: TempDir,
}

impl GuardEnv {
    /// Pairs `identity` for SSH with `keys` (`None` = every key).
    pub fn pair(&self, identity: &CodeIdentity, keys: Option<&[&str]>) {
        let keys: Option<BTreeSet<String>> =
            keys.map(|k| k.iter().map(|s| s.to_string()).collect());
        let label = format!("Test {}", identity.client_id());
        let mut reg = self.registry.lock().unwrap();
        let id = identity.client_id();
        reg.clients.retain(|c| c.id != id);
        reg.clients
            .push(ssh_client_record(identity, &label, keys, 1_000));
        reg.generation += 1;
    }

    pub fn pair_exe(&self, exe: &str) {
        self.pair(&platform_identity(exe).code, None);
    }

    pub fn unpair(&self, identity: &CodeIdentity) {
        let id = identity.client_id();
        self.registry.lock().unwrap().clients.retain(|c| c.id != id);
    }

    pub fn grants_path(&self) -> PathBuf {
        self.dir.path().join("grants.json")
    }

    pub fn advance(&self, secs: u64) {
        self.clock.advance(std::time::Duration::from_secs(secs));
    }
}

/// Guards over an in-memory registry where [`PAIRED_EXES`] are paired with
/// every key, a grants file in a temporary directory, a fake clock and
/// strong authentication that succeeds.
pub fn guards(limits: Limits) -> (AgentGuards, GuardEnv) {
    let env = GuardEnv {
        registry: Arc::new(Mutex::new(ClientRegistry::empty(ACCOUNT_ID))),
        registry_broken: Arc::new(AtomicBool::new(false)),
        clock: Arc::new(FakeClock::new(1_000_000)),
        strong: Arc::new(SwitchStrong {
            outcome: Mutex::new(StrongOutcome::Verified),
            calls: AtomicUsize::new(0),
            reasons: Mutex::new(Vec::new()),
        }),
        dir: TempDir::new().unwrap(),
    };
    for exe in PAIRED_EXES {
        env.pair_exe(exe);
    }
    let (reg, broken) = (env.registry.clone(), env.registry_broken.clone());
    let registry = Box::new(move || {
        if broken.load(Ordering::SeqCst) {
            return Err(GuardError::Signature);
        }
        Ok(reg.lock().unwrap().clone())
    });
    let grants = Arc::new(Mutex::new(GrantStore::open(env.grants_path(), ACCOUNT_ID)));
    let mut g = AgentGuards::new(
        registry,
        grants,
        Box::new(signer()),
        env.strong.clone(),
        env.clock.clone(),
    );
    g.throttle = Throttle::new(limits);
    (g, env)
}

/// Writes one framed message.
#[cfg(unix)]
pub fn send(s: &mut UnixStream, body: &[u8]) {
    let mut w = SshWriter::new();
    w.string(body);
    s.write_all(w.as_slice()).unwrap();
}

/// Reads one framed message body.
#[cfg(unix)]
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

/// The session id the tests' `session-bind@openssh.com` requests bind.
pub const BOUND_SESSION: [u8; 32] = [9u8; 32];

/// What an SSH client signs to authenticate with `key_blob` (RFC 4252
/// section 7): `session_id`, then the userauth request. With `hostbound`,
/// the OpenSSH `publickey-hostbound-v00@openssh.com` method naming that
/// host key.
pub fn userauth_data(session_id: &[u8], key_blob: &[u8], hostbound: Option<&[u8]>) -> Vec<u8> {
    let mut w = onepass_ssh_agent::wire::SshWriter::new();
    let method: &[u8] = if hostbound.is_some() {
        b"publickey-hostbound-v00@openssh.com"
    } else {
        b"publickey"
    };
    let alg = {
        let mut r = onepass_ssh_agent::wire::SshReader::new(key_blob);
        r.string().unwrap().to_vec()
    };
    w.string(session_id)
        .u8(50)
        .string(b"git")
        .string(b"ssh-connection")
        .string(method)
        .u8(1)
        .string(&alg)
        .string(key_blob);
    if let Some(h) = hostbound {
        w.string(h);
    }
    w.into_vec()
}
