//! The SSH agent served by the app (spec section 3), and SSH Key items:
//! generation, import and the keys the agent offers.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::{self, JoinHandle};

use onepass_core::model::{FieldValue, Item, ItemType, SshKeyValue, new_item};
use onepass_guard::{AuditLog, SignedAuditSink};
use onepass_ssh_agent::keys::{AgentKey, KeyError, KeyType, is_encrypted};
use onepass_ssh_agent::{
    Agent, AgentConfig, KeyInfo, KeySource, bind_socket, load_key_of, serve_with_stack, ssh_keys_of,
};
use time::OffsetDateTime;
use zeroize::Zeroizing;

use super::{
    AUDIT_FILE, FfiDeveloperUi, SERVER_STACK, SessionSigner, UiApprover, data_dir, socket_path,
};
use crate::convert::parse_id;
use crate::error::{OnePassError, invalid};
use crate::session::{Session, find_vault};

/// How the app runs its agent.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiSshAgentConfig {
    /// The data folder (audit log).
    pub data_dir: String,
    /// The socket to listen on (its folder is set to `0700`).
    pub socket_path: String,
    /// Serve forwarded connections too, approved at every signature.
    pub allow_forwarded: bool,
    /// `known_hosts` files, read only, to name bound destinations.
    pub known_hosts: Vec<String>,
    /// Every approved signature also needs the device owner (Touch ID).
    pub require_presence: bool,
}

/// [`KeySource`] over the app's session: every call reads the vaults again,
/// so a key edited, removed or moved out of the agent applies at once. A
/// locked session, or a stopped agent (connections opened before the stop
/// stay open until their client leaves), offers nothing.
struct SessionKeys(Arc<Session>, Arc<AtomicBool>);

impl KeySource for SessionKeys {
    fn list(&mut self) -> Result<Vec<KeyInfo>, String> {
        if self.1.load(Ordering::SeqCst) {
            return Err("agent stopped".into());
        }
        self.0
            .with(|repo| Ok(ssh_keys_of(repo)?))
            .map_err(|e| e.to_string())
    }

    fn load(&mut self, item_id: &str) -> Result<AgentKey, String> {
        if self.1.load(Ordering::SeqCst) {
            return Err("agent stopped".into());
        }
        let mut out = None;
        self.0
            .with(|repo| {
                out = Some(load_key_of(repo, item_id));
                Ok(())
            })
            .map_err(|e| e.to_string())?;
        out.unwrap_or_else(|| Err("item not found".into()))
    }
}

/// A running agent. `stop` (or dropping it) closes the socket.
#[derive(uniffi::Object)]
pub struct SshAgentHost {
    socket: PathBuf,
    socket_id: Option<(u64, u64)>,
    stop: Arc<AtomicBool>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

#[uniffi::export]
impl SshAgentHost {
    /// Listens on `config.socket_path` and serves the session's agent keys.
    /// Fails if another agent answers on the socket.
    #[uniffi::constructor]
    pub fn start(
        session: Arc<Session>,
        config: FfiSshAgentConfig,
        ui: Arc<dyn FfiDeveloperUi>,
    ) -> Result<Arc<SshAgentHost>, OnePassError> {
        let dir = data_dir(&config.data_dir)?;
        let socket = socket_path(&config.socket_path)?;
        let log = AuditLog::open(&dir.join(AUDIT_FILE)).map_err(|_| invalid("audit log"))?;
        let sink = SignedAuditSink {
            log,
            signer: SessionSigner(session.clone()),
        };
        let stop = Arc::new(AtomicBool::new(false));
        let agent = Agent::new(
            SessionKeys(session, stop.clone()),
            Arc::new(UiApprover {
                ui,
                presence: config.require_presence,
            }),
            Box::new(sink),
            AgentConfig {
                allow_forwarded: config.allow_forwarded,
                known_hosts: config.known_hosts.iter().map(PathBuf::from).collect(),
                ..AgentConfig::default()
            },
        );
        let listener = bind_socket(&socket).map_err(|e| match e.kind() {
            std::io::ErrorKind::AddrInUse => invalid("another agent is serving this socket"),
            _ => invalid("cannot listen on the agent socket"),
        })?;
        let socket_id = super::socket_identity(&socket);
        let thread = {
            let stop = stop.clone();
            thread::Builder::new()
                .name("onepass-ssh-agent".into())
                .stack_size(SERVER_STACK)
                .spawn(move || {
                    let _ =
                        serve_with_stack(listener, Arc::new(Mutex::new(agent)), stop, SERVER_STACK);
                })
                .map_err(|_| invalid("cannot start the agent"))?
        };
        Ok(Arc::new(SshAgentHost {
            socket,
            socket_id,
            stop,
            thread: Mutex::new(Some(thread)),
        }))
    }

    pub fn socket_path(&self) -> String {
        self.socket.display().to_string()
    }

    pub fn is_running(&self) -> bool {
        self.thread
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .is_some_and(|t| !t.is_finished())
    }

    /// Stops accepting, waits for the accept loop (at most one poll) and
    /// removes the socket. Connections still open get no key and no
    /// signature from then on, and end with their client.
    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
        let handle = self
            .thread
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(h) = handle {
            let _ = h.join();
            super::remove_socket(&self.socket, self.socket_id);
        }
    }
}

impl Drop for SshAgentHost {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Key algorithms the app generates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiSshKeyType {
    Ed25519,
    EcdsaP256,
    EcdsaP384,
    EcdsaP521,
    Rsa3072,
    Rsa4096,
}

impl From<FfiSshKeyType> for KeyType {
    fn from(t: FfiSshKeyType) -> KeyType {
        match t {
            FfiSshKeyType::Ed25519 => KeyType::Ed25519,
            FfiSshKeyType::EcdsaP256 => KeyType::EcdsaP256,
            FfiSshKeyType::EcdsaP384 => KeyType::EcdsaP384,
            FfiSshKeyType::EcdsaP521 => KeyType::EcdsaP521,
            FfiSshKeyType::Rsa3072 => KeyType::Rsa3072,
            FfiSshKeyType::Rsa4096 => KeyType::Rsa4096,
        }
    }
}

/// The settings of a new SSH Key item.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiNewSshKey {
    pub vault_id: String,
    pub title: String,
    /// Host bookmarks: names or OpenSSH `Host` patterns.
    pub hosts: Vec<String>,
    pub use_in_agent: bool,
    pub confirm_each_use: bool,
    /// Key comment; the title when absent.
    pub comment: Option<String>,
}

/// A key the agent offers.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiAgentKey {
    pub item_id: String,
    pub vault_id: String,
    pub vault_name: String,
    pub title: String,
    pub fingerprint: String,
    /// The `authorized_keys` line.
    pub public_key: String,
    pub confirm_each_use: bool,
    pub hosts: Vec<String>,
}

fn key_error(e: KeyError) -> OnePassError {
    invalid(&format!("SSH key: {e}"))
}

/// A bookmark fits on an OpenSSH `Host` line: one token, no quote, no
/// control character.
fn host_ok(host: &str) -> bool {
    !host.is_empty()
        && !host
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || c == '"')
}

fn check_new(new: &FfiNewSshKey) -> Result<(), OnePassError> {
    if new.title.trim().is_empty() {
        return Err(invalid("title"));
    }
    if new.hosts.iter().any(|h| !host_ok(h.trim())) {
        return Err(invalid("host bookmark"));
    }
    let comment = new.comment.as_deref().unwrap_or(&new.title);
    if comment.chars().any(char::is_control) {
        return Err(invalid("key comment"));
    }
    Ok(())
}

fn yes_no(b: bool) -> FieldValue {
    FieldValue::Menu(if b { "yes" } else { "no" }.into())
}

fn set(item: &mut Item, id: &str, value: FieldValue) -> Result<(), OnePassError> {
    item.field_mut(id)
        .ok_or_else(|| invalid("SSH Key template"))?
        .value = value;
    Ok(())
}

/// Fills the `hosts` fields: the template's empty one first, then copies
/// of it after the last one (the field is repeatable).
fn set_hosts(item: &mut Item, hosts: &[String]) -> Result<(), OnePassError> {
    let (si, fi) = item
        .sections
        .iter()
        .enumerate()
        .find_map(|(si, s)| {
            s.fields
                .iter()
                .position(|f| f.id == "hosts")
                .map(|fi| (si, fi))
        })
        .ok_or_else(|| invalid("SSH Key template"))?;
    let template = item.sections[si].fields[fi].clone();
    let mut seen = Vec::new();
    for h in hosts.iter().map(|h| h.trim()) {
        if seen.contains(&h) {
            continue;
        }
        seen.push(h);
    }
    for (n, h) in seen.into_iter().enumerate() {
        if n == 0 {
            item.sections[si].fields[fi].value = FieldValue::Text(h.to_owned());
        } else {
            let mut f = template.clone();
            f.value = FieldValue::Text(h.to_owned());
            item.sections[si].fields.insert(fi + n, f);
        }
    }
    Ok(())
}

impl Session {
    fn save_key(&self, key: &AgentKey, new: FfiNewSshKey) -> Result<String, OnePassError> {
        check_new(&new)?;
        let vault_id = parse_id(&new.vault_id)?;
        let comment = new.comment.clone().unwrap_or_else(|| new.title.clone());
        let value = SshKeyValue {
            private_pem: key.to_openssh_private(&comment).map_err(key_error)?,
            public_openssh: key.public_openssh(&comment),
            fingerprint_sha256: key.fingerprint(),
        };
        self.with(|repo| {
            let vault = find_vault(repo, vault_id)?;
            let mut item = new_item(ItemType::SshKey, vault_id, new.title.trim());
            set(&mut item, "private_key", FieldValue::SshKey(value.clone()))?;
            set(
                &mut item,
                "algorithm",
                FieldValue::Menu(key.algorithm_name().into()),
            )?;
            if !comment.is_empty() {
                set(&mut item, "comment", FieldValue::Text(comment.clone()))?;
            }
            set(&mut item, "use_in_agent", yes_no(new.use_in_agent))?;
            set(&mut item, "confirm_each_use", yes_no(new.confirm_each_use))?;
            set_hosts(&mut item, &new.hosts)?;
            let now = OffsetDateTime::now_utc();
            item.created_at = now;
            item.updated_at = now;
            let id = item.id;
            repo.save_item(&vault, item)?;
            Ok(crate::convert::id_hex(id))
        })
    }
}

#[uniffi::export]
impl Session {
    /// Generates a key (aws-lc-rs) into a new SSH Key item. Returns the
    /// item id.
    pub fn generate_ssh_key(
        &self,
        key_type: FfiSshKeyType,
        new: FfiNewSshKey,
    ) -> Result<String, OnePassError> {
        check_new(&new)?;
        let key = AgentKey::generate(key_type.into()).map_err(key_error)?;
        self.save_key(&key, new)
    }

    /// Imports a private key (OpenSSH, encrypted or not, or PEM) into a new
    /// SSH Key item, stored unencrypted in OpenSSH form (the vault encrypts
    /// it). The passphrase is not kept. Returns the item id.
    pub fn import_ssh_key(
        &self,
        private_key: String,
        passphrase: Option<String>,
        new: FfiNewSshKey,
    ) -> Result<String, OnePassError> {
        check_new(&new)?;
        let text = Zeroizing::new(private_key);
        let passphrase = passphrase.map(Zeroizing::new);
        let key = AgentKey::from_private_text(&text, passphrase.as_deref().map(String::as_str))
            .map_err(key_error)?;
        self.save_key(&key, new)
    }

    /// The keys the agent offers now: SSH Key items marked for the agent,
    /// not trashed nor archived.
    pub fn agent_keys(&self) -> Result<Vec<FfiAgentKey>, OnePassError> {
        let keys = self.with(|repo| Ok(ssh_keys_of(repo)?))?;
        Ok(keys
            .into_iter()
            .map(|k| FfiAgentKey {
                public_key: public_line(&k),
                item_id: k.item_id.replace('-', ""),
                vault_id: k.vault_id.replace('-', ""),
                vault_name: k.vault_name,
                title: k.title,
                fingerprint: k.fingerprint,
                confirm_each_use: k.confirm_each_use,
                hosts: k.hosts,
            })
            .collect())
    }
}

/// Whether a private key text is encrypted (a passphrase is needed).
#[uniffi::export]
pub fn ssh_key_is_encrypted(private_key: String) -> bool {
    let text = Zeroizing::new(private_key);
    is_encrypted(&text)
}

/// The `authorized_keys` line of an agent key, commented with its title.
fn public_line(k: &KeyInfo) -> String {
    use data_encoding::BASE64;
    let algorithm = k
        .public_blob
        .get(..4)
        .and_then(|b| <[u8; 4]>::try_from(b).ok())
        .map(|b| u32::from_be_bytes(b) as usize)
        .and_then(|len| k.public_blob.get(4..4 + len))
        .and_then(|b| std::str::from_utf8(b).ok())
        .unwrap_or("ssh-unknown");
    let title: String = k
        .title
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    format!("{algorithm} {} {title}", BASE64.encode(&k.public_blob))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_and_comments_are_checked() {
        let mut new = FfiNewSshKey {
            vault_id: "x".into(),
            title: "Github".into(),
            hosts: vec!["github.com".into(), "*.exemple.fr".into()],
            use_in_agent: true,
            confirm_each_use: false,
            comment: None,
        };
        assert!(check_new(&new).is_ok());
        new.hosts.push("two words".into());
        assert!(check_new(&new).is_err());
        new.hosts.pop();
        new.comment = Some("a\u{1b}[2J".into());
        assert!(check_new(&new).is_err());
    }
}
