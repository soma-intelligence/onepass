//! The vault key source: which SSH Key items the agent offers, and loading
//! their private keys, over an in-memory repository.

use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use onepass_core::account::{Account, NewAccount};
use onepass_core::crypto::{KdfParams, random_array};
use onepass_core::model::field::SshKeyValue;
use onepass_core::model::key_use::{KeyUse, KeyUseAction, KeyUseChannel};
use onepass_core::model::{FieldValue, Item, ItemType, new_item};
use onepass_core::repo::{DeviceState, Repository};
use onepass_core::store::{MemoryStore, Record, RecordKind, RecordStore};
use onepass_core::vault::{Vault, VaultMeta};
use onepass_guard::Decision;
use onepass_guard::testing::ScriptedApprover;
use onepass_ssh_agent::keys::{AgentKey, KeyType};
use onepass_ssh_agent::wire::{Request, Response};
use onepass_ssh_agent::{
    Agent, AgentConfig, ConnState, KeyInfo, KeySource, RepoKeySource, load_key_of, menu_truthy,
    ssh_keys_of,
};
use time::{Duration as TimeDuration, OffsetDateTime};

mod common;

const PASSWORD: &str = "ssh agent test pw";

/// One account for every test: SLH-DSA creation is slow.
fn shared() -> &'static NewAccount {
    static N: OnceLock<NewAccount> = OnceLock::new();
    N.get_or_init(|| {
        let kdf = KdfParams {
            m_kib: 8192,
            t: 1,
            p: 1,
            salt: random_array().unwrap(),
        };
        Account::create_with_params(PASSWORD, kdf).unwrap()
    })
}

fn repo() -> Repository<MemoryStore> {
    let n = shared();
    let id = n.account.params.account_id;
    let mut store = MemoryStore::new();
    for (kind, data) in [
        (RecordKind::AccountParams, &n.params_record),
        (RecordKind::Keyset, &n.keyset_record),
    ] {
        store
            .put(Record {
                id,
                kind,
                version: 1,
                data: data.clone(),
            })
            .unwrap();
    }
    Repository::unlock(store, PASSWORD, &n.secret_key, DeviceState::default()).unwrap()
}

fn vault(repo: &mut Repository<MemoryStore>, name: &str) -> Vault {
    repo.create_vault(VaultMeta {
        name: name.into(),
        icon: "key".into(),
        color: "blue".into(),
        travel_safe: false,
        mcp_access: false,
    })
    .unwrap()
}

/// An SSH Key item for `key`, as the CLI writes it (spec 6.5).
fn ssh_item(v: &Vault, title: &str, key: &AgentKey, agent: &str, hosts: &[&str]) -> Item {
    let mut item = new_item(ItemType::SshKey, v.id, title);
    item.field_mut("private_key").unwrap().value = FieldValue::SshKey(SshKeyValue {
        private_pem: key.to_openssh_private(title).unwrap(),
        public_openssh: key.public_openssh(title),
        fingerprint_sha256: "SHA256:not-trusted".into(),
    });
    item.field_mut("use_in_agent").unwrap().value = FieldValue::Menu(agent.into());
    item.field_mut("confirm_each_use").unwrap().value = FieldValue::Menu("no".into());
    if let Some((first, rest)) = hosts.split_first() {
        let section = &mut item.sections[0];
        let pos = section.fields.iter().position(|f| f.id == "hosts").unwrap();
        section.fields[pos].value = FieldValue::Text((*first).into());
        for (n, h) in rest.iter().enumerate() {
            let mut copy = section.fields[pos].clone();
            copy.value = FieldValue::Text((*h).into());
            section.fields.insert(pos + 1 + n, copy);
        }
    }
    item
}

#[test]
fn menu_truthy_values() {
    for yes in ["yes", "oui", "true", "1", "YES", " Oui ", "True"] {
        assert!(menu_truthy(&FieldValue::Menu(yes.into())), "{yes}");
        assert!(menu_truthy(&FieldValue::Text(yes.into())), "{yes}");
    }
    for no in ["no", "non", "false", "0", "", "y", "yes please"] {
        assert!(!menu_truthy(&FieldValue::Menu(no.into())), "{no}");
    }
    assert!(!menu_truthy(&FieldValue::Empty));
    assert!(!menu_truthy(&FieldValue::Number(1)));
}

#[test]
fn lists_agent_keys_of_every_vault() {
    let mut repo = repo();
    let perso = vault(&mut repo, "Perso");
    let work = vault(&mut repo, "Work");
    let ed = AgentKey::generate(KeyType::Ed25519).unwrap();
    let ec = AgentKey::generate(KeyType::EcdsaP256).unwrap();
    let off = AgentKey::generate(KeyType::Ed25519).unwrap();
    let trashed = AgentKey::generate(KeyType::Ed25519).unwrap();
    let archived = AgentKey::generate(KeyType::Ed25519).unwrap();

    let mut ed_item = ssh_item(
        &perso,
        "GitHub",
        &ed,
        "oui",
        &["github.com", "*.example.test"],
    );
    ed_item.field_mut("confirm_each_use").unwrap().value = FieldValue::Menu("yes".into());
    let ed_id = ed_item.id;
    repo.save_item(&perso, ed_item).unwrap();
    repo.save_item(&work, ssh_item(&work, "Deploy", &ec, "yes", &[]))
        .unwrap();
    repo.save_item(&perso, ssh_item(&perso, "Off", &off, "no", &[]))
        .unwrap();
    let t = ssh_item(&perso, "Trashed", &trashed, "yes", &[]);
    let tid = t.id;
    repo.save_item(&perso, t).unwrap();
    repo.trash_item(&perso, tid).unwrap();
    let a = ssh_item(&work, "Archived", &archived, "yes", &[]);
    let aid = a.id;
    repo.save_item(&work, a).unwrap();
    repo.archive_item(&work, aid).unwrap();
    // A login is never offered.
    let mut login = new_item(ItemType::Login, perso.id, "Login");
    login.field_mut("username").unwrap().value = FieldValue::Text("u".into());
    repo.save_item(&perso, login).unwrap();

    let mut keys = ssh_keys_of(&mut repo).unwrap();
    keys.sort_by(|a, b| a.title.cmp(&b.title));
    let titles: Vec<&str> = keys.iter().map(|k| k.title.as_str()).collect();
    assert_eq!(titles, ["Deploy", "GitHub"]);

    let gh = &keys[1];
    assert_eq!(gh.item_id, ed_id.to_string());
    assert_eq!(gh.vault_id, perso.id.to_string());
    assert_eq!(gh.vault_name, "Perso");
    assert_eq!(gh.public_blob, ed.public_blob());
    // Computed from the key, not copied from the item.
    assert_eq!(gh.fingerprint, ed.fingerprint());
    assert!(gh.confirm_each_use);
    assert_eq!(gh.hosts, ["github.com", "*.example.test"]);

    let deploy = &keys[0];
    assert_eq!(deploy.vault_name, "Work");
    assert_eq!(deploy.public_blob, ec.public_blob());
    assert!(!deploy.confirm_each_use);
    assert!(deploy.hosts.is_empty());

    // The private key loads, for listed keys only.
    let loaded = load_key_of(&mut repo, &gh.item_id).unwrap();
    assert_eq!(loaded.public_blob(), ed.public_blob());
    assert!(load_key_of(&mut repo, &tid.to_string()).is_err());
    assert!(load_key_of(&mut repo, &aid.to_string()).is_err());
    assert!(load_key_of(&mut repo, "not an id").is_err());
    assert!(load_key_of(&mut repo, &onepass_core::Id::new().to_string()).is_err());
}

#[test]
fn repo_key_source_lists_and_loads() {
    let mut repo = repo();
    let perso = vault(&mut repo, "Perso");
    let ed = AgentKey::generate(KeyType::Ed25519).unwrap();
    let item = ssh_item(&perso, "Laptop", &ed, "true", &[]);
    let id = item.id.to_string();
    repo.save_item(&perso, item).unwrap();

    let mut source = RepoKeySource::new(repo);
    let keys = source.list().unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].item_id, id);
    let key = source.load(&id).unwrap();
    let sig = key.sign(b"data", 0).unwrap();
    onepass_ssh_agent::keys::verify_signature(&ed.public_blob(), b"data", &sig).unwrap();
}

// Key-use log: SSH agent signatures (spec 6.5, "SSH agent" row).

type Shared = Arc<Mutex<RepoKeySource<MemoryStore>>>;

/// A key source the test keeps a handle on, to read the repository the
/// agent wrote to. `drop_after_load` deletes the item right after its key
/// was loaded, so the key-use write has nowhere to go.
struct Handle {
    inner: Shared,
    drop_after_load: bool,
}

impl KeySource for Handle {
    fn list(&mut self) -> Result<Vec<KeyInfo>, String> {
        self.inner.lock().unwrap().list()
    }

    fn load(&mut self, item_id: &str) -> Result<AgentKey, String> {
        let mut src = self.inner.lock().unwrap();
        let key = src.load(item_id)?;
        if self.drop_after_load {
            let id: onepass_core::Id = item_id.parse().unwrap();
            let repo = src.repo_mut();
            let v = repo.vaults().unwrap().remove(0);
            repo.delete_item(&v, id).unwrap();
        }
        Ok(key)
    }

    fn note_signed(&mut self, item_id: &str, field: &str, client: &str) {
        self.inner
            .lock()
            .unwrap()
            .note_signed(item_id, field, client);
    }
}

struct Rig {
    agent: Agent<Handle>,
    source: Shared,
    vault: Vault,
    item_id: onepass_core::Id,
    key: AgentKey,
    approver: Arc<ScriptedApprover>,
}

fn rig(answers: Vec<Decision>, drop_after_load: bool) -> Rig {
    let mut repo = repo();
    let v = vault(&mut repo, "Perso");
    let key = AgentKey::generate(KeyType::Ed25519).unwrap();
    let item = ssh_item(&v, "Laptop", &key, "yes", &[]);
    let item_id = item.id;
    repo.save_item(&v, item).unwrap();
    let source: Shared = Arc::new(Mutex::new(RepoKeySource::new(repo)));
    let approver = Arc::new(ScriptedApprover::new(answers));
    let (guards, env) = common::guards(common::loose_limits());
    // The grants file lives in the guard env's directory.
    std::mem::forget(env);
    let agent = Agent::new(
        Handle {
            inner: source.clone(),
            drop_after_load,
        },
        approver.clone(),
        Box::new(common::SharedAudit::default()),
        AgentConfig::default(),
        guards,
    );
    Rig {
        agent,
        source,
        vault: v,
        item_id,
        key,
        approver,
    }
}

impl Rig {
    fn sign(&self) -> Response {
        let mut conn = ConnState::default();
        self.agent
            .handle(
                &mut conn,
                &common::peer("/usr/bin/ssh"),
                Request::Sign {
                    key_blob: self.key.public_blob(),
                    data: b"data to sign".to_vec(),
                    flags: 0,
                },
            )
            .response
    }

    fn entries(&self) -> Vec<KeyUse> {
        let mut src = self.source.lock().unwrap();
        let repo = src.repo_mut();
        let items = repo.items(&self.vault).unwrap();
        let item = items.iter().find(|i| i.id == self.item_id).unwrap();
        item.key_use_trailer().entries
    }
}

fn is_signature(r: &Response) -> bool {
    matches!(r, Response::Signature(_))
}

#[test]
fn sign_records_signed() {
    let rig = rig(vec![Decision::AllowOnce], false);
    let label = {
        let mut src = rig.source.lock().unwrap();
        let items = src.repo_mut().items(&rig.vault).unwrap();
        items[0].field("private_key").unwrap().label.clone()
    };
    assert!(is_signature(&rig.sign()));
    let entries = rig.entries();
    assert_eq!(entries.len(), 1);
    let e = &entries[0];
    assert_eq!(e.channel, KeyUseChannel::SshAgent);
    assert_eq!(e.action, KeyUseAction::Signed);
    assert_eq!(e.field, label);
    assert_eq!(e.count, 1);
    // The client is a display name: no path, no command line, no host.
    assert!(!e.client.contains('/'), "{}", e.client);
    assert!(!e.client.is_empty());
}

#[test]
fn fifty_signatures_one_entry() {
    let rig = rig(vec![Decision::AllowFor(Duration::from_secs(600))], false);
    for _ in 0..50 {
        assert!(is_signature(&rig.sign()));
    }
    assert_eq!(rig.approver.calls().len(), 1, "one grant covers the rest");
    // Inside the hour the item was written once: the others are queued.
    assert_eq!(rig.entries().len(), 1);
    assert_eq!(rig.entries()[0].count, 1);
    let later = OffsetDateTime::now_utc() + TimeDuration::seconds(3601);
    {
        let mut src = rig.source.lock().unwrap();
        assert!(src.repo_mut().flush_key_use_queue(later).unwrap() > 0);
    }
    let entries = rig.entries();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].count, 50);
}

#[test]
fn refused_sign_records_nothing() {
    let rig = rig(vec![Decision::Deny], false);
    assert!(!is_signature(&rig.sign()));
    assert!(rig.entries().is_empty());
}

#[test]
fn record_failure_still_signs() {
    let rig = rig(vec![Decision::AllowOnce], true);
    assert!(is_signature(&rig.sign()));
    // The item is gone: nothing could be recorded, the signature stands.
    let mut src = rig.source.lock().unwrap();
    assert!(src.repo_mut().items(&rig.vault).unwrap().is_empty());
}
