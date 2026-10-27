//! The vault key source: which SSH Key items the agent offers, and loading
//! their private keys, over an in-memory repository.

use std::sync::OnceLock;

use onepass_core::account::{Account, NewAccount};
use onepass_core::crypto::{KdfParams, random_array};
use onepass_core::model::field::SshKeyValue;
use onepass_core::model::{FieldValue, Item, ItemType, new_item};
use onepass_core::repo::{DeviceState, Repository};
use onepass_core::store::{MemoryStore, Record, RecordKind, RecordStore};
use onepass_core::vault::{Vault, VaultMeta};
use onepass_ssh_agent::keys::{AgentKey, KeyType};
use onepass_ssh_agent::{KeySource, RepoKeySource, load_key_of, menu_truthy, ssh_keys_of};

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
