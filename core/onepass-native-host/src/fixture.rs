//! The `fixture` source: a JSON file of fictional items loaded into a real
//! `Repository` over a `MemoryStore`, with the fast development KDF
//! parameters. Debug builds only: a release build refuses it.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};

use onepass_core::crypto::{DEV_KDF_FLOOR, KdfParams, SecretKey};
use onepass_core::model::{
    Address, FieldType, FieldValue, Item, ItemType, ItemUrl, LoginMethod, MatchRule, Provider,
    new_item,
};
use onepass_core::repo::{DeviceState, Repository};
use onepass_core::store::{MemoryStore, Record, RecordKind, RecordStore};
use onepass_core::vault::{Vault, VaultMeta};
use onepass_core::{Error, Id};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::{Date, Month};
use zeroize::Zeroizing;

use crate::config::HostError;
use crate::vault::RepoVault;

/// Password of the in-memory account. It protects nothing: the store
/// lives in this process only.
const FIXTURE_PASSWORD: &str = "onepass-fixture";
const URL_LABEL: &str = "site web";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureFile {
    #[serde(rename = "_comment", default)]
    _comment: Option<String>,
    #[serde(default = "default_account")]
    account: String,
    vaults: Vec<VaultDef>,
    items: Vec<ItemDef>,
}

fn default_account() -> String {
    "alex@atlas.dev".to_owned()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VaultDef {
    name: String,
    #[serde(default)]
    color: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UrlDef {
    url: String,
    rule: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MethodDef {
    provider: String,
    account_title: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ItemDef {
    #[serde(rename = "type")]
    kind: String,
    title: String,
    vault: String,
    #[serde(default)]
    urls: Vec<UrlDef>,
    #[serde(default)]
    fields: BTreeMap<String, Value>,
    #[serde(default)]
    totp_uri: Option<String>,
    #[serde(default)]
    archived: bool,
    #[serde(default)]
    hide_from_autofill: bool,
    #[serde(default)]
    reprompt: bool,
    #[serde(default)]
    login_methods: Vec<MethodDef>,
}

fn bad(msg: impl Into<String>) -> HostError {
    HostError::new(format!("fixture: {}", msg.into()))
}

fn core(e: Error) -> HostError {
    bad(e.to_string())
}

fn item_type(s: &str) -> Result<ItemType, HostError> {
    Ok(match s {
        "login" => ItemType::Login,
        "password" => ItemType::Password,
        "credit_card" => ItemType::CreditCard,
        "identity" => ItemType::Identity,
        "secure_note" => ItemType::SecureNote,
        "crypto_wallet" => ItemType::CryptoWallet,
        other => return Err(bad(format!("unsupported item type {other:?}"))),
    })
}

fn rule(s: &str) -> Result<MatchRule, HostError> {
    Ok(match s {
        "domain" => MatchRule::Domain,
        "exact_host" => MatchRule::ExactHost,
        "exact_url" => MatchRule::ExactUrl,
        "never" => MatchRule::Never,
        other => return Err(bad(format!("unknown rule {other:?}"))),
    })
}

fn provider(s: &str) -> Result<Provider, HostError> {
    Ok(match s {
        "google" => Provider::Google,
        "apple" => Provider::Apple,
        "microsoft" => Provider::Microsoft,
        "github" => Provider::GitHub,
        "facebook" => Provider::Facebook,
        "x" => Provider::X,
        "linkedin" => Provider::LinkedIn,
        "discord" => Provider::Discord,
        "slack" => Provider::Slack,
        other => return Err(bad(format!("unknown provider {other:?}"))),
    })
}

fn text(id: &str, v: &Value) -> Result<String, HostError> {
    v.as_str()
        .map(str::to_owned)
        .ok_or_else(|| bad(format!("field {id} must be a string")))
}

/// `"MM/YYYY"`.
fn month_year(id: &str, s: &str) -> Result<FieldValue, HostError> {
    let err = || bad(format!("field {id} must be MM/YYYY"));
    let (m, y) = s.split_once('/').ok_or_else(err)?;
    let month: u8 = m.parse().map_err(|_| err())?;
    let year: u16 = y.parse().map_err(|_| err())?;
    if !(1..=12).contains(&month) {
        return Err(err());
    }
    Ok(FieldValue::MonthYear { year, month })
}

/// `"YYYY-MM-DD"`.
fn date(id: &str, s: &str) -> Result<FieldValue, HostError> {
    let err = || bad(format!("field {id} must be YYYY-MM-DD"));
    let mut parts = s.splitn(3, '-');
    let y: i32 = parts.next().and_then(|p| p.parse().ok()).ok_or_else(err)?;
    let m: u8 = parts.next().and_then(|p| p.parse().ok()).ok_or_else(err)?;
    let d: u8 = parts.next().and_then(|p| p.parse().ok()).ok_or_else(err)?;
    let month = Month::try_from(m).map_err(|_| err())?;
    Date::from_calendar_date(y, month, d)
        .map(FieldValue::Date)
        .map_err(|_| err())
}

fn address(id: &str, v: &Value) -> Result<FieldValue, HostError> {
    let get = |k: &str| -> Result<String, HostError> {
        match v.get(k) {
            None => Ok(String::new()),
            Some(s) => text(&format!("{id}.{k}"), s),
        }
    };
    if !v.is_object() {
        return Err(bad(format!("field {id} must be an object")));
    }
    Ok(FieldValue::Address(Address {
        line1: get("line1")?,
        line2: get("line2")?,
        city: get("city")?,
        postal_code: get("postal_code")?,
        region: get("region")?,
        country: get("country")?,
    }))
}

/// The value of a template field from its JSON form, by field kind.
fn value(kind: FieldType, id: &str, v: &Value) -> Result<FieldValue, HostError> {
    let secret = |s: String| Zeroizing::new(s);
    Ok(match kind {
        FieldType::Text => FieldValue::Text(text(id, v)?),
        FieldType::Menu => FieldValue::Menu(text(id, v)?),
        FieldType::Url => FieldValue::Url(text(id, v)?),
        FieldType::Email => FieldValue::Email(text(id, v)?),
        FieldType::Phone => FieldValue::Phone(text(id, v)?),
        FieldType::Password => FieldValue::Password(secret(text(id, v)?)),
        FieldType::Concealed => FieldValue::Concealed(secret(text(id, v)?)),
        FieldType::Otp => FieldValue::Otp(secret(text(id, v)?)),
        FieldType::Mnemonic => FieldValue::Mnemonic(secret(text(id, v)?)),
        FieldType::MonthYear => month_year(id, &text(id, v)?)?,
        FieldType::Date => date(id, &text(id, v)?)?,
        FieldType::Address => address(id, v)?,
        other => return Err(bad(format!("field {id}: unsupported kind {other:?}"))),
    })
}

fn build_item(def: &ItemDef, vault: Id) -> Result<Item, HostError> {
    let mut item = new_item(item_type(&def.kind)?, vault, &def.title);
    for (id, v) in &def.fields {
        let field = item
            .field_mut(id)
            .ok_or_else(|| bad(format!("{}: no field {id}", def.title)))?;
        field.value = value(field.kind, id, v)?;
    }
    if let Some(uri) = &def.totp_uri {
        item.field_mut("totp")
            .ok_or_else(|| bad(format!("{}: no totp field", def.title)))?
            .value = FieldValue::Otp(Zeroizing::new(uri.clone()));
    }
    for u in &def.urls {
        item.urls.push(ItemUrl {
            label: URL_LABEL.to_owned(),
            url: u.url.clone(),
            rule: rule(&u.rule)?,
            primary: item.urls.is_empty(),
        });
    }
    item.archived = def.archived;
    item.hide_from_autofill = def.hide_from_autofill;
    item.reprompt = def.reprompt;
    Ok(item)
}

/// Fast KDF parameters of the dev floor, with a fresh salt.
fn dev_kdf() -> Result<KdfParams, HostError> {
    let mut kdf = KdfParams::new_default().map_err(core)?;
    (kdf.m_kib, kdf.t, kdf.p) = DEV_KDF_FLOOR;
    Ok(kdf)
}

/// A `MemoryStore` shared with the cache writer: the repository owns one
/// handle, the cache keeps another to snapshot the records.
#[derive(Clone, Default)]
pub struct SharedMemory(Arc<Mutex<MemoryStore>>);

impl SharedMemory {
    fn inner(&self) -> MutexGuard<'_, MemoryStore> {
        self.0.lock().unwrap_or_else(|p| p.into_inner())
    }
}

impl RecordStore for SharedMemory {
    fn put(&mut self, r: Record) -> onepass_core::Result<()> {
        self.inner().put(r)
    }
    fn put_if_version(&mut self, r: Record, expected: Option<u64>) -> onepass_core::Result<()> {
        self.inner().put_if_version(r, expected)
    }
    fn get(&self, kind: RecordKind, id: Id) -> onepass_core::Result<Option<Record>> {
        self.inner().get(kind, id)
    }
    fn list(&self, kind: RecordKind) -> onepass_core::Result<Vec<Record>> {
        self.inner().list(kind)
    }
    fn delete(&mut self, kind: RecordKind, id: Id) -> onepass_core::Result<()> {
        self.inner().delete(kind, id)
    }
}

/// The fixture source's vault.
pub type FixtureVault = RepoVault<SharedMemory>;

const KINDS: [RecordKind; 6] = [
    RecordKind::AccountParams,
    RecordKind::Keyset,
    RecordKind::VaultKey,
    RecordKind::VaultMeta,
    RecordKind::Item,
    RecordKind::Manifest,
];
const CACHE_VERSION: u8 = 1;

#[derive(Serialize, Deserialize)]
struct CachedRecord {
    kind: u8,
    id: Id,
    version: u64,
    data: Vec<u8>,
}

/// What `fixture-cache.bin` holds: the encrypted store of a fixture
/// account, the key to open it, and the fixture it was built from.
#[derive(Serialize, Deserialize)]
struct Cache {
    version: u8,
    fixture: Vec<u8>,
    secret_key: Zeroizing<String>,
    state: DeviceState,
    records: Vec<CachedRecord>,
}

fn parse(raw: &[u8]) -> Result<FixtureFile, HostError> {
    serde_json::from_slice(raw).map_err(|e| bad(format!("invalid JSON: {e}")))
}

fn refuse_release() -> Result<(), HostError> {
    if cfg!(debug_assertions) {
        Ok(())
    } else {
        Err(HostError::new(
            "the fixture source is refused in a release build",
        ))
    }
}

/// Create the account and its items. Every save signs a manifest, which
/// takes most of the time in a debug build.
fn build(
    file: &FixtureFile,
    store: SharedMemory,
) -> Result<(Repository<SharedMemory>, SecretKey), HostError> {
    let (mut repo, key) =
        Repository::create_account(store, FIXTURE_PASSWORD, dev_kdf()?).map_err(core)?;
    let mut vaults: HashMap<String, Vault> = HashMap::new();
    for v in repo.vaults().map_err(core)? {
        vaults.insert(v.meta.name.clone(), v);
    }
    for def in &file.vaults {
        if !vaults.contains_key(&def.name) {
            let v = repo
                .create_vault(VaultMeta {
                    name: def.name.clone(),
                    icon: "folder".to_owned(),
                    color: def.color.clone().unwrap_or_else(|| "blue".to_owned()),
                    travel_safe: false,
                    mcp_access: false,
                })
                .map_err(core)?;
            vaults.insert(def.name.clone(), v);
        }
    }

    let mut built = Vec::with_capacity(file.items.len());
    let mut by_title: HashMap<&str, Id> = HashMap::new();
    for def in &file.items {
        let vault = vaults
            .get(&def.vault)
            .ok_or_else(|| bad(format!("{}: unknown vault {:?}", def.title, def.vault)))?;
        let item = build_item(def, vault.id)?;
        by_title.insert(&def.title, item.id);
        built.push((def, item));
    }
    for (def, item) in &mut built {
        for m in &def.login_methods {
            let account = *by_title.get(m.account_title.as_str()).ok_or_else(|| {
                bad(format!(
                    "{}: unknown account {:?}",
                    def.title, m.account_title
                ))
            })?;
            item.login_methods.push(LoginMethod::Provider {
                provider: provider(&m.provider)?,
                account,
                relay_email: None,
            });
        }
    }
    for (def, item) in built {
        let vault = &vaults[&def.vault];
        repo.save_item(vault, item)
            .map_err(|e| bad(format!("{}: {e}", def.title)))?;
    }
    Ok((repo, key))
}

/// The `VaultAccess` view: account name, vault colors by name.
fn wrap(file: &FixtureFile, repo: Repository<SharedMemory>) -> Result<FixtureVault, HostError> {
    let vaults = repo.vaults().map_err(core)?;
    let mut out = RepoVault::new(None, &file.account);
    out.set_known_vaults(vaults.len());
    for def in &file.vaults {
        if let (Some(c), Some(v)) = (&def.color, vaults.iter().find(|v| v.meta.name == def.name)) {
            out.set_color(v.id, c.clone());
        }
    }
    out.set_repo(repo);
    Ok(out)
}

/// Load a fixture file into a fresh in-memory repository, without the
/// cache (the host itself uses `load_fixture_cached`).
#[allow(dead_code)]
pub fn load_fixture(path: &Path) -> Result<FixtureVault, HostError> {
    refuse_release()?;
    let raw = std::fs::read(path).map_err(|e| bad(format!("cannot read: {}", e.kind())))?;
    let file = parse(&raw)?;
    let (repo, _key) = build(&file, SharedMemory::default())?;
    wrap(&file, repo)
}

fn snapshot(store: &SharedMemory) -> onepass_core::Result<Vec<CachedRecord>> {
    let mut out = Vec::new();
    for kind in KINDS {
        for r in store.list(kind)? {
            out.push(CachedRecord {
                kind: kind.code(),
                id: r.id,
                version: r.version,
                data: r.data,
            });
        }
    }
    Ok(out)
}

/// Write the cache atomically (temporary file, rename), mode 0600.
fn write_cache(
    path: &Path,
    fixture: &[u8],
    key: &Zeroizing<String>,
    state: &DeviceState,
    store: &SharedMemory,
) -> Result<(), HostError> {
    let cache = Cache {
        version: CACHE_VERSION,
        fixture: fixture.to_vec(),
        secret_key: key.clone(),
        state: state.clone(),
        records: snapshot(store).map_err(core)?,
    };
    let bytes =
        Zeroizing::new(postcard::to_allocvec(&cache).map_err(|_| bad("cannot encode the cache"))?);
    crate::pairings::write_atomic(path, &bytes)
        .map_err(|e| bad(format!("cannot write the cache: {}", e.kind())))
}

/// Reopen a cached store built from exactly `raw`.
fn read_cache(
    path: &Path,
    raw: &[u8],
) -> Option<(Repository<SharedMemory>, Zeroizing<String>, SharedMemory)> {
    let bytes = Zeroizing::new(std::fs::read(path).ok()?);
    let cache: Cache = postcard::from_bytes(&bytes).ok()?;
    if cache.version != CACHE_VERSION || cache.fixture != raw {
        return None;
    }
    let mut store = SharedMemory::default();
    for r in cache.records {
        store
            .put(Record {
                id: r.id,
                kind: RecordKind::from_code(r.kind).ok()?,
                version: r.version,
                data: r.data,
            })
            .ok()?;
    }
    let key = SecretKey::parse(&cache.secret_key).ok()?;
    let repo = Repository::unlock(store.clone(), FIXTURE_PASSWORD, &key, cache.state).ok()?;
    Some((repo, cache.secret_key, store))
}

/// `load_fixture` through a cache file in the host data directory. The
/// encrypted store, its key and the fixture bytes are kept in `cache`
/// (0600): a later launch with the same fixture reopens it instead of
/// signing every item again, and logins saved by the extension survive
/// the next connection (each connection is a new process).
pub fn load_fixture_cached(path: &Path, cache: &Path) -> Result<FixtureVault, HostError> {
    refuse_release()?;
    let raw = std::fs::read(path).map_err(|e| bad(format!("cannot read: {}", e.kind())))?;
    let file = parse(&raw)?;
    let (repo, key, store) = match read_cache(cache, &raw) {
        Some(found) => found,
        None => {
            let store = SharedMemory::default();
            let (repo, key) = build(&file, store.clone())?;
            let key = Zeroizing::new(key.to_display());
            write_cache(cache, &raw, &key, repo.device_state(), &store)?;
            (repo, key, store)
        }
    };
    let mut vault = wrap(&file, repo)?;
    let cache = cache.to_path_buf();
    vault.set_after_save(Box::new(move |repo| {
        // A failed write only loses the change for later connections.
        let _ = write_cache(&cache, &raw, &key, repo.device_state(), &store);
        Ok(())
    }));
    Ok(vault)
}

#[cfg(test)]
mod tests {
    use super::*;
    use onepass_bridge::service::VaultAccess;

    fn e2e() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/e2e.json")
    }

    #[test]
    fn e2e_fixture_loads() {
        let mut v = load_fixture(&e2e()).unwrap();
        let items = v.items().unwrap();
        assert_eq!(items.len(), 12);
        let docs = items.iter().find(|(_, i)| i.title == "Atlas Docs").unwrap();
        let perso = items
            .iter()
            .find(|(_, i)| i.title == "Google perso")
            .unwrap();
        assert!(matches!(
            docs.1.login_methods[0],
            LoginMethod::Provider { account, .. } if account == perso.1.id
        ));
        let card = items
            .iter()
            .find(|(_, i)| i.title == "Carte Atlas")
            .unwrap();
        assert_eq!(
            card.1.field("expiry").unwrap().value,
            FieldValue::MonthYear {
                year: 2029,
                month: 4
            }
        );
        let names: Vec<_> = v.vaults().unwrap().into_iter().map(|v| v.name).collect();
        assert!(names.contains(&"Personnel".to_owned()));
        assert!(names.contains(&"Atlas".to_owned()));
    }

    #[test]
    fn locked_fixture_unlocks() {
        let mut v = load_fixture(&e2e()).unwrap();
        v.set_locked(true);
        assert!(v.status().locked);
        assert!(v.items().is_err());
        assert!(v.unlock().unwrap());
        assert!(!v.status().locked);
    }

    #[test]
    fn cache_reopens_and_keeps_saves() {
        let dir = tempfile::tempdir().unwrap();
        let cache = dir.path().join("fixture-cache.bin");
        let mut v = load_fixture_cached(&e2e(), &cache).unwrap();
        let (info, mut item) = v
            .items()
            .unwrap()
            .into_iter()
            .find(|(_, i)| i.title == "Atlas admin")
            .unwrap();
        item.title = "Atlas admin 2".into();
        v.save(info.id, item).unwrap();
        drop(v);
        let mut again = load_fixture_cached(&e2e(), &cache).unwrap();
        let items = again.items().unwrap();
        assert_eq!(items.len(), 12);
        assert!(items.iter().any(|(_, i)| i.title == "Atlas admin 2"));
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&cache).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn bad_fixture_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("f.json");
        std::fs::write(
            &p,
            r#"{"vaults":[],"items":[{"type":"rocket","title":"x","vault":"Personnel"}]}"#,
        )
        .unwrap();
        assert!(load_fixture(&p).is_err());
    }
}
