//! Signed MCP policy (spec section 4.2): which scopes each MCP vault grants,
//! and the launch options that can only narrow them.
//!
//! The policy file is a [`seal_config`] envelope under the domain
//! [`POLICY_DOMAIN`], signed by the account's local key: an agent with a
//! shell can write the data directory but cannot grant itself a scope.

use onepass_guard::{ClientRecord, GuardError, LocalSigner, open_config, seal_config};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, File};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::str::FromStr;

/// Signature domain of the policy file.
pub const POLICY_DOMAIN: &[u8] = b"mcp-policy";

/// A permission an MCP vault can grant.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    /// List and read item metadata, never values.
    Metadata,
    /// Use secrets without seeing them (`run_with_secrets`, `fill_template`).
    Use,
    /// Create items (`create_login`).
    Write,
    /// Read current one-time codes.
    Totp,
    /// Read secret values.
    Reveal,
}

impl Scope {
    /// Every scope, in order.
    pub const ALL: [Scope; 5] = [
        Scope::Metadata,
        Scope::Use,
        Scope::Write,
        Scope::Totp,
        Scope::Reveal,
    ];

    /// The lowercase name, as stored and shown.
    pub fn as_str(self) -> &'static str {
        match self {
            Scope::Metadata => "metadata",
            Scope::Use => "use",
            Scope::Write => "write",
            Scope::Totp => "totp",
            Scope::Reveal => "reveal",
        }
    }
}

impl fmt::Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Scope {
    type Err = PolicyError;

    fn from_str(s: &str) -> Result<Scope, PolicyError> {
        Scope::ALL
            .into_iter()
            .find(|c| c.as_str() == s)
            .ok_or(PolicyError::Format)
    }
}

/// The signed policy of one account.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// Account the policy belongs to (hyphenated id).
    pub account_id: String,
    /// Scopes per vault id. A vault absent from the map gets the defaults.
    pub vaults: BTreeMap<String, BTreeSet<Scope>>,
    /// Whether `generate_password` is offered.
    pub allow_generate: bool,
}

impl Policy {
    /// The policy that applies without a file: default scopes everywhere,
    /// generation allowed.
    pub fn default_for(account_id: &str) -> Policy {
        Policy {
            account_id: account_id.to_owned(),
            vaults: BTreeMap::new(),
            allow_generate: true,
        }
    }

    /// The scopes the policy grants on `vault_id`: its entry, else
    /// `metadata` and `use`.
    pub fn scopes_for(&self, vault_id: &str) -> BTreeSet<Scope> {
        self.vaults
            .get(vault_id)
            .cloned()
            .unwrap_or_else(|| BTreeSet::from([Scope::Metadata, Scope::Use]))
    }
}

/// Launch options (`--vault`, `--scopes`): they only ever restrict.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Narrowing {
    /// When set, only these vault ids keep any scope.
    pub vaults: Option<BTreeSet<String>>,
    /// When set, scopes outside this set are dropped everywhere.
    pub scopes: Option<BTreeSet<Scope>>,
}

/// Scopes in force on `vault_id`: the policy's, intersected with the
/// narrowing. A vault outside `narrowing.vaults` gets none.
pub fn effective(policy: &Policy, narrowing: &Narrowing, vault_id: &str) -> BTreeSet<Scope> {
    if narrowing
        .vaults
        .as_ref()
        .is_some_and(|v| !v.contains(vault_id))
    {
        return BTreeSet::new();
    }
    let granted = policy.scopes_for(vault_id);
    match &narrowing.scopes {
        Some(only) => granted.intersection(only).copied().collect(),
        None => granted,
    }
}

/// Scopes a paired client may use, per vault id (spec section 4.1). A
/// vault absent from the map is invisible to the client.
pub type ClientScopes = BTreeMap<String, BTreeSet<Scope>>;

/// The scopes of a client record: its `mcp_scopes`, unknown scope names
/// dropped. A record without `mcp_scopes` gets none (fail closed).
pub fn client_scopes(record: &ClientRecord) -> ClientScopes {
    record
        .mcp_scopes
        .iter()
        .flatten()
        .map(|(vault, names)| {
            (
                vault.clone(),
                names.iter().filter_map(|n| n.parse().ok()).collect(),
            )
        })
        .collect()
}

/// The scopes given at pairing (spec section 3.3): `metadata` and `use` on
/// each of `vault_ids` (the MCP vaults).
pub fn default_client_scopes(vault_ids: impl IntoIterator<Item = String>) -> ClientScopes {
    vault_ids
        .into_iter()
        .map(|v| (v, BTreeSet::from([Scope::Metadata, Scope::Use])))
        .collect()
}

/// Scopes in force on `vault_id` for a paired client: [`effective`]
/// (policy and launch narrowing) intersected with the client's scopes. A
/// vault outside the client's scopes gets none.
pub fn effective_for_client(
    policy: &Policy,
    narrowing: &Narrowing,
    client: &ClientScopes,
    vault_id: &str,
) -> BTreeSet<Scope> {
    match client.get(vault_id) {
        Some(allowed) => effective(policy, narrowing, vault_id)
            .intersection(allowed)
            .copied()
            .collect(),
        None => BTreeSet::new(),
    }
}

/// Why a policy file was refused. Never carries file content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyError {
    /// The signature does not verify.
    Tampered,
    /// A valid policy, but of another account.
    WrongAccount,
    /// An I/O failure (only the kind is kept).
    Io(std::io::ErrorKind),
    /// The file or its payload is not a policy.
    Format,
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PolicyError::Tampered => f.write_str("MCP policy signature verification failed"),
            PolicyError::WrongAccount => f.write_str("MCP policy belongs to another account"),
            PolicyError::Io(kind) => write!(f, "MCP policy i/o error: {kind}"),
            PolicyError::Format => f.write_str("MCP policy has an invalid format"),
        }
    }
}

impl std::error::Error for PolicyError {}

impl From<std::io::Error> for PolicyError {
    fn from(e: std::io::Error) -> Self {
        PolicyError::Io(e.kind())
    }
}

impl From<GuardError> for PolicyError {
    fn from(e: GuardError) -> Self {
        match e {
            GuardError::Signature | GuardError::Tampered(_) => PolicyError::Tampered,
            GuardError::Io(kind) => PolicyError::Io(kind),
            // `Config` is not produced by the policy path.
            GuardError::Format(_) | GuardError::Config(_) => PolicyError::Format,
        }
    }
}

/// Reads and verifies the policy at `path`. A missing file gives
/// [`Policy::default_for`]; a bad signature, a payload that is not a policy
/// or a policy of another account is an error.
pub fn load_policy(
    path: &Path,
    signer: &dyn LocalSigner,
    account_id: &str,
) -> Result<Policy, PolicyError> {
    let text = match fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Policy::default_for(account_id));
        }
        Err(e) if e.kind() == std::io::ErrorKind::InvalidData => return Err(PolicyError::Format),
        Err(e) => return Err(e.into()),
    };
    let payload = open_config(signer, POLICY_DOMAIN, &text)?;
    let policy: Policy = serde_json::from_str(&payload).map_err(|_| PolicyError::Format)?;
    if policy.account_id != account_id {
        return Err(PolicyError::WrongAccount);
    }
    Ok(policy)
}

/// Signs `p` and writes it to `path` atomically (fresh temporary file in
/// the same directory, mode `0600`, fsync, rename, fsync of the directory).
pub fn save_policy(path: &Path, signer: &dyn LocalSigner, p: &Policy) -> Result<(), PolicyError> {
    let payload = serde_json::to_string(p).map_err(|_| PolicyError::Format)?;
    let sealed = seal_config(signer, POLICY_DOMAIN, &payload)?;
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    // A fresh, randomly named file created with O_EXCL: a planted file or
    // symlink cannot redirect the write.
    let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
    tmp.as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    tmp.write_all(sealed.as_bytes())?;
    tmp.as_file().sync_all()?;
    tmp.persist(path).map_err(|e| PolicyError::from(e.error))?;
    File::open(dir)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::hmac;

    /// HMAC-SHA256 signer binding the domain, for tests.
    struct TestSigner([u8; 32]);

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
            let key = hmac::Key::new(hmac::HMAC_SHA256, &self.0);
            Ok(hmac::sign(&key, &Self::input(domain, msg))
                .as_ref()
                .to_vec())
        }
        fn verify(&self, domain: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), GuardError> {
            let key = hmac::Key::new(hmac::HMAC_SHA256, &self.0);
            hmac::verify(&key, &Self::input(domain, msg), sig).map_err(|_| GuardError::Signature)
        }
    }

    const ACCOUNT: &str = "0190f0a0-0000-7000-8000-000000000001";

    fn sample() -> Policy {
        let mut p = Policy::default_for(ACCOUNT);
        p.vaults.insert(
            "vault-a".into(),
            BTreeSet::from([Scope::Metadata, Scope::Reveal]),
        );
        p.vaults.insert("vault-b".into(), BTreeSet::new());
        p.allow_generate = false;
        p
    }

    #[test]
    fn default_scopes_are_metadata_and_use() {
        let p = Policy::default_for(ACCOUNT);
        assert!(p.allow_generate);
        assert!(p.vaults.is_empty());
        assert_eq!(
            p.scopes_for("any"),
            BTreeSet::from([Scope::Metadata, Scope::Use])
        );
        let s = sample();
        assert_eq!(s.scopes_for("vault-b"), BTreeSet::new());
        assert_eq!(
            effective(&s, &Narrowing::default(), "vault-a"),
            BTreeSet::from([Scope::Metadata, Scope::Reveal])
        );
    }

    #[test]
    fn narrowing_only_restricts() {
        let p = Policy::default_for(ACCOUNT);
        let n = Narrowing {
            vaults: None,
            scopes: Some(BTreeSet::from([Scope::Reveal, Scope::Metadata])),
        };
        let got = effective(&p, &n, "any");
        assert_eq!(got, BTreeSet::from([Scope::Metadata]));
        assert!(!got.contains(&Scope::Reveal));
        let all = Narrowing {
            vaults: None,
            scopes: Some(Scope::ALL.into_iter().collect()),
        };
        assert_eq!(effective(&sample(), &all, "vault-b"), BTreeSet::new());
    }

    #[test]
    fn narrowing_vault_filter() {
        let p = sample();
        let n = Narrowing {
            vaults: Some(BTreeSet::from(["vault-a".to_owned()])),
            scopes: None,
        };
        assert_eq!(
            effective(&p, &n, "vault-a"),
            BTreeSet::from([Scope::Metadata, Scope::Reveal])
        );
        assert_eq!(effective(&p, &n, "other"), BTreeSet::new());
        assert_eq!(effective(&p, &n, "vault-b"), BTreeSet::new());
    }

    fn record(scopes: Option<BTreeMap<String, BTreeSet<String>>>) -> ClientRecord {
        ClientRecord {
            id: "team:T:x".into(),
            surface: onepass_guard::Surface::Mcp,
            label: "x".into(),
            code: serde_json::Value::Null,
            paired_at: 1,
            mcp_scopes: scopes,
            ssh_keys: None,
        }
    }

    #[test]
    fn client_scopes_intersect_policy_and_narrowing() {
        let p = sample();
        let names = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<BTreeSet<_>>();
        let rec = record(Some(BTreeMap::from([
            ("vault-a".to_owned(), names(&["reveal", "use", "bogus"])),
            ("other".to_owned(), names(&["metadata", "use"])),
        ])));
        let c = client_scopes(&rec);
        assert_eq!(c["vault-a"], BTreeSet::from([Scope::Use, Scope::Reveal]));
        let none = Narrowing::default();
        // Policy grants metadata+reveal on vault-a; the client use+reveal.
        assert_eq!(
            effective_for_client(&p, &none, &c, "vault-a"),
            BTreeSet::from([Scope::Reveal])
        );
        // Defaults (metadata, use) on "other", the client asks both.
        assert_eq!(
            effective_for_client(&p, &none, &c, "other"),
            BTreeSet::from([Scope::Metadata, Scope::Use])
        );
        // A vault absent from the client's scopes gets nothing.
        assert_eq!(
            effective_for_client(&p, &none, &c, "vault-z"),
            BTreeSet::new()
        );
        // The narrowing still applies.
        let n = Narrowing {
            vaults: None,
            scopes: Some(BTreeSet::from([Scope::Use])),
        };
        assert_eq!(
            effective_for_client(&p, &n, &c, "other"),
            BTreeSet::from([Scope::Use])
        );
        // No mcp_scopes at all: nothing.
        assert!(client_scopes(&record(None)).is_empty());
        let d = default_client_scopes(["a".to_owned()]);
        assert_eq!(d["a"], BTreeSet::from([Scope::Metadata, Scope::Use]));
    }

    #[test]
    fn policy_roundtrip_signed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mcp-policy.json");
        let s = TestSigner([3; 32]);
        save_policy(&path, &s, &sample()).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(load_policy(&path, &s, ACCOUNT).unwrap(), sample());
        // Saving again replaces the file.
        let mut p = sample();
        p.allow_generate = true;
        save_policy(&path, &s, &p).unwrap();
        assert_eq!(load_policy(&path, &s, ACCOUNT).unwrap(), p);
        let text = fs::read_to_string(&path).unwrap();
        assert!(text.contains("reveal"), "scopes are stored lowercase");
    }

    #[test]
    fn tampered_policy_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mcp-policy.json");
        let s = TestSigner([3; 32]);
        save_policy(&path, &s, &Policy::default_for(ACCOUNT)).unwrap();
        let text = fs::read_to_string(&path).unwrap();
        let edited = text.replace(
            "\\\"vaults\\\":{}",
            "\\\"vaults\\\":{\\\"x\\\":[\\\"reveal\\\"]}",
        );
        assert_ne!(edited, text);
        fs::write(&path, edited).unwrap();
        assert_eq!(load_policy(&path, &s, ACCOUNT), Err(PolicyError::Tampered));
        // Another key: refused too.
        save_policy(&path, &s, &Policy::default_for(ACCOUNT)).unwrap();
        let other = TestSigner([4; 32]);
        assert_eq!(
            load_policy(&path, &other, ACCOUNT),
            Err(PolicyError::Tampered)
        );
        fs::write(&path, "not json").unwrap();
        assert_eq!(load_policy(&path, &s, ACCOUNT), Err(PolicyError::Format));
        // A signed payload that is not a policy.
        fs::write(&path, seal_config(&s, POLICY_DOMAIN, "{\"x\":1}").unwrap()).unwrap();
        assert_eq!(load_policy(&path, &s, ACCOUNT), Err(PolicyError::Format));
        // A payload signed under another domain.
        let payload = serde_json::to_string(&sample()).unwrap();
        fs::write(&path, seal_config(&s, b"other", &payload).unwrap()).unwrap();
        assert_eq!(load_policy(&path, &s, ACCOUNT), Err(PolicyError::Tampered));
    }

    #[test]
    fn policy_of_other_account_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mcp-policy.json");
        let s = TestSigner([3; 32]);
        save_policy(&path, &s, &Policy::default_for("someone-else")).unwrap();
        assert_eq!(
            load_policy(&path, &s, ACCOUNT),
            Err(PolicyError::WrongAccount)
        );
    }

    #[test]
    fn save_does_not_follow_a_planted_temp_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mcp-policy.json");
        let victim = dir.path().join("victim");
        fs::write(&victim, "keep").unwrap();
        std::os::unix::fs::symlink(&victim, dir.path().join("mcp-policy.json.tmp")).unwrap();
        let s = TestSigner([3; 32]);
        save_policy(&path, &s, &sample()).unwrap();
        assert_eq!(fs::read_to_string(&victim).unwrap(), "keep");
        assert_eq!(load_policy(&path, &s, ACCOUNT).unwrap(), sample());
    }

    #[test]
    fn missing_policy_file_gives_default() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("absent.json");
        let s = TestSigner([3; 32]);
        assert_eq!(
            load_policy(&path, &s, ACCOUNT).unwrap(),
            Policy::default_for(ACCOUNT)
        );
        assert!(!path.exists());
    }

    #[test]
    fn scope_names() {
        for s in Scope::ALL {
            assert_eq!(s.as_str().parse::<Scope>().unwrap(), s);
            assert_eq!(
                serde_json::to_value(s).unwrap(),
                serde_json::Value::String(s.to_string())
            );
        }
        assert_eq!("Reveal".parse::<Scope>(), Err(PolicyError::Format));
    }
}
