//! Host configuration: a JSON file given by `--config`, else
//! `ONEPASS_NATIVE_HOST_CONFIG`, else `~/.onepass-dev/native-host.json`.

use std::fmt;
use std::path::{Path, PathBuf};

use serde::Deserialize;

/// A startup or setup failure. The message never holds a secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostError(pub String);

impl HostError {
    pub fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}

impl fmt::Display for HostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for HostError {}

/// Where the vault comes from.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Source {
    /// The development CLI data directory (`path`, default `data_dir`).
    Dev {
        #[serde(default)]
        path: Option<PathBuf>,
    },
    /// A JSON file of fictional items (debug builds only).
    Fixture { path: PathBuf },
}

/// How a pairing gets approved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Approval {
    /// Approve at once; the code is written to the log.
    Auto,
    /// Write `pending-pairing.json`, wait for `pairing-approved`.
    File,
}

/// Answer to a reprompt request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reprompt {
    #[default]
    Deny,
    Allow,
}

fn yes() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub data_dir: PathBuf,
    /// Bare Chrome extension ids and Firefox add-on ids.
    pub allowed_extensions: Vec<String>,
    pub source: Source,
    pub approval: Approval,
    #[serde(default = "yes")]
    pub unlocked: bool,
    #[serde(default)]
    pub reprompt: Reprompt,
}

fn home() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

/// `~/x` to `$HOME/x`.
fn expand(p: &Path) -> PathBuf {
    match (p.strip_prefix("~"), home()) {
        (Ok(rest), Some(h)) => h.join(rest),
        _ => p.to_path_buf(),
    }
}

impl Config {
    pub fn parse(bytes: &[u8]) -> Result<Config, HostError> {
        let mut c: Config = serde_json::from_slice(bytes)
            .map_err(|e| HostError::new(format!("invalid config: {e}")))?;
        c.data_dir = expand(&c.data_dir);
        c.source = match c.source {
            Source::Dev { path } => Source::Dev {
                path: path.map(|p| expand(&p)),
            },
            Source::Fixture { path } => Source::Fixture {
                path: expand(&path),
            },
        };
        Ok(c)
    }

    pub fn load(path: &Path) -> Result<Config, HostError> {
        let bytes = std::fs::read(path)
            .map_err(|e| HostError::new(format!("cannot read the config: {}", e.kind())))?;
        Self::parse(&bytes)
    }

    /// The config path: the explicit one, else the environment, else the
    /// default under the home directory.
    pub fn locate(explicit: Option<PathBuf>) -> Result<PathBuf, HostError> {
        if let Some(p) = explicit {
            return Ok(p);
        }
        if let Some(p) = std::env::var_os("ONEPASS_NATIVE_HOST_CONFIG") {
            return Ok(PathBuf::from(p));
        }
        home()
            .map(|h| h.join(".onepass-dev/native-host.json"))
            .ok_or_else(|| HostError::new("no config: HOME is not set"))
    }

    pub fn is_allowed(&self, extension_id: &str) -> bool {
        self.allowed_extensions.iter().any(|a| a == extension_id)
    }
}

/// The calling extension's id from the launch arguments. Chrome passes
/// its origin `chrome-extension://<id>/`; Firefox passes the manifest path
/// then the add-on id. Anything else gives `None`.
pub fn extension_id(positional: &[String]) -> Option<String> {
    let first = positional.first()?;
    if let Some(rest) = first.strip_prefix("chrome-extension://") {
        let id = rest.trim_end_matches('/');
        return (!id.is_empty() && !id.contains('/')).then(|| id.to_owned());
    }
    positional.get(1).filter(|s| !s.is_empty()).cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn chrome_origin_gives_bare_id() {
        assert_eq!(
            extension_id(&args(&["chrome-extension://abcdefgh/"])).as_deref(),
            Some("abcdefgh")
        );
        assert_eq!(extension_id(&args(&["chrome-extension:///"])), None);
        assert_eq!(extension_id(&args(&["chrome-extension://a/b/"])), None);
    }

    #[test]
    fn firefox_gives_addon_id() {
        assert_eq!(
            extension_id(&args(&[
                "/x/me.somalabs.onepass.dev.json",
                "onepass@somalabs.me"
            ]))
            .as_deref(),
            Some("onepass@somalabs.me")
        );
        assert_eq!(extension_id(&args(&["/x/manifest.json"])), None);
        assert_eq!(extension_id(&[]), None);
    }

    #[test]
    fn config_parses_with_defaults() {
        let c = Config::parse(
            br#"{"data_dir":"/tmp/x","allowed_extensions":["a"],
                "source":{"kind":"fixture","path":"/f.json"},"approval":"auto"}"#,
        )
        .unwrap();
        assert!(c.unlocked);
        assert_eq!(c.reprompt, Reprompt::Deny);
        assert_eq!(c.approval, Approval::Auto);
        assert!(c.is_allowed("a"));
        assert!(!c.is_allowed("b"));
        let d = Config::parse(
            br#"{"data_dir":"/tmp/x","allowed_extensions":[],"source":{"kind":"dev"},
                "approval":"file","unlocked":false,"reprompt":"allow"}"#,
        )
        .unwrap();
        assert_eq!(d.source, Source::Dev { path: None });
        assert_eq!(d.reprompt, Reprompt::Allow);
        assert!(Config::parse(br#"{"data_dir":"/x"}"#).is_err());
    }
}
