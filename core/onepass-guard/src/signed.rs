//! Signed configuration envelope: `{"payload":"<text>","signature":"<base64>"}`.

use crate::{GuardError, LocalSigner};
use data_encoding::BASE64;
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    payload: String,
    signature: String,
}

/// Wraps `payload` in a signed envelope. The signature covers the payload
/// under `domain` (the signer binds the domain: `domain || 0x00 || payload`).
pub fn seal_config(
    signer: &dyn LocalSigner,
    domain: &[u8],
    payload: &str,
) -> Result<String, GuardError> {
    let sig = signer.sign(domain, payload.as_bytes())?;
    serde_json::to_string(&Envelope {
        payload: payload.to_owned(),
        signature: BASE64.encode(&sig),
    })
    .map_err(|_| GuardError::Format("envelope"))
}

/// Parses an envelope, verifies its signature under `domain` and returns the
/// payload. A bad signature, a different domain or an edited payload all give
/// [`GuardError::Signature`].
pub fn open_config(
    signer: &dyn LocalSigner,
    domain: &[u8],
    text: &str,
) -> Result<String, GuardError> {
    let env: Envelope = serde_json::from_str(text).map_err(|_| GuardError::Format("envelope"))?;
    let sig = BASE64
        .decode(env.signature.as_bytes())
        .map_err(|_| GuardError::Format("signature encoding"))?;
    signer.verify(domain, env.payload.as_bytes(), &sig)?;
    Ok(env.payload)
}

/// Writes `data` to `path` atomically with mode 0600: a fresh, randomly named
/// file created with O_EXCL in the same directory (a planted file or symlink
/// cannot redirect the write), synced, renamed over `path`, then the
/// directory synced.
pub(crate) fn write_private_atomic(path: &Path, data: &[u8]) -> Result<(), GuardError> {
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
    tmp.as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    tmp.write_all(data)?;
    tmp.as_file().sync_all()?;
    tmp.persist(path).map_err(|e| GuardError::from(e.error))?;
    File::open(dir)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TestSigner;

    #[test]
    fn config_roundtrip() {
        let s = TestSigner::new();
        let sealed = seal_config(&s, b"policy", "{\"a\":1}").unwrap();
        assert_eq!(open_config(&s, b"policy", &sealed).unwrap(), "{\"a\":1}");
    }

    #[test]
    fn config_tamper_refused() {
        let s = TestSigner::new();
        let sealed = seal_config(&s, b"policy", "{\"a\":1}").unwrap();

        let edited = sealed.replace("\\\"a\\\":1", "\\\"a\\\":2");
        assert_ne!(edited, sealed);
        assert_eq!(
            open_config(&s, b"policy", &edited),
            Err(GuardError::Signature)
        );

        let mut env: Envelope = serde_json::from_str(&sealed).unwrap();
        let mut sig = BASE64.decode(env.signature.as_bytes()).unwrap();
        sig[0] ^= 1;
        env.signature = BASE64.encode(&sig);
        let bad_sig = serde_json::to_string(&env).unwrap();
        assert_eq!(
            open_config(&s, b"policy", &bad_sig),
            Err(GuardError::Signature)
        );

        assert_eq!(
            open_config(&s, b"other", &sealed),
            Err(GuardError::Signature)
        );
        assert!(matches!(
            open_config(&s, b"policy", "not json"),
            Err(GuardError::Format(_))
        ));
    }
}
