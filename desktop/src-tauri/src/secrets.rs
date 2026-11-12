//! What this device keeps besides the vault database (spec 2026-10-30
//! section 6.1): the Secret Key, the device keys (classical bytes and the
//! software post-quantum half) and the seed of the hedged random source.
//!
//! They live in one file, `device.bin`, sealed by the OS:
//!
//! - Windows: DPAPI for the current user (`CryptProtectData`, no UI), with
//!   the account id as extra entropy. This is the documented fallback of
//!   section 6.3; the TPM key of the Microsoft Platform Crypto Provider that
//!   wraps a file key comes next and slots in behind [`Sealer`].
//! - Other systems: refused until the Linux Secret Service / TPM2 sealer
//!   lands (section 6.4). The app never writes these secrets in clear.
//!
//! Nothing here is ever logged or sent over the IPC.

use std::fmt;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// The device's secrets, in memory only while the app needs them.
#[derive(Serialize, Deserialize)]
pub struct DeviceSecrets {
    pub account_id: String,
    pub secret_key: Zeroizing<String>,
    pub classical: Zeroizing<Vec<u8>>,
    pub pq: Zeroizing<Vec<u8>>,
    pub rng_seed: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for DeviceSecrets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceSecrets")
            .field("account_id", &self.account_id)
            .finish_non_exhaustive()
    }
}

/// Seals and opens a blob with a key the OS holds for this user.
pub trait Sealer: Send + Sync {
    /// Shown in Settings > Security (spec 6.3: the weaker fallback is shown).
    fn name(&self) -> &'static str;
    fn seal(&self, plain: &[u8], context: &[u8]) -> Result<Vec<u8>, String>;
    fn open(&self, sealed: &[u8], context: &[u8]) -> Result<Zeroizing<Vec<u8>>, String>;
}

/// File header: magic and format version.
const MAGIC: &[u8; 8] = b"OPDSK\x00\x00\x01";
const CONTEXT: &[u8] = b"onepass/desktop/device/v1";

pub fn sealer() -> Box<dyn Sealer> {
    #[cfg(windows)]
    {
        Box::new(windows::Dpapi)
    }
    #[cfg(not(windows))]
    {
        Box::new(Unsupported)
    }
}

fn context(account_id: &str) -> Vec<u8> {
    let mut c = CONTEXT.to_vec();
    c.push(0);
    c.extend_from_slice(account_id.as_bytes());
    c
}

/// Seal and write `secrets` to `path`, replacing it atomically.
pub fn save(sealer: &dyn Sealer, path: &Path, secrets: &DeviceSecrets) -> Result<(), String> {
    let plain = Zeroizing::new(postcard::to_allocvec(secrets).map_err(|_| "encode")?);
    let sealed = sealer.seal(&plain, &context(&secrets.account_id))?;
    let mut out = Vec::with_capacity(MAGIC.len() + 2 + secrets.account_id.len() + sealed.len());
    out.extend_from_slice(MAGIC);
    // The account id in clear: it selects the DPAPI entropy before opening.
    let id = secrets.account_id.as_bytes();
    let len = u16::try_from(id.len()).map_err(|_| "account id")?;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(id);
    out.extend_from_slice(&sealed);
    let tmp: PathBuf = path.with_extension("bin.tmp");
    {
        let mut f = fs::File::create(&tmp).map_err(|e| format!("write: {e}"))?;
        f.write_all(&out).map_err(|e| format!("write: {e}"))?;
        f.sync_all().map_err(|e| format!("write: {e}"))?;
    }
    fs::rename(&tmp, path).map_err(|e| format!("write: {e}"))
}

/// Read and open `path`. `Ok(None)` when there is no file.
pub fn load(sealer: &dyn Sealer, path: &Path) -> Result<Option<DeviceSecrets>, String> {
    let bytes = match fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("read: {e}")),
    };
    let rest = bytes.strip_prefix(MAGIC.as_slice()).ok_or("device file format")?;
    let (len, rest) = rest.split_at_checked(2).ok_or("device file format")?;
    let len = usize::from(u16::from_le_bytes([len[0], len[1]]));
    let (id, sealed) = rest.split_at_checked(len).ok_or("device file format")?;
    let id = std::str::from_utf8(id).map_err(|_| "device file format")?;
    let plain = sealer.open(sealed, &context(id))?;
    let secrets: DeviceSecrets = postcard::from_bytes(&plain).map_err(|_| "device file format")?;
    if secrets.account_id != id {
        return Err("device file format".into());
    }
    Ok(Some(secrets))
}

#[cfg(not(windows))]
struct Unsupported;

#[cfg(not(windows))]
impl Sealer for Unsupported {
    fn name(&self) -> &'static str {
        "none"
    }
    fn seal(&self, _: &[u8], _: &[u8]) -> Result<Vec<u8>, String> {
        Err("no secret store on this system yet".into())
    }
    fn open(&self, _: &[u8], _: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
        Err("no secret store on this system yet".into())
    }
}

#[cfg(windows)]
mod windows {
    #![allow(unsafe_code)]

    use std::ptr;

    use windows_sys::Win32::Foundation::{HLOCAL, LocalFree};
    use windows_sys::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
    };
    use zeroize::Zeroizing;

    use super::Sealer;

    /// DPAPI, current user (section 6.3 fallback).
    pub struct Dpapi;

    fn blob(data: &[u8]) -> Result<CRYPT_INTEGER_BLOB, String> {
        Ok(CRYPT_INTEGER_BLOB {
            cbData: u32::try_from(data.len()).map_err(|_| "too large")?,
            pbData: data.as_ptr().cast_mut(),
        })
    }

    /// Copies the output blob DPAPI allocated, wipes and frees it.
    ///
    /// # Safety
    /// `out` must be a blob DPAPI filled on success.
    unsafe fn take(out: CRYPT_INTEGER_BLOB) -> Zeroizing<Vec<u8>> {
        let len = out.cbData as usize;
        // SAFETY: DPAPI returned `len` readable bytes at `pbData`.
        let bytes = unsafe { std::slice::from_raw_parts_mut(out.pbData, len) };
        let copy = Zeroizing::new(bytes.to_vec());
        zeroize::Zeroize::zeroize(bytes);
        // SAFETY: the buffer was allocated by DPAPI with LocalAlloc.
        unsafe { LocalFree(out.pbData as HLOCAL) };
        copy
    }

    impl Sealer for Dpapi {
        fn name(&self) -> &'static str {
            "dpapi"
        }

        fn seal(&self, plain: &[u8], context: &[u8]) -> Result<Vec<u8>, String> {
            let input = blob(plain)?;
            let entropy = blob(context)?;
            let mut out = CRYPT_INTEGER_BLOB {
                cbData: 0,
                pbData: ptr::null_mut(),
            };
            // SAFETY: every pointer refers to a live blob for the call.
            let ok = unsafe {
                CryptProtectData(
                    &input,
                    ptr::null(),
                    &entropy,
                    ptr::null(),
                    ptr::null(),
                    CRYPTPROTECT_UI_FORBIDDEN,
                    &mut out,
                )
            };
            if ok == 0 {
                return Err(format!("DPAPI seal failed ({})", std::io::Error::last_os_error()));
            }
            // SAFETY: success, so `out` is DPAPI's.
            Ok(unsafe { take(out) }.to_vec())
        }

        fn open(&self, sealed: &[u8], context: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
            let input = blob(sealed)?;
            let entropy = blob(context)?;
            let mut out = CRYPT_INTEGER_BLOB {
                cbData: 0,
                pbData: ptr::null_mut(),
            };
            // SAFETY: as in `seal`.
            let ok = unsafe {
                CryptUnprotectData(
                    &input,
                    ptr::null_mut(),
                    &entropy,
                    ptr::null(),
                    ptr::null(),
                    CRYPTPROTECT_UI_FORBIDDEN,
                    &mut out,
                )
            };
            if ok == 0 {
                return Err("this device file belongs to another Windows user or machine".into());
            }
            // SAFETY: success, so `out` is DPAPI's.
            Ok(unsafe { take(out) })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A sealer that only flips bits, to test the file format anywhere.
    struct Xor;
    impl Sealer for Xor {
        fn name(&self) -> &'static str {
            "test"
        }
        fn seal(&self, p: &[u8], c: &[u8]) -> Result<Vec<u8>, String> {
            Ok(p.iter().zip(c.iter().cycle()).map(|(a, b)| a ^ b).collect())
        }
        fn open(&self, s: &[u8], c: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
            Ok(Zeroizing::new(self.seal(s, c)?))
        }
    }

    fn sample() -> DeviceSecrets {
        DeviceSecrets {
            account_id: "00112233445566778899aabbccddeeff".into(),
            secret_key: Zeroizing::new("A3-ABCDEF".into()),
            classical: Zeroizing::new(vec![1; 65]),
            pq: Zeroizing::new(vec![2; 40]),
            rng_seed: Zeroizing::new(vec![3; 32]),
        }
    }

    #[test]
    fn round_trip_and_missing_file() {
        let dir = std::env::temp_dir().join(format!("onepass-desktop-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("device.bin");
        assert!(load(&Xor, &path).unwrap().is_none());
        save(&Xor, &path, &sample()).unwrap();
        let back = load(&Xor, &path).unwrap().unwrap();
        assert_eq!(back.account_id, sample().account_id);
        assert_eq!(*back.secret_key, *sample().secret_key);
        assert_eq!(*back.pq, *sample().pq);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn truncated_file_is_refused() {
        let dir = std::env::temp_dir().join(format!("onepass-desktop-trunc-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("device.bin");
        fs::write(&path, b"OPDSK\x00\x00\x01\x20").unwrap();
        assert!(load(&Xor, &path).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn dpapi_round_trip() {
        let s = sealer();
        let sealed = s.seal(b"secret", b"ctx").unwrap();
        assert_ne!(sealed, b"secret");
        assert_eq!(&*s.open(&sealed, b"ctx").unwrap(), b"secret");
        assert!(s.open(&sealed, b"other").is_err());
    }
}
