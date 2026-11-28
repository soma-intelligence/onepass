//! Windows Hello unlock, the counterpart of Face ID / Touch ID on the Apple
//! apps (VaultKit `BiometricUnlock`).
//!
//! What is kept: the Account Unlock Key (32 bytes, what `unlock_with_auk`
//! takes), in `hello.bin`, sealed by DPAPI for this Windows user with the
//! account id as extra entropy. It is released only after Windows Hello
//! (`UserConsentVerifier`, face, fingerprint or PIN) confirms the user at
//! this window. As on the Apple apps, the master password is asked again
//! every 14 days and after a restart: the file records when the password
//! was last typed and when Windows started, and is dropped when either rule
//! fails.
//!
//! Limit, stated plainly: DPAPI binds the key to the Windows account, not to
//! the Hello gesture. Code already running as this user could open the file
//! without Hello, which is the same exposure `device.bin` has (spec 6.3).
//! The Secure Enclave key of the Apple apps does not have that gap.

use std::fs;
use std::io::Write;
use std::path::Path;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::secrets::Sealer;
use crate::state::now;

const MAGIC: &[u8; 8] = b"OPHEL\x00\x00\x01";
const CONTEXT: &[u8] = b"onepass/desktop/hello/v1";
/// The master password is asked again after this long (Apple apps: 14 days).
pub const PASSWORD_EVERY_SECS: i64 = 14 * 86_400;
/// A clock set back by more than this drops the enrollment.
const CLOCK_SKEW_SECS: i64 = 300;
/// Two readings of the boot time closer than this are the same boot.
const BOOT_SLACK_SECS: i64 = 120;

#[derive(Serialize, Deserialize)]
struct Enrollment {
    account_id: String,
    auk: Zeroizing<Vec<u8>>,
    enrolled_at: i64,
    last_password_at: i64,
    boot_time: i64,
}

/// Why the master password is needed although Hello was set up.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Dropped {
    Expired,
    Rebooted,
    Invalidated,
}

impl Dropped {
    pub fn key(self) -> &'static str {
        match self {
            Dropped::Expired => "expired",
            Dropped::Rebooted => "rebooted",
            Dropped::Invalidated => "invalidated",
        }
    }
}

fn context(account_id: &str) -> Vec<u8> {
    let mut c = CONTEXT.to_vec();
    c.push(0);
    c.extend_from_slice(account_id.as_bytes());
    c
}

/// When Windows started, in Unix seconds (now minus the uptime).
pub fn boot_time() -> i64 {
    #[cfg(windows)]
    {
        // SAFETY: no argument; milliseconds since the system started.
        let up = unsafe { windows_sys::Win32::System::SystemInformation::GetTickCount64() };
        now() - i64::try_from(up / 1000).unwrap_or(0)
    }
    #[cfg(not(windows))]
    {
        0
    }
}

/// Seals and writes the AUK after a password unlock or a change of password.
pub fn enroll(
    sealer: &dyn Sealer,
    path: &Path,
    account_id: &str,
    auk: &[u8],
) -> Result<(), String> {
    if auk.len() != 32 {
        return Err("unlock key".into());
    }
    let t = now();
    let e = Enrollment {
        account_id: account_id.to_owned(),
        auk: Zeroizing::new(auk.to_vec()),
        enrolled_at: t,
        last_password_at: t,
        boot_time: boot_time(),
    };
    let plain = Zeroizing::new(postcard::to_allocvec(&e).map_err(|_| "encode")?);
    let sealed = sealer.seal(&plain, &context(account_id))?;
    let mut out = Vec::with_capacity(MAGIC.len() + 2 + account_id.len() + sealed.len());
    out.extend_from_slice(MAGIC);
    let id = account_id.as_bytes();
    out.extend_from_slice(
        &u16::try_from(id.len())
            .map_err(|_| "account id")?
            .to_le_bytes(),
    );
    out.extend_from_slice(id);
    out.extend_from_slice(&sealed);
    let tmp = path.with_extension("bin.tmp");
    {
        let mut f = fs::File::create(&tmp).map_err(|e| format!("write: {e}"))?;
        f.write_all(&out).map_err(|e| format!("write: {e}"))?;
        f.sync_all().map_err(|e| format!("write: {e}"))?;
    }
    fs::rename(&tmp, path).map_err(|e| format!("write: {e}"))
}

pub fn remove(path: &Path) {
    let _ = fs::remove_file(path);
}

pub fn is_enrolled(path: &Path) -> bool {
    path.exists()
}

/// Days left before the master password is asked again, if enrolled.
pub fn days_left(sealer: &dyn Sealer, path: &Path) -> Option<i64> {
    let e = read(sealer, path).ok()??;
    Some(((e.last_password_at + PASSWORD_EVERY_SECS - now() + 86_399) / 86_400).max(0))
}

fn read(sealer: &dyn Sealer, path: &Path) -> Result<Option<Enrollment>, String> {
    let bytes = match fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("read: {e}")),
    };
    let rest = bytes.strip_prefix(MAGIC.as_slice()).ok_or("hello file")?;
    let (len, rest) = rest.split_at_checked(2).ok_or("hello file")?;
    let len = usize::from(u16::from_le_bytes([len[0], len[1]]));
    let (id, sealed) = rest.split_at_checked(len).ok_or("hello file")?;
    let id = std::str::from_utf8(id).map_err(|_| "hello file")?;
    let plain = sealer.open(sealed, &context(id))?;
    let e: Enrollment = postcard::from_bytes(&plain).map_err(|_| "hello file")?;
    if e.account_id != id {
        return Err("hello file".into());
    }
    Ok(Some(e))
}

/// The AUK, if the enrollment is still good. A stale one is deleted and the
/// reason returned; a corrupt one is deleted too.
pub fn take_auk(
    sealer: &dyn Sealer,
    path: &Path,
    account_id: &str,
) -> Result<Zeroizing<Vec<u8>>, Option<Dropped>> {
    let e = match read(sealer, path) {
        Ok(Some(e)) => e,
        Ok(None) => return Err(None),
        Err(_) => {
            remove(path);
            return Err(Some(Dropped::Invalidated));
        }
    };
    let t = now();
    let reason = if e.account_id != account_id {
        Some(Dropped::Invalidated)
    } else if (e.boot_time - boot_time()).abs() > BOOT_SLACK_SECS {
        Some(Dropped::Rebooted)
    } else if t - e.last_password_at > PASSWORD_EVERY_SECS
        || t + CLOCK_SKEW_SECS < e.last_password_at
    {
        Some(Dropped::Expired)
    } else {
        None
    };
    if let Some(r) = reason {
        remove(path);
        return Err(Some(r));
    }
    Ok(e.auk)
}

/// Is Windows Hello set up on this PC (a face, a fingerprint or a PIN)?
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Availability {
    Available,
    NotConfigured,
    Unavailable,
}

/// What Windows Hello answered.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Verdict {
    Verified,
    Canceled,
    Failed,
}

/// Debug builds only: ONEPASS_E2E_HELLO=verified|canceled stands in for
/// Windows Hello in the end-to-end test.
fn e2e_hello() -> Option<Verdict> {
    #[cfg(debug_assertions)]
    if let Ok(v) = std::env::var("ONEPASS_E2E_HELLO") {
        return Some(match v.as_str() {
            "verified" => Verdict::Verified,
            "canceled" => Verdict::Canceled,
            _ => Verdict::Failed,
        });
    }
    None
}

#[cfg(windows)]
fn winrt_init() {
    use windows::Win32::System::WinRT::{RO_INIT_MULTITHREADED, RoInitialize};
    // SAFETY: initializes WinRT on this worker thread; an already
    // initialized thread returns an error that changes nothing.
    let _ = unsafe { RoInitialize(RO_INIT_MULTITHREADED) };
}

/// Blocking: call off the event loop's thread.
pub fn availability() -> Availability {
    if e2e_hello().is_some() {
        return Availability::Available;
    }
    #[cfg(windows)]
    {
        use windows::Security::Credentials::UI::{
            UserConsentVerifier, UserConsentVerifierAvailability as A,
        };
        winrt_init();
        match UserConsentVerifier::CheckAvailabilityAsync().and_then(|op| op.join()) {
            Ok(A::Available) => Availability::Available,
            Ok(A::DeviceNotPresent | A::NotConfiguredForUser) => Availability::NotConfigured,
            _ => Availability::Unavailable,
        }
    }
    #[cfg(not(windows))]
    {
        Availability::Unavailable
    }
}

/// Asks Windows Hello to confirm the user, its dialog over `hwnd`.
/// Blocking: call off the event loop's thread.
pub fn verify(hwnd: isize, message: &str) -> Verdict {
    if let Some(v) = e2e_hello() {
        return v;
    }
    #[cfg(windows)]
    {
        use windows::Security::Credentials::UI::{
            UserConsentVerificationResult as R, UserConsentVerifier,
        };
        use windows::Win32::Foundation::HWND;
        use windows::Win32::System::WinRT::IUserConsentVerifierInterop;
        use windows::core::{HSTRING, factory};
        winrt_init();
        let run = || -> windows::core::Result<R> {
            let interop = factory::<UserConsentVerifier, IUserConsentVerifierInterop>()?;
            // SAFETY: `hwnd` is the app's live main window; the message is
            // an HSTRING that outlives the call.
            let op: windows_future::IAsyncOperation<R> = unsafe {
                interop.RequestVerificationForWindowAsync(
                    HWND(hwnd as *mut core::ffi::c_void),
                    &HSTRING::from(message),
                )
            }?;
            op.join()
        };
        match run() {
            Ok(R::Verified) => Verdict::Verified,
            Ok(R::Canceled) => Verdict::Canceled,
            _ => Verdict::Failed,
        }
    }
    #[cfg(not(windows))]
    {
        let _ = (hwnd, message);
        Verdict::Failed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Plain;
    impl Sealer for Plain {
        fn name(&self) -> &'static str {
            "test"
        }
        fn seal(&self, plain: &[u8], context: &[u8]) -> Result<Vec<u8>, String> {
            Ok([context, plain].concat())
        }
        fn open(&self, sealed: &[u8], context: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
            sealed
                .strip_prefix(context)
                .map(|p| Zeroizing::new(p.to_vec()))
                .ok_or_else(|| "context".into())
        }
    }

    /// Asks this PC for real (no dialog): `cargo test -- --ignored`.
    #[test]
    #[ignore]
    fn windows_answers_the_availability_check() {
        let a = availability();
        println!(
            "Windows Hello: {}",
            match a {
                Availability::Available => "available",
                Availability::NotConfigured => "not configured",
                Availability::Unavailable => "unavailable",
            }
        );
    }

    #[test]
    fn the_unlock_key_comes_back_for_its_account_only() {
        let dir = std::env::temp_dir().join(format!("onepass-hello-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("hello.bin");
        enroll(&Plain, &path, "acct", &[7u8; 32]).unwrap();
        assert!(is_enrolled(&path));
        assert_eq!(days_left(&Plain, &path), Some(14));
        assert_eq!(
            take_auk(&Plain, &path, "acct").unwrap().as_slice(),
            &[7u8; 32]
        );
        assert_eq!(
            take_auk(&Plain, &path, "other").err(),
            Some(Some(Dropped::Invalidated))
        );
        assert!(!is_enrolled(&path), "a mismatch drops the enrollment");
        assert!(enroll(&Plain, &path, "acct", &[1u8; 16]).is_err());
        let _ = fs::remove_dir_all(dir);
    }
}
