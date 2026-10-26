//! Security.framework and kernel code-signing calls: the code identity of a
//! running process or of an executable file.
//!
//! A running process is pinned by the kernel's view of its image: the code
//! directory hash (cdhash) the kernel recorded at exec, read with `csops`
//! (by pid) or `csops_audittoken` (by audit token). Nothing about a running
//! process is ever read back from its file, which a same-uid attacker can
//! rename over after exec. Its signature is then checked with
//! `SecCodeCheckValidity` against requirements that include that cdhash
//! (`anchor apple and cdhash H"..."`, then `anchor apple generic and ...`),
//! so a platform or team identity holds only for the very image running,
//! and the identifier and team read from `SecCodeCopySigningInformation`
//! (declared here, `security-framework` does not bind it) are checked again
//! by a requirement that names them exactly.
#![allow(unsafe_code)]

use std::path::{Path, PathBuf};
use std::str::FromStr;

use core_foundation::base::{CFType, TCFType};
use core_foundation::data::CFData;
use core_foundation::dictionary::CFDictionary;
use core_foundation::number::CFNumber;
use core_foundation::string::CFString;
use core_foundation::url::CFURL;
use core_foundation_sys::base::OSStatus;
use core_foundation_sys::dictionary::CFDictionaryRef;
use core_foundation_sys::string::CFStringRef;
use security_framework::os::macos::code_signing::{
    Flags, GuestAttributes, SecCode, SecRequirement, SecStaticCode,
};
use security_framework_sys::code_signing::{SecCSFlags, SecStaticCodeRef};

use crate::code::{CodeIdentity, PeerError};

/// `kSecCSSigningInformation`: include the certificate-derived fields, of
/// which the team identifier, in the signing information.
const SIGNING_INFORMATION: SecCSFlags = 1 << 1;
/// `errSecCSNoSuchCode`: no running code matches the guest attributes.
const NO_SUCH_CODE: OSStatus = -67065;
/// `kPOSIXErrorBase + ESRCH`: what a lookup by pid of an exited process
/// returns.
const POSIX_NO_SUCH_PROCESS: OSStatus = 100_000 + libc::ESRCH;
/// `CS_OPS_STATUS` and `CS_OPS_CDHASH` of `<sys/codesign.h>`.
const CS_OPS_STATUS: libc::c_uint = 0;
const CS_OPS_CDHASH: libc::c_uint = 5;
/// `CS_VALID`: the kernel still holds the running image for valid.
const CS_VALID: u32 = 0x1;
/// `CS_RUNTIME`: the hardened runtime is on (same bit in the code directory
/// flags, `kSecCodeSignatureRuntime`).
const CS_RUNTIME: u32 = 0x1_0000;
/// `CS_DEBUGGED`: the process was debugged and may run code that is not
/// its own.
const CS_DEBUGGED: u32 = 0x1000_0000;
/// `CS_CDHASH_LEN`: a cdhash is 20 bytes (truncated SHA-256 or SHA-1).
const CDHASH_LEN: usize = 20;

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    /// Returns, under the create rule, a dictionary describing the signature
    /// of `code` (a static code, or a dynamic code standing for its static
    /// code, as the documentation allows).
    fn SecCodeCopySigningInformation(
        code: SecStaticCodeRef,
        flags: SecCSFlags,
        information: *mut CFDictionaryRef,
    ) -> OSStatus;
    static kSecCodeInfoIdentifier: CFStringRef;
    static kSecCodeInfoTeamIdentifier: CFStringRef;
    static kSecCodeInfoUnique: CFStringRef;
    static kSecCodeInfoFlags: CFStringRef;
}

// System calls of libsystem_kernel (`<sys/codesign.h>`), stable since
// macOS 10.5 (`csops`) and 10.12 (`csops_audittoken`); libc does not bind
// them.
unsafe extern "C" {
    fn csops(
        pid: libc::pid_t,
        ops: libc::c_uint,
        useraddr: *mut libc::c_void,
        usersize: libc::size_t,
    ) -> libc::c_int;
    fn csops_audittoken(
        pid: libc::pid_t,
        ops: libc::c_uint,
        useraddr: *mut libc::c_void,
        usersize: libc::size_t,
        token: *const [u32; 8],
    ) -> libc::c_int;
}

/// Which process to look up.
#[derive(Clone, Copy)]
pub(crate) enum Guest {
    Pid(i32),
    /// The audit token, with the pid it names (checked by the kernel).
    AuditToken([u8; 32], i32),
}

/// Kernel code-signing operation `ops` on `guest`, into `out`.
fn kernel_csops(guest: Guest, ops: libc::c_uint, out: &mut [u8]) -> Result<(), PeerError> {
    let rc = match guest {
        // SAFETY: `out` is a writable buffer of exactly the size passed; the
        // kernel writes at most that many bytes (and fails with ERANGE when
        // the size does not fit the operation).
        Guest::Pid(pid) => unsafe { csops(pid, ops, out.as_mut_ptr().cast(), out.len()) },
        Guest::AuditToken(token, pid) => {
            let mut words = [0u32; 8];
            for (w, chunk) in words.iter_mut().zip(token.as_chunks::<4>().0) {
                *w = u32::from_ne_bytes(*chunk);
            }
            // SAFETY: as above for `out`; `words` is a live, properly aligned
            // audit_token_t (eight u32) that the kernel only reads.
            unsafe { csops_audittoken(pid, ops, out.as_mut_ptr().cast(), out.len(), &words) }
        }
    };
    if rc == 0 {
        return Ok(());
    }
    match std::io::Error::last_os_error().raw_os_error() {
        Some(libc::ESRCH) => Err(PeerError::Gone),
        // The kernel has no signature blob for the image: unsigned code
        // (Intel only).
        Some(libc::EBADEXEC) if ops == CS_OPS_CDHASH => Err(PeerError::Unreadable("unsigned code")),
        _ => Err(PeerError::Unreadable("code signature unreadable")),
    }
}

/// The kernel's cdhash of the image `guest` runs and its code-signing
/// status flags, refused unless the kernel still holds that image for valid.
fn kernel_cdhash(guest: Guest) -> Result<(String, u32), PeerError> {
    // Code without any signature (Intel only) has no cdhash: refused.
    let mut cdhash = [0u8; CDHASH_LEN];
    kernel_csops(guest, CS_OPS_CDHASH, &mut cdhash)?;
    let mut status = [0u8; 4];
    kernel_csops(guest, CS_OPS_STATUS, &mut status)?;
    let status = u32::from_ne_bytes(status);
    if status & CS_VALID == 0 {
        return Err(PeerError::Unreadable("invalid code signature"));
    }
    Ok((data_encoding::HEXLOWER.encode(&cdhash), status))
}

/// Code identity of the running process `guest`, and the path of its
/// executable as the code-signing system sees it (informative only).
pub(crate) fn identify_running(guest: Guest) -> Result<(CodeIdentity, Option<PathBuf>), PeerError> {
    let mut attrs = GuestAttributes::new();
    match guest {
        Guest::Pid(pid) => attrs.set_pid(pid),
        Guest::AuditToken(token, _) => {
            let data = CFData::from_buffer(&token);
            // The attribute dictionary retains `data`, which may then drop.
            attrs.set_audit_token(data.as_concrete_TypeRef());
        }
    }
    let code = SecCode::copy_guest_with_attribues(None, &attrs, Flags::NONE).map_err(|e| {
        if e.code() == NO_SUCH_CODE || e.code() == POSIX_NO_SUCH_PROCESS {
            PeerError::Gone
        } else {
            PeerError::Unreadable("code lookup")
        }
    })?;
    let (cdhash, status) = kernel_cdhash(guest)?;
    let path = code.path(Flags::NONE).ok().and_then(|url| url.to_path());
    let check = |req: &SecRequirement| code.check_validity(Flags::NONE, req).is_ok();
    let info = || signing_info(code.as_concrete_TypeRef().cast());
    let identity = classify(&cdhash, check, info)?;
    let identity = match identity {
        Some(signed) => signed,
        // An ad hoc pin trusts the code the kernel loaded; a debugged
        // process may run other code under the same cdhash.
        None if status & CS_DEBUGGED != 0 => {
            return Err(PeerError::Unreadable("debugged or injectable code"));
        }
        None => CodeIdentity::AdHoc {
            path: path.clone().unwrap_or_default(),
            cdhash,
            hardened: status & CS_RUNTIME != 0,
        },
    };
    Ok((identity, path))
}

/// Code identity of the executable file at `path`, for an explicit pairing:
/// the same identity a process running it unmodified has.
pub(crate) fn identify_file(path: &Path) -> Result<CodeIdentity, PeerError> {
    let url = CFURL::from_path(path, false).ok_or(PeerError::Unreadable("executable path"))?;
    let code = SecStaticCode::from_path(&url, Flags::NONE)
        .map_err(|_| PeerError::Unreadable("executable file"))?;
    let info = signing_info(code.as_concrete_TypeRef())?;
    let cdhash = info.cdhash.ok_or(PeerError::Unreadable("unsigned code"))?;
    let hardened = info.flags & CS_RUNTIME != 0;
    let check = |req: &SecRequirement| code.check_validity(Flags::NONE, req).is_ok();
    // A static check validates every page against the code directory: a
    // file modified in place fails here instead of passing for its cdhash.
    if !check(&requirement(&format!("cdhash H\"{cdhash}\""))?) {
        return Err(PeerError::Unreadable("invalid code signature"));
    }
    let identity = classify(&cdhash, check, || signing_info(code.as_concrete_TypeRef()))?;
    Ok(identity.unwrap_or(CodeIdentity::AdHoc {
        path: path.to_path_buf(),
        cdhash,
        hardened,
    }))
}

/// Platform or team identity of the code whose cdhash is `cdhash`, or
/// `None` for ad hoc code. Every requirement names the cdhash, and the
/// identity reported is checked by a requirement naming it exactly.
fn classify(
    cdhash: &str,
    check: impl Fn(&SecRequirement) -> bool,
    info: impl Fn() -> Result<SigningInfo, PeerError>,
) -> Result<Option<CodeIdentity>, PeerError> {
    let pin = format!("cdhash H\"{cdhash}\"");
    if check(&requirement(&format!("anchor apple and {pin}"))?) {
        let identifier = info()?
            .identifier
            .ok_or(PeerError::Unreadable("identifier"))?;
        let exact = format!(
            "anchor apple and identifier {} and {pin}",
            quoted(&identifier)?
        );
        if !check(&requirement(&exact)?) {
            return Err(PeerError::Unreadable("identifier mismatch"));
        }
        return Ok(Some(CodeIdentity::Platform { identifier }));
    }
    if check(&requirement(&format!("anchor apple generic and {pin}"))?) {
        let info = info()?;
        if let (Some(identifier), Some(team_id)) = (info.identifier, info.team_id) {
            let exact = format!(
                "anchor apple generic and identifier {} and certificate leaf[subject.OU] = {} and {pin}",
                quoted(&identifier)?,
                quoted(&team_id)?
            );
            if !check(&requirement(&exact)?) {
                return Err(PeerError::Unreadable("team mismatch"));
            }
            return Ok(Some(CodeIdentity::Team {
                team_id,
                identifier,
            }));
        }
    }
    Ok(None)
}

fn requirement(text: &str) -> Result<SecRequirement, PeerError> {
    SecRequirement::from_str(text).map_err(|_| PeerError::Unreadable("requirement"))
}

/// `s` as a requirement-language string literal. Values holding a quote,
/// a backslash or a control character are refused rather than escaped.
fn quoted(s: &str) -> Result<String, PeerError> {
    if s.chars().any(|c| c == '"' || c == '\\' || c.is_control()) {
        return Err(PeerError::Unreadable("unusual identifier"));
    }
    Ok(format!("\"{s}\""))
}

struct SigningInfo {
    identifier: Option<String>,
    team_id: Option<String>,
    /// Hex cdhash of the static code (`kSecCodeInfoUnique`).
    cdhash: Option<String>,
    /// Code directory flags (`kSecCodeInfoFlags`), 0 when absent.
    flags: u32,
}

/// Identifier, team identifier and cdhash from the signing information of
/// `code` (a static code, or a dynamic code standing for one).
fn signing_info(code: SecStaticCodeRef) -> Result<SigningInfo, PeerError> {
    let mut info: CFDictionaryRef = std::ptr::null();
    // SAFETY: `code` is a live SecStaticCode or SecCode owned by the caller
    // for the duration of the call (the documentation accepts either);
    // `info` is a writable out-pointer that the call sets to a dictionary we
    // own (create rule) when it succeeds.
    let status = unsafe { SecCodeCopySigningInformation(code, SIGNING_INFORMATION, &mut info) };
    if status != 0 || info.is_null() {
        return Err(PeerError::Unreadable("signing information"));
    }
    // SAFETY: `info` is a non-null CFDictionary returned under the create
    // rule: wrapping it takes over that one reference, released on drop.
    let info: CFDictionary<CFString, CFType> =
        unsafe { CFDictionary::wrap_under_create_rule(info) };
    let value = |key: CFStringRef| {
        // SAFETY: the kSecCodeInfo* keys are constant CFStrings exported by
        // Security.framework, valid for the life of the process; the get
        // rule adds the reference the wrapper releases.
        let key = unsafe { CFString::wrap_under_get_rule(key) };
        info.find(&key).map(|v| v.clone())
    };
    let string = |key| {
        value(key)
            .and_then(|v| v.downcast::<CFString>())
            .map(|s| s.to_string())
            .filter(|s| !s.is_empty())
    };
    // SAFETY: reading extern statics exported by the linked framework.
    let (id_key, team_key, unique_key, flags_key) = unsafe {
        (
            kSecCodeInfoIdentifier,
            kSecCodeInfoTeamIdentifier,
            kSecCodeInfoUnique,
            kSecCodeInfoFlags,
        )
    };
    let cdhash = value(unique_key)
        .and_then(|v| v.downcast::<CFData>())
        .filter(|d| d.len() == CDHASH_LEN as isize)
        .map(|d| data_encoding::HEXLOWER.encode(d.bytes()));
    Ok(SigningInfo {
        identifier: string(id_key),
        team_id: string(team_key),
        cdhash,
        flags: value(flags_key)
            .and_then(|v| v.downcast::<CFNumber>())
            .and_then(|n| n.to_i64())
            .and_then(|n| u32::try_from(n).ok())
            .unwrap_or(0),
    })
}
