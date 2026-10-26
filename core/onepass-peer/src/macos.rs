//! Security.framework calls: the code-signing identity of a running process.
//!
//! The process is looked up by audit token (socket peers) or by pid
//! (`SecCodeCopyGuestWithAttributes`), checked against the requirements
//! `anchor apple` then `anchor apple generic` (`SecCodeCheckValidity`), and
//! its identifier and team read with `SecCodeCopySigningInformation`, which
//! `security-framework` does not bind: it is declared here.
#![allow(unsafe_code)]

use std::path::PathBuf;
use std::str::FromStr;

use core_foundation::base::{CFType, TCFType};
use core_foundation::data::CFData;
use core_foundation::dictionary::CFDictionary;
use core_foundation::string::CFString;
use core_foundation_sys::base::OSStatus;
use core_foundation_sys::dictionary::CFDictionaryRef;
use core_foundation_sys::string::CFStringRef;
use security_framework::os::macos::code_signing::{
    Flags, GuestAttributes, SecCode, SecRequirement,
};
use security_framework_sys::code_signing::{SecCSFlags, SecStaticCodeRef};

use crate::code::PeerError;

/// `kSecCSSigningInformation`: include the certificate-derived fields, of
/// which the team identifier, in the signing information.
const SIGNING_INFORMATION: SecCSFlags = 1 << 1;
/// `errSecCSNoSuchCode`: no running code matches the guest attributes.
const NO_SUCH_CODE: OSStatus = -67065;
/// `kPOSIXErrorBase + ESRCH`: what a lookup by pid of an exited process
/// returns.
const POSIX_NO_SUCH_PROCESS: OSStatus = 100_000 + libc::ESRCH;

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
}

/// Which process to look up.
pub(crate) enum Guest {
    Pid(i32),
    AuditToken([u8; 32]),
}

/// What the signature of a running process says.
pub(crate) enum Signature {
    /// Satisfies `anchor apple`.
    Platform { identifier: String },
    /// Satisfies `anchor apple generic` and names a team.
    Team { team_id: String, identifier: String },
    /// Anything else: unsigned, ad hoc, invalid or modified on disk.
    Unsigned,
}

/// The signature of the running code of `guest`, and the path of its
/// executable as the code-signing system sees it.
pub(crate) fn signature_of(guest: Guest) -> Result<(Signature, Option<PathBuf>), PeerError> {
    let mut attrs = GuestAttributes::new();
    match guest {
        Guest::Pid(pid) => attrs.set_pid(pid),
        Guest::AuditToken(token) => {
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
    let path = code.path(Flags::NONE).ok().and_then(|url| url.to_path());

    let requirement = |text: &str| {
        SecRequirement::from_str(text).map_err(|_| PeerError::Unreadable("requirement"))
    };
    let satisfies = |text: &str| -> Result<bool, PeerError> {
        Ok(code
            .check_validity(Flags::NONE, &requirement(text)?)
            .is_ok())
    };
    let signature = if satisfies("anchor apple")? {
        match signing_info(&code)? {
            (Some(identifier), _) => Signature::Platform { identifier },
            (None, _) => Signature::Unsigned,
        }
    } else if satisfies("anchor apple generic")? {
        match signing_info(&code)? {
            (Some(identifier), Some(team_id)) => Signature::Team {
                team_id,
                identifier,
            },
            _ => Signature::Unsigned,
        }
    } else {
        Signature::Unsigned
    };
    Ok((signature, path))
}

/// Identifier and team identifier from the signing information of `code`.
fn signing_info(code: &SecCode) -> Result<(Option<String>, Option<String>), PeerError> {
    let mut info: CFDictionaryRef = std::ptr::null();
    // SAFETY: `code` is a live SecCode, which the documentation accepts in
    // place of a SecStaticCode; `info` is a writable out-pointer that the
    // call sets to a dictionary we own (create rule) when it succeeds.
    let status = unsafe {
        SecCodeCopySigningInformation(
            code.as_concrete_TypeRef().cast(),
            SIGNING_INFORMATION,
            &mut info,
        )
    };
    if status != 0 || info.is_null() {
        return Err(PeerError::Unreadable("signing information"));
    }
    // SAFETY: `info` is a non-null CFDictionary returned under the create
    // rule: wrapping it takes over that one reference, released on drop.
    let info: CFDictionary<CFString, CFType> =
        unsafe { CFDictionary::wrap_under_create_rule(info) };
    let string = |key: CFStringRef| {
        // SAFETY: the kSecCodeInfo* keys are constant CFStrings exported by
        // Security.framework, valid for the life of the process; the get
        // rule adds the reference the wrapper releases.
        let key = unsafe { CFString::wrap_under_get_rule(key) };
        info.find(&key)
            .and_then(|v| v.downcast::<CFString>())
            .map(|s| s.to_string())
            .filter(|s| !s.is_empty())
    };
    // SAFETY: reading extern statics exported by the linked framework.
    let (id_key, team_key) = unsafe { (kSecCodeInfoIdentifier, kSecCodeInfoTeamIdentifier) };
    Ok((string(id_key), string(team_key)))
}
