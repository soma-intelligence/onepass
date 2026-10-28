//! Where the socket is, and who may be on each end of it.
#![allow(unsafe_code)]

use std::ffi::CStr;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use onepass_peer::{CodeIdentity, PeerError, identify_peer, identify_pid, peer_cred};

/// The App Group, after the team prefix: `<team>.me.somalabs.onepass`.
pub const GROUP_SUFFIX: &str = "me.somalabs.onepass";
/// The socket file at the root of the group container.
pub const SOCKET_NAME: &str = "bridge.sock";
/// Code-signing identifiers of the three ends.
pub const APP_ID: &str = "me.somalabs.onepass";
pub const SAFARI_ID: &str = "me.somalabs.onepass.safari";
pub const RELAY_ID: &str = "me.somalabs.onepass.relay";
/// The extension id recorded for a Safari pairing (Safari routes only this
/// app's own extension to its handler).
pub const SAFARI_EXTENSION_ID: &str = "safari";
/// `sizeof(sockaddr_un.sun_path)` on Apple platforms, terminating NUL
/// included.
const SUN_PATH: usize = 104;

/// A team identifier: ten uppercase letters or digits.
pub fn is_team_id(s: &str) -> bool {
    s.len() == 10
        && s.bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
}

/// `<home>/Library/Group Containers/<team>.me.somalabs.onepass/bridge.sock`,
/// or `None` when the team id is malformed or the path does not fit a
/// socket address.
pub fn socket_path(home: &Path, team: &str) -> Option<PathBuf> {
    if !is_team_id(team) {
        return None;
    }
    let p = home
        .join("Library/Group Containers")
        .join(format!("{team}.{GROUP_SUFFIX}"))
        .join(SOCKET_NAME);
    (p.as_os_str().as_bytes().len() < SUN_PATH).then_some(p)
}

/// Who connected to the app.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Client {
    Safari,
    Relay,
}

/// The kind of client `id` is, when signed by `team` with one of the two
/// client identifiers; `None` otherwise (ad hoc, another team, platform
/// code, another identifier).
pub fn classify_client(id: &CodeIdentity, team: &str) -> Option<Client> {
    match id {
        CodeIdentity::Team {
            team_id,
            identifier,
        } if team_id == team => match identifier.as_str() {
            SAFARI_ID => Some(Client::Safari),
            RELAY_ID => Some(Client::Relay),
            _ => None,
        },
        _ => None,
    }
}

/// Whether `id` is the OnePass app signed by `team`.
pub fn is_app(id: &CodeIdentity, team: &str) -> bool {
    matches!(id, CodeIdentity::Team { team_id, identifier }
        if team_id == team && identifier == APP_ID)
}

/// The code identity of the process at the other end of `s`, by its audit
/// token.
pub fn peer_identity(s: &UnixStream) -> Result<CodeIdentity, PeerError> {
    identify_peer(&peer_cred(s)).map(|c| c.code)
}

/// The team that signed this process, or `None` (ad hoc or unsigned: such
/// a build neither serves nor reaches the bridge).
pub fn own_team() -> Option<String> {
    match identify_pid(i32::try_from(std::process::id()).ok()?)
        .ok()?
        .code
    {
        CodeIdentity::Team { team_id, .. } if is_team_id(&team_id) => Some(team_id),
        _ => None,
    }
}

/// The user's home directory from the password database. A sandboxed
/// process's `HOME` is its own container, never the group's parent.
pub fn user_home() -> Option<PathBuf> {
    let mut buf = vec![0 as libc::c_char; 4096];
    // SAFETY: an all-zero passwd is a valid out-value for getpwuid_r.
    let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
    let mut out: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: `pw`, `buf` (with its exact length) and `out` are live,
    // writable locals; getuid has no precondition. On success `out` points
    // at `pw`, whose string fields point into `buf`.
    let rc = unsafe {
        libc::getpwuid_r(
            libc::getuid(),
            &mut pw,
            buf.as_mut_ptr(),
            buf.len(),
            &mut out,
        )
    };
    if rc != 0 || out.is_null() || pw.pw_dir.is_null() {
        return None;
    }
    // SAFETY: `pw_dir` is a NUL-terminated string inside `buf`, alive here.
    let dir = unsafe { CStr::from_ptr(pw.pw_dir) };
    let dir = PathBuf::from(std::ffi::OsStr::from_bytes(dir.to_bytes()));
    dir.is_absolute().then_some(dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn team(t: &str, id: &str) -> CodeIdentity {
        CodeIdentity::Team {
            team_id: t.into(),
            identifier: id.into(),
        }
    }

    #[test]
    fn socket_path_in_the_group_container() {
        let p = socket_path(Path::new("/Users/alex"), "ABCDE12345").unwrap();
        assert_eq!(
            p,
            Path::new(
                "/Users/alex/Library/Group Containers/ABCDE12345.me.somalabs.onepass/bridge.sock"
            )
        );
        assert!(socket_path(Path::new("/Users/alex"), "abcde12345").is_none());
        assert!(socket_path(Path::new("/Users/alex"), "../../tmp/x").is_none());
        // Too long for sun_path: refused rather than truncated.
        let long = format!("/Users/{}", "a".repeat(40));
        assert!(socket_path(Path::new(&long), "ABCDE12345").is_none());
    }

    #[test]
    fn only_the_two_clients_of_the_same_team() {
        let t = "ABCDE12345";
        assert_eq!(
            classify_client(&team(t, SAFARI_ID), t),
            Some(Client::Safari)
        );
        assert_eq!(classify_client(&team(t, RELAY_ID), t), Some(Client::Relay));
        assert_eq!(classify_client(&team("AAAAAAAAAA", SAFARI_ID), t), None);
        assert_eq!(classify_client(&team(t, APP_ID), t), None);
        assert_eq!(
            classify_client(&team(t, "me.somalabs.onepass.autofill"), t),
            None
        );
        let adhoc = CodeIdentity::AdHoc {
            path: "/x".into(),
            cdhash: "00".into(),
            hardened: true,
        };
        assert_eq!(classify_client(&adhoc, t), None);
        let platform = CodeIdentity::Platform {
            identifier: SAFARI_ID.into(),
        };
        assert_eq!(classify_client(&platform, t), None);
    }

    #[test]
    fn app_is_exact() {
        let t = "ABCDE12345";
        assert!(is_app(&team(t, APP_ID), t));
        assert!(!is_app(&team("AAAAAAAAAA", APP_ID), t));
        assert!(!is_app(&team(t, RELAY_ID), t));
    }

    #[test]
    fn home_comes_from_the_password_database() {
        let h = user_home().unwrap();
        assert!(h.is_absolute());
    }

    #[test]
    fn test_binaries_have_no_team() {
        // cargo test binaries are signed ad hoc: they can neither serve nor
        // reach the bridge.
        assert_eq!(own_team(), None);
    }
}
