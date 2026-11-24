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
/// Code-signing identifiers of the four ends in the reference build. A
/// build signed under another bundle id prefix keeps the same shape: the
/// app is `<app>`, its clients `<app>.safari`, `<app>.relay` and
/// `<app>.fill`.
pub const APP_ID: &str = "me.somalabs.onepass";
pub const SAFARI_ID: &str = "me.somalabs.onepass.safari";
pub const RELAY_ID: &str = "me.somalabs.onepass.relay";
/// The Mac fill helper (`OnePass Fill.app`, spec 2026-11-23-mac-fill-anywhere).
pub const FILL_ID: &str = "me.somalabs.onepass.fill";
/// Suffix of the relay's identifier after the app's.
pub const RELAY_SUFFIX: &str = ".relay";
/// Suffix of the fill helper's identifier after the app's.
pub const FILL_SUFFIX: &str = ".fill";
/// The extension id recorded for a Safari pairing (Safari routes only this
/// app's own extension to its handler).
pub const SAFARI_EXTENSION_ID: &str = "safari";
/// The extension id recorded for the fill helper's pairing. Fixed by the
/// admission, never sent by the helper.
pub const FILL_EXTENSION_ID: &str = "fill";
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
    /// The Mac fill helper: the desktop context only, and never a browser
    /// request (`onepass_bridge::service::ClientKind::FillHelper`).
    Fill,
}

/// The kind of client `id` is, when signed by `team` as `<app>.safari`,
/// `<app>.relay` or `<app>.fill` (`app` being the app's own identifier);
/// `None` otherwise (ad hoc, another team, platform code, another
/// identifier).
pub fn classify_client(id: &CodeIdentity, team: &str, app: &str) -> Option<Client> {
    match id {
        CodeIdentity::Team {
            team_id,
            identifier,
        } if team_id == team => match identifier.strip_prefix(app)? {
            ".safari" => Some(Client::Safari),
            RELAY_SUFFIX => Some(Client::Relay),
            FILL_SUFFIX => Some(Client::Fill),
            _ => None,
        },
        _ => None,
    }
}

/// Whether `id` is the OnePass app `app` signed by `team`.
pub fn is_app(id: &CodeIdentity, team: &str, app: &str) -> bool {
    matches!(id, CodeIdentity::Team { team_id, identifier }
        if team_id == team && identifier == app)
}

/// The code identity of the process at the other end of `s`, by its audit
/// token.
pub fn peer_identity(s: &UnixStream) -> Result<CodeIdentity, PeerError> {
    identify_peer(&peer_cred(s)).map(|c| c.code)
}

/// The team that signed this process, or `None` (ad hoc or unsigned: such
/// a build neither serves nor reaches the bridge).
pub fn own_team() -> Option<String> {
    own_identity().map(|(team, _)| team)
}

/// The team and code-signing identifier of this process, or `None` (ad hoc
/// or unsigned).
pub fn own_identity() -> Option<(String, String)> {
    match identify_pid(i32::try_from(std::process::id()).ok()?)
        .ok()?
        .code
    {
        CodeIdentity::Team {
            team_id,
            identifier,
        } if is_team_id(&team_id) => Some((team_id, identifier)),
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
        let a = APP_ID;
        assert_eq!(
            classify_client(&team(t, SAFARI_ID), t, a),
            Some(Client::Safari)
        );
        assert_eq!(
            classify_client(&team(t, RELAY_ID), t, a),
            Some(Client::Relay)
        );
        assert_eq!(classify_client(&team("AAAAAAAAAA", SAFARI_ID), t, a), None);
        assert_eq!(classify_client(&team(t, APP_ID), t, a), None);
        assert_eq!(
            classify_client(&team(t, "me.somalabs.onepass.autofill"), t, a),
            None
        );
        assert_eq!(
            classify_client(&team(t, "me.somalabs.onepassx.safari"), t, a),
            None
        );
        let adhoc = CodeIdentity::AdHoc {
            path: "/x".into(),
            cdhash: "00".into(),
            hardened: true,
        };
        assert_eq!(classify_client(&adhoc, t, a), None);
        let platform = CodeIdentity::Platform {
            identifier: SAFARI_ID.into(),
        };
        assert_eq!(classify_client(&platform, t, a), None);
    }

    #[test]
    fn fill_helper_of_the_same_team_only() {
        let t = "ABCDE12345";
        let a = APP_ID;
        assert_eq!(FILL_ID, format!("{APP_ID}{FILL_SUFFIX}"));
        assert_eq!(
            classify_client(&team(t, "me.somalabs.onepass.fill"), t, a),
            Some(Client::Fill)
        );
        assert_eq!(
            classify_client(&team("AAAAAAAAAA", "me.somalabs.onepass.fill"), t, a),
            None
        );
        assert_eq!(
            classify_client(&team(t, "me.somalabs.onepass.fillx"), t, a),
            None
        );
        assert_eq!(
            classify_client(&team(t, "me.somalabs.onepass.fill.x"), t, a),
            None
        );
        assert_eq!(
            classify_client(&team(t, "me.somalabs.onepassx.fill"), t, a),
            None
        );
        let platform = CodeIdentity::Platform {
            identifier: FILL_ID.into(),
        };
        assert_eq!(classify_client(&platform, t, a), None);
        let adhoc = CodeIdentity::AdHoc {
            path: "/x".into(),
            cdhash: "00".into(),
            hardened: true,
        };
        assert_eq!(classify_client(&adhoc, t, a), None);
        // Another build's helper follows its app.
        assert_eq!(
            classify_client(
                &team(t, "me.quentincaron.onepass.fill"),
                t,
                "me.quentincaron.onepass"
            ),
            Some(Client::Fill)
        );
        assert_eq!(
            classify_client(&team(t, FILL_ID), t, "me.quentincaron.onepass"),
            None
        );
    }

    #[test]
    fn clients_follow_the_app_identifier() {
        let t = "ABCDE12345";
        let a = "me.quentincaron.onepass";
        assert_eq!(
            classify_client(&team(t, "me.quentincaron.onepass.safari"), t, a),
            Some(Client::Safari)
        );
        assert_eq!(
            classify_client(&team(t, "me.quentincaron.onepass.relay"), t, a),
            Some(Client::Relay)
        );
        // The reference build's clients are another app's.
        assert_eq!(classify_client(&team(t, SAFARI_ID), t, a), None);
        assert!(is_app(&team(t, a), t, a));
        assert!(!is_app(&team(t, APP_ID), t, a));
    }

    #[test]
    fn app_is_exact() {
        let t = "ABCDE12345";
        assert!(is_app(&team(t, APP_ID), t, APP_ID));
        assert!(!is_app(&team("AAAAAAAAAA", APP_ID), t, APP_ID));
        assert!(!is_app(&team(t, RELAY_ID), t, APP_ID));
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
        assert_eq!(own_identity(), None);
    }
}
