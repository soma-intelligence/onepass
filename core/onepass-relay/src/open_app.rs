//! "Déverrouiller dans OnePass" from Chrome or Firefox.
//!
//! Since macOS 14 an app in the background cannot bring itself forward
//! while the browser is in front: the app's own `activate()` is ignored. The
//! browser launches this relay for the user's click, so the relay asks
//! LaunchServices to open `onepass://unlock` in the OnePass app of its own
//! signature (`open -b <app>`), which also launches the app when it is not
//! running. The request is one plain message on a fresh native messaging
//! connection (`runtime.sendNativeMessage`), compared byte for byte: bridge
//! frames stay opaque, and nothing else is read.

use std::path::Path;

/// The message, exactly as the extension's `JSON.stringify` writes it.
pub const REQUEST: &[u8] = br#"{"onepass":1,"op":"open_app"}"#;
/// The reply to the extension.
pub const REPLY: &[u8] = br#"{"ok":true}"#;
/// The link the app answers by showing its lock screen.
pub const UNLOCK_URL: &str = "onepass://unlock";
/// LaunchServices' command line tool.
pub const OPEN: &str = "/usr/bin/open";

/// Whether the first frame of a connection is the open request.
pub fn is_request(frame: &[u8]) -> bool {
    frame == REQUEST
}

/// The command that brings `app` (a bundle identifier) forward on its lock
/// screen: the program and its arguments.
pub fn command(app: &str) -> (&'static Path, Vec<String>) {
    (
        Path::new(OPEN),
        vec!["-b".into(), app.into(), UNLOCK_URL.into()],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_exact_request_opens_the_app() {
        assert!(is_request(br#"{"onepass":1,"op":"open_app"}"#));
        for other in [
            &br#"{"onepass":1,"op":"open_app","x":1}"#[..],
            br#"{"op":"open_app","onepass":1}"#,
            br#"{"v":1,"t":"pair_hello"}"#,
            b"",
        ] {
            assert!(!is_request(other));
        }
    }

    #[test]
    fn opens_the_unlock_link_in_our_own_app_only() {
        let (program, args) = command("me.somalabs.onepass");
        assert_eq!(program, Path::new("/usr/bin/open"));
        assert_eq!(args, ["-b", "me.somalabs.onepass", "onepass://unlock"]);
    }
}
